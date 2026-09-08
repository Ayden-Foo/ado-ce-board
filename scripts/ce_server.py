"""Local Azure DevOps CE dashboard -- view and edit work items in a browser.

Runs a small web server on 127.0.0.1 that lists the work items you created and
lets you edit State, Assigned To, Title, and add a comment. Changes are written
straight to Azure DevOps.

Runs independently of Copilot, so it keeps working after Copilot is closed. Use
install_autostart.py to have it start again after a reboot.

    python ce_server.py                 # serve on the default port
    python ce_server.py --port 8787
    python ce_server.py --no-browser

Security: binds to 127.0.0.1 only, checks the Host header, and requires a
per-run nonce on every API call so other local processes cannot drive it.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from html import unescape
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import azdo_auth

API = "7.1"
ORG = os.environ.get("AZDO_ORG", "ni")
PROJECT = os.environ.get("AZDO_PROJECT", "DevCentral")
NONCE = secrets.token_urlsafe(24)
URL_FILE = os.path.join(os.path.expanduser("~"), ".azdo_ce_board_url")
ICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "ce-board.ico")

MAX_UPLOAD = int(os.environ.get("CE_BOARD_MAX_UPLOAD_MB", "60")) * 1024 * 1024

# Link kinds offered in the UI, mapped to Azure DevOps relation names.
LINK_TYPES = {
    "related": "System.LinkTypes.Related",
    "duplicate": "System.LinkTypes.Duplicate-Forward",
    "child": "System.LinkTypes.Hierarchy-Forward",
    "parent": "System.LinkTypes.Hierarchy-Reverse",
    "successor": "System.LinkTypes.Dependency-Forward",
    "predecessor": "System.LinkTypes.Dependency-Reverse",
}
REL_LABELS = {v: k for k, v in LINK_TYPES.items()}

# Seen comment ids persist so a restart does not re-announce old comments.
SEEN_PATH = os.environ.get(
    "CE_BOARD_SEEN",
    os.path.join(os.path.expanduser("~"), ".azdo_ce_seen.json"))

FEED_LIMIT = 50
_feed = []
_feed_lock = threading.Lock()

LOG_PATH = os.environ.get(
    "CE_BOARD_LOG",
    os.path.join(os.path.expanduser("~"), ".azdo_ce_board.log"))


def _bind_output():
    """Under pythonw.exe sys.stdout/stderr are None, so any print() would crash
    the server. Send output to a log file instead."""
    if sys.stdout is not None and sys.stderr is not None:
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
        return
    handle = open(LOG_PATH, "a", encoding="utf-8", buffering=1)
    sys.stdout = handle
    sys.stderr = handle
    print("\n=== started {} ===".format(time.strftime("%Y-%m-%d %H:%M:%S")))


_bind_output()

FIELDS = [
    "System.Id", "System.WorkItemType", "System.Title", "System.State",
    "System.AssignedTo", "System.CreatedBy", "System.CreatedDate",
    "System.ChangedDate", "System.ChangedBy", "System.Tags", "System.TeamProject",
]

_states_cache = {}


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def call(path, payload=None, method=None, patch=False, attempts=4):
    url = "https://dev.azure.com/{}/{}".format(urllib.parse.quote(ORG), path)
    # Never let a request block on the console device-code prompt: this is a
    # server, so surface a clean 401 and let the UI offer the Sign in button.
    if not azdo_auth.have_credentials():
        raise ApiError(401, "Not signed in. Use the Sign in button.")
    try:
        token = azdo_auth.get_access_token()
    except SystemExit as exc:
        raise ApiError(401, "Sign-in required: {}".format(exc))
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = ("application/json-patch+json" if patch
                                   else "application/json")
    for attempt in range(attempts):
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method or ("POST" if data else "GET"))
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read().decode("utf-8", "replace")
            return json.loads(body) if body.strip() else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            # Azure DevOps throttles bursts; back off instead of surfacing 503s.
            if exc.code in (429, 502, 503, 504) and attempt < attempts - 1:
                wait = float(exc.headers.get("Retry-After") or 0) or 2 ** attempt
                time.sleep(min(wait, 20))
                continue
            try:
                detail = json.loads(detail).get("message", detail)
            except ValueError:
                detail = detail[:300]
            raise ApiError(exc.code, detail)
        except urllib.error.URLError as exc:
            if attempt < attempts - 1:
                time.sleep(2 ** attempt)
                continue
            raise ApiError(503, "Network error: {}".format(exc.reason))
    raise ApiError(503, "Azure DevOps did not respond.")


def identity_id(value):
    """The stable GUID behind a System.* identity field.

    Display names cannot be compared: the profile reports "Ayden Foo"
    while work item fields report "Foo, Ayden".
    """
    return value.get("id", "") if isinstance(value, dict) else ""


def identity_name(value):
    if isinstance(value, dict):
        return value.get("displayName") or value.get("uniqueName") or ""
    return value or ""


_identity_cache = {}
_follow_cache = {}


def my_display_name():
    """Cached: this is called on every list/search and never changes per token."""
    if not _identity_cache.get("name"):
        data = call("_apis/connectionData?connectOptions=none&api-version=7.1-preview")
        user = data.get("authenticatedUser") or {}
        _identity_cache["name"] = user.get("providerDisplayName", "")
        _identity_cache["id"] = user.get("id", "")
    return _identity_cache["name"]


def my_identity_id():
    if not _identity_cache.get("id"):
        my_display_name()
    return _identity_cache.get("id") or ""


def followed_ids(max_age=60):
    """Work items this user follows.

    Azure DevOps has no WIQL predicate for follows: each one is a personal
    notification subscription with an Artifact filter, so they are read from
    the notification service and then resolved as ordinary work items.
    """
    now = time.time()
    cached = _follow_cache.get("ids")
    if cached is not None and now - _follow_cache.get("at", 0) < max_age:
        return cached
    me = my_identity_id()
    if not me:
        return []
    data = call("_apis/notification/subscriptions?subscriberId={}"
                "&api-version=6.0-preview.1".format(urllib.parse.quote(me)))
    ids = []
    for sub in data.get("value", []):
        f = sub.get("filter") or {}
        if f.get("type") != "Artifact" or f.get("artifactType") != "WorkItem":
            continue
        raw = str(f.get("artifactId") or "")
        if raw.isdigit():
            ids.append(int(raw))
    _follow_cache["ids"] = ids
    _follow_cache["at"] = now
    return ids


def list_items(open_only=True, match="both", top=200):
    display = my_display_name()
    clauses = ["[System.CreatedBy] = @Me"]
    if display and match in ("contains", "both"):
        clauses.append("[System.CreatedBy] CONTAINS '{}'".format(
            display.replace("'", "''")))
    if match == "contains" and len(clauses) > 1:
        clauses = clauses[1:]
    where = ["[System.TeamProject] = '{}'".format(PROJECT.replace("'", "''")),
             "({})".format(" OR ".join(clauses))]
    if open_only:
        where.append("[System.State] NOT IN ('Closed', 'Removed', 'Done')")
    wiql = ("SELECT [System.Id] FROM WorkItems WHERE {} "
            "ORDER BY [System.ChangedDate] DESC".format(" AND ".join(where)))
    result = call("{}/_apis/wit/wiql?api-version={}&$top={}".format(
        urllib.parse.quote(PROJECT), API, top), {"query": wiql})
    ids = [int(x["id"]) for x in result.get("workItems", [])][:top]
    if not ids:
        return []
    items = []
    for start in range(0, len(ids), 200):
        batch = call("_apis/wit/workitemsbatch?api-version=" + API,
                     {"ids": ids[start:start + 200], "fields": FIELDS})
        items.extend(batch.get("value", []))
    order = {wid: pos for pos, wid in enumerate(ids)}
    items.sort(key=lambda it: order.get(it.get("id"), 0))
    return [{
        "id": it.get("id"),
        "type": it["fields"].get("System.WorkItemType", ""),
        "title": it["fields"].get("System.Title", ""),
        "state": it["fields"].get("System.State", ""),
        "assignedTo": identity_name(it["fields"].get("System.AssignedTo")),
        "createdBy": identity_name(it["fields"].get("System.CreatedBy")),
        "changedDate": it["fields"].get("System.ChangedDate", ""),
        "changedBy": identity_name(it["fields"].get("System.ChangedBy")),
        "changedById": identity_id(it["fields"].get("System.ChangedBy")),
        "assignedToId": identity_id(it["fields"].get("System.AssignedTo")),
        "tags": it["fields"].get("System.Tags", ""),
        "project": it["fields"].get("System.TeamProject", ""),
        "url": "https://dev.azure.com/{}/{}/_workitems/edit/{}".format(
            ORG, PROJECT, it.get("id")),
    } for it in items]


def type_states(work_item_type):
    if work_item_type in _states_cache:
        return _states_cache[work_item_type]
    data = call("{}/_apis/wit/workitemtypes/{}/states?api-version={}-preview".format(
        urllib.parse.quote(PROJECT), urllib.parse.quote(work_item_type), API))
    names = [s.get("name") for s in data.get("value", []) if s.get("name")]
    _states_cache[work_item_type] = names
    return names


def search_identities(query, limit=8):
    """Look up people for @mention autocomplete."""
    query = (query or "").strip()
    if len(query) < 2:
        return []
    body = {
        "query": query,
        "identityTypes": ["user"],
        "operationScopes": ["ims", "source"],
        "options": {"MinResults": limit, "MaxResults": limit},
        "properties": ["DisplayName", "Mail", "SignInAddress", "LocalId",
                       "SubjectDescriptor", "Active"],
    }
    try:
        data = call("_apis/IdentityPicker/Identities?api-version=5.0-preview.1", body)
    except ApiError:
        return []
    found = []
    for group in data.get("results") or []:
        for ident in group.get("identities") or []:
            if not ident.get("localId"):
                continue
            found.append({
                "id": ident["localId"],
                "name": ident.get("displayName") or "",
                "mail": ident.get("signInAddress") or ident.get("mail") or "",
            })
    return found[:limit]


def _esc_html(text):
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# The only formatting the editor may send back. Everything else is discarded
# on arrival, so what reaches a work item is always markup this server wrote.
RICH_TAGS = ("b", "strong", "i", "em", "u", "div", "p", "ul", "ol", "li",
             "blockquote", "span", "font")
RICH_DROP_TREE = ("script", "style", "table", "head", "iframe", "object",
                  "svg", "math")
RICH_VOID = ("img", "hr", "input", "meta", "link", "col", "source", "embed")
HIGHLIGHT = "#fff29a"
INDENT_STYLE = "margin:0 0 0 40px"
MAX_RICH_CHARS = 100000
_BLANK_BG = ("transparent", "none", "initial", "inherit", "unset", "white",
             "#fff", "#ffffff", "rgb(255,255,255)", "rgba(0,0,0,0)")


def _is_highlight(attrs):
    """Whether a <span> the editor produced is a highlight worth keeping.

    The colour itself is not taken from the page: any highlighted run is
    redrawn in this module's own colour, so a span cannot carry styling of its
    choosing into a work item.
    """
    for name, value in attrs:
        if name.lower() != "style" or not value:
            continue
        for part in value.split(";"):
            prop, _, val = part.partition(":")
            if prop.strip().lower() in ("background", "background-color"):
                val = re.sub(r"\s+", "", val).strip().lower()
                if val and val not in _BLANK_BG:
                    return True
    return False


class _RichText(HTMLParser):
    """Reduce the editor's HTML to the handful of tags a work item may carry.

    This is the one place the page's own markup is read, so it works by
    allowlist: a tag that is not named here is dropped and only its text
    survives, and every attribute is discarded. Images and tables are dropped
    outright because they travel separately, as tokens the server can vouch
    for. Nothing that can execute, load or style beyond this list gets through.
    """

    def __init__(self, mentions=None):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.out = []
        self.stack = []
        self.skip = 0
        self.chars = 0
        # Longest names first so "Foo, Ayden Junior" is not clobbered by
        # "Foo, Ayden".
        self.people = []
        for person in sorted(mentions or [],
                             key=lambda m: len(m.get("name") or ""),
                             reverse=True):
            name, ident = person.get("name"), person.get("id")
            if name and ident:
                self.people.append((
                    "@" + _esc_html(name),
                    '<a href="#" data-vss-mention="version:2.0,{}">@{}</a>'
                    .format(_esc_html(ident), _esc_html(name))))

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in RICH_DROP_TREE:
            self.skip += 1
            return
        if self.skip:
            return
        if tag == "br":
            self.out.append("<br>")
            return
        if tag in RICH_VOID:
            return
        # The name this tag is written out as, or None if it is dropped.
        out_name = None
        if tag in RICH_TAGS:
            if tag in ("span", "font"):
                # A browser writes a highlight either as a styled span or, with
                # CSS styling turned off, as a <font>. Both arrive here as the
                # same plain span, in this module's own colour.
                if _is_highlight(attrs):
                    self.out.append('<span style="background-color:{}">'
                                    .format(HIGHLIGHT))
                    out_name = "span"
            elif tag == "blockquote":
                self.out.append('<blockquote style="{}">'.format(INDENT_STYLE))
                out_name = "blockquote"
            else:
                self.out.append("<{}>".format(tag))
                out_name = tag
        # Tags that were not written out are still tracked, so their closing
        # tag cannot close something else by accident.
        self.stack.append((tag, out_name))

    def handle_startendtag(self, tag, attrs):
        if tag.lower() == "br" and not self.skip:
            self.out.append("<br>")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in RICH_DROP_TREE:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip or tag == "br" or tag in RICH_VOID:
            return
        if not any(open_tag == tag for open_tag, _ in self.stack):
            return
        while self.stack:
            open_tag, out_name = self.stack.pop()
            if out_name:
                self.out.append("</{}>".format(out_name))
            if open_tag == tag:
                break

    def handle_data(self, data):
        if self.skip or self.chars >= MAX_RICH_CHARS:
            return
        text = data[:MAX_RICH_CHARS - self.chars]
        self.chars += len(text)
        text = _esc_html(text)
        for needle, anchor in self.people:
            text = text.replace(needle, anchor)
        self.out.append(text)

    def result(self):
        while self.stack:
            _, out_name = self.stack.pop()
            if out_name:
                self.out.append("</{}>".format(out_name))
        return "".join(self.out)


def clean_rich_html(html, mentions=None):
    """Sanitise formatted text on its way to a work item."""
    parser = _RichText(mentions)
    parser.feed(html or "")
    out = parser.result()
    # Nothing but empty markup is nothing: an image-only or table-only comment
    # is built from those separately.
    return "" if not _strip_html(out).strip() else out


def editable_html(raw):
    """The same field, reduced to what the editor is able to show and send.

    Seeding the editor with this rather than the raw field means saving it
    back unchanged cannot alter anything, because it has already been through
    the filter that a save goes through.
    """
    return clean_rich_html(raw)


def build_comment_html(text, mentions, html=None):
    """Turn what was written into the HTML Azure DevOps needs, converting
    picked people into real @mention anchors so they get notified.

    Formatted text arrives as HTML and is sanitised. Plain text is still
    accepted: line breaks, blank lines and bullet or numbered lists are turned
    back into markup, so text taken apart by to_plain_text and saved again
    comes out looking the way it went in.
    """
    if html is not None:
        return clean_rich_html(html, mentions)
    html = _esc_html(text)
    # Longest names first so "Foo, Ayden Junior" is not clobbered by "Foo, Ayden".
    for person in sorted(mentions or [], key=lambda m: len(m.get("name") or ""),
                         reverse=True):
        name, ident = person.get("name"), person.get("id")
        if not name or not ident:
            continue
        anchor = ('<a href="#" data-vss-mention="version:2.0,{}">@{}</a>'
                  .format(_esc_html(ident), _esc_html(name)))
        html = html.replace("@" + _esc_html(name), anchor)
    return _lines_to_html(html.replace("\r\n", "\n").split("\n"))


_BULLET = re.compile(r"^\s*[-*\u2022]\s+(.*)$")
_NUMBER = re.compile(r"^\s*\d{1,3}[.)]\s+(.*)$")


def _lines_to_html(lines):
    """Rebuild <ul>/<ol>/<br> layout from already-escaped lines."""
    out, list_tag, need_break = [], None, False
    for line in lines:
        bullet, number = _BULLET.match(line), _NUMBER.match(line)
        want = "ul" if bullet else ("ol" if number else None)
        if want != list_tag:
            if list_tag:
                out.append("</{}>".format(list_tag))
            if want:
                out.append("<{}>".format(want))
            list_tag = want
            # List markup already breaks the line, so the next plain line does
            # not need a <br> in front of it.
            need_break = False
        if want:
            out.append("<li>{}</li>".format((bullet or number).group(1).strip()))
        else:
            if need_break:
                out.append("<br>")
            out.append(line)
            need_break = True
    if list_tag:
        out.append("</{}>".format(list_tag))
    return "".join(out)


# Attachment URLs this server minted, so a comment can only embed images that
# really came from an upload we performed.
_upload_lock = threading.Lock()
_uploaded = set()


def _allowed_images(urls):
    """Keep only attachment URLs this process uploaded and that are ours."""
    out = []
    for candidate in (urls or [])[:20]:
        candidate = str(candidate)
        with _upload_lock:
            known = candidate in _uploaded
        if known and _is_ado_url(candidate) and candidate not in out:
            out.append(candidate)
    return out


def update_item(item_id, changes):
    """Apply field edits and/or a comment to one work item."""
    ops = []
    for field, value in (changes.get("fields") or {}).items():
        if field not in ("System.Title", "System.State", "System.AssignedTo",
                         "System.Tags"):
            raise ApiError(400, "Field not editable here: {}".format(field))
        # An empty AssignedTo means unassign, which requires a remove op.
        if field == "System.AssignedTo" and not str(value).strip():
            ops.append({"op": "remove", "path": "/fields/System.AssignedTo"})
        else:
            ops.append({"op": "add", "path": "/fields/" + field, "value": value})
    comment = (changes.get("comment") or "").strip()
    images = _allowed_images(changes.get("images"))
    tables = _allowed_tables(changes.get("tables"))
    if comment or images or tables or changes.get("html"):
        html = build_comment_html(comment, changes.get("mentions"),
                                  changes.get("html"))
        for table in tables:
            html += ("<br>" if html else "") + table
        for src in images:
            if html:
                html += "<br>"
            html += '<img src="{}" style="max-width:100%">'.format(_esc_html(src))
        ops.append({"op": "add", "path": "/fields/System.History",
                    "value": html})
    if not ops:
        raise ApiError(400, "Nothing to update.")
    return call("{}/_apis/wit/workitems/{}?api-version={}".format(
        urllib.parse.quote(PROJECT), int(item_id), API),
        ops, method="PATCH", patch=True)


def upload_attachment(item_id, file_name, blob, comment=""):
    """Upload a file to Azure DevOps and attach it to a work item."""
    if not blob:
        raise ApiError(400, "Empty file.")
    if len(blob) > MAX_UPLOAD:
        raise ApiError(413, "File is larger than {} MB.".format(
            MAX_UPLOAD // (1024 * 1024)))
    name = os.path.basename(file_name or "").strip() or "attachment"
    name = re.sub(r'[\\/:*?"<>|]', "_", name)[:120]
    if not azdo_auth.have_credentials():
        raise ApiError(401, "Not signed in.")
    try:
        token = azdo_auth.get_access_token()
    except SystemExit as exc:
        raise ApiError(401, "Sign-in required: {}".format(exc))
    url = ("https://dev.azure.com/{}/{}/_apis/wit/attachments"
           "?fileName={}&api-version={}".format(
               urllib.parse.quote(ORG), urllib.parse.quote(PROJECT),
               urllib.parse.quote(name), API))
    req = urllib.request.Request(url, data=blob, method="POST", headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/octet-stream",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            created = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        try:
            detail = json.loads(detail).get("message", detail)
        except ValueError:
            detail = detail[:300]
        raise ApiError(exc.code, detail)
    except urllib.error.URLError as exc:
        raise ApiError(503, "Network error: {}".format(exc.reason))
    attrs = {"name": name}
    if comment:
        attrs["comment"] = comment[:250]
    _add_relation(item_id, "AttachedFile", created["url"], attrs)
    # Remember what we uploaded so a later comment may embed it; nothing the
    # page did not obtain from this server can be turned into an <img>.
    with _upload_lock:
        _uploaded.add(created["url"])
        if len(_uploaded) > 500:
            _uploaded.clear()
            _uploaded.add(created["url"])
    return {"name": name, "url": created["url"], "size": len(blob),
            "key": res_key(created["url"])}


def _add_relation(item_id, rel, url, attributes):
    ops = [{"op": "add", "path": "/relations/-",
            "value": {"rel": rel, "url": url, "attributes": attributes}}]
    return call("{}/_apis/wit/workitems/{}?api-version={}".format(
        urllib.parse.quote(PROJECT), int(item_id), API),
        ops, method="PATCH", patch=True)


def add_link(item_id, kind, target, comment=""):
    """Attach a hyperlink or a link to another work item."""
    kind = (kind or "").strip()
    target = (target or "").strip()
    if not target:
        raise ApiError(400, "Nothing to link to.")
    attrs = {"comment": comment[:250]} if comment else {}
    if kind == "hyperlink":
        if not re.match(r"(?i)^https?://", target):
            raise ApiError(400, "A hyperlink must start with http:// or https://.")
        return _add_relation(item_id, "Hyperlink", target, attrs)
    if kind not in LINK_TYPES:
        raise ApiError(400, "Unsupported link type.")
    digits = re.sub(r"\D", "", target)
    if not digits:
        raise ApiError(400, "Enter the work item ID to link to.")
    if int(digits) == int(item_id):
        raise ApiError(400, "A work item cannot link to itself.")
    # Confirm the target exists, so a typo fails loudly instead of silently.
    call("_apis/wit/workitems/{}?api-version={}&fields=System.Id".format(
        int(digits), API))
    return _add_relation(
        item_id, LINK_TYPES[kind],
        "https://dev.azure.com/{}/_apis/wit/workItems/{}".format(ORG, int(digits)),
        attrs)


def remove_relation(item_id, url):
    """Detach a file or link. The URL is matched against the live item so a
    stale page can never remove the wrong relation by index."""
    if not url:
        raise ApiError(400, "Nothing to remove.")
    item = call("{}/_apis/wit/workitems/{}?api-version={}&$expand=relations".format(
        urllib.parse.quote(PROJECT), int(item_id), API))
    matches = [i for i, r in enumerate(item.get("relations") or [])
               if (r.get("url") or "") == url]
    if not matches:
        raise ApiError(409, "That item was already removed. Refresh and retry.")
    if len(matches) > 1:
        raise ApiError(409, "Several relations share that URL; remove it in "
                            "Azure DevOps.")
    ops = [{"op": "test", "path": "/rev", "value": item.get("rev")},
           {"op": "remove", "path": "/relations/{}".format(matches[0])}]
    return call("{}/_apis/wit/workitems/{}?api-version={}".format(
        urllib.parse.quote(PROJECT), int(item_id), API),
        ops, method="PATCH", patch=True)


def _safe_href(url):
    """Only http(s) URLs may reach an href.

    Relation URLs come from Azure DevOps, where any org member can store an
    arbitrary string - including javascript: - so the scheme is checked here,
    where the data is produced, rather than trusting the client templating.
    """
    scheme = ""
    try:
        scheme = (urllib.parse.urlparse(url).scheme or "").lower()
    except ValueError:
        return ""
    return url if scheme in ("http", "https") else ""


def item_detail(item_id):
    """Full record for one work item: fields, description and its comments."""
    item = call("{}/_apis/wit/workitems/{}?api-version={}&$expand=all".format(
        urllib.parse.quote(PROJECT), int(item_id), API))
    f = item.get("fields", {})
    # A followed item can live in another project, and the comments endpoint
    # is project-scoped, so use the item's own project rather than ours.
    owner = f.get("System.TeamProject") or PROJECT
    try:
        raw = fetch_comments(item_id, owner)
    except ApiError:
        raw = []
    try:
        mine_id = my_identity_id()
    except ApiError:
        mine_id = ""
    comments = [{
        "id": c.get("id"),
        "author": (c.get("createdBy") or {}).get("displayName", ""),
        "at": c.get("createdDate", ""),
        "edited": bool(c.get("modifiedDate")
                       and c.get("modifiedDate") != c.get("createdDate")),
        "mine": bool(mine_id) and (c.get("createdBy") or {}).get("id") == mine_id,
        "text": to_plain_text(c.get("text", "")),
        "html": safe_html(c.get("text", "")),
        "edit": editable_html(c.get("text", "")),
        "kept": _kept_preview(c.get("text", "")),
    } for c in raw]
    comments.sort(key=lambda c: c.get("at") or "")
    attachments = []
    links = []
    for rel in item.get("relations") or []:
        kind = rel.get("rel") or ""
        attrs = rel.get("attributes") or {}
        url = rel.get("url") or ""
        if kind == "AttachedFile":
            name = attrs.get("name") or "attachment"
            image = name.lower().endswith(IMAGE_EXT)
            proxied = _is_ado_url(url)
            attachments.append({
                "name": name,
                "size": attrs.get("resourceSize"),
                "comment": attrs.get("comment") or "",
                "isImage": image and proxied,
                "src": ("/img?n={}&k={}".format(NONCE, res_key(url))
                        if image and proxied else ""),
                "download": ("/file?n={}&k={}&name={}".format(
                    NONCE, res_key(url),
                    urllib.parse.quote(name)) if proxied else _safe_href(url)),
                "url": url,
            })
        elif kind == "Hyperlink" or kind == "ArtifactLink":
            links.append({
                "kind": "hyperlink", "label": attrs.get("name") or url,
                "target": url, "url": url, "href": _safe_href(url),
                "comment": attrs.get("comment") or "", "external": True,
            })
        elif kind in REL_LABELS:
            wid = re.sub(r"\D", "", url.rsplit("/", 1)[-1])
            links.append({
                "kind": REL_LABELS[kind], "label": "#" + wid if wid else url,
                "target": wid, "url": url,
                "webUrl": ("https://dev.azure.com/{}/{}/_workitems/edit/{}".format(
                    ORG, PROJECT, wid) if wid else url),
                "comment": attrs.get("comment") or "", "external": False,
            })
    _annotate_links(links)
    return {
        "item": {
            "id": item.get("id"),
            "type": f.get("System.WorkItemType", ""),
            "title": f.get("System.Title", ""),
            "state": f.get("System.State", ""),
            "reason": f.get("System.Reason", ""),
            "assignedTo": identity_name(f.get("System.AssignedTo")),
            "createdBy": identity_name(f.get("System.CreatedBy")),
            "createdDate": f.get("System.CreatedDate", ""),
            "changedDate": f.get("System.ChangedDate", ""),
            "tags": f.get("System.Tags", ""),
            "areaPath": f.get("System.AreaPath", ""),
            "project": owner,
            "description": to_plain_text(f.get("System.Description", "")),
            "repro": to_plain_text(f.get("Microsoft.VSTS.TCM.ReproSteps", "")),
            "descEdit": editable_html(f.get("System.Description", "")),
            "reproEdit": editable_html(
                f.get("Microsoft.VSTS.TCM.ReproSteps", "")),
            "descriptionHtml": safe_html(f.get("System.Description", "")),
            "reproHtml": safe_html(f.get("Microsoft.VSTS.TCM.ReproSteps", "")),
            # Which field the card is actually showing, so the editor writes
            # back to that one rather than blanking the other.
            "descField": ("System.Description"
                          if _strip_html(f.get("System.Description", "")).strip()
                          or not _strip_html(
                              f.get("Microsoft.VSTS.TCM.ReproSteps", "")).strip()
                          else "Microsoft.VSTS.TCM.ReproSteps"),
            "descKept": _kept_preview(f.get("System.Description", "")),
            "reproKept": _kept_preview(
                f.get("Microsoft.VSTS.TCM.ReproSteps", "")),
            "url": "https://dev.azure.com/{}/{}/_workitems/edit/{}".format(
                ORG, urllib.parse.quote(owner), item.get("id")),
        },
        "attachments": attachments,
        "links": links,
        "comments": comments,
    }


TABLE_TAGS = {"table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption",
              "br", "b", "strong", "i", "em", "u", "p"}
TABLE_VOID = {"br"}
TABLE_STYLE = "border-collapse:collapse"
CELL_STYLE = "border:1px solid #c0c0c0;padding:4px 8px;vertical-align:top"
MAX_TABLE_ROWS = 200
MAX_TABLE_COLS = 50
MAX_CELL_CHARS = 500

# Sanitised tables the server produced, keyed by an opaque token. A comment can
# only embed a table this server built, so the page can never post raw HTML.
_table_lock = threading.Lock()
_tables = {}


class _TableCleaner(HTMLParser):
    """Reduce pasted Excel/Outlook HTML to a plain, safe table.

    Everything outside a <table> is dropped, as are all attributes except
    colspan/rowspan; the borders are styles this module owns, never anything
    that came from the clipboard.
    """

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.out = []
        self.depth = 0        # nesting level of <table>
        self.skip = 0         # inside <style>/<script>
        self.stack = []
        self.rows = 0
        self.cols = 0
        self._row_cols = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in ("style", "script"):
            self.skip += 1
            return
        if self.skip:
            return
        if tag == "table":
            self.depth += 1
            if self.depth > 1:      # a nested table is flattened away
                return
            self.out.append('<table style="{}">'.format(TABLE_STYLE))
            self.stack.append(tag)
            return
        if not self.depth or tag not in TABLE_TAGS:
            return
        if tag == "tr":
            if self.rows >= MAX_TABLE_ROWS:
                return
            self.rows += 1
            self._row_cols = 0
        if tag in ("td", "th"):
            self._row_cols += 1
            if self._row_cols > MAX_TABLE_COLS:
                return
            self.cols = max(self.cols, self._row_cols)
            span = ""
            for name, value in attrs:
                if name.lower() in ("colspan", "rowspan") and value \
                        and value.strip().isdigit():
                    span += ' {}="{}"'.format(name.lower(),
                                              min(int(value.strip()), 50))
            self.out.append('<{}{} style="{}">'.format(tag, span, CELL_STYLE))
        else:
            self.out.append("<{}>".format(tag))
        if tag not in TABLE_VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in ("style", "script"):
            self.skip = max(0, self.skip - 1)
            return
        if self.skip or not self.depth:
            return
        if tag == "table":
            self.depth -= 1
        if tag in TABLE_VOID or tag not in TABLE_TAGS:
            return
        if tag in self.stack:
            while self.stack:
                open_tag = self.stack.pop()
                self.out.append("</{}>".format(open_tag))
                if open_tag == tag:
                    break

    def handle_data(self, data):
        if self.skip or not self.depth or not self.stack:
            return
        text = re.sub(r"\s+", " ", data)[:MAX_CELL_CHARS]
        if not text.strip():
            # Space between one cell and the next is only how the markup was
            # laid out. Inside a cell it can be a real space between words.
            if "td" not in self.stack and "th" not in self.stack:
                return
            text = " "
        self.out.append(_esc_html(text))

    def result(self):
        while self.stack:
            self.out.append("</{}>".format(self.stack.pop()))
        return "".join(self.out)


def _table_from_tsv(text):
    """Build a table from the tab-separated text Excel puts on the clipboard."""
    lines = [ln for ln in (text or "").replace("\r\n", "\n")
             .replace("\r", "\n").split("\n") if ln.strip()]
    if not lines:
        return "", 0, 0
    cells = [ln.split("\t")[:MAX_TABLE_COLS] for ln in lines[:MAX_TABLE_ROWS]]
    out = ['<table style="{}">'.format(TABLE_STYLE)]
    for index, row in enumerate(cells):
        tag = "th" if index == 0 else "td"
        out.append("<tr>")
        for cell in row:
            out.append('<{0} style="{1}">{2}</{0}>'.format(
                tag, CELL_STYLE, _esc_html(cell.strip()[:MAX_CELL_CHARS])))
        out.append("</tr>")
    out.append("</table>")
    return "".join(out), len(cells), max(len(r) for r in cells)


def make_table(html="", tsv=""):
    """Turn pasted clipboard content into a stored, sanitised table."""
    if html and "<table" in html.lower():
        cleaner = _TableCleaner()
        cleaner.feed(html)
        cleaned, rows, cols = cleaner.result(), cleaner.rows, cleaner.cols
    else:
        cleaned, rows, cols = _table_from_tsv(tsv)
    if not cleaned or not rows:
        raise ApiError(400, "That paste did not contain a table.")
    token = _register_table(cleaned)
    return {"token": token, "html": cleaned, "rows": rows, "cols": cols}


def _register_table(html):
    """Keep a sanitised table under an opaque token the page can refer to."""
    token = secrets.token_hex(16)
    with _table_lock:
        if len(_tables) > 200:
            _tables.clear()
        _tables[token] = html
    return token


def _allowed_tables(tokens):
    """Resolve table tokens back to the HTML this server sanitised."""
    out = []
    for token in (tokens or [])[:10]:
        with _table_lock:
            html = _tables.get(str(token))
        if html and html not in out:
            out.append(html)
    return out


def _comment_tables(text):
    """Tables already in a comment, re-cleaned, so an edit keeps them."""
    cleaner = _TableCleaner()
    cleaner.feed(text or "")
    return _split_tables(cleaner.result()) if cleaner.rows else []


def _split_tables(html):
    """Separate one cleaned run of HTML into its individual tables.

    _TableCleaner flattens nested tables, so its output never has a <table>
    inside another one and this split is exact rather than a guess.
    """
    return re.findall(r"<table\b.*?</table>", html or "", re.S)


class _TableGrid(HTMLParser):
    """Read a table this server built back into editable rows and cells.

    Only ever fed _TableCleaner output, so the shape is known. Each cell keeps
    its sanitised inner HTML, which is what lets a row be added or removed
    without flattening the formatting of the cells nobody touched.
    """

    KEEP = ("b", "strong", "i", "em", "u", "p")
    SECTIONS = ("thead", "tbody", "tfoot")

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.rows = []
        self._row = None
        self._cell = None
        self._sect = None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self.SECTIONS:
            self._sect = tag
            return
        if tag == "tr":
            self._row = []
            self.rows.append({"sect": self._sect, "cells": self._row})
            return
        if tag in ("td", "th"):
            if self._row is None:
                self._row = []
                self.rows.append(self._row)
            span = ""
            for name, value in attrs:
                if name.lower() in ("colspan", "rowspan") \
                        and (value or "").strip().isdigit():
                    span += ' {}="{}"'.format(name.lower(),
                                              min(int(value.strip()), 50))
            self._cell = {"tag": tag, "span": span, "inner": [], "text": []}
            self._row.append(self._cell)
            return
        if self._cell is None:
            return
        if tag == "br":
            self._cell["inner"].append("<br>")
            self._cell["text"].append("\n")
        elif tag in self.KEEP:
            self._cell["inner"].append("<{}>".format(tag))

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self.SECTIONS:
            self._sect = None
        elif tag in ("td", "th"):
            self._cell = None
        elif tag == "tr":
            self._row = None
        elif self._cell is not None and tag in self.KEEP:
            self._cell["inner"].append("</{}>".format(tag))

    def handle_data(self, data):
        if self._cell is None:
            return
        self._cell["inner"].append(_esc_html(data))
        self._cell["text"].append(data)

    def result(self):
        grid = []
        for row in self.rows:
            cells = [{"tag": c["tag"], "span": c["span"],
                      "inner": "".join(c["inner"]),
                      "text": "".join(c["text"])} for c in row["cells"]]
            if cells:
                grid.append({"sect": row["sect"], "cells": cells})
        return grid


def _blank_cell(tag="td"):
    return {"tag": tag, "span": "", "inner": "", "text": ""}


def _cell_inner(text):
    """Turn what someone typed into a cell into safe cell HTML."""
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r"[ \t]+", " ", line).strip()
             for line in text[:MAX_CELL_CHARS].split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "<br>".join(_esc_html(line) for line in lines)


def _grid_html(grid):
    """Rebuild a table from its cells, with this module's own borders.

    The thead/tbody grouping of the original is put back as it was, so a table
    that is opened and saved without being changed comes out byte for byte the
    way it went in.
    """
    out = ['<table style="{}">'.format(TABLE_STYLE)]
    section = None
    for row in grid[:MAX_TABLE_ROWS]:
        if row["sect"] != section:
            if section:
                out.append("</{}>".format(section))
            section = row["sect"]
            if section:
                out.append("<{}>".format(section))
        out.append("<tr>")
        for cell in row["cells"][:MAX_TABLE_COLS]:
            out.append('<{0}{1} style="{2}">{3}</{0}>'.format(
                cell["tag"], cell["span"], CELL_STYLE, cell["inner"]))
        out.append("</tr>")
    if section:
        out.append("</{}>".format(section))
    out.append("</table>")
    return "".join(out)


TABLE_OPS = ("setCell", "addRow", "delRow", "addCol", "delCol")


def table_op(token, op, row=0, col=0, text=""):
    """Apply one structural change to a stored table and store the result.

    The page sends what it wants done -- add a row, retype a cell -- never the
    table itself, so an edited table is still markup this server wrote. Cells
    nobody touched keep their existing formatting with them.
    """
    if op not in TABLE_OPS:
        raise ApiError(400, "Unknown table change: {}".format(op))
    with _table_lock:
        html = _tables.get(str(token or ""))
    if not html:
        raise ApiError(400, "That table is no longer open for editing. "
                            "Reload the work item and try again.")
    parser = _TableGrid()
    parser.feed(html)
    grid = parser.result()
    if not grid:
        raise ApiError(400, "That table has no rows to change.")
    width = max(len(r["cells"]) for r in grid)
    try:
        row = max(0, min(int(row), len(grid) - 1))
        col = max(0, min(int(col), width - 1))
    except (TypeError, ValueError):
        raise ApiError(400, "Bad row or column.")
    if op == "setCell":
        if col >= len(grid[row]["cells"]):
            raise ApiError(400, "That cell is not in the table.")
        grid[row]["cells"][col]["inner"] = _cell_inner(text)
    elif op == "addRow":
        if len(grid) >= MAX_TABLE_ROWS:
            raise ApiError(400, "A table here is limited to {} rows."
                                .format(MAX_TABLE_ROWS))
        # A row added under the header belongs to the body, not the header.
        sect = grid[row]["sect"]
        if sect == "thead":
            sect = grid[row + 1]["sect"] if row + 1 < len(grid) else "tbody"
        grid.insert(row + 1, {"sect": sect,
                              "cells": [_blank_cell() for _ in range(width)]})
    elif op == "delRow":
        if len(grid) <= 1:
            raise ApiError(400, "Remove the whole table rather than its last "
                                "row.")
        grid.pop(row)
    elif op == "addCol":
        if width >= MAX_TABLE_COLS:
            raise ApiError(400, "A table here is limited to {} columns."
                                .format(MAX_TABLE_COLS))
        for line in grid:
            cells = line["cells"]
            tag = cells[0]["tag"] if cells else "td"
            cells.insert(min(col + 1, len(cells)), _blank_cell(tag))
    elif op == "delCol":
        if width <= 1:
            raise ApiError(400, "Remove the whole table rather than its last "
                                "column.")
        for line in grid:
            if col < len(line["cells"]):
                line["cells"].pop(col)
        grid = [line for line in grid if line["cells"]]
        if not grid:
            raise ApiError(400, "That would leave nothing of the table.")
    built = _grid_html(grid)
    return {"token": _register_table(built), "html": built, "rows": len(grid),
            "cols": max(len(r["cells"]) for r in grid)}


def _comment_images(text):
    """Attachment images already embedded in a comment, so an edit keeps them.

    The HTML is read back from Azure DevOps rather than trusted from the page,
    so this cannot be used to smuggle an arbitrary image source into a comment.
    """
    found = []
    for src in re.findall(r'<img[^>]*\ssrc="([^"]*)"', text or "", re.I):
        src = unescape(src)
        if _is_ado_url(src) and src not in found:
            found.append(src)
    return found[:20]


def _kept_preview(text):
    """What an edit of this comment would carry over, ready to show.

    Images become opaque /img proxy keys rather than raw attachment URLs, so
    the page still cannot name a source of its own. The table HTML has already
    been through _TableCleaner.
    """
    images = []
    for i, src in enumerate(_comment_images(text)):
        name = ""
        query = urllib.parse.urlparse(src).query
        for candidate in ("fileName", "filename"):
            value = urllib.parse.parse_qs(query).get(candidate)
            if value:
                name = value[0]
                break
        images.append({"key": res_key(src),
                       "name": name or "Image {}".format(i + 1)})
    tables = [{"token": _register_table(html), "html": html}
              for html in _comment_tables(text)]
    return {"images": images, "tables": tables}


def _tables_for_edit(current, changes):
    """Decide which tables an edit ends up with.

    A page that understands table editing sends back the tokens of the tables
    it still wants, which is how a deleted row stays deleted. Anything else and
    the tables already in the field are carried over exactly as they were, so
    an older page cannot quietly drop them by saying nothing. Either way every
    table is markup this server built and stored itself.
    """
    chosen = changes.get("keptTables")
    tables = (_allowed_tables(chosen) if chosen is not None
              else _comment_tables(current))
    for table in _allowed_tables(changes.get("tables")):
        if table not in tables:
            tables.append(table)
    return tables


def _own_comment_path(item_id, comment_id, project):
    """Locate a comment and refuse it unless the signed-in user wrote it.

    Azure DevOps enforces this too; checking here turns a raw 401 into a clear
    message and keeps the rule in one place for both edit and delete.
    """
    path = ("{}/_apis/wit/workItems/{}/comments/{}?api-version=7.1-preview.4"
            .format(urllib.parse.quote(project or PROJECT), int(item_id),
                    int(comment_id)))
    existing = call(path)
    mine_id = my_identity_id()
    author = (existing.get("createdBy") or {}).get("id") or ""
    if mine_id and author and author != mine_id:
        raise ApiError(403, "Azure DevOps only lets you change your own "
                            "comments.")
    return path, existing


def delete_comment(item_id, comment_id, project=None):
    """Delete one of the signed-in user's own Discussion comments."""
    path, _ = _own_comment_path(item_id, comment_id, project)
    call(path, method="DELETE")
    return {"ok": True, "deleted": int(comment_id)}


def edit_comment(item_id, comment_id, changes):
    """Rewrite one of the signed-in user's own Discussion comments."""
    path, existing = _own_comment_path(item_id, comment_id,
                                       changes.get("project"))
    kept = _comment_images(existing.get("text", ""))
    added = [src for src in _allowed_images(changes.get("images"))
             if src not in kept]
    body = build_comment_html((changes.get("comment") or "").strip(),
                              changes.get("mentions"), changes.get("html"))
    for table in _tables_for_edit(existing.get("text", ""), changes):
        body += ("<br>" if body else "") + table
    for src in kept + added:
        if body:
            body += "<br>"
        body += '<img src="{}" style="max-width:100%">'.format(_esc_html(src))
    if not body:
        raise ApiError(400, "A comment cannot be empty. Delete it in Azure "
                            "DevOps if that is what you meant.")
    call(path, {"text": body}, method="PATCH")
    return {"ok": True, "images": len(kept) + len(added)}


DESC_FIELDS = ("System.Description", "Microsoft.VSTS.TCM.ReproSteps")


def edit_description(item_id, changes):
    """Rewrite a work item's Description (or Repro Steps).

    Like a comment edit, the images and tables already in the field are read
    back from Azure DevOps and re-attached, so replacing the wording cannot
    silently discard the screenshots that explain it.
    """
    field = changes.get("field") or "System.Description"
    if field not in DESC_FIELDS:
        raise ApiError(400, "Field not editable here: {}".format(field))
    project = changes.get("project") or PROJECT
    base = "{}/_apis/wit/workitems/{}?api-version={}".format(
        urllib.parse.quote(project), int(item_id), API)
    current = (call(base).get("fields") or {}).get(field, "") or ""
    kept = _comment_images(current)
    body = build_comment_html((changes.get("text") or "").strip(),
                              changes.get("mentions"), changes.get("html"))
    for table in _tables_for_edit(current, changes):
        body += ("<br>" if body else "") + table
    added = [src for src in _allowed_images(changes.get("images"))
             if src not in kept]
    for src in kept + added:
        if body:
            body += "<br>"
        body += '<img src="{}" style="max-width:100%">'.format(_esc_html(src))
    call(base, [{"op": "add", "path": "/fields/" + field, "value": body}],
         method="PATCH", patch=True)
    return {"ok": True, "field": field, "images": len(kept) + len(added)}


def _annotate_links(links):
    """Resolve titles and states for linked work items in one batch call."""
    ids = [l["target"] for l in links if not l["external"] and l["target"]]
    if not ids:
        return
    try:
        got = call("_apis/wit/workitemsbatch?api-version={}".format(API), {
            "ids": [int(i) for i in ids[:200]],
            "fields": ["System.Id", "System.Title", "System.State",
                       "System.WorkItemType"],
        })
    except ApiError:
        return
    by_id = {str(w.get("id")): w.get("fields", {}) for w in got.get("value", [])}
    for link in links:
        f = by_id.get(link["target"])
        if f:
            link["label"] = "#{} {}".format(link["target"],
                                            f.get("System.Title", ""))
            link["state"] = f.get("System.State", "")
            link["type"] = f.get("System.WorkItemType", "")


def search_items(query="", include_closed=True, top=100, scope="created"):
    """Search work items.

    scope: created (by me), assigned (to me), followed (by me) or all.
    """
    query = (query or "").strip()
    if query.isdigit():
        try:
            item = call("{}/_apis/wit/workitems/{}?api-version={}".format(
                urllib.parse.quote(PROJECT), int(query), API))
        except ApiError:
            return []
        f = item.get("fields", {})
        return [{
            "id": item.get("id"),
            "type": f.get("System.WorkItemType", ""),
            "title": f.get("System.Title", ""),
            "state": f.get("System.State", ""),
            "assignedTo": identity_name(f.get("System.AssignedTo")),
            "createdBy": identity_name(f.get("System.CreatedBy")),
            "changedDate": f.get("System.ChangedDate", ""),
            "tags": f.get("System.Tags", ""),
            "url": "https://dev.azure.com/{}/{}/_workitems/edit/{}".format(
                ORG, PROJECT, item.get("id")),
        }]

    display = my_display_name()
    where = []
    if scope != "followed":
        where.append("[System.TeamProject] = '{}'".format(PROJECT.replace("'", "''")))
    if scope == "created":
        # Two disjoint storage shapes for CreatedBy, so match both.
        creator = ["[System.CreatedBy] = @Me"]
        if display:
            creator.append("[System.CreatedBy] CONTAINS '{}'".format(
                display.replace("'", "''")))
        where.append("({})".format(" OR ".join(creator)))
    elif scope == "assigned":
        where.append("[System.AssignedTo] = @Me")
    elif scope == "followed":
        ids = followed_ids()
        if not ids:
            return []
        where.append("[System.Id] IN ({})".format(
            ",".join(str(i) for i in ids[:500])))
    elif scope != "all":
        raise ApiError(400, "Unknown scope: {}".format(scope))
    if query:
        where.append("[System.Title] CONTAINS '{}'".format(query.replace("'", "''")))
    if not include_closed:
        where.append("[System.State] NOT IN ('Closed', 'Removed', 'Done')")
    if scope == "all" and not query:
        raise ApiError(400, "Enter a search term or work item ID to search all "
                            "of {}.".format(PROJECT))
    wiql = ("SELECT [System.Id] FROM WorkItems WHERE {} "
            "ORDER BY [System.ChangedDate] DESC".format(" AND ".join(where)))
    # Follows are not confined to one project, so that query runs org-wide.
    prefix = "" if scope == "followed" else urllib.parse.quote(PROJECT) + "/"
    result = call("{}_apis/wit/wiql?api-version={}&$top={}".format(
        prefix, API, top), {"query": wiql})
    ids = [int(x["id"]) for x in result.get("workItems", [])][:top]
    return _hydrate(ids)


def _hydrate(ids):
    if not ids:
        return []
    items = []
    for start in range(0, len(ids), 200):
        batch = call("_apis/wit/workitemsbatch?api-version=" + API,
                     {"ids": ids[start:start + 200], "fields": FIELDS})
        items.extend(batch.get("value", []))
    order = {wid: pos for pos, wid in enumerate(ids)}
    items.sort(key=lambda it: order.get(it.get("id"), 0))
    return [{
        "id": it.get("id"),
        "type": it["fields"].get("System.WorkItemType", ""),
        "title": it["fields"].get("System.Title", ""),
        "state": it["fields"].get("System.State", ""),
        "assignedTo": identity_name(it["fields"].get("System.AssignedTo")),
        "createdBy": identity_name(it["fields"].get("System.CreatedBy")),
        "changedDate": it["fields"].get("System.ChangedDate", ""),
        "changedBy": identity_name(it["fields"].get("System.ChangedBy")),
        "changedById": identity_id(it["fields"].get("System.ChangedBy")),
        "assignedToId": identity_id(it["fields"].get("System.AssignedTo")),
        "tags": it["fields"].get("System.Tags", ""),
        "project": it["fields"].get("System.TeamProject", ""),
        "url": "https://dev.azure.com/{}/{}/_workitems/edit/{}".format(
            ORG, urllib.parse.quote(
                it["fields"].get("System.TeamProject") or PROJECT),
            it.get("id")),
    } for it in items]


# --------------------------------------------------------------------------
# Comment notifications
# --------------------------------------------------------------------------

def _load_seen():
    """Return (comment ids per item, last known state/assignee per item)."""
    try:
        with open(SEEN_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        comments = {str(k): set(v) for k, v in data.get("comments", {}).items()}
        fields = {str(k): dict(v) for k, v in (data.get("fields") or {}).items()
                  if isinstance(v, dict)}
        return comments, fields
    except (IOError, OSError, ValueError, TypeError):
        return {}, {}


def _save_seen(seen, fields):
    try:
        with open(SEEN_PATH, "w", encoding="utf-8") as handle:
            json.dump({"comments": {k: sorted(v) for k, v in seen.items()},
                       "fields": fields}, handle)
    except (IOError, OSError):
        pass


def fetch_comments(item_id, project=None):
    data = call("{}/_apis/wit/workItems/{}/comments?api-version=7.1-preview.4"
                "&$top=200".format(urllib.parse.quote(project or PROJECT),
                                   int(item_id)))
    return data.get("comments", []) or []


def toast(title, message):
    """Best-effort Windows toast; falls back to stdout elsewhere."""
    if sys.platform != "win32":
        print("[notify] {} - {}".format(title, message))
        return
    script = (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications,"
        " ContentType=WindowsRuntime] > $null;"
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument,"
        " ContentType=WindowsRuntime] > $null;"
        "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
        "[Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
        "$n=$t.GetElementsByTagName('text');"
        "$n.Item(0).AppendChild($t.CreateTextNode($env:CE_TOAST_TITLE)) > $null;"
        "$n.Item(1).AppendChild($t.CreateTextNode($env:CE_TOAST_BODY)) > $null;"
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
        "'{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe'"
        ").Show([Windows.UI.Notifications.ToastNotification]::new($t))"
    )
    env = dict(os.environ, CE_TOAST_TITLE=title[:120], CE_TOAST_BODY=message[:250])
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            env=env, timeout=25, capture_output=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        print("[notify] {} - {}".format(title, message))


IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".tif",
             ".tiff", ".ico")

# Scoped to this organisation on purpose. "*.dev.azure.com" and
# "*.visualstudio.com" are multi-tenant namespaces that anyone can register an
# organisation in, so allowing them would not establish that a URL is trusted.
_ORG_HOSTS = ("dev.azure.com", "{}.visualstudio.com".format(ORG.lower()))


def _is_ado_url(url):
    try:
        parts = urllib.parse.urlparse(url)
    except ValueError:
        return False
    if parts.scheme != "https":
        return False
    host = (parts.hostname or "").lower()
    if host not in _ORG_HOSTS:
        return False
    if host == "dev.azure.com":
        # https://dev.azure.com/<org>/... - the org segment must be ours.
        seg = [s for s in parts.path.split("/") if s]
        return bool(seg) and seg[0].lower() == ORG.lower()
    return True


# Attachment URLs are never accepted from the browser. The server hands out an
# opaque key for each URL it has itself decided is safe to proxy, and /img and
# /file resolve only keys found in this map. Without it, an <img src> written
# into any work item by any org member would steer an authenticated fetch.
_res_lock = threading.Lock()
_res_map = {}


def res_key(url):
    """Register a proxyable URL and return its opaque lookup key."""
    key = hmac.new(NONCE.encode("utf-8"), url.encode("utf-8"),
                   hashlib.sha256).hexdigest()[:32]
    with _res_lock:
        _res_map[key] = url
    return key


def res_url(key):
    with _res_lock:
        url = _res_map.get(key)
    if not url:
        raise ApiError(403, "Unknown resource.")
    return url


def _sniff_image(blob):
    """Identify an image from its magic bytes.

    Azure DevOps returns application/octet-stream for attachment URLs that
    carry no fileName parameter, even for real images, so the declared type
    cannot be trusted on its own.
    """
    if blob[:8].startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if blob[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if blob[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if blob[:2] == b"BM":
        return "image/bmp"
    if blob[:4] == b"RIFF" and blob[8:12] == b"WEBP":
        return "image/webp"
    if blob[:4] in (b"II*\x00", b"MM\x00*"):
        return "image/tiff"
    if blob[:4] == b"\x00\x00\x01\x00":
        return "image/x-icon"
    if blob[:5] == b"%PDF-":
        return "application/pdf"
    head = blob[:400].lstrip()[:200].lower()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
        return "image/svg+xml"
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never let urllib follow a redirect on its own.

    The stdlib handler copies every header except content-length/content-type
    onto the redirected request, so an unchecked hop would forward the user's
    Azure DevOps bearer token to whatever host the redirect names.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_no_redirect_opener = urllib.request.build_opener(_NoRedirect)


def fetch_binary(url):
    """Download an Azure DevOps attachment with the signed-in user's token."""
    if not _is_ado_url(url):
        raise ApiError(400, "Only Azure DevOps attachments can be proxied.")
    if not azdo_auth.have_credentials():
        raise ApiError(401, "Not signed in.")
    try:
        token = azdo_auth.get_access_token()
    except SystemExit as exc:
        raise ApiError(401, "Sign-in required: {}".format(exc))
    origin = (urllib.parse.urlparse(url).hostname or "").lower()
    for _ in range(5):
        req = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + token, "Accept": "*/*"})
        try:
            with _no_redirect_opener.open(req, timeout=60) as resp:
                return (resp.read(),
                        resp.headers.get("Content-Type",
                                         "application/octet-stream"))
        except urllib.error.HTTPError as exc:
            if exc.code not in (301, 302, 303, 307, 308):
                raise ApiError(exc.code,
                               "Attachment fetch failed ({}).".format(exc.code))
            target = exc.headers.get("Location") or ""
            exc.close()
            url = urllib.parse.urljoin(url, target)
            # Re-validate every hop, and never carry the token to a new host.
            if not _is_ado_url(url):
                raise ApiError(502, "Attachment redirect left Azure DevOps.")
            if (urllib.parse.urlparse(url).hostname or "").lower() != origin:
                raise ApiError(502, "Attachment redirect changed host.")
        except urllib.error.URLError as exc:
            raise ApiError(503, "Network error: {}".format(exc.reason))
    raise ApiError(502, "Too many attachment redirects.")


ALLOWED_TAGS = {
    "p", "br", "div", "span", "b", "strong", "i", "em", "u", "s", "strike",
    "sub", "sup", "a", "ul", "ol", "li", "table", "thead", "tbody", "tfoot",
    "tr", "td", "th", "caption", "h1", "h2", "h3", "h4", "h5", "h6",
    "blockquote", "code", "pre", "img", "hr", "font",
}
VOID_TAGS = {"br", "img", "hr"}
ALLOWED_ATTRS = {
    "a": {"href", "title"},
    "img": {"src", "alt", "width", "height", "title"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan"},
}


class _Sanitizer(HTMLParser):
    """Keep rich formatting and images, drop anything that can execute.

    Image sources that point at Azure DevOps are rewritten to this server's
    /img proxy, which re-requests them with the user's bearer token -- the
    browser cannot authenticate to dev.azure.com on its own.
    """

    def __init__(self, nonce):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.nonce = nonce
        self.out = []
        self.open_tags = []
        self.skip_depth = 0
        self.images = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in ("script", "style", "iframe", "object", "embed"):
            self.skip_depth += 1
            return
        if self.skip_depth or tag not in ALLOWED_TAGS:
            return
        kept = []
        allowed = ALLOWED_ATTRS.get(tag, set())
        for name, value in attrs:
            name = (name or "").lower()
            if name not in allowed or value is None:
                continue
            if tag == "a" and name == "href":
                if not re.match(r"(?i)^(https?:|mailto:)", value.strip()):
                    continue
            if tag == "img" and name == "src":
                value = self._image_src(value.strip())
                if not value:
                    return  # unusable image: drop the whole tag
                self.images += 1
            kept.append(' {}="{}"'.format(name, _esc_html(value)))
        if tag == "a":
            kept.append(' target="_blank" rel="noopener noreferrer"')
        self.out.append("<{}{}>".format(tag, "".join(kept)))
        if tag not in VOID_TAGS:
            self.open_tags.append(tag)

    def _image_src(self, src):
        if src.startswith("data:image/"):
            return src
        if _is_ado_url(src):
            return "/img?n={}&k={}".format(self.nonce, res_key(src))
        return ""

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in ("script", "style", "iframe", "object", "embed"):
            self.skip_depth = max(0, self.skip_depth - 1)
            return
        if self.skip_depth or tag in VOID_TAGS or tag not in ALLOWED_TAGS:
            return
        if tag in self.open_tags:
            while self.open_tags:
                open_tag = self.open_tags.pop()
                self.out.append("</{}>".format(open_tag))
                if open_tag == tag:
                    break

    def handle_data(self, data):
        if not self.skip_depth:
            self.out.append(_esc_html(data))

    def result(self):
        while self.open_tags:
            self.out.append("</{}>".format(self.open_tags.pop()))
        return "".join(self.out)


def safe_html(text):
    """Sanitise Azure DevOps rich text for display, preserving images."""
    if not (text or "").strip():
        return ""
    parser = _Sanitizer(NONCE)
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        return _esc_html(_strip_html(text))
    return parser.result()


class _PlainText(HTMLParser):
    """Flatten work item HTML to text that still carries its layout.

    _strip_html collapses every run of whitespace, newlines included, which is
    right for a one-line preview but destroys a comment the moment you open it
    for editing. This keeps line breaks, blank lines between paragraphs, and
    list bullets, so what build_comment_html writes back matches what was
    there before.

    Images and tables are skipped on purpose: they are preserved separately
    and re-attached on save, so including their text here would duplicate
    them.
    """

    BLOCKS = ("p", "div", "tr", "ul", "ol", "blockquote", "pre",
              "h1", "h2", "h3", "h4", "h5", "h6")
    SKIP = ("script", "style", "table")

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.out = []
        self.skip_depth = 0
        self.lists = []
        self.fresh = True

    def _break(self):
        """End the current line, but never open a blank one on its own.

        Block tags come in pairs, so </div><div> would otherwise double-space
        every line of an Azure DevOps description.
        """
        if not self.fresh:
            self.out.append("\n")
            self.fresh = True

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self.SKIP:
            self.skip_depth += 1
            return
        if self.skip_depth:
            return
        if tag == "br":
            # An explicit break is the author's, so it always counts: two in a
            # row are a deliberate blank line.
            self.out.append("\n")
            self.fresh = True
        elif tag in ("ul", "ol"):
            self.lists.append([tag, 0])
            self._break()
        elif tag == "li":
            self._break()
            if self.lists and self.lists[-1][0] == "ol":
                self.lists[-1][1] += 1
                self.out.append("{}. ".format(self.lists[-1][1]))
            else:
                self.out.append("- ")
            self.fresh = False
        elif tag in self.BLOCKS:
            self._break()

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self.SKIP:
            self.skip_depth = max(0, self.skip_depth - 1)
            return
        if self.skip_depth:
            return
        if tag in ("ul", "ol"):
            if self.lists:
                self.lists.pop()
            self._break()
        elif tag in self.BLOCKS:
            self._break()

    def handle_data(self, data):
        if self.skip_depth:
            return
        # Collapse runs of spaces and tabs but never the newlines added above:
        # HTML source indentation must not turn into blank lines in the editor.
        text = re.sub(r"[ \t\r\f\v]+", " ", data.replace("\n", " "))
        if not text.strip() and self.fresh:
            return
        self.out.append(text)
        self.fresh = False

    def result(self):
        text = "".join(self.out).replace("\xa0", " ")
        lines = [line.strip() for line in text.split("\n")]
        out, blanks = [], 0
        for i, line in enumerate(lines):
            if line:
                blanks = 0
                out.append(line)
                continue
            blanks += 1
            # A blank line before a list is markup spacing, not the author's
            # layout; dropping it keeps a second edit identical to the first.
            following = next((n for n in lines[i + 1:] if n), "")
            if _BULLET.match(following) or _NUMBER.match(following):
                continue
            if blanks == 1 and out:
                out.append("")
        return "\n".join(out).strip()


def to_plain_text(text):
    """HTML to editable text, keeping the layout. Falls back to a flat strip."""
    parser = _PlainText()
    try:
        parser.feed(text or "")
        parser.close()
    except Exception:
        return _strip_html(text)
    return parser.result()


def _strip_html(text):
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text or "")
    text = re.sub(r"(?i)<br\s*/?>|</p>|</div>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\s+", " ", text.replace("&nbsp;", " ")
                  .replace("&amp;", "&").replace("&lt;", "<")
                  .replace("&gt;", ">")).strip()


def _push_note(item, kind, author, text, at=""):
    """Add one entry to the in-page notification feed."""
    entry = {
        "workItemId": item["id"],
        "title": item["title"],
        "kind": kind,
        "author": author,
        "text": text,
        "at": at or item.get("changedDate", ""),
        "url": item["url"],
    }
    with _feed_lock:
        _feed.insert(0, entry)
        del _feed[FEED_LIMIT:]


def _check_field_changes(item, item_id, tracked, mine_id, first_pass):
    """Notify when State or Assigned To moved since the last poll.

    The first run only records a baseline, so a fresh install never fires a
    burst of toasts for history the user has already seen.
    """
    current = {"state": item.get("state") or "",
               "assignedTo": item.get("assignedTo") or "",
               "assignedToId": item.get("assignedToId") or ""}
    previous = tracked.get(item_id)
    tracked[item_id] = current
    if previous is None or first_pass:
        return
    who = item.get("changedBy") or "Someone"
    # Skip our own edits: the board already showed the result of those.
    # Identities are matched on id because the profile display name
    # ("Ayden Foo") and the work item one ("Foo, Ayden") differ.
    mine = bool(mine_id) and item.get("changedById") == mine_id
    if previous.get("state") != current["state"]:
        change = "{} -> {}".format(previous.get("state") or "(none)",
                                   current["state"] or "(none)")
        _push_note(item, "state", who, "State: " + change)
        if not mine:
            toast("State changed on {}".format(item["id"]),
                  "{} ({})".format(change, who))
    if previous.get("assignedToId", previous.get("assignedTo")) != current["assignedToId"]:
        if "assignedToId" not in previous:
            return  # upgraded snapshot: this poll only re-baselines the owner
        new_owner = current["assignedTo"] or "(unassigned)"
        to_me = bool(mine_id) and current["assignedToId"] == mine_id
        change = "{} -> {}".format(previous.get("assignedTo") or "(unassigned)",
                                   new_owner)
        _push_note(item, "assigned", who,
                   ("Assigned to you" if to_me else "Assigned") + ": " + change)
        if to_me or not mine:
            toast(("Assigned to you: {}" if to_me else "Reassigned: {}")
                  .format(item["id"]),
                  "{} ({})".format(change, who))


def poll_comments(interval, stop_event):
    """Watch open items for new comments, state changes and reassignments."""
    seen, tracked = _load_seen()
    first_pass = not seen and not tracked
    mine_id = ""
    while not stop_event.is_set():
        try:
            # Before first sign-in there is nothing to poll; wait quietly
            # rather than triggering a blocking console device-code prompt.
            if not azdo_auth.have_credentials():
                stop_event.wait(interval)
                continue
            if not mine_id:
                mine_id = my_identity_id()
            items = list_items(open_only=True)
            active_ids = set()
            for item in items:
                item_id = str(item["id"])
                active_ids.add(item_id)
                _check_field_changes(item, item_id, tracked, mine_id, first_pass)
                known = seen.setdefault(item_id, set())
                try:
                    comments = fetch_comments(item_id)
                except ApiError:
                    continue
                for comment in comments:
                    cid = str(comment.get("id"))
                    if cid in known:
                        continue
                    known.add(cid)
                    by = comment.get("createdBy") or {}
                    author = by.get("displayName") or "Someone"
                    # Seeding the very first run would fire a burst of toasts for
                    # history the user has already read.
                    if first_pass or (mine_id and by.get("id") == mine_id):
                        continue
                    body = _strip_html(comment.get("text", ""))[:200]
                    _push_note(item, "comment", author, body,
                               comment.get("createdDate", ""))
                    toast("New comment on {}".format(item["id"]),
                          "{}: {}".format(author, body))
            # Drop state for items that closed so the file cannot grow forever.
            for stale in set(seen) - active_ids:
                seen.pop(stale, None)
            for stale in set(tracked) - active_ids:
                tracked.pop(stale, None)
            _save_seen(seen, tracked)
            first_pass = False
        except Exception as exc:
            print("[poll] {}".format(exc))
            sys.stdout.flush()
        stop_event.wait(interval)


# Raw string: this is JavaScript/CSS, so backslash escapes such as \n in regexes
# must reach the browser intact rather than being consumed by Python.
PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>My Azure DevOps CEs</title>
<link rel="icon" href="/favicon.ico">
<link rel="apple-touch-icon" href="/favicon.ico">
<style>
 :root{color-scheme:light dark}
 body{font:14px/1.5 system-ui,Segoe UI,sans-serif;margin:0;background:#f6f8fa;color:#1f2328}
 header{background:#24292f;color:#fff;padding:14px 20px;display:flex;gap:16px;align-items:center;flex-wrap:wrap}
 header h1{font-size:16px;margin:0;font-weight:600}
 header .sp{flex:1}
 main{padding:20px;max-width:1100px;margin:0 auto}
 .card{background:#fff;border:1px solid #d0d7de;border-radius:8px;margin-bottom:12px}
 .row{display:flex;gap:12px;align-items:center;padding:12px 14px;cursor:pointer}
 .row:hover{background:#f6f8fa}
 .id{font-family:ui-monospace,Consolas,monospace;color:#0969da;font-weight:600;min-width:74px}
 .title{flex:1;font-weight:500}
 .pill{font-size:12px;padding:2px 9px;border-radius:12px;border:1px solid #d0d7de;white-space:nowrap}
 .New{background:#ddf4ff;border-color:#54aeff}
 .Active{background:#fff8c5;border-color:#d4a72c}
 .Implemented{background:#dafbe1;border-color:#4ac26b}
 .who{color:#656d76;font-size:12px;min-width:130px}
 .edit{display:none;padding:14px;border-top:1px solid #d0d7de;background:#f6f8fa}
 .edit.open{display:block}
 label{display:block;font-size:12px;color:#656d76;margin:8px 0 3px}
 input,select,textarea{width:100%;padding:7px 9px;border:1px solid #d0d7de;border-radius:6px;font:inherit;background:#fff;color:inherit;box-sizing:border-box}
 textarea{min-height:64px;resize:vertical}
.ctext{min-height:150px;max-height:60vh;line-height:1.5;resize:vertical;overflow-y:auto;
   width:100%;padding:7px 9px;border:1px solid #d0d7de;border-radius:0 0 6px 6px;
   background:#fff;color:inherit;box-sizing:border-box;text-align:left}
 .ctext:focus{outline:none;border-color:#0969da}
 .ctext ul,.ctext ol{margin:4px 0;padding-left:26px}
 .ctext blockquote{margin:0 0 0 40px;border:0;padding:0}
 .ctext:empty:before{content:attr(data-ph);color:#8c959f}
 .rtb{display:flex;gap:2px;flex-wrap:wrap;align-items:center;padding:4px 6px;
   border:1px solid #d0d7de;border-bottom:0;border-radius:6px 6px 0 0;background:#f6f8fa}
 .rtb button{width:auto;min-width:28px;height:26px;padding:0 7px;font-size:13px;line-height:1;
   background:transparent;border:1px solid transparent;border-radius:5px;color:#1f2328;cursor:pointer}
 .rtb button:hover{background:#eaeef2;border-color:#d0d7de}
 .rtb .sep{width:1px;height:18px;background:#d0d7de;margin:0 4px}
 .rtb .hl{background:#fff29a;border-color:#e6d98a}
.chint{float:right;font-size:11px;color:#8c959f;font-weight:400}
.pastes{display:flex;flex-wrap:wrap;gap:8px;margin:6px 0 0}
.paste{position:relative;display:inline-flex;align-items:center;border:1px solid #d0d7de;
      border-radius:6px;padding:2px;background:#fff}
.paste img{max-height:72px;max-width:120px;border-radius:4px;cursor:zoom-in;display:block}
.paste a{position:absolute;top:-8px;right:-8px;width:18px;height:18px;line-height:16px;
        text-align:center;border-radius:50%;background:#57606a;color:#fff;font-size:13px;
        text-decoration:none}
.paste.busy{padding:6px 10px;font-size:12px;color:#57606a}
.paste.tbl{flex-direction:column;align-items:stretch;padding:4px 6px;max-width:280px}
.tprev{display:block;max-height:90px;max-width:268px;overflow:auto;font-size:10px}
.tprev table{border-collapse:collapse}
.tprev td,.tprev th{border:1px solid #d0d7de;padding:1px 4px;white-space:nowrap}
.tcap{font-size:11px;color:#57606a;margin-top:3px}
.kind{display:inline-block;font-size:10px;text-transform:uppercase;letter-spacing:.4px;
      border-radius:8px;padding:1px 7px;margin-right:6px;background:#ddf4ff;color:#0969da}
.kind.state{background:#fff1e5;color:#bc4c00}
.kind.assigned{background:#dafbe1;color:#1a7f37}
 .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
 .acts{margin-top:12px;display:flex;gap:8px;align-items:center}
 button{background:#1f883d;color:#fff;border:0;padding:8px 16px;border-radius:6px;cursor:pointer;font:inherit;font-weight:500}
 button.sec{background:#f6f8fa;color:#24292f;border:1px solid #d0d7de}
 button:disabled{opacity:.6;cursor:default}
 .msg{font-size:13px}.ok{color:#1a7f37}.err{color:#cf222e}
 .empty{padding:40px;text-align:center;color:#656d76}
 a.ext{color:#0969da;font-size:12px}
 .bar{display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
 .bar input[type=search]{flex:1;min-width:220px;padding:8px 11px;border:1px solid #d0d7de;border-radius:6px}
 .bar label{margin:0;display:flex;gap:5px;align-items:center;font-size:13px;color:#1f2328}
 .bar input[type=checkbox]{width:auto}
 .bar select{padding:8px 10px;border:1px solid #d0d7de;border-radius:6px;background:#fff}
 .who i{display:block;font-style:normal;font-size:11px;opacity:.75}
 #feed{background:#fff;border:1px solid #d0d7de;border-radius:8px;margin-bottom:14px;display:none}
 #feed.show{display:block}
 #feed h2{font-size:13px;margin:0;padding:10px 14px;border-bottom:1px solid #d0d7de;display:flex;align-items:center;gap:8px}
 .note{padding:10px 14px;border-bottom:1px solid #f0f2f4;font-size:13px}
 .note:last-child{border-bottom:0}
 .note b{color:#0969da}
 .note .meta{color:#656d76;font-size:12px}
 .badge{background:#cf222e;color:#fff;border-radius:10px;padding:1px 7px;font-size:11px}
 .note{cursor:pointer}
 .note:hover{background:#f6f8fa}
 .detail{background:#f6f8fa;border:1px solid #d0d7de;border-radius:6px;padding:12px;margin-bottom:14px;font-size:13px}
 .meta-grid{display:grid;grid-template-columns:auto 1fr;gap:3px 12px;margin-bottom:10px}
 .k{color:#656d76;font-size:12px;font-weight:600}
 .desc{white-space:pre-wrap;border-top:1px solid #d8dee4;padding-top:10px;margin-bottom:10px;max-height:220px;overflow:auto;color:#1f2328}
 .thread{border-top:1px solid #d8dee4;padding-top:10px;max-height:260px;overflow:auto}
 .cm{background:#fff;border:1px solid #d0d7de;border-radius:6px;padding:8px 10px;margin-top:8px;white-space:pre-wrap}
 .cm .meta{color:#656d76;font-size:12px;display:block;margin-bottom:4px}
 .cwrap{position:relative}
 .mbox{display:none;position:absolute;z-index:20;left:0;right:0;top:100%;background:#fff;border:1px solid #d0d7de;border-radius:6px;box-shadow:0 8px 24px rgba(31,35,40,.2);max-height:200px;overflow:auto}
 .mbox.show{display:block}
 .mrow{padding:7px 10px;cursor:pointer;font-size:13px;display:flex;flex-direction:column}
 .mrow span{color:#656d76;font-size:12px}
 .mrow.on,.mrow:hover{background:#ddf4ff}
 .cm a{color:#0969da;font-weight:600;text-decoration:none}
 .rich{white-space:normal}
 .rich img{max-width:100%;height:auto;border:1px solid #d0d7de;border-radius:6px;margin:6px 0;cursor:zoom-in;background:#fff}
 .rich table{border-collapse:collapse;margin:6px 0;font-size:13px}
 .rich td,.rich th{border:1px solid #d0d7de;padding:4px 8px}
 .rich pre{background:#f6f8fa;padding:8px;border-radius:6px;overflow:auto}
 .rich p{margin:6px 0}
 .rich a{color:#0969da}
 .pastes.kept{margin-top:2px}
    .paste.tbl.tedit{max-width:100%;background:#fff}
    .tedit .tprev{max-height:280px;max-width:100%;font-size:12px}
    .tedit .tprev td,.tedit .tprev th{white-space:pre-wrap;min-width:46px;padding:2px 6px}
    .tedit .tprev td:focus,.tedit .tprev th:focus{outline:2px solid #0969da}
    .tedit .cellsel{background:#ddf4ff}
    .ttools{display:flex;gap:12px;margin-top:5px;font-size:11px;align-items:center}
    .ttools a{color:#0969da;text-decoration:none}
    .ttools a:hover{text-decoration:underline}
    .ttools a.warn{color:#cf222e;margin-left:auto}
.pastes.kept .paste{opacity:.85}
.pastes.kept img{cursor:zoom-in}
.shots{display:flex;flex-wrap:wrap;gap:10px;margin:8px 0 12px}
 .shots figure{margin:0;width:130px}
 .shots img{width:130px;height:90px;object-fit:cover;border:1px solid #d0d7de;border-radius:6px;cursor:zoom-in;background:#fff}
 .shots figcaption{font-size:11px;color:#656d76;margin-top:3px;word-break:break-all;line-height:1.3}
 .files{display:flex;flex-direction:column;gap:2px;margin:4px 0 10px}
 .frow{display:flex;align-items:center;gap:8px;padding:4px 6px;border-radius:6px;font-size:12.5px}
 .frow:hover{background:#f6f8fa}
 .fname{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#1f2328;text-decoration:none}
 a.fname{color:#0969da}
 .fsize{color:#656d76;font-size:11px;white-space:nowrap}
 .fdl{color:#0969da;text-decoration:none;font-size:12px;white-space:nowrap}
 .fdl:hover{text-decoration:underline}
 .ltype{font-size:11px;color:#656d76;background:#f6f8fa;border:1px solid #d0d7de;border-radius:10px;padding:1px 7px;white-space:nowrap}
 .proj{font-size:11px;color:#8250df;background:#fbefff;border:1px solid #e2c5ff;border-radius:10px;padding:1px 7px;white-space:nowrap;flex-shrink:0}
 button.link{background:none;border:0;color:#656d76;cursor:pointer;font-size:11px;padding:2px 4px}
 button.link.danger:hover{color:#cf222e;text-decoration:underline}
.meta a.danger{color:#8b949e}
.meta a.danger:hover{color:#cf222e}
 .drop{border:1px dashed #8c959f;border-radius:6px;padding:10px;text-align:center;font-size:12px;color:#656d76;margin-bottom:12px}
 .drop.over{border-color:#0969da;background:#ddf4ff;color:#0969da}
 .pick{color:#0969da;cursor:pointer;text-decoration:underline}
 .addlink{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
 .addlink select{font-size:12px;padding:4px}
 .addlink input{flex:1;min-width:180px;font-size:12px;padding:5px 8px;border:1px solid #d0d7de;border-radius:6px}
 .up{font-size:11px;color:#656d76}
 #lb{display:none;position:fixed;inset:0;z-index:100;background:rgba(13,17,23,.85);align-items:center;justify-content:center;cursor:zoom-out}
 #lb.show{display:flex}
 #lb img{max-width:92vw;max-height:92vh;border-radius:6px;box-shadow:0 12px 40px rgba(0,0,0,.5)}
 #signin{display:none;background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:22px;text-align:center}
 #signin.show{display:block}
 #signin h2{margin:0 0 8px;font-size:17px}
 #signin p{color:#656d76;font-size:13px;margin:0 0 16px}
 #app.hide{display:none}
 .code{font-family:ui-monospace,Consolas,monospace;font-size:30px;letter-spacing:4px;background:#f6f8fa;border:1px dashed #8c959f;border-radius:8px;padding:12px 18px;display:inline-block;margin:10px 0;user-select:all}
 .step{font-size:13px;color:#1f2328;margin:6px 0}
</style></head><body>
<header>
 <h1>My Azure DevOps work items</h1>
 <span id="who" style="font-size:12px;opacity:.8"></span>
 <span class="sp"></span>
 <label style="display:flex;gap:6px;align-items:center;font-size:13px;color:#fff;margin:0">
   <input type="checkbox" id="openOnly" checked style="width:auto"> open only</label>
 <button class="sec" id="refresh">Refresh</button>
</header>
<main>
 <div id="signin"><h2>Sign in to Azure DevOps</h2>
   <p>This dashboard needs a one-time Microsoft sign-in. No password or token is
      stored here &mdash; only a refresh token in your own user profile.</p>
   <div id="signinBody"><button id="signinBtn">Sign in</button></div>
 </div>
 <div id="app">
 <div id="feed"><h2>New comments <span class="badge" id="fcount">0</span>
   <span style="flex:1"></span>
   <button class="sec" style="padding:3px 10px;font-size:12px" onclick="clearFeed()">Dismiss</button></h2>
   <div id="feedItems"></div></div>
 <div class="bar">
   <input type="search" id="q" placeholder="Search by title, or type a work item ID...">
   <select id="scope" title="Which work items to search">
     <option value="created">Created by me</option>
     <option value="assigned">Assigned to me</option>
     <option value="followed">Followed by me</option>
     <option value="all">All of this project</option>
   </select>
   <label><input type="checkbox" id="incClosed"> include closed</label>
   <button class="sec" id="searchBtn">Search</button>
   <button class="sec" id="clearBtn">Clear</button>
 </div>
 <div id="list" class="empty">Loading...</div>
 </div>
</main>
<div id="lb" onclick="this.classList.remove('show')"><img id="lbimg" alt=""></div>
<script>
const NONCE = "__NONCE__";
const PROJECT = "__PROJECT__";
function zoom(src) {
  document.getElementById("lbimg").src = src;
  document.getElementById("lb").classList.add("show");
}
document.addEventListener("keydown", e => {
  if (e.key === "Escape") document.getElementById("lb").classList.remove("show");
});
// Inline images inside rich text are click-to-zoom too.
document.addEventListener("click", e => {
  const t = e.target;
  if (t && t.tagName === "IMG" && t.closest(".rich")) zoom(t.src);
});
const api = (p, opt = {}) => fetch(p, {
    ...opt, headers: {"x-ce-nonce": NONCE, "Content-Type": "application/json", ...(opt.headers || {})}
  }).then(async r => { const t = await r.text(); let d = {}; try { d = t ? JSON.parse(t) : {}; } catch (e) { d = {error: t}; }
    if (!r.ok) throw new Error(d.error || r.status); return d; });
const esc = s => (s || "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let items = [];
let scopeUsed = "created";

function render() {
  const el = document.getElementById("list");
  if (!items.length) { el.className = "empty"; el.textContent = "No work items found."; return; }
  el.className = "";
  el.innerHTML = items.map(w => `
    <div class="card" data-id="${w.id}">
      <div class="row" onclick="toggle(${w.id})">
        <span class="id">${w.id}</span>
        <span class="pill ${esc(w.state)}">${esc(w.state)}</span>
        ${w.project && w.project !== PROJECT ? `<span class="proj">${esc(w.project)}</span>` : ""}
        <span class="title">${esc(w.title)}</span>
        <span class="who">${esc(w.assignedTo) || "unassigned"}${
          scopeUsed !== "created" && w.createdBy ? `<i>by ${esc(w.createdBy)}</i>` : ""}</span>
      </div>
      <div class="edit" id="e${w.id}">
        <div class="detail" id="d${w.id}">Loading details...</div>
        <label>Title</label><input id="t${w.id}" value="${esc(w.title)}">
        <div class="grid">
          <div><label>State</label><select id="s${w.id}"></select></div>
          <div><label>Assigned to (email, blank to unassign)</label>
               <input id="a${w.id}" value="${esc(w.assignedTo)}"></div>
        </div>
        <label>Comment (added to Discussion) &mdash; type @ to tag someone,
          paste a screenshot to attach it
          <span class="chint">drag the corner to resize &middot;
            <a href="#" onclick="event.preventDefault();resetCH()">reset</a></span></label>
        ${editorBox(w.id, w.id, "Write a comment...")}
        <div class="pastes" id="pv${w.id}"></div>
        <div class="acts">
          <button onclick="save(${w.id})" id="b${w.id}">Save</button>
          <a class="ext" href="${w.url}" target="_blank" rel="noopener">Open in Azure DevOps</a>
          <span class="msg" id="m${w.id}"></span>
        </div>
      </div>
    </div>`).join("");
}

async function toggle(id, force) {
  const box = document.getElementById("e" + id);
  const open = force ? (box.classList.add("open"), true) : box.classList.toggle("open");
  if (!open) return;
  history.replaceState(null, "", "#" + id);
  const sel = document.getElementById("s" + id);
  const w = items.find(x => x.id === id);
  if (!sel.options.length) {
    sel.innerHTML = `<option>${esc(w.state)}</option>`;
    try {
      const d = await api("/api/states?type=" + encodeURIComponent(w.type));
      sel.innerHTML = d.states.map(s =>
        `<option${s === w.state ? " selected" : ""}>${esc(s)}</option>`).join("");
    } catch (e) { /* keep the current state as the only option */ }
  }
  loadDetail(id);
}

function fmtSize(n) {
  if (!n && n !== 0) return "";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(0) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

function dropFiles(ev, id) {
  ev.preventDefault();
  const dz = document.getElementById("dz" + id);
  if (dz) dz.classList.remove("over");
  if (ev.dataTransfer && ev.dataTransfer.files.length) uploadFiles(id, ev.dataTransfer.files);
}

async function uploadFiles(id, fileList) {
  const list = [...fileList], msg = document.getElementById("up" + id);
  if (!list.length) return;
  for (let i = 0; i < list.length; i++) {
    const f = list[i];
    if (msg) msg.textContent = `Uploading ${f.name} (${i + 1}/${list.length})...`;
    try {
      // Raw body upload: no multipart encoding needed on either side.
      const r = await fetch(`/api/upload?id=${id}&name=${encodeURIComponent(f.name)}`, {
        method: "POST", body: f,
        headers: {"x-ce-nonce": NONCE, "Content-Type": "application/octet-stream"},
      });
      const t = await r.text();
      let d = {}; try { d = t ? JSON.parse(t) : {}; } catch (e) { d = {error: t}; }
      if (!r.ok) throw new Error(d.error || r.status);
    } catch (e) {
      if (msg) msg.innerHTML = `<span class="err">${esc(f.name)}: ${esc(String(e.message || e))}</span>`;
      return;
    }
  }
  if (msg) msg.textContent = "Uploaded.";
  loadDetail(id);
}

async function addLink(id) {
  const kind = document.getElementById("lk" + id).value;
  const target = document.getElementById("lv" + id).value.trim();
  const msg = document.getElementById("lm" + id);
  if (!target) { if (msg) msg.textContent = "Enter an ID or URL."; return; }
  if (msg) msg.textContent = "Linking...";
  try {
    await api("/api/link", {method: "POST", body: JSON.stringify({id, kind, target})});
    if (msg) msg.textContent = "";
    loadDetail(id);
  } catch (e) {
    if (msg) msg.innerHTML = `<span class="err">${esc(String(e.message || e))}</span>`;
  }
}

async function unlink(id, url, what) {
  if (!confirm(`Remove this ${what} from work item ${id}?`)) return;
  try {
    await api("/api/unlink", {method: "POST", body: JSON.stringify({id, url})});
    loadDetail(id);
  } catch (e) { alert(String(e.message || e)); }
}

// Last loaded detail per work item, so the comment editor can find the
// original text without a second round trip.
const detailCache = {};

function editComment(id, cid) {
  const row = document.getElementById("cm" + id + "-" + cid);
  const d = detailCache[id];
  if (!row || !d) return;
  const c = (d.comments || []).find(x => x.id === cid);
  if (!c || row.querySelector(".ctext")) return;
  // The editor reuses the new-comment element naming ("c"/"mb"/"pv"/"m"/"b"
  // plus a key) so the @mention and paste helpers work here unchanged.
  const k = id + "-" + cid;
  row.dataset.html = row.innerHTML;
  row.innerHTML =
    `<span class="meta">${esc(c.author)} &middot; editing &mdash; type @ to tag
       someone, paste a screenshot or a table</span>
     ${editorBox(k, id, "")}
     <div class="pastes" id="pv${k}"></div>
     ${keptStrip(c.kept, k)}
     <div class="acts">
       <button onclick="saveComment(${id},${cid})" id="b${k}">Save comment</button>
       <button class="sec" onclick="cancelComment(${id},${cid})">Cancel</button>
       <span class="msg" id="m${k}"></span>
     </div>`;
  picked[k] = [];
  pasted[k] = [];
  tabled[k] = [];
  paintKept(k);
  const ta = document.getElementById("c" + k);
  ta.innerHTML = c.edit || "";
  ta.focus();
}

// What is already attached to the comment being edited. Shown so a screenshot
// is visible while you type instead of only described. Read-only: the server
// re-reads these from Azure DevOps and carries them over on its own.
function keptStrip(kept, key) {
  const k = kept || {};
  keptImgs[key] = (k.images || []).slice();
  kepts[key] = (k.tables || []).slice();
  return `<div id="kw${key}"></div>`;
}

// Painted rather than returned as a string, because the tables inside are
// live: removing one, or a row of one, has to redraw just this part.
function paintKept(key) {
  const box = document.getElementById("kw" + key);
  if (!box) return;
  const imgs = keptImgs[key] || [], tabs = kepts[key] || [];
  if (!imgs.length && !tabs.length) { box.innerHTML = ""; return; }
  const note = tabs.length
    ? "Already here &mdash; images are kept as they are, tables can be edited"
    : "Already in this comment &mdash; kept when you save";
  box.innerHTML = `<div class="meta">${note}</div><div class="pastes kept">`
    + imgs.map(im =>
      `<span class="paste"><img src="/img?n=${NONCE}&k=${encodeURIComponent(im.key)}"
         alt="${esc(im.name)}" title="${esc(im.name)}" onclick="zoom(this.src)"></span>`).join("")
    + tabs.map((t, i) => tblHost("kept", key, i)).join("")
    + `</div>`;
  drawTables("kept", key);
}

async function deleteComment(id, cid) {
  const row = document.getElementById("cm" + id + "-" + cid);
  if (!confirm("Delete this comment from work item " + id + "?\n\nThis removes it from the Azure DevOps discussion and cannot be undone here.")) return;
  if (row) row.style.opacity = ".5";
  const project = ((detailCache[id] || {}).item || {}).project || PROJECT;
  try {
    await api("/api/comment/delete", {method: "POST", body: JSON.stringify(
      {id: id, commentId: cid, project: project})});
    await loadDetail(id);
  } catch (e) {
    if (row) row.style.opacity = "";
    alert("Could not delete the comment: " + String(e.message || e));
  }
}

// The description editor reuses the same element naming as the comment boxes
// ("c"/"mb"/"pv"/"m"/"b" plus a key), so @mentions and paste work unchanged.
function descKey(id) { return "desc-" + id; }

function editDesc(id) {
  const box = document.getElementById("ds" + id);
  const d = detailCache[id];
  if (!box || !d || box.querySelector(".ctext")) return;
  const it = d.item;
  const repro = it.descField !== "System.Description";
  const k = descKey(id);
  box.dataset.html = box.innerHTML;
  box.innerHTML =
    editorBox(k, id, "") +
    `<div class="pastes" id="pv${k}"></div>
     ${keptStrip(repro ? it.reproKept : it.descKept, k)}
     <div class="acts">
       <button onclick="saveDesc(${id})" id="b${k}">Save description</button>
       <button class="sec" onclick="cancelDesc(${id})">Cancel</button>
       <span class="msg" id="m${k}"></span>
     </div>`;
  picked[k] = [];
  pasted[k] = [];
  tabled[k] = [];
  paintKept(k);
  const ta = document.getElementById("c" + k);
  ta.innerHTML = (repro ? it.reproEdit : it.descEdit) || "";
  ta.focus();
}

function cancelDesc(id) {
  const box = document.getElementById("ds" + id);
  const k = descKey(id);
  delete picked[k];
  delete pasted[k];
  delete tabled[k];
  delete kepts[k];
  delete keptImgs[k];
  if (box && box.dataset.html) box.innerHTML = box.dataset.html;
}

async function saveDesc(id) {
  const k = descKey(id);
  const msg = document.getElementById("m" + k);
  const btn = document.getElementById("b" + k);
  const it = (detailCache[id] || {}).item || {};
  const text = edText(k).trim(), html = edHtml(k);
  const imgs = (pasted[k] || []).filter(s => !s.pending && s.url).map(s => s.url);
  const tbls = (tabled[k] || []).map(t => t.token);
  const keeps = (keptImgs[k] || []).length + (kepts[k] || []).length;
  if (!text && !imgs.length && !tbls.length && !keeps
      && !confirm("Clear the description of work item " + id + " completely?")) return;
  btn.disabled = true; msg.className = "msg"; msg.textContent = "Saving...";
  const mentions = (picked[k] || []).filter(p => text.includes("@" + p.name));
  try {
    await api("/api/description", {method: "POST", body: JSON.stringify(
      {id: id, field: it.descField, text: text, html: html,
       mentions: mentions, images: imgs, tables: tbls,
       project: it.project || PROJECT,
       keptTables: (kepts[k] || []).map(t => t.token)})});
    delete picked[k];
    delete pasted[k];
    delete tabled[k];
    await loadDetail(id);
  } catch (e) {
    btn.disabled = false;
    msg.className = "msg err"; msg.textContent = String(e.message || e);
  }
}

function cancelComment(id, cid) {
  const row = document.getElementById("cm" + id + "-" + cid);
  const k = id + "-" + cid;
  delete picked[k];
  delete pasted[k];
  delete tabled[k];
  delete kepts[k];
  delete keptImgs[k];
  if (row && row.dataset.html) row.innerHTML = row.dataset.html;
}

async function saveComment(id, cid) {
  const k = id + "-" + cid;
  const msg = document.getElementById("m" + k);
  const btn = document.getElementById("b" + k);
  const text = edText(k).trim(), html = edHtml(k);
  const imgs = (pasted[k] || []).filter(s => !s.pending && s.url).map(s => s.url);
  const tbls = (tabled[k] || []).map(t => t.token);
  if (!text && !imgs.length && !tbls.length) { msg.className = "msg err"; msg.textContent = "Comment cannot be empty."; return; }
  btn.disabled = true; msg.className = "msg"; msg.textContent = "Saving...";
  const mentions = (picked[k] || []).filter(p => text.includes("@" + p.name));
  const project = ((detailCache[id] || {}).item || {}).project || PROJECT;
  try {
    await api("/api/comment", {method: "POST", body: JSON.stringify(
      {id: id, commentId: cid, comment: text, html: html,
       mentions: mentions, images: imgs, tables: tbls, project: project,
       keptTables: (kepts[k] || []).map(t => t.token)})});
    delete picked[k];
    delete pasted[k];
    delete tabled[k];
    await loadDetail(id);
  } catch (e) {
    btn.disabled = false;
    msg.className = "msg err"; msg.textContent = String(e.message || e);
  }
}

async function loadDetail(id) {
  const box = document.getElementById("d" + id);
  if (!box) return;
  box.textContent = "Loading details...";
  try {
    const d = await api("/api/detail?id=" + id);
    detailCache[id] = d;
    const it = d.item, body = it.descriptionHtml || it.reproHtml || "";
    const meta = [["Created", `${esc(it.createdBy)} on ${esc((it.createdDate || "").slice(0, 10))}`],
                  ["Updated", esc((it.changedDate || "").slice(0, 16).replace("T", " "))],
                  ["Area", esc(it.areaPath)], ["Reason", esc(it.reason)],
                  ["Tags", esc(it.tags) || "-"]];
    const thread = d.comments.length
      ? d.comments.map(c => `<div class="cm" id="cm${id}-${c.id}"><span class="meta">${esc(c.author)} &middot; ${
            esc((c.at || "").slice(0, 16).replace("T", " "))}${
            c.edited ? " &middot; edited" : ""}${
            c.mine ? ` &middot; <a href="#" onclick="event.preventDefault();editComment(${id},${c.id})">edit</a>
                     &middot; <a href="#" class="danger" onclick="event.preventDefault();deleteComment(${id},${c.id})">delete</a>` : ""
          }</span><div class="rich">${
            c.html || esc(c.text)}</div></div>`).join("")
      : `<div class="meta">No comments yet.</div>`;
    const files = d.attachments || [];
    const shots = files.filter(a => a.isImage);
    const gallery = shots.length
      ? `<div class="k">Images (${shots.length})</div><div class="shots">` + shots.map(a =>
          `<figure><img src="${esc(a.src)}" alt="${esc(a.name)}" loading="lazy"
             onclick="zoom(this.src)"><figcaption>${esc(a.name)}</figcaption></figure>`).join("") +
        `</div>`
      : "";
    const rows = files.map(a =>
      `<div class="frow"><span class="fname" title="${esc(a.comment || "")}">${
         a.isImage ? "&#128443;" : "&#128196;"} ${esc(a.name)}</span>
       <span class="fsize">${esc(fmtSize(a.size))}</span>
       <a class="fdl" href="${esc(a.download)}" download="${esc(a.name)}">Download</a>
       <button class="link danger" onclick="unlink(${id}, ${JSON.stringify(a.url).replace(/"/g, "&quot;")}, 'file')">Remove</button></div>`).join("");
    const filesBlock =
      `<div class="k">Attachments (${files.length})</div>
       <div class="files">${rows || '<span class="meta">No files attached.</span>'}</div>
       <div class="drop" id="dz${id}" ondragover="event.preventDefault();this.classList.add('over')"
            ondragleave="this.classList.remove('over')"
            ondrop="dropFiles(event, ${id})">
         Drag files here, or <label class="pick">browse<input type="file" multiple
           style="display:none" onchange="uploadFiles(${id}, this.files); this.value='';"></label>
         <span class="up" id="up${id}"></span>
       </div>`;
    const linkRows = (d.links || []).map(l => {
      const href = l.external ? (l.href || "") : (l.webUrl || l.url);
      const badge = l.state ? `<span class="pill">${esc(l.state)}</span>` : "";
      const label = href
        ? `<a class="fname" href="${esc(href)}" target="_blank" rel="noopener"
           title="${esc(l.comment || href)}">${esc(l.label)}</a>`
        : `<span class="fname" title="blocked link">${esc(l.label)}</span>`;
      return `<div class="frow"><span class="ltype">${esc(l.kind)}</span>
        ${label}${badge}
        <button class="link danger" onclick="unlink(${id}, ${JSON.stringify(l.url).replace(/"/g, "&quot;")}, 'link')">Remove</button></div>`;
    }).join("");
    const linksBlock =
      `<div class="k">Links (${(d.links || []).length})</div>
       <div class="files">${linkRows || '<span class="meta">No links.</span>'}</div>
       <div class="addlink">
         <select id="lk${id}">
           <option value="related">Related work item</option>
           <option value="parent">Parent</option>
           <option value="child">Child</option>
           <option value="duplicate">Duplicate of</option>
           <option value="successor">Successor</option>
           <option value="predecessor">Predecessor</option>
           <option value="hyperlink">Hyperlink (URL)</option>
         </select>
         <input id="lv${id}" placeholder="Work item ID, or https://... for a hyperlink">
         <button class="sec" onclick="addLink(${id})">Add link</button>
         <span class="up" id="lm${id}"></span>
       </div>`;
    box.innerHTML =
      `<div class="meta-grid">${meta.map(([k, v]) => `<span class="k">${k}</span><span>${v}</span>`).join("")}</div>` +
      `<div class="k">${it.descField === "System.Description" ? "Description" : "Repro steps"}
         &middot; <a href="#" onclick="event.preventDefault();editDesc(${id})">edit</a></div>
       <div id="ds${id}">` +
      (body ? `<div class="desc rich">${body}</div>`
            : `<span class="meta">No description yet.</span>`) +
      `</div>` +
      gallery + filesBlock + linksBlock +
      `<div class="thread"><span class="k">Discussion (${d.comments.length})</span>${thread}</div>`;
  } catch (e) { box.innerHTML = `<span class="err">${esc(String(e.message || e))}</span>`; }
}

async function openItem(id) {
  // Deep link / notification click: pull the item in even when the current
  // filter would exclude it (e.g. a closed case).
  if (!items.find(x => x.id === id)) {
    try {
      const d = await api("/api/search?q=" + id);
      if (!d.items.length) return;
      items = d.items; render();
    } catch (e) { return; }
  }
  const card = document.querySelector(`.card[data-id="${id}"]`);
  if (card) card.scrollIntoView({block: "center"});
  toggle(id, true);
}

// Screenshots and tables pasted into a comment, per box, pending the next Save.
const pasted = {};
const tabled = {};
// The images and tables a comment already had, while it is being edited.
const keptImgs = {};
const kepts = {};
// Which cell each drawn table has selected, so the row and column buttons
// have something to act on.
const tgState = {};

function tblId(kind, key, i) { return "tg-" + kind + "-" + key + "-" + i; }

function tblList(kind, key) {
  return (kind === "kept" ? kepts[key] : tabled[key]) || [];
}

function tblHost(kind, key, i) {
  return `<span class="paste tbl tedit" id="${tblId(kind, key, i)}"></span>`;
}

function drawTables(kind, key) {
  tblList(kind, key).forEach((t, i) => {
    const gid = tblId(kind, key, i), was = tgState[gid] || {};
    tgState[gid] = {kind: kind, key: key, i: i,
                    row: was.row || 0, col: was.col || 0};
    drawTable(gid);
  });
}

// The page never builds table markup of its own: it shows what the server
// sent, asks for a change, and redraws whatever comes back.
function drawTable(gid) {
  const st = tgState[gid], host = document.getElementById(gid);
  if (!st || !host) return;
  const t = tblList(st.kind, st.key)[st.i];
  if (!t) return;
  host.innerHTML =
    `<span class="tprev"></span>
     <span class="tcap" id="cap${gid}"></span>
     <span class="ttools">
       <a href="#" title="Insert a row below the cell you clicked"
          onclick="event.preventDefault();tblOp('${gid}','addRow')">+ row</a>
       <a href="#" title="Delete the row of the cell you clicked"
          onclick="event.preventDefault();tblOp('${gid}','delRow')">&minus; row</a>
       <a href="#" title="Insert a column right of the cell you clicked"
          onclick="event.preventDefault();tblOp('${gid}','addCol')">+ column</a>
       <a href="#" title="Delete the column of the cell you clicked"
          onclick="event.preventDefault();tblOp('${gid}','delCol')">&minus; column</a>
       <a href="#" class="warn" title="Take this table out of the text"
          onclick="event.preventDefault();dropTableAt('${gid}')">remove table</a>
     </span>`;
  const area = host.querySelector(".tprev");
  area.innerHTML = t.html;      // markup this server sanitised and stored
  const table = area.querySelector("table");
  if (!table) return;
  const rows = Array.from(table.rows);
  if (st.row >= rows.length) st.row = rows.length - 1;
  rows.forEach((tr, ri) => Array.from(tr.cells).forEach((cell, ci) => {
    cell.contentEditable = "true";
    cell.spellcheck = false;
    cell.dataset.was = cell.innerText;
    cell.onfocus = () => { st.row = ri; st.col = ci; markCell(gid); };
    cell.onblur = () => {
      if (cell.innerText !== cell.dataset.was) tblOp(gid, "setCell", cell.innerText);
    };
    cell.onkeydown = (e) => {
      if (e.key === "Escape") { cell.innerText = cell.dataset.was; cell.blur(); }
    };
    // Only the text of a paste is taken, so pasting into a cell cannot carry
    // markup in with it.
    cell.onpaste = (e) => {
      e.preventDefault(); e.stopPropagation();
      const cb = e.clipboardData || window.clipboardData;
      document.execCommand("insertText", false, cb ? cb.getData("text") : "");
    };
  }));
  markCell(gid);
}

function markCell(gid) {
  const st = tgState[gid], host = document.getElementById(gid);
  if (!st || !host) return;
  const t = tblList(st.kind, st.key)[st.i];
  const cap = document.getElementById("cap" + gid);
  if (!t || !cap) return;
  cap.textContent = `Table ${t.rows}x${t.cols} \u2014 row ${(st.row || 0) + 1}`
                    + `, column ${(st.col || 0) + 1}`;
  host.querySelectorAll(".cellsel").forEach(c => c.classList.remove("cellsel"));
  const table = host.querySelector("table");
  const tr = table && table.rows[st.row || 0];
  const cell = tr && tr.cells[st.col || 0];
  if (cell) cell.classList.add("cellsel");
}

async function tblOp(gid, op, text) {
  const st = tgState[gid];
  if (!st) return;
  const list = tblList(st.kind, st.key), t = list[st.i];
  if (!t) return;
  try {
    const d = await api("/api/table/op", {method: "POST", body: JSON.stringify(
      {token: t.token, op: op, row: st.row || 0, col: st.col || 0,
       text: text || ""})});
    list[st.i] = d;
  } catch (e) {
    alert("Could not change the table: " + String(e.message || e));
  }
  drawTable(gid);   // redraw either way, so a refused change is undone on screen
}

function dropTableAt(gid) {
  const st = tgState[gid];
  if (!st) return;
  if (!confirm("Remove this table from the text?\n\nIt goes when you save.")) return;
  tblList(st.kind, st.key).splice(st.i, 1);
  if (st.kind === "kept") paintKept(st.key); else renderPastes(st.key);
}

function renderPastes(key) {
  const box = document.getElementById("pv" + key);
  if (!box) return;
  const imgs = (pasted[key] || []).map((s, i) => s.pending
    ? `<span class="paste busy">Uploading ${esc(s.name)}...</span>`
    : `<span class="paste"><img src="/img?n=${NONCE}&k=${encodeURIComponent(s.key)}"
         alt="${esc(s.name)}" onclick="zoom(this.src)">
       <a href="#" title="Remove from this comment"
          onclick="event.preventDefault();dropPaste('${key}',${i})">&times;</a></span>`).join("");
  const tabs = (tabled[key] || []).map((t, i) => tblHost("new", key, i)).join("");
  box.innerHTML = imgs + tabs;
  drawTables("new", key);
}

function dropPaste(key, i) {
  // The file stays attached to the work item; this only unpicks it from the
  // comment being written.
  (pasted[key] || []).splice(i, 1);
  renderPastes(key);
}

async function pasteTable(key, html, tsv) {
  const msg = document.getElementById("m" + key);
  try {
    const d = await api("/api/table", {method: "POST",
      body: JSON.stringify({html: html || "", tsv: tsv || ""})});
    tabled[key] = tabled[key] || [];
    tabled[key].push(d);
    renderPastes(key);
    if (msg) { msg.className = "msg ok"; msg.textContent = `Table ${d.rows}x${d.cols} attached to this comment.`; }
    return true;
  } catch (e) {
    if (msg) { msg.className = "msg err"; msg.textContent = "Table paste failed: " + String(e.message || e); }
    return false;
  }
}

async function onPaste(ev, key, itemId) {
  const cb = ev.clipboardData || {};
  const files = [];
  for (const it of cb.items || []) {
    if (it.kind === "file" && it.type.indexOf("image/") === 0) {
      const f = it.getAsFile();
      if (f) files.push(f);
    }
  }
  if (!files.length) {
    // Excel and Outlook put real HTML on the clipboard; Excel also offers a
    // tab-separated fallback. Either becomes a table instead of flat text.
    const html = cb.getData ? cb.getData("text/html") : "";
    const plain = cb.getData ? cb.getData("text/plain") : "";
    if (html && html.toLowerCase().indexOf("<table") >= 0) {
      ev.preventDefault();
      return pasteTable(key, html, "");
    }
    if (plain && plain.indexOf("\t") >= 0 && plain.indexOf("\n") >= 0) {
      ev.preventDefault();
      return pasteTable(key, "", plain);
    }
    // Ordinary text paste. Only the text of it is taken, so formatting
    // and markup from another application cannot ride in with it.
    ev.preventDefault();
    document.execCommand("insertText", false, plain || "");
    return;
  }
  ev.preventDefault();
  const msg = document.getElementById("m" + key);
  pasted[key] = pasted[key] || [];
  for (const f of files) {
    const ext = (f.type.split("/")[1] || "png").replace(/[^a-z0-9]/gi, "") || "png";
    const name = "pasted-" + Date.now() + "." + ext;
    const slot = {name: name, pending: true};
    pasted[key].push(slot);
    renderPastes(key);
    try {
      const r = await fetch(`/api/upload?id=${itemId}&name=${encodeURIComponent(name)}`
                            + `&comment=${encodeURIComponent("Pasted into a comment")}`, {
        method: "POST", body: f,
        headers: {"x-ce-nonce": NONCE, "Content-Type": "application/octet-stream"},
      });
      const t = await r.text();
      let d = {}; try { d = t ? JSON.parse(t) : {}; } catch (e) { d = {error: t}; }
      if (!r.ok) throw new Error(d.error || r.status);
      slot.pending = false; slot.url = d.url; slot.key = d.key; slot.name = d.name;
    } catch (e) {
      pasted[key].splice(pasted[key].indexOf(slot), 1);
      if (msg) { msg.className = "msg err"; msg.textContent = "Paste failed: " + String(e.message || e); }
    }
    renderPastes(key);
  }
}

async function save(id) {
  const btn = document.getElementById("b" + id), msg = document.getElementById("m" + id);
  const w = items.find(x => x.id === id);
  const fields = {}, title = document.getElementById("t" + id).value.trim(),
        state = document.getElementById("s" + id).value,
        who = document.getElementById("a" + id).value.trim(),
        comment = edText(id), commentHtml = edHtml(id);
  const imgs = (pasted[id] || []).filter(s => !s.pending && s.url).map(s => s.url);
  const tbls = (tabled[id] || []).map(t => t.token);
  if (title && title !== w.title) fields["System.Title"] = title;
  if (state && state !== w.state) fields["System.State"] = state;
  if (who !== w.assignedTo) fields["System.AssignedTo"] = who;
  if (!Object.keys(fields).length && !comment.trim() && !imgs.length && !tbls.length) { msg.className = "msg"; msg.textContent = "No changes."; return; }
  btn.disabled = true; msg.className = "msg"; msg.textContent = "Saving...";
  // Only send people actually still referenced in the text.
  const mentions = (picked[id] || []).filter(p => comment.includes("@" + p.name));
  try {
    await api("/api/item/" + id, {method: "POST", body: JSON.stringify(
      {fields, comment, html: commentHtml, mentions, images: imgs, tables: tbls})});
    msg.className = "msg ok";
    msg.textContent = "Saved." + (mentions.length ? ` Tagged ${mentions.length} person(s).` : "")
                    + (imgs.length ? ` ${imgs.length} image(s) added.` : "")
                    + (tbls.length ? ` ${tbls.length} table(s) added.` : "");
    edSet(id, "");
    picked[id] = [];
    pasted[id] = [];
    tabled[id] = [];
    renderPastes(id);
    await load(true);
    openItem(id);
  } catch (e) { msg.className = "msg err"; msg.textContent = String(e.message || e); }
  btn.disabled = false;
}

// ---- the formatted text box ------------------------------------------------
// One definition, used by the new-comment box, the comment editor and the
// description editor, so all three behave identically.
const HL = "#fff29a";

function editorBox(key, itemId, placeholder) {
  const b = (cmd, label, title, style) =>
    `<button type="button" title="${title}" style="${style || ''}"
       onmousedown="event.preventDefault()"
       onclick="rte('${key}','${cmd}')">${label}</button>`;
  return `<div class="rtb">
      ${b("bold", "<b>B</b>", "Bold (Ctrl+B)")}
      ${b("italic", "<i>I</i>", "Italic (Ctrl+I)")}
      ${b("underline", "<u>U</u>", "Underline (Ctrl+U)")}
      ${b("hilite", "<span class=hl>&nbsp;A&nbsp;</span>", "Highlight, or remove it")}
      <span class="sep"></span>
      ${b("insertUnorderedList", "&bull;&nbsp;list", "Bulleted list")}
      ${b("insertOrderedList", "1.&nbsp;list", "Numbered list")}
      ${b("indent", "&rarr;", "Indent (Tab)")}
      ${b("outdent", "&larr;", "Outdent (Shift+Tab)")}
      <span class="sep"></span>
      ${b("removeFormat", "clear", "Remove formatting from the selection")}
    </div>
    <div class="cwrap"><div class="ctext" id="c${key}" contenteditable="true"
       data-ph="${placeholder || ''}" spellcheck="true"
       oninput="onComment('${key}')"
       onmousedown="markH(this)" onmouseup="saveH(this)"
       onpaste="onPaste(event, '${key}', ${itemId})"
       onkeydown="editorKey(event, '${key}')"></div>
      <div class="mbox" id="mb${key}"></div></div>`;
}

// Formatting is applied by the browser's own editing commands, so the markup
// is the browser's rather than something this page assembles by hand. The
// server allows through only the few tags these produce.
function rte(key, cmd) {
  const box = document.getElementById("c" + key);
  if (!box) return;
  box.focus();
  if (cmd === "hilite") {
    try { document.execCommand("styleWithCSS", false, true); } catch (e) { /* older browser */ }
    const now = (document.queryCommandValue("backColor") || "").replace(/\s/g, "").toLowerCase();
    const on = now === "rgb(255,242,154)" || now === "#fff29a";
    const colour = on ? "transparent" : HL;
    if (!document.execCommand("hiliteColor", false, colour)) {
      document.execCommand("backColor", false, colour);
    }
    return;
  }
  // Everything else is asked for as tags (<b>, <i>, <u>) rather than styles.
  try { document.execCommand("styleWithCSS", false, false); } catch (e) { /* older browser */ }
  document.execCommand(cmd, false, null);
}

function edText(key) {
  const b = document.getElementById("c" + key);
  return b ? (b.innerText || "") : "";
}

function edHtml(key) {
  const b = document.getElementById("c" + key);
  return b ? b.innerHTML : "";
}

function edSet(key, html) {
  const b = document.getElementById("c" + key);
  if (b) b.innerHTML = html || "";
}

function editorKey(event, id) {
  if (mState && String(mState.id) === String(id)) {
    mentionKey(event, id);
    if (event.defaultPrevented) return;
  }
  if (event.key === "Tab") {
    event.preventDefault();
    document.execCommand(event.shiftKey ? "outdent" : "indent", false, null);
  }
}

// ---- @mention autocomplete -------------------------------------------------
const picked = {};       // work item id -> people already inserted
let mState = null;       // {id, start, people, active}

function mentionQuery(box) {
  // Look back from the caret for an "@..." run that has no line break. The
  // caret is a position in a text node now, so the search stays in that node.
  const sel = window.getSelection();
  if (!sel || !sel.rangeCount) return null;
  const r = sel.getRangeAt(0);
  if (!r.collapsed || r.startContainer.nodeType !== 3) return null;
  if (!box || !box.contains(r.startContainer)) return null;
  const node = r.startContainer, upto = node.data.slice(0, r.startOffset);
  const at = upto.lastIndexOf("@");
  if (at < 0) return null;
  const frag = upto.slice(at + 1);
  if (/[\n\r]/.test(frag) || frag.length > 40) return null;
  if (at > 0 && !/[\s(<]/.test(upto[at - 1])) return null;
  return {node: node, start: at, end: r.startOffset, text: frag};
}

const CH_KEY = "ceCommentHeight";

// A saved height is applied through a stylesheet rule so it covers every
// comment box, including cards rendered later.
function setCH(h) {
  let s = document.getElementById("chstyle");
  if (!s) { s = document.createElement("style"); s.id = "chstyle"; document.head.appendChild(s); }
  s.textContent = h ? ".ctext{height:" + h + "}" : "";
}

function markH(el) { el.dataset.h0 = el.offsetHeight; }

function saveH(el) {
  const before = Number(el.dataset.h0 || 0);
  if (!before || Math.abs(el.offsetHeight - before) < 3) return;  // a click, not a drag
  const h = el.offsetHeight + "px";
  el.style.height = "";
  try { localStorage.setItem(CH_KEY, h); } catch (e) { /* private mode */ }
  setCH(h);
}

function grow(el) {
  if (el && el.isContentEditable) return;   // it already fits its content
  let saved = null;
  try { saved = localStorage.getItem(CH_KEY); } catch (e) { /* ignore */ }
  if (saved) return;  // the user picked a size; leave it alone
  el.style.height = "auto";
  const max = Math.round(window.innerHeight * 0.6);
  el.style.height = Math.min(el.scrollHeight + 2, max) + "px";
}

function resetCH() {
  try { localStorage.removeItem(CH_KEY); } catch (e) { /* ignore */ }
  setCH("");
  document.querySelectorAll(".ctext").forEach(t => { t.style.height = ""; });
}

try { setCH(localStorage.getItem(CH_KEY)); } catch (e) { /* ignore */ }

async function onComment(id) {
  const box = document.getElementById("c" + id);
  const q = mentionQuery(box);
  if (!q || q.text.trim().length < 2) return hideMentions(id);
  try {
    const d = await api("/api/people?q=" + encodeURIComponent(q.text.trim()));
    if (!d.people.length) return hideMentions(id);
    // The caret may have moved on while the lookup was in flight.
    const still = mentionQuery(box);
    if (!still || still.start !== q.start || still.node !== q.node) return;
    mState = {id, node: q.node, start: q.start, end: still.end,
              people: d.people, active: 0};
    drawMentions();
  } catch (e) { hideMentions(id); }
}

function drawMentions() {
  if (!mState) return;
  const el = document.getElementById("mb" + mState.id);
  el.innerHTML = mState.people.map((p, i) =>
    `<div class="mrow${i === mState.active ? " on" : ""}" onmousedown="event.preventDefault();pickMention(${i})">
       <b>${esc(p.name)}</b><span>${esc(p.mail)}</span></div>`).join("");
  el.classList.add("show");
}

function hideMentions(id) {
  const el = document.getElementById("mb" + (id !== undefined ? id : (mState || {}).id));
  if (el) { el.classList.remove("show"); el.innerHTML = ""; }
  mState = null;
}

function pickMention(index) {
  if (!mState) return;
  const id = mState.id, person = mState.people[index];
  const box = document.getElementById("c" + id);
  // Re-read the caret: more may have been typed since the list appeared.
  const q = mentionQuery(box) || mState;
  const node = q.node;
  if (!box || !node || !box.contains(node)) return hideMentions(id);
  const insert = "@" + person.name + " ";
  node.replaceData(q.start, Math.max(0, q.end - q.start), insert);
  const sel = window.getSelection(), r = document.createRange();
  r.setStart(node, q.start + insert.length);
  r.collapse(true);
  sel.removeAllRanges();
  sel.addRange(r);
  box.focus();
  picked[id] = (picked[id] || []).filter(p => p.id !== person.id).concat(person);
  hideMentions(id);
}

function mentionKey(event, id) {
  if (!mState || String(mState.id) !== String(id)) return;
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    const step = event.key === "ArrowDown" ? 1 : -1;
    mState.active = (mState.active + step + mState.people.length) % mState.people.length;
    return drawMentions();
  }
  if (event.key === "Enter" || event.key === "Tab") {
    event.preventDefault(); return pickMention(mState.active);
  }
  if (event.key === "Escape") hideMentions(id);
}

async function load(quiet) {
  const el = document.getElementById("list");
  if (!quiet) { el.className = "empty"; el.textContent = "Loading..."; }
  try {
    const q = document.getElementById("q").value.trim();
    const inc = document.getElementById("incClosed").checked ? "1" : "0";
    const scope = document.getElementById("scope").value;
    // "All of this project" is a search-only mode; there is no sane default list.
    const d = (q || scope !== "created")
      ? await api(`/api/search?q=${encodeURIComponent(q)}&includeClosed=${inc}&scope=${scope}`)
      : await api("/api/items?openOnly=" + (document.getElementById("openOnly").checked ? "1" : "0"));
    items = d.items; document.getElementById("who").textContent = d.user || "";
    scopeUsed = scope;
    render();
  } catch (e) { el.className = "empty"; el.innerHTML = `<span class="err">${esc(String(e.message || e))}</span>`; }
}

function renderFeed(notes) {
  const box = document.getElementById("feed"), body = document.getElementById("feedItems");
  document.getElementById("fcount").textContent = notes.length;
  if (!notes.length) { box.classList.remove("show"); return; }
  box.classList.add("show");
  body.innerHTML = notes.map(n => `<div class="note" onclick="openItem(${n.workItemId})">
      <span class="kind ${esc(n.kind || "comment")}">${esc(n.kind || "comment")}</span>
      <b>#${n.workItemId}</b> ${esc(n.title)}<br>
      <span class="meta">${esc(n.author)} &middot; ${esc((n.at || "").slice(0, 16).replace("T", " "))}</span><br>
      ${esc(n.text)}</div>`).join("");
}
async function pollFeed() {
  try { renderFeed((await api("/api/notifications")).notifications || []); } catch (e) {}
}
async function clearFeed() {
  try { await api("/api/notifications", {method: "POST", body: "{}"}); renderFeed([]); } catch (e) {}
}

document.getElementById("refresh").onclick = () => load();
document.getElementById("openOnly").onchange = () => load();
document.getElementById("searchBtn").onclick = () => load();
document.getElementById("scope").onchange = () => {
  // "open only" only applies to the default created-by-me list.
  document.getElementById("openOnly").disabled =
    document.getElementById("scope").value !== "created";
  load();
};
document.getElementById("incClosed").onchange = () => load();
document.getElementById("clearBtn").onclick = () => {
  document.getElementById("q").value = "";
  document.getElementById("scope").value = "created";
  document.getElementById("openOnly").disabled = false;
  load();
};
document.getElementById("q").addEventListener("keydown", e => { if (e.key === "Enter") load(); });
// ---- first-run sign-in, entirely in the browser ---------------------------
async function boot() {
  let ok = false;
  try { ok = (await api("/api/auth")).signedIn; } catch (e) {}
  document.getElementById("signin").classList.toggle("show", !ok);
  document.getElementById("app").classList.toggle("hide", !ok);
  if (ok) { start(); } 
}

document.getElementById("signinBtn").onclick = async () => {
  const body = document.getElementById("signinBody");
  body.innerHTML = "Starting sign-in...";
  let d;
  try { d = await api("/api/signin", {method: "POST", body: "{}"}); }
  catch (e) { body.innerHTML = `<span class="err">${esc(String(e.message || e))}</span>`; return; }
  body.innerHTML =
    `<div class="step">1. Open <a href="${esc(d.url)}" target="_blank" rel="noopener">${esc(d.url)}</a></div>
     <div class="step">2. Enter this code:</div>
     <div class="code">${esc(d.userCode)}</div>
     <div class="step">3. Sign in with your work account. This page continues automatically.</div>
     <div class="step" id="sstat">Waiting...</div>`;
  window.open(d.url, "_blank", "noopener");
  const deadline = Date.now() + d.expiresIn * 1000;
  let wait = d.interval * 1000;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, wait));
    let s;
    try { s = await api("/api/signin/poll", {method: "POST", body: JSON.stringify({deviceCode: d.deviceCode})}); }
    catch (e) { document.getElementById("sstat").innerHTML = `<span class="err">${esc(String(e.message || e))}</span>`; return; }
    if (s.status === "ok") {
      document.getElementById("signin").classList.remove("show");
      document.getElementById("app").classList.remove("hide");
      return start();
    }
    if (s.status === "slow_down") wait += 5000;
  }
  document.getElementById("sstat").innerHTML = `<span class="err">Sign-in timed out. Try again.</span>`;
};

function start() {
  load().then(() => {
    const id = parseInt(location.hash.slice(1), 10);
    if (id) openItem(id);
  });
  pollFeed();
  setInterval(pollFeed, 30000);
}

window.addEventListener("hashchange", () => {
  const id = parseInt(location.hash.slice(1), 10);
  if (id) openItem(id);
});
boot();
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "CEBoard/1.0"

    def log_message(self, fmt, *args):
        pass

    def _guard(self, need_nonce=True):
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):
            raise ApiError(403, "Unexpected Host header.")
        if need_nonce and not hmac.compare_digest(
                self.headers.get("x-ce-nonce") or "", NONCE):
            raise ApiError(403, "Invalid nonce.")

    def _query_nonce(self, qs):
        if not hmac.compare_digest(qs.get("n", [""])[0], NONCE):
            raise ApiError(403, "Invalid nonce.")

    def _send(self, code, body, ctype="application/json"):
        raw = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        if ctype == "text/html":
            # Inline script/style are the page itself; what matters is that no
            # origin other than this one can be contacted, so a script that did
            # slip through has nowhere to send the nonce or any CE content.
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; img-src 'self' data:; "
                "style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                "connect-src 'self'; form-action 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        try:
            if url.path in ("/", "/" + NONCE, "/" + NONCE + "/"):
                self._guard(need_nonce=False)
                if url.path == "/":
                    # The page carries the nonce, so it must not be readable by
                    # any local process that can simply GET "/". Knowing the
                    # unguessable path is the price of admission.
                    raise ApiError(404, "Not found.")
                page = PAGE.replace("__NONCE__", NONCE).replace(
                    "__PROJECT__", PROJECT.replace('"', ""))
                return self._send(200, page, "text/html")
            if url.path == "/favicon.ico":
                # Gives the tab -- and the standalone app window -- the board's
                # own icon. It is a local file we ship, so no nonce is needed.
                self._guard(need_nonce=False)
                try:
                    with open(ICON_PATH, "rb") as handle:
                        blob = handle.read()
                except (IOError, OSError):
                    raise ApiError(404, "No icon.")
                self.send_response(200)
                self.send_header("Content-Type", "image/x-icon")
                self.send_header("Content-Length", str(len(blob)))
                self.send_header("Cache-Control", "private, max-age=86400")
                self.end_headers()
                return self.wfile.write(blob)
            if url.path == "/img":
                # <img> requests carry no custom headers, so the nonce rides in
                # the query string instead.
                self._guard(need_nonce=False)
                qs = urllib.parse.parse_qs(url.query)
                self._query_nonce(qs)
                blob, ctype = fetch_binary(res_url(qs.get("k", [""])[0]))
                base = ctype.split(";")[0].strip().lower()
                if not (base.startswith("image/") or base == "application/pdf"):
                    # ADO mislabels attachments with no fileName parameter, so
                    # fall back to the magic bytes before rejecting.
                    sniffed = _sniff_image(blob)
                    if not sniffed:
                        raise ApiError(415, "Not an image.")
                    ctype = sniffed
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(blob)))
                self.send_header("Cache-Control", "private, max-age=3600")
                self.send_header("Content-Security-Policy", "sandbox")
                self.end_headers()
                return self.wfile.write(blob)
            if url.path == "/file":
                # Downloads are plain navigations, so the nonce is in the query.
                self._guard(need_nonce=False)
                qs = urllib.parse.parse_qs(url.query)
                self._query_nonce(qs)
                blob, ctype = fetch_binary(res_url(qs.get("k", [""])[0]))
                name = os.path.basename(qs.get("name", ["attachment"])[0])
                name = re.sub(r'[\r\n"\\]', "", name) or "attachment"
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition",
                                 'attachment; filename="{}"; '
                                 "filename*=UTF-8''{}".format(
                                     name.encode("ascii", "replace").decode(),
                                     urllib.parse.quote(name)))
                self.send_header("Content-Length", str(len(blob)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return self.wfile.write(blob)
            self._guard()
            qs = urllib.parse.parse_qs(url.query)
            if url.path == "/api/items":
                open_only = qs.get("openOnly", ["1"])[0] != "0"
                return self._send(200, json.dumps({
                    "items": list_items(open_only=open_only),
                    "user": my_display_name(),
                }))
            if url.path == "/api/states":
                wit = qs.get("type", [""])[0]
                return self._send(200, json.dumps({"states": type_states(wit)}))
            if url.path == "/api/search":
                return self._send(200, json.dumps({
                    "items": search_items(
                        qs.get("q", [""])[0],
                        include_closed=qs.get("includeClosed", ["1"])[0] != "0",
                        scope=qs.get("scope", ["created"])[0]),
                    "user": my_display_name(),
                }))
            if url.path == "/api/notifications":
                with _feed_lock:
                    return self._send(200, json.dumps({"notifications": list(_feed)}))
            if url.path == "/api/detail":
                wid = qs.get("id", [""])[0]
                if not wid.isdigit():
                    raise ApiError(400, "Bad work item id.")
                return self._send(200, json.dumps(item_detail(wid)))
            if url.path == "/api/people":
                return self._send(200, json.dumps(
                    {"people": search_identities(qs.get("q", [""])[0])}))
            if url.path == "/api/auth":
                return self._send(200, json.dumps({
                    "signedIn": azdo_auth.is_signed_in(),
                    "org": ORG, "project": PROJECT,
                }))
            return self._send(404, json.dumps({"error": "Not found"}))
        except ApiError as exc:
            self._send(exc.status if exc.status >= 400 else 500,
                       json.dumps({"error": exc.message}))
        except Exception as exc:  # keep the server alive on unexpected faults
            self._send(500, json.dumps({"error": str(exc)}))

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        try:
            self._guard()
            length = int(self.headers.get("Content-Length") or 0)
            if url.path == "/api/upload":
                # The file is sent as the raw body so the server needs no
                # multipart parser; the metadata rides in the query string.
                qs = urllib.parse.parse_qs(url.query)
                item_id = qs.get("id", [""])[0]
                if not item_id.isdigit():
                    raise ApiError(400, "Bad work item id.")
                if length > MAX_UPLOAD:
                    raise ApiError(413, "File is larger than {} MB.".format(
                        MAX_UPLOAD // (1024 * 1024)))
                blob = self.rfile.read(length)
                return self._send(200, json.dumps(upload_attachment(
                    item_id, qs.get("name", ["attachment"])[0], blob,
                    qs.get("comment", [""])[0])))
            payload = json.loads(self.rfile.read(length) or b"{}")
            if url.path == "/api/link":
                item_id = str(payload.get("id", ""))
                if not item_id.isdigit():
                    raise ApiError(400, "Bad work item id.")
                add_link(item_id, payload.get("kind", ""),
                         payload.get("target", ""), payload.get("comment", ""))
                return self._send(200, json.dumps({"ok": True}))
            if url.path == "/api/unlink":
                item_id = str(payload.get("id", ""))
                if not item_id.isdigit():
                    raise ApiError(400, "Bad work item id.")
                remove_relation(item_id, payload.get("url", ""))
                return self._send(200, json.dumps({"ok": True}))
            if url.path == "/api/table/op":
                return self._send(200, json.dumps(table_op(
                    payload.get("token"), payload.get("op") or "",
                    payload.get("row") or 0, payload.get("col") or 0,
                    payload.get("text") or "")))
            if url.path == "/api/table":
                return self._send(200, json.dumps(make_table(
                    payload.get("html") or "", payload.get("tsv") or "")))
            if url.path == "/api/comment/delete":
                item_id = str(payload.get("id", ""))
                comment_id = str(payload.get("commentId", ""))
                if not item_id.isdigit() or not comment_id.isdigit():
                    raise ApiError(400, "Bad work item or comment id.")
                return self._send(200, json.dumps(delete_comment(
                    item_id, comment_id, payload.get("project"))))
            if url.path == "/api/description":
                item_id = str(payload.get("id", ""))
                if not item_id.isdigit():
                    raise ApiError(400, "Bad work item id.")
                return self._send(200, json.dumps(
                    edit_description(item_id, payload)))
            if url.path == "/api/comment":
                item_id = str(payload.get("id", ""))
                comment_id = str(payload.get("commentId", ""))
                if not item_id.isdigit() or not comment_id.isdigit():
                    raise ApiError(400, "Bad work item or comment id.")
                return self._send(200, json.dumps(
                    edit_comment(item_id, comment_id, payload)))
            if url.path.startswith("/api/item/"):
                item_id = url.path.rsplit("/", 1)[-1]
                if not item_id.isdigit():
                    raise ApiError(400, "Bad work item id.")
                update_item(item_id, payload)
                return self._send(200, json.dumps({"ok": True}))
            if url.path == "/api/notifications":
                with _feed_lock:
                    del _feed[:]
                return self._send(200, json.dumps({"ok": True}))
            if url.path == "/api/signin":
                try:
                    return self._send(200, json.dumps(azdo_auth.begin_device_code()))
                except RuntimeError as exc:
                    raise ApiError(502, str(exc))
            if url.path == "/api/signin/poll":
                code = payload.get("deviceCode") or ""
                if not code:
                    raise ApiError(400, "Missing device code.")
                try:
                    state = azdo_auth.poll_device_code(code)
                except RuntimeError as exc:
                    raise ApiError(400, str(exc))
                if state == "ok":
                    _identity_cache.clear()
                return self._send(200, json.dumps({"status": state}))
            return self._send(404, json.dumps({"error": "Not found"}))
        except ApiError as exc:
            self._send(exc.status if exc.status >= 400 else 500,
                       json.dumps({"error": exc.message}))
        except Exception as exc:
            self._send(500, json.dumps({"error": str(exc)}))


def _write_url_file(url):
    """Hand the nonce-bearing URL to the launcher via the user's profile.

    The page URL is now a secret, so it cannot be guessed by the shortcut; it
    is passed through a file only this user account can read.
    """
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(URL_FILE, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(url)
    except OSError as exc:
        print("[warn] could not write {}: {}".format(URL_FILE, exc))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("CE_BOARD_PORT", "8787")))
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--poll", type=int,
                        default=int(os.environ.get("CE_BOARD_POLL", "180")),
                        help="Seconds between comment checks (0 disables).")
    args = parser.parse_args()

    # Do not fail fast on a missing sign-in: the dashboard now handles the
    # device-code flow in the browser, which is the whole point of "just open
    # the UI". Only report what we found.
    signed_in = azdo_auth.have_credentials()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = "http://127.0.0.1:{}/{}/".format(args.port, NONCE)
    _write_url_file(url)
    print("CE dashboard running at {}".format(url))
    print("Org/project: {}/{}".format(ORG, PROJECT))
    if not signed_in:
        print("No cached sign-in yet - use the Sign in button on the page.")
    stop_event = threading.Event()
    if args.poll > 0:
        print("Watching for comments, state changes and reassignments "
              "every {}s".format(args.poll))
        threading.Thread(target=poll_comments, args=(args.poll, stop_event),
                         daemon=True).start()
    print("Press Ctrl+C to stop.")
    sys.stdout.flush()
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping.")
    finally:
        stop_event.set()
        try:
            os.remove(URL_FILE)
        except OSError:
            pass
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
