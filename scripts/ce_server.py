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
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import azdo_auth

API = "7.1"
ORG = os.environ.get("AZDO_ORG", "ni")
PROJECT = os.environ.get("AZDO_PROJECT", "DevCentral")
NONCE = secrets.token_urlsafe(24)
URL_FILE = os.path.join(os.path.expanduser("~"), ".azdo_ce_board_url")

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
    "System.ChangedDate", "System.Tags", "System.TeamProject",
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


def build_comment_html(text, mentions):
    """Turn plain comment text into the HTML Azure DevOps needs, converting
    picked people into real @mention anchors so they get notified."""
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
    return html.replace("\r\n", "\n").replace("\n", "<br>")


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
    if comment:
        ops.append({"op": "add", "path": "/fields/System.History",
                    "value": build_comment_html(comment, changes.get("mentions"))})
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
    return {"name": name, "url": created["url"], "size": len(blob)}


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
    comments = [{
        "id": c.get("id"),
        "author": (c.get("createdBy") or {}).get("displayName", ""),
        "at": c.get("createdDate", ""),
        "text": _strip_html(c.get("text", "")),
        "html": safe_html(c.get("text", "")),
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
            "description": _strip_html(f.get("System.Description", "")),
            "repro": _strip_html(f.get("Microsoft.VSTS.TCM.ReproSteps", "")),
            "descriptionHtml": safe_html(f.get("System.Description", "")),
            "reproHtml": safe_html(f.get("Microsoft.VSTS.TCM.ReproSteps", "")),
            "url": "https://dev.azure.com/{}/{}/_workitems/edit/{}".format(
                ORG, urllib.parse.quote(owner), item.get("id")),
        },
        "attachments": attachments,
        "links": links,
        "comments": comments,
    }


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
    try:
        with open(SEEN_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return {str(k): set(v) for k, v in data.get("comments", {}).items()}
    except (IOError, OSError, ValueError):
        return {}


def _save_seen(seen):
    try:
        with open(SEEN_PATH, "w", encoding="utf-8") as handle:
            json.dump({"comments": {k: sorted(v) for k, v in seen.items()}}, handle)
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


def _strip_html(text):
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text or "")
    text = re.sub(r"(?i)<br\s*/?>|</p>|</div>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\s+", " ", text.replace("&nbsp;", " ")
                  .replace("&amp;", "&").replace("&lt;", "<")
                  .replace("&gt;", ">")).strip()


def poll_comments(interval, stop_event):
    """Watch open items for new comments and raise a desktop notification."""
    seen = _load_seen()
    first_pass = not seen
    me = ""
    while not stop_event.is_set():
        try:
            # Before first sign-in there is nothing to poll; wait quietly
            # rather than triggering a blocking console device-code prompt.
            if not azdo_auth.have_credentials():
                stop_event.wait(interval)
                continue
            if not me:
                me = my_display_name()
            items = list_items(open_only=True)
            active_ids = set()
            for item in items:
                item_id = str(item["id"])
                active_ids.add(item_id)
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
                    author = ((comment.get("createdBy") or {}).get("displayName")
                              or "Someone")
                    # Seeding the very first run would fire a burst of toasts for
                    # history the user has already read.
                    if first_pass or author == me:
                        continue
                    body = _strip_html(comment.get("text", ""))[:200]
                    entry = {
                        "workItemId": item["id"],
                        "title": item["title"],
                        "author": author,
                        "text": body,
                        "at": comment.get("createdDate", ""),
                        "url": item["url"],
                    }
                    with _feed_lock:
                        _feed.insert(0, entry)
                        del _feed[FEED_LIMIT:]
                    toast("New comment on {}".format(item["id"]),
                          "{}: {}".format(author, body))
            # Drop state for items that closed so the file cannot grow forever.
            for stale in set(seen) - active_ids:
                seen.pop(stale, None)
            _save_seen(seen)
            first_pass = False
        except Exception as exc:
            print("[poll] {}".format(exc))
            sys.stdout.flush()
        stop_event.wait(interval)


# Raw string: this is JavaScript/CSS, so backslash escapes such as \n in regexes
# must reach the browser intact rather than being consumed by Python.
PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>My Azure DevOps CEs</title>
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
        <label>Comment (added to Discussion) &mdash; type @ to tag someone</label>
        <div class="cwrap"><textarea id="c${w.id}" autocomplete="off"
             oninput="onComment(${w.id})" onkeydown="mentionKey(event, ${w.id})"></textarea>
          <div class="mbox" id="mb${w.id}"></div></div>
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

async function loadDetail(id) {
  const box = document.getElementById("d" + id);
  if (!box) return;
  box.textContent = "Loading details...";
  try {
    const d = await api("/api/detail?id=" + id);
    const it = d.item, body = it.descriptionHtml || it.reproHtml || "";
    const meta = [["Created", `${esc(it.createdBy)} on ${esc((it.createdDate || "").slice(0, 10))}`],
                  ["Updated", esc((it.changedDate || "").slice(0, 16).replace("T", " "))],
                  ["Area", esc(it.areaPath)], ["Reason", esc(it.reason)],
                  ["Tags", esc(it.tags) || "-"]];
    const thread = d.comments.length
      ? d.comments.map(c => `<div class="cm"><span class="meta">${esc(c.author)} &middot; ${
            esc((c.at || "").slice(0, 16).replace("T", " "))}</span><div class="rich">${
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
      (body ? `<div class="desc rich">${body}</div>` : "") +
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

async function save(id) {
  const btn = document.getElementById("b" + id), msg = document.getElementById("m" + id);
  const w = items.find(x => x.id === id);
  const fields = {}, title = document.getElementById("t" + id).value.trim(),
        state = document.getElementById("s" + id).value,
        who = document.getElementById("a" + id).value.trim(),
        comment = document.getElementById("c" + id).value;
  if (title && title !== w.title) fields["System.Title"] = title;
  if (state && state !== w.state) fields["System.State"] = state;
  if (who !== w.assignedTo) fields["System.AssignedTo"] = who;
  if (!Object.keys(fields).length && !comment.trim()) { msg.className = "msg"; msg.textContent = "No changes."; return; }
  btn.disabled = true; msg.className = "msg"; msg.textContent = "Saving...";
  // Only send people actually still referenced in the text.
  const mentions = (picked[id] || []).filter(p => comment.includes("@" + p.name));
  try {
    await api("/api/item/" + id, {method: "POST", body: JSON.stringify({fields, comment, mentions})});
    msg.className = "msg ok";
    msg.textContent = "Saved." + (mentions.length ? ` Tagged ${mentions.length} person(s).` : "");
    document.getElementById("c" + id).value = "";
    picked[id] = [];
    await load(true);
    openItem(id);
  } catch (e) { msg.className = "msg err"; msg.textContent = String(e.message || e); }
  btn.disabled = false;
}

// ---- @mention autocomplete -------------------------------------------------
const picked = {};       // work item id -> people already inserted
let mState = null;       // {id, start, people, active}

function mentionQuery(box) {
  // Look back from the caret for an "@..." run that has no whitespace break.
  const upto = box.value.slice(0, box.selectionStart);
  const at = upto.lastIndexOf("@");
  if (at < 0) return null;
  const frag = upto.slice(at + 1);
  if (/[\n\r]/.test(frag) || frag.length > 40) return null;
  if (at > 0 && !/[\s(<]/.test(upto[at - 1])) return null;
  return {start: at, text: frag};
}

async function onComment(id) {
  const box = document.getElementById("c" + id);
  const q = mentionQuery(box);
  if (!q || q.text.trim().length < 2) return hideMentions(id);
  try {
    const d = await api("/api/people?q=" + encodeURIComponent(q.text.trim()));
    if (!d.people.length) return hideMentions(id);
    // The caret may have moved on while the lookup was in flight.
    const still = mentionQuery(box);
    if (!still || still.start !== q.start) return;
    mState = {id, start: q.start, people: d.people, active: 0};
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
  const {id, start} = mState, person = mState.people[index];
  const box = document.getElementById("c" + id);
  const after = box.value.slice(box.selectionStart);
  const insert = "@" + person.name + " ";
  box.value = box.value.slice(0, start) + insert + after;
  const caret = start + insert.length;
  box.focus(); box.setSelectionRange(caret, caret);
  picked[id] = (picked[id] || []).filter(p => p.id !== person.id).concat(person);
  hideMentions(id);
}

function mentionKey(event, id) {
  if (!mState || mState.id !== id) return;
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
        print("Watching for new comments every {}s".format(args.poll))
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
