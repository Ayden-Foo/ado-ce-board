"""Query Azure DevOps work items. Signs in with Microsoft; no PAT required.

Configuration (all optional):
    AZDO_ORG       organization name     (default: ni)
    AZDO_PROJECT   project name          (default: DevCentral)
    AZDO_PAT       personal access token (optional; used instead of sign-in)

Usage:
    python azdo_workitems.py --whoami                # signed-in identity
    python azdo_workitems.py --created --open-only   # my open items
    python azdo_workitems.py --mine                  # assigned to me
    python azdo_workitems.py --id 123456             # one work item
    python azdo_workitems.py --query "SELECT ..."    # raw WIQL
    python azdo_workitems.py --projects              # list projects
Add --json to any listing for machine-readable output.
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Windows consoles often default to a legacy codepage that cannot render
# non-ASCII names, so force UTF-8 output where the runtime allows it.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (ValueError, OSError):
        pass

API = "7.1"

_AUTH_HEADER = None

RECENT_WIQL = """
SELECT [System.Id] FROM WorkItems
WHERE [System.TeamProject] = @project
ORDER BY [System.ChangedDate] DESC
"""

MINE_WIQL = """
SELECT [System.Id] FROM WorkItems
WHERE [System.TeamProject] = @project
  AND [System.AssignedTo] = @me
  AND [System.State] NOT IN ('Closed', 'Removed', 'Done')
ORDER BY [System.ChangedDate] DESC
"""

CREATED_STATES_DONE = ("Closed", "Removed", "Done")


def get_identity(org):
    """Return (displayName, uniqueName) for the signed-in user."""
    data = request("https://dev.azure.com/{}/_apis/connectionData"
                   "?connectOptions=none&api-version=7.1-preview".format(
                       urllib.parse.quote(org)))
    user = data.get("authenticatedUser", {}) or {}
    account = (user.get("properties", {}) or {}).get("Account", {}) or {}
    return user.get("providerDisplayName", ""), account.get("$value", "")


def created_by_me_wiql(org, project, mode="contains", states=None):
    """Build a 'created by me' query.

    Azure DevOps stores System.CreatedBy either as a linked identity or, for
    items raised through some intake paths, as an unresolved display-name
    string. @Me matches only the former, so the mode controls which is used:
      contains - display-name text match
      identity - @Me only
      both     - either
    """
    display, _ = get_identity(org)
    identity_clause = "[System.CreatedBy] = @Me"
    name_clause = "[System.CreatedBy] CONTAINS {}".format(
        "'{}'".format(display.replace("'", "''"))) if display else None

    if mode == "identity" or not name_clause:
        creator = identity_clause
    elif mode == "both":
        creator = "({} OR {})".format(identity_clause, name_clause)
    else:
        creator = name_clause

    where = ["[System.TeamProject] = {}".format(
        "'{}'".format(project.replace("'", "''"))), creator]
    if states:
        where.append("[System.State] NOT IN ({})".format(
            ", ".join("'{}'".format(s.replace("'", "''")) for s in states)))
    return ("SELECT [System.Id] FROM WorkItems WHERE {} "
            "ORDER BY [System.ChangedDate] DESC".format(" AND ".join(where)))

FIELDS = [
    "System.Id",
    "System.WorkItemType",
    "System.Title",
    "System.State",
    "System.AssignedTo",
    "System.CreatedBy",
    "System.CreatedDate",
    "System.ChangedDate",
    "System.Tags",
]


def auth_header():
    """Prefer a PAT when supplied, otherwise use interactive Microsoft sign-in."""
    global _AUTH_HEADER
    pat = os.environ.get("AZDO_PAT")
    if pat:
        if not _AUTH_HEADER:
            token = base64.b64encode((":" + pat).encode("utf-8")).decode("ascii")
            _AUTH_HEADER = "Basic " + token
        return _AUTH_HEADER
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import azdo_auth
    except ImportError:
        raise SystemExit(
            "No AZDO_PAT set and azdo_auth.py is missing. Add one or the other."
        )
    # Not cached here: get_access_token caches internally and refreshes on
    # expiry, which long-running callers depend on.
    return "Bearer " + azdo_auth.get_access_token()


def request(url, payload=None, attempts=4):
    data = None
    headers = {"Authorization": auth_header(), "Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    for attempt in range(attempts):
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read().decode("utf-8", "replace")
            break
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            # Azure DevOps throttles bursts; back off and retry rather than fail.
            if exc.code in (429, 502, 503, 504) and attempt < attempts - 1:
                delay = float(exc.headers.get("Retry-After") or 0) or 2 ** attempt
                time.sleep(min(delay, 30))
                continue
            if exc.code in (401, 203):
                raise SystemExit(
                    "Authentication failed. If using a PAT, check its scopes; "
                    "otherwise run: python azdo_auth.py --force"
                )
            if exc.code == 403:
                raise SystemExit("Access denied (403). Missing the required scope.")
            raise SystemExit("HTTP {} from Azure DevOps: {}".format(exc.code, detail))
        except urllib.error.URLError as exc:
            if attempt < attempts - 1:
                time.sleep(2 ** attempt)
                continue
            raise SystemExit("Network error: {}".format(exc.reason))
    if body.lstrip().startswith("<"):
        raise SystemExit(
            "Got a sign-in page instead of JSON -- the credentials are not valid."
        )
    return json.loads(body)


def base_url(org, project=None):
    url = "https://dev.azure.com/{}/".format(urllib.parse.quote(org))
    if project:
        url += urllib.parse.quote(project) + "/"
    return url + "_apis/"


def list_projects(org):
    result = request(base_url(org) + "projects?api-version=" + API)
    for item in result.get("value", []):
        print("{:<30} {}".format(item.get("name", "-"), item.get("state", "-")))
    print("\n{} project(s).".format(result.get("count", 0)))


def run_wiql(org, project, wiql, top):
    url = base_url(org, project) + "wit/wiql?api-version={}&$top={}".format(API, top)
    result = request(url, {"query": wiql})
    return [str(item["id"]) for item in result.get("workItems", [])][:top]


def fetch_items(org, ids):
    if not ids:
        return []
    items = []
    # The batch endpoint accepts at most 200 ids per call.
    for start in range(0, len(ids), 200):
        chunk = ids[start:start + 200]
        url = base_url(org) + "wit/workitemsbatch?api-version=" + API
        result = request(url, {"ids": [int(i) for i in chunk], "fields": FIELDS})
        items.extend(result.get("value", []))
    order = {wid: pos for pos, wid in enumerate(ids)}
    items.sort(key=lambda it: order.get(str(it.get("id")), 0))
    return items


def display_name(value):
    if isinstance(value, dict):
        return value.get("displayName") or value.get("uniqueName") or "-"
    return value or "-"


def to_records(org, project, items):
    """Flatten work items into plain dicts for JSON output."""
    records = []
    for item in items:
        f = item.get("fields", {})
        records.append({
            "id": item.get("id"),
            "type": f.get("System.WorkItemType"),
            "title": f.get("System.Title"),
            "state": f.get("System.State"),
            "assignedTo": display_name(f.get("System.AssignedTo")),
            "createdBy": display_name(f.get("System.CreatedBy")),
            "createdDate": f.get("System.CreatedDate"),
            "changedDate": f.get("System.ChangedDate"),
            "tags": f.get("System.Tags"),
            "url": "https://dev.azure.com/{}/{}/_workitems/edit/{}".format(
                org, project, item.get("id")),
        })
    return records


def print_items(items, org=None, project=None, as_json=False):
    if as_json:
        print(json.dumps(to_records(org, project, items), indent=2))
        return
    if not items:
        print("No work items found.")
        return
    header = "{:<9} {:<14} {:<14} {:<22} {}".format(
        "ID", "TYPE", "STATE", "ASSIGNED TO", "TITLE")
    print(header)
    print("-" * len(header))
    for item in items:
        f = item.get("fields", {})
        print("{:<9} {:<14} {:<14} {:<22} {}".format(
            item.get("id", "-"),
            (f.get("System.WorkItemType") or "-")[:13],
            (f.get("System.State") or "-")[:13],
            display_name(f.get("System.AssignedTo"))[:21],
            (f.get("System.Title") or "-")[:70],
        ))
    print("\n{} work item(s).".format(len(items)))


def show_item(org, project, item_id):
    url = base_url(org, project) + "wit/workitems/{}?api-version={}&$expand=all".format(
        urllib.parse.quote(str(item_id)), API)
    item = request(url)
    f = item.get("fields", {})
    print("ID:        {}".format(item.get("id")))
    print("Type:      {}".format(f.get("System.WorkItemType", "-")))
    print("Title:     {}".format(f.get("System.Title", "-")))
    print("State:     {}".format(f.get("System.State", "-")))
    print("Assigned:  {}".format(display_name(f.get("System.AssignedTo"))))
    print("Created:   {} by {}".format(
        f.get("System.CreatedDate", "-"), display_name(f.get("System.CreatedBy"))))
    print("Changed:   {}".format(f.get("System.ChangedDate", "-")))
    print("Tags:      {}".format(f.get("System.Tags") or "-"))
    print("URL:       https://dev.azure.com/{}/{}/_workitems/edit/{}".format(
        org, project, item.get("id")))
    description = f.get("System.Description") or f.get(
        "Microsoft.VSTS.TCM.ReproSteps")
    if description:
        import re
        text = re.sub(r"(?i)<br\s*/?>|</p>|</div>", "\n", description)
        text = re.sub(r"<[^>]+>", "", text)
        text = text.replace("&nbsp;", " ").replace("&amp;", "&")
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        print("\nDescription:\n{}".format(text[:2000]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--org", default=os.environ.get("AZDO_ORG", "ni"),
                        help="Azure DevOps organization (env AZDO_ORG)")
    parser.add_argument("--project",
                        default=os.environ.get("AZDO_PROJECT", "DevCentral"),
                        help="project name (env AZDO_PROJECT)")
    parser.add_argument("--top", type=int, default=50)
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of a table")
    parser.add_argument("--projects", action="store_true",
                        help="list projects (quick auth check)")
    parser.add_argument("--recent", action="store_true",
                        help="recently updated work items")
    parser.add_argument("--mine", action="store_true",
                        help="open work items assigned to you")
    parser.add_argument("--created", action="store_true",
                        help="work items you created")
    parser.add_argument("--creator-match", choices=("contains", "identity", "both"),
                        default="contains",
                        help="how --created matches CreatedBy (default: contains)")
    parser.add_argument("--open-only", action="store_true",
                        help="with --created, exclude Closed/Removed/Done")
    parser.add_argument("--whoami", action="store_true",
                        help="show the signed-in identity")
    parser.add_argument("--id", help="show one work item by id")
    parser.add_argument("--query", help="raw WIQL query")
    args = parser.parse_args(argv)

    def emit(ids):
        print_items(fetch_items(args.org, ids), args.org, args.project, args.json)

    if args.whoami:
        display, unique = get_identity(args.org)
        if args.json:
            print(json.dumps({"displayName": display, "uniqueName": unique}))
        else:
            print("{} <{}>".format(display or "-", unique or "-"))
    elif args.projects:
        list_projects(args.org)
    elif args.id:
        show_item(args.org, args.project, args.id)
    elif args.mine:
        emit(run_wiql(args.org, args.project, MINE_WIQL, args.top))
    elif args.created:
        states = CREATED_STATES_DONE if args.open_only else None
        wiql = created_by_me_wiql(args.org, args.project,
                                  mode=args.creator_match, states=states)
        emit(run_wiql(args.org, args.project, wiql, args.top))
    elif args.query:
        emit(run_wiql(args.org, args.project, args.query, args.top))
    else:
        emit(run_wiql(args.org, args.project, RECENT_WIQL, args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
