---
name: ado-triage
description: Query, triage and edit Azure DevOps work items and Customer Escalations (CEs) using Microsoft sign-in, with no Personal Access Token. Also runs a local dashboard for editing CEs, adding comments, searching closed cases, and desktop alerts on new comments. Use when the user asks about their Azure DevOps work items, CEs, escalations, bugs, or backlog — for example "list my open CEs", "what work items did I create", "triage my escalations", "show work item 123456", "which of my items are stale", "open my CE board", "add a comment to a CE", or "search my closed cases".
---

# Azure DevOps work item triage

Query Azure DevOps work items and triage Customer Escalations. Authentication
uses the Microsoft device code flow, so **no Personal Access Token is needed**.

## Setup

Scripts live in `scripts/` next to this file. They need only Python 3.6+ and
the standard library — no `pip install`.

Defaults are `AZDO_ORG=ni` and `AZDO_PROJECT=DevCentral`. Override per user:

```
$env:AZDO_ORG="myorg"; $env:AZDO_PROJECT="MyProject"
```

Or pass `--org` / `--project` on any command.

## First run

On first use the tool prints a URL and a code. **Show both to the user and stop
your turn** — they must sign in before anything else works:

```
python scripts/azdo_auth.py
```

Tokens cache to `~/.azdo_cli_token.json` with a refresh token, so sign-in is a
one-time step per machine. `python scripts/azdo_auth.py --sign-out` clears it.

If a query returns an auth error, run `azdo_auth.py --force` to re-sign-in.

## Commands

```
python scripts/azdo_workitems.py --whoami                     # signed-in identity
python scripts/azdo_workitems.py --created --open-only        # my open items
python scripts/azdo_workitems.py --created                    # all I created
python scripts/azdo_workitems.py --mine                       # assigned to me
python scripts/azdo_workitems.py --recent                     # recently changed
python scripts/azdo_workitems.py --id 123456                  # one item + description
python scripts/azdo_workitems.py --projects                   # list projects
python scripts/azdo_workitems.py --query "SELECT ..."         # raw WIQL
```

Useful flags: `--json` for machine-readable output, `--top N` to raise the limit
(default 50), `--open-only` to drop Closed/Removed/Done.

On Windows set `$env:PYTHONIOENCODING="utf-8"` before running, or non-ASCII
names in results can crash a legacy-codepage console.

## Dashboard (view, edit, comment, search, notifications)

`scripts/ce_server.py` serves a local web UI on `127.0.0.1` that does what the
read-only CLI cannot: **edit work items and add comments**.

```
python scripts/ce_server.py                    # start + open a browser
python scripts/ce_server.py --no-browser --port 8787 --poll 180
```

What it offers:

- **List** — your open items (created by you), with state pills and assignee.
- **Open one item** — click a row, or deep link to `http://127.0.0.1:8787/#4040690`.
  The expanded pane shows created/updated/area/reason/tags, the description, and
  the full **Discussion thread**.
- **Edit** — Title, State (options pulled live from the work item type's real
  workflow), Assigned To (email; blank unassigns), plus a Comment box. `Save`
  writes back via a JSON-Patch `PATCH`. Azure DevOps rule violations are shown
  verbatim rather than swallowed.
- **@mention people** — type `@` followed by two or more letters in the comment
  box to get a live people picker (arrow keys / Enter / Tab / Esc, or click).
  Picked people are converted server-side into real Azure DevOps mention
  anchors (`data-vss-mention="version:2.0,<identity guid>"`), so they get the
  normal notification — not just plain `@text`. Comment text is HTML-escaped
  first, and only people still referenced in the final text are sent.
- **Images and attachments** — descriptions and comments are rendered as
  sanitised rich HTML rather than flattened to plain text, so inline screenshots
  appear in place. Image attachments also get a thumbnail gallery; other files
  become links. Clicking any image opens a full-size lightbox (`Esc` closes).

  Two pieces make this work:

  - `safe_html()` — an `HTMLParser`-based whitelist sanitiser. It keeps
    formatting, tables, links and `<img>`, and drops `<script>`/`<style>`/
    `<iframe>`, every event handler attribute, and `javascript:` hrefs. It also
    balances unclosed tags, which ADO rich text is full of. Anything it cannot
    parse falls back to escaped plain text.
  - `GET /img?n=<nonce>&u=<url>` — an authenticated image proxy. The browser has
    no Azure DevOps credentials, so it cannot load an attachment URL directly;
    `safe_html` rewrites each `src` to this route, which re-fetches the bytes
    with the user's bearer token. `<img>` requests cannot carry custom headers,
    so the nonce travels in the query string instead of `x-ce-nonce`. The proxy
    only accepts `https` URLs whose host is `dev.azure.com` or
    `*.visualstudio.com` (checked by hostname, so `dev.azure.com.evil.com`
    fails) and only returns `image/*` or `application/pdf`. `data:image/...`
    URIs are passed through untouched.

  Attachment URLs that carry no `?fileName=` parameter come back as
  `application/octet-stream` even when they are real JPEGs, so `_sniff_image()`
  checks the magic bytes before the proxy rejects anything. Without it a
  noticeable share of inline screenshots render broken.

- **Attachments — download and upload** — every attached file is listed with its
  size and a Download link (`GET /file?n=&u=&name=`, which streams the bytes
  with a `Content-Disposition` filename). Files can be added by drag-and-drop or
  a file picker; several at once, capped by `CE_BOARD_MAX_UPLOAD_MB` (default
  60 MB).

  Upload is two steps: `POST _apis/wit/attachments?fileName=` returns a URL,
  then a JSON-Patch adds an `AttachedFile` relation pointing at it. The browser
  sends the file as the **raw request body** with the metadata in the query
  string, so the server needs no multipart parser.

- **Links** — hyperlinks and work item links are listed together. Linked work
  items are resolved through one `workitemsbatch` call (`_annotate_links()`) so
  each row shows its title and current state rather than a bare ID. New links
  are added by type: related, parent, child, duplicate, successor, predecessor,
  or a plain URL hyperlink. A work item target is fetched first, so a typo fails
  with a clear error instead of creating a dangling link.

- **Removing a file or link** — `remove_relation()` deletes by **URL, not by
  index**. It re-reads the item, finds the matching relation, and sends a
  JSON-Patch with a `test` op on `/rev`. A stale page therefore cannot detach
  the wrong thing, and a concurrent edit fails loudly instead of silently
  removing a neighbour.


  - *Created by me* (default) — matches both CreatedBy storage shapes, so it
    finds the items `@Me` alone would miss.
  - *Assigned to me*.
  - *Followed by me* — everything the user pressed **Follow** on.
  - *All of this project* — any work item regardless of who raised it. A search
    term or ID is required here, since an unbounded project-wide list is not
    useful. Results show `by <creator>` under the assignee.

  **Follows have no WIQL predicate.** Each one is a personal notification
  subscription, so `followed_ids()` reads
  `_apis/notification/subscriptions?subscriberId=<my id>` and keeps the entries
  whose filter is `type: Artifact` / `artifactType: WorkItem`; `artifactId` is
  the plain work item ID. The result is cached for 60 s, then fed into a WIQL
  `[System.Id] IN (...)` so the usual state and keyword filters still apply.

  Follows are **not confined to one project**, so that query runs org-wide
  (no `_apis` project prefix and no `System.TeamProject` clause). Rows from
  another project get a badge and a link into their own project. Because the
  comments endpoint *is* project-scoped, `item_detail()` reads
  `System.TeamProject` from the item and passes it to `fetch_comments()` —
  without that, opening a followed item from another project returns no
  discussion.

  A numeric query is always fetched by ID directly and ignores scope, so you can
  jump to any work item you have permission to read.
- **New comment alerts** — a background poller checks your open items every
  `--poll` seconds, raises a Windows toast, and lists the comment in a banner
  you can click to jump straight to that item. Comments you wrote yourself are
  ignored, and the first run seeds silently instead of announcing history.
  Seen comment ids persist in `~/.azdo_ce_seen.json`.

Environment: `AZDO_ORG`, `AZDO_PROJECT`, `CE_BOARD_PORT`, `CE_BOARD_POLL`,
`CE_BOARD_LOG`, `CE_BOARD_SEEN`.

Only loopback is bound, and every API call needs a per-launch nonce header, so
another local user or a web page cannot drive it.

### Keep it running across restarts

```
python scripts/install_autostart.py            # register, shortcuts, start now
python scripts/install_autostart.py --status
python scripts/install_autostart.py --uninstall
```

It tries a Task Scheduler logon task first and falls back to a per-user Startup
folder entry when corporate policy denies `schtasks` (common). Either way it
runs under `pythonw.exe`, so there is no console window; output goes to
`~/.azdo_ce_board.log`. It also creates **CE Board** shortcuts on the Desktop
and in the Start Menu pointing at `scripts/open_board.py`, which starts the
server if needed and then opens the page.

### First-run sign-in

The dashboard handles sign-in itself: if there is no cached token the page shows
a **Sign in** button, displays the device code, opens the Microsoft page, and
continues automatically once you finish. The command line is never required, so
non-technical colleagues can use the tool without touching a terminal.

### Sharing it with colleagues

The folder is self-contained and carries no credentials (tokens live in each
user's `~/.azdo_cli_token.json`). Zip it, put it on a share, or commit it to a
repo. A colleague copies it and double-clicks `Install.cmd`, which resolves a
Python interpreter, asks for org/project, installs autostart and shortcuts, and
opens the board. `README.md` is written for that audience.

**No prerequisites, including Python.** `Install.cmd` resolves an interpreter in
this order: a `runtime` folder beside the tool, then a system Python 3.7+ on
PATH, then — with the user's consent — the official portable build from
python.org unpacked into `runtime`. That is a plain zip: no admin rights, no
system-wide install, no PATH or registry changes. `scripts/bootstrap.py` exposes
the same resolution logic to Python callers.

Two package shapes:

- **online** (~32 KB) — downloads the runtime only if the PC has no Python.
- **offline** (~42 MB) — ships the `runtime` folder, for networks that block
  python.org.

## The CreatedBy gotcha — important

Azure DevOps stores `System.CreatedBy` in **two different ways**, and they do
not overlap:

- a **linked AAD identity** (e.g. `Ayden, Foo <ayden.foo@emerson.com>`) — this
  is what `@Me` matches
- an **unresolved display-name string** (e.g. `Ayden Foo`) written by some
  intake paths — `@Me` never matches these

Querying only `[System.CreatedBy] = @Me` can therefore silently hide a large
share of a user's items. Control this with `--creator-match`:

| Value | Matches | Use when |
|---|---|---|
| `contains` (default) | display-name text | items raised through CE intake tooling |
| `identity` | `@Me` only | items created directly in Azure DevOps |
| `both` | either | **the true total** |

If a user says an item is missing from results, re-run with
`--creator-match both` before concluding anything.

## Triage guidance

When asked to triage or analyse, fetch the list with `--json`, then pull detail
for each item with `--id`. Assess and report:

1. **Unassigned open items** — highest priority; nobody owns them
2. **Staleness** — compare `changedDate` to today; call out the longest idle
3. **Terminal-ish states still open** — e.g. `Implemented` or `Resolved` that
   should probably be verified and closed
4. **Blocked on information** — the item's Outstanding Question asks for docs,
   logs, or versions rather than engineering work; these are the cheapest wins
5. **Recurrence signals** — questions like "why is this still happening after
   corrective action" indicate a systemic issue worth linking to related items
6. **Waiting tags** — e.g. `Waiting for TSE` means correctly parked, not stalled

Group findings by urgency, give each item a concrete next action, and note any
cross-item patterns. Report real dates and states from the data; never invent
work items or statuses.

## Security design (do not regress these)

- **The page URL is a secret.** `GET /` returns 404; the page is served only at
  `/<NONCE>/`, and the URL is published to `~/.azdo_ce_board_url` (mode 0600)
  for `open_board.py`. Serving the nonce-bearing page at `/` would hand every
  API capability to any local process that can open a loopback socket, since
  Windows loopback is not per-user.
- **`/img` and `/file` never accept a URL from the browser.** They take an
  opaque key resolved through `_res_map`, populated only by `res_key()` when
  the *server* decided a URL was proxyable. An `<img src>` in a work item is
  content any org member can write, so accepting `u=` was a no-interaction
  path to token theft.
- **Redirects are never followed** (`_NoRedirect` / `_no_redirect_opener`).
  `urllib`'s default handler copies the `Authorization` header across hosts
  and schemes, so a single redirect would leak the bearer token. Hops are
  re-validated and must stay on the same host.
- **`_is_ado_url()` is scoped to this org**, not to Azure DevOps generally:
  `*.dev.azure.com` and `*.visualstudio.com` are multi-tenant namespaces any
  attacker can register in.
- **`_safe_href()` gates every URL that reaches an `href`.** Relation URLs come
  from Azure DevOps and may contain `javascript:`; the client-side `esc()`
  escapes only `& < > "` and would pass it through.
- **CSP on the page** is `default-src 'none'` with `connect-src 'self'`, so
  even a script that slipped through has no external origin to exfiltrate to.
  The page uses no `<form>` and no external resources — keep it that way.
- **The portable Python download is checksum-pinned** (`bootstrap.py:SHA256`
  and the same value in `Install.cmd`), because that interpreter ends up
  holding the user's token and TLS alone is weak against an intercepting
  proxy. Bump both together when changing `VERSION`.
- Nonce comparisons use `hmac.compare_digest`.

## Notes

- The tool reads and writes: it can update fields, post comments, upload
  attachments and add or remove links. Never mutate a real work item without
  the user's explicit confirmation.
- `AZDO_PAT` is honoured if set, for environments where interactive sign-in is
  blocked, but it is not required.
- Sign-in uses the Azure CLI public client id with the Azure DevOps resource
  scope — the standard Microsoft public client, nothing custom.
