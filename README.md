# CE Board — Azure DevOps escalation dashboard

A small local dashboard for triaging Azure DevOps work items and Customer
Escalations: list them, open one, edit it, comment with @mentions, search the
whole project, and get a desktop toast when someone replies.

Everything runs on your own machine. There is no server to host, no database,
and no Personal Access Token.

## Install

1. Copy this whole folder anywhere on your PC (Desktop, Documents, a network
   share — it does not matter).
2. Double-click **`Install.cmd`**.
3. Confirm your Azure DevOps organisation and project when prompted
   (defaults: `ni` / `DevCentral`).
4. The board opens. Click **Sign in**, enter the code shown on the Microsoft
   page, and you are done.

You now have a **CE Board** shortcut on your Desktop and in the Start Menu, and
the board starts automatically whenever you sign in to Windows.

**You do not need to install anything first — not even Python.** Setup uses a
Python already on your PC if there is one; otherwise it offers to download the
official portable build from python.org (about 11 MB) into a `runtime` folder
beside these files. That copy is private to this tool: no admin rights, no
system-wide install, no PATH or registry changes, and deleting the folder
removes it completely.

If your network blocks python.org, ask whoever shared this tool for the
**offline** package, which already contains the `runtime` folder.

Requirements: Windows 10 or 11. Nothing else — no `pip install`, no Node.js,
no Azure CLI, no admin rights, no Personal Access Token.

## Daily use

Open the **CE Board** shortcut.

| What you want | How |
| --- | --- |
| See your open items | Default view |
| Open one | Click the row |
| Change State / Assignee / Title | Expand the row, edit, **Save** |
| Comment | Expand the row, type in the comment box, **Save** |
| Tag a colleague | Type `@` plus 2+ letters and pick from the list |
| Find an old case | Type a keyword or the ID, tick *include closed* |
| Search someone else's items | Set the scope dropdown to *All of this project* |
| See cases you follow | Set the scope dropdown to *Followed by me* |
| Know when someone replies | A Windows toast appears; the item is listed in a banner |
| See a screenshot | Images in the description and comments render inline |
| View an image full size | Click it; press `Esc` or click the backdrop to close |
| Download an attachment | Expand the row, **Download** next to the file |
| Add a file | Drag it onto the drop area, or click *browse* |
| Link a related case | Pick the link type, enter the work item ID, **Add link** |
| Link a web page | Choose *Hyperlink (URL)*, paste the URL, **Add link** |
| Detach a file or link | **Remove** on its row (asks first) |

Screenshots are the whole point of most CEs, so they render in place. Azure
DevOps keeps attachments behind an authenticated URL that a browser cannot fetch
on its own, so the board re-requests each image with your token and serves it
locally. Attached files that are not images appear as links.

You can attach several files at once, up to 60 MB each. Linked work items show
their title and current state, so you can see at a glance whether a related case
is still open. `Remove` detaches the file or link from the work item; it never
deletes anything else.

*Followed by me* lists everything you clicked **Follow** on in Azure DevOps,
including items in other projects — those carry a purple project badge and open
against their own project.

## Sign-in and security

Sign-in uses the standard Microsoft device-code flow. You get a code, you enter
it on `microsoft.com/devicelogin`, and Microsoft issues a token. This tool never
sees your password.

- The token is cached in **your own** user profile at `~/.azdo_cli_token.json`,
  never inside this folder, so copying the folder never carries credentials.
  It is protected by your Windows user-profile permissions: another standard
  user cannot read it, but anything running **as you** — or a local
  administrator — can. Treat it like a password file.
- The server listens on `127.0.0.1` only, so nothing on the network can reach
  it, and stray web pages cannot drive it (every API call needs a per-launch
  nonce that a cross-origin page cannot obtain).
- The page itself lives at an unguessable per-launch URL, published to
  `~/.azdo_ce_board_url` for the shortcut to read. Browse to
  `http://127.0.0.1:8787/` directly and you get a 404 — that is deliberate, so
  another program on the machine cannot simply read the page and lift the
  nonce from it. Note that a process running under **your own** account can
  still read that file; the boundary here is between user accounts, not
  between programs you run.
- Attachments and inline images are fetched with your token by the board, and
  only from this organisation's Azure DevOps host. Redirects are not followed,
  so your token cannot be forwarded elsewhere.
- New-comment pop-ups include a short excerpt of the comment. Windows keeps
  notification history, so that excerpt persists in Windows' own store; turn
  polling off with `CE_BOARD_POLL=0` if that is not acceptable for the content
  you handle.
- You can only see and change what your Azure DevOps account already permits.
  All work item rules are still enforced by Azure DevOps.

Sign out with `python scripts\azdo_auth.py --sign-out`.

## Configuration

Set these before launching if you need something other than the defaults:

| Variable | Default | Meaning |
| --- | --- | --- |
| `AZDO_ORG` | `ni` | Azure DevOps organisation |
| `AZDO_PROJECT` | `DevCentral` | Project |
| `CE_BOARD_PORT` | `8787` | Local port |
| `CE_BOARD_POLL` | `180` | Seconds between comment checks |

To change them permanently, re-run:

```
python scripts\install_autostart.py --org myorg --project MyProject --port 8900
```

## What it writes to your machine

Useful if your team has to answer where escalation data ends up.

| File | Contents |
| --- | --- |
| `~/.azdo_cli_token.json` | Your Azure DevOps access + refresh token. **Sensitive.** |
| `~/.azdo_ce_board_url` | The board's per-launch URL (contains the nonce). |
| `~/.azdo_ce_seen.json` | Comment IDs already notified — numbers only, no text. |
| `~/.azdo_ce_board.log` | Startup and error messages. No tokens, no comment text. |
| `scripts\_ce_board_launch.cmd` | Your org/project/port. No credentials. |

No work item text, no attachment, and no uploaded file is ever written to disk
— uploads stream straight through to Azure DevOps. The one exception is the
Windows notification history noted above.

## Removing it

```
python scripts\install_autostart.py --uninstall
```

That removes the autostart entry and both shortcuts. Delete the folder,
`~/.azdo_cli_token.json`, `~/.azdo_ce_board_url`, `~/.azdo_ce_seen.json` and
`~/.azdo_ce_board.log` to remove every trace.

## Troubleshooting

**The board does not open.** Look at `%USERPROFILE%\.azdo_ce_board.log`.

**`http://127.0.0.1:8787/` shows "Not found".** Expected — the board is at the
secret URL in `~/.azdo_ce_board_url`. Use the shortcut, or open that URL.

**Port already in use.** Something else has 8787; reinstall with `--port 8900`.

**"Not signed in".** Your refresh token expired. Click **Sign in** again.

**A State change is rejected.** Azure DevOps work item rules are enforced
server-side; the exact reason is shown in the UI.

## Using it from Copilot instead

This folder is also a Copilot CLI skill. Drop it into your Copilot skills
directory and ask questions like *"list my open CEs"* or *"triage my
escalations"*. See `SKILL.md`.
