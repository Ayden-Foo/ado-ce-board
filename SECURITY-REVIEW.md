# CE Board — source and security review pack

Tool location: `%APPDATA%\com.github.githubapp\app-skills\ado-triage\`
Distributables: `Desktop\CE-Board.zip` (47.8 KB), `Desktop\CE-Board-offline.zip` (10.8 MB)

## File inventory

| File | Lines | Purpose |
| --- | --- | --- |
| `scripts/ce_server.py` | 1679 | HTTP server, ADO client, HTML sanitiser, embedded UI |
| `scripts/azdo_auth.py` | 172 | Device-code OAuth, token cache |
| `scripts/azdo_workitems.py` | 296 | Query CLI |
| `scripts/install_autostart.py` | 157 | Startup entry + shortcuts |
| `scripts/open_board.py` | 70 | Launcher; resolves the secret board URL |
| `scripts/bootstrap.py` | 115 | Python interpreter resolver + pinned download |
| `Install.cmd` | 87 | Three-tier interpreter bootstrap |
| `README.md` | 129 | Colleague-facing docs |
| `SKILL.md` | 236 | Agent-facing docs |

Excluded from distribution: `scripts/_ce_board_launch.cmd` (machine-specific),
`__pycache__`, `~/.azdo_cli_token.json`.

---

## The six security-critical sections

### 1. Host allowlist — scoped to this organisation

`ce_server.py`, before `_is_ado_url`:

```python
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
```

Uses `parts.hostname`, so `https://dev.azure.com@evil.com/` resolves to
`evil.com` and is rejected. CWE-346.

### 2. Opaque resource keys — the browser never supplies a URL

```python
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
```

An `<img src>` inside a work item is content any org member can write. Before
this change it steered an authenticated fetch. CWE-441, CWE-639.

### 3. Redirects are never followed

```python
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never let urllib follow a redirect on its own.

    The stdlib handler copies every header except content-length/content-type
    onto the redirected request, so an unchecked hop would forward the user's
    Azure DevOps bearer token to whatever host the redirect names.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_no_redirect_opener = urllib.request.build_opener(_NoRedirect)
```

Redirects are then handled manually: each hop is re-validated with
`_is_ado_url()` and must stay on the same host, max five hops. CWE-918.

### 4. The page URL is a secret

```python
if url.path in ("/", "/" + NONCE, "/" + NONCE + "/"):
    self._guard(need_nonce=False)
    if url.path == "/":
        # The page carries the nonce, so it must not be readable by
        # any local process that can simply GET "/". Knowing the
        # unguessable path is the price of admission.
        raise ApiError(404, "Not found.")
```

The URL is published to `~/.azdo_ce_board_url` with mode 0600 for the shortcut
to read. Windows loopback is not per-user, so without this any local process
could read the page and lift the nonce. CWE-200, CWE-522.

Nonce comparison is constant-time (CWE-208):

```python
if need_nonce and not hmac.compare_digest(
        self.headers.get("x-ce-nonce") or "", NONCE):
    raise ApiError(403, "Invalid nonce.")
```

### 5. Scheme allowlist on every href, plus CSP

```python
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
```

Defence in depth on the response:

```
default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline';
script-src 'unsafe-inline'; connect-src 'self'; form-action 'none';
base-uri 'none'
```

`connect-src 'self'` means an injected script has no external origin to
exfiltrate to. CWE-79.

### 6. Pinned interpreter download

`bootstrap.py`:

```python
VERSION = "3.11.9"
# SHA-256 of the official python-3.11.9-embed-amd64.zip. Cross-checked against
# the MD5 published on python.org's 3.11.9 release page.
SHA256 = "009d6bf7e3b2ddca3d784fa09f90fe54336d5b60f0e0f305c37f400bf83cfd3b"
```

Verified before unpacking or executing, because this interpreter ends up
holding the OAuth token and TLS alone is weak against an intercepting
corporate proxy. The same digest is pinned in `Install.cmd`. CWE-494.

---

## Verification evidence

| Test | Result |
| --- | --- |
| Redirect to attacker sink | Stopped at 302, 0 sink hits, token not forwarded |
| Host spoofing (8 cases incl. `evil.dev.azure.com`, `dev.azure.com@evil.com`) | 8/8 rejected |
| `GET /img?u=<url>` (old parameter) | 403 |
| `GET /img?k=deadbeef` | 403 |
| `GET /` | 404 |
| `GET /<nonce>/` | 200 |
| `GET /api/items` without nonce | 403 |
| Tampered runtime zip | Rejected on checksum |
| Inline images across 8 open CEs | 52 found, 0 dropped, 20/20 fetched |

## On-disk artifacts

| Path | Contents | Sensitivity |
| --- | --- | --- |
| `~/.azdo_cli_token.json` | Access + refresh token | High — profile ACL only, not DPAPI |
| `~/.azdo_ce_board_url` | Per-launch board URL incl. nonce | Medium — mode 0600 |
| `~/.azdo_ce_seen.json` | Comment IDs already notified | Low — numbers only |
| `~/.azdo_ce_board.log` | Startup and error messages | Low — no tokens, no comment text |
| `scripts/_ce_board_launch.cmd` | Org, project, port | None |

No work item text, attachment or upload is written to disk. Uploads stream
through memory straight to Azure DevOps.

## Residual risks

- Token file protected by profile ACLs only; anything running as the user, and
  any local administrator, can read it. The boundary is between user accounts,
  not between programs.
- Same applies to `~/.azdo_ce_board_url`.
- CSP still requires `script-src 'unsafe-inline'` because the UI is one inline
  bundle.
- Toast notifications place comment excerpts into Windows notification history,
  which is outside the tool's uninstall path. Disable with `CE_BOARD_POLL=0`.
- Upload, add-link and remove have not been exercised against a real work item.
- This review is internal due diligence, not certification. Formal sign-off
  needs a named owner and a vulnerability-handling process.
