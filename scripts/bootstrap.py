"""Find a usable Python, provisioning a private portable copy if needed.

Colleagues should not have to install Python. This resolves, in order:

  1. a portable runtime already sitting in <tool>/runtime
  2. a system Python 3.7+ on PATH
  3. a fresh portable runtime downloaded from python.org into <tool>/runtime

The portable runtime is the official Windows "embeddable package": a plain zip,
no installer, no admin rights, no registry or PATH changes, removed by deleting
the folder.

Run directly to print the interpreter it resolved:  bootstrap.cmd
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

VERSION = "3.11.9"
# SHA-256 of the official python-3.11.9-embed-amd64.zip. Cross-checked against
# the MD5 published on python.org's 3.11.9 release page.
SHA256 = "009d6bf7e3b2ddca3d784fa09f90fe54336d5b60f0e0f305c37f400bf83cfd3b"
URL = ("https://www.python.org/ftp/python/{v}/python-{v}-embed-amd64.zip"
       .format(v=VERSION))

ROOT = os.path.dirname(os.path.abspath(__file__))
RUNTIME = os.path.join(os.path.dirname(ROOT), "runtime")


def _ok(exe):
    """A usable interpreter: exists and is new enough for this tool."""
    if not exe or not os.path.exists(exe):
        return False
    try:
        out = subprocess.run(
            [exe, "-c", "import sys;print(sys.version_info[:2])"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and out.stdout.strip().startswith("(3,")


def portable(windowed=False):
    """Path to the private runtime's interpreter, if it is installed."""
    exe = os.path.join(RUNTIME, "pythonw.exe" if windowed else "python.exe")
    return exe if os.path.exists(exe) else None


def system():
    """A system Python 3.7+ on PATH, if there is one."""
    for name in ("python", "python3", "py"):
        found = shutil.which(name)
        if not found:
            continue
        try:
            out = subprocess.run(
                [found, "-c", "import sys;sys.exit(0 if sys.version_info>=(3,7) else 1)"],
                capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode == 0:
            return found
    return None


def install_portable(progress=print):
    """Download and unpack the official embeddable package into <tool>/runtime."""
    progress("Downloading a private Python {} ({} MB, no admin rights needed)..."
             .format(VERSION, 11))
    tmp = tempfile.mkdtemp(prefix="ceboard-py-")
    archive = os.path.join(tmp, "python-embed.zip")
    try:
        with urllib.request.urlopen(URL, timeout=300) as resp, \
                open(archive, "wb") as handle:
            shutil.copyfileobj(resp, handle)
        # TLS alone is not enough where a corporate proxy terminates it: this
        # interpreter ends up holding the Azure DevOps token, so verify the
        # published digest before anything is unpacked or executed.
        digest = hashlib.sha256()
        with open(archive, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        actual = digest.hexdigest()
        if actual != SHA256:
            raise RuntimeError(
                "Downloaded runtime failed its integrity check.\n"
                "  expected {}\n  got      {}\n"
                "Refusing to run it. Use the offline package instead."
                .format(SHA256, actual))
        progress("Checksum verified.")
        progress("Unpacking...")
        if os.path.isdir(RUNTIME):
            shutil.rmtree(RUNTIME, ignore_errors=True)
        os.makedirs(RUNTIME, exist_ok=True)
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(RUNTIME)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    exe = portable()
    if not _ok(exe):
        raise RuntimeError("The downloaded runtime does not work.")
    progress("Python ready at {}".format(RUNTIME))
    return exe


def resolve(allow_download=True, progress=print):
    """Return a usable python.exe, provisioning one only as a last resort."""
    found = portable()
    if _ok(found):
        return found
    found = system()
    if found:
        return found
    if not allow_download:
        return None
    return install_portable(progress)


if __name__ == "__main__":
    try:
        exe = resolve()
    except Exception as exc:
        sys.stderr.write("Could not obtain Python: {}\n".format(exc))
        sys.exit(1)
    if not exe:
        sys.stderr.write("No Python found.\n")
        sys.exit(1)
    print(exe)
