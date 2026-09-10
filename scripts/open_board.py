"""Open the CE dashboard, starting the background server first if needed.

This is the single entry point for day-to-day use: double-click the desktop
shortcut and the board opens, whether or not the server was already running.
"""

import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "ce_server.py")
PORT = int(os.environ.get("CE_BOARD_PORT", "8787"))
PROBE = "http://127.0.0.1:{}/".format(PORT)
URL_FILE = os.path.join(os.path.expanduser("~"), ".azdo_ce_board_url")


def board_url():
    """The page lives at an unguessable path; the server publishes it here."""
    try:
        with open(URL_FILE, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def alive(timeout=2):
    try:
        with urllib.request.urlopen(PROBE, timeout=timeout) as resp:
            return resp.status == 200
    except urllib.error.HTTPError:
        # "/" deliberately answers 404 now - a reply at all means it is up.
        return True
    except (urllib.error.URLError, OSError):
        return False


def pythonw():
    candidate = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return candidate if os.path.exists(candidate) else sys.executable


def start_server():
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if sys.platform == "win32":
        # DETACHED_PROCESS so the board outlives the shell that launched it.
        flags |= 0x00000008
    subprocess.Popen(
        [pythonw(), SERVER, "--no-browser", "--port", str(PORT)],
        cwd=HERE, close_fds=True, creationflags=flags)


_CHROMIUM_NAMES = ("msedge.exe", "chrome.exe")


def _exe_path_for(name):
    """Full path for a browser exe name, via the registry App Paths key
    (authoritative, survives the Program Files / Program Files (x86) split)
    with a Program Files scan as a fallback."""
    try:
        import winreg
    except ImportError:
        winreg = None
    if winreg:
        for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                key = winreg.OpenKey(
                    root, r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                          r"\App Paths\{}".format(name))
                with key:
                    path = winreg.QueryValue(key, None)
            except OSError:
                continue
            if path and os.path.exists(path):
                return path
    tails = {"msedge.exe": r"Microsoft\Edge\Application\msedge.exe",
             "chrome.exe": r"Google\Chrome\Application\chrome.exe"}
    tail = tails.get(name)
    if tail:
        for base in (os.environ.get("ProgramFiles", ""),
                     os.environ.get("ProgramFiles(x86)", ""),
                     os.environ.get("LOCALAPPDATA", "")):
            candidate = os.path.join(base, tail) if base else ""
            if candidate and os.path.exists(candidate):
                return candidate
    return ""


def _running_exe_names():
    """Lower-cased image names of currently running processes, via the
    built-in tasklist.exe -- no extra dependency needed to see what the user
    already has open."""
    try:
        out = subprocess.check_output(
            ["tasklist", "/NH", "/FO", "CSV"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=5)
        text = out.decode("utf-8", "ignore")
    except Exception:
        return set()
    names = set()
    for line in text.splitlines():
        first = line.split(",", 1)[0].strip('"')
        if first:
            names.add(first.lower())
    return names


def _default_browser_exe():
    """Path to the user's Windows-configured default browser, if it is one
    of the Chromium engines we can host an app window in."""
    try:
        import winreg
    except ImportError:
        return ""
    try:
        with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\Shell\Associations"
                r"\UrlAssociations\http\UserChoice") as key:
            prog_id, _ = winreg.QueryValueEx(key, "ProgId")
    except OSError:
        return ""
    for name in _CHROMIUM_NAMES:
        if name.split(".")[0] in (prog_id or "").lower():
            return _exe_path_for(name)
    return ""


def browser_exe():
    """Path to whichever browser should host the board's own window.

    Preference order: a Chromium browser (Edge or Chrome) the user already
    has running beats one that merely happens to be installed -- clicking
    into the board should feel like it belongs with whatever the user is
    already using, not switch them to a browser they did not open. Falling
    back from there: their configured Windows default browser, then Edge,
    then Chrome, whichever is actually installed.
    """
    if sys.platform != "win32":
        return ""
    running = _running_exe_names()
    default_path = _default_browser_exe()
    default_name = os.path.basename(default_path).lower() if default_path else ""
    # The user's default browser, if it is already running, wins outright --
    # that is the one they are actually using right now, even if another
    # Chromium engine also happens to be open in the background.
    if default_name in running and default_path:
        return default_path
    for name in _CHROMIUM_NAMES:
        if name in running:
            path = _exe_path_for(name)
            if path:
                return path
    if default_path:
        return default_path
    for name in _CHROMIUM_NAMES:
        path = _exe_path_for(name)
        if path:
            return path
    return ""


def open_window(url):
    """Show the board as its own window: no address bar, no tabs, own icon.

    This is what makes it feel like an application without shipping one. A
    packaged .exe is not an option here -- endpoint protection kills a renamed
    copy of a signed interpreter -- so the board borrows a browser engine that
    is already installed and trusted, and hides the browser.
    """
    if os.environ.get("CE_BOARD_WINDOW", "1") == "0":
        return False
    exe = browser_exe()
    if not exe:
        return False
    try:
        subprocess.Popen(
            [exe, "--app={}".format(url), "--window-size=1360,900"],
            close_fds=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return True
    except OSError:
        return False


def main():
    if not alive():
        print("Starting the CE board...")
        start_server()
        for _ in range(30):
            time.sleep(1)
            if alive():
                break
        else:
            print("The board did not start. Check the log at "
                  "{}".format(os.path.join(os.path.expanduser("~"),
                                           ".azdo_ce_board.log")))
            return 1
    url = ""
    for _ in range(10):
        url = board_url()
        if url:
            break
        time.sleep(0.5)
    if not url:
        print("Could not read the board URL from {}".format(URL_FILE))
        return 1
    if open_window(url):
        print("CE board open at {}".format(url))
    else:
        webbrowser.open(url)
        print("CE board open at {} (in your browser)".format(url))
    return 0


if __name__ == "__main__":
    sys.exit(main())
