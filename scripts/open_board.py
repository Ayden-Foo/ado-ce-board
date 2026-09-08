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


def browser_exe():
    """Path to Edge or Chrome, which can host the board in its own window.

    The registry App Paths key is authoritative and survives the usual
    Program Files / Program Files (x86) split, so it is tried first.
    """
    if sys.platform != "win32":
        return ""
    names = ("msedge.exe", "chrome.exe")
    try:
        import winreg
    except ImportError:
        winreg = None
    if winreg:
        for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for name in names:
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
    for base in (os.environ.get("ProgramFiles", ""),
                 os.environ.get("ProgramFiles(x86)", ""),
                 os.environ.get("LOCALAPPDATA", "")):
        for tail in (r"Microsoft\Edge\Application\msedge.exe",
                     r"Google\Chrome\Application\chrome.exe"):
            candidate = os.path.join(base, tail)
            if base and os.path.exists(candidate):
                return candidate
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
