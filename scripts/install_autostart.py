"""Install the CE dashboard so it starts automatically and survives reboots.

  python install_autostart.py            # register + start now
  python install_autostart.py --status   # show whether it is registered
  python install_autostart.py --uninstall

Tries a Task Scheduler logon task first; corporate policy often blocks that, in
which case it falls back to a shortcut in the per-user Startup folder, which
needs no admin rights. Either way the dashboard runs under pythonw.exe (no
console window) and keeps serving http://127.0.0.1:<port>/ independently of
Copilot.
"""

import argparse
import os
import subprocess
import sys

TASK_NAME = "ADO CE Board"
HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "ce_server.py")
LAUNCHER = os.path.join(HERE, "_ce_board_launch.cmd")
STARTUP_DIR = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows",
                           "Start Menu", "Programs", "Startup")
STARTUP_CMD = os.path.join(STARTUP_DIR, "ado-ce-board.cmd")


def pythonw():
    """Prefer pythonw.exe so the task runs without a console window."""
    candidate = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return candidate if os.path.exists(candidate) else sys.executable


def run(args):
    return subprocess.run(args, capture_output=True, text=True)


def write_launcher(port, poll, org, project):
    with open(LAUNCHER, "w", encoding="utf-8") as handle:
        handle.write("@echo off\r\n")
        handle.write("set PYTHONIOENCODING=utf-8\r\n")
        handle.write("set AZDO_ORG={}\r\n".format(org))
        handle.write("set AZDO_PROJECT={}\r\n".format(project))
        # No /B: pythonw has no console anyway, and a /B child dies when the
        # launching cmd window closes at logon.
        handle.write('start "" "{}" "{}" --no-browser --port {} --poll {}\r\n'
                     .format(pythonw(), SERVER, port, poll))
    return LAUNCHER


def status():
    found = False
    result = run(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST"])
    if result.returncode == 0:
        print("Registered as a Task Scheduler logon task '{}'.".format(TASK_NAME))
        found = True
    if os.path.exists(STARTUP_CMD):
        print("Registered in the Startup folder: {}".format(STARTUP_CMD))
        found = True
    if not found:
        print("Not installed.")
        return 1
    return 0


def uninstall():
    removed = False
    if run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]).returncode == 0:
        print("Removed logon task '{}'.".format(TASK_NAME))
        removed = True
    if os.path.exists(STARTUP_CMD):
        os.remove(STARTUP_CMD)
        print("Removed {}".format(STARTUP_CMD))
        removed = True
    for folder in (os.path.join(os.path.expanduser("~"), "Desktop"),
                   os.path.join(os.environ.get("APPDATA", ""), "Microsoft",
                                "Windows", "Start Menu", "Programs")):
        link = os.path.join(folder, "CE Board.lnk")
        if os.path.exists(link):
            os.remove(link)
            print("Removed {}".format(link))
            removed = True
    if not removed:
        print("Nothing to remove.")
        return 1
    print("It will no longer start automatically. A server already running "
          "stays up until you sign out or reboot.")
    return 0


def make_shortcuts(port):
    """Desktop + Start Menu shortcuts so the board opens like any other app."""
    target = os.path.join(HERE, "open_board.py")
    icon = os.path.join(os.path.dirname(sys.executable), "python.exe")
    made = []
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    programs = os.path.join(os.environ.get("APPDATA", ""), "Microsoft",
                            "Windows", "Start Menu", "Programs")
    for folder in (desktop, programs):
        if not os.path.isdir(folder):
            continue
        link = os.path.join(folder, "CE Board.lnk")
        ps = (
            "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{link}');"
            "$s.TargetPath='{exe}';"
            "$s.Arguments='\"{target}\"';"
            "$s.WorkingDirectory='{cwd}';"
            "$s.IconLocation='{icon}';"
            "$s.Description='Azure DevOps Customer Escalation board';"
            "$s.Save()"
        ).format(link=link.replace("'", "''"), exe=pythonw().replace("'", "''"),
                 target=target.replace("'", "''"), cwd=HERE.replace("'", "''"),
                 icon=icon.replace("'", "''"))
        result = run(["powershell", "-NoProfile", "-NonInteractive",
                      "-Command", ps])
        if result.returncode == 0 and os.path.exists(link):
            made.append(link)
    return made


def install(port, poll, org, project):
    if not os.path.exists(SERVER):
        print("Cannot find {}".format(SERVER))
        return 1

    launcher = write_launcher(port, poll, org, project)

    # schtasks caps /TR at 261 chars, so point it at the launcher batch file.
    run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    task = run(["schtasks", "/Create", "/TN", TASK_NAME,
                "/TR", '"{}"'.format(launcher), "/SC", "ONLOGON",
                "/RL", "LIMITED", "/F"])
    if task.returncode == 0:
        method = "Task Scheduler logon task '{}'".format(TASK_NAME)
    else:
        # Locked-down corporate machines usually deny schtasks; the per-user
        # Startup folder achieves the same thing without any privileges.
        if not os.path.isdir(STARTUP_DIR):
            print("Task Scheduler denied and no Startup folder found:\n{}".format(
                (task.stderr or task.stdout).strip()))
            return 1
        with open(STARTUP_CMD, "w", encoding="utf-8") as handle:
            handle.write('@echo off\r\ncall "{}"\r\n'.format(launcher))
        method = "Startup folder shortcut ({})".format(STARTUP_CMD)

    print("Installed via {}.".format(method))
    for link in make_shortcuts(port):
        print("Shortcut: {}".format(link))
    print("Dashboard: http://127.0.0.1:{}/".format(port))
    print("Scope: {}/{}   comment poll: {}s".format(org, project, poll))
    print("It will start automatically every time you sign in to Windows.")
    print("Remove it with: python install_autostart.py --uninstall")

    subprocess.Popen(["cmd", "/c", launcher],
                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    print("Started now.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("CE_BOARD_PORT", "8787")))
    parser.add_argument("--poll", type=int,
                        default=int(os.environ.get("CE_BOARD_POLL", "180")))
    parser.add_argument("--org", default=os.environ.get("AZDO_ORG", "ni"))
    parser.add_argument("--project",
                        default=os.environ.get("AZDO_PROJECT", "DevCentral"))
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("Autostart installation is Windows-only.")
        return 1
    if args.status:
        return status()
    if args.uninstall:
        return uninstall()
    return install(args.port, args.poll, args.org, args.project)


if __name__ == "__main__":
    sys.exit(main())
