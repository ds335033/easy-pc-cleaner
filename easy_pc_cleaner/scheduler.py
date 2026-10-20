"""Per-user native scheduling. Never requests admin, passwords or SYSTEM."""
from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from .runtime import State, no_links, now

TASK = "Easy PC Cleaner - 90 minute safe cleanup"
LABEL = "org.easy-agent.easy-pc-cleaner"


def launcher() -> list[str]:
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).absolute())]
    source = Path(sys.argv[0]).absolute()
    if source.suffix == ".pyz":
        return [sys.executable, str(source)]
    raise RuntimeError("Enable autopilot from an installed release or the portable .pyz, not a mutable source checkout.")


def atomic_user_file(target: Path, content: bytes):
    if not no_links(target):
        raise ValueError("Linked scheduler file refused.")
    temporary = target.parent / (".epc-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if not no_links(target.parent):
            raise ValueError("Scheduler directory changed.")
        os.replace(temporary, target)
    finally:
        if temporary.exists() and no_links(temporary):
            temporary.unlink()


def systemd_quote(value: str) -> str:
    if any(char in value for char in ("\n", "\r", "\0")):
        raise ValueError("Invalid scheduler argument.")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def definitions(command: list[str], platform: str | None = None) -> dict:
    platform = platform or sys.platform
    args = command + ["autopilot-run"]
    if any(any(char in arg for char in ("\n", "\r", "\0")) for arg in args):
        raise ValueError("Invalid scheduler command.")
    if platform == "win32":
        # /IT uses the logged-in user's existing token, never a saved password.
        return {"create": ["schtasks.exe", "/Create", "/TN", TASK, "/SC", "MINUTE", "/MO", "90", "/TR", subprocess.list2cmdline(args), "/RL", "LIMITED", "/IT", "/F"], "remove": ["schtasks.exe", "/Delete", "/TN", TASK, "/F"]}
    if platform == "darwin":
        return {"plist": {"Label": LABEL, "ProgramArguments": args, "StartInterval": 5400, "RunAtLoad": False, "ProcessType": "Background", "LowPriorityIO": True, "Nice": 10}}
    service = "[Unit]\nDescription=Easy PC Cleaner safe per-user cleanup\n[Service]\nType=oneshot\nNice=10\nExecStart=" + " ".join(systemd_quote(arg) for arg in args) + "\n"
    timer = "[Unit]\nDescription=Easy PC Cleaner every 90 minutes while logged in\n[Timer]\nOnStartupSec=90min\nOnUnitActiveSec=90min\nAccuracySec=1min\n[Install]\nWantedBy=timers.target\n"
    return {"service": service, "timer": timer}


def change(state: State, enabled: bool, *, command: list[str] | None = None) -> dict:
    config = state.read("settings.json", {})
    if not enabled:
        # Fail closed immediately, even if an OS task cannot be unregistered.
        config.update(autopilotEnabled=False, changedAt=now())
        state.write("settings.json", config)
    definition = definitions(command or launcher()) if enabled else definitions(["unused-disabled-launcher"])
    flags = {"timeout": 30, "check": True, "stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    try:
        if sys.platform == "win32":
            subprocess.run(definition["create" if enabled else "remove"], creationflags=0x08000000, **flags)
        elif sys.platform == "darwin":
            target = Path.home() / "Library/LaunchAgents" / (LABEL + ".plist")
            if not no_links(target):
                raise ValueError("Linked scheduler file refused.")
            target.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(target)], timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if enabled:
                atomic_user_file(target, plistlib.dumps(definition["plist"]))
                subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(target)], **flags)
            elif target.is_file():
                target.unlink()
        else:
            if not shutil.which("systemctl"):
                raise RuntimeError("A systemd user session is required; no scheduler was installed.")
            folder = Path.home() / ".config/systemd/user"
            if not no_links(folder):
                raise ValueError("Linked scheduler directory refused.")
            folder.mkdir(parents=True, exist_ok=True)
            if enabled:
                for suffix in ("service", "timer"):
                    target = folder / ("easy-pc-cleaner." + suffix)
                    if not no_links(target):
                        raise ValueError("Linked scheduler file refused.")
                    atomic_user_file(target, definition[suffix].encode("utf-8"))
                subprocess.run(["systemctl", "--user", "daemon-reload"], **flags)
                subprocess.run(["systemctl", "--user", "enable", "--now", "easy-pc-cleaner.timer"], **flags)
            else:
                subprocess.run(["systemctl", "--user", "disable", "--now", "easy-pc-cleaner.timer"], **flags)
        config.update(autopilotEnabled=enabled, intervalMinutes=90, changedAt=now(), schedulerPlatform=sys.platform)
        state.write("settings.json", config)
        return {"enabled": enabled, "intervalMinutes": 90, "status": "configured", "summary": "Autopilot runs while this user is logged in; sleeping or powered-off computers do not clean."}
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as exc:
        config.update(autopilotEnabled=False, changedAt=now())
        state.write("settings.json", config)
        raise RuntimeError("The native user scheduler could not be configured; autopilot remains off. " + type(exc).__name__) from exc


def open_trash() -> dict:
    if sys.platform == "win32":
        command = ["explorer.exe", "shell:RecycleBinFolder"]
    elif sys.platform == "darwin":
        command = ["open", str(Path.home() / ".Trash")]
    elif shutil.which("gio"):
        command = ["gio", "open", "trash:///"]
    else:
        raise RuntimeError("Open your desktop's Trash manually; no files were removed.")
    subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"status": "opened", "summary": "Opened the system Trash / Recycle Bin. Review and empty it there; the app did not delete its contents."}
