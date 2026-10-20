"""Private local state, a cross-process lock, and bounded cleanup reports."""
from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def state_path() -> Path:
    override = os.environ.get("EASY_PC_CLEANER_STATE_DIR")
    if override:
        return Path(override).absolute()
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "EasyPcCleaner"
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/EasyPcCleaner"
    return Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "easy-pc-cleaner"


def no_links(path: Path) -> bool:
    path = path.absolute()
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            return False
    return True


class State:
    def __init__(self, path: Path | None = None):
        self.path = (path or state_path()).absolute()
        if not no_links(self.path):
            raise ValueError("The application state directory must not contain links or reparse points.")
        marker = self.path / ".easy-pc-cleaner-state"
        if self.path.exists() and not marker.is_file() and any(self.path.iterdir()):
            raise ValueError("Refusing to use a nonempty folder that is not owned by Easy PC Cleaner.")
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not no_links(marker):
            raise ValueError("Linked application ownership marker refused.")
        if not marker.exists():
            descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write("easy-pc-cleaner-state-v1\n")
        elif marker.read_text(encoding="utf-8") != "easy-pc-cleaner-state-v1\n":
            raise ValueError("Invalid application ownership marker.")
        if os.name != "nt":
            if self.path.stat().st_uid != os.getuid():
                raise ValueError("Application data must belong to the current user.")
            self.path.chmod(0o700)
        self.reports = self.path / "reports"
        self.reports.mkdir(exist_ok=True, mode=0o700)
        if not no_links(self.reports):
            raise ValueError("The report directory must not be a link.")

    def read(self, name: str, default=None):
        if Path(name).name != name:
            raise ValueError("Invalid application file.")
        path = self.path / name
        if not no_links(path):
            raise ValueError("Linked application files are refused.")
        try:
            if path.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("Application state exceeds the size limit.")
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return default

    def write(self, name: str, value):
        if Path(name).name != name or not no_links(self.path):
            raise ValueError("Invalid application file.")
        temp = self.path / (".write-" + uuid.uuid4().hex)
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, indent=2, ensure_ascii=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.path / name)
        finally:
            if temp.exists():
                temp.unlink()

    @contextlib.contextmanager
    def lock(self):
        path = self.path / "operation.lock"
        if not no_links(path):
            raise ValueError("Linked lock files are refused.")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        stream = os.fdopen(fd, "r+b")
        locked = False
        try:
            if os.name == "nt":
                import msvcrt
                if os.fstat(stream.fileno()).st_size == 0:
                    stream.write(b"0")
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
            yield
        except (BlockingIOError, OSError) as exc:
            if not locked:
                raise RuntimeError("Another cleanup is running. Nothing was changed.") from exc
            raise
        finally:
            if locked:
                if os.name == "nt":
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(stream, fcntl.LOCK_UN)
            stream.close()

    def report(self, report: dict) -> dict:
        value = {**report, "id": uuid.uuid4().hex, "createdAt": now(), "version": VERSION, "application": "easy-pc-cleaner"}
        self.write("last-report.json", value)
        filename = datetime.fromisoformat(value["createdAt"]).strftime("%Y%m%dT%H%M%SZ") + "-" + value["id"] + ".json"
        target = self.reports / filename
        if not no_links(self.reports):
            raise ValueError("Linked report directory refused.")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
        entries = sorted((x for x in self.reports.glob("*.json") if self.owned_report(x)), key=lambda x: x.name, reverse=True)
        for old in entries[200:]:
            if self.owned_report(old):
                old.unlink()
        return value

    def owned_report(self, path: Path) -> bool:
        if path.parent != self.reports or not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{32}\.json", path.name) or not no_links(path):
            return False
        try:
            if path.stat().st_size > 4 * 1024 * 1024:
                return False
            value = json.loads(path.read_text(encoding="utf-8"))
            expected = datetime.fromisoformat(value["createdAt"]).strftime("%Y%m%dT%H%M%SZ") + "-" + value["id"] + ".json"
            return value.get("application") == "easy-pc-cleaner" and expected == path.name
        except (OSError, ValueError, KeyError, TypeError):
            return False

    def history(self) -> list:
        results = []
        for path in sorted(self.reports.glob("*.json"), reverse=True)[:30]:
            if self.owned_report(path):
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                    results.append({key: value.get(key) for key in ("id", "createdAt", "kind", "summary", "deletedCount", "deletedBytes", "reviewRequired", "status")})
                except (ValueError, OSError):
                    continue
        return results


def notify(summary: str) -> bool:
    """Best-effort local desktop notification; the report is always retained."""
    import shutil
    import subprocess
    text = " ".join(summary.split())[:220]
    try:
        if sys.platform == "win32":
            script = "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Windows.Forms; $n=New-Object System.Windows.Forms.NotifyIcon; $n.Icon=[System.Drawing.SystemIcons]::Information; $n.Visible=$true; $n.ShowBalloonTip(4000,'Easy PC Cleaner',$env:EPC_NOTICE,[System.Windows.Forms.ToolTipIcon]::Info); Start-Sleep -Seconds 5; $n.Dispose()"
            subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script], env={**os.environ, "EPC_NOTICE": text}, creationflags=0x08000000, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sys.platform == "darwin":
            # Pass the text as an argument, never interpolate it into AppleScript.
            subprocess.Popen(["osascript", "-e", 'on run argv\ndisplay notification (item 1 of argv) with title "Easy PC Cleaner"\nend run', text], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif shutil.which("notify-send"):
            subprocess.Popen(["notify-send", "Easy PC Cleaner", text], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            return False
        return True
    except OSError:
        return False
