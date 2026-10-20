"""Verified current-user installation; bounded reads and atomic staging."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from . import scheduler, tools
from .runtime import State, VERSION, no_links, now

MAX_FILE = 64 * 1024 * 1024
MAX_BUNDLE = 256 * 1024 * 1024


def file_hash(path: Path) -> str:
    if not no_links(path) or not path.is_file() or path.stat().st_size > MAX_FILE:
        raise ValueError("Release file is linked, missing, or exceeds the size limit.")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        initial = os.fstat(stream.fileno())
        if initial.st_size > MAX_FILE:
            raise ValueError("Release file exceeds the size limit.")
        count = 0
        for block in iter(lambda: stream.read(256 * 1024), b""):
            count += len(block)
            if count > MAX_FILE or count > initial.st_size:
                raise ValueError("Release file grew while being verified.")
            digest.update(block)
        final = os.fstat(stream.fileno())
    if (initial.st_ino, initial.st_size, initial.st_mtime_ns) != (final.st_ino, final.st_size, final.st_mtime_ns) or not no_links(path):
        raise ValueError("A release file changed while it was checked.")
    return digest.hexdigest()


def install(state: State, enable_autopilot=False) -> dict:
    if not getattr(sys, "frozen", False) or sys.platform != "win32":
        raise RuntimeError("Use the Windows bundled release to install. Portable users can run the .pyz and enable their user scheduler.")
    source = Path(sys.executable).parent.absolute()
    manifest_path = source / "bundle-manifest.json"
    if not no_links(manifest_path) or not manifest_path.is_file() or manifest_path.stat().st_size > 1024 * 1024:
        raise ValueError("Release manifest is missing, linked or too large.")
    with manifest_path.open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("Release manifest exceeds the size limit.")
    manifest = json.loads(data)
    if not isinstance(manifest, dict):
        raise ValueError("Invalid release manifest.")
    entries = manifest.get("files", {})
    executable_name = Path(sys.executable).name
    if manifest.get("version") != VERSION or not isinstance(entries, dict) or not 1 <= len(entries) <= 1000 or executable_name not in entries:
        raise ValueError("Release manifest must cover this executable and match this version.")
    total = 0
    validated_sizes = {}
    for relative, expected in entries.items():
        if not isinstance(relative, str) or not isinstance(expected, str) or len(expected) != 64 or any(x not in "0123456789abcdef" for x in expected):
            raise ValueError("Invalid release entry.")
        normalized = PurePosixPath(relative)
        if normalized.is_absolute() or ".." in normalized.parts or "\\" in relative or ":" in relative or str(normalized) != relative or relative == "bundle-manifest.json":
            raise ValueError("Invalid release path.")
        path = source.joinpath(*normalized.parts)
        if file_hash(path) != expected:
            raise ValueError("A release file failed SHA-256 verification. Installation stopped.")
        total += path.stat().st_size
        validated_sizes[relative] = path.stat().st_size
        if total > MAX_BUNDLE:
            raise ValueError("The release exceeds the total size limit.")
    parent = tools.cache_roots()["npm"].parent / "Programs/EasyPcCleaner"
    target = parent / VERSION
    if not no_links(target):
        raise ValueError("Linked installation directory refused.")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.exists():
        raise ValueError("This version is already present. Preserve it; install a new release version instead of overwriting it.")
    else:
        staging = Path(tempfile.mkdtemp(prefix=".install-", dir=parent))
        for relative, expected in entries.items():
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with (source / relative).open("rb") as incoming, os.fdopen(descriptor, "wb") as outgoing:
                written = 0
                digest = hashlib.sha256()
                for block in iter(lambda: incoming.read(256 * 1024), b""):
                    written += len(block)
                    if written > validated_sizes[relative] or written > MAX_FILE:
                        raise ValueError("A release source grew during installation. Staging was preserved for review.")
                    outgoing.write(block)
                    digest.update(block)
                if written != validated_sizes[relative] or digest.hexdigest() != expected:
                    raise ValueError("A release source changed during installation. Staging was preserved for review.")
                outgoing.flush()
                os.fsync(outgoing.fileno())
            if file_hash(destination) != expected:
                raise ValueError("Staged file verification failed. The staging folder was preserved for review.")
        descriptor = os.open(staging / "bundle-manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2)
        if not no_links(parent) or not no_links(staging) or target.exists():
            raise ValueError("Installation location changed. Staging was preserved for review.")
        os.rename(staging, target)  # Windows refuses an existing destination.
    executable = target / executable_name
    state.write("installation.json", {"version": VERSION, "directory": str(target), "executable": str(executable), "verifiedFiles": len(entries), "verifiedAt": now()})
    script = "$s=New-Object -ComObject WScript.Shell; $d=$s.SpecialFolders.Item('Programs'); $l=$s.CreateShortcut((Join-Path $d 'Easy PC Cleaner.lnk')); $l.TargetPath=$env:EPC_EXE; $l.Arguments='dashboard'; $l.WorkingDirectory=$env:EPC_DIR; $l.Description='Safe cleanup and local reports'; $l.Save()"
    shortcut = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script], env={**os.environ, "EPC_EXE": str(executable), "EPC_DIR": str(target)}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, creationflags=0x08000000).returncode == 0
    result = {"status": "installed", "version": VERSION, "directory": str(target), "verifiedFiles": len(entries), "startMenuShortcut": shortcut, "autopilot": {"enabled": False}}
    if enable_autopilot:
        result["autopilot"] = scheduler.change(state, True, command=[str(executable)])
    return result
