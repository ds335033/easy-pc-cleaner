"""Bounded, explicitly requested personal-file and code review. No deletion."""
from __future__ import annotations

import ast
import hashlib
import os
import stat
import time
from collections import defaultdict
from pathlib import Path

from .runtime import no_links

SKIP = {".git", ".ssh", ".gnupg", ".aws", ".azure", ".codex", ".cursor", "node_modules", ".venv", "venv", "__pycache__", "AppData", "Library"}
PROJECT_OUTPUT = {"node_modules", ".next", "dist", "build", "target", ".venv", "__pycache__"}
PRIVATE = {".env", "credentials", "cookies", "login data", "key4.db", "wallet.dat"}


def review(path: str, duplicates: bool = False, *, home: Path | None = None, max_files: int = 10000, max_seconds: float = 15, hash_budget: int = 256 * 1024 * 1024) -> dict:
    base = Path(path).expanduser().absolute()
    owner = (home or Path.home()).absolute()
    if not base.is_relative_to(owner) or base == owner or not base.is_dir() or not no_links(base):
        raise ValueError("Choose one existing folder inside your home, not your entire home, a drive or a linked folder.")
    if any(part.casefold() in {x.casefold() for x in SKIP} or part.startswith(".env") for part in base.relative_to(owner).parts):
        raise ValueError("Credential, application and dependency folders cannot be selected for personal-file review.")
    started = time.monotonic()
    files, outputs, hints = [], [], []
    queue, seen, truncated = [base], 0, False
    while queue:
        if seen >= max_files or time.monotonic() - started >= max_seconds:
            truncated = True
            break
        directory = queue.pop()
        if not no_links(directory):
            continue
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if seen >= max_files or time.monotonic() - started >= max_seconds:
                        truncated = True
                        break
                    seen += 1
                    item = Path(entry.path)
                    # Windows DirEntry.stat may report inode=0; Path.lstat and
                    # fstat use consistent identities for the later hash check.
                    info = item.lstat()
                    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if entry.name in PROJECT_OUTPUT:
                            outputs.append({"path": str(item), "reason": "Project/dependency output: review in the project, never automatically deleted."})
                        elif entry.name not in SKIP and not entry.name.startswith("."):
                            queue.append(item)
                        continue
                    if not stat.S_ISREG(info.st_mode) or entry.name.startswith(".") or entry.name.casefold() in PRIVATE or getattr(info, "st_nlink", 1) > 1:
                        continue
                    ext = item.suffix.casefold()
                    category = "document" if ext in {".pdf", ".docx", ".doc", ".xlsx", ".pptx"} else "image" if ext in {".jpg", ".jpeg", ".png", ".webp", ".heic", ".raw"} else "video" if ext in {".mp4", ".mov", ".mkv", ".avi", ".webm"} else "file"
                    files.append({"path": str(item), "size": info.st_size, "category": category, "mtimeNs": info.st_mtime_ns, "inode": info.st_ino})
                    if ext == ".py" and info.st_size < 256000 and len(hints) < 100 and no_links(item):
                        try:
                            tree = ast.parse(item.read_text(encoding="utf-8"))
                            used = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
                            for node in ast.walk(tree):
                                if isinstance(node, (ast.Import, ast.ImportFrom)) and not (isinstance(node, ast.ImportFrom) and node.module == "__future__"):
                                    for alias in node.names:
                                        name = alias.asname or alias.name.split(".")[0]
                                        if name != "*" and name not in used:
                                            hints.append({"path": str(item), "line": node.lineno, "name": name, "reason": "Possibly unused import; may be a public export or runtime side effect. Review only."})
                        except (OSError, UnicodeError, SyntaxError):
                            pass
        except OSError:
            continue
    groups, hashed_bytes, incomplete_hash = [], 0, False
    if duplicates:
        sizes = defaultdict(list)
        for item in files:
            if 0 < item["size"] <= 64 * 1024 * 1024:
                sizes[item["size"]].append(item)
        digests = defaultdict(list)
        for bucket in sizes.values():
            if len(bucket) < 2:
                continue
            for item in bucket:
                if hashed_bytes + item["size"] > hash_budget or time.monotonic() - started >= max_seconds:
                    incomplete_hash = True
                    break
                candidate = Path(item["path"])
                if not no_links(candidate):
                    continue
                try:
                    digest = hashlib.sha256()
                    with candidate.open("rb") as stream:
                        before = os.fstat(stream.fileno())
                        if before.st_size != item["size"] or before.st_mtime_ns != item["mtimeNs"] or before.st_ino != item["inode"]:
                            continue
                        while chunk := stream.read(128 * 1024):
                            digest.update(chunk)
                        after = os.fstat(stream.fileno())
                    hashed_bytes += item["size"]
                    if (before.st_size, before.st_mtime_ns, before.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ino):
                        digests[(item["size"], digest.hexdigest())].append(item["path"])
                except OSError:
                    continue
        groups = [{"size": size, "paths": paths, "sha256": digest, "action": "Review only; no file is selected for deletion."} for (size, digest), paths in digests.items() if len(paths) > 1][:100]
    return {"kind": "inventory", "root": str(base), "readOnly": True, "filesInspected": len(files), "largeFiles": sorted((x for x in files if x["size"] >= 100 * 1024 * 1024), key=lambda x: x["size"], reverse=True)[:100], "largestFiles": sorted(files, key=lambda x: x["size"], reverse=True)[:30], "duplicateGroups": groups, "projectOutputs": outputs[:100], "deadCodeHints": hints[:100], "truncated": truncated, "duplicateHashingIncomplete": incomplete_hash, "hashedBytes": hashed_bytes, "reviewRequired": True, "summary": f"Reviewed {len(files)} files; {len(groups)} duplicate groups. No personal files or code changed."}
