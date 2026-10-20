"""Bounded cleanup planning with fail-closed, file-by-file revalidation.

Unattended cleanup is intentionally narrow: only clearly disposable, stale
``.tmp`` and ``.temp`` files in a validated operating-system temporary root
are eligible. Package caches, personal files, projects, and requested paths
are inventory-only.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from typing import Any, Iterable, Mapping


MIB = 1024 * 1024
SCHEMA_VERSION = 1
MIN_AUTO_AGE_DAYS = 7
MAX_SCAN_FILES = 100_000
MAX_SCAN_SECONDS = 60.0
MAX_SCAN_BYTES = 2 * 1024 * MIB
MAX_DELETE_FILES = 2_000
MAX_DELETE_BYTES = 512 * MIB

SAFE_TEMP_SUFFIXES = frozenset({".tmp", ".temp"})
PROJECT_MARKERS = (
    ".git", ".hg", ".svn", "package.json", "pyproject.toml",
    "Cargo.toml", "go.mod", ".project", ".idea", ".vscode",
)
BLOCKED_DIRECTORY_NAMES = frozenset(
    name.casefold()
    for name in (
        ".git", ".hg", ".svn", ".ssh", ".gnupg", ".aws", ".azure",
        ".codex", ".cursor", ".idea", ".vscode", "node_modules",
        ".venv", "venv", "vendor", "src", "source", "documents",
        "desktop", "downloads", "pictures", "music", "videos",
    )
)
VALUABLE_SUFFIXES = frozenset(
    suffix.casefold()
    for suffix in (
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".odt", ".ods", ".jpg", ".jpeg", ".png", ".gif", ".webp",
        ".heic", ".raw", ".mp4", ".mov", ".mkv", ".avi", ".webm",
        ".zip", ".7z", ".rar", ".tar", ".gz", ".db", ".sqlite",
        ".pem", ".key", ".pfx", ".p12", ".json", ".yaml", ".yml",
        ".toml", ".ini", ".cfg", ".conf", ".xml", ".csv", ".md",
        ".txt", ".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".go",
        ".rs", ".java", ".kt", ".swift", ".c", ".h", ".cpp", ".hpp",
        ".cs", ".rb", ".php", ".sh", ".ps1", ".bat", ".cmd", ".sql",
    )
)
SENSITIVE_STEMS = frozenset(
    {"config", "configuration", "credentials", "credential", "secret", "secrets", "wallet", "backup", "recovery", "draft"}
)
METADATA_KEYS = ("device", "inode", "size", "mtimeNs", "atimeNs", "nlink", "uid")


@dataclass(frozen=True)
class Policy:
    min_age_days: int = MIN_AUTO_AGE_DAYS
    max_scan_files: int = 20_000
    max_scan_seconds: float = 20.0
    max_scan_bytes: int = 512 * MIB
    max_delete_files: int = MAX_DELETE_FILES
    max_delete_bytes: int = MAX_DELETE_BYTES
    dry_run: bool = True
    requested_paths: tuple[str, ...] = ()
    protected_paths: tuple[str, ...] = ()


def _path(value: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(value)))


def _home() -> Path:
    return _path(Path.home())


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.normpath(str(left))) == os.path.normcase(os.path.normpath(str(right)))


def _package_roots() -> tuple[tuple[str, Path], ...]:
    """Exact known package-cache roots; visible as inventory, never walked or deleted."""
    home = _home()
    roots: list[tuple[str, Path]] = [
        ("npm-cache", home / ".npm" / "_cacache"),
        ("npm-npx", home / ".npm" / "_npx"),
        ("pip-cache", home / ".cache" / "pip"),
        ("uv-cache", home / ".cache" / "uv"),
        ("uv-data-cache", home / ".local" / "share" / "uv" / "cache"),
    ]
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        roaming = os.environ.get("APPDATA")
        if local:
            roots.extend(
                [
                    ("npm-cache", _path(local) / "npm-cache"),
                    ("pip-cache", _path(local) / "pip" / "Cache"),
                    ("uv-cache", _path(local) / "uv" / "cache"),
                ]
            )
        if roaming:
            roots.append(("npm-cache", _path(roaming) / "npm-cache"))
    seen: set[tuple[str, str]] = set()
    result = []
    for label, path in roots:
        key = (label, os.path.normcase(str(path)))
        if key not in seen:
            seen.add(key)
            result.append((label, path))
    return tuple(result)


def _is_reparse_or_link(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    attrs = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _all_ancestors_plain(path: Path) -> bool:
    """Require the complete existing path, including parents above a root, to be link-free."""
    return all(not _is_reparse_or_link(part) for part in (path, *path.parents))


def _owned_by_current_user(info: os.stat_result) -> bool:
    if os.name == "nt" or not hasattr(os, "geteuid"):
        return True
    return int(getattr(info, "st_uid", -1)) == int(os.geteuid())


def _automatic_roots() -> tuple[tuple[str, Path], ...]:
    """Return a temp root only when it matches a platform-owned safe boundary."""
    raw = _path(tempfile.gettempdir())
    try:
        root = raw.resolve(strict=True)
        info = root.stat()
    except OSError:
        return ()
    if not stat.S_ISDIR(info.st_mode) or not _all_ancestors_plain(root):
        return ()

    if sys.platform == "win32":
        # Resolve the real Known Folder instead of trusting LOCALAPPDATA or a
        # conventional C:\Users layout, both of which may be redirected.
        try:
            import ctypes
            buffer = ctypes.create_unicode_buffer(32768)
            if ctypes.windll.shell32.SHGetFolderPathW(None, 0x1C, None, 0, buffer) != 0:
                return ()
            expected = (Path(buffer.value) / "Temp").resolve(strict=False)
        except (AttributeError, OSError, ValueError):
            return ()
        allowed = _same_path(root, expected)
    elif sys.platform == "darwin":
        private = _path("/private/var/folders")
        allowed = root.is_relative_to(private) and _owned_by_current_user(info)
    else:
        allowed_roots = tuple(_path(value).resolve(strict=False) for value in ("/tmp", "/var/tmp"))
        allowed = any(_same_path(root, value) for value in allowed_roots) and bool(info.st_mode & stat.S_ISVTX)
    return (("user-temp", root),) if allowed else ()


def _protected_roots(policy: Policy) -> tuple[Path, ...]:
    home = _home()
    protected = [
        home / "Documents", home / "Desktop", home / "Downloads", home / "Pictures", home / "Music", home / "Videos",
        home / ".ssh", home / ".aws", home / ".gnupg", home / ".config", home / ".gitconfig",
        _path(Path.cwd()), _path(Path(__file__).parents[1]), _path(sys.prefix),
    ]
    for key in ("OneDrive", "OneDriveConsumer"):
        if os.environ.get(key):
            base = _path(os.environ[key])
            protected.extend(base / name for name in ("Documents", "Desktop", "Pictures", "Music", "Videos"))
    for name in ("SystemRoot", "WINDIR", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        if os.environ.get(name):
            protected.append(_path(os.environ[name]))
    protected.extend(_path(item) for item in policy.protected_paths)
    return tuple(protected)


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _safe_ancestry(root: Path, candidate: Path) -> bool:
    """Reject links/reparse points above the root and from root through candidate."""
    if not _within(candidate, root) or not _all_ancestors_plain(root):
        return False
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return False
    current = root
    for part in relative.parts:
        current = current / part
        if _is_reparse_or_link(current):
            return False
    return True


def _is_protected(path: Path, protected: Iterable[Path]) -> bool:
    return any(_within(path, root) or path == root for root in protected)


def _metadata_from_stat(info: os.stat_result) -> dict[str, int] | None:
    if not stat.S_ISREG(info.st_mode) or int(getattr(info, "st_nlink", 1)) != 1 or not _owned_by_current_user(info):
        return None
    return {
        "device": int(info.st_dev), "inode": int(info.st_ino), "size": int(info.st_size),
        "mtimeNs": int(info.st_mtime_ns), "atimeNs": int(info.st_atime_ns),
        "nlink": int(getattr(info, "st_nlink", 1)), "uid": int(getattr(info, "st_uid", 0)),
    }


def _metadata(path: Path) -> dict[str, int] | None:
    try:
        return _metadata_from_stat(path.lstat())
    except OSError:
        return None


def _candidate_id(root_label: str, path: Path, metadata: Mapping[str, int]) -> str:
    body = "|".join([root_label, str(path), *(str(metadata[key]) for key in METADATA_KEYS)])
    return sha256(body.encode("utf-8")).hexdigest()[:24]


def _coerce_policy(value: Policy | Mapping[str, Any] | None) -> Policy:
    if value is None or isinstance(value, Policy):
        policy = value or Policy()
    else:
        if not isinstance(value, Mapping):
            raise TypeError("policy must be a Policy, mapping, or None")
        aliases = {
            "minAgeDays": "min_age_days", "maxScanFiles": "max_scan_files", "maxScanSeconds": "max_scan_seconds",
            "maxScanBytes": "max_scan_bytes", "maxDeleteFiles": "max_delete_files", "maxDeleteBytes": "max_delete_bytes",
            "dryRun": "dry_run", "requestedPaths": "requested_paths", "protectedPaths": "protected_paths",
        }
        fields = {aliases.get(str(key), str(key)): item for key, item in value.items()}
        unknown = set(fields) - set(Policy.__dataclass_fields__)
        if unknown:
            raise ValueError("unsupported policy fields: " + ", ".join(sorted(unknown)))
        for key in ("requested_paths", "protected_paths"):
            if key in fields:
                if isinstance(fields[key], (str, bytes)):
                    raise ValueError(key + " must be a path list")
                fields[key] = tuple(str(item) for item in fields[key])
        policy = Policy(**fields)

    integer_fields = (policy.min_age_days, policy.max_scan_files, policy.max_scan_bytes, policy.max_delete_files, policy.max_delete_bytes)
    if any(isinstance(item, bool) or not isinstance(item, int) for item in integer_fields):
        raise ValueError("policy file, byte and age limits must be integers")
    if isinstance(policy.max_scan_seconds, bool) or not isinstance(policy.max_scan_seconds, (int, float)):
        raise ValueError("max_scan_seconds must be numeric")
    if not isinstance(policy.dry_run, bool):
        raise ValueError("dry_run must be boolean")
    if not (
        MIN_AUTO_AGE_DAYS <= policy.min_age_days
        and 1 <= policy.max_scan_files <= MAX_SCAN_FILES
        and 0 < policy.max_scan_seconds <= MAX_SCAN_SECONDS
        and 0 <= policy.max_scan_bytes <= MAX_SCAN_BYTES
        and 1 <= policy.max_delete_files <= MAX_DELETE_FILES
        and 0 <= policy.max_delete_bytes <= MAX_DELETE_BYTES
    ):
        raise ValueError("policy exceeds the hard cleanup safety limits")
    if len(policy.requested_paths) > 64 or len(policy.protected_paths) > 64:
        raise ValueError("too many policy paths")
    if any(len(item) > 4096 for item in (*policy.requested_paths, *policy.protected_paths)):
        raise ValueError("policy path is too long")
    return policy


def _plan_digest(plan: Mapping[str, Any]) -> str:
    material = {key: value for key, value in plan.items() if key != "planDigest"}
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _contains_project_marker(directory: Path) -> bool:
    for marker in PROJECT_MARKERS:
        try:
            (directory / marker).lstat()
            return True
        except FileNotFoundError:
            continue
        except OSError:
            return True
    return False


def _blocked_context(root: Path, candidate: Path) -> bool:
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return True
    if _contains_project_marker(root):
        return True
    if any(part.casefold() in BLOCKED_DIRECTORY_NAMES or part.casefold().startswith(".easy-pc-cleaner-quarantine-") for part in relative.parts[:-1]):
        return True
    directory = candidate.parent
    while directory != root:
        if _contains_project_marker(directory):
            return True
        parent = directory.parent
        if parent == directory or not _within(parent, root):
            return True
        directory = parent
    return False


def _eligible_temp_file(root: Path, candidate: Path, metadata: Mapping[str, int], oldest_ns: int) -> bool:
    if metadata.get("nlink") != 1 or metadata.get("mtimeNs", 0) > oldest_ns or metadata.get("atimeNs", 0) > oldest_ns:
        return False
    suffixes = tuple(suffix.casefold() for suffix in candidate.suffixes)
    if not suffixes or suffixes[-1] not in SAFE_TEMP_SUFFIXES or any(suffix in VALUABLE_SUFFIXES for suffix in suffixes[:-1]):
        return False
    stem = candidate.name[: -len(suffixes[-1])].rstrip(". ").casefold()
    if stem in SENSITIVE_STEMS or stem.startswith(".env") or any(word in stem for word in ("credential", "password", "secret", "recovery")):
        return False
    return not _blocked_context(root, candidate)


def _inventory_capability(label: str, path: Path) -> dict[str, Any]:
    exists = False
    safe = False
    try:
        exists = path.is_dir()
        safe = exists and _all_ancestors_plain(path.resolve(strict=True))
    except OSError:
        pass
    return {"label": label, "path": str(path), "automatic": False, "exists": exists, "reportOnly": True, "safeToInspect": safe}


def scan(policy: Policy | Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return a bounded cleanup plan; only validated temp artifacts become candidates."""
    policy = _coerce_policy(policy)
    started = time.monotonic()
    oldest_ns = time.time_ns() - policy.min_age_days * 86_400 * 1_000_000_000
    protected = _protected_roots(policy)
    automatic_roots = _automatic_roots()
    capabilities = [_inventory_capability(label, path) for label, path in _package_roots()]
    for raw in policy.requested_paths:
        path = _path(raw)
        capability = _inventory_capability("requested-report-only", path)
        capability["useInventoryCommand"] = True
        capabilities.append(capability)
    for label, root in automatic_roots:
        capabilities.append({"label": label, "path": str(root), "automatic": True, "exists": root.is_dir(), "reportOnly": False, "safeToInspect": True})

    candidates: list[dict[str, Any]] = []
    skipped: dict[str, int] = {}
    examined = 0
    scanned_bytes = 0
    truncated: str | None = None

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    for label, root in automatic_roots:
        if _is_protected(root, protected) or not root.is_dir() or not _all_ancestors_plain(root):
            skip("protected-or-link-root")
            continue
        stack = [root]
        while stack and not truncated:
            if time.monotonic() - started > policy.max_scan_seconds:
                truncated = "max_scan_seconds"
                break
            directory = stack.pop()
            if directory != root:
                try:
                    directory_info = directory.lstat()
                except OSError:
                    skip("unreadable-directory")
                    continue
                if (
                    not stat.S_ISDIR(directory_info.st_mode)
                    or not _owned_by_current_user(directory_info)
                    or not _safe_ancestry(root, directory)
                    or _is_protected(directory, protected)
                    or directory.name.casefold() in BLOCKED_DIRECTORY_NAMES
                    or directory.name.casefold().startswith(".easy-pc-cleaner-quarantine-")
                    or _contains_project_marker(directory)
                ):
                    skip("unsafe-directory")
                    continue
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if examined >= policy.max_scan_files:
                            truncated = "max_scan_files"
                            break
                        if time.monotonic() - started > policy.max_scan_seconds:
                            truncated = "max_scan_seconds"
                            break
                        examined += 1
                        candidate = _path(entry.path)
                        try:
                            info = entry.stat(follow_symlinks=False)
                        except OSError:
                            skip("unreadable-entry")
                            continue
                        attrs = getattr(info, "st_file_attributes", 0)
                        if stat.S_ISLNK(info.st_mode) or bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                            skip("link-or-reparse")
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            stack.append(candidate)
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            skip("not-regular-file")
                            continue
                        if not _safe_ancestry(root, candidate) or _is_protected(candidate, protected):
                            skip("unsafe-file")
                            continue
                        # Windows DirEntry.stat may report zero device/inode/link
                        # fields; lstat the full path before trusting identity.
                        metadata = _metadata(candidate)
                        if metadata is None:
                            skip("not-owned-or-hardlinked")
                            continue
                        if scanned_bytes + metadata["size"] > policy.max_scan_bytes:
                            truncated = "max_scan_bytes"
                            break
                        scanned_bytes += metadata["size"]
                        if not _eligible_temp_file(root, candidate, metadata, oldest_ns):
                            skip("not-clearly-disposable-or-active")
                            continue
                        candidates.append(
                            {
                                "id": _candidate_id(label, candidate, metadata), "path": str(candidate),
                                "rootLabel": label, "rootPath": str(root), "automatic": True,
                                "automaticEligible": True, "size": metadata["size"],
                                "category": "temporary-artifact", "metadata": metadata,
                            }
                        )
            except OSError:
                skip("unreadable-directory")

    plan: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION, "createdAt": int(time.time()), "policy": asdict(policy),
        "capabilities": capabilities, "candidates": candidates,
        "limits": {"truncated": bool(truncated), "reason": truncated},
        "summary": {
            "candidateFiles": len(candidates), "candidateBytes": sum(item["size"] for item in candidates),
            "examinedFiles": examined, "scannedBytes": scanned_bytes, "skipped": skipped, "truncated": truncated,
        },
    }
    plan["planDigest"] = _plan_digest(plan)
    return plan


def _restore_quarantined(source: Path, original: Path, root: Path) -> bool:
    try:
        if os.path.lexists(original) or not _safe_ancestry(root, original.parent):
            return False
        os.replace(source, original)
        return True
    except OSError:
        return False


def _quarantine_remove(candidate: Path, expected: Mapping[str, int], root: Path, quarantine: Path) -> tuple[bool, str, str | None]:
    """Atomically isolate, revalidate, then remove a file from a private directory."""
    lock_stream = None
    fcntl_module = None
    try:
        if os.name != "nt":
            try:
                import fcntl as fcntl_module  # type: ignore[import-not-found]
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                lock_stream = os.fdopen(os.open(candidate, flags), "rb")
                if _metadata_from_stat(os.fstat(lock_stream.fileno())) != expected:
                    return False, "metadata-changed", None
                fcntl_module.flock(lock_stream.fileno(), fcntl_module.LOCK_EX | fcntl_module.LOCK_NB)
            except (BlockingIOError, OSError):
                if lock_stream is not None:
                    lock_stream.close()
                    lock_stream = None
                return False, "locked-or-unreadable", None
        current = _metadata(candidate)
        if current != expected or not _safe_ancestry(root, candidate):
            return False, "metadata-changed", None
        target = quarantine / (_candidate_id("quarantine", candidate, expected) + ".tmp")
        try:
            os.replace(candidate, target)
        except OSError:
            return False, "locked-or-delete-failed", None
        moved = _metadata(target)
        if moved != expected:
            if _restore_quarantined(target, candidate, root):
                return False, "metadata-race-restored", None
            return False, "metadata-race-quarantined", str(target)
        try:
            target.unlink()
            return True, "deleted", None
        except OSError:
            return False, "quarantined-delete-failed", str(target)
    finally:
        if lock_stream is not None:
            if fcntl_module is not None:
                try:
                    fcntl_module.flock(lock_stream.fileno(), fcntl_module.LOCK_UN)
                except OSError:
                    pass
            lock_stream.close()


def clean(plan: Mapping[str, Any], approved_ids: Iterable[str] | None = None, unattended: bool = False) -> dict[str, Any]:
    """Clean a valid plan while independently rederiving every deletion boundary."""
    try:
        digest_valid = isinstance(plan, Mapping) and plan.get("schemaVersion") == SCHEMA_VERSION and plan.get("planDigest") == _plan_digest(plan)
    except (KeyError, TypeError, ValueError):
        digest_valid = False
    if not digest_valid:
        return {"deleted": [], "wouldDelete": [], "skipped": [], "rejected": ["invalid-or-tampered-plan"], "dryRun": True}
    try:
        policy = _coerce_policy(plan.get("policy"))
    except (TypeError, ValueError):
        return {"deleted": [], "wouldDelete": [], "skipped": [], "rejected": ["invalid-policy"], "dryRun": True}
    candidates = plan.get("candidates")
    if not isinstance(candidates, list) or len(candidates) > policy.max_scan_files:
        return {"deleted": [], "wouldDelete": [], "skipped": [], "rejected": ["invalid-candidates"], "dryRun": True}
    plan_summary = plan.get("summary")
    scan_truncated = plan_summary.get("truncated") if isinstance(plan_summary, Mapping) else None

    approved = set(approved_ids or ())
    trusted = {(label, str(path)): path for label, path in _automatic_roots()}
    protected = _protected_roots(policy)
    oldest_ns = time.time_ns() - policy.min_age_days * 86_400 * 1_000_000_000
    deleted: list[str] = []
    would_delete: list[str] = []
    skipped: list[dict[str, str]] = []
    rejected: list[str] = []
    bytes_used = 0
    quarantines: dict[str, Path] = {}

    try:
        for item in candidates:
            if len(deleted) + len(would_delete) >= policy.max_delete_files:
                rejected.append("max_delete_files")
                break
            if not isinstance(item, Mapping):
                skipped.append({"id": "", "reason": "invalid-candidate"})
                continue
            identifier = item.get("id")
            if not isinstance(identifier, str) or (not unattended and identifier not in approved):
                skipped.append({"id": identifier if isinstance(identifier, str) else "", "reason": "approval-required"})
                continue
            root = trusted.get((item.get("rootLabel"), item.get("rootPath")))
            try:
                candidate = _path(str(item.get("path")))
            except (TypeError, ValueError):
                skipped.append({"id": identifier, "reason": "invalid-path"})
                continue
            metadata = item.get("metadata")
            if (
                root is None or item.get("rootLabel") != "user-temp" or item.get("automatic") is not True
                or item.get("automaticEligible") is not True or not isinstance(metadata, Mapping)
            ):
                skipped.append({"id": identifier, "reason": "untrusted-root"})
                continue
            expected = {key: metadata.get(key) for key in METADATA_KEYS}
            if any(isinstance(value, bool) or not isinstance(value, int) for value in expected.values()):
                skipped.append({"id": identifier, "reason": "invalid-metadata"})
                continue
            try:
                identity_matches = _candidate_id(str(item.get("rootLabel")), candidate, expected) == identifier
            except (KeyError, TypeError, ValueError):
                identity_matches = False
            if not identity_matches or not _safe_ancestry(root, candidate) or _is_protected(candidate, protected):
                skipped.append({"id": identifier, "reason": "path-or-identity-mismatch"})
                continue
            current = _metadata(candidate)
            if current != expected:
                skipped.append({"id": identifier, "reason": "metadata-changed"})
                continue
            if not _eligible_temp_file(root, candidate, current, oldest_ns):
                skipped.append({"id": identifier, "reason": "no-longer-eligible"})
                continue
            if bytes_used + current["size"] > policy.max_delete_bytes:
                rejected.append("max_delete_bytes")
                break
            if policy.dry_run:
                would_delete.append(str(candidate))
                bytes_used += current["size"]
                continue

            root_key = str(root)
            quarantine = quarantines.get(root_key)
            if quarantine is None:
                try:
                    quarantine = _path(tempfile.mkdtemp(prefix=".easy-pc-cleaner-quarantine-", dir=str(root)))
                    if os.name != "nt":
                        os.chmod(quarantine, 0o700)
                    if not _safe_ancestry(root, quarantine):
                        quarantine.rmdir()
                        raise OSError("unsafe quarantine")
                    quarantines[root_key] = quarantine
                except OSError:
                    skipped.append({"id": identifier, "reason": "quarantine-unavailable"})
                    continue
            success, reason, recovery_path = _quarantine_remove(candidate, expected, root, quarantine)
            if not success:
                entry = {"id": identifier, "reason": reason}
                if recovery_path:
                    entry["recoveryPath"] = recovery_path
                skipped.append(entry)
                continue
            deleted.append(str(candidate))
            bytes_used += current["size"]
    finally:
        for quarantine in quarantines.values():
            try:
                quarantine.rmdir()
            except OSError:
                pass

    return {
        "deleted": deleted, "wouldDelete": would_delete, "skipped": skipped, "rejected": rejected,
        "dryRun": policy.dry_run, "truncated": scan_truncated,
        "summary": {"deletedFiles": len(deleted), "plannedFiles": len(would_delete), "affectedBytes": bytes_used},
    }
