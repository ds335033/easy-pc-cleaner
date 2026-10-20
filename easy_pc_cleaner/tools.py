"""Package caches are maintained by their own tools, never generic deletion."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from .runtime import no_links

LABELS = {"npm-verify": "npm: verify and garbage collect", "npm-purge": "npm: clear downloaded package cache", "npx-purge": "npx: clear execution cache", "pip-purge": "pip: clear download / wheel cache", "uv-prune": "uv: prune unused cache entries"}


def cache_roots() -> dict[str, Path]:
    home = Path.home()
    if sys.platform == "win32":
        import ctypes
        buffer = ctypes.create_unicode_buffer(32768)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 0x1C, None, 0, buffer) != 0:
            raise ValueError("Windows could not resolve the actual Local AppData known folder.")
        base = Path(buffer.value)
        return {"npm": base / "npm-cache", "pip": base / "pip/Cache", "uv": base / "uv/cache"}
    import pwd
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    if sys.platform == "darwin":
        return {"npm": home / ".npm", "pip": home / "Library/Caches/pip", "uv": home / ".cache/uv"}
    base = home / ".cache"
    return {"npm": home / ".npm", "pip": base / "pip", "uv": base / "uv"}


def npm_command() -> list[str] | None:
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if not npm:
        return None
    if os.name != "nt":
        return [npm]
    node = shutil.which("node.exe")
    script = Path(npm).parent / "node_modules/npm/bin/npm-cli.js"
    if node and script.is_file() and no_links(script):
        return [node, str(script)]
    return None  # Never fall back to an interpolated cmd.exe command.


def command_for(tool: str) -> list[str] | None:
    roots = cache_roots()
    if tool not in LABELS:
        raise ValueError("Unknown package-cache task.")
    root = roots[tool.split("-")[0] if not tool.startswith("npx") else "npm"]
    # Cache location is fixed to the current user's documented default.
    # Refuse links, non-home locations, or home itself, even if env vars change.
    if root.absolute() == Path.home().absolute() or not root.absolute().is_relative_to(Path.home().absolute()) or not no_links(root):
        raise ValueError("Cache root is outside the safe current-user boundary or contains a link.")
    if tool.startswith(("npm-", "npx-")):
        cmd = npm_command()
        if not cmd:
            return None
        action = {"npm-verify": ["verify"], "npm-purge": ["clean", "--force"], "npx-purge": ["npx", "rm", "--force"]}[tool]
        return cmd + ["--cache", str(root), "--ignore-scripts", "--no-audit", "--no-fund", "cache"] + action
    executable = shutil.which("pip.exe" if os.name == "nt" else "pip") or shutil.which("pip3") if tool == "pip-purge" else shutil.which("uv.exe" if os.name == "nt" else "uv")
    if not executable:
        return None
    return [executable, "--cache-dir", str(root), "cache", "purge"] if tool == "pip-purge" else [executable, "cache", "prune", "--cache-dir", str(root)]


def capabilities() -> list[dict]:
    result = []
    for tool, label in LABELS.items():
        try:
            available = command_for(tool) is not None
        except ValueError:
            available = False
        result.append({"id": tool, "label": label, "available": available, "manualOnly": tool != "npm-verify"})
    return result


def run_task(tool: str) -> dict:
    cmd = command_for(tool)
    if cmd is None:
        return {"kind": "cache", "tool": tool, "status": "unavailable", "summary": "The package manager is unavailable; no cache task ran.", "reviewRequired": True}
    env = {key: value for key, value in os.environ.items() if key not in ("NODE_OPTIONS", "PYTHONPATH", "PYTHONSTARTUP")}
    try:
        # No shell, user-supplied arguments, package installation or downloads.
        result = subprocess.run(cmd, cwd=str(Path.home()), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, creationflags=0x08000000 if os.name == "nt" else 0)
        success = result.returncode == 0
        return {"kind": "cache", "tool": tool, "status": "complete" if success else "needs-review", "exitCode": result.returncode, "summary": LABELS[tool] + (" completed." if success else " did not complete; review the package manager before retrying."), "reviewRequired": not success, "bytesReclaimedVerified": False}
    except (OSError, subprocess.TimeoutExpired):
        return {"kind": "cache", "tool": tool, "status": "needs-review", "summary": "The cache task timed out or could not start. Review is required.", "reviewRequired": True, "bytesReclaimedVerified": False}
