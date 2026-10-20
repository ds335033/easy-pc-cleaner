"""Explicit-allowlist portable build; never packages state, reports or secrets."""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"


def main():
    DIST.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="epc-build-") as temporary:
        staging = Path(temporary)
        package = staging / "easy_pc_cleaner"
        package.mkdir()
        for path in sorted((ROOT / "easy_pc_cleaner").glob("*.py")):
            shutil.copyfile(path, package / path.name)
        web = package / "web"
        web.mkdir()
        for name in ("index.html", "style.css", "app.js"):
            shutil.copyfile(ROOT / "easy_pc_cleaner/web" / name, web / name)
        (staging / "__main__.py").write_text("from easy_pc_cleaner.__main__ import main\nraise SystemExit(main())\n", encoding="utf-8")
        zipapp.create_archive(staging, DIST / "easy-pc-cleaner.pyz", interpreter="/usr/bin/env python3", compressed=True)
    print("Built dist/easy-pc-cleaner.pyz; runtime dependencies: Python 3.10+ only.")


def manifest(bundle: Path):
    from easy_pc_cleaner.runtime import VERSION
    files = {str(path.relative_to(bundle)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(bundle.rglob("*")) if path.is_file() and path.name != "bundle-manifest.json"}
    (bundle / "bundle-manifest.json").write_text(json.dumps({"version": VERSION, "files": files}, indent=2) + "\n", encoding="utf-8")
    return files


if __name__ == "__main__":
    main()
