"""Create the scoped Windows release bundle after the portable zipapp exists.

The script deliberately only replaces the generated ``dist/easy-pc-cleaner``
bundle and its sibling release ZIP. It never accepts output paths from the
environment or command line, so a build cannot recursively remove an arbitrary
directory.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
BUNDLE_NAME = "easy-pc-cleaner"
ARCHIVE_NAME = "easy-pc-cleaner-windows-x64.zip"
PORTABLE_NAME = "easy-pc-cleaner.pyz"


def _within(child: Path, parent: Path) -> bool:
    try:
        child.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def _generated_path(name: str) -> Path:
    """Return one exact generated child of dist, rejecting path tricks."""
    if Path(name).name != name:
        raise ValueError("Generated output names must be plain filenames.")
    result = DIST / name
    if result.parent.resolve(strict=False) != DIST.resolve(strict=False) or not _within(result, DIST):
        raise ValueError("Refusing an output path outside this project's dist directory.")
    return result


def _remove_generated_directory(path: Path) -> None:
    """Remove only the known generated bundle, never links or arbitrary paths."""
    expected = _generated_path(BUNDLE_NAME)
    if path != expected:
        raise ValueError("Refusing to remove an unexpected directory.")
    if not path.exists():
        return
    if path.is_symlink() or not path.is_dir():
        raise ValueError("Existing bundle is not a normal generated directory.")
    shutil.rmtree(path)


def _copy_release_document(source: Path, bundle: Path, destination: str | None = None) -> None:
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"Required release document is unavailable: {source.name}")
    target = bundle / (destination or source.name)
    if not _within(target, bundle):
        raise ValueError("Release document target escaped the bundle.")
    shutil.copy2(source, target)


def _reject_links(root: Path) -> None:
    """Release bundles are self-contained; never follow a build-output link."""
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("Release bundle must not contain links.")


def _python_runtime_license(bundle: Path) -> None:
    """Include Python's license whenever the PyInstaller bundle includes its DLL."""
    embeds_python = any(path.is_file() and path.name.casefold().startswith("python") and path.suffix.casefold() == ".dll" for path in bundle.rglob("*"))
    if not embeds_python:
        return
    candidates = (Path(sys.base_prefix) / "LICENSE.txt", Path(sys.base_prefix) / "LICENSE")
    source = next((path for path in candidates if path.is_file() and not path.is_symlink()), None)
    if source is None:
        raise RuntimeError("PyInstaller bundled Python but its runtime license was not found.")
    _copy_release_document(source, bundle, "LICENSE.python.txt")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_release_checksums(portable: Path, archive: Path) -> Path:
    target = _generated_path("SHA256SUMS")
    if target.exists() and target.is_symlink():
        raise ValueError("Refusing to replace a linked checksum file.")
    lines = [f"{_sha256(path)} *{path.name}" for path in (portable, archive)]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return target


def _zip_bundle(bundle: Path, archive: Path) -> None:
    if archive.exists() and archive.is_symlink():
        raise ValueError("Refusing to replace a linked release archive.")
    temporary = archive.with_name(archive.name + ".new")
    if temporary.exists():
        if temporary.is_symlink() or not temporary.is_file():
            raise ValueError("Temporary release archive is unsafe.")
        temporary.unlink()
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for path in sorted(bundle.rglob("*")):
            if path.is_symlink():
                raise ValueError("Release bundle must not contain links.")
            if path.is_file():
                output.write(path, path.relative_to(DIST).as_posix())
    temporary.replace(archive)


def main() -> None:
    if not (ROOT / "launch.py").is_file() or not (ROOT / "build.py").is_file():
        raise RuntimeError("Run this script from a complete easy-pc-cleaner source checkout.")
    DIST.mkdir(exist_ok=True)
    portable = _generated_path(PORTABLE_NAME)
    if not portable.is_file() or portable.is_symlink():
        raise RuntimeError("Build dist/easy-pc-cleaner.pyz before creating the Windows bundle.")
    build_root = ROOT / "build"
    build_root.mkdir(exist_ok=True)
    if build_root.is_symlink() or not build_root.is_dir() or not _within(build_root, ROOT):
        raise RuntimeError("The project build directory must be a normal directory.")

    with tempfile.TemporaryDirectory(prefix="windows-bundle-", dir=build_root) as temporary:
        workspace = Path(temporary)
        staged_dist = workspace / "dist"
        command = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--onedir",
            "--noupx",
            "--console",
            "--hide-console",
            "minimize-early",
            "--name",
            BUNDLE_NAME,
            "--collect-data",
            "easy_pc_cleaner",
            "--paths",
            ".",
            "--distpath",
            str(staged_dist),
            "--workpath",
            str(workspace / "work"),
            "--specpath",
            str(workspace / "spec"),
            str(ROOT / "launch.py"),
        ]
        subprocess.run(command, cwd=ROOT, check=True)
        staged_bundle = staged_dist / BUNDLE_NAME
        if not staged_bundle.is_dir() or staged_bundle.is_symlink() or not _within(staged_bundle, staged_dist):
            raise RuntimeError("PyInstaller did not produce the expected scoped bundle.")
        _reject_links(staged_bundle)
        bundle = _generated_path(BUNDLE_NAME)
        _remove_generated_directory(bundle)
        shutil.copytree(staged_bundle, bundle, symlinks=False)

    for document in (ROOT / "README.md", ROOT / "LICENSE", ROOT / "SECURITY.md"):
        _copy_release_document(document, bundle)
    _python_runtime_license(bundle)
    distribution = importlib.metadata.distribution("pyinstaller")
    license_entry = next((entry for entry in distribution.files or [] if str(entry).endswith("licenses/COPYING.txt")), None)
    if license_entry is None:
        raise RuntimeError("The required PyInstaller license and bootloader exception were not found.")
    _copy_release_document(Path(distribution.locate_file(license_entry)), bundle, "LICENSE.pyinstaller.txt")

    # The portable build owns the canonical manifest format. Generate it only
    # after every executable, data file and required release document exists.
    sys.path.insert(0, str(ROOT))
    import build as portable_build

    portable_build.manifest(bundle)
    archive = _generated_path(ARCHIVE_NAME)
    _zip_bundle(bundle, archive)
    checksums = _write_release_checksums(portable, archive)
    print(f"Built {archive.relative_to(ROOT)} and {checksums.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
