import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from easy_pc_cleaner import install as installer
from easy_pc_cleaner.runtime import State, VERSION


class InstallerSafetyTests(unittest.TestCase):
    def test_hashing_refuses_oversize_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "synthetic.bin"
            path.write_bytes(b"12345")
            with mock.patch.object(installer, "MAX_FILE", 4):
                with self.assertRaises(ValueError):
                    installer.file_hash(path)

    def test_manifest_must_cover_the_running_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            source = home / "release"
            source.mkdir()
            exe = source / "easy-pc-cleaner.exe"
            exe.write_bytes(b"synthetic")
            (source / "bundle-manifest.json").write_text(json.dumps({"version": VERSION, "files": {"README.md": "a" * 64}}), encoding="utf-8")
            state = State(home / "state")
            with mock.patch.object(installer.sys, "frozen", True, create=True), mock.patch.object(installer.sys, "platform", "win32"), mock.patch.object(installer.sys, "executable", str(exe)):
                with self.assertRaisesRegex(ValueError, "must cover"):
                    installer.install(state)

    def test_existing_version_is_preserved_and_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            source = home / "release"
            source.mkdir()
            exe = source / "easy-pc-cleaner.exe"
            exe.write_bytes(b"synthetic")
            expected = hashlib.sha256(exe.read_bytes()).hexdigest()
            manifest = source / "bundle-manifest.json"
            manifest.write_text(json.dumps({"version": VERSION, "files": {exe.name: expected}}), encoding="utf-8")
            target = home / "Programs/EasyPcCleaner" / VERSION
            target.mkdir(parents=True)
            extra = target / "owner-changes.txt"
            extra.write_text("preserve", encoding="utf-8")
            state = State(home / "state")
            with mock.patch.object(installer.sys, "frozen", True, create=True), mock.patch.object(installer.sys, "platform", "win32"), mock.patch.object(installer.sys, "executable", str(exe)), mock.patch.object(installer.tools, "cache_roots", return_value={"npm": home / "npm-cache"}):
                with self.assertRaisesRegex(ValueError, "already present"):
                    installer.install(state)
                manifest.write_text(json.dumps({"version": VERSION, "files": {exe.name: expected, "../owner-data.pdf": expected}}), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Invalid release path"):
                    installer.install(state)
            self.assertEqual(extra.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
