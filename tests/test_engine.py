from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from easy_pc_cleaner import engine


class CleanupEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        # macOS commonly reports TemporaryDirectory below /var, whose normal
        # canonical location is /private/var.  Match the engine's trusted-root
        # canonicalization so the fixture does not introduce a linked ancestor.
        self.root = Path(self.temp.name).resolve() / "user-temp"
        self.root.mkdir()
        self.policy = engine.Policy(
            min_age_days=7,
            max_scan_files=100,
            max_scan_seconds=5,
            max_scan_bytes=100_000,
            max_delete_files=10,
            max_delete_bytes=100_000,
            dry_run=False,
        )
        self.roots = mock.patch.object(engine, "_automatic_roots", return_value=(("user-temp", self.root),))
        self.package_roots = mock.patch.object(engine, "_package_roots", return_value=())
        self.roots.start()
        self.package_roots.start()

    def tearDown(self) -> None:
        self.roots.stop()
        self.package_roots.stop()
        self.temp.cleanup()

    def old_file(self, name: str, content: bytes = b"old") -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        old = time.time() - 8 * 86_400
        os.utime(path, (old, old))
        return path

    def policy_with(self, **values) -> engine.Policy:
        return engine.Policy(**(self.policy.__dict__ | values))

    def test_dry_run_is_bounded_and_exposes_safe_display_aliases(self) -> None:
        first = self.old_file("one.tmp")
        self.old_file("two.temp")
        plan = engine.scan(self.policy_with(dry_run=True, max_delete_files=1))
        candidate = plan["candidates"][0]
        self.assertTrue(candidate["automaticEligible"])
        self.assertEqual(candidate["category"], "temporary-artifact")
        self.assertEqual(candidate["size"], candidate["metadata"]["size"])
        report = engine.clean(plan, [item["id"] for item in plan["candidates"]])
        self.assertTrue(report["dryRun"])
        self.assertEqual(len(report["wouldDelete"]), 1)
        self.assertIn("max_delete_files", report["rejected"])
        self.assertTrue(first.exists())

    def test_explicit_approval_and_unattended_cleanup_use_quarantine(self) -> None:
        approved = self.old_file("approval.tmp")
        plan = engine.scan(self.policy)
        self.assertTrue(engine.clean(plan)["skipped"])
        self.assertTrue(approved.exists())
        report = engine.clean(plan, unattended=True)
        self.assertEqual(report["summary"]["deletedFiles"], 1)
        self.assertEqual(report["summary"]["affectedBytes"], 3)
        self.assertFalse(approved.exists())
        self.assertFalse(any(path.name.startswith(".easy-pc-cleaner-quarantine-") for path in self.root.iterdir()))

    def test_changed_file_and_tampered_plan_do_not_delete(self) -> None:
        path = self.old_file("changed.tmp")
        plan = engine.scan(self.policy)
        path.write_bytes(b"changed")
        report = engine.clean(plan, [plan["candidates"][0]["id"]])
        self.assertTrue(path.exists())
        self.assertEqual(report["skipped"][0]["reason"], "metadata-changed")
        bad = dict(plan)
        bad["candidates"] = []
        self.assertIn("invalid-or-tampered-plan", engine.clean(bad)["rejected"])

    def test_swap_during_quarantine_is_restored_and_never_deleted(self) -> None:
        path = self.old_file("race.tmp")
        plan = engine.scan(self.policy)
        real_replace = os.replace
        swapped = False

        def replace_with_race(source, target):
            nonlocal swapped
            if Path(source) == path and not swapped:
                swapped = True
                path.write_bytes(b"replacement user data")
            return real_replace(source, target)

        with mock.patch.object(engine.os, "replace", side_effect=replace_with_race):
            report = engine.clean(plan, [plan["candidates"][0]["id"]])
        self.assertTrue(path.exists())
        self.assertEqual(path.read_bytes(), b"replacement user data")
        self.assertEqual(report["skipped"][0]["reason"], "metadata-race-restored")

    def test_only_clear_temp_artifacts_are_eligible(self) -> None:
        eligible = self.old_file("remove-me.tmp")
        for name in ("notes.bin", "draft.pdf.tmp", "config.tmp", "credentials.temp", "photo.jpg.temp", "source.py.tmp"):
            self.old_file(name)
        project = self.root / "project"
        project.mkdir()
        (project / "package.json").write_text("{}", encoding="utf-8")
        project_file = self.old_file("project/build.tmp")
        plan = engine.scan(self.policy)
        self.assertEqual([item["path"] for item in plan["candidates"]], [str(eligible)])
        self.assertTrue(project_file.exists())

    def test_project_marker_at_temp_root_disables_automatic_candidates(self) -> None:
        candidate = self.old_file("would-otherwise-clean.tmp")
        (self.root / ".git").mkdir()
        plan = engine.scan(self.policy)
        self.assertEqual(plan["candidates"], [])
        self.assertTrue(candidate.exists())

    def test_recent_access_hardlinks_and_links_are_not_candidates(self) -> None:
        active = self.old_file("active.tmp")
        old = time.time() - 8 * 86_400
        os.utime(active, (time.time(), old))
        source = self.old_file("hardlink.tmp")
        alias = self.root / "hardlink-copy.temp"
        try:
            os.link(source, alias)
        except OSError:
            alias = None
        outside = Path(self.temp.name) / "outside.tmp"
        outside.write_bytes(b"outside")
        linked = self.root / "linked.tmp"
        try:
            linked.symlink_to(outside)
        except (OSError, NotImplementedError):
            linked = None
        plan = engine.scan(self.policy)
        paths = {item["path"] for item in plan["candidates"]}
        self.assertNotIn(str(active), paths)
        self.assertNotIn(str(source), paths)
        if alias is not None:
            self.assertNotIn(str(alias), paths)
        if linked is not None:
            self.assertNotIn(str(linked), paths)

    def test_package_and_requested_roots_are_capabilities_not_traversed(self) -> None:
        package_root = Path(self.temp.name) / "npm-cache"
        package_root.mkdir()
        package_file = package_root / "old.tmp"
        package_file.write_bytes(b"package")
        requested = Path(self.temp.name) / "requested"
        requested.mkdir()
        requested_file = requested / "old.tmp"
        requested_file.write_bytes(b"requested")
        old = time.time() - 8 * 86_400
        os.utime(package_file, (old, old))
        os.utime(requested_file, (old, old))
        with mock.patch.object(engine, "_package_roots", return_value=(("npm-cache", package_root),)):
            plan = engine.scan(self.policy_with(requested_paths=(str(requested),)))
        self.assertFalse(any(item["path"] in (str(package_file), str(requested_file)) for item in plan["candidates"]))
        capabilities = {(item["label"], item["path"]): item for item in plan["capabilities"]}
        self.assertTrue(capabilities[("npm-cache", str(package_root))]["reportOnly"])
        self.assertTrue(capabilities[("requested-report-only", str(requested))]["useInventoryCommand"])

    def test_environment_redirected_temp_root_is_refused(self) -> None:
        self.roots.stop()
        redirected = Path(self.temp.name) / "Documents" / "project-temp"
        redirected.mkdir(parents=True)
        try:
            with mock.patch.object(engine.tempfile, "gettempdir", return_value=str(redirected)):
                self.assertEqual(engine._automatic_roots(), ())
        finally:
            self.roots.start()

    def test_scan_entry_limit_streams_and_reports_truncation(self) -> None:
        for index in range(20):
            self.old_file(f"{index:02d}.tmp")
        plan = engine.scan(self.policy_with(max_scan_files=5, dry_run=True))
        self.assertLessEqual(len(plan["candidates"]), 5)
        self.assertEqual(plan["summary"]["truncated"], "max_scan_files")
        self.assertTrue(plan["limits"]["truncated"])
        report = engine.clean(plan, [item["id"] for item in plan["candidates"]])
        self.assertEqual(report["truncated"], "max_scan_files")
        self.assertTrue(report["dryRun"])

    def test_explicit_protected_boundary_excludes_temp_fixture(self) -> None:
        self.old_file("protected.tmp")
        plan = engine.scan(self.policy_with(protected_paths=(str(self.root),)))
        self.assertEqual(plan["summary"]["candidateFiles"], 0)
        self.assertGreaterEqual(plan["summary"]["skipped"].get("protected-or-link-root", 0), 1)

    def test_policy_refuses_young_or_unbounded_cleanup(self) -> None:
        with self.assertRaises(ValueError):
            engine.scan(self.policy_with(min_age_days=1))
        with self.assertRaises(ValueError):
            engine.scan(self.policy_with(max_delete_files=engine.MAX_DELETE_FILES + 1))


if __name__ == "__main__":
    unittest.main()
