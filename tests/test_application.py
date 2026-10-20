from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from easy_pc_cleaner.app import Dashboard
from easy_pc_cleaner.runtime import State
from easy_pc_cleaner import inventory, scheduler, service, tools


class StateTests(unittest.TestCase):
    def test_private_state_refuses_unrelated_folders(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / "personal.json").write_text("important", encoding="utf-8")
            with self.assertRaises(ValueError):
                State(path)
            self.assertEqual((path / "personal.json").read_text(), "important")

    def test_report_cannot_override_generated_path_and_unrelated_reports_survive(self):
        with tempfile.TemporaryDirectory() as temp:
            state = State(Path(temp) / "state")
            unrelated = state.reports / ("private-" + "a" * 32 + ".json")
            unrelated.write_text('{"keep":true}', encoding="utf-8")
            result = state.report({"id": "../../escape", "createdAt": "../../bad", "version": "bad", "summary": "Synthetic test"})
            self.assertEqual(len(result["id"]), 32)
            self.assertNotEqual(result["version"], "bad")
            self.assertEqual(len(state.history()), 1)
            self.assertTrue(unrelated.is_file())
            self.assertEqual(list(Path(temp).glob("escape*")), [])

    def test_summary_reports_verified_bytes_and_no_dry_run_reclamation(self):
        result = service.summarize({"deleted": ["synthetic.tmp"], "summary": {"affectedBytes": 12}, "dryRun": False})
        self.assertEqual(result["deletedBytes"], 12)
        preview = service.summarize({"deleted": [], "wouldDelete": ["synthetic.tmp"], "summary": {"affectedBytes": 12}, "dryRun": True})
        self.assertEqual(preview["deletedBytes"], 0)
        self.assertIn("nothing was deleted", preview["summary"])

    def test_disabled_and_not_due_autopilot_never_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            state = State(Path(temp) / "state")
            with mock.patch.object(service.engine, "scan") as scan:
                self.assertEqual(service.autopilot_run(state, notices=False)["status"], "disabled")
                state.write("settings.json", {"autopilotEnabled": True, "lastAutopilotEpoch": __import__("time").time()})
                self.assertEqual(service.autopilot_run(state, notices=False)["status"], "not-due")
                scan.assert_not_called()


class InventoryTests(unittest.TestCase):
    def test_requested_duplicates_are_read_only_and_credentials_are_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            folder = home / "Documents"
            folder.mkdir()
            (folder / "first.pdf").write_bytes(b"same synthetic contents")
            (folder / "second.pdf").write_bytes(b"same synthetic contents")
            (folder / ".env").write_text("DO_NOT_READ=synthetic", encoding="utf-8")
            (folder / "example.py").write_text("import math\nprint('example')\n", encoding="utf-8")
            report = inventory.review(str(folder), True, home=home)
            self.assertTrue(report["readOnly"])
            self.assertEqual(len(report["duplicateGroups"]), 1)
            self.assertEqual(report["deadCodeHints"][0]["name"], "math")
            self.assertEqual(len(list(folder.iterdir())), 4)
            self.assertNotIn(".env", json.dumps(report))
            with self.assertRaises(ValueError):
                inventory.review(str(home), home=home)


class SchedulerAndToolTests(unittest.TestCase):
    def test_native_schedules_use_90_minutes_without_admin_or_password(self):
        command = ["C:\\Program Files\\Cleaner\\cleaner.exe"]
        windows = scheduler.definitions(command, "win32")["create"]
        self.assertIn("90", windows)
        self.assertIn("LIMITED", windows)
        self.assertIn("/IT", windows)
        self.assertNotIn("/RP", windows)
        self.assertNotIn("SYSTEM", windows)
        self.assertEqual(scheduler.definitions(["/usr/bin/python3", "/tmp/a.pyz"], "darwin")["plist"]["StartInterval"], 5400)
        linux = scheduler.definitions(["/usr/bin/python3", "/home/test/a b.pyz"], "linux")
        self.assertIn("OnUnitActiveSec=90min", linux["timer"])
        self.assertIn('"/home/test/a b.pyz"', linux["service"])
        self.assertEqual(scheduler.systemd_quote("$thing%"), '"$$thing%%"')

    def test_cache_commands_are_static_and_manual_npx_uses_native_force(self):
        root = Path.home() / ".npm"
        with mock.patch.object(tools, "cache_roots", return_value={"npm": root, "pip": Path.home()/".cache/pip", "uv": Path.home()/".cache/uv"}), mock.patch.object(tools, "npm_command", return_value=["synthetic-npm"]):
            command = tools.command_for("npx-purge")
            self.assertEqual(command[-4:], ["cache", "npx", "rm", "--force"])
            self.assertIn(str(root), command)
            with self.assertRaises(ValueError):
                tools.command_for("arbitrary-shell")
        with mock.patch.object(tools, "command_for", return_value=["synthetic-executable", "cache", "verify"]), mock.patch.object(tools.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            result = tools.run_task("npm-verify")
            self.assertEqual(result["status"], "complete")
            self.assertNotIn("shell", run.call_args.kwargs)
            self.assertNotIn("NODE_OPTIONS", run.call_args.kwargs["env"])
            self.assertFalse(result["bytesReclaimedVerified"])


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = Dashboard(("127.0.0.1", 0), State(Path(self.temp.name) / "state"))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, data=None, approved=False, host=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {"Content-Type": "application/json"}
        if approved:
            headers.update({"Origin": self.server.origin, "X-Easy-PC-Token": self.server.token})
        if host:
            headers["Host"] = host
        connection.request(method, path, json.dumps(data or {}) if method == "POST" else None, headers)
        response = connection.getresponse()
        body = response.read()
        status = response.status
        connection.close()
        return status, body

    def test_loopback_host_origin_and_token_gates(self):
        with mock.patch.object(service.engine, "scan") as scan:
            self.assertEqual(self.request("GET", "/api/state", host="attacker.example")[0], 403)
            self.assertEqual(self.request("POST", "/api/scan")[0], 403)
            scan.assert_not_called()
        self.assertEqual(self.request("GET", "/")[0], 200)
        self.assertEqual(self.request("GET", "/style.css")[0], 200)
        self.assertEqual(self.request("GET", "/app.js")[0], 200)

    def test_clean_requires_current_server_held_plan_and_explicit_confirmation(self):
        plan = {"summary": {}, "candidates": [{"id": "fixture", "path": "synthetic.tmp", "size": 7, "automatic": True}]}
        with mock.patch.object(service.engine, "scan", return_value=plan), mock.patch.object(service.engine, "clean", return_value={"deleted": [], "dryRun": False, "summary": {"affectedBytes": 0}}) as clean:
            self.assertEqual(self.request("POST", "/api/clean", {"confirm": "CLEAN STALE TEMP", "planId": "forged"}, True)[0], 400)
            clean.assert_not_called()
            status, body = self.request("POST", "/api/scan", {}, True)
            self.assertEqual(status, 200)
            identifier = json.loads(body)["plan"]["id"]
            self.assertEqual(self.request("POST", "/api/clean", {"confirm": "CLEAN STALE TEMP", "planId": identifier}, True)[0], 200)
            clean.assert_called_once_with(plan, approved_ids=["fixture"])
            self.assertEqual(self.request("POST", "/api/clean", {"confirm": "CLEAN STALE TEMP", "planId": identifier}, True)[0], 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
