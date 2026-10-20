"""Loopback-only dashboard with Host/Origin checks and per-process CSRF token."""
from __future__ import annotations

import hmac
import json
import secrets
import sys
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import urlsplit

from . import engine, inventory, scheduler, service, tools
from .runtime import State, VERSION


class Dashboard(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, state):
        self.state = state
        self.token = secrets.token_urlsafe(32)
        self.plan = None
        self.plan_id = None
        self.plan_at = 0.0
        self.api_lock = threading.Lock()
        self.workers = threading.BoundedSemaphore(4)
        super().__init__(address, Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.workers.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "EasyPcCleaner"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass  # No request/body/token/path logging.

    def output(self, code, value, content_type="application/json; charset=utf-8"):
        data = value.encode("utf-8") if isinstance(value, str) else json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(data)

    def allowed(self):
        # Exact Host defeats DNS rebinding; no CORS or remote bind option exists.
        return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

    def do_GET(self):
        if not self.allowed():
            return self.output(403, {"error": "Invalid local host."})
        try:
            path = urlsplit(self.path).path
            if path == "/favicon.ico":
                return self.output(204, "", "image/x-icon")
            if path == "/api/state":
                settings = self.server.state.read("settings.json", {})
                report = self.server.state.read("last-report.json")
                return self.output(200, {"version": VERSION, "platform": sys.platform, "autopilot": {"enabled": settings.get("autopilotEnabled") is True, "npmVerify": settings.get("autopilotNpmVerify") is True, "intervalMinutes": 90}, "lastReport": report, "tools": tools.capabilities(), "policy": {"minAgeDays": 7, "maxDeleteMiB": 512}, "pendingReviewCount": len(report.get("rejected", [])) if report else 0, "reportFolder": str(self.server.state.reports)})
            if path == "/api/reports":
                return self.output(200, {"reports": self.server.state.history()})
            if path in ("/", "/index.html", "/app.js", "/style.css"):
                name = "index.html" if path == "/" else path[1:]
                source = files("easy_pc_cleaner").joinpath("web").joinpath(name).read_text(encoding="utf-8")
                if name == "index.html":
                    source = source.replace("__EPC_TOKEN__", self.server.token)
                mime = "text/html" if name.endswith(".html") else "text/javascript" if name.endswith(".js") else "text/css"
                return self.output(200, source, mime + "; charset=utf-8")
            return self.output(404, {"error": "Not found."})
        except (OSError, ValueError):
            return self.output(500, {"error": "Local application data could not be read. Nothing was cleaned."})

    def do_POST(self):
        if not self.allowed() or self.headers.get("Origin") != self.server.origin or not hmac.compare_digest(self.headers.get("X-Easy-PC-Token", ""), self.server.token):
            return self.output(403, {"error": "Use the local dashboard to approve actions."})
        if self.headers.get_content_type() != "application/json":
            return self.output(415, {"error": "JSON is required."})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 8192 or self.headers.get("Transfer-Encoding"):
                raise ValueError("Request is too large or invalid.")
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict):
                raise ValueError("Invalid request.")
        except (ValueError, json.JSONDecodeError):
            return self.output(400, {"error": "Invalid request."})
        if not self.server.api_lock.acquire(blocking=False):
            return self.output(409, {"error": "Another operation is running; wait for its report."})
        try:
            state = self.server.state
            with state.lock():
                if self.path == "/api/scan":
                    plan = engine.scan(service.policy(state, dry_run=False))
                    self.server.plan, self.server.plan_id, self.server.plan_at = plan, uuid.uuid4().hex, time.monotonic()
                    display = {**plan, "id": self.server.plan_id}
                    display["summary"] = {**plan.get("summary", {}), "candidateCount": sum(1 for x in plan.get("candidates", []) if x.get("automaticEligible", x.get("automatic", False))), "candidateBytes": sum(x.get("size", 0) for x in plan.get("candidates", []) if x.get("automaticEligible", x.get("automatic", False)))}
                    return self.output(200, {"plan": display})
                if self.path == "/api/clean":
                    if body.get("confirm") != "CLEAN STALE TEMP" or body.get("planId") != self.server.plan_id or self.server.plan is None or time.monotonic() - self.server.plan_at > 600:
                        raise ValueError("Scan again and confirm the current temporary-file plan.")
                    plan = self.server.plan
                    self.server.plan = None
                    ids = [x["id"] for x in plan.get("candidates", []) if x.get("automaticEligible", x.get("automatic", False))]
                    report = service.summarize(engine.clean(plan, approved_ids=ids))
                    return self.output(200, state.report(report))
                if self.path == "/api/cache":
                    if body.get("confirm") != "RUN CACHE TASK":
                        raise ValueError("Review and confirm the package-cache action.")
                    return self.output(200, state.report(tools.run_task(body.get("tool"))))
                if self.path == "/api/autopilot":
                    enabled = body.get("enabled")
                    if not isinstance(enabled, bool) or enabled and body.get("confirm") != "ENABLE AUTOPILOT":
                        raise ValueError("Confirm the 90-minute safe cleanup schedule.")
                    return self.output(200, scheduler.change(state, enabled))
                if self.path == "/api/inventory":
                    if not isinstance(body.get("path"), str) or not isinstance(body.get("duplicates", False), bool):
                        raise ValueError("Choose one folder for a read-only review.")
                    return self.output(200, state.report(inventory.review(body["path"], body.get("duplicates", False))))
                if self.path == "/api/trash" and body.get("action") == "open":
                    return self.output(200, scheduler.open_trash())
                return self.output(404, {"error": "Unknown local action."})
        except (ValueError, RuntimeError, OSError) as exc:
            # Error strings here are our own bounded diagnostics, never tool output.
            return self.output(400, {"error": str(exc)[:300]})
        finally:
            self.server.api_lock.release()


def serve(state: State, port=0, open_browser=True):
    server = Dashboard(("127.0.0.1", port), state)
    server.timeout = 1
    print(f"Easy PC Cleaner dashboard: {server.origin}", flush=True)
    state.write("dashboard.json", {"url": server.origin, "pid": __import__("os").getpid()})
    if open_browser:
        webbrowser.open(server.origin)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
