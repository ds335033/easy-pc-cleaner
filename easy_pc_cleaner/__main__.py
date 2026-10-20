from __future__ import annotations

import argparse
import json
import sys

from . import engine, inventory, scheduler, service, tools
from .runtime import State, VERSION, notify


def main(argv=None):
    parser = argparse.ArgumentParser(prog="easy-pc-cleaner", description="Private, bounded cleanup. Personal files and code require review.")
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("scan", help="Read-only cache and temporary-file preview")
    clean = commands.add_parser("clean", help="Preview by default; --apply explicitly deletes only approved stale temp files")
    clean.add_argument("--apply", action="store_true")
    cache = commands.add_parser("cache", help="Run an official package-manager cache task after explicit approval")
    cache.add_argument("task", choices=list(tools.LABELS))
    cache.add_argument("--apply", action="store_true")
    view = commands.add_parser("dashboard", help="Open the private local dashboard")
    view.add_argument("--port", type=int, default=0)
    view.add_argument("--no-browser", action="store_true")
    auto = commands.add_parser("autopilot", help="Manage the per-user 90-minute native schedule")
    auto.add_argument("action", choices=("enable", "disable", "status"))
    auto.add_argument("--npm-verify", action="store_true", help="Also run official npm integrity verification / garbage collection; never a full purge")
    commands.add_parser("autopilot-run", help="Scheduler entry point; refuses to run when disabled or not due")
    inspect = commands.add_parser("inventory", help="Read-only large-file, duplicate and code review of one requested folder")
    inspect.add_argument("path")
    inspect.add_argument("--duplicates", action="store_true")
    commands.add_parser("trash", help="Open native Trash / Recycle Bin for manual review")
    install = commands.add_parser("install", help="Install a verified release for this user")
    install.add_argument("--autopilot", action="store_true")
    install.add_argument("--npm-verify", action="store_true")
    args = parser.parse_args(argv)
    state = State()
    try:
        if args.command in (None, "dashboard"):
            from .app import serve
            serve(state, getattr(args, "port", 0), not getattr(args, "no_browser", False))
            return 0
        if args.command == "scan":
            result = engine.scan(service.policy(state, dry_run=True))
        elif args.command == "clean":
            with state.lock():
                plan = engine.scan(service.policy(state, dry_run=not args.apply))
                ids = [item["id"] for item in plan.get("candidates", []) if item.get("automaticEligible", item.get("automatic", False))]
                result = state.report(service.summarize(engine.clean(plan, approved_ids=ids)))
        elif args.command == "cache":
            if not args.apply:
                result = {"dryRun": True, "task": args.task, "summary": "No cache task ran. Add --apply only after reviewing the operation and closing active package tasks."}
            else:
                with state.lock():
                    result = state.report(tools.run_task(args.task))
        elif args.command == "inventory":
            with state.lock():
                result = state.report(inventory.review(args.path, args.duplicates))
        elif args.command == "autopilot":
            if args.action == "status":
                result = state.read("settings.json", {"autopilotEnabled": False, "intervalMinutes": 90})
            else:
                with state.lock():
                    if args.action == "enable" and args.npm_verify:
                        settings = state.read("settings.json", {})
                        state.write("settings.json", {**settings, "autopilotNpmVerify": True})
                    result = scheduler.change(state, args.action == "enable")
        elif args.command == "autopilot-run":
            result = service.autopilot_run(state)
        elif args.command == "trash":
            result = scheduler.open_trash()
        elif args.command == "install":
            from .install import install
            if args.npm_verify:
                settings = state.read("settings.json", {})
                state.write("settings.json", {**settings, "autopilotNpmVerify": True})
            result = install(state, enable_autopilot=args.autopilot)
        else:
            parser.error("Unknown command.")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1 if result.get("status") in ("needs-review", "unavailable") else 0
    except (ValueError, RuntimeError, OSError) as exc:
        failure = {"kind": "cleanup-error", "status": "needs-review", "error": str(exc)[:300], "summary": "Stopped safely. Review this issue before retrying."}
        try:
            state.report(failure)
            if args.command == "autopilot-run":
                notify(failure["summary"])
        except (ValueError, OSError):
            pass
        print(json.dumps(failure), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
