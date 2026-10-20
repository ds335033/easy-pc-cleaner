"""One bounded operation at a time; uncertainty is reported, never escalated."""
from __future__ import annotations

import time
from pathlib import Path

from . import engine, tools
from .runtime import State, notify, now


def policy(state: State, *, dry_run: bool):
    return engine.Policy(dry_run=dry_run, protected_paths=(str(state.path), str(Path(__file__).resolve().parent.parent)))


def summarize(result: dict) -> dict:
    deleted = result.get("deleted", [])
    if isinstance(deleted, int):
        count = deleted
    else:
        count = len(deleted)
    size = 0 if result.get("dryRun") else result.get("summary", {}).get("affectedBytes", result.get("deletedBytes", result.get("bytesDeleted", 0)))
    if not size and isinstance(deleted, list):
        size = sum(x.get("size", 0) for x in deleted if isinstance(x, dict))
    skipped = result.get("skipped", [])
    rejected = result.get("rejected", [])
    needs_review = bool(skipped or rejected or result.get("truncated"))
    preview = result.get("dryRun") is True
    summary = (f"Preview: {len(result.get('wouldDelete', []))} temporary files eligible; nothing was deleted." if preview else f"Removed {count} stale temporary files ({size / 1048576:.1f} MiB). " + ("Some items were skipped for review." if needs_review else "Personal files and project source were preserved."))
    return {**result, "kind": "cleanup", "deletedCount": count, "deletedBytes": size, "reviewRequired": needs_review, "summary": summary}


def autopilot_run(state: State, *, notices: bool = True) -> dict:
    with state.lock():
        settings = state.read("settings.json", {})
        if settings.get("autopilotEnabled") is not True:
            return {"status": "disabled", "summary": "Autopilot is off; nothing was changed."}
        last = settings.get("lastAutopilotEpoch", 0)
        if isinstance(last, (int, float)) and time.time() - last < 5400:
            return {"status": "not-due", "summary": "The 90-minute interval has not elapsed; nothing was changed."}
        # Record before work so a crashing package manager cannot cause rapid retries.
        settings.update(lastAutopilotEpoch=time.time(), lastAutopilotStartedAt=now())
        state.write("settings.json", settings)
        plan = engine.scan(policy(state, dry_run=False))
        result = summarize(engine.clean(plan, unattended=True))
        # Native npm verification may be enabled manually; default unattended work
        # is stale-temp-only. No full cache purge ever runs on a timer.
        if settings.get("autopilotNpmVerify") is True:
            result["packageTask"] = tools.run_task("npm-verify")
            result["reviewRequired"] |= result["packageTask"].get("reviewRequired", False)
        truncated = plan.get("summary", {}).get("truncated")
        result["reviewRequired"] |= bool(truncated)
        result.update(status="partial" if truncated else "complete", trigger="90-minute-user-scheduler", scanTruncated=truncated)
        report = state.report(result)
    if notices:
        notify(report["summary"])
    return report
