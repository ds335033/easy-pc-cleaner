# easy-pc-cleaner

A lightweight, local-first cleaner by **Darren Smith / EASY AGENT**. Free, open source, MIT licensed. Python runtime code has no third-party dependencies.

## What it does

- A private loopback dashboard, a CLI, bounded scans and a JSON report after cleanup.
- A native per-user **90-minute** autopilot; no administrator account, saved password or cloud service required.
- Conservative removal of positively identified stale temporary files. Unknown files, active/recent files, links, projects, documents, photos and videos require review.
- npm verification and manual npm/npx/pip cache maintenance through the official package managers; manual uv pruning. No generic deletion inside package caches or environments.
- Requested-folder large-file and SHA-256 duplicate review, plus tentative Python unused-import hints. These are **read-only**: age, size, duplication or static analysis does not establish that a personal file or code is disposable.
- Opens the OS Recycle Bin / Trash so you can review and empty it yourself. Autopilot never empties Trash.

## Run

Download a release from [GitHub Releases](https://github.com/ds335033/easy-pc-cleaner/releases/latest). Verify its SHA-256 against `SHA256SUMS` before running it.

Windows bundled ZIP: extract the entire folder and run `easy-pc-cleaner.exe`. The first screen is a preview; nothing is cleaned just by opening it. Install for this user with:

```powershell
.\easy-pc-cleaner.exe install --autopilot --npm-verify
```

Portable release on Windows, macOS or Linux requires **Python 3.10+**:

```sh
python3 easy-pc-cleaner.pyz dashboard
python3 easy-pc-cleaner.pyz scan
python3 easy-pc-cleaner.pyz clean                # preview only
python3 easy-pc-cleaner.pyz clean --apply        # stale safe-temp files only
python3 easy-pc-cleaner.pyz cache npm-verify --apply
python3 easy-pc-cleaner.pyz inventory ~/Documents/one-folder --duplicates
python3 easy-pc-cleaner.pyz autopilot enable --npm-verify
python3 easy-pc-cleaner.pyz autopilot disable
```

On Windows use `python` instead of `python3` if appropriate. Source checkout: `python launch.py`. The bundled installer targets Windows; portable users can enable their per-user scheduler from the dashboard. Linux requires a working systemd user session. macOS uses a LaunchAgent. Jobs run while the user is logged in; sleep or shutdown delays work. The app also enforces at least 90 minutes between scheduled runs and refuses overlapping cleanup operations.

## Safety and privacy

Opening the app or scanning never deletes files. Full package-cache purges are manual; close active package installs, npx tools and builds before approving a purge. Missing tools, unsupported platforms, changed files, unexpected paths and uncertain items stop or skip safely. A package manager may need to download cache contents again after a manual purge. This is disk housekeeping, not a performance or malware-removal guarantee.

No account, tracking, AI key or subscription is required. The dashboard binds only to `127.0.0.1`, checks Host and Origin, requires a per-process request token and serves no remote scripts. File names and reports stay on your machine. Local notifications are best effort; JSON reports are the authoritative record. Reports are retained up to 200 owned records. Nothing is emailed or uploaded.

State and reports: Windows `%LOCALAPPDATA%\EasyPcCleaner`; macOS `~/Library/Application Support/EasyPcCleaner`; Linux `~/.local/state/easy-pc-cleaner`. `EASY_PC_CLEANER_STATE_DIR` can select a new empty private directory for testing; existing unrelated nonempty folders are refused. Windows installation: `%LOCALAPPDATA%\Programs\EasyPcCleaner\<version>`; the installer verifies every bundled file and adds a Start Menu shortcut.

Autopilot defaults to safe stale-temp cleanup. Opt in with `--npm-verify` to also run official npm verification and garbage collection; full cache purges always remain manual. Its minimum file age is seven days and temporary-file work is bounded to 20 seconds of scanning, 20,000 examined entries, and at most 2,000 files / 512 MiB removed. The optional npm task has a separate 120-second limit and its reclaimed bytes are not guessed. Read-only discovery can truncate; the report must be reviewed before treating it as a complete machine inventory. Personal-file deletion, automatic dead-code edits, registry cleaning, drivers and system caches are outside this release's automatic scope.

## Development

```sh
python -m unittest discover -s tests -v
python build.py
python dist/easy-pc-cleaner.pyz --version
```

The tests use synthetic files and mocked external operations. Cross-platform CI runs them on Windows, macOS and Linux; a green test does not establish every desktop's notification/scheduler configuration. The initial Windows binary is unsigned; do not bypass a security block. Inspect source or use the portable release if your organization requires signed executables.

Package cache behavior follows [npm cache](https://docs.npmjs.com/cli/commands/npm-cache/), [pip cache](https://pip.pypa.io/en/stable/cli/pip_cache/) and [uv cache](https://docs.astral.sh/uv/concepts/cache/). The portable format follows [Python zipapp](https://docs.python.org/3/library/zipapp.html).
