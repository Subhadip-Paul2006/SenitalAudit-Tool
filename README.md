# SentinelAudit

A **defensive, read-only** Windows security auditing tool. It inspects local
system configuration (firewall, Defender, services, users, registry, event
logs, startup entries, scheduled tasks, etc.), scores the overall security
posture, and generates professional PDF/HTML/JSON reports plus a styled CLI
dashboard.

> SentinelAudit **never modifies system settings**. It only reads configuration
> state and reports on it.

## Requirements

- Windows 10/11 (uses `winreg`, `psutil` Windows APIs, and PowerShell — will
  **not** run on Linux/macOS; `main.py` exits with an error elsewhere)
- Python 3.12+
- Administrator rights for full coverage (password policy, some registry keys,
  security event log, USB history degrade gracefully without admin)

## Install

```powershell
pip install -r requirements.txt
```

## Usage

```powershell
python main.py                    # full audit (default), CLI dashboard only
python main.py --quick            # skip slow modules (event logs, software, tasks, updates)
python main.py --export pdf,html,json
python main.py --compare-last     # diff against previous stored run
python main.py --list-history     # show previous runs
python main.py --full --export pdf --no-admin-check
python main.py --no-save          # don't persist run to database/history.db
```

Exit codes: `0` = score ≥ 75, `1` = 50–74, `2` = < 50 (useful for scripting).

## What it checks

| Module | Source | Flags |
|---|---|---|
| `firewall` | `netsh advfirewall` | Disabled profiles |
| `defender` | `Get-MpComputerStatus` | RTP/AV off, tamper protection off, old signatures |
| `services` | `psutil.win_service_iter()` | Risky services running (Telnet, FTP, WinRM…) |
| `ports` | `psutil.net_connections()` | Listening Telnet/FTP/RDP/SMB… |
| `users` | `Get-LocalUser`, `Get-LocalGroupMember` | Guest enabled, extra admins, non-expiring passwords |
| `password_policy` | `net accounts` | Min length < 8, no lockout, never-expiring passwords |
| `startup` | Run/RunOnce keys, Startup folders | Autostarts outside trusted dirs (review, not malware verdict) |
| `software` | Uninstall registry keys | Missing publisher metadata, very old installs |
| `usb` | `USBSTOR` registry | Historical USB storage devices (informational) |
| `registry` | Security-relevant keys | SMBv1 enabled, RDP without NLA, AutoRun on, Remote Registry |
| `updates` | `Get-HotFix` | Last update > 30 days |
| `eventlogs` | `Get-WinEvent` | Failed-logon spikes (brute force), lockouts, Defender detections |
| `tasks` | `schtasks /query /v` | Scheduled tasks outside trusted paths |

Thresholds, port severities, risky-service list, scoring weights and report
paths are all tunable in **`config.yaml`** — no code changes needed.

## Scoring

Base score 100; each module contributes a (config-weighted) `score_impact`.
Clamped to 0–100. Bands: **90+ Excellent · 75–89 Good · 50–74 Fair · <50 Poor**.

## Reports

- `reports/audit.pdf` — cover page, summary table, per-module findings pages,
  prioritized recommendations page (reportlab)
- `reports/audit.html` — self-contained, inline CSS, single shareable file
- `reports/audit.json` — full raw results for machine consumption/diffing
- `database/history.db` — SQLite, one row per run; `--compare-last` shows new /
  resolved findings and score delta

## Data contract

Every `audit/*.py` module exposes `run() -> dict` with keys
`module`, `status`, `score_impact`, `findings[]`, `raw`. Failures inside a
module degrade gracefully to `status: "error"` instead of killing the run.

## Project layout

```
main.py               CLI + orchestration
audit/                13 audit modules (one concern each)
utils/                config, logging, elevation, system_info, scoring, cli_display, history
report/               pdf.py, html.py (+ JSON export in html.py)
config.yaml           thresholds, weights, lists, paths
database/history.db   created at runtime
reports/  logs/       created at runtime
```
