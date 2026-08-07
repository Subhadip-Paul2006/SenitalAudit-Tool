"""Phase 12 — Event log analysis: failed logons, lockouts, Defender alerts, crashes."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta

from utils.config import get
from utils.module_base import finding, guarded, make_result

MODULE = "eventlogs"


def _count_events(log: str, event_ids: list[int], start_iso: str) -> int:
    """Count events in a log matching IDs since start_iso via Get-WinEvent."""
    ids = ",".join(str(i) for i in event_ids)
    script = (
        f"$ErrorActionPreference='SilentlyContinue';"
        f"(Get-WinEvent -FilterHashtable @{{LogName='{log}'; Id={ids}; "
        f"StartTime='{start_iso}'}}).Count | ConvertTo-Json"
    )
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True, text=True, timeout=180,
    )
    out = proc.stdout.strip()
    if proc.returncode != 0 or not out:
        return 0
    try:
        val = json.loads(out)
        return int(val) if val is not None else 0
    except (json.JSONDecodeError, ValueError, TypeError):
        return 0


@guarded(MODULE)
def run() -> dict:
    """Count security-relevant events over the configured window."""
    cfg = get("eventlogs") or {}
    window_hours = int(cfg.get("window_hours", 24))
    spike = int(cfg.get("failed_logon_spike_threshold", 10))
    start = (datetime.now() - timedelta(hours=window_hours)).isoformat(timespec="seconds")

    counts = {
        "failed_logons_4625": _count_events("Security", [4625], start),
        "successful_logons_4624": _count_events("Security", [4624], start),
        "lockouts_4740": _count_events("Security", [4740], start),
        "service_crashes_7031_7034": _count_events("System", [7031, 7034], start),
        "defender_alerts_1116_1117": _count_events(
            "Microsoft-Windows-Windows Defender/Operational", [1116, 1117], start),
    }

    findings: list[dict] = []
    score = 0

    failed = counts["failed_logons_4625"]
    if failed >= spike:
        score -= 10
        findings.append(finding(
            f"{failed} failed logon attempts in {window_hours}h",
            f"Event ID 4625 count exceeds the spike threshold ({spike}). "
            "This is a classic brute-force indicator.",
            "high",
            "Investigate source accounts/IPs in the Security log; enforce lockout "
            "policy and consider blocking the source.",
        ))
    elif failed > 0:
        findings.append(finding(
            f"{failed} failed logon(s) in {window_hours}h",
            "Below spike threshold; review if unexpected.",
            "info",
        ))

    lockouts = counts["lockouts_4740"]
    if lockouts >= 3:
        score -= 5
        findings.append(finding(
            f"{lockouts} account lockout(s) in {window_hours}h",
            "Event ID 4740 — repeated lockouts may indicate password-guessing.",
            "medium",
            "Identify the lockout source (caller computer) in event details.",
        ))

    crashes = counts["service_crashes_7031_7034"]
    if crashes > 0:
        findings.append(finding(
            f"{crashes} service crash/termination event(s) in {window_hours}h",
            "System log 7031/7034 — unexpected service terminations.",
            "low",
            "Review which services terminated unexpectedly.",
        ))

    malware = counts["defender_alerts_1116_1117"]
    if malware > 0:
        score -= 8
        findings.append(finding(
            f"{malware} Defender malware detection(s) in {window_hours}h",
            "Defender Operational log 1116/1117 — malware or unwanted software detected.",
            "high",
            "Open Windows Security > Protection history and remediate detections.",
        ))

    if all(v == 0 for v in counts.values()):
        findings.append(finding(
            f"No notable security events in the last {window_hours}h",
            "No failed logons, lockouts, crashes, or Defender detections counted.",
            "info",
        ))

    status = "critical" if (failed >= spike or malware > 0) else (
        "warning" if score < 0 else "ok")
    return make_result(MODULE, status, score, findings,
                       raw={"window_hours": window_hours, "counts": counts})


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
