"""Phase 13 — Scheduled tasks audit via schtasks CSV output."""

from __future__ import annotations

import csv
import io
import json
import subprocess

from utils.config import get
from utils.module_base import finding, guarded, make_result

MODULE = "tasks"


def _is_trusted(command: str) -> bool:
    cmd = command.lower().strip().strip('"')
    trusted = [d.lower() for d in ((get("startup") or {}).get("trusted_dirs") or [])]
    if any(t in cmd for t in trusted if t):
        return True
    # system-run tasks and maintenance runners
    if any(x in cmd for x in ("\\windows\\", "system32", "defrag", "windowsdefender")):
        return True
    # Com-host / script-host wrapper invocations: trust based on inner script path
    import re
    m = re.search(r'([a-z]:\\[^"\']+\.(?:ps1|bat|cmd|vbs|js|exe))', cmd)
    if m:
        inner = m.group(1)
        if any(t in inner for t in trusted if t) or "\\windows\\" in inner or "\\program files" in inner:
            return True
    return False


@guarded(MODULE)
def run() -> dict:
    """Enumerate scheduled tasks; flag tasks whose actions point outside trusted paths."""
    proc = subprocess.run(
        ["schtasks", "/query", "/fo", "CSV", "/v"],
        capture_output=True, text=True, timeout=300, errors="replace",
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"schtasks failed: {proc.stderr.strip()[:300]}")

    reader = csv.DictReader(io.StringIO(proc.stdout))
    tasks: list[dict] = []
    suspicious: list[dict] = []
    for row in reader:
        name = row.get("TaskName") or row.get("Task Name") or ""
        task_to_run = row.get("Task To Run") or row.get("TaskToRun") or ""
        status = row.get("Status", "")
        run_as = row.get("Run As User", "")
        entry = {"name": name, "command": task_to_run, "status": status, "run_as": run_as}
        tasks.append(entry)
        cmd = task_to_run.strip()
        if not cmd or cmd.upper() in ("N/A", "COM handler"):
            continue
        if "\\Microsoft\\Windows\\" in name:
            continue  # built-in OS tasks
        if not _is_trusted(cmd):
            suspicious.append(entry)

    findings: list[dict] = []
    score = 0
    for t in suspicious[:30]:
        score = max(score - 1, -10)  # module cap
        findings.append(finding(
            f"Non-standard scheduled task: {t['name']}",
            f"Command: {t['command'][:200]} — Runs as: {t['run_as']}",
            "low",
            "Review this task's publisher/source; unknown scheduled tasks are a "
            "common persistence mechanism (review, not a malware verdict).",
        ))

    if not suspicious:
        findings.append(finding(
            f"{len(tasks)} scheduled tasks reviewed; none flagged",
            "All non-Microsoft tasks use trusted paths.", "info"))
    else:
        findings.insert(0, finding(
            f"{len(suspicious)} scheduled task(s) outside trusted paths",
            f"Out of {len(tasks)} total tasks.", "info"))

    status = "warning" if suspicious else "ok"
    return make_result(MODULE, status, score, findings,
                       raw={"task_count": len(tasks), "flagged": suspicious})


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
