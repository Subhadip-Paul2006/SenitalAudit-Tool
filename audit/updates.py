"""Phase 11 — Windows Update state: installed hotfixes and last update date."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime

from utils.config import get
from utils.module_base import finding, guarded, make_result

MODULE = "updates"


@guarded(MODULE)
def run() -> dict:
    """Use Get-HotFix to find installed KBs and the most recent update date."""
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-HotFix | Sort-Object {$_.InstalledOn -as [datetime]} -Descending | "
         "Select-Object -First 50 HotFixID, Description, "
         "@{N='InstalledOn';E={if ($_.InstalledOn) {$_.InstalledOn.ToString('yyyy-MM-dd')} else {''}}} | "
         "ConvertTo-Json"],
        capture_output=True, text=True, timeout=180,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"Get-HotFix failed: {proc.stderr.strip()[:300]}")

    data = json.loads(proc.stdout)
    hotfixes = data if isinstance(data, list) else [data]

    last_update: datetime | None = None
    parsed = []
    for hf in hotfixes:
        dt = None
        raw_date = hf.get("InstalledOn")
        if raw_date:
            s = str(raw_date).strip()
            if s.startswith("/Date("):
                ms = int(s[6:-2].split("+")[0].split("-")[0])
                dt = datetime.fromtimestamp(ms / 1000)
            else:
                for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y"):
                    try:
                        dt = datetime.strptime(s[:10], fmt)
                        break
                    except ValueError:
                        continue
        parsed.append({"kb": hf.get("HotFixID"),
                       "description": hf.get("Description"),
                       "installed_on": dt.isoformat() if dt else str(raw_date)})
        if dt and (last_update is None or dt > last_update):
            last_update = dt

    findings: list[dict] = []
    score = 0
    stale_days = int((get("updates") or {}).get("stale_days_threshold", 30))

    if last_update is None:
        findings.append(finding(
            "No installed hotfixes returned",
            "Get-HotFix returned no usable install dates.",
            "info",
        ))
    else:
        age = (datetime.now() - last_update).days
        if age > stale_days:
            score -= 6
            findings.append(finding(
                f"Last Windows Update was {age} days ago",
                f"Most recent hotfix installed {last_update.date()}; threshold is {stale_days} days.",
                "medium",
                "Run Windows Update and install pending security patches.",
            ))
        else:
            findings.append(finding(
                f"System updated {age} day(s) ago",
                f"Most recent hotfix: {last_update.date()}.",
                "info",
            ))

    status = "warning" if score < 0 else "ok"
    return make_result(MODULE, status, score, findings, raw={
        "hotfix_count": len(hotfixes),
        "last_update": last_update.isoformat(timespec="seconds") if last_update else None,
        "recent_hotfixes": parsed[:20],
    })


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
