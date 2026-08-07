"""Phase 3 — Running services audit; cross-reference risky-service list."""

from __future__ import annotations

import json

import psutil

from utils.config import get
from utils.module_base import finding, guarded, make_result

MODULE = "services"


@guarded(MODULE)
def run() -> dict:
    """List services; flag running services that match the configured risky list."""
    risky = {s.lower(): s for s in (get("risky_services") or [])}
    services_out: list[dict] = []
    findings: list[dict] = []
    score = 0
    flagged: list[str] = []

    for svc in psutil.win_service_iter():
        try:
            info = svc.as_dict()
        except Exception:  # noqa: BLE001
            continue
        name = info.get("name", "")
        services_out.append(
            {
                "name": name,
                "display_name": info.get("display_name"),
                "status": info.get("status"),
                "start_type": str(info.get("start_type")),
            }
        )
        if name.lower() in risky and str(info.get("status", "")).lower() == "running":
            flagged.append(name)

    # SMB server is informational rather than actionable on most desktops
    info_only = {"lanmanserver"}
    for name in flagged:
        if name.lower() in info_only:
            findings.append(finding(
                f"Service running: {name}",
                f"Risky-listed service '{name}' is running (informational).",
                "info",
            ))
            continue
        score -= 8
        findings.append(finding(
            f"Risky service running: {name}",
            f"The service '{name}' ({risky[name.lower()]}) is running and is on the risky-service list.",
            "medium",
            f"Stop and disable '{name}' if not required: "
            f"Set-Service {name} -StartupType Disabled; Stop-Service {name}",
        ))

    if not flagged:
        findings.append(finding(
            "No risky services running",
            f"Checked {len(services_out)} services against the risky-service list.",
            "info",
        ))

    status = "warning" if any(n.lower() not in info_only for n in flagged) else "ok"
    return make_result(MODULE, status, score, findings,
                       raw={"service_count": len(services_out),
                            "flagged": flagged,
                            "services": services_out})


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
