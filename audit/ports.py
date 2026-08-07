"""Phase 4 — Open/listening ports audit via psutil.net_connections."""

from __future__ import annotations

import json

import psutil

from utils.config import get
from utils.module_base import finding, guarded, make_result

MODULE = "ports"


@guarded(MODULE)
def run() -> dict:
    """Enumerate listening TCP ports and map known ones to services/severity."""
    port_map: dict[int, str] = {int(k): v for k, v in (get("port_service_map") or {}).items()}
    port_sev: dict[int, str] = {int(k): v for k, v in (get("port_severity") or {}).items()}

    listeners: dict[int, set[str]] = {}
    try:
        conns = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, PermissionError):
        conns = psutil.net_connections(kind="tcp")  # retry; if still failing, guarded catches
    for c in conns:
        if c.status != psutil.CONN_LISTEN or not c.laddr:
            continue
        listeners.setdefault(c.laddr.port, set()).add(c.laddr.ip or "")

    findings: list[dict] = []
    score = 0
    flagged: list[dict] = []

    for port in sorted(listeners):
        service = port_map.get(port)
        if service is None:
            continue
        severity = port_sev.get(port, "info")
        flagged.append({"port": port, "service": service, "addresses": sorted(listeners[port])})
        impact = {"high": -10, "medium": -6, "low": -3, "info": 0}.get(severity, 0)
        score += impact
        sev_for_finding = severity if severity != "info" else "info"
        findings.append(finding(
            f"Port {port} ({service}) is listening",
            f"Listening on: {', '.join(sorted(listeners[port]))}.",
            sev_for_finding,
            f"Verify that {service} on port {port} is intentionally exposed; "
            "disable the service or block the port in the firewall if not needed."
            if impact < 0 else None,
        ))

    if not flagged:
        findings.append(finding(
            "No audited ports listening",
            "None of the ports in the configured watch-list are in LISTEN state.",
            "info",
        ))

    worst = "ok"
    for f in flagged:
        sev = port_sev.get(f["port"], "info")
        if sev == "high":
            worst = "critical"
        elif sev == "medium" and worst != "critical":
            worst = "warning"
        elif sev == "low" and worst == "ok":
            worst = "warning"

    return make_result(MODULE, worst, score, findings,
                       raw={"listening": {str(p): sorted(a) for p, a in listeners.items()},
                            "flagged": flagged})


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
