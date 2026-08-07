"""Phase 1 — Windows Firewall profile audit via netsh."""

from __future__ import annotations

import re
import subprocess

from utils.module_base import finding, guarded, make_result

MODULE = "firewall"


def _parse_profiles(output: str) -> dict[str, dict[str, str]]:
    """Parse 'netsh advfirewall show allprofiles' output into per-profile state."""
    profiles: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line in output.splitlines():
        m = re.match(r"^\s*(\w+)\s+Profile Settings:", line)
        if m:
            current = m.group(1)
            profiles[current] = {}
            continue
        if current is None:
            continue
        m = re.match(r"^\s*State\s+(\w+)", line)
        if m:
            profiles[current]["state"] = m.group(1).upper()
        m = re.match(r"^\s*Firewall Policy\s+(.+)$", line)
        if m:
            profiles[current]["policy"] = m.group(1).strip()
    return profiles


@guarded(MODULE)
def run() -> dict:
    """Audit Windows Firewall profile states."""
    proc = subprocess.run(
        ["netsh", "advfirewall", "show", "allprofiles"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    profiles = _parse_profiles(proc.stdout)

    findings: list[dict] = []
    score_impact = 0
    disabled: list[str] = []
    for name, data in profiles.items():
        if data.get("state") == "OFF":
            disabled.append(name)
            score_impact -= 10
            findings.append(
                finding(
                    title=f"Firewall {name} profile is disabled",
                    detail=f"The {name} firewall profile state is OFF.",
                    severity="medium",
                    recommendation=(
                        f"Enable the {name} profile: "
                        f"netsh advfirewall set {name.lower()}profile state on"
                    ),
                )
            )
    if not disabled:
        findings.append(
            finding(
                title="All firewall profiles enabled",
                detail="Domain, Private and Public profiles are all ON.",
                severity="info",
            )
        )

    status = "critical" if len(disabled) == len(profiles) and profiles else (
        "warning" if disabled else "ok"
    )
    return make_result(MODULE, status, score_impact, findings, raw={"profiles": profiles})


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2))
