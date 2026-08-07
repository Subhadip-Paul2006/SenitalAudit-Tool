"""Phase 5 — Local user accounts and admin group membership audit."""

from __future__ import annotations

import json
import subprocess

from utils.module_base import finding, guarded, make_result

MODULE = "users"

_BUILTIN_ACCOUNTS = {
    "administrator", "guest", "defaultaccount", "wdagutilityaccount",
}


def _ps_json(cmd: str) -> list[dict]:
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-Command", cmd],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"PowerShell failed: {proc.stderr.strip()[:300]}")
    data = json.loads(proc.stdout)
    return data if isinstance(data, list) else [data]


@guarded(MODULE)
def run() -> dict:
    """Enumerate local users and local Administrators membership."""
    users = _ps_json(
        "Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordExpires | ConvertTo-Json"
    )
    admins = _ps_json(
        "Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | "
        "Select-Object Name,ObjectClass,PrincipalSource | ConvertTo-Json"
    )

    findings: list[dict] = []
    score = 0

    enabled_users = [u for u in users if u.get("Enabled")]
    guest = next((u for u in users if str(u.get("Name", "")).lower() == "guest"), None)
    if guest and guest.get("Enabled"):
        score -= 10
        findings.append(finding(
            "Guest account is enabled",
            "The built-in Guest account is enabled.",
            "high",
            "Disable it: Disable-LocalUser -Name 'Guest'",
        ))

    # Built-in Administrator enabled is a notable posture point
    builtin_admin = next(
        (u for u in users if str(u.get("Name", "")).lower() == "administrator"), None
    )
    if builtin_admin and builtin_admin.get("Enabled"):
        score -= 3
        findings.append(finding(
            "Built-in Administrator account is enabled",
            "The well-known RID-500 Administrator account is enabled.",
            "low",
            "Consider disabling or renaming the built-in Administrator account.",
        ))

    extra_admins = []
    for m in admins:
        name = str(m.get("Name", ""))
        short = name.split("\\")[-1].lower()
        if short not in {"administrator", "administrators", "domain admins", "enterprise admins"} \
                and m.get("ObjectClass") == "User":
            extra_admins.append(name)

    if extra_admins:
        score -= 2
        findings.append(finding(
            f"{len(extra_admins)} non-default account(s) in Administrators group",
            "Members: " + ", ".join(extra_admins),
            "low",
            "Review these local admin accounts and remove any that are not required.",
        ))
    else:
        findings.append(finding(
            "No unexpected admin accounts",
            "Only default members found in local Administrators group.",
            "info",
        ))

    never_expire = [u["Name"] for u in enabled_users
                    if u.get("PasswordExpires") in (None, "")]
    if never_expire:
        findings.append(finding(
            f"{len(never_expire)} account(s) with non-expiring passwords",
            "Accounts: " + ", ".join(str(n) for n in never_expire),
            "low",
            "Consider enforcing password expiration for interactive accounts.",
        ))

    status = "critical" if score <= -10 else ("warning" if score < 0 else "ok")
    return make_result(MODULE, status, score, findings, raw={
        "users": users,
        "enabled_count": len(enabled_users),
        "admin_members": admins,
    })


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
