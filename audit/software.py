"""Phase 8 — Installed software enumeration via Uninstall registry keys."""

from __future__ import annotations

import json
import winreg
from datetime import datetime

from utils.module_base import finding, guarded, make_result

MODULE = "software"

UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM-64"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM-32"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU"),
]


def _enum_uninstall(hive, subkey: str, label: str) -> list[dict]:
    apps: list[dict] = []
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as root:
            i = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, sub_name, 0, winreg.KEY_READ) as sub:
                        def gv(name: str) -> str | None:
                            try:
                                v, _ = winreg.QueryValueEx(sub, name)
                                return str(v)
                            except (FileNotFoundError, OSError):
                                return None

                        display = gv("DisplayName")
                        if not display:
                            continue
                        if gv("SystemComponent") == "1":
                            continue
                        apps.append({
                            "name": display,
                            "version": gv("DisplayVersion"),
                            "publisher": gv("Publisher"),
                            "install_date": gv("InstallDate"),
                            "source": label,
                        })
                except (PermissionError, OSError):
                    continue
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return apps


def _parse_install_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    raw = raw.strip()
    for fmt in ("%Y%m%d", "%m/%d/%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(raw[:10], fmt)
        except ValueError:
            continue
    return None


@guarded(MODULE)
def run() -> dict:
    """Enumerate installed software; flag missing publishers and very old installs."""
    apps: list[dict] = []
    for hive, subkey, label in UNINSTALL_KEYS:
        apps.extend(_enum_uninstall(hive, subkey, label))

    findings: list[dict] = []
    score = 0
    no_publisher = [a for a in apps if not a.get("publisher")]
    old_cutoff_days = 365 * 2
    old_apps = []
    now = datetime.now()
    for a in apps:
        dt = _parse_install_date(a.get("install_date"))
        if dt and (now - dt).days > old_cutoff_days:
            a["age_days"] = (now - dt).days
            old_apps.append(a)

    if no_publisher:
        score -= min(len(no_publisher), 5)  # cap at -5
        sample = ", ".join(a["name"] for a in no_publisher[:5])
        findings.append(finding(
            f"{len(no_publisher)} installed app(s) have no publisher metadata",
            f"Examples: {sample}",
            "low",
            "Review software with missing publisher info; unsigned/unknown "
            "publishers warrant a manual legitimacy check.",
        ))
    if old_apps:
        findings.append(finding(
            f"{len(old_apps)} app(s) installed over {old_cutoff_days // 365} years ago",
            "Old software may be unpatched; verify it is still maintained.",
            "info",
        ))
    findings.insert(0, finding(
        f"{len(apps)} installed applications enumerated",
        "From HKLM 64/32-bit and HKCU Uninstall registry hives.",
        "info",
    ))

    return make_result(MODULE, "ok", score, findings,
                       raw={"count": len(apps), "apps": apps,
                            "no_publisher_count": len(no_publisher)})


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
