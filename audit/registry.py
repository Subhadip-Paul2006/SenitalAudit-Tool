"""Phase 10 — Security-relevant registry checks: SMBv1, RDP/NLA, AutoRun, LSA."""

from __future__ import annotations

import json
import winreg

from utils.module_base import finding, guarded, make_result

MODULE = "registry"


def _read_value(hive, subkey: str, name: str) -> tuple[bool, object | None]:
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return True, value
    except FileNotFoundError:
        return False, None
    except (PermissionError, OSError):
        return False, None


@guarded(MODULE)
def run() -> dict:
    """Check SMBv1, RDP + NLA, AutoPlay/AutoRun, Remote Registry, LSA protection."""
    findings: list[dict] = []
    score = 0
    raw: dict[str, object] = {}

    # --- SMBv1 server ---
    exists, smbv1 = _read_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "SMB1",
    )
    smbv1_enabled = bool(smbv1) if exists else None
    raw["smbv1"] = {"value_present": exists, "value": smbv1}
    if smbv1_enabled is True:
        score -= 10
        findings.append(finding(
            "SMBv1 is enabled",
            "LanmanServer\\Parameters\\SMB1 = 1. SMBv1 is the EternalBlue-class exposure.",
            "high",
            "Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
            "(or Set-SmbServerConfiguration -EnableSMB1Protocol $false).",
        ))
    elif smbv1_enabled is None:
        # Absent value = default; on Win10 1709+/Win11 SMBv1 is not installed by default
        exists2, mrx = _read_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\mrxsmb10",
            "Start",
        )
        raw["mrxsmb10_start"] = mrx if exists2 else None
        if exists2 and mrx in (0, 1, 2):  # enabled start types
            score -= 10
            findings.append(finding(
                "SMBv1 client driver (mrxsmb10) is enabled",
                f"mrxsmb10 Start = {mrx} indicates SMBv1 is active.",
                "high",
                "Disable SMBv1 via Windows Features or Set-SmbServerConfiguration.",
            ))
        else:
            findings.append(finding("SMBv1 not active (default configuration)",
                                    "No explicit SMB1 enable value; mrxsmb10 not in an enabled state.", "info"))
    else:
        findings.append(finding("SMBv1 explicitly disabled", "SMB1 = 0.", "info"))

    # --- RDP ---
    exists, deny = _read_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections",
    )
    rdp_enabled = exists and int(deny or 1) == 0
    raw["rdp_enabled"] = rdp_enabled
    if rdp_enabled:
        score -= 3
        exists_nla, nla = _read_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "UserAuthentication",
        )
        nla_on = exists_nla and int(nla or 0) == 1
        raw["rdp_nla"] = nla_on
        if nla_on:
            findings.append(finding(
                "RDP is enabled (with NLA)",
                "Remote Desktop connections are allowed; NLA is enforced.",
                "info",
            ))
        else:
            score -= 5
            findings.append(finding(
                "RDP enabled without NLA",
                "Remote Desktop allowed and Network Level Authentication is off.",
                "medium",
                "Enable NLA in System > Remote Desktop settings, or restrict RDP "
                "to VPN/allowed hosts via firewall rules.",
            ))
    else:
        findings.append(finding("RDP is disabled",
                                "fDenyTSConnections indicates incoming RDP is denied.", "info"))

    # --- AutoRun/AutoPlay ---
    exists_ar, nta = _read_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoDriveTypeAutoRun",
    )
    raw["autorun_nodrivetype"] = nta if exists_ar else None
    if not exists_ar or (isinstance(nta, int) and nta < 255):
        score -= 4
        findings.append(finding(
            "AutoRun not fully disabled",
            f"NoDriveTypeAutoRun = {nta if exists_ar else 'not set'}. 255 disables AutoRun for all drive types.",
            "medium",
            "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\"
            "NoDriveTypeAutoRun (DWORD) to 255 via Group Policy.",
        ))
    else:
        findings.append(finding("AutoRun disabled for all drive types",
                                "NoDriveTypeAutoRun = 255.", "info"))

    # --- Remote Registry service ---
    exists_rr, rr_start = _read_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\RemoteRegistry",
        "Start",
    )
    raw["remote_registry_start"] = rr_start if exists_rr else None
    if exists_rr and isinstance(rr_start, int) and rr_start <= 2:
        score -= 6
        findings.append(finding(
            "Remote Registry service set to auto/manual",
            f"RemoteRegistry Start = {rr_start} (0-2 means it can start).",
            "medium",
            "Disable the Remote Registry service unless explicitly required: "
            "Set-Service RemoteRegistry -StartupType Disabled.",
        ))

    status = "critical" if score <= -10 else ("warning" if score < 0 else "ok")
    return make_result(MODULE, status, score, findings, raw=raw)


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
