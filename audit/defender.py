"""Phase 2 — Windows Defender status via Get-MpComputerStatus."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta

from utils.config import get
from utils.module_base import finding, guarded, make_result

MODULE = "defender"


@guarded(MODULE)
def run() -> dict:
    """Query Defender status and evaluate RTP, signature age, tamper protection."""
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-Command", "Get-MpComputerStatus | ConvertTo-Json"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"Get-MpComputerStatus failed: {proc.stderr.strip()[:300]}")

    data = json.loads(proc.stdout)

    rtp = bool(data.get("RealTimeProtectionEnabled"))
    av_enabled = bool(data.get("AntivirusEnabled"))
    tamper = data.get("IsTamperProtected")
    engine = data.get("AMEngineVersion", "unknown")
    sig_ver = data.get("AntivirusSignatureVersion", "unknown")
    sig_update_raw = data.get("AntivirusSignatureLastUpdated")
    full_scan_age_days = data.get("FullScanAge")

    sig_age_days: int | None = None
    sig_update_iso: str | None = None
    if sig_update_raw:
        try:
            # PowerShell JSON dates: "/Date(169...)/" or ISO depending on version
            raw_s = str(sig_update_raw)
            if raw_s.startswith("/Date("):
                ms = int(raw_s[6:-2].split("+")[0].split("-")[0])
                dt = datetime.fromtimestamp(ms / 1000)
            else:
                dt = datetime.fromisoformat(raw_s.replace("Z", "+00:00")).replace(tzinfo=None)
            sig_age_days = (datetime.now() - dt).days
            sig_update_iso = dt.isoformat(timespec="seconds")
        except (ValueError, OSError, OverflowError):
            pass

    findings: list[dict] = []
    score = 0

    if not av_enabled:
        score -= 20
        findings.append(finding(
            "Defender antivirus is disabled",
            "Windows Defender AntivirusEnabled is False.",
            "high",
            "Re-enable Microsoft Defender Antivirus via Windows Security settings.",
        ))
    if not rtp:
        score -= 15
        findings.append(finding(
            "Real-time protection is disabled",
            "Defender RealTimeProtectionEnabled is False.",
            "high",
            "Enable real-time protection in Windows Security > Virus & threat protection.",
        ))
    if tamper is False:
        score -= 10
        findings.append(finding(
            "Tamper Protection is disabled",
            "Defender IsTamperProtected is False.",
            "medium",
            "Enable Tamper Protection in Windows Security to prevent settings being changed by malware.",
        ))

    warn_days = int((get("defender") or {}).get("signature_age_warning_days", 7))
    if sig_age_days is not None and sig_age_days > warn_days:
        score -= 5
        findings.append(finding(
            f"Antivirus signatures are {sig_age_days} days old",
            f"Last signature update: {sig_update_iso}; threshold is {warn_days} days.",
            "medium",
            "Update Defender signatures: Update-MpSignature, or run Windows Update.",
        ))

    if isinstance(full_scan_age_days, int) and full_scan_age_days > 30:
        score -= 2
        findings.append(finding(
            f"Last full scan was {full_scan_age_days} days ago",
            "No full antivirus scan in over 30 days.",
            "low",
            "Run a full scan from Windows Security.",
        ))

    if not findings:
        findings.append(finding(
            "Defender healthy",
            f"RTP on, signatures updated {sig_update_iso}, engine {engine}.",
            "info",
        ))

    status = "critical" if (not av_enabled or not rtp) else ("warning" if score < 0 else "ok")
    return make_result(MODULE, status, score, findings, raw={
        "antivirus_enabled": av_enabled,
        "real_time_protection": rtp,
        "tamper_protected": tamper,
        "engine_version": engine,
        "signature_version": sig_ver,
        "signature_last_updated": sig_update_iso,
        "signature_age_days": sig_age_days,
        "full_scan_age_days": full_scan_age_days,
    })


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
