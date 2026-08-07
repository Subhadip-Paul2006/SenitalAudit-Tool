"""Phase 7 — Startup programs: Run/RunOnce registry keys + Startup folders."""

from __future__ import annotations

import json
import os
import winreg

from utils.config import get
from utils.module_base import finding, guarded, make_result

MODULE = "startup"

RUN_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run (32-bit)"),
]


def _read_run_key(hive, subkey: str, label: str) -> list[dict]:
    entries: list[dict] = []
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                entries.append({"name": name, "command": str(value), "location": label})
                i += 1
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return entries


def _startup_folder_entries() -> list[dict]:
    entries: list[dict] = []
    folders = [
        os.path.join(os.environ.get("APPDATA", ""),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.environ.get("PROGRAMDATA", ""),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    for folder in folders:
        try:
            for fn in os.listdir(folder):
                entries.append({"name": fn, "command": os.path.join(folder, fn),
                                "location": "Startup folder"})
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return entries


def _is_trusted_path(command: str) -> bool:
    trusted = [d.lower() for d in ((get("startup") or {}).get("trusted_dirs") or [])]
    cmd = command.lower().strip().strip('"')
    if any(t.lower() in cmd for t in trusted if t):
        return True
    # Common signed-user-profile locations (OneDrive, per-user app installs)
    user_profile = os.environ.get("USERPROFILE", "").lower()
    trusted_user = [
        os.path.join(user_profile, "appdata\\local\\microsoft\\onedrive"),
        os.path.join(user_profile, "appdata\\local\\programs"),
    ]
    return any(cmd.startswith(t) or t in cmd for t in trusted_user if user_profile)


@guarded(MODULE)
def run() -> dict:
    """Enumerate autostart entries and flag ones outside trusted directories."""
    entries: list[dict] = []
    for hive, subkey, label in RUN_KEYS:
        entries.extend(_read_run_key(hive, subkey, label))
    entries.extend(_startup_folder_entries())

    findings: list[dict] = []
    score = 0
    suspicious = []
    for e in entries:
        cmd = e["command"]
        if cmd and not _is_trusted_path(cmd):
            suspicious.append(e)

    for e in suspicious[:50]:  # cap output
        score -= 2
        findings.append(finding(
            f"Autostart outside trusted directories: {e['name']}",
            f"Location: {e['location']} — Command: {e['command'][:200]}",
            "low",
            "Verify this entry is intentionally installed software; unsigned or "
            "unknown autostart entries deserve review (this is not a malware verdict).",
        ))
    score = max(score, -10)  # module-level impact cap

    if not entries:
        findings.append(finding("No startup entries found",
                                "Run/RunOnce keys and Startup folders are empty.", "info"))
    elif not suspicious:
        findings.append(finding(
            f"{len(entries)} startup entries, all under trusted directories",
            "All autostart commands point into Program Files/Windows.", "info"))

    status = "warning" if suspicious else "ok"
    return make_result(MODULE, status, score, findings,
                       raw={"entries": entries, "suspicious_count": len(suspicious)})


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
