"""Phase 9 — USB storage device history from USBSTOR registry."""

from __future__ import annotations

import json
import winreg
from datetime import datetime

from utils.config import get
from utils.module_base import finding, guarded, make_result

MODULE = "usb"

USBSTOR = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"


def _filetime_to_dt(ft: int) -> datetime:
    return datetime.fromtimestamp((ft - 116444736000000000) / 10_000_000)


@guarded(MODULE)
def run() -> dict:
    """Read historical USB mass-storage devices from the registry."""
    devices: list[dict] = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, USBSTOR, 0, winreg.KEY_READ) as root:
            i = 0
            while True:
                try:
                    dev_class = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                friendly = dev_class.replace("&", " ")
                try:
                    with winreg.OpenKey(root, dev_class, 0, winreg.KEY_READ) as dev_key:
                        j = 0
                        while True:
                            try:
                                serial = winreg.EnumKey(dev_key, j)
                            except OSError:
                                break
                            j += 1
                            entry: dict = {"device": friendly, "serial": serial}
                            try:
                                with winreg.OpenKey(dev_key, serial, 0, winreg.KEY_READ) as sk:
                                    ts = winreg.QueryInfoKey(sk)[2]
                                    entry["last_write"] = _filetime_to_dt(ts).isoformat(timespec="seconds")
                                    try:
                                        fname, _ = winreg.QueryValueEx(sk, "FriendlyName")
                                        entry["friendly_name"] = str(fname)
                                    except (FileNotFoundError, OSError):
                                        pass
                            except (PermissionError, OSError):
                                entry["last_write"] = None
                            devices.append(entry)
                except (PermissionError, OSError):
                    continue
    except (FileNotFoundError, PermissionError, OSError) as exc:
        findings = [finding(
            "USB storage history unavailable",
            f"Could not read {USBSTOR}: {exc}. Run as administrator.",
            "info",
        )]
        return make_result(MODULE, "ok", 0, findings, raw={"devices": []})

    findings = [finding(
        f"{len(devices)} historical USB storage device(s) recorded",
        "Informational: device IDs and last-write times from USBSTOR.",
        "info",
    )]
    flag = bool((get("usb") or {}).get("flag_mass_storage", False))
    if flag and devices:
        findings.append(finding(
            "USB mass-storage devices have been connected (policy flag enabled)",
            f"{len(devices)} device record(s) — see raw data.",
            "low",
            "Review per organizational removable-media policy.",
        ))

    return make_result(MODULE, "ok", 0, findings, raw={"devices": devices})


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
