"""Collect general system information (platform, hardware, network)."""

from __future__ import annotations

import getpass
import logging
import platform
import socket
from datetime import datetime
from typing import Any

logger = logging.getLogger("sentinelaudit.system_info")

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]


def _local_ip() -> str:
    """Best-effort primary LAN IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return "127.0.0.1"


def collect() -> dict[str, Any]:
    """Gather Windows version/build, hostname, arch, RAM, CPU, disk, boot time, user, IP."""
    info: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "windows_edition": platform.win32_edition() if hasattr(platform, "win32_edition") else "",
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "current_user": getpass.getuser(),
        "local_ip": _local_ip(),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }
    if psutil is not None:
        try:
            vm = psutil.virtual_memory()
            info["ram_total_gb"] = round(vm.total / (1024**3), 2)
            info["ram_used_pct"] = vm.percent
            info["cpu_count_logical"] = psutil.cpu_count(logical=True)
            info["cpu_count_physical"] = psutil.cpu_count(logical=False)
            info["cpu_percent"] = psutil.cpu_percent(interval=0.2)
            boot = datetime.fromtimestamp(psutil.boot_time())
            info["boot_time"] = boot.isoformat(timespec="seconds")
            disks = []
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append(
                        {
                            "device": part.device,
                            "mountpoint": part.mountpoint,
                            "fstype": part.fstype,
                            "total_gb": round(usage.total / (1024**3), 2),
                            "used_pct": usage.percent,
                        }
                    )
                except (PermissionError, OSError):
                    continue
            info["disks"] = disks
        except Exception as exc:  # pragma: no cover
            logger.warning("psutil collection partial failure: %s", exc)
    return info


if __name__ == "__main__":
    import json

    print(json.dumps(collect(), indent=2))
