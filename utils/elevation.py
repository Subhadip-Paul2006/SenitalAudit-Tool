"""Admin-rights detection and optional elevated relaunch (Windows only)."""

from __future__ import annotations

import ctypes
import logging
import sys

logger = logging.getLogger("sentinelaudit.elevation")


def is_admin() -> bool:
    """Return True if the current process has administrator privileges."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover
        logger.warning("Admin check failed: %s", exc)
        return False


def relaunch_elevated() -> bool:
    """Attempt to relaunch the current script with admin rights via ShellExecuteW.

    Returns True if the relaunch call was issued (caller should then exit).
    """
    if sys.platform != "win32":
        return False
    try:
        params = " ".join(f'"{a}"' for a in sys.argv)
        ret = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", sys.executable, params, None, 1
        )
        # ShellExecuteW returns >32 on success
        ok = int(ret) > 32
        if not ok:
            logger.error("ShellExecuteW runas failed (code %s)", ret)
        return ok
    except Exception as exc:  # pragma: no cover
        logger.error("Elevated relaunch failed: %s", exc)
        return False


def ensure_admin(interactive: bool = True) -> bool:
    """Check admin rights; offer to relaunch elevated if missing.

    Returns True if we are (or will become) elevated. When a relaunch is
    issued, callers should exit the current process immediately.
    """
    if is_admin():
        return True
    msg = (
        "SentinelAudit is NOT running with administrator privileges.\n"
        "Several checks (password policy, some registry keys, Defender status,\n"
        "security event log) require admin rights and will be skipped or degraded."
    )
    print(msg)
    if not interactive:
        return False
    answer = input("Relaunch elevated now? [y/N]: ").strip().lower()
    if answer == "y":
        if relaunch_elevated():
            sys.exit(0)
    return False
