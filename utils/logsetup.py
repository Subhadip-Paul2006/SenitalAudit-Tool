"""Central logging setup: file + console handlers."""

from __future__ import annotations

import logging
import os

from utils.config import get

_configured = False


def setup_logging() -> logging.Logger:
    """Configure root logger with file and console handlers (idempotent)."""
    global _configured
    if _configured:
        return logging.getLogger("sentinelaudit")

    log_cfg = get("logging", {}) or {}
    log_dir = log_cfg.get("dir", "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, log_cfg.get("file", "sentinelaudit.log"))
    level = getattr(logging, str(log_cfg.get("level", "INFO")).upper(), logging.INFO)

    logger = logging.getLogger("sentinelaudit")
    logger.setLevel(level)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    ch.setLevel(logging.WARNING)  # keep console quiet; CLI layer handles display
    logger.addHandler(ch)

    _configured = True
    return logger
