"""Configuration loader for SentinelAudit."""

from __future__ import annotations

import os
from typing import Any

import yaml

_CONFIG_CACHE: dict[str, Any] | None = None


def load_config(path: str = "config.yaml") -> dict[str, Any]:
    """Load and cache the YAML configuration file."""
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE
    if not os.path.exists(path):
        _CONFIG_CACHE = {}
        return _CONFIG_CACHE
    with open(path, "r", encoding="utf-8") as fh:
        _CONFIG_CACHE = yaml.safe_load(fh) or {}
    return _CONFIG_CACHE


def get(key: str, default: Any = None) -> Any:
    """Get a top-level config value."""
    return load_config().get(key, default)
