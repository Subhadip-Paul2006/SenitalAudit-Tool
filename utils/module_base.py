"""Shared helpers for audit modules: consistent result envelope and error wrapping."""

from __future__ import annotations

import functools
import logging
import traceback
from typing import Any, Callable

logger = logging.getLogger("sentinelaudit.audit")


def make_result(
    module: str,
    status: str = "ok",
    score_impact: int = 0,
    findings: list[dict[str, Any]] | None = None,
    raw: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a standard audit-module result dict (the data contract)."""
    return {
        "module": module,
        "status": status,
        "score_impact": int(score_impact),
        "findings": findings or [],
        "raw": raw or {},
    }


def finding(
    title: str,
    detail: str,
    severity: str = "info",
    recommendation: str | None = None,
) -> dict[str, Any]:
    """Build a standard finding entry."""
    return {
        "title": title,
        "detail": detail,
        "severity": severity,
        "recommendation": recommendation,
    }


def error_result(module: str, exc: BaseException) -> dict[str, Any]:
    """Build an error-status result from an exception."""
    return make_result(
        module=module,
        status="error",
        score_impact=0,
        findings=[
            finding(
                title=f"{module} check failed",
                detail=f"{type(exc).__name__}: {exc}",
                severity="info",
                recommendation="Check logs for details; verify required privileges/dependencies.",
            )
        ],
        raw={"traceback": traceback.format_exc()},
    )


def guarded(module_name: str) -> Callable[[Callable[[], dict[str, Any]]], Callable[[], dict[str, Any]]]:
    """Decorator: wraps an audit module's run() so exceptions degrade gracefully."""

    def decorator(func: Callable[[], dict[str, Any]]) -> Callable[[], dict[str, Any]]:
        @functools.wraps(func)
        def wrapper() -> dict[str, Any]:
            try:
                result = func()
                result.setdefault("module", module_name)
                return result
            except Exception as exc:  # noqa: BLE001
                logger.exception("Module '%s' failed", module_name)
                return error_result(module_name, exc)

        return wrapper

    return decorator


def worst_status(statuses: list[str]) -> str:
    """Return the most severe status from a list."""
    order = ["ok", "info", "warning", "critical", "error"]
    if not statuses:
        return "ok"
    return max(statuses, key=lambda s: order.index(s) if s in order else 0)
