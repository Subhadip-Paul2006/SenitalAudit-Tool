"""Phase 6 — Password/lockout policy audit via 'net accounts'."""

from __future__ import annotations

import json
import re
import subprocess

from utils.config import get
from utils.module_base import finding, guarded, make_result

MODULE = "password_policy"


def _parse_net_accounts(output: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in output.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            data[key.strip()] = val.strip()
    return data


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    if value.upper() == "UNLIMITED":
        return None
    m = re.search(r"-?\d+", value)
    return int(m.group(0)) if m else None


@guarded(MODULE)
def run() -> dict:
    """Parse 'net accounts' and evaluate min length, age and lockout settings."""
    proc = subprocess.run(
        ["net", "accounts"], capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        raise RuntimeError(f"net accounts failed: {proc.stderr.strip()[:200]}")

    raw = _parse_net_accounts(proc.stdout)
    cfg = get("password_policy") or {}
    min_len_threshold = int(cfg.get("min_length_threshold", 8))
    max_age_threshold = int(cfg.get("max_age_days_threshold", 90))

    min_len = _to_int(raw.get("Minimum password length"))
    max_age = _to_int(raw.get("Maximum password age (days)"))
    min_age = _to_int(raw.get("Minimum password age (days)"))
    history = _to_int(raw.get("Length of password history maintained"))
    lockout_threshold = _to_int(raw.get("Lockout threshold"))
    lockout_duration = _to_int(raw.get("Lockout duration (minutes)"))
    lockout_window = _to_int(raw.get("Lockout observation window (minutes)"))

    findings: list[dict] = []
    score = 0

    if min_len is None or min_len < min_len_threshold:
        score -= 8
        findings.append(finding(
            f"Minimum password length is {min_len}",
            f"Policy requires at least {min_len} characters; recommended >= {min_len_threshold}.",
            "high",
            f"Set minimum length to {min_len_threshold}+: net accounts /minpwlen:{min_len_threshold}",
        ))
    if lockout_threshold in (None, 0):
        score -= 5
        findings.append(finding(
            "No account lockout policy",
            "Lockout threshold is 'Never'/0 — unlimited password guesses are allowed.",
            "medium",
            "Set a lockout threshold, e.g.: net accounts /lockoutthreshold:5",
        ))
    if max_age is None:
        score -= 3
        findings.append(finding(
            "Passwords never expire",
            "Maximum password age is UNLIMITED.",
            "low",
            f"Set a maximum password age <= {max_age_threshold} days.",
        ))
    elif max_age > max_age_threshold:
        score -= 2
        findings.append(finding(
            f"Password max age is {max_age} days",
            f"Exceeds recommended maximum of {max_age_threshold} days.",
            "low",
            f"Reduce maximum password age: net accounts /maxpwage:{max_age_threshold}",
        ))
    if history is not None and history == 0:
        score -= 2
        findings.append(finding(
            "No password history enforced",
            "Users can reuse previous passwords immediately.",
            "low",
            "Remember at least 5 passwords: net accounts /uniquepw:5",
        ))

    if not findings:
        findings.append(finding(
            "Password policy meets baseline",
            f"min length {min_len}, max age {max_age}d, lockout after {lockout_threshold} attempts.",
            "info",
        ))

    status = "warning" if score < 0 and score > -8 else ("critical" if score <= -8 else "ok")
    return make_result(MODULE, status, score, findings, raw={
        "min_password_length": min_len,
        "max_password_age_days": max_age,
        "min_password_age_days": min_age,
        "password_history": history,
        "lockout_threshold": lockout_threshold,
        "lockout_duration_minutes": lockout_duration,
        "lockout_window_minutes": lockout_window,
    })


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, default=str))
