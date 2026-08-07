"""Phase 14 — Scoring engine: aggregate module impacts into an overall score."""

from __future__ import annotations

from typing import Any

from utils.config import get

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def compute(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Aggregate module results into a final score, band, and recommendations.

    Args:
        results: mapping of module name -> audit result dict (data contract).

    Returns:
        {
            "score": int (0-100),
            "band": "Excellent" | "Good" | "Fair" | "Poor",
            "module_scores": {name: weighted_impact},
            "recommendations": [ {severity, title, recommendation, module}, ... ]
        }
    """
    cfg = get("scoring") or {}
    base = int(cfg.get("base", 100))
    weights = cfg.get("weights") or {}
    bands = cfg.get("bands") or {"excellent": 90, "good": 75, "fair": 50}

    module_scores: dict[str, int] = {}
    total = base
    for name, res in results.items():
        if not isinstance(res, dict):
            continue
        raw_impact = int(res.get("score_impact", 0))
        weight = float(weights.get(name, 1.0))
        impact = int(round(raw_impact * weight))
        module_scores[name] = impact
        total += impact

    score = max(0, min(100, total))
    if score >= int(bands.get("excellent", 90)):
        band = "Excellent"
    elif score >= int(bands.get("good", 75)):
        band = "Good"
    elif score >= int(bands.get("fair", 50)):
        band = "Fair"
    else:
        band = "Poor"

    recommendations = collect_recommendations(results)
    return {
        "score": score,
        "band": band,
        "module_scores": module_scores,
        "recommendations": recommendations,
    }


def collect_recommendations(results: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    """Pull every finding with a recommendation, dedupe, sort by severity."""
    seen: set[tuple[str, str]] = set()
    recs: list[dict[str, str]] = []
    for module, res in results.items():
        if not isinstance(res, dict):
            continue
        for f in res.get("findings", []):
            rec = f.get("recommendation")
            if not rec:
                continue
            key = (f.get("title", ""), rec)
            if key in seen:
                continue
            seen.add(key)
            recs.append({
                "module": module,
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "recommendation": rec,
            })
    recs.sort(key=lambda r: _SEV_ORDER.get(r["severity"], 99))
    return recs


def severity_counts(results: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Count findings by severity across all modules."""
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for res in results.values():
        if not isinstance(res, dict):
            continue
        for f in res.get("findings", []):
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
    return counts
