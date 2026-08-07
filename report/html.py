"""Phase 16b — Self-contained HTML report (inline CSS, single file)."""

from __future__ import annotations

import html as _html
import json
import os
from typing import Any

from utils.config import get


def generate(system_info: dict[str, Any],
             results: dict[str, dict[str, Any]],
             scoring: dict[str, Any],
             output_path: str | None = None) -> str:
    """Generate a self-contained HTML report and return the path."""
    reports_cfg = get("reports") or {}
    out_dir = reports_cfg.get("output_dir", "reports")
    os.makedirs(out_dir, exist_ok=True)
    if output_path is None:
        output_path = os.path.join(out_dir, reports_cfg.get("html_name", "audit.html"))

    score = scoring.get("score", 0)
    band = scoring.get("band", "?")
    band_class = {"Excellent": "good", "Good": "good", "Fair": "fair", "Poor": "poor"}.get(band, "fair")

    modules_html = []
    for name, res in results.items():
        status = str(res.get("status", "ok"))
        findings_rows = []
        for f in res.get("findings", []):
            sev = str(f.get("severity", "info"))
            rec = f"<div class='rec'>Recommendation: {e(f['recommendation'])}</div>" if f.get("recommendation") else ""
            findings_rows.append(
                f"<tr class='sev-{sev}'><td class='sev'>{sev.upper()}</td>"
                f"<td><b>{e(f.get('title',''))}</b><br><span class='detail'>{e(f.get('detail',''))}</span>{rec}</td></tr>"
            )
        findings_tbl = (
            "<table class='findings'><thead><tr><th style='width:90px'>Severity</th>"
            "<th>Finding</th></tr></thead><tbody>" + "".join(findings_rows) + "</tbody></table>"
            if findings_rows else "<p class='detail'>No findings.</p>"
        )
        modules_html.append(
            f"<section class='module'><h2>{e(name)} "
            f"<span class='badge status-{status}'>{status.upper()}</span></h2>{findings_tbl}</section>"
        )

    summary_rows = "".join(
        f"<tr><td>{e(n)}</td><td><span class='badge status-{r.get('status','ok')}'>{str(r.get('status','?')).upper()}</span></td>"
        f"<td>{r.get('score_impact', 0):+d}</td><td>{len(r.get('findings', []))}</td></tr>"
        for n, r in results.items()
    )

    recs = scoring.get("recommendations", [])
    recs_html = "".join(
        f"<li class='sev-{r['severity']}'><span class='sev-tag'>{r['severity'].upper()}</span> "
        f"<b>[{e(r['module'])}]</b> {e(r['title'])} — {e(r['recommendation'])}</li>"
        for r in recs
    ) or "<li>No outstanding recommendations.</li>"

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentinelAudit Report — {e(system_info.get('hostname',''))}</title>
<style>
  :root {{ --fg:#1f2328; --muted:#57606a; --border:#d0d7de; }}
  * {{ box-sizing:border-box; }}
  body {{ font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         color:var(--fg); max-width:1000px; margin:0 auto; padding:32px 20px; background:#f6f8fa; }}
  header {{ background:#fff; border:1px solid var(--border); border-radius:10px; padding:24px; }}
  h1 {{ margin:0 0 4px; font-size:26px; }}
  .meta {{ color:var(--muted); font-size:14px; }}
  .score {{ font-size:42px; font-weight:700; margin:12px 0 0; }}
  .score.good {{ color:#1a7f37; }} .score.fair {{ color:#9a6700; }} .score.poor {{ color:#cf222e; }}
  section.module {{ background:#fff; border:1px solid var(--border); border-radius:10px;
                    padding:18px 22px; margin-top:18px; }}
  h2 {{ margin:0 0 12px; font-size:19px; text-transform:capitalize; }}
  table {{ border-collapse:collapse; width:100%; font-size:14px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); vertical-align:top; }}
  th {{ background:#f6f8fa; }}
  .badge {{ font-size:11px; padding:3px 9px; border-radius:12px; font-weight:700; }}
  .status-ok {{ background:#dafbe1; color:#1a7f37; }}
  .status-warning {{ background:#fff8c5; color:#9a6700; }}
  .status-critical {{ background:#ffebe9; color:#cf222e; }}
  .status-error {{ background:#fbefff; color:#8250df; }}
  .detail {{ color:var(--muted); font-size:13px; }}
  .rec {{ color:#0550ae; font-size:13px; margin-top:4px; }}
  .sev {{ font-size:11px; font-weight:700; }}
  .sev-high .sev {{ color:#cf222e; }} .sev-medium .sev {{ color:#9a6700; }}
  .sev-low .sev {{ color:#0969da; }} .sev-info .sev {{ color:#57606a; }}
  .sev-tag {{ font-size:10px; font-weight:800; padding:1px 6px; border:1px solid var(--border); border-radius:4px; }}
  ul {{ line-height:1.7; }}
  footer {{ color:var(--muted); font-size:12px; margin-top:28px; text-align:center; }}
</style>
</head>
<body>
<header>
  <h1>SentinelAudit — Windows Security Audit</h1>
  <div class="meta">
    Host <b>{e(system_info.get('hostname','?'))}</b> ·
    Windows {e(system_info.get('os_release','?'))} (build {e(system_info.get('os_version','?'))}) ·
    User {e(system_info.get('current_user','?'))} · IP {e(system_info.get('local_ip','?'))}<br>
    Audit time: {e(system_info.get('timestamp','?'))}
  </div>
  <div class="score {band_class}">{score}/100 — {e(band)}</div>
</header>

<section class="module">
  <h2>Module Summary</h2>
  <table><thead><tr><th>Module</th><th>Status</th><th>Impact</th><th>Findings</th></tr></thead>
  <tbody>{summary_rows}</tbody></table>
</section>

{''.join(modules_html)}

<section class="module">
  <h2>Prioritized Recommendations</h2>
  <ul>{recs_html}</ul>
</section>

<footer>Generated by SentinelAudit — defensive, read-only configuration audit.</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    return output_path


def write_json_report(system_info: dict[str, Any],
                      results: dict[str, dict[str, Any]],
                      scoring: dict[str, Any],
                      output_path: str | None = None) -> str:
    """Write the full machine-readable JSON export."""
    reports_cfg = get("reports") or {}
    out_dir = reports_cfg.get("output_dir", "reports")
    os.makedirs(out_dir, exist_ok=True)
    if output_path is None:
        output_path = os.path.join(out_dir, reports_cfg.get("json_name", "audit.json"))
    payload = {
        "system_info": system_info,
        "scoring": scoring,
        "results": results,
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return output_path


def e(text: Any) -> str:
    return _html.escape(str(text))
