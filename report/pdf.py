"""Phase 16a — PDF report generation via reportlab."""

from __future__ import annotations

import os
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from utils.config import get

_BAND_COLORS = {
    "Excellent": colors.HexColor("#1a7f37"),
    "Good": colors.HexColor("#0969da"),
    "Fair": colors.HexColor("#9a6700"),
    "Poor": colors.HexColor("#cf222e"),
}
_SEV_COLORS = {
    "high": colors.HexColor("#cf222e"),
    "medium": colors.HexColor("#9a6700"),
    "low": colors.HexColor("#0969da"),
    "info": colors.HexColor("#57606a"),
}


def generate(system_info: dict[str, Any],
             results: dict[str, dict[str, Any]],
             scoring: dict[str, Any],
             output_path: str | None = None) -> str:
    """Generate the PDF report and return the output path."""
    reports_cfg = get("reports") or {}
    out_dir = reports_cfg.get("output_dir", "reports")
    os.makedirs(out_dir, exist_ok=True)
    if output_path is None:
        output_path = os.path.join(out_dir, reports_cfg.get("pdf_name", "audit.pdf"))

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverTitle", fontSize=28, leading=34,
                              alignment=1, textColor=colors.HexColor("#1f2328")))
    styles.add(ParagraphStyle(name="CoverSub", fontSize=12, leading=16, alignment=1,
                              textColor=colors.HexColor("#57606a")))
    styles.add(ParagraphStyle(name="H2x", parent=styles["Heading2"],
                              textColor=colors.HexColor("#1f2328")))
    styles.add(ParagraphStyle(name="Small", fontSize=8, leading=10,
                              textColor=colors.HexColor("#57606a")))

    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title="SentinelAudit Security Report")
    story: list = []

    # ---- Cover ----
    score = scoring.get("score", 0)
    band = scoring.get("band", "?")
    band_color = _BAND_COLORS.get(band, colors.black)
    story.append(Spacer(1, 60 * mm))
    story.append(Paragraph("SentinelAudit", styles["CoverTitle"]))
    story.append(Paragraph("Windows Security Audit Report", styles["CoverSub"]))
    story.append(Spacer(1, 15 * mm))
    cover_data = [
        ["Hostname", system_info.get("hostname", "?")],
        ["OS", f"Windows {system_info.get('os_release', '?')} (build {system_info.get('os_version', '?')})"],
        ["Audited user", system_info.get("current_user", "?")],
        ["Local IP", system_info.get("local_ip", "?")],
        ["Audit time", system_info.get("timestamp", "?")],
    ]
    cover_tbl = Table(cover_data, colWidths=[45 * mm, 100 * mm])
    cover_tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#57606a")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(cover_tbl)
    story.append(Spacer(1, 15 * mm))
    score_style = ParagraphStyle("ScoreStyle", fontSize=24, alignment=1, textColor=band_color)
    story.append(Paragraph(f"Overall Score: {score}/100 - {band}", score_style))
    story.append(PageBreak())

    # ---- Summary ----
    story.append(Paragraph("Summary", styles["Heading1"]))
    mod_rows = [["Module", "Status", "Impact", "Findings"]]
    for name, res in results.items():
        mod_rows.append([
            name,
            str(res.get("status", "?")).upper(),
            f"{res.get('score_impact', 0):+d}",
            str(len(res.get("findings", []))),
        ])
    mod_tbl = Table(mod_rows, colWidths=[45 * mm, 35 * mm, 25 * mm, 25 * mm], repeatRows=1)
    mod_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2328")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d0d7de")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(mod_tbl)
    story.append(PageBreak())

    # ---- Per-module findings ----
    story.append(Paragraph("Detailed Findings", styles["Heading1"]))
    for name, res in results.items():
        story.append(Paragraph(f"{name} - {str(res.get('status', '')).upper()}",
                               styles["H2x"]))
        findings = res.get("findings", [])
        if not findings:
            story.append(Paragraph("No findings.", styles["Small"]))
        for f in findings:
            sev = str(f.get("severity", "info"))
            sev_color = _SEV_COLORS.get(sev, colors.black)
            title_p = Paragraph(
                f'<font color="{sev_color.hexval()}">[{sev.upper()}]</font> '
                f"<b>{_esc(f.get('title', ''))}</b>", styles["Normal"])
            story.append(title_p)
            story.append(Paragraph(_esc(f.get("detail", "")), styles["Small"]))
            if f.get("recommendation"):
                story.append(Paragraph(
                    f"<i>Recommendation:</i> {_esc(f['recommendation'])}", styles["Small"]))
            story.append(Spacer(1, 3 * mm))
    story.append(PageBreak())

    # ---- Recommendations ----
    story.append(Paragraph("Prioritized Recommendations", styles["Heading1"]))
    recs = scoring.get("recommendations", [])
    if not recs:
        story.append(Paragraph("No outstanding recommendations.", styles["Normal"]))
    for i, r in enumerate(recs, 1):
        sev_color = _SEV_COLORS.get(r.get("severity", "info"), colors.black)
        story.append(Paragraph(
            f'{i}. <font color="{sev_color.hexval()}">[{r["severity"].upper()}]</font> '
            f"<b>{_esc(r['title'])}</b> ({_esc(r['module'])})", styles["Normal"]))
        story.append(Paragraph(_esc(r["recommendation"]), styles["Small"]))
        story.append(Spacer(1, 2 * mm))

    doc.build(story)
    return output_path


def _esc(text: Any) -> str:
    """Escape text for reportlab Paragraph markup."""
    s = str(text)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
