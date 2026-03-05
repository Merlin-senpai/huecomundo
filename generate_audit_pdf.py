#!/usr/bin/env python3
"""
generate_audit_pdf.py
Reads audit.json (npm audit --json output) and produces a styled PDF report.
Usage: python generate_audit_pdf.py [audit.json] [output.pdf]
"""

import json
import sys
import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)

# ── Colour palette ────────────────────────────────────────────────────────────
C_BG_DARK   = colors.HexColor("#0f172a")   # header background
C_ACCENT    = colors.HexColor("#6366f1")   # indigo accent
C_CRITICAL  = colors.HexColor("#ef4444")
C_HIGH      = colors.HexColor("#f97316")
C_MODERATE  = colors.HexColor("#eab308")
C_LOW       = colors.HexColor("#3b82f6")
C_INFO      = colors.HexColor("#8b5cf6")
C_SUCCESS   = colors.HexColor("#22c55e")
C_TEXT      = colors.HexColor("#1e293b")
C_MUTED     = colors.HexColor("#64748b")
C_ROW_ALT   = colors.HexColor("#f8fafc")
C_ROW_HEAD  = colors.HexColor("#e2e8f0")
C_WHITE     = colors.white

SEV_COLORS = {
    "critical": C_CRITICAL,
    "high":     C_HIGH,
    "moderate": C_MODERATE,
    "low":      C_LOW,
    "info":     C_INFO,
}

SEV_ORDER = ["critical", "high", "moderate", "low", "info"]


# ── Style helpers ─────────────────────────────────────────────────────────────
def build_styles():
    base = getSampleStyleSheet()
    custom = {}

    custom["cover_title"] = ParagraphStyle(
        "cover_title", fontSize=26, textColor=C_WHITE,
        fontName="Helvetica-Bold", alignment=TA_CENTER, leading=32
    )
    custom["cover_sub"] = ParagraphStyle(
        "cover_sub", fontSize=11, textColor=colors.HexColor("#cbd5e1"),
        fontName="Helvetica", alignment=TA_CENTER, leading=16
    )
    custom["section_head"] = ParagraphStyle(
        "section_head", fontSize=13, textColor=C_BG_DARK,
        fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6, leading=18
    )
    custom["body"] = ParagraphStyle(
        "body", fontSize=9, textColor=C_TEXT,
        fontName="Helvetica", leading=14
    )
    custom["muted"] = ParagraphStyle(
        "muted", fontSize=8, textColor=C_MUTED,
        fontName="Helvetica", leading=12
    )
    custom["tag"] = ParagraphStyle(
        "tag", fontSize=8, textColor=C_WHITE,
        fontName="Helvetica-Bold", alignment=TA_CENTER
    )
    custom["vuln_name"] = ParagraphStyle(
        "vuln_name", fontSize=9, textColor=C_TEXT,
        fontName="Helvetica-Bold", leading=13
    )
    custom["vuln_desc"] = ParagraphStyle(
        "vuln_desc", fontSize=8, textColor=C_MUTED,
        fontName="Helvetica", leading=12
    )
    return custom


def sev_badge(sev, styles):
    """Small coloured severity pill."""
    col = SEV_COLORS.get(sev.lower(), C_MUTED)
    label = sev.upper()
    cell = Paragraph(f'<font color="white"><b>{label}</b></font>', styles["tag"])
    t = Table([[cell]], colWidths=[18*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), col),
        ("ROUNDEDCORNERS", [3]),
        ("TOPPADDING",  (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


# ── Cover block ───────────────────────────────────────────────────────────────
def cover_block(story, meta, styles):
    repo   = meta.get("repo", "huecomundo")
    branch = meta.get("branch", "main")
    commit = meta.get("commit", "")[:7]
    ts     = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Dark header table
    header_content = [
        [Paragraph("🛡  Security Audit Report", styles["cover_title"])],
        [Paragraph(f"Repository: <b>{repo}</b>  ·  Branch: <b>{branch}</b>  ·  Commit: <b>{commit}</b>", styles["cover_sub"])],
        [Paragraph(f"Generated: {ts}", styles["cover_sub"])],
    ]
    header_table = Table(header_content, colWidths=[170*mm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_BG_DARK),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_BG_DARK]),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 8*mm))


# ── Summary scorecard ─────────────────────────────────────────────────────────
def summary_scorecard(story, totals, pkg_count, styles):
    story.append(Paragraph("Executive Summary", styles["section_head"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=6))

    total_vulns = sum(totals.get(s, 0) for s in SEV_ORDER)
    overall_color = (
        C_CRITICAL if totals.get("critical", 0) > 0 else
        C_HIGH     if totals.get("high", 0) > 0 else
        C_MODERATE if totals.get("moderate", 0) > 0 else
        C_LOW      if totals.get("low", 0) > 0 else
        C_SUCCESS
    )
    overall_label = (
        "CRITICAL RISK" if totals.get("critical", 0) > 0 else
        "HIGH RISK"     if totals.get("high", 0) > 0 else
        "MODERATE RISK" if totals.get("moderate", 0) > 0 else
        "LOW RISK"      if totals.get("low", 0) > 0 else
        "CLEAN"
    )

    # Overall status pill
    status_cell = Paragraph(f'<font color="white"><b>{overall_label}</b></font>', ParagraphStyle(
        "ol", fontSize=11, textColor=C_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER
    ))
    status_t = Table([[status_cell]], colWidths=[50*mm])
    status_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), overall_color),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    # Stats row
    stat_data = [[
        Paragraph(f'<b>{pkg_count}</b><br/><font color="#64748b" size="8">Packages Audited</font>', styles["body"]),
        Paragraph(f'<b>{total_vulns}</b><br/><font color="#64748b" size="8">Total Issues</font>', styles["body"]),
        Paragraph(f'<font color="#ef4444"><b>{totals.get("critical",0)}</b></font><br/><font color="#64748b" size="8">Critical</font>', styles["body"]),
        Paragraph(f'<font color="#f97316"><b>{totals.get("high",0)}</b></font><br/><font color="#64748b" size="8">High</font>', styles["body"]),
        Paragraph(f'<font color="#eab308"><b>{totals.get("moderate",0)}</b></font><br/><font color="#64748b" size="8">Moderate</font>', styles["body"]),
        Paragraph(f'<font color="#3b82f6"><b>{totals.get("low",0)}</b></font><br/><font color="#64748b" size="8">Low</font>', styles["body"]),
    ]]
    stat_table = Table(stat_data, colWidths=[28*mm]*6)
    stat_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_ROW_ALT),
        ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))

    story.append(KeepTogether([stat_table]))
    story.append(Spacer(1, 4*mm))


# ── Vulnerability detail table ────────────────────────────────────────────────
def vuln_table(story, vulnerabilities, styles):
    if not vulnerabilities:
        story.append(Paragraph("✅  No vulnerabilities found.", styles["body"]))
        return

    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("Vulnerability Details", styles["section_head"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=6))

    # Sort by severity
    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
    sorted_vulns = sorted(
        vulnerabilities.items(),
        key=lambda x: sev_rank.get((x[1].get("severity") or "info").lower(), 99)
    )

    # Table header
    header = [
        Paragraph("<b>Severity</b>", styles["body"]),
        Paragraph("<b>Package</b>", styles["body"]),
        Paragraph("<b>Issue / Advisory</b>", styles["body"]),
        Paragraph("<b>Fix Available</b>", styles["body"]),
    ]
    rows = [header]

    for pkg_name, vuln in sorted_vulns:
        sev = (vuln.get("severity") or "info").lower()
        col = SEV_COLORS.get(sev, C_MUTED)

        # Extract advisory titles from `via`
        via = vuln.get("via", [])
        advisories = []
        for v in via:
            if isinstance(v, dict):
                title = v.get("title") or v.get("url") or ""
                cve   = v.get("cve", "")
                url   = v.get("url", "")
                line  = title
                if cve:
                    line += f" ({cve})"
                advisories.append(line)
            elif isinstance(v, str):
                advisories.append(v)
        advisory_text = "\n".join(advisories) if advisories else "See npm advisory"

        fix_available = "Yes" if vuln.get("fixAvailable") else "No"
        fix_color = C_SUCCESS if fix_available == "Yes" else C_CRITICAL

        sev_cell  = Paragraph(f'<font color="white"><b>{sev.upper()}</b></font>', styles["tag"])
        sev_inner = Table([[sev_cell]], colWidths=[16*mm])
        sev_inner.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), col),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))

        rows.append([
            sev_inner,
            Paragraph(f"<b>{pkg_name}</b>", styles["vuln_name"]),
            Paragraph(advisory_text.replace("\n", "<br/>"), styles["vuln_desc"]),
            Paragraph(f'<font color="{fix_color.hexval()}"><b>{fix_available}</b></font>', styles["body"]),
        ])

    col_widths = [20*mm, 35*mm, 90*mm, 22*mm]
    t = Table(rows, colWidths=col_widths, repeatRows=1)

    row_styles = [
        ("BACKGROUND",    (0, 0), (-1, 0),  C_ROW_HEAD),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
    ]
    t.setStyle(TableStyle(row_styles))
    story.append(t)


# ── Footer ────────────────────────────────────────────────────────────────────
def footer_note(story, styles):
    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_MUTED))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        "Generated by n8n CI/CD Monitor  ·  Data source: npm audit --json  ·  "
        "Fix vulnerabilities with <b>npm audit fix</b> or upgrade affected packages.",
        styles["muted"]
    ))


# ── Main ──────────────────────────────────────────────────────────────────────
def generate(audit_path: str, output_path: str, meta: dict = None):
    with open(audit_path) as f:
        data = json.load(f)

    meta = meta or {}
    styles = build_styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=14*mm,  bottomMargin=18*mm,
        title="Security Audit Report",
        author="n8n CI/CD Monitor",
    )

    story = []

    # Metadata
    audit_meta  = data.get("metadata", {})
    totals      = audit_meta.get("vulnerabilities", {})
    pkg_count   = audit_meta.get("totalDependencies", 0)
    vulns       = data.get("vulnerabilities", {})

    cover_block(story, meta, styles)
    summary_scorecard(story, totals, pkg_count, styles)
    vuln_table(story, vulns, styles)
    footer_note(story, styles)

    doc.build(story)
    print(f"PDF written to {output_path}")


if __name__ == "__main__":
    audit_in = sys.argv[1] if len(sys.argv) > 1 else "audit.json"
    pdf_out  = sys.argv[2] if len(sys.argv) > 2 else "audit_report.pdf"

    # Optional meta from env (set by GitHub Actions)
    meta = {
        "repo":   os.environ.get("REPO_NAME", "huecomundo"),
        "branch": os.environ.get("BRANCH_NAME", "main"),
        "commit": os.environ.get("COMMIT_SHA", ""),
    }
    generate(audit_in, pdf_out, meta)
