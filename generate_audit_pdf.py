#!/usr/bin/env python3
"""
generate_audit_pdf.py — Universal DevSecOps PDF Report Generator
Supports: npm audit (Node.js), pip-audit (Python), composer audit (PHP), OWASP DC (Java)
Usage: python generate_audit_pdf.py audit.json semgrep.json snyk-code.json output.pdf
Stack auto-detected or set STACK env var: nodejs | python | php | java
"""

import json, sys, os
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, PageBreak
)

# ── Palette ───────────────────────────────────────────────────────────────────
DARK    = colors.HexColor("#0f172a")
ACCENT  = colors.HexColor("#6366f1")
C_CRIT  = colors.HexColor("#ef4444")
C_HIGH  = colors.HexColor("#f97316")
C_MOD   = colors.HexColor("#eab308")
C_LOW   = colors.HexColor("#3b82f6")
C_INFO  = colors.HexColor("#8b5cf6")
C_OK    = colors.HexColor("#22c55e")
C_TEXT  = colors.HexColor("#1e293b")
C_MUTED = colors.HexColor("#64748b")
C_ROW   = colors.HexColor("#f8fafc")
C_HEAD  = colors.HexColor("#e2e8f0")
WHITE   = colors.white

SEV_COLOR = {"critical": C_CRIT, "high": C_HIGH, "moderate": C_MOD,
             "medium": C_MOD, "low": C_LOW, "info": C_INFO, "warning": C_MOD,
             "error": C_HIGH}
SEV_ORDER = ["critical", "high", "medium", "moderate", "low", "info", "warning", "error"]


def S():
    return {
        "h_title": ParagraphStyle("h_title", fontSize=20, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER, leading=26),
        "h_sub":   ParagraphStyle("h_sub", fontSize=9, textColor=colors.HexColor("#cbd5e1"),
            fontName="Helvetica", alignment=TA_CENTER, leading=14),
        "sec":     ParagraphStyle("sec", fontSize=11, textColor=DARK,
            fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4),
        "body":    ParagraphStyle("body", fontSize=8, textColor=C_TEXT,
            fontName="Helvetica", leading=12),
        "muted":   ParagraphStyle("muted", fontSize=7, textColor=C_MUTED,
            fontName="Helvetica", leading=11),
        "badge":   ParagraphStyle("badge", fontSize=7, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER),
        "pkg":     ParagraphStyle("pkg", fontSize=8, textColor=DARK,
            fontName="Helvetica-Bold", leading=12),
        "code":    ParagraphStyle("code", fontSize=7, textColor=colors.HexColor("#1e40af"),
            fontName="Courier", leading=11),
        "desc":    ParagraphStyle("desc", fontSize=8, textColor=C_MUTED,
            fontName="Helvetica", leading=12),
    }


def badge_cell(sev, styles):
    col = SEV_COLOR.get(sev.lower(), C_MUTED)
    t = Table([[Paragraph(f"<b>{sev.upper()}</b>", styles["badge"])]], colWidths=[16*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), col),
        ("TOPPADDING",    (0,0),(-1,-1), 2),
        ("BOTTOMPADDING", (0,0),(-1,-1), 2),
    ]))
    return t


def header_banner(story, meta, styles):
    repo   = meta.get("repo", "huecomundo")
    branch = meta.get("branch", "main")
    commit = meta.get("commit", "")[:7]
    ts     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = [
        [Paragraph("Security Audit Report", styles["h_title"])],
        [Paragraph(f"<b>{repo}</b>  ·  branch: <b>{branch}</b>  ·  commit: <b>{commit}</b>", styles["h_sub"])],
        [Paragraph(ts, styles["h_sub"])],
    ]
    t = Table(rows, colWidths=[174*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), DARK),
        ("TOPPADDING",    (0,0),(-1,-1), 10),
        ("BOTTOMPADDING", (0,0),(-1,-1), 10),
        ("LEFTPADDING",   (0,0),(-1,-1), 12),
        ("RIGHTPADDING",  (0,0),(-1,-1), 12),
    ]))
    story.append(t)
    story.append(Spacer(1, 5*mm))


# ── SECTION 1: Dependency Audit (universal — auto-detects stack) ─────────────

def detect_stack(data):
    """Auto-detect stack from audit.json format if STACK env not set."""
    stack = os.environ.get("STACK", "").lower()
    if stack:
        return stack
    if "vulnerabilities" in data and "metadata" in data:
        return "nodejs"
    if "dependencies" in data and isinstance(data.get("dependencies"), list):
        # pip-audit format
        for dep in data.get("dependencies", []):
            if "vulns" in dep:
                return "python"
    if "advisories" in data:
        return "php"
    if "dependencies" in data and isinstance(data.get("dependencies"), dict):
        return "java"
    return "nodejs"  # fallback


def normalize_vulns(data, stack):
    """Normalize all scanner formats into a common list of dicts."""
    vulns = []

    if stack == "nodejs":
        raw = data.get("vulnerabilities", {})
        for pkg, v in raw.items():
            sev = (v.get("severity") or "info").lower()
            titles = []
            for item in v.get("via", []):
                if isinstance(item, dict) and item.get("title"):
                    cve = item.get("cve", "")
                    titles.append(f"{item['title']}{' (' + cve + ')' if cve else ''}")
            fix = v.get("fixAvailable")
            if fix is True:
                fix_text = "Yes"
            elif isinstance(fix, dict):
                fix_text = "Yes (breaking)" if fix.get("isSemVerMajor") else "Yes"
            else:
                fix_text = "No"
            vulns.append({
                "sev": sev, "pkg": pkg,
                "advisory": "<br/>".join(titles) if titles else "See npm advisory",
                "range": v.get("range", "—"), "fix": fix_text
            })

    elif stack == "python":
        # pip-audit format: {"dependencies": [{"name": "pkg", "version": "x", "vulns": [...]}]}
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                sev = vuln.get("fix_versions") and "moderate" or "high"
                fix_text = "Yes" if vuln.get("fix_versions") else "No"
                vulns.append({
                    "sev": sev,
                    "pkg": f"{dep.get('name', '')} {dep.get('version', '')}",
                    "advisory": vuln.get("description", vuln.get("id", "See advisory")),
                    "range": dep.get("version", "—"),
                    "fix": fix_text
                })

    elif stack == "php":
        # composer audit format: {"advisories": {"pkg": [{"advisoryId": ..., "title": ..., "severity": ...}]}}
        advisories = data.get("advisories", {})
        if isinstance(advisories, dict):
            for pkg, adv_list in advisories.items():
                for adv in (adv_list if isinstance(adv_list, list) else [adv_list]):
                    sev = (adv.get("severity") or "medium").lower()
                    vulns.append({
                        "sev": sev, "pkg": pkg,
                        "advisory": adv.get("title", adv.get("advisoryId", "See advisory")),
                        "range": adv.get("affectedVersions", "—"),
                        "fix": "Yes" if adv.get("reportedAt") else "Unknown"
                    })

    elif stack == "java":
        # OWASP dependency-check JSON format
        deps = data.get("dependencies", [])
        if isinstance(deps, list):
            for dep in deps:
                for vuln in dep.get("vulnerabilities", []):
                    sev = (vuln.get("severity") or "medium").lower()
                    cvss = vuln.get("cvssv3", vuln.get("cvssv2", {}))
                    vulns.append({
                        "sev": sev,
                        "pkg": dep.get("fileName", dep.get("name", "unknown")),
                        "advisory": f"{vuln.get('name', '')} — {vuln.get('description', '')[:120]}",
                        "range": dep.get("version", "—"),
                        "fix": "Check NVD"
                    })

    rank = {s: i for i, s in enumerate(["critical", "high", "medium", "moderate", "low", "info"])}
    vulns.sort(key=lambda x: rank.get(x["sev"], 99))
    return vulns


STACK_LABELS = {
    "nodejs": "npm audit",
    "python": "pip-audit",
    "php":    "composer audit",
    "java":   "OWASP Dependency Check",
}


def section_dependency_audit(story, data, styles):
    stack     = detect_stack(data)
    label     = STACK_LABELS.get(stack, "Dependency Audit")
    vulns     = normalize_vulns(data, stack)

    # Count by severity for summary
    counts = {"critical": 0, "high": 0, "moderate": 0, "medium": 0, "low": 0}
    for v in vulns:
        s = v["sev"]
        if s in counts:
            counts[s] += 1
    moderate_total = counts["moderate"] + counts["medium"]

    story.append(Paragraph(f"1. Dependency Vulnerabilities  ({label})", styles["sec"]))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=4))

    def stat(val, label, col="#1e293b"):
        return Paragraph(f'<font color="{col}"><b>{val}</b></font><br/>'
                         f'<font color="#64748b" size="7">{label}</font>', styles["body"])

    row = [[
        stat(len(vulns),          "Total"),
        stat(counts["critical"],  "Critical", "#ef4444"),
        stat(counts["high"],      "High",     "#f97316"),
        stat(moderate_total,      "Moderate", "#eab308"),
        stat(counts["low"],       "Low",      "#3b82f6"),
        stat(stack.upper(),       "Stack"),
    ]]
    grid = Table(row, colWidths=[29*mm]*6)
    grid.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), C_ROW),
        ("BOX",           (0,0),(-1,-1), 0.5, C_HEAD),
        ("GRID",          (0,0),(-1,-1), 0.5, C_HEAD),
        ("ALIGN",         (0,0),(-1,-1), "CENTER"),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0),(-1,-1), 7),
        ("BOTTOMPADDING", (0,0),(-1,-1), 7),
    ]))
    story.append(grid)
    story.append(Spacer(1, 3*mm))

    if not vulns:
        story.append(Paragraph("No dependency vulnerabilities found.", styles["body"]))
        return

    def hdr(t): return Paragraph(f"<b>{t}</b>", styles["body"])
    rows = [[hdr("Sev"), hdr("Package"), hdr("Vulnerability / CVE"), hdr("Affected Range"), hdr("Fix")]]

    for v in vulns:
        fix_col = "#22c55e" if v["fix"] == "Yes" else "#f97316" if "breaking" in v["fix"] else "#ef4444"
        rows.append([
            badge_cell(v["sev"], styles),
            Paragraph(f"<b>{v['pkg']}</b>", styles["pkg"]),
            Paragraph(v["advisory"], styles["desc"]),
            Paragraph(v["range"], styles["code"]),
            Paragraph(f'<font color="{fix_col}"><b>{v["fix"]}</b></font>', styles["desc"]),
        ])

    t = Table(rows, colWidths=[18*mm, 36*mm, 72*mm, 26*mm, 22*mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0,0),(-1,0),  C_HEAD),
        ("GRID",           (0,0),(-1,-1), 0.4, C_HEAD),
        ("VALIGN",         (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING",     (0,0),(-1,-1), 4),
        ("BOTTOMPADDING",  (0,0),(-1,-1), 4),
        ("LEFTPADDING",    (0,0),(-1,-1), 4),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [WHITE, C_ROW]),
    ]))
    story.append(t)


# ── SECTION 2: Semgrep SAST (file:line) ───────────────────────────────────────
def section_semgrep(story, data, styles):
    results = data.get("results", [])
    errors  = data.get("errors", [])

    story.append(PageBreak())
    story.append(Paragraph("2. Static Code Analysis  (Semgrep SAST)", styles["sec"]))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=4))

    if not results:
        story.append(Paragraph("No issues found by Semgrep.", styles["body"]))
        return

    # Count by severity
    sev_counts = {}
    for r in results:
        sev = (r.get("extra", {}).get("severity") or r.get("severity") or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    summary_text = "  ".join(
        f'<font color="{SEV_COLOR.get(s, C_MUTED).hexval()}"><b>{sev_counts[s]} {s.upper()}</b></font>'
        for s in SEV_ORDER if s in sev_counts
    )
    story.append(Paragraph(f"Found {len(results)} issues:  {summary_text}", styles["body"]))
    story.append(Spacer(1, 3*mm))

    # Sort: critical first
    rank = {s: i for i, s in enumerate(SEV_ORDER)}
    sorted_results = sorted(results, key=lambda r: rank.get(
        (r.get("extra",{}).get("severity") or r.get("severity","info")).lower(), 99))

    def hdr(t): return Paragraph(f"<b>{t}</b>", styles["body"])
    rows = [[hdr("Sev"), hdr("File  :  Line"), hdr("Rule / Issue"), hdr("Code snippet")]]

    for r in sorted_results:
        extra   = r.get("extra", {})
        sev     = (extra.get("severity") or r.get("severity") or "info").lower()
        path    = r.get("path", "—")
        start   = r.get("start", {})
        line    = start.get("line", "?")
        col     = start.get("col", "")
        rule_id = r.get("check_id", "").split(".")[-1]   # last segment only, no full path
        message = extra.get("message", r.get("message", "")).strip()
        snippet = (extra.get("lines") or "").strip().replace("\n", " ")[:120]

        loc = f"{path}  :  line {line}" + (f"  col {col}" if col else "")

        rows.append([
            badge_cell(sev, styles),
            Paragraph(loc, styles["code"]),
            Paragraph(f"<b>{rule_id}</b><br/>{message}", styles["desc"]),
            Paragraph(snippet, styles["code"]),
        ])

    t = Table(rows, colWidths=[18*mm, 44*mm, 60*mm, 52*mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0,0),(-1,0),  C_HEAD),
        ("GRID",           (0,0),(-1,-1), 0.4, C_HEAD),
        ("VALIGN",         (0,0),(-1,-1), "TOP"),
        ("TOPPADDING",     (0,0),(-1,-1), 4),
        ("BOTTOMPADDING",  (0,0),(-1,-1), 4),
        ("LEFTPADDING",    (0,0),(-1,-1), 4),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [WHITE, C_ROW]),
    ]))
    story.append(t)


# ── SECTION 3: Snyk Code SAST (file:line) ────────────────────────────────────
def section_snyk_code(story, data, styles):
    # Snyk Code JSON uses "runs[].results[]" (SARIF-like) or flat "vulnerabilities[]"
    runs  = data.get("runs", [])
    flat  = data.get("vulnerabilities", [])

    story.append(PageBreak())
    story.append(Paragraph("3. Snyk Code Analysis  (SAST)", styles["sec"]))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=4))

    issues = []

    # SARIF format
    for run in runs:
        for result in run.get("results", []):
            locs = result.get("locations", [])
            loc  = locs[0] if locs else {}
            phy  = loc.get("physicalLocation", {})
            uri  = phy.get("artifactLocation", {}).get("uri", "—")
            line = phy.get("region", {}).get("startLine", "?")
            col  = phy.get("region", {}).get("startColumn", "")
            sev  = result.get("level", "info").lower()  # "error"/"warning"/"note"
            # map SARIF levels to readable severity
            sev_map = {"error": "high", "warning": "moderate", "note": "info"}
            sev = sev_map.get(sev, sev)
            msg = result.get("message", {}).get("text", "").strip()
            rule= result.get("ruleId", "")
            issues.append({"sev": sev, "file": uri, "line": line, "col": col,
                           "rule": rule, "msg": msg, "snippet": ""})

    # Flat format fallback
    for v in flat:
        sev  = (v.get("severity") or "info").lower()
        locs = v.get("locations", [{}])
        loc  = locs[0] if locs else {}
        uri  = loc.get("uri", v.get("filePath","—"))
        line = loc.get("startLine", v.get("lineNumber","?"))
        msg  = v.get("message", v.get("title","")).strip()
        rule = v.get("id", v.get("ruleId",""))
        issues.append({"sev": sev, "file": uri, "line": line, "col": "",
                       "rule": rule, "msg": msg, "snippet": ""})

    if not issues:
        story.append(Paragraph("No issues found by Snyk Code, or scan output unavailable.", styles["body"]))
        return

    rank = {s: i for i, s in enumerate(SEV_ORDER)}
    issues.sort(key=lambda x: rank.get(x["sev"], 99))

    story.append(Paragraph(f"Found {len(issues)} issues.", styles["body"]))
    story.append(Spacer(1, 3*mm))

    def hdr(t): return Paragraph(f"<b>{t}</b>", styles["body"])
    rows = [[hdr("Sev"), hdr("File  :  Line"), hdr("Rule"), hdr("Description")]]

    for i in issues:
        loc = f"{i['file']}  :  line {i['line']}" + (f"  col {i['col']}" if i['col'] else "")
        rows.append([
            badge_cell(i["sev"], styles),
            Paragraph(loc, styles["code"]),
            Paragraph(i["rule"].split(".")[-1], styles["desc"]),
            Paragraph(i["msg"], styles["desc"]),
        ])

    t = Table(rows, colWidths=[18*mm, 50*mm, 36*mm, 70*mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0,0),(-1,0),  C_HEAD),
        ("GRID",           (0,0),(-1,-1), 0.4, C_HEAD),
        ("VALIGN",         (0,0),(-1,-1), "TOP"),
        ("TOPPADDING",     (0,0),(-1,-1), 4),
        ("BOTTOMPADDING",  (0,0),(-1,-1), 4),
        ("LEFTPADDING",    (0,0),(-1,-1), 4),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [WHITE, C_ROW]),
    ]))
    story.append(t)


# ── Footer ────────────────────────────────────────────────────────────────────
def footer(story, styles):
    story.append(Spacer(1, 6*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_MUTED))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        "Generated by n8n CI/CD Monitor  ·  "
        "Sources: Dependency Audit (npm/pip/composer/OWASP), Semgrep SAST, Snyk Code",
        styles["muted"]
    ))


# ── Entry point ───────────────────────────────────────────────────────────────
def load_json(path):
    if not path or not os.path.exists(path):
        return {}
    safe_path = os.path.realpath(path)
    cwd = os.path.realpath(os.getcwd())
    if not safe_path.startswith(cwd + os.sep):
        raise ValueError(f"Path traversal attempt blocked: {path}")
    try:
        with open(safe_path) as f:  # nosec B open is path-traversal safe: sanitized above
            return json.load(f)
    except Exception:
        return {}


def generate(audit_path, semgrep_path, snyk_code_path, output_path, meta=None):
    audit_data     = load_json(audit_path)
    semgrep_data   = load_json(semgrep_path)
    snyk_code_data = load_json(snyk_code_path)
    meta           = meta or {}
    styles_map     = S()

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=14*mm,  bottomMargin=18*mm,
        title="Security Audit Report",
        author="n8n CI/CD Monitor",
    )

    story = []
    header_banner(story, meta, styles_map)
    section_dependency_audit(story, audit_data, styles_map)
    section_semgrep(story, semgrep_data, styles_map)
    section_snyk_code(story, snyk_code_data, styles_map)
    footer(story, styles_map)
    doc.build(story)
    print(f"PDF written -> {output_path}")


if __name__ == "__main__":
    args = sys.argv[1:]
    audit_path     = args[0] if len(args) > 0 else "audit.json"
    semgrep_path   = args[1] if len(args) > 1 else "semgrep.json"
    snyk_code_path = args[2] if len(args) > 2 else "snyk-code.json"
    output_path    = args[3] if len(args) > 3 else "audit_report.pdf"

    meta = {
        "repo":   os.environ.get("REPO_NAME", "huecomundo"),
        "branch": os.environ.get("BRANCH_NAME", "main"),
        "commit": os.environ.get("COMMIT_SHA", ""),
    }
    generate(audit_path, semgrep_path, snyk_code_path, output_path, meta)
