"""PDF report generation with ReportLab."""
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)
from xml.sax.saxutils import escape

from .models import Scan
from .scanner.base import SEVERITIES

SEV_COLORS = {
    "critical": colors.HexColor("#b91c1c"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#64748b"),
}
GRADE_COLORS = {"A+": "#15803d", "A": "#16a34a", "B": "#65a30d", "C": "#ca8a04", "D": "#ea580c", "F": "#b91c1c"}
INK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#64748b")
LINE = colors.HexColor("#e2e8f0")


def _p(text, style):
    return Paragraph(escape(str(text or "")).replace("\n", "<br/>"), style)


def build_pdf(scan: Scan) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm,
                            title=f"Security Audit - {scan.target.hostname}", author="SecAudit Dashboard")
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontSize=20, textColor=INK, spaceAfter=4, alignment=0)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=13, textColor=INK, spaceBefore=12, spaceAfter=6)
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9, leading=12, textColor=INK)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10, textColor=MUTED)
    mono = ParagraphStyle("mono", parent=small, fontName="Courier", fontSize=7.5, leading=9.5)
    big = ParagraphStyle("big", parent=body, fontSize=34, leading=38, alignment=TA_CENTER,
                         textColor=colors.HexColor(GRADE_COLORS.get(scan.grade or "F", "#334155")))
    center = ParagraphStyle("center", parent=small, alignment=TA_CENTER)

    meta = scan.meta or {}
    tls = meta.get("tls") or {}
    summary = scan.summary or {}
    counts = summary.get("severity_counts", {})
    story = []

    story.append(_p("Website Security Audit Report", h1))
    story.append(_p(f"{scan.target.name} — {scan.target.url}", body))
    story.append(_p(f"Scan #{scan.id} · {scan.finished_at or scan.created_at:%Y-%m-%d %H:%M UTC} · "
                    f"duration {(scan.duration_ms or 0) / 1000:.1f}s", small))
    story.append(Spacer(1, 8))

    # Score block + severity table side by side
    score_tbl = Table([[Paragraph(scan.grade or "-", big)], [_p(f"Score {scan.score}/100", center)]],
                      colWidths=[45 * mm])
    score_tbl.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, LINE),
                                   ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    sev_rows = [["Severity", "Issues"]] + [[s.capitalize(), str(counts.get(s, 0))] for s in SEVERITIES]
    sev_rows.append(["Checks passed", f"{summary.get('passed', 0)} / {summary.get('total_checks', 0)}"])
    sev_tbl = Table(sev_rows, colWidths=[45 * mm, 30 * mm])
    style = [("FONTSIZE", (0, 0), (-1, -1), 9), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
             ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE), ("ALIGN", (1, 0), (1, -1), "RIGHT")]
    for i, s in enumerate(SEVERITIES, start=1):
        style.append(("TEXTCOLOR", (0, i), (0, i), SEV_COLORS[s]))
    sev_tbl.setStyle(TableStyle(style))
    top = Table([[score_tbl, sev_tbl]], colWidths=[60 * mm, 100 * mm])
    top.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(top)

    # Target info
    story.append(_p("Target & TLS overview", h2))
    info = [
        ["Final URL", meta.get("final_url", "-")],
        ["HTTP status", str(meta.get("status_code", "-"))],
        ["TLS protocol", tls.get("protocol", "unavailable")],
        ["Cipher", tls.get("cipher", "-")],
        ["Certificate subject", tls.get("subject", "-")],
        ["Issuer", tls.get("issuer", "-")],
        ["Valid until", f"{(tls.get('not_after') or '-')[:10]}  ({tls.get('days_left', '-')} days left)"],
        ["Key", f"{tls.get('key_type', '-')} {tls.get('key_bits') or ''}"],
    ]
    t = Table([[_p(k, small), _p(v, body)] for k, v in info], colWidths=[40 * mm, 134 * mm])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.3, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)

    # Findings
    failed = [f for f in scan.findings if not f.passed]
    failed.sort(key=lambda f: SEVERITIES.index(f.severity) if f.severity in SEVERITIES else 9)
    story.append(_p(f"Findings ({len(failed)})", h2))
    if not failed:
        story.append(_p("No issues found. Excellent work!", body))
    for f in failed:
        badge = Table([[_p(f.severity.upper(), ParagraphStyle("b", parent=small, textColor=colors.white,
                                                               fontName="Helvetica-Bold", alignment=TA_CENTER))]],
                      colWidths=[20 * mm])
        badge.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SEV_COLORS.get(f.severity, MUTED)),
                                   ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        parts = [Paragraph(f"<b>{escape(f.title)}</b> <font color='#64748b' size='7.5'>[{escape(f.category)}]</font>", body),
                 _p(f.description, body)]
        if f.recommendation:
            parts.append(Paragraph(f"<b>Fix:</b> {escape(f.recommendation)}", body))
        if f.evidence:
            parts.append(_p(f.evidence[:600], mono))
        row = Table([[badge, parts]], colWidths=[24 * mm, 150 * mm])
        row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
                                 ("BOTTOMPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5)]))
        story.append(KeepTogether(row))

    # Passed checks
    passed = [f for f in scan.findings if f.passed]
    if passed:
        story.append(PageBreak())
        story.append(_p(f"Passed checks ({len(passed)})", h2))
        rows = [[_p("✓", ParagraphStyle("ok", parent=body, textColor=colors.HexColor("#16a34a"))),
                 _p(f.title, body), _p(f.category, small)] for f in passed]
        pt = Table(rows, colWidths=[8 * mm, 130 * mm, 36 * mm])
        pt.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.3, LINE)]))
        story.append(pt)

    story.append(Spacer(1, 14))
    story.append(_p("This report covers passive configuration checks only and is not a full penetration test. "
                    "Scans were performed only against a target whose ownership was verified.", small))

    def _footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, f"SecAudit Dashboard · {scan.target.hostname}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
