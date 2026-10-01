"""Render FindingReport objects to PDF (reportlab).

Safety rules for untrusted content (claim values can contain anything):
  * every dynamic string is XML-escaped before it reaches a Paragraph (no markup injection);
  * text outside latin-1 is replaced (built-in fonts cannot draw it) and control chars removed;
  * long values are truncated with an explicit "(+N chars)" marker;
  * status is always written as text, never colour alone.
"""
from __future__ import annotations

import io
import json
import re
from typing import Any, Iterable
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

from .findings import FindingReport, Finding

VALUE_LIMIT = 240
TEXT_LIMIT = 700
CONTENT_W = 180 * mm
INK, MUTED, LINE = colors.HexColor("#101828"), colors.HexColor("#475467"), colors.HexColor("#D0D5DD")
STATUS_STYLE = {  # status -> (text colour, background)
    "FAIL": (colors.HexColor("#B42318"), colors.HexColor("#FEE4E2")),
    "UNABLE_TO_ASSESS": (colors.HexColor("#B54708"), colors.HexColor("#FEF0C7")),
    "PASS": (colors.HexColor("#067647"), colors.HexColor("#D1FADF")),
    "NOT_APPLICABLE": (colors.HexColor("#475467"), colors.HexColor("#EAECF0")),
}
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean(text: Any, limit: int | None = None) -> str:
    s = _CTRL.sub("?", str(text)).encode("latin-1", "replace").decode("latin-1")
    if limit is not None and len(s) > limit:
        s = s[:limit] + f"... (+{len(s) - limit} chars)"
    return s


def fmt_value(value: Any) -> str:
    return clean(json.dumps(value, ensure_ascii=False, sort_keys=True) if value is not None else "null",
                 VALUE_LIMIT)


def styles() -> dict[str, ParagraphStyle]:
    b = getSampleStyleSheet()["Normal"]
    mk = lambda name, **kw: ParagraphStyle(name, parent=b, fontName=kw.pop("fontName", "Helvetica"),
                                           textColor=kw.pop("textColor", INK), **kw)
    return {
        "title": mk("t", fontName="Helvetica-Bold", fontSize=18, leading=22, spaceAfter=4),
        "h2": mk("h2", fontName="Helvetica-Bold", fontSize=12, leading=15, spaceBefore=10, spaceAfter=5),
        "body": mk("body", fontSize=9, leading=12),
        "small": mk("small", fontSize=8, leading=10, textColor=MUTED),
        "cell": mk("cell", fontSize=8, leading=10),
        "cellb": mk("cellb", fontName="Helvetica-Bold", fontSize=8, leading=10),
        "mono": mk("mono", fontName="Courier", fontSize=7.5, leading=9.5),
        "label": mk("label", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=MUTED),
    }


def P(text: Any, style: ParagraphStyle, limit: int | None = None) -> Paragraph:
    return Paragraph(escape(clean(text, limit)), style)


def badge(status: str, st: dict) -> Paragraph:
    fg, _ = STATUS_STYLE.get(status, STATUS_STYLE["NOT_APPLICABLE"])
    return Paragraph(f'<font color="{fg.hexval().replace("0x", "#")}"><b>{escape(clean(status))}</b></font>',
                     st["cell"])


def _grid(rows, widths, header=True, extra=()):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2F4F7")))
    t.setStyle(TableStyle(style + list(extra)))
    return t


def _status_bg(status: str):
    return STATUS_STYLE.get(status, STATUS_STYLE["NOT_APPLICABLE"])[1]


def _finding_block(f: Finding, st: dict) -> list:
    head = _grid([[P(f.rule_id, st["cellb"]), P(f.rule_title, st["cellb"]), badge(f.status, st),
                   P(f"severity: {f.severity}", st["cell"])]],
                 [16 * mm, 100 * mm, 34 * mm, 30 * mm], header=False,
                 extra=[("BACKGROUND", (0, 0), (-1, 0), _status_bg(f.status))])
    lines = ", ".join(f.affected_line_ids) if f.affected_line_ids else "none (claim-level)"
    meta = _grid([
        [P("Explanation", st["label"]), P(f.explanation, st["body"], TEXT_LIMIT)],
        [P("Affected lines", st["label"]), P(lines, st["body"])],
        [P("Rule", st["label"]), P(f"{f.rule_source}  (version {f.rule_version}, method: {f.method})", st["body"])],
        [P("Confidence", st["label"]), P(f.confidence_note, st["body"])],
        [P("Corrective action", st["label"]), P(f.corrective_action or "No action required.", st["body"], TEXT_LIMIT)],
        [P("Human review", st["label"]), P("Required" if f.requires_human_review else "Not required", st["body"])],
    ], [32 * mm, 148 * mm], header=False)
    out: list = [KeepTogether([head, meta])]
    if f.evidence:
        rows = [[P("Evidence path (JSON pointer into the original claim)", st["label"]),
                 P("Observed value", st["label"])]]
        for e in f.evidence:
            note = "  [text omitted for privacy]" if e.redacted else ""
            rows.append([P(e.path, st["mono"]), P(fmt_value(e.value) + note, st["mono"])])
        out.append(Spacer(1, 2))
        out.append(_grid(rows, [60 * mm, 120 * mm]))
    out.append(Spacer(1, 9))
    return out


def claim_story(rep: FindingReport, st: dict) -> list:
    c, run, s, esc = rep.claim, rep.run, rep.summary, rep.escalation
    story: list = [P("ClaimGuard - Validation Findings Report", st["title"]),
                   P("Pre-submission claim check against the fictional payer rulebook (R001-R015)", st["small"]),
                   Spacer(1, 6)]
    total = f"{c.total_amount:.2f} {c.currency or ''}".strip() if c.total_amount is not None else "n/a"
    story.append(_grid([
        [P("Claim ID", st["label"]), P(c.claim_id, st["cellb"]), P("Policy", st["label"]),
         P(f"{c.policy_id} (v{run.policy_version})" if run.policy_version else str(c.policy_id), st["cell"])],
        [P("Submission date", st["label"]), P(c.submission_date or "n/a", st["cell"]),
         P("Total / lines", st["label"]), P(f"{total} / {c.n_lines}", st["cell"])],
        [P("Run ID", st["label"]), P(run.run_id, st["cell"]), P("Engine version", st["label"]),
         P(run.engine_version, st["cell"])],
        [P("Input hash (SHA-256)", st["label"]), P(run.input_hash, st["mono"]), P("Generated (UTC)", st["label"]),
         P(rep.generated_at.strftime("%Y-%m-%d %H:%M:%S"), st["cell"])],
    ], [34 * mm, 66 * mm, 30 * mm, 50 * mm], header=False))

    counts = "   ".join(f"{k}: {v}" for k, v in sorted(s.by_status.items(), key=lambda kv: kv[0]))
    outcome_txt = {"ISSUES_FOUND": "Issues found", "UNRESOLVED_CHECKS": "No failure proven, but checks are unresolved",
                   "NO_ISSUES_DETECTED": "No issues detected by these checks (not a payer approval)"}[s.outcome]
    bg = {"ISSUES_FOUND": "FAIL", "UNRESOLVED_CHECKS": "UNABLE_TO_ASSESS", "NO_ISSUES_DETECTED": "PASS"}[s.outcome]
    esc_txt = (f"Human review required - priority {esc.priority.upper()}. " + "; ".join(esc.reasons)
               if esc.required else "No escalation required by these checks.")
    story += [Spacer(1, 8), P("Summary", st["h2"]),
              _grid([[P("Outcome", st["label"]), P(outcome_txt, st["cellb"])],
                     [P("Check results", st["label"]), P(counts, st["cell"])],
                     [P("Escalation", st["label"]), P(esc_txt, st["cell"], TEXT_LIMIT)]],
                    [34 * mm, 146 * mm], header=False,
                    extra=[("BACKGROUND", (1, 0), (1, 0), _status_bg(bg))])]

    rows = [[P(h, st["label"]) for h in ("Rule", "Check", "Status", "Severity", "Affected lines", "Confidence")]]
    for f in rep.findings:
        rows.append([P(f.rule_id, st["cellb"]), P(f.rule_title, st["cell"]), badge(f.status, st),
                     P(f.severity, st["cell"]), P(", ".join(f.affected_line_ids) or "-", st["cell"]),
                     P("n/a (deterministic)" if f.confidence is None else f"{f.confidence:.2f} ({f.confidence_kind})",
                       st["cell"])])
    story += [P("All checks at a glance", st["h2"]), _grid(rows, [14 * mm, 62 * mm, 32 * mm, 18 * mm, 28 * mm, 26 * mm])]

    flagged = [f for f in rep.findings if f.status in ("FAIL", "UNABLE_TO_ASSESS")]
    story.append(PageBreak())
    story.append(P(f"Findings that need attention ({len(flagged)})", st["h2"]))
    if not flagged:
        story.append(P("None. Every applicable check passed on the supplied data.", st["body"]))
    for f in flagged:
        story += _finding_block(f, st)

    ok = [f for f in rep.findings if f.status not in ("FAIL", "UNABLE_TO_ASSESS")]
    if ok:
        rows = [[P(h, st["label"]) for h in ("Rule", "Check", "Status", "Note")]]
        for f in ok:
            rows.append([P(f.rule_id, st["cellb"]), P(f.rule_title, st["cell"]), badge(f.status, st),
                         P(f.explanation, st["cell"], 300)])
        story += [P(f"Checks passed or not applicable ({len(ok)})", st["h2"]),
                  _grid(rows, [14 * mm, 62 * mm, 32 * mm, 72 * mm]),
                  P("Full evidence for every check is in the machine-readable JSON report.", st["small"])]
    story += [Spacer(1, 10), P(rep.disclaimer, st["small"])]
    return story


def _footer(label: str):
    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(15 * mm, 9 * mm, clean(label, 90))
        canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()
    return draw


def _build(story: list, title: str, footer_label: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm,
                            bottomMargin=16 * mm, title=clean(title), author="ClaimGuard Rule Engine",
                            subject="Structured claim validation findings")
    cb = _footer(footer_label)
    doc.build(story, onFirstPage=cb, onLaterPages=cb)
    return buf.getvalue()


def render_claim_pdf(rep: FindingReport) -> bytes:
    st = styles()
    return _build(claim_story(rep, st), f"ClaimGuard findings {rep.claim.claim_id}",
                  f"ClaimGuard findings | claim {rep.claim.claim_id} | run {rep.run.run_id}")


def render_batch_pdf(reports: Iterable[FindingReport]) -> bytes:
    reports = list(reports)
    st = styles()
    story: list = [P("ClaimGuard - Batch Findings Report", st["title"]),
                   P(f"{len(reports)} claim(s). One detailed section per claim follows this summary.", st["small"]),
                   Spacer(1, 8)]
    rows = [[P(h, st["label"]) for h in ("Claim ID", "Outcome", "FAIL", "UNABLE", "Escalation", "Run ID")]]
    for r in reports:
        rows.append([P(r.claim.claim_id, st["cellb"]), P(r.summary.outcome, st["cell"]),
                     P(r.summary.by_status.get("FAIL", 0), st["cell"]), P(r.summary.unresolved_checks, st["cell"]),
                     P(r.escalation.priority, st["cell"]), P(r.run.run_id, st["cell"])])
    story.append(_grid(rows, [38 * mm, 42 * mm, 14 * mm, 16 * mm, 26 * mm, 44 * mm]))
    for r in reports:
        story.append(PageBreak())
        story += claim_story(r, st)
    return _build(story, "ClaimGuard batch findings report", "ClaimGuard batch findings report")
