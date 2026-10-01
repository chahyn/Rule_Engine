"""Structured, machine-readable validation findings for ONE claim.

Pure functions: no audit, no I/O. Built from the engine's ValidationResponse so the report can
never disagree with the engine. Every finding carries: claim_id, rule_id, rule-linked evidence,
severity, confidence (+ its kind) and the suggested corrective action.

Confidence policy (pack doc 04): deterministic rules have confidence=null and
confidence_kind=not_probabilistic. A number is shown only if a producer supplied one, and is
always labelled with its kind. This module never invents a score.

Data minimisation: attachment `text` (untrusted free text) is replaced by a placeholder.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel

from ..domain.result import ValidationResponse
from ..stores.policy_store import PolicyStore

REPORT_VERSION = "1.0.0"
DISCLAIMER = (
    "Pre-submission administrative check on synthetic data using a fictional rulebook. "
    "PASS means this specific check passed on the supplied data; it is not a payer approval, "
    "a reimbursement decision or a clinical judgement. Attachment text is not reproduced."
)
STATUS_ORDER = {"FAIL": 0, "UNABLE_TO_ASSESS": 1, "PASS": 2, "NOT_APPLICABLE": 3, "NOT_IMPLEMENTED": 4}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
FLAGGED = ("FAIL", "UNABLE_TO_ASSESS")


class EvidenceItem(BaseModel):
    path: str
    value: Any = None
    redacted: bool = False


class Finding(BaseModel):
    claim_id: str
    rule_id: str
    rule_title: str
    rule_version: str
    rule_source: str
    status: str
    severity: str
    affected_line_ids: list[str]
    evidence: list[EvidenceItem]
    explanation: str
    corrective_action: str
    confidence: Optional[float]
    confidence_kind: str
    confidence_note: str
    requires_human_review: bool
    method: str


class ClaimInfo(BaseModel):
    claim_id: str
    policy_id: Optional[str] = None
    submission_date: Optional[str] = None
    currency: Optional[str] = None
    total_amount: Optional[float] = None
    n_lines: int = 0


class RunInfo(BaseModel):
    run_id: str
    input_hash: str
    engine_version: str
    policy_version: Optional[str] = None
    started_at: datetime


class Escalation(BaseModel):
    required: bool
    priority: Literal["none", "medium", "high"]
    reasons: list[str]


class Summary(BaseModel):
    total_checks: int
    by_status: dict[str, int]
    failed_by_severity: dict[str, int]
    unresolved_checks: int
    outcome: Literal["ISSUES_FOUND", "UNRESOLVED_CHECKS", "NO_ISSUES_DETECTED"]


class FindingReport(BaseModel):
    report_version: str
    generated_at: datetime
    claim: ClaimInfo
    run: RunInfo
    summary: Summary
    escalation: Escalation
    findings: list[Finding]
    disclaimer: str


def redact(value: Any) -> tuple[Any, bool]:
    """Replace any `text` string (attachment free text) by a placeholder, recursively."""
    if isinstance(value, dict):
        out, changed = {}, False
        for k, v in value.items():
            if k == "text" and isinstance(v, str):
                out[k], changed = f"[omitted: {len(v)} chars]", True
            else:
                out[k], c = redact(v)
                changed = changed or c
        return out, changed
    if isinstance(value, list):
        items = [redact(v) for v in value]
        return [v for v, _ in items], any(c for _, c in items)
    return value, False


def confidence_note(confidence: Optional[float], kind: str) -> str:
    if confidence is None:
        return "Not applicable: deterministic rule check (not a probability)."
    if kind == "calibrated":
        return f"{confidence:.2f} (calibrated)"
    return f"{confidence:.2f} ({kind}; not a probability of reimbursement)"


def _sort_key(f: Finding):
    return (STATUS_ORDER.get(f.status, 9), SEVERITY_ORDER.get(f.severity, 9), f.rule_id)


def _escalation(findings: list[Finding]) -> Escalation:
    reasons, priority = [], "none"
    for f in findings:
        if f.status == "FAIL" and f.severity == "high":
            reasons.append(f"{f.rule_id}: high-severity failure")
            priority = "high"
        elif f.status == "FAIL":
            reasons.append(f"{f.rule_id}: {f.severity}-severity failure")
            priority = priority if priority == "high" else "medium"
        elif f.status == "UNABLE_TO_ASSESS":
            reasons.append(f"{f.rule_id}: unresolved check (evidence missing)")
            priority = priority if priority == "high" else "medium"
    return Escalation(required=priority != "none", priority=priority, reasons=reasons)


def build_report(raw: dict, response: ValidationResponse, store: PolicyStore,
                 generated_at: Optional[datetime] = None) -> FindingReport:
    findings: list[Finding] = []
    for r in response.results:
        d = r.model_dump(mode="json")
        meta = store.rules.get(d["rule_id"])
        evidence = []
        for e in d["evidence"]:
            value, was_redacted = redact(e["value"])
            evidence.append(EvidenceItem(path=e["path"], value=value, redacted=was_redacted))
        findings.append(Finding(
            claim_id=d["claim_id"], rule_id=d["rule_id"],
            rule_title=meta.title if meta else d["rule_id"], rule_version=d["rule_version"],
            rule_source=d["rule_source"], status=d["status"], severity=d["severity"],
            affected_line_ids=d["affected_line_ids"], evidence=evidence,
            explanation=d["explanation"], corrective_action=d["corrective_action"],
            confidence=d["confidence"], confidence_kind=d["confidence_kind"],
            confidence_note=confidence_note(d["confidence"], d["confidence_kind"]),
            requires_human_review=d["requires_human_review"], method=d["method"]))
    findings.sort(key=_sort_key)

    by_status: dict[str, int] = {}
    failed_by_sev: dict[str, int] = {}
    for f in findings:
        by_status[f.status] = by_status.get(f.status, 0) + 1
        if f.status == "FAIL":
            failed_by_sev[f.severity] = failed_by_sev.get(f.severity, 0) + 1
    outcome = ("ISSUES_FOUND" if by_status.get("FAIL") else
               "UNRESOLVED_CHECKS" if by_status.get("UNABLE_TO_ASSESS") else "NO_ISSUES_DETECTED")

    total = raw.get("total_amount")
    run = response.run
    return FindingReport(
        report_version=REPORT_VERSION, generated_at=generated_at or datetime.now(timezone.utc),
        claim=ClaimInfo(
            claim_id=response.claim_id, policy_id=raw.get("policy_id"),
            submission_date=raw.get("submission_date"), currency=raw.get("currency"),
            total_amount=float(total) if isinstance(total, (int, float)) and not isinstance(total, bool) else None,
            n_lines=len(raw.get("lines") or [])),
        run=RunInfo(run_id=run.run_id, input_hash=run.input_hash, engine_version=run.engine_version,
                    policy_version=run.policy_version, started_at=run.started_at),
        summary=Summary(total_checks=len(findings), by_status=by_status,
                        failed_by_severity=failed_by_sev,
                        unresolved_checks=by_status.get("UNABLE_TO_ASSESS", 0), outcome=outcome),
        escalation=_escalation(findings), findings=findings, disclaimer=DISCLAIMER)
