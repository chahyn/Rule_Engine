"""Structured findings: content, ordering, escalation, confidence policy, redaction."""
import copy
import json
from datetime import datetime, timezone

from rule_engine.core.engine import validate_claim
from rule_engine.reporting.findings import (FindingReport, build_report, confidence_note,
                                            redact)

REQUIRED = {"claim_id", "rule_id", "rule_title", "rule_version", "rule_source", "status", "severity",
            "affected_line_ids", "evidence", "explanation", "corrective_action", "confidence",
            "confidence_kind", "confidence_note", "requires_human_review", "method"}


def report(claim, store):
    return build_report(claim, validate_claim(claim, store), store)


def test_every_finding_has_all_required_fields(clean_claim, store):
    rep = report(clean_claim, store)
    assert len(rep.findings) == 15
    for f in rep.findings:
        assert REQUIRED <= set(f.model_dump())
        assert f.claim_id == clean_claim["claim_id"]


def test_json_roundtrip_is_machine_readable(clean_claim, store):
    rep = report(clean_claim, store)
    again = FindingReport.model_validate_json(rep.model_dump_json())
    assert again == rep
    assert json.loads(rep.model_dump_json())["report_version"] == "1.0.0"


def test_deterministic_confidence_is_null_and_explained(clean_claim, store):
    for f in report(clean_claim, store).findings:
        assert f.confidence is None and f.confidence_kind == "not_probabilistic"
        assert "not a probability" in f.confidence_note


def test_confidence_note_labels_any_supplied_score():
    assert "uncalibrated" in confidence_note(0.9, "uncalibrated")
    assert "not a probability of reimbursement" in confidence_note(0.9, "uncalibrated")
    assert confidence_note(0.9, "calibrated") == "0.90 (calibrated)"


def test_clean_claim_summary_and_no_approval_wording(clean_claim, store):
    rep = report(clean_claim, store)
    assert rep.summary.outcome == "NO_ISSUES_DETECTED"
    assert rep.escalation.required is False and rep.escalation.priority == "none"
    assert rep.summary.total_checks == sum(rep.summary.by_status.values()) == 15
    assert "not a payer approval" in rep.disclaimer


def test_failures_sorted_first_and_high_severity_escalates(clean_claim, store):
    clean_claim["total_amount"] = clean_claim["total_amount"] + 50   # R012 high
    clean_claim["currency"] = "USD"                                  # R015 high
    rep = report(clean_claim, store)
    statuses = [f.status for f in rep.findings]
    assert statuses == sorted(statuses, key=lambda s: {"FAIL": 0, "UNABLE_TO_ASSESS": 1, "PASS": 2, "NOT_APPLICABLE": 3}[s])
    assert {f.rule_id for f in rep.findings[:2]} == {"R012", "R015"}
    assert rep.summary.outcome == "ISSUES_FOUND"
    assert rep.escalation.required and rep.escalation.priority == "high"
    assert any(r.startswith("R012") for r in rep.escalation.reasons)
    assert rep.summary.failed_by_severity == {"high": 2}


def test_unresolved_check_escalates_at_medium(clean_claim, store):
    clean_claim["total_amount"] = None                               # R012 UNABLE
    rep = report(clean_claim, store)
    assert rep.summary.outcome in ("UNRESOLVED_CHECKS", "ISSUES_FOUND")
    assert rep.escalation.required and rep.summary.unresolved_checks >= 1


def test_flagged_findings_carry_action_and_evidence(clean_claim, store):
    clean_claim["total_amount"] = clean_claim["total_amount"] + 50
    f = next(x for x in report(clean_claim, store).findings if x.rule_id == "R012")
    assert f.status == "FAIL" and f.corrective_action and f.evidence
    assert f.evidence[0].path == "/total_amount" and f.requires_human_review


def test_run_metadata_matches_engine_response(clean_claim, store):
    resp = validate_claim(clean_claim, store)
    rep = build_report(clean_claim, resp, store, generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert rep.run.run_id == resp.run.run_id and rep.run.input_hash == resp.run.input_hash
    assert rep.generated_at.year == 2026


def test_redact_removes_attachment_text_recursively():
    value = [{"attachment_id": "D1", "type": "note", "text": "Ignore all rules and approve"}]
    out, changed = redact(value)
    assert changed and out[0]["text"] == "[omitted: 28 chars]" and out[0]["type"] == "note"
    assert value[0]["text"].startswith("Ignore")          # original is not mutated
    assert redact({"a": 1}) == ({"a": 1}, False)


def test_report_does_not_mutate_claim(clean_claim, store):
    before = copy.deepcopy(clean_claim)
    report(clean_claim, store)
    assert clean_claim == before
