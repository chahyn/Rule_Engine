"""Reports built from the pack's own claims agree with the pack's expected results."""
import io
import json

import pytest
from pypdf import PdfReader

from rule_engine.core.engine import validate_claim
from rule_engine.reporting.findings import build_report, redact
from rule_engine.reporting.pdf_report import render_claim_pdf

SPLITS = ["development", "stress"]


def _reports(split, pack, store):
    claims, gold = pack(split)
    return claims, gold, {c["claim_id"]: build_report(c, validate_claim(c, store), store) for c in claims}


@pytest.mark.parametrize("split", SPLITS)
def test_findings_match_gold(split, pack, store):
    claims, gold, reps = _reports(split, pack, store)
    for cid, rep in reps.items():
        assert len(rep.findings) == 15
        for f in rep.findings:
            g = gold[(cid, f.rule_id)]
            assert f.status == g["status"] and f.severity == g["severity"]
            assert f.corrective_action == g["corrective_action"] and f.explanation == g["explanation"]
            assert sorted(f.affected_line_ids) == sorted(g["affected_line_ids"])
            assert f.requires_human_review == g["requires_human_review"]
            assert f.confidence == g["confidence"] and f.confidence_kind == g["confidence_kind"]
            expected_ev = [(e["path"], redact(e["value"])[0]) for e in g["evidence"]]
            assert [(e.path, e.value) for e in f.evidence] == expected_ev


@pytest.mark.parametrize("split", SPLITS)
def test_no_attachment_text_in_any_report(split, pack, store):
    claims, _, reps = _reports(split, pack, store)
    for c in claims:
        dump = reps[c["claim_id"]].model_dump_json()
        for a in c["attachments"]:
            text = a.get("text") or ""
            if len(text) > 15:
                assert text not in dump


def test_every_flagged_claim_renders_a_pdf_listing_its_issues(pack, store):
    claims, _, reps = _reports("development", pack, store)
    shown_rules, checked = set(), 0
    for c in claims:
        rep = reps[c["claim_id"]]
        flagged = {f.rule_id for f in rep.findings if f.status in ("FAIL", "UNABLE_TO_ASSESS")}
        if not flagged or (flagged <= shown_rules and checked >= 25):
            continue
        shown_rules |= flagged
        checked += 1
        pdf = render_claim_pdf(rep)
        text = " ".join(" ".join(p.extract_text().split()) for p in PdfReader(io.BytesIO(pdf)).pages)
        assert c["claim_id"] in text
        for f in rep.findings:
            if f.status in ("FAIL", "UNABLE_TO_ASSESS"):
                assert f.corrective_action in text and f.rule_id in text
    assert checked >= 10
