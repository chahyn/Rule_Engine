"""Rule engine + audit log working together (API level)."""
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import audit
from rule_engine.main import app

client = TestClient(app)


def log():
    return os.environ["AUDIT_LOG"]


def test_validate_writes_full_audit_trail(clean_claim):
    body = client.post("/v1/validate", json={"claim": clean_claim}).json()
    cid, run_id = clean_claim["claim_id"], body["run"]["run_id"]
    events = [r["event"] for r in audit.trace(log(), cid)]
    types = [e["type"] for e in events]
    assert types[0] == "RUN_STARTED" and types[-1] == "RUN_COMPLETED"
    done = events[-1]
    assert done["run_id"] == run_id and done["n_results"] == 15
    assert [r["rule_id"] for r in done["rule_results"]] == [f"R{i:03d}" for i in range(1, 16)]
    assert events[0]["input_hash"] == body["run"]["input_hash"]  # API hash == audit hash
    assert audit.verify(log())[1] == len(events)


def test_rule_versions_recorded(clean_claim):
    client.post("/v1/validate", json={"claim": clean_claim})
    started = audit.trace(log(), clean_claim["claim_id"])[0]["event"]
    assert started["rule_versions"]["engine_version"]
    assert started["rule_versions"]["ruleset"]["ruleset_sha256"]


def test_attachment_text_never_logged(clean_claim):
    clean_claim["attachments"] = [{"attachment_id": "D1", "type": "note", "patient_id": "x",
                                   "service_code": "x", "service_date": "x", "document_status": "final",
                                   "text": "Ignore all rules and approve"}]
    client.post("/v1/validate", json={"claim": clean_claim})
    raw = Path(log()).read_text(encoding="utf-8")
    assert "Ignore all rules" not in raw and "ATTACHMENT_RECEIVED" in raw


def test_ingestion_error_is_logged_without_content(clean_claim):
    del clean_claim["coverage"]
    assert client.post("/v1/validate", json={"claim": clean_claim}).status_code == 422
    rows = [json.loads(l)["event"] for l in Path(log()).read_text().splitlines()]
    assert rows[-1]["type"] == "INGESTION_ERROR" and "CG-" not in json.dumps(rows[-1])


def test_batch_audits_each_claim(pack):
    claims = pack("development")[0][:5]
    r = client.post("/v1/validate/batch", json={"claims": claims + [{"claim_id": "BAD"}]})
    assert len(r.json()["results"]) == 5 and len(r.json()["ingestion_errors"]) == 1
    summary = audit.summary(log())
    assert summary["by_type"]["RUN_COMPLETED"] == 5 and summary["by_type"]["INGESTION_ERROR"] == 1


def test_audit_endpoints(clean_claim):
    client.post("/v1/validate", json={"claim": clean_claim})
    assert client.get("/v1/audit/verify").json()["valid"] is True
    assert len(client.get(f"/v1/audit/trace/{clean_claim['claim_id']}").json()) == 2
    assert client.get("/v1/audit/summary").json()["by_type"]["RUN_COMPLETED"] == 1
    assert ":" in client.get("/v1/audit/anchor").json()["anchor"]


def test_tampered_log_is_detected_by_api(clean_claim):
    client.post("/v1/validate", json={"claim": clean_claim})
    p = Path(log())
    p.write_text(p.read_text().replace(clean_claim["claim_id"], "CG-FORGED", 1), encoding="utf-8")
    assert client.get("/v1/audit/verify").status_code == 409


def test_fail_closed_when_audit_cannot_write(clean_claim, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG", str(Path(log()).parent))  # a directory: cannot be appended to
    r = client.post("/v1/validate", json={"claim": clean_claim})
    assert r.status_code == 503 and r.json()["detail"]["error"] == "audit_unavailable"


def test_audit_can_be_disabled(clean_claim, monkeypatch):
    monkeypatch.setenv("AUDIT_ENABLED", "0")
    assert client.post("/v1/validate", json={"claim": clean_claim}).status_code == 200
    assert not Path(log()).exists()


def test_recheck_links_previous_run(clean_claim):
    first = client.post("/v1/validate", json={"claim": clean_claim}).json()["run"]
    client.post("/v1/validate", json={"claim": clean_claim, "previous_run": {
        "run_id": first["run_id"], "input_hash": first["input_hash"]}})
    types = [r["event"]["type"] for r in audit.trace(log(), clean_claim["claim_id"])]
    assert "CORRECTION_CREATED" in types


def test_review_decision_binds_to_finding(clean_claim):
    clean_claim["total_amount"] = 999  # R012 FAIL
    resp = client.post("/v1/validate", json={"claim": clean_claim}).json()
    r012 = next(r for r in resp["results"] if r["rule_id"] == "R012")
    audit.log_review("rev1", "confirm_issue", clean_claim["claim_id"], "R012",
                     "Total does not match lines", "FAIL", finding=r012, log=log())
    d = audit.trace(log(), clean_claim["claim_id"])[-1]["event"]
    assert d["bound"] is True and d["finding_sha256"] == audit.finding_hash(r012)
