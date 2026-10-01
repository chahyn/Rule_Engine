import io
import os

import audit
from fastapi.testclient import TestClient
from pypdf import PdfReader

from rule_engine.main import app
from rule_engine.reporting.findings import FindingReport

client = TestClient(app)


def log():
    return os.environ["AUDIT_LOG"]


def test_report_json_endpoint(clean_claim):
    r = client.post("/v1/report/json", json={"claim": clean_claim})
    assert r.status_code == 200
    rep = FindingReport.model_validate(r.json())
    assert len(rep.findings) == 15 and rep.claim.claim_id == clean_claim["claim_id"]


def test_report_pdf_endpoint(clean_claim):
    r = client.post("/v1/report/pdf", json={"claim": clean_claim})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    assert f'claimguard_{clean_claim["claim_id"]}.pdf' in r.headers["content-disposition"]
    assert len(PdfReader(io.BytesIO(r.content)).pages) >= 1


def test_filename_is_sanitised(clean_claim):
    clean_claim["claim_id"] = 'CG-1"; filename=evil.exe/../x'
    r = client.post("/v1/report/pdf", json={"claim": clean_claim})
    disposition = r.headers["content-disposition"]
    assert r.status_code == 200 and "/" not in disposition and "evil.exe" not in disposition.split("filename=")[0]
    assert disposition.count('"') == 2


def test_report_is_audited_and_traceable(clean_claim):
    rep = client.post("/v1/report/json", json={"claim": clean_claim}).json()
    events = [r["event"] for r in audit.trace(log(), clean_claim["claim_id"])]
    assert events[-1]["type"] == "RUN_COMPLETED" and events[-1]["run_id"] == rep["run"]["run_id"]


def test_malformed_claim_gives_422_and_no_report(clean_claim):
    del clean_claim["lines"]
    for path in ("/v1/report/json", "/v1/report/pdf"):
        r = client.post(path, json={"claim": clean_claim})
        assert r.status_code == 422 and r.json()["detail"]["error"] == "ingestion_error"


def test_fail_closed_when_audit_unavailable(clean_claim, monkeypatch):
    from pathlib import Path
    monkeypatch.setenv("AUDIT_LOG", str(Path(log()).parent))
    assert client.post("/v1/report/pdf", json={"claim": clean_claim}).status_code == 503


def test_works_with_audit_disabled(clean_claim, monkeypatch):
    monkeypatch.setenv("AUDIT_ENABLED", "0")
    assert client.post("/v1/report/pdf", json={"claim": clean_claim}).status_code == 200
