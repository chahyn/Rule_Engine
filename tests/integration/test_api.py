import json

from fastapi.testclient import TestClient

from rule_engine.main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_validate_returns_15_results_and_run_metadata(clean_claim):
    r = client.post("/v1/validate", json={"claim": clean_claim})
    assert r.status_code == 200
    body = r.json()
    assert len(body["results"]) == 15
    assert len(body["run"]["input_hash"]) == 64 and body["run"]["policy_id"] == clean_claim["policy_id"]


def test_validate_is_deterministic_for_same_input(clean_claim):
    a = client.post("/v1/validate", json={"claim": clean_claim}).json()
    b = client.post("/v1/validate", json={"claim": clean_claim}).json()
    assert a["results"] == b["results"] and a["run"]["input_hash"] == b["run"]["input_hash"]


def test_malformed_claim_is_422_not_pass(clean_claim):
    del clean_claim["coverage"]
    r = client.post("/v1/validate", json={"claim": clean_claim})
    assert r.status_code == 422 and r.json()["detail"]["error"] == "ingestion_error"


def test_batch_separates_ingestion_errors(clean_claim):
    r = client.post("/v1/validate/batch", json={"claims": [clean_claim, {"claim_id": "BAD"}]})
    body = r.json()
    assert r.status_code == 200 and len(body["results"]) == 1
    assert body["ingestion_errors"][0]["index"] == 1 and body["ingestion_errors"][0]["claim_id"] == "BAD"


def test_catalog_endpoints():
    assert len(client.get("/v1/rules").json()) == 15
    assert client.get("/v1/policies/EDU-PLUS").status_code == 200
    assert client.get("/v1/policies/NOPE").status_code == 404
