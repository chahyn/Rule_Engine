import json
from pathlib import Path

import pytest

from rule_engine.core.engine import evaluate_claim
from rule_engine.stores.policy_store import PolicyStore

ROOT = Path(__file__).resolve().parents[1]
PACK_DATA = ROOT / "pack_data"
RULES_DIR = ROOT / "data" / "rules"


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


@pytest.fixture(autouse=True)
def _isolated_audit(tmp_path, monkeypatch):
    """Tests never touch outputs/audit.jsonl: each test gets its own audit file."""
    monkeypatch.setenv("AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AUDIT_ENABLED", "1")


@pytest.fixture(scope="session")
def store() -> PolicyStore:
    return PolicyStore.from_dir(RULES_DIR)


@pytest.fixture(scope="session")
def pack():
    cache = {}

    def load(split: str):
        if split not in cache:
            d = PACK_DATA / split
            if not (d / "claims.jsonl").exists():
                pytest.skip(f"{d} not found")
            claims = read_jsonl(d / "claims.jsonl")
            gold = {(g["claim_id"], g["rule_id"]): g for g in read_jsonl(d / "expected_results.jsonl")}
            cache[split] = (claims, gold)
        return cache[split]
    return load


@pytest.fixture(scope="session")
def predictions(store, pack):
    cache = {}

    def run(split: str):
        if split not in cache:
            claims, _ = pack(split)
            out = {}
            for raw in claims:
                for r in evaluate_claim(raw, store):
                    d = r.model_dump(mode="json")
                    out[(d["claim_id"], d["rule_id"])] = d
            cache[split] = out
        return cache[split]
    return run


@pytest.fixture()
def clean_claim(pack):
    """First claim of the pack (a clean claim: all applicable checks pass)."""
    return json.loads(json.dumps(pack("development")[0][0]))
