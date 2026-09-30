"""Engine output vs the pack's expected_results.jsonl, field by field."""
import pytest

RULE_IDS = [f"R{i:03d}" for i in range(1, 16)]
SPLITS = ["development", "validation", "stress"]
FIELDS = ["status", "evidence", "affected_line_ids", "explanation",
          "corrective_action", "requires_human_review", "severity", "rule_source"]


def _norm(field, v):
    return sorted(v) if field == "affected_line_ids" else v


@pytest.mark.parametrize("split", SPLITS)
def test_complete_and_exact_pairs(split, pack, predictions):
    _, gold = pack(split)
    pred = predictions(split)
    assert set(pred) == set(gold), "missing or extra claim-rule pairs"


@pytest.mark.parametrize("split", SPLITS)
@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_field_matches_gold(split, field, rule_id, pack, predictions):
    _, gold = pack(split)
    pred = predictions(split)
    bad = [(cid, _norm(field, g[field]), _norm(field, pred[(cid, rid)][field]))
           for (cid, rid), g in gold.items()
           if rid == rule_id and _norm(field, g[field]) != _norm(field, pred[(cid, rid)][field])]
    if bad:
        head = "\n".join(f"  {c}: expected={e!r:.200} got={g!r:.200}" for c, e, g in bad[:5])
        pytest.fail(f"{rule_id}.{field} ({split}): {len(bad)} mismatches\n{head}")


def test_no_result_uses_not_implemented(predictions):
    assert all(p["status"] != "NOT_IMPLEMENTED" for p in predictions("development").values())


def test_deterministic_confidence_fields(predictions):
    for p in predictions("development").values():
        assert p["confidence"] is None and p["confidence_kind"] == "not_probabilistic"
        assert p["method"] == "deterministic" and p["review_status"] == "unreviewed"
