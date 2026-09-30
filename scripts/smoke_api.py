"""Send every claim of a split to the running API and compare with the gold file.
Usage: python scripts/smoke_api.py development
"""
import json
import sys
import urllib.request
from pathlib import Path

split = sys.argv[1] if len(sys.argv) > 1 else "development"
root = Path(__file__).resolve().parents[1] / "pack_data" / split
claims = [json.loads(l) for l in open(root / "claims.jsonl", encoding="utf-8") if l.strip()]
gold = {(g["claim_id"], g["rule_id"]): g
        for g in (json.loads(l) for l in open(root / "expected_results.jsonl", encoding="utf-8") if l.strip())}

req = urllib.request.Request(
    "http://127.0.0.1:8000/v1/validate/batch",
    data=json.dumps({"claims": claims}).encode(),
    headers={"Content-Type": "application/json"})
body = json.load(urllib.request.urlopen(req))

pred = {(r["claim_id"], r["rule_id"]): r for resp in body["results"] for r in resp["results"]}
fields = ["status", "evidence", "affected_line_ids", "explanation",
          "corrective_action", "requires_human_review", "severity", "rule_source"]

def norm(f, v):
    return sorted(v) if f == "affected_line_ids" else v

bad = [(k, f) for k, g in gold.items() for f in fields
       if k not in pred or norm(f, g[f]) != norm(f, pred[k][f])]
print(f"claims sent: {len(claims)}  results: {len(pred)}  expected: {len(gold)}")
print(f"ingestion errors: {len(body['ingestion_errors'])}")
print(f"field mismatches: {len(bad)}")
for k, f in bad[:10]:
    print("  ", k, f)
print("OK" if not bad and len(pred) == len(gold) else "MISMATCH")