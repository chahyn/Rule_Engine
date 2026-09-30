"""Score the engine against a gold file (doc 07 metrics + field-level diffs).

    python scripts/evaluate.py --split development
    python scripts/evaluate.py --claims X.jsonl --gold Y.jsonl --show 3
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rule_engine.core.engine import evaluate_claim  # noqa: E402
from rule_engine.stores.policy_store import PolicyStore  # noqa: E402


def read_jsonl(p):
    with open(p, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def ratio(n, d):
    return None if d == 0 else round(n / d, 4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="development")
    ap.add_argument("--claims"); ap.add_argument("--gold")
    ap.add_argument("--rules-dir", default=str(ROOT / "data" / "rules"))
    ap.add_argument("--show", type=int, default=0, help="print N mismatches per field/rule")
    ap.add_argument("--output", help="write metrics JSON here")
    a = ap.parse_args()

    claims_p = Path(a.claims or ROOT / "pack_data" / a.split / "claims.jsonl")
    gold_p = Path(a.gold or ROOT / "pack_data" / a.split / "expected_results.jsonl")
    store = PolicyStore.from_dir(Path(a.rules_dir))
    claims, gold = read_jsonl(claims_p), read_jsonl(gold_p)
    gold_map = {(g["claim_id"], g["rule_id"]): g for g in gold}

    t0 = time.perf_counter()
    pred = {}
    for c in claims:
        for r in evaluate_claim(c, store):
            d = r.model_dump(mode="json")
            pred[(d["claim_id"], d["rule_id"])] = d
    elapsed = time.perf_counter() - t0

    missing = set(gold_map) - set(pred)
    extra = set(pred) - set(gold_map)
    fields = ["status", "evidence", "affected_line_ids", "explanation",
              "corrective_action", "requires_human_review", "severity", "rule_source"]
    diffs = defaultdict(list)
    conf = Counter()
    per_rule = defaultdict(Counter)
    claim_ok = defaultdict(lambda: True)
    for k, g in gold_map.items():
        p = pred.get(k)
        if p is None:
            continue
        conf[(g["status"], p["status"])] += 1
        pr = per_rule[k[1]]
        pr["n"] += 1
        pr["status_ok"] += g["status"] == p["status"]
        if g["status"] != p["status"]:
            claim_ok[k[0]] = False
        for f in fields:
            gv = sorted(g[f]) if f == "affected_line_ids" else g[f]
            pv = sorted(p[f]) if f == "affected_line_ids" else p[f]
            if gv != pv:
                diffs[(f, k[1])].append((k[0], gv, pv))

    tp = conf[("FAIL", "FAIL")]
    pred_fail = sum(v for (g, p), v in conf.items() if p == "FAIL")
    exp_fail = sum(v for (g, p), v in conf.items() if g == "FAIL")
    nonfail = sum(v for (g, p), v in conf.items() if g != "FAIL")
    fa = sum(v for (g, p), v in conf.items() if g != "FAIL" and p == "FAIL")
    prec, rec = ratio(tp, pred_fail), ratio(tp, exp_fail)
    f1 = None if not prec or not rec else round(2 * prec * rec / (prec + rec), 4)
    n = sum(conf.values())
    U = "UNABLE_TO_ASSESS"
    metrics = {
        "pairs": n, "missing_pairs": len(missing), "extra_pairs": len(extra),
        "status_accuracy": ratio(sum(v for (g, p), v in conf.items() if g == p), n),
        "issue_precision": prec, "issue_recall": rec, "issue_f1": f1,
        "false_alarm_rate": ratio(fa, nonfail),
        "false_abstentions": sum(v for (g, p), v in conf.items() if p == U and g != U),
        "missed_abstentions": sum(v for (g, p), v in conf.items() if g == U and p != U),
        "claim_exact_match": ratio(sum(1 for c in claims if claim_ok[c["claim_id"]]), len(claims)),
        "field_mismatch_counts": {f"{f}:{r}": len(v) for (f, r), v in sorted(diffs.items())},
        "ms_per_claim": round(elapsed * 1000 / max(len(claims), 1), 3),
    }
    print(f"claims={len(claims)}  pairs={n}  missing={len(missing)}  extra={len(extra)}")
    for k in ["status_accuracy", "issue_precision", "issue_recall", "issue_f1",
              "false_alarm_rate", "false_abstentions", "missed_abstentions",
              "claim_exact_match", "ms_per_claim"]:
        print(f"  {k:20s} {metrics[k]}")
    print("\nper-rule status accuracy:")
    for r in sorted(per_rule):
        pr = per_rule[r]
        print(f"  {r}  {pr['status_ok']}/{pr['n']}")
    print("\nfield mismatches (field:rule -> count):")
    if not diffs:
        print("  none")
    for (f, r), v in sorted(diffs.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        print(f"  {f}:{r} -> {len(v)}")
        for cid, gv, pv in v[: a.show]:
            print(f"      {cid}\n        gold={json.dumps(gv)[:400]}\n        pred={json.dumps(pv)[:400]}")
    if a.output:
        Path(a.output).parent.mkdir(parents=True, exist_ok=True)
        Path(a.output).write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    ok = not missing and not extra and not diffs
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
