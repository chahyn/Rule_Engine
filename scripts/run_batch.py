"""Run the rule engine on a claims file, write predictions AND the audit trail.

    python scripts/run_batch.py --input pack_data/stress/claims.jsonl --output outputs/stress_predictions.jsonl
    python scripts/run_batch.py --input ... --output ... --no-audit     # predictions only

The gold file is never read. Audit events (docs/AUDIT_INTEGRATION.md): FILE_RECEIVED, then per claim
RUN_STARTED (hash of the ORIGINAL line bytes) / ATTACHMENT_RECEIVED / RUN_COMPLETED (status + hash of
every rule finding), INGESTION_ERROR for rejected lines, and an anchor at the end.
"""
import argparse
import csv
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import audit  # noqa: E402
from rule_engine.core.engine import IngestionError, evaluate_claim  # noqa: E402
from rule_engine.stores.policy_store import PolicyStore  # noqa: E402
from rule_engine.version import ENGINE_VERSION  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--input", required=True)
ap.add_argument("--output", required=True)
ap.add_argument("--rules-dir", default=str(ROOT / "data" / "rules"))
ap.add_argument("--audit-log", default=str(ROOT / "outputs" / "audit.jsonl"))
ap.add_argument("--anchor-file", default=str(ROOT / "outputs" / "audit_anchors.txt"))
ap.add_argument("--no-audit", action="store_true")
a = ap.parse_args()

store = PolicyStore.from_dir(Path(a.rules_dir))
log = a.audit_log
use_audit = not a.no_audit
if use_audit:
    Path(log).parent.mkdir(parents=True, exist_ok=True)
    audit.verify(log)  # never append to a tampered log (raises AuditError)
    rule_versions = {"ruleset": audit.ruleset_fingerprint(a.rules_dir), "engine_version": ENGINE_VERSION}
    audit.log_file(a.input, "claims_input", log=log)

out = Path(a.output)
out.parent.mkdir(parents=True, exist_ok=True)
errors, n_claims, rows = [], 0, []
t0 = time.perf_counter()
raws = [l for l in Path(a.input).read_bytes().splitlines() if l.strip()]  # original bytes

with open(out, "w", encoding="utf-8") as fout:
    for lineno, raw_bytes in enumerate(raws, 1):
        src = f"{Path(a.input).name}:{lineno}"
        try:
            raw = json.loads(raw_bytes)
            results = [r.model_dump(mode="json") for r in evaluate_claim(raw, store)] if not use_audit else None
            if use_audit:
                from rule_engine.core.engine import check_envelope
                check_envelope(raw)
        except (json.JSONDecodeError, IngestionError) as e:
            errors.append({"line": lineno, "error": str(e), "details": getattr(e, "details", [])})
            if use_audit:
                audit.log_ingestion_error(src, type(e).__name__, log=log)
            continue
        if use_audit:
            run_id, _ = audit.run_started(raw["claim_id"], raw_bytes, rule_versions, log=log)
            audit.log_attachments(run_id, raw, log=log)
            try:
                results = [r.model_dump(mode="json") for r in evaluate_claim(raw, store)]
            except Exception as exc:
                audit.run_failed(run_id, raw["claim_id"], type(exc).__name__, log=log)
                errors.append({"line": lineno, "error": type(exc).__name__, "details": []})
                continue
        for d in results:
            fout.write(json.dumps(d, ensure_ascii=False) + "\n")
            rows.append([d["claim_id"], d["rule_id"], d["status"], ",".join(d["affected_line_ids"]),
                         d["explanation"], d["requires_human_review"]])
        if use_audit:
            audit.run_completed(run_id, raw["claim_id"], results, log=log)
        n_claims += 1

with open(out.with_suffix(".csv"), "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["claim_id", "rule_id", "status", "affected_line_ids", "explanation", "requires_human_review"])
    w.writerows(rows)

if errors:
    err_path = out.with_name(out.stem + "_ingestion_errors.json")
    err_path.write_text(json.dumps(errors, indent=2), encoding="utf-8")

print(f"claims processed: {n_claims}  results: {n_claims * 15}  ingestion errors: {len(errors)}")
print(f"time: {(time.perf_counter() - t0) * 1000:.0f} ms")
print(f"wrote {out} and {out.with_suffix('.csv')}")
if use_audit:
    print("audit anchor:", audit.save_anchor(log, a.anchor_file))
    print(f"audit log: {log}   (verify: python src/audit.py --verify --log {log} --expect-file {a.anchor_file})")
