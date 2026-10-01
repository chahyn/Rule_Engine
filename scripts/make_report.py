"""Generate structured findings reports (JSON + PDF) from a claims file.

    python scripts/make_report.py --input pack_data/development/claims.jsonl --claim-id CG-27BFD8541DEB
    python scripts/make_report.py --input pack_data/stress/claims.jsonl --all --only-flagged --combined
    python scripts/make_report.py --input ... --all --limit 20 --output-dir outputs/reports --no-audit

Each claim is validated through the audited path (unless --no-audit), so the report's run_id
can be traced with:  python src/audit.py --trace <CLAIM_ID>
Outputs: <output-dir>/<claim_id>.pdf and <claim_id>.json, plus batch_report.pdf with --combined.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

ap = argparse.ArgumentParser()
ap.add_argument("--input", required=True, help="claims JSONL")
ap.add_argument("--claim-id", action="append", default=[], help="repeatable")
ap.add_argument("--all", action="store_true", help="every claim in the file")
ap.add_argument("--limit", type=int, help="with --all: first N claims only")
ap.add_argument("--only-flagged", action="store_true", help="skip claims with no FAIL / UNABLE_TO_ASSESS")
ap.add_argument("--combined", action="store_true", help="also write one batch_report.pdf")
ap.add_argument("--no-json", action="store_true")
ap.add_argument("--no-pdf", action="store_true", help="with --combined: only the batch PDF")
ap.add_argument("--no-audit", action="store_true")
ap.add_argument("--output-dir", default=str(ROOT / "outputs" / "reports"))
ap.add_argument("--rules-dir", default=str(ROOT / "data" / "rules"))
a = ap.parse_args()

if a.no_audit:
    os.environ["AUDIT_ENABLED"] = "0"
if not a.all and not a.claim_id:
    ap.error("choose --all or at least one --claim-id")

from rule_engine.core.engine import IngestionError  # noqa: E402
from rule_engine.reporting.pdf_report import render_batch_pdf, render_claim_pdf  # noqa: E402
from rule_engine.reporting.service import validate_and_report  # noqa: E402
from rule_engine.stores.policy_store import PolicyStore  # noqa: E402

store = PolicyStore.from_dir(Path(a.rules_dir))
out = Path(a.output_dir)
out.mkdir(parents=True, exist_ok=True)
wanted = set(a.claim_id)
reports, skipped, errors, n = [], 0, 0, 0

with open(a.input, encoding="utf-8") as f:
    for lineno, line in enumerate(f, 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            errors += 1
            continue
        cid = raw.get("claim_id") if isinstance(raw, dict) else None
        if not a.all and cid not in wanted:
            continue
        if a.all and a.limit is not None and n >= a.limit:
            break
        n += 1
        try:
            rep = validate_and_report(raw, store, source=f"{Path(a.input).name}:{lineno}")
        except IngestionError as e:
            errors += 1
            print(f"  line {lineno}: ingestion error ({e}); no report")
            continue
        if a.only_flagged and not rep.escalation.required:
            skipped += 1
            continue
        reports.append(rep)
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", rep.claim.claim_id)
        if not a.no_json:
            (out / f"{safe}.json").write_text(rep.model_dump_json(indent=2), encoding="utf-8")
        if not a.no_pdf:
            (out / f"{safe}.pdf").write_bytes(render_claim_pdf(rep))

if a.combined and reports:
    (out / "batch_report.pdf").write_bytes(render_batch_pdf(reports))
if wanted and not a.all and not a.only_flagged:
    for m in sorted(wanted - {r.claim.claim_id for r in reports}):
        print(f"  claim not found in {Path(a.input).name}: {m}")

print(f"reports written: {len(reports)}  skipped (no issues): {skipped}  errors: {errors}")
print(f"output folder: {out}")
