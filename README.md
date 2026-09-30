# ClaimGuard Rule Engine

Independent, stateless, deterministic rule-engine service for the ClaimGuard AI challenge.
Implements the 15 fictional payer rules (R001-R015) and exposes them over a REST API.
Ingestion, audit/log, review UI and AI explanation live in other modules and talk to this one over HTTP.

## Install and run

```bash
python -m venv .venv && source .venv/bin/activate      # Windows Git Bash: source .venv/Scripts/activate
pip install -e . pytest httpx
uvicorn rule_engine.main:app --reload                   # docs at http://127.0.0.1:8000/docs
```

## Data

Rules, policies and catalogue are read from `data/rules/` (`RULES_DIR` env var overrides).
Copy the pack splits you want to score into `pack_data/<split>/` (`claims.jsonl`, `expected_results.jsonl`).

## API

| Endpoint | Purpose |
|---|---|
| `POST /v1/validate` | `{claim, policy_override?}` -> `{claim_id, results[15], run}`; 422 on ingestion error |
| `POST /v1/validate/batch` | `{claims[]}` -> `{results[], ingestion_errors[]}` |
| `GET /v1/rules` | Rule catalogue |
| `GET /v1/policies/{id}` | Policy in use (404 if unknown) |
| `GET /health` | Liveness + versions |

`run` = `run_id`, `input_hash` (SHA-256 of canonical claim JSON), `engine_version`, `rule_versions`,
`policy_id`, `policy_version`, `started_at`, `duration_ms`: what your audit module should log.

## Score and test

```bash
python scripts/evaluate.py --split development --show 2      # metrics + field diffs vs gold
python scripts/evaluate.py --split validation --output outputs/val_metrics.json
python -m pytest -q
```

Develop on `development`; freeze a commit before the first `validation` run (doc 07).

## Design rules

- Rules read the original claim dict; evidence values are never taken from transformed copies.
- Precedence: FAIL > UNABLE_TO_ASSESS > PASS / NOT_APPLICABLE. `NOT_IMPLEMENTED` is never emitted.
- Decimal + ROUND_HALF_UP, 0.01 tolerance inclusive, inclusive date ranges, case-sensitive IDs.
- Unknown policy -> UNABLE_TO_ASSESS on dependent rules. Structural problems -> `IngestionError` / HTTP 422.
- Attachment text and notes are never interpreted.
