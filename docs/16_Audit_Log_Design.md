# 16 | Audit log design (team deliverable)

Code: `src/audit.py` (library + CLI, standard library only), `src/run_baseline.py`, `src/audit_demo.py`.
Tests: `tests/test_audit_full.py` (20) next to the pack's own 11. Integration guide: `docs/AUDIT_INTEGRATION.md`.

## What the log proves

| Question | Event |
|---|---|
| Which file entered the system? | `FILE_RECEIVED` (name, size, SHA-256) |
| Which exact claim bytes, which rule files, which engine? | `RUN_STARTED` (hash of the original JSONL line, `ruleset_fingerprint`, engine version) |
| Which attachments came with a claim? | `ATTACHMENT_RECEIVED` (hash and length; text not stored) |
| Was each rule valid or not? | `RUN_COMPLETED`: `rule_results` = rule_id, status, rule_source, hash of the finding, for all rules |
| What did the model do? | `MODEL_CALL` (model, prompt-file hash, latency, error, fallback) |
| What failed? | `INGESTION_ERROR`, `RUN_FAILED`, `TOOL_ERROR` |
| What did a human decide, on what? | review event: action, actor, reason, original status, `run_id`, `finding_sha256`, `recheck_pending` |
| Was a claim corrected? | `CORRECTION_CREATED` linking the previous run and input hashes |
| Which measurements belong to which predictions? | `EVALUATION_COMPLETED` (hashes of predictions and metrics, frozen commit) |
| Was the log repaired? | `LOG_REPAIRED` (hash of the quarantined bytes) |

A human decision is bound to the finding recorded by the run. It is rejected when the reviewer's original status differs from the run, when the claim was never evaluated, or when the predictions file no longer matches the recorded finding hash. It never carries a rewritten status: a correction is a new input and a new run.

Claim contents, attachment text, prompts and raw model output are not logged. Secret-shaped fields and values (`api_key`, `sk-...`, `AKIA...`, `ghp_...`, Bearer, private keys) and very long texts are refused.

## Design choices

- Append cost is constant (only the last line is read and checked); `--verify` re-reads everything on demand.
- Writers are serialised with a lock file that carries an owner token. A lock older than 30 s is taken over by an atomic rename, and a writer checks that it still owns the lock before writing, so a stolen lock produces an error and no fork.
- An interrupted write leaves an incomplete last line. The log then refuses appends (fail-closed) until `--repair`, which quarantines the partial bytes, refuses to act if the complete part is not intact, and records `LOG_REPAIRED`.
- The `.idx` file is derived and checked on every read (numbers 1..N with no gap, N equals the log size); otherwise it is rebuilt from the log. `--trace` verifies the chain first; `--trace --fast` is a convenience that does not prove completeness.
- `--add` accepts only `INGESTION_ERROR`, `TOOL_ERROR`, `MODEL_CALL`, `RUN_FAILED`.

## Tamper demonstration (`python src/audit_demo.py`)

| Attack | Chain only | + anchor | + HMAC key |
|---|---|---|---|
| Edit the reviewer decision | detected | detected | n/a |
| Delete an event in the middle | detected | detected | n/a |
| Cut off the last events | missed | detected | n/a |
| Edit, then recompute every hash | missed | detected | n/a |
| Same forgery on a log written with the HMAC key | missed | detected | detected |

## Controls: implemented versus production

| Control | Status |
|---|---|
| Hash chain, typed events, mandatory actor / reason / original status, decisions bound to findings | Implemented |
| Secret and long-text refusal, no claim content in the log | Implemented (best effort) |
| Safe concurrent writers, interrupted-write repair | Implemented |
| External anchors (`N:HASH`) | Implemented as a tool; effective only if the anchor is kept outside the log's storage (another repository, message to the mentor) |
| Keyed HMAC per line (`CLAIMGUARD_AUDIT_HMAC_KEY`) | Implemented, optional; symmetric, so whoever holds the key can write |
| Authenticated reviewers | Not implemented: reviewer names are self-declared |
| Append-only, retention-locked storage (WORM), least-privilege writer | Not implemented |
| Asymmetric signatures, trusted timestamps, backups, controlled exports | Not implemented |
| Reviewer views and filters in the UI | Not captured; only exported decisions are |

The log is tamper-evident, not immutable: whoever controls the file can still delete it.

## Reference run

`python src/run_baseline.py` on the 400 development claims writes 1046 events (1 file, 400 run starts, 245 attachments, 400 run completions with 6000 rule results) in about 2 seconds, then records an anchor. Verification: `python src/audit.py --verify --expect-file outputs/audit_anchors.txt`.
