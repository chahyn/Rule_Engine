"""Adapter between the rule engine and src/audit.py (hash-chained audit log).

The engine itself stays pure; this module wraps a validation in the audit events
described in docs/AUDIT_INTEGRATION.md: RUN_STARTED -> ATTACHMENT_RECEIVED* ->
RUN_COMPLETED (status + finding hash of EVERY rule), or INGESTION_ERROR / RUN_FAILED.

Policy is fail-closed: if the audit cannot be written, AuditError propagates and the
caller must NOT return unaudited results.

Environment:
    AUDIT_ENABLED=0   disable auditing (default: enabled)
    AUDIT_LOG=path    audit file (default: <repo>/outputs/audit.jsonl)
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Optional

_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:  # audit.py lives next to the package, in src/
    sys.path.insert(0, str(_SRC))

import audit  # noqa: E402
from audit import AuditError  # noqa: E402,F401  (re-exported for the API layer)

from .config import REPO_ROOT, RULES_DIR  # noqa: E402
from .core.engine import IngestionError, check_envelope, validate_claim  # noqa: E402
from .domain.policy import Policy  # noqa: E402
from .domain.result import ValidationResponse  # noqa: E402
from .stores.policy_store import PolicyStore  # noqa: E402
from .version import ENGINE_VERSION  # noqa: E402


def enabled() -> bool:
    return os.environ.get("AUDIT_ENABLED", "1") != "0"


def log_path() -> str:
    return os.environ.get("AUDIT_LOG", str(REPO_ROOT / "outputs" / "audit.jsonl"))


@lru_cache(maxsize=4)
def _fingerprint(rules_dir: str) -> dict:
    return audit.ruleset_fingerprint(rules_dir)


def rule_versions(policy_override: Optional[Policy] = None) -> dict:
    rv = {"ruleset": _fingerprint(str(RULES_DIR)), "engine_version": ENGINE_VERSION}
    if policy_override is not None:  # an inline policy changes the outcome: record it
        rv["policy_override_sha256"] = audit.digest(policy_override.model_dump(mode="json"))
    return rv


def audited_validate(raw: dict, store: PolicyStore,
                     policy_override: Optional[Policy] = None,
                     source: str = "api",
                     previous_run: Optional[tuple] = None) -> ValidationResponse:
    """Validate one claim and write its audit trail. `raw` should be the original envelope;
    audit hashes its canonical JSON (same value as run.input_hash in the response)."""
    if not enabled():
        return validate_claim(raw, store, policy_override)
    log = log_path()
    try:
        check_envelope(raw)
    except IngestionError:
        audit.log_ingestion_error(source, "IngestionError", log=log)  # never the claim content
        raise
    claim_id = raw["claim_id"]
    run_id, _ = audit.run_started(claim_id, raw, rule_versions(policy_override),
                                  previous_run=previous_run, log=log)
    audit.log_attachments(run_id, raw, log=log)  # hash + length only, never the text
    try:
        resp = validate_claim(raw, store, policy_override, run_id=run_id)
    except Exception as exc:
        audit.run_failed(run_id, claim_id, type(exc).__name__, log=log)
        raise
    audit.run_completed(run_id, claim_id, [r.model_dump(mode="json") for r in resp.results], log=log)
    return resp
