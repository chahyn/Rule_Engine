from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import ValidationError

from ..domain.claim import Claim
from ..domain.enums import Status
from ..domain.policy import Policy
from ..domain.result import RuleResult, RunMetadata, ValidationResponse
from ..stores.policy_store import PolicyStore
from ..version import ENGINE_VERSION
from .context import ClaimContext
from .hashing import input_hash
from .registry import RULES


class IngestionError(ValueError):
    """Structural (transport-contract) problem: never a silent PASS."""

    def __init__(self, message: str, details: Optional[list] = None):
        super().__init__(message)
        self.details = details or []


def _guard(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise IngestionError("claim envelope must be a JSON object")
    try:
        Claim.model_validate(raw)
    except ValidationError as e:
        raise IngestionError("claim envelope violates transport contract",
                             [{"loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()])
    return raw


def evaluate_claim(raw: dict, store: PolicyStore,
                   policy_override: Optional[Policy] = None) -> list[RuleResult]:
    """Exactly 15 results, one per rule, in R001..R015 order."""
    _guard(raw)
    policy = policy_override or store.get(raw["policy_id"])
    ctx = ClaimContext(raw=raw, policy=policy, store=store)
    results = [fn(ctx) for fn in RULES.values()]
    assert len(results) == 15 and all(r.status != Status.NOT_IMPLEMENTED for r in results)
    return results


def validate_claim(raw: dict, store: PolicyStore,
                   policy_override: Optional[Policy] = None) -> ValidationResponse:
    started, t0 = datetime.now(timezone.utc), time.perf_counter()
    results = evaluate_claim(raw, store, policy_override)
    policy = policy_override or store.get(raw["policy_id"])
    run = RunMetadata(
        run_id=str(uuid.uuid4()), input_hash=input_hash(raw), engine_version=ENGINE_VERSION,
        rule_versions={rid: m.version for rid, m in store.rules.items()},
        policy_id=raw["policy_id"], policy_version=policy.version if policy else None,
        started_at=started, duration_ms=round((time.perf_counter() - t0) * 1000, 3))
    return ValidationResponse(claim_id=raw["claim_id"], results=results, run=run)
