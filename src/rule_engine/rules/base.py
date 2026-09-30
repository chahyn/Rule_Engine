from __future__ import annotations

from typing import Iterable

from ..core.context import ClaimContext
from ..domain.enums import Status
from ..domain.result import Evidence, RuleResult

NEEDS_REVIEW = {Status.FAIL, Status.UNABLE_TO_ASSESS}
NO_POLICY = "No policy is supplied for this policy_id."
DEFAULT_PASS = "The supplied evidence satisfies this fictional rule."
DEFAULT_NA = "Rule does not apply to the supplied claim."


def make(ctx: ClaimContext, rule_id: str, status: Status, explanation: str,
         evidence: list[Evidence], affected: Iterable[str] = ()) -> RuleResult:
    meta = ctx.store.rules[rule_id]
    flagged = status in NEEDS_REVIEW
    return RuleResult(
        claim_id=ctx.claim_id, rule_id=rule_id, rule_version=meta.version,
        status=status, severity=meta.severity, affected_line_ids=list(affected),
        evidence=evidence, rule_source=meta.source, explanation=explanation,
        corrective_action=meta.corrective_action if flagged else "",
        requires_human_review=flagged)


def no_policy(ctx: ClaimContext, rule_id: str) -> RuleResult:
    return make(ctx, rule_id, Status.UNABLE_TO_ASSESS, NO_POLICY, ctx.ev("/policy_id"))


def decide(fail: bool, unable: bool, applicable: bool = True) -> Status:
    """Precedence: proven FAIL > UNABLE_TO_ASSESS > PASS / NOT_APPLICABLE."""
    if fail:
        return Status.FAIL
    if unable:
        return Status.UNABLE_TO_ASSESS
    return Status.PASS if applicable else Status.NOT_APPLICABLE
