from ..domain.enums import Status
from .base import DEFAULT_PASS, make, no_policy


def evaluate(ctx):
    if ctx.policy is None:
        return no_policy(ctx, "R015")
    cur, ev = ctx.raw.get("currency"), ctx.ev("/currency", "/policy_id")
    if cur is None or cur == "":
        return make(ctx, "R015", Status.UNABLE_TO_ASSESS, "Currency missing", ev)
    if cur != ctx.policy.currency:
        return make(ctx, "R015", Status.FAIL, "Currency differs from policy", ev)
    return make(ctx, "R015", Status.PASS, DEFAULT_PASS, ev)
