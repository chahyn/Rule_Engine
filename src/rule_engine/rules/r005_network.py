from ..domain.enums import Status
from .base import DEFAULT_PASS, make, no_policy


def evaluate(ctx):
    if ctx.policy is None:
        return no_policy(ctx, "R005")
    prov = ctx.raw.get("provider_id")
    ev = ctx.ev("/provider_id", "/policy_id")
    if prov is None or prov == "":
        return make(ctx, "R005", Status.UNABLE_TO_ASSESS, "Provider missing", ev)
    if prov not in ctx.policy.allowed_providers:
        return make(ctx, "R005", Status.FAIL, "Provider absent from supplied network", ev)
    return make(ctx, "R005", Status.PASS, DEFAULT_PASS, ev)
