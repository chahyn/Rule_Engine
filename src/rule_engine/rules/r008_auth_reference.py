from ..core.context import blank
from ..domain.enums import Status
from .base import DEFAULT_NA, DEFAULT_PASS, make, no_policy


def evaluate(ctx):
    if ctx.policy is None:
        return no_policy(ctx, "R008")
    paths, missing, unknown, required = [], [], False, 0
    for i, ln in enumerate(ctx.lines):
        paths += [f"/lines/{i}/service_code", f"/lines/{i}/authorization_id"]
        code = ln.get("service_code")
        if not ctx.known_service(code):
            unknown = True
        elif code in ctx.policy.auth_required_services:
            required += 1
            if blank(ln.get("authorization_id")):
                missing.append(ctx.line_id(i))
    ev = ctx.ev(*paths)
    if missing:
        return make(ctx, "R008", Status.FAIL, "Required authorization ID missing", ev, missing)
    if unknown:
        return make(ctx, "R008", Status.UNABLE_TO_ASSESS,
                    "Unknown service prevents authorization requirement lookup", ev)
    if required == 0:
        return make(ctx, "R008", Status.NOT_APPLICABLE, DEFAULT_NA, ev)
    return make(ctx, "R008", Status.PASS, DEFAULT_PASS, ev)
