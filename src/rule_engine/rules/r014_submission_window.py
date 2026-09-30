from ..domain.enums import Status
from ..utils.date_utils import parse_iso_date
from .base import DEFAULT_NA, DEFAULT_PASS, make, no_policy


def evaluate(ctx):
    if ctx.policy is None:
        return no_policy(ctx, "R014")
    paths = ["/submission_date", "/policy_id"] + [
        f"/lines/{i}/service_date" for i in range(len(ctx.lines))]
    ev = ctx.ev(*paths)
    sub = parse_iso_date(ctx.raw.get("submission_date"))
    dates = [parse_iso_date(ln.get("service_date")) for ln in ctx.lines]
    if sub is None or any(d is None for d in dates):
        return make(ctx, "R014", Status.UNABLE_TO_ASSESS, "Date missing", ev)
    lag = (sub - max(dates)).days
    if lag < 0:
        return make(ctx, "R014", Status.NOT_APPLICABLE, DEFAULT_NA, ev)
    if lag > ctx.policy.submission_window_days:
        return make(ctx, "R014", Status.FAIL, "Submission exceeds fictional window", ev)
    return make(ctx, "R014", Status.PASS, DEFAULT_PASS, ev)
