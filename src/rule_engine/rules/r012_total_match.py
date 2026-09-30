from ..domain.enums import Status
from ..utils.decimal_utils import round2, to_decimal, within_tolerance
from .base import DEFAULT_PASS, decide, make


def evaluate(ctx):
    total = to_decimal(ctx.raw.get("total_amount"))
    nets = [to_decimal(ln.get("net_amount")) for ln in ctx.lines]
    paths = ["/total_amount"] + [f"/lines/{i}/net_amount" for i in range(len(ctx.lines))]
    if total is None or any(n is None for n in nets):
        return make(ctx, "R012", Status.UNABLE_TO_ASSESS, "Amount input missing", ctx.ev(*paths))
    if within_tolerance(round2(sum(nets)), total):
        return make(ctx, "R012", Status.PASS, DEFAULT_PASS, ctx.ev(*paths))
    return make(ctx, "R012", Status.FAIL, "Claim total differs from submitted line amounts",
                ctx.ev(*paths))
