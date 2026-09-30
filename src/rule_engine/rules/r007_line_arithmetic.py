from ..domain.enums import Status
from ..utils.decimal_utils import round2, to_decimal, within_tolerance
from .base import DEFAULT_PASS, decide, make


def evaluate(ctx):
    bad, unable, paths = [], False, []
    for i, ln in enumerate(ctx.lines):
        paths += [f"/lines/{i}/quantity", f"/lines/{i}/unit_price", f"/lines/{i}/net_amount"]
        q, p, n = (to_decimal(ln.get(k)) for k in ("quantity", "unit_price", "net_amount"))
        if q is None or p is None or n is None:
            unable = True
        elif not within_tolerance(round2(q * p), n):
            bad.append(ctx.line_id(i))
    st = decide(bool(bad), unable)
    text = {Status.FAIL: "Line amount differs from quantity times price",
            Status.UNABLE_TO_ASSESS: "Arithmetic input missing"}.get(st, DEFAULT_PASS)
    return make(ctx, "R007", st, text, ctx.ev(*paths), bad)
