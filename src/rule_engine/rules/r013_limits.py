from ..domain.enums import Status
from ..utils.decimal_utils import is_positive_integer, to_decimal
from .base import DEFAULT_PASS, make, no_policy


def evaluate(ctx):
    if ctx.policy is None:
        return no_policy(ctx, "R013")
    pol, bad, msgs, unable_msgs, paths = ctx.policy, [], set(), [], []
    for i, ln in enumerate(ctx.lines):
        paths += [f"/lines/{i}/quantity", f"/lines/{i}/unit_price", f"/lines/{i}/service_code"]
        code, q_raw = ln.get("service_code"), ln.get("quantity")
        q, p = to_decimal(q_raw), to_decimal(ln.get("unit_price"))
        line_bad = False
        if q is not None and not is_positive_integer(q_raw):
            msgs.add("Quantity must be a positive integer"); line_bad = True
        if p is not None and p <= 0:
            msgs.add("Price must be greater than zero"); line_bad = True
        max_p, max_q = pol.max_unit_price.get(code), pol.max_quantity_per_line.get(code)
        if max_p is None or max_q is None:
            unable_msgs.append("Unknown service limits")
        else:
            if p is not None and p > to_decimal(max_p):
                msgs.add("Price exceeds fictional maximum"); line_bad = True
            if q is not None and q > to_decimal(max_q):
                msgs.add("Quantity exceeds fictional maximum"); line_bad = True
        if q is None or p is None:
            unable_msgs.append("Quantity or price missing")
        if line_bad:
            bad.append(ctx.line_id(i))
    ev = ctx.ev(*paths)
    if bad:
        return make(ctx, "R013", Status.FAIL, "; ".join(sorted(msgs)), ev, bad)
    if unable_msgs:
        return make(ctx, "R013", Status.UNABLE_TO_ASSESS,
                    "; ".join(dict.fromkeys(sorted(unable_msgs, key=lambda m: m != "Unknown service limits"))), ev)
    return make(ctx, "R013", Status.PASS, DEFAULT_PASS, ev)
