from ..domain.enums import Status
from ..utils.date_utils import parse_iso_date
from .base import decide, make

PASS_TEXT = "All service dates are within active coverage, including boundaries."


def evaluate(ctx):
    cov = ctx.raw.get("coverage") or {}
    status = cov.get("status")
    start, end = parse_iso_date(cov.get("start_date")), parse_iso_date(cov.get("end_date"))
    paths = ["/coverage/status", "/coverage/start_date", "/coverage/end_date"] + [
        f"/lines/{i}/service_date" for i in range(len(ctx.lines))]

    reasons, out_of_period, unable_reasons = [], [], []
    if status is not None and status != "active":
        reasons.append("coverage status is not active")
    elif status is None:
        unable_reasons.append("coverage status")
    for i, ln in enumerate(ctx.lines):
        d = parse_iso_date(ln.get("service_date"))
        if d is None:
            if "service date" not in unable_reasons:
                unable_reasons.append("service date")
        elif start is not None and end is not None and not (start <= d <= end):
            out_of_period.append(ctx.line_id(i))
        elif start is not None and d < start or end is not None and d > end:
            out_of_period.append(ctx.line_id(i))
    if start is None or end is None:
        unable_reasons.insert(0, "coverage period")
    if out_of_period:
        reasons.append("service outside coverage period")

    if reasons:
        return make(ctx, "R003", Status.FAIL, "; ".join(reasons), ctx.ev(*paths), out_of_period)
    if unable_reasons:
        return make(ctx, "R003", Status.UNABLE_TO_ASSESS, "; ".join(dict.fromkeys(unable_reasons)),
                    ctx.ev(*paths))
    return make(ctx, "R003", Status.PASS, PASS_TEXT, ctx.ev(*paths))
