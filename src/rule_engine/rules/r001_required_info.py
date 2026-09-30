from ..core.context import blank
from ..domain.enums import Status
from .base import decide, make

TOP = ("invoice_number", "member_id", "diagnosis_code")
LINE = ("service_date", "service_code", "quantity", "unit_price", "net_amount")


def evaluate(ctx):
    missing, affected = [], []
    for f in TOP:
        if blank(ctx.raw.get(f)):
            missing.append(f"/{f}")
    for i, ln in enumerate(ctx.lines):
        for f in LINE:
            if blank(ln.get(f)):
                missing.append(f"/lines/{i}/{f}")
                affected.append(ctx.line_id(i))
    if missing:
        return make(ctx, "R001", Status.FAIL, "Required information is missing.",
                    ctx.ev(*missing), affected)
    return make(ctx, "R001", Status.PASS, "Required information is present.",
                ctx.ev("/invoice_number", "/member_id", "/diagnosis_code", "/lines"))
