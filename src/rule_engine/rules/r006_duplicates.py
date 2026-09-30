from collections import defaultdict

from ..domain.enums import Status
from .base import make

PASS_TEXT = "No duplicate service/date/modifier combinations."


def evaluate(ctx):
    groups, incomplete = defaultdict(list), False
    for i, ln in enumerate(ctx.lines):
        code, date = ln.get("service_code"), ln.get("service_date")
        if code in (None, "") or date in (None, ""):
            incomplete = True
            continue
        groups[(code, date, ln.get("modifier") or "")].append(i)
    dup_idx = sorted(i for g in groups.values() if len(g) > 1 for i in g)
    if dup_idx:
        paths = [f"/lines/{i}/{f}" for i in dup_idx for f in ("service_code", "service_date", "modifier")]
        return make(ctx, "R006", Status.FAIL, "Possible duplicate lines require review.",
                    ctx.ev(*paths), [ctx.line_id(i) for i in dup_idx])
    if incomplete:
        return make(ctx, "R006", Status.UNABLE_TO_ASSESS,
                    "Missing inputs prevent a complete duplicate check.", ctx.ev("/lines"))
    return make(ctx, "R006", Status.PASS, PASS_TEXT, ctx.ev("/lines"))
