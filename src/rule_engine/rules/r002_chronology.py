from ..domain.enums import Status
from ..utils.date_utils import parse_iso_date
from .base import DEFAULT_PASS, decide, make


def evaluate(ctx):
    sub = parse_iso_date(ctx.raw.get("submission_date"))
    paths = ["/submission_date"] + [f"/lines/{i}/service_date" for i in range(len(ctx.lines))]
    bad_lines, unable = [], sub is None
    for i, ln in enumerate(ctx.lines):
        d = parse_iso_date(ln.get("service_date"))
        if d is None:
            unable = True
        elif sub is not None and d > sub:
            bad_lines.append(ctx.line_id(i))
    st = decide(bool(bad_lines), unable)
    text = {Status.FAIL: "Service occurs after submission",
            Status.UNABLE_TO_ASSESS: "Date unavailable"}.get(st, DEFAULT_PASS)
    return make(ctx, "R002", st, text, ctx.ev(*paths), bad_lines)
