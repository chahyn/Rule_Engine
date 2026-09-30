from ..core.context import blank
from ..domain.enums import Status
from .base import DEFAULT_PASS, decide, make


def evaluate(ctx):
    bad, unable = [], False
    for i, ln in enumerate(ctx.lines):
        code = ln.get("service_code")
        if blank(code):
            unable = True
        elif not ctx.known_service(code):
            bad.append(ctx.line_id(i))
    st = decide(bool(bad), unable)
    text = {Status.FAIL: "Service code not in fictional catalogue",
            Status.UNABLE_TO_ASSESS: "Service code missing"}.get(st, DEFAULT_PASS)
    return make(ctx, "R011", st, text,
                ctx.ev(*[f"/lines/{i}/service_code" for i in range(len(ctx.lines))]), bad)
