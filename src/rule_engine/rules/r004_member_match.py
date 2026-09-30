from ..domain.enums import Status
from .base import DEFAULT_PASS, decide, make


def evaluate(ctx):
    cov = ctx.raw.get("coverage") or {}
    pairs = [(ctx.raw.get("patient_id"), cov.get("beneficiary_patient_id")),
             (ctx.raw.get("member_id"), cov.get("member_id"))]
    mismatch = any(a is not None and b is not None and a != b for a, b in pairs)
    unable = any(a is None or b is None for a, b in pairs)
    st = decide(mismatch, unable)
    text = {Status.FAIL: "Patient or member identifier mismatch",
            Status.UNABLE_TO_ASSESS: "Identifier missing"}.get(st, DEFAULT_PASS)
    return make(ctx, "R004", st, text, ctx.ev(
        "/patient_id", "/coverage/beneficiary_patient_id", "/member_id", "/coverage/member_id"))
