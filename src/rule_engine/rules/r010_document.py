from ..core.context import blank
from ..domain.enums import Status
from ..utils.date_utils import parse_iso_date
from .base import DEFAULT_NA, DEFAULT_PASS, make, no_policy


def evaluate(ctx):
    if ctx.policy is None:
        return no_policy(ctx, "R010")
    pid, atts = ctx.raw.get("patient_id"), ctx.raw.get("attachments") or []
    paths, missing, unknown, draft, no_date, required = ["/attachments"], [], False, False, False, 0
    for i, ln in enumerate(ctx.lines):
        code = ln.get("service_code")
        paths.append(f"/lines/{i}/service_code")
        if not ctx.known_service(code):
            unknown = True
            continue
        doc_type = ctx.policy.required_documents.get(code)
        if doc_type is None:
            continue
        required += 1
        paths.append(f"/lines/{i}/service_date")
        if parse_iso_date(ln.get("service_date")) is None:
            no_date = True
            continue
        matches = [a for a in atts if a.get("type") == doc_type and a.get("patient_id") == pid
                   and a.get("service_code") == code and a.get("service_date") == ln.get("service_date")]
        if not matches:
            missing.append(ctx.line_id(i))
        elif not any(a.get("document_status") == "final" for a in matches):
            draft = True
    ev = ctx.ev(*paths)
    if missing:
        return make(ctx, "R010", Status.FAIL, "Matching required document absent", ev, missing)
    if unknown:
        return make(ctx, "R010", Status.UNABLE_TO_ASSESS,
                    "Unknown service prevents document requirement lookup", ev)
    if no_date:
        return make(ctx, "R010", Status.UNABLE_TO_ASSESS, "Service date required to match document", ev)
    if draft:
        return make(ctx, "R010", Status.UNABLE_TO_ASSESS,
                    "Only draft or uncertain matching documentation", ev)
    if required == 0:
        return make(ctx, "R010", Status.NOT_APPLICABLE, DEFAULT_NA, ev)
    return make(ctx, "R010", Status.PASS, DEFAULT_PASS, ev)
