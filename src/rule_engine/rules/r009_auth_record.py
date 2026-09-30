from collections import defaultdict

from ..core.context import blank
from ..domain.enums import Status
from ..domain.result import Evidence
from ..utils.date_utils import parse_iso_date
from ..utils.decimal_utils import to_decimal
from .base import DEFAULT_NA, DEFAULT_PASS, make, no_policy


def evaluate(ctx):
    if ctx.policy is None:
        return no_policy(ctx, "R009")
    raw, auths = ctx.raw, ctx.raw.get("authorizations") or []
    by_id = {}
    for j, a in enumerate(auths):
        by_id.setdefault(a.get("authorization_id"), j)

    unknown, required = False, []
    for i, ln in enumerate(ctx.lines):
        code = ln.get("service_code")
        if not ctx.known_service(code):
            unknown = True
        elif code in ctx.policy.auth_required_services:
            required.append(i)

    # aggregate billed quantity per authorization id (shared authorizations)
    agg = defaultdict(lambda: 0)
    agg_ok = defaultdict(lambda: True)
    for i in required:
        aid = ctx.lines[i].get("authorization_id")
        q = to_decimal(ctx.lines[i].get("quantity"))
        if q is None:
            agg_ok[aid] = False
        else:
            agg[aid] += q

    fail_reasons, fail_lines, unable_reasons = [], [], []
    seen_auth: set = set()
    extras: dict[int, list[Evidence]] = {}
    for i in required:
        ln = ctx.lines[i]
        aid = ln.get("authorization_id")
        if blank(aid):
            unable_reasons.append("Cannot inspect authorization without an ID")
            continue
        j = by_id.get(aid)
        if j is None:
            fail_reasons.append("Referenced authorization not found")
            fail_lines.append(ctx.line_id(i))
            continue
        a = auths[j]
        reasons, unable_here, status_bad = [], False, False
        if a.get("patient_id") != raw.get("patient_id"):
            reasons.append("Authorization patient mismatch")
        if a.get("service_code") != ln.get("service_code"):
            reasons.append("Authorization service mismatch")
        if a.get("status") != "approved":
            reasons.append("Authorization status mismatch")
            status_bad = True
        sd = parse_iso_date(ln.get("service_date"))
        vf, vt = parse_iso_date(a.get("valid_from")), parse_iso_date(a.get("valid_to"))
        if sd is None or vf is None or vt is None:
            unable_here = True
        elif not (vf <= sd <= vt):
            reasons.append("Authorization dates do not cover service date")
        mq = to_decimal(a.get("max_quantity"))
        if mq is None or not agg_ok[aid]:
            unable_here = True
        elif agg[aid] > mq:
            reasons.append("Aggregate quantity exceeds authorization")
        block = []
        if j not in seen_auth:  # shared authorization: record quoted once
            seen_auth.add(j)
            block.append(Evidence(path=f"/authorizations/{j}", value=a))
            if status_bad:
                block += ctx.ev(f"/authorizations/{j}/status")
        block += ctx.ev(f"/lines/{i}/service_date")
        extras[i] = block
        if reasons:
            fail_reasons += reasons
            fail_lines.append(ctx.line_id(i))
        elif unable_here:
            unable_reasons.append("Authorization date input missing")

    first = min(extras) if extras else None
    evidence: list[Evidence] = []
    for i in range(len(ctx.lines)):
        evidence += ctx.ev(f"/lines/{i}/service_code", f"/lines/{i}/authorization_id")
        evidence += extras.get(i, [])
        if i == first:
            evidence += ctx.ev("/lines")

    if fail_reasons:
        return make(ctx, "R009", Status.FAIL, "; ".join(dict.fromkeys(fail_reasons)),
                    evidence, fail_lines)
    if unable_reasons or unknown:
        text = ("; ".join(dict.fromkeys(unable_reasons)) if unable_reasons
                else "Unknown service prevents authorization requirement lookup")
        return make(ctx, "R009", Status.UNABLE_TO_ASSESS, text, evidence)
    if not required:
        return make(ctx, "R009", Status.NOT_APPLICABLE, DEFAULT_NA, evidence)
    return make(ctx, "R009", Status.PASS, DEFAULT_PASS, evidence)
