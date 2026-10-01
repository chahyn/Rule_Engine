import re

from fastapi import APIRouter, Depends, HTTPException, Response

from ..audit_hook import AuditError
from ..core.engine import IngestionError
from ..reporting.findings import FindingReport
from ..reporting.pdf_report import render_claim_pdf
from ..reporting.service import validate_and_report
from .deps import get_store
from .schemas import ValidateRequest

router = APIRouter(prefix="/v1/report", tags=["report"])


def _report(req: ValidateRequest, store, source: str) -> FindingReport:
    prev = (req.previous_run.run_id, req.previous_run.input_hash) if req.previous_run else None
    try:
        return validate_and_report(req.claim, store, req.policy_override, source=source, previous_run=prev)
    except IngestionError as e:
        raise HTTPException(status_code=422, detail={
            "error": "ingestion_error", "message": str(e), "details": e.details})
    except (AuditError, OSError) as e:  # fail-closed: nothing is returned that was not audited
        raise HTTPException(status_code=503, detail={"error": "audit_unavailable", "message": str(e)})


@router.post("/json", response_model=FindingReport)
def report_json(req: ValidateRequest, store=Depends(get_store)):
    """Validate the claim and return the structured findings (machine-readable)."""
    return _report(req, store, "api:/v1/report/json")


@router.post("/pdf")
def report_pdf(req: ValidateRequest, store=Depends(get_store)):
    """Validate the claim and return the findings report as a PDF file."""
    rep = _report(req, store, "api:/v1/report/pdf")
    try:
        pdf = render_claim_pdf(rep)
    except Exception as e:  # rendering must never leak a stack trace or half a file
        raise HTTPException(status_code=500, detail={"error": "report_render_failed", "message": type(e).__name__})
    name = re.sub(r"[^A-Za-z0-9_-]", "_", rep.claim.claim_id)[:60]
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="claimguard_{name}.pdf"'})
