from fastapi import APIRouter, HTTPException

from .. import audit_hook
from ..audit_hook import AuditError, audit

router = APIRouter(prefix="/v1/audit", tags=["audit"])


def _check():
    if not audit_hook.enabled():
        raise HTTPException(status_code=404, detail="audit is disabled (AUDIT_ENABLED=0)")


@router.get("/verify")
def verify():
    """Re-read and verify the whole hash chain. 409 if it was tampered with."""
    _check()
    try:
        head, n = audit.verify(audit_hook.log_path())
    except AuditError as e:
        raise HTTPException(status_code=409, detail={"valid": False, "error": str(e)})
    return {"valid": True, "events": n, "head": head,
            "note": "Keep a trusted copy of this head outside the log to detect replacement or truncation."}


@router.get("/trace/{claim_id}")
def trace(claim_id: str, fast: bool = False):
    """Full history of one claim (chain verified first unless fast=true)."""
    _check()
    try:
        return audit.trace(audit_hook.log_path(), claim_id, verify_chain=not fast)
    except AuditError as e:
        raise HTTPException(status_code=409, detail={"valid": False, "error": str(e)})


@router.get("/summary")
def summary():
    _check()
    try:
        audit.verify(audit_hook.log_path())
        return audit.summary(audit_hook.log_path())
    except FileNotFoundError:
        return {"events": 0, "by_type": {}, "rule_results_by_status": {}, "human_decisions": {}}
    except AuditError as e:
        raise HTTPException(status_code=409, detail={"valid": False, "error": str(e)})


@router.get("/anchor")
def anchor():
    """'N:HASH' line to copy OUTSIDE the log (another repo, message to the mentor)."""
    _check()
    try:
        return {"anchor": audit.anchor_line(audit_hook.log_path())}
    except AuditError as e:
        raise HTTPException(status_code=409, detail={"valid": False, "error": str(e)})
