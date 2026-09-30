from fastapi import APIRouter, Depends, HTTPException

from ..audit_hook import AuditError, audited_validate
from ..config import MAX_BATCH
from ..core.engine import IngestionError
from .deps import get_store
from .schemas import BatchRequest, BatchResponse, IngestionErrorItem, ValidateRequest

router = APIRouter(prefix="/v1", tags=["validate"])


def _audit_down(e: Exception) -> HTTPException:
    # fail-closed: results that could not be audited are never returned
    return HTTPException(status_code=503, detail={"error": "audit_unavailable", "message": str(e)})


@router.post("/validate")
def validate(req: ValidateRequest, store=Depends(get_store)):
    prev = (req.previous_run.run_id, req.previous_run.input_hash) if req.previous_run else None
    try:
        return audited_validate(req.claim, store, req.policy_override,
                                source="api:/v1/validate", previous_run=prev)
    except IngestionError as e:
        raise HTTPException(status_code=422, detail={
            "error": "ingestion_error", "message": str(e), "details": e.details})
    except (AuditError, OSError) as e:
        raise _audit_down(e)


@router.post("/validate/batch", response_model=BatchResponse)
def validate_batch(req: BatchRequest, store=Depends(get_store)):
    if len(req.claims) > MAX_BATCH:
        raise HTTPException(status_code=413, detail=f"batch exceeds {MAX_BATCH} claims")
    results, errors = [], []
    for i, raw in enumerate(req.claims):
        try:
            results.append(audited_validate(raw, store, req.policy_override,
                                            source=f"api:/v1/validate/batch[{i}]"))
        except IngestionError as e:
            cid = raw.get("claim_id") if isinstance(raw, dict) else None
            errors.append(IngestionErrorItem(index=i, claim_id=cid, message=str(e), details=e.details))
        except (AuditError, OSError) as e:
            raise _audit_down(e)
    return BatchResponse(results=results, ingestion_errors=errors)
