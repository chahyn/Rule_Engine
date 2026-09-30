from fastapi import APIRouter, Depends, HTTPException

from ..config import MAX_BATCH
from ..core.engine import IngestionError, validate_claim
from .deps import get_store
from .schemas import BatchRequest, BatchResponse, IngestionErrorItem, ValidateRequest

router = APIRouter(prefix="/v1", tags=["validate"])


@router.post("/validate")
def validate(req: ValidateRequest, store=Depends(get_store)):
    try:
        return validate_claim(req.claim, store, req.policy_override)
    except IngestionError as e:
        raise HTTPException(status_code=422, detail={
            "error": "ingestion_error", "message": str(e), "details": e.details})


@router.post("/validate/batch", response_model=BatchResponse)
def validate_batch(req: BatchRequest, store=Depends(get_store)):
    if len(req.claims) > MAX_BATCH:
        raise HTTPException(status_code=413, detail=f"batch exceeds {MAX_BATCH} claims")
    results, errors = [], []
    for i, raw in enumerate(req.claims):
        try:
            results.append(validate_claim(raw, store, req.policy_override))
        except IngestionError as e:
            cid = raw.get("claim_id") if isinstance(raw, dict) else None
            errors.append(IngestionErrorItem(index=i, claim_id=cid, message=str(e), details=e.details))
    return BatchResponse(results=results, ingestion_errors=errors)
