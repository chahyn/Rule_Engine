from typing import Any, Optional

from pydantic import BaseModel

from ..domain.policy import Policy
from ..domain.result import ValidationResponse


class PreviousRun(BaseModel):
    run_id: str
    input_hash: str


class ValidateRequest(BaseModel):
    claim: dict[str, Any]
    policy_override: Optional[Policy] = None
    previous_run: Optional[PreviousRun] = None  # set when re-checking a corrected claim


class BatchRequest(BaseModel):
    claims: list[Any]
    policy_override: Optional[Policy] = None


class IngestionErrorItem(BaseModel):
    index: int
    claim_id: Optional[str] = None
    message: str
    details: list[dict] = []


class BatchResponse(BaseModel):
    results: list[ValidationResponse]
    ingestion_errors: list[IngestionErrorItem]
