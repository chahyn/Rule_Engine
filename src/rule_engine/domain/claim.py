"""Structural validation model. Rules read the ORIGINAL raw dict (evidence must
quote source values), so this model only guards the transport contract."""
from __future__ import annotations

from typing import Optional, Union

from pydantic import BaseModel, ConfigDict, model_validator

Number = Union[int, float]


class _Base(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Coverage(_Base):
    coverage_id: Optional[str] = None
    status: Optional[str] = None
    beneficiary_patient_id: Optional[str] = None
    member_id: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None


class Line(_Base):
    line_id: str
    service_code: Optional[str] = None
    service_date: Optional[str] = None
    modifier: Optional[str] = None
    quantity: Optional[Number] = None
    unit_price: Optional[Number] = None
    net_amount: Optional[Number] = None
    authorization_id: Optional[str] = None


class Authorization(_Base):
    authorization_id: Optional[str] = None
    patient_id: Optional[str] = None
    service_code: Optional[str] = None
    status: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    max_quantity: Optional[Number] = None


class Attachment(_Base):
    attachment_id: Optional[str] = None
    type: Optional[str] = None
    patient_id: Optional[str] = None
    service_code: Optional[str] = None
    service_date: Optional[str] = None
    document_status: Optional[str] = None
    text: Optional[str] = None  # untrusted; never interpreted


class Claim(_Base):
    schema_version: str
    claim_id: str
    invoice_number: Optional[str] = None
    patient_id: str
    member_id: Optional[str] = None
    provider_id: str
    payer_id: str
    policy_id: str
    diagnosis_code: Optional[str] = None
    submission_date: str
    currency: str
    total_amount: Optional[Number] = None
    coverage: Coverage
    lines: list[Line]
    authorizations: list[Authorization]
    attachments: list[Attachment]
    notes: str

    @model_validator(mode="after")
    def _structural(self) -> "Claim":
        if not self.lines:
            raise ValueError("lines must be a non-empty array")
        ids = [ln.line_id for ln in self.lines]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate line_id within claim")
        return self
