from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .enums import ConfidenceKind, Method, ReviewStatus, Severity, Status

RuleId = Literal[
    "R001", "R002", "R003", "R004", "R005", "R006", "R007", "R008",
    "R009", "R010", "R011", "R012", "R013", "R014", "R015",
]


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(pattern=r"^/")
    value: Any = None


class RuleResult(BaseModel):
    """Mirrors schemas/result.schema.json v1.0.0 (additionalProperties: false)."""
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    claim_id: str
    rule_id: RuleId
    rule_version: Literal["1.0.0"] = "1.0.0"
    status: Status
    severity: Severity
    affected_line_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    rule_source: str
    explanation: str = Field(min_length=1)
    corrective_action: str
    confidence: Optional[float] = Field(default=None, ge=0, le=1)
    confidence_kind: ConfidenceKind = ConfidenceKind.NOT_PROBABILISTIC
    requires_human_review: bool
    method: Method = Method.DETERMINISTIC
    review_status: ReviewStatus = ReviewStatus.UNREVIEWED

    @field_validator("affected_line_ids")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(v))


class RunMetadata(BaseModel):
    run_id: str
    input_hash: str
    engine_version: str
    rule_versions: dict[str, str]
    policy_id: str
    policy_version: Optional[str] = None
    started_at: datetime
    duration_ms: float


class ValidationResponse(BaseModel):
    claim_id: str
    results: list[RuleResult]
    run: RunMetadata
