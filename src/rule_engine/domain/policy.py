from __future__ import annotations

from typing import Any, Union

from pydantic import BaseModel, ConfigDict


class Policy(BaseModel):
    model_config = ConfigDict(extra="ignore")

    policy_id: str
    version: str
    payer_id: str
    currency: str
    submission_window_days: int
    allowed_providers: list[str]
    auth_required_services: list[str]
    required_documents: dict[str, str]
    max_unit_price: dict[str, Union[int, float]]
    max_quantity_per_line: dict[str, int]


class ServiceCatalogue(BaseModel):
    codes: frozenset[str]

    def __contains__(self, code: object) -> bool:
        return isinstance(code, str) and code in self.codes

    @classmethod
    def from_raw(cls, raw: Any) -> "ServiceCatalogue":
        if isinstance(raw, dict):
            return cls(codes=frozenset(raw.keys()))  # services.json is keyed by code
        if isinstance(raw, list):
            return cls(codes=frozenset(
                (i if isinstance(i, str) else i.get("service_code") or i.get("code"))
                for i in raw))
        raise ValueError("Unrecognised services.json structure")
