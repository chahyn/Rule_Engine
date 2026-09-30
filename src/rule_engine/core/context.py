from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ..domain.policy import Policy
from ..domain.result import Evidence
from ..stores.policy_store import PolicyStore
from ..utils import json_pointer as jp


@dataclass
class ClaimContext:
    """Everything a rule needs. `raw` is the ORIGINAL envelope; evidence values
    are always resolved from it, never from transformed copies."""
    raw: dict
    policy: Optional[Policy]
    store: PolicyStore

    @property
    def claim_id(self) -> str:
        return self.raw["claim_id"]

    @property
    def lines(self) -> list[dict]:
        return self.raw["lines"]

    def get(self, *tokens: Any) -> Any:
        return jp.resolve(self.raw, jp.build(*tokens))

    def line_id(self, i: int) -> str:
        return self.lines[i]["line_id"]

    def ev(self, *paths: str) -> list[Evidence]:
        return [Evidence(path=p, value=jp.resolve(self.raw, p)) for p in paths]

    def known_service(self, code: Any) -> bool:
        return code in self.store.services


def blank(v: Any) -> bool:
    """Missing = null or empty string (rule R001 semantics)."""
    return v is None or (isinstance(v, str) and v == "")
