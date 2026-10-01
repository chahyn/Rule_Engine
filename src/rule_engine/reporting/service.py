"""Validate (audited) and build the structured report in one call."""
from __future__ import annotations

from typing import Optional

from ..audit_hook import audited_validate
from ..domain.policy import Policy
from ..stores.policy_store import PolicyStore
from .findings import FindingReport, build_report


def validate_and_report(raw: dict, store: PolicyStore, policy_override: Optional[Policy] = None,
                        source: str = "report", previous_run: Optional[tuple] = None) -> FindingReport:
    response = audited_validate(raw, store, policy_override, source=source, previous_run=previous_run)
    return build_report(raw, response, store)
