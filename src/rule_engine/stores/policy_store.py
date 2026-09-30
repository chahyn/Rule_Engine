from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..domain.policy import Policy, ServiceCatalogue


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    title: str
    severity: str
    logic: str
    corrective_action: str
    version: str
    source: str


class PolicyStore:
    def __init__(self, policies: dict[str, Policy], services: ServiceCatalogue,
                 rules: dict[str, RuleMeta]):
        self._policies = policies
        self.services = services
        self.rules = rules

    @classmethod
    def from_dir(cls, rules_dir: Path) -> "PolicyStore":
        rd = Path(rules_dir)

        def load(name):
            return json.loads((rd / name).read_text(encoding="utf-8"))

        policies = {k: Policy.model_validate(v) for k, v in load("policies.json").items()}
        services = ServiceCatalogue.from_raw(load("services.json"))
        rules = {r["rule_id"]: RuleMeta(
            rule_id=r["rule_id"], title=r["title"], severity=r["severity"],
            logic=r["logic"], corrective_action=r["corrective_action"],
            version=r["version"], source=r["source"]) for r in load("rules.json")}
        return cls(policies, services, rules)

    def get(self, policy_id: object) -> Optional[Policy]:
        """None = no matching policy supplied (not proof of non-coverage)."""
        return self._policies.get(policy_id) if isinstance(policy_id, str) else None

    def all(self) -> dict[str, Policy]:
        return dict(self._policies)
