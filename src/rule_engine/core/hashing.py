import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def input_hash(raw_claim: dict) -> str:
    return hashlib.sha256(canonical_json(raw_claim).encode("utf-8")).hexdigest()
