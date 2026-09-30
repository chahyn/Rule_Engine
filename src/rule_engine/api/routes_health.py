from fastapi import APIRouter

from ..version import ENGINE_VERSION, RULE_VERSION

router = APIRouter(tags=["health"])


@router.get("/health")
def health():
    return {"status": "ok", "engine_version": ENGINE_VERSION, "rule_version": RULE_VERSION}
