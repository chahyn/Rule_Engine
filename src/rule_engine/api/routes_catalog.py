from fastapi import APIRouter, Depends, HTTPException

from .deps import get_store

router = APIRouter(prefix="/v1", tags=["catalog"])


@router.get("/rules")
def list_rules(store=Depends(get_store)):
    return [{"rule_id": m.rule_id, "title": m.title, "severity": m.severity,
             "version": m.version, "source": m.source, "logic": m.logic,
             "corrective_action": m.corrective_action} for m in store.rules.values()]


@router.get("/policies/{policy_id}")
def get_policy(policy_id: str, store=Depends(get_store)):
    p = store.get(policy_id)
    if p is None:
        raise HTTPException(status_code=404, detail="no matching policy supplied")
    return p
