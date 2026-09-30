from functools import lru_cache

from ..config import RULES_DIR
from ..stores.policy_store import PolicyStore


@lru_cache(maxsize=1)
def get_store() -> PolicyStore:
    return PolicyStore.from_dir(RULES_DIR)
