import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = Path(os.getenv("RULES_DIR", REPO_ROOT / "data" / "rules"))
MAX_BATCH = int(os.getenv("MAX_BATCH", "1000"))
