from __future__ import annotations

import re
from datetime import date
from typing import Optional

_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse_iso_date(value: object) -> Optional[date]:
    """Strict YYYY-MM-DD; None for null, wrong type, other formats, impossible dates."""
    if not isinstance(value, str) or not _ISO.match(value):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None
