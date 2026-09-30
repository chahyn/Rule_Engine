from __future__ import annotations

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Optional

CENT = Decimal("0.01")
TOLERANCE = Decimal("0.01")  # inclusive


def to_decimal(value: Any) -> Optional[Decimal]:
    """JSON number -> Decimal via str(). None for null, bool, strings, NaN/inf."""
    if value is None or isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        return None
    try:
        d = Decimal(str(value))
    except InvalidOperation:
        return None
    return d if d.is_finite() else None


def round2(value: Decimal) -> Decimal:
    return value.quantize(CENT, rounding=ROUND_HALF_UP)


def within_tolerance(a: Decimal, b: Decimal, tol: Decimal = TOLERANCE) -> bool:
    return abs(round2(a) - round2(b)) <= tol


def is_positive_integer(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value > 0
    if isinstance(value, float):
        return value.is_integer() and value > 0
    return False
