from decimal import Decimal

from rule_engine.core.hashing import input_hash
from rule_engine.utils import json_pointer as jp
from rule_engine.utils.date_utils import parse_iso_date
from rule_engine.utils.decimal_utils import is_positive_integer, round2, to_decimal, within_tolerance


def test_decimal_no_float_noise():
    assert round2(to_decimal(0.1) + to_decimal(0.2)) == Decimal("0.30")


def test_round_half_up_and_inclusive_tolerance():
    assert round2(Decimal("2.675")) == Decimal("2.68")
    assert within_tolerance(Decimal("100.00"), Decimal("100.01"))
    assert not within_tolerance(Decimal("100.00"), Decimal("100.02"))


def test_to_decimal_rejects_bad_values():
    assert to_decimal(None) is None and to_decimal(True) is None
    assert to_decimal("12") is None and to_decimal(float("nan")) is None


def test_positive_integer():
    assert is_positive_integer(2.0) and not is_positive_integer(1.5)
    assert not is_positive_integer(0) and not is_positive_integer(True)


def test_dates_strict():
    assert parse_iso_date("2026-02-28") and not parse_iso_date("2026-02-30")
    assert not parse_iso_date("20260228") and not parse_iso_date(None)


def test_json_pointer():
    doc = {"lines": [{"d": 1}], "a/b": 2}
    assert jp.build("lines", 0, "d") == "/lines/0/d"
    assert jp.resolve(doc, "/a~1b") == 2
    assert jp.resolve(doc, "/lines/9/d", "X") == "X"


def test_hash_order_independent():
    assert input_hash({"a": 1, "b": 2}) == input_hash({"b": 2, "a": 1})
