from __future__ import annotations

from datetime import datetime
from decimal import Decimal, localcontext
from pathlib import Path

import pytest
from agentkernel.canonical import canonical_digest, canonical_json_bytes
from agentkernel.errors import AgentKernelError, ErrorCode
from hypothesis import given
from hypothesis import strategies as st


def test_mapping_order_and_unicode_normalization_are_deterministic() -> None:
    composed = {"é": "café", "number": 7}
    decomposed = {"e\u0301": "cafe\u0301", "number": 7}

    assert canonical_json_bytes(composed) == canonical_json_bytes(decomposed)
    assert canonical_digest(composed) == canonical_digest(decomposed)


@given(st.dictionaries(st.text(min_size=1), st.integers(), max_size=20))
def test_reversing_mapping_insertion_order_does_not_change_digest(values: dict[str, int]) -> None:
    reversed_values = dict(reversed(tuple(values.items())))
    assert canonical_digest(values) == canonical_digest(reversed_values)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numbers_are_rejected(value: float) -> None:
    with pytest.raises(AgentKernelError) as captured:
        canonical_json_bytes(value)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(AgentKernelError, match="timezone-aware"):
        canonical_json_bytes(datetime(2026, 1, 1))


def test_unicode_normalized_duplicate_key_is_rejected() -> None:
    with pytest.raises(AgentKernelError, match="duplicate"):
        canonical_json_bytes({"é": 1, "e\u0301": 2})


def test_decimal_encoding_is_independent_of_decimal_context() -> None:
    value = Decimal("123456789.12345000")
    with localcontext() as context:
        context.prec = 4
        low_precision = canonical_json_bytes(value)
    with localcontext() as context:
        context.prec = 50
        high_precision = canonical_json_bytes(value)
    assert low_precision == high_precision == b'"123456789.12345"'


def test_platform_path_must_be_normalized_by_a_resource_adapter() -> None:
    with pytest.raises(AgentKernelError, match="not canonical resources"):
        canonical_json_bytes(Path("workspace") / "file.txt")
