from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta, tzinfo
from decimal import Decimal, localcontext
from enum import Enum
from pathlib import Path
from typing import overload

import pytest
from agentkernel.canonical import (
    canonical_digest,
    canonical_json_bytes,
    validate_canonical_input_bounds,
)
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


def _validate_small_canonical_input(value: object) -> None:
    validate_canonical_input_bounds(
        value,
        max_depth=8,
        max_container_items=256,
        max_nodes=1_024,
        max_string_characters=512,
        max_total_string_characters=4_096,
        max_integer_bits=63,
    )


@pytest.mark.parametrize("value", [Decimal("1E+999999999"), Decimal("1E-999999999")])
def test_pre_hash_bounds_reject_huge_decimal_renderings(value: Decimal) -> None:
    with pytest.raises(AgentKernelError, match="oversized decimal") as captured:
        _validate_small_canonical_input(value)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


class _LyingSequence(Sequence[int]):
    def __len__(self) -> int:
        return 0

    @overload
    def __getitem__(self, _index: int) -> int: ...

    @overload
    def __getitem__(self, _index: slice) -> Sequence[int]: ...

    def __getitem__(self, _index: int | slice) -> int | Sequence[int]:
        if isinstance(_index, slice):
            return ()
        return 1


def test_pre_hash_bounds_reject_custom_containers_before_iteration() -> None:
    with pytest.raises(AgentKernelError, match="built-in sequence") as captured:
        _validate_small_canonical_input(_LyingSequence())
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


class _SneakyString(str):
    def __len__(self) -> int:
        return 0


class _SneakyInteger(int):
    def bit_length(self) -> int:
        return 0


@pytest.mark.parametrize("value", [_SneakyString("x" * 1_000), _SneakyInteger(1 << 1_000)])
def test_pre_hash_bounds_reject_scalar_subclasses_before_overridden_methods(
    value: object,
) -> None:
    with pytest.raises(AgentKernelError, match="built-in scalar") as captured:
        _validate_small_canonical_input(value)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


class _ExplosiveTimezone(tzinfo):
    def utcoffset(self, _value: datetime | None) -> timedelta | None:
        raise AssertionError("untrusted timezone callback executed")

    def dst(self, _value: datetime | None) -> timedelta | None:
        raise AssertionError("untrusted timezone callback executed")

    def tzname(self, _value: datetime | None) -> str | None:
        raise AssertionError("untrusted timezone callback executed")


def test_pre_hash_bounds_reject_custom_timezone_without_invoking_it() -> None:
    value = datetime(2026, 1, 1, tzinfo=_ExplosiveTimezone())
    with pytest.raises(AgentKernelError, match="built-in timezone") as captured:
        _validate_small_canonical_input(value)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_pre_hash_bounds_reject_unpaired_surrogates_as_validation_errors() -> None:
    with pytest.raises(AgentKernelError, match="valid UTF-8") as captured:
        _validate_small_canonical_input("\ud800")
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


class _ExplosiveEnum(Enum):
    VALUE = "safe"

    @property
    def value(self) -> str:
        raise AssertionError("untrusted Enum.value callback executed")


def test_canonicalization_reads_the_internal_enum_value_without_callback() -> None:
    _validate_small_canonical_input(_ExplosiveEnum.VALUE)
    assert canonical_json_bytes(_ExplosiveEnum.VALUE) == b'"safe"'
