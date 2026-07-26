from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, date, datetime
from decimal import Decimal
from uuid import UUID

import pytest
from agentkernel.canonical import (
    canonical_json_bytes,
    canonical_json_text,
    validate_canonical_input_bounds,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from pydantic import BaseModel


def _bound(
    value: object,
    *,
    max_depth: int = 8,
    max_container_items: int = 16,
    max_nodes: int = 64,
    max_string_characters: int = 32,
    max_total_string_characters: int = 128,
    max_integer_bits: int = 64,
) -> None:
    validate_canonical_input_bounds(
        value,
        max_depth=max_depth,
        max_container_items=max_container_items,
        max_nodes=max_nodes,
        max_string_characters=max_string_characters,
        max_total_string_characters=max_total_string_characters,
        max_integer_bits=max_integer_bits,
    )


@pytest.mark.parametrize(
    ("value", "overrides", "message"),
    [
        (None, {"max_nodes": 0}, "node bound"),
        ([["nested"]], {"max_depth": 0}, "nesting-depth"),
        ("oversized", {"max_string_characters": 4}, "oversized scalar"),
        (["abcd", "efgh"], {"max_total_string_characters": 7}, "aggregate text"),
        (1 << 65, {"max_integer_bits": 64}, "oversized integer"),
        ({"a": 1, "b": 2}, {"max_container_items": 1}, "mapping exceeds"),
        ([1, 2], {"max_container_items": 1}, "sequence exceeds"),
    ],
)
def test_pre_hash_resource_bounds_reject_each_independent_exhaustion(
    value: object,
    overrides: dict[str, int],
    message: str,
) -> None:
    with pytest.raises(AgentKernelError, match=message) as captured:
        _bound(value, **overrides)  # type: ignore[arg-type]
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


class _FloatSubclass(float):
    pass


class _DecimalSubclass(Decimal):
    pass


class _DateSubclass(date):
    pass


class _DictSubclass(dict[str, object]):
    pass


class _ListSubclass(list[object]):
    pass


class _UnvalidatedModel(BaseModel):
    value: int


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (_FloatSubclass(1.0), "built-in scalar"),
        (_DecimalSubclass("1.0"), "built-in scalar"),
        (_DateSubclass(2030, 1, 1), "built-in scalar"),
        (_DictSubclass(value=1), "built-in mapping"),
        (_ListSubclass([1]), "built-in sequence"),
        (_UnvalidatedModel(value=1), "unvalidated model"),
    ],
)
def test_pre_hash_walk_rejects_callback_capable_subclasses(
    value: object,
    message: str,
) -> None:
    with pytest.raises(AgentKernelError, match=message) as captured:
        _bound(value)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


class _MappingSubclass(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        if key != "value":
            raise KeyError(key)
        return 1

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(("value",))

    def __len__(self) -> int:
        return 1


def test_pre_hash_walk_rejects_abstract_mapping_implementations() -> None:
    with pytest.raises(AgentKernelError, match="built-in mapping") as captured:
        _bound(_MappingSubclass())
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_pre_hash_walk_rejects_cycles_but_accepts_repeated_noncyclic_aliases() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(AgentKernelError, match="reference cycle") as captured:
        _bound(cyclic)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR

    shared = ["safe"]
    _bound([shared, shared])


def test_pre_hash_walk_accepts_bounded_builtin_scalar_profiles() -> None:
    _bound(
        [
            None,
            True,
            1,
            1.25,
            Decimal("NaN"),
            datetime(2030, 1, 1, tzinfo=UTC),
            date(2030, 1, 1),
            UUID("12345678-1234-5678-1234-567812345678"),
            b"bytes",
            bytearray(b"bytes"),
            frozenset({"a", "b"}),
        ]
    )


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan")])
def test_canonical_json_rejects_nonfinite_floats(value: float) -> None:
    with pytest.raises(AgentKernelError, match="non-finite floating") as captured:
        canonical_json_bytes(value)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize("value", [Decimal("Infinity"), Decimal("-Infinity"), Decimal("NaN")])
def test_canonical_json_rejects_nonfinite_decimals(value: Decimal) -> None:
    with pytest.raises(AgentKernelError, match="non-finite decimal") as captured:
        canonical_json_bytes(value)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (-0.0, "0.0"),
        (Decimal("0.000"), '"0"'),
        (Decimal("12E+2"), '"1200"'),
        (Decimal("0.0012"), '"0.0012"'),
        (Decimal("-12.30"), '"-12.3"'),
        (date(2030, 1, 2), '"2030-01-02"'),
        (UUID("12345678-1234-5678-1234-567812345678"), '"12345678-1234-5678-1234-567812345678"'),
        (b"\xff\x00", '{"$bytes_base64url":"_wA"}'),
    ],
)
def test_canonical_json_has_stable_edge_scalar_renderings(value: object, expected: str) -> None:
    assert canonical_json_text(value) == expected


def test_canonical_json_sorts_sets_by_their_canonical_representation() -> None:
    assert canonical_json_text(frozenset({"z", "a"})) == '["a","z"]'


def test_canonical_json_rejects_non_string_object_keys_and_unknown_types() -> None:
    with pytest.raises(AgentKernelError, match="keys must be strings") as key_error:
        canonical_json_bytes({1: "value"})
    assert key_error.value.code is ErrorCode.VALIDATION_ERROR

    with pytest.raises(AgentKernelError, match="not supported") as type_error:
        canonical_json_bytes(object())
    assert type_error.value.code is ErrorCode.VALIDATION_ERROR
