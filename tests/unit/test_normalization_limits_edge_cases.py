from __future__ import annotations

import json

import pytest
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.normalization.limits import bounded_json_size


def test_bounded_json_size_matches_compact_utf8_json_for_edge_scalars() -> None:
    value = {
        "escaped": 'quote" slash\\ controls\b\t\n\f\r',
        "unicode": "é—😀",
        "values": [None, True, False, 0, -123, 1.25, (), {}],
    }
    expected = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    assert bounded_json_size(value, max_bytes=10_000) == len(expected)


@pytest.mark.parametrize(
    "limits",
    [
        {"max_bytes": 0},
        {"max_bytes": 1, "max_depth": 0},
        {"max_bytes": 1, "max_nodes": 0},
        {"max_bytes": 1, "max_collection_items": 0},
    ],
)
def test_bounded_json_size_requires_positive_limits(limits: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="limits must be positive"):
        bounded_json_size(None, **limits)


@pytest.mark.parametrize(
    ("value", "max_bytes"),
    [
        (None, 3),
        ("é", 3),
        ('"', 3),
        (b"12", 3),
        (bytearray(b"12"), 3),
    ],
)
def test_encoded_byte_budget_fails_before_allocating_oversized_values(
    value: object,
    max_bytes: int,
) -> None:
    with pytest.raises(AgentKernelError, match="encoded bytes") as captured:
        bounded_json_size(value, max_bytes=max_bytes)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_large_integer_lower_bound_prevents_decimal_rendering() -> None:
    with pytest.raises(AgentKernelError, match="encoded bytes") as captured:
        bounded_json_size(1 << 10_000, max_bytes=100)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_python_integer_rendering_limit_is_reported_as_invalid_json() -> None:
    with pytest.raises(AgentKernelError, match="bounded UTF-8 JSON") as captured:
        bounded_json_size(10**5_000, max_bytes=10_000)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_floats_are_not_json(value: float) -> None:
    with pytest.raises(AgentKernelError, match="bounded UTF-8 JSON") as captured:
        bounded_json_size(value, max_bytes=100)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize("value", ["\ud800", b"ok", bytearray(b"ok"), object()])
def test_non_json_scalar_types_fail_validation(value: object) -> None:
    with pytest.raises(AgentKernelError, match="bounded UTF-8 JSON") as captured:
        bounded_json_size(value, max_bytes=100)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_mapping_requires_string_keys() -> None:
    with pytest.raises(AgentKernelError, match="bounded UTF-8 JSON") as captured:
        bounded_json_size({1: "value"}, max_bytes=100)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize("value", [{"a": 1, "b": 2}, [1, 2], (1, 2)])
def test_collection_item_limit_applies_to_each_json_container(value: object) -> None:
    with pytest.raises(AgentKernelError, match="collection size") as captured:
        bounded_json_size(value, max_bytes=100, max_collection_items=1)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


@pytest.mark.parametrize(
    "value",
    [{"child": {"nested": None}}, [[None]], ((None,),)],
)
def test_nonempty_container_cannot_cross_the_depth_boundary(value: object) -> None:
    with pytest.raises(AgentKernelError, match="nesting depth") as captured:
        bounded_json_size(value, max_bytes=100, max_depth=1, max_nodes=10)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


@pytest.mark.parametrize("value", [{"a": 1}, [1], (1,)])
def test_node_budget_counts_mapping_keys_and_values_and_sequence_items(value: object) -> None:
    with pytest.raises(AgentKernelError, match="node count") as captured:
        bounded_json_size(value, max_bytes=100, max_nodes=1)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_mapping_and_sequence_reference_cycles_fail_validation() -> None:
    mapping: dict[str, object] = {}
    mapping["self"] = mapping
    with pytest.raises(AgentKernelError, match="bounded UTF-8 JSON") as mapping_error:
        bounded_json_size(mapping, max_bytes=100, max_depth=8, max_nodes=10)
    assert mapping_error.value.code is ErrorCode.VALIDATION_ERROR

    sequence: list[object] = []
    sequence.append(sequence)
    with pytest.raises(AgentKernelError, match="bounded UTF-8 JSON") as sequence_error:
        bounded_json_size(sequence, max_bytes=100, max_depth=8, max_nodes=10)
    assert sequence_error.value.code is ErrorCode.VALIDATION_ERROR
