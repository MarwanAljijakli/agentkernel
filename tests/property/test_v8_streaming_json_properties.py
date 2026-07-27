from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from agentkernel.authority.v8_contracts import (
    AuthorityInputTerminationReasonV8,
    TransportEncodingV8,
)
from agentkernel.authority.v8_streaming import (
    AUTHORITY_INPUT_READ_QUANTUM_V8,
    BoundedAuthorityInputFailureV8,
    BoundedAuthorityInputResultV8,
    BoundedAuthorityInputSuccessV8,
    SourceDataV8,
    SourceEofV8,
    read_bounded_authority_input_v8,
)
from hypothesis import given, settings
from hypothesis import strategies as st


@dataclass(slots=True)
class _PartitionSource:
    body: bytes
    widths: tuple[int, ...]
    cursor: int = 0
    width_cursor: int = 0
    finishes: list[bool] = field(default_factory=list)

    async def read(self, max_bytes: int):
        if self.cursor == len(self.body):
            return SourceEofV8()
        requested = (
            self.widths[self.width_cursor] if self.width_cursor < len(self.widths) else max_bytes
        )
        self.width_cursor += 1
        take = min(requested, max_bytes, len(self.body) - self.cursor)
        start = self.cursor
        self.cursor += take
        return SourceDataV8(self.body[start : self.cursor])

    def abort_current_read(self) -> None:
        raise AssertionError("property source read must never require abort")

    def finish_response(self, reusable: bool) -> None:
        self.finishes.append(reusable)


async def _read_partitioned(
    wire: bytes,
    widths: tuple[int, ...],
    *,
    encoding: TransportEncodingV8,
) -> BoundedAuthorityInputResultV8:
    source = _PartitionSource(wire, widths)
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=encoding,
        operation_deadline=datetime.now(UTC) + timedelta(seconds=30),
    )
    assert len(source.finishes) == 1
    return result


@dataclass(slots=True)
class _ReferenceCounters:
    nodes: int = 0
    maximum_depth: int = 0
    maximum_object_members: int = 0
    maximum_array_elements: int = 0
    maximum_string_bytes: int = 0
    aggregate_scalar_bytes: int = 0
    maximum_number_bytes: int = 0


def _reference_counters(value: object) -> _ReferenceCounters:
    counters = _ReferenceCounters()
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        counters.nodes += 1
        if isinstance(current, dict):
            counters.maximum_depth = max(counters.maximum_depth, depth)
            counters.maximum_object_members = max(
                counters.maximum_object_members,
                len(current),
            )
            for key, child in reversed(tuple(current.items())):
                counters.nodes += 1
                encoded_key_length = len(key.encode("utf-8"))
                counters.maximum_string_bytes = max(
                    counters.maximum_string_bytes,
                    encoded_key_length,
                )
                counters.aggregate_scalar_bytes += encoded_key_length
                stack.append((child, depth + 1 if isinstance(child, (dict, list)) else depth))
        elif isinstance(current, list):
            counters.maximum_depth = max(counters.maximum_depth, depth)
            counters.maximum_array_elements = max(
                counters.maximum_array_elements,
                len(current),
            )
            stack.extend(
                (child, depth + 1 if isinstance(child, (dict, list)) else depth)
                for child in reversed(current)
            )
        elif isinstance(current, str):
            encoded_length = len(current.encode("utf-8"))
            counters.maximum_string_bytes = max(
                counters.maximum_string_bytes,
                encoded_length,
            )
            counters.aggregate_scalar_bytes += encoded_length
        elif current is None:
            counters.aggregate_scalar_bytes += 4
        elif type(current) is bool:
            counters.aggregate_scalar_bytes += 4 if current else 5
        elif type(current) is int:
            token_length = len(str(current).encode("ascii"))
            counters.aggregate_scalar_bytes += token_length
            counters.maximum_number_bytes = max(
                counters.maximum_number_bytes,
                token_length,
            )
        else:
            raise AssertionError(f"unsupported reference scalar: {type(current)!r}")
    return counters


_safe_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),
    max_size=12,
)
_leaf = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**12), max_value=10**12),
    _safe_text,
)
_json_value = st.recursive(
    _leaf,
    lambda children: st.one_of(
        st.lists(children, max_size=6),
        st.dictionaries(_safe_text, children, max_size=6),
    ),
    max_leaves=30,
)
_root_object = st.dictionaries(_safe_text, _json_value, max_size=6)
_partitions = st.lists(
    st.integers(min_value=1, max_value=AUTHORITY_INPUT_READ_QUANTUM_V8),
    min_size=1,
    max_size=20,
).map(tuple)


@settings(max_examples=60, deadline=None)
@given(
    value=_root_object,
    widths=_partitions,
    use_gzip=st.booleans(),
)
def test_small_reference_objects_have_identical_counters_and_digests(
    value: dict[str, Any],
    widths: tuple[int, ...],
    use_gzip: bool,
) -> None:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    encoding = TransportEncodingV8.GZIP if use_gzip else TransportEncodingV8.IDENTITY
    wire = gzip.compress(raw, mtime=0) if use_gzip else raw

    result = asyncio.run(_read_partitioned(wire, widths, encoding=encoding))

    assert type(result) is BoundedAuthorityInputSuccessV8
    assert json.loads(result.document.raw_bytes) == value
    assert result.document.raw_bytes == raw
    reference = _reference_counters(value)
    assert result.document.syntax_node_count == reference.nodes
    assert result.document.maximum_depth == reference.maximum_depth
    assert result.document.maximum_object_members == reference.maximum_object_members
    assert result.document.maximum_array_elements == reference.maximum_array_elements
    assert result.document.maximum_decoded_string_bytes == reference.maximum_string_bytes
    assert result.document.aggregate_decoded_scalar_bytes == (reference.aggregate_scalar_bytes)
    assert result.document.maximum_number_token_bytes == reference.maximum_number_bytes
    assert result.observation.complete_wire_digest == (f"sha256:{hashlib.sha256(wire).hexdigest()}")
    assert result.observation.complete_decompressed_digest == (
        f"sha256:{hashlib.sha256(raw).hexdigest()}"
    )


@settings(max_examples=80, deadline=None)
@given(
    payload=st.sampled_from(
        [
            b"",
            b"1",
            b'{"a":1,"\\u0061":2}',
            b'{"a":-0}',
            b'{"a":1.5}',
            b'{"a":"\\uD800"}',
            b'{"a":"\xff"}',
            b'{"a":',
            b"{} trailing",
        ]
    ),
    widths=_partitions,
)
def test_failure_observation_and_reason_are_partition_invariant(
    payload: bytes,
    widths: tuple[int, ...],
) -> None:
    baseline = asyncio.run(
        _read_partitioned(
            payload,
            (AUTHORITY_INPUT_READ_QUANTUM_V8,),
            encoding=TransportEncodingV8.IDENTITY,
        )
    )
    partitioned = asyncio.run(
        _read_partitioned(
            payload,
            widths,
            encoding=TransportEncodingV8.IDENTITY,
        )
    )

    assert type(baseline) is BoundedAuthorityInputFailureV8
    assert type(partitioned) is BoundedAuthorityInputFailureV8
    assert partitioned.observation.model_dump(mode="python") == (
        baseline.observation.model_dump(mode="python")
    )
    assert partitioned.termination == baseline.termination


@settings(max_examples=50, deadline=None)
@given(
    split=st.integers(min_value=1, max_value=58),
    use_gzip=st.booleans(),
)
def test_every_utf8_escape_state_survives_arbitrary_split(
    split: int,
    use_gzip: bool,
) -> None:
    raw = (
        '{"é":"quote:\\\\\\" slash:\\\\/ controls:\\\\b\\\\f\\\\n\\\\r\\\\t '
        'bmp:\\\\u0061 pair:\\\\uD83D\\\\uDE00"}'
    ).encode()
    wire = gzip.compress(raw, mtime=0) if use_gzip else raw
    actual_split = min(split, len(wire) - 1)
    encoding = TransportEncodingV8.GZIP if use_gzip else TransportEncodingV8.IDENTITY

    baseline = asyncio.run(
        _read_partitioned(
            wire,
            (AUTHORITY_INPUT_READ_QUANTUM_V8,),
            encoding=encoding,
        )
    )
    partitioned = asyncio.run(
        _read_partitioned(
            wire,
            (actual_split, len(wire) - actual_split),
            encoding=encoding,
        )
    )

    assert type(baseline) is BoundedAuthorityInputSuccessV8
    assert type(partitioned) is BoundedAuthorityInputSuccessV8
    assert partitioned.document == baseline.document
    assert partitioned.observation == baseline.observation


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding", [TransportEncodingV8.IDENTITY, TransportEncodingV8.GZIP])
@pytest.mark.parametrize(
    ("raw", "expected_reason"),
    [
        (b'{"n":0}', None),
        (b'{"n":-1}', None),
        (b'{"n":1234567890}', None),
        (b'{"t":true,"f":false,"n":null}', None),
        (b'{"s":"\\"\\\\\\/\\b\\f\\n\\r\\t"}', None),
        (b'{"s":"\\u0061\\uD83D\\uDE00"}', None),
        ('{"s":"é€😀"}'.encode(), None),
        (b'{"n":-0}', AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER),
        (b'{"n":01}', AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER),
        (b'{"n":1.0}', AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER),
        (b'{"n":1e2}', AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER),
        (b'{"n":-', AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER),
        (b'{"x":tru', AuthorityInputTerminationReasonV8.INVALID_JSON),
        (b'{"x":fals', AuthorityInputTerminationReasonV8.INVALID_JSON),
        (b'{"x":nul', AuthorityInputTerminationReasonV8.INVALID_JSON),
        (b'{"x":True}', AuthorityInputTerminationReasonV8.INVALID_JSON),
        (b'{"s":"text', AuthorityInputTerminationReasonV8.INVALID_JSON),
        (b'{"s":"text\\', AuthorityInputTerminationReasonV8.INVALID_JSON),
        (b'{"s":"\\u12', AuthorityInputTerminationReasonV8.INVALID_JSON),
        (b'{"s":"\\uD800', AuthorityInputTerminationReasonV8.LONE_SURROGATE),
        (b'{"s":"\\uDC00"}', AuthorityInputTerminationReasonV8.LONE_SURROGATE),
        (b'{"s":"\xc3("}', AuthorityInputTerminationReasonV8.INVALID_UTF8),
        (b'{"s":"\xe2\x82', AuthorityInputTerminationReasonV8.INVALID_UTF8),
        (b'{"s":"\xf0\x9f\x98', AuthorityInputTerminationReasonV8.INVALID_UTF8),
    ],
)
async def test_number_literal_escape_and_utf8_states_match_at_every_byte_split(
    raw: bytes,
    expected_reason: AuthorityInputTerminationReasonV8 | None,
    encoding: TransportEncodingV8,
) -> None:
    wire = gzip.compress(raw, mtime=0) if encoding is TransportEncodingV8.GZIP else raw
    baseline = await _read_partitioned(
        wire,
        (AUTHORITY_INPUT_READ_QUANTUM_V8,),
        encoding=encoding,
    )
    if expected_reason is None:
        assert type(baseline) is BoundedAuthorityInputSuccessV8
    else:
        assert type(baseline) is BoundedAuthorityInputFailureV8
        assert baseline.termination is not None
        assert baseline.termination.reason is expected_reason

    for split in range(1, len(wire)):
        partitioned = await _read_partitioned(
            wire,
            (split, len(wire) - split),
            encoding=encoding,
        )
        assert type(partitioned) is type(baseline)
        assert partitioned.observation == baseline.observation
        if type(baseline) is BoundedAuthorityInputSuccessV8:
            assert type(partitioned) is BoundedAuthorityInputSuccessV8
            assert partitioned.document == baseline.document
        else:
            assert type(partitioned) is BoundedAuthorityInputFailureV8
            assert partitioned.termination == baseline.termination


@settings(max_examples=50, deadline=None)
@given(widths=_partitions, trailing=st.binary(min_size=1, max_size=16))
def test_gzip_trailing_witness_is_partition_invariant(
    widths: tuple[int, ...],
    trailing: bytes,
) -> None:
    member = gzip.compress(b"{}", mtime=0)
    wire = member + trailing
    result = asyncio.run(_read_partitioned(wire, widths, encoding=TransportEncodingV8.GZIP))

    assert type(result) is BoundedAuthorityInputFailureV8
    assert result.termination is not None
    assert result.termination.reason.value == "TRAILING_COMPRESSED_DATA"
    assert result.observation.observed_wire_prefix_length == len(member) + 1
    assert result.observation.observed_wire_prefix_digest == (
        f"sha256:{hashlib.sha256(member + trailing[:1]).hexdigest()}"
    )


@settings(max_examples=100, deadline=None)
@given(payload=st.binary(max_size=100), widths=_partitions)
def test_arbitrary_small_bytes_fail_closed_without_escaping(
    payload: bytes,
    widths: tuple[int, ...],
) -> None:
    result = asyncio.run(
        _read_partitioned(
            payload,
            widths,
            encoding=TransportEncodingV8.IDENTITY,
        )
    )

    assert type(result) in {
        BoundedAuthorityInputSuccessV8,
        BoundedAuthorityInputFailureV8,
    }
    if type(result) is BoundedAuthorityInputSuccessV8:
        parsed = json.loads(result.document.raw_bytes)
        assert type(parsed) is dict
