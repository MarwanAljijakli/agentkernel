from __future__ import annotations

import asyncio
import gzip
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from agentkernel.authority.v8_contracts import (
    AUTHORITY_INPUT_BYTE_LIMIT_V8,
    AuthorityInputPhaseV8,
    AuthorityInputTerminationReasonV8,
    CompleteBoundedResponseObservationV8,
    IncompleteBoundedResponseObservationV8,
    NoResponseObservationV8,
    TransportEncodingV8,
)
from agentkernel.authority.v8_streaming import (
    AUTHORITY_INPUT_MAX_AGGREGATE_SCALAR_BYTES_V8,
    AUTHORITY_INPUT_MAX_NODES_V8,
    AUTHORITY_INPUT_MAX_SCALAR_BYTES_V8,
    AUTHORITY_INPUT_READ_QUANTUM_V8,
    AuthorityInputTerminationV8,
    BoundedAuthorityInputFailureV8,
    BoundedAuthorityInputSuccessV8,
    Http11AuthorityInputSourceV8,
    InProcessAuthorityInputSourceV8,
    SourceDataV8,
    SourceDisconnectedV8,
    SourceEofV8,
    SourceFramingFailureV8,
    admit_http11_authority_input_v8,
    read_bounded_authority_input_v8,
)
from agentkernel.errors import AgentKernelError, ErrorCode


def _deadline() -> datetime:
    return datetime.now(UTC) + timedelta(seconds=30)


async def _read(
    body: bytes,
    *,
    encoding: TransportEncodingV8 = TransportEncodingV8.IDENTITY,
    return_size: int = AUTHORITY_INPUT_READ_QUANTUM_V8,
):
    source = InProcessAuthorityInputSourceV8(body=body, return_size=return_size)
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=encoding,
        operation_deadline=_deadline(),
    )
    return result, source


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "return_size",
    [1, 2, 3, 7, 63, 64, 65, 1_024, 65_535, 65_536],
)
@pytest.mark.parametrize("encoding", [TransportEncodingV8.IDENTITY, TransportEncodingV8.GZIP])
async def test_valid_document_is_partition_invariant(
    return_size: int,
    encoding: TransportEncodingV8,
) -> None:
    raw = b'{"a":-12,"b":[true,false,null],"emoji":"\\uD83D\\uDE00"}'
    wire = raw if encoding is TransportEncodingV8.IDENTITY else gzip.compress(raw, mtime=0)

    result, source = await _read(wire, encoding=encoding, return_size=return_size)

    assert type(result) is BoundedAuthorityInputSuccessV8
    assert result.document.raw_bytes == raw
    assert result.document.syntax_node_count == 10
    assert result.document.maximum_depth == 2
    assert result.document.maximum_object_members == 3
    assert result.document.maximum_array_elements == 3
    assert result.document.maximum_number_token_bytes == 3
    assert result.observation.complete_wire_digest == (f"sha256:{hashlib.sha256(wire).hexdigest()}")
    assert result.observation.complete_decompressed_digest == (
        f"sha256:{hashlib.sha256(raw).hexdigest()}"
    )
    assert source.finish_count == 1
    assert source.reusable is True


@pytest.mark.asyncio
async def test_utf8_continuation_state_is_independent_from_json_surrogate_state() -> None:
    prefix = b'{"x":"\\uD83D\\uDE00'
    first_quantum = prefix + (b"a" * (AUTHORITY_INPUT_READ_QUANTUM_V8 - len(prefix) - 1)) + b"\xc3"
    raw = first_quantum + b'\xa9"}'

    result, source = await _read(
        raw,
        return_size=AUTHORITY_INPUT_READ_QUANTUM_V8,
    )

    assert type(result) is BoundedAuthorityInputSuccessV8
    assert result.document.raw_bytes == raw
    assert source.reusable is True


@pytest.mark.asyncio
async def test_empty_identity_and_eof_truncation_keep_complete_transport_evidence() -> None:
    empty_result, empty_source = await _read(b"")
    truncated_result, truncated_source = await _read(b'{"x":')

    for result, source, reason in (
        (empty_result, empty_source, AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT),
        (truncated_result, truncated_source, AuthorityInputTerminationReasonV8.INVALID_JSON),
    ):
        assert type(result) is BoundedAuthorityInputFailureV8
        assert type(result.observation) is CompleteBoundedResponseObservationV8
        assert result.termination is not None
        assert result.termination.phase is AuthorityInputPhaseV8.JSON_SCAN
        assert result.termination.reason is reason
        assert source.finish_count == 1
        assert source.reusable is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("phase", "reason"),
    [
        (
            AuthorityInputPhaseV8.WIRE_READ,
            AuthorityInputTerminationReasonV8.DISCONNECTED,
        ),
        *[
            (AuthorityInputPhaseV8.JSON_SCAN, reason)
            for reason in (
                AuthorityInputTerminationReasonV8.DUPLICATE_OBJECT_KEY,
                AuthorityInputTerminationReasonV8.DEPTH_LIMIT_EXCEEDED,
                AuthorityInputTerminationReasonV8.NODE_LIMIT_EXCEEDED,
                AuthorityInputTerminationReasonV8.CONTAINER_LIMIT_EXCEEDED,
                AuthorityInputTerminationReasonV8.SCALAR_LIMIT_EXCEEDED,
                AuthorityInputTerminationReasonV8.AGGREGATE_SCALAR_LIMIT_EXCEEDED,
            )
        ],
    ],
)
async def test_complete_failure_rejects_impossible_streaming_termination(
    phase: AuthorityInputPhaseV8,
    reason: AuthorityInputTerminationReasonV8,
) -> None:
    result, _source = await _read(b"{}")

    assert type(result) is BoundedAuthorityInputSuccessV8
    with pytest.raises(ValueError, match="complete observation"):
        BoundedAuthorityInputFailureV8(
            observation=result.observation,
            transport_encoding=TransportEncodingV8.IDENTITY,
            termination=AuthorityInputTerminationV8(
                phase=phase,
                reason=reason,
            ),
        )


def test_streaming_termination_matrix_and_error_codes_are_exhaustive() -> None:
    expected_pairs = {
        AuthorityInputPhaseV8.BEFORE_RESPONSE: {
            AuthorityInputTerminationReasonV8.DISCONNECTED,
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
        },
        AuthorityInputPhaseV8.WIRE_READ: {
            AuthorityInputTerminationReasonV8.DISCONNECTED,
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION,
            AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE,
            AuthorityInputTerminationReasonV8.TRANSFER_FRAMING_FAILED,
        },
        AuthorityInputPhaseV8.CONTENT_DECODE: {
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.DECOMPRESSION_FAILED,
        },
        AuthorityInputPhaseV8.UTF8_DECODE: {
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.INVALID_UTF8,
        },
        AuthorityInputPhaseV8.JSON_SCAN: {
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.INVALID_JSON,
            AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT,
            AuthorityInputTerminationReasonV8.DUPLICATE_OBJECT_KEY,
            AuthorityInputTerminationReasonV8.LONE_SURROGATE,
            AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER,
            AuthorityInputTerminationReasonV8.DEPTH_LIMIT_EXCEEDED,
            AuthorityInputTerminationReasonV8.NODE_LIMIT_EXCEEDED,
            AuthorityInputTerminationReasonV8.CONTAINER_LIMIT_EXCEEDED,
            AuthorityInputTerminationReasonV8.SCALAR_LIMIT_EXCEEDED,
            AuthorityInputTerminationReasonV8.AGGREGATE_SCALAR_LIMIT_EXCEEDED,
        },
        AuthorityInputPhaseV8.RESPONSE_FINALIZE: {
            AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM,
            AuthorityInputTerminationReasonV8.TRAILING_COMPRESSED_DATA,
        },
    }
    assert set(expected_pairs) == set(AuthorityInputPhaseV8)
    assert set().union(*expected_pairs.values()) == set(AuthorityInputTerminationReasonV8)

    validation_reasons = {
        AuthorityInputTerminationReasonV8.INVALID_UTF8,
        AuthorityInputTerminationReasonV8.INVALID_JSON,
        AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT,
        AuthorityInputTerminationReasonV8.DUPLICATE_OBJECT_KEY,
        AuthorityInputTerminationReasonV8.LONE_SURROGATE,
        AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER,
    }
    resource_reasons = {
        AuthorityInputTerminationReasonV8.DEPTH_LIMIT_EXCEEDED,
        AuthorityInputTerminationReasonV8.NODE_LIMIT_EXCEEDED,
        AuthorityInputTerminationReasonV8.CONTAINER_LIMIT_EXCEEDED,
        AuthorityInputTerminationReasonV8.SCALAR_LIMIT_EXCEEDED,
        AuthorityInputTerminationReasonV8.AGGREGATE_SCALAR_LIMIT_EXCEEDED,
    }
    for phase in AuthorityInputPhaseV8:
        for reason in AuthorityInputTerminationReasonV8:
            if reason not in expected_pairs[phase]:
                with pytest.raises(ValueError, match="phase/reason"):
                    AuthorityInputTerminationV8(phase=phase, reason=reason)
                continue
            termination = AuthorityInputTerminationV8(phase=phase, reason=reason)
            expected_code = (
                ErrorCode.DEADLINE_EXCEEDED
                if reason is AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED
                else ErrorCode.VALIDATION_ERROR
                if reason in validation_reasons
                else ErrorCode.RESOURCE_LIMIT_EXCEEDED
                if reason in resource_reasons
                else ErrorCode.EVIDENCE_UNAVAILABLE
            )
            assert termination.error_code is expected_code


@pytest.mark.asyncio
async def test_bounded_document_rejects_metadata_beyond_scanner_limits() -> None:
    result, _source = await _read(b'{"n":1}')

    assert type(result) is BoundedAuthorityInputSuccessV8
    with pytest.raises(ValueError, match="syntax_node_count"):
        replace(
            result.document,
            syntax_node_count=AUTHORITY_INPUT_MAX_NODES_V8 + 1,
        )
    with pytest.raises(ValueError, match="number-token"):
        replace(
            result.document,
            maximum_number_token_bytes=(result.document.aggregate_decoded_scalar_bytes + 1),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"1", AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT),
        (b"[]", AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT),
        (b'{"x":-0}', AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER),
        (b'{"x":01}', AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER),
        (b'{"x":1.0}', AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER),
        (b'{"x":1e2}', AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER),
        (b'{"x":NaN}', AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER),
        (b'{"x":Infinity}', AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER),
        (b'{"x":TRUE}', AuthorityInputTerminationReasonV8.INVALID_JSON),
        (b'{"x":1}\x0b', AuthorityInputTerminationReasonV8.INVALID_JSON),
    ],
)
async def test_json_profile_rejects_noncanonical_material(
    raw: bytes,
    reason: AuthorityInputTerminationReasonV8,
) -> None:
    result, source = await _read(raw, return_size=1)

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is IncompleteBoundedResponseObservationV8
    assert result.termination is not None
    assert result.termination.reason is reason
    assert source.reusable is False


@pytest.mark.asyncio
async def test_decoded_duplicate_key_and_surrogate_rules() -> None:
    duplicate, _source = await _read(b'{"a":1,"\\u0061":2}', return_size=1)
    valid_pair, _source = await _read(b'{"x":"\\uD83D\\uDE00"}', return_size=1)
    lone, _source = await _read(b'{"x":"\\uD800x"}', return_size=1)

    assert type(duplicate) is BoundedAuthorityInputFailureV8
    assert duplicate.termination is not None
    assert duplicate.termination.reason is AuthorityInputTerminationReasonV8.DUPLICATE_OBJECT_KEY
    assert type(valid_pair) is BoundedAuthorityInputSuccessV8
    assert valid_pair.document.maximum_decoded_string_bytes == 4
    assert type(lone) is BoundedAuthorityInputFailureV8
    assert lone.termination is not None
    assert lone.termination.reason is AuthorityInputTerminationReasonV8.LONE_SURROGATE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":1,"\\u0061":2}',
        b'{"nested":{"a":1,"a":2}}',
    ],
)
async def test_duplicate_keys_fail_for_direct_escaped_and_nested_forms(raw: bytes) -> None:
    result, source = await _read(raw, return_size=1)

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is IncompleteBoundedResponseObservationV8
    assert result.termination is not None
    assert result.termination.phase is AuthorityInputPhaseV8.JSON_SCAN
    assert result.termination.reason is AuthorityInputTerminationReasonV8.DUPLICATE_OBJECT_KEY
    assert source.reusable is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raw", "phase", "reason"),
    [
        (
            b'{"x":"text',
            AuthorityInputPhaseV8.JSON_SCAN,
            AuthorityInputTerminationReasonV8.INVALID_JSON,
        ),
        (
            b'{"x":"text\\',
            AuthorityInputPhaseV8.JSON_SCAN,
            AuthorityInputTerminationReasonV8.INVALID_JSON,
        ),
        (
            b'{"x":-',
            AuthorityInputPhaseV8.JSON_SCAN,
            AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER,
        ),
        (
            b'{"x":tru',
            AuthorityInputPhaseV8.JSON_SCAN,
            AuthorityInputTerminationReasonV8.INVALID_JSON,
        ),
        (
            b'{"x":"\xe2\x82',
            AuthorityInputPhaseV8.UTF8_DECODE,
            AuthorityInputTerminationReasonV8.INVALID_UTF8,
        ),
    ],
)
async def test_eof_truncations_keep_complete_transport_evidence(
    raw: bytes,
    phase: AuthorityInputPhaseV8,
    reason: AuthorityInputTerminationReasonV8,
) -> None:
    result, source = await _read(raw, return_size=1)

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is CompleteBoundedResponseObservationV8
    assert result.termination is not None
    assert result.termination.phase is phase
    assert result.termination.reason is reason
    assert source.reusable is True


def _nested_object(depth: int) -> bytes:
    return (b'{"x":' * (depth - 1)) + b"{}" + (b"}" * (depth - 1))


@pytest.mark.asyncio
async def test_depth_boundary_is_exact() -> None:
    accepted, _source = await _read(_nested_object(64))
    rejected, _source = await _read(_nested_object(65))

    assert type(accepted) is BoundedAuthorityInputSuccessV8
    assert accepted.document.maximum_depth == 64
    assert accepted.document.syntax_node_count < AUTHORITY_INPUT_MAX_NODES_V8
    assert accepted.document.maximum_object_members < 4_096
    assert accepted.document.maximum_array_elements < 4_096
    assert (
        accepted.document.aggregate_decoded_scalar_bytes
        < AUTHORITY_INPUT_MAX_AGGREGATE_SCALAR_BYTES_V8
    )
    assert type(rejected) is BoundedAuthorityInputFailureV8
    assert rejected.termination is not None
    assert rejected.termination.reason is AuthorityInputTerminationReasonV8.DEPTH_LIMIT_EXCEEDED


@pytest.mark.asyncio
async def test_member_and_element_boundaries_are_exact() -> None:
    object_at_limit = b"{" + b",".join(f'"k{index}":0'.encode() for index in range(4_096)) + b"}"
    object_over_limit = object_at_limit[:-1] + b',"overflow":0}'
    array_at_limit = b'{"a":[' + (b"0," * 4_095) + b"0]}"
    array_over_limit = b'{"a":[' + (b"0," * 4_096) + b"0]}"

    for raw in (object_at_limit, array_at_limit):
        result, _source = await _read(raw)
        assert type(result) is BoundedAuthorityInputSuccessV8
        assert result.document.syntax_node_count < AUTHORITY_INPUT_MAX_NODES_V8
        assert result.document.maximum_depth < 64
        assert (
            result.document.aggregate_decoded_scalar_bytes
            < AUTHORITY_INPUT_MAX_AGGREGATE_SCALAR_BYTES_V8
        )
    for raw in (object_over_limit, array_over_limit):
        result, _source = await _read(raw)
        assert type(result) is BoundedAuthorityInputFailureV8
        assert result.termination is not None
        assert (
            result.termination.reason is AuthorityInputTerminationReasonV8.CONTAINER_LIMIT_EXCEEDED
        )


def _node_boundary_document(last_array_elements: int) -> bytes:
    full_array = b"[" + (b"0," * 4_095) + b"0]"
    final_array = b"[" + (b"0," * (last_array_elements - 1)) + b"0]"
    members = [
        f'"k{index}":'.encode() + (full_array if index < 63 else final_array) for index in range(64)
    ]
    return b"{" + b",".join(members) + b"}"


@pytest.mark.asyncio
async def test_node_boundary_is_exact_without_crossing_container_limits() -> None:
    accepted, _source = await _read(_node_boundary_document(3_967))
    rejected, _source = await _read(_node_boundary_document(3_968))

    assert type(accepted) is BoundedAuthorityInputSuccessV8
    assert accepted.document.syntax_node_count == AUTHORITY_INPUT_MAX_NODES_V8
    assert accepted.document.maximum_depth < 64
    assert accepted.document.maximum_object_members < 4_096
    assert accepted.document.maximum_array_elements == 4_096
    accepted_maximum_string_bytes = accepted.document.maximum_decoded_string_bytes
    assert accepted_maximum_string_bytes < AUTHORITY_INPUT_MAX_SCALAR_BYTES_V8
    assert (
        accepted.document.aggregate_decoded_scalar_bytes
        < AUTHORITY_INPUT_MAX_AGGREGATE_SCALAR_BYTES_V8
    )
    assert type(rejected) is BoundedAuthorityInputFailureV8
    assert rejected.termination is not None
    assert rejected.termination.reason is AuthorityInputTerminationReasonV8.NODE_LIMIT_EXCEEDED


@pytest.mark.asyncio
async def test_single_and_aggregate_scalar_boundaries_are_exact() -> None:
    scalar_at_limit = b'{"x":"' + (b"a" * AUTHORITY_INPUT_MAX_SCALAR_BYTES_V8) + b'"}'
    scalar_over_limit = scalar_at_limit[:-2] + b'a"}'

    values = [AUTHORITY_INPUT_MAX_SCALAR_BYTES_V8 - 1] * 4
    aggregate_at_limit = (
        b"{"
        + b",".join(
            f'"{key}":"'.encode() + (b"x" * size) + b'"'
            for key, size in zip("abcd", values, strict=True)
        )
        + b"}"
    )
    aggregate_over_limit = aggregate_at_limit[:-2] + b'x"}'

    scalar_result, _source = await _read(scalar_at_limit)
    scalar_failure, _source = await _read(scalar_over_limit)
    aggregate_result, _source = await _read(aggregate_at_limit)
    aggregate_failure, _source = await _read(aggregate_over_limit)

    assert type(scalar_result) is BoundedAuthorityInputSuccessV8
    assert scalar_result.document.maximum_decoded_string_bytes == (
        AUTHORITY_INPUT_MAX_SCALAR_BYTES_V8
    )
    assert scalar_result.document.syntax_node_count < AUTHORITY_INPUT_MAX_NODES_V8
    assert scalar_result.document.maximum_depth < 64
    assert scalar_result.document.maximum_object_members < 4_096
    assert scalar_result.document.maximum_array_elements < 4_096
    assert type(scalar_failure) is BoundedAuthorityInputFailureV8
    assert scalar_failure.termination is not None
    assert (
        scalar_failure.termination.reason is AuthorityInputTerminationReasonV8.SCALAR_LIMIT_EXCEEDED
    )
    assert type(aggregate_result) is BoundedAuthorityInputSuccessV8
    assert aggregate_result.document.aggregate_decoded_scalar_bytes == (
        AUTHORITY_INPUT_MAX_AGGREGATE_SCALAR_BYTES_V8
    )
    aggregate_maximum_string_bytes = aggregate_result.document.maximum_decoded_string_bytes
    assert aggregate_maximum_string_bytes < AUTHORITY_INPUT_MAX_SCALAR_BYTES_V8
    assert aggregate_result.document.syntax_node_count < AUTHORITY_INPUT_MAX_NODES_V8
    assert aggregate_result.document.maximum_depth < 64
    assert aggregate_result.document.maximum_object_members < 4_096
    assert aggregate_result.document.maximum_array_elements < 4_096
    assert type(aggregate_failure) is BoundedAuthorityInputFailureV8
    assert aggregate_failure.termination is not None
    assert (
        aggregate_failure.termination.reason
        is AuthorityInputTerminationReasonV8.AGGREGATE_SCALAR_LIMIT_EXCEEDED
    )


@pytest.mark.asyncio
async def test_gzip_completion_truncation_crc_and_trailing_witness() -> None:
    good = gzip.compress(b"{}", mtime=0)
    truncated, _source = await _read(good[:-1], encoding=TransportEncodingV8.GZIP)
    corrupt_bytes = bytearray(good)
    corrupt_bytes[-5] ^= 1
    corrupt, _source = await _read(bytes(corrupt_bytes), encoding=TransportEncodingV8.GZIP)
    trailing, _source = await _read(good + b"secret-tail", encoding=TransportEncodingV8.GZIP)

    assert type(truncated) is BoundedAuthorityInputFailureV8
    assert truncated.termination is not None
    assert (
        truncated.termination.reason
        is AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM
    )
    assert type(corrupt) is BoundedAuthorityInputFailureV8
    assert corrupt.termination is not None
    assert corrupt.termination.reason is AuthorityInputTerminationReasonV8.DECOMPRESSION_FAILED
    assert type(trailing) is BoundedAuthorityInputFailureV8
    assert trailing.termination is not None
    assert trailing.termination.reason is AuthorityInputTerminationReasonV8.TRAILING_COMPRESSED_DATA
    assert trailing.observation.observed_wire_prefix_length == len(good) + 1
    assert trailing.observation.observed_wire_prefix_digest == (
        f"sha256:{hashlib.sha256(good + b's').hexdigest()}"
    )


@pytest.mark.asyncio
async def test_empty_gzip_eof_is_the_closed_no_response_finalize_case() -> None:
    result, source = await _read(b"", encoding=TransportEncodingV8.GZIP)

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is NoResponseObservationV8
    assert result.observation.failure_phase is AuthorityInputPhaseV8.RESPONSE_FINALIZE
    assert result.termination is not None
    assert (
        result.termination.reason is AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM
    )
    assert source.reusable is False


class _ScriptedSource:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = outcomes
        self.read_count = 0
        self.abort_count = 0
        self.finishes: list[bool] = []

    async def read(self, _max_bytes: int):
        self.read_count += 1
        if not self.outcomes:
            raise AssertionError("poison read after terminal result")
        return self.outcomes.pop(0)

    def abort_current_read(self) -> None:
        self.abort_count += 1

    def finish_response(self, reusable: bool) -> None:
        self.finishes.append(reusable)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (SourceDisconnectedV8(), AuthorityInputTerminationReasonV8.DISCONNECTED),
        (
            SourceFramingFailureV8(),
            AuthorityInputTerminationReasonV8.TRANSFER_FRAMING_FAILED,
        ),
        (SourceDataV8(b""), AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION),
        (object(), AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION),
    ],
)
async def test_closed_source_outcomes_fail_without_an_accepted_byte(
    outcome: object,
    reason: AuthorityInputTerminationReasonV8,
) -> None:
    source = _ScriptedSource([outcome])
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=_deadline(),
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is NoResponseObservationV8
    assert result.termination is not None
    assert result.termination.reason is reason
    assert source.read_count == 1
    assert source.finishes == [False]


@pytest.mark.asyncio
async def test_oversized_source_return_accepts_only_one_protocol_witness() -> None:
    source = _ScriptedSource([SourceDataV8(b"x" * (AUTHORITY_INPUT_READ_QUANTUM_V8 + 1))])
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=_deadline(),
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is IncompleteBoundedResponseObservationV8
    assert result.observation.observed_wire_prefix_length == 1
    assert result.observation.observed_wire_prefix_digest == (
        f"sha256:{hashlib.sha256(b'x').hexdigest()}"
    )
    assert result.termination is not None
    assert result.termination.reason is AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION
    assert source.read_count == 1


@pytest.mark.asyncio
async def test_http11_content_length_and_chunked_sources_prove_eof() -> None:
    content_length = admit_http11_authority_input_v8(
        b"HTTP/1.1 200 \r\nContent-Length:\t2 \t\r\n\r\n{}"
    )
    chunked = admit_http11_authority_input_v8(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n"
    )

    for admitted in (content_length, chunked):
        result = await read_bounded_authority_input_v8(
            admitted.source,
            transport_encoding=admitted.transport_encoding,
            operation_deadline=_deadline(),
        )
        assert type(result) is BoundedAuthorityInputSuccessV8
        assert result.document.raw_bytes == b"{}"


def test_kernel_owned_source_lifecycle_hooks_are_idempotent() -> None:
    sources = (
        InProcessAuthorityInputSourceV8(b"{}"),
        Http11AuthorityInputSourceV8(
            b"{}",
            body_offset=0,
            content_length=2,
            chunked=False,
        ),
    )

    for source in sources:
        source.abort_current_read()
        source.abort_current_read()
        assert source.abort_count == 1

        source.finish_response(True)
        source.finish_response(False)
        source.abort_current_read()
        assert source.finish_count == 1
        assert source.reusable is True
        assert source.abort_count == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 200 \r\n\r\n",
        b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 204 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 00\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: br\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nUpgrade: websocket\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive, Upgrade\r\n\r\n",
    ],
)
def test_http11_admission_rejects_wider_or_ambiguous_profiles(raw: bytes) -> None:
    with pytest.raises(AgentKernelError):
        admit_http11_authority_input_v8(raw)


def test_http11_content_length_limit_fails_before_source_admission() -> None:
    accepted = (
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(AUTHORITY_INPUT_BYTE_LIMIT_V8).encode()
        + b"\r\n\r\n"
    )
    admitted = admit_http11_authority_input_v8(accepted)
    assert admitted.transport_encoding is TransportEncodingV8.IDENTITY

    for value in (AUTHORITY_INPUT_BYTE_LIMIT_V8 + 1, 10_000_000):
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(value).encode() + b"\r\n\r\n"
        with pytest.raises(AgentKernelError) as captured:
            admit_http11_authority_input_v8(raw)
        assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


class _FixedClock:
    def __init__(self, now: datetime, *, spurious_waiter: bool = False) -> None:
        self.value = now
        self.spurious_waiter = spurious_waiter
        self.wait_forever = asyncio.Event()

    def now(self) -> datetime:
        return self.value

    async def wait_until(self, _deadline: datetime) -> None:
        if self.spurious_waiter:
            return
        await self.wait_forever.wait()


class _ManualToken:
    def __init__(self) -> None:
        self.event = asyncio.Event()

    def is_cancelled(self) -> bool:
        return self.event.is_set()

    async def wait_cancelled(self) -> None:
        await self.event.wait()

    def cancel(self) -> None:
        self.event.set()


class _HungSource:
    def __init__(self, *, late_secret: str | None = None) -> None:
        self.started = asyncio.Event()
        self.released = asyncio.Event()
        self.late_secret = late_secret
        self.read_count = 0
        self.abort_count = 0
        self.events: list[str] = []

    async def read(self, _max_bytes: int):
        self.read_count += 1
        self.started.set()
        try:
            await self.released.wait()
        except asyncio.CancelledError:
            await self.released.wait()
            if self.late_secret is not None:
                raise RuntimeError(self.late_secret) from None
            raise
        return SourceEofV8()

    def abort_current_read(self) -> None:
        self.abort_count += 1
        self.events.append("abort")
        self.released.set()

    def finish_response(self, reusable: bool) -> None:
        self.events.append(f"finish:{reusable}")


@pytest.mark.asyncio
@pytest.mark.parametrize("offset_seconds", [-1, 0, 1])
async def test_deadline_t_minus_one_equality_and_t_plus_one(
    offset_seconds: int,
) -> None:
    deadline = datetime(2030, 1, 1, tzinfo=UTC)
    now = deadline + timedelta(seconds=offset_seconds)
    source = _ScriptedSource([SourceDataV8(b"{}"), SourceEofV8()])
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=deadline,
        clock=_FixedClock(now),
        cancellation_token=_ManualToken(),
    )

    if offset_seconds < 0:
        assert type(result) is BoundedAuthorityInputSuccessV8
        assert source.read_count == 2
        assert source.finishes == [True]
        return
    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is NoResponseObservationV8
    assert result.observation.failure_phase is AuthorityInputPhaseV8.BEFORE_RESPONSE
    assert result.termination is not None
    assert result.termination.reason is AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED
    assert source.read_count == 0
    assert source.finishes == [False]


@pytest.mark.asyncio
async def test_pending_cancellation_aborts_before_finish_and_sinks_late_exception() -> None:
    secret = "synthetic-provider-secret"
    source = _HungSource(late_secret=secret)
    token = _ManualToken()
    clock = _FixedClock(datetime(2030, 1, 1, tzinfo=UTC))
    deadline = datetime(2030, 1, 2, tzinfo=UTC)
    loop = asyncio.get_running_loop()
    captured_contexts: list[dict[str, object]] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: captured_contexts.append(context))
    try:
        task = asyncio.create_task(
            read_bounded_authority_input_v8(
                source,
                transport_encoding=TransportEncodingV8.IDENTITY,
                operation_deadline=deadline,
                clock=clock,
                cancellation_token=token,
            )
        )
        await source.started.wait()
        token.cancel()
        result = await task
        await asyncio.sleep(0)
        await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(previous_handler)

    assert type(result) is BoundedAuthorityInputFailureV8
    assert result.termination is not None
    assert result.termination.reason is AuthorityInputTerminationReasonV8.CANCELLED
    assert source.read_count == 1
    assert source.abort_count == 1
    assert source.events == ["abort", "finish:False"]
    assert captured_contexts == []


@pytest.mark.asyncio
async def test_spurious_deadline_waiter_fails_closed_without_rearm() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)
    source = _HungSource()
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=now + timedelta(days=1),
        clock=_FixedClock(now, spurious_waiter=True),
        cancellation_token=_ManualToken(),
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert result.termination is not None
    assert result.termination.reason is AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE
    assert result.termination.phase is AuthorityInputPhaseV8.WIRE_READ
    assert source.read_count == 1
    assert source.abort_count == 1
    assert source.events == ["abort", "finish:False"]
