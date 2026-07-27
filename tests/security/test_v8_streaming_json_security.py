from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import struct
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from agentkernel.authority import v8_streaming as streaming
from agentkernel.authority.v8_contracts import (
    AUTHORITY_INPUT_BYTE_LIMIT_V8,
    AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8,
    AuthorityInputPhaseV8,
    AuthorityInputTerminationReasonV8,
    CompleteBoundedResponseObservationV8,
    IncompleteBoundedResponseObservationV8,
    NoResponseObservationV8,
    OverflowBoundaryV8,
    OverflowPrefixObservationV8,
    TransportEncodingV8,
)
from agentkernel.authority.v8_streaming import (
    AUTHORITY_INPUT_READ_QUANTUM_V8,
    HTTP11_MAX_AGGREGATE_HEADER_BYTES_V8,
    HTTP11_MAX_CHUNK_FRAMING_BYTES_V8,
    HTTP11_MAX_CHUNK_SIZE_LINE_BYTES_V8,
    HTTP11_MAX_HEADER_BLOCK_BYTES_V8,
    HTTP11_MAX_IMMUTABLE_RESPONSE_BYTES_V8,
    HTTP11_MAX_NONZERO_CHUNKS_V8,
    HTTP11_MAX_STATUS_LINE_BYTES_V8,
    BoundedAuthorityInputFailureV8,
    BoundedAuthorityInputSuccessV8,
    InProcessAuthorityInputSourceV8,
    SourceDataV8,
    SourceDisconnectedV8,
    SourceEofV8,
    SourceFramingFailureV8,
    admit_http11_authority_input_v8,
    read_bounded_authority_input_v8,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from pydantic import BaseModel, TypeAdapter

pytestmark = pytest.mark.security


def _deadline() -> datetime:
    return datetime.now(UTC) + timedelta(seconds=60)


async def _read(
    body: bytes,
    *,
    encoding: TransportEncodingV8 = TransportEncodingV8.IDENTITY,
):
    source = InProcessAuthorityInputSourceV8(body)
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=encoding,
        operation_deadline=_deadline(),
    )
    return result, source


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"\xef\xbb\xbf{}", AuthorityInputTerminationReasonV8.INVALID_UTF8),
        (b"\xff\xfe{\x00}\x00", AuthorityInputTerminationReasonV8.INVALID_UTF8),
        (b'{"x":"\xc0\x80"}', AuthorityInputTerminationReasonV8.INVALID_UTF8),
        (b'{"x":"\xed\xa0\x80"}', AuthorityInputTerminationReasonV8.INVALID_UTF8),
        (b'{"x":"\xf4\x90\x80\x80"}', AuthorityInputTerminationReasonV8.INVALID_UTF8),
        (b'{"x":"\xe2("}', AuthorityInputTerminationReasonV8.INVALID_UTF8),
        (b'{"x":"\x1f"}', AuthorityInputTerminationReasonV8.INVALID_JSON),
        ('{"x":\u0661}'.encode(), AuthorityInputTerminationReasonV8.INVALID_JSON),
        (b'{"x":"\\uDC00"}', AuthorityInputTerminationReasonV8.LONE_SURROGATE),
        (b'{"x":"\\uD800\\u0041"}', AuthorityInputTerminationReasonV8.LONE_SURROGATE),
        (b'{"x":"\\uD800', AuthorityInputTerminationReasonV8.LONE_SURROGATE),
    ],
)
async def test_utf8_escape_and_ascii_number_security_profile(
    raw: bytes,
    reason: AuthorityInputTerminationReasonV8,
) -> None:
    source = InProcessAuthorityInputSourceV8(raw, return_size=1)
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=_deadline(),
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert result.termination is not None
    assert result.termination.reason is reason
    assert source.finish_count == 1
    assert source.reusable is (raw == b'{"x":"\\uD800')


@pytest.mark.asyncio
async def test_identity_wire_limit_includes_the_first_excess_witness() -> None:
    at_limit = b"{}" + (b" " * (AUTHORITY_INPUT_BYTE_LIMIT_V8 - 2))
    accepted, accepted_source = await _read(at_limit)
    overflow, overflow_source = await _read(at_limit + b"!")

    assert type(accepted) is BoundedAuthorityInputSuccessV8
    assert accepted.observation.complete_wire_length == AUTHORITY_INPUT_BYTE_LIMIT_V8
    assert accepted_source.reusable is True
    assert type(overflow) is BoundedAuthorityInputFailureV8
    assert type(overflow.observation) is OverflowPrefixObservationV8
    assert overflow.observation.exceeded_boundary is OverflowBoundaryV8.UNCOMPRESSED_WIRE
    assert overflow.observation.observed_wire_prefix_length == (
        AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
    )
    assert overflow.observation.observed_decompressed_prefix_length == (
        AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
    )
    assert overflow.observation.observed_wire_prefix_digest == (
        f"sha256:{hashlib.sha256(at_limit + b'!').hexdigest()}"
    )
    assert overflow_source.reusable is False


@pytest.mark.asyncio
async def test_gzip_decompressed_limit_includes_the_first_excess_witness() -> None:
    at_limit = b"{}" + (b" " * (AUTHORITY_INPUT_BYTE_LIMIT_V8 - 2))
    accepted_wire = gzip.compress(at_limit, compresslevel=9, mtime=0)
    overflow_wire = gzip.compress(at_limit + b" ", compresslevel=9, mtime=0)

    accepted, accepted_source = await _read(
        accepted_wire,
        encoding=TransportEncodingV8.GZIP,
    )
    overflow, overflow_source = await _read(
        overflow_wire,
        encoding=TransportEncodingV8.GZIP,
    )

    assert type(accepted) is BoundedAuthorityInputSuccessV8
    assert accepted.observation.complete_decompressed_length == (AUTHORITY_INPUT_BYTE_LIMIT_V8)
    assert accepted_source.reusable is True
    assert type(overflow) is BoundedAuthorityInputFailureV8
    assert type(overflow.observation) is OverflowPrefixObservationV8
    assert overflow.observation.exceeded_boundary is OverflowBoundaryV8.DECOMPRESSED
    assert overflow.observation.observed_decompressed_prefix_length == (
        AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
    )
    assert overflow.observation.observed_decompressed_prefix_digest == (
        f"sha256:{hashlib.sha256(at_limit + b' ').hexdigest()}"
    )
    assert overflow_source.reusable is False


def _reference_gzip_prefix_for_output_count(
    wire: bytes,
    *,
    required_output_bytes: int,
) -> bytes:
    """Find the minimal compressed prefix with an independent bytewise replay."""

    decoder = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    produced = 0
    for index, byte in enumerate(wire):
        pending = bytes((byte,))
        while True:
            output = decoder.decompress(
                pending,
                max_length=required_output_bytes - produced,
            )
            produced += len(output)
            if produced >= required_output_bytes:
                return wire[: index + 1]
            if decoder.unconsumed_tail:
                pending = decoder.unconsumed_tail
                continue
            pending = b""
            if not output:
                break
    raise AssertionError("reference GZIP stream did not produce the required output")


def _reference_gzip_error_prefix(wire: bytes) -> tuple[bytes, bytes]:
    """Return the first bytewise zlib-error witness and prior output."""

    decoder = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    decompressed = bytearray()
    for index, byte in enumerate(wire):
        pending = bytes((byte,))
        while True:
            try:
                output = decoder.decompress(
                    pending,
                    max_length=AUTHORITY_INPUT_READ_QUANTUM_V8,
                )
            except zlib.error:
                return wire[: index + 1], bytes(decompressed)
            decompressed.extend(output)
            if decoder.unconsumed_tail:
                pending = decoder.unconsumed_tail
                continue
            pending = b""
            if not output:
                break
    raise AssertionError("reference GZIP stream did not produce a zlib error")


@pytest.mark.asyncio
async def test_gzip_scanner_witness_before_limit_precedes_first_excess_byte() -> None:
    before_limit = b"{}" + (b" " * (AUTHORITY_INPUT_BYTE_LIMIT_V8 - 3)) + b"@" + b" "
    at_first_excess = b"{}" + (b" " * (AUTHORITY_INPUT_BYTE_LIMIT_V8 - 2)) + b"@"
    cases = (
        (
            gzip.compress(before_limit, mtime=0),
            AuthorityInputTerminationReasonV8.INVALID_JSON,
            (1, 7, AUTHORITY_INPUT_READ_QUANTUM_V8),
        ),
        (
            gzip.compress(at_first_excess, mtime=0),
            None,
            (
                1,
                2,
                3,
                7,
                63,
                64,
                65,
                1_024,
                65_535,
                AUTHORITY_INPUT_READ_QUANTUM_V8,
            ),
        ),
    )

    for wire, expected_reason, return_sizes in cases:
        expected_wire_prefix: bytes | None = None
        if expected_reason is None:
            expected_wire_prefix = _reference_gzip_prefix_for_output_count(
                wire,
                required_output_bytes=AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8,
            )
        baseline_observation: object | None = None
        for return_size in return_sizes:
            source = InProcessAuthorityInputSourceV8(wire, return_size=return_size)
            result = await read_bounded_authority_input_v8(
                source,
                transport_encoding=TransportEncodingV8.GZIP,
                operation_deadline=_deadline(),
            )

            assert type(result) is BoundedAuthorityInputFailureV8
            if expected_reason is None:
                assert type(result.observation) is OverflowPrefixObservationV8
                assert result.observation.exceeded_boundary is OverflowBoundaryV8.DECOMPRESSED
                assert expected_wire_prefix is not None
                assert result.observation.observed_wire_prefix_length == len(expected_wire_prefix)
                assert result.observation.observed_wire_prefix_digest == (
                    f"sha256:{hashlib.sha256(expected_wire_prefix).hexdigest()}"
                )
                assert result.termination is None
            else:
                assert type(result.observation) is IncompleteBoundedResponseObservationV8
                assert result.termination is not None
                assert result.termination.phase is AuthorityInputPhaseV8.JSON_SCAN
                assert result.termination.reason is expected_reason
            assert result.observation.observed_decompressed_prefix_length == (
                AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
                if expected_reason is None
                else AUTHORITY_INPUT_BYTE_LIMIT_V8
            )
            if baseline_observation is None:
                baseline_observation = result.observation
            else:
                assert result.observation == baseline_observation
            assert source.reusable is False


@pytest.mark.asyncio
async def test_corrupt_crc_exact_wire_witness_is_partition_invariant() -> None:
    raw = b'{"valid":true}'
    corrupted = bytearray(gzip.compress(raw, mtime=0))
    corrupted[-8] ^= 0x01
    wire = bytes(corrupted)
    expected_wire_prefix, expected_decompressed = _reference_gzip_error_prefix(wire)
    assert expected_decompressed == raw

    baseline: IncompleteBoundedResponseObservationV8 | None = None
    for return_size in (
        1,
        2,
        3,
        7,
        63,
        64,
        65,
        1_024,
        65_535,
        AUTHORITY_INPUT_READ_QUANTUM_V8,
    ):
        source = InProcessAuthorityInputSourceV8(wire, return_size=return_size)
        result = await read_bounded_authority_input_v8(
            source,
            transport_encoding=TransportEncodingV8.GZIP,
            operation_deadline=_deadline(),
        )

        assert type(result) is BoundedAuthorityInputFailureV8
        assert type(result.observation) is IncompleteBoundedResponseObservationV8
        assert result.observation.observed_wire_prefix_length == len(expected_wire_prefix)
        assert result.observation.observed_wire_prefix_digest == (
            f"sha256:{hashlib.sha256(expected_wire_prefix).hexdigest()}"
        )
        assert result.observation.observed_decompressed_prefix_length == len(raw)
        assert result.observation.observed_decompressed_prefix_digest == (
            f"sha256:{hashlib.sha256(raw).hexdigest()}"
        )
        assert result.termination is not None
        assert result.termination.phase is AuthorityInputPhaseV8.CONTENT_DECODE
        assert result.termination.reason is AuthorityInputTerminationReasonV8.DECOMPRESSION_FAILED
        if baseline is None:
            baseline = result.observation
        else:
            assert result.observation == baseline
        assert source.reusable is False


@pytest.mark.asyncio
async def test_incompressible_gzip_overflow_crosses_many_logical_content_quanta(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    random_material = hashlib.shake_256(b"g1a-overflow-whitespace").digest(
        AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8 - 2
    )
    whitespace = b" \t\r\n"
    translation = bytes(whitespace[index % len(whitespace)] for index in range(256))
    raw = b"{}" + random_material.translate(translation)
    assert len(raw) == AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
    wire = gzip.compress(raw, compresslevel=6, mtime=0)
    assert len(wire) > AUTHORITY_INPUT_READ_QUANTUM_V8 * 10

    replay_window_sizes: list[tuple[int, int]] = []
    original_append = streaming._append_gzip_replay_window_v8

    def observed_append(window: bytearray, data: bytes) -> None:
        original_append(window, data)
        replay_window_sizes.append((len(window), len(data)))

    monkeypatch.setattr(streaming, "_append_gzip_replay_window_v8", observed_append)

    baseline: OverflowPrefixObservationV8 | None = None
    for return_size in (65_535, AUTHORITY_INPUT_READ_QUANTUM_V8):
        source = InProcessAuthorityInputSourceV8(wire, return_size=return_size)
        result = await read_bounded_authority_input_v8(
            source,
            transport_encoding=TransportEncodingV8.GZIP,
            operation_deadline=_deadline(),
        )

        assert type(result) is BoundedAuthorityInputFailureV8
        assert type(result.observation) is OverflowPrefixObservationV8
        assert result.observation.exceeded_boundary is OverflowBoundaryV8.DECOMPRESSED
        assert (
            result.observation.observed_decompressed_prefix_length
            == AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
        )
        assert result.observation.observed_decompressed_prefix_digest == (
            f"sha256:{hashlib.sha256(raw).hexdigest()}"
        )
        if baseline is None:
            baseline = result.observation
        else:
            assert result.observation == baseline
        assert source.reusable is False

    assert replay_window_sizes
    assert max(size for size, _appended in replay_window_sizes) <= (AUTHORITY_INPUT_READ_QUANTUM_V8)
    assert sum(size == appended for size, appended in replay_window_sizes if appended) > 2


def _gzip_with_comment(total_length: int) -> bytes:
    payload = b"{}"
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    deflate = compressor.compress(payload) + compressor.flush()
    header = b"\x1f\x8b\x08\x10\x00\x00\x00\x00\x00\xff"
    trailer = struct.pack("<II", zlib.crc32(payload), len(payload))
    comment_length = total_length - len(header) - 1 - len(deflate) - len(trailer)
    assert comment_length >= 0
    return header + (b"a" * comment_length) + b"\x00" + deflate + trailer


@pytest.mark.asyncio
async def test_gzip_compressed_limit_does_not_decode_the_witness() -> None:
    at_limit = _gzip_with_comment(AUTHORITY_INPUT_BYTE_LIMIT_V8)
    over_limit = _gzip_with_comment(AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8)
    accepted, _source = await _read(at_limit, encoding=TransportEncodingV8.GZIP)
    overflow, source = await _read(over_limit, encoding=TransportEncodingV8.GZIP)

    assert type(accepted) is BoundedAuthorityInputSuccessV8
    assert type(overflow) is BoundedAuthorityInputFailureV8
    assert type(overflow.observation) is OverflowPrefixObservationV8
    assert overflow.observation.exceeded_boundary is OverflowBoundaryV8.COMPRESSED_WIRE
    assert overflow.observation.observed_wire_prefix_digest == (
        f"sha256:{hashlib.sha256(over_limit).hexdigest()}"
    )
    assert overflow.observation.observed_decompressed_prefix_length == 2
    assert overflow.observation.observed_decompressed_prefix_digest == (
        f"sha256:{hashlib.sha256(b'{}').hexdigest()}"
    )
    assert source.reusable is False


def _gzip_with_empty_stored_blocks(empty_block_count: int) -> bytes:
    payload = b"{}"
    header = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"
    empty_nonfinal_block = b"\x00\x00\x00\xff\xff"
    final_block = b"\x01\x02\x00\xfd\xff{}"
    trailer = struct.pack("<II", zlib.crc32(payload), len(payload))
    return header + (empty_nonfinal_block * empty_block_count) + final_block + trailer


@pytest.mark.asyncio
async def test_gzip_many_empty_blocks_and_incompressible_json_terminate_boundedly() -> None:
    many_blocks = _gzip_with_empty_stored_blocks(40_000)
    random_bytes = hashlib.shake_256(b"g1a-incompressible-json").digest(131_072)
    incompressible_raw = b'{"x":"' + random_bytes.hex().encode("ascii") + b'"}'
    incompressible_wire = gzip.compress(incompressible_raw, compresslevel=9, mtime=0)

    many_blocks_result, many_blocks_source = await _read(
        many_blocks,
        encoding=TransportEncodingV8.GZIP,
    )
    incompressible_result, incompressible_source = await _read(
        incompressible_wire,
        encoding=TransportEncodingV8.GZIP,
    )

    assert type(many_blocks_result) is BoundedAuthorityInputSuccessV8
    assert many_blocks_result.document.raw_bytes == b"{}"
    assert many_blocks_source.reusable is True
    assert type(incompressible_result) is BoundedAuthorityInputSuccessV8
    assert incompressible_result.document.raw_bytes == incompressible_raw
    assert incompressible_source.reusable is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cut_name", "cut"),
    [
        ("header", 9),
        ("deflate-body", 11),
        ("trailer", -1),
    ],
)
async def test_gzip_truncated_header_body_and_trailer_are_distinct_eof_fixtures(
    cut_name: str,
    cut: int,
) -> None:
    del cut_name
    good = gzip.compress(b'{"payload":"enough-deflate-body"}', mtime=0)
    truncated_wire = good[:cut]
    result, source = await _read(
        truncated_wire,
        encoding=TransportEncodingV8.GZIP,
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is IncompleteBoundedResponseObservationV8
    assert result.termination is not None
    assert result.termination.phase is AuthorityInputPhaseV8.RESPONSE_FINALIZE
    termination_reason = result.termination.reason
    assert termination_reason is AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM
    assert source.reusable is False


class _InstrumentedDecompressor:
    def __init__(
        self,
        inner: object,
        events: list[tuple[str, bool, int]],
        *,
        copied: bool = False,
    ) -> None:
        self.inner = inner
        self.events = events
        self.copied = copied

    @property
    def eof(self) -> bool:
        self.events.append(("eof", self.copied, 0))
        return self.inner.eof

    @property
    def unconsumed_tail(self) -> bytes:
        self.events.append(("unconsumed_tail", self.copied, 0))
        return self.inner.unconsumed_tail

    @property
    def unused_data(self) -> bytes:
        self.events.append(("unused_data", self.copied, 0))
        return self.inner.unused_data

    def copy(self) -> _InstrumentedDecompressor:
        self.events.append(("copy", self.copied, 0))
        return _InstrumentedDecompressor(
            self.inner.copy(),
            self.events,
            copied=True,
        )

    def decompress(self, data: bytes, max_length: int = 0) -> bytes:
        self.events.append(("decompress", self.copied, max_length))
        return self.inner.decompress(data, max_length=max_length)


@pytest.mark.asyncio
async def test_gzip_decoder_contract_and_copy_replay_are_exercised_directly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wire = gzip.compress(b"@", mtime=0)
    original_factory = zlib.decompressobj
    events: list[tuple[str, bool, int]] = []

    def instrumented_factory(*args: object, **kwargs: object) -> _InstrumentedDecompressor:
        return _InstrumentedDecompressor(
            original_factory(*args, **kwargs),
            events,
        )

    monkeypatch.setattr(streaming.zlib, "decompressobj", instrumented_factory)
    result, source = await _read(wire, encoding=TransportEncodingV8.GZIP)

    assert type(result) is BoundedAuthorityInputFailureV8
    assert result.termination is not None
    assert result.termination.reason is AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT
    assert source.reusable is False
    assert {"eof", "unconsumed_tail", "unused_data", "copy"} <= {event[0] for event in events}
    decompress_events = [event for event in events if event[0] == "decompress"]
    assert decompress_events
    assert all(max_length > 0 for _name, _copied, max_length in decompress_events)
    assert any(copied for _name, copied, _max_length in decompress_events)


def test_gzip_replay_window_is_bounded_to_one_transport_quantum() -> None:
    window = bytearray()
    streaming._append_gzip_replay_window_v8(
        window,
        b"x" * AUTHORITY_INPUT_READ_QUANTUM_V8,
    )
    assert len(window) == AUTHORITY_INPUT_READ_QUANTUM_V8
    with pytest.raises(ValueError, match="one logical transport quantum"):
        streaming._append_gzip_replay_window_v8(window, b"x")


@pytest.mark.asyncio
async def test_fixed_logical_quantum_is_independent_of_source_partition() -> None:
    identity_body = b"@\xff"
    identity_prefix = b"@"
    for return_size in (1, 2, AUTHORITY_INPUT_READ_QUANTUM_V8):
        source = InProcessAuthorityInputSourceV8(identity_body, return_size=return_size)
        result = await read_bounded_authority_input_v8(
            source,
            transport_encoding=TransportEncodingV8.IDENTITY,
            operation_deadline=_deadline(),
        )
        assert type(result) is BoundedAuthorityInputFailureV8
        assert type(result.observation) is IncompleteBoundedResponseObservationV8
        assert result.observation.observed_wire_prefix_length == len(identity_prefix)
        assert result.observation.observed_wire_prefix_digest == (
            f"sha256:{hashlib.sha256(identity_prefix).hexdigest()}"
        )
        assert result.termination is not None
        assert result.termination.phase is AuthorityInputPhaseV8.JSON_SCAN
        assert result.termination.reason is AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT
        assert source.reusable is False

    gzip_raw = b"@"
    gzip_wire = gzip.compress(gzip_raw, mtime=0)
    replay = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    gzip_prefix = b""
    for byte in gzip_wire:
        gzip_prefix += bytes((byte,))
        if replay.decompress(bytes((byte,)), max_length=1):
            break
    assert gzip_prefix
    for return_size in (1, 2, 3, 7, len(gzip_wire)):
        source = InProcessAuthorityInputSourceV8(gzip_wire, return_size=return_size)
        result = await read_bounded_authority_input_v8(
            source,
            transport_encoding=TransportEncodingV8.GZIP,
            operation_deadline=_deadline(),
        )
        assert type(result) is BoundedAuthorityInputFailureV8
        assert type(result.observation) is IncompleteBoundedResponseObservationV8
        assert result.observation.observed_wire_prefix_length == len(gzip_prefix)
        assert result.observation.observed_wire_prefix_digest == (
            f"sha256:{hashlib.sha256(gzip_prefix).hexdigest()}"
        )
        assert result.observation.observed_decompressed_prefix_length == 1
        assert result.observation.observed_decompressed_prefix_digest == (
            f"sha256:{hashlib.sha256(gzip_raw).hexdigest()}"
        )
        assert result.termination is not None
        assert result.termination.phase is AuthorityInputPhaseV8.JSON_SCAN
        assert result.termination.reason is AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT
        assert source.reusable is False


@pytest.mark.asyncio
async def test_buffered_gzip_output_is_drained_before_accepting_another_read() -> None:
    raw = b'{"x":"' + (b"a" * (131_071 - 6)) + b'\xc3X"}'
    wire = gzip.compress(raw, mtime=0)
    expected_decompressed_prefix = raw[: raw.index(b"\xc3") + 2]
    replay = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    produced = 0
    expected_wire_length = 0
    for index, byte in enumerate(wire, start=1):
        expected_wire_length = index
        output = replay.decompress(
            bytes((byte,)),
            max_length=len(expected_decompressed_prefix) - produced,
        )
        produced += len(output)
        while produced < len(expected_decompressed_prefix):
            output = replay.decompress(
                b"",
                max_length=len(expected_decompressed_prefix) - produced,
            )
            produced += len(output)
            if not output:
                break
        if produced == len(expected_decompressed_prefix):
            break
    assert produced == len(expected_decompressed_prefix)

    for return_size in (1, 2, 3, 7, 63, AUTHORITY_INPUT_READ_QUANTUM_V8):
        source = InProcessAuthorityInputSourceV8(wire, return_size=return_size)
        result = await read_bounded_authority_input_v8(
            source,
            transport_encoding=TransportEncodingV8.GZIP,
            operation_deadline=_deadline(),
        )

        assert type(result) is BoundedAuthorityInputFailureV8
        assert type(result.observation) is IncompleteBoundedResponseObservationV8
        assert result.observation.observed_wire_prefix_length == expected_wire_length
        assert result.observation.observed_wire_prefix_digest == (
            f"sha256:{hashlib.sha256(wire[:expected_wire_length]).hexdigest()}"
        )
        assert result.observation.observed_decompressed_prefix_length == len(
            expected_decompressed_prefix
        )
        assert result.observation.observed_decompressed_prefix_digest == (
            f"sha256:{hashlib.sha256(expected_decompressed_prefix).hexdigest()}"
        )
        assert result.termination is not None
        assert result.termination.phase is AuthorityInputPhaseV8.UTF8_DECODE
        assert result.termination.reason is AuthorityInputTerminationReasonV8.INVALID_UTF8
        assert source.reusable is False


@pytest.mark.asyncio
async def test_empty_and_one_byte_gzip_use_distinct_eof_evidence() -> None:
    valid_empty_member = gzip.compress(b"", mtime=0)
    complete, complete_source = await _read(
        valid_empty_member,
        encoding=TransportEncodingV8.GZIP,
    )
    truncated, truncated_source = await _read(
        valid_empty_member[:1],
        encoding=TransportEncodingV8.GZIP,
    )

    assert type(complete) is BoundedAuthorityInputFailureV8
    assert type(complete.observation) is CompleteBoundedResponseObservationV8
    assert complete.observation.complete_wire_digest == (
        f"sha256:{hashlib.sha256(valid_empty_member).hexdigest()}"
    )
    assert complete.observation.complete_decompressed_length == 0
    assert complete.termination is not None
    assert complete.termination.reason is AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT
    assert complete_source.reusable is True

    assert type(truncated) is BoundedAuthorityInputFailureV8
    assert type(truncated.observation) is IncompleteBoundedResponseObservationV8
    assert truncated.observation.observed_wire_prefix_length == 1
    assert truncated.observation.observed_wire_prefix_digest == (
        f"sha256:{hashlib.sha256(valid_empty_member[:1]).hexdigest()}"
    )
    assert truncated.termination is not None
    assert (
        truncated.termination.reason
        is AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM
    )
    assert truncated_source.reusable is False


@pytest.mark.asyncio
async def test_gzip_trailing_witness_is_identical_at_every_source_split() -> None:
    raw = b"{}"
    first_member = gzip.compress(raw, mtime=0)
    tails = (gzip.compress(b'{"second":true}', mtime=0), b"arbitrary-trailing")
    for tail in tails:
        wire = first_member + tail
        expected_wire_prefix = first_member + tail[:1]
        for return_size in range(1, len(wire) + 1):
            source = InProcessAuthorityInputSourceV8(wire, return_size=return_size)
            result = await read_bounded_authority_input_v8(
                source,
                transport_encoding=TransportEncodingV8.GZIP,
                operation_deadline=_deadline(),
            )
            assert type(result) is BoundedAuthorityInputFailureV8
            assert type(result.observation) is IncompleteBoundedResponseObservationV8
            assert result.observation.observed_wire_prefix_length == len(expected_wire_prefix)
            assert result.observation.observed_wire_prefix_digest == (
                f"sha256:{hashlib.sha256(expected_wire_prefix).hexdigest()}"
            )
            assert result.observation.observed_decompressed_prefix_length == len(raw)
            assert result.observation.observed_decompressed_prefix_digest == (
                f"sha256:{hashlib.sha256(raw).hexdigest()}"
            )
            assert result.termination is not None
            assert (
                result.termination.reason
                is AuthorityInputTerminationReasonV8.TRAILING_COMPRESSED_DATA
            )
            assert source.reusable is False


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal_kind", ["trailing", "corrupt-crc"])
@pytest.mark.parametrize(
    ("raw", "phase", "reason"),
    [
        (
            b"@",
            AuthorityInputPhaseV8.JSON_SCAN,
            AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT,
        ),
        (
            b"\xff",
            AuthorityInputPhaseV8.UTF8_DECODE,
            AuthorityInputTerminationReasonV8.INVALID_UTF8,
        ),
        (
            b'{"a":1,"a":2}',
            AuthorityInputPhaseV8.JSON_SCAN,
            AuthorityInputTerminationReasonV8.DUPLICATE_OBJECT_KEY,
        ),
        (
            (b'{"x":' * 64) + b"{}" + (b"}" * 64),
            AuthorityInputPhaseV8.JSON_SCAN,
            AuthorityInputTerminationReasonV8.DEPTH_LIMIT_EXCEEDED,
        ),
    ],
)
async def test_decoded_witness_precedes_later_gzip_terminal_at_every_source_split(
    raw: bytes,
    phase: AuthorityInputPhaseV8,
    reason: AuthorityInputTerminationReasonV8,
    terminal_kind: str,
) -> None:
    member = gzip.compress(raw, mtime=0)
    if terminal_kind == "trailing":
        wire = member + b"X"
    else:
        corrupt = bytearray(member)
        corrupt[-1] ^= 1
        wire = bytes(corrupt)

    baseline_observation: IncompleteBoundedResponseObservationV8 | None = None
    for return_size in (1, 2, 3, 7, 63, AUTHORITY_INPUT_READ_QUANTUM_V8):
        source = InProcessAuthorityInputSourceV8(wire, return_size=return_size)
        result = await read_bounded_authority_input_v8(
            source,
            transport_encoding=TransportEncodingV8.GZIP,
            operation_deadline=_deadline(),
        )

        assert type(result) is BoundedAuthorityInputFailureV8
        assert type(result.observation) is IncompleteBoundedResponseObservationV8
        assert result.termination is not None
        assert result.termination.phase is phase
        assert result.termination.reason is reason
        observed_wire_prefix = wire[: result.observation.observed_wire_prefix_length]
        assert result.observation.observed_wire_prefix_digest == (
            f"sha256:{hashlib.sha256(observed_wire_prefix).hexdigest()}"
        )
        assert result.observation.observed_decompressed_prefix_digest == (
            "sha256:"
            + hashlib.sha256(
                raw[: result.observation.observed_decompressed_prefix_length]
            ).hexdigest()
        )
        if baseline_observation is None:
            baseline_observation = result.observation
        else:
            assert result.observation == baseline_observation
        assert source.reusable is False


class _PoisonSource:
    def __init__(self, first: object) -> None:
        self.first = first
        self.read_count = 0
        self.abort_count = 0
        self.finishes: list[bool] = []

    async def read(self, _max_bytes: int):
        self.read_count += 1
        if self.read_count > 1:
            raise AssertionError("poison read after first terminal witness")
        if isinstance(self.first, BaseException):
            raise self.first
        return self.first

    def abort_current_read(self) -> None:
        self.abort_count += 1

    def finish_response(self, reusable: bool) -> None:
        self.finishes.append(reusable)


class _BytesSubclass(bytes):
    pass


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "first",
    [
        SourceDataV8(_BytesSubclass(b"{}")),
        RuntimeError("synthetic-secret-source-error"),
        TimeoutError("synthetic-secret-timeout"),
        ConnectionResetError("synthetic-secret-connection-reset"),
        OSError("synthetic-secret-os-error"),
        asyncio.CancelledError(),
        b"not-a-source-variant",
    ],
)
async def test_invalid_source_shapes_and_exceptions_are_sanitized(first: object) -> None:
    source = _PoisonSource(first)
    loop = asyncio.get_running_loop()
    contexts: list[dict[str, object]] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: contexts.append(context))
    try:
        result = await read_bounded_authority_input_v8(
            source,
            transport_encoding=TransportEncodingV8.IDENTITY,
            operation_deadline=_deadline(),
        )
        await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(previous_handler)

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is NoResponseObservationV8
    assert result.termination is not None
    assert result.termination.phase is AuthorityInputPhaseV8.WIRE_READ
    assert result.termination.reason is AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION
    assert "synthetic-secret" not in repr(result)
    assert contexts == []
    assert source.read_count == 1
    assert source.finishes == [False]


class _SyncRaisingSource(_PoisonSource):
    def read(self, _max_bytes: int):
        self.read_count += 1
        raise RuntimeError("synthetic-secret-sync-source")


class _NonAwaitableSource(_PoisonSource):
    def read(self, _max_bytes: int):
        self.read_count += 1
        return SourceEofV8()


@pytest.mark.asyncio
@pytest.mark.parametrize("source_type", [_SyncRaisingSource, _NonAwaitableSource])
async def test_source_wrapper_normalizes_sync_raise_and_nonawaitable(source_type) -> None:
    source = source_type(SourceEofV8())
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=_deadline(),
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert result.termination is not None
    assert result.termination.reason is AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION
    assert source.read_count == 1
    assert source.finishes == [False]


@pytest.mark.asyncio
async def test_early_scanner_rejection_never_performs_a_poison_second_read() -> None:
    invalid_prefix = b'{"x":-0}'
    witness = b'{"x":-0'
    body = invalid_prefix + (b" " * (AUTHORITY_INPUT_READ_QUANTUM_V8 - len(invalid_prefix)))
    source = _PoisonSource(SourceDataV8(body))
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=_deadline(),
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is IncompleteBoundedResponseObservationV8
    assert result.observation.observed_wire_prefix_length == len(witness)
    assert result.observation.observed_wire_prefix_digest == (
        f"sha256:{hashlib.sha256(witness).hexdigest()}"
    )
    assert result.termination is not None
    assert result.termination.reason is AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER
    assert source.read_count == 1
    assert source.finishes == [False]


@pytest.mark.asyncio
async def test_short_root_rejection_never_waits_for_a_poison_second_read() -> None:
    source = _PoisonSource(SourceDataV8(b"@"))
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=_deadline(),
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is IncompleteBoundedResponseObservationV8
    assert result.observation.observed_wire_prefix_length == 1
    assert result.observation.observed_wire_prefix_digest == (
        f"sha256:{hashlib.sha256(b'@').hexdigest()}"
    )
    assert result.termination is not None
    assert result.termination.phase is AuthorityInputPhaseV8.JSON_SCAN
    assert result.termination.reason is AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT
    assert source.read_count == 1
    assert source.finishes == [False]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}x",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n02\r\n{}\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;x=y\r\n{}\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nX: y\r\n\r\n",
    ],
)
async def test_framing_failures_never_create_complete_or_reusable_evidence(raw: bytes) -> None:
    admitted = admit_http11_authority_input_v8(raw)
    result = await read_bounded_authority_input_v8(
        admitted.source,
        transport_encoding=admitted.transport_encoding,
        operation_deadline=_deadline(),
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is IncompleteBoundedResponseObservationV8 or (
        result.observation.kind == "NO_RESPONSE"
    )
    assert result.termination is not None
    assert result.termination.reason is AuthorityInputTerminationReasonV8.TRANSFER_FRAMING_FAILED
    assert admitted.source.reusable is False


def _response_with_headers(headers: list[bytes], *, reason: bytes = b"OK") -> bytes:
    return b"HTTP/1.1 200 " + reason + b"\r\n" + b"\r\n".join(headers) + b"\r\n\r\n"


def test_http11_literal_header_boundaries() -> None:
    status_reason = b"x" * (HTTP11_MAX_STATUS_LINE_BYTES_V8 - len(b"HTTP/1.1 200 ") - len(b"\r\n"))
    admitted = admit_http11_authority_input_v8(
        _response_with_headers([b"Content-Length: 0"], reason=status_reason)
    )
    assert admitted.transport_encoding is TransportEncodingV8.IDENTITY
    with pytest.raises(AgentKernelError) as status_error:
        admit_http11_authority_input_v8(
            _response_with_headers([b"Content-Length: 0"], reason=status_reason + b"x")
        )
    assert status_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    name_at_limit = b"x" * 256
    admit_http11_authority_input_v8(
        _response_with_headers([name_at_limit + b":", b"Content-Length: 0"])
    )
    with pytest.raises(AgentKernelError) as name_error:
        admit_http11_authority_input_v8(
            _response_with_headers([name_at_limit + b"x:", b"Content-Length: 0"])
        )
    assert name_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    value_at_limit = b"x" * 8_192
    admit_http11_authority_input_v8(
        _response_with_headers([b"X: " + value_at_limit, b"Content-Length: 0"])
    )
    with pytest.raises(AgentKernelError) as value_error:
        admit_http11_authority_input_v8(
            _response_with_headers([b"X: " + value_at_limit + b"x", b"Content-Length: 0"])
        )
    assert value_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    fields_at_limit = [f"X{index}:".encode() for index in range(255)]
    admit_http11_authority_input_v8(
        _response_with_headers([*fields_at_limit, b"Content-Length: 0"])
    )
    with pytest.raises(AgentKernelError) as field_error:
        admit_http11_authority_input_v8(
            _response_with_headers([*fields_at_limit, b"Y:", b"Content-Length: 0"])
        )
    assert field_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_http11_encoded_header_block_exact_and_next_byte() -> None:
    prefix = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX:"
    suffix = b"\r\n\r\n"
    ows = b" " * (HTTP11_MAX_HEADER_BLOCK_BYTES_V8 - len(prefix) - len(suffix))
    exact = prefix + ows + suffix
    assert exact.find(b"\r\n\r\n") + 4 == HTTP11_MAX_HEADER_BLOCK_BYTES_V8
    admit_http11_authority_input_v8(exact)

    with pytest.raises(AgentKernelError) as captured:
        admit_http11_authority_input_v8(prefix + ows + b" " + suffix)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_http11_decoded_header_aggregate_counter_exact_and_next_byte() -> None:
    exact = streaming._advance_http11_aggregate_header_bytes_v8(
        0,
        HTTP11_MAX_AGGREGATE_HEADER_BYTES_V8 // 2,
        HTTP11_MAX_AGGREGATE_HEADER_BYTES_V8 // 2,
    )
    assert exact == HTTP11_MAX_AGGREGATE_HEADER_BYTES_V8
    with pytest.raises(AgentKernelError) as captured:
        streaming._advance_http11_aggregate_header_bytes_v8(exact, 1, 0)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    with pytest.raises(TypeError, match="exact integers"):
        streaming._advance_http11_aggregate_header_bytes_v8(False, 1, 1)


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nContent-Length:0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nContent-Length:1\r\n\r\n",
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding:chunked\r\n"
            b"Transfer-Encoding:chunked\r\n\r\n0\r\n\r\n"
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nContent-Encoding:gzip\r\n"
            b"Content-Encoding:gzip\r\n\r\n"
        ),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding:gzip, chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding:chunked, gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding:chunked;level=1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nTransfer-Encoding:chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length:+1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length:-1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length:0,0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length:1 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length:00\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX:one\r\n two\r\nContent-Length:0\r\n\r\n",
        b"HTTP/1.1 200 OK\nContent-Length:0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length :0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX\x1f:value\r\nContent-Length:0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX:\x1f\r\nContent-Length:0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX:\x80\r\nContent-Length:0\r\n\r\n",
        b"HTTP/1.1 200 \x1f\r\nContent-Length:0\r\n\r\n",
        b"HTTP/1.1 200 \x80\r\nContent-Length:0\r\n\r\n",
        b"HTTP/1.1 200 OK\rContent-Length:0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nContent-Encoding:\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nContent-Encoding:gzip, identity\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nContent-Encoding:gzip;level=1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nContent-Encoding:br\r\n\r\n",
    ],
    ids=[
        "duplicate-identical-content-length",
        "conflicting-content-length",
        "duplicate-transfer-encoding",
        "duplicate-content-encoding",
        "listed-final-transfer-encoding",
        "listed-nonfinal-transfer-encoding",
        "parameterized-transfer-encoding",
        "content-length-plus-transfer-encoding",
        "signed-positive-content-length",
        "signed-negative-content-length",
        "comma-content-length",
        "internal-whitespace-content-length",
        "leading-zero-content-length",
        "obs-fold",
        "bare-lf",
        "whitespace-before-colon",
        "control-in-name",
        "control-in-value",
        "obs-text-in-value",
        "control-in-status-reason",
        "obs-text-in-status-reason",
        "bare-cr-after-status-reason",
        "empty-content-length",
        "empty-transfer-encoding",
        "empty-content-encoding",
        "listed-content-encoding",
        "parameterized-content-encoding",
        "unsupported-content-encoding",
    ],
)
def test_http11_raw_profile_rejects_ambiguous_or_noncanonical_headers(raw: bytes) -> None:
    with pytest.raises(AgentKernelError):
        admit_http11_authority_input_v8(raw)


@pytest.mark.parametrize("ows", [b"", b" ", b"\t", b" \t "])
def test_http11_supported_framing_and_encoding_strip_only_sp_htab_ows(ows: bytes) -> None:
    content_length = admit_http11_authority_input_v8(
        b"HTTP/1.1 200 OK\r\nContent-Length:" + ows + b"0" + ows + b"\r\n\r\n"
    )
    transfer_encoding_value = ows + b"chunked" + ows
    transfer_header = b"Transfer-Encoding:" + transfer_encoding_value
    transfer_response = _response_with_headers([transfer_header]) + b"0\r\n\r\n"
    transfer_encoding = admit_http11_authority_input_v8(transfer_response)
    content_encoding = admit_http11_authority_input_v8(
        b"HTTP/1.1 200 OK\r\nContent-Length:"
        + ows
        + b"0"
        + ows
        + b"\r\nContent-Encoding:"
        + ows
        + b"gzip"
        + ows
        + b"\r\n\r\n"
    )

    assert content_length.transport_encoding is TransportEncodingV8.IDENTITY
    assert transfer_encoding.transport_encoding is TransportEncodingV8.IDENTITY
    assert content_encoding.transport_encoding is TransportEncodingV8.GZIP


def test_http11_status_protocol_alpn_and_upgrade_profiles_are_closed() -> None:
    accepted = b"HTTP/1.1 200 \r\nContent-Length:0\r\n\r\n"
    admit_http11_authority_input_v8(accepted)
    admit_http11_authority_input_v8(accepted, alpn_protocol=None)
    admit_http11_authority_input_v8(accepted, alpn_protocol="http/1.1")

    rejected_profiles = (
        b"HTTP/1.0 200 OK\r\nContent-Length:0\r\n\r\n",
        b"HTTP/2 200 OK\r\nContent-Length:0\r\n\r\n",
        b"HTTP/3 200 OK\r\nContent-Length:0\r\n\r\n",
        b"HTTP/1.1 204 OK\r\nContent-Length:0\r\n\r\n",
        b"HTTP/1.1 200\r\nContent-Length:0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length:0\r\nUpgrade:websocket\r\n\r\n",
        b"\r\n".join(
            (
                b"HTTP/1.1 200 OK",
                b"Content-Length:0",
                b"Connection:keep-alive, Upgrade",
                b"",
                b"",
            )
        ),
        b"HTTP/1.1 200 OK\r\n\r\n",
    )
    for raw in rejected_profiles:
        with pytest.raises(AgentKernelError):
            admit_http11_authority_input_v8(raw)

    for alpn_protocol in ("h2", "h3", "HTTP/1.1"):
        with pytest.raises(AgentKernelError) as captured:
            admit_http11_authority_input_v8(
                accepted,
                alpn_protocol=alpn_protocol,
            )
        assert captured.value.code is ErrorCode.UNSUPPORTED_SEMANTICS


@pytest.mark.asyncio
async def test_http11_chunk_size_line_exact_and_next_byte() -> None:
    exact_digits = b"1" + (b"0" * 15)
    exact = admit_http11_authority_input_v8(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + exact_digits + b"\r\nx"
    )
    assert len(exact_digits + b"\r\n") == HTTP11_MAX_CHUNK_SIZE_LINE_BYTES_V8
    exact_outcome = await exact.source.read(1)
    assert type(exact_outcome) is SourceDataV8
    assert exact_outcome.data == b"x"

    excess = admit_http11_authority_input_v8(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + exact_digits + b"0\r\nx"
    )
    excess_outcome = await excess.source.read(1)
    assert type(excess_outcome) is SourceFramingFailureV8


@pytest.mark.asyncio
async def test_http11_nonzero_chunk_count_exact_and_next_chunk() -> None:
    header = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    chunk = b"1\r\nx\r\n"
    exact = admit_http11_authority_input_v8(
        header + (chunk * HTTP11_MAX_NONZERO_CHUNKS_V8) + b"0\r\n\r\n"
    )
    for _ in range(HTTP11_MAX_NONZERO_CHUNKS_V8):
        outcome = await exact.source.read(1)
        assert type(outcome) is SourceDataV8
        assert outcome.data == b"x"
    assert type(await exact.source.read(1)) is SourceEofV8

    excess = admit_http11_authority_input_v8(
        header + (chunk * (HTTP11_MAX_NONZERO_CHUNKS_V8 + 1)) + b"0\r\n\r\n"
    )
    for _ in range(HTTP11_MAX_NONZERO_CHUNKS_V8):
        assert type(await excess.source.read(1)) is SourceDataV8
    assert type(await excess.source.read(1)) is SourceFramingFailureV8


def test_http11_chunk_framing_counter_exact_and_next_byte() -> None:
    exact = streaming._advance_http11_chunk_framing_bytes_v8(
        0,
        HTTP11_MAX_CHUNK_FRAMING_BYTES_V8,
    )
    assert exact == HTTP11_MAX_CHUNK_FRAMING_BYTES_V8
    with pytest.raises(ValueError, match="exceeds"):
        streaming._advance_http11_chunk_framing_bytes_v8(exact, 1)
    with pytest.raises(TypeError, match="exact integers"):
        streaming._advance_http11_chunk_framing_bytes_v8(False, 1)
    with pytest.raises(TypeError, match="exact integers"):
        streaming._advance_http11_chunk_framing_bytes_v8(0, True)
    with pytest.raises(ValueError, match="nonnegative"):
        streaming._advance_http11_chunk_framing_bytes_v8(-1, 1)
    with pytest.raises(ValueError, match="nonnegative"):
        streaming._advance_http11_chunk_framing_bytes_v8(0, -1)


def test_http11_immutable_response_envelope_exact_and_next_byte() -> None:
    header = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    exact = header + (b"x" * (HTTP11_MAX_IMMUTABLE_RESPONSE_BYTES_V8 - len(header)))

    admitted = admit_http11_authority_input_v8(exact)
    assert admitted.transport_encoding is TransportEncodingV8.IDENTITY
    with pytest.raises(AgentKernelError) as captured:
        admit_http11_authority_input_v8(exact + b"x")
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


class _CheckpointClock:
    def __init__(self) -> None:
        self.value = datetime(2030, 1, 1, tzinfo=UTC)
        self.event = asyncio.Event()

    def now(self) -> datetime:
        return self.value

    async def wait_until(self, _deadline: datetime) -> None:
        await self.event.wait()


class _CheckpointToken:
    def __init__(self, cancel_on_sample: int) -> None:
        self.cancel_on_sample = cancel_on_sample
        self.samples = 0
        self.event = asyncio.Event()

    def is_cancelled(self) -> bool:
        self.samples += 1
        return self.samples >= self.cancel_on_sample

    async def wait_cancelled(self) -> None:
        await self.event.wait()


class _RaceClock:
    def __init__(self) -> None:
        self.value = datetime(2030, 1, 1, tzinfo=UTC)
        self.deadline = self.value + timedelta(days=1)
        self.event = asyncio.Event()

    def now(self) -> datetime:
        return self.value

    async def wait_until(self, _deadline: datetime) -> None:
        await self.event.wait()

    def expire(self) -> None:
        self.value = self.deadline
        self.event.set()


class _RaceToken:
    def __init__(self) -> None:
        self.event = asyncio.Event()

    def is_cancelled(self) -> bool:
        return self.event.is_set()

    async def wait_cancelled(self) -> None:
        await self.event.wait()

    def cancel(self) -> None:
        self.event.set()


class _PrefixThenHungSource:
    def __init__(self, prefix: bytes, *, late_kind: str) -> None:
        self.prefix = prefix
        self.late_kind = late_kind
        self.read_count = 0
        self.abort_count = 0
        self.finishes: list[bool] = []
        self.events: list[str] = []
        self.hung_started = asyncio.Event()
        self.release = asyncio.Event()

    async def read(self, _max_bytes: int):
        self.read_count += 1
        if self.prefix and self.read_count == 1:
            return SourceDataV8(self.prefix)
        if self.read_count > (2 if self.prefix else 1):
            raise AssertionError("poison read after closed hung generation")
        self.hung_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await self.release.wait()
            if self.late_kind == "data":
                return SourceDataV8(b"late-provider-data")
            if self.late_kind == "eof":
                return SourceEofV8()
            if self.late_kind == "exception":
                raise RuntimeError("synthetic-secret-late-source") from None
            raise

    def abort_current_read(self) -> None:
        self.abort_count += 1
        self.events.append("abort")
        self.release.set()

    def finish_response(self, reusable: bool) -> None:
        self.finishes.append(reusable)
        self.events.append(f"finish:{reusable}")


class _ExpiringSampleClock:
    def __init__(self, *, expire_on_sample: int | None) -> None:
        self.live = datetime(2030, 1, 1, tzinfo=UTC)
        self.deadline = self.live + timedelta(days=1)
        self.expire_on_sample = expire_on_sample
        self.samples = 0
        self.event = asyncio.Event()

    def now(self) -> datetime:
        self.samples += 1
        if self.expire_on_sample is not None and self.samples >= self.expire_on_sample:
            return self.deadline
        return self.live

    async def wait_until(self, _deadline: datetime) -> None:
        await self.event.wait()


class _CancelledErrorSampleClock(_ExpiringSampleClock):
    def __init__(self, *, fail_on_sample: int) -> None:
        super().__init__(expire_on_sample=None)
        self.fail_on_sample = fail_on_sample

    def now(self) -> datetime:
        self.samples += 1
        if self.samples >= self.fail_on_sample:
            raise asyncio.CancelledError
        return self.live


class _CancelledErrorSampleToken(_CheckpointToken):
    def __init__(self, *, fail_on_sample: int) -> None:
        super().__init__(cancel_on_sample=99)
        self.fail_on_sample = fail_on_sample

    def is_cancelled(self) -> bool:
        self.samples += 1
        if self.samples >= self.fail_on_sample:
            raise asyncio.CancelledError
        return False


class _SyntheticProcessControl(BaseException):
    pass


class _ProcessControlClock(_ExpiringSampleClock):
    def __init__(self, *, fail_on_sample: int, wake_immediately: bool) -> None:
        super().__init__(expire_on_sample=None)
        self.fail_on_sample = fail_on_sample
        self.wake_immediately = wake_immediately

    def now(self) -> datetime:
        self.samples += 1
        if self.samples >= self.fail_on_sample:
            raise _SyntheticProcessControl
        return self.live

    async def wait_until(self, _deadline: datetime) -> None:
        if self.wake_immediately:
            return
        await self.event.wait()


class _ProcessControlToken(_CheckpointToken):
    def __init__(self, *, fail_on_sample: int, wake_immediately: bool) -> None:
        super().__init__(cancel_on_sample=99)
        self.fail_on_sample = fail_on_sample
        self.wake_immediately = wake_immediately

    def is_cancelled(self) -> bool:
        self.samples += 1
        if self.samples >= self.fail_on_sample:
            raise _SyntheticProcessControl
        return False

    async def wait_cancelled(self) -> None:
        if self.wake_immediately:
            return
        await self.event.wait()


class _SequenceSource:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = outcomes
        self.read_count = 0
        self.abort_count = 0
        self.finishes: list[bool] = []

    async def read(self, _max_bytes: int):
        self.read_count += 1
        if not self.outcomes:
            raise AssertionError("poison read after source sequence")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def abort_current_read(self) -> None:
        self.abort_count += 1

    def finish_response(self, reusable: bool) -> None:
        self.finishes.append(reusable)


async def _assert_no_gate_tasks() -> None:
    for _ in range(4):
        await asyncio.sleep(0)
    current = asyncio.current_task()
    leaked = [
        task
        for task in asyncio.all_tasks()
        if task is not current
        and not task.done()
        and task.get_name().startswith("agentkernel-v8-authority-input-")
    ]
    assert leaked == []


@pytest.mark.asyncio
@pytest.mark.parametrize("control_side", ["clock", "token"])
@pytest.mark.parametrize("prefix", [b"", b"{}"])
async def test_sync_control_cancelled_error_is_normalized_without_escaping(
    control_side: str,
    prefix: bytes,
) -> None:
    fail_on_sample = 6 if prefix else 1
    clock = (
        _CancelledErrorSampleClock(fail_on_sample=fail_on_sample)
        if control_side == "clock"
        else _ExpiringSampleClock(expire_on_sample=None)
    )
    token = (
        _CancelledErrorSampleToken(fail_on_sample=fail_on_sample)
        if control_side == "token"
        else _CheckpointToken(99)
    )
    source = _PoisonSource(SourceDataV8(prefix or b"uncommitted"))
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=clock.deadline,
        clock=clock,
        cancellation_token=token,
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert result.termination is not None
    assert result.termination.reason is AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE
    if prefix:
        assert type(result.observation) is IncompleteBoundedResponseObservationV8
        assert result.observation.observed_wire_prefix_length == len(prefix)
        assert result.termination.phase is AuthorityInputPhaseV8.WIRE_READ
        assert source.read_count == 1
    else:
        assert type(result.observation) is NoResponseObservationV8
        assert result.termination.phase is AuthorityInputPhaseV8.WIRE_READ
        assert source.read_count == 0
    assert source.finishes == [False]


@pytest.mark.asyncio
async def test_source_process_control_propagates_after_retrieving_waiters() -> None:
    source = _PoisonSource(_SyntheticProcessControl())
    loop = asyncio.get_running_loop()
    contexts: list[dict[str, object]] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: contexts.append(context))
    try:
        with pytest.raises(_SyntheticProcessControl):
            await read_bounded_authority_input_v8(
                source,
                transport_encoding=TransportEncodingV8.IDENTITY,
                operation_deadline=_deadline(),
            )
        await _assert_no_gate_tasks()
    finally:
        loop.set_exception_handler(previous_handler)

    assert source.read_count == 1
    assert source.abort_count == 0
    assert source.finishes == [False]
    assert contexts == []


@pytest.mark.asyncio
@pytest.mark.parametrize("control_side", ["clock", "token"])
async def test_sample_process_control_propagates_after_closing_pending_generation(
    control_side: str,
) -> None:
    source = _PrefixThenHungSource(b"", late_kind="data")
    clock = _ProcessControlClock(
        fail_on_sample=2,
        wake_immediately=control_side == "clock",
    )
    token = _ProcessControlToken(
        fail_on_sample=2,
        wake_immediately=control_side == "token",
    )
    loop = asyncio.get_running_loop()
    contexts: list[dict[str, object]] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: contexts.append(context))
    try:
        with pytest.raises(_SyntheticProcessControl):
            await read_bounded_authority_input_v8(
                source,
                transport_encoding=TransportEncodingV8.IDENTITY,
                operation_deadline=clock.deadline,
                clock=clock,
                cancellation_token=token,
            )
        await _assert_no_gate_tasks()
    finally:
        loop.set_exception_handler(previous_handler)

    assert source.read_count == 1
    assert source.abort_count == 1
    assert source.events == ["abort", "finish:False"]
    assert contexts == []


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", ["deadline", "cancel"])
@pytest.mark.parametrize("prefix", [b"", b'{"accepted":'])
async def test_hung_read_preserves_exact_prior_prefix_and_aborts_once(
    signal: str,
    prefix: bytes,
) -> None:
    source = _PrefixThenHungSource(prefix, late_kind="data")
    clock = _RaceClock()
    token = _RaceToken()
    gate = asyncio.create_task(
        read_bounded_authority_input_v8(
            source,
            transport_encoding=TransportEncodingV8.IDENTITY,
            operation_deadline=clock.deadline,
            clock=clock,
            cancellation_token=token,
        )
    )
    await source.hung_started.wait()
    if signal == "deadline":
        clock.expire()
        expected_reason = AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED
    else:
        token.cancel()
        expected_reason = AuthorityInputTerminationReasonV8.CANCELLED
    result = await gate
    await _assert_no_gate_tasks()

    assert type(result) is BoundedAuthorityInputFailureV8
    assert result.termination is not None
    assert result.termination.phase is AuthorityInputPhaseV8.WIRE_READ
    assert result.termination.reason is expected_reason
    if prefix:
        assert type(result.observation) is IncompleteBoundedResponseObservationV8
        assert result.observation.observed_wire_prefix_length == len(prefix)
        assert result.observation.observed_wire_prefix_digest == (
            f"sha256:{hashlib.sha256(prefix).hexdigest()}"
        )
        assert result.observation.observed_decompressed_prefix_length == len(prefix)
    else:
        assert type(result.observation) is NoResponseObservationV8
    assert source.read_count == (2 if prefix else 1)
    assert source.abort_count == 1
    assert source.finishes == [False]
    assert source.events == ["abort", "finish:False"]


@pytest.mark.asyncio
@pytest.mark.parametrize("late_kind", ["eof", "exception"])
async def test_late_hung_read_terminal_is_sunk_without_changing_evidence(
    late_kind: str,
) -> None:
    source = _PrefixThenHungSource(b'{"stable":', late_kind=late_kind)
    clock = _RaceClock()
    token = _RaceToken()
    loop = asyncio.get_running_loop()
    contexts: list[dict[str, object]] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: contexts.append(context))
    try:
        gate = asyncio.create_task(
            read_bounded_authority_input_v8(
                source,
                transport_encoding=TransportEncodingV8.IDENTITY,
                operation_deadline=clock.deadline,
                clock=clock,
                cancellation_token=token,
            )
        )
        await source.hung_started.wait()
        token.cancel()
        result = await gate
        await _assert_no_gate_tasks()
    finally:
        loop.set_exception_handler(previous_handler)

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is IncompleteBoundedResponseObservationV8
    assert result.observation.observed_wire_prefix_length == len(source.prefix)
    assert result.observation.observed_wire_prefix_digest == (
        f"sha256:{hashlib.sha256(source.prefix).hexdigest()}"
    )
    assert "synthetic-secret" not in repr(result)
    assert contexts == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("expire_on_sample", "cancel_on_sample", "reason"),
    [
        (2, 99, AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED),
        (None, 2, AuthorityInputTerminationReasonV8.CANCELLED),
        (2, 2, AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED),
    ],
)
async def test_ready_source_loses_to_sampled_deadline_or_cancellation(
    expire_on_sample: int | None,
    cancel_on_sample: int,
    reason: AuthorityInputTerminationReasonV8,
) -> None:
    clock = _ExpiringSampleClock(expire_on_sample=expire_on_sample)
    token = _CheckpointToken(cancel_on_sample)
    source = _PoisonSource(SourceDataV8(b"uncommitted-ready-result"))
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=clock.deadline,
        clock=clock,
        cancellation_token=token,
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is NoResponseObservationV8
    assert result.termination is not None
    assert result.termination.phase is AuthorityInputPhaseV8.WIRE_READ
    assert result.termination.reason is reason
    assert source.read_count == 1
    assert source.abort_count == 0
    assert source.finishes == [False]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("terminal", "reason"),
    [
        (
            SourceDisconnectedV8(),
            AuthorityInputTerminationReasonV8.DISCONNECTED,
        ),
        (
            SourceFramingFailureV8(),
            AuthorityInputTerminationReasonV8.TRANSFER_FRAMING_FAILED,
        ),
    ],
)
async def test_nonempty_prefix_then_closed_source_terminal_stays_incomplete(
    terminal: object,
    reason: AuthorityInputTerminationReasonV8,
) -> None:
    source = _SequenceSource([SourceDataV8(b"{"), terminal])
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=_deadline(),
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is IncompleteBoundedResponseObservationV8
    assert result.observation.observed_wire_prefix_length == 1
    assert result.observation.observed_wire_prefix_digest == (
        f"sha256:{hashlib.sha256(b'{').hexdigest()}"
    )
    assert result.observation.observed_decompressed_prefix_length == 1
    assert result.termination is not None
    assert result.termination.phase is AuthorityInputPhaseV8.WIRE_READ
    assert result.termination.reason is reason
    assert source.read_count == 2
    assert source.finishes == [False]


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", ["deadline", "cancel"])
async def test_checkpoint_two_rejects_ready_empty_eof_without_committing_it(
    signal: str,
) -> None:
    clock = _ExpiringSampleClock(expire_on_sample=2 if signal == "deadline" else None)
    token = _CheckpointToken(2 if signal == "cancel" else 99)
    source = _PoisonSource(SourceEofV8())
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=clock.deadline,
        clock=clock,
        cancellation_token=token,
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is NoResponseObservationV8
    assert result.termination is not None
    assert result.termination.phase is AuthorityInputPhaseV8.WIRE_READ
    assert result.termination.reason is (
        AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED
        if signal == "deadline"
        else AuthorityInputTerminationReasonV8.CANCELLED
    )
    assert source.read_count == 1
    assert source.finishes == [False]


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", ["deadline", "cancel"])
async def test_zero_byte_gzip_truncation_wins_before_any_later_signal(
    signal: str,
) -> None:
    clock = _ExpiringSampleClock(expire_on_sample=3 if signal == "deadline" else None)
    token = _CheckpointToken(3 if signal == "cancel" else 99)
    source = _PoisonSource(SourceEofV8())
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.GZIP,
        operation_deadline=clock.deadline,
        clock=clock,
        cancellation_token=token,
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is NoResponseObservationV8
    assert result.observation.failure_phase is AuthorityInputPhaseV8.RESPONSE_FINALIZE
    assert result.termination is not None
    assert result.termination.phase is AuthorityInputPhaseV8.RESPONSE_FINALIZE
    termination_reason = result.termination.reason
    assert termination_reason is AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM
    assert source.read_count == 1
    assert source.finishes == [False]


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", ["deadline", "cancel"])
async def test_checkpoint_one_before_later_read_is_wire_read(signal: str) -> None:
    clock = _ExpiringSampleClock(expire_on_sample=6 if signal == "deadline" else None)
    token = _CheckpointToken(6 if signal == "cancel" else 99)
    source = _PoisonSource(SourceDataV8(b"{}"))
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=clock.deadline,
        clock=clock,
        cancellation_token=token,
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is IncompleteBoundedResponseObservationV8
    assert result.observation.observed_wire_prefix_length == 2
    assert result.observation.observed_wire_prefix_digest == (
        f"sha256:{hashlib.sha256(b'{}').hexdigest()}"
    )
    assert result.termination is not None
    assert result.termination.phase is AuthorityInputPhaseV8.WIRE_READ
    assert result.termination.reason is (
        AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED
        if signal == "deadline"
        else AuthorityInputTerminationReasonV8.CANCELLED
    )
    assert source.read_count == 1
    assert source.finishes == [False]


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", ["deadline", "cancel"])
@pytest.mark.parametrize(
    ("sample", "phase"),
    [
        (8, AuthorityInputPhaseV8.CONTENT_DECODE),
        (9, AuthorityInputPhaseV8.UTF8_DECODE),
        (10, AuthorityInputPhaseV8.JSON_SCAN),
        (11, AuthorityInputPhaseV8.JSON_SCAN),
    ],
)
async def test_eof_finalization_and_publication_signal_keep_complete_evidence(
    signal: str,
    sample: int,
    phase: AuthorityInputPhaseV8,
) -> None:
    clock = _ExpiringSampleClock(expire_on_sample=sample if signal == "deadline" else None)
    token = _CheckpointToken(sample if signal == "cancel" else 99)
    source = _SequenceSource([SourceDataV8(b"{}"), SourceEofV8()])
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=clock.deadline,
        clock=clock,
        cancellation_token=token,
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is CompleteBoundedResponseObservationV8
    assert result.observation.complete_wire_length == 2
    assert result.observation.complete_wire_digest == (
        f"sha256:{hashlib.sha256(b'{}').hexdigest()}"
    )
    assert result.termination is not None
    assert result.termination.phase is phase
    assert result.termination.reason is (
        AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED
        if signal == "deadline"
        else AuthorityInputTerminationReasonV8.CANCELLED
    )
    assert source.read_count == 2
    assert source.abort_count == 0
    assert source.finishes == [True]


async def _waiter_mode_coroutine(mode: str, hang_event: asyncio.Event) -> None:
    if mode == "normal":
        return
    if mode == "exception":
        raise RuntimeError("synthetic-secret-control-waiter")
    if mode == "cancelled":
        raise asyncio.CancelledError
    if mode == "hang":
        await hang_event.wait()
        return
    raise AssertionError(f"unknown waiter test mode: {mode}")


class _ModeClock:
    def __init__(self, mode: str, *, trigger_call: int = 1) -> None:
        self.value = datetime(2030, 1, 1, tzinfo=UTC)
        self.mode = mode
        self.trigger_call = trigger_call
        self.wait_calls = 0
        self.hang_event = asyncio.Event()

    def now(self) -> datetime:
        return self.value

    def wait_until(self, _deadline: datetime):
        self.wait_calls += 1
        mode = self.mode if self.wait_calls >= self.trigger_call else "hang"
        if mode == "sync_raise":
            raise RuntimeError("synthetic-secret-sync-clock")
        if mode == "nonawaitable":
            return None
        return _waiter_mode_coroutine(mode, self.hang_event)


class _ModeToken:
    def __init__(self, mode: str, *, trigger_call: int = 1) -> None:
        self.mode = mode
        self.trigger_call = trigger_call
        self.wait_calls = 0
        self.hang_event = asyncio.Event()

    def is_cancelled(self) -> bool:
        return False

    def wait_cancelled(self):
        self.wait_calls += 1
        mode = self.mode if self.wait_calls >= self.trigger_call else "hang"
        if mode == "sync_raise":
            raise RuntimeError("synthetic-secret-sync-token")
        if mode == "nonawaitable":
            return None
        return _waiter_mode_coroutine(mode, self.hang_event)


@pytest.mark.asyncio
@pytest.mark.parametrize("waiter_side", ["deadline", "cancel"])
@pytest.mark.parametrize(
    "mode",
    ["normal", "exception", "cancelled", "sync_raise", "nonawaitable"],
)
async def test_invalid_waiter_terminal_is_sanitized_once_without_rearm(
    waiter_side: str,
    mode: str,
) -> None:
    source = _PrefixThenHungSource(b"", late_kind="data")
    clock = _ModeClock(mode if waiter_side == "deadline" else "hang")
    token = _ModeToken(mode if waiter_side == "cancel" else "hang")
    loop = asyncio.get_running_loop()
    contexts: list[dict[str, object]] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: contexts.append(context))
    try:
        result = await read_bounded_authority_input_v8(
            source,
            transport_encoding=TransportEncodingV8.IDENTITY,
            operation_deadline=clock.value + timedelta(days=1),
            clock=clock,
            cancellation_token=token,
        )
        await _assert_no_gate_tasks()
    finally:
        loop.set_exception_handler(previous_handler)

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is NoResponseObservationV8
    assert result.termination is not None
    assert result.termination.phase is AuthorityInputPhaseV8.WIRE_READ
    assert result.termination.reason is AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE
    assert (clock.wait_calls if waiter_side == "deadline" else token.wait_calls) == 1
    assert source.read_count == 1
    assert source.abort_count == 1
    assert source.events == ["abort", "finish:False"]
    assert "synthetic-secret" not in repr(result)
    assert contexts == []


@pytest.mark.asyncio
@pytest.mark.parametrize("waiter_side", ["deadline", "cancel"])
async def test_spurious_waiter_on_second_generation_keeps_nonempty_prefix(
    waiter_side: str,
) -> None:
    prefix = b'{"accepted":'
    source = _PrefixThenHungSource(prefix, late_kind="eof")
    clock = _ModeClock(
        "normal" if waiter_side == "deadline" else "hang",
        trigger_call=2,
    )
    token = _ModeToken(
        "normal" if waiter_side == "cancel" else "hang",
        trigger_call=2,
    )
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=clock.value + timedelta(days=1),
        clock=clock,
        cancellation_token=token,
    )
    await _assert_no_gate_tasks()

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is IncompleteBoundedResponseObservationV8
    assert result.observation.observed_wire_prefix_length == len(prefix)
    assert result.observation.observed_wire_prefix_digest == (
        f"sha256:{hashlib.sha256(prefix).hexdigest()}"
    )
    assert result.termination is not None
    assert result.termination.reason is AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE
    assert (clock.wait_calls if waiter_side == "deadline" else token.wait_calls) == 2
    assert source.read_count == 2
    assert source.abort_count == 1
    assert source.events == ["abort", "finish:False"]


class _SlowCleanupClock:
    def __init__(self) -> None:
        self.value = datetime(2030, 1, 1, tzinfo=UTC)
        self.cleanup_started = asyncio.Event()
        self.allow_cleanup = asyncio.Event()

    def now(self) -> datetime:
        return self.value

    async def wait_until(self, _deadline: datetime) -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cleanup_started.set()
            await self.allow_cleanup.wait()
            raise


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ready_outcome",
    [
        SourceDataV8(b"ready-result"),
        RuntimeError("synthetic-secret-ready-source"),
    ],
)
async def test_external_gate_cancellation_during_post_race_cleanup_retrieves_source(
    ready_outcome: object,
) -> None:
    source = _PoisonSource(ready_outcome)
    clock = _SlowCleanupClock()
    token = _ModeToken("hang")
    loop = asyncio.get_running_loop()
    contexts: list[dict[str, object]] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: contexts.append(context))
    try:
        gate = asyncio.create_task(
            read_bounded_authority_input_v8(
                source,
                transport_encoding=TransportEncodingV8.IDENTITY,
                operation_deadline=clock.value + timedelta(days=1),
                clock=clock,
                cancellation_token=token,
            )
        )
        await clock.cleanup_started.wait()
        gate.cancel()
        await asyncio.sleep(0)
        assert not gate.done()
        clock.allow_cleanup.set()
        with pytest.raises(asyncio.CancelledError):
            await gate
        await _assert_no_gate_tasks()
    finally:
        loop.set_exception_handler(previous_handler)

    assert source.read_count == 1
    assert source.abort_count == 0
    assert source.finishes == [False]
    assert contexts == []


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", ["deadline", "cancel"])
@pytest.mark.parametrize(
    ("sample", "phase", "accepted_length", "expected_reads"),
    [
        (1, AuthorityInputPhaseV8.BEFORE_RESPONSE, 0, 0),
        (2, AuthorityInputPhaseV8.WIRE_READ, 0, 1),
        (3, AuthorityInputPhaseV8.CONTENT_DECODE, 1, 1),
        (4, AuthorityInputPhaseV8.UTF8_DECODE, 1, 1),
        (5, AuthorityInputPhaseV8.JSON_SCAN, 1, 1),
        (
            6,
            AuthorityInputPhaseV8.WIRE_READ,
            AUTHORITY_INPUT_READ_QUANTUM_V8,
            1,
        ),
    ],
)
async def test_full_quantum_checkpoint_matrix_commits_the_declared_prefix(
    signal: str,
    sample: int,
    phase: AuthorityInputPhaseV8,
    accepted_length: int,
    expected_reads: int,
) -> None:
    body = b"{}" + (b" " * (AUTHORITY_INPUT_READ_QUANTUM_V8 - 2))
    source = _PoisonSource(SourceDataV8(body))
    clock = _ExpiringSampleClock(expire_on_sample=sample if signal == "deadline" else None)
    token = _CheckpointToken(sample if signal == "cancel" else 99)
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.IDENTITY,
        operation_deadline=clock.deadline,
        clock=clock,
        cancellation_token=token,
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    if accepted_length:
        assert type(result.observation) is IncompleteBoundedResponseObservationV8
        assert result.observation.observed_wire_prefix_length == accepted_length
        assert result.observation.observed_wire_prefix_digest == (
            f"sha256:{hashlib.sha256(body[:accepted_length]).hexdigest()}"
        )
    else:
        assert type(result.observation) is NoResponseObservationV8
    assert result.termination is not None
    assert result.termination.phase is phase
    assert result.termination.reason is (
        AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED
        if signal == "deadline"
        else AuthorityInputTerminationReasonV8.CANCELLED
    )
    assert source.read_count == expected_reads
    assert source.finishes == [False]


@pytest.mark.asyncio
async def test_gzip_output_is_checkpointed_in_fixed_utf8_quanta() -> None:
    raw = b"{}" + (b" " * 140_000)
    wire = gzip.compress(raw, mtime=0)
    source = _PoisonSource(SourceDataV8(wire))
    clock = _CheckpointClock()
    token = _CheckpointToken(cancel_on_sample=6)
    result = await read_bounded_authority_input_v8(
        source,
        transport_encoding=TransportEncodingV8.GZIP,
        operation_deadline=clock.value + timedelta(days=1),
        clock=clock,
        cancellation_token=token,
    )

    assert type(result) is BoundedAuthorityInputFailureV8
    assert type(result.observation) is IncompleteBoundedResponseObservationV8
    assert result.observation.observed_decompressed_prefix_length == (
        AUTHORITY_INPUT_READ_QUANTUM_V8
    )
    assert result.termination is not None
    assert result.termination.phase is AuthorityInputPhaseV8.UTF8_DECODE
    assert result.termination.reason is AuthorityInputTerminationReasonV8.CANCELLED


def _node_limit_then_invalid_value() -> bytes:
    full_array = b"[" + (b"0," * 4_095) + b"0]"
    array_members = [f'"a{index}":'.encode() + full_array for index in range(63)]
    scalar_members = [f'"s{index}":0'.encode() for index in range(1_984)]
    return b"{" + b",".join([*array_members, *scalar_members, b'"invalid":@'])


@pytest.mark.asyncio
async def test_invalid_value_witness_does_not_increment_node_or_container_count() -> None:
    node_result, _source = await _read(_node_limit_then_invalid_value())
    container_result, _source = await _read(b'{"a":[' + (b"0," * 4_096) + b"@")

    assert type(node_result) is BoundedAuthorityInputFailureV8
    assert node_result.termination is not None
    assert node_result.termination.reason is AuthorityInputTerminationReasonV8.INVALID_JSON
    assert type(container_result) is BoundedAuthorityInputFailureV8
    assert container_result.termination is not None
    assert container_result.termination.reason is AuthorityInputTerminationReasonV8.INVALID_JSON


def test_streaming_boundary_has_no_tree_parser_or_forbidden_dependency() -> None:
    module_path = (
        Path(__file__).resolve().parents[2] / "agentkernel" / "authority" / "v8_streaming.py"
    )
    source = module_path.read_text(encoding="utf-8")

    assert "json.load" not in source
    assert "json.loads" not in source
    assert "pydantic" not in source
    for forbidden in (
        "agentkernel.storage",
        "agentkernel.coordinator",
        "agentkernel.adapters",
        "agentkernel.model_gateway",
    ):
        assert forbidden not in source


@pytest.mark.asyncio
async def test_successful_raw_gate_never_calls_tree_or_pydantic_materializers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def forbidden_materializer(*_args: object, **_kwargs: object) -> object:
        calls.append("materializer")
        raise AssertionError("raw streaming gate invoked a full model materializer")

    monkeypatch.setattr(json, "loads", forbidden_materializer)
    monkeypatch.setattr(
        BaseModel,
        "model_validate_json",
        classmethod(forbidden_materializer),
    )
    monkeypatch.setattr(TypeAdapter, "validate_json", forbidden_materializer)

    result, source = await _read(b'{"raw_gate_only":1}')

    assert type(result) is BoundedAuthorityInputSuccessV8
    assert result.document.raw_bytes == b'{"raw_gate_only":1}'
    assert source.reusable is True
    assert calls == []
