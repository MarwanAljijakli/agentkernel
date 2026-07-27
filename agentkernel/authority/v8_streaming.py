"""Bounded transport, UTF-8, and JSON gate for v8 authority-provider input.

This module is intentionally isolated from provider, storage, coordinator, and
materialization code.  It accepts only a kernel-owned, interruptible source and
publishes a raw JSON document after transport, UTF-8, and iterative syntax
preflight have all completed within the frozen v8 limits.
"""

from __future__ import annotations

import asyncio
import hashlib
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol, cast, runtime_checkable

from agentkernel.authority.v8_contracts import (
    AUTHORITY_INPUT_BYTE_LIMIT_V8,
    AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8,
    AuthorityInputObservationV8,
    AuthorityInputPhaseV8,
    AuthorityInputTerminationReasonV8,
    CompleteBoundedResponseObservationV8,
    IncompleteBoundedResponseObservationV8,
    NoResponseObservationV8,
    OverflowBoundaryV8,
    OverflowPrefixObservationV8,
    TransportEncodingV8,
)
from agentkernel.errors import AgentKernelError, ErrorCode

AUTHORITY_INPUT_READ_QUANTUM_V8: Final = 65_536
AUTHORITY_INPUT_MAX_DEPTH_V8: Final = 64
AUTHORITY_INPUT_MAX_NODES_V8: Final = 262_144
AUTHORITY_INPUT_MAX_CONTAINER_ITEMS_V8: Final = 4_096
AUTHORITY_INPUT_MAX_SCALAR_BYTES_V8: Final = 1_048_576
AUTHORITY_INPUT_MAX_AGGREGATE_SCALAR_BYTES_V8: Final = 4_194_304

HTTP11_MAX_HEADER_BLOCK_BYTES_V8: Final = 65_536
HTTP11_MAX_STATUS_LINE_BYTES_V8: Final = 256
HTTP11_MAX_HEADER_FIELDS_V8: Final = 256
HTTP11_MAX_HEADER_NAME_BYTES_V8: Final = 256
HTTP11_MAX_HEADER_VALUE_BYTES_V8: Final = 8_192
HTTP11_MAX_AGGREGATE_HEADER_BYTES_V8: Final = 65_536
HTTP11_MAX_CHUNK_SIZE_LINE_BYTES_V8: Final = 18
HTTP11_MAX_NONZERO_CHUNKS_V8: Final = 65_536
HTTP11_MAX_CHUNK_FRAMING_BYTES_V8: Final = 1_048_576
HTTP11_MAX_IMMUTABLE_RESPONSE_BYTES_V8: Final = (
    HTTP11_MAX_HEADER_BLOCK_BYTES_V8
    + HTTP11_MAX_CHUNK_FRAMING_BYTES_V8
    + AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
)

_EMPTY_SHA256: Final = f"sha256:{hashlib.sha256(b'').hexdigest()}"
_HTTP_TOKEN_BYTES: Final = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_JSON_WHITESPACE: Final = frozenset(" \t\r\n")
_HEX_CHARACTERS: Final = frozenset("0123456789abcdefABCDEF")
_TERMINATION_PHASE_REASON_MATRIX: Final = {
    AuthorityInputPhaseV8.BEFORE_RESPONSE: frozenset(
        {
            AuthorityInputTerminationReasonV8.DISCONNECTED,
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
        }
    ),
    AuthorityInputPhaseV8.WIRE_READ: frozenset(
        {
            AuthorityInputTerminationReasonV8.DISCONNECTED,
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION,
            AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE,
            AuthorityInputTerminationReasonV8.TRANSFER_FRAMING_FAILED,
        }
    ),
    AuthorityInputPhaseV8.CONTENT_DECODE: frozenset(
        {
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.DECOMPRESSION_FAILED,
        }
    ),
    AuthorityInputPhaseV8.UTF8_DECODE: frozenset(
        {
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.INVALID_UTF8,
        }
    ),
    AuthorityInputPhaseV8.JSON_SCAN: frozenset(
        {
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
        }
    ),
    AuthorityInputPhaseV8.RESPONSE_FINALIZE: frozenset(
        {
            AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM,
            AuthorityInputTerminationReasonV8.TRAILING_COMPRESSED_DATA,
        }
    ),
}
_COMPLETE_FAILURE_PHASE_REASON_MATRIX: Final = {
    AuthorityInputPhaseV8.WIRE_READ: frozenset(
        {AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE}
    ),
    AuthorityInputPhaseV8.CONTENT_DECODE: frozenset(
        {
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
        }
    ),
    AuthorityInputPhaseV8.UTF8_DECODE: frozenset(
        {
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.INVALID_UTF8,
        }
    ),
    AuthorityInputPhaseV8.JSON_SCAN: frozenset(
        {
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.INVALID_JSON,
            AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT,
            AuthorityInputTerminationReasonV8.LONE_SURROGATE,
            AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER,
        }
    ),
}
_VALIDATION_TERMINATION_REASONS: Final = frozenset(
    {
        AuthorityInputTerminationReasonV8.INVALID_UTF8,
        AuthorityInputTerminationReasonV8.INVALID_JSON,
        AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT,
        AuthorityInputTerminationReasonV8.DUPLICATE_OBJECT_KEY,
        AuthorityInputTerminationReasonV8.LONE_SURROGATE,
        AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER,
    }
)
_RESOURCE_TERMINATION_REASONS: Final = frozenset(
    {
        AuthorityInputTerminationReasonV8.DEPTH_LIMIT_EXCEEDED,
        AuthorityInputTerminationReasonV8.NODE_LIMIT_EXCEEDED,
        AuthorityInputTerminationReasonV8.CONTAINER_LIMIT_EXCEEDED,
        AuthorityInputTerminationReasonV8.SCALAR_LIMIT_EXCEEDED,
        AuthorityInputTerminationReasonV8.AGGREGATE_SCALAR_LIMIT_EXCEEDED,
    }
)
_OUTPUT_TERMINATION_REASONS: Final = _VALIDATION_TERMINATION_REASONS | _RESOURCE_TERMINATION_REASONS


def _is_ascii_digit(character: str) -> bool:
    return "0" <= character <= "9"


def _is_exact_utc_datetime(value: object) -> bool:
    if type(value) is not datetime:
        return False
    try:
        return value.utcoffset() == timedelta(0)
    except (Exception, asyncio.CancelledError):
        return False


@dataclass(frozen=True, slots=True)
class SourceDataV8:
    """One source outcome carrying transfer-decoded response-body bytes.

    Runtime validation deliberately remains in the gate so a malformed trusted
    dependency is normalized to a stable protocol failure instead of escaping.
    """

    data: bytes


@dataclass(frozen=True, slots=True)
class SourceEofV8:
    """The transport source proved its declared transfer framing ended cleanly."""


@dataclass(frozen=True, slots=True)
class SourceDisconnectedV8:
    """The source disconnected before it could prove framed completion."""


@dataclass(frozen=True, slots=True)
class SourceFramingFailureV8:
    """The source found a bounded transfer-framing violation."""


type AuthorityInputSourceOutcomeV8 = (
    SourceDataV8 | SourceEofV8 | SourceDisconnectedV8 | SourceFramingFailureV8
)


@runtime_checkable
class AuthorityInputSourceV8(Protocol):
    """Kernel-owned interruptible source presented to the bounded parser."""

    async def read(self, max_bytes: int) -> AuthorityInputSourceOutcomeV8: ...

    def abort_current_read(self) -> None: ...

    def finish_response(self, reusable: bool) -> None: ...


@runtime_checkable
class AuthorityInputClockV8(Protocol):
    """Trusted nondecreasing UTC clock and level-triggered deadline waiter."""

    def now(self) -> datetime: ...

    async def wait_until(self, deadline: datetime) -> None: ...


@runtime_checkable
class AuthorityInputCancellationTokenV8(Protocol):
    """Trusted ordered monotonic cancellation signal."""

    def is_cancelled(self) -> bool: ...

    async def wait_cancelled(self) -> None: ...


# Compatibility aliases for the initially proposed API vocabulary.
TrustedClockV8 = AuthorityInputClockV8
CancellationTokenV8 = AuthorityInputCancellationTokenV8


@dataclass(frozen=True, slots=True)
class AuthorityInputTerminationV8:
    """One stable, provider-data-free streaming termination."""

    phase: AuthorityInputPhaseV8
    reason: AuthorityInputTerminationReasonV8

    def __post_init__(self) -> None:
        if type(self.phase) is not AuthorityInputPhaseV8:
            raise TypeError("phase must be an exact AuthorityInputPhaseV8")
        if type(self.reason) is not AuthorityInputTerminationReasonV8:
            raise TypeError("reason must be an exact AuthorityInputTerminationReasonV8")
        if self.reason not in _TERMINATION_PHASE_REASON_MATRIX[self.phase]:
            raise ValueError("termination uses an unsupported phase/reason pairing")

    @property
    def error_code(self) -> ErrorCode:
        if self.reason is AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED:
            return ErrorCode.DEADLINE_EXCEEDED
        if self.reason in _VALIDATION_TERMINATION_REASONS:
            return ErrorCode.VALIDATION_ERROR
        if self.reason in _RESOURCE_TERMINATION_REASONS:
            return ErrorCode.RESOURCE_LIMIT_EXCEEDED
        return ErrorCode.EVIDENCE_UNAVAILABLE


@dataclass(frozen=True, slots=True)
class BoundedJsonDocumentV8:
    """Bounded raw JSON plus noncanonical scanner metadata for later preflight."""

    raw_bytes: bytes
    syntax_node_count: int
    maximum_depth: int
    maximum_object_members: int
    maximum_array_elements: int
    maximum_decoded_string_bytes: int
    aggregate_decoded_scalar_bytes: int
    maximum_number_token_bytes: int

    def __post_init__(self) -> None:
        if type(self.raw_bytes) is not bytes:
            raise TypeError("raw_bytes must be exact built-in bytes")
        if len(self.raw_bytes) > AUTHORITY_INPUT_BYTE_LIMIT_V8:
            raise ValueError("raw_bytes exceeds the v8 decompressed-byte limit")
        integer_fields = (
            self.syntax_node_count,
            self.maximum_depth,
            self.maximum_object_members,
            self.maximum_array_elements,
            self.maximum_decoded_string_bytes,
            self.aggregate_decoded_scalar_bytes,
            self.maximum_number_token_bytes,
        )
        if any(type(value) is not int or value < 0 for value in integer_fields):
            raise TypeError("scanner metadata must contain exact nonnegative integers")
        if self.syntax_node_count > AUTHORITY_INPUT_MAX_NODES_V8:
            raise ValueError("syntax_node_count exceeds the v8 scanner limit")
        if self.maximum_depth > AUTHORITY_INPUT_MAX_DEPTH_V8:
            raise ValueError("maximum_depth exceeds the v8 scanner limit")
        if (
            self.maximum_object_members > AUTHORITY_INPUT_MAX_CONTAINER_ITEMS_V8
            or self.maximum_array_elements > AUTHORITY_INPUT_MAX_CONTAINER_ITEMS_V8
        ):
            raise ValueError("container metadata exceeds the v8 scanner limit")
        if self.maximum_decoded_string_bytes > AUTHORITY_INPUT_MAX_SCALAR_BYTES_V8:
            raise ValueError("decoded string metadata exceeds the v8 scanner limit")
        if self.aggregate_decoded_scalar_bytes > AUTHORITY_INPUT_MAX_AGGREGATE_SCALAR_BYTES_V8:
            raise ValueError("aggregate scalar metadata exceeds the v8 scanner limit")
        if self.maximum_number_token_bytes > self.aggregate_decoded_scalar_bytes:
            raise ValueError("number-token metadata exceeds the aggregate scalar count")


@dataclass(frozen=True, slots=True)
class BoundedAuthorityInputSuccessV8:
    """A complete bounded transport whose raw document passed the G1a gate."""

    observation: CompleteBoundedResponseObservationV8
    document: BoundedJsonDocumentV8

    def __post_init__(self) -> None:
        if type(self.observation) is not CompleteBoundedResponseObservationV8:
            raise TypeError("success requires an exact complete response observation")
        if type(self.document) is not BoundedJsonDocumentV8:
            raise TypeError("success requires an exact bounded JSON document")
        if (
            self.observation.complete_decompressed_length != len(self.document.raw_bytes)
            or self.observation.complete_decompressed_digest
            != f"sha256:{hashlib.sha256(self.document.raw_bytes).hexdigest()}"
        ):
            raise ValueError("success document does not match its complete observation")


@dataclass(frozen=True, slots=True)
class BoundedAuthorityInputFailureV8:
    """A terminal failure with its strongest canonical transport observation."""

    observation: AuthorityInputObservationV8
    transport_encoding: TransportEncodingV8
    termination: AuthorityInputTerminationV8 | None

    def __post_init__(self) -> None:
        if type(self.transport_encoding) is not TransportEncodingV8:
            raise TypeError("failure requires an exact transport encoding")
        observation_type = type(self.observation)
        if observation_type is OverflowPrefixObservationV8:
            if self.termination is not None:
                raise ValueError("byte overflow has no streaming termination identifier")
            overflow = cast("OverflowPrefixObservationV8", self.observation)
            if overflow.transport_encoding is not self.transport_encoding:
                raise ValueError("overflow encoding does not match its gate result")
            return
        if type(self.termination) is not AuthorityInputTerminationV8:
            raise TypeError("non-overflow failure requires an exact termination")
        termination = self.termination
        if observation_type is NoResponseObservationV8:
            no_response = cast("NoResponseObservationV8", self.observation)
            if no_response.failure_phase is not termination.phase:
                raise ValueError("no-response phase does not match its termination")
            NoResponseObservationV8.from_termination(
                failure_phase=termination.phase,
                termination_reason=termination.reason,
                transport_encoding=self.transport_encoding,
                observed_wire_prefix_length=0,
                observed_decompressed_prefix_length=0,
            )
            return
        if observation_type is IncompleteBoundedResponseObservationV8:
            incomplete = cast("IncompleteBoundedResponseObservationV8", self.observation)
            if (
                incomplete.termination_phase is not termination.phase
                or incomplete.termination_reason is not termination.reason
                or incomplete.transport_encoding is not self.transport_encoding
            ):
                raise ValueError("incomplete observation does not match its termination")
            return
        if observation_type is not CompleteBoundedResponseObservationV8:
            raise TypeError("failure contains an unsupported observation variant")
        complete = cast("CompleteBoundedResponseObservationV8", self.observation)
        if complete.transport_encoding is not self.transport_encoding:
            raise ValueError("complete observation encoding does not match its gate result")
        allowed_complete_reasons = _COMPLETE_FAILURE_PHASE_REASON_MATRIX.get(
            termination.phase,
            frozenset(),
        )
        if termination.reason not in allowed_complete_reasons:
            raise ValueError("complete observation uses an unsupported streaming termination")

    @property
    def error_code(self) -> ErrorCode:
        if self.termination is None:
            return ErrorCode.RESOURCE_LIMIT_EXCEEDED
        return self.termination.error_code


type BoundedAuthorityInputResultV8 = BoundedAuthorityInputSuccessV8 | BoundedAuthorityInputFailureV8
type AuthorityInputGateResultV8 = BoundedAuthorityInputResultV8


@dataclass(frozen=True, slots=True)
class AdmittedHttp11AuthorityInputV8:
    """One bounded HTTP/1.1 response admitted to the parser-facing source."""

    source: AuthorityInputSourceV8
    transport_encoding: TransportEncodingV8


@dataclass(slots=True)
class InProcessAuthorityInputSourceV8:
    """Exact immutable in-process body with explicit, cursor-proven EOF."""

    body: bytes
    return_size: int = AUTHORITY_INPUT_READ_QUANTUM_V8
    _cursor: int = field(init=False, default=0)
    _finished: bool = field(init=False, default=False)
    _finish_count: int = field(init=False, default=0)
    _abort_count: int = field(init=False, default=0)
    _reusable: bool | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        if type(self.body) is not bytes:
            raise TypeError("body must be exact built-in bytes")
        if type(self.return_size) is not int or self.return_size < 1:
            raise ValueError("return_size must be an exact positive integer")

    async def read(self, max_bytes: int) -> AuthorityInputSourceOutcomeV8:
        if self._finished or type(max_bytes) is not int or max_bytes < 1:
            return SourceFramingFailureV8()
        if self._cursor == len(self.body):
            return SourceEofV8()
        take = min(max_bytes, self.return_size, len(self.body) - self._cursor)
        start = self._cursor
        self._cursor += take
        return SourceDataV8(self.body[start : self._cursor])

    def abort_current_read(self) -> None:
        if self._finished or self._abort_count:
            return
        self._abort_count = 1

    def finish_response(self, reusable: bool) -> None:
        if self._finished:
            return
        self._finish_count = 1
        self._finished = True
        self._reusable = reusable

    @property
    def finish_count(self) -> int:
        return self._finish_count

    @property
    def abort_count(self) -> int:
        return self._abort_count

    @property
    def reusable(self) -> bool | None:
        return self._reusable


def _advance_http11_chunk_framing_bytes_v8(
    current: int,
    count: int,
) -> int:
    if type(current) is not int or type(count) is not int:
        raise TypeError("HTTP/1.1 chunk framing counters require exact integers")
    if not 0 <= current <= HTTP11_MAX_CHUNK_FRAMING_BYTES_V8 or count < 0:
        raise ValueError("HTTP/1.1 chunk framing counters require bounded nonnegative values")
    candidate = current + count
    if candidate > HTTP11_MAX_CHUNK_FRAMING_BYTES_V8:
        raise ValueError("HTTP/1.1 chunk framing exceeds the v8 aggregate limit")
    return candidate


class Http11AuthorityInputSourceV8:
    """Bounded parser-facing source for one admitted immutable HTTP/1.1 response."""

    __slots__ = (
        "_abort_count",
        "_body_cursor",
        "_chunk_count",
        "_chunk_framing_bytes",
        "_chunk_remaining",
        "_chunked",
        "_content_length",
        "_delivered",
        "_failed",
        "_finish_count",
        "_finished",
        "_need_chunk_data_crlf",
        "_raw_response",
        "_reusable",
        "_terminal_chunk_seen",
    )

    def __init__(
        self,
        raw_response: bytes,
        *,
        body_offset: int,
        content_length: int | None,
        chunked: bool,
    ) -> None:
        self._raw_response = raw_response
        self._body_cursor = body_offset
        self._content_length = content_length
        self._chunked = chunked
        self._delivered = 0
        self._chunk_remaining = 0
        self._need_chunk_data_crlf = False
        self._terminal_chunk_seen = False
        self._chunk_count = 0
        self._chunk_framing_bytes = 0
        self._failed = False
        self._finished = False
        self._finish_count = 0
        self._abort_count = 0
        self._reusable: bool | None = None

    async def read(self, max_bytes: int) -> AuthorityInputSourceOutcomeV8:
        if (
            self._finished
            or self._failed
            or type(max_bytes) is not int
            or not 1 <= max_bytes <= AUTHORITY_INPUT_READ_QUANTUM_V8
        ):
            return SourceFramingFailureV8()
        if self._chunked:
            return self._read_chunked(max_bytes)
        return self._read_content_length(max_bytes)

    def abort_current_read(self) -> None:
        if self._finished or self._abort_count:
            return
        self._abort_count = 1

    def finish_response(self, reusable: bool) -> None:
        if self._finished:
            return
        self._finish_count = 1
        self._finished = True
        self._reusable = reusable

    @property
    def finish_count(self) -> int:
        return self._finish_count

    @property
    def abort_count(self) -> int:
        return self._abort_count

    @property
    def reusable(self) -> bool | None:
        return self._reusable

    def _read_content_length(self, max_bytes: int) -> AuthorityInputSourceOutcomeV8:
        content_length = self._content_length
        if content_length is None:
            return self._framing_failure()
        if self._delivered == content_length:
            if self._body_cursor != len(self._raw_response):
                return self._framing_failure()
            return SourceEofV8()
        available = len(self._raw_response) - self._body_cursor
        if available <= 0:
            return self._framing_failure()
        take = min(max_bytes, content_length - self._delivered, available)
        start = self._body_cursor
        self._body_cursor += take
        self._delivered += take
        return SourceDataV8(self._raw_response[start : self._body_cursor])

    def _read_chunked(self, max_bytes: int) -> AuthorityInputSourceOutcomeV8:
        while True:
            if self._need_chunk_data_crlf:
                if not self._consume_exact_crlf():
                    return self._framing_failure()
                self._need_chunk_data_crlf = False

            if self._chunk_remaining:
                available = len(self._raw_response) - self._body_cursor
                if available <= 0:
                    return self._framing_failure()
                take = min(max_bytes, self._chunk_remaining, available)
                start = self._body_cursor
                self._body_cursor += take
                self._chunk_remaining -= take
                if self._chunk_remaining == 0:
                    self._need_chunk_data_crlf = True
                return SourceDataV8(self._raw_response[start : self._body_cursor])

            if self._terminal_chunk_seen:
                if self._body_cursor != len(self._raw_response):
                    return self._framing_failure()
                return SourceEofV8()

            size = self._consume_chunk_size_line()
            if size is None:
                return self._framing_failure()
            if size == 0:
                if not self._consume_exact_crlf():
                    return self._framing_failure()
                self._terminal_chunk_seen = True
                continue
            self._chunk_count += 1
            if self._chunk_count > HTTP11_MAX_NONZERO_CHUNKS_V8:
                return self._framing_failure()
            self._chunk_remaining = size

    def _consume_chunk_size_line(self) -> int | None:
        start = self._body_cursor
        line_end = -1
        maximum_end = min(
            len(self._raw_response),
            start + HTTP11_MAX_CHUNK_SIZE_LINE_BYTES_V8,
        )
        cursor = start
        while cursor < maximum_end:
            byte = self._raw_response[cursor]
            if byte == 0x0A:
                return None
            if byte == 0x0D:
                if cursor + 1 >= len(self._raw_response):
                    return None
                if self._raw_response[cursor + 1] != 0x0A:
                    return None
                line_end = cursor
                break
            cursor += 1
        if line_end < 0:
            return None
        line_bytes = line_end + 2 - start
        digit_count = line_end - start
        if line_bytes > HTTP11_MAX_CHUNK_SIZE_LINE_BYTES_V8 or not 1 <= digit_count <= 16:
            return None
        if digit_count > 1 and self._raw_response[start] == ord("0"):
            return None
        for index in range(start, line_end):
            if chr(self._raw_response[index]) not in _HEX_CHARACTERS:
                return None
        if not self._advance_chunk_framing(line_bytes):
            return None
        self._body_cursor = line_end + 2
        return int(self._raw_response[start:line_end], 16)

    def _consume_exact_crlf(self) -> bool:
        if (
            self._body_cursor + 2 > len(self._raw_response)
            or self._raw_response[self._body_cursor : self._body_cursor + 2] != b"\r\n"
            or not self._advance_chunk_framing(2)
        ):
            return False
        self._body_cursor += 2
        return True

    def _advance_chunk_framing(self, count: int) -> bool:
        try:
            candidate = _advance_http11_chunk_framing_bytes_v8(
                self._chunk_framing_bytes,
                count,
            )
        except ValueError:
            return False
        self._chunk_framing_bytes = candidate
        return True

    def _framing_failure(self) -> SourceFramingFailureV8:
        self._failed = True
        return SourceFramingFailureV8()


def _raise_http11_admission_error_v8(
    code: ErrorCode,
    diagnostic: str,
) -> None:
    raise AgentKernelError(code, diagnostic)


def _advance_http11_aggregate_header_bytes_v8(
    current: int,
    name_length: int,
    value_length: int,
) -> int:
    exact_integer_counters = (
        type(current) is int and type(name_length) is int and type(value_length) is int
    )
    if not exact_integer_counters:
        raise TypeError("HTTP/1.1 header counters require exact integers")
    if (
        not 0 <= current <= HTTP11_MAX_AGGREGATE_HEADER_BYTES_V8
        or name_length < 0
        or value_length < 0
    ):
        raise ValueError("HTTP/1.1 header counters require bounded nonnegative values")
    candidate = current + name_length + value_length
    if candidate > HTTP11_MAX_AGGREGATE_HEADER_BYTES_V8:
        _raise_http11_admission_error_v8(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "HTTP/1.1 decoded headers exceed the v8 aggregate limit",
        )
    return candidate


def admit_http11_authority_input_v8(
    raw_response: bytes,
    *,
    alpn_protocol: str | None = None,
) -> AdmittedHttp11AuthorityInputV8:
    """Validate the closed HTTP/1.1 profile before admitting a body source."""

    if type(raw_response) is not bytes:
        _raise_http11_admission_error_v8(
            ErrorCode.VALIDATION_ERROR,
            "HTTP/1.1 authority response must be exact built-in bytes",
        )
    if len(raw_response) > HTTP11_MAX_IMMUTABLE_RESPONSE_BYTES_V8:
        _raise_http11_admission_error_v8(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "Immutable HTTP/1.1 response exceeds the v8 parser envelope",
        )
    if alpn_protocol is not None and (
        type(alpn_protocol) is not str or alpn_protocol != "http/1.1"
    ):
        _raise_http11_admission_error_v8(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "Unsupported authority response protocol",
        )

    header_marker = raw_response.find(
        b"\r\n\r\n",
        0,
        min(len(raw_response), HTTP11_MAX_HEADER_BLOCK_BYTES_V8),
    )
    if header_marker < 0:
        code = (
            ErrorCode.RESOURCE_LIMIT_EXCEEDED
            if len(raw_response) >= HTTP11_MAX_HEADER_BLOCK_BYTES_V8
            else ErrorCode.EVIDENCE_UNAVAILABLE
        )
        _raise_http11_admission_error_v8(code, "Invalid bounded HTTP/1.1 response headers")
    body_offset = header_marker + 4
    if body_offset > HTTP11_MAX_HEADER_BLOCK_BYTES_V8:
        _raise_http11_admission_error_v8(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "HTTP/1.1 response header block exceeds the v8 limit",
        )

    status_end = raw_response.find(b"\r\n", 0, header_marker + 2)
    if status_end < 0:
        _raise_http11_admission_error_v8(
            ErrorCode.EVIDENCE_UNAVAILABLE,
            "Invalid bounded HTTP/1.1 status line",
        )
    if status_end + 2 > HTTP11_MAX_STATUS_LINE_BYTES_V8:
        _raise_http11_admission_error_v8(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "HTTP/1.1 status line exceeds the v8 limit",
        )
    status_line = raw_response[:status_end]
    status_prefix = b"HTTP/1.1 "
    status_remainder = (
        status_line[len(status_prefix) :] if status_line.startswith(status_prefix) else b""
    )
    if (
        len(status_remainder) < 4
        or not all(ord("0") <= byte <= ord("9") for byte in status_remainder[:3])
        or status_remainder[3] != ord(" ")
        or any(byte != 0x09 and not 0x20 <= byte <= 0x7E for byte in status_remainder[4:])
    ):
        _raise_http11_admission_error_v8(
            ErrorCode.EVIDENCE_UNAVAILABLE,
            "Invalid bounded HTTP/1.1 status line",
        )
    if status_remainder[:3] != b"200":
        _raise_http11_admission_error_v8(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "HTTP/1.1 authority response status does not admit a body",
        )

    content_length_value: bytes | None = None
    transfer_encoding_value: bytes | None = None
    content_encoding_value: bytes | None = None
    upgrade_requested = False
    field_count = 0
    aggregate_header_bytes = 0
    cursor = status_end + 2
    while cursor < header_marker:
        line_end = raw_response.find(b"\r\n", cursor, header_marker + 2)
        if line_end < 0:
            _raise_http11_admission_error_v8(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Invalid bounded HTTP/1.1 header field",
            )
        field_count += 1
        if field_count > HTTP11_MAX_HEADER_FIELDS_V8:
            _raise_http11_admission_error_v8(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "HTTP/1.1 response has too many header fields",
            )
        colon = raw_response.find(b":", cursor, line_end)
        if colon <= cursor:
            _raise_http11_admission_error_v8(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Invalid bounded HTTP/1.1 header field",
            )
        name_length = colon - cursor
        if name_length > HTTP11_MAX_HEADER_NAME_BYTES_V8:
            _raise_http11_admission_error_v8(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "HTTP/1.1 header name exceeds the v8 limit",
            )
        if any(raw_response[index] not in _HTTP_TOKEN_BYTES for index in range(cursor, colon)):
            _raise_http11_admission_error_v8(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Invalid bounded HTTP/1.1 header name",
            )

        value_start = colon + 1
        for index in range(value_start, line_end):
            byte = raw_response[index]
            if byte != 0x09 and not 0x20 <= byte <= 0x7E:
                _raise_http11_admission_error_v8(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "Invalid bounded HTTP/1.1 header value",
                )
        while value_start < line_end and raw_response[value_start] in {0x09, 0x20}:
            value_start += 1
        value_end = line_end
        while value_end > value_start and raw_response[value_end - 1] in {0x09, 0x20}:
            value_end -= 1
        value_length = value_end - value_start
        if value_length > HTTP11_MAX_HEADER_VALUE_BYTES_V8:
            _raise_http11_admission_error_v8(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "HTTP/1.1 header value exceeds the v8 limit",
            )
        aggregate_header_bytes = _advance_http11_aggregate_header_bytes_v8(
            aggregate_header_bytes,
            name_length,
            value_length,
        )

        name = raw_response[cursor:colon].lower()
        value = raw_response[value_start:value_end]
        if name == b"content-length":
            if content_length_value is not None:
                _raise_http11_admission_error_v8(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "Duplicate HTTP/1.1 Content-Length is unsupported",
                )
            content_length_value = value
        elif name == b"transfer-encoding":
            if transfer_encoding_value is not None:
                _raise_http11_admission_error_v8(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "Duplicate HTTP/1.1 Transfer-Encoding is unsupported",
                )
            transfer_encoding_value = value
        elif name == b"content-encoding":
            if content_encoding_value is not None:
                _raise_http11_admission_error_v8(
                    ErrorCode.UNSUPPORTED_SEMANTICS,
                    "Duplicate HTTP/1.1 Content-Encoding is unsupported",
                )
            content_encoding_value = value
        elif name == b"upgrade" or (
            name == b"connection"
            and any(token.strip(b" \t").lower() == b"upgrade" for token in value.split(b","))
        ):
            upgrade_requested = True
        cursor = line_end + 2

    if upgrade_requested:
        _raise_http11_admission_error_v8(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "HTTP/1.1 authority response upgrade is unsupported",
        )

    if (content_length_value is None) == (transfer_encoding_value is None):
        _raise_http11_admission_error_v8(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "HTTP/1.1 authority response requires exactly one supported framing",
        )

    content_length: int | None = None
    chunked = transfer_encoding_value is not None
    if content_length_value is not None:
        if (
            not content_length_value
            or (len(content_length_value) > 1 and content_length_value.startswith(b"0"))
            or any(not ord("0") <= byte <= ord("9") for byte in content_length_value)
        ):
            _raise_http11_admission_error_v8(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Invalid HTTP/1.1 Content-Length",
            )
        if len(content_length_value) > 7:
            _raise_http11_admission_error_v8(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "HTTP/1.1 Content-Length exceeds the v8 body limit",
            )
        if len(content_length_value) == 7 and content_length_value > str(
            AUTHORITY_INPUT_BYTE_LIMIT_V8
        ).encode("ascii"):
            _raise_http11_admission_error_v8(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "HTTP/1.1 Content-Length exceeds the v8 body limit",
            )
        content_length = int(content_length_value)
    elif transfer_encoding_value is None or transfer_encoding_value.lower() != b"chunked":
        _raise_http11_admission_error_v8(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "Unsupported HTTP/1.1 Transfer-Encoding",
        )

    if content_encoding_value is None:
        transport_encoding = TransportEncodingV8.IDENTITY
    elif content_encoding_value.lower() == b"gzip":
        transport_encoding = TransportEncodingV8.GZIP
    else:
        _raise_http11_admission_error_v8(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "Unsupported HTTP/1.1 Content-Encoding",
        )
        raise AssertionError("unreachable admission branch")

    source = Http11AuthorityInputSourceV8(
        raw_response,
        body_offset=body_offset,
        content_length=content_length,
        chunked=chunked,
    )
    return AdmittedHttp11AuthorityInputV8(
        source=source,
        transport_encoding=transport_encoding,
    )


@dataclass(slots=True)
class _JsonFrameV8:
    kind: str
    state: str
    item_count: int = 0
    keys: set[str] | None = None


class _IterativeJsonScannerV8:
    """Strict, nonrecursive UTF-8/JSON scanner with the frozen v8 counters."""

    __slots__ = (
        "aggregate_scalar_bytes",
        "frames",
        "literal_index",
        "literal_target",
        "maximum_array_elements",
        "maximum_decoded_string_bytes",
        "maximum_depth",
        "maximum_number_token_bytes",
        "maximum_object_members",
        "mode",
        "number_length",
        "number_state",
        "root_complete",
        "root_started",
        "string_bytes",
        "string_key_bytes",
        "string_role",
        "string_state",
        "surrogate_high",
        "syntax_node_count",
        "unicode_digits",
        "utf8_accumulator",
        "utf8_character_count",
        "utf8_continuations",
        "utf8_first_continuation",
        "utf8_first_maximum",
        "utf8_first_minimum",
        "utf8_sequence_length",
    )

    def __init__(self) -> None:
        self.frames: list[_JsonFrameV8] = []
        self.mode = "STRUCTURAL"
        self.root_started = False
        self.root_complete = False
        self.syntax_node_count = 0
        self.maximum_depth = 0
        self.maximum_object_members = 0
        self.maximum_array_elements = 0
        self.maximum_decoded_string_bytes = 0
        self.aggregate_scalar_bytes = 0
        self.maximum_number_token_bytes = 0

        self.string_role = ""
        self.string_state = "NORMAL"
        self.string_bytes = 0
        self.string_key_bytes: bytearray | None = None
        self.unicode_digits = ""
        self.surrogate_high = 0

        self.number_state = ""
        self.number_length = 0
        self.literal_target = ""
        self.literal_index = 0

        self.utf8_continuations = 0
        self.utf8_accumulator = 0
        self.utf8_sequence_length = 0
        self.utf8_first_continuation = False
        self.utf8_first_minimum = 0x80
        self.utf8_first_maximum = 0xBF
        self.utf8_character_count = 0

    def feed_byte(
        self,
        byte: int,
    ) -> tuple[
        AuthorityInputPhaseV8 | None,
        AuthorityInputTerminationReasonV8 | None,
    ]:
        character, encoded_length, failure = self._decode_utf8_byte(byte)
        if failure is not None:
            return AuthorityInputPhaseV8.UTF8_DECODE, failure
        if character is None:
            return None, None
        if self.utf8_character_count == 0 and character == "\ufeff":
            return (
                AuthorityInputPhaseV8.UTF8_DECODE,
                AuthorityInputTerminationReasonV8.INVALID_UTF8,
            )
        self.utf8_character_count += 1
        failure = self._consume_character(character, encoded_length)
        if failure is not None:
            return AuthorityInputPhaseV8.JSON_SCAN, failure
        return None, None

    def finalize_utf8(self) -> AuthorityInputTerminationReasonV8 | None:
        if self.utf8_continuations:
            return AuthorityInputTerminationReasonV8.INVALID_UTF8
        return None

    def finalize_json(self) -> AuthorityInputTerminationReasonV8 | None:
        """Finish JSON without constructing a Python object tree."""

        if self.mode == "STRING":
            if self.string_state in {
                "EXPECT_LOW_BACKSLASH",
                "EXPECT_LOW_U",
                "LOW_UNICODE",
            }:
                return AuthorityInputTerminationReasonV8.LONE_SURROGATE
            return AuthorityInputTerminationReasonV8.INVALID_JSON
        if self.mode == "NUMBER":
            if self.number_state == "MINUS":
                return AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER
            self._finish_number()
        elif self.mode == "LITERAL":
            return AuthorityInputTerminationReasonV8.INVALID_JSON
        if not self.root_started:
            return AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT
        if self.frames or not self.root_complete:
            return AuthorityInputTerminationReasonV8.INVALID_JSON
        return None

    def document(self, raw_bytes: bytes) -> BoundedJsonDocumentV8:
        return BoundedJsonDocumentV8(
            raw_bytes=raw_bytes,
            syntax_node_count=self.syntax_node_count,
            maximum_depth=self.maximum_depth,
            maximum_object_members=self.maximum_object_members,
            maximum_array_elements=self.maximum_array_elements,
            maximum_decoded_string_bytes=self.maximum_decoded_string_bytes,
            aggregate_decoded_scalar_bytes=self.aggregate_scalar_bytes,
            maximum_number_token_bytes=self.maximum_number_token_bytes,
        )

    def _decode_utf8_byte(
        self,
        byte: int,
    ) -> tuple[str | None, int, AuthorityInputTerminationReasonV8 | None]:
        if self.utf8_continuations:
            if not 0x80 <= byte <= 0xBF:
                return None, 0, AuthorityInputTerminationReasonV8.INVALID_UTF8
            if self.utf8_first_continuation and not (
                self.utf8_first_minimum <= byte <= self.utf8_first_maximum
            ):
                return None, 0, AuthorityInputTerminationReasonV8.INVALID_UTF8
            self.utf8_first_continuation = False
            self.utf8_accumulator = (self.utf8_accumulator << 6) | (byte & 0x3F)
            self.utf8_continuations -= 1
            if self.utf8_continuations:
                return None, 0, None
            codepoint = self.utf8_accumulator
            encoded_length = self.utf8_sequence_length
            if 0xD800 <= codepoint <= 0xDFFF or codepoint > 0x10FFFF:
                return None, 0, AuthorityInputTerminationReasonV8.INVALID_UTF8
            return chr(codepoint), encoded_length, None

        if byte <= 0x7F:
            return chr(byte), 1, None
        if 0xC2 <= byte <= 0xDF:
            self._start_utf8_sequence(
                byte & 0x1F,
                continuations=1,
                length=2,
            )
            return None, 0, None
        if 0xE0 <= byte <= 0xEF:
            first_minimum = 0xA0 if byte == 0xE0 else 0x80
            first_maximum = 0x9F if byte == 0xED else 0xBF
            self._start_utf8_sequence(
                byte & 0x0F,
                continuations=2,
                length=3,
                first_minimum=first_minimum,
                first_maximum=first_maximum,
            )
            return None, 0, None
        if 0xF0 <= byte <= 0xF4:
            first_minimum = 0x90 if byte == 0xF0 else 0x80
            first_maximum = 0x8F if byte == 0xF4 else 0xBF
            self._start_utf8_sequence(
                byte & 0x07,
                continuations=3,
                length=4,
                first_minimum=first_minimum,
                first_maximum=first_maximum,
            )
            return None, 0, None
        return None, 0, AuthorityInputTerminationReasonV8.INVALID_UTF8

    def _start_utf8_sequence(
        self,
        accumulator: int,
        *,
        continuations: int,
        length: int,
        first_minimum: int = 0x80,
        first_maximum: int = 0xBF,
    ) -> None:
        self.utf8_accumulator = accumulator
        self.utf8_continuations = continuations
        self.utf8_sequence_length = length
        self.utf8_first_continuation = True
        self.utf8_first_minimum = first_minimum
        self.utf8_first_maximum = first_maximum

    def _consume_character(
        self,
        character: str,
        encoded_length: int,
    ) -> AuthorityInputTerminationReasonV8 | None:
        while True:
            if self.mode == "STRING":
                return self._consume_string_character(character)
            if self.mode == "NUMBER":
                number_failure, reprocess = self._consume_number_character(character)
                if number_failure is not None:
                    return number_failure
                if not reprocess:
                    return None
                continue
            if self.mode == "LITERAL":
                return self._consume_literal_character(character)
            return self._consume_structural_character(character, encoded_length)

    def _consume_structural_character(
        self,
        character: str,
        _encoded_length: int,
    ) -> AuthorityInputTerminationReasonV8 | None:
        if character in _JSON_WHITESPACE:
            return None
        if self.root_complete:
            return AuthorityInputTerminationReasonV8.INVALID_JSON
        if not self.root_started:
            if character != "{":
                return AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT
            self.root_started = True
            return self._open_container("OBJECT")

        frame = self.frames[-1]
        if frame.kind == "OBJECT":
            if frame.state in {"FIRST_KEY_OR_END", "KEY_REQUIRED"}:
                if character == "}" and frame.state == "FIRST_KEY_OR_END":
                    return self._close_container("OBJECT")
                if character != '"':
                    return AuthorityInputTerminationReasonV8.INVALID_JSON
                frame.item_count += 1
                self.maximum_object_members = max(
                    self.maximum_object_members,
                    frame.item_count,
                )
                if frame.item_count > AUTHORITY_INPUT_MAX_CONTAINER_ITEMS_V8:
                    return AuthorityInputTerminationReasonV8.CONTAINER_LIMIT_EXCEEDED
                node_failure = self._add_node()
                if node_failure is not None:
                    return node_failure
                self._start_string("KEY")
                return None
            if frame.state == "COLON":
                if character != ":":
                    return AuthorityInputTerminationReasonV8.INVALID_JSON
                frame.state = "VALUE"
                return None
            if frame.state == "VALUE":
                return self._start_value(character)
            if frame.state == "COMMA_OR_END":
                if character == ",":
                    frame.state = "KEY_REQUIRED"
                    return None
                if character == "}":
                    return self._close_container("OBJECT")
                return AuthorityInputTerminationReasonV8.INVALID_JSON
            return AuthorityInputTerminationReasonV8.INVALID_JSON

        if frame.state in {"FIRST_VALUE_OR_END", "VALUE_REQUIRED"}:
            if character == "]" and frame.state == "FIRST_VALUE_OR_END":
                return self._close_container("ARRAY")
            return self._start_value(character)
        if frame.state == "COMMA_OR_END":
            if character == ",":
                frame.state = "VALUE_REQUIRED"
                return None
            if character == "]":
                return self._close_container("ARRAY")
        return AuthorityInputTerminationReasonV8.INVALID_JSON

    def _start_value(
        self,
        character: str,
    ) -> AuthorityInputTerminationReasonV8 | None:
        literal_target = {"t": "true", "f": "false", "n": "null"}.get(character)
        is_number = character == "-" or _is_ascii_digit(character)
        if character not in {'"', "{", "["} and literal_target is None and not is_number:
            if character in {"N", "I"}:
                return AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER
            return AuthorityInputTerminationReasonV8.INVALID_JSON

        parent = self.frames[-1]
        if parent.kind == "ARRAY":
            parent.item_count += 1
            self.maximum_array_elements = max(
                self.maximum_array_elements,
                parent.item_count,
            )
            if parent.item_count > AUTHORITY_INPUT_MAX_CONTAINER_ITEMS_V8:
                return AuthorityInputTerminationReasonV8.CONTAINER_LIMIT_EXCEEDED
        parent.state = "COMMA_OR_END"

        node_failure = self._add_node()
        if node_failure is not None:
            return node_failure
        if character == "{":
            return self._open_container("OBJECT", node_already_counted=True)
        if character == "[":
            return self._open_container("ARRAY", node_already_counted=True)
        if character == '"':
            self._start_string("VALUE")
            return None
        if is_number:
            return self._start_number(character)
        if literal_target is not None:
            self.mode = "LITERAL"
            self.literal_target = literal_target
            self.literal_index = 1
            return self._add_token_bytes(1)
        raise AssertionError("validated JSON value start was not handled")

    def _open_container(
        self,
        kind: str,
        *,
        node_already_counted: bool = False,
    ) -> AuthorityInputTerminationReasonV8 | None:
        if not node_already_counted:
            node_failure = self._add_node()
            if node_failure is not None:
                return node_failure
        depth = len(self.frames) + 1
        self.maximum_depth = max(self.maximum_depth, depth)
        if depth > AUTHORITY_INPUT_MAX_DEPTH_V8:
            return AuthorityInputTerminationReasonV8.DEPTH_LIMIT_EXCEEDED
        if kind == "OBJECT":
            self.frames.append(
                _JsonFrameV8(
                    kind="OBJECT",
                    state="FIRST_KEY_OR_END",
                    keys=set(),
                )
            )
        else:
            self.frames.append(_JsonFrameV8(kind="ARRAY", state="FIRST_VALUE_OR_END"))
        return None

    def _close_container(
        self,
        expected_kind: str,
    ) -> AuthorityInputTerminationReasonV8 | None:
        if not self.frames or self.frames[-1].kind != expected_kind:
            return AuthorityInputTerminationReasonV8.INVALID_JSON
        self.frames.pop()
        if not self.frames:
            self.root_complete = True
        return None

    def _start_string(self, role: str) -> None:
        self.mode = "STRING"
        self.string_role = role
        self.string_state = "NORMAL"
        self.string_bytes = 0
        self.string_key_bytes = bytearray() if role == "KEY" else None
        self.unicode_digits = ""

    def _consume_string_character(
        self,
        character: str,
    ) -> AuthorityInputTerminationReasonV8 | None:
        if self.string_state == "NORMAL":
            if character == '"':
                return self._finish_string()
            if character == "\\":
                self.string_state = "ESCAPE"
                return None
            if ord(character) < 0x20:
                return AuthorityInputTerminationReasonV8.INVALID_JSON
            return self._add_string_character(character)

        if self.string_state == "ESCAPE":
            simple_escape = {
                '"': '"',
                "\\": "\\",
                "/": "/",
                "b": "\b",
                "f": "\f",
                "n": "\n",
                "r": "\r",
                "t": "\t",
            }.get(character)
            if simple_escape is not None:
                self.string_state = "NORMAL"
                return self._add_string_character(simple_escape)
            if character == "u":
                self.string_state = "UNICODE"
                self.unicode_digits = ""
                return None
            return AuthorityInputTerminationReasonV8.INVALID_JSON

        if self.string_state == "UNICODE":
            if character not in _HEX_CHARACTERS:
                return AuthorityInputTerminationReasonV8.INVALID_JSON
            self.unicode_digits += character
            if len(self.unicode_digits) < 4:
                return None
            codepoint = int(self.unicode_digits, 16)
            if 0xD800 <= codepoint <= 0xDBFF:
                self.surrogate_high = codepoint
                self.string_state = "EXPECT_LOW_BACKSLASH"
                return None
            if 0xDC00 <= codepoint <= 0xDFFF:
                return AuthorityInputTerminationReasonV8.LONE_SURROGATE
            self.string_state = "NORMAL"
            return self._add_string_character(chr(codepoint))

        if self.string_state == "EXPECT_LOW_BACKSLASH":
            if character != "\\":
                return AuthorityInputTerminationReasonV8.LONE_SURROGATE
            self.string_state = "EXPECT_LOW_U"
            return None
        if self.string_state == "EXPECT_LOW_U":
            if character != "u":
                return AuthorityInputTerminationReasonV8.LONE_SURROGATE
            self.string_state = "LOW_UNICODE"
            self.unicode_digits = ""
            return None
        if self.string_state == "LOW_UNICODE":
            if character not in _HEX_CHARACTERS:
                return AuthorityInputTerminationReasonV8.LONE_SURROGATE
            self.unicode_digits += character
            if len(self.unicode_digits) < 4:
                return None
            low = int(self.unicode_digits, 16)
            if not 0xDC00 <= low <= 0xDFFF:
                return AuthorityInputTerminationReasonV8.LONE_SURROGATE
            high = self.surrogate_high
            self.surrogate_high = 0
            codepoint = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
            self.string_state = "NORMAL"
            return self._add_string_character(chr(codepoint))
        return AuthorityInputTerminationReasonV8.INVALID_JSON

    def _add_string_character(
        self,
        character: str,
    ) -> AuthorityInputTerminationReasonV8 | None:
        encoded = character.encode("utf-8")
        self.string_bytes += len(encoded)
        self.maximum_decoded_string_bytes = max(
            self.maximum_decoded_string_bytes,
            self.string_bytes,
        )
        if self.string_bytes > AUTHORITY_INPUT_MAX_SCALAR_BYTES_V8:
            return AuthorityInputTerminationReasonV8.SCALAR_LIMIT_EXCEEDED
        aggregate_failure = self._add_token_bytes(len(encoded))
        if aggregate_failure is not None:
            return aggregate_failure
        if self.string_key_bytes is not None:
            self.string_key_bytes.extend(encoded)
        return None

    def _finish_string(self) -> AuthorityInputTerminationReasonV8 | None:
        if self.string_role == "KEY":
            frame = self.frames[-1]
            key_bytes = self.string_key_bytes
            if key_bytes is None or frame.keys is None:
                return AuthorityInputTerminationReasonV8.INVALID_JSON
            key = bytes(key_bytes).decode("utf-8", errors="strict")
            if key in frame.keys:
                return AuthorityInputTerminationReasonV8.DUPLICATE_OBJECT_KEY
            frame.keys.add(key)
            frame.state = "COLON"
        self.mode = "STRUCTURAL"
        self.string_role = ""
        self.string_key_bytes = None
        return None

    def _start_number(
        self,
        character: str,
    ) -> AuthorityInputTerminationReasonV8 | None:
        self.mode = "NUMBER"
        self.number_length = 1
        self.maximum_number_token_bytes = max(self.maximum_number_token_bytes, 1)
        aggregate_failure = self._add_token_bytes(1)
        if aggregate_failure is not None:
            return aggregate_failure
        if character == "-":
            self.number_state = "MINUS"
        elif character == "0":
            self.number_state = "ZERO"
        else:
            self.number_state = "DIGITS"
        return None

    def _consume_number_character(
        self,
        character: str,
    ) -> tuple[AuthorityInputTerminationReasonV8 | None, bool]:
        if _is_ascii_digit(character):
            if self.number_state == "ZERO":
                return AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER, False
            if self.number_state == "MINUS":
                if character == "0":
                    return AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER, False
                self.number_state = "DIGITS"
            self.number_length += 1
            self.maximum_number_token_bytes = max(
                self.maximum_number_token_bytes,
                self.number_length,
            )
            return self._add_token_bytes(1), False
        if character in {".", "e", "E", "+", "-"} or character.isalpha():
            return AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER, False
        if self.number_state == "MINUS":
            return AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER, False
        self._finish_number()
        return None, True

    def _finish_number(self) -> None:
        self.mode = "STRUCTURAL"
        self.number_state = ""
        self.number_length = 0

    def _consume_literal_character(
        self,
        character: str,
    ) -> AuthorityInputTerminationReasonV8 | None:
        if (
            self.literal_index >= len(self.literal_target)
            or character != self.literal_target[self.literal_index]
        ):
            return AuthorityInputTerminationReasonV8.INVALID_JSON
        self.literal_index += 1
        aggregate_failure = self._add_token_bytes(1)
        if aggregate_failure is not None:
            return aggregate_failure
        if self.literal_index == len(self.literal_target):
            self.mode = "STRUCTURAL"
            self.literal_target = ""
            self.literal_index = 0
        return None

    def _add_node(self) -> AuthorityInputTerminationReasonV8 | None:
        self.syntax_node_count += 1
        if self.syntax_node_count > AUTHORITY_INPUT_MAX_NODES_V8:
            return AuthorityInputTerminationReasonV8.NODE_LIMIT_EXCEEDED
        return None

    def _add_token_bytes(
        self,
        count: int,
    ) -> AuthorityInputTerminationReasonV8 | None:
        self.aggregate_scalar_bytes += count
        if self.aggregate_scalar_bytes > AUTHORITY_INPUT_MAX_AGGREGATE_SCALAR_BYTES_V8:
            return AuthorityInputTerminationReasonV8.AGGREGATE_SCALAR_LIMIT_EXCEEDED
        return None


class MonotonicAuthorityInputClockV8:
    """Event-loop monotonic time projected onto one fixed UTC origin."""

    __slots__ = ("_loop_origin", "_utc_origin")

    def __init__(self) -> None:
        loop = asyncio.get_running_loop()
        self._loop_origin = loop.time()
        self._utc_origin = datetime.now(UTC)

    def now(self) -> datetime:
        elapsed = asyncio.get_running_loop().time() - self._loop_origin
        return self._utc_origin + timedelta(seconds=elapsed)

    async def wait_until(self, deadline: datetime) -> None:
        remaining = (deadline - self.now()).total_seconds()
        if remaining > 0:
            await asyncio.sleep(remaining)


class NeverCancelledAuthorityInputTokenV8:
    """Default level-triggered token that never becomes cancelled."""

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = asyncio.Event()

    def is_cancelled(self) -> bool:
        return False

    async def wait_cancelled(self) -> None:
        await self._event.wait()


class _HashStateV8(Protocol):
    def update(self, data: bytes, /) -> None: ...

    def hexdigest(self) -> str: ...

    def copy(self) -> _HashStateV8: ...


@dataclass(slots=True)
class _GateStateV8:
    encoding: TransportEncodingV8
    scanner: _IterativeJsonScannerV8 = field(default_factory=_IterativeJsonScannerV8)
    raw_document: bytearray = field(default_factory=bytearray)
    wire_hasher: _HashStateV8 = field(default_factory=hashlib.sha256)
    decompressed_hasher: _HashStateV8 = field(default_factory=hashlib.sha256)
    wire_length: int = 0
    decompressed_length: int = 0
    content_quantum_offset: int = 0
    content_quantum_open: bool = False
    pipeline_quantum_offset: int = 0
    pipeline_quantum_open: bool = False

    def accept_wire(self, data: bytes) -> None:
        self.wire_hasher.update(data)
        self.wire_length += len(data)

    def accept_decompressed(self, data: bytes) -> None:
        self.decompressed_hasher.update(data)
        self.decompressed_length += len(data)
        self.raw_document.extend(data)

    def wire_digest(self) -> str:
        if self.wire_length == 0:
            return _EMPTY_SHA256
        return f"sha256:{self.wire_hasher.hexdigest()}"

    def decompressed_digest(self) -> str:
        if self.decompressed_length == 0:
            return _EMPTY_SHA256
        return f"sha256:{self.decompressed_hasher.hexdigest()}"

    def wire_snapshot(self) -> tuple[int, _HashStateV8]:
        return self.wire_length, self.wire_hasher.copy()

    def restore_wire(self, snapshot: tuple[int, _HashStateV8]) -> None:
        self.wire_length, self.wire_hasher = snapshot


@dataclass(slots=True)
class _SourceLifecycleV8:
    source: AuthorityInputSourceV8
    aborted: bool = False
    finished: bool = False

    def abort(self) -> None:
        if self.aborted:
            return
        self.aborted = True
        self.source.abort_current_read()

    def finish(self, *, reusable: bool) -> None:
        if self.finished:
            raise RuntimeError("authority input response was finalized more than once")
        self.finished = True
        self.source.finish_response(reusable)


@dataclass(frozen=True, slots=True)
class _SupervisedReadV8:
    outcome: object | None = None
    termination_reason: AuthorityInputTerminationReasonV8 | None = None


_RETIRED_SOURCE_TASKS_V8: set[asyncio.Task[object]] = set()


def _consume_retired_source_task_v8(task: asyncio.Task[object]) -> None:
    _RETIRED_SOURCE_TASKS_V8.discard(task)
    try:
        task.result()
    except BaseException:
        # This is a sanitizing sink: no provider result, exception type, or
        # exception message is forwarded to logging or the event-loop handler.
        return


def _retire_source_task_v8(task: asyncio.Task[object]) -> None:
    _RETIRED_SOURCE_TASKS_V8.add(task)
    task.add_done_callback(_consume_retired_source_task_v8)
    task.cancel()


def _discard_ready_source_task_v8(task: asyncio.Task[object]) -> None:
    try:
        task.result()
    except BaseException:
        return


async def _cancel_and_retrieve_waiters_v8(
    *tasks: asyncio.Task[None],
) -> None:
    for task in tasks:
        if not task.done():
            task.cancel()
    if not tasks:
        return

    cleanup = asyncio.gather(*tasks, return_exceptions=True)
    deferred_cancellation: asyncio.CancelledError | None = None
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError as exc:
            if deferred_cancellation is None:
                deferred_cancellation = exc
    cleanup.result()
    if deferred_cancellation is not None:
        raise deferred_cancellation


async def _invoke_source_read_v8(source: AuthorityInputSourceV8) -> object:
    return await source.read(AUTHORITY_INPUT_READ_QUANTUM_V8)


async def _invoke_deadline_waiter_v8(
    clock: AuthorityInputClockV8,
    operation_deadline: datetime,
) -> None:
    await clock.wait_until(operation_deadline)


async def _invoke_cancellation_waiter_v8(
    cancellation_token: AuthorityInputCancellationTokenV8,
) -> None:
    await cancellation_token.wait_cancelled()


def _sample_control_v8(
    clock: AuthorityInputClockV8,
    cancellation_token: AuthorityInputCancellationTokenV8,
    operation_deadline: datetime,
) -> AuthorityInputTerminationReasonV8 | None:
    try:
        now = clock.now()
    except (Exception, asyncio.CancelledError):
        return AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE
    if not _is_exact_utc_datetime(now) or not _is_exact_utc_datetime(operation_deadline):
        return AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE

    try:
        deadline_won = now >= operation_deadline
    except (Exception, asyncio.CancelledError):
        return AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE
    try:
        cancelled = cast("object", cancellation_token.is_cancelled())
    except (Exception, asyncio.CancelledError):
        if deadline_won:
            return AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED
        return AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE
    if type(cancelled) is not bool:
        if deadline_won:
            return AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED
        return AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE
    if deadline_won:
        return AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED
    if cancelled:
        return AuthorityInputTerminationReasonV8.CANCELLED
    return None


async def _supervised_read_v8(
    source: AuthorityInputSourceV8,
    lifecycle: _SourceLifecycleV8,
    *,
    clock: AuthorityInputClockV8,
    cancellation_token: AuthorityInputCancellationTokenV8,
    operation_deadline: datetime,
) -> _SupervisedReadV8:
    source_task = asyncio.create_task(
        _invoke_source_read_v8(source),
        name="agentkernel-v8-authority-input-read",
    )
    deadline_task = asyncio.create_task(
        _invoke_deadline_waiter_v8(clock, operation_deadline),
        name="agentkernel-v8-authority-input-deadline",
    )
    cancellation_task = asyncio.create_task(
        _invoke_cancellation_waiter_v8(cancellation_token),
        name="agentkernel-v8-authority-input-cancellation",
    )
    source_generation_closed = False
    waiters_retrieved = False
    try:
        done, _pending = await asyncio.wait(
            {source_task, deadline_task, cancellation_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        sampled_reason = _sample_control_v8(
            clock,
            cancellation_token,
            operation_deadline,
        )
        waiter_completed = deadline_task in done or cancellation_task in done
        if sampled_reason is not None or waiter_completed:
            reason = (
                sampled_reason
                if sampled_reason is not None
                else AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE
            )
            if source_task.done():
                _discard_ready_source_task_v8(source_task)
            else:
                lifecycle.abort()
                _retire_source_task_v8(source_task)
            source_generation_closed = True
            await _cancel_and_retrieve_waiters_v8(deadline_task, cancellation_task)
            waiters_retrieved = True
            return _SupervisedReadV8(termination_reason=reason)

        if source_task not in done:
            if source_task.done():
                _discard_ready_source_task_v8(source_task)
            else:
                lifecycle.abort()
                _retire_source_task_v8(source_task)
            source_generation_closed = True
            supervised = _SupervisedReadV8(
                termination_reason=AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE
            )
        else:
            source_generation_closed = True
            try:
                outcome = source_task.result()
            except asyncio.CancelledError:
                supervised = _SupervisedReadV8(
                    termination_reason=AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION
                )
            except Exception:
                supervised = _SupervisedReadV8(
                    termination_reason=AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION
                )
            else:
                supervised = _SupervisedReadV8(outcome=outcome)
        await _cancel_and_retrieve_waiters_v8(deadline_task, cancellation_task)
        waiters_retrieved = True
        return supervised
    finally:
        if not source_generation_closed:
            if source_task.done():
                _discard_ready_source_task_v8(source_task)
            else:
                lifecycle.abort()
                _retire_source_task_v8(source_task)
        if not waiters_retrieved:
            await _cancel_and_retrieve_waiters_v8(
                deadline_task,
                cancellation_task,
            )


def _complete_observation_v8(
    state: _GateStateV8,
) -> CompleteBoundedResponseObservationV8:
    return CompleteBoundedResponseObservationV8(
        transport_encoding=state.encoding,
        complete_wire_digest=state.wire_digest(),
        complete_wire_length=state.wire_length,
        complete_decompressed_digest=state.decompressed_digest(),
        complete_decompressed_length=state.decompressed_length,
    )


def _prefix_failure_v8(
    state: _GateStateV8,
    *,
    phase: AuthorityInputPhaseV8,
    reason: AuthorityInputTerminationReasonV8,
) -> BoundedAuthorityInputFailureV8:
    termination = AuthorityInputTerminationV8(phase=phase, reason=reason)
    if state.wire_length == 0:
        observation: AuthorityInputObservationV8 = NoResponseObservationV8.from_termination(
            failure_phase=phase,
            termination_reason=reason,
            transport_encoding=state.encoding,
            observed_wire_prefix_length=0,
            observed_decompressed_prefix_length=0,
        )
    else:
        observation = IncompleteBoundedResponseObservationV8(
            termination_phase=phase,
            termination_reason=reason,
            transport_encoding=state.encoding,
            observed_wire_prefix_digest=state.wire_digest(),
            observed_wire_prefix_length=state.wire_length,
            observed_decompressed_prefix_digest=state.decompressed_digest(),
            observed_decompressed_prefix_length=state.decompressed_length,
        )
    return BoundedAuthorityInputFailureV8(
        observation=observation,
        transport_encoding=state.encoding,
        termination=termination,
    )


def _complete_failure_v8(
    state: _GateStateV8,
    *,
    phase: AuthorityInputPhaseV8,
    reason: AuthorityInputTerminationReasonV8,
    observation: CompleteBoundedResponseObservationV8,
) -> BoundedAuthorityInputFailureV8:
    return BoundedAuthorityInputFailureV8(
        observation=observation,
        transport_encoding=state.encoding,
        termination=AuthorityInputTerminationV8(phase=phase, reason=reason),
    )


def _overflow_failure_v8(
    state: _GateStateV8,
    *,
    boundary: OverflowBoundaryV8,
) -> BoundedAuthorityInputFailureV8:
    observation = OverflowPrefixObservationV8(
        transport_encoding=state.encoding,
        observed_wire_prefix_digest=state.wire_digest(),
        observed_wire_prefix_length=state.wire_length,
        observed_decompressed_prefix_digest=state.decompressed_digest(),
        observed_decompressed_prefix_length=state.decompressed_length,
        exceeded_boundary=boundary,
        configured_limit=AUTHORITY_INPUT_BYTE_LIMIT_V8,
        first_excess_observed_count=AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8,
    )
    return BoundedAuthorityInputFailureV8(
        observation=observation,
        transport_encoding=state.encoding,
        termination=None,
    )


def _checkpoint_failure_v8(
    state: _GateStateV8,
    *,
    phase: AuthorityInputPhaseV8,
    clock: AuthorityInputClockV8,
    cancellation_token: AuthorityInputCancellationTokenV8,
    operation_deadline: datetime,
    complete_observation: CompleteBoundedResponseObservationV8 | None = None,
) -> BoundedAuthorityInputFailureV8 | None:
    reason = _sample_control_v8(clock, cancellation_token, operation_deadline)
    if reason is None:
        return None
    actual_phase = (
        AuthorityInputPhaseV8.WIRE_READ
        if reason is AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE
        else phase
    )
    if complete_observation is not None:
        return _complete_failure_v8(
            state,
            phase=actual_phase,
            reason=reason,
            observation=complete_observation,
        )
    return _prefix_failure_v8(state, phase=actual_phase, reason=reason)


def _content_checkpoint_v8(
    state: _GateStateV8,
    *,
    clock: AuthorityInputClockV8,
    cancellation_token: AuthorityInputCancellationTokenV8,
    operation_deadline: datetime,
) -> BoundedAuthorityInputFailureV8 | None:
    if state.content_quantum_open:
        return None
    failure = _checkpoint_failure_v8(
        state,
        phase=AuthorityInputPhaseV8.CONTENT_DECODE,
        clock=clock,
        cancellation_token=cancellation_token,
        operation_deadline=operation_deadline,
    )
    if failure is None:
        state.content_quantum_open = True
    return failure


def _advance_content_quantum_v8(state: _GateStateV8, count: int) -> None:
    if type(count) is not int or count < 0:
        raise ValueError("invalid content-quantum advancement")
    state.content_quantum_offset = (
        state.content_quantum_offset + count
    ) % AUTHORITY_INPUT_READ_QUANTUM_V8
    if count and state.content_quantum_offset == 0:
        state.content_quantum_open = False


def _process_decompressed_pipeline_v8(
    state: _GateStateV8,
    data: bytes,
    *,
    identity: bool,
    initial_committed: int,
    clock: AuthorityInputClockV8,
    cancellation_token: AuthorityInputCancellationTokenV8,
    operation_deadline: datetime,
) -> tuple[int, BoundedAuthorityInputFailureV8 | None]:
    if not 0 <= initial_committed <= len(data):
        raise ValueError("invalid precommitted decompressed prefix")
    commit_cursor = initial_committed

    def commit_through(end: int) -> None:
        nonlocal commit_cursor
        if end <= commit_cursor:
            return
        accepted = data[commit_cursor:end]
        if identity:
            state.accept_wire(accepted)
        state.accept_decompressed(accepted)
        commit_cursor = end

    for index, byte in enumerate(data):
        if not state.pipeline_quantum_open:
            commit_through(index)
            utf8_checkpoint = _checkpoint_failure_v8(
                state,
                phase=AuthorityInputPhaseV8.UTF8_DECODE,
                clock=clock,
                cancellation_token=cancellation_token,
                operation_deadline=operation_deadline,
            )
            if utf8_checkpoint is not None:
                return index, utf8_checkpoint
            json_checkpoint = _checkpoint_failure_v8(
                state,
                phase=AuthorityInputPhaseV8.JSON_SCAN,
                clock=clock,
                cancellation_token=cancellation_token,
                operation_deadline=operation_deadline,
            )
            if json_checkpoint is not None:
                return index, json_checkpoint
            state.pipeline_quantum_open = True

        failure_phase, scanner_reason = state.scanner.feed_byte(byte)
        state.pipeline_quantum_offset = (
            state.pipeline_quantum_offset + 1
        ) % AUTHORITY_INPUT_READ_QUANTUM_V8
        if state.pipeline_quantum_offset == 0:
            state.pipeline_quantum_open = False
        if scanner_reason is not None:
            commit_through(index + 1)
            if failure_phase is None:
                raise AssertionError("scanner failure requires an exact phase")
            return index + 1, _prefix_failure_v8(
                state,
                phase=failure_phase,
                reason=scanner_reason,
            )

    commit_through(len(data))
    return len(data), None


class _ZlibDecompressorV8(Protocol):
    @property
    def eof(self) -> bool: ...

    @property
    def unconsumed_tail(self) -> bytes: ...

    @property
    def unused_data(self) -> bytes: ...

    def copy(self) -> _ZlibDecompressorV8: ...

    def decompress(self, data: bytes, max_length: int = 0) -> bytes: ...


def _replay_gzip_failure_v8(
    state: _GateStateV8,
    decoder_copy: _ZlibDecompressorV8,
    data: bytes,
    *,
    preaccepted_wire_bytes: int,
    clock: AuthorityInputClockV8,
    cancellation_token: AuthorityInputCancellationTokenV8,
    operation_deadline: datetime,
) -> BoundedAuthorityInputFailureV8:
    for index, byte in enumerate(data):
        byte_value = bytes((byte,))
        if index >= preaccepted_wire_bytes:
            state.accept_wire(byte_value)
        pending = byte_value
        while True:
            pipeline_offset = state.pipeline_quantum_offset
            maximum_output_bytes = AUTHORITY_INPUT_READ_QUANTUM_V8 - pipeline_offset
            remaining = AUTHORITY_INPUT_BYTE_LIMIT_V8 - state.decompressed_length
            try:
                output = decoder_copy.decompress(
                    pending,
                    max_length=min(maximum_output_bytes, remaining + 1),
                )
            except zlib.error:
                return _prefix_failure_v8(
                    state,
                    phase=AuthorityInputPhaseV8.CONTENT_DECODE,
                    reason=AuthorityInputTerminationReasonV8.DECOMPRESSION_FAILED,
                )
            pending = b""
            if len(output) == remaining + 1:
                if remaining:
                    _processed, scanner_failure = _process_decompressed_pipeline_v8(
                        state,
                        output[:remaining],
                        identity=False,
                        initial_committed=0,
                        clock=clock,
                        cancellation_token=cancellation_token,
                        operation_deadline=operation_deadline,
                    )
                    if scanner_failure is not None:
                        return scanner_failure
                state.accept_decompressed(output[remaining:])
                return _overflow_failure_v8(
                    state,
                    boundary=OverflowBoundaryV8.DECOMPRESSED,
                )
            if output:
                _processed, scanner_failure = _process_decompressed_pipeline_v8(
                    state,
                    output,
                    identity=False,
                    initial_committed=0,
                    clock=clock,
                    cancellation_token=cancellation_token,
                    operation_deadline=operation_deadline,
                )
                if scanner_failure is not None:
                    return scanner_failure
            if decoder_copy.unused_data:
                return _prefix_failure_v8(
                    state,
                    phase=AuthorityInputPhaseV8.RESPONSE_FINALIZE,
                    reason=AuthorityInputTerminationReasonV8.TRAILING_COMPRESSED_DATA,
                )
            if decoder_copy.unconsumed_tail:
                pending = decoder_copy.unconsumed_tail
                continue
            if not output:
                break
    return _prefix_failure_v8(
        state,
        phase=AuthorityInputPhaseV8.CONTENT_DECODE,
        reason=AuthorityInputTerminationReasonV8.DECOMPRESSION_FAILED,
    )


def _decode_gzip_quantum_v8(
    state: _GateStateV8,
    decoder: _ZlibDecompressorV8,
    data: bytes,
    *,
    maximum_output_bytes: int,
    preaccepted_wire_bytes: int,
    clock: AuthorityInputClockV8,
    cancellation_token: AuthorityInputCancellationTokenV8,
    operation_deadline: datetime,
) -> tuple[
    bytes | None,
    bytes,
    int,
    _ZlibDecompressorV8 | None,
    int,
    BoundedAuthorityInputFailureV8 | None,
]:
    if (
        type(maximum_output_bytes) is not int
        or maximum_output_bytes < 1
        or type(preaccepted_wire_bytes) is not int
        or not 0 <= preaccepted_wire_bytes <= len(data)
    ):
        raise ValueError("invalid bounded GZIP decode request")
    if decoder.eof:
        if preaccepted_wire_bytes == 0 and data:
            state.accept_wire(data[:1])
        return (
            None,
            b"",
            0,
            None,
            0,
            _prefix_failure_v8(
                state,
                phase=AuthorityInputPhaseV8.RESPONSE_FINALIZE,
                reason=AuthorityInputTerminationReasonV8.TRAILING_COMPRESSED_DATA,
            ),
        )
    decoder_copy = decoder.copy()
    remaining = AUTHORITY_INPUT_BYTE_LIMIT_V8 - state.decompressed_length
    try:
        output = decoder.decompress(
            data,
            max_length=min(maximum_output_bytes, remaining + 1),
        )
    except zlib.error:
        return (
            None,
            b"",
            0,
            None,
            0,
            _replay_gzip_failure_v8(
                state,
                decoder_copy,
                data,
                preaccepted_wire_bytes=preaccepted_wire_bytes,
                clock=clock,
                cancellation_token=cancellation_token,
                operation_deadline=operation_deadline,
            ),
        )

    consumed = len(data) - len(decoder.unconsumed_tail) - len(decoder.unused_data)
    remaining_preaccepted = max(0, preaccepted_wire_bytes - consumed)
    if len(output) == remaining + 1:
        return (
            None,
            b"",
            0,
            None,
            0,
            _replay_gzip_failure_v8(
                state,
                decoder_copy,
                data,
                preaccepted_wire_bytes=preaccepted_wire_bytes,
                clock=clock,
                cancellation_token=cancellation_token,
                operation_deadline=operation_deadline,
            ),
        )
    if decoder.unused_data:
        return (
            None,
            b"",
            0,
            None,
            0,
            _replay_gzip_failure_v8(
                state,
                decoder_copy,
                data,
                preaccepted_wire_bytes=preaccepted_wire_bytes,
                clock=clock,
                cancellation_token=cancellation_token,
                operation_deadline=operation_deadline,
            ),
        )
    if consumed > preaccepted_wire_bytes:
        state.accept_wire(data[preaccepted_wire_bytes:consumed])
    return (
        output,
        decoder.unconsumed_tail,
        remaining_preaccepted,
        decoder_copy,
        consumed,
        None,
    )


def _minimal_gzip_wire_prefix_for_output_v8(
    decoder_copy: _ZlibDecompressorV8,
    data: bytes,
    *,
    required_output_bytes: int,
) -> int:
    if type(required_output_bytes) is not int or required_output_bytes < 1:
        raise ValueError("GZIP witness replay requires a positive output count")

    produced = 0
    try:
        buffered = decoder_copy.decompress(
            b"",
            max_length=required_output_bytes,
        )
    except zlib.error:
        return len(data)
    produced += len(buffered)
    if produced >= required_output_bytes:
        return 0

    for index, byte in enumerate(data):
        pending = bytes((byte,))
        while True:
            try:
                output = decoder_copy.decompress(
                    pending,
                    max_length=required_output_bytes - produced,
                )
            except zlib.error:
                return len(data)
            produced += len(output)
            if produced >= required_output_bytes:
                return index + 1
            if decoder_copy.unconsumed_tail:
                pending = decoder_copy.unconsumed_tail
                continue
            pending = b""
            if not output:
                break
    return len(data)


def _restore_gzip_output_witness_wire_v8(
    state: _GateStateV8,
    decoder_copy: _ZlibDecompressorV8,
    data: bytes,
    wire_snapshot: tuple[int, _HashStateV8],
    *,
    required_output_bytes: int,
) -> None:
    minimum_wire_bytes = _minimal_gzip_wire_prefix_for_output_v8(
        decoder_copy,
        data,
        required_output_bytes=required_output_bytes,
    )
    state.restore_wire(wire_snapshot)
    state.accept_wire(data[:minimum_wire_bytes])


def _append_gzip_replay_window_v8(
    window: bytearray,
    data: bytes,
) -> None:
    if type(window) is not bytearray or type(data) is not bytes:
        raise TypeError("GZIP replay window requires exact byte containers")
    if len(window) + len(data) > AUTHORITY_INPUT_READ_QUANTUM_V8:
        raise ValueError("GZIP replay window exceeds one logical transport quantum")
    window.extend(data)


async def read_bounded_authority_input_v8(
    source: AuthorityInputSourceV8,
    *,
    transport_encoding: TransportEncodingV8,
    operation_deadline: datetime,
    clock: AuthorityInputClockV8 | None = None,
    cancellation_token: AuthorityInputCancellationTokenV8 | None = None,
) -> BoundedAuthorityInputResultV8:
    """Read, supervise, decode, and preflight one bounded authority response."""

    lifecycle = _SourceLifecycleV8(source)
    reusable = False
    if type(transport_encoding) is not TransportEncodingV8:
        lifecycle.finish(reusable=False)
        raise AgentKernelError(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "Unsupported v8 authority input content encoding",
        )
    if not _is_exact_utc_datetime(operation_deadline):
        lifecycle.finish(reusable=False)
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Authority input deadline must be an exact UTC datetime",
        )
    actual_clock = clock if clock is not None else MonotonicAuthorityInputClockV8()
    actual_token = (
        cancellation_token
        if cancellation_token is not None
        else NeverCancelledAuthorityInputTokenV8()
    )
    state = _GateStateV8(encoding=transport_encoding)
    decoder: _ZlibDecompressorV8 | None = (
        cast("_ZlibDecompressorV8", zlib.decompressobj(wbits=16 + zlib.MAX_WBITS))
        if transport_encoding is TransportEncodingV8.GZIP
        else None
    )
    first_read = True
    gzip_quantum_wire = bytearray()
    gzip_quantum_decompressed_start = 0
    gzip_quantum_decoder_copy = decoder.copy() if decoder is not None else None
    gzip_quantum_wire_snapshot = state.wire_snapshot()

    def finish_result(
        result: BoundedAuthorityInputResultV8,
        *,
        response_reusable: bool,
    ) -> BoundedAuthorityInputResultV8:
        lifecycle.finish(reusable=response_reusable)
        return result

    def restore_gzip_output_witness_wire() -> None:
        if gzip_quantum_decoder_copy is None:
            raise AssertionError("GZIP witness requires a logical-quantum decoder snapshot")
        required_output_bytes = state.decompressed_length - gzip_quantum_decompressed_start
        if required_output_bytes < 1:
            raise AssertionError("GZIP output witness requires decompressed evidence")
        _restore_gzip_output_witness_wire_v8(
            state,
            gzip_quantum_decoder_copy,
            bytes(gzip_quantum_wire),
            gzip_quantum_wire_snapshot,
            required_output_bytes=required_output_bytes,
        )

    try:
        while True:
            checkpoint_phase = (
                AuthorityInputPhaseV8.BEFORE_RESPONSE
                if first_read
                else AuthorityInputPhaseV8.WIRE_READ
            )
            checkpoint_failure = _checkpoint_failure_v8(
                state,
                phase=checkpoint_phase,
                clock=actual_clock,
                cancellation_token=actual_token,
                operation_deadline=operation_deadline,
            )
            if checkpoint_failure is not None:
                return finish_result(checkpoint_failure, response_reusable=False)

            supervised = await _supervised_read_v8(
                source,
                lifecycle,
                clock=actual_clock,
                cancellation_token=actual_token,
                operation_deadline=operation_deadline,
            )
            first_read = False
            if supervised.termination_reason is not None:
                failure = _prefix_failure_v8(
                    state,
                    phase=AuthorityInputPhaseV8.WIRE_READ,
                    reason=supervised.termination_reason,
                )
                return finish_result(failure, response_reusable=False)

            outcome = supervised.outcome
            if type(outcome) is SourceDisconnectedV8:
                failure = _prefix_failure_v8(
                    state,
                    phase=AuthorityInputPhaseV8.WIRE_READ,
                    reason=AuthorityInputTerminationReasonV8.DISCONNECTED,
                )
                return finish_result(failure, response_reusable=False)
            if type(outcome) is SourceFramingFailureV8:
                failure = _prefix_failure_v8(
                    state,
                    phase=AuthorityInputPhaseV8.WIRE_READ,
                    reason=AuthorityInputTerminationReasonV8.TRANSFER_FRAMING_FAILED,
                )
                return finish_result(failure, response_reusable=False)
            if type(outcome) is SourceEofV8:
                if decoder is not None and not decoder.eof:
                    failure = _prefix_failure_v8(
                        state,
                        phase=AuthorityInputPhaseV8.RESPONSE_FINALIZE,
                        reason=AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM,
                    )
                    return finish_result(failure, response_reusable=False)

                complete_observation = _complete_observation_v8(state)
                reusable = True
                for final_phase in (
                    AuthorityInputPhaseV8.CONTENT_DECODE,
                    AuthorityInputPhaseV8.UTF8_DECODE,
                    AuthorityInputPhaseV8.JSON_SCAN,
                ):
                    checkpoint_failure = _checkpoint_failure_v8(
                        state,
                        phase=final_phase,
                        clock=actual_clock,
                        cancellation_token=actual_token,
                        operation_deadline=operation_deadline,
                        complete_observation=complete_observation,
                    )
                    if checkpoint_failure is not None:
                        return finish_result(
                            checkpoint_failure,
                            response_reusable=reusable,
                        )
                    if final_phase is AuthorityInputPhaseV8.UTF8_DECODE:
                        utf8_failure = state.scanner.finalize_utf8()
                        if utf8_failure is not None:
                            failure = _complete_failure_v8(
                                state,
                                phase=AuthorityInputPhaseV8.UTF8_DECODE,
                                reason=utf8_failure,
                                observation=complete_observation,
                            )
                            return finish_result(failure, response_reusable=reusable)
                    if final_phase is AuthorityInputPhaseV8.JSON_SCAN:
                        json_failure = state.scanner.finalize_json()
                        if json_failure is not None:
                            failure = _complete_failure_v8(
                                state,
                                phase=AuthorityInputPhaseV8.JSON_SCAN,
                                reason=json_failure,
                                observation=complete_observation,
                            )
                            return finish_result(failure, response_reusable=reusable)

                publication_failure = _checkpoint_failure_v8(
                    state,
                    phase=AuthorityInputPhaseV8.JSON_SCAN,
                    clock=actual_clock,
                    cancellation_token=actual_token,
                    operation_deadline=operation_deadline,
                    complete_observation=complete_observation,
                )
                if publication_failure is not None:
                    return finish_result(
                        publication_failure,
                        response_reusable=reusable,
                    )
                document = state.scanner.document(bytes(state.raw_document))
                success = BoundedAuthorityInputSuccessV8(
                    observation=complete_observation,
                    document=document,
                )
                return finish_result(success, response_reusable=reusable)

            if type(outcome) is not SourceDataV8:
                failure = _prefix_failure_v8(
                    state,
                    phase=AuthorityInputPhaseV8.WIRE_READ,
                    reason=AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION,
                )
                return finish_result(failure, response_reusable=False)
            source_data = outcome.data
            if type(source_data) is not bytes or not source_data:
                failure = _prefix_failure_v8(
                    state,
                    phase=AuthorityInputPhaseV8.WIRE_READ,
                    reason=AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION,
                )
                return finish_result(failure, response_reusable=False)

            previous_wire_length = state.wire_length
            first_byte = source_data[:1]
            state.accept_wire(first_byte)
            if transport_encoding is TransportEncodingV8.IDENTITY:
                state.accept_decompressed(first_byte)
            if state.wire_length == AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8:
                boundary = (
                    OverflowBoundaryV8.UNCOMPRESSED_WIRE
                    if transport_encoding is TransportEncodingV8.IDENTITY
                    else OverflowBoundaryV8.COMPRESSED_WIRE
                )
                overflow = _overflow_failure_v8(state, boundary=boundary)
                return finish_result(overflow, response_reusable=False)

            if len(source_data) > AUTHORITY_INPUT_READ_QUANTUM_V8:
                failure = _prefix_failure_v8(
                    state,
                    phase=AuthorityInputPhaseV8.WIRE_READ,
                    reason=AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION,
                )
                return finish_result(failure, response_reusable=False)
            if transport_encoding is TransportEncodingV8.IDENTITY:
                bytes_before_identity_overflow = min(
                    len(source_data),
                    AUTHORITY_INPUT_BYTE_LIMIT_V8 - previous_wire_length,
                )
                bounded_identity = source_data[:bytes_before_identity_overflow]
                identity_cursor = 0
                while identity_cursor < len(bounded_identity):
                    content_checkpoint = _content_checkpoint_v8(
                        state,
                        clock=actual_clock,
                        cancellation_token=actual_token,
                        operation_deadline=operation_deadline,
                    )
                    if content_checkpoint is not None:
                        return finish_result(
                            content_checkpoint,
                            response_reusable=False,
                        )
                    content_offset = state.content_quantum_offset
                    content_remaining = AUTHORITY_INPUT_READ_QUANTUM_V8 - content_offset
                    segment_end = min(
                        len(bounded_identity),
                        identity_cursor + content_remaining,
                    )
                    identity_segment = bounded_identity[identity_cursor:segment_end]
                    initial_committed = 1 if identity_cursor == 0 else 0
                    processed, identity_failure = _process_decompressed_pipeline_v8(
                        state,
                        identity_segment,
                        identity=True,
                        initial_committed=initial_committed,
                        clock=actual_clock,
                        cancellation_token=actual_token,
                        operation_deadline=operation_deadline,
                    )
                    _advance_content_quantum_v8(state, processed)
                    if identity_failure is not None:
                        return finish_result(
                            identity_failure,
                            response_reusable=False,
                        )
                    identity_cursor = segment_end
                if len(source_data) > bytes_before_identity_overflow:
                    witness = source_data[
                        bytes_before_identity_overflow : bytes_before_identity_overflow + 1
                    ]
                    state.accept_wire(witness)
                    state.accept_decompressed(witness)
                    overflow = _overflow_failure_v8(
                        state,
                        boundary=OverflowBoundaryV8.UNCOMPRESSED_WIRE,
                    )
                    return finish_result(overflow, response_reusable=False)
                continue

            if decoder is None:
                raise AssertionError("GZIP input requires an initialized decoder")
            bytes_before_compressed_overflow = min(
                len(source_data),
                AUTHORITY_INPUT_BYTE_LIMIT_V8 - previous_wire_length,
            )
            bounded_compressed = source_data[:bytes_before_compressed_overflow]
            pending_compressed = bounded_compressed
            preaccepted_wire_bytes = 1
            replayed_pending_prefix = 0
            while pending_compressed:
                content_checkpoint = _content_checkpoint_v8(
                    state,
                    clock=actual_clock,
                    cancellation_token=actual_token,
                    operation_deadline=operation_deadline,
                )
                if content_checkpoint is not None:
                    return finish_result(
                        content_checkpoint,
                        response_reusable=False,
                    )
                content_remaining = AUTHORITY_INPUT_READ_QUANTUM_V8 - state.content_quantum_offset
                compressed_segment = pending_compressed[:content_remaining]
                remaining_after_segment = pending_compressed[content_remaining:]
                _append_gzip_replay_window_v8(
                    gzip_quantum_wire,
                    compressed_segment[replayed_pending_prefix:],
                )
                pipeline_offset = state.pipeline_quantum_offset
                maximum_output_bytes = AUTHORITY_INPUT_READ_QUANTUM_V8 - pipeline_offset
                (
                    output,
                    unconsumed,
                    preaccepted_wire_bytes,
                    _decoder_copy,
                    consumed_compressed,
                    gzip_failure,
                ) = _decode_gzip_quantum_v8(
                    state,
                    decoder,
                    compressed_segment,
                    maximum_output_bytes=maximum_output_bytes,
                    preaccepted_wire_bytes=preaccepted_wire_bytes,
                    clock=actual_clock,
                    cancellation_token=actual_token,
                    operation_deadline=operation_deadline,
                )
                if gzip_failure is not None:
                    termination = gzip_failure.termination
                    output_terminal = (
                        termination is not None
                        and termination.reason in _OUTPUT_TERMINATION_REASONS
                    )
                    decompressed_overflow = (
                        type(gzip_failure.observation) is OverflowPrefixObservationV8
                        and gzip_failure.observation.exceeded_boundary
                        is OverflowBoundaryV8.DECOMPRESSED
                    )
                    if output_terminal or decompressed_overflow:
                        restore_gzip_output_witness_wire()
                        if termination is not None:
                            gzip_failure = _prefix_failure_v8(
                                state,
                                phase=termination.phase,
                                reason=termination.reason,
                            )
                        else:
                            gzip_failure = _overflow_failure_v8(
                                state,
                                boundary=OverflowBoundaryV8.DECOMPRESSED,
                            )
                    return finish_result(gzip_failure, response_reusable=False)
                _advance_content_quantum_v8(state, consumed_compressed)
                if output:
                    processed_output, scanner_failure = _process_decompressed_pipeline_v8(
                        state,
                        output,
                        identity=False,
                        initial_committed=0,
                        clock=actual_clock,
                        cancellation_token=actual_token,
                        operation_deadline=operation_deadline,
                    )
                    if scanner_failure is not None:
                        if processed_output:
                            restore_gzip_output_witness_wire()
                            termination = scanner_failure.termination
                            if termination is None:
                                raise AssertionError(
                                    "scanner failure requires a termination identifier"
                                )
                            scanner_failure = _prefix_failure_v8(
                                state,
                                phase=termination.phase,
                                reason=termination.reason,
                            )
                        return finish_result(
                            scanner_failure,
                            response_reusable=False,
                        )
                while not unconsumed and output is not None:
                    pipeline_offset = state.pipeline_quantum_offset
                    maximum_output_bytes = AUTHORITY_INPUT_READ_QUANTUM_V8 - pipeline_offset
                    remaining_output_bytes = (
                        AUTHORITY_INPUT_BYTE_LIMIT_V8 - state.decompressed_length
                    )
                    try:
                        output = decoder.decompress(
                            b"",
                            max_length=min(
                                maximum_output_bytes,
                                remaining_output_bytes + 1,
                            ),
                        )
                    except zlib.error:
                        failure = _prefix_failure_v8(
                            state,
                            phase=AuthorityInputPhaseV8.CONTENT_DECODE,
                            reason=AuthorityInputTerminationReasonV8.DECOMPRESSION_FAILED,
                        )
                        return finish_result(failure, response_reusable=False)
                    if len(output) == remaining_output_bytes + 1:
                        if remaining_output_bytes:
                            processed_output, scanner_failure = _process_decompressed_pipeline_v8(
                                state,
                                output[:remaining_output_bytes],
                                identity=False,
                                initial_committed=0,
                                clock=actual_clock,
                                cancellation_token=actual_token,
                                operation_deadline=operation_deadline,
                            )
                            if scanner_failure is not None:
                                restore_gzip_output_witness_wire()
                                termination = scanner_failure.termination
                                if termination is None:
                                    raise AssertionError(
                                        "scanner failure requires a termination identifier"
                                    )
                                scanner_failure = _prefix_failure_v8(
                                    state,
                                    phase=termination.phase,
                                    reason=termination.reason,
                                )
                                return finish_result(
                                    scanner_failure,
                                    response_reusable=False,
                                )
                        state.accept_decompressed(output[remaining_output_bytes:])
                        restore_gzip_output_witness_wire()
                        overflow = _overflow_failure_v8(
                            state,
                            boundary=OverflowBoundaryV8.DECOMPRESSED,
                        )
                        return finish_result(overflow, response_reusable=False)
                    if not output:
                        break
                    processed_output, scanner_failure = _process_decompressed_pipeline_v8(
                        state,
                        output,
                        identity=False,
                        initial_committed=0,
                        clock=actual_clock,
                        cancellation_token=actual_token,
                        operation_deadline=operation_deadline,
                    )
                    if scanner_failure is not None:
                        restore_gzip_output_witness_wire()
                        termination = scanner_failure.termination
                        if termination is None:
                            raise AssertionError(
                                "scanner failure requires a termination identifier"
                            )
                        scanner_failure = _prefix_failure_v8(
                            state,
                            phase=termination.phase,
                            reason=termination.reason,
                        )
                        return finish_result(
                            scanner_failure,
                            response_reusable=False,
                        )
                if len(unconsumed) == len(compressed_segment) and not output:
                    failure = _prefix_failure_v8(
                        state,
                        phase=AuthorityInputPhaseV8.CONTENT_DECODE,
                        reason=AuthorityInputTerminationReasonV8.DECOMPRESSION_FAILED,
                    )
                    return finish_result(failure, response_reusable=False)
                if consumed_compressed and state.content_quantum_offset == 0:
                    gzip_quantum_decompressed_start = state.decompressed_length
                    gzip_quantum_decoder_copy = decoder.copy()
                    gzip_quantum_wire_snapshot = state.wire_snapshot()
                    gzip_quantum_wire.clear()
                    replayed_pending_prefix = 0
                else:
                    replayed_pending_prefix = len(unconsumed)
                pending_compressed = unconsumed + remaining_after_segment
            if len(source_data) > bytes_before_compressed_overflow:
                witness = source_data[
                    bytes_before_compressed_overflow : bytes_before_compressed_overflow + 1
                ]
                state.accept_wire(witness)
                overflow = _overflow_failure_v8(
                    state,
                    boundary=OverflowBoundaryV8.COMPRESSED_WIRE,
                )
                return finish_result(overflow, response_reusable=False)
    except BaseException:
        if not lifecycle.finished:
            lifecycle.finish(reusable=False)
        raise


read_bounded_authority_json_v8 = read_bounded_authority_input_v8


__all__ = [
    "AUTHORITY_INPUT_MAX_AGGREGATE_SCALAR_BYTES_V8",
    "AUTHORITY_INPUT_MAX_CONTAINER_ITEMS_V8",
    "AUTHORITY_INPUT_MAX_DEPTH_V8",
    "AUTHORITY_INPUT_MAX_NODES_V8",
    "AUTHORITY_INPUT_MAX_SCALAR_BYTES_V8",
    "AUTHORITY_INPUT_READ_QUANTUM_V8",
    "HTTP11_MAX_AGGREGATE_HEADER_BYTES_V8",
    "HTTP11_MAX_CHUNK_FRAMING_BYTES_V8",
    "HTTP11_MAX_CHUNK_SIZE_LINE_BYTES_V8",
    "HTTP11_MAX_HEADER_BLOCK_BYTES_V8",
    "HTTP11_MAX_HEADER_FIELDS_V8",
    "HTTP11_MAX_HEADER_NAME_BYTES_V8",
    "HTTP11_MAX_HEADER_VALUE_BYTES_V8",
    "HTTP11_MAX_IMMUTABLE_RESPONSE_BYTES_V8",
    "HTTP11_MAX_NONZERO_CHUNKS_V8",
    "HTTP11_MAX_STATUS_LINE_BYTES_V8",
    "AdmittedHttp11AuthorityInputV8",
    "AuthorityInputCancellationTokenV8",
    "AuthorityInputClockV8",
    "AuthorityInputGateResultV8",
    "AuthorityInputSourceOutcomeV8",
    "AuthorityInputSourceV8",
    "AuthorityInputTerminationV8",
    "BoundedAuthorityInputFailureV8",
    "BoundedAuthorityInputResultV8",
    "BoundedAuthorityInputSuccessV8",
    "BoundedJsonDocumentV8",
    "CancellationTokenV8",
    "Http11AuthorityInputSourceV8",
    "InProcessAuthorityInputSourceV8",
    "MonotonicAuthorityInputClockV8",
    "NeverCancelledAuthorityInputTokenV8",
    "SourceDataV8",
    "SourceDisconnectedV8",
    "SourceEofV8",
    "SourceFramingFailureV8",
    "TrustedClockV8",
    "admit_http11_authority_input_v8",
    "read_bounded_authority_input_v8",
    "read_bounded_authority_json_v8",
]
