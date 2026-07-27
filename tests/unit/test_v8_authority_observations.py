from __future__ import annotations

import gzip
import hashlib
from typing import Any, Literal

import pytest
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
    validate_authority_input_observation_v8,
)
from pydantic import TypeAdapter, ValidationError


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


EMPTY_DIGEST = _digest_bytes(b"")
WIRE_DIGEST = _digest_bytes(b"wire-prefix")
DECOMPRESSED_DIGEST = _digest_bytes(b"decompressed-prefix")


class _IntegerSubclass(int):
    pass


def _complete_payload(
    *,
    encoding: TransportEncodingV8 = TransportEncodingV8.IDENTITY,
    wire_length: int = 1,
    decompressed_length: int | None = None,
) -> dict[str, Any]:
    if decompressed_length is None:
        decompressed_length = wire_length if encoding is TransportEncodingV8.IDENTITY else 0
    wire_digest = EMPTY_DIGEST if wire_length == 0 else WIRE_DIGEST
    decompressed_digest = (
        wire_digest
        if encoding is TransportEncodingV8.IDENTITY
        else EMPTY_DIGEST
        if decompressed_length == 0
        else DECOMPRESSED_DIGEST
    )
    return {
        "kind": "COMPLETE_BOUNDED_RESPONSE",
        "transport_encoding": encoding,
        "complete_wire_digest": wire_digest,
        "complete_wire_length": wire_length,
        "complete_decompressed_digest": decompressed_digest,
        "complete_decompressed_length": decompressed_length,
    }


def _incomplete_payload(
    *,
    encoding: TransportEncodingV8 = TransportEncodingV8.IDENTITY,
    phase: AuthorityInputPhaseV8 = AuthorityInputPhaseV8.WIRE_READ,
    reason: AuthorityInputTerminationReasonV8 = (AuthorityInputTerminationReasonV8.DISCONNECTED),
    wire_length: int = 1,
    decompressed_length: int | None = None,
) -> dict[str, Any]:
    if decompressed_length is None:
        decompressed_length = wire_length if encoding is TransportEncodingV8.IDENTITY else 0
    wire_digest = WIRE_DIGEST
    decompressed_digest = (
        wire_digest
        if encoding is TransportEncodingV8.IDENTITY
        else EMPTY_DIGEST
        if decompressed_length == 0
        else DECOMPRESSED_DIGEST
    )
    return {
        "kind": "INCOMPLETE_BOUNDED_RESPONSE",
        "termination_phase": phase,
        "termination_reason": reason,
        "transport_encoding": encoding,
        "observed_wire_prefix_digest": wire_digest,
        "observed_wire_prefix_length": wire_length,
        "observed_decompressed_prefix_digest": decompressed_digest,
        "observed_decompressed_prefix_length": decompressed_length,
    }


def _overflow_payload(
    *,
    encoding: TransportEncodingV8 = TransportEncodingV8.IDENTITY,
    boundary: OverflowBoundaryV8 = OverflowBoundaryV8.UNCOMPRESSED_WIRE,
) -> dict[str, Any]:
    if encoding is TransportEncodingV8.IDENTITY:
        wire_length = AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
        decompressed_length = AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
        decompressed_digest = WIRE_DIGEST
    elif boundary is OverflowBoundaryV8.COMPRESSED_WIRE:
        wire_length = AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
        decompressed_length = AUTHORITY_INPUT_BYTE_LIMIT_V8
        decompressed_digest = DECOMPRESSED_DIGEST
    else:
        wire_length = AUTHORITY_INPUT_BYTE_LIMIT_V8
        decompressed_length = AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
        decompressed_digest = DECOMPRESSED_DIGEST
    return {
        "kind": "OVERFLOW_PREFIX",
        "transport_encoding": encoding,
        "observed_wire_prefix_digest": WIRE_DIGEST,
        "observed_wire_prefix_length": wire_length,
        "observed_decompressed_prefix_digest": decompressed_digest,
        "observed_decompressed_prefix_length": decompressed_length,
        "exceeded_boundary": boundary,
        "configured_limit": AUTHORITY_INPUT_BYTE_LIMIT_V8,
        "first_excess_observed_count": AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8,
    }


VALID_VARIANT_PAYLOADS = (
    {
        "kind": "NO_RESPONSE",
        "failure_phase": AuthorityInputPhaseV8.WIRE_READ,
    },
    _complete_payload(),
    _incomplete_payload(),
    _overflow_payload(),
)


def test_closed_enums_have_exact_frozen_values() -> None:
    assert tuple(TransportEncodingV8) == (
        TransportEncodingV8.IDENTITY,
        TransportEncodingV8.GZIP,
    )
    assert {item.value for item in AuthorityInputPhaseV8} == {
        "BEFORE_RESPONSE",
        "WIRE_READ",
        "CONTENT_DECODE",
        "UTF8_DECODE",
        "JSON_SCAN",
        "RESPONSE_FINALIZE",
    }
    assert {item.value for item in AuthorityInputTerminationReasonV8} == {
        "DISCONNECTED",
        "DEADLINE_EXCEEDED",
        "CANCELLED",
        "SOURCE_PROTOCOL_VIOLATION",
        "CONTROL_SIGNAL_FAILURE",
        "TRANSFER_FRAMING_FAILED",
        "DECOMPRESSION_FAILED",
        "TRUNCATED_COMPRESSED_STREAM",
        "TRAILING_COMPRESSED_DATA",
        "INVALID_UTF8",
        "INVALID_JSON",
        "ROOT_NOT_OBJECT",
        "DUPLICATE_OBJECT_KEY",
        "LONE_SURROGATE",
        "NONCANONICAL_NUMBER",
        "DEPTH_LIMIT_EXCEEDED",
        "NODE_LIMIT_EXCEEDED",
        "CONTAINER_LIMIT_EXCEEDED",
        "SCALAR_LIMIT_EXCEEDED",
        "AGGREGATE_SCALAR_LIMIT_EXCEEDED",
    }
    assert {item.value for item in OverflowBoundaryV8} == {
        "UNCOMPRESSED_WIRE",
        "COMPRESSED_WIRE",
        "DECOMPRESSED",
    }
    assert "DEPTH_LIMIT_EXCEEDED" not in OverflowBoundaryV8.__members__


@pytest.mark.parametrize("payload", VALID_VARIANT_PAYLOADS)
def test_observation_union_accepts_each_exact_variant(payload: dict[str, Any]) -> None:
    adapter: TypeAdapter[AuthorityInputObservationV8] = TypeAdapter(AuthorityInputObservationV8)
    restored = adapter.validate_python(payload)
    safely_restored = validate_authority_input_observation_v8(payload)

    assert restored == safely_restored
    assert safely_restored.model_dump(mode="python") == payload


@pytest.mark.parametrize("payload", VALID_VARIANT_PAYLOADS)
def test_observation_union_restores_from_json(payload: dict[str, Any]) -> None:
    observation = validate_authority_input_observation_v8(payload)
    adapter: TypeAdapter[AuthorityInputObservationV8] = TypeAdapter(AuthorityInputObservationV8)

    assert adapter.validate_json(observation.model_dump_json()) == observation


@pytest.mark.parametrize("payload", VALID_VARIANT_PAYLOADS)
def test_each_observation_variant_requires_all_its_canonical_fields(
    payload: dict[str, Any],
) -> None:
    for field_name in payload:
        if field_name in {"configured_limit", "first_excess_observed_count"}:
            continue
        missing = dict(payload)
        missing.pop(field_name)
        with pytest.raises((ValidationError, ValueError)):
            validate_authority_input_observation_v8(missing)


def test_each_observation_variant_rejects_every_foreign_field() -> None:
    all_fields: dict[str, object] = {}
    for payload in VALID_VARIANT_PAYLOADS:
        all_fields.update(payload)

    for payload in VALID_VARIANT_PAYLOADS:
        for field_name, value in all_fields.items():
            if field_name == "kind" or field_name in payload:
                continue
            with pytest.raises((ValidationError, ValueError)):
                validate_authority_input_observation_v8({**payload, field_name: value})


def test_observation_union_rejects_unknown_or_wrong_discriminators() -> None:
    for kind in ("", "COMPLETE", "overflow_prefix", 1, None):
        with pytest.raises((ValidationError, ValueError)):
            validate_authority_input_observation_v8({"kind": kind})
    with pytest.raises((ValidationError, ValueError)):
        validate_authority_input_observation_v8({})


def test_observation_union_preflights_kind_before_discriminator_callbacks() -> None:
    class CallbackString(str):
        calls = 0

        def __hash__(self) -> int:
            type(self).calls += 1
            return super().__hash__()

        def __eq__(self, other: object) -> bool:
            type(self).calls += 1
            return super().__eq__(other)

    adapter: TypeAdapter[AuthorityInputObservationV8] = TypeAdapter(AuthorityInputObservationV8)
    payload = {
        "kind": CallbackString("NO_RESPONSE"),
        "failure_phase": AuthorityInputPhaseV8.WIRE_READ,
    }
    CallbackString.calls = 0

    with pytest.raises(ValidationError, match="built-in str"):
        adapter.validate_python(payload)
    assert CallbackString.calls == 0

    with pytest.raises(ValidationError, match="raw text bound"):
        adapter.validate_python({**payload, "kind": "N" * 65})


def test_observation_union_inspects_exact_model_storage_before_discriminator_lookup() -> None:
    class CallbackStringKey(str):
        calls = 0

        def __hash__(self) -> int:
            type(self).calls += 1
            return super().__hash__()

        def __eq__(self, other: object) -> bool:
            type(self).calls += 1
            return super().__eq__(other)

    poisoned = NoResponseObservationV8(failure_phase=AuthorityInputPhaseV8.WIRE_READ).model_copy()
    stored_fields = object.__getattribute__(poisoned, "__dict__")
    kind = stored_fields.pop("kind")
    stored_fields[CallbackStringKey("kind")] = kind
    CallbackStringKey.calls = 0

    with pytest.raises(ValidationError):
        TypeAdapter(AuthorityInputObservationV8).validate_python(poisoned)
    assert CallbackStringKey.calls == 0


_NO_RESPONSE_ALLOWED: dict[
    AuthorityInputPhaseV8,
    frozenset[AuthorityInputTerminationReasonV8],
] = {
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
    AuthorityInputPhaseV8.RESPONSE_FINALIZE: frozenset(
        {AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM}
    ),
}


@pytest.mark.parametrize("phase", tuple(AuthorityInputPhaseV8))
@pytest.mark.parametrize("reason", tuple(AuthorityInputTerminationReasonV8))
@pytest.mark.parametrize("encoding", tuple(TransportEncodingV8))
def test_no_response_factory_enforces_full_phase_reason_encoding_matrix(
    phase: AuthorityInputPhaseV8,
    reason: AuthorityInputTerminationReasonV8,
    encoding: TransportEncodingV8,
) -> None:
    should_pass = reason in _NO_RESPONSE_ALLOWED.get(phase, frozenset()) and (
        phase is not AuthorityInputPhaseV8.RESPONSE_FINALIZE or encoding is TransportEncodingV8.GZIP
    )

    def factory() -> NoResponseObservationV8:
        return NoResponseObservationV8.from_termination(
            failure_phase=phase,
            termination_reason=reason,
            transport_encoding=encoding,
            observed_wire_prefix_length=0,
            observed_decompressed_prefix_length=0,
        )

    if should_pass:
        observation = factory()
        assert observation.failure_phase is phase
        assert set(observation.model_dump()) == {"kind", "failure_phase"}
    else:
        with pytest.raises(ValueError, match=r"NO_RESPONSE|requires declared GZIP"):
            factory()


def test_empty_gzip_finalize_is_the_only_later_phase_no_response_case() -> None:
    observation = NoResponseObservationV8.from_termination(
        failure_phase=AuthorityInputPhaseV8.RESPONSE_FINALIZE,
        termination_reason=AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM,
        transport_encoding=TransportEncodingV8.GZIP,
        observed_wire_prefix_length=0,
        observed_decompressed_prefix_length=0,
    )
    assert observation == NoResponseObservationV8(
        failure_phase=AuthorityInputPhaseV8.RESPONSE_FINALIZE
    )

    for invalid_phase in (
        AuthorityInputPhaseV8.CONTENT_DECODE,
        AuthorityInputPhaseV8.UTF8_DECODE,
        AuthorityInputPhaseV8.JSON_SCAN,
    ):
        with pytest.raises(ValidationError):
            NoResponseObservationV8(failure_phase=invalid_phase)


@pytest.mark.parametrize(
    "field_name",
    ["observed_wire_prefix_length", "observed_decompressed_prefix_length"],
)
@pytest.mark.parametrize("bad_value", [True, 0.0, "0", _IntegerSubclass(0)])
def test_no_response_factory_rejects_coercive_or_nonzero_counters(
    field_name: str,
    bad_value: object,
) -> None:
    values: dict[str, object] = {
        "failure_phase": AuthorityInputPhaseV8.WIRE_READ,
        "termination_reason": AuthorityInputTerminationReasonV8.DISCONNECTED,
        "transport_encoding": TransportEncodingV8.IDENTITY,
        "observed_wire_prefix_length": 0,
        "observed_decompressed_prefix_length": 0,
    }
    values[field_name] = bad_value
    with pytest.raises(ValueError, match="exact built-in integers"):
        NoResponseObservationV8.from_termination(**values)  # type: ignore[arg-type]

    values[field_name] = 1
    with pytest.raises(ValueError, match="both accepted byte counters"):
        NoResponseObservationV8.from_termination(**values)  # type: ignore[arg-type]


def test_no_response_factory_rejects_polymorphic_contract_subclass() -> None:
    class ExtendedNoResponse(NoResponseObservationV8):
        kind: Literal["EVIL"] = "EVIL"

    with pytest.raises(TypeError, match="cannot construct a contract subclass"):
        ExtendedNoResponse.from_termination(
            failure_phase=AuthorityInputPhaseV8.WIRE_READ,
            termination_reason=AuthorityInputTerminationReasonV8.DISCONNECTED,
            transport_encoding=TransportEncodingV8.IDENTITY,
            observed_wire_prefix_length=0,
            observed_decompressed_prefix_length=0,
        )


def test_observation_restore_rejects_unsigned_exact_model_storage() -> None:
    valid = NoResponseObservationV8(failure_phase=AuthorityInputPhaseV8.WIRE_READ)
    poisoned = valid.model_copy(update={"unsigned_policy": "allow"})

    with pytest.raises(ValueError, match="unsupported stored field"):
        NoResponseObservationV8.model_validate(poisoned)
    with pytest.raises(ValueError, match="unsupported stored field"):
        validate_authority_input_observation_v8(poisoned)


@pytest.mark.parametrize(
    ("storage_attribute", "poisoned_value"),
    [
        ("__pydantic_fields_set__", {"kind", "failure_phase", "unsigned_policy"}),
        ("__pydantic_extra__", {"unsigned_policy": "allow"}),
        ("__pydantic_private__", {"_unsigned_policy": "allow"}),
    ],
)
def test_observation_type_adapter_rejects_hidden_exact_model_storage(
    storage_attribute: str,
    poisoned_value: object,
) -> None:
    poisoned = NoResponseObservationV8(failure_phase=AuthorityInputPhaseV8.WIRE_READ).model_copy()
    object.__setattr__(poisoned, storage_attribute, poisoned_value)

    with pytest.raises(ValidationError, match="unsupported model state"):
        TypeAdapter(NoResponseObservationV8).validate_python(poisoned)
    with pytest.raises(ValidationError, match="unsupported model state"):
        TypeAdapter(AuthorityInputObservationV8).validate_python(poisoned)
    with pytest.raises(ValueError, match="unsupported model state"):
        validate_authority_input_observation_v8(poisoned)


def test_empty_clean_identity_eof_is_complete_not_no_response() -> None:
    observation = CompleteBoundedResponseObservationV8(
        transport_encoding=TransportEncodingV8.IDENTITY,
        complete_wire_digest=EMPTY_DIGEST,
        complete_wire_length=0,
        complete_decompressed_digest=EMPTY_DIGEST,
        complete_decompressed_length=0,
    )
    assert observation.kind == "COMPLETE_BOUNDED_RESPONSE"


@pytest.mark.parametrize("length", [0, 1, AUTHORITY_INPUT_BYTE_LIMIT_V8])
def test_complete_identity_accepts_exact_boundary_and_repeats_pair(length: int) -> None:
    observation = CompleteBoundedResponseObservationV8.model_validate(
        _complete_payload(wire_length=length)
    )
    assert observation.complete_wire_length == length
    assert observation.complete_decompressed_length == length


def test_complete_identity_rejects_pair_mismatch_and_limit_excess() -> None:
    for mutation in (
        {"complete_decompressed_length": 2},
        {"complete_decompressed_digest": DECOMPRESSED_DIGEST},
        {"complete_wire_length": AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8},
        {"complete_decompressed_length": AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8},
    ):
        with pytest.raises(ValidationError):
            CompleteBoundedResponseObservationV8.model_validate({**_complete_payload(), **mutation})


@pytest.mark.parametrize(
    ("wire_length", "decompressed_length"),
    [
        (20, 0),
        (20, AUTHORITY_INPUT_BYTE_LIMIT_V8),
        (AUTHORITY_INPUT_BYTE_LIMIT_V8, 0),
        (AUTHORITY_INPUT_BYTE_LIMIT_V8, AUTHORITY_INPUT_BYTE_LIMIT_V8),
    ],
)
def test_complete_gzip_accepts_exact_length_domain(
    wire_length: int,
    decompressed_length: int,
) -> None:
    observation = CompleteBoundedResponseObservationV8.model_validate(
        _complete_payload(
            encoding=TransportEncodingV8.GZIP,
            wire_length=wire_length,
            decompressed_length=decompressed_length,
        )
    )
    assert observation.transport_encoding is TransportEncodingV8.GZIP


@pytest.mark.parametrize(
    ("wire_length", "decompressed_length"),
    [
        (0, 0),
        (19, 0),
        (AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8, 0),
        (20, AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8),
    ],
)
def test_complete_gzip_rejects_every_length_outside_domain(
    wire_length: int,
    decompressed_length: int,
) -> None:
    with pytest.raises(ValidationError):
        CompleteBoundedResponseObservationV8.model_validate(
            _complete_payload(
                encoding=TransportEncodingV8.GZIP,
                wire_length=wire_length,
                decompressed_length=decompressed_length,
            )
        )


def test_valid_empty_gzip_member_is_complete_transport() -> None:
    wire = gzip.compress(b"", mtime=0)
    assert len(wire) == 20
    observation = CompleteBoundedResponseObservationV8(
        transport_encoding=TransportEncodingV8.GZIP,
        complete_wire_digest=_digest_bytes(wire),
        complete_wire_length=len(wire),
        complete_decompressed_digest=EMPTY_DIGEST,
        complete_decompressed_length=0,
    )
    assert observation.kind == "COMPLETE_BOUNDED_RESPONSE"


def test_every_zero_length_digest_is_the_literal_empty_sha256() -> None:
    complete_identity = _complete_payload(wire_length=0)
    complete_identity["complete_wire_digest"] = WIRE_DIGEST
    complete_identity["complete_decompressed_digest"] = WIRE_DIGEST
    with pytest.raises(ValidationError, match="zero-length complete wire"):
        CompleteBoundedResponseObservationV8.model_validate(complete_identity)

    complete_gzip = _complete_payload(
        encoding=TransportEncodingV8.GZIP,
        wire_length=20,
        decompressed_length=0,
    )
    complete_gzip["complete_decompressed_digest"] = DECOMPRESSED_DIGEST
    with pytest.raises(ValidationError, match="zero-length complete decompressed"):
        CompleteBoundedResponseObservationV8.model_validate(complete_gzip)

    incomplete_gzip = _incomplete_payload(
        encoding=TransportEncodingV8.GZIP,
        decompressed_length=0,
    )
    incomplete_gzip["observed_decompressed_prefix_digest"] = DECOMPRESSED_DIGEST
    with pytest.raises(ValidationError, match="zero-length decompressed prefix"):
        IncompleteBoundedResponseObservationV8.model_validate(incomplete_gzip)

    overflow_gzip = _overflow_payload(
        encoding=TransportEncodingV8.GZIP,
        boundary=OverflowBoundaryV8.COMPRESSED_WIRE,
    )
    overflow_gzip["observed_decompressed_prefix_length"] = 0
    overflow_gzip["observed_decompressed_prefix_digest"] = DECOMPRESSED_DIGEST
    with pytest.raises(ValidationError, match="zero-length decompressed overflow"):
        OverflowPrefixObservationV8.model_validate(overflow_gzip)


_INCOMPLETE_ALLOWED: dict[
    AuthorityInputPhaseV8,
    frozenset[AuthorityInputTerminationReasonV8],
] = {
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
_GZIP_ONLY = {
    AuthorityInputTerminationReasonV8.DECOMPRESSION_FAILED,
    AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM,
    AuthorityInputTerminationReasonV8.TRAILING_COMPRESSED_DATA,
}


@pytest.mark.parametrize("phase", tuple(AuthorityInputPhaseV8))
@pytest.mark.parametrize("reason", tuple(AuthorityInputTerminationReasonV8))
@pytest.mark.parametrize("encoding", tuple(TransportEncodingV8))
def test_incomplete_observation_enforces_full_phase_reason_encoding_matrix(
    phase: AuthorityInputPhaseV8,
    reason: AuthorityInputTerminationReasonV8,
    encoding: TransportEncodingV8,
) -> None:
    should_pass = reason in _INCOMPLETE_ALLOWED.get(phase, frozenset()) and (
        encoding is TransportEncodingV8.GZIP or reason not in _GZIP_ONLY
    )
    payload = _incomplete_payload(encoding=encoding, phase=phase, reason=reason)

    if should_pass:
        observation = IncompleteBoundedResponseObservationV8.model_validate(payload)
        assert observation.termination_phase is phase
        assert observation.termination_reason is reason
    else:
        with pytest.raises(ValidationError):
            IncompleteBoundedResponseObservationV8.model_validate(payload)


@pytest.mark.parametrize("length", [1, AUTHORITY_INPUT_BYTE_LIMIT_V8])
def test_incomplete_identity_accepts_exact_length_domain(length: int) -> None:
    observation = IncompleteBoundedResponseObservationV8.model_validate(
        _incomplete_payload(wire_length=length)
    )
    assert observation.observed_wire_prefix_length == length
    assert observation.observed_decompressed_prefix_length == length


def test_incomplete_identity_rejects_zero_excess_and_pair_mismatch() -> None:
    for mutation in (
        {"observed_wire_prefix_length": 0, "observed_decompressed_prefix_length": 0},
        {"observed_decompressed_prefix_length": 2},
        {"observed_decompressed_prefix_digest": DECOMPRESSED_DIGEST},
        {"observed_wire_prefix_length": AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8},
        {"observed_decompressed_prefix_length": AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8},
    ):
        with pytest.raises(ValidationError):
            IncompleteBoundedResponseObservationV8.model_validate(
                {**_incomplete_payload(), **mutation}
            )


@pytest.mark.parametrize("wire_length", [1, AUTHORITY_INPUT_BYTE_LIMIT_V8])
@pytest.mark.parametrize("decompressed_length", [0, AUTHORITY_INPUT_BYTE_LIMIT_V8])
def test_incomplete_gzip_accepts_exact_length_domain(
    wire_length: int,
    decompressed_length: int,
) -> None:
    observation = IncompleteBoundedResponseObservationV8.model_validate(
        _incomplete_payload(
            encoding=TransportEncodingV8.GZIP,
            wire_length=wire_length,
            decompressed_length=decompressed_length,
        )
    )
    assert observation.transport_encoding is TransportEncodingV8.GZIP


def test_one_gzip_byte_then_eof_is_incomplete_truncation() -> None:
    wire = b"\x1f"
    observation = IncompleteBoundedResponseObservationV8(
        termination_phase=AuthorityInputPhaseV8.RESPONSE_FINALIZE,
        termination_reason=AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM,
        transport_encoding=TransportEncodingV8.GZIP,
        observed_wire_prefix_digest=_digest_bytes(wire),
        observed_wire_prefix_length=1,
        observed_decompressed_prefix_digest=EMPTY_DIGEST,
        observed_decompressed_prefix_length=0,
    )
    assert observation.kind == "INCOMPLETE_BOUNDED_RESPONSE"


@pytest.mark.parametrize(
    ("encoding", "boundary", "should_pass"),
    [
        (TransportEncodingV8.IDENTITY, OverflowBoundaryV8.UNCOMPRESSED_WIRE, True),
        (TransportEncodingV8.IDENTITY, OverflowBoundaryV8.COMPRESSED_WIRE, False),
        (TransportEncodingV8.IDENTITY, OverflowBoundaryV8.DECOMPRESSED, False),
        (TransportEncodingV8.GZIP, OverflowBoundaryV8.UNCOMPRESSED_WIRE, False),
        (TransportEncodingV8.GZIP, OverflowBoundaryV8.COMPRESSED_WIRE, True),
        (TransportEncodingV8.GZIP, OverflowBoundaryV8.DECOMPRESSED, True),
    ],
)
def test_overflow_encoding_boundary_cartesian_matrix(
    encoding: TransportEncodingV8,
    boundary: OverflowBoundaryV8,
    should_pass: bool,
) -> None:
    payload = _overflow_payload(encoding=encoding, boundary=boundary)
    if should_pass:
        observation = OverflowPrefixObservationV8.model_validate(payload)
        assert observation.exceeded_boundary is boundary
    else:
        with pytest.raises(ValidationError):
            OverflowPrefixObservationV8.model_validate(payload)


def test_overflow_length_shapes_include_exact_first_witness() -> None:
    identity = OverflowPrefixObservationV8.model_validate(_overflow_payload())
    assert identity.observed_wire_prefix_length == AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
    assert identity.observed_decompressed_prefix_length == AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
    assert identity.observed_wire_prefix_digest == identity.observed_decompressed_prefix_digest

    compressed = OverflowPrefixObservationV8.model_validate(
        _overflow_payload(
            encoding=TransportEncodingV8.GZIP,
            boundary=OverflowBoundaryV8.COMPRESSED_WIRE,
        )
    )
    assert compressed.observed_wire_prefix_length == AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
    assert compressed.observed_decompressed_prefix_length <= AUTHORITY_INPUT_BYTE_LIMIT_V8

    decompressed = OverflowPrefixObservationV8.model_validate(
        _overflow_payload(
            encoding=TransportEncodingV8.GZIP,
            boundary=OverflowBoundaryV8.DECOMPRESSED,
        )
    )
    assert decompressed.observed_wire_prefix_length <= AUTHORITY_INPUT_BYTE_LIMIT_V8
    assert decompressed.observed_decompressed_prefix_length == AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8


def test_overflow_rejects_every_nearby_wrong_length_shape() -> None:
    cases = (
        {
            **_overflow_payload(),
            "observed_wire_prefix_length": AUTHORITY_INPUT_BYTE_LIMIT_V8,
        },
        {
            **_overflow_payload(),
            "observed_decompressed_prefix_length": AUTHORITY_INPUT_BYTE_LIMIT_V8,
        },
        {
            **_overflow_payload(
                encoding=TransportEncodingV8.GZIP,
                boundary=OverflowBoundaryV8.COMPRESSED_WIRE,
            ),
            "observed_wire_prefix_length": AUTHORITY_INPUT_BYTE_LIMIT_V8,
        },
        {
            **_overflow_payload(
                encoding=TransportEncodingV8.GZIP,
                boundary=OverflowBoundaryV8.COMPRESSED_WIRE,
            ),
            "observed_decompressed_prefix_length": AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8,
        },
        {
            **_overflow_payload(
                encoding=TransportEncodingV8.GZIP,
                boundary=OverflowBoundaryV8.DECOMPRESSED,
            ),
            "observed_wire_prefix_length": AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8,
        },
        {
            **_overflow_payload(
                encoding=TransportEncodingV8.GZIP,
                boundary=OverflowBoundaryV8.DECOMPRESSED,
            ),
            "observed_decompressed_prefix_length": AUTHORITY_INPUT_BYTE_LIMIT_V8,
        },
    )
    for payload in cases:
        with pytest.raises(ValidationError):
            OverflowPrefixObservationV8.model_validate(payload)


@pytest.mark.parametrize(
    ("field_name", "expected"),
    [
        ("configured_limit", AUTHORITY_INPUT_BYTE_LIMIT_V8),
        ("first_excess_observed_count", AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8),
    ],
)
def test_overflow_fixed_counters_require_exact_builtin_constant(
    field_name: str,
    expected: int,
) -> None:
    payload = _overflow_payload()
    assert OverflowPrefixObservationV8.model_validate(payload)
    omitted = dict(payload)
    omitted.pop(field_name)
    assert OverflowPrefixObservationV8.model_validate(omitted)

    for invalid in (
        True,
        float(expected),
        str(expected),
        _IntegerSubclass(expected),
        expected - 1,
        expected + 1,
    ):
        with pytest.raises(ValidationError):
            OverflowPrefixObservationV8.model_validate({**payload, field_name: invalid})


def test_observation_schemas_publish_the_global_and_fixed_byte_bounds() -> None:
    complete_properties = CompleteBoundedResponseObservationV8.model_json_schema()["properties"]
    assert complete_properties["complete_wire_length"]["maximum"] == (AUTHORITY_INPUT_BYTE_LIMIT_V8)
    assert complete_properties["complete_decompressed_length"]["maximum"] == (
        AUTHORITY_INPUT_BYTE_LIMIT_V8
    )

    incomplete_properties = IncompleteBoundedResponseObservationV8.model_json_schema()["properties"]
    assert incomplete_properties["observed_wire_prefix_length"]["maximum"] == (
        AUTHORITY_INPUT_BYTE_LIMIT_V8
    )
    assert incomplete_properties["observed_decompressed_prefix_length"]["maximum"] == (
        AUTHORITY_INPUT_BYTE_LIMIT_V8
    )

    overflow_properties = OverflowPrefixObservationV8.model_json_schema()["properties"]
    assert overflow_properties["observed_wire_prefix_length"]["maximum"] == (
        AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
    )
    assert overflow_properties["observed_decompressed_prefix_length"]["maximum"] == (
        AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
    )
    assert {
        overflow_properties["configured_limit"]["minimum"],
        overflow_properties["configured_limit"]["maximum"],
    } == {AUTHORITY_INPUT_BYTE_LIMIT_V8}
    assert {
        overflow_properties["first_excess_observed_count"]["minimum"],
        overflow_properties["first_excess_observed_count"]["maximum"],
    } == {AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8}


@pytest.mark.parametrize(
    ("model_type", "payload", "integer_field"),
    [
        (
            CompleteBoundedResponseObservationV8,
            _complete_payload(),
            "complete_wire_length",
        ),
        (
            IncompleteBoundedResponseObservationV8,
            _incomplete_payload(),
            "observed_wire_prefix_length",
        ),
        (
            OverflowPrefixObservationV8,
            _overflow_payload(),
            "observed_wire_prefix_length",
        ),
    ],
)
@pytest.mark.parametrize("invalid", [True, 1.0, "1", _IntegerSubclass(1)])
def test_all_observation_lengths_use_exact_builtin_integer_preflight(
    model_type: type[
        CompleteBoundedResponseObservationV8
        | IncompleteBoundedResponseObservationV8
        | OverflowPrefixObservationV8
    ],
    payload: dict[str, Any],
    integer_field: str,
    invalid: object,
) -> None:
    with pytest.raises(ValidationError, match="exact built-in int"):
        model_type.model_validate({**payload, integer_field: invalid})


def test_observation_raw_preflight_rejects_mapping_and_string_subclasses() -> None:
    class DictSubclass(dict[str, object]):
        pass

    class StringSubclass(str):
        pass

    with pytest.raises(ValueError, match="built-in dict"):
        validate_authority_input_observation_v8(DictSubclass(VALID_VARIANT_PAYLOADS[0]))

    payload = _complete_payload()
    payload["complete_wire_digest"] = StringSubclass(WIRE_DIGEST)
    with pytest.raises(ValidationError, match="built-in str"):
        CompleteBoundedResponseObservationV8.model_validate(payload)


def test_model_construct_poison_is_revalidated_on_reopen_and_union_restore() -> None:
    poisoned_complete = CompleteBoundedResponseObservationV8.model_construct(
        **{
            **_complete_payload(),
            "complete_decompressed_digest": DECOMPRESSED_DIGEST,
        }
    )
    with pytest.raises(ValidationError, match="repeat its wire digest"):
        CompleteBoundedResponseObservationV8.model_validate(poisoned_complete)
    with pytest.raises(ValidationError, match="repeat its wire digest"):
        validate_authority_input_observation_v8(poisoned_complete)

    poisoned_overflow = OverflowPrefixObservationV8.model_construct(
        **{
            **_overflow_payload(),
            "configured_limit": AUTHORITY_INPUT_BYTE_LIMIT_V8 - 1,
        }
    )
    with pytest.raises(ValidationError, match="configured_limit"):
        OverflowPrefixObservationV8.model_validate(poisoned_overflow)
    with pytest.raises(ValidationError, match="configured_limit"):
        validate_authority_input_observation_v8(poisoned_overflow)


def test_observations_are_immutable_and_keep_exact_canonical_field_order() -> None:
    observations = (
        NoResponseObservationV8(failure_phase=AuthorityInputPhaseV8.WIRE_READ),
        CompleteBoundedResponseObservationV8.model_validate(_complete_payload()),
        IncompleteBoundedResponseObservationV8.model_validate(_incomplete_payload()),
        OverflowPrefixObservationV8.model_validate(_overflow_payload()),
    )
    assert [list(item.model_dump()) for item in observations] == [
        ["kind", "failure_phase"],
        [
            "kind",
            "transport_encoding",
            "complete_wire_digest",
            "complete_wire_length",
            "complete_decompressed_digest",
            "complete_decompressed_length",
        ],
        [
            "kind",
            "termination_phase",
            "termination_reason",
            "transport_encoding",
            "observed_wire_prefix_digest",
            "observed_wire_prefix_length",
            "observed_decompressed_prefix_digest",
            "observed_decompressed_prefix_length",
        ],
        [
            "kind",
            "transport_encoding",
            "observed_wire_prefix_digest",
            "observed_wire_prefix_length",
            "observed_decompressed_prefix_digest",
            "observed_decompressed_prefix_length",
            "exceeded_boundary",
            "configured_limit",
            "first_excess_observed_count",
        ],
    ]
    field_name = "kind"
    for observation in observations:
        with pytest.raises(ValidationError):
            setattr(observation, field_name, "tampered")
