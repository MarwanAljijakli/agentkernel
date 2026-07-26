from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from agentkernel.adapters.base import (
    AdapterManifest,
    BlockingCancellation,
    CommitContext,
    EvidenceClock,
    NormalizerManifest,
    OperationManifest,
    ReadOnlyContext,
    RecoveryContext,
    StageContext,
    VerifyContext,
    implementation_digest_for_modules,
    load_canonical_model_artifact,
    put_adapter_observation,
    validate_active_deadline,
    validate_canonical_artifact,
    validate_fencing_token,
)
from agentkernel.adapters.mock import MockReversibleAdapter, VersionedMemoryTarget
from agentkernel.adapters.registry import AdapterRegistry
from agentkernel.canonical import canonical_json_bytes, sha256_digest
from agentkernel.domain.enums import RiskClass
from agentkernel.domain.models import ActionProposal, AdapterObservation, Artifact
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.artifacts import LocalArtifactStore
from pydantic import ValidationError

_DIGEST_ZERO = "sha256:" + ("0" * 64)


class _MemoryEvidenceStore:
    def __init__(self, *, corrupt_readback: bool = False, corrupt_digest: bool = False) -> None:
        self._content: dict[str, bytes] = {}
        self._corrupt_readback = corrupt_readback
        self._corrupt_digest = corrupt_digest

    def put(
        self,
        content: bytes,
        *,
        media_type: str = "application/octet-stream",
    ) -> Artifact:
        digest = sha256_digest(content)
        self._content[digest] = content
        return Artifact(
            digest=_DIGEST_ZERO if self._corrupt_digest else digest,
            media_type=media_type,
            size_bytes=len(content),
            created_at=datetime(2030, 1, 1, tzinfo=UTC),
            storage_ref="memory/artifact",
        )

    def get(self, digest: str) -> bytes:
        content = self._content[digest]
        return content + b"tampered" if self._corrupt_readback else content


def _operation(*, normalizer: NormalizerManifest | None = None) -> OperationManifest:
    return OperationManifest(
        risk_floor=RiskClass.REVERSIBLE,
        effect_domains=("memory",),
        staging=True,
        commit=True,
        abort=True,
        rollback=True,
        reconcile=True,
        preconditions=("target_version_matches",),
        staged_postconditions=("stage_digest_matches",),
        committed_postconditions=("content_matches",),
        normalizer=normalizer,
    )


def _observation() -> AdapterObservation:
    return AdapterObservation(
        evidence_kind="reconciliation",
        adapter="mock",
        adapter_manifest_digest=_DIGEST_ZERO,
        tenant_id="tenant:test",
        transaction_id="tx:test",
        intent_hash=_DIGEST_ZERO,
        normalized_action_digest=_DIGEST_ZERO,
        subject_ref=_DIGEST_ZERO,
        operation_permit_ref=_DIGEST_ZERO,
        authority_permit_ref=_DIGEST_ZERO,
        subject_authority_ref=_DIGEST_ZERO,
        operation_status="NO_EFFECT",
        observed_state_digest=_DIGEST_ZERO,
        durable_state_digest=_DIGEST_ZERO,
        observed_at=datetime(2030, 1, 1, tzinfo=UTC),
    )


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        (
            lambda deadline: ReadOnlyContext(deadline, worker_id="worker:test"),
            "Inspection worker",
        ),
        (
            lambda deadline: StageContext(deadline, "worker:test", permit_ref=_DIGEST_ZERO),
            "Stage permit",
        ),
        (
            lambda deadline: VerifyContext(deadline, worker_id="worker:test"),
            "Verification permit",
        ),
        (
            lambda deadline: CommitContext(
                deadline,
                1,
                "intent:test",
                "version:test",
                permit_ref=_DIGEST_ZERO,
            ),
            "Commit permit",
        ),
        (
            lambda deadline: RecoveryContext(
                deadline,
                _DIGEST_ZERO,
                worker_id="worker:test",
            ),
            "Recovery worker",
        ),
    ],
)
def test_partial_authority_contexts_fail_closed(factory: object, message: str) -> None:
    deadline = datetime(2030, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match=message):
        factory(deadline)  # type: ignore[operator]


def test_verification_context_cannot_authorize_mutating_verification() -> None:
    with pytest.raises(ValueError, match="read-only"):
        VerifyContext(datetime(2030, 1, 1, tzinfo=UTC), read_only=False)


@pytest.mark.parametrize(
    "value",
    [
        datetime(2030, 1, 1),
        datetime(2030, 1, 1, tzinfo=timezone(timedelta(hours=1))),
    ],
)
def test_evidence_clock_requires_aware_utc(value: datetime) -> None:
    clock = EvidenceClock(lambda: value)
    with pytest.raises(AgentKernelError, match="aware UTC") as captured:
        clock.now()
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_evidence_clock_accepts_equal_instants_but_rejects_regression() -> None:
    instant = datetime(2030, 1, 1, tzinfo=UTC)
    values = iter((instant, instant, instant - timedelta(microseconds=1)))
    clock = EvidenceClock(lambda: next(values))

    assert clock.now() == instant
    assert clock.now() == instant
    with pytest.raises(AgentKernelError, match="moved backwards") as captured:
        clock.now()
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize(
    "store",
    [
        _MemoryEvidenceStore(corrupt_digest=True),
        _MemoryEvidenceStore(corrupt_readback=True),
    ],
)
def test_adapter_observation_requires_exact_immutable_readback(
    store: _MemoryEvidenceStore,
) -> None:
    with pytest.raises(AgentKernelError, match="immutable evidence") as captured:
        put_adapter_observation(store, _observation())
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_adapter_observation_publishes_its_exact_canonical_digest() -> None:
    store = _MemoryEvidenceStore()
    observation = _observation()
    assert put_adapter_observation(store, observation) == sha256_digest(
        canonical_json_bytes(observation)
    )


@pytest.mark.parametrize(
    "modules",
    [(), ("agentkernel.ids", "agentkernel.ids"), ("agentkernel.ids", "agentkernel.errors")],
)
def test_implementation_measurement_requires_a_sorted_unique_nonempty_set(
    modules: tuple[str, ...],
) -> None:
    with pytest.raises(AgentKernelError, match="sorted and unique") as captured:
        implementation_digest_for_modules(*modules)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize("module", ["sys", "agentkernel_module_that_does_not_exist"])
def test_implementation_measurement_requires_a_source_artifact(module: str) -> None:
    with pytest.raises(AgentKernelError, match="no measurable source") as captured:
        implementation_digest_for_modules(module)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_implementation_measurement_is_reproducible_for_installed_source() -> None:
    first = implementation_digest_for_modules("agentkernel.ids")
    second = implementation_digest_for_modules("agentkernel.ids")
    assert first == second
    assert first.startswith("sha256:")


def test_canonical_artifact_validation_distinguishes_digest_store_and_bytes() -> None:
    proposal = ActionProposal(
        goal_id="goal:test",
        transaction_id="tx:test",
        agent_id="agent:test",
        adapter="mock",
        adapter_version="0.2.0",
        operation="set_values",
        arguments={"values": {"answer": "42"}},
        deadline=datetime(2030, 1, 1, tzinfo=UTC),
    )
    expected = canonical_json_bytes(proposal)
    reference = sha256_digest(expected)

    with pytest.raises(AgentKernelError, match="digest mismatch") as digest_error:
        validate_canonical_artifact(proposal, _DIGEST_ZERO, None, label="Proposal")
    assert digest_error.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError, match="read-only artifact store") as store_error:
        validate_canonical_artifact(proposal, reference, None, label="Proposal")
    assert store_error.value.code is ErrorCode.EVIDENCE_UNAVAILABLE

    corrupt = _MemoryEvidenceStore(corrupt_readback=True)
    corrupt.put(expected)
    with pytest.raises(AgentKernelError, match="authorized canonical") as bytes_error:
        validate_canonical_artifact(proposal, reference, corrupt, label="Proposal")
    assert bytes_error.value.code is ErrorCode.INTEGRITY_ERROR

    exact = _MemoryEvidenceStore()
    exact.put(expected)
    validate_canonical_artifact(proposal, reference, exact, label="Proposal")


def test_canonical_model_loading_rejects_unavailable_wrong_and_noncanonical_evidence() -> None:
    proposal = ActionProposal(
        goal_id="goal:test",
        transaction_id="tx:test",
        agent_id="agent:test",
        adapter="mock",
        adapter_version="0.2.0",
        operation="set_values",
        arguments={"values": {"answer": "42"}},
        deadline=datetime(2030, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(AgentKernelError, match="read-only artifact store") as unavailable:
        load_canonical_model_artifact(
            _DIGEST_ZERO,
            ActionProposal,
            None,
            label="Proposal",
        )
    assert unavailable.value.code is ErrorCode.EVIDENCE_UNAVAILABLE

    wrong_schema = _MemoryEvidenceStore()
    wrong_artifact = wrong_schema.put(b"{}")
    with pytest.raises(AgentKernelError, match="wrong schema") as schema_error:
        load_canonical_model_artifact(
            wrong_artifact.digest,
            ActionProposal,
            wrong_schema,
            label="Proposal",
        )
    assert schema_error.value.code is ErrorCode.INTEGRITY_ERROR

    noncanonical = _MemoryEvidenceStore()
    noncanonical_bytes = proposal.model_dump_json(indent=2).encode()
    noncanonical_artifact = noncanonical.put(noncanonical_bytes)
    with pytest.raises(AgentKernelError, match="not exact canonical") as canonical_error:
        load_canonical_model_artifact(
            noncanonical_artifact.digest,
            ActionProposal,
            noncanonical,
            label="Proposal",
        )
    assert canonical_error.value.code is ErrorCode.INTEGRITY_ERROR

    exact = _MemoryEvidenceStore()
    exact_artifact = exact.put(canonical_json_bytes(proposal))
    assert (
        load_canonical_model_artifact(
            exact_artifact.digest,
            ActionProposal,
            exact,
            label="Proposal",
        )
        == proposal
    )


def test_adapter_deadline_and_fencing_boundaries_fail_closed() -> None:
    with pytest.raises(AgentKernelError, match="must be aware") as naive:
        validate_active_deadline(datetime(2030, 1, 1))
    assert naive.value.code is ErrorCode.VALIDATION_ERROR

    with pytest.raises(AgentKernelError, match="expired") as expired:
        validate_active_deadline(datetime.now(UTC) - timedelta(microseconds=1))
    assert expired.value.code is ErrorCode.DEADLINE_EXCEEDED
    validate_active_deadline(datetime.now(UTC) + timedelta(minutes=1))

    for invalid in (True, 0, -1, 1.0):
        with pytest.raises(AgentKernelError, match="positive int") as fencing:
            validate_fencing_token(invalid)  # type: ignore[arg-type]
        assert fencing.value.code is ErrorCode.VALIDATION_ERROR
    validate_fencing_token(1)


@pytest.mark.parametrize("value", ["cafe\u0301", "\ud800"])
def test_manifest_security_text_must_be_utf8_nfc(value: str) -> None:
    with pytest.raises(ValidationError):
        NormalizerManifest(
            schema_ref=value,
            schema_digest=_DIGEST_ZERO,
            implementation="normalizer:test",
            version="1.0.0",
            implementation_digest=_DIGEST_ZERO,
            max_resources=1,
            max_argument_bytes=1,
        )

    with pytest.raises(ValidationError):
        AdapterManifest(
            api_version=value,
            name="adapter:test",
            version="1.0.0",
            implementation_digest=_DIGEST_ZERO,
            operations={"operation": _operation()},
        )


@pytest.mark.parametrize(
    "update",
    [
        {"effect_domains": ("memory", "memory")},
        {"preconditions": ("z", "a")},
        {"staged_postconditions": ("cafe\u0301",)},
        {"committed_postconditions": ("\ud800",)},
        {"idempotency": "cafe\u0301"},
    ],
)
def test_operation_manifest_semantic_sets_are_canonical(update: dict[str, object]) -> None:
    values = _operation().model_dump(mode="python") | update
    with pytest.raises(ValidationError):
        OperationManifest.model_validate(values)


def test_adapter_registry_rejects_unmeasured_duplicate_and_unknown_adapters() -> None:
    adapter = MockReversibleAdapter(VersionedMemoryTarget())
    registry = AdapterRegistry()
    registry.register(adapter)

    with pytest.raises(AgentKernelError, match="already registered") as duplicate:
        registry.register(adapter)
    assert duplicate.value.code is ErrorCode.VALIDATION_ERROR

    with pytest.raises(AgentKernelError, match="not registered") as unknown:
        registry.lookup("unknown")
    assert unknown.value.code is ErrorCode.UNKNOWN_ADAPTER

    unmeasured = MockReversibleAdapter(VersionedMemoryTarget())
    unmeasured.manifest = unmeasured.manifest.model_copy(
        update={"implementation_digest": _DIGEST_ZERO}
    )
    with pytest.raises(AgentKernelError, match="installed implementation") as measurement:
        AdapterRegistry().register(unmeasured)
    assert measurement.value.code is ErrorCode.INTEGRITY_ERROR


def test_adapter_registry_enforces_pins_review_and_permits(tmp_path: Path) -> None:
    adapter = MockReversibleAdapter(VersionedMemoryTarget())
    registry = AdapterRegistry()
    digest = registry.register(adapter)

    with pytest.raises(AgentKernelError, match="authorized digest") as wrong_digest:
        registry.resolve("mock", expected_digest=_DIGEST_ZERO, enforcement_profile=False)
    assert wrong_digest.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError, match="Unreviewed") as unreviewed:
        registry.resolve("mock", expected_digest=digest, enforcement_profile=True)
    assert unreviewed.value.code is ErrorCode.AUTHORITY_MISSING

    reviewed = AdapterRegistry()
    reviewed_digest = reviewed.register(adapter, reviewed=True)
    with pytest.raises(AgentKernelError, match="mandatory permits") as no_permits:
        reviewed.resolve("mock", expected_digest=reviewed_digest, enforcement_profile=True)
    assert no_permits.value.code is ErrorCode.AUTHORITY_MISSING

    evidence = LocalArtifactStore(tmp_path / "artifacts")
    enforced_adapter = MockReversibleAdapter(
        VersionedMemoryTarget(),
        require_permits=True,
        artifacts=evidence,
    )
    enforced = AdapterRegistry()
    enforced_digest = enforced.register(enforced_adapter, reviewed=True)
    assert (
        enforced.resolve(
            "mock",
            expected_digest=enforced_digest,
            enforcement_profile=True,
        )
        is enforced_adapter
    )


def test_adapter_registry_detects_post_admission_mutation() -> None:
    adapter = MockReversibleAdapter(VersionedMemoryTarget())
    registry = AdapterRegistry()
    registry.register(adapter)
    adapter.manifest = adapter.manifest.model_copy(update={"version": "9.9.9"})

    with pytest.raises(AgentKernelError, match="pins changed") as captured:
        registry.lookup("mock")
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_adapter_registry_resolves_only_admitted_operations() -> None:
    adapter = MockReversibleAdapter(VersionedMemoryTarget())
    registry = AdapterRegistry()
    registry.register(adapter, reviewed=True)

    with pytest.raises(AgentKernelError, match="operation is not admitted") as missing:
        registry.resolve_admitted("mock", "delete_everything", enforcement_profile=False)
    assert missing.value.code is ErrorCode.UNKNOWN_ADAPTER

    with pytest.raises(AgentKernelError, match="permit and normalizer admission") as permits:
        registry.resolve_admitted("mock", "set_values", enforcement_profile=True)
    assert permits.value.code is ErrorCode.AUTHORITY_MISSING

    admitted = registry.resolve_admitted("mock", "set_values", enforcement_profile=False)
    assert admitted.adapter is adapter
    assert admitted.operation_name == "set_values"
    assert admitted.manifest_digest == adapter.manifest.digest


def test_blocking_cancellation_is_observable_at_effect_linearization_point() -> None:
    cancellation = BlockingCancellation()
    assert not cancellation.requested
    cancellation.raise_if_requested()
    cancellation.request()
    assert cancellation.requested
    with pytest.raises(asyncio.CancelledError):
        cancellation.raise_if_requested()
