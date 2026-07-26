"""Fail-closed, permit-fenced coordinator for the single-node enforced profile.

This coordinator is intentionally separate from the embedded Phase-0 coordinator.  It accepts
only registry-admitted adapters and normalizers, persists evidence before referencing it, and
never treats an adapter return value as transaction authority.
"""

from __future__ import annotations

from asyncio import CancelledError, Lock, get_running_loop, sleep, timeout_at
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import RLock
from typing import Literal, Protocol, Self, TypeVar, runtime_checkable
from uuid import uuid4
from weakref import WeakValueDictionary

from pydantic import BaseModel, Field, field_validator, model_validator

from agentkernel.adapters.base import (
    AdapterManifest,
    CommitContext,
    EffectAdapter,
    EffectPlan,
    ReadOnlyContext,
    ReconcileReport,
    ReconcileStatus,
    RecoveryContext,
    StageContext,
    StagedEffect,
    StagedReceipt,
    VerifyContext,
)
from agentkernel.adapters.registry import AdapterRegistry, AdmittedAdapterOperation
from agentkernel.authority.evaluator import (
    AuthorityEvaluationContext,
    AuthorityEvaluationVerdict,
    AuthorityEvaluator,
    AuthoritySnapshot,
    EnforcedAuthorityDecision,
)
from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import (
    AuthorizationRoundPurpose,
    AuthorizationVerdict,
    CommitDispatchState,
    LeasePurpose,
    ReconciliationOutcome,
    RecoveryWorkKind,
    RecoveryWorkState,
    StageMaterialState,
    TransactionState,
    VerificationPhase,
    VerificationStatus,
)
from agentkernel.domain.models import (
    RECOVERY_ACTION_BINDING_ARGUMENT,
    ActionProposal,
    AdapterObservation,
    Artifact,
    AuthenticatedActionContext,
    CommitPermit,
    Digest,
    EffectReceipt,
    InspectionPermit,
    IntentRecord,
    NormalizedAction,
    ProvenanceRecord,
    RecoveryActionBinding,
    RecoveryPermit,
    RecoveryReport,
    StagePermit,
    StrictModel,
    VerificationPermit,
    VerificationReport,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.normalization.registry import NormalizerRegistry
from agentkernel.policy.aggregation import (
    AggregatePolicyDecision,
    PolicyLayerInput,
    PolicyLayerSnapshot,
    PolicyResourceInput,
    evaluate_policy_layers,
)
from agentkernel.policy.engine import PolicyVerdict
from agentkernel.storage.control import (
    CapabilityChainReservation,
    CapabilityReservationState,
    DecisionKind,
    IntentAttemptState,
    IntentDisposition,
    decision_snapshot_digest,
)
from agentkernel.storage.enforced import (
    EnforcedStoreDisposition,
    EnforcedTransactionProjection,
    RecoveryActionHandoff,
    RecoveryCursor,
    RecoveryHandoffEvidenceAuditCheckpoint,
    RecoveryHandoffFailureEvidenceStatus,
    SQLiteEnforcedTransactionStore,
    capability_reservation_digest,
    capability_reservation_plan_digest,
    preview_committed_capability_reservation,
    scheduled_reconciliation_successor_recovery_id,
)
from agentkernel.transactions.contracts import (
    AuthorizationRoundRecord,
    CommitDispatchRecord,
    DispatchEvidenceUnavailableRecord,
    EnforcedTransactionRecord,
    LateRecoveryReportRecord,
    ReconciliationAttemptRecord,
    RecoveryCompletionReportRecord,
    RecoveryEvidenceUnavailableRecord,
    RecoveryWorkRecord,
    StageMaterialRecord,
    WorkerLeaseRecord,
)
from agentkernel.transactions.state_machine import TransitionEvent

Clock = Callable[[], datetime]
CrashHook = Callable[["CoordinatorCrashPoint"], None]
_ModelT = TypeVar("_ModelT", bound=BaseModel)
_ProviderResultT = TypeVar("_ProviderResultT")

_APPROVAL_OBLIGATION = "approval"
_RISK_ORDER = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}
_MAX_RECOVERY_SCAN_PER_RUN = 4_096
_MIN_RECOVERY_SCAN_PER_RUN = 256
_RECOVERY_HANDOFF_EVIDENCE_AUDIT_PAGE = 256
_PRE_DISPATCH_STATES = frozenset(
    {
        TransactionState.NEW,
        TransactionState.PLANNED,
        TransactionState.AUTHORIZED_TO_STAGE,
        TransactionState.STAGING,
        TransactionState.STAGED,
        TransactionState.STAGE_VERIFIED,
        TransactionState.AWAITING_APPROVAL,
        TransactionState.READY_TO_COMMIT,
        TransactionState.ABORTING,
    }
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _stable_id(prefix: str, material: object) -> str:
    suffix = canonical_digest(
        {"profile": "agentkernel.coordinator-id/v1", "prefix": prefix, "material": material}
    ).removeprefix("sha256:")
    return f"{prefix}:{suffix[:40]}"


class CoordinatorCrashPoint(StrEnum):
    """All durable or effect boundaries exposed to process-kill testing."""

    AFTER_INGRESS_ARTIFACT = "after_ingress_artifact"
    AFTER_INGRESS_CREATED = "after_ingress_created"
    AFTER_NORMALIZED_ARTIFACT = "after_normalized_artifact"
    AFTER_INTENT_ACQUIRED = "after_intent_acquired"
    AFTER_STAGING_AUTHORIZED = "after_staging_authorized"
    AFTER_STAGING_LEASE_ACQUIRED = "after_staging_lease_acquired"
    BEFORE_INSPECT = "before_inspect"
    AFTER_INSPECT_CALL = "after_inspect_call"
    AFTER_PLAN_ARTIFACT = "after_plan_artifact"
    AFTER_STAGE_ALLOCATED = "after_stage_allocated"
    BEFORE_STAGE = "before_stage"
    AFTER_STAGE_CALL = "after_stage_call"
    AFTER_STAGED_EFFECT_RECORDED = "after_staged_effect_recorded"
    BEFORE_EXECUTE = "before_execute"
    AFTER_EXECUTE_CALL = "after_execute_call"
    AFTER_EXECUTION_RECORDED = "after_execution_recorded"
    BEFORE_STAGED_VERIFY = "before_staged_verify"
    AFTER_STAGED_VERIFY_CALL = "after_staged_verify_call"
    AFTER_STAGE_VERIFIED = "after_stage_verified"
    AFTER_READY_TO_COMMIT = "after_ready_to_commit"
    AFTER_PRECOMMIT_AUTHORIZED = "after_precommit_authorized"
    AFTER_PRECOMMIT_INSPECT = "after_precommit_inspect"
    AFTER_COMMIT_PERMIT_ARTIFACT = "after_commit_permit_artifact"
    AFTER_COMMIT_DISPATCHED = "after_commit_dispatched"
    BEFORE_COMMIT = "before_commit"
    AFTER_COMMIT_CALL = "after_commit_call"
    AFTER_RECEIPT_ARTIFACT = "after_receipt_artifact"
    AFTER_RECEIPT_ATTACHED = "after_receipt_attached"
    BEFORE_COMMITTED_VERIFY = "before_committed_verify"
    AFTER_COMMITTED_VERIFY_CALL = "after_committed_verify_call"
    AFTER_OUTCOME_CLASSIFIED = "after_outcome_classified"
    AFTER_ABORTING = "after_aborting"
    AFTER_RECOVERY_ACTION_ATTACHED = "after_recovery_action_attached"
    AFTER_RECOVERY_AUTHORIZED = "after_recovery_authorized"
    AFTER_RECOVERY_CLAIMED = "after_recovery_claimed"
    BEFORE_RECOVERY_ADAPTER = "before_recovery_adapter"
    AFTER_RECOVERY_ADAPTER_CALL = "after_recovery_adapter_call"
    AFTER_RECOVERY_FINISHED = "after_recovery_finished"
    AFTER_RECONCILIATION_STARTED = "after_reconciliation_started"
    BEFORE_RECONCILE = "before_reconcile"
    AFTER_RECONCILE_CALL = "after_reconcile_call"
    AFTER_RECONCILIATION_FINISHED = "after_reconciliation_finished"


class CoordinatorInjectedCrash(BaseException):
    """Uncatchable-by-coordinator process-crash signal used at durable test boundaries."""

    def __init__(self, point: CoordinatorCrashPoint) -> None:
        super().__init__(point.value)
        self.point = point


class _RecoveryHandoffContended(Exception):
    """Internal signal that an exact live pre-work handoff won acquisition."""


class PolicyEvaluationInputs(StrictModel):
    """All-and-only deterministic policy inputs supplied by the trusted deployment."""

    snapshot: PolicyLayerSnapshot
    layers: tuple[PolicyLayerInput, ...] = Field(max_length=112)
    resources: tuple[PolicyResourceInput, ...] = Field(min_length=1, max_length=256)
    unknown_facts: tuple[str, ...] = Field(default=(), max_length=256)

    @field_validator("unknown_facts")
    @classmethod
    def _unknown_facts_are_canonical(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("Policy unknown facts must be sorted and unique")
        return values

    @model_validator(mode="after")
    def _inputs_are_canonical_and_unique(self) -> Self:
        layer_keys = tuple(
            (
                layer.layer.value,
                layer.scope_id,
                layer.policy.bundle.name,
                layer.policy.bundle.version,
                layer.policy.digest,
            )
            for layer in self.layers
        )
        resource_keys = tuple(
            (resource.resource_index, resource.resource_use_ref) for resource in self.resources
        )
        resource_refs = tuple(resource.resource_use_ref for resource in self.resources)
        if len(set(layer_keys)) != len(layer_keys) or layer_keys != tuple(sorted(layer_keys)):
            raise ValueError("Policy layer inputs must be sorted and unique")
        if (
            len(set(resource_keys)) != len(resource_keys)
            or len(set(resource_refs)) != len(resource_refs)
            or resource_keys != tuple(sorted(resource_keys))
        ):
            raise ValueError("Policy resource inputs must be sorted and unique")
        return self


class EnforcedTransactionRequest(StrictModel):
    """Untrusted proposal plus authentication material awaiting explicit validation.

    ``presented_context`` is transport evidence only.  The coordinator registers solely the
    context returned by :class:`AuthenticatedContextValidator`.
    """

    proposal: ActionProposal
    presented_context: AuthenticatedActionContext
    authentication_evidence_ref: Digest
    provenance_records: tuple[ProvenanceRecord, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def _provenance_ids_are_unique(self) -> Self:
        identifiers = tuple(record.provenance_id for record in self.provenance_records)
        if len(set(identifiers)) != len(identifiers) or identifiers != tuple(sorted(identifiers)):
            raise ValueError("Presented provenance identifiers must be sorted and unique")
        return self


class ValidatedAuthenticatedContext(StrictModel):
    """Trusted validation output bound to the exact supplied authentication evidence."""

    context: AuthenticatedActionContext
    authentication_evidence_ref: Digest


@runtime_checkable
class ArtifactStore(Protocol):
    """Minimal content-addressed evidence interface required by the coordinator."""

    def put_model(
        self,
        model: BaseModel,
        *,
        media_type: str = "application/vnd.agentkernel.canonical+json",
    ) -> Artifact: ...

    def get(self, digest: str) -> bytes: ...

    def get_model(self, digest: str, model_type: type[_ModelT]) -> _ModelT: ...


@runtime_checkable
class AuthenticatedContextValidator(Protocol):
    """Authenticate request identity without trusting caller-supplied context fields."""

    async def validate(
        self,
        request: EnforcedTransactionRequest,
    ) -> ValidatedAuthenticatedContext: ...


@runtime_checkable
class AuthoritySnapshotProvider(Protocol):
    """Capture one immutable authority snapshot at the requested evaluation instant."""

    async def snapshot_for(
        self,
        *,
        action: NormalizedAction,
        purpose: AuthorizationRoundPurpose,
        evaluated_at: datetime,
    ) -> AuthoritySnapshot: ...


@runtime_checkable
class PolicyInputProvider(Protocol):
    """Provide exact policy-layer and per-resource inputs for a native decision."""

    async def inputs_for(
        self,
        *,
        action: NormalizedAction,
        authority_decision: EnforcedAuthorityDecision,
        purpose: AuthorizationRoundPurpose,
        evaluated_at: datetime,
    ) -> PolicyEvaluationInputs: ...


@runtime_checkable
class RecoveryActionFactory(Protocol):
    """Create a separately normalized recovery action; it is never the target action."""

    async def create(
        self,
        *,
        target: EnforcedTransactionRecord,
        target_action: NormalizedAction,
        kind: RecoveryWorkKind,
        target_evidence_ref: str,
        binding: RecoveryActionBinding,
        deadline: datetime,
    ) -> NormalizedAction: ...


@dataclass(frozen=True, slots=True)
class EnforcedCoordinatorConfig:
    worker_id: str = "worker:enforced"
    authority_audience: str = "service:agentkernel"
    lease_duration: timedelta = timedelta(minutes=2)
    recovery_deadline: timedelta = timedelta(minutes=5)
    handoff_evidence_reaudit_interval: timedelta = timedelta(minutes=5)
    reconciliation_backoff: timedelta = timedelta(seconds=30)
    max_reconciliation_attempts: int = 3
    crash_hook: CrashHook | None = None

    def __post_init__(self) -> None:
        if not self.worker_id or not self.authority_audience:
            raise ValueError("Worker and authority audience must be non-empty")
        for name, value in (
            ("lease_duration", self.lease_duration),
            ("recovery_deadline", self.recovery_deadline),
            (
                "handoff_evidence_reaudit_interval",
                self.handoff_evidence_reaudit_interval,
            ),
            ("reconciliation_backoff", self.reconciliation_backoff),
        ):
            if value <= timedelta(0):
                raise ValueError(f"{name} must be positive")
            if name == "handoff_evidence_reaudit_interval" and value > timedelta(days=1):
                raise ValueError("handoff_evidence_reaudit_interval must be no more than one day")
        if (
            type(self.max_reconciliation_attempts) is not int
            or not 1 <= self.max_reconciliation_attempts <= 32
        ):
            raise ValueError("max_reconciliation_attempts must be an integer from 1 through 32")


class CoordinatorEvidence(StrictModel):
    """Small content-addressed control fact used at non-adapter state boundaries."""

    profile: Literal["agentkernel.coordinator-evidence/v1"] = "agentkernel.coordinator-evidence/v1"
    transaction_id: str
    event: str
    reason_code: str
    recorded_at: datetime
    subject_ref: str | None = None


@dataclass(frozen=True, slots=True)
class EnforcedSessionReceipts:
    staged: StagedReceipt | None = None
    effect: EffectReceipt | None = None
    staged_verification: VerificationReport | None = None
    committed_verification: VerificationReport | None = None


@dataclass(frozen=True, slots=True)
class EnforcedTransactionStatus:
    record: EnforcedTransactionRecord
    action: NormalizedAction | None
    stage: StageMaterialRecord | None
    dispatch: CommitDispatchRecord | None
    dispatch_evidence_unavailable: DispatchEvidenceUnavailableRecord | None
    recovery_work: tuple[RecoveryWorkRecord, ...]
    event_count: int
    recovery_handoffs: tuple[RecoveryActionHandoff, ...] = ()
    recovery_evidence_unavailable: tuple[RecoveryEvidenceUnavailableRecord, ...] = ()
    requested_record: EnforcedTransactionRecord | None = None
    intent_disposition: IntentDisposition | None = None
    intent_owner_transaction_id: str | None = None
    effect_receipt: EffectReceipt | None = None

    @property
    def owner_transaction_id(self) -> str:
        return self.intent_owner_transaction_id or self.record.transaction_id


@dataclass(frozen=True, slots=True)
class RecoveryRunResult:
    tenant_id: str
    observed_at: datetime
    scanned: int
    processed: int
    remaining: int
    statuses: tuple[EnforcedTransactionStatus, ...]
    failures: tuple[RecoveryCandidateFailure, ...]
    handoff_evidence_audit_cycle: int
    handoff_evidence_audit_high_watermark: int
    handoff_evidence_audit_cycle_complete: bool
    handoff_evidence_audit_ready: bool
    handoff_evidence_audit_failure_count: int
    handoff_evidence_last_completed_cycle: int | None
    handoff_evidence_last_completed_at: datetime | None
    handoff_evidence_last_completed_high_watermark: int | None
    handoff_evidence_last_completed_failure_count: int | None


class RecoveryFailureKind(StrEnum):
    CANDIDATE = "CANDIDATE"
    RECOVERY_TERMINAL = "RECOVERY_TERMINAL"
    EVIDENCE_AUDIT = "EVIDENCE_AUDIT"


@dataclass(frozen=True, slots=True)
class RecoveryCandidateFailure:
    transaction_id: str
    reason_code: str
    evidence_ref: str | None
    kind: RecoveryFailureKind = RecoveryFailureKind.CANDIDATE


@dataclass(frozen=True, slots=True)
class _AuthorizationEvidence:
    round: AuthorizationRoundRecord
    authority: EnforcedAuthorityDecision
    policy: AggregatePolicyDecision
    capability_ids: tuple[str, ...]
    reservation: CapabilityChainReservation | None
    authority_valid_until: datetime | None


@dataclass(slots=True)
class _RecoveryExecutionPhase:
    boundary: str
    provider_entered: bool = False
    lineage_revalidation: bool = False


class EnforcedTransactionCoordinator:
    """Orchestrate one enforced action through durable, artifact-bound authority."""

    def __init__(
        self,
        *,
        store: SQLiteEnforcedTransactionStore,
        registry: AdapterRegistry,
        normalizers: NormalizerRegistry,
        artifacts: ArtifactStore,
        context_validator: AuthenticatedContextValidator,
        authority_snapshots: AuthoritySnapshotProvider,
        policy_inputs: PolicyInputProvider,
        recovery_actions: RecoveryActionFactory,
        authority_evaluator: AuthorityEvaluator | None = None,
        config: EnforcedCoordinatorConfig | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        self._store = store
        self._registry = registry
        self._normalizers = normalizers
        self._artifacts = artifacts
        self._context_validator = context_validator
        self._authority_snapshots = authority_snapshots
        self._policy_inputs = policy_inputs
        self._recovery_actions = recovery_actions
        self._authority_evaluator = authority_evaluator or AuthorityEvaluator()
        self._config = config or EnforcedCoordinatorConfig()
        self._clock = clock
        self._clock_lock = RLock()
        self._last_clock_value: datetime | None = None
        self._recovery_scan_cursors: dict[str, RecoveryCursor] = {}
        self._recovery_lock_guard = RLock()
        self._recovery_locks: WeakValueDictionary[tuple[str, str], Lock] = WeakValueDictionary()
        self._dispatch_resume_locks: WeakValueDictionary[tuple[str, str], Lock] = (
            WeakValueDictionary()
        )

    def _now(self) -> datetime:
        with self._clock_lock:
            value = self._clock()
            if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Coordinator clock must return an aware UTC timestamp",
                )
            captured = value.astimezone(UTC).replace(tzinfo=UTC)
            if self._last_clock_value is not None and captured < self._last_clock_value:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Coordinator clock moved backwards",
                )
            self._last_clock_value = captured
            return captured

    def _crash(self, point: CoordinatorCrashPoint) -> None:
        hook = self._config.crash_hook
        if hook is not None:
            try:
                hook(point)
            except CoordinatorInjectedCrash:
                raise
            except BaseException as error:
                raise CoordinatorInjectedCrash(point) from error

    def _recovery_lock_for(self, tenant_id: str, transaction_id: str) -> Lock:
        key = (tenant_id, transaction_id)
        with self._recovery_lock_guard:
            lock = self._recovery_locks.get(key)
            if lock is None:
                lock = Lock()
                self._recovery_locks[key] = lock
            return lock

    def _dispatch_resume_lock_for(self, tenant_id: str, transaction_id: str) -> Lock:
        key = (tenant_id, transaction_id)
        with self._recovery_lock_guard:
            lock = self._dispatch_resume_locks.get(key)
            if lock is None:
                lock = Lock()
                self._dispatch_resume_locks[key] = lock
            return lock

    def _put_model(self, value: BaseModel) -> str:
        try:
            artifact = self._artifacts.put_model(value)
        except OSError as error:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Artifact persistence is unavailable",
                retryable=True,
            ) from error
        expected = canonical_digest(value)
        if artifact.digest != expected:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Artifact store returned a digest inconsistent with canonical evidence",
            )
        return artifact.digest

    def _get_artifact(self, digest: str) -> bytes:
        try:
            return self._artifacts.get(digest)
        except OSError as error:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Artifact retrieval is unavailable",
                retryable=True,
            ) from error

    def _get_artifact_model(self, digest: str, model_type: type[_ModelT]) -> _ModelT:
        try:
            return self._artifacts.get_model(digest, model_type)
        except OSError as error:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Artifact retrieval is unavailable",
                retryable=True,
            ) from error

    def _put_control_evidence(
        self,
        *,
        transaction_id: str,
        event: str,
        reason_code: str,
        recorded_at: datetime,
        subject_ref: str | None = None,
    ) -> str:
        return self._put_model(
            CoordinatorEvidence(
                transaction_id=transaction_id,
                event=event,
                reason_code=reason_code,
                recorded_at=recorded_at,
                subject_ref=subject_ref,
            )
        )

    @staticmethod
    def _is_evidence_store_outage(error: BaseException) -> bool:
        """Recognize availability failures without downgrading integrity violations."""

        return isinstance(error, AgentKernelError) and error.code is ErrorCode.EVIDENCE_UNAVAILABLE

    def _put_failure_evidence_or_fallback(
        self,
        *,
        transaction_id: str,
        event: str,
        reason_code: str,
        recorded_at: datetime,
        subject_ref: str | None = None,
    ) -> tuple[str | None, str, RecoveryHandoffFailureEvidenceStatus]:
        """Return durable failure evidence, degrading explicitly if artifacts are unavailable."""

        try:
            return (
                self._put_control_evidence(
                    transaction_id=transaction_id,
                    event=event,
                    reason_code=reason_code,
                    recorded_at=recorded_at,
                    subject_ref=subject_ref,
                ),
                reason_code,
                RecoveryHandoffFailureEvidenceStatus.AVAILABLE,
            )
        except (Exception, CancelledError) as error:
            if not self._is_evidence_store_outage(error):
                raise
            fallback_reason = f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{reason_code}"
            fallback = CoordinatorEvidence(
                transaction_id=transaction_id,
                event=event,
                reason_code=fallback_reason,
                recorded_at=recorded_at,
                subject_ref=subject_ref,
            )
            try:
                return (
                    self._put_model(fallback),
                    fallback_reason,
                    RecoveryHandoffFailureEvidenceStatus.AVAILABLE,
                )
            except (Exception, CancelledError) as fallback_error:
                if not self._is_evidence_store_outage(fallback_error):
                    raise
                return (
                    None,
                    fallback_reason,
                    RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE,
                )

    @staticmethod
    def _check_deadline(deadline: datetime, now: datetime, *, boundary: str) -> None:
        if now >= deadline:
            raise AgentKernelError(
                ErrorCode.DEADLINE_EXCEEDED,
                f"Transaction deadline elapsed before {boundary}",
            )

    async def _await_provider(
        self,
        operation: Callable[[], Awaitable[_ProviderResultT]],
        *,
        deadline: datetime,
        boundary: str,
        enforce_completion_deadline: bool = True,
    ) -> _ProviderResultT:
        """Await one cooperative provider under the coordinator's absolute deadline."""

        now = self._now()
        self._check_deadline(deadline, now, boundary=boundary)
        loop_deadline = get_running_loop().time() + (deadline - now).total_seconds()
        deadline_scope = timeout_at(loop_deadline)
        try:
            async with deadline_scope:
                result = await operation()
        except TimeoutError as error:
            if not deadline_scope.expired():
                raise
            raise AgentKernelError(
                ErrorCode.DEADLINE_EXCEEDED,
                f"Transaction deadline elapsed during {boundary}",
            ) from error
        if enforce_completion_deadline:
            self._check_deadline(deadline, self._now(), boundary=boundary)
        return result

    def _check_authorization_valid(
        self,
        authorization: _AuthorizationEvidence,
        *,
        boundary: str,
    ) -> None:
        if authorization.authority_valid_until is not None:
            self._check_deadline(
                authorization.authority_valid_until,
                self._now(),
                boundary=boundary,
            )

    def _validate_authorization_artifacts(self, record: AuthorizationRoundRecord) -> None:
        """Reload and cross-bind every artifact needed to reproduce one authority round."""

        if record.schema_version != "1.1":
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Legacy authorization round lacks discoverable canonical evidence",
            )
        authority_snapshot_ref = record.authority_snapshot_ref
        authority_context_ref = record.authority_context_ref
        authority_decision_ref = record.authority_decision_ref
        policy_inputs_ref = record.policy_inputs_ref
        policy_snapshot_ref = record.policy_snapshot_ref
        policy_decision_ref = record.policy_decision_ref
        if (
            authority_snapshot_ref is None
            or authority_context_ref is None
            or authority_decision_ref is None
            or policy_inputs_ref is None
            or policy_snapshot_ref is None
            or policy_decision_ref is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Authorization round lost a required evidence artifact reference",
            )
        snapshot = self._get_artifact_model(
            authority_snapshot_ref,
            AuthoritySnapshot,
        )
        authority_context = self._get_artifact_model(
            authority_context_ref,
            AuthorityEvaluationContext,
        )
        authority = self._get_artifact_model(
            authority_decision_ref,
            EnforcedAuthorityDecision,
        )
        supplied = self._get_artifact_model(
            policy_inputs_ref,
            PolicyEvaluationInputs,
        )
        policy_snapshot = self._get_artifact_model(
            policy_snapshot_ref,
            PolicyLayerSnapshot,
        )
        policy = self._get_artifact_model(
            policy_decision_ref,
            AggregatePolicyDecision,
        )
        action = self._store.get_normalized_action(
            record.tenant_id,
            record.subject_transaction_id,
        ).action
        capability_ids = (
            () if authority.reservation_plan is None else authority.reservation_plan.capability_ids
        )
        capabilities_by_id = {
            capability.capability_id: capability for capability in snapshot.capabilities
        }
        supplied_resources = {
            resource.resource_use_ref: resource for resource in supplied.resources
        }
        policy_resources = {
            resource.resource_use_ref: resource for resource in policy.resource_inputs
        }
        expected_valid_until = (
            min(capabilities_by_id[capability_id].expires_at for capability_id in capability_ids)
            if capability_ids
            and all(capability_id in capabilities_by_id for capability_id in capability_ids)
            else None
        )
        if (
            snapshot.tenant_id != record.tenant_id
            or snapshot.snapshot_id != record.authority_snapshot_id
            or snapshot.snapshot_digest != record.authority_snapshot_digest
            or authority_context.tenant_id != action.tenant_id
            or authority_context.principal_id != action.principal_id
            or authority_context.subject != action.agent_id
            or authority_context.goal_id != action.goal_id
            or authority_context.run_id != action.run_id
            or authority_context.actor_id != action.actor_id
            or authority_context.on_behalf_of != action.on_behalf_of
            or authority_context.configuration_digest != action.configuration_digest
            or authority_context.evaluated_at != record.evaluated_at
            or authority_context.authority_snapshot_digest != snapshot.snapshot_digest
            or authority.tenant_id != record.tenant_id
            or authority.transaction_id != record.subject_transaction_id
            or authority.intent_hash != record.subject_intent_hash
            or authority.authority_snapshot_digest != record.authority_snapshot_digest
            or authority.evaluation_context_digest != canonical_digest(authority_context)
            or authority.evaluated_at != authority_context.evaluated_at
            or authority.decision_digest != record.authority_decision_digest
            or supplied.snapshot != policy_snapshot
            or policy.normalized_action.transaction_id != record.subject_transaction_id
            or canonical_digest(policy.normalized_action) != record.subject_normalized_action_digest
            or policy.authority_decision != authority
            or policy.policy_snapshot != policy_snapshot
            or policy.layer_inputs != supplied.layers
            or policy_resources != supplied_resources
            or policy.input_unknown_facts != supplied.unknown_facts
            or policy.aggregate_digest != record.policy_decision_digest
            or policy_snapshot.snapshot_digest != record.policy_snapshot_digest
            or (
                record.verdict is AuthorizationVerdict.ELIGIBLE
                and expected_valid_until != record.authority_valid_until
            )
            or (
                record.verdict is not AuthorizationVerdict.ELIGIBLE
                and record.authority_valid_until is not None
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Authorization artifacts differ from their durable round bindings",
            )

    def _validate_adapter_observation(
        self,
        evidence_refs: tuple[str, ...],
        *,
        evidence_kind: str,
        action: NormalizedAction,
        adapter_manifest_digest: str,
        subject_ref: str,
        operation_permit_ref: str,
        authority_permit_ref: str,
        subject_authority_ref: str,
        operation_status: str,
        permit_issued_at: datetime,
        permit_deadline: datetime,
        received_at: datetime,
        dispatch: CommitDispatchRecord | None = None,
        expected_observed_state_digest: str | None = None,
        allow_late: bool = False,
    ) -> tuple[str, AdapterObservation]:
        """Require one canonical, fully parent-bound adapter observation."""

        if not evidence_refs:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Enforced adapter result lacks its mandatory observation artifact",
            )
        if len(evidence_refs) != 1 or len(set(evidence_refs)) != 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Enforced adapter result must identify exactly one observation artifact",
            )
        observation_ref = evidence_refs[0]
        observation = self._get_artifact_model(observation_ref, AdapterObservation)
        expected_generation = (
            (None, None, None, None)
            if dispatch is None
            else (
                dispatch.dispatch_id,
                dispatch.permit.owner_version,
                dispatch.permit.owner_history_sequence,
                dispatch.permit.owner_history_digest,
            )
        )
        observed_generation = (
            observation.dispatch_id,
            observation.owner_version,
            observation.owner_history_sequence,
            observation.owner_history_digest,
        )
        if (
            observation.evidence_kind != evidence_kind
            or observation.adapter != action.adapter
            or observation.adapter_manifest_digest != adapter_manifest_digest
            or observation.tenant_id != action.tenant_id
            or observation.transaction_id != action.transaction_id
            or observation.intent_hash != action.intent_hash
            or observation.normalized_action_digest != canonical_digest(action)
            or observation.subject_ref != subject_ref
            or observation.operation_permit_ref != operation_permit_ref
            or observation.authority_permit_ref != authority_permit_ref
            or observation.subject_authority_ref != subject_authority_ref
            or observation.operation_status != operation_status
            or observed_generation != expected_generation
            or observation.observed_at < permit_issued_at
            or observation.observed_at > received_at
            or (not allow_late and observation.observed_at >= permit_deadline)
            or (
                expected_observed_state_digest is not None
                and observation.observed_state_digest != expected_observed_state_digest
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter observation differs from its result, permit, subject, or dispatch",
            )
        return observation_ref, observation

    @staticmethod
    def _validate_effect_receipt_identity(
        action: NormalizedAction,
        dispatch: CommitDispatchRecord,
        receipt: EffectReceipt,
    ) -> None:
        """Bind a provider receipt to the one dispatched action and target guard."""

        if (
            receipt.transaction_id != action.transaction_id
            or receipt.adapter != action.adapter
            or receipt.operation != action.operation
            or receipt.intent_hash != action.intent_hash
            or receipt.target_version_before != dispatch.permit.target_version_guard
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Effect receipt differs from its dispatched action or target generation",
            )

    def _validate_committed_dispatch_evidence(
        self,
        action: NormalizedAction,
        dispatch: CommitDispatchRecord,
        receipt: EffectReceipt,
    ) -> None:
        """Re-prove a committed dispatch from its permit, PASS report, and state observation."""

        if dispatch.state is not CommitDispatchState.COMMITTED:
            return
        receipt_ref = dispatch.effect_receipt_ref
        verification_permit_ref = dispatch.committed_verification_permit_ref
        verification_ref = dispatch.committed_verification_ref
        if receipt_ref is None or verification_permit_ref is None or verification_ref is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Committed dispatch lost its verification evidence",
            )
        verification_permit = self._get_artifact_model(
            verification_permit_ref,
            VerificationPermit,
        )
        verification = self._get_artifact_model(verification_ref, VerificationReport)
        if (
            canonical_digest(verification_permit) != verification_permit_ref
            or verification_permit.permit_digest != dispatch.committed_verification_permit_digest
            or canonical_digest(verification) != verification_ref
            or verification.status is not VerificationStatus.PASS
            or verification_permit.tenant_id != action.tenant_id
            or verification_permit.transaction_id != action.transaction_id
            or verification_permit.intent_hash != action.intent_hash
            or verification_permit.normalized_action_digest != canonical_digest(action)
            or verification_permit.adapter_manifest_digest
            != dispatch.permit.adapter_manifest_digest
            or verification_permit.phase is not VerificationPhase.COMMITTED
            or verification_permit.subject_ref != receipt_ref
            or verification_permit.subject_permit_digest != dispatch.permit.permit_digest
            or verification_permit.subject_permit_ref != dispatch.permit_ref
            or verification_permit.issued_at > dispatch.updated_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Committed dispatch verification differs from its receipt or authority",
            )
        if verification_permit.authority_permit_ref == dispatch.permit_ref:
            authority_matches = (
                verification_permit.authority_permit_digest == dispatch.permit.permit_digest
                and verification_permit.authorization_round_id
                == dispatch.permit.authorization_round_id
                and verification_permit.authorization_round_digest
                == dispatch.permit.authorization_round_digest
                and verification_permit.lease_id == dispatch.permit.lease_id
                and verification_permit.worker_id == dispatch.permit.worker_id
                and verification_permit.fencing_token == dispatch.permit.fencing_token
                and verification_permit.issued_at >= dispatch.permit.issued_at
                and verification_permit.deadline == dispatch.permit.deadline
            )
        else:
            recovery_permit = self._get_artifact_model(
                verification_permit.authority_permit_ref,
                RecoveryPermit,
            )
            authority_matches = (
                canonical_digest(recovery_permit) == verification_permit.authority_permit_ref
                and recovery_permit.permit_digest == verification_permit.authority_permit_digest
                and recovery_permit.tenant_id == action.tenant_id
                and recovery_permit.transaction_id == action.transaction_id
                and recovery_permit.intent_hash == action.intent_hash
                and recovery_permit.adapter_manifest_digest
                == dispatch.permit.adapter_manifest_digest
                and recovery_permit.recovery_kind is RecoveryWorkKind.RECONCILE_DISPATCH
                and recovery_permit.target_id == dispatch.dispatch_id
                and verification_permit.authorization_round_id
                == recovery_permit.authorization_round_id
                and verification_permit.authorization_round_digest
                == recovery_permit.authorization_round_digest
                and verification_permit.lease_id == recovery_permit.lease_id
                and verification_permit.worker_id == recovery_permit.worker_id
                and verification_permit.fencing_token == recovery_permit.fencing_token
                and verification_permit.issued_at >= recovery_permit.issued_at
                and verification_permit.deadline == recovery_permit.deadline
            )
        required_refs = {
            receipt_ref,
            verification_permit.permit_digest,
            verification_permit_ref,
            verification_ref,
            *verification.evidence_refs,
        }
        if not authority_matches or not required_refs.issubset(dispatch.outcome_evidence_refs):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Committed dispatch lost its exact verification evidence closure",
            )
        self._validate_adapter_observation(
            verification.evidence_refs,
            evidence_kind="committed_verification",
            action=action,
            adapter_manifest_digest=dispatch.permit.adapter_manifest_digest,
            subject_ref=receipt_ref,
            operation_permit_ref=verification_permit_ref,
            authority_permit_ref=verification_permit.authority_permit_ref,
            subject_authority_ref=dispatch.permit_ref,
            operation_status=VerificationStatus.PASS.value,
            permit_issued_at=verification_permit.issued_at,
            permit_deadline=verification_permit.deadline,
            received_at=dispatch.updated_at,
            dispatch=dispatch,
            expected_observed_state_digest=receipt.target_version_after,
            allow_late=False,
        )

    async def transaction(
        self,
        request: EnforcedTransactionRequest,
    ) -> EnforcedTransactionSession | EnforcedTransactionStatus:
        """Authenticate, durably admit, normalize, and authorize without adapter I/O."""

        # Availability and content integrity are checked by the artifact reader before any
        # caller-presented identity can become trusted ingress state.
        self._get_artifact(request.authentication_evidence_ref)
        validated_context = await self._await_provider(
            lambda: self._context_validator.validate(request),
            deadline=request.proposal.deadline,
            boundary="authenticated context validation",
        )
        validated = ValidatedAuthenticatedContext.model_validate(
            validated_context.model_dump(mode="python")
        )
        if validated.authentication_evidence_ref != request.authentication_evidence_ref:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Authenticated context validation used different evidence",
            )
        trusted_context = validated.context
        proposal_ref = self._put_model(request.proposal)
        request_ref = self._put_model(request)
        self._crash(CoordinatorCrashPoint.AFTER_INGRESS_ARTIFACT)
        now = self._now()
        ingress = EnforcedTransactionRecord(
            tenant_id=trusted_context.tenant_id,
            transaction_id=request.proposal.transaction_id,
            principal_id=trusted_context.principal_id,
            goal_id=trusted_context.goal_id,
            run_id=trusted_context.run_id,
            trace_id=trusted_context.trace_id,
            actor_id=trusted_context.actor_id,
            on_behalf_of=trusted_context.on_behalf_of,
            agent_id=trusted_context.agent_id,
            request_digest=request_ref,
            state=TransactionState.NEW,
            version=0,
            created_at=now,
            updated_at=now,
        )
        created = self._store.admit_enforced_transaction(trusted_context, ingress)
        record = created.transaction
        self._crash(CoordinatorCrashPoint.AFTER_INGRESS_CREATED)
        if record.state is not TransactionState.NEW:
            current = self.status(record.tenant_id, record.transaction_id)
            return self._readonly_admission_result(
                requested_record=record,
                owner_transaction_id=current.owner_transaction_id,
                disposition=current.intent_disposition or IntentDisposition.SAME_TRANSACTION,
            )
        try:
            if (
                request.proposal.goal_id != trusted_context.goal_id
                or request.proposal.agent_id != trusted_context.agent_id
            ):
                raise AgentKernelError(
                    ErrorCode.AUTHORITY_MISSING,
                    "Proposal identity differs from the authenticated request context",
                )
            self._check_deadline(request.proposal.deadline, self._now(), boundary="normalization")
            admitted = self._registry.resolve_admitted(
                request.proposal.adapter,
                request.proposal.operation,
                enforcement_profile=True,
            )
            if request.proposal.adapter_version != admitted.adapter_version:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Proposal adapter version differs from registry admission",
                )
            admitted_manifest = AdapterManifest.model_validate_json(admitted.manifest_bytes)
            if admitted_manifest.digest != admitted.manifest_digest:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Registry admission bytes differ from their pinned manifest digest",
                )
            supplied_action = await self._await_provider(
                lambda: self._normalizers.normalize_async(
                    request.proposal,
                    trusted_context,
                    adapter_manifest=admitted_manifest,
                    expected_adapter_manifest_digest=admitted.manifest_digest,
                    provenance_records=request.provenance_records,
                    enforcement_profile=True,
                ),
                deadline=request.proposal.deadline,
                boundary="normalization",
            )
            action = NormalizedAction.model_validate(supplied_action.model_dump(mode="python"))
            action_ref = self._put_model(action)
            self._crash(CoordinatorCrashPoint.AFTER_NORMALIZED_ARTIFACT)
            planned = self._store.plan_and_acquire_intent(
                action,
                expected_version=record.version,
                planned_at=self._now(),
            )
            record = planned.transaction
            self._crash(CoordinatorCrashPoint.AFTER_INTENT_ACQUIRED)
            if planned.disposition in {
                EnforcedStoreDisposition.ALIAS,
                EnforcedStoreDisposition.REVIEW_REQUIRED,
                EnforcedStoreDisposition.EXACT_RETRY,
            }:
                return self._readonly_admission_result(
                    requested_record=record,
                    owner_transaction_id=planned.acquisition.owner_transaction_id,
                    disposition=planned.acquisition.disposition,
                )
            if (
                planned.disposition is not EnforcedStoreDisposition.PLANNED
                or record.state is not TransactionState.PLANNED
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Normalized intent is not a fresh executable owner",
                    details={
                        "disposition": planned.disposition.value,
                        "intent_disposition": planned.acquisition.disposition.value,
                        "owner_transaction_id": planned.acquisition.owner_transaction_id,
                        "owner_version": planned.acquisition.owner_version,
                    },
                    review_required=(
                        planned.disposition is EnforcedStoreDisposition.REVIEW_REQUIRED
                    ),
                )
            authorization = await self._evaluate_authorization(
                action,
                purpose=AuthorizationRoundPurpose.STAGING,
                controlled_transaction_id=action.transaction_id,
            )
            self._check_authorization_valid(
                authorization,
                boundary="staging authorization persistence",
            )
            self._check_deadline(
                action.deadline,
                self._now(),
                boundary="staging authorization persistence",
            )
            authorized = self._store.authorize_for_staging(
                authorization.round,
                authority_decision=authorization.authority,
                policy_decision=authorization.policy,
                capability_ids=authorization.capability_ids,
                expected_transaction_version=record.version,
            )
            record = authorized.transaction
            self._crash(CoordinatorCrashPoint.AFTER_STAGING_AUTHORIZED)
            if authorization.round.verdict is not AuthorizationVerdict.ELIGIBLE:
                code = (
                    ErrorCode.POLICY_UNKNOWN
                    if authorization.round.verdict is AuthorizationVerdict.UNKNOWN
                    else ErrorCode.POLICY_DENIED
                )
                raise AgentKernelError(
                    code,
                    "Staging authority or policy did not produce an eligible decision",
                    details={"reason_code": authorization.round.reason_code},
                    review_required=authorization.round.verdict is AuthorizationVerdict.UNKNOWN,
                )
        except (Exception, CancelledError) as error:
            if record.state is TransactionState.NEW:
                if isinstance(error, CancelledError):
                    event = TransitionEvent.CANCELLED
                    reason = "CANCELLED"
                elif (
                    isinstance(error, AgentKernelError)
                    and error.code is ErrorCode.DEADLINE_EXCEEDED
                ):
                    event = TransitionEvent.DEADLINE_EXCEEDED
                    reason = ErrorCode.DEADLINE_EXCEEDED.value
                else:
                    event = TransitionEvent.VALIDATION_FAILED
                    reason = (
                        error.code.value
                        if isinstance(error, AgentKernelError)
                        else "VALIDATION_ERROR"
                    )
                if event in {
                    TransitionEvent.CANCELLED,
                    TransitionEvent.DEADLINE_EXCEEDED,
                }:
                    result = self._store.apply_control_transition(
                        tenant_id=record.tenant_id,
                        transaction_id=record.transaction_id,
                        expected_version=record.version,
                        transition_event=event,
                        recorded_at=self._now(),
                        evidence_refs=(request_ref,),
                        reason_code=reason,
                        recovery_timeout=self._config.recovery_deadline,
                    )
                    record = await self._settle_abort_handoff(
                        result.transaction,
                        cancellation=error if isinstance(error, CancelledError) else None,
                    )
                else:
                    result = self._store.apply_control_transition(
                        tenant_id=record.tenant_id,
                        transaction_id=record.transaction_id,
                        expected_version=record.version,
                        transition_event=TransitionEvent.VALIDATION_FAILED,
                        recorded_at=self._now(),
                        evidence_refs=(request_ref,),
                        reason_code=reason,
                    )
                    record = result.transaction
            elif record.state is TransactionState.PLANNED:
                if isinstance(error, CancelledError):
                    event = TransitionEvent.CANCELLED
                    reason = "CANCELLED"
                elif (
                    isinstance(error, AgentKernelError)
                    and error.code is ErrorCode.DEADLINE_EXCEEDED
                ):
                    event = TransitionEvent.DEADLINE_EXCEEDED
                    reason = ErrorCode.DEADLINE_EXCEEDED.value
                else:
                    event = TransitionEvent.AUTHORITY_OR_POLICY_DENIED
                    reason = (
                        error.code.value
                        if isinstance(error, AgentKernelError)
                        else "AUTHORIZATION_ERROR"
                    )
                evidence_ref = self._put_control_evidence(
                    transaction_id=record.transaction_id,
                    event=event.value,
                    reason_code=reason,
                    recorded_at=self._now(),
                )
                result = self._store.apply_control_transition(
                    tenant_id=record.tenant_id,
                    transaction_id=record.transaction_id,
                    expected_version=record.version,
                    transition_event=event,
                    recorded_at=self._now(),
                    evidence_refs=(evidence_ref,),
                    reason_code=reason,
                    recovery_timeout=self._config.recovery_deadline,
                )
                record = result.transaction
                if event in {
                    TransitionEvent.CANCELLED,
                    TransitionEvent.DEADLINE_EXCEEDED,
                }:
                    record = await self._settle_abort_handoff(
                        record,
                        cancellation=error if isinstance(error, CancelledError) else None,
                    )
            raise
        return EnforcedTransactionSession(
            coordinator=self,
            request=request,
            trusted_context=trusted_context,
            admitted=admitted,
            admitted_manifest=admitted_manifest,
            action=action,
            proposal_ref=proposal_ref,
            action_ref=action_ref,
            staging_authorization=authorization,
            initial_record=record,
        )

    async def _evaluate_authorization(
        self,
        action: NormalizedAction,
        *,
        purpose: AuthorizationRoundPurpose,
        controlled_transaction_id: str,
        operation_deadline: datetime | None = None,
    ) -> _AuthorizationEvidence:
        evaluated_at = self._now()
        purpose_name = purpose.value.lower()
        evaluation_deadline = (
            action.deadline
            if operation_deadline is None
            else min(action.deadline, operation_deadline)
        )
        self._check_deadline(
            evaluation_deadline,
            evaluated_at,
            boundary=f"{purpose_name} authority evaluation",
        )
        supplied_snapshot = await self._await_provider(
            lambda: self._authority_snapshots.snapshot_for(
                action=action,
                purpose=purpose,
                evaluated_at=evaluated_at,
            ),
            deadline=evaluation_deadline,
            boundary=f"{purpose_name} authority snapshot",
        )
        snapshot = AuthoritySnapshot.model_validate(supplied_snapshot.model_dump(mode="python"))
        self._check_deadline(
            evaluation_deadline,
            self._now(),
            boundary=f"{purpose_name} authority snapshot",
        )
        authority_snapshot_ref = self._put_model(snapshot)
        authority_context = AuthorityEvaluationContext(
            tenant_id=action.tenant_id,
            principal_id=action.principal_id,
            subject=action.agent_id,
            audience=self._config.authority_audience,
            goal_id=action.goal_id,
            run_id=action.run_id,
            actor_id=action.actor_id,
            on_behalf_of=action.on_behalf_of,
            configuration_digest=action.configuration_digest,
            evaluated_at=evaluated_at,
            authority_snapshot_digest=snapshot.snapshot_digest,
        )
        authority_context_ref = self._put_model(authority_context)
        authority = self._authority_evaluator.evaluate(
            action=action,
            context=authority_context,
            snapshot=snapshot,
        )
        capability_ids = (
            () if authority.reservation_plan is None else authority.reservation_plan.capability_ids
        )
        authority_valid_until: datetime | None = None
        if authority.verdict is AuthorityEvaluationVerdict.ALLOW:
            capabilities_by_id = {
                capability.capability_id: capability for capability in snapshot.capabilities
            }
            if not capability_ids or any(
                capability_id not in capabilities_by_id for capability_id in capability_ids
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Eligible authority lacks every selected capability grant",
                )
            authority_valid_until = min(
                capabilities_by_id[capability_id].expires_at for capability_id in capability_ids
            )
        authorization_deadline = (
            evaluation_deadline
            if authority_valid_until is None
            else min(evaluation_deadline, authority_valid_until)
        )
        self._check_deadline(
            authorization_deadline,
            self._now(),
            boundary=f"{purpose_name} authority decision",
        )
        authority_decision_ref = self._put_model(authority)
        supplied_inputs = await self._await_provider(
            lambda: self._policy_inputs.inputs_for(
                action=action,
                authority_decision=authority,
                purpose=purpose,
                evaluated_at=evaluated_at,
            ),
            deadline=authorization_deadline,
            boundary=f"{purpose_name} policy inputs",
        )
        supplied = PolicyEvaluationInputs.model_validate(supplied_inputs.model_dump(mode="python"))
        self._check_deadline(
            authorization_deadline,
            self._now(),
            boundary=f"{purpose_name} policy inputs",
        )
        policy_snapshot_ref = self._put_model(supplied.snapshot)
        policy_inputs_ref = self._put_model(supplied)
        expected_resources = {
            canonical_digest(resource): resource for resource in action.resource_uses
        }
        supplied_resources = {
            resource.resource_use_ref: resource.resource_use for resource in supplied.resources
        }
        supplied_refs = tuple(resource.resource_use_ref for resource in supplied.resources)
        if (
            len(supplied.resources) != len(action.resource_uses)
            or len(set(supplied_refs)) != len(supplied_refs)
            or supplied_resources != expected_resources
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Policy provider did not supply all-and-only normalized resource uses",
            )
        policy = evaluate_policy_layers(
            normalized_action=action,
            authority_decision=authority,
            policy_snapshot=supplied.snapshot,
            layers=supplied.layers,
            resources=supplied.resources,
            unknown_facts=supplied.unknown_facts,
        )
        self._check_deadline(
            authorization_deadline,
            self._now(),
            boundary=f"{purpose_name} policy decision",
        )
        policy_decision_ref = self._put_model(policy)
        if authority.verdict is AuthorityEvaluationVerdict.DENY:
            verdict = AuthorizationVerdict.DENIED
            reason_code = authority.reason_code.value
        elif policy.verdict is PolicyVerdict.ELIGIBLE:
            verdict = AuthorizationVerdict.ELIGIBLE
            reason_code = policy.reason_code
        elif policy.verdict is PolicyVerdict.DENY and (
            policy.reason_code == ErrorCode.POLICY_UNKNOWN.value or bool(policy.unknown_facts)
        ):
            verdict = AuthorizationVerdict.UNKNOWN
            reason_code = ErrorCode.POLICY_UNKNOWN.value
        else:
            verdict = AuthorizationVerdict.DENIED
            reason_code = policy.reason_code

        if verdict is AuthorizationVerdict.ELIGIBLE and not capability_ids:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Eligible native authority lacks a capability reservation plan",
            )
        history = self._store.list_intent_history(
            tenant_id=action.tenant_id,
            intent_hash=action.intent_hash,
        )
        if not history:
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Intent owner history is empty")
        head = history[-1]
        reservation: CapabilityChainReservation | None = None
        if verdict is AuthorizationVerdict.ELIGIBLE:
            if purpose is AuthorizationRoundPurpose.PRECOMMIT:
                reservation = self._store.get_capability_chain(
                    tenant_id=action.tenant_id,
                    goal_id=action.goal_id,
                    run_id=action.run_id,
                    intent_hash=action.intent_hash,
                )
                if reservation.state is not CapabilityReservationState.RESERVED:
                    raise AgentKernelError(
                        ErrorCode.AUTHORITY_MISSING,
                        "Precommit revalidation lost its reserved capability fence",
                    )
            else:
                reservation = self._store.preview_capability_chain_reservation(
                    tenant_id=action.tenant_id,
                    goal_id=action.goal_id,
                    run_id=action.run_id,
                    intent_hash=action.intent_hash,
                    capability_ids=capability_ids,
                    reserved_at=evaluated_at,
                )
        purpose_token = purpose.value.lower()
        round_id = _stable_id(
            f"authorization.{purpose_token}",
            {
                "tenant_id": action.tenant_id,
                "controlled_transaction_id": controlled_transaction_id,
                "subject_transaction_id": action.transaction_id,
                "owner_version": head.owner_version,
            },
        )
        authority_id = _stable_id(
            "decision.authority",
            {"tenant_id": action.tenant_id, "round_id": round_id},
        )
        policy_id = _stable_id(
            "decision.policy",
            {"tenant_id": action.tenant_id, "round_id": round_id},
        )
        round_record = AuthorizationRoundRecord.create(
            tenant_id=action.tenant_id,
            controlled_transaction_id=controlled_transaction_id,
            subject_transaction_id=action.transaction_id,
            subject_intent_hash=action.intent_hash,
            subject_normalized_action_digest=canonical_digest(action),
            round_id=round_id,
            purpose=purpose,
            verdict=verdict,
            authority_snapshot_id=snapshot.snapshot_id,
            authority_snapshot_digest=snapshot.snapshot_digest,
            authority_snapshot_ref=authority_snapshot_ref,
            authority_context_ref=authority_context_ref,
            authority_decision_id=authority_id,
            authority_decision_record_digest=decision_snapshot_digest(
                tenant_id=action.tenant_id,
                kind=DecisionKind.AUTHORITY,
                decision_id=authority_id,
                transaction_id=action.transaction_id,
                intent_hash=action.intent_hash,
                decision=authority,
            ),
            authority_decision_digest=authority.decision_digest,
            authority_decision_ref=authority_decision_ref,
            policy_decision_id=policy_id,
            policy_decision_record_digest=decision_snapshot_digest(
                tenant_id=action.tenant_id,
                kind=DecisionKind.POLICY,
                decision_id=policy_id,
                transaction_id=action.transaction_id,
                intent_hash=action.intent_hash,
                decision=policy,
            ),
            policy_decision_digest=policy.aggregate_digest,
            policy_inputs_ref=policy_inputs_ref,
            policy_snapshot_digest=supplied.snapshot.snapshot_digest,
            policy_snapshot_ref=policy_snapshot_ref,
            policy_decision_ref=policy_decision_ref,
            capability_reservation_plan_digest=(
                None
                if reservation is None
                else capability_reservation_plan_digest(
                    tenant_id=action.tenant_id,
                    goal_id=action.goal_id,
                    run_id=action.run_id,
                    intent_hash=action.intent_hash,
                    capability_ids=capability_ids,
                )
            ),
            capability_reservation_digest=(
                None if reservation is None else capability_reservation_digest(reservation)
            ),
            reservation_version=None if reservation is None else reservation.version,
            reservation_goal_id=None if reservation is None else action.goal_id,
            reservation_run_id=None if reservation is None else action.run_id,
            owner_version=head.owner_version,
            owner_history_sequence=head.sequence,
            owner_history_digest=head.history_digest,
            allowed_modes=policy.allowed_modes if verdict is AuthorizationVerdict.ELIGIBLE else (),
            obligations=policy.obligations if verdict is AuthorizationVerdict.ELIGIBLE else (),
            reason_code=reason_code,
            evaluated_at=evaluated_at,
            authority_valid_until=(
                authority_valid_until if verdict is AuthorizationVerdict.ELIGIBLE else None
            ),
        )
        # These artifacts are immutable forensic evidence. The SQL store additionally persists
        # its own content-bound decision records for atomic authorization.
        self._check_deadline(
            authorization_deadline,
            self._now(),
            boundary=f"{purpose_name} authorization evidence",
        )
        self._put_model(round_record)
        self._validate_authorization_artifacts(round_record)
        return _AuthorizationEvidence(
            round=round_record,
            authority=authority,
            policy=policy,
            # A denied/unknown round retains the evaluator decision as evidence, but it
            # must not expose that decision's candidate plan as reservable authority.
            capability_ids=(capability_ids if verdict is AuthorizationVerdict.ELIGIBLE else ()),
            reservation=reservation,
            authority_valid_until=(
                authority_valid_until if verdict is AuthorizationVerdict.ELIGIBLE else None
            ),
        )

    def _validate_recovery_handoff_failure_evidence(
        self,
        handoff: RecoveryActionHandoff,
        *,
        tenant_id: str,
        late_reports: Mapping[str, LateRecoveryReportRecord] | None = None,
    ) -> None:
        status = handoff.failure_evidence_status
        if status is RecoveryHandoffFailureEvidenceStatus.NONE:
            return
        if status is RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE:
            return
        evidence_ref = handoff.failure_evidence_ref
        if evidence_ref is None or handoff.closed_at is None or handoff.failure_reason_code is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Available recovery handoff evidence lacks its terminal bindings",
            )
        late_report = (
            self._store.get_late_recovery_report(
                tenant_id=tenant_id,
                transaction_id=handoff.binding.target_transaction_id,
                recovery_id=handoff.binding.recovery_id,
            )
            if late_reports is None
            else late_reports.get(handoff.binding.recovery_id)
        )
        if late_report is not None:
            if late_report.operation_evidence_ref != evidence_ref:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late recovery report differs from its handoff failure evidence",
                )
            self._validate_late_recovery_handoff_evidence(
                handoff,
                evidence_ref=evidence_ref,
                late_report=late_report,
            )
            return
        evidence = self._get_artifact_model(evidence_ref, CoordinatorEvidence)
        expected_event = (
            TransitionEvent.STAGING_DISCARD_FAILED.value
            if handoff.binding.recovery_kind is RecoveryWorkKind.DISCARD_STAGING
            else "recovery.authorization_handoff_failed"
        )
        expected_subject_ref = (
            handoff.binding.target_evidence_ref
            if handoff.binding.recovery_kind is RecoveryWorkKind.DISCARD_STAGING
            else handoff.binding_ref
        )
        if (
            canonical_digest(evidence) != evidence_ref
            or evidence.profile != "agentkernel.coordinator-evidence/v1"
            or evidence.transaction_id != handoff.binding.target_transaction_id
            or evidence.event != expected_event
            or evidence.reason_code != handoff.failure_reason_code
            or evidence.recorded_at != handoff.closed_at
            or evidence.subject_ref != expected_subject_ref
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff failure evidence differs from its durable association",
            )

    def _validate_late_recovery_handoff_evidence(
        self,
        handoff: RecoveryActionHandoff,
        *,
        evidence_ref: str,
        late_report: LateRecoveryReportRecord,
    ) -> None:
        """Validate the adapter observation (or control fallback) owning a late result."""

        action = handoff.action
        if action is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery handoff lost its attached recovery action",
            )
        binding = handoff.binding
        if (
            late_report.operation_evidence_ref != evidence_ref
            or evidence_ref not in late_report.evidence_refs
            or late_report.reason_code != handoff.failure_reason_code
            or late_report.reported_at != handoff.closed_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery report differs from its terminal handoff",
            )
        reported_at = late_report.reported_at
        work = self._store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=binding.target_transaction_id,
            recovery_id=binding.recovery_id,
        )
        permit = work.permit
        if permit is None or work.permit_ref is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery handoff lost its operation permit",
            )
        target_action = self._store.get_normalized_action(
            action.tenant_id,
            binding.target_transaction_id,
        ).action
        dispatch: CommitDispatchRecord | None = None
        queried_dispatch: CommitDispatchRecord | None = None
        if work.kind is RecoveryWorkKind.DISCARD_STAGING:
            evidence_kind = "discard_staging"
            subject_ref = work.target_evidence_ref
        else:
            dispatch = self._store.get_commit_dispatch(
                tenant_id=action.tenant_id,
                transaction_id=binding.target_transaction_id,
            )
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                queried_dispatch = self._get_artifact_model(
                    work.target_evidence_ref,
                    CommitDispatchRecord,
                )
                if (
                    canonical_digest(queried_dispatch) != work.target_evidence_ref
                    or queried_dispatch.tenant_id != dispatch.tenant_id
                    or queried_dispatch.transaction_id != dispatch.transaction_id
                    or queried_dispatch.intent_hash != dispatch.intent_hash
                    or queried_dispatch.dispatch_id != dispatch.dispatch_id
                    or queried_dispatch.owner_version != dispatch.owner_version
                    or queried_dispatch.permit != dispatch.permit
                    or queried_dispatch.permit_ref != dispatch.permit_ref
                    or queried_dispatch.created_at != dispatch.created_at
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Late reconciliation target differs from its queried dispatch generation",
                    )
                evidence_kind = "reconciliation"
                subject_ref = canonical_digest(
                    IntentRecord(
                        intent_hash=target_action.intent_hash,
                        transaction_id=target_action.transaction_id,
                        idempotency_key=(
                            target_action.idempotency_key or target_action.intent_hash
                        ),
                        dispatched=True,
                        outcome_receipt_ref=queried_dispatch.effect_receipt_ref,
                        created_at=queried_dispatch.created_at,
                    )
                )
            else:
                evidence_kind = (
                    "rollback" if work.kind is RecoveryWorkKind.ROLLBACK else "compensation"
                )
                if dispatch.effect_receipt_ref is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Late effect recovery lost its authoritative receipt",
                    )
                subject_ref = dispatch.effect_receipt_ref
        operation_content = self._get_artifact(evidence_ref)
        try:
            fallback = CoordinatorEvidence.model_validate_json(operation_content)
        except ValueError:
            fallback = None
        if fallback is not None:
            operation_reason_code = (
                fallback.reason_code
                if late_report.schema_version == "1.0"
                else late_report.operation_reason_code
            )
            allowed_events = {
                RecoveryWorkKind.DISCARD_STAGING: {
                    TransitionEvent.STAGING_DISCARD_FAILED.value,
                    "recovery.execution_failed",
                },
                RecoveryWorkKind.ROLLBACK: {
                    "recovery.authorization_handoff_failed",
                    "recovery.execution_failed",
                },
                RecoveryWorkKind.COMPENSATE: {
                    "recovery.authorization_handoff_failed",
                    "recovery.execution_failed",
                },
                RecoveryWorkKind.RECONCILE_DISPATCH: {
                    "recovery.authorization_handoff_failed",
                    "reconciliation.query_failed",
                },
            }[work.kind]
            expected_subject = {
                TransitionEvent.STAGING_DISCARD_FAILED.value: work.target_evidence_ref,
                "recovery.authorization_handoff_failed": handoff.binding_ref,
                "recovery.execution_failed": work.permit_ref,
                "reconciliation.query_failed": work.permit_ref,
            }.get(fallback.event)
            expected_late_reason = {
                TransitionEvent.STAGING_DISCARD_FAILED.value: (ErrorCode.DEADLINE_EXCEEDED.value),
                "recovery.authorization_handoff_failed": (ErrorCode.DEADLINE_EXCEEDED.value),
                "recovery.execution_failed": ("RECOVERY_RESULT_AFTER_PERMIT_DEADLINE"),
                "reconciliation.query_failed": ("RECONCILIATION_RESULT_AFTER_PERMIT_DEADLINE"),
            }.get(fallback.event)
            allowed_inner_reasons = {
                *(code.value for code in ErrorCode),
                "RECOVERY_CANCELLED_AFTER_PROVIDER_ENTRY",
                "RECOVERY_EXECUTION_FAILED",
                "RECONCILIATION_CANCELLED_AFTER_PROVIDER_ENTRY",
                "RECONCILIATION_QUERY_FAILED",
            }
            if (
                canonical_digest(fallback) != evidence_ref
                or fallback.transaction_id != binding.target_transaction_id
                or fallback.event not in allowed_events
                or expected_subject is None
                or fallback.subject_ref != expected_subject
                or fallback.recorded_at < permit.issued_at
                or fallback.recorded_at > reported_at
                or (
                    fallback.event
                    not in {"recovery.execution_failed", "reconciliation.query_failed"}
                    and fallback.recorded_at != reported_at
                )
                or (
                    fallback.event
                    not in {"recovery.execution_failed", "reconciliation.query_failed"}
                    and fallback.reason_code != late_report.reason_code
                )
                or (
                    fallback.event in {"recovery.execution_failed", "reconciliation.query_failed"}
                    and fallback.reason_code not in allowed_inner_reasons
                )
                or operation_reason_code != fallback.reason_code
                or late_report.reason_code != expected_late_reason
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late recovery control evidence differs from its durable report",
                )
            return

        try:
            observation = AdapterObservation.model_validate_json(operation_content)
        except ValueError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery operation evidence has an unsupported artifact type",
            ) from error
        if canonical_digest(observation) != evidence_ref:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery observation differs from its content address",
            )
        if late_report.operation_reason_code is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late adapter observation unexpectedly carries a control reason",
            )

        report_types: tuple[
            type[ReconcileReport] | type[RecoveryReport] | type[VerificationReport],
            ...,
        ] = (
            (ReconcileReport, VerificationReport)
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
            else (RecoveryReport,)
        )
        reports: list[ReconcileReport | RecoveryReport | VerificationReport] = []
        reconciliation_reports: list[tuple[str, ReconcileReport]] = []
        for report_ref in late_report.evidence_refs:
            content = self._get_artifact(report_ref)
            for report_type in report_types:
                try:
                    candidate = report_type.model_validate_json(content)
                except ValueError:
                    continue
                if canonical_digest(candidate) != report_ref:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Late recovery report artifact differs from its content address",
                    )
                if isinstance(candidate, ReconcileReport):
                    reconciliation_reports.append((report_ref, candidate))
                if candidate.evidence_refs == (evidence_ref,):
                    reports.append(candidate)
        if len(reports) != 1 or (
            work.kind is RecoveryWorkKind.RECONCILE_DISPATCH and len(reconciliation_reports) != 1
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery evidence must identify one query and one exact operation report",
            )
        report = reports[0]
        reconcile_report: ReconcileReport | None = None
        receipt_ref: str | None = None
        if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
            if dispatch is None or queried_dispatch is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late reconciliation lost its dispatch generation",
                )
            reconcile_ref, reconcile_report = reconciliation_reports[0]
            receipt_ref = (
                None
                if reconcile_report.receipt is None
                else canonical_digest(reconcile_report.receipt)
            )
            if (
                reconcile_ref not in late_report.evidence_refs
                or not set(reconcile_report.evidence_refs).issubset(late_report.evidence_refs)
                or (receipt_ref is not None and receipt_ref not in late_report.evidence_refs)
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late reconciliation report escaped its evidence closure",
                )
            if receipt_ref is not None:
                retained_receipt = self._get_artifact_model(receipt_ref, EffectReceipt)
                if retained_receipt != reconcile_report.receipt:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Late reconciliation receipt differs from its retained artifact",
                    )
                self._validate_effect_receipt_identity(
                    target_action,
                    queried_dispatch,
                    retained_receipt,
                )
            self._validate_adapter_observation(
                reconcile_report.evidence_refs,
                evidence_kind="reconciliation",
                action=target_action,
                adapter_manifest_digest=work.adapter_manifest_digest,
                subject_ref=subject_ref,
                operation_permit_ref=work.permit_ref,
                authority_permit_ref=work.permit_ref,
                subject_authority_ref=permit.target_evidence_ref,
                operation_status=reconcile_report.status.value,
                permit_issued_at=permit.issued_at,
                permit_deadline=permit.deadline,
                received_at=reported_at,
                dispatch=queried_dispatch,
                allow_late=True,
            )
        if isinstance(report, VerificationReport):
            if (
                reconcile_report is None
                or reconcile_report.status is not ReconcileStatus.COMMITTED
                or receipt_ref is None
                or dispatch is None
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late verification report lost its committed reconciliation subject",
                )
            verification_permit_ref = observation.operation_permit_ref
            verification_permit = self._get_artifact_model(
                verification_permit_ref,
                VerificationPermit,
            )
            if (
                canonical_digest(verification_permit) != verification_permit_ref
                or verification_permit.tenant_id != work.tenant_id
                or verification_permit.transaction_id != work.transaction_id
                or verification_permit.intent_hash != work.intent_hash
                or verification_permit.normalized_action_digest != canonical_digest(target_action)
                or verification_permit.adapter_manifest_digest != work.adapter_manifest_digest
                or verification_permit.authorization_round_id != work.authorization_round_id
                or verification_permit.authorization_round_digest != work.authorization_round_digest
                or verification_permit.lease_id != permit.lease_id
                or verification_permit.worker_id != permit.worker_id
                or verification_permit.fencing_token != permit.fencing_token
                or verification_permit.phase is not VerificationPhase.COMMITTED
                or verification_permit.subject_ref != receipt_ref
                or verification_permit.authority_permit_digest != permit.permit_digest
                or verification_permit.authority_permit_ref != work.permit_ref
                or verification_permit.subject_permit_digest != dispatch.permit.permit_digest
                or verification_permit.subject_permit_ref != dispatch.permit_ref
                or verification_permit.issued_at < permit.issued_at
                or verification_permit.deadline != permit.deadline
                or verification_permit.issued_at > reported_at
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late verification permit differs from its recovery authority",
                )
            _observation_ref, evidence = self._validate_adapter_observation(
                report.evidence_refs,
                evidence_kind="committed_verification",
                action=target_action,
                adapter_manifest_digest=work.adapter_manifest_digest,
                subject_ref=receipt_ref,
                operation_permit_ref=verification_permit_ref,
                authority_permit_ref=work.permit_ref,
                subject_authority_ref=dispatch.permit_ref,
                operation_status=report.status.value,
                permit_issued_at=verification_permit.issued_at,
                permit_deadline=verification_permit.deadline,
                received_at=reported_at,
                dispatch=dispatch,
                expected_observed_state_digest=(
                    self._get_artifact_model(receipt_ref, EffectReceipt).target_version_after
                    if report.status is VerificationStatus.PASS
                    else None
                ),
                allow_late=True,
            )
            if canonical_digest(evidence) != evidence_ref:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late verification observation lost its content address",
                )
            return
        expected_observed_state_digest = (
            None if isinstance(report, ReconcileReport) else report.restored_state_digest
        )
        _observation_ref, evidence = self._validate_adapter_observation(
            report.evidence_refs,
            evidence_kind=evidence_kind,
            action=target_action,
            adapter_manifest_digest=work.adapter_manifest_digest,
            subject_ref=subject_ref,
            operation_permit_ref=work.permit_ref,
            authority_permit_ref=work.permit_ref,
            subject_authority_ref=permit.target_evidence_ref,
            operation_status=report.status.value,
            permit_issued_at=permit.issued_at,
            permit_deadline=permit.deadline,
            received_at=reported_at,
            dispatch=dispatch,
            expected_observed_state_digest=expected_observed_state_digest,
            allow_late=True,
        )
        if canonical_digest(evidence) != evidence_ref:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late adapter observation lost its content or durable-state evidence",
            )

    def _derive_legacy_reconciliation_operation_evidence_ref(
        self,
        work: RecoveryWorkRecord,
        attempt: ReconciliationAttemptRecord,
        *,
        permit_ref: str,
    ) -> str:
        """Derive one terminal operation from a published 1.0 evidence closure."""

        completion_refs = attempt.completion_evidence_refs
        if (
            attempt.schema_version != "1.0"
            or attempt.outcome is None
            or attempt.completed_at is None
            or completion_refs is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Legacy reconciliation lacks a completed evidence closure",
            )
        control_refs: list[str] = []
        reconcile_reports: list[ReconcileReport] = []
        verification_reports: list[VerificationReport] = []
        for artifact_ref in completion_refs:
            content = self._get_artifact(artifact_ref)
            try:
                control = CoordinatorEvidence.model_validate_json(content)
            except ValueError:
                control = None
            if control is not None:
                if canonical_digest(control) != artifact_ref:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Legacy reconciliation control evidence lost its content address",
                    )
                if (
                    control.transaction_id == work.transaction_id
                    and control.event == "reconciliation.query_failed"
                    and control.recorded_at == attempt.completed_at
                    and control.subject_ref == permit_ref
                ):
                    control_refs.append(artifact_ref)
                continue
            for report_type in (ReconcileReport, VerificationReport):
                try:
                    report = report_type.model_validate_json(content)
                except ValueError:
                    continue
                if canonical_digest(report) != artifact_ref:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Legacy reconciliation report lost its content address",
                    )
                if isinstance(report, ReconcileReport):
                    reconcile_reports.append(report)
                else:
                    verification_reports.append(report)

        if control_refs:
            if len(control_refs) != 1:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Legacy reconciliation has ambiguous terminal control evidence",
                )
            return control_refs[0]
        if len(reconcile_reports) != 1 or len(verification_reports) > 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Legacy reconciliation has an ambiguous operation report closure",
            )
        reconcile_report = reconcile_reports[0]
        owner: ReconcileReport | VerificationReport
        if verification_reports:
            if reconcile_report.status is not ReconcileStatus.COMMITTED:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Legacy reconciliation verification lacks a committed query",
                )
            owner = verification_reports[0]
        else:
            owner = reconcile_report
        if len(owner.evidence_refs) != 1 or owner.evidence_refs[0] not in completion_refs:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Legacy reconciliation operation owner is not uniquely retained",
            )
        return owner.evidence_refs[0]

    def _historical_reconciliation_permit(
        self,
        work: RecoveryWorkRecord,
        attempt: ReconciliationAttemptRecord,
    ) -> tuple[RecoveryPermit, str]:
        """Load and re-prove the exact permit used by a reclaimed attempt."""

        current_permit = work.permit
        completion_refs = attempt.completion_evidence_refs
        if (
            current_permit is None
            or completion_refs is None
            or attempt.completed_at is None
            or not 1 <= attempt.attempt < work.attempt
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical reconciliation lacks a reclaim permit closure",
            )
        lease = self._store.get_worker_lease(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            lease_id=attempt.lease_id,
        )
        authorization_round = self._store.get_authorization_round(
            tenant_id=work.tenant_id,
            controlled_transaction_id=work.transaction_id,
            round_id=work.authorization_round_id,
        )
        if (
            authorization_round.authority_valid_until is None
            or lease.purpose is not LeasePurpose.RECONCILIATION
            or lease.fencing_token != attempt.fencing_token
            or lease.released_at != attempt.completed_at
            or lease.acquired_at > attempt.started_at
            or attempt.started_at >= lease.expires_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical reconciliation permit lost its worker fence",
            )
        expected = RecoveryPermit.create(
            **{
                **current_permit.model_dump(
                    mode="python",
                    exclude={"permit_digest"},
                ),
                "lease_id": lease.lease_id,
                "worker_id": lease.worker_id,
                "fencing_token": lease.fencing_token,
                "issued_at": lease.acquired_at,
                "deadline": min(
                    work.deadline,
                    lease.expires_at,
                    authorization_round.authority_valid_until,
                ).astimezone(UTC),
            }
        )
        candidates: list[tuple[str, RecoveryPermit]] = []
        for artifact_ref in attempt.evidence_refs:
            content = self._get_artifact(artifact_ref)
            try:
                candidate = RecoveryPermit.model_validate_json(content)
            except ValueError:
                continue
            if canonical_digest(candidate) != artifact_ref:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Historical recovery permit lost its content address",
                )
            if (
                candidate.lease_id == attempt.lease_id
                and candidate.fencing_token == attempt.fencing_token
            ):
                candidates.append((artifact_ref, candidate))
        if (
            len(candidates) != 1
            or candidates[0][1] != expected
            or candidates[0][0] not in completion_refs
            or not expected.issued_at <= attempt.started_at < expected.deadline
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical reconciliation has no unique exact recovery permit",
            )
        return candidates[0][1], candidates[0][0]

    def _current_reconciliation_permit(
        self,
        work: RecoveryWorkRecord,
        attempt: ReconciliationAttemptRecord | None,
    ) -> tuple[RecoveryPermit, str]:
        """Reload the exact current permit and, once started, its attempt retention."""

        permit = work.permit
        permit_ref = work.permit_ref
        if permit is None or permit_ref is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Current reconciliation lost its recovery permit binding",
            )
        retained = self._get_artifact_model(permit_ref, RecoveryPermit)
        if (
            canonical_digest(retained) != permit_ref
            or retained != permit
            or (attempt is not None and permit_ref not in attempt.evidence_refs)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Current reconciliation permit differs from its retained attempt closure",
            )
        return retained, permit_ref

    def _validate_reconciliation_attempt_operation_evidence(
        self,
        work: RecoveryWorkRecord,
        attempt: ReconciliationAttemptRecord,
        *,
        historical_permit: RecoveryPermit | None = None,
        historical_permit_ref: str | None = None,
    ) -> None:
        """Validate the exact provider operation (or control fallback) ending an attempt."""

        if (historical_permit is None) != (historical_permit_ref is None):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical reconciliation permit binding is incomplete",
            )
        if historical_permit is None:
            permit, permit_ref = self._current_reconciliation_permit(work, attempt)
        else:
            if historical_permit_ref is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Historical reconciliation permit reference is absent",
                )
            permit = historical_permit
            permit_ref = historical_permit_ref
            if (
                canonical_digest(permit) != permit_ref
                or permit_ref not in attempt.evidence_refs
                or (
                    attempt.completion_evidence_refs is not None
                    and permit_ref not in attempt.completion_evidence_refs
                )
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Historical reconciliation permit escaped its attempt closure",
                )
        evidence_ref = attempt.operation_evidence_ref
        if evidence_ref is None and attempt.schema_version == "1.0":
            evidence_ref = self._derive_legacy_reconciliation_operation_evidence_ref(
                work,
                attempt,
                permit_ref=permit_ref,
            )
        completed_at = attempt.completed_at
        completion_refs = attempt.completion_evidence_refs
        if (
            work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
            or attempt.outcome is None
            or completed_at is None
            or completion_refs is None
            or evidence_ref is None
            or evidence_ref not in completion_refs
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Terminal reconciliation lost its exact operation evidence binding",
            )
        operation_content = self._get_artifact(evidence_ref)
        try:
            fallback = CoordinatorEvidence.model_validate_json(operation_content)
        except ValueError:
            fallback = None
        if fallback is not None:
            operation_reason_code = (
                fallback.reason_code
                if attempt.schema_version == "1.0"
                else attempt.operation_reason_code
            )
            allowed_inner_reasons = {
                *(code.value for code in ErrorCode),
                "RECONCILIATION_CANCELLED_AFTER_PROVIDER_ENTRY",
                "RECOVERY_LEASE_EXPIRED",
                "RECONCILIATION_QUERY_FAILED",
            }
            if (
                canonical_digest(fallback) != evidence_ref
                or attempt.outcome is not ReconciliationOutcome.UNKNOWN
                or operation_reason_code is None
                or fallback.transaction_id != work.transaction_id
                or fallback.event != "reconciliation.query_failed"
                or fallback.reason_code != operation_reason_code
                or fallback.reason_code not in allowed_inner_reasons
                or fallback.recorded_at != completed_at
                or fallback.subject_ref != permit_ref
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation control evidence differs from its completed attempt",
                )
            return

        try:
            observation = AdapterObservation.model_validate_json(operation_content)
        except ValueError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation operation evidence has an unsupported artifact type",
            ) from error
        if (
            canonical_digest(observation) != evidence_ref
            or attempt.operation_reason_code is not None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation adapter operation differs from its completed attempt",
            )

        action = self._store.get_normalized_action(
            work.tenant_id,
            work.transaction_id,
        ).action
        dispatch = self._store.get_commit_dispatch(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
        )
        queried_dispatch = self._get_artifact_model(
            work.target_evidence_ref,
            CommitDispatchRecord,
        )
        if (
            canonical_digest(queried_dispatch) != work.target_evidence_ref
            or queried_dispatch.tenant_id != dispatch.tenant_id
            or queried_dispatch.transaction_id != dispatch.transaction_id
            or queried_dispatch.intent_hash != dispatch.intent_hash
            or queried_dispatch.dispatch_id != dispatch.dispatch_id
            or queried_dispatch.owner_version != dispatch.owner_version
            or queried_dispatch.permit != dispatch.permit
            or queried_dispatch.permit_ref != dispatch.permit_ref
            or queried_dispatch.created_at != dispatch.created_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation query target differs from its durable dispatch generation",
            )
        intent_ref = canonical_digest(
            IntentRecord(
                intent_hash=action.intent_hash,
                transaction_id=action.transaction_id,
                idempotency_key=action.idempotency_key or action.intent_hash,
                dispatched=True,
                outcome_receipt_ref=queried_dispatch.effect_receipt_ref,
                created_at=queried_dispatch.created_at,
            )
        )
        if intent_ref not in completion_refs:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation attempt lost its queried intent evidence",
            )
        self._get_artifact(intent_ref)

        reconcile_reports: list[tuple[str, ReconcileReport]] = []
        verification_reports: list[tuple[str, VerificationReport]] = []
        operation_owners: list[tuple[str, ReconcileReport | VerificationReport]] = []
        for report_ref in completion_refs:
            content = self._get_artifact(report_ref)
            for report_type in (ReconcileReport, VerificationReport):
                try:
                    candidate = report_type.model_validate_json(content)
                except ValueError:
                    continue
                if canonical_digest(candidate) != report_ref:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Reconciliation report differs from its content address",
                    )
                if isinstance(candidate, ReconcileReport):
                    reconcile_reports.append((report_ref, candidate))
                else:
                    verification_reports.append((report_ref, candidate))
                if candidate.evidence_refs == (evidence_ref,):
                    operation_owners.append((report_ref, candidate))
        if len(reconcile_reports) != 1 or len(operation_owners) != 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion must identify one query and one final operation",
            )

        reconcile_ref, reconcile_report = reconcile_reports[0]
        if reconcile_ref not in completion_refs or not set(reconcile_report.evidence_refs).issubset(
            completion_refs
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation query report escaped its completion evidence",
            )
        receipt_ref = (
            None if reconcile_report.receipt is None else canonical_digest(reconcile_report.receipt)
        )
        if receipt_ref != attempt.effect_receipt_ref or (
            receipt_ref is not None and receipt_ref not in completion_refs
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation receipt differs from its completed attempt",
            )
        if receipt_ref is not None:
            retained_receipt = self._get_artifact_model(receipt_ref, EffectReceipt)
            if retained_receipt != reconcile_report.receipt:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation report receipt differs from its retained artifact",
                )
            self._validate_effect_receipt_identity(
                action,
                queried_dispatch,
                retained_receipt,
            )
        self._validate_adapter_observation(
            reconcile_report.evidence_refs,
            evidence_kind="reconciliation",
            action=action,
            adapter_manifest_digest=work.adapter_manifest_digest,
            subject_ref=intent_ref,
            operation_permit_ref=permit_ref,
            authority_permit_ref=permit_ref,
            subject_authority_ref=permit.target_evidence_ref,
            operation_status=reconcile_report.status.value,
            permit_issued_at=permit.issued_at,
            permit_deadline=permit.deadline,
            received_at=completed_at,
            dispatch=dispatch,
            allow_late=False,
        )

        owner_ref, owner = operation_owners[0]
        if isinstance(owner, ReconcileReport):
            expected_outcome = {
                ReconcileStatus.NO_EFFECT: (
                    ReconciliationOutcome.NO_EFFECT
                    if receipt_ref is None
                    else ReconciliationOutcome.PARTIAL_OR_INVALID
                ),
                ReconcileStatus.PARTIAL_OR_INVALID: (ReconciliationOutcome.PARTIAL_OR_INVALID),
                ReconcileStatus.UNKNOWN: ReconciliationOutcome.UNKNOWN,
                ReconcileStatus.COMMITTED: ReconciliationOutcome.PARTIAL_OR_INVALID,
            }[owner.status]
            if (
                owner_ref != reconcile_ref
                or verification_reports
                or (owner.status is ReconcileStatus.COMMITTED and receipt_ref is not None)
                or attempt.outcome is not expected_outcome
                or (
                    attempt.no_effect_evidence_ref
                    != (
                        evidence_ref
                        if expected_outcome is ReconciliationOutcome.NO_EFFECT
                        else None
                    )
                )
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation query observation is not the final attempted operation",
                )
            return

        if (
            len(verification_reports) != 1
            or owner_ref != verification_reports[0][0]
            or reconcile_report.status is not ReconcileStatus.COMMITTED
            or receipt_ref is None
            or receipt_ref != dispatch.effect_receipt_ref
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation verification lost its committed query result",
            )
        verification_permit_ref = observation.operation_permit_ref
        verification_permit = self._get_artifact_model(
            verification_permit_ref,
            VerificationPermit,
        )
        if (
            canonical_digest(verification_permit) != verification_permit_ref
            or verification_permit.tenant_id != work.tenant_id
            or verification_permit.transaction_id != work.transaction_id
            or verification_permit.intent_hash != work.intent_hash
            or verification_permit.normalized_action_digest != canonical_digest(action)
            or verification_permit.adapter_manifest_digest != work.adapter_manifest_digest
            or verification_permit.authorization_round_id != work.authorization_round_id
            or verification_permit.authorization_round_digest != work.authorization_round_digest
            or verification_permit.lease_id != permit.lease_id
            or verification_permit.worker_id != permit.worker_id
            or verification_permit.fencing_token != permit.fencing_token
            or verification_permit.phase is not VerificationPhase.COMMITTED
            or verification_permit.subject_ref != receipt_ref
            or verification_permit.authority_permit_digest != permit.permit_digest
            or verification_permit.authority_permit_ref != permit_ref
            or verification_permit.subject_permit_digest != dispatch.permit.permit_digest
            or verification_permit.subject_permit_ref != dispatch.permit_ref
            or verification_permit.issued_at < permit.issued_at
            or verification_permit.deadline != permit.deadline
            or verification_permit.issued_at > completed_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation verification permit differs from its recovery authority",
            )
        self._validate_adapter_observation(
            owner.evidence_refs,
            evidence_kind="committed_verification",
            action=action,
            adapter_manifest_digest=work.adapter_manifest_digest,
            subject_ref=receipt_ref,
            operation_permit_ref=verification_permit_ref,
            authority_permit_ref=permit_ref,
            subject_authority_ref=dispatch.permit_ref,
            operation_status=owner.status.value,
            permit_issued_at=verification_permit.issued_at,
            permit_deadline=verification_permit.deadline,
            received_at=completed_at,
            dispatch=dispatch,
            expected_observed_state_digest=(
                retained_receipt.target_version_after
                if owner.status is VerificationStatus.PASS
                else None
            ),
            allow_late=False,
        )
        expected_outcome = {
            VerificationStatus.PASS: ReconciliationOutcome.COMMITTED,
            VerificationStatus.FAIL: ReconciliationOutcome.PARTIAL_OR_INVALID,
            VerificationStatus.UNKNOWN: ReconciliationOutcome.UNKNOWN,
            VerificationStatus.ERROR: ReconciliationOutcome.UNKNOWN,
        }[owner.status]
        expected_committed_evidence = (
            (
                verification_permit.permit_digest,
                verification_permit_ref,
                owner_ref,
            )
            if expected_outcome is ReconciliationOutcome.COMMITTED
            else (None, None, None)
        )
        if (
            attempt.outcome is not expected_outcome
            or (
                attempt.committed_verification_permit_digest,
                attempt.committed_verification_permit_ref,
                attempt.committed_verification_ref,
            )
            != expected_committed_evidence
            or attempt.no_effect_evidence_ref is not None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation verification differs from its durable classification",
            )

    def _validate_recovery_completion_operation_evidence(
        self,
        work: RecoveryWorkRecord,
        completion: RecoveryCompletionReportRecord,
    ) -> None:
        """Validate the exact provider operation (or control fallback) ending recovery."""

        evidence_ref = completion.operation_evidence_ref
        if (
            work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
            or work.permit is None
            or work.permit_ref is None
            or evidence_ref not in completion.evidence_refs
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion lost its exact operation evidence binding",
            )
        operation_content = self._get_artifact(evidence_ref)
        try:
            fallback = CoordinatorEvidence.model_validate_json(operation_content)
        except ValueError:
            fallback = None
        if fallback is not None:
            allowed_inner_reasons = {
                *(code.value for code in ErrorCode),
                "RECOVERY_CANCELLED_AFTER_PROVIDER_ENTRY",
                "RECOVERY_EXECUTION_FAILED",
            }
            if (
                canonical_digest(fallback) != evidence_ref
                or completion.succeeded
                or completion.reason_code is None
                or fallback.transaction_id != work.transaction_id
                or fallback.event != "recovery.execution_failed"
                or fallback.reason_code != completion.reason_code
                or fallback.reason_code not in allowed_inner_reasons
                or fallback.recorded_at != completion.completed_at
                or fallback.subject_ref != work.permit_ref
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery control evidence differs from its completion report",
                )
            return

        try:
            observation = AdapterObservation.model_validate_json(operation_content)
        except ValueError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion operation has an unsupported artifact type",
            ) from error
        if canonical_digest(observation) != evidence_ref:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion observation differs from its content address",
            )
        reports: list[RecoveryReport] = []
        for report_ref in completion.evidence_refs:
            content = self._get_artifact(report_ref)
            try:
                report = RecoveryReport.model_validate_json(content)
            except ValueError:
                continue
            if canonical_digest(report) != report_ref:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery report differs from its content address",
                )
            if report.evidence_refs == (evidence_ref,):
                reports.append(report)
        if len(reports) != 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion must identify one exact operation report",
            )
        report = reports[0]
        expected_success = report.status is VerificationStatus.PASS
        expected_reason = None if expected_success else "RECOVERY_VERIFICATION_FAILED"
        if (
            completion.succeeded != expected_success
            or completion.reason_code != expected_reason
            or (expected_success and report.restored_state_digest is None)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery report differs from its durable classification",
            )
        action = self._store.get_normalized_action(
            work.tenant_id,
            work.transaction_id,
        ).action
        dispatch: CommitDispatchRecord | None = None
        if work.kind is RecoveryWorkKind.DISCARD_STAGING:
            evidence_kind = "discard_staging"
            subject_ref = work.target_evidence_ref
        else:
            dispatch = self._store.get_commit_dispatch(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
            )
            if dispatch.effect_receipt_ref is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Effect recovery completion lost its authoritative receipt",
                )
            receipt = self._get_artifact_model(
                dispatch.effect_receipt_ref,
                EffectReceipt,
            )
            if canonical_digest(receipt) != dispatch.effect_receipt_ref:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Effect recovery receipt lost its content address",
                )
            self._validate_effect_receipt_identity(action, dispatch, receipt)
            evidence_kind = "rollback" if work.kind is RecoveryWorkKind.ROLLBACK else "compensation"
            subject_ref = dispatch.effect_receipt_ref
        self._validate_adapter_observation(
            report.evidence_refs,
            evidence_kind=evidence_kind,
            action=action,
            adapter_manifest_digest=work.adapter_manifest_digest,
            subject_ref=subject_ref,
            operation_permit_ref=work.permit_ref,
            authority_permit_ref=work.permit_ref,
            subject_authority_ref=work.permit.target_evidence_ref,
            operation_status=report.status.value,
            permit_issued_at=work.permit.issued_at,
            permit_deadline=work.permit.deadline,
            received_at=completion.completed_at,
            dispatch=dispatch,
            expected_observed_state_digest=report.restored_state_digest,
            allow_late=False,
        )

    def _audit_tenant_recovery_handoff_evidence(
        self,
        tenant_id: str,
        *,
        observed_at: datetime,
        force: bool = False,
    ) -> tuple[
        tuple[RecoveryCandidateFailure, ...],
        RecoveryHandoffEvidenceAuditCheckpoint,
    ]:
        for _attempt in range(8):
            checkpoint = self._store.get_recovery_handoff_evidence_audit_checkpoint(tenant_id)
            if checkpoint is None or checkpoint.current_cycle_complete:
                try:
                    checkpoint = self._store.start_recovery_handoff_evidence_audit_cycle(
                        tenant_id=tenant_id,
                        expected=checkpoint,
                        recorded_at=observed_at,
                        reaudit_interval=(self._config.handoff_evidence_reaudit_interval),
                        force=force,
                    )
                except AgentKernelError as error:
                    if error.code is ErrorCode.VERSION_CONFLICT:
                        continue
                    raise
            if checkpoint.current_cycle_complete:
                return (), checkpoint
            page = self._store.scan_terminal_recovery_handoff_evidence(
                tenant_id=tenant_id,
                cycle_high_watermark=checkpoint.current_cycle_high_watermark,
                limit=_RECOVERY_HANDOFF_EVIDENCE_AUDIT_PAGE,
                cursor=checkpoint.cursor,
            )
            failures: list[RecoveryCandidateFailure] = []
            for handoff in page.handoffs:
                if (
                    handoff.failure_evidence_status
                    is RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE
                ):
                    failures.append(
                        RecoveryCandidateFailure(
                            transaction_id=handoff.binding.target_transaction_id,
                            reason_code=ErrorCode.EVIDENCE_UNAVAILABLE.value,
                            evidence_ref=None,
                            kind=RecoveryFailureKind.EVIDENCE_AUDIT,
                        )
                    )
                    continue
                try:
                    self._validate_recovery_handoff_failure_evidence(
                        handoff,
                        tenant_id=tenant_id,
                    )
                except AgentKernelError as error:
                    failures.append(
                        RecoveryCandidateFailure(
                            transaction_id=handoff.binding.target_transaction_id,
                            reason_code=error.code.value,
                            evidence_ref=handoff.failure_evidence_ref,
                            kind=RecoveryFailureKind.EVIDENCE_AUDIT,
                        )
                    )
            try:
                advanced = self._store.advance_recovery_handoff_evidence_audit(
                    tenant_id=tenant_id,
                    expected=checkpoint,
                    next_cursor=page.next_cursor,
                    page_failure_count=len(failures),
                    completed=page.cycle_complete,
                    recorded_at=observed_at,
                )
            except AgentKernelError as error:
                if error.code is ErrorCode.VERSION_CONFLICT:
                    continue
                raise
            return tuple(failures), advanced
        raise AgentKernelError(
            ErrorCode.VERSION_CONFLICT,
            "Recovery handoff evidence audit remained contended",
            retryable=True,
        )

    def status(self, tenant_id: str, transaction_id: str) -> EnforcedTransactionStatus:
        projection = self._store.get_transaction_projection(
            tenant_id=tenant_id,
            transaction_id=transaction_id,
        )
        for round_record in projection.authorization_rounds:
            self._validate_authorization_artifacts(round_record)
        if projection.dispatch is not None and projection.dispatch.effect_receipt_ref is not None:
            if projection.action is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Receipt-bearing status lost its normalized action",
                )
            receipt = self._get_artifact_model(
                projection.dispatch.effect_receipt_ref,
                EffectReceipt,
            )
            if canonical_digest(receipt) != projection.dispatch.effect_receipt_ref:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Status effect receipt lost its content address",
                )
            self._validate_effect_receipt_identity(
                projection.action,
                projection.dispatch,
                receipt,
            )
            self._validate_committed_dispatch_evidence(
                projection.action,
                projection.dispatch,
                receipt,
            )
        late_reports = {report.recovery_id: report for report in projection.late_recovery_reports}
        for handoff in projection.recovery_handoffs:
            self._validate_recovery_handoff_failure_evidence(
                handoff,
                tenant_id=tenant_id,
                late_reports=late_reports,
            )
        self._recovery_terminal_failure(projection)
        return self._status_from_projection(projection)

    @staticmethod
    def _status_from_projection(
        projection: EnforcedTransactionProjection,
    ) -> EnforcedTransactionStatus:
        return EnforcedTransactionStatus(
            record=projection.record,
            action=projection.action,
            stage=projection.stage,
            dispatch=projection.dispatch,
            dispatch_evidence_unavailable=projection.dispatch_evidence_unavailable,
            recovery_work=projection.recovery_work,
            event_count=projection.event_count,
            recovery_handoffs=projection.recovery_handoffs,
            recovery_evidence_unavailable=(projection.recovery_evidence_unavailable),
            intent_disposition=(
                None
                if projection.intent_acquisition is None
                else projection.intent_acquisition.disposition
            ),
            intent_owner_transaction_id=(
                None
                if projection.intent_acquisition is None
                else projection.intent_acquisition.owner_transaction_id
            ),
        )

    def _recovery_result_status(
        self,
        tenant_id: str,
        transaction_id: str,
        *,
        unavailable_error: AgentKernelError | None = None,
    ) -> EnforcedTransactionStatus:
        """Return a degraded view only when the failing read names its typed stop."""

        try:
            return self.status(tenant_id, transaction_id)
        except Exception as error:
            if not self._is_evidence_store_outage(error):
                raise
            projection = self._store.get_transaction_projection(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
            )
            expected_error = unavailable_error or error
            if not self._matches_typed_unavailable_error(
                expected_error,
                projection,
            ):
                raise
            return self._status_from_projection(projection)

    @staticmethod
    def _matches_typed_unavailable_error(
        error: BaseException,
        projection: EnforcedTransactionProjection,
    ) -> bool:
        """Require an exact, non-sensitive token for the unavailable SQL record."""

        if not isinstance(error, AgentKernelError) or (
            error.code is not ErrorCode.EVIDENCE_UNAVAILABLE
        ):
            return False
        token_keys = {"kind", "owner_id", "boundary", "record_digest"}
        if set(error.details) != token_keys:
            return False
        token = (
            error.details["kind"],
            error.details["owner_id"],
            error.details["boundary"],
            error.details["record_digest"],
        )
        expected_tokens: set[tuple[object, object, object, object]] = {
            (
                "recovery",
                record.recovery_id,
                record.boundary,
                record.record_digest,
            )
            for record in projection.recovery_evidence_unavailable
        }
        dispatch_record = projection.dispatch_evidence_unavailable
        if dispatch_record is not None:
            expected_tokens.add(
                (
                    "dispatch",
                    dispatch_record.dispatch_id,
                    dispatch_record.boundary,
                    dispatch_record.record_digest,
                )
            )
        return token in expected_tokens

    @staticmethod
    def _typed_unavailable_error(
        record: DispatchEvidenceUnavailableRecord | RecoveryEvidenceUnavailableRecord,
    ) -> AgentKernelError:
        if isinstance(record, DispatchEvidenceUnavailableRecord):
            kind = "dispatch"
            owner_id = record.dispatch_id
        else:
            kind = "recovery"
            owner_id = record.recovery_id
        return AgentKernelError(
            ErrorCode.EVIDENCE_UNAVAILABLE,
            "Typed unavailable-evidence stop",
            details={
                "kind": kind,
                "owner_id": owner_id,
                "boundary": record.boundary,
                "record_digest": record.record_digest,
            },
            review_required=True,
        )

    def _typed_unavailable_error_for_failure(
        self,
        projection: EnforcedTransactionProjection,
        failure: RecoveryCandidateFailure,
    ) -> AgentKernelError | None:
        if projection.recovery_evidence_unavailable:
            record = max(
                projection.recovery_evidence_unavailable,
                key=lambda item: (item.reported_at, item.recovery_id),
            )
            if failure.reason_code == record.reason_code:
                return self._typed_unavailable_error(record)
        dispatch_record = projection.dispatch_evidence_unavailable
        reconciliation_lineage_exists = any(
            work.kind is RecoveryWorkKind.RECONCILE_DISPATCH for work in projection.recovery_work
        ) or any(
            handoff.binding.recovery_kind is RecoveryWorkKind.RECONCILE_DISPATCH
            for handoff in projection.recovery_handoffs
        )
        if (
            dispatch_record is not None
            and not reconciliation_lineage_exists
            and failure.reason_code == dispatch_record.reason_code
        ):
            return self._typed_unavailable_error(dispatch_record)
        return None

    def _readonly_admission_result(
        self,
        *,
        requested_record: EnforcedTransactionRecord,
        owner_transaction_id: str,
        disposition: IntentDisposition,
    ) -> EnforcedTransactionStatus:
        owner = self.status(requested_record.tenant_id, owner_transaction_id)
        if owner.record.tenant_id != requested_record.tenant_id or (
            requested_record.intent_hash is not None
            and owner.record.intent_hash != requested_record.intent_hash
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Intent admission result differs from its durable owner",
            )
        receipt: EffectReceipt | None = None
        if owner.dispatch is not None and owner.dispatch.effect_receipt_ref is not None:
            if owner.action is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Receipt-bearing owner lost its normalized action",
                )
            receipt = self._get_artifact_model(
                owner.dispatch.effect_receipt_ref,
                EffectReceipt,
            )
            if canonical_digest(receipt) != owner.dispatch.effect_receipt_ref:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Durable effect receipt lost its content address",
                )
            self._validate_effect_receipt_identity(
                owner.action,
                owner.dispatch,
                receipt,
            )
        return replace(
            owner,
            requested_record=requested_record,
            intent_disposition=disposition,
            intent_owner_transaction_id=owner_transaction_id,
            effect_receipt=receipt,
        )

    def _stage_recovery_binding(
        self,
        record: EnforcedTransactionRecord,
        stage: StageMaterialRecord,
        *,
        stage_target_ref: str,
    ) -> RecoveryActionBinding:
        if (
            record.intent_hash is None
            or record.normalized_action_digest is None
            or record.adapter_manifest_digest is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stage recovery binding requires complete transaction action bindings",
            )
        target_action = self._store.get_normalized_action(
            record.tenant_id,
            record.transaction_id,
        ).action
        if canonical_digest(target_action) != record.normalized_action_digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stage recovery binding differs from its durable normalized action",
            )
        history = self._store.list_intent_history(
            tenant_id=record.tenant_id,
            intent_hash=record.intent_hash,
        )
        if not history:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stage recovery binding requires durable target intent history",
            )
        head = history[-1]
        deadline = self._store.get_transaction_recovery_deadline(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        recovery_id = _stable_id(
            "recovery",
            {
                "tenant_id": record.tenant_id,
                "transaction_id": record.transaction_id,
                "kind": RecoveryWorkKind.DISCARD_STAGING.value,
                "target_ref": stage_target_ref,
                "ordinal": 1,
            },
        )
        return RecoveryActionBinding(
            target_transaction_id=record.transaction_id,
            target_intent_hash=record.intent_hash,
            target_normalized_action_digest=record.normalized_action_digest,
            recovery_kind=RecoveryWorkKind.DISCARD_STAGING,
            target_id=stage.stage_id,
            target_evidence_ref=stage_target_ref,
            target_version_guard=stage.target_version_guard,
            target_owner_version=head.owner_version,
            target_owner_history_sequence=head.sequence,
            target_owner_history_digest=head.history_digest,
            adapter_manifest_digest=record.adapter_manifest_digest,
            risk_class=target_action.risk_floor,
            effect_domains=target_action.effect_domains,
            resource_uses_digest=canonical_digest(target_action.resource_uses),
            recovery_id=recovery_id,
            root_recovery_id=recovery_id,
            predecessor_recovery_id=None,
            recovery_ordinal=1,
            max_recovery_attempts=1,
            not_before=record.updated_at,
            absolute_deadline=deadline,
        )

    def _abort_handoff_failure(
        self,
        record: EnforcedTransactionRecord,
        *,
        reason_code: str,
        recovery_action: NormalizedAction | None = None,
        recovery_action_binding: RecoveryActionBinding | None = None,
        handoff_lease: WorkerLeaseRecord | None = None,
    ) -> EnforcedTransactionRecord:
        """Persist a fail-closed abort outcome when no recovery handoff can be created."""

        current = self._store.get_enforced_transaction(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        if current.state.is_terminal:
            return current
        active = self._store.get_active_recovery_work(
            tenant_id=current.tenant_id,
            transaction_id=current.transaction_id,
        )
        if active:
            return current
        if current.state is not TransactionState.ABORTING:
            raise AgentKernelError(
                ErrorCode.ILLEGAL_TRANSITION,
                "Abort handoff failure requires an ABORTING transaction",
            )
        try:
            stage = self._store.get_stage_material(
                tenant_id=current.tenant_id,
                transaction_id=current.transaction_id,
            )
        except AgentKernelError as error:
            if error.code is not ErrorCode.VALIDATION_ERROR:
                raise
            recorded_at = self._now()
            completed = self._store.complete_unstaged_abort(
                tenant_id=current.tenant_id,
                transaction_id=current.transaction_id,
                expected_transaction_version=current.version,
                recorded_at=recorded_at,
            )
            return completed.transaction
        self._validate_reconciliation_lineage_operation_evidence(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        stage_target_ref = canonical_digest(stage)
        if recovery_action is None:
            candidate_binding = self._stage_recovery_binding(
                current,
                stage,
                stage_target_ref=stage_target_ref,
            )
            candidate_handoff = self._store.get_recovery_action_handoff(
                tenant_id=current.tenant_id,
                target_transaction_id=current.transaction_id,
                recovery_id=candidate_binding.recovery_id,
            )
            if candidate_handoff is not None:
                recovery_action = candidate_handoff.action
                recovery_action_binding = candidate_handoff.binding
        recorded_at = self._now()
        failure_evidence_ref, reason_code, evidence_status = self._put_failure_evidence_or_fallback(
            transaction_id=current.transaction_id,
            event=TransitionEvent.STAGING_DISCARD_FAILED.value,
            reason_code=reason_code,
            recorded_at=recorded_at,
            subject_ref=stage_target_ref,
        )
        try:
            failed = self._store.fail_stage_recovery_handoff(
                tenant_id=current.tenant_id,
                transaction_id=current.transaction_id,
                expected_transaction_version=current.version,
                stage_id=stage.stage_id,
                expected_stage_version=stage.version,
                stage_target_ref=stage_target_ref,
                failure_evidence_ref=failure_evidence_ref,
                failure_evidence_status=evidence_status,
                recorded_at=recorded_at,
                reason_code=reason_code,
                recovery_action_transaction_id=(
                    None if recovery_action is None else recovery_action.transaction_id
                ),
                recovery_action_intent_hash=(
                    None if recovery_action is None else recovery_action.intent_hash
                ),
                recovery_action_digest=(
                    None if recovery_action is None else canonical_digest(recovery_action)
                ),
                recovery_action_binding=recovery_action_binding,
                handoff_lease_id=(None if handoff_lease is None else handoff_lease.lease_id),
                handoff_worker_id=(None if handoff_lease is None else handoff_lease.worker_id),
                handoff_fencing_token=(
                    None if handoff_lease is None else handoff_lease.fencing_token
                ),
                expected_handoff_lease_version=(
                    None if handoff_lease is None else handoff_lease.version
                ),
            )
        except AgentKernelError as error:
            if error.code is not ErrorCode.VERSION_CONFLICT:
                raise
            refreshed = self._store.get_enforced_transaction(
                tenant_id=current.tenant_id,
                transaction_id=current.transaction_id,
            )
            if refreshed.state.is_terminal or self._store.get_active_recovery_work(
                tenant_id=refreshed.tenant_id,
                transaction_id=refreshed.transaction_id,
            ):
                return refreshed
            raise
        return failed.transaction

    def _fail_unattached_recovery_action(
        self,
        record: EnforcedTransactionRecord,
        *,
        binding: RecoveryActionBinding,
        reason_code: str,
        handoff_lease: WorkerLeaseRecord | None,
    ) -> EnforcedTransactionRecord:
        recorded_at = self._now()
        evidence_ref, reason_code, evidence_status = self._put_failure_evidence_or_fallback(
            transaction_id=record.transaction_id,
            event="recovery.authorization_handoff_failed",
            reason_code=reason_code,
            recorded_at=recorded_at,
            subject_ref=canonical_digest(binding),
        )
        failed = self._store.fail_recovery_action_handoff(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
            expected_transaction_version=record.version,
            recovery_id=binding.recovery_id,
            failure_evidence_ref=evidence_ref,
            failure_evidence_status=evidence_status,
            reason_code=reason_code,
            recorded_at=recorded_at,
            handoff_lease=handoff_lease,
        )
        return failed.transaction

    def _settle_recovery_authorization_failure(
        self,
        record: EnforcedTransactionRecord,
        *,
        binding: RecoveryActionBinding,
        error: BaseException,
        handoff_lease: WorkerLeaseRecord | None,
        attached_recovery_action: NormalizedAction | None = None,
        fallback_reason_code: str = "RECOVERY_AUTHORIZATION_FAILED",
    ) -> None:
        """Close the exact handoff and intent before propagating a provider failure."""

        reason_code = (
            error.code.value
            if isinstance(error, AgentKernelError)
            else "CANCELLED"
            if isinstance(error, CancelledError)
            else fallback_reason_code
        )
        if record.state is TransactionState.ABORTING:
            self._abort_handoff_failure(
                record,
                reason_code=reason_code,
                recovery_action=attached_recovery_action,
                recovery_action_binding=binding,
                handoff_lease=handoff_lease,
            )
            return
        self._fail_unattached_recovery_action(
            record,
            binding=binding,
            reason_code=reason_code,
            handoff_lease=handoff_lease,
        )

    def _terminal_reconciliation_follow_on_required(
        self,
        record: EnforcedTransactionRecord,
        work_items: tuple[RecoveryWorkRecord, ...],
    ) -> bool:
        """Recognize the only terminal reconciliation histories that require new work."""

        if (
            not work_items
            or record.state not in {TransactionState.ABORTING, TransactionState.FAILED}
            or any(work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH for work in work_items)
        ):
            return False
        handoffs = self._store.list_recovery_action_handoffs(
            tenant_id=record.tenant_id,
            target_transaction_id=record.transaction_id,
        )
        if any(
            handoff.binding.recovery_kind is not RecoveryWorkKind.RECONCILE_DISPATCH
            for handoff in handoffs
        ):
            return False
        latest_reconciliation = max(
            work_items,
            key=lambda work: (work.recovery_ordinal, work.updated_at, work.recovery_id),
        )
        if (
            latest_reconciliation.state is not RecoveryWorkState.SUCCEEDED
            or latest_reconciliation.attempt < 1
        ):
            return False
        latest_attempt = self._store.get_reconciliation_attempt(
            tenant_id=latest_reconciliation.tenant_id,
            transaction_id=latest_reconciliation.transaction_id,
            recovery_id=latest_reconciliation.recovery_id,
            attempt=latest_reconciliation.attempt,
        )
        expected_outcome = (
            ReconciliationOutcome.PARTIAL_OR_INVALID
            if record.state is TransactionState.FAILED
            else ReconciliationOutcome.NO_EFFECT
        )
        if latest_attempt.completed_at is None or latest_attempt.outcome is not expected_outcome:
            return False
        self._validate_reconciliation_lineage_operation_evidence(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        return True

    def _validate_reconciliation_work_generation_evidence(
        self,
        projection: EnforcedTransactionProjection,
        work: RecoveryWorkRecord,
    ) -> None:
        """Re-prove one reconciliation generation's finite authorization closure."""

        handoffs = tuple(
            handoff
            for handoff in projection.recovery_handoffs
            if handoff.binding.recovery_id == work.recovery_id
        )
        rounds = tuple(
            round_record
            for round_record in projection.authorization_rounds
            if round_record.controlled_transaction_id == work.transaction_id
            and round_record.round_id == work.authorization_round_id
        )
        if len(handoffs) != 1 or len(rounds) != 1 or projection.action is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation generation lost its unique handoff, round, or target action",
            )
        handoff = handoffs[0]
        authorization_round = rounds[0]
        target_action = projection.action
        binding = self._get_artifact_model(
            handoff.binding_ref,
            RecoveryActionBinding,
        )
        recovery_action = self._get_artifact_model(
            work.recovery_action_digest,
            NormalizedAction,
        )
        stored_recovery_action = self._store.get_normalized_action(
            work.tenant_id,
            work.recovery_action_transaction_id,
        ).action
        approval = self._get_artifact_model(
            work.approval_evidence_ref,
            CoordinatorEvidence,
        )
        if (
            work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
            or canonical_digest(target_action) != binding.target_normalized_action_digest
            or canonical_digest(binding) != handoff.binding_ref
            or binding != handoff.binding
            or binding.target_transaction_id != work.transaction_id
            or binding.target_intent_hash != work.intent_hash
            or binding.recovery_kind is not work.kind
            or binding.target_id != work.target_id
            or binding.target_evidence_ref != work.target_evidence_ref
            or binding.target_version_guard != work.target_version_guard
            or binding.target_owner_version != work.target_owner_version
            or binding.target_owner_history_sequence != work.target_owner_history_sequence
            or binding.target_owner_history_digest != work.target_owner_history_digest
            or binding.adapter_manifest_digest != work.adapter_manifest_digest
            or binding.risk_class is not target_action.risk_floor
            or binding.effect_domains != target_action.effect_domains
            or binding.resource_uses_digest != canonical_digest(target_action.resource_uses)
            or binding.recovery_id != work.recovery_id
            or binding.root_recovery_id != work.root_recovery_id
            or binding.predecessor_recovery_id != work.predecessor_recovery_id
            or binding.recovery_ordinal != work.recovery_ordinal
            or binding.max_recovery_attempts != work.max_recovery_attempts
            or binding.not_before != work.not_before
            or binding.absolute_deadline != work.deadline
            or handoff.action != recovery_action
            or canonical_digest(recovery_action) != work.recovery_action_digest
            or recovery_action != stored_recovery_action
            or recovery_action.transaction_id != work.recovery_action_transaction_id
            or recovery_action.intent_hash != work.recovery_action_intent_hash
            or recovery_action.adapter_manifest_digest != work.adapter_manifest_digest
            or authorization_round.purpose is not AuthorizationRoundPurpose.RECOVERY
            or authorization_round.controlled_transaction_id != work.transaction_id
            or authorization_round.subject_transaction_id != work.recovery_action_transaction_id
            or authorization_round.subject_intent_hash != work.recovery_action_intent_hash
            or authorization_round.subject_normalized_action_digest != work.recovery_action_digest
            or authorization_round.round_digest != work.authorization_round_digest
            or authorization_round.authority_decision_digest != work.authority_decision_digest
            or authorization_round.policy_decision_digest != work.policy_decision_digest
            or authorization_round.policy_snapshot_digest != work.policy_snapshot_digest
            or not (
                (
                    authorization_round.capability_reservation_digest
                    == work.capability_reservation_digest
                    and authorization_round.reservation_version == work.reservation_version
                )
                or (
                    work.permit is not None
                    and authorization_round.capability_reservation_digest is not None
                    and authorization_round.reservation_version is not None
                    and work.capability_reservation_digest
                    == work.permit.capability_reservation_digest
                    and work.reservation_version == authorization_round.reservation_version + 1
                )
            )
            or authorization_round.owner_version != work.owner_version
            or authorization_round.owner_history_sequence != work.owner_history_sequence
            or authorization_round.owner_history_digest != work.owner_history_digest
            or canonical_digest(approval) != work.approval_evidence_ref
            or approval.transaction_id != work.recovery_action_transaction_id
            or approval.event != "recovery.approval_not_required"
            or approval.reason_code != "NO_APPROVAL_REQUIRED"
            or approval.recorded_at != authorization_round.evaluated_at
            or approval.subject_ref != work.recovery_action_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation generation differs from its durable authorization closure",
            )
        self._validate_authorization_artifacts(authorization_round)

        current_attempts = tuple(
            attempt
            for attempt in projection.reconciliation_attempts
            if attempt.recovery_id == work.recovery_id and attempt.attempt == work.attempt
        )
        if work.permit is None:
            if work.attempt != 0 or current_attempts:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unclaimed reconciliation generation unexpectedly has an attempt",
                )
            return
        if len(current_attempts) != 1:
            if not current_attempts and work.state is RecoveryWorkState.RUNNING:
                self._current_reconciliation_permit(work, None)
                return
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Claimed reconciliation generation lost its unique current attempt",
            )
        self._current_reconciliation_permit(work, current_attempts[0])

    def _validate_reconciliation_lineage_operation_evidence(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
    ) -> EnforcedTransactionProjection:
        """Re-prove all completed reconciliation operations before a new effect."""

        projection = self._store.get_transaction_projection(
            tenant_id=tenant_id,
            transaction_id=transaction_id,
        )
        if any(
            work.kind is RecoveryWorkKind.RECONCILE_DISPATCH for work in projection.recovery_work
        ):
            self._validate_completed_recovery_operation_evidence(projection)
        return projection

    def _exact_prework_handoff_won_acquisition(
        self,
        record: EnforcedTransactionRecord,
        *,
        proposed_binding: RecoveryActionBinding,
        registered_handoff: RecoveryActionHandoff | None,
        error: AgentKernelError,
    ) -> bool:
        if error.code is not ErrorCode.VERSION_CONFLICT or not error.retryable:
            return False
        expected_binding = (
            proposed_binding if registered_handoff is None else registered_handoff.binding
        )
        expected_binding_ref = (
            canonical_digest(proposed_binding)
            if registered_handoff is None
            else registered_handoff.binding_ref
        )

        def matches_expected_handoff(handoff: RecoveryActionHandoff) -> bool:
            return (
                handoff.binding == expected_binding
                and handoff.binding_ref == expected_binding_ref
                and (
                    registered_handoff is None
                    or (
                        handoff.handoff_lease_id == registered_handoff.handoff_lease_id
                        and handoff.created_at == registered_handoff.created_at
                    )
                )
            )

        live_handoff = self._store.get_live_open_prework_handoff(
            tenant_id=record.tenant_id,
            target_transaction_id=record.transaction_id,
            observed_at=self._now(),
        )
        if live_handoff is not None and matches_expected_handoff(live_handoff):
            return True

        progressed_handoff = self._store.get_recovery_action_handoff(
            tenant_id=record.tenant_id,
            target_transaction_id=record.transaction_id,
            recovery_id=expected_binding.recovery_id,
        )
        if progressed_handoff is None or not matches_expected_handoff(progressed_handoff):
            return False
        projection = self._store.get_transaction_projection(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        return any(
            work.recovery_id == expected_binding.recovery_id for work in projection.recovery_work
        )

    @staticmethod
    def _assert_registered_recovery_binding_bounds(
        proposed_binding: RecoveryActionBinding,
        registered_handoff: RecoveryActionHandoff | None,
    ) -> None:
        if registered_handoff is not None and (
            registered_handoff.binding.absolute_deadline != proposed_binding.absolute_deadline
            or registered_handoff.binding.max_recovery_attempts
            != proposed_binding.max_recovery_attempts
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Registered recovery handoff changed its durable deadline or attempt bound",
            )

    async def _settle_abort_handoff(
        self,
        record: EnforcedTransactionRecord,
        *,
        cancellation: CancelledError | None = None,
        report_contention: bool = False,
    ) -> EnforcedTransactionRecord:
        """Finish or durably hand off abort recovery despite repeated caller cancellation."""

        pending_cancellation = cancellation

        def finish(result: EnforcedTransactionRecord) -> EnforcedTransactionRecord:
            if pending_cancellation is not None:
                raise pending_cancellation
            return result

        if record.state.is_terminal:
            return finish(record)
        deadline = self._store.get_transaction_recovery_deadline(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        now = self._now()
        active = self._store.get_active_recovery_work(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        historical_work = self._store.list_recovery_work(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        resumable_prework_handoff = self._store.get_resumable_open_prework_handoff(
            tenant_id=record.tenant_id,
            target_transaction_id=record.transaction_id,
            observed_at=now,
        )
        if active:
            deadline = min(deadline, *(work.deadline for work in active))
        elif (
            historical_work
            and resumable_prework_handoff is None
            and not self._terminal_reconciliation_follow_on_required(
                record,
                historical_work,
            )
        ):
            return finish(record)
        else:
            try:
                stage = self._store.get_stage_material(
                    tenant_id=record.tenant_id,
                    transaction_id=record.transaction_id,
                )
            except AgentKernelError as error:
                if error.code is not ErrorCode.VALIDATION_ERROR:
                    raise
            else:
                stage_target_ref = canonical_digest(stage)
                proposed_binding = self._stage_recovery_binding(
                    record,
                    stage,
                    stage_target_ref=stage_target_ref,
                )
                registered_handoff = self._store.get_recovery_action_handoff(
                    tenant_id=record.tenant_id,
                    target_transaction_id=record.transaction_id,
                    recovery_id=proposed_binding.recovery_id,
                )
                self._assert_registered_recovery_binding_bounds(
                    proposed_binding,
                    registered_handoff,
                )
                if registered_handoff is not None:
                    deadline = registered_handoff.binding.absolute_deadline
        if now >= deadline:
            return finish(
                self._abort_handoff_failure(
                    record,
                    reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                )
            )
        loop_deadline = get_running_loop().time() + (deadline - now).total_seconds()
        current = record
        while True:
            if get_running_loop().time() >= loop_deadline:
                return finish(
                    self._abort_handoff_failure(
                        current,
                        reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                    )
                )
            try:
                result = await self._recover_aborting(
                    current,
                    report_contention=True,
                )
            except _RecoveryHandoffContended:
                if report_contention:
                    raise
                try:
                    await sleep(0.01)
                except CancelledError as retry_cancellation:
                    if pending_cancellation is None:
                        pending_cancellation = retry_cancellation
                current = self._store.get_enforced_transaction(
                    tenant_id=current.tenant_id,
                    transaction_id=current.transaction_id,
                )
                if current.state.is_terminal:
                    return finish(current)
                continue
            except CancelledError as error:
                if pending_cancellation is None:
                    pending_cancellation = error
                current = self._store.get_enforced_transaction(
                    tenant_id=current.tenant_id,
                    transaction_id=current.transaction_id,
                )
                if current.state.is_terminal:
                    return finish(current)
                continue
            except Exception as error:
                current = self._store.get_enforced_transaction(
                    tenant_id=current.tenant_id,
                    transaction_id=current.transaction_id,
                )
                if current.state.is_terminal:
                    return finish(current)
                if isinstance(error, AgentKernelError) and error.code in {
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    ErrorCode.INTEGRITY_ERROR,
                }:
                    if pending_cancellation is not None:
                        raise pending_cancellation from error
                    raise
                if self._store.get_active_recovery_work(
                    tenant_id=current.tenant_id,
                    transaction_id=current.transaction_id,
                ):
                    return finish(current)
                historical_work = self._store.list_recovery_work(
                    tenant_id=current.tenant_id,
                    transaction_id=current.transaction_id,
                )
                if historical_work and not self._terminal_reconciliation_follow_on_required(
                    current,
                    historical_work,
                ):
                    return finish(current)
                reason_code = (
                    error.code.value
                    if isinstance(error, AgentKernelError)
                    else "RECOVERY_HANDOFF_FAILED"
                )
                return finish(self._abort_handoff_failure(current, reason_code=reason_code))
            else:
                return finish(result)

    async def _recover_aborting(
        self,
        record: EnforcedTransactionRecord,
        *,
        report_contention: bool = False,
    ) -> EnforcedTransactionRecord:
        lock = self._recovery_lock_for(record.tenant_id, record.transaction_id)
        async with lock:
            current = self._store.get_enforced_transaction(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
            try:
                return await self._recover_aborting_serialized(current)
            except _RecoveryHandoffContended:
                if report_contention:
                    raise
                return self._store.get_enforced_transaction(
                    tenant_id=current.tenant_id,
                    transaction_id=current.transaction_id,
                )

    async def _recover_aborting_serialized(
        self,
        record: EnforcedTransactionRecord,
    ) -> EnforcedTransactionRecord:
        if record.state.is_terminal:
            return record
        if record.state is not TransactionState.ABORTING:
            raise AgentKernelError(
                ErrorCode.ILLEGAL_TRANSITION,
                "Stage cleanup requires an ABORTING transaction",
            )
        lineage_projection = self._validate_reconciliation_lineage_operation_evidence(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        active = self._store.get_active_recovery_work(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        if len(active) > 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Transaction has multiple active recovery generations",
            )
        if active:
            result = await self._run_recovery_work(active[0])
            return result.record
        try:
            stage = self._store.get_stage_material(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
        except AgentKernelError as error:
            if error.code is not ErrorCode.VALIDATION_ERROR:
                raise
            recorded_at = self._now()
            completed = self._store.complete_unstaged_abort(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
                expected_transaction_version=record.version,
                recorded_at=recorded_at,
            )
            return completed.transaction
        stage_target_ref = canonical_digest(stage)
        proposed_binding = self._stage_recovery_binding(
            record,
            stage,
            stage_target_ref=stage_target_ref,
        )
        registered_handoff = self._store.get_recovery_action_handoff(
            tenant_id=record.tenant_id,
            target_transaction_id=record.transaction_id,
            recovery_id=proposed_binding.recovery_id,
        )
        self._assert_registered_recovery_binding_bounds(
            proposed_binding,
            registered_handoff,
        )
        deadline = (
            proposed_binding.absolute_deadline
            if registered_handoff is None
            else registered_handoff.binding.absolute_deadline
        )
        now = self._now()
        self._check_deadline(deadline, now, boundary="recovery handoff lease")
        published_stage_ref = self._put_model(stage)
        if published_stage_ref != stage_target_ref:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Published stage material differs from its durable recovery target",
            )
        try:
            handoff = self._store.acquire_recovery_handoff_lease(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
                expected_transaction_version=record.version,
                stage_id=stage.stage_id,
                expected_stage_version=stage.version,
                stage_target_ref=stage_target_ref,
                lease_id=_stable_id(
                    "lease.recovery-handoff",
                    {
                        "tenant_id": record.tenant_id,
                        "transaction_id": record.transaction_id,
                        "nonce": uuid4().hex,
                    },
                ),
                worker_id=self._config.worker_id,
                acquired_at=now,
                expires_at=min(deadline, now + self._config.lease_duration),
                binding=(
                    proposed_binding if registered_handoff is None else registered_handoff.binding
                ),
            )
        except AgentKernelError as error:
            if self._exact_prework_handoff_won_acquisition(
                record,
                proposed_binding=proposed_binding,
                registered_handoff=registered_handoff,
                error=error,
            ):
                raise _RecoveryHandoffContended from error
            raise
        try:
            work = await self._authorize_recovery_work(
                record,
                kind=RecoveryWorkKind.DISCARD_STAGING,
                target=stage,
                handoff_lease=handoff.lease,
                lineage_projection=lineage_projection,
            )
        except Exception as error:
            current = self._store.get_enforced_transaction(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
            active = self._store.get_active_recovery_work(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
            pre_provider_evidence_failure = isinstance(error, AgentKernelError) and error.code in {
                ErrorCode.EVIDENCE_UNAVAILABLE,
                ErrorCode.INTEGRITY_ERROR,
            }
            if not current.state.is_terminal and not active and not pre_provider_evidence_failure:
                reason_code = (
                    error.code.value
                    if isinstance(error, AgentKernelError)
                    else "RECOVERY_HANDOFF_FAILED"
                )
                self._abort_handoff_failure(
                    current,
                    reason_code=reason_code,
                    handoff_lease=handoff.lease,
                )
            raise
        finally:
            current_lease = self._store.get_worker_lease(
                tenant_id=handoff.lease.tenant_id,
                transaction_id=handoff.lease.transaction_id,
                lease_id=handoff.lease.lease_id,
            )
            if current_lease.released_at is None:
                self._store.release_worker_lease(
                    tenant_id=current_lease.tenant_id,
                    transaction_id=current_lease.transaction_id,
                    lease_id=current_lease.lease_id,
                    expected_version=current_lease.version,
                    released_at=self._now(),
                )
        if work is None or work.state is not RecoveryWorkState.PENDING:
            return self._store.get_enforced_transaction(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
        result = await self._run_recovery_work(work)
        return result.record

    async def _recover_failed(
        self,
        record: EnforcedTransactionRecord,
        *,
        report_contention: bool = False,
    ) -> EnforcedTransactionRecord:
        if record.state is not TransactionState.FAILED:
            return record
        self._validate_reconciliation_lineage_operation_evidence(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        active = self._store.get_active_recovery_work(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        if len(active) > 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Failed transaction has multiple active recovery generations",
            )
        if active:
            return (await self._run_recovery_work(active[0])).record
        action = self._store.get_normalized_action(
            record.tenant_id,
            record.transaction_id,
        ).action
        try:
            dispatch = self._store.get_commit_dispatch(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
        except AgentKernelError as error:
            if error.code is not ErrorCode.VALIDATION_ERROR:
                raise
            evidence_ref = self._put_control_evidence(
                transaction_id=record.transaction_id,
                event=TransitionEvent.RECOVERY_UNAVAILABLE.value,
                reason_code="FAILED_TRANSACTION_LACKS_DISPATCH_EVIDENCE",
                recorded_at=self._now(),
            )
            result = self._store.apply_control_transition(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
                expected_version=record.version,
                transition_event=TransitionEvent.RECOVERY_UNAVAILABLE,
                recorded_at=self._now(),
                evidence_refs=(evidence_ref,),
                reason_code="FAILED_TRANSACTION_LACKS_DISPATCH_EVIDENCE",
            )
            return result.transaction
        operation = self._registry.resolve_admitted(
            action.adapter,
            action.operation,
            enforcement_profile=True,
        ).operation
        if action.risk_floor.value == "R1" and operation.rollback:
            kind = RecoveryWorkKind.ROLLBACK
        elif action.risk_floor.value == "R2" and operation.compensate:
            kind = RecoveryWorkKind.COMPENSATE
        else:
            evidence_ref = self._put_control_evidence(
                transaction_id=record.transaction_id,
                event=TransitionEvent.RECOVERY_UNAVAILABLE.value,
                reason_code="RECOVERY_SEMANTICS_UNAVAILABLE",
                recorded_at=self._now(),
                subject_ref=canonical_digest(dispatch),
            )
            result = self._store.apply_control_transition(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
                expected_version=record.version,
                transition_event=TransitionEvent.RECOVERY_UNAVAILABLE,
                recorded_at=self._now(),
                evidence_refs=(evidence_ref,),
                reason_code="RECOVERY_SEMANTICS_UNAVAILABLE",
            )
            return result.transaction
        try:
            work = await self._authorize_recovery_work(record, kind=kind, target=dispatch)
        except _RecoveryHandoffContended:
            if report_contention:
                raise
            return self._store.get_enforced_transaction(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
        if work is None or work.state is not RecoveryWorkState.PENDING:
            return self._store.get_enforced_transaction(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
        return (await self._run_recovery_work(work)).record

    def _propose_recovery_action_binding(
        self,
        record: EnforcedTransactionRecord,
        *,
        kind: RecoveryWorkKind,
        target: StageMaterialRecord | CommitDispatchRecord,
        target_ref: str,
        observed_at: datetime,
        predecessor: RecoveryWorkRecord | None,
    ) -> RecoveryActionBinding:
        """Build the complete target generation before its lease is acquired atomically."""

        if (
            record.intent_hash is None
            or record.normalized_action_digest is None
            or record.adapter_manifest_digest is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target lacks complete durable action bindings",
            )
        target_action = self._store.get_normalized_action(
            record.tenant_id,
            record.transaction_id,
        ).action
        if canonical_digest(target_action) != record.normalized_action_digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target action differs from its durable transaction binding",
            )
        target_history = self._store.list_intent_history(
            tenant_id=record.tenant_id,
            intent_hash=record.intent_hash,
        )
        if not target_history:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target intent history is empty",
            )
        target_head = target_history[-1]
        if isinstance(target, StageMaterialRecord):
            target_id = target.stage_id
            target_version_guard = target.target_version_guard
            target_owner_version = target_head.owner_version
            target_owner_history_sequence = target_head.sequence
            target_owner_history_digest = target_head.history_digest
        else:
            target_id = target.dispatch_id
            target_version_guard = target.permit.target_version_guard
            target_owner_version = target.permit.owner_version
            target_owner_history_sequence = target.permit.owner_history_sequence
            target_owner_history_digest = target.permit.owner_history_digest
        if predecessor is None:
            recovery_ordinal = 1
            max_recovery_attempts = (
                self._config.max_reconciliation_attempts
                if kind is RecoveryWorkKind.RECONCILE_DISPATCH
                else 1
            )
            predecessor_recovery_id = None
            not_before = record.updated_at
            deadline = self._store.get_transaction_recovery_deadline(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
            recovery_id = _stable_id(
                "recovery",
                {
                    "tenant_id": record.tenant_id,
                    "transaction_id": record.transaction_id,
                    "kind": kind.value,
                    "target_ref": target_ref,
                    "ordinal": recovery_ordinal,
                },
            )
            root_recovery_id = recovery_id
        else:
            if (
                kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                or predecessor.kind is not kind
                or predecessor.transaction_id != record.transaction_id
                or predecessor.target_id != target_id
                or predecessor.target_version_guard != target_version_guard
                or predecessor.state is not RecoveryWorkState.RETRY_SCHEDULED
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation successor differs from its scheduled predecessor",
                )
            attempt = self._store.get_reconciliation_attempt(
                tenant_id=predecessor.tenant_id,
                transaction_id=predecessor.transaction_id,
                recovery_id=predecessor.recovery_id,
                attempt=predecessor.attempt,
            )
            if (
                attempt.outcome is not ReconciliationOutcome.UNKNOWN
                or attempt.next_attempt_not_before is None
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Scheduled reconciliation predecessor lacks a durable UNKNOWN backoff",
                )
            not_before = attempt.next_attempt_not_before
            if observed_at < not_before:
                raise AgentKernelError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "Reconciliation retry backoff has not elapsed",
                    retryable=True,
                )
            recovery_ordinal = predecessor.recovery_ordinal + 1
            max_recovery_attempts = predecessor.max_recovery_attempts
            predecessor_recovery_id = predecessor.recovery_id
            root_recovery_id = predecessor.root_recovery_id
            deadline = predecessor.deadline
            recovery_id = _stable_id(
                "recovery",
                {
                    "tenant_id": record.tenant_id,
                    "root_recovery_id": root_recovery_id,
                    "predecessor_recovery_id": predecessor_recovery_id,
                    "ordinal": recovery_ordinal,
                    "target_ref": target_ref,
                },
            )
        return RecoveryActionBinding(
            target_transaction_id=record.transaction_id,
            target_intent_hash=record.intent_hash,
            target_normalized_action_digest=record.normalized_action_digest,
            recovery_kind=kind,
            target_id=target_id,
            target_evidence_ref=target_ref,
            target_version_guard=target_version_guard,
            target_owner_version=target_owner_version,
            target_owner_history_sequence=target_owner_history_sequence,
            target_owner_history_digest=target_owner_history_digest,
            adapter_manifest_digest=record.adapter_manifest_digest,
            risk_class=target_action.risk_floor,
            effect_domains=target_action.effect_domains,
            resource_uses_digest=canonical_digest(target_action.resource_uses),
            recovery_id=recovery_id,
            root_recovery_id=root_recovery_id,
            predecessor_recovery_id=predecessor_recovery_id,
            recovery_ordinal=recovery_ordinal,
            max_recovery_attempts=max_recovery_attempts,
            not_before=not_before,
            absolute_deadline=deadline,
        )

    async def _attach_recovery_action(
        self,
        record: EnforcedTransactionRecord,
        *,
        target_action: NormalizedAction,
        kind: RecoveryWorkKind,
        target_ref: str,
        binding: RecoveryActionBinding,
        expected_binding_ref: str,
        stored_recovery_action: NormalizedAction | None,
        handoff_lease: WorkerLeaseRecord | None,
    ) -> tuple[NormalizedAction, str, str]:
        """Create, validate, and attach one action inside a durable cleanup boundary."""

        attached_recovery_action: NormalizedAction | None = None
        factory_entered = stored_recovery_action is not None
        factory_returned = stored_recovery_action is not None
        try:
            binding_ref = self._put_model(binding)
            if binding_ref != expected_binding_ref:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Durable recovery action handoff binding digest changed",
                )
            binding_bytes = self._get_artifact(binding_ref)
            deadline = binding.absolute_deadline
            provider_deadline = (
                deadline if handoff_lease is None else min(deadline, handoff_lease.expires_at)
            )
            self._check_deadline(
                provider_deadline,
                self._now(),
                boundary="recovery action factory",
            )
            if stored_recovery_action is None:
                factory_entered = True
                supplied_recovery_action = await self._await_provider(
                    lambda: self._recovery_actions.create(
                        target=record,
                        target_action=target_action,
                        kind=kind,
                        target_evidence_ref=target_ref,
                        binding=binding,
                        deadline=deadline,
                    ),
                    deadline=provider_deadline,
                    boundary="recovery action factory",
                )
                factory_returned = True
            else:
                supplied_recovery_action = stored_recovery_action
            recovery_action = NormalizedAction.model_validate(
                supplied_recovery_action.model_dump(mode="python")
            )
            binding_arguments = tuple(
                argument
                for argument in recovery_action.semantic_arguments
                if argument.argument_name == RECOVERY_ACTION_BINDING_ARGUMENT
            )
            remaining_arguments = tuple(
                argument
                for argument in recovery_action.semantic_arguments
                if argument.argument_name != RECOVERY_ACTION_BINDING_ARGUMENT
            )
            if (
                recovery_action.tenant_id != record.tenant_id
                or recovery_action.principal_id != record.principal_id
                or recovery_action.goal_id != record.goal_id
                or recovery_action.run_id != record.run_id
                or recovery_action.trace_id != target_action.trace_id
                or recovery_action.actor_id != target_action.actor_id
                or recovery_action.on_behalf_of != target_action.on_behalf_of
                or recovery_action.agent_id != target_action.agent_id
                or recovery_action.transaction_id == record.transaction_id
                or recovery_action.adapter != record.adapter
                or recovery_action.adapter_version != target_action.adapter_version
                or recovery_action.operation != record.operation
                or recovery_action.adapter_manifest_digest != record.adapter_manifest_digest
                or recovery_action.normalizer_implementation
                != target_action.normalizer_implementation
                or recovery_action.normalizer_version != target_action.normalizer_version
                or recovery_action.normalizer_digest != target_action.normalizer_digest
                or recovery_action.operation_schema_ref != target_action.operation_schema_ref
                or recovery_action.operation_schema_digest != target_action.operation_schema_digest
                or recovery_action.configuration_digest != target_action.configuration_digest
                or recovery_action.risk_floor is not target_action.risk_floor
                or recovery_action.effect_domains != target_action.effect_domains
                or recovery_action.resource_uses != target_action.resource_uses
                or recovery_action.provenance != target_action.provenance
                or remaining_arguments != target_action.semantic_arguments
                or len(binding_arguments) != 1
                or binding_arguments[0].digest != binding_ref
                or binding_arguments[0].size_bytes != len(binding_bytes)
                or binding_arguments[0].media_type != "application/vnd.agentkernel.canonical+json"
                or recovery_action.deadline != deadline
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery factory output differs from its controlled target",
                )
            attached_at = self._now()
            self._check_deadline(
                provider_deadline,
                attached_at,
                boundary="recovery action handoff attachment",
            )
            recovery_action_ref = self._put_model(recovery_action)
            acquisition = self._store.register_recovery_action(
                recovery_action,
                registered_at=attached_at,
                binding=binding,
            )
            attached_recovery_action = recovery_action
            if acquisition.disposition not in {
                IntentDisposition.ACQUIRED,
                IntentDisposition.SAME_TRANSACTION,
            }:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Recovery action did not acquire a distinct executable intent",
                    review_required=True,
                )
            return recovery_action, recovery_action_ref, binding_ref
        except (Exception, CancelledError) as error:
            if (
                (
                    not factory_entered
                    or (isinstance(error, CancelledError) and not factory_returned)
                )
                and stored_recovery_action is None
                and attached_recovery_action is None
            ):
                # No recovery factory result or intent exists yet. Keep the durable
                # handoff open so a fresh lease can retry the pre-provider evidence
                # barrier or a cooperatively cancelled factory invocation.
                raise
            self._settle_recovery_authorization_failure(
                record,
                binding=binding,
                error=error,
                handoff_lease=handoff_lease,
                attached_recovery_action=attached_recovery_action,
                fallback_reason_code="RECOVERY_ACTION_HANDOFF_FAILED",
            )
            raise

    async def _authorize_recovery_work(
        self,
        record: EnforcedTransactionRecord,
        *,
        kind: RecoveryWorkKind,
        target: StageMaterialRecord | CommitDispatchRecord,
        predecessor: RecoveryWorkRecord | None = None,
        handoff_lease: WorkerLeaseRecord | None = None,
        lineage_projection: EnforcedTransactionProjection | None = None,
    ) -> RecoveryWorkRecord | None:
        if lineage_projection is None:
            lineage_projection = self._validate_reconciliation_lineage_operation_evidence(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
        else:
            self._validate_completed_recovery_operation_evidence(lineage_projection)
        if handoff_lease is not None:
            return await self._authorize_recovery_work_claimed(
                record,
                kind=kind,
                target=target,
                predecessor=predecessor,
                handoff_lease=handoff_lease,
                lineage_projection=lineage_projection,
            )
        target_ref = canonical_digest(target)
        now = self._now()
        proposed_binding = self._propose_recovery_action_binding(
            record,
            kind=kind,
            target=target,
            target_ref=target_ref,
            observed_at=now,
            predecessor=predecessor,
        )
        recovery_id = proposed_binding.recovery_id
        registered_handoff = self._store.get_recovery_action_handoff(
            tenant_id=record.tenant_id,
            target_transaction_id=record.transaction_id,
            recovery_id=recovery_id,
        )
        self._assert_registered_recovery_binding_bounds(
            proposed_binding,
            registered_handoff,
        )
        deadline = (
            registered_handoff.binding.absolute_deadline
            if registered_handoff is not None
            else proposed_binding.absolute_deadline
        )
        if now >= deadline and predecessor is not None:
            if registered_handoff is not None:
                if registered_handoff.binding != proposed_binding:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Expired reconciliation successor handoff changed its binding",
                    )
                if registered_handoff.closed_at is None:
                    self._fail_unattached_recovery_action(
                        record,
                        binding=registered_handoff.binding,
                        reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                        handoff_lease=None,
                    )
                now = self._now()
            return self._terminalize_expired_recovery(
                predecessor,
                reported_at=now,
            )
        if registered_handoff is not None and registered_handoff.closed_at is not None:
            if registered_handoff.binding == proposed_binding and registered_handoff.action is None:
                return None
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Recovery authorization handoff is already terminal",
                review_required=True,
            )
        if now >= deadline:
            if registered_handoff is not None:
                self._fail_unattached_recovery_action(
                    record,
                    binding=registered_handoff.binding,
                    reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                    handoff_lease=None,
                )
                return None
            if (
                kind
                in {
                    RecoveryWorkKind.ROLLBACK,
                    RecoveryWorkKind.COMPENSATE,
                    RecoveryWorkKind.RECONCILE_DISPATCH,
                }
                and predecessor is None
                and isinstance(target, CommitDispatchRecord)
            ):
                binding_ref = canonical_digest(proposed_binding)
                (
                    evidence_ref,
                    reason_code,
                    evidence_status,
                ) = self._put_failure_evidence_or_fallback(
                    transaction_id=record.transaction_id,
                    event="recovery.authorization_handoff_failed",
                    reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                    recorded_at=now,
                    subject_ref=binding_ref,
                )
                self._store.terminalize_expired_recovery_handoff(
                    tenant_id=record.tenant_id,
                    transaction_id=record.transaction_id,
                    expected_transaction_version=record.version,
                    binding=proposed_binding,
                    lease_id=_stable_id(
                        "lease.expired-recovery-handoff",
                        {
                            "tenant_id": record.tenant_id,
                            "transaction_id": record.transaction_id,
                            "recovery_id": recovery_id,
                        },
                    ),
                    worker_id=self._config.worker_id,
                    failure_evidence_ref=evidence_ref,
                    recorded_at=now,
                    reason_code=reason_code,
                    failure_evidence_status=evidence_status,
                )
                return None
        self._check_deadline(deadline, now, boundary="recovery authorization handoff")
        lease_id = _stable_id(
            "lease.recovery-authorization",
            {
                "tenant_id": record.tenant_id,
                "transaction_id": record.transaction_id,
                "recovery_id": recovery_id,
                "nonce": uuid4().hex,
            },
        )
        expires_at = min(deadline, now + self._config.lease_duration)
        try:
            if isinstance(target, StageMaterialRecord):
                claimed = self._store.acquire_recovery_handoff_lease(
                    tenant_id=record.tenant_id,
                    transaction_id=record.transaction_id,
                    expected_transaction_version=record.version,
                    stage_id=target.stage_id,
                    expected_stage_version=target.version,
                    stage_target_ref=target_ref,
                    lease_id=lease_id,
                    worker_id=self._config.worker_id,
                    acquired_at=now,
                    expires_at=expires_at,
                    binding=(
                        proposed_binding
                        if registered_handoff is None
                        else registered_handoff.binding
                    ),
                )
            else:
                claimed = self._store.acquire_recovery_authorization_lease(
                    tenant_id=record.tenant_id,
                    transaction_id=record.transaction_id,
                    expected_transaction_version=record.version,
                    kind=kind,
                    dispatch_id=target.dispatch_id,
                    dispatch_target_ref=target_ref,
                    recovery_id=recovery_id,
                    lease_id=lease_id,
                    worker_id=self._config.worker_id,
                    acquired_at=now,
                    expires_at=expires_at,
                    binding=(
                        proposed_binding
                        if registered_handoff is None
                        else registered_handoff.binding
                    ),
                )
        except AgentKernelError as error:
            if self._exact_prework_handoff_won_acquisition(
                record,
                proposed_binding=proposed_binding,
                registered_handoff=registered_handoff,
                error=error,
            ):
                raise _RecoveryHandoffContended from error
            raise
        try:
            return await self._authorize_recovery_work_claimed(
                record,
                kind=kind,
                target=target,
                predecessor=predecessor,
                handoff_lease=claimed.lease,
                lineage_projection=lineage_projection,
            )
        finally:
            current_lease = self._store.get_worker_lease(
                tenant_id=claimed.lease.tenant_id,
                transaction_id=claimed.lease.transaction_id,
                lease_id=claimed.lease.lease_id,
            )
            if current_lease.released_at is None:
                self._store.release_worker_lease(
                    tenant_id=current_lease.tenant_id,
                    transaction_id=current_lease.transaction_id,
                    lease_id=current_lease.lease_id,
                    expected_version=current_lease.version,
                    released_at=self._now(),
                )

    async def _authorize_recovery_work_claimed(
        self,
        record: EnforcedTransactionRecord,
        *,
        kind: RecoveryWorkKind,
        target: StageMaterialRecord | CommitDispatchRecord,
        predecessor: RecoveryWorkRecord | None = None,
        handoff_lease: WorkerLeaseRecord | None = None,
        lineage_projection: EnforcedTransactionProjection,
    ) -> RecoveryWorkRecord:
        target_ref = canonical_digest(target)
        if (
            record.intent_hash is None
            or record.normalized_action_digest is None
            or record.adapter is None
            or record.operation is None
            or record.adapter_manifest_digest is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target lacks complete planned-action bindings",
            )
        target_action = self._store.get_normalized_action(
            record.tenant_id,
            record.transaction_id,
        ).action
        if canonical_digest(target_action) != record.normalized_action_digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target action differs from the durable transaction binding",
            )
        target_history = self._store.list_intent_history(
            tenant_id=record.tenant_id,
            intent_hash=record.intent_hash,
        )
        if not target_history:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target intent history is empty",
            )
        target_head = target_history[-1]
        if isinstance(target, StageMaterialRecord):
            target_id = target.stage_id
            target_version_guard = target.target_version_guard
            target_owner_version = target_head.owner_version
            target_owner_history_sequence = target_head.sequence
            target_owner_history_digest = target_head.history_digest
        else:
            target_id = target.dispatch_id
            target_version_guard = target.permit.target_version_guard
            # A recovery permit controls the already-dispatched generation.  Its target
            # ownership is the immutable dispatch permit binding, not the later intent
            # history head advanced by precommit/recovery reservations.
            target_owner_version = target.permit.owner_version
            target_owner_history_sequence = target.permit.owner_history_sequence
            target_owner_history_digest = target.permit.owner_history_digest
        now = self._now()
        if predecessor is None:
            recovery_ordinal = 1
            max_recovery_attempts = (
                self._config.max_reconciliation_attempts
                if kind is RecoveryWorkKind.RECONCILE_DISPATCH
                else 1
            )
            predecessor_recovery_id = None
            not_before = record.updated_at
            deadline = self._store.get_transaction_recovery_deadline(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
            recovery_id = _stable_id(
                "recovery",
                {
                    "tenant_id": record.tenant_id,
                    "transaction_id": record.transaction_id,
                    "kind": kind.value,
                    "target_ref": target_ref,
                    "ordinal": recovery_ordinal,
                },
            )
            root_recovery_id = recovery_id
        else:
            if (
                kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                or predecessor.kind is not kind
                or predecessor.transaction_id != record.transaction_id
                or predecessor.target_id != target_id
                or predecessor.target_version_guard != target_version_guard
                or predecessor.state is not RecoveryWorkState.RETRY_SCHEDULED
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation successor differs from its scheduled predecessor",
                )
            attempt = self._store.get_reconciliation_attempt(
                tenant_id=predecessor.tenant_id,
                transaction_id=predecessor.transaction_id,
                recovery_id=predecessor.recovery_id,
                attempt=predecessor.attempt,
            )
            if (
                attempt.outcome is not ReconciliationOutcome.UNKNOWN
                or attempt.next_attempt_not_before is None
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Scheduled reconciliation predecessor lacks a durable UNKNOWN backoff",
                )
            not_before = attempt.next_attempt_not_before
            if now < not_before:
                raise AgentKernelError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "Reconciliation retry backoff has not elapsed",
                    retryable=True,
                )
            recovery_ordinal = predecessor.recovery_ordinal + 1
            max_recovery_attempts = predecessor.max_recovery_attempts
            predecessor_recovery_id = predecessor.recovery_id
            root_recovery_id = predecessor.root_recovery_id
            deadline = predecessor.deadline
            recovery_id = _stable_id(
                "recovery",
                {
                    "tenant_id": record.tenant_id,
                    "root_recovery_id": root_recovery_id,
                    "predecessor_recovery_id": predecessor_recovery_id,
                    "ordinal": recovery_ordinal,
                    "target_ref": target_ref,
                },
            )
        proposed_binding = RecoveryActionBinding(
            target_transaction_id=record.transaction_id,
            target_intent_hash=record.intent_hash,
            target_normalized_action_digest=record.normalized_action_digest,
            recovery_kind=kind,
            target_id=target_id,
            target_evidence_ref=target_ref,
            target_version_guard=target_version_guard,
            target_owner_version=target_owner_version,
            target_owner_history_sequence=target_owner_history_sequence,
            target_owner_history_digest=target_owner_history_digest,
            adapter_manifest_digest=record.adapter_manifest_digest,
            risk_class=target_action.risk_floor,
            effect_domains=target_action.effect_domains,
            resource_uses_digest=canonical_digest(target_action.resource_uses),
            recovery_id=recovery_id,
            root_recovery_id=root_recovery_id,
            predecessor_recovery_id=predecessor_recovery_id,
            recovery_ordinal=recovery_ordinal,
            max_recovery_attempts=max_recovery_attempts,
            not_before=not_before,
            absolute_deadline=deadline,
        )
        registered_handoff = self._store.get_recovery_action_handoff(
            tenant_id=record.tenant_id,
            target_transaction_id=record.transaction_id,
            recovery_id=recovery_id,
        )
        if registered_handoff is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery lease acquisition lost its atomic action handoff reservation",
            )
        binding = registered_handoff.binding
        if (
            binding.target_transaction_id != proposed_binding.target_transaction_id
            or binding.target_intent_hash != proposed_binding.target_intent_hash
            or binding.target_normalized_action_digest
            != proposed_binding.target_normalized_action_digest
            or binding.recovery_kind is not proposed_binding.recovery_kind
            or binding.target_id != proposed_binding.target_id
            or binding.target_evidence_ref != proposed_binding.target_evidence_ref
            or binding.target_version_guard != proposed_binding.target_version_guard
            or binding.target_owner_version != proposed_binding.target_owner_version
            or binding.target_owner_history_sequence
            != proposed_binding.target_owner_history_sequence
            or binding.target_owner_history_digest != proposed_binding.target_owner_history_digest
            or binding.adapter_manifest_digest != proposed_binding.adapter_manifest_digest
            or binding.risk_class is not proposed_binding.risk_class
            or binding.effect_domains != proposed_binding.effect_domains
            or binding.resource_uses_digest != proposed_binding.resource_uses_digest
            or binding.recovery_id != proposed_binding.recovery_id
            or binding.root_recovery_id != proposed_binding.root_recovery_id
            or binding.predecessor_recovery_id != proposed_binding.predecessor_recovery_id
            or binding.recovery_ordinal != proposed_binding.recovery_ordinal
            or (
                predecessor is not None
                and binding.max_recovery_attempts != proposed_binding.max_recovery_attempts
            )
            or binding.not_before != proposed_binding.not_before
            or registered_handoff.closed_at is not None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Durable recovery action handoff differs from its target generation",
            )
        deadline = binding.absolute_deadline
        max_recovery_attempts = binding.max_recovery_attempts
        stored_recovery_action = registered_handoff.action
        handoff_deadline = (
            deadline if handoff_lease is None else min(deadline, handoff_lease.expires_at)
        )
        if self._now() >= handoff_deadline:
            error = AgentKernelError(
                ErrorCode.DEADLINE_EXCEEDED,
                "Recovery authorization handoff deadline elapsed before artifact publication",
            )
            self._settle_recovery_authorization_failure(
                record,
                binding=binding,
                error=error,
                handoff_lease=handoff_lease,
                attached_recovery_action=stored_recovery_action,
            )
            raise error
        self._validate_completed_recovery_operation_evidence(lineage_projection)
        published_target_ref = self._put_model(target)
        if published_target_ref != target_ref:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target artifact differs from its durable record",
            )
        recovery_action, recovery_action_ref, binding_ref = await self._attach_recovery_action(
            record,
            target_action=target_action,
            kind=kind,
            target_ref=target_ref,
            binding=binding,
            expected_binding_ref=registered_handoff.binding_ref,
            stored_recovery_action=stored_recovery_action,
            handoff_lease=handoff_lease,
        )
        self._crash(CoordinatorCrashPoint.AFTER_RECOVERY_ACTION_ATTACHED)
        try:
            authorization = await self._evaluate_authorization(
                recovery_action,
                purpose=AuthorizationRoundPurpose.RECOVERY,
                controlled_transaction_id=record.transaction_id,
                operation_deadline=(None if handoff_lease is None else handoff_lease.expires_at),
            )
            self._check_authorization_valid(
                authorization,
                boundary="recovery authorization persistence",
            )
            self._check_deadline(
                (
                    recovery_action.deadline
                    if handoff_lease is None
                    else min(recovery_action.deadline, handoff_lease.expires_at)
                ),
                self._now(),
                boundary="recovery authorization persistence",
            )
        except (Exception, CancelledError) as error:
            self._settle_recovery_authorization_failure(
                record,
                binding=binding,
                error=error,
                handoff_lease=handoff_lease,
                attached_recovery_action=recovery_action,
            )
            raise
        try:
            if (
                authorization.round.verdict is AuthorizationVerdict.ELIGIBLE
                and _APPROVAL_OBLIGATION in authorization.round.obligations
            ):
                raise AgentKernelError(
                    ErrorCode.APPROVAL_REQUIRED,
                    "Recovery policy requires an unavailable bound approval service",
                    review_required=True,
                )
            approval_evidence_ref = self._put_control_evidence(
                transaction_id=recovery_action.transaction_id,
                event="recovery.approval_not_required",
                reason_code="NO_APPROVAL_REQUIRED",
                recorded_at=authorization.round.evaluated_at,
                subject_ref=recovery_action_ref,
            )
            handoff_failure_evidence_ref: str | None = None
            handoff_failure_evidence_status = RecoveryHandoffFailureEvidenceStatus.NONE
            handoff_failure_reason_code: str | None = None
            if authorization.round.verdict is not AuthorizationVerdict.ELIGIBLE:
                if authorization.round.reason_code is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Terminal recovery authorization lacks a reason code",
                    )
                (
                    handoff_failure_evidence_ref,
                    handoff_failure_reason_code,
                    (handoff_failure_evidence_status),
                ) = self._put_failure_evidence_or_fallback(
                    transaction_id=record.transaction_id,
                    event=(
                        TransitionEvent.STAGING_DISCARD_FAILED.value
                        if kind is RecoveryWorkKind.DISCARD_STAGING
                        else "recovery.authorization_handoff_failed"
                    ),
                    reason_code=authorization.round.reason_code,
                    recorded_at=authorization.round.evaluated_at,
                    subject_ref=(
                        target_ref if kind is RecoveryWorkKind.DISCARD_STAGING else binding_ref
                    ),
                )
            work_state = {
                AuthorizationVerdict.ELIGIBLE: RecoveryWorkState.PENDING,
                AuthorizationVerdict.DENIED: RecoveryWorkState.FAILED,
                AuthorizationVerdict.UNKNOWN: RecoveryWorkState.REVIEW_REQUIRED,
            }[authorization.round.verdict]
            work = RecoveryWorkRecord(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
                intent_hash=record.intent_hash,
                recovery_id=recovery_id,
                root_recovery_id=root_recovery_id,
                predecessor_recovery_id=predecessor_recovery_id,
                recovery_ordinal=recovery_ordinal,
                max_recovery_attempts=max_recovery_attempts,
                not_before=not_before,
                recovery_action_transaction_id=recovery_action.transaction_id,
                recovery_action_intent_hash=recovery_action.intent_hash,
                recovery_action_digest=recovery_action_ref,
                adapter_manifest_digest=recovery_action.adapter_manifest_digest,
                kind=kind,
                target_id=target_id,
                target_owner_version=target_owner_version,
                target_owner_history_sequence=target_owner_history_sequence,
                target_owner_history_digest=target_owner_history_digest,
                target_evidence_ref=target_ref,
                target_version_guard=target_version_guard,
                state=work_state,
                authorization_round_id=authorization.round.round_id,
                authorization_round_digest=authorization.round.round_digest,
                authority_decision_digest=authorization.round.authority_decision_digest,
                policy_decision_digest=authorization.round.policy_decision_digest,
                policy_snapshot_digest=authorization.round.policy_snapshot_digest,
                capability_reservation_digest=(
                    None
                    if authorization.reservation is None
                    else capability_reservation_digest(authorization.reservation)
                ),
                reservation_version=(
                    None if authorization.reservation is None else authorization.reservation.version
                ),
                owner_version=authorization.round.owner_version,
                owner_history_sequence=authorization.round.owner_history_sequence,
                owner_history_digest=authorization.round.owner_history_digest,
                approval_required=False,
                approval_id=None,
                approval_evidence_ref=approval_evidence_ref,
                deadline=deadline,
                version=0,
                evidence_refs=(
                    (binding_ref,)
                    if authorization.round.verdict is AuthorizationVerdict.ELIGIBLE
                    else tuple(
                        sorted(
                            {
                                authorization.round.round_digest,
                                binding_ref,
                                *(
                                    (handoff_failure_evidence_ref,)
                                    if handoff_failure_evidence_ref is not None
                                    else ()
                                ),
                            }
                        )
                    )
                ),
                reason_code=(
                    None
                    if authorization.round.verdict is AuthorizationVerdict.ELIGIBLE
                    else authorization.round.reason_code
                ),
                created_at=authorization.round.evaluated_at,
                updated_at=authorization.round.evaluated_at,
            )
            self._check_deadline(
                (
                    recovery_action.deadline
                    if handoff_lease is None
                    else min(recovery_action.deadline, handoff_lease.expires_at)
                ),
                self._now(),
                boundary="recovery handoff persistence",
            )
            self._validate_completed_recovery_operation_evidence(lineage_projection)
            persisted = self._store.authorize_recovery(
                work,
                authorization_round=authorization.round,
                authority_decision=authorization.authority,
                policy_decision=authorization.policy,
                capability_ids=authorization.capability_ids,
                handoff_lease=handoff_lease,
                handoff_failure_evidence_ref=handoff_failure_evidence_ref,
                handoff_failure_evidence_status=handoff_failure_evidence_status,
                handoff_failure_reason_code=handoff_failure_reason_code,
            )
        except (Exception, CancelledError) as error:
            self._settle_recovery_authorization_failure(
                record,
                binding=binding,
                error=error,
                handoff_lease=handoff_lease,
                attached_recovery_action=recovery_action,
            )
            raise
        self._crash(CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED)
        return persisted.work

    def _terminalize_expired_recovery(
        self,
        work: RecoveryWorkRecord,
        *,
        reported_at: datetime,
    ) -> RecoveryWorkRecord:
        """Persist ordinary deadline evidence, using typed fallback only on artifact outage."""

        if work.state is RecoveryWorkState.RETRY_SCHEDULED:
            self._validate_reconciliation_lineage_operation_evidence(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
            )
        handoff = self._store.get_recovery_action_handoff(
            tenant_id=work.tenant_id,
            target_transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        if handoff is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Expired recovery work lost its durable action handoff",
            )
        evidence_event = (
            TransitionEvent.STAGING_DISCARD_FAILED.value
            if work.kind is RecoveryWorkKind.DISCARD_STAGING
            else "recovery.authorization_handoff_failed"
        )
        evidence_subject_ref = (
            work.target_evidence_ref
            if work.kind is RecoveryWorkKind.DISCARD_STAGING
            else handoff.binding_ref
        )
        if work.state is RecoveryWorkState.RETRY_SCHEDULED:
            current_dispatch = self._store.get_commit_dispatch(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
            )
            expected_successor_recovery_id = scheduled_reconciliation_successor_recovery_id(
                work,
                current_dispatch,
            )
            (
                failure_evidence_ref,
                _failure_reason_code,
                failure_evidence_status,
            ) = self._put_failure_evidence_or_fallback(
                transaction_id=work.transaction_id,
                event=evidence_event,
                reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                recorded_at=reported_at,
                subject_ref=evidence_subject_ref,
            )
            return self._store.terminalize_scheduled_reconciliation_deadline(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
                recovery_id=work.recovery_id,
                expected_successor_recovery_id=expected_successor_recovery_id,
                expected_work_version=work.version,
                failure_evidence_ref=failure_evidence_ref,
                failure_evidence_status=failure_evidence_status,
                recorded_at=reported_at,
            ).work
        try:
            evidence_ref = self._put_control_evidence(
                transaction_id=work.transaction_id,
                event=evidence_event,
                reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                recorded_at=reported_at,
                subject_ref=evidence_subject_ref,
            )
        except (Exception, CancelledError) as error:
            if not self._is_evidence_store_outage(error):
                raise
            authorization_round = self._store.get_authorization_round(
                tenant_id=work.tenant_id,
                controlled_transaction_id=work.transaction_id,
                round_id=work.authorization_round_id,
            )
            if authorization_round.authority_valid_until is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery deadline fallback lost its authority deadline",
                ) from error
            bounded_deadline = min(
                work.deadline,
                authorization_round.authority_valid_until,
            )
            return self._terminalize_recovery_evidence_unavailable(
                work,
                boundary=(
                    "RECOVERY_DEADLINE"
                    if reported_at >= bounded_deadline
                    else "RECOVERY_LEASE_EXPIRED"
                ),
                reported_at=reported_at,
                cause=error,
            )
        if work.state is RecoveryWorkState.PENDING:
            return self._store.fail_recovery_revalidation(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
                recovery_id=work.recovery_id,
                expected_work_version=work.version,
                target_state=RecoveryWorkState.REVIEW_REQUIRED,
                evidence_refs=(evidence_ref,),
                reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                recorded_at=reported_at,
                handoff_failure_evidence_ref=evidence_ref,
                handoff_failure_evidence_status=(RecoveryHandoffFailureEvidenceStatus.AVAILABLE),
                handoff_failure_reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
            ).work
        if work.state is RecoveryWorkState.RUNNING:
            return self._store.record_late_recovery_outcome(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
                recovery_id=work.recovery_id,
                expected_work_version=work.version,
                evidence_refs=(evidence_ref,),
                operation_evidence_ref=evidence_ref,
                operation_reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                reported_at=reported_at,
                reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
            ).work
        raise AgentKernelError(
            ErrorCode.VERSION_CONFLICT,
            "Recovery deadline settlement lost its executable generation",
        )

    def _claim_or_reclaim_recovery(self, work: RecoveryWorkRecord) -> RecoveryWorkRecord | None:
        authorization_round = self._store.get_authorization_round(
            tenant_id=work.tenant_id,
            controlled_transaction_id=work.transaction_id,
            round_id=work.authorization_round_id,
        )
        now = self._now()
        if authorization_round.authority_valid_until is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Executable recovery authorization lacks its authority deadline",
            )
        bounded_deadline = min(work.deadline, authorization_round.authority_valid_until)
        released_lease = None
        if work.state is RecoveryWorkState.RUNNING:
            if work.lease_id is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Running recovery work lacks its lease",
                )
            released_lease = self._store.get_worker_lease(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
                lease_id=work.lease_id,
            )
            if released_lease.released_at is not None:
                return self._terminalize_recovery_evidence_unavailable(
                    work,
                    boundary="RECOVERY_LEASE_RELEASED",
                    reported_at=now,
                    cause="RECOVERY_LEASE_RELEASED_WITH_UNKNOWN_OUTCOME",
                )
        if now >= bounded_deadline:
            if work.state in {RecoveryWorkState.PENDING, RecoveryWorkState.RUNNING}:
                return self._terminalize_expired_recovery(work, reported_at=now)
            return None
        if work.state is RecoveryWorkState.RUNNING:
            if released_lease is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Running recovery work lost its inspected lease",
                )
            old_lease = released_lease
            if old_lease.expires_at > now:
                return None
            return self._terminalize_recovery_evidence_unavailable(
                work,
                boundary="RECOVERY_LEASE_EXPIRED",
                reported_at=now,
                cause="RECOVERY_LEASE_EXPIRED_WITH_UNKNOWN_OUTCOME",
            )
        if work.state is not RecoveryWorkState.PENDING:
            return None
        self._validate_authorization_artifacts(authorization_round)
        expires = min(bounded_deadline, now + self._config.lease_duration)
        lease_id = _stable_id(
            "lease.recovery",
            {
                "tenant_id": work.tenant_id,
                "recovery_id": work.recovery_id,
                "attempt": work.attempt + 1,
                "worker": self._config.worker_id,
            },
        )
        preview = self._store.preview_recovery_claim(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
            expected_work_version=work.version,
            lease_id=lease_id,
            worker_id=self._config.worker_id,
            acquired_at=now,
            expires_at=expires,
        )
        permit_ref = self._put_model(preview.permit)
        if permit_ref != preview.permit_ref:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery claim preview differs from its canonical permit artifact",
            )
        claimed = self._store.claim_recovery(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
            expected_work_version=work.version,
            lease_id=lease_id,
            worker_id=self._config.worker_id,
            acquired_at=now,
            expires_at=expires,
            permit=preview.permit,
            permit_ref=permit_ref,
        )
        self._crash(CoordinatorCrashPoint.AFTER_RECOVERY_CLAIMED)
        return claimed.work

    def _terminalize_recovery_evidence_unavailable(
        self,
        work: RecoveryWorkRecord,
        *,
        boundary: str,
        reported_at: datetime,
        cause: BaseException | str,
    ) -> RecoveryWorkRecord:
        cause_code = (
            cause.code.value
            if isinstance(cause, AgentKernelError)
            else "CANCELLED"
            if isinstance(cause, CancelledError)
            else cause
            if isinstance(cause, str)
            else "RECOVERY_EVIDENCE_WRITE_FAILED"
        )
        reason_code = f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{cause_code}"
        supporting_refs = tuple(
            sorted(
                {
                    *work.evidence_refs,
                    work.authorization_round_digest,
                    work.recovery_action_digest,
                    work.target_evidence_ref,
                    work.approval_evidence_ref,
                    *((work.permit_ref,) if work.permit_ref is not None else ()),
                }
            )
        )
        result = self._store.terminalize_recovery_evidence_unavailable(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
            expected_work_version=work.version,
            boundary=boundary,
            supporting_refs=supporting_refs,
            reported_at=reported_at,
            reason_code=reason_code,
        )
        return result.work

    def _terminalize_dispatch_evidence_unavailable(
        self,
        record: EnforcedTransactionRecord,
        dispatch: CommitDispatchRecord,
        *,
        boundary: str,
        reported_at: datetime,
        cause: str,
        supporting_refs: tuple[str, ...] = (),
    ) -> EnforcedTransactionRecord:
        reason_code = f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{cause}"
        result = self._store.classify_dispatch_evidence_unavailable(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
            expected_dispatch_version=dispatch.version,
            expected_transaction_version=record.version,
            boundary=boundary,
            supporting_refs=supporting_refs,
            recorded_at=reported_at,
            reason_code=reason_code,
            recovery_timeout=self._config.recovery_deadline,
        )
        return result.transaction

    def _load_recovery_target_snapshot(
        self,
        work: RecoveryWorkRecord,
    ) -> StageMaterialRecord | CommitDispatchRecord:
        """Resolve the exact authorized target artifact before any recovery provider I/O."""

        if work.permit is None or work.permit_ref is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target evidence gate requires an issued permit",
            )
        if work.kind is RecoveryWorkKind.DISCARD_STAGING:
            stage_target = self._store.get_stage_material(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
            )
            target: StageMaterialRecord | CommitDispatchRecord = stage_target
            target_id = stage_target.stage_id
            target_guard = stage_target.target_version_guard
            stage_artifact = self._get_artifact_model(
                work.target_evidence_ref,
                StageMaterialRecord,
            )
            artifact_target: StageMaterialRecord | CommitDispatchRecord = stage_artifact
        else:
            dispatch_target = self._store.get_commit_dispatch(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
            )
            target = dispatch_target
            target_id = dispatch_target.dispatch_id
            target_guard = dispatch_target.permit.target_version_guard
            dispatch_artifact = self._get_artifact_model(
                work.target_evidence_ref,
                CommitDispatchRecord,
            )
            artifact_target = dispatch_artifact
        if (
            canonical_digest(target) != work.target_evidence_ref
            or artifact_target != target
            or target_id != work.target_id
            or target_guard != work.target_version_guard
            or work.permit.target_id != work.target_id
            or work.permit.target_evidence_ref != work.target_evidence_ref
            or work.permit.target_version_guard != work.target_version_guard
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target differs from its admitted SQL and artifact generation",
            )
        return target

    async def _run_recovery_work(self, work: RecoveryWorkRecord) -> EnforcedTransactionStatus:
        phase = _RecoveryExecutionPhase(
            boundary=(
                "RECONCILIATION_SETUP_OR_QUERY"
                if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                else "POST_CLAIM_SETUP"
            )
        )
        if work.state is RecoveryWorkState.PENDING:
            self._validate_reconciliation_lineage_operation_evidence(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
            )
        elif work.state is RecoveryWorkState.RUNNING:
            if work.lease_id is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Running recovery work lost its lineage-inspection lease",
                )
            inspected_lease = self._store.get_worker_lease(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
                lease_id=work.lease_id,
            )
            if inspected_lease.released_at is None:
                self._validate_reconciliation_lineage_operation_evidence(
                    tenant_id=work.tenant_id,
                    transaction_id=work.transaction_id,
                )
        try:
            return await self._run_recovery_work_unsettled(work, phase=phase)
        except (Exception, CancelledError) as error:
            if phase.lineage_revalidation:
                raise
            current = self._store.get_recovery_work(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
                recovery_id=work.recovery_id,
            )
            if current.state is RecoveryWorkState.RUNNING:
                is_deadline = (
                    isinstance(error, AgentKernelError)
                    and error.code is ErrorCode.DEADLINE_EXCEEDED
                )
                if is_deadline:
                    self._terminalize_expired_recovery(
                        current,
                        reported_at=self._now(),
                    )
                elif self._is_evidence_store_outage(error):
                    self._terminalize_recovery_evidence_unavailable(
                        current,
                        boundary=phase.boundary,
                        reported_at=self._now(),
                        cause=error,
                    )
                elif not phase.provider_entered and not (
                    isinstance(error, AgentKernelError) and error.code is ErrorCode.INTEGRITY_ERROR
                ):
                    recorded_at = self._now()
                    reason_code = (
                        error.code.value
                        if isinstance(error, AgentKernelError)
                        else "RECOVERY_SETUP_CANCELLED"
                        if isinstance(error, CancelledError)
                        else "RECOVERY_SETUP_INTERNAL_FAILURE"
                    )
                    try:
                        if current.kind is RecoveryWorkKind.DISCARD_STAGING:
                            evidence_event = TransitionEvent.STAGING_DISCARD_FAILED.value
                            evidence_subject_ref = current.target_evidence_ref
                        else:
                            handoff = self._store.get_recovery_action_handoff(
                                tenant_id=current.tenant_id,
                                target_transaction_id=current.transaction_id,
                                recovery_id=current.recovery_id,
                            )
                            if handoff is None:
                                raise AgentKernelError(
                                    ErrorCode.INTEGRITY_ERROR,
                                    "Claimed recovery setup lost its durable handoff",
                                )
                            evidence_event = "recovery.authorization_handoff_failed"
                            evidence_subject_ref = handoff.binding_ref
                        evidence_ref = self._put_control_evidence(
                            transaction_id=current.transaction_id,
                            event=evidence_event,
                            reason_code=reason_code,
                            recorded_at=recorded_at,
                            subject_ref=evidence_subject_ref,
                        )
                        self._store.fail_claimed_recovery_setup(
                            tenant_id=current.tenant_id,
                            transaction_id=current.transaction_id,
                            recovery_id=current.recovery_id,
                            expected_work_version=current.version,
                            failure_evidence_ref=evidence_ref,
                            reason_code=reason_code,
                            recorded_at=recorded_at,
                        )
                    except (Exception, CancelledError) as settlement_error:
                        if not self._is_evidence_store_outage(settlement_error):
                            raise
                        refreshed = self._store.get_recovery_work(
                            tenant_id=current.tenant_id,
                            transaction_id=current.transaction_id,
                            recovery_id=current.recovery_id,
                        )
                        if refreshed.state is RecoveryWorkState.RUNNING:
                            self._terminalize_recovery_evidence_unavailable(
                                refreshed,
                                boundary=phase.boundary,
                                reported_at=self._now(),
                                cause=settlement_error,
                            )
            raise

    async def _run_recovery_work_unsettled(
        self,
        work: RecoveryWorkRecord,
        *,
        phase: _RecoveryExecutionPhase,
    ) -> EnforcedTransactionStatus:
        phase.lineage_revalidation = work.state is RecoveryWorkState.RUNNING
        claimed = self._claim_or_reclaim_recovery(work)
        if claimed is None or claimed.state is not RecoveryWorkState.RUNNING:
            return self.status(work.tenant_id, work.transaction_id)
        phase.boundary = "RECOVERY_LINEAGE_REVALIDATION"
        phase.lineage_revalidation = True
        self._validate_reconciliation_lineage_operation_evidence(
            tenant_id=claimed.tenant_id,
            transaction_id=claimed.transaction_id,
        )
        phase.lineage_revalidation = False
        phase.boundary = (
            "RECONCILIATION_SETUP_OR_QUERY"
            if claimed.kind is RecoveryWorkKind.RECONCILE_DISPATCH
            else "POST_CLAIM_SETUP"
        )
        if claimed.permit is None or claimed.permit_ref is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Claimed recovery work lacks its exact permit artifact",
            )
        self._check_deadline(
            claimed.permit.deadline,
            self._now(),
            boundary="post-claim recovery setup",
        )
        target_snapshot = self._load_recovery_target_snapshot(claimed)
        recovery_action = self._store.get_normalized_action(
            claimed.tenant_id,
            claimed.recovery_action_transaction_id,
        ).action
        admitted = self._registry.resolve_admitted(
            recovery_action.adapter,
            recovery_action.operation,
            enforcement_profile=True,
        )
        if admitted.manifest_digest != claimed.adapter_manifest_digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery adapter admission changed after authorization",
            )
        context = RecoveryContext(
            deadline=claimed.permit.deadline,
            authority_ref=claimed.authorization_round_digest,
            worker_id=claimed.worker_id,
            permit=claimed.permit,
            permit_ref=claimed.permit_ref,
        )
        if claimed.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
            if not isinstance(target_snapshot, CommitDispatchRecord):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation target evidence is not a commit dispatch",
                )
            await self._run_reconciliation(
                claimed,
                admitted.adapter,
                context,
                target_dispatch=target_snapshot,
                phase=phase,
            )
            return self.status(claimed.tenant_id, claimed.transaction_id)
        target_action = self._store.get_normalized_action(
            claimed.tenant_id,
            claimed.transaction_id,
        ).action
        result_evidence_refs: tuple[str, ...] = ()
        operation_evidence_ref: str | None = None
        try:
            self._check_deadline(
                context.deadline,
                self._now(),
                boundary="recovery adapter dispatch",
            )
            self._crash(CoordinatorCrashPoint.BEFORE_RECOVERY_ADAPTER)
            dispatch: CommitDispatchRecord | None = None
            if claimed.kind is RecoveryWorkKind.DISCARD_STAGING:
                if not isinstance(target_snapshot, StageMaterialRecord):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Discard target evidence is not private stage material",
                    )
                subject_ref = claimed.target_evidence_ref
                evidence_kind = "discard_staging"
                phase.boundary = "RECOVERY_ADAPTER_OR_EVIDENCE"
                phase.provider_entered = True
                report = await self._await_provider(
                    lambda: admitted.adapter.abort_stage(claimed.target_id, context),
                    deadline=context.deadline,
                    boundary="stage-discard recovery adapter",
                    enforce_completion_deadline=False,
                )
            else:
                if not isinstance(target_snapshot, CommitDispatchRecord):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Effect recovery target evidence is not a commit dispatch",
                    )
                dispatch = target_snapshot
                if dispatch.effect_receipt_ref is None:
                    raise AgentKernelError(
                        ErrorCode.EVIDENCE_UNAVAILABLE,
                        "Effect-bearing recovery lacks an authoritative receipt artifact",
                    )
                receipt = self._get_artifact_model(
                    dispatch.effect_receipt_ref,
                    EffectReceipt,
                )
                subject_ref = dispatch.effect_receipt_ref
                if claimed.kind is RecoveryWorkKind.ROLLBACK:
                    evidence_kind = "rollback"
                    phase.boundary = "RECOVERY_ADAPTER_OR_EVIDENCE"
                    phase.provider_entered = True
                    report = await self._await_provider(
                        lambda: admitted.adapter.rollback(receipt, context),
                        deadline=context.deadline,
                        boundary="rollback recovery adapter",
                        enforce_completion_deadline=False,
                    )
                elif claimed.kind is RecoveryWorkKind.COMPENSATE:
                    evidence_kind = "compensation"
                    phase.boundary = "RECOVERY_ADAPTER_OR_EVIDENCE"
                    phase.provider_entered = True
                    report = await self._await_provider(
                        lambda: admitted.adapter.compensate(receipt, context),
                        deadline=context.deadline,
                        boundary="compensation recovery adapter",
                        enforce_completion_deadline=False,
                    )
                else:
                    raise AgentKernelError(
                        ErrorCode.UNSUPPORTED_SEMANTICS,
                        "Unknown recovery work kind",
                    )
            report_received_at = self._now()
            self._crash(CoordinatorCrashPoint.AFTER_RECOVERY_ADAPTER_CALL)
            report_ref = self._put_model(report)
            result_evidence_refs = tuple(sorted({report_ref, *report.evidence_refs}))
            if report.status is VerificationStatus.PASS and report.restored_state_digest is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Successful recovery report lacks its observed restored-state digest",
                )
            operation_evidence_ref, _ = self._validate_adapter_observation(
                report.evidence_refs,
                evidence_kind=evidence_kind,
                action=target_action,
                adapter_manifest_digest=claimed.adapter_manifest_digest,
                subject_ref=subject_ref,
                operation_permit_ref=claimed.permit_ref,
                authority_permit_ref=claimed.permit_ref,
                subject_authority_ref=claimed.permit.target_evidence_ref,
                operation_status=report.status.value,
                permit_issued_at=claimed.permit.issued_at,
                permit_deadline=claimed.permit.deadline,
                received_at=report_received_at,
                dispatch=dispatch,
                expected_observed_state_digest=report.restored_state_digest,
                allow_late=True,
            )
            completed_at = report_received_at
            if completed_at >= context.deadline:
                late = self._store.record_late_recovery_outcome(
                    tenant_id=claimed.tenant_id,
                    transaction_id=claimed.transaction_id,
                    recovery_id=claimed.recovery_id,
                    expected_work_version=claimed.version,
                    evidence_refs=result_evidence_refs,
                    operation_evidence_ref=operation_evidence_ref,
                    operation_reason_code=None,
                    reported_at=completed_at,
                    reason_code="RECOVERY_RESULT_AFTER_PERMIT_DEADLINE",
                )
                return self.status(
                    late.transaction.tenant_id,
                    late.transaction.transaction_id,
                )
            succeeded = report.status is VerificationStatus.PASS
            finished = self._store.finish_recovery(
                tenant_id=claimed.tenant_id,
                transaction_id=claimed.transaction_id,
                recovery_id=claimed.recovery_id,
                expected_work_version=claimed.version,
                succeeded=succeeded,
                evidence_refs=result_evidence_refs,
                operation_evidence_ref=operation_evidence_ref,
                completed_at=completed_at,
                reason_code=None if succeeded else "RECOVERY_VERIFICATION_FAILED",
            )
            self._crash(CoordinatorCrashPoint.AFTER_RECOVERY_FINISHED)
            return self.status(
                finished.transaction.tenant_id,
                finished.transaction.transaction_id,
            )
        except (Exception, CancelledError) as error:
            current = self._store.get_recovery_work(
                tenant_id=claimed.tenant_id,
                transaction_id=claimed.transaction_id,
                recovery_id=claimed.recovery_id,
            )
            if current.state is RecoveryWorkState.RUNNING:
                reason = (
                    error.code.value
                    if isinstance(error, AgentKernelError)
                    else "RECOVERY_CANCELLED_AFTER_PROVIDER_ENTRY"
                    if isinstance(error, CancelledError)
                    else "RECOVERY_EXECUTION_FAILED"
                )
                evidence_ref = self._put_control_evidence(
                    transaction_id=claimed.transaction_id,
                    event="recovery.execution_failed",
                    reason_code=reason,
                    recorded_at=self._now(),
                    subject_ref=claimed.permit_ref,
                )
                recorded_at = self._now()
                failure_refs = tuple(sorted({*result_evidence_refs, evidence_ref}))
                if recorded_at >= context.deadline:
                    self._store.record_late_recovery_outcome(
                        tenant_id=claimed.tenant_id,
                        transaction_id=claimed.transaction_id,
                        recovery_id=claimed.recovery_id,
                        expected_work_version=current.version,
                        evidence_refs=failure_refs,
                        operation_evidence_ref=evidence_ref,
                        operation_reason_code=reason,
                        reported_at=recorded_at,
                        reason_code="RECOVERY_RESULT_AFTER_PERMIT_DEADLINE",
                    )
                else:
                    self._store.finish_recovery(
                        tenant_id=claimed.tenant_id,
                        transaction_id=claimed.transaction_id,
                        recovery_id=claimed.recovery_id,
                        expected_work_version=current.version,
                        succeeded=False,
                        evidence_refs=failure_refs,
                        operation_evidence_ref=evidence_ref,
                        completed_at=recorded_at,
                        reason_code=reason,
                    )
            raise

    async def _run_reconciliation(
        self,
        work: RecoveryWorkRecord,
        adapter: EffectAdapter,
        context: RecoveryContext,
        *,
        target_dispatch: CommitDispatchRecord,
        phase: _RecoveryExecutionPhase,
    ) -> None:
        if work.permit is None or work.permit_ref is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation lost its recovery permit evidence",
            )
        self._check_deadline(
            context.deadline,
            self._now(),
            boundary="reconciliation setup",
        )
        action = self._store.get_normalized_action(
            work.tenant_id,
            work.transaction_id,
        ).action
        dispatch = target_dispatch
        action_ref = canonical_digest(action)
        self._get_artifact(action_ref)
        intent = IntentRecord(
            intent_hash=action.intent_hash,
            transaction_id=action.transaction_id,
            idempotency_key=action.idempotency_key or action.intent_hash,
            dispatched=True,
            outcome_receipt_ref=dispatch.effect_receipt_ref,
            created_at=dispatch.created_at,
        )
        intent_ref = self._put_model(intent)
        started = self._store.start_reconciliation(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
            expected_work_version=work.version,
            evidence_refs=(intent_ref,),
            started_at=self._now(),
        )
        self._crash(CoordinatorCrashPoint.AFTER_RECONCILIATION_STARTED)
        evidence_refs = {intent_ref}
        try:
            self._check_deadline(
                context.deadline,
                self._now(),
                boundary="reconciliation query",
            )
            self._crash(CoordinatorCrashPoint.BEFORE_RECONCILE)
            phase.provider_entered = True
            phase.boundary = "RECONCILIATION_EVIDENCE"
            report = await adapter.reconcile(intent, context)
            report_received_at = self._now()
            self._crash(CoordinatorCrashPoint.AFTER_RECONCILE_CALL)
            report_ref = self._put_model(report)
            evidence_refs.update({report_ref, *report.evidence_refs})
            receipt_ref: str | None = None
            if report.receipt is not None:
                receipt_ref = self._put_model(report.receipt)
                evidence_refs.add(receipt_ref)
                self._validate_effect_receipt_identity(
                    action,
                    dispatch,
                    report.receipt,
                )
            reconciliation_observation_ref, _ = self._validate_adapter_observation(
                report.evidence_refs,
                evidence_kind="reconciliation",
                action=action,
                adapter_manifest_digest=work.adapter_manifest_digest,
                subject_ref=intent_ref,
                operation_permit_ref=work.permit_ref,
                authority_permit_ref=work.permit_ref,
                subject_authority_ref=work.permit.target_evidence_ref,
                operation_status=report.status.value,
                permit_issued_at=work.permit.issued_at,
                permit_deadline=work.permit.deadline,
                received_at=report_received_at,
                dispatch=dispatch,
                allow_late=True,
            )
            terminal_operation_evidence_ref = reconciliation_observation_ref
            if report_received_at >= context.deadline:
                self._store.record_late_recovery_outcome(
                    tenant_id=work.tenant_id,
                    transaction_id=work.transaction_id,
                    recovery_id=work.recovery_id,
                    expected_work_version=work.version,
                    evidence_refs=tuple(sorted(evidence_refs)),
                    operation_evidence_ref=reconciliation_observation_ref,
                    operation_reason_code=None,
                    reported_at=report_received_at,
                    reason_code="RECONCILIATION_RESULT_AFTER_PERMIT_DEADLINE",
                )
                return
            outcome = {
                ReconcileStatus.COMMITTED: ReconciliationOutcome.COMMITTED,
                ReconcileStatus.NO_EFFECT: ReconciliationOutcome.NO_EFFECT,
                ReconcileStatus.PARTIAL_OR_INVALID: ReconciliationOutcome.PARTIAL_OR_INVALID,
                ReconcileStatus.UNKNOWN: ReconciliationOutcome.UNKNOWN,
            }[report.status]
            verification_permit: VerificationPermit | None = None
            verification_permit_ref: str | None = None
            verification_ref: str | None = None
            verification_received_at: datetime | None = None
            reason_code: str | None = None
            if outcome is ReconciliationOutcome.COMMITTED:
                if (
                    report.receipt is None
                    or receipt_ref is None
                    or work.permit is None
                    or work.permit_ref is None
                ):
                    outcome = ReconciliationOutcome.PARTIAL_OR_INVALID
                    reason_code = "RECONCILIATION_COMMITTED_RECEIPT_MISSING"
                else:
                    self._check_deadline(
                        context.deadline,
                        self._now(),
                        boundary="reconciliation verification permit issuance",
                    )
                    verification_permit = VerificationPermit.create(
                        tenant_id=work.tenant_id,
                        transaction_id=work.transaction_id,
                        intent_hash=work.intent_hash,
                        normalized_action_digest=action_ref,
                        adapter_manifest_digest=work.adapter_manifest_digest,
                        authorization_round_id=work.authorization_round_id,
                        authorization_round_digest=work.authorization_round_digest,
                        lease_id=work.permit.lease_id,
                        worker_id=work.permit.worker_id,
                        fencing_token=work.permit.fencing_token,
                        phase=VerificationPhase.COMMITTED,
                        subject_ref=receipt_ref,
                        authority_permit_digest=work.permit.permit_digest,
                        authority_permit_ref=work.permit_ref,
                        subject_permit_digest=dispatch.permit.permit_digest,
                        subject_permit_ref=dispatch.permit_ref,
                        issued_at=self._now(),
                        deadline=context.deadline,
                    )
                    verification_permit_ref = self._put_model(verification_permit)
                    verification = await adapter.verify_committed(
                        report.receipt,
                        VerifyContext(
                            deadline=context.deadline,
                            worker_id=context.worker_id,
                            phase=VerificationPhase.COMMITTED,
                            permit=verification_permit,
                            permit_ref=verification_permit_ref,
                            normalized_action=action,
                            normalized_action_ref=action_ref,
                            subject_ref=receipt_ref,
                        ),
                    )
                    verification_received_at = self._now()
                    verification_ref = self._put_model(verification)
                    verification_observation_ref, _ = self._validate_adapter_observation(
                        verification.evidence_refs,
                        evidence_kind="committed_verification",
                        action=action,
                        adapter_manifest_digest=work.adapter_manifest_digest,
                        subject_ref=receipt_ref,
                        operation_permit_ref=verification_permit_ref,
                        authority_permit_ref=verification_permit.authority_permit_ref,
                        subject_authority_ref=verification_permit.subject_permit_ref,
                        operation_status=verification.status.value,
                        permit_issued_at=verification_permit.issued_at,
                        permit_deadline=verification_permit.deadline,
                        received_at=verification_received_at,
                        dispatch=dispatch,
                        expected_observed_state_digest=(
                            report.receipt.target_version_after
                            if verification.status is VerificationStatus.PASS
                            else None
                        ),
                        allow_late=True,
                    )
                    terminal_operation_evidence_ref = verification_observation_ref
                    evidence_refs.update(
                        {
                            verification_permit_ref,
                            verification_ref,
                            verification_observation_ref,
                        }
                    )
                    if verification.status is VerificationStatus.FAIL:
                        outcome = ReconciliationOutcome.PARTIAL_OR_INVALID
                        reason_code = ErrorCode.VERIFICATION_FAILED.value
                    elif verification.status in {
                        VerificationStatus.UNKNOWN,
                        VerificationStatus.ERROR,
                    }:
                        outcome = ReconciliationOutcome.UNKNOWN
                        reason_code = ErrorCode.VERIFICATION_UNKNOWN.value
            elif outcome is ReconciliationOutcome.NO_EFFECT and report.receipt is not None:
                outcome = ReconciliationOutcome.PARTIAL_OR_INVALID
                reason_code = "RECONCILIATION_NO_EFFECT_WITH_RECEIPT"
            if reason_code is None and outcome not in {
                ReconciliationOutcome.COMMITTED,
                ReconciliationOutcome.NO_EFFECT,
            }:
                reason_code = (
                    "RECONCILIATION_UNKNOWN"
                    if outcome is ReconciliationOutcome.UNKNOWN
                    else "RECONCILIATION_PARTIAL_OR_INVALID"
                )
            committed_permit = (
                verification_permit if outcome is ReconciliationOutcome.COMMITTED else None
            )
            committed_permit_ref = (
                verification_permit_ref if outcome is ReconciliationOutcome.COMMITTED else None
            )
            committed_verification_ref = (
                verification_ref if outcome is ReconciliationOutcome.COMMITTED else None
            )
            completed_at = report_received_at
            if verification_received_at is not None:
                completed_at = verification_received_at
            if completed_at >= context.deadline:
                self._store.record_late_recovery_outcome(
                    tenant_id=work.tenant_id,
                    transaction_id=work.transaction_id,
                    recovery_id=work.recovery_id,
                    expected_work_version=work.version,
                    evidence_refs=tuple(sorted(evidence_refs)),
                    operation_evidence_ref=terminal_operation_evidence_ref,
                    operation_reason_code=None,
                    reported_at=completed_at,
                    reason_code="RECONCILIATION_RESULT_AFTER_PERMIT_DEADLINE",
                )
                return
            finished = self._store.finish_reconciliation(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
                recovery_id=work.recovery_id,
                expected_attempt_version=started.attempt.version,
                outcome=outcome,
                evidence_refs=tuple(sorted(evidence_refs)),
                operation_evidence_ref=terminal_operation_evidence_ref,
                operation_reason_code=None,
                completed_at=completed_at,
                effect_receipt_ref=receipt_ref,
                committed_verification_permit=committed_permit,
                committed_verification_permit_ref=committed_permit_ref,
                committed_verification_ref=committed_verification_ref,
                no_effect_evidence_ref=(
                    reconciliation_observation_ref
                    if outcome is ReconciliationOutcome.NO_EFFECT
                    else None
                ),
                next_attempt_not_before=(
                    completed_at + self._config.reconciliation_backoff
                    if outcome is ReconciliationOutcome.UNKNOWN
                    else None
                ),
                reason_code=reason_code,
            )
            self._crash(CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED)
            if outcome is ReconciliationOutcome.PARTIAL_OR_INVALID:
                await self._recover_failed(finished.transaction)
            elif outcome is ReconciliationOutcome.NO_EFFECT:
                await self._recover_aborting(finished.transaction)
        except (Exception, CancelledError) as error:
            attempt = self._store.get_reconciliation_attempt(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
                recovery_id=work.recovery_id,
                attempt=work.attempt,
            )
            if attempt.outcome is None:
                reason = (
                    error.code.value
                    if isinstance(error, AgentKernelError)
                    else "RECONCILIATION_CANCELLED_AFTER_PROVIDER_ENTRY"
                    if isinstance(error, CancelledError)
                    else "RECONCILIATION_QUERY_FAILED"
                )
                completed_at = self._now()
                phase.boundary = "RECONCILIATION_EVIDENCE"
                evidence_ref = self._put_control_evidence(
                    transaction_id=work.transaction_id,
                    event="reconciliation.query_failed",
                    reason_code=reason,
                    recorded_at=completed_at,
                    subject_ref=work.permit_ref,
                )
                failure_refs = tuple(sorted({*evidence_refs, evidence_ref}))
                if completed_at >= context.deadline:
                    self._store.record_late_recovery_outcome(
                        tenant_id=work.tenant_id,
                        transaction_id=work.transaction_id,
                        recovery_id=work.recovery_id,
                        expected_work_version=work.version,
                        evidence_refs=failure_refs,
                        operation_evidence_ref=evidence_ref,
                        operation_reason_code=reason,
                        reported_at=completed_at,
                        reason_code="RECONCILIATION_RESULT_AFTER_PERMIT_DEADLINE",
                    )
                else:
                    self._store.finish_reconciliation(
                        tenant_id=work.tenant_id,
                        transaction_id=work.transaction_id,
                        recovery_id=work.recovery_id,
                        expected_attempt_version=attempt.version,
                        outcome=ReconciliationOutcome.UNKNOWN,
                        evidence_refs=failure_refs,
                        operation_evidence_ref=evidence_ref,
                        operation_reason_code=reason,
                        completed_at=completed_at,
                        next_attempt_not_before=(
                            completed_at + self._config.reconciliation_backoff
                        ),
                        reason_code=reason,
                    )
            raise

    async def _recover_candidate(
        self,
        record: EnforcedTransactionRecord,
        *,
        observed_at: datetime,
        resume_typed_dispatch: bool = False,
    ) -> bool:
        if record.state.is_terminal:
            return False
        all_work = self._store.list_recovery_work(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        resumable_prework_handoff = self._store.get_resumable_open_prework_handoff(
            tenant_id=record.tenant_id,
            target_transaction_id=record.transaction_id,
            observed_at=observed_at,
        )
        if (
            resumable_prework_handoff is None
            and self._store.get_live_open_prework_handoff(
                tenant_id=record.tenant_id,
                target_transaction_id=record.transaction_id,
                observed_at=observed_at,
            )
            is not None
        ):
            return False
        if record.state is TransactionState.IN_DOUBT:
            dispatch = self._store.get_commit_dispatch(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
            if (
                dispatch.unavailable_record_digest is not None
                and not resume_typed_dispatch
                and resumable_prework_handoff is None
                and not any(
                    work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                    and work.state
                    in {
                        RecoveryWorkState.PENDING,
                        RecoveryWorkState.RUNNING,
                        RecoveryWorkState.RETRY_SCHEDULED,
                    }
                    for work in all_work
                )
            ):
                # The typed SQL classification is the durable terminal scanner result.
                # A later operator-driven reconciliation may create an authorized lineage;
                # until then the scanner must not mint or resend work by itself.
                return False
        if any(
            work.state is RecoveryWorkState.REVIEW_REQUIRED
            and self._store.get_recovery_evidence_unavailable(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
                recovery_id=work.recovery_id,
            )
            is not None
            for work in all_work
        ):
            return False
        if not all_work:
            handoffs = self._store.list_recovery_action_handoffs(
                tenant_id=record.tenant_id,
                target_transaction_id=record.transaction_id,
            )
            if handoffs and all(
                handoff.closed_at is not None
                or (
                    handoff.action is not None
                    and self._store.get_intent_attempt(
                        tenant_id=handoff.action.tenant_id,
                        intent_hash=handoff.action.intent_hash,
                        transaction_id=handoff.action.transaction_id,
                    ).state
                    is not IntentAttemptState.ACTIVE
                )
                for handoff in handoffs
            ):
                return False
        active = self._store.get_active_recovery_work(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        executable = tuple(
            work
            for work in active
            if work.state in {RecoveryWorkState.PENDING, RecoveryWorkState.RUNNING}
        )
        if len(executable) > 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery scanner found multiple executable work generations",
            )
        if executable:
            await self._run_recovery_work(executable[0])
            return True
        scheduled = tuple(
            sorted(
                (work for work in active if work.state is RecoveryWorkState.RETRY_SCHEDULED),
                key=lambda work: work.recovery_ordinal,
            )
        )
        if scheduled:
            predecessor = scheduled[-1]
            if (
                any(work.root_recovery_id != predecessor.root_recovery_id for work in scheduled)
                or predecessor.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Scheduled reconciliation lineage is inconsistent",
                )
            lineage = tuple(
                work
                for work in self._store.list_recovery_work(
                    tenant_id=record.tenant_id,
                    transaction_id=record.transaction_id,
                )
                if work.root_recovery_id == predecessor.root_recovery_id
            )
            latest = max(lineage, key=lambda work: work.recovery_ordinal)
            if latest.recovery_ordinal > predecessor.recovery_ordinal:
                # A denied, unknown-authority, or review-required successor is the durable
                # lineage head. Older scheduled generations cannot mint another successor.
                return False
            attempt = self._store.get_reconciliation_attempt(
                tenant_id=predecessor.tenant_id,
                transaction_id=predecessor.transaction_id,
                recovery_id=predecessor.recovery_id,
                attempt=predecessor.attempt,
            )
            if attempt.next_attempt_not_before is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Scheduled reconciliation lacks its durable retry instant",
                )
            if observed_at >= predecessor.deadline:
                self._terminalize_expired_recovery(
                    predecessor,
                    reported_at=observed_at,
                )
                return True
            if observed_at < attempt.next_attempt_not_before:
                return False
            dispatch = self._store.get_commit_dispatch(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
            authorization_observed_at = self._now()
            if authorization_observed_at >= predecessor.deadline:
                self._terminalize_expired_recovery(
                    predecessor,
                    reported_at=authorization_observed_at,
                )
                return True
            try:
                successor = await self._authorize_recovery_work(
                    record,
                    kind=RecoveryWorkKind.RECONCILE_DISPATCH,
                    target=dispatch,
                    predecessor=predecessor,
                )
            except _RecoveryHandoffContended:
                return False
            if successor is not None and successor.state is RecoveryWorkState.PENDING:
                await self._run_recovery_work(successor)
            return True
        resume_after_terminal_reconciliation = self._terminal_reconciliation_follow_on_required(
            record, all_work
        )
        if (
            all_work
            and not resume_after_terminal_reconciliation
            and resumable_prework_handoff is None
        ):
            # Only a completed reconciliation classification may hand off to a new
            # recovery kind.  Terminal rollback, compensation, and discard generations
            # remain quiescent and cannot be revived by a scanner restart.
            return False
        if record.state in _PRE_DISPATCH_STATES:
            if record.state is not TransactionState.ABORTING:
                evidence_ref = self._put_control_evidence(
                    transaction_id=record.transaction_id,
                    event=TransitionEvent.CONTEXT_EXITED.value,
                    reason_code="RECOVERY_SCANNER_CONTEXT_EXIT",
                    recorded_at=self._now(),
                )
                transitioned = self._store.apply_control_transition(
                    tenant_id=record.tenant_id,
                    transaction_id=record.transaction_id,
                    expected_version=record.version,
                    transition_event=TransitionEvent.CONTEXT_EXITED,
                    recorded_at=self._now(),
                    evidence_refs=(evidence_ref,),
                    reason_code="RECOVERY_SCANNER_CONTEXT_EXIT",
                    recovery_timeout=self._config.recovery_deadline,
                )
                record = transitioned.transaction
            try:
                await self._settle_abort_handoff(
                    record,
                    report_contention=True,
                )
            except _RecoveryHandoffContended:
                return False
            return True
        if record.state is TransactionState.COMMITTING:
            dispatch = self._store.get_commit_dispatch(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
            classified_at = self._now()
            record = self._terminalize_dispatch_evidence_unavailable(
                record,
                dispatch,
                boundary="RECOVERY_SCANNER_CLASSIFICATION",
                reported_at=classified_at,
                cause="PROCESS_RESTART_AFTER_DISPATCH",
            )
            return True
        if record.state is TransactionState.IN_DOUBT:
            existing_reconciliation = tuple(
                work
                for work in self._store.list_recovery_work(
                    tenant_id=record.tenant_id,
                    transaction_id=record.transaction_id,
                )
                if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
            )
            if existing_reconciliation:
                # A lineage without executable/scheduled work has reached a denied, failed,
                # deadline, or attempt-limit review head. Never mint a new ordinal-one root.
                return False
            dispatch = self._store.get_commit_dispatch(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
            try:
                work = await self._authorize_recovery_work(
                    record,
                    kind=RecoveryWorkKind.RECONCILE_DISPATCH,
                    target=dispatch,
                )
            except _RecoveryHandoffContended:
                return False
            if work is not None and work.state is RecoveryWorkState.PENDING:
                await self._run_recovery_work(work)
            return True
        if record.state is TransactionState.FAILED:
            try:
                await self._recover_failed(record, report_contention=True)
            except _RecoveryHandoffContended:
                return False
            return True
        return False

    async def resume_dispatch_reconciliation(
        self,
        tenant_id: str,
        transaction_id: str,
    ) -> EnforcedTransactionStatus:
        """Explicitly resume a dispatch stopped by typed unavailable-evidence review."""

        lock = self._dispatch_resume_lock_for(tenant_id, transaction_id)
        async with lock:
            record = self._store.get_enforced_transaction(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
            )
            if record.state is not TransactionState.IN_DOUBT:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Typed dispatch reconciliation can resume only from IN_DOUBT",
                )
            dispatch = self._store.get_commit_dispatch(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
            )
            if dispatch.unavailable_record_digest is None:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Dispatch has no typed unavailable-evidence stop to resume",
                )
            await self._recover_candidate(
                record,
                observed_at=self._now(),
                resume_typed_dispatch=True,
            )
            return self.status(tenant_id, transaction_id)

    def _recovery_terminal_failure(
        self,
        projection: EnforcedTransactionProjection,
    ) -> RecoveryCandidateFailure | None:
        def retrievable_evidence_ref(value: str | None) -> str | None:
            if value is not None:
                self._get_artifact(value)
            return value

        self._validate_completed_recovery_operation_evidence(projection)
        if projection.recovery_evidence_unavailable:
            unavailable_record = max(
                projection.recovery_evidence_unavailable,
                key=lambda item: (item.reported_at, item.recovery_id),
            )
            return RecoveryCandidateFailure(
                transaction_id=projection.record.transaction_id,
                reason_code=unavailable_record.reason_code,
                evidence_ref=None,
                kind=RecoveryFailureKind.RECOVERY_TERMINAL,
            )
        terminal_work = tuple(
            item
            for item in projection.recovery_work
            if item.state in {RecoveryWorkState.FAILED, RecoveryWorkState.REVIEW_REQUIRED}
            and item.reason_code is not None
        )
        if terminal_work:
            completion_by_recovery = {
                report.recovery_id: report for report in projection.recovery_completion_reports
            }
            late_by_recovery = {
                report.recovery_id: report for report in projection.late_recovery_reports
            }
            attempts_by_generation = {
                (attempt.recovery_id, attempt.attempt): attempt
                for attempt in projection.reconciliation_attempts
            }
            work = max(
                terminal_work,
                key=lambda item: (item.updated_at, item.recovery_ordinal, item.recovery_id),
            )
            completion = completion_by_recovery.get(work.recovery_id)
            late = None if completion is not None else late_by_recovery.get(work.recovery_id)
            attempt = (
                attempts_by_generation.get((work.recovery_id, work.attempt))
                if completion is None
                and late is None
                and work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                and work.attempt > 0
                else None
            )
            handoff = next(
                (
                    item
                    for item in projection.recovery_handoffs
                    if item.binding.recovery_id == work.recovery_id
                ),
                None,
            )
            if completion is not None:
                self._validate_recovery_completion_operation_evidence(
                    work,
                    completion,
                )
            if attempt is not None:
                self._validate_reconciliation_attempt_operation_evidence(
                    work,
                    attempt,
                )
            scheduled_deadline_handoff = (
                work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                and work.state is RecoveryWorkState.REVIEW_REQUIRED
                and work.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
                and attempt is not None
                and attempt.outcome is ReconciliationOutcome.UNKNOWN
                and attempt.next_attempt_not_before is not None
                and attempt.next_attempt_not_before < work.deadline
                and handoff is not None
                and handoff.closed_at is not None
                and handoff.closed_at >= work.deadline
            )
            if scheduled_deadline_handoff and handoff is not None:
                evidence_ref = (
                    handoff.failure_evidence_ref
                    if handoff.failure_evidence_status
                    is RecoveryHandoffFailureEvidenceStatus.AVAILABLE
                    else None
                )
                failure_reason_code = handoff.failure_reason_code or work.reason_code
            else:
                evidence_ref = (
                    completion.operation_evidence_ref
                    if completion is not None
                    else late.operation_evidence_ref
                    if late is not None
                    else attempt.operation_evidence_ref
                    if attempt is not None
                    else handoff.failure_evidence_ref
                    if handoff is not None
                    and handoff.failure_evidence_status
                    is RecoveryHandoffFailureEvidenceStatus.AVAILABLE
                    else None
                )
                failure_reason_code = work.reason_code
            return RecoveryCandidateFailure(
                transaction_id=projection.record.transaction_id,
                reason_code=failure_reason_code or "RECOVERY_TERMINAL",
                evidence_ref=retrievable_evidence_ref(evidence_ref),
                kind=RecoveryFailureKind.RECOVERY_TERMINAL,
            )
        closed_prework = tuple(
            handoff
            for handoff in projection.recovery_handoffs
            if handoff.closed_at is not None
            and handoff.failure_reason_code is not None
            and not any(
                work.recovery_id == handoff.binding.recovery_id for work in projection.recovery_work
            )
        )
        if closed_prework:
            handoff = max(
                closed_prework,
                key=lambda item: (
                    item.closed_at or item.created_at,
                    item.terminal_sequence or 0,
                    item.binding.recovery_id,
                ),
            )
            evidence_ref = (
                handoff.failure_evidence_ref
                if handoff.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.AVAILABLE
                else None
            )
            return RecoveryCandidateFailure(
                transaction_id=projection.record.transaction_id,
                reason_code=handoff.failure_reason_code or "RECOVERY_TERMINAL",
                evidence_ref=retrievable_evidence_ref(evidence_ref),
                kind=RecoveryFailureKind.RECOVERY_TERMINAL,
            )
        dispatch_unavailable_record = projection.dispatch_evidence_unavailable
        reconciliation_lineage_exists = any(
            work.kind is RecoveryWorkKind.RECONCILE_DISPATCH for work in projection.recovery_work
        ) or any(
            handoff.binding.recovery_kind is RecoveryWorkKind.RECONCILE_DISPATCH
            for handoff in projection.recovery_handoffs
        )
        if dispatch_unavailable_record is not None and not reconciliation_lineage_exists:
            return RecoveryCandidateFailure(
                transaction_id=projection.record.transaction_id,
                reason_code=dispatch_unavailable_record.reason_code,
                evidence_ref=None,
                kind=RecoveryFailureKind.RECOVERY_TERMINAL,
            )
        return None

    def _validate_completed_recovery_operation_evidence(
        self,
        projection: EnforcedTransactionProjection,
    ) -> None:
        """Re-prove every completed provider operation represented by a status view."""

        completion_by_recovery = {
            report.recovery_id: report for report in projection.recovery_completion_reports
        }
        late_by_recovery = {
            report.recovery_id: report for report in projection.late_recovery_reports
        }
        attempts_by_generation = {
            (attempt.recovery_id, attempt.attempt): attempt
            for attempt in projection.reconciliation_attempts
        }
        unavailable_ids = {
            record.recovery_id for record in projection.recovery_evidence_unavailable
        }
        handoff_by_recovery = {
            handoff.binding.recovery_id: handoff for handoff in projection.recovery_handoffs
        }
        work_by_recovery = {work.recovery_id: work for work in projection.recovery_work}
        for work in projection.recovery_work:
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                self._validate_reconciliation_work_generation_evidence(
                    projection,
                    work,
                )
            completion = completion_by_recovery.get(work.recovery_id)
            late = late_by_recovery.get(work.recovery_id)
            if completion is not None:
                self._validate_recovery_completion_operation_evidence(work, completion)
            if late is not None:
                handoff = handoff_by_recovery.get(work.recovery_id)
                if handoff is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Late recovery report lost its action handoff",
                    )
                self._validate_late_recovery_handoff_evidence(
                    handoff,
                    evidence_ref=late.operation_evidence_ref,
                    late_report=late,
                )
            if work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH or work.attempt < 1:
                continue
            attempt = attempts_by_generation.get((work.recovery_id, work.attempt))
            if (
                attempt is not None
                and attempt.completed_at is not None
                and late is None
                and work.recovery_id not in unavailable_ids
            ):
                self._validate_reconciliation_attempt_operation_evidence(work, attempt)
        for attempt in projection.reconciliation_attempts:
            historical_work = work_by_recovery.get(attempt.recovery_id)
            if (
                historical_work is None
                or attempt.completed_at is None
                or attempt.attempt >= historical_work.attempt
            ):
                continue
            historical_permit, historical_permit_ref = self._historical_reconciliation_permit(
                historical_work, attempt
            )
            self._validate_reconciliation_attempt_operation_evidence(
                historical_work,
                attempt,
                historical_permit=historical_permit,
                historical_permit_ref=historical_permit_ref,
            )

    async def recover_once(
        self,
        tenant_id: str,
        limit: int = 100,
        *,
        force_handoff_evidence_audit: bool = False,
    ) -> RecoveryRunResult:
        """Process bounded work while keyset-scanning past non-actionable candidates."""

        if type(limit) is not int or not 1 <= limit <= 1_000:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery work limit must be an integer from 1 through 1000",
            )
        if type(force_handoff_evidence_audit) is not bool:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery handoff evidence audit force flag must be a boolean",
            )
        observed_at = self._now()
        audit_failures, audit_checkpoint = self._audit_tenant_recovery_handoff_evidence(
            tenant_id,
            observed_at=observed_at,
            force=force_handoff_evidence_audit,
        )
        failures: list[RecoveryCandidateFailure] = list(audit_failures)
        scan_budget = min(
            _MAX_RECOVERY_SCAN_PER_RUN,
            max(_MIN_RECOVERY_SCAN_PER_RUN, limit * 32),
        )
        processed = 0
        work_attempts = 0
        raw_scanned = 0
        records_by_id: dict[str, EnforcedTransactionRecord] = {}
        typed_status_errors: dict[str, AgentKernelError] = {}
        cursor = self._recovery_scan_cursors.get(tenant_id)
        wrapped = False
        while raw_scanned < scan_budget and work_attempts < limit:
            page_limit = min(
                1_000,
                limit - work_attempts,
                scan_budget - raw_scanned,
            )
            page = self._store.scan_recovery_candidates(
                tenant_id=tenant_id,
                observed_at=observed_at,
                limit=page_limit,
                cursor=cursor,
            )
            if not page.records:
                if cursor is not None and not wrapped:
                    cursor = None
                    wrapped = True
                    continue
                self._recovery_scan_cursors.pop(tenant_id, None)
                break

            for initial in page.records:
                raw_scanned += 1
                if initial.transaction_id in records_by_id:
                    continue
                records_by_id[initial.transaction_id] = initial
                try:
                    record = self._store.get_enforced_transaction(
                        tenant_id=tenant_id,
                        transaction_id=initial.transaction_id,
                    )
                    if await self._recover_candidate(record, observed_at=observed_at):
                        processed += 1
                        work_attempts += 1
                        projection = self._store.get_transaction_projection(
                            tenant_id=tenant_id,
                            transaction_id=initial.transaction_id,
                        )
                        terminal_failure = self._recovery_terminal_failure(projection)
                        if terminal_failure is not None:
                            failures.append(terminal_failure)
                            typed_error = self._typed_unavailable_error_for_failure(
                                projection,
                                terminal_failure,
                            )
                            if typed_error is not None:
                                typed_status_errors[initial.transaction_id] = typed_error
                except Exception as error:
                    work_attempts += 1
                    if (
                        isinstance(error, AgentKernelError)
                        and error.code is ErrorCode.INTEGRITY_ERROR
                    ):
                        raise
                    projection = self._store.get_transaction_projection(
                        tenant_id=tenant_id,
                        transaction_id=initial.transaction_id,
                    )
                    terminal_failure = self._recovery_terminal_failure(projection)
                    if terminal_failure is not None:
                        processed += 1
                        failures.append(terminal_failure)
                        typed_error = self._typed_unavailable_error_for_failure(
                            projection,
                            terminal_failure,
                        )
                        if typed_error is not None:
                            typed_status_errors[initial.transaction_id] = typed_error
                        continue
                    candidate_reason = (
                        error.code.value
                        if isinstance(error, AgentKernelError)
                        else "RECOVERY_CANDIDATE_FAILED"
                    )
                    evidence_ref, reason, _evidence_status = self._put_failure_evidence_or_fallback(
                        transaction_id=initial.transaction_id,
                        event="recovery.candidate_failed",
                        reason_code=candidate_reason,
                        recorded_at=self._now(),
                        subject_ref=initial.normalized_action_digest,
                    )
                    failures.append(
                        RecoveryCandidateFailure(
                            transaction_id=initial.transaction_id,
                            reason_code=reason,
                            evidence_ref=evidence_ref,
                        )
                    )

            next_cursor = page.next_cursor
            if next_cursor is not None:
                if cursor is not None and (
                    next_cursor.updated_at,
                    next_cursor.transaction_id,
                ) <= (cursor.updated_at, cursor.transaction_id):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery scan cursor did not advance",
                    )
                cursor = next_cursor
                if work_attempts >= limit or raw_scanned >= scan_budget:
                    self._recovery_scan_cursors[tenant_id] = cursor
                    break
                continue

            self._recovery_scan_cursors.pop(tenant_id, None)
            if cursor is not None and not wrapped and work_attempts < limit:
                cursor = None
                wrapped = True
                continue
            break

        transaction_ids = tuple(records_by_id)
        statuses = tuple(
            self._recovery_result_status(
                tenant_id,
                transaction_id,
                unavailable_error=typed_status_errors.get(transaction_id),
            )
            for transaction_id in transaction_ids
        )
        remaining = self._store.count_recovery_candidates(
            tenant_id=tenant_id,
            observed_at=self._now(),
        )
        return RecoveryRunResult(
            tenant_id=tenant_id,
            observed_at=observed_at,
            scanned=len(transaction_ids),
            processed=processed,
            remaining=remaining,
            statuses=statuses,
            failures=tuple(failures),
            handoff_evidence_audit_cycle=audit_checkpoint.current_cycle,
            handoff_evidence_audit_high_watermark=(audit_checkpoint.current_cycle_high_watermark),
            handoff_evidence_audit_cycle_complete=(audit_checkpoint.current_cycle_complete),
            handoff_evidence_audit_ready=audit_checkpoint.current_cycle_ready,
            handoff_evidence_audit_failure_count=(audit_checkpoint.current_cycle_failure_count),
            handoff_evidence_last_completed_cycle=(audit_checkpoint.last_completed_cycle),
            handoff_evidence_last_completed_at=audit_checkpoint.last_completed_at,
            handoff_evidence_last_completed_high_watermark=(
                audit_checkpoint.last_completed_high_watermark
            ),
            handoff_evidence_last_completed_failure_count=(
                audit_checkpoint.last_completed_failure_count
            ),
        )


class EnforcedTransactionSession:
    """One explicit-commit async scope; normal exit without commit aborts private state."""

    def __init__(
        self,
        *,
        coordinator: EnforcedTransactionCoordinator,
        request: EnforcedTransactionRequest,
        trusted_context: AuthenticatedActionContext,
        admitted: AdmittedAdapterOperation,
        admitted_manifest: AdapterManifest,
        action: NormalizedAction,
        proposal_ref: str,
        action_ref: str,
        staging_authorization: _AuthorizationEvidence,
        initial_record: EnforcedTransactionRecord,
    ) -> None:
        self._coordinator = coordinator
        self._request = request
        self._trusted_context = trusted_context
        self._admitted = admitted
        self._admitted_manifest = admitted_manifest
        self._adapter: EffectAdapter = admitted.adapter
        self._action = action
        self._proposal_ref = proposal_ref
        self._action_ref = action_ref
        self._staging_authorization = staging_authorization
        self._record = initial_record
        self._lease_id: str | None = None
        self._lease_fencing_token: int | None = None
        self._lease_deadline: datetime | None = None
        self._inspection_permit: InspectionPermit | None = None
        self._inspection_permit_ref: str | None = None
        self._plan: EffectPlan | None = None
        self._stage: StageMaterialRecord | None = None
        self._staged_effect: StagedEffect | None = None
        self._staged_receipt: StagedReceipt | None = None
        self._effect_receipt: EffectReceipt | None = None
        self._staged_verification: VerificationReport | None = None
        self._staged_verification_permit: VerificationPermit | None = None
        self._staged_verification_permit_ref: str | None = None
        self._committed_verification: VerificationReport | None = None
        self._entered = False
        self._explicit_commit = False
        self._operation_lock = Lock()

    @property
    def record(self) -> EnforcedTransactionRecord:
        return self._record

    @property
    def action(self) -> NormalizedAction:
        return self._action

    @property
    def receipts(self) -> EnforcedSessionReceipts:
        return EnforcedSessionReceipts(
            staged=self._staged_receipt,
            effect=self._effect_receipt,
            staged_verification=self._staged_verification,
            committed_verification=self._committed_verification,
        )

    @property
    def plan(self) -> EffectPlan | None:
        return self._plan

    def _now(self) -> datetime:
        return self._coordinator._now()

    def _crash(self, point: CoordinatorCrashPoint) -> None:
        self._coordinator._crash(point)

    def _check_deadline(self, boundary: str) -> None:
        deadline = self._lease_deadline or self._action.deadline
        self._coordinator._check_deadline(deadline, self._now(), boundary=boundary)

    def _require_lease(self) -> tuple[str, int]:
        if (
            self._lease_id is None
            or self._lease_fencing_token is None
            or self._lease_deadline is None
        ):
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Session lost its staging lease")
        return self._lease_id, self._lease_fencing_token

    def _require_lease_deadline(self) -> datetime:
        self._require_lease()
        deadline = self._lease_deadline
        if deadline is None:
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Session lost its lease deadline")
        return deadline

    def _release_staging_lease_for_recovery(self) -> None:
        """Relinquish this session's live staging fence before claiming recovery work."""

        if self._lease_id is None:
            return
        lease = self._coordinator._store.get_worker_lease(
            tenant_id=self._action.tenant_id,
            transaction_id=self._action.transaction_id,
            lease_id=self._lease_id,
        )
        if lease.released_at is not None:
            return
        if lease.worker_id != self._coordinator._config.worker_id:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_REVOKED,
                "The session cannot release a staging lease owned by another worker",
            )
        self._coordinator._store.release_worker_lease(
            tenant_id=self._action.tenant_id,
            transaction_id=self._action.transaction_id,
            lease_id=lease.lease_id,
            expected_version=lease.version,
            released_at=self._now(),
        )

    async def _recover_aborting(
        self,
        *,
        cancellation: CancelledError | None = None,
    ) -> EnforcedTransactionRecord:
        self._release_staging_lease_for_recovery()
        try:
            return await self._coordinator._settle_abort_handoff(
                self._record,
                cancellation=cancellation,
            )
        except CancelledError:
            self._record = self._coordinator._store.get_enforced_transaction(
                tenant_id=self._record.tenant_id,
                transaction_id=self._record.transaction_id,
            )
            raise

    async def __aenter__(self) -> Self:
        async with self._operation_lock:
            if self._entered:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "An enforced transaction session can only be entered once",
                )
            self._entered = True
            await self._stage_and_verify()
            return self

    def _validate_plan(self, plan: EffectPlan) -> None:
        operation = self._admitted.operation
        if (
            plan.proposal != self._request.proposal
            or plan.intent_hash != self._action.intent_hash
            or plan.risk_class != self._action.risk_floor
            or plan.effect_domains != self._action.effect_domains
            or plan.effect_domains != operation.effect_domains
            or plan.proposal.operation != self._admitted.operation_name
            or _RISK_ORDER[plan.risk_class.value] < _RISK_ORDER[operation.risk_floor.value]
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter effect plan differs from normalized or admitted semantics",
            )

    async def _stage_and_verify(self) -> None:
        try:
            self._check_deadline("staging lease acquisition")
            now = self._now()
            authority_valid_until = self._staging_authorization.authority_valid_until
            if authority_valid_until is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Eligible staging authorization lacks its capability validity bound",
                )
            expires = min(
                self._action.deadline,
                authority_valid_until,
                now + self._coordinator._config.lease_duration,
            )
            if expires <= now:
                raise AgentKernelError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "No positive staging lease remains before the transaction deadline",
                )
            lease_id = _stable_id(
                "lease.staging",
                {
                    "tenant_id": self._action.tenant_id,
                    "transaction_id": self._action.transaction_id,
                    "worker": self._coordinator._config.worker_id,
                },
            )
            acquired = self._coordinator._store.acquire_staging_lease(
                tenant_id=self._action.tenant_id,
                transaction_id=self._action.transaction_id,
                lease_id=lease_id,
                worker_id=self._coordinator._config.worker_id,
                acquired_at=now,
                expires_at=expires,
                expected_transaction_version=self._record.version,
            )
            self._record = acquired.transaction
            self._lease_id = acquired.lease.lease_id
            self._lease_fencing_token = acquired.lease.fencing_token
            self._lease_deadline = min(
                self._action.deadline,
                acquired.lease.expires_at,
                authority_valid_until,
            )
            permit_deadline = self._require_lease_deadline()
            self._crash(CoordinatorCrashPoint.AFTER_STAGING_LEASE_ACQUIRED)
            inspection = InspectionPermit.create(
                tenant_id=self._action.tenant_id,
                transaction_id=self._action.transaction_id,
                intent_hash=self._action.intent_hash,
                normalized_action_digest=self._action_ref,
                proposal_ref=self._proposal_ref,
                adapter_manifest_digest=self._admitted.manifest_digest,
                authorization_round_id=self._staging_authorization.round.round_id,
                authorization_round_digest=self._staging_authorization.round.round_digest,
                lease_id=acquired.lease.lease_id,
                worker_id=acquired.lease.worker_id,
                fencing_token=acquired.lease.fencing_token,
                issued_at=now,
                deadline=permit_deadline,
            )
            inspection_ref = self._coordinator._put_model(inspection)
            self._inspection_permit = inspection
            self._inspection_permit_ref = inspection_ref
            read_context = ReadOnlyContext(
                deadline=permit_deadline,
                worker_id=acquired.lease.worker_id,
                permit=inspection,
                permit_ref=inspection_ref,
                normalized_action=self._action,
                normalized_action_ref=self._action_ref,
                proposal=self._request.proposal,
                proposal_ref=self._proposal_ref,
            )
            self._crash(CoordinatorCrashPoint.BEFORE_INSPECT)
            plan = await self._adapter.inspect(self._request.proposal, read_context)
            self._crash(CoordinatorCrashPoint.AFTER_INSPECT_CALL)
            self._check_deadline("stage allocation")
            plan_ref = self._coordinator._put_model(plan)
            self._validate_plan(plan)
            self._plan = plan
            self._crash(CoordinatorCrashPoint.AFTER_PLAN_ARTIFACT)
            stage_id = _stable_id(
                "stage",
                {
                    "tenant_id": self._action.tenant_id,
                    "transaction_id": self._action.transaction_id,
                    "plan_ref": plan_ref,
                },
            )
            stage_permit = StagePermit.create(
                tenant_id=self._action.tenant_id,
                transaction_id=self._action.transaction_id,
                intent_hash=self._action.intent_hash,
                normalized_action_digest=self._action_ref,
                adapter_manifest_digest=self._admitted.manifest_digest,
                authorization_round_id=self._staging_authorization.round.round_id,
                authorization_round_digest=self._staging_authorization.round.round_digest,
                inspection_permit_digest=inspection.permit_digest,
                inspection_permit_ref=inspection_ref,
                plan_digest=canonical_digest(plan),
                plan_ref=plan_ref,
                stage_id=stage_id,
                lease_id=acquired.lease.lease_id,
                worker_id=acquired.lease.worker_id,
                fencing_token=acquired.lease.fencing_token,
                target_version_guard=plan.base_version,
                issued_at=self._now(),
                deadline=permit_deadline,
            )
            stage_permit_ref = self._coordinator._put_model(stage_permit)
            material = StageMaterialRecord(
                tenant_id=self._action.tenant_id,
                transaction_id=self._action.transaction_id,
                stage_id=stage_id,
                lease_id=acquired.lease.lease_id,
                fencing_token=acquired.lease.fencing_token,
                intent_hash=self._action.intent_hash,
                normalized_action_digest=self._action_ref,
                adapter_manifest_digest=self._admitted.manifest_digest,
                plan_digest=canonical_digest(plan),
                plan_ref=plan_ref,
                inspection_permit_digest=inspection.permit_digest,
                inspection_permit_ref=inspection_ref,
                stage_permit_digest=stage_permit.permit_digest,
                stage_permit_ref=stage_permit_ref,
                state=StageMaterialState.ALLOCATED,
                target_version_guard=plan.base_version,
                version=0,
                created_at=self._now(),
                updated_at=self._now(),
            )
            allocated = self._coordinator._store.allocate_stage_material(
                material,
                inspection_permit=inspection,
                stage_permit=stage_permit,
            )
            self._stage = allocated.material
            self._crash(CoordinatorCrashPoint.AFTER_STAGE_ALLOCATED)
            stage_context = StageContext(
                deadline=permit_deadline,
                worker_id=acquired.lease.worker_id,
                permit=stage_permit,
                permit_ref=stage_permit_ref,
                normalized_action=self._action,
                normalized_action_ref=self._action_ref,
            )
            self._check_deadline("adapter stage")
            self._crash(CoordinatorCrashPoint.BEFORE_STAGE)
            staged_effect = await self._adapter.stage(plan, stage_context)
            self._crash(CoordinatorCrashPoint.AFTER_STAGE_CALL)
            staged_effect_ref = self._coordinator._put_model(staged_effect)
            if (
                staged_effect.stage_id != stage_id
                or staged_effect.plan != plan
                or canonical_digest(staged_effect.plan) != material.plan_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Adapter staged effect differs from its allocated generation",
                )
            self._staged_effect = staged_effect
            staged_material = self._coordinator._store.record_staged_material(
                tenant_id=self._action.tenant_id,
                transaction_id=self._action.transaction_id,
                expected_material_version=allocated.material.version,
                base_state_digest=staged_effect.base_state_digest,
                staged_effect_ref=staged_effect_ref,
                recorded_at=self._now(),
            )
            self._stage = staged_material.material
            self._crash(CoordinatorCrashPoint.AFTER_STAGED_EFFECT_RECORDED)
            self._check_deadline("isolated stage execution")
            self._crash(CoordinatorCrashPoint.BEFORE_EXECUTE)
            staged_receipt = await self._adapter.execute(staged_effect, stage_context)
            self._crash(CoordinatorCrashPoint.AFTER_EXECUTE_CALL)
            staged_receipt_ref = self._coordinator._put_model(staged_receipt)
            if staged_receipt.staged != staged_effect:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Adapter staged receipt differs from its staged effect",
                )
            self._staged_receipt = staged_receipt
            executed = self._coordinator._store.record_stage_execution(
                tenant_id=self._action.tenant_id,
                transaction_id=self._action.transaction_id,
                expected_material_version=staged_material.material.version,
                expected_transaction_version=self._record.version,
                staged_receipt_ref=staged_receipt_ref,
                staged_state_digest=staged_receipt.staged_state_digest,
                recorded_at=self._now(),
            )
            self._stage = executed.material
            self._record = executed.transaction
            self._crash(CoordinatorCrashPoint.AFTER_EXECUTION_RECORDED)
            self._check_deadline("staged verification permit issuance")
            verification_permit = VerificationPermit.create(
                tenant_id=self._action.tenant_id,
                transaction_id=self._action.transaction_id,
                intent_hash=self._action.intent_hash,
                normalized_action_digest=self._action_ref,
                adapter_manifest_digest=self._admitted.manifest_digest,
                authorization_round_id=self._staging_authorization.round.round_id,
                authorization_round_digest=self._staging_authorization.round.round_digest,
                lease_id=acquired.lease.lease_id,
                worker_id=acquired.lease.worker_id,
                fencing_token=acquired.lease.fencing_token,
                phase=VerificationPhase.STAGED,
                subject_ref=staged_receipt_ref,
                authority_permit_digest=stage_permit.permit_digest,
                authority_permit_ref=stage_permit_ref,
                subject_permit_digest=stage_permit.permit_digest,
                subject_permit_ref=stage_permit_ref,
                issued_at=self._now(),
                deadline=permit_deadline,
            )
            verification_permit_ref = self._coordinator._put_model(verification_permit)
            verify_context = VerifyContext(
                deadline=permit_deadline,
                worker_id=acquired.lease.worker_id,
                phase=VerificationPhase.STAGED,
                permit=verification_permit,
                permit_ref=verification_permit_ref,
                normalized_action=self._action,
                normalized_action_ref=self._action_ref,
                subject_ref=staged_receipt_ref,
            )
            self._check_deadline("staged verification")
            self._crash(CoordinatorCrashPoint.BEFORE_STAGED_VERIFY)
            verification = await self._adapter.verify_staged(staged_receipt, verify_context)
            verification_received_at = self._now()
            self._crash(CoordinatorCrashPoint.AFTER_STAGED_VERIFY_CALL)
            verification_ref = self._coordinator._put_model(verification)
            self._coordinator._validate_adapter_observation(
                verification.evidence_refs,
                evidence_kind="staged_verification",
                action=self._action,
                adapter_manifest_digest=self._admitted.manifest_digest,
                subject_ref=staged_receipt_ref,
                operation_permit_ref=verification_permit_ref,
                authority_permit_ref=verification_permit.authority_permit_ref,
                subject_authority_ref=verification_permit.subject_permit_ref,
                operation_status=verification.status.value,
                permit_issued_at=verification_permit.issued_at,
                permit_deadline=verification_permit.deadline,
                received_at=verification_received_at,
                expected_observed_state_digest=(
                    staged_receipt.staged_state_digest
                    if verification.status is VerificationStatus.PASS
                    else None
                ),
            )
            self._staged_verification = verification
            self._staged_verification_permit = verification_permit
            self._staged_verification_permit_ref = verification_permit_ref
            verified = self._coordinator._store.record_stage_verification(
                tenant_id=self._action.tenant_id,
                transaction_id=self._action.transaction_id,
                expected_material_version=executed.material.version,
                expected_transaction_version=self._record.version,
                verification_permit=verification_permit,
                verification_permit_ref=verification_permit_ref,
                verification_ref=verification_ref,
                passed=verification.status is VerificationStatus.PASS,
                recorded_at=self._now(),
                recovery_timeout=self._coordinator._config.recovery_deadline,
            )
            self._stage = verified.material
            self._record = verified.transaction
            self._crash(CoordinatorCrashPoint.AFTER_STAGE_VERIFIED)
            if verification.status is not VerificationStatus.PASS:
                self._record = await self._recover_aborting()
                code = (
                    ErrorCode.VERIFICATION_FAILED
                    if verification.status is VerificationStatus.FAIL
                    else ErrorCode.VERIFICATION_UNKNOWN
                )
                raise AgentKernelError(code, "Staged verification did not pass")
            if _APPROVAL_OBLIGATION in self._staging_authorization.round.obligations:
                approval_ref = self._coordinator._put_control_evidence(
                    transaction_id=self._action.transaction_id,
                    event=TransitionEvent.APPROVAL_REQUIRED.value,
                    reason_code=ErrorCode.APPROVAL_REQUIRED.value,
                    recorded_at=self._now(),
                )
                transitioned = self._coordinator._store.apply_control_transition(
                    tenant_id=self._action.tenant_id,
                    transaction_id=self._action.transaction_id,
                    expected_version=self._record.version,
                    transition_event=TransitionEvent.APPROVAL_REQUIRED,
                    recorded_at=self._now(),
                    evidence_refs=(approval_ref,),
                    reason_code=ErrorCode.APPROVAL_REQUIRED.value,
                )
                self._record = transitioned.transaction
                return
            no_approval_ref = self._coordinator._put_control_evidence(
                transaction_id=self._action.transaction_id,
                event=TransitionEvent.NO_APPROVAL_REQUIRED.value,
                reason_code="NO_APPROVAL_REQUIRED",
                recorded_at=self._now(),
            )
            transitioned = self._coordinator._store.apply_control_transition(
                tenant_id=self._action.tenant_id,
                transaction_id=self._action.transaction_id,
                expected_version=self._record.version,
                transition_event=TransitionEvent.NO_APPROVAL_REQUIRED,
                recorded_at=self._now(),
                evidence_refs=(no_approval_ref,),
            )
            self._record = transitioned.transaction
            self._crash(CoordinatorCrashPoint.AFTER_READY_TO_COMMIT)
        except (Exception, CancelledError) as error:
            if self._record.state in _PRE_DISPATCH_STATES and not self._record.state.is_terminal:
                await self._abort_for_error(error)
            raise

    async def commit(self) -> EnforcedTransactionRecord:
        """Revalidate and cross the authoritative boundary once, after durable dispatch."""

        async with self._operation_lock:
            if not self._entered:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Transaction session must be entered before commit",
                )
            if self._record.state is TransactionState.AWAITING_APPROVAL:
                raise AgentKernelError(
                    ErrorCode.APPROVAL_REQUIRED,
                    "This release has no approval service; commit remains fail-closed",
                    review_required=True,
                )
            if self._record.state is not TransactionState.READY_TO_COMMIT:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Transaction is not ready for explicit commit",
                    details={"state": self._record.state.value},
                )
            if self._stage is None or self._staged_receipt is None or self._plan is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Ready transaction lost its verified staged material",
                )
            lease_id, fencing_token = self._require_lease()
            permit_deadline = self._require_lease_deadline()
            try:
                self._check_deadline("precommit authorization")
                authorization = await self._coordinator._evaluate_authorization(
                    self._action,
                    purpose=AuthorizationRoundPurpose.PRECOMMIT,
                    controlled_transaction_id=self._action.transaction_id,
                )
                self._coordinator._check_authorization_valid(
                    authorization,
                    boundary="precommit authorization persistence",
                )
                self._check_deadline("precommit authorization persistence")
                if authorization.round.verdict is AuthorizationVerdict.ELIGIBLE:
                    persisted = self._coordinator._store.authorize_for_precommit(
                        authorization.round,
                        authority_decision=authorization.authority,
                        policy_decision=authorization.policy,
                        capability_ids=authorization.capability_ids,
                        expected_transaction_version=self._record.version,
                    )
                else:
                    persisted = self._coordinator._store.record_precommit_denial(
                        authorization.round,
                        authority_decision=authorization.authority,
                        policy_decision=authorization.policy,
                        expected_transaction_version=self._record.version,
                        recovery_timeout=self._coordinator._config.recovery_deadline,
                    )
                self._record = persisted.transaction
                self._crash(CoordinatorCrashPoint.AFTER_PRECOMMIT_AUTHORIZED)
                if authorization.round.verdict is not AuthorizationVerdict.ELIGIBLE:
                    self._record = await self._recover_aborting()
                    code = (
                        ErrorCode.POLICY_UNKNOWN
                        if authorization.round.verdict is AuthorizationVerdict.UNKNOWN
                        else ErrorCode.POLICY_DENIED
                    )
                    raise AgentKernelError(
                        code,
                        "Precommit authority or policy revalidation failed",
                        details={"reason_code": authorization.round.reason_code},
                        review_required=authorization.round.verdict is AuthorizationVerdict.UNKNOWN,
                    )
                if authorization.authority_valid_until is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Eligible precommit authorization lacks its capability validity bound",
                    )
                permit_deadline = min(
                    self._require_lease_deadline(),
                    authorization.authority_valid_until,
                )
                self._coordinator._check_deadline(
                    permit_deadline,
                    self._now(),
                    boundary="precommit permit issuance",
                )
                if _APPROVAL_OBLIGATION in authorization.round.obligations:
                    evidence_ref = self._coordinator._put_control_evidence(
                        transaction_id=self._action.transaction_id,
                        event=TransitionEvent.COMMIT_REVALIDATION_FAILED.value,
                        reason_code=ErrorCode.APPROVAL_REQUIRED.value,
                        recorded_at=self._now(),
                    )
                    transitioned = self._coordinator._store.apply_control_transition(
                        tenant_id=self._action.tenant_id,
                        transaction_id=self._action.transaction_id,
                        expected_version=self._record.version,
                        transition_event=TransitionEvent.COMMIT_REVALIDATION_FAILED,
                        recorded_at=self._now(),
                        evidence_refs=(evidence_ref,),
                        reason_code=ErrorCode.APPROVAL_REQUIRED.value,
                        recovery_timeout=self._coordinator._config.recovery_deadline,
                    )
                    self._record = transitioned.transaction
                    self._record = await self._recover_aborting()
                    raise AgentKernelError(
                        ErrorCode.APPROVAL_REQUIRED,
                        "Precommit policy introduced an unmet approval obligation",
                        review_required=True,
                    )

                self._check_deadline("precommit inspection permit issuance")
                inspection = InspectionPermit.create(
                    tenant_id=self._action.tenant_id,
                    transaction_id=self._action.transaction_id,
                    intent_hash=self._action.intent_hash,
                    normalized_action_digest=self._action_ref,
                    proposal_ref=self._proposal_ref,
                    adapter_manifest_digest=self._admitted.manifest_digest,
                    authorization_round_id=authorization.round.round_id,
                    authorization_round_digest=authorization.round.round_digest,
                    lease_id=lease_id,
                    worker_id=self._coordinator._config.worker_id,
                    fencing_token=fencing_token,
                    issued_at=self._now(),
                    deadline=permit_deadline,
                )
                inspection_ref = self._coordinator._put_model(inspection)
                read_context = ReadOnlyContext(
                    deadline=permit_deadline,
                    worker_id=self._coordinator._config.worker_id,
                    permit=inspection,
                    permit_ref=inspection_ref,
                    normalized_action=self._action,
                    normalized_action_ref=self._action_ref,
                    proposal=self._request.proposal,
                    proposal_ref=self._proposal_ref,
                )
                self._check_deadline("precommit target inspection")
                refreshed = await self._adapter.inspect(self._request.proposal, read_context)
                self._crash(CoordinatorCrashPoint.AFTER_PRECOMMIT_INSPECT)
                refreshed_ref = self._coordinator._put_model(refreshed)
                self._validate_plan(refreshed)
                if (
                    refreshed.base_version != self._plan.base_version
                    or refreshed.canonical_resource != self._plan.canonical_resource
                    or refreshed.semantic_arguments != self._plan.semantic_arguments
                ):
                    stale_ref = self._coordinator._put_control_evidence(
                        transaction_id=self._action.transaction_id,
                        event=TransitionEvent.TARGET_VERSION_CHANGED.value,
                        reason_code=ErrorCode.STALE_STATE.value,
                        recorded_at=self._now(),
                        subject_ref=refreshed_ref,
                    )
                    transitioned = self._coordinator._store.apply_control_transition(
                        tenant_id=self._action.tenant_id,
                        transaction_id=self._action.transaction_id,
                        expected_version=self._record.version,
                        transition_event=TransitionEvent.TARGET_VERSION_CHANGED,
                        recorded_at=self._now(),
                        evidence_refs=(stale_ref,),
                        reason_code=ErrorCode.STALE_STATE.value,
                        recovery_timeout=self._coordinator._config.recovery_deadline,
                    )
                    self._record = transitioned.transaction
                    self._record = await self._recover_aborting()
                    raise AgentKernelError(
                        ErrorCode.STALE_STATE,
                        "Authoritative target changed after staging",
                    )
                reservation = authorization.reservation
                if reservation is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Eligible precommit authorization lost its capability reservation",
                    )
                committed_reservation = preview_committed_capability_reservation(reservation)
                events = self._coordinator._store.list_enforced_transaction_events(
                    tenant_id=self._action.tenant_id,
                    transaction_id=self._action.transaction_id,
                )
                if not events or events[-1].event != TransitionEvent.NO_APPROVAL_REQUIRED.value:
                    raise AgentKernelError(
                        ErrorCode.APPROVAL_INVALID,
                        "Commit lacks a durable no-approval or granted-approval event",
                    )
                approval_evidence_ref = events[-1].evidence_refs[0]
                if (
                    self._stage.staged_receipt_ref is None
                    or self._stage.staged_state_digest is None
                    or self._stage.verification_permit_digest is None
                    or self._stage.verification_permit_ref is None
                    or self._stage.verification_ref is None
                    or self._staged_verification_permit is None
                    or self._staged_verification_permit_ref is None
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Commit lost exact staged receipt or verification evidence",
                    )
                if (
                    self._staged_verification_permit.permit_digest
                    != self._stage.verification_permit_digest
                    or self._staged_verification_permit_ref != self._stage.verification_permit_ref
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "In-memory staged verification authority differs from durable "
                        "stage material",
                    )
                dispatch_id = _stable_id(
                    "dispatch",
                    {
                        "tenant_id": self._action.tenant_id,
                        "transaction_id": self._action.transaction_id,
                        "owner_version": authorization.round.owner_version,
                    },
                )
                self._check_deadline("commit permit issuance")
                permit = CommitPermit.create(
                    tenant_id=self._action.tenant_id,
                    transaction_id=self._action.transaction_id,
                    intent_hash=self._action.intent_hash,
                    normalized_action_digest=self._action_ref,
                    dispatch_id=dispatch_id,
                    stage_id=self._stage.stage_id,
                    plan_digest=self._stage.plan_digest,
                    plan_ref=self._stage.plan_ref,
                    stage_permit_digest=self._stage.stage_permit_digest,
                    stage_permit_ref=self._stage.stage_permit_ref,
                    lease_id=lease_id,
                    worker_id=self._coordinator._config.worker_id,
                    fencing_token=fencing_token,
                    idempotency_key=self._action.idempotency_key or self._action.intent_hash,
                    target_version_guard=self._stage.target_version_guard,
                    staged_receipt_ref=self._stage.staged_receipt_ref,
                    staged_state_digest=self._stage.staged_state_digest,
                    staged_verification_permit_digest=(self._stage.verification_permit_digest),
                    staged_verification_permit_ref=self._stage.verification_permit_ref,
                    staged_verification_ref=self._stage.verification_ref,
                    precommit_inspection_permit_digest=inspection.permit_digest,
                    precommit_inspection_permit_ref=inspection_ref,
                    precommit_plan_digest=canonical_digest(refreshed),
                    precommit_plan_ref=refreshed_ref,
                    approval_required=False,
                    approval_id=None,
                    approval_evidence_ref=approval_evidence_ref,
                    adapter_manifest_digest=self._admitted.manifest_digest,
                    authority_decision_digest=authorization.round.authority_decision_digest,
                    policy_decision_digest=authorization.round.policy_decision_digest,
                    policy_snapshot_digest=authorization.round.policy_snapshot_digest,
                    authorization_round_id=authorization.round.round_id,
                    authorization_round_digest=authorization.round.round_digest,
                    capability_reservation_digest=capability_reservation_digest(
                        committed_reservation
                    ),
                    reservation_version=committed_reservation.version,
                    owner_version=authorization.round.owner_version,
                    owner_history_sequence=authorization.round.owner_history_sequence,
                    owner_history_digest=authorization.round.owner_history_digest,
                    issued_at=self._now(),
                    deadline=permit_deadline,
                )
                permit_ref = self._coordinator._put_model(permit)
                self._crash(CoordinatorCrashPoint.AFTER_COMMIT_PERMIT_ARTIFACT)
                dispatch = CommitDispatchRecord(
                    tenant_id=self._action.tenant_id,
                    transaction_id=self._action.transaction_id,
                    intent_hash=self._action.intent_hash,
                    dispatch_id=dispatch_id,
                    owner_version=authorization.round.owner_version,
                    permit=permit,
                    permit_ref=permit_ref,
                    state=CommitDispatchState.DISPATCHED,
                    version=0,
                    created_at=self._now(),
                    updated_at=self._now(),
                )
                begun = self._coordinator._store.begin_commit_dispatch(
                    dispatch,
                    precommit_inspection_permit=inspection,
                    precommit_inspection_permit_ref=inspection_ref,
                    precommit_plan=refreshed,
                    precommit_plan_ref=refreshed_ref,
                    expected_transaction_version=self._record.version,
                )
                self._record = begun.transaction
                self._crash(CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED)
                if begun.disposition is not EnforcedStoreDisposition.COMMIT_NOW:
                    raise AgentKernelError(
                        ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                        "Durable dispatch already exists; implicit resend is forbidden",
                        reconcilable=True,
                    )
                self._check_deadline("authoritative commit")
                self._crash(CoordinatorCrashPoint.BEFORE_COMMIT)
                receipt = await self._adapter.commit(
                    self._staged_receipt,
                    CommitContext(
                        deadline=permit_deadline,
                        fencing_token=fencing_token,
                        idempotency_key=permit.idempotency_key,
                        target_version_guard=permit.target_version_guard,
                        permit=permit,
                        permit_ref=permit_ref,
                        normalized_action=self._action,
                        normalized_action_ref=self._action_ref,
                    ),
                )
                self._crash(CoordinatorCrashPoint.AFTER_COMMIT_CALL)
                receipt_ref = self._coordinator._put_model(receipt)
                self._crash(CoordinatorCrashPoint.AFTER_RECEIPT_ARTIFACT)
                if (
                    receipt.transaction_id != self._action.transaction_id
                    or receipt.adapter != self._action.adapter
                    or receipt.operation != self._action.operation
                    or receipt.intent_hash != self._action.intent_hash
                    or receipt.target_version_before != permit.target_version_guard
                ):
                    integrity_error = AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Adapter effect receipt differs from its commit permit",
                    )
                    await self._persist_unknown_dispatch(
                        integrity_error,
                        forensic_refs=(receipt_ref,),
                    )
                    raise integrity_error
                self._effect_receipt = receipt
                attached = self._coordinator._store.attach_receipt(
                    tenant_id=self._action.tenant_id,
                    transaction_id=self._action.transaction_id,
                    expected_dispatch_version=begun.dispatch.version,
                    effect_receipt_ref=receipt_ref,
                    evidence_refs=(receipt_ref,),
                    recorded_at=self._now(),
                )
                self._crash(CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED)
                self._check_deadline("committed verification permit issuance")
                verification_permit = VerificationPermit.create(
                    tenant_id=self._action.tenant_id,
                    transaction_id=self._action.transaction_id,
                    intent_hash=self._action.intent_hash,
                    normalized_action_digest=self._action_ref,
                    adapter_manifest_digest=self._admitted.manifest_digest,
                    authorization_round_id=authorization.round.round_id,
                    authorization_round_digest=authorization.round.round_digest,
                    lease_id=lease_id,
                    worker_id=self._coordinator._config.worker_id,
                    fencing_token=fencing_token,
                    phase=VerificationPhase.COMMITTED,
                    subject_ref=receipt_ref,
                    authority_permit_digest=permit.permit_digest,
                    authority_permit_ref=permit_ref,
                    subject_permit_digest=permit.permit_digest,
                    subject_permit_ref=permit_ref,
                    issued_at=self._now(),
                    deadline=permit_deadline,
                )
                verification_permit_ref = self._coordinator._put_model(verification_permit)
                self._check_deadline("committed-state verification")
                self._crash(CoordinatorCrashPoint.BEFORE_COMMITTED_VERIFY)
                verification = await self._adapter.verify_committed(
                    receipt,
                    VerifyContext(
                        deadline=permit_deadline,
                        worker_id=self._coordinator._config.worker_id,
                        phase=VerificationPhase.COMMITTED,
                        permit=verification_permit,
                        permit_ref=verification_permit_ref,
                        normalized_action=self._action,
                        normalized_action_ref=self._action_ref,
                        subject_ref=receipt_ref,
                    ),
                )
                verification_received_at = self._now()
                self._crash(CoordinatorCrashPoint.AFTER_COMMITTED_VERIFY_CALL)
                verification_ref = self._coordinator._put_model(verification)
                verification_observation_ref, _ = self._coordinator._validate_adapter_observation(
                    verification.evidence_refs,
                    evidence_kind="committed_verification",
                    action=self._action,
                    adapter_manifest_digest=self._admitted.manifest_digest,
                    subject_ref=receipt_ref,
                    operation_permit_ref=verification_permit_ref,
                    authority_permit_ref=verification_permit.authority_permit_ref,
                    subject_authority_ref=verification_permit.subject_permit_ref,
                    operation_status=verification.status.value,
                    permit_issued_at=verification_permit.issued_at,
                    permit_deadline=verification_permit.deadline,
                    received_at=verification_received_at,
                    dispatch=attached.dispatch,
                    expected_observed_state_digest=(
                        receipt.target_version_after
                        if verification.status is VerificationStatus.PASS
                        else None
                    ),
                )
                self._committed_verification = verification
                if verification.status is VerificationStatus.PASS:
                    classified = self._coordinator._store.classify_dispatch_outcome(
                        tenant_id=self._action.tenant_id,
                        transaction_id=self._action.transaction_id,
                        expected_dispatch_version=attached.dispatch.version,
                        expected_transaction_version=self._record.version,
                        classification=ReconciliationOutcome.COMMITTED,
                        evidence_refs=(
                            receipt_ref,
                            verification_permit_ref,
                            verification_ref,
                            verification_observation_ref,
                        ),
                        recorded_at=self._now(),
                        effect_receipt_ref=receipt_ref,
                        committed_verification_permit=verification_permit,
                        committed_verification_permit_ref=verification_permit_ref,
                        committed_verification_ref=verification_ref,
                        recovery_timeout=self._coordinator._config.recovery_deadline,
                    )
                    self._record = classified.transaction
                    self._explicit_commit = True
                    self._crash(CoordinatorCrashPoint.AFTER_OUTCOME_CLASSIFIED)
                    return self._record
                classification = (
                    ReconciliationOutcome.PARTIAL_OR_INVALID
                    if verification.status is VerificationStatus.FAIL
                    else ReconciliationOutcome.UNKNOWN
                )
                reason_code = (
                    ErrorCode.VERIFICATION_FAILED.value
                    if classification is ReconciliationOutcome.PARTIAL_OR_INVALID
                    else ErrorCode.VERIFICATION_UNKNOWN.value
                )
                classified = self._coordinator._store.classify_dispatch_outcome(
                    tenant_id=self._action.tenant_id,
                    transaction_id=self._action.transaction_id,
                    expected_dispatch_version=attached.dispatch.version,
                    expected_transaction_version=self._record.version,
                    classification=classification,
                    evidence_refs=(
                        receipt_ref,
                        verification_permit_ref,
                        verification_ref,
                        verification_observation_ref,
                    ),
                    recorded_at=self._now(),
                    effect_receipt_ref=receipt_ref,
                    reason_code=reason_code,
                    recovery_timeout=self._coordinator._config.recovery_deadline,
                )
                self._record = classified.transaction
                self._crash(CoordinatorCrashPoint.AFTER_OUTCOME_CLASSIFIED)
                if classification is ReconciliationOutcome.UNKNOWN:
                    raise AgentKernelError(
                        ErrorCode.VERIFICATION_UNKNOWN,
                        "Committed effect verification was inconclusive",
                        reconcilable=True,
                        review_required=True,
                    )
                self._record = await self._coordinator._recover_failed(self._record)
                raise AgentKernelError(
                    ErrorCode.VERIFICATION_FAILED,
                    "Committed effect did not pass independent verification",
                )
            except (CancelledError, TimeoutError) as error:
                if self._record.state is TransactionState.COMMITTING:
                    await self._persist_unknown_dispatch(error)
                elif self._record.state in _PRE_DISPATCH_STATES:
                    await self._abort_for_error(error)
                raise
            except Exception as error:
                if self._record.state is TransactionState.COMMITTING:
                    await self._persist_unknown_dispatch(error)
                elif (
                    self._record.state in _PRE_DISPATCH_STATES
                    and not self._record.state.is_terminal
                ):
                    await self._abort_for_error(error)
                raise

    async def _persist_unknown_dispatch(
        self,
        error: BaseException,
        *,
        forensic_refs: tuple[str, ...] = (),
    ) -> None:
        try:
            dispatch = self._coordinator._store.get_commit_dispatch(
                tenant_id=self._action.tenant_id,
                transaction_id=self._action.transaction_id,
            )
        except AgentKernelError as lookup_error:
            if lookup_error.code is ErrorCode.VALIDATION_ERROR:
                return
            raise
        if self._record.state is not TransactionState.COMMITTING:
            return
        deadline_error = isinstance(error, TimeoutError) or (
            isinstance(error, AgentKernelError) and error.code is ErrorCode.DEADLINE_EXCEEDED
        )
        reason = (
            ErrorCode.DEADLINE_EXCEEDED.value
            if deadline_error
            else (
                "CANCELLED_AFTER_DISPATCH"
                if isinstance(error, CancelledError)
                else "COMMIT_OUTCOME_UNKNOWN"
            )
        )
        self._record = self._coordinator._terminalize_dispatch_evidence_unavailable(
            self._record,
            dispatch,
            boundary="POST_DISPATCH_CLASSIFICATION",
            reported_at=self._now(),
            cause=reason,
            supporting_refs=forensic_refs,
        )

    async def cancel(self) -> EnforcedTransactionRecord:
        """Cancel only before dispatch, then prove private-stage cleanup."""

        async with self._operation_lock:
            if self._record.state in {TransactionState.COMMITTING, TransactionState.IN_DOUBT}:
                raise AgentKernelError(
                    ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                    "Cancellation cannot claim no effect after durable dispatch",
                    reconcilable=True,
                )
            if self._record.state.is_terminal:
                return self._record
            await self._transition_to_aborting(
                TransitionEvent.CANCELLED,
                reason_code="CANCELLED",
            )
            self._record = await self._recover_aborting()
            return self._record

    async def _abort_for_error(self, error: BaseException) -> None:
        cancellation = error if isinstance(error, CancelledError) else None
        if self._record.state is TransactionState.ABORTING:
            self._record = await self._recover_aborting(cancellation=cancellation)
            return
        if self._record.state.is_terminal or self._record.state not in _PRE_DISPATCH_STATES:
            return
        if isinstance(error, CancelledError):
            event = TransitionEvent.CANCELLED
            reason = "CANCELLED"
        elif isinstance(error, TimeoutError) or (
            isinstance(error, AgentKernelError) and error.code is ErrorCode.DEADLINE_EXCEEDED
        ):
            event = TransitionEvent.DEADLINE_EXCEEDED
            reason = ErrorCode.DEADLINE_EXCEEDED.value
        elif self._record.state is TransactionState.STAGING:
            event = TransitionEvent.STAGING_FAILED
            reason = error.code.value if isinstance(error, AgentKernelError) else "STAGING_FAILED"
        elif self._record.state is TransactionState.STAGED:
            event = TransitionEvent.STAGED_VERIFICATION_FAILED
            reason = (
                error.code.value
                if isinstance(error, AgentKernelError)
                else "STAGED_VERIFICATION_FAILED"
            )
        elif self._record.state is TransactionState.READY_TO_COMMIT:
            event = TransitionEvent.COMMIT_REVALIDATION_FAILED
            reason = (
                error.code.value
                if isinstance(error, AgentKernelError)
                else "COMMIT_REVALIDATION_FAILED"
            )
        else:
            event = TransitionEvent.CONTEXT_EXITED
            reason = (
                error.code.value
                if isinstance(error, AgentKernelError)
                else "PREDISPATCH_CONTROL_FAILURE"
            )
        await self._transition_to_aborting(event, reason_code=reason)
        self._record = await self._recover_aborting(cancellation=cancellation)

    async def _transition_to_aborting(
        self,
        event: TransitionEvent,
        *,
        reason_code: str,
    ) -> None:
        evidence_ref = self._coordinator._put_control_evidence(
            transaction_id=self._action.transaction_id,
            event=event.value,
            reason_code=reason_code,
            recorded_at=self._now(),
        )
        result = self._coordinator._store.apply_control_transition(
            tenant_id=self._action.tenant_id,
            transaction_id=self._action.transaction_id,
            expected_version=self._record.version,
            transition_event=event,
            recorded_at=self._now(),
            evidence_refs=(evidence_ref,),
            reason_code=reason_code,
            recovery_timeout=self._coordinator._config.recovery_deadline,
        )
        self._record = result.transaction
        self._crash(CoordinatorCrashPoint.AFTER_ABORTING)

    async def __aexit__(self, *_exc: object) -> None:
        cancellation = _exc[1] if len(_exc) > 1 and isinstance(_exc[1], CancelledError) else None
        async with self._operation_lock:
            if self._explicit_commit or self._record.state.is_terminal:
                return
            if self._record.state not in _PRE_DISPATCH_STATES:
                return
            if self._record.state is not TransactionState.ABORTING:
                await self._transition_to_aborting(
                    TransitionEvent.CONTEXT_EXITED,
                    reason_code="CONTEXT_EXITED_WITHOUT_COMMIT",
                )
            self._record = await self._recover_aborting(cancellation=cancellation)
