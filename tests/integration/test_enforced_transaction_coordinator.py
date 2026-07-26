from __future__ import annotations

import asyncio
import multiprocessing
import os
import threading
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from agentkernel.adapters.base import (
    BlockingCancellation,
    CommitContext,
    EffectPlan,
    EvidenceClock,
    ReadOnlyContext,
    ReconcileReport,
    ReconcileStatus,
    RecoveryContext,
    StageContext,
    StagedEffect,
    StagedReceipt,
    VerifyContext,
)
from agentkernel.adapters.mock import MockReversibleAdapter, VersionedMemoryTarget
from agentkernel.adapters.registry import AdapterRegistry
from agentkernel.api import (
    CreateTransactionRequest,
    DispatchReconciliationRequest,
    InProcessKernelAPI,
    RecoveryScanRequest,
    TransactionStatusQuery,
)
from agentkernel.authority import (
    AuthorityEvaluationContext,
    AuthoritySnapshot,
    CapabilityBudgetState,
    CapabilityKeyVersion,
    EnforcedAuthorityDecision,
    EnforcedCapabilityGrant,
)
from agentkernel.canonical import canonical_digest, canonical_json_bytes
from agentkernel.domain.enums import (
    AuthorizationRoundPurpose,
    CommitDispatchState,
    ReconciliationOutcome,
    RecoveryWorkKind,
    RecoveryWorkState,
    RiskClass,
    StageMaterialState,
    TransactionState,
    VerificationStatus,
)
from agentkernel.domain.models import (
    RECOVERY_ACTION_BINDING_ARGUMENT,
    ActionProposal,
    AdapterObservation,
    AuthenticatedActionContext,
    EffectReceipt,
    InspectionPermit,
    IntentRecord,
    NormalizedAction,
    PolicyBundle,
    PolicyDefault,
    PolicyEffect,
    PolicyRule,
    RecoveryActionBinding,
    RecoveryReport,
    SemanticArgument,
    StagePermit,
    VerificationPermit,
    VerificationReport,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.artifacts import LocalArtifactStore
from agentkernel.normalization.mock import MockSetValuesNormalizer
from agentkernel.normalization.registry import NormalizerRegistry
from agentkernel.policy import (
    AggregatePolicyDecision,
    PolicyContext,
    PolicyLayer,
    PolicyLayerInput,
    PolicyLayerSnapshot,
    PolicyResourceInput,
    compile_policy,
)
from agentkernel.storage.control import IntentDisposition
from agentkernel.storage.enforced import SQLiteEnforcedTransactionStore
from agentkernel.transactions.enforced import (
    CoordinatorCrashPoint,
    CoordinatorInjectedCrash,
    EnforcedCoordinatorConfig,
    EnforcedTransactionCoordinator,
    EnforcedTransactionRequest,
    EnforcedTransactionSession,
    EnforcedTransactionStatus,
    PolicyEvaluationInputs,
    RecoveryActionFactory,
    RecoveryFailureKind,
    ValidatedAuthenticatedContext,
)

_CAPABILITY_ID = "capability:coordinator-test"
_MEDIA_TYPE = "application/vnd.agentkernel.canonical+json"
_PROCESS_CRASH_EXIT_CODE = 87


@dataclass(slots=True)
class _Clock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, delta: timedelta) -> None:
        self.value += delta


@dataclass(frozen=True, slots=True)
class _ContextValidator:
    context: AuthenticatedActionContext

    async def validate(
        self,
        request: EnforcedTransactionRequest,
    ) -> ValidatedAuthenticatedContext:
        return ValidatedAuthenticatedContext(
            context=self.context,
            authentication_evidence_ref=request.authentication_evidence_ref,
        )


@dataclass(slots=True)
class _AuthoritySnapshots:
    store: SQLiteEnforcedTransactionStore
    issued_at: datetime
    clock: _Clock | None = None
    grant_expires_at: datetime | None = None
    advance_after_snapshot: timedelta | None = None

    async def snapshot_for(
        self,
        *,
        action: NormalizedAction,
        purpose: AuthorizationRoundPurpose,
        evaluated_at: datetime,
    ) -> AuthoritySnapshot:
        budget = self.store.get_capability_budget(
            tenant_id=action.tenant_id,
            capability_id=_CAPABILITY_ID,
            goal_id=action.goal_id,
            run_id=action.run_id,
        )
        reservation_rows = self.store._connection.execute(
            "SELECT intent_hash FROM enforced_capability_chain_reservations "
            "WHERE tenant_id = ? AND goal_id = ? AND run_id = ? "
            "AND reservation_state = 'RESERVED' ORDER BY intent_hash",
            (action.tenant_id, action.goal_id, action.run_id),
        ).fetchall()
        reserved_intent_hashes = tuple(str(row["intent_hash"]) for row in reservation_rows)
        if len(reserved_intent_hashes) != budget.reserved_uses:
            raise AssertionError("test authority snapshot observed inconsistent reservations")
        grant = EnforcedCapabilityGrant.create(
            tenant_id=action.tenant_id,
            capability_id=_CAPABILITY_ID,
            token_version=1,
            key_id="key:coordinator-test",
            issuer=action.principal_id,
            subject=action.agent_id,
            audience="service:agentkernel",
            goal_id=action.goal_id,
            run_id=action.run_id,
            actions=("memory.read", "memory.write"),
            resource_scopes=("memory://mock/**",),
            data_classes=(),
            issued_at=self.issued_at - timedelta(minutes=1),
            not_before=self.issued_at - timedelta(seconds=30),
            expires_at=self.grant_expires_at or self.issued_at + timedelta(hours=1),
            max_uses=32,
            nonce="nonce:coordinator-test",
        )
        snapshot = AuthoritySnapshot.create(
            tenant_id=action.tenant_id,
            snapshot_id=f"snapshot:{purpose.value.lower()}",
            revision=1,
            as_of=evaluated_at,
            capabilities=(grant,),
            accepted_key_versions=(
                CapabilityKeyVersion(
                    tenant_id=action.tenant_id,
                    key_id=grant.key_id,
                    token_version=grant.token_version,
                ),
            ),
            budget_states=(
                CapabilityBudgetState(
                    tenant_id=action.tenant_id,
                    capability_id=_CAPABILITY_ID,
                    goal_id=action.goal_id,
                    run_id=action.run_id,
                    max_uses=budget.max_uses,
                    consumed_uses=budget.committed_uses,
                    reserved_uses=budget.reserved_uses,
                    reserved_intent_hashes=reserved_intent_hashes,
                ),
            ),
        )
        if self.advance_after_snapshot is not None:
            assert self.clock is not None
            self.clock.advance(self.advance_after_snapshot)
        return snapshot


class _PolicyInputs:
    def __init__(self, clock: _Clock | None = None) -> None:
        policy = compile_policy(
            PolicyBundle(
                name="coordinator-allow",
                version="1.0.0",
                default=PolicyDefault.ABSTAIN,
                rules=(
                    PolicyRule(
                        rule_id="allow-memory",
                        effect=PolicyEffect.GRANT,
                        modes=("read", "stage", "commit_reversible"),
                        when={"resource_within": "memory://mock/**"},
                    ),
                ),
            )
        )
        self.layer = PolicyLayerInput(
            layer=PolicyLayer.SYSTEM,
            scope_id="scope:coordinator-test",
            policy=policy,
        )
        self.snapshot = PolicyLayerSnapshot.create((self.layer.identity,))
        self.last_inputs: PolicyEvaluationInputs | None = None
        self.clock = clock
        self.advance_after_inputs: timedelta | None = None

    async def inputs_for(
        self,
        *,
        action: NormalizedAction,
        authority_decision: EnforcedAuthorityDecision,
        purpose: AuthorizationRoundPurpose,
        evaluated_at: datetime,
    ) -> PolicyEvaluationInputs:
        del purpose, evaluated_at
        provenance = {item.provenance_id: item for item in action.provenance}
        resources = tuple(
            PolicyResourceInput(
                resource_index=index,
                resource_use_ref=canonical_digest(resource),
                resource_use=resource,
                context=PolicyContext(
                    action=resource.authority_action,
                    resource=resource.canonical_resource,
                    provenance_trust=tuple(
                        sorted(
                            {provenance[item].trust for item in resource.provenance_ids},
                            key=lambda trust: trust.value,
                        )
                    ),
                    requested_scope_expands=(
                        False
                        if authority_decision.resource_decisions[index].verdict.value == "ALLOW"
                        else None
                    ),
                    data_classes=resource.data_classes,
                    destination_external=resource.destination_external,
                    risk_class=action.risk_floor,
                ),
            )
            for index, resource in enumerate(action.resource_uses)
        )
        supplied = PolicyEvaluationInputs(
            snapshot=self.snapshot,
            layers=(self.layer,),
            resources=resources,
        )
        self.last_inputs = supplied
        if self.advance_after_inputs is not None:
            assert self.clock is not None
            self.clock.advance(self.advance_after_inputs)
        return supplied


class _RecoveryActions(RecoveryActionFactory):
    async def create(
        self,
        *,
        target: object,
        target_action: NormalizedAction,
        kind: object,
        target_evidence_ref: str,
        binding: RecoveryActionBinding,
        deadline: datetime,
    ) -> NormalizedAction:
        del target, kind, target_evidence_ref
        binding_bytes = canonical_json_bytes(binding)
        binding_argument = SemanticArgument(
            argument_name=RECOVERY_ACTION_BINDING_ARGUMENT,
            resource=target_action.resource_uses[0].canonical_resource,
            digest=canonical_digest(binding),
            size_bytes=len(binding_bytes),
            media_type=_MEDIA_TYPE,
        )
        context = AuthenticatedActionContext(
            tenant_id=target_action.tenant_id,
            principal_id=target_action.principal_id,
            goal_id=target_action.goal_id,
            run_id=target_action.run_id,
            trace_id=target_action.trace_id,
            actor_id=target_action.actor_id,
            on_behalf_of=target_action.on_behalf_of,
            agent_id=target_action.agent_id,
            configuration_digest=target_action.configuration_digest,
        )
        return NormalizedAction.create(
            context=context,
            transaction_id=f"recovery.action:{binding.recovery_id.rsplit(':', 1)[-1]}",
            deadline=deadline,
            idempotency_key=f"recovery:{binding.recovery_id}",
            adapter=target_action.adapter,
            adapter_version=target_action.adapter_version,
            adapter_manifest_digest=target_action.adapter_manifest_digest,
            operation=target_action.operation,
            normalizer_implementation=target_action.normalizer_implementation,
            normalizer_version=target_action.normalizer_version,
            normalizer_digest=target_action.normalizer_digest,
            operation_schema_ref=target_action.operation_schema_ref,
            operation_schema_digest=target_action.operation_schema_digest,
            risk_floor=target_action.risk_floor,
            effect_domains=target_action.effect_domains,
            resource_uses=target_action.resource_uses,
            semantic_arguments=tuple(
                sorted(
                    (*target_action.semantic_arguments, binding_argument),
                    key=lambda argument: argument.sort_key(),
                )
            ),
            provenance=target_action.provenance,
        )


class _ControlledVerificationAdapter(MockReversibleAdapter):
    def __init__(
        self,
        target: VersionedMemoryTarget,
        *,
        require_permits: bool = False,
        artifacts: LocalArtifactStore | None = None,
        clock: EvidenceClock | None = None,
    ) -> None:
        super().__init__(
            target,
            require_permits=require_permits,
            artifacts=artifacts,
            clock=clock,
        )
        self.staged_status = VerificationStatus.PASS
        self.committed_status = VerificationStatus.PASS
        self.abort_stage_calls = 0
        self.rollback_calls = 0
        self.artifacts = artifacts

    def _observation_refs_for_status(
        self,
        evidence_refs: tuple[str, ...],
        status: str,
    ) -> tuple[str, ...]:
        if self.artifacts is None or len(evidence_refs) != 1:
            raise AssertionError("controlled test adapter requires one durable observation")
        observation = self.artifacts.get_model(
            evidence_refs[0],
            AdapterObservation,
        )
        return (
            self.artifacts.put_model(
                observation.model_copy(update={"operation_status": status})
            ).digest,
        )

    async def verify_staged(
        self,
        receipt: StagedReceipt,
        ctx: VerifyContext,
    ) -> VerificationReport:
        passed = await super().verify_staged(receipt, ctx)
        if self.staged_status is VerificationStatus.PASS:
            return passed
        return VerificationReport(
            status=self.staged_status,
            verifier="adapter.mock.controlled-staged",
            summary=f"Synthetic {self.staged_status.value} staged verification",
            evidence_refs=self._observation_refs_for_status(
                passed.evidence_refs,
                self.staged_status.value,
            ),
        )

    async def verify_committed(
        self,
        receipt: EffectReceipt,
        ctx: VerifyContext,
    ) -> VerificationReport:
        passed = await super().verify_committed(receipt, ctx)
        if self.committed_status is VerificationStatus.PASS:
            return passed
        return VerificationReport(
            status=self.committed_status,
            verifier="adapter.mock.controlled-committed",
            summary=f"Synthetic {self.committed_status.value} committed verification",
            evidence_refs=self._observation_refs_for_status(
                passed.evidence_refs,
                self.committed_status.value,
            ),
        )

    async def abort_stage(self, stage_id: str, ctx: RecoveryContext) -> RecoveryReport:
        self.abort_stage_calls += 1
        return await super().abort_stage(stage_id, ctx)

    async def rollback(
        self,
        receipt: EffectReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        self.rollback_calls += 1
        return await super().rollback(receipt, ctx)


class _MalformedReceiptAdapter(_ControlledVerificationAdapter):
    def __init__(
        self,
        target: VersionedMemoryTarget,
        *,
        require_permits: bool = False,
        artifacts: LocalArtifactStore | None = None,
        clock: EvidenceClock | None = None,
    ) -> None:
        super().__init__(
            target,
            require_permits=require_permits,
            artifacts=artifacts,
            clock=clock,
        )
        self.malformed_receipt: EffectReceipt | None = None

    async def commit(
        self,
        receipt: StagedReceipt,
        ctx: CommitContext,
    ) -> EffectReceipt:
        committed = await super().commit(receipt, ctx)
        self.malformed_receipt = committed.model_copy(
            update={"transaction_id": "transaction:malformed-adapter-return"}
        )
        return self.malformed_receipt


class _TimeoutAfterDurableEffectAdapter(_ControlledVerificationAdapter):
    def __init__(
        self,
        target: VersionedMemoryTarget,
        *,
        require_permits: bool = False,
        artifacts: LocalArtifactStore | None = None,
        clock: EvidenceClock | None = None,
    ) -> None:
        super().__init__(
            target,
            require_permits=require_permits,
            artifacts=artifacts,
            clock=clock,
        )
        self.commit_calls = 0
        self.reconcile_calls = 0
        self.applied_receipt: EffectReceipt | None = None

    async def commit(
        self,
        receipt: StagedReceipt,
        ctx: CommitContext,
    ) -> EffectReceipt:
        self.commit_calls += 1
        self.applied_receipt = await super().commit(receipt, ctx)
        raise TimeoutError("synthetic lost acknowledgement after durable effect")

    async def reconcile(
        self,
        intent: IntentRecord,
        ctx: RecoveryContext,
    ) -> ReconcileReport:
        self.reconcile_calls += 1
        return await super().reconcile(intent, ctx)


class _ObservationFaultAdapter(_ControlledVerificationAdapter):
    observation_fault = "missing"

    async def verify_staged(
        self,
        receipt: StagedReceipt,
        ctx: VerifyContext,
    ) -> VerificationReport:
        report = await super().verify_staged(receipt, ctx)
        if self.artifacts is None or len(report.evidence_refs) != 1:
            raise AssertionError("observation fault adapter requires one observation")
        observation_ref = report.evidence_refs[0]
        if self.observation_fault == "missing":
            return report.model_copy(update={"evidence_refs": ()})
        if self.observation_fault == "tampered":
            _artifact_path(self.artifacts.root, observation_ref).write_bytes(
                b"tampered-adapter-observation"
            )
            return report
        if self.observation_fault == "unrelated":
            unrelated = self.artifacts.put(b"unrelated-adapter-evidence")
            return report.model_copy(update={"evidence_refs": (unrelated.digest,)})
        observation = self.artifacts.get_model(observation_ref, AdapterObservation)
        if self.observation_fault == "wrong_parent":
            changed = observation.model_copy(
                update={"operation_permit_ref": observation.subject_authority_ref}
            )
        elif self.observation_fault == "future":
            changed = observation.model_copy(
                update={"observed_at": ctx.deadline + timedelta(seconds=1)}
            )
        else:
            raise AssertionError(f"unknown observation fault: {self.observation_fault}")
        changed_ref = self.artifacts.put_model(changed).digest
        return report.model_copy(update={"evidence_refs": (changed_ref,)})


class _CrashAfterPrivateStageAdapter(_ControlledVerificationAdapter):
    async def stage(self, plan: EffectPlan, ctx: StageContext) -> StagedEffect:
        await super().stage(plan, ctx)
        raise RuntimeError("synthetic crash after private stage creation")


class _WrongCommittedGenerationAdapter(_ControlledVerificationAdapter):
    async def verify_committed(
        self,
        receipt: EffectReceipt,
        ctx: VerifyContext,
    ) -> VerificationReport:
        report = await super().verify_committed(receipt, ctx)
        if self.artifacts is None or len(report.evidence_refs) != 1:
            raise AssertionError("generation fault adapter requires one observation")
        observation = self.artifacts.get_model(
            report.evidence_refs[0],
            AdapterObservation,
        )
        if observation.owner_version is None:
            raise AssertionError("committed observation lacks a dispatch generation")
        changed = observation.model_copy(update={"owner_version": observation.owner_version + 2})
        changed_ref = self.artifacts.put_model(changed).digest
        return report.model_copy(update={"evidence_refs": (changed_ref,)})


class _QuiescentCommitBarrierAdapter(_ControlledVerificationAdapter):
    def __init__(
        self,
        target: VersionedMemoryTarget,
        *,
        require_permits: bool = False,
        artifacts: LocalArtifactStore | None = None,
        clock: EvidenceClock | None = None,
    ) -> None:
        super().__init__(
            target,
            require_permits=require_permits,
            artifacts=artifacts,
            clock=clock,
        )
        self.commit_barrier: str | None = None
        self.commit_barrier_entered = threading.Event()
        self.commit_barrier_release = threading.Event()
        self.commit_cancellation_seen = threading.Event()
        self._commit_cancellation: BlockingCancellation | None = None

    def _commit_locked(
        self,
        receipt: StagedReceipt,
        ctx: CommitContext,
        cancellation: BlockingCancellation,
    ) -> EffectReceipt:
        self._commit_cancellation = cancellation
        try:
            return super()._commit_locked(receipt, ctx, cancellation)
        finally:
            self._commit_cancellation = None

    def _fault_point(self, name: str) -> None:
        if name != self.commit_barrier:
            return
        self.commit_barrier_entered.set()
        for _ in range(500):
            if self._commit_cancellation is not None and self._commit_cancellation.requested:
                self.commit_cancellation_seen.set()
            if self.commit_barrier_release.wait(timeout=0.01):
                return
        raise AssertionError(f"commit barrier timed out: {name}")


class _SequencedReconciliationAdapter(_ControlledVerificationAdapter):
    def __init__(
        self,
        target: VersionedMemoryTarget,
        *,
        require_permits: bool = False,
        artifacts: LocalArtifactStore | None = None,
        clock: EvidenceClock | None = None,
    ) -> None:
        super().__init__(
            target,
            require_permits=require_permits,
            artifacts=artifacts,
            clock=clock,
        )
        self.reconcile_statuses: list[ReconcileStatus] = []
        self.reconcile_calls = 0

    async def reconcile(
        self,
        intent: IntentRecord,
        ctx: RecoveryContext,
    ) -> ReconcileReport:
        authoritative = await super().reconcile(intent, ctx)
        self.reconcile_calls += 1
        if not self.reconcile_statuses:
            return authoritative
        status = self.reconcile_statuses.pop(0)
        if status is ReconcileStatus.COMMITTED:
            return authoritative
        return ReconcileReport(
            status=status,
            evidence_refs=self._observation_refs_for_status(
                authoritative.evidence_refs,
                status.value,
            ),
        )


class _LateRecoveryAdapter(_SequencedReconciliationAdapter):
    test_clock: _Clock | None = None

    def _expire_recovery_permit(self) -> None:
        if self.test_clock is None:
            raise AssertionError("late recovery adapter requires the harness clock")
        self.test_clock.advance(timedelta(minutes=2))

    async def abort_stage(self, stage_id: str, ctx: RecoveryContext) -> RecoveryReport:
        report = await super().abort_stage(stage_id, ctx)
        self._expire_recovery_permit()
        return report

    async def rollback(
        self,
        receipt: EffectReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        report = await super().rollback(receipt, ctx)
        self._expire_recovery_permit()
        return report

    async def reconcile(
        self,
        intent: IntentRecord,
        ctx: RecoveryContext,
    ) -> ReconcileReport:
        report = await super().reconcile(intent, ctx)
        self._expire_recovery_permit()
        return report


class _LateCompensatingAdapter(_ControlledVerificationAdapter):
    test_clock: _Clock | None = None
    compensation_calls = 0

    def __init__(
        self,
        target: VersionedMemoryTarget,
        *,
        require_permits: bool = False,
        artifacts: LocalArtifactStore | None = None,
        clock: EvidenceClock | None = None,
    ) -> None:
        super().__init__(
            target,
            require_permits=require_permits,
            artifacts=artifacts,
            clock=clock,
        )
        operation = self.manifest.operations["set_values"].model_copy(
            update={"risk_floor": RiskClass.COMPENSATABLE, "compensate": True}
        )
        self.manifest = self.manifest.model_copy(update={"operations": {"set_values": operation}})

    async def inspect(
        self,
        proposal: ActionProposal,
        ctx: ReadOnlyContext,
    ) -> EffectPlan:
        plan = await super().inspect(proposal, ctx)
        return plan.model_copy(update={"risk_class": RiskClass.COMPENSATABLE})

    async def compensate(
        self,
        receipt: EffectReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        with self._target.lock:
            self.compensation_calls += 1
            tenant_id = ctx.permit.tenant_id if ctx.permit is not None else "tenant:embedded"
            dispatch = self._dispatch_for_receipt(tenant_id, receipt)
            self._admit_recovery(
                ctx,
                kind=RecoveryWorkKind.COMPENSATE,
                transaction_id=receipt.transaction_id,
                intent_hash=receipt.intent_hash,
                target_id=dispatch.dispatch_id if dispatch is not None else None,
                target_version_guard=receipt.target_version_before,
                target_normalized_action_digest=(
                    dispatch.normalized_action_digest if dispatch is not None else None
                ),
                target_owner_version=(dispatch.owner_version if dispatch is not None else None),
                target_owner_history_sequence=(
                    dispatch.owner_history_sequence if dispatch is not None else None
                ),
                target_owner_history_digest=(
                    dispatch.owner_history_digest if dispatch is not None else None
                ),
            )
            if dispatch is None or dispatch.receipt != receipt:
                return RecoveryReport(
                    status=VerificationStatus.UNKNOWN,
                    strategy="compensate_memory_snapshot",
                    residual_effects=("missing_snapshot",),
                )
            if self._target.state == dispatch.after_state:
                self._target.state = deepcopy(dispatch.before_state)
                self._target.version += 1
                dispatch.status = "ROLLED_BACK"
            status = (
                VerificationStatus.PASS
                if self._target.state == dispatch.before_state
                else VerificationStatus.UNKNOWN
            )
            report = RecoveryReport(
                status=status,
                strategy="compensate_memory_snapshot",
                restored_state_digest=self._target.digest,
                residual_effects=(
                    () if status is VerificationStatus.PASS else ("target_state_changed",)
                ),
            )
            if ctx.permit is None or ctx.permit_ref is None:
                raise AssertionError("compensation test requires an enforced recovery permit")
            evidence_refs = self._record_observation(
                evidence_kind="compensation",
                tenant_id=ctx.permit.tenant_id,
                transaction_id=receipt.transaction_id,
                intent_hash=receipt.intent_hash,
                normalized_action_digest=dispatch.normalized_action_digest,
                subject_ref=canonical_digest(receipt),
                operation_permit_ref=ctx.permit_ref,
                authority_permit_ref=ctx.permit_ref,
                subject_authority_ref=ctx.permit.target_evidence_ref,
                operation_status=status.value,
                observed_state_digest=self._target.digest,
                durable_state_digest=self._dispatch_digest(dispatch),
                dispatch=dispatch,
            )
            report = report.model_copy(update={"evidence_refs": evidence_refs})
        if self.test_clock is None:
            raise AssertionError("late compensation adapter requires the harness clock")
        self.test_clock.advance(timedelta(minutes=2))
        return report


class _FailOneDiscardAdapter(_ControlledVerificationAdapter):
    def __init__(
        self,
        target: VersionedMemoryTarget,
        *,
        require_permits: bool = False,
        artifacts: LocalArtifactStore | None = None,
        clock: EvidenceClock | None = None,
    ) -> None:
        super().__init__(
            target,
            require_permits=require_permits,
            artifacts=artifacts,
            clock=clock,
        )
        self.fail_stage_id: str | None = None

    async def abort_stage(self, stage_id: str, ctx: RecoveryContext) -> RecoveryReport:
        if stage_id == self.fail_stage_id:
            self.abort_stage_calls += 1
            raise AgentKernelError(
                ErrorCode.ROLLBACK_FAILED,
                "Synthetic isolated discard failure",
            )
        return await super().abort_stage(stage_id, ctx)


@dataclass(slots=True)
class _Harness:
    store: SQLiteEnforcedTransactionStore
    artifacts: LocalArtifactStore
    target: VersionedMemoryTarget
    adapter: MockReversibleAdapter
    registry: AdapterRegistry
    normalizers: NormalizerRegistry
    context_validator: _ContextValidator
    authority_snapshots: _AuthoritySnapshots
    policy_inputs: _PolicyInputs
    recovery_actions: _RecoveryActions
    coordinator: EnforcedTransactionCoordinator
    request: EnforcedTransactionRequest
    clock: _Clock


def _make_harness(
    tmp_path: Path,
    *,
    transaction_id: str = "transaction:coordinator",
    adapter_type: type[MockReversibleAdapter] = MockReversibleAdapter,
    crash_point: CoordinatorCrashPoint | None = None,
    hard_crash: bool = False,
    max_reconciliation_attempts: int = 3,
) -> _Harness:
    now = datetime.now(UTC)
    clock = _Clock(now)
    evidence_clock = EvidenceClock(clock)
    artifacts = LocalArtifactStore(tmp_path / "artifacts", clock=evidence_clock)
    store = SQLiteEnforcedTransactionStore(tmp_path / "control.db")
    normalizer = MockSetValuesNormalizer()
    context = AuthenticatedActionContext(
        tenant_id="tenant:coordinator",
        principal_id="principal:coordinator",
        goal_id="goal:coordinator",
        run_id="run:coordinator",
        trace_id="trace:coordinator",
        actor_id="actor:coordinator",
        on_behalf_of="principal:coordinator",
        agent_id="agent:coordinator",
        configuration_digest=normalizer.configuration_digest,
    )
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = adapter_type(
        target,
        require_permits=True,
        artifacts=artifacts,
        clock=evidence_clock,
    )
    adapters = AdapterRegistry()
    adapters.register(adapter, reviewed=True)
    normalizers = NormalizerRegistry()
    normalizers.register("mock", "set_values", normalizer, reviewed=True)
    store.register_action_context(context, registered_at=now)
    store.register_capability_budget(
        tenant_id=context.tenant_id,
        capability_id=_CAPABILITY_ID,
        goal_id=context.goal_id,
        run_id=context.run_id,
        max_uses=32,
        registered_at=now,
    )
    proposal = ActionProposal(
        goal_id=context.goal_id,
        transaction_id=transaction_id,
        agent_id=context.agent_id,
        adapter="mock",
        adapter_version=adapter.manifest.version,
        operation="set_values",
        arguments={"values": {"answer": "42"}},
        provenance_ids=(),
        capability_refs=(_CAPABILITY_ID,),
        deadline=now + timedelta(minutes=5),
        idempotency_key=f"idempotency:{transaction_id}",
    )
    authentication = artifacts.put(b"authenticated-context-proof")
    request = EnforcedTransactionRequest(
        proposal=proposal,
        presented_context=context,
        authentication_evidence_ref=authentication.digest,
    )

    def crash_hook(point: CoordinatorCrashPoint) -> None:
        if point is crash_point:
            if hard_crash:
                os._exit(_PROCESS_CRASH_EXIT_CODE)
            raise RuntimeError("simulated process crash")

    context_validator = _ContextValidator(context)
    authority_snapshots = _AuthoritySnapshots(store, now, clock=clock)
    policy_inputs = _PolicyInputs(clock)
    recovery_actions = _RecoveryActions()
    coordinator = EnforcedTransactionCoordinator(
        store=store,
        registry=adapters,
        normalizers=normalizers,
        artifacts=artifacts,
        context_validator=context_validator,
        authority_snapshots=authority_snapshots,
        policy_inputs=policy_inputs,
        recovery_actions=recovery_actions,
        config=EnforcedCoordinatorConfig(
            worker_id="worker:coordinator",
            lease_duration=timedelta(minutes=1),
            recovery_deadline=timedelta(minutes=4),
            reconciliation_backoff=timedelta(seconds=2),
            max_reconciliation_attempts=max_reconciliation_attempts,
            crash_hook=crash_hook if crash_point is not None else None,
        ),
        clock=clock,
    )
    return _Harness(
        store=store,
        artifacts=artifacts,
        target=target,
        adapter=adapter,
        registry=adapters,
        normalizers=normalizers,
        context_validator=context_validator,
        authority_snapshots=authority_snapshots,
        policy_inputs=policy_inputs,
        recovery_actions=recovery_actions,
        coordinator=coordinator,
        request=request,
        clock=clock,
    )


def _restart_coordinator(
    harness: _Harness,
    *,
    worker_id: str = "worker:recovery",
    max_reconciliation_attempts: int = 3,
    recovery_deadline: timedelta = timedelta(minutes=4),
    reconciliation_backoff: timedelta = timedelta(seconds=2),
    crash_point: CoordinatorCrashPoint | None = None,
) -> EnforcedTransactionCoordinator:
    def crash_hook(point: CoordinatorCrashPoint) -> None:
        if point is crash_point:
            raise RuntimeError("simulated process crash")

    return EnforcedTransactionCoordinator(
        store=harness.store,
        registry=harness.registry,
        normalizers=harness.normalizers,
        artifacts=harness.artifacts,
        context_validator=harness.context_validator,
        authority_snapshots=harness.authority_snapshots,
        policy_inputs=harness.policy_inputs,
        recovery_actions=harness.recovery_actions,
        config=EnforcedCoordinatorConfig(
            worker_id=worker_id,
            lease_duration=timedelta(minutes=1),
            recovery_deadline=recovery_deadline,
            reconciliation_backoff=reconciliation_backoff,
            max_reconciliation_attempts=max_reconciliation_attempts,
            crash_hook=crash_hook if crash_point is not None else None,
        ),
        clock=harness.clock,
    )


async def _stop_dispatch_before_explicit_resume(
    harness: _Harness,
    session: EnforcedTransactionSession,
    *,
    coordinator: EnforcedTransactionCoordinator | None = None,
) -> EnforcedTransactionCoordinator:
    restarted = coordinator or _restart_coordinator(harness)
    stopped = await restarted.recover_once(session.record.tenant_id)
    assert stopped.processed == 1
    assert stopped.remaining == 0
    assert len(stopped.failures) == 1
    assert stopped.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
    assert stopped.failures[0].reason_code == "EVIDENCE_UNAVAILABLE:PROCESS_RESTART_AFTER_DISPATCH"
    assert stopped.statuses[0].record.state is TransactionState.IN_DOUBT
    assert not harness.store.list_recovery_work(
        tenant_id=session.record.tenant_id,
        transaction_id=session.record.transaction_id,
    )
    dispatch = harness.store.get_commit_dispatch(
        tenant_id=session.record.tenant_id,
        transaction_id=session.record.transaction_id,
    )
    assert dispatch.unavailable_record_digest is not None
    assert (
        harness.store.get_dispatch_evidence_unavailable(
            tenant_id=dispatch.tenant_id,
            transaction_id=dispatch.transaction_id,
            dispatch_id=dispatch.dispatch_id,
        )
        is not None
    )
    return restarted


def _reopen_coordinator(
    harness: _Harness,
    database_path: Path,
    *,
    authority_audience: str = "service:agentkernel",
) -> tuple[SQLiteEnforcedTransactionStore, EnforcedTransactionCoordinator]:
    store = SQLiteEnforcedTransactionStore(database_path)
    artifacts = LocalArtifactStore(harness.artifacts.root)
    authority_snapshots = _AuthoritySnapshots(
        store=store,
        issued_at=harness.authority_snapshots.issued_at,
        clock=harness.clock,
        grant_expires_at=harness.authority_snapshots.grant_expires_at,
    )
    coordinator = EnforcedTransactionCoordinator(
        store=store,
        registry=harness.registry,
        normalizers=harness.normalizers,
        artifacts=artifacts,
        context_validator=harness.context_validator,
        authority_snapshots=authority_snapshots,
        policy_inputs=harness.policy_inputs,
        recovery_actions=harness.recovery_actions,
        config=EnforcedCoordinatorConfig(
            worker_id="worker:reopened",
            authority_audience=authority_audience,
            lease_duration=timedelta(minutes=1),
            recovery_deadline=timedelta(minutes=4),
            reconciliation_backoff=timedelta(seconds=2),
            max_reconciliation_attempts=3,
        ),
        clock=harness.clock,
    )
    return store, coordinator


def _artifact_path(root: Path, digest: str) -> Path:
    algorithm, hexadecimal = digest.split(":", maxsplit=1)
    return root / algorithm / hexadecimal[:2] / hexadecimal[2:4] / hexadecimal


def _kill_process_after_durable_dispatch(root: str) -> None:
    harness = _make_harness(
        Path(root),
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
        hard_crash=True,
    )

    async def execute() -> None:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            await session.commit()

    asyncio.run(execute())
    os._exit(_PROCESS_CRASH_EXIT_CODE + 1)


@pytest.mark.asyncio
async def test_kernel_api_preserves_explicit_commit_duplicate_idempotency_and_tenant_scope(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path)
    api = InProcessKernelAPI(harness.coordinator)
    request = CreateTransactionRequest(transaction=harness.request)
    try:
        created = await api.transaction(request)
        assert isinstance(created, EnforcedTransactionSession)
        async with created:
            assert harness.target.state == {"before": "kept"}
            committed = await created.commit()

        assert committed.state is TransactionState.COMMITTED
        assert harness.target.state == {"before": "kept", "answer": "42"}
        assert harness.target.version == 1
        assert len(harness.target.dispatches) == 1

        duplicate = await api.transaction(request)
        assert isinstance(duplicate, EnforcedTransactionStatus)
        assert duplicate.record == committed
        assert harness.target.version == 1
        assert len(harness.target.dispatches) == 1

        status = api.status(
            TransactionStatusQuery(
                tenant_id=committed.tenant_id,
                transaction_id=committed.transaction_id,
            )
        )
        assert status.record == committed
        with pytest.raises(AgentKernelError) as wrong_tenant:
            api.status(
                TransactionStatusQuery(
                    tenant_id="tenant:not-the-owner",
                    transaction_id=committed.transaction_id,
                )
            )
        assert wrong_tenant.value.code is ErrorCode.VALIDATION_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_kernel_api_context_exit_aborts_without_authoritative_effect(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path)
    api = InProcessKernelAPI(harness.coordinator)
    try:
        created = await api.transaction(CreateTransactionRequest(transaction=harness.request))
        assert isinstance(created, EnforcedTransactionSession)
        async with created:
            assert created.record.state is TransactionState.READY_TO_COMMIT

        assert created.record.state is TransactionState.ABORTED
        assert harness.target.state == {"before": "kept"}
        assert harness.target.version == 0
        assert harness.target.dispatches == {}
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_kernel_api_recover_once_resumes_tenant_aborting_work(tmp_path: Path) -> None:
    harness = _make_harness(
        tmp_path,
        crash_point=CoordinatorCrashPoint.AFTER_ABORTING,
    )
    try:
        api = InProcessKernelAPI(harness.coordinator)
        created = await api.transaction(CreateTransactionRequest(transaction=harness.request))
        assert isinstance(created, EnforcedTransactionSession)
        with pytest.raises(CoordinatorInjectedCrash):
            async with created:
                pass
        assert created.record.state is TransactionState.ABORTING

        harness.clock.advance(timedelta(minutes=1, microseconds=1))
        recovery_api = InProcessKernelAPI(_restart_coordinator(harness))
        recovered = await recovery_api.recover_once(
            RecoveryScanRequest(tenant_id=created.record.tenant_id, limit=1)
        )

        assert recovered.processed == 1
        assert not recovered.failures
        assert recovered.statuses[0].record.state is TransactionState.ABORTED
        assert harness.target.state == {"before": "kept"}
        assert harness.target.dispatches == {}
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_kernel_api_explicit_reconciliation_never_redispatches_original_intent(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_TimeoutAfterDurableEffectAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _TimeoutAfterDurableEffectAdapter)
    try:
        api = InProcessKernelAPI(harness.coordinator)
        created = await api.transaction(CreateTransactionRequest(transaction=harness.request))
        assert isinstance(created, EnforcedTransactionSession)
        with pytest.raises(TimeoutError):
            async with created:
                await created.commit()
        assert created.record.state is TransactionState.IN_DOUBT

        recovery_api = InProcessKernelAPI(_restart_coordinator(harness))
        reconciled = await recovery_api.resume_dispatch_reconciliation(
            DispatchReconciliationRequest(
                tenant_id=created.record.tenant_id,
                transaction_id=created.record.transaction_id,
            )
        )

        assert reconciled.record.state is TransactionState.COMMITTED
        assert adapter.commit_calls == 1
        assert adapter.reconcile_calls == 1
        assert harness.target.version == 1
        assert len(harness.target.dispatches) == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_enforced_happy_commit_binds_full_request_and_lease_deadlines(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            ready_record = session.record
            assert ready_record.state is TransactionState.READY_TO_COMMIT
            committed = await session.commit()
        assert committed.state is TransactionState.COMMITTED
        assert harness.target.state["answer"] == "42"
        stored_request = harness.artifacts.get_model(
            committed.request_digest,
            EnforcedTransactionRequest,
        )
        assert stored_request == harness.request
        stage = harness.store.get_stage_material(
            tenant_id=committed.tenant_id,
            transaction_id=committed.transaction_id,
        )
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=committed.tenant_id,
            transaction_id=committed.transaction_id,
        )
        lease = harness.store.get_worker_lease(
            tenant_id=committed.tenant_id,
            transaction_id=committed.transaction_id,
            lease_id=stage.lease_id,
        )
        assert dispatch.permit.deadline == lease.expires_at
        assert dispatch.permit.deadline < session.action.deadline
        assert dispatch.permit.staged_verification_permit_ref == stage.verification_permit_ref
        assert harness.artifacts.get(dispatch.permit.precommit_plan_ref)
        assert committed.authorization_round_id is not None
        authorization_round = harness.store.get_authorization_round(
            tenant_id=committed.tenant_id,
            controlled_transaction_id=committed.transaction_id,
            round_id=committed.authorization_round_id,
        )
        assert authorization_round.purpose is AuthorizationRoundPurpose.PRECOMMIT
        assert authorization_round.authority_snapshot_ref is not None
        assert authorization_round.authority_context_ref is not None
        assert authorization_round.authority_decision_ref is not None
        assert authorization_round.policy_inputs_ref is not None
        assert authorization_round.policy_snapshot_ref is not None
        assert authorization_round.policy_decision_ref is not None
        assert (
            harness.artifacts.get_model(
                authorization_round.authority_snapshot_ref,
                AuthoritySnapshot,
            ).snapshot_digest
            == authorization_round.authority_snapshot_digest
        )
        authority_context = harness.artifacts.get_model(
            authorization_round.authority_context_ref,
            AuthorityEvaluationContext,
        )
        assert authority_context.audience == "service:agentkernel"
        assert (
            canonical_digest(authority_context)
            == harness.artifacts.get_model(
                authorization_round.authority_decision_ref,
                EnforcedAuthorityDecision,
            ).evaluation_context_digest
        )
        assert (
            harness.artifacts.get_model(
                authorization_round.authority_decision_ref,
                EnforcedAuthorityDecision,
            ).decision_digest
            == authorization_round.authority_decision_digest
        )
        assert isinstance(
            harness.artifacts.get_model(
                authorization_round.policy_inputs_ref,
                PolicyEvaluationInputs,
            ),
            PolicyEvaluationInputs,
        )
        assert (
            harness.artifacts.get_model(
                authorization_round.policy_snapshot_ref,
                PolicyLayerSnapshot,
            ).snapshot_digest
            == authorization_round.policy_snapshot_digest
        )
        assert (
            harness.artifacts.get_model(
                authorization_round.policy_decision_ref,
                AggregatePolicyDecision,
            ).aggregate_digest
            == authorization_round.policy_decision_digest
        )
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_capability_expiry_bounds_every_stage_and_commit_permit(tmp_path: Path) -> None:
    harness = _make_harness(tmp_path)
    authority_deadline = harness.clock() + timedelta(seconds=30)
    harness.authority_snapshots.grant_expires_at = authority_deadline
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            stage = harness.store.get_stage_material(
                tenant_id=session.record.tenant_id,
                transaction_id=session.record.transaction_id,
            )
            lease = harness.store.get_worker_lease(
                tenant_id=session.record.tenant_id,
                transaction_id=session.record.transaction_id,
                lease_id=stage.lease_id,
            )
            inspection = harness.artifacts.get_model(
                stage.inspection_permit_ref,
                InspectionPermit,
            )
            stage_permit = harness.artifacts.get_model(stage.stage_permit_ref, StagePermit)
            assert stage.verification_permit_ref is not None
            staged_verification = harness.artifacts.get_model(
                stage.verification_permit_ref,
                VerificationPermit,
            )
            assert {
                lease.expires_at,
                inspection.deadline,
                stage_permit.deadline,
                staged_verification.deadline,
            } == {authority_deadline}
            committed = await session.commit()

        dispatch = harness.store.get_commit_dispatch(
            tenant_id=committed.tenant_id,
            transaction_id=committed.transaction_id,
        )
        precommit_inspection = harness.artifacts.get_model(
            dispatch.permit.precommit_inspection_permit_ref,
            InspectionPermit,
        )
        assert dispatch.committed_verification_permit_ref is not None
        committed_verification = harness.artifacts.get_model(
            dispatch.committed_verification_permit_ref,
            VerificationPermit,
        )
        assert {
            dispatch.permit.deadline,
            precommit_inspection.deadline,
            committed_verification.deadline,
        } == {authority_deadline}
        assert committed.authorization_round_id is not None
        authorization_round = harness.store.get_authorization_round(
            tenant_id=committed.tenant_id,
            controlled_transaction_id=committed.transaction_id,
            round_id=committed.authorization_round_id,
        )
        assert authorization_round.authority_valid_until == authority_deadline
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_capability_expiry_bounds_recovery_lease_and_permit(tmp_path: Path) -> None:
    harness = _make_harness(tmp_path)
    authority_deadline = harness.clock() + timedelta(seconds=30)
    harness.authority_snapshots.grant_expires_at = authority_deadline
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            pass
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(works) == 1
        assert works[0].permit is not None
        assert works[0].lease_id is not None
        lease = harness.store.get_worker_lease(
            tenant_id=works[0].tenant_id,
            transaction_id=works[0].transaction_id,
            lease_id=works[0].lease_id,
        )
        authorization_round = harness.store.get_authorization_round(
            tenant_id=works[0].tenant_id,
            controlled_transaction_id=works[0].transaction_id,
            round_id=works[0].authorization_round_id,
        )
        assert works[0].permit.deadline == authority_deadline
        assert lease.expires_at == authority_deadline
        assert authorization_round.authority_valid_until == authority_deadline
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_committed_outcome_event_and_receipt_survive_crash_reopen(
    tmp_path: Path,
) -> None:
    harness = _make_harness(
        tmp_path,
        crash_point=CoordinatorCrashPoint.AFTER_OUTCOME_CLASSIFIED,
    )
    database_path = tmp_path / "control.db"
    reopened_store: SQLiteEnforcedTransactionStore | None = None
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                await session.commit()

        assert session.record.state is TransactionState.COMMITTED
        dispatch_before = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        outcomes_before = harness.store.list_dispatch_outcomes(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        events_before = harness.store.list_enforced_transaction_events(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert dispatch_before.state is CommitDispatchState.COMMITTED
        assert dispatch_before.effect_receipt_ref is not None
        assert outcomes_before[-1].classification is ReconciliationOutcome.COMMITTED
        assert outcomes_before[-1].effect_receipt_ref == dispatch_before.effect_receipt_ref
        assert events_before[-1].target_state is TransactionState.COMMITTED

        receipt_ref = dispatch_before.effect_receipt_ref
        outcome_digest = outcomes_before[-1].outcome_digest
        event_digest = events_before[-1].event_digest
        event_count = len(events_before)
        harness.store.close()

        reopened_store, coordinator = _reopen_coordinator(harness, database_path)
        status = coordinator.status(session.record.tenant_id, session.record.transaction_id)
        outcomes_after = reopened_store.list_dispatch_outcomes(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        events_after = reopened_store.list_enforced_transaction_events(
            session.record.tenant_id,
            session.record.transaction_id,
        )

        assert status.record.state is TransactionState.COMMITTED
        assert status.dispatch is not None
        assert status.dispatch.state is CommitDispatchState.COMMITTED
        assert status.dispatch.effect_receipt_ref == receipt_ref
        reopened_receipt = harness.artifacts.get_model(receipt_ref, EffectReceipt)
        assert canonical_digest(reopened_receipt) == receipt_ref
        assert outcomes_after[-1].outcome_digest == outcome_digest
        assert outcomes_after[-1].classification is ReconciliationOutcome.COMMITTED
        assert outcomes_after[-1].effect_receipt_ref == receipt_ref
        assert events_after[-1].event_digest == event_digest
        assert events_after[-1].target_state is TransactionState.COMMITTED
        assert status.event_count == event_count == len(events_after)
    finally:
        if reopened_store is not None:
            reopened_store.close()
        else:
            harness.store.close()


@pytest.mark.asyncio
async def test_reopened_status_reconstructs_original_authority_context(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path)
    database_path = tmp_path / "control.db"
    reopened_store: SQLiteEnforcedTransactionStore | None = None
    try:
        session = await harness.coordinator.transaction(harness.request)
        await session.__aenter__()
        assert session.record.authorization_round_id is not None
        authorization_round = harness.store.get_authorization_round(
            tenant_id=session.record.tenant_id,
            controlled_transaction_id=session.record.transaction_id,
            round_id=session.record.authorization_round_id,
        )
        assert authorization_round.authority_context_ref is not None
        assert authorization_round.authority_decision_ref is not None
        harness.store.close()

        reopened_store, coordinator = _reopen_coordinator(
            harness,
            database_path,
            authority_audience="service:changed-after-restart",
        )
        status = coordinator.status(session.record.tenant_id, session.record.transaction_id)
        authority_context = harness.artifacts.get_model(
            authorization_round.authority_context_ref,
            AuthorityEvaluationContext,
        )
        authority_decision = harness.artifacts.get_model(
            authorization_round.authority_decision_ref,
            EnforcedAuthorityDecision,
        )
        assert status.record.state is TransactionState.READY_TO_COMMIT
        assert authority_context.audience == "service:agentkernel"
        assert canonical_digest(authority_context) == authority_decision.evaluation_context_digest
    finally:
        if reopened_store is not None:
            reopened_store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing", ErrorCode.EVIDENCE_UNAVAILABLE),
        ("tampered", ErrorCode.INTEGRITY_ERROR),
    ],
)
async def test_reopened_status_rejects_missing_or_tampered_authority_artifact(
    tmp_path: Path,
    mutation: str,
    expected_code: ErrorCode,
) -> None:
    harness = _make_harness(tmp_path)
    database_path = tmp_path / "control.db"
    reopened_store: SQLiteEnforcedTransactionStore | None = None
    try:
        session = await harness.coordinator.transaction(harness.request)
        await session.__aenter__()
        assert session.record.authorization_round_id is not None
        authorization_round = harness.store.get_authorization_round(
            tenant_id=session.record.tenant_id,
            controlled_transaction_id=session.record.transaction_id,
            round_id=session.record.authorization_round_id,
        )
        evidence_ref = (
            authorization_round.authority_snapshot_ref
            if mutation == "missing"
            else authorization_round.authority_context_ref
        )
        assert evidence_ref is not None
        artifact_path = _artifact_path(
            harness.artifacts.root,
            evidence_ref,
        )
        harness.store.close()
        if mutation == "missing":
            artifact_path.unlink()
        else:
            artifact_path.write_bytes(b"tampered-authority-context")

        reopened_store, coordinator = _reopen_coordinator(harness, database_path)
        with pytest.raises(AgentKernelError) as captured:
            coordinator.status(session.record.tenant_id, session.record.transaction_id)
        assert captured.value.code is expected_code
    finally:
        if reopened_store is not None:
            reopened_store.close()


@pytest.mark.asyncio
async def test_exact_retry_reports_existing_owner_without_resuming_or_redispatching(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path)
    try:
        session = await harness.coordinator.transaction(harness.request)
        assert not isinstance(session, EnforcedTransactionStatus)
        async with session:
            committed = await session.commit()
        replay = await harness.coordinator.transaction(harness.request)
        assert isinstance(replay, EnforcedTransactionStatus)
        assert committed.state is TransactionState.COMMITTED
        assert replay.record == committed
        assert replay.requested_record == committed
        assert replay.intent_disposition is IntentDisposition.SAME_TRANSACTION
        assert replay.owner_transaction_id == committed.transaction_id
        assert replay.effect_receipt == session.receipts.effect
        assert replay.dispatch is not None
        assert replay.dispatch.effect_receipt_ref == canonical_digest(replay.effect_receipt)
        assert not hasattr(replay, "commit")
        assert len(harness.target.dispatches) == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_committed_alias_returns_owner_receipt_without_commit_capability(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path)
    alias_proposal = harness.request.proposal.model_copy(
        update={
            "transaction_id": "transaction:coordinator-alias",
            "idempotency_key": "idempotency:transaction:coordinator-alias",
        }
    )
    alias_request = harness.request.model_copy(update={"proposal": alias_proposal})
    try:
        owner = await harness.coordinator.transaction(harness.request)
        assert not isinstance(owner, EnforcedTransactionStatus)
        async with owner:
            committed = await owner.commit()

        alias = await harness.coordinator.transaction(alias_request)
        assert isinstance(alias, EnforcedTransactionStatus)
        assert alias.record == committed
        assert alias.requested_record is not None
        assert alias.requested_record.transaction_id == alias_proposal.transaction_id
        assert alias.requested_record.state is TransactionState.REJECTED
        assert alias.intent_disposition is IntentDisposition.ALIAS_COMMITTED
        assert alias.owner_transaction_id == committed.transaction_id
        assert alias.effect_receipt == owner.receipts.effect
        assert alias.dispatch is not None
        assert alias.dispatch.effect_receipt_ref == canonical_digest(alias.effect_receipt)
        assert not hasattr(alias, "commit")
        assert len(harness.target.dispatches) == 1

        durable_alias = harness.coordinator.status(
            alias.requested_record.tenant_id,
            alias.requested_record.transaction_id,
        )
        assert durable_alias.record == alias.requested_record
        assert durable_alias.action is not None
        assert durable_alias.action.intent_hash == committed.intent_hash
        assert durable_alias.intent_disposition is IntentDisposition.ALIAS_COMMITTED
        assert durable_alias.owner_transaction_id == committed.transaction_id
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_active_alias_returns_read_only_owner_status_without_adapter_io(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path)
    alias_proposal = harness.request.proposal.model_copy(
        update={
            "transaction_id": "transaction:coordinator-active-alias",
            "idempotency_key": "idempotency:transaction:coordinator-active-alias",
        }
    )
    alias_request = harness.request.model_copy(update={"proposal": alias_proposal})
    owner = None
    try:
        owner = await harness.coordinator.transaction(harness.request)
        assert not isinstance(owner, EnforcedTransactionStatus)

        alias = await harness.coordinator.transaction(alias_request)
        assert isinstance(alias, EnforcedTransactionStatus)
        assert alias.record.transaction_id == owner.record.transaction_id
        assert alias.record.state is TransactionState.AUTHORIZED_TO_STAGE
        assert alias.requested_record is not None
        assert alias.requested_record.transaction_id == alias_proposal.transaction_id
        assert alias.requested_record.state is TransactionState.REJECTED
        assert alias.intent_disposition is IntentDisposition.ALIAS_ACTIVE
        assert alias.owner_transaction_id == owner.record.transaction_id
        assert alias.effect_receipt is None
        assert alias.dispatch is None
        assert not hasattr(alias, "commit")
        assert harness.target.dispatches == {}
        assert harness.target.state == {"before": "kept"}
    finally:
        if owner is not None and not isinstance(owner, EnforcedTransactionStatus):
            await owner.cancel()
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["tampered", "missing", "extra"])
async def test_status_rejects_corrupt_dispatch_outcome_chain(
    tmp_path: Path,
    mutation: str,
) -> None:
    harness = _make_harness(tmp_path)
    try:
        session = await harness.coordinator.transaction(harness.request)
        assert not isinstance(session, EnforcedTransactionStatus)
        async with session:
            committed = await session.commit()

        if mutation == "tampered":
            harness.store._connection.execute("DROP TRIGGER enforced_dispatch_outcomes_no_update")
            harness.store._connection.execute(
                "UPDATE enforced_dispatch_outcomes SET previous_outcome_digest = ? "
                "WHERE tenant_id = ? AND transaction_id = ? AND sequence = 1",
                (
                    canonical_digest({"forged": "predecessor"}),
                    committed.tenant_id,
                    committed.transaction_id,
                ),
            )
        elif mutation == "missing":
            harness.store._connection.execute("DROP TRIGGER enforced_dispatch_outcomes_no_delete")
            harness.store._connection.execute(
                "DELETE FROM enforced_dispatch_outcomes WHERE tenant_id = ? "
                "AND transaction_id = ? AND sequence = ("
                "SELECT MAX(sequence) FROM enforced_dispatch_outcomes "
                "WHERE tenant_id = ? AND transaction_id = ?)",
                (
                    committed.tenant_id,
                    committed.transaction_id,
                    committed.tenant_id,
                    committed.transaction_id,
                ),
            )
        else:
            harness.store._connection.execute(
                "INSERT INTO enforced_dispatch_outcomes("
                "tenant_id, transaction_id, intent_hash, owner_version, dispatch_id, "
                "sequence, outcome_id, source_state, target_state, classification, "
                "effect_receipt_ref, committed_verification_permit_digest, "
                "committed_verification_permit_ref, committed_verification_ref, "
                "no_effect_evidence_ref, evidence_refs_json, reason_code, "
                "previous_outcome_digest, outcome_digest, outcome_json, recorded_at) "
                "SELECT tenant_id, transaction_id, intent_hash, owner_version, dispatch_id, "
                "sequence + 100, ?, source_state, target_state, classification, "
                "effect_receipt_ref, committed_verification_permit_digest, "
                "committed_verification_permit_ref, committed_verification_ref, "
                "no_effect_evidence_ref, evidence_refs_json, reason_code, "
                "previous_outcome_digest, ?, outcome_json, recorded_at "
                "FROM enforced_dispatch_outcomes WHERE tenant_id = ? AND transaction_id = ? "
                "ORDER BY sequence LIMIT 1",
                (
                    "outcome:forged-extra",
                    canonical_digest({"forged": "outcome"}),
                    committed.tenant_id,
                    committed.transaction_id,
                ),
            )

        with pytest.raises(AgentKernelError) as captured:
            harness.coordinator.status(committed.tenant_id, committed.transaction_id)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_status_rejects_commit_history_after_dispatch_is_deleted(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path)
    try:
        session = await harness.coordinator.transaction(harness.request)
        assert not isinstance(session, EnforcedTransactionStatus)
        async with session:
            committed = await session.commit()

        harness.store._connection.execute("DROP TRIGGER enforced_dispatch_outcomes_no_delete")
        harness.store._connection.execute("DROP TRIGGER enforced_commit_dispatches_no_delete")
        harness.store._connection.execute(
            "DELETE FROM enforced_dispatch_outcomes WHERE tenant_id = ? AND transaction_id = ?",
            (committed.tenant_id, committed.transaction_id),
        )
        harness.store._connection.execute(
            "DELETE FROM enforced_commit_dispatches WHERE tenant_id = ? AND transaction_id = ?",
            (committed.tenant_id, committed.transaction_id),
        )

        with pytest.raises(AgentKernelError) as captured:
            harness.coordinator.status(committed.tenant_id, committed.transaction_id)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_status_validates_historical_staging_authorization_artifacts(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path)
    try:
        session = await harness.coordinator.transaction(harness.request)
        assert not isinstance(session, EnforcedTransactionStatus)
        async with session:
            committed = await session.commit()

        staging_row = harness.store._connection.execute(
            "SELECT round_id FROM enforced_authorization_rounds "
            "WHERE tenant_id = ? AND controlled_transaction_id = ? AND purpose = 'STAGING'",
            (committed.tenant_id, committed.transaction_id),
        ).fetchone()
        assert staging_row is not None
        staging_round = harness.store.get_authorization_round(
            tenant_id=committed.tenant_id,
            controlled_transaction_id=committed.transaction_id,
            round_id=str(staging_row["round_id"]),
        )
        assert staging_round.authority_snapshot_ref is not None
        _artifact_path(
            harness.artifacts.root,
            staging_round.authority_snapshot_ref,
        ).unlink()

        with pytest.raises(AgentKernelError) as captured:
            harness.coordinator.status(committed.tenant_id, committed.transaction_id)
        assert captured.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fault", "expected_code"),
    [
        ("missing", ErrorCode.EVIDENCE_UNAVAILABLE),
        ("tampered", ErrorCode.INTEGRITY_ERROR),
        ("unrelated", ErrorCode.INTEGRITY_ERROR),
        ("wrong_parent", ErrorCode.INTEGRITY_ERROR),
        ("future", ErrorCode.INTEGRITY_ERROR),
    ],
)
async def test_staged_verification_rejects_untrusted_adapter_observation(
    tmp_path: Path,
    fault: str,
    expected_code: ErrorCode,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_ObservationFaultAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _ObservationFaultAdapter)
    adapter.observation_fault = fault
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(AgentKernelError) as captured:
            await session.__aenter__()
        assert captured.value.code is expected_code
        assert session.record.state is TransactionState.ABORTED
        assert adapter.abort_stage_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_boundary", ["authority", "policy"])
async def test_coordinator_clock_rollback_fails_closed_across_provider_boundary(
    tmp_path: Path,
    provider_boundary: str,
) -> None:
    harness = _make_harness(tmp_path)
    if provider_boundary == "authority":
        harness.authority_snapshots.advance_after_snapshot = timedelta(microseconds=-1)
    else:
        harness.policy_inputs.advance_after_inputs = timedelta(microseconds=-1)
    try:
        with pytest.raises(AgentKernelError) as captured:
            await harness.coordinator.transaction(harness.request)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
        assert "clock moved backwards" in captured.value.message
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_crash_after_private_stage_before_return_is_discarded_from_allocated_record(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_CrashAfterPrivateStageAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _CrashAfterPrivateStageAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(RuntimeError, match="synthetic crash after private stage creation"):
            await session.__aenter__()
        stage = harness.store.get_stage_material(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert session.record.state is TransactionState.ABORTED
        assert stage.state is StageMaterialState.DISCARDED
        assert stage.staged_effect_ref is None
        assert len(work) == 1
        assert work[0].state is RecoveryWorkState.SUCCEEDED
        assert adapter.abort_stage_calls == 1
        observations: list[AdapterObservation] = []
        for evidence_ref in work[0].evidence_refs:
            try:
                observations.append(harness.artifacts.get_model(evidence_ref, AdapterObservation))
            except AgentKernelError:
                continue
        assert len(observations) == 1
        assert stage.discard_evidence_ref == canonical_digest(observations[0])
        assert observations[0].subject_ref == work[0].target_evidence_ref
        assert observations[0].subject_authority_ref == work[0].target_evidence_ref
        assert observations[0].operation_permit_ref == work[0].permit_ref
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_committed_verification_rejects_wrong_dispatch_generation(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_WrongCommittedGenerationAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            with pytest.raises(AgentKernelError) as captured:
                await session.commit()
            assert captured.value.code is ErrorCode.INTEGRITY_ERROR
        assert session.record.state is TransactionState.IN_DOUBT
        assert harness.target.state["answer"] == "42"
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert dispatch.state.value == "IN_DOUBT"
        assert dispatch.committed_verification_ref is None
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_context_exit_discards_private_stage_and_aborts(tmp_path: Path) -> None:
    harness = _make_harness(tmp_path)
    original = dict(harness.target.state)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            ready_record = session.record
            assert ready_record.state is TransactionState.READY_TO_COMMIT
        assert session.record.state is TransactionState.ABORTED
        assert harness.target.state == original
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(works) == 1
        assert works[0].state is RecoveryWorkState.SUCCEEDED
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_late_discard_is_review_required_and_never_redispatched(tmp_path: Path) -> None:
    harness = _make_harness(tmp_path, adapter_type=_LateRecoveryAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _LateRecoveryAdapter)
    adapter.test_clock = harness.clock
    original = dict(harness.target.state)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            pass
        stage = harness.store.get_stage_material(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert session.record.state is TransactionState.RECOVERY_FAILED
        assert stage.state is StageMaterialState.DISCARD_FAILED
        assert harness.target.state == original
        assert len(works) == 1
        assert works[0].state is RecoveryWorkState.REVIEW_REQUIRED
        assert adapter.abort_stage_calls == 1

        repeated = await _restart_coordinator(harness).recover_once(session.record.tenant_id)
        assert repeated.processed == 0
        assert adapter.abort_stage_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_expired_running_recovery_is_not_reclaimed_or_dispatched(
    tmp_path: Path,
) -> None:
    harness = _make_harness(
        tmp_path,
        adapter_type=_ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_CLAIMED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _ControlledVerificationAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                pass
        running = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(running) == 1
        assert running[0].state is RecoveryWorkState.RUNNING
        assert adapter.abort_stage_calls == 0

        harness.clock.advance(timedelta(minutes=2))
        recovery = _restart_coordinator(harness, worker_id="worker:no-reclaim")
        result = await recovery.recover_once(session.record.tenant_id)
        assert result.processed == 1
        assert len(result.failures) == 1
        assert result.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert (
            result.failures[0].reason_code
            == "EVIDENCE_UNAVAILABLE:RECOVERY_LEASE_EXPIRED_WITH_UNKNOWN_OUTCOME"
        )
        assert result.failures[0].evidence_ref is None
        reviewed = harness.store.get_recovery_work(
            tenant_id=running[0].tenant_id,
            transaction_id=running[0].transaction_id,
            recovery_id=running[0].recovery_id,
        )
        assert reviewed.state is RecoveryWorkState.REVIEW_REQUIRED
        assert adapter.abort_stage_calls == 0

        repeated = await recovery.recover_once(session.record.tenant_id)
        assert repeated.processed == 0
        assert adapter.abort_stage_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_explicit_cancel_releases_stage_lease_and_aborts_once(tmp_path: Path) -> None:
    harness = _make_harness(tmp_path, adapter_type=_ControlledVerificationAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _ControlledVerificationAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            cancelled = await session.cancel()
        assert cancelled.state is TransactionState.ABORTED
        assert adapter.abort_stage_calls == 1
        stage = harness.store.get_stage_material(
            tenant_id=cancelled.tenant_id,
            transaction_id=cancelled.transaction_id,
        )
        lease = harness.store.get_worker_lease(
            tenant_id=cancelled.tenant_id,
            transaction_id=cancelled.transaction_id,
            lease_id=stage.lease_id,
        )
        assert lease.released_at is not None
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "expected_code"),
    [
        (VerificationStatus.FAIL, ErrorCode.VERIFICATION_FAILED),
        (VerificationStatus.UNKNOWN, ErrorCode.VERIFICATION_UNKNOWN),
        (VerificationStatus.ERROR, ErrorCode.VERIFICATION_UNKNOWN),
    ],
)
async def test_staged_nonpass_is_distinct_and_discards_exactly_once(
    tmp_path: Path,
    status: VerificationStatus,
    expected_code: ErrorCode,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_ControlledVerificationAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _ControlledVerificationAdapter)
    adapter.staged_status = status
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(AgentKernelError) as captured:
            async with session:
                pytest.fail("non-PASS staged verification entered the transaction body")
        assert captured.value.code is expected_code
        assert session.record.state is TransactionState.ABORTED
        assert adapter.abort_stage_calls == 1
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(works) == 1
        assert works[0].state is RecoveryWorkState.SUCCEEDED

        repeated = await _restart_coordinator(harness).recover_once(session.record.tenant_id)
        assert repeated.processed == 0
        assert adapter.abort_stage_calls == 1
        assert (
            len(
                harness.store.list_recovery_work(
                    tenant_id=session.record.tenant_id,
                    transaction_id=session.record.transaction_id,
                )
            )
            == 1
        )
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [VerificationStatus.UNKNOWN, VerificationStatus.ERROR],
)
async def test_committed_inconclusive_verification_stays_in_doubt_without_rollback(
    tmp_path: Path,
    status: VerificationStatus,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_ControlledVerificationAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _ControlledVerificationAdapter)
    adapter.committed_status = status
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            with pytest.raises(AgentKernelError) as captured:
                await session.commit()
            assert captured.value.code is ErrorCode.VERIFICATION_UNKNOWN
        assert session.record.state is TransactionState.IN_DOUBT
        assert adapter.rollback_calls == 0
        assert harness.target.state["answer"] == "42"
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert dispatch.state.value == "IN_DOUBT"
        assert dispatch.effect_receipt_ref is not None
        assert dispatch.committed_verification_ref is None
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_committed_failed_verification_rolls_back_exactly_once(tmp_path: Path) -> None:
    harness = _make_harness(tmp_path, adapter_type=_ControlledVerificationAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _ControlledVerificationAdapter)
    adapter.committed_status = VerificationStatus.FAIL
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            with pytest.raises(AgentKernelError) as captured:
                await session.commit()
            assert captured.value.code is ErrorCode.VERIFICATION_FAILED
        assert session.record.state is TransactionState.ROLLED_BACK
        assert adapter.rollback_calls == 1
        assert harness.target.state == {"before": "kept"}
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(works) == 1
        assert works[0].state is RecoveryWorkState.SUCCEEDED
        repeated = await _restart_coordinator(harness).recover_once(session.record.tenant_id)
        assert repeated.processed == 0
        assert adapter.rollback_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_late_rollback_is_review_required_even_when_effect_was_restored(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_LateRecoveryAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _LateRecoveryAdapter)
    adapter.test_clock = harness.clock
    adapter.committed_status = VerificationStatus.FAIL
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            with pytest.raises(AgentKernelError) as captured:
                await session.commit()
            assert captured.value.code is ErrorCode.VERIFICATION_FAILED
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert session.record.state is TransactionState.RECOVERY_FAILED
        assert harness.target.state == {"before": "kept"}
        assert len(works) == 1
        assert works[0].state is RecoveryWorkState.REVIEW_REQUIRED
        assert adapter.rollback_calls == 1

        repeated = await _restart_coordinator(harness).recover_once(session.record.tenant_id)
        assert repeated.processed == 0
        assert adapter.rollback_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_late_compensation_is_review_required_even_when_effect_was_compensated(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_LateCompensatingAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _LateCompensatingAdapter)
    adapter.test_clock = harness.clock
    adapter.committed_status = VerificationStatus.FAIL
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            with pytest.raises(AgentKernelError) as captured:
                await session.commit()
            assert captured.value.code is ErrorCode.VERIFICATION_FAILED
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert session.record.state is TransactionState.COMPENSATION_FAILED
        assert harness.target.state == {"before": "kept"}
        assert len(works) == 1
        assert works[0].kind is RecoveryWorkKind.COMPENSATE
        assert works[0].state is RecoveryWorkState.REVIEW_REQUIRED
        assert adapter.compensation_calls == 1

        repeated = await _restart_coordinator(harness).recover_once(session.record.tenant_id)
        assert repeated.processed == 0
        assert adapter.compensation_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_malformed_post_effect_receipt_is_forensic_only_and_in_doubt(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_MalformedReceiptAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _MalformedReceiptAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            with pytest.raises(AgentKernelError) as captured:
                await session.commit()
            assert captured.value.code is ErrorCode.INTEGRITY_ERROR
        assert session.record.state is TransactionState.IN_DOUBT
        assert adapter.malformed_receipt is not None
        malformed_ref = canonical_digest(adapter.malformed_receipt)
        assert harness.artifacts.get(malformed_ref)
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert dispatch.effect_receipt_ref is None
        assert malformed_ref not in dispatch.outcome_evidence_refs
        assert dispatch.unavailable_record_digest is not None
        unavailable = harness.store.get_dispatch_evidence_unavailable(
            tenant_id=dispatch.tenant_id,
            transaction_id=dispatch.transaction_id,
            dispatch_id=dispatch.dispatch_id,
        )
        assert unavailable is not None
        assert unavailable.record_digest == dispatch.unavailable_record_digest
        assert unavailable.reason_code == "EVIDENCE_UNAVAILABLE:COMMIT_OUTCOME_UNKNOWN"
        assert malformed_ref in unavailable.supporting_refs
        assert adapter.rollback_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_identity_validation_failure_is_rejected_after_durable_ingress(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path)
    mismatched = harness.request.model_copy(
        update={"proposal": harness.request.proposal.model_copy(update={"goal_id": "goal:other"})}
    )
    try:
        with pytest.raises(AgentKernelError) as captured:
            await harness.coordinator.transaction(mismatched)
        assert captured.value.code is ErrorCode.AUTHORITY_MISSING
        record = harness.store.get_enforced_transaction(
            tenant_id=harness.request.presented_context.tenant_id,
            transaction_id=harness.request.proposal.transaction_id,
        )
        assert record.state is TransactionState.REJECTED
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_expired_ingress_stops_before_unvalidated_identity(tmp_path: Path) -> None:
    harness = _make_harness(tmp_path)
    expired = harness.request.model_copy(
        update={
            "proposal": harness.request.proposal.model_copy(update={"deadline": harness.clock()})
        }
    )
    try:
        with pytest.raises(AgentKernelError) as captured:
            await harness.coordinator.transaction(expired)
        assert captured.value.code is ErrorCode.DEADLINE_EXCEEDED
        with pytest.raises(AgentKernelError) as missing:
            harness.store.get_enforced_transaction(
                tenant_id=expired.presented_context.tenant_id,
                transaction_id=expired.proposal.transaction_id,
            )
        assert missing.value.code is ErrorCode.VALIDATION_ERROR
        assert not harness.target.dispatches
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_capability_expiry_crossed_by_authority_provider_fails_before_persistence(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path)
    harness.authority_snapshots.grant_expires_at = harness.clock() + timedelta(seconds=1)
    harness.authority_snapshots.advance_after_snapshot = timedelta(seconds=2)
    try:
        with pytest.raises(AgentKernelError) as captured:
            await harness.coordinator.transaction(harness.request)
        assert captured.value.code is ErrorCode.DEADLINE_EXCEEDED
        record = harness.store.get_enforced_transaction(
            tenant_id=harness.request.presented_context.tenant_id,
            transaction_id=harness.request.proposal.transaction_id,
        )
        assert record.state is TransactionState.ABORTED
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_capability_expiry_crossed_by_policy_provider_fails_before_persistence(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path)
    harness.authority_snapshots.grant_expires_at = harness.clock() + timedelta(seconds=1)
    harness.policy_inputs.advance_after_inputs = timedelta(seconds=2)
    try:
        with pytest.raises(AgentKernelError) as captured:
            await harness.coordinator.transaction(harness.request)
        assert captured.value.code is ErrorCode.DEADLINE_EXCEEDED
        record = harness.store.get_enforced_transaction(
            tenant_id=harness.request.presented_context.tenant_id,
            transaction_id=harness.request.proposal.transaction_id,
        )
        assert record.state is TransactionState.ABORTED
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_crash_after_dispatch_is_reconciled_without_redispatch(tmp_path: Path) -> None:
    harness = _make_harness(
        tmp_path,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_CALL,
    )
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                await session.commit()
        assert harness.target.state["answer"] == "42"
        assert session.record.state is TransactionState.COMMITTING
        recovery = await _stop_dispatch_before_explicit_resume(harness, session)
        resumed = await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert resumed.record.state is TransactionState.COMMITTED
        assert len(harness.target.dispatches) == 1
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert dispatch.committed_verification_permit_ref is not None
        verification_permit = harness.artifacts.get_model(
            dispatch.committed_verification_permit_ref,
            VerificationPermit,
        )
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(works) == 1
        assert works[0].permit is not None
        assert works[0].permit_ref is not None
        assert verification_permit.authority_permit_ref == works[0].permit_ref
        assert verification_permit.authority_permit_digest == works[0].permit.permit_digest
        assert verification_permit.subject_permit_ref == dispatch.permit_ref
        assert verification_permit.subject_permit_digest == dispatch.permit.permit_digest
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_timeout_after_durable_effect_reconciles_without_second_commit_or_dispatch(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_TimeoutAfterDurableEffectAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _TimeoutAfterDurableEffectAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(
            TimeoutError,
            match="lost acknowledgement after durable effect",
        ):
            async with session:
                await session.commit()

        assert session.record.state is TransactionState.IN_DOUBT
        assert adapter.applied_receipt is not None
        assert adapter.commit_calls == 1
        assert adapter.reconcile_calls == 0
        assert harness.target.state == {"before": "kept", "answer": "42"}
        assert harness.target.version == 1
        assert len(harness.target.dispatches) == 1

        unknown_dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        unknown_outcomes = harness.store.list_dispatch_outcomes(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert unknown_dispatch.state is CommitDispatchState.IN_DOUBT
        assert unknown_dispatch.effect_receipt_ref is None
        assert unknown_outcomes[-1].classification is ReconciliationOutcome.UNKNOWN
        assert unknown_outcomes[-1].effect_receipt_ref is None

        recovery = _restart_coordinator(harness)
        recovered = await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )

        assert recovered.record.state is TransactionState.COMMITTED
        assert adapter.commit_calls == 1
        assert adapter.reconcile_calls == 1
        assert harness.target.state == {"before": "kept", "answer": "42"}
        assert harness.target.version == 1
        assert len(harness.target.dispatches) == 1

        committed_dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        committed_outcomes = harness.store.list_dispatch_outcomes(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        receipt_ref = canonical_digest(adapter.applied_receipt)
        assert committed_dispatch.state is CommitDispatchState.COMMITTED
        assert committed_dispatch.effect_receipt_ref == receipt_ref
        assert harness.artifacts.get_model(receipt_ref, EffectReceipt) == adapter.applied_receipt
        assert committed_outcomes[-1].classification is ReconciliationOutcome.COMMITTED
        assert committed_outcomes[-1].effect_receipt_ref == receipt_ref

        repeated = await recovery.recover_once(session.record.tenant_id)
        assert repeated.processed == 0
        assert not repeated.failures
        assert adapter.commit_calls == 1
        assert adapter.reconcile_calls == 1
        assert len(harness.target.dispatches) == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_cancel_between_coordinator_and_adapter_dispatch_recovers_truthful_no_effect(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_QuiescentCommitBarrierAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _QuiescentCommitBarrierAdapter)
    adapter.commit_barrier = "commit.before_dispatch"
    try:
        session = await harness.coordinator.transaction(harness.request)

        async def commit_in_scope() -> None:
            async with session:
                await session.commit()

        commit_task = asyncio.create_task(commit_in_scope())
        assert await asyncio.to_thread(adapter.commit_barrier_entered.wait, 1)
        durable_dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert durable_dispatch.state is CommitDispatchState.DISPATCHED
        assert session.record.state is TransactionState.COMMITTING
        assert harness.target.dispatches == {}
        assert harness.target.state == {"before": "kept"}

        commit_task.cancel()
        assert await asyncio.to_thread(adapter.commit_cancellation_seen.wait, 1)
        assert not commit_task.done()
        assert (
            harness.store.get_commit_dispatch(
                tenant_id=session.record.tenant_id,
                transaction_id=session.record.transaction_id,
            ).state
            is CommitDispatchState.DISPATCHED
        )

        adapter.commit_barrier_release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(commit_task, timeout=1)

        assert session.record.state is TransactionState.IN_DOUBT
        assert harness.target.dispatches == {}
        assert harness.target.state == {"before": "kept"}
        outcomes = harness.store.list_dispatch_outcomes(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert outcomes[-1].target_state is CommitDispatchState.IN_DOUBT
        assert outcomes[-1].classification is ReconciliationOutcome.UNKNOWN
        assert outcomes[-1].reason_code == "EVIDENCE_UNAVAILABLE:CANCELLED_AFTER_DISPATCH"

        recovery = _restart_coordinator(harness)
        recovered = await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert recovered.record.state is TransactionState.ABORTED
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert dispatch.state is CommitDispatchState.NO_EFFECT
        assert dispatch.no_effect_evidence_ref is not None
        assert harness.target.dispatches == {}
        assert harness.target.state == {"before": "kept"}
        assert harness.target.version == 0
    finally:
        adapter.commit_barrier_release.set()
        harness.store.close()


@pytest.mark.asyncio
async def test_repeated_cancel_after_adapter_dispatch_waits_then_recovers_exactly_once(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_QuiescentCommitBarrierAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _QuiescentCommitBarrierAdapter)
    adapter.commit_barrier = "commit.after_prepared"
    try:
        session = await harness.coordinator.transaction(harness.request)

        async def commit_in_scope() -> None:
            async with session:
                await session.commit()

        commit_task = asyncio.create_task(commit_in_scope())
        assert await asyncio.to_thread(adapter.commit_barrier_entered.wait, 1)
        assert session.record.state is TransactionState.COMMITTING
        assert harness.target.state == {"before": "kept"}

        commit_task.cancel()
        assert await asyncio.to_thread(adapter.commit_cancellation_seen.wait, 1)
        commit_task.cancel()
        await asyncio.sleep(0)
        assert not commit_task.done()
        assert session.record.state is TransactionState.COMMITTING

        adapter.commit_barrier_release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(commit_task, timeout=1)

        assert session.record.state is TransactionState.IN_DOUBT
        assert harness.target.state == {"before": "kept", "answer": "42"}
        assert harness.target.version == 1
        assert len(harness.target.dispatches) == 1
        outcomes = harness.store.list_dispatch_outcomes(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert outcomes[-1].target_state is CommitDispatchState.IN_DOUBT
        assert outcomes[-1].classification is ReconciliationOutcome.UNKNOWN
        assert outcomes[-1].reason_code == "EVIDENCE_UNAVAILABLE:CANCELLED_AFTER_DISPATCH"

        recovery = _restart_coordinator(harness)
        recovered = await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert recovered.record.state is TransactionState.COMMITTED
        assert harness.target.state == {"before": "kept", "answer": "42"}
        assert harness.target.version == 1
        assert len(harness.target.dispatches) == 1

        repeated = await recovery.recover_once(session.record.tenant_id)
        assert not repeated.failures
        assert repeated.processed == 0
        assert harness.target.version == 1
        assert len(harness.target.dispatches) == 1
        final_outcomes = harness.store.list_dispatch_outcomes(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert (
            sum(
                outcome.classification is ReconciliationOutcome.COMMITTED
                for outcome in final_outcomes
            )
            == 1
        )
    finally:
        adapter.commit_barrier_release.set()
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "crash_point",
    [
        CoordinatorCrashPoint.AFTER_STAGING_LEASE_ACQUIRED,
        CoordinatorCrashPoint.AFTER_STAGE_CALL,
        CoordinatorCrashPoint.AFTER_EXECUTE_CALL,
        CoordinatorCrashPoint.AFTER_STAGE_VERIFIED,
        CoordinatorCrashPoint.AFTER_READY_TO_COMMIT,
    ],
)
async def test_predispatch_crash_boundaries_recover_after_fence_expiry(
    tmp_path: Path,
    crash_point: CoordinatorCrashPoint,
) -> None:
    harness = _make_harness(
        tmp_path,
        adapter_type=_ControlledVerificationAdapter,
        crash_point=crash_point,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _ControlledVerificationAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                pytest.fail("crash point did not interrupt predispatch work")
        assert harness.target.state == {"before": "kept"}

        harness.clock.advance(timedelta(minutes=1, microseconds=1))
        result = await _restart_coordinator(harness).recover_once(session.record.tenant_id)
        assert not result.failures
        assert result.statuses[0].record.state is TransactionState.ABORTED
        assert harness.target.state == {"before": "kept"}
        with pytest.raises(AgentKernelError) as missing:
            harness.store.get_commit_dispatch(
                tenant_id=session.record.tenant_id,
                transaction_id=session.record.transaction_id,
            )
        assert missing.value.code is ErrorCode.VALIDATION_ERROR
        assert adapter.abort_stage_calls <= 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_recovery_scanner_isolates_one_candidate_failure_and_continues(
    tmp_path: Path,
) -> None:
    harness = _make_harness(tmp_path, adapter_type=_FailOneDiscardAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _FailOneDiscardAdapter)
    second_proposal = harness.request.proposal.model_copy(
        update={
            "transaction_id": "transaction:coordinator-second",
            "arguments": {"values": {"answer": "43"}},
            "idempotency_key": "idempotency:transaction:coordinator-second",
        }
    )
    second_request = harness.request.model_copy(update={"proposal": second_proposal})
    try:
        first = await harness.coordinator.transaction(harness.request)
        await first.__aenter__()
        first_stage = harness.store.get_stage_material(
            tenant_id=first.record.tenant_id,
            transaction_id=first.record.transaction_id,
        )
        adapter.fail_stage_id = first_stage.stage_id

        second = await harness.coordinator.transaction(second_request)
        await second.__aenter__()
        harness.clock.advance(timedelta(minutes=1, microseconds=1))

        result = await _restart_coordinator(harness).recover_once(first.record.tenant_id)
        assert result.scanned == 2
        assert result.processed == 2
        assert len(result.failures) == 1
        assert result.failures[0].transaction_id == first.record.transaction_id
        assert harness.artifacts.get(result.failures[0].evidence_ref)
        states = {status.record.transaction_id: status.record.state for status in result.statuses}
        assert states[first.record.transaction_id] is TransactionState.RECOVERY_FAILED
        assert states[second.record.transaction_id] is TransactionState.ABORTED
        assert adapter.abort_stage_calls == 2
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_recovery_limit_does_not_starve_later_work_behind_typed_stop(
    tmp_path: Path,
) -> None:
    harness = _make_harness(
        tmp_path,
        transaction_id="transaction:a-blocked",
        adapter_type=_SequencedReconciliationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_CALL,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _SequencedReconciliationAdapter)
    adapter.reconcile_statuses = [ReconcileStatus.UNKNOWN]
    try:
        blocked = await harness.coordinator.transaction(harness.request)
        assert not isinstance(blocked, EnforcedTransactionStatus)
        with pytest.raises(CoordinatorInjectedCrash):
            async with blocked:
                await blocked.commit()

        first_recovery = _restart_coordinator(
            harness,
            max_reconciliation_attempts=1,
        )
        await _stop_dispatch_before_explicit_resume(
            harness,
            blocked,
            coordinator=first_recovery,
        )
        first = await first_recovery.resume_dispatch_reconciliation(
            blocked.record.tenant_id,
            blocked.record.transaction_id,
        )
        assert first.record.state is TransactionState.IN_DOUBT
        blocked_work = harness.store.list_recovery_work(
            tenant_id=blocked.record.tenant_id,
            transaction_id=blocked.record.transaction_id,
        )
        assert blocked_work[-1].state is RecoveryWorkState.REVIEW_REQUIRED

        actionable_proposal = harness.request.proposal.model_copy(
            update={
                "transaction_id": "transaction:z-actionable",
                "arguments": {"values": {"answer": "43"}},
                "idempotency_key": "idempotency:transaction:z-actionable",
            }
        )
        actionable_request = harness.request.model_copy(update={"proposal": actionable_proposal})
        crashing = _restart_coordinator(
            harness,
            worker_id="worker:second-dispatch",
            crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
        )
        actionable = await crashing.transaction(actionable_request)
        assert not isinstance(actionable, EnforcedTransactionStatus)
        with pytest.raises(CoordinatorInjectedCrash):
            async with actionable:
                await actionable.commit()
        assert actionable.record.state is TransactionState.COMMITTING
        assert len(harness.target.dispatches) == 1

        recovery = _restart_coordinator(harness, worker_id="worker:fair-recovery")
        result = await recovery.recover_once(blocked.record.tenant_id, limit=1)
        assert result.scanned == 1
        assert result.processed == 1
        assert len(result.failures) == 1
        assert result.failures[0].transaction_id == actionable.record.transaction_id
        assert result.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert (
            result.failures[0].reason_code == "EVIDENCE_UNAVAILABLE:PROCESS_RESTART_AFTER_DISPATCH"
        )
        states = {status.record.transaction_id: status.record.state for status in result.statuses}
        assert states[actionable.record.transaction_id] is TransactionState.IN_DOUBT
        assert (
            harness.store.get_enforced_transaction(
                blocked.record.tenant_id,
                blocked.record.transaction_id,
            ).state
            is TransactionState.IN_DOUBT
        )
        assert result.remaining == 0
        assert len(harness.target.dispatches) == 1

        resumed = await recovery.resume_dispatch_reconciliation(
            actionable.record.tenant_id,
            actionable.record.transaction_id,
        )
        assert resumed.record.state is TransactionState.ABORTED

        bounded = await recovery.recover_once(blocked.record.tenant_id, limit=1)
        assert bounded.processed == 0
        assert bounded.scanned == 0
        assert bounded.remaining == 0
        assert len(harness.target.dispatches) == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_real_process_kill_after_pre_effect_dispatch_reopens_without_redispatch(
    tmp_path: Path,
) -> None:
    process = multiprocessing.get_context("spawn").Process(
        target=_kill_process_after_durable_dispatch,
        args=(str(tmp_path),),
    )
    process.start()
    process.join(timeout=30)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
        pytest.fail("coordinator crash-injection child did not terminate")
    assert process.exitcode == _PROCESS_CRASH_EXIT_CODE

    restarted = _make_harness(tmp_path)
    try:
        recovery = _restart_coordinator(restarted, worker_id="worker:post-process-restart")
        result = await recovery.recover_once("tenant:coordinator")
        assert len(result.failures) == 1
        assert (
            result.failures[0].reason_code == "EVIDENCE_UNAVAILABLE:PROCESS_RESTART_AFTER_DISPATCH"
        )
        assert result.processed == 1
        assert result.statuses[0].record.state is TransactionState.IN_DOUBT
        assert (
            restarted.store.get_enforced_transaction(
                "tenant:coordinator",
                "transaction:coordinator",
            ).state
            is TransactionState.IN_DOUBT
        )
        dispatch = restarted.store.get_commit_dispatch(
            tenant_id="tenant:coordinator",
            transaction_id="transaction:coordinator",
        )
        assert dispatch.state is CommitDispatchState.IN_DOUBT
        assert dispatch.unavailable_record_digest is not None
        works = restarted.store.list_recovery_work(
            tenant_id="tenant:coordinator",
            transaction_id="transaction:coordinator",
        )
        assert not works

        with pytest.raises(AgentKernelError) as captured:
            await recovery.resume_dispatch_reconciliation(
                "tenant:coordinator",
                "transaction:coordinator",
            )
        assert captured.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        assert (
            restarted.store.get_enforced_transaction(
                "tenant:coordinator",
                "transaction:coordinator",
            ).state
            is TransactionState.RECOVERY_FAILED
        )
        dispatch = restarted.store.get_commit_dispatch(
            tenant_id="tenant:coordinator",
            transaction_id="transaction:coordinator",
        )
        assert dispatch.state is CommitDispatchState.NO_EFFECT
        works = restarted.store.list_recovery_work(
            tenant_id="tenant:coordinator",
            transaction_id="transaction:coordinator",
        )
        assert len(works) == 2
        by_kind = {work.kind: work for work in works}
        assert by_kind[RecoveryWorkKind.RECONCILE_DISPATCH].state is RecoveryWorkState.SUCCEEDED
        discard = by_kind[RecoveryWorkKind.DISCARD_STAGING]
        assert discard.state is RecoveryWorkState.FAILED
        assert discard.reason_code == ErrorCode.EVIDENCE_UNAVAILABLE.value
        assert restarted.target.dispatches == {}
    finally:
        restarted.store.close()


@pytest.mark.asyncio
async def test_late_reconciliation_closes_attempt_without_retry_or_redispatch(
    tmp_path: Path,
) -> None:
    harness = _make_harness(
        tmp_path,
        adapter_type=_LateRecoveryAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_CALL,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _LateRecoveryAdapter)
    adapter.test_clock = harness.clock
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                await session.commit()

        recovery = await _stop_dispatch_before_explicit_resume(harness, session)
        result = await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert result.record.state is TransactionState.IN_DOUBT
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(works) == 1
        assert works[0].state is RecoveryWorkState.REVIEW_REQUIRED
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=works[0].tenant_id,
            transaction_id=works[0].transaction_id,
            recovery_id=works[0].recovery_id,
            attempt=works[0].attempt,
        )
        assert attempt.outcome is not None
        assert attempt.outcome.value == "UNKNOWN"
        assert attempt.next_attempt_not_before is None
        assert adapter.reconcile_calls == 1
        assert len(harness.target.dispatches) == 1

        repeated = await recovery.recover_once(session.record.tenant_id)
        assert repeated.processed == 0
        assert adapter.reconcile_calls == 1
        assert len(harness.target.dispatches) == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_unknown_reconciliation_honors_backoff_then_commits_successor(
    tmp_path: Path,
) -> None:
    harness = _make_harness(
        tmp_path,
        adapter_type=_SequencedReconciliationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_CALL,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _SequencedReconciliationAdapter)
    adapter.reconcile_statuses = [ReconcileStatus.UNKNOWN, ReconcileStatus.COMMITTED]
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                await session.commit()
        recovery = await _stop_dispatch_before_explicit_resume(harness, session)

        first = await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert first.record.state is TransactionState.IN_DOUBT
        first_work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(first_work) == 1
        assert first_work[0].state is RecoveryWorkState.RETRY_SCHEDULED
        assert first_work[0].recovery_ordinal == 1

        early = await recovery.recover_once(session.record.tenant_id)
        assert early.processed == 0
        assert not early.failures
        projection = harness.store.get_transaction_projection(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert recovery._recovery_terminal_failure(projection) is None
        assert adapter.reconcile_calls == 1

        harness.clock.advance(timedelta(seconds=2))
        second = await recovery.recover_once(session.record.tenant_id)
        assert not second.failures
        assert second.statuses[0].record.state is TransactionState.COMMITTED
        lineage = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert [work.recovery_ordinal for work in lineage] == [1, 2]
        assert lineage[0].state is RecoveryWorkState.RETRIED
        assert lineage[1].state is RecoveryWorkState.SUCCEEDED
        assert lineage[1].predecessor_recovery_id == lineage[0].recovery_id
        assert lineage[1].root_recovery_id == lineage[0].root_recovery_id
        assert lineage[1].recovery_id != lineage[0].recovery_id
        assert adapter.reconcile_calls == 2
        assert len(harness.target.dispatches) == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_reconciliation_attempt_limit_cannot_be_bypassed_by_repeated_scans(
    tmp_path: Path,
) -> None:
    harness = _make_harness(
        tmp_path,
        adapter_type=_SequencedReconciliationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_CALL,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _SequencedReconciliationAdapter)
    adapter.reconcile_statuses = [ReconcileStatus.UNKNOWN, ReconcileStatus.UNKNOWN]
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                await session.commit()
        recovery = _restart_coordinator(harness, max_reconciliation_attempts=2)
        await _stop_dispatch_before_explicit_resume(
            harness,
            session,
            coordinator=recovery,
        )
        await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        harness.clock.advance(timedelta(seconds=2))
        limited = await recovery.recover_once(session.record.tenant_id)
        assert len(limited.failures) == 1
        assert limited.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert limited.failures[0].reason_code == "RECONCILIATION_UNKNOWN"
        assert limited.failures[0].evidence_ref is not None
        assert harness.artifacts.get(limited.failures[0].evidence_ref)
        assert limited.statuses[0].record.state is TransactionState.IN_DOUBT
        lineage = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(lineage) == 2
        assert lineage[-1].recovery_ordinal == 2
        assert lineage[-1].state is RecoveryWorkState.REVIEW_REQUIRED

        for _ in range(3):
            harness.clock.advance(timedelta(minutes=1))
            repeated = await recovery.recover_once(session.record.tenant_id)
            assert repeated.processed == 0
            assert not repeated.failures
        assert adapter.reconcile_calls == 2
        assert (
            len(
                harness.store.list_recovery_work(
                    tenant_id=session.record.tenant_id,
                    transaction_id=session.record.transaction_id,
                )
            )
            == 2
        )
        assert len(harness.target.dispatches) == 1

        projection = harness.store.get_transaction_projection(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        terminal = recovery._recovery_terminal_failure(projection)
        assert terminal is not None
        assert terminal.evidence_ref == limited.failures[0].evidence_ref
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_reconciliation_backoff_past_absolute_deadline_requires_review(
    tmp_path: Path,
) -> None:
    harness = _make_harness(
        tmp_path,
        adapter_type=_SequencedReconciliationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_CALL,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _SequencedReconciliationAdapter)
    adapter.reconcile_statuses = [ReconcileStatus.UNKNOWN]
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                await session.commit()
        recovery = _restart_coordinator(
            harness,
            max_reconciliation_attempts=3,
            recovery_deadline=timedelta(seconds=30),
            reconciliation_backoff=timedelta(minutes=1),
        )
        await _stop_dispatch_before_explicit_resume(
            harness,
            session,
            coordinator=recovery,
        )
        result = await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert result.record.state is TransactionState.IN_DOUBT
        lineage = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(lineage) == 1
        assert lineage[0].state is RecoveryWorkState.REVIEW_REQUIRED
        harness.clock.advance(timedelta(minutes=2))
        repeated = await recovery.recover_once(session.record.tenant_id)
        assert repeated.processed == 0
        assert adapter.reconcile_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_policy_inputs_reject_duplicate_masking(tmp_path: Path) -> None:
    harness = _make_harness(tmp_path)
    try:
        session = await harness.coordinator.transaction(harness.request)
        supplied = harness.policy_inputs.last_inputs
        assert supplied is not None
        with pytest.raises(ValueError, match="sorted and unique"):
            PolicyEvaluationInputs(
                snapshot=supplied.snapshot,
                layers=(supplied.layers[0], supplied.layers[0]),
                resources=supplied.resources,
            )
        with pytest.raises(ValueError, match="sorted and unique"):
            PolicyEvaluationInputs(
                snapshot=supplied.snapshot,
                layers=supplied.layers,
                resources=(supplied.resources[0], supplied.resources[0]),
            )
        with pytest.raises(ValueError, match="sorted and unique"):
            PolicyEvaluationInputs(
                snapshot=supplied.snapshot,
                layers=supplied.layers,
                resources=supplied.resources,
                unknown_facts=("duplicate", "duplicate"),
            )
        async with session:
            pass
    finally:
        harness.store.close()
