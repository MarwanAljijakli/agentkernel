from __future__ import annotations

import asyncio
import inspect
import sqlite3
import threading
from asyncio import CancelledError
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
import test_enforced_transaction_coordinator as support
from agentkernel.adapters.base import (
    CommitContext,
    EffectPlan,
    ReconcileReport,
    ReconcileStatus,
    RecoveryContext,
    RecoveryReport,
    StageContext,
    StagedEffect,
    StagedReceipt,
    VerifyContext,
)
from agentkernel.canonical import canonical_digest, canonical_json_text
from agentkernel.domain.enums import (
    AuthorizationRoundPurpose,
    LeasePurpose,
    ReconciliationOutcome,
    RecoveryWorkKind,
    RecoveryWorkState,
    RiskClass,
    StageMaterialState,
    TransactionState,
    VerificationStatus,
)
from agentkernel.domain.models import (
    AdapterObservation,
    AuthenticatedActionContext,
    EffectReceipt,
    IntentRecord,
    NormalizedAction,
    PolicyBundle,
    PolicyDefault,
    PolicyEffect,
    PolicyRule,
    RecoveryActionBinding,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.artifacts import LocalArtifactStore
from agentkernel.normalization.mock import MockSetValuesNormalizer
from agentkernel.normalization.registry import NormalizerRegistry
from agentkernel.policy import (
    PolicyLayer,
    PolicyLayerInput,
    PolicyLayerSnapshot,
    PolicyResourceInput,
    compile_policy,
)
from agentkernel.storage.control import CapabilityReservationState, IntentAttemptState
from agentkernel.storage.enforced import (
    EnforcedStoreDisposition,
    RecoveryActionHandoff,
    RecoveryCursor,
    RecoveryHandoffFailureEvidenceStatus,
    SQLiteEnforcedTransactionStore,
)
from agentkernel.transactions.contracts import (
    CommitDispatchRecord,
    EnforcedTransactionRecord,
    LateRecoveryReportRecord,
    ReconciliationAttemptRecord,
    RecoveryCompletionReportRecord,
    StageMaterialRecord,
    WorkerLeaseRecord,
)
from agentkernel.transactions.enforced import (
    AuthenticatedContextValidator,
    AuthoritySnapshotProvider,
    CoordinatorCrashPoint,
    CoordinatorEvidence,
    CoordinatorInjectedCrash,
    EnforcedCoordinatorConfig,
    EnforcedTransactionCoordinator,
    EnforcedTransactionRequest,
    EnforcedTransactionStatus,
    PolicyEvaluationInputs,
    PolicyInputProvider,
    RecoveryActionFactory,
    RecoveryFailureKind,
    RecoveryRunResult,
    ValidatedAuthenticatedContext,
    _RecoveryExecutionPhase,
)
from agentkernel.transactions.state_machine import TransitionEvent


def _coordinator_kwargs(harness: support._Harness) -> dict[str, object]:
    return {
        "store": harness.store,
        "registry": harness.registry,
        "normalizers": harness.normalizers,
        "artifacts": harness.artifacts,
        "context_validator": harness.context_validator,
        "authority_snapshots": harness.authority_snapshots,
        "policy_inputs": harness.policy_inputs,
        "recovery_actions": harness.recovery_actions,
        "config": EnforcedCoordinatorConfig(
            worker_id="worker:edge-cases",
            lease_duration=timedelta(minutes=1),
            recovery_deadline=timedelta(minutes=4),
            reconciliation_backoff=timedelta(seconds=2),
        ),
        "clock": harness.clock,
    }


def _clone_coordinator(
    harness: support._Harness,
    **overrides: object,
) -> EnforcedTransactionCoordinator:
    kwargs = _coordinator_kwargs(harness)
    kwargs.update(overrides)
    return EnforcedTransactionCoordinator(**kwargs)


def _worker_lease_snapshot(
    store: SQLiteEnforcedTransactionStore,
    *,
    tenant_id: str,
    transaction_id: str,
) -> tuple[tuple[object, ...], ...]:
    rows = store._connection.execute(
        "SELECT * FROM enforced_worker_leases "
        "WHERE tenant_id = ? AND transaction_id = ? ORDER BY fencing_token",
        (tenant_id, transaction_id),
    ).fetchall()
    return tuple(tuple(row) for row in rows)


def _artifact_file_snapshot(root: Path) -> tuple[str, ...]:
    return tuple(sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()))


def _restore_private_artifact(
    store: LocalArtifactStore,
    path: Path,
    content: bytes,
) -> None:
    """Restore a damaged test blob through the production private-file boundary."""

    path.unlink(missing_ok=True)
    restored = store.put(content)
    assert support._artifact_path(store.root, restored.digest) == path


def _rewrite_test_intent_head_evidence(
    store: SQLiteEnforcedTransactionStore,
    *,
    tenant_id: str,
    intent_hash: str,
    transaction_id: str,
    evidence_digest: str,
) -> None:
    """Rewrite one test fixture's content-addressed intent head coherently."""

    owner = store._connection.execute(
        "SELECT * FROM enforced_intent_owners WHERE tenant_id = ? AND intent_hash = ?",
        (tenant_id, intent_hash),
    ).fetchone()
    assert owner is not None
    sequence = int(owner["history_head_sequence"])
    row = store._connection.execute(
        "SELECT * FROM enforced_intent_attempt_history WHERE tenant_id = ? "
        "AND intent_hash = ? AND sequence = ?",
        (tenant_id, intent_hash, sequence),
    ).fetchone()
    assert row is not None
    assert str(row["transaction_id"]) == transaction_id
    payload: dict[str, object] = {
        "profile": "agentkernel.intent-attempt-history/v2",
        "tenant_id": tenant_id,
        "intent_hash": intent_hash,
        "sequence": sequence,
        "transaction_id": transaction_id,
        "event_type": str(row["event_type"]),
        "disposition": None if row["disposition"] is None else str(row["disposition"]),
        "attempt_state": str(row["attempt_state"]),
        "owner_transaction_id": str(row["owner_transaction_id"]),
        "owner_version": int(row["owner_version"]),
        "effective_idempotency_key": str(row["effective_idempotency_key"]),
        "evidence_digest": evidence_digest,
        "previous_history_digest": (
            None if row["previous_history_digest"] is None else str(row["previous_history_digest"])
        ),
        "recorded_at": str(row["recorded_at"]),
    }
    history_digest = canonical_digest(payload)
    trigger_row = store._connection.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
        "AND name = 'enforced_intent_history_no_update'"
    ).fetchone()
    assert trigger_row is not None
    assert trigger_row[0] is not None
    store._execute("DROP TRIGGER enforced_intent_history_no_update")
    store._execute(
        "UPDATE enforced_intent_attempt_history SET evidence_digest = ?, "
        "history_digest = ? WHERE tenant_id = ? AND intent_hash = ? AND sequence = ?",
        (evidence_digest, history_digest, tenant_id, intent_hash, sequence),
    )
    store._execute(
        "UPDATE enforced_intent_attempts SET evidence_digest = ? WHERE tenant_id = ? "
        "AND intent_hash = ? AND transaction_id = ?",
        (evidence_digest, tenant_id, intent_hash, transaction_id),
    )
    store._execute(
        "UPDATE enforced_intent_owners SET history_head_digest = ? WHERE tenant_id = ? "
        "AND intent_hash = ? AND history_head_sequence = ?",
        (history_digest, tenant_id, intent_hash, sequence),
    )
    store._execute(str(trigger_row[0]))


def _policy_layer(mode: str) -> PolicyLayerInput:
    rules = [
        PolicyRule(
            rule_id=f"grant-memory-{mode}",
            effect=PolicyEffect.GRANT,
            modes=("read", "stage", "commit_reversible"),
            when={"resource_within": "memory://mock/**"},
        )
    ]
    if mode == "deny":
        rules.append(
            PolicyRule(
                rule_id="deny-memory-edge-case",
                effect=PolicyEffect.DENY,
                when={"resource_within": "memory://mock/**"},
            )
        )
    elif mode == "approval":
        rules.append(
            PolicyRule(
                rule_id="approve-memory-edge-case",
                effect=PolicyEffect.REQUIRE_APPROVAL,
                when={"resource_within": "memory://mock/**"},
            )
        )
    return PolicyLayerInput(
        layer=PolicyLayer.SYSTEM,
        scope_id=f"scope:edge-{mode}",
        policy=compile_policy(
            PolicyBundle(
                name=f"coordinator-edge-{mode}",
                version="1.0.0",
                default=PolicyDefault.ABSTAIN,
                rules=tuple(rules),
            )
        ),
    )


class _PurposePolicyInputs(support._PolicyInputs):
    def __init__(
        self,
        clock: support._Clock,
        scenarios: dict[AuthorizationRoundPurpose, str],
    ) -> None:
        super().__init__(clock)
        self._scenarios = scenarios

    async def inputs_for(
        self,
        *,
        action,
        authority_decision,
        purpose: AuthorizationRoundPurpose,
        evaluated_at: datetime,
    ) -> PolicyEvaluationInputs:
        supplied = await super().inputs_for(
            action=action,
            authority_decision=authority_decision,
            purpose=purpose,
            evaluated_at=evaluated_at,
        )
        mode = self._scenarios.get(purpose, "allow")
        if mode == "allow":
            return supplied
        if mode == "unknown":
            return supplied.model_copy(update={"unknown_facts": ("fact:edge-unavailable",)})
        layer = _policy_layer(mode)
        return supplied.model_copy(
            update={
                "snapshot": PolicyLayerSnapshot.create((layer.identity,)),
                "layers": (layer,),
            }
        )


class _ExtraResourcePolicyInputs(support._PolicyInputs):
    async def inputs_for(
        self,
        *,
        action,
        authority_decision,
        purpose: AuthorizationRoundPurpose,
        evaluated_at: datetime,
    ) -> PolicyEvaluationInputs:
        supplied = await super().inputs_for(
            action=action,
            authority_decision=authority_decision,
            purpose=purpose,
            evaluated_at=evaluated_at,
        )
        source = supplied.resources[0]
        extra_use = source.resource_use.model_copy(
            update={"canonical_resource": "memory://mock/unrequested"}
        )
        extra = PolicyResourceInput(
            resource_index=len(supplied.resources),
            resource_use_ref=canonical_digest(extra_use),
            resource_use=extra_use,
            context=source.context.model_copy(update={"resource": "memory://mock/unrequested"}),
        )
        return PolicyEvaluationInputs(
            snapshot=supplied.snapshot,
            layers=supplied.layers,
            resources=(*supplied.resources, extra),
        )


class _WrongEvidenceValidator:
    def __init__(self, context, evidence_ref: str) -> None:
        self._context = context
        self._evidence_ref = evidence_ref

    async def validate(
        self,
        request: EnforcedTransactionRequest,
    ) -> ValidatedAuthenticatedContext:
        del request
        return ValidatedAuthenticatedContext(
            context=self._context,
            authentication_evidence_ref=self._evidence_ref,
        )


class _WrongDigestArtifacts:
    def __init__(self, delegate) -> None:
        self._delegate = delegate

    def put_model(self, model, *, media_type="application/vnd.agentkernel.canonical+json"):
        artifact = self._delegate.put_model(model, media_type=media_type)
        return artifact.model_copy(update={"digest": f"sha256:{'0' * 64}"})

    def get(self, digest: str) -> bytes:
        return self._delegate.get(digest)

    def get_model(self, digest: str, model_type):
        return self._delegate.get_model(digest, model_type)


class _TogglePutOutageArtifacts:
    def __init__(self, delegate) -> None:
        self._delegate = delegate
        self.fail_put = False

    def put_model(self, model, *, media_type="application/vnd.agentkernel.canonical+json"):
        if self.fail_put:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "synthetic artifact write outage",
            )
        return self._delegate.put_model(model, media_type=media_type)

    def get(self, digest: str) -> bytes:
        return self._delegate.get(digest)

    def get_model(self, digest: str, model_type):
        return self._delegate.get_model(digest, model_type)


class _TerminalRecoveryEvidencePutOutageArtifacts:
    def __init__(self, delegate) -> None:
        self._delegate = delegate
        self.blocked_puts = 0

    def put_model(self, model, *, media_type="application/vnd.agentkernel.canonical+json"):
        if (
            isinstance(model, CoordinatorEvidence)
            and model.event == "recovery.authorization_handoff_failed"
        ):
            self.blocked_puts += 1
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "synthetic terminal recovery evidence write outage",
            )
        return self._delegate.put_model(model, media_type=media_type)

    def get(self, digest: str) -> bytes:
        return self._delegate.get(digest)

    def get_model(self, digest: str, model_type):
        return self._delegate.get_model(digest, model_type)


class _SelectiveGetOutageArtifacts:
    def __init__(self, delegate, blocked_digest: str) -> None:
        self._delegate = delegate
        self._blocked_digest = blocked_digest
        self.blocked_gets = 0

    def put_model(self, model, *, media_type="application/vnd.agentkernel.canonical+json"):
        return self._delegate.put_model(model, media_type=media_type)

    def get(self, digest: str) -> bytes:
        if digest == self._blocked_digest:
            self.blocked_gets += 1
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "synthetic selective artifact read outage",
            )
        return self._delegate.get(digest)

    def get_model(self, digest: str, model_type):
        if digest == self._blocked_digest:
            self.blocked_gets += 1
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "synthetic selective artifact read outage",
            )
        return self._delegate.get_model(digest, model_type)


class _StagePutOutageArtifacts:
    def __init__(self, delegate) -> None:
        self._delegate = delegate
        self.blocked_puts = 0

    def put_model(self, model, *, media_type="application/vnd.agentkernel.canonical+json"):
        if isinstance(model, StageMaterialRecord):
            self.blocked_puts += 1
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "synthetic stage-material write outage",
            )
        return self._delegate.put_model(model, media_type=media_type)

    def get(self, digest: str) -> bytes:
        return self._delegate.get(digest)

    def get_model(self, digest: str, model_type):
        return self._delegate.get_model(digest, model_type)


class _MismatchedGetArtifacts:
    def __init__(self, delegate, digest: str, replacement) -> None:
        self._delegate = delegate
        self._digest = digest
        self._replacement = replacement
        self.mismatched_gets = 0

    def put_model(self, model, *, media_type="application/vnd.agentkernel.canonical+json"):
        return self._delegate.put_model(model, media_type=media_type)

    def get(self, digest: str) -> bytes:
        return self._delegate.get(digest)

    def get_model(self, digest: str, model_type):
        if digest == self._digest:
            self.mismatched_gets += 1
            return self._replacement
        return self._delegate.get_model(digest, model_type)


class _ProjectionStore:
    def __init__(self, delegate, mutation: str) -> None:
        self._delegate = delegate
        self._mutation = mutation

    def get_transaction_projection(self, *, tenant_id: str, transaction_id: str):
        projection = self._delegate.get_transaction_projection(
            tenant_id=tenant_id,
            transaction_id=transaction_id,
        )
        authorization = projection.authorization_rounds[0]
        update = (
            {"schema_version": "1.0"}
            if self._mutation == "legacy"
            else {"authority_snapshot_ref": None}
        )
        return replace(
            projection,
            authorization_rounds=(authorization.model_copy(update=update),),
        )

    def __getattr__(self, name: str):
        return getattr(self._delegate, name)


class _RecoveryHandoffProjectionStore:
    def __init__(self, delegate, mutation: str) -> None:
        self._delegate = delegate
        self._mutation = mutation

    def get_transaction_projection(self, *, tenant_id: str, transaction_id: str):
        projection = self._delegate.get_transaction_projection(
            tenant_id=tenant_id,
            transaction_id=transaction_id,
        )
        handoff = projection.recovery_handoffs[-1]
        update = (
            {"failure_reason_code": ErrorCode.DEADLINE_EXCEEDED.value}
            if self._mutation == "untyped"
            else {"closed_at": None, "terminal_sequence": None}
        )
        return replace(
            projection,
            recovery_handoffs=(
                *projection.recovery_handoffs[:-1],
                replace(handoff, **update),
            ),
        )

    def __getattr__(self, name: str):
        return getattr(self._delegate, name)


class _CancellingNormalizer:
    def __init__(self) -> None:
        self._delegate = MockSetValuesNormalizer()
        self.manifest = self._delegate.manifest

    @property
    def configuration_digest(self) -> str:
        return self._delegate.configuration_digest

    def normalize(self, **_kwargs):
        raise CancelledError


class _CancellingAuthoritySnapshots:
    async def snapshot_for(self, **_kwargs):
        raise CancelledError


class _BlockingAuthoritySnapshots:
    def __init__(self, delegate: support._AuthoritySnapshots) -> None:
        self._delegate = delegate
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.finished = asyncio.Event()
        self.calls = 0
        self.active = 0
        self.max_active = 0

    async def snapshot_for(self, **kwargs):
        self.calls += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.started.set()
        try:
            await self.release.wait()
            return await self._delegate.snapshot_for(**kwargs)
        finally:
            self.active -= 1
            self.finished.set()


class _BlockingContextValidator:
    def __init__(self, delegate: support._ContextValidator, expected_calls: int) -> None:
        self._delegate = delegate
        self._expected_calls = expected_calls
        self.all_started = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = 0
        self.finished = 0
        self.active = 0

    async def validate(self, request: EnforcedTransactionRequest):
        self.calls += 1
        self.active += 1
        if self.calls == self._expected_calls:
            self.all_started.set()
        try:
            await self.release.wait()
            return await self._delegate.validate(request)
        finally:
            self.active -= 1
            self.finished += 1


class _BlockingNormalizers:
    def __init__(self, delegate: NormalizerRegistry) -> None:
        self._delegate = delegate
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.finished = asyncio.Event()
        self.active = 0

    async def normalize_async(self, *args, **kwargs):
        self.active += 1
        self.started.set()
        try:
            await self.release.wait()
            return await self._delegate.normalize_async(*args, **kwargs)
        finally:
            self.active -= 1
            self.finished.set()


class _BlockingPolicyInputs:
    def __init__(self, delegate: support._PolicyInputs) -> None:
        self._delegate = delegate
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.finished = asyncio.Event()
        self.active = 0

    async def inputs_for(self, **kwargs):
        self.active += 1
        self.started.set()
        try:
            await self.release.wait()
            return await self._delegate.inputs_for(**kwargs)
        finally:
            self.active -= 1
            self.finished.set()


class _BlockingRecoveryActions:
    def __init__(self, delegate: support._RecoveryActions) -> None:
        self._delegate = delegate
        self.first_started = asyncio.Event()
        self.second_started = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = 0
        self.active = 0
        self.max_active = 0

    async def create(self, **kwargs):
        self.calls += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        if self.calls == 1:
            self.first_started.set()
        elif self.calls == 2:
            self.second_started.set()
        try:
            await self.release.wait()
            return await self._delegate.create(**kwargs)
        finally:
            self.active -= 1


class _RecordingRecoveryActions:
    def __init__(self, delegate: support._RecoveryActions) -> None:
        self._delegate = delegate
        self.action = None
        self.calls = 0

    async def create(self, **kwargs):
        self.calls += 1
        self.action = await self._delegate.create(**kwargs)
        return self.action


class _BlockingRecoveryPolicyInputs:
    def __init__(self, delegate: support._PolicyInputs) -> None:
        self._delegate = delegate
        self.started = asyncio.Event()
        self.finished = asyncio.Event()
        self.active = 0
        self.calls = 0

    async def inputs_for(self, **kwargs):
        if kwargs["purpose"] is not AuthorizationRoundPurpose.RECOVERY:
            return await self._delegate.inputs_for(**kwargs)
        self.calls += 1
        self.active += 1
        self.started.set()
        try:
            await asyncio.Event().wait()
        finally:
            self.active -= 1
            self.finished.set()


class _BlockingAfterPrivateStageAdapter(support._ControlledVerificationAdapter):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.stage_started = asyncio.Event()
        self.stage_finished = asyncio.Event()

    async def stage(self, plan: EffectPlan, ctx: StageContext) -> StagedEffect:
        staged = await super().stage(plan, ctx)
        self.stage_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            self.stage_finished.set()
        return staged


class _MalformedPlanAdapter(support._ControlledVerificationAdapter):
    async def inspect(self, proposal, ctx) -> EffectPlan:
        plan = await super().inspect(proposal, ctx)
        return plan.model_copy(update={"intent_hash": f"sha256:{'0' * 64}"})


class _MalformedStageAdapter(support._ControlledVerificationAdapter):
    async def stage(self, plan: EffectPlan, ctx: StageContext) -> StagedEffect:
        staged = await super().stage(plan, ctx)
        return staged.model_copy(update={"stage_id": "stage:foreign"})


class _MalformedStagedReceiptAdapter(support._ControlledVerificationAdapter):
    async def execute(self, staged: StagedEffect, ctx: StageContext) -> StagedReceipt:
        receipt = await super().execute(staged, ctx)
        foreign_stage = receipt.staged.model_copy(update={"stage_id": "stage:foreign"})
        return receipt.model_copy(update={"staged": foreign_stage})


class _DuplicateObservationAdapter(support._ControlledVerificationAdapter):
    async def verify_staged(self, receipt: StagedReceipt, ctx: VerifyContext):
        report = await super().verify_staged(receipt, ctx)
        return report.model_copy(update={"evidence_refs": report.evidence_refs * 2})


class _ForgedCommittedPostStateAdapter(support._ControlledVerificationAdapter):
    forged_receipt: EffectReceipt | None = None

    async def commit(
        self,
        receipt: StagedReceipt,
        ctx: CommitContext,
    ) -> EffectReceipt:
        committed = await super().commit(receipt, ctx)
        forged = committed.model_copy(
            update={
                "target_version_after": canonical_digest({"forged": "after"}),
                "effect_digest": canonical_digest({"forged": "effect"}),
            }
        )
        for dispatch in self._target.dispatches.values():
            if dispatch.receipt == committed:
                dispatch.receipt = forged
        self.forged_receipt = forged
        return forged


class _RecoveryUnavailableAdapter(support._ControlledVerificationAdapter):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        operation = self.manifest.operations["set_values"].model_copy(
            update={
                "risk_floor": RiskClass.COMPENSATABLE,
                "rollback": False,
                "compensate": False,
            }
        )
        self.manifest = self.manifest.model_copy(update={"operations": {"set_values": operation}})
        self.committed_status = VerificationStatus.FAIL

    async def inspect(self, proposal, ctx) -> EffectPlan:
        plan = await super().inspect(proposal, ctx)
        return plan.model_copy(update={"risk_class": RiskClass.COMPENSATABLE})


class _RecoveryProviderRuntimeErrorAdapter(support._ControlledVerificationAdapter):
    async def abort_stage(self, stage_id: str, ctx: RecoveryContext):
        del stage_id, ctx
        self.abort_stage_calls += 1
        raise RuntimeError("synthetic recovery provider failure")


class _RecoveryProviderCancelledAdapter(support._ControlledVerificationAdapter):
    async def abort_stage(self, stage_id: str, ctx: RecoveryContext):
        del stage_id, ctx
        self.abort_stage_calls += 1
        raise CancelledError


class _CountingReconcileAdapter(support._ControlledVerificationAdapter):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.reconcile_calls = 0

    async def reconcile(self, intent: IntentRecord, ctx: RecoveryContext) -> ReconcileReport:
        self.reconcile_calls += 1
        return await super().reconcile(intent, ctx)


class _UnknownCountingReconcileAdapter(_CountingReconcileAdapter):
    async def reconcile(self, intent: IntentRecord, ctx: RecoveryContext) -> ReconcileReport:
        authoritative = await super().reconcile(intent, ctx)
        return authoritative.model_copy(
            update={
                "status": ReconcileStatus.UNKNOWN,
                "receipt": None,
                "evidence_refs": self._observation_refs_for_status(
                    authoritative.evidence_refs,
                    ReconcileStatus.UNKNOWN.value,
                ),
            }
        )


class _BlockingSecondReconcileAdapter(support._SequencedReconciliationAdapter):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.second_reconcile_entered = asyncio.Event()
        self.second_reconcile_release = asyncio.Event()

    async def reconcile(
        self,
        intent: IntentRecord,
        ctx: RecoveryContext,
    ) -> ReconcileReport:
        report = await super().reconcile(intent, ctx)
        if self.reconcile_calls == 2:
            self.second_reconcile_entered.set()
            await self.second_reconcile_release.wait()
        return report


class _PartialCountingReconcileAdapter(_CountingReconcileAdapter):
    async def reconcile(self, intent: IntentRecord, ctx: RecoveryContext) -> ReconcileReport:
        authoritative = await super().reconcile(intent, ctx)
        return authoritative.model_copy(
            update={
                "status": ReconcileStatus.PARTIAL_OR_INVALID,
                "evidence_refs": self._observation_refs_for_status(
                    authoritative.evidence_refs,
                    ReconcileStatus.PARTIAL_OR_INVALID.value,
                ),
            }
        )


class _PartialCompensatingReconcileAdapter(support._LateCompensatingAdapter):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.reconcile_calls = 0

    async def reconcile(self, intent: IntentRecord, ctx: RecoveryContext) -> ReconcileReport:
        authoritative = await super().reconcile(intent, ctx)
        self.reconcile_calls += 1
        return authoritative.model_copy(
            update={
                "status": ReconcileStatus.PARTIAL_OR_INVALID,
                "evidence_refs": self._observation_refs_for_status(
                    authoritative.evidence_refs,
                    ReconcileStatus.PARTIAL_OR_INVALID.value,
                ),
            }
        )


class _CountingRecoveryActions(support._RecoveryActions):
    def __init__(self) -> None:
        self.create_calls = 0

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
        self.create_calls += 1
        return await super().create(
            target=target,
            target_action=target_action,
            kind=kind,
            target_evidence_ref=target_evidence_ref,
            binding=binding,
            deadline=deadline,
        )


class _ReconcileRaisesAdapter(support._ControlledVerificationAdapter):
    async def reconcile(self, intent: IntentRecord, ctx: RecoveryContext) -> ReconcileReport:
        del intent, ctx
        raise AgentKernelError(
            ErrorCode.EVIDENCE_UNAVAILABLE,
            "Synthetic reconciliation evidence outage",
        )


class _CommittedWithoutReceiptAdapter(support._ControlledVerificationAdapter):
    async def reconcile(self, intent: IntentRecord, ctx: RecoveryContext) -> ReconcileReport:
        authoritative = await super().reconcile(intent, ctx)
        return ReconcileReport(
            status=ReconcileStatus.COMMITTED,
            evidence_refs=self._observation_refs_for_status(
                authoritative.evidence_refs,
                ReconcileStatus.COMMITTED.value,
            ),
        )


class _NoEffectWithReceiptAdapter(support._ControlledVerificationAdapter):
    async def reconcile(self, intent: IntentRecord, ctx: RecoveryContext) -> ReconcileReport:
        authoritative = await super().reconcile(intent, ctx)
        if authoritative.receipt is None:
            raise AssertionError("committed reconciliation fixture requires a receipt")
        return ReconcileReport(
            status=ReconcileStatus.NO_EFFECT,
            receipt=authoritative.receipt,
            evidence_refs=self._observation_refs_for_status(
                authoritative.evidence_refs,
                ReconcileStatus.NO_EFFECT.value,
            ),
        )


class _LateReconciliationVerificationAdapter(support._ControlledVerificationAdapter):
    test_clock: support._Clock | None = None

    async def verify_committed(
        self,
        receipt: EffectReceipt,
        ctx: VerifyContext,
    ):
        report = await super().verify_committed(receipt, ctx)
        if self.test_clock is None:
            raise AssertionError("late verification fixture requires the harness clock")
        self.test_clock.advance(timedelta(minutes=2))
        return report


class _ForeignReconciliationReceiptAdapter(support._ControlledVerificationAdapter):
    foreign_receipt: EffectReceipt | None = None

    async def reconcile(
        self,
        intent: IntentRecord,
        ctx: RecoveryContext,
    ) -> ReconcileReport:
        report = await super().reconcile(intent, ctx)
        if report.receipt is None:
            raise AssertionError("foreign receipt fixture requires a committed effect")
        self.foreign_receipt = report.receipt.model_copy(
            update={"transaction_id": "transaction:foreign-reconciliation-receipt"}
        )
        return report.model_copy(update={"receipt": self.foreign_receipt})


class _LateForeignReconciliationReceiptAdapter(_ForeignReconciliationReceiptAdapter):
    test_clock: support._Clock | None = None

    async def reconcile(
        self,
        intent: IntentRecord,
        ctx: RecoveryContext,
    ) -> ReconcileReport:
        report = await super().reconcile(intent, ctx)
        if self.test_clock is None:
            raise AssertionError("late foreign receipt fixture requires the harness clock")
        self.test_clock.advance(timedelta(minutes=2))
        return report


class _LateInvalidRecoveryReportAdapter(support._ControlledVerificationAdapter):
    test_clock: support._Clock | None = None
    rejected_report_ref: str | None = None

    async def abort_stage(
        self,
        stage_id: str,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        report = await super().abort_stage(stage_id, ctx)
        invalid = report.model_copy(update={"restored_state_digest": None})
        self.rejected_report_ref = canonical_digest(invalid)
        if self.test_clock is None:
            raise AssertionError("late invalid recovery fixture requires the harness clock")
        self.test_clock.advance(timedelta(minutes=2))
        return invalid


class _CommittedVerificationRaisesAdapter(support._ControlledVerificationAdapter):
    async def verify_committed(
        self,
        receipt: EffectReceipt,
        ctx: VerifyContext,
    ):
        del receipt, ctx
        raise AgentKernelError(
            ErrorCode.EVIDENCE_UNAVAILABLE,
            "Synthetic committed verification evidence outage",
        )


async def _crash_during_commit(harness: support._Harness):
    session = await harness.coordinator.transaction(harness.request)
    with pytest.raises(CoordinatorInjectedCrash):
        async with session:
            await session.commit()
    return session


async def _expire_unstarted_dispatch_recovery(
    harness: support._Harness,
    *,
    recovery_timeout: timedelta = timedelta(seconds=4),
):
    session = await _crash_during_commit(harness)
    transaction = harness.store.get_enforced_transaction(
        session.record.tenant_id,
        session.record.transaction_id,
    )
    dispatch = harness.store.get_commit_dispatch(
        tenant_id=transaction.tenant_id,
        transaction_id=transaction.transaction_id,
    )
    classified = harness.store.classify_dispatch_outcome(
        tenant_id=transaction.tenant_id,
        transaction_id=transaction.transaction_id,
        expected_dispatch_version=dispatch.version,
        expected_transaction_version=transaction.version,
        classification=ReconciliationOutcome.UNKNOWN,
        evidence_refs=(dispatch.permit_ref,),
        recorded_at=harness.clock(),
        recovery_timeout=recovery_timeout,
    )
    deadline = harness.store.get_transaction_recovery_deadline(
        tenant_id=transaction.tenant_id,
        transaction_id=transaction.transaction_id,
    )
    assert classified.transaction.state is TransactionState.IN_DOUBT
    assert classified.dispatch.unavailable_record_digest is None
    assert deadline == harness.clock() + recovery_timeout
    assert not harness.store.list_recovery_work(
        tenant_id=transaction.tenant_id,
        transaction_id=transaction.transaction_id,
    )
    assert not harness.store.list_recovery_action_handoffs(
        tenant_id=transaction.tenant_id,
        target_transaction_id=transaction.transaction_id,
    )
    harness.clock.advance(recovery_timeout + timedelta(microseconds=1))
    return session, classified.transaction, classified.dispatch, deadline


async def _expire_unstarted_failed_recovery(
    harness: support._Harness,
):
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    adapter.committed_status = VerificationStatus.FAIL
    session = await _crash_during_commit(harness)
    transaction = harness.store.get_enforced_transaction(
        session.record.tenant_id,
        session.record.transaction_id,
    )
    dispatch = harness.store.get_commit_dispatch(
        tenant_id=transaction.tenant_id,
        transaction_id=transaction.transaction_id,
    )
    deadline = harness.store.get_transaction_recovery_deadline(
        tenant_id=transaction.tenant_id,
        transaction_id=transaction.transaction_id,
    )
    assert transaction.state is TransactionState.FAILED
    assert dispatch.state.value == "PARTIAL_OR_INVALID"
    assert not harness.store.list_recovery_work(
        tenant_id=transaction.tenant_id,
        transaction_id=transaction.transaction_id,
    )
    assert not harness.store.list_recovery_action_handoffs(
        tenant_id=transaction.tenant_id,
        target_transaction_id=transaction.transaction_id,
    )
    assert deadline > harness.clock()
    harness.clock.advance(deadline - harness.clock() + timedelta(microseconds=1))
    return session, transaction, dispatch, deadline


async def _crash_after_recovery_authorized(harness: support._Harness):
    session = await harness.coordinator.transaction(harness.request)
    with pytest.raises(CoordinatorInjectedCrash):
        async with session:
            pass
    work = harness.store.list_recovery_work(
        tenant_id=session.record.tenant_id,
        transaction_id=session.record.transaction_id,
    )
    assert len(work) == 1
    assert work[0].state is RecoveryWorkState.PENDING
    return session, work[0]


async def _stop_dispatch_before_explicit_resume(
    harness: support._Harness,
    session,
) -> EnforcedTransactionCoordinator:
    restarted = support._restart_coordinator(harness)
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


async def _crash_after_reconciliation_started(
    harness: support._Harness,
    session,
):
    crashing = support._restart_coordinator(
        harness,
        crash_point=CoordinatorCrashPoint.AFTER_RECONCILIATION_STARTED,
    )
    with pytest.raises(CoordinatorInjectedCrash):
        await crashing.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
    works = harness.store.list_recovery_work(
        tenant_id=session.record.tenant_id,
        transaction_id=session.record.transaction_id,
    )
    assert len(works) == 1
    running = works[0]
    assert running.state is RecoveryWorkState.RUNNING
    attempt = harness.store.get_reconciliation_attempt(
        tenant_id=running.tenant_id,
        transaction_id=running.transaction_id,
        recovery_id=running.recovery_id,
        attempt=running.attempt,
    )
    assert attempt.outcome is None
    assert attempt.completed_at is None
    assert attempt.version == 0
    dispatch = harness.store.get_commit_dispatch(
        tenant_id=running.tenant_id,
        transaction_id=running.transaction_id,
    )
    return running, attempt, dispatch


def _assert_discard_target_closed(
    harness: support._Harness,
    work,
    *,
    recovery_intent_state: IntentAttemptState,
) -> None:
    transaction = harness.store.get_enforced_transaction(
        tenant_id=work.tenant_id,
        transaction_id=work.transaction_id,
    )
    assert transaction.state is TransactionState.RECOVERY_FAILED
    stage = harness.store.get_stage_material(
        tenant_id=work.tenant_id,
        transaction_id=work.transaction_id,
    )
    assert stage.state is StageMaterialState.DISCARD_FAILED
    target_attempt = harness.store.get_intent_attempt(
        tenant_id=work.tenant_id,
        intent_hash=work.intent_hash,
        transaction_id=work.transaction_id,
    )
    assert target_attempt.state is IntentAttemptState.REVIEW_REQUIRED
    target_action = harness.store.get_normalized_action(
        work.tenant_id,
        work.transaction_id,
    ).action
    target_reservation = harness.store.get_capability_chain(
        tenant_id=work.tenant_id,
        goal_id=target_action.goal_id,
        run_id=target_action.run_id,
        intent_hash=target_action.intent_hash,
    )
    assert target_reservation.state is CapabilityReservationState.RELEASED
    recovery_attempt = harness.store.get_intent_attempt(
        tenant_id=work.tenant_id,
        intent_hash=work.recovery_action_intent_hash,
        transaction_id=work.recovery_action_transaction_id,
    )
    assert recovery_attempt.state is recovery_intent_state
    handoff = harness.store.get_recovery_action_handoff(
        tenant_id=work.tenant_id,
        target_transaction_id=work.transaction_id,
        recovery_id=work.recovery_id,
    )
    assert handoff is not None
    assert handoff.closed_at == work.updated_at
    assert handoff.failure_reason_code == work.reason_code
    if work.lease_id is not None:
        lease = harness.store.get_worker_lease(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            lease_id=work.lease_id,
        )
        assert lease.released_at == work.updated_at


@pytest.mark.parametrize(
    "kwargs",
    [
        {"worker_id": ""},
        {"authority_audience": ""},
        {"lease_duration": timedelta(0)},
        {"recovery_deadline": timedelta(seconds=-1)},
        {"reconciliation_backoff": timedelta(0)},
        {"max_reconciliation_attempts": True},
        {"max_reconciliation_attempts": 33},
    ],
)
def test_coordinator_config_rejects_ambiguous_or_unbounded_values(kwargs) -> None:
    with pytest.raises(ValueError, match="must"):
        EnforcedCoordinatorConfig(**kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, 1_001, True, 1.5])
async def test_recovery_limit_rejects_non_integer_or_unbounded_values(
    tmp_path: Path,
    limit,
) -> None:
    harness = support._make_harness(tmp_path)
    try:
        with pytest.raises(AgentKernelError) as captured:
            await harness.coordinator.recover_once("tenant:coordinator", limit=limit)
        assert captured.value.code is ErrorCode.VALIDATION_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_successor_prework_lost_acquisition_is_quiescent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._SequencedReconciliationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._SequencedReconciliationAdapter)
    adapter.reconcile_statuses = [
        ReconcileStatus.UNKNOWN,
        ReconcileStatus.COMMITTED,
    ]
    recovery_actions = _RecordingRecoveryActions(harness.recovery_actions)
    harness.recovery_actions = recovery_actions
    try:
        session = await _crash_during_commit(harness)
        recovery = await _stop_dispatch_before_explicit_resume(harness, session)
        first = await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert first.record.state is TransactionState.IN_DOUBT
        scheduled = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        assert scheduled.state is RecoveryWorkState.RETRY_SCHEDULED
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            recovery_id=scheduled.recovery_id,
            attempt=scheduled.attempt,
        )
        assert attempt.next_attempt_not_before is not None
        harness.clock.advance(attempt.next_attempt_not_before - harness.clock())
        assert recovery_actions.calls == adapter.reconcile_calls == 1

        original_acquire = harness.store.acquire_recovery_authorization_lease
        competing_leases: list[WorkerLeaseRecord] = []

        def competing_acquire_then_conflict(**kwargs):
            competing = original_acquire(
                **{
                    **kwargs,
                    "lease_id": "lease:competing-successor-prework",
                    "worker_id": "worker:competing-successor-prework",
                }
            )
            competing_leases.append(competing.lease)
            return original_acquire(**kwargs)

        monkeypatch.setattr(
            harness.store,
            "acquire_recovery_authorization_lease",
            competing_acquire_then_conflict,
        )
        lost_race = await support._restart_coordinator(harness).recover_once(scheduled.tenant_id)

        assert lost_race.scanned == 1
        assert lost_race.processed == lost_race.remaining == 0
        assert not lost_race.failures
        assert len(competing_leases) == 1
        successor_handoff = next(
            handoff
            for handoff in harness.store.list_recovery_action_handoffs(
                tenant_id=scheduled.tenant_id,
                target_transaction_id=scheduled.transaction_id,
            )
            if handoff.binding.predecessor_recovery_id == scheduled.recovery_id
        )
        assert successor_handoff.binding.recovery_ordinal == scheduled.recovery_ordinal + 1
        assert successor_handoff.action is None
        assert successor_handoff.closed_at is None
        assert (
            harness.store.get_live_open_prework_handoff(
                tenant_id=scheduled.tenant_id,
                target_transaction_id=scheduled.transaction_id,
                observed_at=harness.clock(),
            )
            == successor_handoff
        )
        assert not any(
            work.recovery_id == successor_handoff.binding.recovery_id
            for work in harness.store.list_recovery_work(
                tenant_id=scheduled.tenant_id,
                transaction_id=scheduled.transaction_id,
            )
        )
        assert recovery_actions.calls == adapter.reconcile_calls == 1

        monkeypatch.setattr(
            harness.store,
            "acquire_recovery_authorization_lease",
            original_acquire,
        )
        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        before_expiry = await restarted.recover_once(scheduled.tenant_id)
        assert before_expiry.scanned == before_expiry.processed == before_expiry.remaining == 0
        assert not before_expiry.failures

        harness.clock.advance(
            competing_leases[0].expires_at - harness.clock() + timedelta(microseconds=1)
        )
        assert (
            reopened_store.get_resumable_open_prework_handoff(
                tenant_id=scheduled.tenant_id,
                target_transaction_id=scheduled.transaction_id,
                observed_at=harness.clock(),
            )
            == successor_handoff
        )
        resumed = await restarted.recover_once(scheduled.tenant_id)

        assert resumed.scanned == resumed.processed == 1
        assert resumed.remaining == 0
        assert not resumed.failures
        assert resumed.statuses[0].record.state is TransactionState.COMMITTED
        assert recovery_actions.calls == adapter.reconcile_calls == 2
        works = reopened_store.list_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        assert len(works) == 2
        successor_work = next(
            work for work in works if work.recovery_id == successor_handoff.binding.recovery_id
        )
        assert successor_work.state is RecoveryWorkState.SUCCEEDED
        assert successor_work.predecessor_recovery_id == scheduled.recovery_id
        latest_recovery_lease = reopened_store._connection.execute(
            "SELECT * FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND purpose = 'RECOVERY' "
            "ORDER BY fencing_token DESC LIMIT 1",
            (scheduled.tenant_id, scheduled.transaction_id),
        ).fetchone()
        assert latest_recovery_lease is not None
        assert int(latest_recovery_lease["fencing_token"]) > competing_leases[0].fencing_token
        repeated = await restarted.recover_once(scheduled.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.calls == adapter.reconcile_calls == 2
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_public_recovery_fails_closed_for_invalid_and_reversing_clocks(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path)
    try:
        default_kwargs = _coordinator_kwargs(harness)
        default_kwargs.pop("clock")
        default_clock = EnforcedTransactionCoordinator(**default_kwargs)
        empty = await default_clock.recover_once("tenant:empty")
        assert empty.observed_at.tzinfo is UTC

        naive = _clone_coordinator(harness, clock=lambda: datetime(2026, 1, 1))
        with pytest.raises(AgentKernelError) as naive_error:
            await naive.recover_once("tenant:empty")
        assert naive_error.value.code is ErrorCode.INTEGRITY_ERROR

        non_utc = _clone_coordinator(
            harness,
            clock=lambda: datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=3))),
        )
        with pytest.raises(AgentKernelError) as offset_error:
            await non_utc.recover_once("tenant:empty")
        assert offset_error.value.code is ErrorCode.INTEGRITY_ERROR

        clock_reversed = False

        def reversing_clock() -> datetime:
            return datetime(2026, 1, 1 if clock_reversed else 2, tzinfo=UTC)

        reversing = _clone_coordinator(harness, clock=reversing_clock)
        await reversing.recover_once("tenant:empty")
        clock_reversed = True
        with pytest.raises(AgentKernelError) as backwards_error:
            await reversing.recover_once("tenant:empty")
        assert backwards_error.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_context_validation_cannot_substitute_authentication_evidence(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path)
    other_evidence = harness.artifacts.put(b"different-authentication-proof")
    coordinator = _clone_coordinator(
        harness,
        context_validator=_WrongEvidenceValidator(
            harness.context_validator.context,
            other_evidence.digest,
        ),
    )
    try:
        with pytest.raises(AgentKernelError) as captured:
            await coordinator.transaction(harness.request)
        assert captured.value.code is ErrorCode.AUTHORITY_MISSING
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_artifact_store_digest_substitution_fails_before_durable_ingress(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path)
    coordinator = _clone_coordinator(
        harness,
        artifacts=_WrongDigestArtifacts(harness.artifacts),
    )
    try:
        with pytest.raises(AgentKernelError) as captured:
            await coordinator.transaction(harness.request)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
        with pytest.raises(AgentKernelError) as missing:
            harness.store.get_enforced_transaction(
                "tenant:coordinator",
                harness.request.proposal.transaction_id,
            )
        assert missing.value.code is ErrorCode.VALIDATION_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_adapter_version_mismatch_is_durably_rejected_without_adapter_io(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path)
    bad_request = harness.request.model_copy(
        update={
            "proposal": harness.request.proposal.model_copy(update={"adapter_version": "9.9.9"})
        }
    )
    try:
        with pytest.raises(AgentKernelError) as captured:
            await harness.coordinator.transaction(bad_request)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
        status = harness.coordinator.status(
            "tenant:coordinator",
            bad_request.proposal.transaction_id,
        )
        assert status.record.state is TransactionState.REJECTED
        assert not harness.target.dispatches
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_cancellation_at_new_and_planned_boundaries_aborts_without_effect(
    tmp_path: Path,
) -> None:
    new_harness = support._make_harness(tmp_path / "new", transaction_id="transaction:cancel-new")
    cancelling_registry = NormalizerRegistry()
    cancelling_registry.register(
        "mock",
        "set_values",
        _CancellingNormalizer(),
        reviewed=True,
    )
    new_harness.coordinator._normalizers = cancelling_registry
    try:
        with pytest.raises(CancelledError):
            await new_harness.coordinator.transaction(new_harness.request)
        new_status = new_harness.coordinator.status(
            "tenant:coordinator",
            "transaction:cancel-new",
        )
        assert new_status.record.state is TransactionState.ABORTED
        assert new_status.action is None
        assert not new_harness.target.dispatches
    finally:
        new_harness.store.close()

    planned_harness = support._make_harness(
        tmp_path / "planned",
        transaction_id="transaction:cancel-planned",
    )
    planned_harness.coordinator._authority_snapshots = _CancellingAuthoritySnapshots()
    try:
        with pytest.raises(CancelledError):
            await planned_harness.coordinator.transaction(planned_harness.request)
        planned_status = planned_harness.coordinator.status(
            "tenant:coordinator",
            "transaction:cancel-planned",
        )
        assert planned_status.record.state is TransactionState.ABORTED
        assert planned_status.action is not None
        assert not planned_harness.target.dispatches
    finally:
        planned_harness.store.close()


@pytest.mark.asyncio
async def test_real_task_cancellation_during_blocking_authority_provider_aborts_once(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:blocking-authority-cancel",
    )
    provider = _BlockingAuthoritySnapshots(harness.authority_snapshots)
    harness.coordinator._authority_snapshots = provider
    baseline_tasks = asyncio.all_tasks()
    task = asyncio.create_task(harness.coordinator.transaction(harness.request))
    try:
        await asyncio.wait_for(provider.started.wait(), timeout=1)

        task.cancel()
        with pytest.raises(CancelledError):
            await asyncio.wait_for(task, timeout=1)

        status = harness.coordinator.status(
            "tenant:coordinator",
            harness.request.proposal.transaction_id,
        )
        events = harness.store.list_enforced_transaction_events(
            "tenant:coordinator",
            harness.request.proposal.transaction_id,
        )
        assert status.record.state is TransactionState.ABORTED
        assert tuple(event.target_state for event in events[-2:]) == (
            TransactionState.ABORTING,
            TransactionState.ABORTED,
        )
        assert not harness.target.dispatches
        stable_projection = (status.record.version, status.event_count)
        assert task.done()
        assert provider.finished.is_set()
        assert provider.active == 0
        assert provider.max_active == 1
        assert not {
            candidate
            for candidate in asyncio.all_tasks()
            if candidate not in baseline_tasks and not candidate.done()
        }

        provider.release.set()
        await asyncio.sleep(0)
        after_provider = harness.coordinator.status(
            "tenant:coordinator",
            harness.request.proposal.transaction_id,
        )
        assert (after_provider.record.version, after_provider.event_count) == stable_projection
        assert after_provider.record.state is TransactionState.ABORTED
        assert not harness.target.dispatches
    finally:
        provider.release.set()
        harness.store.close()


@pytest.mark.asyncio
async def test_real_task_cancellation_during_blocking_normalizer_aborts_without_late_plan(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:blocking-normalizer-cancel",
    )
    normalizers = _BlockingNormalizers(harness.normalizers)
    harness.coordinator._normalizers = normalizers
    baseline_tasks = asyncio.all_tasks()
    task = asyncio.create_task(harness.coordinator.transaction(harness.request))
    try:
        await asyncio.wait_for(normalizers.started.wait(), timeout=1)

        task.cancel()
        with pytest.raises(CancelledError):
            await asyncio.wait_for(task, timeout=1)

        status = harness.coordinator.status(
            "tenant:coordinator",
            harness.request.proposal.transaction_id,
        )
        assert status.record.state is TransactionState.ABORTED
        assert status.action is None
        assert not harness.target.dispatches
        stable_projection = (status.record.version, status.event_count)
        assert task.done()
        assert normalizers.finished.is_set()
        assert normalizers.active == 0
        assert not {
            candidate
            for candidate in asyncio.all_tasks()
            if candidate not in baseline_tasks and not candidate.done()
        }

        normalizers.release.set()
        await asyncio.sleep(0)
        after_normalizer = harness.coordinator.status(
            "tenant:coordinator",
            harness.request.proposal.transaction_id,
        )
        assert (after_normalizer.record.version, after_normalizer.event_count) == stable_projection
        assert after_normalizer.record.state is TransactionState.ABORTED
        assert after_normalizer.action is None
        assert not harness.target.dispatches
    finally:
        normalizers.release.set()
        harness.store.close()


@pytest.mark.asyncio
async def test_asyncio_timeout_during_blocking_policy_provider_aborts_without_late_dispatch(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:blocking-policy-timeout",
    )
    provider = _BlockingPolicyInputs(harness.policy_inputs)
    harness.coordinator._policy_inputs = provider
    baseline_tasks = asyncio.all_tasks()
    task = asyncio.create_task(harness.coordinator.transaction(harness.request))
    try:
        await asyncio.wait_for(provider.started.wait(), timeout=1)

        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.05):
                await task

        status = harness.coordinator.status(
            "tenant:coordinator",
            harness.request.proposal.transaction_id,
        )
        events = harness.store.list_enforced_transaction_events(
            "tenant:coordinator",
            harness.request.proposal.transaction_id,
        )
        assert status.record.state is TransactionState.ABORTED
        assert tuple(event.target_state for event in events[-2:]) == (
            TransactionState.ABORTING,
            TransactionState.ABORTED,
        )
        assert not harness.target.dispatches
        stable_projection = (status.record.version, status.event_count)
        assert task.done()
        assert provider.finished.is_set()
        assert provider.active == 0
        assert not {
            candidate
            for candidate in asyncio.all_tasks()
            if candidate not in baseline_tasks and not candidate.done()
        }

        provider.release.set()
        await asyncio.sleep(0)
        after_provider = harness.coordinator.status(
            "tenant:coordinator",
            harness.request.proposal.transaction_id,
        )
        assert (after_provider.record.version, after_provider.event_count) == stable_projection
        assert after_provider.record.state is TransactionState.ABORTED
        assert not harness.target.dispatches
    finally:
        provider.release.set()
        harness.store.close()


def test_all_coordinator_provider_contracts_are_async_first() -> None:
    assert inspect.iscoroutinefunction(AuthenticatedContextValidator.validate)
    assert inspect.iscoroutinefunction(AuthoritySnapshotProvider.snapshot_for)
    assert inspect.iscoroutinefunction(PolicyInputProvider.inputs_for)
    assert inspect.iscoroutinefunction(RecoveryActionFactory.create)
    assert inspect.iscoroutinefunction(NormalizerRegistry.normalize_async)
    assert not inspect.iscoroutinefunction(NormalizerRegistry.normalize)


@pytest.mark.asyncio
async def test_many_context_validator_cancellations_leave_no_tasks_threads_or_identity(
    tmp_path: Path,
) -> None:
    request_count = 48
    harness = support._make_harness(tmp_path)
    provider = _BlockingContextValidator(harness.context_validator, request_count)
    harness.coordinator._context_validator = provider
    requests = tuple(
        harness.request.model_copy(
            update={
                "proposal": harness.request.proposal.model_copy(
                    update={
                        "transaction_id": f"transaction:context-cancel-{index}",
                        "idempotency_key": f"idempotency:context-cancel-{index}",
                    }
                )
            }
        )
        for index in range(request_count)
    )
    baseline_tasks = asyncio.all_tasks()
    baseline_threads = {thread.ident for thread in threading.enumerate()}
    tasks = tuple(
        asyncio.create_task(harness.coordinator.transaction(request)) for request in requests
    )
    try:
        await asyncio.wait_for(provider.all_started.wait(), timeout=2)
        for task in tasks:
            task.cancel()
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=2,
        )

        assert all(isinstance(result, CancelledError) for result in results)
        assert provider.calls == request_count
        assert provider.finished == request_count
        assert provider.active == 0
        assert {thread.ident for thread in threading.enumerate()} == baseline_threads
        assert not {
            candidate
            for candidate in asyncio.all_tasks()
            if candidate not in baseline_tasks and not candidate.done()
        }
        with pytest.raises(AgentKernelError) as missing:
            harness.store.get_enforced_transaction(
                tenant_id=harness.request.presented_context.tenant_id,
                transaction_id=requests[0].proposal.transaction_id,
            )
        assert missing.value.code is ErrorCode.VALIDATION_ERROR
    finally:
        provider.release.set()
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_name", ["authority", "policy"])
async def test_internal_provider_deadline_aborts_with_stable_reason(
    tmp_path: Path,
    provider_name: str,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id=f"transaction:{provider_name}-internal-deadline",
    )
    request = harness.request.model_copy(
        update={
            "proposal": harness.request.proposal.model_copy(
                update={"deadline": harness.clock() + timedelta(milliseconds=200)}
            )
        }
    )
    if provider_name == "authority":
        provider = _BlockingAuthoritySnapshots(harness.authority_snapshots)
        harness.coordinator._authority_snapshots = provider
    else:
        provider = _BlockingPolicyInputs(harness.policy_inputs)
        harness.coordinator._policy_inputs = provider
    baseline_tasks = asyncio.all_tasks()
    try:
        with pytest.raises(AgentKernelError) as captured:
            await harness.coordinator.transaction(request)
        assert captured.value.code is ErrorCode.DEADLINE_EXCEEDED
        assert provider.finished.is_set()
        assert provider.active == 0

        status = harness.coordinator.status(
            request.presented_context.tenant_id,
            request.proposal.transaction_id,
        )
        events = harness.store.list_enforced_transaction_events(
            request.presented_context.tenant_id,
            request.proposal.transaction_id,
        )
        assert status.record.state is TransactionState.ABORTED
        assert tuple(event.target_state for event in events[-2:]) == (
            TransactionState.ABORTING,
            TransactionState.ABORTED,
        )
        deadline_record_ref = harness.store._connection.execute(
            "SELECT deadline_ref FROM enforced_transaction_recovery_deadlines "
            "WHERE tenant_id = ? AND transaction_id = ?",
            (
                request.presented_context.tenant_id,
                request.proposal.transaction_id,
            ),
        ).fetchone()[0]
        deadline_evidence = harness.artifacts.get_model(
            next(ref for ref in events[-2].evidence_refs if ref != deadline_record_ref),
            CoordinatorEvidence,
        )
        assert deadline_evidence.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert not harness.target.dispatches
        assert not {
            candidate
            for candidate in asyncio.all_tasks()
            if candidate not in baseline_tasks and not candidate.done()
        }
    finally:
        provider.release.set()
        harness.store.close()


@pytest.mark.asyncio
async def test_second_cancellation_during_recovery_factory_settles_before_reraise(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:recovery-factory-second-cancel",
        adapter_type=_BlockingAfterPrivateStageAdapter,
    )
    recovery_actions = _BlockingRecoveryActions(harness.recovery_actions)
    harness.coordinator._recovery_actions = recovery_actions
    session = await harness.coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    adapter = harness.adapter
    assert isinstance(adapter, _BlockingAfterPrivateStageAdapter)
    baseline_tasks = asyncio.all_tasks()
    task = asyncio.create_task(session.__aenter__())
    try:
        await asyncio.wait_for(adapter.stage_started.wait(), timeout=2)
        task.cancel()
        await asyncio.wait_for(recovery_actions.first_started.wait(), timeout=2)
        harness.clock.advance(timedelta(seconds=1))
        task.cancel()
        await asyncio.wait_for(recovery_actions.second_started.wait(), timeout=2)
        recovery_actions.release.set()

        with pytest.raises(CancelledError):
            await asyncio.wait_for(task, timeout=2)

        status = harness.coordinator.status(
            harness.request.presented_context.tenant_id,
            harness.request.proposal.transaction_id,
        )
        durable_recovery = harness.store.get_active_recovery_work(
            tenant_id=status.record.tenant_id,
            transaction_id=status.record.transaction_id,
        )
        assert status.record.state.is_terminal or durable_recovery
        assert status.record.state is TransactionState.ABORTED
        assert adapter.stage_finished.is_set()
        assert recovery_actions.calls == 2
        assert recovery_actions.max_active == 1
        assert recovery_actions.active == 0
        assert task.done()
        assert not {
            candidate
            for candidate in asyncio.all_tasks()
            if candidate not in baseline_tasks and not candidate.done()
        }

        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            harness.store = reopened
            reopened_status = _clone_coordinator(harness, store=reopened).status(
                status.record.tenant_id,
                status.record.transaction_id,
            )
            assert reopened_status.record.state is TransactionState.ABORTED
    finally:
        recovery_actions.release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        harness.store.close()


@pytest.mark.asyncio
async def test_cancellation_during_voluntary_cancel_is_rethrown_after_cleanup(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:voluntary-cancel-interrupted",
    )
    recovery_actions = _BlockingRecoveryActions(harness.recovery_actions)
    harness.coordinator._recovery_actions = recovery_actions
    session = await harness.coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    task = asyncio.create_task(session.cancel())
    try:
        await asyncio.wait_for(recovery_actions.first_started.wait(), timeout=2)
        task.cancel()
        await asyncio.wait_for(recovery_actions.second_started.wait(), timeout=2)
        recovery_actions.release.set()

        with pytest.raises(CancelledError):
            await asyncio.wait_for(task, timeout=2)

        assert task.cancelled()
        assert session.record.state is TransactionState.ABORTED
        assert recovery_actions.calls == 2
        assert recovery_actions.max_active == 1
        assert recovery_actions.active == 0
    finally:
        recovery_actions.release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        harness.store.close()


@pytest.mark.asyncio
async def test_cancel_and_recovery_scanner_serialize_recovery_factory(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:cancel-scanner-serialization",
    )
    recovery_actions = _BlockingRecoveryActions(harness.recovery_actions)
    harness.coordinator._recovery_actions = recovery_actions
    scanner_coordinator = _clone_coordinator(
        harness,
        recovery_actions=recovery_actions,
        config=EnforcedCoordinatorConfig(
            worker_id="worker:concurrent-recovery-scanner",
            lease_duration=timedelta(minutes=1),
            recovery_deadline=timedelta(minutes=4),
            reconciliation_backoff=timedelta(seconds=2),
        ),
    )
    session = await harness.coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    cancel_task = asyncio.create_task(session.cancel())
    scanner_task = None
    try:
        await asyncio.wait_for(recovery_actions.first_started.wait(), timeout=2)
        scanner_task = asyncio.create_task(
            scanner_coordinator.recover_once(session.record.tenant_id)
        )
        await asyncio.sleep(0.05)

        assert recovery_actions.calls == 1
        assert recovery_actions.active == 1
        assert recovery_actions.max_active == 1

        recovery_actions.release.set()
        cancelled_record, _ = await asyncio.wait_for(
            asyncio.gather(cancel_task, scanner_task),
            timeout=2,
        )
        status = harness.coordinator.status(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert cancelled_record.state is TransactionState.ABORTED
        assert status.record.state is TransactionState.ABORTED
        assert recovery_actions.calls == 1
        assert recovery_actions.max_active == 1
        assert recovery_actions.active == 0
        assert not harness.store.get_active_recovery_work(
            tenant_id=status.record.tenant_id,
            transaction_id=status.record.transaction_id,
        )
    finally:
        recovery_actions.release.set()
        for pending in (cancel_task, scanner_task):
            if pending is not None and not pending.done():
                pending.cancel()
        await asyncio.gather(
            *(pending for pending in (cancel_task, scanner_task) if pending is not None),
            return_exceptions=True,
        )
        harness.store.close()


@pytest.mark.asyncio
async def test_repeated_cancel_during_live_handoff_contention_waits_for_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:cancel-live-handoff-contention",
    )
    recovery_actions = _BlockingRecoveryActions(harness.recovery_actions)
    harness.coordinator._recovery_actions = recovery_actions
    contender = _clone_coordinator(
        harness,
        recovery_actions=recovery_actions,
        config=EnforcedCoordinatorConfig(
            worker_id="worker:cancelled-handoff-contender",
            lease_duration=timedelta(minutes=1),
            recovery_deadline=timedelta(minutes=4),
            reconciliation_backoff=timedelta(seconds=2),
        ),
    )
    session = await harness.coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    owner_task = asyncio.create_task(session.cancel())
    contender_task = None
    first_conflict = asyncio.Event()
    second_conflict = asyncio.Event()
    original_acquire = harness.store.acquire_recovery_handoff_lease
    conflict_count = 0
    coordination_timeout = 15.0

    def acquire_with_conflict_signal(**kwargs):
        nonlocal conflict_count
        try:
            return original_acquire(**kwargs)
        except AgentKernelError as error:
            if error.code is ErrorCode.VERSION_CONFLICT:
                conflict_count += 1
                if conflict_count == 1:
                    first_conflict.set()
                elif conflict_count == 2:
                    second_conflict.set()
            raise

    try:
        await asyncio.wait_for(
            recovery_actions.first_started.wait(),
            timeout=coordination_timeout,
        )
        monkeypatch.setattr(
            harness.store,
            "acquire_recovery_handoff_lease",
            acquire_with_conflict_signal,
        )
        aborting = harness.store.get_enforced_transaction(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert aborting.state is TransactionState.ABORTING
        contender_task = asyncio.create_task(contender._settle_abort_handoff(aborting))

        await asyncio.wait_for(first_conflict.wait(), timeout=coordination_timeout)
        contender_task.cancel("original-contention-cancel")
        await asyncio.wait_for(second_conflict.wait(), timeout=coordination_timeout)
        contender_task.cancel("repeated-contention-cancel")
        await asyncio.sleep(0)
        assert not contender_task.done()

        recovery_actions.release.set()
        owner_result = await asyncio.wait_for(owner_task, timeout=coordination_timeout)
        with pytest.raises(CancelledError) as captured:
            await asyncio.wait_for(contender_task, timeout=coordination_timeout)

        assert captured.value.args == ("original-contention-cancel",)
        assert owner_result.state is TransactionState.ABORTED
        assert contender_task.cancelled()
        assert recovery_actions.calls == 1
        assert recovery_actions.max_active == 1
        assert recovery_actions.active == 0
        assert not harness.store.get_active_recovery_work(
            tenant_id=aborting.tenant_id,
            transaction_id=aborting.transaction_id,
        )
    finally:
        recovery_actions.release.set()
        for pending in (owner_task, contender_task):
            if pending is not None and not pending.done():
                pending.cancel()
        await asyncio.gather(
            *(pending for pending in (owner_task, contender_task) if pending is not None),
            return_exceptions=True,
        )
        harness.store.close()


@pytest.mark.asyncio
async def test_recovery_factory_internal_deadline_finishes_abort_fail_closed(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:recovery-factory-deadline",
    )
    recovery_actions = _BlockingRecoveryActions(harness.recovery_actions)
    coordinator = _clone_coordinator(
        harness,
        recovery_actions=recovery_actions,
        config=EnforcedCoordinatorConfig(
            worker_id="worker:recovery-factory-deadline",
            lease_duration=timedelta(minutes=1),
            recovery_deadline=timedelta(milliseconds=200),
            reconciliation_backoff=timedelta(seconds=2),
        ),
    )
    session = await coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    baseline_tasks = asyncio.all_tasks()
    try:
        record = await asyncio.wait_for(session.cancel(), timeout=2)

        assert record.state is TransactionState.RECOVERY_FAILED
        assert record.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert recovery_actions.calls == 1
        assert recovery_actions.active == 0
        assert recovery_actions.max_active == 1
        stage = harness.store.get_stage_material(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        assert stage.state is StageMaterialState.DISCARD_FAILED
        assert stage.discard_evidence_ref is not None
        intent_attempt = harness.store.get_intent_attempt(
            tenant_id=record.tenant_id,
            intent_hash=session.action.intent_hash,
            transaction_id=record.transaction_id,
        )
        assert intent_attempt.state is IntentAttemptState.REVIEW_REQUIRED
        assert intent_attempt.evidence_digest == stage.discard_evidence_ref
        failure_evidence = harness.artifacts.get_model(
            stage.discard_evidence_ref,
            CoordinatorEvidence,
        )
        assert failure_evidence.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert failure_evidence.event == TransitionEvent.STAGING_DISCARD_FAILED.value
        assert not harness.store.get_active_recovery_work(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        with pytest.raises(AgentKernelError) as no_dispatch:
            harness.store.get_commit_dispatch(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
        assert no_dispatch.value.code is ErrorCode.VALIDATION_ERROR
        assert not {
            candidate
            for candidate in asyncio.all_tasks()
            if candidate not in baseline_tasks and not candidate.done()
        }
    finally:
        recovery_actions.release.set()
        harness.store.close()


@pytest.mark.asyncio
async def test_recovery_policy_deadline_closes_registered_recovery_intent(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:recovery-policy-deadline",
    )
    recovery_actions = _RecordingRecoveryActions(harness.recovery_actions)
    policy_inputs = _BlockingRecoveryPolicyInputs(harness.policy_inputs)
    coordinator = _clone_coordinator(
        harness,
        recovery_actions=recovery_actions,
        policy_inputs=policy_inputs,
        config=EnforcedCoordinatorConfig(
            worker_id="worker:recovery-policy-deadline",
            lease_duration=timedelta(minutes=1),
            recovery_deadline=timedelta(milliseconds=200),
            reconciliation_backoff=timedelta(seconds=2),
        ),
    )
    session = await coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    try:
        record = await asyncio.wait_for(session.cancel(), timeout=2)

        assert record.state is TransactionState.RECOVERY_FAILED
        assert record.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert policy_inputs.started.is_set()
        assert policy_inputs.finished.is_set()
        assert policy_inputs.active == 0
        assert recovery_actions.action is not None
        recovery_attempt = harness.store.get_intent_attempt(
            tenant_id=recovery_actions.action.tenant_id,
            intent_hash=recovery_actions.action.intent_hash,
            transaction_id=recovery_actions.action.transaction_id,
        )
        assert recovery_attempt.state is IntentAttemptState.NO_EFFECT_CONFIRMED
        assert not harness.store.get_active_recovery_work(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        with pytest.raises(AgentKernelError) as no_dispatch:
            harness.store.get_commit_dispatch(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
            )
        assert no_dispatch.value.code is ErrorCode.VALIDATION_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_recovery_policy_unknown_closes_discard_handoff_for_review(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:recovery-review-required-handoff",
        adapter_type=support._ControlledVerificationAdapter,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    recovery_actions = _RecordingRecoveryActions(harness.recovery_actions)
    policy_inputs = _PurposePolicyInputs(
        harness.clock,
        {AuthorizationRoundPurpose.RECOVERY: "unknown"},
    )
    coordinator = _clone_coordinator(
        harness,
        recovery_actions=recovery_actions,
        policy_inputs=policy_inputs,
    )
    session = await coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    try:
        record = await session.cancel()
        assert record.state is TransactionState.RECOVERY_FAILED
        work = harness.store.list_recovery_work(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        assert len(work) == 1
        assert work[0].state is RecoveryWorkState.REVIEW_REQUIRED
        assert work[0].reason_code == ErrorCode.POLICY_UNKNOWN.value
        _assert_discard_target_closed(
            harness,
            work[0],
            recovery_intent_state=IntentAttemptState.NO_EFFECT_CONFIRMED,
        )
        recovery_action = harness.store.get_normalized_action(
            work[0].tenant_id,
            work[0].recovery_action_transaction_id,
        ).action
        with pytest.raises(AgentKernelError) as no_recovery_reservation:
            harness.store.get_capability_chain(
                tenant_id=recovery_action.tenant_id,
                goal_id=recovery_action.goal_id,
                run_id=recovery_action.run_id,
                intent_hash=recovery_action.intent_hash,
            )
        assert no_recovery_reservation.value.code is ErrorCode.AUTHORITY_MISSING
        assert adapter.abort_stage_calls == 0

        started_at = asyncio.get_running_loop().time()
        scan = await asyncio.wait_for(coordinator.recover_once(record.tenant_id), timeout=0.5)
        elapsed = asyncio.get_running_loop().time() - started_at

        assert elapsed < 0.2
        assert scan.processed == 0
        assert not scan.failures
        assert recovery_actions.calls == 1
        assert (
            harness.store.get_enforced_transaction(record.tenant_id, record.transaction_id).state
            is TransactionState.RECOVERY_FAILED
        )
        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            assert reopened.count_recovery_candidates(tenant_id=record.tenant_id) == 0
            reopened_handoff = reopened.get_recovery_action_handoff(
                tenant_id=work[0].tenant_id,
                target_transaction_id=work[0].transaction_id,
                recovery_id=work[0].recovery_id,
            )
            assert reopened_handoff is not None
            assert reopened_handoff.closed_at == work[0].updated_at
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_failure_after_recovery_action_registration_closes_intent_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:recovery-post-registration-failure",
    )
    recovery_actions = _RecordingRecoveryActions(harness.recovery_actions)
    coordinator = _clone_coordinator(harness, recovery_actions=recovery_actions)
    original_put_evidence = coordinator._put_control_evidence

    def fail_approval_evidence(**kwargs):
        if kwargs["event"] == "recovery.approval_not_required":
            raise OSError("synthetic post-registration evidence failure")
        return original_put_evidence(**kwargs)

    monkeypatch.setattr(coordinator, "_put_control_evidence", fail_approval_evidence)
    session = await coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    try:
        record = await session.cancel()

        assert record.state is TransactionState.RECOVERY_FAILED
        assert record.reason_code == "RECOVERY_AUTHORIZATION_FAILED"
        assert recovery_actions.action is not None
        recovery_attempt = harness.store.get_intent_attempt(
            tenant_id=recovery_actions.action.tenant_id,
            intent_hash=recovery_actions.action.intent_hash,
            transaction_id=recovery_actions.action.transaction_id,
        )
        assert recovery_attempt.state is IntentAttemptState.NO_EFFECT_CONFIRMED
        failed_stage = harness.store.get_stage_material(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        assert failed_stage.state is StageMaterialState.DISCARD_FAILED
        assert not harness.store.get_active_recovery_work(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        active_lease_count = harness.store._connection.execute(
            "SELECT COUNT(*) FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
            (record.tenant_id, record.transaction_id),
        ).fetchone()[0]
        assert active_lease_count == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_restart_resumes_registered_action_after_handoff_owner_dies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:recovery-registered-action-crash",
        adapter_type=support._ControlledVerificationAdapter,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    recovery_actions = _RecordingRecoveryActions(harness.recovery_actions)
    coordinator = _clone_coordinator(harness, recovery_actions=recovery_actions)
    original_register = harness.store.register_recovery_action
    original_release = harness.store.release_worker_lease

    def crash_after_register(action, *, registered_at, binding):
        original_register(action, registered_at=registered_at, binding=binding)
        raise SimulatedProcessDeath

    def abandon_recovery_handoff(**kwargs):
        lease = harness.store.get_worker_lease(
            tenant_id=kwargs["tenant_id"],
            transaction_id=kwargs["transaction_id"],
            lease_id=kwargs["lease_id"],
        )
        if lease.purpose is LeasePurpose.RECOVERY:
            return lease
        return original_release(**kwargs)

    session = await coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    try:
        monkeypatch.setattr(
            harness.store,
            "register_recovery_action",
            crash_after_register,
        )
        monkeypatch.setattr(
            harness.store,
            "release_worker_lease",
            abandon_recovery_handoff,
        )
        with pytest.raises(SimulatedProcessDeath):
            await session.cancel()

        crashed = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert crashed.state is TransactionState.ABORTING
        assert recovery_actions.action is not None
        orphaned_attempt = harness.store.get_intent_attempt(
            tenant_id=recovery_actions.action.tenant_id,
            intent_hash=recovery_actions.action.intent_hash,
            transaction_id=recovery_actions.action.transaction_id,
        )
        assert orphaned_attempt.state is IntentAttemptState.ACTIVE
        assert not harness.store.list_recovery_work(
            tenant_id=crashed.tenant_id,
            transaction_id=crashed.transaction_id,
        )

        monkeypatch.setattr(
            harness.store,
            "register_recovery_action",
            original_register,
        )
        monkeypatch.setattr(
            harness.store,
            "release_worker_lease",
            original_release,
        )
        harness.clock.advance(timedelta(minutes=1, microseconds=1))
        restarted = _clone_coordinator(
            harness,
            recovery_actions=recovery_actions,
            config=EnforcedCoordinatorConfig(
                worker_id="worker:registered-action-restart",
                lease_duration=timedelta(minutes=1),
                recovery_deadline=timedelta(minutes=4),
                reconciliation_backoff=timedelta(seconds=2),
            ),
        )
        result = await restarted.recover_once(crashed.tenant_id)

        assert result.processed == 1
        assert not result.failures
        assert result.statuses[0].record.state is TransactionState.ABORTED
        assert recovery_actions.calls == 1
        assert adapter.abort_stage_calls == 1
        completed_attempt = harness.store.get_intent_attempt(
            tenant_id=recovery_actions.action.tenant_id,
            intent_hash=recovery_actions.action.intent_hash,
            transaction_id=recovery_actions.action.transaction_id,
        )
        assert completed_attempt.state is IntentAttemptState.COMMITTED
        active_lease_count = harness.store._connection.execute(
            "SELECT COUNT(*) FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
            (crashed.tenant_id, crashed.transaction_id),
        ).fetchone()[0]
        assert active_lease_count == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_transition_persists_recovery_deadline_before_first_claim(
    tmp_path: Path,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:deadline-before-first-claim",
        adapter_type=support._ControlledVerificationAdapter,
    )
    recovery_actions = _RecordingRecoveryActions(harness.recovery_actions)
    staging_lease_duration = timedelta(minutes=1)
    recovery_deadline = timedelta(seconds=4)

    def crash_after_aborting(point: CoordinatorCrashPoint) -> None:
        if point is CoordinatorCrashPoint.AFTER_ABORTING:
            raise SimulatedProcessDeath

    coordinator = _clone_coordinator(
        harness,
        recovery_actions=recovery_actions,
        config=EnforcedCoordinatorConfig(
            worker_id="worker:old-deadline",
            lease_duration=staging_lease_duration,
            recovery_deadline=recovery_deadline,
            reconciliation_backoff=timedelta(seconds=1),
            crash_hook=crash_after_aborting,
        ),
    )
    session = await coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    try:
        # Leave ample real time for coverage-instrumented staging while positioning
        # the fake clock so the old lease and durable recovery deadline expire
        # before the unchanged five-second restart scan.
        harness.clock.advance(staging_lease_duration - recovery_deadline)
        with pytest.raises(CoordinatorInjectedCrash):
            await session.cancel()

        crashed = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert crashed.state is TransactionState.ABORTING
        durable_deadline = harness.store.get_transaction_recovery_deadline(
            tenant_id=crashed.tenant_id,
            transaction_id=crashed.transaction_id,
        )
        assert durable_deadline == crashed.updated_at + recovery_deadline
        deadline_row = harness.store._connection.execute(
            "SELECT deadline_ref, transaction_version "
            "FROM enforced_transaction_recovery_deadlines "
            "WHERE tenant_id = ? AND transaction_id = ?",
            (crashed.tenant_id, crashed.transaction_id),
        ).fetchone()
        transition_event = harness.store.list_enforced_transaction_events(
            crashed.tenant_id,
            crashed.transaction_id,
        )[deadline_row["transaction_version"]]
        assert deadline_row["deadline_ref"] in transition_event.evidence_refs
        assert not harness.store.list_recovery_action_handoffs(
            tenant_id=crashed.tenant_id,
            target_transaction_id=crashed.transaction_id,
        )

        harness.clock.advance(timedelta(seconds=5))
        restarted = _clone_coordinator(
            harness,
            recovery_actions=recovery_actions,
            config=EnforcedCoordinatorConfig(
                worker_id="worker:new-longer-deadline",
                lease_duration=timedelta(seconds=1),
                recovery_deadline=timedelta(seconds=20),
                reconciliation_backoff=timedelta(seconds=1),
            ),
        )
        result = await restarted.recover_once(crashed.tenant_id)

        assert not result.failures
        assert result.statuses[0].record.state is TransactionState.RECOVERY_FAILED
        assert result.statuses[0].record.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert recovery_actions.calls == 0
        adapter = harness.adapter
        assert isinstance(adapter, support._ControlledVerificationAdapter)
        assert adapter.abort_stage_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_recovery_lease_atomically_reserves_binding_before_factory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    lease_duration = timedelta(minutes=1)
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:atomic-lease-binding",
        adapter_type=support._ControlledVerificationAdapter,
    )
    recovery_actions = _RecordingRecoveryActions(harness.recovery_actions)
    coordinator = _clone_coordinator(
        harness,
        recovery_actions=recovery_actions,
        config=EnforcedCoordinatorConfig(
            worker_id="worker:atomic-lease-binding",
            lease_duration=lease_duration,
            recovery_deadline=timedelta(seconds=4),
            reconciliation_backoff=timedelta(seconds=1),
        ),
    )

    async def die_after_atomic_acquire(*_args, **_kwargs):
        raise SimulatedProcessDeath

    session = await coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    monkeypatch.setattr(
        coordinator,
        "_authorize_recovery_work_claimed",
        die_after_atomic_acquire,
    )
    try:
        with pytest.raises(SimulatedProcessDeath):
            await session.cancel()

        crashed = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=crashed.tenant_id,
            target_transaction_id=crashed.transaction_id,
        )
        assert len(handoffs) == 1
        assert handoffs[0].action is None
        assert handoffs[0].binding.absolute_deadline == crashed.updated_at + timedelta(seconds=4)
        assert recovery_actions.calls == 0

        harness.clock.advance(timedelta(seconds=5))
        restarted = _clone_coordinator(
            harness,
            recovery_actions=recovery_actions,
            config=EnforcedCoordinatorConfig(
                worker_id="worker:atomic-lease-restart",
                lease_duration=timedelta(seconds=1),
                recovery_deadline=timedelta(seconds=20),
                reconciliation_backoff=timedelta(seconds=1),
            ),
        )
        result = await restarted.recover_once(crashed.tenant_id)

        assert len(result.failures) == 1
        assert result.failures[0].reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert result.failures[0].evidence_ref is not None
        assert result.statuses[0].record.state is TransactionState.RECOVERY_FAILED
        assert recovery_actions.calls == 0
        closed = harness.store.list_recovery_action_handoffs(
            tenant_id=crashed.tenant_id,
            target_transaction_id=crashed.transaction_id,
        )[0]
        assert closed.closed_at == harness.clock()
        assert closed.failure_reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        evidence = harness.artifacts.get_model(
            result.failures[0].evidence_ref,
            CoordinatorEvidence,
        )
        assert evidence.event == TransitionEvent.STAGING_DISCARD_FAILED.value
        assert evidence.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert evidence.subject_ref == closed.binding.target_evidence_ref
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_duplicate_open_prework_handoff_is_rejected_without_new_lease(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:duplicate-open-prework-handoff",
    )
    session = await harness.coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    database_path = harness.store.path
    try:
        transitioned = harness.store.apply_control_transition(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
            expected_version=session.record.version,
            transition_event=TransitionEvent.CONTEXT_EXITED,
            recorded_at=harness.clock(),
            evidence_refs=(canonical_digest(session.action),),
            reason_code="DUPLICATE_OPEN_PREWORK_HANDOFF_TEST",
            recovery_timeout=harness.coordinator._config.recovery_deadline,
        )
        stage = harness.store.get_stage_material(
            tenant_id=transitioned.transaction.tenant_id,
            transaction_id=transitioned.transaction.transaction_id,
        )
        staging_lease = harness.store.get_worker_lease(
            tenant_id=stage.tenant_id,
            transaction_id=stage.transaction_id,
            lease_id=stage.lease_id,
        )
        harness.store.release_worker_lease(
            tenant_id=staging_lease.tenant_id,
            transaction_id=staging_lease.transaction_id,
            lease_id=staging_lease.lease_id,
            expected_version=staging_lease.version,
            released_at=harness.clock(),
        )
        stage_target_ref = harness.artifacts.put_model(stage).digest
        first_binding = harness.coordinator._stage_recovery_binding(
            transitioned.transaction,
            stage,
            stage_target_ref=stage_target_ref,
        )
        first = harness.store.acquire_recovery_handoff_lease(
            tenant_id=stage.tenant_id,
            transaction_id=stage.transaction_id,
            expected_transaction_version=transitioned.transaction.version,
            stage_id=stage.stage_id,
            expected_stage_version=stage.version,
            stage_target_ref=stage_target_ref,
            lease_id="lease:first-open-prework-handoff",
            worker_id="worker:first-open-prework-handoff",
            acquired_at=harness.clock(),
            expires_at=harness.clock() + timedelta(minutes=1),
            binding=first_binding,
        )
        harness.store.release_worker_lease(
            tenant_id=first.lease.tenant_id,
            transaction_id=first.lease.transaction_id,
            lease_id=first.lease.lease_id,
            expected_version=first.lease.version,
            released_at=harness.clock(),
        )
        before_lease_rows = harness.store._connection.execute(
            "SELECT COUNT(*), MAX(fencing_token) FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ?",
            (stage.tenant_id, stage.transaction_id),
        ).fetchone()
        duplicate_binding = first_binding.model_copy(
            update={
                "recovery_id": "recovery:duplicate-open-prework-handoff",
                "root_recovery_id": "recovery:duplicate-open-prework-handoff",
            }
        )

        with pytest.raises(AgentKernelError) as duplicate:
            harness.store.acquire_recovery_handoff_lease(
                tenant_id=stage.tenant_id,
                transaction_id=stage.transaction_id,
                expected_transaction_version=transitioned.transaction.version,
                stage_id=stage.stage_id,
                expected_stage_version=stage.version,
                stage_target_ref=stage_target_ref,
                lease_id="lease:duplicate-open-prework-handoff",
                worker_id="worker:duplicate-open-prework-handoff",
                acquired_at=harness.clock(),
                expires_at=harness.clock() + timedelta(minutes=1),
                binding=duplicate_binding,
            )

        assert duplicate.value.code is ErrorCode.VERSION_CONFLICT
        after_lease_rows = harness.store._connection.execute(
            "SELECT COUNT(*), MAX(fencing_token) FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ?",
            (stage.tenant_id, stage.transaction_id),
        ).fetchone()
        assert tuple(after_lease_rows) == tuple(before_lease_rows)
        handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=stage.tenant_id,
            target_transaction_id=stage.transaction_id,
        )
        assert len(handoffs) == 1
        assert handoffs[0].binding == first_binding
        assert handoffs[0].action is None
        assert handoffs[0].closed_at is None

        same_timestamp = harness.store.acquire_recovery_handoff_lease(
            tenant_id=stage.tenant_id,
            transaction_id=stage.transaction_id,
            expected_transaction_version=transitioned.transaction.version,
            stage_id=stage.stage_id,
            expected_stage_version=stage.version,
            stage_target_ref=stage_target_ref,
            lease_id="lease:same-time-prework-reacquire",
            worker_id="worker:same-time-prework-reacquire",
            acquired_at=harness.clock(),
            expires_at=harness.clock() + timedelta(minutes=1),
            binding=first_binding,
        )
        assert same_timestamp.lease.fencing_token > first.lease.fencing_token
        harness.store.release_worker_lease(
            tenant_id=same_timestamp.lease.tenant_id,
            transaction_id=same_timestamp.lease.transaction_id,
            lease_id=same_timestamp.lease.lease_id,
            expected_version=same_timestamp.lease.version,
            released_at=harness.clock(),
        )

        harness.clock.advance(timedelta(seconds=2))
        reacquired = harness.store.acquire_recovery_handoff_lease(
            tenant_id=stage.tenant_id,
            transaction_id=stage.transaction_id,
            expected_transaction_version=transitioned.transaction.version,
            stage_id=stage.stage_id,
            expected_stage_version=stage.version,
            stage_target_ref=stage_target_ref,
            lease_id="lease:valid-prework-reacquire",
            worker_id="worker:valid-prework-reacquire",
            acquired_at=harness.clock(),
            expires_at=harness.clock() + timedelta(minutes=1),
            binding=first_binding,
        )
        assert reacquired.lease.fencing_token > first.lease.fencing_token
        rebound = harness.store.list_recovery_action_handoffs(
            tenant_id=stage.tenant_id,
            target_transaction_id=stage.transaction_id,
        )[0]
        assert rebound.handoff_lease_id == first.lease.lease_id
        assert rebound.handoff_worker_id == first.lease.worker_id
        assert rebound.handoff_fencing_token == first.lease.fencing_token

        harness.store.close()
        with SQLiteEnforcedTransactionStore(database_path) as reopened:
            assert (
                reopened.list_recovery_action_handoffs(
                    tenant_id=stage.tenant_id,
                    target_transaction_id=stage.transaction_id,
                )
                == handoffs
            )
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_preexisting_recovery_action_attaches_at_cas_time_and_reopens(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:preexisting-recovery-action",
    )
    session = await harness.coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    database_path = harness.store.path
    reopened: SQLiteEnforcedTransactionStore | None = None
    try:
        transitioned = harness.store.apply_control_transition(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
            expected_version=session.record.version,
            transition_event=TransitionEvent.CONTEXT_EXITED,
            recorded_at=harness.clock(),
            evidence_refs=(canonical_digest(session.action),),
            reason_code="PREEXISTING_RECOVERY_ACTION_TEST",
            recovery_timeout=timedelta(minutes=4),
        )
        stage = harness.store.get_stage_material(
            tenant_id=transitioned.transaction.tenant_id,
            transaction_id=transitioned.transaction.transaction_id,
        )
        staging_lease = harness.store.get_worker_lease(
            tenant_id=stage.tenant_id,
            transaction_id=stage.transaction_id,
            lease_id=stage.lease_id,
        )
        harness.store.release_worker_lease(
            tenant_id=staging_lease.tenant_id,
            transaction_id=staging_lease.transaction_id,
            lease_id=staging_lease.lease_id,
            expected_version=staging_lease.version,
            released_at=harness.clock(),
        )
        stage_ref = harness.artifacts.put_model(stage).digest
        binding = harness.coordinator._stage_recovery_binding(
            transitioned.transaction,
            stage,
            stage_target_ref=stage_ref,
        )
        harness.artifacts.put_model(binding)
        action = await harness.recovery_actions.create(
            target=transitioned.transaction,
            target_action=session.action,
            kind=binding.recovery_kind,
            target_evidence_ref=stage_ref,
            binding=binding,
            deadline=binding.absolute_deadline,
        )
        harness.store.register_recovery_action(
            action,
            registered_at=harness.clock(),
        )
        original_recorded_at = harness.store.get_normalized_action(
            action.tenant_id,
            action.transaction_id,
        ).recorded_at
        harness.clock.advance(timedelta(seconds=1))
        handoff_lease = harness.store.acquire_recovery_handoff_lease(
            tenant_id=stage.tenant_id,
            transaction_id=stage.transaction_id,
            expected_transaction_version=transitioned.transaction.version,
            stage_id=stage.stage_id,
            expected_stage_version=stage.version,
            stage_target_ref=stage_ref,
            lease_id="lease:preexisting-recovery-action",
            worker_id="worker:preexisting-recovery-action",
            acquired_at=harness.clock(),
            expires_at=harness.clock() + timedelta(minutes=1),
            binding=binding,
        )
        harness.store.register_recovery_action(
            action,
            registered_at=harness.clock(),
            binding=binding,
        )
        attached = harness.store.get_recovery_action_handoff(
            tenant_id=stage.tenant_id,
            target_transaction_id=stage.transaction_id,
            recovery_id=binding.recovery_id,
        )
        assert attached is not None
        assert attached.action == action
        assert attached.attached_at == harness.clock()
        assert attached.attached_at > original_recorded_at
        query_plan = harness.store._connection.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM enforced_recovery_action_handoffs "
            "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
            (stage.tenant_id, stage.transaction_id, binding.recovery_id),
        ).fetchall()
        assert any("SEARCH" in str(row[3]) and "INDEX" in str(row[3]) for row in query_plan)
        harness.store.release_worker_lease(
            tenant_id=handoff_lease.lease.tenant_id,
            transaction_id=handoff_lease.lease.transaction_id,
            lease_id=handoff_lease.lease.lease_id,
            expected_version=handoff_lease.lease.version,
            released_at=harness.clock(),
        )

        harness.store.close()
        reopened = SQLiteEnforcedTransactionStore(database_path)
        restored = reopened.get_recovery_action_handoff(
            tenant_id=stage.tenant_id,
            target_transaction_id=stage.transaction_id,
            recovery_id=binding.recovery_id,
        )
        assert restored == attached
    finally:
        if reopened is not None:
            reopened.close()
        else:
            harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper_mode", ["extend", "delete"])
async def test_recovery_deadline_tamper_is_rejected_on_reopen(
    tmp_path: Path,
    tamper_mode: str,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id=f"transaction:deadline-tamper-{tamper_mode}",
    )
    session = await harness.coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    terminal = await session.cancel()
    assert terminal.state is TransactionState.ABORTED
    database_path = harness.store.path
    harness.store.close()

    raw = sqlite3.connect(database_path)
    try:
        raw.execute("DROP TRIGGER enforced_transactions_recovery_deadline_immutable")
        if tamper_mode == "extend":
            raw.execute(
                "UPDATE enforced_transactions SET recovery_deadline = ? "
                "WHERE tenant_id = ? AND transaction_id = ?",
                ("2099-01-01T00:00:00.000000Z", terminal.tenant_id, terminal.transaction_id),
            )
        else:
            raw.execute("DROP TRIGGER enforced_transaction_recovery_deadlines_no_delete")
            raw.execute(
                "DELETE FROM enforced_transaction_recovery_deadlines "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (terminal.tenant_id, terminal.transaction_id),
            )
            raw.execute(
                "UPDATE enforced_transactions SET recovery_deadline = NULL "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (terminal.tenant_id, terminal.transaction_id),
            )
        raw.commit()
    finally:
        raw.close()

    with pytest.raises(AgentKernelError) as captured:
        SQLiteEnforcedTransactionStore(database_path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.asyncio
async def test_expired_recovery_handoff_lease_can_fail_closed(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:expired-recovery-handoff-lease",
    )
    session = await harness.coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    try:
        transitioned = harness.store.apply_control_transition(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
            expected_version=session.record.version,
            transition_event=TransitionEvent.CONTEXT_EXITED,
            recorded_at=harness.clock(),
            evidence_refs=(canonical_digest(session.action),),
            reason_code="EXPIRED_HANDOFF_TEST",
            recovery_timeout=harness.coordinator._config.recovery_deadline,
        )
        stage = harness.store.get_stage_material(
            tenant_id=transitioned.transaction.tenant_id,
            transaction_id=transitioned.transaction.transaction_id,
        )
        staging_lease = harness.store.get_worker_lease(
            tenant_id=stage.tenant_id,
            transaction_id=stage.transaction_id,
            lease_id=stage.lease_id,
        )
        harness.store.release_worker_lease(
            tenant_id=staging_lease.tenant_id,
            transaction_id=staging_lease.transaction_id,
            lease_id=staging_lease.lease_id,
            expected_version=staging_lease.version,
            released_at=harness.clock(),
        )
        stage_target_ref = harness.artifacts.put_model(stage).digest
        binding = harness.coordinator._stage_recovery_binding(
            transitioned.transaction,
            stage,
            stage_target_ref=stage_target_ref,
        )
        handoff = harness.store.acquire_recovery_handoff_lease(
            tenant_id=stage.tenant_id,
            transaction_id=stage.transaction_id,
            expected_transaction_version=transitioned.transaction.version,
            stage_id=stage.stage_id,
            expected_stage_version=stage.version,
            stage_target_ref=stage_target_ref,
            lease_id="lease:expired-recovery-handoff",
            worker_id="worker:crashed-recovery-handoff",
            acquired_at=harness.clock(),
            expires_at=harness.clock() + timedelta(seconds=1),
            binding=binding,
        )
        harness.clock.advance(timedelta(seconds=2))

        failed = harness.coordinator._abort_handoff_failure(
            transitioned.transaction,
            reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
        )

        assert failed.state is TransactionState.RECOVERY_FAILED
        assert failed.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        failed_stage = harness.store.get_stage_material(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )
        assert failed_stage.state is StageMaterialState.DISCARD_FAILED
        attempt = harness.store.get_intent_attempt(
            tenant_id=failed.tenant_id,
            intent_hash=session.action.intent_hash,
            transaction_id=failed.transaction_id,
        )
        assert attempt.state is IntentAttemptState.REVIEW_REQUIRED
        released_handoff = harness.store.get_worker_lease(
            tenant_id=handoff.lease.tenant_id,
            transaction_id=handoff.lease.transaction_id,
            lease_id=handoff.lease.lease_id,
        )
        assert released_handoff.released_at == harness.clock()
        assert not harness.store.get_active_recovery_work(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_unattached_recovery_handoff_evidence_survives_status_audit_and_reopen(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:unattached-recovery-handoff",
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    try:
        session = await _crash_during_commit(harness)
        coordinator = await _stop_dispatch_before_explicit_resume(harness, session)
        record = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        observed_at = harness.clock()
        binding = coordinator._propose_recovery_action_binding(
            record,
            kind=RecoveryWorkKind.RECONCILE_DISPATCH,
            target=dispatch,
            target_ref=canonical_digest(dispatch),
            observed_at=observed_at,
            predecessor=None,
        )
        claimed = harness.store.acquire_recovery_authorization_lease(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
            expected_transaction_version=record.version,
            kind=RecoveryWorkKind.RECONCILE_DISPATCH,
            dispatch_id=dispatch.dispatch_id,
            dispatch_target_ref=canonical_digest(dispatch),
            recovery_id=binding.recovery_id,
            lease_id="lease:unattached-recovery-handoff",
            worker_id="worker:unattached-recovery-handoff",
            acquired_at=observed_at,
            expires_at=min(binding.absolute_deadline, observed_at + timedelta(minutes=1)),
            binding=binding,
        )
        failed = coordinator._fail_unattached_recovery_action(
            record,
            binding=binding,
            reason_code="SYNTHETIC_UNATTACHED_FAILURE",
            handoff_lease=claimed.lease,
        )
        handoff = harness.store.get_recovery_action_handoff(
            tenant_id=record.tenant_id,
            target_transaction_id=record.transaction_id,
            recovery_id=binding.recovery_id,
        )
        assert handoff is not None
        assert handoff.action is None
        assert handoff.failure_evidence_status is (RecoveryHandoffFailureEvidenceStatus.AVAILABLE)
        exact = harness.store.fail_recovery_action_handoff(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
            expected_transaction_version=record.version,
            recovery_id=binding.recovery_id,
            failure_evidence_ref=handoff.failure_evidence_ref,
            reason_code="SYNTHETIC_UNATTACHED_FAILURE",
            recorded_at=observed_at,
            handoff_lease=claimed.lease,
        )
        assert exact.transaction == failed
        with pytest.raises(AgentKernelError) as changed_time:
            harness.store.fail_recovery_action_handoff(
                tenant_id=record.tenant_id,
                transaction_id=record.transaction_id,
                expected_transaction_version=record.version,
                recovery_id=binding.recovery_id,
                failure_evidence_ref=handoff.failure_evidence_ref,
                reason_code="SYNTHETIC_UNATTACHED_FAILURE",
                recorded_at=observed_at + timedelta(microseconds=1),
                handoff_lease=claimed.lease,
            )
        assert changed_time.value.code is ErrorCode.INTEGRITY_ERROR
        assert coordinator.status(record.tenant_id, record.transaction_id).record == failed
        projection = harness.store.get_transaction_projection(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        terminal = coordinator._recovery_terminal_failure(projection)
        assert terminal is not None
        assert terminal.reason_code == "SYNTHETIC_UNATTACHED_FAILURE"
        assert terminal.evidence_ref == handoff.failure_evidence_ref
        audit_failures, checkpoint = coordinator._audit_tenant_recovery_handoff_evidence(
            record.tenant_id,
            observed_at=harness.clock(),
            force=True,
        )
        assert not audit_failures
        assert checkpoint.current_cycle_complete

        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            harness.store = reopened
            reopened_coordinator = _clone_coordinator(harness, store=reopened)
            assert (
                reopened_coordinator.status(record.tenant_id, record.transaction_id).record
                == failed
            )
            audit_failures, checkpoint = (
                reopened_coordinator._audit_tenant_recovery_handoff_evidence(
                    record.tenant_id,
                    observed_at=harness.clock(),
                    force=True,
                )
            )
            assert not audit_failures
            assert checkpoint.current_cycle_complete
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_failed_recovery_handoff_rolls_back_stage_intent_and_transaction(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        transaction_id="transaction:recovery-handoff-atomic-rollback",
    )
    session = await harness.coordinator.transaction(harness.request)
    assert not isinstance(session, EnforcedTransactionStatus)
    await session.__aenter__()
    transitioned = harness.store.apply_control_transition(
        tenant_id=session.record.tenant_id,
        transaction_id=session.record.transaction_id,
        expected_version=session.record.version,
        transition_event=TransitionEvent.CONTEXT_EXITED,
        recorded_at=harness.clock(),
        evidence_refs=(canonical_digest(session.action),),
        reason_code="ATOMIC_ROLLBACK_TEST",
        recovery_timeout=harness.coordinator._config.recovery_deadline,
    )
    stage = harness.store.get_stage_material(
        tenant_id=transitioned.transaction.tenant_id,
        transaction_id=transitioned.transaction.transaction_id,
    )
    lease = harness.store.get_worker_lease(
        tenant_id=stage.tenant_id,
        transaction_id=stage.transaction_id,
        lease_id=stage.lease_id,
    )
    harness.store.release_worker_lease(
        tenant_id=lease.tenant_id,
        transaction_id=lease.transaction_id,
        lease_id=lease.lease_id,
        expected_version=lease.version,
        released_at=harness.clock(),
    )
    stage_target_ref = harness.artifacts.put_model(stage).digest
    failure_evidence_ref = harness.artifacts.put_model(
        CoordinatorEvidence(
            transaction_id=stage.transaction_id,
            event=TransitionEvent.STAGING_DISCARD_FAILED.value,
            reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
            recorded_at=harness.clock(),
            subject_ref=stage_target_ref,
        )
    ).digest
    attempt_before = harness.store.get_intent_attempt(
        tenant_id=stage.tenant_id,
        intent_hash=stage.intent_hash,
        transaction_id=stage.transaction_id,
    )
    event_count_before = len(
        harness.store.list_enforced_transaction_events(stage.tenant_id, stage.transaction_id)
    )
    harness.store._connection.execute(
        "CREATE TRIGGER fail_recovery_handoff_transaction "
        "BEFORE UPDATE OF state ON enforced_transactions "
        "WHEN NEW.state = 'RECOVERY_FAILED' "
        "BEGIN SELECT RAISE(ABORT, 'synthetic atomic rollback'); END"
    )
    try:
        with pytest.raises(AgentKernelError) as captured:
            harness.store.fail_stage_recovery_handoff(
                tenant_id=stage.tenant_id,
                transaction_id=stage.transaction_id,
                expected_transaction_version=transitioned.transaction.version,
                stage_id=stage.stage_id,
                expected_stage_version=stage.version,
                stage_target_ref=stage_target_ref,
                failure_evidence_ref=failure_evidence_ref,
                reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                recorded_at=harness.clock(),
            )
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
        assert (
            harness.store.get_enforced_transaction(
                tenant_id=stage.tenant_id,
                transaction_id=stage.transaction_id,
            )
            == transitioned.transaction
        )
        assert (
            harness.store.get_stage_material(
                tenant_id=stage.tenant_id,
                transaction_id=stage.transaction_id,
            )
            == stage
        )
        assert (
            harness.store.get_intent_attempt(
                tenant_id=stage.tenant_id,
                intent_hash=stage.intent_hash,
                transaction_id=stage.transaction_id,
            )
            == attempt_before
        )
        assert (
            len(
                harness.store.list_enforced_transaction_events(
                    stage.tenant_id,
                    stage.transaction_id,
                )
            )
            == event_count_before
        )
    finally:
        harness.store._connection.execute("DROP TRIGGER fail_recovery_handoff_transaction")
        harness.store.close()


@pytest.mark.asyncio
async def test_same_transaction_id_isolated_across_tenants_and_dispatch_fences(
    tmp_path: Path,
) -> None:
    transaction_id = "transaction:shared-across-tenants"
    harness = support._make_harness(tmp_path, transaction_id=transaction_id)
    second_context = AuthenticatedActionContext(
        tenant_id="tenant:coordinator-second",
        principal_id="principal:coordinator-second",
        goal_id="goal:coordinator-second",
        run_id="run:coordinator-second",
        trace_id="trace:coordinator-second",
        actor_id="actor:coordinator-second",
        on_behalf_of="principal:coordinator-second",
        agent_id="agent:coordinator-second",
        configuration_digest=harness.request.presented_context.configuration_digest,
    )
    harness.store.register_action_context(second_context, registered_at=harness.clock())
    harness.store.register_capability_budget(
        tenant_id=second_context.tenant_id,
        capability_id=support._CAPABILITY_ID,
        goal_id=second_context.goal_id,
        run_id=second_context.run_id,
        max_uses=32,
        registered_at=harness.clock(),
    )
    second_proposal = harness.request.proposal.model_copy(
        update={
            "goal_id": second_context.goal_id,
            "agent_id": second_context.agent_id,
            "arguments": {"values": {"answer": "84"}},
            "idempotency_key": "idempotency:shared-second-tenant",
        }
    )
    second_authentication = harness.artifacts.put(b"authenticated-context-proof:second-tenant")
    second_request = EnforcedTransactionRequest(
        proposal=second_proposal,
        presented_context=second_context,
        authentication_evidence_ref=second_authentication.digest,
    )
    second_coordinator = _clone_coordinator(
        harness,
        context_validator=support._ContextValidator(second_context),
        authority_snapshots=support._AuthoritySnapshots(
            harness.store,
            harness.clock(),
            clock=harness.clock,
        ),
        policy_inputs=support._PolicyInputs(harness.clock),
    )
    try:
        first = await harness.coordinator.transaction(harness.request)
        assert not isinstance(first, EnforcedTransactionStatus)
        async with first:
            first_record = await first.commit()
        assert first_record.state is TransactionState.COMMITTED

        # A newer token in the first tenant must not revoke the second tenant's token 1.
        harness.adapter._accept_transaction_fence(
            first_record.tenant_id,
            transaction_id,
            9,
        )

        second = await second_coordinator.transaction(second_request)
        assert not isinstance(second, EnforcedTransactionStatus)
        async with second:
            second_record = await second.commit()
        assert second_record.state is TransactionState.COMMITTED

        first_dispatch = harness.store.get_commit_dispatch(
            tenant_id=first_record.tenant_id,
            transaction_id=transaction_id,
        )
        second_dispatch = harness.store.get_commit_dispatch(
            tenant_id=second_record.tenant_id,
            transaction_id=transaction_id,
        )
        assert first_dispatch.dispatch_id != second_dispatch.dispatch_id
        assert harness.target.transaction_fences[(first_record.tenant_id, transaction_id)] == 9
        assert harness.target.transaction_fences[(second_record.tenant_id, transaction_id)] == 1
        assert {dispatch.tenant_id for dispatch in harness.target.dispatches.values()} == {
            first_record.tenant_id,
            second_record.tenant_id,
        }
        assert (
            harness.coordinator.status(
                first_record.tenant_id,
                transaction_id,
            ).record.state
            is TransactionState.COMMITTED
        )
        assert (
            second_coordinator.status(
                second_record.tenant_id,
                transaction_id,
            ).record.state
            is TransactionState.COMMITTED
        )
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "expected_code"),
    [
        ("deny", ErrorCode.POLICY_DENIED),
        ("unknown", ErrorCode.POLICY_UNKNOWN),
    ],
)
async def test_staging_policy_denial_and_unknown_are_distinct_durable_rejections(
    tmp_path: Path,
    mode: str,
    expected_code: ErrorCode,
) -> None:
    harness = support._make_harness(tmp_path)
    provider = _PurposePolicyInputs(
        harness.clock,
        {AuthorizationRoundPurpose.STAGING: mode},
    )
    harness.coordinator._policy_inputs = provider
    try:
        with pytest.raises(AgentKernelError) as captured:
            await harness.coordinator.transaction(harness.request)
        assert captured.value.code is expected_code
        status = harness.coordinator.status(
            "tenant:coordinator",
            harness.request.proposal.transaction_id,
        )
        assert status.record.state is TransactionState.REJECTED
        assert not harness.target.dispatches
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_policy_provider_cannot_add_an_unrequested_resource(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path)
    harness.coordinator._policy_inputs = _ExtraResourcePolicyInputs(harness.clock)
    try:
        with pytest.raises(AgentKernelError) as captured:
            await harness.coordinator.transaction(harness.request)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
        status = harness.coordinator.status(
            "tenant:coordinator",
            harness.request.proposal.transaction_id,
        )
        assert status.record.state is TransactionState.REJECTED
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_staging_approval_obligation_stays_fail_closed_and_cleans_private_state(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path, adapter_type=support._ControlledVerificationAdapter)
    harness.coordinator._policy_inputs = _PurposePolicyInputs(
        harness.clock,
        {AuthorizationRoundPurpose.STAGING: "approval"},
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            assert session.plan is not None
            assert session.record.state is TransactionState.AWAITING_APPROVAL
            with pytest.raises(AgentKernelError) as captured:
                await session.commit()
            assert captured.value.code is ErrorCode.APPROVAL_REQUIRED
        assert session.record.state is TransactionState.ABORTED
        assert adapter.abort_stage_calls == 1
        assert harness.target.state == {"before": "kept"}
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "expected_code"),
    [
        ("deny", ErrorCode.POLICY_DENIED),
        ("unknown", ErrorCode.POLICY_UNKNOWN),
        ("approval", ErrorCode.APPROVAL_REQUIRED),
    ],
)
async def test_precommit_policy_change_aborts_before_authoritative_effect(
    tmp_path: Path,
    mode: str,
    expected_code: ErrorCode,
) -> None:
    harness = support._make_harness(tmp_path, adapter_type=support._ControlledVerificationAdapter)
    harness.coordinator._policy_inputs = _PurposePolicyInputs(
        harness.clock,
        {AuthorizationRoundPurpose.PRECOMMIT: mode},
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            with pytest.raises(AgentKernelError) as captured:
                await session.commit()
            assert captured.value.code is expected_code
        assert session.record.state is TransactionState.ABORTED
        assert adapter.abort_stage_calls == 1
        assert harness.target.state == {"before": "kept"}
        assert not harness.target.dispatches
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_target_change_after_staging_is_preserved_and_commit_is_aborted(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path, adapter_type=support._ControlledVerificationAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            with harness.target.lock:
                harness.target.state["external"] = "change"
                harness.target.version += 1
            with pytest.raises(AgentKernelError) as captured:
                await session.commit()
            assert captured.value.code is ErrorCode.STALE_STATE
        assert session.record.state is TransactionState.STALE_STATE
        assert harness.target.state == {"before": "kept", "external": "change"}
        assert adapter.abort_stage_calls == 1
        assert not harness.target.dispatches
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "adapter_type",
    [
        _MalformedPlanAdapter,
        _MalformedStageAdapter,
        _MalformedStagedReceiptAdapter,
        _DuplicateObservationAdapter,
    ],
)
async def test_untrusted_staging_outputs_are_rejected_and_private_state_is_cleaned(
    tmp_path: Path,
    adapter_type,
) -> None:
    harness = support._make_harness(tmp_path, adapter_type=adapter_type)
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(AgentKernelError) as captured:
            await session.__aenter__()
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
        assert session.record.state is TransactionState.ABORTED
        assert harness.target.state == {"before": "kept"}
        assert not harness.target.dispatches
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_committed_pass_rejects_receipt_post_state_that_differs_from_observation(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path, adapter_type=_ForgedCommittedPostStateAdapter)
    adapter = harness.adapter
    assert isinstance(adapter, _ForgedCommittedPostStateAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            with pytest.raises(AgentKernelError) as captured:
                await session.commit()
            assert captured.value.code is ErrorCode.INTEGRITY_ERROR

        assert adapter.forged_receipt is not None
        assert adapter.forged_receipt.target_version_after != harness.target.digest
        assert harness.target.state["answer"] == "42"
        status = harness.coordinator.status(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert status.record.state is TransactionState.IN_DOUBT
        assert status.dispatch is not None
        assert status.dispatch.effect_receipt_ref == canonical_digest(adapter.forged_receipt)
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_session_public_api_rejects_commit_before_enter_and_reentry(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path)
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(AgentKernelError) as before_enter:
            await session.commit()
        assert before_enter.value.code is ErrorCode.ILLEGAL_TRANSITION

        async with session:
            assert session.plan is not None
        assert session.record.state is TransactionState.ABORTED

        with pytest.raises(AgentKernelError) as reentered:
            async with session:
                pytest.fail("a session must not be entered twice")
        assert reentered.value.code is ErrorCode.ILLEGAL_TRANSITION
        assert await session.cancel() == session.record
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("legacy", ErrorCode.EVIDENCE_UNAVAILABLE),
        ("missing_ref", ErrorCode.INTEGRITY_ERROR),
    ],
)
async def test_status_rejects_legacy_or_incomplete_authorization_projection(
    tmp_path: Path,
    mutation: str,
    expected_code: ErrorCode,
) -> None:
    harness = support._make_harness(tmp_path)
    try:
        session = await harness.coordinator.transaction(harness.request)
        coordinator = _clone_coordinator(
            harness,
            store=_ProjectionStore(harness.store, mutation),
        )
        with pytest.raises(AgentKernelError) as captured:
            coordinator.status(session.record.tenant_id, session.record.transaction_id)
        assert captured.value.code is expected_code
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_failed_verification_records_recovery_unavailable_without_a_strategy(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path, adapter_type=_RecoveryUnavailableAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            with pytest.raises(AgentKernelError) as captured:
                await session.commit()
            assert captured.value.code is ErrorCode.VERIFICATION_FAILED
        assert session.record.state is TransactionState.RECOVERY_FAILED
        assert harness.target.state["answer"] == "42"
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("crash_point", "initial_state"),
    [
        (CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED, RecoveryWorkState.PENDING),
        (CoordinatorCrashPoint.BEFORE_RECOVERY_ADAPTER, RecoveryWorkState.RUNNING),
    ],
)
async def test_expired_recovery_generation_is_closed_for_review_without_adapter_io(
    tmp_path: Path,
    crash_point: CoordinatorCrashPoint,
    initial_state: RecoveryWorkState,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=crash_point,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                pass
        work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(work) == 1
        assert work[0].state is initial_state

        harness.clock.advance(timedelta(minutes=10))
        result = await support._restart_coordinator(harness).recover_once(session.record.tenant_id)
        assert result.processed == 1
        assert result.remaining == 0
        assert len(result.failures) == 1
        assert result.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert result.failures[0].reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        closed = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert closed[0].state is RecoveryWorkState.REVIEW_REQUIRED
        assert closed[0].reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert closed[0].unavailable_record_digest is None
        status = harness.coordinator.status(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert status.record.state is TransactionState.RECOVERY_FAILED
        assert status.stage is not None
        assert status.stage.state is StageMaterialState.DISCARD_FAILED
        target_attempt = harness.store.get_intent_attempt(
            tenant_id=closed[0].tenant_id,
            intent_hash=closed[0].intent_hash,
            transaction_id=closed[0].transaction_id,
        )
        assert target_attempt.state is IntentAttemptState.REVIEW_REQUIRED
        target_action = harness.store.get_normalized_action(
            closed[0].tenant_id,
            closed[0].transaction_id,
        ).action
        target_reservation = harness.store.get_capability_chain(
            tenant_id=closed[0].tenant_id,
            goal_id=target_action.goal_id,
            run_id=target_action.run_id,
            intent_hash=target_action.intent_hash,
        )
        assert target_reservation.state is CapabilityReservationState.RELEASED
        recovery_attempt = harness.store.get_intent_attempt(
            tenant_id=closed[0].tenant_id,
            intent_hash=closed[0].recovery_action_intent_hash,
            transaction_id=closed[0].recovery_action_transaction_id,
        )
        assert recovery_attempt.state is (
            IntentAttemptState.NO_EFFECT_CONFIRMED
            if initial_state is RecoveryWorkState.PENDING
            else IntentAttemptState.REVIEW_REQUIRED
        )
        recovery_action = harness.store.get_normalized_action(
            closed[0].tenant_id,
            closed[0].recovery_action_transaction_id,
        ).action
        recovery_reservation = harness.store.get_capability_chain(
            tenant_id=closed[0].tenant_id,
            goal_id=recovery_action.goal_id,
            run_id=recovery_action.run_id,
            intent_hash=recovery_action.intent_hash,
        )
        assert recovery_reservation.state is (
            CapabilityReservationState.RELEASED
            if initial_state is RecoveryWorkState.PENDING
            else CapabilityReservationState.COMMITTED
        )
        handoff = harness.store.get_recovery_action_handoff(
            tenant_id=closed[0].tenant_id,
            target_transaction_id=closed[0].transaction_id,
            recovery_id=closed[0].recovery_id,
        )
        assert handoff is not None
        assert handoff.closed_at == closed[0].updated_at
        assert handoff.failure_evidence_ref is not None
        assert handoff.failure_reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        if closed[0].lease_id is not None:
            assert (
                harness.store.get_worker_lease(
                    tenant_id=closed[0].tenant_id,
                    transaction_id=closed[0].transaction_id,
                    lease_id=closed[0].lease_id,
                ).released_at
                == closed[0].updated_at
            )
        assert adapter.abort_stage_calls == 0
        assert harness.target.state == {"before": "kept"}
        repeated = await support._restart_coordinator(harness).recover_once(
            session.record.tenant_id
        )
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_recovery_authorization_atomically_releases_handoff_before_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    original_release = harness.store.release_worker_lease

    def reject_non_atomic_recovery_release(**kwargs):
        lease = harness.store.get_worker_lease(
            tenant_id=kwargs["tenant_id"],
            transaction_id=kwargs["transaction_id"],
            lease_id=kwargs["lease_id"],
        )
        if lease.purpose is LeasePurpose.RECOVERY:
            raise AssertionError("recovery handoff must transfer inside authorize_recovery")
        return original_release(**kwargs)

    try:
        session = await harness.coordinator.transaction(harness.request)
        monkeypatch.setattr(
            harness.store,
            "release_worker_lease",
            reject_non_atomic_recovery_release,
        )
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                pass

        work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(work) == 1
        assert work[0].state is RecoveryWorkState.PENDING
        active_lease_count = harness.store._connection.execute(
            "SELECT COUNT(*) FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
            (session.record.tenant_id, session.record.transaction_id),
        ).fetchone()[0]
        assert active_lease_count == 0

        result = await support._restart_coordinator(harness).recover_once(session.record.tenant_id)
        assert result.processed == 1
        assert not result.failures
        assert result.statuses[0].record.state is TransactionState.ABORTED
        assert adapter.abort_stage_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [RuntimeError, OSError])
async def test_pre_provider_recovery_setup_failure_is_not_evidence_outage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    try:
        session, pending = await _crash_after_recovery_authorized(harness)
        restarted = support._restart_coordinator(harness)

        def fail_resolution(*_args, **_kwargs):
            raise error_type("synthetic pre-provider setup failure")

        monkeypatch.setattr(harness.registry, "resolve_admitted", fail_resolution)
        result = await restarted.recover_once(session.record.tenant_id)

        assert result.processed == 1
        assert result.remaining == 0
        assert len(result.failures) == 1
        failure = result.failures[0]
        assert failure.kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert failure.reason_code == "RECOVERY_SETUP_INTERNAL_FAILURE"
        assert failure.evidence_ref is not None
        closed = harness.store.get_recovery_work(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
            recovery_id=pending.recovery_id,
        )
        assert closed.state is RecoveryWorkState.REVIEW_REQUIRED
        evidence = harness.artifacts.get_model(
            failure.evidence_ref,
            CoordinatorEvidence,
        )
        assert evidence.event == TransitionEvent.STAGING_DISCARD_FAILED.value
        assert evidence.reason_code == "RECOVERY_SETUP_INTERNAL_FAILURE"
        assert evidence.subject_ref == closed.target_evidence_ref
        assert closed.unavailable_record_digest is None
        assert (
            harness.store.get_recovery_evidence_unavailable(
                tenant_id=closed.tenant_id,
                transaction_id=closed.transaction_id,
                recovery_id=closed.recovery_id,
            )
            is None
        )
        assert closed.lease_id is not None
        assert (
            harness.store.get_worker_lease(
                tenant_id=closed.tenant_id,
                transaction_id=closed.transaction_id,
                lease_id=closed.lease_id,
            ).released_at
            == closed.updated_at
        )
        recovery_attempt = harness.store.get_intent_attempt(
            tenant_id=closed.tenant_id,
            intent_hash=closed.recovery_action_intent_hash,
            transaction_id=closed.recovery_action_transaction_id,
        )
        assert recovery_attempt.state is IntentAttemptState.NO_EFFECT_CONFIRMED
        _assert_discard_target_closed(
            harness,
            closed,
            recovery_intent_state=IntentAttemptState.NO_EFFECT_CONFIRMED,
        )
        assert adapter.abort_stage_calls == 0

        repeated = await restarted.recover_once(session.record.tenant_id)
        assert repeated.scanned == 0
        assert repeated.processed == 0
        assert repeated.remaining == 0
        assert not repeated.failures
        assert not repeated.statuses
        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            coordinator = _clone_coordinator(harness, store=reopened)
            reopened_work = reopened.get_recovery_work(
                tenant_id=closed.tenant_id,
                transaction_id=closed.transaction_id,
                recovery_id=closed.recovery_id,
            )
            assert reopened_work == closed
            assert reopened.count_recovery_candidates(tenant_id=closed.tenant_id) == 0
            status = coordinator.status(
                closed.tenant_id,
                closed.transaction_id,
            )
            assert status.record.state is TransactionState.RECOVERY_FAILED
            reopened_failure = coordinator._recovery_terminal_failure(
                reopened.get_transaction_projection(
                    tenant_id=closed.tenant_id,
                    transaction_id=closed.transaction_id,
                )
            )
            assert reopened_failure is not None
            assert reopened_failure.evidence_ref == failure.evidence_ref
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_pre_provider_cancellation_settles_known_no_effect_without_false_outage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED,
    )
    try:
        session, pending = await _crash_after_recovery_authorized(harness)
        restarted = support._restart_coordinator(harness)

        def cancel_resolution(*_args, **_kwargs):
            raise CancelledError

        monkeypatch.setattr(harness.registry, "resolve_admitted", cancel_resolution)
        with pytest.raises(CancelledError):
            await restarted.recover_once(session.record.tenant_id)

        closed = harness.store.get_recovery_work(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
            recovery_id=pending.recovery_id,
        )
        assert closed.state is RecoveryWorkState.REVIEW_REQUIRED
        assert closed.reason_code == "RECOVERY_SETUP_CANCELLED"
        assert closed.unavailable_record_digest is None
        assert (
            harness.store.get_recovery_evidence_unavailable(
                tenant_id=closed.tenant_id,
                transaction_id=closed.transaction_id,
                recovery_id=closed.recovery_id,
            )
            is None
        )
        _assert_discard_target_closed(
            harness,
            closed,
            recovery_intent_state=IntentAttemptState.NO_EFFECT_CONFIRMED,
        )
        repeated = await restarted.recover_once(session.record.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            assert (
                reopened.get_recovery_work(
                    tenant_id=closed.tenant_id,
                    transaction_id=closed.transaction_id,
                    recovery_id=closed.recovery_id,
                )
                == closed
            )
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_setup_failure_artifact_outage_uses_typed_unavailable_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED,
    )
    try:
        session, pending = await _crash_after_recovery_authorized(harness)
        outage = _TogglePutOutageArtifacts(harness.artifacts)
        restarted = _clone_coordinator(harness, artifacts=outage)

        def fail_after_claim(*_args, **_kwargs):
            outage.fail_put = True
            raise RuntimeError("synthetic pre-provider setup failure")

        monkeypatch.setattr(harness.registry, "resolve_admitted", fail_after_claim)
        result = await restarted.recover_once(session.record.tenant_id)

        assert result.processed == 1
        assert result.remaining == 0
        assert len(result.failures) == 1
        assert result.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert result.failures[0].reason_code.startswith("EVIDENCE_UNAVAILABLE:")
        closed = harness.store.get_recovery_work(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
            recovery_id=pending.recovery_id,
        )
        unavailable = harness.store.get_recovery_evidence_unavailable(
            tenant_id=closed.tenant_id,
            transaction_id=closed.transaction_id,
            recovery_id=closed.recovery_id,
        )
        assert unavailable is not None
        assert unavailable.boundary == "POST_CLAIM_SETUP"
        assert closed.unavailable_record_digest == unavailable.record_digest
        _assert_discard_target_closed(
            harness,
            closed,
            recovery_intent_state=IntentAttemptState.NO_EFFECT_CONFIRMED,
        )
        repeated = await restarted.recover_once(session.record.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert len(repeated.failures) == 1
        assert repeated.failures[0].kind is RecoveryFailureKind.EVIDENCE_AUDIT
        assert repeated.failures[0].reason_code == ErrorCode.EVIDENCE_UNAVAILABLE.value
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_missing_recovery_target_artifact_is_fenced_before_adapter_entry(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    try:
        session, pending = await _crash_after_recovery_authorized(harness)
        outage = _SelectiveGetOutageArtifacts(
            harness.artifacts,
            pending.target_evidence_ref,
        )
        restarted = _clone_coordinator(harness, artifacts=outage)

        result = await restarted.recover_once(session.record.tenant_id)

        assert result.processed == 1
        assert result.remaining == 0
        assert len(result.failures) == 1
        assert result.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert result.failures[0].reason_code.startswith("EVIDENCE_UNAVAILABLE:")
        closed = harness.store.get_recovery_work(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
            recovery_id=pending.recovery_id,
        )
        unavailable = harness.store.get_recovery_evidence_unavailable(
            tenant_id=closed.tenant_id,
            transaction_id=closed.transaction_id,
            recovery_id=closed.recovery_id,
        )
        assert unavailable is not None
        assert unavailable.boundary == "POST_CLAIM_SETUP"
        assert closed.unavailable_record_digest == unavailable.record_digest
        assert outage.blocked_gets == 1
        assert adapter.abort_stage_calls == 0
        _assert_discard_target_closed(
            harness,
            closed,
            recovery_intent_state=IntentAttemptState.NO_EFFECT_CONFIRMED,
        )

        repeated = await restarted.recover_once(session.record.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert len(repeated.failures) == 1
        assert repeated.failures[0].kind is RecoveryFailureKind.EVIDENCE_AUDIT
        assert adapter.abort_stage_calls == 0

        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            assert (
                reopened.get_recovery_work(
                    tenant_id=closed.tenant_id,
                    transaction_id=closed.transaction_id,
                    recovery_id=closed.recovery_id,
                )
                == closed
            )
            assert reopened.count_recovery_candidates(tenant_id=closed.tenant_id) == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_mismatched_recovery_target_artifact_fails_integrity_before_adapter(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    try:
        session, pending = await _crash_after_recovery_authorized(harness)
        sql_stage = harness.store.get_stage_material(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
        )
        mismatched_stage = StageMaterialRecord.model_validate(
            {
                **sql_stage.model_dump(mode="python"),
                "target_version_guard": "guard:mismatched-artifact",
            }
        )
        artifacts = _MismatchedGetArtifacts(
            harness.artifacts,
            pending.target_evidence_ref,
            mismatched_stage,
        )
        restarted = _clone_coordinator(harness, artifacts=artifacts)

        with pytest.raises(AgentKernelError) as captured:
            await restarted.recover_once(session.record.tenant_id)

        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
        assert artifacts.mismatched_gets == 1
        assert adapter.abort_stage_calls == 0
        preserved = harness.store.get_recovery_work(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
            recovery_id=pending.recovery_id,
        )
        assert preserved.state is RecoveryWorkState.RUNNING
        assert preserved.unavailable_record_digest is None
        assert (
            harness.store.get_recovery_evidence_unavailable(
                tenant_id=pending.tenant_id,
                transaction_id=pending.transaction_id,
                recovery_id=pending.recovery_id,
            )
            is None
        )
        target = harness.store.get_enforced_transaction(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
        )
        assert target.state is TransactionState.ABORTING
        target_attempt = harness.store.get_intent_attempt(
            tenant_id=pending.tenant_id,
            intent_hash=pending.intent_hash,
            transaction_id=pending.transaction_id,
        )
        assert target_attempt.state is IntentAttemptState.ACTIVE
        handoff = harness.store.get_recovery_action_handoff(
            tenant_id=pending.tenant_id,
            target_transaction_id=pending.transaction_id,
            recovery_id=pending.recovery_id,
        )
        assert handoff is not None
        assert handoff.closed_at is None
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_stage_target_publication_outage_preserves_reservation_until_retry(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        assert not isinstance(session, EnforcedTransactionStatus)
        await session.__aenter__()
        outage = _StagePutOutageArtifacts(harness.artifacts)
        harness.coordinator._artifacts = outage

        with pytest.raises(AgentKernelError) as unavailable:
            await session.cancel()

        assert unavailable.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        assert outage.blocked_puts == 1
        assert adapter.abort_stage_calls == 0
        pending = harness.store.get_enforced_transaction(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert pending.state is TransactionState.ABORTING
        stage = harness.store.get_stage_material(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
        )
        assert stage.state is StageMaterialState.VERIFIED
        target_attempt = harness.store.get_intent_attempt(
            tenant_id=pending.tenant_id,
            intent_hash=session.action.intent_hash,
            transaction_id=pending.transaction_id,
        )
        assert target_attempt.state is IntentAttemptState.ACTIVE
        reservation = harness.store.get_capability_chain(
            tenant_id=pending.tenant_id,
            goal_id=session.action.goal_id,
            run_id=session.action.run_id,
            intent_hash=session.action.intent_hash,
        )
        assert reservation.state is CapabilityReservationState.RESERVED
        assert not harness.store.list_recovery_work(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
        )
        assert not harness.store.list_recovery_action_handoffs(
            tenant_id=pending.tenant_id,
            target_transaction_id=pending.transaction_id,
        )

        harness.coordinator._artifacts = harness.artifacts
        resumed = await harness.coordinator.recover_once(pending.tenant_id)
        assert resumed.scanned == resumed.processed == 1
        assert resumed.remaining == 0
        assert not resumed.failures
        assert resumed.statuses[0].record.state is TransactionState.ABORTED
        assert adapter.abort_stage_calls == 1
        discarded = harness.store.get_stage_material(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
        )
        assert discarded.state is StageMaterialState.DISCARDED
        settled_attempt = harness.store.get_intent_attempt(
            tenant_id=pending.tenant_id,
            intent_hash=session.action.intent_hash,
            transaction_id=pending.transaction_id,
        )
        assert settled_attempt.state is IntentAttemptState.NO_EFFECT_CONFIRMED
        settled_reservation = harness.store.get_capability_chain(
            tenant_id=pending.tenant_id,
            goal_id=session.action.goal_id,
            run_id=session.action.run_id,
            intent_hash=session.action.intent_hash,
        )
        assert settled_reservation.state is CapabilityReservationState.RELEASED
        repeated = await harness.coordinator.recover_once(pending.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            assert (
                reopened.get_enforced_transaction(
                    pending.tenant_id,
                    pending.transaction_id,
                ).state
                is TransactionState.ABORTED
            )
            assert (
                reopened.get_capability_chain(
                    tenant_id=pending.tenant_id,
                    goal_id=session.action.goal_id,
                    run_id=session.action.run_id,
                    intent_hash=session.action.intent_hash,
                ).state
                is CapabilityReservationState.RELEASED
            )
            assert reopened.count_recovery_candidates(tenant_id=pending.tenant_id) == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_provider_runtime_failure_reports_exact_terminal_evidence(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_RecoveryProviderRuntimeErrorAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _RecoveryProviderRuntimeErrorAdapter)
    try:
        session, pending = await _crash_after_recovery_authorized(harness)
        restarted = support._restart_coordinator(harness)
        result = await restarted.recover_once(session.record.tenant_id)

        assert result.processed == 1
        assert len(result.failures) == 1
        failure = result.failures[0]
        assert failure.kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert failure.reason_code == "RECOVERY_EXECUTION_FAILED"
        assert failure.evidence_ref is not None
        assert harness.artifacts.get(failure.evidence_ref)
        closed = harness.store.get_recovery_work(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
            recovery_id=pending.recovery_id,
        )
        assert closed.state is RecoveryWorkState.FAILED
        assert closed.unavailable_record_digest is None
        assert adapter.abort_stage_calls == 1

        repeated = await restarted.recover_once(session.record.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert adapter.abort_stage_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_provider_cancellation_is_terminal_and_not_retried(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_RecoveryProviderCancelledAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _RecoveryProviderCancelledAdapter)
    try:
        session, pending = await _crash_after_recovery_authorized(harness)
        restarted = support._restart_coordinator(harness)
        with pytest.raises(CancelledError):
            await restarted.recover_once(session.record.tenant_id)

        closed = harness.store.get_recovery_work(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
            recovery_id=pending.recovery_id,
        )
        assert closed.state is RecoveryWorkState.FAILED
        assert closed.reason_code == "RECOVERY_CANCELLED_AFTER_PROVIDER_ENTRY"
        assert closed.unavailable_record_digest is None
        assert closed.lease_id is not None
        assert (
            harness.store.get_worker_lease(
                tenant_id=closed.tenant_id,
                transaction_id=closed.transaction_id,
                lease_id=closed.lease_id,
            ).released_at
            == closed.updated_at
        )
        assert adapter.abort_stage_calls == 1
        repeated = await restarted.recover_once(session.record.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert adapter.abort_stage_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_typed_dispatch_unavailability_is_quiescent_on_repeat_scan(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    try:
        session = await _crash_during_commit(harness)
        projection = harness.store.get_transaction_projection(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        blocked_ref = next(
            round_record.authority_snapshot_ref
            for round_record in projection.authorization_rounds
            if round_record.authority_snapshot_ref is not None
        )
        outage = _SelectiveGetOutageArtifacts(
            harness.artifacts,
            blocked_ref,
        )
        restarted = _clone_coordinator(harness, artifacts=outage)
        first = await restarted.recover_once(session.record.tenant_id)

        assert first.processed == 1
        assert first.remaining == 0
        assert len(first.failures) == 1
        assert first.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        unavailable = harness.store.get_dispatch_evidence_unavailable(
            tenant_id=dispatch.tenant_id,
            transaction_id=dispatch.transaction_id,
            dispatch_id=dispatch.dispatch_id,
        )
        assert unavailable is not None
        assert dispatch.unavailable_record_digest == unavailable.record_digest
        assert outage.blocked_gets == 1
        with pytest.raises(AgentKernelError) as generic_status_outage:
            restarted.status(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert generic_status_outage.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        assert generic_status_outage.value.details == {}

        repeated = await restarted.recover_once(session.record.tenant_id)
        assert repeated.scanned == 0
        assert repeated.processed == 0
        assert repeated.remaining == 0
        assert not repeated.failures
        assert not repeated.statuses
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "generation_field",
    [
        "permit",
        "authorization",
        "recovery_action",
        "approval",
        "handoff_binding",
    ],
)
async def test_recovery_status_degrades_only_for_exact_unavailable_record_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    generation_field: str,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        running, _attempt, _dispatch = await _crash_after_reconciliation_started(
            harness,
            session,
        )
        closed = harness.coordinator._terminalize_recovery_evidence_unavailable(
            running,
            boundary="RECONCILIATION_EVIDENCE",
            reported_at=harness.clock(),
            cause="SYNTHETIC_TYPED_STOP",
        )
        assert closed.state is RecoveryWorkState.REVIEW_REQUIRED
        unavailable = harness.store.get_recovery_evidence_unavailable(
            tenant_id=closed.tenant_id,
            transaction_id=closed.transaction_id,
            recovery_id=closed.recovery_id,
        )
        assert unavailable is not None
        projection = harness.store.get_transaction_projection(
            tenant_id=closed.tenant_id,
            transaction_id=closed.transaction_id,
        )
        handoff = next(
            item
            for item in projection.recovery_handoffs
            if item.binding.recovery_id == closed.recovery_id
        )
        authorization_round = next(
            item
            for item in projection.authorization_rounds
            if item.round_id == closed.authorization_round_id
            and item.controlled_transaction_id == closed.transaction_id
        )
        generation_refs = {
            "permit": closed.permit_ref,
            "authorization": authorization_round.authority_decision_ref,
            "recovery_action": closed.recovery_action_digest,
            "approval": closed.approval_evidence_ref,
            "handoff_binding": handoff.binding_ref,
        }
        damaged_ref = generation_refs[generation_field]
        assert damaged_ref is not None
        healthy_status = harness.coordinator._recovery_result_status(
            closed.tenant_id,
            closed.transaction_id,
        )

        damaged_path = support._artifact_path(harness.artifacts.root, damaged_ref)
        original = damaged_path.read_bytes()
        damaged_path.unlink()
        try:
            with pytest.raises(AgentKernelError) as unrelated_outage:
                harness.coordinator._recovery_result_status(
                    closed.tenant_id,
                    closed.transaction_id,
                )
            assert unrelated_outage.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
            assert (
                harness.store.get_transaction_projection(
                    tenant_id=closed.tenant_id,
                    transaction_id=closed.transaction_id,
                )
                == projection
            )
        finally:
            _restore_private_artifact(harness.artifacts, damaged_path, original)

        exact_token: dict[str, object] = {
            "kind": "recovery",
            "owner_id": unavailable.recovery_id,
            "boundary": unavailable.boundary,
            "record_digest": unavailable.record_digest,
        }
        raised_details = exact_token

        def unavailable_status(
            _tenant_id: str,
            _transaction_id: str,
        ) -> EnforcedTransactionStatus:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "synthetic unavailable record read",
                details=raised_details,
            )

        monkeypatch.setattr(harness.coordinator, "status", unavailable_status)
        assert (
            harness.coordinator._recovery_result_status(
                closed.tenant_id,
                closed.transaction_id,
            )
            == healthy_status
        )
        mismatches = {
            "kind": "dispatch",
            "owner_id": f"{unavailable.recovery_id}:other",
            "boundary": "RECOVERY_DEADLINE",
            "record_digest": canonical_digest({"different": "record"}),
        }
        for field, mismatch in mismatches.items():
            raised_details = {**exact_token, field: mismatch}
            with pytest.raises(AgentKernelError) as rejected_token:
                harness.coordinator._recovery_result_status(
                    closed.tenant_id,
                    closed.transaction_id,
                )
            assert rejected_token.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        raised_details = {**exact_token, "extra": "not-exact"}
        with pytest.raises(AgentKernelError) as token_with_extra_field:
            harness.coordinator._recovery_result_status(
                closed.tenant_id,
                closed.transaction_id,
            )
        assert token_with_extra_field.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("crash_point", "expected_state"),
    [
        (CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED, TransactionState.ABORTED),
        (CoordinatorCrashPoint.AFTER_COMMIT_CALL, TransactionState.COMMITTED),
    ],
)
async def test_explicit_dispatch_resume_preserves_historical_unavailable_binding(
    tmp_path: Path,
    crash_point: CoordinatorCrashPoint,
    expected_state: TransactionState,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(tmp_path, crash_point=crash_point)
    reopened_store = None
    try:
        session = await _crash_during_commit(harness)
        restarted = support._restart_coordinator(harness)
        stopped = await restarted.recover_once(session.record.tenant_id)
        assert stopped.processed == 1
        assert stopped.remaining == 0

        stopped_dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        report = harness.store.get_dispatch_evidence_unavailable(
            tenant_id=stopped_dispatch.tenant_id,
            transaction_id=stopped_dispatch.transaction_id,
            dispatch_id=stopped_dispatch.dispatch_id,
        )
        assert report is not None

        resumed = await restarted.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert resumed.record.state is expected_state
        with pytest.raises(AgentKernelError) as repeated_resume:
            await restarted.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert repeated_resume.value.code is ErrorCode.ILLEGAL_TRANSITION
        resolved_dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert resolved_dispatch.unavailable_record_digest == report.record_digest
        assert (
            harness.store.get_dispatch_evidence_unavailable(
                tenant_id=resolved_dispatch.tenant_id,
                transaction_id=resolved_dispatch.transaction_id,
                dispatch_id=resolved_dispatch.dispatch_id,
            )
            == report
        )
        typed_outcome = next(
            outcome
            for outcome in harness.store.list_dispatch_outcomes(
                tenant_id=resolved_dispatch.tenant_id,
                transaction_id=resolved_dispatch.transaction_id,
            )
            if outcome.unavailable_record_digest == report.record_digest
        )
        assert typed_outcome.classification is not None
        assert typed_outcome.outcome_digest in {
            outcome.outcome_digest
            for outcome in harness.store.list_dispatch_outcomes(
                tenant_id=resolved_dispatch.tenant_id,
                transaction_id=resolved_dispatch.transaction_id,
            )
        }

        harness.store.close()
        reopened_store, reopened = support._reopen_coordinator(harness, database_path)
        reopened_status = reopened.status(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert reopened_status.record.state is expected_state
        assert reopened_status.dispatch_evidence_unavailable == report
        with pytest.raises(AgentKernelError) as reopened_resume:
            await reopened.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert reopened_resume.value.code is ErrorCode.ILLEGAL_TRANSITION
    finally:
        if reopened_store is not None:
            reopened_store.close()
        harness.store.close()


@pytest.mark.asyncio
async def test_concurrent_explicit_dispatch_resume_runs_one_reconciliation_lineage(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)

        results = await asyncio.gather(
            restarted.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            ),
            restarted.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            ),
            return_exceptions=True,
        )

        assert adapter.reconcile_calls == 1
        assert sum(isinstance(item, EnforcedTransactionStatus) for item in results) == 1
        errors = tuple(item for item in results if isinstance(item, AgentKernelError))
        assert len(errors) == 1
        assert errors[0].code is ErrorCode.ILLEGAL_TRANSITION
        lineages = tuple(
            work
            for work in harness.store.list_recovery_work(
                tenant_id=session.record.tenant_id,
                transaction_id=session.record.transaction_id,
            )
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
        )
        assert len(lineages) == 1
        assert lineages[0].recovery_ordinal == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("policy_mode", "expected_state", "expected_reason"),
    [
        ("deny", RecoveryWorkState.FAILED, ErrorCode.POLICY_DENIED.value),
        ("unknown", RecoveryWorkState.REVIEW_REQUIRED, ErrorCode.POLICY_UNKNOWN.value),
    ],
)
async def test_terminal_dispatch_resume_authorization_closes_handoff_without_provider(
    tmp_path: Path,
    policy_mode: str,
    expected_state: RecoveryWorkState,
    expected_reason: str,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        target_before = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        dispatch_before = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        terminal = _clone_coordinator(
            harness,
            policy_inputs=_PurposePolicyInputs(
                harness.clock,
                {AuthorizationRoundPurpose.RECOVERY: policy_mode},
            ),
        )

        resumed = await terminal.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )

        assert resumed.record.state is TransactionState.IN_DOUBT
        assert adapter.reconcile_calls == 0
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(works) == 1
        assert works[0].kind is RecoveryWorkKind.RECONCILE_DISPATCH
        assert works[0].state is expected_state
        assert works[0].reason_code == expected_reason
        assert not harness.store.get_active_recovery_work(
            tenant_id=works[0].tenant_id,
            transaction_id=works[0].transaction_id,
        )
        recovery_attempt = harness.store.get_intent_attempt(
            tenant_id=works[0].tenant_id,
            intent_hash=works[0].recovery_action_intent_hash,
            transaction_id=works[0].recovery_action_transaction_id,
        )
        assert recovery_attempt.state is IntentAttemptState.NO_EFFECT_CONFIRMED
        recovery_action = harness.store.get_normalized_action(
            works[0].tenant_id,
            works[0].recovery_action_transaction_id,
        ).action
        with pytest.raises(AgentKernelError) as no_reservation:
            harness.store.get_capability_chain(
                tenant_id=recovery_action.tenant_id,
                goal_id=recovery_action.goal_id,
                run_id=recovery_action.run_id,
                intent_hash=recovery_action.intent_hash,
            )
        assert no_reservation.value.code is ErrorCode.AUTHORITY_MISSING
        handoff = harness.store.get_recovery_action_handoff(
            tenant_id=works[0].tenant_id,
            target_transaction_id=works[0].transaction_id,
            recovery_id=works[0].recovery_id,
        )
        assert handoff is not None
        assert handoff.closed_at == works[0].updated_at
        assert handoff.failure_evidence_status is (RecoveryHandoffFailureEvidenceStatus.AVAILABLE)
        assert handoff.failure_reason_code == expected_reason
        assert handoff.failure_evidence_ref is not None
        evidence = harness.artifacts.get_model(
            handoff.failure_evidence_ref,
            CoordinatorEvidence,
        )
        assert evidence.event == "recovery.authorization_handoff_failed"
        assert evidence.subject_ref == handoff.binding_ref
        assert evidence.reason_code == expected_reason
        assert (
            harness.store.get_enforced_transaction(
                session.record.tenant_id,
                session.record.transaction_id,
            )
            == target_before
        )
        assert (
            harness.store.get_commit_dispatch(
                tenant_id=session.record.tenant_id,
                transaction_id=session.record.transaction_id,
            )
            == dispatch_before
        )
        repeated = await terminal.recover_once(session.record.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            assert reopened.count_recovery_candidates(tenant_id=works[0].tenant_id) == 0
            assert (
                reopened.get_recovery_action_handoff(
                    tenant_id=works[0].tenant_id,
                    target_transaction_id=works[0].transaction_id,
                    recovery_id=works[0].recovery_id,
                )
                == handoff
            )
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("policy_mode", "expected_state", "expected_reason"),
    [
        ("deny", RecoveryWorkState.FAILED, ErrorCode.POLICY_DENIED.value),
        ("unknown", RecoveryWorkState.REVIEW_REQUIRED, ErrorCode.POLICY_UNKNOWN.value),
    ],
)
async def test_terminal_recovery_authorization_artifact_outage_is_explicit_and_exact(
    tmp_path: Path,
    policy_mode: str,
    expected_state: RecoveryWorkState,
    expected_reason: str,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        target_before = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        dispatch_before = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        target_attempt_before = harness.store.get_intent_attempt(
            tenant_id=session.record.tenant_id,
            intent_hash=session.action.intent_hash,
            transaction_id=session.record.transaction_id,
        )
        target_reservation_before = harness.store.get_capability_chain(
            tenant_id=session.action.tenant_id,
            goal_id=session.action.goal_id,
            run_id=session.action.run_id,
            intent_hash=session.action.intent_hash,
        )
        outage = _TerminalRecoveryEvidencePutOutageArtifacts(harness.artifacts)
        terminal = _clone_coordinator(
            harness,
            artifacts=outage,
            policy_inputs=_PurposePolicyInputs(
                harness.clock,
                {AuthorizationRoundPurpose.RECOVERY: policy_mode},
            ),
        )

        resumed = await terminal.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )

        assert resumed.record == target_before
        assert adapter.reconcile_calls == 0
        assert outage.blocked_puts == 2
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(works) == 1
        work = works[0]
        assert work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
        assert work.state is expected_state
        assert work.reason_code == expected_reason
        assert (
            harness.store.get_intent_attempt(
                tenant_id=work.tenant_id,
                intent_hash=work.recovery_action_intent_hash,
                transaction_id=work.recovery_action_transaction_id,
            ).state
            is IntentAttemptState.NO_EFFECT_CONFIRMED
        )
        recovery_action = harness.store.get_normalized_action(
            work.tenant_id,
            work.recovery_action_transaction_id,
        ).action
        with pytest.raises(AgentKernelError) as no_recovery_reservation:
            harness.store.get_capability_chain(
                tenant_id=recovery_action.tenant_id,
                goal_id=recovery_action.goal_id,
                run_id=recovery_action.run_id,
                intent_hash=recovery_action.intent_hash,
            )
        assert no_recovery_reservation.value.code is ErrorCode.AUTHORITY_MISSING
        handoff = harness.store.get_recovery_action_handoff(
            tenant_id=work.tenant_id,
            target_transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert handoff is not None
        assert handoff.closed_at == work.updated_at
        assert handoff.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE
        assert handoff.failure_evidence_ref is None
        assert (
            handoff.failure_reason_code
            == f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{expected_reason}"
        )
        assert (
            harness.store.get_enforced_transaction(
                session.record.tenant_id,
                session.record.transaction_id,
            )
            == target_before
        )
        assert (
            harness.store.get_commit_dispatch(
                tenant_id=session.record.tenant_id,
                transaction_id=session.record.transaction_id,
            )
            == dispatch_before
        )
        assert (
            harness.store.get_intent_attempt(
                tenant_id=session.record.tenant_id,
                intent_hash=session.action.intent_hash,
                transaction_id=session.record.transaction_id,
            )
            == target_attempt_before
        )
        assert (
            harness.store.get_capability_chain(
                tenant_id=session.action.tenant_id,
                goal_id=session.action.goal_id,
                run_id=session.action.run_id,
                intent_hash=session.action.intent_hash,
            )
            == target_reservation_before
        )

        repeated = await terminal.recover_once(session.record.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert len(repeated.failures) == 1
        assert repeated.failures[0].kind is RecoveryFailureKind.EVIDENCE_AUDIT
        assert repeated.failures[0].reason_code == ErrorCode.EVIDENCE_UNAVAILABLE.value
        exact_repeat = await terminal.recover_once(session.record.tenant_id)
        assert exact_repeat.scanned == exact_repeat.processed == exact_repeat.remaining == 0
        assert not exact_repeat.failures
        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            assert reopened.count_recovery_candidates(tenant_id=work.tenant_id) == 0
            assert (
                reopened.get_recovery_action_handoff(
                    tenant_id=work.tenant_id,
                    target_transaction_id=work.transaction_id,
                    recovery_id=work.recovery_id,
                )
                == handoff
            )
            assert (
                reopened.get_intent_attempt(
                    tenant_id=session.record.tenant_id,
                    intent_hash=session.action.intent_hash,
                    transaction_id=session.record.transaction_id,
                )
                == target_attempt_before
            )
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_reconciliation_setup_failure_closes_handoff_before_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        target_before = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        dispatch_before = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )

        def fail_resolution(*_args, **_kwargs):
            raise RuntimeError("synthetic reconciliation setup failure")

        monkeypatch.setattr(harness.registry, "resolve_admitted", fail_resolution)
        with pytest.raises(RuntimeError, match="reconciliation setup failure"):
            await restarted.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )

        assert adapter.reconcile_calls == 0
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(works) == 1
        closed = works[0]
        assert closed.kind is RecoveryWorkKind.RECONCILE_DISPATCH
        assert closed.state is RecoveryWorkState.REVIEW_REQUIRED
        assert closed.reason_code == "RECOVERY_SETUP_INTERNAL_FAILURE"
        assert closed.lease_id is not None
        assert (
            harness.store.get_worker_lease(
                tenant_id=closed.tenant_id,
                transaction_id=closed.transaction_id,
                lease_id=closed.lease_id,
            ).released_at
            == closed.updated_at
        )
        recovery_attempt = harness.store.get_intent_attempt(
            tenant_id=closed.tenant_id,
            intent_hash=closed.recovery_action_intent_hash,
            transaction_id=closed.recovery_action_transaction_id,
        )
        assert recovery_attempt.state is IntentAttemptState.NO_EFFECT_CONFIRMED
        recovery_action = harness.store.get_normalized_action(
            closed.tenant_id,
            closed.recovery_action_transaction_id,
        ).action
        recovery_reservation = harness.store.get_capability_chain(
            tenant_id=recovery_action.tenant_id,
            goal_id=recovery_action.goal_id,
            run_id=recovery_action.run_id,
            intent_hash=recovery_action.intent_hash,
        )
        assert recovery_reservation.state is CapabilityReservationState.COMMITTED
        handoff = harness.store.get_recovery_action_handoff(
            tenant_id=closed.tenant_id,
            target_transaction_id=closed.transaction_id,
            recovery_id=closed.recovery_id,
        )
        assert handoff is not None
        assert handoff.closed_at == closed.updated_at
        assert handoff.failure_reason_code == closed.reason_code
        assert handoff.failure_evidence_ref is not None
        evidence = harness.artifacts.get_model(
            handoff.failure_evidence_ref,
            CoordinatorEvidence,
        )
        assert evidence.event == "recovery.authorization_handoff_failed"
        assert evidence.subject_ref == handoff.binding_ref
        assert (
            harness.store.get_enforced_transaction(
                session.record.tenant_id,
                session.record.transaction_id,
            )
            == target_before
        )
        assert (
            harness.store.get_commit_dispatch(
                tenant_id=session.record.tenant_id,
                transaction_id=session.record.transaction_id,
            )
            == dispatch_before
        )
        repeated = await restarted.recover_once(session.record.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            assert reopened.count_recovery_candidates(tenant_id=closed.tenant_id) == 0
            assert (
                reopened.get_recovery_action_handoff(
                    tenant_id=closed.tenant_id,
                    target_transaction_id=closed.transaction_id,
                    recovery_id=closed.recovery_id,
                )
                == handoff
            )
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_reconciliation_started_retry_rejects_released_lease_before_provider(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        running, attempt, dispatch = await _crash_after_reconciliation_started(
            harness,
            session,
        )
        assert adapter.reconcile_calls == 0
        assert running.lease_id is not None
        lease = harness.store.get_worker_lease(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            lease_id=running.lease_id,
        )
        released_at = harness.clock()
        harness.store.release_worker_lease(
            tenant_id=lease.tenant_id,
            transaction_id=lease.transaction_id,
            lease_id=lease.lease_id,
            expected_version=lease.version,
            released_at=released_at,
        )
        assert running.permit is not None
        assert running.permit_ref is not None
        assert running.worker_id is not None
        restarted = support._restart_coordinator(harness)

        with pytest.raises(AgentKernelError) as rejected:
            await restarted._run_reconciliation(
                running,
                adapter,
                RecoveryContext(
                    deadline=running.permit.deadline,
                    authority_ref=running.authorization_round_digest,
                    worker_id=running.worker_id,
                    permit=running.permit,
                    permit_ref=running.permit_ref,
                ),
                target_dispatch=dispatch,
                phase=_RecoveryExecutionPhase(
                    boundary="RECONCILIATION_SETUP_OR_QUERY",
                ),
            )

        assert rejected.value.code is ErrorCode.VERSION_CONFLICT
        assert adapter.reconcile_calls == 0
        assert (
            harness.store.get_reconciliation_attempt(
                tenant_id=running.tenant_id,
                transaction_id=running.transaction_id,
                recovery_id=running.recovery_id,
                attempt=running.attempt,
            )
            == attempt
        )
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "after_release",
    [timedelta(0), timedelta(minutes=2)],
    ids=("before-expiry", "after-expiry"),
)
async def test_scanner_terminalizes_released_running_reconciliation_without_provider(
    tmp_path: Path,
    after_release: timedelta,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        running, started, _dispatch = await _crash_after_reconciliation_started(
            harness,
            session,
        )
        assert adapter.reconcile_calls == 0
        assert running.lease_id is not None
        lease = harness.store.get_worker_lease(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            lease_id=running.lease_id,
        )
        released_at = harness.clock()
        released = harness.store.release_worker_lease(
            tenant_id=lease.tenant_id,
            transaction_id=lease.transaction_id,
            lease_id=lease.lease_id,
            expected_version=lease.version,
            released_at=released_at,
        )
        harness.clock.advance(after_release)
        harness.store.close()
        reopened_store, reopened_coordinator = support._reopen_coordinator(
            harness,
            tmp_path / "control.db",
        )
        harness.store = reopened_store
        harness.coordinator = reopened_coordinator
        assert (
            harness.store.get_recovery_work(
                tenant_id=running.tenant_id,
                transaction_id=running.transaction_id,
                recovery_id=running.recovery_id,
            )
            == running
        )

        result = await reopened_coordinator.recover_once(running.tenant_id)

        assert result.processed == 1
        assert adapter.reconcile_calls == 0
        closed = harness.store.get_recovery_work(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            recovery_id=running.recovery_id,
        )
        assert closed.state is RecoveryWorkState.REVIEW_REQUIRED
        assert (
            closed.reason_code
            == "EVIDENCE_UNAVAILABLE:RECOVERY_LEASE_RELEASED_WITH_UNKNOWN_OUTCOME"
        )
        unavailable = harness.store.get_recovery_evidence_unavailable(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            recovery_id=running.recovery_id,
        )
        assert unavailable is not None
        assert unavailable.boundary == "RECOVERY_LEASE_RELEASED"
        assert unavailable.reported_at == harness.clock()
        current_lease = harness.store.get_worker_lease(
            tenant_id=released.tenant_id,
            transaction_id=released.transaction_id,
            lease_id=released.lease_id,
        )
        assert current_lease == released
        assert current_lease.released_at == released_at
        closed_attempt = harness.store.get_reconciliation_attempt(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            recovery_id=running.recovery_id,
            attempt=running.attempt,
        )
        assert closed_attempt.outcome is ReconciliationOutcome.UNKNOWN
        assert closed_attempt.version == started.version + 1
        assert closed_attempt.completed_at == unavailable.reported_at
        assert closed_attempt.completion_evidence_refs == unavailable.supporting_refs
        handoff = harness.store.get_recovery_action_handoff(
            tenant_id=running.tenant_id,
            target_transaction_id=running.transaction_id,
            recovery_id=running.recovery_id,
        )
        assert handoff is not None
        assert handoff.closed_at == unavailable.reported_at
        assert handoff.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE
        repeated = await support._restart_coordinator(harness).recover_once(running.tenant_id)
        assert repeated.processed == repeated.remaining == 0
        assert adapter.reconcile_calls == 0
        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            assert (
                reopened.get_recovery_evidence_unavailable(
                    tenant_id=running.tenant_id,
                    transaction_id=running.transaction_id,
                    recovery_id=running.recovery_id,
                )
                == unavailable
            )
            assert (
                reopened.get_worker_lease(
                    tenant_id=released.tenant_id,
                    transaction_id=released.transaction_id,
                    lease_id=released.lease_id,
                )
                == released
            )
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_authorized_reconciliation_crash_remains_scannable_until_deadline_settlement(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        target_before = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        dispatch_before = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED,
        )
        with pytest.raises(CoordinatorInjectedCrash):
            await crashing.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )

        pending = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(pending) == 1
        assert pending[0].state is RecoveryWorkState.PENDING
        assert harness.store.count_recovery_candidates(tenant_id=pending[0].tenant_id) == 1
        open_handoff = harness.store.get_recovery_action_handoff(
            tenant_id=pending[0].tenant_id,
            target_transaction_id=pending[0].transaction_id,
            recovery_id=pending[0].recovery_id,
        )
        assert open_handoff is not None
        assert open_handoff.closed_at is None
        assert adapter.reconcile_calls == 0

        harness.clock.advance(timedelta(minutes=10))
        restarted = support._restart_coordinator(harness)
        expired = await restarted.recover_once(session.record.tenant_id)
        assert expired.processed == 1
        assert len(expired.failures) == 1
        assert expired.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert expired.failures[0].reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        closed = harness.store.get_recovery_work(
            tenant_id=pending[0].tenant_id,
            transaction_id=pending[0].transaction_id,
            recovery_id=pending[0].recovery_id,
        )
        assert closed.state is RecoveryWorkState.REVIEW_REQUIRED
        assert closed.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        recovery_attempt = harness.store.get_intent_attempt(
            tenant_id=closed.tenant_id,
            intent_hash=closed.recovery_action_intent_hash,
            transaction_id=closed.recovery_action_transaction_id,
        )
        assert recovery_attempt.state is IntentAttemptState.NO_EFFECT_CONFIRMED
        recovery_action = harness.store.get_normalized_action(
            closed.tenant_id,
            closed.recovery_action_transaction_id,
        ).action
        recovery_reservation = harness.store.get_capability_chain(
            tenant_id=recovery_action.tenant_id,
            goal_id=recovery_action.goal_id,
            run_id=recovery_action.run_id,
            intent_hash=recovery_action.intent_hash,
        )
        assert recovery_reservation.state is CapabilityReservationState.RELEASED
        handoff = harness.store.get_recovery_action_handoff(
            tenant_id=closed.tenant_id,
            target_transaction_id=closed.transaction_id,
            recovery_id=closed.recovery_id,
        )
        assert handoff is not None
        assert handoff.closed_at == closed.updated_at
        assert handoff.failure_reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert handoff.failure_evidence_ref is not None
        assert (
            harness.store.get_enforced_transaction(
                session.record.tenant_id,
                session.record.transaction_id,
            )
            == target_before
        )
        assert (
            harness.store.get_commit_dispatch(
                tenant_id=session.record.tenant_id,
                transaction_id=session.record.transaction_id,
            )
            == dispatch_before
        )
        assert adapter.reconcile_calls == 0
        repeated = await restarted.recover_once(session.record.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            assert reopened.count_recovery_candidates(tenant_id=closed.tenant_id) == 0
            assert (
                reopened.get_recovery_action_handoff(
                    tenant_id=closed.tenant_id,
                    target_transaction_id=closed.transaction_id,
                    recovery_id=closed.recovery_id,
                )
                == handoff
            )
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_expired_unstarted_reconciliation_persists_review_barrier_and_quiesces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        (
            session,
            target_before,
            dispatch_before,
            deadline,
        ) = await _expire_unstarted_dispatch_recovery(harness)
        target_attempt_before = harness.store.get_intent_attempt(
            tenant_id=target_before.tenant_id,
            intent_hash=target_before.intent_hash,
            transaction_id=target_before.transaction_id,
        )
        assert target_attempt_before.state is IntentAttemptState.RECONCILE_REQUIRED
        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        harness.coordinator = restarted
        calls: list[dict[str, object]] = []
        dispositions: list[EnforcedStoreDisposition] = []
        original_terminalize = reopened_store.terminalize_expired_recovery_handoff

        def capture_terminalization(**kwargs):
            calls.append(dict(kwargs))
            result = original_terminalize(**kwargs)
            dispositions.append(result.disposition)
            return result

        monkeypatch.setattr(
            reopened_store,
            "terminalize_expired_recovery_handoff",
            capture_terminalization,
        )

        first = await restarted.recover_once(target_before.tenant_id)

        assert first.scanned == first.processed == 1
        assert first.remaining == 0
        assert len(first.failures) == 1
        assert first.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert first.failures[0].reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert first.statuses[0].record == target_before
        assert first.statuses[0].record.state is TransactionState.IN_DOUBT
        assert dispositions == [EnforcedStoreDisposition.STORED]
        assert len(calls) == 1
        assert adapter.reconcile_calls == 0
        assert recovery_actions.create_calls == 0
        assert harness.target.state == {"before": "kept"}
        assert not reopened_store.list_recovery_work(
            tenant_id=target_before.tenant_id,
            transaction_id=target_before.transaction_id,
        )
        assert (
            reopened_store.get_intent_attempt(
                tenant_id=target_before.tenant_id,
                intent_hash=target_before.intent_hash,
                transaction_id=target_before.transaction_id,
            )
            == target_attempt_before
        )
        assert (
            reopened_store.get_commit_dispatch(
                tenant_id=target_before.tenant_id,
                transaction_id=target_before.transaction_id,
            )
            == dispatch_before
        )
        handoffs = reopened_store.list_recovery_action_handoffs(
            tenant_id=target_before.tenant_id,
            target_transaction_id=target_before.transaction_id,
        )
        assert len(handoffs) == 1
        handoff = handoffs[0]
        assert handoff.action is None
        assert handoff.created_at == handoff.closed_at == harness.clock()
        assert handoff.created_at > deadline
        assert handoff.binding.absolute_deadline == deadline
        assert handoff.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.AVAILABLE
        assert handoff.failure_evidence_ref is not None
        assert handoff.failure_reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        evidence = harness.artifacts.get_model(
            handoff.failure_evidence_ref,
            CoordinatorEvidence,
        )
        assert evidence.event == "recovery.authorization_handoff_failed"
        assert evidence.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert evidence.recorded_at == handoff.closed_at
        assert evidence.subject_ref == handoff.binding_ref
        settlement_lease = reopened_store.get_worker_lease(
            tenant_id=target_before.tenant_id,
            transaction_id=target_before.transaction_id,
            lease_id=handoff.handoff_lease_id,
        )
        assert settlement_lease.purpose is LeasePurpose.RECOVERY
        assert settlement_lease.acquired_at == settlement_lease.released_at == handoff.created_at
        assert settlement_lease.expires_at == handoff.created_at + timedelta(microseconds=1)
        assert settlement_lease.version == 1
        active_count = reopened_store._connection.execute(
            "SELECT COUNT(*) FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
            (target_before.tenant_id, target_before.transaction_id),
        ).fetchone()
        assert active_count is not None
        assert int(active_count[0]) == 0
        with pytest.raises(AgentKernelError) as released_cannot_grant_work:
            reopened_store._assert_active_lease_tx(
                tenant_id=settlement_lease.tenant_id,
                transaction_id=settlement_lease.transaction_id,
                lease_id=settlement_lease.lease_id,
                worker_id=settlement_lease.worker_id,
                fencing_token=settlement_lease.fencing_token,
                purpose=LeasePurpose.RECOVERY,
                at=settlement_lease.acquired_at,
            )
        assert released_cannot_grant_work.value.code is ErrorCode.VERSION_CONFLICT

        exact_retry = original_terminalize(**calls[0])
        assert exact_retry.disposition is EnforcedStoreDisposition.EXACT_RETRY
        conflicting_evidence = harness.artifacts.put_model(
            evidence.model_copy(
                update={"recorded_at": evidence.recorded_at + timedelta(microseconds=1)}
            )
        ).digest
        conflicting_calls = (
            {"failure_evidence_ref": conflicting_evidence},
            {"worker_id": "worker:conflicting-settlement"},
            {"lease_id": "lease:conflicting-settlement"},
            {"recorded_at": harness.clock() + timedelta(microseconds=1)},
        )
        for changed in conflicting_calls:
            arguments = {**calls[0], **changed}
            with pytest.raises(AgentKernelError) as conflict:
                original_terminalize(**arguments)
            assert conflict.value.code is ErrorCode.VERSION_CONFLICT

        repeated = await restarted.recover_once(target_before.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert adapter.reconcile_calls == recovery_actions.create_calls == 0

        reopened_store.close()
        second_store, second_restart = support._reopen_coordinator(harness, database_path)
        harness.store = second_store
        harness.coordinator = second_restart
        after_restart = await second_restart.recover_once(target_before.tenant_id)
        assert after_restart.scanned == after_restart.processed == after_restart.remaining == 0
        assert not after_restart.failures
        assert second_store.count_recovery_candidates(tenant_id=target_before.tenant_id) == 0
        assert second_store.list_recovery_action_handoffs(
            tenant_id=target_before.tenant_id,
            target_transaction_id=target_before.transaction_id,
        ) == (handoff,)
        assert adapter.reconcile_calls == recovery_actions.create_calls == 0
        assert session.record.transaction_id == target_before.transaction_id
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_expired_unstarted_reconciliation_quiesces_when_artifacts_are_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        (
            _session,
            target_before,
            dispatch_before,
            deadline,
        ) = await _expire_unstarted_dispatch_recovery(harness)
        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        captured: list[dict[str, object]] = []
        original_terminalize = reopened_store.terminalize_expired_recovery_handoff

        def capture_terminalization(**kwargs):
            captured.append(dict(kwargs))
            return original_terminalize(**kwargs)

        def artifact_outage(*_args, **_kwargs):
            raise OSError("synthetic artifact persistence outage")

        monkeypatch.setattr(
            reopened_store,
            "terminalize_expired_recovery_handoff",
            capture_terminalization,
        )
        monkeypatch.setattr(restarted._artifacts, "put_model", artifact_outage)

        first = await restarted.recover_once(target_before.tenant_id)

        unavailable_reason = (
            f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{ErrorCode.DEADLINE_EXCEEDED.value}"
        )
        assert first.scanned == first.processed == 1
        assert first.remaining == 0
        assert len(first.failures) == 1
        assert first.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert first.failures[0].reason_code == unavailable_reason
        assert first.failures[0].evidence_ref is None
        assert first.statuses[0].record == target_before
        assert len(captured) == 1
        assert captured[0]["failure_evidence_ref"] is None
        assert (
            captured[0]["failure_evidence_status"]
            is RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE
        )
        assert captured[0]["reason_code"] == unavailable_reason
        assert adapter.reconcile_calls == recovery_actions.create_calls == 0
        assert harness.target.state == {"before": "kept"}
        assert not reopened_store.list_recovery_work(
            tenant_id=target_before.tenant_id,
            transaction_id=target_before.transaction_id,
        )
        assert (
            reopened_store.get_commit_dispatch(
                tenant_id=target_before.tenant_id,
                transaction_id=target_before.transaction_id,
            )
            == dispatch_before
        )
        handoffs = reopened_store.list_recovery_action_handoffs(
            tenant_id=target_before.tenant_id,
            target_transaction_id=target_before.transaction_id,
        )
        assert len(handoffs) == 1
        handoff = handoffs[0]
        assert handoff.action is None
        assert handoff.created_at == handoff.closed_at == harness.clock()
        assert handoff.created_at > deadline
        assert handoff.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE
        assert handoff.failure_evidence_ref is None
        assert handoff.failure_reason_code == unavailable_reason
        lease = reopened_store.get_worker_lease(
            tenant_id=target_before.tenant_id,
            transaction_id=target_before.transaction_id,
            lease_id=handoff.handoff_lease_id,
        )
        assert lease.acquired_at == lease.released_at == handoff.created_at
        assert lease.expires_at == handoff.created_at + timedelta(microseconds=1)
        assert lease.version == 1
        active_count = reopened_store._connection.execute(
            "SELECT COUNT(*) FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
            (target_before.tenant_id, target_before.transaction_id),
        ).fetchone()
        assert active_count is not None
        assert int(active_count[0]) == 0

        healthy_status = restarted._recovery_result_status(
            target_before.tenant_id,
            target_before.transaction_id,
        )
        assert healthy_status == first.statuses[0]
        projection = reopened_store.get_transaction_projection(
            tenant_id=target_before.tenant_id,
            transaction_id=target_before.transaction_id,
        )
        blocked_ref = next(
            round_record.authority_snapshot_ref
            for round_record in projection.authorization_rounds
            if round_record.authority_snapshot_ref is not None
        )
        read_outage = _SelectiveGetOutageArtifacts(restarted._artifacts, blocked_ref)
        degraded_coordinator = _clone_coordinator(
            harness,
            store=reopened_store,
            artifacts=read_outage,
            authority_snapshots=restarted._authority_snapshots,
            recovery_actions=recovery_actions,
        )
        with pytest.raises(AgentKernelError) as unrelated_outage:
            degraded_coordinator._recovery_result_status(
                target_before.tenant_id,
                target_before.transaction_id,
            )
        assert unrelated_outage.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        assert read_outage.blocked_gets == 1

        artifact_path = support._artifact_path(harness.artifacts.root, blocked_ref)
        artifact_content = artifact_path.read_bytes()
        try:
            artifact_path.write_bytes(b"corrupt-authorization-artifact")
            with pytest.raises(AgentKernelError) as corrupt:
                restarted._recovery_result_status(
                    target_before.tenant_id,
                    target_before.transaction_id,
                )
            assert corrupt.value.code is ErrorCode.INTEGRITY_ERROR
        finally:
            _restore_private_artifact(harness.artifacts, artifact_path, artifact_content)

        for mutation in ("untyped", "open"):
            malformed_coordinator = _clone_coordinator(
                harness,
                store=_RecoveryHandoffProjectionStore(reopened_store, mutation),
                artifacts=read_outage,
                authority_snapshots=restarted._authority_snapshots,
                recovery_actions=recovery_actions,
            )
            with pytest.raises(AgentKernelError) as rejected:
                malformed_coordinator._recovery_result_status(
                    target_before.tenant_id,
                    target_before.transaction_id,
                )
            assert rejected.value.code is ErrorCode.EVIDENCE_UNAVAILABLE

        exact_retry = original_terminalize(**captured[0])
        assert exact_retry.disposition is EnforcedStoreDisposition.EXACT_RETRY
        blocked_gets_before_exact_retry = read_outage.blocked_gets
        with pytest.raises(AgentKernelError) as exact_retry_outage:
            degraded_coordinator._recovery_result_status(
                target_before.tenant_id,
                target_before.transaction_id,
            )
        assert exact_retry_outage.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        assert read_outage.blocked_gets == 4
        assert read_outage.blocked_gets == blocked_gets_before_exact_retry + 1
        repeated = await restarted.recover_once(target_before.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert len(repeated.failures) == 1
        assert repeated.failures[0].kind is RecoveryFailureKind.EVIDENCE_AUDIT
        assert repeated.failures[0].reason_code == ErrorCode.EVIDENCE_UNAVAILABLE.value
        exact_repeat = await restarted.recover_once(target_before.tenant_id)
        assert exact_repeat.scanned == exact_repeat.processed == exact_repeat.remaining == 0
        assert not exact_repeat.failures

        reopened_store.close()
        final_store, final_restart = support._reopen_coordinator(harness, database_path)
        harness.store = final_store
        after_restart = await final_restart.recover_once(target_before.tenant_id)
        assert after_restart.scanned == after_restart.processed == after_restart.remaining == 0
        assert not after_restart.failures
        assert final_store.count_recovery_candidates(tenant_id=target_before.tenant_id) == 0
        assert final_store.list_recovery_action_handoffs(
            tenant_id=target_before.tenant_id,
            target_transaction_id=target_before.transaction_id,
        ) == (handoff,)
        final_projection = final_store.get_transaction_projection(
            tenant_id=target_before.tenant_id,
            transaction_id=target_before.transaction_id,
        )
        final_blocked_ref = next(
            round_record.authority_snapshot_ref
            for round_record in final_projection.authorization_rounds
            if round_record.authority_snapshot_ref is not None
        )
        final_outage = _SelectiveGetOutageArtifacts(
            final_restart._artifacts,
            final_blocked_ref,
        )
        reopened_degraded = _clone_coordinator(
            harness,
            store=final_store,
            artifacts=final_outage,
            authority_snapshots=final_restart._authority_snapshots,
            recovery_actions=recovery_actions,
        )
        with pytest.raises(AgentKernelError) as reopened_outage:
            reopened_degraded._recovery_result_status(
                target_before.tenant_id,
                target_before.transaction_id,
            )
        assert reopened_outage.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        assert final_outage.blocked_gets == 1
        assert adapter.reconcile_calls == recovery_actions.create_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter_type", "expected_kind"),
    [
        (support._ControlledVerificationAdapter, RecoveryWorkKind.ROLLBACK),
        (support._LateCompensatingAdapter, RecoveryWorkKind.COMPENSATE),
    ],
    ids=("rollback", "compensate"),
)
@pytest.mark.parametrize("artifact_outage", [False, True], ids=("evidence", "outage"))
async def test_expired_unstarted_failed_recovery_terminalizes_without_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    adapter_type: type[support._ControlledVerificationAdapter],
    expected_kind: RecoveryWorkKind,
    artifact_outage: bool,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=CoordinatorCrashPoint.AFTER_OUTCOME_CLASSIFIED,
    )
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        _session, failed, dispatch, deadline = await _expire_unstarted_failed_recovery(harness)
        action = harness.store.get_normalized_action(
            failed.tenant_id,
            failed.transaction_id,
        ).action
        target_attempt_before = harness.store.get_intent_attempt(
            tenant_id=failed.tenant_id,
            intent_hash=failed.intent_hash,
            transaction_id=failed.transaction_id,
        )
        assert target_attempt_before.state is IntentAttemptState.REVIEW_REQUIRED
        target_capability_before = harness.store.get_capability_chain(
            tenant_id=action.tenant_id,
            goal_id=action.goal_id,
            run_id=action.run_id,
            intent_hash=action.intent_hash,
        )
        assert target_capability_before.state is CapabilityReservationState.COMMITTED

        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        captured: list[dict[str, object]] = []
        original_terminalize = reopened_store.terminalize_expired_recovery_handoff

        def capture_terminalization(**kwargs):
            captured.append(dict(kwargs))
            return original_terminalize(**kwargs)

        monkeypatch.setattr(
            reopened_store,
            "terminalize_expired_recovery_handoff",
            capture_terminalization,
        )
        outage = _TerminalRecoveryEvidencePutOutageArtifacts(restarted._artifacts)
        if artifact_outage:
            monkeypatch.setattr(restarted, "_artifacts", outage)

        first = await restarted.recover_once(failed.tenant_id)

        expected_reason = (
            f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{ErrorCode.DEADLINE_EXCEEDED.value}"
            if artifact_outage
            else ErrorCode.DEADLINE_EXCEEDED.value
        )
        expected_status = (
            RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE
            if artifact_outage
            else RecoveryHandoffFailureEvidenceStatus.AVAILABLE
        )
        assert first.scanned == first.processed == 1
        assert first.remaining == 0
        assert len(first.failures) == 1
        assert first.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert first.failures[0].reason_code == expected_reason
        terminal = first.statuses[0].record
        assert terminal.state is TransactionState.RECOVERY_FAILED
        assert terminal.version == failed.version + 1
        assert terminal.updated_at == harness.clock()
        assert terminal.reason_code == expected_reason
        assert not reopened_store.list_recovery_work(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )
        assert len(captured) == 1
        assert recovery_actions.create_calls == 0
        adapter = harness.adapter
        assert isinstance(adapter, support._ControlledVerificationAdapter)
        assert adapter.rollback_calls == 0
        if isinstance(adapter, support._LateCompensatingAdapter):
            assert adapter.compensation_calls == 0

        handoffs = reopened_store.list_recovery_action_handoffs(
            tenant_id=failed.tenant_id,
            target_transaction_id=failed.transaction_id,
        )
        assert len(handoffs) == 1
        handoff = handoffs[0]
        assert handoff.binding.recovery_kind is expected_kind
        assert handoff.binding.absolute_deadline == deadline
        assert handoff.binding.target_evidence_ref == canonical_digest(dispatch)
        assert handoff.action is None
        assert handoff.created_at == handoff.closed_at == harness.clock()
        assert handoff.created_at > deadline
        assert handoff.failure_evidence_status is expected_status
        assert handoff.failure_reason_code == expected_reason
        assert (handoff.failure_evidence_ref is None) is artifact_outage
        if handoff.failure_evidence_ref is not None:
            evidence = harness.artifacts.get_model(
                handoff.failure_evidence_ref,
                CoordinatorEvidence,
            )
            assert evidence.event == "recovery.authorization_handoff_failed"
            assert evidence.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
            assert evidence.subject_ref == handoff.binding_ref

        settlement_lease = reopened_store.get_worker_lease(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
            lease_id=handoff.handoff_lease_id,
        )
        assert settlement_lease.purpose is LeasePurpose.RECOVERY
        assert settlement_lease.acquired_at == settlement_lease.released_at == handoff.created_at
        assert settlement_lease.expires_at == handoff.created_at + timedelta(microseconds=1)
        assert settlement_lease.version == 1
        active_count = reopened_store._connection.execute(
            "SELECT COUNT(*) FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
            (failed.tenant_id, failed.transaction_id),
        ).fetchone()
        assert active_count is not None
        assert int(active_count[0]) == 0
        assert (
            reopened_store.get_intent_attempt(
                tenant_id=failed.tenant_id,
                intent_hash=failed.intent_hash,
                transaction_id=failed.transaction_id,
            )
            == target_attempt_before
        )
        assert (
            reopened_store.get_capability_chain(
                tenant_id=action.tenant_id,
                goal_id=action.goal_id,
                run_id=action.run_id,
                intent_hash=action.intent_hash,
            )
            == target_capability_before
        )
        event = reopened_store.list_enforced_transaction_events(
            failed.tenant_id,
            failed.transaction_id,
        )[-1]
        assert event.event == TransitionEvent.RECOVERY_UNAVAILABLE.value
        assert event.source_state is TransactionState.FAILED
        assert event.target_state is TransactionState.RECOVERY_FAILED
        assert event.recorded_at == handoff.closed_at
        assert event.evidence_refs == (handoff.failure_evidence_ref or handoff.binding_ref,)

        exact = original_terminalize(**captured[0])
        assert exact.disposition is EnforcedStoreDisposition.EXACT_RETRY
        repeated = await restarted.recover_once(failed.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        if artifact_outage:
            assert len(repeated.failures) == 1
            assert repeated.failures[0].kind is RecoveryFailureKind.EVIDENCE_AUDIT
            quiet = await restarted.recover_once(failed.tenant_id)
            assert quiet.scanned == quiet.processed == quiet.remaining == 0
            assert not quiet.failures
        else:
            assert not repeated.failures

        reopened_store.close()
        final_store, final_restart = support._reopen_coordinator(harness, database_path)
        harness.store = final_store
        after_restart = await final_restart.recover_once(failed.tenant_id)
        assert after_restart.scanned == after_restart.processed == after_restart.remaining == 0
        assert not after_restart.failures
        assert final_store.count_recovery_candidates(tenant_id=failed.tenant_id) == 0
        assert recovery_actions.create_calls == 0
        assert adapter.rollback_calls == 0
        if isinstance(adapter, support._LateCompensatingAdapter):
            assert adapter.compensation_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "adapter_type",
    [support._ControlledVerificationAdapter, support._LateCompensatingAdapter],
    ids=("rollback", "compensate"),
)
async def test_expired_failed_recovery_terminalization_is_crash_consistent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    adapter_type: type[support._ControlledVerificationAdapter],
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=CoordinatorCrashPoint.AFTER_OUTCOME_CLASSIFIED,
    )
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        _session, failed, _dispatch, _deadline = await _expire_unstarted_failed_recovery(harness)
        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        captured: list[dict[str, object]] = []
        original_terminalize = reopened_store.terminalize_expired_recovery_handoff

        def crash_after_commit(**kwargs):
            captured.append(dict(kwargs))
            original_terminalize(**kwargs)
            raise SimulatedProcessDeath

        monkeypatch.setattr(
            reopened_store,
            "terminalize_expired_recovery_handoff",
            crash_after_commit,
        )
        with pytest.raises(SimulatedProcessDeath):
            await restarted.recover_once(failed.tenant_id)
        assert len(captured) == 1
        assert (
            reopened_store.get_enforced_transaction(
                failed.tenant_id,
                failed.transaction_id,
            ).state
            is TransactionState.RECOVERY_FAILED
        )
        assert not reopened_store.list_recovery_work(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )

        reopened_store.close()
        recovered_store, recovered = support._reopen_coordinator(harness, database_path)
        harness.store = recovered_store
        exact = recovered_store.terminalize_expired_recovery_handoff(**captured[0])
        assert exact.disposition is EnforcedStoreDisposition.EXACT_RETRY
        converged = await recovered.recover_once(failed.tenant_id)
        assert converged.scanned == converged.processed == converged.remaining == 0
        assert not converged.failures
        handoffs = recovered_store.list_recovery_action_handoffs(
            tenant_id=failed.tenant_id,
            target_transaction_id=failed.transaction_id,
        )
        assert len(handoffs) == 1
        assert handoffs[0].action is None
        assert handoffs[0].closed_at is not None
        assert recovery_actions.create_calls == 0
        adapter = harness.adapter
        assert isinstance(adapter, support._ControlledVerificationAdapter)
        assert adapter.rollback_calls == 0
        if isinstance(adapter, support._LateCompensatingAdapter):
            assert adapter.compensation_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "adapter_type",
    [support._ControlledVerificationAdapter, support._LateCompensatingAdapter],
    ids=("rollback", "compensate"),
)
async def test_concurrent_expired_failed_recovery_scans_share_one_terminal_barrier(
    tmp_path: Path,
    adapter_type: type[support._ControlledVerificationAdapter],
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=CoordinatorCrashPoint.AFTER_OUTCOME_CLASSIFIED,
    )
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        _session, failed, _dispatch, _deadline = await _expire_unstarted_failed_recovery(harness)
        harness.store.close()
        barrier = threading.Barrier(2)
        capture_lock = threading.Lock()
        dispositions: list[EnforcedStoreDisposition] = []
        scan_results: list[tuple[int, int, int]] = []

        def run_scan() -> None:
            store = SQLiteEnforcedTransactionStore(database_path)
            try:
                coordinator = _clone_coordinator(
                    harness,
                    store=store,
                    config=EnforcedCoordinatorConfig(
                        worker_id="worker:parallel-failed-expiry",
                        lease_duration=timedelta(minutes=1),
                        recovery_deadline=timedelta(minutes=4),
                        reconciliation_backoff=timedelta(seconds=2),
                    ),
                )
                original_terminalize = store.terminalize_expired_recovery_handoff

                def gated_terminalize(**kwargs):
                    barrier.wait(timeout=5)
                    result = original_terminalize(**kwargs)
                    with capture_lock:
                        dispositions.append(result.disposition)
                    return result

                store.terminalize_expired_recovery_handoff = gated_terminalize
                result = asyncio.run(coordinator.recover_once(failed.tenant_id))
                with capture_lock:
                    scan_results.append((result.scanned, result.processed, result.remaining))
            finally:
                store.close()

        await asyncio.gather(
            asyncio.to_thread(run_scan),
            asyncio.to_thread(run_scan),
        )

        assert sorted(dispositions) == sorted(
            [
                EnforcedStoreDisposition.STORED,
                EnforcedStoreDisposition.EXACT_RETRY,
            ]
        )
        assert sorted(scan_results) == [(1, 1, 0), (1, 1, 0)]
        reopened = SQLiteEnforcedTransactionStore(database_path)
        harness.store = reopened
        terminal = reopened.get_enforced_transaction(
            failed.tenant_id,
            failed.transaction_id,
        )
        assert terminal.state is TransactionState.RECOVERY_FAILED
        handoffs = reopened.list_recovery_action_handoffs(
            tenant_id=failed.tenant_id,
            target_transaction_id=failed.transaction_id,
        )
        assert len(handoffs) == 1
        assert handoffs[0].action is None
        assert handoffs[0].closed_at is not None
        assert reopened.count_recovery_candidates(tenant_id=failed.tenant_id) == 0
        assert recovery_actions.create_calls == 0
        adapter = harness.adapter
        assert isinstance(adapter, support._ControlledVerificationAdapter)
        assert adapter.rollback_calls == 0
        if isinstance(adapter, support._LateCompensatingAdapter):
            assert adapter.compensation_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter_type", "expected_kind", "wrong_kind"),
    [
        (
            support._ControlledVerificationAdapter,
            RecoveryWorkKind.ROLLBACK,
            RecoveryWorkKind.COMPENSATE,
        ),
        (
            support._LateCompensatingAdapter,
            RecoveryWorkKind.COMPENSATE,
            RecoveryWorkKind.ROLLBACK,
        ),
    ],
    ids=("rollback", "compensate"),
)
async def test_expired_failed_recovery_terminalization_rejects_conflicting_generation(
    tmp_path: Path,
    adapter_type: type[support._ControlledVerificationAdapter],
    expected_kind: RecoveryWorkKind,
    wrong_kind: RecoveryWorkKind,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=CoordinatorCrashPoint.AFTER_OUTCOME_CLASSIFIED,
    )
    try:
        _session, failed, dispatch, _deadline = await _expire_unstarted_failed_recovery(harness)
        coordinator = _clone_coordinator(harness)
        binding = coordinator._propose_recovery_action_binding(
            failed,
            kind=expected_kind,
            target=dispatch,
            target_ref=canonical_digest(dispatch),
            observed_at=harness.clock(),
            predecessor=None,
        )
        evidence_ref = harness.artifacts.put_model(
            CoordinatorEvidence(
                transaction_id=failed.transaction_id,
                event="recovery.authorization_handoff_failed",
                reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                recorded_at=harness.clock(),
                subject_ref=canonical_digest(binding),
            )
        ).digest
        arguments: dict[str, object] = {
            "tenant_id": failed.tenant_id,
            "transaction_id": failed.transaction_id,
            "expected_transaction_version": failed.version,
            "binding": binding,
            "lease_id": "lease:failed-expiry-probe",
            "worker_id": "worker:failed-expiry-probe",
            "failure_evidence_ref": evidence_ref,
            "recorded_at": harness.clock(),
        }

        with pytest.raises(AgentKernelError) as stale:
            harness.store.terminalize_expired_recovery_handoff(
                **{**arguments, "expected_transaction_version": failed.version + 1}
            )
        assert stale.value.code is ErrorCode.VERSION_CONFLICT
        with pytest.raises(AgentKernelError) as wrong_target:
            harness.store.terminalize_expired_recovery_handoff(
                **{
                    **arguments,
                    "binding": binding.model_copy(
                        update={"target_evidence_ref": "sha256:" + ("1" * 64)}
                    ),
                }
            )
        assert wrong_target.value.code is ErrorCode.VERSION_CONFLICT
        with pytest.raises(AgentKernelError) as wrong_deadline:
            harness.store.terminalize_expired_recovery_handoff(
                **{
                    **arguments,
                    "binding": binding.model_copy(
                        update={
                            "absolute_deadline": (
                                binding.absolute_deadline - timedelta(microseconds=1)
                            )
                        }
                    ),
                }
            )
        assert wrong_deadline.value.code is ErrorCode.VERSION_CONFLICT
        with pytest.raises(AgentKernelError) as wrong_recovery_kind:
            harness.store.terminalize_expired_recovery_handoff(
                **{
                    **arguments,
                    "binding": binding.model_copy(update={"recovery_kind": wrong_kind}),
                }
            )
        assert wrong_recovery_kind.value.code is ErrorCode.VALIDATION_ERROR

        stored = harness.store.terminalize_expired_recovery_handoff(**arguments)
        assert stored.disposition is EnforcedStoreDisposition.STORED
        for changed in (
            {"worker_id": "worker:conflicting-failed-expiry"},
            {"lease_id": "lease:conflicting-failed-expiry"},
            {"recorded_at": harness.clock() + timedelta(microseconds=1)},
            {
                "failure_evidence_ref": harness.artifacts.put_model(
                    CoordinatorEvidence(
                        transaction_id=failed.transaction_id,
                        event="recovery.authorization_handoff_failed",
                        reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                        recorded_at=harness.clock() + timedelta(microseconds=1),
                        subject_ref=canonical_digest(binding),
                    )
                ).digest
            },
        ):
            with pytest.raises(AgentKernelError) as conflict:
                harness.store.terminalize_expired_recovery_handoff(**{**arguments, **changed})
            assert conflict.value.code is ErrorCode.VERSION_CONFLICT

        trigger_row = harness.store._connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
            "AND name = 'enforced_recovery_action_handoffs_valid_update'"
        ).fetchone()
        assert trigger_row is not None
        assert trigger_row[0] is not None
        with harness.store._immediate():
            harness.store._execute("DROP TRIGGER enforced_recovery_action_handoffs_valid_update")
            harness.store._execute(
                "UPDATE enforced_recovery_action_handoffs SET target_evidence_ref = ? "
                "WHERE tenant_id = ? AND target_transaction_id = ?",
                ("sha256:" + ("2" * 64), failed.tenant_id, failed.transaction_id),
            )
            harness.store._execute(str(trigger_row[0]))
        with pytest.raises(AgentKernelError) as corrupt:
            harness.store.get_transaction_projection(
                tenant_id=failed.tenant_id,
                transaction_id=failed.transaction_id,
            )
        assert corrupt.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter_type", "expected_kind", "expected_state"),
    [
        (
            _PartialCountingReconcileAdapter,
            RecoveryWorkKind.ROLLBACK,
            TransactionState.ROLLED_BACK,
        ),
        (
            _PartialCompensatingReconcileAdapter,
            RecoveryWorkKind.COMPENSATE,
            TransactionState.COMPENSATED,
        ),
    ],
    ids=("rollback", "compensate"),
)
async def test_restart_after_partial_reconciliation_creates_one_follow_on_recovery(
    tmp_path: Path,
    adapter_type: type[support._ControlledVerificationAdapter],
    expected_kind: RecoveryWorkKind,
    expected_state: TransactionState,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(
        adapter,
        (_PartialCountingReconcileAdapter, _PartialCompensatingReconcileAdapter),
    )
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED,
        )
        with pytest.raises(CoordinatorInjectedCrash) as crash:
            await crashing.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert crash.value.point is CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED
        failed = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert failed.state is TransactionState.FAILED
        historical = harness.store.list_recovery_work(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )
        assert len(historical) == 1
        assert historical[0].kind is RecoveryWorkKind.RECONCILE_DISPATCH
        assert historical[0].state is RecoveryWorkState.SUCCEEDED
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=historical[0].tenant_id,
            transaction_id=historical[0].transaction_id,
            recovery_id=historical[0].recovery_id,
            attempt=historical[0].attempt,
        )
        assert attempt.outcome is ReconciliationOutcome.PARTIAL_OR_INVALID

        harness.store.close()
        reopened_store, reopened = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        recovery_config = EnforcedCoordinatorConfig(
            worker_id="worker:partial-follow-on",
            lease_duration=timedelta(minutes=4),
            recovery_deadline=timedelta(minutes=4),
            reconciliation_backoff=timedelta(seconds=2),
        )
        recovered = _clone_coordinator(
            harness,
            store=reopened_store,
            artifacts=reopened._artifacts,
            authority_snapshots=reopened._authority_snapshots,
            config=recovery_config,
        )
        if isinstance(adapter, _PartialCompensatingReconcileAdapter):
            adapter.test_clock = harness.clock

        first = await recovered.recover_once(failed.tenant_id)

        assert first.scanned == first.processed == 1
        assert first.remaining == 0
        assert not first.failures
        assert first.statuses[0].record.state is expected_state
        works = reopened_store.list_recovery_work(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )
        assert len(works) == 2
        follow_on = tuple(
            work for work in works if work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
        )
        assert len(follow_on) == 1
        assert follow_on[0].kind is expected_kind
        assert follow_on[0].state is RecoveryWorkState.SUCCEEDED
        assert adapter.reconcile_calls == 1
        if expected_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 1
        else:
            assert isinstance(adapter, _PartialCompensatingReconcileAdapter)
            assert adapter.compensation_calls == 1

        repeated = await recovered.recover_once(failed.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert (
            len(
                reopened_store.list_recovery_work(
                    tenant_id=failed.tenant_id,
                    transaction_id=failed.transaction_id,
                )
            )
            == 2
        )
        assert adapter.reconcile_calls == 1
        if expected_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 1
        else:
            assert isinstance(adapter, _PartialCompensatingReconcileAdapter)
            assert adapter.compensation_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact_damage", ["missing", "corrupt"])
@pytest.mark.parametrize(
    (
        "adapter_type",
        "crash_point",
        "expected_outcome",
        "intermediate_state",
        "follow_on_kind",
        "terminal_state",
    ),
    [
        (
            _PartialCountingReconcileAdapter,
            CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
            ReconciliationOutcome.PARTIAL_OR_INVALID,
            TransactionState.FAILED,
            RecoveryWorkKind.ROLLBACK,
            TransactionState.ROLLED_BACK,
        ),
        (
            _CountingReconcileAdapter,
            CoordinatorCrashPoint.BEFORE_COMMIT,
            ReconciliationOutcome.NO_EFFECT,
            TransactionState.ABORTING,
            RecoveryWorkKind.DISCARD_STAGING,
            TransactionState.ABORTED,
        ),
    ],
    ids=("partial-rollback", "no-effect-discard"),
)
async def test_terminal_reconciliation_follow_on_revalidates_operation_evidence(
    tmp_path: Path,
    artifact_damage: str,
    adapter_type: type[support._ControlledVerificationAdapter],
    crash_point: CoordinatorCrashPoint,
    expected_outcome: ReconciliationOutcome,
    intermediate_state: TransactionState,
    follow_on_kind: RecoveryWorkKind,
    terminal_state: TransactionState,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=crash_point,
    )
    adapter = harness.adapter
    assert isinstance(adapter, (_PartialCountingReconcileAdapter, _CountingReconcileAdapter))
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED,
        )
        with pytest.raises(CoordinatorInjectedCrash) as crash:
            await crashing.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert crash.value.point is CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED

        intermediate = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert intermediate.state is intermediate_state
        historical_work = harness.store.list_recovery_work(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
        )
        historical_handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=intermediate.tenant_id,
            target_transaction_id=intermediate.transaction_id,
        )
        assert len(historical_work) == len(historical_handoffs) == 1
        reconciliation = historical_work[0]
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=reconciliation.tenant_id,
            transaction_id=reconciliation.transaction_id,
            recovery_id=reconciliation.recovery_id,
            attempt=reconciliation.attempt,
        )
        assert attempt.outcome is expected_outcome
        assert attempt.operation_evidence_ref is not None
        operation_path = support._artifact_path(
            harness.artifacts.root,
            attempt.operation_evidence_ref,
        )
        original_operation = operation_path.read_bytes()
        initial_lease_count = int(
            harness.store._connection.execute(
                "SELECT COUNT(*) FROM enforced_worker_leases "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (intermediate.tenant_id, intermediate.transaction_id),
            ).fetchone()[0]
        )

        if artifact_damage == "missing":
            operation_path.unlink()
            expected_error = ErrorCode.EVIDENCE_UNAVAILABLE
        else:
            operation_path.write_bytes(b"corrupt-reconciliation-operation-evidence")
            expected_error = ErrorCode.INTEGRITY_ERROR

        recovery_actions = _CountingRecoveryActions()
        harness.recovery_actions = recovery_actions
        harness.store.close()
        reopened_store, reopened = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        recovered = _clone_coordinator(
            harness,
            store=reopened_store,
            artifacts=reopened._artifacts,
            authority_snapshots=reopened._authority_snapshots,
            recovery_actions=recovery_actions,
        )
        try:
            with pytest.raises(AgentKernelError) as blocked:
                await recovered.recover_once(intermediate.tenant_id)
            assert blocked.value.code is expected_error
            assert (
                reopened_store.get_enforced_transaction(
                    intermediate.tenant_id,
                    intermediate.transaction_id,
                ).state
                is intermediate_state
            )
            assert (
                reopened_store.list_recovery_work(
                    tenant_id=intermediate.tenant_id,
                    transaction_id=intermediate.transaction_id,
                )
                == historical_work
            )
            assert (
                reopened_store.list_recovery_action_handoffs(
                    tenant_id=intermediate.tenant_id,
                    target_transaction_id=intermediate.transaction_id,
                )
                == historical_handoffs
            )
            assert (
                int(
                    reopened_store._connection.execute(
                        "SELECT COUNT(*) FROM enforced_worker_leases "
                        "WHERE tenant_id = ? AND transaction_id = ?",
                        (intermediate.tenant_id, intermediate.transaction_id),
                    ).fetchone()[0]
                )
                == initial_lease_count
            )
            assert recovery_actions.create_calls == 0
            assert adapter.rollback_calls == adapter.abort_stage_calls == 0
        finally:
            _restore_private_artifact(harness.artifacts, operation_path, original_operation)

        converged = await recovered.recover_once(intermediate.tenant_id)
        assert converged.scanned == converged.processed == 1
        assert converged.remaining == 0
        assert not converged.failures
        assert converged.statuses[0].record.state is terminal_state
        works = reopened_store.list_recovery_work(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
        )
        assert len(works) == 2
        follow_on = tuple(work for work in works if work.kind is follow_on_kind)
        assert len(follow_on) == 1
        assert follow_on[0].state is RecoveryWorkState.SUCCEEDED
        assert recovery_actions.create_calls == 1
        if follow_on_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 1
            assert adapter.abort_stage_calls == 0
        else:
            assert adapter.abort_stage_calls == 1
            assert adapter.rollback_calls == 0

        repeated = await recovered.recover_once(intermediate.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.create_calls == 1
        assert (
            len(
                reopened_store.list_recovery_work(
                    tenant_id=intermediate.tenant_id,
                    transaction_id=intermediate.transaction_id,
                )
            )
            == 2
        )
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact_damage", ["missing", "corrupt"])
@pytest.mark.parametrize(
    "generation_field",
    [
        "permit",
        "recovery_action",
        "approval",
        "handoff_binding",
        "authority_snapshot",
        "authority_context",
        "authority_decision",
        "policy_inputs",
        "policy_snapshot",
        "policy_decision",
    ],
)
@pytest.mark.parametrize(
    (
        "adapter_type",
        "crash_point",
        "intermediate_state",
        "follow_on_kind",
        "terminal_state",
    ),
    [
        (
            _PartialCountingReconcileAdapter,
            CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
            TransactionState.FAILED,
            RecoveryWorkKind.ROLLBACK,
            TransactionState.ROLLED_BACK,
        ),
        (
            _CountingReconcileAdapter,
            CoordinatorCrashPoint.BEFORE_COMMIT,
            TransactionState.ABORTING,
            RecoveryWorkKind.DISCARD_STAGING,
            TransactionState.ABORTED,
        ),
    ],
    ids=("partial-rollback", "no-effect-discard"),
)
async def test_terminal_reconciliation_follow_on_revalidates_full_generation_closure(
    tmp_path: Path,
    artifact_damage: str,
    generation_field: str,
    adapter_type: type[support._ControlledVerificationAdapter],
    crash_point: CoordinatorCrashPoint,
    intermediate_state: TransactionState,
    follow_on_kind: RecoveryWorkKind,
    terminal_state: TransactionState,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=crash_point,
    )
    adapter = harness.adapter
    assert isinstance(adapter, (_PartialCountingReconcileAdapter, _CountingReconcileAdapter))
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    damaged_path: Path | None = None
    original_artifact: bytes | None = None
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED,
        )
        with pytest.raises(CoordinatorInjectedCrash) as crash:
            await crashing.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert crash.value.point is CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED

        intermediate = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert intermediate.state is intermediate_state
        work_items = harness.store.list_recovery_work(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
        )
        handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=intermediate.tenant_id,
            target_transaction_id=intermediate.transaction_id,
        )
        assert len(work_items) == len(handoffs) == 1
        reconciliation = work_items[0]
        assert reconciliation.kind is RecoveryWorkKind.RECONCILE_DISPATCH
        assert reconciliation.state is RecoveryWorkState.SUCCEEDED
        assert reconciliation.permit_ref is not None
        projection = harness.store.get_transaction_projection(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
        )
        assert projection.dispatch_evidence_unavailable is not None
        matching_rounds = tuple(
            round_record
            for round_record in projection.authorization_rounds
            if round_record.controlled_transaction_id == reconciliation.transaction_id
            and round_record.round_id == reconciliation.authorization_round_id
        )
        assert len(matching_rounds) == 1
        authorization_round = matching_rounds[0]
        generation_refs = {
            "permit": reconciliation.permit_ref,
            "recovery_action": reconciliation.recovery_action_digest,
            "approval": reconciliation.approval_evidence_ref,
            "handoff_binding": handoffs[0].binding_ref,
            "authority_snapshot": authorization_round.authority_snapshot_ref,
            "authority_context": authorization_round.authority_context_ref,
            "authority_decision": authorization_round.authority_decision_ref,
            "policy_inputs": authorization_round.policy_inputs_ref,
            "policy_snapshot": authorization_round.policy_snapshot_ref,
            "policy_decision": authorization_round.policy_decision_ref,
        }
        assert all(artifact_ref is not None for artifact_ref in generation_refs.values())
        assert harness.artifacts.get(handoffs[0].binding_ref)
        baseline_leases = _worker_lease_snapshot(
            harness.store,
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
        )

        harness.store.close()
        reopened_store, recovered = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        recovered = _clone_coordinator(
            harness,
            store=reopened_store,
            artifacts=recovered._artifacts,
            authority_snapshots=recovered._authority_snapshots,
            recovery_actions=recovery_actions,
        )
        artifact_ref = generation_refs[generation_field]
        assert artifact_ref is not None
        damaged_path = support._artifact_path(harness.artifacts.root, artifact_ref)
        original_artifact = damaged_path.read_bytes()
        if artifact_damage == "missing":
            damaged_path.unlink()
            expected_error = ErrorCode.EVIDENCE_UNAVAILABLE
        else:
            damaged_path.write_bytes(
                f"corrupt-reconciliation-generation-{generation_field}".encode()
            )
            expected_error = ErrorCode.INTEGRITY_ERROR
        damaged_files = _artifact_file_snapshot(harness.artifacts.root)
        try:
            with pytest.raises(AgentKernelError) as blocked_status:
                recovered._recovery_result_status(
                    intermediate.tenant_id,
                    intermediate.transaction_id,
                )
            assert blocked_status.value.code is expected_error
            with pytest.raises(AgentKernelError) as blocked_recovery:
                await recovered.recover_once(intermediate.tenant_id)
            assert blocked_recovery.value.code is expected_error
            assert (
                reopened_store.get_enforced_transaction(
                    intermediate.tenant_id,
                    intermediate.transaction_id,
                )
                == intermediate
            )
            assert (
                reopened_store.list_recovery_work(
                    tenant_id=intermediate.tenant_id,
                    transaction_id=intermediate.transaction_id,
                )
                == work_items
            )
            assert (
                reopened_store.list_recovery_action_handoffs(
                    tenant_id=intermediate.tenant_id,
                    target_transaction_id=intermediate.transaction_id,
                )
                == handoffs
            )
            assert (
                _worker_lease_snapshot(
                    reopened_store,
                    tenant_id=intermediate.tenant_id,
                    transaction_id=intermediate.transaction_id,
                )
                == baseline_leases
            )
            assert _artifact_file_snapshot(harness.artifacts.root) == damaged_files
            assert recovery_actions.create_calls == adapter.reconcile_calls == 1
            assert adapter.rollback_calls == adapter.abort_stage_calls == 0
        finally:
            _restore_private_artifact(harness.artifacts, damaged_path, original_artifact)
            damaged_path = None
            original_artifact = None

        converged = await recovered.recover_once(intermediate.tenant_id)
        assert converged.scanned == converged.processed == 1
        assert converged.remaining == 0
        assert not converged.failures
        assert converged.statuses[0].record.state is terminal_state
        works = reopened_store.list_recovery_work(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
        )
        follow_on = tuple(work for work in works if work.kind is follow_on_kind)
        assert len(works) == 2
        assert len(follow_on) == 1
        assert follow_on[0].state is RecoveryWorkState.SUCCEEDED
        assert recovery_actions.create_calls == 2
        if follow_on_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 1
            assert adapter.abort_stage_calls == 0
        else:
            assert adapter.abort_stage_calls == 1
            assert adapter.rollback_calls == 0
        repeated = await recovered.recover_once(intermediate.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.create_calls == 2
    finally:
        if damaged_path is not None and original_artifact is not None:
            _restore_private_artifact(harness.artifacts, damaged_path, original_artifact)
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact_damage", ["missing", "corrupt"])
@pytest.mark.parametrize(
    (
        "adapter_type",
        "crash_point",
        "expected_outcome",
        "intermediate_state",
        "follow_on_kind",
        "terminal_state",
    ),
    [
        (
            _PartialCountingReconcileAdapter,
            CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
            ReconciliationOutcome.PARTIAL_OR_INVALID,
            TransactionState.FAILED,
            RecoveryWorkKind.ROLLBACK,
            TransactionState.ROLLED_BACK,
        ),
        (
            _CountingReconcileAdapter,
            CoordinatorCrashPoint.BEFORE_COMMIT,
            ReconciliationOutcome.NO_EFFECT,
            TransactionState.ABORTING,
            RecoveryWorkKind.DISCARD_STAGING,
            TransactionState.ABORTED,
        ),
    ],
    ids=("partial-rollback", "no-effect-discard"),
)
async def test_immediate_reconciliation_follow_on_revalidates_historical_attempt(
    tmp_path: Path,
    artifact_damage: str,
    adapter_type: type[support._ControlledVerificationAdapter],
    crash_point: CoordinatorCrashPoint,
    expected_outcome: ReconciliationOutcome,
    intermediate_state: TransactionState,
    follow_on_kind: RecoveryWorkKind,
    terminal_state: TransactionState,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=crash_point,
    )
    adapter = harness.adapter
    assert isinstance(adapter, (_PartialCountingReconcileAdapter, _CountingReconcileAdapter))
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        running, _started, _dispatch = await _crash_after_reconciliation_started(
            harness,
            session,
        )
        assert running.permit_ref is not None
        harness.clock.advance(timedelta(minutes=1, microseconds=1))
        acquired_at = harness.clock()
        authorization_round = harness.store.get_authorization_round(
            tenant_id=running.tenant_id,
            controlled_transaction_id=running.transaction_id,
            round_id=running.authorization_round_id,
        )
        assert authorization_round.authority_valid_until is not None
        expires_at = min(
            running.deadline,
            authorization_round.authority_valid_until,
            acquired_at + timedelta(seconds=30),
        )
        preview = harness.store.preview_recovery_reclaim(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            recovery_id=running.recovery_id,
            expected_work_version=running.version,
            lease_id=f"lease:immediate-historical:{artifact_damage}",
            worker_id=f"worker:immediate-historical:{artifact_damage}",
            acquired_at=acquired_at,
            expires_at=expires_at,
        )
        coordinator = support._restart_coordinator(
            harness,
            worker_id=preview.lease.worker_id,
        )
        replacement_permit_ref = coordinator._put_model(preview.permit)
        assert replacement_permit_ref == preview.permit_ref
        first_operation_ref = coordinator._put_control_evidence(
            transaction_id=running.transaction_id,
            event="reconciliation.query_failed",
            reason_code="RECOVERY_LEASE_EXPIRED",
            recorded_at=acquired_at,
            subject_ref=running.permit_ref,
        )
        reclaimed = harness.store.reclaim_expired_recovery(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            recovery_id=running.recovery_id,
            expected_work_version=running.version,
            lease_id=preview.lease.lease_id,
            worker_id=preview.lease.worker_id,
            acquired_at=preview.lease.acquired_at,
            expires_at=preview.lease.expires_at,
            permit=preview.permit,
            permit_ref=preview.permit_ref,
            evidence_refs=tuple(
                sorted(
                    {
                        running.permit_ref,
                        replacement_permit_ref,
                        first_operation_ref,
                    }
                )
            ),
            operation_evidence_ref=first_operation_ref,
            operation_reason_code="RECOVERY_LEASE_EXPIRED",
        )
        assert reclaimed.work.attempt == 2
        assert reclaimed.work.permit is not None
        assert reclaimed.work.permit_ref is not None
        target_dispatch = coordinator._load_recovery_target_snapshot(reclaimed.work)
        context = RecoveryContext(
            deadline=reclaimed.work.permit.deadline,
            authority_ref=reclaimed.work.authorization_round_digest,
            worker_id=reclaimed.work.worker_id,
            permit=reclaimed.work.permit,
            permit_ref=reclaimed.work.permit_ref,
        )
        operation_path = support._artifact_path(
            harness.artifacts.root,
            first_operation_ref,
        )
        original_operation = operation_path.read_bytes()
        baseline_handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=running.tenant_id,
            target_transaction_id=running.transaction_id,
        )
        baseline_lease_count = int(
            harness.store._connection.execute(
                "SELECT COUNT(*) FROM enforced_worker_leases "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (running.tenant_id, running.transaction_id),
            ).fetchone()[0]
        )
        baseline_factory_calls = recovery_actions.create_calls
        if artifact_damage == "missing":
            operation_path.unlink()
            expected_error = ErrorCode.EVIDENCE_UNAVAILABLE
        else:
            operation_path.write_bytes(b"corrupt-immediate-historical-operation")
            expected_error = ErrorCode.INTEGRITY_ERROR

        try:
            with pytest.raises(AgentKernelError) as blocked:
                await coordinator._run_reconciliation(
                    reclaimed.work,
                    adapter,
                    context,
                    target_dispatch=target_dispatch,  # type: ignore[arg-type]
                    phase=_RecoveryExecutionPhase(boundary="RECONCILIATION_SETUP_OR_QUERY"),
                )
            assert blocked.value.code is expected_error
            intermediate = harness.store.get_enforced_transaction(
                running.tenant_id,
                running.transaction_id,
            )
            assert intermediate.state is intermediate_state
            attempts = harness.store.list_reconciliation_attempts(
                tenant_id=running.tenant_id,
                transaction_id=running.transaction_id,
            )
            assert len(attempts) == 2
            assert attempts[0].outcome is ReconciliationOutcome.UNKNOWN
            assert attempts[1].outcome is expected_outcome
            assert (
                harness.store.list_recovery_action_handoffs(
                    tenant_id=running.tenant_id,
                    target_transaction_id=running.transaction_id,
                )
                == baseline_handoffs
            )
            assert (
                int(
                    harness.store._connection.execute(
                        "SELECT COUNT(*) FROM enforced_worker_leases "
                        "WHERE tenant_id = ? AND transaction_id = ?",
                        (running.tenant_id, running.transaction_id),
                    ).fetchone()[0]
                )
                == baseline_lease_count
            )
            assert recovery_actions.create_calls == baseline_factory_calls == 1
            assert adapter.rollback_calls == adapter.abort_stage_calls == 0
        finally:
            _restore_private_artifact(harness.artifacts, operation_path, original_operation)

        converged = await coordinator.recover_once(running.tenant_id)
        assert converged.scanned == converged.processed == 1
        assert converged.remaining == 0
        assert not converged.failures
        assert converged.statuses[0].record.state is terminal_state
        works = harness.store.list_recovery_work(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
        )
        follow_on = tuple(work for work in works if work.kind is follow_on_kind)
        assert len(works) == 2
        assert len(follow_on) == 1
        assert follow_on[0].state is RecoveryWorkState.SUCCEEDED
        assert recovery_actions.create_calls == baseline_factory_calls + 1
        assert adapter.reconcile_calls == 1
        if follow_on_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 1
            assert adapter.abort_stage_calls == 0
        else:
            assert adapter.abort_stage_calls == 1
            assert adapter.rollback_calls == 0

        repeated = await coordinator.recover_once(running.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.create_calls == baseline_factory_calls + 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact_damage", ["missing", "corrupt"])
@pytest.mark.parametrize(
    (
        "adapter_type",
        "crash_point",
        "expected_outcome",
        "intermediate_state",
        "follow_on_kind",
        "terminal_state",
    ),
    [
        (
            _PartialCountingReconcileAdapter,
            CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
            ReconciliationOutcome.PARTIAL_OR_INVALID,
            TransactionState.FAILED,
            RecoveryWorkKind.ROLLBACK,
            TransactionState.ROLLED_BACK,
        ),
        (
            _CountingReconcileAdapter,
            CoordinatorCrashPoint.BEFORE_COMMIT,
            ReconciliationOutcome.NO_EFFECT,
            TransactionState.ABORTING,
            RecoveryWorkKind.DISCARD_STAGING,
            TransactionState.ABORTED,
        ),
    ],
    ids=("partial-rollback", "no-effect-discard"),
)
async def test_terminal_reconciliation_follow_on_revalidates_every_completed_attempt(
    tmp_path: Path,
    artifact_damage: str,
    adapter_type: type[support._ControlledVerificationAdapter],
    crash_point: CoordinatorCrashPoint,
    expected_outcome: ReconciliationOutcome,
    intermediate_state: TransactionState,
    follow_on_kind: RecoveryWorkKind,
    terminal_state: TransactionState,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=crash_point,
    )
    adapter = harness.adapter
    assert isinstance(adapter, (_PartialCountingReconcileAdapter, _CountingReconcileAdapter))
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        running, _started, _dispatch = await _crash_after_reconciliation_started(
            harness,
            session,
        )
        assert running.permit_ref is not None
        harness.clock.advance(timedelta(minutes=1, microseconds=1))
        acquired_at = harness.clock()
        authorization_round = harness.store.get_authorization_round(
            tenant_id=running.tenant_id,
            controlled_transaction_id=running.transaction_id,
            round_id=running.authorization_round_id,
        )
        assert authorization_round.authority_valid_until is not None
        expires_at = min(
            running.deadline,
            authorization_round.authority_valid_until,
            acquired_at + timedelta(seconds=30),
        )
        preview = harness.store.preview_recovery_reclaim(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            recovery_id=running.recovery_id,
            expected_work_version=running.version,
            lease_id=f"lease:historical-follow-on:{artifact_damage}",
            worker_id=f"worker:historical-follow-on:{artifact_damage}",
            acquired_at=acquired_at,
            expires_at=expires_at,
        )
        crashing = support._restart_coordinator(
            harness,
            worker_id=preview.lease.worker_id,
            crash_point=CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED,
        )
        replacement_permit_ref = crashing._put_model(preview.permit)
        assert replacement_permit_ref == preview.permit_ref
        first_operation_ref = crashing._put_control_evidence(
            transaction_id=running.transaction_id,
            event="reconciliation.query_failed",
            reason_code="RECOVERY_LEASE_EXPIRED",
            recorded_at=acquired_at,
            subject_ref=running.permit_ref,
        )
        reclaimed = harness.store.reclaim_expired_recovery(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            recovery_id=running.recovery_id,
            expected_work_version=running.version,
            lease_id=preview.lease.lease_id,
            worker_id=preview.lease.worker_id,
            acquired_at=preview.lease.acquired_at,
            expires_at=preview.lease.expires_at,
            permit=preview.permit,
            permit_ref=preview.permit_ref,
            evidence_refs=tuple(
                sorted(
                    {
                        running.permit_ref,
                        replacement_permit_ref,
                        first_operation_ref,
                    }
                )
            ),
            operation_evidence_ref=first_operation_ref,
            operation_reason_code="RECOVERY_LEASE_EXPIRED",
        )
        assert reclaimed.work.attempt == 2
        assert reclaimed.work.permit is not None
        assert reclaimed.work.permit_ref is not None
        target_dispatch = crashing._load_recovery_target_snapshot(reclaimed.work)
        context = RecoveryContext(
            deadline=reclaimed.work.permit.deadline,
            authority_ref=reclaimed.work.authorization_round_digest,
            worker_id=reclaimed.work.worker_id,
            permit=reclaimed.work.permit,
            permit_ref=reclaimed.work.permit_ref,
        )
        with pytest.raises(CoordinatorInjectedCrash) as crash:
            await crashing._run_reconciliation(
                reclaimed.work,
                adapter,
                context,
                target_dispatch=target_dispatch,  # type: ignore[arg-type]
                phase=_RecoveryExecutionPhase(boundary="RECONCILIATION_SETUP_OR_QUERY"),
            )
        assert crash.value.point is CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED

        intermediate = harness.store.get_enforced_transaction(
            running.tenant_id,
            running.transaction_id,
        )
        assert intermediate.state is intermediate_state
        attempts = harness.store.list_reconciliation_attempts(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
        )
        assert len(attempts) == 2
        assert attempts[0].attempt == 1
        assert attempts[0].outcome is ReconciliationOutcome.UNKNOWN
        assert attempts[0].operation_evidence_ref == first_operation_ref
        assert attempts[1].attempt == 2
        assert attempts[1].outcome is expected_outcome
        historical_work = harness.store.list_recovery_work(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
        )
        historical_handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=running.tenant_id,
            target_transaction_id=running.transaction_id,
        )
        initial_lease_count = int(
            harness.store._connection.execute(
                "SELECT COUNT(*) FROM enforced_worker_leases "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (running.tenant_id, running.transaction_id),
            ).fetchone()[0]
        )
        operation_path = support._artifact_path(
            harness.artifacts.root,
            first_operation_ref,
        )
        original_operation = operation_path.read_bytes()
        if artifact_damage == "missing":
            operation_path.unlink()
            expected_error = ErrorCode.EVIDENCE_UNAVAILABLE
        else:
            operation_path.write_bytes(b"corrupt-historical-reconciliation-operation")
            expected_error = ErrorCode.INTEGRITY_ERROR

        recovery_actions = _CountingRecoveryActions()
        harness.recovery_actions = recovery_actions
        harness.store.close()
        reopened_store, reopened = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        recovered = _clone_coordinator(
            harness,
            store=reopened_store,
            artifacts=reopened._artifacts,
            authority_snapshots=reopened._authority_snapshots,
            recovery_actions=recovery_actions,
        )
        try:
            with pytest.raises(AgentKernelError) as blocked:
                await recovered.recover_once(intermediate.tenant_id)
            assert blocked.value.code is expected_error
            assert (
                reopened_store.get_enforced_transaction(
                    intermediate.tenant_id,
                    intermediate.transaction_id,
                )
                == intermediate
            )
            assert (
                reopened_store.list_recovery_work(
                    tenant_id=intermediate.tenant_id,
                    transaction_id=intermediate.transaction_id,
                )
                == historical_work
            )
            assert (
                reopened_store.list_recovery_action_handoffs(
                    tenant_id=intermediate.tenant_id,
                    target_transaction_id=intermediate.transaction_id,
                )
                == historical_handoffs
            )
            assert (
                int(
                    reopened_store._connection.execute(
                        "SELECT COUNT(*) FROM enforced_worker_leases "
                        "WHERE tenant_id = ? AND transaction_id = ?",
                        (intermediate.tenant_id, intermediate.transaction_id),
                    ).fetchone()[0]
                )
                == initial_lease_count
            )
            assert recovery_actions.create_calls == 0
            assert adapter.reconcile_calls == 1
            assert adapter.rollback_calls == adapter.abort_stage_calls == 0
        finally:
            _restore_private_artifact(harness.artifacts, operation_path, original_operation)

        converged = await recovered.recover_once(intermediate.tenant_id)
        assert converged.scanned == converged.processed == 1
        assert converged.remaining == 0
        assert not converged.failures
        assert converged.statuses[0].record.state is terminal_state
        works = reopened_store.list_recovery_work(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
        )
        follow_on = tuple(work for work in works if work.kind is follow_on_kind)
        assert len(works) == 2
        assert len(follow_on) == 1
        assert follow_on[0].state is RecoveryWorkState.SUCCEEDED
        assert recovery_actions.create_calls == 1
        assert adapter.reconcile_calls == 1
        if follow_on_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 1
            assert adapter.abort_stage_calls == 0
        else:
            assert adapter.abort_stage_calls == 1
            assert adapter.rollback_calls == 0

        repeated = await recovered.recover_once(intermediate.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.create_calls == 1
        assert adapter.reconcile_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_terminal_reconciliation_follow_on_revalidates_retried_work_generation(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._SequencedReconciliationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._SequencedReconciliationAdapter)
    adapter.reconcile_statuses = [
        ReconcileStatus.UNKNOWN,
        ReconcileStatus.PARTIAL_OR_INVALID,
    ]
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        session = await _crash_during_commit(harness)
        recovery = await _stop_dispatch_before_explicit_resume(harness, session)
        first = await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert first.record.state is TransactionState.IN_DOUBT
        first_work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        assert first_work.state is RecoveryWorkState.RETRY_SCHEDULED
        first_attempt = harness.store.get_reconciliation_attempt(
            tenant_id=first_work.tenant_id,
            transaction_id=first_work.transaction_id,
            recovery_id=first_work.recovery_id,
            attempt=first_work.attempt,
        )
        assert first_attempt.outcome is ReconciliationOutcome.UNKNOWN
        assert first_attempt.operation_evidence_ref is not None
        assert first_attempt.next_attempt_not_before is not None

        harness.clock.advance(first_attempt.next_attempt_not_before - harness.clock())
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED,
        )
        with pytest.raises(CoordinatorInjectedCrash) as crash:
            await crashing.recover_once(first_work.tenant_id)
        assert crash.value.point is CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED

        failed = harness.store.get_enforced_transaction(
            first_work.tenant_id,
            first_work.transaction_id,
        )
        assert failed.state is TransactionState.FAILED
        lineage = harness.store.list_recovery_work(
            tenant_id=first_work.tenant_id,
            transaction_id=first_work.transaction_id,
        )
        assert [work.recovery_ordinal for work in lineage] == [1, 2]
        assert lineage[0].state is RecoveryWorkState.RETRIED
        assert lineage[1].state is RecoveryWorkState.SUCCEEDED
        assert lineage[1].predecessor_recovery_id == lineage[0].recovery_id
        assert adapter.reconcile_calls == 2
        assert adapter.rollback_calls == 0
        assert recovery_actions.create_calls == 2

        operation_path = support._artifact_path(
            harness.artifacts.root,
            first_attempt.operation_evidence_ref,
        )
        original_operation = operation_path.read_bytes()
        operation_path.unlink()
        harness.store.close()
        reopened_store, reopened = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        recovered = _clone_coordinator(
            harness,
            store=reopened_store,
            artifacts=reopened._artifacts,
            authority_snapshots=reopened._authority_snapshots,
            recovery_actions=recovery_actions,
        )
        try:
            with pytest.raises(AgentKernelError) as blocked:
                await recovered.recover_once(failed.tenant_id)
            assert blocked.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
            assert (
                reopened_store.list_recovery_work(
                    tenant_id=failed.tenant_id,
                    transaction_id=failed.transaction_id,
                )
                == lineage
            )
            assert adapter.reconcile_calls == recovery_actions.create_calls == 2
            assert adapter.rollback_calls == 0
        finally:
            _restore_private_artifact(harness.artifacts, operation_path, original_operation)

        converged = await recovered.recover_once(failed.tenant_id)
        assert converged.scanned == converged.processed == 1
        assert converged.remaining == 0
        assert not converged.failures
        assert converged.statuses[0].record.state is TransactionState.ROLLED_BACK
        assert adapter.reconcile_calls == 2
        assert adapter.rollback_calls == 1
        assert recovery_actions.create_calls == 3

        repeated = await recovered.recover_once(failed.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert adapter.reconcile_calls == 2
        assert adapter.rollback_calls == 1
        assert recovery_actions.create_calls == 3
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact_damage", ["missing", "corrupt"])
@pytest.mark.parametrize(
    (
        "crash_point",
        "terminal_status",
        "intermediate_state",
        "follow_on_kind",
        "terminal_state",
    ),
    [
        (
            CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
            ReconcileStatus.PARTIAL_OR_INVALID,
            TransactionState.FAILED,
            RecoveryWorkKind.ROLLBACK,
            TransactionState.ROLLED_BACK,
        ),
        (
            CoordinatorCrashPoint.BEFORE_COMMIT,
            ReconcileStatus.NO_EFFECT,
            TransactionState.ABORTING,
            RecoveryWorkKind.DISCARD_STAGING,
            TransactionState.ABORTED,
        ),
    ],
    ids=("partial-rollback", "no-effect-discard"),
)
async def test_immediate_reconciliation_follow_on_revalidates_retried_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_damage: str,
    crash_point: CoordinatorCrashPoint,
    terminal_status: ReconcileStatus,
    intermediate_state: TransactionState,
    follow_on_kind: RecoveryWorkKind,
    terminal_state: TransactionState,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._SequencedReconciliationAdapter,
        crash_point=crash_point,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._SequencedReconciliationAdapter)
    adapter.reconcile_statuses = [ReconcileStatus.UNKNOWN, terminal_status]
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        session = await _crash_during_commit(harness)
        recovery = await _stop_dispatch_before_explicit_resume(harness, session)
        first = await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert first.record.state is TransactionState.IN_DOUBT
        first_work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        assert first_work.state is RecoveryWorkState.RETRY_SCHEDULED
        first_attempt = harness.store.get_reconciliation_attempt(
            tenant_id=first_work.tenant_id,
            transaction_id=first_work.transaction_id,
            recovery_id=first_work.recovery_id,
            attempt=first_work.attempt,
        )
        assert first_attempt.outcome is ReconciliationOutcome.UNKNOWN
        assert first_attempt.operation_evidence_ref is not None
        assert first_attempt.next_attempt_not_before is not None
        operation_path = support._artifact_path(
            harness.artifacts.root,
            first_attempt.operation_evidence_ref,
        )
        original_operation = operation_path.read_bytes()
        boundary_snapshot: dict[str, object] = {}
        original_reconcile = adapter.reconcile

        async def reconcile_and_damage_prior_evidence(
            intent: IntentRecord,
            context: RecoveryContext,
        ) -> ReconcileReport:
            report = await original_reconcile(intent, context)
            boundary_snapshot["handoffs"] = harness.store.list_recovery_action_handoffs(
                tenant_id=first_work.tenant_id,
                target_transaction_id=first_work.transaction_id,
            )
            boundary_snapshot["lease_count"] = int(
                harness.store._connection.execute(
                    "SELECT COUNT(*) FROM enforced_worker_leases "
                    "WHERE tenant_id = ? AND transaction_id = ?",
                    (first_work.tenant_id, first_work.transaction_id),
                ).fetchone()[0]
            )
            boundary_snapshot["factory_calls"] = recovery_actions.create_calls
            if artifact_damage == "missing":
                operation_path.unlink()
            else:
                operation_path.write_bytes(b"corrupt-immediate-retried-operation")
            return report

        monkeypatch.setattr(adapter, "reconcile", reconcile_and_damage_prior_evidence)
        harness.clock.advance(first_attempt.next_attempt_not_before - harness.clock())
        expected_error = (
            ErrorCode.EVIDENCE_UNAVAILABLE
            if artifact_damage == "missing"
            else ErrorCode.INTEGRITY_ERROR
        )
        try:
            with pytest.raises(AgentKernelError) as blocked:
                await recovery.recover_once(first_work.tenant_id)
            assert blocked.value.code is expected_error
            assert boundary_snapshot
            intermediate = harness.store.get_enforced_transaction(
                first_work.tenant_id,
                first_work.transaction_id,
            )
            assert intermediate.state is intermediate_state
            lineage = harness.store.list_recovery_work(
                tenant_id=first_work.tenant_id,
                transaction_id=first_work.transaction_id,
            )
            assert [work.recovery_ordinal for work in lineage] == [1, 2]
            assert lineage[0].state is RecoveryWorkState.RETRIED
            assert lineage[1].state is RecoveryWorkState.SUCCEEDED
            assert lineage[1].predecessor_recovery_id == lineage[0].recovery_id
            assert (
                harness.store.list_recovery_action_handoffs(
                    tenant_id=first_work.tenant_id,
                    target_transaction_id=first_work.transaction_id,
                )
                == boundary_snapshot["handoffs"]
            )
            assert (
                int(
                    harness.store._connection.execute(
                        "SELECT COUNT(*) FROM enforced_worker_leases "
                        "WHERE tenant_id = ? AND transaction_id = ?",
                        (first_work.tenant_id, first_work.transaction_id),
                    ).fetchone()[0]
                )
                == boundary_snapshot["lease_count"]
            )
            assert recovery_actions.create_calls == boundary_snapshot["factory_calls"] == 2
            assert adapter.reconcile_calls == 2
            assert adapter.rollback_calls == adapter.abort_stage_calls == 0
        finally:
            _restore_private_artifact(harness.artifacts, operation_path, original_operation)

        converged = await recovery.recover_once(first_work.tenant_id)
        assert converged.scanned == converged.processed == 1
        assert converged.remaining == 0
        assert not converged.failures
        assert converged.statuses[0].record.state is terminal_state
        works = harness.store.list_recovery_work(
            tenant_id=first_work.tenant_id,
            transaction_id=first_work.transaction_id,
        )
        follow_on = tuple(work for work in works if work.kind is follow_on_kind)
        assert len(works) == 3
        assert len(follow_on) == 1
        assert follow_on[0].state is RecoveryWorkState.SUCCEEDED
        assert recovery_actions.create_calls == 3
        assert adapter.reconcile_calls == 2
        if follow_on_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 1
            assert adapter.abort_stage_calls == 0
        else:
            assert adapter.abort_stage_calls == 1
            assert adapter.rollback_calls == 0

        repeated = await recovery.recover_once(first_work.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.create_calls == 3
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact_damage", ["missing", "corrupt"])
async def test_reconciliation_successor_authorization_revalidates_prior_evidence(
    tmp_path: Path,
    artifact_damage: str,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._SequencedReconciliationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._SequencedReconciliationAdapter)
    adapter.reconcile_statuses = [
        ReconcileStatus.UNKNOWN,
        ReconcileStatus.COMMITTED,
    ]
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        session = await _crash_during_commit(harness)
        recovery = await _stop_dispatch_before_explicit_resume(harness, session)
        first = await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert first.record.state is TransactionState.IN_DOUBT
        scheduled = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        assert scheduled.state is RecoveryWorkState.RETRY_SCHEDULED
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            recovery_id=scheduled.recovery_id,
            attempt=scheduled.attempt,
        )
        assert attempt.outcome is ReconciliationOutcome.UNKNOWN
        assert attempt.operation_evidence_ref is not None
        assert attempt.next_attempt_not_before is not None
        operation_path = support._artifact_path(
            harness.artifacts.root,
            attempt.operation_evidence_ref,
        )
        original_operation = operation_path.read_bytes()
        baseline_work = harness.store.list_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        baseline_handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=scheduled.tenant_id,
            target_transaction_id=scheduled.transaction_id,
        )
        baseline_lease_count = int(
            harness.store._connection.execute(
                "SELECT COUNT(*) FROM enforced_worker_leases "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (scheduled.tenant_id, scheduled.transaction_id),
            ).fetchone()[0]
        )
        if artifact_damage == "missing":
            operation_path.unlink()
            expected_error = ErrorCode.EVIDENCE_UNAVAILABLE
        else:
            operation_path.write_bytes(b"corrupt-successor-authorization-operation")
            expected_error = ErrorCode.INTEGRITY_ERROR
        harness.clock.advance(attempt.next_attempt_not_before - harness.clock())

        try:
            with pytest.raises(AgentKernelError) as blocked:
                await recovery.recover_once(scheduled.tenant_id)
            assert blocked.value.code is expected_error
            assert (
                harness.store.list_recovery_work(
                    tenant_id=scheduled.tenant_id,
                    transaction_id=scheduled.transaction_id,
                )
                == baseline_work
            )
            assert (
                harness.store.list_recovery_action_handoffs(
                    tenant_id=scheduled.tenant_id,
                    target_transaction_id=scheduled.transaction_id,
                )
                == baseline_handoffs
            )
            assert (
                int(
                    harness.store._connection.execute(
                        "SELECT COUNT(*) FROM enforced_worker_leases "
                        "WHERE tenant_id = ? AND transaction_id = ?",
                        (scheduled.tenant_id, scheduled.transaction_id),
                    ).fetchone()[0]
                )
                == baseline_lease_count
            )
            assert recovery_actions.create_calls == 1
            assert adapter.reconcile_calls == 1
            assert adapter.rollback_calls == adapter.abort_stage_calls == 0
        finally:
            _restore_private_artifact(harness.artifacts, operation_path, original_operation)

        converged = await recovery.recover_once(scheduled.tenant_id)
        assert converged.scanned == converged.processed == 1
        assert converged.remaining == 0
        assert not converged.failures
        assert converged.statuses[0].record.state is TransactionState.COMMITTED
        lineage = harness.store.list_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        assert [work.recovery_ordinal for work in lineage] == [1, 2]
        assert lineage[0].state is RecoveryWorkState.RETRIED
        assert lineage[1].state is RecoveryWorkState.SUCCEEDED
        assert recovery_actions.create_calls == adapter.reconcile_calls == 2

        repeated = await recovery.recover_once(scheduled.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.create_calls == adapter.reconcile_calls == 2
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact_damage", ["missing", "corrupt"])
async def test_authorized_reconciliation_successor_revalidates_prior_evidence_before_claim(
    tmp_path: Path,
    artifact_damage: str,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._SequencedReconciliationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._SequencedReconciliationAdapter)
    adapter.reconcile_statuses = [
        ReconcileStatus.UNKNOWN,
        ReconcileStatus.COMMITTED,
    ]
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        session = await _crash_during_commit(harness)
        recovery = await _stop_dispatch_before_explicit_resume(harness, session)
        await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        scheduled = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        assert scheduled.state is RecoveryWorkState.RETRY_SCHEDULED
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            recovery_id=scheduled.recovery_id,
            attempt=scheduled.attempt,
        )
        assert attempt.operation_evidence_ref is not None
        assert attempt.next_attempt_not_before is not None
        harness.clock.advance(attempt.next_attempt_not_before - harness.clock())
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED,
        )
        with pytest.raises(CoordinatorInjectedCrash) as crash:
            await crashing.recover_once(scheduled.tenant_id)
        assert crash.value.point is CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED
        authorized_work = harness.store.list_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        assert [work.recovery_ordinal for work in authorized_work] == [1, 2]
        assert authorized_work[0].state is RecoveryWorkState.RETRIED
        assert authorized_work[1].state is RecoveryWorkState.PENDING
        authorized_handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=scheduled.tenant_id,
            target_transaction_id=scheduled.transaction_id,
        )
        authorized_lease_count = int(
            harness.store._connection.execute(
                "SELECT COUNT(*) FROM enforced_worker_leases "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (scheduled.tenant_id, scheduled.transaction_id),
            ).fetchone()[0]
        )
        operation_path = support._artifact_path(
            harness.artifacts.root,
            attempt.operation_evidence_ref,
        )
        original_operation = operation_path.read_bytes()
        if artifact_damage == "missing":
            operation_path.unlink()
            expected_error = ErrorCode.EVIDENCE_UNAVAILABLE
        else:
            operation_path.write_bytes(b"corrupt-authorized-successor-operation")
            expected_error = ErrorCode.INTEGRITY_ERROR
        restarted = support._restart_coordinator(harness)

        try:
            with pytest.raises(AgentKernelError) as blocked:
                await restarted.recover_once(scheduled.tenant_id)
            assert blocked.value.code is expected_error
            assert (
                harness.store.list_recovery_work(
                    tenant_id=scheduled.tenant_id,
                    transaction_id=scheduled.transaction_id,
                )
                == authorized_work
            )
            assert (
                harness.store.list_recovery_action_handoffs(
                    tenant_id=scheduled.tenant_id,
                    target_transaction_id=scheduled.transaction_id,
                )
                == authorized_handoffs
            )
            assert (
                int(
                    harness.store._connection.execute(
                        "SELECT COUNT(*) FROM enforced_worker_leases "
                        "WHERE tenant_id = ? AND transaction_id = ?",
                        (scheduled.tenant_id, scheduled.transaction_id),
                    ).fetchone()[0]
                )
                == authorized_lease_count
            )
            assert recovery_actions.create_calls == 2
            assert adapter.reconcile_calls == 1
            assert adapter.rollback_calls == adapter.abort_stage_calls == 0
        finally:
            _restore_private_artifact(harness.artifacts, operation_path, original_operation)

        converged = await restarted.recover_once(scheduled.tenant_id)
        assert converged.scanned == converged.processed == 1
        assert converged.remaining == 0
        assert not converged.failures
        assert converged.statuses[0].record.state is TransactionState.COMMITTED
        lineage = harness.store.list_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        assert lineage[1].state is RecoveryWorkState.SUCCEEDED
        assert recovery_actions.create_calls == adapter.reconcile_calls == 2

        repeated = await restarted.recover_once(scheduled.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.create_calls == adapter.reconcile_calls == 2
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact_damage", ["missing", "corrupt"])
async def test_live_running_reconciliation_successor_evidence_failure_is_read_only_and_resumable(
    tmp_path: Path,
    artifact_damage: str,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_BlockingSecondReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _BlockingSecondReconcileAdapter)
    adapter.reconcile_statuses = [
        ReconcileStatus.UNKNOWN,
        ReconcileStatus.COMMITTED,
    ]
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    live_task: asyncio.Task[RecoveryRunResult] | None = None
    scanner_store: SQLiteEnforcedTransactionStore | None = None
    operation_path: Path | None = None
    original_operation: bytes | None = None
    try:
        session = await _crash_during_commit(harness)
        recovery = await _stop_dispatch_before_explicit_resume(harness, session)
        await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        scheduled = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        first_attempt = harness.store.get_reconciliation_attempt(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            recovery_id=scheduled.recovery_id,
            attempt=scheduled.attempt,
        )
        assert first_attempt.operation_evidence_ref is not None
        assert first_attempt.next_attempt_not_before is not None
        harness.clock.advance(first_attempt.next_attempt_not_before - harness.clock())

        live_coordinator = support._restart_coordinator(harness)
        live_task = asyncio.create_task(live_coordinator.recover_once(scheduled.tenant_id))
        await asyncio.wait_for(adapter.second_reconcile_entered.wait(), timeout=5)

        baseline_transaction = harness.store.get_enforced_transaction(
            scheduled.tenant_id,
            scheduled.transaction_id,
        )
        baseline_work = harness.store.list_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        assert [work.state for work in baseline_work] == [
            RecoveryWorkState.RETRIED,
            RecoveryWorkState.RUNNING,
        ]
        baseline_attempts = harness.store.list_reconciliation_attempts(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        assert len(baseline_attempts) == 2
        running_attempt = next(
            attempt
            for attempt in baseline_attempts
            if attempt.recovery_id == baseline_work[1].recovery_id
        )
        assert running_attempt.completed_at is None
        baseline_handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=scheduled.tenant_id,
            target_transaction_id=scheduled.transaction_id,
        )
        baseline_leases = _worker_lease_snapshot(
            harness.store,
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        baseline_artifacts = _artifact_file_snapshot(harness.artifacts.root)
        operation_path = support._artifact_path(
            harness.artifacts.root,
            first_attempt.operation_evidence_ref,
        )
        original_operation = operation_path.read_bytes()
        if artifact_damage == "missing":
            operation_path.unlink()
            expected_error = ErrorCode.EVIDENCE_UNAVAILABLE
        else:
            operation_path.write_bytes(b"corrupt-live-running-predecessor-operation")
            expected_error = ErrorCode.INTEGRITY_ERROR
        damaged_artifacts = _artifact_file_snapshot(harness.artifacts.root)

        scanner_store, scanner = support._reopen_coordinator(harness, database_path)
        with pytest.raises(AgentKernelError) as blocked:
            await scanner.recover_once(scheduled.tenant_id)
        assert blocked.value.code is expected_error
        assert (
            scanner_store.get_enforced_transaction(
                scheduled.tenant_id,
                scheduled.transaction_id,
            )
            == baseline_transaction
        )
        assert (
            scanner_store.list_recovery_work(
                tenant_id=scheduled.tenant_id,
                transaction_id=scheduled.transaction_id,
            )
            == baseline_work
        )
        assert (
            scanner_store.list_reconciliation_attempts(
                tenant_id=scheduled.tenant_id,
                transaction_id=scheduled.transaction_id,
            )
            == baseline_attempts
        )
        assert (
            scanner_store.list_recovery_action_handoffs(
                tenant_id=scheduled.tenant_id,
                target_transaction_id=scheduled.transaction_id,
            )
            == baseline_handoffs
        )
        assert (
            _worker_lease_snapshot(
                scanner_store,
                tenant_id=scheduled.tenant_id,
                transaction_id=scheduled.transaction_id,
            )
            == baseline_leases
        )
        assert _artifact_file_snapshot(harness.artifacts.root) == damaged_artifacts
        assert recovery_actions.create_calls == adapter.reconcile_calls == 2
        assert baseline_artifacts != damaged_artifacts or artifact_damage == "corrupt"

        _restore_private_artifact(harness.artifacts, operation_path, original_operation)
        original_operation = None
        adapter.second_reconcile_release.set()
        completed = await asyncio.wait_for(live_task, timeout=5)
        live_task = None
        assert completed.statuses[0].record.state is TransactionState.COMMITTED
        assert recovery_actions.create_calls == adapter.reconcile_calls == 2
        repeated = await live_coordinator.recover_once(scheduled.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
    finally:
        if operation_path is not None and original_operation is not None:
            _restore_private_artifact(harness.artifacts, operation_path, original_operation)
        adapter.second_reconcile_release.set()
        if live_task is not None:
            await asyncio.gather(live_task, return_exceptions=True)
        if scanner_store is not None:
            scanner_store.close()
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact_damage", ["missing", "corrupt"])
async def test_successor_authorization_revalidates_after_handoff_lease_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_damage: str,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._SequencedReconciliationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._SequencedReconciliationAdapter)
    adapter.reconcile_statuses = [
        ReconcileStatus.UNKNOWN,
        ReconcileStatus.COMMITTED,
    ]
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    operation_path: Path | None = None
    original_operation: bytes | None = None
    try:
        session = await _crash_during_commit(harness)
        recovery = await _stop_dispatch_before_explicit_resume(harness, session)
        await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        scheduled = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        assert scheduled.state is RecoveryWorkState.RETRY_SCHEDULED
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            recovery_id=scheduled.recovery_id,
            attempt=scheduled.attempt,
        )
        assert attempt.operation_evidence_ref is not None
        assert attempt.next_attempt_not_before is not None
        operation_path = support._artifact_path(
            harness.artifacts.root,
            attempt.operation_evidence_ref,
        )
        original_operation = operation_path.read_bytes()
        baseline_transaction = harness.store.get_enforced_transaction(
            scheduled.tenant_id,
            scheduled.transaction_id,
        )
        baseline_work = harness.store.list_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        baseline_handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=scheduled.tenant_id,
            target_transaction_id=scheduled.transaction_id,
        )
        baseline_leases = _worker_lease_snapshot(
            harness.store,
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        captured_lease: list[WorkerLeaseRecord] = []
        original_acquire = harness.store.acquire_recovery_authorization_lease

        def acquire_and_damage_prior_operation(**kwargs):
            claimed = original_acquire(**kwargs)
            captured_lease.append(claimed.lease)
            if len(captured_lease) == 1:
                if artifact_damage == "missing":
                    operation_path.unlink()
                else:
                    operation_path.write_bytes(b"corrupt-post-handoff-lease-operation")
            return claimed

        monkeypatch.setattr(
            harness.store,
            "acquire_recovery_authorization_lease",
            acquire_and_damage_prior_operation,
        )
        harness.clock.advance(attempt.next_attempt_not_before - harness.clock())
        expected_error = (
            ErrorCode.EVIDENCE_UNAVAILABLE
            if artifact_damage == "missing"
            else ErrorCode.INTEGRITY_ERROR
        )

        with pytest.raises(AgentKernelError) as blocked:
            await recovery.recover_once(scheduled.tenant_id)
        assert blocked.value.code is expected_error
        assert len(captured_lease) == 1
        assert (
            harness.store.get_enforced_transaction(
                scheduled.tenant_id,
                scheduled.transaction_id,
            )
            == baseline_transaction
        )
        assert (
            harness.store.list_recovery_work(
                tenant_id=scheduled.tenant_id,
                transaction_id=scheduled.transaction_id,
            )
            == baseline_work
        )
        handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=scheduled.tenant_id,
            target_transaction_id=scheduled.transaction_id,
        )
        assert len(handoffs) == len(baseline_handoffs) + 1
        handoffs_by_recovery_id = {handoff.binding.recovery_id: handoff for handoff in handoffs}
        for baseline_handoff in baseline_handoffs:
            assert handoffs_by_recovery_id[baseline_handoff.binding.recovery_id] == baseline_handoff
        new_handoffs = tuple(
            handoff
            for handoff in handoffs
            if handoff.binding.recovery_id
            not in {baseline_handoff.binding.recovery_id for baseline_handoff in baseline_handoffs}
        )
        assert len(new_handoffs) == 1
        failed_handoff = new_handoffs[0]
        assert failed_handoff.binding.predecessor_recovery_id == scheduled.recovery_id
        assert failed_handoff.action is None
        assert failed_handoff.closed_at is None
        assert failed_handoff.failure_evidence_status is (RecoveryHandoffFailureEvidenceStatus.NONE)
        assert failed_handoff.failure_evidence_ref is None
        lease = harness.store.get_worker_lease(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            lease_id=captured_lease[0].lease_id,
        )
        assert lease.released_at is not None
        assert (
            len(
                _worker_lease_snapshot(
                    harness.store,
                    tenant_id=scheduled.tenant_id,
                    transaction_id=scheduled.transaction_id,
                )
            )
            == len(baseline_leases) + 1
        )
        assert recovery_actions.create_calls == adapter.reconcile_calls == 1
        assert adapter.rollback_calls == adapter.abort_stage_calls == 0

        _restore_private_artifact(harness.artifacts, operation_path, original_operation)
        original_operation = None
        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        resumed = await restarted.recover_once(scheduled.tenant_id)
        assert resumed.scanned == resumed.processed == 1
        assert resumed.remaining == 0
        assert not resumed.failures
        assert resumed.statuses[0].record.state is TransactionState.COMMITTED
        lineage = reopened_store.list_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        assert [work.state for work in lineage] == [
            RecoveryWorkState.RETRIED,
            RecoveryWorkState.SUCCEEDED,
        ]
        resumed_handoffs = reopened_store.list_recovery_action_handoffs(
            tenant_id=scheduled.tenant_id,
            target_transaction_id=scheduled.transaction_id,
        )
        assert len(resumed_handoffs) == len(handoffs)
        resumed_handoff = next(
            handoff
            for handoff in resumed_handoffs
            if handoff.binding.recovery_id == failed_handoff.binding.recovery_id
        )
        assert resumed_handoff.action is not None
        assert recovery_actions.create_calls == adapter.reconcile_calls == 2
        repeated = await restarted.recover_once(scheduled.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
    finally:
        if operation_path is not None and original_operation is not None:
            _restore_private_artifact(harness.artifacts, operation_path, original_operation)
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("artifact_damage", "expire_before_resume"),
    [
        ("missing", False),
        ("corrupt", False),
        ("missing", True),
    ],
    ids=("missing-resume", "corrupt-resume", "deadline-settlement"),
)
async def test_discard_authorization_revalidates_after_handoff_lease_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_damage: str,
    expire_before_resume: bool,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.BEFORE_COMMIT,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    operation_path: Path | None = None
    original_operation: bytes | None = None
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED,
        )
        with pytest.raises(CoordinatorInjectedCrash):
            await crashing.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        intermediate = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert intermediate.state is TransactionState.ABORTING
        baseline_work = harness.store.list_recovery_work(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
        )
        assert len(baseline_work) == 1
        reconciliation = baseline_work[0]
        assert reconciliation.kind is RecoveryWorkKind.RECONCILE_DISPATCH
        assert reconciliation.state is RecoveryWorkState.SUCCEEDED
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=reconciliation.tenant_id,
            transaction_id=reconciliation.transaction_id,
            recovery_id=reconciliation.recovery_id,
            attempt=reconciliation.attempt,
        )
        assert attempt.operation_evidence_ref is not None
        operation_path = support._artifact_path(
            harness.artifacts.root,
            attempt.operation_evidence_ref,
        )
        original_operation = operation_path.read_bytes()
        baseline_handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=intermediate.tenant_id,
            target_transaction_id=intermediate.transaction_id,
        )
        baseline_leases = _worker_lease_snapshot(
            harness.store,
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
        )
        captured_leases: list[WorkerLeaseRecord] = []
        original_acquire = harness.store.acquire_recovery_handoff_lease

        def acquire_and_damage_prior_operation(**kwargs):
            acquired = original_acquire(**kwargs)
            captured_leases.append(acquired.lease)
            if len(captured_leases) == 1:
                if artifact_damage == "missing":
                    operation_path.unlink()
                else:
                    operation_path.write_bytes(b"corrupt-discard-post-handoff-operation")
            return acquired

        monkeypatch.setattr(
            harness.store,
            "acquire_recovery_handoff_lease",
            acquire_and_damage_prior_operation,
        )
        recovery = support._restart_coordinator(harness)
        expected_error = (
            ErrorCode.EVIDENCE_UNAVAILABLE
            if artifact_damage == "missing"
            else ErrorCode.INTEGRITY_ERROR
        )

        with pytest.raises(AgentKernelError) as blocked:
            await recovery.recover_once(intermediate.tenant_id)
        assert blocked.value.code is expected_error
        assert len(captured_leases) == 1
        assert (
            harness.store.get_enforced_transaction(
                intermediate.tenant_id,
                intermediate.transaction_id,
            )
            == intermediate
        )
        assert (
            harness.store.list_recovery_work(
                tenant_id=intermediate.tenant_id,
                transaction_id=intermediate.transaction_id,
            )
            == baseline_work
        )
        handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=intermediate.tenant_id,
            target_transaction_id=intermediate.transaction_id,
        )
        assert len(handoffs) == len(baseline_handoffs) + 1
        assert (
            tuple(
                handoff
                for handoff in handoffs
                if handoff.binding.recovery_kind is RecoveryWorkKind.RECONCILE_DISPATCH
            )
            == baseline_handoffs
        )
        open_discard = next(
            handoff
            for handoff in handoffs
            if handoff.binding.recovery_kind is RecoveryWorkKind.DISCARD_STAGING
        )
        assert open_discard.binding.recovery_kind is RecoveryWorkKind.DISCARD_STAGING
        assert open_discard.action is None
        assert open_discard.closed_at is None
        assert open_discard.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.NONE
        assert open_discard.failure_evidence_ref is None
        released = harness.store.get_worker_lease(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
            lease_id=captured_leases[0].lease_id,
        )
        assert released.released_at is not None
        assert (
            len(
                _worker_lease_snapshot(
                    harness.store,
                    tenant_id=intermediate.tenant_id,
                    transaction_id=intermediate.transaction_id,
                )
            )
            == len(baseline_leases) + 1
        )
        assert recovery_actions.create_calls == adapter.reconcile_calls == 1
        assert adapter.abort_stage_calls == 0

        _restore_private_artifact(harness.artifacts, operation_path, original_operation)
        original_operation = None
        if expire_before_resume:
            harness.clock.advance(open_discard.binding.absolute_deadline - harness.clock())
        assert (
            harness.store.count_recovery_candidates(
                tenant_id=intermediate.tenant_id,
                observed_at=harness.clock(),
            )
            == 1
        )
        surfaced = harness.store.scan_recovery_candidates(
            tenant_id=intermediate.tenant_id,
            observed_at=harness.clock(),
            limit=10,
        )
        assert surfaced.records == (intermediate,)

        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        resumed = await restarted.recover_once(intermediate.tenant_id)
        assert resumed.scanned == resumed.processed == 1
        assert resumed.remaining == 0
        if expire_before_resume:
            assert len(resumed.failures) == 1
            assert resumed.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
            assert resumed.failures[0].reason_code == ErrorCode.DEADLINE_EXCEEDED.value
            assert resumed.statuses[0].record.state is TransactionState.RECOVERY_FAILED
            expired_handoff = reopened_store.get_recovery_action_handoff(
                tenant_id=intermediate.tenant_id,
                target_transaction_id=intermediate.transaction_id,
                recovery_id=open_discard.binding.recovery_id,
            )
            assert expired_handoff is not None
            assert expired_handoff.closed_at == harness.clock()
            assert expired_handoff.action is None
            assert recovery_actions.create_calls == adapter.reconcile_calls == 1
            assert adapter.abort_stage_calls == 0
            repeated = await restarted.recover_once(intermediate.tenant_id)
            assert repeated.scanned == repeated.processed == repeated.remaining == 0
            assert not repeated.failures
            return
        assert not resumed.failures
        assert resumed.statuses[0].record.state is TransactionState.ABORTED
        final_work = reopened_store.list_recovery_work(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
        )
        assert [work.state for work in final_work] == [
            RecoveryWorkState.SUCCEEDED,
            RecoveryWorkState.SUCCEEDED,
        ]
        final_handoffs = reopened_store.list_recovery_action_handoffs(
            tenant_id=intermediate.tenant_id,
            target_transaction_id=intermediate.transaction_id,
        )
        assert len(final_handoffs) == len(handoffs)
        final_discard = next(
            handoff
            for handoff in final_handoffs
            if handoff.binding.recovery_kind is RecoveryWorkKind.DISCARD_STAGING
        )
        assert final_discard.binding.recovery_id == open_discard.binding.recovery_id
        assert final_discard.action is not None
        latest_lease_row = reopened_store._connection.execute(
            "SELECT lease_id FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? "
            "ORDER BY fencing_token DESC LIMIT 1",
            (intermediate.tenant_id, intermediate.transaction_id),
        ).fetchone()
        assert latest_lease_row is not None
        latest_lease = reopened_store.get_worker_lease(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
            lease_id=str(latest_lease_row["lease_id"]),
        )
        assert latest_lease.lease_id != captured_leases[0].lease_id
        assert latest_lease.fencing_token > captured_leases[0].fencing_token
        assert latest_lease.released_at is not None
        assert recovery_actions.create_calls == 2
        assert adapter.reconcile_calls == adapter.abort_stage_calls == 1

        assert (
            restarted.status(
                intermediate.tenant_id,
                intermediate.transaction_id,
            ).record.state
            is TransactionState.ABORTED
        )
        repeated = await restarted.recover_once(intermediate.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.create_calls == 2
        assert adapter.abort_stage_calls == 1
    finally:
        if operation_path is not None and original_operation is not None:
            _restore_private_artifact(harness.artifacts, operation_path, original_operation)
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact_damage", ["missing", "corrupt"])
@pytest.mark.parametrize(
    ("adapter_type", "follow_on_kind", "terminal_state"),
    [
        (
            _PartialCountingReconcileAdapter,
            RecoveryWorkKind.ROLLBACK,
            TransactionState.ROLLED_BACK,
        ),
        (
            _PartialCompensatingReconcileAdapter,
            RecoveryWorkKind.COMPENSATE,
            TransactionState.COMPENSATED,
        ),
    ],
    ids=("rollback", "compensate"),
)
async def test_failed_follow_on_revalidates_after_handoff_lease_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_damage: str,
    adapter_type: type[support._ControlledVerificationAdapter],
    follow_on_kind: RecoveryWorkKind,
    terminal_state: TransactionState,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(
        adapter,
        (_PartialCountingReconcileAdapter, _PartialCompensatingReconcileAdapter),
    )
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    operation_path: Path | None = None
    original_operation: bytes | None = None
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED,
        )
        with pytest.raises(CoordinatorInjectedCrash):
            await crashing.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        failed = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert failed.state is TransactionState.FAILED
        baseline_work = harness.store.list_recovery_work(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )
        assert len(baseline_work) == 1
        reconciliation = baseline_work[0]
        assert reconciliation.kind is RecoveryWorkKind.RECONCILE_DISPATCH
        assert reconciliation.state is RecoveryWorkState.SUCCEEDED
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=reconciliation.tenant_id,
            transaction_id=reconciliation.transaction_id,
            recovery_id=reconciliation.recovery_id,
            attempt=reconciliation.attempt,
        )
        assert attempt.operation_evidence_ref is not None
        operation_path = support._artifact_path(
            harness.artifacts.root,
            attempt.operation_evidence_ref,
        )
        original_operation = operation_path.read_bytes()
        baseline_handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=failed.tenant_id,
            target_transaction_id=failed.transaction_id,
        )
        baseline_leases = _worker_lease_snapshot(
            harness.store,
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )
        captured_leases: list[WorkerLeaseRecord] = []
        original_acquire = harness.store.acquire_recovery_authorization_lease

        def acquire_and_damage_prior_operation(**kwargs):
            acquired = original_acquire(**kwargs)
            captured_leases.append(acquired.lease)
            if len(captured_leases) == 1:
                if artifact_damage == "missing":
                    operation_path.unlink()
                else:
                    operation_path.write_bytes(b"corrupt-failed-follow-on-post-handoff-operation")
            return acquired

        monkeypatch.setattr(
            harness.store,
            "acquire_recovery_authorization_lease",
            acquire_and_damage_prior_operation,
        )
        recovery = support._restart_coordinator(harness)
        expected_error = (
            ErrorCode.EVIDENCE_UNAVAILABLE
            if artifact_damage == "missing"
            else ErrorCode.INTEGRITY_ERROR
        )

        with pytest.raises(AgentKernelError) as blocked:
            await recovery.recover_once(failed.tenant_id)
        assert blocked.value.code is expected_error
        assert len(captured_leases) == 1
        assert (
            harness.store.get_enforced_transaction(
                failed.tenant_id,
                failed.transaction_id,
            )
            == failed
        )
        assert (
            harness.store.list_recovery_work(
                tenant_id=failed.tenant_id,
                transaction_id=failed.transaction_id,
            )
            == baseline_work
        )
        handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=failed.tenant_id,
            target_transaction_id=failed.transaction_id,
        )
        assert len(handoffs) == len(baseline_handoffs) + 1
        assert (
            tuple(
                handoff
                for handoff in handoffs
                if handoff.binding.recovery_kind is RecoveryWorkKind.RECONCILE_DISPATCH
            )
            == baseline_handoffs
        )
        open_follow_on = next(
            handoff for handoff in handoffs if handoff.binding.recovery_kind is follow_on_kind
        )
        assert open_follow_on.action is None
        assert open_follow_on.closed_at is None
        assert open_follow_on.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.NONE
        assert open_follow_on.failure_evidence_ref is None
        released = harness.store.get_worker_lease(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
            lease_id=captured_leases[0].lease_id,
        )
        assert released.released_at is not None
        assert (
            len(
                _worker_lease_snapshot(
                    harness.store,
                    tenant_id=failed.tenant_id,
                    transaction_id=failed.transaction_id,
                )
            )
            == len(baseline_leases) + 1
        )
        assert recovery_actions.create_calls == adapter.reconcile_calls == 1
        if follow_on_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 0
        else:
            assert adapter.compensation_calls == 0

        _restore_private_artifact(harness.artifacts, operation_path, original_operation)
        original_operation = None
        assert (
            harness.store.count_recovery_candidates(
                tenant_id=failed.tenant_id,
                observed_at=harness.clock(),
            )
            == 1
        )
        surfaced = harness.store.scan_recovery_candidates(
            tenant_id=failed.tenant_id,
            observed_at=harness.clock(),
            limit=10,
        )
        assert surfaced.records == (failed,)

        harness.store.close()
        reopened_store, reopened = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        restarted = _clone_coordinator(
            harness,
            store=reopened_store,
            artifacts=reopened._artifacts,
            authority_snapshots=reopened._authority_snapshots,
            config=EnforcedCoordinatorConfig(
                worker_id="worker:resumed-failed-follow-on",
                lease_duration=timedelta(minutes=4),
                recovery_deadline=timedelta(minutes=4),
                reconciliation_backoff=timedelta(seconds=2),
            ),
        )
        if isinstance(adapter, _PartialCompensatingReconcileAdapter):
            adapter.test_clock = harness.clock
        resumed = await restarted.recover_once(failed.tenant_id)
        assert resumed.scanned == resumed.processed == 1
        assert resumed.remaining == 0
        assert not resumed.failures
        assert resumed.statuses[0].record.state is terminal_state
        final_work = reopened_store.list_recovery_work(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )
        assert len(final_work) == 2
        final_follow_on = next(work for work in final_work if work.kind is follow_on_kind)
        assert final_follow_on.state is RecoveryWorkState.SUCCEEDED
        final_handoffs = reopened_store.list_recovery_action_handoffs(
            tenant_id=failed.tenant_id,
            target_transaction_id=failed.transaction_id,
        )
        final_handoff = next(
            handoff for handoff in final_handoffs if handoff.binding.recovery_kind is follow_on_kind
        )
        assert final_handoff.binding.recovery_id == open_follow_on.binding.recovery_id
        assert final_handoff.action is not None
        latest_lease_row = reopened_store._connection.execute(
            "SELECT lease_id FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? "
            "ORDER BY fencing_token DESC LIMIT 1",
            (failed.tenant_id, failed.transaction_id),
        ).fetchone()
        assert latest_lease_row is not None
        latest_lease = reopened_store.get_worker_lease(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
            lease_id=str(latest_lease_row["lease_id"]),
        )
        assert latest_lease.lease_id != captured_leases[0].lease_id
        assert latest_lease.fencing_token > captured_leases[0].fencing_token
        assert latest_lease.released_at is not None
        assert recovery_actions.create_calls == 2
        if follow_on_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 1
        else:
            assert adapter.compensation_calls == 1
        repeated = await restarted.recover_once(failed.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.create_calls == 2
        if follow_on_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 1
        else:
            assert adapter.compensation_calls == 1
    finally:
        if operation_path is not None and original_operation is not None:
            _restore_private_artifact(harness.artifacts, operation_path, original_operation)
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "adapter_type",
        "crash_point",
        "follow_on_kind",
        "intermediate_state",
        "terminal_state",
        "settle_attached_action",
    ),
    [
        (
            _CountingReconcileAdapter,
            CoordinatorCrashPoint.BEFORE_COMMIT,
            RecoveryWorkKind.DISCARD_STAGING,
            TransactionState.ABORTING,
            TransactionState.ABORTED,
            False,
        ),
        (
            _PartialCountingReconcileAdapter,
            CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
            RecoveryWorkKind.ROLLBACK,
            TransactionState.FAILED,
            TransactionState.ROLLED_BACK,
            False,
        ),
        (
            _PartialCompensatingReconcileAdapter,
            CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
            RecoveryWorkKind.COMPENSATE,
            TransactionState.FAILED,
            TransactionState.COMPENSATED,
            False,
        ),
        (
            _CountingReconcileAdapter,
            CoordinatorCrashPoint.BEFORE_COMMIT,
            RecoveryWorkKind.DISCARD_STAGING,
            TransactionState.ABORTING,
            TransactionState.ABORTED,
            True,
        ),
    ],
    ids=("discard", "rollback", "compensate", "non-active-excluded"),
)
async def test_terminal_follow_on_resumes_attached_action_after_process_death(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    adapter_type: type[support._ControlledVerificationAdapter],
    crash_point: CoordinatorCrashPoint,
    follow_on_kind: RecoveryWorkKind,
    intermediate_state: TransactionState,
    terminal_state: TransactionState,
    settle_attached_action: bool,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=crash_point,
    )
    adapter = harness.adapter
    assert isinstance(
        adapter,
        (
            _CountingReconcileAdapter,
            _PartialCountingReconcileAdapter,
            _PartialCompensatingReconcileAdapter,
        ),
    )
    recovery_actions = _RecordingRecoveryActions(harness.recovery_actions)
    harness.recovery_actions = recovery_actions
    original_register = harness.store.register_recovery_action
    original_release = harness.store.release_worker_lease
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED,
        )
        with pytest.raises(CoordinatorInjectedCrash):
            await crashing.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        intermediate = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert intermediate.state is intermediate_state
        baseline_work = harness.store.list_recovery_work(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
        )
        assert len(baseline_work) == 1
        assert baseline_work[0].kind is RecoveryWorkKind.RECONCILE_DISPATCH
        assert baseline_work[0].state is RecoveryWorkState.SUCCEEDED

        def crash_after_register(action, *, registered_at, binding):
            original_register(
                action,
                registered_at=registered_at,
                binding=binding,
            )
            raise SimulatedProcessDeath

        def abandon_recovery_handoff(**kwargs):
            lease = harness.store.get_worker_lease(
                tenant_id=kwargs["tenant_id"],
                transaction_id=kwargs["transaction_id"],
                lease_id=kwargs["lease_id"],
            )
            if lease.purpose is LeasePurpose.RECOVERY:
                return lease
            return original_release(**kwargs)

        monkeypatch.setattr(
            harness.store,
            "register_recovery_action",
            crash_after_register,
        )
        monkeypatch.setattr(
            harness.store,
            "release_worker_lease",
            abandon_recovery_handoff,
        )
        recovery = support._restart_coordinator(harness)
        with pytest.raises(SimulatedProcessDeath):
            await recovery.recover_once(intermediate.tenant_id)

        assert recovery_actions.action is not None
        assert recovery_actions.calls == 2
        assert (
            harness.store.get_enforced_transaction(
                intermediate.tenant_id,
                intermediate.transaction_id,
            )
            == intermediate
        )
        assert (
            harness.store.list_recovery_work(
                tenant_id=intermediate.tenant_id,
                transaction_id=intermediate.transaction_id,
            )
            == baseline_work
        )
        attached_handoff = next(
            handoff
            for handoff in harness.store.list_recovery_action_handoffs(
                tenant_id=intermediate.tenant_id,
                target_transaction_id=intermediate.transaction_id,
            )
            if handoff.binding.recovery_kind is follow_on_kind
        )
        assert attached_handoff.action == recovery_actions.action
        assert attached_handoff.closed_at is None
        attached_attempt = harness.store.get_intent_attempt(
            tenant_id=recovery_actions.action.tenant_id,
            intent_hash=recovery_actions.action.intent_hash,
            transaction_id=recovery_actions.action.transaction_id,
        )
        assert attached_attempt.state is IntentAttemptState.ACTIVE
        original_handoff_lease = harness.store.get_worker_lease(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
            lease_id=attached_handoff.handoff_lease_id,
        )
        assert original_handoff_lease.released_at is None
        if follow_on_kind is RecoveryWorkKind.DISCARD_STAGING:
            assert adapter.abort_stage_calls == 0
        elif follow_on_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 0
        else:
            assert adapter.compensation_calls == 0

        if settle_attached_action:
            harness.store.record_intent_attempt_state(
                tenant_id=recovery_actions.action.tenant_id,
                intent_hash=recovery_actions.action.intent_hash,
                transaction_id=recovery_actions.action.transaction_id,
                expected_version=attached_attempt.version,
                state=IntentAttemptState.NO_EFFECT_CONFIRMED,
                evidence_digest=attached_handoff.binding_ref,
                recorded_at=harness.clock(),
            )
            assert (
                harness.store.get_resumable_open_prework_handoff(
                    tenant_id=intermediate.tenant_id,
                    target_transaction_id=intermediate.transaction_id,
                    observed_at=original_handoff_lease.expires_at + timedelta(microseconds=1),
                )
                is None
            )
            assert (
                harness.store.count_recovery_candidates(
                    tenant_id=intermediate.tenant_id,
                    observed_at=original_handoff_lease.expires_at + timedelta(microseconds=1),
                )
                == 0
            )
            assert not harness.store.scan_recovery_candidates(
                tenant_id=intermediate.tenant_id,
                observed_at=original_handoff_lease.expires_at + timedelta(microseconds=1),
                limit=10,
            ).records
            with pytest.raises(AgentKernelError) as invalid_open_action:
                harness.store.list_recovery_action_handoffs(
                    tenant_id=intermediate.tenant_id,
                    target_transaction_id=intermediate.transaction_id,
                )
            assert invalid_open_action.value.code is ErrorCode.INTEGRITY_ERROR
            return

        harness.store.close()
        reopened_store, reopened = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        assert (
            reopened_store.count_recovery_candidates(
                tenant_id=intermediate.tenant_id,
                observed_at=harness.clock(),
            )
            == 0
        )
        assert (
            reopened_store.get_resumable_open_prework_handoff(
                tenant_id=intermediate.tenant_id,
                target_transaction_id=intermediate.transaction_id,
                observed_at=harness.clock(),
            )
            is None
        )
        harness.clock.advance(
            original_handoff_lease.expires_at - harness.clock() + timedelta(microseconds=1)
        )
        assert (
            reopened_store.count_recovery_candidates(
                tenant_id=intermediate.tenant_id,
                observed_at=harness.clock(),
            )
            == 1
        )
        assert (
            reopened_store.get_resumable_open_prework_handoff(
                tenant_id=intermediate.tenant_id,
                target_transaction_id=intermediate.transaction_id,
                observed_at=harness.clock(),
            )
            == attached_handoff
        )
        restarted = _clone_coordinator(
            harness,
            store=reopened_store,
            artifacts=reopened._artifacts,
            authority_snapshots=reopened._authority_snapshots,
            recovery_actions=recovery_actions,
            config=EnforcedCoordinatorConfig(
                worker_id="worker:attached-follow-on-restart",
                lease_duration=timedelta(minutes=4),
                recovery_deadline=timedelta(minutes=4),
                reconciliation_backoff=timedelta(seconds=2),
            ),
        )
        if isinstance(adapter, _PartialCompensatingReconcileAdapter):
            adapter.test_clock = harness.clock

        resumed = await restarted.recover_once(intermediate.tenant_id)

        assert resumed.scanned == resumed.processed == 1
        assert resumed.remaining == 0
        assert not resumed.failures
        assert resumed.statuses[0].record.state is terminal_state
        assert recovery_actions.calls == 2
        final_work = reopened_store.list_recovery_work(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
        )
        assert len(final_work) == 2
        follow_on = next(work for work in final_work if work.kind is follow_on_kind)
        assert follow_on.state is RecoveryWorkState.SUCCEEDED
        final_handoff = reopened_store.get_recovery_action_handoff(
            tenant_id=intermediate.tenant_id,
            target_transaction_id=intermediate.transaction_id,
            recovery_id=attached_handoff.binding.recovery_id,
        )
        assert final_handoff is not None
        assert final_handoff.binding.recovery_id == attached_handoff.binding.recovery_id
        assert final_handoff.action == attached_handoff.action
        latest_lease_row = reopened_store._connection.execute(
            "SELECT lease_id FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? "
            "ORDER BY fencing_token DESC LIMIT 1",
            (intermediate.tenant_id, intermediate.transaction_id),
        ).fetchone()
        assert latest_lease_row is not None
        latest_lease = reopened_store.get_worker_lease(
            tenant_id=intermediate.tenant_id,
            transaction_id=intermediate.transaction_id,
            lease_id=str(latest_lease_row["lease_id"]),
        )
        assert latest_lease.fencing_token > original_handoff_lease.fencing_token
        assert latest_lease.released_at is not None
        if follow_on_kind is RecoveryWorkKind.DISCARD_STAGING:
            assert adapter.abort_stage_calls == 1
        elif follow_on_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 1
        else:
            assert adapter.compensation_calls == 1
        repeated = await restarted.recover_once(intermediate.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.calls == 2
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter_type", "expected_kind", "expected_state"),
    [
        (
            _PartialCountingReconcileAdapter,
            RecoveryWorkKind.ROLLBACK,
            TransactionState.ROLLED_BACK,
        ),
        (
            _PartialCompensatingReconcileAdapter,
            RecoveryWorkKind.COMPENSATE,
            TransactionState.COMPENSATED,
        ),
    ],
    ids=("rollback", "compensate"),
)
async def test_concurrent_scanners_after_terminal_reconciliation_create_one_follow_on(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    adapter_type: type[support._ControlledVerificationAdapter],
    expected_kind: RecoveryWorkKind,
    expected_state: TransactionState,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(
        adapter,
        (_PartialCountingReconcileAdapter, _PartialCompensatingReconcileAdapter),
    )
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    second_store: SQLiteEnforcedTransactionStore | None = None
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED,
        )
        with pytest.raises(CoordinatorInjectedCrash):
            await crashing.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        failed = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert failed.state is TransactionState.FAILED
        reconciliation = harness.store.list_recovery_work(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )[0]
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=reconciliation.tenant_id,
            transaction_id=reconciliation.transaction_id,
            recovery_id=reconciliation.recovery_id,
            attempt=reconciliation.attempt,
        )
        assert attempt.operation_evidence_ref is not None
        operation_path = support._artifact_path(
            harness.artifacts.root,
            attempt.operation_evidence_ref,
        )
        operation_evidence = operation_path.read_bytes()
        original_acquire = harness.store.acquire_recovery_authorization_lease

        def pause_after_handoff_acquire(**kwargs):
            acquired = original_acquire(**kwargs)
            operation_path.unlink()
            return acquired

        monkeypatch.setattr(
            harness.store,
            "acquire_recovery_authorization_lease",
            pause_after_handoff_acquire,
        )
        paused = support._restart_coordinator(harness)
        with pytest.raises(AgentKernelError) as paused_outage:
            await paused.recover_once(failed.tenant_id)
        assert paused_outage.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        _restore_private_artifact(harness.artifacts, operation_path, operation_evidence)
        monkeypatch.setattr(
            harness.store,
            "acquire_recovery_authorization_lease",
            original_acquire,
        )
        paused_handoff = next(
            handoff
            for handoff in harness.store.list_recovery_action_handoffs(
                tenant_id=failed.tenant_id,
                target_transaction_id=failed.transaction_id,
            )
            if handoff.binding.recovery_kind is expected_kind
        )
        assert paused_handoff.action is None
        assert paused_handoff.closed_at is None
        assert not harness.store.list_recovery_work(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )[1:]
        paused_lease = harness.store.get_worker_lease(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
            lease_id=paused_handoff.handoff_lease_id,
        )
        assert paused_lease.released_at is not None
        assert recovery_actions.create_calls == adapter.reconcile_calls == 1

        harness.store.close()
        first_store, first_reopened = support._reopen_coordinator(harness, database_path)
        second_store, second_reopened = support._reopen_coordinator(harness, database_path)
        harness.store = first_store
        recovery_config = EnforcedCoordinatorConfig(
            worker_id="worker:concurrent-partial-follow-on",
            lease_duration=timedelta(minutes=4),
            recovery_deadline=timedelta(minutes=4),
            reconciliation_backoff=timedelta(seconds=2),
        )
        first_coordinator = _clone_coordinator(
            harness,
            store=first_store,
            artifacts=first_reopened._artifacts,
            authority_snapshots=first_reopened._authority_snapshots,
            config=recovery_config,
        )
        second_coordinator = _clone_coordinator(
            harness,
            store=second_store,
            artifacts=second_reopened._artifacts,
            authority_snapshots=second_reopened._authority_snapshots,
            config=recovery_config,
        )
        if isinstance(adapter, _PartialCompensatingReconcileAdapter):
            adapter.test_clock = harness.clock
        barrier = asyncio.Barrier(2)
        first_recover_candidate = first_coordinator._recover_candidate
        second_recover_candidate = second_coordinator._recover_candidate

        async def first_gated_candidate(*args, **kwargs):
            await asyncio.wait_for(barrier.wait(), timeout=5)
            return await first_recover_candidate(*args, **kwargs)

        async def second_gated_candidate(*args, **kwargs):
            await asyncio.wait_for(barrier.wait(), timeout=5)
            return await second_recover_candidate(*args, **kwargs)

        monkeypatch.setattr(first_coordinator, "_recover_candidate", first_gated_candidate)
        monkeypatch.setattr(second_coordinator, "_recover_candidate", second_gated_candidate)

        results = await asyncio.wait_for(
            asyncio.gather(
                first_coordinator.recover_once(failed.tenant_id),
                second_coordinator.recover_once(failed.tenant_id),
            ),
            timeout=15,
        )

        result_summary = [
            (
                result.scanned,
                result.processed,
                result.remaining,
                tuple(
                    (failure.kind, failure.reason_code, failure.evidence_ref)
                    for failure in result.failures
                ),
            )
            for result in results
        ]
        assert first_store.count_recovery_candidates(tenant_id=failed.tenant_id) == 0
        assert (
            first_store.get_enforced_transaction(
                failed.tenant_id,
                failed.transaction_id,
            ).state
            is expected_state
        ), result_summary
        works = first_store.list_recovery_work(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )
        assert len(works) == 2
        follow_on = tuple(
            work for work in works if work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
        )
        assert len(follow_on) == 1
        assert follow_on[0].kind is expected_kind
        assert follow_on[0].state is RecoveryWorkState.SUCCEEDED
        final_handoff = first_store.get_recovery_action_handoff(
            tenant_id=failed.tenant_id,
            target_transaction_id=failed.transaction_id,
            recovery_id=paused_handoff.binding.recovery_id,
        )
        assert final_handoff is not None
        assert final_handoff.action is not None
        latest_lease_row = first_store._connection.execute(
            "SELECT lease_id FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? "
            "ORDER BY fencing_token DESC LIMIT 1",
            (failed.tenant_id, failed.transaction_id),
        ).fetchone()
        assert latest_lease_row is not None
        latest_lease = first_store.get_worker_lease(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
            lease_id=str(latest_lease_row["lease_id"]),
        )
        assert latest_lease.fencing_token > paused_lease.fencing_token
        assert recovery_actions.create_calls == 2
        assert adapter.reconcile_calls == 1
        if expected_kind is RecoveryWorkKind.ROLLBACK:
            assert adapter.rollback_calls == 1
        else:
            assert isinstance(adapter, _PartialCompensatingReconcileAdapter)
            assert adapter.compensation_calls == 1
        assert 1 <= sum(result.processed for result in results) <= 2
        assert all(not result.failures for result in results), result_summary
    finally:
        if second_store is not None:
            second_store.close()
        harness.store.close()


@pytest.mark.asyncio
async def test_restart_after_no_effect_reconciliation_finishes_abort_once(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.BEFORE_COMMIT,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    try:
        session = await _crash_during_commit(harness)
        assert harness.target.state == {"before": "kept"}
        await _stop_dispatch_before_explicit_resume(harness, session)
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED,
        )
        with pytest.raises(CoordinatorInjectedCrash) as crash:
            await crashing.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert crash.value.point is CoordinatorCrashPoint.AFTER_RECONCILIATION_FINISHED
        aborting = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert aborting.state is TransactionState.ABORTING
        historical = harness.store.list_recovery_work(
            tenant_id=aborting.tenant_id,
            transaction_id=aborting.transaction_id,
        )
        assert len(historical) == 1
        assert historical[0].kind is RecoveryWorkKind.RECONCILE_DISPATCH
        assert historical[0].state is RecoveryWorkState.SUCCEEDED
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=historical[0].tenant_id,
            transaction_id=historical[0].transaction_id,
            recovery_id=historical[0].recovery_id,
            attempt=historical[0].attempt,
        )
        assert attempt.outcome is ReconciliationOutcome.NO_EFFECT
        assert adapter.reconcile_calls == 1
        assert adapter.abort_stage_calls == 0

        harness.store.close()
        reopened_store, recovered = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        first = await recovered.recover_once(aborting.tenant_id)

        assert first.scanned == first.processed == 1
        assert first.remaining == 0
        assert not first.failures
        assert first.statuses[0].record.state is TransactionState.ABORTED
        assert adapter.reconcile_calls == 1
        assert adapter.abort_stage_calls == 1
        works = reopened_store.list_recovery_work(
            tenant_id=aborting.tenant_id,
            transaction_id=aborting.transaction_id,
        )
        assert len(works) == 2
        discard = tuple(work for work in works if work.kind is RecoveryWorkKind.DISCARD_STAGING)
        assert len(discard) == 1
        assert discard[0].state is RecoveryWorkState.SUCCEEDED

        repeated = await recovered.recover_once(aborting.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert adapter.reconcile_calls == adapter.abort_stage_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact_outage", [False, True], ids=("evidence", "outage"))
async def test_scheduled_reconciliation_expiry_closes_lineage_without_redispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_outage: bool,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_UnknownCountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _UnknownCountingReconcileAdapter)
    try:
        session = await _crash_during_commit(harness)
        transaction = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
        )
        harness.store.classify_dispatch_outcome(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
            expected_dispatch_version=dispatch.version,
            expected_transaction_version=transaction.version,
            classification=ReconciliationOutcome.UNKNOWN,
            evidence_refs=(dispatch.permit_ref,),
            recorded_at=harness.clock(),
            recovery_timeout=timedelta(seconds=10),
        )
        deadline = harness.store.get_transaction_recovery_deadline(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
        )
        first = await _clone_coordinator(harness).recover_once(transaction.tenant_id)
        assert first.scanned == first.processed == 1
        assert first.remaining == 1
        scheduled_rows = harness.store.list_recovery_work(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
        )
        assert len(scheduled_rows) == 1
        scheduled = scheduled_rows[0]
        assert scheduled.state is RecoveryWorkState.RETRY_SCHEDULED
        assert scheduled.deadline == deadline
        assert scheduled.recovery_ordinal == 1
        assert adapter.reconcile_calls == 1
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            recovery_id=scheduled.recovery_id,
            attempt=scheduled.attempt,
        )
        assert attempt.outcome is ReconciliationOutcome.UNKNOWN
        assert attempt.next_attempt_not_before is not None
        assert attempt.next_attempt_not_before < scheduled.deadline
        scheduled_transaction = harness.store.get_enforced_transaction(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
        )
        harness.clock.advance(timedelta(seconds=11))

        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        outage = _TerminalRecoveryEvidencePutOutageArtifacts(restarted._artifacts)
        if artifact_outage:
            monkeypatch.setattr(restarted, "_artifacts", outage)
        expired = await restarted.recover_once(transaction.tenant_id)

        expected_reason = (
            f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{ErrorCode.DEADLINE_EXCEEDED.value}"
            if artifact_outage
            else ErrorCode.DEADLINE_EXCEEDED.value
        )
        expected_status = (
            RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE
            if artifact_outage
            else RecoveryHandoffFailureEvidenceStatus.AVAILABLE
        )
        assert expired.scanned == expired.processed == 1
        assert expired.remaining == 0
        assert len(expired.failures) == 1
        assert expired.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert expired.failures[0].reason_code == expected_reason
        assert expired.statuses[0].record == scheduled_transaction
        assert adapter.reconcile_calls == 1
        assert outage.blocked_puts == (2 if artifact_outage else 0)
        works = reopened_store.list_recovery_work(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
        )
        assert len(works) == 1
        terminal = works[0]
        assert terminal.state is RecoveryWorkState.REVIEW_REQUIRED
        assert terminal.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert terminal.recovery_id == scheduled.recovery_id
        handoff = reopened_store.get_recovery_action_handoff(
            tenant_id=terminal.tenant_id,
            target_transaction_id=terminal.transaction_id,
            recovery_id=terminal.recovery_id,
        )
        assert handoff is not None
        assert handoff.closed_at == terminal.updated_at == harness.clock()
        assert handoff.failure_evidence_status is expected_status
        assert (handoff.failure_evidence_ref is None) is artifact_outage
        assert handoff.failure_reason_code == expected_reason
        assert expired.failures[0].evidence_ref == handoff.failure_evidence_ref
        repeated = await restarted.recover_once(transaction.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        if artifact_outage:
            assert len(repeated.failures) == 1
            assert repeated.failures[0].kind is RecoveryFailureKind.EVIDENCE_AUDIT
            assert repeated.failures[0].reason_code == ErrorCode.EVIDENCE_UNAVAILABLE.value
            quiet = await restarted.recover_once(transaction.tenant_id)
            assert quiet.scanned == quiet.processed == quiet.remaining == 0
            assert not quiet.failures
        else:
            assert not repeated.failures
        assert adapter.reconcile_calls == 1

        reopened_store.close()
        final_store, final_restart = support._reopen_coordinator(harness, database_path)
        harness.store = final_store
        after_restart = await final_restart.recover_once(transaction.tenant_id)
        assert after_restart.scanned == after_restart.processed == after_restart.remaining == 0
        assert not after_restart.failures
        assert final_store.count_recovery_candidates(tenant_id=transaction.tenant_id) == 0
        assert adapter.reconcile_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("artifact_damage", ["missing", "corrupt"])
async def test_scheduled_reconciliation_expiry_revalidates_prior_operation_before_closure(
    tmp_path: Path,
    artifact_damage: str,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_UnknownCountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _UnknownCountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    operation_path: Path | None = None
    original_operation: bytes | None = None
    try:
        session = await _crash_during_commit(harness)
        transaction = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
        )
        harness.store.classify_dispatch_outcome(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
            expected_dispatch_version=dispatch.version,
            expected_transaction_version=transaction.version,
            classification=ReconciliationOutcome.UNKNOWN,
            evidence_refs=(dispatch.permit_ref,),
            recorded_at=harness.clock(),
            recovery_timeout=timedelta(seconds=10),
        )
        coordinator = _clone_coordinator(
            harness,
            recovery_actions=recovery_actions,
        )
        first = await coordinator.recover_once(transaction.tenant_id)
        assert first.scanned == first.processed == 1
        scheduled = harness.store.list_recovery_work(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
        )[0]
        assert scheduled.state is RecoveryWorkState.RETRY_SCHEDULED
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            recovery_id=scheduled.recovery_id,
            attempt=scheduled.attempt,
        )
        assert attempt.operation_evidence_ref is not None
        operation_path = support._artifact_path(
            harness.artifacts.root,
            attempt.operation_evidence_ref,
        )
        original_operation = operation_path.read_bytes()
        harness.clock.advance(scheduled.deadline - harness.clock() + timedelta(microseconds=1))
        if artifact_damage == "missing":
            operation_path.unlink()
            expected_error = ErrorCode.EVIDENCE_UNAVAILABLE
        else:
            operation_path.write_bytes(b"corrupt-expired-scheduled-operation")
            expected_error = ErrorCode.INTEGRITY_ERROR

        baseline_transaction = harness.store.get_enforced_transaction(
            scheduled.tenant_id,
            scheduled.transaction_id,
        )
        baseline_work = harness.store.list_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        baseline_handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=scheduled.tenant_id,
            target_transaction_id=scheduled.transaction_id,
        )
        baseline_leases = _worker_lease_snapshot(
            harness.store,
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        baseline_artifacts = _artifact_file_snapshot(harness.artifacts.root)

        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        with pytest.raises(AgentKernelError) as blocked:
            await restarted.recover_once(scheduled.tenant_id)
        assert blocked.value.code is expected_error
        assert (
            reopened_store.get_enforced_transaction(
                scheduled.tenant_id,
                scheduled.transaction_id,
            )
            == baseline_transaction
        )
        assert (
            reopened_store.list_recovery_work(
                tenant_id=scheduled.tenant_id,
                transaction_id=scheduled.transaction_id,
            )
            == baseline_work
        )
        assert (
            reopened_store.list_recovery_action_handoffs(
                tenant_id=scheduled.tenant_id,
                target_transaction_id=scheduled.transaction_id,
            )
            == baseline_handoffs
        )
        assert (
            _worker_lease_snapshot(
                reopened_store,
                tenant_id=scheduled.tenant_id,
                transaction_id=scheduled.transaction_id,
            )
            == baseline_leases
        )
        assert _artifact_file_snapshot(harness.artifacts.root) == baseline_artifacts
        assert recovery_actions.create_calls == adapter.reconcile_calls == 1

        _restore_private_artifact(harness.artifacts, operation_path, original_operation)
        original_operation = None
        expired = await restarted.recover_once(scheduled.tenant_id)
        assert expired.scanned == expired.processed == 1
        assert expired.remaining == 0
        assert len(expired.failures) == 1
        terminal = reopened_store.get_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            recovery_id=scheduled.recovery_id,
        )
        assert terminal.state is RecoveryWorkState.REVIEW_REQUIRED
        assert terminal.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert recovery_actions.create_calls == adapter.reconcile_calls == 1
        repeated = await restarted.recover_once(scheduled.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
    finally:
        if operation_path is not None and original_operation is not None:
            _restore_private_artifact(harness.artifacts, operation_path, original_operation)
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "crossing_point",
    ["before-authorization", "inside-authorization"],
)
async def test_scheduled_reconciliation_crossing_deadline_terminalizes_in_same_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crossing_point: str,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_UnknownCountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _UnknownCountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        session = await _crash_during_commit(harness)
        transaction = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
        )
        harness.store.classify_dispatch_outcome(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
            expected_dispatch_version=dispatch.version,
            expected_transaction_version=transaction.version,
            classification=ReconciliationOutcome.UNKNOWN,
            evidence_refs=(dispatch.permit_ref,),
            recorded_at=harness.clock(),
            recovery_timeout=timedelta(seconds=10),
        )
        coordinator = _clone_coordinator(
            harness,
            recovery_actions=recovery_actions,
        )
        scheduled_scan = await coordinator.recover_once(transaction.tenant_id)
        assert scheduled_scan.scanned == scheduled_scan.processed == 1
        assert scheduled_scan.remaining == 1
        scheduled = harness.store.list_recovery_work(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
        )[0]
        assert scheduled.state is RecoveryWorkState.RETRY_SCHEDULED
        assert adapter.reconcile_calls == 1
        assert recovery_actions.create_calls == 1

        harness.clock.advance(scheduled.deadline - harness.clock() - timedelta(microseconds=1))
        assert harness.clock() < scheduled.deadline
        crossed = False

        if crossing_point == "before-authorization":
            original_get_dispatch = harness.store.get_commit_dispatch

            def get_dispatch_and_cross_deadline(*, tenant_id: str, transaction_id: str):
                nonlocal crossed
                current = original_get_dispatch(
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                )
                if transaction_id == scheduled.transaction_id and not crossed:
                    crossed = True
                    harness.clock.advance(scheduled.deadline - harness.clock())
                return current

            monkeypatch.setattr(
                harness.store,
                "get_commit_dispatch",
                get_dispatch_and_cross_deadline,
            )
        else:
            original_authorize = coordinator._authorize_recovery_work
            original_now = coordinator._now
            inside_authorization = False

            async def authorize_with_deadline_crossing(*args, **kwargs):
                nonlocal inside_authorization
                inside_authorization = True
                try:
                    return await original_authorize(*args, **kwargs)
                finally:
                    inside_authorization = False

            def cross_on_authorization_clock_read():
                nonlocal crossed
                if inside_authorization and not crossed:
                    crossed = True
                    assert harness.clock() < scheduled.deadline
                    harness.clock.advance(scheduled.deadline - harness.clock())
                return original_now()

            monkeypatch.setattr(
                coordinator,
                "_authorize_recovery_work",
                authorize_with_deadline_crossing,
            )
            monkeypatch.setattr(
                coordinator,
                "_now",
                cross_on_authorization_clock_read,
            )

        terminalized = await coordinator.recover_once(transaction.tenant_id)

        assert crossed
        assert terminalized.observed_at < scheduled.deadline
        assert harness.clock() == scheduled.deadline
        assert terminalized.scanned == terminalized.processed == 1
        assert terminalized.remaining == 0
        assert len(terminalized.failures) == 1
        assert terminalized.failures[0].kind is RecoveryFailureKind.RECOVERY_TERMINAL
        assert terminalized.failures[0].reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        works = harness.store.list_recovery_work(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
        )
        assert len(works) == 1
        closed = works[0]
        assert closed.recovery_id == scheduled.recovery_id
        assert closed.state is RecoveryWorkState.REVIEW_REQUIRED
        assert closed.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=transaction.tenant_id,
            target_transaction_id=transaction.transaction_id,
        )
        assert len(handoffs) == 1
        assert handoffs[0].binding.recovery_id == scheduled.recovery_id
        assert handoffs[0].closed_at == scheduled.deadline
        assert adapter.reconcile_calls == 1
        assert recovery_actions.create_calls == 1

        repeated = await coordinator.recover_once(transaction.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert adapter.reconcile_calls == recovery_actions.create_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("winner", "attach_successor"),
    [
        pytest.param("terminalizer", False, id="terminalizer"),
        pytest.param("successor-handoff", False, id="successor-unattached"),
        pytest.param("successor-handoff", True, id="successor-attached"),
    ],
)
async def test_scheduled_deadline_and_successor_handoff_have_one_atomic_winner(
    tmp_path: Path,
    winner: str,
    attach_successor: bool,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_UnknownCountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _UnknownCountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        session = await _crash_during_commit(harness)
        transaction = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
        )
        harness.store.classify_dispatch_outcome(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
            expected_dispatch_version=dispatch.version,
            expected_transaction_version=transaction.version,
            classification=ReconciliationOutcome.UNKNOWN,
            evidence_refs=(dispatch.permit_ref,),
            recorded_at=harness.clock(),
            recovery_timeout=timedelta(seconds=10),
        )
        coordinator = _clone_coordinator(
            harness,
            recovery_actions=recovery_actions,
        )
        scheduled_scan = await coordinator.recover_once(transaction.tenant_id)
        assert scheduled_scan.scanned == scheduled_scan.processed == 1
        scheduled = harness.store.list_recovery_work(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
        )[0]
        assert scheduled.state is RecoveryWorkState.RETRY_SCHEDULED
        current = harness.store.get_enforced_transaction(
            scheduled.tenant_id,
            scheduled.transaction_id,
        )
        current_dispatch = harness.store.get_commit_dispatch(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        successor_binding = coordinator._propose_recovery_action_binding(
            current,
            kind=RecoveryWorkKind.RECONCILE_DISPATCH,
            target=current_dispatch,
            target_ref=canonical_digest(current_dispatch),
            observed_at=scheduled.deadline - timedelta(microseconds=1),
            predecessor=scheduled,
        )
        predecessor_handoff = harness.store.get_recovery_action_handoff(
            tenant_id=scheduled.tenant_id,
            target_transaction_id=scheduled.transaction_id,
            recovery_id=scheduled.recovery_id,
        )
        assert predecessor_handoff is not None
        deadline_evidence_ref = harness.artifacts.put_model(
            CoordinatorEvidence(
                transaction_id=scheduled.transaction_id,
                event="recovery.authorization_handoff_failed",
                reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                recorded_at=scheduled.deadline,
                subject_ref=predecessor_handoff.binding_ref,
            )
        ).digest
        terminalize_arguments = {
            "tenant_id": scheduled.tenant_id,
            "transaction_id": scheduled.transaction_id,
            "recovery_id": scheduled.recovery_id,
            "expected_successor_recovery_id": successor_binding.recovery_id,
            "expected_work_version": scheduled.version,
            "failure_evidence_ref": deadline_evidence_ref,
            "failure_evidence_status": RecoveryHandoffFailureEvidenceStatus.AVAILABLE,
            "recorded_at": scheduled.deadline,
        }
        successor_lease_id = f"lease:successor-race-{winner}"
        register_arguments = {
            "tenant_id": current.tenant_id,
            "transaction_id": current.transaction_id,
            "expected_transaction_version": current.version,
            "kind": RecoveryWorkKind.RECONCILE_DISPATCH,
            "dispatch_id": current_dispatch.dispatch_id,
            "dispatch_target_ref": canonical_digest(current_dispatch),
            "recovery_id": successor_binding.recovery_id,
            "lease_id": successor_lease_id,
            "worker_id": f"worker:successor-race-{winner}",
            "acquired_at": scheduled.deadline - timedelta(microseconds=1),
            "expires_at": scheduled.deadline,
            "binding": successor_binding,
        }
        ready = threading.Event()
        barrier = threading.Barrier(2)

        def run_loser():
            with SQLiteEnforcedTransactionStore(database_path) as concurrent_store:
                ready.set()
                barrier.wait(timeout=5)
                try:
                    if winner == "terminalizer":
                        return concurrent_store.acquire_recovery_authorization_lease(
                            **register_arguments
                        )
                    return concurrent_store.terminalize_scheduled_reconciliation_deadline(
                        **terminalize_arguments
                    )
                except AgentKernelError as error:
                    return error

        loser_task = asyncio.create_task(asyncio.to_thread(run_loser))
        assert await asyncio.to_thread(ready.wait, 5)
        harness.store._connection.execute("BEGIN IMMEDIATE")
        try:
            winning_result = (
                harness.store.terminalize_scheduled_reconciliation_deadline(**terminalize_arguments)
                if winner == "terminalizer"
                else harness.store.acquire_recovery_authorization_lease(**register_arguments)
            )
            await asyncio.to_thread(barrier.wait, 5)
            await asyncio.sleep(0.05)
            harness.store._connection.execute("COMMIT")
        finally:
            if harness.store._connection.in_transaction:
                harness.store._connection.execute("ROLLBACK")
        loser_result = await asyncio.wait_for(loser_task, timeout=10)

        assert winning_result.disposition is (
            EnforcedStoreDisposition.REVIEW_REQUIRED
            if winner == "terminalizer"
            else EnforcedStoreDisposition.STORED
        )
        assert isinstance(loser_result, AgentKernelError)
        assert loser_result.code is ErrorCode.VERSION_CONFLICT
        raced_predecessor = harness.store.get_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            recovery_id=scheduled.recovery_id,
        )
        successor_handoff = harness.store.get_recovery_action_handoff(
            tenant_id=scheduled.tenant_id,
            target_transaction_id=scheduled.transaction_id,
            recovery_id=successor_binding.recovery_id,
        )
        if winner == "terminalizer":
            assert raced_predecessor.state is RecoveryWorkState.REVIEW_REQUIRED
            assert successor_handoff is None
            with pytest.raises(AgentKernelError) as no_successor_lease:
                harness.store.get_worker_lease(
                    tenant_id=scheduled.tenant_id,
                    transaction_id=scheduled.transaction_id,
                    lease_id=successor_lease_id,
                )
            assert no_successor_lease.value.code is ErrorCode.VALIDATION_ERROR
        else:
            assert raced_predecessor == scheduled
            assert successor_handoff is not None
            assert successor_handoff.closed_at is None
            if attach_successor:
                target_action = harness.store.get_normalized_action(
                    current.tenant_id,
                    current.transaction_id,
                ).action
                recovery_action = await recovery_actions.create(
                    target=current,
                    target_action=target_action,
                    kind=RecoveryWorkKind.RECONCILE_DISPATCH,
                    target_evidence_ref=canonical_digest(current_dispatch),
                    binding=successor_binding,
                    deadline=successor_binding.absolute_deadline,
                )
                harness.store.register_recovery_action(
                    recovery_action,
                    registered_at=scheduled.deadline - timedelta(microseconds=1),
                    binding=successor_binding,
                )
                with pytest.raises(AgentKernelError) as attached_owner:
                    harness.store.terminalize_scheduled_reconciliation_deadline(
                        **terminalize_arguments
                    )
                assert attached_owner.value.code is ErrorCode.VERSION_CONFLICT
            harness.clock.advance(scheduled.deadline - harness.clock())
            coordinator._fail_unattached_recovery_action(
                current,
                binding=successor_binding,
                reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                handoff_lease=None,
            )
            coordinator._terminalize_expired_recovery(
                scheduled,
                reported_at=scheduled.deadline,
            )

        final_predecessor = harness.store.get_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            recovery_id=scheduled.recovery_id,
        )
        assert final_predecessor.state is RecoveryWorkState.REVIEW_REQUIRED
        assert not harness.store.get_active_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=scheduled.tenant_id,
            target_transaction_id=scheduled.transaction_id,
        )
        assert all(handoff.closed_at is not None for handoff in handoffs)
        assert not any(
            work.predecessor_recovery_id == scheduled.recovery_id
            for work in harness.store.list_recovery_work(
                tenant_id=scheduled.tenant_id,
                transaction_id=scheduled.transaction_id,
            )
        )
        settled_successor = harness.store.get_recovery_action_handoff(
            tenant_id=scheduled.tenant_id,
            target_transaction_id=scheduled.transaction_id,
            recovery_id=successor_binding.recovery_id,
        )
        assert (settled_successor is not None) is (winner == "successor-handoff")
        if settled_successor is not None:
            assert settled_successor.closed_at == scheduled.deadline
            assert (settled_successor.action is not None) is attach_successor
        exact_retry = harness.store.terminalize_scheduled_reconciliation_deadline(
            **terminalize_arguments
        )
        assert exact_retry.disposition is EnforcedStoreDisposition.EXACT_RETRY
        changed_successor_arguments = {
            **terminalize_arguments,
            "expected_successor_recovery_id": "recovery:changed-successor-association",
        }
        with pytest.raises(AgentKernelError) as changed_successor:
            harness.store.terminalize_scheduled_reconciliation_deadline(
                **changed_successor_arguments
            )
        assert changed_successor.value.code is ErrorCode.VERSION_CONFLICT
        with SQLiteEnforcedTransactionStore(database_path) as reopened_store:
            reopened_retry = reopened_store.terminalize_scheduled_reconciliation_deadline(
                **terminalize_arguments
            )
            assert reopened_retry.disposition is EnforcedStoreDisposition.EXACT_RETRY
            with reopened_store._immediate():
                later_lease, created = reopened_store._acquire_worker_lease_tx(
                    tenant_id=scheduled.tenant_id,
                    transaction_id=scheduled.transaction_id,
                    lease_id=f"lease:post-terminal-tamper:{winner}",
                    worker_id=f"worker:post-terminal-tamper:{winner}",
                    purpose=LeasePurpose.RECOVERY,
                    acquired_at=scheduled.deadline + timedelta(microseconds=1),
                    expires_at=scheduled.deadline + timedelta(microseconds=2),
                )
                assert created
                released_later_lease = WorkerLeaseRecord.model_validate(
                    {
                        **later_lease.model_dump(mode="python"),
                        "version": later_lease.version + 1,
                        "released_at": later_lease.expires_at,
                    }
                )
                reopened_store._update_worker_lease_tx(
                    later_lease,
                    released_later_lease,
                )
            with pytest.raises(AgentKernelError) as tampered_association:
                reopened_store.terminalize_scheduled_reconciliation_deadline(
                    **terminalize_arguments
                )
            assert tampered_association.value.code is ErrorCode.INTEGRITY_ERROR
        repeated = await coordinator.recover_once(scheduled.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert adapter.reconcile_calls == 1
        assert recovery_actions.create_calls == 1 + int(attach_successor)
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_expired_handoff_terminalization_is_crash_consistent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SimulatedProcessDeath(BaseException):
        pass

    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        (
            _session,
            target_before,
            _dispatch_before,
            _deadline,
        ) = await _expire_unstarted_dispatch_recovery(harness)
        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        captured: list[dict[str, object]] = []
        original_terminalize = reopened_store.terminalize_expired_recovery_handoff

        def crash_after_commit(**kwargs):
            captured.append(dict(kwargs))
            original_terminalize(**kwargs)
            raise SimulatedProcessDeath

        monkeypatch.setattr(
            reopened_store,
            "terminalize_expired_recovery_handoff",
            crash_after_commit,
        )
        with pytest.raises(SimulatedProcessDeath):
            await restarted.recover_once(target_before.tenant_id)
        assert len(captured) == 1
        assert adapter.reconcile_calls == recovery_actions.create_calls == 0
        assert not reopened_store.list_recovery_work(
            tenant_id=target_before.tenant_id,
            transaction_id=target_before.transaction_id,
        )

        reopened_store.close()
        recovered_store, recovered = support._reopen_coordinator(harness, database_path)
        harness.store = recovered_store
        exact_retry = recovered_store.terminalize_expired_recovery_handoff(**captured[0])
        assert exact_retry.disposition is EnforcedStoreDisposition.EXACT_RETRY
        converged = await recovered.recover_once(target_before.tenant_id)
        assert converged.scanned == converged.processed == converged.remaining == 0
        assert not converged.failures
        assert (
            recovered_store.get_enforced_transaction(
                target_before.tenant_id,
                target_before.transaction_id,
            )
            == target_before
        )
        handoffs = recovered_store.list_recovery_action_handoffs(
            tenant_id=target_before.tenant_id,
            target_transaction_id=target_before.transaction_id,
        )
        assert len(handoffs) == 1
        assert handoffs[0].action is None
        assert handoffs[0].closed_at is not None
        lease = recovered_store.get_worker_lease(
            tenant_id=target_before.tenant_id,
            transaction_id=target_before.transaction_id,
            lease_id=handoffs[0].handoff_lease_id,
        )
        assert lease.released_at == handoffs[0].closed_at
        active_count = recovered_store._connection.execute(
            "SELECT COUNT(*) FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
            (target_before.tenant_id, target_before.transaction_id),
        ).fetchone()
        assert active_count is not None
        assert int(active_count[0]) == 0
        assert adapter.reconcile_calls == recovery_actions.create_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_concurrent_expired_recovery_coordinators_share_one_review_barrier(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        (
            _session,
            target_before,
            _dispatch_before,
            _deadline,
        ) = await _expire_unstarted_dispatch_recovery(harness)
        harness.store.close()
        barrier = threading.Barrier(2)
        capture_lock = threading.Lock()
        dispositions: list[EnforcedStoreDisposition] = []

        def run_coordinator() -> None:
            store = SQLiteEnforcedTransactionStore(database_path)
            try:
                coordinator = _clone_coordinator(
                    harness,
                    store=store,
                    config=EnforcedCoordinatorConfig(
                        worker_id="worker:parallel-expiry",
                        lease_duration=timedelta(minutes=1),
                        recovery_deadline=timedelta(minutes=4),
                        reconciliation_backoff=timedelta(seconds=2),
                    ),
                )
                record = store.get_enforced_transaction(
                    target_before.tenant_id,
                    target_before.transaction_id,
                )
                dispatch = store.get_commit_dispatch(
                    tenant_id=target_before.tenant_id,
                    transaction_id=target_before.transaction_id,
                )
                original_terminalize = store.terminalize_expired_recovery_handoff

                def gated_terminalize(**kwargs):
                    barrier.wait(timeout=5)
                    result = original_terminalize(**kwargs)
                    with capture_lock:
                        dispositions.append(result.disposition)
                    return result

                store.terminalize_expired_recovery_handoff = gated_terminalize
                result = asyncio.run(
                    coordinator._authorize_recovery_work(
                        record,
                        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
                        target=dispatch,
                    )
                )
                assert result is None
            finally:
                store.close()

        await asyncio.gather(
            asyncio.to_thread(run_coordinator),
            asyncio.to_thread(run_coordinator),
        )

        assert sorted(dispositions) == sorted(
            [
                EnforcedStoreDisposition.STORED,
                EnforcedStoreDisposition.EXACT_RETRY,
            ]
        )
        reopened = SQLiteEnforcedTransactionStore(database_path)
        harness.store = reopened
        handoffs = reopened.list_recovery_action_handoffs(
            tenant_id=target_before.tenant_id,
            target_transaction_id=target_before.transaction_id,
        )
        assert len(handoffs) == 1
        assert handoffs[0].action is None
        assert handoffs[0].closed_at is not None
        assert not reopened.list_recovery_work(
            tenant_id=target_before.tenant_id,
            transaction_id=target_before.transaction_id,
        )
        assert reopened.count_recovery_candidates(tenant_id=target_before.tenant_id) == 0
        lease = reopened.get_worker_lease(
            tenant_id=target_before.tenant_id,
            transaction_id=target_before.transaction_id,
            lease_id=handoffs[0].handoff_lease_id,
        )
        assert lease.released_at == handoffs[0].closed_at
        active_count = reopened._connection.execute(
            "SELECT COUNT(*) FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
            (target_before.tenant_id, target_before.transaction_id),
        ).fetchone()
        assert active_count is not None
        assert int(active_count[0]) == 0
        assert adapter.reconcile_calls == recovery_actions.create_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_expired_handoff_terminalization_rejects_corrupt_generation_inputs(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    try:
        _session, target, dispatch, _deadline = await _expire_unstarted_dispatch_recovery(harness)
        coordinator = _clone_coordinator(harness)
        binding = coordinator._propose_recovery_action_binding(
            target,
            kind=RecoveryWorkKind.RECONCILE_DISPATCH,
            target=dispatch,
            target_ref=canonical_digest(dispatch),
            observed_at=harness.clock(),
            predecessor=None,
        )
        evidence_ref = harness.artifacts.put_model(
            CoordinatorEvidence(
                transaction_id=target.transaction_id,
                event="recovery.authorization_handoff_failed",
                reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
                recorded_at=harness.clock(),
                subject_ref=canonical_digest(binding),
            )
        ).digest
        arguments: dict[str, object] = {
            "tenant_id": target.tenant_id,
            "transaction_id": target.transaction_id,
            "expected_transaction_version": target.version,
            "binding": binding,
            "lease_id": "lease:corruption-probe",
            "worker_id": "worker:corruption-probe",
            "failure_evidence_ref": evidence_ref,
            "recorded_at": harness.clock(),
        }

        with pytest.raises(AgentKernelError) as stale_version:
            harness.store.terminalize_expired_recovery_handoff(
                **{**arguments, "expected_transaction_version": target.version + 1}
            )
        assert stale_version.value.code is ErrorCode.VERSION_CONFLICT
        wrong_dispatch_binding = binding.model_copy(
            update={"target_evidence_ref": "sha256:" + ("1" * 64)}
        )
        with pytest.raises(AgentKernelError) as wrong_dispatch:
            harness.store.terminalize_expired_recovery_handoff(
                **{**arguments, "binding": wrong_dispatch_binding}
            )
        assert wrong_dispatch.value.code is ErrorCode.VERSION_CONFLICT
        wrong_deadline_binding = binding.model_copy(
            update={"absolute_deadline": binding.absolute_deadline - timedelta(microseconds=1)}
        )
        with pytest.raises(AgentKernelError) as wrong_deadline:
            harness.store.terminalize_expired_recovery_handoff(
                **{**arguments, "binding": wrong_deadline_binding}
            )
        assert wrong_deadline.value.code is ErrorCode.VERSION_CONFLICT

        harness.store._execute(
            "UPDATE enforced_commit_dispatches SET state = 'COMMITTED' "
            "WHERE tenant_id = ? AND transaction_id = ?",
            (target.tenant_id, target.transaction_id),
        )
        try:
            with pytest.raises(AgentKernelError) as corrupt_dispatch:
                harness.store.terminalize_expired_recovery_handoff(**arguments)
            assert corrupt_dispatch.value.code is ErrorCode.INTEGRITY_ERROR
        finally:
            harness.store._execute(
                "UPDATE enforced_commit_dispatches SET state = 'IN_DOUBT' "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (target.tenant_id, target.transaction_id),
            )

        assert not harness.store.list_recovery_action_handoffs(
            tenant_id=target.tenant_id,
            target_transaction_id=target.transaction_id,
        )
        assert not harness.store.list_recovery_work(
            tenant_id=target.tenant_id,
            transaction_id=target.transaction_id,
        )
        active_count = harness.store._connection.execute(
            "SELECT COUNT(*) FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
            (target.tenant_id, target.transaction_id),
        ).fetchone()
        assert active_count is not None
        assert int(active_count[0]) == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_explicit_dispatch_resume_rejects_wrong_tenant_and_untyped_in_doubt(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    reopened_store = None
    try:
        session = await _crash_during_commit(harness)
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        transaction = harness.store.get_enforced_transaction(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        classified = harness.store.classify_dispatch_outcome(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.transaction_id,
            expected_dispatch_version=dispatch.version,
            expected_transaction_version=transaction.version,
            classification=ReconciliationOutcome.UNKNOWN,
            evidence_refs=(dispatch.permit_ref,),
            recorded_at=harness.clock(),
            recovery_timeout=harness.coordinator._config.recovery_deadline,
        )
        assert classified.transaction.state is TransactionState.IN_DOUBT
        assert classified.dispatch.unavailable_record_digest is None

        with pytest.raises(AgentKernelError) as wrong_tenant:
            await harness.coordinator.resume_dispatch_reconciliation(
                "tenant:not-the-owner",
                session.record.transaction_id,
            )
        assert wrong_tenant.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as untyped:
            await harness.coordinator.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert untyped.value.code is ErrorCode.VALIDATION_ERROR

        harness.store.close()
        reopened_store, reopened = support._reopen_coordinator(harness, database_path)
        with pytest.raises(AgentKernelError) as reopened_untyped:
            await reopened.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert reopened_untyped.value.code is ErrorCode.VALIDATION_ERROR
    finally:
        if reopened_store is not None:
            reopened_store.close()
        harness.store.close()


@pytest.mark.asyncio
async def test_recovery_scanner_resumes_an_already_aborting_transaction(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_ABORTING,
    )
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                pass
        assert session.record.state is TransactionState.ABORTING

        harness.clock.advance(timedelta(minutes=1, microseconds=1))
        result = await support._restart_coordinator(harness).recover_once(session.record.tenant_id)
        assert not result.failures
        assert result.statuses[0].record.state is TransactionState.ABORTED
        assert harness.target.state == {"before": "kept"}
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_recovery_scanner_fails_expired_aborting_stage_closed(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_ABORTING,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                pass
        harness.clock.advance(timedelta(minutes=10))

        result = await support._restart_coordinator(harness).recover_once(session.record.tenant_id)

        assert result.processed == 1
        assert not result.failures
        failed = result.statuses[0].record
        assert failed.state is TransactionState.RECOVERY_FAILED
        assert failed.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        stage = harness.store.get_stage_material(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )
        assert stage.state is StageMaterialState.DISCARD_FAILED
        attempt = harness.store.get_intent_attempt(
            tenant_id=failed.tenant_id,
            intent_hash=session.action.intent_hash,
            transaction_id=failed.transaction_id,
        )
        assert attempt.state is IntentAttemptState.REVIEW_REQUIRED
        assert adapter.abort_stage_calls == 0
        assert not harness.store.get_active_recovery_work(
            tenant_id=failed.tenant_id,
            transaction_id=failed.transaction_id,
        )
        active_lease_count = harness.store._connection.execute(
            "SELECT COUNT(*) FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
            (failed.tenant_id, failed.transaction_id),
        ).fetchone()[0]
        assert active_lease_count == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_reconciliation_exception_is_durable_unknown_and_retryable(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_ReconcileRaisesAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        with pytest.raises(AgentKernelError) as captured:
            await restarted.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert captured.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert works[0].state is RecoveryWorkState.RETRY_SCHEDULED
        assert (
            restarted.status(
                session.record.tenant_id,
                session.record.transaction_id,
            ).record.state
            is TransactionState.IN_DOUBT
        )
        assert harness.target.state == {"before": "kept"}
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_committed_reconciliation_without_receipt_is_partial_and_not_accepted(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CommittedWithoutReceiptAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        with pytest.raises(AgentKernelError) as captured:
            await restarted.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert captured.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        assert (
            restarted.status(
                session.record.tenant_id,
                session.record.transaction_id,
            ).record.state
            is TransactionState.RECOVERY_FAILED
        )
        assert harness.target.state == {"before": "kept"}
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_no_effect_reconciliation_with_receipt_is_partial_and_rolled_back(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_NoEffectWithReceiptAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _NoEffectWithReceiptAdapter)
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        resumed = await restarted.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert resumed.record.state is TransactionState.ROLLED_BACK
        assert adapter.rollback_calls == 1
        assert harness.target.state == {"before": "kept"}
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("verification_status", "expected_state", "rollback_calls"),
    [
        (VerificationStatus.FAIL, TransactionState.ROLLED_BACK, 1),
        (VerificationStatus.UNKNOWN, TransactionState.IN_DOUBT, 0),
    ],
)
async def test_reconciled_commit_is_independently_verified_before_classification(
    tmp_path: Path,
    verification_status: VerificationStatus,
    expected_state: TransactionState,
    rollback_calls: int,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    adapter.committed_status = verification_status
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        resumed = await restarted.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert resumed.record.state is expected_state
        assert adapter.rollback_calls == rollback_calls
        attempts = harness.store.list_reconciliation_attempts(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(attempts) == 1
        assert attempts[0].operation_evidence_ref is not None
        assert attempts[0].operation_reason_code is None
        observation = harness.artifacts.get_model(
            attempts[0].operation_evidence_ref,
            AdapterObservation,
        )
        assert observation.evidence_kind == "committed_verification"
        if verification_status is VerificationStatus.UNKNOWN:
            works = harness.store.list_recovery_work(
                tenant_id=session.record.tenant_id,
                transaction_id=session.record.transaction_id,
            )
            assert works[0].state is RecoveryWorkState.RETRY_SCHEDULED

        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            harness.store = reopened
            reopened_attempt = reopened.get_reconciliation_attempt(
                tenant_id=attempts[0].tenant_id,
                transaction_id=attempts[0].transaction_id,
                recovery_id=attempts[0].recovery_id,
                attempt=attempts[0].attempt,
            )
            assert reopened_attempt.operation_evidence_ref == attempts[0].operation_evidence_ref
            assert (
                _clone_coordinator(harness, store=reopened)
                .status(session.record.tenant_id, session.record.transaction_id)
                .record.state
                is expected_state
            )
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_reconciliation_verification_exception_binds_control_operation_evidence(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CommittedVerificationRaisesAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        with pytest.raises(AgentKernelError) as captured:
            await restarted.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert captured.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        attempts = harness.store.list_reconciliation_attempts(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(attempts) == 1
        attempt = attempts[0]
        assert attempt.operation_evidence_ref is not None
        assert attempt.operation_reason_code == ErrorCode.EVIDENCE_UNAVAILABLE.value
        control = harness.artifacts.get_model(
            attempt.operation_evidence_ref,
            CoordinatorEvidence,
        )
        assert control.event == "reconciliation.query_failed"
        assert control.reason_code == attempt.operation_reason_code
        work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        assert control.subject_ref == work.permit_ref
        assert attempt.operation_evidence_ref in attempt.completion_evidence_refs

        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            harness.store = reopened
            reopened_attempt = reopened.get_reconciliation_attempt(
                tenant_id=attempt.tenant_id,
                transaction_id=attempt.transaction_id,
                recovery_id=attempt.recovery_id,
                attempt=attempt.attempt,
            )
            assert reopened_attempt == attempt
            status = _clone_coordinator(harness, store=reopened).status(
                session.record.tenant_id,
                session.record.transaction_id,
            )
            assert status.record.state is TransactionState.IN_DOUBT
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_recovery_post_report_failure_binds_control_operation_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = support._make_harness(tmp_path)
    original_finish = harness.store.finish_recovery
    submitted_operation_refs: list[str] = []

    def fail_first_finish(**kwargs: object):
        operation_ref = str(kwargs["operation_evidence_ref"])
        submitted_operation_refs.append(operation_ref)
        if len(submitted_operation_refs) == 1:
            observation = harness.artifacts.get_model(
                operation_ref,
                AdapterObservation,
            )
            assert observation.evidence_kind == "discard_staging"
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Synthetic failure after valid recovery evidence",
            )
        return original_finish(**kwargs)

    monkeypatch.setattr(harness.store, "finish_recovery", fail_first_finish)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            pass
        work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        completion = harness.store.get_recovery_completion_report(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert completion is not None
        assert len(submitted_operation_refs) == 2
        assert completion.operation_evidence_ref == submitted_operation_refs[1]
        assert completion.operation_evidence_ref != submitted_operation_refs[0]
        assert submitted_operation_refs[0] in completion.evidence_refs
        control = harness.artifacts.get_model(
            completion.operation_evidence_ref,
            CoordinatorEvidence,
        )
        assert control.event == "recovery.execution_failed"
        assert control.reason_code == ErrorCode.INTEGRITY_ERROR.value
        assert control.subject_ref == work.permit_ref
        projection = harness.store.get_transaction_projection(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
        )
        terminal = harness.coordinator._recovery_terminal_failure(projection)
        assert terminal is not None
        assert terminal.evidence_ref == completion.operation_evidence_ref

        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            harness.store = reopened
            coordinator = _clone_coordinator(harness, store=reopened)
            reopened_status = coordinator.status(
                work.tenant_id,
                work.transaction_id,
            )
            assert reopened_status.record.state is TransactionState.RECOVERY_FAILED
            reopened_terminal = coordinator._recovery_terminal_failure(
                reopened.get_transaction_projection(
                    tenant_id=work.tenant_id,
                    transaction_id=work.transaction_id,
                )
            )
            assert reopened_terminal is not None
            assert reopened_terminal.evidence_ref == completion.operation_evidence_ref
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_status_rejects_deleted_successful_recovery_completion(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            pass
        work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        assert work.state is RecoveryWorkState.SUCCEEDED
        completion = harness.store.get_recovery_completion_report(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert completion is not None
        assert completion.succeeded

        trigger_row = harness.store._connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
            "AND name = 'enforced_recovery_completion_reports_no_delete'"
        ).fetchone()
        assert trigger_row is not None
        assert trigger_row[0] is not None
        with harness.store._immediate():
            harness.store._execute("DROP TRIGGER enforced_recovery_completion_reports_no_delete")
            harness.store._execute(
                "DELETE FROM enforced_recovery_completion_reports "
                "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ?",
                (work.tenant_id, work.transaction_id, work.recovery_id),
            )
            harness.store._execute(str(trigger_row[0]))

        with pytest.raises(AgentKernelError) as captured:
            harness.coordinator.status(work.tenant_id, work.transaction_id)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_terminal_failure_projection_is_linearizable_across_recovery_completion(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED,
    )
    try:
        session, pending = await _crash_after_recovery_authorized(harness)
        before_completion = harness.store.get_transaction_projection(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
        )
        assert before_completion.recovery_completion_reports == ()
        assert harness.coordinator._recovery_terminal_failure(before_completion) is None

        restarted = support._restart_coordinator(harness)
        completed = await restarted.recover_once(session.record.tenant_id)
        assert completed.processed == 1
        assert completed.statuses[0].record.state is TransactionState.ABORTED

        assert restarted._recovery_terminal_failure(before_completion) is None
        after_completion = harness.store.get_transaction_projection(
            tenant_id=pending.tenant_id,
            transaction_id=pending.transaction_id,
        )
        assert len(after_completion.recovery_completion_reports) == 1
        assert restarted.status(pending.tenant_id, pending.transaction_id).record.state is (
            TransactionState.ABORTED
        )
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_status_rejects_cross_kind_terminal_record_substitution(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    adapter.committed_status = VerificationStatus.FAIL
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            with pytest.raises(AgentKernelError) as failed_commit:
                await session.commit()
            assert failed_commit.value.code is ErrorCode.VERIFICATION_FAILED
        work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        completion = harness.store.get_recovery_completion_report(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert completion is not None
        assert work.kind is RecoveryWorkKind.ROLLBACK
        assert work.permit is not None
        assert work.permit_ref is not None
        assert work.lease_id is not None
        assert work.fencing_token is not None
        substituted = ReconciliationAttemptRecord.model_validate(
            {
                "tenant_id": work.tenant_id,
                "transaction_id": work.transaction_id,
                "intent_hash": work.intent_hash,
                "dispatch_id": work.target_id,
                "recovery_id": work.recovery_id,
                "attempt": work.attempt,
                "lease_id": work.lease_id,
                "fencing_token": work.fencing_token,
                "outcome": ReconciliationOutcome.UNKNOWN,
                "operation_evidence_ref": completion.operation_evidence_ref,
                "operation_reason_code": "RECONCILIATION_QUERY_FAILED",
                "evidence_refs": tuple(
                    sorted(
                        {
                            work.permit_ref,
                            work.target_evidence_ref,
                            completion.operation_evidence_ref,
                        }
                    )
                ),
                "completion_evidence_refs": (completion.operation_evidence_ref,),
                "started_at": work.permit.issued_at,
                "completed_at": work.updated_at,
                "version": 1,
            }
        )
        substituted_started = ReconciliationAttemptRecord.model_validate(
            {
                **substituted.model_dump(mode="python"),
                "outcome": None,
                "operation_evidence_ref": None,
                "operation_reason_code": None,
                "completion_evidence_refs": None,
                "completed_at": None,
                "version": 0,
            }
        )
        trigger_row = harness.store._connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
            "AND name = 'enforced_recovery_completion_reports_no_delete'"
        ).fetchone()
        assert trigger_row is not None
        assert trigger_row[0] is not None
        with harness.store._immediate():
            harness.store._execute("DROP TRIGGER enforced_recovery_completion_reports_no_delete")
            harness.store._execute(
                "DELETE FROM enforced_recovery_completion_reports "
                "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ?",
                (work.tenant_id, work.transaction_id, work.recovery_id),
            )
            harness.store._insert_reconciliation_attempt_tx(substituted_started)
            harness.store._update_reconciliation_attempt_tx(
                substituted_started,
                substituted,
            )
            harness.store._execute(str(trigger_row[0]))

        with pytest.raises(AgentKernelError) as captured:
            harness.coordinator.status(work.tenant_id, work.transaction_id)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_status_revalidates_successful_recovery_operation_artifact(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            pass
        work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        completion = harness.store.get_recovery_completion_report(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert completion is not None
        assert completion.succeeded

        support._artifact_path(
            harness.artifacts.root,
            completion.operation_evidence_ref,
        ).write_bytes(b"tampered-successful-recovery-operation")

        with pytest.raises(AgentKernelError) as captured:
            harness.coordinator.status(work.tenant_id, work.transaction_id)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_status_revalidates_successful_reconciliation_operation_artifact(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    adapter.committed_status = VerificationStatus.PASS
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        resumed = await restarted.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert resumed.record.state is TransactionState.COMMITTED
        attempt = harness.store.list_reconciliation_attempts(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        assert attempt.operation_evidence_ref is not None

        support._artifact_path(
            harness.artifacts.root,
            attempt.operation_evidence_ref,
        ).write_bytes(b"tampered-successful-reconciliation-operation")

        with pytest.raises(AgentKernelError) as captured:
            restarted.status(session.record.tenant_id, session.record.transaction_id)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_status_revalidates_committed_effect_receipt_artifact(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(tmp_path)
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            committed = await session.commit()
        assert committed.state is TransactionState.COMMITTED
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert dispatch.effect_receipt_ref is not None
        assert (
            harness.coordinator.status(dispatch.tenant_id, dispatch.transaction_id).record.state
            is TransactionState.COMMITTED
        )

        support._artifact_path(
            harness.artifacts.root,
            dispatch.effect_receipt_ref,
        ).write_bytes(b"tampered-committed-effect-receipt")
        with pytest.raises(AgentKernelError) as rejected:
            harness.coordinator.status(dispatch.tenant_id, dispatch.transaction_id)
        assert rejected.value.code is ErrorCode.INTEGRITY_ERROR

        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            harness.store = reopened
            with pytest.raises(AgentKernelError) as reopened_rejected:
                _clone_coordinator(harness, store=reopened).status(
                    dispatch.tenant_id,
                    dispatch.transaction_id,
                )
            assert reopened_rejected.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_reconciliation_replay_rejects_foreign_receipt_identity(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_CALL,
    )
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        resumed = await restarted.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert resumed.record.state is TransactionState.COMMITTED
        attempt = harness.store.list_reconciliation_attempts(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        work = harness.store.get_recovery_work(
            tenant_id=attempt.tenant_id,
            transaction_id=attempt.transaction_id,
            recovery_id=attempt.recovery_id,
        )
        assert attempt.completion_evidence_refs is not None
        reports: list[tuple[str, ReconcileReport]] = []
        for artifact_ref in attempt.completion_evidence_refs:
            try:
                report = ReconcileReport.model_validate_json(harness.artifacts.get(artifact_ref))
            except ValueError:
                continue
            reports.append((artifact_ref, report))
        assert len(reports) == 1
        original_report_ref, original_report = reports[0]
        assert original_report.receipt is not None
        original_receipt_ref = canonical_digest(original_report.receipt)
        foreign_receipt = original_report.receipt.model_copy(
            update={"intent_hash": canonical_digest("foreign-reconciliation-intent")}
        )
        foreign_receipt_ref = harness.artifacts.put_model(foreign_receipt).digest
        foreign_report = original_report.model_copy(update={"receipt": foreign_receipt})
        foreign_report_ref = harness.artifacts.put_model(foreign_report).digest

        def replace_receipt_closure(values: tuple[str, ...]) -> tuple[str, ...]:
            return tuple(
                sorted(
                    {
                        *(
                            ref
                            for ref in values
                            if ref not in {original_report_ref, original_receipt_ref}
                        ),
                        foreign_report_ref,
                        foreign_receipt_ref,
                    }
                )
            )

        forged = ReconciliationAttemptRecord.model_validate(
            {
                **attempt.model_dump(mode="python"),
                "effect_receipt_ref": foreign_receipt_ref,
                "evidence_refs": replace_receipt_closure(attempt.evidence_refs),
                "completion_evidence_refs": replace_receipt_closure(
                    attempt.completion_evidence_refs
                ),
            }
        )
        with pytest.raises(AgentKernelError) as rejected:
            restarted._validate_reconciliation_attempt_operation_evidence(
                work,
                forged,
            )
        assert rejected.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("tampered_artifact", ["historical-permit", "expiry-operation"])
async def test_status_revalidates_reclaimed_historical_reconciliation_artifacts(
    tmp_path: Path,
    tampered_artifact: str,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        running, _started, _dispatch = await _crash_after_reconciliation_started(
            harness,
            session,
        )
        assert running.permit is not None
        assert running.permit_ref is not None
        assert running.lease_id is not None
        assert running.worker_id is not None
        harness.clock.advance(timedelta(minutes=1, microseconds=1))
        acquired_at = harness.clock()
        authorization_round = harness.store.get_authorization_round(
            tenant_id=running.tenant_id,
            controlled_transaction_id=running.transaction_id,
            round_id=running.authorization_round_id,
        )
        assert authorization_round.authority_valid_until is not None
        expires_at = min(
            running.deadline,
            authorization_round.authority_valid_until,
            acquired_at + timedelta(seconds=30),
        )
        preview = harness.store.preview_recovery_reclaim(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            recovery_id=running.recovery_id,
            expected_work_version=running.version,
            lease_id="lease:reconciliation:historical:replacement",
            worker_id="worker:reconciliation:historical:replacement",
            acquired_at=acquired_at,
            expires_at=expires_at,
        )
        reclaimer = support._restart_coordinator(
            harness,
            worker_id="worker:reconciliation:historical:replacement",
        )
        replacement_permit_ref = reclaimer._put_model(preview.permit)
        assert replacement_permit_ref == preview.permit_ref
        operation_ref = reclaimer._put_control_evidence(
            transaction_id=running.transaction_id,
            event="reconciliation.query_failed",
            reason_code="RECOVERY_LEASE_EXPIRED",
            recorded_at=acquired_at,
            subject_ref=running.permit_ref,
        )
        evidence_refs = tuple(
            sorted(
                {
                    running.permit_ref,
                    replacement_permit_ref,
                    operation_ref,
                }
            )
        )
        reclaimed = harness.store.reclaim_expired_recovery(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            recovery_id=running.recovery_id,
            expected_work_version=running.version,
            lease_id=preview.lease.lease_id,
            worker_id=preview.lease.worker_id,
            acquired_at=preview.lease.acquired_at,
            expires_at=preview.lease.expires_at,
            permit=preview.permit,
            permit_ref=preview.permit_ref,
            evidence_refs=evidence_refs,
            operation_evidence_ref=operation_ref,
            operation_reason_code="RECOVERY_LEASE_EXPIRED",
        )
        assert reclaimed.work.attempt == running.attempt + 1
        historical_attempt = harness.store.get_reconciliation_attempt(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            recovery_id=running.recovery_id,
            attempt=running.attempt,
        )
        legacy_historical_attempt = ReconciliationAttemptRecord.model_validate(
            {
                **historical_attempt.model_dump(
                    mode="python",
                    exclude={
                        "schema_version",
                        "operation_evidence_ref",
                        "operation_reason_code",
                    },
                ),
                "schema_version": "1.0",
            }
        )
        legacy_permit, legacy_permit_ref = reclaimer._historical_reconciliation_permit(
            reclaimed.work,
            legacy_historical_attempt,
        )
        reclaimer._validate_reconciliation_attempt_operation_evidence(
            reclaimed.work,
            legacy_historical_attempt,
            historical_permit=legacy_permit,
            historical_permit_ref=legacy_permit_ref,
        )
        assert (
            reclaimer.status(running.tenant_id, running.transaction_id).record.state
            is TransactionState.IN_DOUBT
        )

        corrupted_ref = (
            running.permit_ref if tampered_artifact == "historical-permit" else operation_ref
        )
        support._artifact_path(harness.artifacts.root, corrupted_ref).write_bytes(
            b"tampered-historical-reconciliation-artifact"
        )
        with pytest.raises(AgentKernelError) as rejected:
            reclaimer.status(running.tenant_id, running.transaction_id)
        assert rejected.value.code is ErrorCode.INTEGRITY_ERROR

        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            harness.store = reopened
            with pytest.raises(AgentKernelError) as reopened_rejected:
                _clone_coordinator(harness, store=reopened).status(
                    running.tenant_id,
                    running.transaction_id,
                )
            assert reopened_rejected.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_published_v6_completed_reconciliation_derives_unique_operation_evidence(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    adapter.committed_status = VerificationStatus.PASS
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        resumed = await restarted.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert resumed.record.state is TransactionState.COMMITTED
        attempt = harness.store.list_reconciliation_attempts(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        work = harness.store.get_recovery_work(
            tenant_id=attempt.tenant_id,
            transaction_id=attempt.transaction_id,
            recovery_id=attempt.recovery_id,
        )
        legacy = ReconciliationAttemptRecord.model_validate(
            {
                **attempt.model_dump(
                    mode="python",
                    exclude={
                        "schema_version",
                        "operation_evidence_ref",
                        "operation_reason_code",
                    },
                ),
                "schema_version": "1.0",
            }
        )
        attempt_digest = canonical_digest(attempt.canonical_record_json())
        legacy_digest = canonical_digest(legacy.canonical_record_json())
        assert attempt_digest in work.evidence_refs
        rewritten_work = type(work).model_validate(
            {
                **work.model_dump(mode="python"),
                "evidence_refs": tuple(
                    sorted(
                        {
                            *(ref for ref in work.evidence_refs if ref != attempt_digest),
                            legacy_digest,
                        }
                    )
                ),
            }
        )
        trigger_row = harness.store._connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
            "AND name = 'enforced_reconciliation_operation_evidence_valid_update'"
        ).fetchone()
        assert trigger_row is not None
        assert trigger_row[0] is not None
        with harness.store._immediate():
            harness.store._execute(
                "DROP TRIGGER enforced_reconciliation_operation_evidence_valid_update"
            )
            harness.store._execute(
                "UPDATE enforced_reconciliation_attempts SET operation_evidence_ref = NULL, "
                "operation_reason_code = NULL, record_digest = ?, record_json = ? "
                "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
                "AND attempt = ?",
                (
                    canonical_digest(legacy.canonical_record_json()),
                    canonical_json_text(legacy.canonical_record_json()),
                    legacy.tenant_id,
                    legacy.transaction_id,
                    legacy.recovery_id,
                    legacy.attempt,
                ),
            )
            harness.store._execute(
                "UPDATE enforced_recovery_work SET evidence_refs_json = ?, "
                "record_digest = ?, record_json = ? WHERE tenant_id = ? "
                "AND transaction_id = ? AND recovery_id = ?",
                (
                    canonical_json_text(rewritten_work.evidence_refs),
                    canonical_digest(rewritten_work),
                    canonical_json_text(rewritten_work),
                    rewritten_work.tenant_id,
                    rewritten_work.transaction_id,
                    rewritten_work.recovery_id,
                ),
            )
            _rewrite_test_intent_head_evidence(
                harness.store,
                tenant_id=rewritten_work.tenant_id,
                intent_hash=rewritten_work.recovery_action_intent_hash,
                transaction_id=rewritten_work.recovery_action_transaction_id,
                evidence_digest=canonical_digest(rewritten_work),
            )
            harness.store._execute(str(trigger_row[0]))

        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            harness.store = reopened
            reopened_attempt = reopened.get_reconciliation_attempt(
                tenant_id=legacy.tenant_id,
                transaction_id=legacy.transaction_id,
                recovery_id=legacy.recovery_id,
                attempt=legacy.attempt,
            )
            assert reopened_attempt.schema_version == "1.0"
            assert reopened_attempt.operation_evidence_ref is None
            reopened_status = _clone_coordinator(harness, store=reopened).status(
                legacy.tenant_id,
                legacy.transaction_id,
            )
            assert reopened_status.record.state is TransactionState.COMMITTED
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_legacy_reconciliation_rejects_ambiguous_operation_evidence(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._ControlledVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._ControlledVerificationAdapter)
    adapter.committed_status = VerificationStatus.PASS
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        await restarted.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        attempt = harness.store.list_reconciliation_attempts(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        work = harness.store.get_recovery_work(
            tenant_id=attempt.tenant_id,
            transaction_id=attempt.transaction_id,
            recovery_id=attempt.recovery_id,
        )
        assert attempt.completed_at is not None
        assert work.permit_ref is not None
        first_control = restarted._put_control_evidence(
            transaction_id=work.transaction_id,
            event="reconciliation.query_failed",
            reason_code=ErrorCode.VALIDATION_ERROR.value,
            recorded_at=attempt.completed_at,
            subject_ref=work.permit_ref,
        )
        second_control = restarted._put_control_evidence(
            transaction_id=work.transaction_id,
            event="reconciliation.query_failed",
            reason_code=ErrorCode.INTEGRITY_ERROR.value,
            recorded_at=attempt.completed_at,
            subject_ref=work.permit_ref,
        )
        assert attempt.completion_evidence_refs is not None
        legacy = ReconciliationAttemptRecord.model_validate(
            {
                **attempt.model_dump(
                    mode="python",
                    exclude={
                        "schema_version",
                        "operation_evidence_ref",
                        "operation_reason_code",
                    },
                ),
                "schema_version": "1.0",
                "evidence_refs": tuple(
                    sorted({*attempt.evidence_refs, first_control, second_control})
                ),
                "completion_evidence_refs": tuple(
                    sorted(
                        {
                            *attempt.completion_evidence_refs,
                            first_control,
                            second_control,
                        }
                    )
                ),
            }
        )
        with pytest.raises(AgentKernelError) as ambiguous:
            restarted._derive_legacy_reconciliation_operation_evidence_ref(
                work,
                legacy,
                permit_ref=work.permit_ref,
            )
        assert ambiguous.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_reconciliation_verification_after_deadline_is_review_required(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_LateReconciliationVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_CALL,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _LateReconciliationVerificationAdapter)
    adapter.test_clock = harness.clock
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        resumed = await restarted.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        works = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert works[0].state is RecoveryWorkState.REVIEW_REQUIRED
        assert resumed.record.state is TransactionState.IN_DOUBT
        assert harness.target.state["answer"] == "42"
        assert adapter.rollback_calls == 0
        report = harness.store.get_late_recovery_report(
            tenant_id=works[0].tenant_id,
            transaction_id=works[0].transaction_id,
            recovery_id=works[0].recovery_id,
        )
        assert report is not None
        assert report.operation_reason_code is None
        observation = harness.artifacts.get_model(
            report.operation_evidence_ref,
            AdapterObservation,
        )
        assert observation.evidence_kind == "committed_verification"
        attempts = harness.store.list_reconciliation_attempts(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(attempts) == 1
        assert attempts[0].operation_evidence_ref == report.operation_evidence_ref
        assert attempts[0].operation_reason_code is None
        failures, checkpoint = restarted._audit_tenant_recovery_handoff_evidence(
            session.record.tenant_id,
            observed_at=harness.clock(),
            force=True,
        )
        assert not failures
        assert checkpoint.current_cycle_complete

        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            harness.store = reopened
            coordinator = _clone_coordinator(harness, store=reopened)
            reopened_attempt = reopened.get_reconciliation_attempt(
                tenant_id=attempts[0].tenant_id,
                transaction_id=attempts[0].transaction_id,
                recovery_id=attempts[0].recovery_id,
                attempt=attempts[0].attempt,
            )
            assert reopened_attempt == attempts[0]
            reopened_status = coordinator.status(
                session.record.tenant_id,
                session.record.transaction_id,
            )
            assert reopened_status.record.state is TransactionState.IN_DOUBT
            reopened_failures, reopened_checkpoint = (
                coordinator._audit_tenant_recovery_handoff_evidence(
                    session.record.tenant_id,
                    observed_at=harness.clock(),
                    force=True,
                )
            )
            assert not reopened_failures
            assert reopened_checkpoint.current_cycle_complete
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter_type", "expected_work_state"),
    [
        (_ForeignReconciliationReceiptAdapter, RecoveryWorkState.RETRY_SCHEDULED),
        (_LateForeignReconciliationReceiptAdapter, RecoveryWorkState.REVIEW_REQUIRED),
    ],
    ids=("before-deadline", "after-deadline"),
)
async def test_foreign_reconciliation_receipt_is_never_accepted(
    tmp_path: Path,
    adapter_type: type[_ForeignReconciliationReceiptAdapter],
    expected_work_state: RecoveryWorkState,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=adapter_type,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_CALL,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _ForeignReconciliationReceiptAdapter)
    if isinstance(adapter, _LateForeignReconciliationReceiptAdapter):
        adapter.test_clock = harness.clock
    try:
        session = await _crash_during_commit(harness)
        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        with pytest.raises(AgentKernelError) as rejected:
            await restarted.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert rejected.value.code is ErrorCode.INTEGRITY_ERROR
        assert adapter.foreign_receipt is not None
        foreign_receipt_ref = canonical_digest(adapter.foreign_receipt)

        work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
            attempt=work.attempt,
        )
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
        )
        assert work.state is expected_work_state
        assert attempt.outcome is ReconciliationOutcome.UNKNOWN
        assert attempt.effect_receipt_ref is None
        assert attempt.operation_reason_code == ErrorCode.INTEGRITY_ERROR.value
        assert foreign_receipt_ref in attempt.evidence_refs
        assert dispatch.effect_receipt_ref is None
        assert (
            restarted.status(work.tenant_id, work.transaction_id).record.state
            is TransactionState.IN_DOUBT
        )

        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            harness.store = reopened
            assert (
                _clone_coordinator(harness, store=reopened)
                .status(work.tenant_id, work.transaction_id)
                .record.state
                is TransactionState.IN_DOUBT
            )
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_late_invalid_provider_report_uses_control_fallback_across_audit_and_reopen(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_LateInvalidRecoveryReportAdapter,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _LateInvalidRecoveryReportAdapter)
    adapter.test_clock = harness.clock
    try:
        session = await harness.coordinator.transaction(harness.request)
        async with session:
            pass

        record = harness.store.get_enforced_transaction(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        work = harness.store.list_recovery_work(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )[0]
        report = harness.store.get_late_recovery_report(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert report is not None
        assert adapter.rejected_report_ref is not None
        assert adapter.rejected_report_ref in report.evidence_refs
        assert report.operation_evidence_ref != adapter.rejected_report_ref
        control = harness.artifacts.get_model(
            report.operation_evidence_ref,
            CoordinatorEvidence,
        )
        assert control.event == "recovery.execution_failed"
        assert report.operation_reason_code == control.reason_code
        assert harness.coordinator.status(record.tenant_id, record.transaction_id).record == record
        failures, checkpoint = harness.coordinator._audit_tenant_recovery_handoff_evidence(
            record.tenant_id,
            observed_at=harness.clock(),
            force=True,
        )
        assert not failures
        assert checkpoint.current_cycle_complete

        legacy = LateRecoveryReportRecord.create(
            **report.model_dump(
                mode="python",
                exclude={
                    "schema_version",
                    "operation_reason_code",
                    "report_digest",
                },
            ),
            schema_version="1.0",
        )
        trigger_rows = harness.store._connection.execute(
            "SELECT name, sql FROM sqlite_schema WHERE type = 'trigger' "
            "AND name = 'enforced_late_recovery_reports_no_update'"
        ).fetchall()
        assert len(trigger_rows) == 1
        assert all(row[1] is not None for row in trigger_rows)
        with harness.store._immediate():
            for trigger_row in trigger_rows:
                harness.store._execute(f"DROP TRIGGER {trigger_row[0]}")
            harness.store._execute(
                "UPDATE enforced_late_recovery_reports SET operation_reason_code = NULL, "
                "report_digest = ?, report_json = ? WHERE tenant_id = ? "
                "AND transaction_id = ? AND recovery_id = ?",
                (
                    legacy.report_digest,
                    canonical_json_text(
                        legacy.model_dump(
                            mode="python",
                            exclude={"operation_reason_code"},
                        )
                    ),
                    legacy.tenant_id,
                    legacy.transaction_id,
                    legacy.recovery_id,
                ),
            )
            for trigger_row in trigger_rows:
                harness.store._execute(str(trigger_row[1]))
        migrated_legacy = harness.store.get_late_recovery_report(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert migrated_legacy is not None
        assert migrated_legacy.schema_version == "1.0"
        assert migrated_legacy.operation_reason_code is None
        assert harness.coordinator.status(record.tenant_id, record.transaction_id).record == record

        harness.store.close()
        with SQLiteEnforcedTransactionStore(tmp_path / "control.db") as reopened:
            harness.store = reopened
            coordinator = _clone_coordinator(harness, store=reopened)
            assert coordinator.status(record.tenant_id, record.transaction_id).record == record
            reopened_failures, reopened_checkpoint = (
                coordinator._audit_tenant_recovery_handoff_evidence(
                    record.tenant_id,
                    observed_at=harness.clock(),
                    force=True,
                )
            )
            assert not reopened_failures
            assert reopened_checkpoint.current_cycle_complete
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_late_report_status_audit_is_bounded_with_ten_thousand_history_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_LateReconciliationVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _LateReconciliationVerificationAdapter)
    adapter.test_clock = harness.clock
    try:
        session = await _crash_during_commit(harness)
        coordinator = await _stop_dispatch_before_explicit_resume(harness, session)
        await coordinator.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        expected_report = harness.store.get_late_recovery_report(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert expected_report is not None
        assert expected_report.operation_reason_code is None

        decoy_intent_hash = canonical_digest({"bounded_late_audit": "decoy-intent"})
        decoy_transaction_id = "transaction:bounded-late-audit-decoy"
        previous_digest: str | None = None
        rows: list[tuple[object, ...]] = []
        for sequence in range(10_000):
            history_digest = canonical_digest(
                {
                    "bounded_late_audit_history": sequence,
                    "previous": previous_digest,
                }
            )
            rows.append(
                (
                    session.record.tenant_id,
                    decoy_intent_hash,
                    sequence,
                    decoy_transaction_id,
                    "STATE_CHANGED",
                    None,
                    "REVIEW_REQUIRED",
                    decoy_transaction_id,
                    0,
                    None,
                    previous_digest,
                    history_digest,
                    work.updated_at.isoformat().replace("+00:00", "Z"),
                )
            )
            previous_digest = history_digest
        assert harness.store._connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        harness.store._connection.execute("PRAGMA foreign_keys = OFF")
        try:
            with harness.store._immediate():
                harness.store._connection.executemany(
                    "INSERT INTO enforced_intent_attempt_history(tenant_id, intent_hash, "
                    "sequence, transaction_id, event_type, disposition, attempt_state, "
                    "owner_transaction_id, owner_version, evidence_digest, "
                    "previous_history_digest, history_digest, recorded_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    rows,
                )
        finally:
            harness.store._connection.execute("PRAGMA foreign_keys = ON")
        assert harness.store._connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1

        def fail_unbounded_path(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("late evidence audit traversed an unbounded exact-retry path")

        monkeypatch.setattr(
            harness.store,
            "_validate_intent_ledger",
            fail_unbounded_path,
        )
        monkeypatch.setattr(
            harness.store,
            "_assert_late_recovery_retry_tx",
            fail_unbounded_path,
        )
        monkeypatch.setattr(
            harness.store,
            "_assert_target_capability_settlement_tx",
            fail_unbounded_path,
        )
        getter_traced: list[str] = []
        harness.store._connection.set_trace_callback(getter_traced.append)
        try:
            observed_report = harness.store.get_late_recovery_report(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
                recovery_id=work.recovery_id,
            )
        finally:
            harness.store._connection.set_trace_callback(None)
        audit_traced: list[str] = []
        harness.store._connection.set_trace_callback(audit_traced.append)
        try:
            failures, checkpoint = coordinator._audit_tenant_recovery_handoff_evidence(
                work.tenant_id,
                observed_at=harness.clock(),
                force=True,
            )
        finally:
            harness.store._connection.set_trace_callback(None)
        assert observed_report == expected_report
        assert not failures
        assert checkpoint.current_cycle_complete
        getter_selects = [
            statement for statement in getter_traced if statement.lstrip().startswith("SELECT")
        ]
        audit_selects = [
            statement for statement in audit_traced if statement.lstrip().startswith("SELECT")
        ]
        assert len(getter_selects) <= 20
        assert len(audit_selects) <= 200
        assert not any(
            "enforced_intent_attempt_history" in statement for statement in getter_selects
        )
        history_queries = [
            statement
            for statement in audit_selects
            if "enforced_intent_attempt_history" in statement
        ]
        assert history_queries
        assert all(
            " LIMIT " in statement or " sequence = " in statement for statement in history_queries
        )
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    [
        "terminal-work-digest",
        "completion-conflict",
        "adapter-operation-reason",
        "event-subject-cross-pair",
        "inner-reason",
    ],
)
async def test_late_recovery_evidence_audit_rejects_coherent_association_tamper(
    tmp_path: Path,
    tamper: str,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_LateReconciliationVerificationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _LateReconciliationVerificationAdapter)
    adapter.test_clock = harness.clock
    try:
        session = await _crash_during_commit(harness)
        coordinator = await _stop_dispatch_before_explicit_resume(harness, session)
        await coordinator.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        work = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        report = harness.store.get_late_recovery_report(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert report is not None
        handoff = harness.store.get_recovery_action_handoff(
            tenant_id=work.tenant_id,
            target_transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert handoff is not None
        if tamper == "terminal-work-digest":
            forged = type(report).create(
                **report.model_dump(
                    mode="python",
                    exclude={"report_digest", "terminal_work_digest"},
                ),
                terminal_work_digest=canonical_digest({"forged": "late-terminal-work"}),
            )
            trigger_row = harness.store._connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
                "AND name = 'enforced_late_recovery_reports_no_update'"
            ).fetchone()
            assert trigger_row is not None
            assert trigger_row[0] is not None
            with harness.store._immediate():
                harness.store._execute("DROP TRIGGER enforced_late_recovery_reports_no_update")
                harness.store._execute(
                    "UPDATE enforced_late_recovery_reports SET terminal_work_digest = ?, "
                    "report_digest = ?, report_json = ? WHERE tenant_id = ? "
                    "AND transaction_id = ? AND recovery_id = ?",
                    (
                        forged.terminal_work_digest,
                        forged.report_digest,
                        canonical_json_text(forged),
                        forged.tenant_id,
                        forged.transaction_id,
                        forged.recovery_id,
                    ),
                )
                harness.store._execute(str(trigger_row[0]))
            with pytest.raises(AgentKernelError) as captured:
                harness.store.get_late_recovery_report(
                    tenant_id=work.tenant_id,
                    transaction_id=work.transaction_id,
                    recovery_id=work.recovery_id,
                )
        elif tamper == "completion-conflict":
            completion = RecoveryCompletionReportRecord.create(
                tenant_id=work.tenant_id,
                transaction_id=work.transaction_id,
                recovery_id=work.recovery_id,
                succeeded=False,
                operation_evidence_ref=report.operation_evidence_ref,
                evidence_refs=report.evidence_refs,
                completed_at=report.reported_at,
                reason_code=report.reason_code,
                terminal_work_digest=canonical_digest(work),
            )
            with harness.store._immediate():
                harness.store._insert_recovery_completion_report_tx(completion)
            with pytest.raises(AgentKernelError) as captured:
                harness.store.get_late_recovery_report(
                    tenant_id=work.tenant_id,
                    transaction_id=work.transaction_id,
                    recovery_id=work.recovery_id,
                )
        elif tamper == "adapter-operation-reason":
            forged = type(report).create(
                **report.model_dump(
                    mode="python",
                    exclude={"report_digest", "operation_reason_code"},
                ),
                operation_reason_code="FORGED_CONTROL_REASON",
            )
            trigger_row = harness.store._connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
                "AND name = 'enforced_late_recovery_reports_no_update'"
            ).fetchone()
            assert trigger_row is not None
            assert trigger_row[0] is not None
            with harness.store._immediate():
                harness.store._execute("DROP TRIGGER enforced_late_recovery_reports_no_update")
                harness.store._execute(
                    "UPDATE enforced_late_recovery_reports SET operation_reason_code = ?, "
                    "report_digest = ?, report_json = ? WHERE tenant_id = ? "
                    "AND transaction_id = ? AND recovery_id = ?",
                    (
                        forged.operation_reason_code,
                        forged.report_digest,
                        canonical_json_text(forged),
                        forged.tenant_id,
                        forged.transaction_id,
                        forged.recovery_id,
                    ),
                )
                harness.store._execute(str(trigger_row[0]))
            with pytest.raises(AgentKernelError) as captured:
                harness.store.get_late_recovery_report(
                    tenant_id=work.tenant_id,
                    transaction_id=work.transaction_id,
                    recovery_id=work.recovery_id,
                )
            with pytest.raises(AgentKernelError):
                coordinator.status(work.tenant_id, work.transaction_id)

            harness.store.close()
            with pytest.raises(AgentKernelError) as reopened_captured:
                SQLiteEnforcedTransactionStore(tmp_path / "control.db")
            assert reopened_captured.value.code is ErrorCode.INTEGRITY_ERROR
        else:
            assert work.permit_ref is not None
            cross_evidence = CoordinatorEvidence(
                transaction_id=work.transaction_id,
                event=(
                    "reconciliation.query_failed"
                    if tamper == "inner-reason"
                    else "recovery.authorization_handoff_failed"
                ),
                reason_code=(
                    "ARBITRARY_UNBOUND_INNER_REASON"
                    if tamper == "inner-reason"
                    else report.reason_code
                ),
                recorded_at=report.reported_at,
                subject_ref=work.permit_ref,
            )
            cross_ref = harness.artifacts.put_model(cross_evidence).digest
            forged = type(report).create(
                **report.model_dump(
                    mode="python",
                    exclude={
                        "report_digest",
                        "operation_evidence_ref",
                        "operation_reason_code",
                        "evidence_refs",
                    },
                ),
                operation_evidence_ref=cross_ref,
                operation_reason_code=cross_evidence.reason_code,
                evidence_refs=(cross_ref,),
            )
            with pytest.raises(AgentKernelError) as captured:
                coordinator._validate_late_recovery_handoff_evidence(
                    handoff,
                    evidence_ref=cross_ref,
                    late_report=forged,
                )
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_cancel_after_durable_dispatch_reports_in_doubt_then_reconciles(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    try:
        session = await _crash_during_commit(harness)
        with pytest.raises(AgentKernelError) as captured:
            await session.cancel()
        assert captured.value.code is ErrorCode.EXTERNAL_RESULT_IN_DOUBT

        restarted = await _stop_dispatch_before_explicit_resume(harness, session)
        resumed = await restarted.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert resumed.record.state is TransactionState.ABORTED
        assert harness.target.state == {"before": "kept"}
    finally:
        harness.store.close()


def _reserve_released_typed_reconciliation_prework(
    harness: support._Harness,
    coordinator: EnforcedTransactionCoordinator,
    *,
    tenant_id: str,
    transaction_id: str,
    lease_id: str,
    worker_id: str,
) -> tuple[
    EnforcedTransactionRecord,
    CommitDispatchRecord,
    RecoveryActionHandoff,
    WorkerLeaseRecord,
]:
    record = harness.store.get_enforced_transaction(
        tenant_id=tenant_id,
        transaction_id=transaction_id,
    )
    dispatch = harness.store.get_commit_dispatch(
        tenant_id=record.tenant_id,
        transaction_id=record.transaction_id,
    )
    observed_at = harness.clock()
    binding = coordinator._propose_recovery_action_binding(
        record,
        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        target=dispatch,
        target_ref=canonical_digest(dispatch),
        observed_at=observed_at,
        predecessor=None,
    )
    claimed = harness.store.acquire_recovery_authorization_lease(
        tenant_id=record.tenant_id,
        transaction_id=record.transaction_id,
        expected_transaction_version=record.version,
        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        dispatch_id=dispatch.dispatch_id,
        dispatch_target_ref=canonical_digest(dispatch),
        recovery_id=binding.recovery_id,
        lease_id=lease_id,
        worker_id=worker_id,
        acquired_at=observed_at,
        expires_at=min(
            binding.absolute_deadline,
            observed_at + coordinator._config.lease_duration,
        ),
        binding=binding,
    )
    harness.store.release_worker_lease(
        tenant_id=record.tenant_id,
        transaction_id=record.transaction_id,
        lease_id=claimed.lease.lease_id,
        expected_version=claimed.lease.version,
        released_at=observed_at,
    )
    handoff = harness.store.get_recovery_action_handoff(
        tenant_id=record.tenant_id,
        target_transaction_id=record.transaction_id,
        recovery_id=binding.recovery_id,
    )
    assert handoff is not None
    return record, dispatch, handoff, claimed.lease


@pytest.mark.asyncio
async def test_root_prework_rejects_forged_deadline_and_attempt_bound(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        session = await _crash_during_commit(harness)
        coordinator = await _stop_dispatch_before_explicit_resume(harness, session)
        record = harness.store.get_enforced_transaction(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        dispatch = harness.store.get_commit_dispatch(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        observed_at = harness.clock()
        valid_binding = coordinator._propose_recovery_action_binding(
            record,
            kind=RecoveryWorkKind.RECONCILE_DISPATCH,
            target=dispatch,
            target_ref=canonical_digest(dispatch),
            observed_at=observed_at,
            predecessor=None,
        )
        forged_bindings = (
            RecoveryActionBinding.model_validate(
                {
                    **valid_binding.model_dump(mode="python"),
                    "absolute_deadline": valid_binding.absolute_deadline + timedelta(minutes=5),
                }
            ),
            RecoveryActionBinding.model_validate(
                {
                    **valid_binding.model_dump(mode="python"),
                    "max_recovery_attempts": 100,
                }
            ),
        )
        for index, forged_binding in enumerate(forged_bindings):
            lease_id = f"lease:forged-root-bound:{index}"
            with pytest.raises(AgentKernelError) as rejected:
                harness.store.acquire_recovery_authorization_lease(
                    tenant_id=record.tenant_id,
                    transaction_id=record.transaction_id,
                    expected_transaction_version=record.version,
                    kind=RecoveryWorkKind.RECONCILE_DISPATCH,
                    dispatch_id=dispatch.dispatch_id,
                    dispatch_target_ref=canonical_digest(dispatch),
                    recovery_id=valid_binding.recovery_id,
                    lease_id=lease_id,
                    worker_id=f"worker:forged-root-bound:{index}",
                    acquired_at=observed_at,
                    expires_at=observed_at + timedelta(minutes=1),
                    binding=forged_binding,
                )
            assert rejected.value.code is ErrorCode.VERSION_CONFLICT
            assert not rejected.value.retryable
            with pytest.raises(AgentKernelError) as absent_lease:
                harness.store.get_worker_lease(
                    tenant_id=record.tenant_id,
                    transaction_id=record.transaction_id,
                    lease_id=lease_id,
                )
            assert absent_lease.value.code is ErrorCode.VALIDATION_ERROR
            assert (
                harness.store.get_recovery_action_handoff(
                    tenant_id=record.tenant_id,
                    target_transaction_id=record.transaction_id,
                    recovery_id=valid_binding.recovery_id,
                )
                is None
            )

        valid_claim = harness.store.acquire_recovery_authorization_lease(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
            expected_transaction_version=record.version,
            kind=RecoveryWorkKind.RECONCILE_DISPATCH,
            dispatch_id=dispatch.dispatch_id,
            dispatch_target_ref=canonical_digest(dispatch),
            recovery_id=valid_binding.recovery_id,
            lease_id="lease:valid-root-bound",
            worker_id="worker:valid-root-bound",
            acquired_at=observed_at,
            expires_at=observed_at + timedelta(minutes=1),
            binding=valid_binding,
        )
        harness.store.release_worker_lease(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
            lease_id=valid_claim.lease.lease_id,
            expected_version=valid_claim.lease.version,
            released_at=observed_at,
        )
        trigger_row = harness.store._connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
            "AND name = 'enforced_recovery_action_handoffs_valid_update'"
        ).fetchone()
        assert trigger_row is not None
        assert trigger_row[0] is not None

        def tamper_persisted_binding(binding: RecoveryActionBinding) -> None:
            with harness.store._immediate():
                harness.store._execute(
                    "DROP TRIGGER enforced_recovery_action_handoffs_valid_update"
                )
                harness.store._execute(
                    "UPDATE enforced_recovery_action_handoffs "
                    "SET binding_ref = ?, binding_json = ? "
                    "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
                    (
                        canonical_digest(binding),
                        canonical_json_text(binding),
                        record.tenant_id,
                        record.transaction_id,
                        valid_binding.recovery_id,
                    ),
                )
                harness.store._execute(str(trigger_row[0]))

        coordinator_mismatch_binding = RecoveryActionBinding.model_validate(
            {
                **valid_binding.model_dump(mode="python"),
                "max_recovery_attempts": valid_binding.max_recovery_attempts + 1,
            }
        )
        assert coordinator_mismatch_binding.max_recovery_attempts <= 32
        tamper_persisted_binding(coordinator_mismatch_binding)

        with pytest.raises(AgentKernelError) as semantic_rejection:
            await coordinator.resume_dispatch_reconciliation(
                record.tenant_id,
                record.transaction_id,
            )
        assert semantic_rejection.value.code is ErrorCode.INTEGRITY_ERROR
        assert str(semantic_rejection.value) == (
            "Registered recovery handoff changed its durable deadline or attempt bound"
        )
        assert recovery_actions.create_calls == adapter.reconcile_calls == 0

        deadline_mismatch_binding = RecoveryActionBinding.model_validate(
            {
                **valid_binding.model_dump(mode="python"),
                "absolute_deadline": valid_binding.absolute_deadline + timedelta(minutes=5),
            }
        )
        tamper_persisted_binding(deadline_mismatch_binding)
        harness.store.close()
        with pytest.raises(AgentKernelError) as reopen_rejection:
            SQLiteEnforcedTransactionStore(database_path)
        assert reopen_rejection.value.code is ErrorCode.INTEGRITY_ERROR
        assert recovery_actions.create_calls == adapter.reconcile_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_typed_reconciliation_unattached_prework_resumes_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    original_acquire = harness.store.acquire_recovery_authorization_lease
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        outage = _TogglePutOutageArtifacts(harness.artifacts)
        coordinator = _clone_coordinator(
            harness,
            artifacts=outage,
            recovery_actions=recovery_actions,
        )
        captured_leases: list[WorkerLeaseRecord] = []

        def acquire_then_fail_artifact_publication(**kwargs):
            claimed = original_acquire(**kwargs)
            captured_leases.append(claimed.lease)
            outage.fail_put = True
            return claimed

        monkeypatch.setattr(
            harness.store,
            "acquire_recovery_authorization_lease",
            acquire_then_fail_artifact_publication,
        )
        with pytest.raises(AgentKernelError) as unavailable:
            await coordinator.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert unavailable.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        outage.fail_put = False
        monkeypatch.setattr(
            harness.store,
            "acquire_recovery_authorization_lease",
            original_acquire,
        )

        assert len(captured_leases) == 1
        handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=session.record.tenant_id,
            target_transaction_id=session.record.transaction_id,
        )
        assert len(handoffs) == 1
        open_handoff = handoffs[0]
        assert open_handoff.binding.recovery_kind is RecoveryWorkKind.RECONCILE_DISPATCH
        assert open_handoff.binding.recovery_ordinal == 1
        assert open_handoff.action is None
        assert open_handoff.closed_at is None
        assert not harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        released_lease = harness.store.get_worker_lease(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
            lease_id=captured_leases[0].lease_id,
        )
        assert released_lease.released_at is not None
        assert (
            harness.store.get_resumable_open_prework_handoff(
                tenant_id=session.record.tenant_id,
                target_transaction_id=session.record.transaction_id,
                observed_at=harness.clock(),
            )
            == open_handoff
        )
        assert (
            harness.store.count_recovery_candidates(
                tenant_id=session.record.tenant_id,
                observed_at=harness.clock(),
            )
            == 1
        )
        assert recovery_actions.create_calls == adapter.reconcile_calls == 0

        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        original_reopened_acquire = reopened_store.acquire_recovery_authorization_lease
        competing_leases: list[WorkerLeaseRecord] = []

        def competing_acquire_then_conflict(**kwargs):
            competing = original_reopened_acquire(
                **{
                    **kwargs,
                    "lease_id": "lease:competing-prework",
                    "worker_id": "worker:competing-prework",
                }
            )
            competing_leases.append(competing.lease)
            return original_reopened_acquire(**kwargs)

        monkeypatch.setattr(
            reopened_store,
            "acquire_recovery_authorization_lease",
            competing_acquire_then_conflict,
        )
        lost_race = await restarted.recover_once(session.record.tenant_id)
        assert lost_race.scanned == 1
        assert lost_race.processed == lost_race.remaining == 0
        assert not lost_race.failures
        assert len(competing_leases) == 1
        assert (
            reopened_store.get_live_open_prework_handoff(
                tenant_id=session.record.tenant_id,
                target_transaction_id=session.record.transaction_id,
                observed_at=harness.clock(),
            )
            == open_handoff
        )
        assert recovery_actions.create_calls == adapter.reconcile_calls == 0
        monkeypatch.setattr(
            reopened_store,
            "acquire_recovery_authorization_lease",
            original_reopened_acquire,
        )
        harness.clock.advance(
            competing_leases[0].expires_at - harness.clock() + timedelta(microseconds=1)
        )
        resumed = await restarted.recover_once(session.record.tenant_id)

        assert resumed.scanned == resumed.processed == 1
        assert resumed.remaining == 0
        assert not resumed.failures
        work = reopened_store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(work) == 1
        assert work[0].recovery_id == open_handoff.binding.recovery_id
        assert work[0].state is RecoveryWorkState.SUCCEEDED
        assert recovery_actions.create_calls == adapter.reconcile_calls == 1
        latest_recovery_lease = reopened_store._connection.execute(
            "SELECT * FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND purpose = 'RECOVERY' "
            "ORDER BY fencing_token DESC LIMIT 1",
            (session.record.tenant_id, session.record.transaction_id),
        ).fetchone()
        assert latest_recovery_lease is not None
        assert int(latest_recovery_lease["fencing_token"]) > released_lease.fencing_token
        repeated = await restarted.recover_once(session.record.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.create_calls == adapter.reconcile_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_generic_conflict_after_candidate_selection_is_not_suppressed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        session = await _crash_during_commit(harness)
        coordinator = await _stop_dispatch_before_explicit_resume(harness, session)
        record, dispatch, handoff, _released_lease = _reserve_released_typed_reconciliation_prework(
            harness,
            coordinator,
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
            lease_id="lease:released-prework-negative",
            worker_id="worker:released-prework-negative",
        )
        original_candidate = coordinator._recover_candidate
        competing_leases: list[WorkerLeaseRecord] = []

        async def acquire_outside_then_raise_generic_conflict(
            selected: EnforcedTransactionRecord,
            *,
            observed_at: datetime,
            resume_typed_dispatch: bool = False,
        ) -> bool:
            if not competing_leases:
                acquired_at = harness.clock()
                competing = harness.store.acquire_recovery_authorization_lease(
                    tenant_id=selected.tenant_id,
                    transaction_id=selected.transaction_id,
                    expected_transaction_version=selected.version,
                    kind=RecoveryWorkKind.RECONCILE_DISPATCH,
                    dispatch_id=dispatch.dispatch_id,
                    dispatch_target_ref=canonical_digest(dispatch),
                    recovery_id=handoff.binding.recovery_id,
                    lease_id="lease:external-candidate-conflict",
                    worker_id="worker:external-candidate-conflict",
                    acquired_at=acquired_at,
                    expires_at=min(
                        handoff.binding.absolute_deadline,
                        acquired_at + coordinator._config.lease_duration,
                    ),
                    binding=handoff.binding,
                )
                competing_leases.append(competing.lease)
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "generic conflict outside recovery handoff acquisition",
                    retryable=True,
                )
            return await original_candidate(
                selected,
                observed_at=observed_at,
                resume_typed_dispatch=resume_typed_dispatch,
            )

        monkeypatch.setattr(
            coordinator,
            "_recover_candidate",
            acquire_outside_then_raise_generic_conflict,
        )
        result = await coordinator.recover_once(record.tenant_id)

        assert result.scanned == 1
        assert result.processed == result.remaining == 0
        assert len(result.failures) == 1
        assert result.failures[0].kind is RecoveryFailureKind.CANDIDATE
        assert result.failures[0].reason_code == ErrorCode.VERSION_CONFLICT.value
        assert len(competing_leases) == 1
        assert (
            harness.store.get_live_open_prework_handoff(
                tenant_id=record.tenant_id,
                target_transaction_id=record.transaction_id,
                observed_at=harness.clock(),
            )
            == handoff
        )
        assert recovery_actions.create_calls == adapter.reconcile_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_lost_acquire_accepts_exact_handoff_progressed_to_work(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED,
        )
        with pytest.raises(CoordinatorInjectedCrash) as crashed:
            await crashing.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert crashed.value.point is CoordinatorCrashPoint.AFTER_RECOVERY_AUTHORIZED

        record = harness.store.get_enforced_transaction(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=record.tenant_id,
            target_transaction_id=record.transaction_id,
        )
        work = harness.store.list_recovery_work(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
        )
        assert len(handoffs) == len(work) == 1
        assert work[0].recovery_id == handoffs[0].binding.recovery_id
        assert work[0].state is RecoveryWorkState.PENDING
        assert (
            harness.store.get_live_open_prework_handoff(
                tenant_id=record.tenant_id,
                target_transaction_id=record.transaction_id,
                observed_at=harness.clock(),
            )
            is None
        )

        assert crashing._exact_prework_handoff_won_acquisition(
            record,
            proposed_binding=handoffs[0].binding,
            registered_handoff=None,
            error=AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "winner progressed to durable recovery work",
                retryable=True,
            ),
        )
        assert not crashing._exact_prework_handoff_won_acquisition(
            record,
            proposed_binding=handoffs[0].binding,
            registered_handoff=None,
            error=AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "stale target conflict",
                retryable=False,
            ),
        )
        assert recovery_actions.create_calls == 1
        assert adapter.reconcile_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_typed_reconciliation_attached_prework_crash_waits_for_lease_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    recovery_actions = _RecordingRecoveryActions(harness.recovery_actions)
    harness.recovery_actions = recovery_actions
    original_release = harness.store.release_worker_lease
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)

        def abandon_recovery_handoff(**kwargs):
            lease = harness.store.get_worker_lease(
                tenant_id=kwargs["tenant_id"],
                transaction_id=kwargs["transaction_id"],
                lease_id=kwargs["lease_id"],
            )
            if lease.purpose is LeasePurpose.RECOVERY:
                return lease
            return original_release(**kwargs)

        monkeypatch.setattr(
            harness.store,
            "release_worker_lease",
            abandon_recovery_handoff,
        )
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_ACTION_ATTACHED,
        )
        with pytest.raises(CoordinatorInjectedCrash) as crashed:
            await crashing.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert crashed.value.point is CoordinatorCrashPoint.AFTER_RECOVERY_ACTION_ATTACHED
        assert recovery_actions.calls == 1
        assert recovery_actions.action is not None

        handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=session.record.tenant_id,
            target_transaction_id=session.record.transaction_id,
        )
        assert len(handoffs) == 1
        attached_handoff = handoffs[0]
        assert attached_handoff.action == recovery_actions.action
        assert attached_handoff.closed_at is None
        original_lease = harness.store.get_worker_lease(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
            lease_id=attached_handoff.handoff_lease_id,
        )
        assert original_lease.released_at is None
        assert not harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert (
            harness.store.get_live_open_prework_handoff(
                tenant_id=session.record.tenant_id,
                target_transaction_id=session.record.transaction_id,
                observed_at=harness.clock(),
            )
            == attached_handoff
        )
        assert (
            harness.store.count_recovery_candidates(
                tenant_id=session.record.tenant_id,
                observed_at=harness.clock(),
            )
            == 0
        )
        assert not harness.store.scan_recovery_candidates(
            tenant_id=session.record.tenant_id,
            observed_at=harness.clock(),
            limit=1,
        ).records

        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        before_expiry = await restarted.recover_once(session.record.tenant_id)
        assert before_expiry.scanned == before_expiry.processed == before_expiry.remaining == 0
        assert not before_expiry.failures
        harness.clock.advance(
            original_lease.expires_at - harness.clock() + timedelta(microseconds=1)
        )
        assert (
            reopened_store.count_recovery_candidates(
                tenant_id=session.record.tenant_id,
                observed_at=harness.clock(),
            )
            == 1
        )
        resumed = await restarted.recover_once(session.record.tenant_id)

        assert resumed.scanned == resumed.processed == 1
        assert resumed.remaining == 0
        assert not resumed.failures
        assert recovery_actions.calls == 1
        assert adapter.reconcile_calls == 1
        work = reopened_store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert len(work) == 1
        assert work[0].recovery_id == attached_handoff.binding.recovery_id
        assert work[0].state is RecoveryWorkState.SUCCEEDED
        expired_original = reopened_store.get_worker_lease(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
            lease_id=original_lease.lease_id,
        )
        assert expired_original.released_at is not None
        latest_recovery_lease = reopened_store._connection.execute(
            "SELECT * FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND purpose = 'RECOVERY' "
            "ORDER BY fencing_token DESC LIMIT 1",
            (session.record.tenant_id, session.record.transaction_id),
        ).fetchone()
        assert latest_recovery_lease is not None
        assert int(latest_recovery_lease["fencing_token"]) > original_lease.fencing_token
        repeated = await restarted.recover_once(session.record.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.calls == adapter.reconcile_calls == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_typed_reconciliation_unattached_prework_deadline_closes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    recovery_actions = _CountingRecoveryActions()
    harness.recovery_actions = recovery_actions
    original_acquire = harness.store.acquire_recovery_authorization_lease
    try:
        session = await _crash_during_commit(harness)
        await _stop_dispatch_before_explicit_resume(harness, session)
        outage = _TogglePutOutageArtifacts(harness.artifacts)
        coordinator = _clone_coordinator(
            harness,
            artifacts=outage,
            recovery_actions=recovery_actions,
        )

        def acquire_then_fail_artifact_publication(**kwargs):
            claimed = original_acquire(**kwargs)
            outage.fail_put = True
            return claimed

        monkeypatch.setattr(
            harness.store,
            "acquire_recovery_authorization_lease",
            acquire_then_fail_artifact_publication,
        )
        with pytest.raises(AgentKernelError) as unavailable:
            await coordinator.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        assert unavailable.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
        outage.fail_put = False
        monkeypatch.setattr(
            harness.store,
            "acquire_recovery_authorization_lease",
            original_acquire,
        )
        open_handoff = harness.store.list_recovery_action_handoffs(
            tenant_id=session.record.tenant_id,
            target_transaction_id=session.record.transaction_id,
        )[0]
        assert open_handoff.action is None
        assert open_handoff.closed_at is None
        assert not harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )

        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        harness.clock.advance(
            open_handoff.binding.absolute_deadline - harness.clock() + timedelta(microseconds=1)
        )
        assert (
            reopened_store.count_recovery_candidates(
                tenant_id=session.record.tenant_id,
                observed_at=harness.clock(),
            )
            == 1
        )
        settled = await restarted.recover_once(session.record.tenant_id)

        assert settled.scanned == settled.processed == 1
        assert settled.remaining == 0
        assert len(settled.failures) == 1
        assert settled.failures[0].reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        closed_handoff = reopened_store.get_recovery_action_handoff(
            tenant_id=session.record.tenant_id,
            target_transaction_id=session.record.transaction_id,
            recovery_id=open_handoff.binding.recovery_id,
        )
        assert closed_handoff is not None
        assert closed_handoff.closed_at == harness.clock()
        assert closed_handoff.action is None
        assert (
            closed_handoff.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.AVAILABLE
        )
        assert closed_handoff.failure_reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        assert not reopened_store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        assert recovery_actions.create_calls == adapter.reconcile_calls == 0
        repeated = await restarted.recover_once(session.record.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures

        reopened_store.close()
        final_store, final_restart = support._reopen_coordinator(harness, database_path)
        harness.store = final_store
        after_restart = await final_restart.recover_once(session.record.tenant_id)
        assert after_restart.scanned == after_restart.processed == after_restart.remaining == 0
        assert not after_restart.failures
        assert (
            final_store.count_recovery_candidates(
                tenant_id=session.record.tenant_id,
                observed_at=harness.clock(),
            )
            == 0
        )
        assert recovery_actions.create_calls == adapter.reconcile_calls == 0
    finally:
        harness.store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "initial_crash", "expected_kind", "expected_state", "effect_counter"),
    [
        (
            "untyped-reconcile",
            CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
            RecoveryWorkKind.RECONCILE_DISPATCH,
            TransactionState.COMMITTED,
            "reconcile_calls",
        ),
        (
            "aborting-discard",
            CoordinatorCrashPoint.AFTER_ABORTING,
            RecoveryWorkKind.DISCARD_STAGING,
            TransactionState.ABORTED,
            "abort_stage_calls",
        ),
        (
            "failed-rollback",
            CoordinatorCrashPoint.AFTER_OUTCOME_CLASSIFIED,
            RecoveryWorkKind.ROLLBACK,
            TransactionState.ROLLED_BACK,
            "rollback_calls",
        ),
    ],
    ids=("untyped-reconcile", "aborting-discard", "failed-rollback"),
)
async def test_direct_prework_live_lease_waits_for_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    initial_crash: CoordinatorCrashPoint,
    expected_kind: RecoveryWorkKind,
    expected_state: TransactionState,
    effect_counter: str,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=_CountingReconcileAdapter,
        crash_point=initial_crash,
    )
    adapter = harness.adapter
    assert isinstance(adapter, _CountingReconcileAdapter)
    recovery_actions = _RecordingRecoveryActions(harness.recovery_actions)
    harness.recovery_actions = recovery_actions
    try:
        if mode == "aborting-discard":
            session = await harness.coordinator.transaction(harness.request)
            with pytest.raises(CoordinatorInjectedCrash):
                async with session:
                    pass
            target = harness.store.get_enforced_transaction(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        else:
            if mode == "failed-rollback":
                adapter.committed_status = VerificationStatus.FAIL
            session = await _crash_during_commit(harness)
            target = harness.store.get_enforced_transaction(
                session.record.tenant_id,
                session.record.transaction_id,
            )
            if mode == "untyped-reconcile":
                dispatch = harness.store.get_commit_dispatch(
                    tenant_id=target.tenant_id,
                    transaction_id=target.transaction_id,
                )
                classified = harness.store.classify_dispatch_outcome(
                    tenant_id=target.tenant_id,
                    transaction_id=target.transaction_id,
                    expected_dispatch_version=dispatch.version,
                    expected_transaction_version=target.version,
                    classification=ReconciliationOutcome.UNKNOWN,
                    evidence_refs=(dispatch.permit_ref,),
                    recorded_at=harness.clock(),
                    recovery_timeout=harness.coordinator._config.recovery_deadline,
                )
                target = classified.transaction
                assert classified.dispatch.unavailable_record_digest is None

        expected_initial_state = {
            "untyped-reconcile": TransactionState.IN_DOUBT,
            "aborting-discard": TransactionState.ABORTING,
            "failed-rollback": TransactionState.FAILED,
        }[mode]
        assert target.state is expected_initial_state
        if mode == "aborting-discard":
            harness.clock.advance(timedelta(minutes=1, microseconds=1))
        assert not harness.store.list_recovery_work(
            tenant_id=target.tenant_id,
            transaction_id=target.transaction_id,
        )
        original_release = harness.store.release_worker_lease

        def abandon_recovery_handoff(**kwargs):
            lease = harness.store.get_worker_lease(
                tenant_id=kwargs["tenant_id"],
                transaction_id=kwargs["transaction_id"],
                lease_id=kwargs["lease_id"],
            )
            if lease.purpose is LeasePurpose.RECOVERY:
                return lease
            return original_release(**kwargs)

        monkeypatch.setattr(
            harness.store,
            "release_worker_lease",
            abandon_recovery_handoff,
        )
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_ACTION_ATTACHED,
        )
        with pytest.raises(CoordinatorInjectedCrash) as crashed:
            await crashing.recover_once(target.tenant_id)
        assert crashed.value.point is CoordinatorCrashPoint.AFTER_RECOVERY_ACTION_ATTACHED
        assert recovery_actions.calls == 1
        assert recovery_actions.action is not None

        handoffs = harness.store.list_recovery_action_handoffs(
            tenant_id=target.tenant_id,
            target_transaction_id=target.transaction_id,
        )
        assert len(handoffs) == 1
        attached_handoff = handoffs[0]
        assert attached_handoff.binding.recovery_kind is expected_kind
        assert attached_handoff.binding.recovery_ordinal == 1
        assert attached_handoff.action == recovery_actions.action
        assert attached_handoff.closed_at is None
        original_lease = harness.store.get_worker_lease(
            tenant_id=target.tenant_id,
            transaction_id=target.transaction_id,
            lease_id=attached_handoff.handoff_lease_id,
        )
        assert original_lease.released_at is None
        assert not harness.store.list_recovery_work(
            tenant_id=target.tenant_id,
            transaction_id=target.transaction_id,
        )

        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        assert (
            reopened_store.get_live_open_prework_handoff(
                tenant_id=target.tenant_id,
                target_transaction_id=target.transaction_id,
                observed_at=harness.clock(),
            )
            == attached_handoff
        )
        assert (
            reopened_store.count_recovery_candidates(
                tenant_id=target.tenant_id,
                observed_at=harness.clock(),
            )
            == 0
        )
        assert not reopened_store.scan_recovery_candidates(
            tenant_id=target.tenant_id,
            observed_at=harness.clock(),
            limit=1,
        ).records
        quiescent = await restarted.recover_once(target.tenant_id)
        assert quiescent.scanned == quiescent.processed == quiescent.remaining == 0
        assert not quiescent.failures

        harness.clock.advance(
            original_lease.expires_at - harness.clock() + timedelta(microseconds=1)
        )
        assert (
            reopened_store.count_recovery_candidates(
                tenant_id=target.tenant_id,
                observed_at=harness.clock(),
            )
            == 1
        )
        page = reopened_store.scan_recovery_candidates(
            tenant_id=target.tenant_id,
            observed_at=harness.clock(),
            limit=1,
            cursor=RecoveryCursor(
                target.updated_at - timedelta(microseconds=1),
                "transaction:prework-cursor",
            ),
        )
        assert tuple(record.transaction_id for record in page.records) == (target.transaction_id,)
        resumed = await restarted.recover_once(target.tenant_id)

        assert resumed.scanned == resumed.processed == 1
        assert resumed.remaining == 0
        assert not resumed.failures
        assert resumed.statuses[0].record.state is expected_state
        assert recovery_actions.calls == 1
        assert getattr(adapter, effect_counter) == 1
        work = reopened_store.list_recovery_work(
            tenant_id=target.tenant_id,
            transaction_id=target.transaction_id,
        )
        assert len(work) == 1
        assert work[0].kind is expected_kind
        assert work[0].recovery_id == attached_handoff.binding.recovery_id
        assert work[0].state is RecoveryWorkState.SUCCEEDED
        expired_original = reopened_store.get_worker_lease(
            tenant_id=target.tenant_id,
            transaction_id=target.transaction_id,
            lease_id=original_lease.lease_id,
        )
        assert expired_original.released_at is not None
        latest_recovery_lease = reopened_store._connection.execute(
            "SELECT * FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND purpose = 'RECOVERY' "
            "ORDER BY fencing_token DESC LIMIT 1",
            (target.tenant_id, target.transaction_id),
        ).fetchone()
        assert latest_recovery_lease is not None
        assert int(latest_recovery_lease["fencing_token"]) > original_lease.fencing_token
        repeated = await restarted.recover_once(target.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.calls == 1
        assert getattr(adapter, effect_counter) == 1
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_successor_prework_live_lease_is_quiescent_until_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        adapter_type=support._SequencedReconciliationAdapter,
        crash_point=CoordinatorCrashPoint.AFTER_RECEIPT_ATTACHED,
    )
    adapter = harness.adapter
    assert isinstance(adapter, support._SequencedReconciliationAdapter)
    adapter.reconcile_statuses = [
        ReconcileStatus.UNKNOWN,
        ReconcileStatus.COMMITTED,
    ]
    recovery_actions = _RecordingRecoveryActions(harness.recovery_actions)
    harness.recovery_actions = recovery_actions
    try:
        session = await _crash_during_commit(harness)
        recovery = await _stop_dispatch_before_explicit_resume(harness, session)
        first = await recovery.resume_dispatch_reconciliation(
            session.record.tenant_id,
            session.record.transaction_id,
        )
        assert first.record.state is TransactionState.IN_DOUBT
        scheduled = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        assert scheduled.state is RecoveryWorkState.RETRY_SCHEDULED
        attempt = harness.store.get_reconciliation_attempt(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            recovery_id=scheduled.recovery_id,
            attempt=scheduled.attempt,
        )
        assert attempt.next_attempt_not_before is not None
        assert recovery_actions.calls == adapter.reconcile_calls == 1
        harness.clock.advance(attempt.next_attempt_not_before - harness.clock())

        original_release = harness.store.release_worker_lease

        def abandon_recovery_handoff(**kwargs):
            lease = harness.store.get_worker_lease(
                tenant_id=kwargs["tenant_id"],
                transaction_id=kwargs["transaction_id"],
                lease_id=kwargs["lease_id"],
            )
            if lease.purpose is LeasePurpose.RECOVERY:
                return lease
            return original_release(**kwargs)

        monkeypatch.setattr(
            harness.store,
            "release_worker_lease",
            abandon_recovery_handoff,
        )
        crashing = support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECOVERY_ACTION_ATTACHED,
        )
        with pytest.raises(CoordinatorInjectedCrash) as crashed:
            await crashing.recover_once(scheduled.tenant_id)
        assert crashed.value.point is CoordinatorCrashPoint.AFTER_RECOVERY_ACTION_ATTACHED
        assert recovery_actions.calls == 2
        assert adapter.reconcile_calls == 1

        successor_handoff = next(
            handoff
            for handoff in harness.store.list_recovery_action_handoffs(
                tenant_id=scheduled.tenant_id,
                target_transaction_id=scheduled.transaction_id,
            )
            if handoff.binding.predecessor_recovery_id == scheduled.recovery_id
        )
        assert successor_handoff.binding.recovery_ordinal == scheduled.recovery_ordinal + 1
        assert successor_handoff.action == recovery_actions.action
        assert successor_handoff.closed_at is None
        assert not any(
            work.recovery_id == successor_handoff.binding.recovery_id
            for work in harness.store.list_recovery_work(
                tenant_id=scheduled.tenant_id,
                transaction_id=scheduled.transaction_id,
            )
        )
        original_lease = harness.store.get_worker_lease(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            lease_id=successor_handoff.handoff_lease_id,
        )
        assert original_lease.released_at is None
        assert (
            harness.store.get_live_open_prework_handoff(
                tenant_id=scheduled.tenant_id,
                target_transaction_id=scheduled.transaction_id,
                observed_at=harness.clock(),
            )
            == successor_handoff
        )
        assert (
            harness.store.count_recovery_candidates(
                tenant_id=scheduled.tenant_id,
                observed_at=harness.clock(),
            )
            == 0
        )
        assert not harness.store.scan_recovery_candidates(
            tenant_id=scheduled.tenant_id,
            observed_at=harness.clock(),
            limit=1,
        ).records
        quiescent = await support._restart_coordinator(harness).recover_once(scheduled.tenant_id)
        assert quiescent.scanned == quiescent.processed == quiescent.remaining == 0
        assert not quiescent.failures

        harness.store.close()
        reopened_store, restarted = support._reopen_coordinator(harness, database_path)
        harness.store = reopened_store
        assert (
            reopened_store.count_recovery_candidates(
                tenant_id=scheduled.tenant_id,
                observed_at=harness.clock(),
            )
            == 0
        )
        before_expiry = await restarted.recover_once(scheduled.tenant_id)
        assert before_expiry.scanned == before_expiry.processed == before_expiry.remaining == 0
        assert not before_expiry.failures

        harness.clock.advance(
            original_lease.expires_at - harness.clock() + timedelta(microseconds=1)
        )
        assert (
            reopened_store.count_recovery_candidates(
                tenant_id=scheduled.tenant_id,
                observed_at=harness.clock(),
            )
            == 1
        )
        assert (
            reopened_store.get_resumable_open_prework_handoff(
                tenant_id=scheduled.tenant_id,
                target_transaction_id=scheduled.transaction_id,
                observed_at=harness.clock(),
            )
            == successor_handoff
        )
        page = reopened_store.scan_recovery_candidates(
            tenant_id=scheduled.tenant_id,
            observed_at=harness.clock(),
            limit=1,
        )
        assert tuple(record.transaction_id for record in page.records) == (
            scheduled.transaction_id,
        )
        resumed = await restarted.recover_once(scheduled.tenant_id)

        assert resumed.scanned == resumed.processed == 1
        assert resumed.remaining == 0
        assert not resumed.failures
        assert resumed.statuses[0].record.state is TransactionState.COMMITTED
        assert recovery_actions.calls == adapter.reconcile_calls == 2
        works = reopened_store.list_recovery_work(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
        )
        assert len(works) == 2
        successor_work = next(
            work for work in works if work.recovery_id == successor_handoff.binding.recovery_id
        )
        assert successor_work.state is RecoveryWorkState.SUCCEEDED
        assert successor_work.predecessor_recovery_id == scheduled.recovery_id
        expired_original = reopened_store.get_worker_lease(
            tenant_id=scheduled.tenant_id,
            transaction_id=scheduled.transaction_id,
            lease_id=original_lease.lease_id,
        )
        assert expired_original.released_at is not None
        latest_recovery_lease = reopened_store._connection.execute(
            "SELECT * FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND purpose = 'RECOVERY' "
            "ORDER BY fencing_token DESC LIMIT 1",
            (scheduled.tenant_id, scheduled.transaction_id),
        ).fetchone()
        assert latest_recovery_lease is not None
        assert int(latest_recovery_lease["fencing_token"]) > original_lease.fencing_token
        repeated = await restarted.recover_once(scheduled.tenant_id)
        assert repeated.scanned == repeated.processed == repeated.remaining == 0
        assert not repeated.failures
        assert recovery_actions.calls == adapter.reconcile_calls == 2
    finally:
        harness.store.close()
