from __future__ import annotations

import asyncio
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from agentkernel.adapters.base import (
    BlockingCancellation,
    CommitContext,
    ReadOnlyContext,
    ReconcileStatus,
    RecoveryContext,
    StageContext,
    StagedReceipt,
    VerifyContext,
    run_blocking_quiescent,
)
from agentkernel.adapters.mock import MockReversibleAdapter, VersionedMemoryTarget
from agentkernel.adapters.registry import AdapterRegistry
from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import (
    ProvenanceTrust,
    RecoveryWorkKind,
    VerificationPhase,
    VerificationStatus,
)
from agentkernel.domain.models import (
    RECOVERY_ACTION_BINDING_ARGUMENT,
    ActionProposal,
    AdapterObservation,
    AuthenticatedActionContext,
    CommitPermit,
    EffectReceipt,
    InspectionPermit,
    IntentRecord,
    NormalizedAction,
    NormalizedProvenance,
    RecoveryActionBinding,
    RecoveryPermit,
    SemanticArgument,
    StagePermit,
    VerificationPermit,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.artifacts import LocalArtifactStore
from agentkernel.normalization.base import AdmittedOperation
from agentkernel.normalization.mock import MockSetValuesNormalizer


def test_adapter_observation_contract_is_tenant_scoped_and_compensation_ready() -> None:
    schema = AdapterObservation.model_json_schema(mode="validation")
    assert "tenant_id" in schema["required"]
    assert "compensation" in schema["properties"]["evidence_kind"]["enum"]


@pytest.mark.asyncio
async def test_quiescent_runner_survives_repeated_cancel_and_consumes_base_exception() -> None:
    class WorkerStopped(BaseException):
        pass

    started = threading.Event()
    release = threading.Event()

    def operation(cancellation: BlockingCancellation) -> None:
        del cancellation
        started.set()
        if not release.wait(timeout=2):
            raise AssertionError("worker release barrier timed out")
        raise WorkerStopped

    task = asyncio.create_task(run_blocking_quiescent(operation))
    assert await asyncio.to_thread(started.wait, 1)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=1)


def _normalized_action(
    proposal: ActionProposal,
    adapter: MockReversibleAdapter,
) -> NormalizedAction:
    normalizer = MockSetValuesNormalizer()
    return normalizer.normalize(
        proposal=proposal,
        context=AuthenticatedActionContext(
            tenant_id="tenant:test",
            principal_id="principal:test",
            goal_id=proposal.goal_id,
            run_id="run:test",
            trace_id="trace:test",
            actor_id="actor:test",
            on_behalf_of="principal:test",
            agent_id=proposal.agent_id,
            configuration_digest=normalizer.configuration_digest,
        ),
        operation=AdmittedOperation(
            adapter=adapter.manifest.name,
            adapter_version=adapter.manifest.version,
            adapter_manifest_digest=adapter.manifest.digest,
            operation=proposal.operation,
            risk_floor=adapter.manifest.operations[proposal.operation].risk_floor,
            effect_domains=adapter.manifest.operations[proposal.operation].effect_domains,
            normalizer_manifest=normalizer.manifest,
            configuration_digest=normalizer.configuration_digest,
        ),
        provenance=tuple(
            NormalizedProvenance(
                provenance_id=provenance_id,
                trust=ProvenanceTrust.MODEL_GENERATED,
                record_digest=canonical_digest({"provenance": provenance_id}),
            )
            for provenance_id in sorted(proposal.provenance_ids)
        ),
    )


def _inspection_permit(
    proposal: ActionProposal,
    adapter: MockReversibleAdapter,
    action: NormalizedAction,
    *,
    fencing_token: int,
) -> InspectionPermit:
    issued_at = datetime.now(UTC)
    return InspectionPermit.create(
        tenant_id="tenant:test",
        transaction_id=proposal.transaction_id,
        intent_hash=action.intent_hash,
        normalized_action_digest=canonical_digest(action),
        proposal_ref=canonical_digest(proposal),
        adapter_manifest_digest=adapter.manifest.digest,
        authorization_round_id="authorization_round:test",
        authorization_round_digest=canonical_digest({"round": "stage"}),
        lease_id="lease:test",
        worker_id="worker:test",
        fencing_token=fencing_token,
        issued_at=issued_at,
        deadline=proposal.deadline,
    )


def _absence_recovery_context(
    *,
    adapter: MockReversibleAdapter,
    artifacts: LocalArtifactStore,
    target_action: NormalizedAction,
    target_action_ref: str,
    target_evidence_ref: str,
    target_id: str,
    target_version_guard: str,
    target_owner_version: int,
    target_owner_history_sequence: int,
    target_owner_history_digest: str,
    fencing_token: int,
) -> tuple[RecoveryContext, RecoveryPermit]:
    now = datetime.now(UTC)
    recovery_id = f"recovery:mock-absence:{fencing_token}"
    binding = RecoveryActionBinding(
        target_transaction_id=target_action.transaction_id,
        target_intent_hash=target_action.intent_hash,
        target_normalized_action_digest=target_action_ref,
        recovery_kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        target_id=target_id,
        target_evidence_ref=target_evidence_ref,
        target_version_guard=target_version_guard,
        target_owner_version=target_owner_version,
        target_owner_history_sequence=target_owner_history_sequence,
        target_owner_history_digest=target_owner_history_digest,
        adapter_manifest_digest=adapter.manifest.digest,
        risk_class=target_action.risk_floor,
        effect_domains=target_action.effect_domains,
        resource_uses_digest=canonical_digest(target_action.resource_uses),
        recovery_id=recovery_id,
        root_recovery_id=recovery_id,
        recovery_ordinal=1,
        max_recovery_attempts=3,
        not_before=now,
        absolute_deadline=target_action.deadline,
    )
    binding_artifact = artifacts.put_model(binding)
    binding_argument = SemanticArgument(
        argument_name=RECOVERY_ACTION_BINDING_ARGUMENT,
        resource=target_action.resource_uses[0].canonical_resource,
        digest=binding_artifact.digest,
        size_bytes=binding_artifact.size_bytes,
        media_type="application/vnd.agentkernel.canonical+json",
    )
    recovery_action = NormalizedAction.create(
        context=AuthenticatedActionContext(
            tenant_id=target_action.tenant_id,
            principal_id=target_action.principal_id,
            goal_id=target_action.goal_id,
            run_id=target_action.run_id,
            trace_id=f"trace:mock-absence:{fencing_token}",
            actor_id=target_action.actor_id,
            on_behalf_of=target_action.on_behalf_of,
            agent_id=target_action.agent_id,
            configuration_digest=target_action.configuration_digest,
        ),
        transaction_id=f"tx:mock-absence-recovery:{fencing_token}",
        deadline=target_action.deadline,
        idempotency_key=recovery_id,
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
                key=lambda item: item.sort_key(),
            )
        ),
        provenance=target_action.provenance,
    )
    recovery_action_ref = artifacts.put_model(recovery_action).digest
    approval_ref = artifacts.put(b"recovery-approval-not-required").digest
    permit = RecoveryPermit.create(
        tenant_id=target_action.tenant_id,
        transaction_id=target_action.transaction_id,
        intent_hash=target_action.intent_hash,
        recovery_id=recovery_id,
        recovery_action_transaction_id=recovery_action.transaction_id,
        recovery_action_intent_hash=recovery_action.intent_hash,
        recovery_action_digest=recovery_action_ref,
        adapter_manifest_digest=adapter.manifest.digest,
        recovery_kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        target_id=target_id,
        target_owner_version=target_owner_version,
        target_owner_history_sequence=target_owner_history_sequence,
        target_owner_history_digest=target_owner_history_digest,
        target_evidence_ref=target_evidence_ref,
        target_version_guard=target_version_guard,
        authorization_round_id=f"authorization_round:mock-absence:{fencing_token}",
        authorization_round_digest=artifacts.put(b"recovery:round").digest,
        authority_decision_digest=artifacts.put(b"recovery:authority:allow").digest,
        policy_decision_digest=artifacts.put(b"recovery:policy:allow").digest,
        policy_snapshot_digest=artifacts.put(b"recovery:policy:snapshot").digest,
        capability_reservation_digest=artifacts.put(b"recovery:capability").digest,
        reservation_version=1,
        owner_version=0,
        owner_history_sequence=0,
        owner_history_digest=canonical_digest({"recovery-owner": fencing_token}),
        approval_required=False,
        approval_evidence_ref=approval_ref,
        lease_id=f"lease:mock-absence:{fencing_token}",
        worker_id=f"worker:mock-absence:{fencing_token}",
        fencing_token=fencing_token,
        issued_at=now,
        deadline=target_action.deadline,
    )
    permit_ref = artifacts.put_model(permit).digest
    return (
        RecoveryContext(
            permit.deadline,
            permit.authorization_round_digest,
            permit.worker_id,
            permit,
            permit_ref,
        ),
        permit,
    )


@pytest.mark.asyncio
async def test_stage_execute_commit_and_rollback_boundaries(
    proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = MockReversibleAdapter(target)
    original_digest = target.digest
    original_state = dict(target.state)
    plan = await adapter.inspect(proposal, ReadOnlyContext(proposal.deadline))
    staged = await adapter.stage(plan, StageContext(proposal.deadline, "worker:test"))
    assert target.digest == original_digest
    receipt = await adapter.execute(staged, StageContext(proposal.deadline, "worker:test"))
    assert target.digest == original_digest
    staged_report = await adapter.verify_staged(receipt, VerifyContext(proposal.deadline))
    assert staged_report.status is VerificationStatus.PASS

    effect = await adapter.commit(
        receipt,
        CommitContext(proposal.deadline, 1, plan.intent_hash, plan.base_version),
    )
    assert target.state == {"before": "kept", "answer": "42"}
    committed = await adapter.verify_committed(effect, VerifyContext(proposal.deadline))
    assert committed.status is VerificationStatus.PASS

    recovery = await adapter.rollback(
        effect,
        RecoveryContext(proposal.deadline, "authority:test"),
    )
    assert recovery.status is VerificationStatus.PASS
    assert target.state == original_state


@pytest.mark.asyncio
async def test_abort_discards_stage_without_authoritative_effect(
    proposal: ActionProposal, now: datetime
) -> None:
    del now
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = MockReversibleAdapter(target)
    original_digest = target.digest
    plan = await adapter.inspect(proposal, ReadOnlyContext(proposal.deadline))
    staged = await adapter.stage(plan, StageContext(proposal.deadline, "worker:test"))
    receipt = await adapter.execute(staged, StageContext(proposal.deadline, "worker:test"))
    report = await adapter.abort(
        receipt,
        RecoveryContext(proposal.deadline, "authority:test"),
    )
    assert report.status is VerificationStatus.PASS
    assert target.digest == original_digest


@pytest.mark.asyncio
async def test_mock_cancel_before_dispatch_has_no_effect(proposal: ActionProposal) -> None:
    class PauseUntilCancelled(MockReversibleAdapter):
        def __init__(self, target: VersionedMemoryTarget) -> None:
            super().__init__(target)
            self.entered = threading.Event()

        def _commit_locked(
            self,
            receipt: StagedReceipt,
            ctx: CommitContext,
            cancellation: BlockingCancellation,
        ) -> EffectReceipt:
            self.entered.set()
            deadline = time.monotonic() + 1
            while not cancellation.requested:
                if time.monotonic() >= deadline:
                    raise AssertionError("cancellation signal was not delivered")
                time.sleep(0.001)
            return super()._commit_locked(receipt, ctx, cancellation)

    target = VersionedMemoryTarget({"before": "kept"})
    adapter = PauseUntilCancelled(target)
    plan = await adapter.inspect(proposal, ReadOnlyContext(proposal.deadline))
    staged = await adapter.stage(plan, StageContext(proposal.deadline, "worker:test"))
    receipt = await adapter.execute(staged, StageContext(proposal.deadline, "worker:test"))
    task = asyncio.create_task(
        adapter.commit(
            receipt,
            CommitContext(proposal.deadline, 1, plan.intent_hash, plan.base_version),
        )
    )
    assert await asyncio.to_thread(adapter.entered.wait, 1)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=1)

    assert target.state == {"before": "kept"}
    assert target.version == 0
    assert target.dispatches == {}


@pytest.mark.asyncio
async def test_mock_timeout_after_dispatch_waits_for_quiescence_and_never_resends(
    proposal: ActionProposal,
) -> None:
    dispatch_durable = threading.Event()

    class SlowAfterPrepared(MockReversibleAdapter):
        def _fault_point(self, name: str) -> None:
            if name == "commit.after_prepared":
                dispatch_durable.set()
                time.sleep(0.2)

    target = VersionedMemoryTarget({"before": "kept"})
    adapter = SlowAfterPrepared(target)
    plan = await adapter.inspect(proposal, ReadOnlyContext(proposal.deadline))
    staged = await adapter.stage(plan, StageContext(proposal.deadline, "worker:test"))
    receipt = await adapter.execute(staged, StageContext(proposal.deadline, "worker:test"))
    context = CommitContext(proposal.deadline, 1, plan.intent_hash, plan.base_version)
    event_loop_responded = asyncio.Event()

    async def tick() -> None:
        await asyncio.sleep(0.03)
        event_loop_responded.set()

    commit_task = asyncio.create_task(adapter.commit(receipt, context))
    assert await asyncio.to_thread(dispatch_durable.wait, 1)
    recovery_adapter = MockReversibleAdapter(target)
    recovery_task = asyncio.create_task(
        recovery_adapter.reconcile(
            IntentRecord(
                intent_hash=plan.intent_hash,
                transaction_id=proposal.transaction_id,
                idempotency_key=plan.intent_hash,
                dispatched=True,
                created_at=datetime.now(UTC),
            ),
            RecoveryContext(proposal.deadline, "authority:test"),
        )
    )
    await asyncio.sleep(0.01)
    assert not recovery_task.done()
    ticker = asyncio.create_task(tick())
    started_at = time.monotonic()
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.01):
            await commit_task
    elapsed = time.monotonic() - started_at
    await ticker

    assert event_loop_responded.is_set()
    assert 0.15 <= elapsed < 1
    assert target.version == 1
    version_after_effect = target.version
    report = await asyncio.wait_for(recovery_task, timeout=1)
    assert report.status is ReconcileStatus.COMMITTED
    assert report.receipt is not None
    assert await adapter.commit(receipt, context) == report.receipt
    assert target.version == version_after_effect


@pytest.mark.asyncio
async def test_enforced_mock_requires_exact_artifacts_and_coordinator_stage_id(
    tmp_path,
    proposal: ActionProposal,
) -> None:
    deadline = datetime.now(UTC) + timedelta(minutes=5)
    request = proposal.model_copy(update={"deadline": deadline})
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = MockReversibleAdapter(target, require_permits=True, artifacts=artifacts)

    action = _normalized_action(request, adapter)
    action_artifact = artifacts.put_model(action)
    proposal_artifact = artifacts.put_model(request)
    inspection = _inspection_permit(request, adapter, action, fencing_token=7)
    inspection_artifact = artifacts.put_model(inspection)
    plan = await adapter.inspect(
        request,
        ReadOnlyContext(
            deadline=deadline,
            worker_id=inspection.worker_id,
            permit=inspection,
            permit_ref=inspection_artifact.digest,
            normalized_action=action,
            normalized_action_ref=action_artifact.digest,
            proposal=request,
            proposal_ref=proposal_artifact.digest,
        ),
    )
    plan_artifact = artifacts.put_model(plan)
    stage_permit = StagePermit.create(
        tenant_id=inspection.tenant_id,
        transaction_id=inspection.transaction_id,
        intent_hash=inspection.intent_hash,
        normalized_action_digest=inspection.normalized_action_digest,
        adapter_manifest_digest=inspection.adapter_manifest_digest,
        authorization_round_id=inspection.authorization_round_id,
        authorization_round_digest=inspection.authorization_round_digest,
        inspection_permit_digest=inspection.permit_digest,
        inspection_permit_ref=inspection_artifact.digest,
        plan_digest=canonical_digest(plan),
        plan_ref=plan_artifact.digest,
        stage_id="stage_coordinator_selected",
        lease_id=inspection.lease_id,
        worker_id=inspection.worker_id,
        fencing_token=inspection.fencing_token,
        target_version_guard=plan.base_version,
        issued_at=inspection.issued_at,
        deadline=deadline,
    )
    stage_permit_artifact = artifacts.put_model(stage_permit)
    stage_context = StageContext(
        deadline=deadline,
        worker_id=stage_permit.worker_id,
        permit=stage_permit,
        permit_ref=stage_permit_artifact.digest,
        normalized_action=action,
        normalized_action_ref=action_artifact.digest,
    )
    staged = await adapter.stage(plan, stage_context)
    assert staged.stage_id == "stage_coordinator_selected"
    staged_receipt = await adapter.execute(staged, stage_context)
    staged_receipt_artifact = artifacts.put_model(staged_receipt)
    verification_permit = VerificationPermit.create(
        tenant_id=inspection.tenant_id,
        transaction_id=inspection.transaction_id,
        intent_hash=inspection.intent_hash,
        normalized_action_digest=inspection.normalized_action_digest,
        adapter_manifest_digest=adapter.manifest.digest,
        authorization_round_id=stage_permit.authorization_round_id,
        authorization_round_digest=stage_permit.authorization_round_digest,
        lease_id=stage_permit.lease_id,
        worker_id=stage_permit.worker_id,
        fencing_token=stage_permit.fencing_token,
        phase=VerificationPhase.STAGED,
        subject_ref=staged_receipt_artifact.digest,
        authority_permit_digest=stage_permit.permit_digest,
        authority_permit_ref=stage_permit_artifact.digest,
        subject_permit_digest=stage_permit.permit_digest,
        subject_permit_ref=stage_permit_artifact.digest,
        issued_at=stage_permit.issued_at,
        deadline=deadline,
    )
    verification_permit_artifact = artifacts.put_model(verification_permit)
    staged_verification = await adapter.verify_staged(
        staged_receipt,
        VerifyContext(
            deadline=deadline,
            worker_id=verification_permit.worker_id,
            phase=VerificationPhase.STAGED,
            permit=verification_permit,
            permit_ref=verification_permit_artifact.digest,
            normalized_action=action,
            normalized_action_ref=action_artifact.digest,
            subject_ref=staged_receipt_artifact.digest,
        ),
    )
    assert staged_verification.status is VerificationStatus.PASS

    staged_verification_artifact = artifacts.put_model(staged_verification)
    approval_artifact = artifacts.put(b"approval-not-required")
    precommit_inspection = InspectionPermit.create(
        tenant_id=inspection.tenant_id,
        transaction_id=inspection.transaction_id,
        intent_hash=inspection.intent_hash,
        normalized_action_digest=inspection.normalized_action_digest,
        proposal_ref=inspection.proposal_ref,
        adapter_manifest_digest=inspection.adapter_manifest_digest,
        authorization_round_id="authorization_round:commit",
        authorization_round_digest=canonical_digest({"round": "commit"}),
        lease_id=stage_permit.lease_id,
        worker_id=stage_permit.worker_id,
        fencing_token=stage_permit.fencing_token,
        issued_at=inspection.issued_at,
        deadline=deadline,
    )
    precommit_inspection_artifact = artifacts.put_model(precommit_inspection)
    precommit_plan = plan.model_copy(update={"plan_id": "plan:precommit"})
    precommit_plan_artifact = artifacts.put_model(precommit_plan)
    commit_permit = CommitPermit.create(
        tenant_id=inspection.tenant_id,
        transaction_id=inspection.transaction_id,
        intent_hash=inspection.intent_hash,
        normalized_action_digest=inspection.normalized_action_digest,
        dispatch_id="dispatch:test",
        stage_id=staged.stage_id,
        plan_digest=canonical_digest(plan),
        plan_ref=plan_artifact.digest,
        stage_permit_digest=stage_permit.permit_digest,
        stage_permit_ref=stage_permit_artifact.digest,
        lease_id=stage_permit.lease_id,
        worker_id=stage_permit.worker_id,
        fencing_token=stage_permit.fencing_token,
        idempotency_key=plan.intent_hash,
        target_version_guard=plan.base_version,
        staged_receipt_ref=staged_receipt_artifact.digest,
        staged_state_digest=staged_receipt.staged_state_digest,
        staged_verification_permit_digest=verification_permit.permit_digest,
        staged_verification_permit_ref=verification_permit_artifact.digest,
        staged_verification_ref=staged_verification_artifact.digest,
        precommit_inspection_permit_digest=precommit_inspection.permit_digest,
        precommit_inspection_permit_ref=precommit_inspection_artifact.digest,
        precommit_plan_digest=canonical_digest(precommit_plan),
        precommit_plan_ref=precommit_plan_artifact.digest,
        approval_required=False,
        approval_evidence_ref=approval_artifact.digest,
        adapter_manifest_digest=adapter.manifest.digest,
        authority_decision_digest=canonical_digest({"authority": "allow"}),
        policy_decision_digest=canonical_digest({"policy": "allow"}),
        policy_snapshot_digest=canonical_digest({"policy": "snapshot"}),
        authorization_round_id="authorization_round:commit",
        authorization_round_digest=canonical_digest({"round": "commit"}),
        capability_reservation_digest=canonical_digest({"reservation": "committed"}),
        reservation_version=1,
        owner_version=0,
        owner_history_sequence=0,
        owner_history_digest=canonical_digest({"owner": "history"}),
        issued_at=inspection.issued_at,
        deadline=deadline,
    )
    commit_permit_artifact = artifacts.put_model(commit_permit)
    effect = await adapter.commit(
        staged_receipt,
        CommitContext(
            deadline=deadline,
            fencing_token=commit_permit.fencing_token,
            idempotency_key=commit_permit.idempotency_key,
            target_version_guard=commit_permit.target_version_guard,
            permit=commit_permit,
            permit_ref=commit_permit_artifact.digest,
            normalized_action=action,
            normalized_action_ref=action_artifact.digest,
        ),
    )

    assert adapter.requires_permits is True
    assert effect.intent_hash == plan.intent_hash
    assert target.state == {"before": "kept", "answer": "42"}

    newer_values = commit_permit.model_dump(mode="python", exclude={"permit_digest"})
    newer_values.update(
        {
            "dispatch_id": "dispatch:new-owner",
            "owner_version": 1,
            "fencing_token": 1,
        }
    )
    newer_owner = CommitPermit.create(**newer_values)
    newer_ref = artifacts.put_model(newer_owner).digest
    with pytest.raises(AgentKernelError) as changed_generation:
        await adapter.commit(
            staged_receipt,
            CommitContext(
                deadline=deadline,
                fencing_token=newer_owner.fencing_token,
                idempotency_key=newer_owner.idempotency_key,
                target_version_guard=newer_owner.target_version_guard,
                permit=newer_owner,
                permit_ref=newer_ref,
                normalized_action=action,
                normalized_action_ref=action_artifact.digest,
            ),
        )
    assert changed_generation.value.code is ErrorCode.INTEGRITY_ERROR
    assert (
        await adapter.commit(
            staged_receipt,
            CommitContext(
                deadline=deadline,
                fencing_token=commit_permit.fencing_token,
                idempotency_key=commit_permit.idempotency_key,
                target_version_guard=commit_permit.target_version_guard,
                permit=commit_permit,
                permit_ref=commit_permit_artifact.digest,
                normalized_action=action,
                normalized_action_ref=action_artifact.digest,
            ),
        )
        == effect
    )
    assert target.intent_fences[(action.tenant_id, plan.intent_hash)] == (0, 7)


@pytest.mark.asyncio
async def test_enforced_mock_rejects_missing_artifact_before_fence_or_target_read(
    tmp_path,
    proposal: ActionProposal,
) -> None:
    deadline = datetime.now(UTC) + timedelta(minutes=5)
    request = proposal.model_copy(update={"deadline": deadline})
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    target = VersionedMemoryTarget({"canary": "untouched"})
    adapter = MockReversibleAdapter(target, require_permits=True, artifacts=artifacts)
    action = _normalized_action(request, adapter)
    permit = _inspection_permit(request, adapter, action, fencing_token=7)

    with pytest.raises(AgentKernelError) as captured:
        await adapter.inspect(
            request,
            ReadOnlyContext(
                deadline=deadline,
                worker_id=permit.worker_id,
                permit=permit,
                permit_ref=canonical_digest(permit),
                normalized_action=action,
                normalized_action_ref=canonical_digest(action),
                proposal=request,
                proposal_ref=canonical_digest(request),
            ),
        )

    assert captured.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
    assert target.state == {"canary": "untouched"}
    assert target.transaction_fences == {}


@pytest.mark.asyncio
async def test_enforced_mock_reconciles_bound_absent_dispatch_as_no_effect(
    tmp_path,
    proposal: ActionProposal,
) -> None:
    deadline = datetime.now(UTC) + timedelta(minutes=5)
    request = proposal.model_copy(update={"deadline": deadline})
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    target = VersionedMemoryTarget({"canary": "untouched"})
    adapter = MockReversibleAdapter(target, require_permits=True, artifacts=artifacts)
    action = _normalized_action(request, adapter)
    action_ref = artifacts.put_model(action).digest
    target_evidence_ref = artifacts.put(b"coordinator:durable-dispatch").digest
    owner_history_digest = canonical_digest({"owner": "mock-absence"})
    recovery_context, permit = _absence_recovery_context(
        adapter=adapter,
        artifacts=artifacts,
        target_action=action,
        target_action_ref=action_ref,
        target_evidence_ref=target_evidence_ref,
        target_id="dispatch:mock-absence",
        target_version_guard=str(target.version),
        target_owner_version=4,
        target_owner_history_sequence=9,
        target_owner_history_digest=owner_history_digest,
        fencing_token=23,
    )
    intent = IntentRecord(
        intent_hash=action.intent_hash,
        transaction_id=request.transaction_id,
        idempotency_key=action.intent_hash,
        dispatched=True,
        created_at=datetime.now(UTC),
    )

    changed_values = permit.model_dump(mode="python", exclude={"permit_digest"})
    changed_values["target_version_guard"] = "different-version"
    changed_permit = RecoveryPermit.create(**changed_values)
    changed_permit_ref = artifacts.put_model(changed_permit).digest
    with pytest.raises(AgentKernelError) as changed_binding:
        await adapter.reconcile(
            intent,
            RecoveryContext(
                changed_permit.deadline,
                changed_permit.authorization_round_digest,
                changed_permit.worker_id,
                changed_permit,
                changed_permit_ref,
            ),
        )
    assert changed_binding.value.code is ErrorCode.INTEGRITY_ERROR
    assert target.intent_fences == {}

    report = await adapter.reconcile(intent, recovery_context)

    assert report.status is ReconcileStatus.NO_EFFECT
    assert len(report.evidence_refs) == 1
    assert target.state == {"canary": "untouched"}
    assert target.version == 0
    assert target.dispatches == {}
    assert target.intent_fences[(action.tenant_id, action.intent_hash)] == (4, 23)
    observation = AdapterObservation.model_validate_json(artifacts.get(report.evidence_refs[0]))
    assert observation.normalized_action_digest == action_ref
    assert observation.subject_ref == canonical_digest(intent)
    assert observation.operation_permit_ref == canonical_digest(permit)
    assert observation.authority_permit_ref == canonical_digest(permit)
    assert observation.subject_authority_ref == target_evidence_ref
    assert observation.operation_status == ReconcileStatus.NO_EFFECT.value
    assert observation.observed_state_digest == target.digest
    assert observation.dispatch_id == permit.target_id
    assert observation.owner_version == permit.target_owner_version
    assert observation.owner_history_sequence == permit.target_owner_history_sequence
    assert observation.owner_history_digest == permit.target_owner_history_digest
    assert observation.durable_state_digest == canonical_digest(
        {
            "profile": "agentkernel.adapter.dispatch-absence/v1",
            "adapter_manifest_digest": adapter.manifest.digest,
            "tenant_id": permit.tenant_id,
            "intent_hash": intent.intent_hash,
            "dispatch_id": permit.target_id,
            "owner_version": permit.target_owner_version,
            "owner_history_sequence": permit.target_owner_history_sequence,
            "owner_history_digest": permit.target_owner_history_digest,
            "reservation_present": False,
        }
    )


@pytest.mark.asyncio
async def test_mock_fence_survives_adapter_recreation(
    tmp_path,
    proposal: ActionProposal,
) -> None:
    deadline = datetime.now(UTC) + timedelta(minutes=5)
    request = proposal.model_copy(update={"deadline": deadline})
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    target = VersionedMemoryTarget()
    first = MockReversibleAdapter(target, require_permits=True, artifacts=artifacts)
    action = _normalized_action(request, first)
    action_ref = artifacts.put_model(action).digest
    proposal_ref = artifacts.put_model(request).digest
    accepted = _inspection_permit(request, first, action, fencing_token=9)
    accepted_ref = artifacts.put_model(accepted).digest
    await first.inspect(
        request,
        ReadOnlyContext(
            deadline=deadline,
            worker_id=accepted.worker_id,
            permit=accepted,
            permit_ref=accepted_ref,
            normalized_action=action,
            normalized_action_ref=action_ref,
            proposal=request,
            proposal_ref=proposal_ref,
        ),
    )

    restarted = MockReversibleAdapter(target, require_permits=True, artifacts=artifacts)
    stale = _inspection_permit(request, restarted, action, fencing_token=8)
    stale_ref = artifacts.put_model(stale).digest
    with pytest.raises(AgentKernelError) as captured:
        await restarted.inspect(
            request,
            ReadOnlyContext(
                deadline=deadline,
                worker_id=stale.worker_id,
                permit=stale,
                permit_ref=stale_ref,
                normalized_action=action,
                normalized_action_ref=action_ref,
                proposal=request,
                proposal_ref=proposal_ref,
            ),
        )

    assert captured.value.code is ErrorCode.AUTHORITY_REVOKED
    assert target.transaction_fences == {(action.tenant_id, request.transaction_id): 9}
    assert target.version == 0


@pytest.mark.asyncio
async def test_mock_prepared_dispatch_is_reconciled_never_resent(
    proposal: ActionProposal,
) -> None:
    class CrashAfterEffect(MockReversibleAdapter):
        def _fault_point(self, name: str) -> None:
            if name == "commit.after_effect":
                raise RuntimeError("simulated lost acknowledgement")

    target = VersionedMemoryTarget()
    adapter = CrashAfterEffect(target)
    plan = await adapter.inspect(proposal, ReadOnlyContext(proposal.deadline))
    staged = await adapter.stage(plan, StageContext(proposal.deadline, "worker:test"))
    staged_receipt = await adapter.execute(
        staged,
        StageContext(proposal.deadline, "worker:test"),
    )
    commit_context = CommitContext(
        proposal.deadline,
        1,
        plan.intent_hash,
        plan.base_version,
    )
    with pytest.raises(RuntimeError, match="lost acknowledgement"):
        await adapter.commit(staged_receipt, commit_context)
    version_after_first_effect = target.version

    with pytest.raises(AgentKernelError) as captured:
        await adapter.commit(staged_receipt, commit_context)
    report = await adapter.reconcile(
        IntentRecord(
            intent_hash=plan.intent_hash,
            transaction_id=proposal.transaction_id,
            idempotency_key=plan.intent_hash,
            dispatched=True,
            created_at=datetime.now(UTC),
        ),
        RecoveryContext(proposal.deadline, "authority:test"),
    )

    assert captured.value.code is ErrorCode.EXTERNAL_RESULT_IN_DOUBT
    assert target.version == version_after_first_effect == 1
    assert report.status.value == "COMMITTED"


@pytest.mark.asyncio
async def test_independent_mock_intents_do_not_share_a_global_fence(
    proposal: ActionProposal,
) -> None:
    target = VersionedMemoryTarget()
    adapter = MockReversibleAdapter(target)

    first_plan = await adapter.inspect(proposal, ReadOnlyContext(proposal.deadline))
    first_stage = await adapter.stage(
        first_plan,
        StageContext(proposal.deadline, "worker:first"),
    )
    first_receipt = await adapter.execute(
        first_stage,
        StageContext(proposal.deadline, "worker:first"),
    )
    await adapter.commit(
        first_receipt,
        CommitContext(proposal.deadline, 99, first_plan.intent_hash, first_plan.base_version),
    )

    second_proposal = proposal.model_copy(
        update={
            "transaction_id": "tx_independent",
            "arguments": {"values": {"second": "effect"}},
        }
    )
    second_plan = await adapter.inspect(second_proposal, ReadOnlyContext(proposal.deadline))
    second_stage = await adapter.stage(
        second_plan,
        StageContext(proposal.deadline, "worker:second"),
    )
    second_receipt = await adapter.execute(
        second_stage,
        StageContext(proposal.deadline, "worker:second"),
    )
    await adapter.commit(
        second_receipt,
        CommitContext(
            proposal.deadline,
            1,
            second_plan.intent_hash,
            second_plan.base_version,
        ),
    )

    assert target.version == 2
    assert target.intent_fences[("tenant:embedded", first_plan.intent_hash)] == (0, 99)
    assert target.intent_fences[("tenant:embedded", second_plan.intent_hash)] == (0, 1)


@pytest.mark.asyncio
async def test_mock_rejects_unicode_normalization_collision(
    proposal: ActionProposal,
) -> None:
    target = VersionedMemoryTarget()
    adapter = MockReversibleAdapter(target)
    decomposed = proposal.model_copy(update={"arguments": {"values": {"answer": "e\u0301"}}})

    with pytest.raises(AgentKernelError) as captured:
        await adapter.inspect(decomposed, ReadOnlyContext(proposal.deadline))

    assert captured.value.code is ErrorCode.VALIDATION_ERROR
    assert target.version == 0


def test_registry_pins_digest_and_review_admission() -> None:
    registry = AdapterRegistry()
    adapter = MockReversibleAdapter(VersionedMemoryTarget())
    digest = registry.register(adapter, reviewed=False)
    assert registry.resolve("mock", expected_digest=digest, enforcement_profile=False) is adapter

    with pytest.raises(AgentKernelError) as unreviewed:
        registry.resolve("mock", expected_digest=digest, enforcement_profile=True)
    assert unreviewed.value.code is ErrorCode.AUTHORITY_MISSING

    with pytest.raises(AgentKernelError) as mismatch:
        registry.resolve(
            "mock",
            expected_digest="sha256:" + "0" * 64,
            enforcement_profile=False,
        )
    assert mismatch.value.code is ErrorCode.INTEGRITY_ERROR


def test_registry_rejects_manifest_mutation_after_admission() -> None:
    registry = AdapterRegistry()
    adapter = MockReversibleAdapter(VersionedMemoryTarget())
    digest = registry.register(adapter, reviewed=True)
    adapter.manifest.operations["set_values"] = adapter.manifest.operations[
        "set_values"
    ].model_copy(update={"rollback": False})

    with pytest.raises(AgentKernelError) as captured:
        registry.resolve("mock", expected_digest=digest, enforcement_profile=True)

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
