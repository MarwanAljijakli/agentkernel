from __future__ import annotations

import asyncio
import multiprocessing
import os
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
)
from agentkernel.adapters.filesystem import FilesystemAdapter
from agentkernel.canonical import canonical_digest, canonical_json_bytes
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
    Artifact,
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
from agentkernel.normalization.filesystem import FilesystemWriteFilesNormalizer
from agentkernel.snapshots.filesystem import snapshot_tree

_CRASH_EXIT_CODE = 86


class _SubstitutingEvidenceStore:
    """Test boundary that preserves valid JSON while substituting one semantic artifact."""

    def __init__(
        self,
        delegate: LocalArtifactStore,
        substitutions: dict[str, bytes],
    ) -> None:
        self._delegate = delegate
        self._substitutions = substitutions

    def put(
        self,
        content: bytes,
        *,
        media_type: str = "application/octet-stream",
    ) -> Artifact:
        return self._delegate.put(content, media_type=media_type)

    def get(self, digest: str) -> bytes:
        return self._substitutions.get(digest, self._delegate.get(digest))


class _CrashFilesystemAdapter(FilesystemAdapter):
    def __init__(
        self,
        *,
        crash_point: str,
        workspace: Path,
        state_root: Path,
        artifacts: LocalArtifactStore,
    ) -> None:
        self._crash_point_name = crash_point
        super().__init__(
            workspace=workspace,
            state_root=state_root,
            require_permits=True,
            artifacts=artifacts,
        )

    def _fault_point(self, name: str) -> None:
        if name == self._crash_point_name:
            os._exit(_CRASH_EXIT_CODE)


class _BarrierFilesystemAdapter(FilesystemAdapter):
    def __init__(
        self,
        *,
        barrier_name: str,
        entered: threading.Event,
        release: threading.Event,
        workspace: Path,
        state_root: Path,
        artifacts: LocalArtifactStore,
    ) -> None:
        self._barrier_name = barrier_name
        self._entered = entered
        self._release = release
        super().__init__(
            workspace=workspace,
            state_root=state_root,
            require_permits=True,
            artifacts=artifacts,
        )

    def _fault_point(self, name: str) -> None:
        if name != self._barrier_name:
            return
        self._entered.set()
        if not self._release.wait(timeout=3):
            raise AssertionError(f"fault barrier timed out: {name}")


@dataclass(frozen=True, slots=True)
class _PreparedDispatch:
    proposal: ActionProposal
    action: NormalizedAction
    action_ref: str
    staged_receipt: StagedReceipt
    staged_receipt_ref: str
    stage_permit: StagePermit
    stage_permit_ref: str
    commit_permit: CommitPermit
    commit_permit_ref: str
    before_digest: str


def _normalized_action(
    proposal: ActionProposal,
    adapter: FilesystemAdapter,
) -> NormalizedAction:
    normalizer = FilesystemWriteFilesNormalizer()
    context = AuthenticatedActionContext(
        tenant_id="tenant:crash-test",
        principal_id="principal:crash-test",
        goal_id=proposal.goal_id,
        run_id="run:crash-test",
        trace_id="trace:crash-test",
        actor_id="actor:crash-test",
        on_behalf_of="principal:crash-test",
        agent_id=proposal.agent_id,
        configuration_digest=normalizer.configuration_digest,
    )
    provenance = tuple(
        NormalizedProvenance(
            provenance_id=provenance_id,
            trust=ProvenanceTrust.MODEL_GENERATED,
            record_digest=canonical_digest({"provenance": provenance_id}),
        )
        for provenance_id in sorted(proposal.provenance_ids)
    )
    return normalizer.normalize(
        proposal=proposal,
        context=context,
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
        provenance=provenance,
    )


async def _prepare_dispatch(
    *,
    workspace: Path,
    state_root: Path,
    artifacts: LocalArtifactStore,
) -> _PreparedDispatch:
    deadline = datetime.now(UTC) + timedelta(minutes=10)
    issued_at = datetime.now(UTC)
    proposal = ActionProposal(
        goal_id="goal:crash",
        transaction_id="tx:crash",
        agent_id="agent:crash-test",
        adapter="filesystem",
        adapter_version="0.2.0",
        operation="write_files",
        arguments={"files": {"a.txt": "one", "b.txt": "two"}},
        provenance_ids=("provenance:crash-test",),
        deadline=deadline,
    )
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    before_digest = snapshot_tree(workspace).digest
    action = _normalized_action(proposal, adapter)
    action_ref = artifacts.put_model(action).digest
    proposal_ref = artifacts.put_model(proposal).digest
    inspection = InspectionPermit.create(
        tenant_id=action.tenant_id,
        transaction_id=proposal.transaction_id,
        intent_hash=action.intent_hash,
        normalized_action_digest=action_ref,
        proposal_ref=proposal_ref,
        adapter_manifest_digest=adapter.manifest.digest,
        authorization_round_id="authorization_round:stage",
        authorization_round_digest=canonical_digest({"round": "stage"}),
        lease_id="lease:crash-test",
        worker_id="worker:crash-test",
        fencing_token=11,
        issued_at=issued_at,
        deadline=deadline,
    )
    inspection_ref = artifacts.put_model(inspection).digest
    plan = await adapter.inspect(
        proposal,
        ReadOnlyContext(
            deadline=deadline,
            worker_id=inspection.worker_id,
            permit=inspection,
            permit_ref=inspection_ref,
            normalized_action=action,
            normalized_action_ref=action_ref,
            proposal=proposal,
            proposal_ref=proposal_ref,
        ),
    )
    plan_ref = artifacts.put_model(plan).digest
    stage_permit = StagePermit.create(
        tenant_id=inspection.tenant_id,
        transaction_id=inspection.transaction_id,
        intent_hash=inspection.intent_hash,
        normalized_action_digest=inspection.normalized_action_digest,
        adapter_manifest_digest=inspection.adapter_manifest_digest,
        authorization_round_id=inspection.authorization_round_id,
        authorization_round_digest=inspection.authorization_round_digest,
        inspection_permit_digest=inspection.permit_digest,
        inspection_permit_ref=inspection_ref,
        plan_digest=canonical_digest(plan),
        plan_ref=plan_ref,
        stage_id="stage:crash-test",
        lease_id=inspection.lease_id,
        worker_id=inspection.worker_id,
        fencing_token=inspection.fencing_token,
        target_version_guard=plan.base_version,
        issued_at=issued_at,
        deadline=deadline,
    )
    stage_permit_ref = artifacts.put_model(stage_permit).digest
    stage_context = StageContext(
        deadline=deadline,
        worker_id=stage_permit.worker_id,
        permit=stage_permit,
        permit_ref=stage_permit_ref,
        normalized_action=action,
        normalized_action_ref=action_ref,
    )
    staged = await adapter.stage(plan, stage_context)
    staged_receipt = await adapter.execute(staged, stage_context)
    staged_receipt_ref = artifacts.put_model(staged_receipt).digest
    staged_verification_permit = VerificationPermit.create(
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
        subject_ref=staged_receipt_ref,
        authority_permit_digest=stage_permit.permit_digest,
        authority_permit_ref=stage_permit_ref,
        subject_permit_digest=stage_permit.permit_digest,
        subject_permit_ref=stage_permit_ref,
        issued_at=issued_at,
        deadline=deadline,
    )
    staged_verification_permit_ref = artifacts.put_model(staged_verification_permit).digest
    staged_verification = await adapter.verify_staged(
        staged_receipt,
        VerifyContext(
            deadline=deadline,
            worker_id=staged_verification_permit.worker_id,
            phase=VerificationPhase.STAGED,
            permit=staged_verification_permit,
            permit_ref=staged_verification_permit_ref,
            normalized_action=action,
            normalized_action_ref=action_ref,
            subject_ref=staged_receipt_ref,
        ),
    )
    assert staged_verification.status is VerificationStatus.PASS
    assert staged_verification.evidence_refs
    for evidence_ref in staged_verification.evidence_refs:
        content = artifacts.get(evidence_ref)
        observation = AdapterObservation.model_validate_json(content)
        assert canonical_json_bytes(observation) == content
        assert observation.tenant_id == staged_verification_permit.tenant_id
        assert observation.operation_permit_ref == staged_verification_permit_ref
        assert observation.authority_permit_ref == stage_permit_ref
        assert observation.subject_authority_ref == stage_permit_ref
    staged_verification_ref = artifacts.put_model(staged_verification).digest

    precommit_inspection = InspectionPermit.create(
        tenant_id=inspection.tenant_id,
        transaction_id=inspection.transaction_id,
        intent_hash=inspection.intent_hash,
        normalized_action_digest=inspection.normalized_action_digest,
        proposal_ref=inspection.proposal_ref,
        adapter_manifest_digest=inspection.adapter_manifest_digest,
        authorization_round_id="authorization_round:commit",
        authorization_round_digest=canonical_digest({"round": "commit"}),
        lease_id=inspection.lease_id,
        worker_id=inspection.worker_id,
        fencing_token=inspection.fencing_token,
        issued_at=issued_at,
        deadline=deadline,
    )
    precommit_inspection_ref = artifacts.put_model(precommit_inspection).digest
    precommit_plan = plan.model_copy(update={"plan_id": "plan:precommit-crash"})
    precommit_plan_ref = artifacts.put_model(precommit_plan).digest
    approval_ref = artifacts.put(b"approval-not-required").digest
    commit_permit = CommitPermit.create(
        tenant_id=inspection.tenant_id,
        transaction_id=inspection.transaction_id,
        intent_hash=inspection.intent_hash,
        normalized_action_digest=inspection.normalized_action_digest,
        dispatch_id="dispatch:crash-test",
        stage_id=staged.stage_id,
        plan_digest=canonical_digest(plan),
        plan_ref=plan_ref,
        stage_permit_digest=stage_permit.permit_digest,
        stage_permit_ref=stage_permit_ref,
        lease_id=stage_permit.lease_id,
        worker_id=stage_permit.worker_id,
        fencing_token=stage_permit.fencing_token,
        idempotency_key=plan.intent_hash,
        target_version_guard=plan.base_version,
        staged_receipt_ref=staged_receipt_ref,
        staged_state_digest=staged_receipt.staged_state_digest,
        staged_verification_permit_digest=staged_verification_permit.permit_digest,
        staged_verification_permit_ref=staged_verification_permit_ref,
        staged_verification_ref=staged_verification_ref,
        precommit_inspection_permit_digest=precommit_inspection.permit_digest,
        precommit_inspection_permit_ref=precommit_inspection_ref,
        precommit_plan_digest=canonical_digest(precommit_plan),
        precommit_plan_ref=precommit_plan_ref,
        approval_required=False,
        approval_evidence_ref=approval_ref,
        adapter_manifest_digest=adapter.manifest.digest,
        authority_decision_digest=artifacts.put(b"authority:allow").digest,
        policy_decision_digest=artifacts.put(b"policy:allow").digest,
        policy_snapshot_digest=artifacts.put(b"policy:snapshot").digest,
        authorization_round_id=precommit_inspection.authorization_round_id,
        authorization_round_digest=precommit_inspection.authorization_round_digest,
        capability_reservation_digest=artifacts.put(b"capability:reserved").digest,
        reservation_version=1,
        owner_version=0,
        owner_history_sequence=0,
        owner_history_digest=canonical_digest({"owner": "initial"}),
        issued_at=issued_at,
        deadline=deadline,
    )
    commit_permit_ref = artifacts.put_model(commit_permit).digest
    return _PreparedDispatch(
        proposal=proposal,
        action=action,
        action_ref=action_ref,
        staged_receipt=staged_receipt,
        staged_receipt_ref=staged_receipt_ref,
        stage_permit=stage_permit,
        stage_permit_ref=stage_permit_ref,
        commit_permit=commit_permit,
        commit_permit_ref=commit_permit_ref,
        before_digest=before_digest,
    )


def _commit_and_crash(
    workspace: Path,
    state_root: Path,
    artifact_root: Path,
    staged_receipt_ref: str,
    action_ref: str,
    commit_permit_ref: str,
    crash_point: str,
) -> None:
    artifacts = LocalArtifactStore(artifact_root)
    receipt = artifacts.get_model(staged_receipt_ref, StagedReceipt)
    action = artifacts.get_model(action_ref, NormalizedAction)
    permit = artifacts.get_model(commit_permit_ref, CommitPermit)
    adapter = _CrashFilesystemAdapter(
        crash_point=crash_point,
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    asyncio.run(
        adapter.commit(
            receipt,
            CommitContext(
                deadline=permit.deadline,
                fencing_token=permit.fencing_token,
                idempotency_key=permit.idempotency_key,
                target_version_guard=permit.target_version_guard,
                permit=permit,
                permit_ref=commit_permit_ref,
                normalized_action=action,
                normalized_action_ref=action_ref,
            ),
        )
    )


def _recovery_context(
    *,
    adapter: FilesystemAdapter,
    artifacts: LocalArtifactStore,
    prepared: _PreparedDispatch,
    kind: RecoveryWorkKind,
    fencing_token: int,
) -> tuple[RecoveryContext, RecoveryPermit]:
    target = prepared.action
    permit = prepared.commit_permit
    now = datetime.now(UTC)
    recovery_id = f"recovery:{kind.value.lower()}:{fencing_token}"
    binding = RecoveryActionBinding(
        target_transaction_id=prepared.proposal.transaction_id,
        target_intent_hash=target.intent_hash,
        target_normalized_action_digest=prepared.action_ref,
        recovery_kind=kind,
        target_id=permit.dispatch_id,
        target_evidence_ref=prepared.commit_permit_ref,
        target_version_guard=permit.target_version_guard,
        target_owner_version=permit.owner_version,
        target_owner_history_sequence=permit.owner_history_sequence,
        target_owner_history_digest=permit.owner_history_digest,
        adapter_manifest_digest=adapter.manifest.digest,
        risk_class=target.risk_floor,
        effect_domains=target.effect_domains,
        resource_uses_digest=canonical_digest(target.resource_uses),
        recovery_id=recovery_id,
        root_recovery_id=recovery_id,
        recovery_ordinal=1,
        max_recovery_attempts=3,
        not_before=now,
        absolute_deadline=prepared.proposal.deadline,
    )
    binding_artifact = artifacts.put_model(binding)
    binding_argument = SemanticArgument(
        argument_name=RECOVERY_ACTION_BINDING_ARGUMENT,
        resource=target.resource_uses[0].canonical_resource,
        digest=binding_artifact.digest,
        size_bytes=binding_artifact.size_bytes,
        media_type="application/vnd.agentkernel.canonical+json",
    )
    semantic_arguments = tuple(
        sorted((*target.semantic_arguments, binding_argument), key=lambda item: item.sort_key())
    )
    recovery_action = NormalizedAction.create(
        context=AuthenticatedActionContext(
            tenant_id=target.tenant_id,
            principal_id=target.principal_id,
            goal_id=target.goal_id,
            run_id=target.run_id,
            trace_id=f"trace:recovery:{fencing_token}",
            actor_id=target.actor_id,
            on_behalf_of=target.on_behalf_of,
            agent_id=target.agent_id,
            configuration_digest=target.configuration_digest,
        ),
        transaction_id=f"tx:recovery:{fencing_token}",
        deadline=binding.absolute_deadline,
        idempotency_key=recovery_id,
        adapter=target.adapter,
        adapter_version=target.adapter_version,
        adapter_manifest_digest=target.adapter_manifest_digest,
        operation=target.operation,
        normalizer_implementation=target.normalizer_implementation,
        normalizer_version=target.normalizer_version,
        normalizer_digest=target.normalizer_digest,
        operation_schema_ref=target.operation_schema_ref,
        operation_schema_digest=target.operation_schema_digest,
        risk_floor=target.risk_floor,
        effect_domains=target.effect_domains,
        resource_uses=target.resource_uses,
        semantic_arguments=semantic_arguments,
        provenance=target.provenance,
    )
    recovery_action_ref = artifacts.put_model(recovery_action).digest
    approval_ref = artifacts.put(b"recovery-approval-not-required").digest
    recovery_permit = RecoveryPermit.create(
        tenant_id=target.tenant_id,
        transaction_id=prepared.proposal.transaction_id,
        intent_hash=target.intent_hash,
        recovery_id=recovery_id,
        recovery_action_transaction_id=recovery_action.transaction_id,
        recovery_action_intent_hash=recovery_action.intent_hash,
        recovery_action_digest=recovery_action_ref,
        adapter_manifest_digest=adapter.manifest.digest,
        recovery_kind=kind,
        target_id=permit.dispatch_id,
        target_owner_version=permit.owner_version,
        target_owner_history_sequence=permit.owner_history_sequence,
        target_owner_history_digest=permit.owner_history_digest,
        target_evidence_ref=prepared.commit_permit_ref,
        target_version_guard=permit.target_version_guard,
        authorization_round_id=f"authorization_round:recovery:{fencing_token}",
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
        lease_id=f"lease:recovery:{fencing_token}",
        worker_id=f"worker:recovery:{fencing_token}",
        fencing_token=fencing_token,
        issued_at=now,
        deadline=prepared.proposal.deadline,
    )
    recovery_permit_ref = artifacts.put_model(recovery_permit).digest
    return (
        RecoveryContext(
            prepared.proposal.deadline,
            recovery_permit.authorization_round_digest,
            recovery_permit.worker_id,
            recovery_permit,
            recovery_permit_ref,
        ),
        recovery_permit,
    )


def _commit_context(prepared: _PreparedDispatch) -> CommitContext:
    permit = prepared.commit_permit
    return CommitContext(
        deadline=permit.deadline,
        fencing_token=permit.fencing_token,
        idempotency_key=permit.idempotency_key,
        target_version_guard=permit.target_version_guard,
        permit=permit,
        permit_ref=prepared.commit_permit_ref,
        normalized_action=prepared.action,
        normalized_action_ref=prepared.action_ref,
    )


def _verification_context(
    *,
    prepared: _PreparedDispatch,
    artifacts: LocalArtifactStore,
    phase: VerificationPhase,
    subject_ref: str,
    authority: StagePermit | CommitPermit | RecoveryPermit,
    authority_ref: str,
    subject_permit: StagePermit | CommitPermit,
    subject_permit_ref: str,
) -> tuple[VerifyContext, VerificationPermit]:
    permit = VerificationPermit.create(
        tenant_id=authority.tenant_id,
        transaction_id=prepared.proposal.transaction_id,
        intent_hash=prepared.action.intent_hash,
        normalized_action_digest=prepared.action_ref,
        adapter_manifest_digest=prepared.action.adapter_manifest_digest,
        authorization_round_id=authority.authorization_round_id,
        authorization_round_digest=authority.authorization_round_digest,
        lease_id=authority.lease_id,
        worker_id=authority.worker_id,
        fencing_token=authority.fencing_token,
        phase=phase,
        subject_ref=subject_ref,
        authority_permit_digest=authority.permit_digest,
        authority_permit_ref=authority_ref,
        subject_permit_digest=subject_permit.permit_digest,
        subject_permit_ref=subject_permit_ref,
        issued_at=authority.issued_at,
        deadline=authority.deadline,
    )
    permit_ref = artifacts.put_model(permit).digest
    return (
        VerifyContext(
            deadline=permit.deadline,
            worker_id=permit.worker_id,
            phase=phase,
            permit=permit,
            permit_ref=permit_ref,
            normalized_action=prepared.action,
            normalized_action_ref=prepared.action_ref,
            subject_ref=subject_ref,
        ),
        permit,
    )


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="enforced handle backend requires POSIX")
async def test_filesystem_cancel_before_dispatch_has_no_effect(tmp_path: Path) -> None:
    class PauseUntilCancelled(FilesystemAdapter):
        entered: threading.Event

        def _commit_sync(
            self,
            receipt: StagedReceipt,
            ctx: CommitContext,
            cancellation: BlockingCancellation,
        ) -> EffectReceipt:
            self.entered.set()
            deadline = time.monotonic() + 2
            while not cancellation.requested:
                if time.monotonic() >= deadline:
                    raise AssertionError("cancellation signal was not delivered")
                time.sleep(0.001)
            return super()._commit_sync(receipt, ctx, cancellation)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "kept.txt").write_text("before", encoding="utf-8")
    state_root = tmp_path / "state"
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    prepared = await _prepare_dispatch(
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    adapter = PauseUntilCancelled(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    adapter.entered = threading.Event()
    task = asyncio.create_task(adapter.commit(prepared.staged_receipt, _commit_context(prepared)))
    assert await asyncio.to_thread(adapter.entered.wait, 1)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=2)

    assert snapshot_tree(workspace).digest == prepared.before_digest
    with sqlite3.connect(state_root / "adapter.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM adapter_dispatches").fetchone() == (0,)


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="enforced handle backend requires POSIX")
async def test_filesystem_reconciles_bound_absent_dispatch_as_no_effect(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "kept.txt").write_text("before", encoding="utf-8")
    state_root = tmp_path / "state"
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    prepared = await _prepare_dispatch(
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    recovery_context, permit = _recovery_context(
        adapter=adapter,
        artifacts=artifacts,
        prepared=prepared,
        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        fencing_token=20,
    )
    intent = IntentRecord(
        intent_hash=prepared.action.intent_hash,
        transaction_id=prepared.proposal.transaction_id,
        idempotency_key=prepared.action.intent_hash,
        dispatched=True,
        created_at=datetime.now(UTC),
    )

    report = await adapter.reconcile(intent, recovery_context)

    assert report.status is ReconcileStatus.NO_EFFECT
    assert len(report.evidence_refs) == 1
    assert snapshot_tree(workspace).digest == prepared.before_digest
    with sqlite3.connect(state_root / "adapter.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM adapter_dispatches").fetchone() == (0,)
    observation = AdapterObservation.model_validate_json(artifacts.get(report.evidence_refs[0]))
    assert observation.normalized_action_digest == prepared.action_ref
    assert observation.subject_ref == canonical_digest(intent)
    assert observation.operation_permit_ref == canonical_digest(permit)
    assert observation.authority_permit_ref == canonical_digest(permit)
    assert observation.subject_authority_ref == prepared.commit_permit_ref
    assert observation.operation_status == ReconcileStatus.NO_EFFECT.value
    assert observation.observed_state_digest == prepared.before_digest
    assert observation.dispatch_id == prepared.commit_permit.dispatch_id
    assert observation.owner_version == prepared.commit_permit.owner_version
    assert observation.owner_history_sequence == prepared.commit_permit.owner_history_sequence
    assert observation.owner_history_digest == prepared.commit_permit.owner_history_digest
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


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="enforced handle backend requires POSIX")
async def test_filesystem_absence_observation_fences_cross_instance_stale_commit(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "kept.txt").write_text("before", encoding="utf-8")
    state_root = tmp_path / "state"
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    prepared = await _prepare_dispatch(
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    entered = threading.Event()
    release = threading.Event()
    stale_adapter = _BarrierFilesystemAdapter(
        barrier_name="commit.before_dispatch",
        entered=entered,
        release=release,
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    recovery_adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    recovery_context, _ = _recovery_context(
        adapter=recovery_adapter,
        artifacts=artifacts,
        prepared=prepared,
        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        fencing_token=20,
    )
    intent = IntentRecord(
        intent_hash=prepared.action.intent_hash,
        transaction_id=prepared.proposal.transaction_id,
        idempotency_key=prepared.action.intent_hash,
        dispatched=True,
        created_at=datetime.now(UTC),
    )
    stale_commit = asyncio.create_task(
        stale_adapter.commit(prepared.staged_receipt, _commit_context(prepared))
    )
    assert await asyncio.to_thread(entered.wait, 1)

    try:
        report = await recovery_adapter.reconcile(intent, recovery_context)
    finally:
        release.set()

    assert report.status is ReconcileStatus.NO_EFFECT
    with pytest.raises(AgentKernelError) as stale:
        await asyncio.wait_for(stale_commit, timeout=2)
    assert stale.value.code is ErrorCode.AUTHORITY_REVOKED
    assert snapshot_tree(workspace).digest == prepared.before_digest
    with sqlite3.connect(state_root / "adapter.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM adapter_dispatches").fetchone() == (0,)


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="enforced handle backend requires POSIX")
async def test_filesystem_timeout_after_dispatch_is_quiescent_and_reconcilable(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "kept.txt").write_text("before", encoding="utf-8")
    state_root = tmp_path / "state"
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    prepared = await _prepare_dispatch(
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    entered = threading.Event()
    release = threading.Event()
    adapter = _BarrierFilesystemAdapter(
        barrier_name="commit.after_prepared",
        entered=entered,
        release=release,
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    commit_task = asyncio.create_task(
        adapter.commit(prepared.staged_receipt, _commit_context(prepared))
    )
    assert await asyncio.to_thread(entered.wait, 1)
    event_loop_responded = asyncio.Event()

    async def release_worker() -> None:
        await asyncio.sleep(0.05)
        event_loop_responded.set()
        release.set()

    releaser = asyncio.create_task(release_worker())
    started_at = time.monotonic()
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.01):
            await commit_task
    elapsed = time.monotonic() - started_at
    await releaser

    assert event_loop_responded.is_set()
    assert 0.03 <= elapsed < 1
    after_effect = snapshot_tree(workspace).digest
    assert after_effect != prepared.before_digest
    restarted = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    retry = await restarted.commit(prepared.staged_receipt, _commit_context(prepared))
    assert snapshot_tree(workspace).digest == after_effect
    recovery_context, _ = _recovery_context(
        adapter=restarted,
        artifacts=artifacts,
        prepared=prepared,
        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        fencing_token=20,
    )
    report = await restarted.reconcile(
        IntentRecord(
            intent_hash=prepared.action.intent_hash,
            transaction_id=prepared.proposal.transaction_id,
            idempotency_key=prepared.action.intent_hash,
            dispatched=True,
            created_at=datetime.now(UTC),
        ),
        recovery_context,
    )
    assert report.status is ReconcileStatus.COMMITTED
    assert report.receipt == retry


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="enforced handle backend requires POSIX")
async def test_cross_instance_verification_is_serialized_by_sqlite_fence(
    tmp_path: Path,
) -> None:
    class ObservationProbe(FilesystemAdapter):
        observation_started: threading.Event

        def _fault_point(self, name: str) -> None:
            if name == "verify_committed.before_observation":
                self.observation_started.set()

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "kept.txt").write_text("before", encoding="utf-8")
    state_root = tmp_path / "state"
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    prepared = await _prepare_dispatch(
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    stage_permit = prepared.stage_permit
    old_staged_context, _ = _verification_context(
        prepared=prepared,
        artifacts=artifacts,
        phase=VerificationPhase.STAGED,
        subject_ref=prepared.staged_receipt_ref,
        authority=stage_permit,
        authority_ref=prepared.stage_permit_ref,
        subject_permit=stage_permit,
        subject_permit_ref=prepared.stage_permit_ref,
    )
    newer_stage_values = stage_permit.model_dump(mode="python", exclude={"permit_digest"})
    newer_stage_values["fencing_token"] = stage_permit.fencing_token + 1
    newer_stage_permit = StagePermit.create(**newer_stage_values)
    newer_stage_ref = artifacts.put_model(newer_stage_permit).digest
    newer_staged_context, _ = _verification_context(
        prepared=prepared,
        artifacts=artifacts,
        phase=VerificationPhase.STAGED,
        subject_ref=prepared.staged_receipt_ref,
        authority=newer_stage_permit,
        authority_ref=newer_stage_ref,
        subject_permit=newer_stage_permit,
        subject_permit_ref=newer_stage_ref,
    )
    staged_entered = threading.Event()
    staged_release = threading.Event()
    old_staged_adapter = _BarrierFilesystemAdapter(
        barrier_name="verify_staged.before_observation",
        entered=staged_entered,
        release=staged_release,
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    newer_staged_adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    old_staged_task = asyncio.create_task(
        old_staged_adapter.verify_staged(prepared.staged_receipt, old_staged_context)
    )
    assert await asyncio.to_thread(staged_entered.wait, 1)
    newer_staged_task = asyncio.create_task(
        newer_staged_adapter.verify_staged(prepared.staged_receipt, newer_staged_context)
    )
    await asyncio.sleep(0.05)
    assert not newer_staged_task.done()
    staged_release.set()
    old_staged_report = await asyncio.wait_for(old_staged_task, timeout=2)
    newer_staged_report = await asyncio.wait_for(newer_staged_task, timeout=2)
    assert old_staged_report.status is VerificationStatus.PASS
    assert newer_staged_report.status is VerificationStatus.PASS

    committing = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    effect = await committing.commit(prepared.staged_receipt, _commit_context(prepared))
    effect_ref = artifacts.put_model(effect).digest
    old_committed_context, _ = _verification_context(
        prepared=prepared,
        artifacts=artifacts,
        phase=VerificationPhase.COMMITTED,
        subject_ref=effect_ref,
        authority=prepared.commit_permit,
        authority_ref=prepared.commit_permit_ref,
        subject_permit=prepared.commit_permit,
        subject_permit_ref=prepared.commit_permit_ref,
    )
    _, recovery_authority = _recovery_context(
        adapter=committing,
        artifacts=artifacts,
        prepared=prepared,
        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        fencing_token=20,
    )
    recovery_authority_ref = canonical_digest(recovery_authority)
    newer_committed_context, _ = _verification_context(
        prepared=prepared,
        artifacts=artifacts,
        phase=VerificationPhase.COMMITTED,
        subject_ref=effect_ref,
        authority=recovery_authority,
        authority_ref=recovery_authority_ref,
        subject_permit=prepared.commit_permit,
        subject_permit_ref=prepared.commit_permit_ref,
    )
    committed_entered = threading.Event()
    committed_release = threading.Event()
    newer_committed_adapter = _BarrierFilesystemAdapter(
        barrier_name="verify_committed.before_observation",
        entered=committed_entered,
        release=committed_release,
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    old_committed_adapter = ObservationProbe(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    old_committed_adapter.observation_started = threading.Event()
    newer_committed_task = asyncio.create_task(
        newer_committed_adapter.verify_committed(effect, newer_committed_context)
    )
    assert await asyncio.to_thread(committed_entered.wait, 1)
    old_committed_task = asyncio.create_task(
        old_committed_adapter.verify_committed(effect, old_committed_context)
    )
    await asyncio.sleep(0.05)
    assert not old_committed_task.done()
    committed_release.set()
    newer_committed_report = await asyncio.wait_for(newer_committed_task, timeout=2)
    assert newer_committed_report.status is VerificationStatus.PASS
    with pytest.raises(AgentKernelError) as stale:
        await asyncio.wait_for(old_committed_task, timeout=2)
    assert stale.value.code is ErrorCode.AUTHORITY_REVOKED
    assert not old_committed_adapter.observation_started.is_set()


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="enforced handle backend requires POSIX")
async def test_preexisting_instance_reloads_commit_recovery_and_rollback_state(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "kept.txt").write_text("before", encoding="utf-8")
    state_root = tmp_path / "state"
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    prepared = await _prepare_dispatch(
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    preexisting = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    committing = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    assert preexisting._recovery_by_receipt == {}

    effect = await committing.commit(prepared.staged_receipt, _commit_context(prepared))
    assert preexisting._recovery_by_receipt == {}
    assert (
        await preexisting.commit(
            prepared.staged_receipt,
            _commit_context(prepared),
        )
        == effect
    )

    effect_ref = artifacts.put_model(effect).digest
    verification_context, _ = _verification_context(
        prepared=prepared,
        artifacts=artifacts,
        phase=VerificationPhase.COMMITTED,
        subject_ref=effect_ref,
        authority=prepared.commit_permit,
        authority_ref=prepared.commit_permit_ref,
        subject_permit=prepared.commit_permit,
        subject_permit_ref=prepared.commit_permit_ref,
    )
    verification = await preexisting.verify_committed(effect, verification_context)
    assert verification.status is VerificationStatus.PASS
    assert verification.evidence_refs
    verification_observation = AdapterObservation.model_validate_json(
        artifacts.get(verification.evidence_refs[-1])
    )
    assert verification_observation.dispatch_id == prepared.commit_permit.dispatch_id
    assert verification_observation.owner_version == prepared.commit_permit.owner_version

    intent = IntentRecord(
        intent_hash=prepared.action.intent_hash,
        transaction_id=prepared.proposal.transaction_id,
        idempotency_key=prepared.action.intent_hash,
        dispatched=True,
        created_at=datetime.now(UTC),
    )
    reconcile_context, _ = _recovery_context(
        adapter=preexisting,
        artifacts=artifacts,
        prepared=prepared,
        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        fencing_token=20,
    )
    reconciliation = await preexisting.reconcile(intent, reconcile_context)
    assert reconciliation.status is ReconcileStatus.COMMITTED
    assert reconciliation.receipt == effect
    assert reconciliation.evidence_refs

    rollback_context, _ = _recovery_context(
        adapter=preexisting,
        artifacts=artifacts,
        prepared=prepared,
        kind=RecoveryWorkKind.ROLLBACK,
        fencing_token=21,
    )
    rollback = await preexisting.rollback(effect, rollback_context)
    assert rollback.status is VerificationStatus.PASS
    assert rollback.evidence_refs
    rollback_observation = AdapterObservation.model_validate_json(
        artifacts.get(rollback.evidence_refs[-1])
    )
    assert rollback_observation.dispatch_id == prepared.commit_permit.dispatch_id
    assert rollback_observation.owner_version == prepared.commit_permit.owner_version
    assert snapshot_tree(workspace).digest == prepared.before_digest


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="private mode enforcement requires POSIX")
async def test_enforced_state_migrates_to_owner_only_and_seals_backup(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "a.txt").write_text("TOP-SECRET", encoding="utf-8")
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o755)
    (state_root / "stages").mkdir(mode=0o755)
    (state_root / "recovery").mkdir(mode=0o755)
    artifacts = LocalArtifactStore(tmp_path / "artifacts")

    prepared = await _prepare_dispatch(
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    effect = await adapter.commit(prepared.staged_receipt, _commit_context(prepared))
    receipt_root = state_root / "recovery" / effect.receipt_id
    backup_root = receipt_root / "backup"
    private_directories = (
        state_root,
        state_root / "stages",
        state_root / "recovery",
        receipt_root,
        backup_root,
    )
    for private_directory in private_directories:
        private_directory.chmod(0o755)
    FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )

    for private_directory in private_directories:
        metadata = private_directory.stat(follow_symlinks=False)
        assert metadata.st_uid == os.geteuid()
        assert stat.S_IMODE(metadata.st_mode) == 0o700
    assert (backup_root / "a.txt").read_text(encoding="utf-8") == "TOP-SECRET"


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="enforced handle backend requires POSIX")
async def test_previously_observed_reserved_manifest_cannot_disappear(
    tmp_path: Path,
) -> None:
    class StopAfterManifest(FilesystemAdapter):
        def _fault_point(self, name: str) -> None:
            if name == "commit.after_manifest_before_prepared":
                raise RuntimeError("stop after durable manifest")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "kept.txt").write_text("before", encoding="utf-8")
    state_root = tmp_path / "state"
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    prepared = await _prepare_dispatch(
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    adapter = StopAfterManifest(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    with pytest.raises(RuntimeError, match="durable manifest"):
        await adapter.commit(prepared.staged_receipt, _commit_context(prepared))

    with sqlite3.connect(state_root / "adapter.sqlite3") as connection:
        receipt_id, status = connection.execute(
            "SELECT receipt_id, status FROM adapter_dispatches"
        ).fetchone()
    assert status == "RESERVED"
    assert (prepared.action.tenant_id, receipt_id) in adapter._recovery_by_receipt
    manifest_path = state_root / "recovery" / receipt_id / "manifest.json"
    assert manifest_path.is_file()
    manifest_path.unlink()

    intent = IntentRecord(
        intent_hash=prepared.action.intent_hash,
        transaction_id=prepared.proposal.transaction_id,
        idempotency_key=prepared.action.intent_hash,
        dispatched=True,
        created_at=datetime.now(UTC),
    )
    recovery_context, _ = _recovery_context(
        adapter=adapter,
        artifacts=artifacts,
        prepared=prepared,
        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        fencing_token=20,
    )
    with pytest.raises(AgentKernelError) as disappeared:
        await adapter.reconcile(intent, recovery_context)
    assert disappeared.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
    assert snapshot_tree(workspace).digest == prepared.before_digest


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="enforced handle backend requires POSIX")
@pytest.mark.parametrize(
    ("fault_point", "durable_status"),
    [
        ("commit.after_prepared", "PREPARED"),
        ("commit.after_effect_started", "EFFECT_STARTED"),
    ],
)
async def test_missing_manifest_after_effect_admission_fails_closed(
    tmp_path: Path,
    fault_point: str,
    durable_status: str,
) -> None:
    class StopAtFault(FilesystemAdapter):
        def _fault_point(self, name: str) -> None:
            if name == fault_point:
                raise RuntimeError("stop after durable effect admission")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "kept.txt").write_text("before", encoding="utf-8")
    state_root = tmp_path / "state"
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    prepared = await _prepare_dispatch(
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    adapter = StopAtFault(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    with pytest.raises(RuntimeError, match="durable effect admission"):
        await adapter.commit(prepared.staged_receipt, _commit_context(prepared))

    with sqlite3.connect(state_root / "adapter.sqlite3") as connection:
        receipt_id, status = connection.execute(
            "SELECT receipt_id, status FROM adapter_dispatches"
        ).fetchone()
    assert status == durable_status
    manifest_path = state_root / "recovery" / receipt_id / "manifest.json"
    assert manifest_path.is_file()
    manifest_path.unlink()

    with pytest.raises(AgentKernelError) as missing:
        FilesystemAdapter(
            workspace=workspace,
            state_root=state_root,
            require_permits=True,
            artifacts=artifacts,
        )
    assert missing.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="enforced handle backend requires POSIX")
@pytest.mark.parametrize(
    ("crash_point", "expected_status"),
    [
        ("commit.after_backup_before_manifest", ReconcileStatus.NO_EFFECT),
        ("commit.after_prepared", ReconcileStatus.NO_EFFECT),
        ("commit.after_effect_started", ReconcileStatus.UNKNOWN),
        ("commit.after_change:a.txt", ReconcileStatus.PARTIAL_OR_INVALID),
        ("commit.after_effect", ReconcileStatus.COMMITTED),
        ("commit.after_committed", ReconcileStatus.COMMITTED),
    ],
)
async def test_enforced_process_kill_never_resends_and_recovery_is_explicit(
    tmp_path: Path,
    crash_point: str,
    expected_status: ReconcileStatus,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "kept.txt").write_text("before", encoding="utf-8")
    state_root = tmp_path / "state"
    artifact_root = tmp_path / "artifacts"
    artifacts = LocalArtifactStore(artifact_root)
    prepared = await _prepare_dispatch(
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )

    process = multiprocessing.get_context("spawn").Process(
        target=_commit_and_crash,
        args=(
            workspace,
            state_root,
            artifact_root,
            prepared.staged_receipt_ref,
            prepared.action_ref,
            prepared.commit_permit_ref,
            crash_point,
        ),
    )
    process.start()
    process.join(timeout=30)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
        pytest.fail("crash-injection child did not terminate")
    assert process.exitcode == _CRASH_EXIT_CODE

    restarted = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    before_retry = snapshot_tree(workspace).digest
    if crash_point == "commit.after_committed":
        retry_receipt = await restarted.commit(
            prepared.staged_receipt,
            _commit_context(prepared),
        )
        assert retry_receipt.intent_hash == prepared.action.intent_hash
    else:
        with pytest.raises(AgentKernelError) as duplicate:
            await restarted.commit(
                prepared.staged_receipt,
                _commit_context(prepared),
            )
        assert duplicate.value.code is ErrorCode.EXTERNAL_RESULT_IN_DOUBT
    assert snapshot_tree(workspace).digest == before_retry

    reconcile_context, recovery_permit = _recovery_context(
        adapter=restarted,
        artifacts=artifacts,
        prepared=prepared,
        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        fencing_token=20,
    )
    intent = IntentRecord(
        intent_hash=prepared.action.intent_hash,
        transaction_id=prepared.proposal.transaction_id,
        idempotency_key=prepared.action.intent_hash,
        dispatched=True,
        created_at=datetime.now(UTC),
    )
    reconciliation = await restarted.reconcile(intent, reconcile_context)
    assert reconciliation.status is expected_status
    assert reconciliation.evidence_refs
    for evidence_ref in reconciliation.evidence_refs:
        content = artifacts.get(evidence_ref)
        observation = AdapterObservation.model_validate_json(content)
        assert canonical_json_bytes(observation) == content
        assert observation.evidence_kind == "reconciliation"
        assert observation.tenant_id == recovery_permit.tenant_id
        assert observation.operation_status == expected_status.value
        assert observation.operation_permit_ref == reconcile_context.permit_ref
        assert observation.authority_permit_ref == reconcile_context.permit_ref
        assert observation.subject_authority_ref == prepared.commit_permit_ref

    if expected_status in {
        ReconcileStatus.UNKNOWN,
        ReconcileStatus.PARTIAL_OR_INVALID,
    }:
        manifest = restarted._recovery_by_intent[
            (prepared.action.tenant_id, prepared.action.intent_hash)
        ]
        rollback_context, _ = _recovery_context(
            adapter=restarted,
            artifacts=artifacts,
            prepared=prepared,
            kind=RecoveryWorkKind.ROLLBACK,
            fencing_token=21,
        )
        recovery = await restarted.rollback(manifest.effect_receipt, rollback_context)
        assert recovery.status is VerificationStatus.PASS
        assert recovery.evidence_refs
        assert snapshot_tree(workspace).digest == prepared.before_digest
    elif expected_status is ReconcileStatus.COMMITTED:
        assert reconciliation.receipt is not None
        receipt_ref = artifacts.put_model(reconciliation.receipt).digest
        verification_permit = VerificationPermit.create(
            tenant_id=recovery_permit.tenant_id,
            transaction_id=recovery_permit.transaction_id,
            intent_hash=recovery_permit.intent_hash,
            normalized_action_digest=prepared.action_ref,
            adapter_manifest_digest=restarted.manifest.digest,
            authorization_round_id=recovery_permit.authorization_round_id,
            authorization_round_digest=recovery_permit.authorization_round_digest,
            lease_id=recovery_permit.lease_id,
            worker_id=recovery_permit.worker_id,
            fencing_token=recovery_permit.fencing_token,
            phase=VerificationPhase.COMMITTED,
            subject_ref=receipt_ref,
            authority_permit_digest=recovery_permit.permit_digest,
            authority_permit_ref=canonical_digest(recovery_permit),
            subject_permit_digest=prepared.commit_permit.permit_digest,
            subject_permit_ref=prepared.commit_permit_ref,
            issued_at=recovery_permit.issued_at,
            deadline=recovery_permit.deadline,
        )
        verification_permit_ref = artifacts.put_model(verification_permit).digest
        verification = await restarted.verify_committed(
            reconciliation.receipt,
            VerifyContext(
                deadline=verification_permit.deadline,
                worker_id=verification_permit.worker_id,
                phase=VerificationPhase.COMMITTED,
                permit=verification_permit,
                permit_ref=verification_permit_ref,
                normalized_action=prepared.action,
                normalized_action_ref=prepared.action_ref,
                subject_ref=receipt_ref,
            ),
        )
        assert verification.status is VerificationStatus.PASS
        assert verification.evidence_refs
        for evidence_ref in verification.evidence_refs:
            content = artifacts.get(evidence_ref)
            observation = AdapterObservation.model_validate_json(content)
            assert canonical_json_bytes(observation) == content
            assert observation.tenant_id == verification_permit.tenant_id
            assert observation.operation_permit_ref == verification_permit_ref
            assert observation.authority_permit_ref == canonical_digest(recovery_permit)
            assert observation.subject_authority_ref == prepared.commit_permit_ref
    else:
        assert snapshot_tree(workspace).digest == prepared.before_digest

    if expected_status is ReconcileStatus.NO_EFFECT:
        observation_ref = reconciliation.evidence_refs[-1]
        observation = AdapterObservation.model_validate_json(artifacts.get(observation_ref))
        wrong_tenant_content = canonical_json_bytes(
            observation.model_copy(update={"tenant_id": "tenant:other"})
        )
        with pytest.raises(AgentKernelError) as wrong_tenant:
            FilesystemAdapter(
                workspace=workspace,
                state_root=state_root,
                require_permits=True,
                artifacts=_SubstitutingEvidenceStore(
                    artifacts,
                    {observation_ref: wrong_tenant_content},
                ),
            )
        assert wrong_tenant.value.code is ErrorCode.INTEGRITY_ERROR

        observation_path = artifacts._path_for(observation_ref)
        observation_path.write_bytes(b"tampered-observation")
        with pytest.raises(AgentKernelError) as tampered:
            FilesystemAdapter(
                workspace=workspace,
                state_root=state_root,
                require_permits=True,
                artifacts=artifacts,
            )
        assert tampered.value.code in {
            ErrorCode.INTEGRITY_ERROR,
            ErrorCode.EVIDENCE_UNAVAILABLE,
        }
