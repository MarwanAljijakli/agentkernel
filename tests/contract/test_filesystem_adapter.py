from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from agentkernel.adapters.base import (
    RECOVERY_ACTION_BINDING_ARGUMENT,
    CommitContext,
    ReadOnlyContext,
    ReconcileStatus,
    RecoveryContext,
    StageContext,
    VerifyContext,
)
from agentkernel.adapters.filesystem import FilesystemAdapter
from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import ProvenanceTrust, RecoveryWorkKind, VerificationStatus
from agentkernel.domain.models import (
    ActionProposal,
    AdapterObservation,
    AuthenticatedActionContext,
    InspectionPermit,
    IntentRecord,
    NormalizedAction,
    NormalizedProvenance,
    RecoveryActionBinding,
    RecoveryPermit,
    SemanticArgument,
    StagePermit,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.artifacts import LocalArtifactStore
from agentkernel.normalization.base import AdmittedOperation
from agentkernel.normalization.filesystem import FilesystemWriteFilesNormalizer
from agentkernel.snapshots.filesystem import snapshot_tree


def test_enforced_filesystem_fails_closed_without_handle_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(os, "O_NOFOLLOW", 0, raising=False)
    with pytest.raises(AgentKernelError) as raised:
        FilesystemAdapter(
            workspace=workspace,
            state_root=tmp_path / "state",
            require_permits=True,
        )
    assert raised.value.code is ErrorCode.UNSUPPORTED_SEMANTICS


@pytest.mark.skipif(os.name != "nt", reason="native Windows-only rejection contract")
def test_native_windows_enforced_filesystem_is_explicitly_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(AgentKernelError) as raised:
        FilesystemAdapter(
            workspace=workspace,
            state_root=tmp_path / "state",
            require_permits=True,
        )
    assert raised.value.code is ErrorCode.UNSUPPORTED_SEMANTICS


def _filesystem_proposal(proposal: ActionProposal) -> ActionProposal:
    return proposal.model_copy(
        update={
            "transaction_id": "tx_filesystem",
            "adapter": "filesystem",
            "adapter_version": "0.2.0",
            "operation": "write_files",
            "arguments": {"files": {"src/result.txt": "verified\n"}},
            "deadline": datetime.now(UTC) + timedelta(minutes=5),
        }
    )


def _normalized_action(
    proposal: ActionProposal,
    adapter: FilesystemAdapter,
) -> NormalizedAction:
    normalizer = FilesystemWriteFilesNormalizer()
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
    adapter: FilesystemAdapter,
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


def _stage_discard_recovery_permit(
    *,
    adapter: FilesystemAdapter,
    artifacts: LocalArtifactStore,
    target_action: NormalizedAction,
    target_action_ref: str,
    target_id: str,
    target_evidence_ref: str,
    target_version_guard: str,
    recovery_id: str,
    recovery_action_transaction_id: str,
    target_owner_version: int,
    fencing_token: int,
    deadline: datetime,
) -> tuple[RecoveryPermit, str]:
    """Issue a semantically bound discard permit for the enforced adapter contract."""

    issued_at = datetime.now(UTC)
    target_owner_history_digest = canonical_digest({"target-owner": "history"})
    binding = RecoveryActionBinding(
        target_transaction_id=target_action.transaction_id,
        target_intent_hash=target_action.intent_hash,
        target_normalized_action_digest=target_action_ref,
        recovery_kind=RecoveryWorkKind.DISCARD_STAGING,
        target_id=target_id,
        target_evidence_ref=target_evidence_ref,
        target_version_guard=target_version_guard,
        target_owner_version=target_owner_version,
        target_owner_history_sequence=0,
        target_owner_history_digest=target_owner_history_digest,
        adapter_manifest_digest=adapter.manifest.digest,
        risk_class=target_action.risk_floor,
        effect_domains=target_action.effect_domains,
        resource_uses_digest=canonical_digest(target_action.resource_uses),
        recovery_id=recovery_id,
        root_recovery_id=recovery_id,
        recovery_ordinal=1,
        max_recovery_attempts=3,
        not_before=issued_at,
        absolute_deadline=deadline,
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
            trace_id=f"trace:{recovery_id}",
            actor_id=target_action.actor_id,
            on_behalf_of=target_action.on_behalf_of,
            agent_id=target_action.agent_id,
            configuration_digest=target_action.configuration_digest,
        ),
        transaction_id=recovery_action_transaction_id,
        deadline=deadline,
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
                key=lambda argument: argument.sort_key(),
            )
        ),
        provenance=target_action.provenance,
    )
    recovery_action_ref = artifacts.put_model(recovery_action).digest
    permit = RecoveryPermit.create(
        tenant_id=target_action.tenant_id,
        transaction_id=target_action.transaction_id,
        intent_hash=target_action.intent_hash,
        recovery_id=recovery_id,
        recovery_action_transaction_id=recovery_action.transaction_id,
        recovery_action_intent_hash=recovery_action.intent_hash,
        recovery_action_digest=recovery_action_ref,
        adapter_manifest_digest=adapter.manifest.digest,
        recovery_kind=RecoveryWorkKind.DISCARD_STAGING,
        target_id=target_id,
        target_owner_version=target_owner_version,
        target_owner_history_sequence=0,
        target_owner_history_digest=target_owner_history_digest,
        target_evidence_ref=target_evidence_ref,
        target_version_guard=target_version_guard,
        authorization_round_id=f"authorization_round:{recovery_id}",
        authorization_round_digest=canonical_digest({"round": recovery_id}),
        authority_decision_digest=canonical_digest({"authority": recovery_id}),
        policy_decision_digest=canonical_digest({"policy": recovery_id}),
        policy_snapshot_digest=canonical_digest({"snapshot": recovery_id}),
        capability_reservation_digest=canonical_digest({"reservation": recovery_id}),
        reservation_version=1,
        owner_version=0,
        owner_history_sequence=0,
        owner_history_digest=canonical_digest({"recovery-owner": recovery_id}),
        approval_required=False,
        approval_evidence_ref=artifacts.put(b"recovery-approval-not-required").digest,
        lease_id=f"lease:{recovery_id}",
        worker_id="worker:recovery",
        fencing_token=fencing_token,
        issued_at=issued_at,
        deadline=deadline,
    )
    return permit, artifacts.put_model(permit).digest


@pytest.mark.asyncio
async def test_filesystem_stage_commit_verify_and_rollback(
    tmp_path: Path, proposal: ActionProposal
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "protected.txt").write_text("unchanged", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    request = _filesystem_proposal(proposal)
    before = snapshot_tree(workspace)
    plan = await adapter.inspect(request, ReadOnlyContext(request.deadline))
    staged = await adapter.stage(plan, StageContext(request.deadline, "worker:test"))
    receipt = await adapter.execute(staged, StageContext(request.deadline, "worker:test"))
    assert snapshot_tree(workspace).digest == before.digest
    staged_report = await adapter.verify_staged(receipt, VerifyContext(request.deadline))
    assert staged_report.status is VerificationStatus.PASS

    effect = await adapter.commit(
        receipt,
        CommitContext(request.deadline, 1, plan.intent_hash, plan.base_version),
    )
    assert (workspace / "src" / "result.txt").read_text(encoding="utf-8") == "verified\n"
    assert (workspace / "protected.txt").read_text(encoding="utf-8") == "unchanged"
    committed_report = await adapter.verify_committed(effect, VerifyContext(request.deadline))
    assert committed_report.status is VerificationStatus.PASS

    rollback = await adapter.rollback(
        effect,
        RecoveryContext(request.deadline, "authority:test"),
    )
    assert rollback.status is VerificationStatus.PASS
    assert snapshot_tree(workspace).digest == before.digest


@pytest.mark.asyncio
async def test_filesystem_abort_leaves_authoritative_workspace_unchanged(
    tmp_path: Path, proposal: ActionProposal
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "before.txt").write_text("kept", encoding="utf-8")
    adapter = FilesystemAdapter(workspace=workspace, state_root=tmp_path / "state")
    request = _filesystem_proposal(proposal)
    before = snapshot_tree(workspace)
    plan = await adapter.inspect(request, ReadOnlyContext(request.deadline))
    staged = await adapter.stage(plan, StageContext(request.deadline, "worker:test"))
    receipt = await adapter.execute(staged, StageContext(request.deadline, "worker:test"))
    report = await adapter.abort(
        receipt,
        RecoveryContext(request.deadline, "authority:test"),
    )
    assert report.status is VerificationStatus.PASS
    assert snapshot_tree(workspace).digest == before.digest


@pytest.mark.asyncio
async def test_filesystem_recovery_metadata_survives_adapter_restart(
    tmp_path: Path, proposal: ActionProposal
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "before.txt").write_text("kept", encoding="utf-8")
    state_root = tmp_path / "state"
    request = _filesystem_proposal(proposal)
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    before = snapshot_tree(workspace)
    plan = await adapter.inspect(request, ReadOnlyContext(request.deadline))
    staged = await adapter.stage(plan, StageContext(request.deadline, "worker:test"))
    staged_receipt = await adapter.execute(staged, StageContext(request.deadline, "worker:test"))
    effect = await adapter.commit(
        staged_receipt,
        CommitContext(request.deadline, 1, plan.intent_hash, plan.base_version),
    )

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    verification = await restarted.verify_committed(effect, VerifyContext(request.deadline))
    reconciliation = await restarted.reconcile(
        IntentRecord(
            intent_hash=effect.intent_hash,
            transaction_id=effect.transaction_id,
            idempotency_key=effect.intent_hash,
            dispatched=True,
            outcome_receipt_ref=None,
            created_at=effect.created_at,
        ),
        RecoveryContext(request.deadline, "authority:test"),
    )
    rollback = await restarted.rollback(
        effect,
        RecoveryContext(request.deadline, "authority:test"),
    )

    assert verification.status is VerificationStatus.PASS
    assert reconciliation.status is ReconcileStatus.COMMITTED
    assert rollback.status is VerificationStatus.PASS
    assert snapshot_tree(workspace).digest == before.digest


@pytest.mark.asyncio
async def test_filesystem_rollback_refuses_to_destroy_later_work(
    tmp_path: Path, proposal: ActionProposal
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    request = _filesystem_proposal(proposal)
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    plan = await adapter.inspect(request, ReadOnlyContext(request.deadline))
    staged = await adapter.stage(plan, StageContext(request.deadline, "worker:test"))
    staged_receipt = await adapter.execute(staged, StageContext(request.deadline, "worker:test"))
    effect = await adapter.commit(
        staged_receipt,
        CommitContext(request.deadline, 1, plan.intent_hash, plan.base_version),
    )
    (workspace / "later.txt").write_text("valuable", encoding="utf-8")

    rollback = await adapter.rollback(
        effect,
        RecoveryContext(request.deadline, "authority:test"),
    )

    assert rollback.status is VerificationStatus.UNKNOWN
    assert rollback.residual_effects == ("target_version_changed_after_commit",)
    assert (workspace / "later.txt").read_text(encoding="utf-8") == "valuable"


@pytest.mark.asyncio
async def test_filesystem_rollback_refuses_a_tampered_backup(
    tmp_path: Path, proposal: ActionProposal
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "before.txt").write_text("original", encoding="utf-8")
    state_root = tmp_path / "state"
    request = _filesystem_proposal(proposal)
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    plan = await adapter.inspect(request, ReadOnlyContext(request.deadline))
    staged = await adapter.stage(plan, StageContext(request.deadline, "worker:test"))
    staged_receipt = await adapter.execute(staged, StageContext(request.deadline, "worker:test"))
    effect = await adapter.commit(
        staged_receipt,
        CommitContext(request.deadline, 1, plan.intent_hash, plan.base_version),
    )
    backup_file = state_root / "recovery" / effect.receipt_id / "backup" / "before.txt"
    backup_file.write_text("CORRUPTED", encoding="utf-8")

    rollback = await adapter.rollback(
        effect,
        RecoveryContext(request.deadline, "authority:test"),
    )

    assert rollback.status is VerificationStatus.ERROR
    assert rollback.residual_effects == ("backup_integrity_mismatch",)
    assert (workspace / "before.txt").read_text(encoding="utf-8") == "original"
    assert (workspace / "src" / "result.txt").read_text(encoding="utf-8") == "verified\n"


@pytest.mark.asyncio
@pytest.mark.skipif(os.name == "nt", reason="native Windows enforced backend fails closed")
async def test_enforced_filesystem_stage_uses_durable_coordinator_id_and_can_abort_by_id(
    tmp_path: Path,
    proposal: ActionProposal,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "before.txt").write_text("kept", encoding="utf-8")
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    deadline = datetime.now(UTC) + timedelta(minutes=5)
    request = _filesystem_proposal(proposal).model_copy(update={"deadline": deadline})
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=tmp_path / "state",
        require_permits=True,
        artifacts=artifacts,
    )
    before = snapshot_tree(workspace).digest
    action = _normalized_action(request, adapter)
    action_ref = artifacts.put_model(action).digest
    proposal_ref = artifacts.put_model(request).digest
    inspection = _inspection_permit(request, adapter, action, fencing_token=11)
    inspection_ref = artifacts.put_model(inspection).digest
    plan = await adapter.inspect(
        request,
        ReadOnlyContext(
            deadline=deadline,
            worker_id=inspection.worker_id,
            permit=inspection,
            permit_ref=inspection_ref,
            normalized_action=action,
            normalized_action_ref=action_ref,
            proposal=request,
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
        stage_id="stage:coordinator",
        lease_id=inspection.lease_id,
        worker_id=inspection.worker_id,
        fencing_token=inspection.fencing_token,
        target_version_guard=plan.base_version,
        issued_at=inspection.issued_at,
        deadline=deadline,
    )
    stage_ref = artifacts.put_model(stage_permit).digest
    stage_context = StageContext(
        deadline=deadline,
        worker_id=stage_permit.worker_id,
        permit=stage_permit,
        permit_ref=stage_ref,
        normalized_action=action,
        normalized_action_ref=action_ref,
    )

    staged = await adapter.stage(plan, stage_context)
    assert staged.stage_id == "stage:coordinator"
    assert snapshot_tree(workspace).digest == before
    assert list((tmp_path / "state" / "stages").glob("*/manifest.json"))

    target_evidence = artifacts.put(b"durable-stage-record")
    recovery_permit, recovery_ref = _stage_discard_recovery_permit(
        adapter=adapter,
        artifacts=artifacts,
        target_action=action,
        target_action_ref=action_ref,
        target_id=staged.stage_id,
        target_evidence_ref=target_evidence.digest,
        target_version_guard=plan.base_version,
        recovery_id="recovery:discard-stage",
        recovery_action_transaction_id="tx:recovery-discard-stage",
        target_owner_version=0,
        fencing_token=12,
        deadline=deadline,
    )
    discarded = await adapter.abort_stage(
        staged.stage_id,
        RecoveryContext(
            deadline,
            recovery_permit.authorization_round_digest,
            recovery_permit.worker_id,
            recovery_permit,
            recovery_ref,
        ),
    )

    assert discarded.status is VerificationStatus.PASS
    assert len(discarded.evidence_refs) == 1
    discard_observation = artifacts.get_model(
        discarded.evidence_refs[0],
        AdapterObservation,
    )
    assert discard_observation.evidence_kind == "discard_staging"
    assert discard_observation.subject_ref == target_evidence.digest
    assert discard_observation.operation_permit_ref == recovery_ref
    assert discard_observation.subject_authority_ref == target_evidence.digest
    assert snapshot_tree(workspace).digest == before
    assert list((tmp_path / "state" / "stages").iterdir()) == []

    newer_owner, newer_ref = _stage_discard_recovery_permit(
        adapter=adapter,
        artifacts=artifacts,
        target_action=action,
        target_action_ref=action_ref,
        target_id=staged.stage_id,
        target_evidence_ref=target_evidence.digest,
        target_version_guard=plan.base_version,
        recovery_id="recovery:new-target-owner",
        recovery_action_transaction_id="tx:recovery-new-target-owner",
        target_owner_version=1,
        fencing_token=13,
        deadline=deadline,
    )
    await adapter.abort_stage(
        staged.stage_id,
        RecoveryContext(
            deadline,
            newer_owner.authorization_round_digest,
            newer_owner.worker_id,
            newer_owner,
            newer_ref,
        ),
    )
    with pytest.raises(AgentKernelError) as stale_owner:
        await adapter.abort_stage(
            staged.stage_id,
            RecoveryContext(
                deadline,
                recovery_permit.authorization_round_digest,
                recovery_permit.worker_id,
                recovery_permit,
                recovery_ref,
            ),
        )
    assert stale_owner.value.code is ErrorCode.AUTHORITY_REVOKED


@pytest.mark.asyncio
@pytest.mark.skipif(os.name == "nt", reason="native Windows enforced backend fails closed")
async def test_filesystem_fence_is_sqlite_durable_and_precedes_target_read(
    tmp_path: Path,
    proposal: ActionProposal,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    state_root = tmp_path / "state"
    deadline = datetime.now(UTC) + timedelta(minutes=5)
    request = _filesystem_proposal(proposal).model_copy(update={"deadline": deadline})
    first = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    action = _normalized_action(request, first)
    action_ref = artifacts.put_model(action).digest
    proposal_ref = artifacts.put_model(request).digest
    accepted = _inspection_permit(request, first, action, fencing_token=15)
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

    with sqlite3.connect(state_root / "adapter.sqlite3") as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute(
            """
            SELECT highwater FROM transaction_fences
            WHERE tenant_id = ? AND transaction_id = ?
            """,
            (action.tenant_id, request.transaction_id),
        ).fetchone() == (15,)

    restarted = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    stale = _inspection_permit(request, restarted, action, fencing_token=14)
    stale_ref = artifacts.put_model(stale).digest
    outside = tmp_path / "outside"
    outside.write_text("canary", encoding="utf-8")
    link = workspace / "linked"
    try:
        link.symlink_to(outside)
    except OSError:
        link = None

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
    assert outside.read_text(encoding="utf-8") == "canary"
    if link is not None:
        link.unlink()

    independent_request = request.model_copy(update={"transaction_id": "tx_independent"})
    independent_action = _normalized_action(independent_request, restarted)
    independent_action_ref = artifacts.put_model(independent_action).digest
    independent_proposal_ref = artifacts.put_model(independent_request).digest
    independent = _inspection_permit(
        independent_request,
        restarted,
        independent_action,
        fencing_token=1,
    )
    independent_ref = artifacts.put_model(independent).digest
    await restarted.inspect(
        independent_request,
        ReadOnlyContext(
            deadline=deadline,
            worker_id=independent.worker_id,
            permit=independent,
            permit_ref=independent_ref,
            normalized_action=independent_action,
            normalized_action_ref=independent_action_ref,
            proposal=independent_request,
            proposal_ref=independent_proposal_ref,
        ),
    )
    with sqlite3.connect(state_root / "adapter.sqlite3") as connection:
        assert connection.execute(
            """
            SELECT highwater FROM transaction_fences
            WHERE tenant_id = ? AND transaction_id = ?
            """,
            (independent_action.tenant_id, independent_request.transaction_id),
        ).fetchone() == (1,)


@pytest.mark.asyncio
@pytest.mark.skipif(os.name == "nt", reason="native Windows enforced backend fails closed")
async def test_filesystem_missing_permit_artifact_fails_before_target_read(
    tmp_path: Path,
    proposal: ActionProposal,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("canary", encoding="utf-8")
    link = workspace / "linked"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is not permitted for this test user")
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    deadline = datetime.now(UTC) + timedelta(minutes=5)
    request = _filesystem_proposal(proposal).model_copy(update={"deadline": deadline})
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=tmp_path / "state",
        require_permits=True,
        artifacts=artifacts,
    )
    action = _normalized_action(request, adapter)
    permit = _inspection_permit(request, adapter, action, fencing_token=3)

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
    assert outside.read_text(encoding="utf-8") == "canary"


@pytest.mark.asyncio
async def test_filesystem_rejects_unicode_normalization_collision(
    tmp_path: Path,
    proposal: ActionProposal,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    adapter = FilesystemAdapter(workspace=workspace, state_root=tmp_path / "state")
    request = _filesystem_proposal(proposal).model_copy(
        update={"arguments": {"files": {"result.txt": "e\u0301"}}}
    )

    with pytest.raises(AgentKernelError) as captured:
        await adapter.inspect(request, ReadOnlyContext(request.deadline))

    assert captured.value.code is ErrorCode.VALIDATION_ERROR
    assert list(workspace.iterdir()) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "files",
    [
        {"A.txt": "upper", "a.txt": "lower"},
        {"foo": "plain", "foo.": "dot alias"},
        {"parent": "file", "parent/child.txt": "child"},
    ],
)
async def test_filesystem_inspection_rejects_aliased_or_conflicting_paths(
    tmp_path: Path,
    proposal: ActionProposal,
    files: dict[str, str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    adapter = FilesystemAdapter(workspace=workspace, state_root=tmp_path / "state")
    request = _filesystem_proposal(proposal).model_copy(update={"arguments": {"files": files}})

    with pytest.raises(AgentKernelError) as captured:
        await adapter.inspect(request, ReadOnlyContext(request.deadline))

    assert captured.value.code is ErrorCode.VALIDATION_ERROR
    assert list(workspace.iterdir()) == []


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junction regression is Windows-only")
@pytest.mark.parametrize("private_child", ["stages", "recovery"])
def test_filesystem_rejects_junctioned_private_state_roots(
    tmp_path: Path,
    private_child: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    outside = tmp_path / f"outside-{private_child}"
    outside.mkdir()
    junction = state_root / private_child
    command_processor = Path(os.environ["SYSTEMROOT"]) / "System32" / "cmd.exe"
    created = subprocess.run(  # noqa: S603
        [str(command_processor), "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        check=False,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip("junction creation is not permitted for this test user")
    try:
        with pytest.raises(AgentKernelError, match="private state"):
            FilesystemAdapter(workspace=workspace, state_root=state_root)
        assert list(outside.iterdir()) == []
    finally:
        junction.rmdir()
