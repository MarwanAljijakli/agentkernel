from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from agentkernel.adapters.base import (
    CommitContext,
    ReadOnlyContext,
    ReconcileStatus,
    RecoveryContext,
    StageContext,
    VerifyContext,
)
from agentkernel.adapters.filesystem import FilesystemAdapter
from agentkernel.domain.enums import VerificationStatus
from agentkernel.domain.models import ActionProposal, IntentRecord
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.snapshots.filesystem import snapshot_tree


def _filesystem_proposal(proposal: ActionProposal) -> ActionProposal:
    return proposal.model_copy(
        update={
            "transaction_id": "tx_filesystem",
            "adapter": "filesystem",
            "operation": "write_files",
            "arguments": {"files": {"src/result.txt": "verified\n"}},
        }
    )


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
        ReadOnlyContext(request.deadline),
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
