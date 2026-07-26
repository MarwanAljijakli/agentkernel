from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import agentkernel.adapters.filesystem as filesystem
import pytest
from agentkernel.adapters.base import (
    CommitContext,
    EffectPlan,
    EvidenceClock,
    ReadOnlyContext,
    ReconcileStatus,
    RecoveryContext,
    StageContext,
    StagedEffect,
    StagedReceipt,
    VerifyContext,
)
from agentkernel.adapters.filesystem import FilesystemAdapter
from agentkernel.canonical import canonical_digest, canonical_json_bytes, sha256_digest
from agentkernel.domain.enums import RecoveryWorkKind, VerificationStatus
from agentkernel.domain.models import ActionProposal, CommitPermit, EffectReceipt, IntentRecord
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.artifacts import LocalArtifactStore
from agentkernel.snapshots.filesystem import snapshot_tree
from tests.integration import test_fenced_adapter_crash_recovery as enforced_helpers

pytestmark = pytest.mark.integration

_POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix",
    reason="the enforced no-follow adapter backend exists only on POSIX",
)


@dataclass(frozen=True, slots=True)
class _PreparedStage:
    proposal: ActionProposal
    plan: EffectPlan
    staged: StagedEffect
    receipt: StagedReceipt
    before_digest: str


class _SimulatedProcessExit(BaseException):
    """Model process loss without letting the adapter's ordinary Exception handler repair state."""


class _FaultingFilesystemAdapter(FilesystemAdapter):
    _armed_fault: str | None = None
    _crash_like = True

    def arm(self, name: str, *, crash_like: bool = True) -> None:
        self._armed_fault = name
        self._crash_like = crash_like

    def _fault_point(self, name: str) -> None:
        if name != self._armed_fault:
            return
        self._armed_fault = None
        if self._crash_like:
            raise _SimulatedProcessExit(name)
        raise RuntimeError(f"injected filesystem failure: {name}")


def _proposal(
    files: dict[str, str],
    *,
    transaction_id: str = "tx:filesystem-edge",
    deadline: datetime | None = None,
) -> ActionProposal:
    return ActionProposal(
        goal_id="goal:filesystem-edge",
        transaction_id=transaction_id,
        agent_id="agent:filesystem-edge",
        adapter="filesystem",
        adapter_version="0.2.0",
        operation="write_files",
        arguments={"files": files},
        provenance_ids=("provenance:filesystem-edge",),
        deadline=deadline or datetime.now(UTC) + timedelta(minutes=10),
    )


async def _prepare_stage(
    adapter: FilesystemAdapter,
    files: dict[str, str],
    *,
    transaction_id: str = "tx:filesystem-edge",
) -> _PreparedStage:
    proposal = _proposal(files, transaction_id=transaction_id)
    before_digest = snapshot_tree(adapter.workspace).digest
    plan = await adapter.inspect(proposal, ReadOnlyContext(proposal.deadline))
    stage_context = StageContext(proposal.deadline, "worker:filesystem-edge")
    staged = await adapter.stage(plan, stage_context)
    receipt = await adapter.execute(staged, stage_context)
    return _PreparedStage(
        proposal=proposal,
        plan=plan,
        staged=staged,
        receipt=receipt,
        before_digest=before_digest,
    )


async def _commit_stage(
    adapter: FilesystemAdapter,
    prepared: _PreparedStage,
    *,
    deadline: datetime | None = None,
    fencing_token: int = 1,
) -> EffectReceipt:
    return await adapter.commit(
        prepared.receipt,
        CommitContext(
            deadline=deadline or prepared.proposal.deadline,
            fencing_token=fencing_token,
            idempotency_key=prepared.plan.intent_hash,
            target_version_guard=prepared.plan.base_version,
        ),
    )


def _intent(prepared: _PreparedStage) -> IntentRecord:
    return IntentRecord(
        intent_hash=prepared.plan.intent_hash,
        transaction_id=prepared.proposal.transaction_id,
        idempotency_key=prepared.plan.intent_hash,
        dispatched=True,
        outcome_receipt_ref=None,
        created_at=datetime.now(UTC),
    )


def _stage_manifest_path(state_root: Path, stage_id: str) -> Path:
    stage_key = canonical_digest({"stage_id": stage_id}).removeprefix("sha256:")
    return state_root / "stages" / stage_key / "manifest.json"


def _recovery_manifest_path(state_root: Path, receipt_id: str) -> Path:
    return state_root / "recovery" / receipt_id / "manifest.json"


def _read_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _write_canonical_json(path: Path, value: object) -> bytes:
    content = canonical_json_bytes(value)
    path.write_bytes(content)
    if os.name == "posix":
        path.chmod(0o600)
    return content


def _dispatch_row(state_root: Path) -> sqlite3.Row:
    connection = sqlite3.connect(state_root / "adapter.sqlite3")
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("SELECT * FROM adapter_dispatches").fetchall()
    finally:
        connection.close()
    assert len(rows) == 1
    return rows[0]


def _dispatch_count(state_root: Path) -> int:
    connection = sqlite3.connect(state_root / "adapter.sqlite3")
    try:
        return int(connection.execute("SELECT COUNT(*) FROM adapter_dispatches").fetchone()[0])
    finally:
        connection.close()


def test_live_tenant_cannot_alias_or_write_the_internal_legacy_fence_namespace(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=tmp_path / "state",
    )

    # This was the old, publicly valid sentinel name. It must now behave like an
    # ordinary tenant and must not raise the high-water mark for another tenant.
    adapter._accept_transaction_fence(
        "tenant:legacy-adapter-v2",
        "transaction:shared",
        100,
    )
    adapter._accept_transaction_fence("tenant:victim", "transaction:shared", 1)
    adapter._accept_intent_fence(
        "tenant:legacy-adapter-v2",
        "sha256:" + "1" * 64,
        9,
        100,
    )
    adapter._accept_intent_fence("tenant:victim", "sha256:" + "1" * 64, 0, 1)

    with sqlite3.connect(tmp_path / "state" / "adapter.sqlite3") as connection:
        transaction_rows = connection.execute(
            """
            SELECT tenant_id, highwater FROM transaction_fences
            WHERE transaction_id = ? ORDER BY tenant_id
            """,
            ("transaction:shared",),
        ).fetchall()
        intent_rows = connection.execute(
            """
            SELECT tenant_id, owner_version, highwater FROM intent_fences
            WHERE intent_hash = ? ORDER BY tenant_id
            """,
            ("sha256:" + "1" * 64,),
        ).fetchall()

    assert transaction_rows == [
        ("tenant:legacy-adapter-v2", 100),
        ("tenant:victim", 1),
    ]
    assert intent_rows == [
        ("tenant:legacy-adapter-v2", 9, 100),
        ("tenant:victim", 0, 1),
    ]

    with pytest.raises(AgentKernelError) as transaction_error:
        adapter._accept_transaction_fence(
            filesystem._LEGACY_TENANT_ID,
            "transaction:internal",
            1,
        )
    assert transaction_error.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as intent_error:
        adapter._accept_intent_fence(
            filesystem._LEGACY_TENANT_ID,
            "sha256:" + "2" * 64,
            0,
            1,
        )
    assert intent_error.value.code is ErrorCode.INTEGRITY_ERROR


def _raw_dispatch_row(adapter: FilesystemAdapter, state_root: Path) -> tuple[Any, ...]:
    connection = sqlite3.connect(state_root / "adapter.sqlite3")
    try:
        row = connection.execute(adapter._dispatch_select_sql()).fetchone()
    finally:
        connection.close()
    assert row is not None
    return row


def _create_v2_metadata_database(
    path: Path,
    *,
    dispatch_row: tuple[Any, ...],
    intent_fence: tuple[Any, ...],
    metadata_updated_at: str,
) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE transaction_fences (
                transaction_id TEXT PRIMARY KEY,
                highwater INTEGER NOT NULL CHECK(highwater > 0),
                updated_at TEXT NOT NULL
            ) STRICT;
            CREATE TABLE intent_fences (
                intent_hash TEXT PRIMARY KEY,
                owner_version INTEGER NOT NULL CHECK(owner_version >= 0),
                highwater INTEGER NOT NULL CHECK(highwater > 0),
                updated_at TEXT NOT NULL
            ) STRICT;
            CREATE TABLE adapter_dispatches (
                intent_hash TEXT NOT NULL,
                owner_version INTEGER NOT NULL CHECK(owner_version >= 0),
                owner_history_sequence INTEGER NOT NULL CHECK(owner_history_sequence >= 0),
                owner_history_digest TEXT NOT NULL,
                dispatch_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                transaction_id TEXT NOT NULL,
                stage_id TEXT NOT NULL,
                staged_state_digest TEXT NOT NULL,
                permit_digest TEXT NOT NULL,
                normalized_action_digest TEXT NOT NULL,
                receipt_json BLOB NOT NULL,
                status TEXT NOT NULL CHECK(status IN (
                    'RESERVED', 'PREPARED', 'EFFECT_STARTED', 'NO_EFFECT',
                    'PARTIAL_OR_UNKNOWN', 'COMMITTED', 'ROLLED_BACK'
                )),
                classification_json BLOB,
                classification_ref TEXT,
                row_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(intent_hash, owner_version),
                UNIQUE(dispatch_id),
                UNIQUE(receipt_id),
                CHECK((status = 'NO_EFFECT') = (classification_json IS NOT NULL)),
                CHECK((classification_json IS NULL) = (classification_ref IS NULL))
            ) STRICT;
            CREATE TRIGGER adapter_dispatches_identity_immutable
            BEFORE UPDATE ON adapter_dispatches
            WHEN OLD.intent_hash != NEW.intent_hash
                OR OLD.owner_version != NEW.owner_version
                OR OLD.owner_history_sequence != NEW.owner_history_sequence
                OR OLD.owner_history_digest != NEW.owner_history_digest
                OR OLD.dispatch_id != NEW.dispatch_id
                OR OLD.receipt_id != NEW.receipt_id
                OR OLD.transaction_id != NEW.transaction_id
                OR OLD.stage_id != NEW.stage_id
                OR OLD.staged_state_digest != NEW.staged_state_digest
                OR OLD.permit_digest != NEW.permit_digest
                OR OLD.normalized_action_digest != NEW.normalized_action_digest
                OR OLD.receipt_json != NEW.receipt_json
                OR OLD.created_at != NEW.created_at
            BEGIN
                SELECT RAISE(ABORT, 'adapter dispatch identity is immutable');
            END;
            CREATE TRIGGER adapter_dispatches_legal_transition
            BEFORE UPDATE OF status ON adapter_dispatches
            WHEN NOT (
                OLD.status = NEW.status
                OR (OLD.status = 'RESERVED' AND NEW.status IN (
                    'PREPARED', 'NO_EFFECT', 'PARTIAL_OR_UNKNOWN'
                ))
                OR (OLD.status = 'PREPARED' AND NEW.status IN (
                    'EFFECT_STARTED', 'NO_EFFECT', 'PARTIAL_OR_UNKNOWN',
                    'COMMITTED', 'ROLLED_BACK'
                ))
                OR (OLD.status = 'EFFECT_STARTED' AND NEW.status IN (
                    'PARTIAL_OR_UNKNOWN', 'COMMITTED', 'ROLLED_BACK'
                ))
                OR (OLD.status = 'PARTIAL_OR_UNKNOWN' AND NEW.status IN (
                    'NO_EFFECT', 'COMMITTED', 'ROLLED_BACK'
                ))
                OR (OLD.status = 'COMMITTED' AND NEW.status = 'ROLLED_BACK')
            )
            BEGIN
                SELECT RAISE(ABORT, 'illegal adapter dispatch transition');
            END;
            CREATE TABLE adapter_schema_metadata (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                schema_version INTEGER NOT NULL CHECK(schema_version > 0),
                updated_at TEXT NOT NULL
            ) STRICT;
            """
        )
        connection.execute(
            """
            INSERT INTO adapter_dispatches(
                intent_hash, owner_version, owner_history_sequence, owner_history_digest,
                dispatch_id, receipt_id, transaction_id, stage_id, staged_state_digest,
                permit_digest, normalized_action_digest, receipt_json, status,
                classification_json, classification_ref, row_digest, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            dispatch_row,
        )
        connection.execute(
            """
            INSERT INTO intent_fences(intent_hash, owner_version, highwater, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            intent_fence,
        )
        connection.execute(
            """
            INSERT INTO adapter_schema_metadata(singleton, schema_version, updated_at)
            VALUES (1, 2, ?)
            """,
            (metadata_updated_at,),
        )
        connection.execute("PRAGMA user_version = 2")
        connection.commit()
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_stage_v1_manifest_migrates_canonically_and_retry_is_idempotent(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"nested/result.txt": "ready"})
    manifest_path = _stage_manifest_path(state_root, prepared.staged.stage_id)
    legacy = _read_json_object(manifest_path)
    assert legacy.pop("schema_version") == 2
    legacy_content = _write_canonical_json(manifest_path, legacy)

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    context = StageContext(prepared.proposal.deadline, "worker:filesystem-edge")
    repeated_receipt = await restarted.execute(prepared.staged, context)

    migrated_content = manifest_path.read_bytes()
    migrated = _read_json_object(manifest_path)
    assert migrated_content != legacy_content
    assert migrated["schema_version"] == 2
    assert canonical_json_bytes(migrated) == migrated_content
    assert repeated_receipt == prepared.receipt
    assert snapshot_tree(workspace).digest == prepared.before_digest


@pytest.mark.asyncio
async def test_claimed_stage_schema_v1_fails_closed_without_rewriting_tamper(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "ready"})
    manifest_path = _stage_manifest_path(state_root, prepared.staged.stage_id)
    tampered = _read_json_object(manifest_path)
    tampered["schema_version"] = 1
    tampered_content = _write_canonical_json(manifest_path, tampered)

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    with pytest.raises(AgentKernelError) as raised:
        await restarted.execute(
            prepared.staged,
            StageContext(prepared.proposal.deadline, "worker:filesystem-edge"),
        )

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR
    assert manifest_path.read_bytes() == tampered_content
    assert snapshot_tree(workspace).digest == prepared.before_digest


@pytest.mark.asyncio
@pytest.mark.parametrize("line_ending", [b"\n", b"\r\n"], ids=["posix", "windows"])
async def test_recovery_v1_manifest_migrates_and_backfills_exact_legacy_dispatch(
    tmp_path: Path,
    line_ending: bytes,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "before.txt").write_text("old", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"before.txt": "new"})
    effect = await _commit_stage(adapter, prepared)
    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    current = _read_json_object(manifest_path)
    historical_v1 = {
        field: current[field]
        for field in ("status", "effect_receipt", "stage_id", "staged_state_digest")
    }
    historical_content = (
        json.dumps(historical_v1, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + line_ending
    )
    manifest_path.write_bytes(historical_content)
    for database_path in (
        state_root / "adapter.sqlite3",
        state_root / "adapter.sqlite3-wal",
        state_root / "adapter.sqlite3-shm",
    ):
        with suppress(FileNotFoundError):
            database_path.unlink()

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    verification = await restarted.verify_committed(
        effect,
        VerifyContext(prepared.proposal.deadline),
    )
    migrated = _read_json_object(manifest_path)
    dispatch = _dispatch_row(state_root)

    assert verification.status is VerificationStatus.PASS
    assert migrated["schema_version"] == 4
    assert migrated["tenant_id"] == "tenant:embedded"
    assert migrated["owner_version"] == 0
    assert migrated["owner_history_sequence"] == 0
    assert migrated["normalized_action_digest"] == effect.intent_hash
    assert dispatch["status"] == "COMMITTED"
    assert dispatch["dispatch_id"] == migrated["dispatch_id"]
    assert dispatch["receipt_id"] == effect.receipt_id


@pytest.mark.asyncio
async def test_recovery_v1_full_tree_backup_remains_usable_for_rollback(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "before.txt").write_text("old", encoding="utf-8")
    (workspace / "untouched.txt").write_text("stable", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"before.txt": "new"})
    effect = await _commit_stage(adapter, prepared)
    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    current = _read_json_object(manifest_path)
    historical_v1 = {
        field: current[field]
        for field in ("status", "effect_receipt", "stage_id", "staged_state_digest")
    }
    manifest_path.write_bytes(
        (json.dumps(historical_v1, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    )
    backup = state_root / "recovery" / effect.receipt_id / "backup"
    (backup / "untouched.txt").write_text("stable", encoding="utf-8")
    for database_path in (
        state_root / "adapter.sqlite3",
        state_root / "adapter.sqlite3-wal",
        state_root / "adapter.sqlite3-shm",
    ):
        with suppress(FileNotFoundError):
            database_path.unlink()

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    migrated = _read_json_object(manifest_path)
    rollback = await restarted.rollback(
        effect,
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )

    assert migrated["backup_evidence_format"] == "FULL_TREE_V1"
    assert migrated["target_evidence_status"] == "VERIFIED_SNAPSHOT"
    assert rollback.status is VerificationStatus.PASS
    assert (workspace / "before.txt").read_text(encoding="utf-8") == "old"
    assert (workspace / "untouched.txt").read_text(encoding="utf-8") == "stable"
    assert snapshot_tree(workspace).digest == effect.target_version_before


@pytest.mark.asyncio
async def test_recovery_v1_older_committed_history_migrates_with_explicitly_unavailable_target(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "x.txt").write_text("v0", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    first_prepared = await _prepare_stage(adapter, {"x.txt": "v1"}, transaction_id="tx:first")
    first_effect = await _commit_stage(adapter, first_prepared)
    second_prepared = await _prepare_stage(adapter, {"x.txt": "v2"}, transaction_id="tx:second")
    second_effect = await _commit_stage(adapter, second_prepared)

    for effect in (first_effect, second_effect):
        manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
        current = _read_json_object(manifest_path)
        historical_v1 = {
            field: current[field]
            for field in ("status", "effect_receipt", "stage_id", "staged_state_digest")
        }
        manifest_path.write_bytes(
            (json.dumps(historical_v1, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "utf-8"
            )
        )
    for database_path in (
        state_root / "adapter.sqlite3",
        state_root / "adapter.sqlite3-wal",
        state_root / "adapter.sqlite3-shm",
    ):
        with suppress(FileNotFoundError):
            database_path.unlink()

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    first_manifest = _read_json_object(_recovery_manifest_path(state_root, first_effect.receipt_id))
    second_manifest = _read_json_object(
        _recovery_manifest_path(state_root, second_effect.receipt_id)
    )
    first_verification = await restarted.verify_committed(
        first_effect,
        VerifyContext(first_prepared.proposal.deadline),
    )
    second_verification = await restarted.verify_committed(
        second_effect,
        VerifyContext(second_prepared.proposal.deadline),
    )
    first_reconciliation = await restarted.reconcile(
        _intent(first_prepared),
        RecoveryContext(first_prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    first_rollback = await restarted.rollback(
        first_effect,
        RecoveryContext(first_prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    with sqlite3.connect(state_root / "adapter.sqlite3") as connection:
        dispatches = dict(
            connection.execute("SELECT receipt_id, status FROM adapter_dispatches").fetchall()
        )

    assert first_manifest["status"] == "COMMITTED"
    assert first_manifest["target_evidence_status"] == "HISTORICAL_TARGET_UNAVAILABLE"
    assert first_manifest["target_snapshot"] is None
    assert first_manifest["diff"] is None
    assert second_manifest["target_evidence_status"] == "VERIFIED_SNAPSHOT"
    assert dispatches == {
        first_effect.receipt_id: "COMMITTED",
        second_effect.receipt_id: "COMMITTED",
    }
    assert first_verification.status is VerificationStatus.FAIL
    assert second_verification.status is VerificationStatus.PASS
    assert first_reconciliation.status is ReconcileStatus.UNKNOWN
    assert first_rollback.status is VerificationStatus.ERROR
    assert snapshot_tree(workspace).digest == second_effect.target_version_after


@pytest.mark.asyncio
async def test_recovery_v1_older_rolled_back_history_survives_later_commit(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "x.txt").write_text("v0", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    first_prepared = await _prepare_stage(adapter, {"x.txt": "v1"}, transaction_id="tx:first")
    first_effect = await _commit_stage(adapter, first_prepared)
    first_rollback = await adapter.rollback(
        first_effect,
        RecoveryContext(first_prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    assert first_rollback.status is VerificationStatus.PASS
    second_prepared = await _prepare_stage(adapter, {"x.txt": "v2"}, transaction_id="tx:second")
    second_effect = await _commit_stage(adapter, second_prepared)

    for effect in (first_effect, second_effect):
        manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
        current = _read_json_object(manifest_path)
        historical_v1 = {
            field: current[field]
            for field in ("status", "effect_receipt", "stage_id", "staged_state_digest")
        }
        manifest_path.write_bytes(
            (json.dumps(historical_v1, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "utf-8"
            )
        )
    for database_path in (
        state_root / "adapter.sqlite3",
        state_root / "adapter.sqlite3-wal",
        state_root / "adapter.sqlite3-shm",
    ):
        with suppress(FileNotFoundError):
            database_path.unlink()

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    first_manifest = _read_json_object(_recovery_manifest_path(state_root, first_effect.receipt_id))
    repeated_rollback = await restarted.rollback(
        first_effect,
        RecoveryContext(first_prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    reconciliation = await restarted.reconcile(
        _intent(first_prepared),
        RecoveryContext(first_prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    with sqlite3.connect(state_root / "adapter.sqlite3") as connection:
        dispatches = dict(
            connection.execute("SELECT receipt_id, status FROM adapter_dispatches").fetchall()
        )

    assert first_manifest["status"] == "ROLLED_BACK"
    assert first_manifest["target_evidence_status"] == "HISTORICAL_TARGET_UNAVAILABLE"
    assert dispatches == {
        first_effect.receipt_id: "ROLLED_BACK",
        second_effect.receipt_id: "COMMITTED",
    }
    assert repeated_rollback.status is VerificationStatus.UNKNOWN
    assert reconciliation.status is ReconcileStatus.UNKNOWN
    assert snapshot_tree(workspace).digest == second_effect.target_version_after


@pytest.mark.asyncio
async def test_recovery_v1_partial_effect_preserves_applied_path_evidence_through_rollback(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "a.txt").write_text("old-a", encoding="utf-8")
    (workspace / "b.txt").write_text("old-b", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = _FaultingFilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"a.txt": "new-a", "b.txt": "new-b"})
    adapter.arm("commit.after_change:a.txt")
    with pytest.raises(_SimulatedProcessExit):
        await _commit_stage(adapter, prepared)

    dispatch = _dispatch_row(state_root)
    manifest_path = _recovery_manifest_path(state_root, dispatch["receipt_id"])
    current = _read_json_object(manifest_path)
    effect = EffectReceipt.model_validate(current["effect_receipt"])
    historical_v1 = {
        "status": "PREPARED",
        "effect_receipt": current["effect_receipt"],
        "stage_id": current["stage_id"],
        "staged_state_digest": current["staged_state_digest"],
    }
    manifest_path.write_bytes(
        (json.dumps(historical_v1, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    )
    current_stage_parent = _stage_manifest_path(state_root, current["stage_id"]).parent
    historical_stage_parent = state_root / "stages" / current["stage_id"]
    current_stage_parent.rename(historical_stage_parent)
    for database_path in (
        state_root / "adapter.sqlite3",
        state_root / "adapter.sqlite3-wal",
        state_root / "adapter.sqlite3-shm",
    ):
        with suppress(FileNotFoundError):
            database_path.unlink()

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    migrated = _read_json_object(manifest_path)
    rollback = await restarted.rollback(
        effect,
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    reconciliation = await restarted.reconcile(
        _intent(prepared),
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    after_reconcile = _read_json_object(manifest_path)

    assert migrated["status"] == "PARTIAL_OR_UNKNOWN"
    assert migrated["applied_paths"] == ["a.txt"]
    assert _dispatch_row(state_root)["status"] == "PARTIAL_OR_UNKNOWN"
    assert rollback.status is VerificationStatus.PASS
    assert snapshot_tree(workspace).digest == effect.target_version_before
    assert reconciliation.status is ReconcileStatus.UNKNOWN
    assert after_reconcile["status"] == "ROLLED_BACK"
    assert after_reconcile["applied_paths"] == ["a.txt"]


@pytest.mark.asyncio
async def test_recovery_v1_terminal_rollback_migrates_without_fabricating_target_evidence(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "before.txt").write_text("old", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"before.txt": "new"})
    effect = await _commit_stage(adapter, prepared)
    first_rollback = await adapter.rollback(
        effect,
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    assert first_rollback.status is VerificationStatus.PASS
    assert snapshot_tree(workspace).digest == effect.target_version_before

    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    current = _read_json_object(manifest_path)
    historical_v1 = {
        field: current[field]
        for field in ("status", "effect_receipt", "stage_id", "staged_state_digest")
    }
    historical_content = (
        json.dumps(historical_v1, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    manifest_path.write_bytes(historical_content)
    stage_key = canonical_digest({"stage_id": current["stage_id"]}).removeprefix("sha256:")
    assert not (state_root / "stages" / stage_key).exists()
    for database_path in (
        state_root / "adapter.sqlite3",
        state_root / "adapter.sqlite3-wal",
        state_root / "adapter.sqlite3-shm",
    ):
        with suppress(FileNotFoundError):
            database_path.unlink()

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    migrated = _read_json_object(manifest_path)
    repeated_rollback = await restarted.rollback(
        effect,
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    committed_verification = await restarted.verify_committed(
        effect,
        VerifyContext(prepared.proposal.deadline),
    )
    reconciliation = await restarted.reconcile(
        _intent(prepared),
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )

    assert manifest_path.read_bytes() != historical_content
    assert migrated["schema_version"] == 4
    assert migrated["status"] == "ROLLED_BACK"
    assert migrated["target_evidence_status"] == "HISTORICAL_TARGET_UNAVAILABLE"
    assert migrated["target_snapshot"] is None
    assert migrated["diff"] is None
    assert migrated["base_snapshot"]["digest"] == effect.target_version_before
    assert _dispatch_row(state_root)["status"] == "ROLLED_BACK"
    assert repeated_rollback.status is VerificationStatus.PASS
    assert committed_verification.status is VerificationStatus.FAIL
    assert reconciliation.status is ReconcileStatus.NO_EFFECT


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper_location", ["backup", "missing_backup"])
async def test_recovery_v1_terminal_rollback_tamper_fails_closed_without_rewrite(
    tmp_path: Path,
    tamper_location: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "before.txt").write_text("old", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"before.txt": "new"})
    effect = await _commit_stage(adapter, prepared)
    rollback = await adapter.rollback(
        effect,
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    assert rollback.status is VerificationStatus.PASS

    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    current = _read_json_object(manifest_path)
    historical_v1 = {
        field: current[field]
        for field in ("status", "effect_receipt", "stage_id", "staged_state_digest")
    }
    historical_content = (
        json.dumps(historical_v1, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    manifest_path.write_bytes(historical_content)
    for database_path in (
        state_root / "adapter.sqlite3",
        state_root / "adapter.sqlite3-wal",
        state_root / "adapter.sqlite3-shm",
    ):
        with suppress(FileNotFoundError):
            database_path.unlink()
    backup_root = state_root / "recovery" / effect.receipt_id / "backup"
    if tamper_location == "backup":
        (backup_root / "before.txt").write_text("tampered", encoding="utf-8")
    elif tamper_location == "missing_backup":
        (backup_root / "before.txt").unlink()
        backup_root.rmdir()
    with pytest.raises(AgentKernelError) as raised:
        FilesystemAdapter(workspace=workspace, state_root=state_root)

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR
    assert manifest_path.read_bytes() == historical_content


@pytest.mark.asyncio
async def test_recovery_v2_manifest_migrates_only_with_its_bound_embedded_identity(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "committed"})
    effect = await _commit_stage(adapter, prepared)
    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    legacy_v2 = _read_json_object(manifest_path)
    assert legacy_v2.pop("tenant_id") == "tenant:embedded"
    assert legacy_v2.pop("backup_evidence_format") == "PER_CHANGE_V2"
    assert legacy_v2.pop("target_evidence_status") == "VERIFIED_SNAPSHOT"
    legacy_v2["schema_version"] = 2
    _write_canonical_json(manifest_path, legacy_v2)

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    migrated = _read_json_object(manifest_path)

    assert migrated["schema_version"] == 4
    assert migrated["tenant_id"] == "tenant:embedded"
    assert await restarted.verify_committed(
        effect,
        VerifyContext(prepared.proposal.deadline),
    ) == await adapter.verify_committed(
        effect,
        VerifyContext(prepared.proposal.deadline),
    )


@pytest.mark.asyncio
async def test_recovery_v3_complete_manifest_migrates_to_v4_idempotently(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "committed"})
    effect = await _commit_stage(adapter, prepared)
    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    legacy_v3 = _read_json_object(manifest_path)
    assert legacy_v3.pop("backup_evidence_format") == "PER_CHANGE_V2"
    assert legacy_v3.pop("target_evidence_status") == "VERIFIED_SNAPSHOT"
    legacy_v3["schema_version"] = 3
    legacy_content = _write_canonical_json(manifest_path, legacy_v3)

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    migrated_content = manifest_path.read_bytes()
    migrated = _read_json_object(manifest_path)
    restarted_again = FilesystemAdapter(workspace=workspace, state_root=state_root)

    assert migrated_content != legacy_content
    assert migrated["schema_version"] == 4
    assert migrated["target_evidence_status"] == "VERIFIED_SNAPSHOT"
    assert manifest_path.read_bytes() == migrated_content
    assert await restarted_again.verify_committed(
        effect,
        VerifyContext(prepared.proposal.deadline),
    ) == await restarted.verify_committed(
        effect,
        VerifyContext(prepared.proposal.deadline),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy_version", [2, 3])
async def test_failed_recovery_v2_v3_semantic_migration_preserves_original_evidence(
    tmp_path: Path,
    legacy_version: int,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "committed"})
    effect = await _commit_stage(adapter, prepared)
    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    legacy = _read_json_object(manifest_path)
    assert legacy.pop("backup_evidence_format") == "PER_CHANGE_V2"
    assert legacy.pop("target_evidence_status") == "VERIFIED_SNAPSHOT"
    if legacy_version == 2:
        assert legacy.pop("tenant_id") == "tenant:embedded"
    legacy["schema_version"] = legacy_version
    legacy["applied_paths"] = [*legacy["applied_paths"], "not-in-diff.txt"]
    original_content = _write_canonical_json(manifest_path, legacy)

    with pytest.raises(AgentKernelError) as raised:
        FilesystemAdapter(workspace=workspace, state_root=state_root)

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR
    assert manifest_path.read_bytes() == original_content
    assert _read_json_object(manifest_path)["schema_version"] == legacy_version


@pytest.mark.asyncio
async def test_recovery_v3_migration_compare_and_swap_preserves_newer_terminal_manifest(
    tmp_path: Path,
) -> None:
    class PausingMigrationAdapter(FilesystemAdapter):
        entered = threading.Event()
        release = threading.Event()

        def _fault_point(self, name: str) -> None:
            if name == "recovery_migration.before_compare_and_swap" and not self.entered.is_set():
                self.entered.set()
                if not self.release.wait(timeout=10):
                    raise RuntimeError("migration interleaving was not released")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    writer = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(writer, {"result.txt": "committed"})
    effect = await _commit_stage(writer, prepared)
    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    legacy_v3 = _read_json_object(manifest_path)
    legacy_v3.pop("backup_evidence_format")
    legacy_v3.pop("target_evidence_status")
    legacy_v3["schema_version"] = 3
    legacy_v3["status"] = "EFFECT_STARTED"
    _write_canonical_json(manifest_path, legacy_v3)

    restarted: list[FilesystemAdapter] = []
    failures: list[BaseException] = []

    def migrate() -> None:
        try:
            restarted.append(PausingMigrationAdapter(workspace=workspace, state_root=state_root))
        except BaseException as error:
            failures.append(error)

    migration_thread = threading.Thread(target=migrate)
    migration_thread.start()
    try:
        assert PausingMigrationAdapter.entered.wait(timeout=10)
        concurrent = FilesystemAdapter(workspace=workspace, state_root=state_root)
        reconciliation = await concurrent.reconcile(
            _intent(prepared),
            RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
        )
        assert reconciliation.status is ReconcileStatus.COMMITTED
    finally:
        PausingMigrationAdapter.release.set()
        migration_thread.join(timeout=10)

    assert not migration_thread.is_alive()
    assert failures == []
    assert len(restarted) == 1
    assert _read_json_object(manifest_path)["status"] == "COMMITTED"
    verification = await restarted[0].verify_committed(
        effect,
        VerifyContext(prepared.proposal.deadline),
    )
    assert verification.status is VerificationStatus.PASS


@pytest.mark.asyncio
async def test_recovery_manifest_lock_rejects_stale_terminal_state_regression(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "committed"})
    effect = await _commit_stage(adapter, prepared)
    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    committed = adapter._recovery_by_receipt[("tenant:embedded", effect.receipt_id)]
    committed_content = manifest_path.read_bytes()

    with pytest.raises(AgentKernelError) as raised:
        adapter._persist_recovery_manifest(
            committed.model_copy(update={"status": "PARTIAL_OR_UNKNOWN"})
        )

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR
    assert manifest_path.read_bytes() == committed_content
    assert _dispatch_row(state_root)["status"] == "COMMITTED"


@pytest.mark.asyncio
async def test_reconciliation_repairs_terminal_dispatch_manifest_status_mismatch(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "committed"})
    effect = await _commit_stage(adapter, prepared)
    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    legacy_v3 = _read_json_object(manifest_path)
    legacy_v3.pop("backup_evidence_format")
    legacy_v3.pop("target_evidence_status")
    legacy_v3["schema_version"] = 3
    legacy_v3["status"] = "EFFECT_STARTED"
    _write_canonical_json(manifest_path, legacy_v3)

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    before = await restarted.verify_committed(
        effect,
        VerifyContext(prepared.proposal.deadline),
    )
    reconciliation = await restarted.reconcile(
        _intent(prepared),
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    after = await restarted.verify_committed(
        effect,
        VerifyContext(prepared.proposal.deadline),
    )

    assert before.status is VerificationStatus.FAIL
    assert reconciliation.status is ReconcileStatus.COMMITTED
    assert _read_json_object(manifest_path)["status"] == "COMMITTED"
    assert after.status is VerificationStatus.PASS


@pytest.mark.asyncio
@pytest.mark.parametrize("backup_evidence_format", ["PER_CHANGE_V2", "FULL_TREE_V1"])
async def test_schema_v4_manifest_cannot_impersonate_legacy_backfill(
    tmp_path: Path,
    backup_evidence_format: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "committed"})
    effect = await _commit_stage(adapter, prepared)
    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    forged = _read_json_object(manifest_path)
    forged.update(
        {
            "tenant_id": "tenant:embedded",
            "dispatch_id": f"dispatch_{effect.intent_hash.removeprefix('sha256:')}",
            "owner_version": 0,
            "owner_history_sequence": 0,
            "owner_history_digest": filesystem._LEGACY_OWNER_HISTORY_DIGEST,
            "permit_digest": filesystem._LEGACY_PERMIT_DIGEST,
            "normalized_action_digest": effect.intent_hash,
            "backup_evidence_format": backup_evidence_format,
        }
    )
    forged_content = _write_canonical_json(manifest_path, forged)
    for database_path in (
        state_root / "adapter.sqlite3",
        state_root / "adapter.sqlite3-wal",
        state_root / "adapter.sqlite3-shm",
    ):
        with suppress(FileNotFoundError):
            database_path.unlink()

    with pytest.raises(AgentKernelError) as raised:
        FilesystemAdapter(workspace=workspace, state_root=state_root)

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR
    assert manifest_path.read_bytes() == forged_content
    assert _dispatch_count(state_root) == 0


@pytest.mark.asyncio
async def test_recovery_v1_manifest_conflicting_with_v2_dispatch_fails_closed(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "committed"})
    effect = await _commit_stage(adapter, prepared)
    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    current = _read_json_object(manifest_path)
    historical_v1 = {
        field: current[field]
        for field in ("status", "effect_receipt", "stage_id", "staged_state_digest")
    }
    manifest_path.write_bytes(
        (json.dumps(historical_v1, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    )

    with pytest.raises(AgentKernelError) as raised:
        FilesystemAdapter(workspace=workspace, state_root=state_root)

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR
    assert (workspace / "result.txt").read_text(encoding="utf-8") == "committed"
    assert _dispatch_row(state_root)["status"] == "COMMITTED"


@pytest.mark.asyncio
async def test_metadata_v2_dispatch_migrates_to_tenant_scoped_v3(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "committed"})
    effect = await _commit_stage(adapter, prepared)
    metadata_path = state_root / "adapter.sqlite3"

    connection = sqlite3.connect(metadata_path)
    try:
        current_row = connection.execute(adapter._dispatch_select_sql()).fetchone()
        assert current_row is not None
        intent_fence = connection.execute(
            """
            SELECT intent_hash, owner_version, highwater, updated_at
            FROM intent_fences WHERE tenant_id = ? AND intent_hash = ?
            """,
            ("tenant:embedded", prepared.plan.intent_hash),
        ).fetchone()
        assert intent_fence is not None
        metadata_updated_at = connection.execute(
            "SELECT updated_at FROM adapter_schema_metadata WHERE singleton = 1"
        ).fetchone()[0]
    finally:
        connection.close()

    receipt = EffectReceipt.model_validate_json(current_row[12])
    created_at = datetime.fromisoformat(current_row[17])
    updated_at = datetime.fromisoformat(current_row[18])
    legacy_identity = {
        "intent_hash": current_row[1],
        "owner_version": current_row[2],
        "owner_history_sequence": current_row[3],
        "owner_history_digest": current_row[4],
        "dispatch_id": current_row[5],
        "transaction_id": current_row[7],
        "stage_id": current_row[8],
        "staged_state_digest": current_row[9],
        "permit_digest": current_row[10],
        "normalized_action_digest": current_row[11],
        "receipt": receipt,
        "status": current_row[13],
        "classification_ref": current_row[15],
        "created_at": created_at,
        "updated_at": updated_at,
    }
    legacy_row_digest = canonical_digest(legacy_identity)
    legacy_dispatch_row = (
        *current_row[1:16],
        legacy_row_digest,
        current_row[17],
        current_row[18],
    )
    invalid_permit = canonical_digest({"permit": "not-the-embedded-v2-permit"})
    invalid_dispatch_row = list(legacy_dispatch_row)
    invalid_dispatch_row[9] = invalid_permit
    invalid_dispatch_row[15] = canonical_digest(
        {**legacy_identity, "permit_digest": invalid_permit}
    )
    invalid_state = tmp_path / "invalid-embedded-state"
    invalid_state.mkdir()
    invalid_metadata = invalid_state / "adapter.sqlite3"
    _create_v2_metadata_database(
        invalid_metadata,
        dispatch_row=tuple(invalid_dispatch_row),
        intent_fence=tuple(intent_fence),
        metadata_updated_at=metadata_updated_at,
    )
    with pytest.raises(AgentKernelError) as invalid_embedded:
        FilesystemAdapter(workspace=workspace, state_root=invalid_state)
    assert invalid_embedded.value.code is ErrorCode.INTEGRITY_ERROR
    with sqlite3.connect(invalid_metadata) as invalid_connection:
        assert invalid_connection.execute("PRAGMA user_version").fetchone()[0] == 2

    for database_path in (
        metadata_path,
        state_root / "adapter.sqlite3-wal",
        state_root / "adapter.sqlite3-shm",
    ):
        with suppress(FileNotFoundError):
            database_path.unlink()
    _create_v2_metadata_database(
        metadata_path,
        dispatch_row=legacy_dispatch_row,
        intent_fence=tuple(intent_fence),
        metadata_updated_at=metadata_updated_at,
    )

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    migrated = _dispatch_row(state_root)
    manifest = _read_json_object(_recovery_manifest_path(state_root, effect.receipt_id))
    with sqlite3.connect(metadata_path) as migrated_connection:
        assert migrated_connection.execute("PRAGMA user_version").fetchone()[0] == 3
        migrated_fence = migrated_connection.execute(
            """
            SELECT owner_version, highwater FROM intent_fences
            WHERE tenant_id = ? AND intent_hash = ?
            """,
            ("tenant:embedded", prepared.plan.intent_hash),
        ).fetchone()

    assert migrated["tenant_id"] == "tenant:embedded"
    assert migrated["dispatch_id"] == current_row[5]
    assert migrated["receipt_id"] == effect.receipt_id
    assert migrated["row_digest"] != legacy_row_digest
    assert migrated_fence == (intent_fence[1], intent_fence[2])
    assert manifest["schema_version"] == 4
    assert manifest["tenant_id"] == "tenant:embedded"
    assert await restarted.verify_committed(
        effect,
        VerifyContext(prepared.proposal.deadline),
    ) == await adapter.verify_committed(
        effect,
        VerifyContext(prepared.proposal.deadline),
    )


@pytest.mark.asyncio
async def test_metadata_v2_tenant_bound_dispatch_requires_artifact_even_in_embedded_mode(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source_state = tmp_path / "source-state"
    source = FilesystemAdapter(workspace=workspace, state_root=source_state)
    prepared = await _prepare_stage(source, {"result.txt": "committed"})
    await _commit_stage(source, prepared)
    current_row = _raw_dispatch_row(source, source_state)
    created_at = datetime.fromisoformat(current_row[17])
    updated_at = datetime.fromisoformat(current_row[18])

    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    action = enforced_helpers._normalized_action(prepared.proposal, source)
    action_ref = artifacts.put_model(action).digest
    intent_hash = action.intent_hash
    transaction_id = action.transaction_id
    receipt = EffectReceipt.model_validate_json(current_row[12]).model_copy(
        update={"intent_hash": intent_hash, "transaction_id": transaction_id}
    )
    owner_version = 7
    owner_history_sequence = 11
    owner_history_digest = canonical_digest(
        {"tenant_id": action.tenant_id, "history": "tenant-bound-v2"}
    )
    dispatch_id = "dispatch:tenant-bound-v2"
    permit_digest = canonical_digest({"permit": "tenant-bound-v2"})
    row_identity = {
        "intent_hash": intent_hash,
        "owner_version": owner_version,
        "owner_history_sequence": owner_history_sequence,
        "owner_history_digest": owner_history_digest,
        "dispatch_id": dispatch_id,
        "transaction_id": transaction_id,
        "stage_id": prepared.staged.stage_id,
        "staged_state_digest": prepared.receipt.staged_state_digest,
        "permit_digest": permit_digest,
        "normalized_action_digest": action_ref,
        "receipt": receipt,
        "status": "RESERVED",
        "classification_ref": None,
        "created_at": created_at,
        "updated_at": updated_at,
    }
    row_digest = canonical_digest(row_identity)
    legacy_dispatch_row = (
        intent_hash,
        owner_version,
        owner_history_sequence,
        owner_history_digest,
        dispatch_id,
        receipt.receipt_id,
        transaction_id,
        prepared.staged.stage_id,
        prepared.receipt.staged_state_digest,
        permit_digest,
        action_ref,
        canonical_json_bytes(receipt),
        "RESERVED",
        None,
        None,
        row_digest,
        created_at.isoformat(),
        updated_at.isoformat(),
    )
    migration_state = tmp_path / "migration-state"
    migration_state.mkdir()
    metadata_path = migration_state / "adapter.sqlite3"
    _create_v2_metadata_database(
        metadata_path,
        dispatch_row=legacy_dispatch_row,
        intent_fence=(
            intent_hash,
            owner_version,
            13,
            updated_at.isoformat(),
        ),
        metadata_updated_at=updated_at.isoformat(),
    )

    # Runtime mode is not durable tenant evidence. A missing artifact must leave the
    # v2 database untouched instead of silently relabeling the dispatch as embedded.
    with pytest.raises(AgentKernelError) as missing_artifact:
        FilesystemAdapter(workspace=workspace, state_root=migration_state)
    assert missing_artifact.value.code is ErrorCode.INTEGRITY_ERROR
    with sqlite3.connect(metadata_path) as failed_connection:
        assert failed_connection.execute("PRAGMA user_version").fetchone()[0] == 2

    wrong_proposal = prepared.proposal.model_copy(
        update={"transaction_id": "transaction:wrong-artifact"}
    )
    wrong_action = enforced_helpers._normalized_action(wrong_proposal, source)
    wrong_action_ref = artifacts.put_model(wrong_action).digest
    wrong_dispatch_row = list(legacy_dispatch_row)
    wrong_dispatch_row[10] = wrong_action_ref
    wrong_dispatch_row[15] = canonical_digest(
        {**row_identity, "normalized_action_digest": wrong_action_ref}
    )
    wrong_state = tmp_path / "wrong-artifact-state"
    wrong_state.mkdir()
    wrong_metadata = wrong_state / "adapter.sqlite3"
    _create_v2_metadata_database(
        wrong_metadata,
        dispatch_row=tuple(wrong_dispatch_row),
        intent_fence=(intent_hash, owner_version, 13, updated_at.isoformat()),
        metadata_updated_at=updated_at.isoformat(),
    )
    with pytest.raises(AgentKernelError) as wrong_artifact:
        FilesystemAdapter(
            workspace=workspace,
            state_root=wrong_state,
            artifacts=artifacts,
        )
    assert wrong_artifact.value.code is ErrorCode.INTEGRITY_ERROR
    with sqlite3.connect(wrong_metadata) as wrong_connection:
        assert wrong_connection.execute("PRAGMA user_version").fetchone()[0] == 2

    # Supplying the canonical action recovers the original tenant even though the
    # adapter was opened in its default non-permit mode.
    FilesystemAdapter(
        workspace=workspace,
        state_root=migration_state,
        artifacts=artifacts,
    )
    with sqlite3.connect(metadata_path) as migrated_connection:
        tenant_rows = migrated_connection.execute(
            "SELECT tenant_id FROM adapter_dispatches"
        ).fetchall()
        fence_rows = migrated_connection.execute(
            "SELECT tenant_id FROM intent_fences WHERE intent_hash = ?",
            (intent_hash,),
        ).fetchall()
        assert migrated_connection.execute("PRAGMA user_version").fetchone()[0] == 3

    assert tenant_rows == [(action.tenant_id,)]
    assert fence_rows == [(action.tenant_id,)]


@pytest.mark.asyncio
async def test_crash_after_manifest_is_reconciled_to_durable_no_effect(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "base.txt").write_text("base", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = _FaultingFilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"new.txt": "new"})
    adapter.arm("commit.after_manifest_before_prepared")

    with pytest.raises(_SimulatedProcessExit):
        await _commit_stage(adapter, prepared)

    assert _dispatch_row(state_root)["status"] == "RESERVED"
    manifest_path = (
        state_root / "recovery" / _dispatch_row(state_root)["receipt_id"] / "manifest.json"
    )
    assert _read_json_object(manifest_path)["status"] == "PREPARED"
    assert snapshot_tree(workspace).digest == prepared.before_digest

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    report = await restarted.reconcile(
        _intent(prepared),
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    durable = _dispatch_row(state_root)

    assert report.status is ReconcileStatus.NO_EFFECT
    assert durable["status"] == "NO_EFFECT"
    assert durable["classification_ref"] is not None
    classification = json.loads(durable["classification_json"])
    assert classification == {
        "classification": "NO_EFFECT",
        "dispatch_id": durable["dispatch_id"],
        "evidence_ref": classification["evidence_ref"],
        "intent_hash": prepared.plan.intent_hash,
        "observed_state_digest": prepared.before_digest,
        "owner_version": 0,
    }
    assert _read_json_object(manifest_path)["status"] == "NO_EFFECT"


@pytest.mark.asyncio
async def test_legacy_reserved_dispatch_without_manifest_remains_unknown_after_restart(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = _FaultingFilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"new.txt": "new"})
    adapter.arm("commit.after_backup_before_manifest")

    with pytest.raises(_SimulatedProcessExit):
        await _commit_stage(adapter, prepared)

    dispatch = _dispatch_row(state_root)
    recovery_directory = state_root / "recovery" / dispatch["receipt_id"]
    assert dispatch["status"] == "RESERVED"
    assert (recovery_directory / "backup").is_dir()
    assert (recovery_directory / "manifest.json").exists() is False
    assert snapshot_tree(workspace).digest == prepared.before_digest

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    report = await restarted.reconcile(
        _intent(prepared),
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )

    assert report.status is ReconcileStatus.UNKNOWN
    assert _dispatch_row(state_root)["status"] == "RESERVED"
    assert (recovery_directory / "manifest.json").exists() is False
    assert snapshot_tree(workspace).digest == prepared.before_digest


@pytest.mark.asyncio
async def test_effect_started_at_base_is_not_misclassified_as_no_effect(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "base.txt").write_text("base", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = _FaultingFilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"new.txt": "new"})
    adapter.arm("commit.after_effect_started")

    with pytest.raises(_SimulatedProcessExit):
        await _commit_stage(adapter, prepared)

    assert _dispatch_row(state_root)["status"] == "EFFECT_STARTED"
    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    report = await restarted.reconcile(
        _intent(prepared),
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )

    assert report.status is ReconcileStatus.UNKNOWN
    assert _dispatch_row(state_root)["status"] == "EFFECT_STARTED"
    assert snapshot_tree(workspace).digest == prepared.before_digest


@pytest.mark.asyncio
async def test_crash_after_one_file_is_truthfully_classified_as_partial(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "a.txt").write_text("old-a", encoding="utf-8")
    (workspace / "b.txt").write_text("old-b", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = _FaultingFilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"a.txt": "new-a", "b.txt": "new-b"})
    adapter.arm("commit.after_change:a.txt")

    with pytest.raises(_SimulatedProcessExit):
        await _commit_stage(adapter, prepared)

    assert (workspace / "a.txt").read_text(encoding="utf-8") == "new-a"
    assert (workspace / "b.txt").read_text(encoding="utf-8") == "old-b"
    assert _dispatch_row(state_root)["status"] == "EFFECT_STARTED"

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    report = await restarted.reconcile(
        _intent(prepared),
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )

    assert report.status is ReconcileStatus.PARTIAL_OR_INVALID
    assert report.receipt is not None
    assert report.receipt.receipt_id == _dispatch_row(state_root)["receipt_id"]
    assert _dispatch_row(state_root)["status"] == "EFFECT_STARTED"


@pytest.mark.asyncio
async def test_post_dispatch_exception_marks_both_durable_surfaces_partial(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "a.txt").write_text("old-a", encoding="utf-8")
    (workspace / "b.txt").write_text("old-b", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = _FaultingFilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"a.txt": "new-a", "b.txt": "new-b"})
    adapter.arm("commit.after_change:a.txt", crash_like=False)

    with pytest.raises(AgentKernelError) as raised:
        await _commit_stage(adapter, prepared)

    assert raised.value.code is ErrorCode.EXTERNAL_RESULT_IN_DOUBT
    assert raised.value.reconcilable is True
    assert raised.value.review_required is True
    dispatch = _dispatch_row(state_root)
    manifest = _read_json_object(_recovery_manifest_path(state_root, dispatch["receipt_id"]))
    assert dispatch["status"] == "PARTIAL_OR_UNKNOWN"
    assert manifest["status"] == "PARTIAL_OR_UNKNOWN"
    assert manifest["applied_paths"] == ["a.txt"]

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    report = await restarted.reconcile(
        _intent(prepared),
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    assert report.status is ReconcileStatus.PARTIAL_OR_INVALID


@pytest.mark.asyncio
async def test_crash_after_effect_is_promoted_to_committed_by_cross_instance_reconcile(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = _FaultingFilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"nested/result.txt": "complete"})
    adapter.arm("commit.after_effect")

    with pytest.raises(_SimulatedProcessExit):
        await _commit_stage(adapter, prepared)

    dispatch = _dispatch_row(state_root)
    assert dispatch["status"] == "EFFECT_STARTED"
    assert (workspace / "nested" / "result.txt").read_text(encoding="utf-8") == "complete"

    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    report = await restarted.reconcile(
        _intent(prepared),
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    repaired = _dispatch_row(state_root)

    assert report.status is ReconcileStatus.COMMITTED
    assert report.receipt is not None
    assert repaired["status"] == "COMMITTED"
    assert (
        _read_json_object(_recovery_manifest_path(state_root, repaired["receipt_id"]))["status"]
        == "COMMITTED"
    )


@pytest.mark.asyncio
async def test_cross_instance_commit_retry_reuses_one_durable_receipt_and_can_rollback(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "before.txt").write_text("old", encoding="utf-8")
    state_root = tmp_path / "state"
    first = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(first, {"before.txt": "new"})
    second = FilesystemAdapter(workspace=workspace, state_root=state_root)

    effect = await _commit_stage(second, prepared)
    verification = await first.verify_committed(effect, VerifyContext(prepared.proposal.deadline))
    repeated = await _commit_stage(first, prepared)
    rollback = await first.rollback(
        effect,
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )

    assert verification.status is VerificationStatus.PASS
    assert repeated == effect
    assert _dispatch_count(state_root) == 1
    assert rollback.status is VerificationStatus.PASS
    assert snapshot_tree(workspace).digest == prepared.before_digest
    # The compatibility profile durably seals the recovery manifest but conservatively leaves
    # its dispatch COMMITTED; only the enforced permit path can authorize that row transition.
    assert _dispatch_row(state_root)["status"] == "COMMITTED"
    assert (
        _read_json_object(_recovery_manifest_path(state_root, effect.receipt_id))["status"]
        == "ROLLED_BACK"
    )


@pytest.mark.asyncio
async def test_rollback_rejects_an_unadmitted_extra_backup_file(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "before.txt").write_text("old", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"before.txt": "new"})
    effect = await _commit_stage(adapter, prepared)
    backup = state_root / "recovery" / effect.receipt_id / "backup"
    (backup / "not-admitted.txt").write_text("forged", encoding="utf-8")

    report = await adapter.rollback(
        effect,
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )

    assert report.status is VerificationStatus.ERROR
    assert report.residual_effects == ("backup_integrity_mismatch",)
    assert (workspace / "before.txt").read_text(encoding="utf-8") == "new"


@pytest.mark.asyncio
async def test_rollback_of_unknown_receipt_reports_missing_backup_without_mutation(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "kept.txt").write_text("kept", encoding="utf-8")
    adapter = FilesystemAdapter(workspace=workspace, state_root=tmp_path / "state")
    before = snapshot_tree(workspace).digest
    now = datetime.now(UTC)
    unknown = EffectReceipt(
        receipt_id="receipt:missing-edge",
        transaction_id="tx:missing-edge",
        adapter="filesystem",
        operation="write_files",
        intent_hash=canonical_digest({"intent": "missing-edge"}),
        target_version_before=before,
        target_version_after=before,
        effect_digest=canonical_digest({"effect": "missing-edge"}),
        created_at=now,
    )

    report = await adapter.rollback(
        unknown,
        RecoveryContext(now + timedelta(minutes=5), "authority:filesystem-edge"),
    )

    assert report.status is VerificationStatus.UNKNOWN
    assert report.residual_effects == ("missing_backup",)
    assert snapshot_tree(workspace).digest == before


@pytest.mark.asyncio
async def test_second_rollback_detects_work_created_after_durable_rollback(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"created.txt": "target"})
    effect = await _commit_stage(adapter, prepared)
    first = await adapter.rollback(
        effect,
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    (workspace / "later.txt").write_text("valuable", encoding="utf-8")

    repeated = await adapter.rollback(
        effect,
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )

    assert first.status is VerificationStatus.PASS
    assert repeated.status is VerificationStatus.UNKNOWN
    assert repeated.residual_effects == ("target_changed_after_rollback",)
    assert (workspace / "later.txt").read_text(encoding="utf-8") == "valuable"


@pytest.mark.asyncio
async def test_legacy_commit_and_rollback_ignore_dispatch_deadline_by_contract(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "legacy"})
    expired = datetime.now(UTC) - timedelta(minutes=1)

    effect = await _commit_stage(adapter, prepared, deadline=expired)
    rollback = await adapter.rollback(
        effect,
        RecoveryContext(expired, "legacy-authority"),
    )

    assert (workspace / "result.txt").exists() is False
    assert rollback.status is VerificationStatus.PASS
    assert snapshot_tree(workspace).digest == prepared.before_digest


@pytest.mark.asyncio
async def test_reconcile_classification_matrix_never_relabels_ambiguous_state(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "value.txt").write_text("base", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"value.txt": "target"})
    effect = await _commit_stage(adapter, prepared)
    intent = _intent(prepared)
    context = RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge")

    (workspace / "value.txt").write_text("base", encoding="utf-8")
    committed_at_base = await adapter.reconcile(intent, context)
    assert committed_at_base.status is ReconcileStatus.UNKNOWN
    assert _dispatch_row(state_root)["status"] == "COMMITTED"

    (workspace / "value.txt").write_text("target", encoding="utf-8")
    committed_at_target = await adapter.reconcile(intent, context)
    assert committed_at_target.status is ReconcileStatus.COMMITTED

    rollback = await adapter.rollback(effect, context)
    assert rollback.status is VerificationStatus.PASS
    rolled_back_at_base = await adapter.reconcile(intent, context)
    assert rolled_back_at_base.status is ReconcileStatus.UNKNOWN
    assert _dispatch_row(state_root)["status"] == "COMMITTED"

    (workspace / "value.txt").write_text("target", encoding="utf-8")
    rolled_back_at_target = await adapter.reconcile(intent, context)
    assert rolled_back_at_target.status is ReconcileStatus.COMMITTED
    assert _dispatch_row(state_root)["status"] == "COMMITTED"

    (workspace / "value.txt").write_text("third-state", encoding="utf-8")
    unguarded = await adapter.reconcile(intent, context)
    assert unguarded.status is ReconcileStatus.UNKNOWN
    assert (workspace / "value.txt").read_text(encoding="utf-8") == "third-state"


@pytest.mark.asyncio
async def test_unknown_intent_reconcile_returns_unknown_without_creating_dispatch(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    now = datetime.now(UTC)
    intent = IntentRecord(
        intent_hash=canonical_digest({"intent": "never-dispatched"}),
        transaction_id="tx:never-dispatched",
        idempotency_key="never-dispatched",
        dispatched=False,
        outcome_receipt_ref=None,
        created_at=now,
    )

    report = await adapter.reconcile(
        intent,
        RecoveryContext(now + timedelta(minutes=5), "authority:filesystem-edge"),
    )

    assert report.status is ReconcileStatus.UNKNOWN
    assert _dispatch_count(state_root) == 0


@pytest.mark.asyncio
async def test_reconcile_snapshot_limit_is_unknown_not_false_no_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "base.txt").write_text("base", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = _FaultingFilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"new.txt": "new"})
    adapter.arm("commit.after_manifest_before_prepared")
    with pytest.raises(_SimulatedProcessExit):
        await _commit_stage(adapter, prepared)
    restarted = FilesystemAdapter(workspace=workspace, state_root=state_root)
    monkeypatch.setattr(filesystem, "_MAX_SNAPSHOT_ENTRIES", 0)

    report = await restarted.reconcile(
        _intent(prepared),
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )

    assert report.status is ReconcileStatus.UNKNOWN
    assert _dispatch_row(state_root)["status"] == "RESERVED"
    assert snapshot_tree(workspace).digest == prepared.before_digest


@pytest.mark.parametrize(
    "files",
    [
        {},
        {f"file-{index:03}.txt": "x" for index in range(257)},
    ],
    ids=["empty", "too-many"],
)
@pytest.mark.asyncio
async def test_public_inspection_enforces_file_count_limits(
    tmp_path: Path,
    files: dict[str, str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    adapter = FilesystemAdapter(workspace=workspace, state_root=tmp_path / "state")
    proposal = _proposal(files)

    with pytest.raises(AgentKernelError) as raised:
        await adapter.inspect(proposal, ReadOnlyContext(proposal.deadline))

    assert raised.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert snapshot_tree(workspace).entries == ()


@pytest.mark.asyncio
async def test_public_inspection_enforces_aggregate_content_limit(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    adapter = FilesystemAdapter(workspace=workspace, state_root=tmp_path / "state")
    proposal = _proposal({"large.txt": "x" * (1_048_576 + 1)})

    with pytest.raises(AgentKernelError) as raised:
        await adapter.inspect(proposal, ReadOnlyContext(proposal.deadline))

    assert raised.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert snapshot_tree(workspace).entries == ()


@pytest.mark.asyncio
async def test_public_stage_rejects_manifest_over_durable_byte_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    proposal = _proposal({"result.txt": "value"})
    plan = await adapter.inspect(proposal, ReadOnlyContext(proposal.deadline))
    monkeypatch.setattr(filesystem, "_MAX_MANIFEST_BYTES", 64)

    with pytest.raises(AgentKernelError) as raised:
        await adapter.stage(plan, StageContext(proposal.deadline, "worker:filesystem-edge"))

    assert raised.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert snapshot_tree(workspace).entries == ()


def test_metadata_schema_missing_integrity_trigger_fails_closed_on_restart(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    FilesystemAdapter(workspace=workspace, state_root=state_root)
    connection = sqlite3.connect(state_root / "adapter.sqlite3")
    try:
        connection.execute("DROP TRIGGER adapter_dispatches_legal_transition")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as raised:
        FilesystemAdapter(workspace=workspace, state_root=state_root)

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR


def test_metadata_schema_newer_than_adapter_fails_closed_on_restart(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    FilesystemAdapter(workspace=workspace, state_root=state_root)
    connection = sqlite3.connect(state_root / "adapter.sqlite3")
    try:
        connection.execute("PRAGMA user_version = 999")
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as raised:
        FilesystemAdapter(workspace=workspace, state_root=state_root)

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.asyncio
async def test_dispatch_row_digest_tamper_is_rejected_by_cross_instance_load(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "committed"})
    await _commit_stage(adapter, prepared)
    connection = sqlite3.connect(state_root / "adapter.sqlite3")
    try:
        connection.execute(
            "UPDATE adapter_dispatches SET row_digest = ?",
            ("sha256:" + ("0" * 64),),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as raised:
        FilesystemAdapter(workspace=workspace, state_root=state_root)

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR
    assert (workspace / "result.txt").read_text(encoding="utf-8") == "committed"


@pytest.mark.asyncio
async def test_deleted_committed_recovery_manifest_fails_closed_across_instances(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "committed"})
    effect = await _commit_stage(adapter, prepared)
    manifest_path = _recovery_manifest_path(state_root, effect.receipt_id)
    manifest_path.unlink()

    with pytest.raises(AgentKernelError) as raised:
        FilesystemAdapter(workspace=workspace, state_root=state_root)

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR
    assert _dispatch_row(state_root)["status"] == "COMMITTED"
    assert (workspace / "result.txt").read_text(encoding="utf-8") == "committed"


@pytest.mark.parametrize(
    "mutation",
    ["receipt-not-bytes", "receipt-invalid-json", "receipt-noncanonical", "naive-created-at"],
)
@pytest.mark.asyncio
async def test_dispatch_decoder_rejects_corrupt_canonical_values(
    tmp_path: Path,
    mutation: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "committed"})
    await _commit_stage(adapter, prepared)
    row = list(_raw_dispatch_row(adapter, state_root))
    if mutation == "receipt-not-bytes":
        row[12] = "not-bytes"
    elif mutation == "receipt-invalid-json":
        row[12] = b"{"
    elif mutation == "receipt-noncanonical":
        receipt_object = json.loads(row[12])
        row[12] = json.dumps(receipt_object, indent=1, sort_keys=True).encode("utf-8")
    else:
        row[17] = datetime.now().isoformat()

    # SQLite's immutable-identity trigger blocks these states at rest. Feed a captured row to
    # the decoder directly to verify its second, independent fail-closed boundary.
    with pytest.raises(AgentKernelError) as raised:
        adapter._load_dispatch_row(tuple(row))

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR
    assert _dispatch_row(state_root)["status"] == "COMMITTED"
    assert (workspace / "result.txt").read_text(encoding="utf-8") == "committed"


@pytest.mark.parametrize(
    "mutation",
    ["digest-mismatch", "invalid-json", "noncanonical-json", "generation-mismatch"],
)
@pytest.mark.asyncio
async def test_no_effect_classification_decoder_rejects_tampered_evidence(
    tmp_path: Path,
    mutation: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "base.txt").write_text("base", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = _FaultingFilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"new.txt": "new"})
    adapter.arm("commit.after_manifest_before_prepared")
    with pytest.raises(_SimulatedProcessExit):
        await _commit_stage(adapter, prepared)
    await adapter.reconcile(
        _intent(prepared),
        RecoveryContext(prepared.proposal.deadline, "authority:filesystem-edge"),
    )
    row = list(_raw_dispatch_row(adapter, state_root))
    classification = json.loads(row[14])
    if mutation == "digest-mismatch":
        row[14] = b"{}"
    elif mutation == "invalid-json":
        row[14] = b"{"
        row[15] = sha256_digest(row[14])
    elif mutation == "noncanonical-json":
        row[14] = json.dumps(classification, indent=1, sort_keys=True).encode("utf-8")
        row[15] = sha256_digest(row[14])
    else:
        classification["owner_version"] = 7
        row[14] = canonical_json_bytes(classification)
        row[15] = sha256_digest(row[14])

    # As above, this bypasses no production write control: it isolates the durable read parser
    # because SQLite constraints and the row digest normally reject the mutation even earlier.
    with pytest.raises(AgentKernelError) as raised:
        adapter._load_dispatch_row(tuple(row))

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR
    assert _dispatch_row(state_root)["status"] == "NO_EFFECT"


@pytest.mark.asyncio
async def test_stale_and_disappeared_dispatch_transitions_fail_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = _FaultingFilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "new"})
    adapter.arm("commit.after_manifest_before_prepared")
    with pytest.raises(_SimulatedProcessExit):
        await _commit_stage(adapter, prepared)
    reserved = adapter._dispatch_for_generation(
        "tenant:embedded",
        prepared.plan.intent_hash,
        0,
    )
    assert reserved is not None
    prepared_dispatch = adapter._transition_dispatch_durable(reserved, "PREPARED")

    # These private transition calls model otherwise nondeterministic cross-process races.
    with pytest.raises(AgentKernelError) as stale:
        adapter._transition_dispatch_durable(reserved, "EFFECT_STARTED")
    assert stale.value.code is ErrorCode.VERSION_CONFLICT
    assert _dispatch_row(state_root)["status"] == "PREPARED"

    connection = sqlite3.connect(state_root / "adapter.sqlite3")
    try:
        connection.execute("DELETE FROM adapter_dispatches")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(AgentKernelError) as disappeared:
        adapter._transition_dispatch_durable(prepared_dispatch, "EFFECT_STARTED")

    assert disappeared.value.code is ErrorCode.INTEGRITY_ERROR
    assert _dispatch_count(state_root) == 0


@pytest.mark.asyncio
async def test_cross_instance_clock_rollback_fails_before_dispatch(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    first = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(first, {"result.txt": "new"})
    connection = sqlite3.connect(state_root / "adapter.sqlite3")
    try:
        durable_raw = connection.execute(
            "SELECT updated_at FROM adapter_schema_metadata WHERE singleton = 1"
        ).fetchone()[0]
    finally:
        connection.close()
    durable_time = datetime.fromisoformat(durable_raw)
    regressed = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        clock=EvidenceClock(lambda: durable_time - timedelta(seconds=1)),
    )

    with pytest.raises(AgentKernelError) as raised:
        await _commit_stage(regressed, prepared)

    assert raised.value.code is ErrorCode.INTEGRITY_ERROR
    assert _dispatch_count(state_root) == 0
    assert snapshot_tree(workspace).digest == prepared.before_digest


@pytest.mark.asyncio
async def test_sqlite_trigger_rejects_illegal_dispatch_regression(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    prepared = await _prepare_stage(adapter, {"result.txt": "committed"})
    await _commit_stage(adapter, prepared)
    connection = sqlite3.connect(state_root / "adapter.sqlite3")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="illegal adapter dispatch transition"):
            connection.execute("UPDATE adapter_dispatches SET status = 'RESERVED'")
    finally:
        connection.close()

    assert _dispatch_row(state_root)["status"] == "COMMITTED"
    assert (workspace / "result.txt").read_text(encoding="utf-8") == "committed"


@_POSIX_ONLY
def test_enforced_snapshot_rejects_replaced_workspace_root(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "trusted.txt").write_text("trusted", encoding="utf-8")
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=tmp_path / "state",
        require_permits=True,
        artifacts=LocalArtifactStore(tmp_path / "artifacts"),
    )
    captured = tmp_path / "captured-workspace"
    workspace.rename(captured)
    workspace.mkdir()
    (workspace / "attacker.txt").write_text("attacker", encoding="utf-8")

    # A public enforced call cannot reach the handle boundary without a coordinator permit.
    # This is the exact internal boundary every enforced public snapshot operation delegates to.
    with pytest.raises(AgentKernelError) as raised:
        adapter._snapshot_workspace()

    assert raised.value.code is ErrorCode.STALE_STATE
    assert (captured / "trusted.txt").read_text(encoding="utf-8") == "trusted"
    assert (workspace / "attacker.txt").read_text(encoding="utf-8") == "attacker"


@_POSIX_ONLY
def test_enforced_snapshot_rejects_workspace_root_that_disappeared(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "trusted.txt").write_text("trusted", encoding="utf-8")
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=tmp_path / "state",
        require_permits=True,
        artifacts=LocalArtifactStore(tmp_path / "artifacts"),
    )
    captured = tmp_path / "captured-workspace"
    workspace.rename(captured)

    with pytest.raises(AgentKernelError) as raised:
        adapter._snapshot_workspace()

    assert raised.value.code is ErrorCode.STALE_STATE
    assert (captured / "trusted.txt").read_text(encoding="utf-8") == "trusted"


@_POSIX_ONLY
def test_enforced_snapshot_never_follows_linked_workspace_entry(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (workspace / "linked.txt").symlink_to(outside)
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=tmp_path / "state",
        require_permits=True,
        artifacts=LocalArtifactStore(tmp_path / "artifacts"),
    )

    # See the companion root-replacement test for why this direct snapshot boundary is used.
    with pytest.raises(AgentKernelError) as raised:
        adapter._snapshot_workspace()

    assert raised.value.code is ErrorCode.UNSUPPORTED_SEMANTICS
    assert raised.value.details == {"path": "linked.txt"}
    assert outside.read_text(encoding="utf-8") == "secret"


@_POSIX_ONLY
def test_enforced_handle_read_applies_individual_file_byte_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "large.txt").write_bytes(b"four")
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=tmp_path / "state",
        require_permits=True,
        artifacts=LocalArtifactStore(tmp_path / "artifacts"),
    )
    monkeypatch.setattr(filesystem, "_MAX_SNAPSHOT_CONTENT_BYTES", 3)

    # The production limit is 1 GiB. Lowering it at the handle helper avoids a 1 GiB fixture
    # while exercising the same no-follow read and exact error classification.
    with adapter._workspace_handle() as workspace_fd, pytest.raises(AgentKernelError) as raised:
        filesystem._entry_at_fd(workspace_fd, "large.txt")

    assert raised.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


@_POSIX_ONLY
@pytest.mark.parametrize("shape", ["aggregate-bytes", "directory-entries", "file-entries"])
def test_enforced_handle_snapshot_applies_aggregate_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shape: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    if shape == "aggregate-bytes":
        (workspace / "a.txt").write_bytes(b"aa")
        (workspace / "b.txt").write_bytes(b"bb")
        monkeypatch.setattr(filesystem, "_MAX_SNAPSHOT_CONTENT_BYTES", 3)
    elif shape == "directory-entries":
        (workspace / "a").mkdir()
        (workspace / "b").mkdir()
        monkeypatch.setattr(filesystem, "_MAX_SNAPSHOT_ENTRIES", 1)
    else:
        (workspace / "a.txt").write_text("a", encoding="utf-8")
        (workspace / "b.txt").write_text("b", encoding="utf-8")
        monkeypatch.setattr(filesystem, "_MAX_SNAPSHOT_ENTRIES", 1)
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=tmp_path / "state",
        require_permits=True,
        artifacts=LocalArtifactStore(tmp_path / "artifacts"),
    )

    with pytest.raises(AgentKernelError) as raised:
        adapter._snapshot_workspace()

    assert raised.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


@_POSIX_ONLY
@pytest.mark.asyncio
async def test_expired_enforced_commit_permit_fails_before_dispatch_or_workspace_write(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "base.txt").write_text("base", encoding="utf-8")
    state_root = tmp_path / "state"
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    prepared = await enforced_helpers._prepare_dispatch(
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    now = datetime.now(UTC)
    permit_values = prepared.commit_permit.model_dump(
        mode="python",
        exclude={"permit_digest"},
    )
    permit_values.update(
        issued_at=now - timedelta(minutes=2),
        deadline=now - timedelta(minutes=1),
    )
    expired_permit = CommitPermit.create(**permit_values)
    expired_ref = artifacts.put_model(expired_permit).digest
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )

    with pytest.raises(AgentKernelError) as raised:
        await adapter.commit(
            prepared.staged_receipt,
            CommitContext(
                deadline=expired_permit.deadline,
                fencing_token=expired_permit.fencing_token,
                idempotency_key=expired_permit.idempotency_key,
                target_version_guard=expired_permit.target_version_guard,
                permit=expired_permit,
                permit_ref=expired_ref,
                normalized_action=prepared.action,
                normalized_action_ref=prepared.action_ref,
            ),
        )

    assert raised.value.code is ErrorCode.DEADLINE_EXCEEDED
    assert _dispatch_count(state_root) == 0
    assert snapshot_tree(workspace).digest == prepared.before_digest


@_POSIX_ONLY
@pytest.mark.asyncio
async def test_preparing_enforced_stage_requires_explicit_recovery_before_retry(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    prepared = await enforced_helpers._prepare_dispatch(
        workspace=workspace,
        state_root=state_root,
        artifacts=artifacts,
    )
    manifest_path = _stage_manifest_path(state_root, prepared.staged_receipt.staged.stage_id)
    interrupted = _read_json_object(manifest_path)
    interrupted["status"] = "PREPARING"
    interrupted["staged_receipt"] = None
    interrupted_content = _write_canonical_json(manifest_path, interrupted)
    adapter = FilesystemAdapter(
        workspace=workspace,
        state_root=state_root,
        require_permits=True,
        artifacts=artifacts,
    )
    stage_context = StageContext(
        deadline=prepared.stage_permit.deadline,
        worker_id=prepared.stage_permit.worker_id,
        permit=prepared.stage_permit,
        permit_ref=prepared.stage_permit_ref,
        normalized_action=prepared.action,
        normalized_action_ref=prepared.action_ref,
    )

    with pytest.raises(AgentKernelError) as raised:
        await adapter.stage(prepared.staged_receipt.staged.plan, stage_context)

    assert raised.value.code is ErrorCode.EXTERNAL_RESULT_IN_DOUBT
    assert raised.value.reconcilable is True
    assert manifest_path.read_bytes() == interrupted_content
    assert snapshot_tree(workspace).digest == prepared.before_digest


@_POSIX_ONLY
@pytest.mark.asyncio
async def test_enforced_rolled_back_dispatch_reconcile_is_conservative_at_both_snapshots(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "base.txt").write_text("base", encoding="utf-8")
    state_root = tmp_path / "state"
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    prepared = await enforced_helpers._prepare_dispatch(
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
    effect = await adapter.commit(
        prepared.staged_receipt,
        enforced_helpers._commit_context(prepared),
    )
    rollback_context, _ = enforced_helpers._recovery_context(
        adapter=adapter,
        artifacts=artifacts,
        prepared=prepared,
        kind=RecoveryWorkKind.ROLLBACK,
        fencing_token=12,
    )
    rollback = await adapter.rollback(effect, rollback_context)
    assert rollback.status is VerificationStatus.PASS
    assert _dispatch_row(state_root)["status"] == "ROLLED_BACK"

    reconcile_context, _ = enforced_helpers._recovery_context(
        adapter=adapter,
        artifacts=artifacts,
        prepared=prepared,
        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        fencing_token=13,
    )
    intent = IntentRecord(
        intent_hash=effect.intent_hash,
        transaction_id=effect.transaction_id,
        idempotency_key=effect.intent_hash,
        dispatched=True,
        outcome_receipt_ref=None,
        created_at=effect.created_at,
    )
    at_base = await adapter.reconcile(intent, reconcile_context)
    assert at_base.status is ReconcileStatus.NO_EFFECT
    assert _dispatch_row(state_root)["status"] == "ROLLED_BACK"

    (workspace / "a.txt").write_text("one", encoding="utf-8")
    (workspace / "b.txt").write_text("two", encoding="utf-8")
    assert snapshot_tree(workspace).digest == effect.target_version_after
    at_target = await adapter.reconcile(intent, reconcile_context)

    assert at_target.status is ReconcileStatus.UNKNOWN
    assert at_target.receipt is None
    assert _dispatch_row(state_root)["status"] == "ROLLED_BACK"


@pytest.mark.skipif(os.name != "nt", reason="Windows MAX_PATH regression")
def test_windows_atomic_write_preserves_headroom_for_private_sibling(tmp_path: Path) -> None:
    destination_length = 225
    filename = "result.txt"
    padding_length = destination_length - len(os.fspath(tmp_path)) - len(filename) - 2
    if not 1 <= padding_length <= 200:
        pytest.skip("pytest temporary root cannot construct the bounded MAX_PATH regression")

    parent = tmp_path / ("p" * padding_length)
    parent.mkdir()
    destination = parent / filename
    legacy_temporary = destination.with_name(f".{filename}.tmp_{'0' * 32}")
    assert len(os.fspath(destination)) == destination_length
    assert len(os.fspath(legacy_temporary)) > 260

    filesystem._atomic_write_bytes(destination, b"durable")

    assert destination.read_bytes() == b"durable"
    assert list(parent.iterdir()) == [destination]


def test_atomic_write_maps_missing_parent_to_stable_error(tmp_path: Path) -> None:
    with pytest.raises(AgentKernelError) as caught:
        filesystem._atomic_write_bytes(tmp_path / "missing" / "result.txt", b"content")

    assert caught.value.code is ErrorCode.STALE_STATE
    assert caught.value.details == {}
