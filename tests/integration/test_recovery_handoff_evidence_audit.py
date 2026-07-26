from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import test_enforced_transaction_coordinator as support
from agentkernel.canonical import canonical_digest, canonical_json_text
from agentkernel.domain.enums import LeasePurpose, RecoveryWorkKind
from agentkernel.domain.models import RecoveryActionBinding
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.storage.control import _timestamp
from agentkernel.storage.enforced import (
    RecoveryHandoffEvidenceCursor,
    SQLiteEnforcedTransactionStore,
)
from agentkernel.transactions.contracts import CommitDispatchRecord, WorkerLeaseRecord
from agentkernel.transactions.enforced import (
    CoordinatorCrashPoint,
    CoordinatorEvidence,
    RecoveryFailureKind,
)
from pydantic import ValidationError

_SYNTHETIC_DIGEST = f"sha256:{'1' * 64}"
_RECORDED_AT = datetime(2026, 7, 23, 6, 0, tzinfo=UTC)


def _terminal_binding(
    store: SQLiteEnforcedTransactionStore,
    session,
    *,
    dispatch: CommitDispatchRecord,
) -> RecoveryActionBinding:
    target_ref = canonical_digest(dispatch)
    recovery_id = (
        "recovery:"
        + canonical_digest(
            {
                "profile": "agentkernel.coordinator-id/v1",
                "prefix": "recovery",
                "material": {
                    "tenant_id": session.record.tenant_id,
                    "transaction_id": session.record.transaction_id,
                    "kind": RecoveryWorkKind.RECONCILE_DISPATCH.value,
                    "target_ref": target_ref,
                    "ordinal": 1,
                },
            }
        ).removeprefix("sha256:")[:40]
    )
    current = store.get_enforced_transaction(
        session.record.tenant_id,
        session.record.transaction_id,
    )
    deadline = store.get_transaction_recovery_deadline(
        tenant_id=session.record.tenant_id,
        transaction_id=session.record.transaction_id,
    )
    return RecoveryActionBinding(
        target_transaction_id=session.record.transaction_id,
        target_intent_hash=dispatch.intent_hash,
        target_normalized_action_digest=dispatch.permit.normalized_action_digest,
        recovery_kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        target_id=dispatch.dispatch_id,
        target_evidence_ref=target_ref,
        target_version_guard=dispatch.permit.target_version_guard,
        target_owner_version=dispatch.owner_version,
        target_owner_history_sequence=dispatch.permit.owner_history_sequence,
        target_owner_history_digest=dispatch.permit.owner_history_digest,
        adapter_manifest_digest=dispatch.permit.adapter_manifest_digest,
        risk_class=session.action.risk_floor,
        effect_domains=session.action.effect_domains,
        resource_uses_digest=canonical_digest(session.action.resource_uses),
        recovery_id=recovery_id,
        root_recovery_id=recovery_id,
        predecessor_recovery_id=None,
        recovery_ordinal=1,
        max_recovery_attempts=3,
        not_before=current.updated_at,
        absolute_deadline=deadline,
    )


def _audit_batch_coordinator(harness, *, batch: int):
    now = harness.clock()
    base_context = harness.context_validator.context
    context = (
        base_context
        if batch == 0
        else support.AuthenticatedActionContext(
            tenant_id=base_context.tenant_id,
            principal_id=f"principal:audit-{batch:03d}",
            goal_id=f"goal:audit-{batch:03d}",
            run_id=f"run:audit-{batch:03d}",
            trace_id=f"trace:audit-{batch:03d}",
            actor_id=f"actor:audit-{batch:03d}",
            on_behalf_of=f"principal:audit-{batch:03d}",
            agent_id=f"agent:audit-{batch:03d}",
            configuration_digest=base_context.configuration_digest,
        )
    )
    capability_id = harness.request.proposal.capability_refs[0]
    if batch != 0:
        harness.store.register_action_context(context, registered_at=now)
        harness.store.register_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capability_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            max_uses=32,
            registered_at=now,
        )
    transaction_id = f"transaction:audit-target-{batch * 32 + 1:05d}"
    proposal = harness.request.proposal.model_copy(
        update={
            "goal_id": context.goal_id,
            "transaction_id": transaction_id,
            "agent_id": context.agent_id,
            "arguments": {"values": {"audit": transaction_id}},
            "idempotency_key": f"idempotency:{transaction_id}",
            "deadline": now + timedelta(minutes=30),
        }
    )
    authentication = harness.artifacts.put(f"authenticated-audit-context-{batch}".encode())
    request = support.EnforcedTransactionRequest(
        proposal=proposal,
        presented_context=context,
        authentication_evidence_ref=authentication.digest,
    )

    def crash_hook(point: CoordinatorCrashPoint) -> None:
        if point is CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED:
            raise RuntimeError("simulated audit-target process crash")

    coordinator = support.EnforcedTransactionCoordinator(
        store=harness.store,
        registry=harness.registry,
        normalizers=harness.normalizers,
        artifacts=harness.artifacts,
        context_validator=support._ContextValidator(context),
        authority_snapshots=support._AuthoritySnapshots(
            harness.store,
            now,
            clock=harness.clock,
        ),
        policy_inputs=support._PolicyInputs(harness.clock),
        recovery_actions=harness.recovery_actions,
        config=support.EnforcedCoordinatorConfig(
            worker_id=f"worker:audit-batch-{batch:03d}",
            lease_duration=timedelta(minutes=20),
            recovery_deadline=timedelta(minutes=20),
            reconciliation_backoff=timedelta(seconds=2),
            max_reconciliation_attempts=3,
            crash_hook=crash_hook,
        ),
        clock=harness.clock,
    )
    return coordinator, request


async def _prepare_reconciliation_targets(harness, *, count: int):
    batches: dict[int, tuple[object, object]] = {}
    sessions = []
    recovery = support._restart_coordinator(
        harness,
        worker_id="worker:audit-target-recovery",
    )
    for index in range(1, count + 1):
        batch = (index - 1) // 32
        if batch not in batches:
            batches[batch] = _audit_batch_coordinator(harness, batch=batch)
        coordinator, base_request = batches[batch]
        transaction_id = f"transaction:audit-target-{index:05d}"
        proposal = base_request.proposal.model_copy(
            update={
                "transaction_id": transaction_id,
                "arguments": {"values": {"audit": transaction_id}},
                "idempotency_key": f"idempotency:{transaction_id}",
            }
        )
        request = base_request.model_copy(update={"proposal": proposal})
        session = await coordinator.transaction(request)
        with pytest.raises(support.CoordinatorInjectedCrash):
            async with session:
                await session.commit()
        await support._stop_dispatch_before_explicit_resume(
            harness,
            session,
            coordinator=recovery,
        )
        sessions.append(session)
    return tuple(sessions)


def _seed_handoff_lease(
    store: SQLiteEnforcedTransactionStore,
    session,
    *,
    binding: RecoveryActionBinding,
    acquired_at: datetime,
    released_at: datetime | None,
) -> WorkerLeaseRecord:
    """Create the exact recovery lease generation required by a synthetic handoff."""

    with store._immediate():
        lease, created = store._acquire_worker_lease_tx(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
            lease_id=f"lease:audit-handoff:{binding.recovery_id}",
            worker_id="worker:audit-handoff",
            purpose=LeasePurpose.RECOVERY,
            acquired_at=acquired_at,
            expires_at=binding.absolute_deadline,
        )
        assert created
        if released_at is not None:
            released = WorkerLeaseRecord.model_validate(
                {
                    **lease.model_dump(mode="python"),
                    "version": lease.version + 1,
                    "released_at": released_at,
                }
            )
            store._update_worker_lease_tx(lease, released)
    return lease


def _insert_terminal_handoffs(
    store: SQLiteEnforcedTransactionStore,
    sessions,
    *,
    first_sequence: int,
    count: int,
    created_at,
) -> None:
    assert len(sessions) == count
    rows: list[tuple[object, ...]] = []
    for sequence, session in zip(
        range(first_sequence, first_sequence + count),
        sessions,
        strict=True,
    ):
        dispatch = store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        binding = _terminal_binding(store, session, dispatch=dispatch)
        lease = _seed_handoff_lease(
            store,
            session,
            binding=binding,
            acquired_at=created_at,
            released_at=created_at,
        )
        rows.append(
            (
                session.record.tenant_id,
                session.record.transaction_id,
                binding.recovery_id,
                binding.recovery_kind.value,
                binding.target_id,
                binding.target_evidence_ref,
                canonical_digest(binding),
                canonical_json_text(binding),
                lease.lease_id,
                lease.worker_id,
                lease.fencing_token,
                _timestamp(created_at),
                _timestamp(created_at),
                sequence,
                "UNAVAILABLE",
                "EVIDENCE_UNAVAILABLE:synthetic",
            )
        )
    store._connection.executemany(
        "INSERT INTO enforced_recovery_action_handoffs("
        "tenant_id, target_transaction_id, recovery_id, recovery_kind, "
        "target_id, target_evidence_ref, binding_ref, binding_json, "
        "handoff_lease_id, handoff_worker_id, handoff_fencing_token, "
        "recovery_action_transaction_id, recovery_action_intent_hash, "
        "recovery_action_digest, created_at, attached_at, closed_at, "
        "terminal_sequence, failure_evidence_status, failure_evidence_ref, "
        "failure_reason_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, "
        "?, NULL, ?, ?, ?, NULL, ?)",
        rows,
    )
    final_sequence = first_sequence + count - 1
    head = store._connection.execute(
        "SELECT terminal_sequence FROM enforced_recovery_handoff_terminal_heads "
        "WHERE tenant_id = ?",
        (sessions[0].record.tenant_id,),
    ).fetchone()
    if head is None:
        store._connection.execute(
            "INSERT INTO enforced_recovery_handoff_terminal_heads("
            "tenant_id, terminal_sequence, updated_at) VALUES (?, ?, ?)",
            (sessions[0].record.tenant_id, final_sequence, _timestamp(created_at)),
        )
    else:
        assert count == 1
        assert int(head["terminal_sequence"]) + 1 == final_sequence
        store._connection.execute(
            "UPDATE enforced_recovery_handoff_terminal_heads SET "
            "terminal_sequence = ?, updated_at = ? WHERE tenant_id = ?",
            (
                final_sequence,
                _timestamp(created_at),
                sessions[0].record.tenant_id,
            ),
        )
    store._connection.commit()


def _insert_open_handoffs(
    store: SQLiteEnforcedTransactionStore,
    sessions,
    *,
    count: int,
    created_at,
) -> tuple[str, ...]:
    assert len(sessions) == count
    rows: list[tuple[object, ...]] = []
    recovery_ids: list[str] = []
    for session in sessions:
        dispatch = store.get_commit_dispatch(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )
        binding = _terminal_binding(store, session, dispatch=dispatch)
        lease = _seed_handoff_lease(
            store,
            session,
            binding=binding,
            acquired_at=created_at,
            released_at=None,
        )
        recovery_ids.append(binding.recovery_id)
        rows.append(
            (
                session.record.tenant_id,
                session.record.transaction_id,
                binding.recovery_id,
                binding.recovery_kind.value,
                binding.target_id,
                binding.target_evidence_ref,
                canonical_digest(binding),
                canonical_json_text(binding),
                lease.lease_id,
                lease.worker_id,
                lease.fencing_token,
                _timestamp(created_at),
            )
        )
    store._connection.executemany(
        "INSERT INTO enforced_recovery_action_handoffs("
        "tenant_id, target_transaction_id, recovery_id, recovery_kind, "
        "target_id, target_evidence_ref, binding_ref, binding_json, "
        "handoff_lease_id, handoff_worker_id, handoff_fencing_token, "
        "recovery_action_transaction_id, recovery_action_intent_hash, "
        "recovery_action_digest, created_at, attached_at, closed_at, "
        "terminal_sequence, failure_evidence_status, failure_evidence_ref, "
        "failure_reason_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, "
        "?, NULL, NULL, NULL, 'NONE', NULL, NULL)",
        rows,
    )
    store._connection.commit()
    return tuple(recovery_ids)


def _insert_semantic_audit_handoffs(
    harness,
    sessions,
    *,
    recorded_at,
) -> None:
    assert len(sessions) == 3
    bindings = tuple(
        _terminal_binding(
            harness.store,
            session,
            dispatch=harness.store.get_commit_dispatch(
                tenant_id=session.record.tenant_id,
                transaction_id=session.record.transaction_id,
            ),
        )
        for session in sessions
    )
    binding_refs = tuple(canonical_digest(binding) for binding in bindings)
    valid_evidence = CoordinatorEvidence(
        transaction_id=sessions[0].record.transaction_id,
        event="recovery.authorization_handoff_failed",
        reason_code="RECOVERY_AUDIT_VALID",
        recorded_at=recorded_at,
        subject_ref=binding_refs[0],
    )
    mismatched_evidence = CoordinatorEvidence(
        transaction_id=sessions[2].record.transaction_id,
        event="recovery.authorization_handoff_failed",
        reason_code="RECOVERY_AUDIT_DIFFERENT",
        recorded_at=recorded_at,
        subject_ref=binding_refs[2],
    )
    valid_ref = harness.artifacts.put_model(valid_evidence).digest
    mismatched_ref = harness.artifacts.put_model(mismatched_evidence).digest
    rows = (
        (
            bindings[0],
            binding_refs[0],
            "AVAILABLE",
            valid_ref,
            valid_evidence.reason_code,
        ),
        (
            bindings[1],
            binding_refs[1],
            "UNAVAILABLE",
            None,
            "EVIDENCE_UNAVAILABLE:synthetic",
        ),
        (
            bindings[2],
            binding_refs[2],
            "AVAILABLE",
            mismatched_ref,
            "RECOVERY_AUDIT_EXPECTED",
        ),
    )
    leases = tuple(
        _seed_handoff_lease(
            harness.store,
            session,
            binding=binding,
            acquired_at=recorded_at,
            released_at=recorded_at,
        )
        for session, binding in zip(sessions, bindings, strict=True)
    )
    harness.store._connection.executemany(
        "INSERT INTO enforced_recovery_action_handoffs("
        "tenant_id, target_transaction_id, recovery_id, recovery_kind, "
        "target_id, target_evidence_ref, binding_ref, binding_json, "
        "handoff_lease_id, handoff_worker_id, handoff_fencing_token, "
        "recovery_action_transaction_id, recovery_action_intent_hash, "
        "recovery_action_digest, created_at, attached_at, closed_at, "
        "terminal_sequence, failure_evidence_status, failure_evidence_ref, "
        "failure_reason_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, "
        "?, NULL, ?, ?, ?, ?, ?)",
        tuple(
            (
                session.record.tenant_id,
                session.record.transaction_id,
                binding.recovery_id,
                binding.recovery_kind.value,
                binding.target_id,
                binding.target_evidence_ref,
                binding_ref,
                canonical_json_text(binding),
                lease.lease_id,
                lease.worker_id,
                lease.fencing_token,
                _timestamp(recorded_at),
                _timestamp(recorded_at),
                sequence,
                status,
                evidence_ref,
                reason_code,
            )
            for sequence, (
                session,
                lease,
                (binding, binding_ref, status, evidence_ref, reason_code),
            ) in enumerate(zip(sessions, leases, rows, strict=True), start=1)
        ),
    )
    harness.store._connection.execute(
        "INSERT INTO enforced_recovery_handoff_terminal_heads("
        "tenant_id, terminal_sequence, updated_at) VALUES (?, 3, ?)",
        (sessions[0].record.tenant_id, _timestamp(recorded_at)),
    )
    harness.store._connection.commit()


def _close_seed_handoff(
    store: SQLiteEnforcedTransactionStore,
    session,
    *,
    recovery_id: str,
    closed_at,
) -> int:
    with store._immediate():
        handoff_row = store._connection.execute(
            "SELECT handoff_lease_id FROM enforced_recovery_action_handoffs "
            "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
            (
                session.record.tenant_id,
                session.record.transaction_id,
                recovery_id,
            ),
        ).fetchone()
        assert handoff_row is not None
        lease = store._get_worker_lease_tx(
            session.record.tenant_id,
            session.record.transaction_id,
            str(handoff_row["handoff_lease_id"]),
        )
        assert lease.released_at is None
        released = WorkerLeaseRecord.model_validate(
            {
                **lease.model_dump(mode="python"),
                "version": lease.version + 1,
                "released_at": closed_at,
            }
        )
        store._update_worker_lease_tx(lease, released)
        terminal_sequence = store._next_recovery_handoff_terminal_sequence_tx(
            session.record.tenant_id,
            recorded_at=closed_at,
        )
        updated = store._connection.execute(
            "UPDATE enforced_recovery_action_handoffs SET closed_at = ?, "
            "terminal_sequence = ?, failure_evidence_status = 'UNAVAILABLE', "
            "failure_reason_code = 'EVIDENCE_UNAVAILABLE:synthetic' "
            "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ? "
            "AND closed_at IS NULL",
            (
                _timestamp(closed_at),
                terminal_sequence,
                session.record.tenant_id,
                session.record.transaction_id,
                recovery_id,
            ),
        )
        assert updated.rowcount == 1
    return terminal_sequence


@pytest.mark.asyncio
async def test_handoff_terminal_sequence_is_atomic_and_not_timestamp_ordered(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    try:
        sessions = await _prepare_reconciliation_targets(harness, count=2)
        first_session, second_session = sessions
        created_at = harness.clock()
        first_id, second_id = _insert_open_handoffs(
            harness.store,
            sessions,
            count=2,
            created_at=created_at,
        )
        assert (
            _close_seed_handoff(
                harness.store,
                first_session,
                recovery_id=first_id,
                closed_at=created_at + timedelta(minutes=10),
            )
            == 1
        )

        harness.store._connection.execute(
            "CREATE TEMP TRIGGER fail_synthetic_terminal_close "
            "BEFORE UPDATE ON enforced_recovery_action_handoffs "
            "WHEN OLD.closed_at IS NULL AND NEW.closed_at IS NOT NULL "
            "BEGIN SELECT RAISE(ABORT, 'synthetic terminal close failure'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="synthetic terminal close failure"):
            _close_seed_handoff(
                harness.store,
                second_session,
                recovery_id=second_id,
                closed_at=created_at + timedelta(minutes=5),
            )
        head_after_rollback = harness.store._connection.execute(
            "SELECT terminal_sequence FROM enforced_recovery_handoff_terminal_heads "
            "WHERE tenant_id = ?",
            (first_session.record.tenant_id,),
        ).fetchone()
        assert int(head_after_rollback["terminal_sequence"]) == 1
        assert (
            harness.store._connection.execute(
                "SELECT closed_at FROM enforced_recovery_action_handoffs "
                "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
                (
                    second_session.record.tenant_id,
                    second_session.record.transaction_id,
                    second_id,
                ),
            ).fetchone()["closed_at"]
            is None
        )
        harness.store._connection.execute("DROP TRIGGER fail_synthetic_terminal_close")

        assert (
            _close_seed_handoff(
                harness.store,
                second_session,
                recovery_id=second_id,
                closed_at=created_at + timedelta(minutes=5),
            )
            == 2
        )
        rows = harness.store._connection.execute(
            "SELECT terminal_sequence, closed_at FROM enforced_recovery_action_handoffs "
            "WHERE tenant_id = ? ORDER BY terminal_sequence",
            (first_session.record.tenant_id,),
        ).fetchall()
        assert [int(row["terminal_sequence"]) for row in rows] == [1, 2]
        assert rows[0]["closed_at"] > rows[1]["closed_at"]

        with pytest.raises(AssertionError):
            _close_seed_handoff(
                harness.store,
                second_session,
                recovery_id=second_id,
                closed_at=created_at + timedelta(minutes=6),
            )
        final_head = harness.store._connection.execute(
            "SELECT terminal_sequence FROM enforced_recovery_handoff_terminal_heads "
            "WHERE tenant_id = ?",
            (first_session.record.tenant_id,),
        ).fetchone()
        assert int(final_head["terminal_sequence"]) == 2
    finally:
        harness.store.close()


@pytest.mark.asyncio
async def test_audit_257_page_restart_and_immutable_high_watermark(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    reopened: SQLiteEnforcedTransactionStore | None = None
    try:
        sessions = await _prepare_reconciliation_targets(harness, count=258)
        session = sessions[0]
        seed_checkpoint = harness.store.get_recovery_handoff_evidence_audit_checkpoint(
            session.record.tenant_id
        )
        assert seed_checkpoint is not None
        recorded_at = harness.clock() + timedelta(minutes=1)
        _insert_terminal_handoffs(
            harness.store,
            sessions[:257],
            first_sequence=1,
            count=257,
            created_at=recorded_at,
        )

        checkpoint = harness.store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=session.record.tenant_id,
            expected=seed_checkpoint,
            recorded_at=recorded_at,
            reaudit_interval=timedelta(minutes=5),
        )
        assert checkpoint.current_cycle == seed_checkpoint.current_cycle + 1
        assert checkpoint.current_cycle_high_watermark == 257
        assert checkpoint.cursor.terminal_sequence == 0
        assert checkpoint.version == seed_checkpoint.version + 1

        first_page = harness.store.scan_terminal_recovery_handoff_evidence(
            tenant_id=session.record.tenant_id,
            cycle_high_watermark=checkpoint.current_cycle_high_watermark,
            cursor=checkpoint.cursor,
            limit=256,
        )
        assert len(first_page.handoffs) == 256
        assert first_page.next_cursor.terminal_sequence == 256
        assert not first_page.cycle_complete
        checkpoint = harness.store.advance_recovery_handoff_evidence_audit(
            tenant_id=session.record.tenant_id,
            expected=checkpoint,
            next_cursor=first_page.next_cursor,
            page_failure_count=256,
            completed=False,
            recorded_at=recorded_at + timedelta(seconds=1),
        )

        _insert_terminal_handoffs(
            harness.store,
            sessions[257:],
            first_sequence=258,
            count=1,
            created_at=recorded_at - timedelta(minutes=1),
        )
        harness.store.close()
        reopened = SQLiteEnforcedTransactionStore(database_path)

        restarted = reopened.get_recovery_handoff_evidence_audit_checkpoint(
            session.record.tenant_id
        )
        assert restarted == checkpoint
        assert restarted.current_cycle_high_watermark == 257
        second_page = reopened.scan_terminal_recovery_handoff_evidence(
            tenant_id=session.record.tenant_id,
            cycle_high_watermark=restarted.current_cycle_high_watermark,
            cursor=restarted.cursor,
            limit=256,
        )
        assert len(second_page.handoffs) == 1
        assert second_page.next_cursor.terminal_sequence == 257
        assert second_page.cycle_complete
        completed = reopened.advance_recovery_handoff_evidence_audit(
            tenant_id=session.record.tenant_id,
            expected=restarted,
            next_cursor=second_page.next_cursor,
            page_failure_count=1,
            completed=True,
            recorded_at=recorded_at + timedelta(seconds=2),
        )
        assert completed.current_cycle_complete
        assert completed.current_cycle_failure_count == 257
        assert completed.last_completed_high_watermark == 257
        assert (
            reopened.validate_recovery_handoff_evidence_audit_history(
                tenant_id=session.record.tenant_id,
                page_size=256,
            )
            == completed
        )

        next_cycle = reopened.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=session.record.tenant_id,
            expected=completed,
            recorded_at=recorded_at + timedelta(seconds=3),
            reaudit_interval=timedelta(minutes=5),
        )
        assert next_cycle.current_cycle == completed.current_cycle + 1
        assert next_cycle.current_cycle_high_watermark == 258
        assert next_cycle.cursor.terminal_sequence == 0
    finally:
        if reopened is not None:
            reopened.close()
        harness.store.close()


def test_audit_non_due_idle_calls_do_not_write(tmp_path: Path) -> None:
    database_path = tmp_path / "control.db"
    tenant_id = "tenant:audit-idle"
    with SQLiteEnforcedTransactionStore(database_path) as store:
        recorded_at = _RECORDED_AT
        checkpoint = store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=tenant_id,
            expected=None,
            recorded_at=recorded_at,
            reaudit_interval=timedelta(minutes=5),
        )
        assert checkpoint.current_cycle_complete
        before_changes = store._connection.total_changes
        before_events = store._connection.execute(
            "SELECT COUNT(*) FROM enforced_recovery_handoff_evidence_audit_events "
            "WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]

        for _ in range(10_000):
            assert (
                store.start_recovery_handoff_evidence_audit_cycle(
                    tenant_id=tenant_id,
                    expected=checkpoint,
                    recorded_at=recorded_at + timedelta(minutes=1),
                    reaudit_interval=timedelta(minutes=5),
                )
                == checkpoint
            )

        assert store._connection.total_changes == before_changes
        assert (
            store._connection.execute(
                "SELECT COUNT(*) FROM enforced_recovery_handoff_evidence_audit_events "
                "WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()[0]
            == before_events
            == 1
        )
        assert (
            store._connection.execute(
                "SELECT 1 FROM enforced_recovery_handoff_terminal_heads WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            is None
        )

        due = store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=tenant_id,
            expected=checkpoint,
            recorded_at=recorded_at + timedelta(minutes=5),
            reaudit_interval=timedelta(minutes=5),
        )
        assert due.current_cycle == checkpoint.current_cycle + 1
        assert due.version == checkpoint.version + 1
        forced = store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=tenant_id,
            expected=due,
            recorded_at=recorded_at + timedelta(minutes=5, microseconds=1),
            reaudit_interval=timedelta(minutes=5),
            force=True,
        )
        assert forced.current_cycle == due.current_cycle + 1
        assert forced.version == due.version + 1
        assert (
            store._connection.execute(
                "SELECT COUNT(*) FROM enforced_recovery_handoff_evidence_audit_events "
                "WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()[0]
            == 3
        )


@pytest.mark.asyncio
async def test_audit_tenant_isolation_and_stale_checkpoint_cas(tmp_path: Path) -> None:
    database_path = tmp_path / "control.db"
    harness = support._make_harness(
        tmp_path,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    competing: SQLiteEnforcedTransactionStore | None = None
    tenant_b = "tenant:audit-isolated-b"
    try:
        sessions = await _prepare_reconciliation_targets(harness, count=1)
        session = sessions[0]
        seed_checkpoint = harness.store.get_recovery_handoff_evidence_audit_checkpoint(
            session.record.tenant_id
        )
        assert seed_checkpoint is not None
        recorded_at = harness.clock()
        _insert_terminal_handoffs(
            harness.store,
            sessions,
            first_sequence=1,
            count=1,
            created_at=recorded_at,
        )
        checkpoint_a = harness.store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=session.record.tenant_id,
            expected=seed_checkpoint,
            recorded_at=recorded_at,
            reaudit_interval=timedelta(minutes=5),
        )
        checkpoint_b = harness.store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=tenant_b,
            expected=None,
            recorded_at=recorded_at,
            reaudit_interval=timedelta(minutes=5),
        )
        page = harness.store.scan_terminal_recovery_handoff_evidence(
            tenant_id=session.record.tenant_id,
            cycle_high_watermark=checkpoint_a.current_cycle_high_watermark,
            cursor=checkpoint_a.cursor,
            limit=256,
        )
        with pytest.raises(AgentKernelError) as cross_tenant:
            harness.store.advance_recovery_handoff_evidence_audit(
                tenant_id=session.record.tenant_id,
                expected=checkpoint_a,
                next_cursor=RecoveryHandoffEvidenceCursor(
                    tenant_id=tenant_b,
                    terminal_sequence=1,
                ),
                page_failure_count=1,
                completed=True,
                recorded_at=recorded_at + timedelta(seconds=1),
            )
        assert cross_tenant.value.code is ErrorCode.VALIDATION_ERROR

        competing = SQLiteEnforcedTransactionStore(database_path)
        completed = harness.store.advance_recovery_handoff_evidence_audit(
            tenant_id=session.record.tenant_id,
            expected=checkpoint_a,
            next_cursor=page.next_cursor,
            page_failure_count=1,
            completed=True,
            recorded_at=recorded_at + timedelta(seconds=1),
        )
        with pytest.raises(AgentKernelError) as stale_advance:
            competing.advance_recovery_handoff_evidence_audit(
                tenant_id=session.record.tenant_id,
                expected=checkpoint_a,
                next_cursor=page.next_cursor,
                page_failure_count=1,
                completed=True,
                recorded_at=recorded_at + timedelta(seconds=1),
            )
        assert stale_advance.value.code is ErrorCode.VERSION_CONFLICT
        assert stale_advance.value.retryable
        with pytest.raises(AgentKernelError) as stale_start:
            competing.start_recovery_handoff_evidence_audit_cycle(
                tenant_id=session.record.tenant_id,
                expected=checkpoint_a,
                recorded_at=recorded_at + timedelta(minutes=5),
                reaudit_interval=timedelta(minutes=5),
            )
        assert stale_start.value.code is ErrorCode.VERSION_CONFLICT
        assert stale_start.value.retryable

        assert (
            competing.get_recovery_handoff_evidence_audit_checkpoint(session.record.tenant_id)
            == completed
        )
        assert competing.get_recovery_handoff_evidence_audit_checkpoint(tenant_b) == checkpoint_b
        assert (
            competing._connection.execute(
                "SELECT COUNT(*) FROM enforced_recovery_handoff_evidence_audit_events "
                "WHERE tenant_id = ?",
                (tenant_b,),
            ).fetchone()[0]
            == 1
        )
    finally:
        if competing is not None:
            competing.close()
        harness.store.close()


@pytest.mark.asyncio
async def test_coordinator_audit_semantics_cadence_and_result_contract(
    tmp_path: Path,
) -> None:
    harness = support._make_harness(
        tmp_path,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    try:
        sessions = await _prepare_reconciliation_targets(harness, count=3)
        session = sessions[0]
        recorded_at = harness.clock()
        _insert_semantic_audit_handoffs(
            harness,
            sessions,
            recorded_at=recorded_at,
        )
        baseline_event_count = harness.store._connection.execute(
            "SELECT COUNT(*) FROM enforced_recovery_handoff_evidence_audit_events "
            "WHERE tenant_id = ?",
            (session.record.tenant_id,),
        ).fetchone()[0]

        first = await harness.coordinator.recover_once(session.record.tenant_id)
        assert first.scanned == first.processed == first.remaining == 0
        assert len(first.failures) == 2
        assert all(failure.kind is RecoveryFailureKind.EVIDENCE_AUDIT for failure in first.failures)
        assert first.handoff_evidence_audit_high_watermark == 3
        assert first.handoff_evidence_audit_cycle_complete
        assert not first.handoff_evidence_audit_ready
        assert first.handoff_evidence_audit_failure_count == 2
        first_event_count = harness.store._connection.execute(
            "SELECT COUNT(*) FROM enforced_recovery_handoff_evidence_audit_events "
            "WHERE tenant_id = ?",
            (session.record.tenant_id,),
        ).fetchone()[0]
        assert first_event_count == baseline_event_count + 2

        non_due = await harness.coordinator.recover_once(session.record.tenant_id)
        assert not non_due.failures
        assert non_due.handoff_evidence_audit_cycle == first.handoff_evidence_audit_cycle
        assert non_due.handoff_evidence_audit_failure_count == 2
        assert (
            harness.store._connection.execute(
                "SELECT COUNT(*) FROM enforced_recovery_handoff_evidence_audit_events "
                "WHERE tenant_id = ?",
                (session.record.tenant_id,),
            ).fetchone()[0]
            == first_event_count
        )

        forced = await harness.coordinator.recover_once(
            session.record.tenant_id,
            force_handoff_evidence_audit=True,
        )
        assert len(forced.failures) == 2
        assert forced.handoff_evidence_audit_cycle == first.handoff_evidence_audit_cycle + 1
        assert forced.handoff_evidence_audit_failure_count == 2
        forced_event_count = harness.store._connection.execute(
            "SELECT COUNT(*) FROM enforced_recovery_handoff_evidence_audit_events "
            "WHERE tenant_id = ?",
            (session.record.tenant_id,),
        ).fetchone()[0]
        assert forced_event_count == first_event_count + 2

        harness.clock.advance(harness.coordinator._config.handoff_evidence_reaudit_interval)
        due = await harness.coordinator.recover_once(session.record.tenant_id)
        assert len(due.failures) == 2
        assert due.handoff_evidence_audit_cycle == forced.handoff_evidence_audit_cycle + 1
        assert due.handoff_evidence_audit_failure_count == 2
        assert (
            harness.store._connection.execute(
                "SELECT COUNT(*) FROM enforced_recovery_handoff_evidence_audit_events "
                "WHERE tenant_id = ?",
                (session.record.tenant_id,),
            ).fetchone()[0]
            == forced_event_count + 2
        )
    finally:
        harness.store.close()


def test_audit_event_material_and_predecessor_chain_are_canonical(tmp_path: Path) -> None:
    database_path = tmp_path / "control.db"
    tenant_id = "tenant:audit-chain"
    with SQLiteEnforcedTransactionStore(database_path) as store:
        checkpoint = store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=tenant_id,
            expected=None,
            recorded_at=_RECORDED_AT,
            reaudit_interval=timedelta(minutes=5),
        )
        for index in range(1, 4):
            checkpoint = store.start_recovery_handoff_evidence_audit_cycle(
                tenant_id=tenant_id,
                expected=checkpoint,
                recorded_at=_RECORDED_AT + timedelta(microseconds=index),
                reaudit_interval=timedelta(minutes=5),
                force=True,
            )

        rows = store._connection.execute(
            "SELECT * FROM enforced_recovery_handoff_evidence_audit_events "
            "WHERE tenant_id = ? ORDER BY sequence",
            (tenant_id,),
        ).fetchall()
        assert len(rows) == checkpoint.version + 1 == 4
        previous_digest = None
        for expected_sequence, row in enumerate(rows):
            event = store._recovery_handoff_evidence_audit_event_from_row(row)
            checkpoint_material = json.loads(str(row["checkpoint_json"]))
            event_material = json.loads(str(row["event_json"]))
            assert event.sequence == expected_sequence
            assert event.checkpoint.version == expected_sequence
            expected_checkpoint_material = (
                store._recovery_handoff_evidence_audit_checkpoint_material(event.checkpoint)
            )
            assert checkpoint_material == expected_checkpoint_material
            assert canonical_json_text(checkpoint_material) == str(row["checkpoint_json"])
            assert canonical_digest(checkpoint_material) == event.checkpoint_digest
            assert event.previous_event_digest == previous_digest
            assert event_material == store._recovery_handoff_evidence_audit_event_material(
                tenant_id=event.tenant_id,
                sequence=event.sequence,
                checkpoint_digest=event.checkpoint_digest,
                previous_event_digest=event.previous_event_digest,
                recorded_at=event.recorded_at,
            )
            assert canonical_json_text(event_material) == str(row["event_json"])
            assert canonical_digest(event_material) == event.event_digest
            previous_digest = event.event_digest
        assert previous_digest == rows[-1]["event_digest"]
        assert (
            store.validate_recovery_handoff_evidence_audit_history(
                tenant_id=tenant_id,
                page_size=2,
            )
            == checkpoint
        )


@pytest.mark.parametrize(
    ("operation", "statement"),
    [
        (
            "update-event",
            "UPDATE enforced_recovery_handoff_evidence_audit_events "
            "SET event_json = '{}' WHERE tenant_id = ?",
        ),
        (
            "delete-event",
            "DELETE FROM enforced_recovery_handoff_evidence_audit_events WHERE tenant_id = ?",
        ),
        (
            "update-checkpoint",
            "UPDATE enforced_recovery_handoff_evidence_audits "
            "SET current_cycle = current_cycle + 1 WHERE tenant_id = ?",
        ),
        (
            "delete-checkpoint",
            "DELETE FROM enforced_recovery_handoff_evidence_audits WHERE tenant_id = ?",
        ),
    ],
)
def test_audit_projection_and_events_are_immutable_by_default(
    tmp_path: Path,
    operation: str,
    statement: str,
) -> None:
    database_path = tmp_path / f"audit-immutable-{operation}.db"
    tenant_id = "tenant:audit-immutable"
    with SQLiteEnforcedTransactionStore(database_path) as store:
        store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=tenant_id,
            expected=None,
            recorded_at=_RECORDED_AT,
            reaudit_interval=timedelta(minutes=5),
        )
        with pytest.raises(sqlite3.IntegrityError):
            store._connection.execute(statement, (tenant_id,))
        assert store.get_recovery_handoff_evidence_audit_checkpoint(tenant_id) is not None


@pytest.mark.parametrize("corrupt_sequence_offset", [0, -1])
def test_hot_audit_getter_rejects_corrupt_head_or_immediate_predecessor(
    tmp_path: Path,
    corrupt_sequence_offset: int,
) -> None:
    database_path = tmp_path / f"audit-hot-corruption-{corrupt_sequence_offset}.db"
    tenant_id = "tenant:audit-hot-corruption"
    store = SQLiteEnforcedTransactionStore(database_path)
    try:
        checkpoint = store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=tenant_id,
            expected=None,
            recorded_at=_RECORDED_AT,
            reaudit_interval=timedelta(minutes=5),
        )
        for index in range(1, 5):
            checkpoint = store.start_recovery_handoff_evidence_audit_cycle(
                tenant_id=tenant_id,
                expected=checkpoint,
                recorded_at=_RECORDED_AT + timedelta(microseconds=index),
                reaudit_interval=timedelta(minutes=5),
                force=True,
            )
        trigger_sql = store._connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?",
            ("enforced_recovery_handoff_evidence_audit_events_no_update",),
        ).fetchone()[0]
        store._connection.execute(
            "DROP TRIGGER enforced_recovery_handoff_evidence_audit_events_no_update"
        )
        store._connection.execute(
            "UPDATE enforced_recovery_handoff_evidence_audit_events "
            "SET event_json = '{}' WHERE tenant_id = ? AND sequence = ?",
            (tenant_id, checkpoint.version + corrupt_sequence_offset),
        )
        store._connection.execute(trigger_sql)
        store._connection.commit()
    finally:
        store.close()

    with pytest.raises(AgentKernelError) as captured:
        SQLiteEnforcedTransactionStore(database_path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.asyncio
@pytest.mark.parametrize("corruption", ["head-mismatch", "sequence-gap"])
async def test_terminal_sequence_head_or_gap_corruption_fails_closed(
    tmp_path: Path,
    corruption: str,
) -> None:
    harness = support._make_harness(
        tmp_path,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_DISPATCHED,
    )
    try:
        count = 1 if corruption == "head-mismatch" else 3
        sessions = await _prepare_reconciliation_targets(harness, count=count)
        session = sessions[0]
        seed_checkpoint = harness.store.get_recovery_handoff_evidence_audit_checkpoint(
            session.record.tenant_id
        )
        assert seed_checkpoint is not None
        _insert_terminal_handoffs(
            harness.store,
            sessions,
            first_sequence=1,
            count=count,
            created_at=harness.clock(),
        )
        if corruption == "head-mismatch":
            harness.store._connection.execute(
                "UPDATE enforced_recovery_handoff_terminal_heads "
                "SET terminal_sequence = 2 WHERE tenant_id = ?",
                (session.record.tenant_id,),
            )
        else:
            trigger_sql = harness.store._connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?",
                ("enforced_recovery_action_handoffs_no_delete",),
            ).fetchone()[0]
            harness.store._connection.execute(
                "DROP TRIGGER enforced_recovery_action_handoffs_no_delete"
            )
            harness.store._connection.execute(
                "DELETE FROM enforced_recovery_action_handoffs "
                "WHERE tenant_id = ? AND terminal_sequence = 2",
                (session.record.tenant_id,),
            )
            harness.store._connection.execute(trigger_sql)
        harness.store._connection.commit()

        if corruption == "head-mismatch":
            with pytest.raises(AgentKernelError) as captured:
                harness.store.start_recovery_handoff_evidence_audit_cycle(
                    tenant_id=session.record.tenant_id,
                    expected=seed_checkpoint,
                    recorded_at=harness.clock(),
                    reaudit_interval=timedelta(minutes=5),
                )
        else:
            checkpoint = harness.store.start_recovery_handoff_evidence_audit_cycle(
                tenant_id=session.record.tenant_id,
                expected=seed_checkpoint,
                recorded_at=harness.clock(),
                reaudit_interval=timedelta(minutes=5),
            )
            with pytest.raises(AgentKernelError) as captured:
                harness.store.scan_terminal_recovery_handoff_evidence(
                    tenant_id=session.record.tenant_id,
                    cycle_high_watermark=checkpoint.current_cycle_high_watermark,
                    cursor=checkpoint.cursor,
                    limit=256,
                )
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    finally:
        harness.store.close()


def test_hot_audit_head_is_bounded_but_full_validation_finds_deep_corruption(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "control.db"
    tenant_id = "tenant:audit-deep-corruption"
    store = SQLiteEnforcedTransactionStore(database_path)
    try:
        recorded_at = _RECORDED_AT
        checkpoint = store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=tenant_id,
            expected=None,
            recorded_at=recorded_at,
            reaudit_interval=timedelta(minutes=5),
        )
        for index in range(1, 300):
            checkpoint = store.start_recovery_handoff_evidence_audit_cycle(
                tenant_id=tenant_id,
                expected=checkpoint,
                recorded_at=recorded_at + timedelta(microseconds=index),
                reaudit_interval=timedelta(minutes=5),
                force=True,
            )
        assert checkpoint.version == 299
        trigger_sql = store._connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?",
            ("enforced_recovery_handoff_evidence_audit_events_no_update",),
        ).fetchone()[0]
        store._connection.execute(
            "DROP TRIGGER enforced_recovery_handoff_evidence_audit_events_no_update"
        )
        store._connection.execute(
            "UPDATE enforced_recovery_handoff_evidence_audit_events "
            "SET event_json = '{}' WHERE tenant_id = ? AND sequence = 10",
            (tenant_id,),
        )
        store._connection.execute(trigger_sql)
        store._connection.commit()
    finally:
        store.close()

    with SQLiteEnforcedTransactionStore(database_path) as reopened:
        assert reopened.get_recovery_handoff_evidence_audit_checkpoint(tenant_id) == checkpoint
        with pytest.raises(AgentKernelError) as captured:
            reopened.validate_recovery_handoff_evidence_audit_history(
                tenant_id=tenant_id,
                page_size=256,
            )
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
def test_ten_thousand_event_hot_read_is_bounded_and_full_validation_is_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "audit-ten-thousand-events.db"
    tenant_id = "tenant:audit-ten-thousand"
    with SQLiteEnforcedTransactionStore(database_path) as store:
        checkpoint = store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=tenant_id,
            expected=None,
            recorded_at=_RECORDED_AT,
            reaudit_interval=timedelta(minutes=5),
        )
        for index in range(1, 10_000):
            checkpoint = store.start_recovery_handoff_evidence_audit_cycle(
                tenant_id=tenant_id,
                expected=checkpoint,
                recorded_at=_RECORDED_AT + timedelta(microseconds=index),
                reaudit_interval=timedelta(minutes=5),
                force=True,
            )
        assert checkpoint.version == 9_999
        assert (
            store._connection.execute(
                "SELECT COUNT(*) FROM enforced_recovery_handoff_evidence_audit_events "
                "WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()[0]
            == 10_000
        )

        original_parser = store._recovery_handoff_evidence_audit_event_from_row
        parse_count = 0

        def counted_parser(row):
            nonlocal parse_count
            parse_count += 1
            return original_parser(row)

        monkeypatch.setattr(
            store,
            "_recovery_handoff_evidence_audit_event_from_row",
            counted_parser,
        )
        traced_selects: list[str] = []
        store._connection.set_trace_callback(
            lambda statement: (
                traced_selects.append(statement)
                if statement.lstrip().upper().startswith("SELECT")
                else None
            )
        )
        assert store.get_recovery_handoff_evidence_audit_checkpoint(tenant_id) == checkpoint
        store._connection.set_trace_callback(None)
        assert parse_count == 2
        assert len(traced_selects) <= 7

        parse_count = 0
        assert (
            store.validate_recovery_handoff_evidence_audit_history(
                tenant_id=tenant_id,
                page_size=256,
            )
            == checkpoint
        )
        assert parse_count == 10_002

        plan = store._connection.execute(
            "EXPLAIN QUERY PLAN SELECT * "
            "FROM enforced_recovery_handoff_evidence_audit_events "
            "WHERE tenant_id = ? AND sequence >= ? AND sequence <= ? "
            "ORDER BY sequence LIMIT ?",
            (tenant_id, 0, checkpoint.version, 256),
        ).fetchall()
        details = " ".join(str(row["detail"]) for row in plan)
        assert "SEARCH" in details
        assert "tenant_id=?" in details


def _read_corrupt_audit_state(
    store: SQLiteEnforcedTransactionStore,
    *,
    tenant_id: str,
    operation: str,
) -> None:
    if operation == "start":
        store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=tenant_id,
            expected=None,
            recorded_at=_RECORDED_AT,
            reaudit_interval=timedelta(minutes=5),
        )
    elif operation == "get":
        store.get_recovery_handoff_evidence_audit_checkpoint(tenant_id)
    else:
        store.validate_recovery_handoff_evidence_audit_history(tenant_id=tenant_id)


@pytest.mark.parametrize("operation", ["start", "get", "full"])
def test_terminal_head_zero_corruption_fails_closed(
    tmp_path: Path,
    operation: str,
) -> None:
    database_path = tmp_path / f"zero-head-{operation}.db"
    tenant_id = "tenant:zero-head"
    with SQLiteEnforcedTransactionStore(database_path) as store:
        recorded_at = _RECORDED_AT
        store._connection.execute("PRAGMA ignore_check_constraints = ON")
        store._connection.execute(
            "INSERT INTO enforced_recovery_handoff_terminal_heads("
            "tenant_id, terminal_sequence, updated_at) VALUES (?, 0, ?)",
            (tenant_id, _timestamp(recorded_at)),
        )
        store._connection.commit()

        with pytest.raises(AgentKernelError) as captured:
            _read_corrupt_audit_state(
                store,
                tenant_id=tenant_id,
                operation=operation,
            )
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_coordinator_evidence_rejects_noncanonical_profile() -> None:
    with pytest.raises(ValidationError, match="profile"):
        CoordinatorEvidence(
            profile="agentkernel.coordinator-evidence/v0",
            transaction_id="txn:wrong-evidence-profile",
            event="recovery.authorization_handoff_failed",
            reason_code="WRONG_PROFILE",
            recorded_at=_RECORDED_AT,
            subject_ref=_SYNTHETIC_DIGEST,
        )


@pytest.mark.parametrize("corrupt_value", [1.5, "abc"])
def test_audit_projection_rejects_non_integer_sqlite_values(
    tmp_path: Path,
    corrupt_value: object,
) -> None:
    database_path = tmp_path / f"audit-bad-integer-{corrupt_value!s}.db"
    tenant_id = "tenant:audit-bad-integer"
    with SQLiteEnforcedTransactionStore(database_path) as store:
        store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=tenant_id,
            expected=None,
            recorded_at=_RECORDED_AT,
            reaudit_interval=timedelta(minutes=5),
        )
        store._connection.execute(
            "DROP TRIGGER enforced_recovery_handoff_evidence_audits_valid_update"
        )
        store._connection.execute(
            "UPDATE enforced_recovery_handoff_evidence_audits "
            "SET current_cycle = ?, last_completed_cycle = ? WHERE tenant_id = ?",
            (corrupt_value, corrupt_value, tenant_id),
        )
        store._connection.commit()

        with pytest.raises(AgentKernelError) as captured:
            store.get_recovery_handoff_evidence_audit_checkpoint(tenant_id)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_full_audit_rejects_noncanonical_nested_checkpoint_timestamp(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "audit-noncanonical-nested-time.db"
    tenant_id = "tenant:audit-noncanonical-nested-time"
    with SQLiteEnforcedTransactionStore(database_path) as store:
        checkpoint = store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=tenant_id,
            expected=None,
            recorded_at=_RECORDED_AT,
            reaudit_interval=timedelta(minutes=5),
        )
        for index in range(1, 5):
            checkpoint = store.start_recovery_handoff_evidence_audit_cycle(
                tenant_id=tenant_id,
                expected=checkpoint,
                recorded_at=_RECORDED_AT + timedelta(microseconds=index),
                reaudit_interval=timedelta(minutes=5),
                force=True,
            )

        rows = store._connection.execute(
            "SELECT * FROM enforced_recovery_handoff_evidence_audit_events "
            "WHERE tenant_id = ? ORDER BY sequence",
            (tenant_id,),
        ).fetchall()
        previous_digest: str | None = None
        replacements: list[tuple[object, ...]] = []
        for row in rows:
            sequence = int(row["sequence"])
            checkpoint_material = json.loads(str(row["checkpoint_json"]))
            if sequence == 1:
                canonical_time = str(checkpoint_material["updated_at"])
                assert canonical_time.endswith("Z")
                checkpoint_material["updated_at"] = canonical_time[:-1] + "+00:00"
            checkpoint_digest = canonical_digest(checkpoint_material)
            recorded_at = datetime.fromisoformat(str(row["recorded_at"]).replace("Z", "+00:00"))
            event_material = store._recovery_handoff_evidence_audit_event_material(
                tenant_id=tenant_id,
                sequence=sequence,
                checkpoint_digest=checkpoint_digest,
                previous_event_digest=previous_digest,
                recorded_at=recorded_at,
            )
            event_digest = canonical_digest(event_material)
            replacements.append(
                (
                    checkpoint_digest,
                    canonical_json_text(checkpoint_material),
                    previous_digest,
                    event_digest,
                    canonical_json_text(event_material),
                    tenant_id,
                    sequence,
                )
            )
            previous_digest = event_digest

        store._connection.execute(
            "DROP TRIGGER enforced_recovery_handoff_evidence_audit_events_no_update"
        )
        store._connection.executemany(
            "UPDATE enforced_recovery_handoff_evidence_audit_events SET "
            "checkpoint_digest = ?, checkpoint_json = ?, previous_event_digest = ?, "
            "event_digest = ?, event_json = ? WHERE tenant_id = ? AND sequence = ?",
            replacements,
        )
        store._connection.execute(
            "DROP TRIGGER enforced_recovery_handoff_evidence_audits_valid_update"
        )
        store._connection.execute(
            "UPDATE enforced_recovery_handoff_evidence_audits SET event_head_digest = ? "
            "WHERE tenant_id = ?",
            (previous_digest, tenant_id),
        )
        store._connection.commit()

        with pytest.raises(AgentKernelError) as captured:
            store.validate_recovery_handoff_evidence_audit_history(
                tenant_id=tenant_id,
                page_size=2,
            )
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
