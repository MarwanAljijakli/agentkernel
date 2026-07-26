from __future__ import annotations

import sqlite3
from datetime import UTC, timedelta
from pathlib import Path

import pytest
from agentkernel.authority import EnforcedAuthorityDecision
from agentkernel.canonical import canonical_digest, canonical_json_text
from agentkernel.domain.enums import (
    AuthorizationRoundPurpose,
    AuthorizationVerdict,
    ReconciliationOutcome,
    RecoveryWorkKind,
    RecoveryWorkState,
    StageMaterialState,
    TransactionState,
)
from agentkernel.domain.models import NormalizedAction, RecoveryActionBinding
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.policy import AggregatePolicyDecision
from agentkernel.storage.control import (
    CapabilityReservationState,
    DecisionKind,
    IntentAttemptState,
    IntentDisposition,
)
from agentkernel.storage.enforced import (
    EnforcedStoreDisposition,
    RecoveryCursor,
    RecoveryHandoffFailureEvidenceStatus,
    SQLiteEnforcedTransactionStore,
    preview_committed_capability_reservation,
)
from agentkernel.transactions.contracts import (
    AuthorizationRoundRecord,
    EnforcedTransactionEvent,
    EnforcedTransactionRecord,
    RecoveryWorkRecord,
    StageMaterialRecord,
)
from tests.integration import test_enforced_transaction_store_v4 as v4

pytestmark = pytest.mark.integration

_NOW = v4._NOW


def _drop_guards(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    """Disable only the disposable fixture's immutability guards before corruption."""

    rows = connection.execute(
        "SELECT name, sql FROM sqlite_schema WHERE type = 'trigger' AND tbl_name = ? ORDER BY name",
        (table,),
    ).fetchall()
    definitions: list[str] = []
    for name, sql in rows:
        assert sql is not None
        definitions.append(str(sql))
        escaped_name = str(name).replace('"', '""')
        connection.execute(f'DROP TRIGGER "{escaped_name}"')  # nosec B608
    return tuple(definitions)


def _restore_guards(connection: sqlite3.Connection, definitions: tuple[str, ...]) -> None:
    for statement in definitions:
        connection.execute(statement)


def _mutate_table(
    path: Path,
    table: str,
    statement: str,
    parameters: tuple[object, ...] = (),
) -> None:
    connection = sqlite3.connect(path)
    try:
        definitions = _drop_guards(connection, table)
        cursor = connection.execute(statement, parameters)
        assert cursor.rowcount != 0
        _restore_guards(connection, definitions)
        connection.commit()
    finally:
        connection.close()


def _authorize_stage(store: SQLiteEnforcedTransactionStore) -> None:
    context = v4._context()
    _, action = v4._bootstrap_planned(store, context)
    record, authority, policy, capability_ids = v4._eligible_round(store, action)
    store.authorize_for_staging(
        record,
        authority_decision=authority,
        policy_decision=policy,
        capability_ids=capability_ids,
        expected_transaction_version=1,
    )


def _pending_discard(
    store: SQLiteEnforcedTransactionStore,
    *,
    authority_valid_until=None,
) -> tuple[object, StageMaterialRecord, RecoveryWorkRecord]:
    context = v4._context()
    action, stage, capability_ids = v4._stage_to_verified(store, context)
    v4._begin_dispatch(store, action, stage, capability_ids)
    no_effect_ref = v4._digest("edge:dispatch:no-effect")
    store.classify_dispatch_outcome(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        expected_dispatch_version=0,
        expected_transaction_version=7,
        classification=ReconciliationOutcome.NO_EFFECT,
        evidence_refs=(no_effect_ref,),
        no_effect_evidence_ref=no_effect_ref,
        recorded_at=_NOW + timedelta(seconds=13),
        recovery_timeout=timedelta(minutes=5),
    )
    work = v4._authorize_recovery_work(
        store,
        context,
        action,
        stage,
        kind=RecoveryWorkKind.DISCARD_STAGING,
        authority_valid_until=authority_valid_until,
    )
    return action, stage, work


def _claim_discard(
    store: SQLiteEnforcedTransactionStore,
    *,
    authority_valid_until=None,
    expires_at=None,
):
    action, stage, work = _pending_discard(
        store,
        authority_valid_until=authority_valid_until,
    )
    acquired_at = _NOW + timedelta(seconds=17)
    expires_at = expires_at or (_NOW + timedelta(minutes=5))
    preview = store.preview_recovery_claim(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=work.recovery_id,
        expected_work_version=0,
        lease_id="lease:edge:discard",
        worker_id="worker:edge:discard",
        acquired_at=acquired_at,
        expires_at=expires_at,
    )
    claimed = store.claim_recovery(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=work.recovery_id,
        expected_work_version=0,
        lease_id=preview.lease.lease_id,
        worker_id=preview.lease.worker_id,
        acquired_at=preview.lease.acquired_at,
        expires_at=preview.lease.expires_at,
        permit=preview.permit,
        permit_ref=preview.permit_ref,
    )
    return action, stage, claimed.work


def _finish_discard(store: SQLiteEnforcedTransactionStore) -> None:
    action, _stage, work = _claim_discard(store)
    operation_ref = v4._digest("edge:discard:operation")
    store.finish_recovery(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=work.recovery_id,
        expected_work_version=work.version,
        succeeded=True,
        evidence_refs=(operation_ref,),
        operation_evidence_ref=operation_ref,
        completed_at=_NOW + timedelta(seconds=18),
    )


def _finish_late_discard(store: SQLiteEnforcedTransactionStore) -> None:
    authority_deadline = _NOW + timedelta(seconds=18)
    action, _stage, work = v4._claim_discard_for_late_report(
        store,
        v4._context(),
        authority_valid_until=authority_deadline,
    )
    operation_ref = v4._digest("edge:late:operation")
    store.record_late_recovery_outcome(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=work.recovery_id,
        expected_work_version=work.version,
        evidence_refs=(operation_ref,),
        operation_evidence_ref=operation_ref,
        reported_at=authority_deadline,
        reason_code="EDGE_LATE_RECOVERY",
    )


def _populate(path: Path, fixture: str) -> None:
    with SQLiteEnforcedTransactionStore(path) as store:
        if fixture == "transaction":
            context = v4._context()
            store.register_action_context(context, registered_at=_NOW)
            store.create_enforced_transaction(v4._new_record(context))
        elif fixture == "planned":
            v4._bootstrap_planned(store, v4._context())
        elif fixture == "round":
            _authorize_stage(store)
        elif fixture == "lease":
            _authorize_stage(store)
            store.acquire_staging_lease(
                tenant_id="tenant:test",
                transaction_id="transaction:test",
                lease_id="lease:edge:stage",
                worker_id="worker:edge:stage",
                acquired_at=_NOW + timedelta(seconds=3),
                expires_at=_NOW + timedelta(minutes=5),
                expected_transaction_version=2,
            )
        elif fixture == "stage":
            v4._stage_to_verified(store, v4._context())
        elif fixture in {"dispatch", "outcome"}:
            action, stage, capability_ids = v4._stage_to_verified(store, v4._context())
            v4._begin_dispatch(store, action, stage, capability_ids)
        elif fixture == "recovery":
            _pending_discard(store)
        elif fixture == "completion":
            _finish_discard(store)
        elif fixture == "late":
            _finish_late_discard(store)
        elif fixture == "reconciliation":
            v4._start_unknown_reconciliation(store, v4._context())
        else:  # pragma: no cover - test parameter programming error
            raise AssertionError(f"Unknown edge fixture: {fixture}")


def _assert_reopen_fails_closed(path: Path) -> None:
    with pytest.raises(AgentKernelError) as captured:
        SQLiteEnforcedTransactionStore(path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_v4_migration_supports_tenant_scoped_keyset_backlog(tmp_path: Path) -> None:
    path = tmp_path / "migrated-backlog.db"
    v4._create_v4_database(path)
    context = v4._context("tenant:edge-backlog")
    other_context = v4._context("tenant:edge-other")

    with SQLiteEnforcedTransactionStore(path) as store:
        assert store.schema_version == 7
        store.register_action_context(context, registered_at=_NOW)
        store.register_action_context(other_context, registered_at=_NOW)
        expected_ids = tuple(f"transaction:edge:{index}" for index in range(3))
        for index, transaction_id in enumerate(expected_ids):
            created_at = _NOW + timedelta(microseconds=index)
            record = v4._new_record(context, transaction_id).model_copy(
                update={"created_at": created_at, "updated_at": created_at}
            )
            store.create_enforced_transaction(record)
        store.create_enforced_transaction(v4._new_record(other_context, "transaction:other"))

        assert store.count_recovery_candidates(tenant_id=context.tenant_id) == 3
        first = store.scan_recovery_candidates(
            tenant_id=context.tenant_id,
            observed_at=_NOW + timedelta(seconds=1),
            limit=2,
        )
        assert tuple(record.transaction_id for record in first.records) == expected_ids[:2]
        assert first.next_cursor is not None
        second = store.scan_recovery_candidates(
            tenant_id=context.tenant_id,
            observed_at=_NOW + timedelta(seconds=1),
            limit=2,
            cursor=first.next_cursor,
        )
        assert tuple(record.transaction_id for record in second.records) == expected_ids[2:]
        assert second.next_cursor is None
        assert first.active_work == second.active_work == ()
        assert first.started_reconciliation == second.started_reconciliation == ()
        assert store.count_recovery_candidates(tenant_id=other_context.tenant_id) == 1

        for limit in (0, 1_001):
            with pytest.raises(AgentKernelError) as invalid_limit:
                store.scan_recovery_candidates(
                    tenant_id=context.tenant_id,
                    observed_at=_NOW,
                    limit=limit,
                )
            assert invalid_limit.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as invalid_cursor:
            store.scan_recovery_candidates(
                tenant_id=context.tenant_id,
                observed_at=_NOW,
                cursor=RecoveryCursor(_NOW, ""),
            )
        assert invalid_cursor.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize(
    ("owner_state", "expected_acquisition", "expected_disposition"),
    [
        (IntentAttemptState.ACTIVE, IntentDisposition.ALIAS_ACTIVE, EnforcedStoreDisposition.ALIAS),
        (
            IntentAttemptState.RECONCILE_REQUIRED,
            IntentDisposition.ALIAS_RECONCILE,
            EnforcedStoreDisposition.ALIAS,
        ),
        (
            IntentAttemptState.COMMITTED,
            IntentDisposition.ALIAS_COMMITTED,
            EnforcedStoreDisposition.ALIAS,
        ),
        (
            IntentAttemptState.REVIEW_REQUIRED,
            IntentDisposition.REVIEW_REQUIRED,
            EnforcedStoreDisposition.REVIEW_REQUIRED,
        ),
    ],
)
def test_duplicate_planning_retry_reports_current_owner_history(
    tmp_path: Path,
    owner_state: IntentAttemptState,
    expected_acquisition: IntentDisposition,
    expected_disposition: EnforcedStoreDisposition,
) -> None:
    context = v4._context("tenant:edge-alias")
    owner_id = "transaction:edge-owner"
    alias_id = f"transaction:edge-alias:{owner_state.value.lower()}"
    with SQLiteEnforcedTransactionStore(tmp_path / f"alias-{owner_state.value}.db") as store:
        _owner, owner_action = v4._bootstrap_planned(store, context, owner_id)
        if owner_state is not IntentAttemptState.ACTIVE:
            store.record_intent_attempt_state(
                tenant_id=context.tenant_id,
                intent_hash=owner_action.intent_hash,
                transaction_id=owner_id,
                expected_version=0,
                state=owner_state,
                evidence_digest=v4._digest(f"edge:owner:{owner_state.value}"),
                recorded_at=_NOW + timedelta(seconds=2),
            )

        store.create_enforced_transaction(v4._new_record(context, alias_id))
        alias_action = v4._action(context, alias_id)
        first = store.plan_and_acquire_intent(
            alias_action,
            expected_version=0,
            planned_at=_NOW + timedelta(seconds=3),
        )
        assert first.acquisition.disposition is expected_acquisition
        assert first.disposition is expected_disposition
        retry = store.plan_and_acquire_intent(
            alias_action,
            expected_version=0,
            planned_at=_NOW + timedelta(seconds=4),
        )
        assert retry.disposition is EnforcedStoreDisposition.EXACT_RETRY
        assert retry.acquisition.disposition is expected_acquisition
        assert retry.transaction.state is TransactionState.REJECTED


def test_planning_and_ingress_reject_changed_or_stale_inputs_atomically(tmp_path: Path) -> None:
    context = v4._context("tenant:edge-planning")
    with SQLiteEnforcedTransactionStore(tmp_path / "planning-errors.db") as store:
        store.register_action_context(context, registered_at=_NOW)
        invalid_ingress = v4._new_record(context, "transaction:invalid-ingress").model_copy(
            update={"version": 1}
        )
        with pytest.raises(AgentKernelError) as invalid:
            store.create_enforced_transaction(invalid_ingress)
        assert invalid.value.code is ErrorCode.VALIDATION_ERROR

        stale_id = "transaction:stale-plan"
        store.create_enforced_transaction(v4._new_record(context, stale_id))
        with pytest.raises(AgentKernelError) as stale:
            store.plan_and_acquire_intent(
                v4._action(context, stale_id),
                expected_version=1,
                planned_at=_NOW + timedelta(seconds=1),
            )
        assert stale.value.code is ErrorCode.VERSION_CONFLICT

        mismatched_id = "transaction:identity-mismatch"
        store.create_enforced_transaction(v4._new_record(context, mismatched_id))
        mismatched = v4._action(context, mismatched_id).model_copy(
            update={"trace_id": "trace:forged"}
        )
        with pytest.raises(AgentKernelError) as identity:
            store.plan_and_acquire_intent(
                mismatched,
                expected_version=0,
                planned_at=_NOW + timedelta(seconds=1),
            )
        assert identity.value.code is ErrorCode.INTEGRITY_ERROR

        _planned, action = v4._bootstrap_planned(
            store,
            context,
            "transaction:changed-retry",
        )
        changed = action.model_copy(update={"operation": "changed_operation"})
        with pytest.raises(AgentKernelError) as changed_retry:
            store.plan_and_acquire_intent(
                changed,
                expected_version=0,
                planned_at=_NOW + timedelta(seconds=2),
            )
        assert changed_retry.value.code is ErrorCode.INTEGRITY_ERROR


def test_authorization_and_history_reads_are_tenant_scoped(tmp_path: Path) -> None:
    with SQLiteEnforcedTransactionStore(tmp_path / "history-reads.db") as store:
        _authorize_stage(store)
        round_record = store.get_authorization_round(
            tenant_id="tenant:test",
            controlled_transaction_id="transaction:test",
            round_id="authorization:stage",
        )
        assert round_record.purpose is AuthorizationRoundPurpose.STAGING
        projection = store.get_transaction_projection(
            tenant_id="tenant:test",
            transaction_id="transaction:test",
        )
        assert projection.authorization_rounds == (round_record,)
        assert projection.intent_acquisition is not None
        assert projection.intent_acquisition.disposition is IntentDisposition.SAME_TRANSACTION
        assert projection.event_count == projection.record.version + 1
        assert store.list_recovery_work(tenant_id="tenant:test") == ()
        assert (
            store.get_started_reconciliation_attempt(
                tenant_id="tenant:test",
                transaction_id="transaction:test",
            )
            is None
        )

        for tenant_id, round_id in (
            ("tenant:other", "authorization:stage"),
            ("tenant:test", "authorization:missing"),
        ):
            with pytest.raises(AgentKernelError) as unknown_round:
                store.get_authorization_round(
                    tenant_id=tenant_id,
                    controlled_transaction_id="transaction:test",
                    round_id=round_id,
                )
            assert unknown_round.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as unknown_work:
            store.get_recovery_work(
                tenant_id="tenant:test",
                transaction_id="transaction:test",
                recovery_id="recovery:missing",
            )
        assert unknown_work.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as invalid_attempt:
            store.get_reconciliation_attempt(
                tenant_id="tenant:test",
                transaction_id="transaction:test",
                recovery_id="recovery:missing",
                attempt=0,
            )
        assert invalid_attempt.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize(
    ("fixture", "table", "json_column"),
    [
        ("transaction", "enforced_transactions", "record_json"),
        ("transaction", "enforced_transaction_events", "event_json"),
        ("round", "enforced_authorization_rounds", "round_json"),
        ("lease", "enforced_worker_leases", "record_json"),
        ("stage", "enforced_stage_material", "record_json"),
        ("dispatch", "enforced_commit_dispatches", "record_json"),
        ("outcome", "enforced_dispatch_outcomes", "outcome_json"),
        ("recovery", "enforced_recovery_work", "record_json"),
        ("completion", "enforced_recovery_completion_reports", "report_json"),
        ("late", "enforced_late_recovery_reports", "report_json"),
        ("reconciliation", "enforced_reconciliation_attempts", "record_json"),
    ],
)
def test_reopen_rejects_invalid_canonical_rows(
    tmp_path: Path,
    fixture: str,
    table: str,
    json_column: str,
) -> None:
    path = tmp_path / f"invalid-{fixture}-{table}.db"
    _populate(path, fixture)
    statement = f'UPDATE "{table}" SET "{json_column}" = ?'  # noqa: S608  # nosec B608
    _mutate_table(path, table, statement, ("{",))
    _assert_reopen_fails_closed(path)


@pytest.mark.parametrize(
    ("fixture", "table", "statement"),
    [
        ("transaction", "enforced_transactions", "UPDATE enforced_transactions SET operation = ?"),
        (
            "transaction",
            "enforced_transaction_events",
            "UPDATE enforced_transaction_events SET rule_id = ?",
        ),
        (
            "round",
            "enforced_authorization_rounds",
            "UPDATE enforced_authorization_rounds SET reason_code = ?",
        ),
        ("lease", "enforced_worker_leases", "UPDATE enforced_worker_leases SET worker_id = ?"),
        ("stage", "enforced_stage_material", "UPDATE enforced_stage_material SET stage_id = ?"),
        ("recovery", "enforced_recovery_work", "UPDATE enforced_recovery_work SET reason_code = ?"),
        (
            "completion",
            "enforced_recovery_completion_reports",
            "UPDATE enforced_recovery_completion_reports SET reason_code = ?",
        ),
        (
            "late",
            "enforced_late_recovery_reports",
            "UPDATE enforced_late_recovery_reports SET reason_code = ?",
        ),
    ],
)
def test_reopen_rejects_projection_tampering_even_when_canonical_json_is_intact(
    tmp_path: Path,
    fixture: str,
    table: str,
    statement: str,
) -> None:
    path = tmp_path / f"projection-{fixture}-{table}.db"
    _populate(path, fixture)
    _mutate_table(path, table, statement, ("forged",))
    _assert_reopen_fails_closed(path)


@pytest.mark.parametrize("tamper", ["noncontiguous", "missing-events", "wrong-head"])
def test_reopen_rejects_transaction_history_chain_tampering(
    tmp_path: Path,
    tamper: str,
) -> None:
    path = tmp_path / f"history-chain-{tamper}.db"
    _populate(path, "planned")
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        if tamper == "noncontiguous":
            definitions = _drop_guards(connection, "enforced_transaction_events")
            row = connection.execute(
                "SELECT event_json FROM enforced_transaction_events WHERE sequence = 1"
            ).fetchone()
            assert row is not None
            event = EnforcedTransactionEvent.model_validate_json(str(row["event_json"]))
            changed = EnforcedTransactionEvent.create(
                **{
                    **event.model_dump(mode="python", exclude={"event_digest"}),
                    "previous_event_digest": v4._digest("edge:forged-previous-event"),
                    "recorded_at": event.recorded_at.astimezone(UTC),
                }
            )
            connection.execute(
                "UPDATE enforced_transaction_events SET previous_event_digest = ?, "
                "event_digest = ?, event_json = ? WHERE sequence = 1",
                (
                    changed.previous_event_digest,
                    changed.event_digest,
                    canonical_json_text(changed),
                ),
            )
            _restore_guards(connection, definitions)
        elif tamper == "missing-events":
            definitions = _drop_guards(connection, "enforced_transaction_events")
            connection.execute("DELETE FROM enforced_transaction_events")
            _restore_guards(connection, definitions)
        else:
            definitions = _drop_guards(connection, "enforced_transactions")
            connection.execute(
                "UPDATE enforced_transactions SET event_head_digest = ?",
                (v4._digest("edge:forged-event-head"),),
            )
            _restore_guards(connection, definitions)
        connection.commit()
    finally:
        connection.close()
    _assert_reopen_fails_closed(path)


def _rewrite_transaction_adapter(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        definitions = _drop_guards(connection, "enforced_transactions")
        row = connection.execute("SELECT record_json FROM enforced_transactions").fetchone()
        assert row is not None
        record = EnforcedTransactionRecord.model_validate_json(str(row["record_json"]))
        changed = EnforcedTransactionRecord.model_validate(
            {**record.model_dump(mode="python"), "adapter": "forged-adapter"}
        )
        connection.execute(
            "UPDATE enforced_transactions SET adapter = ?, record_digest = ?, record_json = ?",
            (changed.adapter, canonical_digest(changed), canonical_json_text(changed)),
        )
        _restore_guards(connection, definitions)
        connection.commit()
    finally:
        connection.close()


def _rewrite_stage_adapter_manifest(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        definitions = _drop_guards(connection, "enforced_stage_material")
        row = connection.execute("SELECT record_json FROM enforced_stage_material").fetchone()
        assert row is not None
        material = StageMaterialRecord.model_validate_json(str(row["record_json"]))
        changed = StageMaterialRecord.model_validate(
            {
                **material.model_dump(mode="python"),
                "adapter_manifest_digest": v4._digest("edge:stage-adapter"),
            }
        )
        connection.execute(
            "UPDATE enforced_stage_material SET adapter_manifest_digest = ?, "
            "record_digest = ?, record_json = ?",
            (
                changed.adapter_manifest_digest,
                canonical_digest(changed),
                canonical_json_text(changed),
            ),
        )
        _restore_guards(connection, definitions)
        connection.commit()
    finally:
        connection.close()


def _rewrite_recovery_adapter_manifest(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        definitions = _drop_guards(connection, "enforced_recovery_work")
        row = connection.execute("SELECT record_json FROM enforced_recovery_work").fetchone()
        assert row is not None
        work = RecoveryWorkRecord.model_validate_json(str(row["record_json"]))
        changed = RecoveryWorkRecord.model_validate(
            {
                **work.model_dump(mode="python"),
                "adapter_manifest_digest": v4._digest("edge:recovery-adapter"),
            }
        )
        connection.execute(
            "UPDATE enforced_recovery_work SET adapter_manifest_digest = ?, "
            "record_digest = ?, record_json = ?",
            (
                changed.adapter_manifest_digest,
                canonical_digest(changed),
                canonical_json_text(changed),
            ),
        )
        _restore_guards(connection, definitions)
        connection.commit()
    finally:
        connection.close()


def _rewrite_round_purpose(path: Path, purpose: AuthorizationRoundPurpose) -> None:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        definitions = _drop_guards(connection, "enforced_authorization_rounds")
        order = "DESC" if purpose is AuthorizationRoundPurpose.STAGING else "ASC"
        row = connection.execute(
            f"SELECT round_json FROM enforced_authorization_rounds "  # noqa: S608  # nosec B608
            f"ORDER BY evaluated_at {order} LIMIT 1"
        ).fetchone()
        assert row is not None
        record = AuthorizationRoundRecord.model_validate_json(str(row["round_json"]))
        values = record.model_dump(mode="python", exclude={"round_digest"})
        values["evaluated_at"] = record.evaluated_at.astimezone(UTC)
        if record.authority_valid_until is not None:
            values["authority_valid_until"] = record.authority_valid_until.astimezone(UTC)
        changed = AuthorizationRoundRecord.create(
            **{
                **values,
                "purpose": purpose,
            }
        )
        connection.execute(
            "UPDATE enforced_authorization_rounds SET purpose = ?, round_digest = ?, "
            "round_json = ? WHERE round_id = ?",
            (
                changed.purpose.value,
                changed.round_digest,
                canonical_json_text(changed),
                changed.round_id,
            ),
        )
        _restore_guards(connection, definitions)
        connection.commit()
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("fixture", "mutator", "expected_message"),
    [
        ("planned", _rewrite_transaction_adapter, "normalized action"),
        ("stage", _rewrite_stage_adapter_manifest, "private stage material"),
        ("recovery", _rewrite_recovery_adapter_manifest, "recovery work"),
    ],
)
def test_projection_rejects_cross_record_binding_tampering(
    tmp_path: Path,
    fixture: str,
    mutator,
    expected_message: str,
) -> None:
    path = tmp_path / f"cross-record-{fixture}.db"
    _populate(path, fixture)
    mutator(path)
    if fixture == "recovery":
        with pytest.raises(AgentKernelError, match="durable action handoff") as captured:
            SQLiteEnforcedTransactionStore(path)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
        return
    with SQLiteEnforcedTransactionStore(path) as store:
        with pytest.raises(AgentKernelError, match=expected_message) as captured:
            store.get_transaction_projection(
                tenant_id="tenant:test",
                transaction_id="transaction:test",
            )
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_projection_rejects_missing_stage_and_authorization_history(tmp_path: Path) -> None:
    missing_stage = tmp_path / "projection-missing-stage.db"
    _populate(missing_stage, "stage")
    _mutate_table(
        missing_stage,
        "enforced_stage_material",
        "DELETE FROM enforced_stage_material",
    )
    with (
        SQLiteEnforcedTransactionStore(missing_stage) as store,
        pytest.raises(AgentKernelError, match="durable stage material"),
    ):
        store.get_transaction_projection(
            tenant_id="tenant:test",
            transaction_id="transaction:test",
        )

    missing_reference = tmp_path / "projection-missing-round.db"
    _populate(missing_reference, "round")
    _mutate_table(
        missing_reference,
        "enforced_authorization_rounds",
        "DELETE FROM enforced_authorization_rounds",
    )
    with (
        SQLiteEnforcedTransactionStore(missing_reference) as store,
        pytest.raises(AgentKernelError, match="missing authorization round"),
    ):
        store.get_transaction_projection(
            tenant_id="tenant:test",
            transaction_id="transaction:test",
        )

    wrong_staging_purpose = tmp_path / "projection-staging-purpose.db"
    _populate(wrong_staging_purpose, "round")
    _rewrite_round_purpose(wrong_staging_purpose, AuthorizationRoundPurpose.PRECOMMIT)
    with (
        SQLiteEnforcedTransactionStore(wrong_staging_purpose) as store,
        pytest.raises(AgentKernelError, match="staging authorization round"),
    ):
        store.get_transaction_projection(
            tenant_id="tenant:test",
            transaction_id="transaction:test",
        )

    wrong_precommit_purpose = tmp_path / "projection-precommit-purpose.db"
    _populate(wrong_precommit_purpose, "dispatch")
    _rewrite_round_purpose(wrong_precommit_purpose, AuthorizationRoundPurpose.STAGING)
    with (
        SQLiteEnforcedTransactionStore(wrong_precommit_purpose) as store,
        pytest.raises(AgentKernelError, match="precommit authorization round"),
    ):
        store.get_transaction_projection(
            tenant_id="tenant:test",
            transaction_id="transaction:test",
        )


def test_projection_rejects_normalized_action_added_after_unbound_ingress(tmp_path: Path) -> None:
    context = v4._context("tenant:edge-unbound")
    transaction_id = "transaction:recovery:discard_staging"
    original = v4._action(context, "transaction:target:edge-unbound")
    action = v4._recovery_action(
        context,
        original,
        kind=RecoveryWorkKind.DISCARD_STAGING,
    )
    with SQLiteEnforcedTransactionStore(tmp_path / "projection-unbound-action.db") as store:
        store.register_action_context(context, registered_at=_NOW)
        store.register_recovery_action(action, registered_at=_NOW + timedelta(seconds=1))
        store.create_enforced_transaction(v4._new_record(context, transaction_id))
        with pytest.raises(AgentKernelError, match="unbound normalized action") as captured:
            store.get_transaction_projection(
                tenant_id=context.tenant_id,
                transaction_id=transaction_id,
            )
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_closed_prework_discard_survives_legal_intent_transfer_and_reaudit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "closed-prework-transfer.db"
    context = v4._context("tenant:closed-prework-transfer")
    with SQLiteEnforcedTransactionStore(path) as store:
        original, stage, capability_ids = v4._stage_to_verified(store, context)
        v4._begin_dispatch(store, original, stage, capability_ids)
        no_effect_ref = v4._digest("closed-prework-transfer:no-effect")
        classified = store.classify_dispatch_outcome(
            tenant_id=original.tenant_id,
            transaction_id=original.transaction_id,
            expected_dispatch_version=0,
            expected_transaction_version=7,
            classification=ReconciliationOutcome.NO_EFFECT,
            evidence_refs=(no_effect_ref,),
            no_effect_evidence_ref=no_effect_ref,
            recorded_at=_NOW + timedelta(seconds=13),
            recovery_timeout=timedelta(minutes=10),
        )
        stage = store.get_stage_material(
            tenant_id=original.tenant_id,
            transaction_id=original.transaction_id,
        )
        target_ref = canonical_digest(stage)
        target_head = store.list_intent_history(
            tenant_id=original.tenant_id,
            intent_hash=original.intent_hash,
        )[-1]
        recovery_id = "recovery:closed-prework-transfer"
        created_at = _NOW + timedelta(seconds=16)
        binding = RecoveryActionBinding(
            target_transaction_id=original.transaction_id,
            target_intent_hash=original.intent_hash,
            target_normalized_action_digest=canonical_digest(original),
            recovery_kind=RecoveryWorkKind.DISCARD_STAGING,
            target_id=stage.stage_id,
            target_evidence_ref=target_ref,
            target_version_guard=stage.target_version_guard,
            target_owner_version=target_head.owner_version,
            target_owner_history_sequence=target_head.sequence,
            target_owner_history_digest=target_head.history_digest,
            adapter_manifest_digest=original.adapter_manifest_digest,
            risk_class=original.risk_floor,
            effect_domains=original.effect_domains,
            resource_uses_digest=canonical_digest(original.resource_uses),
            recovery_id=recovery_id,
            root_recovery_id=recovery_id,
            recovery_ordinal=1,
            max_recovery_attempts=1,
            not_before=created_at,
            absolute_deadline=store.get_transaction_recovery_deadline(
                tenant_id=original.tenant_id,
                transaction_id=original.transaction_id,
            ),
        )
        handoff_claim = store.acquire_recovery_handoff_lease(
            tenant_id=original.tenant_id,
            transaction_id=original.transaction_id,
            expected_transaction_version=classified.transaction.version,
            stage_id=stage.stage_id,
            expected_stage_version=stage.version,
            stage_target_ref=target_ref,
            lease_id="lease:closed-prework-transfer",
            worker_id="worker:closed-prework-transfer",
            acquired_at=created_at,
            expires_at=created_at + timedelta(minutes=1),
            binding=binding,
        )
        recovery_action = v4._recovery_action(
            context,
            original,
            kind=RecoveryWorkKind.DISCARD_STAGING,
            binding=binding,
        )
        store.register_recovery_action(
            recovery_action,
            registered_at=created_at,
            binding=binding,
        )
        failure_ref = v4._digest("closed-prework-transfer:failure")
        failed = store.fail_stage_recovery_handoff(
            tenant_id=original.tenant_id,
            transaction_id=original.transaction_id,
            expected_transaction_version=classified.transaction.version,
            stage_id=stage.stage_id,
            expected_stage_version=stage.version,
            stage_target_ref=target_ref,
            failure_evidence_ref=failure_ref,
            reason_code="RECOVERY_FACTORY_FAILED",
            recorded_at=created_at + timedelta(seconds=1),
            recovery_action_transaction_id=recovery_action.transaction_id,
            recovery_action_intent_hash=recovery_action.intent_hash,
            recovery_action_digest=canonical_digest(recovery_action),
            recovery_action_binding=binding,
            handoff_lease_id=handoff_claim.lease.lease_id,
            handoff_worker_id=handoff_claim.lease.worker_id,
            handoff_fencing_token=handoff_claim.lease.fencing_token,
            expected_handoff_lease_version=handoff_claim.lease.version,
        )
        assert failed.transaction.state is TransactionState.RECOVERY_FAILED

        replacement_action = NormalizedAction.model_validate(
            {
                **recovery_action.model_dump(mode="python"),
                "transaction_id": "transaction:recovery:discard_staging:replacement",
            }
        )
        store.put_normalized_action(
            replacement_action,
            recorded_at=created_at + timedelta(seconds=2),
        )
        transferred = store.acquire_intent(
            tenant_id=replacement_action.tenant_id,
            intent_hash=replacement_action.intent_hash,
            transaction_id=replacement_action.transaction_id,
            attempted_at=created_at + timedelta(seconds=2),
        )
        assert transferred.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT

        handoff = store.get_recovery_action_handoff(
            tenant_id=original.tenant_id,
            target_transaction_id=original.transaction_id,
            recovery_id=recovery_id,
        )
        assert handoff is not None
        assert handoff.closed_at is not None
        checkpoint = store.start_recovery_handoff_evidence_audit_cycle(
            tenant_id=original.tenant_id,
            expected=None,
            recorded_at=created_at + timedelta(seconds=3),
            reaudit_interval=timedelta(hours=1),
            force=True,
        )
        page = store.scan_terminal_recovery_handoff_evidence(
            tenant_id=original.tenant_id,
            cycle_high_watermark=checkpoint.current_cycle_high_watermark,
            cursor=checkpoint.cursor,
        )
        assert page.handoffs == (handoff,)
        store.advance_recovery_handoff_evidence_audit(
            tenant_id=original.tenant_id,
            expected=checkpoint,
            next_cursor=page.next_cursor,
            page_failure_count=0,
            completed=True,
            recorded_at=created_at + timedelta(seconds=4),
        )

    with SQLiteEnforcedTransactionStore(path) as reopened:
        restored = reopened.get_recovery_action_handoff(
            tenant_id=original.tenant_id,
            target_transaction_id=original.transaction_id,
            recovery_id=recovery_id,
        )
        assert restored == handoff


@pytest.mark.parametrize(
    ("target_state", "expected_disposition", "expected_transaction_state"),
    [
        (
            RecoveryWorkState.FAILED,
            EnforcedStoreDisposition.STORED,
            TransactionState.RECOVERY_FAILED,
        ),
        (
            RecoveryWorkState.REVIEW_REQUIRED,
            EnforcedStoreDisposition.REVIEW_REQUIRED,
            TransactionState.RECOVERY_FAILED,
        ),
    ],
)
def test_recovery_revalidation_failure_is_atomic_releasable_and_exact(
    tmp_path: Path,
    target_state: RecoveryWorkState,
    expected_disposition: EnforcedStoreDisposition,
    expected_transaction_state: TransactionState,
) -> None:
    path = tmp_path / f"revalidation-{target_state.value}.db"
    with SQLiteEnforcedTransactionStore(path) as store:
        action, _stage, work = _pending_discard(store)
        evidence_ref = v4._digest(f"edge:revalidation:{target_state.value}")
        handoff_failure_ref = v4._digest(f"edge:revalidation-handoff:{target_state.value}")
        recorded_at = _NOW + timedelta(seconds=17)

        with pytest.raises(AgentKernelError) as invalid_target:
            store.fail_recovery_revalidation(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=work.recovery_id,
                expected_work_version=0,
                target_state=RecoveryWorkState.PENDING,
                evidence_refs=(evidence_ref,),
                reason_code="EDGE_REVALIDATION",
                recorded_at=recorded_at,
            )
        assert invalid_target.value.code is ErrorCode.VALIDATION_ERROR
        for refs, reason in (((), "EDGE_REVALIDATION"), ((evidence_ref,), "")):
            with pytest.raises(AgentKernelError) as missing_evidence:
                store.fail_recovery_revalidation(
                    tenant_id=action.tenant_id,
                    transaction_id=action.transaction_id,
                    recovery_id=work.recovery_id,
                    expected_work_version=0,
                    target_state=target_state,
                    evidence_refs=refs,
                    reason_code=reason,
                    recorded_at=recorded_at,
                )
            assert missing_evidence.value.code is ErrorCode.VALIDATION_ERROR

        result = store.fail_recovery_revalidation(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=work.recovery_id,
            expected_work_version=0,
            target_state=target_state,
            evidence_refs=(evidence_ref, handoff_failure_ref),
            reason_code="EDGE_REVALIDATION",
            recorded_at=recorded_at,
            handoff_failure_evidence_ref=handoff_failure_ref,
            handoff_failure_evidence_status=(RecoveryHandoffFailureEvidenceStatus.AVAILABLE),
            handoff_failure_reason_code="EDGE_REVALIDATION",
        )
        assert result.disposition is expected_disposition
        assert result.work.state is target_state
        assert result.work.version == 1
        assert result.reservation is not None
        assert result.reservation.state is CapabilityReservationState.RELEASED
        assert (
            store.get_enforced_transaction(action.tenant_id, action.transaction_id).state
            is expected_transaction_state
        )
        current_stage = store.get_stage_material(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        assert current_stage.state is StageMaterialState.DISCARD_FAILED

        retry = store.fail_recovery_revalidation(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=work.recovery_id,
            expected_work_version=0,
            target_state=target_state,
            evidence_refs=(evidence_ref, handoff_failure_ref),
            reason_code="EDGE_REVALIDATION",
            recorded_at=recorded_at,
            handoff_failure_evidence_ref=handoff_failure_ref,
            handoff_failure_evidence_status=(RecoveryHandoffFailureEvidenceStatus.AVAILABLE),
            handoff_failure_reason_code="EDGE_REVALIDATION",
        )
        assert retry.disposition is EnforcedStoreDisposition.EXACT_RETRY
        with pytest.raises(AgentKernelError) as changed_retry:
            store.fail_recovery_revalidation(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=work.recovery_id,
                expected_work_version=0,
                target_state=target_state,
                evidence_refs=(evidence_ref, handoff_failure_ref),
                reason_code="EDGE_CHANGED_REVALIDATION",
                recorded_at=recorded_at,
                handoff_failure_evidence_ref=handoff_failure_ref,
                handoff_failure_evidence_status=(RecoveryHandoffFailureEvidenceStatus.AVAILABLE),
                handoff_failure_reason_code="EDGE_CHANGED_REVALIDATION",
            )
        assert changed_retry.value.code is ErrorCode.INTEGRITY_ERROR


def test_recovery_revalidation_cannot_close_an_already_claimed_generation(tmp_path: Path) -> None:
    with SQLiteEnforcedTransactionStore(tmp_path / "revalidation-claimed.db") as store:
        action, _stage, work = _claim_discard(store)
        failure_ref = v4._digest("edge:claimed-revalidation")
        with pytest.raises(AgentKernelError) as captured:
            store.fail_recovery_revalidation(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=work.recovery_id,
                expected_work_version=work.version,
                target_state=RecoveryWorkState.FAILED,
                evidence_refs=(failure_ref,),
                reason_code="EDGE_ALREADY_CLAIMED",
                recorded_at=_NOW + timedelta(seconds=18),
                handoff_failure_evidence_ref=failure_ref,
                handoff_failure_evidence_status=(RecoveryHandoffFailureEvidenceStatus.AVAILABLE),
                handoff_failure_reason_code="EDGE_ALREADY_CLAIMED",
            )
        assert captured.value.code is ErrorCode.VERSION_CONFLICT


def test_recovery_authorization_retry_binds_original_round_and_work(tmp_path: Path) -> None:
    with SQLiteEnforcedTransactionStore(tmp_path / "recovery-authorization-retry.db") as store:
        _action, _stage, work = _pending_discard(store)
        record = store.get_authorization_round(
            tenant_id=work.tenant_id,
            controlled_transaction_id=work.transaction_id,
            round_id=work.authorization_round_id,
        )
        authority = EnforcedAuthorityDecision.model_validate(
            store.get_decision_snapshot(
                tenant_id=work.tenant_id,
                kind=DecisionKind.AUTHORITY,
                decision_id=record.authority_decision_id,
            ).decision
        )
        policy = AggregatePolicyDecision.model_validate(
            store.get_decision_snapshot(
                tenant_id=work.tenant_id,
                kind=DecisionKind.POLICY,
                decision_id=record.policy_decision_id,
            ).decision
        )
        retry = store.authorize_recovery(
            work,
            authorization_round=record,
            authority_decision=authority,
            policy_decision=policy,
            capability_ids=("capability:recovery:discard_staging",),
        )
        assert retry.disposition is EnforcedStoreDisposition.EXACT_RETRY
        assert retry.work == work
        assert retry.reservation is not None

        changed = work.model_copy(update={"reason_code": "EDGE_CHANGED_WORK"})
        with pytest.raises(AgentKernelError) as changed_retry:
            store.authorize_recovery(
                changed,
                authorization_round=record,
                authority_decision=authority,
                policy_decision=policy,
                capability_ids=("capability:recovery:discard_staging",),
            )
        assert changed_retry.value.code is ErrorCode.INTEGRITY_ERROR


def test_recovery_claim_preview_and_commit_reject_changed_generation(tmp_path: Path) -> None:
    with SQLiteEnforcedTransactionStore(tmp_path / "recovery-claim-edges.db") as store:
        action, _stage, work = _pending_discard(store)
        base = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": work.recovery_id,
            "expected_work_version": 0,
            "lease_id": "lease:edge:claim",
            "worker_id": "worker:edge:claim",
            "acquired_at": _NOW + timedelta(seconds=17),
            "expires_at": _NOW + timedelta(minutes=5),
        }
        with pytest.raises(AgentKernelError) as stale:
            store.preview_recovery_claim(**{**base, "expected_work_version": 1})
        assert stale.value.code is ErrorCode.VERSION_CONFLICT
        with pytest.raises(AgentKernelError) as bad_deadline:
            store.preview_recovery_claim(**{**base, "acquired_at": _NOW + timedelta(seconds=15)})
        assert bad_deadline.value.code is ErrorCode.DEADLINE_EXCEEDED
        with pytest.raises(AgentKernelError) as reused_lease:
            store.preview_recovery_claim(**{**base, "lease_id": "lease:stage:test"})
        assert reused_lease.value.code is ErrorCode.INTEGRITY_ERROR

        preview = store.preview_recovery_claim(**base)
        with pytest.raises(AgentKernelError) as wrong_ref:
            store.claim_recovery(
                **base,
                permit=preview.permit,
                permit_ref=v4._digest("edge:wrong-permit-ref"),
            )
        assert wrong_ref.value.code is ErrorCode.INTEGRITY_ERROR
        forged_permit = preview.permit.model_copy(update={"worker_id": "worker:forged"})
        with pytest.raises(AgentKernelError) as changed_preview:
            store.claim_recovery(
                **base,
                permit=forged_permit,
                permit_ref=canonical_digest(forged_permit),
            )
        assert changed_preview.value.code is ErrorCode.INTEGRITY_ERROR

        claimed = store.claim_recovery(
            **base,
            permit=preview.permit,
            permit_ref=preview.permit_ref,
        )
        assert claimed.disposition is EnforcedStoreDisposition.RECOVERY_NOW
        with pytest.raises(AgentKernelError) as changed_retry:
            store.claim_recovery(
                **{**base, "expires_at": base["expires_at"] + timedelta(seconds=1)},
                permit=preview.permit,
                permit_ref=preview.permit_ref,
            )
        assert changed_retry.value.code is ErrorCode.VERSION_CONFLICT


def test_recovery_claim_rejects_expired_authority_and_lost_reservation(tmp_path: Path) -> None:
    expired_path = tmp_path / "recovery-authority-expired.db"
    with SQLiteEnforcedTransactionStore(expired_path) as store:
        action, _stage, work = _pending_discard(
            store,
            authority_valid_until=_NOW + timedelta(seconds=18),
        )
        with pytest.raises(AgentKernelError) as expired:
            store.preview_recovery_claim(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=work.recovery_id,
                expected_work_version=0,
                lease_id="lease:edge:expired-authority",
                worker_id="worker:edge:expired-authority",
                acquired_at=_NOW + timedelta(seconds=18),
                expires_at=_NOW + timedelta(seconds=19),
            )
        assert expired.value.code is ErrorCode.AUTHORITY_EXPIRED

    lost_path = tmp_path / "recovery-reservation-lost.db"
    with SQLiteEnforcedTransactionStore(lost_path) as store:
        action, _stage, work = _pending_discard(store)
        store._connection.execute("PRAGMA foreign_keys = OFF")
        definitions = _drop_guards(
            store._connection,
            "enforced_capability_chain_reservations",
        )
        deleted = store._connection.execute(
            "DELETE FROM enforced_capability_chain_reservations WHERE intent_hash = ?",
            (work.recovery_action_intent_hash,),
        )
        assert deleted.rowcount == 1
        _restore_guards(store._connection, definitions)
        store._connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(AgentKernelError) as lost:
            store.preview_recovery_claim(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=work.recovery_id,
                expected_work_version=0,
                lease_id="lease:edge:lost-reservation",
                worker_id="worker:edge:lost-reservation",
                acquired_at=_NOW + timedelta(seconds=17),
                expires_at=_NOW + timedelta(minutes=5),
            )
        assert lost.value.code is ErrorCode.INTEGRITY_ERROR


def test_finish_and_late_recovery_validate_evidence_and_lifecycle(tmp_path: Path) -> None:
    operation_ref = v4._digest("edge:operation")
    with SQLiteEnforcedTransactionStore(tmp_path / "finish-validation.db") as store:
        action, _stage, pending = _pending_discard(store)
        common = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": pending.recovery_id,
            "expected_work_version": 0,
            "operation_evidence_ref": operation_ref,
            "completed_at": _NOW + timedelta(seconds=18),
        }
        with pytest.raises(AgentKernelError) as empty:
            store.finish_recovery(**common, succeeded=True, evidence_refs=())
        assert empty.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as missing_reason:
            store.finish_recovery(
                **common,
                succeeded=False,
                evidence_refs=(operation_ref,),
            )
        assert missing_reason.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as unclaimed:
            store.finish_recovery(
                **common,
                succeeded=True,
                evidence_refs=(operation_ref,),
            )
        assert unclaimed.value.code is ErrorCode.VERSION_CONFLICT

    with SQLiteEnforcedTransactionStore(tmp_path / "late-validation.db") as store:
        action, _stage, running = _claim_discard(store)
        late_common = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": running.recovery_id,
            "expected_work_version": running.version,
            "operation_evidence_ref": operation_ref,
            "reported_at": _NOW + timedelta(seconds=18),
            "reason_code": "EDGE_LATE",
        }
        with pytest.raises(AgentKernelError) as negative:
            store.record_late_recovery_outcome(
                **{**late_common, "expected_work_version": -1},
                evidence_refs=(operation_ref,),
            )
        assert negative.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as no_evidence:
            store.record_late_recovery_outcome(**late_common, evidence_refs=())
        assert no_evidence.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as omitted_operation:
            store.record_late_recovery_outcome(
                **late_common,
                evidence_refs=(v4._digest("edge:other-evidence"),),
            )
        assert omitted_operation.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as premature:
            store.record_late_recovery_outcome(
                **late_common,
                evidence_refs=(operation_ref,),
            )
        assert premature.value.code is ErrorCode.VALIDATION_ERROR


def test_reconcile_work_cannot_use_generic_finish_api(tmp_path: Path) -> None:
    operation_ref = v4._digest("edge:reconcile-operation")
    with SQLiteEnforcedTransactionStore(tmp_path / "reconcile-finish.db") as store:
        action, work = v4._claim_unknown_reconciliation(store, v4._context())
        with pytest.raises(AgentKernelError) as captured:
            store.finish_recovery(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=work.recovery_id,
                expected_work_version=1,
                succeeded=True,
                evidence_refs=(operation_ref,),
                operation_evidence_ref=operation_ref,
                completed_at=_NOW + timedelta(seconds=18),
            )
        assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_reconciliation_start_exact_retry_rejects_released_lease(
    tmp_path: Path,
) -> None:
    evidence_ref = v4._digest("edge:reconciliation-start")
    with SQLiteEnforcedTransactionStore(tmp_path / "released-start-retry.db") as store:
        action, proposed = v4._claim_unknown_reconciliation(store, v4._context())
        running = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
        )
        started_at = _NOW + timedelta(seconds=18)
        started = store.start_reconciliation(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=running.recovery_id,
            expected_work_version=running.version,
            evidence_refs=(evidence_ref,),
            started_at=started_at,
        )
        assert running.lease_id is not None
        lease = store.get_worker_lease(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            lease_id=running.lease_id,
        )
        store.release_worker_lease(
            tenant_id=lease.tenant_id,
            transaction_id=lease.transaction_id,
            lease_id=lease.lease_id,
            expected_version=lease.version,
            released_at=started_at + timedelta(microseconds=1),
        )

        with pytest.raises(AgentKernelError) as rejected:
            store.start_reconciliation(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=running.recovery_id,
                expected_work_version=running.version,
                evidence_refs=(evidence_ref,),
                started_at=started_at + timedelta(seconds=1),
            )
        assert rejected.value.code is ErrorCode.VERSION_CONFLICT
        assert (
            store.get_reconciliation_attempt(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=running.recovery_id,
                attempt=started.attempt.attempt,
            )
            == started.attempt
        )


def test_unclaimed_denied_recovery_has_no_completion_retry(tmp_path: Path) -> None:
    context = v4._context()
    operation_ref = v4._digest("edge:denied-operation")
    with SQLiteEnforcedTransactionStore(tmp_path / "denied-finish.db") as store:
        action, stage, capability_ids = v4._stage_to_verified(store, context)
        v4._begin_dispatch(store, action, stage, capability_ids)
        no_effect_ref = v4._digest("edge:denied:no-effect")
        store.classify_dispatch_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_dispatch_version=0,
            expected_transaction_version=7,
            classification=ReconciliationOutcome.NO_EFFECT,
            evidence_refs=(no_effect_ref,),
            no_effect_evidence_ref=no_effect_ref,
            recorded_at=_NOW + timedelta(seconds=13),
            recovery_timeout=timedelta(minutes=5),
        )
        denied = v4._authorize_recovery_work(
            store,
            context,
            action,
            stage,
            kind=RecoveryWorkKind.DISCARD_STAGING,
            verdict=AuthorizationVerdict.DENIED,
        )
        assert denied.state is RecoveryWorkState.FAILED
        with pytest.raises(AgentKernelError) as captured:
            store.finish_recovery(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=denied.recovery_id,
                expected_work_version=0,
                succeeded=False,
                evidence_refs=(operation_ref,),
                operation_evidence_ref=operation_ref,
                completed_at=_NOW + timedelta(seconds=17),
                reason_code="EDGE_DENIED",
            )
        assert captured.value.code is ErrorCode.ILLEGAL_TRANSITION


def test_preview_committed_reservation_rejects_non_reserved_generation(tmp_path: Path) -> None:
    with SQLiteEnforcedTransactionStore(tmp_path / "reservation-preview.db") as store:
        _action, _stage, work = _pending_discard(store)
        record = store.get_authorization_round(
            tenant_id=work.tenant_id,
            controlled_transaction_id=work.transaction_id,
            round_id=work.authorization_round_id,
        )
        reservation = store._read_capability_chain(
            tenant_id=work.tenant_id,
            goal_id=record.reservation_goal_id,
            run_id=record.reservation_run_id,
            intent_hash=work.recovery_action_intent_hash,
        )
        assert reservation is not None
        committed = preview_committed_capability_reservation(reservation)
        with pytest.raises(AgentKernelError) as captured:
            preview_committed_capability_reservation(committed)
        assert captured.value.code is ErrorCode.VALIDATION_ERROR
