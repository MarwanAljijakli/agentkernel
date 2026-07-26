from __future__ import annotations

import sqlite3
import subprocess
import sys
import textwrap
import threading
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
import test_enforced_transaction_coordinator as coordinator_support
from agentkernel.canonical import canonical_digest, canonical_json_text
from agentkernel.domain.enums import (
    ReconciliationOutcome,
    RecoveryWorkState,
    ResourceAccessMode,
    ResourceUseKind,
    RiskClass,
)
from agentkernel.domain.models import AuthenticatedActionContext, NormalizedAction, ResourceUse
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.storage.control import (
    CapabilityReservationFence,
    CapabilityReservationState,
    DecisionKind,
    IntentAttemptState,
    IntentDisposition,
    SQLiteControlStore,
)
from agentkernel.storage.enforced import SQLiteEnforcedTransactionStore
from agentkernel.storage.sqlite import MIGRATIONS, SQLiteJournal
from agentkernel.transactions.contracts import ReconciliationAttemptRecord
from agentkernel.transactions.enforced import (
    CoordinatorCrashPoint,
    CoordinatorEvidence,
    CoordinatorInjectedCrash,
)

_NOW = datetime(2026, 7, 22, 12, tzinfo=UTC)
_PROOF = canonical_digest({"proof": "objective-observation"})
_FROZEN_LEGACY_DIGESTS = {
    1: "sha256:c621aaf41e48d6de6b89154575165e8fd19d034e8a48a1d14dd96a12be03041c",
    2: "sha256:18a9e79676b67150c04fd841013de2d48d5c3ae5cc1f2b2a4dc4312edc4d4ef9",
    3: "sha256:816733d3184e356a3ec48b1d681e32c4e9bdef2d1685fa4e76aa12410c8ae5f9",
}


def _context(tenant_id: str = "tenant_a") -> AuthenticatedActionContext:
    suffix = tenant_id.removeprefix("tenant_")
    return AuthenticatedActionContext(
        tenant_id=tenant_id,
        principal_id=f"principal_{suffix}",
        goal_id=f"goal_{suffix}",
        run_id=f"run_{suffix}",
        trace_id=f"trace_{suffix}",
        actor_id="service:kernel",
        on_behalf_of=f"principal_{suffix}",
        agent_id=f"agent_{suffix}",
        configuration_digest=canonical_digest({"config": tenant_id}),
    )


def _action(
    context: AuthenticatedActionContext,
    transaction_id: str,
    *,
    resource_name: str = "shared.txt",
    idempotency_key: str | None = None,
    use_intent_fallback: bool = False,
) -> NormalizedAction:
    resource_use = ResourceUse(
        authority_action="fs.write",
        access_mode=ResourceAccessMode.WRITE,
        canonical_resource=f"fs://workspace/{resource_name}",
        effect_domain="filesystem",
        purpose="integration test",
        use_kind=ResourceUseKind.AUTHORITATIVE_EFFECT,
        destination_external=False,
    )
    return NormalizedAction.create(
        context=context,
        transaction_id=transaction_id,
        deadline=_NOW + timedelta(minutes=5),
        idempotency_key=(
            None if use_intent_fallback else (idempotency_key or f"idem-{resource_name}")
        ),
        adapter="filesystem",
        adapter_version="0.1.0",
        adapter_manifest_digest=canonical_digest({"adapter": "filesystem", "version": 1}),
        operation="write_files",
        normalizer_implementation="normalizer.filesystem",
        normalizer_version="1.0.0",
        normalizer_digest=canonical_digest({"normalizer": "filesystem", "version": 1}),
        operation_schema_ref="agentkernel.io/schemas/v1alpha1/WriteFilesArguments",
        operation_schema_digest=canonical_digest({"schema": "write-files", "version": 1}),
        risk_floor=RiskClass.REVERSIBLE,
        effect_domains=("filesystem",),
        resource_uses=(resource_use,),
    )


def _register_context(store: SQLiteControlStore, context: AuthenticatedActionContext) -> None:
    store.register_action_context(context, registered_at=_NOW)


def _put_actions(
    store: SQLiteControlStore,
    context: AuthenticatedActionContext,
    transaction_ids: tuple[str, ...],
    *,
    resource_name: str = "shared.txt",
) -> tuple[NormalizedAction, ...]:
    _register_context(store, context)
    actions = tuple(
        _action(context, transaction_id, resource_name=resource_name)
        for transaction_id in transaction_ids
    )
    for action in actions:
        store.put_normalized_action(action, recorded_at=_NOW)
    return actions


def _quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _copy_current_data_into_published_v6(
    *,
    source_path: Path,
    destination_path: Path,
    legacy_attempt: ReconciliationAttemptRecord,
) -> None:
    """Materialize v6 bytes from current data without running v7 on the destination."""

    connection = sqlite3.connect(destination_path)
    try:
        for version, sql in MIGRATIONS[:6]:
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, digest, applied_at) VALUES (?, ?, ?)",
                (
                    version,
                    canonical_digest({"version": version, "sql": sql}),
                    "2026-07-22T00:00:00.000000Z",
                ),
            )
        connection.commit()
        trigger_rows = tuple(
            connection.execute(
                "SELECT name, sql FROM sqlite_schema "
                "WHERE type = 'trigger' AND sql IS NOT NULL ORDER BY name"
            ).fetchall()
        )
        for name, _sql in trigger_rows:
            connection.execute(f"DROP TRIGGER {_quote_sqlite_identifier(str(name))}")
        connection.execute("ATTACH DATABASE ? AS source", (str(source_path),))
        table_names = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations' "
                "ORDER BY name"
            ).fetchall()
        )
        for table_name in table_names:
            quoted_table = _quote_sqlite_identifier(table_name)
            columns = tuple(
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({quoted_table})").fetchall()
            )
            source_columns = {
                str(row[1])
                for row in connection.execute(
                    f"PRAGMA source.table_info({quoted_table})"
                ).fetchall()
            }
            copied_columns = tuple(column for column in columns if column in source_columns)
            quoted_columns = ", ".join(
                _quote_sqlite_identifier(column) for column in copied_columns
            )
            connection.execute(
                f"INSERT INTO {quoted_table} ({quoted_columns}) "  # noqa: S608
                f"SELECT {quoted_columns} FROM source.{quoted_table}"
            )
        legacy_json = canonical_json_text(legacy_attempt.canonical_record_json())
        legacy_digest = canonical_digest(legacy_attempt.canonical_record_json())
        updated = connection.execute(
            "UPDATE enforced_reconciliation_attempts "
            "SET record_digest = ?, record_json = ? "
            "WHERE tenant_id = ? AND transaction_id = ? "
            "AND recovery_id = ? AND attempt = ?",
            (
                legacy_digest,
                legacy_json,
                legacy_attempt.tenant_id,
                legacy_attempt.transaction_id,
                legacy_attempt.recovery_id,
                legacy_attempt.attempt,
            ),
        )
        assert updated.rowcount == 1
        for _name, sql in trigger_rows:
            connection.execute(str(sql))
        connection.commit()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        connection.execute("DETACH DATABASE source")
    finally:
        connection.close()


@pytest.mark.integration
def test_current_migrations_use_a_separate_tenant_scoped_namespace(tmp_path: Path) -> None:
    path = tmp_path / "control.db"
    with SQLiteJournal(path) as journal:
        assert journal.schema_version() == 7

    assert {
        version: canonical_digest({"version": version, "sql": sql})
        for version, sql in MIGRATIONS[:3]
    } == _FROZEN_LEGACY_DIGESTS

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        tables = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema "
                "WHERE type = 'table' AND name LIKE 'enforced_%' ORDER BY name"
            )
        )
        assert len(tables) == 33
        for table in tables:
            columns = connection.execute(f"PRAGMA table_info('{table}')").fetchall()
            assert columns[0]["name"] == "tenant_id"
            assert columns[0]["pk"] == 1
            foreign_keys = connection.execute(f"PRAGMA foreign_key_list('{table}')").fetchall()
            groups: dict[int, set[str]] = {}
            for foreign_key in foreign_keys:
                groups.setdefault(int(foreign_key["id"]), set()).add(str(foreign_key["from"]))
            assert all("tenant_id" in local_columns for local_columns in groups.values())
        handoff_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info('enforced_recovery_action_handoffs')"
            ).fetchall()
        }
        assert {
            "handoff_lease_id",
            "handoff_worker_id",
            "handoff_fencing_token",
        } <= handoff_columns
        handoff_triggers = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'trigger' "
                "AND tbl_name = 'enforced_recovery_action_handoffs'"
            ).fetchall()
        }
        assert {
            "enforced_recovery_action_handoffs_valid_lease_insert",
            "enforced_recovery_action_handoffs_lease_no_update",
        } <= handoff_triggers
        handoff_foreign_keys: dict[int, set[str]] = {}
        for row in connection.execute(
            "PRAGMA foreign_key_list('enforced_recovery_action_handoffs')"
        ).fetchall():
            if str(row["table"]) == "enforced_worker_leases":
                handoff_foreign_keys.setdefault(int(row["id"]), set()).add(str(row["from"]))
        assert {
            "tenant_id",
            "target_transaction_id",
            "handoff_lease_id",
            "handoff_fencing_token",
        } in handoff_foreign_keys.values()
    finally:
        connection.close()


@pytest.mark.integration
def test_populated_v3_database_migrates_to_current_schema_and_reopens(tmp_path: Path) -> None:
    path = tmp_path / "populated-v3-upgrade.db"
    connection = sqlite3.connect(path)
    try:
        for version, sql in MIGRATIONS[:3]:
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, digest, applied_at) VALUES (?, ?, ?)",
                (
                    version,
                    canonical_digest({"version": version, "sql": sql}),
                    "2026-07-22T00:00:00.000000Z",
                ),
            )
        connection.execute(
            "INSERT INTO enforced_tenants(tenant_id, created_at) VALUES (?, ?)",
            ("tenant:published-v3", "2026-07-22T00:00:00.000000Z"),
        )
        published_ledger = tuple(
            connection.execute(
                "SELECT version, digest FROM schema_migrations ORDER BY version"
            ).fetchall()
        )
        connection.commit()
    finally:
        connection.close()

    with SQLiteJournal(path) as upgraded:
        assert upgraded.schema_version() == 7
    with SQLiteJournal(path) as reopened:
        assert reopened.schema_version() == 7

    connection = sqlite3.connect(path)
    try:
        assert (
            tuple(
                connection.execute(
                    "SELECT version, digest FROM schema_migrations "
                    "WHERE version <= 3 ORDER BY version"
                ).fetchall()
            )
            == published_ledger
        )
        assert dict(published_ledger) == _FROZEN_LEGACY_DIGESTS
        assert connection.execute(
            "SELECT tenant_id, created_at FROM enforced_tenants WHERE tenant_id = ?",
            ("tenant:published-v3",),
        ).fetchone() == ("tenant:published-v3", "2026-07-22T00:00:00.000000Z")
        columns = connection.execute(
            "PRAGMA table_info(enforced_reconciliation_attempts)"
        ).fetchall()
        primary_key = tuple(
            str(row[1]) for row in sorted(columns, key=lambda row: int(row[5])) if int(row[5])
        )
        assert primary_key == ("tenant_id", "transaction_id", "recovery_id", "attempt")
        round_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(enforced_authorization_rounds)")
        }
        assert {
            "authority_snapshot_ref",
            "authority_context_ref",
            "authority_decision_ref",
            "policy_inputs_ref",
            "policy_snapshot_ref",
            "policy_decision_ref",
            "authority_valid_until",
        } <= round_columns
    finally:
        connection.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_published_v6_started_v1_attempt_upgrades_explicitly_to_v1_1(
    tmp_path: Path,
) -> None:
    # The reconciliation table first appeared in v4, so this compatibility gate is
    # intentionally separate from the published-v3 control-schema migration above.
    source_dir = tmp_path / "current-source"
    source_dir.mkdir()
    harness = coordinator_support._make_harness(
        source_dir,
        crash_point=CoordinatorCrashPoint.AFTER_COMMIT_CALL,
    )
    try:
        session = await harness.coordinator.transaction(harness.request)
        with pytest.raises(CoordinatorInjectedCrash):
            async with session:
                await session.commit()
        await coordinator_support._stop_dispatch_before_explicit_resume(
            harness,
            session,
        )
        crashing = coordinator_support._restart_coordinator(
            harness,
            crash_point=CoordinatorCrashPoint.AFTER_RECONCILIATION_STARTED,
        )
        with pytest.raises(CoordinatorInjectedCrash):
            await crashing.resume_dispatch_reconciliation(
                session.record.tenant_id,
                session.record.transaction_id,
            )
        running = harness.store.list_recovery_work(
            tenant_id=session.record.tenant_id,
            transaction_id=session.record.transaction_id,
        )[0]
        assert running.state is RecoveryWorkState.RUNNING
        started = harness.store.get_reconciliation_attempt(
            tenant_id=running.tenant_id,
            transaction_id=running.transaction_id,
            recovery_id=running.recovery_id,
            attempt=running.attempt,
        )
        assert started.outcome is None
        legacy_attempt = ReconciliationAttemptRecord.model_validate(
            {
                **started.model_dump(
                    mode="python",
                    exclude={"operation_evidence_ref", "operation_reason_code"},
                ),
                "schema_version": "1.0",
            }
        )
    finally:
        harness.store.close()

    published_v6_path = tmp_path / "published-v6-started-v1.db"
    _copy_current_data_into_published_v6(
        source_path=source_dir / "control.db",
        destination_path=published_v6_path,
        legacy_attempt=legacy_attempt,
    )

    with SQLiteEnforcedTransactionStore(published_v6_path) as upgraded:
        assert upgraded.schema_version == 7
        migrated = upgraded.get_reconciliation_attempt(
            tenant_id=legacy_attempt.tenant_id,
            transaction_id=legacy_attempt.transaction_id,
            recovery_id=legacy_attempt.recovery_id,
            attempt=legacy_attempt.attempt,
        )
        assert migrated == legacy_attempt
        assert "operation_evidence_ref" not in migrated.canonical_record_json()

        completed_at = harness.clock()
        assert running.permit_ref is not None
        control = CoordinatorEvidence(
            transaction_id=running.transaction_id,
            event="reconciliation.query_failed",
            reason_code="RECONCILIATION_QUERY_FAILED",
            recorded_at=completed_at,
            subject_ref=running.permit_ref,
        )
        control_ref = harness.artifacts.put_model(control).digest
        completed = upgraded.finish_reconciliation(
            tenant_id=migrated.tenant_id,
            transaction_id=migrated.transaction_id,
            recovery_id=migrated.recovery_id,
            expected_attempt_version=migrated.version,
            outcome=ReconciliationOutcome.UNKNOWN,
            evidence_refs=tuple(sorted({*migrated.evidence_refs, control_ref})),
            operation_evidence_ref=control_ref,
            operation_reason_code=control.reason_code,
            completed_at=completed_at,
            next_attempt_not_before=completed_at + timedelta(seconds=2),
            reason_code=control.reason_code,
        ).attempt
        assert completed.schema_version == "1.1"
        assert completed.operation_evidence_ref == control_ref
        assert completed.operation_reason_code == control.reason_code
        assert completed.canonical_record_json()["operation_evidence_ref"] == control_ref

    with SQLiteEnforcedTransactionStore(published_v6_path) as reopened:
        assert (
            reopened.get_reconciliation_attempt(
                tenant_id=completed.tenant_id,
                transaction_id=completed.transaction_id,
                recovery_id=completed.recovery_id,
                attempt=completed.attempt,
            )
            == completed
        )


@pytest.mark.integration
def test_production_v5_migration_rolls_back_and_retries_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "legacy-v4.db"
    connection = sqlite3.connect(path)
    try:
        for version, sql in MIGRATIONS[:4]:
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, digest, applied_at) VALUES (?, ?, ?)",
                (
                    version,
                    canonical_digest({"version": version, "sql": sql}),
                    "2026-07-22T00:00:00.000000Z",
                ),
            )
        connection.commit()
    finally:
        connection.close()

    original_execute = SQLiteJournal._execute_migration_statement

    def fail_after_late_report_table(
        journal: SQLiteJournal,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> None:
        original_execute(journal, statement, parameters)
        if statement.startswith("CREATE TABLE enforced_late_recovery_reports"):
            raise RuntimeError("injected during production v5")

    monkeypatch.setattr(
        SQLiteJournal,
        "_execute_migration_statement",
        fail_after_late_report_table,
    )
    with pytest.raises(RuntimeError, match="production v5"):
        SQLiteJournal(path)

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 4
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'enforced_late_recovery_reports'"
            ).fetchone()[0]
            == 0
        )
        columns = connection.execute(
            "PRAGMA table_info(enforced_reconciliation_attempts)"
        ).fetchall()
        primary_key = tuple(
            str(row[1]) for row in sorted(columns, key=lambda row: int(row[5])) if int(row[5])
        )
        assert primary_key == ("tenant_id", "transaction_id", "dispatch_id", "attempt")
    finally:
        connection.close()

    monkeypatch.setattr(SQLiteJournal, "_execute_migration_statement", original_execute)
    with SQLiteJournal(path) as retried:
        assert retried.schema_version() == 7


@pytest.mark.integration
def test_concurrent_first_open_retries_only_the_wal_lock_race(tmp_path: Path) -> None:
    path = tmp_path / "concurrent-first-open.db"
    workers = 12
    barrier = threading.Barrier(workers)

    def initialize(_: int) -> int:
        barrier.wait()
        with SQLiteControlStore(path) as store:
            return store.schema_version

    with ThreadPoolExecutor(max_workers=workers) as executor:
        assert tuple(executor.map(initialize, range(workers))) == (MIGRATIONS[-1][0],) * workers


@pytest.mark.integration
def test_unversioned_nonempty_database_is_not_adopted(tmp_path: Path) -> None:
    path = tmp_path / "precreated-weak-schema.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE transactions (transaction_id TEXT)")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as captured:
        SQLiteJournal(path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    assert captured.value.details == {
        "object_type": "table",
        "object_name": "transactions",
    }

    connection = sqlite3.connect(path)
    try:
        objects = tuple(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        )
    finally:
        connection.close()
    assert objects == ("transactions",)


@pytest.mark.integration
def test_production_v3_migration_rolls_back_and_retries_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "legacy-v2.db"
    connection = sqlite3.connect(path)
    try:
        for version, sql in MIGRATIONS[:2]:
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, digest, applied_at) VALUES (?, ?, ?)",
                (
                    version,
                    canonical_digest({"version": version, "sql": sql}),
                    "2026-01-01T00:00:00.000Z",
                ),
            )
        connection.commit()
    finally:
        connection.close()

    original_execute = SQLiteJournal._execute_migration_statement
    statements = 0

    def fail_during_v3(
        journal: SQLiteJournal,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> None:
        nonlocal statements
        original_execute(journal, statement, parameters)
        is_v3_marker = bool(parameters) and parameters[0] == 3
        if not is_v3_marker:
            statements += 1
            if statements == 5:
                raise RuntimeError("injected during production v3")

    monkeypatch.setattr(SQLiteJournal, "_execute_migration_statement", fail_during_v3)
    with pytest.raises(RuntimeError, match="production v3"):
        SQLiteJournal(path)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 2
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name LIKE 'enforced_%'"
            ).fetchone()[0]
            == 0
        )
    finally:
        connection.close()

    monkeypatch.setattr(SQLiteJournal, "_execute_migration_statement", original_execute)
    with SQLiteJournal(path) as retried:
        assert retried.schema_version() == 7


@pytest.mark.integration
def test_normalized_actions_are_immutable_and_tenant_isolated(tmp_path: Path) -> None:
    path = tmp_path / "tenant-actions.db"
    context_a = _context("tenant_a")
    context_b = _context("tenant_b")
    action_a = _action(context_a, "tx_shared", resource_name="a.txt")
    action_b = _action(context_b, "tx_shared", resource_name="b.txt")

    with SQLiteControlStore(path) as store:
        _register_context(store, context_a)
        _register_context(store, context_b)
        assert store.put_normalized_action(action_a, recorded_at=_NOW).created
        assert store.put_normalized_action(action_b, recorded_at=_NOW).created
        retry = store.put_normalized_action(action_a, recorded_at=_NOW + timedelta(seconds=1))
        assert not retry.created
        assert retry.action == action_a
        assert store.get_normalized_action("tenant_a", "tx_shared").action == action_a
        assert store.get_normalized_action("tenant_b", "tx_shared").action == action_b
        with pytest.raises(AgentKernelError) as unknown:
            store.get_normalized_action("tenant_c", "tx_shared")
        assert unknown.value.code is ErrorCode.VALIDATION_ERROR

        conflicting = _action(context_a, "tx_shared", resource_name="other.txt")
        with pytest.raises(AgentKernelError) as mismatch:
            store.put_normalized_action(conflicting, recorded_at=_NOW)
        assert mismatch.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
def test_explicit_identity_registration_is_idempotent_and_rejects_rebinding(
    tmp_path: Path,
) -> None:
    path = tmp_path / "identity-hierarchy.db"
    with SQLiteControlStore(path) as store:
        assert store.path == path.resolve()
        with pytest.raises(AgentKernelError) as missing_tenant:
            store.register_principal("tenant_a", "principal_a", registered_at=_NOW)
        assert missing_tenant.value.code is ErrorCode.INTEGRITY_ERROR

        assert store.register_tenant("tenant_a", registered_at=_NOW)
        assert not store.register_tenant("tenant_a", registered_at=_NOW + timedelta(seconds=1))
        assert store.register_principal("tenant_a", "principal_a", registered_at=_NOW)
        assert not store.register_principal("tenant_a", "principal_a", registered_at=_NOW)
        assert store.register_principal("tenant_a", "principal_b", registered_at=_NOW)
        assert store.register_goal("tenant_a", "principal_a", "goal_shared", registered_at=_NOW)
        assert not store.register_goal("tenant_a", "principal_a", "goal_shared", registered_at=_NOW)
        with pytest.raises(AgentKernelError) as rebound_goal:
            store.register_goal("tenant_a", "principal_b", "goal_shared", registered_at=_NOW)
        assert rebound_goal.value.code is ErrorCode.INTEGRITY_ERROR

        assert store.register_run(
            "tenant_a", "principal_a", "goal_shared", "run_shared", registered_at=_NOW
        )
        assert not store.register_run(
            "tenant_a", "principal_a", "goal_shared", "run_shared", registered_at=_NOW
        )
        assert store.register_goal("tenant_a", "principal_a", "goal_other", registered_at=_NOW)
        with pytest.raises(AgentKernelError) as rebound_run:
            store.register_run(
                "tenant_a", "principal_a", "goal_other", "run_shared", registered_at=_NOW
            )
        assert rebound_run.value.code is ErrorCode.INTEGRITY_ERROR

        base = _context().model_dump(mode="python")
        conflicting_goal_context = AuthenticatedActionContext.model_validate(
            {
                **base,
                "principal_id": "principal_b",
                "on_behalf_of": "principal_b",
                "goal_id": "goal_shared",
                "run_id": "run_shared",
            }
        )
        with pytest.raises(AgentKernelError) as context_goal:
            store.register_action_context(conflicting_goal_context, registered_at=_NOW)
        assert context_goal.value.code is ErrorCode.INTEGRITY_ERROR

        conflicting_run_context = AuthenticatedActionContext.model_validate(
            {**base, "goal_id": "goal_other", "run_id": "run_shared"}
        )
        with pytest.raises(AgentKernelError) as context_run:
            store.register_action_context(conflicting_run_context, registered_at=_NOW)
        assert context_run.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
def test_control_store_rejects_malformed_identifiers_digests_times_and_enums(
    tmp_path: Path,
) -> None:
    path = tmp_path / "invalid-inputs.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        (action,) = _put_actions(store, context, ("tx_validation",))
        with pytest.raises(AgentKernelError) as bad_identifier:
            store.get_normalized_action("tenant/escape", action.transaction_id)
        assert bad_identifier.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as naive_time:
            store.register_tenant("tenant_naive", registered_at=datetime(2026, 1, 1))
        assert naive_time.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as bad_digest:
            store.acquire_intent(
                tenant_id=context.tenant_id,
                intent_hash="not-a-digest",
                transaction_id=action.transaction_id,
                attempted_at=_NOW,
            )
        assert bad_digest.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as negative_owner:
            store.acquire_intent(
                tenant_id=context.tenant_id,
                intent_hash=action.intent_hash,
                transaction_id=action.transaction_id,
                attempted_at=_NOW,
                expected_owner_version=-1,
            )
        assert negative_owner.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as bad_kind:
            store.get_decision_snapshot(
                tenant_id=context.tenant_id,
                kind="NOT_A_DECISION",
                decision_id="decision_unknown",
            )
        assert bad_kind.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.integration
def test_action_and_resource_triggers_reject_direct_mutation(tmp_path: Path) -> None:
    path = tmp_path / "immutable-action.db"
    context = _context()
    action = _action(context, "tx_immutable")
    with SQLiteControlStore(path) as store:
        _register_context(store, context)
        store.put_normalized_action(action, recorded_at=_NOW)

    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE enforced_normalized_actions SET action_json = '{}' "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (context.tenant_id, action.transaction_id),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM enforced_resource_uses WHERE tenant_id = ? AND transaction_id = ?",
                (context.tenant_id, action.transaction_id),
            )
    finally:
        connection.close()


@pytest.mark.integration
def test_action_digest_check_detects_tampering_after_trigger_bypass(tmp_path: Path) -> None:
    path = tmp_path / "tampered-action.db"
    context = _context()
    action = _action(context, "tx_tampered")
    with SQLiteControlStore(path) as store:
        _register_context(store, context)
        store.put_normalized_action(action, recorded_at=_NOW)

    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TRIGGER enforced_normalized_actions_no_update")
        connection.execute(
            "UPDATE enforced_normalized_actions SET action_digest = ? "
            "WHERE tenant_id = ? AND transaction_id = ?",
            ("sha256:" + "0" * 64, context.tenant_id, action.transaction_id),
        )
        connection.execute(
            "CREATE TRIGGER enforced_normalized_actions_no_update "
            "BEFORE UPDATE ON enforced_normalized_actions BEGIN "
            "SELECT RAISE(ABORT, 'enforced normalized actions are immutable'); END"
        )
        connection.commit()
    finally:
        connection.close()

    with SQLiteControlStore(path) as store:
        with pytest.raises(AgentKernelError) as captured:
            store.get_normalized_action(context.tenant_id, action.transaction_id)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
def test_resource_reads_detect_tampering_with_intact_live_schema(tmp_path: Path) -> None:
    path = tmp_path / "tampered-resource-history.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        action = _put_actions(store, context, ("tx_tamper_history",))[0]
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=action.intent_hash,
            transaction_id=action.transaction_id,
            attempted_at=_NOW,
        )

    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TRIGGER enforced_resource_uses_no_update")
        connection.execute(
            "UPDATE enforced_resource_uses SET resource_use_json = '{}' "
            "WHERE tenant_id = ? AND transaction_id = ?",
            (context.tenant_id, action.transaction_id),
        )
        connection.execute(
            "CREATE TRIGGER enforced_resource_uses_no_update "
            "BEFORE UPDATE ON enforced_resource_uses BEGIN "
            "SELECT RAISE(ABORT, 'enforced resource uses are immutable'); END"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as resource_tamper:
        SQLiteControlStore(path)
    assert resource_tamper.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
def test_restart_rejects_tampered_owner_idempotency_projection(tmp_path: Path) -> None:
    path = tmp_path / "tampered-owner-key.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        action = _put_actions(store, context, ("tx_owner_key_tamper",))[0]
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=action.intent_hash,
            transaction_id=action.transaction_id,
            attempted_at=_NOW,
        )

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE enforced_intent_owners SET effective_idempotency_key = ? "
            "WHERE tenant_id = ? AND intent_hash = ?",
            ("idem-forged", context.tenant_id, action.intent_hash),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as captured:
        SQLiteControlStore(path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
def test_decision_row_digest_binds_raw_recorded_at_on_startup(tmp_path: Path) -> None:
    path = tmp_path / "tampered-decision-time.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        action = _put_actions(store, context, ("tx_decision_time",))[0]
        store.append_decision_snapshot(
            tenant_id=context.tenant_id,
            kind=DecisionKind.AUTHORITY,
            decision_id="decision_time",
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            decision={"verdict": "ALLOW"},
            recorded_at=_NOW,
        )

    connection = sqlite3.connect(path)
    try:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
            "AND name = 'enforced_decision_snapshots_no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER enforced_decision_snapshots_no_update")
        connection.execute(
            "UPDATE enforced_decision_snapshots SET recorded_at = ? "
            "WHERE tenant_id = ? AND decision_id = ?",
            (
                "2026-07-22T12:00:01.000000Z",
                context.tenant_id,
                "decision_time",
            ),
        )
        connection.execute(trigger_sql)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as captured:
        SQLiteControlStore(path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
def test_restart_rejects_tampered_intent_attempt_projection(tmp_path: Path) -> None:
    path = tmp_path / "tampered-attempt-projection.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        owner, _alias = _put_actions(store, context, ("tx_owner_tamper", "tx_alias_tamper"))
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW,
        )

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE enforced_intent_attempts "
            "SET attempt_state = 'NO_EFFECT_CONFIRMED', state_version = 1, "
            "evidence_digest = ? WHERE tenant_id = ? AND intent_hash = ? "
            "AND transaction_id = ?",
            (_PROOF, context.tenant_id, owner.intent_hash, owner.transaction_id),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as captured:
        SQLiteControlStore(path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
def test_restart_rejects_tampered_intent_history_with_restored_trigger(
    tmp_path: Path,
) -> None:
    path = tmp_path / "tampered-intent-history.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        (owner,) = _put_actions(store, context, ("tx_history_tamper",))
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW,
        )

    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TRIGGER enforced_intent_history_no_update")
        connection.execute(
            "UPDATE enforced_intent_attempt_history SET disposition = 'REVIEW_REQUIRED' "
            "WHERE tenant_id = ? AND intent_hash = ? AND sequence = 0",
            (context.tenant_id, owner.intent_hash),
        )
        connection.execute(
            "CREATE TRIGGER enforced_intent_history_no_update "
            "BEFORE UPDATE ON enforced_intent_attempt_history BEGIN "
            "SELECT RAISE(ABORT, 'enforced intent history is immutable'); END"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as captured:
        SQLiteControlStore(path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
def test_restart_rejects_tampered_intent_history_head(tmp_path: Path) -> None:
    path = tmp_path / "tampered-intent-head.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        (owner,) = _put_actions(store, context, ("tx_head_tamper",))
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW,
        )

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE enforced_intent_owners SET history_head_digest = ? "
            "WHERE tenant_id = ? AND intent_hash = ?",
            (
                canonical_digest({"tampered": "head"}),
                context.tenant_id,
                owner.intent_hash,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as captured:
        SQLiteControlStore(path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
def test_intent_owner_returns_every_duplicate_disposition_and_survives_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "intent-dispositions.db"
    context = _context()
    transaction_ids = ("tx_owner", "tx_active", "tx_reconcile", "tx_committed")
    with SQLiteControlStore(path) as store:
        actions = _put_actions(store, context, transaction_ids)
        intent_hash = actions[0].intent_hash
        assert {action.intent_hash for action in actions} == {intent_hash}

        assert (
            store.acquire_intent(
                tenant_id=context.tenant_id,
                intent_hash=intent_hash,
                transaction_id="tx_owner",
                attempted_at=_NOW,
            ).disposition
            is IntentDisposition.ACQUIRED
        )
        assert (
            store.acquire_intent(
                tenant_id=context.tenant_id,
                intent_hash=intent_hash,
                transaction_id="tx_owner",
                attempted_at=_NOW,
            ).disposition
            is IntentDisposition.SAME_TRANSACTION
        )
        assert (
            store.acquire_intent(
                tenant_id=context.tenant_id,
                intent_hash=intent_hash,
                transaction_id="tx_active",
                attempted_at=_NOW,
            ).disposition
            is IntentDisposition.ALIAS_ACTIVE
        )
        reconcile = store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=intent_hash,
            transaction_id="tx_owner",
            expected_version=0,
            state=IntentAttemptState.RECONCILE_REQUIRED,
            evidence_digest=_PROOF,
            recorded_at=_NOW,
        )
        assert reconcile.version == 1
        exact_retry = store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=intent_hash,
            transaction_id="tx_owner",
            expected_version=0,
            state=IntentAttemptState.RECONCILE_REQUIRED,
            evidence_digest=_PROOF,
            recorded_at=_NOW,
        )
        assert exact_retry == reconcile
        assert (
            store.acquire_intent(
                tenant_id=context.tenant_id,
                intent_hash=intent_hash,
                transaction_id="tx_reconcile",
                attempted_at=_NOW,
            ).disposition
            is IntentDisposition.ALIAS_RECONCILE
        )
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=intent_hash,
            transaction_id="tx_owner",
            expected_version=1,
            state=IntentAttemptState.COMMITTED,
            evidence_digest=canonical_digest({"receipt": "committed"}),
            recorded_at=_NOW,
        )
        assert (
            store.acquire_intent(
                tenant_id=context.tenant_id,
                intent_hash=intent_hash,
                transaction_id="tx_committed",
                attempted_at=_NOW,
            ).disposition
            is IntentDisposition.ALIAS_COMMITTED
        )

    with SQLiteControlStore(path) as reopened:
        history = reopened.list_intent_history(
            tenant_id=context.tenant_id,
            intent_hash=intent_hash,
        )
        assert tuple(entry.sequence for entry in history) == tuple(range(len(history)))
        assert history[-1].disposition is IntentDisposition.ALIAS_COMMITTED


@pytest.mark.integration
def test_no_effect_transfer_uses_owner_cas_and_rejects_stale_transfer(tmp_path: Path) -> None:
    path = tmp_path / "intent-transfer.db"
    context = _context()
    transaction_ids = ("tx_old", "tx_new", "tx_stale")
    with SQLiteControlStore(path) as store:
        actions = _put_actions(store, context, transaction_ids, resource_name="transfer.txt")
        intent_hash = actions[0].intent_hash
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=intent_hash,
            transaction_id="tx_old",
            attempted_at=_NOW,
        )
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=intent_hash,
            transaction_id="tx_old",
            expected_version=0,
            state=IntentAttemptState.NO_EFFECT_CONFIRMED,
            evidence_digest=_PROOF,
            recorded_at=_NOW,
        )
        transferred = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=intent_hash,
            transaction_id="tx_new",
            attempted_at=_NOW,
            expected_owner_version=0,
        )
        assert transferred.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT
        assert transferred.owner_version == 1
        assert transferred.previous_owner_transaction_id == "tx_old"

        with pytest.raises(AgentKernelError) as old_owner:
            store.record_intent_attempt_state(
                tenant_id=context.tenant_id,
                intent_hash=intent_hash,
                transaction_id="tx_old",
                expected_version=1,
                state=IntentAttemptState.REVIEW_REQUIRED,
                evidence_digest=_PROOF,
                recorded_at=_NOW,
            )
        assert old_owner.value.code is ErrorCode.VERSION_CONFLICT

        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=intent_hash,
            transaction_id="tx_new",
            expected_version=0,
            state=IntentAttemptState.NO_EFFECT_CONFIRMED,
            evidence_digest=_PROOF,
            recorded_at=_NOW,
        )
        stale = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=intent_hash,
            transaction_id="tx_stale",
            attempted_at=_NOW,
            expected_owner_version=0,
        )
        assert stale.disposition is IntentDisposition.REVIEW_REQUIRED
        assert stale.owner_transaction_id == "tx_new"
        retried = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=intent_hash,
            transaction_id="tx_stale",
            attempted_at=_NOW,
            expected_owner_version=1,
        )
        assert retried.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT
        assert retried.owner_transaction_id == "tx_stale"
        assert retried.owner_version == 2


@pytest.mark.integration
@pytest.mark.parametrize("fallback_owner", [False, True])
def test_no_effect_transfer_requires_same_effective_idempotency_key(
    tmp_path: Path,
    fallback_owner: bool,
) -> None:
    path = tmp_path / f"intent-key-fence-{fallback_owner}.db"
    context = _context()
    owner = _action(
        context,
        "tx_key_owner",
        resource_name="key-fence.txt",
        idempotency_key="idem-owner",
        use_intent_fallback=fallback_owner,
    )
    candidate = _action(
        context,
        "tx_key_candidate",
        resource_name="key-fence.txt",
        idempotency_key="idem-different",
    )
    assert owner.intent_hash == candidate.intent_hash
    with SQLiteControlStore(path) as store:
        _register_context(store, context)
        store.put_normalized_action(owner, recorded_at=_NOW)
        store.put_normalized_action(candidate, recorded_at=_NOW)
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW,
        )
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            expected_version=0,
            state=IntentAttemptState.NO_EFFECT_CONFIRMED,
            evidence_digest=_PROOF,
            recorded_at=_NOW,
        )
        rejected = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=candidate.transaction_id,
            attempted_at=_NOW,
            expected_owner_version=0,
        )
        assert rejected.disposition is IntentDisposition.REVIEW_REQUIRED
        assert rejected.owner_transaction_id == owner.transaction_id
        ledger = store._validate_intent_ledger(context.tenant_id, owner.intent_hash)
        assert ledger.effective_idempotency_key == (
            owner.intent_hash if fallback_owner else "idem-owner"
        )
        assert ledger.entries[-1].effective_idempotency_key == "idem-different"

    with SQLiteControlStore(path) as reopened:
        ledger = reopened._validate_intent_ledger(context.tenant_id, owner.intent_hash)
        assert ledger.owner_transaction_id == owner.transaction_id


@pytest.mark.integration
def test_intent_state_cas_illegal_transition_and_review_owner_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "intent-errors.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        owner, alias = _put_actions(
            store,
            context,
            ("tx_review_owner", "tx_review_alias"),
            resource_name="review.txt",
        )
        with pytest.raises(AgentKernelError) as unknown_action:
            store.acquire_intent(
                tenant_id=context.tenant_id,
                intent_hash=owner.intent_hash,
                transaction_id="tx_missing",
                attempted_at=_NOW,
            )
        assert unknown_action.value.code is ErrorCode.VALIDATION_ERROR
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW,
        )
        with pytest.raises(AgentKernelError) as active_target:
            store.record_intent_attempt_state(
                tenant_id=context.tenant_id,
                intent_hash=owner.intent_hash,
                transaction_id=owner.transaction_id,
                expected_version=0,
                state=IntentAttemptState.ACTIVE,
                evidence_digest=_PROOF,
                recorded_at=_NOW,
            )
        assert active_target.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as unknown_state:
            store.record_intent_attempt_state(
                tenant_id=context.tenant_id,
                intent_hash=owner.intent_hash,
                transaction_id=owner.transaction_id,
                expected_version=0,
                state="UNKNOWN_STATE",
                evidence_digest=_PROOF,
                recorded_at=_NOW,
            )
        assert unknown_state.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as stale_state:
            store.record_intent_attempt_state(
                tenant_id=context.tenant_id,
                intent_hash=owner.intent_hash,
                transaction_id=owner.transaction_id,
                expected_version=1,
                state=IntentAttemptState.REVIEW_REQUIRED,
                evidence_digest=_PROOF,
                recorded_at=_NOW,
            )
        assert stale_state.value.code is ErrorCode.VERSION_CONFLICT

        review = store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            expected_version=0,
            state=IntentAttemptState.REVIEW_REQUIRED,
            evidence_digest=_PROOF,
            recorded_at=_NOW,
        )
        assert review.state is IntentAttemptState.REVIEW_REQUIRED
        duplicate = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=alias.transaction_id,
            attempted_at=_NOW,
        )
        assert duplicate.disposition is IntentDisposition.REVIEW_REQUIRED
        with pytest.raises(AgentKernelError) as illegal:
            store.record_intent_attempt_state(
                tenant_id=context.tenant_id,
                intent_hash=owner.intent_hash,
                transaction_id=owner.transaction_id,
                expected_version=1,
                state=IntentAttemptState.COMMITTED,
                evidence_digest=_PROOF,
                recorded_at=_NOW,
            )
        assert illegal.value.code is ErrorCode.ILLEGAL_TRANSITION
        with pytest.raises(AgentKernelError) as missing_attempt:
            store.get_intent_attempt(
                tenant_id=context.tenant_id,
                intent_hash=owner.intent_hash,
                transaction_id="tx_absent",
            )
        assert missing_attempt.value.code is ErrorCode.VALIDATION_ERROR


def _register_budgets(
    store: SQLiteControlStore,
    context: AuthenticatedActionContext,
    capability_ids: tuple[str, ...],
    *,
    max_uses: int,
) -> None:
    for capability_id in capability_ids:
        store.register_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capability_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            max_uses=max_uses,
            registered_at=_NOW,
        )


@pytest.mark.integration
def test_capability_chain_retry_commit_and_release_are_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "capability-retry.db"
    context = _context()
    capabilities = ("cap_a", "cap_b")
    with SQLiteControlStore(path) as store:
        actions = _put_actions(
            store,
            context,
            ("tx_commit",),
            resource_name="same-budget-intent.txt",
        )
        _register_budgets(store, context, capabilities, max_uses=2)
        intent_hash = actions[0].intent_hash
        first = store.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW,
        )
        retry = store.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW + timedelta(seconds=1),
        )
        assert first.changed
        assert not retry.changed
        assert retry.state is CapabilityReservationState.RESERVED
        committed = store.commit_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=intent_hash,
            capability_ids=capabilities,
            fence=first.fence,
            committed_at=_NOW,
        )
        committed_retry = store.commit_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=intent_hash,
            capability_ids=capabilities,
            fence=first.fence,
            committed_at=_NOW,
        )
        assert committed.changed
        assert committed.state is CapabilityReservationState.COMMITTED
        assert not committed_retry.changed
        with pytest.raises(AgentKernelError) as release_committed:
            store.release_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=intent_hash,
                capability_ids=capabilities,
                fence=first.fence,
                released_at=_NOW,
            )
        assert release_committed.value.code is ErrorCode.ILLEGAL_TRANSITION
        for capability_id in capabilities:
            budget = store.get_capability_budget(
                tenant_id=context.tenant_id,
                capability_id=capability_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
            )
            assert (budget.reserved_uses, budget.committed_uses) == (0, 1)
            assert budget.consumed_uses == 1

        release_action = _action(context, "tx_release", resource_name="released-intent.txt")
        store.put_normalized_action(release_action, recorded_at=_NOW)
        reserved = store.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=release_action.intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW,
        )
        assert reserved.changed
        released = store.release_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=release_action.intent_hash,
            capability_ids=capabilities,
            fence=reserved.fence,
            released_at=_NOW,
        )
        released_retry = store.release_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=release_action.intent_hash,
            capability_ids=capabilities,
            fence=reserved.fence,
            released_at=_NOW,
        )
        assert released.changed
        assert not released_retry.changed
        with pytest.raises(AgentKernelError) as replay:
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=release_action.intent_hash,
                capability_ids=capabilities,
                reserved_at=_NOW,
            )
        assert replay.value.code is ErrorCode.AUTHORITY_MISSING


@pytest.mark.integration
def test_released_chain_reactivates_once_after_no_effect_owner_transfer_and_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "capability-reactivation.db"
    context = _context()
    capabilities = ("cap_transfer",)
    with SQLiteControlStore(path) as store:
        owner, successor = _put_actions(
            store,
            context,
            ("tx_release_owner", "tx_release_successor"),
            resource_name="reactivated-intent.txt",
        )
        acquired = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW,
        )
        assert acquired.disposition is IntentDisposition.ACQUIRED
        _register_budgets(store, context, capabilities, max_uses=1)
        reserved = store.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW,
        )
        assert reserved.activation_owner_transaction_id == owner.transaction_id
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            expected_version=0,
            state=IntentAttemptState.NO_EFFECT_CONFIRMED,
            evidence_digest=_PROOF,
            recorded_at=_NOW + timedelta(seconds=1),
        )
        released = store.release_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            fence=reserved.fence,
            released_at=_NOW + timedelta(seconds=2),
        )
        assert released.release_history_digest is not None
        with pytest.raises(AgentKernelError) as no_transfer:
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=owner.intent_hash,
                capability_ids=capabilities,
                reserved_at=_NOW + timedelta(seconds=3),
            )
        assert no_transfer.value.code is ErrorCode.AUTHORITY_MISSING
        transferred = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=successor.intent_hash,
            transaction_id=successor.transaction_id,
            expected_owner_version=0,
            attempted_at=_NOW + timedelta(seconds=4),
        )
        assert transferred.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT

    with SQLiteControlStore(path) as reopened:
        reactivated = reopened.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW + timedelta(seconds=5),
        )
        assert reactivated.changed
        assert reactivated.state is CapabilityReservationState.RESERVED
        assert reactivated.activation_owner_transaction_id == successor.transaction_id
        assert reactivated.activation_owner_version == 1
        assert reactivated.release_history_digest is None
        exact_retry = reopened.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW + timedelta(seconds=6),
        )
        assert not exact_retry.changed
        committed = reopened.commit_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            fence=reactivated.fence,
            committed_at=_NOW + timedelta(seconds=7),
        )
        committed_retry = reopened.commit_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            fence=reactivated.fence,
            committed_at=_NOW + timedelta(seconds=8),
        )
        assert committed.changed
        assert not committed_retry.changed
        budget = reopened.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capabilities[0],
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (budget.reserved_uses, budget.committed_uses) == (0, 1)


@pytest.mark.integration
def test_no_effect_owner_cannot_transfer_before_capability_release(tmp_path: Path) -> None:
    path = tmp_path / "transfer-before-release.db"
    context = _context()
    capabilities = ("cap_release_guard",)
    with SQLiteControlStore(path) as store:
        owner, successor = _put_actions(
            store,
            context,
            ("tx_guard_owner", "tx_guard_successor"),
            resource_name="release-guard.txt",
        )
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW,
        )
        _register_budgets(store, context, capabilities, max_uses=1)
        reserved = store.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW,
        )
        with pytest.raises(AgentKernelError) as active_release:
            store.release_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=owner.intent_hash,
                capability_ids=capabilities,
                fence=reserved.fence,
                released_at=_NOW + timedelta(milliseconds=500),
            )
        assert active_release.value.code is ErrorCode.ILLEGAL_TRANSITION
        still_reserved = store.get_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
        )
        assert still_reserved.state is CapabilityReservationState.RESERVED
        before_proof = store.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capabilities[0],
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (before_proof.reserved_uses, before_proof.committed_uses) == (1, 0)
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            expected_version=0,
            state=IntentAttemptState.NO_EFFECT_CONFIRMED,
            evidence_digest=_PROOF,
            recorded_at=_NOW + timedelta(seconds=1),
        )
        blocked = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=successor.intent_hash,
            transaction_id=successor.transaction_id,
            expected_owner_version=0,
            attempted_at=_NOW + timedelta(seconds=2),
        )
        assert blocked.disposition is IntentDisposition.REVIEW_REQUIRED
        assert blocked.owner_transaction_id == owner.transaction_id
        store.release_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            fence=reserved.fence,
            released_at=_NOW + timedelta(seconds=3),
        )
        transferred = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=successor.intent_hash,
            transaction_id=successor.transaction_id,
            expected_owner_version=0,
            attempted_at=_NOW + timedelta(seconds=4),
        )
        assert transferred.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT
        after_release = store.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capabilities[0],
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (after_release.reserved_uses, after_release.committed_uses) == (0, 0)


def _prepare_released_transferred_chain(
    path: Path,
) -> tuple[AuthenticatedActionContext, NormalizedAction, tuple[str, ...]]:
    context = _context()
    capabilities = ("cap_reactivate",)
    with SQLiteControlStore(path) as store:
        owner, successor = _put_actions(
            store,
            context,
            ("tx_concurrent_owner", "tx_concurrent_successor"),
            resource_name="concurrent-reactivation.txt",
        )
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW,
        )
        _register_budgets(store, context, capabilities, max_uses=1)
        reserved = store.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW,
        )
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            expected_version=0,
            state=IntentAttemptState.NO_EFFECT_CONFIRMED,
            evidence_digest=_PROOF,
            recorded_at=_NOW + timedelta(seconds=1),
        )
        store.release_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            fence=reserved.fence,
            released_at=_NOW + timedelta(seconds=2),
        )
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=successor.intent_hash,
            transaction_id=successor.transaction_id,
            expected_owner_version=0,
            attempted_at=_NOW + timedelta(seconds=3),
        )
    return context, owner, capabilities


def _prepare_reactivated_chain_with_fences(
    path: Path,
) -> tuple[
    AuthenticatedActionContext,
    NormalizedAction,
    tuple[str, ...],
    CapabilityReservationFence,
    CapabilityReservationFence,
]:
    context = _context()
    capabilities = ("cap_fenced",)
    with SQLiteControlStore(path) as store:
        owner, successor = _put_actions(
            store,
            context,
            ("tx_fence_old", "tx_fence_current"),
            resource_name="fenced-reactivation.txt",
        )
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW,
        )
        _register_budgets(store, context, capabilities, max_uses=1)
        original = store.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW,
        )
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            expected_version=0,
            state=IntentAttemptState.NO_EFFECT_CONFIRMED,
            evidence_digest=_PROOF,
            recorded_at=_NOW + timedelta(seconds=1),
        )
        store.release_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            fence=original.fence,
            released_at=_NOW + timedelta(seconds=2),
        )
        transferred = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=successor.intent_hash,
            transaction_id=successor.transaction_id,
            expected_owner_version=0,
            attempted_at=_NOW + timedelta(seconds=3),
        )
        assert transferred.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT
    with SQLiteControlStore(path) as reopened:
        reactivated = reopened.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW + timedelta(seconds=4),
        )
    return context, owner, capabilities, original.fence, reactivated.fence


@pytest.mark.integration
def test_stale_activation_fence_cannot_transition_reactivated_chain_after_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "stale-capability-fence.db"
    context, action, capabilities, stale_fence, current_fence = (
        _prepare_reactivated_chain_with_fences(path)
    )

    with SQLiteControlStore(path) as reopened:
        with pytest.raises(AgentKernelError) as stale_commit:
            reopened.commit_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=capabilities,
                fence=stale_fence,
                committed_at=_NOW + timedelta(seconds=5),
            )
        assert stale_commit.value.code is ErrorCode.VERSION_CONFLICT
        with pytest.raises(AgentKernelError) as stale_release:
            reopened.release_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=capabilities,
                fence=stale_fence,
                released_at=_NOW + timedelta(seconds=5),
            )
        assert stale_release.value.code is ErrorCode.VERSION_CONFLICT

        before = reopened.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capabilities[0],
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (before.reserved_uses, before.committed_uses) == (1, 0)
        committed = reopened.commit_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=action.intent_hash,
            capability_ids=capabilities,
            fence=current_fence,
            committed_at=_NOW + timedelta(seconds=6),
        )
        assert committed.changed

    with SQLiteControlStore(path) as restarted:
        retry = restarted.commit_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=action.intent_hash,
            capability_ids=capabilities,
            fence=current_fence,
            committed_at=_NOW + timedelta(seconds=7),
        )
        assert not retry.changed
        budget = restarted.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capabilities[0],
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (budget.reserved_uses, budget.committed_uses) == (0, 1)


@pytest.mark.integration
def test_concurrent_stale_and_current_activation_transitions_are_fenced(
    tmp_path: Path,
) -> None:
    path = tmp_path / "concurrent-capability-fence.db"
    context, action, capabilities, stale_fence, current_fence = (
        _prepare_reactivated_chain_with_fences(path)
    )
    operations = ("current",) * 6 + ("stale_commit",) * 3 + ("stale_release",) * 3
    barrier = threading.Barrier(len(operations))

    def transition(operation: str) -> tuple[str, bool | ErrorCode]:
        barrier.wait(timeout=10)
        with SQLiteControlStore(path) as store:
            try:
                if operation == "stale_release":
                    result = store.release_capability_chain(
                        tenant_id=context.tenant_id,
                        goal_id=context.goal_id,
                        run_id=context.run_id,
                        intent_hash=action.intent_hash,
                        capability_ids=capabilities,
                        fence=stale_fence,
                        released_at=_NOW + timedelta(seconds=5),
                    )
                else:
                    result = store.commit_capability_chain(
                        tenant_id=context.tenant_id,
                        goal_id=context.goal_id,
                        run_id=context.run_id,
                        intent_hash=action.intent_hash,
                        capability_ids=capabilities,
                        fence=(stale_fence if operation == "stale_commit" else current_fence),
                        committed_at=_NOW + timedelta(seconds=5),
                    )
            except AgentKernelError as error:
                return operation, error.code
            return operation, result.changed

    with ThreadPoolExecutor(max_workers=len(operations)) as executor:
        results = tuple(executor.map(transition, operations))
    current_results = tuple(value for operation, value in results if operation == "current")
    stale_results = tuple(value for operation, value in results if operation != "current")
    assert current_results.count(True) == 1
    assert current_results.count(False) == len(current_results) - 1
    assert stale_results == (ErrorCode.VERSION_CONFLICT,) * len(stale_results)
    with SQLiteControlStore(path) as reopened:
        budget = reopened.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capabilities[0],
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (budget.reserved_uses, budget.committed_uses) == (0, 1)


@pytest.mark.integration
def test_released_chain_reactivation_accepts_contiguous_multi_hop_no_effect_transfers(
    tmp_path: Path,
) -> None:
    path = tmp_path / "multi-hop-capability-transfer.db"
    context = _context()
    capabilities = ("cap_multi_hop",)
    with SQLiteControlStore(path) as store:
        owner, middle, successor = _put_actions(
            store,
            context,
            ("tx_hop_a", "tx_hop_b", "tx_hop_c"),
            resource_name="multi-hop.txt",
        )
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW,
        )
        _register_budgets(store, context, capabilities, max_uses=1)
        original = store.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW,
        )
        same_owner = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW + timedelta(seconds=1),
        )
        assert same_owner.disposition is IntentDisposition.SAME_TRANSACTION
        alias_middle = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=middle.transaction_id,
            attempted_at=_NOW + timedelta(seconds=2),
        )
        assert alias_middle.disposition is IntentDisposition.ALIAS_ACTIVE
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            expected_version=0,
            state=IntentAttemptState.NO_EFFECT_CONFIRMED,
            evidence_digest=canonical_digest({"no_effect_owner": owner.transaction_id}),
            recorded_at=_NOW + timedelta(seconds=3),
        )
        store.release_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            fence=original.fence,
            released_at=_NOW + timedelta(seconds=4),
        )
        same_after_release = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW + timedelta(seconds=5),
        )
        assert same_after_release.disposition is IntentDisposition.SAME_TRANSACTION
        reviewed_middle = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=middle.transaction_id,
            expected_owner_version=99,
            attempted_at=_NOW + timedelta(seconds=6),
        )
        assert reviewed_middle.disposition is IntentDisposition.REVIEW_REQUIRED
        first_transfer = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=middle.transaction_id,
            expected_owner_version=0,
            attempted_at=_NOW + timedelta(seconds=7),
        )
        assert first_transfer.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT

        same_middle = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=middle.transaction_id,
            attempted_at=_NOW + timedelta(seconds=8),
        )
        assert same_middle.disposition is IntentDisposition.SAME_TRANSACTION
        alias_successor = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=successor.transaction_id,
            attempted_at=_NOW + timedelta(seconds=9),
        )
        assert alias_successor.disposition is IntentDisposition.ALIAS_ACTIVE
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=middle.transaction_id,
            expected_version=0,
            state=IntentAttemptState.NO_EFFECT_CONFIRMED,
            evidence_digest=canonical_digest({"no_effect_owner": middle.transaction_id}),
            recorded_at=_NOW + timedelta(seconds=10),
        )
        reviewed_successor = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=successor.transaction_id,
            expected_owner_version=99,
            attempted_at=_NOW + timedelta(seconds=11),
        )
        assert reviewed_successor.disposition is IntentDisposition.REVIEW_REQUIRED
        second_transfer = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=successor.transaction_id,
            expected_owner_version=1,
            attempted_at=_NOW + timedelta(seconds=12),
        )
        assert second_transfer.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT

    with SQLiteControlStore(path) as reopened:
        reactivated = reopened.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW + timedelta(seconds=13),
        )
        assert reactivated.activation_owner_transaction_id == successor.transaction_id
        assert reactivated.activation_owner_version == 2
        assert reactivated.version == 2
        reopened.commit_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            fence=reactivated.fence,
            committed_at=_NOW + timedelta(seconds=14),
        )
        budget = reopened.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capabilities[0],
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (budget.reserved_uses, budget.committed_uses) == (0, 1)


@pytest.mark.integration
@pytest.mark.parametrize(
    "owner_state",
    [
        IntentAttemptState.RECONCILE_REQUIRED,
        IntentAttemptState.COMMITTED,
        IntentAttemptState.NO_EFFECT_CONFIRMED,
        IntentAttemptState.REVIEW_REQUIRED,
    ],
)
def test_initial_capability_reservation_requires_active_intent_owner(
    tmp_path: Path,
    owner_state: IntentAttemptState,
) -> None:
    path = tmp_path / f"initial-owner-{owner_state.value}.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        (action,) = _put_actions(
            store,
            context,
            ("tx_initial_owner_state",),
            resource_name="initial-owner-state.txt",
        )
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=action.intent_hash,
            transaction_id=action.transaction_id,
            attempted_at=_NOW,
        )
        _register_budgets(store, context, ("cap_initial_owner",), max_uses=1)
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=action.intent_hash,
            transaction_id=action.transaction_id,
            expected_version=0,
            state=owner_state,
            evidence_digest=canonical_digest({"owner_state": owner_state.value}),
            recorded_at=_NOW + timedelta(seconds=1),
        )
        with pytest.raises(AgentKernelError) as rejected:
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=("cap_initial_owner",),
                reserved_at=_NOW + timedelta(seconds=2),
            )
        assert rejected.value.code is ErrorCode.AUTHORITY_MISSING
        budget = store.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id="cap_initial_owner",
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (budget.reserved_uses, budget.committed_uses) == (0, 0)


@pytest.mark.integration
@pytest.mark.parametrize(
    "owner_state",
    [
        IntentAttemptState.RECONCILE_REQUIRED,
        IntentAttemptState.COMMITTED,
        IntentAttemptState.NO_EFFECT_CONFIRMED,
        IntentAttemptState.REVIEW_REQUIRED,
    ],
)
def test_reserved_capability_chain_rejects_non_active_owner_commit(
    tmp_path: Path,
    owner_state: IntentAttemptState,
) -> None:
    path = tmp_path / f"reserved-owner-{owner_state.value}.db"
    context = _context()
    capability_id = "cap_reserved_owner"
    with SQLiteControlStore(path) as store:
        (action,) = _put_actions(
            store,
            context,
            ("tx_reserved_owner_state",),
            resource_name="reserved-owner-state.txt",
        )
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=action.intent_hash,
            transaction_id=action.transaction_id,
            attempted_at=_NOW,
        )
        _register_budgets(store, context, (capability_id,), max_uses=1)
        reserved = store.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=action.intent_hash,
            capability_ids=(capability_id,),
            reserved_at=_NOW,
        )
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=action.intent_hash,
            transaction_id=action.transaction_id,
            expected_version=0,
            state=owner_state,
            evidence_digest=canonical_digest({"owner_state": owner_state.value}),
            recorded_at=_NOW + timedelta(seconds=1),
        )
        with pytest.raises(AgentKernelError) as reserve_retry:
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=(capability_id,),
                reserved_at=_NOW + timedelta(seconds=2),
            )
        assert reserve_retry.value.code is ErrorCode.AUTHORITY_MISSING
        with pytest.raises(AgentKernelError) as commit:
            store.commit_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=(capability_id,),
                fence=reserved.fence,
                committed_at=_NOW + timedelta(seconds=2),
            )
        assert commit.value.code is ErrorCode.ILLEGAL_TRANSITION

        if owner_state is IntentAttemptState.NO_EFFECT_CONFIRMED:
            released = store.release_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=(capability_id,),
                fence=reserved.fence,
                released_at=_NOW + timedelta(seconds=3),
            )
            assert released.state is CapabilityReservationState.RELEASED
            expected_reserved = 0
        else:
            with pytest.raises(AgentKernelError) as release:
                store.release_capability_chain(
                    tenant_id=context.tenant_id,
                    goal_id=context.goal_id,
                    run_id=context.run_id,
                    intent_hash=action.intent_hash,
                    capability_ids=(capability_id,),
                    fence=reserved.fence,
                    released_at=_NOW + timedelta(seconds=3),
                )
            assert release.value.code is ErrorCode.ILLEGAL_TRANSITION
            expected_reserved = 1
        budget = store.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capability_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (budget.reserved_uses, budget.committed_uses) == (expected_reserved, 0)


@pytest.mark.integration
@pytest.mark.parametrize(
    "owner_state",
    [
        IntentAttemptState.RECONCILE_REQUIRED,
        IntentAttemptState.COMMITTED,
        IntentAttemptState.NO_EFFECT_CONFIRMED,
        IntentAttemptState.REVIEW_REQUIRED,
    ],
)
def test_reactivation_requires_final_transferred_owner_to_remain_active(
    tmp_path: Path,
    owner_state: IntentAttemptState,
) -> None:
    path = tmp_path / f"reactivation-final-{owner_state.value}.db"
    context, action, capabilities = _prepare_released_transferred_chain(path)
    with SQLiteControlStore(path) as store:
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=action.intent_hash,
            transaction_id="tx_concurrent_successor",
            expected_version=0,
            state=owner_state,
            evidence_digest=canonical_digest({"final_owner_state": owner_state.value}),
            recorded_at=_NOW + timedelta(seconds=4),
        )
        with pytest.raises(AgentKernelError) as rejected:
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=capabilities,
                reserved_at=_NOW + timedelta(seconds=5),
            )
        assert rejected.value.code is ErrorCode.AUTHORITY_MISSING
        budget = store.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capabilities[0],
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (budget.reserved_uses, budget.committed_uses) == (0, 0)


@pytest.mark.integration
def test_reactivation_rejects_ambiguity_inside_multi_hop_transfer_history(
    tmp_path: Path,
) -> None:
    path = tmp_path / "rejected-ambiguous-transfer.db"
    context = _context()
    capabilities = ("cap_rejected_history",)
    with SQLiteControlStore(path) as store:
        owner, middle, successor = _put_actions(
            store,
            context,
            ("tx_rejected_a", "tx_rejected_b", "tx_rejected_c"),
            resource_name="rejected-transfer.txt",
        )
        store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            attempted_at=_NOW,
        )
        _register_budgets(store, context, capabilities, max_uses=1)
        original = store.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW,
        )
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=owner.transaction_id,
            expected_version=0,
            state=IntentAttemptState.NO_EFFECT_CONFIRMED,
            evidence_digest=canonical_digest({"no_effect": owner.transaction_id}),
            recorded_at=_NOW + timedelta(seconds=1),
        )
        store.release_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=owner.intent_hash,
            capability_ids=capabilities,
            fence=original.fence,
            released_at=_NOW + timedelta(seconds=2),
        )
        first_transfer = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=middle.transaction_id,
            expected_owner_version=0,
            attempted_at=_NOW + timedelta(seconds=3),
        )
        assert first_transfer.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=middle.transaction_id,
            expected_version=0,
            state=IntentAttemptState.RECONCILE_REQUIRED,
            evidence_digest=canonical_digest({"reconcile": "ambiguous"}),
            recorded_at=_NOW + timedelta(seconds=4),
        )
        store.record_intent_attempt_state(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=middle.transaction_id,
            expected_version=1,
            state=IntentAttemptState.NO_EFFECT_CONFIRMED,
            evidence_digest=canonical_digest({"no_effect": middle.transaction_id}),
            recorded_at=_NOW + timedelta(seconds=5),
        )
        second_transfer = store.acquire_intent(
            tenant_id=context.tenant_id,
            intent_hash=owner.intent_hash,
            transaction_id=successor.transaction_id,
            expected_owner_version=1,
            attempted_at=_NOW + timedelta(seconds=6),
        )
        assert second_transfer.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT

        with pytest.raises(AgentKernelError) as rejected:
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=owner.intent_hash,
                capability_ids=capabilities,
                reserved_at=_NOW + timedelta(seconds=7),
            )
        assert rejected.value.code is ErrorCode.AUTHORITY_MISSING
        budget = store.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capabilities[0],
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (budget.reserved_uses, budget.committed_uses) == (0, 0)


@pytest.mark.integration
def test_concurrent_reactivation_reserves_budget_exactly_once(tmp_path: Path) -> None:
    path = tmp_path / "concurrent-reactivation.db"
    context, action, capabilities = _prepare_released_transferred_chain(path)
    workers = 12
    barrier = threading.Barrier(workers)

    def reactivate(_: int) -> bool:
        barrier.wait(timeout=10)
        with SQLiteControlStore(path) as store:
            return store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=capabilities,
                reserved_at=_NOW + timedelta(seconds=4),
            ).changed

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = tuple(executor.map(reactivate, range(workers)))
    assert results.count(True) == 1
    assert results.count(False) == workers - 1
    with SQLiteControlStore(path) as reopened:
        budget = reopened.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id=capabilities[0],
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (budget.reserved_uses, budget.committed_uses) == (1, 0)


@pytest.mark.integration
def test_reactivation_rejects_different_request_and_exhausted_budget(tmp_path: Path) -> None:
    path = tmp_path / "reactivation-exhausted.db"
    context, released_action, capabilities = _prepare_released_transferred_chain(path)
    with SQLiteControlStore(path) as store:
        store.register_capability_budget(
            tenant_id=context.tenant_id,
            capability_id="cap_different",
            goal_id=context.goal_id,
            run_id=context.run_id,
            max_uses=1,
            registered_at=_NOW,
        )
        with pytest.raises(AgentKernelError) as changed_request:
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=released_action.intent_hash,
                capability_ids=("cap_different",),
                reserved_at=_NOW + timedelta(seconds=4),
            )
        assert changed_request.value.code is ErrorCode.INTEGRITY_ERROR

        (competitor,) = _put_actions(
            store,
            context,
            ("tx_budget_competitor",),
            resource_name="budget-competitor.txt",
        )
        store.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=competitor.intent_hash,
            capability_ids=capabilities,
            reserved_at=_NOW + timedelta(seconds=5),
        )
        with pytest.raises(AgentKernelError) as exhausted:
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=released_action.intent_hash,
                capability_ids=capabilities,
                reserved_at=_NOW + timedelta(seconds=6),
            )
        assert exhausted.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
        released = store.get_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=released_action.intent_hash,
        )
        assert released.state is CapabilityReservationState.RELEASED


@pytest.mark.integration
def test_capability_registration_and_chain_validation_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "capability-validation.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        (action,) = _put_actions(store, context, ("tx_cap_validation",))
        with pytest.raises(AgentKernelError) as invalid_max:
            store.register_capability_budget(
                tenant_id=context.tenant_id,
                capability_id="cap_a",
                goal_id=context.goal_id,
                run_id=context.run_id,
                max_uses=0,
                registered_at=_NOW,
            )
        assert invalid_max.value.code is ErrorCode.VALIDATION_ERROR
        store.register_capability_budget(
            tenant_id=context.tenant_id,
            capability_id="cap_a",
            goal_id=context.goal_id,
            run_id=context.run_id,
            max_uses=2,
            registered_at=_NOW,
        )
        with pytest.raises(AgentKernelError) as registration_mismatch:
            store.register_capability_budget(
                tenant_id=context.tenant_id,
                capability_id="cap_a",
                goal_id=context.goal_id,
                run_id=context.run_id,
                max_uses=3,
                registered_at=_NOW,
            )
        assert registration_mismatch.value.code is ErrorCode.INTEGRITY_ERROR

        invalid_chains: tuple[Sequence[str], ...] = (
            (),
            "cap_a",
            ("cap_a", "cap_a"),
            ("cap_b", "cap_a"),
            ("not/a/capability",),
            tuple(f"cap_{index:03}" for index in range(257)),
        )
        for capability_ids in invalid_chains:
            with pytest.raises(AgentKernelError) as invalid_chain:
                store.reserve_capability_chain(
                    tenant_id=context.tenant_id,
                    goal_id=context.goal_id,
                    run_id=context.run_id,
                    intent_hash=action.intent_hash,
                    capability_ids=capability_ids,
                    reserved_at=_NOW,
                )
            assert invalid_chain.value.code in {
                ErrorCode.AUTHORITY_MISSING,
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                ErrorCode.VALIDATION_ERROR,
            }

        with pytest.raises(AgentKernelError) as missing_budget:
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=("cap_missing",),
                reserved_at=_NOW,
            )
        assert missing_budget.value.code is ErrorCode.AUTHORITY_MISSING
        with pytest.raises(AgentKernelError) as missing_reservation:
            store.commit_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=("cap_a",),
                fence=CapabilityReservationFence(
                    reservation_version=0,
                    activation_owner_transaction_id=None,
                    activation_owner_version=None,
                    activation_history_sequence=None,
                    activation_history_digest=None,
                ),
                committed_at=_NOW,
            )
        assert missing_reservation.value.code is ErrorCode.AUTHORITY_MISSING

        unknown_intent = canonical_digest({"unknown": "intent"})
        with pytest.raises(AgentKernelError) as unknown_action:
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=unknown_intent,
                capability_ids=("cap_a",),
                reserved_at=_NOW,
            )
        assert unknown_action.value.code is ErrorCode.AUTHORITY_MISSING


@pytest.mark.integration
def test_capability_chain_conflicting_retry_and_partial_capacity_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "capability-mismatch.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        (first,) = _put_actions(
            store,
            context,
            ("tx_first",),
            resource_name="capacity.txt",
        )
        _register_budgets(store, context, ("cap_a", "cap_b", "cap_c"), max_uses=1)
        store.reserve_capability_chain(
            tenant_id=context.tenant_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            intent_hash=first.intent_hash,
            capability_ids=("cap_a", "cap_b"),
            reserved_at=_NOW,
        )
        with pytest.raises(AgentKernelError) as conflict:
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=first.intent_hash,
                capability_ids=("cap_c",),
                reserved_at=_NOW,
            )
        assert conflict.value.code is ErrorCode.INTEGRITY_ERROR

        second_action = _action(context, "tx_second", resource_name="capacity-two.txt")
        store.put_normalized_action(second_action, recorded_at=_NOW)
        before = store.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id="cap_c",
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        with pytest.raises(AgentKernelError) as exhausted:
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=second_action.intent_hash,
                capability_ids=("cap_b", "cap_c"),
                reserved_at=_NOW,
            )
        assert exhausted.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
        after = store.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id="cap_c",
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert after.reserved_uses == before.reserved_uses == 0


@pytest.mark.integration
def test_capability_chain_rolls_back_all_rows_after_injected_mid_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "capability-rollback.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        (action,) = _put_actions(store, context, ("tx_fault",), resource_name="fault.txt")
        capabilities = ("cap_a", "cap_b")
        _register_budgets(store, context, capabilities, max_uses=1)
        original_execute = store._execute
        injected = False

        def fail_after_first_item(
            statement: str,
            parameters: tuple[object, ...] = (),
        ) -> sqlite3.Cursor:
            nonlocal injected
            cursor = original_execute(statement, parameters)
            if "INSERT INTO enforced_capability_use_reservations" in statement and not injected:
                injected = True
                raise RuntimeError("injected after first reservation item")
            return cursor

        monkeypatch.setattr(store, "_execute", fail_after_first_item)
        with pytest.raises(RuntimeError, match="injected"):
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=capabilities,
                reserved_at=_NOW,
            )
        assert injected
        monkeypatch.setattr(store, "_execute", original_execute)
        with pytest.raises(AgentKernelError) as absent:
            store.get_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
            )
        assert absent.value.code is ErrorCode.AUTHORITY_MISSING
        for capability_id in capabilities:
            budget = store.get_capability_budget(
                tenant_id=context.tenant_id,
                capability_id=capability_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
            )
            assert (budget.reserved_uses, budget.committed_uses) == (0, 0)


@pytest.mark.integration
def test_process_crash_rolls_back_partial_capability_reservation(tmp_path: Path) -> None:
    path = tmp_path / "capability-process-crash.db"
    context = _context()
    capabilities = ("cap_crash_a", "cap_crash_b")
    with SQLiteControlStore(path) as store:
        (action,) = _put_actions(
            store,
            context,
            ("tx_process_crash",),
            resource_name="process-crash.txt",
        )
        _register_budgets(store, context, capabilities, max_uses=1)

    crash_program = textwrap.dedent(
        """
        import os
        import sys
        from datetime import UTC, datetime
        from pathlib import Path

        from agentkernel.storage.control import SQLiteControlStore

        store = SQLiteControlStore(Path(sys.argv[1]))
        original_execute = store._execute

        def crash_after_first_counter(statement, parameters=()):
            cursor = original_execute(statement, parameters)
            if (
                "UPDATE enforced_capability_budgets" in statement
                and "reserved_uses = reserved_uses + 1" in statement
            ):
                os._exit(73)
            return cursor

        store._execute = crash_after_first_counter
        store.reserve_capability_chain(
            tenant_id=sys.argv[2],
            goal_id=sys.argv[3],
            run_id=sys.argv[4],
            intent_hash=sys.argv[5],
            capability_ids=("cap_crash_a", "cap_crash_b"),
            reserved_at=datetime(2026, 7, 22, 12, tzinfo=UTC),
        )
        os._exit(99)
        """
    )
    completed = subprocess.run(  # noqa: S603 - controlled interpreter and test arguments
        [
            sys.executable,
            "-c",
            crash_program,
            str(path),
            context.tenant_id,
            context.goal_id,
            context.run_id,
            action.intent_hash,
        ],
        cwd=Path(__file__).parents[2],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 73, completed.stderr

    with SQLiteControlStore(path) as reopened:
        with pytest.raises(AgentKernelError) as absent:
            reopened.get_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
            )
        assert absent.value.code is ErrorCode.AUTHORITY_MISSING
        for capability_id in capabilities:
            budget = reopened.get_capability_budget(
                tenant_id=context.tenant_id,
                capability_id=capability_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
            )
            assert (budget.reserved_uses, budget.committed_uses) == (0, 0)


@pytest.mark.integration
def test_concurrent_capability_writers_never_exceed_budget(tmp_path: Path) -> None:
    path = tmp_path / "capability-concurrency.db"
    context = _context()
    attempts = 20
    limit = 5
    with SQLiteControlStore(path) as store:
        _register_context(store, context)
        actions = tuple(
            _action(context, f"tx_{index}", resource_name=f"concurrent-{index}.txt")
            for index in range(attempts)
        )
        for action in actions:
            store.put_normalized_action(action, recorded_at=_NOW)
        _register_budgets(store, context, ("cap_shared",), max_uses=limit)

    barrier = threading.Barrier(attempts)

    def reserve(action: NormalizedAction) -> ErrorCode | None:
        barrier.wait(timeout=10)
        with SQLiteControlStore(path) as worker_store:
            try:
                worker_store.reserve_capability_chain(
                    tenant_id=context.tenant_id,
                    goal_id=context.goal_id,
                    run_id=context.run_id,
                    intent_hash=action.intent_hash,
                    capability_ids=("cap_shared",),
                    reserved_at=_NOW,
                )
            except AgentKernelError as error:
                return error.code
            return None

    with ThreadPoolExecutor(max_workers=attempts) as executor:
        results = tuple(executor.map(reserve, actions))
    assert results.count(None) == limit
    assert results.count(ErrorCode.RESOURCE_LIMIT_EXCEEDED) == attempts - limit
    with SQLiteControlStore(path) as reopened:
        budget = reopened.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id="cap_shared",
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert budget.reserved_uses == limit
        assert budget.committed_uses == 0


@pytest.mark.integration
def test_sqlite_write_contention_is_typed_retryable_and_connection_recovers(
    tmp_path: Path,
) -> None:
    path = tmp_path / "typed-contention.db"
    context = _context()
    with SQLiteControlStore(path) as lock_owner, SQLiteControlStore(path) as contender:
        contender._connection.execute("PRAGMA busy_timeout = 1")
        with lock_owner._immediate():
            with pytest.raises(AgentKernelError) as caught:
                contender.register_action_context(context, registered_at=_NOW)

            assert caught.value.code is ErrorCode.EVIDENCE_UNAVAILABLE
            assert caught.value.retryable is True
            assert caught.value.reconcilable is False
            assert caught.value.review_required is False
            assert caught.value.details == {}
            assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
            assert not contender._connection.in_transaction

        contender.register_action_context(context, registered_at=_NOW)


@pytest.mark.integration
def test_non_contention_sqlite_operational_error_is_not_hidden(tmp_path: Path) -> None:
    with SQLiteControlStore(tmp_path / "non-contention.db") as store:
        with pytest.raises(sqlite3.OperationalError) as caught, store._immediate():
            store._connection.execute("SELECT * FROM table_that_does_not_exist")

        assert getattr(caught.value, "sqlite_errorcode", None) == sqlite3.SQLITE_ERROR
        assert not store._connection.in_transaction


@pytest.mark.integration
def test_concurrent_exact_capability_retry_consumes_once(tmp_path: Path) -> None:
    path = tmp_path / "capability-concurrent-retry.db"
    context = _context()
    workers = 12
    with SQLiteControlStore(path) as store:
        (action,) = _put_actions(store, context, ("tx_retry",), resource_name="retry.txt")
        _register_budgets(store, context, ("cap_retry",), max_uses=1)

    barrier = threading.Barrier(workers)

    def reserve(_: int) -> CapabilityReservationState:
        barrier.wait(timeout=10)
        with SQLiteControlStore(path) as worker_store:
            return worker_store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=("cap_retry",),
                reserved_at=_NOW,
            ).state

    with ThreadPoolExecutor(max_workers=workers) as executor:
        assert (
            tuple(executor.map(reserve, range(workers)))
            == (CapabilityReservationState.RESERVED,) * workers
        )
    with SQLiteControlStore(path) as reopened:
        budget = reopened.get_capability_budget(
            tenant_id=context.tenant_id,
            capability_id="cap_retry",
            goal_id=context.goal_id,
            run_id=context.run_id,
        )
        assert (budget.reserved_uses, budget.committed_uses) == (1, 0)


@pytest.mark.integration
def test_capability_budget_isolated_across_tenants_and_restart(tmp_path: Path) -> None:
    path = tmp_path / "capability-tenants.db"
    context_a = _context("tenant_a")
    context_b = _context("tenant_b")
    with SQLiteControlStore(path) as store:
        action_a = _put_actions(store, context_a, ("tx_shared",), resource_name="a.txt")[0]
        action_b = _put_actions(store, context_b, ("tx_shared",), resource_name="b.txt")[0]
        _register_budgets(store, context_a, ("cap_shared",), max_uses=1)
        _register_budgets(store, context_b, ("cap_shared",), max_uses=1)
        for context, action in ((context_a, action_a), (context_b, action_b)):
            store.reserve_capability_chain(
                tenant_id=context.tenant_id,
                goal_id=context.goal_id,
                run_id=context.run_id,
                intent_hash=action.intent_hash,
                capability_ids=("cap_shared",),
                reserved_at=_NOW,
            )

    with SQLiteControlStore(path) as reopened:
        for context in (context_a, context_b):
            budget = reopened.get_capability_budget(
                tenant_id=context.tenant_id,
                capability_id="cap_shared",
                goal_id=context.goal_id,
                run_id=context.run_id,
            )
            assert budget.reserved_uses == 1


@pytest.mark.integration
def test_decision_snapshots_are_bound_immutable_and_tenant_isolated(tmp_path: Path) -> None:
    path = tmp_path / "decisions.db"
    contexts = (_context("tenant_a"), _context("tenant_b"))
    snapshots = []
    with SQLiteControlStore(path) as store:
        for context in contexts:
            action = _put_actions(store, context, ("tx_shared",))[0]
            snapshot = store.append_decision_snapshot(
                tenant_id=context.tenant_id,
                kind=DecisionKind.AUTHORITY,
                decision_id="decision_shared",
                transaction_id=action.transaction_id,
                intent_hash=action.intent_hash,
                decision={"eligible": True, "tenant": context.tenant_id},
                recorded_at=_NOW,
            )
            snapshots.append(snapshot)
            retry = store.append_decision_snapshot(
                tenant_id=context.tenant_id,
                kind=DecisionKind.AUTHORITY,
                decision_id="decision_shared",
                transaction_id=action.transaction_id,
                intent_hash=action.intent_hash,
                decision={"tenant": context.tenant_id, "eligible": True},
                recorded_at=_NOW,
            )
            assert not retry.created
            assert retry.row_digest == snapshot.row_digest
            with pytest.raises(AgentKernelError) as timestamp_mismatch:
                store.append_decision_snapshot(
                    tenant_id=context.tenant_id,
                    kind=DecisionKind.AUTHORITY,
                    decision_id="decision_shared",
                    transaction_id=action.transaction_id,
                    intent_hash=action.intent_hash,
                    decision={"tenant": context.tenant_id, "eligible": True},
                    recorded_at=_NOW + timedelta(seconds=1),
                )
            assert timestamp_mismatch.value.code is ErrorCode.INTEGRITY_ERROR
        assert snapshots[0].decision_digest != snapshots[1].decision_digest
        with pytest.raises(AgentKernelError) as cross_tenant:
            store.get_decision_snapshot(
                tenant_id="tenant_c",
                kind=DecisionKind.AUTHORITY,
                decision_id="decision_shared",
            )
        assert cross_tenant.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as mismatch:
            store.append_decision_snapshot(
                tenant_id=contexts[0].tenant_id,
                kind=DecisionKind.AUTHORITY,
                decision_id="decision_shared",
                transaction_id="tx_shared",
                intent_hash=snapshots[0].intent_hash,
                decision={"eligible": False},
                recorded_at=_NOW,
            )
        assert mismatch.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
def test_decision_snapshot_rejects_nonobjects_and_unknown_action_binding(tmp_path: Path) -> None:
    path = tmp_path / "decision-validation.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        (action,) = _put_actions(store, context, ("tx_decision_validation",))
        with pytest.raises(AgentKernelError) as non_object:
            store.append_decision_snapshot(
                tenant_id=context.tenant_id,
                kind=DecisionKind.AUTHORITY,
                decision_id="decision_non_object",
                transaction_id=action.transaction_id,
                intent_hash=action.intent_hash,
                decision=cast("Mapping[str, object]", ["not", "an", "object"]),
                recorded_at=_NOW,
            )
        assert non_object.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as unsupported_value:
            store.append_decision_snapshot(
                tenant_id=context.tenant_id,
                kind=DecisionKind.AUTHORITY,
                decision_id="decision_unsupported",
                transaction_id=action.transaction_id,
                intent_hash=action.intent_hash,
                decision={"unsupported": object()},
                recorded_at=_NOW,
            )
        assert unsupported_value.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as unknown_action:
            store.append_decision_snapshot(
                tenant_id=context.tenant_id,
                kind=DecisionKind.AUTHORITY,
                decision_id="decision_unknown_action",
                transaction_id="tx_missing",
                intent_hash=action.intent_hash,
                decision={"eligible": False},
                recorded_at=_NOW,
            )
        assert unknown_action.value.code is ErrorCode.VALIDATION_ERROR

        model_snapshot = store.append_decision_snapshot(
            tenant_id=context.tenant_id,
            kind=DecisionKind.POLICY,
            decision_id="decision_model",
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            decision=context,
            recorded_at=_NOW,
        )
        assert model_snapshot.decision["tenant_id"] == context.tenant_id

    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE enforced_decision_snapshots SET decision_json = '{}' "
                "WHERE tenant_id = 'tenant_a'"
            )
    finally:
        connection.close()


@pytest.mark.integration
def test_decision_digest_detects_tampering_after_trigger_bypass(tmp_path: Path) -> None:
    path = tmp_path / "tampered-decision.db"
    context = _context()
    with SQLiteControlStore(path) as store:
        action = _put_actions(store, context, ("tx_decision",))[0]
        store.append_decision_snapshot(
            tenant_id=context.tenant_id,
            kind=DecisionKind.POLICY,
            decision_id="decision_policy",
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            decision={"verdict": "ELIGIBLE"},
            recorded_at=_NOW,
        )

    connection = sqlite3.connect(path)
    try:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
            "AND name = 'enforced_decision_snapshots_no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER enforced_decision_snapshots_no_update")
        connection.execute(
            "UPDATE enforced_decision_snapshots SET decision_json = ? "
            "WHERE tenant_id = ? AND decision_kind = ? AND decision_id = ?",
            (
                '{"verdict":"DENY"}',
                context.tenant_id,
                DecisionKind.POLICY.value,
                "decision_policy",
            ),
        )
        connection.execute(trigger_sql)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as captured:
        SQLiteControlStore(path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
