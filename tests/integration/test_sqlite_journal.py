from __future__ import annotations

import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import agentkernel.storage.sqlite as sqlite_storage
import pytest
from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import TransactionState
from agentkernel.domain.models import TransactionRecord
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.ledger import validate_chain
from agentkernel.storage.sqlite import SQLiteJournal
from agentkernel.transactions.state_machine import TransitionEvent

_FROZEN_MIGRATION_DIGESTS = {
    1: "sha256:c621aaf41e48d6de6b89154575165e8fd19d034e8a48a1d14dd96a12be03041c",
    2: "sha256:18a9e79676b67150c04fd841013de2d48d5c3ae5cc1f2b2a4dc4312edc4d4ef9",
}
_CURRENT_SCHEMA_VERSION = 3
_TEST_MIGRATION_VERSION = _CURRENT_SCHEMA_VERSION + 1
_LEGACY_APPLIED_AT = "2026-01-01T00:00:00.000Z"
_ATOMIC_TEST_MIGRATION = """
CREATE TABLE migration_probe (
    value TEXT PRIMARY KEY
);

INSERT INTO migration_probe(value) VALUES ('created;inside-a-string');

INSERT INTO capability_uses(capability_id, uses, updated_at)
VALUES ('migration-probe', 1, '2026-01-01T00:00:00.000Z');

CREATE INDEX migration_probe_value_idx ON migration_probe(value);
"""
_INVARIANT_BREAKING_MIGRATION = """
CREATE TABLE migration_parent (
    id INTEGER PRIMARY KEY
);

CREATE TABLE migration_child (
    parent_id INTEGER NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES migration_parent(id) DEFERRABLE INITIALLY DEFERRED
);

INSERT INTO migration_child(parent_id) VALUES (404);
"""
_MISSING_FOREIGN_KEY_TARGET_MIGRATION = """
CREATE TABLE dangling_foreign_key (
    parent_id INTEGER REFERENCES missing_parent(id)
);
"""


def _create_legacy_fixture(path: Path, version: int, record: TransactionRecord) -> None:
    connection = sqlite3.connect(path)
    try:
        for migration_version, sql in sqlite_storage.MIGRATIONS:
            if migration_version > version:
                continue
            digest = canonical_digest({"version": migration_version, "sql": sql})
            assert digest == _FROZEN_MIGRATION_DIGESTS[migration_version]
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, digest, applied_at) VALUES (?, ?, ?)",
                (migration_version, digest, _LEGACY_APPLIED_AT),
            )
        connection.execute(
            "INSERT INTO transactions(transaction_id, goal_id, state, version, intent_hash, "
            "intended_outcome, record_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                record.transaction_id,
                record.goal_id,
                record.state.value,
                record.version,
                record.intent_hash,
                record.intended_outcome.value if record.intended_outcome else None,
                record.model_dump_json(),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _database_dump(path: Path) -> tuple[str, ...]:
    connection = sqlite3.connect(path)
    try:
        return tuple(connection.iterdump())
    finally:
        connection.close()


def _copy_legacy_fixture(
    tmp_path: Path,
    *,
    version: int,
    record: TransactionRecord,
) -> Path:
    source = tmp_path / f"journal-v{version}.fixture.db"
    candidate = tmp_path / "journal.db"
    _create_legacy_fixture(source, version, record)
    shutil.copy2(source, candidate)
    return candidate


def _create_current_fixture(path: Path, record: TransactionRecord) -> None:
    with SQLiteJournal(path) as journal:
        journal.create_transaction(
            record,
            run_id="run_migration_fixture",
            actor="service:test",
            on_behalf_of="principal:test",
        )


@pytest.mark.integration
def test_wal_migrations_and_records_survive_reopen(tmp_path: Path, now: datetime) -> None:
    path = tmp_path / "journal.db"
    record = TransactionRecord(
        transaction_id="tx_persist",
        goal_id="goal_demo",
        created_at=now,
        updated_at=now,
    )
    with SQLiteJournal(path) as journal:
        assert journal.journal_mode == "wal"
        assert journal.schema_version() == _CURRENT_SCHEMA_VERSION
        journal.create_transaction(
            record,
            run_id="run_persist",
            actor="service:test",
            on_behalf_of="principal:test",
        )

    with SQLiteJournal(path) as reopened:
        assert reopened.get_transaction("tx_persist") == record
        assert validate_chain(reopened.list_events("run_persist")).valid
        assert reopened.schema_version() == _CURRENT_SCHEMA_VERSION


@pytest.mark.integration
@pytest.mark.parametrize(
    "drift_sql",
    [
        "DROP TRIGGER enforced_normalized_actions_no_update;",
        "DROP INDEX enforced_normalized_actions_intent_idx;",
        "DROP TABLE enforced_decision_snapshots;",
        "CREATE TABLE rogue_security_shadow (tenant_id TEXT);",
        """
        DROP TABLE capability_uses;
        CREATE TABLE capability_uses (
            capability_id TEXT PRIMARY KEY,
            uses INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );
        """,
        """
        DROP TABLE intents;
        CREATE TABLE intents (
            intent_hash TEXT PRIMARY KEY,
            transaction_id TEXT NOT NULL,
            reserved_at TEXT NOT NULL
        );
        """,
        """
        DROP TABLE receipts;
        CREATE TABLE receipts (
            receipt_id TEXT PRIMARY KEY,
            transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
            receipt_json TEXT,
            created_at TEXT NOT NULL
        );
        """,
    ],
    ids=[
        "missing-trigger",
        "missing-index",
        "missing-table",
        "unexpected-table",
        "weakened-check",
        "weakened-foreign-key",
        "weakened-not-null-column",
    ],
)
def test_live_schema_drift_is_rejected_with_unchanged_markers(
    tmp_path: Path,
    drift_sql: str,
) -> None:
    path = tmp_path / "schema-drift.db"
    with SQLiteJournal(path):
        pass
    connection = sqlite3.connect(path)
    try:
        markers_before = tuple(
            connection.execute(
                "SELECT version, digest FROM schema_migrations ORDER BY version"
            ).fetchall()
        )
        connection.executescript(drift_sql)
        markers_after = tuple(
            connection.execute(
                "SELECT version, digest FROM schema_migrations ORDER BY version"
            ).fetchall()
        )
    finally:
        connection.close()
    assert markers_after == markers_before

    with pytest.raises(AgentKernelError) as captured:
        SQLiteJournal(path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
def test_foreign_key_check_runs_on_reopen_without_pending_migrations(tmp_path: Path) -> None:
    path = tmp_path / "foreign-key-drift.db"
    with SQLiteJournal(path):
        pass
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            "INSERT INTO receipts(receipt_id, transaction_id, receipt_json, created_at) "
            "VALUES ('receipt_orphan', 'tx_missing', '{}', '2026-01-01T00:00:00.000Z')"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as captured:
        SQLiteJournal(path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    assert captured.value.details["table"] == "receipts"


@pytest.mark.integration
@pytest.mark.parametrize("legacy_version", [1, 2])
def test_real_legacy_fixture_upgrades_without_changing_existing_content(
    tmp_path: Path,
    now: datetime,
    legacy_version: int,
) -> None:
    record = TransactionRecord(
        transaction_id="tx_legacy",
        goal_id="goal_legacy",
        created_at=now,
        updated_at=now,
    )
    path = _copy_legacy_fixture(tmp_path, version=legacy_version, record=record)

    with SQLiteJournal(path) as journal:
        assert journal.schema_version() == _CURRENT_SCHEMA_VERSION
        assert journal.get_transaction(record.transaction_id) == record

    connection = sqlite3.connect(path)
    try:
        applied = tuple(
            connection.execute(
                "SELECT version, digest FROM schema_migrations ORDER BY version"
            ).fetchall()
        )
        capability_table = connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'capability_uses'"
        ).fetchone()
    finally:
        connection.close()
    expected_applied = tuple(
        (version, canonical_digest({"version": version, "sql": sql}))
        for version, sql in sqlite_storage.MIGRATIONS
    )
    assert applied == expected_applied
    assert applied[:2] == tuple(_FROZEN_MIGRATION_DIGESTS.items())
    assert capability_table is not None


@pytest.mark.integration
@pytest.mark.parametrize("legacy_version", [1, 2])
def test_existing_schema_with_deleted_migration_ledger_is_rejected(
    tmp_path: Path,
    now: datetime,
    legacy_version: int,
) -> None:
    record = TransactionRecord(
        transaction_id="tx_missing_migration_provenance",
        goal_id="goal_missing_migration_provenance",
        created_at=now,
        updated_at=now,
    )
    path = _copy_legacy_fixture(tmp_path, version=legacy_version, record=record)
    connection = sqlite3.connect(path)
    try:
        connection.execute("DELETE FROM schema_migrations")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as captured:
        SQLiteJournal(path)

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.integration
@pytest.mark.parametrize(
    "failure_point",
    [1, 2, 3, 4, "before-marker"],
    ids=[
        "after-create-table",
        "after-first-insert",
        "after-second-insert",
        "after-create-index",
        "before-marker",
    ],
)
def test_migration_failure_rolls_back_every_statement_and_retries_cleanly(
    tmp_path: Path,
    now: datetime,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: int | str,
) -> None:
    record = TransactionRecord(
        transaction_id="tx_atomic",
        goal_id="goal_atomic",
        created_at=now,
        updated_at=now,
    )
    path = tmp_path / "journal.db"
    _create_current_fixture(path, record)
    before = _database_dump(path)
    monkeypatch.setattr(
        sqlite_storage,
        "MIGRATIONS",
        (*sqlite_storage.MIGRATIONS, (_TEST_MIGRATION_VERSION, _ATOMIC_TEST_MIGRATION)),
    )
    original_execute = SQLiteJournal._execute_migration_statement
    statement_count = 0
    injected = False

    def fail_once(
        journal: SQLiteJournal,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> None:
        nonlocal injected, statement_count
        is_test_marker = (
            statement == sqlite_storage._MIGRATION_MARKER_SQL
            and parameters[0] == _TEST_MIGRATION_VERSION
        )
        if failure_point == "before-marker" and is_test_marker and not injected:
            injected = True
            raise RuntimeError("injected immediately before migration marker")
        original_execute(journal, statement, parameters)
        if not is_test_marker:
            statement_count += 1
            if statement_count == failure_point and not injected:
                injected = True
                raise RuntimeError("injected after migration statement")

    monkeypatch.setattr(SQLiteJournal, "_execute_migration_statement", fail_once)

    with pytest.raises(RuntimeError, match="injected"):
        SQLiteJournal(path)

    assert injected
    assert _database_dump(path) == before

    with SQLiteJournal(path) as retried:
        assert retried.schema_version() == _TEST_MIGRATION_VERSION
    with SQLiteJournal(path) as reopened:
        assert reopened.schema_version() == _TEST_MIGRATION_VERSION

    connection = sqlite3.connect(path)
    try:
        probe_values = tuple(
            row[0] for row in connection.execute("SELECT value FROM migration_probe").fetchall()
        )
        capability_uses = tuple(
            connection.execute(
                "SELECT capability_id, uses FROM capability_uses ORDER BY capability_id"
            ).fetchall()
        )
    finally:
        connection.close()
    assert probe_values == ("created;inside-a-string",)
    assert capability_uses == (("migration-probe", 1),)


@pytest.mark.integration
def test_failed_first_migration_rolls_back_schema_bootstrap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "journal.db"
    original_execute = SQLiteJournal._execute_migration_statement
    injected = False

    def fail_once(
        journal: SQLiteJournal,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> None:
        nonlocal injected
        original_execute(journal, statement, parameters)
        if not injected:
            injected = True
            raise RuntimeError("injected after first migration statement")

    monkeypatch.setattr(SQLiteJournal, "_execute_migration_statement", fail_once)

    with pytest.raises(RuntimeError, match="injected"):
        SQLiteJournal(path)

    connection = sqlite3.connect(path)
    try:
        objects = tuple(
            connection.execute(
                "SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
        )
    finally:
        connection.close()
    assert objects == ()

    with SQLiteJournal(path) as retried:
        assert retried.schema_version() == _CURRENT_SCHEMA_VERSION


@pytest.mark.integration
def test_applied_migration_digest_mismatch_fails_before_pending_upgrade(
    tmp_path: Path,
    now: datetime,
) -> None:
    record = TransactionRecord(
        transaction_id="tx_digest",
        goal_id="goal_digest",
        created_at=now,
        updated_at=now,
    )
    path = _copy_legacy_fixture(tmp_path, version=1, record=record)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE schema_migrations SET digest = ? WHERE version = 1",
            ("sha256:" + "0" * 64,),
        )
        connection.commit()
    finally:
        connection.close()
    before = _database_dump(path)

    with pytest.raises(AgentKernelError) as captured:
        SQLiteJournal(path)

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    assert captured.value.details == {"version": 1}
    assert _database_dump(path) == before
    connection = sqlite3.connect(path)
    try:
        capability_table = connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'capability_uses'"
        ).fetchone()
    finally:
        connection.close()
    assert capability_table is None


@pytest.mark.integration
@pytest.mark.parametrize(
    ("invalid_sql", "message"),
    [
        (
            "CREATE TABLE rejected_migration (id INTEGER); "
            "INSERT INTO rejected_migration(id) VALUES (",
            "incomplete",
        ),
        (
            "-- transaction control must not be embedded\n"
            "BEGIN EXCLUSIVE;\n"
            "CREATE TABLE rejected_migration (id INTEGER);\n"
            "COMMIT;",
            "transaction-control",
        ),
    ],
    ids=["incomplete", "transaction-control"],
)
def test_invalid_migration_sql_is_rejected_without_database_changes(
    tmp_path: Path,
    now: datetime,
    monkeypatch: pytest.MonkeyPatch,
    invalid_sql: str,
    message: str,
) -> None:
    record = TransactionRecord(
        transaction_id="tx_invalid_migration",
        goal_id="goal_invalid_migration",
        created_at=now,
        updated_at=now,
    )
    path = _copy_legacy_fixture(tmp_path, version=2, record=record)
    before = _database_dump(path)
    monkeypatch.setattr(
        sqlite_storage,
        "MIGRATIONS",
        (*sqlite_storage.MIGRATIONS, (_TEST_MIGRATION_VERSION, invalid_sql)),
    )

    with pytest.raises(AgentKernelError, match=message) as captured:
        SQLiteJournal(path)

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    assert _database_dump(path) == before


@pytest.mark.integration
def test_migration_invariants_are_checked_before_the_marker(
    tmp_path: Path,
    now: datetime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = TransactionRecord(
        transaction_id="tx_invariant",
        goal_id="goal_invariant",
        created_at=now,
        updated_at=now,
    )
    path = _copy_legacy_fixture(tmp_path, version=2, record=record)
    before = _database_dump(path)
    monkeypatch.setattr(
        sqlite_storage,
        "MIGRATIONS",
        (*sqlite_storage.MIGRATIONS, (_TEST_MIGRATION_VERSION, _INVARIANT_BREAKING_MIGRATION)),
    )

    with pytest.raises(AgentKernelError, match="foreign-key invariant") as captured:
        SQLiteJournal(path)

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    assert _database_dump(path) == before


@pytest.mark.integration
def test_missing_foreign_key_target_is_rejected_before_the_marker(
    tmp_path: Path,
    now: datetime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = TransactionRecord(
        transaction_id="tx_missing_parent",
        goal_id="goal_missing_parent",
        created_at=now,
        updated_at=now,
    )
    path = _copy_legacy_fixture(tmp_path, version=2, record=record)
    before = _database_dump(path)
    monkeypatch.setattr(
        sqlite_storage,
        "MIGRATIONS",
        (
            *sqlite_storage.MIGRATIONS,
            (_TEST_MIGRATION_VERSION, _MISSING_FOREIGN_KEY_TARGET_MIGRATION),
        ),
    )

    with pytest.raises(AgentKernelError, match="foreign key to a missing table") as captured:
        SQLiteJournal(path)

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    assert captured.value.details == {
        "version": _TEST_MIGRATION_VERSION,
        "table": "dangling_foreign_key",
        "referenced_table": "missing_parent",
    }
    assert _database_dump(path) == before


@pytest.mark.integration
def test_compare_and_swap_rejects_stale_writer(
    tmp_path: Path, transaction: TransactionRecord
) -> None:
    with SQLiteJournal(tmp_path / "journal.db") as journal:
        journal.create_transaction(
            transaction,
            run_id="run_cas",
            actor="service:test",
            on_behalf_of="principal:test",
        )
        updated, _ = journal.transition(
            transaction.transaction_id,
            expected_version=0,
            transition_event=TransitionEvent.PROPOSAL_VALID,
            now=transaction.updated_at,
            run_id="run_cas",
            actor="service:test",
            on_behalf_of="principal:test",
        )
        assert updated.version == 1
        assert updated.state is TransactionState.PLANNED
        with pytest.raises(AgentKernelError) as captured:
            journal.transition(
                transaction.transaction_id,
                expected_version=0,
                transition_event=TransitionEvent.PROPOSAL_VALID,
                now=transaction.updated_at,
                run_id="run_cas",
                actor="service:test",
                on_behalf_of="principal:test",
            )
        assert captured.value.code is ErrorCode.VERSION_CONFLICT


@pytest.mark.integration
def test_intent_reservation_has_one_owner(tmp_path: Path, now: datetime) -> None:
    digest = "sha256:" + "a" * 64
    first = TransactionRecord(
        transaction_id="tx_first",
        goal_id="goal_demo",
        created_at=now,
        updated_at=now,
    )
    second = first.model_copy(update={"transaction_id": "tx_second"})
    with SQLiteJournal(tmp_path / "journal.db") as journal:
        for record in (first, second):
            journal.create_transaction(
                record,
                run_id="run_intent",
                actor="service:test",
                on_behalf_of="principal:test",
            )
        created = journal.reserve_intent(
            intent_hash=digest,
            transaction_id=first.transaction_id,
            reserved_at=now,
        )
        duplicate = journal.reserve_intent(
            intent_hash=digest,
            transaction_id=second.transaction_id,
            reserved_at=now,
        )
        assert created.created
        assert not duplicate.created
        assert duplicate.transaction_id == first.transaction_id


@pytest.mark.integration
def test_non_terminal_query_excludes_committed(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    pending = TransactionRecord(
        transaction_id="tx_pending",
        goal_id="goal_demo",
        created_at=now,
        updated_at=now,
    )
    committed = pending.model_copy(
        update={"transaction_id": "tx_committed", "state": TransactionState.COMMITTED}
    )
    with SQLiteJournal(tmp_path / "journal.db") as journal:
        for record in (pending, committed):
            journal.create_transaction(
                record,
                run_id="run_states",
                actor="service:test",
                on_behalf_of="principal:test",
            )
        assert journal.list_non_terminal() == (pending,)
