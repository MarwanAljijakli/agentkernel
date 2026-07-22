"""Single-node SQLite WAL transaction journal and event store."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import JsonValue

from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import TERMINAL_TRANSACTION_STATES
from agentkernel.domain.models import EffectReceipt, EventEnvelope, TransactionRecord
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.ledger import make_event
from agentkernel.transactions.state_machine import TransitionEvent, apply_transition

_INITIAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    digest TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    transaction_id TEXT PRIMARY KEY,
    goal_id TEXT NOT NULL,
    state TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 0),
    intent_hash TEXT,
    intended_outcome TEXT,
    record_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS transactions_state_idx ON transactions(state);

CREATE TABLE IF NOT EXISTS intents (
    intent_hash TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    reserved_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    receipt_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    event_id TEXT NOT NULL UNIQUE,
    transaction_id TEXT,
    event_hash TEXT NOT NULL,
    previous_event_hash TEXT,
    event_json TEXT NOT NULL,
    PRIMARY KEY (run_id, sequence)
);
"""

MIGRATIONS: tuple[tuple[int, str], ...] = ((1, _INITIAL_SCHEMA),)

_CAPABILITY_USE_SCHEMA = """
CREATE TABLE IF NOT EXISTS capability_uses (
    capability_id TEXT PRIMARY KEY,
    uses INTEGER NOT NULL CHECK (uses >= 0),
    updated_at TEXT NOT NULL
);
"""

MIGRATIONS = (*MIGRATIONS, (2, _CAPABILITY_USE_SCHEMA))

_ENFORCED_CONTROL_SCHEMA = """
CREATE TABLE enforced_tenants (
    tenant_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id)
);

CREATE TABLE enforced_principals (
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, principal_id),
    FOREIGN KEY (tenant_id) REFERENCES enforced_tenants(tenant_id)
);

CREATE TABLE enforced_goals (
    tenant_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, goal_id),
    UNIQUE (tenant_id, principal_id, goal_id),
    FOREIGN KEY (tenant_id, principal_id)
        REFERENCES enforced_principals(tenant_id, principal_id)
);

CREATE TABLE enforced_runs (
    tenant_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    UNIQUE (tenant_id, goal_id, run_id),
    UNIQUE (tenant_id, principal_id, goal_id, run_id),
    FOREIGN KEY (tenant_id, principal_id, goal_id)
        REFERENCES enforced_goals(tenant_id, principal_id, goal_id)
);

CREATE TABLE enforced_normalized_actions (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    action_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id),
    UNIQUE (tenant_id, transaction_id, intent_hash),
    FOREIGN KEY (tenant_id, principal_id, goal_id, run_id)
        REFERENCES enforced_runs(tenant_id, principal_id, goal_id, run_id)
);

CREATE INDEX enforced_normalized_actions_intent_idx
    ON enforced_normalized_actions(tenant_id, intent_hash);

CREATE TABLE enforced_resource_uses (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    canonical_resource TEXT NOT NULL,
    resource_use_digest TEXT NOT NULL,
    resource_use_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, ordinal),
    UNIQUE (tenant_id, transaction_id, resource_use_digest),
    FOREIGN KEY (tenant_id, transaction_id)
        REFERENCES enforced_normalized_actions(tenant_id, transaction_id)
);

CREATE INDEX enforced_resource_uses_resource_idx
    ON enforced_resource_uses(tenant_id, canonical_resource);

CREATE TABLE enforced_intent_owners (
    tenant_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    owner_transaction_id TEXT NOT NULL,
    owner_version INTEGER NOT NULL CHECK (owner_version >= 0),
    history_head_sequence INTEGER NOT NULL DEFAULT -1 CHECK (history_head_sequence >= -1),
    history_head_digest TEXT,
    acquired_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, intent_hash),
    FOREIGN KEY (tenant_id, owner_transaction_id, intent_hash)
        REFERENCES enforced_normalized_actions(tenant_id, transaction_id, intent_hash),
    CHECK (
        (history_head_sequence = -1 AND history_head_digest IS NULL)
        OR (history_head_sequence >= 0 AND history_head_digest IS NOT NULL)
    )
);

CREATE TABLE enforced_intent_attempts (
    tenant_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    attempt_state TEXT NOT NULL CHECK (
        attempt_state IN (
            'ACTIVE',
            'RECONCILE_REQUIRED',
            'COMMITTED',
            'NO_EFFECT_CONFIRMED',
            'REVIEW_REQUIRED'
        )
    ),
    state_version INTEGER NOT NULL CHECK (state_version >= 0),
    evidence_digest TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, intent_hash, transaction_id),
    FOREIGN KEY (tenant_id, transaction_id, intent_hash)
        REFERENCES enforced_normalized_actions(tenant_id, transaction_id, intent_hash)
);

CREATE TABLE enforced_intent_attempt_history (
    tenant_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    transaction_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('ACQUIRE', 'STATE_CHANGED')),
    disposition TEXT CHECK (
        disposition IS NULL OR disposition IN (
            'ACQUIRED',
            'SAME_TRANSACTION',
            'ALIAS_ACTIVE',
            'ALIAS_RECONCILE',
            'ALIAS_COMMITTED',
            'TRANSFERRED_NO_EFFECT',
            'REVIEW_REQUIRED'
        )
    ),
    attempt_state TEXT NOT NULL,
    owner_transaction_id TEXT NOT NULL,
    owner_version INTEGER NOT NULL CHECK (owner_version >= 0),
    evidence_digest TEXT,
    previous_history_digest TEXT,
    history_digest TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, intent_hash, sequence),
    UNIQUE (tenant_id, intent_hash, history_digest),
    FOREIGN KEY (tenant_id, intent_hash)
        REFERENCES enforced_intent_owners(tenant_id, intent_hash),
    FOREIGN KEY (tenant_id, intent_hash, transaction_id)
        REFERENCES enforced_intent_attempts(tenant_id, intent_hash, transaction_id)
);

CREATE TABLE enforced_capability_budgets (
    tenant_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    max_uses INTEGER NOT NULL CHECK (max_uses > 0),
    reserved_uses INTEGER NOT NULL DEFAULT 0 CHECK (reserved_uses >= 0),
    committed_uses INTEGER NOT NULL DEFAULT 0 CHECK (committed_uses >= 0),
    version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    registration_digest TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, capability_id, goal_id, run_id),
    FOREIGN KEY (tenant_id, goal_id, run_id)
        REFERENCES enforced_runs(tenant_id, goal_id, run_id),
    CHECK (reserved_uses + committed_uses <= max_uses)
);

CREATE TABLE enforced_capability_chain_reservations (
    tenant_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    reservation_state TEXT NOT NULL CHECK (
        reservation_state IN ('RESERVED', 'COMMITTED', 'RELEASED')
    ),
    activation_owner_transaction_id TEXT,
    activation_owner_version INTEGER CHECK (activation_owner_version >= 0),
    activation_history_sequence INTEGER CHECK (activation_history_sequence >= 0),
    activation_history_digest TEXT,
    release_history_sequence INTEGER CHECK (release_history_sequence >= 0),
    release_history_digest TEXT,
    version INTEGER NOT NULL CHECK (version >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, goal_id, run_id, intent_hash),
    FOREIGN KEY (tenant_id, goal_id, run_id)
        REFERENCES enforced_runs(tenant_id, goal_id, run_id),
    FOREIGN KEY (tenant_id, intent_hash, activation_owner_transaction_id)
        REFERENCES enforced_intent_attempts(tenant_id, intent_hash, transaction_id),
    CHECK (
        (activation_owner_transaction_id IS NULL
            AND activation_owner_version IS NULL
            AND activation_history_sequence IS NULL
            AND activation_history_digest IS NULL)
        OR (activation_owner_transaction_id IS NOT NULL
            AND activation_owner_version IS NOT NULL
            AND activation_history_sequence IS NOT NULL
            AND activation_history_digest IS NOT NULL)
    ),
    CHECK (
        (release_history_sequence IS NULL AND release_history_digest IS NULL)
        OR (release_history_sequence IS NOT NULL AND release_history_digest IS NOT NULL)
    ),
    CHECK (
        reservation_state = 'RELEASED'
        OR (release_history_sequence IS NULL AND release_history_digest IS NULL)
    )
);

CREATE TABLE enforced_capability_use_reservations (
    tenant_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    chain_ordinal INTEGER NOT NULL CHECK (chain_ordinal >= 0),
    request_digest TEXT NOT NULL,
    reservation_state TEXT NOT NULL CHECK (
        reservation_state IN ('RESERVED', 'COMMITTED', 'RELEASED')
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, capability_id, goal_id, run_id, intent_hash),
    UNIQUE (tenant_id, goal_id, run_id, intent_hash, chain_ordinal),
    FOREIGN KEY (tenant_id, capability_id, goal_id, run_id)
        REFERENCES enforced_capability_budgets(tenant_id, capability_id, goal_id, run_id),
    FOREIGN KEY (tenant_id, goal_id, run_id, intent_hash)
        REFERENCES enforced_capability_chain_reservations(tenant_id, goal_id, run_id, intent_hash)
);

CREATE TABLE enforced_decision_snapshots (
    tenant_id TEXT NOT NULL,
    decision_kind TEXT NOT NULL CHECK (decision_kind IN ('AUTHORITY', 'POLICY')),
    decision_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    decision_digest TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, decision_kind, decision_id),
    UNIQUE (tenant_id, decision_kind, decision_digest),
    FOREIGN KEY (tenant_id, transaction_id, intent_hash)
        REFERENCES enforced_normalized_actions(tenant_id, transaction_id, intent_hash)
);

CREATE INDEX enforced_decision_snapshots_transaction_idx
    ON enforced_decision_snapshots(tenant_id, transaction_id, decision_kind);

CREATE TRIGGER enforced_normalized_actions_no_update
BEFORE UPDATE ON enforced_normalized_actions
BEGIN
    SELECT RAISE(ABORT, 'enforced normalized actions are immutable');
END;

CREATE TRIGGER enforced_normalized_actions_no_delete
BEFORE DELETE ON enforced_normalized_actions
BEGIN
    SELECT RAISE(ABORT, 'enforced normalized actions are immutable');
END;

CREATE TRIGGER enforced_resource_uses_no_update
BEFORE UPDATE ON enforced_resource_uses
BEGIN
    SELECT RAISE(ABORT, 'enforced resource uses are immutable');
END;

CREATE TRIGGER enforced_resource_uses_no_delete
BEFORE DELETE ON enforced_resource_uses
BEGIN
    SELECT RAISE(ABORT, 'enforced resource uses are immutable');
END;

CREATE TRIGGER enforced_intent_history_no_update
BEFORE UPDATE ON enforced_intent_attempt_history
BEGIN
    SELECT RAISE(ABORT, 'enforced intent history is immutable');
END;

CREATE TRIGGER enforced_intent_history_no_delete
BEFORE DELETE ON enforced_intent_attempt_history
BEGIN
    SELECT RAISE(ABORT, 'enforced intent history is immutable');
END;

CREATE TRIGGER enforced_decision_snapshots_no_update
BEFORE UPDATE ON enforced_decision_snapshots
BEGIN
    SELECT RAISE(ABORT, 'enforced decision snapshots are immutable');
END;

CREATE TRIGGER enforced_decision_snapshots_no_delete
BEFORE DELETE ON enforced_decision_snapshots
BEGIN
    SELECT RAISE(ABORT, 'enforced decision snapshots are immutable');
END;

CREATE TRIGGER enforced_capability_budget_binding_immutable
BEFORE UPDATE ON enforced_capability_budgets
WHEN NEW.tenant_id != OLD.tenant_id
    OR NEW.capability_id != OLD.capability_id
    OR NEW.goal_id != OLD.goal_id
    OR NEW.run_id != OLD.run_id
    OR NEW.max_uses != OLD.max_uses
    OR NEW.registration_digest != OLD.registration_digest
    OR NEW.registered_at != OLD.registered_at
BEGIN
    SELECT RAISE(ABORT, 'enforced capability budget binding is immutable');
END;
"""

MIGRATIONS = (*MIGRATIONS, (3, _ENFORCED_CONTROL_SCHEMA))

_SCHEMA_MIGRATIONS_BOOTSTRAP = (
    "CREATE TABLE IF NOT EXISTS schema_migrations "
    "(version INTEGER PRIMARY KEY, digest TEXT NOT NULL, applied_at TEXT NOT NULL)"
)
_MIGRATION_MARKER_SQL = (
    "INSERT INTO schema_migrations(version, digest, applied_at) "
    "VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"
)
_TRANSACTION_CONTROL_KEYWORDS = frozenset(
    {"BEGIN", "COMMIT", "END", "RELEASE", "ROLLBACK", "SAVEPOINT"}
)


@dataclass(frozen=True, slots=True)
class _PreparedMigration:
    version: int
    digest: str
    statements: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _SchemaObject:
    object_type: str
    name: str
    table_name: str
    create_sql: str | None
    columns: tuple[tuple[int, str, str, int, str | None, int, int], ...] = ()
    foreign_keys: tuple[tuple[int, int, str, str, str | None, str, str, str], ...] = ()
    table_flags: tuple[int, int, int] | None = None
    index_properties: tuple[int, str, int] | None = None
    index_columns: tuple[tuple[int, int, str | None, int, str, int], ...] = ()

    def fingerprint_material(self) -> dict[str, object]:
        return {
            "object_type": self.object_type,
            "name": self.name,
            "table_name": self.table_name,
            "create_sql": self.create_sql,
            "columns": self.columns,
            "foreign_keys": self.foreign_keys,
            "table_flags": self.table_flags,
            "index_properties": self.index_properties,
            "index_columns": self.index_columns,
        }


def _skip_sql_trivia(sql: str) -> tuple[int, bool]:
    """Return the first non-comment position and whether block comments are complete."""

    position = 0
    while position < len(sql):
        if sql[position].isspace():
            position += 1
            continue
        if sql.startswith("--", position):
            newline = sql.find("\n", position + 2)
            if newline == -1:
                return len(sql), True
            position = newline + 1
            continue
        if sql.startswith("/*", position):
            comment_end = sql.find("*/", position + 2)
            if comment_end == -1:
                return len(sql), False
            position = comment_end + 2
            continue
        break
    return position, True


def _leading_sql_keyword(statement: str) -> str | None:
    position, comments_complete = _skip_sql_trivia(statement)
    if not comments_complete:
        return None
    keyword_end = position
    while keyword_end < len(statement) and statement[keyword_end].isalpha():
        keyword_end += 1
    if keyword_end == position:
        return None
    return statement[position:keyword_end].upper()


def _split_migration_sql(version: int, sql: str) -> tuple[str, ...]:
    """Split one migration deterministically and reject unsafe or incomplete SQL."""

    statements: list[str] = []
    pending: list[str] = []
    for character in sql:
        pending.append(character)
        if character != ";":
            continue
        candidate = "".join(pending)
        if not sqlite3.complete_statement(candidate):
            continue
        keyword = _leading_sql_keyword(candidate)
        if keyword is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Migration contains an invalid SQL statement",
                details={"version": version, "statement": len(statements) + 1},
            )
        if keyword in _TRANSACTION_CONTROL_KEYWORDS:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Migration contains transaction-control SQL",
                details={"version": version, "statement": len(statements) + 1},
            )
        statements.append(candidate.strip())
        pending.clear()

    remainder = "".join(pending)
    remainder_position, comments_complete = _skip_sql_trivia(remainder)
    if not comments_complete or remainder_position != len(remainder):
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Migration SQL is incomplete",
            details={"version": version, "statement": len(statements) + 1},
        )
    if not statements:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Migration does not contain an SQL statement",
            details={"version": version},
        )
    return tuple(statements)


def _prepare_migrations() -> tuple[_PreparedMigration, ...]:
    prepared: list[_PreparedMigration] = []
    previous_version = 0
    for version, sql in MIGRATIONS:
        if version <= previous_version:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Migration versions must be positive and strictly increasing",
                details={"version": version},
            )
        prepared.append(
            _PreparedMigration(
                version=version,
                digest=canonical_digest({"version": version, "sql": sql}),
                statements=_split_migration_sql(version, sql),
            )
        )
        previous_version = version
    return tuple(prepared)


def _canonical_schema_sql(sql: object) -> str | None:
    """Normalize insignificant whitespace while preserving every SQL token and literal."""

    if sql is None:
        return None
    source = str(sql).strip()
    rendered: list[str] = []
    quote_end: str | None = None
    pending_space = False
    position = 0
    while position < len(source):
        character = source[position]
        if quote_end is not None:
            rendered.append(character)
            if character == quote_end:
                if (
                    quote_end != "]"
                    and position + 1 < len(source)
                    and source[position + 1] == quote_end
                ):
                    rendered.append(source[position + 1])
                    position += 2
                    continue
                quote_end = None
            position += 1
            continue
        if character.isspace():
            pending_space = True
            position += 1
            continue
        if pending_space and rendered and rendered[-1] not in "(," and character not in "),;":
            rendered.append(" ")
        pending_space = False
        rendered.append(character)
        if character in {"'", '"', "`"}:
            quote_end = character
        elif character == "[":
            quote_end = "]"
        position += 1
    return "".join(rendered)


def _collect_schema_manifest(connection: sqlite3.Connection) -> tuple[_SchemaObject, ...]:
    """Describe every migration-managed object using SQLite's live catalog and pragmas."""

    table_flags = {
        str(row["name"]): (int(row["ncol"]), int(row["wr"]), int(row["strict"]))
        for row in connection.execute("PRAGMA main.table_list").fetchall()
        if str(row["schema"]) == "main"
    }
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM main.sqlite_schema "
        "WHERE type IN ('table', 'index', 'trigger', 'view') "
        "AND (name NOT LIKE 'sqlite_%' OR name LIKE 'sqlite_autoindex_%') "
        "ORDER BY type, name"
    ).fetchall()
    manifest: list[_SchemaObject] = []
    for row in rows:
        object_type = str(row["type"])
        name = str(row["name"])
        table_name = str(row["tbl_name"])
        columns: tuple[tuple[int, str, str, int, str | None, int, int], ...] = ()
        foreign_keys: tuple[tuple[int, int, str, str, str | None, str, str, str], ...] = ()
        flags: tuple[int, int, int] | None = None
        index_properties: tuple[int, str, int] | None = None
        index_columns: tuple[tuple[int, int, str | None, int, str, int], ...] = ()
        if object_type == "table":
            columns = tuple(
                (
                    int(column["cid"]),
                    str(column["name"]),
                    str(column["type"]),
                    int(column["notnull"]),
                    None if column["dflt_value"] is None else str(column["dflt_value"]),
                    int(column["pk"]),
                    int(column["hidden"]),
                )
                for column in connection.execute(
                    'SELECT cid, name, type, "notnull", dflt_value, pk, hidden '
                    "FROM pragma_table_xinfo(?) ORDER BY cid",
                    (name,),
                ).fetchall()
            )
            foreign_keys = tuple(
                (
                    int(foreign_key["id"]),
                    int(foreign_key["seq"]),
                    str(foreign_key["table"]),
                    str(foreign_key["from"]),
                    None if foreign_key["to"] is None else str(foreign_key["to"]),
                    str(foreign_key["on_update"]),
                    str(foreign_key["on_delete"]),
                    str(foreign_key["match"]),
                )
                for foreign_key in connection.execute(
                    'SELECT id, seq, "table", "from", "to", on_update, '
                    'on_delete, "match" FROM pragma_foreign_key_list(?) ORDER BY id, seq',
                    (name,),
                ).fetchall()
            )
            flags = table_flags.get(name)
        elif object_type == "index":
            properties = connection.execute(
                'SELECT "unique", origin, partial FROM pragma_index_list(?) WHERE name = ?',
                (table_name, name),
            ).fetchone()
            if properties is not None:
                index_properties = (
                    int(properties["unique"]),
                    str(properties["origin"]),
                    int(properties["partial"]),
                )
            index_columns = tuple(
                (
                    int(column["seqno"]),
                    int(column["cid"]),
                    None if column["name"] is None else str(column["name"]),
                    int(column["desc"]),
                    str(column["coll"]),
                    int(column["key"]),
                )
                for column in connection.execute(
                    'SELECT seqno, cid, name, "desc", coll, key '
                    "FROM pragma_index_xinfo(?) ORDER BY seqno",
                    (name,),
                ).fetchall()
            )
        manifest.append(
            _SchemaObject(
                object_type=object_type,
                name=name,
                table_name=table_name,
                create_sql=_canonical_schema_sql(row["sql"]),
                columns=columns,
                foreign_keys=foreign_keys,
                table_flags=flags,
                index_properties=index_properties,
                index_columns=index_columns,
            )
        )
    return tuple(manifest)


def _expected_schema_manifest(
    migrations: tuple[_PreparedMigration, ...],
) -> tuple[_SchemaObject, ...]:
    """Materialize trusted migration source in an isolated SQLite database."""

    expected = sqlite3.connect(":memory:", isolation_level=None)
    try:
        expected.row_factory = sqlite3.Row
        expected.execute("PRAGMA foreign_keys = OFF")
        expected.execute(_SCHEMA_MIGRATIONS_BOOTSTRAP)
        for migration in migrations:
            for statement in migration.statements:
                expected.execute(statement)
            expected.execute(_MIGRATION_MARKER_SQL, (migration.version, migration.digest))
        return _collect_schema_manifest(expected)
    finally:
        expected.close()


@dataclass(frozen=True, slots=True)
class IntentReservation:
    intent_hash: str
    transaction_id: str
    created: bool
    previous_transaction_id: str | None = None


class SQLiteJournal:
    """Durable single-process journal with optimistic transaction versioning."""

    def __init__(self, path: Path) -> None:
        self._path = path.resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self._path, isolation_level=None, timeout=5.0)
        try:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            mode = self._enable_wal_with_retry()
            if str(mode).lower() != "wal":
                raise AgentKernelError(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "SQLite journal could not enable WAL mode",
                )
            self._apply_migrations()
        except BaseException:
            self._connection.close()
            raise

    def _enable_wal_with_retry(self) -> object:
        """Enable WAL despite SQLite's immediate first-open journal-mode lock race."""

        deadline = time.monotonic() + 5.0
        delay = 0.01
        while True:
            try:
                row = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()
                if row is None:
                    raise AgentKernelError(
                        ErrorCode.EVIDENCE_UNAVAILABLE,
                        "SQLite did not report a journal mode",
                    )
                return row[0]
            except sqlite3.OperationalError as error:
                code = getattr(error, "sqlite_errorcode", None)
                primary_code = code & 0xFF if isinstance(code, int) else None
                locked = primary_code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
                if not locked:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AgentKernelError(
                        ErrorCode.EVIDENCE_UNAVAILABLE,
                        "SQLite journal-mode initialization remained locked",
                        details={"sqlite": getattr(error, "sqlite_errorname", "SQLITE_BUSY")},
                        retryable=True,
                    ) from error
                time.sleep(min(delay, remaining))
                delay = min(delay * 2, 0.1)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def journal_mode(self) -> str:
        row = self._connection.execute("PRAGMA journal_mode").fetchone()
        return str(row[0]).lower()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> SQLiteJournal:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _execute_migration_statement(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> None:
        """Execute one already-validated migration step inside the active transaction."""

        self._connection.execute(statement, parameters)

    def _check_migration_invariants(self, version: int) -> None:
        missing_parent = self._connection.execute(
            'SELECT child.name AS child_table, foreign_key."table" AS parent_table '
            "FROM main.sqlite_schema AS child "
            "JOIN pragma_foreign_key_list(child.name, 'main') AS foreign_key "
            "LEFT JOIN main.sqlite_schema AS parent "
            "ON parent.type = 'table' "
            'AND parent.name = foreign_key."table" COLLATE NOCASE '
            "WHERE child.type = 'table' "
            "AND child.name NOT LIKE 'sqlite_%' "
            "AND parent.name IS NULL LIMIT 1"
        ).fetchone()
        if missing_parent is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Migration declares a foreign key to a missing table",
                details={
                    "version": version,
                    "table": str(missing_parent["child_table"]),
                    "referenced_table": str(missing_parent["parent_table"]),
                },
            )
        self._check_database_integrity(version=version)

    def _check_database_integrity(self, *, version: int) -> None:
        foreign_key_violation = self._connection.execute("PRAGMA foreign_key_check").fetchone()
        if foreign_key_violation is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "SQLite data violates a foreign-key invariant",
                details={
                    "version": version,
                    "table": str(foreign_key_violation[0]),
                    "rowid": foreign_key_violation[1],
                    "referenced_table": str(foreign_key_violation[2]),
                    "foreign_key_id": int(foreign_key_violation[3]),
                },
            )
        integrity_row = self._connection.execute("PRAGMA integrity_check").fetchone()
        if integrity_row is None or str(integrity_row[0]).lower() != "ok":
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "SQLite data violates an integrity invariant",
                details={
                    "version": version,
                    "result": None if integrity_row is None else str(integrity_row[0]),
                },
            )

    def _validate_live_schema(
        self,
        expected: tuple[_SchemaObject, ...],
        *,
        version: int,
    ) -> None:
        actual = _collect_schema_manifest(self._connection)
        expected_by_key = {(item.object_type, item.name): item for item in expected}
        actual_by_key = {(item.object_type, item.name): item for item in actual}
        missing = sorted(set(expected_by_key) - set(actual_by_key))
        unexpected = sorted(set(actual_by_key) - set(expected_by_key))
        if missing or unexpected:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Live SQLite schema object set differs from migration source",
                details={
                    "version": version,
                    "missing": [f"{kind}:{name}" for kind, name in missing],
                    "unexpected": [f"{kind}:{name}" for kind, name in unexpected],
                },
            )
        for key in sorted(expected_by_key):
            expected_object = expected_by_key[key]
            actual_object = actual_by_key[key]
            if actual_object != expected_object:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Live SQLite schema object differs from migration source",
                    details={
                        "version": version,
                        "object_type": key[0],
                        "object_name": key[1],
                        "expected_fingerprint": canonical_digest(
                            expected_object.fingerprint_material()
                        ),
                        "actual_fingerprint": canonical_digest(
                            actual_object.fingerprint_material()
                        ),
                    },
                )

    def _apply_migrations(self) -> None:
        migrations = _prepare_migrations()
        self._connection.execute("BEGIN EXCLUSIVE")
        try:
            migration_table = self._connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_migrations'"
            ).fetchone()
            if migration_table is None:
                preexisting = self._connection.execute(
                    "SELECT type, name FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name LIMIT 1"
                ).fetchone()
                if preexisting is not None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Unversioned non-empty SQLite schema cannot be adopted",
                        details={
                            "object_type": str(preexisting["type"]),
                            "object_name": str(preexisting["name"]),
                        },
                    )
            self._connection.execute(_SCHEMA_MIGRATIONS_BOOTSTRAP)
            applied_rows = self._connection.execute(
                "SELECT version, digest FROM schema_migrations ORDER BY version"
            ).fetchall()
            if migration_table is not None and not applied_rows:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Existing SQLite schema has an empty migration provenance ledger",
                )
            for index, row in enumerate(applied_rows):
                version = int(row["version"])
                if index >= len(migrations) or version != migrations[index].version:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Applied migration sequence differs from source",
                        details={"version": version},
                    )
                if str(row["digest"]) != migrations[index].digest:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Applied migration digest differs from source",
                        details={"version": version},
                    )

            if applied_rows:
                applied_migrations = migrations[: len(applied_rows)]
                applied_version = applied_migrations[-1].version
                self._validate_live_schema(
                    _expected_schema_manifest(applied_migrations),
                    version=applied_version,
                )
                self._check_database_integrity(version=applied_version)

            for migration in migrations[len(applied_rows) :]:
                for statement in migration.statements:
                    self._execute_migration_statement(statement)
                self._check_migration_invariants(migration.version)
                self._execute_migration_statement(
                    _MIGRATION_MARKER_SQL,
                    (migration.version, migration.digest),
                )
            current_version = migrations[-1].version
            self._validate_live_schema(
                _expected_schema_manifest(migrations),
                version=current_version,
            )
            self._check_database_integrity(version=current_version)
            self._connection.execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def schema_version(self) -> int:
        row = self._connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return int(row[0] or 0)

    def _next_event_position(self, run_id: str) -> tuple[int, str | None]:
        row = self._connection.execute(
            "SELECT sequence, event_hash FROM events WHERE run_id = ? "
            "ORDER BY sequence DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        if row is None:
            return 0, None
        return int(row["sequence"]) + 1, str(row["event_hash"])

    def _insert_event(self, event: EventEnvelope) -> None:
        self._connection.execute(
            "INSERT INTO events(run_id, sequence, event_id, transaction_id, event_hash, "
            "previous_event_hash, event_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event.run_id,
                event.sequence,
                event.event_id,
                event.transaction_id,
                event.event_hash,
                event.previous_event_hash,
                event.model_dump_json(),
            ),
        )

    def create_transaction(
        self,
        record: TransactionRecord,
        *,
        run_id: str,
        actor: str,
        on_behalf_of: str,
    ) -> EventEnvelope:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
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
            sequence, previous_hash = self._next_event_position(run_id)
            event = make_event(
                run_id=run_id,
                transaction_id=record.transaction_id,
                sequence=sequence,
                logical_time=sequence,
                wall_time=record.created_at,
                event_type="transaction.created",
                actor=actor,
                on_behalf_of=on_behalf_of,
                payload={"state": record.state.value, "version": record.version},
                previous_event_hash=previous_hash,
            )
            self._insert_event(event)
            self._connection.execute("COMMIT")
            return event
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def append_event(
        self,
        *,
        run_id: str,
        wall_time: datetime,
        event_type: str,
        actor: str,
        on_behalf_of: str,
        payload: dict[str, JsonValue],
        transaction_id: str | None = None,
    ) -> EventEnvelope:
        """Append non-transition evidence under the authoritative per-run sequence."""

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            sequence, previous_hash = self._next_event_position(run_id)
            event = make_event(
                run_id=run_id,
                transaction_id=transaction_id,
                sequence=sequence,
                logical_time=sequence,
                wall_time=wall_time,
                event_type=event_type,
                actor=actor,
                on_behalf_of=on_behalf_of,
                payload=payload,
                previous_event_hash=previous_hash,
            )
            self._insert_event(event)
            self._connection.execute("COMMIT")
            return event
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def get_transaction(self, transaction_id: str) -> TransactionRecord:
        row = self._connection.execute(
            "SELECT record_json FROM transactions WHERE transaction_id = ?", (transaction_id,)
        ).fetchone()
        if row is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unknown transaction",
                details={"transaction_id": transaction_id},
            )
        return TransactionRecord.model_validate_json(row["record_json"])

    def set_transaction_intent(
        self,
        transaction_id: str,
        *,
        intent_hash: str,
    ) -> TransactionRecord:
        """Bind the inspected intent to a NEW transaction before staging begins."""

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.get_transaction(transaction_id)
            if current.state.value != "NEW" or current.intent_hash is not None:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Intent can only be bound once while a transaction is NEW",
                )
            updated = current.model_copy(update={"intent_hash": intent_hash})
            cursor = self._connection.execute(
                "UPDATE transactions SET intent_hash = ?, record_json = ? "
                "WHERE transaction_id = ? AND version = ?",
                (intent_hash, updated.model_dump_json(), transaction_id, current.version),
            )
            if cursor.rowcount != 1:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Could not bind transaction intent",
                )
            self._connection.execute("COMMIT")
            return updated
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def transition(
        self,
        transaction_id: str,
        *,
        expected_version: int,
        transition_event: TransitionEvent,
        now: datetime,
        run_id: str,
        actor: str,
        on_behalf_of: str,
        reason_code: str | None = None,
    ) -> tuple[TransactionRecord, EventEnvelope]:
        """CAS a transaction and append its transition event in the same DB transaction."""

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.get_transaction(transaction_id)
            if current.version != expected_version:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Transaction version changed",
                    details={"expected": expected_version, "actual": current.version},
                    retryable=True,
                )
            decision = apply_transition(
                current.state,
                transition_event,
                current_intended_outcome=current.intended_outcome,
            )
            updated = current.model_copy(
                update={
                    "state": decision.target,
                    "version": current.version + 1,
                    "intended_outcome": decision.intended_outcome,
                    "updated_at": now,
                    "reason_code": reason_code or decision.rule_id,
                }
            )
            cursor = self._connection.execute(
                "UPDATE transactions SET state = ?, version = ?, intended_outcome = ?, "
                "record_json = ? WHERE transaction_id = ? AND version = ?",
                (
                    updated.state.value,
                    updated.version,
                    updated.intended_outcome.value if updated.intended_outcome else None,
                    updated.model_dump_json(),
                    transaction_id,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Transaction compare-and-swap failed",
                    retryable=True,
                )
            sequence, previous_hash = self._next_event_position(run_id)
            event = make_event(
                run_id=run_id,
                transaction_id=transaction_id,
                sequence=sequence,
                logical_time=sequence,
                wall_time=now,
                event_type="transaction.transitioned",
                actor=actor,
                on_behalf_of=on_behalf_of,
                payload={
                    "from": current.state.value,
                    "to": updated.state.value,
                    "event": transition_event.value,
                    "rule_id": decision.rule_id,
                    "version": updated.version,
                },
                previous_event_hash=previous_hash,
            )
            self._insert_event(event)
            self._connection.execute("COMMIT")
            return updated, event
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def reserve_intent(
        self,
        *,
        intent_hash: str,
        transaction_id: str,
        reserved_at: datetime,
    ) -> IntentReservation:
        """Atomically reserve one normalized intent and return the existing owner on conflict."""

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            cursor = self._connection.execute(
                "INSERT OR IGNORE INTO intents(intent_hash, transaction_id, reserved_at) "
                "VALUES (?, ?, ?)",
                (intent_hash, transaction_id, reserved_at.isoformat()),
            )
            row = self._connection.execute(
                "SELECT transaction_id FROM intents WHERE intent_hash = ?", (intent_hash,)
            ).fetchone()
            if row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Intent reservation disappeared inside its transaction",
                )
            owner = str(row["transaction_id"])
            previous_owner: str | None = None
            created = cursor.rowcount == 1
            if owner != transaction_id:
                owner_row = self._connection.execute(
                    "SELECT state FROM transactions WHERE transaction_id = ?",
                    (owner,),
                ).fetchone()
                receipt_row = self._connection.execute(
                    "SELECT 1 FROM receipts WHERE transaction_id = ? LIMIT 1",
                    (owner,),
                ).fetchone()
                safe_no_effect_states = {
                    "REJECTED",
                    "ABORTED",
                    "STALE_STATE",
                }
                if (
                    owner_row is not None
                    and str(owner_row["state"]) in safe_no_effect_states
                    and receipt_row is None
                ):
                    updated = self._connection.execute(
                        "UPDATE intents SET transaction_id = ?, reserved_at = ? "
                        "WHERE intent_hash = ? AND transaction_id = ?",
                        (transaction_id, reserved_at.isoformat(), intent_hash, owner),
                    )
                    if updated.rowcount == 1:
                        previous_owner = owner
                        owner = transaction_id
                        created = True
            self._connection.execute("COMMIT")
            return IntentReservation(
                intent_hash,
                owner,
                created,
                previous_transaction_id=previous_owner,
            )
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def try_consume_capability_use(self, capability_id: str, max_uses: int) -> bool:
        """Atomically consume one durable capability use without exceeding its budget."""

        if max_uses < 1:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Capability use budget must be positive",
            )
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT uses FROM capability_uses WHERE capability_id = ?",
                (capability_id,),
            ).fetchone()
            uses = int(row["uses"]) if row is not None else 0
            if uses >= max_uses:
                self._connection.execute("COMMIT")
                return False
            self._connection.execute(
                "INSERT INTO capability_uses(capability_id, uses, updated_at) "
                "VALUES (?, 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) "
                "ON CONFLICT(capability_id) DO UPDATE SET "
                "uses = capability_uses.uses + 1, "
                "updated_at = excluded.updated_at",
                (capability_id,),
            )
            self._connection.execute("COMMIT")
            return True
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def link_transaction_supersession(
        self,
        transaction_id: str,
        *,
        previous_transaction_id: str,
    ) -> TransactionRecord:
        """Persist the audit link created when a no-effect intent attempt is retried."""

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.get_transaction(transaction_id)
            if current.state.value != "NEW" or current.supersedes_transaction_id is not None:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Only a new unlinked transaction can supersede a no-effect attempt",
                )
            updated = current.model_copy(
                update={"supersedes_transaction_id": previous_transaction_id}
            )
            cursor = self._connection.execute(
                "UPDATE transactions SET record_json = ? WHERE transaction_id = ? AND version = ?",
                (updated.model_dump_json(), transaction_id, current.version),
            )
            if cursor.rowcount != 1:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Could not persist transaction supersession link",
                )
            self._connection.execute("COMMIT")
            return updated
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def append_receipt(self, receipt: EffectReceipt) -> None:
        """Append an immutable effect receipt; receipt IDs cannot be overwritten."""

        try:
            self._connection.execute(
                "INSERT INTO receipts(receipt_id, transaction_id, receipt_json, created_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    receipt.receipt_id,
                    receipt.transaction_id,
                    receipt.model_dump_json(),
                    receipt.created_at.isoformat(),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Receipt is not appendable",
                details={"receipt_id": receipt.receipt_id},
            ) from error

    def list_events(self, run_id: str) -> tuple[EventEnvelope, ...]:
        rows = self._connection.execute(
            "SELECT event_json FROM events WHERE run_id = ? ORDER BY sequence", (run_id,)
        ).fetchall()
        return tuple(EventEnvelope.model_validate_json(row["event_json"]) for row in rows)

    def list_non_terminal(self) -> tuple[TransactionRecord, ...]:
        terminals = tuple(state.value for state in TERMINAL_TRANSACTION_STATES)
        rows = self._connection.execute(
            "SELECT record_json FROM transactions "
            "WHERE state NOT IN (?, ?, ?, ?, ?, ?, ?, ?) ORDER BY transaction_id",
            terminals,
        ).fetchall()
        return tuple(TransactionRecord.model_validate_json(row["record_json"]) for row in rows)
