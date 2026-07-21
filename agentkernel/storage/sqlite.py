"""Single-node SQLite WAL transaction journal and event store."""

from __future__ import annotations

import sqlite3
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
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        mode = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "SQLite journal could not enable WAL mode",
            )
        self._apply_migrations()

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

    def _apply_migrations(self) -> None:
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(version INTEGER PRIMARY KEY, digest TEXT NOT NULL, applied_at TEXT NOT NULL)"
        )
        applied_rows = self._connection.execute(
            "SELECT version, digest FROM schema_migrations ORDER BY version"
        ).fetchall()
        applied = {int(row["version"]): str(row["digest"]) for row in applied_rows}
        for version, sql in MIGRATIONS:
            digest = canonical_digest({"version": version, "sql": sql})
            if version in applied:
                if applied[version] != digest:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Applied migration digest differs from source",
                        details={"version": version},
                    )
                continue
            self._connection.executescript(sql)
            self._connection.execute(
                "INSERT INTO schema_migrations(version, digest, applied_at) "
                "VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                (version, digest),
            )

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
