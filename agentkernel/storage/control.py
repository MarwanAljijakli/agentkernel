"""Tenant-scoped enforced control-plane state for the single-node SQLite profile.

This module deliberately uses a table namespace separate from the Phase-0 journal.  It
stores only already-normalized actions and durable control decisions; it does not validate
signed capabilities, revocation, or coordinator state transitions.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from pydantic import BaseModel, JsonValue, ValidationError

from agentkernel.canonical import canonical_digest, canonical_json_text
from agentkernel.domain.models import AuthenticatedActionContext, NormalizedAction, ResourceUse
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.storage.sqlite import SQLiteJournal

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,255}$")
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_CAPABILITY_CHAIN = 256
_MAX_SQLITE_INTEGER = (1 << 63) - 1


class IntentDisposition(StrEnum):
    """Normative duplicate-intent outcomes returned by the owner store."""

    ACQUIRED = "ACQUIRED"
    SAME_TRANSACTION = "SAME_TRANSACTION"
    ALIAS_ACTIVE = "ALIAS_ACTIVE"
    ALIAS_RECONCILE = "ALIAS_RECONCILE"
    ALIAS_COMMITTED = "ALIAS_COMMITTED"
    TRANSFERRED_NO_EFFECT = "TRANSFERRED_NO_EFFECT"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class IntentAttemptState(StrEnum):
    """Durable evidence classification for one normalized intent attempt."""

    ACTIVE = "ACTIVE"
    RECONCILE_REQUIRED = "RECONCILE_REQUIRED"
    COMMITTED = "COMMITTED"
    NO_EFFECT_CONFIRMED = "NO_EFFECT_CONFIRMED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class CapabilityReservationState(StrEnum):
    RESERVED = "RESERVED"
    COMMITTED = "COMMITTED"
    RELEASED = "RELEASED"


class DecisionKind(StrEnum):
    AUTHORITY = "AUTHORITY"
    POLICY = "POLICY"


@dataclass(frozen=True, slots=True)
class StoredNormalizedAction:
    action: NormalizedAction
    action_digest: str
    recorded_at: datetime
    created: bool


@dataclass(frozen=True, slots=True)
class IntentAcquisition:
    disposition: IntentDisposition
    tenant_id: str
    intent_hash: str
    transaction_id: str
    owner_transaction_id: str
    owner_version: int
    previous_owner_transaction_id: str | None = None


@dataclass(frozen=True, slots=True)
class IntentAttemptRecord:
    tenant_id: str
    intent_hash: str
    transaction_id: str
    state: IntentAttemptState
    version: int
    evidence_digest: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class IntentHistoryEntry:
    tenant_id: str
    intent_hash: str
    sequence: int
    transaction_id: str
    event_type: str
    disposition: IntentDisposition | None
    attempt_state: IntentAttemptState
    owner_transaction_id: str
    owner_version: int
    evidence_digest: str | None
    previous_history_digest: str | None
    history_digest: str
    recorded_at: datetime


@dataclass(frozen=True, slots=True)
class _AttemptProjection:
    state: IntentAttemptState
    version: int
    evidence_digest: str | None


@dataclass(frozen=True, slots=True)
class _ValidatedIntentLedger:
    owner_transaction_id: str
    owner_version: int
    owner_state: IntentAttemptState
    head_sequence: int
    head_digest: str
    entries: tuple[IntentHistoryEntry, ...]


@dataclass(frozen=True, slots=True)
class CapabilityBudget:
    tenant_id: str
    capability_id: str
    goal_id: str
    run_id: str
    max_uses: int
    reserved_uses: int
    committed_uses: int
    version: int
    registration_digest: str
    registered_at: datetime
    updated_at: datetime

    @property
    def consumed_uses(self) -> int:
        """Return durable committed consumption using authority-evaluator terminology."""

        return self.committed_uses


@dataclass(frozen=True, slots=True)
class CapabilityReservationFence:
    """Immutable activation identity required to transition a reserved chain.

    The chain version prevents an operation retained by an earlier activation from
    transitioning a later activation of the same semantic intent.  The durable
    intent-owner projection additionally binds owned reservations to the exact
    transaction and history entry that activated them.
    """

    reservation_version: int
    activation_owner_transaction_id: str | None
    activation_owner_version: int | None
    activation_history_sequence: int | None
    activation_history_digest: str | None


@dataclass(frozen=True, slots=True)
class CapabilityChainReservation:
    tenant_id: str
    goal_id: str
    run_id: str
    intent_hash: str
    capability_ids: tuple[str, ...]
    request_digest: str
    state: CapabilityReservationState
    version: int
    activation_owner_transaction_id: str | None
    activation_owner_version: int | None
    activation_history_sequence: int | None
    activation_history_digest: str | None
    release_history_sequence: int | None
    release_history_digest: str | None
    changed: bool

    @property
    def fence(self) -> CapabilityReservationFence:
        """Return the exact activation fence a commit or release must present."""

        return CapabilityReservationFence(
            reservation_version=(
                self.version
                if self.state is CapabilityReservationState.RESERVED
                else self.version - 1
            ),
            activation_owner_transaction_id=self.activation_owner_transaction_id,
            activation_owner_version=self.activation_owner_version,
            activation_history_sequence=self.activation_history_sequence,
            activation_history_digest=self.activation_history_digest,
        )


@dataclass(frozen=True, slots=True)
class DecisionSnapshot:
    tenant_id: str
    kind: DecisionKind
    decision_id: str
    transaction_id: str
    intent_hash: str
    decision_digest: str
    decision: dict[str, JsonValue]
    recorded_at: datetime
    created: bool


_ATTEMPT_TRANSITIONS: Mapping[IntentAttemptState, frozenset[IntentAttemptState]] = {
    IntentAttemptState.ACTIVE: frozenset(
        {
            IntentAttemptState.RECONCILE_REQUIRED,
            IntentAttemptState.COMMITTED,
            IntentAttemptState.NO_EFFECT_CONFIRMED,
            IntentAttemptState.REVIEW_REQUIRED,
        }
    ),
    IntentAttemptState.RECONCILE_REQUIRED: frozenset(
        {
            IntentAttemptState.COMMITTED,
            IntentAttemptState.NO_EFFECT_CONFIRMED,
            IntentAttemptState.REVIEW_REQUIRED,
        }
    ),
    IntentAttemptState.COMMITTED: frozenset(),
    IntentAttemptState.NO_EFFECT_CONFIRMED: frozenset(),
    IntentAttemptState.REVIEW_REQUIRED: frozenset(),
}


def _require_identifier(value: str, *, field: str) -> str:
    if _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            f"{field} is not a valid identifier",
            details={"field": field},
        )
    return value


def _require_digest(value: str, *, field: str) -> str:
    if _DIGEST_PATTERN.fullmatch(value) is None:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            f"{field} is not a valid SHA-256 digest",
            details={"field": field},
        )
    return value


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Control-plane timestamps must be timezone-aware",
        )
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as error:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Stored control-plane timestamp is invalid",
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Stored control-plane timestamp lacks a timezone",
        )
    return parsed


def _coerce_attempt_state(value: IntentAttemptState | str) -> IntentAttemptState:
    try:
        return IntentAttemptState(value)
    except ValueError as error:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Unknown intent attempt state",
        ) from error


def _coerce_decision_kind(value: DecisionKind | str) -> DecisionKind:
    try:
        return DecisionKind(value)
    except ValueError as error:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Unknown decision snapshot kind",
        ) from error


def _sqlite_integrity(message: str, error: sqlite3.IntegrityError) -> AgentKernelError:
    return AgentKernelError(
        ErrorCode.INTEGRITY_ERROR,
        message,
        details={"sqlite": getattr(error, "sqlite_errorname", "SQLITE_CONSTRAINT")},
    )


class SQLiteControlStore:
    """Fail-closed, tenant-scoped control state backed by SQLite WAL."""

    def __init__(self, path: Path) -> None:
        self._path = path.resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with SQLiteJournal(self._path):
            pass
        self._connection = sqlite3.connect(self._path, isolation_level=None, timeout=5.0)
        try:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA synchronous = FULL")
            mode = str(self._connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            if mode != "wal":
                raise AgentKernelError(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "SQLite control store is not in WAL mode",
                )
            with self._read_snapshot():
                self._validate_all_intent_ledgers()
        except BaseException:
            self._connection.close()
            raise

    @property
    def path(self) -> Path:
        return self._path

    @property
    def schema_version(self) -> int:
        row = self._connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return int(row[0] or 0)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> SQLiteControlStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _execute(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> sqlite3.Cursor:
        """Execute one statement; kept as a narrow fault-injection seam for recovery tests."""

        return self._connection.execute(statement, parameters)

    @contextmanager
    def _immediate(self) -> Iterator[None]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            self._connection.execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    @contextmanager
    def _read_snapshot(self) -> Iterator[None]:
        self._connection.execute("BEGIN")
        try:
            yield
            self._connection.execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def register_tenant(self, tenant_id: str, *, registered_at: datetime) -> bool:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        timestamp = _timestamp(registered_at)
        with self._immediate():
            cursor = self._execute(
                "INSERT OR IGNORE INTO enforced_tenants(tenant_id, created_at) VALUES (?, ?)",
                (tenant_id, timestamp),
            )
        return cursor.rowcount == 1

    def register_principal(
        self,
        tenant_id: str,
        principal_id: str,
        *,
        registered_at: datetime,
    ) -> bool:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        principal_id = _require_identifier(principal_id, field="principal_id")
        timestamp = _timestamp(registered_at)
        try:
            with self._immediate():
                cursor = self._execute(
                    "INSERT OR IGNORE INTO enforced_principals"
                    "(tenant_id, principal_id, created_at) VALUES (?, ?, ?)",
                    (tenant_id, principal_id, timestamp),
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity(
                "Principal registration violates its tenant binding", error
            ) from error
        return cursor.rowcount == 1

    def register_goal(
        self,
        tenant_id: str,
        principal_id: str,
        goal_id: str,
        *,
        registered_at: datetime,
    ) -> bool:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        principal_id = _require_identifier(principal_id, field="principal_id")
        goal_id = _require_identifier(goal_id, field="goal_id")
        timestamp = _timestamp(registered_at)
        try:
            with self._immediate():
                cursor = self._execute(
                    "INSERT OR IGNORE INTO enforced_goals"
                    "(tenant_id, goal_id, principal_id, created_at) VALUES (?, ?, ?, ?)",
                    (tenant_id, goal_id, principal_id, timestamp),
                )
                row = self._connection.execute(
                    "SELECT principal_id FROM enforced_goals WHERE tenant_id = ? AND goal_id = ?",
                    (tenant_id, goal_id),
                ).fetchone()
                if row is None or str(row["principal_id"]) != principal_id:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Goal is already bound to a different principal",
                    )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity(
                "Goal registration violates its principal binding", error
            ) from error
        return cursor.rowcount == 1

    def register_run(
        self,
        tenant_id: str,
        principal_id: str,
        goal_id: str,
        run_id: str,
        *,
        registered_at: datetime,
    ) -> bool:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        principal_id = _require_identifier(principal_id, field="principal_id")
        goal_id = _require_identifier(goal_id, field="goal_id")
        run_id = _require_identifier(run_id, field="run_id")
        timestamp = _timestamp(registered_at)
        try:
            with self._immediate():
                cursor = self._execute(
                    "INSERT OR IGNORE INTO enforced_runs"
                    "(tenant_id, run_id, goal_id, principal_id, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (tenant_id, run_id, goal_id, principal_id, timestamp),
                )
                row = self._connection.execute(
                    "SELECT principal_id, goal_id FROM enforced_runs "
                    "WHERE tenant_id = ? AND run_id = ?",
                    (tenant_id, run_id),
                ).fetchone()
                if row is None or (str(row["principal_id"]), str(row["goal_id"])) != (
                    principal_id,
                    goal_id,
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Run is already bound to a different principal or goal",
                    )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Run registration violates its goal binding", error) from error
        return cursor.rowcount == 1

    def register_action_context(
        self,
        context: AuthenticatedActionContext,
        *,
        registered_at: datetime,
    ) -> None:
        """Register one authenticated tenant/principal/goal/run hierarchy atomically."""

        timestamp = _timestamp(registered_at)
        try:
            with self._immediate():
                self._execute(
                    "INSERT OR IGNORE INTO enforced_tenants(tenant_id, created_at) VALUES (?, ?)",
                    (context.tenant_id, timestamp),
                )
                self._execute(
                    "INSERT OR IGNORE INTO enforced_principals"
                    "(tenant_id, principal_id, created_at) VALUES (?, ?, ?)",
                    (context.tenant_id, context.principal_id, timestamp),
                )
                self._execute(
                    "INSERT OR IGNORE INTO enforced_goals"
                    "(tenant_id, goal_id, principal_id, created_at) VALUES (?, ?, ?, ?)",
                    (context.tenant_id, context.goal_id, context.principal_id, timestamp),
                )
                self._execute(
                    "INSERT OR IGNORE INTO enforced_runs"
                    "(tenant_id, run_id, goal_id, principal_id, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        context.tenant_id,
                        context.run_id,
                        context.goal_id,
                        context.principal_id,
                        timestamp,
                    ),
                )
                goal = self._connection.execute(
                    "SELECT principal_id FROM enforced_goals WHERE tenant_id = ? AND goal_id = ?",
                    (context.tenant_id, context.goal_id),
                ).fetchone()
                run = self._connection.execute(
                    "SELECT principal_id, goal_id FROM enforced_runs "
                    "WHERE tenant_id = ? AND run_id = ?",
                    (context.tenant_id, context.run_id),
                ).fetchone()
                if goal is None or str(goal["principal_id"]) != context.principal_id:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Authenticated context conflicts with the durable goal binding",
                    )
                if run is None or (str(run["principal_id"]), str(run["goal_id"])) != (
                    context.principal_id,
                    context.goal_id,
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Authenticated context conflicts with the durable run binding",
                    )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Authenticated context registration failed", error) from error

    def put_normalized_action(
        self,
        action: NormalizedAction,
        *,
        recorded_at: datetime,
    ) -> StoredNormalizedAction:
        """Persist one immutable normalized action and all typed resource uses."""

        timestamp = _timestamp(recorded_at)
        action_json = canonical_json_text(action)
        action_digest = canonical_digest(action)
        try:
            with self._immediate():
                existing = self._connection.execute(
                    "SELECT action_digest FROM enforced_normalized_actions "
                    "WHERE tenant_id = ? AND transaction_id = ?",
                    (action.tenant_id, action.transaction_id),
                ).fetchone()
                if existing is not None:
                    if str(existing["action_digest"]) != action_digest:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Normalized action identity already has different immutable content",
                        )
                    stored = self._get_normalized_action(action.tenant_id, action.transaction_id)
                    return StoredNormalizedAction(
                        action=stored.action,
                        action_digest=stored.action_digest,
                        recorded_at=stored.recorded_at,
                        created=False,
                    )

                self._execute(
                    "INSERT INTO enforced_normalized_actions"
                    "(tenant_id, transaction_id, principal_id, goal_id, run_id, intent_hash, "
                    "action_digest, action_json, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        action.tenant_id,
                        action.transaction_id,
                        action.principal_id,
                        action.goal_id,
                        action.run_id,
                        action.intent_hash,
                        action_digest,
                        action_json,
                        timestamp,
                    ),
                )
                for ordinal, resource_use in enumerate(action.resource_uses):
                    self._execute(
                        "INSERT INTO enforced_resource_uses"
                        "(tenant_id, transaction_id, ordinal, canonical_resource, "
                        "resource_use_digest, resource_use_json) VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            action.tenant_id,
                            action.transaction_id,
                            ordinal,
                            resource_use.canonical_resource,
                            canonical_digest(resource_use),
                            canonical_json_text(resource_use),
                        ),
                    )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Normalized action persistence failed closed", error) from error
        return StoredNormalizedAction(
            action=action,
            action_digest=action_digest,
            recorded_at=_parse_timestamp(timestamp),
            created=True,
        )

    def _get_normalized_action(
        self,
        tenant_id: str,
        transaction_id: str,
    ) -> StoredNormalizedAction:
        row = self._connection.execute(
            "SELECT * FROM enforced_normalized_actions WHERE tenant_id = ? AND transaction_id = ?",
            (tenant_id, transaction_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unknown normalized action in this tenant",
            )
        try:
            action = NormalizedAction.model_validate_json(str(row["action_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored normalized action is invalid",
            ) from error
        expected_digest = canonical_digest(action)
        if (
            str(row["tenant_id"]) != action.tenant_id
            or str(row["transaction_id"]) != action.transaction_id
            or str(row["principal_id"]) != action.principal_id
            or str(row["goal_id"]) != action.goal_id
            or str(row["run_id"]) != action.run_id
            or str(row["intent_hash"]) != action.intent_hash
            or str(row["action_digest"]) != expected_digest
            or str(row["action_json"]) != canonical_json_text(action)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored normalized action digest or binding is inconsistent",
            )

        resource_rows = self._connection.execute(
            "SELECT * FROM enforced_resource_uses "
            "WHERE tenant_id = ? AND transaction_id = ? ORDER BY ordinal",
            (tenant_id, transaction_id),
        ).fetchall()
        if len(resource_rows) != len(action.resource_uses):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored normalized action has an incomplete resource-use set",
            )
        for ordinal, (resource_row, expected_use) in enumerate(
            zip(resource_rows, action.resource_uses, strict=True)
        ):
            try:
                resource_use = ResourceUse.model_validate_json(
                    str(resource_row["resource_use_json"])
                )
            except (ValidationError, ValueError) as error:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Stored resource use is invalid",
                ) from error
            if (
                int(resource_row["ordinal"]) != ordinal
                or resource_use != expected_use
                or str(resource_row["canonical_resource"]) != resource_use.canonical_resource
                or str(resource_row["resource_use_digest"]) != canonical_digest(resource_use)
                or str(resource_row["resource_use_json"]) != canonical_json_text(resource_use)
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Stored resource-use digest or binding is inconsistent",
                )
        return StoredNormalizedAction(
            action=action,
            action_digest=expected_digest,
            recorded_at=_parse_timestamp(row["recorded_at"]),
            created=False,
        )

    def get_normalized_action(
        self,
        tenant_id: str,
        transaction_id: str,
    ) -> StoredNormalizedAction:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        return self._get_normalized_action(tenant_id, transaction_id)

    def _require_action_intent(
        self,
        tenant_id: str,
        transaction_id: str,
        intent_hash: str,
    ) -> None:
        row = self._connection.execute(
            "SELECT 1 FROM enforced_normalized_actions "
            "WHERE tenant_id = ? AND transaction_id = ? AND intent_hash = ?",
            (tenant_id, transaction_id, intent_hash),
        ).fetchone()
        if row is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Intent attempt does not match a normalized action in this tenant",
            )

    def _read_intent_history_entries(
        self,
        tenant_id: str,
        intent_hash: str,
    ) -> tuple[IntentHistoryEntry, ...]:
        rows = self._connection.execute(
            "SELECT * FROM enforced_intent_attempt_history "
            "WHERE tenant_id = ? AND intent_hash = ? ORDER BY sequence",
            (tenant_id, intent_hash),
        ).fetchall()
        entries: list[IntentHistoryEntry] = []
        previous_digest: str | None = None
        for sequence, row in enumerate(rows):
            try:
                disposition = (
                    None
                    if row["disposition"] is None
                    else IntentDisposition(str(row["disposition"]))
                )
                attempt_state = IntentAttemptState(str(row["attempt_state"]))
            except ValueError as error:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Stored intent history contains an invalid enum value",
                ) from error
            evidence = None if row["evidence_digest"] is None else str(row["evidence_digest"])
            if evidence is not None and _DIGEST_PATTERN.fullmatch(evidence) is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Stored intent history evidence digest is invalid",
                    details={"sequence": sequence},
                )
            recorded_at_text = str(row["recorded_at"])
            payload: dict[str, object] = {
                "profile": "agentkernel.intent-attempt-history/v1",
                "tenant_id": tenant_id,
                "intent_hash": intent_hash,
                "sequence": sequence,
                "transaction_id": str(row["transaction_id"]),
                "event_type": str(row["event_type"]),
                "disposition": disposition.value if disposition is not None else None,
                "attempt_state": attempt_state.value,
                "owner_transaction_id": str(row["owner_transaction_id"]),
                "owner_version": int(row["owner_version"]),
                "evidence_digest": evidence,
                "previous_history_digest": previous_digest,
                "recorded_at": recorded_at_text,
            }
            history_digest = str(row["history_digest"])
            if (
                int(row["sequence"]) != sequence
                or (
                    None
                    if row["previous_history_digest"] is None
                    else str(row["previous_history_digest"])
                )
                != previous_digest
                or canonical_digest(payload) != history_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Intent attempt history hash chain is inconsistent",
                    details={"sequence": sequence},
                )
            entries.append(
                IntentHistoryEntry(
                    tenant_id=tenant_id,
                    intent_hash=intent_hash,
                    sequence=sequence,
                    transaction_id=str(row["transaction_id"]),
                    event_type=str(row["event_type"]),
                    disposition=disposition,
                    attempt_state=attempt_state,
                    owner_transaction_id=str(row["owner_transaction_id"]),
                    owner_version=int(row["owner_version"]),
                    evidence_digest=evidence,
                    previous_history_digest=previous_digest,
                    history_digest=history_digest,
                    recorded_at=_parse_timestamp(recorded_at_text),
                )
            )
            previous_digest = history_digest
        return tuple(entries)

    def _assert_intent_ledger_absent(self, tenant_id: str, intent_hash: str) -> None:
        dangling = self._connection.execute(
            "SELECT 'attempt' AS object_type FROM enforced_intent_attempts "
            "WHERE tenant_id = ? AND intent_hash = ? "
            "UNION ALL "
            "SELECT 'history' FROM enforced_intent_attempt_history "
            "WHERE tenant_id = ? AND intent_hash = ? LIMIT 1",
            (tenant_id, intent_hash, tenant_id, intent_hash),
        ).fetchone()
        if dangling is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Intent ledger has projections or history without an owner",
                details={"object_type": str(dangling["object_type"])},
            )

    def _validate_all_intent_ledgers(self) -> None:
        dangling = self._connection.execute(
            "SELECT attempt.tenant_id, attempt.intent_hash "
            "FROM enforced_intent_attempts AS attempt "
            "LEFT JOIN enforced_intent_owners AS owner "
            "ON owner.tenant_id = attempt.tenant_id "
            "AND owner.intent_hash = attempt.intent_hash "
            "WHERE owner.intent_hash IS NULL LIMIT 1"
        ).fetchone()
        if dangling is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Intent attempt exists without a durable owner ledger",
                details={
                    "tenant_id": str(dangling["tenant_id"]),
                    "intent_hash": str(dangling["intent_hash"]),
                },
            )
        owners = self._connection.execute(
            "SELECT tenant_id, intent_hash FROM enforced_intent_owners "
            "ORDER BY tenant_id, intent_hash"
        ).fetchall()
        for owner in owners:
            self._validate_intent_ledger(
                str(owner["tenant_id"]),
                str(owner["intent_hash"]),
            )

    def _validate_intent_ledger(
        self,
        tenant_id: str,
        intent_hash: str,
    ) -> _ValidatedIntentLedger:
        owner = self._connection.execute(
            "SELECT * FROM enforced_intent_owners WHERE tenant_id = ? AND intent_hash = ?",
            (tenant_id, intent_hash),
        ).fetchone()
        if owner is None:
            self._assert_intent_ledger_absent(tenant_id, intent_hash)
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unknown intent owner ledger in this tenant",
            )
        entries = self._read_intent_history_entries(tenant_id, intent_hash)
        if not entries:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Intent owner ledger has no acquisition history",
            )

        expected_attempts: dict[str, _AttemptProjection] = {}
        current_owner: str | None = None
        current_owner_version = -1
        for entry in entries:
            if entry.event_type == "ACQUIRE":
                if entry.disposition is None or entry.evidence_digest is not None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Intent acquisition history has invalid evidence semantics",
                        details={"sequence": entry.sequence},
                    )
                expected_attempts.setdefault(
                    entry.transaction_id,
                    _AttemptProjection(IntentAttemptState.ACTIVE, 0, None),
                )
                if entry.sequence == 0:
                    if (
                        entry.disposition is not IntentDisposition.ACQUIRED
                        or entry.transaction_id != entry.owner_transaction_id
                        or entry.owner_version != 0
                        or entry.attempt_state is not IntentAttemptState.ACTIVE
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Intent ledger does not begin with a valid acquisition",
                        )
                    current_owner = entry.owner_transaction_id
                    current_owner_version = 0
                    continue
                if current_owner is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Intent ledger lost its owner projection",
                    )
                owner_projection = expected_attempts[current_owner]
                if entry.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT:
                    requested_projection = expected_attempts[entry.transaction_id]
                    if (
                        owner_projection.state is not IntentAttemptState.NO_EFFECT_CONFIRMED
                        or requested_projection.state is not IntentAttemptState.ACTIVE
                        or entry.transaction_id == current_owner
                        or entry.owner_transaction_id != entry.transaction_id
                        or entry.owner_version != current_owner_version + 1
                        or entry.attempt_state is not IntentAttemptState.ACTIVE
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Intent ownership transfer lacks proven no-effect semantics",
                            details={"sequence": entry.sequence},
                        )
                    current_owner = entry.owner_transaction_id
                    current_owner_version = entry.owner_version
                    continue
                if (
                    entry.owner_transaction_id != current_owner
                    or entry.owner_version != current_owner_version
                    or entry.attempt_state is not owner_projection.state
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Intent alias history changed the owner projection",
                        details={"sequence": entry.sequence},
                    )
                valid_alias = (
                    entry.disposition is IntentDisposition.SAME_TRANSACTION
                    and entry.transaction_id == current_owner
                ) or (
                    entry.transaction_id != current_owner
                    and (
                        (
                            entry.disposition is IntentDisposition.ALIAS_ACTIVE
                            and owner_projection.state is IntentAttemptState.ACTIVE
                        )
                        or (
                            entry.disposition is IntentDisposition.ALIAS_RECONCILE
                            and owner_projection.state is IntentAttemptState.RECONCILE_REQUIRED
                        )
                        or (
                            entry.disposition is IntentDisposition.ALIAS_COMMITTED
                            and owner_projection.state is IntentAttemptState.COMMITTED
                        )
                        or (
                            entry.disposition is IntentDisposition.REVIEW_REQUIRED
                            and owner_projection.state
                            in {
                                IntentAttemptState.NO_EFFECT_CONFIRMED,
                                IntentAttemptState.REVIEW_REQUIRED,
                            }
                        )
                    )
                )
                if not valid_alias:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Intent alias disposition is inconsistent with owner state",
                        details={"sequence": entry.sequence},
                    )
            elif entry.event_type == "STATE_CHANGED":
                if (
                    entry.disposition is not None
                    or entry.evidence_digest is None
                    or current_owner is None
                    or entry.transaction_id != current_owner
                    or entry.owner_transaction_id != current_owner
                    or entry.owner_version != current_owner_version
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Intent state history is not bound to the current owner",
                        details={"sequence": entry.sequence},
                    )
                projection = expected_attempts[current_owner]
                if entry.attempt_state not in _ATTEMPT_TRANSITIONS[projection.state]:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Intent state history contains an illegal transition",
                        details={"sequence": entry.sequence},
                    )
                expected_attempts[current_owner] = _AttemptProjection(
                    entry.attempt_state,
                    projection.version + 1,
                    entry.evidence_digest,
                )
            else:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Intent history contains an unknown event type",
                    details={"sequence": entry.sequence},
                )

        if current_owner is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Intent ledger has no replayable owner",
            )
        attempt_rows = self._connection.execute(
            "SELECT * FROM enforced_intent_attempts "
            "WHERE tenant_id = ? AND intent_hash = ? ORDER BY transaction_id",
            (tenant_id, intent_hash),
        ).fetchall()
        actual_attempts = {
            str(row["transaction_id"]): self._intent_attempt_from_row(row) for row in attempt_rows
        }
        if set(actual_attempts) != set(expected_attempts):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Intent attempt projections differ from replayed history",
            )
        for transaction_id, expected in expected_attempts.items():
            actual = actual_attempts[transaction_id]
            if (
                actual.state is not expected.state
                or actual.version != expected.version
                or actual.evidence_digest != expected.evidence_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Intent attempt projection differs from replayed history",
                    details={"transaction_id": transaction_id},
                )

        head = entries[-1]
        owner_transaction_id = str(owner["owner_transaction_id"])
        owner_version = int(owner["owner_version"])
        head_sequence = int(owner["history_head_sequence"])
        head_digest = (
            None if owner["history_head_digest"] is None else str(owner["history_head_digest"])
        )
        _parse_timestamp(owner["acquired_at"])
        _parse_timestamp(owner["updated_at"])
        if (
            owner_transaction_id != current_owner
            or owner_version != current_owner_version
            or head_sequence != head.sequence
            or head_digest != head.history_digest
            or head_digest is None
            or _DIGEST_PATTERN.fullmatch(head_digest) is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Intent owner projection or durable history head is inconsistent",
            )
        return _ValidatedIntentLedger(
            owner_transaction_id=owner_transaction_id,
            owner_version=owner_version,
            owner_state=expected_attempts[current_owner].state,
            head_sequence=head_sequence,
            head_digest=head_digest,
            entries=entries,
        )

    def _append_intent_history(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
        transaction_id: str,
        event_type: str,
        disposition: IntentDisposition | None,
        attempt_state: IntentAttemptState,
        owner_transaction_id: str,
        owner_version: int,
        evidence_digest: str | None,
        recorded_at: str,
    ) -> IntentHistoryEntry:
        owner = self._connection.execute(
            "SELECT owner_transaction_id, owner_version, history_head_sequence, "
            "history_head_digest FROM enforced_intent_owners "
            "WHERE tenant_id = ? AND intent_hash = ?",
            (tenant_id, intent_hash),
        ).fetchone()
        if (
            owner is None
            or str(owner["owner_transaction_id"]) != owner_transaction_id
            or int(owner["owner_version"]) != owner_version
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Intent history append does not match the owner projection",
            )
        previous_sequence = int(owner["history_head_sequence"])
        previous_digest = (
            None if owner["history_head_digest"] is None else str(owner["history_head_digest"])
        )
        if (previous_sequence == -1) != (previous_digest is None):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Intent owner history head is malformed",
            )
        sequence = previous_sequence + 1
        payload: dict[str, object] = {
            "profile": "agentkernel.intent-attempt-history/v1",
            "tenant_id": tenant_id,
            "intent_hash": intent_hash,
            "sequence": sequence,
            "transaction_id": transaction_id,
            "event_type": event_type,
            "disposition": disposition.value if disposition is not None else None,
            "attempt_state": attempt_state.value,
            "owner_transaction_id": owner_transaction_id,
            "owner_version": owner_version,
            "evidence_digest": evidence_digest,
            "previous_history_digest": previous_digest,
            "recorded_at": recorded_at,
        }
        history_digest = canonical_digest(payload)
        self._execute(
            "INSERT INTO enforced_intent_attempt_history"
            "(tenant_id, intent_hash, sequence, transaction_id, event_type, disposition, "
            "attempt_state, owner_transaction_id, owner_version, evidence_digest, "
            "previous_history_digest, history_digest, recorded_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tenant_id,
                intent_hash,
                sequence,
                transaction_id,
                event_type,
                disposition.value if disposition is not None else None,
                attempt_state.value,
                owner_transaction_id,
                owner_version,
                evidence_digest,
                previous_digest,
                history_digest,
                recorded_at,
            ),
        )
        head_updated = self._execute(
            "UPDATE enforced_intent_owners SET history_head_sequence = ?, "
            "history_head_digest = ?, updated_at = ? "
            "WHERE tenant_id = ? AND intent_hash = ? AND owner_transaction_id = ? "
            "AND owner_version = ? AND history_head_sequence = ? "
            "AND history_head_digest IS ?",
            (
                sequence,
                history_digest,
                recorded_at,
                tenant_id,
                intent_hash,
                owner_transaction_id,
                owner_version,
                previous_sequence,
                previous_digest,
            ),
        )
        if head_updated.rowcount != 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Intent history head compare-and-swap failed",
            )
        return IntentHistoryEntry(
            tenant_id=tenant_id,
            intent_hash=intent_hash,
            sequence=sequence,
            transaction_id=transaction_id,
            event_type=event_type,
            disposition=disposition,
            attempt_state=attempt_state,
            owner_transaction_id=owner_transaction_id,
            owner_version=owner_version,
            evidence_digest=evidence_digest,
            previous_history_digest=previous_digest,
            history_digest=history_digest,
            recorded_at=_parse_timestamp(recorded_at),
        )

    def acquire_intent(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
        transaction_id: str,
        attempted_at: datetime,
        expected_owner_version: int | None = None,
    ) -> IntentAcquisition:
        """Acquire or alias an intent owner, transferring only proven no-effect ownership."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        intent_hash = _require_digest(intent_hash, field="intent_hash")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        if expected_owner_version is not None and expected_owner_version < 0:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Expected owner version cannot be negative",
            )
        timestamp = _timestamp(attempted_at)
        try:
            with self._immediate():
                self._require_action_intent(tenant_id, transaction_id, intent_hash)
                owner_exists = self._connection.execute(
                    "SELECT 1 FROM enforced_intent_owners WHERE tenant_id = ? AND intent_hash = ?",
                    (tenant_id, intent_hash),
                ).fetchone()
                ledger = (
                    None
                    if owner_exists is None
                    else self._validate_intent_ledger(tenant_id, intent_hash)
                )
                if owner_exists is None:
                    self._assert_intent_ledger_absent(tenant_id, intent_hash)
                self._execute(
                    "INSERT OR IGNORE INTO enforced_intent_attempts"
                    "(tenant_id, intent_hash, transaction_id, attempt_state, state_version, "
                    "evidence_digest, created_at, updated_at) "
                    "VALUES (?, ?, ?, 'ACTIVE', 0, NULL, ?, ?)",
                    (tenant_id, intent_hash, transaction_id, timestamp, timestamp),
                )
                previous_owner: str | None = None
                if ledger is None:
                    self._execute(
                        "INSERT INTO enforced_intent_owners"
                        "(tenant_id, intent_hash, owner_transaction_id, owner_version, "
                        "history_head_sequence, history_head_digest, acquired_at, updated_at) "
                        "VALUES (?, ?, ?, 0, -1, NULL, ?, ?)",
                        (tenant_id, intent_hash, transaction_id, timestamp, timestamp),
                    )
                    owner_transaction_id = transaction_id
                    owner_version = 0
                    owner_state = IntentAttemptState.ACTIVE
                    disposition = IntentDisposition.ACQUIRED
                else:
                    owner_transaction_id = ledger.owner_transaction_id
                    owner_version = ledger.owner_version
                    owner_state = ledger.owner_state

                    if owner_transaction_id == transaction_id:
                        disposition = IntentDisposition.SAME_TRANSACTION
                    elif owner_state is IntentAttemptState.ACTIVE:
                        disposition = IntentDisposition.ALIAS_ACTIVE
                    elif owner_state is IntentAttemptState.RECONCILE_REQUIRED:
                        disposition = IntentDisposition.ALIAS_RECONCILE
                    elif owner_state is IntentAttemptState.COMMITTED:
                        disposition = IntentDisposition.ALIAS_COMMITTED
                    elif owner_state is IntentAttemptState.REVIEW_REQUIRED:
                        disposition = IntentDisposition.REVIEW_REQUIRED
                    else:
                        requested_attempt = self._connection.execute(
                            "SELECT * FROM enforced_intent_attempts "
                            "WHERE tenant_id = ? AND intent_hash = ? AND transaction_id = ?",
                            (tenant_id, intent_hash, transaction_id),
                        ).fetchone()
                        requested_state = (
                            None
                            if requested_attempt is None
                            else self._intent_attempt_from_row(requested_attempt).state.value
                        )
                        active_capability_reservation = self._connection.execute(
                            "SELECT 1 FROM enforced_capability_chain_reservations "
                            "WHERE tenant_id = ? AND intent_hash = ? "
                            "AND reservation_state != 'RELEASED' LIMIT 1",
                            (tenant_id, intent_hash),
                        ).fetchone()
                        if (
                            requested_state != IntentAttemptState.ACTIVE.value
                            or active_capability_reservation is not None
                            or (
                                expected_owner_version is not None
                                and expected_owner_version != owner_version
                            )
                        ):
                            disposition = IntentDisposition.REVIEW_REQUIRED
                        else:
                            updated = self._execute(
                                "UPDATE enforced_intent_owners "
                                "SET owner_transaction_id = ?, owner_version = owner_version + 1, "
                                "updated_at = ? WHERE tenant_id = ? AND intent_hash = ? "
                                "AND owner_transaction_id = ? AND owner_version = ? "
                                "AND history_head_sequence = ? AND history_head_digest IS ?",
                                (
                                    transaction_id,
                                    timestamp,
                                    tenant_id,
                                    intent_hash,
                                    owner_transaction_id,
                                    owner_version,
                                    ledger.head_sequence,
                                    ledger.head_digest,
                                ),
                            )
                            if updated.rowcount != 1:
                                disposition = IntentDisposition.REVIEW_REQUIRED
                            else:
                                previous_owner = owner_transaction_id
                                owner_transaction_id = transaction_id
                                owner_version += 1
                                owner_state = IntentAttemptState.ACTIVE
                                disposition = IntentDisposition.TRANSFERRED_NO_EFFECT

                self._append_intent_history(
                    tenant_id=tenant_id,
                    intent_hash=intent_hash,
                    transaction_id=transaction_id,
                    event_type="ACQUIRE",
                    disposition=disposition,
                    attempt_state=owner_state,
                    owner_transaction_id=owner_transaction_id,
                    owner_version=owner_version,
                    evidence_digest=None,
                    recorded_at=timestamp,
                )
                self._validate_intent_ledger(tenant_id, intent_hash)
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Intent acquisition failed closed", error) from error
        return IntentAcquisition(
            disposition=disposition,
            tenant_id=tenant_id,
            intent_hash=intent_hash,
            transaction_id=transaction_id,
            owner_transaction_id=owner_transaction_id,
            owner_version=owner_version,
            previous_owner_transaction_id=previous_owner,
        )

    def record_intent_attempt_state(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
        transaction_id: str,
        expected_version: int,
        state: IntentAttemptState | str,
        evidence_digest: str,
        recorded_at: datetime,
    ) -> IntentAttemptRecord:
        """CAS the current owner's evidence state and append hash-chained history."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        intent_hash = _require_digest(intent_hash, field="intent_hash")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        if expected_version < 0:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR, "Expected version cannot be negative"
            )
        target_state = _coerce_attempt_state(state)
        if target_state is IntentAttemptState.ACTIVE:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "ACTIVE is established only by intent acquisition",
            )
        evidence_digest = _require_digest(evidence_digest, field="evidence_digest")
        timestamp = _timestamp(recorded_at)
        with self._immediate():
            ledger = self._validate_intent_ledger(tenant_id, intent_hash)
            if ledger.owner_transaction_id != transaction_id:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Only the current intent owner may change attempt state",
                )
            row = self._connection.execute(
                "SELECT * FROM enforced_intent_attempts "
                "WHERE tenant_id = ? AND intent_hash = ? AND transaction_id = ?",
                (tenant_id, intent_hash, transaction_id),
            ).fetchone()
            if row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Current intent owner has no attempt state",
                )
            current_state = IntentAttemptState(str(row["attempt_state"]))
            current_version = int(row["state_version"])
            current_evidence = (
                None if row["evidence_digest"] is None else str(row["evidence_digest"])
            )
            if current_state is target_state and current_evidence == evidence_digest:
                return self._intent_attempt_from_row(row)
            if current_version != expected_version:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Intent attempt state changed",
                    details={"expected": expected_version, "actual": current_version},
                    retryable=True,
                )
            if target_state not in _ATTEMPT_TRANSITIONS[current_state]:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Intent attempt state transition is not legal",
                    details={"from": current_state.value, "to": target_state.value},
                )
            updated = self._execute(
                "UPDATE enforced_intent_attempts SET attempt_state = ?, "
                "state_version = state_version + 1, evidence_digest = ?, updated_at = ? "
                "WHERE tenant_id = ? AND intent_hash = ? AND transaction_id = ? "
                "AND state_version = ? AND attempt_state = ?",
                (
                    target_state.value,
                    evidence_digest,
                    timestamp,
                    tenant_id,
                    intent_hash,
                    transaction_id,
                    expected_version,
                    current_state.value,
                ),
            )
            if updated.rowcount != 1:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Intent attempt compare-and-swap failed",
                    retryable=True,
                )
            self._append_intent_history(
                tenant_id=tenant_id,
                intent_hash=intent_hash,
                transaction_id=transaction_id,
                event_type="STATE_CHANGED",
                disposition=None,
                attempt_state=target_state,
                owner_transaction_id=transaction_id,
                owner_version=ledger.owner_version,
                evidence_digest=evidence_digest,
                recorded_at=timestamp,
            )
            self._validate_intent_ledger(tenant_id, intent_hash)
            final_row = self._connection.execute(
                "SELECT * FROM enforced_intent_attempts "
                "WHERE tenant_id = ? AND intent_hash = ? AND transaction_id = ?",
                (tenant_id, intent_hash, transaction_id),
            ).fetchone()
            if final_row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Intent attempt disappeared inside its transaction",
                )
            return self._intent_attempt_from_row(final_row)

    @staticmethod
    def _intent_attempt_from_row(row: sqlite3.Row) -> IntentAttemptRecord:
        try:
            state = IntentAttemptState(str(row["attempt_state"]))
        except ValueError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored intent attempt state is invalid",
            ) from error
        evidence = None if row["evidence_digest"] is None else str(row["evidence_digest"])
        if state is IntentAttemptState.ACTIVE and evidence is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Active intent attempt unexpectedly contains terminal evidence",
            )
        if state is not IntentAttemptState.ACTIVE and (
            evidence is None or _DIGEST_PATTERN.fullmatch(evidence) is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Terminal or uncertain intent attempt lacks valid evidence",
            )
        return IntentAttemptRecord(
            tenant_id=str(row["tenant_id"]),
            intent_hash=str(row["intent_hash"]),
            transaction_id=str(row["transaction_id"]),
            state=state,
            version=int(row["state_version"]),
            evidence_digest=evidence,
            created_at=_parse_timestamp(row["created_at"]),
            updated_at=_parse_timestamp(row["updated_at"]),
        )

    def get_intent_attempt(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
        transaction_id: str,
    ) -> IntentAttemptRecord:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        intent_hash = _require_digest(intent_hash, field="intent_hash")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        with self._read_snapshot():
            self._validate_intent_ledger(tenant_id, intent_hash)
            row = self._connection.execute(
                "SELECT * FROM enforced_intent_attempts "
                "WHERE tenant_id = ? AND intent_hash = ? AND transaction_id = ?",
                (tenant_id, intent_hash, transaction_id),
            ).fetchone()
            if row is None:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Unknown intent attempt in this tenant",
                )
            return self._intent_attempt_from_row(row)

    def list_intent_history(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
    ) -> tuple[IntentHistoryEntry, ...]:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        intent_hash = _require_digest(intent_hash, field="intent_hash")
        with self._read_snapshot():
            return self._validate_intent_ledger(tenant_id, intent_hash).entries

    @staticmethod
    def _capability_registration_digest(
        *,
        tenant_id: str,
        capability_id: str,
        goal_id: str,
        run_id: str,
        max_uses: int,
    ) -> str:
        return canonical_digest(
            {
                "profile": "agentkernel.capability-budget-registration/v1",
                "tenant_id": tenant_id,
                "capability_id": capability_id,
                "goal_id": goal_id,
                "run_id": run_id,
                "max_uses": max_uses,
            }
        )

    @staticmethod
    def _capability_request_digest(
        *,
        tenant_id: str,
        goal_id: str,
        run_id: str,
        intent_hash: str,
        capability_ids: tuple[str, ...],
    ) -> str:
        return canonical_digest(
            {
                "profile": "agentkernel.capability-chain-reservation/v1",
                "tenant_id": tenant_id,
                "goal_id": goal_id,
                "run_id": run_id,
                "intent_hash": intent_hash,
                "capability_ids": capability_ids,
                "units_per_capability": 1,
            }
        )

    @staticmethod
    def _validated_capability_ids(capability_ids: Sequence[str]) -> tuple[str, ...]:
        if isinstance(capability_ids, str):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Capability chain must be a sequence of identifiers",
            )
        values = tuple(
            _require_identifier(value, field="capability_id") for value in capability_ids
        )
        if not values:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "At least one capability budget is required",
            )
        if len(values) > _MAX_CAPABILITY_CHAIN:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Capability chain exceeds the configured bound",
            )
        if len(set(values)) != len(values) or values != tuple(sorted(values)):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Capability chain identifiers must be sorted and unique",
            )
        return values

    @staticmethod
    def _validated_capability_fence(
        fence: CapabilityReservationFence,
    ) -> CapabilityReservationFence:
        if not isinstance(fence, CapabilityReservationFence):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Capability transition requires a reservation fence",
            )
        if (
            isinstance(fence.reservation_version, bool)
            or not isinstance(fence.reservation_version, int)
            or fence.reservation_version < 0
            or fence.reservation_version % 2 != 0
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Capability reservation fence has an invalid activation version",
            )
        owner_values = (
            fence.activation_owner_transaction_id,
            fence.activation_owner_version,
            fence.activation_history_sequence,
            fence.activation_history_digest,
        )
        if any(value is None for value in owner_values) != all(
            value is None for value in owner_values
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Capability reservation fence has an incomplete owner binding",
            )
        if fence.activation_owner_transaction_id is not None:
            _require_identifier(
                fence.activation_owner_transaction_id,
                field="activation_owner_transaction_id",
            )
            if (
                isinstance(fence.activation_owner_version, bool)
                or not isinstance(fence.activation_owner_version, int)
                or fence.activation_owner_version < 0
                or isinstance(fence.activation_history_sequence, bool)
                or not isinstance(fence.activation_history_sequence, int)
                or fence.activation_history_sequence < 0
            ):
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Capability reservation fence has an invalid owner version",
                )
            if fence.activation_history_digest is None:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Capability reservation fence has no activation-history digest",
                )
            _require_digest(
                fence.activation_history_digest,
                field="activation_history_digest",
            )
        return fence

    @staticmethod
    def _assert_capability_fence(
        current: CapabilityChainReservation,
        fence: CapabilityReservationFence,
    ) -> None:
        activation_version = (
            current.version
            if current.state is CapabilityReservationState.RESERVED
            else current.version - 1
        )
        if (
            activation_version != fence.reservation_version
            or current.activation_owner_transaction_id != fence.activation_owner_transaction_id
            or current.activation_owner_version != fence.activation_owner_version
            or current.activation_history_sequence != fence.activation_history_sequence
            or current.activation_history_digest != fence.activation_history_digest
        ):
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Capability transition fence no longer matches the active reservation",
                details={
                    "expected_reservation_version": fence.reservation_version,
                    "actual_activation_version": activation_version,
                },
                retryable=False,
            )

    @staticmethod
    def _is_owner_neutral_acquisition(
        entry: IntentHistoryEntry,
        *,
        owner_transaction_id: str,
        owner_version: int,
        no_effect_ready: bool,
    ) -> bool:
        if (
            entry.event_type != "ACQUIRE"
            or entry.evidence_digest is not None
            or entry.owner_transaction_id != owner_transaction_id
            or entry.owner_version != owner_version
        ):
            return False
        expected_state = (
            IntentAttemptState.NO_EFFECT_CONFIRMED if no_effect_ready else IntentAttemptState.ACTIVE
        )
        return (
            (
                entry.disposition is IntentDisposition.SAME_TRANSACTION
                and entry.transaction_id == owner_transaction_id
                and entry.attempt_state is expected_state
            )
            or (
                not no_effect_ready
                and entry.disposition is IntentDisposition.ALIAS_ACTIVE
                and entry.transaction_id != owner_transaction_id
                and entry.attempt_state is IntentAttemptState.ACTIVE
            )
            or (
                no_effect_ready
                and entry.disposition is IntentDisposition.REVIEW_REQUIRED
                and entry.transaction_id != owner_transaction_id
                and entry.attempt_state is IntentAttemptState.NO_EFFECT_CONFIRMED
            )
        )

    def register_capability_budget(
        self,
        *,
        tenant_id: str,
        capability_id: str,
        goal_id: str,
        run_id: str,
        max_uses: int,
        registered_at: datetime,
    ) -> CapabilityBudget:
        """Pre-register one immutable goal/run-bound budget before any reservation."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        capability_id = _require_identifier(capability_id, field="capability_id")
        goal_id = _require_identifier(goal_id, field="goal_id")
        run_id = _require_identifier(run_id, field="run_id")
        if (
            isinstance(max_uses, bool)
            or not isinstance(max_uses, int)
            or not 1 <= max_uses <= _MAX_SQLITE_INTEGER
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Capability maximum uses must fit a positive SQLite integer",
            )
        timestamp = _timestamp(registered_at)
        registration_digest = self._capability_registration_digest(
            tenant_id=tenant_id,
            capability_id=capability_id,
            goal_id=goal_id,
            run_id=run_id,
            max_uses=max_uses,
        )
        try:
            with self._immediate():
                self._execute(
                    "INSERT OR IGNORE INTO enforced_capability_budgets"
                    "(tenant_id, capability_id, goal_id, run_id, max_uses, reserved_uses, "
                    "committed_uses, version, registration_digest, registered_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 0, 0, 0, ?, ?, ?)",
                    (
                        tenant_id,
                        capability_id,
                        goal_id,
                        run_id,
                        max_uses,
                        registration_digest,
                        timestamp,
                        timestamp,
                    ),
                )
                row = self._connection.execute(
                    "SELECT * FROM enforced_capability_budgets "
                    "WHERE tenant_id = ? AND capability_id = ? AND goal_id = ? AND run_id = ?",
                    (tenant_id, capability_id, goal_id, run_id),
                ).fetchone()
                if row is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Capability budget disappeared inside its transaction",
                    )
                budget = self._capability_budget_from_row(row)
                if budget.max_uses != max_uses or budget.registration_digest != registration_digest:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Capability budget is already registered with different immutable bounds",
                    )
                return budget
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity(
                "Capability budget registration failed closed", error
            ) from error

    @classmethod
    def _capability_budget_from_row(cls, row: sqlite3.Row) -> CapabilityBudget:
        tenant_id = str(row["tenant_id"])
        capability_id = str(row["capability_id"])
        goal_id = str(row["goal_id"])
        run_id = str(row["run_id"])
        max_uses = int(row["max_uses"])
        reserved_uses = int(row["reserved_uses"])
        committed_uses = int(row["committed_uses"])
        version = int(row["version"])
        registration_digest = str(row["registration_digest"])
        expected_digest = cls._capability_registration_digest(
            tenant_id=tenant_id,
            capability_id=capability_id,
            goal_id=goal_id,
            run_id=run_id,
            max_uses=max_uses,
        )
        if (
            registration_digest != expected_digest
            or min(max_uses, version, reserved_uses, committed_uses) < 0
            or max_uses < 1
            or reserved_uses + committed_uses > max_uses
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored capability budget is inconsistent",
            )
        return CapabilityBudget(
            tenant_id=tenant_id,
            capability_id=capability_id,
            goal_id=goal_id,
            run_id=run_id,
            max_uses=max_uses,
            reserved_uses=reserved_uses,
            committed_uses=committed_uses,
            version=version,
            registration_digest=registration_digest,
            registered_at=_parse_timestamp(row["registered_at"]),
            updated_at=_parse_timestamp(row["updated_at"]),
        )

    def get_capability_budget(
        self,
        *,
        tenant_id: str,
        capability_id: str,
        goal_id: str,
        run_id: str,
    ) -> CapabilityBudget:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        capability_id = _require_identifier(capability_id, field="capability_id")
        goal_id = _require_identifier(goal_id, field="goal_id")
        run_id = _require_identifier(run_id, field="run_id")
        row = self._connection.execute(
            "SELECT * FROM enforced_capability_budgets "
            "WHERE tenant_id = ? AND capability_id = ? AND goal_id = ? AND run_id = ?",
            (tenant_id, capability_id, goal_id, run_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Capability budget is not registered in this tenant and run",
            )
        return self._capability_budget_from_row(row)

    def _read_capability_chain(
        self,
        *,
        tenant_id: str,
        goal_id: str,
        run_id: str,
        intent_hash: str,
        expected_capability_ids: tuple[str, ...] | None = None,
    ) -> CapabilityChainReservation | None:
        row = self._connection.execute(
            "SELECT * FROM enforced_capability_chain_reservations "
            "WHERE tenant_id = ? AND goal_id = ? AND run_id = ? AND intent_hash = ?",
            (tenant_id, goal_id, run_id, intent_hash),
        ).fetchone()
        if row is None:
            return None
        item_rows = self._connection.execute(
            "SELECT capability_id, chain_ordinal, request_digest, reservation_state "
            "FROM enforced_capability_use_reservations "
            "WHERE tenant_id = ? AND goal_id = ? AND run_id = ? AND intent_hash = ? "
            "ORDER BY chain_ordinal",
            (tenant_id, goal_id, run_id, intent_hash),
        ).fetchall()
        capability_ids = tuple(str(item["capability_id"]) for item in item_rows)
        request_digest = self._capability_request_digest(
            tenant_id=tenant_id,
            goal_id=goal_id,
            run_id=run_id,
            intent_hash=intent_hash,
            capability_ids=capability_ids,
        )
        try:
            state = CapabilityReservationState(str(row["reservation_state"]))
        except ValueError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored capability chain state is invalid",
            ) from error
        version = int(row["version"])
        activation_owner_transaction_id = (
            None
            if row["activation_owner_transaction_id"] is None
            else str(row["activation_owner_transaction_id"])
        )
        activation_owner_version = (
            None
            if row["activation_owner_version"] is None
            else int(row["activation_owner_version"])
        )
        activation_history_sequence = (
            None
            if row["activation_history_sequence"] is None
            else int(row["activation_history_sequence"])
        )
        activation_history_digest = (
            None
            if row["activation_history_digest"] is None
            else str(row["activation_history_digest"])
        )
        release_history_sequence = (
            None
            if row["release_history_sequence"] is None
            else int(row["release_history_sequence"])
        )
        release_history_digest = (
            None if row["release_history_digest"] is None else str(row["release_history_digest"])
        )
        activation_values = (
            activation_owner_transaction_id,
            activation_owner_version,
            activation_history_sequence,
            activation_history_digest,
        )
        release_values = (release_history_sequence, release_history_digest)
        if (
            not item_rows
            or any(int(item["chain_ordinal"]) != index for index, item in enumerate(item_rows))
            or str(row["request_digest"]) != request_digest
            or any(str(item["request_digest"]) != request_digest for item in item_rows)
            or any(str(item["reservation_state"]) != state.value for item in item_rows)
            or (expected_capability_ids is not None and capability_ids != expected_capability_ids)
            or any(value is None for value in activation_values)
            != all(value is None for value in activation_values)
            or any(value is None for value in release_values)
            != all(value is None for value in release_values)
            or (activation_owner_version is not None and activation_owner_version < 0)
            or (activation_history_sequence is not None and activation_history_sequence < 0)
            or (release_history_sequence is not None and release_history_sequence < 0)
            or version < 0
            or (state is CapabilityReservationState.RESERVED and version % 2 != 0)
            or (state is not CapabilityReservationState.RESERVED and version % 2 != 1)
            or (
                activation_history_digest is not None
                and _DIGEST_PATTERN.fullmatch(activation_history_digest) is None
            )
            or (
                release_history_digest is not None
                and _DIGEST_PATTERN.fullmatch(release_history_digest) is None
            )
            or (state is not CapabilityReservationState.RELEASED and release_history_digest)
            or (
                state is CapabilityReservationState.RELEASED
                and activation_owner_transaction_id is not None
                and release_history_digest is None
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Capability chain reservation is incomplete or inconsistent",
            )
        if activation_owner_transaction_id is not None:
            if (
                activation_owner_version is None
                or activation_history_sequence is None
                or activation_history_digest is None
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Capability activation owner binding is incomplete",
                )
            ledger = self._validate_intent_ledger(tenant_id, intent_hash)
            if activation_history_sequence >= len(ledger.entries):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Capability activation references an absent intent-history entry",
                )
            activation_entry = ledger.entries[activation_history_sequence]
            if (
                activation_entry.history_digest != activation_history_digest
                or activation_entry.owner_transaction_id != activation_owner_transaction_id
                or activation_entry.owner_version != activation_owner_version
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Capability activation owner binding differs from intent history",
                )
            if release_history_sequence is not None:
                if release_history_digest is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Capability release history binding is incomplete",
                    )
                if release_history_sequence >= len(ledger.entries):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Capability release references an absent intent-history entry",
                    )
                release_entry = ledger.entries[release_history_sequence]
                if (
                    release_history_sequence < activation_history_sequence
                    or release_entry.history_digest != release_history_digest
                    or release_entry.owner_transaction_id != activation_owner_transaction_id
                    or release_entry.owner_version != activation_owner_version
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Capability release owner binding differs from intent history",
                    )
            if state is not CapabilityReservationState.RELEASED and (
                ledger.owner_transaction_id != activation_owner_transaction_id
                or ledger.owner_version != activation_owner_version
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Active capability reservation no longer matches the intent owner",
                )
        _parse_timestamp(row["created_at"])
        _parse_timestamp(row["updated_at"])
        return CapabilityChainReservation(
            tenant_id=tenant_id,
            goal_id=goal_id,
            run_id=run_id,
            intent_hash=intent_hash,
            capability_ids=capability_ids,
            request_digest=request_digest,
            state=state,
            version=version,
            activation_owner_transaction_id=activation_owner_transaction_id,
            activation_owner_version=activation_owner_version,
            activation_history_sequence=activation_history_sequence,
            activation_history_digest=activation_history_digest,
            release_history_sequence=release_history_sequence,
            release_history_digest=release_history_digest,
            changed=False,
        )

    def _available_capability_budget_rows(
        self,
        *,
        tenant_id: str,
        goal_id: str,
        run_id: str,
        capability_ids: tuple[str, ...],
    ) -> tuple[sqlite3.Row, ...]:
        budget_rows: list[sqlite3.Row] = []
        for capability_id in capability_ids:
            budget_row = self._connection.execute(
                "SELECT * FROM enforced_capability_budgets "
                "WHERE tenant_id = ? AND capability_id = ? "
                "AND goal_id = ? AND run_id = ?",
                (tenant_id, capability_id, goal_id, run_id),
            ).fetchone()
            if budget_row is None:
                raise AgentKernelError(
                    ErrorCode.AUTHORITY_MISSING,
                    "Capability chain includes an unregistered budget",
                    details={"capability_id": capability_id},
                )
            budget = self._capability_budget_from_row(budget_row)
            if budget.reserved_uses + budget.committed_uses >= budget.max_uses:
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Capability use budget is exhausted",
                    details={"capability_id": capability_id},
                )
            budget_rows.append(budget_row)
        return tuple(budget_rows)

    def _reactivate_released_capability_chain(
        self,
        current: CapabilityChainReservation,
        *,
        reactivated_at: str,
    ) -> CapabilityChainReservation:
        if (
            current.activation_owner_transaction_id is None
            or current.activation_owner_version is None
            or current.activation_history_sequence is None
            or current.activation_history_digest is None
            or current.release_history_sequence is None
            or current.release_history_digest is None
        ):
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Released capability reservation has no transferable owner evidence",
            )
        ledger = self._validate_intent_ledger(current.tenant_id, current.intent_hash)
        if (
            ledger.owner_transaction_id == current.activation_owner_transaction_id
            or ledger.owner_version <= current.activation_owner_version
        ):
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Released capability reservation requires a proven no-effect owner transfer",
            )

        # Nothing ambiguous or effectful may have occurred under the activation before
        # it was released.  NO_EFFECT_CONFIRMED is the sole admissible state change;
        # replay-proven owner-neutral acquisition observations are harmless no-ops.
        no_effect_before_release = False
        for entry in ledger.entries[
            current.activation_history_sequence + 1 : current.release_history_sequence + 1
        ]:
            if self._is_owner_neutral_acquisition(
                entry,
                owner_transaction_id=current.activation_owner_transaction_id,
                owner_version=current.activation_owner_version,
                no_effect_ready=no_effect_before_release,
            ):
                continue
            if (
                entry.event_type == "STATE_CHANGED"
                and not no_effect_before_release
                and entry.transaction_id == current.activation_owner_transaction_id
                and entry.owner_transaction_id == current.activation_owner_transaction_id
                and entry.owner_version == current.activation_owner_version
                and entry.attempt_state is IntentAttemptState.NO_EFFECT_CONFIRMED
                and entry.evidence_digest is not None
            ):
                no_effect_before_release = True
                continue
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Capability activation history contains ambiguous or effectful evidence",
            )

        release_entry = ledger.entries[current.release_history_sequence]
        expected_owner = current.activation_owner_transaction_id
        expected_owner_version = current.activation_owner_version
        no_effect_ready = release_entry.attempt_state is IntentAttemptState.NO_EFFECT_CONFIRMED
        transfer_count = 0
        for entry in ledger.entries[current.release_history_sequence + 1 :]:
            if self._is_owner_neutral_acquisition(
                entry,
                owner_transaction_id=expected_owner,
                owner_version=expected_owner_version,
                no_effect_ready=no_effect_ready,
            ):
                continue
            if entry.event_type == "STATE_CHANGED":
                if not (
                    not no_effect_ready
                    and entry.transaction_id == expected_owner
                    and entry.owner_transaction_id == expected_owner
                    and entry.owner_version == expected_owner_version
                    and entry.attempt_state is IntentAttemptState.NO_EFFECT_CONFIRMED
                    and entry.evidence_digest is not None
                ):
                    raise AgentKernelError(
                        ErrorCode.AUTHORITY_MISSING,
                        "Capability transfer chain contains ambiguous or effectful evidence",
                    )
                no_effect_ready = True
                continue
            if not (
                entry.event_type == "ACQUIRE"
                and entry.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT
                and no_effect_ready
                and entry.transaction_id == entry.owner_transaction_id
                and entry.owner_transaction_id != expected_owner
                and entry.owner_version == expected_owner_version + 1
                and entry.attempt_state is IntentAttemptState.ACTIVE
                and entry.evidence_digest is None
            ):
                raise AgentKernelError(
                    ErrorCode.AUTHORITY_MISSING,
                    "Capability transfer chain is not contiguous no-effect evidence",
                )
            expected_owner = entry.owner_transaction_id
            expected_owner_version = entry.owner_version
            no_effect_ready = False
            transfer_count += 1

        if (
            transfer_count == 0
            or transfer_count != ledger.owner_version - current.activation_owner_version
            or expected_owner != ledger.owner_transaction_id
            or expected_owner_version != ledger.owner_version
            or ledger.owner_state is not IntentAttemptState.ACTIVE
            or no_effect_ready
        ):
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "No complete no-effect transfer chain follows the capability release",
            )
        budget_rows = self._available_capability_budget_rows(
            tenant_id=current.tenant_id,
            goal_id=current.goal_id,
            run_id=current.run_id,
            capability_ids=current.capability_ids,
        )
        chain_updated = self._execute(
            "UPDATE enforced_capability_chain_reservations "
            "SET reservation_state = 'RESERVED', version = version + 1, "
            "activation_owner_transaction_id = ?, activation_owner_version = ?, "
            "activation_history_sequence = ?, activation_history_digest = ?, "
            "release_history_sequence = NULL, release_history_digest = NULL, updated_at = ? "
            "WHERE tenant_id = ? AND goal_id = ? AND run_id = ? AND intent_hash = ? "
            "AND request_digest = ? AND reservation_state = 'RELEASED' AND version = ? "
            "AND activation_owner_transaction_id = ? AND activation_owner_version = ? "
            "AND activation_history_sequence = ? AND activation_history_digest = ? "
            "AND release_history_sequence = ? AND release_history_digest = ?",
            (
                ledger.owner_transaction_id,
                ledger.owner_version,
                ledger.head_sequence,
                ledger.head_digest,
                reactivated_at,
                current.tenant_id,
                current.goal_id,
                current.run_id,
                current.intent_hash,
                current.request_digest,
                current.version,
                current.activation_owner_transaction_id,
                current.activation_owner_version,
                current.activation_history_sequence,
                current.activation_history_digest,
                current.release_history_sequence,
                current.release_history_digest,
            ),
        )
        if chain_updated.rowcount != 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Released capability chain reactivation compare-and-swap failed",
                retryable=True,
            )
        for capability_id, budget_row in zip(
            current.capability_ids,
            budget_rows,
            strict=True,
        ):
            item_updated = self._execute(
                "UPDATE enforced_capability_use_reservations "
                "SET reservation_state = 'RESERVED', updated_at = ? "
                "WHERE tenant_id = ? AND capability_id = ? AND goal_id = ? "
                "AND run_id = ? AND intent_hash = ? AND request_digest = ? "
                "AND reservation_state = 'RELEASED'",
                (
                    reactivated_at,
                    current.tenant_id,
                    capability_id,
                    current.goal_id,
                    current.run_id,
                    current.intent_hash,
                    current.request_digest,
                ),
            )
            if item_updated.rowcount != 1:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Released capability item reactivation was not atomic",
                )
            budget_updated = self._execute(
                "UPDATE enforced_capability_budgets "
                "SET reserved_uses = reserved_uses + 1, version = version + 1, "
                "updated_at = ? WHERE tenant_id = ? AND capability_id = ? "
                "AND goal_id = ? AND run_id = ? AND version = ? "
                "AND reserved_uses + committed_uses < max_uses",
                (
                    reactivated_at,
                    current.tenant_id,
                    capability_id,
                    current.goal_id,
                    current.run_id,
                    int(budget_row["version"]),
                ),
            )
            if budget_updated.rowcount != 1:
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Capability budget changed or was exhausted during reactivation",
                    details={"capability_id": capability_id},
                    retryable=True,
                )
        return CapabilityChainReservation(
            tenant_id=current.tenant_id,
            goal_id=current.goal_id,
            run_id=current.run_id,
            intent_hash=current.intent_hash,
            capability_ids=current.capability_ids,
            request_digest=current.request_digest,
            state=CapabilityReservationState.RESERVED,
            version=current.version + 1,
            activation_owner_transaction_id=ledger.owner_transaction_id,
            activation_owner_version=ledger.owner_version,
            activation_history_sequence=ledger.head_sequence,
            activation_history_digest=ledger.head_digest,
            release_history_sequence=None,
            release_history_digest=None,
            changed=True,
        )

    def reserve_capability_chain(
        self,
        *,
        tenant_id: str,
        goal_id: str,
        run_id: str,
        intent_hash: str,
        capability_ids: Sequence[str],
        reserved_at: datetime,
    ) -> CapabilityChainReservation:
        """Reserve one use from every capability atomically under ``BEGIN IMMEDIATE``."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        goal_id = _require_identifier(goal_id, field="goal_id")
        run_id = _require_identifier(run_id, field="run_id")
        intent_hash = _require_digest(intent_hash, field="intent_hash")
        normalized_ids = self._validated_capability_ids(capability_ids)
        timestamp = _timestamp(reserved_at)
        request_digest = self._capability_request_digest(
            tenant_id=tenant_id,
            goal_id=goal_id,
            run_id=run_id,
            intent_hash=intent_hash,
            capability_ids=normalized_ids,
        )
        try:
            with self._immediate():
                action = self._connection.execute(
                    "SELECT 1 FROM enforced_normalized_actions "
                    "WHERE tenant_id = ? AND goal_id = ? AND run_id = ? AND intent_hash = ? "
                    "LIMIT 1",
                    (tenant_id, goal_id, run_id, intent_hash),
                ).fetchone()
                if action is None:
                    raise AgentKernelError(
                        ErrorCode.AUTHORITY_MISSING,
                        "Capability reservation is not bound to a normalized action",
                    )
                owner_exists = self._connection.execute(
                    "SELECT 1 FROM enforced_intent_owners WHERE tenant_id = ? AND intent_hash = ?",
                    (tenant_id, intent_hash),
                ).fetchone()
                ledger = (
                    None
                    if owner_exists is None
                    else self._validate_intent_ledger(tenant_id, intent_hash)
                )
                if ledger is None:
                    self._assert_intent_ledger_absent(tenant_id, intent_hash)
                else:
                    owner_action = self._connection.execute(
                        "SELECT 1 FROM enforced_normalized_actions "
                        "WHERE tenant_id = ? AND transaction_id = ? AND intent_hash = ? "
                        "AND goal_id = ? AND run_id = ?",
                        (
                            tenant_id,
                            ledger.owner_transaction_id,
                            intent_hash,
                            goal_id,
                            run_id,
                        ),
                    ).fetchone()
                    if owner_action is None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Capability reservation owner is outside the requested goal or run",
                        )
                existing = self._read_capability_chain(
                    tenant_id=tenant_id,
                    goal_id=goal_id,
                    run_id=run_id,
                    intent_hash=intent_hash,
                )
                if (
                    ledger is not None
                    and ledger.owner_state is not IntentAttemptState.ACTIVE
                    and (
                        existing is None
                        or existing.state is not CapabilityReservationState.COMMITTED
                    )
                ):
                    raise AgentKernelError(
                        ErrorCode.AUTHORITY_MISSING,
                        "Capability reservation requires an active intent owner",
                    )
                if existing is not None:
                    if existing.request_digest != request_digest:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Conflicting retry changed the capability chain",
                        )
                    if existing.state is CapabilityReservationState.RELEASED:
                        return self._reactivate_released_capability_chain(
                            existing,
                            reactivated_at=timestamp,
                        )
                    return existing

                budget_rows = self._available_capability_budget_rows(
                    tenant_id=tenant_id,
                    goal_id=goal_id,
                    run_id=run_id,
                    capability_ids=normalized_ids,
                )
                activation_owner_transaction_id = (
                    None if ledger is None else ledger.owner_transaction_id
                )
                activation_owner_version = None if ledger is None else ledger.owner_version
                activation_history_sequence = None if ledger is None else ledger.head_sequence
                activation_history_digest = None if ledger is None else ledger.head_digest

                self._execute(
                    "INSERT INTO enforced_capability_chain_reservations"
                    "(tenant_id, goal_id, run_id, intent_hash, request_digest, "
                    "reservation_state, activation_owner_transaction_id, "
                    "activation_owner_version, activation_history_sequence, "
                    "activation_history_digest, release_history_sequence, "
                    "release_history_digest, version, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?, ?, NULL, NULL, 0, ?, ?)",
                    (
                        tenant_id,
                        goal_id,
                        run_id,
                        intent_hash,
                        request_digest,
                        activation_owner_transaction_id,
                        activation_owner_version,
                        activation_history_sequence,
                        activation_history_digest,
                        timestamp,
                        timestamp,
                    ),
                )
                for ordinal, (capability_id, budget_row) in enumerate(
                    zip(normalized_ids, budget_rows, strict=True)
                ):
                    self._execute(
                        "INSERT INTO enforced_capability_use_reservations"
                        "(tenant_id, capability_id, goal_id, run_id, intent_hash, "
                        "chain_ordinal, request_digest, reservation_state, created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?, ?)",
                        (
                            tenant_id,
                            capability_id,
                            goal_id,
                            run_id,
                            intent_hash,
                            ordinal,
                            request_digest,
                            timestamp,
                            timestamp,
                        ),
                    )
                    updated = self._execute(
                        "UPDATE enforced_capability_budgets "
                        "SET reserved_uses = reserved_uses + 1, version = version + 1, "
                        "updated_at = ? WHERE tenant_id = ? AND capability_id = ? "
                        "AND goal_id = ? AND run_id = ? AND version = ? "
                        "AND reserved_uses + committed_uses < max_uses",
                        (
                            timestamp,
                            tenant_id,
                            capability_id,
                            goal_id,
                            run_id,
                            int(budget_row["version"]),
                        ),
                    )
                    if updated.rowcount != 1:
                        raise AgentKernelError(
                            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                            "Capability use budget changed or was exhausted during reservation",
                            details={"capability_id": capability_id},
                            retryable=True,
                        )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Capability chain reservation failed closed", error) from error
        return CapabilityChainReservation(
            tenant_id=tenant_id,
            goal_id=goal_id,
            run_id=run_id,
            intent_hash=intent_hash,
            capability_ids=normalized_ids,
            request_digest=request_digest,
            state=CapabilityReservationState.RESERVED,
            version=0,
            activation_owner_transaction_id=activation_owner_transaction_id,
            activation_owner_version=activation_owner_version,
            activation_history_sequence=activation_history_sequence,
            activation_history_digest=activation_history_digest,
            release_history_sequence=None,
            release_history_digest=None,
            changed=True,
        )

    def _transition_capability_chain(
        self,
        *,
        tenant_id: str,
        goal_id: str,
        run_id: str,
        intent_hash: str,
        capability_ids: Sequence[str],
        fence: CapabilityReservationFence,
        transitioned_at: datetime,
        target: CapabilityReservationState,
    ) -> CapabilityChainReservation:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        goal_id = _require_identifier(goal_id, field="goal_id")
        run_id = _require_identifier(run_id, field="run_id")
        intent_hash = _require_digest(intent_hash, field="intent_hash")
        normalized_ids = self._validated_capability_ids(capability_ids)
        fence = self._validated_capability_fence(fence)
        timestamp = _timestamp(transitioned_at)
        request_digest = self._capability_request_digest(
            tenant_id=tenant_id,
            goal_id=goal_id,
            run_id=run_id,
            intent_hash=intent_hash,
            capability_ids=normalized_ids,
        )
        try:
            with self._immediate():
                current = self._read_capability_chain(
                    tenant_id=tenant_id,
                    goal_id=goal_id,
                    run_id=run_id,
                    intent_hash=intent_hash,
                    expected_capability_ids=normalized_ids,
                )
                if current is None:
                    raise AgentKernelError(
                        ErrorCode.AUTHORITY_MISSING,
                        "Capability chain has no durable reservation",
                    )
                if current.request_digest != request_digest:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Capability chain transition does not match its reservation",
                    )
                self._assert_capability_fence(current, fence)
                if current.state is target:
                    return current
                if current.state is not CapabilityReservationState.RESERVED:
                    raise AgentKernelError(
                        ErrorCode.ILLEGAL_TRANSITION,
                        "Capability reservation has already reached a different terminal state",
                        details={"from": current.state.value, "to": target.value},
                    )

                ledger: _ValidatedIntentLedger | None = None
                if current.activation_owner_transaction_id is not None:
                    ledger = self._validate_intent_ledger(tenant_id, intent_hash)
                    if (
                        ledger.owner_transaction_id != current.activation_owner_transaction_id
                        or ledger.owner_version != current.activation_owner_version
                    ):
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Capability transition no longer matches its activation owner",
                            retryable=True,
                        )
                    if (
                        target is CapabilityReservationState.COMMITTED
                        and ledger.owner_state is not IntentAttemptState.ACTIVE
                    ):
                        raise AgentKernelError(
                            ErrorCode.ILLEGAL_TRANSITION,
                            "Capability commit requires an active intent owner",
                            details={"owner_state": ledger.owner_state.value},
                        )
                    if (
                        target is CapabilityReservationState.RELEASED
                        and ledger.owner_state is not IntentAttemptState.NO_EFFECT_CONFIRMED
                    ):
                        raise AgentKernelError(
                            ErrorCode.ILLEGAL_TRANSITION,
                            "Owned capability release requires proven no-effect intent state",
                            details={"owner_state": ledger.owner_state.value},
                        )

                release_history_sequence: int | None = None
                release_history_digest: str | None = None
                if target is CapabilityReservationState.RELEASED and ledger is not None:
                    release_history_sequence = ledger.head_sequence
                    release_history_digest = ledger.head_digest

                chain_updated = self._execute(
                    "UPDATE enforced_capability_chain_reservations "
                    "SET reservation_state = ?, version = version + 1, "
                    "release_history_sequence = ?, release_history_digest = ?, "
                    "updated_at = ? "
                    "WHERE tenant_id = ? AND goal_id = ? AND run_id = ? AND intent_hash = ? "
                    "AND request_digest = ? AND reservation_state = 'RESERVED' AND version = ? "
                    "AND activation_owner_transaction_id IS ? "
                    "AND activation_owner_version IS ? AND activation_history_sequence IS ? "
                    "AND activation_history_digest IS ?",
                    (
                        target.value,
                        release_history_sequence,
                        release_history_digest,
                        timestamp,
                        tenant_id,
                        goal_id,
                        run_id,
                        intent_hash,
                        request_digest,
                        current.version,
                        fence.activation_owner_transaction_id,
                        fence.activation_owner_version,
                        fence.activation_history_sequence,
                        fence.activation_history_digest,
                    ),
                )
                if chain_updated.rowcount != 1:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Capability chain compare-and-swap failed",
                        retryable=True,
                    )

                for capability_id in normalized_ids:
                    item_updated = self._execute(
                        "UPDATE enforced_capability_use_reservations "
                        "SET reservation_state = ?, updated_at = ? "
                        "WHERE tenant_id = ? AND capability_id = ? AND goal_id = ? "
                        "AND run_id = ? AND intent_hash = ? AND request_digest = ? "
                        "AND reservation_state = 'RESERVED'",
                        (
                            target.value,
                            timestamp,
                            tenant_id,
                            capability_id,
                            goal_id,
                            run_id,
                            intent_hash,
                            request_digest,
                        ),
                    )
                    if item_updated.rowcount != 1:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Capability chain item transition was not atomic",
                        )
                    if target is CapabilityReservationState.COMMITTED:
                        counter_sql = (
                            "UPDATE enforced_capability_budgets "
                            "SET reserved_uses = reserved_uses - 1, "
                            "committed_uses = committed_uses + 1, version = version + 1, "
                            "updated_at = ? WHERE tenant_id = ? AND capability_id = ? "
                            "AND goal_id = ? AND run_id = ? AND reserved_uses >= 1"
                        )
                    else:
                        counter_sql = (
                            "UPDATE enforced_capability_budgets "
                            "SET reserved_uses = reserved_uses - 1, version = version + 1, "
                            "updated_at = ? WHERE tenant_id = ? AND capability_id = ? "
                            "AND goal_id = ? AND run_id = ? AND reserved_uses >= 1"
                        )
                    counter_updated = self._execute(
                        counter_sql,
                        (timestamp, tenant_id, capability_id, goal_id, run_id),
                    )
                    if counter_updated.rowcount != 1:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Capability budget counter transition was not atomic",
                        )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity(
                "Capability reservation transition failed closed", error
            ) from error
        return CapabilityChainReservation(
            tenant_id=tenant_id,
            goal_id=goal_id,
            run_id=run_id,
            intent_hash=intent_hash,
            capability_ids=normalized_ids,
            request_digest=request_digest,
            state=target,
            version=current.version + 1,
            activation_owner_transaction_id=current.activation_owner_transaction_id,
            activation_owner_version=current.activation_owner_version,
            activation_history_sequence=current.activation_history_sequence,
            activation_history_digest=current.activation_history_digest,
            release_history_sequence=release_history_sequence,
            release_history_digest=release_history_digest,
            changed=True,
        )

    def commit_capability_chain(
        self,
        *,
        tenant_id: str,
        goal_id: str,
        run_id: str,
        intent_hash: str,
        capability_ids: Sequence[str],
        fence: CapabilityReservationFence,
        committed_at: datetime,
    ) -> CapabilityChainReservation:
        """Commit all reserved uses once; exact retries are idempotent."""

        return self._transition_capability_chain(
            tenant_id=tenant_id,
            goal_id=goal_id,
            run_id=run_id,
            intent_hash=intent_hash,
            capability_ids=capability_ids,
            fence=fence,
            transitioned_at=committed_at,
            target=CapabilityReservationState.COMMITTED,
        )

    def release_capability_chain(
        self,
        *,
        tenant_id: str,
        goal_id: str,
        run_id: str,
        intent_hash: str,
        capability_ids: Sequence[str],
        fence: CapabilityReservationFence,
        released_at: datetime,
    ) -> CapabilityChainReservation:
        """Release all uncommitted uses once; exact retries are idempotent."""

        return self._transition_capability_chain(
            tenant_id=tenant_id,
            goal_id=goal_id,
            run_id=run_id,
            intent_hash=intent_hash,
            capability_ids=capability_ids,
            fence=fence,
            transitioned_at=released_at,
            target=CapabilityReservationState.RELEASED,
        )

    def get_capability_chain(
        self,
        *,
        tenant_id: str,
        goal_id: str,
        run_id: str,
        intent_hash: str,
    ) -> CapabilityChainReservation:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        goal_id = _require_identifier(goal_id, field="goal_id")
        run_id = _require_identifier(run_id, field="run_id")
        intent_hash = _require_digest(intent_hash, field="intent_hash")
        with self._read_snapshot():
            result = self._read_capability_chain(
                tenant_id=tenant_id,
                goal_id=goal_id,
                run_id=run_id,
                intent_hash=intent_hash,
            )
            if result is None:
                raise AgentKernelError(
                    ErrorCode.AUTHORITY_MISSING,
                    "Capability chain has no durable reservation",
                )
            return result

    @staticmethod
    def _canonical_decision_document(
        decision: BaseModel | Mapping[str, object],
    ) -> tuple[dict[str, JsonValue], str]:
        material: object = (
            decision.model_dump(mode="python") if isinstance(decision, BaseModel) else decision
        )
        try:
            rendered = canonical_json_text(material)
            parsed = json.loads(rendered)
        except (AgentKernelError, TypeError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Decision snapshot is not valid canonical JSON",
            ) from error
        if not isinstance(parsed, dict):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Decision snapshot must be a JSON object",
            )
        return cast("dict[str, JsonValue]", parsed), rendered

    @staticmethod
    def _decision_digest(
        *,
        tenant_id: str,
        kind: DecisionKind,
        decision_id: str,
        transaction_id: str,
        intent_hash: str,
        decision: Mapping[str, JsonValue],
    ) -> str:
        return canonical_digest(
            {
                "profile": "agentkernel.control-decision-snapshot/v1",
                "tenant_id": tenant_id,
                "decision_kind": kind.value,
                "decision_id": decision_id,
                "transaction_id": transaction_id,
                "intent_hash": intent_hash,
                "decision": decision,
            }
        )

    def append_decision_snapshot(
        self,
        *,
        tenant_id: str,
        kind: DecisionKind | str,
        decision_id: str,
        transaction_id: str,
        intent_hash: str,
        decision: BaseModel | Mapping[str, object],
        recorded_at: datetime,
    ) -> DecisionSnapshot:
        """Append one immutable authority or policy decision bound to an action."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        kind = _coerce_decision_kind(kind)
        decision_id = _require_identifier(decision_id, field="decision_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        intent_hash = _require_digest(intent_hash, field="intent_hash")
        timestamp = _timestamp(recorded_at)
        document, decision_json = self._canonical_decision_document(decision)
        decision_digest = self._decision_digest(
            tenant_id=tenant_id,
            kind=kind,
            decision_id=decision_id,
            transaction_id=transaction_id,
            intent_hash=intent_hash,
            decision=document,
        )
        try:
            with self._immediate():
                self._require_action_intent(tenant_id, transaction_id, intent_hash)
                existing = self._connection.execute(
                    "SELECT decision_digest FROM enforced_decision_snapshots "
                    "WHERE tenant_id = ? AND decision_kind = ? AND decision_id = ?",
                    (tenant_id, kind.value, decision_id),
                ).fetchone()
                if existing is not None:
                    if str(existing["decision_digest"]) != decision_digest:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Decision identity already has different immutable content",
                        )
                    snapshot = self._get_decision_snapshot(tenant_id, kind, decision_id)
                    return DecisionSnapshot(
                        tenant_id=snapshot.tenant_id,
                        kind=snapshot.kind,
                        decision_id=snapshot.decision_id,
                        transaction_id=snapshot.transaction_id,
                        intent_hash=snapshot.intent_hash,
                        decision_digest=snapshot.decision_digest,
                        decision=snapshot.decision,
                        recorded_at=snapshot.recorded_at,
                        created=False,
                    )
                self._execute(
                    "INSERT INTO enforced_decision_snapshots"
                    "(tenant_id, decision_kind, decision_id, transaction_id, intent_hash, "
                    "decision_digest, decision_json, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        tenant_id,
                        kind.value,
                        decision_id,
                        transaction_id,
                        intent_hash,
                        decision_digest,
                        decision_json,
                        timestamp,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Decision snapshot append failed closed", error) from error
        return DecisionSnapshot(
            tenant_id=tenant_id,
            kind=kind,
            decision_id=decision_id,
            transaction_id=transaction_id,
            intent_hash=intent_hash,
            decision_digest=decision_digest,
            decision=document,
            recorded_at=_parse_timestamp(timestamp),
            created=True,
        )

    def _get_decision_snapshot(
        self,
        tenant_id: str,
        kind: DecisionKind,
        decision_id: str,
    ) -> DecisionSnapshot:
        row = self._connection.execute(
            "SELECT * FROM enforced_decision_snapshots "
            "WHERE tenant_id = ? AND decision_kind = ? AND decision_id = ?",
            (tenant_id, kind.value, decision_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unknown decision snapshot in this tenant",
            )
        try:
            parsed = json.loads(str(row["decision_json"]))
        except (TypeError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored decision snapshot is not valid JSON",
            ) from error
        if not isinstance(parsed, dict):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored decision snapshot is not a JSON object",
            )
        document = cast("dict[str, JsonValue]", parsed)
        transaction_id = str(row["transaction_id"])
        intent_hash = str(row["intent_hash"])
        expected_digest = self._decision_digest(
            tenant_id=tenant_id,
            kind=kind,
            decision_id=decision_id,
            transaction_id=transaction_id,
            intent_hash=intent_hash,
            decision=document,
        )
        if (
            str(row["tenant_id"]) != tenant_id
            or str(row["decision_kind"]) != kind.value
            or str(row["decision_id"]) != decision_id
            or str(row["decision_digest"]) != expected_digest
            or str(row["decision_json"]) != canonical_json_text(document)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored decision snapshot digest or binding is inconsistent",
            )
        self._require_action_intent(tenant_id, transaction_id, intent_hash)
        return DecisionSnapshot(
            tenant_id=tenant_id,
            kind=kind,
            decision_id=decision_id,
            transaction_id=transaction_id,
            intent_hash=intent_hash,
            decision_digest=expected_digest,
            decision=document,
            recorded_at=_parse_timestamp(row["recorded_at"]),
            created=False,
        )

    def get_decision_snapshot(
        self,
        *,
        tenant_id: str,
        kind: DecisionKind | str,
        decision_id: str,
    ) -> DecisionSnapshot:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        kind = _coerce_decision_kind(kind)
        decision_id = _require_identifier(decision_id, field="decision_id")
        return self._get_decision_snapshot(tenant_id, kind, decision_id)
