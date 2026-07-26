"""Atomic SQLite persistence for the enforced single-node transaction coordinator.

The store never performs adapter or model I/O.  Every method completes its durable
compare-and-swap before returning a ``*_NOW`` disposition, so callers cannot mistake an
exact retry for fresh authority to execute an external effect.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Self, cast

from pydantic import ValidationError

from agentkernel.adapters.base import EffectPlan
from agentkernel.authority.evaluator import (
    AuthorityEvaluationVerdict,
    EnforcedAuthorityDecision,
)
from agentkernel.canonical import canonical_digest, canonical_json_text
from agentkernel.domain.enums import (
    AuthorizationRoundPurpose,
    AuthorizationVerdict,
    CommitDispatchState,
    LeasePurpose,
    ReconciliationOutcome,
    RecoveryWorkKind,
    RecoveryWorkState,
    RiskClass,
    StageMaterialState,
    TransactionState,
    VerificationPhase,
)
from agentkernel.domain.models import (
    RECOVERY_ACTION_BINDING_ARGUMENT,
    AuthenticatedActionContext,
    CommitPermit,
    InspectionPermit,
    NormalizedAction,
    RecoveryActionBinding,
    RecoveryPermit,
    StagePermit,
    VerificationPermit,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.policy.aggregation import AggregatePolicyDecision
from agentkernel.policy.engine import PolicyVerdict
from agentkernel.storage.control import (
    CapabilityChainReservation,
    CapabilityReservationState,
    DecisionKind,
    IntentAcquisition,
    IntentAttemptRecord,
    IntentAttemptState,
    IntentDisposition,
    SQLiteControlStore,
    _parse_timestamp,
    _require_digest,
    _require_identifier,
    _sqlite_integrity,
    _timestamp,
)
from agentkernel.transactions.contracts import (
    AuthorizationRoundRecord,
    CommitDispatchRecord,
    DispatchEvidenceUnavailableRecord,
    DispatchOutcomeRecord,
    EnforcedTransactionEvent,
    EnforcedTransactionRecord,
    LateRecoveryReportRecord,
    ReconciliationAttemptRecord,
    RecoveryCompletionReportRecord,
    RecoveryEvidenceUnavailableRecord,
    RecoveryWorkRecord,
    StageMaterialRecord,
    TransactionRecoveryDeadlineRecord,
    WorkerLeaseRecord,
)
from agentkernel.transactions.state_machine import TransitionEvent, apply_transition

_MAX_SCAN_LIMIT = 1_000
_MAX_RECONCILIATION_ATTEMPTS = 32
_EXPIRED_HANDOFF_SETTLEMENT_LEASE_DURATION = timedelta(microseconds=1)
_CONTROL_TRANSITIONS = frozenset(
    {
        TransitionEvent.VALIDATION_FAILED,
        TransitionEvent.CANCELLED,
        TransitionEvent.DEADLINE_EXCEEDED,
        TransitionEvent.CONTEXT_EXITED,
        TransitionEvent.AUTHORITY_OR_POLICY_DENIED,
        TransitionEvent.STAGING_FAILED,
        TransitionEvent.STAGED_VERIFICATION_FAILED,
        TransitionEvent.APPROVAL_REQUIRED,
        TransitionEvent.NO_APPROVAL_REQUIRED,
        TransitionEvent.APPROVAL_GRANTED,
        TransitionEvent.APPROVAL_REJECTED,
        TransitionEvent.TARGET_VERSION_CHANGED,
        TransitionEvent.COMMIT_REVALIDATION_FAILED,
        TransitionEvent.RECOVERY_UNAVAILABLE,
    }
)
_RECOVERY_SCAN_STATES = tuple(state for state in TransactionState if not state.is_terminal)
_RECOVERY_DEADLINE_STATES = frozenset(
    {
        TransactionState.ABORTING,
        TransactionState.FAILED,
        TransactionState.IN_DOUBT,
        TransactionState.RECONCILING,
        TransactionState.ROLLING_BACK,
        TransactionState.COMPENSATING,
    }
)
_TERMINAL_RECONCILIATION_FOLLOW_ON_SQL = (
    "tx.state IN ('FAILED', 'ABORTING') "
    "AND NOT EXISTS (SELECT 1 FROM enforced_recovery_work AS non_reconcile_work "
    "WHERE non_reconcile_work.tenant_id = tx.tenant_id "
    "AND non_reconcile_work.transaction_id = tx.transaction_id "
    "AND non_reconcile_work.kind != 'RECONCILE_DISPATCH') "
    "AND NOT EXISTS (SELECT 1 FROM enforced_recovery_action_handoffs AS "
    "non_reconcile_handoff WHERE non_reconcile_handoff.tenant_id = tx.tenant_id "
    "AND non_reconcile_handoff.target_transaction_id = tx.transaction_id "
    "AND non_reconcile_handoff.recovery_kind != 'RECONCILE_DISPATCH') "
    "AND EXISTS (SELECT 1 FROM enforced_recovery_work AS reconciliation_work "
    "JOIN enforced_reconciliation_attempts AS reconciliation_attempt "
    "ON reconciliation_attempt.tenant_id = reconciliation_work.tenant_id "
    "AND reconciliation_attempt.transaction_id = reconciliation_work.transaction_id "
    "AND reconciliation_attempt.recovery_id = reconciliation_work.recovery_id "
    "AND reconciliation_attempt.attempt = reconciliation_work.attempt "
    "WHERE reconciliation_work.tenant_id = tx.tenant_id "
    "AND reconciliation_work.transaction_id = tx.transaction_id "
    "AND reconciliation_work.kind = 'RECONCILE_DISPATCH' "
    "AND reconciliation_work.state = 'SUCCEEDED' "
    "AND reconciliation_work.recovery_ordinal = ("
    "SELECT MAX(latest_reconciliation.recovery_ordinal) "
    "FROM enforced_recovery_work AS latest_reconciliation "
    "WHERE latest_reconciliation.tenant_id = tx.tenant_id "
    "AND latest_reconciliation.transaction_id = tx.transaction_id "
    "AND latest_reconciliation.kind = 'RECONCILE_DISPATCH') "
    "AND reconciliation_attempt.completed_at IS NOT NULL "
    "AND ((tx.state = 'FAILED' "
    "AND reconciliation_attempt.outcome = 'PARTIAL_OR_INVALID') "
    "OR (tx.state = 'ABORTING' "
    "AND reconciliation_attempt.outcome = 'NO_EFFECT')))"
)
_EXPECTED_TERMINAL_RECONCILIATION_HISTORY_SQL = (
    "NOT EXISTS (SELECT 1 FROM enforced_recovery_work AS non_reconcile_history "
    "WHERE non_reconcile_history.tenant_id = tx.tenant_id "
    "AND non_reconcile_history.transaction_id = tx.transaction_id "
    "AND non_reconcile_history.kind != 'RECONCILE_DISPATCH') "
    "AND EXISTS (SELECT 1 FROM enforced_recovery_work AS reconciliation_history "
    "JOIN enforced_reconciliation_attempts AS reconciliation_history_attempt "
    "ON reconciliation_history_attempt.tenant_id = reconciliation_history.tenant_id "
    "AND reconciliation_history_attempt.transaction_id = "
    "reconciliation_history.transaction_id "
    "AND reconciliation_history_attempt.recovery_id = reconciliation_history.recovery_id "
    "AND reconciliation_history_attempt.attempt = reconciliation_history.attempt "
    "WHERE reconciliation_history.tenant_id = tx.tenant_id "
    "AND reconciliation_history.transaction_id = tx.transaction_id "
    "AND reconciliation_history.kind = 'RECONCILE_DISPATCH' "
    "AND reconciliation_history.state = 'SUCCEEDED' "
    "AND reconciliation_history.recovery_ordinal = ("
    "SELECT MAX(latest_history.recovery_ordinal) "
    "FROM enforced_recovery_work AS latest_history "
    "WHERE latest_history.tenant_id = tx.tenant_id "
    "AND latest_history.transaction_id = tx.transaction_id "
    "AND latest_history.kind = 'RECONCILE_DISPATCH') "
    "AND reconciliation_history_attempt.completed_at IS NOT NULL "
    "AND ((tx.state = 'FAILED' "
    "AND reconciliation_history_attempt.outcome = 'PARTIAL_OR_INVALID') "
    "OR (tx.state = 'ABORTING' "
    "AND reconciliation_history_attempt.outcome = 'NO_EFFECT')))"
)
_OPEN_PREWORK_TARGET_SQL = (
    "((tx.state = 'ABORTING' "
    "AND prework_handoff.recovery_kind = 'DISCARD_STAGING' "
    "AND EXISTS (SELECT 1 FROM enforced_stage_material AS prework_stage "
    "WHERE prework_stage.tenant_id = prework_handoff.tenant_id "
    "AND prework_stage.transaction_id = prework_handoff.target_transaction_id "
    "AND prework_stage.stage_id = prework_handoff.target_id "
    "AND prework_stage.record_digest = prework_handoff.target_evidence_ref)) "
    "OR (tx.state = 'FAILED' "
    "AND prework_handoff.recovery_kind IN ('ROLLBACK', 'COMPENSATE') "
    "AND EXISTS (SELECT 1 FROM enforced_commit_dispatches AS prework_dispatch "
    "WHERE prework_dispatch.tenant_id = prework_handoff.tenant_id "
    "AND prework_dispatch.transaction_id = prework_handoff.target_transaction_id "
    "AND prework_dispatch.dispatch_id = prework_handoff.target_id "
    "AND prework_dispatch.record_digest = prework_handoff.target_evidence_ref)) "
    "OR (tx.state = 'IN_DOUBT' "
    "AND prework_handoff.recovery_kind = 'RECONCILE_DISPATCH' "
    "AND EXISTS (SELECT 1 FROM enforced_commit_dispatches AS prework_dispatch "
    "WHERE prework_dispatch.tenant_id = prework_handoff.tenant_id "
    "AND prework_dispatch.transaction_id = prework_handoff.target_transaction_id "
    "AND prework_dispatch.dispatch_id = prework_handoff.target_id "
    "AND prework_dispatch.state = 'IN_DOUBT' "
    "AND prework_dispatch.record_digest = prework_handoff.target_evidence_ref)))"
)
_OPEN_PREWORK_HANDOFF_BODY_SQL = (
    "SELECT 1 FROM enforced_recovery_action_handoffs AS prework_handoff "  # noqa: S608  # nosec B608
    "JOIN enforced_worker_leases AS latest_prework_lease "
    "ON latest_prework_lease.tenant_id = prework_handoff.tenant_id "
    "AND latest_prework_lease.transaction_id = prework_handoff.target_transaction_id "
    "AND latest_prework_lease.fencing_token >= prework_handoff.handoff_fencing_token "
    "WHERE prework_handoff.tenant_id = tx.tenant_id "
    "AND prework_handoff.target_transaction_id = tx.transaction_id "
    "AND prework_handoff.closed_at IS NULL "
    "AND prework_handoff.failure_evidence_status = 'NONE' "
    "AND ((prework_handoff.recovery_action_transaction_id IS NULL "
    "AND prework_handoff.recovery_action_intent_hash IS NULL "
    "AND prework_handoff.recovery_action_digest IS NULL "
    "AND prework_handoff.attached_at IS NULL) "
    "OR (prework_handoff.recovery_action_transaction_id IS NOT NULL "
    "AND prework_handoff.recovery_action_intent_hash IS NOT NULL "
    "AND prework_handoff.recovery_action_digest IS NOT NULL "
    "AND prework_handoff.attached_at IS NOT NULL "
    "AND EXISTS (SELECT 1 FROM enforced_intent_attempts AS recovery_action_attempt "
    "WHERE recovery_action_attempt.tenant_id = prework_handoff.tenant_id "
    "AND recovery_action_attempt.intent_hash = "
    "prework_handoff.recovery_action_intent_hash "
    "AND recovery_action_attempt.transaction_id = "
    "prework_handoff.recovery_action_transaction_id "
    "AND recovery_action_attempt.attempt_state = 'ACTIVE'))) "
    f"AND ({_OPEN_PREWORK_TARGET_SQL}) "
    "AND NOT EXISTS (SELECT 1 FROM enforced_recovery_work AS linked_prework "
    "WHERE linked_prework.tenant_id = prework_handoff.tenant_id "
    "AND linked_prework.transaction_id = prework_handoff.target_transaction_id "
    "AND linked_prework.recovery_id = prework_handoff.recovery_id) "
    "AND latest_prework_lease.purpose = 'RECOVERY' "
    "AND NOT EXISTS (SELECT 1 FROM enforced_worker_leases AS newer_prework_lease "
    "WHERE newer_prework_lease.tenant_id = latest_prework_lease.tenant_id "
    "AND newer_prework_lease.transaction_id = latest_prework_lease.transaction_id "
    "AND newer_prework_lease.fencing_token > latest_prework_lease.fencing_token)"
)
_NO_RECOVERY_WORK_HISTORY_SQL = (
    "NOT EXISTS (SELECT 1 FROM enforced_recovery_work AS any_prework_history "
    "WHERE any_prework_history.tenant_id = tx.tenant_id "
    "AND any_prework_history.transaction_id = tx.transaction_id)"
)
_RESUMABLE_OPEN_PREWORK_HISTORY_SQL = (
    f"((tx.state = 'ABORTING' "  # nosec B608
    "AND prework_handoff.recovery_kind = 'DISCARD_STAGING' "
    f"AND (({_NO_RECOVERY_WORK_HISTORY_SQL}) "
    f"OR ({_EXPECTED_TERMINAL_RECONCILIATION_HISTORY_SQL}))) "
    "OR (tx.state = 'FAILED' "
    "AND prework_handoff.recovery_kind IN ('ROLLBACK', 'COMPENSATE') "
    f"AND (({_NO_RECOVERY_WORK_HISTORY_SQL}) "
    f"OR ({_EXPECTED_TERMINAL_RECONCILIATION_HISTORY_SQL}))) "
    "OR (tx.state = 'IN_DOUBT' "
    "AND prework_handoff.recovery_kind = 'RECONCILE_DISPATCH' "
    f"AND ({_NO_RECOVERY_WORK_HISTORY_SQL})))"
)
_LIVE_OPEN_PREWORK_HANDOFF_SQL = (
    f"EXISTS ({_OPEN_PREWORK_HANDOFF_BODY_SQL} "
    "AND latest_prework_lease.released_at IS NULL "
    "AND latest_prework_lease.expires_at > ?)"
)
_RESUMABLE_OPEN_PREWORK_HANDOFF_SQL = (
    f"EXISTS ({_OPEN_PREWORK_HANDOFF_BODY_SQL} "
    f"AND ({_RESUMABLE_OPEN_PREWORK_HISTORY_SQL}) "
    "AND ((latest_prework_lease.released_at IS NOT NULL "
    "AND latest_prework_lease.released_at <= ?) "
    "OR latest_prework_lease.expires_at <= ?))"
)


def _lease_bounded_deadline(
    work_deadline: datetime | None,
    lease_expires_at: datetime,
    authority_valid_until: datetime | None,
) -> datetime:
    if work_deadline is None or authority_valid_until is None:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Permit authority requires durable work and authority deadlines",
        )
    return min(work_deadline, lease_expires_at, authority_valid_until)


class EnforcedStoreDisposition(StrEnum):
    """Durable result classification; only fresh authority uses a ``*_NOW`` value."""

    CREATED = "CREATED"
    STORED = "STORED"
    EXACT_RETRY = "EXACT_RETRY"
    PLANNED = "PLANNED"
    ALIAS = "ALIAS"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    STAGE_NOW = "STAGE_NOW"
    COMMIT_NOW = "COMMIT_NOW"
    RECOVERY_NOW = "RECOVERY_NOW"
    RECONCILE_NOW = "RECONCILE_NOW"


@dataclass(frozen=True, slots=True)
class EnforcedTransactionResult:
    transaction: EnforcedTransactionRecord
    event: EnforcedTransactionEvent | None
    disposition: EnforcedStoreDisposition


@dataclass(frozen=True, slots=True)
class PlanningResult:
    transaction: EnforcedTransactionRecord
    event: EnforcedTransactionEvent | None
    acquisition: IntentAcquisition
    disposition: EnforcedStoreDisposition


@dataclass(frozen=True, slots=True)
class AuthorizationResult:
    transaction: EnforcedTransactionRecord
    event: EnforcedTransactionEvent | None
    round: AuthorizationRoundRecord
    reservation: CapabilityChainReservation | None
    disposition: EnforcedStoreDisposition


@dataclass(frozen=True, slots=True)
class WorkerLeaseResult:
    lease: WorkerLeaseRecord
    transaction: EnforcedTransactionRecord
    event: EnforcedTransactionEvent | None
    disposition: EnforcedStoreDisposition


@dataclass(frozen=True, slots=True)
class StageMaterialResult:
    material: StageMaterialRecord
    transaction: EnforcedTransactionRecord
    event: EnforcedTransactionEvent | None
    disposition: EnforcedStoreDisposition


@dataclass(frozen=True, slots=True)
class CommitDispatchResult:
    dispatch: CommitDispatchRecord
    outcome: DispatchOutcomeRecord
    transaction: EnforcedTransactionRecord
    event: EnforcedTransactionEvent | None
    disposition: EnforcedStoreDisposition


@dataclass(frozen=True, slots=True)
class DispatchClassificationResult:
    dispatch: CommitDispatchRecord
    outcome: DispatchOutcomeRecord
    transaction: EnforcedTransactionRecord
    event: EnforcedTransactionEvent | None
    disposition: EnforcedStoreDisposition


@dataclass(frozen=True, slots=True)
class RecoveryAuthorizationResult:
    work: RecoveryWorkRecord
    round: AuthorizationRoundRecord
    reservation: CapabilityChainReservation | None
    disposition: EnforcedStoreDisposition


class RecoveryHandoffFailureEvidenceStatus(StrEnum):
    """Truthful availability state for terminal handoff failure evidence."""

    NONE = "NONE"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


def _require_handoff_failure_evidence(
    failure_evidence_ref: str | None,
    *,
    status: RecoveryHandoffFailureEvidenceStatus,
    reason_code: str,
) -> str | None:
    if status is RecoveryHandoffFailureEvidenceStatus.AVAILABLE:
        if failure_evidence_ref is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Available handoff failure evidence requires a content reference",
            )
        return _require_digest(failure_evidence_ref, field="failure_evidence_ref")
    if status is RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE:
        if failure_evidence_ref is not None or not reason_code.startswith(
            ErrorCode.EVIDENCE_UNAVAILABLE.value
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unavailable handoff failure evidence requires an explicit unavailable reason",
            )
        return None
    raise AgentKernelError(
        ErrorCode.VALIDATION_ERROR,
        "Terminal handoff failure evidence cannot use NONE status",
    )


def _require_stored_integer(value: object, *, field: str) -> int:
    """Reject SQLite dynamic typing instead of coercing corrupt persisted counters."""

    if type(value) is not int:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            f"Stored {field} is not an exact integer",
        )
    return value


@dataclass(frozen=True, slots=True)
class RecoveryActionHandoff:
    action: NormalizedAction | None
    binding: RecoveryActionBinding
    binding_ref: str
    handoff_lease_id: str
    handoff_worker_id: str
    handoff_fencing_token: int
    created_at: datetime
    attached_at: datetime | None
    closed_at: datetime | None
    terminal_sequence: int | None
    failure_evidence_status: RecoveryHandoffFailureEvidenceStatus
    failure_evidence_ref: str | None
    failure_reason_code: str | None


@dataclass(frozen=True, slots=True)
class RecoveryClaimResult:
    work: RecoveryWorkRecord
    lease: WorkerLeaseRecord
    disposition: EnforcedStoreDisposition


@dataclass(frozen=True, slots=True)
class RecoveryClaimPreview:
    work: RecoveryWorkRecord
    lease: WorkerLeaseRecord
    permit: RecoveryPermit
    permit_ref: str


@dataclass(frozen=True, slots=True)
class RecoveryFinishResult:
    work: RecoveryWorkRecord
    transaction: EnforcedTransactionRecord
    event: EnforcedTransactionEvent | None
    lease: WorkerLeaseRecord
    disposition: EnforcedStoreDisposition


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    attempt: ReconciliationAttemptRecord
    transaction: EnforcedTransactionRecord
    event: EnforcedTransactionEvent | None
    disposition: EnforcedStoreDisposition


@dataclass(frozen=True, slots=True)
class LateRecoveryResult:
    """Atomic fail-closed disposition for evidence reported after permit expiry."""

    work: RecoveryWorkRecord
    transaction: EnforcedTransactionRecord
    event: EnforcedTransactionEvent | None
    lease: WorkerLeaseRecord | None
    reconciliation_attempt: ReconciliationAttemptRecord | None
    disposition: EnforcedStoreDisposition


@dataclass(frozen=True, slots=True)
class RecoveryCursor:
    updated_at: datetime
    transaction_id: str


@dataclass(frozen=True, slots=True)
class RecoveryHandoffEvidenceCursor:
    tenant_id: str
    terminal_sequence: int


@dataclass(frozen=True, slots=True)
class RecoveryHandoffEvidencePage:
    handoffs: tuple[RecoveryActionHandoff, ...]
    next_cursor: RecoveryHandoffEvidenceCursor
    cycle_high_watermark: int

    @property
    def cycle_complete(self) -> bool:
        return self.next_cursor.terminal_sequence == self.cycle_high_watermark


@dataclass(frozen=True, slots=True)
class RecoveryHandoffEvidenceAuditCheckpoint:
    tenant_id: str
    current_cycle: int
    current_cycle_high_watermark: int
    cursor: RecoveryHandoffEvidenceCursor
    current_cycle_failure_count: int
    last_completed_cycle: int | None
    last_completed_at: datetime | None
    last_completed_high_watermark: int | None
    last_completed_failure_count: int | None
    version: int
    updated_at: datetime

    @property
    def current_cycle_complete(self) -> bool:
        return (
            self.cursor.terminal_sequence == self.current_cycle_high_watermark
            and self.last_completed_cycle == self.current_cycle
            and self.last_completed_high_watermark == self.current_cycle_high_watermark
        )

    @property
    def current_cycle_ready(self) -> bool:
        return self.current_cycle_complete and self.current_cycle_failure_count == 0


@dataclass(frozen=True, slots=True)
class RecoveryHandoffEvidenceAuditEvent:
    tenant_id: str
    sequence: int
    checkpoint_digest: str
    checkpoint: RecoveryHandoffEvidenceAuditCheckpoint
    previous_event_digest: str | None
    event_digest: str
    recorded_at: datetime


@dataclass(frozen=True, slots=True)
class RecoveryScanPage:
    records: tuple[EnforcedTransactionRecord, ...]
    next_cursor: RecoveryCursor | None
    active_work: tuple[RecoveryWorkRecord, ...] = ()
    started_reconciliation: tuple[ReconciliationAttemptRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class EnforcedTransactionProjection:
    """One transaction status projection read from a single SQLite snapshot."""

    record: EnforcedTransactionRecord
    action: NormalizedAction | None
    stage: StageMaterialRecord | None
    dispatch: CommitDispatchRecord | None
    dispatch_evidence_unavailable: DispatchEvidenceUnavailableRecord | None
    recovery_work: tuple[RecoveryWorkRecord, ...]
    recovery_handoffs: tuple[RecoveryActionHandoff, ...]
    recovery_evidence_unavailable: tuple[RecoveryEvidenceUnavailableRecord, ...]
    recovery_completion_reports: tuple[RecoveryCompletionReportRecord, ...]
    late_recovery_reports: tuple[LateRecoveryReportRecord, ...]
    reconciliation_attempts: tuple[ReconciliationAttemptRecord, ...]
    authorization_rounds: tuple[AuthorizationRoundRecord, ...]
    event_count: int
    intent_acquisition: IntentAcquisition | None


def _event_id(
    tenant_id: str,
    transaction_id: str,
    version: int,
    event: str,
) -> str:
    digest = canonical_digest(
        {
            "profile": "agentkernel.enforced-event-id/v1",
            "tenant_id": tenant_id,
            "transaction_id": transaction_id,
            "version": version,
            "event": event,
        }
    )
    return f"event.{digest.removeprefix('sha256:')}"


def _outcome_id(dispatch_id: str, sequence: int) -> str:
    digest = canonical_digest(
        {
            "profile": "agentkernel.dispatch-outcome-id/v1",
            "dispatch_id": dispatch_id,
            "sequence": sequence,
        }
    )
    return f"outcome.{digest.removeprefix('sha256:')}"


def _reservation_material(reservation: CapabilityChainReservation) -> dict[str, object]:
    return {
        "profile": "agentkernel.capability-chain-fence/v1",
        "tenant_id": reservation.tenant_id,
        "goal_id": reservation.goal_id,
        "run_id": reservation.run_id,
        "intent_hash": reservation.intent_hash,
        "capability_ids": reservation.capability_ids,
        "request_digest": reservation.request_digest,
        "state": reservation.state.value,
        "version": reservation.version,
        "activation_owner_transaction_id": reservation.activation_owner_transaction_id,
        "activation_owner_version": reservation.activation_owner_version,
        "activation_history_sequence": reservation.activation_history_sequence,
        "activation_history_digest": reservation.activation_history_digest,
        "release_history_sequence": reservation.release_history_sequence,
        "release_history_digest": reservation.release_history_digest,
        "budget_reuse": reservation.budget_reuse,
    }


def _authorization_evidence_refs(record: AuthorizationRoundRecord) -> tuple[str, ...]:
    refs = {
        record.round_digest,
        record.authority_decision_record_digest,
        record.policy_decision_record_digest,
    }
    refs.update(
        value
        for value in (
            record.authority_snapshot_ref,
            record.authority_context_ref,
            record.authority_decision_ref,
            record.policy_inputs_ref,
            record.policy_snapshot_ref,
            record.policy_decision_ref,
            record.capability_reservation_digest,
        )
        if value is not None
    )
    return tuple(sorted(refs))


def capability_reservation_digest(reservation: CapabilityChainReservation) -> str:
    """Return the stable digest stored in authorization rounds and work permits."""

    return canonical_digest(_reservation_material(reservation))


def capability_reservation_plan_digest(
    *,
    tenant_id: str,
    goal_id: str,
    run_id: str,
    intent_hash: str,
    capability_ids: Sequence[str],
) -> str:
    """Return the pure reservation-plan digest callers can bind before the SQL CAS."""

    return canonical_digest(
        {
            "profile": "agentkernel.capability-reservation-plan/v1",
            "tenant_id": tenant_id,
            "goal_id": goal_id,
            "run_id": run_id,
            "intent_hash": intent_hash,
            "capability_ids": tuple(capability_ids),
        }
    )


def _reconciliation_attempt_digest(record: ReconciliationAttemptRecord) -> str:
    return canonical_digest(record.canonical_record_json())


def _reconciliation_attempt_json(record: ReconciliationAttemptRecord) -> str:
    return canonical_json_text(record.canonical_record_json())


def scheduled_reconciliation_successor_recovery_id(
    work: RecoveryWorkRecord,
    dispatch: CommitDispatchRecord,
) -> str:
    """Derive the sole successor identity allowed for one scheduled retry."""

    suffix = canonical_digest(
        {
            "profile": "agentkernel.coordinator-id/v1",
            "prefix": "recovery",
            "material": {
                "tenant_id": work.tenant_id,
                "root_recovery_id": work.root_recovery_id,
                "predecessor_recovery_id": work.recovery_id,
                "ordinal": work.recovery_ordinal + 1,
                "target_ref": canonical_digest(dispatch),
            },
        }
    ).removeprefix("sha256:")
    return f"recovery:{suffix[:40]}"


def preview_committed_capability_reservation(
    reservation: CapabilityChainReservation,
) -> CapabilityChainReservation:
    """Return the exact odd committed fence produced from one reserved generation."""

    if reservation.state is not CapabilityReservationState.RESERVED or reservation.version % 2 != 0:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Committed capability preview requires a reserved even generation",
        )
    return replace(
        reservation,
        state=CapabilityReservationState.COMMITTED,
        version=reservation.version + 1,
        changed=True,
        budget_reuse=False,
    )


class SQLiteEnforcedTransactionStore(SQLiteControlStore):
    """Tenant-scoped v4 state, leases, dispatch fencing, and recovery evidence."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        try:
            with self._read_snapshot():
                self._validate_all_enforced_state()
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> Self:
        return self

    def _require_registered_identity_tx(self, record: EnforcedTransactionRecord) -> None:
        """Require bootstrap through the trusted authenticated-context registration path."""

        bound = self._connection.execute(
            "SELECT principal_id, goal_id FROM enforced_runs WHERE tenant_id = ? AND run_id = ?",
            (record.tenant_id, record.run_id),
        ).fetchone()
        if bound is None or (str(bound["principal_id"]), str(bound["goal_id"])) != (
            record.principal_id,
            record.goal_id,
        ):
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Enforced ingress identity is not pre-registered or does not match",
            )

    @staticmethod
    def _transaction_values(record: EnforcedTransactionRecord) -> tuple[object, ...]:
        return (
            record.intent_hash,
            record.normalized_action_digest,
            record.adapter,
            record.operation,
            record.adapter_manifest_digest,
            record.state.value,
            record.version,
            None if record.deadline is None else _timestamp(record.deadline),
            record.authorization_round_id,
            record.authorization_round_digest,
            record.authority_decision_digest,
            record.policy_decision_digest,
            record.policy_snapshot_digest,
            record.capability_reservation_digest,
            canonical_json_text(record.allowed_modes),
            canonical_json_text(record.obligations),
            None if record.intended_outcome is None else record.intended_outcome.value,
            record.reason_code,
            record.version,
            canonical_digest(record),
            canonical_json_text(record),
            _timestamp(record.updated_at),
        )

    def _insert_transaction_tx(
        self,
        record: EnforcedTransactionRecord,
        event: EnforcedTransactionEvent,
    ) -> None:
        self._execute(
            "INSERT INTO enforced_transactions("
            "tenant_id, transaction_id, principal_id, goal_id, run_id, trace_id, actor_id, "
            "on_behalf_of, agent_id, request_digest, intent_hash, normalized_action_digest, "
            "adapter, operation, adapter_manifest_digest, state, version, deadline, "
            "authorization_round_id, authorization_round_digest, authority_decision_digest, "
            "policy_decision_digest, policy_snapshot_digest, capability_reservation_digest, "
            "allowed_modes_json, obligations_json, intended_outcome, reason_code, "
            "event_head_sequence, event_head_digest, record_digest, record_json, "
            "created_at, updated_at) VALUES ("
            "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.tenant_id,
                record.transaction_id,
                record.principal_id,
                record.goal_id,
                record.run_id,
                record.trace_id,
                record.actor_id,
                record.on_behalf_of,
                record.agent_id,
                record.request_digest,
                record.intent_hash,
                record.normalized_action_digest,
                record.adapter,
                record.operation,
                record.adapter_manifest_digest,
                record.state.value,
                record.version,
                None if record.deadline is None else _timestamp(record.deadline),
                record.authorization_round_id,
                record.authorization_round_digest,
                record.authority_decision_digest,
                record.policy_decision_digest,
                record.policy_snapshot_digest,
                record.capability_reservation_digest,
                canonical_json_text(record.allowed_modes),
                canonical_json_text(record.obligations),
                None if record.intended_outcome is None else record.intended_outcome.value,
                record.reason_code,
                record.version,
                event.event_digest,
                canonical_digest(record),
                canonical_json_text(record),
                _timestamp(record.created_at),
                _timestamp(record.updated_at),
            ),
        )
        self._insert_transaction_event_tx(event)

    def _insert_transaction_event_tx(self, event: EnforcedTransactionEvent) -> None:
        self._execute(
            "INSERT INTO enforced_transaction_events("
            "tenant_id, transaction_id, sequence, transaction_version, event_id, rule_id, "
            "event, source_state, target_state, intended_outcome, actor_id, on_behalf_of, "
            "evidence_refs_json, previous_event_digest, event_digest, event_json, recorded_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.tenant_id,
                event.transaction_id,
                event.sequence,
                event.transaction_version,
                event.event_id,
                event.rule_id,
                event.event,
                None if event.source_state is None else event.source_state.value,
                event.target_state.value,
                None if event.intended_outcome is None else event.intended_outcome.value,
                event.actor_id,
                event.on_behalf_of,
                canonical_json_text(event.evidence_refs),
                event.previous_event_digest,
                event.event_digest,
                canonical_json_text(event),
                _timestamp(event.recorded_at),
            ),
        )

    @staticmethod
    def _creation_event(record: EnforcedTransactionRecord) -> EnforcedTransactionEvent:
        return EnforcedTransactionEvent.create(
            tenant_id=record.tenant_id,
            transaction_id=record.transaction_id,
            sequence=0,
            transaction_version=0,
            event_id=_event_id(
                record.tenant_id,
                record.transaction_id,
                0,
                "transaction.created",
            ),
            rule_id="TX-CREATE",
            event="transaction.created",
            source_state=None,
            target_state=TransactionState.NEW,
            intended_outcome=None,
            actor_id=record.actor_id,
            on_behalf_of=record.on_behalf_of,
            evidence_refs=(record.request_digest,),
            previous_event_digest=None,
            recorded_at=record.created_at,
        )

    @staticmethod
    def _assert_valid_ingress(record: EnforcedTransactionRecord) -> None:
        if (
            record.state is not TransactionState.NEW
            or record.version != 0
            or record.created_at != record.updated_at
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Enforced ingress must create NEW at version zero and one timestamp",
            )

    @staticmethod
    def _same_ingress_request(
        stored: EnforcedTransactionRecord,
        proposed: EnforcedTransactionRecord,
    ) -> bool:
        immutable_fields = (
            "tenant_id",
            "transaction_id",
            "principal_id",
            "goal_id",
            "run_id",
            "trace_id",
            "actor_id",
            "on_behalf_of",
            "agent_id",
            "request_digest",
        )
        return all(getattr(stored, field) == getattr(proposed, field) for field in immutable_fields)

    def admit_enforced_transaction(
        self,
        context: AuthenticatedActionContext,
        record: EnforcedTransactionRecord,
    ) -> EnforcedTransactionResult:
        """Atomically bind authenticated identity and admit one idempotent NEW request."""

        self._assert_valid_ingress(record)
        if (
            record.tenant_id != context.tenant_id
            or record.principal_id != context.principal_id
            or record.goal_id != context.goal_id
            or record.run_id != context.run_id
            or record.trace_id != context.trace_id
            or record.actor_id != context.actor_id
            or record.on_behalf_of != context.on_behalf_of
            or record.agent_id != context.agent_id
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Enforced ingress differs from its authenticated action context",
            )
        event = self._creation_event(record)
        try:
            with self._immediate():
                self._register_action_context_tx(
                    context,
                    registered_at=_timestamp(record.created_at),
                )
                existing = self._connection.execute(
                    "SELECT 1 FROM enforced_transactions "
                    "WHERE tenant_id = ? AND transaction_id = ?",
                    (record.tenant_id, record.transaction_id),
                ).fetchone()
                if existing is not None:
                    stored = self._get_enforced_transaction_tx(
                        record.tenant_id,
                        record.transaction_id,
                    )
                    if not self._same_ingress_request(stored, record):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Transaction identity was reused with different ingress content",
                        )
                    return EnforcedTransactionResult(
                        stored,
                        None,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                self._insert_transaction_tx(record, event)
                return EnforcedTransactionResult(
                    record,
                    event,
                    EnforcedStoreDisposition.CREATED,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Atomic enforced admission failed closed", error) from error

    def create_enforced_transaction(
        self,
        record: EnforcedTransactionRecord,
    ) -> EnforcedTransactionResult:
        """Atomically create the bounded ingress record and its chain origin event."""

        self._assert_valid_ingress(record)
        event = self._creation_event(record)
        try:
            with self._immediate():
                existing = self._connection.execute(
                    "SELECT 1 FROM enforced_transactions "
                    "WHERE tenant_id = ? AND transaction_id = ?",
                    (record.tenant_id, record.transaction_id),
                ).fetchone()
                if existing is not None:
                    stored = self._get_enforced_transaction_tx(
                        record.tenant_id,
                        record.transaction_id,
                    )
                    if stored != record:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Transaction identity was reused with different ingress content",
                        )
                    return EnforcedTransactionResult(
                        stored,
                        None,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                self._require_registered_identity_tx(record)
                self._insert_transaction_tx(record, event)
                return EnforcedTransactionResult(
                    record,
                    event,
                    EnforcedStoreDisposition.CREATED,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity(
                "Enforced transaction creation failed closed",
                error,
            ) from error

    def _transaction_from_row(self, row: sqlite3.Row) -> EnforcedTransactionRecord:
        try:
            record = EnforcedTransactionRecord.model_validate_json(str(row["record_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored enforced transaction is invalid",
            ) from error
        expected: dict[str, object] = {
            "tenant_id": record.tenant_id,
            "transaction_id": record.transaction_id,
            "principal_id": record.principal_id,
            "goal_id": record.goal_id,
            "run_id": record.run_id,
            "trace_id": record.trace_id,
            "actor_id": record.actor_id,
            "on_behalf_of": record.on_behalf_of,
            "agent_id": record.agent_id,
            "request_digest": record.request_digest,
            "intent_hash": record.intent_hash,
            "normalized_action_digest": record.normalized_action_digest,
            "adapter": record.adapter,
            "operation": record.operation,
            "adapter_manifest_digest": record.adapter_manifest_digest,
            "state": record.state.value,
            "version": record.version,
            "deadline": None if record.deadline is None else _timestamp(record.deadline),
            "authorization_round_id": record.authorization_round_id,
            "authorization_round_digest": record.authorization_round_digest,
            "authority_decision_digest": record.authority_decision_digest,
            "policy_decision_digest": record.policy_decision_digest,
            "policy_snapshot_digest": record.policy_snapshot_digest,
            "capability_reservation_digest": record.capability_reservation_digest,
            "allowed_modes_json": canonical_json_text(record.allowed_modes),
            "obligations_json": canonical_json_text(record.obligations),
            "intended_outcome": (
                None if record.intended_outcome is None else record.intended_outcome.value
            ),
            "reason_code": record.reason_code,
            "event_head_sequence": record.version,
            "record_digest": canonical_digest(record),
            "record_json": canonical_json_text(record),
            "created_at": _timestamp(record.created_at),
            "updated_at": _timestamp(record.updated_at),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Enforced transaction projection differs from canonical content",
            )
        return record

    def _event_from_row(self, row: sqlite3.Row) -> EnforcedTransactionEvent:
        try:
            event = EnforcedTransactionEvent.model_validate_json(str(row["event_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored enforced transaction event is invalid",
            ) from error
        expected = {
            "tenant_id": event.tenant_id,
            "transaction_id": event.transaction_id,
            "sequence": event.sequence,
            "transaction_version": event.transaction_version,
            "event_id": event.event_id,
            "rule_id": event.rule_id,
            "event": event.event,
            "source_state": None if event.source_state is None else event.source_state.value,
            "target_state": event.target_state.value,
            "intended_outcome": (
                None if event.intended_outcome is None else event.intended_outcome.value
            ),
            "actor_id": event.actor_id,
            "on_behalf_of": event.on_behalf_of,
            "evidence_refs_json": canonical_json_text(event.evidence_refs),
            "previous_event_digest": event.previous_event_digest,
            "event_digest": event.event_digest,
            "event_json": canonical_json_text(event),
            "recorded_at": _timestamp(event.recorded_at),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Enforced transaction event projection differs from canonical content",
            )
        return event

    def _validate_transaction_chain_tx(
        self,
        record: EnforcedTransactionRecord,
    ) -> tuple[EnforcedTransactionEvent, ...]:
        rows = self._connection.execute(
            "SELECT * FROM enforced_transaction_events "
            "WHERE tenant_id = ? AND transaction_id = ? ORDER BY sequence",
            (record.tenant_id, record.transaction_id),
        ).fetchall()
        events = tuple(self._event_from_row(row) for row in rows)
        previous: str | None = None
        for sequence, event in enumerate(events):
            if (
                event.sequence != sequence
                or event.transaction_version != sequence
                or event.previous_event_digest != previous
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Enforced transaction event chain is not contiguous",
                )
            previous = event.event_digest
        if (
            not events
            or len(events) != record.version + 1
            or events[-1].target_state is not record.state
            or previous is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Enforced transaction projection differs from its event chain",
            )
        head = self._connection.execute(
            "SELECT event_head_sequence, event_head_digest FROM enforced_transactions "
            "WHERE tenant_id = ? AND transaction_id = ?",
            (record.tenant_id, record.transaction_id),
        ).fetchone()
        if (
            head is None
            or int(head["event_head_sequence"]) != record.version
            or str(head["event_head_digest"]) != previous
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Enforced transaction event head is inconsistent",
            )
        return events

    def _get_enforced_transaction_tx(
        self,
        tenant_id: str,
        transaction_id: str,
    ) -> EnforcedTransactionRecord:
        row = self._connection.execute(
            "SELECT * FROM enforced_transactions WHERE tenant_id = ? AND transaction_id = ?",
            (tenant_id, transaction_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unknown enforced transaction in this tenant",
            )
        record = self._transaction_from_row(row)
        self._validate_transaction_chain_tx(record)
        self._validate_transaction_recovery_deadline_tx(record, row)
        return record

    def _get_enforced_transaction_head_tx(
        self,
        tenant_id: str,
        transaction_id: str,
    ) -> EnforcedTransactionRecord:
        """Validate only the canonical projection, event head, and one predecessor."""

        row = self._connection.execute(
            "SELECT * FROM enforced_transactions WHERE tenant_id = ? AND transaction_id = ?",
            (tenant_id, transaction_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unknown enforced transaction in this tenant",
            )
        record = self._transaction_from_row(row)
        event_row = self._connection.execute(
            "SELECT * FROM enforced_transaction_events "
            "WHERE tenant_id = ? AND transaction_id = ? AND sequence = ?",
            (tenant_id, transaction_id, record.version),
        ).fetchone()
        tail_row = self._connection.execute(
            "SELECT sequence, event_digest FROM enforced_transaction_events "
            "WHERE tenant_id = ? AND transaction_id = ? ORDER BY sequence DESC LIMIT 1",
            (tenant_id, transaction_id),
        ).fetchone()
        if event_row is None or tail_row is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Enforced transaction lost its event head",
            )
        event = self._event_from_row(event_row)
        if (
            event.sequence != record.version
            or event.transaction_version != record.version
            or event.target_state is not record.state
            or int(row["event_head_sequence"]) != record.version
            or str(row["event_head_digest"]) != event.event_digest
            or int(tail_row["sequence"]) != record.version
            or str(tail_row["event_digest"]) != event.event_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Enforced transaction projection differs from its bounded event head",
            )
        if record.version == 0:
            if event.previous_event_digest is not None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Enforced transaction genesis has an event predecessor",
                )
        else:
            predecessor_row = self._connection.execute(
                "SELECT * FROM enforced_transaction_events "
                "WHERE tenant_id = ? AND transaction_id = ? AND sequence = ?",
                (tenant_id, transaction_id, record.version - 1),
            ).fetchone()
            predecessor = None if predecessor_row is None else self._event_from_row(predecessor_row)
            predecessor_parent_row = (
                None
                if record.version == 1
                else self._connection.execute(
                    "SELECT event_digest FROM enforced_transaction_events "
                    "WHERE tenant_id = ? AND transaction_id = ? AND sequence = ?",
                    (tenant_id, transaction_id, record.version - 2),
                ).fetchone()
            )
            expected_predecessor_parent = (
                None
                if predecessor_parent_row is None
                else str(predecessor_parent_row["event_digest"])
            )
            if (
                predecessor is None
                or event.previous_event_digest != predecessor.event_digest
                or predecessor.previous_event_digest != expected_predecessor_parent
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Enforced transaction event head lost its predecessor",
                )
        self._validate_transaction_recovery_deadline_tx(record, row)
        return record

    def _recovery_deadline_record_from_row(
        self,
        row: sqlite3.Row,
    ) -> TransactionRecoveryDeadlineRecord:
        try:
            record = TransactionRecoveryDeadlineRecord.model_validate_json(str(row["record_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored transaction recovery deadline record is invalid",
            ) from error
        deadline_ref = canonical_digest(record)
        event_row = self._connection.execute(
            "SELECT * FROM enforced_transaction_events "
            "WHERE tenant_id = ? AND transaction_id = ? AND sequence = ?",
            (record.tenant_id, record.transaction_id, record.transaction_version),
        ).fetchone()
        if event_row is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Transaction recovery deadline lost its transition event",
            )
        event = self._event_from_row(event_row)
        if (
            str(row["tenant_id"]) != record.tenant_id
            or str(row["transaction_id"]) != record.transaction_id
            or int(row["transaction_version"]) != record.transaction_version
            or str(row["absolute_deadline"]) != _timestamp(record.absolute_deadline)
            or str(row["deadline_ref"]) != deadline_ref
            or str(row["record_json"]) != canonical_json_text(record)
            or str(row["recorded_at"]) != _timestamp(record.recorded_at)
            or event.transaction_version != record.transaction_version
            or event.rule_id != record.rule_id
            or event.event != record.transition_event.value
            or event.source_state is not record.source_state
            or event.target_state is not record.target_state
            or event.intended_outcome is not record.intended_outcome
            or event.previous_event_digest != record.previous_event_digest
            or event.recorded_at != record.recorded_at
            or deadline_ref not in event.evidence_refs
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Transaction recovery deadline differs from its canonical transition evidence",
            )
        return record

    def _validate_transaction_recovery_deadline_tx(
        self,
        transaction: EnforcedTransactionRecord,
        transaction_row: sqlite3.Row,
    ) -> TransactionRecoveryDeadlineRecord | None:
        deadline_row = self._connection.execute(
            "SELECT * FROM enforced_transaction_recovery_deadlines "
            "WHERE tenant_id = ? AND transaction_id = ?",
            (transaction.tenant_id, transaction.transaction_id),
        ).fetchone()
        recovery_states = tuple(state.value for state in _RECOVERY_DEADLINE_STATES)
        recovery_slots = ", ".join("?" for _ in recovery_states)
        first_recovery_event_row = self._connection.execute(
            "SELECT * FROM enforced_transaction_events "  # noqa: S608  # nosec B608
            "WHERE tenant_id = ? AND transaction_id = ? "
            f"AND target_state IN ({recovery_slots}) ORDER BY sequence LIMIT 1",
            (
                transaction.tenant_id,
                transaction.transaction_id,
                *recovery_states,
            ),
        ).fetchone()
        projected_deadline = transaction_row["recovery_deadline"]
        if deadline_row is None and projected_deadline is None:
            if first_recovery_event_row is not None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction recovery history lacks canonical deadline evidence",
                )
            return None
        if deadline_row is None or projected_deadline is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Transaction recovery deadline projection is partial",
            )
        deadline = self._recovery_deadline_record_from_row(deadline_row)
        first_recovery_event = (
            None
            if first_recovery_event_row is None
            else self._event_from_row(first_recovery_event_row)
        )
        if (
            first_recovery_event is None
            or deadline.tenant_id != transaction.tenant_id
            or deadline.transaction_id != transaction.transaction_id
            or str(projected_deadline) != _timestamp(deadline.absolute_deadline)
            or deadline.transaction_version > transaction.version
            or deadline.transaction_version != first_recovery_event.transaction_version
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Transaction recovery deadline projection differs from canonical evidence",
            )
        return deadline

    def get_enforced_transaction(
        self,
        tenant_id: str,
        transaction_id: str,
    ) -> EnforcedTransactionRecord:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        with self._read_snapshot():
            return self._get_enforced_transaction_tx(tenant_id, transaction_id)

    def get_transaction_recovery_deadline(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
    ) -> datetime:
        """Return the immutable deadline persisted with the first recovery-state entry."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        with self._read_snapshot():
            record = self._get_enforced_transaction_tx(tenant_id, transaction_id)
            row = self._connection.execute(
                "SELECT * FROM enforced_transactions WHERE tenant_id = ? AND transaction_id = ?",
                (tenant_id, transaction_id),
            ).fetchone()
            if row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction has no durable recovery deadline",
                )
            deadline_record = self._validate_transaction_recovery_deadline_tx(record, row)
            if deadline_record is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction has no durable recovery deadline",
                )
            return deadline_record.absolute_deadline

    def _root_recovery_binding_matches_durable_bounds_tx(
        self,
        transaction: EnforcedTransactionRecord,
        binding: RecoveryActionBinding,
    ) -> bool:
        if binding.recovery_ordinal != 1:
            return True
        transaction_row = self._connection.execute(
            "SELECT * FROM enforced_transactions WHERE tenant_id = ? AND transaction_id = ?",
            (transaction.tenant_id, transaction.transaction_id),
        ).fetchone()
        if transaction_row is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery binding target transaction is unavailable",
            )
        deadline = self._validate_transaction_recovery_deadline_tx(
            transaction,
            transaction_row,
        )
        valid_attempt_limit = (
            1 <= binding.max_recovery_attempts <= _MAX_RECONCILIATION_ATTEMPTS
            if binding.recovery_kind is RecoveryWorkKind.RECONCILE_DISPATCH
            else binding.max_recovery_attempts == 1
        )
        return (
            deadline is not None
            and binding.absolute_deadline == deadline.absolute_deadline
            and valid_attempt_limit
        )

    def list_enforced_transaction_events(
        self,
        tenant_id: str,
        transaction_id: str,
    ) -> tuple[EnforcedTransactionEvent, ...]:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        with self._read_snapshot():
            record = self._get_enforced_transaction_tx(tenant_id, transaction_id)
            return self._validate_transaction_chain_tx(record)

    def get_transaction_projection(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
    ) -> EnforcedTransactionProjection:
        """Read a complete, chain-validated status view in one database snapshot."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        with self._read_snapshot():
            record = self._get_enforced_transaction_tx(tenant_id, transaction_id)
            events = self._validate_transaction_chain_tx(record)

            action_row = self._connection.execute(
                "SELECT 1 FROM enforced_normalized_actions "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (tenant_id, transaction_id),
            ).fetchone()
            action = (
                None
                if action_row is None
                else self._get_normalized_action(tenant_id, transaction_id).action
            )
            legacy_alias_projection = (
                record.state is TransactionState.REJECTED
                and record.reason_code in {"DUPLICATE_INTENT", "DUPLICATE_INTENT_REVIEW_REQUIRED"}
                and record.intent_hash is None
                and action is not None
            )
            if record.intent_hash is not None and action is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction and normalized-action presence differ",
                )
            if action is not None and record.intent_hash is None and not legacy_alias_projection:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction unexpectedly has unbound normalized action content",
                )
            if (
                action is not None
                and record.intent_hash is not None
                and (
                    record.intent_hash != action.intent_hash
                    or record.normalized_action_digest != canonical_digest(action)
                    or record.adapter != action.adapter
                    or record.operation != action.operation
                    or record.adapter_manifest_digest != action.adapter_manifest_digest
                )
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction differs from its normalized action",
                )
            intent_acquisition = (
                None
                if action is None
                else self._current_acquisition_tx(
                    tenant_id=tenant_id,
                    intent_hash=action.intent_hash,
                    transaction_id=transaction_id,
                )
            )

            stage_row = self._connection.execute(
                "SELECT * FROM enforced_stage_material WHERE tenant_id = ? AND transaction_id = ?",
                (tenant_id, transaction_id),
            ).fetchone()
            stage = None if stage_row is None else self._stage_from_row(stage_row)
            dispatch_row = self._connection.execute(
                "SELECT * FROM enforced_commit_dispatches "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (tenant_id, transaction_id),
            ).fetchone()
            dispatch = None if dispatch_row is None else self._dispatch_from_row(dispatch_row)
            dispatch_evidence_unavailable = None
            if dispatch is not None:
                self._validate_dispatch_outcome_chain_tx(dispatch)
                dispatch_evidence_unavailable = self._validate_dispatch_unavailable_link_tx(
                    dispatch
                )
            if stage is not None and (
                stage.intent_hash != record.intent_hash
                or stage.normalized_action_digest != record.normalized_action_digest
                or stage.adapter_manifest_digest != record.adapter_manifest_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction differs from its private stage material",
                )
            if dispatch is not None and (
                dispatch.intent_hash != record.intent_hash
                or dispatch.permit.normalized_action_digest != record.normalized_action_digest
                or dispatch.permit.adapter_manifest_digest != record.adapter_manifest_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction differs from its commit dispatch",
                )

            recovery_rows = self._connection.execute(
                "SELECT * FROM enforced_recovery_work "
                "WHERE tenant_id = ? AND transaction_id = ? "
                "ORDER BY created_at, recovery_id",
                (tenant_id, transaction_id),
            ).fetchall()
            recovery_work = tuple(self._recovery_from_row(row) for row in recovery_rows)
            if any(
                work.intent_hash != record.intent_hash
                or work.adapter_manifest_digest != record.adapter_manifest_digest
                for work in recovery_work
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction differs from its recovery work",
                )
            for work in recovery_work:
                self._validate_recovery_work_handoff_lifecycle_tx(work)
            unavailable_rows = self._connection.execute(
                "SELECT * FROM enforced_recovery_evidence_unavailable_reports "
                "WHERE tenant_id = ? AND transaction_id = ? ORDER BY recovery_id",
                (tenant_id, transaction_id),
            ).fetchall()
            recovery_evidence_unavailable = tuple(
                self._recovery_evidence_unavailable_from_row(unavailable_row)
                for unavailable_row in unavailable_rows
            )
            unavailable_by_recovery = {
                unavailable.recovery_id: unavailable
                for unavailable in recovery_evidence_unavailable
            }
            for work in recovery_work:
                unavailable = unavailable_by_recovery.get(work.recovery_id)
                if (work.unavailable_record_digest is None) != (unavailable is None) or (
                    unavailable is not None
                    and work.unavailable_record_digest != unavailable.record_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery work and typed unavailable evidence presence differ",
                    )
            for unavailable in recovery_evidence_unavailable:
                self._validate_recovery_evidence_unavailable_association_tx(unavailable)
            if any(
                unavailable.recovery_id not in {work.recovery_id for work in recovery_work}
                for unavailable in recovery_evidence_unavailable
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unavailable recovery evidence lacks its transaction work",
                )

            handoff_rows = self._connection.execute(
                "SELECT * FROM enforced_recovery_action_handoffs "
                "WHERE tenant_id = ? AND target_transaction_id = ? "
                "ORDER BY created_at, recovery_id",
                (tenant_id, transaction_id),
            ).fetchall()
            recovery_handoffs = tuple(
                self._recovery_action_handoff_from_row(
                    handoff_row,
                    tenant_id=tenant_id,
                    target_transaction_id=transaction_id,
                    recovery_id=str(handoff_row["recovery_id"]),
                )
                for handoff_row in handoff_rows
            )
            for handoff in recovery_handoffs:
                self._validate_recovery_action_handoff_reverse_tx(
                    handoff,
                    tenant_id=tenant_id,
                )

            round_rows = self._connection.execute(
                "SELECT * FROM enforced_authorization_rounds "
                "WHERE tenant_id = ? AND controlled_transaction_id = ? "
                "ORDER BY evaluated_at, round_id",
                (tenant_id, transaction_id),
            ).fetchall()
            authorization_rounds = tuple(
                self._round_from_row(round_row) for round_row in round_rows
            )
            round_ids = {round_record.round_id for round_record in authorization_rounds}
            referenced_round_ids = {
                *(work.authorization_round_id for work in recovery_work),
                *((record.authorization_round_id,) if record.authorization_round_id else ()),
            }
            if not referenced_round_ids <= round_ids:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction references a missing authorization round",
                )

            work_by_id = {work.recovery_id: work for work in recovery_work}
            attempt_rows = self._connection.execute(
                "SELECT * FROM enforced_reconciliation_attempts "
                "WHERE tenant_id = ? AND transaction_id = ? "
                "ORDER BY recovery_id, attempt",
                (tenant_id, transaction_id),
            ).fetchall()
            reconciliation_attempts = tuple(
                self._reconciliation_from_row(attempt_row) for attempt_row in attempt_rows
            )
            attempts_by_recovery: dict[str, list[ReconciliationAttemptRecord]] = {}
            for attempt in reconciliation_attempts:
                attempt_work = work_by_id.get(attempt.recovery_id)
                if (
                    attempt_work is None
                    or attempt_work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                    or attempt.attempt > attempt_work.attempt
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Reconciliation attempt has no exact recovery-work owner",
                    )
                attempts_by_recovery.setdefault(attempt.recovery_id, []).append(attempt)
                if attempt.attempt == attempt_work.attempt:
                    lease = self._assert_reconciliation_attempt_binding_tx(
                        attempt_work,
                        attempt,
                    )
                    if attempt.outcome is None:
                        if (
                            attempt_work.state is not RecoveryWorkState.RUNNING
                            or attempt_work.lease_id != attempt.lease_id
                            or attempt_work.fencing_token != attempt.fencing_token
                            or lease.released_at is not None
                        ):
                            raise AgentKernelError(
                                ErrorCode.INTEGRITY_ERROR,
                                "Started reconciliation differs from its running work",
                            )
                    elif attempt.recovery_id in unavailable_by_recovery:
                        # The typed-unavailable association owns the exact closure.  A
                        # provider lease may have been released before a later scanner
                        # durably classified the missing result.
                        pass
                    elif (
                        attempt.completed_at is None
                        or lease.released_at != attempt.completed_at
                        or _reconciliation_attempt_digest(attempt) not in attempt_work.evidence_refs
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Completed reconciliation differs from its terminal work",
                        )

            for work in recovery_work:
                if work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH:
                    continue
                self._assert_reconciliation_attempt_lineage_tx(work)

            completion_rows = self._connection.execute(
                "SELECT * FROM enforced_recovery_completion_reports "
                "WHERE tenant_id = ? AND transaction_id = ? ORDER BY recovery_id",
                (tenant_id, transaction_id),
            ).fetchall()
            recovery_completion_reports = tuple(
                self._recovery_completion_report_from_row(completion_row)
                for completion_row in completion_rows
            )
            completion_by_recovery: dict[str, RecoveryCompletionReportRecord] = {}
            for completion in recovery_completion_reports:
                completion_work = work_by_id.get(completion.recovery_id)
                if completion_work is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery completion report has no recovery-work owner",
                    )
                self._validate_recovery_completion_report_association_tx(
                    completion_work,
                    completion,
                )
                completion_by_recovery[completion.recovery_id] = completion

            late_rows = self._connection.execute(
                "SELECT * FROM enforced_late_recovery_reports "
                "WHERE tenant_id = ? AND transaction_id = ? ORDER BY recovery_id",
                (tenant_id, transaction_id),
            ).fetchall()
            late_recovery_reports = tuple(
                self._late_recovery_report_from_row(late_row) for late_row in late_rows
            )
            late_by_recovery: dict[str, LateRecoveryReportRecord] = {}
            for late in late_recovery_reports:
                late_work = work_by_id.get(late.recovery_id)
                if late_work is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Late recovery report has no recovery-work owner",
                    )
                current_attempt = next(
                    (
                        attempt
                        for attempt in attempts_by_recovery.get(late.recovery_id, ())
                        if attempt.attempt == late_work.attempt
                    ),
                    None,
                )
                self._validate_late_recovery_report_association_tx(
                    late_work,
                    late,
                    current_attempt,
                )
                late_by_recovery[late.recovery_id] = late

            for work in recovery_work:
                completion_owner = completion_by_recovery.get(work.recovery_id)
                late_owner = late_by_recovery.get(work.recovery_id)
                unavailable = unavailable_by_recovery.get(work.recovery_id)
                attempts = attempts_by_recovery.get(work.recovery_id, ())
                if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                    if completion_owner is not None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Reconciliation work cannot own a recovery completion report",
                        )
                elif attempts:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Non-reconciliation work cannot own reconciliation attempts",
                    )
                if completion_owner is not None and (
                    late_owner is not None or unavailable is not None
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery work has conflicting terminal report owners",
                    )
                if late_owner is not None and unavailable is not None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery work is both late and evidence-unavailable",
                    )

            event_names = {event.event for event in events}
            staging_succeeded = TransitionEvent.STAGING_SUCCEEDED.value in event_names
            commit_started = TransitionEvent.COMMIT_GUARDS_PASSED.value in event_names
            if (staging_succeeded or dispatch is not None) and stage is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction history requires durable stage material",
                )
            if commit_started != (dispatch is not None):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction history and commit dispatch presence differ",
                )
            purposes = {round_record.purpose for round_record in authorization_rounds}
            if (
                TransitionEvent.AUTHORIZED_FOR_STAGING.value in event_names
                and AuthorizationRoundPurpose.STAGING not in purposes
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction history requires its staging authorization round",
                )
            if commit_started and AuthorizationRoundPurpose.PRECOMMIT not in purposes:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Transaction history requires its precommit authorization round",
                )
            return EnforcedTransactionProjection(
                record=record,
                action=action,
                stage=stage,
                dispatch=dispatch,
                dispatch_evidence_unavailable=dispatch_evidence_unavailable,
                recovery_work=recovery_work,
                recovery_handoffs=recovery_handoffs,
                recovery_evidence_unavailable=recovery_evidence_unavailable,
                recovery_completion_reports=recovery_completion_reports,
                late_recovery_reports=late_recovery_reports,
                reconciliation_attempts=reconciliation_attempts,
                authorization_rounds=authorization_rounds,
                event_count=len(events),
                intent_acquisition=intent_acquisition,
            )

    def _apply_transition_tx(
        self,
        current: EnforcedTransactionRecord,
        *,
        expected_version: int,
        transition_event: TransitionEvent,
        recorded_at: datetime,
        evidence_refs: tuple[str, ...] = (),
        reason_code: str | None = None,
        updates: Mapping[str, object] | None = None,
        recovery_deadline: datetime | None = None,
    ) -> tuple[EnforcedTransactionRecord, EnforcedTransactionEvent]:
        if current.version != expected_version:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Enforced transaction version changed",
                details={"expected": expected_version, "actual": current.version},
                retryable=True,
            )
        decision = apply_transition(
            current.state,
            transition_event,
            current_intended_outcome=current.intended_outcome,
        )
        values = current.model_dump(mode="python")
        values.update(updates or {})
        values.update(
            {
                "state": decision.target,
                "version": current.version + 1,
                "intended_outcome": decision.intended_outcome,
                "reason_code": reason_code,
                "updated_at": recorded_at,
            }
        )
        updated = EnforcedTransactionRecord.model_validate(values)
        previous_row = self._connection.execute(
            "SELECT event_head_digest, recovery_deadline FROM enforced_transactions "
            "WHERE tenant_id = ? AND transaction_id = ? AND version = ?",
            (current.tenant_id, current.transaction_id, expected_version),
        ).fetchone()
        if previous_row is None:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Enforced transaction compare-and-swap source disappeared",
                retryable=True,
            )
        previous_digest = str(previous_row["event_head_digest"])
        deadline_record: TransactionRecoveryDeadlineRecord | None = None
        deadline_ref: str | None = None
        stored_recovery_deadline = (
            None
            if previous_row["recovery_deadline"] is None
            else _parse_timestamp(previous_row["recovery_deadline"])
        )
        if stored_recovery_deadline is None and decision.target in _RECOVERY_DEADLINE_STATES:
            if recovery_deadline is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery-state entry requires an explicit durable recovery timeout",
                )
            stored_recovery_deadline = recovery_deadline
            if stored_recovery_deadline <= recorded_at:
                raise AgentKernelError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "Transaction recovery transition has no positive durable deadline",
                )
            deadline_record = TransactionRecoveryDeadlineRecord(
                tenant_id=current.tenant_id,
                transaction_id=current.transaction_id,
                transaction_version=updated.version,
                rule_id=decision.rule_id,
                transition_event=transition_event,
                source_state=current.state,
                target_state=decision.target,
                intended_outcome=decision.intended_outcome,
                previous_event_digest=previous_digest,
                absolute_deadline=stored_recovery_deadline,
                recorded_at=recorded_at,
            )
            deadline_ref = canonical_digest(deadline_record)
        event = EnforcedTransactionEvent.create(
            tenant_id=current.tenant_id,
            transaction_id=current.transaction_id,
            sequence=updated.version,
            transaction_version=updated.version,
            event_id=_event_id(
                current.tenant_id,
                current.transaction_id,
                updated.version,
                transition_event.value,
            ),
            rule_id=decision.rule_id,
            event=transition_event.value,
            source_state=current.state,
            target_state=updated.state,
            intended_outcome=updated.intended_outcome,
            actor_id=current.actor_id,
            on_behalf_of=current.on_behalf_of,
            evidence_refs=tuple(
                sorted(
                    {
                        *evidence_refs,
                        *((deadline_ref,) if deadline_ref is not None else ()),
                    }
                )
            ),
            previous_event_digest=previous_digest,
            recorded_at=recorded_at,
        )
        cursor = self._execute(
            "UPDATE enforced_transactions SET "
            "intent_hash = ?, normalized_action_digest = ?, adapter = ?, operation = ?, "
            "adapter_manifest_digest = ?, state = ?, version = ?, deadline = ?, "
            "authorization_round_id = ?, authorization_round_digest = ?, "
            "authority_decision_digest = ?, policy_decision_digest = ?, "
            "policy_snapshot_digest = ?, capability_reservation_digest = ?, "
            "allowed_modes_json = ?, obligations_json = ?, intended_outcome = ?, "
            "reason_code = ?, event_head_sequence = ?, event_head_digest = ?, "
            "record_digest = ?, record_json = ?, updated_at = ?, recovery_deadline = ? "
            "WHERE tenant_id = ? AND transaction_id = ? AND version = ? "
            "AND event_head_sequence = ? AND event_head_digest = ?",
            (
                *self._transaction_values(updated)[:19],
                event.event_digest,
                *self._transaction_values(updated)[19:],
                (
                    None
                    if stored_recovery_deadline is None
                    else _timestamp(stored_recovery_deadline)
                ),
                current.tenant_id,
                current.transaction_id,
                expected_version,
                expected_version,
                previous_digest,
            ),
        )
        if cursor.rowcount != 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Enforced transaction compare-and-swap failed",
                retryable=True,
            )
        self._insert_transaction_event_tx(event)
        if deadline_record is not None and deadline_ref is not None:
            self._execute(
                "INSERT INTO enforced_transaction_recovery_deadlines("
                "tenant_id, transaction_id, transaction_version, absolute_deadline, "
                "deadline_ref, record_json, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    deadline_record.tenant_id,
                    deadline_record.transaction_id,
                    deadline_record.transaction_version,
                    _timestamp(deadline_record.absolute_deadline),
                    deadline_ref,
                    canonical_json_text(deadline_record),
                    _timestamp(deadline_record.recorded_at),
                ),
            )
        return updated, event

    def apply_control_transition(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_version: int,
        transition_event: TransitionEvent,
        recorded_at: datetime,
        evidence_refs: tuple[str, ...] = (),
        reason_code: str | None = None,
        recovery_timeout: timedelta | None = None,
    ) -> EnforcedTransactionResult:
        """Apply a non-authority, non-effect transition from an explicit allow-list."""

        if transition_event not in _CONTROL_TRANSITIONS:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Transition requires a specialized atomic store operation",
                details={"event": transition_event.value},
            )
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        if recovery_timeout is not None and recovery_timeout <= timedelta(0):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery timeout must be positive",
            )
        try:
            with self._immediate():
                current = self._get_enforced_transaction_tx(tenant_id, transaction_id)
                updated, event = self._apply_transition_tx(
                    current,
                    expected_version=expected_version,
                    transition_event=transition_event,
                    recorded_at=recorded_at,
                    evidence_refs=evidence_refs,
                    reason_code=reason_code,
                    recovery_deadline=(
                        None if recovery_timeout is None else recorded_at + recovery_timeout
                    ),
                )
                return EnforcedTransactionResult(
                    updated,
                    event,
                    EnforcedStoreDisposition.STORED,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Enforced control transition failed closed", error) from error

    def _current_acquisition_tx(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
        transaction_id: str,
    ) -> IntentAcquisition:
        ledger = self._validate_intent_ledger(tenant_id, intent_hash)
        if ledger.owner_transaction_id == transaction_id:
            disposition = IntentDisposition.SAME_TRANSACTION
        elif ledger.owner_state is IntentAttemptState.ACTIVE:
            disposition = IntentDisposition.ALIAS_ACTIVE
        elif ledger.owner_state is IntentAttemptState.RECONCILE_REQUIRED:
            disposition = IntentDisposition.ALIAS_RECONCILE
        elif ledger.owner_state is IntentAttemptState.COMMITTED:
            disposition = IntentDisposition.ALIAS_COMMITTED
        else:
            disposition = IntentDisposition.REVIEW_REQUIRED
        return IntentAcquisition(
            disposition=disposition,
            tenant_id=tenant_id,
            intent_hash=intent_hash,
            transaction_id=transaction_id,
            owner_transaction_id=ledger.owner_transaction_id,
            owner_version=ledger.owner_version,
        )

    def plan_and_acquire_intent(
        self,
        action: NormalizedAction,
        *,
        expected_version: int,
        planned_at: datetime,
        expected_owner_version: int | None = None,
    ) -> PlanningResult:
        """Persist normalization, acquire intent ownership, and transition in one CAS."""

        timestamp = _timestamp(planned_at)
        action_digest = canonical_digest(action)
        try:
            with self._immediate():
                current = self._get_enforced_transaction_tx(
                    action.tenant_id,
                    action.transaction_id,
                )
                if current.state is not TransactionState.NEW:
                    stored = self._get_normalized_action(
                        action.tenant_id,
                        action.transaction_id,
                    )
                    if stored.action_digest != action_digest or stored.action != action:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Planning retry changed the normalized action",
                        )
                    acquisition = self._current_acquisition_tx(
                        tenant_id=action.tenant_id,
                        intent_hash=action.intent_hash,
                        transaction_id=action.transaction_id,
                    )
                    return PlanningResult(
                        current,
                        None,
                        acquisition,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                if current.version != expected_version:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Planning source version changed",
                        retryable=True,
                    )
                if (
                    current.principal_id != action.principal_id
                    or current.goal_id != action.goal_id
                    or current.run_id != action.run_id
                    or current.trace_id != action.trace_id
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Normalized action identity differs from durable ingress",
                    )
                self._put_normalized_action_tx(
                    action,
                    recorded_at=timestamp,
                    action_digest=action_digest,
                )
                acquisition = self._acquire_intent_tx(
                    tenant_id=action.tenant_id,
                    intent_hash=action.intent_hash,
                    transaction_id=action.transaction_id,
                    attempted_at=timestamp,
                    expected_owner_version=expected_owner_version,
                )
                if acquisition.disposition in {
                    IntentDisposition.ACQUIRED,
                    IntentDisposition.SAME_TRANSACTION,
                    IntentDisposition.TRANSFERRED_NO_EFFECT,
                }:
                    ledger = self._validate_intent_ledger(
                        action.tenant_id,
                        action.intent_hash,
                    )
                    updated, event = self._apply_transition_tx(
                        current,
                        expected_version=expected_version,
                        transition_event=TransitionEvent.PROPOSAL_VALID,
                        recorded_at=planned_at,
                        evidence_refs=(action_digest, ledger.head_digest),
                        updates={
                            "intent_hash": action.intent_hash,
                            "normalized_action_digest": action_digest,
                            "adapter": action.adapter,
                            "operation": action.operation,
                            "adapter_manifest_digest": action.adapter_manifest_digest,
                            "deadline": action.deadline,
                        },
                    )
                    disposition = EnforcedStoreDisposition.PLANNED
                else:
                    reason = (
                        "DUPLICATE_INTENT_REVIEW_REQUIRED"
                        if acquisition.disposition is IntentDisposition.REVIEW_REQUIRED
                        else "DUPLICATE_INTENT"
                    )
                    updated, event = self._apply_transition_tx(
                        current,
                        expected_version=expected_version,
                        transition_event=TransitionEvent.VALIDATION_FAILED,
                        recorded_at=planned_at,
                        evidence_refs=(action_digest,),
                        reason_code=reason,
                        updates={
                            "intent_hash": action.intent_hash,
                            "normalized_action_digest": action_digest,
                            "adapter": action.adapter,
                            "operation": action.operation,
                            "adapter_manifest_digest": action.adapter_manifest_digest,
                            "deadline": action.deadline,
                        },
                    )
                    disposition = (
                        EnforcedStoreDisposition.REVIEW_REQUIRED
                        if acquisition.disposition is IntentDisposition.REVIEW_REQUIRED
                        else EnforcedStoreDisposition.ALIAS
                    )
                return PlanningResult(updated, event, acquisition, disposition)
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Atomic intent planning failed closed", error) from error

    def _recovery_action_handoff_from_row(
        self,
        row: sqlite3.Row,
        *,
        tenant_id: str,
        target_transaction_id: str,
        recovery_id: str,
    ) -> RecoveryActionHandoff:
        try:
            binding = RecoveryActionBinding.model_validate_json(str(row["binding_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored recovery action handoff binding is invalid",
            ) from error
        binding_ref = canonical_digest(binding)
        created_at = _parse_timestamp(row["created_at"])
        if (
            row["handoff_lease_id"] is None
            or row["handoff_worker_id"] is None
            or row["handoff_fencing_token"] is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored recovery handoff lost its original lease identity",
            )
        handoff_lease_id = _require_identifier(
            str(row["handoff_lease_id"]),
            field="handoff_lease_id",
        )
        handoff_worker_id = _require_identifier(
            str(row["handoff_worker_id"]),
            field="handoff_worker_id",
        )
        handoff_fencing_token = _require_stored_integer(
            row["handoff_fencing_token"],
            field="recovery handoff fencing token",
        )
        original_lease_row = self._connection.execute(
            "SELECT * FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND lease_id = ?",
            (tenant_id, target_transaction_id, handoff_lease_id),
        ).fetchone()
        if original_lease_row is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff lost its original lease generation",
            )
        original_lease = self._lease_from_row(original_lease_row)
        attached_at = None if row["attached_at"] is None else _parse_timestamp(row["attached_at"])
        closed_at = None if row["closed_at"] is None else _parse_timestamp(row["closed_at"])
        terminal_sequence = (
            None
            if row["terminal_sequence"] is None
            else _require_stored_integer(
                row["terminal_sequence"],
                field="recovery handoff terminal sequence",
            )
        )
        try:
            failure_evidence_status = RecoveryHandoffFailureEvidenceStatus(
                str(row["failure_evidence_status"])
            )
        except ValueError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored recovery action handoff evidence status is invalid",
            ) from error
        failure_evidence_ref = (
            None
            if row["failure_evidence_ref"] is None
            else _require_digest(
                str(row["failure_evidence_ref"]),
                field="failure_evidence_ref",
            )
        )
        failure_reason_code = (
            None if row["failure_reason_code"] is None else str(row["failure_reason_code"])
        )
        expired_failure_identity = (
            failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.AVAILABLE
            and failure_evidence_ref is not None
            and failure_reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        ) or (
            failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE
            and failure_evidence_ref is None
            and failure_reason_code
            == (f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{ErrorCode.DEADLINE_EXCEEDED.value}")
        )
        expired_no_work_settlement = (
            binding.recovery_kind
            in {
                RecoveryWorkKind.ROLLBACK,
                RecoveryWorkKind.COMPENSATE,
                RecoveryWorkKind.RECONCILE_DISPATCH,
            }
            and binding.recovery_ordinal == 1
            and binding.root_recovery_id == binding.recovery_id
            and binding.predecessor_recovery_id is None
            and row["recovery_action_transaction_id"] is None
            and row["recovery_action_intent_hash"] is None
            and row["recovery_action_digest"] is None
            and attached_at is None
            and closed_at == created_at
            and created_at >= binding.absolute_deadline
            and expired_failure_identity
            and original_lease.version == 1
            and original_lease.acquired_at == created_at
            and original_lease.expires_at == created_at + _EXPIRED_HANDOFF_SETTLEMENT_LEASE_DURATION
            and original_lease.released_at == created_at
        )
        if (
            str(row["tenant_id"]) != tenant_id
            or str(row["target_transaction_id"]) != target_transaction_id
            or str(row["recovery_id"]) != recovery_id
            or str(row["recovery_kind"]) != binding.recovery_kind.value
            or str(row["target_id"]) != binding.target_id
            or str(row["target_evidence_ref"]) != binding.target_evidence_ref
            or str(row["binding_ref"]) != binding_ref
            or str(row["binding_json"]) != canonical_json_text(binding)
            or str(row["created_at"]) != _timestamp(created_at)
            or (attached_at is not None and str(row["attached_at"]) != _timestamp(attached_at))
            or (closed_at is not None and str(row["closed_at"]) != _timestamp(closed_at))
            or binding.target_transaction_id != target_transaction_id
            or binding.recovery_id != recovery_id
            or original_lease.lease_id != handoff_lease_id
            or original_lease.worker_id != handoff_worker_id
            or original_lease.fencing_token != handoff_fencing_token
            or original_lease.purpose is not LeasePurpose.RECOVERY
            or original_lease.acquired_at != created_at
            or (
                original_lease.expires_at > binding.absolute_deadline
                and not expired_no_work_settlement
            )
            or created_at < binding.not_before
            or (created_at >= binding.absolute_deadline and not expired_no_work_settlement)
            or (attached_at is not None and attached_at < created_at)
            or (attached_at is not None and attached_at >= binding.absolute_deadline)
            or (closed_at is not None and closed_at < created_at)
            or (closed_at is not None and attached_at is not None and closed_at < attached_at)
            or (
                closed_at is None
                and (
                    terminal_sequence is not None
                    or failure_evidence_status is not RecoveryHandoffFailureEvidenceStatus.NONE
                    or failure_evidence_ref is not None
                    or failure_reason_code is not None
                )
            )
            or (
                closed_at is not None
                and (
                    terminal_sequence is None
                    or terminal_sequence < 1
                    or failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.NONE
                    or failure_reason_code is None
                    or (failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.AVAILABLE)
                    != (failure_evidence_ref is not None)
                    or (
                        failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE
                        and not failure_reason_code.startswith(ErrorCode.EVIDENCE_UNAVAILABLE.value)
                    )
                )
            )
            or (failure_reason_code is not None and not failure_reason_code.strip())
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery action handoff projection differs from canonical content",
            )
        action_values = (
            row["recovery_action_transaction_id"],
            row["recovery_action_intent_hash"],
            row["recovery_action_digest"],
            row["attached_at"],
        )
        if all(value is None for value in action_values):
            action = None
        elif any(value is None for value in action_values):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery action handoff has a partial action attachment",
            )
        else:
            action_subject = self._get_normalized_action(
                tenant_id,
                str(row["recovery_action_transaction_id"]),
            )
            action = action_subject.action
            enforced_subject = self._connection.execute(
                "SELECT 1 FROM enforced_transactions WHERE tenant_id = ? AND transaction_id = ?",
                (tenant_id, action.transaction_id),
            ).fetchone()
            binding_arguments = tuple(
                argument
                for argument in action.semantic_arguments
                if argument.argument_name == RECOVERY_ACTION_BINDING_ARGUMENT
            )
            if (
                enforced_subject is not None
                or str(row["recovery_action_intent_hash"]) != action.intent_hash
                or str(row["recovery_action_digest"]) != action_subject.action_digest
                or action.deadline != binding.absolute_deadline
                or len(binding_arguments) != 1
                or binding_arguments[0].digest != binding_ref
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery action handoff attachment differs from canonical content",
                )
        return RecoveryActionHandoff(
            action=action,
            binding=binding,
            binding_ref=binding_ref,
            handoff_lease_id=handoff_lease_id,
            handoff_worker_id=handoff_worker_id,
            handoff_fencing_token=handoff_fencing_token,
            created_at=created_at,
            attached_at=attached_at,
            closed_at=closed_at,
            terminal_sequence=terminal_sequence,
            failure_evidence_status=failure_evidence_status,
            failure_evidence_ref=failure_evidence_ref,
            failure_reason_code=failure_reason_code,
        )

    def _next_recovery_handoff_terminal_sequence_tx(
        self,
        tenant_id: str,
        *,
        recorded_at: datetime,
    ) -> int:
        row = self._connection.execute(
            "SELECT terminal_sequence, updated_at "
            "FROM enforced_recovery_handoff_terminal_heads WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if row is None:
            terminal_sequence = 1
            self._execute(
                "INSERT INTO enforced_recovery_handoff_terminal_heads("
                "tenant_id, terminal_sequence, updated_at) VALUES (?, ?, ?)",
                (tenant_id, terminal_sequence, _timestamp(recorded_at)),
            )
            return terminal_sequence
        previous_sequence = _require_stored_integer(
            row["terminal_sequence"],
            field="recovery handoff terminal head sequence",
        )
        if previous_sequence < 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff terminal head is invalid",
            )
        terminal_sequence = previous_sequence + 1
        cursor = self._execute(
            "UPDATE enforced_recovery_handoff_terminal_heads SET "
            "terminal_sequence = ?, updated_at = ? "
            "WHERE tenant_id = ? AND terminal_sequence = ?",
            (
                terminal_sequence,
                _timestamp(recorded_at),
                tenant_id,
                previous_sequence,
            ),
        )
        if cursor.rowcount != 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Recovery handoff terminal head lost its compare-and-swap",
                retryable=True,
            )
        return terminal_sequence

    def reserve_recovery_action_handoff(
        self,
        *,
        tenant_id: str,
        target_transaction_id: str,
        expected_transaction_version: int,
        binding: RecoveryActionBinding,
        created_at: datetime,
        handoff_lease: WorkerLeaseRecord,
    ) -> RecoveryActionHandoff:
        """Persist the immutable recovery generation before invoking its action factory."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        target_transaction_id = _require_identifier(
            target_transaction_id,
            field="target_transaction_id",
        )
        try:
            binding = RecoveryActionBinding.model_validate(binding.model_dump(mode="python"))
        except (AttributeError, TypeError, ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery action handoff binding is not canonical",
            ) from error
        binding_ref = canonical_digest(binding)
        binding_json = canonical_json_text(binding)
        invalid_initial_lineage = binding.recovery_ordinal == 1 and (
            binding.root_recovery_id != binding.recovery_id
            or binding.predecessor_recovery_id is not None
        )
        invalid_retry_lineage = binding.recovery_ordinal > 1 and (
            binding.recovery_kind is not RecoveryWorkKind.RECONCILE_DISPATCH
            or binding.root_recovery_id == binding.recovery_id
            or binding.predecessor_recovery_id is None
            or binding.predecessor_recovery_id == binding.recovery_id
        )
        if (
            invalid_initial_lineage
            or invalid_retry_lineage
            or binding.target_transaction_id != target_transaction_id
            or created_at < binding.not_before
            or created_at >= binding.absolute_deadline
            or handoff_lease.tenant_id != tenant_id
            or handoff_lease.transaction_id != target_transaction_id
            or handoff_lease.purpose is not LeasePurpose.RECOVERY
            or handoff_lease.released_at is not None
            or handoff_lease.acquired_at > created_at
            or handoff_lease.expires_at <= created_at
            or handoff_lease.expires_at > binding.absolute_deadline
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery action handoff differs from its lease or durable deadline",
            )
        required_state = {
            RecoveryWorkKind.DISCARD_STAGING: TransactionState.ABORTING,
            RecoveryWorkKind.ROLLBACK: TransactionState.FAILED,
            RecoveryWorkKind.COMPENSATE: TransactionState.FAILED,
            RecoveryWorkKind.RECONCILE_DISPATCH: TransactionState.IN_DOUBT,
        }[binding.recovery_kind]
        try:
            with self._immediate():
                transaction = self._get_enforced_transaction_tx(
                    tenant_id,
                    target_transaction_id,
                )
                stored_lease = self._assert_active_lease_tx(
                    tenant_id=tenant_id,
                    transaction_id=target_transaction_id,
                    lease_id=handoff_lease.lease_id,
                    worker_id=handoff_lease.worker_id,
                    fencing_token=handoff_lease.fencing_token,
                    purpose=LeasePurpose.RECOVERY,
                    at=created_at,
                )
                target_action = self._get_normalized_action(
                    tenant_id,
                    target_transaction_id,
                ).action
                if (
                    stored_lease != handoff_lease
                    or transaction.state is not required_state
                    or transaction.version != expected_transaction_version
                    or not self._root_recovery_binding_matches_durable_bounds_tx(
                        transaction,
                        binding,
                    )
                    or transaction.intent_hash != binding.target_intent_hash
                    or transaction.normalized_action_digest
                    != binding.target_normalized_action_digest
                    or transaction.adapter_manifest_digest != binding.adapter_manifest_digest
                    or transaction.updated_at > created_at
                    or target_action.risk_floor is not binding.risk_class
                    or target_action.effect_domains != binding.effect_domains
                    or canonical_digest(target_action.resource_uses) != binding.resource_uses_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery action handoff lost its exact target or lease",
                        retryable=False,
                    )
                if binding.recovery_kind is RecoveryWorkKind.DISCARD_STAGING:
                    stage = self._get_stage_material_tx(tenant_id, target_transaction_id)
                    ledger = self._validate_intent_ledger(
                        tenant_id,
                        binding.target_intent_hash,
                    )
                    target_matches = (
                        stage.stage_id == binding.target_id
                        and canonical_digest(stage) == binding.target_evidence_ref
                        and stage.target_version_guard == binding.target_version_guard
                        and stage.state
                        not in {StageMaterialState.DISCARDED, StageMaterialState.DISCARD_FAILED}
                        and ledger.owner_transaction_id == target_transaction_id
                        and ledger.owner_version == binding.target_owner_version
                        and ledger.head_sequence == binding.target_owner_history_sequence
                        and ledger.head_digest == binding.target_owner_history_digest
                    )
                else:
                    dispatch = self._get_commit_dispatch_tx(tenant_id, target_transaction_id)
                    target_matches = (
                        dispatch.dispatch_id == binding.target_id
                        and canonical_digest(dispatch) == binding.target_evidence_ref
                        and dispatch.permit.target_version_guard == binding.target_version_guard
                        and dispatch.permit.owner_version == binding.target_owner_version
                        and dispatch.permit.owner_history_sequence
                        == binding.target_owner_history_sequence
                        and dispatch.permit.owner_history_digest
                        == binding.target_owner_history_digest
                    )
                if not target_matches:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery action handoff differs from its exact target generation",
                        retryable=False,
                    )
                existing_work = self._connection.execute(
                    "SELECT 1 FROM enforced_recovery_work "
                    "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ?",
                    (tenant_id, target_transaction_id, binding.recovery_id),
                ).fetchone()
                if existing_work is not None:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery action handoff cannot overlap its durable work",
                        retryable=True,
                    )
                existing = self._connection.execute(
                    "SELECT * FROM enforced_recovery_action_handoffs "
                    "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
                    (tenant_id, target_transaction_id, binding.recovery_id),
                ).fetchone()
                if existing is not None:
                    handoff = self._recovery_action_handoff_from_row(
                        existing,
                        tenant_id=tenant_id,
                        target_transaction_id=target_transaction_id,
                        recovery_id=binding.recovery_id,
                    )
                    if (
                        handoff.binding != binding
                        or handoff.binding_ref != binding_ref
                        or handoff.closed_at is not None
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery action handoff retry changed immutable binding",
                        )
                    self._assert_recovery_handoff_lease_lineage_tx(
                        handoff,
                        tenant_id=tenant_id,
                        expected_active=stored_lease,
                    )
                    return handoff
                if (
                    binding.recovery_ordinal == 1
                    and binding.recovery_kind is RecoveryWorkKind.RECONCILE_DISPATCH
                ):
                    historical_lineage = self._connection.execute(
                        "SELECT 1 FROM enforced_recovery_action_handoffs "
                        "WHERE tenant_id = ? AND target_transaction_id = ? "
                        "AND target_id = ? AND recovery_id != ? LIMIT 1",
                        (
                            tenant_id,
                            target_transaction_id,
                            binding.target_id,
                            binding.recovery_id,
                        ),
                    ).fetchone()
                    if historical_lineage is not None:
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Dispatch target already has a durable reconciliation lineage",
                            retryable=False,
                        )
                open_rows = self._connection.execute(
                    "SELECT * FROM enforced_recovery_action_handoffs "
                    "WHERE tenant_id = ? AND target_transaction_id = ? AND target_id = ? "
                    "AND recovery_id != ? AND closed_at IS NULL ORDER BY created_at, recovery_id",
                    (
                        tenant_id,
                        target_transaction_id,
                        binding.target_id,
                        binding.recovery_id,
                    ),
                ).fetchall()
                immediate_predecessor_seen = False
                for open_row in open_rows:
                    open_recovery_id = str(open_row["recovery_id"])
                    open_work_row = self._connection.execute(
                        "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
                        "AND transaction_id = ? AND recovery_id = ?",
                        (tenant_id, target_transaction_id, open_recovery_id),
                    ).fetchone()
                    if open_work_row is None:
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Recovery target generation already has an open pre-work handoff",
                            retryable=False,
                        )
                    self._recovery_action_handoff_from_row(
                        open_row,
                        tenant_id=tenant_id,
                        target_transaction_id=target_transaction_id,
                        recovery_id=open_recovery_id,
                    )
                    predecessor = self._recovery_from_row(open_work_row)
                    settled_lineage = (
                        predecessor.kind is not binding.recovery_kind
                        and predecessor.state
                        in {
                            RecoveryWorkState.SUCCEEDED,
                            RecoveryWorkState.FAILED,
                            RecoveryWorkState.REVIEW_REQUIRED,
                            RecoveryWorkState.RETRIED,
                        }
                        and self._connection.execute(
                            "SELECT 1 FROM enforced_recovery_work "
                            "WHERE tenant_id = ? AND transaction_id = ? "
                            "AND root_recovery_id = ? "
                            "AND state IN ('PENDING', 'RUNNING', 'RETRY_SCHEDULED') "
                            "LIMIT 1",
                            (
                                tenant_id,
                                target_transaction_id,
                                predecessor.root_recovery_id,
                            ),
                        ).fetchone()
                        is None
                    )
                    if settled_lineage:
                        self._validate_recovery_work_handoff_lifecycle_tx(predecessor)
                        predecessor_lease = (
                            None
                            if predecessor.lease_id is None
                            else self._get_worker_lease_tx(
                                tenant_id,
                                target_transaction_id,
                                predecessor.lease_id,
                            )
                        )
                        if predecessor_lease is not None and predecessor_lease.released_at is None:
                            raise AgentKernelError(
                                ErrorCode.VERSION_CONFLICT,
                                "Settled recovery lineage retains an active execution lease",
                                retryable=False,
                            )
                        continue
                    common_lineage = (
                        binding.recovery_ordinal > 1
                        and predecessor.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                        and predecessor.root_recovery_id == binding.root_recovery_id
                        and predecessor.target_id == binding.target_id
                        and predecessor.target_version_guard == binding.target_version_guard
                        and predecessor.target_owner_version == binding.target_owner_version
                        and predecessor.target_owner_history_sequence
                        == binding.target_owner_history_sequence
                        and predecessor.target_owner_history_digest
                        == binding.target_owner_history_digest
                        and predecessor.intent_hash == binding.target_intent_hash
                        and predecessor.adapter_manifest_digest == binding.adapter_manifest_digest
                        and predecessor.deadline == binding.absolute_deadline
                    )
                    if (
                        common_lineage
                        and predecessor.recovery_id == binding.predecessor_recovery_id
                    ):
                        attempt = self._get_reconciliation_attempt_tx(
                            tenant_id,
                            target_transaction_id,
                            predecessor.recovery_id,
                            predecessor.attempt,
                        )
                        predecessor_lease = (
                            None
                            if predecessor.lease_id is None
                            else self._get_worker_lease_tx(
                                tenant_id,
                                target_transaction_id,
                                predecessor.lease_id,
                            )
                        )
                        if (
                            immediate_predecessor_seen
                            or predecessor.state is not RecoveryWorkState.RETRY_SCHEDULED
                            or predecessor.recovery_ordinal + 1 != binding.recovery_ordinal
                            or predecessor.recovery_ordinal >= predecessor.max_recovery_attempts
                            or predecessor.max_recovery_attempts != binding.max_recovery_attempts
                            or attempt.outcome is not ReconciliationOutcome.UNKNOWN
                            or attempt.next_attempt_not_before is None
                            or attempt.next_attempt_not_before != binding.not_before
                            or predecessor_lease is None
                            or predecessor_lease.released_at is None
                        ):
                            raise AgentKernelError(
                                ErrorCode.VERSION_CONFLICT,
                                "Recovery handoff successor differs from its retry predecessor",
                                retryable=False,
                            )
                        immediate_predecessor_seen = True
                        continue
                    if (
                        common_lineage
                        and predecessor.state is RecoveryWorkState.RETRIED
                        and predecessor.recovery_ordinal < binding.recovery_ordinal - 1
                    ):
                        continue
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery target generation already has conflicting open work",
                        retryable=False,
                    )
                if binding.recovery_ordinal > 1 and not immediate_predecessor_seen:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery handoff retry lost its exact predecessor",
                        retryable=False,
                    )
                self._execute(
                    "INSERT INTO enforced_recovery_action_handoffs("
                    "tenant_id, target_transaction_id, recovery_id, recovery_kind, "
                    "target_id, target_evidence_ref, binding_ref, binding_json, "
                    "handoff_lease_id, handoff_worker_id, handoff_fencing_token, "
                    "recovery_action_transaction_id, recovery_action_intent_hash, "
                    "recovery_action_digest, created_at, attached_at, closed_at, "
                    "failure_evidence_ref, failure_reason_code) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "NULL, NULL, NULL, ?, NULL, NULL, NULL, NULL)",
                    (
                        tenant_id,
                        target_transaction_id,
                        binding.recovery_id,
                        binding.recovery_kind.value,
                        binding.target_id,
                        binding.target_evidence_ref,
                        binding_ref,
                        binding_json,
                        handoff_lease.lease_id,
                        handoff_lease.worker_id,
                        handoff_lease.fencing_token,
                        _timestamp(created_at),
                    ),
                )
                return RecoveryActionHandoff(
                    action=None,
                    binding=binding,
                    binding_ref=binding_ref,
                    handoff_lease_id=handoff_lease.lease_id,
                    handoff_worker_id=handoff_lease.worker_id,
                    handoff_fencing_token=handoff_lease.fencing_token,
                    created_at=created_at,
                    attached_at=None,
                    closed_at=None,
                    terminal_sequence=None,
                    failure_evidence_status=RecoveryHandoffFailureEvidenceStatus.NONE,
                    failure_evidence_ref=None,
                    failure_reason_code=None,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity(
                "Recovery action handoff reservation failed",
                error,
            ) from error

    def register_recovery_action(
        self,
        action: NormalizedAction,
        *,
        registered_at: datetime,
        binding: RecoveryActionBinding | None = None,
    ) -> IntentAcquisition:
        """Atomically normalize/acquire a recovery subject whose intent history is its lifecycle."""

        timestamp = _timestamp(registered_at)
        action_digest = canonical_digest(action)
        binding_ref: str | None = None
        if binding is not None:
            binding = RecoveryActionBinding.model_validate(binding.model_dump(mode="python"))
            binding_ref = canonical_digest(binding)
            binding_arguments = tuple(
                argument
                for argument in action.semantic_arguments
                if argument.argument_name == RECOVERY_ACTION_BINDING_ARGUMENT
            )
            if (
                len(binding_arguments) != 1
                or binding_arguments[0].digest != binding_ref
                or binding.target_transaction_id == action.transaction_id
                or binding.absolute_deadline != action.deadline
            ):
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Recovery action association differs from its canonical binding",
                )
        with self._immediate():
            transaction = self._connection.execute(
                "SELECT 1 FROM enforced_transactions WHERE tenant_id = ? AND transaction_id = ?",
                (action.tenant_id, action.transaction_id),
            ).fetchone()
            if transaction is not None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery action must not create a dangling enforced transaction",
                )
            association: sqlite3.Row | None = None
            if binding is not None and binding_ref is not None:
                association = self._connection.execute(
                    "SELECT * FROM enforced_recovery_action_handoffs "
                    "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
                    (action.tenant_id, binding.target_transaction_id, binding.recovery_id),
                ).fetchone()
                if association is None:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery action lacks its pre-provider durable handoff",
                        retryable=False,
                    )
                handoff = self._recovery_action_handoff_from_row(
                    association,
                    tenant_id=action.tenant_id,
                    target_transaction_id=binding.target_transaction_id,
                    recovery_id=binding.recovery_id,
                )
                if (
                    handoff.binding != binding
                    or handoff.binding_ref != binding_ref
                    or handoff.closed_at is not None
                    or registered_at < handoff.created_at
                    or registered_at >= binding.absolute_deadline
                    or (handoff.action is not None and handoff.action != action)
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery action attachment changed or outlived its durable handoff",
                        retryable=False,
                    )
                target_action = self._get_normalized_action(
                    action.tenant_id,
                    binding.target_transaction_id,
                ).action
                self._assert_recovery_action_mirrors_target_tx(
                    handoff,
                    tenant_id=action.tenant_id,
                    target_action=target_action,
                    action=action,
                )
            self._put_normalized_action_tx(
                action,
                recorded_at=timestamp,
                action_digest=action_digest,
            )
            acquisition = self._acquire_intent_tx(
                tenant_id=action.tenant_id,
                intent_hash=action.intent_hash,
                transaction_id=action.transaction_id,
                attempted_at=timestamp,
                expected_owner_version=None,
            )
            if acquisition.disposition not in {
                IntentDisposition.ACQUIRED,
                IntentDisposition.SAME_TRANSACTION,
            }:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery action did not acquire its own distinct intent",
                )
            if binding is not None and binding_ref is not None and association is not None:
                if association["recovery_action_transaction_id"] is None:
                    cursor = self._execute(
                        "UPDATE enforced_recovery_action_handoffs SET "
                        "recovery_action_transaction_id = ?, recovery_action_intent_hash = ?, "
                        "recovery_action_digest = ?, attached_at = ? "
                        "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ? "
                        "AND recovery_action_transaction_id IS NULL AND closed_at IS NULL",
                        (
                            action.transaction_id,
                            action.intent_hash,
                            action_digest,
                            timestamp,
                            action.tenant_id,
                            binding.target_transaction_id,
                            binding.recovery_id,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Recovery action handoff attachment lost its compare-and-swap",
                            retryable=True,
                        )
                elif (
                    str(association["recovery_action_transaction_id"]) != action.transaction_id
                    or str(association["recovery_action_intent_hash"]) != action.intent_hash
                    or str(association["recovery_action_digest"]) != action_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery action handoff retry changed its attached action",
                    )
            return acquisition

    def _round_from_row(self, row: sqlite3.Row) -> AuthorizationRoundRecord:
        try:
            record = AuthorizationRoundRecord.model_validate_json(str(row["round_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored authorization round is invalid",
            ) from error
        expected: dict[str, object] = {
            "tenant_id": record.tenant_id,
            "controlled_transaction_id": record.controlled_transaction_id,
            "round_id": record.round_id,
            "subject_transaction_id": record.subject_transaction_id,
            "subject_intent_hash": record.subject_intent_hash,
            "subject_normalized_action_digest": record.subject_normalized_action_digest,
            "purpose": record.purpose.value,
            "verdict": record.verdict.value,
            "authority_snapshot_id": record.authority_snapshot_id,
            "authority_snapshot_digest": record.authority_snapshot_digest,
            "authority_snapshot_ref": record.authority_snapshot_ref,
            "authority_context_ref": record.authority_context_ref,
            "authority_decision_kind": DecisionKind.AUTHORITY.value,
            "authority_decision_id": record.authority_decision_id,
            "authority_decision_record_digest": record.authority_decision_record_digest,
            "authority_decision_digest": record.authority_decision_digest,
            "authority_decision_ref": record.authority_decision_ref,
            "policy_decision_kind": DecisionKind.POLICY.value,
            "policy_decision_id": record.policy_decision_id,
            "policy_decision_record_digest": record.policy_decision_record_digest,
            "policy_decision_digest": record.policy_decision_digest,
            "policy_inputs_ref": record.policy_inputs_ref,
            "policy_snapshot_digest": record.policy_snapshot_digest,
            "policy_snapshot_ref": record.policy_snapshot_ref,
            "policy_decision_ref": record.policy_decision_ref,
            "capability_reservation_plan_digest": (record.capability_reservation_plan_digest),
            "capability_reservation_digest": record.capability_reservation_digest,
            "reservation_version": record.reservation_version,
            "reservation_goal_id": record.reservation_goal_id,
            "reservation_run_id": record.reservation_run_id,
            "owner_version": record.owner_version,
            "owner_history_sequence": record.owner_history_sequence,
            "owner_history_digest": record.owner_history_digest,
            "allowed_modes_json": canonical_json_text(record.allowed_modes),
            "obligations_json": canonical_json_text(record.obligations),
            "reason_code": record.reason_code,
            "evaluated_at": _timestamp(record.evaluated_at),
            "authority_valid_until": (
                None
                if record.authority_valid_until is None
                else _timestamp(record.authority_valid_until)
            ),
            "round_digest": record.round_digest,
            "round_json": canonical_json_text(record),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Authorization round projection differs from canonical content",
            )
        return record

    def _get_authorization_round_tx(
        self,
        tenant_id: str,
        controlled_transaction_id: str,
        round_id: str,
    ) -> AuthorizationRoundRecord:
        row = self._connection.execute(
            "SELECT * FROM enforced_authorization_rounds "
            "WHERE tenant_id = ? AND controlled_transaction_id = ? AND round_id = ?",
            (tenant_id, controlled_transaction_id, round_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unknown authorization round in this tenant",
            )
        return self._round_from_row(row)

    def get_authorization_round(
        self,
        *,
        tenant_id: str,
        controlled_transaction_id: str,
        round_id: str,
    ) -> AuthorizationRoundRecord:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        controlled_transaction_id = _require_identifier(
            controlled_transaction_id,
            field="controlled_transaction_id",
        )
        round_id = _require_identifier(round_id, field="round_id")
        return self._get_authorization_round_tx(
            tenant_id,
            controlled_transaction_id,
            round_id,
        )

    def _insert_authorization_round_tx(self, record: AuthorizationRoundRecord) -> bool:
        existing = self._connection.execute(
            "SELECT * FROM enforced_authorization_rounds "
            "WHERE tenant_id = ? AND controlled_transaction_id = ? AND round_id = ?",
            (record.tenant_id, record.controlled_transaction_id, record.round_id),
        ).fetchone()
        if existing is not None:
            if self._round_from_row(existing) != record:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Authorization round identity has conflicting immutable content",
                )
            return False
        columns = (
            "tenant_id",
            "controlled_transaction_id",
            "round_id",
            "subject_transaction_id",
            "subject_intent_hash",
            "subject_normalized_action_digest",
            "purpose",
            "verdict",
            "authority_snapshot_id",
            "authority_snapshot_digest",
            "authority_snapshot_ref",
            "authority_context_ref",
            "authority_decision_kind",
            "authority_decision_id",
            "authority_decision_record_digest",
            "authority_decision_digest",
            "authority_decision_ref",
            "policy_decision_kind",
            "policy_decision_id",
            "policy_decision_record_digest",
            "policy_decision_digest",
            "policy_inputs_ref",
            "policy_snapshot_digest",
            "policy_snapshot_ref",
            "policy_decision_ref",
            "capability_reservation_plan_digest",
            "capability_reservation_digest",
            "reservation_version",
            "reservation_goal_id",
            "reservation_run_id",
            "owner_version",
            "owner_history_sequence",
            "owner_history_digest",
            "allowed_modes_json",
            "obligations_json",
            "reason_code",
            "evaluated_at",
            "authority_valid_until",
            "round_digest",
            "round_json",
        )
        values: tuple[object, ...] = (
            record.tenant_id,
            record.controlled_transaction_id,
            record.round_id,
            record.subject_transaction_id,
            record.subject_intent_hash,
            record.subject_normalized_action_digest,
            record.purpose.value,
            record.verdict.value,
            record.authority_snapshot_id,
            record.authority_snapshot_digest,
            record.authority_snapshot_ref,
            record.authority_context_ref,
            DecisionKind.AUTHORITY.value,
            record.authority_decision_id,
            record.authority_decision_record_digest,
            record.authority_decision_digest,
            record.authority_decision_ref,
            DecisionKind.POLICY.value,
            record.policy_decision_id,
            record.policy_decision_record_digest,
            record.policy_decision_digest,
            record.policy_inputs_ref,
            record.policy_snapshot_digest,
            record.policy_snapshot_ref,
            record.policy_decision_ref,
            record.capability_reservation_plan_digest,
            record.capability_reservation_digest,
            record.reservation_version,
            record.reservation_goal_id,
            record.reservation_run_id,
            record.owner_version,
            record.owner_history_sequence,
            record.owner_history_digest,
            canonical_json_text(record.allowed_modes),
            canonical_json_text(record.obligations),
            record.reason_code,
            _timestamp(record.evaluated_at),
            (
                None
                if record.authority_valid_until is None
                else _timestamp(record.authority_valid_until)
            ),
            record.round_digest,
            canonical_json_text(record),
        )
        self._execute(
            f"INSERT INTO enforced_authorization_rounds({', '.join(columns)}) "  # noqa: S608  # nosec B608
            f"VALUES ({', '.join('?' for _ in columns)})",
            values,
        )
        return True

    @staticmethod
    def _assert_round_decision_semantics(
        record: AuthorizationRoundRecord,
        *,
        action: NormalizedAction,
        authority: EnforcedAuthorityDecision,
        policy: AggregatePolicyDecision,
        capability_ids: tuple[str, ...],
    ) -> None:
        if not isinstance(authority, EnforcedAuthorityDecision) or not isinstance(
            policy, AggregatePolicyDecision
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Authorization persistence accepts only native strict decision models",
            )
        expected_resources = tuple(
            (
                index,
                canonical_digest(resource),
                resource.authority_action,
                resource.canonical_resource,
                resource.provenance_ids,
            )
            for index, resource in enumerate(action.resource_uses)
        )
        authority_resources = tuple(
            (
                decision.resource_index,
                decision.resource_use_digest,
                decision.authority_action,
                decision.canonical_resource,
                decision.provenance_ids,
            )
            for decision in authority.resource_decisions
        )
        policy_resources = {
            resource.resource_index: (resource.resource_use_ref, resource.resource_use)
            for resource in policy.resource_inputs
        }
        expected_policy_resources = {
            index: (canonical_digest(resource), resource)
            for index, resource in enumerate(action.resource_uses)
        }
        if (
            record.schema_version != "1.1"
            or authority.tenant_id != record.tenant_id
            or authority.transaction_id != record.subject_transaction_id
            or authority.intent_hash != record.subject_intent_hash
            or authority.evaluated_at != record.evaluated_at
            or authority.authority_snapshot_id != record.authority_snapshot_id
            or authority.authority_snapshot_digest != record.authority_snapshot_digest
            or authority.decision_digest != record.authority_decision_digest
            or policy.normalized_action != action
            or policy.authority_decision != authority
            or policy.aggregate_digest != record.policy_decision_digest
            or policy.policy_snapshot.snapshot_digest != record.policy_snapshot_digest
            or authority_resources != expected_resources
            or policy_resources != expected_policy_resources
            or len(policy_resources) != len(policy.resource_inputs)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Authorization evidence differs from its exact action, resources, or snapshots",
            )
        bound_capabilities = (
            () if authority.reservation_plan is None else authority.reservation_plan.capability_ids
        )
        if authority.verdict is AuthorityEvaluationVerdict.DENY:
            expected_verdict = AuthorizationVerdict.DENIED
            expected_reason = authority.reason_code.value
        elif policy.verdict is PolicyVerdict.ELIGIBLE:
            expected_verdict = AuthorizationVerdict.ELIGIBLE
            expected_reason = policy.reason_code
        elif policy.verdict is PolicyVerdict.DENY and (
            policy.reason_code == ErrorCode.POLICY_UNKNOWN.value or bool(policy.unknown_facts)
        ):
            expected_verdict = AuthorizationVerdict.UNKNOWN
            expected_reason = ErrorCode.POLICY_UNKNOWN.value
        else:
            expected_verdict = AuthorizationVerdict.DENIED
            expected_reason = policy.reason_code
        if (
            record.verdict is not expected_verdict
            or record.reason_code != expected_reason
            or (
                record.verdict is AuthorizationVerdict.ELIGIBLE
                and (
                    authority.verdict is not AuthorityEvaluationVerdict.ALLOW
                    or policy.verdict is not PolicyVerdict.ELIGIBLE
                    or bound_capabilities != capability_ids
                    or record.allowed_modes != policy.allowed_modes
                    or record.obligations != policy.obligations
                )
            )
            or (
                record.verdict is not AuthorizationVerdict.ELIGIBLE
                and (capability_ids or record.allowed_modes or record.obligations)
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Authorization round contradicts strict authority or policy evidence",
            )

    def _persist_round_dependencies_tx(
        self,
        record: AuthorizationRoundRecord,
        *,
        authority_decision: EnforcedAuthorityDecision,
        policy_decision: AggregatePolicyDecision,
        capability_ids: Sequence[str],
    ) -> CapabilityChainReservation | None:
        if not isinstance(authority_decision, EnforcedAuthorityDecision) or not isinstance(
            policy_decision, AggregatePolicyDecision
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Authorization persistence requires native strict decision models",
            )
        subject = self._get_normalized_action(
            record.tenant_id,
            record.subject_transaction_id,
        )
        if (
            subject.action.intent_hash != record.subject_intent_hash
            or subject.action_digest != record.subject_normalized_action_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Authorization subject differs from its normalized action",
            )
        try:
            authority = EnforcedAuthorityDecision.model_validate(
                authority_decision.model_dump(mode="python")
            )
            policy = AggregatePolicyDecision.model_validate(
                policy_decision.model_dump(mode="python")
            )
        except ValidationError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Authorization decision model failed strict revalidation",
            ) from error
        if record.verdict is AuthorizationVerdict.ELIGIBLE:
            normalized_ids = self._validated_capability_ids(capability_ids)
        else:
            if capability_ids:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Ineligible authorization cannot reserve capabilities",
                )
            normalized_ids = ()
        self._assert_round_decision_semantics(
            record,
            action=subject.action,
            authority=authority,
            policy=policy,
            capability_ids=normalized_ids,
        )
        authority_snapshot = self.append_decision_snapshot(
            tenant_id=record.tenant_id,
            kind=DecisionKind.AUTHORITY,
            decision_id=record.authority_decision_id,
            transaction_id=record.subject_transaction_id,
            intent_hash=record.subject_intent_hash,
            decision=authority,
            recorded_at=record.evaluated_at,
        )
        policy_snapshot = self.append_decision_snapshot(
            tenant_id=record.tenant_id,
            kind=DecisionKind.POLICY,
            decision_id=record.policy_decision_id,
            transaction_id=record.subject_transaction_id,
            intent_hash=record.subject_intent_hash,
            decision=policy,
            recorded_at=record.evaluated_at,
        )
        if (
            authority_snapshot.decision_digest != record.authority_decision_record_digest
            or policy_snapshot.decision_digest != record.policy_decision_record_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Authorization round decision-record digest differs from durable evidence",
            )
        ledger = self._validate_intent_ledger(record.tenant_id, record.subject_intent_hash)
        if (
            ledger.owner_transaction_id != record.subject_transaction_id
            or ledger.owner_version != record.owner_version
            or ledger.head_sequence != record.owner_history_sequence
            or ledger.head_digest != record.owner_history_digest
        ):
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Authorization round no longer matches intent ownership evidence",
                retryable=False,
            )
        if record.verdict is not AuthorizationVerdict.ELIGIBLE:
            return None
        expected_plan = capability_reservation_plan_digest(
            tenant_id=record.tenant_id,
            goal_id=subject.action.goal_id,
            run_id=subject.action.run_id,
            intent_hash=record.subject_intent_hash,
            capability_ids=normalized_ids,
        )
        if record.capability_reservation_plan_digest != expected_plan:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Authorization round capability plan digest is inconsistent",
            )
        reservation = self.reserve_capability_chain(
            tenant_id=record.tenant_id,
            goal_id=subject.action.goal_id,
            run_id=subject.action.run_id,
            intent_hash=record.subject_intent_hash,
            capability_ids=normalized_ids,
            reserved_at=record.evaluated_at,
        )
        if (
            record.reservation_goal_id != reservation.goal_id
            or record.reservation_run_id != reservation.run_id
            or record.reservation_version != reservation.version
            or record.capability_reservation_digest != capability_reservation_digest(reservation)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Authorization round differs from the durable capability reservation",
            )
        return reservation

    def authorize_for_staging(
        self,
        record: AuthorizationRoundRecord,
        *,
        authority_decision: EnforcedAuthorityDecision,
        policy_decision: AggregatePolicyDecision,
        capability_ids: Sequence[str] = (),
        expected_transaction_version: int,
    ) -> AuthorizationResult:
        """Persist decisions, reserve the full chain, and CAS PLANNED atomically."""

        if record.purpose is not AuthorizationRoundPurpose.STAGING:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Staging authorization requires a STAGING round",
            )
        if record.controlled_transaction_id != record.subject_transaction_id:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Staging authorization subject must be the controlled transaction",
            )
        try:
            with self._immediate():
                current = self._get_enforced_transaction_tx(
                    record.tenant_id,
                    record.controlled_transaction_id,
                )
                existing = self._connection.execute(
                    "SELECT * FROM enforced_authorization_rounds "
                    "WHERE tenant_id = ? AND controlled_transaction_id = ? AND round_id = ?",
                    (record.tenant_id, record.controlled_transaction_id, record.round_id),
                ).fetchone()
                if existing is not None:
                    stored_round = self._round_from_row(existing)
                    normalized_ids = self._validated_capability_ids(capability_ids)
                    self._assert_round_decision_semantics(
                        record,
                        action=self._get_normalized_action(
                            record.tenant_id,
                            record.subject_transaction_id,
                        ).action,
                        authority=authority_decision,
                        policy=policy_decision,
                        capability_ids=normalized_ids,
                    )
                    if stored_round != record:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Staging authorization retry changed the immutable round",
                        )
                    reservation = (
                        None
                        if record.verdict is not AuthorizationVerdict.ELIGIBLE
                        else self._read_capability_chain(
                            tenant_id=record.tenant_id,
                            goal_id=cast("str", record.reservation_goal_id),
                            run_id=cast("str", record.reservation_run_id),
                            intent_hash=record.subject_intent_hash,
                        )
                    )
                    if record.verdict is AuthorizationVerdict.ELIGIBLE and reservation is None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Stored eligible round lost its capability reservation",
                        )
                    transition_event = (
                        TransitionEvent.AUTHORIZED_FOR_STAGING
                        if record.verdict is AuthorizationVerdict.ELIGIBLE
                        else TransitionEvent.AUTHORITY_OR_POLICY_DENIED
                    )
                    expected_target = apply_transition(
                        TransactionState.PLANNED,
                        transition_event,
                    ).target
                    events = self._validate_transaction_chain_tx(current)
                    latest_event = events[-1]
                    expected_refs = set(_authorization_evidence_refs(record))
                    if (
                        current.version != expected_transaction_version + 1
                        or current.state is not expected_target
                        or current.intent_hash != record.subject_intent_hash
                        or current.normalized_action_digest
                        != record.subject_normalized_action_digest
                        or latest_event.event != transition_event.value
                        or latest_event.source_state is not TransactionState.PLANNED
                        or latest_event.target_state is not expected_target
                        or latest_event.recorded_at != record.evaluated_at
                        or not expected_refs.issubset(latest_event.evidence_refs)
                    ):
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Staging authorization retry no longer matches its exact generation",
                        )
                    if record.verdict is AuthorizationVerdict.ELIGIBLE:
                        if reservation is None:
                            raise AgentKernelError(
                                ErrorCode.INTEGRITY_ERROR,
                                "Eligible staging retry lost its capability reservation",
                            )
                        if (
                            reservation.state is not CapabilityReservationState.RESERVED
                            or reservation.version != record.reservation_version
                            or capability_reservation_digest(reservation)
                            != record.capability_reservation_digest
                            or current.authorization_round_id != record.round_id
                            or current.authorization_round_digest != record.round_digest
                        ):
                            raise AgentKernelError(
                                ErrorCode.INTEGRITY_ERROR,
                                "Staging retry lost its exact reserved authority generation",
                            )
                    return AuthorizationResult(
                        current,
                        None,
                        stored_round,
                        reservation,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                if current.version != expected_transaction_version:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Staging authorization source version changed",
                        retryable=True,
                    )
                if (
                    current.state is not TransactionState.PLANNED
                    or current.intent_hash != record.subject_intent_hash
                    or current.normalized_action_digest != record.subject_normalized_action_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.ILLEGAL_TRANSITION,
                        "Staging authorization requires the exact PLANNED transaction",
                    )
                reservation = self._persist_round_dependencies_tx(
                    record,
                    authority_decision=authority_decision,
                    policy_decision=policy_decision,
                    capability_ids=capability_ids,
                )
                self._insert_authorization_round_tx(record)
                if record.verdict is AuthorizationVerdict.ELIGIBLE:
                    if reservation is None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Eligible staging authorization was not reserved",
                        )
                    updated, event = self._apply_transition_tx(
                        current,
                        expected_version=expected_transaction_version,
                        transition_event=TransitionEvent.AUTHORIZED_FOR_STAGING,
                        recorded_at=record.evaluated_at,
                        evidence_refs=_authorization_evidence_refs(record),
                        updates={
                            "authorization_round_id": record.round_id,
                            "authorization_round_digest": record.round_digest,
                            "authority_decision_digest": record.authority_decision_digest,
                            "policy_decision_digest": record.policy_decision_digest,
                            "policy_snapshot_digest": record.policy_snapshot_digest,
                            "capability_reservation_digest": (record.capability_reservation_digest),
                            "allowed_modes": record.allowed_modes,
                            "obligations": record.obligations,
                        },
                    )
                else:
                    updated, event = self._apply_transition_tx(
                        current,
                        expected_version=expected_transaction_version,
                        transition_event=TransitionEvent.AUTHORITY_OR_POLICY_DENIED,
                        recorded_at=record.evaluated_at,
                        evidence_refs=_authorization_evidence_refs(record),
                        reason_code=record.reason_code,
                    )
                return AuthorizationResult(
                    updated,
                    event,
                    record,
                    reservation,
                    EnforcedStoreDisposition.STORED,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Atomic staging authorization failed closed", error) from error

    def authorize_for_precommit(
        self,
        record: AuthorizationRoundRecord,
        *,
        authority_decision: EnforcedAuthorityDecision,
        policy_decision: AggregatePolicyDecision,
        capability_ids: Sequence[str] = (),
        expected_transaction_version: int,
    ) -> AuthorizationResult:
        """Persist eligible precommit evidence while leaving READY_TO_COMMIT unchanged."""

        if (
            record.purpose is not AuthorizationRoundPurpose.PRECOMMIT
            or record.verdict is not AuthorizationVerdict.ELIGIBLE
            or record.controlled_transaction_id != record.subject_transaction_id
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Precommit authorization requires an eligible self-subject PRECOMMIT round",
            )
        try:
            with self._immediate():
                current = self._get_enforced_transaction_tx(
                    record.tenant_id,
                    record.controlled_transaction_id,
                )
                existing = self._connection.execute(
                    "SELECT * FROM enforced_authorization_rounds WHERE tenant_id = ? "
                    "AND controlled_transaction_id = ? AND round_id = ?",
                    (record.tenant_id, record.controlled_transaction_id, record.round_id),
                ).fetchone()
                if existing is not None:
                    stored = self._round_from_row(existing)
                    normalized_ids = self._validated_capability_ids(capability_ids)
                    self._assert_round_decision_semantics(
                        record,
                        action=self._get_normalized_action(
                            record.tenant_id,
                            record.subject_transaction_id,
                        ).action,
                        authority=authority_decision,
                        policy=policy_decision,
                        capability_ids=normalized_ids,
                    )
                    if stored != record:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Precommit authorization retry changed its immutable round",
                        )
                    reservation = self._read_capability_chain(
                        tenant_id=record.tenant_id,
                        goal_id=cast("str", record.reservation_goal_id),
                        run_id=cast("str", record.reservation_run_id),
                        intent_hash=record.subject_intent_hash,
                        expected_capability_ids=normalized_ids,
                    )
                    if reservation is None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Stored precommit round lost its capability generation",
                        )
                    if (
                        current.state is not TransactionState.READY_TO_COMMIT
                        or current.version != expected_transaction_version
                        or current.intent_hash != record.subject_intent_hash
                        or current.normalized_action_digest
                        != record.subject_normalized_action_digest
                        or reservation.state is not CapabilityReservationState.RESERVED
                        or reservation.version != record.reservation_version
                        or capability_reservation_digest(reservation)
                        != record.capability_reservation_digest
                    ):
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Precommit authorization retry no longer controls the exact "
                            "ready generation",
                        )
                    return AuthorizationResult(
                        current,
                        None,
                        stored,
                        reservation,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                if (
                    current.state is not TransactionState.READY_TO_COMMIT
                    or current.version != expected_transaction_version
                    or current.intent_hash != record.subject_intent_hash
                    or current.normalized_action_digest != record.subject_normalized_action_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Precommit authorization requires the exact READY_TO_COMMIT generation",
                    )
                reservation = self._persist_round_dependencies_tx(
                    record,
                    authority_decision=authority_decision,
                    policy_decision=policy_decision,
                    capability_ids=capability_ids,
                )
                if reservation is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Eligible precommit authorization lost its capability reservation",
                    )
                self._insert_authorization_round_tx(record)
                return AuthorizationResult(
                    current,
                    None,
                    record,
                    reservation,
                    EnforcedStoreDisposition.STORED,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Precommit authorization failed closed", error) from error

    def record_precommit_denial(
        self,
        record: AuthorizationRoundRecord,
        *,
        authority_decision: EnforcedAuthorityDecision,
        policy_decision: AggregatePolicyDecision,
        expected_transaction_version: int,
        recovery_timeout: timedelta,
    ) -> AuthorizationResult:
        """Persist an ineligible PRECOMMIT round and abort before dispatch authority."""

        if not isinstance(recovery_timeout, timedelta) or recovery_timeout <= timedelta(0):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Precommit denial recovery timeout must be positive",
            )
        if (
            record.purpose is not AuthorizationRoundPurpose.PRECOMMIT
            or record.verdict is AuthorizationVerdict.ELIGIBLE
            or record.controlled_transaction_id != record.subject_transaction_id
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Precommit denial requires an ineligible self-subject PRECOMMIT round",
            )
        try:
            with self._immediate():
                current = self._get_enforced_transaction_tx(
                    record.tenant_id,
                    record.controlled_transaction_id,
                )
                existing = self._connection.execute(
                    "SELECT * FROM enforced_authorization_rounds WHERE tenant_id = ? "
                    "AND controlled_transaction_id = ? AND round_id = ?",
                    (record.tenant_id, record.controlled_transaction_id, record.round_id),
                ).fetchone()
                if existing is not None:
                    stored = self._round_from_row(existing)
                    self._assert_round_decision_semantics(
                        record,
                        action=self._get_normalized_action(
                            record.tenant_id,
                            record.subject_transaction_id,
                        ).action,
                        authority=authority_decision,
                        policy=policy_decision,
                        capability_ids=(),
                    )
                    if stored != record:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Precommit denial retry changed its immutable round",
                        )
                    events = self._validate_transaction_chain_tx(current)
                    latest_event = events[-1]
                    if (
                        current.state is not TransactionState.ABORTING
                        or current.version != expected_transaction_version + 1
                        or current.intent_hash != record.subject_intent_hash
                        or current.normalized_action_digest
                        != record.subject_normalized_action_digest
                        or latest_event.event != TransitionEvent.COMMIT_REVALIDATION_FAILED.value
                        or latest_event.source_state is not TransactionState.READY_TO_COMMIT
                        or latest_event.target_state is not TransactionState.ABORTING
                        or latest_event.recorded_at != record.evaluated_at
                        or current.reason_code != record.reason_code
                        or not set(_authorization_evidence_refs(record)).issubset(
                            latest_event.evidence_refs
                        )
                    ):
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Precommit denial retry no longer matches its exact abort generation",
                        )
                    return AuthorizationResult(
                        current,
                        None,
                        stored,
                        None,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                if (
                    current.state is not TransactionState.READY_TO_COMMIT
                    or current.version != expected_transaction_version
                    or current.intent_hash != record.subject_intent_hash
                    or current.normalized_action_digest != record.subject_normalized_action_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Precommit denial source is not the exact READY_TO_COMMIT generation",
                    )
                reservation = self._persist_round_dependencies_tx(
                    record,
                    authority_decision=authority_decision,
                    policy_decision=policy_decision,
                    capability_ids=(),
                )
                if reservation is not None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Ineligible precommit round unexpectedly reserved capability authority",
                    )
                self._insert_authorization_round_tx(record)
                updated, event = self._apply_transition_tx(
                    current,
                    expected_version=expected_transaction_version,
                    transition_event=TransitionEvent.COMMIT_REVALIDATION_FAILED,
                    recorded_at=record.evaluated_at,
                    evidence_refs=_authorization_evidence_refs(record),
                    reason_code=record.reason_code,
                    recovery_deadline=record.evaluated_at + recovery_timeout,
                )
                return AuthorizationResult(
                    updated,
                    event,
                    record,
                    None,
                    EnforcedStoreDisposition.STORED,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Precommit denial failed closed", error) from error

    def _lease_from_row(self, row: sqlite3.Row) -> WorkerLeaseRecord:
        try:
            lease = WorkerLeaseRecord.model_validate_json(str(row["record_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored worker lease is invalid",
            ) from error
        expected = {
            "tenant_id": lease.tenant_id,
            "transaction_id": lease.transaction_id,
            "lease_id": lease.lease_id,
            "worker_id": lease.worker_id,
            "purpose": lease.purpose.value,
            "fencing_token": lease.fencing_token,
            "version": lease.version,
            "acquired_at": _timestamp(lease.acquired_at),
            "expires_at": _timestamp(lease.expires_at),
            "released_at": (None if lease.released_at is None else _timestamp(lease.released_at)),
            "record_digest": canonical_digest(lease),
            "record_json": canonical_json_text(lease),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Worker lease projection differs from canonical content",
            )
        return lease

    def _get_worker_lease_tx(
        self,
        tenant_id: str,
        transaction_id: str,
        lease_id: str,
    ) -> WorkerLeaseRecord:
        row = self._connection.execute(
            "SELECT * FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND lease_id = ?",
            (tenant_id, transaction_id, lease_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Unknown worker lease")
        return self._lease_from_row(row)

    def get_worker_lease(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        lease_id: str,
    ) -> WorkerLeaseRecord:
        return self._get_worker_lease_tx(
            _require_identifier(tenant_id, field="tenant_id"),
            _require_identifier(transaction_id, field="transaction_id"),
            _require_identifier(lease_id, field="lease_id"),
        )

    def _update_worker_lease_tx(
        self,
        current: WorkerLeaseRecord,
        updated: WorkerLeaseRecord,
    ) -> WorkerLeaseRecord:
        cursor = self._execute(
            "UPDATE enforced_worker_leases SET version = ?, expires_at = ?, "
            "released_at = ?, record_digest = ?, record_json = ? "
            "WHERE tenant_id = ? AND transaction_id = ? AND lease_id = ? AND version = ? "
            "AND fencing_token = ? AND released_at IS ?",
            (
                updated.version,
                _timestamp(updated.expires_at),
                None if updated.released_at is None else _timestamp(updated.released_at),
                canonical_digest(updated),
                canonical_json_text(updated),
                current.tenant_id,
                current.transaction_id,
                current.lease_id,
                current.version,
                current.fencing_token,
                None if current.released_at is None else _timestamp(current.released_at),
            ),
        )
        if cursor.rowcount != 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Worker lease compare-and-swap failed",
                retryable=True,
            )
        return updated

    def _acquire_worker_lease_tx(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        lease_id: str,
        worker_id: str,
        purpose: LeasePurpose,
        acquired_at: datetime,
        expires_at: datetime,
    ) -> tuple[WorkerLeaseRecord, bool]:
        existing = self._connection.execute(
            "SELECT * FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND lease_id = ?",
            (tenant_id, transaction_id, lease_id),
        ).fetchone()
        if existing is not None:
            lease = self._lease_from_row(existing)
            if (
                lease.worker_id != worker_id
                or lease.purpose is not purpose
                or lease.acquired_at != acquired_at
                or lease.expires_at != expires_at
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Worker lease retry changed immutable acquisition content",
                )
            return lease, False
        active = self._connection.execute(
            "SELECT * FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
            (tenant_id, transaction_id),
        ).fetchone()
        if active is not None:
            active_lease = self._lease_from_row(active)
            if active_lease.expires_at > acquired_at:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Another unexpired worker lease owns this transaction",
                    retryable=True,
                )
            expired = WorkerLeaseRecord.model_validate(
                {
                    **active_lease.model_dump(mode="python"),
                    "version": active_lease.version + 1,
                    "released_at": acquired_at,
                }
            )
            self._update_worker_lease_tx(active_lease, expired)
        fence_row = self._connection.execute(
            "SELECT MAX(fencing_token) AS maximum FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ?",
            (tenant_id, transaction_id),
        ).fetchone()
        fencing_token = (
            1
            if fence_row is None or fence_row["maximum"] is None
            else int(fence_row["maximum"]) + 1
        )
        lease = WorkerLeaseRecord(
            tenant_id=tenant_id,
            transaction_id=transaction_id,
            lease_id=lease_id,
            worker_id=worker_id,
            purpose=purpose,
            fencing_token=fencing_token,
            version=0,
            acquired_at=acquired_at,
            expires_at=expires_at,
        )
        self._execute(
            "INSERT INTO enforced_worker_leases("
            "tenant_id, transaction_id, lease_id, worker_id, purpose, fencing_token, "
            "version, acquired_at, expires_at, released_at, record_digest, record_json) "
            "VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, NULL, ?, ?)",
            (
                lease.tenant_id,
                lease.transaction_id,
                lease.lease_id,
                lease.worker_id,
                lease.purpose.value,
                lease.fencing_token,
                _timestamp(lease.acquired_at),
                _timestamp(lease.expires_at),
                canonical_digest(lease),
                canonical_json_text(lease),
            ),
        )
        return lease, True

    def acquire_recovery_handoff_lease(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_transaction_version: int,
        stage_id: str,
        expected_stage_version: int,
        stage_target_ref: str,
        lease_id: str,
        worker_id: str,
        acquired_at: datetime,
        expires_at: datetime,
        binding: RecoveryActionBinding,
    ) -> WorkerLeaseResult:
        """Fence recovery-provider authorization before any RecoveryWork exists."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        stage_id = _require_identifier(stage_id, field="stage_id")
        stage_target_ref = _require_digest(stage_target_ref, field="stage_target_ref")
        lease_id = _require_identifier(lease_id, field="lease_id")
        worker_id = _require_identifier(worker_id, field="worker_id")
        if acquired_at >= expires_at:
            raise AgentKernelError(
                ErrorCode.DEADLINE_EXCEEDED,
                "Recovery handoff lease has no positive validity interval",
            )
        try:
            with self._immediate():
                transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
                stage = self._get_stage_material_tx(tenant_id, transaction_id)
                if (
                    transaction.state is not TransactionState.ABORTING
                    or transaction.version != expected_transaction_version
                    or binding.recovery_kind is not RecoveryWorkKind.DISCARD_STAGING
                    or not self._root_recovery_binding_matches_durable_bounds_tx(
                        transaction,
                        binding,
                    )
                    or stage.stage_id != stage_id
                    or stage.version != expected_stage_version
                    or canonical_digest(stage) != stage_target_ref
                    or stage.state
                    in {StageMaterialState.DISCARDED, StageMaterialState.DISCARD_FAILED}
                    or transaction.intent_hash != stage.intent_hash
                    or transaction.normalized_action_digest != stage.normalized_action_digest
                    or transaction.adapter_manifest_digest != stage.adapter_manifest_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery handoff lease differs from its exact ABORTING stage target",
                        retryable=False,
                    )
                recovery = self._connection.execute(
                    "SELECT 1 FROM enforced_recovery_work "
                    "WHERE tenant_id = ? AND transaction_id = ? "
                    "AND (kind = 'DISCARD_STAGING' "
                    "OR state IN ('PENDING', 'RUNNING', 'RETRY_SCHEDULED')) LIMIT 1",
                    (tenant_id, transaction_id),
                ).fetchone()
                if recovery is not None:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery handoff lease cannot overlap durable recovery work",
                        retryable=True,
                    )
                lease, created = self._acquire_worker_lease_tx(
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                    lease_id=lease_id,
                    worker_id=worker_id,
                    purpose=LeasePurpose.RECOVERY,
                    acquired_at=acquired_at,
                    expires_at=expires_at,
                )
                self.reserve_recovery_action_handoff(
                    tenant_id=tenant_id,
                    target_transaction_id=transaction_id,
                    expected_transaction_version=expected_transaction_version,
                    binding=binding,
                    created_at=acquired_at,
                    handoff_lease=lease,
                )
                return WorkerLeaseResult(
                    lease,
                    transaction,
                    None,
                    (
                        EnforcedStoreDisposition.STORED
                        if created
                        else EnforcedStoreDisposition.EXACT_RETRY
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Recovery handoff lease acquisition failed", error) from error

    def acquire_recovery_authorization_lease(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_transaction_version: int,
        kind: RecoveryWorkKind,
        dispatch_id: str,
        dispatch_target_ref: str,
        recovery_id: str,
        lease_id: str,
        worker_id: str,
        acquired_at: datetime,
        expires_at: datetime,
        binding: RecoveryActionBinding,
    ) -> WorkerLeaseResult:
        """Fence effect-bearing recovery authorization before provider or work creation."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        dispatch_id = _require_identifier(dispatch_id, field="dispatch_id")
        dispatch_target_ref = _require_digest(
            dispatch_target_ref,
            field="dispatch_target_ref",
        )
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        lease_id = _require_identifier(lease_id, field="lease_id")
        worker_id = _require_identifier(worker_id, field="worker_id")
        required_state = {
            RecoveryWorkKind.ROLLBACK: TransactionState.FAILED,
            RecoveryWorkKind.COMPENSATE: TransactionState.FAILED,
            RecoveryWorkKind.RECONCILE_DISPATCH: TransactionState.IN_DOUBT,
        }.get(kind)
        if required_state is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Effect-bearing recovery authorization lease has an invalid recovery kind",
            )
        if acquired_at >= expires_at:
            raise AgentKernelError(
                ErrorCode.DEADLINE_EXCEEDED,
                "Recovery authorization lease has no positive validity interval",
            )
        if binding.recovery_kind is not kind or binding.recovery_id != recovery_id:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery authorization lease differs from its immutable handoff binding",
            )
        try:
            with self._immediate():
                transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
                dispatch = self._get_commit_dispatch_tx(tenant_id, transaction_id)
                if (
                    transaction.state is not required_state
                    or transaction.version != expected_transaction_version
                    or not self._root_recovery_binding_matches_durable_bounds_tx(
                        transaction,
                        binding,
                    )
                    or dispatch.dispatch_id != dispatch_id
                    or canonical_digest(dispatch) != dispatch_target_ref
                    or transaction.intent_hash != dispatch.intent_hash
                    or transaction.normalized_action_digest
                    != dispatch.permit.normalized_action_digest
                    or transaction.adapter_manifest_digest
                    != dispatch.permit.adapter_manifest_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery authorization lease differs from its exact dispatch target",
                        retryable=False,
                    )
                existing = self._connection.execute(
                    "SELECT 1 FROM enforced_recovery_work "
                    "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ?",
                    (tenant_id, transaction_id, recovery_id),
                ).fetchone()
                if existing is not None:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery authorization lease conflicts with durable work",
                        retryable=True,
                    )
                lease, created = self._acquire_worker_lease_tx(
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                    lease_id=lease_id,
                    worker_id=worker_id,
                    purpose=LeasePurpose.RECOVERY,
                    acquired_at=acquired_at,
                    expires_at=expires_at,
                )
                self.reserve_recovery_action_handoff(
                    tenant_id=tenant_id,
                    target_transaction_id=transaction_id,
                    expected_transaction_version=expected_transaction_version,
                    binding=binding,
                    created_at=acquired_at,
                    handoff_lease=lease,
                )
                return WorkerLeaseResult(
                    lease,
                    transaction,
                    None,
                    (
                        EnforcedStoreDisposition.STORED
                        if created
                        else EnforcedStoreDisposition.EXACT_RETRY
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity(
                "Recovery authorization lease acquisition failed",
                error,
            ) from error

    def _assert_active_lease_tx(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        lease_id: str,
        worker_id: str,
        fencing_token: int,
        purpose: LeasePurpose,
        at: datetime,
    ) -> WorkerLeaseRecord:
        lease = self._get_worker_lease_tx(tenant_id, transaction_id, lease_id)
        if (
            lease.worker_id != worker_id
            or lease.fencing_token != fencing_token
            or lease.purpose is not purpose
            or lease.released_at is not None
            or lease.expires_at <= at
        ):
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Worker lease is stale, expired, released, or bound to different work",
                retryable=False,
            )
        newer = self._connection.execute(
            "SELECT 1 FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ? AND fencing_token > ? LIMIT 1",
            (tenant_id, transaction_id, fencing_token),
        ).fetchone()
        if newer is not None:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Worker lease fencing token has been superseded",
                retryable=False,
            )
        return lease

    def acquire_staging_lease(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        lease_id: str,
        worker_id: str,
        acquired_at: datetime,
        expires_at: datetime,
        expected_transaction_version: int,
    ) -> WorkerLeaseResult:
        """Acquire the exclusive staging fence and only then return ``STAGE_NOW``."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        lease_id = _require_identifier(lease_id, field="lease_id")
        worker_id = _require_identifier(worker_id, field="worker_id")
        try:
            with self._immediate():
                current = self._get_enforced_transaction_tx(tenant_id, transaction_id)
                if current.deadline is None or not (acquired_at < expires_at <= current.deadline):
                    raise AgentKernelError(
                        ErrorCode.DEADLINE_EXCEEDED,
                        "Staging lease is outside the durable transaction deadline",
                    )
                lease, created = self._acquire_worker_lease_tx(
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                    lease_id=lease_id,
                    worker_id=worker_id,
                    purpose=LeasePurpose.STAGING,
                    acquired_at=acquired_at,
                    expires_at=expires_at,
                )
                if not created:
                    if current.state is not TransactionState.STAGING:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Existing staging lease lacks its atomic STAGING transition",
                        )
                    return WorkerLeaseResult(
                        lease,
                        current,
                        None,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                updated, event = self._apply_transition_tx(
                    current,
                    expected_version=expected_transaction_version,
                    transition_event=TransitionEvent.WORKER_LEASE_ACQUIRED,
                    recorded_at=acquired_at,
                    evidence_refs=(canonical_digest(lease),),
                )
                return WorkerLeaseResult(
                    lease,
                    updated,
                    event,
                    EnforcedStoreDisposition.STAGE_NOW,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Staging lease acquisition failed closed", error) from error

    def renew_worker_lease(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        lease_id: str,
        expected_version: int,
        renewed_at: datetime,
        expires_at: datetime,
    ) -> WorkerLeaseRecord:
        with self._immediate():
            current = self._get_worker_lease_tx(tenant_id, transaction_id, lease_id)
            if current.version != expected_version:
                raise AgentKernelError(ErrorCode.VERSION_CONFLICT, "Worker lease version changed")
            if current.released_at is not None or current.expires_at <= renewed_at:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Expired or released worker lease cannot be renewed",
                )
            if expires_at <= current.expires_at:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Worker lease renewal must extend the expiry",
                )
            permit_issued = False
            deadline: datetime | None
            if current.purpose is LeasePurpose.STAGING:
                transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
                deadline = transaction.deadline
                permit_issued = (
                    self._connection.execute(
                        "SELECT 1 FROM enforced_stage_material WHERE tenant_id = ? "
                        "AND transaction_id = ? AND lease_id = ? LIMIT 1",
                        (tenant_id, transaction_id, lease_id),
                    ).fetchone()
                    is not None
                )
            else:
                work_row = self._connection.execute(
                    "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
                    "AND transaction_id = ? AND lease_id = ?",
                    (tenant_id, transaction_id, lease_id),
                ).fetchone()
                if work_row is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery lease has no durable work binding",
                    )
                work = self._recovery_from_row(work_row)
                deadline = work.deadline
                permit_issued = work.permit is not None
            if permit_issued:
                raise AgentKernelError(
                    ErrorCode.AUTHORITY_MISSING,
                    "Worker lease cannot be renewed after an execution permit was issued",
                )
            if deadline is None or expires_at > deadline:
                raise AgentKernelError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "Worker lease renewal exceeds its durable work deadline",
                )
            updated = WorkerLeaseRecord.model_validate(
                {
                    **current.model_dump(mode="python"),
                    "version": current.version + 1,
                    "expires_at": expires_at,
                }
            )
            return self._update_worker_lease_tx(current, updated)

    def release_worker_lease(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        lease_id: str,
        expected_version: int,
        released_at: datetime,
    ) -> WorkerLeaseRecord:
        with self._immediate():
            current = self._get_worker_lease_tx(tenant_id, transaction_id, lease_id)
            if current.released_at is not None:
                if current.released_at != released_at:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Worker lease release retry changed its timestamp",
                    )
                return current
            if current.version != expected_version:
                raise AgentKernelError(ErrorCode.VERSION_CONFLICT, "Worker lease version changed")
            updated = WorkerLeaseRecord.model_validate(
                {
                    **current.model_dump(mode="python"),
                    "version": current.version + 1,
                    "released_at": released_at,
                }
            )
            return self._update_worker_lease_tx(current, updated)

    def _stage_from_row(self, row: sqlite3.Row) -> StageMaterialRecord:
        try:
            material = StageMaterialRecord.model_validate_json(str(row["record_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored stage material is invalid",
            ) from error
        expected = {
            "tenant_id": material.tenant_id,
            "transaction_id": material.transaction_id,
            "stage_id": material.stage_id,
            "lease_id": material.lease_id,
            "fencing_token": material.fencing_token,
            "intent_hash": material.intent_hash,
            "normalized_action_digest": material.normalized_action_digest,
            "adapter_manifest_digest": material.adapter_manifest_digest,
            "plan_digest": material.plan_digest,
            "plan_ref": material.plan_ref,
            "inspection_permit_digest": material.inspection_permit_digest,
            "inspection_permit_ref": material.inspection_permit_ref,
            "stage_permit_digest": material.stage_permit_digest,
            "stage_permit_ref": material.stage_permit_ref,
            "state": material.state.value,
            "base_state_digest": material.base_state_digest,
            "target_version_guard": material.target_version_guard,
            "staged_effect_ref": material.staged_effect_ref,
            "staged_receipt_ref": material.staged_receipt_ref,
            "staged_state_digest": material.staged_state_digest,
            "verification_permit_digest": material.verification_permit_digest,
            "verification_permit_ref": material.verification_permit_ref,
            "verification_ref": material.verification_ref,
            "discard_evidence_ref": material.discard_evidence_ref,
            "version": material.version,
            "record_digest": canonical_digest(material),
            "record_json": canonical_json_text(material),
            "created_at": _timestamp(material.created_at),
            "updated_at": _timestamp(material.updated_at),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stage material projection differs from canonical content",
            )
        return material

    def _get_stage_material_tx(
        self,
        tenant_id: str,
        transaction_id: str,
    ) -> StageMaterialRecord:
        row = self._connection.execute(
            "SELECT * FROM enforced_stage_material WHERE tenant_id = ? AND transaction_id = ?",
            (tenant_id, transaction_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Unknown private stage material")
        return self._stage_from_row(row)

    def get_stage_material(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
    ) -> StageMaterialRecord:
        return self._get_stage_material_tx(
            _require_identifier(tenant_id, field="tenant_id"),
            _require_identifier(transaction_id, field="transaction_id"),
        )

    def allocate_stage_material(
        self,
        material: StageMaterialRecord,
        *,
        inspection_permit: InspectionPermit,
        stage_permit: StagePermit,
    ) -> StageMaterialResult:
        """Bind one coordinator-selected private stage before adapter stage I/O."""

        if material.state is not StageMaterialState.ALLOCATED or material.version != 0:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Initial stage material must be ALLOCATED at version zero",
            )
        if (
            material.tenant_id != inspection_permit.tenant_id
            or material.transaction_id != inspection_permit.transaction_id
            or material.intent_hash != inspection_permit.intent_hash
            or material.normalized_action_digest != inspection_permit.normalized_action_digest
            or material.adapter_manifest_digest != inspection_permit.adapter_manifest_digest
            or material.lease_id != inspection_permit.lease_id
            or material.fencing_token != inspection_permit.fencing_token
            or material.inspection_permit_digest != inspection_permit.permit_digest
            or material.inspection_permit_ref != canonical_digest(inspection_permit)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stage material differs from its inspection permit",
            )
        if (
            material.tenant_id != stage_permit.tenant_id
            or material.transaction_id != stage_permit.transaction_id
            or material.intent_hash != stage_permit.intent_hash
            or material.normalized_action_digest != stage_permit.normalized_action_digest
            or material.adapter_manifest_digest != stage_permit.adapter_manifest_digest
            or material.stage_id != stage_permit.stage_id
            or material.lease_id != stage_permit.lease_id
            or material.fencing_token != stage_permit.fencing_token
            or material.plan_digest != stage_permit.plan_digest
            or material.plan_ref != stage_permit.plan_ref
            or material.inspection_permit_digest != stage_permit.inspection_permit_digest
            or material.inspection_permit_ref != stage_permit.inspection_permit_ref
            or inspection_permit.authorization_round_id != stage_permit.authorization_round_id
            or inspection_permit.authorization_round_digest
            != stage_permit.authorization_round_digest
            or inspection_permit.worker_id != stage_permit.worker_id
            or material.stage_permit_digest != stage_permit.permit_digest
            or material.stage_permit_ref != canonical_digest(stage_permit)
            or material.target_version_guard != stage_permit.target_version_guard
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stage material differs from its stage permit",
            )
        try:
            with self._immediate():
                current = self._get_enforced_transaction_tx(
                    material.tenant_id,
                    material.transaction_id,
                )
                if current.authorization_round_id is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Staging transaction has no durable authorization round",
                    )
                round_record = self._get_authorization_round_tx(
                    current.tenant_id,
                    current.transaction_id,
                    current.authorization_round_id,
                )
                if (
                    round_record.verdict is not AuthorizationVerdict.ELIGIBLE
                    or round_record.purpose is not AuthorizationRoundPurpose.STAGING
                    or round_record.round_digest != current.authorization_round_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Staging transaction lost its eligible authority window",
                    )
                existing = self._connection.execute(
                    "SELECT * FROM enforced_stage_material "
                    "WHERE tenant_id = ? AND transaction_id = ?",
                    (material.tenant_id, material.transaction_id),
                ).fetchone()
                if existing is not None:
                    stored = self._stage_from_row(existing)
                    if stored != material:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Stage allocation retry changed immutable content",
                        )
                    return StageMaterialResult(
                        stored,
                        current,
                        None,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                lease = self._assert_active_lease_tx(
                    tenant_id=material.tenant_id,
                    transaction_id=material.transaction_id,
                    lease_id=material.lease_id,
                    worker_id=stage_permit.worker_id,
                    fencing_token=material.fencing_token,
                    purpose=LeasePurpose.STAGING,
                    at=material.created_at,
                )
                expected_permit_deadline = _lease_bounded_deadline(
                    current.deadline,
                    lease.expires_at,
                    round_record.authority_valid_until,
                )
                if (
                    current.state is not TransactionState.STAGING
                    or current.intent_hash != material.intent_hash
                    or current.normalized_action_digest != material.normalized_action_digest
                    or current.adapter_manifest_digest != material.adapter_manifest_digest
                    or current.authorization_round_id != stage_permit.authorization_round_id
                    or current.authorization_round_digest != stage_permit.authorization_round_digest
                    or inspection_permit.deadline != expected_permit_deadline
                    or stage_permit.deadline != expected_permit_deadline
                    or not (
                        inspection_permit.issued_at
                        <= material.created_at
                        < inspection_permit.deadline
                    )
                    or not (stage_permit.issued_at <= material.created_at < stage_permit.deadline)
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Stage allocation differs from the authorized transaction",
                    )
                self._execute(
                    "INSERT INTO enforced_stage_material("
                    "tenant_id, transaction_id, stage_id, lease_id, fencing_token, "
                    "intent_hash, normalized_action_digest, adapter_manifest_digest, "
                    "plan_digest, plan_ref, inspection_permit_digest, inspection_permit_ref, "
                    "stage_permit_digest, stage_permit_ref, state, base_state_digest, "
                    "target_version_guard, staged_effect_ref, staged_receipt_ref, "
                    "staged_state_digest, verification_permit_digest, "
                    "verification_permit_ref, verification_ref, discard_evidence_ref, version, "
                    "record_digest, record_json, created_at, updated_at) VALUES ("
                    "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL, NULL, "
                    "NULL, NULL, NULL, NULL, NULL, 0, ?, ?, ?, ?)",
                    (
                        material.tenant_id,
                        material.transaction_id,
                        material.stage_id,
                        material.lease_id,
                        material.fencing_token,
                        material.intent_hash,
                        material.normalized_action_digest,
                        material.adapter_manifest_digest,
                        material.plan_digest,
                        material.plan_ref,
                        material.inspection_permit_digest,
                        material.inspection_permit_ref,
                        material.stage_permit_digest,
                        material.stage_permit_ref,
                        material.state.value,
                        material.target_version_guard,
                        canonical_digest(material),
                        canonical_json_text(material),
                        _timestamp(material.created_at),
                        _timestamp(material.updated_at),
                    ),
                )
                return StageMaterialResult(
                    material,
                    current,
                    None,
                    EnforcedStoreDisposition.STORED,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Private stage allocation failed closed", error) from error

    def _update_stage_material_tx(
        self,
        current: StageMaterialRecord,
        updated: StageMaterialRecord,
    ) -> StageMaterialRecord:
        cursor = self._execute(
            "UPDATE enforced_stage_material SET state = ?, base_state_digest = ?, "
            "staged_effect_ref = ?, staged_receipt_ref = ?, staged_state_digest = ?, "
            "verification_permit_digest = ?, verification_permit_ref = ?, "
            "verification_ref = ?, discard_evidence_ref = ?, version = ?, record_digest = ?, "
            "record_json = ?, updated_at = ? "
            "WHERE tenant_id = ? AND transaction_id = ? "
            "AND stage_id = ? AND version = ? AND state = ? AND fencing_token = ?",
            (
                updated.state.value,
                updated.base_state_digest,
                updated.staged_effect_ref,
                updated.staged_receipt_ref,
                updated.staged_state_digest,
                updated.verification_permit_digest,
                updated.verification_permit_ref,
                updated.verification_ref,
                updated.discard_evidence_ref,
                updated.version,
                canonical_digest(updated),
                canonical_json_text(updated),
                _timestamp(updated.updated_at),
                current.tenant_id,
                current.transaction_id,
                current.stage_id,
                current.version,
                current.state.value,
                current.fencing_token,
            ),
        )
        if cursor.rowcount != 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Stage material compare-and-swap failed",
                retryable=True,
            )
        return updated

    def record_staged_material(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_material_version: int,
        base_state_digest: str,
        staged_effect_ref: str,
        recorded_at: datetime,
    ) -> StageMaterialResult:
        """Record private staged bytes and atomically expose only their evidence refs."""

        base_state_digest = _require_digest(base_state_digest, field="base_state_digest")
        staged_effect_ref = _require_digest(staged_effect_ref, field="staged_effect_ref")
        with self._immediate():
            current = self._get_stage_material_tx(tenant_id, transaction_id)
            transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
            if current.state is StageMaterialState.STAGED:
                if (
                    current.base_state_digest != base_state_digest
                    or current.staged_effect_ref != staged_effect_ref
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Stage result retry changed durable evidence",
                    )
                return StageMaterialResult(
                    current,
                    transaction,
                    None,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            if (
                current.state is not StageMaterialState.ALLOCATED
                or current.version != expected_material_version
            ):
                raise AgentKernelError(ErrorCode.VERSION_CONFLICT, "Stage material version changed")
            updated_material = StageMaterialRecord.model_validate(
                {
                    **current.model_dump(mode="python"),
                    "state": StageMaterialState.STAGED,
                    "base_state_digest": base_state_digest,
                    "staged_effect_ref": staged_effect_ref,
                    "version": current.version + 1,
                    "updated_at": recorded_at,
                }
            )
            self._update_stage_material_tx(current, updated_material)
            return StageMaterialResult(
                updated_material,
                transaction,
                None,
                EnforcedStoreDisposition.STORED,
            )

    def record_stage_execution(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_material_version: int,
        expected_transaction_version: int,
        staged_receipt_ref: str,
        staged_state_digest: str,
        recorded_at: datetime,
    ) -> StageMaterialResult:
        staged_receipt_ref = _require_digest(staged_receipt_ref, field="staged_receipt_ref")
        staged_state_digest = _require_digest(
            staged_state_digest,
            field="staged_state_digest",
        )
        with self._immediate():
            current = self._get_stage_material_tx(tenant_id, transaction_id)
            transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
            if current.state is StageMaterialState.EXECUTED:
                if (
                    current.staged_receipt_ref != staged_receipt_ref
                    or current.staged_state_digest != staged_state_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Stage execution retry changed durable evidence",
                    )
                if transaction.state is not TransactionState.STAGED:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Executed stage lacks its atomic STAGED transaction transition",
                    )
                return StageMaterialResult(
                    current,
                    transaction,
                    None,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            if (
                current.state is not StageMaterialState.STAGED
                or current.version != expected_material_version
            ):
                raise AgentKernelError(ErrorCode.VERSION_CONFLICT, "Stage material version changed")
            updated = StageMaterialRecord.model_validate(
                {
                    **current.model_dump(mode="python"),
                    "state": StageMaterialState.EXECUTED,
                    "staged_receipt_ref": staged_receipt_ref,
                    "staged_state_digest": staged_state_digest,
                    "version": current.version + 1,
                    "updated_at": recorded_at,
                }
            )
            self._update_stage_material_tx(current, updated)
            updated_transaction, event = self._apply_transition_tx(
                transaction,
                expected_version=expected_transaction_version,
                transition_event=TransitionEvent.STAGING_SUCCEEDED,
                recorded_at=recorded_at,
                evidence_refs=(staged_receipt_ref, staged_state_digest),
            )
            return StageMaterialResult(
                updated,
                updated_transaction,
                event,
                EnforcedStoreDisposition.STORED,
            )

    def record_stage_verification(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_material_version: int,
        expected_transaction_version: int,
        verification_permit: VerificationPermit,
        verification_permit_ref: str,
        verification_ref: str,
        passed: bool,
        recorded_at: datetime,
        recovery_timeout: timedelta | None = None,
    ) -> StageMaterialResult:
        verification_ref = _require_digest(verification_ref, field="verification_ref")
        verification_permit_ref = _require_digest(
            verification_permit_ref,
            field="verification_permit_ref",
        )
        if verification_permit_ref != canonical_digest(verification_permit):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stage verification permit artifact ref is inconsistent",
            )
        with self._immediate():
            current = self._get_stage_material_tx(tenant_id, transaction_id)
            transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
            lease = self._get_worker_lease_tx(tenant_id, transaction_id, current.lease_id)
            if transaction.authorization_round_id is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Staged verification has no durable authorization round",
                )
            round_record = self._get_authorization_round_tx(
                tenant_id,
                transaction_id,
                transaction.authorization_round_id,
            )
            if (
                round_record.verdict is not AuthorizationVerdict.ELIGIBLE
                or round_record.purpose is not AuthorizationRoundPurpose.STAGING
                or round_record.round_digest != transaction.authorization_round_digest
                or verification_permit.phase is not VerificationPhase.STAGED
                or verification_permit.tenant_id != current.tenant_id
                or verification_permit.transaction_id != current.transaction_id
                or verification_permit.intent_hash != current.intent_hash
                or verification_permit.normalized_action_digest != current.normalized_action_digest
                or verification_permit.adapter_manifest_digest != current.adapter_manifest_digest
                or verification_permit.authorization_round_id != transaction.authorization_round_id
                or verification_permit.authorization_round_digest
                != transaction.authorization_round_digest
                or verification_permit.lease_id != current.lease_id
                or verification_permit.worker_id != lease.worker_id
                or verification_permit.fencing_token != current.fencing_token
                or verification_permit.subject_ref != current.staged_receipt_ref
                or verification_permit.authority_permit_digest != current.stage_permit_digest
                or verification_permit.authority_permit_ref != current.stage_permit_ref
                or verification_permit.subject_permit_digest != current.stage_permit_digest
                or verification_permit.subject_permit_ref != current.stage_permit_ref
                or verification_permit.deadline
                != _lease_bounded_deadline(
                    transaction.deadline,
                    lease.expires_at,
                    round_record.authority_valid_until,
                )
                or not (verification_permit.issued_at <= recorded_at < verification_permit.deadline)
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Stage verification permit differs from the exact executed material",
                )
            if passed and current.state is StageMaterialState.VERIFIED:
                if (
                    current.verification_permit_digest != verification_permit.permit_digest
                    or current.verification_permit_ref != verification_permit_ref
                    or current.verification_ref != verification_ref
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Stage verification retry changed evidence",
                    )
                return StageMaterialResult(
                    current,
                    transaction,
                    None,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            if (
                current.state is not StageMaterialState.EXECUTED
                or current.version != expected_material_version
            ):
                raise AgentKernelError(ErrorCode.VERSION_CONFLICT, "Stage material version changed")
            self._assert_active_lease_tx(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                lease_id=verification_permit.lease_id,
                worker_id=verification_permit.worker_id,
                fencing_token=verification_permit.fencing_token,
                purpose=LeasePurpose.STAGING,
                at=recorded_at,
            )
            if passed:
                updated_material = StageMaterialRecord.model_validate(
                    {
                        **current.model_dump(mode="python"),
                        "state": StageMaterialState.VERIFIED,
                        "verification_permit_digest": verification_permit.permit_digest,
                        "verification_permit_ref": verification_permit_ref,
                        "verification_ref": verification_ref,
                        "version": current.version + 1,
                        "updated_at": recorded_at,
                    }
                )
                self._update_stage_material_tx(current, updated_material)
                transition = TransitionEvent.STAGED_VERIFICATION_PASSED
            else:
                updated_material = current
                transition = TransitionEvent.STAGED_VERIFICATION_FAILED
            updated_transaction, event = self._apply_transition_tx(
                transaction,
                expected_version=expected_transaction_version,
                transition_event=transition,
                recorded_at=recorded_at,
                evidence_refs=(
                    verification_permit.permit_digest,
                    verification_permit_ref,
                    verification_ref,
                ),
                reason_code=None if passed else "STAGED_VERIFICATION_FAILED",
                recovery_deadline=(
                    None if recovery_timeout is None else recorded_at + recovery_timeout
                ),
            )
            return StageMaterialResult(
                updated_material,
                updated_transaction,
                event,
                EnforcedStoreDisposition.STORED,
            )

    def _dispatch_from_row(self, row: sqlite3.Row) -> CommitDispatchRecord:
        raw_json = str(row["record_json"])
        try:
            raw_material = json.loads(raw_json)
            if not isinstance(raw_material, dict):
                raise TypeError("Commit dispatch JSON must be an object")
            dispatch = CommitDispatchRecord.model_validate(raw_material)
        except (json.JSONDecodeError, TypeError, ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored commit dispatch is invalid",
            ) from error
        legacy_without_unavailable_link = (
            "unavailable_record_digest" not in raw_material
            and dispatch.unavailable_record_digest is None
        )
        expected_record_json = (
            canonical_json_text(raw_material)
            if legacy_without_unavailable_link
            else canonical_json_text(dispatch)
        )
        expected_record_digest = (
            canonical_digest(raw_material)
            if legacy_without_unavailable_link
            else canonical_digest(dispatch)
        )
        permit = dispatch.permit
        expected = {
            "tenant_id": dispatch.tenant_id,
            "transaction_id": dispatch.transaction_id,
            "intent_hash": dispatch.intent_hash,
            "dispatch_id": dispatch.dispatch_id,
            "owner_version": dispatch.owner_version,
            "stage_id": permit.stage_id,
            "lease_id": permit.lease_id,
            "fencing_token": permit.fencing_token,
            "idempotency_key": permit.idempotency_key,
            "permit_ref": dispatch.permit_ref,
            "permit_digest": permit.permit_digest,
            "permit_json": canonical_json_text(permit),
            "state": dispatch.state.value,
            "effect_receipt_ref": dispatch.effect_receipt_ref,
            "committed_verification_permit_digest": (dispatch.committed_verification_permit_digest),
            "committed_verification_permit_ref": (dispatch.committed_verification_permit_ref),
            "committed_verification_ref": dispatch.committed_verification_ref,
            "no_effect_evidence_ref": dispatch.no_effect_evidence_ref,
            "outcome_evidence_refs_json": canonical_json_text(dispatch.outcome_evidence_refs),
            "unavailable_record_digest": dispatch.unavailable_record_digest,
            "outcome_head_sequence": dispatch.version,
            "version": dispatch.version,
            "record_digest": expected_record_digest,
            "record_json": expected_record_json,
            "created_at": _timestamp(dispatch.created_at),
            "updated_at": _timestamp(dispatch.updated_at),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Commit dispatch projection differs from canonical content",
            )
        return dispatch

    def _outcome_from_row(self, row: sqlite3.Row) -> DispatchOutcomeRecord:
        raw_json = str(row["outcome_json"])
        try:
            raw_material = json.loads(raw_json)
            if not isinstance(raw_material, dict):
                raise TypeError("Dispatch outcome JSON must be an object")
            outcome = DispatchOutcomeRecord.model_validate(raw_material)
        except (json.JSONDecodeError, TypeError, ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored dispatch outcome is invalid",
            ) from error
        legacy_without_unavailable_link = (
            "unavailable_record_digest" not in raw_material
            and outcome.unavailable_record_digest is None
        )
        expected_outcome_json = (
            canonical_json_text(raw_material)
            if legacy_without_unavailable_link
            else canonical_json_text(outcome)
        )
        expected = {
            "tenant_id": outcome.tenant_id,
            "transaction_id": outcome.transaction_id,
            "intent_hash": outcome.intent_hash,
            "owner_version": outcome.owner_version,
            "dispatch_id": outcome.dispatch_id,
            "sequence": outcome.sequence,
            "outcome_id": outcome.outcome_id,
            "source_state": (None if outcome.source_state is None else outcome.source_state.value),
            "target_state": outcome.target_state.value,
            "classification": (
                None if outcome.classification is None else outcome.classification.value
            ),
            "effect_receipt_ref": outcome.effect_receipt_ref,
            "committed_verification_permit_digest": (outcome.committed_verification_permit_digest),
            "committed_verification_permit_ref": (outcome.committed_verification_permit_ref),
            "committed_verification_ref": outcome.committed_verification_ref,
            "no_effect_evidence_ref": outcome.no_effect_evidence_ref,
            "evidence_refs_json": canonical_json_text(outcome.evidence_refs),
            "unavailable_record_digest": outcome.unavailable_record_digest,
            "reason_code": outcome.reason_code,
            "previous_outcome_digest": outcome.previous_outcome_digest,
            "outcome_digest": outcome.outcome_digest,
            "outcome_json": expected_outcome_json,
            "recorded_at": _timestamp(outcome.recorded_at),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Dispatch outcome projection differs from canonical content",
            )
        return outcome

    def _validate_dispatch_outcome_chain_tx(
        self,
        dispatch: CommitDispatchRecord,
    ) -> tuple[DispatchOutcomeRecord, ...]:
        rows = self._connection.execute(
            "SELECT * FROM enforced_dispatch_outcomes "
            "WHERE tenant_id = ? AND transaction_id = ? AND dispatch_id = ? "
            "ORDER BY sequence",
            (dispatch.tenant_id, dispatch.transaction_id, dispatch.dispatch_id),
        ).fetchall()
        outcomes = tuple(self._outcome_from_row(row) for row in rows)
        previous: str | None = None
        for sequence, outcome in enumerate(outcomes):
            if outcome.sequence != sequence or outcome.previous_outcome_digest != previous:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Dispatch outcome chain is not contiguous",
                )
            previous = outcome.outcome_digest
        head = self._connection.execute(
            "SELECT outcome_head_sequence, outcome_head_digest "
            "FROM enforced_commit_dispatches WHERE tenant_id = ? AND transaction_id = ? "
            "AND dispatch_id = ?",
            (dispatch.tenant_id, dispatch.transaction_id, dispatch.dispatch_id),
        ).fetchone()
        if (
            not outcomes
            or len(outcomes) != dispatch.version + 1
            or outcomes[-1].target_state is not dispatch.state
            or head is None
            or int(head["outcome_head_sequence"]) != dispatch.version
            or str(head["outcome_head_digest"]) != previous
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Commit dispatch projection differs from its outcome chain",
            )
        return outcomes

    def _get_commit_dispatch_tx(
        self,
        tenant_id: str,
        transaction_id: str,
    ) -> CommitDispatchRecord:
        row = self._connection.execute(
            "SELECT * FROM enforced_commit_dispatches WHERE tenant_id = ? AND transaction_id = ?",
            (tenant_id, transaction_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Unknown commit dispatch")
        dispatch = self._dispatch_from_row(row)
        self._validate_dispatch_outcome_chain_tx(dispatch)
        return dispatch

    def _get_commit_dispatch_head_tx(
        self,
        tenant_id: str,
        transaction_id: str,
    ) -> CommitDispatchRecord:
        """Validate the canonical dispatch projection and a bounded outcome head."""

        row = self._connection.execute(
            "SELECT * FROM enforced_commit_dispatches WHERE tenant_id = ? AND transaction_id = ?",
            (tenant_id, transaction_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Unknown commit dispatch")
        dispatch = self._dispatch_from_row(row)
        head_row = self._connection.execute(
            "SELECT * FROM enforced_dispatch_outcomes WHERE tenant_id = ? "
            "AND transaction_id = ? AND dispatch_id = ? AND sequence = ?",
            (tenant_id, transaction_id, dispatch.dispatch_id, dispatch.version),
        ).fetchone()
        tail_row = self._connection.execute(
            "SELECT sequence, outcome_digest FROM enforced_dispatch_outcomes "
            "WHERE tenant_id = ? AND transaction_id = ? AND dispatch_id = ? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant_id, transaction_id, dispatch.dispatch_id),
        ).fetchone()
        if head_row is None or tail_row is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Commit dispatch lost its bounded outcome head",
            )
        head = self._outcome_from_row(head_row)
        if (
            head.sequence != dispatch.version
            or head.target_state is not dispatch.state
            or int(row["outcome_head_sequence"]) != dispatch.version
            or str(row["outcome_head_digest"]) != head.outcome_digest
            or int(tail_row["sequence"]) != dispatch.version
            or str(tail_row["outcome_digest"]) != head.outcome_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Commit dispatch projection differs from its bounded outcome head",
            )
        if dispatch.version == 0:
            if head.previous_outcome_digest is not None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Commit dispatch genesis has an outcome predecessor",
                )
        else:
            predecessor_row = self._connection.execute(
                "SELECT * FROM enforced_dispatch_outcomes WHERE tenant_id = ? "
                "AND transaction_id = ? AND dispatch_id = ? AND sequence = ?",
                (
                    tenant_id,
                    transaction_id,
                    dispatch.dispatch_id,
                    dispatch.version - 1,
                ),
            ).fetchone()
            predecessor_parent_row = (
                None
                if dispatch.version == 1
                else self._connection.execute(
                    "SELECT outcome_digest FROM enforced_dispatch_outcomes "
                    "WHERE tenant_id = ? AND transaction_id = ? AND dispatch_id = ? "
                    "AND sequence = ?",
                    (
                        tenant_id,
                        transaction_id,
                        dispatch.dispatch_id,
                        dispatch.version - 2,
                    ),
                ).fetchone()
            )
            predecessor = (
                None if predecessor_row is None else self._outcome_from_row(predecessor_row)
            )
            expected_parent = (
                None
                if predecessor_parent_row is None
                else str(predecessor_parent_row["outcome_digest"])
            )
            if (
                predecessor is None
                or head.previous_outcome_digest != predecessor.outcome_digest
                or predecessor.previous_outcome_digest != expected_parent
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Commit dispatch outcome head lost its predecessor",
                )
        return dispatch

    def get_commit_dispatch(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
    ) -> CommitDispatchRecord:
        with self._read_snapshot():
            dispatch = self._get_commit_dispatch_tx(
                _require_identifier(tenant_id, field="tenant_id"),
                _require_identifier(transaction_id, field="transaction_id"),
            )
            self._validate_dispatch_unavailable_link_tx(dispatch)
            return dispatch

    def list_dispatch_outcomes(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
    ) -> tuple[DispatchOutcomeRecord, ...]:
        with self._read_snapshot():
            dispatch = self._get_commit_dispatch_tx(tenant_id, transaction_id)
            self._validate_dispatch_unavailable_link_tx(dispatch)
            return self._validate_dispatch_outcome_chain_tx(dispatch)

    def _dispatch_evidence_unavailable_from_row(
        self,
        row: sqlite3.Row,
    ) -> DispatchEvidenceUnavailableRecord:
        try:
            record = DispatchEvidenceUnavailableRecord.model_validate_json(str(row["record_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored unavailable dispatch evidence record is invalid",
            ) from error
        expected: dict[str, object] = {
            "tenant_id": record.tenant_id,
            "transaction_id": record.transaction_id,
            "dispatch_id": record.dispatch_id,
            "boundary": record.boundary,
            "evidence_status": record.evidence_status,
            "operation_evidence_ref": record.operation_evidence_ref,
            "supporting_refs_json": canonical_json_text(record.supporting_refs),
            "reported_at": _timestamp(record.reported_at),
            "reason_code": record.reason_code,
            "record_digest": record.record_digest,
            "record_json": canonical_json_text(record),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable dispatch evidence projection differs from canonical content",
            )
        return record

    def _get_dispatch_evidence_unavailable_tx(
        self,
        tenant_id: str,
        transaction_id: str,
        dispatch_id: str,
    ) -> DispatchEvidenceUnavailableRecord | None:
        row = self._connection.execute(
            "SELECT * FROM enforced_dispatch_evidence_unavailable_reports "
            "WHERE tenant_id = ? AND transaction_id = ? AND dispatch_id = ?",
            (tenant_id, transaction_id, dispatch_id),
        ).fetchone()
        return None if row is None else self._dispatch_evidence_unavailable_from_row(row)

    def _validate_dispatch_evidence_unavailable_association_tx(
        self,
        record: DispatchEvidenceUnavailableRecord,
    ) -> tuple[CommitDispatchRecord, DispatchOutcomeRecord]:
        dispatch = self._get_commit_dispatch_tx(record.tenant_id, record.transaction_id)
        self._validate_dispatch_outcome_chain_tx(dispatch)
        lease = self._get_worker_lease_tx(
            record.tenant_id,
            record.transaction_id,
            dispatch.permit.lease_id,
        )
        binding_row = self._connection.execute(
            "SELECT * FROM enforced_dispatch_evidence_unavailable_bindings "
            "WHERE tenant_id = ? AND transaction_id = ? AND dispatch_id = ?",
            (record.tenant_id, record.transaction_id, record.dispatch_id),
        ).fetchone()
        if binding_row is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable dispatch evidence lost its immutable binding",
            )
        outcome_row = self._connection.execute(
            "SELECT * FROM enforced_dispatch_outcomes "
            "WHERE tenant_id = ? AND transaction_id = ? AND dispatch_id = ? "
            "AND sequence = ?",
            (
                record.tenant_id,
                record.transaction_id,
                record.dispatch_id,
                int(binding_row["outcome_sequence"]),
            ),
        ).fetchone()
        event_row = self._connection.execute(
            "SELECT * FROM enforced_transaction_events "
            "WHERE tenant_id = ? AND transaction_id = ? AND sequence = ?",
            (
                record.tenant_id,
                record.transaction_id,
                int(binding_row["event_sequence"]),
            ),
        ).fetchone()
        if outcome_row is None or event_row is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable dispatch evidence binding is dangling",
            )
        outcome = self._outcome_from_row(outcome_row)
        event = self._event_from_row(event_row)
        required_supporting = {
            dispatch.permit_ref,
            *((outcome.effect_receipt_ref,) if outcome.effect_receipt_ref else ()),
        }
        if (
            dispatch.dispatch_id != record.dispatch_id
            or dispatch.unavailable_record_digest != record.record_digest
            or record.record_digest in dispatch.outcome_evidence_refs
            or str(binding_row["record_digest"]) != record.record_digest
            or int(binding_row["outcome_sequence"]) != outcome.sequence
            or str(binding_row["outcome_digest"]) != outcome.outcome_digest
            or int(binding_row["event_sequence"]) != event.sequence
            or str(binding_row["event_digest"]) != event.event_digest
            or outcome.classification is not ReconciliationOutcome.UNKNOWN
            or outcome.source_state is not CommitDispatchState.DISPATCHED
            or outcome.target_state is not CommitDispatchState.IN_DOUBT
            or outcome.unavailable_record_digest != record.record_digest
            or outcome.recorded_at != record.reported_at
            or outcome.reason_code != record.reason_code
            or record.record_digest in outcome.evidence_refs
            or not required_supporting.issubset(record.supporting_refs)
            or lease.released_at != record.reported_at
            or event.event != TransitionEvent.COMMIT_OUTCOME_UNKNOWN.value
            or event.recorded_at != record.reported_at
            or outcome.outcome_digest not in event.evidence_refs
            or record.record_digest in event.evidence_refs
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable dispatch evidence differs from its terminal association",
            )
        return dispatch, outcome

    def _validate_dispatch_unavailable_link_tx(
        self,
        dispatch: CommitDispatchRecord,
    ) -> DispatchEvidenceUnavailableRecord | None:
        record = self._get_dispatch_evidence_unavailable_tx(
            dispatch.tenant_id,
            dispatch.transaction_id,
            dispatch.dispatch_id,
        )
        if dispatch.unavailable_record_digest is None:
            if record is not None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unavailable dispatch evidence is orphaned from its dispatch head",
                )
            return None
        if record is None or record.record_digest != dispatch.unavailable_record_digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Commit dispatch lost its typed unavailable evidence record",
            )
        self._validate_dispatch_evidence_unavailable_association_tx(record)
        return record

    def get_dispatch_evidence_unavailable(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        dispatch_id: str,
    ) -> DispatchEvidenceUnavailableRecord | None:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        dispatch_id = _require_identifier(dispatch_id, field="dispatch_id")
        with self._read_snapshot():
            record = self._get_dispatch_evidence_unavailable_tx(
                tenant_id,
                transaction_id,
                dispatch_id,
            )
            if record is not None:
                self._validate_dispatch_evidence_unavailable_association_tx(record)
            return record

    def get_dispatch_evidence_unavailable_by_digest(
        self,
        *,
        tenant_id: str,
        record_digest: str,
    ) -> DispatchEvidenceUnavailableRecord:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        record_digest = _require_digest(record_digest, field="record_digest")
        with self._read_snapshot():
            row = self._connection.execute(
                "SELECT * FROM enforced_dispatch_evidence_unavailable_reports "
                "WHERE tenant_id = ? AND record_digest = ?",
                (tenant_id, record_digest),
            ).fetchone()
            if row is None:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Unknown unavailable dispatch evidence record in this tenant",
                )
            record = self._dispatch_evidence_unavailable_from_row(row)
            self._validate_dispatch_evidence_unavailable_association_tx(record)
            return record

    def _insert_dispatch_evidence_unavailable_tx(
        self,
        record: DispatchEvidenceUnavailableRecord,
    ) -> None:
        self._execute(
            "INSERT INTO enforced_dispatch_evidence_unavailable_reports("
            "tenant_id, transaction_id, dispatch_id, boundary, evidence_status, "
            "operation_evidence_ref, supporting_refs_json, reported_at, reason_code, "
            "record_digest, record_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.tenant_id,
                record.transaction_id,
                record.dispatch_id,
                record.boundary,
                record.evidence_status,
                record.operation_evidence_ref,
                canonical_json_text(record.supporting_refs),
                _timestamp(record.reported_at),
                record.reason_code,
                record.record_digest,
                canonical_json_text(record),
            ),
        )

    def _insert_dispatch_outcome_tx(self, outcome: DispatchOutcomeRecord) -> None:
        self._execute(
            "INSERT INTO enforced_dispatch_outcomes("
            "tenant_id, transaction_id, intent_hash, owner_version, dispatch_id, sequence, "
            "outcome_id, source_state, target_state, classification, effect_receipt_ref, "
            "committed_verification_permit_digest, committed_verification_permit_ref, "
            "committed_verification_ref, "
            "no_effect_evidence_ref, evidence_refs_json, reason_code, previous_outcome_digest, "
            "unavailable_record_digest, outcome_digest, outcome_json, recorded_at) VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                outcome.tenant_id,
                outcome.transaction_id,
                outcome.intent_hash,
                outcome.owner_version,
                outcome.dispatch_id,
                outcome.sequence,
                outcome.outcome_id,
                None if outcome.source_state is None else outcome.source_state.value,
                outcome.target_state.value,
                None if outcome.classification is None else outcome.classification.value,
                outcome.effect_receipt_ref,
                outcome.committed_verification_permit_digest,
                outcome.committed_verification_permit_ref,
                outcome.committed_verification_ref,
                outcome.no_effect_evidence_ref,
                canonical_json_text(outcome.evidence_refs),
                outcome.reason_code,
                outcome.previous_outcome_digest,
                outcome.unavailable_record_digest,
                outcome.outcome_digest,
                canonical_json_text(outcome),
                _timestamp(outcome.recorded_at),
            ),
        )

    def _insert_commit_dispatch_tx(
        self,
        dispatch: CommitDispatchRecord,
        outcome: DispatchOutcomeRecord,
    ) -> None:
        permit = dispatch.permit
        self._execute(
            "INSERT INTO enforced_commit_dispatches("
            "tenant_id, transaction_id, intent_hash, dispatch_id, owner_version, stage_id, "
            "lease_id, fencing_token, idempotency_key, permit_ref, permit_digest, "
            "permit_json, state, effect_receipt_ref, committed_verification_permit_digest, "
            "committed_verification_permit_ref, committed_verification_ref, "
            "no_effect_evidence_ref, outcome_evidence_refs_json, "
            "unavailable_record_digest, outcome_head_sequence, outcome_head_digest, version, "
            "record_digest, record_json, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, "
            "NULL, NULL, NULL, NULL, ?, NULL, 0, ?, 0, ?, ?, ?, ?)",
            (
                dispatch.tenant_id,
                dispatch.transaction_id,
                dispatch.intent_hash,
                dispatch.dispatch_id,
                dispatch.owner_version,
                permit.stage_id,
                permit.lease_id,
                permit.fencing_token,
                permit.idempotency_key,
                dispatch.permit_ref,
                permit.permit_digest,
                canonical_json_text(permit),
                dispatch.state.value,
                canonical_json_text(dispatch.outcome_evidence_refs),
                outcome.outcome_digest,
                canonical_digest(dispatch),
                canonical_json_text(dispatch),
                _timestamp(dispatch.created_at),
                _timestamp(dispatch.updated_at),
            ),
        )
        self._insert_dispatch_outcome_tx(outcome)

    def _update_commit_dispatch_tx(
        self,
        current: CommitDispatchRecord,
        updated: CommitDispatchRecord,
        outcome: DispatchOutcomeRecord,
    ) -> CommitDispatchRecord:
        cursor = self._execute(
            "UPDATE enforced_commit_dispatches SET state = ?, effect_receipt_ref = ?, "
            "committed_verification_permit_digest = ?, "
            "committed_verification_permit_ref = ?, committed_verification_ref = ?, "
            "no_effect_evidence_ref = ?, "
            "outcome_evidence_refs_json = ?, unavailable_record_digest = ?, "
            "outcome_head_sequence = ?, "
            "outcome_head_digest = ?, version = ?, record_digest = ?, record_json = ?, "
            "updated_at = ? WHERE tenant_id = ? AND transaction_id = ? AND dispatch_id = ? "
            "AND version = ? AND state = ? AND outcome_head_sequence = ?",
            (
                updated.state.value,
                updated.effect_receipt_ref,
                updated.committed_verification_permit_digest,
                updated.committed_verification_permit_ref,
                updated.committed_verification_ref,
                updated.no_effect_evidence_ref,
                canonical_json_text(updated.outcome_evidence_refs),
                updated.unavailable_record_digest,
                updated.version,
                outcome.outcome_digest,
                updated.version,
                canonical_digest(updated),
                canonical_json_text(updated),
                _timestamp(updated.updated_at),
                current.tenant_id,
                current.transaction_id,
                current.dispatch_id,
                current.version,
                current.state.value,
                current.version,
            ),
        )
        if cursor.rowcount != 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Commit dispatch compare-and-swap failed",
                retryable=True,
            )
        self._insert_dispatch_outcome_tx(outcome)
        return updated

    @staticmethod
    def _assert_commit_permit_bindings(
        permit: CommitPermit,
        *,
        transaction: EnforcedTransactionRecord,
        action: NormalizedAction,
        stage: StageMaterialRecord,
        round_record: AuthorizationRoundRecord,
        approval_event: EnforcedTransactionEvent,
        lease: WorkerLeaseRecord,
        precommit_inspection_permit: InspectionPermit,
        precommit_inspection_permit_ref: str,
        precommit_plan: EffectPlan,
        precommit_plan_ref: str,
    ) -> None:
        approval_required = "approval" in round_record.obligations
        expected_approval_event = (
            TransitionEvent.APPROVAL_GRANTED.value
            if approval_required
            else TransitionEvent.NO_APPROVAL_REQUIRED.value
        )
        expected_deadline = _lease_bounded_deadline(
            transaction.deadline,
            lease.expires_at,
            round_record.authority_valid_until,
        )
        precommit_plan_digest = canonical_digest(precommit_plan)
        if (
            permit.tenant_id != transaction.tenant_id
            or permit.transaction_id != transaction.transaction_id
            or permit.intent_hash != transaction.intent_hash
            or permit.normalized_action_digest != transaction.normalized_action_digest
            or permit.adapter_manifest_digest != transaction.adapter_manifest_digest
            or permit.stage_id != stage.stage_id
            or permit.plan_digest != stage.plan_digest
            or permit.plan_ref != stage.plan_ref
            or permit.stage_permit_digest != stage.stage_permit_digest
            or permit.stage_permit_ref != stage.stage_permit_ref
            or permit.lease_id != stage.lease_id
            or permit.fencing_token != stage.fencing_token
            or permit.target_version_guard != stage.target_version_guard
            or permit.staged_receipt_ref != stage.staged_receipt_ref
            or permit.staged_state_digest != stage.staged_state_digest
            or permit.staged_verification_permit_digest != stage.verification_permit_digest
            or permit.staged_verification_permit_ref != stage.verification_permit_ref
            or permit.staged_verification_ref != stage.verification_ref
            or stage.verification_permit_digest is None
            or stage.verification_permit_ref is None
            or permit.authorization_round_id != round_record.round_id
            or permit.authorization_round_digest != round_record.round_digest
            or permit.authority_decision_digest != round_record.authority_decision_digest
            or permit.policy_decision_digest != round_record.policy_decision_digest
            or permit.policy_snapshot_digest != round_record.policy_snapshot_digest
            or permit.owner_version != round_record.owner_version
            or permit.owner_history_sequence != round_record.owner_history_sequence
            or permit.owner_history_digest != round_record.owner_history_digest
            or permit.lease_id != lease.lease_id
            or permit.worker_id != lease.worker_id
            or permit.fencing_token != lease.fencing_token
            or permit.deadline != expected_deadline
            or precommit_inspection_permit.tenant_id != transaction.tenant_id
            or precommit_inspection_permit.transaction_id != transaction.transaction_id
            or precommit_inspection_permit.intent_hash != action.intent_hash
            or precommit_inspection_permit.normalized_action_digest
            != transaction.normalized_action_digest
            or precommit_inspection_permit.proposal_ref != canonical_digest(precommit_plan.proposal)
            or precommit_inspection_permit.adapter_manifest_digest
            != transaction.adapter_manifest_digest
            or precommit_inspection_permit.authorization_round_id != round_record.round_id
            or precommit_inspection_permit.authorization_round_digest != round_record.round_digest
            or precommit_inspection_permit.lease_id != lease.lease_id
            or precommit_inspection_permit.worker_id != lease.worker_id
            or precommit_inspection_permit.fencing_token != lease.fencing_token
            or precommit_inspection_permit.deadline != expected_deadline
            or not (
                precommit_inspection_permit.issued_at
                <= permit.issued_at
                < precommit_inspection_permit.deadline
            )
            or permit.precommit_inspection_permit_digest
            != precommit_inspection_permit.permit_digest
            or permit.precommit_inspection_permit_ref != precommit_inspection_permit_ref
            or permit.precommit_plan_digest != precommit_plan_digest
            or permit.precommit_plan_ref != precommit_plan_ref
            or precommit_plan.intent_hash != action.intent_hash
            or precommit_plan.proposal.transaction_id != transaction.transaction_id
            or precommit_plan.proposal.goal_id != transaction.goal_id
            or precommit_plan.proposal.agent_id != transaction.agent_id
            or precommit_plan.proposal.adapter != action.adapter
            or precommit_plan.proposal.adapter_version != action.adapter_version
            or precommit_plan.proposal.operation != action.operation
            or precommit_plan.proposal.deadline != transaction.deadline
            or precommit_plan.proposal.idempotency_key != action.idempotency_key
            or precommit_plan.base_version != stage.target_version_guard
            or permit.idempotency_key != (action.idempotency_key or action.intent_hash)
            or permit.approval_required != approval_required
            or approval_event.event != expected_approval_event
            or approval_event.target_state is not TransactionState.READY_TO_COMMIT
            or permit.approval_evidence_ref not in approval_event.evidence_refs
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Commit permit differs from staged, authorization, or transaction evidence",
            )

    def begin_commit_dispatch(
        self,
        dispatch: CommitDispatchRecord,
        *,
        precommit_inspection_permit: InspectionPermit,
        precommit_inspection_permit_ref: str,
        precommit_plan: EffectPlan,
        precommit_plan_ref: str,
        expected_transaction_version: int,
    ) -> CommitDispatchResult:
        """Commit budget and dispatch evidence before returning fresh commit authority."""

        precommit_inspection_permit_ref = _require_digest(
            precommit_inspection_permit_ref,
            field="precommit_inspection_permit_ref",
        )
        precommit_plan_ref = _require_digest(
            precommit_plan_ref,
            field="precommit_plan_ref",
        )
        if precommit_inspection_permit_ref != canonical_digest(precommit_inspection_permit):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Precommit inspection permit artifact ref is inconsistent",
            )
        if precommit_plan_ref != canonical_digest(precommit_plan):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Precommit plan artifact ref is inconsistent",
            )
        if (
            dispatch.permit.precommit_inspection_permit_digest
            != precommit_inspection_permit.permit_digest
            or dispatch.permit.precommit_inspection_permit_ref != precommit_inspection_permit_ref
            or dispatch.permit.precommit_plan_digest != canonical_digest(precommit_plan)
            or dispatch.permit.precommit_plan_ref != precommit_plan_ref
            or precommit_inspection_permit.proposal_ref != canonical_digest(precommit_plan.proposal)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Commit authority differs from its precommit inspection artifacts",
            )
        if (
            dispatch.state is not CommitDispatchState.DISPATCHED
            or dispatch.version != 0
            or dispatch.outcome_evidence_refs
            or dispatch.updated_at != dispatch.created_at
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Initial commit dispatch must be evidence-free DISPATCHED version zero",
            )
        try:
            with self._immediate():
                current = self._get_enforced_transaction_tx(
                    dispatch.tenant_id,
                    dispatch.transaction_id,
                )
                existing = self._connection.execute(
                    "SELECT * FROM enforced_commit_dispatches "
                    "WHERE tenant_id = ? AND transaction_id = ?",
                    (dispatch.tenant_id, dispatch.transaction_id),
                ).fetchone()
                if existing is not None:
                    stored = self._dispatch_from_row(existing)
                    outcomes = self._validate_dispatch_outcome_chain_tx(stored)
                    if (
                        stored.dispatch_id != dispatch.dispatch_id
                        or stored.permit != dispatch.permit
                        or stored.permit_ref != dispatch.permit_ref
                        or stored.owner_version != dispatch.owner_version
                        or stored.created_at != dispatch.created_at
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Commit dispatch retry changed immutable authority",
                        )
                    return CommitDispatchResult(
                        stored,
                        outcomes[-1],
                        current,
                        None,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                if (
                    current.state is not TransactionState.READY_TO_COMMIT
                    or current.version != expected_transaction_version
                ):
                    raise AgentKernelError(
                        ErrorCode.ILLEGAL_TRANSITION,
                        "Commit dispatch requires exact READY_TO_COMMIT version",
                    )
                stage = self._get_stage_material_tx(
                    dispatch.tenant_id,
                    dispatch.transaction_id,
                )
                if stage.state is not StageMaterialState.VERIFIED:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Commit dispatch requires verified private stage material",
                    )
                action = self._get_normalized_action(
                    dispatch.tenant_id,
                    dispatch.transaction_id,
                ).action
                events = self._validate_transaction_chain_tx(current)
                permit = dispatch.permit
                authorization_round = self._get_authorization_round_tx(
                    dispatch.tenant_id,
                    dispatch.transaction_id,
                    permit.authorization_round_id,
                )
                if (
                    authorization_round.purpose is not AuthorizationRoundPurpose.PRECOMMIT
                    or authorization_round.verdict is not AuthorizationVerdict.ELIGIBLE
                    or authorization_round.controlled_transaction_id != dispatch.transaction_id
                ):
                    raise AgentKernelError(
                        ErrorCode.AUTHORITY_MISSING,
                        "Commit dispatch has no eligible persisted PRECOMMIT round",
                    )
                lease = self._assert_active_lease_tx(
                    tenant_id=dispatch.tenant_id,
                    transaction_id=dispatch.transaction_id,
                    lease_id=permit.lease_id,
                    worker_id=permit.worker_id,
                    fencing_token=permit.fencing_token,
                    purpose=LeasePurpose.STAGING,
                    at=dispatch.created_at,
                )
                reservation = self._read_capability_chain(
                    tenant_id=dispatch.tenant_id,
                    goal_id=cast("str", authorization_round.reservation_goal_id),
                    run_id=cast("str", authorization_round.reservation_run_id),
                    intent_hash=authorization_round.subject_intent_hash,
                )
                if (
                    reservation is None
                    or reservation.state is not CapabilityReservationState.RESERVED
                    or reservation.version != authorization_round.reservation_version
                    or capability_reservation_digest(reservation)
                    != authorization_round.capability_reservation_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.AUTHORITY_MISSING,
                        "Persisted precommit round lost its reserved capability fence",
                    )
                self._assert_commit_permit_bindings(
                    permit,
                    transaction=current,
                    action=action,
                    stage=stage,
                    round_record=authorization_round,
                    approval_event=events[-1],
                    lease=lease,
                    precommit_inspection_permit=precommit_inspection_permit,
                    precommit_inspection_permit_ref=precommit_inspection_permit_ref,
                    precommit_plan=precommit_plan,
                    precommit_plan_ref=precommit_plan_ref,
                )
                committed = self.commit_capability_chain(
                    tenant_id=reservation.tenant_id,
                    goal_id=reservation.goal_id,
                    run_id=reservation.run_id,
                    intent_hash=reservation.intent_hash,
                    capability_ids=reservation.capability_ids,
                    fence=reservation.fence,
                    committed_at=dispatch.created_at,
                )
                if (
                    committed.state is not CapabilityReservationState.COMMITTED
                    or permit.reservation_version != committed.version
                    or permit.capability_reservation_digest
                    != capability_reservation_digest(committed)
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Commit permit differs from consumed capability evidence",
                    )
                ledger = self._validate_intent_ledger(dispatch.tenant_id, dispatch.intent_hash)
                if (
                    ledger.owner_transaction_id != dispatch.transaction_id
                    or ledger.owner_version != dispatch.owner_version
                    or ledger.head_sequence != permit.owner_history_sequence
                    or ledger.head_digest != permit.owner_history_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Commit dispatch no longer owns the normalized intent",
                        retryable=False,
                    )
                dispatch_evidence_refs = tuple(
                    sorted(
                        {
                            dispatch.permit_ref,
                            permit.permit_digest,
                            authorization_round.round_digest,
                            permit.staged_verification_permit_digest,
                            permit.staged_verification_permit_ref,
                            permit.staged_verification_ref,
                            permit.precommit_inspection_permit_digest,
                            permit.precommit_inspection_permit_ref,
                            permit.precommit_plan_digest,
                            permit.precommit_plan_ref,
                            permit.capability_reservation_digest,
                        }
                    )
                )
                outcome = DispatchOutcomeRecord.create(
                    tenant_id=dispatch.tenant_id,
                    transaction_id=dispatch.transaction_id,
                    intent_hash=dispatch.intent_hash,
                    owner_version=dispatch.owner_version,
                    dispatch_id=dispatch.dispatch_id,
                    sequence=0,
                    outcome_id=_outcome_id(dispatch.dispatch_id, 0),
                    source_state=None,
                    target_state=CommitDispatchState.DISPATCHED,
                    classification=None,
                    evidence_refs=dispatch_evidence_refs,
                    recorded_at=dispatch.created_at,
                )
                updated_transaction, event = self._apply_transition_tx(
                    current,
                    expected_version=expected_transaction_version,
                    transition_event=TransitionEvent.COMMIT_GUARDS_PASSED,
                    recorded_at=dispatch.created_at,
                    evidence_refs=dispatch_evidence_refs,
                    updates={
                        "authorization_round_id": authorization_round.round_id,
                        "authorization_round_digest": authorization_round.round_digest,
                        "authority_decision_digest": (
                            authorization_round.authority_decision_digest
                        ),
                        "policy_decision_digest": authorization_round.policy_decision_digest,
                        "policy_snapshot_digest": authorization_round.policy_snapshot_digest,
                        "capability_reservation_digest": (permit.capability_reservation_digest),
                        "allowed_modes": authorization_round.allowed_modes,
                        "obligations": authorization_round.obligations,
                    },
                )
                self._insert_commit_dispatch_tx(dispatch, outcome)
                return CommitDispatchResult(
                    dispatch,
                    outcome,
                    updated_transaction,
                    event,
                    EnforcedStoreDisposition.COMMIT_NOW,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Commit dispatch persistence failed closed", error) from error

    def attach_receipt(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_dispatch_version: int,
        effect_receipt_ref: str,
        evidence_refs: tuple[str, ...],
        recorded_at: datetime,
    ) -> DispatchClassificationResult:
        """Durably attach the first observed effect receipt without classifying success."""

        effect_receipt_ref = _require_digest(
            effect_receipt_ref,
            field="effect_receipt_ref",
        )
        with self._immediate():
            dispatch = self._get_commit_dispatch_tx(tenant_id, transaction_id)
            transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
            outcomes = self._validate_dispatch_outcome_chain_tx(dispatch)
            if dispatch.effect_receipt_ref is not None:
                if dispatch.effect_receipt_ref != effect_receipt_ref:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Dispatch receipt retry changed the observed effect receipt",
                    )
                return DispatchClassificationResult(
                    dispatch,
                    outcomes[-1],
                    transaction,
                    None,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            if (
                dispatch.state is not CommitDispatchState.DISPATCHED
                or dispatch.version != expected_dispatch_version
                or transaction.state is not TransactionState.COMMITTING
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Dispatch receipt source state changed",
                )
            refs = tuple(sorted({*evidence_refs, effect_receipt_ref}))
            outcome = DispatchOutcomeRecord.create(
                tenant_id=dispatch.tenant_id,
                transaction_id=dispatch.transaction_id,
                intent_hash=dispatch.intent_hash,
                owner_version=dispatch.owner_version,
                dispatch_id=dispatch.dispatch_id,
                sequence=dispatch.version + 1,
                outcome_id=_outcome_id(dispatch.dispatch_id, dispatch.version + 1),
                source_state=dispatch.state,
                target_state=CommitDispatchState.DISPATCHED,
                classification=None,
                effect_receipt_ref=effect_receipt_ref,
                evidence_refs=refs,
                previous_outcome_digest=outcomes[-1].outcome_digest,
                recorded_at=recorded_at,
            )
            updated = CommitDispatchRecord.model_validate(
                {
                    **dispatch.model_dump(mode="python"),
                    "effect_receipt_ref": effect_receipt_ref,
                    "outcome_evidence_refs": tuple(
                        sorted({*dispatch.outcome_evidence_refs, *refs})
                    ),
                    "version": dispatch.version + 1,
                    "updated_at": recorded_at,
                }
            )
            self._update_commit_dispatch_tx(dispatch, updated, outcome)
            return DispatchClassificationResult(
                updated,
                outcome,
                transaction,
                None,
                EnforcedStoreDisposition.STORED,
            )

    def _release_active_dispatch_lease_tx(
        self,
        dispatch: CommitDispatchRecord,
        *,
        released_at: datetime,
    ) -> None:
        lease = self._get_worker_lease_tx(
            dispatch.tenant_id,
            dispatch.transaction_id,
            dispatch.permit.lease_id,
        )
        if lease.released_at is None:
            updated = WorkerLeaseRecord.model_validate(
                {
                    **lease.model_dump(mode="python"),
                    "version": lease.version + 1,
                    "released_at": released_at,
                }
            )
            self._update_worker_lease_tx(lease, updated)

    def classify_dispatch_evidence_unavailable(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_dispatch_version: int,
        expected_transaction_version: int,
        boundary: str,
        supporting_refs: tuple[str, ...],
        recorded_at: datetime,
        reason_code: str,
        recovery_timeout: timedelta,
    ) -> DispatchClassificationResult:
        """Fence a dispatched effect as IN_DOUBT without inventing artifact evidence."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        boundary = _require_identifier(boundary, field="boundary")
        reason_code = _require_identifier(reason_code, field="reason_code")
        if not reason_code.startswith(f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:"):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unavailable dispatch classification requires an unavailable reason",
            )
        if recovery_timeout <= timedelta(0):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unavailable dispatch recovery timeout must be positive",
            )
        supplied_supporting = {
            _require_digest(value, field="supporting_ref") for value in supporting_refs
        }
        with self._immediate():
            dispatch = self._get_commit_dispatch_tx(tenant_id, transaction_id)
            transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
            outcomes = self._validate_dispatch_outcome_chain_tx(dispatch)
            resolved_supporting = {
                *supplied_supporting,
                dispatch.permit_ref,
                *((dispatch.effect_receipt_ref,) if dispatch.effect_receipt_ref else ()),
            }
            record = DispatchEvidenceUnavailableRecord.create(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                dispatch_id=dispatch.dispatch_id,
                boundary=boundary,
                supporting_refs=tuple(sorted(resolved_supporting)),
                reported_at=recorded_at,
                reason_code=reason_code,
            )
            existing = self._get_dispatch_evidence_unavailable_tx(
                tenant_id,
                transaction_id,
                dispatch.dispatch_id,
            )
            if existing is not None:
                if existing != record:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Unavailable dispatch retry changed its terminal record",
                    )
                self._validate_dispatch_evidence_unavailable_association_tx(existing)
                return DispatchClassificationResult(
                    dispatch,
                    outcomes[-1],
                    transaction,
                    None,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            if (
                dispatch.state is not CommitDispatchState.DISPATCHED
                or dispatch.version != expected_dispatch_version
                or transaction.state is not TransactionState.COMMITTING
                or transaction.version != expected_transaction_version
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Unavailable dispatch classification lost its exact dispatched generation",
                )
            outcome_refs = (
                () if dispatch.effect_receipt_ref is None else (dispatch.effect_receipt_ref,)
            )
            outcome = DispatchOutcomeRecord.create(
                tenant_id=dispatch.tenant_id,
                transaction_id=dispatch.transaction_id,
                intent_hash=dispatch.intent_hash,
                owner_version=dispatch.owner_version,
                dispatch_id=dispatch.dispatch_id,
                sequence=dispatch.version + 1,
                outcome_id=_outcome_id(dispatch.dispatch_id, dispatch.version + 1),
                source_state=dispatch.state,
                target_state=CommitDispatchState.IN_DOUBT,
                classification=ReconciliationOutcome.UNKNOWN,
                effect_receipt_ref=dispatch.effect_receipt_ref,
                evidence_refs=outcome_refs,
                unavailable_record_digest=record.record_digest,
                reason_code=record.reason_code,
                previous_outcome_digest=outcomes[-1].outcome_digest,
                recorded_at=recorded_at,
            )
            updated_dispatch = CommitDispatchRecord.model_validate(
                {
                    **dispatch.model_dump(mode="python"),
                    "state": CommitDispatchState.IN_DOUBT,
                    "outcome_evidence_refs": tuple(
                        sorted({*dispatch.outcome_evidence_refs, *outcome_refs})
                    ),
                    "unavailable_record_digest": record.record_digest,
                    "version": dispatch.version + 1,
                    "updated_at": recorded_at,
                }
            )
            self._update_commit_dispatch_tx(dispatch, updated_dispatch, outcome)
            updated_transaction, event = self._apply_transition_tx(
                transaction,
                expected_version=expected_transaction_version,
                transition_event=TransitionEvent.COMMIT_OUTCOME_UNKNOWN,
                recorded_at=recorded_at,
                evidence_refs=(outcome.outcome_digest,),
                reason_code=record.reason_code,
                recovery_deadline=recorded_at + recovery_timeout,
            )
            ledger = self._validate_intent_ledger(tenant_id, dispatch.intent_hash)
            owner_attempt = self._connection.execute(
                "SELECT state_version FROM enforced_intent_attempts "
                "WHERE tenant_id = ? AND intent_hash = ? AND transaction_id = ?",
                (tenant_id, dispatch.intent_hash, dispatch.transaction_id),
            ).fetchone()
            if owner_attempt is None or ledger.owner_transaction_id != dispatch.transaction_id:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unavailable dispatch classification lost its intent owner",
                )
            self._record_intent_attempt_state_tx(
                tenant_id=tenant_id,
                intent_hash=dispatch.intent_hash,
                transaction_id=dispatch.transaction_id,
                expected_version=int(owner_attempt["state_version"]),
                target_state=IntentAttemptState.RECONCILE_REQUIRED,
                evidence_digest=outcome.outcome_digest,
                recorded_at=_timestamp(recorded_at),
            )
            self._release_active_dispatch_lease_tx(dispatch, released_at=recorded_at)
            self._insert_dispatch_evidence_unavailable_tx(record)
            self._execute(
                "INSERT INTO enforced_dispatch_evidence_unavailable_bindings("
                "tenant_id, transaction_id, dispatch_id, record_digest, outcome_sequence, "
                "outcome_digest, event_sequence, event_digest) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tenant_id,
                    transaction_id,
                    dispatch.dispatch_id,
                    record.record_digest,
                    outcome.sequence,
                    outcome.outcome_digest,
                    event.sequence,
                    event.event_digest,
                ),
            )
            return DispatchClassificationResult(
                updated_dispatch,
                outcome,
                updated_transaction,
                event,
                EnforcedStoreDisposition.REVIEW_REQUIRED,
            )

    def _assert_committed_verification_permit_tx(
        self,
        permit: VerificationPermit,
        permit_ref: str,
        *,
        dispatch: CommitDispatchRecord,
        transaction: EnforcedTransactionRecord,
        effect_receipt_ref: str,
        recorded_at: datetime,
        require_active_lease: bool,
    ) -> None:
        if permit_ref != canonical_digest(permit):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Committed verification permit artifact ref is inconsistent",
            )
        parent_digest: str
        parent_ref: str
        authorization_round_id: str
        authorization_round_digest: str
        lease_id: str
        worker_id: str
        fencing_token: int
        deadline: datetime
        purpose: LeasePurpose
        if permit.authority_permit_ref == dispatch.permit_ref:
            parent_digest = dispatch.permit.permit_digest
            parent_ref = dispatch.permit_ref
            authorization_round_id = dispatch.permit.authorization_round_id
            authorization_round_digest = dispatch.permit.authorization_round_digest
            lease_id = dispatch.permit.lease_id
            worker_id = dispatch.permit.worker_id
            fencing_token = dispatch.permit.fencing_token
            deadline = dispatch.permit.deadline
            purpose = LeasePurpose.STAGING
        else:
            row = self._connection.execute(
                "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
                "AND transaction_id = ? AND permit_ref = ?",
                (
                    transaction.tenant_id,
                    transaction.transaction_id,
                    permit.authority_permit_ref,
                ),
            ).fetchone()
            if row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Committed verification permit has no durable parent permit",
                )
            work = self._recovery_from_row(row)
            if work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH or work.permit is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Committed verification recovery parent is not reconciliation authority",
                )
            round_record = self._get_authorization_round_tx(
                work.tenant_id,
                work.transaction_id,
                work.authorization_round_id,
            )
            self._assert_recovery_round_bindings(work, round_record)
            if (
                work.target_id != dispatch.dispatch_id
                or work.intent_hash != dispatch.intent_hash
                or work.target_version_guard != dispatch.permit.target_version_guard
                or work.permit.recovery_action_digest
                != round_record.subject_normalized_action_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation authority does not bind the original dispatch subject",
                )
            parent_digest = work.permit.permit_digest
            parent_ref = cast("str", work.permit_ref)
            authorization_round_id = work.authorization_round_id
            authorization_round_digest = work.authorization_round_digest
            lease_id = cast("str", work.lease_id)
            worker_id = cast("str", work.worker_id)
            fencing_token = cast("int", work.fencing_token)
            deadline = work.permit.deadline
            purpose = LeasePurpose.RECONCILIATION
        if (
            permit.phase is not VerificationPhase.COMMITTED
            or permit.tenant_id != transaction.tenant_id
            or permit.transaction_id != transaction.transaction_id
            or permit.intent_hash != transaction.intent_hash
            or permit.normalized_action_digest != transaction.normalized_action_digest
            or permit.adapter_manifest_digest != transaction.adapter_manifest_digest
            or permit.authorization_round_id != authorization_round_id
            or permit.authorization_round_digest != authorization_round_digest
            or permit.lease_id != lease_id
            or permit.worker_id != worker_id
            or permit.fencing_token != fencing_token
            or permit.subject_ref != effect_receipt_ref
            or permit.authority_permit_digest != parent_digest
            or permit.authority_permit_ref != parent_ref
            or permit.subject_permit_digest != dispatch.permit.permit_digest
            or permit.subject_permit_ref != dispatch.permit_ref
            or permit.deadline != deadline
            or not (permit.issued_at <= recorded_at < permit.deadline)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Committed verification permit differs from its exact effect subject",
            )
        if require_active_lease:
            self._assert_active_lease_tx(
                tenant_id=transaction.tenant_id,
                transaction_id=transaction.transaction_id,
                lease_id=lease_id,
                worker_id=worker_id,
                fencing_token=fencing_token,
                purpose=purpose,
                at=recorded_at,
            )

    def classify_dispatch_outcome(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_dispatch_version: int,
        expected_transaction_version: int,
        classification: ReconciliationOutcome,
        evidence_refs: tuple[str, ...],
        recorded_at: datetime,
        effect_receipt_ref: str | None = None,
        committed_verification_permit: VerificationPermit | None = None,
        committed_verification_permit_ref: str | None = None,
        committed_verification_ref: str | None = None,
        no_effect_evidence_ref: str | None = None,
        reason_code: str | None = None,
        recovery_timeout: timedelta | None = None,
    ) -> DispatchClassificationResult:
        """Classify one dispatched generation once; UNKNOWN never authorizes resend."""

        committed_verification_permit_digest = (
            None
            if committed_verification_permit is None
            else committed_verification_permit.permit_digest
        )
        if recovery_timeout is not None and recovery_timeout <= timedelta(0):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery timeout must be positive",
            )
        with self._immediate():
            dispatch = self._get_commit_dispatch_tx(tenant_id, transaction_id)
            transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
            outcomes = self._validate_dispatch_outcome_chain_tx(dispatch)
            target_state = {
                ReconciliationOutcome.COMMITTED: CommitDispatchState.COMMITTED,
                ReconciliationOutcome.NO_EFFECT: CommitDispatchState.NO_EFFECT,
                ReconciliationOutcome.PARTIAL_OR_INVALID: (CommitDispatchState.PARTIAL_OR_INVALID),
                ReconciliationOutcome.UNKNOWN: CommitDispatchState.IN_DOUBT,
            }[classification]
            if classification is ReconciliationOutcome.COMMITTED:
                if (
                    (effect_receipt_ref is None and dispatch.effect_receipt_ref is None)
                    or committed_verification_permit is None
                    or (
                        committed_verification_permit_ref is None
                        or committed_verification_ref is None
                    )
                ):
                    raise AgentKernelError(
                        ErrorCode.AUTHORITY_MISSING,
                        "Committed classification requires receipt, verification, and permit",
                    )
                committed_verification_permit_ref = _require_digest(
                    committed_verification_permit_ref,
                    field="committed_verification_permit_ref",
                )
            elif (
                committed_verification_permit is not None
                or committed_verification_permit_ref is not None
                or committed_verification_ref is not None
            ):
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Only committed classification may carry verification authority",
                )
            repeated_reconciliation_unknown = (
                target_state is CommitDispatchState.IN_DOUBT
                and transaction.state is TransactionState.RECONCILING
            )
            if dispatch.state is target_state and not repeated_reconciliation_unknown:
                latest = outcomes[-1]
                resolved_effect_receipt = (
                    dispatch.effect_receipt_ref
                    if effect_receipt_ref is None
                    else _require_digest(
                        effect_receipt_ref,
                        field="effect_receipt_ref",
                    )
                )
                supplied_refs = {
                    _require_digest(value, field="evidence_ref") for value in evidence_refs
                }
                for value in (
                    resolved_effect_receipt,
                    committed_verification_permit_digest,
                    committed_verification_permit_ref,
                    committed_verification_ref,
                    no_effect_evidence_ref,
                ):
                    if value is not None:
                        supplied_refs.add(_require_digest(value, field="outcome_evidence_ref"))
                if (
                    latest.classification is not classification
                    or latest.effect_receipt_ref != resolved_effect_receipt
                    or latest.committed_verification_permit_digest
                    != committed_verification_permit_digest
                    or latest.committed_verification_permit_ref != committed_verification_permit_ref
                    or latest.committed_verification_ref != committed_verification_ref
                    or latest.no_effect_evidence_ref != no_effect_evidence_ref
                    or latest.reason_code != reason_code
                    or latest.recorded_at != recorded_at
                    or tuple(sorted(supplied_refs)) != latest.evidence_refs
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Dispatch classification retry changed terminal evidence",
                    )
                if committed_verification_permit is not None:
                    self._assert_committed_verification_permit_tx(
                        committed_verification_permit,
                        cast("str", committed_verification_permit_ref),
                        dispatch=dispatch,
                        transaction=transaction,
                        effect_receipt_ref=cast("str", resolved_effect_receipt),
                        recorded_at=recorded_at,
                        require_active_lease=False,
                    )
                return DispatchClassificationResult(
                    dispatch,
                    latest,
                    transaction,
                    None,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            if (
                dispatch.version != expected_dispatch_version
                or transaction.version != expected_transaction_version
                or dispatch.state
                not in {CommitDispatchState.DISPATCHED, CommitDispatchState.IN_DOUBT}
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Dispatch classification source changed or is terminal",
                )
            if dispatch.effect_receipt_ref is not None:
                if classification is ReconciliationOutcome.NO_EFFECT:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "A dispatch with effect evidence cannot be classified as no-effect",
                    )
                if effect_receipt_ref is None:
                    effect_receipt_ref = dispatch.effect_receipt_ref
                elif effect_receipt_ref != dispatch.effect_receipt_ref:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Dispatch classification changed the observed receipt",
                    )
            if committed_verification_permit is not None:
                self._assert_committed_verification_permit_tx(
                    committed_verification_permit,
                    cast("str", committed_verification_permit_ref),
                    dispatch=dispatch,
                    transaction=transaction,
                    effect_receipt_ref=cast("str", effect_receipt_ref),
                    recorded_at=recorded_at,
                    require_active_lease=True,
                )
            if classification is ReconciliationOutcome.PARTIAL_OR_INVALID and reason_code is None:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Partial or invalid dispatch classification requires a stable reason",
                )
            ref_set = set(evidence_refs)
            if effect_receipt_ref is not None:
                ref_set.add(effect_receipt_ref)
            if committed_verification_permit_digest is not None:
                ref_set.add(committed_verification_permit_digest)
            if committed_verification_permit_ref is not None:
                ref_set.add(committed_verification_permit_ref)
            if committed_verification_ref is not None:
                ref_set.add(committed_verification_ref)
            if no_effect_evidence_ref is not None:
                ref_set.add(no_effect_evidence_ref)
            refs = tuple(sorted(ref_set))
            outcome = DispatchOutcomeRecord.create(
                tenant_id=dispatch.tenant_id,
                transaction_id=dispatch.transaction_id,
                intent_hash=dispatch.intent_hash,
                owner_version=dispatch.owner_version,
                dispatch_id=dispatch.dispatch_id,
                sequence=dispatch.version + 1,
                outcome_id=_outcome_id(dispatch.dispatch_id, dispatch.version + 1),
                source_state=dispatch.state,
                target_state=target_state,
                classification=classification,
                effect_receipt_ref=effect_receipt_ref,
                committed_verification_permit_digest=(committed_verification_permit_digest),
                committed_verification_permit_ref=committed_verification_permit_ref,
                committed_verification_ref=committed_verification_ref,
                no_effect_evidence_ref=no_effect_evidence_ref,
                evidence_refs=refs,
                reason_code=reason_code,
                previous_outcome_digest=outcomes[-1].outcome_digest,
                recorded_at=recorded_at,
            )
            updated_dispatch = CommitDispatchRecord.model_validate(
                {
                    **dispatch.model_dump(mode="python"),
                    "state": target_state,
                    "effect_receipt_ref": effect_receipt_ref,
                    "committed_verification_permit_digest": (committed_verification_permit_digest),
                    "committed_verification_permit_ref": (committed_verification_permit_ref),
                    "committed_verification_ref": committed_verification_ref,
                    "no_effect_evidence_ref": no_effect_evidence_ref,
                    "outcome_evidence_refs": tuple(
                        sorted({*dispatch.outcome_evidence_refs, *refs})
                    ),
                    "version": dispatch.version + 1,
                    "updated_at": recorded_at,
                }
            )
            self._update_commit_dispatch_tx(dispatch, updated_dispatch, outcome)
            if transaction.state is TransactionState.COMMITTING:
                transition = {
                    ReconciliationOutcome.COMMITTED: TransitionEvent.COMMIT_VERIFIED,
                    ReconciliationOutcome.NO_EFFECT: TransitionEvent.COMMIT_FAILED_NO_EFFECT,
                    ReconciliationOutcome.PARTIAL_OR_INVALID: (
                        TransitionEvent.COMMIT_PARTIAL_OR_INVALID
                    ),
                    ReconciliationOutcome.UNKNOWN: TransitionEvent.COMMIT_OUTCOME_UNKNOWN,
                }[classification]
            elif transaction.state is TransactionState.RECONCILING:
                transition = {
                    ReconciliationOutcome.COMMITTED: TransitionEvent.RECONCILIATION_COMMITTED,
                    ReconciliationOutcome.NO_EFFECT: TransitionEvent.RECONCILIATION_NO_EFFECT,
                    ReconciliationOutcome.PARTIAL_OR_INVALID: (
                        TransitionEvent.RECONCILIATION_PARTIAL_OR_INVALID
                    ),
                    ReconciliationOutcome.UNKNOWN: TransitionEvent.RECONCILIATION_UNKNOWN,
                }[classification]
            else:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Dispatch classification requires COMMITTING or RECONCILING",
                )
            updated_transaction, event = self._apply_transition_tx(
                transaction,
                expected_version=expected_transaction_version,
                transition_event=transition,
                recorded_at=recorded_at,
                evidence_refs=(outcome.outcome_digest, *refs),
                reason_code=(
                    reason_code
                    if classification is ReconciliationOutcome.PARTIAL_OR_INVALID
                    else None
                ),
                recovery_deadline=(
                    None if recovery_timeout is None else recorded_at + recovery_timeout
                ),
            )
            ledger = self._validate_intent_ledger(tenant_id, dispatch.intent_hash)
            target_attempt = {
                ReconciliationOutcome.COMMITTED: IntentAttemptState.COMMITTED,
                ReconciliationOutcome.NO_EFFECT: IntentAttemptState.NO_EFFECT_CONFIRMED,
                ReconciliationOutcome.PARTIAL_OR_INVALID: IntentAttemptState.REVIEW_REQUIRED,
                ReconciliationOutcome.UNKNOWN: IntentAttemptState.RECONCILE_REQUIRED,
            }[classification]
            if not (
                ledger.owner_state is IntentAttemptState.RECONCILE_REQUIRED
                and target_attempt is IntentAttemptState.RECONCILE_REQUIRED
            ):
                owner_attempt = self._connection.execute(
                    "SELECT state_version FROM enforced_intent_attempts "
                    "WHERE tenant_id = ? AND intent_hash = ? AND transaction_id = ?",
                    (tenant_id, dispatch.intent_hash, dispatch.transaction_id),
                ).fetchone()
                if owner_attempt is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Dispatch owner lost its intent-attempt projection",
                    )
                self._record_intent_attempt_state_tx(
                    tenant_id=tenant_id,
                    intent_hash=dispatch.intent_hash,
                    transaction_id=dispatch.transaction_id,
                    expected_version=int(owner_attempt["state_version"]),
                    target_state=target_attempt,
                    evidence_digest=outcome.outcome_digest,
                    recorded_at=_timestamp(recorded_at),
                )
            self._release_active_dispatch_lease_tx(dispatch, released_at=recorded_at)
            return DispatchClassificationResult(
                updated_dispatch,
                outcome,
                updated_transaction,
                event,
                EnforcedStoreDisposition.STORED,
            )

    def complete_unstaged_abort(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_transaction_version: int,
        recorded_at: datetime,
    ) -> EnforcedTransactionResult:
        """Finish ABORTING when SQL proves no private stage or dispatch ever existed."""

        with self._immediate():
            transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
            if transaction.state in {TransactionState.ABORTED, TransactionState.STALE_STATE}:
                return EnforcedTransactionResult(
                    transaction,
                    None,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            if (
                transaction.state is not TransactionState.ABORTING
                or transaction.version != expected_transaction_version
            ):
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Unstaged abort completion requires exact ABORTING version",
                )
            stage = self._connection.execute(
                "SELECT 1 FROM enforced_stage_material WHERE tenant_id = ? AND transaction_id = ?",
                (tenant_id, transaction_id),
            ).fetchone()
            dispatch = self._connection.execute(
                "SELECT 1 FROM enforced_commit_dispatches "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (tenant_id, transaction_id),
            ).fetchone()
            if stage is not None or dispatch is not None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Staged or dispatched work requires separately authorized recovery",
                )
            intent_attempt_version: int | None = None
            reservation: CapabilityChainReservation | None = None
            action: NormalizedAction | None = None
            if transaction.intent_hash is not None:
                ledger = self._validate_intent_ledger(tenant_id, transaction.intent_hash)
                if ledger.owner_transaction_id != transaction_id:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Only the current intent owner may complete a no-effect abort",
                    )
                if ledger.owner_state is IntentAttemptState.ACTIVE:
                    attempt_row = self._connection.execute(
                        "SELECT state_version FROM enforced_intent_attempts "
                        "WHERE tenant_id = ? AND intent_hash = ? AND transaction_id = ?",
                        (tenant_id, transaction.intent_hash, transaction_id),
                    ).fetchone()
                    if attempt_row is None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Abort owner lost its intent-attempt projection",
                        )
                    intent_attempt_version = int(attempt_row["state_version"])
                action = self._get_normalized_action(tenant_id, transaction_id).action
                reservation = self._read_capability_chain(
                    tenant_id=tenant_id,
                    goal_id=action.goal_id,
                    run_id=action.run_id,
                    intent_hash=action.intent_hash,
                )
                if (
                    reservation is not None
                    and reservation.state is not CapabilityReservationState.RESERVED
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Unstaged abort cannot release a dispatched capability use",
                    )
            active_lease = self._connection.execute(
                "SELECT * FROM enforced_worker_leases "
                "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
                (tenant_id, transaction_id),
            ).fetchone()
            if active_lease is not None:
                lease = self._lease_from_row(active_lease)
                released = WorkerLeaseRecord.model_validate(
                    {
                        **lease.model_dump(mode="python"),
                        "version": lease.version + 1,
                        "released_at": recorded_at,
                    }
                )
                self._update_worker_lease_tx(lease, released)
            updated, event = self._apply_transition_tx(
                transaction,
                expected_version=expected_transaction_version,
                transition_event=TransitionEvent.STAGING_DISCARD_SUCCEEDED,
                recorded_at=recorded_at,
                reason_code="NO_PRIVATE_STAGE_OR_DISPATCH",
            )
            if transaction.intent_hash is not None and intent_attempt_version is not None:
                self._record_intent_attempt_state_tx(
                    tenant_id=tenant_id,
                    intent_hash=transaction.intent_hash,
                    transaction_id=transaction_id,
                    expected_version=intent_attempt_version,
                    target_state=IntentAttemptState.NO_EFFECT_CONFIRMED,
                    evidence_digest=event.event_digest,
                    recorded_at=_timestamp(recorded_at),
                )
            if reservation is not None and action is not None:
                self.release_capability_chain(
                    tenant_id=tenant_id,
                    goal_id=action.goal_id,
                    run_id=action.run_id,
                    intent_hash=action.intent_hash,
                    capability_ids=reservation.capability_ids,
                    fence=reservation.fence,
                    released_at=recorded_at,
                )
            return EnforcedTransactionResult(
                updated,
                event,
                EnforcedStoreDisposition.STORED,
            )

    def _exact_undispatched_target_reservation_tx(
        self,
        transaction: EnforcedTransactionRecord,
    ) -> CapabilityChainReservation:
        """Return the exact still-reserved original capability generation.

        A private-stage failure is review-required, but SQL still proves that no
        commit dispatch ever crossed the external-effect boundary.  That proof is
        sufficient to release the original pre-dispatch budget without claiming that
        the private stage itself was successfully discarded.
        """

        if (
            transaction.intent_hash is None
            or transaction.normalized_action_digest is None
            or transaction.authorization_round_id is None
            or transaction.authorization_round_digest is None
            or transaction.authority_decision_digest is None
            or transaction.policy_decision_digest is None
            or transaction.policy_snapshot_digest is None
            or transaction.capability_reservation_digest is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Undispatched recovery target lacks its authorization bindings",
            )
        dispatched = self._connection.execute(
            "SELECT 1 FROM enforced_commit_dispatches "
            "WHERE tenant_id = ? AND transaction_id = ? LIMIT 1",
            (transaction.tenant_id, transaction.transaction_id),
        ).fetchone()
        if dispatched is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "A dispatched target capability cannot be released as pre-dispatch",
            )
        action_subject = self._get_normalized_action(
            transaction.tenant_id,
            transaction.transaction_id,
        )
        action = action_subject.action
        record = self._get_authorization_round_tx(
            transaction.tenant_id,
            transaction.transaction_id,
            transaction.authorization_round_id,
        )
        if (
            action_subject.action_digest != transaction.normalized_action_digest
            or action.intent_hash != transaction.intent_hash
            or record.purpose
            not in {AuthorizationRoundPurpose.STAGING, AuthorizationRoundPurpose.PRECOMMIT}
            or record.verdict is not AuthorizationVerdict.ELIGIBLE
            or record.controlled_transaction_id != transaction.transaction_id
            or record.subject_transaction_id != transaction.transaction_id
            or record.subject_intent_hash != transaction.intent_hash
            or record.subject_normalized_action_digest != transaction.normalized_action_digest
            or record.round_digest != transaction.authorization_round_digest
            or record.authority_decision_digest != transaction.authority_decision_digest
            or record.policy_decision_digest != transaction.policy_decision_digest
            or record.policy_snapshot_digest != transaction.policy_snapshot_digest
            or record.capability_reservation_digest != transaction.capability_reservation_digest
            or record.reservation_goal_id != action.goal_id
            or record.reservation_run_id != action.run_id
            or record.reservation_version is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Undispatched target differs from its exact authorization round",
            )
        reservation = self._read_capability_chain(
            tenant_id=transaction.tenant_id,
            goal_id=action.goal_id,
            run_id=action.run_id,
            intent_hash=transaction.intent_hash,
        )
        if (
            reservation is None
            or reservation.state is not CapabilityReservationState.RESERVED
            or reservation.version != record.reservation_version
            or capability_reservation_digest(reservation)
            != transaction.capability_reservation_digest
            or reservation.activation_owner_transaction_id != transaction.transaction_id
            or reservation.activation_owner_version != record.owner_version
            or reservation.activation_history_sequence != record.owner_history_sequence
            or reservation.activation_history_digest != record.owner_history_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Undispatched target lost its exact reserved capability fence",
            )
        return reservation

    def _release_review_required_undispatched_reservation_tx(
        self,
        transaction: EnforcedTransactionRecord,
        reservation: CapabilityChainReservation,
        *,
        released_at: datetime,
    ) -> None:
        """Release one exact pre-dispatch reservation after bounded review settlement."""

        ledger = self._validate_intent_ledger(transaction.tenant_id, reservation.intent_hash)
        if (
            ledger.owner_transaction_id != transaction.transaction_id
            or ledger.owner_version != reservation.activation_owner_version
            or ledger.owner_state is not IntentAttemptState.REVIEW_REQUIRED
            or reservation.state is not CapabilityReservationState.RESERVED
            or reservation.activation_owner_transaction_id != transaction.transaction_id
            or reservation.activation_history_sequence is None
            or reservation.activation_history_digest is None
        ):
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Review-required capability release lost its exact undispatched owner",
                retryable=False,
            )
        timestamp = _timestamp(released_at)
        released = self._execute(
            "UPDATE enforced_capability_chain_reservations SET "
            "reservation_state = 'RELEASED', version = version + 1, "
            "release_history_sequence = ?, release_history_digest = ?, "
            "reuse_without_budget = 0, updated_at = ? "
            "WHERE tenant_id = ? AND goal_id = ? AND run_id = ? AND intent_hash = ? "
            "AND request_digest = ? AND reservation_state = 'RESERVED' AND version = ? "
            "AND reuse_without_budget = ? "
            "AND activation_owner_transaction_id = ? "
            "AND activation_owner_version = ? AND activation_history_sequence = ? "
            "AND activation_history_digest = ?",
            (
                ledger.head_sequence,
                ledger.head_digest,
                timestamp,
                reservation.tenant_id,
                reservation.goal_id,
                reservation.run_id,
                reservation.intent_hash,
                reservation.request_digest,
                reservation.version,
                int(reservation.budget_reuse),
                reservation.activation_owner_transaction_id,
                reservation.activation_owner_version,
                reservation.activation_history_sequence,
                reservation.activation_history_digest,
            ),
        )
        if released.rowcount != 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Review-required capability release lost its exact reservation CAS",
                retryable=True,
            )
        for capability_id in reservation.capability_ids:
            item = self._execute(
                "UPDATE enforced_capability_use_reservations SET "
                "reservation_state = 'RELEASED', updated_at = ? "
                "WHERE tenant_id = ? AND capability_id = ? AND goal_id = ? "
                "AND run_id = ? AND intent_hash = ? AND request_digest = ? "
                "AND reservation_state = 'RESERVED'",
                (
                    timestamp,
                    reservation.tenant_id,
                    capability_id,
                    reservation.goal_id,
                    reservation.run_id,
                    reservation.intent_hash,
                    reservation.request_digest,
                ),
            )
            if item.rowcount != 1:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Review-required capability item release was not atomic",
                )
            if reservation.budget_reuse:
                continue
            budget = self._execute(
                "UPDATE enforced_capability_budgets "
                "SET reserved_uses = reserved_uses - 1, version = version + 1, "
                "updated_at = ? WHERE tenant_id = ? AND capability_id = ? "
                "AND goal_id = ? AND run_id = ? AND reserved_uses >= 1",
                (
                    timestamp,
                    reservation.tenant_id,
                    capability_id,
                    reservation.goal_id,
                    reservation.run_id,
                ),
            )
            if budget.rowcount != 1:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Review-required capability budget release was not atomic",
                )

    def fail_stage_recovery_handoff(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_transaction_version: int,
        stage_id: str,
        expected_stage_version: int,
        stage_target_ref: str,
        failure_evidence_ref: str | None,
        reason_code: str,
        recorded_at: datetime,
        failure_evidence_status: RecoveryHandoffFailureEvidenceStatus = (
            RecoveryHandoffFailureEvidenceStatus.AVAILABLE
        ),
        recovery_action_transaction_id: str | None = None,
        recovery_action_intent_hash: str | None = None,
        recovery_action_digest: str | None = None,
        recovery_action_binding: RecoveryActionBinding | None = None,
        handoff_lease_id: str | None = None,
        handoff_worker_id: str | None = None,
        handoff_fencing_token: int | None = None,
        expected_handoff_lease_version: int | None = None,
    ) -> StageMaterialResult:
        """Atomically fail a stage when separately authorized recovery cannot be created."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        stage_id = _require_identifier(stage_id, field="stage_id")
        stage_target_ref = _require_digest(stage_target_ref, field="stage_target_ref")
        recovery_action_group = (
            recovery_action_transaction_id,
            recovery_action_intent_hash,
            recovery_action_digest,
        )
        if any(value is None for value in recovery_action_group) != all(
            value is None for value in recovery_action_group
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery action cleanup bindings must be all present or all absent",
            )
        if recovery_action_transaction_id is not None and recovery_action_binding is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Attached recovery action cleanup requires its durable binding",
            )
        if recovery_action_binding is not None:
            try:
                recovery_action_binding = RecoveryActionBinding.model_validate(
                    recovery_action_binding.model_dump(mode="python")
                )
            except (AttributeError, TypeError, ValidationError, ValueError) as error:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Recovery action cleanup binding is not canonical",
                ) from error
        if recovery_action_transaction_id is not None:
            recovery_action_transaction_id = _require_identifier(
                recovery_action_transaction_id,
                field="recovery_action_transaction_id",
            )
            recovery_action_intent_hash = _require_digest(
                cast("str", recovery_action_intent_hash),
                field="recovery_action_intent_hash",
            )
            recovery_action_digest = _require_digest(
                cast("str", recovery_action_digest),
                field="recovery_action_digest",
            )
        handoff_lease_group = (
            handoff_lease_id,
            handoff_worker_id,
            handoff_fencing_token,
            expected_handoff_lease_version,
        )
        if any(value is None for value in handoff_lease_group) != all(
            value is None for value in handoff_lease_group
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery handoff lease bindings must be all present or all absent",
            )
        if handoff_lease_id is not None:
            handoff_lease_id = _require_identifier(
                handoff_lease_id,
                field="handoff_lease_id",
            )
            handoff_worker_id = _require_identifier(
                cast("str", handoff_worker_id),
                field="handoff_worker_id",
            )
        if not isinstance(reason_code, str) or not reason_code.strip():
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Failed recovery handoff requires a stable reason code",
            )
        failure_evidence_ref = _require_handoff_failure_evidence(
            failure_evidence_ref,
            status=failure_evidence_status,
            reason_code=reason_code,
        )
        operation_evidence_ref = failure_evidence_ref or (
            canonical_digest(recovery_action_binding)
            if recovery_action_binding is not None
            else stage_target_ref
        )
        try:
            with self._immediate():
                transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
                stage = self._get_stage_material_tx(tenant_id, transaction_id)
                if (
                    transaction.state is not TransactionState.ABORTING
                    or transaction.version != expected_transaction_version
                    or stage.stage_id != stage_id
                    or stage.version != expected_stage_version
                    or stage.state
                    in {StageMaterialState.DISCARDED, StageMaterialState.DISCARD_FAILED}
                    or canonical_digest(stage) != stage_target_ref
                    or transaction.intent_hash is None
                    or transaction.intent_hash != stage.intent_hash
                    or transaction.normalized_action_digest != stage.normalized_action_digest
                    or transaction.adapter_manifest_digest != stage.adapter_manifest_digest
                    or recorded_at < transaction.updated_at
                    or recorded_at < stage.updated_at
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Failed recovery handoff differs from its exact ABORTING stage target",
                        retryable=False,
                    )
                recovery = self._connection.execute(
                    "SELECT 1 FROM enforced_recovery_work "
                    "WHERE tenant_id = ? AND transaction_id = ? "
                    "AND (kind = 'DISCARD_STAGING' "
                    "OR state IN ('PENDING', 'RUNNING', 'RETRY_SCHEDULED')) LIMIT 1",
                    (tenant_id, transaction_id),
                ).fetchone()
                dispatch_row = self._connection.execute(
                    "SELECT * FROM enforced_commit_dispatches "
                    "WHERE tenant_id = ? AND transaction_id = ? LIMIT 1",
                    (tenant_id, transaction_id),
                ).fetchone()
                active_lease_row = self._connection.execute(
                    "SELECT * FROM enforced_worker_leases "
                    "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL LIMIT 1",
                    (tenant_id, transaction_id),
                ).fetchone()
                dispatch = None if dispatch_row is None else self._dispatch_from_row(dispatch_row)
                if recovery is not None or (
                    dispatch is not None
                    and (
                        dispatch.state is not CommitDispatchState.NO_EFFECT
                        or dispatch.effect_receipt_ref is not None
                    )
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Failed recovery handoff conflicts with work or an effect-bearing dispatch",
                        retryable=False,
                    )
                if active_lease_row is not None:
                    active_lease = self._lease_from_row(active_lease_row)
                    expected_handoff = handoff_lease_id is not None
                    handoff_matches = (
                        expected_handoff
                        and active_lease.lease_id == handoff_lease_id
                        and active_lease.worker_id == handoff_worker_id
                        and active_lease.purpose is LeasePurpose.RECOVERY
                        and active_lease.fencing_token == handoff_fencing_token
                        and active_lease.version == expected_handoff_lease_version
                    )
                    expired_unowned_lease = (
                        not expected_handoff
                        and active_lease.purpose in {LeasePurpose.STAGING, LeasePurpose.RECOVERY}
                        and active_lease.expires_at <= recorded_at
                    )
                    if not handoff_matches and not expired_unowned_lease:
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Failed recovery handoff conflicts with a live worker lease",
                            retryable=False,
                        )
                    released_lease = WorkerLeaseRecord.model_validate(
                        {
                            **active_lease.model_dump(mode="python"),
                            "version": active_lease.version + 1,
                            "released_at": recorded_at,
                        }
                    )
                    self._update_worker_lease_tx(active_lease, released_lease)
                elif handoff_lease_id is not None:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Failed recovery handoff lost its expected handoff lease",
                        retryable=False,
                    )
                ledger = self._validate_intent_ledger(tenant_id, transaction.intent_hash)
                if ledger.owner_transaction_id != transaction_id or ledger.owner_state not in {
                    IntentAttemptState.ACTIVE,
                    IntentAttemptState.NO_EFFECT_CONFIRMED,
                }:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Failed recovery handoff lost its active intent ownership",
                        retryable=False,
                    )
                target_reservation = (
                    self._exact_undispatched_target_reservation_tx(transaction)
                    if ledger.owner_state is IntentAttemptState.ACTIVE
                    else None
                )
                failed_stage = StageMaterialRecord.model_validate(
                    {
                        **stage.model_dump(mode="python"),
                        "state": StageMaterialState.DISCARD_FAILED,
                        "discard_evidence_ref": operation_evidence_ref,
                        "version": stage.version + 1,
                        "updated_at": recorded_at,
                    }
                )
                self._update_stage_material_tx(stage, failed_stage)
                if ledger.owner_state is IntentAttemptState.ACTIVE:
                    self._transition_owned_attempt_tx(
                        tenant_id=tenant_id,
                        intent_hash=transaction.intent_hash,
                        transaction_id=transaction_id,
                        owner_version=ledger.owner_version,
                        owner_history_sequence=ledger.head_sequence,
                        owner_history_digest=ledger.head_digest,
                        target_state=IntentAttemptState.REVIEW_REQUIRED,
                        evidence_digest=operation_evidence_ref,
                        recorded_at=recorded_at,
                    )
                    if target_reservation is None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Failed stage handoff lost its reserved target capability",
                        )
                    self._release_review_required_undispatched_reservation_tx(
                        transaction,
                        target_reservation,
                        released_at=recorded_at,
                    )
                association: sqlite3.Row | None = None
                if recovery_action_binding is not None:
                    binding = recovery_action_binding
                    association = self._connection.execute(
                        "SELECT * FROM enforced_recovery_action_handoffs "
                        "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
                        (tenant_id, transaction_id, binding.recovery_id),
                    ).fetchone()
                    if (
                        association is None
                        or str(association["recovery_kind"])
                        != RecoveryWorkKind.DISCARD_STAGING.value
                        or str(association["target_id"]) != stage.stage_id
                        or str(association["target_evidence_ref"]) != stage_target_ref
                        or str(association["binding_ref"]) != canonical_digest(binding)
                        or str(association["binding_json"]) != canonical_json_text(binding)
                        or association["closed_at"] is not None
                        or (
                            recovery_action_transaction_id is None
                            and association["recovery_action_transaction_id"] is not None
                        )
                        or (
                            recovery_action_transaction_id is not None
                            and (
                                str(association["recovery_action_transaction_id"])
                                != recovery_action_transaction_id
                                or str(association["recovery_action_intent_hash"])
                                != recovery_action_intent_hash
                                or str(association["recovery_action_digest"])
                                != recovery_action_digest
                            )
                        )
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery action cleanup lacks its exact durable handoff association",
                        )
                if recovery_action_transaction_id is not None:
                    binding = cast("RecoveryActionBinding", recovery_action_binding)
                    enforced_subject = self._connection.execute(
                        "SELECT 1 FROM enforced_transactions "
                        "WHERE tenant_id = ? AND transaction_id = ?",
                        (tenant_id, recovery_action_transaction_id),
                    ).fetchone()
                    if enforced_subject is not None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery action cleanup cannot mutate an enforced transaction subject",
                        )
                    recovery_subject = self._get_normalized_action(
                        tenant_id,
                        recovery_action_transaction_id,
                    )
                    target_subject = self._get_normalized_action(tenant_id, transaction_id)
                    recovery_action = recovery_subject.action
                    target_action = target_subject.action
                    binding_arguments = tuple(
                        argument
                        for argument in recovery_action.semantic_arguments
                        if argument.argument_name == RECOVERY_ACTION_BINDING_ARGUMENT
                    )
                    remaining_arguments = tuple(
                        argument
                        for argument in recovery_action.semantic_arguments
                        if argument.argument_name != RECOVERY_ACTION_BINDING_ARGUMENT
                    )
                    if (
                        recovery_subject.action_digest != recovery_action_digest
                        or recovery_action.intent_hash != recovery_action_intent_hash
                        or recovery_action.transaction_id != recovery_action_transaction_id
                        or recovery_action.transaction_id == transaction_id
                        or recovery_action.tenant_id != target_action.tenant_id
                        or recovery_action.principal_id != target_action.principal_id
                        or recovery_action.goal_id != target_action.goal_id
                        or recovery_action.run_id != target_action.run_id
                        or recovery_action.trace_id != target_action.trace_id
                        or recovery_action.actor_id != target_action.actor_id
                        or recovery_action.on_behalf_of != target_action.on_behalf_of
                        or recovery_action.agent_id != target_action.agent_id
                        or recovery_action.adapter != target_action.adapter
                        or recovery_action.adapter_version != target_action.adapter_version
                        or recovery_action.operation != target_action.operation
                        or recovery_action.adapter_manifest_digest
                        != target_action.adapter_manifest_digest
                        or recovery_action.configuration_digest
                        != target_action.configuration_digest
                        or recovery_action.normalizer_implementation
                        != target_action.normalizer_implementation
                        or recovery_action.normalizer_version != target_action.normalizer_version
                        or recovery_action.normalizer_digest != target_action.normalizer_digest
                        or recovery_action.operation_schema_ref
                        != target_action.operation_schema_ref
                        or recovery_action.operation_schema_digest
                        != target_action.operation_schema_digest
                        or recovery_action.risk_floor is not target_action.risk_floor
                        or recovery_action.effect_domains != target_action.effect_domains
                        or recovery_action.resource_uses != target_action.resource_uses
                        or recovery_action.provenance != target_action.provenance
                        or remaining_arguments != target_action.semantic_arguments
                        or len(binding_arguments) != 1
                        or binding_arguments[0].digest != canonical_digest(binding)
                        or binding.target_transaction_id != transaction_id
                        or binding.target_intent_hash != transaction.intent_hash
                        or binding.target_normalized_action_digest
                        != transaction.normalized_action_digest
                        or binding.recovery_kind is not RecoveryWorkKind.DISCARD_STAGING
                        or binding.target_id != stage.stage_id
                        or binding.target_evidence_ref != stage_target_ref
                        or binding.target_version_guard != stage.target_version_guard
                        or binding.adapter_manifest_digest != transaction.adapter_manifest_digest
                        or binding.risk_class is not target_action.risk_floor
                        or binding.effect_domains != target_action.effect_domains
                        or binding.resource_uses_digest
                        != canonical_digest(target_action.resource_uses)
                        or binding.absolute_deadline != recovery_action.deadline
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery action cleanup differs from its failed target",
                        )
                    recovery_ledger = self._validate_intent_ledger(
                        tenant_id,
                        recovery_action_intent_hash,
                    )
                    if (
                        recovery_ledger.owner_transaction_id != recovery_action_transaction_id
                        or recovery_ledger.owner_state is not IntentAttemptState.ACTIVE
                    ):
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Recovery action cleanup lost its active intent ownership",
                            retryable=False,
                        )
                    self._transition_owned_attempt_tx(
                        tenant_id=tenant_id,
                        intent_hash=recovery_action_intent_hash,
                        transaction_id=recovery_action_transaction_id,
                        owner_version=recovery_ledger.owner_version,
                        owner_history_sequence=recovery_ledger.head_sequence,
                        owner_history_digest=recovery_ledger.head_digest,
                        target_state=IntentAttemptState.NO_EFFECT_CONFIRMED,
                        evidence_digest=operation_evidence_ref,
                        recorded_at=recorded_at,
                    )
                if association is not None:
                    terminal_sequence = self._next_recovery_handoff_terminal_sequence_tx(
                        tenant_id,
                        recorded_at=recorded_at,
                    )
                    cursor = self._execute(
                        "UPDATE enforced_recovery_action_handoffs SET "
                        "closed_at = ?, terminal_sequence = ?, failure_evidence_status = ?, "
                        "failure_evidence_ref = ?, failure_reason_code = ? "
                        "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ? "
                        "AND closed_at IS NULL",
                        (
                            _timestamp(recorded_at),
                            terminal_sequence,
                            failure_evidence_status.value,
                            failure_evidence_ref,
                            reason_code,
                            tenant_id,
                            transaction_id,
                            cast("RecoveryActionBinding", recovery_action_binding).recovery_id,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Failed recovery handoff lost its terminal association CAS",
                            retryable=True,
                        )
                updated, event = self._apply_transition_tx(
                    transaction,
                    expected_version=expected_transaction_version,
                    transition_event=TransitionEvent.STAGING_DISCARD_FAILED,
                    recorded_at=recorded_at,
                    evidence_refs=(operation_evidence_ref,),
                    reason_code=reason_code,
                )
                return StageMaterialResult(
                    failed_stage,
                    updated,
                    event,
                    EnforcedStoreDisposition.STORED,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Failed recovery handoff did not persist", error) from error

    def terminalize_expired_recovery_handoff(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_transaction_version: int,
        binding: RecoveryActionBinding,
        lease_id: str,
        worker_id: str,
        failure_evidence_ref: str | None,
        recorded_at: datetime,
        reason_code: str = ErrorCode.DEADLINE_EXCEEDED.value,
        failure_evidence_status: RecoveryHandoffFailureEvidenceStatus = (
            RecoveryHandoffFailureEvidenceStatus.AVAILABLE
        ),
    ) -> EnforcedTransactionResult:
        """Atomically persist a no-work review barrier after a recovery deadline."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        lease_id = _require_identifier(lease_id, field="lease_id")
        worker_id = _require_identifier(worker_id, field="worker_id")
        if type(expected_transaction_version) is not int or expected_transaction_version < 0:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Expired recovery handoff requires an exact transaction version",
            )
        expected_reason_code = {
            RecoveryHandoffFailureEvidenceStatus.AVAILABLE: (ErrorCode.DEADLINE_EXCEEDED.value),
            RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE: (
                f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{ErrorCode.DEADLINE_EXCEEDED.value}"
            ),
        }.get(failure_evidence_status)
        if expected_reason_code is None or reason_code != expected_reason_code:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Expired recovery handoff requires a typed deadline settlement reason",
            )
        failure_evidence_ref = _require_handoff_failure_evidence(
            failure_evidence_ref,
            status=failure_evidence_status,
            reason_code=reason_code,
        )
        try:
            binding = RecoveryActionBinding.model_validate(binding.model_dump(mode="python"))
        except (AttributeError, TypeError, ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Expired recovery handoff binding is not canonical",
            ) from error
        invalid_effect_kind = (
            binding.recovery_kind is RecoveryWorkKind.ROLLBACK
            and binding.risk_class is not RiskClass.REVERSIBLE
        ) or (
            binding.recovery_kind is RecoveryWorkKind.COMPENSATE
            and binding.risk_class is not RiskClass.COMPENSATABLE
        )
        if (
            binding.target_transaction_id != transaction_id
            or binding.recovery_kind
            not in {
                RecoveryWorkKind.ROLLBACK,
                RecoveryWorkKind.COMPENSATE,
                RecoveryWorkKind.RECONCILE_DISPATCH,
            }
            or binding.recovery_ordinal != 1
            or binding.root_recovery_id != binding.recovery_id
            or binding.predecessor_recovery_id is not None
            or recorded_at < binding.absolute_deadline
            or invalid_effect_kind
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Expired recovery handoff is outside its initial recovery deadline",
            )
        binding_ref = canonical_digest(binding)
        binding_json = canonical_json_text(binding)
        effect_recovery = binding.recovery_kind in {
            RecoveryWorkKind.ROLLBACK,
            RecoveryWorkKind.COMPENSATE,
        }
        source_state = TransactionState.FAILED if effect_recovery else TransactionState.IN_DOUBT
        terminal_state = (
            TransactionState.RECOVERY_FAILED if effect_recovery else TransactionState.IN_DOUBT
        )
        try:
            with self._immediate():
                transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
                dispatch = self._get_commit_dispatch_tx(tenant_id, transaction_id)
                action = self._get_normalized_action(tenant_id, transaction_id).action
                transaction_row = self._connection.execute(
                    "SELECT * FROM enforced_transactions "
                    "WHERE tenant_id = ? AND transaction_id = ?",
                    (tenant_id, transaction_id),
                ).fetchone()
                if transaction_row is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Expired recovery handoff lost its transaction projection",
                    )
                deadline_record = self._validate_transaction_recovery_deadline_tx(
                    transaction,
                    transaction_row,
                )
                if (
                    deadline_record is None
                    or deadline_record.absolute_deadline != binding.absolute_deadline
                    or transaction.updated_at > recorded_at
                    or transaction.intent_hash != binding.target_intent_hash
                    or transaction.normalized_action_digest
                    != binding.target_normalized_action_digest
                    or transaction.adapter_manifest_digest != binding.adapter_manifest_digest
                    or canonical_digest(action) != binding.target_normalized_action_digest
                    or action.risk_floor is not binding.risk_class
                    or action.effect_domains != binding.effect_domains
                    or canonical_digest(action.resource_uses) != binding.resource_uses_digest
                    or dispatch.dispatch_id != binding.target_id
                    or canonical_digest(dispatch) != binding.target_evidence_ref
                    or dispatch.permit.target_version_guard != binding.target_version_guard
                    or dispatch.permit.owner_version != binding.target_owner_version
                    or dispatch.permit.owner_history_sequence
                    != binding.target_owner_history_sequence
                    or dispatch.permit.owner_history_digest != binding.target_owner_history_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Expired recovery handoff lost its exact dispatch generation",
                        retryable=False,
                    )
                work_row = self._connection.execute(
                    "SELECT 1 FROM enforced_recovery_work "
                    "WHERE tenant_id = ? AND transaction_id = ? LIMIT 1",
                    (tenant_id, transaction_id),
                ).fetchone()
                if work_row is not None:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Expired recovery handoff cannot replace durable recovery work",
                        retryable=False,
                    )
                handoff_rows = self._connection.execute(
                    "SELECT * FROM enforced_recovery_action_handoffs "
                    "WHERE tenant_id = ? AND target_transaction_id = ? "
                    "ORDER BY recovery_id",
                    (tenant_id, transaction_id),
                ).fetchall()
                if handoff_rows:
                    if len(handoff_rows) != 1:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Expired recovery target has conflicting handoff lineages",
                        )
                    handoff = self._recovery_action_handoff_from_row(
                        handoff_rows[0],
                        tenant_id=tenant_id,
                        target_transaction_id=transaction_id,
                        recovery_id=str(handoff_rows[0]["recovery_id"]),
                    )
                    if (
                        handoff.binding != binding
                        or handoff.binding_ref != binding_ref
                        or handoff.action is not None
                        or handoff.closed_at is None
                        or handoff.failure_evidence_status is not failure_evidence_status
                        or handoff.failure_reason_code != reason_code
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Expired recovery handoff retry changed its terminal barrier",
                        )
                    self._validate_recovery_action_handoff_reverse_tx(
                        handoff,
                        tenant_id=tenant_id,
                    )
                    expected_terminal_version = expected_transaction_version + (
                        1 if effect_recovery else 0
                    )
                    transition_event: EnforcedTransactionEvent | None = None
                    if effect_recovery:
                        event_row = self._connection.execute(
                            "SELECT * FROM enforced_transaction_events WHERE tenant_id = ? "
                            "AND transaction_id = ? AND sequence = ?",
                            (tenant_id, transaction_id, transaction.version),
                        ).fetchone()
                        transition_event = (
                            None if event_row is None else self._event_from_row(event_row)
                        )
                    operation_evidence_ref = failure_evidence_ref or binding_ref
                    exact_retry = (
                        transaction.state is terminal_state
                        and transaction.version == expected_terminal_version
                        and handoff.handoff_lease_id == lease_id
                        and handoff.handoff_worker_id == worker_id
                        and handoff.created_at == recorded_at
                        and handoff.closed_at == recorded_at
                        and handoff.failure_evidence_ref == failure_evidence_ref
                        and (
                            not effect_recovery
                            or (
                                transition_event is not None
                                and transition_event.event
                                == TransitionEvent.RECOVERY_UNAVAILABLE.value
                                and transition_event.source_state is source_state
                                and transition_event.target_state is terminal_state
                                and transition_event.recorded_at == recorded_at
                                and transition_event.evidence_refs == (operation_evidence_ref,)
                                and transaction.updated_at == recorded_at
                                and transaction.reason_code == reason_code
                            )
                        )
                    )
                    if not exact_retry:
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Expired recovery handoff retry changed its settlement identity",
                            retryable=False,
                        )
                    return EnforcedTransactionResult(
                        transaction,
                        transition_event,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                if (
                    transaction.state is not source_state
                    or transaction.version != expected_transaction_version
                    or (not effect_recovery and dispatch.state is not CommitDispatchState.IN_DOUBT)
                    or (
                        effect_recovery
                        and dispatch.state is not CommitDispatchState.PARTIAL_OR_INVALID
                    )
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Expired recovery handoff lost its exact source generation",
                        retryable=False,
                    )
                lease, created = self._acquire_worker_lease_tx(
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                    lease_id=lease_id,
                    worker_id=worker_id,
                    purpose=LeasePurpose.RECOVERY,
                    acquired_at=recorded_at,
                    expires_at=(recorded_at + _EXPIRED_HANDOFF_SETTLEMENT_LEASE_DURATION),
                )
                if not created or lease.version != 0 or lease.released_at is not None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Expired recovery handoff encountered an orphan settlement lease",
                    )
                released_lease = WorkerLeaseRecord.model_validate(
                    {
                        **lease.model_dump(mode="python"),
                        "version": lease.version + 1,
                        "released_at": recorded_at,
                    }
                )
                self._update_worker_lease_tx(lease, released_lease)
                terminal_sequence = self._next_recovery_handoff_terminal_sequence_tx(
                    tenant_id,
                    recorded_at=recorded_at,
                )
                self._execute(
                    "INSERT INTO enforced_recovery_action_handoffs("
                    "tenant_id, target_transaction_id, recovery_id, recovery_kind, "
                    "target_id, target_evidence_ref, binding_ref, binding_json, "
                    "handoff_lease_id, handoff_worker_id, handoff_fencing_token, "
                    "recovery_action_transaction_id, recovery_action_intent_hash, "
                    "recovery_action_digest, created_at, attached_at, closed_at, "
                    "terminal_sequence, failure_evidence_status, failure_evidence_ref, "
                    "failure_reason_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "NULL, NULL, NULL, ?, NULL, ?, ?, ?, ?, ?)",
                    (
                        tenant_id,
                        transaction_id,
                        binding.recovery_id,
                        binding.recovery_kind.value,
                        binding.target_id,
                        binding.target_evidence_ref,
                        binding_ref,
                        binding_json,
                        released_lease.lease_id,
                        released_lease.worker_id,
                        released_lease.fencing_token,
                        _timestamp(recorded_at),
                        _timestamp(recorded_at),
                        terminal_sequence,
                        failure_evidence_status.value,
                        failure_evidence_ref,
                        reason_code,
                    ),
                )
                transition_event = None
                if effect_recovery:
                    operation_evidence_ref = failure_evidence_ref or binding_ref
                    transaction, transition_event = self._apply_transition_tx(
                        transaction,
                        expected_version=expected_transaction_version,
                        transition_event=TransitionEvent.RECOVERY_UNAVAILABLE,
                        recorded_at=recorded_at,
                        evidence_refs=(operation_evidence_ref,),
                        reason_code=reason_code,
                    )
                row = self._connection.execute(
                    "SELECT * FROM enforced_recovery_action_handoffs "
                    "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
                    (tenant_id, transaction_id, binding.recovery_id),
                ).fetchone()
                if row is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Expired recovery handoff was not durably visible",
                    )
                handoff = self._recovery_action_handoff_from_row(
                    row,
                    tenant_id=tenant_id,
                    target_transaction_id=transaction_id,
                    recovery_id=binding.recovery_id,
                )
                self._validate_recovery_action_handoff_reverse_tx(
                    handoff,
                    tenant_id=tenant_id,
                )
                return EnforcedTransactionResult(
                    transaction,
                    transition_event,
                    EnforcedStoreDisposition.STORED,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity(
                "Expired recovery handoff did not persist atomically",
                error,
            ) from error

    def fail_recovery_action_handoff(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        expected_transaction_version: int,
        recovery_id: str,
        failure_evidence_ref: str | None,
        reason_code: str,
        recorded_at: datetime,
        handoff_lease: WorkerLeaseRecord | None = None,
        failure_evidence_status: RecoveryHandoffFailureEvidenceStatus = (
            RecoveryHandoffFailureEvidenceStatus.AVAILABLE
        ),
    ) -> EnforcedTransactionResult:
        """Atomically close an open effect-bearing recovery action without effect claims."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        if not isinstance(reason_code, str) or not reason_code.strip():
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery action handoff failure requires a stable reason code",
            )
        failure_evidence_ref = _require_handoff_failure_evidence(
            failure_evidence_ref,
            status=failure_evidence_status,
            reason_code=reason_code,
        )
        try:
            with self._immediate():
                transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
                association = self._connection.execute(
                    "SELECT * FROM enforced_recovery_action_handoffs "
                    "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
                    (tenant_id, transaction_id, recovery_id),
                ).fetchone()
                if association is None:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery action handoff failure lacks a durable association",
                        retryable=False,
                    )
                handoff = self._recovery_action_handoff_from_row(
                    association,
                    tenant_id=tenant_id,
                    target_transaction_id=transaction_id,
                    recovery_id=recovery_id,
                )
                if handoff.closed_at is not None:
                    expected_source_version = (
                        transaction.version - 1
                        if transaction.state is TransactionState.RECOVERY_FAILED
                        else transaction.version
                    )
                    if expected_transaction_version != expected_source_version:
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Recovery action handoff failure retry used a stale source version",
                            retryable=False,
                        )
                    transition_event: EnforcedTransactionEvent | None = None
                    if transaction.state is TransactionState.RECOVERY_FAILED:
                        event_row = self._connection.execute(
                            "SELECT * FROM enforced_transaction_events WHERE tenant_id = ? "
                            "AND transaction_id = ? AND sequence = ?",
                            (tenant_id, transaction_id, transaction.version),
                        ).fetchone()
                        transition_event = (
                            None if event_row is None else self._event_from_row(event_row)
                        )
                    operation_evidence_ref = failure_evidence_ref or handoff.binding_ref
                    if (
                        handoff.failure_evidence_status is not failure_evidence_status
                        or handoff.failure_evidence_ref != failure_evidence_ref
                        or handoff.failure_reason_code != reason_code
                        or handoff.closed_at != recorded_at
                        or transaction.state
                        not in {TransactionState.IN_DOUBT, TransactionState.RECOVERY_FAILED}
                        or (
                            transaction.state is TransactionState.RECOVERY_FAILED
                            and (
                                transition_event is None
                                or transition_event.event
                                != TransitionEvent.RECOVERY_UNAVAILABLE.value
                                or transition_event.source_state is not TransactionState.FAILED
                                or transition_event.target_state
                                is not TransactionState.RECOVERY_FAILED
                                or transition_event.recorded_at != recorded_at
                                or transition_event.evidence_refs != (operation_evidence_ref,)
                                or transaction.reason_code != reason_code
                            )
                        )
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery action handoff failure retry changed terminal evidence",
                        )
                    return EnforcedTransactionResult(
                        transaction,
                        None,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                if (
                    transaction.version != expected_transaction_version
                    or transaction.state not in {TransactionState.FAILED, TransactionState.IN_DOUBT}
                    or recorded_at < transaction.updated_at
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery action handoff failure lost its exact target transaction",
                        retryable=False,
                    )
                binding = handoff.binding
                operation_evidence_ref = failure_evidence_ref or handoff.binding_ref
                dispatch = self._get_commit_dispatch_tx(tenant_id, transaction_id)
                if (
                    binding.recovery_id != recovery_id
                    or binding.target_transaction_id != transaction_id
                    or binding.recovery_kind
                    not in {
                        RecoveryWorkKind.ROLLBACK,
                        RecoveryWorkKind.COMPENSATE,
                        RecoveryWorkKind.RECONCILE_DISPATCH,
                    }
                    or binding.target_id != dispatch.dispatch_id
                    or binding.target_evidence_ref != canonical_digest(dispatch)
                    or handoff.binding_ref != canonical_digest(binding)
                    or str(association["target_id"]) != binding.target_id
                    or str(association["target_evidence_ref"]) != binding.target_evidence_ref
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery action handoff failure differs from its dispatch target",
                    )
                work = self._connection.execute(
                    "SELECT 1 FROM enforced_recovery_work "
                    "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ?",
                    (tenant_id, transaction_id, recovery_id),
                ).fetchone()
                if work is not None:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery action handoff already has durable work",
                        retryable=False,
                    )
                active_lease_row = self._connection.execute(
                    "SELECT * FROM enforced_worker_leases "
                    "WHERE tenant_id = ? AND transaction_id = ? AND released_at IS NULL",
                    (tenant_id, transaction_id),
                ).fetchone()
                if active_lease_row is not None:
                    active_lease = self._lease_from_row(active_lease_row)
                    exact_handoff = (
                        handoff_lease is not None
                        and active_lease == handoff_lease
                        and active_lease.purpose is LeasePurpose.RECOVERY
                    )
                    expired_handoff = (
                        handoff_lease is None
                        and active_lease.purpose is LeasePurpose.RECOVERY
                        and active_lease.expires_at <= recorded_at
                    )
                    if not exact_handoff and not expired_handoff:
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Recovery action handoff failure conflicts with a live lease",
                            retryable=False,
                        )
                    released = WorkerLeaseRecord.model_validate(
                        {
                            **active_lease.model_dump(mode="python"),
                            "version": active_lease.version + 1,
                            "released_at": recorded_at,
                        }
                    )
                    self._update_worker_lease_tx(active_lease, released)
                elif handoff_lease is not None:
                    stored_lease = self._get_worker_lease_tx(
                        handoff_lease.tenant_id,
                        handoff_lease.transaction_id,
                        handoff_lease.lease_id,
                    )
                    if stored_lease.released_at is None:
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Recovery action handoff failure lost its expected lease",
                            retryable=False,
                        )
                recovery_action = handoff.action
                if recovery_action is not None:
                    ledger = self._validate_intent_ledger(
                        tenant_id,
                        recovery_action.intent_hash,
                    )
                    if (
                        ledger.owner_transaction_id != recovery_action.transaction_id
                        or ledger.owner_state is not IntentAttemptState.ACTIVE
                    ):
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Recovery action handoff failure lost active intent ownership",
                            retryable=False,
                        )
                    self._transition_owned_attempt_tx(
                        tenant_id=tenant_id,
                        intent_hash=recovery_action.intent_hash,
                        transaction_id=recovery_action.transaction_id,
                        owner_version=ledger.owner_version,
                        owner_history_sequence=ledger.head_sequence,
                        owner_history_digest=ledger.head_digest,
                        target_state=IntentAttemptState.NO_EFFECT_CONFIRMED,
                        evidence_digest=operation_evidence_ref,
                        recorded_at=recorded_at,
                    )
                terminal_sequence = self._next_recovery_handoff_terminal_sequence_tx(
                    tenant_id,
                    recorded_at=recorded_at,
                )
                closed = self._execute(
                    "UPDATE enforced_recovery_action_handoffs SET "
                    "closed_at = ?, terminal_sequence = ?, failure_evidence_status = ?, "
                    "failure_evidence_ref = ?, failure_reason_code = ? "
                    "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ? "
                    "AND closed_at IS NULL",
                    (
                        _timestamp(recorded_at),
                        terminal_sequence,
                        failure_evidence_status.value,
                        failure_evidence_ref,
                        reason_code,
                        tenant_id,
                        transaction_id,
                        recovery_id,
                    ),
                )
                if closed.rowcount != 1:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery action handoff failure lost its terminal CAS",
                        retryable=True,
                    )
                if transaction.state is TransactionState.FAILED:
                    updated, event = self._apply_transition_tx(
                        transaction,
                        expected_version=expected_transaction_version,
                        transition_event=TransitionEvent.RECOVERY_UNAVAILABLE,
                        recorded_at=recorded_at,
                        evidence_refs=(operation_evidence_ref,),
                        reason_code=reason_code,
                    )
                    return EnforcedTransactionResult(
                        updated,
                        event,
                        EnforcedStoreDisposition.STORED,
                    )
                return EnforcedTransactionResult(
                    transaction,
                    None,
                    EnforcedStoreDisposition.STORED,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity(
                "Recovery action handoff failure did not persist",
                error,
            ) from error

    def _recovery_from_row(self, row: sqlite3.Row) -> RecoveryWorkRecord:
        raw_json = str(row["record_json"])
        try:
            raw_material = json.loads(raw_json)
            if not isinstance(raw_material, dict):
                raise TypeError("Recovery work JSON must be an object")
            work = RecoveryWorkRecord.model_validate(raw_material)
        except (json.JSONDecodeError, TypeError, ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored recovery work is invalid",
            ) from error
        legacy_without_unavailable_link = (
            "unavailable_record_digest" not in raw_material
            and work.unavailable_record_digest is None
        )
        expected_record_json = (
            canonical_json_text(raw_material)
            if legacy_without_unavailable_link
            else canonical_json_text(work)
        )
        expected_record_digest = (
            canonical_digest(raw_material)
            if legacy_without_unavailable_link
            else canonical_digest(work)
        )
        permit = work.permit
        expected: dict[str, object] = {
            "tenant_id": work.tenant_id,
            "transaction_id": work.transaction_id,
            "intent_hash": work.intent_hash,
            "recovery_id": work.recovery_id,
            "root_recovery_id": work.root_recovery_id,
            "predecessor_recovery_id": work.predecessor_recovery_id,
            "recovery_ordinal": work.recovery_ordinal,
            "max_recovery_attempts": work.max_recovery_attempts,
            "not_before": _timestamp(work.not_before),
            "recovery_action_transaction_id": work.recovery_action_transaction_id,
            "recovery_action_intent_hash": work.recovery_action_intent_hash,
            "recovery_action_digest": work.recovery_action_digest,
            "adapter_manifest_digest": work.adapter_manifest_digest,
            "kind": work.kind.value,
            "target_id": work.target_id,
            "target_owner_version": work.target_owner_version,
            "target_owner_history_sequence": work.target_owner_history_sequence,
            "target_owner_history_digest": work.target_owner_history_digest,
            "target_evidence_ref": work.target_evidence_ref,
            "target_version_guard": work.target_version_guard,
            "state": work.state.value,
            "authorization_round_id": work.authorization_round_id,
            "authorization_round_digest": work.authorization_round_digest,
            "authority_decision_digest": work.authority_decision_digest,
            "policy_decision_digest": work.policy_decision_digest,
            "policy_snapshot_digest": work.policy_snapshot_digest,
            "capability_reservation_digest": work.capability_reservation_digest,
            "reservation_version": work.reservation_version,
            "owner_version": work.owner_version,
            "owner_history_sequence": work.owner_history_sequence,
            "owner_history_digest": work.owner_history_digest,
            "approval_required": int(work.approval_required),
            "approval_id": work.approval_id,
            "approval_evidence_ref": work.approval_evidence_ref,
            "permit_ref": work.permit_ref,
            "permit_digest": None if permit is None else permit.permit_digest,
            "permit_json": None if permit is None else canonical_json_text(permit),
            "lease_id": work.lease_id,
            "worker_id": work.worker_id,
            "fencing_token": work.fencing_token,
            "deadline": _timestamp(work.deadline),
            "attempt": work.attempt,
            "version": work.version,
            "evidence_refs_json": canonical_json_text(work.evidence_refs),
            "reason_code": work.reason_code,
            "unavailable_record_digest": work.unavailable_record_digest,
            "record_digest": expected_record_digest,
            "record_json": expected_record_json,
            "created_at": _timestamp(work.created_at),
            "updated_at": _timestamp(work.updated_at),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery work projection differs from canonical content",
            )
        return work

    def _get_recovery_work_tx(
        self,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
    ) -> RecoveryWorkRecord:
        row = self._connection.execute(
            "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ?",
            (tenant_id, transaction_id, recovery_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Unknown recovery work")
        return self._recovery_from_row(row)

    def get_recovery_work(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
    ) -> RecoveryWorkRecord:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        with self._read_snapshot():
            work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
            self._validate_recovery_work_unavailable_link_tx(work)
            return work

    def list_recovery_work(
        self,
        *,
        tenant_id: str,
        transaction_id: str | None = None,
    ) -> tuple[RecoveryWorkRecord, ...]:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        with self._read_snapshot():
            if transaction_id is None:
                rows = self._connection.execute(
                    "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
                    "ORDER BY transaction_id, created_at, recovery_id",
                    (tenant_id,),
                ).fetchall()
            else:
                transaction_id = _require_identifier(
                    transaction_id,
                    field="transaction_id",
                )
                rows = self._connection.execute(
                    "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
                    "AND transaction_id = ? ORDER BY created_at, recovery_id",
                    (tenant_id, transaction_id),
                ).fetchall()
            work_items = tuple(self._recovery_from_row(row) for row in rows)
            for work in work_items:
                self._validate_recovery_work_unavailable_link_tx(work)
            return work_items

    def get_active_recovery_work(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
    ) -> tuple[RecoveryWorkRecord, ...]:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        rows = self._connection.execute(
            "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
            "AND transaction_id = ? AND state IN ('PENDING', 'RUNNING', 'RETRY_SCHEDULED') "
            "ORDER BY created_at, recovery_id",
            (tenant_id, transaction_id),
        ).fetchall()
        return tuple(self._recovery_from_row(row) for row in rows)

    def get_recovery_action_handoff(
        self,
        *,
        tenant_id: str,
        target_transaction_id: str,
        recovery_id: str,
    ) -> RecoveryActionHandoff | None:
        """Read one recovery-action association through its bounded primary-key lookup."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        target_transaction_id = _require_identifier(
            target_transaction_id,
            field="target_transaction_id",
        )
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        with self._read_snapshot():
            row = self._connection.execute(
                "SELECT * FROM enforced_recovery_action_handoffs "
                "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
                (tenant_id, target_transaction_id, recovery_id),
            ).fetchone()
            if row is None:
                return None
            handoff = self._recovery_action_handoff_from_row(
                row,
                tenant_id=tenant_id,
                target_transaction_id=target_transaction_id,
                recovery_id=recovery_id,
            )
            self._validate_recovery_action_handoff_reverse_tx(
                handoff,
                tenant_id=tenant_id,
                bounded=True,
            )
            return handoff

    def list_recovery_action_handoffs(
        self,
        *,
        tenant_id: str,
        target_transaction_id: str,
    ) -> tuple[RecoveryActionHandoff, ...]:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        target_transaction_id = _require_identifier(
            target_transaction_id,
            field="target_transaction_id",
        )
        with self._read_snapshot():
            rows = self._connection.execute(
                "SELECT * FROM enforced_recovery_action_handoffs "
                "WHERE tenant_id = ? AND target_transaction_id = ? ORDER BY recovery_id",
                (tenant_id, target_transaction_id),
            ).fetchall()
            handoffs = tuple(
                self._recovery_action_handoff_from_row(
                    row,
                    tenant_id=tenant_id,
                    target_transaction_id=target_transaction_id,
                    recovery_id=str(row["recovery_id"]),
                )
                for row in rows
            )
            for handoff in handoffs:
                self._validate_recovery_action_handoff_reverse_tx(
                    handoff,
                    tenant_id=tenant_id,
                    bounded=True,
                )
            return handoffs

    def _open_prework_history_is_eligible_tx(
        self,
        transaction: EnforcedTransactionRecord,
        handoff: RecoveryActionHandoff,
        work_items: tuple[RecoveryWorkRecord, ...],
    ) -> bool:
        """Validate the only durable histories that may precede unworked handoff work."""

        binding = handoff.binding
        if binding.recovery_kind is RecoveryWorkKind.RECONCILE_DISPATCH:
            if transaction.state is not TransactionState.IN_DOUBT:
                return False
            if binding.recovery_ordinal == 1:
                return not work_items
            if binding.predecessor_recovery_id is None or any(
                work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                or work.root_recovery_id != binding.root_recovery_id
                for work in work_items
            ):
                return False
            predecessor = next(
                (
                    work
                    for work in work_items
                    if work.recovery_id == binding.predecessor_recovery_id
                ),
                None,
            )
            if (
                predecessor is None
                or predecessor.state is not RecoveryWorkState.RETRY_SCHEDULED
                or predecessor.recovery_ordinal + 1 != binding.recovery_ordinal
                or predecessor.max_recovery_attempts != binding.max_recovery_attempts
                or predecessor.deadline != binding.absolute_deadline
                or max(
                    work_items,
                    key=lambda work: (
                        work.recovery_ordinal,
                        work.updated_at,
                        work.recovery_id,
                    ),
                )
                != predecessor
            ):
                return False
            predecessor_attempt = self._get_reconciliation_attempt_tx(
                transaction.tenant_id,
                transaction.transaction_id,
                predecessor.recovery_id,
                predecessor.attempt,
            )
            return (
                predecessor_attempt.outcome is ReconciliationOutcome.UNKNOWN
                and predecessor_attempt.next_attempt_not_before is not None
                and predecessor_attempt.next_attempt_not_before == binding.not_before
            )
        expected_target = (
            transaction.state is TransactionState.ABORTING
            and binding.recovery_kind is RecoveryWorkKind.DISCARD_STAGING
        ) or (
            transaction.state is TransactionState.FAILED
            and binding.recovery_kind in {RecoveryWorkKind.ROLLBACK, RecoveryWorkKind.COMPENSATE}
        )
        if not expected_target:
            return False
        if not work_items:
            return True
        if any(work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH for work in work_items):
            return False
        latest_reconciliation = max(
            work_items,
            key=lambda work: (
                work.recovery_ordinal,
                work.updated_at,
                work.recovery_id,
            ),
        )
        latest_attempt = self._get_reconciliation_attempt_tx(
            transaction.tenant_id,
            transaction.transaction_id,
            latest_reconciliation.recovery_id,
            latest_reconciliation.attempt,
        )
        expected_outcome = (
            ReconciliationOutcome.NO_EFFECT
            if transaction.state is TransactionState.ABORTING
            else ReconciliationOutcome.PARTIAL_OR_INVALID
        )
        return (
            latest_reconciliation.state is RecoveryWorkState.SUCCEEDED
            and latest_attempt.completed_at is not None
            and latest_attempt.outcome is expected_outcome
        )

    def _get_open_prework_handoff_tx(
        self,
        *,
        tenant_id: str,
        target_transaction_id: str,
        observed_at: datetime,
        live: bool,
    ) -> RecoveryActionHandoff | None:
        transaction = self._get_enforced_transaction_head_tx(
            tenant_id,
            target_transaction_id,
        )
        if transaction.state is TransactionState.IN_DOUBT:
            dispatch = self._get_commit_dispatch_head_tx(
                tenant_id,
                target_transaction_id,
            )
            self._validate_dispatch_unavailable_link_tx(dispatch)
        work_rows = self._connection.execute(
            "SELECT * FROM enforced_recovery_work "
            "WHERE tenant_id = ? AND transaction_id = ? "
            "ORDER BY recovery_ordinal, recovery_id",
            (tenant_id, target_transaction_id),
        ).fetchall()
        work_items = tuple(self._recovery_from_row(row) for row in work_rows)
        rows = self._connection.execute(
            "SELECT handoff.* FROM enforced_recovery_action_handoffs AS handoff "
            "WHERE handoff.tenant_id = ? AND handoff.target_transaction_id = ? "
            "AND handoff.closed_at IS NULL "
            "AND handoff.failure_evidence_status = 'NONE' "
            "AND ((handoff.recovery_action_transaction_id IS NULL "
            "AND handoff.recovery_action_intent_hash IS NULL "
            "AND handoff.recovery_action_digest IS NULL "
            "AND handoff.attached_at IS NULL) "
            "OR (handoff.recovery_action_transaction_id IS NOT NULL "
            "AND handoff.recovery_action_intent_hash IS NOT NULL "
            "AND handoff.recovery_action_digest IS NOT NULL "
            "AND handoff.attached_at IS NOT NULL "
            "AND EXISTS (SELECT 1 FROM enforced_intent_attempts AS action_attempt "
            "WHERE action_attempt.tenant_id = handoff.tenant_id "
            "AND action_attempt.intent_hash = handoff.recovery_action_intent_hash "
            "AND action_attempt.transaction_id = handoff.recovery_action_transaction_id "
            "AND action_attempt.attempt_state = 'ACTIVE'))) "
            "AND NOT EXISTS (SELECT 1 FROM enforced_recovery_work AS linked_work "
            "WHERE linked_work.tenant_id = handoff.tenant_id "
            "AND linked_work.transaction_id = handoff.target_transaction_id "
            "AND linked_work.recovery_id = handoff.recovery_id) "
            "ORDER BY handoff.created_at, handoff.recovery_id",
            (tenant_id, target_transaction_id),
        ).fetchall()
        candidates: list[RecoveryActionHandoff] = []
        for row in rows:
            handoff = self._recovery_action_handoff_from_row(
                row,
                tenant_id=tenant_id,
                target_transaction_id=target_transaction_id,
                recovery_id=str(row["recovery_id"]),
            )
            if not self._open_prework_history_is_eligible_tx(
                transaction,
                handoff,
                work_items,
            ):
                continue
            self._validate_recovery_action_handoff_reverse_tx(
                handoff,
                tenant_id=tenant_id,
                bounded=True,
            )
            lease_rows = self._connection.execute(
                "SELECT * FROM enforced_worker_leases "
                "WHERE tenant_id = ? AND transaction_id = ? AND fencing_token >= ? "
                "ORDER BY fencing_token",
                (
                    tenant_id,
                    target_transaction_id,
                    handoff.handoff_fencing_token,
                ),
            ).fetchall()
            leases = tuple(self._lease_from_row(lease_row) for lease_row in lease_rows)
            if not leases:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Open pre-work handoff lost its worker lease lineage",
                )
            original = leases[0]
            if (
                original.lease_id != handoff.handoff_lease_id
                or original.worker_id != handoff.handoff_worker_id
                or original.fencing_token != handoff.handoff_fencing_token
                or original.acquired_at != handoff.created_at
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Open pre-work handoff differs from its original worker lease",
                )
            previous: WorkerLeaseRecord | None = None
            for lease in leases:
                if (
                    lease.purpose is not LeasePurpose.RECOVERY
                    or lease.acquired_at < handoff.created_at
                    or lease.expires_at > handoff.binding.absolute_deadline
                    or (
                        previous is not None
                        and (
                            previous.released_at is None
                            or previous.released_at > lease.acquired_at
                            or previous.fencing_token >= lease.fencing_token
                        )
                    )
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Open pre-work handoff has an invalid worker lease lineage",
                    )
                previous = lease
            latest = leases[-1]
            lease_matches = (
                latest.released_at is None and latest.expires_at > observed_at
                if live
                else (latest.released_at is not None and latest.released_at <= observed_at)
                or latest.expires_at <= observed_at
            )
            if lease_matches:
                candidates.append(handoff)
        if len(candidates) > 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Transaction has multiple eligible open pre-work handoffs",
            )
        return candidates[0] if candidates else None

    def get_live_open_prework_handoff(
        self,
        *,
        tenant_id: str,
        target_transaction_id: str,
        observed_at: datetime,
    ) -> RecoveryActionHandoff | None:
        """Return one exact unworked handoff whose latest lease is still live."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        target_transaction_id = _require_identifier(
            target_transaction_id,
            field="target_transaction_id",
        )
        observed = _parse_timestamp(_timestamp(observed_at))
        with self._read_snapshot():
            return self._get_open_prework_handoff_tx(
                tenant_id=tenant_id,
                target_transaction_id=target_transaction_id,
                observed_at=observed,
                live=True,
            )

    def get_resumable_open_prework_handoff(
        self,
        *,
        tenant_id: str,
        target_transaction_id: str,
        observed_at: datetime,
    ) -> RecoveryActionHandoff | None:
        """Return one exact unworked handoff whose latest lease is released or expired."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        target_transaction_id = _require_identifier(
            target_transaction_id,
            field="target_transaction_id",
        )
        observed = _parse_timestamp(_timestamp(observed_at))
        with self._read_snapshot():
            return self._get_open_prework_handoff_tx(
                tenant_id=tenant_id,
                target_transaction_id=target_transaction_id,
                observed_at=observed,
                live=False,
            )

    def _recovery_handoff_terminal_high_watermark_tx(self, tenant_id: str) -> int:
        head = self._connection.execute(
            "SELECT terminal_sequence FROM enforced_recovery_handoff_terminal_heads "
            "WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        latest = self._connection.execute(
            "SELECT terminal_sequence FROM enforced_recovery_action_handoffs "
            "WHERE tenant_id = ? AND terminal_sequence IS NOT NULL "
            "ORDER BY terminal_sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        head_sequence = (
            0
            if head is None
            else _require_stored_integer(
                head["terminal_sequence"],
                field="recovery handoff terminal head sequence",
            )
        )
        latest_sequence = (
            0
            if latest is None
            else _require_stored_integer(
                latest["terminal_sequence"],
                field="recovery handoff latest terminal sequence",
            )
        )
        if head is not None and head_sequence < 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff terminal head sequence is invalid",
            )
        if latest is not None and latest_sequence < 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff terminal row sequence is invalid",
            )
        if head_sequence != latest_sequence:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff terminal head differs from its latest row",
            )
        return head_sequence

    def scan_terminal_recovery_handoff_evidence(
        self,
        *,
        tenant_id: str,
        cycle_high_watermark: int,
        limit: int = 256,
        cursor: RecoveryHandoffEvidenceCursor,
    ) -> RecoveryHandoffEvidencePage:
        """Page one tenant's immutable terminal sequence within a captured cycle."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        if type(limit) is not int or not 1 <= limit <= _MAX_SCAN_LIMIT:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery handoff evidence scan limit is invalid",
            )
        if (
            type(cycle_high_watermark) is not int
            or cycle_high_watermark < 0
            or cursor.tenant_id != tenant_id
            or type(cursor.terminal_sequence) is not int
            or not 0 <= cursor.terminal_sequence <= cycle_high_watermark
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery handoff evidence cycle cursor is invalid",
            )
        with self._read_snapshot():
            if cursor.terminal_sequence == cycle_high_watermark:
                return RecoveryHandoffEvidencePage(
                    (),
                    cursor,
                    cycle_high_watermark,
                )
            rows = self._connection.execute(
                "SELECT * FROM enforced_recovery_action_handoffs "
                "WHERE tenant_id = ? AND terminal_sequence > ? "
                "AND terminal_sequence <= ? "
                "ORDER BY terminal_sequence LIMIT ?",
                (
                    tenant_id,
                    cursor.terminal_sequence,
                    cycle_high_watermark,
                    limit + 1,
                ),
            ).fetchall()
            page_rows = rows[:limit]
            if not page_rows:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff evidence cycle contains a terminal sequence gap",
                )
            expected_sequence = cursor.terminal_sequence
            for row in page_rows:
                expected_sequence += 1
                if (
                    _require_stored_integer(
                        row["terminal_sequence"],
                        field="recovery handoff terminal sequence",
                    )
                    != expected_sequence
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery handoff evidence cycle is not contiguous",
                    )
            handoffs = tuple(
                self._recovery_action_handoff_from_row(
                    row,
                    tenant_id=str(row["tenant_id"]),
                    target_transaction_id=str(row["target_transaction_id"]),
                    recovery_id=str(row["recovery_id"]),
                )
                for row in page_rows
            )
            for handoff in handoffs:
                self._validate_recovery_action_handoff_reverse_tx(
                    handoff,
                    tenant_id=tenant_id,
                    bounded=True,
                )
            next_cursor = RecoveryHandoffEvidenceCursor(
                tenant_id=tenant_id,
                terminal_sequence=_require_stored_integer(
                    page_rows[-1]["terminal_sequence"],
                    field="recovery handoff terminal sequence",
                ),
            )
            if len(rows) <= limit and next_cursor.terminal_sequence != cycle_high_watermark:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff evidence cycle ended before its high-watermark",
                )
            return RecoveryHandoffEvidencePage(
                handoffs,
                next_cursor,
                cycle_high_watermark,
            )

    @staticmethod
    def _recovery_handoff_evidence_audit_checkpoint_material(
        checkpoint: RecoveryHandoffEvidenceAuditCheckpoint,
    ) -> dict[str, object]:
        return {
            "profile": "agentkernel.recovery-handoff-evidence-audit-checkpoint/v1",
            "tenant_id": checkpoint.tenant_id,
            "current_cycle": checkpoint.current_cycle,
            "current_cycle_high_watermark": checkpoint.current_cycle_high_watermark,
            "cursor_terminal_sequence": checkpoint.cursor.terminal_sequence,
            "current_cycle_failure_count": checkpoint.current_cycle_failure_count,
            "last_completed_cycle": checkpoint.last_completed_cycle,
            "last_completed_at": (
                None
                if checkpoint.last_completed_at is None
                else _timestamp(checkpoint.last_completed_at)
            ),
            "last_completed_high_watermark": checkpoint.last_completed_high_watermark,
            "last_completed_failure_count": checkpoint.last_completed_failure_count,
            "version": checkpoint.version,
            "updated_at": _timestamp(checkpoint.updated_at),
        }

    @staticmethod
    def _recovery_handoff_evidence_audit_event_material(
        *,
        tenant_id: str,
        sequence: int,
        checkpoint_digest: str,
        previous_event_digest: str | None,
        recorded_at: datetime,
    ) -> dict[str, object]:
        return {
            "profile": "agentkernel.recovery-handoff-evidence-audit-event/v1",
            "tenant_id": tenant_id,
            "sequence": sequence,
            "checkpoint_digest": checkpoint_digest,
            "previous_event_digest": previous_event_digest,
            "recorded_at": _timestamp(recorded_at),
        }

    def _recovery_handoff_evidence_audit_checkpoint_from_material(
        self,
        material: object,
    ) -> RecoveryHandoffEvidenceAuditCheckpoint:
        expected_keys = {
            "profile",
            "tenant_id",
            "current_cycle",
            "current_cycle_high_watermark",
            "cursor_terminal_sequence",
            "current_cycle_failure_count",
            "last_completed_cycle",
            "last_completed_at",
            "last_completed_high_watermark",
            "last_completed_failure_count",
            "version",
            "updated_at",
        }
        if type(material) is not dict or set(material) != expected_keys:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff evidence audit checkpoint material is malformed",
            )
        values = cast("dict[str, object]", material)
        integer_fields = (
            "current_cycle",
            "current_cycle_high_watermark",
            "cursor_terminal_sequence",
            "current_cycle_failure_count",
            "version",
        )
        optional_integer_fields = (
            "last_completed_cycle",
            "last_completed_high_watermark",
            "last_completed_failure_count",
        )
        if (
            values["profile"] != "agentkernel.recovery-handoff-evidence-audit-checkpoint/v1"
            or type(values["tenant_id"]) is not str
            or any(type(values[field]) is not int for field in integer_fields)
            or any(
                values[field] is not None and type(values[field]) is not int
                for field in optional_integer_fields
            )
            or type(values["updated_at"]) is not str
            or (
                values["last_completed_at"] is not None
                and type(values["last_completed_at"]) is not str
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff evidence audit checkpoint material has invalid types",
            )
        tenant_id = _require_identifier(
            values["tenant_id"],
            field="tenant_id",
        )
        current_cycle = cast("int", values["current_cycle"])
        high_watermark = cast("int", values["current_cycle_high_watermark"])
        cursor_sequence = cast("int", values["cursor_terminal_sequence"])
        failure_count = cast("int", values["current_cycle_failure_count"])
        last_cycle = cast("int | None", values["last_completed_cycle"])
        last_at = (
            None
            if values["last_completed_at"] is None
            else _parse_timestamp(values["last_completed_at"])
        )
        last_high_watermark = cast(
            "int | None",
            values["last_completed_high_watermark"],
        )
        last_failure_count = cast(
            "int | None",
            values["last_completed_failure_count"],
        )
        version = cast("int", values["version"])
        updated_at = _parse_timestamp(values["updated_at"])
        checkpoint = RecoveryHandoffEvidenceAuditCheckpoint(
            tenant_id=tenant_id,
            current_cycle=current_cycle,
            current_cycle_high_watermark=high_watermark,
            cursor=RecoveryHandoffEvidenceCursor(
                tenant_id=tenant_id,
                terminal_sequence=cursor_sequence,
            ),
            current_cycle_failure_count=failure_count,
            last_completed_cycle=last_cycle,
            last_completed_at=last_at,
            last_completed_high_watermark=last_high_watermark,
            last_completed_failure_count=last_failure_count,
            version=version,
            updated_at=updated_at,
        )
        completion_values = (
            last_cycle,
            last_at,
            last_high_watermark,
            last_failure_count,
        )
        if (
            current_cycle < 1
            or high_watermark < 0
            or not 0 <= cursor_sequence <= high_watermark
            or failure_count < 0
            or version < 0
            or any(value is None for value in completion_values)
            != all(value is None for value in completion_values)
            or (last_cycle is not None and not 1 <= last_cycle <= current_cycle)
            or (last_high_watermark is not None and last_high_watermark < 0)
            or (last_failure_count is not None and last_failure_count < 0)
            or (
                cursor_sequence == high_watermark
                and (
                    last_cycle != current_cycle
                    or last_at != updated_at
                    or last_high_watermark != high_watermark
                    or last_failure_count != failure_count
                )
            )
            or (
                cursor_sequence < high_watermark
                and last_cycle is not None
                and last_cycle >= current_cycle
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff evidence audit checkpoint material is inconsistent",
            )
        if material != self._recovery_handoff_evidence_audit_checkpoint_material(checkpoint):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff evidence audit checkpoint material is not canonical",
            )
        return checkpoint

    @staticmethod
    def _validate_recovery_handoff_evidence_audit_transition(
        previous: RecoveryHandoffEvidenceAuditCheckpoint | None,
        current: RecoveryHandoffEvidenceAuditCheckpoint,
    ) -> None:
        valid = False
        if previous is None:
            valid = (
                current.version == 0
                and current.current_cycle == 1
                and current.cursor.terminal_sequence == 0
                and current.current_cycle_failure_count == 0
                and (
                    (current.current_cycle_high_watermark == 0 and current.current_cycle_complete)
                    or (
                        current.current_cycle_high_watermark > 0
                        and current.last_completed_cycle is None
                        and current.last_completed_at is None
                        and current.last_completed_high_watermark is None
                        and current.last_completed_failure_count is None
                    )
                )
            )
        elif current.tenant_id == previous.tenant_id and current.version == previous.version + 1:
            if current.current_cycle == previous.current_cycle:
                cursor_delta = current.cursor.terminal_sequence - previous.cursor.terminal_sequence
                failure_delta = (
                    current.current_cycle_failure_count - previous.current_cycle_failure_count
                )
                valid = (
                    not previous.current_cycle_complete
                    and current.current_cycle_high_watermark
                    == previous.current_cycle_high_watermark
                    and 1 <= cursor_delta <= _MAX_SCAN_LIMIT
                    and 0 <= failure_delta <= cursor_delta
                    and (
                        current.current_cycle_complete
                        or (
                            current.last_completed_cycle == previous.last_completed_cycle
                            and current.last_completed_at == previous.last_completed_at
                            and current.last_completed_high_watermark
                            == previous.last_completed_high_watermark
                            and current.last_completed_failure_count
                            == previous.last_completed_failure_count
                        )
                    )
                )
            elif current.current_cycle == previous.current_cycle + 1:
                valid = (
                    previous.current_cycle_complete
                    and current.current_cycle_high_watermark
                    >= previous.current_cycle_high_watermark
                    and current.cursor.terminal_sequence == 0
                    and current.current_cycle_failure_count == 0
                    and (
                        current.current_cycle_complete
                        or (
                            current.last_completed_cycle == previous.last_completed_cycle
                            and current.last_completed_at == previous.last_completed_at
                            and current.last_completed_high_watermark
                            == previous.last_completed_high_watermark
                            and current.last_completed_failure_count
                            == previous.last_completed_failure_count
                        )
                    )
                )
        if not valid:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff evidence audit checkpoint transition is invalid",
            )

    def _recovery_handoff_evidence_audit_event_from_row(
        self,
        row: sqlite3.Row,
    ) -> RecoveryHandoffEvidenceAuditEvent:
        tenant_id = _require_identifier(str(row["tenant_id"]), field="tenant_id")
        sequence = _require_stored_integer(
            row["sequence"],
            field="recovery handoff evidence audit event sequence",
        )
        checkpoint_digest = _require_digest(
            str(row["checkpoint_digest"]),
            field="checkpoint_digest",
        )
        previous_event_digest = (
            None
            if row["previous_event_digest"] is None
            else _require_digest(
                str(row["previous_event_digest"]),
                field="previous_event_digest",
            )
        )
        recorded_at = _parse_timestamp(row["recorded_at"])
        try:
            checkpoint_material = json.loads(str(row["checkpoint_json"]))
        except (TypeError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff evidence audit event checkpoint JSON is invalid",
            ) from error
        checkpoint = self._recovery_handoff_evidence_audit_checkpoint_from_material(
            checkpoint_material
        )
        material = self._recovery_handoff_evidence_audit_event_material(
            tenant_id=tenant_id,
            sequence=sequence,
            checkpoint_digest=checkpoint_digest,
            previous_event_digest=previous_event_digest,
            recorded_at=recorded_at,
        )
        event_digest = canonical_digest(material)
        if (
            sequence < 0
            or checkpoint.tenant_id != tenant_id
            or checkpoint.version != sequence
            or canonical_digest(checkpoint_material) != checkpoint_digest
            or str(row["checkpoint_json"]) != canonical_json_text(checkpoint_material)
            or str(row["recorded_at"]) != _timestamp(recorded_at)
            or str(row["event_digest"]) != event_digest
            or str(row["event_json"]) != canonical_json_text(material)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff evidence audit event differs from canonical content",
            )
        return RecoveryHandoffEvidenceAuditEvent(
            tenant_id=tenant_id,
            sequence=sequence,
            checkpoint_digest=checkpoint_digest,
            checkpoint=checkpoint,
            previous_event_digest=previous_event_digest,
            event_digest=event_digest,
            recorded_at=recorded_at,
        )

    def _recovery_handoff_evidence_audit_from_row(
        self,
        row: sqlite3.Row,
    ) -> RecoveryHandoffEvidenceAuditCheckpoint:
        tenant_id = _require_identifier(str(row["tenant_id"]), field="tenant_id")
        current_cycle = _require_stored_integer(
            row["current_cycle"],
            field="recovery handoff evidence audit current cycle",
        )
        high_watermark = _require_stored_integer(
            row["current_cycle_high_watermark"],
            field="recovery handoff evidence audit high-watermark",
        )
        cursor_sequence = _require_stored_integer(
            row["cursor_terminal_sequence"],
            field="recovery handoff evidence audit cursor sequence",
        )
        current_failure_count = _require_stored_integer(
            row["current_cycle_failure_count"],
            field="recovery handoff evidence audit failure count",
        )
        version = _require_stored_integer(
            row["version"],
            field="recovery handoff evidence audit version",
        )
        updated_at = _parse_timestamp(row["updated_at"])
        cursor = RecoveryHandoffEvidenceCursor(
            tenant_id=tenant_id,
            terminal_sequence=cursor_sequence,
        )
        if cursor_sequence > 0:
            handoff = self._connection.execute(
                "SELECT closed_at FROM enforced_recovery_action_handoffs "
                "WHERE tenant_id = ? AND terminal_sequence = ?",
                (tenant_id, cursor_sequence),
            ).fetchone()
            if handoff is None or handoff["closed_at"] is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff evidence audit cursor lacks its terminal row",
                )
        last_cycle_value = row["last_completed_cycle"]
        last_at_value = row["last_completed_at"]
        last_high_watermark_value = row["last_completed_high_watermark"]
        last_failure_value = row["last_completed_failure_count"]
        if (
            last_cycle_value is None
            and last_at_value is None
            and last_high_watermark_value is None
            and last_failure_value is None
        ):
            last_cycle = None
            last_at = None
            last_high_watermark = None
            last_failure_count = None
        elif (
            last_cycle_value is None
            or last_at_value is None
            or last_high_watermark_value is None
            or last_failure_value is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff evidence audit completion is partial",
            )
        else:
            last_cycle = _require_stored_integer(
                last_cycle_value,
                field="recovery handoff evidence audit last completed cycle",
            )
            last_at = _parse_timestamp(last_at_value)
            last_high_watermark = _require_stored_integer(
                last_high_watermark_value,
                field="recovery handoff evidence audit last high-watermark",
            )
            last_failure_count = _require_stored_integer(
                last_failure_value,
                field="recovery handoff evidence audit last failure count",
            )
        if (
            current_cycle < 1
            or high_watermark < 0
            or not 0 <= cursor_sequence <= high_watermark
            or current_failure_count < 0
            or version < 0
            or (last_cycle is not None and not 1 <= last_cycle <= current_cycle)
            or (last_high_watermark is not None and last_high_watermark < 0)
            or (last_failure_count is not None and last_failure_count < 0)
            or (
                cursor_sequence == high_watermark
                and (
                    last_cycle != current_cycle
                    or last_high_watermark != high_watermark
                    or last_failure_count != current_failure_count
                )
            )
            or (
                cursor_sequence < high_watermark
                and last_cycle is not None
                and last_cycle >= current_cycle
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff evidence audit checkpoint is invalid",
            )
        checkpoint = RecoveryHandoffEvidenceAuditCheckpoint(
            tenant_id=tenant_id,
            current_cycle=current_cycle,
            current_cycle_high_watermark=high_watermark,
            cursor=cursor,
            current_cycle_failure_count=current_failure_count,
            last_completed_cycle=last_cycle,
            last_completed_at=last_at,
            last_completed_high_watermark=last_high_watermark,
            last_completed_failure_count=last_failure_count,
            version=version,
            updated_at=updated_at,
        )
        material = self._recovery_handoff_evidence_audit_checkpoint_material(checkpoint)
        checkpoint_digest = canonical_digest(material)
        event_head_sequence = _require_stored_integer(
            row["event_head_sequence"],
            field="recovery handoff evidence audit event head sequence",
        )
        event_head_digest = str(row["event_head_digest"])
        if (
            str(row["record_digest"]) != checkpoint_digest
            or str(row["record_json"]) != canonical_json_text(material)
            or str(row["updated_at"]) != _timestamp(updated_at)
            or (last_at is not None and str(row["last_completed_at"]) != _timestamp(last_at))
            or event_head_sequence != version
            or high_watermark > self._recovery_handoff_terminal_high_watermark_tx(tenant_id)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff evidence audit projection differs from canonical content",
            )
        event_row = self._connection.execute(
            "SELECT * FROM enforced_recovery_handoff_evidence_audit_events "
            "WHERE tenant_id = ? AND sequence = ?",
            (tenant_id, version),
        ).fetchone()
        tail_row = self._connection.execute(
            "SELECT sequence, event_digest "
            "FROM enforced_recovery_handoff_evidence_audit_events "
            "WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        if (
            event_row is None
            or tail_row is None
            or _require_stored_integer(
                tail_row["sequence"],
                field="recovery handoff evidence audit tail sequence",
            )
            != version
            or str(tail_row["event_digest"]) != event_head_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff evidence audit lost or exceeded its head event",
            )
        event = self._recovery_handoff_evidence_audit_event_from_row(event_row)
        if (
            event.checkpoint_digest != checkpoint_digest
            or event.checkpoint != checkpoint
            or event.event_digest != event_head_digest
            or event.recorded_at != updated_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff evidence audit head differs from its checkpoint",
            )
        if version == 0:
            if event.previous_event_digest is not None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff evidence audit genesis has a predecessor",
                )
            self._validate_recovery_handoff_evidence_audit_transition(
                None,
                event.checkpoint,
            )
        else:
            predecessor_row = self._connection.execute(
                "SELECT * FROM enforced_recovery_handoff_evidence_audit_events "
                "WHERE tenant_id = ? AND sequence = ?",
                (tenant_id, version - 1),
            ).fetchone()
            if predecessor_row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff evidence audit head lost its predecessor",
                )
            predecessor = self._recovery_handoff_evidence_audit_event_from_row(predecessor_row)
            if event.previous_event_digest != predecessor.event_digest:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff evidence audit head chain is inconsistent",
                )
            self._validate_recovery_handoff_evidence_audit_transition(
                predecessor.checkpoint,
                event.checkpoint,
            )
        return checkpoint

    def get_recovery_handoff_evidence_audit_checkpoint(
        self,
        tenant_id: str,
    ) -> RecoveryHandoffEvidenceAuditCheckpoint | None:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        with self._read_snapshot():
            row = self._connection.execute(
                "SELECT * FROM enforced_recovery_handoff_evidence_audits WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            if row is None:
                self._recovery_handoff_terminal_high_watermark_tx(tenant_id)
                return None
            return self._recovery_handoff_evidence_audit_from_row(row)

    def _persist_recovery_handoff_evidence_audit_checkpoint_tx(
        self,
        *,
        current: RecoveryHandoffEvidenceAuditCheckpoint | None,
        checkpoint: RecoveryHandoffEvidenceAuditCheckpoint,
    ) -> RecoveryHandoffEvidenceAuditCheckpoint:
        material = self._recovery_handoff_evidence_audit_checkpoint_material(checkpoint)
        checkpoint_digest = canonical_digest(material)
        previous_event_digest: str | None = None
        if current is not None:
            previous_row = self._connection.execute(
                "SELECT * FROM enforced_recovery_handoff_evidence_audit_events "
                "WHERE tenant_id = ? AND sequence = ?",
                (current.tenant_id, current.version),
            ).fetchone()
            if previous_row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff evidence audit lost its previous head",
                )
            previous_event_digest = self._recovery_handoff_evidence_audit_event_from_row(
                previous_row
            ).event_digest
        event_material = self._recovery_handoff_evidence_audit_event_material(
            tenant_id=checkpoint.tenant_id,
            sequence=checkpoint.version,
            checkpoint_digest=checkpoint_digest,
            previous_event_digest=previous_event_digest,
            recorded_at=checkpoint.updated_at,
        )
        event_digest = canonical_digest(event_material)
        values = (
            checkpoint.current_cycle,
            checkpoint.current_cycle_high_watermark,
            checkpoint.cursor.terminal_sequence,
            checkpoint.current_cycle_failure_count,
            checkpoint.last_completed_cycle,
            (
                None
                if checkpoint.last_completed_at is None
                else _timestamp(checkpoint.last_completed_at)
            ),
            checkpoint.last_completed_high_watermark,
            checkpoint.last_completed_failure_count,
            checkpoint.version,
            checkpoint.version,
            event_digest,
            checkpoint_digest,
            canonical_json_text(material),
            _timestamp(checkpoint.updated_at),
        )
        if current is None:
            self._execute(
                "INSERT INTO enforced_recovery_handoff_evidence_audits("
                "tenant_id, current_cycle, current_cycle_high_watermark, "
                "cursor_terminal_sequence, current_cycle_failure_count, "
                "last_completed_cycle, last_completed_at, "
                "last_completed_high_watermark, last_completed_failure_count, "
                "version, event_head_sequence, event_head_digest, record_digest, "
                "record_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (checkpoint.tenant_id, *values),
            )
        else:
            cursor = self._execute(
                "UPDATE enforced_recovery_handoff_evidence_audits SET "
                "current_cycle = ?, current_cycle_high_watermark = ?, "
                "cursor_terminal_sequence = ?, current_cycle_failure_count = ?, "
                "last_completed_cycle = ?, last_completed_at = ?, "
                "last_completed_high_watermark = ?, last_completed_failure_count = ?, "
                "version = ?, event_head_sequence = ?, event_head_digest = ?, "
                "record_digest = ?, record_json = ?, updated_at = ? "
                "WHERE tenant_id = ? AND version = ?",
                (*values, checkpoint.tenant_id, current.version),
            )
            if cursor.rowcount != 1:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Recovery handoff evidence audit lost its checkpoint CAS",
                    retryable=True,
                )
        self._execute(
            "INSERT INTO enforced_recovery_handoff_evidence_audit_events("
            "tenant_id, sequence, checkpoint_digest, checkpoint_json, "
            "previous_event_digest, event_digest, event_json, recorded_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                checkpoint.tenant_id,
                checkpoint.version,
                checkpoint_digest,
                canonical_json_text(material),
                previous_event_digest,
                event_digest,
                canonical_json_text(event_material),
                _timestamp(checkpoint.updated_at),
            ),
        )
        return checkpoint

    def start_recovery_handoff_evidence_audit_cycle(
        self,
        *,
        tenant_id: str,
        expected: RecoveryHandoffEvidenceAuditCheckpoint | None,
        recorded_at: datetime,
        reaudit_interval: timedelta,
        force: bool = False,
    ) -> RecoveryHandoffEvidenceAuditCheckpoint:
        """Atomically name a cycle and capture its tenant-local terminal high-watermark."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        if type(force) is not bool:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery handoff evidence audit force flag is invalid",
            )
        if (
            not isinstance(reaudit_interval, timedelta)
            or reaudit_interval <= timedelta(0)
            or reaudit_interval > timedelta(days=1)
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery handoff evidence reaudit interval is invalid",
            )
        with self._read_snapshot():
            preflight_row = self._connection.execute(
                "SELECT * FROM enforced_recovery_handoff_evidence_audits WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            preflight = (
                None
                if preflight_row is None
                else self._recovery_handoff_evidence_audit_from_row(preflight_row)
            )
            if preflight != expected:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Recovery handoff evidence audit checkpoint changed",
                    retryable=True,
                )
            preflight_high_watermark = self._recovery_handoff_terminal_high_watermark_tx(tenant_id)
            preflight_due = (
                preflight is None
                or force
                or preflight_high_watermark > preflight.current_cycle_high_watermark
                or (
                    preflight.last_completed_at is not None
                    and recorded_at >= preflight.last_completed_at + reaudit_interval
                )
            )
            if not preflight_due:
                return cast(
                    "RecoveryHandoffEvidenceAuditCheckpoint",
                    preflight,
                )
        try:
            with self._immediate():
                row = self._connection.execute(
                    "SELECT * FROM enforced_recovery_handoff_evidence_audits WHERE tenant_id = ?",
                    (tenant_id,),
                ).fetchone()
                current = (
                    None if row is None else self._recovery_handoff_evidence_audit_from_row(row)
                )
                if current != expected:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery handoff evidence audit checkpoint changed",
                        retryable=True,
                    )
                if current is not None and not current.current_cycle_complete:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery handoff evidence audit cycle is still in progress",
                        retryable=True,
                    )
                high_watermark = self._recovery_handoff_terminal_high_watermark_tx(tenant_id)
                if (
                    current is not None
                    and not force
                    and high_watermark == current.current_cycle_high_watermark
                    and current.last_completed_at is not None
                    and recorded_at < current.last_completed_at + reaudit_interval
                ):
                    return current
                current_cycle = 1 if current is None else current.current_cycle + 1
                completed = high_watermark == 0
                checkpoint = RecoveryHandoffEvidenceAuditCheckpoint(
                    tenant_id=tenant_id,
                    current_cycle=current_cycle,
                    current_cycle_high_watermark=high_watermark,
                    cursor=RecoveryHandoffEvidenceCursor(
                        tenant_id=tenant_id,
                        terminal_sequence=0,
                    ),
                    current_cycle_failure_count=0,
                    last_completed_cycle=(
                        current_cycle
                        if completed
                        else None
                        if current is None
                        else current.last_completed_cycle
                    ),
                    last_completed_at=(
                        recorded_at
                        if completed
                        else None
                        if current is None
                        else current.last_completed_at
                    ),
                    last_completed_high_watermark=(
                        high_watermark
                        if completed
                        else None
                        if current is None
                        else current.last_completed_high_watermark
                    ),
                    last_completed_failure_count=(
                        0
                        if completed
                        else None
                        if current is None
                        else current.last_completed_failure_count
                    ),
                    version=0 if current is None else current.version + 1,
                    updated_at=recorded_at,
                )
                return self._persist_recovery_handoff_evidence_audit_checkpoint_tx(
                    current=current,
                    checkpoint=checkpoint,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity(
                "Recovery handoff evidence audit cycle did not persist",
                error,
            ) from error

    def advance_recovery_handoff_evidence_audit(
        self,
        *,
        tenant_id: str,
        expected: RecoveryHandoffEvidenceAuditCheckpoint,
        next_cursor: RecoveryHandoffEvidenceCursor,
        page_failure_count: int,
        completed: bool,
        recorded_at: datetime,
    ) -> RecoveryHandoffEvidenceAuditCheckpoint:
        """CAS-advance one checked evidence page, including pages with reported failures."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        if (
            type(page_failure_count) is not int
            or page_failure_count < 0
            or type(completed) is not bool
            or type(expected.cursor.terminal_sequence) is not int
            or type(next_cursor.terminal_sequence) is not int
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery handoff evidence page advance types are invalid",
            )
        cursor_delta = next_cursor.terminal_sequence - expected.cursor.terminal_sequence
        if (
            next_cursor.tenant_id != tenant_id
            or expected.tenant_id != tenant_id
            or expected.current_cycle_complete
            or not 1 <= cursor_delta <= _MAX_SCAN_LIMIT
            or next_cursor.terminal_sequence > expected.current_cycle_high_watermark
            or completed != (next_cursor.terminal_sequence == expected.current_cycle_high_watermark)
            or page_failure_count > cursor_delta
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery handoff evidence page advance is invalid",
            )
        try:
            with self._immediate():
                row = self._connection.execute(
                    "SELECT * FROM enforced_recovery_handoff_evidence_audits WHERE tenant_id = ?",
                    (tenant_id,),
                ).fetchone()
                current = (
                    None if row is None else self._recovery_handoff_evidence_audit_from_row(row)
                )
                if current != expected:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery handoff evidence audit checkpoint changed",
                        retryable=True,
                    )
                if current is None:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery handoff evidence audit cycle disappeared",
                        retryable=True,
                    )
                sequence_span = self._connection.execute(
                    "SELECT COUNT(*) AS item_count, MIN(terminal_sequence) AS first_sequence, "
                    "MAX(terminal_sequence) AS last_sequence "
                    "FROM enforced_recovery_action_handoffs "
                    "WHERE tenant_id = ? AND terminal_sequence > ? "
                    "AND terminal_sequence <= ?",
                    (
                        tenant_id,
                        current.cursor.terminal_sequence,
                        next_cursor.terminal_sequence,
                    ),
                ).fetchone()
                if (
                    sequence_span is None
                    or _require_stored_integer(
                        sequence_span["item_count"],
                        field="recovery handoff evidence page item count",
                    )
                    != cursor_delta
                    or _require_stored_integer(
                        sequence_span["first_sequence"],
                        field="recovery handoff evidence page first sequence",
                    )
                    != current.cursor.terminal_sequence + 1
                    or _require_stored_integer(
                        sequence_span["last_sequence"],
                        field="recovery handoff evidence page last sequence",
                    )
                    != next_cursor.terminal_sequence
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery handoff evidence page contains a terminal sequence gap",
                    )
                current_failure_count = current.current_cycle_failure_count + page_failure_count
                last_completed_cycle = (
                    current.current_cycle if completed else current.last_completed_cycle
                )
                last_completed_at = recorded_at if completed else current.last_completed_at
                last_completed_high_watermark = (
                    current.current_cycle_high_watermark
                    if completed
                    else current.last_completed_high_watermark
                )
                last_completed_failure_count = (
                    current_failure_count if completed else current.last_completed_failure_count
                )
                checkpoint = RecoveryHandoffEvidenceAuditCheckpoint(
                    tenant_id=tenant_id,
                    current_cycle=current.current_cycle,
                    current_cycle_high_watermark=current.current_cycle_high_watermark,
                    cursor=next_cursor,
                    current_cycle_failure_count=current_failure_count,
                    last_completed_cycle=last_completed_cycle,
                    last_completed_at=last_completed_at,
                    last_completed_high_watermark=last_completed_high_watermark,
                    last_completed_failure_count=last_completed_failure_count,
                    version=current.version + 1,
                    updated_at=recorded_at,
                )
                return self._persist_recovery_handoff_evidence_audit_checkpoint_tx(
                    current=current,
                    checkpoint=checkpoint,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity(
                "Recovery handoff evidence audit checkpoint did not persist",
                error,
            ) from error

    def validate_recovery_handoff_evidence_audit_history(
        self,
        *,
        tenant_id: str,
        page_size: int = 256,
    ) -> RecoveryHandoffEvidenceAuditCheckpoint | None:
        """Explicitly validate a complete audit chain; never used by bounded hot paths."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        if type(page_size) is not int or not 1 <= page_size <= _MAX_SCAN_LIMIT:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery handoff evidence audit history page size is invalid",
            )
        with self._read_snapshot():
            row = self._connection.execute(
                "SELECT * FROM enforced_recovery_handoff_evidence_audits WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            if row is None:
                self._recovery_handoff_terminal_high_watermark_tx(tenant_id)
                return None
            checkpoint = self._recovery_handoff_evidence_audit_from_row(row)
            bounds = self._connection.execute(
                "SELECT COUNT(*) AS event_count, MIN(sequence) AS first_sequence, "
                "MAX(sequence) AS last_sequence "
                "FROM enforced_recovery_handoff_evidence_audit_events "
                "WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            if (
                bounds is None
                or _require_stored_integer(
                    bounds["event_count"],
                    field="recovery handoff evidence audit event count",
                )
                != checkpoint.version + 1
                or _require_stored_integer(
                    bounds["first_sequence"],
                    field="recovery handoff evidence audit first event sequence",
                )
                != 0
                or _require_stored_integer(
                    bounds["last_sequence"],
                    field="recovery handoff evidence audit last event sequence",
                )
                != checkpoint.version
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff evidence audit history exceeds or misses its head",
                )
            expected_sequence = 0
            previous_digest: str | None = None
            previous_checkpoint: RecoveryHandoffEvidenceAuditCheckpoint | None = None
            while expected_sequence <= checkpoint.version:
                rows = self._connection.execute(
                    "SELECT * FROM enforced_recovery_handoff_evidence_audit_events "
                    "WHERE tenant_id = ? AND sequence >= ? AND sequence <= ? "
                    "ORDER BY sequence LIMIT ?",
                    (
                        tenant_id,
                        expected_sequence,
                        checkpoint.version,
                        page_size,
                    ),
                ).fetchall()
                if not rows:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery handoff evidence audit history contains a gap",
                    )
                for event_row in rows:
                    event = self._recovery_handoff_evidence_audit_event_from_row(event_row)
                    if (
                        event.sequence != expected_sequence
                        or event.previous_event_digest != previous_digest
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery handoff evidence audit history is not contiguous",
                        )
                    self._validate_recovery_handoff_evidence_audit_transition(
                        previous_checkpoint,
                        event.checkpoint,
                    )
                    expected_sequence += 1
                    previous_digest = event.event_digest
                    previous_checkpoint = event.checkpoint
            if previous_digest != str(row["event_head_digest"]):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff evidence audit history differs from its head",
                )
            return checkpoint

    @staticmethod
    def _same_recovery_authorization_identity(
        stored: RecoveryWorkRecord,
        proposed: RecoveryWorkRecord,
    ) -> bool:
        fields = (
            "tenant_id",
            "transaction_id",
            "intent_hash",
            "recovery_id",
            "root_recovery_id",
            "predecessor_recovery_id",
            "recovery_ordinal",
            "max_recovery_attempts",
            "not_before",
            "recovery_action_transaction_id",
            "recovery_action_intent_hash",
            "recovery_action_digest",
            "adapter_manifest_digest",
            "kind",
            "target_id",
            "target_owner_version",
            "target_owner_history_sequence",
            "target_owner_history_digest",
            "target_evidence_ref",
            "target_version_guard",
            "authorization_round_id",
            "authorization_round_digest",
            "authority_decision_digest",
            "policy_decision_digest",
            "policy_snapshot_digest",
            "owner_version",
            "owner_history_sequence",
            "owner_history_digest",
            "approval_required",
            "approval_id",
            "approval_evidence_ref",
            "deadline",
            "created_at",
        )
        return all(getattr(stored, field) == getattr(proposed, field) for field in fields)

    def _authorized_recovery_work_digest_tx(
        self,
        work: RecoveryWorkRecord,
    ) -> str:
        """Reconstruct the exact eligible work generation persisted at authorization."""

        authorization_round = self._get_authorization_round_tx(
            work.tenant_id,
            work.transaction_id,
            work.authorization_round_id,
        )
        handoff = self._assert_recovery_work_handoff_tx(work)
        if (
            authorization_round.verdict is not AuthorizationVerdict.ELIGIBLE
            or work.created_at != authorization_round.evaluated_at
            or authorization_round.capability_reservation_digest is None
            or authorization_round.reservation_version is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery successor lost its exact eligible authorization generation",
            )
        authorized_material = work.model_dump(mode="python")
        for lease_field in ("lease_id", "worker_id", "fencing_token"):
            authorized_material.pop(lease_field)
        authorized = RecoveryWorkRecord.model_validate(
            {
                **authorized_material,
                "state": RecoveryWorkState.PENDING,
                "capability_reservation_digest": (
                    authorization_round.capability_reservation_digest
                ),
                "reservation_version": authorization_round.reservation_version,
                "permit": None,
                "permit_ref": None,
                "attempt": 0,
                "version": 0,
                "evidence_refs": (handoff.binding_ref,),
                "reason_code": None,
                "unavailable_record_digest": None,
                "updated_at": authorization_round.evaluated_at,
            }
        )
        self._assert_recovery_round_bindings(authorized, authorization_round)
        return canonical_digest(authorized)

    def _assert_authorized_handoff_lease_settlement_tx(
        self,
        work: RecoveryWorkRecord,
        handoff: RecoveryActionHandoff,
    ) -> WorkerLeaseRecord:
        """Validate the complete handoff fence lineage consumed by authorization."""

        authorization_round = self._get_authorization_round_tx(
            work.tenant_id,
            work.transaction_id,
            work.authorization_round_id,
        )
        rows = self._connection.execute(
            "SELECT * FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND fencing_token >= ? ORDER BY fencing_token",
            (
                work.tenant_id,
                work.transaction_id,
                handoff.handoff_fencing_token,
            ),
        ).fetchall()
        leases = tuple(self._lease_from_row(row) for row in rows)
        if not leases:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery authorization lost its handoff lease lineage",
            )
        original = leases[0]
        if (
            original.lease_id != handoff.handoff_lease_id
            or original.worker_id != handoff.handoff_worker_id
            or original.fencing_token != handoff.handoff_fencing_token
            or original.purpose is not LeasePurpose.RECOVERY
            or original.acquired_at != handoff.created_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery authorization lost its original handoff lease identity",
            )
        previous: WorkerLeaseRecord | None = None
        consumed: WorkerLeaseRecord | None = None
        for lease in leases:
            if (
                lease.purpose is not LeasePurpose.RECOVERY
                or lease.version != 1
                or lease.released_at is None
                or lease.expires_at > handoff.binding.absolute_deadline
                or lease.acquired_at > authorization_round.evaluated_at
                or lease.released_at > authorization_round.evaluated_at
                or (
                    previous is not None
                    and (
                        previous.released_at is None
                        or previous.released_at > lease.acquired_at
                        or previous.fencing_token >= lease.fencing_token
                    )
                )
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery authorization handoff lease lineage is invalid",
                )
            previous = lease
            if (
                lease.released_at == authorization_round.evaluated_at
                and lease.acquired_at <= authorization_round.evaluated_at
                and authorization_round.evaluated_at < lease.expires_at
            ):
                consumed = lease
                break
        if consumed is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery authorization lost its consumed handoff lease settlement",
            )
        return consumed

    def _insert_recovery_work_tx(self, work: RecoveryWorkRecord) -> None:
        columns = (
            "tenant_id",
            "transaction_id",
            "intent_hash",
            "recovery_id",
            "root_recovery_id",
            "predecessor_recovery_id",
            "recovery_ordinal",
            "max_recovery_attempts",
            "not_before",
            "recovery_action_transaction_id",
            "recovery_action_intent_hash",
            "recovery_action_digest",
            "adapter_manifest_digest",
            "kind",
            "target_id",
            "target_owner_version",
            "target_owner_history_sequence",
            "target_owner_history_digest",
            "target_evidence_ref",
            "target_version_guard",
            "state",
            "authorization_round_id",
            "authorization_round_digest",
            "authority_decision_digest",
            "policy_decision_digest",
            "policy_snapshot_digest",
            "capability_reservation_digest",
            "reservation_version",
            "owner_version",
            "owner_history_sequence",
            "owner_history_digest",
            "approval_required",
            "approval_id",
            "approval_evidence_ref",
            "permit_ref",
            "permit_digest",
            "permit_json",
            "lease_id",
            "worker_id",
            "fencing_token",
            "deadline",
            "attempt",
            "version",
            "evidence_refs_json",
            "reason_code",
            "unavailable_record_digest",
            "record_digest",
            "record_json",
            "created_at",
            "updated_at",
        )
        permit = work.permit
        values: tuple[object, ...] = (
            work.tenant_id,
            work.transaction_id,
            work.intent_hash,
            work.recovery_id,
            work.root_recovery_id,
            work.predecessor_recovery_id,
            work.recovery_ordinal,
            work.max_recovery_attempts,
            _timestamp(work.not_before),
            work.recovery_action_transaction_id,
            work.recovery_action_intent_hash,
            work.recovery_action_digest,
            work.adapter_manifest_digest,
            work.kind.value,
            work.target_id,
            work.target_owner_version,
            work.target_owner_history_sequence,
            work.target_owner_history_digest,
            work.target_evidence_ref,
            work.target_version_guard,
            work.state.value,
            work.authorization_round_id,
            work.authorization_round_digest,
            work.authority_decision_digest,
            work.policy_decision_digest,
            work.policy_snapshot_digest,
            work.capability_reservation_digest,
            work.reservation_version,
            work.owner_version,
            work.owner_history_sequence,
            work.owner_history_digest,
            int(work.approval_required),
            work.approval_id,
            work.approval_evidence_ref,
            work.permit_ref,
            None if permit is None else permit.permit_digest,
            None if permit is None else canonical_json_text(permit),
            work.lease_id,
            work.worker_id,
            work.fencing_token,
            _timestamp(work.deadline),
            work.attempt,
            work.version,
            canonical_json_text(work.evidence_refs),
            work.reason_code,
            work.unavailable_record_digest,
            canonical_digest(work),
            canonical_json_text(work),
            _timestamp(work.created_at),
            _timestamp(work.updated_at),
        )
        placeholders = ", ".join("?" for _ in columns)
        statement = (
            f"INSERT INTO enforced_recovery_work({', '.join(columns)}) "  # noqa: S608  # nosec B608
            f"VALUES ({placeholders})"
        )
        self._execute(statement, values)

    def _update_recovery_work_tx(
        self,
        current: RecoveryWorkRecord,
        updated: RecoveryWorkRecord,
    ) -> RecoveryWorkRecord:
        permit = updated.permit
        cursor = self._execute(
            "UPDATE enforced_recovery_work SET state = ?, "
            "capability_reservation_digest = ?, reservation_version = ?, permit_ref = ?, "
            "permit_digest = ?, permit_json = ?, lease_id = ?, worker_id = ?, "
            "fencing_token = ?, attempt = ?, version = ?, evidence_refs_json = ?, "
            "reason_code = ?, unavailable_record_digest = ?, record_digest = ?, "
            "record_json = ?, updated_at = ? "
            "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
            "AND state = ? AND version = ?",
            (
                updated.state.value,
                updated.capability_reservation_digest,
                updated.reservation_version,
                updated.permit_ref,
                None if permit is None else permit.permit_digest,
                None if permit is None else canonical_json_text(permit),
                updated.lease_id,
                updated.worker_id,
                updated.fencing_token,
                updated.attempt,
                updated.version,
                canonical_json_text(updated.evidence_refs),
                updated.reason_code,
                updated.unavailable_record_digest,
                canonical_digest(updated),
                canonical_json_text(updated),
                _timestamp(updated.updated_at),
                current.tenant_id,
                current.transaction_id,
                current.recovery_id,
                current.state.value,
                current.version,
            ),
        )
        if cursor.rowcount != 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Recovery work compare-and-swap failed",
                retryable=True,
            )
        return updated

    def _assert_recovery_subject_owner_tx(self, work: RecoveryWorkRecord) -> None:
        enforced_subject = self._connection.execute(
            "SELECT 1 FROM enforced_transactions WHERE tenant_id = ? AND transaction_id = ?",
            (work.tenant_id, work.recovery_action_transaction_id),
        ).fetchone()
        if enforced_subject is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery subject lifecycle must use its durable intent history only",
            )
        subject = self._get_normalized_action(
            work.tenant_id,
            work.recovery_action_transaction_id,
        )
        if (
            subject.action.intent_hash != work.recovery_action_intent_hash
            or subject.action_digest != work.recovery_action_digest
            or subject.action.adapter_manifest_digest != work.adapter_manifest_digest
            or subject.action.deadline < work.deadline
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery action differs from its durable work binding",
            )
        ledger = self._validate_intent_ledger(
            work.tenant_id,
            work.recovery_action_intent_hash,
        )
        if (
            ledger.owner_transaction_id != work.recovery_action_transaction_id
            or ledger.owner_version != work.owner_version
            or ledger.head_sequence != work.owner_history_sequence
            or ledger.head_digest != work.owner_history_digest
        ):
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Recovery action no longer owns its normalized intent",
                retryable=False,
            )

    def _assert_recovery_target_owner_tx(self, work: RecoveryWorkRecord) -> None:
        ledger = self._validate_intent_ledger(work.tenant_id, work.intent_hash)
        owner_matches = (
            ledger.owner_transaction_id == work.transaction_id
            and ledger.owner_version == work.target_owner_version
        )
        if work.kind is RecoveryWorkKind.DISCARD_STAGING:
            history_matches = (
                ledger.head_sequence == work.target_owner_history_sequence
                and ledger.head_digest == work.target_owner_history_digest
            )
        else:
            history_matches = (
                work.target_owner_history_sequence < len(ledger.entries)
                and (entry := ledger.entries[work.target_owner_history_sequence]).history_digest
                == work.target_owner_history_digest
                and entry.owner_transaction_id == work.transaction_id
                and entry.owner_version == work.target_owner_version
            )
        if not owner_matches or not history_matches:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Recovery target ownership changed after authorization",
                retryable=False,
            )

    def _assert_recovery_target_tx(
        self,
        work: RecoveryWorkRecord,
        *,
        require_authorizable_state: bool,
    ) -> tuple[
        EnforcedTransactionRecord,
        StageMaterialRecord | None,
        CommitDispatchRecord | None,
    ]:
        transaction = self._get_enforced_transaction_tx(
            work.tenant_id,
            work.transaction_id,
        )
        target_action = self._get_normalized_action(
            work.tenant_id,
            work.transaction_id,
        ).action
        if (
            transaction.intent_hash != work.intent_hash
            or transaction.adapter_manifest_digest != work.adapter_manifest_digest
            or target_action.adapter_manifest_digest != work.adapter_manifest_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery work intent or adapter differs from the controlled transaction",
            )
        self._assert_recovery_target_owner_tx(work)
        stage: StageMaterialRecord | None = None
        dispatch: CommitDispatchRecord | None = None
        if work.kind is RecoveryWorkKind.DISCARD_STAGING:
            stage = self._get_stage_material_tx(work.tenant_id, work.transaction_id)
            if (
                stage.stage_id != work.target_id
                or canonical_digest(stage) != work.target_evidence_ref
                or stage.target_version_guard != work.target_version_guard
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Recovery work no longer matches the private stage generation",
                    retryable=False,
                )
            if require_authorizable_state and (
                transaction.state is not TransactionState.ABORTING
                or stage.state in {StageMaterialState.DISCARDED, StageMaterialState.DISCARD_FAILED}
            ):
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Stage discard recovery requires exact ABORTING material",
                )
        else:
            dispatch = self._get_commit_dispatch_tx(work.tenant_id, work.transaction_id)
            if (
                dispatch.dispatch_id != work.target_id
                or dispatch.intent_hash != work.intent_hash
                or dispatch.owner_version != work.target_owner_version
                or canonical_digest(dispatch) != work.target_evidence_ref
                or dispatch.permit.target_version_guard != work.target_version_guard
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Recovery work no longer matches the dispatch generation",
                    retryable=False,
                )
            if require_authorizable_state:
                if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                    valid = (
                        transaction.state is TransactionState.IN_DOUBT
                        and dispatch.state is CommitDispatchState.IN_DOUBT
                    )
                else:
                    valid = (
                        transaction.state is TransactionState.FAILED
                        and dispatch.state is CommitDispatchState.PARTIAL_OR_INVALID
                    )
                if not valid:
                    raise AgentKernelError(
                        ErrorCode.ILLEGAL_TRANSITION,
                        "Recovery kind does not match the durable target state",
                    )
        return transaction, stage, dispatch

    @staticmethod
    def _assert_recovery_round_bindings(
        work: RecoveryWorkRecord,
        record: AuthorizationRoundRecord,
    ) -> None:
        reservation_matches_round = (
            work.capability_reservation_digest == record.capability_reservation_digest
            and work.reservation_version == record.reservation_version
        )
        reservation_was_committed = (
            work.permit is not None
            and record.capability_reservation_digest is not None
            and record.reservation_version is not None
            and work.capability_reservation_digest == work.permit.capability_reservation_digest
            and work.reservation_version == record.reservation_version + 1
        )
        if (
            record.purpose is not AuthorizationRoundPurpose.RECOVERY
            or record.controlled_transaction_id != work.transaction_id
            or record.subject_transaction_id != work.recovery_action_transaction_id
            or record.subject_intent_hash != work.recovery_action_intent_hash
            or record.subject_normalized_action_digest != work.recovery_action_digest
            or work.authorization_round_id != record.round_id
            or work.authorization_round_digest != record.round_digest
            or work.authority_decision_digest != record.authority_decision_digest
            or work.policy_decision_digest != record.policy_decision_digest
            or work.policy_snapshot_digest != record.policy_snapshot_digest
            or work.owner_version != record.owner_version
            or work.owner_history_sequence != record.owner_history_sequence
            or work.owner_history_digest != record.owner_history_digest
            or not (reservation_matches_round or reservation_was_committed)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery work differs from its authorization round",
            )

    def _apply_terminal_recovery_authorization_tx(
        self,
        work: RecoveryWorkRecord,
        transaction: EnforcedTransactionRecord,
        stage: StageMaterialRecord | None,
        *,
        evidence_ref: str,
        reason_code: str,
        recorded_at: datetime,
    ) -> None:
        if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
            if transaction.state is not TransactionState.IN_DOUBT:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Terminal reconciliation authorization must leave IN_DOUBT",
                )
            return
        if work.kind is RecoveryWorkKind.DISCARD_STAGING:
            if stage is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Terminal stage recovery authorization lost its target material",
                )
            failed_stage = StageMaterialRecord.model_validate(
                {
                    **stage.model_dump(mode="python"),
                    "state": StageMaterialState.DISCARD_FAILED,
                    "discard_evidence_ref": evidence_ref,
                    "version": stage.version + 1,
                    "updated_at": recorded_at,
                }
            )
            self._update_stage_material_tx(stage, failed_stage)
            self._finish_target_intent_tx(
                work,
                succeeded=False,
                evidence_digest=evidence_ref,
                recorded_at=recorded_at,
            )
            transition = TransitionEvent.STAGING_DISCARD_FAILED
        else:
            if transaction.state is not TransactionState.FAILED:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Terminal rollback or compensation authorization requires FAILED",
                )
            self._finish_target_intent_tx(
                work,
                succeeded=False,
                evidence_digest=evidence_ref,
                recorded_at=recorded_at,
            )
            transition = TransitionEvent.RECOVERY_UNAVAILABLE
        self._apply_transition_tx(
            transaction,
            expected_version=transaction.version,
            transition_event=transition,
            recorded_at=recorded_at,
            evidence_refs=(evidence_ref,),
            reason_code=reason_code,
        )

    def _assert_recovery_lineage_tx(
        self,
        work: RecoveryWorkRecord,
        authorization_round: AuthorizationRoundRecord,
    ) -> None:
        if work.recovery_ordinal == 1:
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                overlap = self._connection.execute(
                    "SELECT 1 FROM enforced_recovery_work WHERE tenant_id = ? "
                    "AND transaction_id = ? AND kind = 'RECONCILE_DISPATCH' "
                    "AND target_id = ? LIMIT 1",
                    (work.tenant_id, work.transaction_id, work.target_id),
                ).fetchone()
                if overlap is not None:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "A reconciliation lineage already exists for this dispatch",
                    )
            return
        if (
            work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
            or work.predecessor_recovery_id is None
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Only reconciliation UNKNOWN may create a recovery retry generation",
            )
        predecessor = self._get_recovery_work_tx(
            work.tenant_id,
            work.transaction_id,
            work.predecessor_recovery_id,
        )
        if predecessor.recovery_ordinal >= predecessor.max_recovery_attempts:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Reconciliation retry limit is exhausted and requires review",
                review_required=True,
            )
        attempt = self._get_reconciliation_attempt_tx(
            predecessor.tenant_id,
            predecessor.transaction_id,
            predecessor.recovery_id,
            predecessor.attempt,
        )
        if (
            predecessor.state is not RecoveryWorkState.RETRY_SCHEDULED
            or predecessor.root_recovery_id != work.root_recovery_id
            or work.recovery_ordinal != predecessor.recovery_ordinal + 1
            or work.max_recovery_attempts != predecessor.max_recovery_attempts
            or work.deadline != predecessor.deadline
            or work.intent_hash != predecessor.intent_hash
            or work.target_id != predecessor.target_id
            or work.target_version_guard != predecessor.target_version_guard
            or work.recovery_action_transaction_id == predecessor.recovery_action_transaction_id
            or work.authorization_round_id == predecessor.authorization_round_id
            or attempt.outcome is not ReconciliationOutcome.UNKNOWN
            or attempt.next_attempt_not_before is None
            or work.not_before != attempt.next_attempt_not_before
            or work.created_at < attempt.next_attempt_not_before
            or authorization_round.evaluated_at < attempt.next_attempt_not_before
            or work.created_at >= work.deadline
            or authorization_round.evaluated_at >= work.deadline
        ):
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Reconciliation retry differs from its durable UNKNOWN predecessor",
            )
        if predecessor.lease_id is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Scheduled reconciliation retry lost its predecessor lease",
            )
        predecessor_lease = self._get_worker_lease_tx(
            predecessor.tenant_id,
            predecessor.transaction_id,
            predecessor.lease_id,
        )
        if predecessor_lease.released_at is None:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Reconciliation retry cannot overlap its predecessor lease",
            )
        overlap = self._connection.execute(
            "SELECT 1 FROM enforced_recovery_work WHERE tenant_id = ? "
            "AND transaction_id = ? AND root_recovery_id = ? "
            "AND state IN ('PENDING', 'RUNNING') LIMIT 1",
            (work.tenant_id, work.transaction_id, work.root_recovery_id),
        ).fetchone()
        if overlap is not None:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Reconciliation lineage already has an executable generation",
            )
        retried = RecoveryWorkRecord.model_validate(
            {
                **predecessor.model_dump(mode="python"),
                "state": RecoveryWorkState.RETRIED,
                "version": predecessor.version + 1,
                "evidence_refs": tuple(
                    sorted(
                        {
                            *predecessor.evidence_refs,
                            authorization_round.round_digest,
                            canonical_digest(work),
                        }
                    )
                ),
                "updated_at": authorization_round.evaluated_at,
            }
        )
        self._update_recovery_work_tx(predecessor, retried)

    def authorize_recovery(
        self,
        work: RecoveryWorkRecord,
        *,
        authorization_round: AuthorizationRoundRecord,
        authority_decision: EnforcedAuthorityDecision,
        policy_decision: AggregatePolicyDecision,
        capability_ids: Sequence[str] = (),
        handoff_lease: WorkerLeaseRecord | None = None,
        handoff_failure_evidence_ref: str | None = None,
        handoff_failure_evidence_status: RecoveryHandoffFailureEvidenceStatus = (
            RecoveryHandoffFailureEvidenceStatus.NONE
        ),
        handoff_failure_reason_code: str | None = None,
    ) -> RecoveryAuthorizationResult:
        """Persist authorization with a mandatory handoff; its lease is retry-optional."""

        self._assert_recovery_round_bindings(work, authorization_round)
        if handoff_failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.NONE:
            if handoff_failure_evidence_ref is not None or handoff_failure_reason_code is not None:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Nonterminal recovery authorization cannot carry handoff failure fields",
                )
        else:
            if handoff_failure_reason_code is None:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Terminal recovery authorization requires a handoff failure reason",
                )
            handoff_failure_evidence_ref = _require_handoff_failure_evidence(
                handoff_failure_evidence_ref,
                status=handoff_failure_evidence_status,
                reason_code=handoff_failure_reason_code,
            )
        expected_state = {
            AuthorizationVerdict.ELIGIBLE: RecoveryWorkState.PENDING,
            AuthorizationVerdict.DENIED: RecoveryWorkState.FAILED,
            AuthorizationVerdict.UNKNOWN: RecoveryWorkState.REVIEW_REQUIRED,
        }[authorization_round.verdict]
        if (
            work.state is not expected_state
            or work.version != 0
            or work.attempt != 0
            or work.permit is not None
            or work.created_at != authorization_round.evaluated_at
            or work.updated_at != authorization_round.evaluated_at
            or work.created_at >= work.deadline
            or authorization_round.evaluated_at >= work.deadline
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery authorization requires an exact unclaimed initial work record",
            )
        if handoff_lease is not None and (
            handoff_lease.tenant_id != work.tenant_id
            or handoff_lease.transaction_id != work.transaction_id
            or handoff_lease.purpose is not LeasePurpose.RECOVERY
            or handoff_lease.released_at is not None
            or handoff_lease.expires_at > work.deadline
            or authorization_round.evaluated_at < handoff_lease.acquired_at
            or authorization_round.evaluated_at >= handoff_lease.expires_at
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery authorization handoff lease differs from its exact work fence",
            )

        def release_handoff_tx() -> None:
            if handoff_lease is None:
                return
            current = self._get_worker_lease_tx(
                handoff_lease.tenant_id,
                handoff_lease.transaction_id,
                handoff_lease.lease_id,
            )
            released = WorkerLeaseRecord.model_validate(
                {
                    **handoff_lease.model_dump(mode="python"),
                    "version": handoff_lease.version + 1,
                    "released_at": authorization_round.evaluated_at,
                }
            )
            if current == released:
                return
            if current != handoff_lease:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Recovery authorization lost its exact handoff lease",
                    retryable=False,
                )
            self._update_worker_lease_tx(current, released)

        try:
            with self._immediate():
                existing = self._connection.execute(
                    "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
                    "AND transaction_id = ? AND recovery_id = ?",
                    (work.tenant_id, work.transaction_id, work.recovery_id),
                ).fetchone()
                handoff_row = self._connection.execute(
                    "SELECT * FROM enforced_recovery_action_handoffs "
                    "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
                    (work.tenant_id, work.transaction_id, work.recovery_id),
                ).fetchone()
                terminal_authorization = (
                    authorization_round.verdict is not AuthorizationVerdict.ELIGIBLE
                )
                if handoff_row is None:
                    raise AgentKernelError(
                        ErrorCode.VALIDATION_ERROR,
                        "Recovery authorization requires a durable action handoff",
                    )
                handoff = self._assert_recovery_work_handoff_tx(work)
                if (
                    authorization_round.verdict is AuthorizationVerdict.ELIGIBLE
                    and work.evidence_refs != (handoff.binding_ref,)
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Eligible recovery work lost its exact handoff evidence",
                    )
                if existing is None and handoff_lease is None:
                    raise AgentKernelError(
                        ErrorCode.VALIDATION_ERROR,
                        "New recovery authorization requires its active handoff lease",
                    )
                if terminal_authorization:
                    if (
                        handoff_failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.NONE
                        or (
                            handoff_failure_evidence_ref is not None
                            and handoff_failure_evidence_ref not in work.evidence_refs
                        )
                        or handoff_failure_reason_code is None
                    ):
                        raise AgentKernelError(
                            ErrorCode.VALIDATION_ERROR,
                            "Terminal recovery authorization requires bound handoff evidence",
                        )
                elif (
                    handoff_failure_evidence_status is not RecoveryHandoffFailureEvidenceStatus.NONE
                ):
                    raise AgentKernelError(
                        ErrorCode.VALIDATION_ERROR,
                        "Eligible recovery authorization cannot carry failure evidence",
                    )
                if existing is not None:
                    stored = self._recovery_from_row(existing)
                    stored_round = self._get_authorization_round_tx(
                        work.tenant_id,
                        work.transaction_id,
                        work.authorization_round_id,
                    )
                    if authorization_round.verdict is AuthorizationVerdict.ELIGIBLE:
                        normalized_capability_ids = self._validated_capability_ids(capability_ids)
                    else:
                        if capability_ids:
                            raise AgentKernelError(
                                ErrorCode.VALIDATION_ERROR,
                                "Ineligible recovery cannot reserve capabilities",
                            )
                        normalized_capability_ids = ()
                    self._assert_round_decision_semantics(
                        authorization_round,
                        action=self._get_normalized_action(
                            work.tenant_id,
                            work.recovery_action_transaction_id,
                        ).action,
                        authority=authority_decision,
                        policy=policy_decision,
                        capability_ids=normalized_capability_ids,
                    )
                    if (
                        stored_round != authorization_round
                        or not self._same_recovery_authorization_identity(stored, work)
                        or (stored.version == 0 and stored != work)
                        or (
                            authorization_round.verdict is AuthorizationVerdict.ELIGIBLE
                            and canonical_digest(work)
                            != self._authorized_recovery_work_digest_tx(stored)
                        )
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery authorization retry changed immutable work",
                        )
                    reservation = (
                        None
                        if authorization_round.verdict is not AuthorizationVerdict.ELIGIBLE
                        else self._read_capability_chain(
                            tenant_id=work.tenant_id,
                            goal_id=cast("str", authorization_round.reservation_goal_id),
                            run_id=cast("str", authorization_round.reservation_run_id),
                            intent_hash=work.recovery_action_intent_hash,
                        )
                    )
                    capability_state = (
                        None
                        if authorization_round.verdict is not AuthorizationVerdict.ELIGIBLE
                        else (
                            CapabilityReservationState.RESERVED
                            if stored.state is RecoveryWorkState.PENDING
                            else (
                                CapabilityReservationState.RELEASED
                                if stored.permit is None
                                else CapabilityReservationState.COMMITTED
                            )
                        )
                    )
                    if (
                        reservation is not None
                        and reservation.capability_ids != normalized_capability_ids
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery authorization retry changed capability authority",
                        )
                    self._assert_recovery_capability_settlement_tx(
                        stored,
                        stored_round,
                        expected_state=capability_state,
                    )
                    self._validate_recovery_action_handoff_reverse_tx(
                        handoff,
                        tenant_id=stored.tenant_id,
                    )
                    if terminal_authorization and handoff_row is not None:
                        self._assert_terminal_recovery_target_settlement_tx(
                            stored,
                            terminal_evidence_ref=authorization_round.round_digest,
                            recorded_at=authorization_round.evaluated_at,
                        )
                        self._assert_recovery_capability_settlement_tx(
                            stored,
                            authorization_round,
                            expected_state=None,
                        )
                        self._close_recovery_work_handoff_tx(
                            stored,
                            failure_evidence_status=handoff_failure_evidence_status,
                            failure_evidence_ref=handoff_failure_evidence_ref,
                            reason_code=cast("str", handoff_failure_reason_code),
                            recorded_at=authorization_round.evaluated_at,
                        )
                    release_handoff_tx()
                    return RecoveryAuthorizationResult(
                        stored,
                        stored_round,
                        reservation,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                self._assert_recovery_lineage_tx(work, authorization_round)
                self._assert_recovery_subject_owner_tx(work)
                target_transaction, target_stage, _ = self._assert_recovery_target_tx(
                    work,
                    require_authorizable_state=True,
                )
                reservation = self._persist_round_dependencies_tx(
                    authorization_round,
                    authority_decision=authority_decision,
                    policy_decision=policy_decision,
                    capability_ids=capability_ids,
                )
                self._insert_authorization_round_tx(authorization_round)
                if authorization_round.verdict is AuthorizationVerdict.ELIGIBLE:
                    if (
                        reservation is None
                        or work.capability_reservation_digest
                        != capability_reservation_digest(reservation)
                        or work.reservation_version != reservation.version
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery work differs from its reserved capability fence",
                        )
                elif reservation is not None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Ineligible recovery unexpectedly reserved capability authority",
                    )
                self._insert_recovery_work_tx(work)
                if authorization_round.verdict is not AuthorizationVerdict.ELIGIBLE:
                    if (
                        work.reason_code != authorization_round.reason_code
                        or authorization_round.round_digest not in work.evidence_refs
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Ineligible recovery work lacks its exact round evidence",
                        )
                    self._apply_terminal_recovery_authorization_tx(
                        work,
                        target_transaction,
                        target_stage,
                        evidence_ref=authorization_round.round_digest,
                        reason_code=authorization_round.reason_code,
                        recorded_at=authorization_round.evaluated_at,
                    )
                    self._transition_owned_attempt_tx(
                        tenant_id=work.tenant_id,
                        intent_hash=work.recovery_action_intent_hash,
                        transaction_id=work.recovery_action_transaction_id,
                        owner_version=work.owner_version,
                        owner_history_sequence=work.owner_history_sequence,
                        owner_history_digest=work.owner_history_digest,
                        target_state=IntentAttemptState.NO_EFFECT_CONFIRMED,
                        evidence_digest=canonical_digest(work),
                        recorded_at=authorization_round.evaluated_at,
                    )
                    if handoff_row is not None:
                        self._close_recovery_work_handoff_tx(
                            work,
                            failure_evidence_status=handoff_failure_evidence_status,
                            failure_evidence_ref=handoff_failure_evidence_ref,
                            reason_code=cast("str", handoff_failure_reason_code),
                            recorded_at=authorization_round.evaluated_at,
                        )
                release_handoff_tx()
                disposition = (
                    EnforcedStoreDisposition.REVIEW_REQUIRED
                    if authorization_round.verdict is AuthorizationVerdict.UNKNOWN
                    else EnforcedStoreDisposition.STORED
                )
                return RecoveryAuthorizationResult(
                    work,
                    authorization_round,
                    reservation,
                    disposition,
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Recovery authorization failed closed", error) from error

    def fail_recovery_revalidation(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        expected_work_version: int,
        target_state: RecoveryWorkState,
        evidence_refs: tuple[str, ...],
        reason_code: str,
        recorded_at: datetime,
        handoff_failure_evidence_ref: str | None = None,
        handoff_failure_evidence_status: RecoveryHandoffFailureEvidenceStatus = (
            RecoveryHandoffFailureEvidenceStatus.NONE
        ),
        handoff_failure_reason_code: str | None = None,
    ) -> RecoveryAuthorizationResult:
        """CAS an unclaimed eligible work item closed after pre-permit revalidation fails."""

        if target_state not in {
            RecoveryWorkState.FAILED,
            RecoveryWorkState.REVIEW_REQUIRED,
        }:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery revalidation can finish only as failed or review-required",
            )
        refs = tuple(
            sorted({_require_digest(value, field="evidence_ref") for value in evidence_refs})
        )
        if not refs or not reason_code:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery revalidation failure requires reason and evidence",
            )
        if handoff_failure_reason_code is None:
            if (
                handoff_failure_evidence_status is not RecoveryHandoffFailureEvidenceStatus.NONE
                or handoff_failure_evidence_ref is not None
            ):
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Terminal recovery revalidation requires a handoff failure reason",
                )
        else:
            handoff_failure_evidence_ref = _require_handoff_failure_evidence(
                handoff_failure_evidence_ref,
                status=handoff_failure_evidence_status,
                reason_code=handoff_failure_reason_code,
            )
            if handoff_failure_reason_code not in {
                reason_code,
                f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{reason_code}",
            }:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Recovery revalidation handoff reason differs from terminal work",
                )
        deadline_terminal = reason_code == ErrorCode.DEADLINE_EXCEEDED.value
        if deadline_terminal and len(refs) != 1:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Expired pending recovery requires one control-evidence artifact",
            )
        with self._immediate():
            work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
            record = self._get_authorization_round_tx(
                tenant_id,
                transaction_id,
                work.authorization_round_id,
            )
            handoff_row = self._connection.execute(
                "SELECT * FROM enforced_recovery_action_handoffs "
                "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
                (work.tenant_id, work.transaction_id, work.recovery_id),
            ).fetchone()
            if handoff_row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Terminal recovery revalidation lost its durable action handoff",
                )
            if (
                handoff_failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.NONE
                or handoff_failure_reason_code is None
                or (
                    handoff_failure_evidence_ref is not None
                    and handoff_failure_evidence_ref not in refs
                )
            ):
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Terminal recovery revalidation requires bound handoff evidence",
                )
            if work.state in {
                RecoveryWorkState.FAILED,
                RecoveryWorkState.REVIEW_REQUIRED,
            }:
                if work.version != expected_work_version + 1:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery revalidation retry used a stale source generation",
                        retryable=False,
                    )
                if (
                    work.state is not target_state
                    or work.reason_code != reason_code
                    or work.evidence_refs != refs
                    or work.updated_at != recorded_at
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery revalidation retry changed terminal evidence",
                    )
                self._close_recovery_work_handoff_tx(
                    work,
                    failure_evidence_status=handoff_failure_evidence_status,
                    failure_evidence_ref=handoff_failure_evidence_ref,
                    reason_code=handoff_failure_reason_code,
                    recorded_at=recorded_at,
                )
                self._assert_terminal_recovery_target_settlement_tx(
                    work,
                    terminal_evidence_ref=refs[0],
                    recorded_at=recorded_at,
                )
                self._assert_recovery_capability_settlement_tx(
                    work,
                    record,
                    expected_state=CapabilityReservationState.RELEASED,
                )
                self._validate_recovery_action_handoff_reverse_tx(
                    self._assert_recovery_work_handoff_tx(work),
                    tenant_id=work.tenant_id,
                )
                return RecoveryAuthorizationResult(
                    work,
                    record,
                    None,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            if (
                work.state is not RecoveryWorkState.PENDING
                or work.version != expected_work_version
                or work.attempt != 0
                or work.permit is not None
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Recovery work is no longer the expected unclaimed generation",
                )
            reservation = self._read_capability_chain(
                tenant_id=tenant_id,
                goal_id=cast("str", record.reservation_goal_id),
                run_id=cast("str", record.reservation_run_id),
                intent_hash=work.recovery_action_intent_hash,
            )
            updated = RecoveryWorkRecord.model_validate(
                {
                    **work.model_dump(mode="python"),
                    "state": target_state,
                    "version": work.version + 1,
                    "evidence_refs": refs,
                    "reason_code": reason_code,
                    "updated_at": recorded_at,
                }
            )
            # Revalidation fails before a recovery permit or adapter dispatch exists, so
            # the recovery action is authoritatively NO_EFFECT even when the original
            # target still needs review. Record that proof before releasing its budget;
            # the surrounding BEGIN IMMEDIATE keeps the intent, budget, work, and target
            # transitions atomic if any later invariant fails.
            self._transition_owned_attempt_tx(
                tenant_id=work.tenant_id,
                intent_hash=work.recovery_action_intent_hash,
                transaction_id=work.recovery_action_transaction_id,
                owner_version=work.owner_version,
                owner_history_sequence=work.owner_history_sequence,
                owner_history_digest=work.owner_history_digest,
                target_state=IntentAttemptState.NO_EFFECT_CONFIRMED,
                evidence_digest=canonical_digest(updated),
                recorded_at=recorded_at,
            )
            released: CapabilityChainReservation | None = None
            if reservation is not None:
                if (
                    reservation.state is not CapabilityReservationState.RESERVED
                    or reservation.version != work.reservation_version
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery revalidation lost its reserved capability fence",
                    )
                released = self.release_capability_chain(
                    tenant_id=reservation.tenant_id,
                    goal_id=reservation.goal_id,
                    run_id=reservation.run_id,
                    intent_hash=reservation.intent_hash,
                    capability_ids=reservation.capability_ids,
                    fence=reservation.fence,
                    released_at=recorded_at,
                )
            self._update_recovery_work_tx(work, updated)
            target_transaction, target_stage, _ = self._assert_recovery_target_tx(
                work,
                require_authorizable_state=True,
            )
            self._apply_terminal_recovery_authorization_tx(
                work,
                target_transaction,
                target_stage,
                evidence_ref=refs[0],
                reason_code=reason_code,
                recorded_at=recorded_at,
            )
            self._close_recovery_work_handoff_tx(
                work,
                failure_evidence_status=handoff_failure_evidence_status,
                failure_evidence_ref=handoff_failure_evidence_ref,
                reason_code=handoff_failure_reason_code,
                recorded_at=recorded_at,
            )
            return RecoveryAuthorizationResult(
                updated,
                record,
                released,
                (
                    EnforcedStoreDisposition.REVIEW_REQUIRED
                    if target_state is RecoveryWorkState.REVIEW_REQUIRED
                    else EnforcedStoreDisposition.STORED
                ),
            )

    def _scheduled_reconciliation_successor_handoff_tx(
        self,
        work: RecoveryWorkRecord,
        attempt: ReconciliationAttemptRecord,
        *,
        expected_successor_recovery_id: str,
    ) -> RecoveryActionHandoff | None:
        """Discover and canonically validate the sole predecessor-bound handoff."""

        expected_row = self._connection.execute(
            "SELECT * FROM enforced_recovery_action_handoffs "
            "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
            (
                work.tenant_id,
                work.transaction_id,
                expected_successor_recovery_id,
            ),
        ).fetchone()
        expected_handoff = (
            None
            if expected_row is None
            else self._recovery_action_handoff_from_row(
                expected_row,
                tenant_id=work.tenant_id,
                target_transaction_id=work.transaction_id,
                recovery_id=expected_successor_recovery_id,
            )
        )
        rows = self._connection.execute(
            "SELECT * FROM enforced_recovery_action_handoffs "
            "WHERE tenant_id = ? AND target_transaction_id = ? "
            "AND recovery_kind = ? ORDER BY recovery_id LIMIT ?",
            (
                work.tenant_id,
                work.transaction_id,
                RecoveryWorkKind.RECONCILE_DISPATCH.value,
                work.max_recovery_attempts + 1,
            ),
        ).fetchall()
        if len(rows) > work.max_recovery_attempts:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Scheduled reconciliation lineage exceeds its bounded handoff count",
            )
        handoffs = tuple(
            self._recovery_action_handoff_from_row(
                row,
                tenant_id=work.tenant_id,
                target_transaction_id=work.transaction_id,
                recovery_id=str(row["recovery_id"]),
            )
            for row in rows
        )
        successors = tuple(
            handoff
            for handoff in handoffs
            if handoff.binding.predecessor_recovery_id == work.recovery_id
        )
        if len(successors) > 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Scheduled reconciliation predecessor has multiple successor handoffs",
            )
        if not successors:
            if expected_handoff is not None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Scheduled reconciliation successor identity detached from its predecessor",
                )
            return None
        handoff = successors[0]
        if expected_handoff is None or handoff != expected_handoff:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Scheduled reconciliation predecessor changed its deterministic successor",
            )
        binding = handoff.binding
        target_action = self._get_normalized_action(
            work.tenant_id,
            work.transaction_id,
        ).action
        dispatch = self._get_commit_dispatch_tx(
            work.tenant_id,
            work.transaction_id,
        )
        if (
            attempt.next_attempt_not_before is None
            or binding.target_transaction_id != work.transaction_id
            or binding.target_intent_hash != work.intent_hash
            or binding.target_normalized_action_digest != canonical_digest(target_action)
            or binding.recovery_kind is not RecoveryWorkKind.RECONCILE_DISPATCH
            or binding.target_id != dispatch.dispatch_id
            or binding.target_evidence_ref != canonical_digest(dispatch)
            or binding.target_version_guard != dispatch.permit.target_version_guard
            or binding.target_owner_version != work.target_owner_version
            or binding.target_owner_history_sequence != work.target_owner_history_sequence
            or binding.target_owner_history_digest != work.target_owner_history_digest
            or binding.adapter_manifest_digest != work.adapter_manifest_digest
            or binding.risk_class is not target_action.risk_floor
            or binding.effect_domains != target_action.effect_domains
            or binding.resource_uses_digest != canonical_digest(target_action.resource_uses)
            or binding.recovery_id != expected_successor_recovery_id
            or binding.root_recovery_id != work.root_recovery_id
            or binding.predecessor_recovery_id != work.recovery_id
            or binding.recovery_ordinal != work.recovery_ordinal + 1
            or binding.max_recovery_attempts != work.max_recovery_attempts
            or binding.not_before != attempt.next_attempt_not_before
            or binding.absolute_deadline != work.deadline
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Scheduled reconciliation successor handoff changed its exact lineage",
            )
        return handoff

    def terminalize_scheduled_reconciliation_deadline(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        expected_successor_recovery_id: str,
        expected_work_version: int,
        failure_evidence_ref: str | None,
        failure_evidence_status: RecoveryHandoffFailureEvidenceStatus,
        recorded_at: datetime,
    ) -> RecoveryAuthorizationResult:
        """Close a scheduled reconciliation lineage after its immutable deadline."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        expected_successor_recovery_id = _require_identifier(
            expected_successor_recovery_id,
            field="expected_successor_recovery_id",
        )
        if type(expected_work_version) is not int or expected_work_version < 0:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Scheduled reconciliation expiry requires an exact work version",
            )
        handoff_reason_code = {
            RecoveryHandoffFailureEvidenceStatus.AVAILABLE: (ErrorCode.DEADLINE_EXCEEDED.value),
            RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE: (
                f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{ErrorCode.DEADLINE_EXCEEDED.value}"
            ),
        }.get(failure_evidence_status)
        if handoff_reason_code is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Scheduled reconciliation expiry requires typed terminal evidence",
            )
        failure_evidence_ref = _require_handoff_failure_evidence(
            failure_evidence_ref,
            status=failure_evidence_status,
            reason_code=handoff_reason_code,
        )
        with self._immediate():
            work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
            current_dispatch = self._get_commit_dispatch_tx(tenant_id, transaction_id)
            derived_successor_recovery_id = scheduled_reconciliation_successor_recovery_id(
                work,
                current_dispatch,
            )
            if expected_successor_recovery_id != derived_successor_recovery_id:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Scheduled reconciliation expiry changed its deterministic successor",
                    retryable=False,
                )
            authorization_round = self._get_authorization_round_tx(
                tenant_id,
                transaction_id,
                work.authorization_round_id,
            )
            handoff = self._assert_recovery_work_handoff_tx(work)
            recovery_action = self._get_normalized_action(
                tenant_id,
                work.recovery_action_transaction_id,
            ).action
            reservation = self._read_capability_chain(
                tenant_id=tenant_id,
                goal_id=recovery_action.goal_id,
                run_id=recovery_action.run_id,
                intent_hash=work.recovery_action_intent_hash,
            )
            if work.state is RecoveryWorkState.REVIEW_REQUIRED:
                expected_refs = (
                    work.evidence_refs
                    if failure_evidence_ref is None
                    else tuple(sorted({*work.evidence_refs, failure_evidence_ref}))
                )
                if (
                    work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                    or work.version != expected_work_version + 1
                    or work.reason_code != ErrorCode.DEADLINE_EXCEEDED.value
                    or work.updated_at != recorded_at
                    or work.evidence_refs != expected_refs
                    or handoff.closed_at != recorded_at
                    or handoff.failure_evidence_status is not failure_evidence_status
                    or handoff.failure_evidence_ref != failure_evidence_ref
                    or handoff.failure_reason_code != handoff_reason_code
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Scheduled reconciliation expiry retry changed its terminal barrier",
                    )
                self._validate_recovery_work_handoff_lifecycle_tx(work)
                self._validate_recovery_action_handoff_reverse_tx(
                    handoff,
                    tenant_id=tenant_id,
                )
                attempts = self._assert_reconciliation_attempt_lineage_tx(work)
                attempt = next(
                    (candidate for candidate in attempts if candidate.attempt == work.attempt),
                    None,
                )
                if attempt is None or attempt.completed_at is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Scheduled reconciliation expiry retry lost its completed attempt",
                    )
                successor_handoff = self._scheduled_reconciliation_successor_handoff_tx(
                    work,
                    attempt,
                    expected_successor_recovery_id=derived_successor_recovery_id,
                )
                successor_work_row = self._connection.execute(
                    "SELECT 1 FROM enforced_recovery_work WHERE tenant_id = ? "
                    "AND transaction_id = ? AND (recovery_id = ? "
                    "OR predecessor_recovery_id = ?) LIMIT 1",
                    (
                        tenant_id,
                        transaction_id,
                        derived_successor_recovery_id,
                        work.recovery_id,
                    ),
                ).fetchone()
                if successor_work_row is not None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Scheduled reconciliation expiry retry overlaps successor work",
                    )
                if successor_handoff is not None:
                    self._assert_settled_reconciliation_successor_fence_tx(
                        work,
                        successor_handoff,
                    )
                else:
                    if work.fencing_token is None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Scheduled reconciliation expiry retry lost its predecessor fence",
                        )
                    later_fence = self._connection.execute(
                        "SELECT 1 FROM enforced_worker_leases WHERE tenant_id = ? "
                        "AND transaction_id = ? AND fencing_token > ? LIMIT 1",
                        (
                            tenant_id,
                            transaction_id,
                            work.fencing_token,
                        ),
                    ).fetchone()
                    if later_fence is not None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Scheduled reconciliation expiry retry gained a later fence",
                        )
                self._assert_recovery_capability_settlement_tx(
                    work,
                    authorization_round,
                    expected_state=CapabilityReservationState.COMMITTED,
                )
                return RecoveryAuthorizationResult(
                    work,
                    authorization_round,
                    reservation,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            if (
                work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                or work.state is not RecoveryWorkState.RETRY_SCHEDULED
                or work.version != expected_work_version
                or work.attempt < 1
                or work.permit is None
                or work.permit_ref is None
                or work.lease_id is None
                or work.worker_id is None
                or work.fencing_token is None
                or work.reason_code is None
                or work.unavailable_record_digest is not None
                or recorded_at < work.deadline
                or handoff.closed_at is not None
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Scheduled reconciliation expiry lost its exact retry generation",
                    retryable=False,
                )
            self._validate_recovery_work_handoff_lifecycle_tx(work)
            attempts = self._assert_reconciliation_attempt_lineage_tx(work)
            attempt = next(
                (candidate for candidate in attempts if candidate.attempt == work.attempt),
                None,
            )
            lease = self._get_worker_lease_tx(
                tenant_id,
                transaction_id,
                work.lease_id,
            )
            if attempt is None or attempt.completed_at is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Scheduled reconciliation expiry lost its completed attempt",
                )
            successor_handoff = self._scheduled_reconciliation_successor_handoff_tx(
                work,
                attempt,
                expected_successor_recovery_id=derived_successor_recovery_id,
            )
            successor_work_row = self._connection.execute(
                "SELECT 1 FROM enforced_recovery_work WHERE tenant_id = ? "
                "AND transaction_id = ? AND (recovery_id = ? "
                "OR predecessor_recovery_id = ?) LIMIT 1",
                (
                    tenant_id,
                    transaction_id,
                    derived_successor_recovery_id,
                    work.recovery_id,
                ),
            ).fetchone()
            if successor_work_row is not None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Scheduled reconciliation expiry overlaps durable successor work",
                )
            if successor_handoff is not None and successor_handoff.closed_at is None:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Scheduled reconciliation successor handoff won deadline ownership",
                    retryable=False,
                )
            transaction = self._assert_finished_reconciliation_retry_tx(
                work,
                attempt,
                expected_attempt_version=attempt.version - 1,
                outcome=ReconciliationOutcome.UNKNOWN,
                evidence_refs=attempt.completion_evidence_refs or (),
                operation_evidence_ref=attempt.operation_evidence_ref or "",
                operation_reason_code=attempt.operation_reason_code,
                completed_at=attempt.completed_at,
                effect_receipt_ref=attempt.effect_receipt_ref,
                committed_verification_permit_digest=(attempt.committed_verification_permit_digest),
                committed_verification_permit_ref=(attempt.committed_verification_permit_ref),
                committed_verification_ref=attempt.committed_verification_ref,
                no_effect_evidence_ref=attempt.no_effect_evidence_ref,
                next_attempt_not_before=attempt.next_attempt_not_before,
                reason_code=work.reason_code,
                settled_successor_handoff=successor_handoff,
            )
            dispatch = self._get_commit_dispatch_tx(tenant_id, transaction_id)
            if (
                attempt.outcome is not ReconciliationOutcome.UNKNOWN
                or attempt.version != 1
                or attempt.next_attempt_not_before is None
                or attempt.next_attempt_not_before >= work.deadline
                or work.updated_at != attempt.completed_at
                or transaction.state is not TransactionState.IN_DOUBT
                or dispatch is None
                or dispatch.state is not CommitDispatchState.IN_DOUBT
                or lease.purpose is not LeasePurpose.RECONCILIATION
                or lease.worker_id != work.worker_id
                or lease.fencing_token != work.fencing_token
                or lease.version != 1
                or lease.released_at != attempt.completed_at
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Scheduled reconciliation expiry differs from its completed attempt",
                )
            action_attempt = self._validate_bounded_intent_attempt_lifecycle_tx(
                tenant_id=tenant_id,
                intent_hash=work.recovery_action_intent_hash,
                transaction_id=work.recovery_action_transaction_id,
                expected_states=frozenset({IntentAttemptState.REVIEW_REQUIRED}),
            )
            self._validate_bounded_intent_attempt_lifecycle_tx(
                tenant_id=tenant_id,
                intent_hash=work.intent_hash,
                transaction_id=work.transaction_id,
                expected_states=frozenset({IntentAttemptState.RECONCILE_REQUIRED}),
            )
            if (
                action_attempt.evidence_digest != canonical_digest(work)
                or action_attempt.updated_at != attempt.completed_at
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Scheduled reconciliation expiry lost its prior review evidence",
                )
            self._assert_recovery_capability_settlement_tx(
                work,
                authorization_round,
                expected_state=CapabilityReservationState.COMMITTED,
            )
            self._assert_no_orphan_active_recovery_lease_tx(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
            )
            terminal_refs = (
                work.evidence_refs
                if failure_evidence_ref is None
                else tuple(sorted({*work.evidence_refs, failure_evidence_ref}))
            )
            updated = RecoveryWorkRecord.model_validate(
                {
                    **work.model_dump(mode="python"),
                    "state": RecoveryWorkState.REVIEW_REQUIRED,
                    "version": work.version + 1,
                    "evidence_refs": terminal_refs,
                    "reason_code": ErrorCode.DEADLINE_EXCEEDED.value,
                    "updated_at": recorded_at,
                }
            )
            self._close_recovery_work_handoff_tx(
                work,
                failure_evidence_status=failure_evidence_status,
                failure_evidence_ref=failure_evidence_ref,
                reason_code=handoff_reason_code,
                recorded_at=recorded_at,
            )
            self._update_recovery_work_tx(work, updated)
            terminal_handoff = self._assert_recovery_work_handoff_tx(updated)
            self._validate_recovery_work_handoff_lifecycle_tx(updated)
            self._validate_recovery_action_handoff_reverse_tx(
                terminal_handoff,
                tenant_id=tenant_id,
            )
            self._assert_reconciliation_attempt_lineage_tx(updated)
            return RecoveryAuthorizationResult(
                updated,
                authorization_round,
                reservation,
                EnforcedStoreDisposition.REVIEW_REQUIRED,
            )

    def fail_claimed_recovery_setup(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        expected_work_version: int,
        failure_evidence_ref: str,
        reason_code: str,
        recorded_at: datetime,
    ) -> RecoveryWorkRecord:
        """Close claimed work when setup fails before any recovery provider is entered."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        failure_evidence_ref = _require_digest(
            failure_evidence_ref,
            field="failure_evidence_ref",
        )
        if not reason_code:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Claimed recovery setup failure requires a reason",
            )
        with self._immediate():
            work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
            expected_refs = tuple(
                sorted(
                    {
                        *work.evidence_refs,
                        failure_evidence_ref,
                        work.target_evidence_ref,
                        *((work.permit_ref,) if work.permit_ref is not None else ()),
                    }
                )
            )
            if work.state is RecoveryWorkState.REVIEW_REQUIRED:
                if (
                    work.version != expected_work_version + 1
                    or work.reason_code != reason_code
                    or work.evidence_refs != expected_refs
                    or work.updated_at != recorded_at
                    or work.lease_id is None
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Claimed recovery setup retry changed its terminal evidence",
                    )
                lease = self._get_worker_lease_tx(
                    tenant_id,
                    transaction_id,
                    work.lease_id,
                )
                if lease.released_at != recorded_at:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Claimed recovery setup retry lost its lease settlement",
                    )
                self._close_recovery_work_handoff_tx(
                    work,
                    failure_evidence_status=(RecoveryHandoffFailureEvidenceStatus.AVAILABLE),
                    failure_evidence_ref=failure_evidence_ref,
                    reason_code=reason_code,
                    recorded_at=recorded_at,
                )
                self._assert_terminal_recovery_target_settlement_tx(
                    work,
                    terminal_evidence_ref=failure_evidence_ref,
                    recorded_at=recorded_at,
                )
                authorization_round = self._get_authorization_round_tx(
                    work.tenant_id,
                    work.transaction_id,
                    work.authorization_round_id,
                )
                self._assert_recovery_capability_settlement_tx(
                    work,
                    authorization_round,
                    expected_state=CapabilityReservationState.COMMITTED,
                )
                return work
            if (
                work.state is not RecoveryWorkState.RUNNING
                or work.version != expected_work_version
                or work.permit is None
                or work.permit_ref is None
                or work.lease_id is None
                or work.worker_id is None
                or work.fencing_token is None
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Recovery setup failure lost its exact claimed generation",
                )
            attempt_row = self._connection.execute(
                "SELECT 1 FROM enforced_reconciliation_attempts "
                "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
                "AND attempt = ?",
                (tenant_id, transaction_id, recovery_id, work.attempt),
            ).fetchone()
            if attempt_row is not None:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Recovery setup failure cannot close an entered reconciliation query",
                )
            lease = self._get_worker_lease_tx(
                tenant_id,
                transaction_id,
                work.lease_id,
            )
            purpose = (
                LeasePurpose.RECONCILIATION
                if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                else LeasePurpose.RECOVERY
            )
            if (
                lease.worker_id != work.worker_id
                or lease.fencing_token != work.fencing_token
                or lease.purpose is not purpose
                or lease.released_at is not None
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Recovery setup failure lost its active lease generation",
                )
            transaction, stage, _ = self._assert_recovery_target_tx(
                work,
                require_authorizable_state=False,
            )
            updated = RecoveryWorkRecord.model_validate(
                {
                    **work.model_dump(mode="python"),
                    "state": RecoveryWorkState.REVIEW_REQUIRED,
                    "version": work.version + 1,
                    "evidence_refs": expected_refs,
                    "reason_code": reason_code,
                    "updated_at": recorded_at,
                }
            )
            self._transition_owned_attempt_tx(
                tenant_id=work.tenant_id,
                intent_hash=work.recovery_action_intent_hash,
                transaction_id=work.recovery_action_transaction_id,
                owner_version=work.owner_version,
                owner_history_sequence=work.owner_history_sequence,
                owner_history_digest=work.owner_history_digest,
                target_state=IntentAttemptState.NO_EFFECT_CONFIRMED,
                evidence_digest=canonical_digest(updated),
                recorded_at=recorded_at,
            )
            recovery_action = self._get_normalized_action(
                work.tenant_id,
                work.recovery_action_transaction_id,
            ).action
            reservation = self._read_capability_chain(
                tenant_id=work.tenant_id,
                goal_id=recovery_action.goal_id,
                run_id=recovery_action.run_id,
                intent_hash=recovery_action.intent_hash,
            )
            if (
                reservation is None
                or reservation.state is not CapabilityReservationState.COMMITTED
                or reservation.version != work.reservation_version
                or capability_reservation_digest(reservation) != work.capability_reservation_digest
                or reservation.activation_owner_transaction_id
                != work.recovery_action_transaction_id
                or reservation.activation_owner_version != work.owner_version
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery setup failure lost its consumed capability fence",
                )
            if work.kind is RecoveryWorkKind.DISCARD_STAGING:
                if stage is None or transaction.state is not TransactionState.ABORTING:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Claimed discard setup failure lost its private target",
                    )
                work_evidence = canonical_digest(updated)
                failed_stage = StageMaterialRecord.model_validate(
                    {
                        **stage.model_dump(mode="python"),
                        "state": StageMaterialState.DISCARD_FAILED,
                        "discard_evidence_ref": failure_evidence_ref,
                        "version": stage.version + 1,
                        "updated_at": recorded_at,
                    }
                )
                self._update_stage_material_tx(stage, failed_stage)
                self._finish_target_intent_tx(
                    work,
                    succeeded=False,
                    evidence_digest=work_evidence,
                    recorded_at=recorded_at,
                )
                self._apply_transition_tx(
                    transaction,
                    expected_version=transaction.version,
                    transition_event=TransitionEvent.STAGING_DISCARD_FAILED,
                    recorded_at=recorded_at,
                    evidence_refs=(work_evidence, failure_evidence_ref),
                    reason_code=reason_code,
                )
            elif work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                if transaction.state is not TransactionState.IN_DOUBT:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Reconciliation setup failure must leave its target IN_DOUBT",
                    )
            else:
                expected_state = (
                    TransactionState.ROLLING_BACK
                    if work.kind is RecoveryWorkKind.ROLLBACK
                    else TransactionState.COMPENSATING
                )
                if transaction.state is not expected_state:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Claimed effect recovery setup failure lost its running target",
                    )
                work_evidence = canonical_digest(updated)
                self._finish_target_intent_tx(
                    work,
                    succeeded=False,
                    evidence_digest=work_evidence,
                    recorded_at=recorded_at,
                )
                self._apply_transition_tx(
                    transaction,
                    expected_version=transaction.version,
                    transition_event=(
                        TransitionEvent.ROLLBACK_FAILED_OR_UNKNOWN
                        if work.kind is RecoveryWorkKind.ROLLBACK
                        else TransitionEvent.COMPENSATION_FAILED_OR_UNKNOWN
                    ),
                    recorded_at=recorded_at,
                    evidence_refs=(work_evidence, failure_evidence_ref),
                    reason_code=reason_code,
                )
            self._close_recovery_work_handoff_tx(
                work,
                failure_evidence_status=RecoveryHandoffFailureEvidenceStatus.AVAILABLE,
                failure_evidence_ref=failure_evidence_ref,
                reason_code=reason_code,
                recorded_at=recorded_at,
            )
            self._update_recovery_work_tx(work, updated)
            self._release_recovery_lease_tx(updated, released_at=recorded_at)
            return updated

    def _preview_worker_lease_tx(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        lease_id: str,
        worker_id: str,
        purpose: LeasePurpose,
        acquired_at: datetime,
        expires_at: datetime,
    ) -> WorkerLeaseRecord:
        existing = self._connection.execute(
            "SELECT * FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND lease_id = ?",
            (tenant_id, transaction_id, lease_id),
        ).fetchone()
        if existing is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery lease identity already exists without this work generation",
            )
        active = self._connection.execute(
            "SELECT * FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND released_at IS NULL",
            (tenant_id, transaction_id),
        ).fetchone()
        if active is not None and self._lease_from_row(active).expires_at > acquired_at:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Another unexpired worker lease owns this transaction",
                retryable=True,
            )
        fence_row = self._connection.execute(
            "SELECT MAX(fencing_token) AS maximum FROM enforced_worker_leases "
            "WHERE tenant_id = ? AND transaction_id = ?",
            (tenant_id, transaction_id),
        ).fetchone()
        fencing_token = (
            1
            if fence_row is None or fence_row["maximum"] is None
            else int(fence_row["maximum"]) + 1
        )
        return WorkerLeaseRecord(
            tenant_id=tenant_id,
            transaction_id=transaction_id,
            lease_id=lease_id,
            worker_id=worker_id,
            purpose=purpose,
            fencing_token=fencing_token,
            version=0,
            acquired_at=acquired_at,
            expires_at=expires_at,
        )

    @staticmethod
    def _build_recovery_permit(
        work: RecoveryWorkRecord,
        lease: WorkerLeaseRecord,
        *,
        authority_valid_until: datetime,
        capability_reservation_digest_value: str,
        reservation_version: int,
    ) -> RecoveryPermit:
        return RecoveryPermit.create(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            intent_hash=work.intent_hash,
            recovery_id=work.recovery_id,
            recovery_action_transaction_id=work.recovery_action_transaction_id,
            recovery_action_intent_hash=work.recovery_action_intent_hash,
            recovery_action_digest=work.recovery_action_digest,
            adapter_manifest_digest=work.adapter_manifest_digest,
            recovery_kind=work.kind,
            target_id=work.target_id,
            target_owner_version=work.target_owner_version,
            target_owner_history_sequence=work.target_owner_history_sequence,
            target_owner_history_digest=work.target_owner_history_digest,
            target_evidence_ref=work.target_evidence_ref,
            target_version_guard=work.target_version_guard,
            authorization_round_id=work.authorization_round_id,
            authorization_round_digest=work.authorization_round_digest,
            authority_decision_digest=work.authority_decision_digest,
            policy_decision_digest=work.policy_decision_digest,
            policy_snapshot_digest=work.policy_snapshot_digest,
            capability_reservation_digest=capability_reservation_digest_value,
            reservation_version=reservation_version,
            owner_version=work.owner_version,
            owner_history_sequence=work.owner_history_sequence,
            owner_history_digest=work.owner_history_digest,
            approval_required=work.approval_required,
            approval_id=work.approval_id,
            approval_evidence_ref=work.approval_evidence_ref,
            lease_id=lease.lease_id,
            worker_id=lease.worker_id,
            fencing_token=lease.fencing_token,
            issued_at=lease.acquired_at,
            deadline=_lease_bounded_deadline(
                work.deadline,
                lease.expires_at,
                authority_valid_until,
            ).astimezone(UTC),
        )

    def _preview_pending_recovery_claim_tx(
        self,
        work: RecoveryWorkRecord,
        *,
        expected_work_version: int,
        lease_id: str,
        worker_id: str,
        acquired_at: datetime,
        expires_at: datetime,
    ) -> RecoveryClaimPreview:
        if work.state is not RecoveryWorkState.PENDING:
            raise AgentKernelError(
                ErrorCode.ILLEGAL_TRANSITION,
                "Only pending recovery work may be claimed",
            )
        if work.version != expected_work_version:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Recovery work version changed",
                retryable=True,
            )
        if acquired_at < work.created_at or not (acquired_at < expires_at <= work.deadline):
            raise AgentKernelError(
                ErrorCode.DEADLINE_EXCEEDED,
                "Recovery claim is outside its durable deadline",
            )
        self._assert_recovery_subject_owner_tx(work)
        self._assert_recovery_target_tx(work, require_authorizable_state=True)
        record = self._get_authorization_round_tx(
            work.tenant_id,
            work.transaction_id,
            work.authorization_round_id,
        )
        if record.verdict is not AuthorizationVerdict.ELIGIBLE:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Ineligible recovery work cannot be claimed",
            )
        if record.authority_valid_until is None or acquired_at >= record.authority_valid_until:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_EXPIRED,
                "Recovery authority expired before work claim",
            )
        self._assert_recovery_round_bindings(work, record)
        purpose = (
            LeasePurpose.RECONCILIATION
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
            else LeasePurpose.RECOVERY
        )
        lease = self._preview_worker_lease_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            lease_id=lease_id,
            worker_id=worker_id,
            purpose=purpose,
            acquired_at=acquired_at,
            expires_at=expires_at,
        )
        reservation = self._read_capability_chain(
            tenant_id=work.tenant_id,
            goal_id=cast("str", record.reservation_goal_id),
            run_id=cast("str", record.reservation_run_id),
            intent_hash=work.recovery_action_intent_hash,
        )
        if (
            reservation is None
            or reservation.state is not CapabilityReservationState.RESERVED
            or reservation.version != work.reservation_version
            or capability_reservation_digest(reservation) != work.capability_reservation_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery claim lost its reserved capability fence",
            )
        committed = preview_committed_capability_reservation(reservation)
        permit = self._build_recovery_permit(
            work,
            lease,
            authority_valid_until=record.authority_valid_until,
            capability_reservation_digest_value=capability_reservation_digest(committed),
            reservation_version=committed.version,
        )
        return RecoveryClaimPreview(work, lease, permit, canonical_digest(permit))

    def preview_recovery_claim(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        expected_work_version: int,
        lease_id: str,
        worker_id: str,
        acquired_at: datetime,
        expires_at: datetime,
    ) -> RecoveryClaimPreview:
        """Predict exact claim artifacts without writing state or consuming authority."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        lease_id = _require_identifier(lease_id, field="lease_id")
        worker_id = _require_identifier(worker_id, field="worker_id")
        with self._read_snapshot():
            work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
            return self._preview_pending_recovery_claim_tx(
                work,
                expected_work_version=expected_work_version,
                lease_id=lease_id,
                worker_id=worker_id,
                acquired_at=acquired_at,
                expires_at=expires_at,
            )

    def claim_recovery(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        expected_work_version: int,
        lease_id: str,
        worker_id: str,
        acquired_at: datetime,
        expires_at: datetime,
        permit: RecoveryPermit,
        permit_ref: str,
    ) -> RecoveryClaimResult:
        """Commit the recovery capability and fence before returning fresh authority."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        lease_id = _require_identifier(lease_id, field="lease_id")
        worker_id = _require_identifier(worker_id, field="worker_id")
        permit_ref = _require_digest(permit_ref, field="permit_ref")
        if permit_ref != canonical_digest(permit):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery claim permit artifact ref is inconsistent",
            )
        try:
            with self._immediate():
                work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
                if work.state is RecoveryWorkState.RUNNING:
                    expected_purpose = (
                        LeasePurpose.RECONCILIATION
                        if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                        else LeasePurpose.RECOVERY
                    )
                    lease = self._assert_active_lease_tx(
                        tenant_id=tenant_id,
                        transaction_id=transaction_id,
                        lease_id=lease_id,
                        worker_id=worker_id,
                        fencing_token=work.fencing_token or 0,
                        purpose=expected_purpose,
                        at=acquired_at,
                    )
                    if (
                        work.version != expected_work_version + 1
                        or expected_work_version != 0
                        or work.attempt != 1
                        or work.lease_id != lease_id
                        or work.worker_id != worker_id
                        or work.permit != permit
                        or work.permit_ref != permit_ref
                        or work.updated_at != acquired_at
                        or lease.acquired_at != acquired_at
                        or lease.expires_at != expires_at
                        or lease.version != 0
                    ):
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Recovery claim retry changed its exact permit generation",
                        )
                    authorization_round = self._get_authorization_round_tx(
                        tenant_id,
                        transaction_id,
                        work.authorization_round_id,
                    )
                    self._assert_recovery_round_bindings(work, authorization_round)
                    self._assert_recovery_capability_settlement_tx(
                        work,
                        authorization_round,
                        expected_state=CapabilityReservationState.COMMITTED,
                    )
                    handoff = self._assert_recovery_work_handoff_tx(work)
                    if handoff.closed_at is not None or work.evidence_refs != (
                        handoff.binding_ref,
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery claim retry changed its open handoff evidence",
                        )
                    self._validate_recovery_action_handoff_reverse_tx(
                        handoff,
                        tenant_id=work.tenant_id,
                    )
                    transaction, _stage, _dispatch = self._assert_recovery_target_tx(
                        work,
                        require_authorizable_state=False,
                    )
                    expected_target_state = {
                        RecoveryWorkKind.DISCARD_STAGING: TransactionState.ABORTING,
                        RecoveryWorkKind.ROLLBACK: TransactionState.ROLLING_BACK,
                        RecoveryWorkKind.COMPENSATE: TransactionState.COMPENSATING,
                        RecoveryWorkKind.RECONCILE_DISPATCH: TransactionState.IN_DOUBT,
                    }[work.kind]
                    if transaction.state is not expected_target_state:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery claim retry target is outside its exact running phase",
                        )
                    if work.kind in {
                        RecoveryWorkKind.ROLLBACK,
                        RecoveryWorkKind.COMPENSATE,
                    }:
                        event_row = self._connection.execute(
                            "SELECT * FROM enforced_transaction_events WHERE tenant_id = ? "
                            "AND transaction_id = ? AND sequence = ?",
                            (tenant_id, transaction_id, transaction.version),
                        ).fetchone()
                        event = None if event_row is None else self._event_from_row(event_row)
                        expected_event = (
                            TransitionEvent.START_ROLLBACK
                            if work.kind is RecoveryWorkKind.ROLLBACK
                            else TransitionEvent.START_COMPENSATION
                        )
                        if (
                            event is None
                            or event.event != expected_event.value
                            or event.recorded_at != acquired_at
                            or event.evidence_refs
                            != tuple(sorted({permit_ref, work.authorization_round_digest}))
                            or transaction.updated_at != acquired_at
                            or transaction.reason_code is not None
                        ):
                            raise AgentKernelError(
                                ErrorCode.INTEGRITY_ERROR,
                                "Recovery claim retry lost its exact transition event",
                            )
                    return RecoveryClaimResult(
                        work,
                        lease,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                preview = self._preview_pending_recovery_claim_tx(
                    work,
                    expected_work_version=expected_work_version,
                    lease_id=lease_id,
                    worker_id=worker_id,
                    acquired_at=acquired_at,
                    expires_at=expires_at,
                )
                if preview.permit != permit or preview.permit_ref != permit_ref:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery claim differs from its no-write artifact preview",
                    )
                transaction, _, _ = self._assert_recovery_target_tx(
                    work,
                    require_authorizable_state=True,
                )
                record = self._get_authorization_round_tx(
                    tenant_id,
                    transaction_id,
                    work.authorization_round_id,
                )
                if record.verdict is not AuthorizationVerdict.ELIGIBLE:
                    raise AgentKernelError(
                        ErrorCode.AUTHORITY_MISSING,
                        "Ineligible recovery work cannot be claimed",
                    )
                self._assert_recovery_round_bindings(work, record)
                purpose = (
                    LeasePurpose.RECONCILIATION
                    if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                    else LeasePurpose.RECOVERY
                )
                lease, created = self._acquire_worker_lease_tx(
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                    lease_id=lease_id,
                    worker_id=worker_id,
                    purpose=purpose,
                    acquired_at=acquired_at,
                    expires_at=expires_at,
                )
                if not created:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Existing recovery lease lacks its atomic work claim",
                    )
                if lease != preview.lease:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery lease changed after its artifact preview",
                        retryable=True,
                    )
                reservation = self._read_capability_chain(
                    tenant_id=tenant_id,
                    goal_id=cast("str", record.reservation_goal_id),
                    run_id=cast("str", record.reservation_run_id),
                    intent_hash=work.recovery_action_intent_hash,
                )
                if (
                    reservation is None
                    or reservation.state is not CapabilityReservationState.RESERVED
                    or reservation.version != work.reservation_version
                    or capability_reservation_digest(reservation)
                    != work.capability_reservation_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery claim lost its reserved capability fence",
                    )
                committed = self.commit_capability_chain(
                    tenant_id=reservation.tenant_id,
                    goal_id=reservation.goal_id,
                    run_id=reservation.run_id,
                    intent_hash=reservation.intent_hash,
                    capability_ids=reservation.capability_ids,
                    fence=reservation.fence,
                    committed_at=acquired_at,
                )
                if (
                    permit.capability_reservation_digest != capability_reservation_digest(committed)
                    or permit.reservation_version != committed.version
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery permit differs from consumed capability authority",
                    )
                updated = RecoveryWorkRecord.model_validate(
                    {
                        **work.model_dump(mode="python"),
                        "state": RecoveryWorkState.RUNNING,
                        "capability_reservation_digest": capability_reservation_digest(committed),
                        "reservation_version": committed.version,
                        "permit": permit,
                        "permit_ref": permit_ref,
                        "lease_id": lease.lease_id,
                        "worker_id": lease.worker_id,
                        "fencing_token": lease.fencing_token,
                        "attempt": work.attempt + 1,
                        "version": work.version + 1,
                        "updated_at": acquired_at,
                    }
                )
                if work.kind in {
                    RecoveryWorkKind.ROLLBACK,
                    RecoveryWorkKind.COMPENSATE,
                }:
                    transition = (
                        TransitionEvent.START_ROLLBACK
                        if work.kind is RecoveryWorkKind.ROLLBACK
                        else TransitionEvent.START_COMPENSATION
                    )
                    self._apply_transition_tx(
                        transaction,
                        expected_version=transaction.version,
                        transition_event=transition,
                        recorded_at=acquired_at,
                        evidence_refs=(permit_ref, work.authorization_round_digest),
                    )
                self._update_recovery_work_tx(work, updated)
                disposition = (
                    EnforcedStoreDisposition.STORED
                    if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                    else EnforcedStoreDisposition.RECOVERY_NOW
                )
                return RecoveryClaimResult(updated, lease, disposition)
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Recovery claim failed closed", error) from error

    def _preview_recovery_reclaim_tx(
        self,
        work: RecoveryWorkRecord,
        *,
        expected_work_version: int,
        lease_id: str,
        worker_id: str,
        acquired_at: datetime,
        expires_at: datetime,
    ) -> RecoveryClaimPreview:
        if (
            work.state is not RecoveryWorkState.RUNNING
            or work.version != expected_work_version
            or work.permit is None
            or work.permit_ref is None
            or work.lease_id is None
            or work.worker_id is None
            or work.fencing_token is None
        ):
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Recovery reclaim requires the exact running generation",
            )
        old_lease = self._get_worker_lease_tx(
            work.tenant_id,
            work.transaction_id,
            work.lease_id,
        )
        if old_lease.released_at is not None or old_lease.expires_at > acquired_at:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Recovery reclaim requires an expired active lease",
            )
        if not (acquired_at < expires_at <= work.deadline):
            raise AgentKernelError(
                ErrorCode.DEADLINE_EXCEEDED,
                "Recovery reclaim is outside its durable deadline",
            )
        self._assert_recovery_subject_owner_tx(work)
        transaction, _, _ = self._assert_recovery_target_tx(
            work,
            require_authorizable_state=False,
        )
        expected_states = {
            RecoveryWorkKind.DISCARD_STAGING: {TransactionState.ABORTING},
            RecoveryWorkKind.ROLLBACK: {TransactionState.ROLLING_BACK},
            RecoveryWorkKind.COMPENSATE: {TransactionState.COMPENSATING},
            RecoveryWorkKind.RECONCILE_DISPATCH: {
                TransactionState.IN_DOUBT,
                TransactionState.RECONCILING,
            },
        }[work.kind]
        if transaction.state not in expected_states:
            raise AgentKernelError(
                ErrorCode.ILLEGAL_TRANSITION,
                "Expired recovery lease no longer controls a resumable target state",
            )
        record = self._get_authorization_round_tx(
            work.tenant_id,
            work.transaction_id,
            work.authorization_round_id,
        )
        if (
            record.verdict is not AuthorizationVerdict.ELIGIBLE
            or record.purpose is not AuthorizationRoundPurpose.RECOVERY
            or record.round_digest != work.authorization_round_digest
            or record.subject_transaction_id != work.recovery_action_transaction_id
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Running recovery work lost its immutable authorization round",
            )
        if record.authority_valid_until is None or acquired_at >= record.authority_valid_until:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_EXPIRED,
                "Recovery authority expired before reclaim",
            )
        reservation = self._read_capability_chain(
            tenant_id=work.tenant_id,
            goal_id=cast("str", record.reservation_goal_id),
            run_id=cast("str", record.reservation_run_id),
            intent_hash=work.recovery_action_intent_hash,
        )
        if (
            reservation is None
            or reservation.state is not CapabilityReservationState.COMMITTED
            or reservation.version != work.reservation_version
            or capability_reservation_digest(reservation) != work.capability_reservation_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery reclaim lost its committed capability generation",
            )
        purpose = (
            LeasePurpose.RECONCILIATION
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
            else LeasePurpose.RECOVERY
        )
        lease = self._preview_worker_lease_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            lease_id=lease_id,
            worker_id=worker_id,
            purpose=purpose,
            acquired_at=acquired_at,
            expires_at=expires_at,
        )
        permit = self._build_recovery_permit(
            work,
            lease,
            authority_valid_until=record.authority_valid_until,
            capability_reservation_digest_value=capability_reservation_digest(reservation),
            reservation_version=reservation.version,
        )
        return RecoveryClaimPreview(work, lease, permit, canonical_digest(permit))

    def preview_recovery_reclaim(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        expected_work_version: int,
        lease_id: str,
        worker_id: str,
        acquired_at: datetime,
        expires_at: datetime,
    ) -> RecoveryClaimPreview:
        """Predict a higher-fenced expired-work permit without writing any reference."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        lease_id = _require_identifier(lease_id, field="lease_id")
        worker_id = _require_identifier(worker_id, field="worker_id")
        with self._read_snapshot():
            work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                self._assert_reconciliation_attempt_lineage_tx(work)
            return self._preview_recovery_reclaim_tx(
                work,
                expected_work_version=expected_work_version,
                lease_id=lease_id,
                worker_id=worker_id,
                acquired_at=acquired_at,
                expires_at=expires_at,
            )

    def reclaim_expired_recovery(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        expected_work_version: int,
        lease_id: str,
        worker_id: str,
        acquired_at: datetime,
        expires_at: datetime,
        permit: RecoveryPermit,
        permit_ref: str,
        evidence_refs: tuple[str, ...],
        operation_evidence_ref: str | None = None,
        operation_reason_code: str | None = None,
    ) -> RecoveryClaimResult:
        """Replace an expired recovery lease with a durable higher-fenced permit."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        lease_id = _require_identifier(lease_id, field="lease_id")
        worker_id = _require_identifier(worker_id, field="worker_id")
        permit_ref = _require_digest(permit_ref, field="permit_ref")
        refs = tuple(
            sorted({_require_digest(value, field="evidence_ref") for value in evidence_refs})
        )
        if operation_evidence_ref is not None:
            operation_evidence_ref = _require_digest(
                operation_evidence_ref,
                field="operation_evidence_ref",
            )
            if operation_evidence_ref not in refs:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Reclaim operation evidence must belong to its expiry evidence",
                )
        if operation_reason_code is not None:
            operation_reason_code = _require_identifier(
                operation_reason_code,
                field="operation_reason_code",
            )
            if operation_evidence_ref is None:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Reclaim operation reason requires operation evidence",
                )
        if not refs or permit_ref != canonical_digest(permit):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery reclaim requires exact permit and expiry evidence artifacts",
            )
        try:
            with self._immediate():
                work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
                if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                    self._assert_reconciliation_attempt_lineage_tx(work)
                if work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH and (
                    operation_evidence_ref is not None or operation_reason_code is not None
                ):
                    raise AgentKernelError(
                        ErrorCode.VALIDATION_ERROR,
                        "Only reconciliation reclaim may carry operation evidence",
                    )
                if (
                    work.state is RecoveryWorkState.RUNNING
                    and work.version == expected_work_version + 1
                    and work.lease_id == lease_id
                    and work.worker_id == worker_id
                ):
                    expected_purpose = (
                        LeasePurpose.RECONCILIATION
                        if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                        else LeasePurpose.RECOVERY
                    )
                    lease = self._assert_active_lease_tx(
                        tenant_id=tenant_id,
                        transaction_id=transaction_id,
                        lease_id=lease_id,
                        worker_id=worker_id,
                        fencing_token=work.fencing_token or 0,
                        purpose=expected_purpose,
                        at=acquired_at,
                    )
                    if (
                        lease.acquired_at != acquired_at
                        or lease.expires_at != expires_at
                        or lease.version != 0
                    ):
                        raise AgentKernelError(
                            ErrorCode.VERSION_CONFLICT,
                            "Recovery reclaim retry lease generation has progressed",
                            retryable=False,
                        )
                    if (
                        work.permit != permit
                        or work.permit_ref != permit_ref
                        or work.evidence_refs != refs
                        or work.updated_at != acquired_at
                        or work.attempt != work.version
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery reclaim retry changed its exact generation",
                        )
                    predecessor_row = self._connection.execute(
                        "SELECT * FROM enforced_worker_leases WHERE tenant_id = ? "
                        "AND transaction_id = ? AND fencing_token < ? "
                        "ORDER BY fencing_token DESC LIMIT 1",
                        (tenant_id, transaction_id, work.fencing_token),
                    ).fetchone()
                    predecessor_lease = (
                        None if predecessor_row is None else self._lease_from_row(predecessor_row)
                    )
                    if (
                        predecessor_lease is None
                        or predecessor_lease.purpose is not expected_purpose
                        or predecessor_lease.released_at != acquired_at
                        or predecessor_lease.expires_at > acquired_at
                        or predecessor_lease.version < 1
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery reclaim retry lost its exact predecessor lease",
                        )
                    authorization_round = self._get_authorization_round_tx(
                        tenant_id,
                        transaction_id,
                        work.authorization_round_id,
                    )
                    self._assert_recovery_round_bindings(work, authorization_round)
                    self._assert_recovery_capability_settlement_tx(
                        work,
                        authorization_round,
                        expected_state=CapabilityReservationState.COMMITTED,
                    )
                    handoff = self._assert_recovery_work_handoff_tx(work)
                    if handoff.closed_at is not None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery reclaim retry unexpectedly closed its action handoff",
                        )
                    self._validate_recovery_action_handoff_reverse_tx(
                        handoff,
                        tenant_id=work.tenant_id,
                    )
                    transaction, _stage, _dispatch = self._assert_recovery_target_tx(
                        work,
                        require_authorizable_state=False,
                    )
                    expected_target_states = {
                        RecoveryWorkKind.DISCARD_STAGING: {TransactionState.ABORTING},
                        RecoveryWorkKind.ROLLBACK: {TransactionState.ROLLING_BACK},
                        RecoveryWorkKind.COMPENSATE: {TransactionState.COMPENSATING},
                        RecoveryWorkKind.RECONCILE_DISPATCH: {
                            TransactionState.IN_DOUBT,
                        },
                    }[work.kind]
                    if transaction.state not in expected_target_states:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery reclaim retry target is outside its exact running phase",
                        )
                    if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                        predecessor_attempt_row = self._connection.execute(
                            "SELECT * FROM enforced_reconciliation_attempts "
                            "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
                            "AND attempt = ?",
                            (
                                tenant_id,
                                transaction_id,
                                recovery_id,
                                work.attempt - 1,
                            ),
                        ).fetchone()
                        if predecessor_attempt_row is not None:
                            predecessor_attempt = self._reconciliation_from_row(
                                predecessor_attempt_row
                            )
                            event_row = self._connection.execute(
                                "SELECT * FROM enforced_transaction_events "
                                "WHERE tenant_id = ? AND transaction_id = ? AND sequence = ?",
                                (tenant_id, transaction_id, transaction.version),
                            ).fetchone()
                            event = None if event_row is None else self._event_from_row(event_row)
                            if (
                                predecessor_attempt.outcome is not ReconciliationOutcome.UNKNOWN
                                or predecessor_attempt.version != 1
                                or predecessor_attempt.lease_id != predecessor_lease.lease_id
                                or predecessor_attempt.fencing_token
                                != predecessor_lease.fencing_token
                                or predecessor_attempt.completed_at != acquired_at
                                or predecessor_attempt.next_attempt_not_before != acquired_at
                                or predecessor_attempt.operation_evidence_ref
                                != operation_evidence_ref
                                or predecessor_attempt.operation_reason_code
                                != operation_reason_code
                                or predecessor_attempt.completion_evidence_refs != refs
                                or not set(refs).issubset(predecessor_attempt.evidence_refs)
                                or event is None
                                or event.event != TransitionEvent.RECONCILIATION_UNKNOWN.value
                                or event.recorded_at != acquired_at
                                or event.evidence_refs
                                != tuple(
                                    sorted(
                                        {
                                            _reconciliation_attempt_digest(predecessor_attempt),
                                            *refs,
                                        }
                                    )
                                )
                            ):
                                raise AgentKernelError(
                                    ErrorCode.INTEGRITY_ERROR,
                                    "Recovery reclaim retry lost its closed "
                                    "reconciliation predecessor",
                                )
                        elif (
                            operation_evidence_ref is not None or operation_reason_code is not None
                        ):
                            raise AgentKernelError(
                                ErrorCode.INTEGRITY_ERROR,
                                "Recovery reclaim retry introduced unused operation evidence",
                            )
                    return RecoveryClaimResult(
                        work,
                        lease,
                        EnforcedStoreDisposition.EXACT_RETRY,
                    )
                preview = self._preview_recovery_reclaim_tx(
                    work,
                    expected_work_version=expected_work_version,
                    lease_id=lease_id,
                    worker_id=worker_id,
                    acquired_at=acquired_at,
                    expires_at=expires_at,
                )
                if (
                    preview.permit != permit
                    or preview.permit_ref != permit_ref
                    or work.permit_ref not in refs
                    or permit_ref not in refs
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery reclaim differs from its preview or omits permit history",
                    )
                transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
                if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                    started_rows = self._connection.execute(
                        "SELECT * FROM enforced_reconciliation_attempts WHERE tenant_id = ? "
                        "AND transaction_id = ? AND recovery_id = ? AND completed_at IS NULL",
                        (tenant_id, transaction_id, recovery_id),
                    ).fetchall()
                    if transaction.state is TransactionState.RECONCILING:
                        if len(started_rows) != 1:
                            raise AgentKernelError(
                                ErrorCode.INTEGRITY_ERROR,
                                "Reclaiming reconciliation requires one expired STARTED attempt",
                            )
                        started = self._reconciliation_from_row(started_rows[0])
                        if (
                            started.attempt != work.attempt
                            or started.lease_id != work.lease_id
                            or started.fencing_token != work.fencing_token
                        ):
                            raise AgentKernelError(
                                ErrorCode.INTEGRITY_ERROR,
                                "Expired reconciliation attempt differs from its work lease",
                            )
                        if operation_evidence_ref is None:
                            raise AgentKernelError(
                                ErrorCode.VALIDATION_ERROR,
                                "Reclaiming a STARTED reconciliation requires expiry evidence",
                            )
                        closed = ReconciliationAttemptRecord.model_validate(
                            {
                                **started.model_dump(mode="python"),
                                "schema_version": "1.1",
                                "outcome": ReconciliationOutcome.UNKNOWN,
                                "evidence_refs": tuple(sorted({*started.evidence_refs, *refs})),
                                "operation_evidence_ref": operation_evidence_ref,
                                "operation_reason_code": operation_reason_code,
                                "completion_evidence_refs": refs,
                                "completed_at": acquired_at,
                                "next_attempt_not_before": acquired_at,
                                "version": 1,
                            }
                        )
                        self._update_reconciliation_attempt_tx(started, closed)
                        transaction, _ = self._apply_transition_tx(
                            transaction,
                            expected_version=transaction.version,
                            transition_event=TransitionEvent.RECONCILIATION_UNKNOWN,
                            recorded_at=acquired_at,
                            evidence_refs=(_reconciliation_attempt_digest(closed), *refs),
                        )
                    elif started_rows:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "IN_DOUBT recovery cannot retain a STARTED reconciliation attempt",
                        )
                purpose = (
                    LeasePurpose.RECONCILIATION
                    if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                    else LeasePurpose.RECOVERY
                )
                lease, created = self._acquire_worker_lease_tx(
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                    lease_id=lease_id,
                    worker_id=worker_id,
                    purpose=purpose,
                    acquired_at=acquired_at,
                    expires_at=expires_at,
                )
                if not created or lease != preview.lease:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Recovery reclaim fence changed after its artifact preview",
                        retryable=True,
                    )
                updated = RecoveryWorkRecord.model_validate(
                    {
                        **work.model_dump(mode="python"),
                        "permit": permit,
                        "permit_ref": permit_ref,
                        "lease_id": lease.lease_id,
                        "worker_id": lease.worker_id,
                        "fencing_token": lease.fencing_token,
                        "attempt": work.attempt + 1,
                        "version": work.version + 1,
                        "evidence_refs": refs,
                        "updated_at": acquired_at,
                    }
                )
                self._update_recovery_work_tx(work, updated)
                return RecoveryClaimResult(
                    updated,
                    lease,
                    (
                        EnforcedStoreDisposition.STORED
                        if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                        else EnforcedStoreDisposition.RECOVERY_NOW
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise _sqlite_integrity("Expired recovery reclaim failed closed", error) from error

    def _transition_owned_attempt_tx(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
        transaction_id: str,
        owner_version: int,
        owner_history_sequence: int,
        owner_history_digest: str,
        target_state: IntentAttemptState,
        evidence_digest: str,
        recorded_at: datetime,
    ) -> None:
        ledger = self._validate_intent_ledger(tenant_id, intent_hash)
        if (
            ledger.owner_transaction_id != transaction_id
            or ledger.owner_version != owner_version
            or ledger.head_sequence != owner_history_sequence
            or ledger.head_digest != owner_history_digest
        ):
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Intent ownership changed before recovery evidence was persisted",
                retryable=False,
            )
        if ledger.owner_state is target_state:
            return
        row = self._connection.execute(
            "SELECT state_version FROM enforced_intent_attempts WHERE tenant_id = ? "
            "AND intent_hash = ? AND transaction_id = ?",
            (tenant_id, intent_hash, transaction_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery intent owner lost its attempt projection",
            )
        self._record_intent_attempt_state_tx(
            tenant_id=tenant_id,
            intent_hash=intent_hash,
            transaction_id=transaction_id,
            expected_version=int(row["state_version"]),
            target_state=target_state,
            evidence_digest=evidence_digest,
            recorded_at=_timestamp(recorded_at),
        )

    def _release_recovery_lease_tx(
        self,
        work: RecoveryWorkRecord,
        *,
        released_at: datetime,
    ) -> WorkerLeaseRecord:
        if work.lease_id is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Claimed recovery work lost its lease binding",
            )
        lease = self._get_worker_lease_tx(
            work.tenant_id,
            work.transaction_id,
            work.lease_id,
        )
        if lease.released_at is not None:
            return lease
        updated = WorkerLeaseRecord.model_validate(
            {
                **lease.model_dump(mode="python"),
                "version": lease.version + 1,
                "released_at": released_at,
            }
        )
        return self._update_worker_lease_tx(lease, updated)

    def _assert_recovery_work_handoff_tx(
        self,
        work: RecoveryWorkRecord,
    ) -> RecoveryActionHandoff:
        """Return the exact immutable handoff associated with a recovery generation."""

        row = self._connection.execute(
            "SELECT * FROM enforced_recovery_action_handoffs "
            "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
            (work.tenant_id, work.transaction_id, work.recovery_id),
        ).fetchone()
        if row is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery work lost its durable action handoff",
            )
        handoff = self._recovery_action_handoff_from_row(
            row,
            tenant_id=work.tenant_id,
            target_transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        binding = handoff.binding
        action = handoff.action
        if (
            action is None
            or action.transaction_id != work.recovery_action_transaction_id
            or action.intent_hash != work.recovery_action_intent_hash
            or canonical_digest(action) != work.recovery_action_digest
            or binding.recovery_id != work.recovery_id
            or binding.root_recovery_id != work.root_recovery_id
            or binding.predecessor_recovery_id != work.predecessor_recovery_id
            or binding.recovery_ordinal != work.recovery_ordinal
            or binding.max_recovery_attempts != work.max_recovery_attempts
            or binding.not_before != work.not_before
            or binding.absolute_deadline != work.deadline
            or binding.target_transaction_id != work.transaction_id
            or binding.target_intent_hash != work.intent_hash
            or binding.adapter_manifest_digest != work.adapter_manifest_digest
            or binding.recovery_kind is not work.kind
            or binding.target_id != work.target_id
            or binding.target_evidence_ref != work.target_evidence_ref
            or binding.target_version_guard != work.target_version_guard
            or binding.target_owner_version != work.target_owner_version
            or binding.target_owner_history_sequence != work.target_owner_history_sequence
            or binding.target_owner_history_digest != work.target_owner_history_digest
            or handoff.binding_ref != canonical_digest(binding)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery work differs from its durable action handoff",
            )
        target_action = self._get_normalized_action(
            work.tenant_id,
            work.transaction_id,
        ).action
        self._assert_recovery_action_mirrors_target_tx(
            handoff,
            tenant_id=work.tenant_id,
            target_action=target_action,
        )
        return handoff

    def _close_recovery_work_handoff_tx(
        self,
        work: RecoveryWorkRecord,
        *,
        failure_evidence_status: RecoveryHandoffFailureEvidenceStatus,
        failure_evidence_ref: str | None,
        reason_code: str,
        recorded_at: datetime,
    ) -> None:
        """Close the immutable handoff associated with one terminal work generation."""

        failure_evidence_ref = _require_handoff_failure_evidence(
            failure_evidence_ref,
            status=failure_evidence_status,
            reason_code=reason_code,
        )
        handoff = self._assert_recovery_work_handoff_tx(work)
        if handoff.closed_at is not None:
            if (
                handoff.closed_at != recorded_at
                or handoff.failure_evidence_status is not failure_evidence_status
                or handoff.failure_evidence_ref != failure_evidence_ref
                or handoff.failure_reason_code != reason_code
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff terminal retry changed its exact evidence",
                )
            return
        terminal_sequence = self._next_recovery_handoff_terminal_sequence_tx(
            work.tenant_id,
            recorded_at=recorded_at,
        )
        closed = self._execute(
            "UPDATE enforced_recovery_action_handoffs SET "
            "closed_at = ?, terminal_sequence = ?, failure_evidence_status = ?, "
            "failure_evidence_ref = ?, failure_reason_code = ? "
            "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ? "
            "AND closed_at IS NULL",
            (
                _timestamp(recorded_at),
                terminal_sequence,
                failure_evidence_status.value,
                failure_evidence_ref,
                reason_code,
                work.tenant_id,
                work.transaction_id,
                work.recovery_id,
            ),
        )
        if closed.rowcount != 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Recovery handoff terminalization lost its exact CAS",
                retryable=True,
            )

    def _validate_recovery_work_handoff_lifecycle_tx(
        self,
        work: RecoveryWorkRecord,
    ) -> None:
        """Validate work-to-handoff association and terminal ownership settlement."""

        handoff = self._assert_recovery_work_handoff_tx(work)
        self._assert_authorized_handoff_lease_settlement_tx(work, handoff)
        if handoff.closed_at is not None:
            if work.state not in {
                RecoveryWorkState.FAILED,
                RecoveryWorkState.REVIEW_REQUIRED,
            }:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Closed recovery handoff is attached to non-failure work",
                )
            if handoff.closed_at != work.updated_at:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Closed recovery handoff timestamp differs from its terminal work",
                )
            allowed_reasons = {
                work.reason_code,
                (
                    None
                    if work.reason_code is None
                    else f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{work.reason_code}"
                ),
            }
            if handoff.failure_reason_code not in allowed_reasons:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff terminal reason differs from its work",
                )
            if (
                handoff.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.AVAILABLE
                and handoff.failure_evidence_ref not in work.evidence_refs
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff failure artifact is absent from its terminal work",
                )
        if work.lease_id is not None:
            bound_lease = self._get_worker_lease_tx(
                work.tenant_id,
                work.transaction_id,
                work.lease_id,
            )
            if work.state is RecoveryWorkState.RUNNING and (
                bound_lease.worker_id != work.worker_id
                or bound_lease.fencing_token != work.fencing_token
                or bound_lease.purpose
                is not (
                    LeasePurpose.RECONCILIATION
                    if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                    else LeasePurpose.RECOVERY
                )
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Running recovery handoff lost its exact active lease",
                )
            if work.state is RecoveryWorkState.RUNNING and bound_lease.released_at is not None:
                newer_lease = self._connection.execute(
                    "SELECT 1 FROM enforced_worker_leases WHERE tenant_id = ? "
                    "AND transaction_id = ? AND fencing_token > ? LIMIT 1",
                    (work.tenant_id, work.transaction_id, work.fencing_token),
                ).fetchone()
                if bound_lease.version < 1 or newer_lease is not None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Released running recovery lease is not its latest exact fence",
                    )
            if work.state is not RecoveryWorkState.RUNNING and bound_lease.released_at is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Non-running recovery handoff retains its execution lease",
                )
        completion_report = self._connection.execute(
            "SELECT 1 FROM enforced_recovery_completion_reports WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ? LIMIT 1",
            (work.tenant_id, work.transaction_id, work.recovery_id),
        ).fetchone()
        late_report = self._connection.execute(
            "SELECT 1 FROM enforced_late_recovery_reports WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ? LIMIT 1",
            (work.tenant_id, work.transaction_id, work.recovery_id),
        ).fetchone()
        unavailable_report = self._connection.execute(
            "SELECT 1 FROM enforced_recovery_evidence_unavailable_reports "
            "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? LIMIT 1",
            (work.tenant_id, work.transaction_id, work.recovery_id),
        ).fetchone()
        current_completed_attempt = self._connection.execute(
            "SELECT 1 FROM enforced_reconciliation_attempts WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ? "
            "AND attempt = ? AND completed_at IS NOT NULL LIMIT 1",
            (work.tenant_id, work.transaction_id, work.recovery_id, work.attempt),
        ).fetchone()
        if work.state in {RecoveryWorkState.SUCCEEDED, RecoveryWorkState.FAILED}:
            if (
                handoff.closed_at is None
                and completion_report is None
                and current_completed_attempt is None
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Finished recovery work lost its terminal completion evidence",
                )
            return
        if work.state is RecoveryWorkState.RETRIED:
            successor_rows = self._connection.execute(
                "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
                "AND transaction_id = ? AND predecessor_recovery_id = ?",
                (work.tenant_id, work.transaction_id, work.recovery_id),
            ).fetchall()
            if len(successor_rows) != 1:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Retried recovery work lost its unique successor generation",
                )
            successor = self._recovery_from_row(successor_rows[0])
            attempt = self._get_reconciliation_attempt_tx(
                work.tenant_id,
                work.transaction_id,
                work.recovery_id,
                work.attempt,
            )
            successor_round = self._get_authorization_round_tx(
                successor.tenant_id,
                successor.transaction_id,
                successor.authorization_round_id,
            )
            self._assert_recovery_work_handoff_tx(successor)
            authorized_successor_digest = self._authorized_recovery_work_digest_tx(successor)
            expected_progression_evidence = tuple(
                sorted(
                    {
                        *attempt.evidence_refs,
                        _reconciliation_attempt_digest(attempt),
                        successor_round.round_digest,
                        authorized_successor_digest,
                    }
                )
            )
            if (
                work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                or successor.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                or work.recovery_ordinal >= work.max_recovery_attempts
                or successor.root_recovery_id != work.root_recovery_id
                or successor.recovery_ordinal != work.recovery_ordinal + 1
                or successor.max_recovery_attempts != work.max_recovery_attempts
                or successor.deadline != work.deadline
                or successor.intent_hash != work.intent_hash
                or successor.adapter_manifest_digest != work.adapter_manifest_digest
                or successor.target_id != work.target_id
                or successor.target_version_guard != work.target_version_guard
                or successor.target_owner_version != work.target_owner_version
                or successor.target_owner_history_sequence != work.target_owner_history_sequence
                or successor.target_owner_history_digest != work.target_owner_history_digest
                or successor.recovery_action_transaction_id == work.recovery_action_transaction_id
                or successor.authorization_round_id == work.authorization_round_id
                or attempt.outcome is not ReconciliationOutcome.UNKNOWN
                or attempt.next_attempt_not_before is None
                or successor.not_before != attempt.next_attempt_not_before
                or successor.created_at < attempt.next_attempt_not_before
                or successor_round.evaluated_at < attempt.next_attempt_not_before
                or successor.created_at >= successor.deadline
                or successor_round.evaluated_at >= successor.deadline
                or work.updated_at != successor_round.evaluated_at
                or work.evidence_refs != expected_progression_evidence
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Retried recovery successor differs from its exact lineage",
                )
            return
        if work.state is not RecoveryWorkState.REVIEW_REQUIRED:
            return
        if (
            completion_report is None
            and late_report is None
            and unavailable_report is None
            and current_completed_attempt is None
            and handoff.closed_at is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Terminal recovery work retains an unclosed action handoff",
            )

    def _assert_recovery_action_mirrors_target_tx(
        self,
        handoff: RecoveryActionHandoff,
        *,
        tenant_id: str,
        target_action: NormalizedAction,
        action: NormalizedAction | None = None,
    ) -> None:
        """Require an attached recovery action to be the target's semantic mirror."""

        recovery_action = handoff.action if action is None else action
        if recovery_action is None:
            return
        binding = handoff.binding
        stored_action_digest = (
            canonical_digest(recovery_action)
            if action is not None
            else self._get_normalized_action(
                tenant_id,
                recovery_action.transaction_id,
            ).action_digest
        )
        binding_arguments = tuple(
            argument
            for argument in recovery_action.semantic_arguments
            if argument.argument_name == RECOVERY_ACTION_BINDING_ARGUMENT
        )
        remaining_arguments = tuple(
            argument
            for argument in recovery_action.semantic_arguments
            if argument.argument_name != RECOVERY_ACTION_BINDING_ARGUMENT
        )
        if (
            stored_action_digest != canonical_digest(recovery_action)
            or recovery_action.transaction_id == binding.target_transaction_id
            or recovery_action.tenant_id != target_action.tenant_id
            or recovery_action.principal_id != target_action.principal_id
            or recovery_action.goal_id != target_action.goal_id
            or recovery_action.run_id != target_action.run_id
            or recovery_action.trace_id != target_action.trace_id
            or recovery_action.actor_id != target_action.actor_id
            or recovery_action.on_behalf_of != target_action.on_behalf_of
            or recovery_action.agent_id != target_action.agent_id
            or recovery_action.adapter != target_action.adapter
            or recovery_action.adapter_version != target_action.adapter_version
            or recovery_action.operation != target_action.operation
            or recovery_action.adapter_manifest_digest != target_action.adapter_manifest_digest
            or recovery_action.configuration_digest != target_action.configuration_digest
            or recovery_action.normalizer_implementation != target_action.normalizer_implementation
            or recovery_action.normalizer_version != target_action.normalizer_version
            or recovery_action.normalizer_digest != target_action.normalizer_digest
            or recovery_action.operation_schema_ref != target_action.operation_schema_ref
            or recovery_action.operation_schema_digest != target_action.operation_schema_digest
            or recovery_action.risk_floor is not target_action.risk_floor
            or recovery_action.effect_domains != target_action.effect_domains
            or recovery_action.resource_uses != target_action.resource_uses
            or recovery_action.provenance != target_action.provenance
            or remaining_arguments != target_action.semantic_arguments
            or len(binding_arguments) != 1
            or binding_arguments[0].digest != handoff.binding_ref
            or binding.target_intent_hash != target_action.intent_hash
            or binding.target_normalized_action_digest != canonical_digest(target_action)
            or binding.adapter_manifest_digest != target_action.adapter_manifest_digest
            or binding.risk_class is not target_action.risk_floor
            or binding.effect_domains != target_action.effect_domains
            or binding.resource_uses_digest != canonical_digest(target_action.resource_uses)
            or binding.absolute_deadline != recovery_action.deadline
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff action differs from its target semantic mirror",
            )

    def _assert_no_orphan_active_recovery_lease_tx(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
    ) -> None:
        """Reject an active target lease not owned by work or an open pre-work handoff."""

        active_rows = self._connection.execute(
            "SELECT * FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND released_at IS NULL ORDER BY fencing_token",
            (tenant_id, transaction_id),
        ).fetchall()
        for row in active_rows:
            lease = self._lease_from_row(row)
            running_rows = self._connection.execute(
                "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
                "AND transaction_id = ? AND state = 'RUNNING' AND lease_id = ?",
                (tenant_id, transaction_id, lease.lease_id),
            ).fetchall()
            valid_running = False
            if len(running_rows) == 1:
                running = self._recovery_from_row(running_rows[0])
                valid_running = (
                    running.worker_id == lease.worker_id
                    and running.fencing_token == lease.fencing_token
                    and lease.purpose
                    is (
                        LeasePurpose.RECONCILIATION
                        if running.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                        else LeasePurpose.RECOVERY
                    )
                )
            handoff_rows = self._connection.execute(
                "SELECT * FROM enforced_recovery_action_handoffs AS handoff "
                "WHERE handoff.tenant_id = ? AND handoff.target_transaction_id = ? "
                "AND handoff.closed_at IS NULL AND handoff.created_at <= ? "
                "AND NOT EXISTS (SELECT 1 FROM enforced_recovery_work AS work "
                "WHERE work.tenant_id = handoff.tenant_id "
                "AND work.transaction_id = handoff.target_transaction_id "
                "AND work.recovery_id = handoff.recovery_id)",
                (tenant_id, transaction_id, _timestamp(lease.acquired_at)),
            ).fetchall()
            valid_handoff = False
            if len(handoff_rows) == 1 and lease.purpose is LeasePurpose.RECOVERY:
                handoff = self._recovery_action_handoff_from_row(
                    handoff_rows[0],
                    tenant_id=tenant_id,
                    target_transaction_id=transaction_id,
                    recovery_id=str(handoff_rows[0]["recovery_id"]),
                )
                self._assert_recovery_handoff_lease_lineage_tx(
                    handoff,
                    tenant_id=tenant_id,
                    expected_active=lease,
                )
                valid_handoff = True
            if not valid_running and not valid_handoff:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery target retains an orphan active worker lease",
                )

    def _assert_recovery_handoff_lease_lineage_tx(
        self,
        handoff: RecoveryActionHandoff,
        *,
        tenant_id: str,
        expected_active: WorkerLeaseRecord,
    ) -> None:
        """Validate the original handoff lease and every public reacquire generation."""

        rows = self._connection.execute(
            "SELECT * FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND fencing_token >= ? ORDER BY fencing_token",
            (
                tenant_id,
                handoff.binding.target_transaction_id,
                handoff.handoff_fencing_token,
            ),
        ).fetchall()
        leases = tuple(self._lease_from_row(row) for row in rows)
        if not leases:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff lost its lease lineage",
            )
        original = leases[0]
        if (
            original.lease_id != handoff.handoff_lease_id
            or original.worker_id != handoff.handoff_worker_id
            or original.fencing_token != handoff.handoff_fencing_token
            or original.acquired_at != handoff.created_at
            or original.purpose is not LeasePurpose.RECOVERY
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff original lease differs from its immutable identity",
            )
        previous: WorkerLeaseRecord | None = None
        for lease in leases:
            if (
                lease.purpose is not LeasePurpose.RECOVERY
                or lease.expires_at > handoff.binding.absolute_deadline
                or (
                    previous is not None
                    and (
                        previous.released_at is None
                        or previous.released_at > lease.acquired_at
                        or previous.fencing_token >= lease.fencing_token
                    )
                )
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff reacquire lease lineage is invalid",
                )
            previous = lease
        if leases[-1] != expected_active or expected_active.released_at is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff active lease is not its latest fenced generation",
            )

    def _validate_recovery_action_handoff_reverse_tx(
        self,
        handoff: RecoveryActionHandoff,
        *,
        tenant_id: str,
        bounded: bool = False,
    ) -> None:
        """Validate one handoff against either its work or exact pre-work lifecycle."""

        binding = handoff.binding
        invalid_initial_lineage = binding.recovery_ordinal == 1 and (
            binding.root_recovery_id != binding.recovery_id
            or binding.predecessor_recovery_id is not None
        )
        invalid_retry_lineage = binding.recovery_ordinal > 1 and (
            binding.recovery_kind is not RecoveryWorkKind.RECONCILE_DISPATCH
            or binding.root_recovery_id == binding.recovery_id
            or binding.predecessor_recovery_id is None
            or binding.predecessor_recovery_id == binding.recovery_id
        )
        if invalid_initial_lineage or invalid_retry_lineage:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff has an invalid durable lineage",
            )
        if (
            binding.recovery_kind is RecoveryWorkKind.RECONCILE_DISPATCH
            and binding.recovery_ordinal == 1
        ):
            duplicate_root = self._connection.execute(
                "SELECT 1 FROM enforced_recovery_action_handoffs "
                "WHERE tenant_id = ? AND target_transaction_id = ? AND target_id = ? "
                "AND recovery_kind = 'RECONCILE_DISPATCH' AND recovery_id != ? "
                "AND json_extract(binding_json, '$.recovery_ordinal') = 1 LIMIT 1",
                (
                    tenant_id,
                    binding.target_transaction_id,
                    binding.target_id,
                    binding.recovery_id,
                ),
            ).fetchone()
            if duplicate_root is not None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Dispatch target has more than one initial reconciliation lineage",
                )
        work_row = self._connection.execute(
            "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ?",
            (
                tenant_id,
                binding.target_transaction_id,
                binding.recovery_id,
            ),
        ).fetchone()
        if work_row is not None:
            work = self._recovery_from_row(work_row)
            self._validate_recovery_work_handoff_lifecycle_tx(work)
            transaction = (
                self._get_enforced_transaction_head_tx(
                    tenant_id,
                    work.transaction_id,
                )
                if bounded
                else self._get_enforced_transaction_tx(
                    tenant_id,
                    work.transaction_id,
                )
            )
            if not self._root_recovery_binding_matches_durable_bounds_tx(
                transaction,
                binding,
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery work handoff exceeds its durable root bounds",
                )
            target_action = self._get_normalized_action(
                tenant_id,
                work.transaction_id,
            ).action
            self._assert_recovery_action_mirrors_target_tx(
                handoff,
                tenant_id=tenant_id,
                target_action=target_action,
            )
            authorization_round = self._get_authorization_round_tx(
                tenant_id,
                work.transaction_id,
                work.authorization_round_id,
            )
            capability_state = (
                None
                if authorization_round.verdict is not AuthorizationVerdict.ELIGIBLE
                else (
                    CapabilityReservationState.RESERVED
                    if work.state is RecoveryWorkState.PENDING
                    else (
                        CapabilityReservationState.RELEASED
                        if work.permit is None
                        else CapabilityReservationState.COMMITTED
                    )
                )
            )
            recovery_owner = self._connection.execute(
                "SELECT owner_transaction_id, owner_version FROM enforced_intent_owners "
                "WHERE tenant_id = ? AND intent_hash = ?",
                (tenant_id, work.recovery_action_intent_hash),
            ).fetchone()
            if handoff.closed_at is None or (
                recovery_owner is not None
                and str(recovery_owner["owner_transaction_id"])
                == work.recovery_action_transaction_id
                and _require_stored_integer(
                    recovery_owner["owner_version"],
                    field="recovery action current intent owner version",
                )
                == work.owner_version
            ):
                if bounded:
                    self._assert_bounded_recovery_capability_settlement_tx(
                        work,
                        authorization_round,
                        expected_state=capability_state,
                    )
                else:
                    self._assert_recovery_capability_settlement_tx(
                        work,
                        authorization_round,
                        expected_state=capability_state,
                    )
            active_lease_rows = self._connection.execute(
                "SELECT * FROM enforced_worker_leases WHERE tenant_id = ? "
                "AND transaction_id = ? AND released_at IS NULL ORDER BY fencing_token",
                (tenant_id, work.transaction_id),
            ).fetchall()
            if work.state is RecoveryWorkState.PENDING and active_lease_rows:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unclaimed recovery handoff retains an active execution lease",
                )
            if work.state is RecoveryWorkState.RUNNING:
                expected_target_states = {
                    RecoveryWorkKind.DISCARD_STAGING: {TransactionState.ABORTING},
                    RecoveryWorkKind.ROLLBACK: {TransactionState.ROLLING_BACK},
                    RecoveryWorkKind.COMPENSATE: {TransactionState.COMPENSATING},
                    RecoveryWorkKind.RECONCILE_DISPATCH: {
                        TransactionState.IN_DOUBT,
                        TransactionState.RECONCILING,
                    },
                }[work.kind]
                active_leases = tuple(self._lease_from_row(row) for row in active_lease_rows)
                running_lease = (
                    None
                    if work.lease_id is None
                    else self._get_worker_lease_tx(
                        tenant_id,
                        work.transaction_id,
                        work.lease_id,
                    )
                )
                released_current = (
                    running_lease is not None
                    and running_lease.released_at is not None
                    and not active_leases
                )
                active_current = (
                    len(active_leases) == 1
                    and work.lease_id is not None
                    and active_leases[0].lease_id == work.lease_id
                    and active_leases[0].worker_id == work.worker_id
                    and active_leases[0].fencing_token == work.fencing_token
                )
                if (
                    not active_current and not released_current
                ) or transaction.state not in expected_target_states:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Running recovery handoff differs from its exact active generation",
                    )
            elif work.state is RecoveryWorkState.PENDING:
                expected_target_state = {
                    RecoveryWorkKind.DISCARD_STAGING: TransactionState.ABORTING,
                    RecoveryWorkKind.ROLLBACK: TransactionState.FAILED,
                    RecoveryWorkKind.COMPENSATE: TransactionState.FAILED,
                    RecoveryWorkKind.RECONCILE_DISPATCH: TransactionState.IN_DOUBT,
                }[work.kind]
                if transaction.state is not expected_target_state:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Pending recovery handoff target is outside its generation",
                    )
            elif (
                work.state is RecoveryWorkState.RETRY_SCHEDULED
                and transaction.state is not TransactionState.IN_DOUBT
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Scheduled reconciliation handoff target is not IN_DOUBT",
                )
            if handoff.closed_at is not None:
                scheduled_attempt: ReconciliationAttemptRecord | None = None
                scheduled_deadline_terminal = False
                if (
                    work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                    and work.state is RecoveryWorkState.REVIEW_REQUIRED
                    and work.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
                    and work.attempt > 0
                    and handoff.closed_at >= work.deadline
                ):
                    attempt_row = self._connection.execute(
                        "SELECT * FROM enforced_reconciliation_attempts "
                        "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
                        "AND attempt = ?",
                        (
                            tenant_id,
                            work.transaction_id,
                            work.recovery_id,
                            work.attempt,
                        ),
                    ).fetchone()
                    scheduled_attempt = (
                        None if attempt_row is None else self._reconciliation_from_row(attempt_row)
                    )
                    scheduled_deadline_terminal = (
                        scheduled_attempt is not None
                        and scheduled_attempt.outcome is ReconciliationOutcome.UNKNOWN
                        and scheduled_attempt.completed_at is not None
                        and scheduled_attempt.next_attempt_not_before is not None
                        and scheduled_attempt.next_attempt_not_before < work.deadline
                    )
                expected_state = {
                    RecoveryWorkKind.DISCARD_STAGING: TransactionState.RECOVERY_FAILED,
                    RecoveryWorkKind.ROLLBACK: TransactionState.RECOVERY_FAILED,
                    RecoveryWorkKind.COMPENSATE: (
                        TransactionState.COMPENSATION_FAILED
                        if work.permit is not None
                        else TransactionState.RECOVERY_FAILED
                    ),
                    RecoveryWorkKind.RECONCILE_DISPATCH: TransactionState.IN_DOUBT,
                }[work.kind]
                if transaction.state is not expected_state:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Terminal handoff page target state differs from its work",
                    )
                terminal_dispatch_row = self._connection.execute(
                    "SELECT 1 FROM enforced_commit_dispatches WHERE tenant_id = ? "
                    "AND transaction_id = ? LIMIT 1",
                    (tenant_id, work.transaction_id),
                ).fetchone()
                terminal_dispatch = (
                    None
                    if terminal_dispatch_row is None
                    else self._get_commit_dispatch_head_tx(
                        tenant_id,
                        work.transaction_id,
                    )
                )
                if work.kind is RecoveryWorkKind.DISCARD_STAGING:
                    stage = self._get_stage_material_tx(tenant_id, work.transaction_id)
                    if (
                        stage.stage_id != work.target_id
                        or stage.target_version_guard != work.target_version_guard
                        or stage.state is not StageMaterialState.DISCARD_FAILED
                        or stage.updated_at != handoff.closed_at
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Terminal handoff page differs from failed stage material",
                        )
                else:
                    if terminal_dispatch is None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Terminal recovery handoff lost its dispatch target",
                        )
                    dispatch_identity_changed = (
                        terminal_dispatch.dispatch_id != work.target_id
                        or terminal_dispatch.intent_hash != work.intent_hash
                        or terminal_dispatch.owner_version != work.target_owner_version
                        or terminal_dispatch.permit.target_version_guard
                        != work.target_version_guard
                    )
                    dispatch_evidence_changed = (
                        canonical_digest(terminal_dispatch) != work.target_evidence_ref
                    )
                    if dispatch_identity_changed or (
                        dispatch_evidence_changed and not scheduled_deadline_terminal
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Terminal handoff page differs from its dispatch head",
                        )
                    if scheduled_deadline_terminal:
                        if scheduled_attempt is None:
                            raise AgentKernelError(
                                ErrorCode.INTEGRITY_ERROR,
                                "Scheduled deadline handoff lost its reconciliation attempt",
                            )
                        matching_outcomes = tuple(
                            candidate
                            for candidate in self._validate_dispatch_outcome_chain_tx(
                                terminal_dispatch
                            )
                            if candidate.classification is ReconciliationOutcome.UNKNOWN
                            and candidate.recorded_at == scheduled_attempt.completed_at
                            and candidate.evidence_refs == scheduled_attempt.evidence_refs
                        )
                        if (
                            terminal_dispatch.state is not CommitDispatchState.IN_DOUBT
                            or terminal_dispatch.updated_at != scheduled_attempt.completed_at
                            or len(matching_outcomes) != 1
                        ):
                            raise AgentKernelError(
                                ErrorCode.INTEGRITY_ERROR,
                                "Scheduled deadline handoff differs from its UNKNOWN outcome",
                            )
                self._validate_bounded_intent_history_binding_tx(
                    tenant_id=tenant_id,
                    intent_hash=work.recovery_action_intent_hash,
                    transaction_id=work.recovery_action_transaction_id,
                    owner_version=work.owner_version,
                    history_sequence=work.owner_history_sequence,
                    history_digest=work.owner_history_digest,
                )
                self._validate_bounded_intent_history_binding_tx(
                    tenant_id=tenant_id,
                    intent_hash=work.intent_hash,
                    transaction_id=work.transaction_id,
                    owner_version=work.target_owner_version,
                    history_sequence=work.target_owner_history_sequence,
                    history_digest=work.target_owner_history_digest,
                )
                late_terminal = self._get_late_recovery_report_tx(
                    tenant_id,
                    work.transaction_id,
                    work.recovery_id,
                )
                unavailable_terminal = self._get_recovery_evidence_unavailable_tx(
                    tenant_id,
                    work.transaction_id,
                    work.recovery_id,
                )
                if late_terminal is not None and unavailable_terminal is not None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Closed recovery handoff has conflicting terminal reports",
                    )
                recovery_action_terminal_state = (
                    IntentAttemptState.REVIEW_REQUIRED
                    if late_terminal is not None
                    or (
                        unavailable_terminal is not None
                        and work.permit is not None
                        and unavailable_terminal.boundary
                        not in {
                            "POST_CLAIM_SETUP",
                            "RECONCILIATION_SETUP_OR_QUERY",
                        }
                    )
                    or scheduled_deadline_terminal
                    else IntentAttemptState.NO_EFFECT_CONFIRMED
                )
                self._validate_bounded_intent_attempt_lifecycle_tx(
                    tenant_id=tenant_id,
                    intent_hash=work.recovery_action_intent_hash,
                    transaction_id=work.recovery_action_transaction_id,
                    expected_states=frozenset({recovery_action_terminal_state}),
                )
                self._validate_bounded_intent_attempt_lifecycle_tx(
                    tenant_id=tenant_id,
                    intent_hash=work.intent_hash,
                    transaction_id=work.transaction_id,
                    expected_states=frozenset(
                        {
                            IntentAttemptState.NO_EFFECT_CONFIRMED,
                            IntentAttemptState.REVIEW_REQUIRED,
                            IntentAttemptState.RECONCILE_REQUIRED,
                        }
                    ),
                )
                target_owner = self._connection.execute(
                    "SELECT owner_transaction_id, owner_version "
                    "FROM enforced_intent_owners WHERE tenant_id = ? AND intent_hash = ?",
                    (tenant_id, work.intent_hash),
                ).fetchone()
                if (
                    target_owner is not None
                    and str(target_owner["owner_transaction_id"]) == work.transaction_id
                    and _require_stored_integer(
                        target_owner["owner_version"],
                        field="terminal recovery target current owner version",
                    )
                    == work.target_owner_version
                ):
                    if bounded:
                        self._assert_bounded_target_capability_settlement_tx(
                            tenant_id=tenant_id,
                            transaction_id=work.transaction_id,
                            intent_hash=work.intent_hash,
                            owner_version=work.target_owner_version,
                            dispatch=terminal_dispatch,
                        )
                    else:
                        self._assert_target_capability_settlement_tx(
                            tenant_id=tenant_id,
                            transaction_id=work.transaction_id,
                            intent_hash=work.intent_hash,
                            owner_version=work.target_owner_version,
                            dispatch=terminal_dispatch,
                        )
            else:
                self._validate_bounded_intent_binding_tx(
                    tenant_id=tenant_id,
                    intent_hash=work.recovery_action_intent_hash,
                    transaction_id=work.recovery_action_transaction_id,
                    owner_version=work.owner_version,
                    history_sequence=work.owner_history_sequence,
                    history_digest=work.owner_history_digest,
                )
                self._validate_bounded_intent_binding_tx(
                    tenant_id=tenant_id,
                    intent_hash=work.intent_hash,
                    transaction_id=work.transaction_id,
                    owner_version=work.target_owner_version,
                    history_sequence=work.target_owner_history_sequence,
                    history_digest=work.target_owner_history_digest,
                )
            self._assert_no_orphan_active_recovery_lease_tx(
                tenant_id=tenant_id,
                transaction_id=work.transaction_id,
            )
            return
        if binding.recovery_ordinal > 1:
            predecessor_row = self._connection.execute(
                "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
                "AND transaction_id = ? AND recovery_id = ?",
                (
                    tenant_id,
                    binding.target_transaction_id,
                    binding.predecessor_recovery_id,
                ),
            ).fetchone()
            predecessor = (
                None if predecessor_row is None else self._recovery_from_row(predecessor_row)
            )
            expected_successor_failure_reason = {
                RecoveryHandoffFailureEvidenceStatus.AVAILABLE: (ErrorCode.DEADLINE_EXCEEDED.value),
                RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE: (
                    f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:{ErrorCode.DEADLINE_EXCEEDED.value}"
                ),
            }.get(handoff.failure_evidence_status)
            common_predecessor = (
                predecessor is not None
                and predecessor.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                and predecessor.root_recovery_id == binding.root_recovery_id
                and predecessor.recovery_ordinal + 1 == binding.recovery_ordinal
                and predecessor.max_recovery_attempts == binding.max_recovery_attempts
                and predecessor.deadline == binding.absolute_deadline
            )
            open_scheduled_predecessor = (
                common_predecessor
                and handoff.closed_at is None
                and predecessor is not None
                and predecessor.state is RecoveryWorkState.RETRY_SCHEDULED
            )
            closed_deadline_scheduled_predecessor = False
            closed_deadline_predecessor = False
            if (
                common_predecessor
                and handoff.closed_at == binding.absolute_deadline
                and expected_successor_failure_reason is not None
                and handoff.failure_reason_code == expected_successor_failure_reason
                and predecessor is not None
            ):
                predecessor_handoff = self._assert_recovery_work_handoff_tx(predecessor)
                closed_deadline_scheduled_predecessor = (
                    predecessor.state is RecoveryWorkState.RETRY_SCHEDULED
                    and predecessor_handoff.closed_at is None
                )
                if (
                    predecessor.state is RecoveryWorkState.REVIEW_REQUIRED
                    and predecessor.reason_code == ErrorCode.DEADLINE_EXCEEDED.value
                    and predecessor.updated_at == binding.absolute_deadline
                ):
                    expected_predecessor_failure_reason = {
                        RecoveryHandoffFailureEvidenceStatus.AVAILABLE: (
                            ErrorCode.DEADLINE_EXCEEDED.value
                        ),
                        RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE: (
                            f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:"
                            f"{ErrorCode.DEADLINE_EXCEEDED.value}"
                        ),
                    }.get(predecessor_handoff.failure_evidence_status)
                    closed_deadline_predecessor = (
                        predecessor_handoff.closed_at == binding.absolute_deadline
                        and expected_predecessor_failure_reason is not None
                        and predecessor_handoff.failure_reason_code
                        == expected_predecessor_failure_reason
                    )
            if (
                not open_scheduled_predecessor
                and not closed_deadline_scheduled_predecessor
                and not closed_deadline_predecessor
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation pre-work handoff lost its scheduled predecessor",
                )
            if predecessor is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation pre-work handoff lost its scheduled predecessor",
                )
            predecessor_attempt = self._get_reconciliation_attempt_tx(
                tenant_id,
                binding.target_transaction_id,
                predecessor.recovery_id,
                predecessor.attempt,
            )
            if (
                predecessor_attempt.outcome is not ReconciliationOutcome.UNKNOWN
                or predecessor_attempt.completed_at is None
                or predecessor_attempt.next_attempt_not_before is None
                or predecessor_attempt.next_attempt_not_before != binding.not_before
                or predecessor_attempt.next_attempt_not_before >= binding.absolute_deadline
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation pre-work handoff differs from predecessor backoff",
                )
        overlapping_prework = self._connection.execute(
            "SELECT 1 FROM enforced_recovery_action_handoffs AS other "
            "WHERE other.tenant_id = ? AND other.target_transaction_id = ? "
            "AND other.target_id = ? AND other.recovery_id != ? "
            "AND other.closed_at IS NULL AND NOT EXISTS ("
            "SELECT 1 FROM enforced_recovery_work AS linked "
            "WHERE linked.tenant_id = other.tenant_id "
            "AND linked.transaction_id = other.target_transaction_id "
            "AND linked.recovery_id = other.recovery_id) LIMIT 1",
            (
                tenant_id,
                binding.target_transaction_id,
                binding.target_id,
                binding.recovery_id,
            ),
        ).fetchone()
        if overlapping_prework is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target generation has duplicate open pre-work handoffs",
            )
        transaction = (
            self._get_enforced_transaction_head_tx(
                tenant_id,
                binding.target_transaction_id,
            )
            if bounded
            else self._get_enforced_transaction_tx(
                tenant_id,
                binding.target_transaction_id,
            )
        )
        if not self._root_recovery_binding_matches_durable_bounds_tx(
            transaction,
            binding,
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Pre-work recovery handoff exceeds its durable root bounds",
            )
        target_action = self._get_normalized_action(
            tenant_id,
            binding.target_transaction_id,
        ).action
        if (
            transaction.intent_hash != binding.target_intent_hash
            or transaction.normalized_action_digest != binding.target_normalized_action_digest
            or canonical_digest(target_action) != binding.target_normalized_action_digest
            or transaction.adapter_manifest_digest != binding.adapter_manifest_digest
            or target_action.risk_floor is not binding.risk_class
            or target_action.effect_domains != binding.effect_domains
            or canonical_digest(target_action.resource_uses) != binding.resource_uses_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff differs from its typed target action",
            )
        allowed_target_states = (
            {
                RecoveryWorkKind.DISCARD_STAGING: {
                    IntentAttemptState.ACTIVE,
                    IntentAttemptState.NO_EFFECT_CONFIRMED,
                    IntentAttemptState.REVIEW_REQUIRED,
                },
                RecoveryWorkKind.ROLLBACK: {IntentAttemptState.REVIEW_REQUIRED},
                RecoveryWorkKind.COMPENSATE: {IntentAttemptState.REVIEW_REQUIRED},
                RecoveryWorkKind.RECONCILE_DISPATCH: {
                    IntentAttemptState.RECONCILE_REQUIRED,
                    IntentAttemptState.REVIEW_REQUIRED,
                },
            }[binding.recovery_kind]
            if handoff.closed_at is None
            else {
                RecoveryWorkKind.DISCARD_STAGING: {
                    IntentAttemptState.NO_EFFECT_CONFIRMED,
                    IntentAttemptState.REVIEW_REQUIRED,
                },
                RecoveryWorkKind.ROLLBACK: {IntentAttemptState.REVIEW_REQUIRED},
                RecoveryWorkKind.COMPENSATE: {IntentAttemptState.REVIEW_REQUIRED},
                RecoveryWorkKind.RECONCILE_DISPATCH: {
                    IntentAttemptState.RECONCILE_REQUIRED,
                    IntentAttemptState.REVIEW_REQUIRED,
                },
            }[binding.recovery_kind]
        )
        if handoff.closed_at is not None:
            if bounded:
                self._validate_bounded_intent_history_binding_tx(
                    tenant_id=tenant_id,
                    intent_hash=binding.target_intent_hash,
                    transaction_id=binding.target_transaction_id,
                    owner_version=binding.target_owner_version,
                    history_sequence=binding.target_owner_history_sequence,
                    history_digest=binding.target_owner_history_digest,
                )
            else:
                target_ledger = self._validate_intent_ledger(
                    tenant_id,
                    binding.target_intent_hash,
                )
                target_history = (
                    target_ledger.entries[binding.target_owner_history_sequence]
                    if binding.target_owner_history_sequence < len(target_ledger.entries)
                    else None
                )
                if (
                    target_history is None
                    or target_history.owner_transaction_id != binding.target_transaction_id
                    or target_history.owner_version != binding.target_owner_version
                    or target_history.history_digest != binding.target_owner_history_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery handoff target differs from its historical binding",
                    )
            target_state = self._validate_bounded_intent_attempt_lifecycle_tx(
                tenant_id=tenant_id,
                intent_hash=binding.target_intent_hash,
                transaction_id=binding.target_transaction_id,
                expected_states=frozenset(allowed_target_states),
            ).state
        elif bounded:
            target_state, _target_evidence, _target_updated_at = (
                self._validate_bounded_intent_binding_tx(
                    tenant_id=tenant_id,
                    intent_hash=binding.target_intent_hash,
                    transaction_id=binding.target_transaction_id,
                    owner_version=binding.target_owner_version,
                    history_sequence=binding.target_owner_history_sequence,
                    history_digest=binding.target_owner_history_digest,
                )
            )
        else:
            target_ledger = self._validate_intent_ledger(
                tenant_id,
                binding.target_intent_hash,
            )
            target_history = (
                target_ledger.entries[binding.target_owner_history_sequence]
                if binding.target_owner_history_sequence < len(target_ledger.entries)
                else None
            )
            if (
                target_ledger.owner_transaction_id != binding.target_transaction_id
                or target_ledger.owner_version != binding.target_owner_version
                or target_history is None
                or target_history.owner_transaction_id != binding.target_transaction_id
                or target_history.owner_version != binding.target_owner_version
                or target_history.history_digest != binding.target_owner_history_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff target ownership differs from its bound history",
                )
            target_state = target_ledger.owner_state
        if target_state not in allowed_target_states:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff target intent is outside its lifecycle",
            )
        dispatch_row = self._connection.execute(
            "SELECT * FROM enforced_commit_dispatches WHERE tenant_id = ? AND transaction_id = ?",
            (tenant_id, binding.target_transaction_id),
        ).fetchone()
        dispatch = (
            None
            if dispatch_row is None
            else (
                self._get_commit_dispatch_head_tx(
                    tenant_id,
                    binding.target_transaction_id,
                )
                if bounded
                else self._get_commit_dispatch_tx(
                    tenant_id,
                    binding.target_transaction_id,
                )
            )
        )
        if binding.recovery_kind is RecoveryWorkKind.DISCARD_STAGING:
            stage = self._get_stage_material_tx(tenant_id, binding.target_transaction_id)
            if (
                stage.stage_id != binding.target_id
                or stage.target_version_guard != binding.target_version_guard
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff differs from its stage target identity",
                )
            if handoff.closed_at is None:
                valid_target = (
                    transaction.state is TransactionState.ABORTING
                    and stage.state
                    not in {StageMaterialState.DISCARDED, StageMaterialState.DISCARD_FAILED}
                    and canonical_digest(stage) == binding.target_evidence_ref
                )
            else:
                operation_evidence_ref = handoff.failure_evidence_ref or handoff.binding_ref
                valid_target = (
                    transaction.state is TransactionState.RECOVERY_FAILED
                    and stage.state is StageMaterialState.DISCARD_FAILED
                    and stage.discard_evidence_ref == operation_evidence_ref
                    and stage.updated_at == handoff.closed_at
                )
        else:
            if (
                dispatch is None
                or dispatch.dispatch_id != binding.target_id
                or dispatch.permit.target_version_guard != binding.target_version_guard
                or canonical_digest(dispatch) != binding.target_evidence_ref
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery handoff differs from its dispatch target generation",
                )
            expected_state = (
                {
                    RecoveryWorkKind.ROLLBACK: TransactionState.FAILED,
                    RecoveryWorkKind.COMPENSATE: TransactionState.FAILED,
                    RecoveryWorkKind.RECONCILE_DISPATCH: TransactionState.IN_DOUBT,
                }[binding.recovery_kind]
                if handoff.closed_at is None
                else {
                    RecoveryWorkKind.ROLLBACK: TransactionState.RECOVERY_FAILED,
                    RecoveryWorkKind.COMPENSATE: TransactionState.RECOVERY_FAILED,
                    RecoveryWorkKind.RECONCILE_DISPATCH: TransactionState.IN_DOUBT,
                }[binding.recovery_kind]
            )
            valid_target = transaction.state is expected_state
        if not valid_target:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff target is outside its pre-work lifecycle",
            )
        self._assert_recovery_action_mirrors_target_tx(
            handoff,
            tenant_id=tenant_id,
            target_action=target_action,
        )
        if handoff.action is not None:
            expected_action_state = (
                IntentAttemptState.ACTIVE
                if handoff.closed_at is None
                else IntentAttemptState.NO_EFFECT_CONFIRMED
            )
            if handoff.closed_at is not None:
                self._validate_bounded_intent_attempt_lifecycle_tx(
                    tenant_id=tenant_id,
                    intent_hash=handoff.action.intent_hash,
                    transaction_id=handoff.action.transaction_id,
                    expected_states=frozenset({expected_action_state}),
                )
            elif bounded:
                self._validate_bounded_intent_settlement_tx(
                    tenant_id=tenant_id,
                    intent_hash=handoff.action.intent_hash,
                    transaction_id=handoff.action.transaction_id,
                    expected_states=frozenset({expected_action_state}),
                )
            else:
                recovery_ledger = self._validate_intent_ledger(
                    tenant_id,
                    handoff.action.intent_hash,
                )
                if (
                    recovery_ledger.owner_transaction_id != handoff.action.transaction_id
                    or recovery_ledger.owner_state is not expected_action_state
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery handoff action intent differs from its lifecycle",
                    )
            action_reservation = self._connection.execute(
                "SELECT 1 FROM enforced_capability_chain_reservations "
                "WHERE tenant_id = ? AND intent_hash = ? LIMIT 1",
                (tenant_id, handoff.action.intent_hash),
            ).fetchone()
            action_owner = self._connection.execute(
                "SELECT owner_transaction_id FROM enforced_intent_owners "
                "WHERE tenant_id = ? AND intent_hash = ?",
                (tenant_id, handoff.action.intent_hash),
            ).fetchone()
            if action_reservation is not None and (
                handoff.closed_at is None
                or action_owner is None
                or str(action_owner["owner_transaction_id"]) == handoff.action.transaction_id
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Pre-work recovery handoff gained capability authority",
                )
        active_lease_rows = self._connection.execute(
            "SELECT * FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND released_at IS NULL ORDER BY fencing_token",
            (tenant_id, binding.target_transaction_id),
        ).fetchall()
        if handoff.closed_at is not None:
            if active_lease_rows:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Closed recovery handoff retains an active worker lease",
                )
            target_owner = self._connection.execute(
                "SELECT owner_transaction_id, owner_version FROM enforced_intent_owners "
                "WHERE tenant_id = ? AND intent_hash = ?",
                (tenant_id, binding.target_intent_hash),
            ).fetchone()
            if (
                target_owner is not None
                and str(target_owner["owner_transaction_id"]) == binding.target_transaction_id
                and _require_stored_integer(
                    target_owner["owner_version"],
                    field="closed recovery handoff target owner version",
                )
                == binding.target_owner_version
            ):
                if bounded:
                    self._assert_bounded_target_capability_settlement_tx(
                        tenant_id=tenant_id,
                        transaction_id=binding.target_transaction_id,
                        intent_hash=binding.target_intent_hash,
                        owner_version=binding.target_owner_version,
                        dispatch=dispatch,
                    )
                else:
                    self._assert_target_capability_settlement_tx(
                        tenant_id=tenant_id,
                        transaction_id=binding.target_transaction_id,
                        intent_hash=binding.target_intent_hash,
                        owner_version=binding.target_owner_version,
                        dispatch=dispatch,
                    )
        elif any(
            (lease := self._lease_from_row(row)).purpose is not LeasePurpose.RECOVERY
            or lease.acquired_at < handoff.created_at
            or lease.expires_at > binding.absolute_deadline
            for row in active_lease_rows
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Open recovery handoff has a conflicting worker lease",
            )

    def _assert_terminal_intent_state_tx(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
        transaction_id: str,
        owner_version: int,
        history_sequence: int,
        history_digest: str,
        expected_states: set[IntentAttemptState],
        label: str,
    ) -> None:
        ledger = self._validate_intent_ledger(tenant_id, intent_hash)
        historical = (
            ledger.entries[history_sequence] if history_sequence < len(ledger.entries) else None
        )
        if (
            ledger.owner_transaction_id != transaction_id
            or ledger.owner_version != owner_version
            or ledger.owner_state not in expected_states
            or historical is None
            or historical.owner_transaction_id != transaction_id
            or historical.owner_version != owner_version
            or historical.history_digest != history_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                f"Terminal {label} intent settlement differs from its bound generation",
            )

    def _assert_terminal_recovery_target_settlement_tx(
        self,
        work: RecoveryWorkRecord,
        *,
        terminal_evidence_ref: str,
        recorded_at: datetime,
    ) -> None:
        transaction = self._get_enforced_transaction_tx(
            work.tenant_id,
            work.transaction_id,
        )
        if (
            transaction.intent_hash != work.intent_hash
            or transaction.adapter_manifest_digest != work.adapter_manifest_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Terminal recovery target differs from its work identity",
            )
        if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
            if transaction.state is not TransactionState.IN_DOUBT:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Terminal reconciliation work must leave its target IN_DOUBT",
                )
        else:
            expected_terminal_state = (
                TransactionState.COMPENSATION_FAILED
                if work.kind is RecoveryWorkKind.COMPENSATE and work.permit is not None
                else TransactionState.RECOVERY_FAILED
            )
            if transaction.state is not expected_terminal_state:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Terminal effect recovery work did not settle its target",
                )
            if transaction.updated_at != recorded_at or transaction.reason_code != work.reason_code:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Terminal recovery target lost its exact event projection",
                )
            expected_event = (
                TransitionEvent.STAGING_DISCARD_FAILED
                if work.kind is RecoveryWorkKind.DISCARD_STAGING
                else (
                    TransitionEvent.RECOVERY_UNAVAILABLE
                    if work.permit is None
                    else (
                        TransitionEvent.ROLLBACK_FAILED_OR_UNKNOWN
                        if work.kind is RecoveryWorkKind.ROLLBACK
                        else TransitionEvent.COMPENSATION_FAILED_OR_UNKNOWN
                    )
                )
            )
            expected_event_evidence = (
                (terminal_evidence_ref,)
                if work.permit is None
                else tuple(sorted({canonical_digest(work), terminal_evidence_ref}))
            )
            event_row = self._connection.execute(
                "SELECT * FROM enforced_transaction_events WHERE tenant_id = ? "
                "AND transaction_id = ? AND sequence = ?",
                (work.tenant_id, work.transaction_id, transaction.version),
            ).fetchone()
            event = None if event_row is None else self._event_from_row(event_row)
            if (
                event is None
                or event.event != expected_event.value
                or event.recorded_at != recorded_at
                or event.evidence_refs != expected_event_evidence
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Terminal recovery target lost its exact transaction event",
                )
        if work.kind is RecoveryWorkKind.DISCARD_STAGING:
            stage = self._get_stage_material_tx(work.tenant_id, work.transaction_id)
            if (
                stage.stage_id != work.target_id
                or stage.target_version_guard != work.target_version_guard
                or stage.state is not StageMaterialState.DISCARD_FAILED
                or stage.discard_evidence_ref != terminal_evidence_ref
                or stage.updated_at != recorded_at
                or stage.version
                != (
                    4
                    if stage.verification_ref is not None
                    else (
                        3
                        if stage.staged_receipt_ref is not None
                        else (2 if stage.staged_effect_ref is not None else 1)
                    )
                )
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Terminal discard work differs from its failed stage settlement",
                )
        else:
            dispatch = self._get_commit_dispatch_tx(
                work.tenant_id,
                work.transaction_id,
            )
            if (
                dispatch.dispatch_id != work.target_id
                or dispatch.intent_hash != work.intent_hash
                or dispatch.owner_version != work.target_owner_version
                or canonical_digest(dispatch) != work.target_evidence_ref
                or dispatch.permit.target_version_guard != work.target_version_guard
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Terminal recovery work differs from its dispatch target",
                )
        self._assert_terminal_intent_state_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.recovery_action_intent_hash,
            transaction_id=work.recovery_action_transaction_id,
            owner_version=work.owner_version,
            history_sequence=work.owner_history_sequence,
            history_digest=work.owner_history_digest,
            expected_states={IntentAttemptState.NO_EFFECT_CONFIRMED},
            label="recovery action",
        )
        action_attempt = self._validate_bounded_intent_attempt_lifecycle_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.recovery_action_intent_hash,
            transaction_id=work.recovery_action_transaction_id,
            expected_states=frozenset({IntentAttemptState.NO_EFFECT_CONFIRMED}),
        )
        if (
            action_attempt.evidence_digest != canonical_digest(work)
            or action_attempt.updated_at != recorded_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Terminal recovery action lost its exact intent evidence",
            )
        target_states = (
            {
                IntentAttemptState.NO_EFFECT_CONFIRMED,
                IntentAttemptState.REVIEW_REQUIRED,
            }
            if work.kind is RecoveryWorkKind.DISCARD_STAGING
            else {IntentAttemptState.REVIEW_REQUIRED}
        )
        self._assert_terminal_intent_state_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.intent_hash,
            transaction_id=work.transaction_id,
            owner_version=work.target_owner_version,
            history_sequence=work.target_owner_history_sequence,
            history_digest=work.target_owner_history_digest,
            expected_states=target_states,
            label="recovery target",
        )
        target_attempt = self._validate_bounded_intent_attempt_lifecycle_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.intent_hash,
            transaction_id=work.transaction_id,
            expected_states=frozenset(target_states),
        )
        if target_attempt.updated_at == recorded_at and target_attempt.evidence_digest not in {
            terminal_evidence_ref,
            canonical_digest(work),
        }:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Terminal recovery target changed its exact intent evidence",
            )
        target_dispatch_row = self._connection.execute(
            "SELECT 1 FROM enforced_commit_dispatches WHERE tenant_id = ? "
            "AND transaction_id = ? LIMIT 1",
            (work.tenant_id, work.transaction_id),
        ).fetchone()
        self._assert_target_capability_settlement_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            intent_hash=work.intent_hash,
            owner_version=work.target_owner_version,
            dispatch=(
                None
                if work.kind is RecoveryWorkKind.DISCARD_STAGING and target_dispatch_row is None
                else self._get_commit_dispatch_tx(
                    work.tenant_id,
                    work.transaction_id,
                )
            ),
        )
        self._assert_no_orphan_active_recovery_lease_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
        )

    def _assert_target_capability_settlement_tx(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        intent_hash: str,
        owner_version: int,
        dispatch: CommitDispatchRecord | None,
    ) -> None:
        target_action = self._get_normalized_action(
            tenant_id,
            transaction_id,
        ).action
        reservation = self._read_capability_chain(
            tenant_id=tenant_id,
            goal_id=target_action.goal_id,
            run_id=target_action.run_id,
            intent_hash=intent_hash,
        )
        if reservation is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target lost its capability reservation",
            )
        if dispatch is not None:
            permit = dispatch.permit
            valid = (
                reservation.state is CapabilityReservationState.COMMITTED
                and reservation.version == permit.reservation_version
                and capability_reservation_digest(reservation)
                == permit.capability_reservation_digest
                and reservation.activation_owner_transaction_id == transaction_id
                and reservation.activation_owner_version == permit.owner_version
                and reservation.activation_history_sequence == permit.owner_history_sequence
                and reservation.activation_history_digest == permit.owner_history_digest
                and owner_version == permit.owner_version
                and reservation.release_history_sequence is None
                and reservation.release_history_digest is None
            )
        else:
            round_row = self._connection.execute(
                "SELECT * FROM enforced_authorization_rounds WHERE tenant_id = ? "
                "AND controlled_transaction_id = ? AND purpose = 'STAGING' "
                "ORDER BY evaluated_at DESC LIMIT 1",
                (tenant_id, transaction_id),
            ).fetchone()
            round_record = None if round_row is None else self._round_from_row(round_row)
            valid = (
                round_record is not None
                and round_record.reservation_version is not None
                and reservation.state is CapabilityReservationState.RELEASED
                and reservation.version == round_record.reservation_version + 1
                and reservation.activation_owner_transaction_id == transaction_id
                and reservation.activation_owner_version == round_record.owner_version
                and reservation.activation_history_sequence == round_record.owner_history_sequence
                and reservation.activation_history_digest == round_record.owner_history_digest
                and owner_version == round_record.owner_version
                and reservation.release_history_sequence is not None
                and reservation.release_history_digest is not None
            )
        if not valid:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target capability settlement differs from its exact fence",
            )

    def _read_bounded_capability_chain_tx(
        self,
        *,
        tenant_id: str,
        goal_id: str,
        run_id: str,
        intent_hash: str,
    ) -> CapabilityChainReservation | None:
        """Read one capability chain without traversing its complete intent ledger."""

        row = self._connection.execute(
            "SELECT * FROM enforced_capability_chain_reservations "
            "WHERE tenant_id = ? AND goal_id = ? AND run_id = ? AND intent_hash = ?",
            (tenant_id, goal_id, run_id, intent_hash),
        ).fetchone()
        if row is None:
            return None
        item_rows = self._connection.execute(
            "SELECT capability_id, chain_ordinal, request_digest, reservation_state, "
            "created_at, updated_at FROM enforced_capability_use_reservations "
            "WHERE tenant_id = ? AND goal_id = ? AND run_id = ? AND intent_hash = ? "
            "ORDER BY chain_ordinal LIMIT 257",
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
        version = _require_stored_integer(
            row["version"],
            field="bounded capability chain version",
        )
        activation_owner_transaction_id = (
            None
            if row["activation_owner_transaction_id"] is None
            else str(row["activation_owner_transaction_id"])
        )
        activation_owner_version = (
            None
            if row["activation_owner_version"] is None
            else _require_stored_integer(
                row["activation_owner_version"],
                field="bounded capability activation owner version",
            )
        )
        activation_history_sequence = (
            None
            if row["activation_history_sequence"] is None
            else _require_stored_integer(
                row["activation_history_sequence"],
                field="bounded capability activation history sequence",
            )
        )
        activation_history_digest = (
            None
            if row["activation_history_digest"] is None
            else _require_digest(
                str(row["activation_history_digest"]),
                field="bounded capability activation history digest",
            )
        )
        release_history_sequence = (
            None
            if row["release_history_sequence"] is None
            else _require_stored_integer(
                row["release_history_sequence"],
                field="bounded capability release history sequence",
            )
        )
        release_history_digest = (
            None
            if row["release_history_digest"] is None
            else _require_digest(
                str(row["release_history_digest"]),
                field="bounded capability release history digest",
            )
        )
        budget_reuse_value = _require_stored_integer(
            row["reuse_without_budget"],
            field="bounded capability budget-reuse flag",
        )
        activation_values = (
            activation_owner_transaction_id,
            activation_owner_version,
            activation_history_sequence,
            activation_history_digest,
        )
        release_values = (release_history_sequence, release_history_digest)
        if (
            not 1 <= len(item_rows) <= 256
            or any(
                _require_stored_integer(
                    item["chain_ordinal"],
                    field="bounded capability chain ordinal",
                )
                != index
                for index, item in enumerate(item_rows)
            )
            or str(row["request_digest"]) != request_digest
            or any(str(item["request_digest"]) != request_digest for item in item_rows)
            or any(str(item["reservation_state"]) != state.value for item in item_rows)
            or any(value is None for value in activation_values)
            != all(value is None for value in activation_values)
            or any(value is None for value in release_values)
            != all(value is None for value in release_values)
            or (state is CapabilityReservationState.RESERVED and version % 2 != 0)
            or (state is not CapabilityReservationState.RESERVED and version % 2 != 1)
            or budget_reuse_value not in {0, 1}
            or (budget_reuse_value == 1 and state is not CapabilityReservationState.RESERVED)
            or (state is not CapabilityReservationState.RELEASED and release_values != (None, None))
            or (
                state is CapabilityReservationState.RELEASED
                and activation_owner_transaction_id is not None
                and release_values == (None, None)
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Bounded capability chain is incomplete or inconsistent",
            )
        _parse_timestamp(row["created_at"])
        _parse_timestamp(row["updated_at"])
        for item in item_rows:
            _parse_timestamp(item["created_at"])
            _parse_timestamp(item["updated_at"])
        if activation_owner_transaction_id is not None:
            if (
                activation_owner_version is None
                or activation_history_sequence is None
                or activation_history_digest is None
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Bounded capability activation binding is incomplete",
                )
            self._validate_bounded_intent_history_binding_tx(
                tenant_id=tenant_id,
                intent_hash=intent_hash,
                transaction_id=activation_owner_transaction_id,
                owner_version=activation_owner_version,
                history_sequence=activation_history_sequence,
                history_digest=activation_history_digest,
            )
            if release_history_sequence is not None:
                if (
                    release_history_digest is None
                    or release_history_sequence < activation_history_sequence
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Bounded capability release binding is invalid",
                    )
                self._validate_bounded_intent_history_binding_tx(
                    tenant_id=tenant_id,
                    intent_hash=intent_hash,
                    transaction_id=activation_owner_transaction_id,
                    owner_version=activation_owner_version,
                    history_sequence=release_history_sequence,
                    history_digest=release_history_digest,
                )
            if state is CapabilityReservationState.RESERVED:
                owner = self._connection.execute(
                    "SELECT owner_transaction_id, owner_version FROM enforced_intent_owners "
                    "WHERE tenant_id = ? AND intent_hash = ?",
                    (tenant_id, intent_hash),
                ).fetchone()
                if (
                    owner is None
                    or str(owner["owner_transaction_id"]) != activation_owner_transaction_id
                    or _require_stored_integer(
                        owner["owner_version"],
                        field="bounded capability current owner version",
                    )
                    != activation_owner_version
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Bounded active capability chain differs from its owner",
                    )
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
            budget_reuse=bool(budget_reuse_value),
        )

    def _assert_bounded_target_capability_settlement_tx(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        intent_hash: str,
        owner_version: int,
        dispatch: CommitDispatchRecord | None,
    ) -> None:
        target_action = self._get_normalized_action(tenant_id, transaction_id).action
        reservation = self._read_bounded_capability_chain_tx(
            tenant_id=tenant_id,
            goal_id=target_action.goal_id,
            run_id=target_action.run_id,
            intent_hash=intent_hash,
        )
        if reservation is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery target lost its bounded capability reservation",
            )
        if dispatch is not None:
            permit = dispatch.permit
            valid = (
                reservation.state is CapabilityReservationState.COMMITTED
                and reservation.version == permit.reservation_version
                and capability_reservation_digest(reservation)
                == permit.capability_reservation_digest
                and reservation.activation_owner_transaction_id == transaction_id
                and reservation.activation_owner_version == permit.owner_version
                and reservation.activation_history_sequence == permit.owner_history_sequence
                and reservation.activation_history_digest == permit.owner_history_digest
                and owner_version == permit.owner_version
                and reservation.release_history_sequence is None
                and reservation.release_history_digest is None
            )
        else:
            round_row = self._connection.execute(
                "SELECT * FROM enforced_authorization_rounds WHERE tenant_id = ? "
                "AND controlled_transaction_id = ? AND purpose = 'STAGING' "
                "ORDER BY evaluated_at DESC LIMIT 1",
                (tenant_id, transaction_id),
            ).fetchone()
            round_record = None if round_row is None else self._round_from_row(round_row)
            valid = (
                round_record is not None
                and round_record.reservation_version is not None
                and reservation.state is CapabilityReservationState.RELEASED
                and reservation.version == round_record.reservation_version + 1
                and reservation.activation_owner_transaction_id == transaction_id
                and reservation.activation_owner_version == round_record.owner_version
                and reservation.activation_history_sequence == round_record.owner_history_sequence
                and reservation.activation_history_digest == round_record.owner_history_digest
                and owner_version == round_record.owner_version
                and reservation.release_history_sequence is not None
                and reservation.release_history_digest is not None
            )
        if not valid:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Bounded recovery target capability settlement differs from its fence",
            )

    def _assert_bounded_recovery_capability_settlement_tx(
        self,
        work: RecoveryWorkRecord,
        authorization_round: AuthorizationRoundRecord,
        *,
        expected_state: CapabilityReservationState | None,
    ) -> None:
        if expected_state is None:
            existing = self._connection.execute(
                "SELECT 1 FROM enforced_capability_chain_reservations "
                "WHERE tenant_id = ? AND intent_hash = ? LIMIT 1",
                (work.tenant_id, work.recovery_action_intent_hash),
            ).fetchone()
            if (
                existing is not None
                or authorization_round.reservation_goal_id is not None
                or authorization_round.reservation_run_id is not None
                or work.capability_reservation_digest is not None
                or work.reservation_version is not None
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Ineligible recovery authorization gained a capability reservation",
                )
            return
        if (
            authorization_round.reservation_goal_id is None
            or authorization_round.reservation_run_id is None
            or work.capability_reservation_digest is None
            or work.reservation_version is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Terminal recovery lost its bounded capability reservation binding",
            )
        reservation = self._read_bounded_capability_chain_tx(
            tenant_id=work.tenant_id,
            goal_id=authorization_round.reservation_goal_id,
            run_id=authorization_round.reservation_run_id,
            intent_hash=work.recovery_action_intent_hash,
        )
        expected_version = (
            work.reservation_version + 1
            if expected_state is CapabilityReservationState.RELEASED
            else work.reservation_version
        )
        if (
            reservation is None
            or reservation.state is not expected_state
            or reservation.version != expected_version
            or reservation.activation_owner_transaction_id != work.recovery_action_transaction_id
            or reservation.activation_owner_version != work.owner_version
            or reservation.activation_history_sequence != work.owner_history_sequence
            or reservation.activation_history_digest != work.owner_history_digest
            or (
                expected_state is not CapabilityReservationState.RELEASED
                and capability_reservation_digest(reservation) != work.capability_reservation_digest
            )
            or (
                expected_state is CapabilityReservationState.RELEASED
                and (
                    reservation.release_history_sequence is None
                    or reservation.release_history_digest is None
                )
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Terminal bounded recovery capability settlement differs from its phase",
            )

    def _assert_recovery_capability_settlement_tx(
        self,
        work: RecoveryWorkRecord,
        authorization_round: AuthorizationRoundRecord,
        *,
        expected_state: CapabilityReservationState | None,
    ) -> None:
        if expected_state is None:
            existing = self._connection.execute(
                "SELECT 1 FROM enforced_capability_chain_reservations "
                "WHERE tenant_id = ? AND intent_hash = ? LIMIT 1",
                (work.tenant_id, work.recovery_action_intent_hash),
            ).fetchone()
            if (
                existing is not None
                or authorization_round.reservation_goal_id is not None
                or authorization_round.reservation_run_id is not None
                or work.capability_reservation_digest is not None
                or work.reservation_version is not None
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Ineligible recovery authorization gained a capability reservation",
                )
            return
        if (
            authorization_round.reservation_goal_id is None
            or authorization_round.reservation_run_id is None
            or work.capability_reservation_digest is None
            or work.reservation_version is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Terminal recovery lost its capability reservation binding",
            )
        reservation = self._read_capability_chain(
            tenant_id=work.tenant_id,
            goal_id=authorization_round.reservation_goal_id,
            run_id=authorization_round.reservation_run_id,
            intent_hash=work.recovery_action_intent_hash,
        )
        expected_version = (
            work.reservation_version + 1
            if expected_state is CapabilityReservationState.RELEASED
            else work.reservation_version
        )
        if (
            reservation is None
            or reservation.state is not expected_state
            or reservation.version != expected_version
            or reservation.activation_owner_transaction_id != work.recovery_action_transaction_id
            or reservation.activation_owner_version != work.owner_version
            or reservation.activation_history_sequence != work.owner_history_sequence
            or reservation.activation_history_digest != work.owner_history_digest
            or (
                expected_state is not CapabilityReservationState.RELEASED
                and capability_reservation_digest(reservation) != work.capability_reservation_digest
            )
            or (
                expected_state is CapabilityReservationState.RELEASED
                and (
                    reservation.release_history_sequence is None
                    or reservation.release_history_digest is None
                )
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Terminal recovery capability settlement differs from its phase",
            )

    def _finish_target_intent_tx(
        self,
        work: RecoveryWorkRecord,
        *,
        succeeded: bool,
        evidence_digest: str,
        recorded_at: datetime,
    ) -> None:
        self._assert_recovery_target_owner_tx(work)
        ledger = self._validate_intent_ledger(work.tenant_id, work.intent_hash)
        target_transaction: EnforcedTransactionRecord | None = None
        target_reservation: CapabilityChainReservation | None = None
        if work.kind is RecoveryWorkKind.DISCARD_STAGING and (
            ledger.owner_state
            not in {
                IntentAttemptState.NO_EFFECT_CONFIRMED,
                IntentAttemptState.REVIEW_REQUIRED,
            }
        ):
            target_transaction = self._get_enforced_transaction_tx(
                work.tenant_id,
                work.transaction_id,
            )
            target_reservation = self._exact_undispatched_target_reservation_tx(target_transaction)
        target_state = (
            IntentAttemptState.NO_EFFECT_CONFIRMED
            if succeeded
            else IntentAttemptState.REVIEW_REQUIRED
        )
        if not succeeded and ledger.owner_state is IntentAttemptState.NO_EFFECT_CONFIRMED:
            return
        if ledger.owner_state is not target_state:
            row = self._connection.execute(
                "SELECT state_version FROM enforced_intent_attempts WHERE tenant_id = ? "
                "AND intent_hash = ? AND transaction_id = ?",
                (work.tenant_id, work.intent_hash, work.transaction_id),
            ).fetchone()
            if row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery target lost its intent-attempt projection",
                )
            self._record_intent_attempt_state_tx(
                tenant_id=work.tenant_id,
                intent_hash=work.intent_hash,
                transaction_id=work.transaction_id,
                expected_version=int(row["state_version"]),
                target_state=target_state,
                evidence_digest=evidence_digest,
                recorded_at=_timestamp(recorded_at),
            )
        if target_reservation is not None:
            if succeeded:
                self.release_capability_chain(
                    tenant_id=target_reservation.tenant_id,
                    goal_id=target_reservation.goal_id,
                    run_id=target_reservation.run_id,
                    intent_hash=target_reservation.intent_hash,
                    capability_ids=target_reservation.capability_ids,
                    fence=target_reservation.fence,
                    released_at=recorded_at,
                )
            else:
                self._release_review_required_undispatched_reservation_tx(
                    cast("EnforcedTransactionRecord", target_transaction),
                    target_reservation,
                    released_at=recorded_at,
                )

    def _assert_finished_recovery_retry_tx(
        self,
        work: RecoveryWorkRecord,
        report: RecoveryCompletionReportRecord,
        *,
        expected_work_version: int,
    ) -> tuple[EnforcedTransactionRecord, WorkerLeaseRecord]:
        """Validate the complete terminal settlement behind a recovery exact retry."""

        expected_state = (
            RecoveryWorkState.SUCCEEDED if report.succeeded else RecoveryWorkState.FAILED
        )
        if work.version != expected_work_version + 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Recovery completion retry used a stale source generation",
                retryable=False,
            )
        if (
            work.state is not expected_state
            or work.permit is None
            or work.permit_ref is None
            or work.lease_id is None
            or work.worker_id is None
            or work.fencing_token is None
            or work.updated_at != report.completed_at
            or work.reason_code != report.reason_code
            or report.terminal_work_digest != canonical_digest(work)
            or work.evidence_refs != tuple(sorted({*report.evidence_refs, work.permit_ref}))
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion retry differs from its terminal work generation",
            )
        lease = self._get_worker_lease_tx(
            work.tenant_id,
            work.transaction_id,
            work.lease_id,
        )
        if (
            lease.worker_id != work.worker_id
            or lease.fencing_token != work.fencing_token
            or lease.purpose is not LeasePurpose.RECOVERY
            or lease.released_at != report.completed_at
            or lease.version != 1
            or report.completed_at < lease.acquired_at
            or report.completed_at >= lease.expires_at
            or report.completed_at < work.permit.issued_at
            or report.completed_at >= work.permit.deadline
            or report.completed_at >= work.deadline
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion retry lost its exact released lease",
            )
        newer_lease = self._connection.execute(
            "SELECT 1 FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND fencing_token > ? LIMIT 1",
            (work.tenant_id, work.transaction_id, work.fencing_token),
        ).fetchone()
        if newer_lease is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion retry was superseded by a newer fence",
            )
        handoff = self._assert_recovery_work_handoff_tx(work)
        if handoff.closed_at is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Normal recovery completion unexpectedly closed its action handoff",
            )
        self._validate_recovery_action_handoff_reverse_tx(
            handoff,
            tenant_id=work.tenant_id,
        )
        authorization_round = self._get_authorization_round_tx(
            work.tenant_id,
            work.transaction_id,
            work.authorization_round_id,
        )
        self._assert_recovery_round_bindings(work, authorization_round)
        self._assert_recovery_capability_settlement_tx(
            work,
            authorization_round,
            expected_state=CapabilityReservationState.COMMITTED,
        )
        self._validate_bounded_intent_history_binding_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.recovery_action_intent_hash,
            transaction_id=work.recovery_action_transaction_id,
            owner_version=work.owner_version,
            history_sequence=work.owner_history_sequence,
            history_digest=work.owner_history_digest,
        )
        action_attempt = self._validate_bounded_intent_attempt_lifecycle_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.recovery_action_intent_hash,
            transaction_id=work.recovery_action_transaction_id,
            expected_states=frozenset(
                {
                    IntentAttemptState.COMMITTED
                    if report.succeeded
                    else IntentAttemptState.REVIEW_REQUIRED
                }
            ),
        )
        if (
            action_attempt.evidence_digest != canonical_digest(work)
            or action_attempt.updated_at != report.completed_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion retry lost its action-intent terminal evidence",
            )
        target_states = (
            frozenset(
                {
                    IntentAttemptState.NO_EFFECT_CONFIRMED
                    if report.succeeded
                    else IntentAttemptState.REVIEW_REQUIRED,
                    *({IntentAttemptState.NO_EFFECT_CONFIRMED} if not report.succeeded else set()),
                }
            )
            if work.kind is RecoveryWorkKind.DISCARD_STAGING
            else frozenset({IntentAttemptState.REVIEW_REQUIRED})
        )
        self._validate_bounded_intent_history_binding_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.intent_hash,
            transaction_id=work.transaction_id,
            owner_version=work.target_owner_version,
            history_sequence=work.target_owner_history_sequence,
            history_digest=work.target_owner_history_digest,
        )
        target_attempt = self._validate_bounded_intent_attempt_lifecycle_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.intent_hash,
            transaction_id=work.transaction_id,
            expected_states=target_states,
        )
        transaction = self._get_enforced_transaction_tx(
            work.tenant_id,
            work.transaction_id,
        )
        expected_transaction_states = {
            RecoveryWorkKind.DISCARD_STAGING: (
                {TransactionState.ABORTED, TransactionState.STALE_STATE}
                if report.succeeded
                else {TransactionState.RECOVERY_FAILED}
            ),
            RecoveryWorkKind.ROLLBACK: (
                {TransactionState.ROLLED_BACK}
                if report.succeeded
                else {TransactionState.RECOVERY_FAILED}
            ),
            RecoveryWorkKind.COMPENSATE: (
                {TransactionState.COMPENSATED}
                if report.succeeded
                else {TransactionState.COMPENSATION_FAILED}
            ),
        }[work.kind]
        if (
            transaction.state not in expected_transaction_states
            or transaction.updated_at != report.completed_at
            or transaction.reason_code != report.reason_code
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion retry target transaction is not terminal",
            )
        if (
            target_attempt.updated_at == report.completed_at
            and target_attempt.evidence_digest != canonical_digest(work)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion retry changed its target-intent evidence",
            )
        expected_event = {
            RecoveryWorkKind.DISCARD_STAGING: (
                TransitionEvent.STAGING_DISCARD_SUCCEEDED
                if report.succeeded
                else TransitionEvent.STAGING_DISCARD_FAILED
            ),
            RecoveryWorkKind.ROLLBACK: (
                TransitionEvent.ROLLBACK_VERIFIED
                if report.succeeded
                else TransitionEvent.ROLLBACK_FAILED_OR_UNKNOWN
            ),
            RecoveryWorkKind.COMPENSATE: (
                TransitionEvent.COMPENSATION_VERIFIED
                if report.succeeded
                else TransitionEvent.COMPENSATION_FAILED_OR_UNKNOWN
            ),
        }[work.kind]
        event_row = self._connection.execute(
            "SELECT * FROM enforced_transaction_events WHERE tenant_id = ? "
            "AND transaction_id = ? AND sequence = ?",
            (work.tenant_id, work.transaction_id, transaction.version),
        ).fetchone()
        event = None if event_row is None else self._event_from_row(event_row)
        expected_event_evidence = tuple(sorted({canonical_digest(work), *work.evidence_refs}))
        if (
            event is None
            or event.event != expected_event.value
            or event.recorded_at != report.completed_at
            or event.evidence_refs != expected_event_evidence
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion retry lost its exact transaction event",
            )
        if work.kind is RecoveryWorkKind.DISCARD_STAGING:
            stage = self._get_stage_material_tx(work.tenant_id, work.transaction_id)
            expected_stage_state = (
                StageMaterialState.DISCARDED
                if report.succeeded
                else StageMaterialState.DISCARD_FAILED
            )
            if (
                stage.stage_id != work.target_id
                or stage.target_version_guard != work.target_version_guard
                or stage.state is not expected_stage_state
                or stage.discard_evidence_ref != report.operation_evidence_ref
                or stage.updated_at != report.completed_at
                or stage.version
                != (
                    4
                    if stage.verification_ref is not None
                    else (
                        3
                        if stage.staged_receipt_ref is not None
                        else (2 if stage.staged_effect_ref is not None else 1)
                    )
                )
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery completion retry differs from its terminal stage",
                )
            target_dispatch_row = self._connection.execute(
                "SELECT 1 FROM enforced_commit_dispatches WHERE tenant_id = ? "
                "AND transaction_id = ? LIMIT 1",
                (work.tenant_id, work.transaction_id),
            ).fetchone()
            target_dispatch = (
                None
                if target_dispatch_row is None
                else self._get_commit_dispatch_tx(
                    work.tenant_id,
                    work.transaction_id,
                )
            )
        else:
            target_dispatch = self._get_commit_dispatch_tx(
                work.tenant_id,
                work.transaction_id,
            )
            if (
                target_dispatch.dispatch_id != work.target_id
                or target_dispatch.intent_hash != work.intent_hash
                or target_dispatch.owner_version != work.target_owner_version
                or canonical_digest(target_dispatch) != work.target_evidence_ref
                or target_dispatch.permit.target_version_guard != work.target_version_guard
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery completion retry differs from its dispatch target",
                )
        self._assert_target_capability_settlement_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            intent_hash=work.intent_hash,
            owner_version=work.target_owner_version,
            dispatch=target_dispatch,
        )
        self._assert_no_orphan_active_recovery_lease_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
        )
        return transaction, lease

    def finish_recovery(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        expected_work_version: int,
        succeeded: bool,
        evidence_refs: tuple[str, ...],
        operation_evidence_ref: str,
        completed_at: datetime,
        reason_code: str | None = None,
    ) -> RecoveryFinishResult:
        """Persist a fenced discard, rollback, or compensation result atomically."""

        normalized_refs = tuple(
            sorted({_require_digest(value, field="evidence_ref") for value in evidence_refs})
        )
        if not normalized_refs:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Recovery completion requires durable evidence",
            )
        operation_evidence_ref = _require_digest(
            operation_evidence_ref,
            field="operation_evidence_ref",
        )
        if operation_evidence_ref not in normalized_refs:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Operation evidence must be included in the recovery evidence set",
            )
        if not succeeded and reason_code is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Failed recovery requires a stable reason code",
            )
        if succeeded and reason_code is not None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Successful recovery cannot carry a failure reason",
            )
        with self._immediate():
            work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Dispatch reconciliation must use finish_reconciliation",
                )
            expected_state = RecoveryWorkState.SUCCEEDED if succeeded else RecoveryWorkState.FAILED
            if work.state in {
                RecoveryWorkState.SUCCEEDED,
                RecoveryWorkState.FAILED,
                RecoveryWorkState.REVIEW_REQUIRED,
            }:
                if work.permit_ref is None:
                    raise AgentKernelError(
                        ErrorCode.ILLEGAL_TRANSITION,
                        "Unclaimed recovery denial has no completion retry",
                    )
                completion_report = RecoveryCompletionReportRecord.create(
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                    recovery_id=recovery_id,
                    succeeded=succeeded,
                    operation_evidence_ref=operation_evidence_ref,
                    evidence_refs=normalized_refs,
                    completed_at=completed_at,
                    reason_code=reason_code,
                    terminal_work_digest=canonical_digest(work),
                )
                if (
                    self._get_recovery_completion_report_tx(
                        tenant_id,
                        transaction_id,
                        recovery_id,
                    )
                    != completion_report
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery completion retry changed its exact submitted report",
                    )
                transaction, lease = self._assert_finished_recovery_retry_tx(
                    work,
                    completion_report,
                    expected_work_version=expected_work_version,
                )
                return RecoveryFinishResult(
                    work,
                    transaction,
                    None,
                    lease,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            if (
                work.state is not RecoveryWorkState.RUNNING
                or work.version != expected_work_version
                or work.permit is None
                or work.lease_id is None
                or work.worker_id is None
                or work.fencing_token is None
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Recovery work is not the expected claimed generation",
                )
            if completed_at >= work.deadline or completed_at >= work.permit.deadline:
                raise AgentKernelError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "Recovery completion arrived after its permit or work deadline",
                )
            purpose = LeasePurpose.RECOVERY
            self._assert_active_lease_tx(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                lease_id=work.lease_id,
                worker_id=work.worker_id,
                fencing_token=work.fencing_token,
                purpose=purpose,
                at=completed_at,
            )
            transaction, stage, _ = self._assert_recovery_target_tx(
                work,
                require_authorizable_state=False,
            )
            expected_source = {
                RecoveryWorkKind.DISCARD_STAGING: TransactionState.ABORTING,
                RecoveryWorkKind.ROLLBACK: TransactionState.ROLLING_BACK,
                RecoveryWorkKind.COMPENSATE: TransactionState.COMPENSATING,
            }[work.kind]
            if transaction.state is not expected_source:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Recovery completion source state changed",
                )
            terminal_refs = tuple(sorted({*normalized_refs, cast("str", work.permit_ref)}))
            updated_work = RecoveryWorkRecord.model_validate(
                {
                    **work.model_dump(mode="python"),
                    "state": expected_state,
                    "version": work.version + 1,
                    "evidence_refs": terminal_refs,
                    "reason_code": None if succeeded else reason_code,
                    "updated_at": completed_at,
                }
            )
            completion_report = RecoveryCompletionReportRecord.create(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                recovery_id=recovery_id,
                succeeded=succeeded,
                operation_evidence_ref=operation_evidence_ref,
                evidence_refs=normalized_refs,
                completed_at=completed_at,
                reason_code=reason_code,
                terminal_work_digest=canonical_digest(updated_work),
            )
            self._insert_recovery_completion_report_tx(completion_report)
            work_evidence = canonical_digest(updated_work)
            if work.kind is RecoveryWorkKind.DISCARD_STAGING:
                if stage is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Discard recovery lost private stage material",
                    )
                updated_stage = StageMaterialRecord.model_validate(
                    {
                        **stage.model_dump(mode="python"),
                        "state": (
                            StageMaterialState.DISCARDED
                            if succeeded
                            else StageMaterialState.DISCARD_FAILED
                        ),
                        "discard_evidence_ref": operation_evidence_ref,
                        "version": stage.version + 1,
                        "updated_at": completed_at,
                    }
                )
                self._update_stage_material_tx(stage, updated_stage)
                self._finish_target_intent_tx(
                    work,
                    succeeded=succeeded,
                    evidence_digest=work_evidence,
                    recorded_at=completed_at,
                )
                transition = (
                    TransitionEvent.STAGING_DISCARD_SUCCEEDED
                    if succeeded
                    else TransitionEvent.STAGING_DISCARD_FAILED
                )
            elif work.kind is RecoveryWorkKind.ROLLBACK:
                transition = (
                    TransitionEvent.ROLLBACK_VERIFIED
                    if succeeded
                    else TransitionEvent.ROLLBACK_FAILED_OR_UNKNOWN
                )
            else:
                transition = (
                    TransitionEvent.COMPENSATION_VERIFIED
                    if succeeded
                    else TransitionEvent.COMPENSATION_FAILED_OR_UNKNOWN
                )
            updated_transaction, event = self._apply_transition_tx(
                transaction,
                expected_version=transaction.version,
                transition_event=transition,
                recorded_at=completed_at,
                evidence_refs=(work_evidence, *terminal_refs),
                reason_code=None if succeeded else reason_code,
            )
            self._transition_owned_attempt_tx(
                tenant_id=work.tenant_id,
                intent_hash=work.recovery_action_intent_hash,
                transaction_id=work.recovery_action_transaction_id,
                owner_version=work.owner_version,
                owner_history_sequence=work.owner_history_sequence,
                owner_history_digest=work.owner_history_digest,
                target_state=(
                    IntentAttemptState.COMMITTED
                    if succeeded
                    else IntentAttemptState.REVIEW_REQUIRED
                ),
                evidence_digest=work_evidence,
                recorded_at=completed_at,
            )
            self._update_recovery_work_tx(work, updated_work)
            released = self._release_recovery_lease_tx(
                updated_work,
                released_at=completed_at,
            )
            return RecoveryFinishResult(
                updated_work,
                updated_transaction,
                event,
                released,
                EnforcedStoreDisposition.STORED,
            )

    def _recovery_completion_report_from_row(
        self,
        row: sqlite3.Row,
    ) -> RecoveryCompletionReportRecord:
        try:
            report = RecoveryCompletionReportRecord.model_validate_json(str(row["report_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored recovery completion report is invalid",
            ) from error
        expected: dict[str, object] = {
            "tenant_id": report.tenant_id,
            "transaction_id": report.transaction_id,
            "recovery_id": report.recovery_id,
            "succeeded": int(report.succeeded),
            "operation_evidence_ref": report.operation_evidence_ref,
            "evidence_refs_json": canonical_json_text(report.evidence_refs),
            "completed_at": _timestamp(report.completed_at),
            "reason_code": report.reason_code,
            "terminal_work_digest": report.terminal_work_digest,
            "report_digest": report.report_digest,
            "report_json": canonical_json_text(report),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion report projection differs from canonical content",
            )
        return report

    def _get_recovery_completion_report_tx(
        self,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
    ) -> RecoveryCompletionReportRecord | None:
        row = self._connection.execute(
            "SELECT * FROM enforced_recovery_completion_reports WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ?",
            (tenant_id, transaction_id, recovery_id),
        ).fetchone()
        return None if row is None else self._recovery_completion_report_from_row(row)

    def _validate_recovery_completion_report_association_tx(
        self,
        work: RecoveryWorkRecord,
        report: RecoveryCompletionReportRecord,
    ) -> None:
        """Bind one normal recovery completion to its exact terminal generation."""

        expected_state = (
            RecoveryWorkState.SUCCEEDED if report.succeeded else RecoveryWorkState.FAILED
        )
        if (
            work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
            or work.lease_id is None
            or work.permit is None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion report has no compatible durable permit generation",
            )
        lease = self._get_worker_lease_tx(
            report.tenant_id,
            report.transaction_id,
            work.lease_id,
        )
        handoff = self._assert_recovery_work_handoff_tx(work)
        if (
            work.state is not expected_state
            or work.updated_at != report.completed_at
            or work.reason_code != report.reason_code
            or report.terminal_work_digest != canonical_digest(work)
            or work.evidence_refs
            != tuple(sorted({*report.evidence_refs, cast("str", work.permit_ref)}))
            or lease.released_at != report.completed_at
            or handoff.closed_at is not None
            or self._get_late_recovery_report_tx(
                work.tenant_id,
                work.transaction_id,
                work.recovery_id,
            )
            is not None
            or self._get_recovery_evidence_unavailable_tx(
                work.tenant_id,
                work.transaction_id,
                work.recovery_id,
            )
            is not None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery completion report differs from its terminal work",
            )
        if work.kind is RecoveryWorkKind.DISCARD_STAGING and (
            self._get_stage_material_tx(work.tenant_id, work.transaction_id).discard_evidence_ref
            != report.operation_evidence_ref
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Discard completion report differs from its stage evidence",
            )

    def get_recovery_completion_report(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
    ) -> RecoveryCompletionReportRecord | None:
        """Return a completion report only after validating its terminal work binding."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        with self._read_snapshot():
            report = self._get_recovery_completion_report_tx(
                tenant_id,
                transaction_id,
                recovery_id,
            )
            if report is None:
                return None
            work = self._get_recovery_work_tx(
                tenant_id,
                transaction_id,
                recovery_id,
            )
            self._validate_recovery_completion_report_association_tx(work, report)
            return report

    def _insert_recovery_completion_report_tx(
        self,
        report: RecoveryCompletionReportRecord,
    ) -> None:
        self._execute(
            "INSERT INTO enforced_recovery_completion_reports(tenant_id, transaction_id, "
            "recovery_id, succeeded, operation_evidence_ref, evidence_refs_json, "
            "completed_at, reason_code, terminal_work_digest, report_digest, report_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                report.tenant_id,
                report.transaction_id,
                report.recovery_id,
                int(report.succeeded),
                report.operation_evidence_ref,
                canonical_json_text(report.evidence_refs),
                _timestamp(report.completed_at),
                report.reason_code,
                report.terminal_work_digest,
                report.report_digest,
                canonical_json_text(report),
            ),
        )

    def _late_recovery_report_from_row(
        self,
        row: sqlite3.Row,
    ) -> LateRecoveryReportRecord:
        try:
            report = LateRecoveryReportRecord.model_validate_json(str(row["report_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored late recovery report is invalid",
            ) from error
        canonical_report_json = canonical_json_text(
            report
            if report.schema_version == "1.1"
            else report.model_dump(
                mode="python",
                exclude={"operation_reason_code"},
            )
        )
        expected: dict[str, object] = {
            "tenant_id": report.tenant_id,
            "transaction_id": report.transaction_id,
            "recovery_id": report.recovery_id,
            "operation_evidence_ref": report.operation_evidence_ref,
            "operation_reason_code": report.operation_reason_code,
            "evidence_refs_json": canonical_json_text(report.evidence_refs),
            "reported_at": _timestamp(report.reported_at),
            "reason_code": report.reason_code,
            "terminal_work_digest": report.terminal_work_digest,
            "report_digest": report.report_digest,
            "report_json": canonical_report_json,
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery report projection differs from canonical content",
            )
        return report

    def _get_late_recovery_report_tx(
        self,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
    ) -> LateRecoveryReportRecord | None:
        row = self._connection.execute(
            "SELECT * FROM enforced_late_recovery_reports WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ?",
            (tenant_id, transaction_id, recovery_id),
        ).fetchone()
        return None if row is None else self._late_recovery_report_from_row(row)

    def get_late_recovery_report(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
    ) -> LateRecoveryReportRecord | None:
        """Return the exact late-result record bound to one recovery generation."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        with self._read_snapshot():
            report = self._get_late_recovery_report_tx(
                tenant_id,
                transaction_id,
                recovery_id,
            )
            if report is None:
                return None
            work = self._get_recovery_work_tx(
                tenant_id,
                transaction_id,
                recovery_id,
            )
            attempt: ReconciliationAttemptRecord | None = None
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                attempt_row = self._connection.execute(
                    "SELECT * FROM enforced_reconciliation_attempts WHERE tenant_id = ? "
                    "AND transaction_id = ? AND recovery_id = ? AND attempt = ?",
                    (tenant_id, transaction_id, recovery_id, work.attempt),
                ).fetchone()
                attempt = (
                    None if attempt_row is None else self._reconciliation_from_row(attempt_row)
                )
            self._validate_late_recovery_report_association_tx(
                work,
                report,
                attempt,
            )
            return report

    def _validate_late_recovery_report_association_tx(
        self,
        work: RecoveryWorkRecord,
        report: LateRecoveryReportRecord,
        attempt: ReconciliationAttemptRecord | None,
    ) -> None:
        """Bound one late report with point reads only for status and evidence audit."""

        if (
            work.state is not RecoveryWorkState.REVIEW_REQUIRED
            or work.permit is None
            or work.permit_ref is None
            or work.lease_id is None
            or work.worker_id is None
            or work.fencing_token is None
            or work.updated_at != report.reported_at
            or work.reason_code != report.reason_code
            or report.terminal_work_digest != canonical_digest(work)
            or report.operation_evidence_ref not in report.evidence_refs
            or not {
                *report.evidence_refs,
                work.permit_ref,
                work.target_evidence_ref,
            }.issubset(work.evidence_refs)
            or report.reported_at < min(work.deadline, work.permit.deadline)
            or self._get_recovery_completion_report_tx(
                work.tenant_id,
                work.transaction_id,
                work.recovery_id,
            )
            is not None
            or self._get_recovery_evidence_unavailable_tx(
                work.tenant_id,
                work.transaction_id,
                work.recovery_id,
            )
            is not None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery report differs from its terminal work",
            )
        lease = self._get_worker_lease_tx(
            work.tenant_id,
            work.transaction_id,
            work.lease_id,
        )
        expected_purpose = (
            LeasePurpose.RECONCILIATION
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
            else LeasePurpose.RECOVERY
        )
        newer_lease = self._connection.execute(
            "SELECT 1 FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND fencing_token > ? LIMIT 1",
            (work.tenant_id, work.transaction_id, work.fencing_token),
        ).fetchone()
        if (
            lease.worker_id != work.worker_id
            or lease.fencing_token != work.fencing_token
            or lease.purpose is not expected_purpose
            or lease.released_at != report.reported_at
            or lease.version != 1
            or report.reported_at < lease.acquired_at
            or newer_lease is not None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery report lost its exact released lease",
            )
        handoff = self._assert_recovery_work_handoff_tx(work)
        if (
            handoff.closed_at != report.reported_at
            or handoff.failure_evidence_status is not RecoveryHandoffFailureEvidenceStatus.AVAILABLE
            or handoff.failure_evidence_ref != report.operation_evidence_ref
            or handoff.failure_reason_code != report.reason_code
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery report differs from its terminal handoff",
            )
        if attempt is not None and (
            attempt.outcome is not ReconciliationOutcome.UNKNOWN
            or attempt.version != 1
            or attempt.recovery_id != work.recovery_id
            or attempt.attempt != work.attempt
            or attempt.lease_id != work.lease_id
            or attempt.fencing_token != work.fencing_token
            or attempt.completed_at != report.reported_at
            or attempt.next_attempt_not_before is not None
            or attempt.operation_evidence_ref != report.operation_evidence_ref
            or attempt.operation_reason_code != report.operation_reason_code
            or attempt.completion_evidence_refs != report.evidence_refs
            or _reconciliation_attempt_digest(attempt) not in work.evidence_refs
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery report differs from its closed reconciliation attempt",
            )

    def _insert_late_recovery_report_tx(self, report: LateRecoveryReportRecord) -> None:
        self._execute(
            "INSERT INTO enforced_late_recovery_reports(tenant_id, transaction_id, "
            "recovery_id, operation_evidence_ref, operation_reason_code, "
            "evidence_refs_json, reported_at, reason_code, terminal_work_digest, "
            "report_digest, report_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                report.tenant_id,
                report.transaction_id,
                report.recovery_id,
                report.operation_evidence_ref,
                report.operation_reason_code,
                canonical_json_text(report.evidence_refs),
                _timestamp(report.reported_at),
                report.reason_code,
                report.terminal_work_digest,
                report.report_digest,
                canonical_json_text(report),
            ),
        )

    def _recovery_evidence_unavailable_from_row(
        self,
        row: sqlite3.Row,
    ) -> RecoveryEvidenceUnavailableRecord:
        try:
            record = RecoveryEvidenceUnavailableRecord.model_validate_json(str(row["record_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored unavailable recovery evidence record is invalid",
            ) from error
        expected: dict[str, object] = {
            "tenant_id": record.tenant_id,
            "transaction_id": record.transaction_id,
            "recovery_id": record.recovery_id,
            "boundary": record.boundary,
            "evidence_status": record.evidence_status,
            "operation_evidence_ref": record.operation_evidence_ref,
            "supporting_refs_json": canonical_json_text(record.supporting_refs),
            "reported_at": _timestamp(record.reported_at),
            "reason_code": record.reason_code,
            "record_digest": record.record_digest,
            "record_json": canonical_json_text(record),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence projection differs from canonical content",
            )
        return record

    def _get_recovery_evidence_unavailable_tx(
        self,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
    ) -> RecoveryEvidenceUnavailableRecord | None:
        row = self._connection.execute(
            "SELECT * FROM enforced_recovery_evidence_unavailable_reports "
            "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ?",
            (tenant_id, transaction_id, recovery_id),
        ).fetchone()
        return None if row is None else self._recovery_evidence_unavailable_from_row(row)

    def _validate_bounded_intent_history_row_tx(
        self,
        row: sqlite3.Row,
        *,
        expected_previous_digest: str | None,
    ) -> str:
        tenant_id = str(row["tenant_id"])
        intent_hash = str(row["intent_hash"])
        sequence = int(row["sequence"])
        transaction_id = str(row["transaction_id"])
        action = self._get_normalized_action(tenant_id, transaction_id).action
        effective_idempotency_key = action.idempotency_key or action.intent_hash
        previous_digest = (
            None if row["previous_history_digest"] is None else str(row["previous_history_digest"])
        )
        evidence_digest = None if row["evidence_digest"] is None else str(row["evidence_digest"])
        legacy_payload: dict[str, object] = {
            "profile": "agentkernel.intent-attempt-history/v1",
            "tenant_id": tenant_id,
            "intent_hash": intent_hash,
            "sequence": sequence,
            "transaction_id": transaction_id,
            "event_type": str(row["event_type"]),
            "disposition": None if row["disposition"] is None else str(row["disposition"]),
            "attempt_state": str(row["attempt_state"]),
            "owner_transaction_id": str(row["owner_transaction_id"]),
            "owner_version": int(row["owner_version"]),
            "evidence_digest": evidence_digest,
            "previous_history_digest": previous_digest,
            "recorded_at": _timestamp(_parse_timestamp(row["recorded_at"])),
        }
        payload = {
            **legacy_payload,
            "profile": "agentkernel.intent-attempt-history/v2",
            "effective_idempotency_key": effective_idempotency_key,
        }
        history_digest = str(row["history_digest"])
        if (
            previous_digest != expected_previous_digest
            or str(row["effective_idempotency_key"]) != effective_idempotency_key
            or history_digest not in {canonical_digest(legacy_payload), canonical_digest(payload)}
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence intent-history boundary is invalid",
            )
        return history_digest

    def _validate_bounded_intent_settlement_tx(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
        transaction_id: str,
        expected_states: frozenset[IntentAttemptState],
    ) -> tuple[IntentAttemptState, str | None, datetime]:
        attempt_row = self._connection.execute(
            "SELECT * FROM enforced_intent_attempts "
            "WHERE tenant_id = ? AND intent_hash = ? AND transaction_id = ?",
            (tenant_id, intent_hash, transaction_id),
        ).fetchone()
        owner_row = self._connection.execute(
            "SELECT * FROM enforced_intent_owners WHERE tenant_id = ? AND intent_hash = ?",
            (tenant_id, intent_hash),
        ).fetchone()
        head_row = self._connection.execute(
            "SELECT * FROM enforced_intent_attempt_history "
            "WHERE tenant_id = ? AND intent_hash = ? ORDER BY sequence DESC LIMIT 1",
            (tenant_id, intent_hash),
        ).fetchone()
        if attempt_row is None or owner_row is None or head_row is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence lost an intent settlement projection",
            )
        attempt = self._intent_attempt_from_row(attempt_row)
        owner_transaction_id = str(owner_row["owner_transaction_id"])
        owner_version = int(owner_row["owner_version"])
        head_sequence = int(owner_row["history_head_sequence"])
        head_digest = str(owner_row["history_head_digest"])
        previous_history_digest = (
            None
            if head_row["previous_history_digest"] is None
            else str(head_row["previous_history_digest"])
        )
        head_evidence = (
            None if head_row["evidence_digest"] is None else str(head_row["evidence_digest"])
        )
        previous_row = (
            None
            if head_sequence == 0
            else self._connection.execute(
                "SELECT * FROM enforced_intent_attempt_history "
                "WHERE tenant_id = ? AND intent_hash = ? AND sequence = ?",
                (tenant_id, intent_hash, head_sequence - 1),
            ).fetchone()
        )
        predecessor_previous_row = (
            None
            if head_sequence <= 1
            else self._connection.execute(
                "SELECT history_digest FROM enforced_intent_attempt_history "
                "WHERE tenant_id = ? AND intent_hash = ? AND sequence = ?",
                (tenant_id, intent_hash, head_sequence - 2),
            ).fetchone()
        )
        validated_previous_digest = (
            None
            if previous_row is None
            else self._validate_bounded_intent_history_row_tx(
                previous_row,
                expected_previous_digest=(
                    None
                    if predecessor_previous_row is None
                    else str(predecessor_previous_row["history_digest"])
                ),
            )
        )
        validated_head_digest = self._validate_bounded_intent_history_row_tx(
            head_row,
            expected_previous_digest=validated_previous_digest,
        )
        head_transaction_id = str(head_row["transaction_id"])
        head_action = self._get_normalized_action(
            tenant_id,
            head_transaction_id,
        ).action
        effective_idempotency_key = head_action.idempotency_key or head_action.intent_hash
        head_recorded_at = _parse_timestamp(head_row["recorded_at"])
        recorded_at_text = _timestamp(head_recorded_at)
        legacy_payload: dict[str, object] = {
            "profile": "agentkernel.intent-attempt-history/v1",
            "tenant_id": tenant_id,
            "intent_hash": intent_hash,
            "sequence": head_sequence,
            "transaction_id": head_transaction_id,
            "event_type": str(head_row["event_type"]),
            "disposition": (
                None if head_row["disposition"] is None else str(head_row["disposition"])
            ),
            "attempt_state": str(head_row["attempt_state"]),
            "owner_transaction_id": str(head_row["owner_transaction_id"]),
            "owner_version": int(head_row["owner_version"]),
            "evidence_digest": head_evidence,
            "previous_history_digest": previous_history_digest,
            "recorded_at": recorded_at_text,
        }
        payload = {
            **legacy_payload,
            "profile": "agentkernel.intent-attempt-history/v2",
            "effective_idempotency_key": effective_idempotency_key,
        }
        if (
            attempt.state not in expected_states
            or owner_transaction_id != transaction_id
            or int(head_row["sequence"]) != head_sequence
            or str(head_row["history_digest"]) != head_digest
            or str(head_row["owner_transaction_id"]) != owner_transaction_id
            or int(head_row["owner_version"]) != owner_version
            or str(head_row["attempt_state"]) != attempt.state.value
            or (
                attempt.state is IntentAttemptState.REVIEW_REQUIRED
                and (
                    str(head_row["event_type"]) != "STATE_CHANGED"
                    or head_transaction_id != transaction_id
                    or head_evidence != attempt.evidence_digest
                    or head_recorded_at != attempt.updated_at
                )
            )
            or str(head_row["effective_idempotency_key"]) != effective_idempotency_key
            or validated_head_digest != head_digest
            or head_digest not in {canonical_digest(legacy_payload), canonical_digest(payload)}
            or (
                previous_history_digest
                != (None if previous_row is None else str(previous_row["history_digest"]))
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence differs from bounded intent settlement",
            )
        return attempt.state, attempt.evidence_digest, attempt.updated_at

    def _validate_bounded_intent_history_binding_tx(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
        transaction_id: str,
        owner_version: int,
        history_sequence: int,
        history_digest: str,
    ) -> None:
        history_row = self._connection.execute(
            "SELECT * FROM enforced_intent_attempt_history WHERE tenant_id = ? "
            "AND intent_hash = ? AND sequence = ?",
            (tenant_id, intent_hash, history_sequence),
        ).fetchone()
        predecessor_row = (
            None
            if history_sequence == 0
            else self._connection.execute(
                "SELECT * FROM enforced_intent_attempt_history WHERE tenant_id = ? "
                "AND intent_hash = ? AND sequence = ?",
                (tenant_id, intent_hash, history_sequence - 1),
            ).fetchone()
        )
        predecessor_parent_row = (
            None
            if history_sequence <= 1
            else self._connection.execute(
                "SELECT history_digest FROM enforced_intent_attempt_history "
                "WHERE tenant_id = ? AND intent_hash = ? AND sequence = ?",
                (tenant_id, intent_hash, history_sequence - 2),
            ).fetchone()
        )
        successor_row = self._connection.execute(
            "SELECT * FROM enforced_intent_attempt_history WHERE tenant_id = ? "
            "AND intent_hash = ? AND sequence = ?",
            (tenant_id, intent_hash, history_sequence + 1),
        ).fetchone()
        expected_predecessor_parent = (
            None
            if predecessor_parent_row is None
            else str(predecessor_parent_row["history_digest"])
        )
        predecessor_digest = (
            None
            if predecessor_row is None
            else self._validate_bounded_intent_history_row_tx(
                predecessor_row,
                expected_previous_digest=expected_predecessor_parent,
            )
        )
        validated_digest = (
            None
            if history_row is None
            else self._validate_bounded_intent_history_row_tx(
                history_row,
                expected_previous_digest=predecessor_digest,
            )
        )
        if successor_row is not None:
            self._validate_bounded_intent_history_row_tx(
                successor_row,
                expected_previous_digest=validated_digest,
            )
        if (
            history_row is None
            or str(history_row["transaction_id"]) != transaction_id
            or str(history_row["owner_transaction_id"]) != transaction_id
            or _require_stored_integer(
                history_row["owner_version"],
                field="recovery handoff intent owner version",
            )
            != owner_version
            or validated_digest != history_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff intent binding differs from its historical chain",
            )

    def _validate_bounded_intent_binding_tx(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
        transaction_id: str,
        owner_version: int,
        history_sequence: int,
        history_digest: str,
    ) -> tuple[IntentAttemptState, str | None, datetime]:
        settlement = self._validate_bounded_intent_settlement_tx(
            tenant_id=tenant_id,
            intent_hash=intent_hash,
            transaction_id=transaction_id,
            expected_states=frozenset(IntentAttemptState),
        )
        owner_row = self._connection.execute(
            "SELECT owner_transaction_id, owner_version FROM enforced_intent_owners "
            "WHERE tenant_id = ? AND intent_hash = ?",
            (tenant_id, intent_hash),
        ).fetchone()
        self._validate_bounded_intent_history_binding_tx(
            tenant_id=tenant_id,
            intent_hash=intent_hash,
            transaction_id=transaction_id,
            owner_version=owner_version,
            history_sequence=history_sequence,
            history_digest=history_digest,
        )
        if (
            owner_row is None
            or str(owner_row["owner_transaction_id"]) != transaction_id
            or _require_stored_integer(
                owner_row["owner_version"],
                field="recovery handoff current intent owner version",
            )
            != owner_version
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Open recovery handoff intent owner differs from its binding",
            )
        return settlement

    def _validate_bounded_intent_attempt_lifecycle_tx(
        self,
        *,
        tenant_id: str,
        intent_hash: str,
        transaction_id: str,
        expected_states: frozenset[IntentAttemptState],
    ) -> IntentAttemptRecord:
        """Validate one attempt and its latest own history row without current ownership."""

        attempt_row = self._connection.execute(
            "SELECT * FROM enforced_intent_attempts WHERE tenant_id = ? "
            "AND intent_hash = ? AND transaction_id = ?",
            (tenant_id, intent_hash, transaction_id),
        ).fetchone()
        if attempt_row is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff lost its historical intent attempt",
            )
        attempt = self._intent_attempt_from_row(attempt_row)
        history_rows = self._connection.execute(
            "SELECT * FROM enforced_intent_attempt_history WHERE tenant_id = ? "
            "AND intent_hash = ? AND transaction_id = ? AND attempt_state = ? "
            "AND recorded_at = ? ORDER BY sequence DESC LIMIT 2",
            (
                tenant_id,
                intent_hash,
                transaction_id,
                attempt.state.value,
                _timestamp(attempt.updated_at),
            ),
        ).fetchall()
        if len(history_rows) != 1 or attempt.state not in expected_states:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff intent attempt differs from its lifecycle",
            )
        history_row = history_rows[0]
        sequence = _require_stored_integer(
            history_row["sequence"],
            field="recovery handoff intent attempt history sequence",
        )
        predecessor_row = (
            None
            if sequence == 0
            else self._connection.execute(
                "SELECT * FROM enforced_intent_attempt_history WHERE tenant_id = ? "
                "AND intent_hash = ? AND sequence = ?",
                (tenant_id, intent_hash, sequence - 1),
            ).fetchone()
        )
        predecessor_parent_row = (
            None
            if sequence <= 1
            else self._connection.execute(
                "SELECT history_digest FROM enforced_intent_attempt_history "
                "WHERE tenant_id = ? AND intent_hash = ? AND sequence = ?",
                (tenant_id, intent_hash, sequence - 2),
            ).fetchone()
        )
        predecessor_digest = (
            None
            if predecessor_row is None
            else self._validate_bounded_intent_history_row_tx(
                predecessor_row,
                expected_previous_digest=(
                    None
                    if predecessor_parent_row is None
                    else str(predecessor_parent_row["history_digest"])
                ),
            )
        )
        history_digest = self._validate_bounded_intent_history_row_tx(
            history_row,
            expected_previous_digest=predecessor_digest,
        )
        successor_row = self._connection.execute(
            "SELECT * FROM enforced_intent_attempt_history WHERE tenant_id = ? "
            "AND intent_hash = ? AND sequence = ?",
            (tenant_id, intent_hash, sequence + 1),
        ).fetchone()
        if successor_row is not None:
            self._validate_bounded_intent_history_row_tx(
                successor_row,
                expected_previous_digest=history_digest,
            )
        if (
            str(history_row["event_type"]) not in {"ACQUIRE", "STATE_CHANGED"}
            or str(history_row["owner_transaction_id"]) != transaction_id
            or str(history_row["attempt_state"]) != attempt.state.value
            or (
                None
                if history_row["evidence_digest"] is None
                else str(history_row["evidence_digest"])
            )
            != attempt.evidence_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff intent attempt history differs from its projection",
            )
        return attempt

    def _validate_recovery_evidence_unavailable_association_tx(
        self,
        record: RecoveryEvidenceUnavailableRecord,
    ) -> RecoveryWorkRecord:
        work = self._get_recovery_work_tx(
            record.tenant_id,
            record.transaction_id,
            record.recovery_id,
        )
        if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
            self._assert_reconciliation_attempt_lineage_tx(work)
        claimed = (
            work.permit is not None
            and work.permit_ref is not None
            and work.lease_id is not None
            and work.worker_id is not None
            and work.fencing_token is not None
        )
        unclaimed = (
            work.permit is None
            and work.permit_ref is None
            and work.lease_id is None
            and work.worker_id is None
            and work.fencing_token is None
            and work.attempt == 0
        )
        if not claimed and not unclaimed:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence has partial execution bindings",
            )
        known_no_effect = unclaimed or record.boundary in {
            "POST_CLAIM_SETUP",
            "RECONCILIATION_SETUP_OR_QUERY",
        }
        lease = (
            None
            if unclaimed
            else self._get_worker_lease_tx(
                record.tenant_id,
                record.transaction_id,
                cast("str", work.lease_id),
            )
        )
        expected_lease_purpose = (
            LeasePurpose.RECONCILIATION
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
            else LeasePurpose.RECOVERY
        )
        released_before_terminalization = record.boundary == "RECOVERY_LEASE_RELEASED"
        required_work_evidence = {
            *record.supporting_refs,
            work.target_evidence_ref,
            *((work.permit_ref,) if work.permit_ref is not None else ()),
        }
        if (
            work.state is not RecoveryWorkState.REVIEW_REQUIRED
            or work.updated_at != record.reported_at
            or work.reason_code != record.reason_code
            or work.unavailable_record_digest != record.record_digest
            or not required_work_evidence.issubset(work.evidence_refs)
            or record.record_digest in work.evidence_refs
            or (
                lease is not None
                and (
                    lease.worker_id != work.worker_id
                    or lease.fencing_token != work.fencing_token
                    or lease.purpose is not expected_lease_purpose
                    or lease.version != 1
                    or lease.released_at is None
                    or (released_before_terminalization and lease.released_at > record.reported_at)
                    or (
                        not released_before_terminalization
                        and lease.released_at != record.reported_at
                    )
                )
            )
            or self._get_recovery_completion_report_tx(
                record.tenant_id,
                record.transaction_id,
                record.recovery_id,
            )
            is not None
            or self._get_late_recovery_report_tx(
                record.tenant_id,
                record.transaction_id,
                record.recovery_id,
            )
            is not None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence differs from terminal work or lease",
            )
        if lease is not None:
            newer_lease = self._connection.execute(
                "SELECT 1 FROM enforced_worker_leases WHERE tenant_id = ? "
                "AND transaction_id = ? AND fencing_token > ? LIMIT 1",
                (work.tenant_id, work.transaction_id, work.fencing_token),
            ).fetchone()
            if newer_lease is not None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unavailable recovery evidence was superseded by a newer fence",
                )
        _action_state, action_evidence, action_updated_at = (
            self._validate_bounded_intent_settlement_tx(
                tenant_id=work.tenant_id,
                intent_hash=work.recovery_action_intent_hash,
                transaction_id=work.recovery_action_transaction_id,
                expected_states=frozenset(
                    {
                        IntentAttemptState.NO_EFFECT_CONFIRMED
                        if known_no_effect
                        else IntentAttemptState.REVIEW_REQUIRED
                    }
                ),
            )
        )
        _target_state, _target_evidence, _target_updated_at = (
            self._validate_bounded_intent_settlement_tx(
                tenant_id=work.tenant_id,
                intent_hash=work.intent_hash,
                transaction_id=work.transaction_id,
                expected_states=frozenset(
                    {
                        IntentAttemptState.REVIEW_REQUIRED,
                        IntentAttemptState.NO_EFFECT_CONFIRMED,
                    }
                ),
            )
        )
        if action_evidence != record.record_digest or action_updated_at != record.reported_at:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence differs from intent settlement evidence",
            )
        transaction = self._get_enforced_transaction_head_tx(
            work.tenant_id,
            work.transaction_id,
        )
        common_boundaries = (
            {"RECOVERY_DEADLINE"}
            if unclaimed
            else {
                "RECOVERY_DEADLINE",
                "RECOVERY_LEASE_EXPIRED",
                "RECOVERY_LEASE_RELEASED",
            }
        )
        kind_boundaries = (
            {
                "RECONCILIATION_SETUP_OR_QUERY",
                "RECONCILIATION_EVIDENCE",
                *common_boundaries,
            }
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
            else {
                "POST_CLAIM_SETUP",
                "RECOVERY_ADAPTER_OR_EVIDENCE",
                *common_boundaries,
            }
        )
        authorization_round = self._get_authorization_round_tx(
            work.tenant_id,
            work.transaction_id,
            work.authorization_round_id,
        )
        self._assert_recovery_round_bindings(work, authorization_round)
        if authorization_round.authority_valid_until is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence lost its authority deadline",
            )
        recovery_deadline = min(work.deadline, authorization_round.authority_valid_until)
        if (
            record.boundary not in kind_boundaries
            or (record.boundary == "RECOVERY_DEADLINE" and record.reported_at < recovery_deadline)
            or (
                record.boundary == "RECOVERY_LEASE_EXPIRED"
                and (lease is None or record.reported_at < lease.expires_at)
            )
            or (
                record.boundary == "RECOVERY_LEASE_RELEASED"
                and (
                    lease is None
                    or lease.released_at is None
                    or lease.released_at > record.reported_at
                )
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence boundary differs from durable timing",
            )
        recovery_reservation = self._read_capability_chain(
            tenant_id=work.tenant_id,
            goal_id=cast("str", authorization_round.reservation_goal_id),
            run_id=cast("str", authorization_round.reservation_run_id),
            intent_hash=work.recovery_action_intent_hash,
        )
        if (
            recovery_reservation is None
            or (
                unclaimed
                and (
                    recovery_reservation.state is not CapabilityReservationState.RELEASED
                    or work.reservation_version is None
                    or recovery_reservation.version != work.reservation_version + 1
                )
            )
            or (
                claimed
                and (
                    recovery_reservation.state is not CapabilityReservationState.COMMITTED
                    or recovery_reservation.version != work.reservation_version
                    or capability_reservation_digest(recovery_reservation)
                    != work.capability_reservation_digest
                )
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence differs from capability settlement",
            )
        self._assert_recovery_capability_settlement_tx(
            work,
            authorization_round,
            expected_state=(
                CapabilityReservationState.RELEASED
                if unclaimed
                else CapabilityReservationState.COMMITTED
            ),
        )
        handoff_row = self._connection.execute(
            "SELECT * FROM enforced_recovery_action_handoffs "
            "WHERE tenant_id = ? AND target_transaction_id = ? AND recovery_id = ?",
            (work.tenant_id, work.transaction_id, work.recovery_id),
        ).fetchone()
        handoff = (
            None
            if handoff_row is None
            else self._recovery_action_handoff_from_row(
                handoff_row,
                tenant_id=work.tenant_id,
                target_transaction_id=work.transaction_id,
                recovery_id=work.recovery_id,
            )
        )
        if (
            handoff is None
            or handoff.closed_at != record.reported_at
            or handoff.failure_evidence_status
            is not RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE
            or handoff.failure_evidence_ref is not None
            or handoff.failure_reason_code != record.reason_code
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence differs from terminal handoff",
            )
        self._validate_recovery_action_handoff_reverse_tx(
            handoff,
            tenant_id=work.tenant_id,
        )
        attempt: ReconciliationAttemptRecord | None = None
        if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
            attempt_row = self._connection.execute(
                "SELECT * FROM enforced_reconciliation_attempts "
                "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
                "AND attempt = ?",
                (work.tenant_id, work.transaction_id, work.recovery_id, work.attempt),
            ).fetchone()
            attempt = None if attempt_row is None else self._reconciliation_from_row(attempt_row)
            if attempt is None:
                if transaction.state is not TransactionState.IN_DOUBT:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Unavailable unstarted reconciliation did not remain IN_DOUBT",
                    )
            elif (
                attempt.outcome is not ReconciliationOutcome.UNKNOWN
                or attempt.version != 1
                or attempt.completed_at != record.reported_at
                or attempt.next_attempt_not_before is not None
                or attempt.operation_evidence_ref is not None
                or attempt.operation_reason_code is not None
                or attempt.completion_evidence_refs != record.supporting_refs
                or not required_work_evidence.issubset(attempt.evidence_refs)
                or _reconciliation_attempt_digest(attempt) not in work.evidence_refs
                or record.record_digest in attempt.evidence_refs
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unavailable reconciliation differs from its closed attempt",
                )
            if attempt is not None:
                self._assert_reconciliation_attempt_binding_tx(work, attempt)
        elif work.kind is RecoveryWorkKind.DISCARD_STAGING:
            stage = self._get_stage_material_tx(work.tenant_id, work.transaction_id)
            if (
                stage.state is not StageMaterialState.DISCARD_FAILED
                or stage.discard_evidence_ref != record.record_digest
                or stage.updated_at != record.reported_at
                or stage.version
                != (
                    4
                    if stage.verification_ref is not None
                    else (
                        3
                        if stage.staged_receipt_ref is not None
                        else (2 if stage.staged_effect_ref is not None else 1)
                    )
                )
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unavailable discard evidence differs from private stage settlement",
                )
        binding_row = self._connection.execute(
            "SELECT * FROM enforced_recovery_evidence_unavailable_event_bindings "
            "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ?",
            (record.tenant_id, record.transaction_id, record.recovery_id),
        ).fetchone()
        event_required = work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH or attempt is not None
        if binding_row is None:
            if event_required:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unavailable recovery evidence lost its transaction-event binding",
                )
        else:
            event_row = self._connection.execute(
                "SELECT * FROM enforced_transaction_events "
                "WHERE tenant_id = ? AND transaction_id = ? AND sequence = ?",
                (
                    record.tenant_id,
                    record.transaction_id,
                    int(binding_row["event_sequence"]),
                ),
            ).fetchone()
            if event_row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unavailable recovery evidence event binding is dangling",
                )
            event = self._event_from_row(event_row)
            expected_event_evidence = {
                canonical_digest(work),
                *work.evidence_refs,
            }
            expected_event = (
                TransitionEvent.RECOVERY_UNAVAILABLE.value
                if unclaimed
                and work.kind in {RecoveryWorkKind.ROLLBACK, RecoveryWorkKind.COMPENSATE}
                else {
                    RecoveryWorkKind.DISCARD_STAGING: (
                        TransitionEvent.STAGING_DISCARD_FAILED.value
                    ),
                    RecoveryWorkKind.ROLLBACK: (TransitionEvent.ROLLBACK_FAILED_OR_UNKNOWN.value),
                    RecoveryWorkKind.COMPENSATE: (
                        TransitionEvent.COMPENSATION_FAILED_OR_UNKNOWN.value
                    ),
                    RecoveryWorkKind.RECONCILE_DISPATCH: (
                        TransitionEvent.RECONCILIATION_UNKNOWN.value
                    ),
                }[work.kind]
            )
            if (
                not event_required
                or str(binding_row["record_digest"]) != record.record_digest
                or str(binding_row["event_digest"]) != event.event_digest
                or event.event != expected_event
                or event.recorded_at != record.reported_at
                or event.sequence != transaction.version
                or event.evidence_refs != tuple(sorted(expected_event_evidence))
                or record.record_digest in event.evidence_refs
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unavailable recovery evidence differs from its transaction event",
                )
        expected_transaction_state = (
            TransactionState.RECOVERY_FAILED
            if unclaimed and work.kind in {RecoveryWorkKind.ROLLBACK, RecoveryWorkKind.COMPENSATE}
            else {
                RecoveryWorkKind.DISCARD_STAGING: TransactionState.RECOVERY_FAILED,
                RecoveryWorkKind.ROLLBACK: TransactionState.RECOVERY_FAILED,
                RecoveryWorkKind.COMPENSATE: TransactionState.COMPENSATION_FAILED,
                RecoveryWorkKind.RECONCILE_DISPATCH: TransactionState.IN_DOUBT,
            }[work.kind]
        )
        if transaction.state is not expected_transaction_state:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence differs from transaction settlement",
            )
        if event_required and transaction.reason_code != record.reason_code:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence differs from transaction reason",
            )
        if event_required and transaction.updated_at != record.reported_at:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence differs from transaction timing",
            )
        target_dispatch_row = self._connection.execute(
            "SELECT 1 FROM enforced_commit_dispatches WHERE tenant_id = ? "
            "AND transaction_id = ? LIMIT 1",
            (work.tenant_id, work.transaction_id),
        ).fetchone()
        target_dispatch = (
            None
            if target_dispatch_row is None
            else self._get_commit_dispatch_head_tx(
                work.tenant_id,
                work.transaction_id,
            )
        )
        if work.kind is not RecoveryWorkKind.DISCARD_STAGING and (
            target_dispatch is None
            or target_dispatch.dispatch_id != work.target_id
            or target_dispatch.intent_hash != work.intent_hash
            or target_dispatch.owner_version != work.target_owner_version
            or canonical_digest(target_dispatch) != work.target_evidence_ref
            or target_dispatch.permit.target_version_guard != work.target_version_guard
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Unavailable recovery evidence differs from its dispatch generation",
            )
        self._assert_target_capability_settlement_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            intent_hash=work.intent_hash,
            owner_version=work.target_owner_version,
            dispatch=target_dispatch,
        )
        return work

    def _validate_recovery_work_unavailable_link_tx(
        self,
        work: RecoveryWorkRecord,
    ) -> None:
        record = self._get_recovery_evidence_unavailable_tx(
            work.tenant_id,
            work.transaction_id,
            work.recovery_id,
        )
        if work.unavailable_record_digest is None:
            if record is not None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unavailable recovery evidence is orphaned from its work head",
                )
            return
        if record is None or record.record_digest != work.unavailable_record_digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery work lost its typed unavailable evidence record",
            )
        self._validate_recovery_evidence_unavailable_association_tx(record)

    def get_recovery_evidence_unavailable(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
    ) -> RecoveryEvidenceUnavailableRecord | None:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        with self._read_snapshot():
            record = self._get_recovery_evidence_unavailable_tx(
                tenant_id,
                transaction_id,
                recovery_id,
            )
            if record is not None:
                self._validate_recovery_evidence_unavailable_association_tx(record)
            return record

    def get_recovery_evidence_unavailable_by_digest(
        self,
        *,
        tenant_id: str,
        record_digest: str,
    ) -> RecoveryEvidenceUnavailableRecord:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        record_digest = _require_digest(record_digest, field="record_digest")
        with self._read_snapshot():
            row = self._connection.execute(
                "SELECT * FROM enforced_recovery_evidence_unavailable_reports "
                "WHERE tenant_id = ? AND record_digest = ?",
                (tenant_id, record_digest),
            ).fetchone()
            if row is None:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Unknown unavailable recovery evidence record in this tenant",
                )
            record = self._recovery_evidence_unavailable_from_row(row)
            self._validate_recovery_evidence_unavailable_association_tx(record)
            return record

    def _insert_recovery_evidence_unavailable_tx(
        self,
        record: RecoveryEvidenceUnavailableRecord,
    ) -> None:
        self._execute(
            "INSERT INTO enforced_recovery_evidence_unavailable_reports("
            "tenant_id, transaction_id, recovery_id, boundary, evidence_status, "
            "operation_evidence_ref, supporting_refs_json, reported_at, reason_code, "
            "record_digest, record_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.tenant_id,
                record.transaction_id,
                record.recovery_id,
                record.boundary,
                record.evidence_status,
                record.operation_evidence_ref,
                canonical_json_text(record.supporting_refs),
                _timestamp(record.reported_at),
                record.reason_code,
                record.record_digest,
                canonical_json_text(record),
            ),
        )

    def _assert_late_recovery_retry_tx(
        self,
        work: RecoveryWorkRecord,
        report: LateRecoveryReportRecord,
        attempt: ReconciliationAttemptRecord | None,
    ) -> tuple[EnforcedTransactionRecord, WorkerLeaseRecord]:
        """Validate the closed uncertain-effect settlement behind a late exact retry."""

        if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
            self._assert_reconciliation_attempt_lineage_tx(work)

        if (
            work.state is not RecoveryWorkState.REVIEW_REQUIRED
            or work.permit is None
            or work.permit_ref is None
            or work.lease_id is None
            or work.worker_id is None
            or work.fencing_token is None
            or work.updated_at != report.reported_at
            or work.reason_code != report.reason_code
            or report.terminal_work_digest != canonical_digest(work)
            or report.reported_at < min(work.deadline, work.permit.deadline)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery retry differs from its terminal work generation",
            )
        lease = self._get_worker_lease_tx(
            work.tenant_id,
            work.transaction_id,
            work.lease_id,
        )
        expected_purpose = (
            LeasePurpose.RECONCILIATION
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
            else LeasePurpose.RECOVERY
        )
        if (
            lease.worker_id != work.worker_id
            or lease.fencing_token != work.fencing_token
            or lease.purpose is not expected_purpose
            or lease.released_at != report.reported_at
            or lease.version != 1
            or report.reported_at < lease.acquired_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery retry lost its exact released lease",
            )
        newer_lease = self._connection.execute(
            "SELECT 1 FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND fencing_token > ? LIMIT 1",
            (work.tenant_id, work.transaction_id, work.fencing_token),
        ).fetchone()
        if newer_lease is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery retry was superseded by a newer fence",
            )
        handoff = self._assert_recovery_work_handoff_tx(work)
        if (
            handoff.closed_at != report.reported_at
            or handoff.failure_evidence_status is not RecoveryHandoffFailureEvidenceStatus.AVAILABLE
            or handoff.failure_evidence_ref != report.operation_evidence_ref
            or handoff.failure_reason_code != report.reason_code
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery retry differs from its closed action handoff",
            )
        self._validate_recovery_action_handoff_reverse_tx(
            handoff,
            tenant_id=work.tenant_id,
        )
        authorization_round = self._get_authorization_round_tx(
            work.tenant_id,
            work.transaction_id,
            work.authorization_round_id,
        )
        self._assert_recovery_round_bindings(work, authorization_round)
        self._assert_recovery_capability_settlement_tx(
            work,
            authorization_round,
            expected_state=CapabilityReservationState.COMMITTED,
        )
        self._validate_bounded_intent_history_binding_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.recovery_action_intent_hash,
            transaction_id=work.recovery_action_transaction_id,
            owner_version=work.owner_version,
            history_sequence=work.owner_history_sequence,
            history_digest=work.owner_history_digest,
        )
        action_attempt = self._validate_bounded_intent_attempt_lifecycle_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.recovery_action_intent_hash,
            transaction_id=work.recovery_action_transaction_id,
            expected_states=frozenset({IntentAttemptState.REVIEW_REQUIRED}),
        )
        if (
            action_attempt.evidence_digest != canonical_digest(work)
            or action_attempt.updated_at != report.reported_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery retry lost its action-intent terminal evidence",
            )
        target_states = (
            frozenset({IntentAttemptState.RECONCILE_REQUIRED})
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
            else (
                frozenset(
                    {
                        IntentAttemptState.REVIEW_REQUIRED,
                        IntentAttemptState.NO_EFFECT_CONFIRMED,
                    }
                )
                if work.kind is RecoveryWorkKind.DISCARD_STAGING
                else frozenset({IntentAttemptState.REVIEW_REQUIRED})
            )
        )
        self._validate_bounded_intent_history_binding_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.intent_hash,
            transaction_id=work.transaction_id,
            owner_version=work.target_owner_version,
            history_sequence=work.target_owner_history_sequence,
            history_digest=work.target_owner_history_digest,
        )
        target_attempt = self._validate_bounded_intent_attempt_lifecycle_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.intent_hash,
            transaction_id=work.transaction_id,
            expected_states=target_states,
        )
        transaction = self._get_enforced_transaction_tx(
            work.tenant_id,
            work.transaction_id,
        )
        expected_transaction_state = {
            RecoveryWorkKind.DISCARD_STAGING: TransactionState.RECOVERY_FAILED,
            RecoveryWorkKind.ROLLBACK: TransactionState.RECOVERY_FAILED,
            RecoveryWorkKind.COMPENSATE: TransactionState.COMPENSATION_FAILED,
            RecoveryWorkKind.RECONCILE_DISPATCH: TransactionState.IN_DOUBT,
        }[work.kind]
        event_required = work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH or (
            attempt is not None
        )
        if transaction.state is not expected_transaction_state or (
            event_required
            and (
                transaction.updated_at != report.reported_at
                or transaction.reason_code != report.reason_code
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery retry target transaction differs from its terminal phase",
            )
        if (
            target_attempt.updated_at == report.reported_at
            and target_attempt.evidence_digest != canonical_digest(work)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Late recovery retry changed its target-intent evidence",
            )
        if event_required:
            expected_event = {
                RecoveryWorkKind.DISCARD_STAGING: (TransitionEvent.STAGING_DISCARD_FAILED),
                RecoveryWorkKind.ROLLBACK: (TransitionEvent.ROLLBACK_FAILED_OR_UNKNOWN),
                RecoveryWorkKind.COMPENSATE: (TransitionEvent.COMPENSATION_FAILED_OR_UNKNOWN),
                RecoveryWorkKind.RECONCILE_DISPATCH: (TransitionEvent.RECONCILIATION_UNKNOWN),
            }[work.kind]
            event_row = self._connection.execute(
                "SELECT * FROM enforced_transaction_events WHERE tenant_id = ? "
                "AND transaction_id = ? AND sequence = ?",
                (work.tenant_id, work.transaction_id, transaction.version),
            ).fetchone()
            event = None if event_row is None else self._event_from_row(event_row)
            if (
                event is None
                or event.event != expected_event.value
                or event.recorded_at != report.reported_at
                or event.evidence_refs
                != tuple(sorted({canonical_digest(work), *work.evidence_refs}))
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late recovery retry lost its exact transaction event",
                )
        if work.kind is RecoveryWorkKind.DISCARD_STAGING:
            stage = self._get_stage_material_tx(work.tenant_id, work.transaction_id)
            if (
                stage.stage_id != work.target_id
                or stage.target_version_guard != work.target_version_guard
                or stage.state is not StageMaterialState.DISCARD_FAILED
                or stage.discard_evidence_ref != report.operation_evidence_ref
                or stage.updated_at != report.reported_at
                or stage.version
                != (
                    4
                    if stage.verification_ref is not None
                    else (
                        3
                        if stage.staged_receipt_ref is not None
                        else (2 if stage.staged_effect_ref is not None else 1)
                    )
                )
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late recovery retry differs from its failed stage settlement",
                )
            target_dispatch_row = self._connection.execute(
                "SELECT 1 FROM enforced_commit_dispatches WHERE tenant_id = ? "
                "AND transaction_id = ? LIMIT 1",
                (work.tenant_id, work.transaction_id),
            ).fetchone()
            target_dispatch = (
                None
                if target_dispatch_row is None
                else self._get_commit_dispatch_tx(
                    work.tenant_id,
                    work.transaction_id,
                )
            )
        else:
            target_dispatch = self._get_commit_dispatch_tx(
                work.tenant_id,
                work.transaction_id,
            )
            if (
                target_dispatch.dispatch_id != work.target_id
                or target_dispatch.intent_hash != work.intent_hash
                or target_dispatch.owner_version != work.target_owner_version
                or canonical_digest(target_dispatch) != work.target_evidence_ref
                or target_dispatch.permit.target_version_guard != work.target_version_guard
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late recovery retry differs from its dispatch target",
                )
        if attempt is not None:
            self._assert_reconciliation_attempt_binding_tx(work, attempt)
            if (
                attempt.outcome is not ReconciliationOutcome.UNKNOWN
                or attempt.version != 1
                or attempt.completed_at != report.reported_at
                or attempt.next_attempt_not_before is not None
                or attempt.operation_evidence_ref != report.operation_evidence_ref
                or attempt.operation_reason_code != report.operation_reason_code
                or attempt.completion_evidence_refs != report.evidence_refs
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late recovery retry differs from its closed reconciliation attempt",
                )
        self._assert_target_capability_settlement_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            intent_hash=work.intent_hash,
            owner_version=work.target_owner_version,
            dispatch=target_dispatch,
        )
        self._assert_no_orphan_active_recovery_lease_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
        )
        return transaction, lease

    def record_late_recovery_outcome(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        expected_work_version: int,
        evidence_refs: tuple[str, ...],
        operation_evidence_ref: str,
        operation_reason_code: str | None = None,
        reported_at: datetime,
        reason_code: str,
    ) -> LateRecoveryResult:
        """Fence late recovery evidence without treating it as verified success.

        An adapter response arriving at or after the exact permit deadline cannot be
        accepted by the normal completion APIs.  This operation preserves that evidence,
        closes the running generation as review-required, releases its lease, and moves
        the original transaction through an existing failure/unknown transition.
        """

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        reason_code = _require_identifier(reason_code, field="reason_code")
        if expected_work_version < 0:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Expected recovery work version cannot be negative",
            )
        normalized_refs = tuple(
            sorted({_require_digest(value, field="evidence_ref") for value in evidence_refs})
        )
        if not normalized_refs:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Late recovery outcome requires durable evidence",
            )
        operation_evidence_ref = _require_digest(
            operation_evidence_ref,
            field="operation_evidence_ref",
        )
        if operation_reason_code is not None:
            operation_reason_code = _require_identifier(
                operation_reason_code,
                field="operation_reason_code",
            )
        if operation_evidence_ref not in normalized_refs:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Operation evidence must be included in the late evidence set",
            )
        with self._immediate():
            work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                self._assert_reconciliation_attempt_lineage_tx(work)
            if (
                work.state is RecoveryWorkState.REVIEW_REQUIRED
                and work.version == expected_work_version + 1
            ):
                report = LateRecoveryReportRecord.create(
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                    recovery_id=recovery_id,
                    operation_evidence_ref=operation_evidence_ref,
                    operation_reason_code=operation_reason_code,
                    evidence_refs=normalized_refs,
                    reported_at=reported_at,
                    reason_code=reason_code,
                    terminal_work_digest=canonical_digest(work),
                )
                stored_report = self._get_late_recovery_report_tx(
                    tenant_id,
                    transaction_id,
                    recovery_id,
                )
                if stored_report != report:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Late recovery retry changed its exact submitted report",
                    )
                stored_attempt: ReconciliationAttemptRecord | None = None
                if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                    attempt_row = self._connection.execute(
                        "SELECT * FROM enforced_reconciliation_attempts "
                        "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
                        "AND attempt = ?",
                        (tenant_id, transaction_id, recovery_id, work.attempt),
                    ).fetchone()
                    if attempt_row is not None:
                        stored_attempt = self._reconciliation_from_row(attempt_row)
                transaction, lease = self._assert_late_recovery_retry_tx(
                    work,
                    report,
                    stored_attempt,
                )
                return LateRecoveryResult(
                    work,
                    transaction,
                    None,
                    lease,
                    stored_attempt,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )

            if (
                work.state is not RecoveryWorkState.RUNNING
                or work.version != expected_work_version
                or work.permit is None
                or work.permit_ref is None
                or work.lease_id is None
                or work.worker_id is None
                or work.fencing_token is None
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Late outcome requires the exact running recovery generation",
                )
            if reported_at < min(work.deadline, work.permit.deadline):
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Recovery outcome is not late; use the normal completion API",
                )
            if (
                self._get_late_recovery_report_tx(tenant_id, transaction_id, recovery_id)
                is not None
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Running recovery generation already has a late report",
                )
            purpose = (
                LeasePurpose.RECONCILIATION
                if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                else LeasePurpose.RECOVERY
            )
            lease = self._get_worker_lease_tx(tenant_id, transaction_id, work.lease_id)
            if (
                lease.worker_id != work.worker_id
                or lease.fencing_token != work.fencing_token
                or lease.purpose is not purpose
                or lease.released_at is not None
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Late recovery lease was released or superseded",
                )
            newer = self._connection.execute(
                "SELECT 1 FROM enforced_worker_leases WHERE tenant_id = ? "
                "AND transaction_id = ? AND fencing_token > ? LIMIT 1",
                (tenant_id, transaction_id, work.fencing_token),
            ).fetchone()
            if newer is not None:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Late recovery lease was superseded by a newer fence",
                )

            transaction, stage, _ = self._assert_recovery_target_tx(
                work,
                require_authorizable_state=False,
            )
            attempt: ReconciliationAttemptRecord | None = None
            event: EnforcedTransactionEvent | None = None
            late_refs = {
                *work.evidence_refs,
                *normalized_refs,
                work.permit_ref,
                work.target_evidence_ref,
            }

            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                attempt_row = self._connection.execute(
                    "SELECT * FROM enforced_reconciliation_attempts "
                    "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
                    "AND attempt = ?",
                    (tenant_id, transaction_id, recovery_id, work.attempt),
                ).fetchone()
                if attempt_row is None:
                    if transaction.state is not TransactionState.IN_DOUBT:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Late reconciliation without STARTED evidence must remain IN_DOUBT",
                        )
                else:
                    started = self._reconciliation_from_row(attempt_row)
                    if (
                        started.outcome is not None
                        or transaction.state is not TransactionState.RECONCILING
                    ):
                        raise AgentKernelError(
                            ErrorCode.ILLEGAL_TRANSITION,
                            "Late reconciliation no longer controls a STARTED generation",
                        )
                    attempt = ReconciliationAttemptRecord.model_validate(
                        {
                            **started.model_dump(mode="python"),
                            "schema_version": "1.1",
                            "outcome": ReconciliationOutcome.UNKNOWN,
                            "evidence_refs": tuple(
                                sorted({*started.evidence_refs, *normalized_refs})
                            ),
                            "operation_evidence_ref": operation_evidence_ref,
                            "operation_reason_code": operation_reason_code,
                            "completion_evidence_refs": normalized_refs,
                            "completed_at": reported_at,
                            "next_attempt_not_before": None,
                            "version": 1,
                        }
                    )
                    self._update_reconciliation_attempt_tx(started, attempt)
                    late_refs.add(_reconciliation_attempt_digest(attempt))
            else:
                expected_source = {
                    RecoveryWorkKind.DISCARD_STAGING: TransactionState.ABORTING,
                    RecoveryWorkKind.ROLLBACK: TransactionState.ROLLING_BACK,
                    RecoveryWorkKind.COMPENSATE: TransactionState.COMPENSATING,
                }[work.kind]
                if transaction.state is not expected_source:
                    raise AgentKernelError(
                        ErrorCode.ILLEGAL_TRANSITION,
                        "Late recovery target is no longer its running generation",
                    )

            updated_work = RecoveryWorkRecord.model_validate(
                {
                    **work.model_dump(mode="python"),
                    "state": RecoveryWorkState.REVIEW_REQUIRED,
                    "version": work.version + 1,
                    "evidence_refs": tuple(sorted(late_refs)),
                    "reason_code": reason_code,
                    "updated_at": reported_at,
                }
            )
            report = LateRecoveryReportRecord.create(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                recovery_id=recovery_id,
                operation_evidence_ref=operation_evidence_ref,
                operation_reason_code=operation_reason_code,
                evidence_refs=normalized_refs,
                reported_at=reported_at,
                reason_code=reason_code,
                terminal_work_digest=canonical_digest(updated_work),
            )
            self._insert_late_recovery_report_tx(report)
            work_evidence = canonical_digest(updated_work)

            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                if attempt is not None:
                    transaction, event = self._apply_transition_tx(
                        transaction,
                        expected_version=transaction.version,
                        transition_event=TransitionEvent.RECONCILIATION_UNKNOWN,
                        recorded_at=reported_at,
                        evidence_refs=(work_evidence, *updated_work.evidence_refs),
                        reason_code=reason_code,
                    )
            else:
                if work.kind is RecoveryWorkKind.DISCARD_STAGING:
                    if stage is None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Late discard lost its private stage material",
                        )
                    failed_stage = StageMaterialRecord.model_validate(
                        {
                            **stage.model_dump(mode="python"),
                            "state": StageMaterialState.DISCARD_FAILED,
                            "discard_evidence_ref": operation_evidence_ref,
                            "version": stage.version + 1,
                            "updated_at": reported_at,
                        }
                    )
                    self._update_stage_material_tx(stage, failed_stage)
                    self._finish_target_intent_tx(
                        work,
                        succeeded=False,
                        evidence_digest=work_evidence,
                        recorded_at=reported_at,
                    )
                    transition = TransitionEvent.STAGING_DISCARD_FAILED
                elif work.kind is RecoveryWorkKind.ROLLBACK:
                    transition = TransitionEvent.ROLLBACK_FAILED_OR_UNKNOWN
                else:
                    transition = TransitionEvent.COMPENSATION_FAILED_OR_UNKNOWN
                transaction, event = self._apply_transition_tx(
                    transaction,
                    expected_version=transaction.version,
                    transition_event=transition,
                    recorded_at=reported_at,
                    evidence_refs=(work_evidence, *updated_work.evidence_refs),
                    reason_code=reason_code,
                )

            self._transition_owned_attempt_tx(
                tenant_id=work.tenant_id,
                intent_hash=work.recovery_action_intent_hash,
                transaction_id=work.recovery_action_transaction_id,
                owner_version=work.owner_version,
                owner_history_sequence=work.owner_history_sequence,
                owner_history_digest=work.owner_history_digest,
                target_state=IntentAttemptState.REVIEW_REQUIRED,
                evidence_digest=work_evidence,
                recorded_at=reported_at,
            )
            self._close_recovery_work_handoff_tx(
                work,
                failure_evidence_status=RecoveryHandoffFailureEvidenceStatus.AVAILABLE,
                failure_evidence_ref=operation_evidence_ref,
                reason_code=reason_code,
                recorded_at=reported_at,
            )
            self._update_recovery_work_tx(work, updated_work)
            released = self._release_recovery_lease_tx(
                updated_work,
                released_at=reported_at,
            )
            return LateRecoveryResult(
                updated_work,
                transaction,
                event,
                released,
                attempt,
                EnforcedStoreDisposition.REVIEW_REQUIRED,
            )

    def terminalize_recovery_evidence_unavailable(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        expected_work_version: int,
        boundary: str,
        supporting_refs: tuple[str, ...],
        reported_at: datetime,
        reason_code: str,
    ) -> LateRecoveryResult:
        """Atomically fence possible recovery effects when artifact evidence is unavailable."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        recovery_id = _require_identifier(recovery_id, field="recovery_id")
        boundary = _require_identifier(boundary, field="boundary")
        reason_code = _require_identifier(reason_code, field="reason_code")
        if not reason_code.startswith(f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:"):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unavailable recovery terminalization requires an unavailable reason",
            )
        normalized_refs = tuple(
            sorted({_require_digest(value, field="supporting_ref") for value in supporting_refs})
        )
        if not normalized_refs:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unavailable recovery terminalization requires supporting references",
            )
        record = RecoveryEvidenceUnavailableRecord.create(
            tenant_id=tenant_id,
            transaction_id=transaction_id,
            recovery_id=recovery_id,
            boundary=boundary,
            supporting_refs=normalized_refs,
            reported_at=reported_at,
            reason_code=reason_code,
        )
        with self._immediate():
            work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                self._assert_reconciliation_attempt_lineage_tx(work)
            stored_record = self._get_recovery_evidence_unavailable_tx(
                tenant_id,
                transaction_id,
                recovery_id,
            )
            if stored_record is not None:
                if stored_record != record:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Unavailable recovery retry changed its terminal record",
                    )
                if (
                    work.state is not RecoveryWorkState.REVIEW_REQUIRED
                    or work.version != expected_work_version + 1
                    or work.updated_at != reported_at
                    or work.reason_code != reason_code
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Unavailable recovery retry differs from terminal work",
                    )
                stored_lease = (
                    None
                    if work.lease_id is None
                    else self._get_worker_lease_tx(
                        tenant_id,
                        transaction_id,
                        work.lease_id,
                    )
                )
                if stored_lease is not None:
                    released_before_terminalization = record.boundary == "RECOVERY_LEASE_RELEASED"
                    if (
                        stored_lease.released_at is None
                        or (
                            released_before_terminalization
                            and stored_lease.released_at > reported_at
                        )
                        or (
                            not released_before_terminalization
                            and stored_lease.released_at != reported_at
                        )
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Unavailable recovery retry lost its lease settlement",
                        )
                if stored_lease is None and (
                    work.permit is not None
                    or work.worker_id is not None
                    or work.fencing_token is not None
                    or work.attempt != 0
                    or record.boundary != "RECOVERY_DEADLINE"
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Unavailable unclaimed recovery retry gained execution bindings",
                    )
                stored_attempt: ReconciliationAttemptRecord | None = None
                if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                    attempt_row = self._connection.execute(
                        "SELECT * FROM enforced_reconciliation_attempts "
                        "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
                        "AND attempt = ?",
                        (tenant_id, transaction_id, recovery_id, work.attempt),
                    ).fetchone()
                    stored_attempt = (
                        None if attempt_row is None else self._reconciliation_from_row(attempt_row)
                    )
                self._validate_recovery_evidence_unavailable_association_tx(stored_record)
                return LateRecoveryResult(
                    work,
                    self._get_enforced_transaction_tx(tenant_id, transaction_id),
                    None,
                    stored_lease,
                    stored_attempt,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            pending = (
                work.state is RecoveryWorkState.PENDING
                and work.version == expected_work_version
                and work.permit is None
                and work.permit_ref is None
                and work.lease_id is None
                and work.worker_id is None
                and work.fencing_token is None
                and work.attempt == 0
                and boundary == "RECOVERY_DEADLINE"
            )
            running = (
                work.state is RecoveryWorkState.RUNNING
                and work.version == expected_work_version
                and work.permit is not None
                and work.permit_ref is not None
                and work.lease_id is not None
                and work.worker_id is not None
                and work.fencing_token is not None
            )
            if not pending and not running:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Unavailable evidence requires an exact pending-deadline or running generation",
                )
            known_no_effect = pending or boundary in {
                "POST_CLAIM_SETUP",
                "RECONCILIATION_SETUP_OR_QUERY",
            }
            lease: WorkerLeaseRecord | None = None
            if running:
                lease = self._get_worker_lease_tx(
                    tenant_id,
                    transaction_id,
                    cast("str", work.lease_id),
                )
                purpose = (
                    LeasePurpose.RECONCILIATION
                    if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH
                    else LeasePurpose.RECOVERY
                )
                released_before_terminalization = boundary == "RECOVERY_LEASE_RELEASED"
                if (
                    lease.worker_id != work.worker_id
                    or lease.fencing_token != work.fencing_token
                    or lease.purpose is not purpose
                    or (
                        released_before_terminalization
                        and (lease.released_at is None or lease.released_at > reported_at)
                    )
                    or (not released_before_terminalization and lease.released_at is not None)
                ):
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Unavailable recovery evidence lost its exact lease generation",
                    )
                newer = self._connection.execute(
                    "SELECT 1 FROM enforced_worker_leases WHERE tenant_id = ? "
                    "AND transaction_id = ? AND fencing_token > ? LIMIT 1",
                    (tenant_id, transaction_id, work.fencing_token),
                ).fetchone()
                if newer is not None:
                    raise AgentKernelError(
                        ErrorCode.VERSION_CONFLICT,
                        "Unavailable recovery evidence was superseded by a newer fence",
                    )
            authorization_round = self._get_authorization_round_tx(
                tenant_id,
                transaction_id,
                work.authorization_round_id,
            )
            self._assert_recovery_round_bindings(work, authorization_round)
            if authorization_round.authority_valid_until is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unavailable recovery evidence lost its authority deadline",
                )
            recovery_deadline = min(
                work.deadline,
                authorization_round.authority_valid_until,
            )
            if boundary == "RECOVERY_DEADLINE" and reported_at < recovery_deadline:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Unavailable recovery deadline evidence was reported too early",
                )
            recovery_reservation = self._read_capability_chain(
                tenant_id=tenant_id,
                goal_id=cast("str", authorization_round.reservation_goal_id),
                run_id=cast("str", authorization_round.reservation_run_id),
                intent_hash=work.recovery_action_intent_hash,
            )
            expected_reservation_state = (
                CapabilityReservationState.RESERVED
                if pending
                else CapabilityReservationState.COMMITTED
            )
            if (
                recovery_reservation is None
                or recovery_reservation.state is not expected_reservation_state
                or recovery_reservation.version != work.reservation_version
                or capability_reservation_digest(recovery_reservation)
                != work.capability_reservation_digest
                or recovery_reservation.activation_owner_transaction_id
                != work.recovery_action_transaction_id
                or recovery_reservation.activation_owner_version != work.owner_version
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unavailable recovery evidence lost its exact capability generation",
                )
            transaction, stage, _ = self._assert_recovery_target_tx(
                work,
                require_authorizable_state=False,
            )
            terminal_refs = tuple(
                sorted(
                    {
                        *work.evidence_refs,
                        *normalized_refs,
                        work.target_evidence_ref,
                        *((work.permit_ref,) if work.permit_ref is not None else ()),
                    }
                )
            )
            attempt: ReconciliationAttemptRecord | None = None
            event: EnforcedTransactionEvent | None = None
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                attempt_row = self._connection.execute(
                    "SELECT * FROM enforced_reconciliation_attempts "
                    "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
                    "AND attempt = ?",
                    (tenant_id, transaction_id, recovery_id, work.attempt),
                ).fetchone()
                if attempt_row is None:
                    if transaction.state is not TransactionState.IN_DOUBT:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Unavailable reconciliation without an attempt must remain IN_DOUBT",
                        )
                else:
                    started = self._reconciliation_from_row(attempt_row)
                    if (
                        started.outcome is not None
                        or transaction.state is not TransactionState.RECONCILING
                    ):
                        raise AgentKernelError(
                            ErrorCode.ILLEGAL_TRANSITION,
                            "Unavailable reconciliation no longer owns a started attempt",
                        )
                    attempt = ReconciliationAttemptRecord.model_validate(
                        {
                            **started.model_dump(mode="python"),
                            "schema_version": "1.1",
                            "outcome": ReconciliationOutcome.UNKNOWN,
                            "evidence_refs": tuple(
                                sorted({*started.evidence_refs, *terminal_refs})
                            ),
                            "completion_evidence_refs": normalized_refs,
                            "completed_at": reported_at,
                            "next_attempt_not_before": None,
                            "version": 1,
                        }
                    )
                    self._update_reconciliation_attempt_tx(started, attempt)
                    terminal_refs = tuple(
                        sorted({*terminal_refs, _reconciliation_attempt_digest(attempt)})
                    )
            else:
                expected_source = (
                    TransactionState.FAILED
                    if pending
                    and work.kind in {RecoveryWorkKind.ROLLBACK, RecoveryWorkKind.COMPENSATE}
                    else {
                        RecoveryWorkKind.DISCARD_STAGING: TransactionState.ABORTING,
                        RecoveryWorkKind.ROLLBACK: TransactionState.ROLLING_BACK,
                        RecoveryWorkKind.COMPENSATE: TransactionState.COMPENSATING,
                    }[work.kind]
                )
                if transaction.state is not expected_source:
                    raise AgentKernelError(
                        ErrorCode.ILLEGAL_TRANSITION,
                        "Unavailable recovery target is no longer its exact generation",
                    )
            updated_work = RecoveryWorkRecord.model_validate(
                {
                    **work.model_dump(mode="python"),
                    "state": RecoveryWorkState.REVIEW_REQUIRED,
                    "version": work.version + 1,
                    "evidence_refs": terminal_refs,
                    "reason_code": reason_code,
                    "unavailable_record_digest": record.record_digest,
                    "updated_at": reported_at,
                }
            )
            work_evidence = canonical_digest(updated_work)
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                if attempt is not None:
                    transaction, event = self._apply_transition_tx(
                        transaction,
                        expected_version=transaction.version,
                        transition_event=TransitionEvent.RECONCILIATION_UNKNOWN,
                        recorded_at=reported_at,
                        evidence_refs=(work_evidence, *terminal_refs),
                        reason_code=reason_code,
                    )
            else:
                if work.kind is RecoveryWorkKind.DISCARD_STAGING:
                    if stage is None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Unavailable discard evidence lost private stage material",
                        )
                    failed_stage = StageMaterialRecord.model_validate(
                        {
                            **stage.model_dump(mode="python"),
                            "state": StageMaterialState.DISCARD_FAILED,
                            "discard_evidence_ref": record.record_digest,
                            "version": stage.version + 1,
                            "updated_at": reported_at,
                        }
                    )
                    self._update_stage_material_tx(stage, failed_stage)
                    self._finish_target_intent_tx(
                        work,
                        succeeded=False,
                        evidence_digest=record.record_digest,
                        recorded_at=reported_at,
                    )
                    transition = TransitionEvent.STAGING_DISCARD_FAILED
                elif pending:
                    transition = TransitionEvent.RECOVERY_UNAVAILABLE
                elif work.kind is RecoveryWorkKind.ROLLBACK:
                    transition = TransitionEvent.ROLLBACK_FAILED_OR_UNKNOWN
                else:
                    transition = TransitionEvent.COMPENSATION_FAILED_OR_UNKNOWN
                transaction, event = self._apply_transition_tx(
                    transaction,
                    expected_version=transaction.version,
                    transition_event=transition,
                    recorded_at=reported_at,
                    evidence_refs=(work_evidence, *terminal_refs),
                    reason_code=reason_code,
                )
            if work.kind is not RecoveryWorkKind.DISCARD_STAGING:
                self._finish_target_intent_tx(
                    work,
                    succeeded=False,
                    evidence_digest=record.record_digest,
                    recorded_at=reported_at,
                )
            self._transition_owned_attempt_tx(
                tenant_id=work.tenant_id,
                intent_hash=work.recovery_action_intent_hash,
                transaction_id=work.recovery_action_transaction_id,
                owner_version=work.owner_version,
                owner_history_sequence=work.owner_history_sequence,
                owner_history_digest=work.owner_history_digest,
                target_state=(
                    IntentAttemptState.NO_EFFECT_CONFIRMED
                    if known_no_effect
                    else IntentAttemptState.REVIEW_REQUIRED
                ),
                evidence_digest=record.record_digest,
                recorded_at=reported_at,
            )
            if pending:
                self.release_capability_chain(
                    tenant_id=recovery_reservation.tenant_id,
                    goal_id=recovery_reservation.goal_id,
                    run_id=recovery_reservation.run_id,
                    intent_hash=recovery_reservation.intent_hash,
                    capability_ids=recovery_reservation.capability_ids,
                    fence=recovery_reservation.fence,
                    released_at=reported_at,
                )
            self._close_recovery_work_handoff_tx(
                work,
                failure_evidence_status=RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE,
                failure_evidence_ref=None,
                reason_code=reason_code,
                recorded_at=reported_at,
            )
            self._update_recovery_work_tx(work, updated_work)
            released = (
                None
                if pending
                else self._release_recovery_lease_tx(
                    updated_work,
                    released_at=reported_at,
                )
            )
            self._insert_recovery_evidence_unavailable_tx(record)
            if event is not None:
                self._execute(
                    "INSERT INTO enforced_recovery_evidence_unavailable_event_bindings("
                    "tenant_id, transaction_id, recovery_id, record_digest, "
                    "event_sequence, event_digest) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        tenant_id,
                        transaction_id,
                        recovery_id,
                        record.record_digest,
                        event.sequence,
                        event.event_digest,
                    ),
                )
            return LateRecoveryResult(
                updated_work,
                transaction,
                event,
                released,
                attempt,
                EnforcedStoreDisposition.REVIEW_REQUIRED,
            )

    def _reconciliation_from_row(self, row: sqlite3.Row) -> ReconciliationAttemptRecord:
        try:
            attempt = ReconciliationAttemptRecord.model_validate_json(str(row["record_json"]))
        except (ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stored reconciliation attempt is invalid",
            ) from error
        expected: dict[str, object] = {
            "tenant_id": attempt.tenant_id,
            "transaction_id": attempt.transaction_id,
            "intent_hash": attempt.intent_hash,
            "dispatch_id": attempt.dispatch_id,
            "recovery_id": attempt.recovery_id,
            "attempt": attempt.attempt,
            "lease_id": attempt.lease_id,
            "fencing_token": attempt.fencing_token,
            "outcome": None if attempt.outcome is None else attempt.outcome.value,
            "effect_receipt_ref": attempt.effect_receipt_ref,
            "committed_verification_permit_digest": (attempt.committed_verification_permit_digest),
            "committed_verification_permit_ref": (attempt.committed_verification_permit_ref),
            "committed_verification_ref": attempt.committed_verification_ref,
            "no_effect_evidence_ref": attempt.no_effect_evidence_ref,
            "operation_evidence_ref": attempt.operation_evidence_ref,
            "operation_reason_code": attempt.operation_reason_code,
            "evidence_refs_json": canonical_json_text(attempt.evidence_refs),
            "completion_evidence_refs_json": (
                None
                if attempt.completion_evidence_refs is None
                else canonical_json_text(attempt.completion_evidence_refs)
            ),
            "started_at": _timestamp(attempt.started_at),
            "completed_at": (
                None if attempt.completed_at is None else _timestamp(attempt.completed_at)
            ),
            "next_attempt_not_before": (
                None
                if attempt.next_attempt_not_before is None
                else _timestamp(attempt.next_attempt_not_before)
            ),
            "version": attempt.version,
            "record_digest": _reconciliation_attempt_digest(attempt),
            "record_json": _reconciliation_attempt_json(attempt),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation projection differs from canonical content",
            )
        return attempt

    def _get_reconciliation_attempt_tx(
        self,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        attempt: int,
    ) -> ReconciliationAttemptRecord:
        row = self._connection.execute(
            "SELECT * FROM enforced_reconciliation_attempts WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ? AND attempt = ?",
            (tenant_id, transaction_id, recovery_id, attempt),
        ).fetchone()
        if row is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unknown reconciliation attempt",
            )
        return self._reconciliation_from_row(row)

    def get_reconciliation_attempt(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        attempt: int,
    ) -> ReconciliationAttemptRecord:
        if attempt < 1:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Reconciliation attempt must be positive",
            )
        return self._get_reconciliation_attempt_tx(
            _require_identifier(tenant_id, field="tenant_id"),
            _require_identifier(transaction_id, field="transaction_id"),
            _require_identifier(recovery_id, field="recovery_id"),
            attempt,
        )

    def list_reconciliation_attempts(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
    ) -> tuple[ReconciliationAttemptRecord, ...]:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        rows = self._connection.execute(
            "SELECT * FROM enforced_reconciliation_attempts WHERE tenant_id = ? "
            "AND transaction_id = ? ORDER BY dispatch_id, recovery_id, attempt",
            (tenant_id, transaction_id),
        ).fetchall()
        return tuple(self._reconciliation_from_row(row) for row in rows)

    def get_started_reconciliation_attempt(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
    ) -> ReconciliationAttemptRecord | None:
        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        transaction_id = _require_identifier(transaction_id, field="transaction_id")
        rows = self._connection.execute(
            "SELECT * FROM enforced_reconciliation_attempts WHERE tenant_id = ? "
            "AND transaction_id = ? AND completed_at IS NULL "
            "ORDER BY dispatch_id, recovery_id, attempt",
            (tenant_id, transaction_id),
        ).fetchall()
        if len(rows) > 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Transaction has multiple started reconciliation attempts",
            )
        return None if not rows else self._reconciliation_from_row(rows[0])

    def _insert_reconciliation_attempt_tx(
        self,
        attempt: ReconciliationAttemptRecord,
    ) -> None:
        self._execute(
            "INSERT INTO enforced_reconciliation_attempts(tenant_id, transaction_id, "
            "intent_hash, dispatch_id, recovery_id, attempt, lease_id, fencing_token, "
            "outcome, effect_receipt_ref, committed_verification_permit_digest, "
            "committed_verification_permit_ref, committed_verification_ref, "
            "no_effect_evidence_ref, operation_evidence_ref, operation_reason_code, "
            "evidence_refs_json, completion_evidence_refs_json, "
            "started_at, completed_at, "
            "next_attempt_not_before, version, record_digest, record_json) VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "
            "?, NULL, ?, NULL, NULL, 0, ?, ?)",
            (
                attempt.tenant_id,
                attempt.transaction_id,
                attempt.intent_hash,
                attempt.dispatch_id,
                attempt.recovery_id,
                attempt.attempt,
                attempt.lease_id,
                attempt.fencing_token,
                canonical_json_text(attempt.evidence_refs),
                _timestamp(attempt.started_at),
                _reconciliation_attempt_digest(attempt),
                _reconciliation_attempt_json(attempt),
            ),
        )

    def _update_reconciliation_attempt_tx(
        self,
        current: ReconciliationAttemptRecord,
        updated: ReconciliationAttemptRecord,
    ) -> ReconciliationAttemptRecord:
        cursor = self._execute(
            "UPDATE enforced_reconciliation_attempts SET outcome = ?, "
            "effect_receipt_ref = ?, committed_verification_permit_digest = ?, "
            "committed_verification_permit_ref = ?, committed_verification_ref = ?, "
            "no_effect_evidence_ref = ?, operation_evidence_ref = ?, "
            "operation_reason_code = ?, "
            "evidence_refs_json = ?, completion_evidence_refs_json = ?, completed_at = ?, "
            "next_attempt_not_before = ?, version = ?, record_digest = ?, record_json = ? "
            "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
            "AND dispatch_id = ? AND attempt = ? AND version = ? AND completed_at IS NULL",
            (
                None if updated.outcome is None else updated.outcome.value,
                updated.effect_receipt_ref,
                updated.committed_verification_permit_digest,
                updated.committed_verification_permit_ref,
                updated.committed_verification_ref,
                updated.no_effect_evidence_ref,
                updated.operation_evidence_ref,
                updated.operation_reason_code,
                canonical_json_text(updated.evidence_refs),
                (
                    None
                    if updated.completion_evidence_refs is None
                    else canonical_json_text(updated.completion_evidence_refs)
                ),
                None if updated.completed_at is None else _timestamp(updated.completed_at),
                (
                    None
                    if updated.next_attempt_not_before is None
                    else _timestamp(updated.next_attempt_not_before)
                ),
                updated.version,
                _reconciliation_attempt_digest(updated),
                _reconciliation_attempt_json(updated),
                current.tenant_id,
                current.transaction_id,
                current.recovery_id,
                current.dispatch_id,
                current.attempt,
                current.version,
            ),
        )
        if cursor.rowcount != 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Reconciliation attempt compare-and-swap failed",
                retryable=True,
            )
        return updated

    def _assert_reconciliation_attempt_binding_tx(
        self,
        work: RecoveryWorkRecord,
        attempt: ReconciliationAttemptRecord,
    ) -> WorkerLeaseRecord:
        """Re-prove one reconciliation attempt against its immutable work generation."""

        if (
            work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
            or work.permit is None
            or work.permit_ref is None
            or work.lease_id is None
            or work.worker_id is None
            or work.fencing_token is None
            or attempt.tenant_id != work.tenant_id
            or attempt.transaction_id != work.transaction_id
            or attempt.intent_hash != work.intent_hash
            or attempt.dispatch_id != work.target_id
            or attempt.recovery_id != work.recovery_id
            or attempt.attempt != work.attempt
            or attempt.lease_id != work.lease_id
            or attempt.fencing_token != work.fencing_token
            or work.permit_ref not in attempt.evidence_refs
            or work.target_evidence_ref not in attempt.evidence_refs
            or attempt.started_at < work.not_before
            or attempt.started_at >= work.deadline
            or attempt.started_at >= work.permit.deadline
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation attempt differs from its exact recovery generation",
            )
        lease = self._get_worker_lease_tx(
            work.tenant_id,
            work.transaction_id,
            attempt.lease_id,
        )
        if (
            lease.worker_id != work.worker_id
            or lease.fencing_token != attempt.fencing_token
            or lease.purpose is not LeasePurpose.RECONCILIATION
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation attempt differs from its fenced worker lease",
            )
        authorization_round = self._get_authorization_round_tx(
            work.tenant_id,
            work.transaction_id,
            work.authorization_round_id,
        )
        self._assert_recovery_round_bindings(work, authorization_round)
        self._assert_recovery_capability_settlement_tx(
            work,
            authorization_round,
            expected_state=CapabilityReservationState.COMMITTED,
        )
        return lease

    def _assert_historical_reconciliation_attempt_binding_tx(
        self,
        work: RecoveryWorkRecord,
        attempt: ReconciliationAttemptRecord,
    ) -> WorkerLeaseRecord:
        """Re-prove one STARTED attempt closed by a higher-fenced reclaim."""

        completion_refs = attempt.completion_evidence_refs
        operation_binding_is_valid = (
            attempt.schema_version == "1.0"
            and attempt.operation_evidence_ref is None
            and attempt.operation_reason_code is None
        ) or (
            attempt.schema_version == "1.1"
            and attempt.operation_evidence_ref is not None
            and completion_refs is not None
            and attempt.operation_evidence_ref in completion_refs
        )
        if (
            work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
            or attempt.tenant_id != work.tenant_id
            or attempt.transaction_id != work.transaction_id
            or attempt.intent_hash != work.intent_hash
            or attempt.dispatch_id != work.target_id
            or attempt.recovery_id != work.recovery_id
            or not 1 <= attempt.attempt < work.attempt
            or work.target_evidence_ref not in attempt.evidence_refs
            or attempt.version != 1
            or attempt.outcome is not ReconciliationOutcome.UNKNOWN
            or attempt.effect_receipt_ref is not None
            or attempt.committed_verification_permit_digest is not None
            or attempt.committed_verification_permit_ref is not None
            or attempt.committed_verification_ref is not None
            or attempt.no_effect_evidence_ref is not None
            or completion_refs is None
            or not completion_refs
            or not set(completion_refs).issubset(attempt.evidence_refs)
            or attempt.completed_at is None
            or attempt.next_attempt_not_before != attempt.completed_at
            or not operation_binding_is_valid
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical reconciliation differs from a reclaimed STARTED attempt",
            )

        lease = self._get_worker_lease_tx(
            work.tenant_id,
            work.transaction_id,
            attempt.lease_id,
        )
        authorization_round = self._get_authorization_round_tx(
            work.tenant_id,
            work.transaction_id,
            work.authorization_round_id,
        )
        self._assert_recovery_round_bindings(work, authorization_round)
        self._assert_recovery_capability_settlement_tx(
            work,
            authorization_round,
            expected_state=CapabilityReservationState.COMMITTED,
        )
        if (
            authorization_round.authority_valid_until is None
            or work.capability_reservation_digest is None
            or work.reservation_version is None
            or lease.purpose is not LeasePurpose.RECONCILIATION
            or lease.fencing_token != attempt.fencing_token
            or lease.version < 1
            or lease.released_at != attempt.completed_at
            or lease.expires_at > attempt.completed_at
            or lease.acquired_at > attempt.started_at
            or attempt.started_at >= lease.expires_at
            or attempt.started_at < work.not_before
            or attempt.started_at >= work.deadline
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical reconciliation lost its expired worker lease",
            )
        historical_permit = self._build_recovery_permit(
            work,
            lease,
            authority_valid_until=authorization_round.authority_valid_until,
            capability_reservation_digest_value=work.capability_reservation_digest,
            reservation_version=work.reservation_version,
        )
        historical_permit_ref = canonical_digest(historical_permit)
        if (
            historical_permit_ref not in attempt.evidence_refs
            or historical_permit_ref not in completion_refs
            or not (historical_permit.issued_at <= attempt.started_at < historical_permit.deadline)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical reconciliation lost its exact recovery permit",
            )

        replacement_row = self._connection.execute(
            "SELECT * FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND fencing_token > ? ORDER BY fencing_token LIMIT 1",
            (work.tenant_id, work.transaction_id, attempt.fencing_token),
        ).fetchone()
        if replacement_row is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical reconciliation lost its replacement fence",
            )
        replacement = self._lease_from_row(replacement_row)
        replacement_permit = self._build_recovery_permit(
            work,
            replacement,
            authority_valid_until=authorization_round.authority_valid_until,
            capability_reservation_digest_value=work.capability_reservation_digest,
            reservation_version=work.reservation_version,
        )
        replacement_permit_ref = canonical_digest(replacement_permit)
        if (
            replacement.purpose is not LeasePurpose.RECONCILIATION
            or replacement.acquired_at != attempt.completed_at
            or replacement.fencing_token <= attempt.fencing_token
            or replacement_permit_ref not in completion_refs
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical reconciliation differs from its reclaim fence",
            )
        next_attempt_row = self._connection.execute(
            "SELECT * FROM enforced_reconciliation_attempts WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ? AND attempt = ?",
            (
                work.tenant_id,
                work.transaction_id,
                work.recovery_id,
                attempt.attempt + 1,
            ),
        ).fetchone()
        if next_attempt_row is not None:
            next_attempt = self._reconciliation_from_row(next_attempt_row)
            if (
                next_attempt.lease_id != replacement.lease_id
                or next_attempt.fencing_token != replacement.fencing_token
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Historical reconciliation replacement differs from its next attempt",
                )
        elif attempt.attempt + 1 == work.attempt and (
            work.lease_id != replacement.lease_id or work.fencing_token != replacement.fencing_token
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical reconciliation replacement differs from current work",
            )

        started_matches = 0
        started_rows = self._connection.execute(
            "SELECT * FROM enforced_transaction_events WHERE tenant_id = ? "
            "AND transaction_id = ? AND event = ? AND recorded_at = ?",
            (
                work.tenant_id,
                work.transaction_id,
                TransitionEvent.RECONCILIATION_STARTED.value,
                _timestamp(attempt.started_at),
            ),
        ).fetchall()
        terminal_fields: dict[str, object] = {
            "outcome": None,
            "effect_receipt_ref": None,
            "committed_verification_permit_digest": None,
            "committed_verification_permit_ref": None,
            "committed_verification_ref": None,
            "no_effect_evidence_ref": None,
            "operation_evidence_ref": None,
            "operation_reason_code": None,
            "completion_evidence_refs": None,
            "completed_at": None,
            "next_attempt_not_before": None,
            "version": 0,
        }
        for started_row in started_rows:
            event = self._event_from_row(started_row)
            for candidate_digest in event.evidence_refs:
                started_refs = tuple(ref for ref in event.evidence_refs if ref != candidate_digest)
                try:
                    started = ReconciliationAttemptRecord.model_validate(
                        {
                            **attempt.model_dump(mode="python"),
                            **terminal_fields,
                            "evidence_refs": started_refs,
                        }
                    )
                except ValidationError:
                    continue
                if (
                    _reconciliation_attempt_digest(started) == candidate_digest
                    and historical_permit_ref in started.evidence_refs
                    and work.target_evidence_ref in started.evidence_refs
                ):
                    started_matches += 1
        if started_matches != 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical reconciliation lost its exact STARTED event",
            )

        final_digest = _reconciliation_attempt_digest(attempt)
        expected_completion_evidence = tuple(sorted({final_digest, *completion_refs}))
        completed_rows = self._connection.execute(
            "SELECT * FROM enforced_transaction_events WHERE tenant_id = ? "
            "AND transaction_id = ? AND event = ? AND recorded_at = ?",
            (
                work.tenant_id,
                work.transaction_id,
                TransitionEvent.RECONCILIATION_UNKNOWN.value,
                _timestamp(attempt.completed_at),
            ),
        ).fetchall()
        matching_completions = tuple(
            event
            for row in completed_rows
            if (event := self._event_from_row(row)).evidence_refs == expected_completion_evidence
        )
        if len(matching_completions) != 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical reconciliation lost its exact reclaim completion event",
            )
        return lease

    def _assert_reconciliation_attempt_lineage_tx(
        self,
        work: RecoveryWorkRecord,
    ) -> tuple[ReconciliationAttemptRecord, ...]:
        """Require every prior same-work reconciliation generation and its closure proof."""

        if work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Only reconciliation work can own reconciliation attempt lineage",
            )
        rows = self._connection.execute(
            "SELECT * FROM enforced_reconciliation_attempts WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ? ORDER BY attempt",
            (work.tenant_id, work.transaction_id, work.recovery_id),
        ).fetchall()
        attempts = tuple(self._reconciliation_from_row(row) for row in rows)
        present_attempts = {attempt.attempt for attempt in attempts}
        required_historical_attempts = set(range(1, work.attempt))
        if not required_historical_attempts.issubset(present_attempts) or any(
            attempt.attempt > work.attempt for attempt in attempts
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation work lost its contiguous historical attempt lineage",
            )
        for attempt in attempts:
            if attempt.attempt < work.attempt:
                self._assert_historical_reconciliation_attempt_binding_tx(work, attempt)
        current_attempt = next(
            (attempt for attempt in attempts if attempt.attempt == work.attempt),
            None,
        )
        start_rows = self._connection.execute(
            "SELECT * FROM enforced_transaction_events WHERE tenant_id = ? "
            "AND transaction_id = ? AND event = ?",
            (
                work.tenant_id,
                work.transaction_id,
                TransitionEvent.RECONCILIATION_STARTED.value,
            ),
        ).fetchall()
        current_start_events = tuple(
            event
            for row in start_rows
            if work.permit_ref is not None
            and work.permit_ref in (event := self._event_from_row(row)).evidence_refs
            and work.target_evidence_ref in event.evidence_refs
        )
        if len(current_start_events) > 1 or (
            current_attempt is not None and len(current_start_events) != 1
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Current reconciliation attempt differs from its unique STARTED event",
            )
        if current_attempt is not None:
            started_matches = 0
            terminal_fields: dict[str, object] = {
                "outcome": None,
                "effect_receipt_ref": None,
                "committed_verification_permit_digest": None,
                "committed_verification_permit_ref": None,
                "committed_verification_ref": None,
                "no_effect_evidence_ref": None,
                "operation_evidence_ref": None,
                "operation_reason_code": None,
                "completion_evidence_refs": None,
                "completed_at": None,
                "next_attempt_not_before": None,
                "version": 0,
            }
            for event in current_start_events:
                if event.recorded_at != current_attempt.started_at:
                    continue
                for candidate_digest in event.evidence_refs:
                    started_refs = tuple(
                        ref for ref in event.evidence_refs if ref != candidate_digest
                    )
                    schema_versions: list[str] = [current_attempt.schema_version]
                    if current_attempt.schema_version == "1.0":
                        # Published v6 databases can retain a v1.1 STARTED digest
                        # while their attempt row uses the legacy v1.0 shape.
                        schema_versions.append("1.1")
                    for schema_version in schema_versions:
                        try:
                            started = ReconciliationAttemptRecord.model_validate(
                                {
                                    **current_attempt.model_dump(mode="python"),
                                    **terminal_fields,
                                    "schema_version": schema_version,
                                    "evidence_refs": started_refs,
                                }
                            )
                        except ValidationError:
                            continue
                        same_started_shape = current_attempt == started or (
                            current_attempt.schema_version == "1.0"
                            and schema_version == "1.1"
                            and current_attempt.model_dump(
                                mode="python", exclude={"schema_version"}
                            )
                            == started.model_dump(mode="python", exclude={"schema_version"})
                        )
                        if (
                            _reconciliation_attempt_digest(started) == candidate_digest
                            and work.permit_ref in started.evidence_refs
                            and work.target_evidence_ref in started.evidence_refs
                            and (current_attempt.outcome is not None or same_started_shape)
                        ):
                            started_matches += 1
            if started_matches != 1:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Current reconciliation attempt lost its exact STARTED event",
                )
        transaction = self._get_enforced_transaction_tx(work.tenant_id, work.transaction_id)
        unknown_rows = self._connection.execute(
            "SELECT * FROM enforced_transaction_events WHERE tenant_id = ? "
            "AND transaction_id = ? AND event = ? AND recorded_at = ?",
            (
                work.tenant_id,
                work.transaction_id,
                TransitionEvent.RECONCILIATION_UNKNOWN.value,
                _timestamp(work.updated_at),
            ),
        ).fetchall()
        current_terminal_event_exists = bool(unknown_rows)
        current_attempt_required = bool(current_start_events) or (
            work.attempt > 0
            and (
                work.state
                in {
                    RecoveryWorkState.RETRY_SCHEDULED,
                    RecoveryWorkState.RETRIED,
                    RecoveryWorkState.SUCCEEDED,
                }
                or (
                    work.state is RecoveryWorkState.RUNNING
                    and transaction.state is TransactionState.RECONCILING
                )
                or (
                    work.state is RecoveryWorkState.REVIEW_REQUIRED
                    and current_terminal_event_exists
                )
            )
        )
        if current_attempt_required and current_attempt is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation work lost its current started attempt",
            )
        if current_attempt is not None:
            self._assert_reconciliation_attempt_binding_tx(work, current_attempt)
        return attempts

    def _assert_started_reconciliation_retry_tx(
        self,
        work: RecoveryWorkRecord,
        attempt: ReconciliationAttemptRecord,
        *,
        expected_work_version: int,
        evidence_refs: tuple[str, ...],
        observed_at: datetime,
    ) -> EnforcedTransactionRecord:
        """Validate every durable fence before a STARTED retry may re-enter the provider."""

        self._assert_reconciliation_attempt_lineage_tx(work)

        if (
            work.state is not RecoveryWorkState.RUNNING
            or work.version != expected_work_version
            or attempt.version != 0
            or attempt.outcome is not None
            or attempt.completed_at is not None
            or attempt.completion_evidence_refs is not None
            or attempt.next_attempt_not_before is not None
            or attempt.evidence_refs != evidence_refs
            or observed_at < attempt.started_at
        ):
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Reconciliation STARTED retry lost its exact running generation",
                retryable=False,
            )
        lease = self._assert_reconciliation_attempt_binding_tx(work, attempt)
        self._assert_active_lease_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            lease_id=lease.lease_id,
            worker_id=lease.worker_id,
            fencing_token=lease.fencing_token,
            purpose=LeasePurpose.RECONCILIATION,
            at=observed_at,
        )
        handoff = self._assert_recovery_work_handoff_tx(work)
        if handoff.closed_at is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Running reconciliation retry has a closed action handoff",
            )
        self._validate_recovery_action_handoff_reverse_tx(
            handoff,
            tenant_id=work.tenant_id,
        )
        self._assert_recovery_subject_owner_tx(work)
        transaction, _stage, dispatch = self._assert_recovery_target_tx(
            work,
            require_authorizable_state=False,
        )
        if (
            transaction.state is not TransactionState.RECONCILING
            or dispatch is None
            or dispatch.state is not CommitDispatchState.IN_DOUBT
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation STARTED retry target is outside its running phase",
            )
        self._assert_target_capability_settlement_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            intent_hash=work.intent_hash,
            owner_version=work.target_owner_version,
            dispatch=dispatch,
        )
        event_rows = self._connection.execute(
            "SELECT * FROM enforced_transaction_events WHERE tenant_id = ? "
            "AND transaction_id = ? AND event = ? AND recorded_at = ?",
            (
                work.tenant_id,
                work.transaction_id,
                TransitionEvent.RECONCILIATION_STARTED.value,
                _timestamp(attempt.started_at),
            ),
        ).fetchall()
        attempt_digest = _reconciliation_attempt_digest(attempt)
        matching_events = tuple(
            event
            for row in event_rows
            if attempt_digest in (event := self._event_from_row(row)).evidence_refs
        )
        expected_event_evidence = tuple(sorted({attempt_digest, *attempt.evidence_refs}))
        if (
            len(matching_events) != 1
            or matching_events[0].sequence != transaction.version
            or matching_events[0].target_state is not transaction.state
            or matching_events[0].evidence_refs != expected_event_evidence
            or transaction.updated_at != attempt.started_at
            or transaction.reason_code is not None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation STARTED retry lost its unique transaction event",
            )
        return transaction

    def _assert_settled_reconciliation_successor_fence_tx(
        self,
        work: RecoveryWorkRecord,
        handoff: RecoveryActionHandoff,
    ) -> None:
        """Allow only one failed, work-free successor fence after deadline ownership."""

        binding = handoff.binding
        if (
            work.fencing_token is None
            or handoff.closed_at is None
            or handoff.terminal_sequence is None
            or handoff.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.NONE
            or handoff.failure_reason_code is None
            or binding.recovery_kind is not RecoveryWorkKind.RECONCILE_DISPATCH
            or binding.target_transaction_id != work.transaction_id
            or binding.recovery_id == work.recovery_id
            or binding.root_recovery_id != work.root_recovery_id
            or binding.predecessor_recovery_id != work.recovery_id
            or binding.recovery_ordinal != work.recovery_ordinal + 1
            or binding.max_recovery_attempts != work.max_recovery_attempts
            or binding.absolute_deadline != work.deadline
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Settled reconciliation successor changed its failed pre-work lineage",
            )
        successor_work = self._connection.execute(
            "SELECT 1 FROM enforced_recovery_work WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ?",
            (
                work.tenant_id,
                work.transaction_id,
                binding.recovery_id,
            ),
        ).fetchone()
        successor_lease = self._get_worker_lease_tx(
            work.tenant_id,
            work.transaction_id,
            handoff.handoff_lease_id,
        )
        later_fence = self._connection.execute(
            "SELECT 1 FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND fencing_token > ? LIMIT 1",
            (
                work.tenant_id,
                work.transaction_id,
                handoff.handoff_fencing_token,
            ),
        ).fetchone()
        if (
            successor_work is not None
            or successor_lease.lease_id != handoff.handoff_lease_id
            or successor_lease.worker_id != handoff.handoff_worker_id
            or successor_lease.fencing_token != handoff.handoff_fencing_token
            or successor_lease.fencing_token != work.fencing_token + 1
            or successor_lease.purpose is not LeasePurpose.RECOVERY
            or successor_lease.acquired_at != handoff.created_at
            or successor_lease.expires_at > binding.absolute_deadline
            or successor_lease.version != 1
            or successor_lease.released_at != handoff.closed_at
            or later_fence is not None
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Settled reconciliation successor lost its sole released fence",
            )
        self._validate_recovery_action_handoff_reverse_tx(
            handoff,
            tenant_id=work.tenant_id,
            bounded=True,
        )

    def _assert_finished_reconciliation_retry_tx(
        self,
        work: RecoveryWorkRecord,
        attempt: ReconciliationAttemptRecord,
        *,
        expected_attempt_version: int,
        outcome: ReconciliationOutcome,
        evidence_refs: tuple[str, ...],
        operation_evidence_ref: str,
        operation_reason_code: str | None,
        completed_at: datetime,
        effect_receipt_ref: str | None,
        committed_verification_permit_digest: str | None,
        committed_verification_permit_ref: str | None,
        committed_verification_ref: str | None,
        no_effect_evidence_ref: str | None,
        next_attempt_not_before: datetime | None,
        reason_code: str | None,
        settled_successor_handoff: RecoveryActionHandoff | None = None,
    ) -> EnforcedTransactionRecord:
        """Validate a completed reconciliation and every downstream durable binding."""

        self._assert_reconciliation_attempt_lineage_tx(work)

        if attempt.version != expected_attempt_version + 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Reconciliation completion retry used a stale attempt generation",
                retryable=False,
            )
        retry_is_scheduled = (
            outcome is ReconciliationOutcome.UNKNOWN
            and next_attempt_not_before is not None
            and work.recovery_ordinal < work.max_recovery_attempts
            and next_attempt_not_before < work.deadline
        )
        terminal_state = (
            RecoveryWorkState.RETRY_SCHEDULED
            if retry_is_scheduled
            else (
                RecoveryWorkState.REVIEW_REQUIRED
                if outcome is ReconciliationOutcome.UNKNOWN
                else RecoveryWorkState.SUCCEEDED
            )
        )
        progressed_retry = retry_is_scheduled and work.state is RecoveryWorkState.RETRIED
        expected_reason = (
            reason_code
            if terminal_state
            in {
                RecoveryWorkState.RETRY_SCHEDULED,
                RecoveryWorkState.REVIEW_REQUIRED,
            }
            else None
        )
        terminal_work_evidence = tuple(
            sorted({*attempt.evidence_refs, _reconciliation_attempt_digest(attempt)})
        )
        terminal_work = work
        if (
            attempt.outcome is not outcome
            or attempt.effect_receipt_ref != effect_receipt_ref
            or attempt.committed_verification_permit_digest != committed_verification_permit_digest
            or attempt.committed_verification_permit_ref != committed_verification_permit_ref
            or attempt.committed_verification_ref != committed_verification_ref
            or attempt.no_effect_evidence_ref != no_effect_evidence_ref
            or attempt.operation_evidence_ref != operation_evidence_ref
            or attempt.operation_reason_code != operation_reason_code
            or attempt.completion_evidence_refs != evidence_refs
            or attempt.completed_at != completed_at
            or attempt.next_attempt_not_before != next_attempt_not_before
            or (work.state is not terminal_state and not progressed_retry)
            or work.reason_code != expected_reason
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion retry changed its exact terminal generation",
            )
        if progressed_retry:
            successor_rows = self._connection.execute(
                "SELECT * FROM enforced_recovery_work WHERE tenant_id = ? "
                "AND transaction_id = ? AND predecessor_recovery_id = ?",
                (work.tenant_id, work.transaction_id, work.recovery_id),
            ).fetchall()
            if len(successor_rows) != 1:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Retried reconciliation completion lost its unique successor",
                )
            successor = self._recovery_from_row(successor_rows[0])
            successor_round = self._get_authorization_round_tx(
                successor.tenant_id,
                successor.transaction_id,
                successor.authorization_round_id,
            )
            authorized_successor_digest = self._authorized_recovery_work_digest_tx(successor)
            progression_extras = set(work.evidence_refs).difference(terminal_work_evidence)
            terminal_work = RecoveryWorkRecord.model_validate(
                {
                    **work.model_dump(mode="python"),
                    "state": RecoveryWorkState.RETRY_SCHEDULED,
                    "version": work.version - 1,
                    "evidence_refs": terminal_work_evidence,
                    "updated_at": completed_at,
                }
            )
            if work.updated_at != successor_round.evaluated_at or progression_extras != {
                successor_round.round_digest,
                authorized_successor_digest,
            }:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Retried reconciliation completion differs from successor authorization",
                )
            self._validate_recovery_work_handoff_lifecycle_tx(work)
            self._validate_recovery_work_handoff_lifecycle_tx(successor)
        elif work.updated_at != completed_at or work.evidence_refs != terminal_work_evidence:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion retry changed its terminal work evidence",
            )
        lease = self._assert_reconciliation_attempt_binding_tx(work, attempt)
        permit = work.permit
        if permit is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion retry lost its recovery permit",
            )
        authorization_round = self._get_authorization_round_tx(
            work.tenant_id,
            work.transaction_id,
            work.authorization_round_id,
        )
        if authorization_round.authority_valid_until is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion retry lost its authority deadline",
            )
        if (
            lease.released_at != completed_at
            or lease.version != 1
            or lease.acquired_at < work.not_before
            or lease.expires_at > work.deadline
            or permit.issued_at != lease.acquired_at
            or permit.deadline
            != _lease_bounded_deadline(
                work.deadline,
                lease.expires_at,
                authorization_round.authority_valid_until,
            )
            or completed_at < lease.acquired_at
            or completed_at >= lease.expires_at
            or completed_at < permit.issued_at
            or completed_at < attempt.started_at
            or completed_at >= permit.deadline
            or completed_at >= work.deadline
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion retry lost its exact lease release",
            )
        newer_lease = self._connection.execute(
            "SELECT 1 FROM enforced_worker_leases WHERE tenant_id = ? "
            "AND transaction_id = ? AND fencing_token > ? LIMIT 1",
            (work.tenant_id, work.transaction_id, work.fencing_token),
        ).fetchone()
        if settled_successor_handoff is not None:
            self._assert_settled_reconciliation_successor_fence_tx(
                work,
                settled_successor_handoff,
            )
        if newer_lease is not None and not progressed_retry and settled_successor_handoff is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion retry was superseded by a newer fence",
            )
        handoff = self._assert_recovery_work_handoff_tx(work)
        if handoff.closed_at is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Completed reconciliation unexpectedly closed its action handoff",
            )
        self._validate_recovery_action_handoff_reverse_tx(
            handoff,
            tenant_id=work.tenant_id,
        )
        self._validate_bounded_intent_history_binding_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.recovery_action_intent_hash,
            transaction_id=work.recovery_action_transaction_id,
            owner_version=work.owner_version,
            history_sequence=work.owner_history_sequence,
            history_digest=work.owner_history_digest,
        )
        action_attempt = self._validate_bounded_intent_attempt_lifecycle_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.recovery_action_intent_hash,
            transaction_id=work.recovery_action_transaction_id,
            expected_states=frozenset(
                {
                    IntentAttemptState.REVIEW_REQUIRED
                    if outcome is ReconciliationOutcome.UNKNOWN
                    else IntentAttemptState.COMMITTED
                }
            ),
        )
        if (
            action_attempt.evidence_digest != canonical_digest(terminal_work)
            or action_attempt.updated_at != completed_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion retry lost its action-intent evidence",
            )
        target_intent_state = {
            ReconciliationOutcome.COMMITTED: IntentAttemptState.COMMITTED,
            ReconciliationOutcome.NO_EFFECT: IntentAttemptState.NO_EFFECT_CONFIRMED,
            ReconciliationOutcome.PARTIAL_OR_INVALID: IntentAttemptState.REVIEW_REQUIRED,
            ReconciliationOutcome.UNKNOWN: IntentAttemptState.RECONCILE_REQUIRED,
        }[outcome]
        self._validate_bounded_intent_history_binding_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.intent_hash,
            transaction_id=work.transaction_id,
            owner_version=work.target_owner_version,
            history_sequence=work.target_owner_history_sequence,
            history_digest=work.target_owner_history_digest,
        )
        target_attempt = self._validate_bounded_intent_attempt_lifecycle_tx(
            tenant_id=work.tenant_id,
            intent_hash=work.intent_hash,
            transaction_id=work.transaction_id,
            expected_states=frozenset({target_intent_state}),
        )
        dispatch = self._get_commit_dispatch_tx(
            work.tenant_id,
            work.transaction_id,
        )
        if (
            dispatch.dispatch_id != work.target_id
            or dispatch.intent_hash != work.intent_hash
            or dispatch.owner_version != work.target_owner_version
            or dispatch.permit.target_version_guard != work.target_version_guard
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion retry differs from its dispatch generation",
            )
        outcome_matches = tuple(
            candidate
            for candidate in self._validate_dispatch_outcome_chain_tx(dispatch)
            if candidate.classification is outcome
            and candidate.recorded_at == completed_at
            and candidate.effect_receipt_ref == attempt.effect_receipt_ref
            and candidate.committed_verification_permit_digest
            == attempt.committed_verification_permit_digest
            and candidate.committed_verification_permit_ref
            == attempt.committed_verification_permit_ref
            and candidate.committed_verification_ref == attempt.committed_verification_ref
            and candidate.no_effect_evidence_ref == attempt.no_effect_evidence_ref
            and candidate.evidence_refs == attempt.evidence_refs
            and candidate.reason_code == reason_code
        )
        if len(outcome_matches) != 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion retry lost its exact dispatch outcome",
            )
        matching_outcome = outcome_matches[0]
        event_kind = {
            ReconciliationOutcome.COMMITTED: TransitionEvent.RECONCILIATION_COMMITTED,
            ReconciliationOutcome.NO_EFFECT: TransitionEvent.RECONCILIATION_NO_EFFECT,
            ReconciliationOutcome.PARTIAL_OR_INVALID: (
                TransitionEvent.RECONCILIATION_PARTIAL_OR_INVALID
            ),
            ReconciliationOutcome.UNKNOWN: TransitionEvent.RECONCILIATION_UNKNOWN,
        }[outcome]
        event_rows = self._connection.execute(
            "SELECT * FROM enforced_transaction_events WHERE tenant_id = ? "
            "AND transaction_id = ? AND event = ? AND recorded_at = ?",
            (
                work.tenant_id,
                work.transaction_id,
                event_kind.value,
                _timestamp(completed_at),
            ),
        ).fetchall()
        matching_events = tuple(
            event
            for row in event_rows
            if matching_outcome.outcome_digest in (event := self._event_from_row(row)).evidence_refs
        )
        expected_event_evidence = tuple(
            sorted({matching_outcome.outcome_digest, *attempt.evidence_refs})
        )
        if len(matching_events) != 1 or matching_events[0].evidence_refs != expected_event_evidence:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion retry lost its transaction event",
            )
        transaction = self._get_enforced_transaction_tx(
            work.tenant_id,
            work.transaction_id,
        )
        expected_transaction_reason = (
            reason_code if outcome is ReconciliationOutcome.PARTIAL_OR_INVALID else None
        )
        if (
            matching_events[0].sequence != transaction.version
            or matching_events[0].target_state is not transaction.state
            or transaction.updated_at != completed_at
            or transaction.reason_code != expected_transaction_reason
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion retry changed its transaction projection",
            )
        if outcome is not ReconciliationOutcome.UNKNOWN and (
            target_attempt.evidence_digest != matching_outcome.outcome_digest
            or target_attempt.updated_at != completed_at
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Reconciliation completion retry lost its target-intent evidence",
            )
        if not progressed_retry:
            expected_transaction_state = {
                ReconciliationOutcome.COMMITTED: TransactionState.COMMITTED,
                ReconciliationOutcome.NO_EFFECT: TransactionState.ABORTING,
                ReconciliationOutcome.PARTIAL_OR_INVALID: TransactionState.FAILED,
                ReconciliationOutcome.UNKNOWN: TransactionState.IN_DOUBT,
            }[outcome]
            expected_dispatch_state = {
                ReconciliationOutcome.COMMITTED: CommitDispatchState.COMMITTED,
                ReconciliationOutcome.NO_EFFECT: CommitDispatchState.NO_EFFECT,
                ReconciliationOutcome.PARTIAL_OR_INVALID: (CommitDispatchState.PARTIAL_OR_INVALID),
                ReconciliationOutcome.UNKNOWN: CommitDispatchState.IN_DOUBT,
            }[outcome]
            if (
                transaction.state is not expected_transaction_state
                or dispatch.state is not expected_dispatch_state
                or dispatch.updated_at != completed_at
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation completion retry target differs from its terminal phase",
                )
        self._assert_target_capability_settlement_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
            intent_hash=work.intent_hash,
            owner_version=work.target_owner_version,
            dispatch=dispatch,
        )
        self._assert_no_orphan_active_recovery_lease_tx(
            tenant_id=work.tenant_id,
            transaction_id=work.transaction_id,
        )
        return transaction

    def start_reconciliation(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        expected_work_version: int,
        evidence_refs: tuple[str, ...],
        started_at: datetime,
    ) -> ReconciliationResult:
        """Persist STARTED and IN_DOUBT -> RECONCILING before an external read."""

        supplied_refs = tuple(
            sorted({_require_digest(value, field="evidence_ref") for value in evidence_refs})
        )
        with self._immediate():
            work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
            if (
                work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                or work.state is not RecoveryWorkState.RUNNING
                or work.version != expected_work_version
                or work.permit is None
                or work.permit_ref is None
                or work.lease_id is None
                or work.worker_id is None
                or work.fencing_token is None
            ):
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Reconciliation requires exact claimed recovery work",
                )
            self._assert_reconciliation_attempt_lineage_tx(work)
            if started_at >= work.deadline or started_at >= work.permit.deadline:
                raise AgentKernelError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "Reconciliation start arrived after its permit or work deadline",
                )
            refs = tuple(sorted({*supplied_refs, work.permit_ref, work.target_evidence_ref}))
            existing = self._connection.execute(
                "SELECT * FROM enforced_reconciliation_attempts WHERE tenant_id = ? "
                "AND transaction_id = ? AND recovery_id = ? AND attempt = ?",
                (tenant_id, transaction_id, recovery_id, work.attempt),
            ).fetchone()
            if existing is not None:
                stored = self._reconciliation_from_row(existing)
                transaction = self._assert_started_reconciliation_retry_tx(
                    work,
                    stored,
                    expected_work_version=expected_work_version,
                    evidence_refs=refs,
                    observed_at=started_at,
                )
                return ReconciliationResult(
                    stored,
                    transaction,
                    None,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            self._assert_recovery_subject_owner_tx(work)
            transaction, _, dispatch = self._assert_recovery_target_tx(
                work,
                require_authorizable_state=True,
            )
            if dispatch is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation lost its dispatch target",
                )
            self._assert_active_lease_tx(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                lease_id=work.lease_id,
                worker_id=work.worker_id,
                fencing_token=work.fencing_token,
                purpose=LeasePurpose.RECONCILIATION,
                at=started_at,
            )
            attempt = ReconciliationAttemptRecord(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                intent_hash=work.intent_hash,
                dispatch_id=dispatch.dispatch_id,
                recovery_id=recovery_id,
                attempt=work.attempt,
                lease_id=work.lease_id,
                fencing_token=work.fencing_token,
                evidence_refs=refs,
                started_at=started_at,
                version=0,
            )
            self._insert_reconciliation_attempt_tx(attempt)
            updated_transaction, event = self._apply_transition_tx(
                transaction,
                expected_version=transaction.version,
                transition_event=TransitionEvent.RECONCILIATION_STARTED,
                recorded_at=started_at,
                evidence_refs=(_reconciliation_attempt_digest(attempt), *refs),
            )
            return ReconciliationResult(
                attempt,
                updated_transaction,
                event,
                EnforcedStoreDisposition.RECONCILE_NOW,
            )

    def finish_reconciliation(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
        recovery_id: str,
        expected_attempt_version: int,
        outcome: ReconciliationOutcome,
        evidence_refs: tuple[str, ...],
        operation_evidence_ref: str,
        completed_at: datetime,
        operation_reason_code: str | None = None,
        effect_receipt_ref: str | None = None,
        committed_verification_permit: VerificationPermit | None = None,
        committed_verification_permit_ref: str | None = None,
        committed_verification_ref: str | None = None,
        no_effect_evidence_ref: str | None = None,
        next_attempt_not_before: datetime | None = None,
        reason_code: str | None = None,
    ) -> ReconciliationResult:
        """Finish one evidence read and classify its original dispatch without resend."""

        normalized_refs = tuple(
            sorted({_require_digest(value, field="evidence_ref") for value in evidence_refs})
        )
        operation_evidence_ref = _require_digest(
            operation_evidence_ref,
            field="operation_evidence_ref",
        )
        if operation_evidence_ref not in normalized_refs:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Reconciliation operation evidence must belong to its completion input",
            )
        if operation_reason_code is not None:
            operation_reason_code = _require_identifier(
                operation_reason_code,
                field="operation_reason_code",
            )
        committed_verification_permit_digest = (
            None
            if committed_verification_permit is None
            else committed_verification_permit.permit_digest
        )
        if (
            outcome
            in {
                ReconciliationOutcome.PARTIAL_OR_INVALID,
                ReconciliationOutcome.UNKNOWN,
            }
            and reason_code is None
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Partial or unknown reconciliation requires a stable reason",
            )
        with self._immediate():
            work = self._get_recovery_work_tx(tenant_id, transaction_id, recovery_id)
            if work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Recovery work is not dispatch reconciliation",
                )
            self._assert_reconciliation_attempt_lineage_tx(work)
            attempt = self._get_reconciliation_attempt_tx(
                tenant_id,
                transaction_id,
                recovery_id,
                work.attempt,
            )
            if attempt.outcome is not None:
                transaction = self._assert_finished_reconciliation_retry_tx(
                    work,
                    attempt,
                    expected_attempt_version=expected_attempt_version,
                    outcome=outcome,
                    evidence_refs=normalized_refs,
                    operation_evidence_ref=operation_evidence_ref,
                    operation_reason_code=operation_reason_code,
                    completed_at=completed_at,
                    effect_receipt_ref=effect_receipt_ref,
                    committed_verification_permit_digest=(committed_verification_permit_digest),
                    committed_verification_permit_ref=(committed_verification_permit_ref),
                    committed_verification_ref=committed_verification_ref,
                    no_effect_evidence_ref=no_effect_evidence_ref,
                    next_attempt_not_before=next_attempt_not_before,
                    reason_code=reason_code,
                )
                return ReconciliationResult(
                    attempt,
                    transaction,
                    None,
                    EnforcedStoreDisposition.EXACT_RETRY,
                )
            if (
                work.state is not RecoveryWorkState.RUNNING
                or work.permit is None
                or work.lease_id is None
                or work.worker_id is None
                or work.fencing_token is None
                or attempt.version != expected_attempt_version
            ):
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Reconciliation attempt or recovery work changed",
                )
            if completed_at >= work.deadline or completed_at >= work.permit.deadline:
                raise AgentKernelError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "Reconciliation completion arrived after its permit or work deadline",
                )
            self._assert_active_lease_tx(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                lease_id=work.lease_id,
                worker_id=work.worker_id,
                fencing_token=work.fencing_token,
                purpose=LeasePurpose.RECONCILIATION,
                at=completed_at,
            )
            transaction = self._get_enforced_transaction_tx(tenant_id, transaction_id)
            dispatch = self._get_commit_dispatch_tx(tenant_id, transaction_id)
            if (
                transaction.state is not TransactionState.RECONCILING
                or dispatch.dispatch_id != attempt.dispatch_id
            ):
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Reconciliation target is no longer the started generation",
                )
            refs = set(attempt.evidence_refs)
            refs.update(normalized_refs)
            for value in (
                effect_receipt_ref,
                committed_verification_permit_digest,
                committed_verification_permit_ref,
                committed_verification_ref,
                no_effect_evidence_ref,
            ):
                if value is not None:
                    refs.add(_require_digest(value, field="outcome_evidence_ref"))
            completed = ReconciliationAttemptRecord.model_validate(
                {
                    **attempt.model_dump(mode="python"),
                    "schema_version": "1.1",
                    "outcome": outcome,
                    "effect_receipt_ref": effect_receipt_ref,
                    "committed_verification_permit_digest": (committed_verification_permit_digest),
                    "committed_verification_permit_ref": (committed_verification_permit_ref),
                    "committed_verification_ref": committed_verification_ref,
                    "no_effect_evidence_ref": no_effect_evidence_ref,
                    "operation_evidence_ref": operation_evidence_ref,
                    "operation_reason_code": operation_reason_code,
                    "evidence_refs": tuple(sorted(refs)),
                    "completion_evidence_refs": normalized_refs,
                    "completed_at": completed_at,
                    "next_attempt_not_before": next_attempt_not_before,
                    "version": 1,
                }
            )
            self._update_reconciliation_attempt_tx(attempt, completed)
            classified = self.classify_dispatch_outcome(
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                expected_dispatch_version=dispatch.version,
                expected_transaction_version=transaction.version,
                classification=outcome,
                evidence_refs=completed.evidence_refs,
                recorded_at=completed_at,
                effect_receipt_ref=effect_receipt_ref,
                committed_verification_permit=committed_verification_permit,
                committed_verification_permit_ref=committed_verification_permit_ref,
                committed_verification_ref=committed_verification_ref,
                no_effect_evidence_ref=no_effect_evidence_ref,
                reason_code=reason_code,
            )
            retry_is_scheduled = (
                outcome is ReconciliationOutcome.UNKNOWN
                and next_attempt_not_before is not None
                and work.recovery_ordinal < work.max_recovery_attempts
                and next_attempt_not_before < work.deadline
            )
            terminal_state = (
                RecoveryWorkState.RETRY_SCHEDULED
                if retry_is_scheduled
                else (
                    RecoveryWorkState.REVIEW_REQUIRED
                    if outcome is ReconciliationOutcome.UNKNOWN
                    else RecoveryWorkState.SUCCEEDED
                )
            )
            work_refs = tuple(
                sorted({*completed.evidence_refs, _reconciliation_attempt_digest(completed)})
            )
            updated_work = RecoveryWorkRecord.model_validate(
                {
                    **work.model_dump(mode="python"),
                    "state": terminal_state,
                    "version": work.version + 1,
                    "evidence_refs": work_refs,
                    "reason_code": (
                        reason_code
                        if terminal_state
                        in {
                            RecoveryWorkState.RETRY_SCHEDULED,
                            RecoveryWorkState.REVIEW_REQUIRED,
                        }
                        else None
                    ),
                    "updated_at": completed_at,
                }
            )
            self._transition_owned_attempt_tx(
                tenant_id=work.tenant_id,
                intent_hash=work.recovery_action_intent_hash,
                transaction_id=work.recovery_action_transaction_id,
                owner_version=work.owner_version,
                owner_history_sequence=work.owner_history_sequence,
                owner_history_digest=work.owner_history_digest,
                target_state=(
                    IntentAttemptState.REVIEW_REQUIRED
                    if outcome is ReconciliationOutcome.UNKNOWN
                    else IntentAttemptState.COMMITTED
                ),
                evidence_digest=canonical_digest(updated_work),
                recorded_at=completed_at,
            )
            self._update_recovery_work_tx(work, updated_work)
            self._release_recovery_lease_tx(updated_work, released_at=completed_at)
            return ReconciliationResult(
                completed,
                classified.transaction,
                classified.event,
                EnforcedStoreDisposition.STORED,
            )

    def scan_recovery_candidates(
        self,
        *,
        tenant_id: str,
        observed_at: datetime,
        limit: int = 100,
        cursor: RecoveryCursor | None = None,
    ) -> RecoveryScanPage:
        """Return a stable tenant-scoped keyset page of nonterminal recovery candidates."""

        with self._read_snapshot():
            return self._scan_recovery_candidates_tx(
                tenant_id=tenant_id,
                observed_at=observed_at,
                limit=limit,
                cursor=cursor,
            )

    def _scan_recovery_candidates_tx(
        self,
        *,
        tenant_id: str,
        observed_at: datetime,
        limit: int,
        cursor: RecoveryCursor | None,
    ) -> RecoveryScanPage:
        """Build one recovery page while the caller owns a read snapshot."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        observed = _timestamp(observed_at)
        if limit < 1 or limit > _MAX_SCAN_LIMIT:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                f"Recovery scan limit must be between 1 and {_MAX_SCAN_LIMIT}",
            )
        states = tuple(state.value for state in _RECOVERY_SCAN_STATES)
        state_slots = ", ".join("?" for _ in states)
        parameters: list[object] = [tenant_id, *states, observed]
        cursor_clause = ""
        if cursor is not None:
            cursor_time = _timestamp(cursor.updated_at)
            cursor_id = _require_identifier(cursor.transaction_id, field="cursor.transaction_id")
            cursor_clause = (
                " AND (tx.updated_at > ? OR (tx.updated_at = ? AND tx.transaction_id > ?))"
            )
            parameters.extend((cursor_time, cursor_time, cursor_id))
        parameters.extend((observed, observed, observed))
        parameters.append(limit + 1)
        statement = (
            "SELECT tx.* FROM enforced_transactions AS tx WHERE tx.tenant_id = ? "  # noqa: S608  # nosec B608
            f"AND tx.state IN ({state_slots}) AND tx.updated_at <= ?{cursor_clause} "
            "AND (("
            "NOT (EXISTS ("
            "SELECT 1 FROM enforced_dispatch_evidence_unavailable_reports AS dispatch_stop "
            "WHERE dispatch_stop.tenant_id = tx.tenant_id "
            "AND dispatch_stop.transaction_id = tx.transaction_id) "
            "AND NOT EXISTS (SELECT 1 FROM enforced_recovery_work AS resumed_work "
            "WHERE resumed_work.tenant_id = tx.tenant_id "
            "AND resumed_work.transaction_id = tx.transaction_id "
            "AND resumed_work.kind = 'RECONCILE_DISPATCH' "
            "AND resumed_work.state IN ('PENDING', 'RUNNING', 'RETRY_SCHEDULED')) "
            f"AND NOT ({_TERMINAL_RECONCILIATION_FOLLOW_ON_SQL})) "
            f"AND NOT ({_LIVE_OPEN_PREWORK_HANDOFF_SQL}) "
            "AND NOT EXISTS ("
            "SELECT 1 FROM enforced_recovery_action_handoffs AS prework_stop "
            "WHERE prework_stop.tenant_id = tx.tenant_id "
            "AND prework_stop.target_transaction_id = tx.transaction_id "
            "AND prework_stop.recovery_kind = 'RECONCILE_DISPATCH' "
            "AND prework_stop.closed_at IS NOT NULL "
            "AND NOT EXISTS (SELECT 1 FROM enforced_recovery_work AS linked_work "
            "WHERE linked_work.tenant_id = prework_stop.tenant_id "
            "AND linked_work.transaction_id = prework_stop.target_transaction_id "
            "AND linked_work.recovery_id = prework_stop.recovery_id)) "
            "AND NOT ("
            "EXISTS (SELECT 1 FROM enforced_recovery_work AS any_work "
            "WHERE any_work.tenant_id = tx.tenant_id "
            "AND any_work.transaction_id = tx.transaction_id) "
            "AND NOT EXISTS (SELECT 1 FROM enforced_recovery_work AS active_work "
            "WHERE active_work.tenant_id = tx.tenant_id "
            "AND active_work.transaction_id = tx.transaction_id "
            "AND active_work.state IN ('PENDING', 'RUNNING', 'RETRY_SCHEDULED')) "
            f"AND NOT ({_TERMINAL_RECONCILIATION_FOLLOW_ON_SQL}))"
            f") OR ({_RESUMABLE_OPEN_PREWORK_HANDOFF_SQL})) "
            "ORDER BY tx.updated_at, tx.transaction_id LIMIT ?"
        )
        rows = self._connection.execute(statement, tuple(parameters)).fetchall()
        has_more = len(rows) > limit
        selected = rows[:limit]
        records = tuple(self._transaction_from_row(row) for row in selected)
        for record in records:
            self._validate_transaction_chain_tx(record)
        next_cursor = None
        if has_more and records:
            last = records[-1]
            next_cursor = RecoveryCursor(last.updated_at, last.transaction_id)
        active_work = tuple(
            work
            for record in records
            for work in self.get_active_recovery_work(
                tenant_id=tenant_id,
                transaction_id=record.transaction_id,
            )
        )
        started_reconciliation = tuple(
            attempt
            for record in records
            if (
                attempt := self.get_started_reconciliation_attempt(
                    tenant_id=tenant_id,
                    transaction_id=record.transaction_id,
                )
            )
            is not None
        )
        return RecoveryScanPage(
            records,
            next_cursor,
            active_work,
            started_reconciliation,
        )

    def count_recovery_candidates(
        self,
        *,
        tenant_id: str,
        observed_at: datetime | None = None,
    ) -> int:
        """Count the current tenant-wide nonterminal recovery backlog atomically."""

        tenant_id = _require_identifier(tenant_id, field="tenant_id")
        observed = _timestamp(observed_at or datetime.now(UTC))
        states = tuple(state.value for state in _RECOVERY_SCAN_STATES)
        state_slots = ", ".join("?" for _ in states)
        with self._read_snapshot():
            row = self._connection.execute(
                "SELECT COUNT(*) FROM enforced_transactions AS tx "  # noqa: S608  # nosec B608
                f"WHERE tx.tenant_id = ? AND tx.state IN ({state_slots}) "
                "AND (("
                "NOT (EXISTS ("
                "SELECT 1 FROM enforced_dispatch_evidence_unavailable_reports AS dispatch_stop "
                "WHERE dispatch_stop.tenant_id = tx.tenant_id "
                "AND dispatch_stop.transaction_id = tx.transaction_id) "
                "AND NOT EXISTS (SELECT 1 FROM enforced_recovery_work AS resumed_work "
                "WHERE resumed_work.tenant_id = tx.tenant_id "
                "AND resumed_work.transaction_id = tx.transaction_id "
                "AND resumed_work.kind = 'RECONCILE_DISPATCH' "
                "AND resumed_work.state IN ('PENDING', 'RUNNING', 'RETRY_SCHEDULED')) "
                f"AND NOT ({_TERMINAL_RECONCILIATION_FOLLOW_ON_SQL})) "
                f"AND NOT ({_LIVE_OPEN_PREWORK_HANDOFF_SQL}) "
                "AND NOT EXISTS ("
                "SELECT 1 FROM enforced_recovery_action_handoffs AS prework_stop "
                "WHERE prework_stop.tenant_id = tx.tenant_id "
                "AND prework_stop.target_transaction_id = tx.transaction_id "
                "AND prework_stop.recovery_kind = 'RECONCILE_DISPATCH' "
                "AND prework_stop.closed_at IS NOT NULL "
                "AND NOT EXISTS (SELECT 1 FROM enforced_recovery_work AS linked_work "
                "WHERE linked_work.tenant_id = prework_stop.tenant_id "
                "AND linked_work.transaction_id = prework_stop.target_transaction_id "
                "AND linked_work.recovery_id = prework_stop.recovery_id)) "
                "AND NOT ("
                "EXISTS (SELECT 1 FROM enforced_recovery_work AS any_work "
                "WHERE any_work.tenant_id = tx.tenant_id "
                "AND any_work.transaction_id = tx.transaction_id) "
                "AND NOT EXISTS (SELECT 1 FROM enforced_recovery_work AS active_work "
                "WHERE active_work.tenant_id = tx.tenant_id "
                "AND active_work.transaction_id = tx.transaction_id "
                "AND active_work.state IN ('PENDING', 'RUNNING', 'RETRY_SCHEDULED')) "
                f"AND NOT ({_TERMINAL_RECONCILIATION_FOLLOW_ON_SQL}))"
                f") OR ({_RESUMABLE_OPEN_PREWORK_HANDOFF_SQL})) ",
                (tenant_id, *states, observed, observed, observed),
            ).fetchone()
            if row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery backlog count was unavailable",
                )
            return int(row[0])

    def _validate_all_enforced_state(self) -> None:
        rows = self._connection.execute(
            "SELECT * FROM enforced_transactions ORDER BY tenant_id, transaction_id"
        ).fetchall()
        for row in rows:
            record = self._transaction_from_row(row)
            self._validate_transaction_chain_tx(record)
            self._validate_transaction_recovery_deadline_tx(record, row)
        handoff_rows = self._connection.execute(
            "SELECT * FROM enforced_recovery_action_handoffs "
            "ORDER BY tenant_id, target_transaction_id, recovery_id"
        ).fetchall()
        terminal_tenants: set[str] = set()
        for row in handoff_rows:
            handoff = self._recovery_action_handoff_from_row(
                row,
                tenant_id=str(row["tenant_id"]),
                target_transaction_id=str(row["target_transaction_id"]),
                recovery_id=str(row["recovery_id"]),
            )
            self._validate_recovery_action_handoff_reverse_tx(
                handoff,
                tenant_id=str(row["tenant_id"]),
                bounded=False,
            )
            if handoff.terminal_sequence is not None:
                terminal_tenants.add(str(row["tenant_id"]))
        head_rows = self._connection.execute(
            "SELECT tenant_id FROM enforced_recovery_handoff_terminal_heads ORDER BY tenant_id"
        ).fetchall()
        head_tenants = {str(row["tenant_id"]) for row in head_rows}
        if head_tenants != terminal_tenants:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery handoff terminal heads differ from terminal tenants",
            )
        for tenant_id in head_tenants:
            self._recovery_handoff_terminal_high_watermark_tx(tenant_id)
        audit_rows = self._connection.execute(
            "SELECT * FROM enforced_recovery_handoff_evidence_audits ORDER BY tenant_id"
        ).fetchall()
        for row in audit_rows:
            self._recovery_handoff_evidence_audit_from_row(row)
        round_rows = self._connection.execute(
            "SELECT * FROM enforced_authorization_rounds "
            "ORDER BY tenant_id, controlled_transaction_id, round_id"
        ).fetchall()
        for row in round_rows:
            self._round_from_row(row)
        lease_rows = self._connection.execute(
            "SELECT * FROM enforced_worker_leases ORDER BY tenant_id, transaction_id, fencing_token"
        ).fetchall()
        highest_fence: dict[tuple[str, str], int] = {}
        active: set[tuple[str, str]] = set()
        for row in lease_rows:
            lease = self._lease_from_row(row)
            key = (lease.tenant_id, lease.transaction_id)
            previous = highest_fence.get(key, 0)
            if lease.fencing_token <= previous:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Worker lease fencing tokens are not strictly increasing",
                )
            highest_fence[key] = lease.fencing_token
            if lease.released_at is None:
                if key in active:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Transaction has more than one active worker lease",
                    )
                active.add(key)
        stage_rows = self._connection.execute(
            "SELECT * FROM enforced_stage_material ORDER BY tenant_id, transaction_id"
        ).fetchall()
        for row in stage_rows:
            self._stage_from_row(row)
        dispatch_rows = self._connection.execute(
            "SELECT * FROM enforced_commit_dispatches ORDER BY tenant_id, transaction_id"
        ).fetchall()
        for row in dispatch_rows:
            dispatch = self._dispatch_from_row(row)
            self._validate_dispatch_outcome_chain_tx(dispatch)
            self._validate_dispatch_unavailable_link_tx(dispatch)
        dispatch_unavailable_rows = self._connection.execute(
            "SELECT * FROM enforced_dispatch_evidence_unavailable_reports "
            "ORDER BY tenant_id, transaction_id, dispatch_id"
        ).fetchall()
        for row in dispatch_unavailable_rows:
            unavailable = self._dispatch_evidence_unavailable_from_row(row)
            self._validate_dispatch_evidence_unavailable_association_tx(unavailable)
        reconciliation_rows = self._connection.execute(
            "SELECT * FROM enforced_reconciliation_attempts "
            "ORDER BY tenant_id, transaction_id, dispatch_id, recovery_id, attempt"
        ).fetchall()
        for row in reconciliation_rows:
            attempt = self._reconciliation_from_row(row)
            work = self._get_recovery_work_tx(
                attempt.tenant_id,
                attempt.transaction_id,
                attempt.recovery_id,
            )
            lease = self._get_worker_lease_tx(
                attempt.tenant_id,
                attempt.transaction_id,
                attempt.lease_id,
            )
            unavailable_attempt = self._connection.execute(
                "SELECT 1 FROM enforced_recovery_evidence_unavailable_reports "
                "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ?",
                (attempt.tenant_id, attempt.transaction_id, attempt.recovery_id),
            ).fetchone()
            if (
                work.kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                or work.target_id != attempt.dispatch_id
                or work.intent_hash != attempt.intent_hash
                or attempt.attempt > work.attempt
                or lease.purpose is not LeasePurpose.RECONCILIATION
                or lease.fencing_token != attempt.fencing_token
                or (
                    attempt.schema_version == "1.1"
                    and attempt.outcome is not None
                    and (
                        (unavailable_attempt is None and attempt.operation_evidence_ref is None)
                        or (
                            unavailable_attempt is not None
                            and (
                                attempt.operation_evidence_ref is not None
                                or attempt.operation_reason_code is not None
                            )
                        )
                    )
                )
                or (
                    attempt.outcome is None
                    and (
                        work.state is not RecoveryWorkState.RUNNING
                        or work.attempt != attempt.attempt
                        or work.lease_id != attempt.lease_id
                        or work.fencing_token != attempt.fencing_token
                    )
                )
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Reconciliation attempt differs from its recovery work",
                )
        recovery_rows = self._connection.execute(
            "SELECT * FROM enforced_recovery_work ORDER BY tenant_id, transaction_id, recovery_id"
        ).fetchall()
        for row in recovery_rows:
            work = self._recovery_from_row(row)
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                self._assert_reconciliation_attempt_lineage_tx(work)
            self._validate_recovery_work_handoff_lifecycle_tx(work)
            self._validate_recovery_work_unavailable_link_tx(work)
            round_record = self._get_authorization_round_tx(
                work.tenant_id,
                work.transaction_id,
                work.authorization_round_id,
            )
            capability_state = (
                None
                if round_record.verdict is not AuthorizationVerdict.ELIGIBLE
                else (
                    CapabilityReservationState.RESERVED
                    if work.state is RecoveryWorkState.PENDING
                    else (
                        CapabilityReservationState.RELEASED
                        if work.permit is None
                        else CapabilityReservationState.COMMITTED
                    )
                )
            )
            self._assert_recovery_capability_settlement_tx(
                work,
                round_record,
                expected_state=capability_state,
            )
            if (
                round_record.purpose is not AuthorizationRoundPurpose.RECOVERY
                or round_record.controlled_transaction_id != work.transaction_id
                or round_record.subject_transaction_id != work.recovery_action_transaction_id
                or round_record.subject_intent_hash != work.recovery_action_intent_hash
                or round_record.subject_normalized_action_digest != work.recovery_action_digest
                or round_record.round_digest != work.authorization_round_digest
                or round_record.owner_version != work.owner_version
                or round_record.owner_history_sequence != work.owner_history_sequence
                or round_record.owner_history_digest != work.owner_history_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery work differs from its immutable authorization round",
                )
        completion_report_rows = self._connection.execute(
            "SELECT * FROM enforced_recovery_completion_reports "
            "ORDER BY tenant_id, transaction_id, recovery_id"
        ).fetchall()
        for row in completion_report_rows:
            completion_report = self._recovery_completion_report_from_row(row)
            work = self._get_recovery_work_tx(
                completion_report.tenant_id,
                completion_report.transaction_id,
                completion_report.recovery_id,
            )
            expected_state = (
                RecoveryWorkState.SUCCEEDED
                if completion_report.succeeded
                else RecoveryWorkState.FAILED
            )
            if work.lease_id is None or work.permit is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery completion report has no durable permit generation",
                )
            lease = self._get_worker_lease_tx(
                completion_report.tenant_id,
                completion_report.transaction_id,
                work.lease_id,
            )
            if (
                work.state is not expected_state
                or work.updated_at != completion_report.completed_at
                or work.reason_code != completion_report.reason_code
                or completion_report.terminal_work_digest != canonical_digest(work)
                or work.evidence_refs
                != tuple(
                    sorted(
                        {
                            *completion_report.evidence_refs,
                            cast("str", work.permit_ref),
                        }
                    )
                )
                or lease.released_at != completion_report.completed_at
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery completion report differs from its terminal work",
                )
            if (
                work.kind is RecoveryWorkKind.DISCARD_STAGING
                and self._get_stage_material_tx(
                    completion_report.tenant_id,
                    completion_report.transaction_id,
                ).discard_evidence_ref
                != completion_report.operation_evidence_ref
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Discard completion report differs from its stage evidence",
                )
        late_report_rows = self._connection.execute(
            "SELECT * FROM enforced_late_recovery_reports "
            "ORDER BY tenant_id, transaction_id, recovery_id"
        ).fetchall()
        for row in late_report_rows:
            late_report = self._late_recovery_report_from_row(row)
            work = self._get_recovery_work_tx(
                late_report.tenant_id,
                late_report.transaction_id,
                late_report.recovery_id,
            )
            if work.lease_id is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late recovery report has no durable lease generation",
                )
            lease = self._get_worker_lease_tx(
                late_report.tenant_id,
                late_report.transaction_id,
                work.lease_id,
            )
            if (
                work.state is not RecoveryWorkState.REVIEW_REQUIRED
                or work.updated_at != late_report.reported_at
                or work.reason_code != late_report.reason_code
                or late_report.terminal_work_digest != canonical_digest(work)
                or lease.released_at != late_report.reported_at
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Late recovery report differs from its fenced terminal work",
                )
            late_attempt: ReconciliationAttemptRecord | None = None
            if work.kind is RecoveryWorkKind.RECONCILE_DISPATCH:
                attempt_row = self._connection.execute(
                    "SELECT * FROM enforced_reconciliation_attempts "
                    "WHERE tenant_id = ? AND transaction_id = ? "
                    "AND recovery_id = ? AND attempt = ?",
                    (
                        work.tenant_id,
                        work.transaction_id,
                        work.recovery_id,
                        work.attempt,
                    ),
                ).fetchone()
                late_attempt = (
                    None if attempt_row is None else self._reconciliation_from_row(attempt_row)
                )
            self._validate_late_recovery_report_association_tx(
                work,
                late_report,
                late_attempt,
            )
        unavailable_rows = self._connection.execute(
            "SELECT * FROM enforced_recovery_evidence_unavailable_reports "
            "ORDER BY tenant_id, transaction_id, recovery_id"
        ).fetchall()
        for row in unavailable_rows:
            recovery_unavailable = self._recovery_evidence_unavailable_from_row(row)
            self._validate_recovery_evidence_unavailable_association_tx(recovery_unavailable)
