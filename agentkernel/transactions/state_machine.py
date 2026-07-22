"""Pure implementation of the normative AgentKernel transaction state machine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from agentkernel.domain.enums import IntendedOutcome, TransactionState
from agentkernel.errors import AgentKernelError, ErrorCode


class TransitionEvent(StrEnum):
    PROPOSAL_VALID = "proposal.valid"
    VALIDATION_FAILED = "proposal.validation_failed"
    CANCELLED = "control.cancelled"
    DEADLINE_EXCEEDED = "control.deadline_exceeded"
    CONTEXT_EXITED = "control.context_exited"
    AUTHORIZED_FOR_STAGING = "authority.staging_authorized"
    AUTHORITY_OR_POLICY_DENIED = "authority_or_policy.denied"
    WORKER_LEASE_ACQUIRED = "worker.lease_acquired"
    STAGING_SUCCEEDED = "staging.succeeded"
    STAGING_FAILED = "staging.failed"
    STAGED_VERIFICATION_PASSED = "verification.staged_passed"
    STAGED_VERIFICATION_FAILED = "verification.staged_failed"
    APPROVAL_REQUIRED = "approval.required"
    NO_APPROVAL_REQUIRED = "approval.not_required"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_REJECTED = "approval.rejected"
    TARGET_VERSION_CHANGED = "commit.target_version_changed"
    COMMIT_REVALIDATION_FAILED = "commit.revalidation_failed"
    COMMIT_GUARDS_PASSED = "commit.guards_passed"
    COMMIT_VERIFIED = "commit.verified"
    COMMIT_FAILED_NO_EFFECT = "commit.failed_no_effect"
    COMMIT_PARTIAL_OR_INVALID = "commit.partial_or_invalid"
    COMMIT_OUTCOME_UNKNOWN = "commit.outcome_unknown"
    START_ROLLBACK = "recovery.rollback_started"
    START_COMPENSATION = "recovery.compensation_started"
    RECOVERY_UNAVAILABLE = "recovery.unavailable"
    STAGING_DISCARD_SUCCEEDED = "abort.discard_succeeded"
    STAGING_DISCARD_FAILED = "abort.discard_failed"
    ROLLBACK_VERIFIED = "recovery.rollback_verified"
    ROLLBACK_FAILED_OR_UNKNOWN = "recovery.rollback_failed_or_unknown"
    COMPENSATION_VERIFIED = "recovery.compensation_verified"
    COMPENSATION_FAILED_OR_UNKNOWN = "recovery.compensation_failed_or_unknown"
    RECONCILIATION_STARTED = "reconcile.started"
    RECONCILIATION_COMMITTED = "reconcile.committed"
    RECONCILIATION_NO_EFFECT = "reconcile.no_effect"
    RECONCILIATION_PARTIAL_OR_INVALID = "reconcile.partial_or_invalid"
    RECONCILIATION_UNKNOWN = "reconcile.unknown"


@dataclass(frozen=True, slots=True)
class TransitionRule:
    """A single executable row/variant from the normative transition table."""

    rule_id: str
    source: TransactionState
    event: TransitionEvent
    target: TransactionState | None
    intended_outcome: IntendedOutcome | None = None


@dataclass(frozen=True, slots=True)
class TransitionDecision:
    """Pure transition output to be durably applied by a journal."""

    rule_id: str
    source: TransactionState
    event: TransitionEvent
    target: TransactionState
    intended_outcome: IntendedOutcome | None


def _rule(
    rule_id: str,
    source: TransactionState,
    event: TransitionEvent,
    target: TransactionState | None,
    intended: IntendedOutcome | None = None,
) -> TransitionRule:
    return TransitionRule(rule_id, source, event, target, intended)


NORMATIVE_TRANSITIONS: tuple[TransitionRule, ...] = (
    _rule("TX-001", TransactionState.NEW, TransitionEvent.PROPOSAL_VALID, TransactionState.PLANNED),
    _rule(
        "TX-002",
        TransactionState.NEW,
        TransitionEvent.VALIDATION_FAILED,
        TransactionState.REJECTED,
    ),
    _rule(
        "TX-003",
        TransactionState.NEW,
        TransitionEvent.CANCELLED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    _rule(
        "TX-004",
        TransactionState.NEW,
        TransitionEvent.DEADLINE_EXCEEDED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    _rule(
        "TX-005",
        TransactionState.NEW,
        TransitionEvent.CONTEXT_EXITED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    _rule(
        "TX-006",
        TransactionState.PLANNED,
        TransitionEvent.AUTHORIZED_FOR_STAGING,
        TransactionState.AUTHORIZED_TO_STAGE,
    ),
    _rule(
        "TX-007",
        TransactionState.PLANNED,
        TransitionEvent.AUTHORITY_OR_POLICY_DENIED,
        TransactionState.REJECTED,
    ),
    *tuple(
        _rule(
            f"TX-008-{source.value}-{event.name}",
            source,
            event,
            TransactionState.ABORTING,
            IntendedOutcome.ABORTED,
        )
        for source in (TransactionState.PLANNED, TransactionState.AUTHORIZED_TO_STAGE)
        for event in (
            TransitionEvent.CANCELLED,
            TransitionEvent.DEADLINE_EXCEEDED,
            TransitionEvent.CONTEXT_EXITED,
        )
    ),
    _rule(
        "TX-009",
        TransactionState.AUTHORIZED_TO_STAGE,
        TransitionEvent.WORKER_LEASE_ACQUIRED,
        TransactionState.STAGING,
    ),
    _rule(
        "TX-010",
        TransactionState.STAGING,
        TransitionEvent.STAGING_SUCCEEDED,
        TransactionState.STAGED,
    ),
    _rule(
        "TX-011",
        TransactionState.STAGING,
        TransitionEvent.STAGING_FAILED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    *tuple(
        _rule(
            f"TX-012-{event.name}",
            TransactionState.STAGING,
            event,
            TransactionState.ABORTING,
            IntendedOutcome.ABORTED,
        )
        for event in (
            TransitionEvent.CANCELLED,
            TransitionEvent.DEADLINE_EXCEEDED,
            TransitionEvent.CONTEXT_EXITED,
        )
    ),
    _rule(
        "TX-013",
        TransactionState.STAGED,
        TransitionEvent.STAGED_VERIFICATION_PASSED,
        TransactionState.STAGE_VERIFIED,
    ),
    _rule(
        "TX-014",
        TransactionState.STAGED,
        TransitionEvent.STAGED_VERIFICATION_FAILED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    *tuple(
        _rule(
            f"TX-015-{event.name}",
            TransactionState.STAGED,
            event,
            TransactionState.ABORTING,
            IntendedOutcome.ABORTED,
        )
        for event in (
            TransitionEvent.CANCELLED,
            TransitionEvent.DEADLINE_EXCEEDED,
            TransitionEvent.CONTEXT_EXITED,
        )
    ),
    _rule(
        "TX-016",
        TransactionState.STAGE_VERIFIED,
        TransitionEvent.APPROVAL_REQUIRED,
        TransactionState.AWAITING_APPROVAL,
    ),
    _rule(
        "TX-017",
        TransactionState.STAGE_VERIFIED,
        TransitionEvent.NO_APPROVAL_REQUIRED,
        TransactionState.READY_TO_COMMIT,
    ),
    *tuple(
        _rule(
            f"TX-018-{source.value}-{event.name}",
            source,
            event,
            TransactionState.ABORTING,
            IntendedOutcome.ABORTED,
        )
        for source in (TransactionState.STAGE_VERIFIED, TransactionState.READY_TO_COMMIT)
        for event in (
            TransitionEvent.CANCELLED,
            TransitionEvent.DEADLINE_EXCEEDED,
            TransitionEvent.CONTEXT_EXITED,
        )
    ),
    _rule(
        "TX-019",
        TransactionState.AWAITING_APPROVAL,
        TransitionEvent.APPROVAL_GRANTED,
        TransactionState.READY_TO_COMMIT,
    ),
    _rule(
        "TX-020",
        TransactionState.AWAITING_APPROVAL,
        TransitionEvent.APPROVAL_REJECTED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    *tuple(
        _rule(
            f"TX-021-{event.name}",
            TransactionState.AWAITING_APPROVAL,
            event,
            TransactionState.ABORTING,
            IntendedOutcome.ABORTED,
        )
        for event in (
            TransitionEvent.CANCELLED,
            TransitionEvent.DEADLINE_EXCEEDED,
            TransitionEvent.CONTEXT_EXITED,
        )
    ),
    _rule(
        "TX-022",
        TransactionState.READY_TO_COMMIT,
        TransitionEvent.TARGET_VERSION_CHANGED,
        TransactionState.ABORTING,
        IntendedOutcome.STALE_STATE,
    ),
    _rule(
        "TX-023",
        TransactionState.READY_TO_COMMIT,
        TransitionEvent.COMMIT_REVALIDATION_FAILED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    _rule(
        "TX-024",
        TransactionState.READY_TO_COMMIT,
        TransitionEvent.COMMIT_GUARDS_PASSED,
        TransactionState.COMMITTING,
    ),
    _rule(
        "TX-025",
        TransactionState.COMMITTING,
        TransitionEvent.COMMIT_VERIFIED,
        TransactionState.COMMITTED,
    ),
    _rule(
        "TX-026",
        TransactionState.COMMITTING,
        TransitionEvent.COMMIT_FAILED_NO_EFFECT,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    _rule(
        "TX-027",
        TransactionState.COMMITTING,
        TransitionEvent.COMMIT_PARTIAL_OR_INVALID,
        TransactionState.FAILED,
    ),
    _rule(
        "TX-028",
        TransactionState.COMMITTING,
        TransitionEvent.COMMIT_OUTCOME_UNKNOWN,
        TransactionState.IN_DOUBT,
    ),
    _rule(
        "TX-029",
        TransactionState.FAILED,
        TransitionEvent.START_ROLLBACK,
        TransactionState.ROLLING_BACK,
    ),
    _rule(
        "TX-030",
        TransactionState.FAILED,
        TransitionEvent.START_COMPENSATION,
        TransactionState.COMPENSATING,
    ),
    _rule(
        "TX-031",
        TransactionState.FAILED,
        TransitionEvent.RECOVERY_UNAVAILABLE,
        TransactionState.RECOVERY_FAILED,
    ),
    _rule(
        "TX-032",
        TransactionState.ABORTING,
        TransitionEvent.STAGING_DISCARD_SUCCEEDED,
        None,
    ),
    _rule(
        "TX-033",
        TransactionState.ABORTING,
        TransitionEvent.STAGING_DISCARD_FAILED,
        TransactionState.RECOVERY_FAILED,
    ),
    _rule(
        "TX-034",
        TransactionState.ROLLING_BACK,
        TransitionEvent.ROLLBACK_VERIFIED,
        TransactionState.ROLLED_BACK,
    ),
    _rule(
        "TX-035",
        TransactionState.ROLLING_BACK,
        TransitionEvent.ROLLBACK_FAILED_OR_UNKNOWN,
        TransactionState.RECOVERY_FAILED,
    ),
    _rule(
        "TX-036",
        TransactionState.COMPENSATING,
        TransitionEvent.COMPENSATION_VERIFIED,
        TransactionState.COMPENSATED,
    ),
    _rule(
        "TX-037",
        TransactionState.COMPENSATING,
        TransitionEvent.COMPENSATION_FAILED_OR_UNKNOWN,
        TransactionState.COMPENSATION_FAILED,
    ),
    _rule(
        "TX-038",
        TransactionState.IN_DOUBT,
        TransitionEvent.RECONCILIATION_STARTED,
        TransactionState.RECONCILING,
    ),
    _rule(
        "TX-039",
        TransactionState.RECONCILING,
        TransitionEvent.RECONCILIATION_COMMITTED,
        TransactionState.COMMITTED,
    ),
    _rule(
        "TX-040",
        TransactionState.RECONCILING,
        TransitionEvent.RECONCILIATION_NO_EFFECT,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    _rule(
        "TX-041",
        TransactionState.RECONCILING,
        TransitionEvent.RECONCILIATION_PARTIAL_OR_INVALID,
        TransactionState.FAILED,
    ),
    _rule(
        "TX-042",
        TransactionState.RECONCILING,
        TransitionEvent.RECONCILIATION_UNKNOWN,
        TransactionState.IN_DOUBT,
    ),
)

_TRANSITION_INDEX = {(rule.source, rule.event): rule for rule in NORMATIVE_TRANSITIONS}
if len(_TRANSITION_INDEX) != len(NORMATIVE_TRANSITIONS):
    raise RuntimeError("Duplicate state/event pair in the normative transaction table")

_RULE_IDS = {rule.rule_id for rule in NORMATIVE_TRANSITIONS}
if len(_RULE_IDS) != len(NORMATIVE_TRANSITIONS):
    raise RuntimeError("Duplicate rule ID in the normative transaction table")

if any(
    rule.target is TransactionState.ABORTING
    and rule.intended_outcome not in {IntendedOutcome.ABORTED, IntendedOutcome.STALE_STATE}
    for rule in NORMATIVE_TRANSITIONS
):
    raise RuntimeError("Every ABORTING rule must declare ABORTED or STALE_STATE")


def apply_transition(
    source: TransactionState,
    event: TransitionEvent,
    *,
    current_intended_outcome: IntendedOutcome | None = None,
) -> TransitionDecision:
    """Evaluate one transition without mutating persistence or executing an effect."""

    rule = _TRANSITION_INDEX.get((source, event))
    if rule is None:
        raise AgentKernelError(
            ErrorCode.ILLEGAL_TRANSITION,
            "Event is not legal from the current durable state",
            details={"state": source.value, "event": event.value},
        )

    target = rule.target
    intended_outcome = rule.intended_outcome or current_intended_outcome
    if target is None:
        if (
            source is not TransactionState.ABORTING
            or event is not TransitionEvent.STAGING_DISCARD_SUCCEEDED
        ):
            raise RuntimeError("Only the normative ABORTING completion may have a dynamic target")
        if current_intended_outcome is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "ABORTING completion is missing its durable intended outcome",
            )
        target = TransactionState(current_intended_outcome.value)

    if target is TransactionState.ABORTING and intended_outcome is None:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Every ABORTING transition must persist ABORTED or STALE_STATE",
        )

    return TransitionDecision(
        rule_id=rule.rule_id,
        source=source,
        event=event,
        target=target,
        intended_outcome=intended_outcome,
    )
