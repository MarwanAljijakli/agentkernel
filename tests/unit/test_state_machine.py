from __future__ import annotations

import pytest
from agentkernel.domain.enums import IntendedOutcome, TransactionState
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.transactions.state_machine import (
    NORMATIVE_TRANSITIONS,
    TransitionEvent,
    TransitionRule,
    apply_transition,
)

_DYNAMIC_OUTCOMES = tuple(IntendedOutcome)
_NORMATIVE_CASES = tuple(
    pytest.param(
        rule,
        intended_outcome,
        id=(
            f"{rule.rule_id}-{intended_outcome.value}"
            if intended_outcome is not None
            else rule.rule_id
        ),
    )
    for rule in NORMATIVE_TRANSITIONS
    for intended_outcome in (_DYNAMIC_OUTCOMES if rule.target is None else (None,))
)

_ABORTING_RULES = tuple(
    pytest.param(rule, id=rule.rule_id)
    for rule in NORMATIVE_TRANSITIONS
    if rule.target is TransactionState.ABORTING
)

_PRE_COMMIT_STATES = (
    TransactionState.NEW,
    TransactionState.PLANNED,
    TransactionState.AUTHORIZED_TO_STAGE,
    TransactionState.STAGING,
    TransactionState.STAGED,
    TransactionState.STAGE_VERIFIED,
    TransactionState.AWAITING_APPROVAL,
    TransactionState.READY_TO_COMMIT,
)
_PRE_COMMIT_EXIT_EVENTS = (
    TransitionEvent.CANCELLED,
    TransitionEvent.DEADLINE_EXCEEDED,
    TransitionEvent.CONTEXT_EXITED,
)

_EXPECTED_TRANSITIONS = (
    TransitionRule(
        "TX-001",
        TransactionState.NEW,
        TransitionEvent.PROPOSAL_VALID,
        TransactionState.PLANNED,
    ),
    TransitionRule(
        "TX-002",
        TransactionState.NEW,
        TransitionEvent.VALIDATION_FAILED,
        TransactionState.REJECTED,
    ),
    TransitionRule(
        "TX-003",
        TransactionState.NEW,
        TransitionEvent.CANCELLED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    TransitionRule(
        "TX-004",
        TransactionState.NEW,
        TransitionEvent.DEADLINE_EXCEEDED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    TransitionRule(
        "TX-005",
        TransactionState.NEW,
        TransitionEvent.CONTEXT_EXITED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    TransitionRule(
        "TX-006",
        TransactionState.PLANNED,
        TransitionEvent.AUTHORIZED_FOR_STAGING,
        TransactionState.AUTHORIZED_TO_STAGE,
    ),
    TransitionRule(
        "TX-007",
        TransactionState.PLANNED,
        TransitionEvent.AUTHORITY_OR_POLICY_DENIED,
        TransactionState.REJECTED,
    ),
    *tuple(
        TransitionRule(
            f"TX-008-{source.value}-{event.name}",
            source,
            event,
            TransactionState.ABORTING,
            IntendedOutcome.ABORTED,
        )
        for source in (TransactionState.PLANNED, TransactionState.AUTHORIZED_TO_STAGE)
        for event in _PRE_COMMIT_EXIT_EVENTS
    ),
    TransitionRule(
        "TX-009",
        TransactionState.AUTHORIZED_TO_STAGE,
        TransitionEvent.WORKER_LEASE_ACQUIRED,
        TransactionState.STAGING,
    ),
    TransitionRule(
        "TX-010",
        TransactionState.STAGING,
        TransitionEvent.STAGING_SUCCEEDED,
        TransactionState.STAGED,
    ),
    TransitionRule(
        "TX-011",
        TransactionState.STAGING,
        TransitionEvent.STAGING_FAILED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    *tuple(
        TransitionRule(
            f"TX-012-{event.name}",
            TransactionState.STAGING,
            event,
            TransactionState.ABORTING,
            IntendedOutcome.ABORTED,
        )
        for event in _PRE_COMMIT_EXIT_EVENTS
    ),
    TransitionRule(
        "TX-013",
        TransactionState.STAGED,
        TransitionEvent.STAGED_VERIFICATION_PASSED,
        TransactionState.STAGE_VERIFIED,
    ),
    TransitionRule(
        "TX-014",
        TransactionState.STAGED,
        TransitionEvent.STAGED_VERIFICATION_FAILED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    *tuple(
        TransitionRule(
            f"TX-015-{event.name}",
            TransactionState.STAGED,
            event,
            TransactionState.ABORTING,
            IntendedOutcome.ABORTED,
        )
        for event in _PRE_COMMIT_EXIT_EVENTS
    ),
    TransitionRule(
        "TX-016",
        TransactionState.STAGE_VERIFIED,
        TransitionEvent.APPROVAL_REQUIRED,
        TransactionState.AWAITING_APPROVAL,
    ),
    TransitionRule(
        "TX-017",
        TransactionState.STAGE_VERIFIED,
        TransitionEvent.NO_APPROVAL_REQUIRED,
        TransactionState.READY_TO_COMMIT,
    ),
    *tuple(
        TransitionRule(
            f"TX-018-{source.value}-{event.name}",
            source,
            event,
            TransactionState.ABORTING,
            IntendedOutcome.ABORTED,
        )
        for source in (TransactionState.STAGE_VERIFIED, TransactionState.READY_TO_COMMIT)
        for event in _PRE_COMMIT_EXIT_EVENTS
    ),
    TransitionRule(
        "TX-019",
        TransactionState.AWAITING_APPROVAL,
        TransitionEvent.APPROVAL_GRANTED,
        TransactionState.READY_TO_COMMIT,
    ),
    TransitionRule(
        "TX-020",
        TransactionState.AWAITING_APPROVAL,
        TransitionEvent.APPROVAL_REJECTED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    *tuple(
        TransitionRule(
            f"TX-021-{event.name}",
            TransactionState.AWAITING_APPROVAL,
            event,
            TransactionState.ABORTING,
            IntendedOutcome.ABORTED,
        )
        for event in _PRE_COMMIT_EXIT_EVENTS
    ),
    TransitionRule(
        "TX-022",
        TransactionState.READY_TO_COMMIT,
        TransitionEvent.TARGET_VERSION_CHANGED,
        TransactionState.ABORTING,
        IntendedOutcome.STALE_STATE,
    ),
    TransitionRule(
        "TX-023",
        TransactionState.READY_TO_COMMIT,
        TransitionEvent.COMMIT_REVALIDATION_FAILED,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    TransitionRule(
        "TX-024",
        TransactionState.READY_TO_COMMIT,
        TransitionEvent.COMMIT_GUARDS_PASSED,
        TransactionState.COMMITTING,
    ),
    TransitionRule(
        "TX-025",
        TransactionState.COMMITTING,
        TransitionEvent.COMMIT_VERIFIED,
        TransactionState.COMMITTED,
    ),
    TransitionRule(
        "TX-026",
        TransactionState.COMMITTING,
        TransitionEvent.COMMIT_FAILED_NO_EFFECT,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    TransitionRule(
        "TX-027",
        TransactionState.COMMITTING,
        TransitionEvent.COMMIT_PARTIAL_OR_INVALID,
        TransactionState.FAILED,
    ),
    TransitionRule(
        "TX-028",
        TransactionState.COMMITTING,
        TransitionEvent.COMMIT_OUTCOME_UNKNOWN,
        TransactionState.IN_DOUBT,
    ),
    TransitionRule(
        "TX-029",
        TransactionState.FAILED,
        TransitionEvent.START_ROLLBACK,
        TransactionState.ROLLING_BACK,
    ),
    TransitionRule(
        "TX-030",
        TransactionState.FAILED,
        TransitionEvent.START_COMPENSATION,
        TransactionState.COMPENSATING,
    ),
    TransitionRule(
        "TX-031",
        TransactionState.FAILED,
        TransitionEvent.RECOVERY_UNAVAILABLE,
        TransactionState.RECOVERY_FAILED,
    ),
    TransitionRule(
        "TX-032",
        TransactionState.ABORTING,
        TransitionEvent.STAGING_DISCARD_SUCCEEDED,
        None,
    ),
    TransitionRule(
        "TX-033",
        TransactionState.ABORTING,
        TransitionEvent.STAGING_DISCARD_FAILED,
        TransactionState.RECOVERY_FAILED,
    ),
    TransitionRule(
        "TX-034",
        TransactionState.ROLLING_BACK,
        TransitionEvent.ROLLBACK_VERIFIED,
        TransactionState.ROLLED_BACK,
    ),
    TransitionRule(
        "TX-035",
        TransactionState.ROLLING_BACK,
        TransitionEvent.ROLLBACK_FAILED_OR_UNKNOWN,
        TransactionState.RECOVERY_FAILED,
    ),
    TransitionRule(
        "TX-036",
        TransactionState.COMPENSATING,
        TransitionEvent.COMPENSATION_VERIFIED,
        TransactionState.COMPENSATED,
    ),
    TransitionRule(
        "TX-037",
        TransactionState.COMPENSATING,
        TransitionEvent.COMPENSATION_FAILED_OR_UNKNOWN,
        TransactionState.COMPENSATION_FAILED,
    ),
    TransitionRule(
        "TX-038",
        TransactionState.IN_DOUBT,
        TransitionEvent.RECONCILIATION_STARTED,
        TransactionState.RECONCILING,
    ),
    TransitionRule(
        "TX-039",
        TransactionState.RECONCILING,
        TransitionEvent.RECONCILIATION_COMMITTED,
        TransactionState.COMMITTED,
    ),
    TransitionRule(
        "TX-040",
        TransactionState.RECONCILING,
        TransitionEvent.RECONCILIATION_NO_EFFECT,
        TransactionState.ABORTING,
        IntendedOutcome.ABORTED,
    ),
    TransitionRule(
        "TX-041",
        TransactionState.RECONCILING,
        TransitionEvent.RECONCILIATION_PARTIAL_OR_INVALID,
        TransactionState.FAILED,
    ),
    TransitionRule(
        "TX-042",
        TransactionState.RECONCILING,
        TransitionEvent.RECONCILIATION_UNKNOWN,
        TransactionState.IN_DOUBT,
    ),
)


@pytest.mark.parametrize(("rule", "current_intended_outcome"), _NORMATIVE_CASES)
def test_every_normative_rule_variant_is_executable(
    rule: TransitionRule,
    current_intended_outcome: IntendedOutcome | None,
) -> None:
    decision = apply_transition(
        rule.source,
        rule.event,
        current_intended_outcome=current_intended_outcome,
    )

    expected_target = (
        TransactionState(current_intended_outcome.value)
        if rule.target is None and current_intended_outcome is not None
        else rule.target
    )
    assert decision.rule_id == rule.rule_id
    assert decision.source is rule.source
    assert decision.event is rule.event
    assert decision.target is expected_target
    assert decision.intended_outcome is (rule.intended_outcome or current_intended_outcome)


def test_normative_row_and_variant_inventory_is_complete_and_unique() -> None:
    assert NORMATIVE_TRANSITIONS == _EXPECTED_TRANSITIONS
    assert len({rule.rule_id for rule in NORMATIVE_TRANSITIONS}) == len(NORMATIVE_TRANSITIONS)
    assert len({(rule.source, rule.event) for rule in NORMATIVE_TRANSITIONS}) == len(
        NORMATIVE_TRANSITIONS
    )


@pytest.mark.parametrize("rule", _ABORTING_RULES)
def test_every_aborting_rule_declares_a_valid_intended_outcome(rule: TransitionRule) -> None:
    assert rule.intended_outcome in {IntendedOutcome.ABORTED, IntendedOutcome.STALE_STATE}
    decision = apply_transition(rule.source, rule.event)
    assert decision.target is TransactionState.ABORTING
    assert decision.intended_outcome is rule.intended_outcome


@pytest.mark.parametrize("state", _PRE_COMMIT_STATES, ids=lambda state: state.value)
@pytest.mark.parametrize("event", _PRE_COMMIT_EXIT_EVENTS, ids=lambda event: event.name)
def test_every_pre_commit_control_exit_enters_aborting(
    state: TransactionState,
    event: TransitionEvent,
) -> None:
    decision = apply_transition(state, event)
    assert decision.target is TransactionState.ABORTING
    assert decision.intended_outcome is IntendedOutcome.ABORTED


def test_new_validation_failure_remains_rejected() -> None:
    decision = apply_transition(TransactionState.NEW, TransitionEvent.VALIDATION_FAILED)
    assert decision.target is TransactionState.REJECTED
    assert decision.intended_outcome is None


@pytest.mark.parametrize("state", list(TransactionState))
def test_representative_illegal_transition_is_rejected(state: TransactionState) -> None:
    legal = {(rule.source, rule.event) for rule in NORMATIVE_TRANSITIONS}
    event = next(candidate for candidate in TransitionEvent if (state, candidate) not in legal)
    with pytest.raises(AgentKernelError) as captured:
        apply_transition(state, event)
    assert captured.value.code is ErrorCode.ILLEGAL_TRANSITION


def test_aborting_completion_requires_durable_intended_outcome() -> None:
    with pytest.raises(AgentKernelError) as captured:
        apply_transition(TransactionState.ABORTING, TransitionEvent.STAGING_DISCARD_SUCCEEDED)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize("intended_outcome", _DYNAMIC_OUTCOMES)
def test_aborting_completion_uses_the_persisted_intended_outcome(
    intended_outcome: IntendedOutcome,
) -> None:
    decision = apply_transition(
        TransactionState.ABORTING,
        TransitionEvent.STAGING_DISCARD_SUCCEEDED,
        current_intended_outcome=intended_outcome,
    )
    assert decision.target is TransactionState(intended_outcome.value)
    assert decision.intended_outcome is intended_outcome


def test_stale_alias_is_not_a_durable_transaction_state() -> None:
    assert "STALE" not in TransactionState.__members__
    assert "STALE" not in {state.value for state in TransactionState}
    with pytest.raises(ValueError, match="'STALE' is not a valid TransactionState"):
        TransactionState("STALE")
