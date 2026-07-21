from __future__ import annotations

import pytest
from agentkernel.domain.enums import IntendedOutcome, TransactionState
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.transactions.state_machine import (
    NORMATIVE_TRANSITIONS,
    TransitionEvent,
    apply_transition,
)


@pytest.mark.parametrize("rule", NORMATIVE_TRANSITIONS, ids=lambda rule: rule.rule_id)
def test_every_normative_rule_is_executable(rule: object) -> None:
    source = rule.source  # type: ignore[attr-defined]
    event = rule.event  # type: ignore[attr-defined]
    intended = IntendedOutcome.ABORTED if rule.target is None else None  # type: ignore[attr-defined]
    decision = apply_transition(source, event, current_intended_outcome=intended)
    expected = TransactionState(intended.value) if rule.target is None else rule.target  # type: ignore[attr-defined]
    assert decision.target is expected
    if decision.target is TransactionState.ABORTING:
        assert decision.intended_outcome in {IntendedOutcome.ABORTED, IntendedOutcome.STALE_STATE}


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
