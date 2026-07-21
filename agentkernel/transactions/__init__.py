"""Transaction state, persistence, and coordination primitives."""

from agentkernel.transactions.state_machine import (
    NORMATIVE_TRANSITIONS,
    TransitionDecision,
    TransitionEvent,
    apply_transition,
)

__all__ = [
    "NORMATIVE_TRANSITIONS",
    "TransitionDecision",
    "TransitionEvent",
    "apply_transition",
]
