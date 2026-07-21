"""Explicit replay fidelity and divergence contract."""

from agentkernel.domain.enums import ReplayLevel
from agentkernel.domain.models import Digest, NonEmptyStr, StrictModel


class ReplayReport(StrictModel):
    level: ReplayLevel
    authoritative_effects: bool = False
    original_action_hash: Digest
    replay_action_hash: Digest
    original_final_state_hash: Digest
    replay_final_state_hash: Digest
    divergences: tuple[NonEmptyStr, ...] = ()

    @property
    def matched(self) -> bool:
        return (
            not self.authoritative_effects
            and not self.divergences
            and self.original_action_hash == self.replay_action_hash
            and self.original_final_state_hash == self.replay_final_state_hash
        )
