"""Canonical event construction and append-only hash-chain validation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import JsonValue

from agentkernel.canonical import canonical_digest
from agentkernel.domain.models import EventEnvelope
from agentkernel.ids import new_id


@dataclass(frozen=True, slots=True)
class LedgerValidation:
    valid: bool
    first_broken_sequence: int | None
    reason: str | None
    final_hash: str | None


def event_hash_material(event: EventEnvelope | dict[str, Any]) -> dict[str, Any]:
    """Return semantic fields covered by the event hash.

    `event_hash` is self-referential and `signature_ref` is attached after hashing, so both
    are excluded. A production checkpoint separately binds signatures to the resulting hash.
    """

    data = event.model_dump(mode="python") if isinstance(event, EventEnvelope) else dict(event)
    data.pop("event_hash", None)
    data.pop("signature_ref", None)
    return data


def make_event(
    *,
    run_id: str,
    sequence: int,
    logical_time: int,
    wall_time: datetime,
    event_type: str,
    actor: str,
    on_behalf_of: str,
    payload: dict[str, JsonValue] | None = None,
    transaction_id: str | None = None,
    artifact_refs: tuple[str, ...] = (),
    previous_event_hash: str | None = None,
    event_id: str | None = None,
) -> EventEnvelope:
    data: dict[str, Any] = {
        "schema_version": "1.0",
        "event_id": event_id or new_id("evt"),
        "run_id": run_id,
        "transaction_id": transaction_id,
        "sequence": sequence,
        "logical_time": logical_time,
        "wall_time": wall_time,
        "event_type": event_type,
        "actor": actor,
        "on_behalf_of": on_behalf_of,
        "payload": payload or {},
        "artifact_refs": artifact_refs,
        "previous_event_hash": previous_event_hash,
    }
    return EventEnvelope(**data, event_hash=canonical_digest(event_hash_material(data)))


def validate_chain(events: list[EventEnvelope] | tuple[EventEnvelope, ...]) -> LedgerValidation:
    """Validate a complete supplied chain and report its first observable break.

    A hash chain cannot detect deletion of an uncheckpointed final suffix. Production profiles
    must compare the returned final hash/sequence with an independently controlled checkpoint.
    """

    previous_hash: str | None = None
    previous_sequence: int | None = None
    for event in events:
        expected_sequence = 0 if previous_sequence is None else previous_sequence + 1
        if event.sequence != expected_sequence:
            return LedgerValidation(
                valid=False,
                first_broken_sequence=event.sequence,
                reason=f"non-contiguous sequence; expected {expected_sequence}",
                final_hash=previous_hash,
            )
        if event.previous_event_hash != previous_hash:
            return LedgerValidation(
                valid=False,
                first_broken_sequence=event.sequence,
                reason="previous_event_hash does not match the prior event",
                final_hash=previous_hash,
            )
        expected_hash = canonical_digest(event_hash_material(event))
        if event.event_hash != expected_hash:
            return LedgerValidation(
                valid=False,
                first_broken_sequence=event.sequence,
                reason="event_hash does not match canonical event content",
                final_hash=previous_hash,
            )
        previous_sequence = event.sequence
        previous_hash = event.event_hash
    return LedgerValidation(
        valid=True,
        first_broken_sequence=None,
        reason=None,
        final_hash=previous_hash,
    )
