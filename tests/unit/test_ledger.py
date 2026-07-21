from __future__ import annotations

from datetime import UTC, datetime

from agentkernel.evidence.ledger import make_event, validate_chain


def _events() -> list:
    events = []
    previous = None
    for sequence in range(3):
        event = make_event(
            run_id="run_demo",
            sequence=sequence,
            logical_time=sequence,
            wall_time=datetime(2026, 1, 1, tzinfo=UTC),
            event_type="test.event",
            actor="service:test",
            on_behalf_of="principal:test",
            payload={"sequence": sequence},
            previous_event_hash=previous,
            event_id=f"evt_{sequence}",
        )
        events.append(event)
        previous = event.event_hash
    return events


def test_valid_chain_passes() -> None:
    result = validate_chain(_events())
    assert result.valid
    assert result.first_broken_sequence is None


def test_mutation_reports_first_broken_sequence() -> None:
    events = _events()
    events[1] = events[1].model_copy(update={"payload": {"sequence": 999}})
    result = validate_chain(events)
    assert not result.valid
    assert result.first_broken_sequence == 1
    assert result.reason == "event_hash does not match canonical event content"


def test_reordering_is_detected() -> None:
    events = _events()
    events[1], events[2] = events[2], events[1]
    result = validate_chain(events)
    assert not result.valid
    assert result.first_broken_sequence == 2
    assert "non-contiguous" in str(result.reason)


def test_middle_deletion_is_detected() -> None:
    events = _events()
    result = validate_chain([events[0], events[2]])
    assert not result.valid
    assert result.first_broken_sequence == 2
