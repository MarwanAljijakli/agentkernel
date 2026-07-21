from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from agentkernel.domain.enums import TransactionState
from agentkernel.domain.models import TransactionRecord
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.ledger import validate_chain
from agentkernel.storage.sqlite import SQLiteJournal
from agentkernel.transactions.state_machine import TransitionEvent


@pytest.mark.integration
def test_wal_migrations_and_records_survive_reopen(tmp_path: Path, now: datetime) -> None:
    path = tmp_path / "journal.db"
    record = TransactionRecord(
        transaction_id="tx_persist",
        goal_id="goal_demo",
        created_at=now,
        updated_at=now,
    )
    with SQLiteJournal(path) as journal:
        assert journal.journal_mode == "wal"
        assert journal.schema_version() == 2
        journal.create_transaction(
            record,
            run_id="run_persist",
            actor="service:test",
            on_behalf_of="principal:test",
        )

    with SQLiteJournal(path) as reopened:
        assert reopened.get_transaction("tx_persist") == record
        assert validate_chain(reopened.list_events("run_persist")).valid
        assert reopened.schema_version() == 2


@pytest.mark.integration
def test_compare_and_swap_rejects_stale_writer(
    tmp_path: Path, transaction: TransactionRecord
) -> None:
    with SQLiteJournal(tmp_path / "journal.db") as journal:
        journal.create_transaction(
            transaction,
            run_id="run_cas",
            actor="service:test",
            on_behalf_of="principal:test",
        )
        updated, _ = journal.transition(
            transaction.transaction_id,
            expected_version=0,
            transition_event=TransitionEvent.PROPOSAL_VALID,
            now=transaction.updated_at,
            run_id="run_cas",
            actor="service:test",
            on_behalf_of="principal:test",
        )
        assert updated.version == 1
        assert updated.state is TransactionState.PLANNED
        with pytest.raises(AgentKernelError) as captured:
            journal.transition(
                transaction.transaction_id,
                expected_version=0,
                transition_event=TransitionEvent.PROPOSAL_VALID,
                now=transaction.updated_at,
                run_id="run_cas",
                actor="service:test",
                on_behalf_of="principal:test",
            )
        assert captured.value.code is ErrorCode.VERSION_CONFLICT


@pytest.mark.integration
def test_intent_reservation_has_one_owner(tmp_path: Path, now: datetime) -> None:
    digest = "sha256:" + "a" * 64
    first = TransactionRecord(
        transaction_id="tx_first",
        goal_id="goal_demo",
        created_at=now,
        updated_at=now,
    )
    second = first.model_copy(update={"transaction_id": "tx_second"})
    with SQLiteJournal(tmp_path / "journal.db") as journal:
        for record in (first, second):
            journal.create_transaction(
                record,
                run_id="run_intent",
                actor="service:test",
                on_behalf_of="principal:test",
            )
        created = journal.reserve_intent(
            intent_hash=digest,
            transaction_id=first.transaction_id,
            reserved_at=now,
        )
        duplicate = journal.reserve_intent(
            intent_hash=digest,
            transaction_id=second.transaction_id,
            reserved_at=now,
        )
        assert created.created
        assert not duplicate.created
        assert duplicate.transaction_id == first.transaction_id


@pytest.mark.integration
def test_non_terminal_query_excludes_committed(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    pending = TransactionRecord(
        transaction_id="tx_pending",
        goal_id="goal_demo",
        created_at=now,
        updated_at=now,
    )
    committed = pending.model_copy(
        update={"transaction_id": "tx_committed", "state": TransactionState.COMMITTED}
    )
    with SQLiteJournal(tmp_path / "journal.db") as journal:
        for record in (pending, committed):
            journal.create_transaction(
                record,
                run_id="run_states",
                actor="service:test",
                on_behalf_of="principal:test",
            )
        assert journal.list_non_terminal() == (pending,)
