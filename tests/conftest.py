from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from agentkernel.domain.models import ActionProposal, TransactionRecord


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
def proposal(now: datetime) -> ActionProposal:
    return ActionProposal(
        goal_id="goal_demo",
        transaction_id="tx_demo",
        agent_id="agent:scripted:demo",
        adapter="mock",
        adapter_version="0.1.0",
        operation="set_values",
        arguments={"values": {"answer": "42"}},
        provenance_ids=("prov_model_1",),
        capability_refs=("cap_demo",),
        deadline=now + timedelta(minutes=5),
    )


@pytest.fixture
def transaction(now: datetime) -> TransactionRecord:
    return TransactionRecord(
        transaction_id="tx_demo",
        goal_id="goal_demo",
        created_at=now,
        updated_at=now,
    )
