from __future__ import annotations

import json

import pytest
from agentkernel.domain.enums import TransactionState
from agentkernel.domain.models import ActionProposal, TransactionRecord
from pydantic import ValidationError


def test_contract_rejects_unknown_fields(proposal: ActionProposal) -> None:
    data = proposal.model_dump(mode="python")
    data["surprise"] = "not part of the contract"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ActionProposal.model_validate(data)


def test_contract_round_trip_is_stable(proposal: ActionProposal) -> None:
    first = proposal.model_dump_json()
    second = ActionProposal.model_validate_json(first).model_dump_json()
    assert first == second


def test_effect_payload_preserves_significant_whitespace(proposal: ActionProposal) -> None:
    updated = proposal.model_copy(update={"arguments": {"content": "  exact\n"}})
    round_tripped = ActionProposal.model_validate_json(updated.model_dump_json())
    assert round_tripped.arguments["content"] == "  exact\n"


def test_schema_generation_is_deterministic() -> None:
    first = json.dumps(ActionProposal.model_json_schema(), sort_keys=True)
    second = json.dumps(ActionProposal.model_json_schema(), sort_keys=True)
    assert first == second
    assert "api_version" in first


def test_stale_is_not_a_durable_state(transaction: TransactionRecord) -> None:
    data = transaction.model_dump(mode="python")
    data["state"] = "STALE"
    with pytest.raises(ValidationError):
        TransactionRecord.model_validate(data)
    assert TransactionState.STALE_STATE.value == "STALE_STATE"
