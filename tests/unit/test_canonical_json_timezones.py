from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone, tzinfo

import pytest
from agentkernel.authority.evaluator import AuthoritySnapshot, EnforcedCapabilityGrant
from agentkernel.canonical import validate_canonical_input_bounds
from agentkernel.domain.models import ActionProposal, AuthenticatedActionContext
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.transactions.enforced import EnforcedTransactionRequest
from pydantic import TypeAdapter

_DIGEST = "sha256:" + ("0" * 64)


def _bound(value: object) -> None:
    validate_canonical_input_bounds(
        value,
        max_depth=16,
        max_container_items=256,
        max_nodes=4_096,
        max_string_characters=512,
        max_total_string_characters=65_536,
        max_integer_bits=63,
    )


def _request() -> EnforcedTransactionRequest:
    context = AuthenticatedActionContext(
        tenant_id="tenant:json",
        principal_id="principal:json",
        goal_id="goal:json",
        run_id="run:json",
        trace_id="trace:json",
        actor_id="actor:json",
        on_behalf_of="principal:json",
        agent_id="agent:json",
        configuration_digest=_DIGEST,
    )
    proposal = ActionProposal(
        goal_id=context.goal_id,
        transaction_id="transaction:json",
        agent_id=context.agent_id,
        adapter="mock",
        adapter_version="1.0",
        operation="set_values",
        arguments={"values": {"answer": "42"}},
        deadline=datetime(2030, 1, 1, 0, 5, tzinfo=UTC),
    )
    return EnforcedTransactionRequest(
        proposal=proposal,
        presented_context=context,
        authentication_evidence_ref=_DIGEST,
    )


def test_pre_hash_accepts_request_deadline_after_json_round_trip() -> None:
    request = _request()

    restored = EnforcedTransactionRequest.model_validate_json(request.model_dump_json())

    assert restored.proposal.deadline.tzinfo is not UTC
    _bound(restored.model_dump(mode="python"))


def test_pre_hash_accepts_authority_snapshot_timestamp_after_json_round_trip() -> None:
    as_of = datetime(2030, 1, 1, tzinfo=UTC)
    capability = EnforcedCapabilityGrant.create(
        tenant_id="tenant:json",
        capability_id="capability:json",
        token_version=1,
        key_id="key:json",
        issuer="issuer:json",
        subject="agent:json",
        audience="service:json",
        goal_id="goal:json",
        run_id="run:json",
        actions=("mock.set_values",),
        resource_scopes=("fs://workspace/**",),
        data_classes=(),
        issued_at=as_of - timedelta(minutes=2),
        not_before=as_of - timedelta(minutes=1),
        expires_at=as_of + timedelta(minutes=5),
        max_uses=1,
        nonce="nonce:json",
    )
    snapshot = AuthoritySnapshot.create(
        tenant_id="tenant:json",
        snapshot_id="snapshot:json",
        revision=1,
        as_of=as_of,
        capabilities=(capability,),
    )

    restored = AuthoritySnapshot.model_validate_json(snapshot.model_dump_json())

    assert restored.as_of.tzinfo is not UTC
    assert restored.capabilities[0].issued_at.tzinfo is not UTC
    _bound(restored.model_dump(mode="python"))


@pytest.mark.parametrize(
    "value",
    [
        datetime(2030, 1, 1),
        datetime(2030, 1, 1, tzinfo=timezone(timedelta(hours=1))),
        TypeAdapter(datetime).validate_json('"2030-01-01T01:00:00+01:00"'),
    ],
)
def test_pre_hash_rejects_naive_and_non_utc_timestamps(value: datetime) -> None:
    with pytest.raises(AgentKernelError) as captured:
        _bound(value)

    assert captured.value.code is ErrorCode.VALIDATION_ERROR


class _ExplosiveTimezone(tzinfo):
    def __eq__(self, _value: object) -> bool:
        raise AssertionError("untrusted timezone equality callback executed")

    def __hash__(self) -> int:
        raise AssertionError("untrusted timezone hash callback executed")

    def utcoffset(self, _value: datetime | None) -> timedelta | None:
        raise AssertionError("untrusted timezone callback executed")

    def dst(self, _value: datetime | None) -> timedelta | None:
        raise AssertionError("untrusted timezone callback executed")

    def tzname(self, _value: datetime | None) -> str | None:
        raise AssertionError("untrusted timezone callback executed")


def test_pre_hash_rejects_custom_timezone_without_invoking_callbacks() -> None:
    with pytest.raises(AgentKernelError) as captured:
        _bound(datetime(2030, 1, 1, tzinfo=_ExplosiveTimezone()))

    assert captured.value.code is ErrorCode.VALIDATION_ERROR
