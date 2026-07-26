from __future__ import annotations

import asyncio
from typing import cast

import pytest
from agentkernel import (
    CreateTransactionRequest,
    DispatchReconciliationRequest,
    InProcessKernelAPI,
    KernelAPI,
    RecoveryScanRequest,
    TransactionStatusQuery,
)
from agentkernel.domain.models import ActionProposal, AuthenticatedActionContext
from agentkernel.transactions.enforced import (
    EnforcedTransactionCoordinator,
    EnforcedTransactionRequest,
)
from pydantic import BaseModel, ValidationError

_DIGEST = "sha256:" + ("0" * 64)


def _transaction_request(proposal: ActionProposal) -> EnforcedTransactionRequest:
    return EnforcedTransactionRequest(
        proposal=proposal,
        presented_context=AuthenticatedActionContext(
            tenant_id="tenant:api",
            principal_id="principal:api",
            goal_id=proposal.goal_id,
            run_id="run:api",
            trace_id="trace:api",
            actor_id="actor:api",
            on_behalf_of="principal:api",
            agent_id=proposal.agent_id,
            configuration_digest=_DIGEST,
        ),
        authentication_evidence_ref=_DIGEST,
    )


def _contract_cases(
    transaction: EnforcedTransactionRequest,
) -> tuple[tuple[type[BaseModel], dict[str, object]], ...]:
    return (
        (CreateTransactionRequest, {"transaction": transaction}),
        (
            TransactionStatusQuery,
            {"tenant_id": "tenant:api", "transaction_id": "transaction:api"},
        ),
        (RecoveryScanRequest, {"tenant_id": "tenant:api"}),
        (
            DispatchReconciliationRequest,
            {"tenant_id": "tenant:api", "transaction_id": "transaction:api"},
        ),
    )


def test_kernel_api_contracts_are_versioned_and_forbid_unknown_fields(
    proposal: ActionProposal,
) -> None:
    transaction = _transaction_request(proposal)
    for model_type, payload in _contract_cases(transaction):
        contract = model_type.model_validate(payload)
        dumped = contract.model_dump(mode="python")
        assert dumped["api_version"] == "agentkernel.io/v1alpha1"
        assert dumped["schema_version"] == "1.0"
        assert model_type.model_config["strict"] is True
        assert model_type.model_config["extra"] == "forbid"
        assert model_type.model_json_schema()["additionalProperties"] is False

        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            model_type.model_validate({**payload, "unexpected": True})
        with pytest.raises(ValidationError):
            model_type.model_validate({**payload, "api_version": "agentkernel.io/v1"})
        with pytest.raises(ValidationError):
            model_type.model_validate({**payload, "schema_version": "2.0"})


@pytest.mark.parametrize("limit", [0, -1, 1_001, True, False, "1", 1.0])
def test_recovery_scan_limit_is_strict_and_bounded(limit: object) -> None:
    with pytest.raises(ValidationError):
        RecoveryScanRequest.model_validate({"tenant_id": "tenant:api", "limit": limit})


def test_recovery_scan_accepts_only_documented_bounds() -> None:
    assert RecoveryScanRequest(tenant_id="tenant:api").limit == 100
    assert RecoveryScanRequest(tenant_id="tenant:api", limit=1).limit == 1
    assert RecoveryScanRequest(tenant_id="tenant:api", limit=1_000).limit == 1_000


def test_tenant_queries_reject_missing_or_invalid_scope() -> None:
    with pytest.raises(ValidationError):
        TransactionStatusQuery.model_validate({"transaction_id": "transaction:api"})
    with pytest.raises(ValidationError):
        DispatchReconciliationRequest(
            tenant_id="",
            transaction_id="transaction:api",
        )


class _CancellingCoordinator:
    async def transaction(self, request: EnforcedTransactionRequest) -> None:
        del request
        raise asyncio.CancelledError


@pytest.mark.asyncio
async def test_in_process_api_is_protocol_compatible_and_preserves_cancellation(
    proposal: ActionProposal,
) -> None:
    coordinator = cast("EnforcedTransactionCoordinator", _CancellingCoordinator())
    api = InProcessKernelAPI(coordinator)

    assert isinstance(api, KernelAPI)
    assert not hasattr(api, "adapter")
    with pytest.raises(asyncio.CancelledError):
        await api.transaction(CreateTransactionRequest(transaction=_transaction_request(proposal)))


def test_in_process_api_documents_trusted_caller_boundary() -> None:
    protocol_doc = " ".join((KernelAPI.__doc__ or "").split())
    service_doc = " ".join((InProcessKernelAPI.__doc__ or "").split())

    assert "must not be exposed directly to an untrusted transport" in protocol_doc
    assert "tenant identifiers are routing scope, not access-control proof" in protocol_doc
    assert "must not be exposed directly to an untrusted transport" in service_doc
    assert (
        "authenticate callers and authorize status, recovery, and reconciliation operations"
        in service_doc
    )
    assert "tenant identifiers alone are not access-control proof" in service_doc
