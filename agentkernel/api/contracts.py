"""Strict logical contracts for the embedded AgentKernel API boundary.

These contracts describe an in-process A0 boundary for trusted callers only. They do not provide
operating-system confinement, process separation, transport authentication, authorization, or an
A1+ assurance claim, and must not be exposed directly to an untrusted transport.
"""

from __future__ import annotations

from typing import Annotated, Protocol, runtime_checkable

from pydantic import ConfigDict, Field, StrictInt

from agentkernel.domain.models import ApiVersion, Identifier, SchemaVersion, StrictModel
from agentkernel.transactions.enforced import (
    EnforcedTransactionRequest,
    EnforcedTransactionSession,
    EnforcedTransactionStatus,
    RecoveryRunResult,
)

_RecoveryLimit = Annotated[StrictInt, Field(ge=1, le=1_000)]


class _VersionedKernelContract(StrictModel):
    model_config = ConfigDict(strict=True)

    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    schema_version: SchemaVersion = "1.0"


class CreateTransactionRequest(_VersionedKernelContract):
    """Request admission through the configured enforced transaction coordinator."""

    transaction: EnforcedTransactionRequest


class TransactionStatusQuery(_VersionedKernelContract):
    """Identify a transaction in an explicit tenant partition, not an access-control grant."""

    tenant_id: Identifier
    transaction_id: Identifier


class RecoveryScanRequest(_VersionedKernelContract):
    """Request one bounded recovery scan for one explicit tenant."""

    tenant_id: Identifier
    limit: _RecoveryLimit = 100


class DispatchReconciliationRequest(_VersionedKernelContract):
    """Explicitly resume typed reconciliation for one tenant-owned dispatch."""

    tenant_id: Identifier
    transaction_id: Identifier


@runtime_checkable
class KernelAPI(Protocol):
    """Logical Kernel API surface for the embedded A0 profile.

    The in-process implementation is for trusted code only and must not be exposed directly to an
    untrusted transport. It does not itself provide OS confinement, process separation, transport
    authentication, authorization, or A1+ enforcement. A future transport must authenticate and
    authorize status, recovery, and reconciliation requests before invoking this interface;
    caller-supplied tenant identifiers are routing scope, not access-control proof.
    """

    async def transaction(
        self,
        request: CreateTransactionRequest,
    ) -> EnforcedTransactionSession | EnforcedTransactionStatus: ...

    def status(self, query: TransactionStatusQuery) -> EnforcedTransactionStatus: ...

    async def recover_once(self, request: RecoveryScanRequest) -> RecoveryRunResult: ...

    async def resume_dispatch_reconciliation(
        self,
        request: DispatchReconciliationRequest,
    ) -> EnforcedTransactionStatus: ...


__all__ = [
    "CreateTransactionRequest",
    "DispatchReconciliationRequest",
    "KernelAPI",
    "RecoveryScanRequest",
    "TransactionStatusQuery",
]
