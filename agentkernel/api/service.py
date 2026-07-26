"""In-process A0 Kernel API implementation for trusted callers.

This module does not provide OS confinement, authentication, authorization, or a safe untrusted
transport boundary.
"""

from __future__ import annotations

from agentkernel.api.contracts import (
    CreateTransactionRequest,
    DispatchReconciliationRequest,
    RecoveryScanRequest,
    TransactionStatusQuery,
)
from agentkernel.transactions.enforced import (
    EnforcedTransactionCoordinator,
    EnforcedTransactionSession,
    EnforcedTransactionStatus,
    RecoveryRunResult,
)


class InProcessKernelAPI:
    """Delegate embedded A0 commands to one enforced coordinator.

    This logical in-process boundary is for trusted callers and must not be exposed directly to an
    untrusted transport. It does not itself authenticate or authorize callers, isolate a process,
    confine operating-system access, or establish A1+ assurance. A future transport must
    authenticate callers and authorize status, recovery, and reconciliation operations; tenant
    identifiers alone are not access-control proof. This implementation deliberately adds no
    fallback, retry, local composition, or adapter access.
    """

    __slots__ = ("_coordinator",)

    def __init__(self, coordinator: EnforcedTransactionCoordinator) -> None:
        self._coordinator = coordinator

    async def transaction(
        self,
        request: CreateTransactionRequest,
    ) -> EnforcedTransactionSession | EnforcedTransactionStatus:
        """Delegate admission without changing cancellation or idempotency behavior."""

        return await self._coordinator.transaction(request.transaction)

    def status(self, query: TransactionStatusQuery) -> EnforcedTransactionStatus:
        """Read a status using the caller's explicit tenant and transaction identity."""

        return self._coordinator.status(query.tenant_id, query.transaction_id)

    async def recover_once(self, request: RecoveryScanRequest) -> RecoveryRunResult:
        """Run one bounded tenant recovery pass without hidden retries."""

        return await self._coordinator.recover_once(request.tenant_id, limit=request.limit)

    async def resume_dispatch_reconciliation(
        self,
        request: DispatchReconciliationRequest,
    ) -> EnforcedTransactionStatus:
        """Resume only the explicitly identified typed dispatch reconciliation."""

        return await self._coordinator.resume_dispatch_reconciliation(
            request.tenant_id,
            request.transaction_id,
        )


__all__ = ["InProcessKernelAPI"]
