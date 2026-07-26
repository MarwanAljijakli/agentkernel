"""Public contracts for AgentKernel's embedded logical API.

The available implementation is an in-process A0 boundary for trusted callers only and must not be
exposed directly to an untrusted transport. It does not itself provide OS confinement, process
separation, authentication, authorization, or A1+ enforcement. A future transport must authenticate
and authorize status, recovery, and reconciliation operations before invoking it.
"""

from agentkernel.api.contracts import (
    CreateTransactionRequest,
    DispatchReconciliationRequest,
    KernelAPI,
    RecoveryScanRequest,
    TransactionStatusQuery,
)
from agentkernel.api.service import InProcessKernelAPI

__all__ = [
    "CreateTransactionRequest",
    "DispatchReconciliationRequest",
    "InProcessKernelAPI",
    "KernelAPI",
    "RecoveryScanRequest",
    "TransactionStatusQuery",
]
