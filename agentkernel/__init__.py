"""AgentKernel public contracts.

The current package is a pre-alpha executable foundation. It does not claim A1+ enforcement,
container isolation, or universal safety.
"""

from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from agentkernel.domain import (
    ActionProposal,
    CapabilityGrant,
    GoalRecord,
    PolicyBundle,
    TransactionRecord,
)
from agentkernel.transactions.contracts import (
    DispatchEvidenceUnavailableRecord,
    RecoveryEvidenceUnavailableRecord,
)

_LAZY_ENFORCED_EXPORTS = frozenset(
    {
        "CoordinatorCrashPoint",
        "EnforcedCoordinatorConfig",
        "EnforcedTransactionCoordinator",
        "EnforcedTransactionRequest",
        "EnforcedTransactionStatus",
        "RecoveryFailureKind",
        "RecoveryRunResult",
        "ValidatedAuthenticatedContext",
    }
)
_LAZY_API_EXPORTS = frozenset(
    {
        "CreateTransactionRequest",
        "DispatchReconciliationRequest",
        "InProcessKernelAPI",
        "KernelAPI",
        "RecoveryScanRequest",
        "TransactionStatusQuery",
    }
)


def __getattr__(name: str) -> Any:
    if name in _LAZY_ENFORCED_EXPORTS:
        return getattr(import_module("agentkernel.transactions.enforced"), name)
    if name in _LAZY_API_EXPORTS:
        return getattr(import_module("agentkernel.api"), name)
    raise AttributeError(name)


try:
    __version__ = version("agentkernel-runtime")
except PackageNotFoundError:
    __version__ = "0.1.0.dev0"

__all__ = [
    "ActionProposal",
    "CapabilityGrant",
    "CoordinatorCrashPoint",
    "CreateTransactionRequest",
    "DispatchEvidenceUnavailableRecord",
    "DispatchReconciliationRequest",
    "EnforcedCoordinatorConfig",
    "EnforcedTransactionCoordinator",
    "EnforcedTransactionRequest",
    "EnforcedTransactionStatus",
    "GoalRecord",
    "InProcessKernelAPI",
    "KernelAPI",
    "PolicyBundle",
    "RecoveryEvidenceUnavailableRecord",
    "RecoveryFailureKind",
    "RecoveryRunResult",
    "RecoveryScanRequest",
    "TransactionRecord",
    "TransactionStatusQuery",
    "ValidatedAuthenticatedContext",
    "__version__",
]
