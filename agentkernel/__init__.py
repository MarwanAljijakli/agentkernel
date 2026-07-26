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


def __getattr__(name: str) -> Any:
    if name not in _LAZY_ENFORCED_EXPORTS:
        raise AttributeError(name)
    return getattr(import_module("agentkernel.transactions.enforced"), name)


try:
    __version__ = version("agentkernel-runtime")
except PackageNotFoundError:
    __version__ = "0.1.0.dev0"

__all__ = [
    "ActionProposal",
    "CapabilityGrant",
    "CoordinatorCrashPoint",
    "DispatchEvidenceUnavailableRecord",
    "EnforcedCoordinatorConfig",
    "EnforcedTransactionCoordinator",
    "EnforcedTransactionRequest",
    "EnforcedTransactionStatus",
    "GoalRecord",
    "PolicyBundle",
    "RecoveryEvidenceUnavailableRecord",
    "RecoveryFailureKind",
    "RecoveryRunResult",
    "TransactionRecord",
    "ValidatedAuthenticatedContext",
    "__version__",
]
