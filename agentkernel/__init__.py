"""AgentKernel public contracts.

The current package is a pre-alpha executable foundation. It does not claim A1+ enforcement,
container isolation, or universal safety.
"""

from importlib.metadata import PackageNotFoundError, version

from agentkernel.domain import (
    ActionProposal,
    CapabilityGrant,
    GoalRecord,
    PolicyBundle,
    TransactionRecord,
)

try:
    __version__ = version("agentkernel-runtime")
except PackageNotFoundError:
    __version__ = "0.1.0.dev0"

__all__ = [
    "ActionProposal",
    "CapabilityGrant",
    "GoalRecord",
    "PolicyBundle",
    "TransactionRecord",
    "__version__",
]
