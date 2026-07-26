"""Transaction state, persistence, and coordination primitives."""

from importlib import import_module
from typing import TYPE_CHECKING, Any

from agentkernel.domain.models import (
    CommitPermit,
    InspectionPermit,
    RecoveryPermit,
    StagePermit,
    VerificationPermit,
)
from agentkernel.transactions.contracts import (
    AuthorizationRoundRecord,
    CommitDispatchRecord,
    DispatchEvidenceUnavailableRecord,
    DispatchOutcomeRecord,
    EnforcedTransactionEvent,
    EnforcedTransactionRecord,
    LateRecoveryReportRecord,
    ReconciliationAttemptRecord,
    RecoveryCompletionReportRecord,
    RecoveryEvidenceUnavailableRecord,
    RecoveryWorkRecord,
    StageMaterialRecord,
    TransactionRecoveryDeadlineRecord,
    WorkerLeaseRecord,
)
from agentkernel.transactions.state_machine import (
    NORMATIVE_TRANSITIONS,
    TransitionDecision,
    TransitionEvent,
    apply_transition,
)

if TYPE_CHECKING:
    from agentkernel.transactions.enforced import (
        ArtifactStore,
        AuthenticatedContextValidator,
        AuthoritySnapshotProvider,
        CoordinatorCrashPoint,
        CoordinatorInjectedCrash,
        EnforcedCoordinatorConfig,
        EnforcedSessionReceipts,
        EnforcedTransactionCoordinator,
        EnforcedTransactionRequest,
        EnforcedTransactionSession,
        EnforcedTransactionStatus,
        PolicyEvaluationInputs,
        PolicyInputProvider,
        RecoveryActionFactory,
        RecoveryCandidateFailure,
        RecoveryFailureKind,
        RecoveryRunResult,
        ValidatedAuthenticatedContext,
    )

_LAZY_ENFORCED_EXPORTS = frozenset(
    {
        "ArtifactStore",
        "AuthenticatedContextValidator",
        "AuthoritySnapshotProvider",
        "CoordinatorCrashPoint",
        "CoordinatorInjectedCrash",
        "EnforcedCoordinatorConfig",
        "EnforcedSessionReceipts",
        "EnforcedTransactionCoordinator",
        "EnforcedTransactionRequest",
        "EnforcedTransactionSession",
        "EnforcedTransactionStatus",
        "PolicyEvaluationInputs",
        "PolicyInputProvider",
        "RecoveryActionFactory",
        "RecoveryCandidateFailure",
        "RecoveryFailureKind",
        "RecoveryRunResult",
        "ValidatedAuthenticatedContext",
    }
)


def __getattr__(name: str) -> Any:
    if name not in _LAZY_ENFORCED_EXPORTS:
        raise AttributeError(name)
    return getattr(import_module("agentkernel.transactions.enforced"), name)


__all__ = [
    "NORMATIVE_TRANSITIONS",
    "ArtifactStore",
    "AuthenticatedContextValidator",
    "AuthoritySnapshotProvider",
    "AuthorizationRoundRecord",
    "CommitDispatchRecord",
    "CommitPermit",
    "CoordinatorCrashPoint",
    "CoordinatorInjectedCrash",
    "DispatchEvidenceUnavailableRecord",
    "DispatchOutcomeRecord",
    "EnforcedCoordinatorConfig",
    "EnforcedSessionReceipts",
    "EnforcedTransactionCoordinator",
    "EnforcedTransactionEvent",
    "EnforcedTransactionRecord",
    "EnforcedTransactionRequest",
    "EnforcedTransactionSession",
    "EnforcedTransactionStatus",
    "InspectionPermit",
    "LateRecoveryReportRecord",
    "PolicyEvaluationInputs",
    "PolicyInputProvider",
    "ReconciliationAttemptRecord",
    "RecoveryActionFactory",
    "RecoveryCandidateFailure",
    "RecoveryCompletionReportRecord",
    "RecoveryEvidenceUnavailableRecord",
    "RecoveryFailureKind",
    "RecoveryPermit",
    "RecoveryRunResult",
    "RecoveryWorkRecord",
    "StageMaterialRecord",
    "StagePermit",
    "TransactionRecoveryDeadlineRecord",
    "TransitionDecision",
    "TransitionEvent",
    "ValidatedAuthenticatedContext",
    "VerificationPermit",
    "WorkerLeaseRecord",
    "apply_transition",
]
