"""Versioned enumerations used by the trusted core."""

from enum import StrEnum


class RiskClass(StrEnum):
    READ_ONLY = "R0"
    REVERSIBLE = "R1"
    COMPENSATABLE = "R2"
    IRREVERSIBLE = "R3"
    FORBIDDEN = "R4"


class ResourceAccessMode(StrEnum):
    """The primitive access requested for one canonical resource."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    CONNECT = "connect"


class ResourceUseKind(StrEnum):
    """Why an action needs a resource, independent of the access mode."""

    AUTHORITATIVE_EFFECT = "authoritative_effect"
    PRECONDITION_READ = "precondition_read"
    VERIFIER_READ = "verifier_read"
    PROCESS_EXECUTION = "process_execution"
    EGRESS = "egress"


class VerificationStatus(StrEnum):
    PASS = "PASS"  # nosec B105
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class ProvenanceTrust(StrEnum):
    TRUSTED_CONTROL = "trusted_control"
    AUTHORIZED_USER = "authorized_user"
    PROJECT_DATA = "project_data"
    EXTERNAL_UNTRUSTED = "external_untrusted"
    MODEL_GENERATED = "model_generated"
    UNKNOWN = "unknown"


class ReplayLevel(StrEnum):
    INSPECT = "L0"
    TOOL_RESULT = "L1"
    ENVIRONMENT = "L2"
    DETERMINISTIC_COMPONENT = "L3"
    COUNTERFACTUAL_FORK = "L4"


class TransactionState(StrEnum):
    """Normative durable transaction states from specification Section 8.2."""

    NEW = "NEW"
    PLANNED = "PLANNED"
    REJECTED = "REJECTED"
    AUTHORIZED_TO_STAGE = "AUTHORIZED_TO_STAGE"
    STAGING = "STAGING"
    STAGED = "STAGED"
    STAGE_VERIFIED = "STAGE_VERIFIED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    READY_TO_COMMIT = "READY_TO_COMMIT"
    COMMITTING = "COMMITTING"
    COMMITTED = "COMMITTED"
    FAILED = "FAILED"
    ABORTING = "ABORTING"
    ABORTED = "ABORTED"
    STALE_STATE = "STALE_STATE"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    COMPENSATING = "COMPENSATING"
    COMPENSATED = "COMPENSATED"
    COMPENSATION_FAILED = "COMPENSATION_FAILED"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    IN_DOUBT = "IN_DOUBT"
    RECONCILING = "RECONCILING"

    @property
    def is_terminal(self) -> bool:
        return self in TERMINAL_TRANSACTION_STATES


TERMINAL_TRANSACTION_STATES = frozenset(
    {
        TransactionState.COMMITTED,
        TransactionState.REJECTED,
        TransactionState.ABORTED,
        TransactionState.STALE_STATE,
        TransactionState.ROLLED_BACK,
        TransactionState.COMPENSATED,
        TransactionState.RECOVERY_FAILED,
        TransactionState.COMPENSATION_FAILED,
    }
)


class IntendedOutcome(StrEnum):
    ABORTED = "ABORTED"
    STALE_STATE = "STALE_STATE"


class ActionState(StrEnum):
    """Durable per-action saga states reserved by the v1alpha1 schema."""

    PENDING = "PENDING"
    STAGING = "STAGING"
    STAGED = "STAGED"
    STAGE_VERIFIED = "STAGE_VERIFIED"
    COMMIT_DISPATCHED = "COMMIT_DISPATCHED"
    COMMITTED = "COMMITTED"
    FAILED = "FAILED"
    IN_DOUBT = "IN_DOUBT"
    RECONCILING = "RECONCILING"
    NO_EFFECT = "NO_EFFECT"
    SKIPPED = "SKIPPED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    COMPENSATING = "COMPENSATING"
    COMPENSATED = "COMPENSATED"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    COMPENSATION_FAILED = "COMPENSATION_FAILED"
