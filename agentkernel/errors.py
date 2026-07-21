"""Stable, machine-readable failures exposed by AgentKernel."""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """Public error codes; serialized values are part of the compatibility contract."""

    VALIDATION_ERROR = "VALIDATION_ERROR"
    UNKNOWN_ADAPTER = "UNKNOWN_ADAPTER"
    UNSUPPORTED_SEMANTICS = "UNSUPPORTED_SEMANTICS"
    AUTHORITY_MISSING = "AUTHORITY_MISSING"
    AUTHORITY_EXPIRED = "AUTHORITY_EXPIRED"
    AUTHORITY_REVOKED = "AUTHORITY_REVOKED"
    POLICY_DENIED = "POLICY_DENIED"
    POLICY_UNKNOWN = "POLICY_UNKNOWN"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    STALE_STATE = "STALE_STATE"
    PRECONDITION_FAILED = "PRECONDITION_FAILED"
    SANDBOX_FAILED = "SANDBOX_FAILED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    VERIFICATION_UNKNOWN = "VERIFICATION_UNKNOWN"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    COMPENSATION_FAILED = "COMPENSATION_FAILED"
    EXTERNAL_RESULT_IN_DOUBT = "EXTERNAL_RESULT_IN_DOUBT"
    EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    ILLEGAL_TRANSITION = "ILLEGAL_TRANSITION"
    VERSION_CONFLICT = "VERSION_CONFLICT"
    INTEGRITY_ERROR = "INTEGRITY_ERROR"


class AgentKernelError(Exception):
    """Base exception with a stable code and non-sensitive structured details."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        retryable: bool = False,
        reconcilable: bool = False,
        review_required: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}
        self.retryable = retryable
        self.reconcilable = reconcilable
        self.review_required = review_required

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-ready representation that intentionally omits tracebacks."""

        return {
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
            "retryable": self.retryable,
            "reconcilable": self.reconcilable,
            "review_required": self.review_required,
        }


class UnsupportedSemantics(AgentKernelError):
    """Raised when an adapter truthfully lacks a requested lifecycle method."""

    def __init__(self, semantic: str) -> None:
        super().__init__(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            f"Adapter does not support {semantic}",
            details={"semantic": semantic},
        )
