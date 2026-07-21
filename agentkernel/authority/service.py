"""Deterministic coarse grants; information never becomes authority."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from pydantic import AwareDatetime

from agentkernel.domain.enums import ProvenanceTrust
from agentkernel.domain.models import Identifier, NonEmptyStr, StrictModel
from agentkernel.errors import AgentKernelError, ErrorCode


class AuthorityVerdict(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class AuthorityGrant(StrictModel):
    capability_id: Identifier
    subject: Identifier
    goal_id: Identifier
    run_id: Identifier
    actions: tuple[NonEmptyStr, ...]
    resources: tuple[NonEmptyStr, ...]
    not_before: AwareDatetime
    expires_at: AwareDatetime
    max_uses: int = 100


class AuthorityDecision(StrictModel):
    verdict: AuthorityVerdict
    reason_code: NonEmptyStr
    matched_capability: Identifier | None = None
    provenance: tuple[ProvenanceTrust, ...] = ()
    authority_expansion_from_untrusted: bool = False


class CapabilityUseLedger(Protocol):
    def try_consume_capability_use(self, capability_id: str, max_uses: int) -> bool: ...


def resource_matches(grant: str, requested: str) -> bool:
    """Match only exact resources or a terminal hierarchical `/**` scope."""

    if "*" not in grant:
        return grant == requested
    if not grant.endswith("/**") or grant.count("*") != 2:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Unsupported resource wildcard; only a terminal /** is allowed",
        )
    prefix = grant.removesuffix("**")
    return requested.startswith(prefix) and len(requested) > len(prefix)


class AuthorityService:
    """Check explicit grants without consulting model text or untrusted instructions."""

    def __init__(
        self,
        grants: tuple[AuthorityGrant, ...],
        *,
        clock: Callable[[], datetime],
        use_ledger: CapabilityUseLedger | None = None,
    ) -> None:
        self._grants = grants
        self._clock = clock
        self._uses: dict[str, int] = {}
        self._use_ledger = use_ledger

    @property
    def durable_use_tracking(self) -> bool:
        return self._use_ledger is not None

    def check(
        self,
        *,
        subject: str,
        goal_id: str,
        run_id: str,
        action: str,
        resource: str,
        provenance: tuple[ProvenanceTrust, ...] = (),
    ) -> AuthorityDecision:
        now = self._clock()
        identity_candidates = tuple(
            grant
            for grant in self._grants
            if grant.subject == subject and grant.goal_id == goal_id and grant.run_id == run_id
        )
        budget_exhausted = False
        for grant in identity_candidates:
            if not (grant.not_before <= now < grant.expires_at):
                continue
            if action not in grant.actions:
                continue
            if not any(resource_matches(scope, resource) for scope in grant.resources):
                continue
            if self._use_ledger is not None:
                consumed = self._use_ledger.try_consume_capability_use(
                    grant.capability_id,
                    grant.max_uses,
                )
            else:
                uses = self._uses.get(grant.capability_id, 0)
                consumed = uses < grant.max_uses
                if consumed:
                    self._uses[grant.capability_id] = uses + 1
            if not consumed:
                budget_exhausted = True
                continue
            return AuthorityDecision(
                verdict=AuthorityVerdict.ALLOW,
                reason_code="AUTHORITY_GRANTED",
                matched_capability=grant.capability_id,
                provenance=provenance,
            )
        untrusted = bool(
            set(provenance)
            & {
                ProvenanceTrust.PROJECT_DATA,
                ProvenanceTrust.EXTERNAL_UNTRUSTED,
                ProvenanceTrust.MODEL_GENERATED,
                ProvenanceTrust.UNKNOWN,
            }
        )
        return AuthorityDecision(
            verdict=AuthorityVerdict.DENY,
            reason_code=(
                ErrorCode.AUTHORITY_EXPIRED.value
                if budget_exhausted
                else ErrorCode.AUTHORITY_MISSING.value
            ),
            provenance=provenance,
            authority_expansion_from_untrusted=untrusted,
        )
