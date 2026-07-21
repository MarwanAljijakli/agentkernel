"""Least-privilege coarse capability checks for the local profile."""

from agentkernel.authority.service import (
    AuthorityDecision,
    AuthorityGrant,
    AuthorityService,
    resource_matches,
)

__all__ = ["AuthorityDecision", "AuthorityGrant", "AuthorityService", "resource_matches"]
