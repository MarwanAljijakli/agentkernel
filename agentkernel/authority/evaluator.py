"""Pure, deterministic authority evaluation for the enforced control-plane profile.

This module deliberately performs no I/O and never consumes capability budgets.  It
evaluates a content-digested authority snapshot and emits a content-digested reservation
plan that a durable store can reserve atomically immediately before dispatch.  Signature
verification and key custody are snapshot-admission concerns and are intentionally not
claimed here.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from itertools import pairwise
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    AwareDatetime,
    Field,
    StringConstraints,
    TypeAdapter,
    field_validator,
    model_validator,
)

from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import ResourceAccessMode, ResourceUseKind, RiskClass
from agentkernel.domain.models import (
    MAX_RESOURCE_DATA_CLASSES,
    CanonicalResource,
    Digest,
    Identifier,
    NonEmptyStr,
    NormalizedAction,
    ResourceUse,
    StrictModel,
)

_MAX_CAPABILITIES = 4096
_MAX_SCOPE_ITEMS = 4096
_MAX_RESERVATION_CAPABILITIES = 256
_MAX_PROVENANCE_BINDINGS = 256
_MAX_AUTHORITY_WORK_UNITS = 4096
_MAX_DELEGATION_DEPTH = 64
_MAX_DELEGATION_CHAIN_NODES = _MAX_DELEGATION_DEPTH + 1
_MAX_CAPABILITY_MATERIAL_UNITS = 8_192
_MAX_AUTHORITY_SNAPSHOT_MATERIAL_UNITS = 16_384
_MAX_AUTHORITY_MATERIAL_BYTES = 4 * 1024 * 1024
_SENSITIVE_DATA_CLASSES = frozenset({"credential", "credentials", "secret", "secrets"})
_CANONICAL_RESOURCE_ADAPTER = TypeAdapter(CanonicalResource)


def _raw_field(value: object, field_name: str) -> object:
    if isinstance(value, Mapping):
        return value.get(field_name)
    return getattr(value, field_name, None)


def _raw_collection(value: object, field_name: str) -> Collection[object]:
    candidate = _raw_field(value, field_name)
    if isinstance(candidate, Collection) and not isinstance(
        candidate,
        (str, bytes, bytearray),
    ):
        return candidate
    return ()


def _bounded_text_bytes(
    collections: tuple[Collection[object], ...],
    *,
    max_bytes: int,
    subject: str,
) -> None:
    total = 0
    for values in collections:
        for value in values:
            if not isinstance(value, str):
                continue
            try:
                total += len(value.encode("utf-8", errors="strict"))
            except UnicodeEncodeError as error:
                raise ValueError(f"{subject} contains invalid UTF-8 text") from error
            if total > max_bytes:
                raise ValueError(f"{subject} exceeds its aggregate text-byte limit")


def _validate_grant_raw_bounds(value: object) -> None:
    collections = tuple(
        _raw_collection(value, field_name)
        for field_name in ("actions", "resource_scopes", "data_classes")
    )
    if any(len(items) > _MAX_SCOPE_ITEMS for items in collections):
        raise ValueError("Capability scope collection exceeds its item limit")
    if sum(len(items) for items in collections) > _MAX_CAPABILITY_MATERIAL_UNITS:
        raise ValueError("Capability exceeds its aggregate material-unit limit")
    _bounded_text_bytes(
        collections,
        max_bytes=_MAX_AUTHORITY_MATERIAL_BYTES,
        subject="Capability",
    )


def _validate_snapshot_raw_bounds(value: object) -> None:
    capabilities = _raw_collection(value, "capabilities")
    key_versions = _raw_collection(value, "accepted_key_versions")
    budgets = _raw_collection(value, "budget_states")
    revocations = _raw_collection(value, "revocations")
    top_level = (capabilities, key_versions, budgets, revocations)
    if any(len(items) > _MAX_CAPABILITIES for items in top_level):
        raise ValueError("Authority snapshot collection exceeds its item limit")

    material_units = sum(len(items) for items in top_level)
    text_collections: list[Collection[object]] = []
    for capability in capabilities:
        grant_collections = tuple(
            _raw_collection(capability, field_name)
            for field_name in ("actions", "resource_scopes", "data_classes")
        )
        if any(len(items) > _MAX_SCOPE_ITEMS for items in grant_collections):
            raise ValueError("Authority snapshot capability exceeds its item limit")
        material_units += sum(len(items) for items in grant_collections)
        if material_units > _MAX_AUTHORITY_SNAPSHOT_MATERIAL_UNITS:
            raise ValueError("Authority snapshot exceeds its aggregate material-unit limit")
        text_collections.extend(grant_collections)
    for budget in budgets:
        reserved_intents = _raw_collection(budget, "reserved_intent_hashes")
        material_units += len(reserved_intents)
        if material_units > _MAX_AUTHORITY_SNAPSHOT_MATERIAL_UNITS:
            raise ValueError("Authority snapshot exceeds its aggregate material-unit limit")
        text_collections.append(reserved_intents)
    text_collections.append(
        tuple(
            reason
            for revocation in revocations
            if isinstance((reason := _raw_field(revocation, "reason")), str)
        )
    )
    _bounded_text_bytes(
        tuple(text_collections),
        max_bytes=_MAX_AUTHORITY_MATERIAL_BYTES,
        subject="Authority snapshot",
    )


def _resource_has_hierarchical_alias(value: str, *, allow_terminal_wildcard: bool) -> bool:
    """Reject URI spellings whose string hierarchy can disagree with an adapter."""

    parsed = urlsplit(value)
    if "@" in parsed.netloc or parsed.netloc != parsed.netloc.lower():
        return True
    path = parsed.path
    if "%2F" in path or "%5C" in path:
        return True
    segments = path.split("/")
    if any(segment in {".", ".."} for segment in segments):
        return True
    if "//" in path:
        return True
    if "*" not in value:
        return False
    return not (
        allow_terminal_wildcard
        and value.endswith("/**")
        and value.count("*") == 2
        and "*" not in value.removesuffix("/**")
    )


def _validate_resource_scope(value: str) -> str:
    terminal_wildcard = value.endswith("/**") and value.count("*") == 2
    if "*" in value and not terminal_wildcard:
        raise ValueError("Capability resource scope uses an unsupported wildcard")
    canonical_base = value.removesuffix("/**") if terminal_wildcard else value
    parsed_base = urlsplit(canonical_base)
    validation_base = (
        f"{canonical_base}/"
        if terminal_wildcard and parsed_base.scheme != "fs" and not parsed_base.path
        else canonical_base
    )
    _CANONICAL_RESOURCE_ADAPTER.validate_python(validation_base)
    if _resource_has_hierarchical_alias(value, allow_terminal_wildcard=True):
        raise ValueError("Capability resource scope is not canonical or uses an unsafe wildcard")
    return value


CapabilityResourceScope = Annotated[
    str,
    StringConstraints(min_length=1, max_length=8192),
    AfterValidator(_validate_resource_scope),
]


def resource_scope_matches(scope: str, requested: str) -> bool:
    """Match one concrete canonical resource against exact or terminal ``/**`` scope."""

    try:
        _validate_resource_scope(scope)
        _CANONICAL_RESOURCE_ADAPTER.validate_python(requested)
    except ValueError:
        return False
    if "*" in requested or _resource_has_hierarchical_alias(
        requested,
        allow_terminal_wildcard=False,
    ):
        return False
    if not scope.endswith("/**"):
        return scope == requested
    base = scope.removesuffix("/**")
    descendant_prefix = f"{base}/"
    return requested.startswith(descendant_prefix) and len(requested) > len(descendant_prefix)


def _resource_scope_is_subset(child: str, parent: str) -> bool:
    if not child.endswith("/**"):
        return resource_scope_matches(parent, child)
    if not parent.endswith("/**"):
        return False
    child_base = child.removesuffix("/**")
    parent_base = parent.removesuffix("/**")
    return child_base == parent_base or child_base.startswith(f"{parent_base}/")


def resource_scope_contains(scope: str, requested: str) -> bool:
    """Return whether one canonical capability/policy scope contains a resource or sub-scope."""

    try:
        _validate_resource_scope(scope)
        _validate_resource_scope(requested)
    except ValueError:
        return False
    return _resource_scope_is_subset(requested, scope)


def _require_sorted_unique(
    values: tuple[str, ...],
    *,
    field_name: str,
    allow_wildcard: bool = False,
) -> tuple[str, ...]:
    if any(unicodedata.normalize("NFC", value) != value for value in values):
        raise ValueError(f"{field_name} must contain only Unicode NFC strings")
    if len(set(values)) != len(values) or values != tuple(sorted(values)):
        raise ValueError(f"{field_name} must be sorted and unique")
    if not allow_wildcard and any("*" in value for value in values):
        raise ValueError(f"{field_name} does not support wildcards")
    return values


def _effective_data_classes(
    action: NormalizedAction,
    resource_use: ResourceUse,
) -> tuple[str, ...]:
    """Conservatively inherit every label from provenance bound to this resource use."""

    provenance_by_id = {value.provenance_id: value for value in action.provenance}
    inherited = {
        data_class
        for provenance_id in resource_use.provenance_ids
        for data_class in provenance_by_id[provenance_id].data_classes
    }
    return tuple(sorted(set(resource_use.data_classes) | inherited))


class AuthorityEvaluationVerdict(StrEnum):
    """Fail-closed result of the enforced authority evaluator."""

    ALLOW = "ALLOW"
    DENY = "DENY"


class AuthorityReasonCode(StrEnum):
    """Stable, evidence-safe reasons emitted by the pure evaluator."""

    AUTHORITY_GRANTED = "AUTHORITY_GRANTED"
    AUTHORITY_MISSING = "AUTHORITY_MISSING"
    ACTION_CONTEXT_MISMATCH = "ACTION_CONTEXT_MISMATCH"
    SNAPSHOT_MISMATCH = "SNAPSHOT_MISMATCH"
    SNAPSHOT_FROM_FUTURE = "SNAPSHOT_FROM_FUTURE"
    SNAPSHOT_STALE = "SNAPSHOT_STALE"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
    AUDIENCE_MISMATCH = "AUDIENCE_MISMATCH"
    GOAL_MISMATCH = "GOAL_MISMATCH"
    RUN_MISMATCH = "RUN_MISMATCH"
    ROOT_ISSUER_MISMATCH = "ROOT_ISSUER_MISMATCH"
    UNKNOWN_KEY = "UNKNOWN_KEY"
    UNSUPPORTED_TOKEN_VERSION = "UNSUPPORTED_TOKEN_VERSION"  # noqa: S105  # nosec B105
    CAPABILITY_NOT_YET_VALID = "CAPABILITY_NOT_YET_VALID"
    CAPABILITY_EXPIRED = "CAPABILITY_EXPIRED"
    CAPABILITY_REVOKED = "CAPABILITY_REVOKED"
    CAPABILITY_BUDGET_STATE_MISSING = "CAPABILITY_BUDGET_STATE_MISSING"
    CAPABILITY_BUDGET_STATE_MISMATCH = "CAPABILITY_BUDGET_STATE_MISMATCH"
    CAPABILITY_BUDGET_EXHAUSTED = "CAPABILITY_BUDGET_EXHAUSTED"
    CAPABILITY_RESERVATION_PLAN_TOO_LARGE = "CAPABILITY_RESERVATION_PLAN_TOO_LARGE"
    AUTHORITY_COMPLEXITY_LIMIT = "AUTHORITY_COMPLEXITY_LIMIT"
    DELEGATION_PARENT_MISSING = "DELEGATION_PARENT_MISSING"
    DELEGATION_CYCLE = "DELEGATION_CYCLE"
    DELEGATION_CHAIN_TOO_DEEP = "DELEGATION_CHAIN_TOO_DEEP"
    DELEGATION_ISSUER_MISMATCH = "DELEGATION_ISSUER_MISMATCH"
    DELEGATION_ACTION_WIDENED = "DELEGATION_ACTION_WIDENED"
    DELEGATION_RESOURCE_WIDENED = "DELEGATION_RESOURCE_WIDENED"
    DELEGATION_DATA_CLASS_WIDENED = "DELEGATION_DATA_CLASS_WIDENED"
    DELEGATION_TIME_WIDENED = "DELEGATION_TIME_WIDENED"
    DELEGATION_DEPTH_INVALID = "DELEGATION_DEPTH_INVALID"
    DELEGATION_BUDGET_WIDENED = "DELEGATION_BUDGET_WIDENED"
    ACTION_NOT_GRANTED = "ACTION_NOT_GRANTED"
    RESOURCE_NOT_GRANTED = "RESOURCE_NOT_GRANTED"
    RESOURCE_ALIAS_REJECTED = "RESOURCE_ALIAS_REJECTED"
    DATA_CLASS_NOT_GRANTED = "DATA_CLASS_NOT_GRANTED"
    WILDCARD_SCOPE_FORBIDDEN = "WILDCARD_SCOPE_FORBIDDEN"
    FORBIDDEN_RISK_CLASS = "FORBIDDEN_RISK_CLASS"
    PARTIAL_RESOURCE_DENIAL = "PARTIAL_RESOURCE_DENIAL"
    MULTIPLE_RESOURCE_DENIALS = "MULTIPLE_RESOURCE_DENIALS"


_AGGREGATE_ONLY_REASONS = frozenset(
    {
        AuthorityReasonCode.PARTIAL_RESOURCE_DENIAL,
        AuthorityReasonCode.MULTIPLE_RESOURCE_DENIALS,
    }
)
_GLOBAL_DENIAL_REASONS = frozenset(
    {
        AuthorityReasonCode.ACTION_CONTEXT_MISMATCH,
        AuthorityReasonCode.SNAPSHOT_MISMATCH,
        AuthorityReasonCode.SNAPSHOT_FROM_FUTURE,
        AuthorityReasonCode.SNAPSHOT_STALE,
        AuthorityReasonCode.TENANT_MISMATCH,
        AuthorityReasonCode.FORBIDDEN_RISK_CLASS,
        AuthorityReasonCode.AUTHORITY_COMPLEXITY_LIMIT,
        AuthorityReasonCode.CAPABILITY_RESERVATION_PLAN_TOO_LARGE,
    }
)


class CapabilityKeyVersion(StrictModel):
    """One key/version pair already admitted for capability validation."""

    tenant_id: Identifier
    key_id: Identifier
    token_version: Annotated[int, Field(ge=1)]

    def sort_key(self) -> tuple[str, int]:
        return (self.key_id, self.token_version)


class CapabilityBudgetState(StrictModel):
    """Read-only budget facts captured by the durable authority snapshot."""

    tenant_id: Identifier
    capability_id: Identifier
    goal_id: Identifier
    run_id: Identifier
    max_uses: Annotated[int, Field(ge=1)]
    consumed_uses: Annotated[int, Field(ge=0)] = 0
    reserved_uses: Annotated[int, Field(ge=0)] = 0
    reserved_intent_hashes: Annotated[
        tuple[Digest, ...],
        Field(max_length=_MAX_SCOPE_ITEMS),
    ] = ()

    @model_validator(mode="after")
    def _reservation_owners_match_reserved_count(self) -> Self:
        if self.reserved_intent_hashes != tuple(sorted(set(self.reserved_intent_hashes))):
            raise ValueError("Reserved capability intent hashes must be sorted and unique")
        if len(self.reserved_intent_hashes) != self.reserved_uses:
            raise ValueError("Reserved capability count must match its intent-owner evidence")
        if self.consumed_uses + self.reserved_uses > self.max_uses:
            raise ValueError("Capability budget counters exceed max_uses")
        return self


class CapabilityRevocation(StrictModel):
    """A durable revocation by capability ID, nonce, or both."""

    revocation_id: Identifier
    tenant_id: Identifier
    effective_at: AwareDatetime
    reason: NonEmptyStr
    capability_id: Identifier | None = None
    nonce: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _has_target(self) -> Self:
        if self.capability_id is None and self.nonce is None:
            raise ValueError("A revocation must target a capability ID, nonce, or both")
        return self

    @field_validator("nonce", "reason")
    @classmethod
    def _canonical_text(cls, value: str | None) -> str | None:
        if value is not None and unicodedata.normalize("NFC", value) != value:
            raise ValueError("Revocation text must use Unicode NFC")
        return value


def _grant_payload(grant: EnforcedCapabilityGrant) -> dict[str, object]:
    return grant.model_dump(mode="python", exclude={"grant_digest"})


class EnforcedCapabilityGrant(StrictModel):
    """A content-bound capability record admitted to the enforced authority snapshot."""

    tenant_id: Identifier
    capability_id: Identifier
    token_version: Annotated[int, Field(ge=1)]
    key_id: Identifier
    issuer: Identifier
    subject: Identifier
    audience: Identifier
    goal_id: Identifier
    run_id: Identifier
    actions: Annotated[tuple[NonEmptyStr, ...], Field(min_length=1, max_length=_MAX_SCOPE_ITEMS)]
    resource_scopes: Annotated[
        tuple[CapabilityResourceScope, ...],
        Field(min_length=1, max_length=_MAX_SCOPE_ITEMS),
    ]
    data_classes: Annotated[tuple[NonEmptyStr, ...], Field(max_length=_MAX_SCOPE_ITEMS)] = ()
    issued_at: AwareDatetime
    not_before: AwareDatetime
    expires_at: AwareDatetime
    max_uses: Annotated[int, Field(ge=1)]
    delegation_depth_remaining: Annotated[int, Field(ge=0, le=_MAX_DELEGATION_DEPTH)] = 0
    parent_capability: Identifier | None = None
    nonce: NonEmptyStr
    grant_digest: Digest

    @model_validator(mode="before")
    @classmethod
    def _bounded_raw_material(cls, value: object) -> object:
        _validate_grant_raw_bounds(value)
        return value

    @field_validator("actions", "data_classes")
    @classmethod
    def _canonical_exact_scopes(cls, values: tuple[str, ...], info: object) -> tuple[str, ...]:
        return _require_sorted_unique(
            values,
            field_name=str(getattr(info, "field_name", "scope")),
        )

    @field_validator("resource_scopes")
    @classmethod
    def _canonical_resource_scopes(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _require_sorted_unique(
            values,
            field_name="resource_scopes",
            allow_wildcard=True,
        )

    @field_validator("nonce")
    @classmethod
    def _canonical_nonce(cls, value: str) -> str:
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError("Capability nonce must use Unicode NFC")
        return value

    @model_validator(mode="after")
    def _valid_window_and_digest(self) -> Self:
        if not self.issued_at <= self.not_before < self.expires_at:
            raise ValueError(
                "Capability timestamps must satisfy issued_at <= not_before < expires_at"
            )
        if self.grant_digest != canonical_digest(_grant_payload(self)):
            raise ValueError("Capability grant has a mismatched grant_digest")
        return self

    @classmethod
    def create(
        cls,
        *,
        tenant_id: Identifier,
        capability_id: Identifier,
        token_version: int,
        key_id: Identifier,
        issuer: Identifier,
        subject: Identifier,
        audience: Identifier,
        goal_id: Identifier,
        run_id: Identifier,
        actions: tuple[NonEmptyStr, ...],
        resource_scopes: tuple[CapabilityResourceScope, ...],
        data_classes: tuple[NonEmptyStr, ...],
        issued_at: datetime,
        not_before: datetime,
        expires_at: datetime,
        max_uses: int,
        delegation_depth_remaining: int = 0,
        parent_capability: Identifier | None = None,
        nonce: NonEmptyStr,
    ) -> Self:
        _validate_grant_raw_bounds(
            {
                "actions": actions,
                "resource_scopes": resource_scopes,
                "data_classes": data_classes,
            }
        )
        payload: dict[str, object] = {
            "tenant_id": tenant_id,
            "capability_id": capability_id,
            "token_version": token_version,
            "key_id": key_id,
            "issuer": issuer,
            "subject": subject,
            "audience": audience,
            "goal_id": goal_id,
            "run_id": run_id,
            "actions": tuple(sorted(actions)),
            "resource_scopes": tuple(sorted(resource_scopes)),
            "data_classes": tuple(sorted(data_classes)),
            "issued_at": issued_at,
            "not_before": not_before,
            "expires_at": expires_at,
            "max_uses": max_uses,
            "delegation_depth_remaining": delegation_depth_remaining,
            "parent_capability": parent_capability,
            "nonce": nonce,
        }
        return cls.model_validate({**payload, "grant_digest": canonical_digest(payload)})


def _snapshot_payload(snapshot: AuthoritySnapshot) -> dict[str, object]:
    return snapshot.model_dump(mode="python", exclude={"snapshot_digest"})


class AuthoritySnapshot(StrictModel):
    """Immutable durable facts used for one reproducible authority decision."""

    tenant_id: Identifier
    snapshot_id: Identifier
    revision: Annotated[int, Field(ge=1)]
    as_of: AwareDatetime
    capabilities: Annotated[
        tuple[EnforcedCapabilityGrant, ...],
        Field(max_length=_MAX_CAPABILITIES),
    ] = ()
    accepted_key_versions: Annotated[
        tuple[CapabilityKeyVersion, ...],
        Field(max_length=_MAX_CAPABILITIES),
    ] = ()
    budget_states: Annotated[
        tuple[CapabilityBudgetState, ...],
        Field(max_length=_MAX_CAPABILITIES),
    ] = ()
    revocations: Annotated[
        tuple[CapabilityRevocation, ...],
        Field(max_length=_MAX_CAPABILITIES),
    ] = ()
    snapshot_digest: Digest

    @model_validator(mode="before")
    @classmethod
    def _bounded_raw_material(cls, value: object) -> object:
        _validate_snapshot_raw_bounds(value)
        return value

    @model_validator(mode="after")
    def _canonical_snapshot(self) -> Self:
        capabilities = tuple(
            EnforcedCapabilityGrant.model_validate(value.model_dump(mode="python"))
            for value in self.capabilities
        )
        capability_ids = tuple(value.capability_id for value in capabilities)
        nonces = tuple(value.nonce for value in capabilities)
        if capability_ids != tuple(sorted(capability_ids)) or len(set(capability_ids)) != len(
            capability_ids
        ):
            raise ValueError("Snapshot capabilities must be sorted and unique by capability_id")
        if len(set(nonces)) != len(nonces):
            raise ValueError("Snapshot capability nonces must be unique")

        accepted_key_versions = tuple(
            CapabilityKeyVersion.model_validate(value.model_dump(mode="python"))
            for value in self.accepted_key_versions
        )
        budget_states = tuple(
            CapabilityBudgetState.model_validate(value.model_dump(mode="python"))
            for value in self.budget_states
        )
        revocations = tuple(
            CapabilityRevocation.model_validate(value.model_dump(mode="python"))
            for value in self.revocations
        )

        key_pairs = tuple(value.sort_key() for value in accepted_key_versions)
        if key_pairs != tuple(sorted(key_pairs)) or len(set(key_pairs)) != len(key_pairs):
            raise ValueError("Accepted key versions must be sorted and unique")

        budget_ids = tuple(value.capability_id for value in budget_states)
        if budget_ids != tuple(sorted(budget_ids)) or len(set(budget_ids)) != len(budget_ids):
            raise ValueError("Budget states must be sorted and unique by capability_id")

        revocation_ids = tuple(value.revocation_id for value in revocations)
        if revocation_ids != tuple(sorted(revocation_ids)) or len(set(revocation_ids)) != len(
            revocation_ids
        ):
            raise ValueError("Revocations must be sorted and unique by revocation_id")

        if (
            any(value.tenant_id != self.tenant_id for value in capabilities)
            or any(value.tenant_id != self.tenant_id for value in accepted_key_versions)
            or any(value.tenant_id != self.tenant_id for value in budget_states)
            or any(value.tenant_id != self.tenant_id for value in revocations)
        ):
            raise ValueError("Every authority snapshot record must belong to its tenant")
        if self.snapshot_digest != canonical_digest(_snapshot_payload(self)):
            raise ValueError("Authority snapshot has a mismatched snapshot_digest")
        return self

    @classmethod
    def create(
        cls,
        *,
        tenant_id: Identifier,
        snapshot_id: Identifier,
        revision: int,
        as_of: datetime,
        capabilities: tuple[EnforcedCapabilityGrant, ...] = (),
        accepted_key_versions: tuple[CapabilityKeyVersion, ...] = (),
        budget_states: tuple[CapabilityBudgetState, ...] = (),
        revocations: tuple[CapabilityRevocation, ...] = (),
    ) -> Self:
        _validate_snapshot_raw_bounds(
            {
                "capabilities": capabilities,
                "accepted_key_versions": accepted_key_versions,
                "budget_states": budget_states,
                "revocations": revocations,
            }
        )
        payload: dict[str, object] = {
            "tenant_id": tenant_id,
            "snapshot_id": snapshot_id,
            "revision": revision,
            "as_of": as_of,
            "capabilities": tuple(sorted(capabilities, key=lambda value: value.capability_id)),
            "accepted_key_versions": tuple(
                sorted(accepted_key_versions, key=lambda value: value.sort_key())
            ),
            "budget_states": tuple(sorted(budget_states, key=lambda value: value.capability_id)),
            "revocations": tuple(sorted(revocations, key=lambda value: value.revocation_id)),
        }
        return cls.model_validate({**payload, "snapshot_digest": canonical_digest(payload)})


class AuthorityEvaluationContext(StrictModel):
    """Authenticated coordinator facts; ``evaluated_at`` is the snapshot capture instant."""

    tenant_id: Identifier
    principal_id: Identifier
    subject: Identifier
    audience: Identifier
    goal_id: Identifier
    run_id: Identifier
    actor_id: Identifier
    on_behalf_of: Identifier
    configuration_digest: Digest
    evaluated_at: AwareDatetime
    authority_snapshot_digest: Digest


def _resource_decision_payload(decision: ResourceAuthorityDecision) -> dict[str, object]:
    return decision.model_dump(mode="python", exclude={"evidence_digest"})


class ResourceAuthorityDecision(StrictModel):
    """Deterministic evidence for one independently authorized resource use."""

    resource_index: Annotated[int, Field(ge=0)]
    resource_use_digest: Digest
    authority_action: NonEmptyStr
    canonical_resource: CanonicalResource
    data_classes: Annotated[tuple[NonEmptyStr, ...], Field(max_length=MAX_RESOURCE_DATA_CLASSES)]
    provenance_ids: Annotated[tuple[Identifier, ...], Field(max_length=_MAX_PROVENANCE_BINDINGS)]
    verdict: AuthorityEvaluationVerdict
    reason_code: AuthorityReasonCode
    capability_chain_ids: Annotated[
        tuple[Identifier, ...], Field(max_length=_MAX_DELEGATION_CHAIN_NODES)
    ] = ()
    evidence_digest: Digest

    @field_validator("data_classes", "provenance_ids")
    @classmethod
    def _canonical_evidence_lists(
        cls,
        values: tuple[str, ...],
        info: object,
    ) -> tuple[str, ...]:
        return _require_sorted_unique(
            values,
            field_name=str(getattr(info, "field_name", "evidence list")),
        )

    @model_validator(mode="after")
    def _consistent_evidence(self) -> Self:
        if len(set(self.capability_chain_ids)) != len(self.capability_chain_ids):
            raise ValueError("A capability chain cannot contain duplicate capability IDs")
        if self.verdict is AuthorityEvaluationVerdict.ALLOW:
            if self.reason_code is not AuthorityReasonCode.AUTHORITY_GRANTED:
                raise ValueError("Allowed resource evidence requires AUTHORITY_GRANTED")
            if not self.capability_chain_ids:
                raise ValueError("Allowed resource evidence requires a capability chain")
        else:
            if self.reason_code is AuthorityReasonCode.AUTHORITY_GRANTED:
                raise ValueError("Denied resource evidence cannot claim AUTHORITY_GRANTED")
            if self.reason_code in _AGGREGATE_ONLY_REASONS:
                raise ValueError("Aggregate denial reasons are invalid at resource level")
            if self.capability_chain_ids:
                raise ValueError(
                    "Denied resource evidence cannot authorize a partial capability chain"
                )
        if self.evidence_digest != canonical_digest(_resource_decision_payload(self)):
            raise ValueError("Resource authority evidence has a mismatched evidence_digest")
        return self

    @classmethod
    def create(
        cls,
        *,
        resource_index: int,
        resource_use: ResourceUse,
        effective_data_classes: tuple[NonEmptyStr, ...],
        verdict: AuthorityEvaluationVerdict,
        reason_code: AuthorityReasonCode,
        capability_chain_ids: tuple[Identifier, ...] = (),
    ) -> Self:
        payload: dict[str, object] = {
            "resource_index": resource_index,
            "resource_use_digest": canonical_digest(resource_use),
            "authority_action": resource_use.authority_action,
            "canonical_resource": resource_use.canonical_resource,
            "data_classes": effective_data_classes,
            "provenance_ids": resource_use.provenance_ids,
            "verdict": verdict,
            "reason_code": reason_code,
            "capability_chain_ids": capability_chain_ids,
        }
        return cls.model_validate({**payload, "evidence_digest": canonical_digest(payload)})


def _reservation_plan_payload(plan: CapabilityReservationPlan) -> dict[str, object]:
    return plan.model_dump(mode="python", exclude={"plan_digest"})


class CapabilityReservationPlan(StrictModel):
    """A deterministic all-or-none budget reservation request for the durable store."""

    tenant_id: Identifier
    transaction_id: Identifier
    intent_hash: Digest
    authority_snapshot_digest: Digest
    capability_ids: Annotated[
        tuple[Identifier, ...],
        Field(min_length=1, max_length=_MAX_RESERVATION_CAPABILITIES),
    ]
    units_per_capability: Literal[1] = 1
    plan_digest: Digest

    @model_validator(mode="after")
    def _consistent_plan(self) -> Self:
        if self.capability_ids != tuple(sorted(self.capability_ids)) or len(
            set(self.capability_ids)
        ) != len(self.capability_ids):
            raise ValueError("Reservation capability_ids must be sorted and unique")
        if self.plan_digest != canonical_digest(_reservation_plan_payload(self)):
            raise ValueError("Capability reservation plan has a mismatched plan_digest")
        return self

    @classmethod
    def create(
        cls,
        *,
        tenant_id: Identifier,
        transaction_id: Identifier,
        intent_hash: Digest,
        authority_snapshot_digest: Digest,
        capability_ids: tuple[Identifier, ...],
    ) -> Self:
        payload: dict[str, object] = {
            "tenant_id": tenant_id,
            "transaction_id": transaction_id,
            "intent_hash": intent_hash,
            "authority_snapshot_digest": authority_snapshot_digest,
            "capability_ids": tuple(sorted(set(capability_ids))),
            "units_per_capability": 1,
        }
        return cls.model_validate({**payload, "plan_digest": canonical_digest(payload)})


def _authority_decision_payload(decision: EnforcedAuthorityDecision) -> dict[str, object]:
    return decision.model_dump(mode="python", exclude={"decision_digest"})


class EnforcedAuthorityDecision(StrictModel):
    """Whole-action authority result, including reproducible per-resource evidence."""

    tenant_id: Identifier
    transaction_id: Identifier
    intent_hash: Digest
    authority_snapshot_tenant_id: Identifier
    authority_snapshot_id: Identifier
    authority_snapshot_revision: Annotated[int, Field(ge=1)]
    authority_snapshot_as_of: AwareDatetime
    authority_snapshot_digest: Digest
    expected_authority_snapshot_digest: Digest
    evaluation_context_digest: Digest
    evaluated_at: AwareDatetime
    verdict: AuthorityEvaluationVerdict
    reason_code: AuthorityReasonCode
    resource_decisions: Annotated[
        tuple[ResourceAuthorityDecision, ...],
        Field(min_length=1, max_length=_MAX_SCOPE_ITEMS),
    ]
    reservation_plan: CapabilityReservationPlan | None = None
    provenance_used_as_authority: Literal[False] = False
    decision_digest: Digest

    @model_validator(mode="after")
    def _consistent_decision(self) -> Self:
        decisions = tuple(
            ResourceAuthorityDecision.model_validate(value.model_dump(mode="python"))
            for value in self.resource_decisions
        )
        indexes = tuple(value.resource_index for value in decisions)
        if indexes != tuple(range(len(decisions))):
            raise ValueError("Resource authority decisions must cover consecutive resource indexes")
        observed_global_reason: AuthorityReasonCode | None = None
        if self.authority_snapshot_digest != self.expected_authority_snapshot_digest:
            observed_global_reason = AuthorityReasonCode.SNAPSHOT_MISMATCH
        elif self.authority_snapshot_tenant_id != self.tenant_id:
            observed_global_reason = AuthorityReasonCode.TENANT_MISMATCH
        elif self.authority_snapshot_as_of > self.evaluated_at:
            observed_global_reason = AuthorityReasonCode.SNAPSHOT_FROM_FUTURE
        elif self.authority_snapshot_as_of < self.evaluated_at:
            observed_global_reason = AuthorityReasonCode.SNAPSHOT_STALE
        observed_fact_reasons = {
            AuthorityReasonCode.SNAPSHOT_MISMATCH,
            AuthorityReasonCode.TENANT_MISMATCH,
            AuthorityReasonCode.SNAPSHOT_FROM_FUTURE,
            AuthorityReasonCode.SNAPSHOT_STALE,
        }
        if observed_global_reason is not None:
            if (
                self.verdict is not AuthorityEvaluationVerdict.DENY
                or self.reason_code is not observed_global_reason
                or any(value.reason_code is not observed_global_reason for value in decisions)
            ):
                raise ValueError("Observed snapshot facts must fail closed with matching evidence")
        elif self.reason_code in observed_fact_reasons or any(
            value.reason_code in observed_fact_reasons for value in decisions
        ):
            raise ValueError("Snapshot fact denial contradicts the recorded snapshot facts")
        resource_global_reasons = {
            value.reason_code for value in decisions if value.reason_code in _GLOBAL_DENIAL_REASONS
        }
        if resource_global_reasons and (
            len(resource_global_reasons) != 1
            or any(value.reason_code not in resource_global_reasons for value in decisions)
            or self.reason_code not in resource_global_reasons
        ):
            raise ValueError("A global denial reason must apply to every resource decision")
        allowed = all(value.verdict is AuthorityEvaluationVerdict.ALLOW for value in decisions)
        if self.verdict is AuthorityEvaluationVerdict.ALLOW:
            if not decisions or not allowed:
                raise ValueError("An allowed action requires every resource use to be allowed")
            if self.reason_code is not AuthorityReasonCode.AUTHORITY_GRANTED:
                raise ValueError("An allowed action requires AUTHORITY_GRANTED")
            if self.reservation_plan is None:
                raise ValueError("An allowed action requires an atomic reservation plan")
            plan = CapabilityReservationPlan.model_validate(
                self.reservation_plan.model_dump(mode="python")
            )
            expected_ids = tuple(
                sorted(
                    {
                        capability_id
                        for decision in decisions
                        for capability_id in decision.capability_chain_ids
                    }
                )
            )
            if plan.capability_ids != expected_ids:
                raise ValueError("Reservation plan does not cover every selected capability chain")
            if (
                plan.tenant_id != self.tenant_id
                or plan.transaction_id != self.transaction_id
                or plan.intent_hash != self.intent_hash
                or plan.authority_snapshot_digest != self.authority_snapshot_digest
            ):
                raise ValueError("Reservation plan is not bound to this authority decision")
        else:
            if self.reservation_plan is not None or allowed:
                raise ValueError("A denied action cannot carry an executable reservation plan")
            denied = tuple(
                value for value in decisions if value.verdict is AuthorityEvaluationVerdict.DENY
            )
            unique_reasons = {value.reason_code for value in denied}
            if len(denied) != len(decisions):
                expected_reason = AuthorityReasonCode.PARTIAL_RESOURCE_DENIAL
            elif len(unique_reasons) == 1:
                expected_reason = denied[0].reason_code
            else:
                expected_reason = AuthorityReasonCode.MULTIPLE_RESOURCE_DENIALS
            if self.reason_code is not expected_reason:
                raise ValueError("Denied action reason does not summarize its resource evidence")
        if self.decision_digest != canonical_digest(_authority_decision_payload(self)):
            raise ValueError("Authority decision has a mismatched decision_digest")
        return self

    @classmethod
    def create(
        cls,
        *,
        action: NormalizedAction,
        context: AuthorityEvaluationContext,
        snapshot: AuthoritySnapshot,
        verdict: AuthorityEvaluationVerdict,
        reason_code: AuthorityReasonCode,
        resource_decisions: tuple[ResourceAuthorityDecision, ...],
        reservation_plan: CapabilityReservationPlan | None,
    ) -> Self:
        payload: dict[str, object] = {
            "tenant_id": context.tenant_id,
            "transaction_id": action.transaction_id,
            "intent_hash": action.intent_hash,
            "authority_snapshot_tenant_id": snapshot.tenant_id,
            "authority_snapshot_id": snapshot.snapshot_id,
            "authority_snapshot_revision": snapshot.revision,
            "authority_snapshot_as_of": snapshot.as_of,
            "authority_snapshot_digest": snapshot.snapshot_digest,
            "expected_authority_snapshot_digest": context.authority_snapshot_digest,
            "evaluation_context_digest": canonical_digest(context),
            "evaluated_at": context.evaluated_at,
            "verdict": verdict,
            "reason_code": reason_code,
            "resource_decisions": resource_decisions,
            "reservation_plan": reservation_plan,
            "provenance_used_as_authority": False,
        }
        return cls.model_validate({**payload, "decision_digest": canonical_digest(payload)})


@dataclass(frozen=True, slots=True)
class _CandidateFailure:
    reason: AuthorityReasonCode
    stage: int
    capability_id: str


@dataclass(frozen=True, slots=True)
class _CandidateResult:
    chain: tuple[EnforcedCapabilityGrant, ...] | None
    failure: _CandidateFailure | None


def _failure(
    reason: AuthorityReasonCode,
    stage: int,
    capability_id: str,
) -> _CandidateResult:
    return _CandidateResult(
        chain=None,
        failure=_CandidateFailure(reason=reason, stage=stage, capability_id=capability_id),
    )


class AuthorityEvaluator:
    """Evaluate resource-complete authority without I/O, clocks, or budget mutation."""

    def evaluate(
        self,
        *,
        action: NormalizedAction,
        context: AuthorityEvaluationContext,
        snapshot: AuthoritySnapshot,
    ) -> EnforcedAuthorityDecision:
        """Return a fail-closed, content-digested decision for one normalized action."""

        action = NormalizedAction.model_validate(action.model_dump(mode="python"))
        context = AuthorityEvaluationContext.model_validate(context.model_dump(mode="python"))
        snapshot = AuthoritySnapshot.model_validate(snapshot.model_dump(mode="python"))

        global_reason = self._global_denial_reason(action, context, snapshot)
        if global_reason is not None:
            return self._deny_every_resource(action, context, snapshot, global_reason)
        if action.risk_floor is RiskClass.FORBIDDEN:
            return self._deny_every_resource(
                action,
                context,
                snapshot,
                AuthorityReasonCode.FORBIDDEN_RISK_CLASS,
            )
        capability_by_id = {value.capability_id: value for value in snapshot.capabilities}
        chain_by_id, chain_resolution_units = self._resolve_chains_bounded(capability_by_id)
        if (
            chain_by_id is None
            or self._estimated_work_units(
                action,
                snapshot,
                chain_by_id=chain_by_id,
                chain_resolution_units=chain_resolution_units,
            )
            > _MAX_AUTHORITY_WORK_UNITS
        ):
            return self._deny_every_resource(
                action,
                context,
                snapshot,
                AuthorityReasonCode.AUTHORITY_COMPLEXITY_LIMIT,
            )

        budget_by_id = {value.capability_id: value for value in snapshot.budget_states}
        accepted_pairs = {
            (value.key_id, value.token_version) for value in snapshot.accepted_key_versions
        }
        known_key_ids = {value.key_id for value in snapshot.accepted_key_versions}
        effective_revocations = tuple(
            value for value in snapshot.revocations if value.effective_at <= context.evaluated_at
        )
        revoked_capability_ids = frozenset(
            value.capability_id
            for value in effective_revocations
            if value.capability_id is not None
        )
        revoked_nonces = frozenset(
            value.nonce for value in effective_revocations if value.nonce is not None
        )

        resource_decisions: list[ResourceAuthorityDecision] = []
        for index, resource_use in enumerate(action.resource_uses):
            effective_data_classes = _effective_data_classes(action, resource_use)
            terminal_read_scope = resource_use.canonical_resource.endswith("/**") and (
                resource_use.access_mode is ResourceAccessMode.READ
                and resource_use.use_kind
                in {ResourceUseKind.PRECONDITION_READ, ResourceUseKind.VERIFIER_READ}
                and not resource_use.destination_external
            )
            if _resource_has_hierarchical_alias(
                resource_use.canonical_resource,
                allow_terminal_wildcard=terminal_read_scope,
            ) or ("*" in resource_use.canonical_resource and not terminal_read_scope):
                resource_decisions.append(
                    ResourceAuthorityDecision.create(
                        resource_index=index,
                        resource_use=resource_use,
                        effective_data_classes=effective_data_classes,
                        verdict=AuthorityEvaluationVerdict.DENY,
                        reason_code=AuthorityReasonCode.RESOURCE_ALIAS_REJECTED,
                    )
                )
                continue

            valid_chains: list[tuple[EnforcedCapabilityGrant, ...]] = []
            failures: list[_CandidateFailure] = []
            for capability in snapshot.capabilities:
                candidate = self._evaluate_candidate(
                    leaf=capability,
                    resource_use=resource_use,
                    effective_data_classes=effective_data_classes,
                    action=action,
                    context=context,
                    chain_result=chain_by_id[capability.capability_id],
                    budget_by_id=budget_by_id,
                    accepted_pairs=accepted_pairs,
                    known_key_ids=known_key_ids,
                    revoked_capability_ids=revoked_capability_ids,
                    revoked_nonces=revoked_nonces,
                )
                if candidate.chain is not None:
                    valid_chains.append(candidate.chain)
                elif candidate.failure is not None:
                    failures.append(candidate.failure)

            if valid_chains:
                selected = min(
                    valid_chains,
                    key=lambda chain: (
                        len(chain),
                        chain[-1].capability_id,
                        tuple(value.capability_id for value in chain),
                    ),
                )
                resource_decisions.append(
                    ResourceAuthorityDecision.create(
                        resource_index=index,
                        resource_use=resource_use,
                        effective_data_classes=effective_data_classes,
                        verdict=AuthorityEvaluationVerdict.ALLOW,
                        reason_code=AuthorityReasonCode.AUTHORITY_GRANTED,
                        capability_chain_ids=tuple(value.capability_id for value in selected),
                    )
                )
                continue

            reason = AuthorityReasonCode.AUTHORITY_MISSING
            if failures:
                closest = sorted(
                    failures,
                    key=lambda value: (-value.stage, value.capability_id, value.reason.value),
                )[0]
                reason = closest.reason
            resource_decisions.append(
                ResourceAuthorityDecision.create(
                    resource_index=index,
                    resource_use=resource_use,
                    effective_data_classes=effective_data_classes,
                    verdict=AuthorityEvaluationVerdict.DENY,
                    reason_code=reason,
                )
            )

        decisions = tuple(resource_decisions)
        denied = tuple(
            value for value in decisions if value.verdict is AuthorityEvaluationVerdict.DENY
        )
        if denied:
            unique_reasons = {value.reason_code for value in denied}
            if len(denied) != len(decisions):
                aggregate_reason = AuthorityReasonCode.PARTIAL_RESOURCE_DENIAL
            elif len(unique_reasons) == 1:
                aggregate_reason = denied[0].reason_code
            else:
                aggregate_reason = AuthorityReasonCode.MULTIPLE_RESOURCE_DENIALS
            return EnforcedAuthorityDecision.create(
                action=action,
                context=context,
                snapshot=snapshot,
                verdict=AuthorityEvaluationVerdict.DENY,
                reason_code=aggregate_reason,
                resource_decisions=decisions,
                reservation_plan=None,
            )

        capability_ids = tuple(
            sorted(
                {
                    capability_id
                    for decision in decisions
                    for capability_id in decision.capability_chain_ids
                }
            )
        )
        if len(capability_ids) > _MAX_RESERVATION_CAPABILITIES:
            return self._deny_every_resource(
                action,
                context,
                snapshot,
                AuthorityReasonCode.CAPABILITY_RESERVATION_PLAN_TOO_LARGE,
            )
        reservation_plan = CapabilityReservationPlan.create(
            tenant_id=context.tenant_id,
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            authority_snapshot_digest=snapshot.snapshot_digest,
            capability_ids=capability_ids,
        )
        return EnforcedAuthorityDecision.create(
            action=action,
            context=context,
            snapshot=snapshot,
            verdict=AuthorityEvaluationVerdict.ALLOW,
            reason_code=AuthorityReasonCode.AUTHORITY_GRANTED,
            resource_decisions=decisions,
            reservation_plan=reservation_plan,
        )

    @staticmethod
    def _estimated_work_units(
        action: NormalizedAction,
        snapshot: AuthoritySnapshot,
        *,
        chain_by_id: dict[
            str,
            tuple[EnforcedCapabilityGrant, ...] | AuthorityReasonCode,
        ],
        chain_resolution_units: int,
    ) -> int:
        candidate_units = 0
        for capability in snapshot.capabilities:
            chain_result = chain_by_id[capability.capability_id]
            if isinstance(chain_result, AuthorityReasonCode):
                candidate_units += 1
                continue
            candidate_units += sum(
                1 + len(node.actions) + len(node.resource_scopes) + len(node.data_classes)
                for node in chain_result
            )
            candidate_units += sum(
                1
                + len(child.actions)
                + len(child.data_classes)
                + len(child.resource_scopes) * max(1, len(parent.resource_scopes))
                for parent, child in pairwise(chain_result)
            )
        return (
            len(snapshot.capabilities)
            + len(snapshot.accepted_key_versions)
            + len(snapshot.budget_states)
            + len(snapshot.revocations)
            + chain_resolution_units
            + len(action.resource_uses) * max(1, candidate_units)
        )

    @classmethod
    def _resolve_chains_bounded(
        cls,
        capability_by_id: dict[str, EnforcedCapabilityGrant],
    ) -> tuple[
        dict[str, tuple[EnforcedCapabilityGrant, ...] | AuthorityReasonCode] | None,
        int,
    ]:
        chain_by_id: dict[
            str,
            tuple[EnforcedCapabilityGrant, ...] | AuthorityReasonCode,
        ] = {}
        work_units = 0
        for capability_id in sorted(capability_by_id):
            chain_result, chain_units = cls._resolve_chain_with_work(
                capability_by_id[capability_id],
                capability_by_id,
            )
            work_units += chain_units
            if work_units > _MAX_AUTHORITY_WORK_UNITS:
                return None, work_units
            chain_by_id[capability_id] = chain_result
        return chain_by_id, work_units

    @staticmethod
    def _global_denial_reason(
        action: NormalizedAction,
        context: AuthorityEvaluationContext,
        snapshot: AuthoritySnapshot,
    ) -> AuthorityReasonCode | None:
        if context.authority_snapshot_digest != snapshot.snapshot_digest:
            return AuthorityReasonCode.SNAPSHOT_MISMATCH
        if snapshot.tenant_id != context.tenant_id:
            return AuthorityReasonCode.TENANT_MISMATCH
        if snapshot.as_of > context.evaluated_at:
            return AuthorityReasonCode.SNAPSHOT_FROM_FUTURE
        if snapshot.as_of < context.evaluated_at:
            return AuthorityReasonCode.SNAPSHOT_STALE
        if (
            action.tenant_id != context.tenant_id
            or action.principal_id != context.principal_id
            or action.agent_id != context.subject
            or action.goal_id != context.goal_id
            or action.run_id != context.run_id
            or action.actor_id != context.actor_id
            or action.on_behalf_of != context.on_behalf_of
            or action.configuration_digest != context.configuration_digest
        ):
            return AuthorityReasonCode.ACTION_CONTEXT_MISMATCH
        return None

    @staticmethod
    def _deny_every_resource(
        action: NormalizedAction,
        context: AuthorityEvaluationContext,
        snapshot: AuthoritySnapshot,
        reason: AuthorityReasonCode,
    ) -> EnforcedAuthorityDecision:
        decisions = tuple(
            ResourceAuthorityDecision.create(
                resource_index=index,
                resource_use=resource_use,
                effective_data_classes=_effective_data_classes(action, resource_use),
                verdict=AuthorityEvaluationVerdict.DENY,
                reason_code=reason,
            )
            for index, resource_use in enumerate(action.resource_uses)
        )
        return EnforcedAuthorityDecision.create(
            action=action,
            context=context,
            snapshot=snapshot,
            verdict=AuthorityEvaluationVerdict.DENY,
            reason_code=reason,
            resource_decisions=decisions,
            reservation_plan=None,
        )

    def _evaluate_candidate(
        self,
        *,
        leaf: EnforcedCapabilityGrant,
        resource_use: ResourceUse,
        effective_data_classes: tuple[str, ...],
        action: NormalizedAction,
        context: AuthorityEvaluationContext,
        chain_result: tuple[EnforcedCapabilityGrant, ...] | AuthorityReasonCode,
        budget_by_id: dict[str, CapabilityBudgetState],
        accepted_pairs: set[tuple[str, int]],
        known_key_ids: set[str],
        revoked_capability_ids: frozenset[str],
        revoked_nonces: frozenset[str],
    ) -> _CandidateResult:
        if isinstance(chain_result, AuthorityReasonCode):
            return _failure(chain_result, 1, leaf.capability_id)
        chain = chain_result

        if leaf.subject != context.subject:
            return _failure(AuthorityReasonCode.SUBJECT_MISMATCH, 2, leaf.capability_id)
        for capability in chain:
            if capability.tenant_id != context.tenant_id:
                return _failure(AuthorityReasonCode.TENANT_MISMATCH, 3, leaf.capability_id)
            if capability.audience != context.audience:
                return _failure(AuthorityReasonCode.AUDIENCE_MISMATCH, 4, leaf.capability_id)
            if capability.goal_id != context.goal_id:
                return _failure(AuthorityReasonCode.GOAL_MISMATCH, 5, leaf.capability_id)
            if capability.run_id != context.run_id:
                return _failure(AuthorityReasonCode.RUN_MISMATCH, 6, leaf.capability_id)
        if chain[0].issuer != context.principal_id:
            return _failure(AuthorityReasonCode.ROOT_ISSUER_MISMATCH, 7, leaf.capability_id)

        for parent, child in pairwise(chain):
            edge_reason = self._delegation_edge_denial(parent, child)
            if edge_reason is not None:
                return _failure(edge_reason, 8, leaf.capability_id)

        for capability in chain:
            key_pair = (capability.key_id, capability.token_version)
            if key_pair not in accepted_pairs:
                reason = (
                    AuthorityReasonCode.UNSUPPORTED_TOKEN_VERSION
                    if capability.key_id in known_key_ids
                    else AuthorityReasonCode.UNKNOWN_KEY
                )
                return _failure(reason, 9, leaf.capability_id)
            if context.evaluated_at < capability.not_before:
                return _failure(
                    AuthorityReasonCode.CAPABILITY_NOT_YET_VALID,
                    10,
                    leaf.capability_id,
                )
            if context.evaluated_at >= capability.expires_at:
                return _failure(
                    AuthorityReasonCode.CAPABILITY_EXPIRED,
                    11,
                    leaf.capability_id,
                )
            if self._is_revoked(
                capability,
                revoked_capability_ids,
                revoked_nonces,
            ):
                return _failure(
                    AuthorityReasonCode.CAPABILITY_REVOKED,
                    12,
                    leaf.capability_id,
                )
            budget = budget_by_id.get(capability.capability_id)
            if budget is None:
                return _failure(
                    AuthorityReasonCode.CAPABILITY_BUDGET_STATE_MISSING,
                    13,
                    leaf.capability_id,
                )
            if (
                budget.goal_id != capability.goal_id
                or budget.run_id != capability.run_id
                or budget.max_uses != capability.max_uses
            ):
                return _failure(
                    AuthorityReasonCode.CAPABILITY_BUDGET_STATE_MISMATCH,
                    14,
                    leaf.capability_id,
                )
            already_reserved_for_intent = action.intent_hash in budget.reserved_intent_hashes
            if (
                budget.consumed_uses + budget.reserved_uses >= capability.max_uses
                and not already_reserved_for_intent
            ):
                return _failure(
                    AuthorityReasonCode.CAPABILITY_BUDGET_EXHAUSTED,
                    15,
                    leaf.capability_id,
                )

        if any(resource_use.authority_action not in value.actions for value in chain):
            return _failure(AuthorityReasonCode.ACTION_NOT_GRANTED, 16, leaf.capability_id)
        if any(
            not any(
                resource_scope_contains(scope, resource_use.canonical_resource)
                for scope in value.resource_scopes
            )
            for value in chain
        ):
            return _failure(AuthorityReasonCode.RESOURCE_NOT_GRANTED, 17, leaf.capability_id)
        if any(not set(effective_data_classes) <= set(value.data_classes) for value in chain):
            return _failure(AuthorityReasonCode.DATA_CLASS_NOT_GRANTED, 18, leaf.capability_id)
        if self._wildcard_is_forbidden(action, resource_use, effective_data_classes, chain):
            return _failure(AuthorityReasonCode.WILDCARD_SCOPE_FORBIDDEN, 19, leaf.capability_id)
        return _CandidateResult(chain=chain, failure=None)

    @staticmethod
    def _resolve_chain_with_work(
        leaf: EnforcedCapabilityGrant,
        capability_by_id: dict[str, EnforcedCapabilityGrant],
    ) -> tuple[tuple[EnforcedCapabilityGrant, ...] | AuthorityReasonCode, int]:
        reverse_chain: list[EnforcedCapabilityGrant] = []
        seen: set[str] = set()
        current = leaf
        work_units = 0
        while True:
            work_units += 1
            if current.capability_id in seen:
                return AuthorityReasonCode.DELEGATION_CYCLE, work_units
            if len(reverse_chain) >= _MAX_DELEGATION_CHAIN_NODES:
                return AuthorityReasonCode.DELEGATION_CHAIN_TOO_DEEP, work_units
            seen.add(current.capability_id)
            reverse_chain.append(current)
            if current.parent_capability is None:
                break
            parent = capability_by_id.get(current.parent_capability)
            if parent is None:
                return AuthorityReasonCode.DELEGATION_PARENT_MISSING, work_units
            current = parent
        return tuple(reversed(reverse_chain)), work_units

    @staticmethod
    def _delegation_edge_denial(
        parent: EnforcedCapabilityGrant,
        child: EnforcedCapabilityGrant,
    ) -> AuthorityReasonCode | None:
        if child.issuer != parent.subject:
            return AuthorityReasonCode.DELEGATION_ISSUER_MISMATCH
        if not set(child.actions) <= set(parent.actions):
            return AuthorityReasonCode.DELEGATION_ACTION_WIDENED
        if any(
            not any(
                _resource_scope_is_subset(child_scope, parent_scope)
                for parent_scope in parent.resource_scopes
            )
            for child_scope in child.resource_scopes
        ):
            return AuthorityReasonCode.DELEGATION_RESOURCE_WIDENED
        if not set(child.data_classes) <= set(parent.data_classes):
            return AuthorityReasonCode.DELEGATION_DATA_CLASS_WIDENED
        if (
            child.issued_at < parent.issued_at
            or child.not_before < parent.not_before
            or child.expires_at > parent.expires_at
        ):
            return AuthorityReasonCode.DELEGATION_TIME_WIDENED
        if child.delegation_depth_remaining >= parent.delegation_depth_remaining:
            return AuthorityReasonCode.DELEGATION_DEPTH_INVALID
        if child.max_uses > parent.max_uses:
            return AuthorityReasonCode.DELEGATION_BUDGET_WIDENED
        return None

    @staticmethod
    def _is_revoked(
        capability: EnforcedCapabilityGrant,
        revoked_capability_ids: frozenset[str],
        revoked_nonces: frozenset[str],
    ) -> bool:
        return (
            capability.capability_id in revoked_capability_ids or capability.nonce in revoked_nonces
        )

    @staticmethod
    def _wildcard_is_forbidden(
        action: NormalizedAction,
        resource_use: ResourceUse,
        effective_data_classes: tuple[str, ...],
        chain: tuple[EnforcedCapabilityGrant, ...],
    ) -> bool:
        sensitive_or_irreversible = action.risk_floor is RiskClass.IRREVERSIBLE or bool(
            set(effective_data_classes) & _SENSITIVE_DATA_CLASSES
        )
        if resource_use.canonical_resource.endswith("/**"):
            return sensitive_or_irreversible
        effective_scope_is_wildcard = all(
            not any(
                scope == resource_use.canonical_resource for scope in capability.resource_scopes
            )
            for capability in chain
        )
        if not effective_scope_is_wildcard:
            return False
        return sensitive_or_irreversible


__all__ = [
    "AuthorityEvaluationContext",
    "AuthorityEvaluationVerdict",
    "AuthorityEvaluator",
    "AuthorityReasonCode",
    "AuthoritySnapshot",
    "CapabilityBudgetState",
    "CapabilityKeyVersion",
    "CapabilityReservationPlan",
    "CapabilityResourceScope",
    "CapabilityRevocation",
    "EnforcedAuthorityDecision",
    "EnforcedCapabilityGrant",
    "ResourceAuthorityDecision",
    "resource_scope_contains",
    "resource_scope_matches",
]
