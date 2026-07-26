"""Deterministic, deny-dominant aggregation for the bounded policy DSL subset.

The embedded digests are consistency bindings. They become tamper-evident only when an
authoritative journal or signature binds them; they are not standalone authenticity proofs.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

from pydantic import Field, StringConstraints, field_validator, model_validator

from agentkernel.authority.evaluator import (
    AuthorityEvaluationVerdict,
    AuthorityReasonCode,
    EnforcedAuthorityDecision,
    ResourceAuthorityDecision,
)
from agentkernel.canonical import canonical_digest
from agentkernel.domain.models import (
    Digest,
    Identifier,
    NonEmptyStr,
    NormalizedAction,
    ResourceUse,
    StrictModel,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.policy.engine import CompiledPolicy, PolicyContext, PolicyDecision, PolicyVerdict

MAX_POLICY_BUNDLES = 64
MAX_RESOURCE_USES = 512
MAX_UNKNOWN_FACTS = 256
MAX_POLICY_MODES = 16
MAX_POLICY_OBLIGATIONS = 2
MAX_POLICY_MATCHES = 4_096
MAX_POLICY_WORK_UNITS = 32_768
MAX_POLICY_EVIDENCE_UNITS = 524_288
_MAX_POLICY_TEXT_CHARS = 512
PolicyMatchReference = Annotated[str, StringConstraints(min_length=1, max_length=640)]


class PolicyLayer(StrEnum):
    """Normative policy layers in their evidence-rendering order."""

    SYSTEM = "system"
    DEPLOYMENT = "deployment"
    TENANT = "tenant"
    USER = "user"
    GOAL = "goal"
    ADAPTER = "adapter"
    DATA = "data"


_LAYER_ORDER = {layer: position for position, layer in enumerate(PolicyLayer)}


class PolicyLayerIdentity(StrictModel):
    """Immutable identity of one compiled bundle at one policy layer."""

    layer: PolicyLayer
    scope_id: Identifier
    bundle_name: Identifier
    bundle_version: NonEmptyStr
    bundle_digest: Digest

    @field_validator("bundle_version")
    @classmethod
    def _canonical_bundle_version(cls, value: str) -> str:
        return _canonical_semantic_text(value, scope="policy bundle version")


class PolicyLayerSnapshot(StrictModel):
    """Canonical all-and-only manifest of policy bundles expected for this evaluation."""

    identities: tuple[PolicyLayerIdentity, ...] = Field(max_length=MAX_POLICY_BUNDLES)
    snapshot_digest: Digest

    @model_validator(mode="after")
    def _canonical_snapshot(self) -> PolicyLayerSnapshot:
        identities = tuple(
            PolicyLayerIdentity.model_validate(identity.model_dump(mode="python"))
            for identity in self.identities
        )
        keys = tuple(_layer_identity_sort_key(identity) for identity in identities)
        if len(keys) != len(set(keys)) or keys != tuple(sorted(keys)):
            raise ValueError("Policy layer snapshot identities must be sorted and unique")
        if self.snapshot_digest != canonical_digest(_policy_snapshot_payload(self)):
            raise ValueError("Policy layer snapshot has a mismatched snapshot_digest")
        return self

    @classmethod
    def create(cls, identities: Sequence[PolicyLayerIdentity]) -> PolicyLayerSnapshot:
        if len(identities) > MAX_POLICY_BUNDLES:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Policy layer snapshot exceeds its configured bound",
            )
        ordered = tuple(sorted(identities, key=_layer_identity_sort_key))
        unsigned = cls.model_construct(
            identities=ordered,
            snapshot_digest="sha256:" + ("0" * 64),
        )
        return cls(
            identities=ordered,
            snapshot_digest=canonical_digest(_policy_snapshot_payload(unsigned)),
        )


class PolicyLayerInput(StrictModel):
    """A compiled bundle plus caller-declared unknown evidence for that layer."""

    layer: PolicyLayer
    scope_id: Identifier
    policy: CompiledPolicy
    unknown_facts: tuple[NonEmptyStr, ...] = Field(default=(), max_length=MAX_UNKNOWN_FACTS)

    @field_validator("unknown_facts")
    @classmethod
    def _canonical_unknown_facts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_unknown_facts(values, scope="policy layer input")

    @property
    def identity(self) -> PolicyLayerIdentity:
        return PolicyLayerIdentity(
            layer=self.layer,
            scope_id=self.scope_id,
            bundle_name=self.policy.bundle.name,
            bundle_version=self.policy.bundle.version,
            bundle_digest=self.policy.digest,
        )


class PolicyResourceInput(StrictModel):
    """One lightweight resource context, bound to action and authority by its aggregate."""

    resource_index: int = Field(ge=0, le=MAX_RESOURCE_USES - 1)
    resource_use_ref: Digest
    resource_use: ResourceUse
    context: PolicyContext
    unknown_facts: tuple[NonEmptyStr, ...] = Field(default=(), max_length=MAX_UNKNOWN_FACTS)

    @field_validator("unknown_facts")
    @classmethod
    def _canonical_unknown_facts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_unknown_facts(values, scope="policy resource input")

    @model_validator(mode="after")
    def _bind_context_to_resource_use(self) -> PolicyResourceInput:
        try:
            resource_use = ResourceUse.model_validate(self.resource_use.model_dump(mode="python"))
        except ValueError as error:
            raise ValueError("Policy resource input resource use is invalid") from error
        try:
            context = PolicyContext.model_validate(self.context.model_dump(mode="python"))
        except ValueError as error:
            raise ValueError("Policy resource input context is invalid") from error

        if self.resource_use_ref != canonical_digest(self.resource_use):
            raise ValueError("Policy resource-use reference does not match the full resource use")
        if (
            context.action != resource_use.authority_action
            or context.resource != resource_use.canonical_resource
            or context.data_classes != resource_use.data_classes
            or context.destination_external is not resource_use.destination_external
        ):
            raise ValueError("Policy context action, resource, or labels differ from resource use")
        return self


class PolicyLayerDecisionEvidence(StrictModel):
    """The complete deterministic result of one bundle for one resource use."""

    identity: PolicyLayerIdentity
    resource_use_ref: Digest
    context_digest: Digest
    decision: PolicyDecision
    input_unknown_facts: tuple[NonEmptyStr, ...] = Field(default=(), max_length=MAX_UNKNOWN_FACTS)
    unknown_facts: tuple[NonEmptyStr, ...] = Field(default=(), max_length=MAX_UNKNOWN_FACTS)
    decision_digest: Digest

    @field_validator("input_unknown_facts", "unknown_facts")
    @classmethod
    def _canonical_unknown_facts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_unknown_facts(values, scope="policy layer evidence")

    @model_validator(mode="after")
    def verify_decision_digest(self) -> PolicyLayerDecisionEvidence:
        if self.identity.bundle_digest != self.decision.bundle_digest:
            raise ValueError("Policy layer identity and decision bundle digests differ")
        expected_unknown_facts = tuple(
            sorted(set(self.input_unknown_facts) | set(self.decision.unknown_facts))
        )
        if self.unknown_facts != expected_unknown_facts:
            raise ValueError("Policy layer evidence does not bind all and only its unknown facts")
        if self.decision_digest != canonical_digest(_layer_decision_payload(self)):
            raise ValueError("Policy layer decision digest does not match its evidence")
        return self


class ResourcePolicyDecision(StrictModel):
    """Aggregate policy outcome for exactly one typed resource-use reference."""

    resource_use_ref: Digest
    context_digest: Digest
    authority_decision_digest: Digest
    authority_verdict: AuthorityEvaluationVerdict
    authority_resource_decision: ResourceAuthorityDecision
    verdict: PolicyVerdict
    allowed_modes: tuple[NonEmptyStr, ...] = Field(default=(), max_length=MAX_POLICY_MODES)
    obligations: tuple[NonEmptyStr, ...] = Field(default=(), max_length=MAX_POLICY_OBLIGATIONS)
    matched_grants: tuple[PolicyMatchReference, ...] = Field(
        default=(), max_length=MAX_POLICY_MATCHES
    )
    matched_denials: tuple[PolicyMatchReference, ...] = Field(
        default=(), max_length=MAX_POLICY_MATCHES
    )
    bundle_digests: tuple[Digest, ...] = Field(default=(), max_length=MAX_POLICY_BUNDLES)
    layer_decisions: tuple[PolicyLayerDecisionEvidence, ...] = Field(
        default=(), max_length=MAX_POLICY_BUNDLES
    )
    unknown_facts: tuple[NonEmptyStr, ...] = Field(default=(), max_length=MAX_UNKNOWN_FACTS)
    reason_code: NonEmptyStr
    explanation: NonEmptyStr
    aggregate_digest: Digest

    @field_validator("unknown_facts")
    @classmethod
    def _canonical_unknown_facts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_unknown_facts(values, scope="resource policy decision")

    @model_validator(mode="after")
    def verify_aggregate_digest(self) -> ResourcePolicyDecision:
        authority_resource_decision = ResourceAuthorityDecision.model_validate(
            self.authority_resource_decision.model_dump(mode="python")
        )
        if authority_resource_decision.resource_use_digest != self.resource_use_ref:
            raise ValueError("Resource policy authority evidence refers to another resource use")
        layer_keys = tuple(_layer_evidence_sort_key(evidence) for evidence in self.layer_decisions)
        if len(layer_keys) != len(set(layer_keys)) or layer_keys != tuple(sorted(layer_keys)):
            raise ValueError("Policy layer evidence must have sorted unique identities")
        if any(
            evidence.resource_use_ref != self.resource_use_ref for evidence in self.layer_decisions
        ):
            raise ValueError("Policy layer evidence refers to a different resource use")
        if any(evidence.context_digest != self.context_digest for evidence in self.layer_decisions):
            raise ValueError("Policy layer evidence refers to a different policy context")
        evidence_digests = tuple(
            sorted(evidence.identity.bundle_digest for evidence in self.layer_decisions)
        )
        if self.bundle_digests != evidence_digests:
            raise ValueError("Resource policy bundle digests differ from layer evidence")
        if self.layer_decisions:
            evidence_unknown_facts = tuple(
                sorted(
                    {fact for evidence in self.layer_decisions for fact in evidence.unknown_facts}
                )
            )
            if self.unknown_facts != evidence_unknown_facts:
                raise ValueError("Resource unknown facts differ from policy layer evidence")
        elif "missing-policy-layer-evidence" not in self.unknown_facts:
            raise ValueError("A resource without policy layers must record missing evidence")
        summary = _summarize_resource(
            self.layer_decisions,
            authority_allowed=(
                self.authority_verdict is AuthorityEvaluationVerdict.ALLOW
                and authority_resource_decision.verdict is AuthorityEvaluationVerdict.ALLOW
            ),
            unknown_facts=self.unknown_facts,
        )
        if (
            self.verdict != summary.verdict
            or self.allowed_modes != summary.allowed_modes
            or self.obligations != summary.obligations
            or self.matched_grants != summary.matched_grants
            or self.matched_denials != summary.matched_denials
            or self.bundle_digests != summary.bundle_digests
            or self.reason_code != summary.reason_code
            or self.explanation != summary.explanation
        ):
            raise ValueError("Resource policy aggregate contradicts its layer evidence")
        if self.aggregate_digest != canonical_digest(_resource_decision_payload(self)):
            raise ValueError("Resource policy aggregate digest does not match its evidence")
        return self


class AggregatePolicyDecision(StrictModel):
    """Whole-action result; every resource must independently be eligible."""

    normalized_action: NormalizedAction
    authority_decision: EnforcedAuthorityDecision
    policy_snapshot: PolicyLayerSnapshot
    layer_inputs: tuple[PolicyLayerInput, ...] = Field(max_length=MAX_POLICY_BUNDLES)
    resource_inputs: tuple[PolicyResourceInput, ...] = Field(
        min_length=1, max_length=MAX_RESOURCE_USES
    )
    input_unknown_facts: tuple[NonEmptyStr, ...] = Field(default=(), max_length=MAX_UNKNOWN_FACTS)
    verdict: PolicyVerdict
    allowed_modes: tuple[NonEmptyStr, ...] = Field(default=(), max_length=MAX_POLICY_MODES)
    obligations: tuple[NonEmptyStr, ...] = Field(default=(), max_length=MAX_POLICY_OBLIGATIONS)
    matched_grants: tuple[PolicyMatchReference, ...] = Field(
        default=(), max_length=MAX_POLICY_MATCHES
    )
    matched_denials: tuple[PolicyMatchReference, ...] = Field(
        default=(), max_length=MAX_POLICY_MATCHES
    )
    bundle_digests: tuple[Digest, ...] = Field(default=(), max_length=MAX_POLICY_BUNDLES)
    resource_decisions: tuple[ResourcePolicyDecision, ...] = Field(
        min_length=1, max_length=MAX_RESOURCE_USES
    )
    unknown_facts: tuple[NonEmptyStr, ...] = Field(default=(), max_length=MAX_UNKNOWN_FACTS)
    reason_code: NonEmptyStr
    explanation: NonEmptyStr
    aggregate_digest: Digest

    @field_validator("input_unknown_facts", "unknown_facts")
    @classmethod
    def _canonical_unknown_facts(cls, values: tuple[str, ...], info: object) -> tuple[str, ...]:
        return _canonical_unknown_facts(
            values,
            scope=f"action policy {getattr(info, 'field_name', 'unknown facts')}",
        )

    @model_validator(mode="after")
    def verify_aggregate_digest(self) -> AggregatePolicyDecision:
        layer_keys = tuple(_layer_sort_key(layer) for layer in self.layer_inputs)
        if len(layer_keys) != len(set(layer_keys)) or layer_keys != tuple(sorted(layer_keys)):
            raise ValueError("Action policy inputs require sorted unique policy layers")
        input_resource_refs = tuple(resource.resource_use_ref for resource in self.resource_inputs)
        if len(input_resource_refs) != len(
            set(input_resource_refs)
        ) or input_resource_refs != tuple(sorted(input_resource_refs)):
            raise ValueError("Action policy inputs require sorted unique resource uses")
        try:
            (
                normalized_action,
                authority_decision,
                policy_snapshot,
                layer_inputs,
                resource_inputs,
            ) = _validate_inputs(
                self.normalized_action,
                self.authority_decision,
                self.policy_snapshot,
                self.layer_inputs,
                self.resource_inputs,
                self.input_unknown_facts,
            )
        except AgentKernelError as error:
            raise ValueError("Action policy evaluation inputs are invalid") from error
        effective_unknown_facts = _effective_action_unknown_facts(
            layers=layer_inputs,
            policy_snapshot=policy_snapshot,
            unknown_facts=self.input_unknown_facts,
        )
        expected_resource_decisions = tuple(
            _resource_decision(
                normalized_action=normalized_action,
                resource=resource,
                layers=layer_inputs,
                authority_decision=authority_decision,
                action_unknown_facts=effective_unknown_facts,
            )
            for resource in resource_inputs
        )
        if self.resource_decisions != expected_resource_decisions:
            raise ValueError("Action policy evidence differs from deterministic re-evaluation")
        resource_refs = tuple(decision.resource_use_ref for decision in self.resource_decisions)
        if (
            not resource_refs
            or len(resource_refs) != len(set(resource_refs))
            or resource_refs != tuple(sorted(resource_refs))
        ):
            raise ValueError("Action policy evidence requires sorted unique resource decisions")
        if any(
            decision.authority_decision_digest != self.authority_decision.decision_digest
            or decision.authority_verdict is not self.authority_decision.verdict
            for decision in self.resource_decisions
        ):
            raise ValueError("Action and resource authority evidence differs")
        _validate_evidence_units(self.resource_decisions)
        summary = _summarize_action(self.resource_decisions)
        if (
            self.verdict != summary.verdict
            or self.allowed_modes != summary.allowed_modes
            or self.obligations != summary.obligations
            or self.matched_grants != summary.matched_grants
            or self.matched_denials != summary.matched_denials
            or self.bundle_digests != summary.bundle_digests
            or self.unknown_facts != summary.unknown_facts
            or self.reason_code != summary.reason_code
            or self.explanation != summary.explanation
        ):
            raise ValueError("Action policy aggregate contradicts its resource evidence")
        if self.aggregate_digest != canonical_digest(_action_decision_payload(self)):
            raise ValueError("Action policy aggregate digest does not match its evidence")
        return self


def _layer_decision_payload(evidence: PolicyLayerDecisionEvidence) -> dict[str, object]:
    return {
        "profile": "agentkernel.policy.layer-decision/v1",
        "identity": evidence.identity,
        "resource_use_ref": evidence.resource_use_ref,
        "context_digest": evidence.context_digest,
        "decision": evidence.decision,
        "input_unknown_facts": evidence.input_unknown_facts,
        "unknown_facts": evidence.unknown_facts,
    }


def _resource_decision_payload(decision: ResourcePolicyDecision) -> dict[str, object]:
    return {
        "profile": "agentkernel.policy.resource-aggregate/v1",
        "resource_use_ref": decision.resource_use_ref,
        "context_digest": decision.context_digest,
        "authority_decision_digest": decision.authority_decision_digest,
        "authority_verdict": decision.authority_verdict,
        "authority_resource_decision": decision.authority_resource_decision,
        "verdict": decision.verdict,
        "allowed_modes": decision.allowed_modes,
        "obligations": decision.obligations,
        "matched_grants": decision.matched_grants,
        "matched_denials": decision.matched_denials,
        "bundle_digests": decision.bundle_digests,
        "layer_decisions": decision.layer_decisions,
        "unknown_facts": decision.unknown_facts,
        "reason_code": decision.reason_code,
        "explanation": decision.explanation,
    }


def _action_decision_payload(decision: AggregatePolicyDecision) -> dict[str, object]:
    return {
        "profile": "agentkernel.policy.action-aggregate/v1",
        "normalized_action": decision.normalized_action,
        "authority_decision": decision.authority_decision,
        "policy_snapshot": decision.policy_snapshot,
        "layer_inputs": decision.layer_inputs,
        "resource_inputs": decision.resource_inputs,
        "input_unknown_facts": decision.input_unknown_facts,
        "verdict": decision.verdict,
        "allowed_modes": decision.allowed_modes,
        "obligations": decision.obligations,
        "matched_grants": decision.matched_grants,
        "matched_denials": decision.matched_denials,
        "bundle_digests": decision.bundle_digests,
        "resource_decisions": decision.resource_decisions,
        "unknown_facts": decision.unknown_facts,
        "reason_code": decision.reason_code,
        "explanation": decision.explanation,
    }


def _policy_snapshot_payload(snapshot: PolicyLayerSnapshot) -> dict[str, object]:
    return {
        "profile": "agentkernel.policy.layer-snapshot/v1",
        "identities": snapshot.identities,
    }


def _context_binding_payload(
    normalized_action: NormalizedAction,
    authority_decision: EnforcedAuthorityDecision,
    resource: PolicyResourceInput,
) -> dict[str, object]:
    return {
        "profile": "agentkernel.policy.context-binding/v1",
        "intent_hash": normalized_action.intent_hash,
        "authority_decision_digest": authority_decision.decision_digest,
        "resource_index": resource.resource_index,
        "resource_use_ref": resource.resource_use_ref,
        "context": resource.context,
    }


def _raise_duplicate(kind: str) -> None:
    raise AgentKernelError(
        ErrorCode.VALIDATION_ERROR,
        f"Duplicate {kind} is not valid policy evidence",
    )


def _canonical_semantic_text(value: str, *, scope: str) -> str:
    if not 1 <= len(value) <= _MAX_POLICY_TEXT_CHARS:
        raise ValueError(f"{scope} must contain 1..{_MAX_POLICY_TEXT_CHARS} characters")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{scope} must be valid UTF-8") from error
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{scope} must use Unicode NFC")
    return value


def _canonical_unknown_facts(values: tuple[str, ...], *, scope: str) -> tuple[str, ...]:
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{scope} unknown facts must be sorted and unique")
    for value in values:
        _canonical_semantic_text(value, scope=f"{scope} unknown facts")
    return values


def _validate_unknown_facts(facts: tuple[str, ...], *, scope: str) -> None:
    if len(facts) > MAX_UNKNOWN_FACTS:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            f"{scope} contains too many unknown policy facts",
        )
    try:
        for fact in facts:
            _canonical_semantic_text(fact, scope=f"{scope} unknown facts")
    except (TypeError, ValueError) as error:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            f"{scope} contains a non-canonical unknown policy fact",
        ) from error
    if len(facts) != len(set(facts)):
        _raise_duplicate(f"unknown fact in {scope}")
    try:
        _canonical_unknown_facts(tuple(sorted(facts)), scope=scope)
    except ValueError as error:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            f"{scope} contains a non-canonical unknown policy fact",
        ) from error


def _validate_inputs(
    normalized_action: NormalizedAction,
    authority_decision: EnforcedAuthorityDecision,
    policy_snapshot: PolicyLayerSnapshot,
    layers: tuple[PolicyLayerInput, ...],
    resources: tuple[PolicyResourceInput, ...],
    unknown_facts: tuple[str, ...],
) -> tuple[
    NormalizedAction,
    EnforcedAuthorityDecision,
    PolicyLayerSnapshot,
    tuple[PolicyLayerInput, ...],
    tuple[PolicyResourceInput, ...],
]:
    if not resources:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "At least one resource-use policy input is required",
        )
    if len(resources) > MAX_RESOURCE_USES or len(layers) > MAX_POLICY_BUNDLES:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "Policy aggregation input exceeds its configured bound",
        )

    # Unknown evidence is attacker-controlled and must be bounded/canonical before any
    # cross-product, union, or deterministic sorting work.
    _validate_unknown_facts(unknown_facts, scope="action")
    for layer in layers:
        _validate_unknown_facts(layer.unknown_facts, scope="policy layer")
    for resource in resources:
        _validate_unknown_facts(resource.unknown_facts, scope="resource use")
    total_declared_unknown_facts = (
        len(unknown_facts)
        + sum(len(layer.unknown_facts) for layer in layers)
        + sum(len(resource.unknown_facts) for resource in resources)
    )
    if total_declared_unknown_facts > MAX_UNKNOWN_FACTS:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "Policy aggregation contains too many unknown facts",
        )

    try:
        normalized_action = NormalizedAction.model_validate(
            normalized_action.model_dump(mode="python")
        )
        authority_decision = EnforcedAuthorityDecision.model_validate(
            authority_decision.model_dump(mode="python")
        )
        policy_snapshot = PolicyLayerSnapshot.model_validate(
            policy_snapshot.model_dump(mode="python")
        )
        layers = tuple(
            PolicyLayerInput.model_validate(layer.model_dump(mode="python")) for layer in layers
        )
        resources = tuple(
            PolicyResourceInput.model_validate(resource.model_dump(mode="python"))
            for resource in resources
        )
    except ValueError as error:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Policy aggregation contains invalid trusted input evidence",
        ) from error

    resource_refs = tuple(resource.resource_use_ref for resource in resources)
    if len(resource_refs) != len(set(resource_refs)):
        _raise_duplicate("resource-use reference")
    resource_indexes = tuple(resource.resource_index for resource in resources)
    if len(resource_indexes) != len(set(resource_indexes)):
        _raise_duplicate("resource-use index")

    expected_resource_refs = tuple(
        sorted(canonical_digest(resource_use) for resource_use in normalized_action.resource_uses)
    )
    if len(expected_resource_refs) != len(set(expected_resource_refs)):
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Normalized action resource-use digests are not unique",
        )
    if tuple(sorted(resource_refs)) != expected_resource_refs or tuple(
        sorted(resource_indexes)
    ) != tuple(range(len(normalized_action.resource_uses))):
        raise AgentKernelError(
            ErrorCode.EVIDENCE_UNAVAILABLE,
            "Policy resource inputs must cover all and only normalized action resource uses",
        )

    if (
        authority_decision.tenant_id != normalized_action.tenant_id
        or authority_decision.transaction_id != normalized_action.transaction_id
        or authority_decision.intent_hash != normalized_action.intent_hash
        or len(authority_decision.resource_decisions) != len(normalized_action.resource_uses)
    ):
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Authority decision is not bound to the normalized action",
        )
    resources_by_index = {resource.resource_index: resource for resource in resources}
    for index, (resource_use, authority_resource) in enumerate(
        zip(
            normalized_action.resource_uses,
            authority_decision.resource_decisions,
            strict=True,
        )
    ):
        if (
            authority_resource.resource_index != index
            or authority_resource.resource_use_digest != canonical_digest(resource_use)
            or authority_resource.authority_action != resource_use.authority_action
            or authority_resource.canonical_resource != resource_use.canonical_resource
            or authority_resource.data_classes != resource_use.data_classes
            or authority_resource.provenance_ids != resource_use.provenance_ids
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Authority resource evidence differs from the normalized action",
            )
        policy_resource = resources_by_index[index]
        if policy_resource.resource_use != resource_use:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Policy resource index differs from the normalized action",
            )
        expected_context = _trusted_policy_context(
            normalized_action,
            resource_use,
            authority_resource,
        )
        if policy_resource.context != expected_context:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Policy context differs from trusted normalized action and authority facts",
            )

    identities = tuple((layer.layer, layer.scope_id, layer.policy.bundle.name) for layer in layers)
    if len(identities) != len(set(identities)):
        _raise_duplicate("policy layer identity")

    policy_node_units = sum(
        1
        + sum(
            1 + len(rule.modes) + _condition_node_work_units(rule.when)
            for rule in layer.policy.bundle.rules
        )
        for layer in layers
    )
    work_units = len(resources) * max(1, policy_node_units)
    if work_units > MAX_POLICY_WORK_UNITS:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "Policy aggregation exceeds its deterministic work budget",
        )

    action_unknown_set = frozenset(unknown_facts)
    layer_unknown_sets = tuple(frozenset(layer.unknown_facts) for layer in layers)
    resource_unknown_sets = tuple(frozenset(resource.unknown_facts) for resource in resources)
    repeated_input_fact_units = sum(
        len(action_unknown_set | layer_unknown_set | resource_unknown_set)
        for resource_unknown_set in resource_unknown_sets
        for layer_unknown_set in layer_unknown_sets
    )
    action_material_units = (
        1
        + len(normalized_action.resource_uses)
        + len(normalized_action.semantic_arguments)
        + len(normalized_action.provenance)
        + sum(
            len(resource_use.data_classes) + len(resource_use.provenance_ids)
            for resource_use in normalized_action.resource_uses
        )
        + sum(len(argument.provenance_ids) for argument in normalized_action.semantic_arguments)
    )
    estimated_evidence_units = (
        (8 * work_units)
        + (2 * repeated_input_fact_units)
        + action_material_units
        + len(authority_decision.resource_decisions)
        + len(policy_snapshot.identities)
    )
    if estimated_evidence_units > MAX_POLICY_EVIDENCE_UNITS:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "Policy aggregation exceeds its deterministic evidence budget",
        )

    for layer in layers:
        if layer.policy.digest != canonical_digest(layer.policy.bundle):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Compiled policy bundle digest does not match its content",
            )
    return normalized_action, authority_decision, policy_snapshot, layers, resources


_SCOPE_EXPANSION_REASONS = frozenset(
    {
        AuthorityReasonCode.ACTION_NOT_GRANTED,
        AuthorityReasonCode.RESOURCE_NOT_GRANTED,
        AuthorityReasonCode.DATA_CLASS_NOT_GRANTED,
        AuthorityReasonCode.DELEGATION_ACTION_WIDENED,
        AuthorityReasonCode.DELEGATION_RESOURCE_WIDENED,
        AuthorityReasonCode.DELEGATION_DATA_CLASS_WIDENED,
        AuthorityReasonCode.WILDCARD_SCOPE_FORBIDDEN,
    }
)


def _requested_scope_expands(
    authority_resource: ResourceAuthorityDecision,
) -> bool | None:
    if (
        authority_resource.verdict is AuthorityEvaluationVerdict.ALLOW
        and authority_resource.reason_code is AuthorityReasonCode.AUTHORITY_GRANTED
    ):
        return False
    if authority_resource.reason_code in _SCOPE_EXPANSION_REASONS:
        return True
    return None


def _trusted_policy_context(
    normalized_action: NormalizedAction,
    resource_use: ResourceUse,
    authority_resource: ResourceAuthorityDecision,
) -> PolicyContext:
    provenance_by_id = {binding.provenance_id: binding for binding in normalized_action.provenance}
    try:
        provenance_trust = tuple(
            sorted(
                {
                    provenance_by_id[provenance_id].trust
                    for provenance_id in resource_use.provenance_ids
                },
                key=lambda trust: trust.value,
            )
        )
    except KeyError as error:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Policy resource use references missing normalized provenance",
        ) from error
    return PolicyContext(
        action=resource_use.authority_action,
        resource=resource_use.canonical_resource,
        provenance_trust=provenance_trust,
        requested_scope_expands=_requested_scope_expands(authority_resource),
        data_classes=resource_use.data_classes,
        destination_external=resource_use.destination_external,
        risk_class=normalized_action.risk_floor,
    )


def _condition_node_work_units(condition: object) -> int:
    units = 0
    pending = [condition]
    while pending:
        value = pending.pop()
        units += 1
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return units


def _effective_action_unknown_facts(
    *,
    layers: tuple[PolicyLayerInput, ...],
    policy_snapshot: PolicyLayerSnapshot,
    unknown_facts: tuple[str, ...],
) -> tuple[str, ...]:
    facts = set(unknown_facts)
    actual_identities = tuple(layer.identity for layer in layers)
    if not layers:
        facts.add("missing-policy-layer-evidence")
    if actual_identities != policy_snapshot.identities:
        facts.add("policy-layer-snapshot-mismatch")
    effective = tuple(sorted(facts))
    _validate_unknown_facts(effective, scope="effective action")
    return effective


def _validate_evidence_units(resource_decisions: Sequence[ResourcePolicyDecision]) -> None:
    units = len(resource_decisions)
    for resource in resource_decisions:
        units += (
            1
            + len(resource.allowed_modes)
            + len(resource.obligations)
            + len(resource.matched_grants)
            + len(resource.matched_denials)
            + len(resource.bundle_digests)
            + len(resource.unknown_facts)
            + len(resource.layer_decisions)
        )
        for evidence in resource.layer_decisions:
            decision = evidence.decision
            units += (
                len(evidence.input_unknown_facts)
                + len(evidence.unknown_facts)
                + len(decision.allowed_modes)
                + len(decision.obligations)
                + len(decision.matched_grants)
                + len(decision.matched_denials)
                + len(decision.matched_approvals)
                + len(decision.matched_shadows)
                + len(decision.unknown_rules)
                + len(decision.unknown_facts)
                + len(decision.blocking_unknown_rules)
                + len(decision.blocking_unknown_facts)
            )
    if units > MAX_POLICY_EVIDENCE_UNITS:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "Policy aggregation emitted too much deterministic evidence",
        )


def _layer_identity_sort_key(
    identity: PolicyLayerIdentity,
) -> tuple[int, str, str, str, str]:
    return (
        _LAYER_ORDER[identity.layer],
        identity.scope_id,
        identity.bundle_name,
        identity.bundle_version,
        identity.bundle_digest,
    )


def _layer_sort_key(layer: PolicyLayerInput) -> tuple[int, str, str, str, str]:
    return _layer_identity_sort_key(layer.identity)


def _layer_evidence_sort_key(
    evidence: PolicyLayerDecisionEvidence,
) -> tuple[int, str, str, str, str]:
    return _layer_identity_sort_key(evidence.identity)


def _qualified_matches(
    evidence: Sequence[PolicyLayerDecisionEvidence],
    attribute: str,
) -> tuple[str, ...]:
    qualified: set[str] = set()
    for item in evidence:
        rule_ids = getattr(item.decision, attribute)
        for rule_id in rule_ids:
            qualified.add(
                f"{item.identity.layer.value}:{item.identity.scope_id}:"
                f"{item.identity.bundle_digest}:{rule_id}"
            )
    return tuple(sorted(qualified))


def _decision_reason(
    *,
    authority_allowed: bool,
    blocking_unknown_facts: tuple[str, ...],
    decisions: Sequence[PolicyDecision],
    has_grant: bool,
    allowed_modes: set[str],
) -> tuple[PolicyVerdict, str, str]:
    denied = tuple(decision for decision in decisions if decision.verdict is PolicyVerdict.DENY)
    if any(decision.reason_code == ErrorCode.POLICY_DENIED.value for decision in denied):
        return (
            PolicyVerdict.DENY,
            ErrorCode.POLICY_DENIED.value,
            "At least one applicable policy bundle denied",
        )
    if denied and all(decision.reason_code == "MODE_CONFLICT" for decision in denied):
        return (
            PolicyVerdict.DENY,
            "MODE_CONFLICT",
            "Every applicable policy denial is a mode conflict",
        )
    if blocking_unknown_facts or any(
        decision.reason_code == ErrorCode.POLICY_UNKNOWN.value for decision in denied
    ):
        return (
            PolicyVerdict.DENY,
            ErrorCode.POLICY_UNKNOWN.value,
            "Policy evidence is incomplete or contains an explicit unknown fact",
        )
    if not authority_allowed:
        return (
            PolicyVerdict.DENY,
            ErrorCode.AUTHORITY_MISSING.value,
            "A complete allowed authority decision is required for policy eligibility",
        )
    if denied:
        return (
            PolicyVerdict.DENY,
            ErrorCode.POLICY_UNKNOWN.value,
            "Policy denials contain incompatible or incomplete evidence",
        )
    if not has_grant:
        return (
            PolicyVerdict.DENY,
            ErrorCode.POLICY_DENIED.value,
            "No applicable policy grant matched; abstention is not permission",
        )
    if not allowed_modes:
        return (
            PolicyVerdict.DENY,
            "MODE_CONFLICT",
            "Matched policy grants have no common allowed execution mode",
        )
    return (
        PolicyVerdict.ELIGIBLE,
        "POLICY_ELIGIBLE",
        "Authority and all applicable policy bundles permit this resource use",
    )


@dataclass(frozen=True, slots=True)
class _ResourceSummary:
    verdict: PolicyVerdict
    allowed_modes: tuple[str, ...]
    obligations: tuple[str, ...]
    matched_grants: tuple[str, ...]
    matched_denials: tuple[str, ...]
    bundle_digests: tuple[str, ...]
    reason_code: str
    explanation: str


def _summarize_resource(
    evidence: Sequence[PolicyLayerDecisionEvidence],
    *,
    authority_allowed: bool,
    unknown_facts: tuple[str, ...],
) -> _ResourceSummary:
    decisions = tuple(item.decision for item in evidence)
    eligible = tuple(
        decision for decision in decisions if decision.verdict is PolicyVerdict.ELIGIBLE
    )
    mode_sets = tuple(set(decision.allowed_modes) for decision in eligible)
    allowed_modes = set.intersection(*mode_sets) if mode_sets else set()
    blocking_unknown_facts = (
        tuple(
            sorted(
                {fact for layer_evidence in evidence for fact in layer_evidence.input_unknown_facts}
            )
        )
        if evidence
        else unknown_facts
    )
    verdict, reason_code, explanation = _decision_reason(
        authority_allowed=authority_allowed,
        blocking_unknown_facts=blocking_unknown_facts,
        decisions=decisions,
        has_grant=any(decision.matched_grants for decision in decisions),
        allowed_modes=allowed_modes,
    )
    summary = _ResourceSummary(
        verdict=verdict,
        allowed_modes=(tuple(sorted(allowed_modes)) if verdict is PolicyVerdict.ELIGIBLE else ()),
        obligations=tuple(
            sorted({obligation for decision in decisions for obligation in decision.obligations})
        ),
        matched_grants=_qualified_matches(evidence, "matched_grants"),
        matched_denials=_qualified_matches(evidence, "matched_denials"),
        bundle_digests=tuple(sorted(item.identity.bundle_digest for item in evidence)),
        reason_code=reason_code,
        explanation=explanation,
    )
    _validate_summary_bounds(summary)
    return summary


def _validate_summary_bounds(summary: _ResourceSummary | _ActionSummary) -> None:
    bounds = (
        ("allowed modes", summary.allowed_modes, MAX_POLICY_MODES),
        ("obligations", summary.obligations, MAX_POLICY_OBLIGATIONS),
        ("matched grants", summary.matched_grants, MAX_POLICY_MATCHES),
        ("matched denials", summary.matched_denials, MAX_POLICY_MATCHES),
        ("bundle digests", summary.bundle_digests, MAX_POLICY_BUNDLES),
    )
    for name, values, limit in bounds:
        if len(values) > limit:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                f"Policy aggregate contains too many {name}",
            )


@dataclass(frozen=True, slots=True)
class _ActionSummary:
    verdict: PolicyVerdict
    allowed_modes: tuple[str, ...]
    obligations: tuple[str, ...]
    matched_grants: tuple[str, ...]
    matched_denials: tuple[str, ...]
    bundle_digests: tuple[str, ...]
    unknown_facts: tuple[str, ...]
    reason_code: str
    explanation: str


def _summarize_action(
    resource_decisions: Sequence[ResourcePolicyDecision],
) -> _ActionSummary:
    obligations = tuple(
        sorted(
            {
                obligation
                for resource_decision in resource_decisions
                for obligation in resource_decision.obligations
            }
        )
    )
    matched_grants = tuple(
        sorted(
            {
                match
                for resource_decision in resource_decisions
                for match in resource_decision.matched_grants
            }
        )
    )
    matched_denials = tuple(
        sorted(
            {
                match
                for resource_decision in resource_decisions
                for match in resource_decision.matched_denials
            }
        )
    )
    unknown_facts = tuple(
        sorted(
            {
                fact
                for resource_decision in resource_decisions
                for fact in resource_decision.unknown_facts
            }
        )
    )
    layer_identity_sets = {
        tuple(_layer_evidence_sort_key(evidence) for evidence in decision.layer_decisions)
        for decision in resource_decisions
    }
    if len(layer_identity_sets) != 1:
        raise ValueError("Resource decisions were not evaluated against the same policy layers")
    bundle_sets = {decision.bundle_digests for decision in resource_decisions}
    bundle_digests = next(iter(bundle_sets))
    eligible_mode_sets = tuple(
        set(decision.allowed_modes)
        for decision in resource_decisions
        if decision.verdict is PolicyVerdict.ELIGIBLE
    )
    common_modes = set.intersection(*eligible_mode_sets) if eligible_mode_sets else set()

    denied_resources = tuple(
        decision for decision in resource_decisions if decision.verdict is PolicyVerdict.DENY
    )
    if denied_resources:
        verdict = PolicyVerdict.DENY
        reasons = {decision.reason_code for decision in denied_resources}
        if ErrorCode.POLICY_DENIED.value in reasons:
            reason_code = ErrorCode.POLICY_DENIED.value
            explanation = "At least one resource use is denied by policy"
        elif all(reason == "MODE_CONFLICT" for reason in reasons):
            reason_code = "MODE_CONFLICT"
            explanation = "Every denied resource has incompatible policy modes"
        elif ErrorCode.POLICY_UNKNOWN.value in reasons:
            reason_code = ErrorCode.POLICY_UNKNOWN.value
            explanation = "At least one resource lacks complete policy evidence"
        elif ErrorCode.AUTHORITY_MISSING.value in reasons:
            reason_code = ErrorCode.AUTHORITY_MISSING.value
            explanation = "The action lacks a complete allowed authority decision"
        else:
            reason_code = ErrorCode.POLICY_UNKNOWN.value
            explanation = "Resource denial reasons do not form complete policy evidence"
    else:
        verdict = PolicyVerdict.ELIGIBLE
        reason_code = "POLICY_ELIGIBLE"
        explanation = "Every resource use is independently authority- and policy-eligible"

    summary = _ActionSummary(
        verdict=verdict,
        # This is only the common summary. Heterogeneous eligible resources may have no common
        # mode; enforcement consumes each nested resource decision rather than treating an empty
        # action-level intersection as denial.
        allowed_modes=(tuple(sorted(common_modes)) if verdict is PolicyVerdict.ELIGIBLE else ()),
        obligations=obligations,
        matched_grants=matched_grants,
        matched_denials=matched_denials,
        bundle_digests=bundle_digests,
        unknown_facts=unknown_facts,
        reason_code=reason_code,
        explanation=explanation,
    )
    _validate_summary_bounds(summary)
    if len(summary.unknown_facts) > MAX_UNKNOWN_FACTS:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "Action policy aggregate contains too many unknown facts",
        )
    return summary


def _layer_evidence(
    layer: PolicyLayerInput,
    resource: PolicyResourceInput,
    action_unknown_facts: tuple[str, ...],
    context_digest: str,
) -> PolicyLayerDecisionEvidence:
    decision = layer.policy.evaluate(resource.context)
    input_unknown_facts = tuple(
        sorted(set(action_unknown_facts) | set(layer.unknown_facts) | set(resource.unknown_facts))
    )
    unknown_facts = tuple(sorted(set(input_unknown_facts) | set(decision.unknown_facts)))
    _validate_unknown_facts(decision.unknown_facts, scope="policy decision")
    _validate_unknown_facts(unknown_facts, scope="policy layer evidence")
    identity = layer.identity
    unsigned = PolicyLayerDecisionEvidence.model_construct(
        identity=identity,
        resource_use_ref=resource.resource_use_ref,
        context_digest=context_digest,
        decision=decision,
        input_unknown_facts=input_unknown_facts,
        unknown_facts=unknown_facts,
        decision_digest="sha256:" + ("0" * 64),
    )
    return PolicyLayerDecisionEvidence(
        **unsigned.model_dump(exclude={"decision_digest"}),
        decision_digest=canonical_digest(_layer_decision_payload(unsigned)),
    )


def _resource_decision(
    *,
    normalized_action: NormalizedAction,
    resource: PolicyResourceInput,
    layers: tuple[PolicyLayerInput, ...],
    authority_decision: EnforcedAuthorityDecision,
    action_unknown_facts: tuple[str, ...],
) -> ResourcePolicyDecision:
    authority_resource_decision = authority_decision.resource_decisions[resource.resource_index]
    context_digest = canonical_digest(
        _context_binding_payload(normalized_action, authority_decision, resource)
    )
    evidence = tuple(
        _layer_evidence(layer, resource, action_unknown_facts, context_digest) for layer in layers
    )
    unknown_facts = (
        tuple(sorted({fact for item in evidence for fact in item.unknown_facts}))
        if evidence
        else tuple(sorted(set(action_unknown_facts) | set(resource.unknown_facts)))
    )
    summary = _summarize_resource(
        evidence,
        authority_allowed=(
            authority_decision.verdict is AuthorityEvaluationVerdict.ALLOW
            and authority_resource_decision.verdict is AuthorityEvaluationVerdict.ALLOW
        ),
        unknown_facts=unknown_facts,
    )
    unsigned = ResourcePolicyDecision.model_construct(
        resource_use_ref=resource.resource_use_ref,
        context_digest=context_digest,
        authority_decision_digest=authority_decision.decision_digest,
        authority_verdict=authority_decision.verdict,
        authority_resource_decision=authority_resource_decision,
        verdict=summary.verdict,
        allowed_modes=summary.allowed_modes,
        obligations=summary.obligations,
        matched_grants=summary.matched_grants,
        matched_denials=summary.matched_denials,
        bundle_digests=summary.bundle_digests,
        layer_decisions=evidence,
        unknown_facts=unknown_facts,
        reason_code=summary.reason_code,
        explanation=summary.explanation,
        aggregate_digest="sha256:" + ("0" * 64),
    )
    return ResourcePolicyDecision(
        **unsigned.model_dump(exclude={"aggregate_digest"}),
        aggregate_digest=canonical_digest(_resource_decision_payload(unsigned)),
    )


def evaluate_policy_layers(
    *,
    normalized_action: NormalizedAction,
    authority_decision: EnforcedAuthorityDecision,
    policy_snapshot: PolicyLayerSnapshot,
    layers: Sequence[PolicyLayerInput],
    resources: Sequence[PolicyResourceInput],
    unknown_facts: Sequence[str] = (),
) -> AggregatePolicyDecision:
    """Evaluate every bundle/resource and aggregate without order-based overrides.

    This function intentionally implements only the repository's deterministic DSL subset.
    Constraint reduction and Z3 evidence are not represented as successful checks here.
    """

    if len(unknown_facts) > MAX_UNKNOWN_FACTS:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "Action contains too many unknown policy facts",
        )
    action_unknown_facts = tuple(unknown_facts)
    _validate_unknown_facts(action_unknown_facts, scope="action")
    if len(layers) > MAX_POLICY_BUNDLES or len(resources) > MAX_RESOURCE_USES:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "Policy aggregation input exceeds its configured bound",
        )
    layer_inputs = tuple(layers)
    resource_inputs = tuple(resources)
    (
        normalized_action,
        authority_decision,
        policy_snapshot,
        layer_inputs,
        resource_inputs,
    ) = _validate_inputs(
        normalized_action,
        authority_decision,
        policy_snapshot,
        layer_inputs,
        resource_inputs,
        action_unknown_facts,
    )
    ordered_layers = tuple(sorted(layer_inputs, key=_layer_sort_key))
    ordered_resources = tuple(sorted(resource_inputs, key=lambda item: item.resource_use_ref))
    effective_unknown_facts = _effective_action_unknown_facts(
        layers=ordered_layers,
        policy_snapshot=policy_snapshot,
        unknown_facts=action_unknown_facts,
    )

    resource_decisions = tuple(
        _resource_decision(
            normalized_action=normalized_action,
            resource=resource,
            layers=ordered_layers,
            authority_decision=authority_decision,
            action_unknown_facts=effective_unknown_facts,
        )
        for resource in ordered_resources
    )
    _validate_evidence_units(resource_decisions)
    summary = _summarize_action(resource_decisions)
    unsigned = AggregatePolicyDecision.model_construct(
        normalized_action=normalized_action,
        authority_decision=authority_decision,
        policy_snapshot=policy_snapshot,
        layer_inputs=ordered_layers,
        resource_inputs=ordered_resources,
        input_unknown_facts=tuple(sorted(action_unknown_facts)),
        verdict=summary.verdict,
        allowed_modes=summary.allowed_modes,
        obligations=summary.obligations,
        matched_grants=summary.matched_grants,
        matched_denials=summary.matched_denials,
        bundle_digests=summary.bundle_digests,
        resource_decisions=resource_decisions,
        unknown_facts=summary.unknown_facts,
        reason_code=summary.reason_code,
        explanation=summary.explanation,
        aggregate_digest="sha256:" + ("0" * 64),
    )
    return AggregatePolicyDecision(
        **unsigned.model_dump(exclude={"aggregate_digest"}),
        aggregate_digest=canonical_digest(_action_decision_payload(unsigned)),
    )
