"""Bounded policy DSL compiler and deny-dominant deterministic evaluator."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any, Self, cast

import yaml
from pydantic import BaseModel, Field, JsonValue, TypeAdapter, ValidationError, model_validator
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver

from agentkernel.authority.evaluator import CapabilityResourceScope, resource_scope_contains
from agentkernel.canonical import canonical_json_bytes, sha256_digest
from agentkernel.domain.enums import ProvenanceTrust, RiskClass
from agentkernel.domain.models import (
    CanonicalResource,
    Digest,
    NonEmptyStr,
    PolicyBundle,
    PolicyDefault,
    PolicyEffect,
    StrictModel,
)
from agentkernel.errors import AgentKernelError, ErrorCode

_ALLOWED_PREDICATES = frozenset(
    {
        "action_in",
        "resource_within",
        "provenance_trust_in",
        "requested_scope_expands",
        "data_class_in",
        "destination_external",
        "risk_class_in",
    }
)
_ALLOWED_MODES = frozenset(
    {
        "read",
        "stage",
        "commit_reversible",
        "commit_compensatable",
        "commit_irreversible",
        "model_external",
    }
)
_MAX_POLICY_BYTES = 256 * 1024
_MAX_NODES = 10_000
_MAX_DEPTH = 32
_POLICY_RESOURCE_SCOPE_ADAPTER = TypeAdapter(CapabilityResourceScope)


def _require_semantic_text(value: str, *, field_name: str) -> None:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field_name} must be valid UTF-8") from error
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{field_name} must use Unicode NFC")


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys and merge-key ambiguity."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise ConstructorError(
                "while constructing a policy mapping",
                node.start_mark,
                "YAML merge keys are not allowed in policy files",
                key_node.start_mark,
            )
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise ConstructorError(
                "while constructing a policy mapping",
                node.start_mark,
                "policy mapping keys must be scalar and hashable",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise ConstructorError(
                "while constructing a policy mapping",
                node.start_mark,
                f"duplicate policy key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class PolicyVerdict(StrEnum):
    ELIGIBLE = "ELIGIBLE"
    DENY = "DENY"
    ABSTAIN = "ABSTAIN"


class PolicyContext(StrictModel):
    action: NonEmptyStr
    resource: CanonicalResource
    provenance_trust: tuple[ProvenanceTrust, ...] | None = Field(default=None, max_length=64)
    requested_scope_expands: bool | None = None
    data_classes: tuple[NonEmptyStr, ...] | None = Field(default=None, max_length=64)
    destination_external: bool | None = None
    risk_class: RiskClass

    @model_validator(mode="after")
    def _canonical_semantic_strings(self) -> Self:
        _require_semantic_text(self.action, field_name="policy action")
        if self.data_classes is not None:
            if self.data_classes != tuple(sorted(set(self.data_classes))):
                raise ValueError("Policy context data classes must be sorted and unique")
            for data_class in self.data_classes:
                _require_semantic_text(data_class, field_name="policy data class")
        if self.provenance_trust is not None and self.provenance_trust != tuple(
            sorted(set(self.provenance_trust), key=lambda value: value.value)
        ):
            raise ValueError("Policy context provenance classes must be sorted and unique")
        return self


class PolicyDecision(StrictModel):
    verdict: PolicyVerdict
    allowed_modes: tuple[NonEmptyStr, ...] = Field(default=(), max_length=16)
    obligations: tuple[NonEmptyStr, ...] = Field(default=(), max_length=2)
    matched_grants: tuple[NonEmptyStr, ...] = Field(default=(), max_length=2_048)
    matched_denials: tuple[NonEmptyStr, ...] = Field(default=(), max_length=2_048)
    matched_approvals: tuple[NonEmptyStr, ...] = Field(default=(), max_length=2_048)
    matched_shadows: tuple[NonEmptyStr, ...] = Field(default=(), max_length=2_048)
    unknown_rules: tuple[NonEmptyStr, ...] = Field(default=(), max_length=2_048)
    unknown_facts: tuple[NonEmptyStr, ...] = Field(default=(), max_length=256)
    blocking_unknown_rules: tuple[NonEmptyStr, ...] = Field(default=(), max_length=2_048)
    blocking_unknown_facts: tuple[NonEmptyStr, ...] = Field(default=(), max_length=256)
    reason_code: NonEmptyStr
    bundle_digest: Digest

    @model_validator(mode="after")
    def _consistent_verdict_evidence(self) -> Self:
        canonical_fields = {
            "allowed_modes": self.allowed_modes,
            "obligations": self.obligations,
            "matched_grants": self.matched_grants,
            "matched_denials": self.matched_denials,
            "matched_approvals": self.matched_approvals,
            "matched_shadows": self.matched_shadows,
            "unknown_rules": self.unknown_rules,
            "unknown_facts": self.unknown_facts,
            "blocking_unknown_rules": self.blocking_unknown_rules,
            "blocking_unknown_facts": self.blocking_unknown_facts,
        }
        for field_name, values in canonical_fields.items():
            if values != tuple(sorted(set(values))):
                raise ValueError(f"Policy decision {field_name} must be sorted and unique")
            for value in values:
                _require_semantic_text(value, field_name=f"policy decision {field_name}")
        if bool(self.unknown_rules) != bool(self.unknown_facts):
            raise ValueError("Policy decision unknown rules and facts must be recorded together")
        if bool(self.blocking_unknown_rules) != bool(self.blocking_unknown_facts):
            raise ValueError(
                "Policy decision blocking unknown rules and facts must be recorded together"
            )
        if not set(self.blocking_unknown_rules) <= set(self.unknown_rules) or not set(
            self.blocking_unknown_facts
        ) <= set(self.unknown_facts):
            raise ValueError(
                "Blocking unknown policy evidence must be part of all unknown evidence"
            )
        if set(self.matched_grants) & set(self.matched_denials):
            raise ValueError("A policy rule cannot be both a matched grant and denial")
        expected_obligations = tuple(
            obligation
            for obligation, matched in (
                ("approval", self.matched_approvals),
                ("shadow", self.matched_shadows),
            )
            if matched
        )
        if self.obligations != expected_obligations:
            raise ValueError("Policy obligations do not match their rule evidence")
        if self.blocking_unknown_rules and (
            self.verdict is not PolicyVerdict.DENY or self.allowed_modes
        ):
            raise ValueError("Blocking unknown policy evidence must deny eligibility")

        if self.matched_denials:
            if (
                self.verdict is not PolicyVerdict.DENY
                or self.reason_code != ErrorCode.POLICY_DENIED.value
                or self.allowed_modes
            ):
                raise ValueError("Matched policy denials must produce a deny decision")
            return self

        if self.verdict is PolicyVerdict.ELIGIBLE:
            if (
                self.reason_code != "POLICY_ELIGIBLE"
                or not self.matched_grants
                or not self.allowed_modes
                or self.blocking_unknown_rules
            ):
                raise ValueError("Eligible policy evidence requires grants and allowed modes")
            return self

        if self.allowed_modes:
            raise ValueError("Non-eligible policy evidence cannot expose allowed modes")
        if self.verdict is PolicyVerdict.ABSTAIN:
            if (
                self.reason_code != "POLICY_ABSTAINED"
                or self.matched_grants
                or self.matched_denials
                or self.blocking_unknown_rules
            ):
                raise ValueError("Abstaining policy evidence has contradictory matches or reason")
            return self

        if self.reason_code == ErrorCode.POLICY_UNKNOWN.value:
            if not self.blocking_unknown_rules or not self.blocking_unknown_facts:
                raise ValueError("POLICY_UNKNOWN requires the blocking unknown evidence used")
        elif self.reason_code == "MODE_CONFLICT":
            if not self.matched_grants:
                raise ValueError("MODE_CONFLICT requires at least one matched grant")
        elif self.reason_code == ErrorCode.POLICY_DENIED.value:
            if self.matched_grants:
                raise ValueError("Default policy denial cannot contain an unmatched grant")
        else:
            raise ValueError("Denied policy evidence has an unsupported reason")
        return self


class _TruthValue(StrEnum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class _ConditionResult:
    truth: _TruthValue
    unknown_facts: frozenset[str] = frozenset()


class CompiledPolicy(StrictModel):
    bundle: PolicyBundle
    digest: Digest

    @model_validator(mode="after")
    def _digest_binds_bundle(self) -> Self:
        try:
            bundle = PolicyBundle.model_validate(self.bundle.model_dump(mode="python"))
            _bounded_shape(bundle)
            _validate_bundle_semantics(bundle)
        except AgentKernelError as error:
            raise ValueError("Compiled policy bundle violates compiler semantics") from error
        except (AttributeError, TypeError, ValidationError, ValueError) as error:
            raise ValueError("Compiled policy bundle is not a canonical contract") from error
        canonical = canonical_json_bytes(bundle)
        if len(canonical) > _MAX_POLICY_BYTES:
            raise ValueError("Compiled policy bundle exceeds its byte limit")
        if self.digest != sha256_digest(canonical):
            raise ValueError("Compiled policy digest does not match its bundle")
        return self

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        matched_grants: list[str] = []
        matched_denials: list[str] = []
        matched_approvals: list[str] = []
        matched_shadows: list[str] = []
        obligations: set[str] = set()
        mode_sets: list[set[str]] = []
        unknown_grant_mode_sets: list[set[str]] = []
        unknown_grant_rules: list[str] = []
        unknown_grant_facts: set[str] = set()
        unknown_rules: list[str] = []
        unknown_facts: set[str] = set()
        blocking_unknown_rules: list[str] = []
        blocking_unknown_facts: set[str] = set()
        for rule in self.bundle.rules:
            condition = _match_condition(rule.when, context)
            if condition.truth is _TruthValue.FALSE:
                continue
            if condition.truth is _TruthValue.UNKNOWN:
                unknown_rules.append(rule.rule_id)
                unknown_facts.update(condition.unknown_facts)
                if rule.effect is PolicyEffect.GRANT:
                    unknown_grant_rules.append(rule.rule_id)
                    unknown_grant_facts.update(condition.unknown_facts)
                    unknown_grant_mode_sets.append(set(rule.modes))
                elif rule.effect in {
                    PolicyEffect.DENY,
                    PolicyEffect.REQUIRE_APPROVAL,
                    PolicyEffect.REQUIRE_SHADOW,
                }:
                    blocking_unknown_rules.append(rule.rule_id)
                    blocking_unknown_facts.update(condition.unknown_facts)
                continue
            if rule.effect is PolicyEffect.DENY:
                matched_denials.append(rule.rule_id)
            elif rule.effect is PolicyEffect.GRANT:
                matched_grants.append(rule.rule_id)
                mode_sets.append(set(rule.modes))
            elif rule.effect is PolicyEffect.REQUIRE_APPROVAL:
                obligations.add("approval")
                matched_approvals.append(rule.rule_id)
            elif rule.effect is PolicyEffect.REQUIRE_SHADOW:
                obligations.add("shadow")
                matched_shadows.append(rule.rule_id)

        if matched_denials:
            return PolicyDecision(
                verdict=PolicyVerdict.DENY,
                matched_grants=tuple(sorted(matched_grants)),
                matched_denials=tuple(sorted(matched_denials)),
                matched_approvals=tuple(sorted(matched_approvals)),
                matched_shadows=tuple(sorted(matched_shadows)),
                obligations=tuple(sorted(obligations)),
                unknown_rules=tuple(sorted(unknown_rules)),
                unknown_facts=tuple(sorted(unknown_facts)),
                blocking_unknown_rules=tuple(sorted(blocking_unknown_rules)),
                blocking_unknown_facts=tuple(sorted(blocking_unknown_facts)),
                reason_code=ErrorCode.POLICY_DENIED.value,
                bundle_digest=self.digest,
            )
        if blocking_unknown_rules:
            return PolicyDecision(
                verdict=PolicyVerdict.DENY,
                matched_grants=tuple(sorted(matched_grants)),
                matched_approvals=tuple(sorted(matched_approvals)),
                matched_shadows=tuple(sorted(matched_shadows)),
                obligations=tuple(sorted(obligations)),
                unknown_rules=tuple(sorted(unknown_rules)),
                unknown_facts=tuple(sorted(unknown_facts)),
                blocking_unknown_rules=tuple(sorted(blocking_unknown_rules)),
                blocking_unknown_facts=tuple(sorted(blocking_unknown_facts)),
                reason_code=ErrorCode.POLICY_UNKNOWN.value,
                bundle_digest=self.digest,
            )
        if not matched_grants and unknown_grant_rules:
            return PolicyDecision(
                verdict=PolicyVerdict.DENY,
                obligations=tuple(sorted(obligations)),
                matched_approvals=tuple(sorted(matched_approvals)),
                matched_shadows=tuple(sorted(matched_shadows)),
                unknown_rules=tuple(sorted(unknown_rules)),
                unknown_facts=tuple(sorted(unknown_facts)),
                blocking_unknown_rules=tuple(sorted(unknown_grant_rules)),
                blocking_unknown_facts=tuple(sorted(unknown_grant_facts)),
                reason_code=ErrorCode.POLICY_UNKNOWN.value,
                bundle_digest=self.digest,
            )
        if not matched_grants:
            return PolicyDecision(
                verdict=(
                    PolicyVerdict.DENY
                    if self.bundle.default is PolicyDefault.DENY
                    else PolicyVerdict.ABSTAIN
                ),
                obligations=tuple(sorted(obligations)),
                matched_approvals=tuple(sorted(matched_approvals)),
                matched_shadows=tuple(sorted(matched_shadows)),
                unknown_rules=tuple(sorted(unknown_rules)),
                unknown_facts=tuple(sorted(unknown_facts)),
                reason_code=(
                    ErrorCode.POLICY_DENIED.value
                    if self.bundle.default is PolicyDefault.DENY
                    else "POLICY_ABSTAINED"
                ),
                bundle_digest=self.digest,
            )
        possible_mode_sets = (*mode_sets, *unknown_grant_mode_sets)
        allowed_modes = set.intersection(*possible_mode_sets) if possible_mode_sets else set()
        if not allowed_modes:
            if unknown_grant_rules:
                return PolicyDecision(
                    verdict=PolicyVerdict.DENY,
                    matched_grants=tuple(sorted(matched_grants)),
                    matched_approvals=tuple(sorted(matched_approvals)),
                    matched_shadows=tuple(sorted(matched_shadows)),
                    obligations=tuple(sorted(obligations)),
                    unknown_rules=tuple(sorted(unknown_rules)),
                    unknown_facts=tuple(sorted(unknown_facts)),
                    blocking_unknown_rules=tuple(sorted(unknown_grant_rules)),
                    blocking_unknown_facts=tuple(sorted(unknown_grant_facts)),
                    reason_code=ErrorCode.POLICY_UNKNOWN.value,
                    bundle_digest=self.digest,
                )
            return PolicyDecision(
                verdict=PolicyVerdict.DENY,
                matched_grants=tuple(sorted(matched_grants)),
                matched_approvals=tuple(sorted(matched_approvals)),
                matched_shadows=tuple(sorted(matched_shadows)),
                obligations=tuple(sorted(obligations)),
                unknown_rules=tuple(sorted(unknown_rules)),
                unknown_facts=tuple(sorted(unknown_facts)),
                reason_code="MODE_CONFLICT",
                bundle_digest=self.digest,
            )
        return PolicyDecision(
            verdict=PolicyVerdict.ELIGIBLE,
            allowed_modes=tuple(sorted(allowed_modes)),
            obligations=tuple(sorted(obligations)),
            matched_grants=tuple(sorted(matched_grants)),
            matched_approvals=tuple(sorted(matched_approvals)),
            matched_shadows=tuple(sorted(matched_shadows)),
            unknown_rules=tuple(sorted(unknown_rules)),
            unknown_facts=tuple(sorted(unknown_facts)),
            reason_code="POLICY_ELIGIBLE",
            bundle_digest=self.digest,
        )


def _bounded_utf8_size(value: str, *, total: list[int]) -> None:
    """Count UTF-8 bytes without first allocating an encoded copy of an untrusted string."""

    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Policy strings must be valid Unicode scalar values",
            )
        total[0] += (
            1 if codepoint <= 0x7F else 2 if codepoint <= 0x7FF else 3 if codepoint <= 0xFFFF else 4
        )
        if total[0] > _MAX_POLICY_BYTES:
            raise AgentKernelError(ErrorCode.RESOURCE_LIMIT_EXCEEDED, "Policy is too large")


def _bounded_shape(
    value: Any,
    *,
    depth: int = 0,
    seen: list[int] | None = None,
    utf8_size: list[int] | None = None,
) -> None:
    if depth > _MAX_DEPTH:
        raise AgentKernelError(ErrorCode.RESOURCE_LIMIT_EXCEEDED, "Policy nesting is too deep")
    nodes = seen if seen is not None else [0]
    encoded = utf8_size if utf8_size is not None else [0]
    nodes[0] += 1
    if nodes[0] > _MAX_NODES:
        raise AgentKernelError(ErrorCode.RESOURCE_LIMIT_EXCEEDED, "Policy has too many nodes")
    if isinstance(value, BaseModel):
        for field_name in type(value).model_fields:
            _bounded_utf8_size(field_name, total=encoded)
            _bounded_shape(
                getattr(value, field_name),
                depth=depth + 1,
                seen=nodes,
                utf8_size=encoded,
            )
    elif isinstance(value, Enum):
        _bounded_shape(value.value, depth=depth, seen=nodes, utf8_size=encoded)
    elif isinstance(value, dict):
        for key, item in value.items():
            _bounded_shape(key, depth=depth + 1, seen=nodes, utf8_size=encoded)
            _bounded_shape(item, depth=depth + 1, seen=nodes, utf8_size=encoded)
    elif isinstance(value, list | tuple):
        for item in value:
            _bounded_shape(item, depth=depth + 1, seen=nodes, utf8_size=encoded)
    elif isinstance(value, str):
        _bounded_utf8_size(value, total=encoded)


def _validate_condition(condition: dict[str, JsonValue], *, depth: int = 0) -> None:
    if depth > _MAX_DEPTH or len(condition) != 1:
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Policy condition must have one key")
    key, value = next(iter(condition.items()))
    if key in {"all", "any"}:
        if not isinstance(value, list) or not value:
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, f"{key} requires a non-empty list")
        for child in value:
            if not isinstance(child, dict):
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR, "Condition child must be an object"
                )
            _validate_condition(child, depth=depth + 1)
        return
    if key not in _ALLOWED_PREDICATES:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Unknown policy predicate",
            details={"predicate": key},
        )
    if key in {"requested_scope_expands", "destination_external"}:
        if not isinstance(value, bool):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                f"{key} requires a boolean",
            )
        return
    if key == "resource_within":
        if not isinstance(value, str) or not value:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "resource_within requires a non-empty string",
            )
        try:
            _POLICY_RESOURCE_SCOPE_ADAPTER.validate_python(value)
        except ValueError as error:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "resource_within requires an exact canonical resource or terminal /** scope",
            ) from error
        return
    values = _string_values(value)
    if not values or any(not item for item in values):
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            f"{key} requires a non-empty list of non-empty strings",
        )
    if key == "provenance_trust_in":
        allowed = {item.value for item in ProvenanceTrust}
        if not set(values) <= allowed:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "provenance_trust_in contains an unknown provenance class",
            )
    if key == "risk_class_in":
        allowed = {item.value for item in RiskClass}
        if not set(values) <= allowed:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "risk_class_in contains an unknown risk class",
            )


def _validate_bundle_semantics(bundle: PolicyBundle) -> None:
    rule_ids = tuple(rule.rule_id for rule in bundle.rules)
    if len(rule_ids) != len(set(rule_ids)):
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Policy rule IDs must be unique")
    for rule in bundle.rules:
        _validate_condition(rule.when)
        if rule.effect is PolicyEffect.GRANT and not rule.modes:
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "A grant must declare modes")
        if len(rule.modes) != len(set(rule.modes)):
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Policy grant modes must be unique")
        if rule.effect is PolicyEffect.GRANT and not set(rule.modes) <= _ALLOWED_MODES:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "A grant contains an unknown execution mode",
            )
        if rule.effect is not PolicyEffect.GRANT and rule.modes:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Only grant rules may declare allowed modes",
            )


def compile_policy(bundle: PolicyBundle) -> CompiledPolicy:
    try:
        bundle = PolicyBundle.model_validate(bundle.model_dump(mode="python"))
    except (AttributeError, TypeError, ValidationError, ValueError) as error:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Policy bundle is not a canonical public contract",
        ) from error
    _bounded_shape(bundle)
    _validate_bundle_semantics(bundle)
    canonical = canonical_json_bytes(bundle)
    if len(canonical) > _MAX_POLICY_BYTES:
        raise AgentKernelError(ErrorCode.RESOURCE_LIMIT_EXCEEDED, "Policy is too large")
    return CompiledPolicy(bundle=bundle, digest=sha256_digest(canonical))


def load_policy(path: Path) -> CompiledPolicy:
    with path.open("rb") as policy_stream:
        raw = policy_stream.read(_MAX_POLICY_BYTES + 1)
    if len(raw) > _MAX_POLICY_BYTES:
        raise AgentKernelError(ErrorCode.RESOURCE_LIMIT_EXCEEDED, "Policy file is too large")
    try:
        document = yaml.load(raw, Loader=_UniqueKeySafeLoader)  # noqa: S506  # nosec B506
    except yaml.YAMLError as error:
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Policy YAML is invalid") from error
    _bounded_shape(document)
    try:
        bundle = PolicyBundle.model_validate(document)
    except ValueError as error:
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Policy schema is invalid") from error
    return compile_policy(bundle)


def _string_values(value: JsonValue) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Predicate requires a string list")
    values = cast("tuple[str, ...]", tuple(value))
    try:
        for item in values:
            _require_semantic_text(item, field_name="policy predicate string")
    except ValueError as error:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Policy predicate strings must be canonical UTF-8 Unicode NFC",
        ) from error
    return values


def _known(outcome: bool) -> _ConditionResult:
    return _ConditionResult(_TruthValue.TRUE if outcome else _TruthValue.FALSE)


def _unknown(fact: str) -> _ConditionResult:
    return _ConditionResult(_TruthValue.UNKNOWN, frozenset({fact}))


def _match_condition(
    condition: dict[str, JsonValue],
    context: PolicyContext,
) -> _ConditionResult:
    key, value = next(iter(condition.items()))
    if key in {"all", "any"}:
        children = cast_conditions(value)
        outcomes = tuple(_match_condition(child, context) for child in children)
        if key == "all":
            if any(outcome.truth is _TruthValue.FALSE for outcome in outcomes):
                return _ConditionResult(_TruthValue.FALSE)
            if any(outcome.truth is _TruthValue.UNKNOWN for outcome in outcomes):
                return _ConditionResult(
                    _TruthValue.UNKNOWN,
                    frozenset(fact for outcome in outcomes for fact in outcome.unknown_facts),
                )
            return _ConditionResult(_TruthValue.TRUE)
        if any(outcome.truth is _TruthValue.TRUE for outcome in outcomes):
            return _ConditionResult(_TruthValue.TRUE)
        if any(outcome.truth is _TruthValue.UNKNOWN for outcome in outcomes):
            return _ConditionResult(
                _TruthValue.UNKNOWN,
                frozenset(fact for outcome in outcomes for fact in outcome.unknown_facts),
            )
        return _ConditionResult(_TruthValue.FALSE)
    if key == "action_in":
        return _known(context.action in _string_values(value))
    if key == "resource_within":
        if not isinstance(value, str):
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "resource_within requires a string")
        return _known(resource_scope_contains(value, context.resource))
    if key == "provenance_trust_in":
        if context.provenance_trust is None:
            return _unknown("provenance_trust")
        return _known(bool(set(context.provenance_trust) & set(_string_values(value))))
    if key == "requested_scope_expands":
        if context.requested_scope_expands is None:
            return _unknown("requested_scope_expands")
        return _known(isinstance(value, bool) and context.requested_scope_expands is value)
    if key == "data_class_in":
        if context.data_classes is None:
            return _unknown("data_classes")
        return _known(bool(set(context.data_classes) & set(_string_values(value))))
    if key == "destination_external":
        if context.destination_external is None:
            return _unknown("destination_external")
        return _known(isinstance(value, bool) and context.destination_external is value)
    if key == "risk_class_in":
        return _known(context.risk_class.value in _string_values(value))
    raise AgentKernelError(ErrorCode.POLICY_UNKNOWN, "Policy predicate was not compiled")


def cast_conditions(value: JsonValue) -> tuple[dict[str, JsonValue], ...]:
    if not isinstance(value, list) or not all(isinstance(child, dict) for child in value):
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Logical condition is malformed")
    return cast("tuple[dict[str, JsonValue], ...]", tuple(value))
