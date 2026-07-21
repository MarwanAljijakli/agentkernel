"""Bounded policy DSL compiler and deny-dominant deterministic evaluator."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import JsonValue
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver

from agentkernel.authority.service import resource_matches
from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import ProvenanceTrust, RiskClass
from agentkernel.domain.models import (
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


class PolicyContext(StrictModel):
    action: NonEmptyStr
    resource: NonEmptyStr
    provenance_trust: tuple[ProvenanceTrust, ...] = ()
    requested_scope_expands: bool = False
    data_classes: tuple[NonEmptyStr, ...] = ()
    destination_external: bool = False
    risk_class: RiskClass


class PolicyDecision(StrictModel):
    verdict: PolicyVerdict
    allowed_modes: tuple[NonEmptyStr, ...] = ()
    obligations: tuple[NonEmptyStr, ...] = ()
    matched_grants: tuple[NonEmptyStr, ...] = ()
    matched_denials: tuple[NonEmptyStr, ...] = ()
    reason_code: NonEmptyStr
    bundle_digest: Digest


class CompiledPolicy(StrictModel):
    bundle: PolicyBundle
    digest: Digest

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        matched_grants: list[str] = []
        matched_denials: list[str] = []
        obligations: set[str] = set()
        mode_sets: list[set[str]] = []
        for rule in self.bundle.rules:
            if not _matches(rule.when, context):
                continue
            if rule.effect is PolicyEffect.DENY:
                matched_denials.append(rule.rule_id)
            elif rule.effect is PolicyEffect.GRANT:
                matched_grants.append(rule.rule_id)
                mode_sets.append(set(rule.modes))
            elif rule.effect is PolicyEffect.REQUIRE_APPROVAL:
                obligations.add("approval")
            elif rule.effect is PolicyEffect.REQUIRE_SHADOW:
                obligations.add("shadow")

        if matched_denials:
            return PolicyDecision(
                verdict=PolicyVerdict.DENY,
                matched_grants=tuple(matched_grants),
                matched_denials=tuple(matched_denials),
                obligations=tuple(sorted(obligations)),
                reason_code=ErrorCode.POLICY_DENIED.value,
                bundle_digest=self.digest,
            )
        if not matched_grants:
            reason = (
                ErrorCode.POLICY_DENIED.value
                if self.bundle.default is PolicyDefault.DENY
                else "POLICY_ABSTAINED"
            )
            return PolicyDecision(
                verdict=PolicyVerdict.DENY,
                obligations=tuple(sorted(obligations)),
                reason_code=reason,
                bundle_digest=self.digest,
            )
        allowed_modes = set.intersection(*mode_sets) if mode_sets else set()
        if not allowed_modes:
            return PolicyDecision(
                verdict=PolicyVerdict.DENY,
                matched_grants=tuple(matched_grants),
                obligations=tuple(sorted(obligations)),
                reason_code="MODE_CONFLICT",
                bundle_digest=self.digest,
            )
        return PolicyDecision(
            verdict=PolicyVerdict.ELIGIBLE,
            allowed_modes=tuple(sorted(allowed_modes)),
            obligations=tuple(sorted(obligations)),
            matched_grants=tuple(matched_grants),
            reason_code="POLICY_ELIGIBLE",
            bundle_digest=self.digest,
        )


def _bounded_shape(value: Any, *, depth: int = 0, seen: list[int] | None = None) -> None:
    if depth > _MAX_DEPTH:
        raise AgentKernelError(ErrorCode.RESOURCE_LIMIT_EXCEEDED, "Policy nesting is too deep")
    nodes = seen if seen is not None else [0]
    nodes[0] += 1
    if nodes[0] > _MAX_NODES:
        raise AgentKernelError(ErrorCode.RESOURCE_LIMIT_EXCEEDED, "Policy has too many nodes")
    if isinstance(value, dict):
        for key, item in value.items():
            _bounded_shape(key, depth=depth + 1, seen=nodes)
            _bounded_shape(item, depth=depth + 1, seen=nodes)
    elif isinstance(value, list | tuple):
        for item in value:
            _bounded_shape(item, depth=depth + 1, seen=nodes)


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


def compile_policy(bundle: PolicyBundle) -> CompiledPolicy:
    for rule in bundle.rules:
        _validate_condition(rule.when)
        if rule.effect is PolicyEffect.GRANT and not rule.modes:
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "A grant must declare modes")
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
    return CompiledPolicy(bundle=bundle, digest=canonical_digest(bundle))


def load_policy(path: Path) -> CompiledPolicy:
    raw = path.read_bytes()
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
    return cast("tuple[str, ...]", tuple(value))


def _matches(condition: dict[str, JsonValue], context: PolicyContext) -> bool:
    key, value = next(iter(condition.items()))
    if key in {"all", "any"}:
        children = cast_conditions(value)
        outcomes = (_matches(child, context) for child in children)
        return all(outcomes) if key == "all" else any(outcomes)
    if key == "action_in":
        return context.action in _string_values(value)
    if key == "resource_within":
        if not isinstance(value, str):
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "resource_within requires a string")
        return resource_matches(value, context.resource)
    if key == "provenance_trust_in":
        return bool(set(context.provenance_trust) & set(_string_values(value)))
    if key == "requested_scope_expands":
        return isinstance(value, bool) and context.requested_scope_expands is value
    if key == "data_class_in":
        return bool(set(context.data_classes) & set(_string_values(value)))
    if key == "destination_external":
        return isinstance(value, bool) and context.destination_external is value
    if key == "risk_class_in":
        return context.risk_class.value in _string_values(value)
    raise AgentKernelError(ErrorCode.POLICY_UNKNOWN, "Policy predicate was not compiled")


def cast_conditions(value: JsonValue) -> tuple[dict[str, JsonValue], ...]:
    if not isinstance(value, list) or not all(isinstance(child, dict) for child in value):
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Logical condition is malformed")
    return cast("tuple[dict[str, JsonValue], ...]", tuple(value))
