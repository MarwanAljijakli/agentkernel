from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import agentkernel.policy.aggregation as aggregation
import pytest
from agentkernel.authority import (
    AuthorityEvaluationVerdict,
    AuthorityReasonCode,
    CapabilityReservationPlan,
    EnforcedAuthorityDecision,
    ResourceAuthorityDecision,
)
from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import (
    ProvenanceTrust,
    ResourceAccessMode,
    ResourceUseKind,
    RiskClass,
)
from agentkernel.domain.models import (
    AuthenticatedActionContext,
    NormalizedAction,
    NormalizedProvenance,
    PolicyBundle,
    PolicyDefault,
    PolicyEffect,
    PolicyRule,
    ResourceUse,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.policy import (
    MAX_POLICY_BUNDLES,
    MAX_RESOURCE_USES,
    MAX_UNKNOWN_FACTS,
    CompiledPolicy,
    PolicyContext,
    PolicyLayer,
    PolicyLayerInput,
    PolicyResourceInput,
    PolicyVerdict,
    compile_policy,
    load_policy,
)
from pydantic import ValidationError


def _ref(name: str) -> str:
    return canonical_digest({"resource-use": name})


_ACTION_BY_RESOURCE_INPUT_ID: dict[int, NormalizedAction] = {}


class _ExplodingOversizedSequence:
    def __init__(self, size: int) -> None:
        self._size = size

    def __len__(self) -> int:
        return self._size

    def __iter__(self):
        raise AssertionError("oversized sequence was copied or iterated")

    def __getitem__(self, _index):
        raise AssertionError("oversized sequence was indexed")


def _context(
    resource: str = "fs://workspace/a.txt",
    *,
    action: str = "fs.read",
    provenance_trust: tuple[ProvenanceTrust, ...] = (),
    requested_scope_expands: bool | None = None,
    data_classes: tuple[str, ...] = (),
    destination_external: bool = False,
    risk_class: RiskClass = RiskClass.READ_ONLY,
) -> PolicyContext:
    return PolicyContext(
        action=action,
        resource=resource,
        provenance_trust=provenance_trust,
        requested_scope_expands=requested_scope_expands,
        data_classes=data_classes,
        destination_external=destination_external,
        risk_class=risk_class,
    )


def _grant(
    name: str,
    *,
    modes: tuple[str, ...] = ("read", "stage"),
    resource: str = "fs://workspace/**",
    extra_rules: tuple[PolicyRule, ...] = (),
    default: PolicyDefault = PolicyDefault.ABSTAIN,
) -> CompiledPolicy:
    return compile_policy(
        PolicyBundle(
            name=name,
            version="1.0.0",
            default=default,
            rules=(
                PolicyRule(
                    rule_id=f"{name}-grant",
                    effect=PolicyEffect.GRANT,
                    modes=modes,
                    when={"resource_within": resource},
                ),
                *extra_rules,
            ),
        )
    )


def _layer(
    layer: PolicyLayer,
    policy: CompiledPolicy,
    *,
    unknown_facts: tuple[str, ...] = (),
) -> PolicyLayerInput:
    return PolicyLayerInput(
        layer=layer,
        scope_id=f"scope:{layer.value}",
        policy=policy,
        unknown_facts=unknown_facts,
    )


def _resource_use(
    name: str = "a",
    resource: str = "fs://workspace/a.txt",
    *,
    authority_action: str = "fs.read",
    access_mode: ResourceAccessMode = ResourceAccessMode.READ,
    data_classes: tuple[str, ...] = (),
    provenance_ids: tuple[str, ...] = (),
    use_kind: ResourceUseKind = ResourceUseKind.PRECONDITION_READ,
    destination_external: bool = False,
) -> ResourceUse:
    return ResourceUse(
        authority_action=authority_action,
        access_mode=access_mode,
        canonical_resource=resource,
        effect_domain="filesystem",
        data_classes=data_classes,
        purpose=f"policy-test-{name}",
        provenance_ids=provenance_ids,
        use_kind=use_kind,
        destination_external=destination_external,
    )


def _normalized_action(
    resource_uses: tuple[ResourceUse, ...],
    *,
    risk_floor: RiskClass = RiskClass.READ_ONLY,
    provenance: tuple[NormalizedProvenance, ...] = (),
    transaction_id: str = "transaction:policy-test",
    tenant_id: str = "tenant:policy-test",
) -> NormalizedAction:
    ordered_uses = tuple(sorted(resource_uses, key=lambda value: value.sort_key()))
    action_context = AuthenticatedActionContext(
        tenant_id=tenant_id,
        principal_id="principal:policy-test",
        goal_id="goal:policy-test",
        run_id="run:policy-test",
        trace_id="trace:policy-test",
        actor_id="actor:policy-test",
        on_behalf_of="principal:policy-test",
        agent_id="agent:policy-test",
        configuration_digest=_ref("configuration"),
    )
    return NormalizedAction.create(
        context=action_context,
        transaction_id=transaction_id,
        deadline=datetime(2030, 1, 1, tzinfo=UTC),
        idempotency_key=None,
        adapter="adapter:policy-test",
        adapter_version="1.0.0",
        adapter_manifest_digest=_ref("adapter-manifest"),
        operation="policy.test",
        normalizer_implementation="normalizer:policy-test",
        normalizer_version="1.0.0",
        normalizer_digest=_ref("normalizer"),
        operation_schema_ref="schema:policy-test",
        operation_schema_digest=_ref("operation-schema"),
        risk_floor=risk_floor,
        effect_domains=tuple(sorted({value.effect_domain for value in ordered_uses})),
        resource_uses=ordered_uses,
        provenance=tuple(sorted(provenance, key=lambda value: value.provenance_id)),
    )


def _policy_resource_input(
    action: NormalizedAction,
    resource_use: ResourceUse,
    *,
    context: PolicyContext | None = None,
) -> PolicyResourceInput:
    resource_index = action.resource_uses.index(resource_use)
    provenance_by_id = {binding.provenance_id: binding for binding in action.provenance}
    provenance_trust = tuple(
        sorted(
            {provenance_by_id[value].trust for value in resource_use.provenance_ids},
            key=lambda value: value.value,
        )
    )
    expected_context = _context(
        resource_use.canonical_resource,
        action=resource_use.authority_action,
        provenance_trust=provenance_trust,
        data_classes=resource_use.data_classes,
        destination_external=resource_use.destination_external,
        risk_class=action.risk_floor,
    )
    policy_resource = PolicyResourceInput(
        resource_index=resource_index,
        resource_use_ref=canonical_digest(resource_use),
        resource_use=resource_use,
        context=context or expected_context,
    )
    _ACTION_BY_RESOURCE_INPUT_ID[id(policy_resource)] = action
    return policy_resource


def _action_for(resource: PolicyResourceInput) -> NormalizedAction:
    return _ACTION_BY_RESOURCE_INPUT_ID[id(resource)]


def _resources(
    resource_uses: tuple[ResourceUse, ...],
    *,
    risk_floor: RiskClass = RiskClass.READ_ONLY,
    provenance: tuple[NormalizedProvenance, ...] = (),
) -> tuple[PolicyResourceInput, ...]:
    action = _normalized_action(resource_uses, risk_floor=risk_floor, provenance=provenance)
    return tuple(_policy_resource_input(action, value) for value in action.resource_uses)


def _resource(name: str = "a", resource: str = "fs://workspace/a.txt") -> PolicyResourceInput:
    return _resources((_resource_use(name, resource),))[0]


def _authority_decision(
    action: NormalizedAction,
    *,
    allowed: bool,
    resource_decisions: tuple[ResourceAuthorityDecision, ...] | None = None,
    denial_reason: AuthorityReasonCode = AuthorityReasonCode.AUTHORITY_MISSING,
) -> EnforcedAuthorityDecision:
    verdict = AuthorityEvaluationVerdict.ALLOW if allowed else AuthorityEvaluationVerdict.DENY
    reason_code = AuthorityReasonCode.AUTHORITY_GRANTED if allowed else denial_reason
    decisions = resource_decisions or tuple(
        ResourceAuthorityDecision.create(
            resource_index=index,
            resource_use=resource_use,
            effective_data_classes=resource_use.data_classes,
            verdict=verdict,
            reason_code=reason_code,
            capability_chain_ids=(("capability:policy-test",) if allowed else ()),
        )
        for index, resource_use in enumerate(action.resource_uses)
    )
    snapshot_digest = _ref("authority-snapshot")
    reservation_plan = (
        CapabilityReservationPlan.create(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            authority_snapshot_digest=snapshot_digest,
            capability_ids=("capability:policy-test",),
        )
        if allowed
        else None
    )
    evaluated_at = datetime(2029, 1, 1, tzinfo=UTC)
    payload: dict[str, object] = {
        "tenant_id": action.tenant_id,
        "transaction_id": action.transaction_id,
        "intent_hash": action.intent_hash,
        "authority_snapshot_tenant_id": action.tenant_id,
        "authority_snapshot_id": "snapshot:policy-test",
        "authority_snapshot_revision": 1,
        "authority_snapshot_as_of": evaluated_at,
        "authority_snapshot_digest": snapshot_digest,
        "expected_authority_snapshot_digest": snapshot_digest,
        "evaluation_context_digest": _ref("authority-context"),
        "evaluated_at": evaluated_at,
        "verdict": verdict,
        "reason_code": reason_code,
        "resource_decisions": decisions,
        "reservation_plan": reservation_plan,
        "provenance_used_as_authority": False,
    }
    return EnforcedAuthorityDecision.model_validate(
        {**payload, "decision_digest": canonical_digest(payload)}
    )


def evaluate_policy_layers(
    *,
    capability_valid: bool,
    layers,
    resources,
    unknown_facts=(),
    policy_snapshot=None,
    authority_decision=None,
    preserve_resource_context: bool = False,
):
    layer_inputs = tuple(layers)
    resource_inputs = tuple(resources)
    action = _action_for(resource_inputs[0]) if resource_inputs else _action_for(_resource())
    authority = authority_decision or _authority_decision(action, allowed=capability_valid)
    if not preserve_resource_context:
        provenance_by_id = {binding.provenance_id: binding for binding in action.provenance}
        expansion_reasons = {
            AuthorityReasonCode.ACTION_NOT_GRANTED,
            AuthorityReasonCode.RESOURCE_NOT_GRANTED,
            AuthorityReasonCode.DATA_CLASS_NOT_GRANTED,
            AuthorityReasonCode.DELEGATION_ACTION_WIDENED,
            AuthorityReasonCode.DELEGATION_RESOURCE_WIDENED,
            AuthorityReasonCode.DELEGATION_DATA_CLASS_WIDENED,
            AuthorityReasonCode.WILDCARD_SCOPE_FORBIDDEN,
        }
        rebound_resources: list[PolicyResourceInput] = []
        for resource in resource_inputs:
            authority_resource = authority.resource_decisions[resource.resource_index]
            if authority_resource.verdict is AuthorityEvaluationVerdict.ALLOW:
                requested_scope_expands = False
            elif authority_resource.reason_code in expansion_reasons:
                requested_scope_expands = True
            else:
                requested_scope_expands = None
            provenance_trust = tuple(
                sorted(
                    {
                        provenance_by_id[value].trust
                        for value in resource.resource_use.provenance_ids
                    },
                    key=lambda value: value.value,
                )
            )
            rebound = PolicyResourceInput(
                resource_index=resource.resource_index,
                resource_use_ref=resource.resource_use_ref,
                resource_use=resource.resource_use,
                context=_context(
                    resource.resource_use.canonical_resource,
                    action=resource.resource_use.authority_action,
                    provenance_trust=provenance_trust,
                    requested_scope_expands=requested_scope_expands,
                    data_classes=resource.resource_use.data_classes,
                    destination_external=resource.resource_use.destination_external,
                    risk_class=action.risk_floor,
                ),
                unknown_facts=resource.unknown_facts,
            )
            _ACTION_BY_RESOURCE_INPUT_ID[id(rebound)] = action
            rebound_resources.append(rebound)
        resource_inputs = tuple(rebound_resources)
    unique_identities = {canonical_digest(layer.identity): layer.identity for layer in layer_inputs}
    inferred_identities = (
        tuple(unique_identities.values()) if len(layer_inputs) <= MAX_POLICY_BUNDLES else ()
    )
    snapshot = policy_snapshot or aggregation.PolicyLayerSnapshot.create(inferred_identities)
    return aggregation.evaluate_policy_layers(
        normalized_action=action,
        authority_decision=authority,
        policy_snapshot=snapshot,
        layers=layer_inputs,
        resources=resource_inputs,
        unknown_facts=unknown_facts,
    )


def test_policy_resource_reference_and_context_are_bound_to_the_full_resource_use() -> None:
    dangerous = _resource_use(
        "dangerous",
        "fs://workspace/secret.txt",
        authority_action="fs.write",
        access_mode=ResourceAccessMode.WRITE,
        data_classes=("secret",),
        provenance_ids=("source:external",),
        use_kind=ResourceUseKind.AUTHORITATIVE_EFFECT,
    )
    expected_context = _context(
        dangerous.canonical_resource,
        action=dangerous.authority_action,
        provenance_trust=(ProvenanceTrust.EXTERNAL_UNTRUSTED,),
        data_classes=dangerous.data_classes,
        risk_class=RiskClass.IRREVERSIBLE,
    )

    with pytest.raises(ValidationError, match="differ from resource use"):
        PolicyResourceInput(
            resource_index=0,
            resource_use_ref=canonical_digest(dangerous),
            resource_use=dangerous,
            context=_context("fs://workspace/a.txt"),
        )

    with pytest.raises(ValidationError, match="reference does not match"):
        PolicyResourceInput(
            resource_index=0,
            resource_use_ref=_ref("forged"),
            resource_use=dangerous,
            context=expected_context,
        )


def test_policy_context_cannot_downgrade_r3_normalized_risk_to_r0() -> None:
    resource_use = _resource_use()
    action = _normalized_action((resource_use,), risk_floor=RiskClass.IRREVERSIBLE)

    resource = _policy_resource_input(
        action,
        resource_use,
        context=_context(resource_use.canonical_resource, risk_class=RiskClass.READ_ONLY),
    )
    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=True,
            layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
            resources=(resource,),
            preserve_resource_context=True,
        )
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_policy_context_cannot_upgrade_external_provenance_to_trusted_control() -> None:
    external = NormalizedProvenance(
        provenance_id="source:external",
        trust=ProvenanceTrust.EXTERNAL_UNTRUSTED,
        record_digest=_ref("external-provenance"),
    )
    resource_use = _resource_use(provenance_ids=(external.provenance_id,))
    action = _normalized_action((resource_use,), provenance=(external,))

    resource = _policy_resource_input(
        action,
        resource_use,
        context=_context(
            resource_use.canonical_resource,
            provenance_trust=(ProvenanceTrust.TRUSTED_CONTROL,),
        ),
    )
    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=True,
            layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
            resources=(resource,),
            preserve_resource_context=True,
        )
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize("forged_value", [None, True])
def test_requested_scope_expansion_cannot_differ_from_allowed_authority(
    forged_value: bool | None,
) -> None:
    resource_use = _resource_use()
    action = _normalized_action((resource_use,))

    resource = _policy_resource_input(
        action,
        resource_use,
        context=_context(
            resource_use.canonical_resource,
            requested_scope_expands=forged_value,
        ),
    )
    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=True,
            layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
            resources=(resource,),
            preserve_resource_context=True,
        )
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_policy_resource_revalidates_normalized_action_intent_hash() -> None:
    resource_use = _resource_use()
    action = _normalized_action((resource_use,), risk_floor=RiskClass.IRREVERSIBLE)
    forged_action = action.model_copy(update={"risk_floor": RiskClass.READ_ONLY})

    resource = _policy_resource_input(forged_action, resource_use)
    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=True,
            layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
            resources=(resource,),
        )
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_context_binding_digest_includes_the_normalized_intent() -> None:
    resource_use = _resource_use()
    first_action = _normalized_action((resource_use,), tenant_id="tenant:first")
    second_action = _normalized_action((resource_use,), tenant_id="tenant:second")
    first = _policy_resource_input(first_action, resource_use)
    second = _policy_resource_input(second_action, resource_use)
    layer = _layer(PolicyLayer.SYSTEM, _grant("grant"))
    first_decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(layer,),
        resources=(first,),
    )
    second_decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(layer,),
        resources=(second,),
    )

    assert first.context == second.context
    assert first_action.intent_hash != second_action.intent_hash
    assert (
        first_decision.resource_decisions[0].context_digest
        != second_decision.resource_decisions[0].context_digest
    )


def test_policy_inputs_cannot_omit_a_sensitive_resource_from_the_normalized_action() -> None:
    safe = _resource_use("safe", "fs://workspace/a.txt")
    sensitive = _resource_use(
        "sensitive",
        "fs://workspace/secret.txt",
        authority_action="fs.write",
        access_mode=ResourceAccessMode.WRITE,
        data_classes=("secret",),
        use_kind=ResourceUseKind.AUTHORITATIVE_EFFECT,
    )
    resources = _resources((safe, sensitive), risk_floor=RiskClass.IRREVERSIBLE)
    safe_only = tuple(
        resource
        for resource in resources
        if resource.resource_use.canonical_resource == safe.canonical_resource
    )

    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=True,
            layers=(_layer(PolicyLayer.SYSTEM, _grant("safe-only")),),
            resources=safe_only,
        )
    assert captured.value.code is ErrorCode.EVIDENCE_UNAVAILABLE


def test_policy_inputs_cannot_mix_resources_from_distinct_normalized_intents() -> None:
    first = _resource("first", "fs://workspace/a.txt")
    second_action_resources = _resources(
        (
            _resource_use("other-a", "fs://workspace/a.txt"),
            _resource_use("second", "fs://workspace/b.txt"),
        )
    )
    second = next(
        resource
        for resource in second_action_resources
        if resource.resource_use.canonical_resource == "fs://workspace/b.txt"
    )

    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=True,
            layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
            resources=(first, second),
            preserve_resource_context=True,
        )
    assert captured.value.code is ErrorCode.EVIDENCE_UNAVAILABLE


def test_deny_dominates_all_layers_and_input_order() -> None:
    grant = _layer(PolicyLayer.GOAL, _grant("goal"))
    deny_rule = PolicyRule(
        rule_id="immutable-deny",
        effect=PolicyEffect.DENY,
        when={"action_in": ["fs.read"]},
    )
    deny = _layer(
        PolicyLayer.SYSTEM,
        compile_policy(PolicyBundle(name="system", version="1.0.0", rules=(deny_rule,))),
    )

    first = evaluate_policy_layers(
        capability_valid=True,
        layers=(grant, deny),
        resources=(_resource(),),
    )
    second = evaluate_policy_layers(
        capability_valid=True,
        layers=(deny, grant),
        resources=(_resource(),),
    )

    assert first.verdict is PolicyVerdict.DENY
    assert first.reason_code == ErrorCode.POLICY_DENIED.value
    assert first.aggregate_digest == second.aggregate_digest
    assert len(first.matched_grants) == 1
    assert len(first.matched_denials) == 1
    assert len(first.resource_decisions[0].layer_decisions) == 2


def test_known_policy_deny_precedes_blocking_input_unknown_without_dropping_it() -> None:
    deny_rule = PolicyRule(
        rule_id="known-deny",
        effect=PolicyEffect.DENY,
        when={"action_in": ["fs.read"]},
    )
    deny = _layer(
        PolicyLayer.SYSTEM,
        compile_policy(PolicyBundle(name="deny", version="1.0.0", rules=(deny_rule,))),
    )

    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(deny,),
        resources=(_resource(),),
        unknown_facts=("policy-service-timeout",),
    )

    assert decision.verdict is PolicyVerdict.DENY
    assert decision.reason_code == ErrorCode.POLICY_DENIED.value
    assert decision.resource_decisions[0].reason_code == ErrorCode.POLICY_DENIED.value
    assert decision.unknown_facts == ("policy-service-timeout",)
    assert decision.resource_decisions[0].unknown_facts == ("policy-service-timeout",)


def test_qualified_match_evidence_accepts_maximum_identifier_lengths() -> None:
    rule_id = "r" + ("x" * 255)
    scope_id = "s" + ("y" * 255)
    policy = compile_policy(
        PolicyBundle(
            name="maximum-evidence",
            version="1.0.0",
            rules=(
                PolicyRule(
                    rule_id=rule_id,
                    effect=PolicyEffect.GRANT,
                    modes=("read", "stage"),
                    when={"resource_within": "fs://workspace/**"},
                ),
            ),
        )
    )
    layer = PolicyLayerInput(
        layer=PolicyLayer.DEPLOYMENT,
        scope_id=scope_id,
        policy=policy,
    )

    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(layer,),
        resources=(_resource(),),
    )

    assert decision.verdict is PolicyVerdict.ELIGIBLE
    assert len(decision.matched_grants) == 1
    assert len(decision.matched_grants[0]) == 596
    assert decision.resource_decisions[0].matched_grants == decision.matched_grants


def test_default_deny_and_abstain_have_distinct_layer_results() -> None:
    default_deny = _layer(
        PolicyLayer.SYSTEM,
        compile_policy(PolicyBundle(name="deny", version="1.0.0", rules=())),
    )
    abstain = _layer(
        PolicyLayer.DEPLOYMENT,
        compile_policy(
            PolicyBundle(
                name="abstain",
                version="1.0.0",
                default=PolicyDefault.ABSTAIN,
                rules=(),
            )
        ),
    )

    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(default_deny, abstain),
        resources=(_resource(),),
    )

    assert decision.verdict is PolicyVerdict.DENY
    layer_verdicts = tuple(
        item.decision.verdict for item in decision.resource_decisions[0].layer_decisions
    )
    assert layer_verdicts == (PolicyVerdict.DENY, PolicyVerdict.ABSTAIN)


def test_capability_and_at_least_one_policy_grant_are_both_required() -> None:
    grant = _layer(PolicyLayer.SYSTEM, _grant("grant"))
    invalid_capability = evaluate_policy_layers(
        capability_valid=False,
        layers=(grant,),
        resources=(_resource(),),
    )
    assert invalid_capability.verdict is PolicyVerdict.DENY
    assert invalid_capability.reason_code == ErrorCode.AUTHORITY_MISSING.value
    assert all(
        resource.verdict is PolicyVerdict.DENY for resource in invalid_capability.resource_decisions
    )
    assert all(
        resource.authority_decision_digest == invalid_capability.authority_decision.decision_digest
        for resource in invalid_capability.resource_decisions
    )

    abstain = _layer(
        PolicyLayer.SYSTEM,
        compile_policy(
            PolicyBundle(
                name="zero-grants",
                version="1.0.0",
                default=PolicyDefault.ABSTAIN,
                rules=(),
            )
        ),
    )
    zero_grants = evaluate_policy_layers(
        capability_valid=True,
        layers=(abstain,),
        resources=(_resource(),),
    )
    assert zero_grants.verdict is PolicyVerdict.DENY
    assert zero_grants.reason_code == ErrorCode.POLICY_DENIED.value


def test_authority_decision_must_bind_action_and_every_resource_evidence() -> None:
    resources = _resources(
        (
            _resource_use("a", "fs://workspace/a.txt"),
            _resource_use("b", "fs://workspace/b.txt"),
        )
    )
    action = _action_for(resources[0])
    swapped = tuple(
        ResourceAuthorityDecision.create(
            resource_index=index,
            resource_use=action.resource_uses[1 - index],
            effective_data_classes=action.resource_uses[1 - index].data_classes,
            verdict=AuthorityEvaluationVerdict.ALLOW,
            reason_code=AuthorityReasonCode.AUTHORITY_GRANTED,
            capability_chain_ids=("capability:policy-test",),
        )
        for index in range(2)
    )
    forged_authority = _authority_decision(
        action,
        allowed=True,
        resource_decisions=swapped,
    )

    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=True,
            authority_decision=forged_authority,
            layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
            resources=resources,
        )
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_authority_decision_digest_and_intent_binding_are_revalidated() -> None:
    resource = _resource()
    action = _action_for(resource)
    authority = _authority_decision(action, allowed=True)
    tampered_digest = authority.model_copy(update={"decision_digest": _ref("tampered")})

    with pytest.raises(AgentKernelError) as digest_error:
        evaluate_policy_layers(
            capability_valid=True,
            authority_decision=tampered_digest,
            layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
            resources=(resource,),
        )
    assert digest_error.value.code is ErrorCode.INTEGRITY_ERROR

    other_action = _normalized_action(
        (resource.resource_use,),
        tenant_id="tenant:other",
        transaction_id="transaction:other",
    )
    other_authority = _authority_decision(other_action, allowed=True)
    with pytest.raises(AgentKernelError) as action_error:
        evaluate_policy_layers(
            capability_valid=True,
            authority_decision=other_authority,
            layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
            resources=(resource,),
        )
    assert action_error.value.code is ErrorCode.INTEGRITY_ERROR


def test_authority_derives_scope_expansion_for_project_data_policy() -> None:
    provenance = NormalizedProvenance(
        provenance_id="source:project",
        trust=ProvenanceTrust.PROJECT_DATA,
        data_classes=("project_data",),
        record_digest=_ref("project-provenance"),
    )
    resource_use = _resource_use(
        provenance_ids=(provenance.provenance_id,),
        data_classes=("project_data",),
        authority_action="fs.write",
        access_mode=ResourceAccessMode.WRITE,
        use_kind=ResourceUseKind.AUTHORITATIVE_EFFECT,
    )
    resource = _resources(
        (resource_use,),
        risk_floor=RiskClass.REVERSIBLE,
        provenance=(provenance,),
    )[0]
    layer = _layer(
        PolicyLayer.SYSTEM,
        load_policy(Path("policies/system/base.yaml")),
    )

    allowed = evaluate_policy_layers(
        capability_valid=True,
        layers=(layer,),
        resources=(resource,),
    )
    assert allowed.verdict is PolicyVerdict.ELIGIBLE
    assert allowed.resource_inputs[0].context.requested_scope_expands is False
    assert allowed.resource_inputs[0].context.provenance_trust == (ProvenanceTrust.PROJECT_DATA,)

    action = _action_for(resource)
    denied_authority = _authority_decision(
        action,
        allowed=False,
        denial_reason=AuthorityReasonCode.RESOURCE_NOT_GRANTED,
    )
    denied = evaluate_policy_layers(
        capability_valid=False,
        authority_decision=denied_authority,
        layers=(layer,),
        resources=(resource,),
    )
    assert denied.authority_decision.verdict is AuthorityEvaluationVerdict.DENY
    assert denied.resource_inputs[0].context.requested_scope_expands is True
    assert denied.verdict is PolicyVerdict.DENY
    assert denied.reason_code == ErrorCode.POLICY_DENIED.value

    forged_resource = PolicyResourceInput(
        resource_index=resource.resource_index,
        resource_use_ref=resource.resource_use_ref,
        resource_use=resource.resource_use,
        context=denied.resource_inputs[0].context.model_copy(
            update={"requested_scope_expands": False}
        ),
    )
    _ACTION_BY_RESOURCE_INPUT_ID[id(forged_resource)] = action
    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=False,
            authority_decision=denied_authority,
            layers=(layer,),
            resources=(forged_resource,),
            preserve_resource_context=True,
        )
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_missing_or_explicit_unknown_evidence_fails_closed() -> None:
    missing_layers = evaluate_policy_layers(
        capability_valid=True,
        layers=(),
        resources=(_resource(),),
    )
    assert missing_layers.verdict is PolicyVerdict.DENY
    assert missing_layers.reason_code == ErrorCode.POLICY_UNKNOWN.value

    unknown = evaluate_policy_layers(
        capability_valid=True,
        layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
        resources=(_resource(),),
        unknown_facts=("policy-service-timeout",),
    )
    assert unknown.verdict is PolicyVerdict.DENY
    assert unknown.reason_code == ErrorCode.POLICY_UNKNOWN.value
    assert unknown.unknown_facts == ("policy-service-timeout",)


@pytest.mark.parametrize("mismatch", ["omitted", "extra"])
def test_policy_layer_snapshot_requires_all_and_only_expected_identities(mismatch: str) -> None:
    system = _layer(PolicyLayer.SYSTEM, _grant("system"))
    goal = _layer(PolicyLayer.GOAL, _grant("goal"))
    if mismatch == "omitted":
        layers = (system,)
        snapshot_identities = (system.identity, goal.identity)
    else:
        layers = (system, goal)
        snapshot_identities = (system.identity,)
    snapshot = aggregation.PolicyLayerSnapshot.create(snapshot_identities)

    decision = evaluate_policy_layers(
        capability_valid=True,
        policy_snapshot=snapshot,
        layers=layers,
        resources=(_resource(),),
    )

    assert decision.verdict is PolicyVerdict.DENY
    assert decision.reason_code == ErrorCode.POLICY_UNKNOWN.value
    assert "policy-layer-snapshot-mismatch" in decision.unknown_facts


def test_policy_layer_snapshot_digest_is_revalidated() -> None:
    layer = _layer(PolicyLayer.SYSTEM, _grant("grant"))
    snapshot = aggregation.PolicyLayerSnapshot.create((layer.identity,))
    tampered = snapshot.model_copy(update={"snapshot_digest": _ref("tampered")})

    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=True,
            policy_snapshot=tampered,
            layers=(layer,),
            resources=(_resource(),),
        )
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_policy_layer_inputs_revalidate_nested_compiled_policy_instances() -> None:
    layer = _layer(PolicyLayer.SYSTEM, _grant("grant"))
    invalid_rule = layer.policy.bundle.rules[0].model_copy(
        update={"when": {"uncompiled_predicate": True}}
    )
    invalid_bundle = layer.policy.bundle.model_copy(update={"rules": (invalid_rule,)})
    forged_policy = CompiledPolicy.model_construct(
        bundle=invalid_bundle,
        digest=canonical_digest(invalid_bundle),
    )
    forged_layer = layer.model_copy(update={"policy": forged_policy})

    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=True,
            layers=(forged_layer,),
            resources=(_resource(),),
        )
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_unknown_mandatory_predicate_is_preserved_at_every_evidence_level() -> None:
    unknown_approval = PolicyRule(
        rule_id="approval-if-external",
        effect=PolicyEffect.REQUIRE_APPROVAL,
        when={"requested_scope_expands": True},
    )
    decision = evaluate_policy_layers(
        capability_valid=False,
        layers=(
            _layer(
                PolicyLayer.SYSTEM,
                _grant("known-grant", extra_rules=(unknown_approval,)),
            ),
        ),
        resources=(_resource(),),
    )

    resource = decision.resource_decisions[0]
    layer = resource.layer_decisions[0]
    assert decision.verdict is PolicyVerdict.DENY
    assert decision.reason_code == ErrorCode.POLICY_UNKNOWN.value
    assert layer.decision.unknown_facts == ("requested_scope_expands",)
    assert layer.unknown_facts == ("requested_scope_expands",)
    assert resource.unknown_facts == ("requested_scope_expands",)
    assert decision.unknown_facts == ("requested_scope_expands",)


def test_unknown_grant_is_recorded_without_overriding_a_known_grant() -> None:
    unknown_grant = PolicyRule(
        rule_id="external-grant",
        effect=PolicyEffect.GRANT,
        modes=("read",),
        when={"requested_scope_expands": True},
    )
    decision = evaluate_policy_layers(
        capability_valid=False,
        layers=(
            _layer(
                PolicyLayer.SYSTEM,
                _grant("known-grant", modes=("read",), extra_rules=(unknown_grant,)),
            ),
        ),
        resources=(_resource(),),
    )

    resource = decision.resource_decisions[0]
    layer = resource.layer_decisions[0]
    assert decision.verdict is PolicyVerdict.DENY
    assert decision.reason_code == ErrorCode.AUTHORITY_MISSING.value
    assert layer.decision.verdict is PolicyVerdict.ELIGIBLE
    assert layer.decision.unknown_facts == ("requested_scope_expands",)
    assert layer.unknown_facts == ("requested_scope_expands",)
    assert resource.unknown_facts == ("requested_scope_expands",)
    assert decision.unknown_facts == ("requested_scope_expands",)


def test_modes_intersect_and_empty_intersection_denies() -> None:
    compatible = evaluate_policy_layers(
        capability_valid=True,
        layers=(
            _layer(PolicyLayer.SYSTEM, _grant("broad", modes=("read", "stage"))),
            _layer(PolicyLayer.GOAL, _grant("narrow", modes=("read",))),
        ),
        resources=(_resource(),),
    )
    assert compatible.verdict is PolicyVerdict.ELIGIBLE
    assert compatible.allowed_modes == ("read",)

    conflict = evaluate_policy_layers(
        capability_valid=True,
        layers=(
            _layer(PolicyLayer.SYSTEM, _grant("read-only", modes=("read",))),
            _layer(PolicyLayer.GOAL, _grant("stage-only", modes=("stage",))),
        ),
        resources=(_resource(),),
    )
    assert conflict.verdict is PolicyVerdict.DENY
    assert conflict.reason_code == "MODE_CONFLICT"


def test_obligations_union_but_never_supply_permission() -> None:
    approval = PolicyRule(
        rule_id="approval",
        effect=PolicyEffect.REQUIRE_APPROVAL,
        when={"action_in": ["fs.read"]},
    )
    shadow = PolicyRule(
        rule_id="shadow",
        effect=PolicyEffect.REQUIRE_SHADOW,
        when={"action_in": ["fs.read"]},
    )
    granted = evaluate_policy_layers(
        capability_valid=True,
        layers=(
            _layer(PolicyLayer.SYSTEM, _grant("with-approval", extra_rules=(approval,))),
            _layer(
                PolicyLayer.GOAL,
                compile_policy(
                    PolicyBundle(
                        name="shadow-only",
                        version="1.0.0",
                        default=PolicyDefault.ABSTAIN,
                        rules=(shadow,),
                    )
                ),
            ),
        ),
        resources=(_resource(),),
    )
    assert granted.verdict is PolicyVerdict.ELIGIBLE
    assert granted.obligations == ("approval", "shadow")

    obligation_only = evaluate_policy_layers(
        capability_valid=True,
        layers=(
            _layer(
                PolicyLayer.SYSTEM,
                compile_policy(
                    PolicyBundle(
                        name="approval-only",
                        version="1.0.0",
                        default=PolicyDefault.ABSTAIN,
                        rules=(approval,),
                    )
                ),
            ),
        ),
        resources=(_resource(),),
    )
    assert obligation_only.verdict is PolicyVerdict.DENY
    assert obligation_only.obligations == ("approval",)


def test_every_resource_is_evaluated_and_one_denial_denies_action() -> None:
    layer = _layer(PolicyLayer.SYSTEM, _grant("only-a", resource="fs://workspace/a.txt"))
    resources = _resources(
        (
            _resource_use("b", "fs://workspace/b.txt"),
            _resource_use("a", "fs://workspace/a.txt"),
        )
    )
    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(layer,),
        resources=resources,
    )

    assert decision.verdict is PolicyVerdict.DENY
    assert len(decision.resource_decisions) == 2
    assert {item.verdict for item in decision.resource_decisions} == {
        PolicyVerdict.ELIGIBLE,
        PolicyVerdict.DENY,
    }


@pytest.mark.parametrize("duplicate_kind", ["resource", "layer"])
def test_duplicate_evidence_is_rejected(duplicate_kind: str) -> None:
    first = _layer(PolicyLayer.SYSTEM, _grant("first"))
    second = _layer(PolicyLayer.DEPLOYMENT, _grant("second"))
    layers = (first, second)
    resources = _resources(
        (
            _resource_use("a"),
            _resource_use("b", "fs://workspace/b.txt"),
        )
    )
    if duplicate_kind == "resource":
        resource = _resource("same")
        resources = (resource, resource)
    elif duplicate_kind == "layer":
        layers = (first, first)
    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=True,
            layers=layers,
            resources=resources,
        )
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_same_bundle_digest_may_apply_at_distinct_layers() -> None:
    policy = _grant("shared")
    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(
            _layer(PolicyLayer.SYSTEM, policy),
            _layer(PolicyLayer.DEPLOYMENT, policy),
        ),
        resources=(_resource(),),
    )

    assert decision.verdict is PolicyVerdict.ELIGIBLE
    assert decision.bundle_digests == (policy.digest, policy.digest)


@pytest.mark.parametrize("invalid_version", ["cafe\N{COMBINING ACUTE ACCENT}", "\ud800"])
def test_policy_layer_identity_rejects_noncanonical_bundle_version(
    invalid_version: str,
) -> None:
    layer = _layer(PolicyLayer.SYSTEM, _grant("grant"))
    identity_payload = layer.identity.model_dump(mode="python")
    identity_payload["bundle_version"] = invalid_version

    with pytest.raises(ValidationError, match=r"valid UTF-8|Unicode NFC|valid string"):
        type(layer.identity).model_validate(identity_payload)


def test_composed_and_decomposed_bundle_versions_cannot_form_distinct_raw_keys() -> None:
    composed = "caf\N{LATIN SMALL LETTER E WITH ACUTE}"
    decomposed = "cafe\N{COMBINING ACUTE ACCENT}"
    assert canonical_digest(composed) == canonical_digest(decomposed)
    layer = _layer(PolicyLayer.SYSTEM, _grant("grant"))
    payload = layer.identity.model_dump(mode="python") | {"bundle_version": decomposed}

    with pytest.raises(ValidationError, match="Unicode NFC"):
        type(layer.identity).model_validate(payload)


def test_empty_and_oversized_resource_inputs_are_rejected() -> None:
    layer = _layer(PolicyLayer.SYSTEM, _grant("grant"))
    with pytest.raises(AgentKernelError) as empty:
        evaluate_policy_layers(capability_valid=True, layers=(layer,), resources=())
    assert empty.value.code is ErrorCode.VALIDATION_ERROR

    oversized = (_resource(),) * (MAX_RESOURCE_USES + 1)
    with pytest.raises(AgentKernelError) as over_limit:
        evaluate_policy_layers(capability_valid=True, layers=(layer,), resources=oversized)
    assert over_limit.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


@pytest.mark.parametrize("sequence_kind", ["layers", "resources", "unknown", "snapshot"])
def test_oversized_sequences_are_rejected_before_copy_or_iteration(sequence_kind: str) -> None:
    layer = _layer(PolicyLayer.SYSTEM, _grant("grant"))
    baseline = evaluate_policy_layers(
        capability_valid=True,
        layers=(layer,),
        resources=(_resource(),),
    )
    if sequence_kind == "snapshot":
        with pytest.raises(AgentKernelError) as captured:
            aggregation.PolicyLayerSnapshot.create(
                _ExplodingOversizedSequence(MAX_POLICY_BUNDLES + 1)
            )
    else:
        layers = (
            _ExplodingOversizedSequence(MAX_POLICY_BUNDLES + 1)
            if sequence_kind == "layers"
            else baseline.layer_inputs
        )
        resources = (
            _ExplodingOversizedSequence(MAX_RESOURCE_USES + 1)
            if sequence_kind == "resources"
            else baseline.resource_inputs
        )
        unknown_facts = _ExplodingOversizedSequence(1_000_000) if sequence_kind == "unknown" else ()
        with pytest.raises(AgentKernelError) as captured:
            aggregation.evaluate_policy_layers(
                normalized_action=baseline.normalized_action,
                authority_decision=baseline.authority_decision,
                policy_snapshot=baseline.policy_snapshot,
                layers=layers,
                resources=resources,
                unknown_facts=unknown_facts,
            )
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


@pytest.mark.parametrize("unknown_fact", ["", "x" * 513])
def test_invalid_unknown_fact_length_is_rejected_before_unicode_normalization(
    monkeypatch: pytest.MonkeyPatch,
    unknown_fact: str,
) -> None:
    baseline = evaluate_policy_layers(
        capability_valid=True,
        layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
        resources=(_resource(),),
    )

    def fail_if_normalized(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("invalid unknown fact reached Unicode normalization")

    class ExplodingUnicodeData:
        normalize = staticmethod(fail_if_normalized)

    monkeypatch.setattr(aggregation, "unicodedata", ExplodingUnicodeData)
    with pytest.raises(AgentKernelError) as captured:
        aggregation.evaluate_policy_layers(
            normalized_action=baseline.normalized_action,
            authority_decision=baseline.authority_decision,
            policy_snapshot=baseline.policy_snapshot,
            layers=baseline.layer_inputs,
            resources=baseline.resource_inputs,
            unknown_facts=(unknown_fact,),
        )
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_oversized_layer_and_unknown_fact_inputs_are_rejected() -> None:
    layers = tuple(
        _layer(PolicyLayer.SYSTEM, _grant(f"layer-{index}"))
        for index in range(MAX_POLICY_BUNDLES + 1)
    )
    with pytest.raises(AgentKernelError) as layer_limit:
        evaluate_policy_layers(
            capability_valid=True,
            layers=layers,
            resources=(_resource(),),
        )
    assert layer_limit.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    with pytest.raises(AgentKernelError) as fact_limit:
        evaluate_policy_layers(
            capability_valid=True,
            layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
            resources=(_resource(),),
            unknown_facts=tuple(f"unknown-{index}" for index in range(MAX_UNKNOWN_FACTS + 1)),
        )
    assert fact_limit.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


@pytest.mark.parametrize(
    ("level", "field_name", "limit"),
    [
        ("resource", "allowed_modes", aggregation.MAX_POLICY_MODES),
        ("resource", "obligations", aggregation.MAX_POLICY_OBLIGATIONS),
        ("resource", "matched_grants", aggregation.MAX_POLICY_MATCHES),
        ("resource", "matched_denials", aggregation.MAX_POLICY_MATCHES),
        ("resource", "bundle_digests", MAX_POLICY_BUNDLES),
        ("resource", "layer_decisions", MAX_POLICY_BUNDLES),
        ("action", "resource_decisions", MAX_RESOURCE_USES),
    ],
)
def test_derived_policy_evidence_tuples_have_explicit_bounds(
    level: str,
    field_name: str,
    limit: int,
) -> None:
    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
        resources=(_resource(),),
    )
    model = decision.resource_decisions[0] if level == "resource" else decision
    payload = model.model_dump(mode="python")
    existing = payload[field_name]
    exemplar = existing[0] if existing else "evidence"
    payload[field_name] = tuple(exemplar for _ in range(limit + 1))

    with pytest.raises(ValidationError):
        type(model).model_validate(payload)


@pytest.mark.parametrize(
    "budget_name",
    ["MAX_POLICY_WORK_UNITS", "MAX_POLICY_EVIDENCE_UNITS"],
)
def test_policy_evaluation_enforces_total_work_and_evidence_budgets(
    monkeypatch: pytest.MonkeyPatch,
    budget_name: str,
) -> None:
    monkeypatch.setattr(aggregation, budget_name, 1)

    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=True,
            layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
            resources=(_resource(),),
        )
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_policy_work_budget_counts_nested_condition_nodes_before_evaluation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested = PolicyRule(
        rule_id="wide-condition",
        effect=PolicyEffect.DENY,
        when={"any": [{"action_in": [f"action-{index}"]} for index in range(64)]},
    )
    layer = _layer(
        PolicyLayer.SYSTEM,
        _grant("grant", extra_rules=(nested,)),
    )
    resources = _resources(
        (
            _resource_use("a", "fs://workspace/a.txt"),
            _resource_use("b", "fs://workspace/b.txt"),
        )
    )
    monkeypatch.setattr(aggregation, "MAX_POLICY_WORK_UNITS", 100)

    def unexpected_evaluation(*_args, **_kwargs):
        raise AssertionError("policy evaluation ran before the work cap")

    monkeypatch.setattr(CompiledPolicy, "evaluate", unexpected_evaluation)
    with pytest.raises(AgentKernelError) as captured:
        evaluate_policy_layers(
            capability_valid=True,
            layers=(layer,),
            resources=resources,
        )
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_large_resource_evidence_serializes_action_once_within_budget() -> None:
    resource_uses = tuple(
        _resource_use(f"file-{index:03}", f"fs://workspace/file-{index:03}.txt")
        for index in range(256)
    )
    resources = _resources(resource_uses)
    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(_layer(PolicyLayer.SYSTEM, _grant("workspace")),),
        resources=resources,
    )
    encoded = decision.model_dump_json().encode("utf-8")

    assert decision.verdict is PolicyVerdict.ELIGIBLE
    assert len(decision.resource_inputs) == 256
    assert encoded.count(b'"normalized_action"') == 1
    assert len(encoded) < 4_000_000


def test_digest_is_stable_under_layer_and_resource_input_order() -> None:
    layers = (
        _layer(PolicyLayer.SYSTEM, _grant("system")),
        _layer(PolicyLayer.GOAL, _grant("goal", modes=("read",))),
    )
    resources = _resources(
        (
            _resource_use("a", "fs://workspace/a.txt"),
            _resource_use("b", "fs://workspace/b.txt"),
        )
    )
    forward = evaluate_policy_layers(
        capability_valid=True,
        layers=layers,
        resources=resources,
    )
    reverse = evaluate_policy_layers(
        capability_valid=True,
        layers=tuple(reversed(layers)),
        resources=tuple(reversed(resources)),
    )

    assert forward.aggregate_digest == reverse.aggregate_digest
    assert tuple(item.aggregate_digest for item in forward.resource_decisions) == tuple(
        item.aggregate_digest for item in reverse.resource_decisions
    )


def test_textual_rule_order_never_allows_a_deny_to_be_overridden() -> None:
    grant = PolicyRule(
        rule_id="grant",
        effect=PolicyEffect.GRANT,
        modes=("read",),
        when={"action_in": ["fs.read"]},
    )
    deny = PolicyRule(
        rule_id="deny",
        effect=PolicyEffect.DENY,
        when={"action_in": ["fs.read"]},
    )
    outcomes = []
    for index, rules in enumerate(((grant, deny), (deny, grant))):
        layer = _layer(
            PolicyLayer.SYSTEM,
            compile_policy(PolicyBundle(name=f"order-{index}", version="1.0.0", rules=rules)),
        )
        outcomes.append(
            evaluate_policy_layers(
                capability_valid=True,
                layers=(layer,),
                resources=(_resource(),),
            )
        )

    assert all(outcome.verdict is PolicyVerdict.DENY for outcome in outcomes)
    assert all(len(outcome.matched_grants) == 1 for outcome in outcomes)
    assert all(len(outcome.matched_denials) == 1 for outcome in outcomes)


@pytest.mark.parametrize("level", ["layer", "resource", "action"])
def test_policy_evidence_digest_tampering_is_rejected(level: str) -> None:
    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
        resources=(_resource(),),
    )
    if level == "layer":
        model = decision.resource_decisions[0].layer_decisions[0]
        payload = model.model_dump(mode="python") | {"decision_digest": _ref("tampered")}
        model_type = type(model)
    elif level == "resource":
        model = decision.resource_decisions[0]
        payload = model.model_dump(mode="python") | {"aggregate_digest": _ref("tampered")}
        model_type = type(model)
    else:
        model = decision
        payload = model.model_dump(mode="python") | {"aggregate_digest": _ref("tampered")}
        model_type = type(model)

    with pytest.raises(ValidationError, match="digest does not match"):
        model_type.model_validate(payload)


def test_policy_evidence_round_trip_revalidates_all_digests() -> None:
    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(
            _layer(PolicyLayer.SYSTEM, _grant("system")),
            _layer(PolicyLayer.DATA, _grant("data", modes=("read",))),
        ),
        resources=(_resource(),),
    )

    assert type(decision).model_validate_json(decision.model_dump_json()) == decision


def test_heterogeneous_resource_modes_do_not_create_a_false_action_conflict() -> None:
    read_layer = _layer(
        PolicyLayer.SYSTEM,
        _grant("read-a", modes=("read",), resource="fs://workspace/a.txt"),
    )
    write_layer = _layer(
        PolicyLayer.GOAL,
        _grant(
            "write-b",
            modes=("stage", "commit_reversible"),
            resource="fs://workspace/b.txt",
        ),
    )
    resources = _resources(
        (
            _resource_use("read", "fs://workspace/a.txt"),
            _resource_use("write", "fs://workspace/b.txt"),
        )
    )
    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(read_layer, write_layer),
        resources=resources,
    )

    assert decision.verdict is PolicyVerdict.ELIGIBLE
    assert decision.allowed_modes == ()
    assert {resource.allowed_modes for resource in decision.resource_decisions} == {
        ("read",),
        ("commit_reversible", "stage"),
    }


@pytest.mark.parametrize("level", ["resource", "action"])
def test_recomputed_digest_cannot_hide_contradictory_derived_fields(level: str) -> None:
    decision = evaluate_policy_layers(
        capability_valid=False,
        layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
        resources=(_resource(),),
    )
    if level == "resource":
        model = decision.resource_decisions[0]
        tampered = model.model_copy(
            update={
                "verdict": PolicyVerdict.ELIGIBLE,
                "reason_code": "POLICY_ELIGIBLE",
                "explanation": "forged eligibility",
                "aggregate_digest": _ref("placeholder"),
            }
        )
        payload = tampered.model_dump(mode="python")
        payload["aggregate_digest"] = canonical_digest(
            aggregation._resource_decision_payload(tampered)
        )
        model_type = type(model)
    else:
        tampered = decision.model_copy(
            update={
                "verdict": PolicyVerdict.ELIGIBLE,
                "reason_code": "POLICY_ELIGIBLE",
                "explanation": "forged eligibility",
                "aggregate_digest": _ref("placeholder"),
            }
        )
        payload = tampered.model_dump(mode="python")
        payload["aggregate_digest"] = canonical_digest(
            aggregation._action_decision_payload(tampered)
        )
        model_type = type(decision)

    with pytest.raises(ValidationError, match="contradicts"):
        model_type.model_validate(payload)


def test_recomputed_digest_cannot_omit_unknown_layer_evidence() -> None:
    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(_layer(PolicyLayer.SYSTEM, _grant("grant")),),
        resources=(_resource(),),
    )
    resource = decision.resource_decisions[0]
    layer = resource.layer_decisions[0]
    tampered_layer = layer.model_copy(
        update={
            "input_unknown_facts": ("policy-timeout",),
            "unknown_facts": ("policy-timeout",),
            "decision_digest": _ref("placeholder"),
        }
    )
    layer_payload = tampered_layer.model_dump(mode="python")
    layer_payload["decision_digest"] = canonical_digest(
        aggregation._layer_decision_payload(tampered_layer)
    )
    rehashed_layer = type(layer).model_validate(layer_payload)
    tampered_resource = resource.model_copy(
        update={
            "layer_decisions": (rehashed_layer,),
            "aggregate_digest": _ref("placeholder"),
        }
    )
    resource_payload = tampered_resource.model_dump(mode="python")
    resource_payload["aggregate_digest"] = canonical_digest(
        aggregation._resource_decision_payload(tampered_resource)
    )

    with pytest.raises(ValidationError, match="unknown facts differ"):
        type(resource).model_validate(resource_payload)


def test_layer_digest_binds_whether_an_unknown_fact_is_input_blocking() -> None:
    unknown_grant = PolicyRule(
        rule_id="unknown-compatible",
        effect=PolicyEffect.GRANT,
        modes=("read",),
        when={"requested_scope_expands": True},
    )
    decision = evaluate_policy_layers(
        capability_valid=False,
        layers=(
            _layer(
                PolicyLayer.SYSTEM,
                _grant("known", modes=("read",), extra_rules=(unknown_grant,)),
            ),
        ),
        resources=(_resource(),),
    )
    layer = decision.resource_decisions[0].layer_decisions[0]
    assert layer.input_unknown_facts == ()
    assert layer.unknown_facts == ("requested_scope_expands",)

    payload = layer.model_dump(mode="python")
    payload["input_unknown_facts"] = ("requested_scope_expands",)
    with pytest.raises(ValidationError, match="digest does not match"):
        type(layer).model_validate(payload)


@pytest.mark.parametrize("mutation", ["reverse", "duplicate"])
def test_recomputed_digests_cannot_reorder_or_duplicate_layer_evidence(
    mutation: str,
) -> None:
    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(
            _layer(PolicyLayer.SYSTEM, _grant("system", modes=("read",))),
            _layer(PolicyLayer.GOAL, _grant("goal", modes=("read",))),
        ),
        resources=(_resource(),),
    )
    resource = decision.resource_decisions[0]
    layer_decisions = (
        tuple(reversed(resource.layer_decisions))
        if mutation == "reverse"
        else (*resource.layer_decisions, resource.layer_decisions[-1])
    )
    tampered = resource.model_copy(
        update={
            "layer_decisions": layer_decisions,
            "bundle_digests": tuple(
                sorted(item.identity.bundle_digest for item in layer_decisions)
            ),
            "aggregate_digest": _ref("placeholder"),
        }
    )
    payload = tampered.model_dump(mode="python")
    payload["aggregate_digest"] = canonical_digest(aggregation._resource_decision_payload(tampered))

    with pytest.raises(ValidationError, match="sorted unique identities"):
        type(resource).model_validate(payload)


def test_policy_decision_rejects_eligible_verdict_with_matched_denial() -> None:
    deny_rule = PolicyRule(
        rule_id="deny",
        effect=PolicyEffect.DENY,
        when={"action_in": ["fs.read"]},
    )
    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(
            _layer(
                PolicyLayer.SYSTEM,
                _grant("grant", modes=("read",), extra_rules=(deny_rule,)),
            ),
        ),
        resources=(_resource(),),
    )
    nested = decision.resource_decisions[0].layer_decisions[0].decision
    payload = nested.model_dump(mode="python") | {
        "verdict": PolicyVerdict.ELIGIBLE,
        "allowed_modes": ("read",),
        "reason_code": "POLICY_ELIGIBLE",
    }

    with pytest.raises(ValidationError, match="Matched policy denials"):
        type(nested).model_validate(payload)


def _forge_rehashed_aggregate_with_nested_decision(
    aggregate_decision,
    replacement_decision,
) -> dict[str, object]:
    resource = aggregate_decision.resource_decisions[0]
    original_layer = resource.layer_decisions[0]
    tampered_layer = original_layer.model_copy(
        update={
            "decision": replacement_decision,
            "decision_digest": _ref("placeholder"),
        }
    )
    layer_payload = tampered_layer.model_dump(mode="python")
    layer_payload["decision_digest"] = canonical_digest(
        aggregation._layer_decision_payload(tampered_layer)
    )
    rehashed_layer = type(original_layer).model_validate(layer_payload)
    layer_decisions = (rehashed_layer, *resource.layer_decisions[1:])
    resource_summary = aggregation._summarize_resource(
        layer_decisions,
        authority_allowed=(
            resource.authority_verdict is AuthorityEvaluationVerdict.ALLOW
            and resource.authority_resource_decision.verdict is AuthorityEvaluationVerdict.ALLOW
        ),
        unknown_facts=resource.unknown_facts,
    )
    tampered_resource = resource.model_copy(
        update={
            "verdict": resource_summary.verdict,
            "allowed_modes": resource_summary.allowed_modes,
            "obligations": resource_summary.obligations,
            "matched_grants": resource_summary.matched_grants,
            "matched_denials": resource_summary.matched_denials,
            "bundle_digests": resource_summary.bundle_digests,
            "layer_decisions": layer_decisions,
            "reason_code": resource_summary.reason_code,
            "explanation": resource_summary.explanation,
            "aggregate_digest": _ref("placeholder"),
        }
    )
    resource_payload = tampered_resource.model_dump(mode="python")
    resource_payload["aggregate_digest"] = canonical_digest(
        aggregation._resource_decision_payload(tampered_resource)
    )
    rehashed_resource = type(resource).model_validate(resource_payload)
    action_summary = aggregation._summarize_action((rehashed_resource,))
    tampered_action = aggregate_decision.model_copy(
        update={
            "verdict": action_summary.verdict,
            "allowed_modes": action_summary.allowed_modes,
            "obligations": action_summary.obligations,
            "matched_grants": action_summary.matched_grants,
            "matched_denials": action_summary.matched_denials,
            "bundle_digests": action_summary.bundle_digests,
            "resource_decisions": (rehashed_resource,),
            "unknown_facts": action_summary.unknown_facts,
            "reason_code": action_summary.reason_code,
            "explanation": action_summary.explanation,
            "aggregate_digest": _ref("placeholder"),
        }
    )
    action_payload = tampered_action.model_dump(mode="python")
    action_payload["aggregate_digest"] = canonical_digest(
        aggregation._action_decision_payload(tampered_action)
    )
    return action_payload


def test_rehash_cannot_turn_blocking_unknown_obligation_into_eligibility() -> None:
    unknown_approval = PolicyRule(
        rule_id="approval-if-external",
        effect=PolicyEffect.REQUIRE_APPROVAL,
        when={"requested_scope_expands": True},
    )
    decision = evaluate_policy_layers(
        capability_valid=False,
        layers=(
            _layer(
                PolicyLayer.SYSTEM,
                _grant("known", modes=("read",), extra_rules=(unknown_approval,)),
            ),
        ),
        resources=(_resource(),),
    )
    nested = decision.resource_decisions[0].layer_decisions[0].decision
    forged_nested = type(nested).model_validate(
        nested.model_dump(mode="python")
        | {
            "verdict": PolicyVerdict.ELIGIBLE,
            "allowed_modes": ("read",),
            "blocking_unknown_rules": (),
            "blocking_unknown_facts": (),
            "reason_code": "POLICY_ELIGIBLE",
        }
    )
    forged_payload = _forge_rehashed_aggregate_with_nested_decision(decision, forged_nested)

    with pytest.raises(ValidationError, match="deterministic re-evaluation"):
        type(decision).model_validate(forged_payload)


def test_rehash_cannot_drop_a_matched_approval_obligation_and_rule() -> None:
    approval = PolicyRule(
        rule_id="approval",
        effect=PolicyEffect.REQUIRE_APPROVAL,
        when={"action_in": ["fs.read"]},
    )
    decision = evaluate_policy_layers(
        capability_valid=True,
        layers=(
            _layer(
                PolicyLayer.SYSTEM,
                _grant("known", modes=("read",), extra_rules=(approval,)),
            ),
        ),
        resources=(_resource(),),
    )
    nested = decision.resource_decisions[0].layer_decisions[0].decision
    forged_nested = type(nested).model_validate(
        nested.model_dump(mode="python")
        | {
            "obligations": (),
            "matched_approvals": (),
        }
    )
    forged_payload = _forge_rehashed_aggregate_with_nested_decision(decision, forged_nested)

    with pytest.raises(ValidationError, match="deterministic re-evaluation"):
        type(decision).model_validate(forged_payload)
