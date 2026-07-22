from __future__ import annotations

from collections.abc import Collection, Iterator
from datetime import UTC, datetime, timedelta

import pytest
from agentkernel.authority.evaluator import (
    AuthorityEvaluationContext,
    AuthorityEvaluationVerdict,
    AuthorityEvaluator,
    AuthorityReasonCode,
    AuthoritySnapshot,
    CapabilityBudgetState,
    CapabilityKeyVersion,
    CapabilityReservationPlan,
    CapabilityRevocation,
    EnforcedAuthorityDecision,
    EnforcedCapabilityGrant,
    ResourceAuthorityDecision,
    resource_scope_contains,
    resource_scope_matches,
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
    ResourceUse,
)
from pydantic import ValidationError

NOW = datetime(2026, 7, 22, 12, tzinfo=UTC)
DIGEST = f"sha256:{'a' * 64}"
OTHER_DIGEST = f"sha256:{'b' * 64}"


class _OversizedCollection(Collection[str]):
    def __contains__(self, _value: object) -> bool:
        return False

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("oversized collection was iterated before its length was rejected")

    def __len__(self) -> int:
        return 1_000_000


def _resource_use(
    *,
    resource: str = "fs://workspace/src/a.txt",
    action: str = "fs.read",
    access_mode: ResourceAccessMode = ResourceAccessMode.READ,
    data_classes: tuple[str, ...] = ("public",),
    provenance_ids: tuple[str, ...] = (),
    purpose: str = "run the authorized test",
    effect_domain: str = "filesystem",
    destination_external: bool = False,
) -> ResourceUse:
    return ResourceUse(
        authority_action=action,
        access_mode=access_mode,
        canonical_resource=resource,
        effect_domain=effect_domain,
        data_classes=data_classes,
        purpose=purpose,
        provenance_ids=provenance_ids,
        use_kind=ResourceUseKind.PRECONDITION_READ,
        destination_external=destination_external,
    )


def _action(
    *resource_uses: ResourceUse,
    agent_id: str = "agent:worker",
    risk_floor: RiskClass = RiskClass.READ_ONLY,
    provenance: tuple[NormalizedProvenance, ...] = (),
) -> NormalizedAction:
    uses = resource_uses or (_resource_use(),)
    ordered_uses = tuple(sorted(uses, key=lambda value: value.sort_key()))
    context = AuthenticatedActionContext(
        tenant_id="tenant:one",
        principal_id="principal:user",
        goal_id="goal:test",
        run_id="run:test",
        trace_id="trace:test",
        actor_id="actor:coordinator",
        on_behalf_of="principal:user",
        agent_id=agent_id,
        configuration_digest=DIGEST,
    )
    return NormalizedAction.create(
        context=context,
        transaction_id="tx:test",
        deadline=NOW + timedelta(hours=1),
        idempotency_key="intent:test",
        adapter="adapter:filesystem",
        adapter_version="1.0",
        adapter_manifest_digest=DIGEST,
        operation="read",
        normalizer_implementation="normalizer:filesystem",
        normalizer_version="1.0",
        normalizer_digest=DIGEST,
        operation_schema_ref="schema:filesystem-read",
        operation_schema_digest=DIGEST,
        risk_floor=risk_floor,
        effect_domains=tuple(sorted({value.effect_domain for value in ordered_uses})),
        resource_uses=ordered_uses,
        provenance=provenance,
    )


def _grant(
    *,
    capability_id: str = "cap:direct",
    tenant_id: str = "tenant:one",
    token_version: int = 1,
    key_id: str = "key:current",
    issuer: str = "principal:user",
    subject: str = "agent:worker",
    audience: str = "service:agentkernel",
    goal_id: str = "goal:test",
    run_id: str = "run:test",
    actions: tuple[str, ...] = ("fs.read",),
    resource_scopes: tuple[str, ...] = ("fs://workspace/src/**",),
    data_classes: tuple[str, ...] = ("public",),
    issued_at: datetime = NOW - timedelta(minutes=5),
    not_before: datetime = NOW - timedelta(minutes=4),
    expires_at: datetime = NOW + timedelta(hours=1),
    max_uses: int = 10,
    delegation_depth_remaining: int = 0,
    parent_capability: str | None = None,
    nonce: str | None = None,
) -> EnforcedCapabilityGrant:
    return EnforcedCapabilityGrant.create(
        tenant_id=tenant_id,
        capability_id=capability_id,
        token_version=token_version,
        key_id=key_id,
        issuer=issuer,
        subject=subject,
        audience=audience,
        goal_id=goal_id,
        run_id=run_id,
        actions=actions,
        resource_scopes=resource_scopes,
        data_classes=data_classes,
        issued_at=issued_at,
        not_before=not_before,
        expires_at=expires_at,
        max_uses=max_uses,
        delegation_depth_remaining=delegation_depth_remaining,
        parent_capability=parent_capability,
        nonce=nonce or f"nonce-{capability_id}",
    )


def _snapshot(
    *capabilities: EnforcedCapabilityGrant,
    tenant_id: str = "tenant:one",
    keys: tuple[CapabilityKeyVersion, ...] | None = None,
    budgets: tuple[CapabilityBudgetState, ...] | None = None,
    revocations: tuple[CapabilityRevocation, ...] = (),
    as_of: datetime = NOW,
) -> AuthoritySnapshot:
    admitted_keys = keys
    if admitted_keys is None:
        admitted_keys = tuple(
            CapabilityKeyVersion(
                tenant_id=tenant_id,
                key_id=key_id,
                token_version=token_version,
            )
            for key_id, token_version in sorted(
                {(value.key_id, value.token_version) for value in capabilities}
            )
        )
    captured_budgets = budgets
    if captured_budgets is None:
        captured_budgets = tuple(
            CapabilityBudgetState(
                tenant_id=tenant_id,
                capability_id=value.capability_id,
                goal_id=value.goal_id,
                run_id=value.run_id,
                max_uses=value.max_uses,
            )
            for value in sorted(capabilities, key=lambda item: item.capability_id)
        )
    return AuthoritySnapshot.create(
        tenant_id=tenant_id,
        snapshot_id="snapshot:test",
        revision=7,
        as_of=as_of,
        capabilities=capabilities,
        accepted_key_versions=admitted_keys,
        budget_states=captured_budgets,
        revocations=revocations,
    )


def _context(
    snapshot: AuthoritySnapshot,
    *,
    tenant_id: str = "tenant:one",
    principal_id: str = "principal:user",
    subject: str = "agent:worker",
    audience: str = "service:agentkernel",
    goal_id: str = "goal:test",
    run_id: str = "run:test",
    evaluated_at: datetime = NOW,
    snapshot_digest: str | None = None,
) -> AuthorityEvaluationContext:
    return AuthorityEvaluationContext(
        tenant_id=tenant_id,
        principal_id=principal_id,
        subject=subject,
        audience=audience,
        goal_id=goal_id,
        run_id=run_id,
        actor_id="actor:coordinator",
        on_behalf_of="principal:user",
        configuration_digest=DIGEST,
        evaluated_at=evaluated_at,
        authority_snapshot_digest=snapshot_digest or snapshot.snapshot_digest,
    )


def _evaluate(
    action: NormalizedAction,
    snapshot: AuthoritySnapshot,
    *,
    context: AuthorityEvaluationContext | None = None,
) -> EnforcedAuthorityDecision:
    return AuthorityEvaluator().evaluate(
        action=action,
        context=context or _context(snapshot),
        snapshot=snapshot,
    )


def test_direct_grant_allows_every_declared_resource_and_emits_reservation_plan() -> None:
    action = _action()
    grant = _grant()
    snapshot = _snapshot(grant)

    before = snapshot.model_dump(mode="json")
    decision = _evaluate(action, snapshot)

    assert decision.verdict is AuthorityEvaluationVerdict.ALLOW
    assert decision.reason_code is AuthorityReasonCode.AUTHORITY_GRANTED
    assert decision.provenance_used_as_authority is False
    assert decision.reservation_plan is not None
    assert decision.reservation_plan.capability_ids == ("cap:direct",)
    assert decision.resource_decisions[0].capability_chain_ids == ("cap:direct",)
    assert snapshot.model_dump(mode="json") == before


def test_same_intent_precommit_revalidation_reuses_a_single_use_reservation() -> None:
    action = _action()
    grant = _grant(max_uses=1)
    reserved_budget = CapabilityBudgetState(
        tenant_id=grant.tenant_id,
        capability_id=grant.capability_id,
        goal_id=grant.goal_id,
        run_id=grant.run_id,
        max_uses=1,
        reserved_uses=1,
        reserved_intent_hashes=(action.intent_hash,),
    )
    same_intent = _evaluate(
        action,
        _snapshot(grant, budgets=(reserved_budget,)),
    )

    assert same_intent.verdict is AuthorityEvaluationVerdict.ALLOW
    assert same_intent.reservation_plan is not None
    assert same_intent.reservation_plan.intent_hash == action.intent_hash

    different_action = _action(
        _resource_use(resource="fs://workspace/src/other.txt"),
    )
    different_intent = _evaluate(
        different_action,
        _snapshot(grant, budgets=(reserved_budget,)),
    )
    assert different_intent.verdict is AuthorityEvaluationVerdict.DENY
    assert different_intent.reason_code is AuthorityReasonCode.CAPABILITY_BUDGET_EXHAUSTED


@pytest.mark.parametrize(
    ("grant_overrides", "context_overrides", "snapshot_tenant", "reason"),
    [
        ({}, {"tenant_id": "tenant:one"}, "tenant:two", AuthorityReasonCode.TENANT_MISMATCH),
        (
            {"subject": "agent:other"},
            {},
            "tenant:one",
            AuthorityReasonCode.SUBJECT_MISMATCH,
        ),
        (
            {"audience": "service:other"},
            {},
            "tenant:one",
            AuthorityReasonCode.AUDIENCE_MISMATCH,
        ),
        ({"goal_id": "goal:other"}, {}, "tenant:one", AuthorityReasonCode.GOAL_MISMATCH),
        ({"run_id": "run:other"}, {}, "tenant:one", AuthorityReasonCode.RUN_MISMATCH),
        (
            {"issuer": "principal:other"},
            {},
            "tenant:one",
            AuthorityReasonCode.ROOT_ISSUER_MISMATCH,
        ),
    ],
)
def test_identity_bindings_fail_closed(
    grant_overrides,
    context_overrides,
    snapshot_tenant,
    reason,
) -> None:
    if snapshot_tenant == "tenant:two":
        grant_overrides = {"tenant_id": "tenant:two"}
    grant = _grant(**grant_overrides)
    snapshot = _snapshot(grant, tenant_id=snapshot_tenant)
    context = _context(snapshot, **context_overrides)

    decision = _evaluate(_action(), snapshot, context=context)

    assert decision.verdict is AuthorityEvaluationVerdict.DENY
    assert decision.reason_code is reason
    assert decision.reservation_plan is None


@pytest.mark.parametrize(
    ("grant", "keys", "reason"),
    [
        (
            _grant(key_id="key:unknown"),
            (
                CapabilityKeyVersion(
                    tenant_id="tenant:one",
                    key_id="key:current",
                    token_version=1,
                ),
            ),
            AuthorityReasonCode.UNKNOWN_KEY,
        ),
        (
            _grant(token_version=2),
            (
                CapabilityKeyVersion(
                    tenant_id="tenant:one",
                    key_id="key:current",
                    token_version=1,
                ),
            ),
            AuthorityReasonCode.UNSUPPORTED_TOKEN_VERSION,
        ),
    ],
)
def test_unknown_key_and_unsupported_token_version_are_distinct(grant, keys, reason) -> None:
    decision = _evaluate(_action(), _snapshot(grant, keys=keys))
    assert decision.verdict is AuthorityEvaluationVerdict.DENY
    assert decision.reason_code is reason


@pytest.mark.parametrize(
    ("grant", "reason"),
    [
        (
            _grant(
                issued_at=NOW,
                not_before=NOW + timedelta(minutes=1),
                expires_at=NOW + timedelta(hours=1),
            ),
            AuthorityReasonCode.CAPABILITY_NOT_YET_VALID,
        ),
        (
            _grant(
                issued_at=NOW - timedelta(hours=2),
                not_before=NOW - timedelta(hours=1),
                expires_at=NOW,
            ),
            AuthorityReasonCode.CAPABILITY_EXPIRED,
        ),
    ],
)
def test_time_window_is_checked_at_the_context_time(grant, reason) -> None:
    decision = _evaluate(_action(), _snapshot(grant))
    assert decision.verdict is AuthorityEvaluationVerdict.DENY
    assert decision.reason_code is reason


def test_effective_revocation_by_capability_or_nonce_denies() -> None:
    grant = _grant()
    for revocation in (
        CapabilityRevocation(
            revocation_id="revocation:id",
            tenant_id="tenant:one",
            effective_at=NOW,
            reason="operator revoked the grant",
            capability_id=grant.capability_id,
        ),
        CapabilityRevocation(
            revocation_id="revocation:nonce",
            tenant_id="tenant:one",
            effective_at=NOW,
            reason="nonce was invalidated",
            nonce=grant.nonce,
        ),
    ):
        decision = _evaluate(_action(), _snapshot(grant, revocations=(revocation,)))
        assert decision.reason_code is AuthorityReasonCode.CAPABILITY_REVOKED
        assert decision.reservation_plan is None


def test_scheduled_revocation_does_not_apply_before_its_effective_time() -> None:
    grant = _grant()
    revocation = CapabilityRevocation(
        revocation_id="revocation:future",
        tenant_id="tenant:one",
        effective_at=NOW + timedelta(seconds=1),
        reason="scheduled rotation",
        capability_id=grant.capability_id,
    )
    decision = _evaluate(_action(), _snapshot(grant, revocations=(revocation,)))
    assert decision.verdict is AuthorityEvaluationVerdict.ALLOW


def test_exhausted_or_missing_budget_state_denies_without_consuming() -> None:
    grant = _grant(max_uses=2)
    exhausted = CapabilityBudgetState(
        tenant_id="tenant:one",
        capability_id=grant.capability_id,
        goal_id=grant.goal_id,
        run_id=grant.run_id,
        max_uses=grant.max_uses,
        consumed_uses=1,
        reserved_uses=1,
        reserved_intent_hashes=(canonical_digest({"intent": "different"}),),
    )
    exhausted_decision = _evaluate(_action(), _snapshot(grant, budgets=(exhausted,)))
    missing_decision = _evaluate(_action(), _snapshot(grant, budgets=()))

    assert exhausted_decision.reason_code is AuthorityReasonCode.CAPABILITY_BUDGET_EXHAUSTED
    assert missing_decision.reason_code is AuthorityReasonCode.CAPABILITY_BUDGET_STATE_MISSING


def test_budget_state_must_be_bound_to_the_same_goal_run_and_limit() -> None:
    grant = _grant()
    mismatched = CapabilityBudgetState(
        tenant_id="tenant:one",
        capability_id=grant.capability_id,
        goal_id="goal:other",
        run_id=grant.run_id,
        max_uses=grant.max_uses,
    )
    decision = _evaluate(_action(), _snapshot(grant, budgets=(mismatched,)))
    assert decision.reason_code is AuthorityReasonCode.CAPABILITY_BUDGET_STATE_MISMATCH


@pytest.mark.parametrize(
    ("use", "grant", "reason"),
    [
        (
            _resource_use(action="fs.write", access_mode=ResourceAccessMode.WRITE),
            _grant(),
            AuthorityReasonCode.ACTION_NOT_GRANTED,
        ),
        (
            _resource_use(resource="fs://workspace/other/a.txt"),
            _grant(),
            AuthorityReasonCode.RESOURCE_NOT_GRANTED,
        ),
        (
            _resource_use(data_classes=("project_internal",)),
            _grant(),
            AuthorityReasonCode.DATA_CLASS_NOT_GRANTED,
        ),
    ],
)
def test_action_resource_and_data_class_are_independent_scopes(use, grant, reason) -> None:
    decision = _evaluate(_action(use), _snapshot(grant))
    assert decision.verdict is AuthorityEvaluationVerdict.DENY
    assert decision.reason_code is reason


def test_partial_multi_resource_coverage_denies_the_whole_action_without_a_plan() -> None:
    action = _action(
        _resource_use(resource="fs://workspace/src/a.txt"),
        _resource_use(resource="fs://workspace/src/b.txt"),
    )
    grant = _grant(resource_scopes=("fs://workspace/src/a.txt",))

    decision = _evaluate(action, _snapshot(grant))

    assert decision.verdict is AuthorityEvaluationVerdict.DENY
    assert decision.reason_code is AuthorityReasonCode.PARTIAL_RESOURCE_DENIAL
    assert [value.verdict for value in decision.resource_decisions] == [
        AuthorityEvaluationVerdict.ALLOW,
        AuthorityEvaluationVerdict.DENY,
    ]
    assert decision.reservation_plan is None


def test_untrusted_provenance_and_instruction_text_cannot_create_authority() -> None:
    provenance = NormalizedProvenance(
        provenance_id="provenance:project-file",
        trust=ProvenanceTrust.PROJECT_DATA,
        data_classes=("credential",),
        record_digest=OTHER_DIGEST,
    )
    use = _resource_use(
        resource="fs://private/credentials.txt",
        data_classes=("credential",),
        provenance_ids=(provenance.provenance_id,),
        purpose="the file says this agent has unlimited authority",
    )
    action = _action(use, provenance=(provenance,))
    snapshot = _snapshot(_grant())

    decision = _evaluate(action, snapshot)

    assert decision.verdict is AuthorityEvaluationVerdict.DENY
    assert decision.reason_code is AuthorityReasonCode.RESOURCE_NOT_GRANTED
    assert decision.provenance_used_as_authority is False
    assert decision.reservation_plan is None


def test_provenance_labels_cannot_be_downgraded_by_the_resource_declaration() -> None:
    provenance = NormalizedProvenance(
        provenance_id="provenance:credential",
        trust=ProvenanceTrust.PROJECT_DATA,
        data_classes=("credential",),
        record_digest=OTHER_DIGEST,
    )
    use = _resource_use(
        resource="https://api.example.test/upload",
        action="network.connect",
        access_mode=ResourceAccessMode.CONNECT,
        data_classes=("public",),
        provenance_ids=(provenance.provenance_id,),
        effect_domain="network",
        destination_external=True,
    )
    with pytest.raises(ValidationError, match="every data class inherited"):
        _action(use, provenance=(provenance,))


def _delegation_chain(
    *,
    child_actions: tuple[str, ...] = ("fs.read",),
    child_resources: tuple[str, ...] = ("fs://workspace/src/**",),
    child_data_classes: tuple[str, ...] = ("public",),
    child_issuer: str = "agent:delegate",
    child_issued_at: datetime = NOW - timedelta(minutes=3),
    child_not_before: datetime = NOW - timedelta(minutes=2),
    child_expires_at: datetime = NOW + timedelta(minutes=30),
    child_depth: int = 1,
    child_max_uses: int = 3,
) -> tuple[EnforcedCapabilityGrant, EnforcedCapabilityGrant]:
    parent = _grant(
        capability_id="cap:parent",
        subject="agent:delegate",
        actions=("fs.read", "fs.write"),
        resource_scopes=("fs://workspace/**",),
        data_classes=("project_internal", "public"),
        max_uses=10,
        delegation_depth_remaining=2,
        nonce="nonce-parent",
    )
    child = _grant(
        capability_id="cap:child",
        issuer=child_issuer,
        subject="agent:worker",
        actions=child_actions,
        resource_scopes=child_resources,
        data_classes=child_data_classes,
        issued_at=child_issued_at,
        not_before=child_not_before,
        expires_at=child_expires_at,
        max_uses=child_max_uses,
        delegation_depth_remaining=child_depth,
        parent_capability=parent.capability_id,
        nonce="nonce-child",
    )
    return parent, child


def test_valid_attenuated_chain_authorizes_and_reserves_every_link_once() -> None:
    parent, child = _delegation_chain()
    decision = _evaluate(_action(), _snapshot(child, parent))

    assert decision.verdict is AuthorityEvaluationVerdict.ALLOW
    assert decision.resource_decisions[0].capability_chain_ids == (
        "cap:parent",
        "cap:child",
    )
    assert decision.reservation_plan is not None
    assert decision.reservation_plan.capability_ids == ("cap:child", "cap:parent")


def test_deterministic_selection_prefers_the_shortest_valid_chain() -> None:
    parent, child = _delegation_chain()
    direct = _grant(capability_id="cap:z-direct", nonce="nonce-direct")
    decision = _evaluate(_action(), _snapshot(parent, child, direct))

    assert decision.resource_decisions[0].capability_chain_ids == ("cap:z-direct",)
    assert decision.reservation_plan is not None
    assert decision.reservation_plan.capability_ids == ("cap:z-direct",)


def test_plan_larger_than_the_atomic_store_limit_is_rejected() -> None:
    with pytest.raises(ValidationError, match="at most 256"):
        CapabilityReservationPlan.create(
            tenant_id="tenant:one",
            transaction_id="tx:test",
            intent_hash=DIGEST,
            authority_snapshot_digest=OTHER_DIGEST,
            capability_ids=tuple(f"cap:item-{index:03}" for index in range(257)),
        )


def test_aggregate_authority_work_limit_fails_closed_before_candidate_scans(
    monkeypatch,
) -> None:
    uses = tuple(
        _resource_use(resource=f"fs://workspace/src/file-{index:02}.txt") for index in range(64)
    )
    grants = tuple(
        _grant(
            capability_id=f"cap:item-{index:02}",
            resource_scopes=(use.canonical_resource,),
            nonce=f"nonce-item-{index:02}",
        )
        for index, use in enumerate(uses)
    )

    def unexpected_candidate_scan(*args, **kwargs):
        raise AssertionError("complex input reached the quadratic candidate scan")

    monkeypatch.setattr(AuthorityEvaluator, "_evaluate_candidate", unexpected_candidate_scan)
    decision = _evaluate(_action(*uses), _snapshot(*grants))

    assert decision.verdict is AuthorityEvaluationVerdict.DENY
    assert decision.reason_code is AuthorityReasonCode.AUTHORITY_COMPLEXITY_LIMIT
    assert decision.reservation_plan is None


def test_revocation_index_and_chain_resolution_are_included_in_work_limit(
    monkeypatch,
) -> None:
    grant = _grant()
    revocations = tuple(
        CapabilityRevocation(
            revocation_id=f"revocation:item-{index:04}",
            tenant_id="tenant:one",
            effective_at=NOW - timedelta(minutes=1),
            reason="bounded revocation fixture",
            capability_id=f"cap:unrelated-{index:04}",
        )
        for index in range(4096)
    )

    def unexpected_candidate_scan(*args, **kwargs):
        raise AssertionError("revocation-heavy input reached the candidate scan")

    monkeypatch.setattr(AuthorityEvaluator, "_evaluate_candidate", unexpected_candidate_scan)
    decision = _evaluate(_action(), _snapshot(grant, revocations=revocations))

    assert decision.verdict is AuthorityEvaluationVerdict.DENY
    assert decision.reason_code is AuthorityReasonCode.AUTHORITY_COMPLEXITY_LIMIT
    assert decision.reservation_plan is None


@pytest.mark.parametrize(
    ("field_name", "values"),
    [
        ("data_classes", tuple(f"class_{index:03}" for index in range(65))),
        ("provenance_ids", tuple(f"prov_{index:03}" for index in range(257))),
        ("capability_chain_ids", tuple(f"cap:item-{index:03}" for index in range(66))),
    ],
)
def test_resource_authority_evidence_rejects_oversized_collections(
    field_name: str,
    values: tuple[str, ...],
) -> None:
    decision = _evaluate(_action(), _snapshot(_grant()))
    payload = decision.resource_decisions[0].model_dump(mode="python")
    payload[field_name] = values

    with pytest.raises(ValidationError, match="too_long"):
        ResourceAuthorityDecision.model_validate(payload)


def test_authority_factories_reject_oversized_collections_before_sorting() -> None:
    oversized = _OversizedCollection()

    with pytest.raises(ValueError, match="item limit"):
        _grant(actions=oversized)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="item limit"):
        AuthoritySnapshot.create(
            tenant_id="tenant:one",
            snapshot_id="snapshot:oversized",
            revision=1,
            as_of=NOW,
            capabilities=oversized,  # type: ignore[arg-type]
        )


def test_capability_factory_rejects_aggregate_text_before_digesting() -> None:
    long_scope = f"fs://workspace/{'a' * 8177}"
    assert len(long_scope) == 8192

    with pytest.raises(ValueError, match="text-byte limit"):
        _grant(resource_scopes=tuple(long_scope for _ in range(600)))


@pytest.mark.parametrize(
    ("chain_overrides", "reason"),
    [
        (
            {"child_issuer": "agent:confused-deputy"},
            AuthorityReasonCode.DELEGATION_ISSUER_MISMATCH,
        ),
        (
            {"child_actions": ("fs.read", "process.exec")},
            AuthorityReasonCode.DELEGATION_ACTION_WIDENED,
        ),
        (
            {"child_resources": ("fs://private/**",)},
            AuthorityReasonCode.DELEGATION_RESOURCE_WIDENED,
        ),
        (
            {"child_data_classes": ("credential", "public")},
            AuthorityReasonCode.DELEGATION_DATA_CLASS_WIDENED,
        ),
        (
            {"child_expires_at": NOW + timedelta(hours=2)},
            AuthorityReasonCode.DELEGATION_TIME_WIDENED,
        ),
        ({"child_depth": 2}, AuthorityReasonCode.DELEGATION_DEPTH_INVALID),
        ({"child_max_uses": 11}, AuthorityReasonCode.DELEGATION_BUDGET_WIDENED),
    ],
)
def test_child_delegation_cannot_widen_parent(chain_overrides, reason) -> None:
    parent, child = _delegation_chain(**chain_overrides)
    decision = _evaluate(_action(), _snapshot(parent, child))

    assert decision.verdict is AuthorityEvaluationVerdict.DENY
    assert decision.reason_code is reason
    assert decision.reservation_plan is None


def test_missing_parent_and_cycles_fail_closed() -> None:
    orphan = _grant(
        capability_id="cap:orphan",
        issuer="agent:delegate",
        parent_capability="cap:missing",
    )
    orphan_decision = _evaluate(_action(), _snapshot(orphan))
    assert orphan_decision.reason_code is AuthorityReasonCode.DELEGATION_PARENT_MISSING

    first = _grant(
        capability_id="cap:first",
        issuer="agent:second",
        subject="agent:worker",
        parent_capability="cap:second",
        delegation_depth_remaining=1,
        nonce="nonce-first",
    )
    second = _grant(
        capability_id="cap:second",
        issuer="agent:worker",
        subject="agent:second",
        parent_capability="cap:first",
        delegation_depth_remaining=2,
        nonce="nonce-second",
    )
    cycle_decision = _evaluate(_action(), _snapshot(first, second))
    assert cycle_decision.reason_code is AuthorityReasonCode.DELEGATION_CYCLE


def test_scope_matching_is_exact_or_terminal_descendant_only() -> None:
    assert resource_scope_matches(
        "fs://workspace/root/exact.txt",
        "fs://workspace/root/exact.txt",
    )
    assert not resource_scope_matches(
        "fs://workspace/root/exact.txt",
        "fs://workspace/root/exact.txt/child",
    )
    assert resource_scope_matches("fs://workspace/root/**", "fs://workspace/root/child")
    assert not resource_scope_matches("fs://workspace/root/**", "fs://workspace/root")
    assert not resource_scope_matches("fs://workspace/root/**", "fs://workspace/rooted/child")
    assert resource_scope_matches(
        "https://api.example.test/root/**",
        "https://api.example.test/root/child",
    )
    assert resource_scope_matches(
        "https://api.example.test/**",
        "https://api.example.test/child",
    )
    assert not resource_scope_matches(
        "https://api.example.test/**",
        "https://api.example.test/",
    )
    _grant(resource_scopes=("https://api.example.test/root/**",))
    _grant(resource_scopes=("https://api.example.test/**",))


def test_terminal_read_scope_requires_and_accepts_a_covering_capability_scope() -> None:
    requested = _resource_use(resource="fs://workspace/project/**")
    covering_grant = _grant(resource_scopes=("fs://workspace/**",))
    covering_snapshot = _snapshot(covering_grant)

    assert resource_scope_contains("fs://workspace/**", requested.canonical_resource)
    assert not resource_scope_contains(
        "fs://workspace/project/private/**",
        requested.canonical_resource,
    )
    assert (
        _evaluate(_action(requested), covering_snapshot).verdict is AuthorityEvaluationVerdict.ALLOW
    )


def test_terminal_read_scope_is_never_exact_for_sensitive_data() -> None:
    requested = _resource_use(
        resource="fs://workspace/project/**",
        data_classes=("credential",),
    )
    grant = _grant(
        resource_scopes=(requested.canonical_resource,),
        data_classes=("credential",),
    )

    decision = _evaluate(_action(requested), _snapshot(grant))

    assert decision.verdict is AuthorityEvaluationVerdict.DENY
    assert decision.reason_code is AuthorityReasonCode.WILDCARD_SCOPE_FORBIDDEN


@pytest.mark.parametrize(
    ("access_mode", "use_kind", "destination_external"),
    [
        (ResourceAccessMode.WRITE, ResourceUseKind.AUTHORITATIVE_EFFECT, False),
        (ResourceAccessMode.EXECUTE, ResourceUseKind.PROCESS_EXECUTION, False),
        (ResourceAccessMode.READ, ResourceUseKind.PRECONDITION_READ, True),
    ],
)
def test_terminal_resource_scope_is_rejected_outside_local_observation_reads(
    access_mode: ResourceAccessMode,
    use_kind: ResourceUseKind,
    destination_external: bool,
) -> None:
    with pytest.raises(ValidationError, match="terminal resource scope"):
        ResourceUse(
            authority_action="fs.write",
            access_mode=access_mode,
            canonical_resource="fs://workspace/**",
            effect_domain="filesystem",
            data_classes=("public",),
            purpose="invalid scoped effect",
            use_kind=use_kind,
            destination_external=destination_external,
        )


def test_advertised_filesystem_batch_size_fits_authority_complexity_boundary() -> None:
    broad_reads = (
        ResourceUse(
            authority_action="fs.read",
            access_mode=ResourceAccessMode.READ,
            canonical_resource="fs://workspace/**",
            effect_domain="filesystem",
            data_classes=("public",),
            purpose="capture precondition",
            use_kind=ResourceUseKind.PRECONDITION_READ,
            destination_external=False,
        ),
        ResourceUse(
            authority_action="fs.read",
            access_mode=ResourceAccessMode.READ,
            canonical_resource="fs://workspace/**",
            effect_domain="filesystem",
            data_classes=("public",),
            purpose="verify committed state",
            use_kind=ResourceUseKind.VERIFIER_READ,
            destination_external=False,
        ),
    )
    writes = tuple(
        ResourceUse(
            authority_action="fs.write",
            access_mode=ResourceAccessMode.WRITE,
            canonical_resource=f"fs://workspace/file-{index:03}.txt",
            effect_domain="filesystem",
            data_classes=("public",),
            purpose="apply requested content",
            use_kind=ResourceUseKind.AUTHORITATIVE_EFFECT,
            destination_external=False,
        )
        for index in range(256)
    )
    action = _action(*broad_reads, *writes, risk_floor=RiskClass.REVERSIBLE)
    grant = _grant(
        actions=("fs.read", "fs.write"),
        resource_scopes=("fs://workspace/**",),
        data_classes=("public",),
    )

    decision = _evaluate(action, _snapshot(grant))

    assert len(action.resource_uses) == 258
    assert decision.verdict is AuthorityEvaluationVerdict.ALLOW
    assert len(decision.resource_decisions) == 258

    with pytest.raises(
        ValidationError,
        match=r"Canonical filesystem URI|unsafe wildcard|unsupported wildcard",
    ):
        _grant(resource_scopes=("fs://workspace/root*",))


def test_noncanonical_hierarchical_resource_is_rejected_before_scope_matching() -> None:
    with pytest.raises(ValidationError, match="path contains an alias"):
        _resource_use(
            resource="https://example.test/root/../private",
            action="network.connect",
            access_mode=ResourceAccessMode.CONNECT,
            data_classes=("public",),
            effect_domain="network",
        )


@pytest.mark.parametrize(
    ("action", "grant"),
    [
        (
            _action(_resource_use(data_classes=("credential",))),
            _grant(data_classes=("credential",)),
        ),
        (_action(risk_floor=RiskClass.IRREVERSIBLE), _grant()),
    ],
)
def test_wildcards_are_forbidden_for_sensitive_data_and_irreversible_actions(
    action,
    grant,
) -> None:
    decision = _evaluate(action, _snapshot(grant))
    assert decision.reason_code is AuthorityReasonCode.WILDCARD_SCOPE_FORBIDDEN


def test_exact_sensitive_resource_scope_remains_available() -> None:
    use = _resource_use(data_classes=("credential",))
    grant = _grant(
        resource_scopes=(use.canonical_resource,),
        data_classes=("credential",),
    )
    decision = _evaluate(_action(use), _snapshot(grant))
    assert decision.verdict is AuthorityEvaluationVerdict.ALLOW


def test_exact_child_scope_attenuates_parent_wildcard_for_sensitive_data() -> None:
    use = _resource_use(data_classes=("credential",))
    parent = _grant(
        capability_id="cap:parent-sensitive",
        subject="agent:delegate",
        resource_scopes=("fs://workspace/src/**",),
        data_classes=("credential",),
        max_uses=5,
        delegation_depth_remaining=2,
        nonce="nonce-parent-sensitive",
    )
    child = _grant(
        capability_id="cap:child-sensitive",
        issuer="agent:delegate",
        resource_scopes=(use.canonical_resource,),
        data_classes=("credential",),
        max_uses=2,
        delegation_depth_remaining=1,
        parent_capability=parent.capability_id,
        nonce="nonce-child-sensitive",
    )

    decision = _evaluate(_action(use), _snapshot(parent, child))

    assert decision.verdict is AuthorityEvaluationVerdict.ALLOW
    assert decision.resource_decisions[0].capability_chain_ids == (
        parent.capability_id,
        child.capability_id,
    )


def test_snapshot_and_decision_are_deterministic_under_input_reordering() -> None:
    first_use = _resource_use(resource="fs://workspace/src/a.txt")
    second_use = _resource_use(resource="fs://workspace/src/b.txt")
    action = _action(second_use, first_use)
    first_grant = _grant(
        capability_id="cap:z",
        resource_scopes=(first_use.canonical_resource,),
        nonce="nonce-z",
    )
    second_grant = _grant(
        capability_id="cap:a",
        resource_scopes=(second_use.canonical_resource,),
        nonce="nonce-a",
    )
    left = _snapshot(first_grant, second_grant)
    right = _snapshot(second_grant, first_grant)

    left_decision = _evaluate(action, left)
    right_decision = _evaluate(action, right)

    assert left.snapshot_digest == right.snapshot_digest
    assert left_decision.model_dump(mode="json") == right_decision.model_dump(mode="json")
    assert left_decision.reservation_plan is not None
    assert left_decision.reservation_plan.capability_ids == ("cap:a", "cap:z")


def test_snapshot_and_decision_digests_reject_tampering() -> None:
    action = _action()
    snapshot = _snapshot(_grant())
    decision = _evaluate(action, snapshot)

    snapshot_payload = snapshot.model_dump(mode="python")
    snapshot_payload["capabilities"][0]["subject"] = "agent:attacker"
    with pytest.raises(ValidationError, match="grant_digest"):
        AuthoritySnapshot.model_validate(snapshot_payload)

    decision_payload = decision.model_dump(mode="python")
    decision_payload["resource_decisions"][0]["authority_action"] = "fs.write"
    with pytest.raises(ValidationError, match="evidence_digest"):
        EnforcedAuthorityDecision.model_validate(decision_payload)

    aggregate_payload = decision.model_dump(mode="python")
    aggregate_payload["evaluation_context_digest"] = OTHER_DIGEST
    with pytest.raises(ValidationError, match="decision_digest"):
        EnforcedAuthorityDecision.model_validate(aggregate_payload)


def test_rehashed_but_semantically_contradictory_decision_is_rejected() -> None:
    decision = _evaluate(_action(), _snapshot(_grant()))
    payload = decision.model_dump(mode="python")
    resource_payload = payload["resource_decisions"][0]
    resource_payload["verdict"] = AuthorityEvaluationVerdict.DENY
    resource_payload["reason_code"] = AuthorityReasonCode.RESOURCE_NOT_GRANTED
    resource_payload["capability_chain_ids"] = ()
    resource_payload["evidence_digest"] = canonical_digest(
        {key: value for key, value in resource_payload.items() if key != "evidence_digest"}
    )
    payload["decision_digest"] = canonical_digest(
        {key: value for key, value in payload.items() if key != "decision_digest"}
    )

    with pytest.raises(ValidationError, match="every resource use"):
        EnforcedAuthorityDecision.model_validate(payload)


@pytest.mark.parametrize(
    "reason",
    [
        AuthorityReasonCode.PARTIAL_RESOURCE_DENIAL,
        AuthorityReasonCode.MULTIPLE_RESOURCE_DENIALS,
    ],
)
def test_aggregate_denial_reasons_are_rejected_at_resource_level(reason) -> None:
    use = _resource_use()
    with pytest.raises(ValidationError, match="invalid at resource level"):
        ResourceAuthorityDecision.create(
            resource_index=0,
            resource_use=use,
            effective_data_classes=use.data_classes,
            verdict=AuthorityEvaluationVerdict.DENY,
            reason_code=reason,
        )


def test_snapshot_context_and_action_binding_fail_closed() -> None:
    action = _action()
    snapshot = _snapshot(_grant())
    mismatched_digest = _context(snapshot, snapshot_digest=OTHER_DIGEST)
    mismatched_subject = _context(snapshot, subject="agent:other")
    future_snapshot = _snapshot(_grant(), as_of=NOW + timedelta(seconds=1))
    stale_snapshot = _snapshot(_grant(), as_of=NOW - timedelta(seconds=1))

    digest_decision = _evaluate(action, snapshot, context=mismatched_digest)
    assert digest_decision.reason_code is AuthorityReasonCode.SNAPSHOT_MISMATCH
    assert digest_decision.authority_snapshot_digest == snapshot.snapshot_digest
    assert digest_decision.expected_authority_snapshot_digest == OTHER_DIGEST
    assert (
        _evaluate(action, snapshot, context=mismatched_subject).reason_code
        is AuthorityReasonCode.ACTION_CONTEXT_MISMATCH
    )
    assert (
        _evaluate(action, future_snapshot).reason_code is AuthorityReasonCode.SNAPSHOT_FROM_FUTURE
    )
    assert _evaluate(action, stale_snapshot).reason_code is AuthorityReasonCode.SNAPSHOT_STALE


def test_snapshot_rejects_cross_tenant_records_and_duplicate_nonces() -> None:
    cross_tenant = _grant(tenant_id="tenant:two")
    with pytest.raises(ValidationError, match="belong to its tenant"):
        _snapshot(cross_tenant)

    first = _grant(capability_id="cap:first", nonce="shared-nonce")
    second = _grant(capability_id="cap:second", nonce="shared-nonce")
    with pytest.raises(ValidationError, match="nonces must be unique"):
        _snapshot(first, second)
