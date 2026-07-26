from __future__ import annotations

from pathlib import Path

import pytest
from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import ProvenanceTrust, RiskClass
from agentkernel.domain.models import PolicyBundle, PolicyDefault, PolicyEffect, PolicyRule
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.policy.engine import (
    CompiledPolicy,
    PolicyContext,
    PolicyVerdict,
    compile_policy,
    load_policy,
)
from pydantic import ValidationError


def test_repository_policy_allows_scoped_staged_write() -> None:
    policy = load_policy(Path("policies/system/base.yaml"))
    decision = policy.evaluate(
        PolicyContext(
            action="fs.write",
            resource="fs://workspace/src/result.txt",
            provenance_trust=(ProvenanceTrust.MODEL_GENERATED,),
            requested_scope_expands=False,
            data_classes=("project_data",),
            destination_external=False,
            risk_class=RiskClass.REVERSIBLE,
        )
    )
    assert decision.verdict is PolicyVerdict.ELIGIBLE
    assert decision.allowed_modes == ("commit_reversible", "stage")
    assert decision.matched_grants == ("staged-workspace-write",)


def test_deny_dominates_a_matching_grant() -> None:
    policy = load_policy(Path("policies/system/base.yaml"))
    decision = policy.evaluate(
        PolicyContext(
            action="fs.write",
            resource="fs://workspace/src/result.txt",
            provenance_trust=(ProvenanceTrust.PROJECT_DATA,),
            requested_scope_expands=True,
            risk_class=RiskClass.REVERSIBLE,
        )
    )
    assert decision.verdict is PolicyVerdict.DENY
    assert "untrusted-data-cannot-expand-authority" in decision.matched_denials


def test_obligation_never_grants_permission() -> None:
    bundle = PolicyBundle(
        name="approval-only",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="review-external",
                effect=PolicyEffect.REQUIRE_APPROVAL,
                when={"destination_external": True},
            ),
        ),
    )
    decision = compile_policy(bundle).evaluate(
        PolicyContext(
            action="network.send",
            resource="http://example.test/",
            destination_external=True,
            risk_class=RiskClass.IRREVERSIBLE,
        )
    )
    assert decision.verdict is PolicyVerdict.DENY
    assert decision.obligations == ("approval",)


def test_matched_obligation_rules_are_explicit_evidence() -> None:
    bundle = PolicyBundle(
        name="obligation-evidence",
        version="1.0.0",
        default=PolicyDefault.ABSTAIN,
        rules=(
            PolicyRule(
                rule_id="grant-read",
                effect=PolicyEffect.GRANT,
                modes=("read",),
                when={"action_in": ["fs.read"]},
            ),
            PolicyRule(
                rule_id="approval-read",
                effect=PolicyEffect.REQUIRE_APPROVAL,
                when={"action_in": ["fs.read"]},
            ),
            PolicyRule(
                rule_id="shadow-read",
                effect=PolicyEffect.REQUIRE_SHADOW,
                when={"action_in": ["fs.read"]},
            ),
        ),
    )

    decision = compile_policy(bundle).evaluate(
        PolicyContext(
            action="fs.read",
            resource="fs://workspace/a.txt",
            risk_class=RiskClass.READ_ONLY,
        )
    )

    assert decision.verdict is PolicyVerdict.ELIGIBLE
    assert decision.obligations == ("approval", "shadow")
    assert decision.matched_approvals == ("approval-read",)
    assert decision.matched_shadows == ("shadow-read",)


def test_default_abstain_is_explicit_and_does_not_grant() -> None:
    bundle = PolicyBundle(
        name="abstaining",
        version="1.0.0",
        default=PolicyDefault.ABSTAIN,
        rules=(),
    )

    decision = compile_policy(bundle).evaluate(
        PolicyContext(
            action="fs.read",
            resource="fs://workspace/a.txt",
            risk_class=RiskClass.READ_ONLY,
        )
    )

    assert decision.verdict is PolicyVerdict.ABSTAIN
    assert decision.allowed_modes == ()
    assert decision.reason_code == "POLICY_ABSTAINED"


def test_unknown_fact_that_could_activate_a_deny_fails_closed() -> None:
    policy = load_policy(Path("policies/system/base.yaml"))
    decision = policy.evaluate(
        PolicyContext(
            action="fs.write",
            resource="fs://workspace/src/result.txt",
            provenance_trust=(ProvenanceTrust.MODEL_GENERATED,),
            data_classes=("project_data",),
            destination_external=False,
            risk_class=RiskClass.REVERSIBLE,
        )
    )

    assert decision.verdict is PolicyVerdict.DENY
    assert decision.reason_code == ErrorCode.POLICY_UNKNOWN.value
    assert decision.unknown_facts == ("requested_scope_expands",)
    assert decision.unknown_rules == ("untrusted-data-cannot-expand-authority",)


def test_unknown_grant_fails_closed_when_it_could_remove_the_known_mode() -> None:
    unknown_grant = PolicyRule(
        rule_id="unknown-grant",
        effect=PolicyEffect.GRANT,
        modes=("model_external",),
        when={"destination_external": True},
    )
    known_grant = PolicyRule(
        rule_id="known-grant",
        effect=PolicyEffect.GRANT,
        modes=("read",),
        when={"action_in": ["fs.read"]},
    )
    policy = compile_policy(
        PolicyBundle(
            name="tri-state-grants",
            version="1.0.0",
            default=PolicyDefault.ABSTAIN,
            rules=(unknown_grant, known_grant),
        )
    )
    context = PolicyContext(
        action="fs.read",
        resource="fs://workspace/a.txt",
        risk_class=RiskClass.READ_ONLY,
    )

    decision = policy.evaluate(context)
    assert decision.verdict is PolicyVerdict.DENY
    assert decision.reason_code == ErrorCode.POLICY_UNKNOWN.value
    assert decision.matched_grants == ("known-grant",)
    assert decision.unknown_rules == ("unknown-grant",)
    assert decision.blocking_unknown_rules == ("unknown-grant",)

    unknown_only = compile_policy(
        PolicyBundle(
            name="unknown-only",
            version="1.0.0",
            default=PolicyDefault.ABSTAIN,
            rules=(unknown_grant,),
        )
    ).evaluate(context)
    assert unknown_only.verdict is PolicyVerdict.DENY
    assert unknown_only.reason_code == ErrorCode.POLICY_UNKNOWN.value
    assert unknown_only.matched_grants == ()


def test_unknown_grant_with_compatible_modes_is_recorded_without_blocking() -> None:
    policy = compile_policy(
        PolicyBundle(
            name="compatible-unknown-grant",
            version="1.0.0",
            default=PolicyDefault.ABSTAIN,
            rules=(
                PolicyRule(
                    rule_id="known-grant",
                    effect=PolicyEffect.GRANT,
                    modes=("read", "stage"),
                    when={"action_in": ["fs.read"]},
                ),
                PolicyRule(
                    rule_id="unknown-grant",
                    effect=PolicyEffect.GRANT,
                    modes=("read",),
                    when={"requested_scope_expands": True},
                ),
            ),
        )
    )

    decision = policy.evaluate(
        PolicyContext(
            action="fs.read",
            resource="fs://workspace/a.txt",
            risk_class=RiskClass.READ_ONLY,
        )
    )

    assert decision.verdict is PolicyVerdict.ELIGIBLE
    assert decision.allowed_modes == ("read",)
    assert decision.unknown_rules == ("unknown-grant",)
    assert decision.blocking_unknown_rules == ()


def test_unknown_mandatory_obligation_fails_closed() -> None:
    policy = compile_policy(
        PolicyBundle(
            name="unknown-obligation",
            version="1.0.0",
            default=PolicyDefault.ABSTAIN,
            rules=(
                PolicyRule(
                    rule_id="approval-if-external",
                    effect=PolicyEffect.REQUIRE_APPROVAL,
                    when={"destination_external": True},
                ),
                PolicyRule(
                    rule_id="known-grant",
                    effect=PolicyEffect.GRANT,
                    modes=("read",),
                    when={"action_in": ["fs.read"]},
                ),
            ),
        )
    )
    decision = policy.evaluate(
        PolicyContext(
            action="fs.read",
            resource="fs://workspace/a.txt",
            risk_class=RiskClass.READ_ONLY,
        )
    )

    assert decision.verdict is PolicyVerdict.DENY
    assert decision.reason_code == ErrorCode.POLICY_UNKNOWN.value


def test_conflicting_matching_grant_modes_fail_closed() -> None:
    bundle = PolicyBundle(
        name="conflict",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="read",
                effect=PolicyEffect.GRANT,
                modes=("read",),
                when={"action_in": ["fs.read"]},
            ),
            PolicyRule(
                rule_id="stage",
                effect=PolicyEffect.GRANT,
                modes=("stage",),
                when={"action_in": ["fs.read"]},
            ),
        ),
    )
    decision = compile_policy(bundle).evaluate(
        PolicyContext(
            action="fs.read",
            resource="fs://workspace/a.txt",
            risk_class=RiskClass.READ_ONLY,
        )
    )
    assert decision.verdict is PolicyVerdict.DENY
    assert decision.reason_code == "MODE_CONFLICT"


def test_unknown_predicate_is_rejected_before_evaluation() -> None:
    bundle = PolicyBundle(
        name="invalid",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="unknown",
                effect=PolicyEffect.DENY,
                when={"execute_python": "allow_all()"},
            ),
        ),
    )
    with pytest.raises(AgentKernelError) as captured:
        compile_policy(bundle)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_compile_policy_revalidates_bypassed_non_nfc_bundle_instances() -> None:
    composed = PolicyBundle(
        name="canonical-version",
        version="café",
        rules=(
            PolicyRule(
                rule_id="grant-read",
                effect=PolicyEffect.GRANT,
                modes=("read",),
                when={"action_in": ["fs.read"]},
            ),
        ),
    )
    bypassed = composed.model_copy(update={"version": "cafe\u0301"})
    assert canonical_digest(composed) == canonical_digest(bypassed)
    assert compile_policy(composed).digest.startswith("sha256:")

    with pytest.raises(AgentKernelError) as captured:
        compile_policy(bypassed)

    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_compiled_policy_deserialization_rejects_semantics_the_compiler_rejects() -> None:
    bundle = PolicyBundle(
        name="invalid-compiled-policy",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="grant-root-shell",
                effect=PolicyEffect.GRANT,
                modes=("root_shell",),
                when={"action_in": ["fs.read"]},
            ),
        ),
    )
    digest = canonical_digest(bundle)

    with pytest.raises(ValidationError, match="compiler semantics"):
        CompiledPolicy(bundle=bundle, digest=digest)


@pytest.mark.parametrize(
    ("predicate", "invalid_value"),
    [
        ("destination_external", "true"),
        ("requested_scope_expands", 1),
        ("resource_within", ["fs://workspace/**"]),
        ("action_in", "fs.write"),
        ("data_class_in", []),
        ("provenance_trust_in", ["invented_trust"]),
        ("risk_class_in", ["R9"]),
    ],
)
def test_invalid_predicate_values_are_rejected_at_compile_time(
    predicate: str,
    invalid_value: object,
) -> None:
    bundle = PolicyBundle(
        name="invalid-value",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="deny-that-must-not-fail-open",
                effect=PolicyEffect.DENY,
                when={predicate: invalid_value},  # type: ignore[dict-item]
            ),
        ),
    )

    with pytest.raises(AgentKernelError) as captured:
        compile_policy(bundle)

    assert captured.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize(
    "scope",
    [
        "fs://*/secret",
        "fs://workspace/*/secret",
        "fs://workspace/**/secret",
        "fs://workspace/../secret",
        "FS://workspace/secret",
    ],
)
def test_resource_scope_grammar_is_rejected_at_compile_time(scope: str) -> None:
    bundle = PolicyBundle(
        name="invalid-resource-scope",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="invalid-scope",
                effect=PolicyEffect.DENY,
                when={"resource_within": scope},
            ),
        ),
    )

    with pytest.raises(AgentKernelError) as captured:
        compile_policy(bundle)

    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_compile_policy_enforces_direct_model_nesting_limit() -> None:
    condition: dict[str, object] = {"action_in": ["fs.read"]}
    for _ in range(40):
        condition = {"all": [condition]}
    bundle = PolicyBundle(
        name="too-deep",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="deep",
                effect=PolicyEffect.DENY,
                when=condition,  # type: ignore[arg-type]
            ),
        ),
    )

    with pytest.raises(AgentKernelError) as captured:
        compile_policy(bundle)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_compile_policy_enforces_direct_model_node_limit() -> None:
    bundle = PolicyBundle(
        name="too-many-nodes",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="wide",
                effect=PolicyEffect.DENY,
                when={"action_in": [f"action-{index}" for index in range(10_001)]},
            ),
        ),
    )

    with pytest.raises(AgentKernelError) as captured:
        compile_policy(bundle)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_policy_loader_rejects_a_sparse_oversized_file(tmp_path: Path) -> None:
    policy_path = tmp_path / "oversized.yaml"
    with policy_path.open("wb") as stream:
        stream.truncate(8 * 1024 * 1024)

    with pytest.raises(AgentKernelError) as captured:
        load_policy(policy_path)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


@pytest.mark.parametrize("value", ["cafe\u0301", "\ud800"])
def test_policy_predicate_strings_must_be_canonical_utf8_nfc(value: str) -> None:
    bundle = PolicyBundle(
        name="canonical-text",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="canonical",
                effect=PolicyEffect.DENY,
                when={"data_class_in": [value]},
            ),
        ),
    )

    with pytest.raises(AgentKernelError) as captured:
        compile_policy(bundle)

    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_policy_context_rejects_non_nfc_semantic_values() -> None:
    with pytest.raises(ValueError, match="Unicode NFC"):
        PolicyContext(
            action="fs.read",
            resource="fs://workspace/a.txt",
            data_classes=("cafe\u0301",),
            risk_class=RiskClass.READ_ONLY,
        )


def test_duplicate_yaml_keys_are_rejected_instead_of_overriding_deny(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "duplicate.yaml"
    policy_path.write_text(
        """\
api_version: agentkernel.io/v1alpha1
kind: PolicyBundle
name: duplicate-key
version: 1.0.0
default: deny
rules:
  - rule_id: ambiguous
    effect: deny
    effect: grant
    modes: [external]
    when:
      destination_external: true
""",
        encoding="utf-8",
    )

    with pytest.raises(AgentKernelError) as captured:
        load_policy(policy_path)

    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_unknown_execution_mode_is_rejected_at_compile_time() -> None:
    bundle = PolicyBundle(
        name="unknown-mode",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="typo",
                effect=PolicyEffect.GRANT,
                modes=("external_inference",),
                when={"destination_external": True},
            ),
        ),
    )

    with pytest.raises(AgentKernelError) as captured:
        compile_policy(bundle)

    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_duplicate_rule_ids_and_modes_are_rejected() -> None:
    duplicate_rule = PolicyRule(
        rule_id="same",
        effect=PolicyEffect.GRANT,
        modes=("read",),
        when={"action_in": ["fs.read"]},
    )
    duplicate_ids = PolicyBundle(
        name="duplicate-rules",
        version="1.0.0",
        rules=(duplicate_rule, duplicate_rule),
    )
    with pytest.raises(AgentKernelError) as duplicate_id_error:
        compile_policy(duplicate_ids)
    assert duplicate_id_error.value.code is ErrorCode.VALIDATION_ERROR

    duplicate_modes = PolicyBundle(
        name="duplicate-modes",
        version="1.0.0",
        rules=(duplicate_rule.model_copy(update={"modes": ("read", "read")}),),
    )
    with pytest.raises(AgentKernelError) as duplicate_mode_error:
        compile_policy(duplicate_modes)
    assert duplicate_mode_error.value.code is ErrorCode.VALIDATION_ERROR
