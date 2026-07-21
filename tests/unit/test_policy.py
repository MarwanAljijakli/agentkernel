from __future__ import annotations

from pathlib import Path

import pytest
from agentkernel.domain.enums import ProvenanceTrust, RiskClass
from agentkernel.domain.models import PolicyBundle, PolicyEffect, PolicyRule
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.policy.engine import (
    PolicyContext,
    PolicyVerdict,
    compile_policy,
    load_policy,
)


def test_repository_policy_allows_scoped_staged_write() -> None:
    policy = load_policy(Path("policies/system/base.yaml"))
    decision = policy.evaluate(
        PolicyContext(
            action="fs.write",
            resource="fs://workspace/src/result.txt",
            provenance_trust=(ProvenanceTrust.MODEL_GENERATED,),
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
