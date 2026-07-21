from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from agentkernel.authority.service import (
    AuthorityGrant,
    AuthorityService,
    AuthorityVerdict,
    resource_matches,
)
from agentkernel.domain.enums import ProvenanceTrust
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.storage.sqlite import SQLiteJournal


def _service(now: datetime) -> AuthorityService:
    grant = AuthorityGrant(
        capability_id="cap_demo",
        subject="agent:scripted:demo",
        goal_id="goal_demo",
        run_id="run_demo",
        actions=("fs.read", "fs.write"),
        resources=("fs://workspace/**",),
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
        max_uses=10,
    )
    return AuthorityService((grant,), clock=lambda: now)


def test_scoped_grant_allows_only_matching_action_and_resource() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    service = _service(now)
    allowed = service.check(
        subject="agent:scripted:demo",
        goal_id="goal_demo",
        run_id="run_demo",
        action="fs.write",
        resource="fs://workspace/src/result.txt",
        provenance=(ProvenanceTrust.MODEL_GENERATED,),
    )
    assert allowed.verdict is AuthorityVerdict.ALLOW
    assert allowed.matched_capability == "cap_demo"


def test_project_data_cannot_expand_authority() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    service = _service(now)
    denied = service.check(
        subject="agent:scripted:demo",
        goal_id="goal_demo",
        run_id="run_demo",
        action="credential.read",
        resource="fs://synthetic-home/.ssh/demo_key",
        provenance=(ProvenanceTrust.PROJECT_DATA,),
    )
    assert denied.verdict is AuthorityVerdict.DENY
    assert denied.reason_code == ErrorCode.AUTHORITY_MISSING.value
    assert denied.authority_expansion_from_untrusted is True


def test_resource_wildcards_are_deliberately_limited() -> None:
    assert resource_matches("fs://workspace/**", "fs://workspace/a.txt")
    assert not resource_matches("fs://workspace/**", "fs://other/a.txt")
    with pytest.raises(AgentKernelError) as captured:
        resource_matches("fs://*/secret", "fs://workspace/secret")
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_expired_grant_does_not_authorize() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    grant = AuthorityGrant(
        capability_id="cap_expired",
        subject="agent:test",
        goal_id="goal_demo",
        run_id="run_demo",
        actions=("fs.read",),
        resources=("fs://workspace/**",),
        not_before=now - timedelta(hours=2),
        expires_at=now - timedelta(hours=1),
    )
    service = AuthorityService((grant,), clock=lambda: now)
    decision = service.check(
        subject="agent:test",
        goal_id="goal_demo",
        run_id="run_demo",
        action="fs.read",
        resource="fs://workspace/a.txt",
    )
    assert decision.verdict is AuthorityVerdict.DENY


def test_capability_use_budget_survives_service_and_database_restart(tmp_path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    path = tmp_path / "authority.db"
    grant = AuthorityGrant(
        capability_id="cap_single_use",
        subject="agent:test",
        goal_id="goal_demo",
        run_id="run_demo",
        actions=("model.infer.external",),
        resources=("model://external/**",),
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
        max_uses=1,
    )
    with SQLiteJournal(path) as journal:
        first_service = AuthorityService((grant,), clock=lambda: now, use_ledger=journal)
        first = first_service.check(
            subject="agent:test",
            goal_id="goal_demo",
            run_id="run_demo",
            action="model.infer.external",
            resource="model://external/model",
        )
    with SQLiteJournal(path) as reopened:
        restarted_service = AuthorityService((grant,), clock=lambda: now, use_ledger=reopened)
        second = restarted_service.check(
            subject="agent:test",
            goal_id="goal_demo",
            run_id="run_demo",
            action="model.infer.external",
            resource="model://external/model",
        )

    assert first.verdict is AuthorityVerdict.ALLOW
    assert second.verdict is AuthorityVerdict.DENY
    assert second.reason_code == ErrorCode.AUTHORITY_EXPIRED.value


def test_exhausted_grant_does_not_hide_a_second_valid_grant() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    grants = tuple(
        AuthorityGrant(
            capability_id=f"cap_{name}",
            subject="agent:test",
            goal_id="goal_demo",
            run_id="run_demo",
            actions=("fs.read",),
            resources=("fs://workspace/**",),
            not_before=now - timedelta(minutes=1),
            expires_at=now + timedelta(minutes=5),
            max_uses=1,
        )
        for name in ("first", "second")
    )
    service = AuthorityService(grants, clock=lambda: now)

    first = service.check(
        subject="agent:test",
        goal_id="goal_demo",
        run_id="run_demo",
        action="fs.read",
        resource="fs://workspace/a.txt",
    )
    second = service.check(
        subject="agent:test",
        goal_id="goal_demo",
        run_id="run_demo",
        action="fs.read",
        resource="fs://workspace/b.txt",
    )

    assert first.matched_capability == "cap_first"
    assert second.matched_capability == "cap_second"
