from __future__ import annotations

from datetime import datetime

import pytest
from agentkernel.adapters.base import (
    CommitContext,
    ReadOnlyContext,
    RecoveryContext,
    StageContext,
    VerifyContext,
)
from agentkernel.adapters.mock import MockReversibleAdapter, VersionedMemoryTarget
from agentkernel.adapters.registry import AdapterRegistry
from agentkernel.domain.enums import VerificationStatus
from agentkernel.domain.models import ActionProposal
from agentkernel.errors import AgentKernelError, ErrorCode


@pytest.mark.asyncio
async def test_stage_execute_commit_and_rollback_boundaries(
    proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = MockReversibleAdapter(target)
    original_digest = target.digest
    original_state = dict(target.state)
    plan = await adapter.inspect(proposal, ReadOnlyContext(proposal.deadline))
    staged = await adapter.stage(plan, StageContext(proposal.deadline, "worker:test"))
    assert target.digest == original_digest
    receipt = await adapter.execute(staged, StageContext(proposal.deadline, "worker:test"))
    assert target.digest == original_digest
    staged_report = await adapter.verify_staged(receipt, VerifyContext(proposal.deadline))
    assert staged_report.status is VerificationStatus.PASS

    effect = await adapter.commit(
        receipt,
        CommitContext(proposal.deadline, 1, plan.intent_hash, plan.base_version),
    )
    assert target.state == {"before": "kept", "answer": "42"}
    committed = await adapter.verify_committed(effect, VerifyContext(proposal.deadline))
    assert committed.status is VerificationStatus.PASS

    recovery = await adapter.rollback(
        effect,
        RecoveryContext(proposal.deadline, "authority:test"),
    )
    assert recovery.status is VerificationStatus.PASS
    assert target.state == original_state


@pytest.mark.asyncio
async def test_abort_discards_stage_without_authoritative_effect(
    proposal: ActionProposal, now: datetime
) -> None:
    del now
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = MockReversibleAdapter(target)
    original_digest = target.digest
    plan = await adapter.inspect(proposal, ReadOnlyContext(proposal.deadline))
    staged = await adapter.stage(plan, StageContext(proposal.deadline, "worker:test"))
    receipt = await adapter.execute(staged, StageContext(proposal.deadline, "worker:test"))
    report = await adapter.abort(
        receipt,
        RecoveryContext(proposal.deadline, "authority:test"),
    )
    assert report.status is VerificationStatus.PASS
    assert target.digest == original_digest


def test_registry_pins_digest_and_review_admission() -> None:
    registry = AdapterRegistry()
    adapter = MockReversibleAdapter(VersionedMemoryTarget())
    digest = registry.register(adapter, reviewed=False)
    assert registry.resolve("mock", expected_digest=digest, enforcement_profile=False) is adapter

    with pytest.raises(AgentKernelError) as unreviewed:
        registry.resolve("mock", expected_digest=digest, enforcement_profile=True)
    assert unreviewed.value.code is ErrorCode.AUTHORITY_MISSING

    with pytest.raises(AgentKernelError) as mismatch:
        registry.resolve(
            "mock",
            expected_digest="sha256:" + "0" * 64,
            enforcement_profile=False,
        )
    assert mismatch.value.code is ErrorCode.INTEGRITY_ERROR


def test_registry_rejects_manifest_mutation_after_admission() -> None:
    registry = AdapterRegistry()
    adapter = MockReversibleAdapter(VersionedMemoryTarget())
    digest = registry.register(adapter, reviewed=True)
    adapter.manifest.operations["set_values"] = adapter.manifest.operations[
        "set_values"
    ].model_copy(update={"rollback": False})

    with pytest.raises(AgentKernelError) as captured:
        registry.resolve("mock", expected_digest=digest, enforcement_profile=True)

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
