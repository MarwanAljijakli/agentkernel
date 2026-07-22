from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from agentkernel.adapters.base import RecoveryContext, StageContext, VerifyContext
from agentkernel.adapters.filesystem import FilesystemAdapter
from agentkernel.adapters.mock import MockReversibleAdapter, VersionedMemoryTarget
from agentkernel.adapters.registry import AdapterRegistry
from agentkernel.domain.enums import TransactionState, VerificationStatus
from agentkernel.domain.models import ActionProposal, VerificationReport
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.ledger import validate_chain
from agentkernel.storage.sqlite import SQLiteJournal
from agentkernel.transactions.coordinator import TransactionCoordinator
from agentkernel.transactions.state_machine import TransitionEvent


def _clock(now: datetime):
    return lambda: now


@pytest.mark.asyncio
@pytest.mark.integration
async def test_context_exit_without_commit_aborts_and_preserves_target(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = MockReversibleAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)
    with SQLiteJournal(tmp_path / "journal.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        session = await coordinator.transaction(
            proposal,
            run_id="run_abort",
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        async with session:
            assert session.record.state is TransactionState.READY_TO_COMMIT
            assert target.state == {"before": "kept"}
        assert session.record.state is TransactionState.ABORTED
        assert target.state == {"before": "kept"}
        assert validate_chain(journal.list_events("run_abort")).valid


@pytest.mark.asyncio
@pytest.mark.integration
async def test_explicit_cancel_discards_stage_and_preserves_target(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = MockReversibleAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)
    with SQLiteJournal(tmp_path / "journal.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        session = await coordinator.transaction(
            proposal,
            run_id="run_cancel",
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        async with session:
            cancelled = await session.cancel()

        assert cancelled.state is TransactionState.ABORTED
        assert target.state == {"before": "kept"}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_explicit_commit_is_the_only_authoritative_effect(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = MockReversibleAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)
    with SQLiteJournal(tmp_path / "journal.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        session = await coordinator.transaction(
            proposal,
            run_id="run_commit",
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        async with session:
            assert target.state == {"before": "kept"}
            committed = await session.commit()
        assert committed.state is TransactionState.COMMITTED
        assert target.state["answer"] == "42"
        assert validate_chain(journal.list_events("run_commit")).valid
        with pytest.raises(AgentKernelError) as captured:
            await session.cancel()
        assert captured.value.code is ErrorCode.ILLEGAL_TRANSITION


class UnknownVerifierAdapter(MockReversibleAdapter):
    async def verify_staged(self, receipt, ctx: VerifyContext) -> VerificationReport:
        del receipt, ctx
        return VerificationReport(
            status=VerificationStatus.UNKNOWN,
            verifier="adapter.mock.unknown",
            summary="Required evidence is absent",
        )


class TimeoutAfterEffectAdapter(MockReversibleAdapter):
    async def commit(self, receipt, ctx):
        await super().commit(receipt, ctx)
        raise TimeoutError("synthetic lost acknowledgement")


class DriftAtCommitGuardAdapter(MockReversibleAdapter):
    async def commit(self, receipt, ctx):
        self.target.state["external"] = "drift"
        self.target.version += 1
        return await super().commit(receipt, ctx)


class UncleanStageAdapter(MockReversibleAdapter):
    async def stage(self, plan, ctx):
        del plan, ctx
        raise AgentKernelError(
            ErrorCode.ROLLBACK_FAILED,
            "synthetic partial staging cleanup failure",
        )


class TrackingAbortAdapter(MockReversibleAdapter):
    def __init__(self, target):
        super().__init__(target)
        self.abort_calls = 0

    async def abort(self, staged, ctx: RecoveryContext):
        self.abort_calls += 1
        return await super().abort(staged, ctx)


class CancellableInspectAdapter(MockReversibleAdapter):
    def __init__(self, target):
        super().__init__(target)
        self.inspect_started = asyncio.Event()

    async def inspect(self, proposal, ctx):
        del proposal, ctx
        self.inspect_started.set()
        await asyncio.Event().wait()


class DeadlineDuringInspectAdapter(MockReversibleAdapter):
    async def inspect(self, proposal, ctx):
        del proposal, ctx
        raise AgentKernelError(
            ErrorCode.DEADLINE_EXCEEDED,
            "Synthetic deadline elapsed during inspection",
        )


class BlockingPrecommitAdapter(TrackingAbortAdapter):
    def __init__(self, target, boundary: str):
        super().__init__(target)
        self.boundary = boundary
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.active_stage_ids: set[str] = set()

    async def stage(self, plan, ctx):
        staged = await super().stage(plan, ctx)
        self.active_stage_ids.add(staged.stage_id)
        if self.boundary == "stage":
            self.started.set()
            await self.release.wait()
        return staged

    async def execute(self, staged, ctx):
        receipt = await super().execute(staged, ctx)
        if self.boundary == "execute":
            self.started.set()
            await self.release.wait()
        return receipt

    async def abort(self, staged, ctx: RecoveryContext):
        stage_id = staged.staged.stage_id if hasattr(staged, "staged") else staged.stage_id
        self.active_stage_ids.discard(stage_id)
        return await super().abort(staged, ctx)


async def _place_session_in_precommit_state(session, adapter, state, proposal) -> None:
    if state is TransactionState.NEW:
        return
    session._transition(TransitionEvent.PROPOSAL_VALID)
    if state is TransactionState.PLANNED:
        return
    session._transition(TransitionEvent.AUTHORIZED_FOR_STAGING)
    if state is TransactionState.AUTHORIZED_TO_STAGE:
        return
    session._transition(TransitionEvent.WORKER_LEASE_ACQUIRED)
    stage_context = StageContext(deadline=proposal.deadline, worker_id="worker:test")
    session._staged_effect = await adapter.stage(session._plan, stage_context)
    if state is TransactionState.STAGING:
        return
    session._staged_receipt = await adapter.execute(session._staged_effect, stage_context)
    session._transition(TransitionEvent.STAGING_SUCCEEDED)
    if state is TransactionState.STAGED:
        return
    session._verification = await adapter.verify_staged(
        session._staged_receipt,
        VerifyContext(deadline=proposal.deadline),
    )
    session._transition(TransitionEvent.STAGED_VERIFICATION_PASSED)
    if state is TransactionState.STAGE_VERIFIED:
        return
    if state is TransactionState.AWAITING_APPROVAL:
        session._transition(TransitionEvent.APPROVAL_REQUIRED)
        return
    session._transition(TransitionEvent.NO_APPROVAL_REQUIRED)


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.parametrize(
    "state",
    [
        TransactionState.NEW,
        TransactionState.PLANNED,
        TransactionState.AUTHORIZED_TO_STAGE,
        TransactionState.STAGING,
        TransactionState.STAGED,
        TransactionState.STAGE_VERIFIED,
        TransactionState.AWAITING_APPROVAL,
        TransactionState.READY_TO_COMMIT,
    ],
)
@pytest.mark.parametrize("cause", ["cancel", "deadline", "context_exit"])
async def test_every_precommit_state_exits_without_authoritative_effect(
    tmp_path: Path,
    proposal: ActionProposal,
    now: datetime,
    state: TransactionState,
    cause: str,
) -> None:
    current_time = [now]

    def clock() -> datetime:
        return current_time[0]

    target = VersionedMemoryTarget({"before": "kept"})
    initial_digest = target.digest
    initial_version = target.version
    adapter = TrackingAbortAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)
    suffix = f"{state.value.lower()}_{cause}"
    request = proposal.model_copy(update={"transaction_id": f"tx_{suffix}"})
    run_id = f"run_{suffix}"

    with SQLiteJournal(tmp_path / f"{suffix}.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=clock)
        session = await coordinator.transaction(
            request,
            run_id=run_id,
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        await _place_session_in_precommit_state(session, adapter, state, request)

        if cause == "cancel":
            await session.cancel()
        elif cause == "deadline":
            current_time[0] = request.deadline
            await session.enforce_deadline()
        else:
            await session.__aexit__(None, None, None)

        expected = TransactionState.ABORTED
        assert session.record.state is expected
        assert target.digest == initial_digest
        assert target.version == initial_version
        assert adapter.abort_calls == int(
            expected is TransactionState.ABORTED
            and state
            in {
                TransactionState.STAGING,
                TransactionState.STAGED,
                TransactionState.STAGE_VERIFIED,
                TransactionState.AWAITING_APPROVAL,
                TransactionState.READY_TO_COMMIT,
            }
        )
        events = journal.list_events(run_id)
        assert validate_chain(events).valid
        terminal_transition = events[-1].payload
        assert terminal_transition["to"] == expected.value
        if expected is TransactionState.ABORTED:
            assert any(event.payload.get("to") == "ABORTING" for event in events)
        if state is TransactionState.NEW and cause == "cancel":
            assert (await session.cancel()).state is TransactionState.ABORTED
            assert (await session.enforce_deadline()).state is TransactionState.ABORTED


@pytest.mark.asyncio
@pytest.mark.integration
async def test_task_cancellation_during_inspection_durably_aborts_new_transaction(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = CancellableInspectAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)

    with SQLiteJournal(tmp_path / "cancel-inspect.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        task = asyncio.create_task(
            coordinator.transaction(
                proposal,
                run_id="run_cancel_inspect",
                actor="service:coordinator",
                on_behalf_of="principal:test",
                adapter_manifest_digest=digest,
            )
        )
        await adapter.inspect_started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert journal.get_transaction(proposal.transaction_id).state is TransactionState.ABORTED
        assert target.state == {"before": "kept"}
        events = journal.list_events("run_cancel_inspect")
        assert [event.payload.get("to") for event in events[1:]] == ["ABORTING", "ABORTED"]
        assert validate_chain(events).valid


@pytest.mark.asyncio
@pytest.mark.integration
async def test_deadline_during_inspection_durably_aborts_new_transaction(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = DeadlineDuringInspectAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)
    run_id = "run_deadline_during_inspect"

    with SQLiteJournal(tmp_path / "deadline-during-inspect.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        with pytest.raises(AgentKernelError) as captured:
            await coordinator.transaction(
                proposal,
                run_id=run_id,
                actor="service:coordinator",
                on_behalf_of="principal:test",
                adapter_manifest_digest=digest,
            )

        assert captured.value.code is ErrorCode.DEADLINE_EXCEEDED
        assert journal.get_transaction(proposal.transaction_id).state is TransactionState.ABORTED
        assert target.state == {"before": "kept"}
        events = journal.list_events(run_id)
        assert [event.payload.get("to") for event in events[1:]] == ["ABORTING", "ABORTED"]
        assert validate_chain(events).valid


@pytest.mark.asyncio
@pytest.mark.integration
async def test_deadline_elapsing_before_session_entry_aborts_new_transaction(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    current_time = [now]

    def clock() -> datetime:
        return current_time[0]

    target = VersionedMemoryTarget({"before": "kept"})
    adapter = MockReversibleAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)
    run_id = "run_deadline_before_entry"

    with SQLiteJournal(tmp_path / "deadline-before-entry.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=clock)
        session = await coordinator.transaction(
            proposal,
            run_id=run_id,
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        current_time[0] = proposal.deadline

        with pytest.raises(AgentKernelError) as captured:
            await session.__aenter__()

        assert captured.value.code is ErrorCode.DEADLINE_EXCEEDED
        assert session.record.state is TransactionState.ABORTED
        assert target.state == {"before": "kept"}
        events = journal.list_events(run_id)
        assert [event.payload.get("to") for event in events[1:]] == ["ABORTING", "ABORTED"]
        assert validate_chain(events).valid


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.parametrize("boundary", ["stage", "execute"])
async def test_concurrent_cancel_waits_for_precommit_operation_then_discards_stage(
    tmp_path: Path, proposal: ActionProposal, now: datetime, boundary: str
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    initial_digest = target.digest
    adapter = BlockingPrecommitAdapter(target, boundary)
    registry = AdapterRegistry()
    digest = registry.register(adapter)
    run_id = f"run_cancel_race_{boundary}"
    request = proposal.model_copy(update={"transaction_id": f"tx_cancel_race_{boundary}"})

    with SQLiteJournal(tmp_path / f"cancel-race-{boundary}.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        session = await coordinator.transaction(
            request,
            run_id=run_id,
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        enter_task = asyncio.create_task(session.__aenter__())
        await adapter.started.wait()
        cancel_task = asyncio.create_task(session.cancel())
        await asyncio.sleep(0)
        assert not cancel_task.done()

        adapter.release.set()
        assert await enter_task is session
        cancelled = await cancel_task

        assert cancelled.state is TransactionState.ABORTED
        assert adapter.abort_calls == 1
        assert adapter.active_stage_ids == set()
        assert target.digest == initial_digest
        assert target.version == 0
        assert validate_chain(journal.list_events(run_id)).valid


@pytest.mark.asyncio
@pytest.mark.integration
async def test_unknown_verification_fails_closed(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = UnknownVerifierAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)
    with SQLiteJournal(tmp_path / "journal.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        session = await coordinator.transaction(
            proposal,
            run_id="run_unknown",
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        with pytest.raises(AgentKernelError) as captured:
            async with session:
                pass
        assert captured.value.code is ErrorCode.VERIFICATION_UNKNOWN
        assert session.record.state is TransactionState.ABORTED
        assert target.state == {"before": "kept"}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_target_drift_aborts_as_stale_before_commit_dispatch(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = MockReversibleAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)
    with SQLiteJournal(tmp_path / "journal.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        session = await coordinator.transaction(
            proposal,
            run_id="run_stale",
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        async with session:
            target.state["concurrent"] = "change"
            target.version += 1
            with pytest.raises(AgentKernelError) as captured:
                await session.commit()
            assert captured.value.code is ErrorCode.STALE_STATE
        assert session.record.state is TransactionState.STALE_STATE
        assert "answer" not in target.state

        retry_proposal = proposal.model_copy(update={"transaction_id": "tx_retry_after_stale"})
        retry = await coordinator.transaction(
            retry_proposal,
            run_id="run_stale_retry",
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        async with retry:
            retried_record = await retry.commit()
        assert retried_record.state is TransactionState.COMMITTED
        assert retried_record.supersedes_transaction_id == proposal.transaction_id
        assert target.state["answer"] == "42"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_expired_proposal_is_rejected_before_adapter_inspection(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = MockReversibleAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)
    expired = proposal.model_copy(update={"deadline": now - timedelta(seconds=1)})

    with SQLiteJournal(tmp_path / "journal.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        with pytest.raises(AgentKernelError) as captured:
            await coordinator.transaction(
                expired,
                run_id="run_expired",
                actor="service:coordinator",
                on_behalf_of="principal:test",
                adapter_manifest_digest=digest,
            )

        assert captured.value.code is ErrorCode.DEADLINE_EXCEEDED
        events = journal.list_events("run_expired")
        assert [event.event_type for event in events] == [
            "transaction.created",
            "transaction.transitioned",
        ]
        assert journal.get_transaction(expired.transaction_id).state is TransactionState.REJECTED
        assert target.state == {"before": "kept"}


@pytest.mark.asyncio
@pytest.mark.integration
async def test_proposal_adapter_version_must_match_admitted_manifest(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = MockReversibleAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)
    mismatched = proposal.model_copy(update={"adapter_version": "9.9.9"})

    with SQLiteJournal(tmp_path / "journal.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        with pytest.raises(AgentKernelError) as captured:
            await coordinator.transaction(
                mismatched,
                run_id="run_version_mismatch",
                actor="service:coordinator",
                on_behalf_of="principal:test",
                adapter_manifest_digest=digest,
            )

        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
        assert target.version == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_enforcement_profile_is_refused_without_authority_policy_composition(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    adapter = MockReversibleAdapter(VersionedMemoryTarget())
    registry = AdapterRegistry()
    digest = registry.register(adapter, reviewed=True)

    with SQLiteJournal(tmp_path / "journal.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        with pytest.raises(AgentKernelError) as captured:
            await coordinator.transaction(
                proposal,
                run_id="run_enforcement_refused",
                actor="service:coordinator",
                on_behalf_of="principal:test",
                adapter_manifest_digest=digest,
                enforcement_profile=True,
            )

        assert captured.value.code is ErrorCode.UNSUPPORTED_SEMANTICS
        assert journal.get_transaction(proposal.transaction_id).state is TransactionState.REJECTED


@pytest.mark.asyncio
@pytest.mark.integration
async def test_lost_commit_acknowledgement_is_persisted_in_doubt(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = TimeoutAfterEffectAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)

    with SQLiteJournal(tmp_path / "journal.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        session = await coordinator.transaction(
            proposal,
            run_id="run_lost_ack",
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        with pytest.raises(TimeoutError, match="lost acknowledgement"):
            async with session:
                await session.commit()

        assert session.record.state is TransactionState.IN_DOUBT
        assert target.state["answer"] == "42"
        assert journal.list_non_terminal() == (session.record,)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_stale_guard_at_commit_dispatch_is_classified_as_confirmed_no_effect(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = DriftAtCommitGuardAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)

    with SQLiteJournal(tmp_path / "journal.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        session = await coordinator.transaction(
            proposal,
            run_id="run_stale_at_dispatch",
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        with pytest.raises(AgentKernelError) as captured:
            async with session:
                await session.commit()

        assert captured.value.code is ErrorCode.STALE_STATE
        assert session.record.state is TransactionState.ABORTED
        assert target.state == {"before": "kept", "external": "drift"}
        assert "answer" not in target.state


@pytest.mark.asyncio
@pytest.mark.integration
async def test_execute_failure_discards_persisted_filesystem_stage(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "src").write_text("path collision", encoding="utf-8")
    state_root = tmp_path / "state"
    adapter = FilesystemAdapter(workspace=workspace, state_root=state_root)
    registry = AdapterRegistry()
    digest = registry.register(adapter)
    request = proposal.model_copy(
        update={
            "adapter": "filesystem",
            "operation": "write_files",
            "arguments": {"files": {"src/result.txt": "never committed\n"}},
        }
    )

    with SQLiteJournal(tmp_path / "journal.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        session = await coordinator.transaction(
            request,
            run_id="run_execute_failure",
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        with pytest.raises(FileExistsError):
            async with session:
                pass

        assert session.record.state is TransactionState.ABORTED
        assert list((state_root / "stages").iterdir()) == []
        assert (workspace / "src").read_text(encoding="utf-8") == "path collision"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_unverified_partial_stage_cleanup_enters_recovery_failed(
    tmp_path: Path, proposal: ActionProposal, now: datetime
) -> None:
    target = VersionedMemoryTarget({"before": "kept"})
    adapter = UncleanStageAdapter(target)
    registry = AdapterRegistry()
    digest = registry.register(adapter)

    with SQLiteJournal(tmp_path / "journal.db") as journal:
        coordinator = TransactionCoordinator(journal=journal, registry=registry, clock=_clock(now))
        session = await coordinator.transaction(
            proposal,
            run_id="run_unclean_stage",
            actor="service:coordinator",
            on_behalf_of="principal:test",
            adapter_manifest_digest=digest,
        )
        with pytest.raises(AgentKernelError) as captured:
            async with session:
                pass

        assert captured.value.code is ErrorCode.ROLLBACK_FAILED
        assert session.record.state is TransactionState.RECOVERY_FAILED
        assert target.state == {"before": "kept"}
