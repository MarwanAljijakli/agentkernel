"""Minimal embedded coordinator proving explicit commit and fail-closed verification."""

from __future__ import annotations

from asyncio import CancelledError, Lock
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Self

from agentkernel.adapters.base import (
    CommitContext,
    EffectAdapter,
    EffectPlan,
    ReadOnlyContext,
    RecoveryContext,
    StageContext,
    StagedEffect,
    StagedReceipt,
    VerifyContext,
)
from agentkernel.adapters.registry import AdapterRegistry
from agentkernel.domain.enums import TransactionState, VerificationStatus
from agentkernel.domain.models import ActionProposal, TransactionRecord, VerificationReport
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.storage.sqlite import SQLiteJournal
from agentkernel.transactions.state_machine import TransitionEvent

Clock = Callable[[], datetime]

_PRE_COMMIT_STATES = frozenset(
    {
        TransactionState.NEW,
        TransactionState.PLANNED,
        TransactionState.AUTHORIZED_TO_STAGE,
        TransactionState.STAGING,
        TransactionState.STAGED,
        TransactionState.STAGE_VERIFIED,
        TransactionState.AWAITING_APPROVAL,
        TransactionState.READY_TO_COMMIT,
    }
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class TransactionCoordinator:
    """Coordinate the v1alpha1 effect lifecycle in the A0 embedded profile.

    Authority and deterministic policy services are deliberately not implied here. Callers must
    not label this embedded composition as A1+ enforcement.
    """

    def __init__(
        self,
        *,
        journal: SQLiteJournal,
        registry: AdapterRegistry,
        clock: Clock = _utc_now,
    ) -> None:
        self._journal = journal
        self._registry = registry
        self._clock = clock

    async def transaction(
        self,
        proposal: ActionProposal,
        *,
        run_id: str,
        actor: str,
        on_behalf_of: str,
        adapter_manifest_digest: str,
        enforcement_profile: bool = False,
    ) -> TransactionSession:
        now = self._clock()
        record = TransactionRecord(
            transaction_id=proposal.transaction_id,
            goal_id=proposal.goal_id,
            adapter_manifest_digest=adapter_manifest_digest,
            created_at=now,
            updated_at=now,
        )
        self._journal.create_transaction(
            record,
            run_id=run_id,
            actor=actor,
            on_behalf_of=on_behalf_of,
        )
        try:
            if now >= proposal.deadline:
                raise AgentKernelError(
                    ErrorCode.DEADLINE_EXCEEDED,
                    "Proposal deadline elapsed before transaction admission",
                )
            if enforcement_profile:
                raise AgentKernelError(
                    ErrorCode.UNSUPPORTED_SEMANTICS,
                    "The embedded coordinator cannot claim an enforcement profile",
                )
            adapter = self._registry.resolve(
                proposal.adapter,
                expected_digest=adapter_manifest_digest,
                enforcement_profile=False,
            )
            if proposal.adapter_version != adapter.manifest.version:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Proposal adapter version does not match the admitted manifest",
                    details={
                        "proposal_version": proposal.adapter_version,
                        "admitted_version": adapter.manifest.version,
                    },
                )
            plan = await adapter.inspect(proposal, ReadOnlyContext(deadline=proposal.deadline))
            record = self._journal.set_transaction_intent(
                proposal.transaction_id,
                intent_hash=plan.intent_hash,
            )
        except CancelledError:
            record, _ = self._journal.transition(
                proposal.transaction_id,
                expected_version=record.version,
                transition_event=TransitionEvent.CANCELLED,
                now=self._clock(),
                run_id=run_id,
                actor=actor,
                on_behalf_of=on_behalf_of,
                reason_code=TransitionEvent.CANCELLED.value,
            )
            self._journal.transition(
                proposal.transaction_id,
                expected_version=record.version,
                transition_event=TransitionEvent.STAGING_DISCARD_SUCCEEDED,
                now=self._clock(),
                run_id=run_id,
                actor=actor,
                on_behalf_of=on_behalf_of,
            )
            raise
        except BaseException as error:
            reason = error.code.value if isinstance(error, AgentKernelError) else "VALIDATION_ERROR"
            self._journal.transition(
                proposal.transaction_id,
                expected_version=record.version,
                transition_event=TransitionEvent.VALIDATION_FAILED,
                now=self._clock(),
                run_id=run_id,
                actor=actor,
                on_behalf_of=on_behalf_of,
                reason_code=reason,
            )
            raise
        return TransactionSession(
            journal=self._journal,
            adapter=adapter,
            plan=plan,
            run_id=run_id,
            actor=actor,
            on_behalf_of=on_behalf_of,
            clock=self._clock,
            adapter_manifest_digest=adapter_manifest_digest,
            initial_record=record,
        )


class TransactionSession:
    """Async context that aborts staged work unless `commit()` succeeds explicitly."""

    def __init__(
        self,
        *,
        journal: SQLiteJournal,
        adapter: EffectAdapter,
        plan: EffectPlan,
        run_id: str,
        actor: str,
        on_behalf_of: str,
        clock: Clock,
        adapter_manifest_digest: str,
        initial_record: TransactionRecord,
    ) -> None:
        self._journal = journal
        self._adapter = adapter
        self._plan = plan
        self._run_id = run_id
        self._actor = actor
        self._on_behalf_of = on_behalf_of
        self._clock = clock
        self._adapter_manifest_digest = adapter_manifest_digest
        self._record: TransactionRecord | None = initial_record
        self._staged_effect: StagedEffect | None = None
        self._staged_receipt: StagedReceipt | None = None
        self._verification: VerificationReport | None = None
        self._staging_cleanup_failed = False
        self._operation_lock = Lock()

    def _ensure_pre_effect_guards(self) -> None:
        if self._clock() >= self._plan.proposal.deadline:
            raise AgentKernelError(
                ErrorCode.DEADLINE_EXCEEDED,
                "Transaction deadline elapsed before the next effect boundary",
            )
        if self._adapter.manifest.digest != self._adapter_manifest_digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter manifest changed after admission",
            )

    @property
    def record(self) -> TransactionRecord:
        if self._record is None:
            raise RuntimeError("Transaction context has not been entered")
        return self._record

    @property
    def staged_receipt(self) -> StagedReceipt | None:
        return self._staged_receipt

    @property
    def verification(self) -> VerificationReport | None:
        return self._verification

    def _transition(self, event: TransitionEvent, *, reason_code: str | None = None) -> None:
        current = self.record
        updated, _ = self._journal.transition(
            current.transaction_id,
            expected_version=current.version,
            transition_event=event,
            now=self._clock(),
            run_id=self._run_id,
            actor=self._actor,
            on_behalf_of=self._on_behalf_of,
            reason_code=reason_code,
        )
        self._record = updated

    async def __aenter__(self) -> Self:
        async with self._operation_lock:
            return await self._enter()

    async def _enter(self) -> Self:
        if self.record.state is not TransactionState.NEW:
            raise AgentKernelError(
                ErrorCode.ILLEGAL_TRANSITION,
                "Transaction session can only be entered once",
            )
        try:
            self._ensure_pre_effect_guards()
        except AgentKernelError:
            self._transition(TransitionEvent.VALIDATION_FAILED)
            raise
        now = self._clock()
        reservation = self._journal.reserve_intent(
            intent_hash=self._plan.intent_hash,
            transaction_id=self.record.transaction_id,
            reserved_at=now,
        )
        if reservation.transaction_id != self.record.transaction_id:
            self._transition(TransitionEvent.VALIDATION_FAILED)
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Normalized intent is already owned by another transaction",
                details={"owner_transaction_id": reservation.transaction_id},
            )
        if reservation.previous_transaction_id is not None:
            self._record = self._journal.link_transaction_supersession(
                self.record.transaction_id,
                previous_transaction_id=reservation.previous_transaction_id,
            )

        self._transition(TransitionEvent.PROPOSAL_VALID)
        # Phase 0's embedded coordinator has no authority service. This transition is an
        # explicit composition input and carries A0 only; Release 0.1 replaces it with evidence.
        self._transition(TransitionEvent.AUTHORIZED_FOR_STAGING)
        self._transition(TransitionEvent.WORKER_LEASE_ACQUIRED)
        stage_context = StageContext(
            deadline=self._plan.proposal.deadline,
            worker_id="worker:embedded",
        )
        try:
            self._ensure_pre_effect_guards()
            staged = await self._adapter.stage(self._plan, stage_context)
            self._staged_effect = staged
            self._ensure_pre_effect_guards()
            self._staged_receipt = await self._adapter.execute(staged, stage_context)
        except BaseException as error:
            self._staging_cleanup_failed = (
                isinstance(error, AgentKernelError) and error.code is ErrorCode.ROLLBACK_FAILED
            )
            if isinstance(error, CancelledError):
                event = TransitionEvent.CANCELLED
            elif isinstance(error, AgentKernelError) and error.code is ErrorCode.DEADLINE_EXCEEDED:
                event = TransitionEvent.DEADLINE_EXCEEDED
            else:
                event = TransitionEvent.STAGING_FAILED
            self._transition(event)
            await self._complete_abort()
            raise
        self._transition(TransitionEvent.STAGING_SUCCEEDED)
        try:
            self._ensure_pre_effect_guards()
            self._verification = await self._adapter.verify_staged(
                self._staged_receipt,
                VerifyContext(deadline=self._plan.proposal.deadline),
            )
        except BaseException as error:
            if isinstance(error, CancelledError):
                event = TransitionEvent.CANCELLED
            elif isinstance(error, AgentKernelError) and error.code is ErrorCode.DEADLINE_EXCEEDED:
                event = TransitionEvent.DEADLINE_EXCEEDED
            else:
                event = TransitionEvent.STAGED_VERIFICATION_FAILED
            self._transition(event)
            await self._complete_abort()
            raise
        if self._verification.status is not VerificationStatus.PASS:
            self._transition(TransitionEvent.STAGED_VERIFICATION_FAILED)
            await self._complete_abort()
            code = (
                ErrorCode.VERIFICATION_UNKNOWN
                if self._verification.status is VerificationStatus.UNKNOWN
                else ErrorCode.VERIFICATION_FAILED
            )
            raise AgentKernelError(code, "Staged verification did not pass")
        self._transition(TransitionEvent.STAGED_VERIFICATION_PASSED)
        self._transition(TransitionEvent.NO_APPROVAL_REQUIRED)
        return self

    async def commit(self) -> TransactionRecord:
        """Journal commit intent before allowing the adapter's first authoritative effect."""

        async with self._operation_lock:
            return await self._commit()

    async def _commit(self) -> TransactionRecord:
        if self.record.state is not TransactionState.READY_TO_COMMIT:
            raise AgentKernelError(
                ErrorCode.ILLEGAL_TRANSITION,
                "Transaction is not ready for explicit commit",
                details={"state": self.record.state.value},
            )
        if self._staged_receipt is None:
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Missing staged receipt")
        try:
            self._ensure_pre_effect_guards()
        except AgentKernelError as error:
            self._transition(
                TransitionEvent.DEADLINE_EXCEEDED
                if error.code is ErrorCode.DEADLINE_EXCEEDED
                else TransitionEvent.COMMIT_REVALIDATION_FAILED
            )
            await self._complete_abort()
            raise
        refreshed = await self._adapter.inspect(
            self._plan.proposal,
            ReadOnlyContext(deadline=self._plan.proposal.deadline),
        )
        if refreshed.base_version != self._plan.base_version:
            self._transition(TransitionEvent.TARGET_VERSION_CHANGED)
            await self._complete_abort()
            raise AgentKernelError(
                ErrorCode.STALE_STATE,
                "Authoritative target changed between staging and commit",
            )
        try:
            self._ensure_pre_effect_guards()
        except AgentKernelError as error:
            self._transition(
                TransitionEvent.DEADLINE_EXCEEDED
                if error.code is ErrorCode.DEADLINE_EXCEEDED
                else TransitionEvent.COMMIT_REVALIDATION_FAILED
            )
            await self._complete_abort()
            raise
        self._transition(TransitionEvent.COMMIT_GUARDS_PASSED)
        try:
            receipt = await self._adapter.commit(
                self._staged_receipt,
                CommitContext(
                    deadline=self._plan.proposal.deadline,
                    fencing_token=1,
                    idempotency_key=self._plan.intent_hash,
                    target_version_guard=self._plan.base_version,
                ),
            )
        except AgentKernelError as error:
            if error.code is ErrorCode.STALE_STATE:
                self._transition(TransitionEvent.COMMIT_FAILED_NO_EFFECT)
                await self._complete_abort()
            else:
                self._transition(TransitionEvent.COMMIT_OUTCOME_UNKNOWN)
            raise
        except BaseException:
            self._transition(TransitionEvent.COMMIT_OUTCOME_UNKNOWN)
            raise
        try:
            self._journal.append_receipt(receipt)
        except BaseException:
            self._transition(TransitionEvent.COMMIT_OUTCOME_UNKNOWN)
            raise
        try:
            verification = await self._adapter.verify_committed(
                receipt,
                VerifyContext(deadline=self._plan.proposal.deadline),
            )
        except BaseException:
            self._transition(TransitionEvent.COMMIT_PARTIAL_OR_INVALID)
            raise
        if verification.status is VerificationStatus.PASS:
            self._transition(TransitionEvent.COMMIT_VERIFIED)
            return self.record
        self._transition(TransitionEvent.COMMIT_PARTIAL_OR_INVALID)
        raise AgentKernelError(
            ErrorCode.VERIFICATION_FAILED,
            "Committed state could not be verified; recovery is required",
        )

    async def cancel(self) -> TransactionRecord:
        """Cancel a pre-commit transaction and verify staged-state cleanup."""

        async with self._operation_lock:
            return await self._abort_precommit(TransitionEvent.CANCELLED)

    async def enforce_deadline(self) -> TransactionRecord:
        """Apply the absolute deadline at a durable pre-commit boundary."""

        async with self._operation_lock:
            return await self._enforce_deadline()

    async def _enforce_deadline(self) -> TransactionRecord:
        if self.record.state.is_terminal or self._clock() < self._plan.proposal.deadline:
            return self.record
        if self.record.state is TransactionState.NEW:
            self._transition(
                TransitionEvent.VALIDATION_FAILED,
                reason_code=ErrorCode.DEADLINE_EXCEEDED.value,
            )
            return self.record
        return await self._abort_precommit(TransitionEvent.DEADLINE_EXCEEDED)

    async def _abort_precommit(self, event: TransitionEvent) -> TransactionRecord:
        if self.record.state.is_terminal and self.record.state is not TransactionState.COMMITTED:
            return self.record
        if self.record.state not in _PRE_COMMIT_STATES:
            raise AgentKernelError(
                ErrorCode.ILLEGAL_TRANSITION,
                "Cancellation cannot claim no effect after the commit boundary",
                details={"state": self.record.state.value, "event": event.value},
            )
        self._transition(event)
        await self._complete_abort()
        return self.record

    async def _complete_abort(self) -> None:
        if self.record.state is not TransactionState.ABORTING:
            return
        if self._staging_cleanup_failed:
            self._transition(TransitionEvent.STAGING_DISCARD_FAILED)
            return
        staged_for_abort = self._staged_receipt or self._staged_effect
        if staged_for_abort is not None:
            report = await self._adapter.abort(
                staged_for_abort,
                RecoveryContext(
                    deadline=self._plan.proposal.deadline,
                    authority_ref="authority:embedded-abort",
                ),
            )
            if report.status is not VerificationStatus.PASS:
                self._transition(TransitionEvent.STAGING_DISCARD_FAILED)
                return
        self._transition(TransitionEvent.STAGING_DISCARD_SUCCEEDED)

    async def __aexit__(self, *_exc: object) -> None:
        async with self._operation_lock:
            await self._exit()

    async def _exit(self) -> None:
        if self._record is None or self.record.state.is_terminal:
            return
        if self.record.state in _PRE_COMMIT_STATES:
            await self._abort_precommit(TransitionEvent.CONTEXT_EXITED)
            return
        await self._complete_abort()
