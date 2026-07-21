"""Reference reversible adapter used to prove the effect boundary contract."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast

from pydantic import JsonValue

from agentkernel.adapters.base import (
    AdapterManifest,
    CommitContext,
    EffectPlan,
    OperationManifest,
    ReadOnlyContext,
    ReconcileReport,
    ReconcileStatus,
    RecoveryContext,
    StageContext,
    StagedEffect,
    StagedReceipt,
    VerifyContext,
)
from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import RiskClass, VerificationStatus
from agentkernel.domain.models import (
    ActionProposal,
    EffectReceipt,
    IntentRecord,
    RecoveryReport,
    VerificationReport,
)
from agentkernel.errors import AgentKernelError, ErrorCode, UnsupportedSemantics
from agentkernel.ids import new_id


@dataclass(slots=True)
class VersionedMemoryTarget:
    state: dict[str, str] = field(default_factory=dict)
    version: int = 0

    @property
    def digest(self) -> str:
        return canonical_digest(self.state)


class MockReversibleAdapter:
    """Apply dictionary updates only during explicit coordinator-authorized commit."""

    def __init__(self, target: VersionedMemoryTarget) -> None:
        self._target = target
        self._stages: dict[str, StagedReceipt] = {}
        self._snapshots: dict[str, dict[str, str]] = {}
        self._receipts_by_intent: dict[str, EffectReceipt] = {}
        self.manifest = AdapterManifest(
            name="mock",
            version="0.1.0",
            implementation_digest=canonical_digest(
                {"implementation": "MockReversibleAdapter", "protocol": "v1alpha1"}
            ),
            operations={
                "set_values": OperationManifest(
                    risk_floor=RiskClass.REVERSIBLE,
                    effect_domains=("memory",),
                    staging=True,
                    commit=True,
                    abort=True,
                    rollback=True,
                    reconcile=True,
                    preconditions=("target_version_matches",),
                    staged_postconditions=("staged_digest_matches",),
                    committed_postconditions=("content_matches_staged",),
                )
            },
        )

    @property
    def target(self) -> VersionedMemoryTarget:
        return self._target

    async def inspect(self, proposal: ActionProposal, ctx: ReadOnlyContext) -> EffectPlan:
        del ctx
        if proposal.operation != "set_values":
            raise UnsupportedSemantics(proposal.operation)
        raw_values = proposal.arguments.get("values")
        if not isinstance(raw_values, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in raw_values.items()
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "set_values requires a string-to-string values object",
            )
        intent_hash = canonical_digest(
            {
                "operation": proposal.operation,
                "canonical_resource": "memory://mock/target",
                "semantic_arguments": {"values": raw_values},
                "goal": proposal.goal_id,
                "principal": proposal.agent_id,
                "adapter_protocol_version": self.manifest.version,
            }
        )
        return EffectPlan(
            plan_id=new_id("plan"),
            proposal=proposal,
            canonical_resource="memory://mock/target",
            base_version=str(self._target.version),
            intent_hash=intent_hash,
            risk_class=RiskClass.REVERSIBLE,
            effect_domains=("memory",),
            semantic_arguments={"values": raw_values},
        )

    async def stage(self, plan: EffectPlan, ctx: StageContext) -> StagedEffect:
        del ctx
        return StagedEffect(
            stage_id=new_id("stage"),
            plan=plan,
            base_state_digest=self._target.digest,
            private_state={"state": cast("dict[str, JsonValue]", deepcopy(self._target.state))},
        )

    async def execute(self, staged: StagedEffect, ctx: StageContext) -> StagedReceipt:
        del ctx
        staged_state = cast("dict[str, str]", deepcopy(staged.private_state["state"]))
        values = cast("dict[str, str]", staged.plan.semantic_arguments["values"])
        staged_state.update(values)
        receipt = StagedReceipt(
            receipt_id=new_id("staged"),
            staged=staged,
            staged_state_digest=canonical_digest(staged_state),
            private_state={"state": cast("dict[str, JsonValue]", staged_state)},
        )
        self._stages[staged.stage_id] = receipt
        return receipt

    async def verify_staged(self, receipt: StagedReceipt, ctx: VerifyContext) -> VerificationReport:
        del ctx
        state = receipt.private_state.get("state")
        status = (
            VerificationStatus.PASS
            if state is not None and canonical_digest(state) == receipt.staged_state_digest
            else VerificationStatus.FAIL
        )
        return VerificationReport(
            status=status,
            verifier="adapter.mock.staged",
            summary="Staged state digest matches"
            if status is VerificationStatus.PASS
            else "Mismatch",
        )

    async def commit(self, receipt: StagedReceipt, ctx: CommitContext) -> EffectReceipt:
        existing = self._receipts_by_intent.get(receipt.staged.plan.intent_hash)
        if existing is not None:
            return existing
        if ctx.target_version_guard != receipt.staged.plan.base_version:
            raise AgentKernelError(ErrorCode.STALE_STATE, "Commit context guard differs from plan")
        if str(self._target.version) != receipt.staged.plan.base_version:
            raise AgentKernelError(ErrorCode.STALE_STATE, "Authoritative target version changed")
        before_state = deepcopy(self._target.state)
        before_version = self._target.version
        after_state = cast("dict[str, str]", deepcopy(receipt.private_state["state"]))
        self._target.state = after_state
        self._target.version += 1
        effect_receipt = EffectReceipt(
            receipt_id=new_id("receipt"),
            transaction_id=receipt.staged.plan.proposal.transaction_id,
            adapter=self.manifest.name,
            operation=receipt.staged.plan.proposal.operation,
            intent_hash=receipt.staged.plan.intent_hash,
            target_version_before=str(before_version),
            target_version_after=str(self._target.version),
            effect_digest=canonical_digest({"before": before_state, "after": after_state}),
            created_at=datetime.now(UTC),
        )
        self._snapshots[effect_receipt.receipt_id] = before_state
        self._receipts_by_intent[effect_receipt.intent_hash] = effect_receipt
        self._stages.pop(receipt.staged.stage_id, None)
        return effect_receipt

    async def verify_committed(
        self, receipt: EffectReceipt, ctx: VerifyContext
    ) -> VerificationReport:
        del ctx
        known = self._receipts_by_intent.get(receipt.intent_hash)
        status = (
            VerificationStatus.PASS
            if known == receipt and str(self._target.version) == receipt.target_version_after
            else VerificationStatus.FAIL
        )
        return VerificationReport(
            status=status,
            verifier="adapter.mock.committed",
            summary="Authoritative receipt and target version match",
        )

    async def abort(
        self,
        staged: StagedEffect | StagedReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        del ctx
        stage_id = staged.staged.stage_id if isinstance(staged, StagedReceipt) else staged.stage_id
        self._stages.pop(stage_id, None)
        return RecoveryReport(
            status=VerificationStatus.PASS,
            strategy="discard_staged_memory",
            restored_state_digest=self._target.digest,
        )

    async def rollback(self, receipt: EffectReceipt, ctx: RecoveryContext) -> RecoveryReport:
        del ctx
        snapshot = self._snapshots.get(receipt.receipt_id)
        if snapshot is None:
            return RecoveryReport(
                status=VerificationStatus.UNKNOWN,
                strategy="restore_memory_snapshot",
                residual_effects=("missing_snapshot",),
            )
        if str(self._target.version) != receipt.target_version_after:
            return RecoveryReport(
                status=VerificationStatus.UNKNOWN,
                strategy="restore_memory_snapshot",
                restored_state_digest=self._target.digest,
                residual_effects=("target_version_changed_after_commit",),
            )
        self._target.state = deepcopy(snapshot)
        self._target.version += 1
        return RecoveryReport(
            status=VerificationStatus.PASS,
            strategy="restore_memory_snapshot",
            restored_state_digest=self._target.digest,
        )

    async def reconcile(self, intent: IntentRecord, ctx: ReadOnlyContext) -> ReconcileReport:
        del ctx
        receipt = self._receipts_by_intent.get(intent.intent_hash)
        if receipt is None:
            return ReconcileReport(status=ReconcileStatus.NO_EFFECT)
        return ReconcileReport(status=ReconcileStatus.COMMITTED, receipt=receipt)

    async def compensate(self, receipt: EffectReceipt, ctx: RecoveryContext) -> RecoveryReport:
        del receipt, ctx
        raise UnsupportedSemantics("compensate")
