"""Explicit stage/execute/verify/commit/recovery adapter protocol."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import Field, JsonValue

from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import RiskClass
from agentkernel.domain.models import (
    ActionProposal,
    Digest,
    EffectReceipt,
    Identifier,
    IntentRecord,
    NonEmptyStr,
    RecoveryReport,
    StrictModel,
    VerificationReport,
)


class OperationManifest(StrictModel):
    risk_floor: RiskClass
    effect_domains: tuple[NonEmptyStr, ...]
    idempotency: NonEmptyStr = "intent_hash"
    staging: bool
    commit: bool
    abort: bool
    rollback: bool
    reconcile: bool
    compensate: bool = False
    preconditions: tuple[NonEmptyStr, ...] = ()
    staged_postconditions: tuple[NonEmptyStr, ...] = ()
    committed_postconditions: tuple[NonEmptyStr, ...] = ()


class AdapterManifest(StrictModel):
    api_version: str = "agentkernel.io/v1alpha1"
    name: Identifier
    version: NonEmptyStr
    implementation_digest: Digest
    operations: dict[NonEmptyStr, OperationManifest]

    @property
    def digest(self) -> str:
        """Digest the exact versioned manifest admitted to the registry."""

        return canonical_digest(self)


class EffectPlan(StrictModel):
    plan_id: Identifier
    proposal: ActionProposal
    canonical_resource: NonEmptyStr
    base_version: NonEmptyStr
    intent_hash: Digest
    risk_class: RiskClass
    effect_domains: tuple[NonEmptyStr, ...]
    semantic_arguments: dict[str, JsonValue] = Field(default_factory=dict)


class StagedEffect(StrictModel):
    stage_id: Identifier
    plan: EffectPlan
    base_state_digest: Digest
    private_state: dict[str, JsonValue] = Field(default_factory=dict)


class StagedReceipt(StrictModel):
    receipt_id: Identifier
    staged: StagedEffect
    staged_state_digest: Digest
    private_state: dict[str, JsonValue] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ReadOnlyContext:
    deadline: datetime


@dataclass(frozen=True, slots=True)
class StageContext:
    deadline: datetime
    worker_id: str


@dataclass(frozen=True, slots=True)
class VerifyContext:
    deadline: datetime
    read_only: bool = True


@dataclass(frozen=True, slots=True)
class CommitContext:
    deadline: datetime
    fencing_token: int
    idempotency_key: str
    target_version_guard: str


@dataclass(frozen=True, slots=True)
class RecoveryContext:
    deadline: datetime
    authority_ref: str


class ReconcileStatus(StrEnum):
    COMMITTED = "COMMITTED"
    NO_EFFECT = "NO_EFFECT"
    PARTIAL_OR_INVALID = "PARTIAL_OR_INVALID"
    UNKNOWN = "UNKNOWN"


class ReconcileReport(StrictModel):
    status: ReconcileStatus
    receipt: EffectReceipt | None = None
    evidence_refs: tuple[Digest, ...] = ()


@runtime_checkable
class EffectAdapter(Protocol):
    """The only trusted lifecycle through which an R1+ effect may occur.

    A commit implementation may raise ``STALE_STATE`` only when its target-version guard proves
    that this transaction has not performed an authoritative mutation. Any failure after the
    first possible mutation must use an ambiguous/verification failure so the coordinator can
    persist ``IN_DOUBT`` or recovery-required state.
    """

    manifest: AdapterManifest

    async def inspect(self, proposal: ActionProposal, ctx: ReadOnlyContext) -> EffectPlan: ...

    async def stage(self, plan: EffectPlan, ctx: StageContext) -> StagedEffect: ...

    async def execute(self, staged: StagedEffect, ctx: StageContext) -> StagedReceipt: ...

    async def verify_staged(
        self, receipt: StagedReceipt, ctx: VerifyContext
    ) -> VerificationReport: ...

    async def commit(self, receipt: StagedReceipt, ctx: CommitContext) -> EffectReceipt: ...

    async def verify_committed(
        self, receipt: EffectReceipt, ctx: VerifyContext
    ) -> VerificationReport: ...

    async def abort(
        self,
        staged: StagedEffect | StagedReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport: ...

    async def rollback(self, receipt: EffectReceipt, ctx: RecoveryContext) -> RecoveryReport: ...

    async def reconcile(self, intent: IntentRecord, ctx: ReadOnlyContext) -> ReconcileReport: ...

    async def compensate(self, receipt: EffectReceipt, ctx: RecoveryContext) -> RecoveryReport: ...
