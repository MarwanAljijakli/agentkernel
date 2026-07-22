"""Explicit stage/execute/verify/commit/recovery adapter protocol."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Protocol, runtime_checkable

from pydantic import Field, JsonValue, field_validator

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


def _canonical_manifest_text(value: str, *, field_name: str) -> str:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field_name} must be valid UTF-8") from error
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{field_name} must use Unicode NFC")
    return value


class NormalizerManifest(StrictModel):
    """Pinned pure-normalizer admission metadata for one operation schema.

    ``implementation_digest`` is only as strong as the admission pipeline that produced it.
    A declarative pre-release pin is not evidence of installed-byte measurement or signing.
    """

    schema_ref: NonEmptyStr
    schema_digest: Digest
    implementation: Identifier
    version: NonEmptyStr
    implementation_digest: Digest
    max_resources: Annotated[int, Field(ge=1, le=4096)]
    max_argument_bytes: Annotated[int, Field(ge=1, le=16_777_216)]

    @field_validator("schema_ref", "version")
    @classmethod
    def _text_is_unicode_nfc(cls, value: str) -> str:
        return _canonical_manifest_text(value, field_name="Normalizer manifest text")

    @property
    def digest(self) -> str:
        """Digest the complete normalizer contract, including its resource bounds."""

        return canonical_digest(self)


class OperationManifest(StrictModel):
    risk_floor: RiskClass
    effect_domains: Annotated[tuple[NonEmptyStr, ...], Field(max_length=64)]
    idempotency: NonEmptyStr = "intent_hash"
    staging: bool
    commit: bool
    abort: bool
    rollback: bool
    reconcile: bool
    compensate: bool = False
    preconditions: Annotated[tuple[NonEmptyStr, ...], Field(max_length=256)] = ()
    staged_postconditions: Annotated[tuple[NonEmptyStr, ...], Field(max_length=256)] = ()
    committed_postconditions: Annotated[tuple[NonEmptyStr, ...], Field(max_length=256)] = ()
    normalizer: NormalizerManifest | None = None

    @field_validator("idempotency")
    @classmethod
    def _canonical_idempotency(cls, value: str) -> str:
        return _canonical_manifest_text(value, field_name="Operation idempotency mode")

    @field_validator(
        "effect_domains",
        "preconditions",
        "staged_postconditions",
        "committed_postconditions",
    )
    @classmethod
    def _canonical_semantic_sets(cls, values: tuple[str, ...], info: object) -> tuple[str, ...]:
        field_name = getattr(info, "field_name", "operation manifest tuple")
        if values != tuple(sorted(set(values))):
            raise ValueError(f"{field_name} must be sorted and unique")
        for value in values:
            _canonical_manifest_text(value, field_name=field_name)
        return values


class AdapterManifest(StrictModel):
    api_version: str = "agentkernel.io/v1alpha1"
    name: Identifier
    version: NonEmptyStr
    implementation_digest: Digest
    operations: Annotated[
        dict[NonEmptyStr, OperationManifest], Field(min_length=1, max_length=1_024)
    ]

    @field_validator("api_version", "version")
    @classmethod
    def _canonical_text(cls, value: str, info: object) -> str:
        return _canonical_manifest_text(
            value,
            field_name=getattr(info, "field_name", "adapter manifest text"),
        )

    @field_validator("operations")
    @classmethod
    def _canonical_operation_names(
        cls,
        values: dict[str, OperationManifest],
    ) -> dict[str, OperationManifest]:
        for operation in values:
            _canonical_manifest_text(operation, field_name="Adapter operation name")
        return values

    @property
    def digest(self) -> str:
        """Digest the exact versioned manifest admitted to the registry."""

        # Excluding only absent optional extensions preserves the A0 manifest identity.
        return canonical_digest(self.model_dump(mode="python", exclude_none=True))


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
