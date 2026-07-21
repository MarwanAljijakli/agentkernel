"""Immutable public and durable AgentKernel data contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue, StringConstraints

from agentkernel.domain.enums import (
    ActionState,
    IntendedOutcome,
    ProvenanceTrust,
    RiskClass,
    TransactionState,
    VerificationStatus,
)

ApiVersion = Literal["agentkernel.io/v1alpha1"]
SchemaVersion = Literal["1.0"]
NonEmptyStr = Annotated[str, StringConstraints(min_length=1, max_length=512)]
Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,255}$")]
Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]


class StrictModel(BaseModel):
    """Shared trust-boundary behavior for every serialized contract."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
    )


class GoalRecord(StrictModel):
    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    goal_id: Identifier
    principal_id: Identifier
    text: Annotated[str, StringConstraints(min_length=1, max_length=32_768)]
    resource_scope: tuple[NonEmptyStr, ...] = ()
    created_at: AwareDatetime
    deadline: AwareDatetime | None = None
    budget: dict[str, Annotated[int, Field(ge=0)]] = Field(default_factory=dict)


class CapabilityGrant(StrictModel):
    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    capability_id: Identifier
    token_version: Annotated[int, Field(ge=1)] = 1
    key_id: Identifier
    issuer: Identifier
    subject: Identifier
    audience: Identifier
    goal_id: Identifier
    run_id: Identifier
    actions: tuple[NonEmptyStr, ...]
    resources: tuple[NonEmptyStr, ...]
    conditions: dict[str, JsonValue] = Field(default_factory=dict)
    data_classes: tuple[NonEmptyStr, ...] = ()
    issued_at: AwareDatetime
    not_before: AwareDatetime
    expires_at: AwareDatetime
    max_uses: Annotated[int, Field(ge=1)] = 1
    delegation_depth_remaining: Annotated[int, Field(ge=0)] = 0
    parent_capability: Identifier | None = None
    nonce: NonEmptyStr
    signature: NonEmptyStr


class ProvenanceRecord(StrictModel):
    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    provenance_id: Identifier
    source: NonEmptyStr
    acquisition_step: NonEmptyStr
    trust: ProvenanceTrust
    data_classes: tuple[NonEmptyStr, ...] = ()
    parent_ids: tuple[Identifier, ...] = ()
    transformations: tuple[NonEmptyStr, ...] = ()
    integrity_ref: Digest | None = None


class ActionProposal(StrictModel):
    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    goal_id: Identifier
    transaction_id: Identifier
    agent_id: Identifier
    adapter: Identifier
    adapter_version: NonEmptyStr
    operation: NonEmptyStr
    arguments: dict[str, JsonValue]
    provenance_ids: tuple[Identifier, ...] = ()
    capability_refs: tuple[Identifier, ...] = ()
    deadline: AwareDatetime
    idempotency_key: NonEmptyStr | None = None


class TransactionRecord(StrictModel):
    schema_version: SchemaVersion = "1.0"
    transaction_id: Identifier
    goal_id: Identifier
    state: TransactionState = TransactionState.NEW
    version: Annotated[int, Field(ge=0)] = 0
    intent_hash: Digest | None = None
    intended_outcome: IntendedOutcome | None = None
    policy_digest: Digest | None = None
    capability_digest: Digest | None = None
    adapter_manifest_digest: Digest | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime
    reason_code: NonEmptyStr | None = None
    supersedes_transaction_id: Identifier | None = None


class ActionExecutionRecord(StrictModel):
    schema_version: SchemaVersion = "1.0"
    transaction_id: Identifier
    action_id: Identifier
    ordinal: Annotated[int, Field(ge=0)]
    dependency_ordinals: tuple[Annotated[int, Field(ge=0)], ...] = ()
    intent_hash: Digest
    adapter: Identifier
    adapter_version: NonEmptyStr
    adapter_digest: Digest
    risk_class: RiskClass
    state: ActionState = ActionState.PENDING
    version: Annotated[int, Field(ge=0)] = 0
    idempotency_key: NonEmptyStr
    target_version_guard: NonEmptyStr | None = None
    staged_receipt_ref: Digest | None = None
    effect_receipt_ref: Digest | None = None
    recovery_receipt_ref: Digest | None = None
    reason_code: NonEmptyStr | None = None


class IntentRecord(StrictModel):
    schema_version: SchemaVersion = "1.0"
    intent_hash: Digest
    transaction_id: Identifier
    action_id: Identifier | None = None
    idempotency_key: NonEmptyStr
    dispatched: bool = False
    outcome_receipt_ref: Digest | None = None
    created_at: AwareDatetime


class VerificationReport(StrictModel):
    schema_version: SchemaVersion = "1.0"
    status: VerificationStatus
    verifier: Identifier
    summary: Annotated[str, StringConstraints(max_length=4096)] = ""
    evidence_refs: tuple[Digest, ...] = ()


class EffectReceipt(StrictModel):
    schema_version: SchemaVersion = "1.0"
    receipt_id: Identifier
    transaction_id: Identifier
    adapter: Identifier
    operation: NonEmptyStr
    intent_hash: Digest
    target_version_before: NonEmptyStr
    target_version_after: NonEmptyStr
    effect_digest: Digest
    created_at: AwareDatetime


class RecoveryReport(StrictModel):
    schema_version: SchemaVersion = "1.0"
    status: VerificationStatus
    strategy: NonEmptyStr
    restored_state_digest: Digest | None = None
    residual_effects: tuple[NonEmptyStr, ...] = ()
    evidence_refs: tuple[Digest, ...] = ()


class Artifact(StrictModel):
    schema_version: SchemaVersion = "1.0"
    digest: Digest
    media_type: NonEmptyStr
    size_bytes: Annotated[int, Field(ge=0)]
    created_at: AwareDatetime
    storage_ref: NonEmptyStr


class EventEnvelope(StrictModel):
    schema_version: SchemaVersion = "1.0"
    event_id: Identifier
    run_id: Identifier
    transaction_id: Identifier | None = None
    sequence: Annotated[int, Field(ge=0)]
    logical_time: Annotated[int, Field(ge=0)]
    wall_time: AwareDatetime
    event_type: NonEmptyStr
    actor: Identifier
    on_behalf_of: Identifier
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    artifact_refs: tuple[Digest, ...] = ()
    previous_event_hash: Digest | None = None
    event_hash: Digest
    signature_ref: NonEmptyStr | None = None


class PolicyDefault(StrEnum):
    DENY = "deny"
    ABSTAIN = "abstain"


class PolicyEffect(StrEnum):
    GRANT = "grant"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_SHADOW = "require_shadow"


class PolicyRule(StrictModel):
    rule_id: Identifier
    effect: PolicyEffect
    modes: tuple[NonEmptyStr, ...] = ()
    when: dict[str, JsonValue]


class PolicyBundle(StrictModel):
    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    kind: Literal["PolicyBundle"] = "PolicyBundle"
    name: Identifier
    version: NonEmptyStr
    default: PolicyDefault = PolicyDefault.DENY
    rules: tuple[PolicyRule, ...]


class BenchmarkTask(StrictModel):
    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    kind: Literal["BenchmarkTask"] = "BenchmarkTask"
    task_id: Identifier
    version: NonEmptyStr
    license: NonEmptyStr
    environment: dict[str, JsonValue]
    goal: Annotated[str, StringConstraints(min_length=1, max_length=32_768)]
    authority: dict[str, JsonValue]
    budgets: dict[str, Annotated[int, Field(ge=0)]]
    invariants: tuple[NonEmptyStr, ...]
    success: tuple[NonEmptyStr, ...]
    forbidden_actions: tuple[NonEmptyStr, ...] = ()
    labels: dict[str, NonEmptyStr] = Field(default_factory=dict)


def utc_now() -> datetime:
    """Provide an injectable-friendly default for application composition only."""

    return datetime.now().astimezone()
