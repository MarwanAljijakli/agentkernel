"""Versioned durable contracts for the enforced single-node coordinator.

These models bind evidence and work permits; their digests are consistency checks. Authenticity
still depends on admission plus the durable control store and is not implied by a bare digest.
"""

from __future__ import annotations

import unicodedata
from typing import Annotated, Any, Literal, Self, cast

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, field_validator, model_validator

from agentkernel.canonical import canonical_digest, validate_canonical_input_bounds
from agentkernel.domain.enums import (
    AuthorizationRoundPurpose,
    AuthorizationVerdict,
    CommitDispatchState,
    IntendedOutcome,
    LeasePurpose,
    ReconciliationOutcome,
    RecoveryWorkKind,
    RecoveryWorkState,
    StageMaterialState,
    TransactionState,
)
from agentkernel.domain.models import (
    CommitPermit,
    Digest,
    Identifier,
    NonEmptyStr,
    RecoveryPermit,
    StrictModel,
)
from agentkernel.errors import AgentKernelError
from agentkernel.transactions.state_machine import TransitionEvent, apply_transition

_MAX_EVIDENCE_REFS = 256
_MAX_OBLIGATIONS = 64
_MAX_MODES = 16
_MAX_DURABLE_INTEGER = (1 << 63) - 1
_NonNegativeInt = Annotated[StrictInt, Field(ge=0, le=_MAX_DURABLE_INTEGER)]
_PositiveInt = Annotated[StrictInt, Field(ge=1, le=_MAX_DURABLE_INTEGER)]


def _canonical_set(values: tuple[str, ...], *, field_name: str) -> tuple[str, ...]:
    try:
        for value in values:
            value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field_name} must contain valid UTF-8") from error
    if any(unicodedata.normalize("NFC", value) != value for value in values):
        raise ValueError(f"{field_name} must use Unicode NFC")
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{field_name} must be sorted and unique")
    return values


def _canonical_text(value: str, *, field_name: str) -> str:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field_name} must be valid UTF-8") from error
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{field_name} must use Unicode NFC")
    return value


def _preflight_digest_create(values: dict[str, object]) -> None:
    validate_canonical_input_bounds(
        values,
        max_depth=16,
        max_container_items=256,
        max_nodes=4_096,
        max_string_characters=512,
        max_total_string_characters=65_536,
        max_integer_bits=63,
    )


class EnforcedTransactionRecord(StrictModel):
    """Tenant-first transaction projection used only by the enforced coordinator."""

    api_version: Literal["agentkernel.io/v1alpha1"] = "agentkernel.io/v1alpha1"
    schema_version: Literal["1.0", "1.1"] = "1.1"
    tenant_id: Identifier
    transaction_id: Identifier
    principal_id: Identifier
    goal_id: Identifier
    run_id: Identifier
    trace_id: Identifier
    actor_id: Identifier
    on_behalf_of: Identifier
    agent_id: Identifier
    request_digest: Digest
    intent_hash: Digest | None = None
    normalized_action_digest: Digest | None = None
    adapter: Identifier | None = None
    operation: NonEmptyStr | None = None
    adapter_manifest_digest: Digest | None = None
    state: TransactionState
    version: _NonNegativeInt
    deadline: AwareDatetime | None = None
    authorization_round_id: Identifier | None = None
    authorization_round_digest: Digest | None = None
    authority_decision_digest: Digest | None = None
    policy_decision_digest: Digest | None = None
    policy_snapshot_digest: Digest | None = None
    capability_reservation_digest: Digest | None = None
    allowed_modes: Annotated[tuple[NonEmptyStr, ...], Field(max_length=_MAX_MODES)] = ()
    obligations: Annotated[tuple[NonEmptyStr, ...], Field(max_length=_MAX_OBLIGATIONS)] = ()
    intended_outcome: IntendedOutcome | None = None
    reason_code: NonEmptyStr | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime

    @field_validator("allowed_modes", "obligations")
    @classmethod
    def _canonical_sets(cls, values: tuple[str, ...], info: object) -> tuple[str, ...]:
        return _canonical_set(
            values,
            field_name=getattr(info, "field_name", "transaction semantic set"),
        )

    @field_validator("operation", "reason_code")
    @classmethod
    def _canonical_record_text(cls, value: str | None, info: object) -> str | None:
        if value is None:
            return None
        return _canonical_text(
            value,
            field_name=f"Transaction {getattr(info, 'field_name', 'control text')}",
        )

    @model_validator(mode="after")
    def _consistent_record(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("Enforced transaction update precedes creation")
        planning_bindings = (
            self.intent_hash,
            self.normalized_action_digest,
            self.adapter,
            self.operation,
            self.adapter_manifest_digest,
            self.deadline,
        )
        if any(value is not None for value in planning_bindings) and not all(
            value is not None for value in planning_bindings
        ):
            raise ValueError("Planning bindings must be all present or all absent")
        if self.state is TransactionState.NEW and (
            self.version != 0
            or any(value is not None for value in planning_bindings)
            or self.intended_outcome is not None
            or self.reason_code is not None
        ):
            raise ValueError("NEW must be the unplanned version-zero durable ingress record")
        if self.state is not TransactionState.NEW and self.version == 0:
            raise ValueError("Only NEW may have transaction version zero")
        planned_states = {
            TransactionState.PLANNED,
            TransactionState.AUTHORIZED_TO_STAGE,
            TransactionState.STAGING,
            TransactionState.STAGED,
            TransactionState.STAGE_VERIFIED,
            TransactionState.AWAITING_APPROVAL,
            TransactionState.READY_TO_COMMIT,
            TransactionState.COMMITTING,
            TransactionState.COMMITTED,
            TransactionState.FAILED,
            TransactionState.STALE_STATE,
            TransactionState.ROLLING_BACK,
            TransactionState.ROLLED_BACK,
            TransactionState.COMPENSATING,
            TransactionState.COMPENSATED,
            TransactionState.COMPENSATION_FAILED,
            TransactionState.IN_DOUBT,
            TransactionState.RECONCILING,
        }
        if self.state in planned_states and not all(
            value is not None for value in planning_bindings
        ):
            raise ValueError(f"{self.state.value} requires complete planning bindings")
        if self.state is TransactionState.ABORTING and self.intended_outcome is None:
            raise ValueError("ABORTING requires a durable intended outcome")
        if self.state is TransactionState.ABORTED and (
            self.intended_outcome is not IntendedOutcome.ABORTED
        ):
            raise ValueError("ABORTED requires intended outcome ABORTED")
        if self.state is TransactionState.STALE_STATE and (
            self.intended_outcome is not IntendedOutcome.STALE_STATE
        ):
            raise ValueError("STALE_STATE requires intended outcome STALE_STATE")
        if (
            self.state
            not in {
                TransactionState.ABORTING,
                TransactionState.ABORTED,
                TransactionState.STALE_STATE,
                TransactionState.RECOVERY_FAILED,
            }
            and self.intended_outcome is not None
        ):
            raise ValueError("Only abort-path transactions carry intended_outcome")
        authorization_digests = (
            self.authorization_round_id,
            self.authorization_round_digest,
            self.authority_decision_digest,
            self.policy_decision_digest,
            self.policy_snapshot_digest,
            self.capability_reservation_digest,
        )
        if self.state is TransactionState.NEW and (
            any(value is not None for value in authorization_digests)
            or self.allowed_modes
            or self.obligations
        ):
            raise ValueError("NEW cannot carry authorization evidence, modes, or obligations")
        if any(value is not None for value in authorization_digests) and not all(
            value is not None for value in authorization_digests
        ):
            raise ValueError("Authorization bindings must be all present or all absent")
        if not all(value is not None for value in authorization_digests) and (
            self.allowed_modes or self.obligations
        ):
            raise ValueError("Authorization modes and obligations require complete bindings")
        authorized_states = {
            TransactionState.AUTHORIZED_TO_STAGE,
            TransactionState.STAGING,
            TransactionState.STAGED,
            TransactionState.STAGE_VERIFIED,
            TransactionState.AWAITING_APPROVAL,
            TransactionState.READY_TO_COMMIT,
            TransactionState.COMMITTING,
            TransactionState.COMMITTED,
            TransactionState.FAILED,
            TransactionState.STALE_STATE,
            TransactionState.ROLLING_BACK,
            TransactionState.ROLLED_BACK,
            TransactionState.COMPENSATING,
            TransactionState.COMPENSATED,
            TransactionState.COMPENSATION_FAILED,
            TransactionState.IN_DOUBT,
            TransactionState.RECONCILING,
        }
        if self.state in authorized_states and not all(
            value is not None for value in authorization_digests
        ):
            raise ValueError(f"{self.state.value} requires complete authorization bindings")
        if (
            self.state
            in {
                TransactionState.REJECTED,
                TransactionState.FAILED,
                TransactionState.RECOVERY_FAILED,
                TransactionState.COMPENSATION_FAILED,
            }
            and self.reason_code is None
        ):
            raise ValueError(f"{self.state.value} requires a stable reason code")
        return self


class AuthorizationRoundRecord(StrictModel):
    """Immutable link from one evaluation round to exact decision and reservation evidence."""

    api_version: Literal["agentkernel.io/v1alpha1"] = "agentkernel.io/v1alpha1"
    schema_version: Literal["1.0", "1.1"] = "1.1"
    tenant_id: Identifier
    controlled_transaction_id: Identifier
    subject_transaction_id: Identifier
    subject_intent_hash: Digest
    subject_normalized_action_digest: Digest
    round_id: Identifier
    purpose: AuthorizationRoundPurpose
    verdict: AuthorizationVerdict
    authority_snapshot_id: Identifier
    authority_snapshot_digest: Digest
    authority_snapshot_ref: Digest | None = None
    authority_context_ref: Digest | None = None
    authority_decision_id: Identifier
    authority_decision_record_digest: Digest
    authority_decision_digest: Digest
    authority_decision_ref: Digest | None = None
    policy_decision_id: Identifier
    policy_decision_record_digest: Digest
    policy_decision_digest: Digest
    policy_inputs_ref: Digest | None = None
    policy_snapshot_digest: Digest
    policy_snapshot_ref: Digest | None = None
    policy_decision_ref: Digest | None = None
    capability_reservation_plan_digest: Digest | None = None
    capability_reservation_digest: Digest | None = None
    reservation_version: _NonNegativeInt | None = None
    reservation_goal_id: Identifier | None = None
    reservation_run_id: Identifier | None = None
    owner_version: _NonNegativeInt
    owner_history_sequence: _NonNegativeInt
    owner_history_digest: Digest
    allowed_modes: Annotated[tuple[NonEmptyStr, ...], Field(max_length=_MAX_MODES)] = ()
    obligations: Annotated[tuple[NonEmptyStr, ...], Field(max_length=_MAX_OBLIGATIONS)] = ()
    reason_code: NonEmptyStr
    evaluated_at: AwareDatetime
    authority_valid_until: AwareDatetime | None = None
    round_digest: Digest

    @field_validator("allowed_modes", "obligations")
    @classmethod
    def _canonical_sets(cls, values: tuple[str, ...], info: object) -> tuple[str, ...]:
        return _canonical_set(
            values,
            field_name=getattr(info, "field_name", "authorization semantic set"),
        )

    @field_validator("reason_code")
    @classmethod
    def _canonical_reason_code(cls, value: str) -> str:
        return _canonical_text(value, field_name="Authorization reason code")

    @model_validator(mode="after")
    def _consistent_round(self) -> Self:
        if self.purpose is AuthorizationRoundPurpose.RECOVERY and (
            self.controlled_transaction_id == self.subject_transaction_id
        ):
            raise ValueError("Recovery authorization requires a separate normalized action")
        if self.purpose is not AuthorizationRoundPurpose.RECOVERY and (
            self.controlled_transaction_id != self.subject_transaction_id
        ):
            raise ValueError("Staging and precommit authorization must evaluate the transaction")
        reservation = (
            self.capability_reservation_plan_digest,
            self.capability_reservation_digest,
            self.reservation_version,
            self.reservation_goal_id,
            self.reservation_run_id,
        )
        if any(value is not None for value in reservation) and not all(
            value is not None for value in reservation
        ):
            raise ValueError("Authorization reservation bindings must be all present or all absent")
        if self.verdict is AuthorizationVerdict.ELIGIBLE and not all(
            value is not None for value in reservation
        ):
            raise ValueError("Eligible authorization requires a durable reservation fence")
        if self.verdict is AuthorizationVerdict.ELIGIBLE and (
            self.reservation_version is None or self.reservation_version % 2 != 0
        ):
            raise ValueError("Eligible authorization requires a reserved even version")
        if self.verdict is not AuthorizationVerdict.ELIGIBLE and any(
            value is not None for value in reservation
        ):
            raise ValueError("Ineligible authorization cannot carry a capability reservation")
        if self.verdict is AuthorizationVerdict.ELIGIBLE and not self.allowed_modes:
            raise ValueError("Eligible authorization requires at least one allowed mode")
        if self.verdict is not AuthorizationVerdict.ELIGIBLE and self.allowed_modes:
            raise ValueError("Ineligible authorization cannot carry allowed modes")
        artifact_refs = (
            self.authority_snapshot_ref,
            self.authority_context_ref,
            self.authority_decision_ref,
            self.policy_inputs_ref,
            self.policy_snapshot_ref,
            self.policy_decision_ref,
        )
        if self.schema_version == "1.0":
            if any(value is not None for value in artifact_refs) or (
                self.authority_valid_until is not None
            ):
                raise ValueError("Legacy authorization rounds cannot carry v1.1 evidence")
        elif not all(value is not None for value in artifact_refs):
            raise ValueError("Authorization round requires discoverable evidence artifacts")
        if self.schema_version == "1.1" and (
            self.authority_snapshot_ref == self.authority_snapshot_digest
            or self.authority_decision_ref == self.authority_decision_digest
            or self.policy_snapshot_ref == self.policy_snapshot_digest
            or self.policy_decision_ref == self.policy_decision_digest
        ):
            raise ValueError("Semantic decision digests are not evidence artifact references")
        if self.verdict is AuthorizationVerdict.ELIGIBLE and self.schema_version == "1.1":
            if (
                self.authority_valid_until is None
                or self.authority_valid_until <= self.evaluated_at
            ):
                raise ValueError("Eligible authorization requires a future authority window")
        elif self.authority_valid_until is not None:
            raise ValueError("Ineligible authorization cannot grant an authority window")
        if self.round_digest != canonical_digest(self.digest_material()):
            raise ValueError("Authorization round digest mismatch")
        return self

    def digest_material(self) -> dict[str, object]:
        return self.model_dump(mode="python", exclude={"round_digest"})

    @classmethod
    def create(cls, **values: object) -> AuthorizationRoundRecord:
        _preflight_digest_create(values)
        constructor = cast("Any", cls.model_construct)
        unsigned = cast(
            "AuthorizationRoundRecord",
            constructor(**values, round_digest="sha256:" + ("0" * 64)),
        )
        return cls.model_validate(
            {**values, "round_digest": canonical_digest(unsigned.digest_material())}
        )


class EnforcedTransactionEvent(StrictModel):
    """Hash-bound CAS event written in the same transaction as its state change."""

    api_version: Literal["agentkernel.io/v1alpha1"] = "agentkernel.io/v1alpha1"
    schema_version: Literal["1.0"] = "1.0"
    tenant_id: Identifier
    transaction_id: Identifier
    sequence: _NonNegativeInt
    transaction_version: _NonNegativeInt
    event_id: Identifier
    rule_id: NonEmptyStr
    event: NonEmptyStr
    source_state: TransactionState | None
    target_state: TransactionState
    intended_outcome: IntendedOutcome | None = None
    actor_id: Identifier
    on_behalf_of: Identifier
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=_MAX_EVIDENCE_REFS)] = ()
    previous_event_digest: Digest | None = None
    recorded_at: AwareDatetime
    event_digest: Digest

    @field_validator("evidence_refs")
    @classmethod
    def _canonical_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_set(values, field_name="transaction event evidence")

    @model_validator(mode="after")
    def _digest_matches(self) -> Self:
        is_creation = self.event == "transaction.created"
        if is_creation:
            if (
                self.sequence != 0
                or self.transaction_version != 0
                or self.rule_id != "TX-CREATE"
                or self.source_state is not None
                or self.target_state is not TransactionState.NEW
                or self.previous_event_digest is not None
                or self.intended_outcome is not None
            ):
                raise ValueError("Creation event must atomically establish NEW at version zero")
        elif (
            self.transaction_version < 1
            or self.sequence != self.transaction_version
            or self.rule_id == "TX-CREATE"
            or self.source_state is None
            or self.source_state is self.target_state
            or self.previous_event_digest is None
        ):
            raise ValueError("Transition events require a source and positive transaction version")
        if self.target_state is TransactionState.ABORTING and self.intended_outcome is None:
            raise ValueError("ABORTING event requires intended_outcome")
        if self.intended_outcome is not None and self.target_state not in {
            TransactionState.ABORTING,
            TransactionState.ABORTED,
            TransactionState.STALE_STATE,
            TransactionState.RECOVERY_FAILED,
        }:
            raise ValueError("Only abort-path events carry intended_outcome")
        if not is_creation:
            source_state = self.source_state
            if source_state is None:
                raise ValueError("Transition event lost its required source state")
            try:
                transition_event = TransitionEvent(self.event)
                decision = apply_transition(
                    source_state,
                    transition_event,
                    current_intended_outcome=(
                        self.intended_outcome if source_state is TransactionState.ABORTING else None
                    ),
                )
            except (AgentKernelError, ValueError) as error:
                raise ValueError("Event is not a normative transaction transition") from error
            if (
                decision.rule_id != self.rule_id
                or decision.target is not self.target_state
                or decision.intended_outcome is not self.intended_outcome
            ):
                raise ValueError("Event rule, target, or intended outcome is not normative")
        if self.event_digest != canonical_digest(self.digest_material()):
            raise ValueError("Enforced transaction event digest mismatch")
        return self

    def digest_material(self) -> dict[str, object]:
        return self.model_dump(mode="python", exclude={"event_digest"})

    @classmethod
    def create(cls, **values: object) -> EnforcedTransactionEvent:
        _preflight_digest_create(values)
        constructor = cast("Any", cls.model_construct)
        unsigned = cast(
            "EnforcedTransactionEvent",
            constructor(**values, event_digest="sha256:" + ("0" * 64)),
        )
        return cls.model_validate(
            {**values, "event_digest": canonical_digest(unsigned.digest_material())}
        )


class TransactionRecoveryDeadlineRecord(StrictModel):
    """Canonical evidence fixing the first recovery-state deadline into the event chain."""

    api_version: Literal["agentkernel.io/v1alpha1"] = "agentkernel.io/v1alpha1"
    schema_version: Literal["1.0"] = "1.0"
    tenant_id: Identifier
    transaction_id: Identifier
    transaction_version: _PositiveInt
    rule_id: NonEmptyStr
    transition_event: TransitionEvent
    source_state: TransactionState
    target_state: TransactionState
    intended_outcome: IntendedOutcome | None = None
    previous_event_digest: Digest
    absolute_deadline: AwareDatetime
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def _consistent_deadline_transition(self) -> Self:
        if self.absolute_deadline <= self.recorded_at:
            raise ValueError("Recovery deadline must follow its transition time")
        try:
            decision = apply_transition(
                self.source_state,
                self.transition_event,
                current_intended_outcome=(
                    self.intended_outcome
                    if self.source_state is TransactionState.ABORTING
                    else None
                ),
            )
        except AgentKernelError as error:
            raise ValueError("Recovery deadline transition is not normative") from error
        if (
            decision.rule_id != self.rule_id
            or decision.target is not self.target_state
            or decision.intended_outcome is not self.intended_outcome
            or self.target_state
            not in {
                TransactionState.ABORTING,
                TransactionState.FAILED,
                TransactionState.IN_DOUBT,
                TransactionState.RECONCILING,
                TransactionState.ROLLING_BACK,
                TransactionState.COMPENSATING,
            }
        ):
            raise ValueError("Recovery deadline differs from its normative transition")
        return self


class WorkerLeaseRecord(StrictModel):
    """Exclusive worker lease whose fencing token never decreases for a transaction."""

    schema_version: Literal["1.0"] = "1.0"
    tenant_id: Identifier
    transaction_id: Identifier
    lease_id: Identifier
    worker_id: Identifier
    purpose: LeasePurpose
    fencing_token: _PositiveInt
    version: _NonNegativeInt
    acquired_at: AwareDatetime
    expires_at: AwareDatetime
    released_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _valid_interval(self) -> Self:
        if self.expires_at <= self.acquired_at:
            raise ValueError("Worker lease must expire after acquisition")
        if self.released_at is not None and self.released_at < self.acquired_at:
            raise ValueError("Worker lease release precedes acquisition")
        if self.released_at is not None and self.version < 1:
            raise ValueError("A released worker lease must advance version zero")
        return self


class StageMaterialRecord(StrictModel):
    """Durable references to private stage artifacts; payload bytes remain out of SQLite."""

    schema_version: Literal["1.0"] = "1.0"
    tenant_id: Identifier
    transaction_id: Identifier
    stage_id: Identifier
    lease_id: Identifier
    fencing_token: _PositiveInt
    intent_hash: Digest
    normalized_action_digest: Digest
    adapter_manifest_digest: Digest
    plan_digest: Digest
    plan_ref: Digest
    inspection_permit_digest: Digest
    inspection_permit_ref: Digest
    stage_permit_digest: Digest
    stage_permit_ref: Digest
    state: StageMaterialState
    base_state_digest: Digest | None = None
    target_version_guard: NonEmptyStr
    staged_effect_ref: Digest | None = None
    staged_receipt_ref: Digest | None = None
    staged_state_digest: Digest | None = None
    verification_permit_digest: Digest | None = None
    verification_permit_ref: Digest | None = None
    verification_ref: Digest | None = None
    discard_evidence_ref: Digest | None = None
    version: _NonNegativeInt
    created_at: AwareDatetime
    updated_at: AwareDatetime

    @field_validator("target_version_guard")
    @classmethod
    def _canonical_target_guard(cls, value: str) -> str:
        return _canonical_text(value, field_name="Stage material target-version guard")

    @model_validator(mode="after")
    def _consistent_material(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("Stage material update precedes creation")
        exact_versions = {
            StageMaterialState.ALLOCATED: 0,
            StageMaterialState.STAGED: 1,
            StageMaterialState.EXECUTED: 2,
            StageMaterialState.VERIFIED: 3,
        }
        expected_version = exact_versions.get(self.state)
        if expected_version is not None and self.version != expected_version:
            raise ValueError(
                f"{self.state.value} stage material requires version {expected_version}"
            )
        effect_pair = (self.base_state_digest, self.staged_effect_ref)
        receipt_pair = (self.staged_receipt_ref, self.staged_state_digest)
        if (effect_pair[0] is None) != (effect_pair[1] is None):
            raise ValueError("Base-state and staged-effect evidence must appear together")
        if (receipt_pair[0] is None) != (receipt_pair[1] is None):
            raise ValueError("Staged receipt and state digest must appear together")
        if receipt_pair[0] is not None and effect_pair[0] is None:
            raise ValueError("Staged receipt requires staged-effect evidence")
        verification_group = (
            self.verification_permit_digest,
            self.verification_permit_ref,
            self.verification_ref,
        )
        if any(value is None for value in verification_group) != all(
            value is None for value in verification_group
        ):
            raise ValueError("Staged verification and its permit must appear together")
        if self.verification_ref is not None and receipt_pair[0] is None:
            raise ValueError("Staged verification requires executed-stage evidence")
        if self.state in {
            StageMaterialState.DISCARDED,
            StageMaterialState.DISCARD_FAILED,
        }:
            minimum_discard_version = 1
            if effect_pair[0] is not None:
                minimum_discard_version = 2
            if receipt_pair[0] is not None:
                minimum_discard_version = 3
            if self.verification_ref is not None:
                minimum_discard_version = 4
            if self.version < minimum_discard_version:
                raise ValueError(
                    "Discard outcome version cannot precede its retained stage evidence"
                )

        prefix = (
            self.base_state_digest,
            self.staged_effect_ref,
            self.staged_receipt_ref,
            self.staged_state_digest,
            self.verification_permit_digest,
            self.verification_permit_ref,
            self.verification_ref,
        )
        if self.state is StageMaterialState.ALLOCATED and any(
            value is not None for value in (*prefix, self.discard_evidence_ref)
        ):
            raise ValueError("Allocated stage material cannot carry result evidence")
        if self.state is StageMaterialState.STAGED and (
            effect_pair[0] is None
            or any(value is not None for value in (*receipt_pair, *verification_group))
            or self.discard_evidence_ref is not None
        ):
            raise ValueError("STAGED requires exactly staged-effect and base-state evidence")
        if self.state is StageMaterialState.EXECUTED and (
            receipt_pair[0] is None
            or any(value is not None for value in verification_group)
            or self.discard_evidence_ref is not None
        ):
            raise ValueError("EXECUTED requires exact receipt evidence without verification")
        if self.state is StageMaterialState.VERIFIED and (
            any(value is None for value in verification_group)
            or self.discard_evidence_ref is not None
        ):
            raise ValueError("VERIFIED requires exact staged-verification evidence")
        if (
            self.state
            in {
                StageMaterialState.DISCARDED,
                StageMaterialState.DISCARD_FAILED,
            }
            and self.discard_evidence_ref is None
        ):
            raise ValueError("Discard outcome requires durable evidence")
        if (
            self.state
            not in {
                StageMaterialState.DISCARDED,
                StageMaterialState.DISCARD_FAILED,
            }
            and self.discard_evidence_ref is not None
        ):
            raise ValueError("Only a discard outcome can carry discard evidence")
        return self


class CommitDispatchRecord(StrictModel):
    """One dispatch generation, unique per tenant, intent, and owner version."""

    schema_version: Literal["1.0"] = "1.0"
    tenant_id: Identifier
    transaction_id: Identifier
    intent_hash: Digest
    dispatch_id: Identifier
    owner_version: _NonNegativeInt
    permit: CommitPermit
    permit_ref: Digest
    state: CommitDispatchState
    effect_receipt_ref: Digest | None = None
    committed_verification_permit_digest: Digest | None = None
    committed_verification_permit_ref: Digest | None = None
    committed_verification_ref: Digest | None = None
    no_effect_evidence_ref: Digest | None = None
    outcome_evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=_MAX_EVIDENCE_REFS)] = ()
    unavailable_record_digest: Digest | None = None
    version: _NonNegativeInt
    created_at: AwareDatetime
    updated_at: AwareDatetime

    @field_validator("permit", mode="before")
    @classmethod
    def _revalidate_permit(cls, value: object) -> CommitPermit:
        if isinstance(value, CommitPermit):
            value = value.model_dump(mode="python")
        return CommitPermit.model_validate(value)

    @field_validator("outcome_evidence_refs")
    @classmethod
    def _canonical_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_set(values, field_name="dispatch outcome evidence")

    @model_validator(mode="after")
    def _consistent_dispatch(self) -> Self:
        if (
            self.tenant_id != self.permit.tenant_id
            or self.transaction_id != self.permit.transaction_id
            or self.intent_hash != self.permit.intent_hash
            or self.dispatch_id != self.permit.dispatch_id
            or self.owner_version != self.permit.owner_version
        ):
            raise ValueError("Commit dispatch and permit identities differ")
        if self.permit_ref != canonical_digest(self.permit):
            raise ValueError("Commit dispatch permit artifact ref is inconsistent")
        if self.updated_at < self.created_at:
            raise ValueError("Commit dispatch update precedes creation")
        if not (self.permit.issued_at <= self.created_at < self.permit.deadline):
            raise ValueError("Commit dispatch must be durably created while its permit is valid")
        if self.state is not CommitDispatchState.DISPATCHED and self.version < 1:
            raise ValueError("A classified commit dispatch must advance version zero")
        if self.state is CommitDispatchState.COMMITTED and self.effect_receipt_ref is None:
            raise ValueError("Committed dispatch requires an effect receipt")
        if self.state is CommitDispatchState.COMMITTED and self.committed_verification_ref is None:
            raise ValueError("Committed dispatch requires committed-state verification")
        committed_verification_group = (
            self.committed_verification_permit_digest,
            self.committed_verification_permit_ref,
            self.committed_verification_ref,
        )
        if any(value is None for value in committed_verification_group) != all(
            value is None for value in committed_verification_group
        ):
            raise ValueError("Committed verification and its permit must appear together")
        if self.state is CommitDispatchState.NO_EFFECT and self.no_effect_evidence_ref is None:
            raise ValueError("No-effect dispatch requires authoritative absence evidence")
        if self.effect_receipt_ref is not None and self.no_effect_evidence_ref is not None:
            raise ValueError("Dispatch cannot be both committed and no-effect")
        if (
            self.state is CommitDispatchState.DISPATCHED
            and self.version == 0
            and (
                self.effect_receipt_ref is not None
                or self.committed_verification_permit_digest is not None
                or self.committed_verification_permit_ref is not None
                or self.committed_verification_ref is not None
                or self.no_effect_evidence_ref is not None
                or self.outcome_evidence_refs
            )
        ):
            raise ValueError("A newly dispatched record cannot carry outcome evidence")
        if (
            self.state is CommitDispatchState.DISPATCHED
            and self.version > 0
            and (
                self.effect_receipt_ref is None
                or self.committed_verification_permit_digest is not None
                or self.committed_verification_permit_ref is not None
                or self.committed_verification_ref is not None
                or self.no_effect_evidence_ref is not None
                or not self.outcome_evidence_refs
            )
        ):
            raise ValueError("A pending receipt observation requires exact effect evidence")
        if (
            self.state is not CommitDispatchState.DISPATCHED
            and not self.outcome_evidence_refs
            and self.unavailable_record_digest is None
        ):
            raise ValueError("A classified dispatch requires durable outcome evidence")
        if self.unavailable_record_digest is not None and (
            self.state is CommitDispatchState.DISPATCHED
            or self.unavailable_record_digest in self.outcome_evidence_refs
        ):
            raise ValueError(
                "Unavailable dispatch evidence must be typed and outside artifact refs"
            )
        if self.state is not CommitDispatchState.COMMITTED and (
            any(value is not None for value in committed_verification_group)
        ):
            raise ValueError("Only a committed dispatch carries committed-state verification")
        if self.state is CommitDispatchState.NO_EFFECT and self.effect_receipt_ref is not None:
            raise ValueError("A no-effect dispatch cannot carry an effect receipt")
        if self.state is not CommitDispatchState.NO_EFFECT and self.no_effect_evidence_ref:
            raise ValueError("Only a no-effect dispatch carries authoritative absence evidence")
        return self


class DispatchOutcomeRecord(StrictModel):
    """Immutable hash-chain observation for one durable dispatch generation."""

    schema_version: Literal["1.0"] = "1.0"
    tenant_id: Identifier
    transaction_id: Identifier
    intent_hash: Digest
    owner_version: _NonNegativeInt
    dispatch_id: Identifier
    sequence: _NonNegativeInt
    outcome_id: Identifier
    source_state: CommitDispatchState | None
    target_state: CommitDispatchState
    classification: ReconciliationOutcome | None = None
    effect_receipt_ref: Digest | None = None
    committed_verification_permit_digest: Digest | None = None
    committed_verification_permit_ref: Digest | None = None
    committed_verification_ref: Digest | None = None
    no_effect_evidence_ref: Digest | None = None
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=_MAX_EVIDENCE_REFS)]
    unavailable_record_digest: Digest | None = None
    reason_code: NonEmptyStr | None = None
    previous_outcome_digest: Digest | None = None
    recorded_at: AwareDatetime
    outcome_digest: Digest

    @field_validator("evidence_refs")
    @classmethod
    def _canonical_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_set(values, field_name="dispatch outcome evidence")

    @field_validator("reason_code")
    @classmethod
    def _canonical_reason_code(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _canonical_text(value, field_name="Dispatch outcome reason code")

    @model_validator(mode="after")
    def _consistent_outcome(self) -> Self:
        if self.sequence == 0:
            if (
                self.source_state is not None
                or self.target_state is not CommitDispatchState.DISPATCHED
                or self.classification is not None
                or self.previous_outcome_digest is not None
                or self.effect_receipt_ref is not None
                or self.committed_verification_permit_digest is not None
                or self.committed_verification_permit_ref is not None
                or self.committed_verification_ref is not None
                or self.no_effect_evidence_ref is not None
                or self.reason_code is not None
            ):
                raise ValueError("Initial dispatch outcome must record only durable dispatch")
        elif self.source_state is None or self.previous_outcome_digest is None:
            raise ValueError(
                "Dispatch observations after sequence zero require a hash-chain source"
            )

        if self.sequence > 0 and self.classification is None:
            receipt_observation = (
                self.source_state is CommitDispatchState.DISPATCHED
                and self.target_state is CommitDispatchState.DISPATCHED
                and self.effect_receipt_ref is not None
                and self.committed_verification_permit_digest is None
                and self.committed_verification_permit_ref is None
                and self.committed_verification_ref is None
                and self.no_effect_evidence_ref is None
                and self.reason_code is None
            )
            review_escalation = (
                self.source_state is CommitDispatchState.IN_DOUBT
                and self.target_state is CommitDispatchState.REVIEW_REQUIRED
                and self.effect_receipt_ref is None
                and self.committed_verification_permit_digest is None
                and self.committed_verification_permit_ref is None
                and self.committed_verification_ref is None
                and self.no_effect_evidence_ref is None
                and self.reason_code is not None
            )
            if not (receipt_observation or review_escalation):
                raise ValueError("Unclassified dispatch observation is not a legal evidence step")
        if self.classification is not None:
            expected_state = {
                ReconciliationOutcome.COMMITTED: CommitDispatchState.COMMITTED,
                ReconciliationOutcome.NO_EFFECT: CommitDispatchState.NO_EFFECT,
                ReconciliationOutcome.PARTIAL_OR_INVALID: (CommitDispatchState.PARTIAL_OR_INVALID),
                ReconciliationOutcome.UNKNOWN: CommitDispatchState.IN_DOUBT,
            }[self.classification]
            if self.target_state is not expected_state:
                raise ValueError("Dispatch classification does not match its target state")
            if self.source_state not in {
                CommitDispatchState.DISPATCHED,
                CommitDispatchState.IN_DOUBT,
            }:
                raise ValueError("Terminal dispatch evidence cannot be reclassified")
        if self.classification is ReconciliationOutcome.COMMITTED and (
            self.effect_receipt_ref is None
            or self.committed_verification_permit_digest is None
            or self.committed_verification_permit_ref is None
            or self.committed_verification_ref is None
            or self.no_effect_evidence_ref is not None
        ):
            raise ValueError("Committed dispatch outcome requires receipt and verification")
        if self.classification is ReconciliationOutcome.NO_EFFECT and (
            self.no_effect_evidence_ref is None
            or self.effect_receipt_ref is not None
            or self.committed_verification_permit_digest is not None
            or self.committed_verification_permit_ref is not None
            or self.committed_verification_ref is not None
        ):
            raise ValueError("No-effect dispatch outcome requires authoritative absence evidence")
        if self.classification in {
            ReconciliationOutcome.PARTIAL_OR_INVALID,
            ReconciliationOutcome.UNKNOWN,
        } and any(
            value is not None
            for value in (
                self.committed_verification_permit_digest,
                self.committed_verification_permit_ref,
                self.committed_verification_ref,
                self.no_effect_evidence_ref,
            )
        ):
            raise ValueError(
                "Partial or unknown dispatch cannot carry verification or absence evidence"
            )
        if self.unavailable_record_digest is not None and (
            self.classification is not ReconciliationOutcome.UNKNOWN
            or self.target_state is not CommitDispatchState.IN_DOUBT
            or self.unavailable_record_digest in self.evidence_refs
        ):
            raise ValueError("Unavailable dispatch evidence must be a typed UNKNOWN classification")
        if self.sequence > 0 and not self.evidence_refs and self.unavailable_record_digest is None:
            raise ValueError("Dispatch classification requires evidence or typed unavailability")
        digest_material = self.digest_material()
        accepted_digests = {canonical_digest(digest_material)}
        if self.unavailable_record_digest is None:
            legacy_material = dict(digest_material)
            legacy_material.pop("unavailable_record_digest", None)
            accepted_digests.add(canonical_digest(legacy_material))
        if self.outcome_digest not in accepted_digests:
            raise ValueError("Dispatch outcome digest mismatch")
        return self

    def digest_material(self) -> dict[str, object]:
        return self.model_dump(mode="python", exclude={"outcome_digest"})

    @classmethod
    def create(cls, **values: object) -> DispatchOutcomeRecord:
        _preflight_digest_create(values)
        constructor = cast("Any", cls.model_construct)
        unsigned = cast(
            "DispatchOutcomeRecord",
            constructor(**values, outcome_digest="sha256:" + ("0" * 64)),
        )
        return cls.model_validate(
            {**values, "outcome_digest": canonical_digest(unsigned.digest_material())}
        )


class ReconciliationAttemptRecord(StrictModel):
    """One bounded evidence query for a previously dispatched intent."""

    schema_version: Literal["1.0", "1.1"] = "1.1"
    tenant_id: Identifier
    transaction_id: Identifier
    intent_hash: Digest
    dispatch_id: Identifier
    recovery_id: Identifier
    attempt: _PositiveInt
    lease_id: Identifier
    fencing_token: _PositiveInt
    outcome: ReconciliationOutcome | None = None
    effect_receipt_ref: Digest | None = None
    committed_verification_permit_digest: Digest | None = None
    committed_verification_permit_ref: Digest | None = None
    committed_verification_ref: Digest | None = None
    no_effect_evidence_ref: Digest | None = None
    operation_evidence_ref: Digest | None = None
    operation_reason_code: Identifier | None = None
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=_MAX_EVIDENCE_REFS)] = ()
    completion_evidence_refs: (
        Annotated[tuple[Digest, ...], Field(max_length=_MAX_EVIDENCE_REFS)] | None
    ) = None
    started_at: AwareDatetime
    completed_at: AwareDatetime | None = None
    next_attempt_not_before: AwareDatetime | None = None
    version: _NonNegativeInt = 0

    @field_validator("evidence_refs", "completion_evidence_refs")
    @classmethod
    def _canonical_evidence(
        cls,
        values: tuple[str, ...] | None,
    ) -> tuple[str, ...] | None:
        if values is None:
            return None
        return _canonical_set(values, field_name="reconciliation evidence")

    @model_validator(mode="after")
    def _valid_times(self) -> Self:
        if self.schema_version == "1.0" and (
            self.operation_evidence_ref is not None or self.operation_reason_code is not None
        ):
            raise ValueError("Legacy reconciliation attempts cannot carry operation evidence")
        if self.operation_reason_code is not None and self.operation_evidence_ref is None:
            raise ValueError("Reconciliation operation reason requires operation evidence")
        if (self.outcome is None) != (self.completed_at is None):
            raise ValueError("Reconciliation outcome and completion must appear together")
        if (self.outcome is None) != (self.completion_evidence_refs is None):
            raise ValueError(
                "Reconciliation completion input evidence must appear with its outcome"
            )
        outcome_refs = (
            self.effect_receipt_ref,
            self.committed_verification_permit_digest,
            self.committed_verification_permit_ref,
            self.committed_verification_ref,
            self.no_effect_evidence_ref,
        )
        if self.outcome is None and (
            any(value is not None for value in outcome_refs)
            or self.operation_evidence_ref is not None
            or self.operation_reason_code is not None
            or self.next_attempt_not_before
        ):
            raise ValueError("Started reconciliation cannot carry outcome evidence")
        if self.outcome is None and (self.version != 0 or not self.evidence_refs):
            raise ValueError("Started reconciliation must be version zero with durable evidence")
        if self.outcome is not None and self.version != 1:
            raise ValueError("Completed reconciliation must be version one after STARTED")
        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("Reconciliation completion precedes start")
        if self.completed_at is not None and not self.evidence_refs:
            raise ValueError("Completed reconciliation requires durable evidence")
        if self.completion_evidence_refs is not None and not set(
            self.completion_evidence_refs
        ).issubset(self.evidence_refs):
            raise ValueError("Reconciliation completion input evidence must be retained durably")
        if (
            self.operation_evidence_ref is not None
            and self.completion_evidence_refs is not None
            and self.operation_evidence_ref not in self.completion_evidence_refs
        ):
            raise ValueError(
                "Reconciliation operation evidence must belong to its completion input"
            )
        if (
            self.next_attempt_not_before is not None
            and self.outcome is not ReconciliationOutcome.UNKNOWN
        ):
            raise ValueError("Only an unknown reconciliation outcome may schedule another attempt")
        if self.outcome is ReconciliationOutcome.COMMITTED and (
            self.effect_receipt_ref is None
            or self.committed_verification_permit_digest is None
            or self.committed_verification_permit_ref is None
            or self.committed_verification_ref is None
            or self.no_effect_evidence_ref is not None
        ):
            raise ValueError("Committed reconciliation requires receipt and verification evidence")
        if self.outcome is ReconciliationOutcome.NO_EFFECT and (
            self.no_effect_evidence_ref is None
            or self.effect_receipt_ref is not None
            or self.committed_verification_permit_digest is not None
            or self.committed_verification_permit_ref is not None
            or self.committed_verification_ref is not None
        ):
            raise ValueError("No-effect reconciliation requires authoritative absence evidence")
        if self.outcome in {
            ReconciliationOutcome.PARTIAL_OR_INVALID,
            ReconciliationOutcome.UNKNOWN,
        } and any(
            value is not None
            for value in (
                self.committed_verification_permit_digest,
                self.committed_verification_permit_ref,
                self.committed_verification_ref,
                self.no_effect_evidence_ref,
            )
        ):
            raise ValueError(
                "Partial or unknown reconciliation cannot carry verification or absence evidence"
            )
        if self.next_attempt_not_before is not None and (
            self.completed_at is None or self.next_attempt_not_before < self.completed_at
        ):
            raise ValueError("Reconciliation backoff precedes completion")
        return self

    def canonical_record_json(self) -> dict[str, object]:
        exclude: set[str] = set()
        if self.schema_version == "1.0":
            exclude.update({"operation_evidence_ref", "operation_reason_code"})
        return self.model_dump(mode="python", exclude=exclude)


class LateRecoveryReportRecord(StrictModel):
    """Exact adapter evidence reported after a recovery permit became unusable."""

    schema_version: Literal["1.0", "1.1"] = "1.1"
    tenant_id: Identifier
    transaction_id: Identifier
    recovery_id: Identifier
    operation_evidence_ref: Digest
    operation_reason_code: Identifier | None = None
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=_MAX_EVIDENCE_REFS)]
    reported_at: AwareDatetime
    reason_code: NonEmptyStr
    terminal_work_digest: Digest
    report_digest: Digest

    @field_validator("evidence_refs")
    @classmethod
    def _canonical_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_set(values, field_name="late recovery evidence")

    @field_validator("reason_code")
    @classmethod
    def _canonical_reason_code(cls, value: str) -> str:
        return _canonical_text(value, field_name="Late recovery reason code")

    @field_validator("operation_reason_code")
    @classmethod
    def _canonical_operation_reason_code(cls, value: str | None) -> str | None:
        return (
            None
            if value is None
            else _canonical_text(value, field_name="Late recovery operation reason code")
        )

    @model_validator(mode="after")
    def _consistent_report(self) -> Self:
        if self.schema_version == "1.0" and self.operation_reason_code is not None:
            raise ValueError("Legacy late reports cannot carry an operation reason")
        if self.operation_evidence_ref not in self.evidence_refs:
            raise ValueError("Operation evidence must be included in the late report")
        if self.report_digest != canonical_digest(self.digest_material()):
            raise ValueError("Late recovery report digest mismatch")
        return self

    def digest_material(self) -> dict[str, object]:
        exclude = {"report_digest"}
        if self.schema_version == "1.0":
            exclude.add("operation_reason_code")
        return self.model_dump(mode="python", exclude=exclude)

    @classmethod
    def create(cls, **values: object) -> LateRecoveryReportRecord:
        _preflight_digest_create(values)
        constructor = cast("Any", cls.model_construct)
        unsigned = cast(
            "LateRecoveryReportRecord",
            constructor(**values, report_digest="sha256:" + ("0" * 64)),
        )
        return cls.model_validate(
            {**values, "report_digest": canonical_digest(unsigned.digest_material())}
        )


class DispatchEvidenceUnavailableRecord(StrictModel):
    """SQL-bound fact that a dispatched effect could not receive artifact evidence."""

    schema_version: Literal["1.0"] = "1.0"
    tenant_id: Identifier
    transaction_id: Identifier
    dispatch_id: Identifier
    boundary: Literal[
        "POST_DISPATCH_CLASSIFICATION",
        "RECOVERY_SCANNER_CLASSIFICATION",
    ]
    evidence_status: Literal["UNAVAILABLE"] = "UNAVAILABLE"
    operation_evidence_ref: None = None
    supporting_refs: Annotated[
        tuple[Digest, ...],
        Field(min_length=1, max_length=_MAX_EVIDENCE_REFS),
    ]
    reported_at: AwareDatetime
    reason_code: NonEmptyStr
    record_digest: Digest

    @field_validator("supporting_refs")
    @classmethod
    def _canonical_supporting_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_set(values, field_name="unavailable dispatch supporting evidence")

    @field_validator("reason_code")
    @classmethod
    def _canonical_text_fields(cls, value: str) -> str:
        return _canonical_text(value, field_name="Unavailable dispatch evidence field")

    @model_validator(mode="after")
    def _consistent_record(self) -> Self:
        if not self.reason_code.startswith("EVIDENCE_UNAVAILABLE:"):
            raise ValueError("Unavailable dispatch evidence requires an unavailable reason")
        if self.record_digest != canonical_digest(self.digest_material()):
            raise ValueError("Unavailable dispatch evidence digest mismatch")
        return self

    def digest_material(self) -> dict[str, object]:
        return self.model_dump(mode="python", exclude={"record_digest"})

    @classmethod
    def create(cls, **values: object) -> DispatchEvidenceUnavailableRecord:
        _preflight_digest_create(values)
        constructor = cast("Any", cls.model_construct)
        unsigned = cast(
            "DispatchEvidenceUnavailableRecord",
            constructor(**values, record_digest="sha256:" + ("0" * 64)),
        )
        return cls.model_validate(
            {**values, "record_digest": canonical_digest(unsigned.digest_material())}
        )


class RecoveryEvidenceUnavailableRecord(StrictModel):
    """SQL-bound terminal fact when possible recovery effects lack artifact evidence."""

    schema_version: Literal["1.0"] = "1.0"
    tenant_id: Identifier
    transaction_id: Identifier
    recovery_id: Identifier
    boundary: Literal[
        "RECOVERY_DEADLINE",
        "RECOVERY_LEASE_EXPIRED",
        "RECOVERY_LEASE_RELEASED",
        "POST_CLAIM_SETUP",
        "RECOVERY_ADAPTER_OR_EVIDENCE",
        "RECONCILIATION_SETUP_OR_QUERY",
        "RECONCILIATION_EVIDENCE",
    ]
    evidence_status: Literal["UNAVAILABLE"] = "UNAVAILABLE"
    operation_evidence_ref: None = None
    supporting_refs: Annotated[
        tuple[Digest, ...],
        Field(min_length=1, max_length=_MAX_EVIDENCE_REFS),
    ]
    reported_at: AwareDatetime
    reason_code: NonEmptyStr
    record_digest: Digest

    @field_validator("supporting_refs")
    @classmethod
    def _canonical_supporting_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_set(values, field_name="unavailable recovery supporting evidence")

    @field_validator("reason_code")
    @classmethod
    def _canonical_text_fields(cls, value: str) -> str:
        return _canonical_text(value, field_name="Unavailable recovery evidence field")

    @model_validator(mode="after")
    def _consistent_record(self) -> Self:
        if not self.reason_code.startswith("EVIDENCE_UNAVAILABLE:"):
            raise ValueError("Unavailable recovery evidence requires an unavailable reason")
        if self.record_digest != canonical_digest(self.digest_material()):
            raise ValueError("Unavailable recovery evidence digest mismatch")
        return self

    def digest_material(self) -> dict[str, object]:
        return self.model_dump(mode="python", exclude={"record_digest"})

    @classmethod
    def create(cls, **values: object) -> RecoveryEvidenceUnavailableRecord:
        _preflight_digest_create(values)
        constructor = cast("Any", cls.model_construct)
        unsigned = cast(
            "RecoveryEvidenceUnavailableRecord",
            constructor(**values, record_digest="sha256:" + ("0" * 64)),
        )
        return cls.model_validate(
            {**values, "record_digest": canonical_digest(unsigned.digest_material())}
        )


class RecoveryCompletionReportRecord(StrictModel):
    """Exact evidence identity for one on-time recovery completion."""

    schema_version: Literal["1.0"] = "1.0"
    tenant_id: Identifier
    transaction_id: Identifier
    recovery_id: Identifier
    succeeded: bool
    operation_evidence_ref: Digest
    evidence_refs: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=_MAX_EVIDENCE_REFS)]
    completed_at: AwareDatetime
    reason_code: NonEmptyStr | None = None
    terminal_work_digest: Digest
    report_digest: Digest

    @field_validator("evidence_refs")
    @classmethod
    def _canonical_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_set(values, field_name="recovery completion evidence")

    @field_validator("reason_code")
    @classmethod
    def _canonical_reason_code(cls, value: str | None) -> str | None:
        return (
            None
            if value is None
            else _canonical_text(value, field_name="Recovery completion reason code")
        )

    @model_validator(mode="after")
    def _consistent_report(self) -> Self:
        if self.operation_evidence_ref not in self.evidence_refs:
            raise ValueError("Operation evidence must be included in the completion report")
        if self.succeeded == (self.reason_code is not None):
            raise ValueError("Only a failed recovery completion carries a reason code")
        if self.report_digest != canonical_digest(self.digest_material()):
            raise ValueError("Recovery completion report digest mismatch")
        return self

    def digest_material(self) -> dict[str, object]:
        return self.model_dump(mode="python", exclude={"report_digest"})

    @classmethod
    def create(cls, **values: object) -> RecoveryCompletionReportRecord:
        _preflight_digest_create(values)
        constructor = cast("Any", cls.model_construct)
        unsigned = cast(
            "RecoveryCompletionReportRecord",
            constructor(**values, report_digest="sha256:" + ("0" * 64)),
        )
        return cls.model_validate(
            {**values, "report_digest": canonical_digest(unsigned.digest_material())}
        )


class RecoveryWorkRecord(StrictModel):
    """Separately authorized, deadline-bounded recovery work item."""

    schema_version: Literal["1.0"] = "1.0"
    tenant_id: Identifier
    transaction_id: Identifier
    intent_hash: Digest
    recovery_id: Identifier
    root_recovery_id: Identifier
    predecessor_recovery_id: Identifier | None = None
    recovery_ordinal: _PositiveInt
    max_recovery_attempts: _PositiveInt
    not_before: AwareDatetime
    recovery_action_transaction_id: Identifier
    recovery_action_intent_hash: Digest
    recovery_action_digest: Digest
    adapter_manifest_digest: Digest
    kind: RecoveryWorkKind
    target_id: Identifier
    target_owner_version: _NonNegativeInt
    target_owner_history_sequence: _NonNegativeInt
    target_owner_history_digest: Digest
    target_evidence_ref: Digest
    target_version_guard: NonEmptyStr
    state: RecoveryWorkState
    authorization_round_id: Identifier
    authorization_round_digest: Digest
    authority_decision_digest: Digest
    policy_decision_digest: Digest
    policy_snapshot_digest: Digest
    capability_reservation_digest: Digest | None = None
    reservation_version: _NonNegativeInt | None = None
    owner_version: _NonNegativeInt
    owner_history_sequence: _NonNegativeInt
    owner_history_digest: Digest
    approval_required: StrictBool
    approval_id: Identifier | None = None
    approval_evidence_ref: Digest
    permit: RecoveryPermit | None = None
    permit_ref: Digest | None = None
    lease_id: Identifier | None = None
    worker_id: Identifier | None = None
    fencing_token: _PositiveInt | None = None
    deadline: AwareDatetime
    attempt: _NonNegativeInt = 0
    version: _NonNegativeInt = 0
    evidence_refs: Annotated[tuple[Digest, ...], Field(max_length=_MAX_EVIDENCE_REFS)] = ()
    reason_code: NonEmptyStr | None = None
    unavailable_record_digest: Digest | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime

    @field_validator("target_version_guard")
    @classmethod
    def _canonical_target_guard(cls, value: str) -> str:
        return _canonical_text(value, field_name="Recovery work target-version guard")

    @field_validator("reason_code")
    @classmethod
    def _canonical_reason_code(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _canonical_text(value, field_name="Recovery work reason code")

    @field_validator("permit", mode="before")
    @classmethod
    def _revalidate_permit(cls, value: object) -> RecoveryPermit | None:
        if value is None:
            return None
        if isinstance(value, RecoveryPermit):
            value = value.model_dump(mode="python")
        return RecoveryPermit.model_validate(value)

    @field_validator("evidence_refs")
    @classmethod
    def _canonical_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_set(values, field_name="recovery evidence")

    @model_validator(mode="after")
    def _consistent_recovery(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("Recovery update precedes creation")
        has_unavailable_reason = self.reason_code is not None and self.reason_code.startswith(
            "EVIDENCE_UNAVAILABLE:"
        )
        if has_unavailable_reason != (self.unavailable_record_digest is not None):
            raise ValueError(
                "Typed unavailable recovery reason and record digest must appear together"
            )
        if self.unavailable_record_digest is not None and (
            self.state is not RecoveryWorkState.REVIEW_REQUIRED
            or self.unavailable_record_digest in self.evidence_refs
        ):
            raise ValueError(
                "Unavailable recovery record must be typed, terminal, and outside artifact refs"
            )
        if self.created_at >= self.deadline:
            raise ValueError("Recovery work must be created before its deadline")
        if self.not_before > self.created_at or self.not_before >= self.deadline:
            raise ValueError("Recovery work must be created within its retry window")
        if self.recovery_ordinal > self.max_recovery_attempts:
            raise ValueError("Recovery work exceeds its durable attempt bound")
        if self.recovery_ordinal == 1 and (
            self.root_recovery_id != self.recovery_id or self.predecessor_recovery_id is not None
        ):
            raise ValueError("Initial recovery work must establish its own lineage root")
        if self.recovery_ordinal > 1 and (
            self.root_recovery_id == self.recovery_id
            or self.predecessor_recovery_id is None
            or self.predecessor_recovery_id == self.recovery_id
        ):
            raise ValueError("Retry recovery work requires a distinct predecessor and root")
        if self.recovery_action_transaction_id == self.transaction_id:
            raise ValueError("Recovery work requires a separate normalized transaction")
        if self.approval_required != (self.approval_id is not None):
            raise ValueError("Recovery work approval ID does not match approval requirement")
        reservation_bindings = (
            self.capability_reservation_digest,
            self.reservation_version,
        )
        if any(value is not None for value in reservation_bindings) and not all(
            value is not None for value in reservation_bindings
        ):
            raise ValueError("Recovery reservation digest and version must appear together")
        execution_bindings = (
            self.permit,
            self.permit_ref,
            self.lease_id,
            self.worker_id,
            self.fencing_token,
        )
        if any(value is not None for value in execution_bindings) and not all(
            value is not None for value in execution_bindings
        ):
            raise ValueError("Recovery execution bindings must be all present or all absent")
        if self.state is RecoveryWorkState.PENDING and any(
            value is not None for value in execution_bindings
        ):
            raise ValueError("Pending recovery work cannot carry a worker permit")
        if self.state is RecoveryWorkState.PENDING and (
            self.version != 0 or self.attempt != 0 or self.updated_at != self.created_at
        ):
            raise ValueError("Pending recovery work must be unclaimed version zero")
        if self.state is RecoveryWorkState.PENDING and (
            self.reservation_version is None or self.reservation_version % 2 != 0
        ):
            raise ValueError("Pending recovery work requires a reserved even version")
        if self.state is RecoveryWorkState.RUNNING and not all(
            value is not None for value in execution_bindings
        ):
            raise ValueError("Running recovery work requires a worker permit")
        if self.state is RecoveryWorkState.RUNNING and (self.version < 1 or self.attempt < 1):
            raise ValueError("Running recovery work must advance its claim and attempt")
        if self.permit is None and (
            self.reservation_version is not None and self.reservation_version % 2 != 0
        ):
            raise ValueError("Odd recovery reservation version requires its issued permit")
        if self.permit is not None and (
            self.tenant_id != self.permit.tenant_id
            or self.transaction_id != self.permit.transaction_id
            or self.intent_hash != self.permit.intent_hash
            or self.recovery_id != self.permit.recovery_id
            or self.recovery_action_transaction_id != self.permit.recovery_action_transaction_id
            or self.recovery_action_intent_hash != self.permit.recovery_action_intent_hash
            or self.recovery_action_digest != self.permit.recovery_action_digest
            or self.adapter_manifest_digest != self.permit.adapter_manifest_digest
            or self.kind is not self.permit.recovery_kind
            or self.target_id != self.permit.target_id
            or self.target_owner_version != self.permit.target_owner_version
            or self.target_owner_history_sequence != self.permit.target_owner_history_sequence
            or self.target_owner_history_digest != self.permit.target_owner_history_digest
            or self.target_evidence_ref != self.permit.target_evidence_ref
            or self.target_version_guard != self.permit.target_version_guard
            or self.authorization_round_id != self.permit.authorization_round_id
            or self.authorization_round_digest != self.permit.authorization_round_digest
            or self.authority_decision_digest != self.permit.authority_decision_digest
            or self.policy_decision_digest != self.permit.policy_decision_digest
            or self.policy_snapshot_digest != self.permit.policy_snapshot_digest
            or self.capability_reservation_digest != self.permit.capability_reservation_digest
            or self.reservation_version != self.permit.reservation_version
            or self.owner_version != self.permit.owner_version
            or self.owner_history_sequence != self.permit.owner_history_sequence
            or self.owner_history_digest != self.permit.owner_history_digest
            or self.approval_required != self.permit.approval_required
            or self.approval_id != self.permit.approval_id
            or self.approval_evidence_ref != self.permit.approval_evidence_ref
            or self.lease_id != self.permit.lease_id
            or self.worker_id != self.permit.worker_id
            or self.fencing_token != self.permit.fencing_token
            or self.permit.deadline > self.deadline
        ):
            raise ValueError("Recovery work and permit bindings differ")
        if self.permit is not None and self.permit.issued_at < self.created_at:
            raise ValueError("Recovery permit cannot predate its work item")
        if (
            self.state is RecoveryWorkState.RUNNING
            and self.permit is not None
            and not (self.permit.issued_at <= self.updated_at < self.permit.deadline)
        ):
            raise ValueError("Running recovery work must start while its permit is valid")
        if self.permit is not None and self.permit_ref != canonical_digest(self.permit):
            raise ValueError("Recovery permit artifact ref is inconsistent")
        if self.state is RecoveryWorkState.SUCCEEDED and (
            self.permit is None or not self.evidence_refs
        ):
            raise ValueError("Successful recovery requires a permit and durable evidence")
        if self.state is RecoveryWorkState.SUCCEEDED and (self.version < 2 or self.attempt < 1):
            raise ValueError("Successful recovery must advance a claimed work item")
        closed_states = {
            RecoveryWorkState.FAILED,
            RecoveryWorkState.RETRY_SCHEDULED,
            RecoveryWorkState.RETRIED,
            RecoveryWorkState.REVIEW_REQUIRED,
        }
        if self.state in closed_states and not (self.reason_code and self.evidence_refs):
            raise ValueError("Closed recovery work requires a reason and durable evidence")
        if self.state in closed_states:
            if self.permit is None and self.attempt != 0:
                raise ValueError("Unclaimed recovery denial cannot report an execution attempt")
            if self.permit is not None and (self.version < 2 or self.attempt < 1):
                raise ValueError("Executed recovery failure must advance a claimed work item")
        if self.state is RecoveryWorkState.RETRY_SCHEDULED and self.permit is None:
            raise ValueError("Scheduled recovery retry must retain its prior permit evidence")
        return self
