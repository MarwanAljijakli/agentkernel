from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from agentkernel.adapters.base import ReadOnlyContext
from agentkernel.canonical import canonical_digest, canonical_json_text
from agentkernel.domain.enums import (
    AuthorizationRoundPurpose,
    AuthorizationVerdict,
    CommitDispatchState,
    IntendedOutcome,
    LeasePurpose,
    ReconciliationOutcome,
    RecoveryWorkKind,
    RecoveryWorkState,
    ResourceAccessMode,
    ResourceUseKind,
    RiskClass,
    StageMaterialState,
    TransactionState,
)
from agentkernel.domain.models import (
    ActionProposal,
    AuthenticatedActionContext,
    NormalizedAction,
    ResourceUse,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.transactions import (
    AuthorizationRoundRecord,
    CommitDispatchRecord,
    CommitPermit,
    DispatchEvidenceUnavailableRecord,
    DispatchOutcomeRecord,
    EnforcedTransactionEvent,
    EnforcedTransactionRecord,
    InspectionPermit,
    LateRecoveryReportRecord,
    ReconciliationAttemptRecord,
    RecoveryCompletionReportRecord,
    RecoveryEvidenceUnavailableRecord,
    RecoveryPermit,
    RecoveryWorkRecord,
    StageMaterialRecord,
    StagePermit,
    TransactionRecoveryDeadlineRecord,
    TransitionEvent,
    WorkerLeaseRecord,
)
from pydantic import ValidationError

_NOW = datetime(2030, 1, 1, tzinfo=UTC)


def _digest(name: str) -> str:
    return canonical_digest({"contract": name})


def _inspection_subject() -> tuple[NormalizedAction, ActionProposal]:
    context = AuthenticatedActionContext(
        tenant_id="tenant:test",
        principal_id="principal:test",
        goal_id="goal:test",
        run_id="run:test",
        trace_id="trace:test",
        actor_id="service:coordinator",
        on_behalf_of="principal:test",
        agent_id="agent:test",
        configuration_digest=_digest("configuration"),
    )
    action = NormalizedAction.create(
        context=context,
        transaction_id="transaction:test",
        deadline=_NOW + timedelta(minutes=1),
        idempotency_key="idempotency:test",
        adapter="filesystem",
        adapter_version="0.1.0",
        adapter_manifest_digest=_digest("adapter"),
        operation="write_files",
        normalizer_implementation="normalizer.filesystem",
        normalizer_version="1.0.0",
        normalizer_digest=_digest("normalizer"),
        operation_schema_ref="agentkernel.test/WriteFiles",
        operation_schema_digest=_digest("operation-schema"),
        risk_floor=RiskClass.REVERSIBLE,
        effect_domains=("filesystem",),
        resource_uses=(
            ResourceUse(
                authority_action="fs.write",
                access_mode=ResourceAccessMode.WRITE,
                canonical_resource="fs://workspace/result.txt",
                effect_domain="filesystem",
                purpose="contract test",
                use_kind=ResourceUseKind.AUTHORITATIVE_EFFECT,
                destination_external=False,
            ),
        ),
    )
    proposal = ActionProposal(
        goal_id=action.goal_id,
        transaction_id=action.transaction_id,
        agent_id=action.agent_id,
        adapter=action.adapter,
        adapter_version=action.adapter_version,
        operation=action.operation,
        arguments={"path": "result.txt", "content": "test"},
        deadline=action.deadline,
        idempotency_key=action.idempotency_key,
    )
    return action, proposal


def _permit() -> CommitPermit:
    return CommitPermit.create(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        intent_hash=_digest("intent"),
        normalized_action_digest=_digest("action"),
        dispatch_id="dispatch:test",
        stage_id="stage:test",
        plan_digest=_digest("plan"),
        plan_ref=_digest("plan-artifact"),
        stage_permit_digest=_digest("stage-permit"),
        stage_permit_ref=_digest("stage-permit-artifact"),
        lease_id="lease:test",
        worker_id="worker:test",
        fencing_token=7,
        idempotency_key="idempotency:test",
        target_version_guard="version:before",
        staged_receipt_ref=_digest("staged-receipt"),
        staged_state_digest=_digest("staged-state"),
        staged_verification_permit_digest=_digest("staged-verification-permit"),
        staged_verification_permit_ref=_digest("staged-verification-permit-artifact"),
        staged_verification_ref=_digest("staged-verification"),
        precommit_inspection_permit_digest=_digest("precommit-inspection-permit"),
        precommit_inspection_permit_ref=_digest("precommit-inspection-permit-artifact"),
        precommit_plan_digest=_digest("precommit-plan"),
        precommit_plan_ref=_digest("precommit-plan-artifact"),
        approval_required=False,
        approval_evidence_ref=_digest("approval-not-required"),
        adapter_manifest_digest=_digest("adapter"),
        authority_decision_digest=_digest("authority"),
        policy_decision_digest=_digest("policy"),
        policy_snapshot_digest=_digest("policy-snapshot"),
        authorization_round_id="authorization-round:commit",
        authorization_round_digest=_digest("authorization-round:commit"),
        capability_reservation_digest=_digest("reservation"),
        reservation_version=3,
        owner_version=2,
        owner_history_sequence=4,
        owner_history_digest=_digest("owner-history"),
        issued_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )


def test_commit_permit_requires_consumed_reservation_version() -> None:
    permit = _permit().model_dump(mode="python")
    permit["reservation_version"] = 4
    with pytest.raises(ValidationError, match="committed odd"):
        CommitPermit.model_validate(permit)


def test_enforced_transaction_requires_atomic_authorization_binding() -> None:
    values = {
        "tenant_id": "tenant:test",
        "transaction_id": "transaction:test",
        "principal_id": "principal:test",
        "goal_id": "goal:test",
        "run_id": "run:test",
        "trace_id": "trace:test",
        "actor_id": "service:coordinator",
        "on_behalf_of": "principal:test",
        "agent_id": "agent:test",
        "request_digest": _digest("request"),
        "intent_hash": _digest("intent"),
        "normalized_action_digest": _digest("action"),
        "adapter": "filesystem",
        "operation": "write_files",
        "adapter_manifest_digest": _digest("adapter"),
        "state": TransactionState.AUTHORIZED_TO_STAGE,
        "version": 2,
        "deadline": _NOW + timedelta(minutes=2),
        "authority_decision_digest": _digest("authority"),
        "policy_decision_digest": _digest("policy"),
        "policy_snapshot_digest": _digest("policy-snapshot"),
        "authorization_round_id": "authorization-round:stage",
        "authorization_round_digest": _digest("authorization-round:stage"),
        "capability_reservation_digest": _digest("reservation"),
        "allowed_modes": ("read", "stage"),
        "obligations": ("shadow",),
        "created_at": _NOW,
        "updated_at": _NOW,
    }

    record = EnforcedTransactionRecord.model_validate(values)
    assert record.state is TransactionState.AUTHORIZED_TO_STAGE

    with pytest.raises(ValidationError, match="update precedes creation"):
        EnforcedTransactionRecord.model_validate(
            {**record.model_dump(mode="python"), "updated_at": _NOW - timedelta(seconds=1)}
        )

    with pytest.raises(ValidationError, match="Planning bindings must be all present"):
        EnforcedTransactionRecord.model_validate(
            {**record.model_dump(mode="python"), "operation": None}
        )

    new_with_authority = {
        **values,
        "intent_hash": None,
        "normalized_action_digest": None,
        "adapter": None,
        "operation": None,
        "adapter_manifest_digest": None,
        "deadline": None,
        "state": TransactionState.NEW,
        "version": 0,
    }
    with pytest.raises(ValidationError, match="NEW cannot carry authorization"):
        EnforcedTransactionRecord.model_validate(new_with_authority)

    with pytest.raises(ValidationError, match="NEW must be the unplanned version-zero"):
        EnforcedTransactionRecord.model_validate({**new_with_authority, "version": 1})

    unplanned = {
        **new_with_authority,
        "authority_decision_digest": None,
        "policy_decision_digest": None,
        "policy_snapshot_digest": None,
        "authorization_round_id": None,
        "authorization_round_digest": None,
        "capability_reservation_digest": None,
        "allowed_modes": (),
        "obligations": (),
    }
    with pytest.raises(ValidationError, match="Only NEW may have transaction version zero"):
        EnforcedTransactionRecord.model_validate(
            {**record.model_dump(mode="python"), "state": TransactionState.PLANNED, "version": 0}
        )
    with pytest.raises(ValidationError, match="requires complete planning bindings"):
        EnforcedTransactionRecord.model_validate(
            {**unplanned, "state": TransactionState.PLANNED, "version": 1}
        )
    with pytest.raises(ValidationError, match="STALE_STATE requires intended outcome"):
        EnforcedTransactionRecord.model_validate(
            {
                **record.model_dump(mode="python"),
                "state": TransactionState.STALE_STATE,
                "reason_code": "STALE_TARGET",
            }
        )
    with pytest.raises(ValidationError, match="Only abort-path transactions"):
        EnforcedTransactionRecord.model_validate(
            {
                **record.model_dump(mode="python"),
                "intended_outcome": IntendedOutcome.ABORTED,
            }
        )
    with pytest.raises(ValidationError, match="modes and obligations require complete"):
        EnforcedTransactionRecord.model_validate(
            {
                **unplanned,
                "state": TransactionState.PLANNED,
                "version": 1,
                "intent_hash": record.intent_hash,
                "normalized_action_digest": record.normalized_action_digest,
                "adapter": record.adapter,
                "operation": record.operation,
                "adapter_manifest_digest": record.adapter_manifest_digest,
                "deadline": record.deadline,
                "allowed_modes": ("stage",),
            }
        )
    with pytest.raises(ValidationError, match="requires complete authorization bindings"):
        EnforcedTransactionRecord.model_validate(
            {
                **record.model_dump(mode="python"),
                "authorization_round_id": None,
                "authorization_round_digest": None,
                "authority_decision_digest": None,
                "policy_decision_digest": None,
                "policy_snapshot_digest": None,
                "capability_reservation_digest": None,
                "allowed_modes": (),
                "obligations": (),
            }
        )

    del values["policy_decision_digest"]
    with pytest.raises(ValidationError, match="all present or all absent"):
        EnforcedTransactionRecord.model_validate(values)


def test_aborting_transaction_and_event_require_intended_outcome() -> None:
    record_values = {
        "tenant_id": "tenant:test",
        "transaction_id": "transaction:test",
        "principal_id": "principal:test",
        "goal_id": "goal:test",
        "run_id": "run:test",
        "trace_id": "trace:test",
        "actor_id": "service:coordinator",
        "on_behalf_of": "principal:test",
        "agent_id": "agent:test",
        "request_digest": _digest("request"),
        "intent_hash": _digest("intent"),
        "normalized_action_digest": _digest("action"),
        "adapter": "filesystem",
        "operation": "write_files",
        "adapter_manifest_digest": _digest("adapter"),
        "state": TransactionState.ABORTING,
        "version": 1,
        "deadline": _NOW + timedelta(minutes=1),
        "created_at": _NOW,
        "updated_at": _NOW,
    }
    with pytest.raises(ValidationError, match="intended outcome"):
        EnforcedTransactionRecord.model_validate(record_values)

    event_values = {
        "tenant_id": "tenant:test",
        "transaction_id": "transaction:test",
        "sequence": 1,
        "transaction_version": 1,
        "event_id": "event:test",
        "rule_id": "TX-003",
        "event": "control.cancelled",
        "source_state": TransactionState.NEW,
        "target_state": TransactionState.ABORTING,
        "actor_id": "service:coordinator",
        "on_behalf_of": "principal:test",
        "previous_event_digest": _digest("created-event"),
        "recorded_at": _NOW,
    }
    with pytest.raises(ValidationError, match="intended_outcome"):
        EnforcedTransactionEvent.create(**event_values)

    event = EnforcedTransactionEvent.create(
        **event_values,
        intended_outcome=IntendedOutcome.ABORTED,
    )
    assert event.event_digest == canonical_digest(event.digest_material())


def test_recovery_deadline_record_round_trips_through_public_json_contract() -> None:
    record = TransactionRecoveryDeadlineRecord(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        transaction_version=1,
        rule_id="TX-003",
        transition_event=TransitionEvent.CANCELLED,
        source_state=TransactionState.NEW,
        target_state=TransactionState.ABORTING,
        intended_outcome=IntendedOutcome.ABORTED,
        previous_event_digest=_digest("created-event"),
        absolute_deadline=_NOW + timedelta(minutes=4),
        recorded_at=_NOW,
    )

    restored = TransactionRecoveryDeadlineRecord.model_validate_json(record.model_dump_json())

    assert restored == record
    assert restored.api_version == "agentkernel.io/v1alpha1"
    assert restored.transition_event is TransitionEvent.CANCELLED


def test_durable_new_precedes_normalization_and_has_atomic_creation_event() -> None:
    record = EnforcedTransactionRecord(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        principal_id="principal:test",
        goal_id="goal:test",
        run_id="run:test",
        trace_id="trace:test",
        actor_id="service:coordinator",
        on_behalf_of="principal:test",
        agent_id="agent:test",
        request_digest=_digest("untrusted-request"),
        state=TransactionState.NEW,
        version=0,
        created_at=_NOW,
        updated_at=_NOW,
    )
    assert record.intent_hash is None
    assert record.deadline is None

    event = EnforcedTransactionEvent.create(
        tenant_id=record.tenant_id,
        transaction_id=record.transaction_id,
        sequence=0,
        transaction_version=0,
        event_id="event:created",
        rule_id="TX-CREATE",
        event="transaction.created",
        source_state=None,
        target_state=TransactionState.NEW,
        actor_id=record.actor_id,
        on_behalf_of=record.on_behalf_of,
        recorded_at=_NOW,
    )
    assert event.event_digest == canonical_digest(event.digest_material())

    invalid = event.model_dump(mode="python")
    invalid["source_state"] = TransactionState.NEW
    invalid["event_digest"] = _digest("forged")
    with pytest.raises(ValidationError, match="establish NEW at version zero"):
        EnforcedTransactionEvent.model_validate(invalid)


def test_recovery_failed_preserves_abort_intended_outcome() -> None:
    record = EnforcedTransactionRecord(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        principal_id="principal:test",
        goal_id="goal:test",
        run_id="run:test",
        trace_id="trace:test",
        actor_id="service:coordinator",
        on_behalf_of="principal:test",
        agent_id="agent:test",
        request_digest=_digest("request"),
        state=TransactionState.RECOVERY_FAILED,
        version=2,
        intended_outcome=IntendedOutcome.ABORTED,
        reason_code="STAGING_DISCARD_FAILED",
        created_at=_NOW,
        updated_at=_NOW,
    )
    assert record.intended_outcome is IntendedOutcome.ABORTED


def test_terminal_outcomes_and_failures_require_exact_durable_classification() -> None:
    values = {
        "tenant_id": "tenant:test",
        "transaction_id": "transaction:test",
        "principal_id": "principal:test",
        "goal_id": "goal:test",
        "run_id": "run:test",
        "trace_id": "trace:test",
        "actor_id": "service:coordinator",
        "on_behalf_of": "principal:test",
        "agent_id": "agent:test",
        "request_digest": _digest("request"),
        "state": TransactionState.ABORTED,
        "version": 2,
        "created_at": _NOW,
        "updated_at": _NOW,
    }
    with pytest.raises(ValidationError, match="ABORTED requires"):
        EnforcedTransactionRecord.model_validate(values)

    rejected = {**values, "state": TransactionState.REJECTED}
    with pytest.raises(ValidationError, match="stable reason code"):
        EnforcedTransactionRecord.model_validate(rejected)


def test_transaction_event_rejects_digest_tampering() -> None:
    event = EnforcedTransactionEvent.create(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        sequence=1,
        transaction_version=1,
        event_id="event:test",
        rule_id="TX-001",
        event="proposal.valid",
        source_state=TransactionState.NEW,
        target_state=TransactionState.PLANNED,
        actor_id="service:coordinator",
        on_behalf_of="principal:test",
        previous_event_digest=_digest("created-event"),
        recorded_at=_NOW,
    )
    payload = event.model_dump(mode="python")
    payload["rule_id"] = "TX-forged"
    with pytest.raises(ValidationError, match="not normative"):
        EnforcedTransactionEvent.model_validate(payload)

    payload = event.model_dump(mode="python")
    payload["recorded_at"] = _NOW + timedelta(seconds=1)
    with pytest.raises(ValidationError, match="digest mismatch"):
        EnforcedTransactionEvent.model_validate(payload)

    with pytest.raises(ValidationError, match="normative transaction"):
        EnforcedTransactionEvent.create(
            tenant_id="tenant:test",
            transaction_id="transaction:test",
            sequence=2,
            transaction_version=2,
            event_id="event:impossible",
            rule_id="TX-forged",
            event="proposal.valid",
            source_state=TransactionState.COMMITTED,
            target_state=TransactionState.PLANNED,
            actor_id="service:coordinator",
            on_behalf_of="principal:test",
            previous_event_digest=event.event_digest,
            recorded_at=_NOW,
        )


def test_worker_lease_and_stage_material_are_fence_bound() -> None:
    lease = WorkerLeaseRecord(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        lease_id="lease:test",
        worker_id="worker:test",
        purpose=LeasePurpose.STAGING,
        fencing_token=7,
        version=0,
        acquired_at=_NOW,
        expires_at=_NOW + timedelta(seconds=30),
    )
    assert lease.fencing_token == 7

    with pytest.raises(ValidationError, match="expire after acquisition"):
        WorkerLeaseRecord.model_validate(
            {**lease.model_dump(mode="python"), "expires_at": lease.acquired_at}
        )
    with pytest.raises(ValidationError, match="release precedes acquisition"):
        WorkerLeaseRecord.model_validate(
            {
                **lease.model_dump(mode="python"),
                "released_at": lease.acquired_at - timedelta(seconds=1),
                "version": 1,
            }
        )

    released_without_version_advance = lease.model_dump(mode="python")
    released_without_version_advance["released_at"] = _NOW + timedelta(seconds=1)
    with pytest.raises(ValidationError, match="released worker lease"):
        WorkerLeaseRecord.model_validate(released_without_version_advance)

    material = StageMaterialRecord(
        tenant_id=lease.tenant_id,
        transaction_id=lease.transaction_id,
        stage_id="stage:test",
        lease_id=lease.lease_id,
        fencing_token=lease.fencing_token,
        intent_hash=_digest("intent"),
        normalized_action_digest=_digest("action"),
        adapter_manifest_digest=_digest("adapter"),
        plan_digest=_digest("plan"),
        plan_ref=_digest("plan-artifact"),
        inspection_permit_digest=_digest("inspection-permit"),
        inspection_permit_ref=_digest("inspection-permit-artifact"),
        stage_permit_digest=_digest("stage-permit"),
        stage_permit_ref=_digest("stage-permit-artifact"),
        state=StageMaterialState.VERIFIED,
        base_state_digest=_digest("before"),
        target_version_guard="version:before",
        staged_effect_ref=_digest("staged-effect"),
        staged_receipt_ref=_digest("staged-receipt"),
        staged_state_digest=_digest("staged-state"),
        verification_permit_digest=_digest("verification-permit"),
        verification_permit_ref=_digest("verification-permit-artifact"),
        verification_ref=_digest("verification"),
        version=3,
        created_at=_NOW,
        updated_at=_NOW,
    )
    assert material.lease_id == lease.lease_id

    with pytest.raises(ValidationError, match="update precedes creation"):
        StageMaterialRecord.model_validate(
            {**material.model_dump(mode="python"), "updated_at": _NOW - timedelta(seconds=1)}
        )
    with pytest.raises(ValidationError, match="Base-state and staged-effect"):
        StageMaterialRecord.model_validate(
            {**material.model_dump(mode="python"), "base_state_digest": None}
        )
    with pytest.raises(ValidationError, match="receipt requires staged-effect"):
        StageMaterialRecord.model_validate(
            {
                **material.model_dump(mode="python"),
                "base_state_digest": None,
                "staged_effect_ref": None,
            }
        )
    with pytest.raises(ValidationError, match="verification and its permit"):
        StageMaterialRecord.model_validate(
            {
                **material.model_dump(mode="python"),
                "verification_permit_ref": None,
            }
        )

    no_receipt_or_verification = {
        "staged_receipt_ref": None,
        "staged_state_digest": None,
        "verification_permit_digest": None,
        "verification_permit_ref": None,
        "verification_ref": None,
    }
    with pytest.raises(ValidationError, match="Allocated stage material"):
        StageMaterialRecord.model_validate(
            {
                **material.model_dump(mode="python"),
                **no_receipt_or_verification,
                "state": StageMaterialState.ALLOCATED,
                "version": 0,
            }
        )
    with pytest.raises(ValidationError, match="STAGED requires exactly"):
        StageMaterialRecord.model_validate(
            {
                **material.model_dump(mode="python"),
                **no_receipt_or_verification,
                "state": StageMaterialState.STAGED,
                "base_state_digest": None,
                "staged_effect_ref": None,
                "version": 1,
            }
        )
    with pytest.raises(ValidationError, match="EXECUTED requires exact"):
        StageMaterialRecord.model_validate(
            {
                **material.model_dump(mode="python"),
                **no_receipt_or_verification,
                "state": StageMaterialState.EXECUTED,
                "version": 2,
            }
        )
    with pytest.raises(ValidationError, match="VERIFIED requires exact"):
        StageMaterialRecord.model_validate(
            {
                **material.model_dump(mode="python"),
                "verification_permit_digest": None,
                "verification_permit_ref": None,
                "verification_ref": None,
            }
        )
    with pytest.raises(ValidationError, match="Discard outcome requires durable evidence"):
        StageMaterialRecord.model_validate(
            {
                **material.model_dump(mode="python"),
                "state": StageMaterialState.DISCARDED,
                "version": 4,
            }
        )

    verified_at_version_zero = material.model_dump(mode="python")
    verified_at_version_zero["version"] = 0
    with pytest.raises(ValidationError, match="VERIFIED stage material requires version 3"):
        StageMaterialRecord.model_validate(verified_at_version_zero)

    premature_verified_discard = material.model_dump(mode="python")
    premature_verified_discard.update(
        {
            "state": StageMaterialState.DISCARDED,
            "discard_evidence_ref": _digest("discard"),
            "version": 1,
        }
    )
    with pytest.raises(ValidationError, match="cannot precede its retained stage evidence"):
        StageMaterialRecord.model_validate(premature_verified_discard)
    premature_verified_discard["version"] = 4
    assert (
        StageMaterialRecord.model_validate(premature_verified_discard).state
        is StageMaterialState.DISCARDED
    )

    payload = material.model_dump(mode="python")
    payload["staged_receipt_ref"] = None
    with pytest.raises(ValidationError, match="must appear together"):
        StageMaterialRecord.model_validate(payload)

    allocated = material.model_dump(mode="python")
    allocated.update(
        {
            "state": StageMaterialState.ALLOCATED,
            "base_state_digest": None,
            "staged_effect_ref": None,
            "staged_receipt_ref": None,
            "staged_state_digest": None,
            "verification_ref": _digest("premature-verification"),
            "version": 0,
        }
    )
    with pytest.raises(ValidationError, match=r"Allocated|requires executed-stage"):
        StageMaterialRecord.model_validate(allocated)

    noncanonical_guard = material.model_dump(mode="python")
    noncanonical_guard["target_version_guard"] = "cafe\u0301"
    with pytest.raises(ValidationError, match="Unicode NFC"):
        StageMaterialRecord.model_validate(noncanonical_guard)


def test_fence_and_version_integers_are_strict() -> None:
    values = {
        "tenant_id": "tenant:test",
        "transaction_id": "transaction:test",
        "lease_id": "lease:test",
        "worker_id": "worker:test",
        "purpose": LeasePurpose.STAGING,
        "fencing_token": True,
        "version": 0,
        "acquired_at": _NOW,
        "expires_at": _NOW + timedelta(seconds=30),
    }
    with pytest.raises(ValidationError, match="valid integer"):
        WorkerLeaseRecord.model_validate(values)

    values["fencing_token"] = 1
    values["version"] = "0"
    with pytest.raises(ValidationError, match="valid integer"):
        WorkerLeaseRecord.model_validate(values)

    values["version"] = 0
    values["fencing_token"] = 1 << 63
    with pytest.raises(ValidationError, match="less than or equal"):
        WorkerLeaseRecord.model_validate(values)


def test_stage_permit_binds_plan_stage_worker_and_fence() -> None:
    permit = StagePermit.create(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        intent_hash=_digest("intent"),
        normalized_action_digest=_digest("action"),
        adapter_manifest_digest=_digest("adapter"),
        authorization_round_id="authorization-round:stage",
        authorization_round_digest=_digest("authorization-round:stage"),
        inspection_permit_digest=_digest("inspection-permit"),
        inspection_permit_ref=_digest("inspection-permit-artifact"),
        plan_digest=_digest("plan"),
        plan_ref=_digest("plan-artifact"),
        stage_id="stage:test",
        lease_id="lease:test",
        worker_id="worker:test",
        fencing_token=7,
        target_version_guard="version:before",
        issued_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )
    assert permit.permit_digest == canonical_digest(permit.digest_material())

    payload = permit.model_dump(mode="python")
    payload["plan_digest"] = _digest("other-plan")
    with pytest.raises(ValidationError, match="digest mismatch"):
        StagePermit.model_validate(payload)

    payload = permit.model_dump(mode="python")
    payload["target_version_guard"] = "cafe\u0301"
    with pytest.raises(ValidationError, match="Unicode NFC"):
        StagePermit.model_validate(payload)

    oversized = permit.model_dump(mode="python", exclude={"permit_digest"})
    oversized["target_version_guard"] = "x" * 513
    with pytest.raises(AgentKernelError, match="oversized scalar") as captured:
        StagePermit.create(**oversized)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    class SneakyString(str):
        def __len__(self) -> int:
            return 0

    custom_scalar = permit.model_dump(mode="python", exclude={"permit_digest"})
    custom_scalar["target_version_guard"] = SneakyString("version:forged")
    with pytest.raises(AgentKernelError, match="built-in scalar") as captured:
        StagePermit.create(**custom_scalar)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_digest_creator_rejects_oversized_evidence_before_hashing() -> None:
    evidence = tuple(_digest(f"evidence-{index}") for index in range(257))
    with pytest.raises(AgentKernelError, match="sequence exceeds") as captured:
        EnforcedTransactionEvent.create(
            tenant_id="tenant:test",
            transaction_id="transaction:test",
            sequence=1,
            transaction_version=1,
            event_id="event:test",
            rule_id="TX-001",
            event="proposal.valid",
            source_state=TransactionState.NEW,
            target_state=TransactionState.PLANNED,
            intended_outcome=None,
            actor_id="service:coordinator",
            on_behalf_of="principal:test",
            evidence_refs=evidence,
            previous_event_digest=_digest("previous"),
            recorded_at=_NOW,
        )
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_inspection_permit_closes_the_pre_inspect_authority_gap() -> None:
    action, proposal = _inspection_subject()
    permit = InspectionPermit.create(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        intent_hash=action.intent_hash,
        normalized_action_digest=canonical_digest(action),
        proposal_ref=canonical_digest(proposal),
        adapter_manifest_digest=_digest("adapter"),
        authorization_round_id="authorization-round:stage",
        authorization_round_digest=_digest("authorization-round:stage"),
        lease_id="lease:test",
        worker_id="worker:test",
        fencing_token=7,
        issued_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )
    context = ReadOnlyContext(
        deadline=permit.deadline,
        worker_id=permit.worker_id,
        permit=permit,
        permit_ref=canonical_digest(permit),
        normalized_action=action,
        normalized_action_ref=canonical_digest(action),
        proposal=proposal,
        proposal_ref=canonical_digest(proposal),
    )
    assert context.permit is permit

    with pytest.raises(ValueError, match="differ"):
        ReadOnlyContext(
            deadline=permit.deadline,
            worker_id="worker:other",
            permit=permit,
            permit_ref=canonical_digest(permit),
            normalized_action=action,
            normalized_action_ref=canonical_digest(action),
            proposal=proposal,
            proposal_ref=canonical_digest(proposal),
        )

    forged = InspectionPermit.model_construct(
        **{
            **permit.model_dump(mode="python"),
            "fencing_token": True,
        }
    )
    with pytest.raises(ValidationError):
        ReadOnlyContext(
            deadline=forged.deadline,
            worker_id=forged.worker_id,
            permit=forged,
            permit_ref=canonical_digest(forged),
            normalized_action=action,
            normalized_action_ref=canonical_digest(action),
            proposal=proposal,
            proposal_ref=canonical_digest(proposal),
        )


def test_authorization_round_links_wrapper_and_inner_decision_digests() -> None:
    round_record = AuthorizationRoundRecord.create(
        tenant_id="tenant:test",
        controlled_transaction_id="transaction:test",
        subject_transaction_id="transaction:test",
        subject_intent_hash=_digest("intent"),
        subject_normalized_action_digest=_digest("action"),
        round_id="authorization-round:stage",
        purpose=AuthorizationRoundPurpose.STAGING,
        verdict=AuthorizationVerdict.ELIGIBLE,
        authority_snapshot_id="authority-snapshot:test",
        authority_snapshot_digest=_digest("authority-snapshot"),
        authority_snapshot_ref=_digest("authority-snapshot-artifact"),
        authority_context_ref=_digest("authority-context-artifact"),
        authority_decision_id="authority-decision:test",
        authority_decision_record_digest=_digest("authority-record"),
        authority_decision_digest=_digest("authority-inner"),
        authority_decision_ref=_digest("authority-decision-artifact"),
        policy_decision_id="policy-decision:test",
        policy_decision_record_digest=_digest("policy-record"),
        policy_decision_digest=_digest("policy-inner"),
        policy_inputs_ref=_digest("policy-inputs-artifact"),
        policy_snapshot_digest=_digest("policy-snapshot"),
        policy_snapshot_ref=_digest("policy-snapshot-artifact"),
        policy_decision_ref=_digest("policy-decision-artifact"),
        capability_reservation_plan_digest=_digest("reservation-plan"),
        capability_reservation_digest=_digest("reservation"),
        reservation_version=0,
        reservation_goal_id="goal:test",
        reservation_run_id="run:test",
        owner_version=0,
        owner_history_sequence=0,
        owner_history_digest=_digest("owner-history"),
        allowed_modes=("read", "stage"),
        obligations=("shadow",),
        reason_code="ELIGIBLE",
        evaluated_at=_NOW,
        authority_valid_until=_NOW + timedelta(minutes=1),
    )
    assert round_record.round_digest == canonical_digest(round_record.digest_material())

    uncommitted_round = round_record.model_dump(mode="python")
    uncommitted_round["reservation_version"] = 1
    with pytest.raises(ValidationError, match="reserved even"):
        AuthorizationRoundRecord.model_validate(uncommitted_round)

    forged = round_record.model_dump(mode="python")
    forged["authority_decision_digest"] = _digest("forged")
    with pytest.raises(ValidationError, match="digest mismatch"):
        AuthorizationRoundRecord.model_validate(forged)

    invalid_recovery = round_record.model_dump(mode="python")
    invalid_recovery["purpose"] = AuthorizationRoundPurpose.RECOVERY
    invalid_recovery["round_digest"] = _digest("forged")
    with pytest.raises(ValidationError, match="separate normalized action"):
        AuthorizationRoundRecord.model_validate(invalid_recovery)

    baseline = round_record.model_dump(mode="python")
    with pytest.raises(ValidationError, match="must evaluate the transaction"):
        AuthorizationRoundRecord.model_validate(
            {**baseline, "controlled_transaction_id": "transaction:other"}
        )
    with pytest.raises(ValidationError, match="reservation bindings must be all present"):
        AuthorizationRoundRecord.model_validate({**baseline, "reservation_run_id": None})

    reservation_fields = {
        "capability_reservation_plan_digest": None,
        "capability_reservation_digest": None,
        "reservation_version": None,
        "reservation_goal_id": None,
        "reservation_run_id": None,
    }
    with pytest.raises(ValidationError, match="requires a durable reservation fence"):
        AuthorizationRoundRecord.model_validate({**baseline, **reservation_fields})
    with pytest.raises(ValidationError, match="cannot carry a capability reservation"):
        AuthorizationRoundRecord.model_validate(
            {**baseline, "verdict": AuthorizationVerdict.DENIED}
        )
    with pytest.raises(ValidationError, match="at least one allowed mode"):
        AuthorizationRoundRecord.model_validate({**baseline, "allowed_modes": ()})
    with pytest.raises(ValidationError, match="cannot carry allowed modes"):
        AuthorizationRoundRecord.model_validate(
            {
                **baseline,
                **reservation_fields,
                "verdict": AuthorizationVerdict.DENIED,
                "authority_valid_until": None,
            }
        )

    artifact_fields = (
        "authority_snapshot_ref",
        "authority_context_ref",
        "authority_decision_ref",
        "policy_inputs_ref",
        "policy_snapshot_ref",
        "policy_decision_ref",
    )
    legacy_values = {
        **round_record.model_dump(mode="python", exclude={"round_digest"}),
        "schema_version": "1.0",
        "authority_valid_until": None,
        **dict.fromkeys(artifact_fields),
    }
    legacy_round = AuthorizationRoundRecord.create(**legacy_values)
    assert legacy_round.schema_version == "1.0"

    with pytest.raises(ValidationError, match="Legacy authorization rounds"):
        AuthorizationRoundRecord.model_validate(
            {**baseline, "schema_version": "1.0", "authority_valid_until": None}
        )
    with pytest.raises(ValidationError, match="discoverable evidence artifacts"):
        AuthorizationRoundRecord.model_validate({**baseline, "policy_inputs_ref": None})
    with pytest.raises(ValidationError, match="not evidence artifact references"):
        AuthorizationRoundRecord.model_validate(
            {**baseline, "authority_snapshot_ref": round_record.authority_snapshot_digest}
        )
    with pytest.raises(ValidationError, match="future authority window"):
        AuthorizationRoundRecord.model_validate({**baseline, "authority_valid_until": _NOW})
    with pytest.raises(ValidationError, match="cannot grant an authority window"):
        AuthorizationRoundRecord.model_validate(
            {
                **baseline,
                **reservation_fields,
                "verdict": AuthorizationVerdict.DENIED,
                "allowed_modes": (),
            }
        )
    with pytest.raises(ValidationError, match="sorted and unique"):
        AuthorizationRoundRecord.model_validate({**baseline, "allowed_modes": ("stage", "read")})
    with pytest.raises(ValidationError, match=r"valid (?:UTF-8|string)"):
        AuthorizationRoundRecord.model_validate({**baseline, "obligations": ("\ud800",)})


def test_commit_permit_binds_every_precommit_guard_and_rejects_tampering() -> None:
    permit = _permit()
    assert permit.permit_digest == canonical_digest(permit.digest_material())
    assert canonical_digest({"value": "caf\u00e9"}) == canonical_digest({"value": "cafe\u0301"})

    payload = permit.model_dump(mode="python")
    payload["fencing_token"] = 8
    with pytest.raises(ValidationError, match="digest mismatch"):
        CommitPermit.model_validate(payload)

    for field in ("idempotency_key", "target_version_guard"):
        payload = permit.model_dump(mode="python")
        payload[field] = "cafe\u0301"
        with pytest.raises(ValidationError, match="Unicode NFC"):
            CommitPermit.model_validate(payload)


def test_dispatch_requires_matching_permit_and_authoritative_outcome_evidence() -> None:
    permit = _permit()
    dispatch = CommitDispatchRecord(
        tenant_id=permit.tenant_id,
        transaction_id=permit.transaction_id,
        intent_hash=permit.intent_hash,
        dispatch_id=permit.dispatch_id,
        owner_version=permit.owner_version,
        permit=permit,
        permit_ref=canonical_digest(permit),
        state=CommitDispatchState.DISPATCHED,
        version=0,
        created_at=_NOW,
        updated_at=_NOW,
    )
    assert dispatch.effect_receipt_ref is None

    committed = dispatch.model_copy(
        update={
            "state": CommitDispatchState.COMMITTED,
            "effect_receipt_ref": _digest("effect-receipt"),
            "committed_verification_permit_digest": _digest("committed-verification-permit"),
            "committed_verification_permit_ref": _digest("committed-verification-permit-artifact"),
            "committed_verification_ref": _digest("committed-verification"),
            "outcome_evidence_refs": (_digest("commit-observation"),),
            "version": 1,
        }
    )
    committed = CommitDispatchRecord.model_validate(committed.model_dump(mode="python"))
    assert committed.state is CommitDispatchState.COMMITTED

    in_doubt_with_receipt = CommitDispatchRecord.model_validate(
        {
            **dispatch.model_dump(mode="python"),
            "state": CommitDispatchState.IN_DOUBT,
            "effect_receipt_ref": _digest("unverified-effect-receipt"),
            "outcome_evidence_refs": (_digest("ambiguous-observation"),),
            "version": 1,
        }
    )
    assert in_doubt_with_receipt.effect_receipt_ref is not None

    with pytest.raises(ValidationError, match="artifact ref is inconsistent"):
        CommitDispatchRecord.model_validate(
            {**dispatch.model_dump(mode="python"), "permit_ref": _digest("forged-permit-ref")}
        )
    with pytest.raises(ValidationError, match="update precedes creation"):
        CommitDispatchRecord.model_validate(
            {**dispatch.model_dump(mode="python"), "updated_at": _NOW - timedelta(seconds=1)}
        )
    with pytest.raises(ValidationError, match="requires an effect receipt"):
        CommitDispatchRecord.model_validate(
            {**committed.model_dump(mode="python"), "effect_receipt_ref": None}
        )
    with pytest.raises(ValidationError, match="requires committed-state verification"):
        CommitDispatchRecord.model_validate(
            {**committed.model_dump(mode="python"), "committed_verification_ref": None}
        )

    classified = {
        **dispatch.model_dump(mode="python"),
        "state": CommitDispatchState.IN_DOUBT,
        "version": 1,
        "outcome_evidence_refs": (_digest("ambiguous-observation"),),
    }
    with pytest.raises(ValidationError, match="verification and its permit"):
        CommitDispatchRecord.model_validate(
            {**classified, "committed_verification_permit_digest": _digest("partial-verification")}
        )
    with pytest.raises(ValidationError, match="both committed and no-effect"):
        CommitDispatchRecord.model_validate(
            {
                **classified,
                "effect_receipt_ref": _digest("receipt"),
                "no_effect_evidence_ref": _digest("absence"),
            }
        )
    with pytest.raises(ValidationError, match="newly dispatched record"):
        CommitDispatchRecord.model_validate(
            {
                **dispatch.model_dump(mode="python"),
                "outcome_evidence_refs": (_digest("premature-outcome"),),
            }
        )
    with pytest.raises(ValidationError, match="pending receipt observation"):
        CommitDispatchRecord.model_validate({**dispatch.model_dump(mode="python"), "version": 1})
    with pytest.raises(ValidationError, match="classified dispatch requires durable"):
        CommitDispatchRecord.model_validate(
            {
                **dispatch.model_dump(mode="python"),
                "state": CommitDispatchState.IN_DOUBT,
                "version": 1,
            }
        )
    with pytest.raises(ValidationError, match="Unavailable dispatch evidence must be typed"):
        CommitDispatchRecord.model_validate(
            {
                **dispatch.model_dump(mode="python"),
                "unavailable_record_digest": _digest("unavailable-record"),
            }
        )
    with pytest.raises(ValidationError, match="Only a committed dispatch"):
        CommitDispatchRecord.model_validate(
            {
                **classified,
                "committed_verification_permit_digest": _digest("verification-permit"),
                "committed_verification_permit_ref": _digest("verification-permit-artifact"),
                "committed_verification_ref": _digest("verification"),
            }
        )
    with pytest.raises(ValidationError, match="Only a no-effect dispatch"):
        CommitDispatchRecord.model_validate(
            {**classified, "no_effect_evidence_ref": _digest("unexpected-absence")}
        )

    invalid = dispatch.model_dump(mode="python")
    invalid["tenant_id"] = "tenant:other"
    with pytest.raises(ValidationError, match="identities differ"):
        CommitDispatchRecord.model_validate(invalid)

    invalid = dispatch.model_dump(mode="python")
    invalid["state"] = CommitDispatchState.NO_EFFECT
    invalid["version"] = 1
    with pytest.raises(ValidationError, match="absence evidence"):
        CommitDispatchRecord.model_validate(invalid)

    invalid = committed.model_dump(mode="python")
    invalid["version"] = 0
    with pytest.raises(ValidationError, match="advance version zero"):
        CommitDispatchRecord.model_validate(invalid)

    invalid = dispatch.model_dump(mode="python")
    invalid["created_at"] = permit.deadline
    invalid["updated_at"] = permit.deadline
    with pytest.raises(ValidationError, match="while its permit is valid"):
        CommitDispatchRecord.model_validate(invalid)

    forged_values = permit.model_dump(mode="python")
    forged_values["fencing_token"] = True
    forged_unsigned = CommitPermit.model_construct(**forged_values)
    forged_values["permit_digest"] = canonical_digest(forged_unsigned.digest_material())
    forged_permit = CommitPermit.model_construct(**forged_values)
    invalid = dispatch.model_dump(mode="python")
    invalid["permit"] = forged_permit
    invalid["permit_ref"] = canonical_digest(forged_permit)
    with pytest.raises(ValidationError, match="valid integer"):
        CommitDispatchRecord.model_validate(invalid)


def test_dispatch_outcome_chain_binds_each_authoritative_classification() -> None:
    initial = DispatchOutcomeRecord.create(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        intent_hash=_digest("intent"),
        owner_version=2,
        dispatch_id="dispatch:test",
        sequence=0,
        outcome_id="outcome:dispatched",
        source_state=None,
        target_state=CommitDispatchState.DISPATCHED,
        evidence_refs=(_digest("commit-permit-artifact"),),
        recorded_at=_NOW,
    )
    assert initial.outcome_digest == canonical_digest(initial.digest_material())

    committed = DispatchOutcomeRecord.create(
        tenant_id=initial.tenant_id,
        transaction_id=initial.transaction_id,
        intent_hash=initial.intent_hash,
        owner_version=initial.owner_version,
        dispatch_id=initial.dispatch_id,
        sequence=1,
        outcome_id="outcome:committed",
        source_state=CommitDispatchState.DISPATCHED,
        target_state=CommitDispatchState.COMMITTED,
        classification=ReconciliationOutcome.COMMITTED,
        effect_receipt_ref=_digest("effect-receipt"),
        committed_verification_permit_digest=_digest("committed-verification-permit"),
        committed_verification_permit_ref=_digest("committed-verification-permit-artifact"),
        committed_verification_ref=_digest("committed-verification"),
        evidence_refs=(_digest("commit-observation"),),
        previous_outcome_digest=initial.outcome_digest,
        recorded_at=_NOW + timedelta(seconds=1),
    )
    assert committed.classification is ReconciliationOutcome.COMMITTED

    partial_with_receipt = DispatchOutcomeRecord.create(
        tenant_id=initial.tenant_id,
        transaction_id=initial.transaction_id,
        intent_hash=initial.intent_hash,
        owner_version=initial.owner_version,
        dispatch_id=initial.dispatch_id,
        sequence=1,
        outcome_id="outcome:partial",
        source_state=CommitDispatchState.DISPATCHED,
        target_state=CommitDispatchState.PARTIAL_OR_INVALID,
        classification=ReconciliationOutcome.PARTIAL_OR_INVALID,
        effect_receipt_ref=_digest("unverified-effect-receipt"),
        evidence_refs=(_digest("partial-observation"),),
        reason_code="COMMITTED_VERIFICATION_FAILED",
        previous_outcome_digest=initial.outcome_digest,
        recorded_at=_NOW + timedelta(seconds=1),
    )
    assert partial_with_receipt.effect_receipt_ref is not None

    with pytest.raises(ValidationError, match="Initial dispatch outcome"):
        DispatchOutcomeRecord.model_validate(
            {
                **initial.model_dump(mode="python"),
                "source_state": CommitDispatchState.DISPATCHED,
            }
        )
    with pytest.raises(ValidationError, match="hash-chain source"):
        DispatchOutcomeRecord.model_validate(
            {**committed.model_dump(mode="python"), "source_state": None}
        )

    illegal_unclassified = {
        **committed.model_dump(mode="python"),
        "target_state": CommitDispatchState.COMMITTED,
        "classification": None,
        "effect_receipt_ref": None,
        "committed_verification_permit_digest": None,
        "committed_verification_permit_ref": None,
        "committed_verification_ref": None,
    }
    with pytest.raises(ValidationError, match="Unclassified dispatch observation"):
        DispatchOutcomeRecord.model_validate(illegal_unclassified)
    with pytest.raises(ValidationError, match="requires receipt and verification"):
        DispatchOutcomeRecord.model_validate(
            {**committed.model_dump(mode="python"), "effect_receipt_ref": None}
        )
    with pytest.raises(ValidationError, match="requires authoritative absence evidence"):
        DispatchOutcomeRecord.model_validate(
            {
                **committed.model_dump(mode="python"),
                "target_state": CommitDispatchState.NO_EFFECT,
                "classification": ReconciliationOutcome.NO_EFFECT,
                "effect_receipt_ref": None,
                "committed_verification_permit_digest": None,
                "committed_verification_permit_ref": None,
                "committed_verification_ref": None,
            }
        )
    with pytest.raises(ValidationError, match="cannot carry verification or absence"):
        DispatchOutcomeRecord.model_validate(
            {
                **partial_with_receipt.model_dump(mode="python"),
                "committed_verification_permit_digest": _digest("verification-permit"),
                "committed_verification_permit_ref": _digest("verification-permit-artifact"),
                "committed_verification_ref": _digest("verification"),
            }
        )
    unavailable_ref = _digest("typed-unavailability")
    with pytest.raises(ValidationError, match="typed UNKNOWN classification"):
        DispatchOutcomeRecord.model_validate(
            {
                **partial_with_receipt.model_dump(mode="python"),
                "target_state": CommitDispatchState.IN_DOUBT,
                "classification": ReconciliationOutcome.UNKNOWN,
                "unavailable_record_digest": unavailable_ref,
                "evidence_refs": (unavailable_ref,),
            }
        )
    with pytest.raises(ValidationError, match="requires evidence or typed unavailability"):
        DispatchOutcomeRecord.model_validate(
            {**partial_with_receipt.model_dump(mode="python"), "evidence_refs": ()}
        )
    with pytest.raises(ValidationError, match="digest mismatch"):
        DispatchOutcomeRecord.model_validate(
            {**initial.model_dump(mode="python"), "outcome_digest": _digest("forged-outcome")}
        )

    forged = committed.model_dump(mode="python")
    forged["target_state"] = CommitDispatchState.NO_EFFECT
    with pytest.raises(ValidationError, match="classification"):
        DispatchOutcomeRecord.model_validate(forged)

    terminal_rewrite = committed.model_dump(mode="python")
    terminal_rewrite.update(
        {
            "sequence": 2,
            "outcome_id": "outcome:rewritten",
            "source_state": CommitDispatchState.COMMITTED,
            "target_state": CommitDispatchState.NO_EFFECT,
            "classification": ReconciliationOutcome.NO_EFFECT,
            "effect_receipt_ref": None,
            "committed_verification_ref": None,
            "no_effect_evidence_ref": _digest("false-absence"),
            "previous_outcome_digest": committed.outcome_digest,
            "outcome_digest": _digest("forged"),
        }
    )
    with pytest.raises(ValidationError, match="cannot be reclassified"):
        DispatchOutcomeRecord.model_validate(terminal_rewrite)


def test_recovery_completion_report_binds_exact_operation_evidence() -> None:
    refs = tuple(sorted((_digest("completion:wrapper"), _digest("completion:operation"))))
    wrapper_ref, operation_ref = refs
    report = RecoveryCompletionReportRecord.create(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        recovery_id="recovery:test",
        succeeded=True,
        operation_evidence_ref=operation_ref,
        evidence_refs=refs,
        completed_at=_NOW,
        terminal_work_digest=_digest("completion:terminal-work"),
    )
    assert report.operation_evidence_ref == operation_ref

    changed_identity = RecoveryCompletionReportRecord.create(
        tenant_id=report.tenant_id,
        transaction_id=report.transaction_id,
        recovery_id=report.recovery_id,
        succeeded=True,
        operation_evidence_ref=wrapper_ref,
        evidence_refs=refs,
        completed_at=report.completed_at,
        terminal_work_digest=report.terminal_work_digest,
    )
    assert changed_identity.report_digest != report.report_digest

    with pytest.raises(ValidationError, match="digest mismatch"):
        RecoveryCompletionReportRecord.model_validate(
            {**report.model_dump(mode="python"), "report_digest": _digest("forged-completion")}
        )

    with pytest.raises(ValidationError, match="included"):
        RecoveryCompletionReportRecord.create(
            tenant_id=report.tenant_id,
            transaction_id=report.transaction_id,
            recovery_id=report.recovery_id,
            succeeded=True,
            operation_evidence_ref=_digest("completion:missing"),
            evidence_refs=refs,
            completed_at=report.completed_at,
            terminal_work_digest=report.terminal_work_digest,
        )
    with pytest.raises(ValidationError, match="reason code"):
        RecoveryCompletionReportRecord.create(
            tenant_id=report.tenant_id,
            transaction_id=report.transaction_id,
            recovery_id=report.recovery_id,
            succeeded=False,
            operation_evidence_ref=operation_ref,
            evidence_refs=refs,
            completed_at=report.completed_at,
            terminal_work_digest=report.terminal_work_digest,
        )


@pytest.mark.parametrize(
    ("record_type", "identity", "boundary"),
    [
        (
            DispatchEvidenceUnavailableRecord,
            {"dispatch_id": "dispatch:test"},
            "POST_DISPATCH_CLASSIFICATION",
        ),
        (
            RecoveryEvidenceUnavailableRecord,
            {"recovery_id": "recovery:test"},
            "POST_CLAIM_SETUP",
        ),
        (
            RecoveryEvidenceUnavailableRecord,
            {"recovery_id": "recovery:test"},
            "RECOVERY_LEASE_RELEASED",
        ),
    ],
)
def test_typed_unavailable_records_are_canonical_and_reject_false_evidence(
    record_type: (
        type[DispatchEvidenceUnavailableRecord] | type[RecoveryEvidenceUnavailableRecord]
    ),
    identity: dict[str, str],
    boundary: str,
) -> None:
    supporting_refs = tuple(sorted((_digest("support:a"), _digest("support:b"))))
    record = record_type.create(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        **identity,
        boundary=boundary,
        supporting_refs=supporting_refs,
        reported_at=_NOW,
        reason_code="EVIDENCE_UNAVAILABLE:SYNTHETIC_OUTAGE",
    )
    assert record.operation_evidence_ref is None
    assert record.record_digest == canonical_digest(record.digest_material())

    changed = record.model_dump(mode="python")
    changed["record_digest"] = _digest("forged-unavailable-record")
    with pytest.raises(ValidationError, match="digest mismatch"):
        record_type.model_validate(changed)

    invalid_reason = record.model_dump(mode="python")
    invalid_reason.update(
        {
            "reason_code": "INTERNAL_FAILURE",
            "record_digest": _digest("forged-unavailable-reason"),
        }
    )
    with pytest.raises(ValidationError, match="unavailable reason"):
        record_type.model_validate(invalid_reason)

    false_operation = record.model_dump(mode="python")
    false_operation.update(
        {
            "operation_evidence_ref": _digest("fabricated-operation-evidence"),
            "record_digest": _digest("forged-unavailable-operation"),
        }
    )
    with pytest.raises(ValidationError):
        record_type.model_validate(false_operation)


def test_reconciliation_attempt_schema_versions_preserve_legacy_fingerprint() -> None:
    legacy = ReconciliationAttemptRecord(
        schema_version="1.0",
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        intent_hash=_digest("intent"),
        dispatch_id="dispatch:test",
        recovery_id="recovery:test",
        attempt=1,
        lease_id="lease:reconcile",
        fencing_token=8,
        evidence_refs=(_digest("request"),),
        started_at=_NOW,
    )
    legacy_json = legacy.canonical_record_json()
    assert "operation_evidence_ref" not in legacy_json
    assert "operation_reason_code" not in legacy_json
    assert canonical_digest(legacy_json) == (
        "sha256:d6bcc3512b661ebd4f0ca35401fcc1c8d783000ee9a1359efcd3914d99954290"
    )
    assert "operation_evidence_ref" not in canonical_json_text(legacy_json)

    operation_ref = _digest("operation")
    current = ReconciliationAttemptRecord(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        intent_hash=_digest("intent"),
        dispatch_id="dispatch:test",
        recovery_id="recovery:test",
        attempt=1,
        lease_id="lease:reconcile",
        fencing_token=8,
        outcome=ReconciliationOutcome.UNKNOWN,
        operation_evidence_ref=operation_ref,
        operation_reason_code="RECONCILIATION_QUERY_FAILED",
        evidence_refs=(operation_ref,),
        completion_evidence_refs=(operation_ref,),
        started_at=_NOW,
        completed_at=_NOW + timedelta(seconds=1),
        next_attempt_not_before=_NOW + timedelta(seconds=5),
        version=1,
    )
    assert current.canonical_record_json()["operation_evidence_ref"] == operation_ref
    assert canonical_digest(current.canonical_record_json()) == (
        "sha256:89855285a1b57d4a8a39e88fd9ebc9f259f8e98ca19ebedd94eea0b84a384114"
    )

    with pytest.raises(ValidationError, match="reason requires operation evidence"):
        ReconciliationAttemptRecord.model_validate(
            {
                **legacy.model_dump(mode="python"),
                "schema_version": "1.1",
                "operation_reason_code": "QUERY_FAILED",
            }
        )
    with pytest.raises(ValidationError, match="outcome and completion must appear together"):
        ReconciliationAttemptRecord.model_validate(
            {
                **legacy.model_dump(mode="python"),
                "schema_version": "1.1",
                "outcome": ReconciliationOutcome.UNKNOWN,
            }
        )
    with pytest.raises(ValidationError, match="input evidence must appear with its outcome"):
        ReconciliationAttemptRecord.model_validate(
            {
                **legacy.model_dump(mode="python"),
                "schema_version": "1.1",
                "completion_evidence_refs": legacy.evidence_refs,
            }
        )
    with pytest.raises(ValidationError, match="Started reconciliation cannot carry"):
        ReconciliationAttemptRecord.model_validate(
            {
                **legacy.model_dump(mode="python"),
                "schema_version": "1.1",
                "effect_receipt_ref": _digest("premature-receipt"),
            }
        )
    with pytest.raises(ValidationError, match="must be version one"):
        ReconciliationAttemptRecord.model_validate(
            {**current.model_dump(mode="python"), "version": 0}
        )
    with pytest.raises(ValidationError, match="completion precedes start"):
        ReconciliationAttemptRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                "completed_at": current.started_at - timedelta(seconds=1),
            }
        )
    with pytest.raises(ValidationError, match="requires durable evidence"):
        ReconciliationAttemptRecord.model_validate(
            {**current.model_dump(mode="python"), "evidence_refs": ()}
        )
    with pytest.raises(ValidationError, match="input evidence must be retained"):
        ReconciliationAttemptRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                "completion_evidence_refs": (_digest("missing-input"),),
            }
        )
    other_ref = _digest("other-completion-input")
    with pytest.raises(ValidationError, match="operation evidence must belong"):
        ReconciliationAttemptRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                "evidence_refs": tuple(sorted((operation_ref, other_ref))),
                "completion_evidence_refs": (other_ref,),
            }
        )
    with pytest.raises(ValidationError, match="Only an unknown reconciliation"):
        ReconciliationAttemptRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                "outcome": ReconciliationOutcome.PARTIAL_OR_INVALID,
            }
        )
    with pytest.raises(ValidationError, match="No-effect reconciliation"):
        ReconciliationAttemptRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                "outcome": ReconciliationOutcome.NO_EFFECT,
                "next_attempt_not_before": None,
            }
        )
    with pytest.raises(ValidationError, match="cannot carry verification or absence"):
        ReconciliationAttemptRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                "no_effect_evidence_ref": _digest("invalid-absence"),
            }
        )
    with pytest.raises(ValidationError, match="backoff precedes completion"):
        ReconciliationAttemptRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                "next_attempt_not_before": current.started_at,
            }
        )

    forged_legacy = legacy.model_dump(mode="python")
    forged_legacy["operation_evidence_ref"] = operation_ref
    with pytest.raises(ValidationError, match="Legacy reconciliation"):
        ReconciliationAttemptRecord.model_validate(forged_legacy)


def test_late_recovery_report_schema_versions_preserve_legacy_fingerprint() -> None:
    operation_ref = _digest("late-operation")
    legacy = LateRecoveryReportRecord.create(
        schema_version="1.0",
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        recovery_id="recovery:test",
        operation_evidence_ref=operation_ref,
        evidence_refs=tuple(sorted((operation_ref, _digest("late-report")))),
        reported_at=_NOW + timedelta(seconds=2),
        reason_code="RECONCILIATION_RESULT_AFTER_PERMIT_DEADLINE",
        terminal_work_digest=_digest("terminal-work"),
    )
    legacy_material = legacy.digest_material()
    assert "operation_reason_code" not in legacy_material
    assert legacy.report_digest == (
        "sha256:079333dc0228998847dff235d28b56c5490afaec876b3f802f3ee3708c36f453"
    )
    assert "operation_reason_code" not in canonical_json_text(legacy_material)

    control_ref = _digest("late-control")
    current = LateRecoveryReportRecord.create(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        recovery_id="recovery:test",
        operation_evidence_ref=control_ref,
        operation_reason_code="RECONCILIATION_QUERY_FAILED",
        evidence_refs=(control_ref,),
        reported_at=_NOW + timedelta(seconds=2),
        reason_code="RECONCILIATION_RESULT_AFTER_PERMIT_DEADLINE",
        terminal_work_digest=_digest("terminal-work"),
    )
    assert current.digest_material()["operation_reason_code"] == ("RECONCILIATION_QUERY_FAILED")
    assert current.report_digest == (
        "sha256:22c63e87284cf19e035bc12ef2aefaeca91bd388ae58f621e971cc984cec701d"
    )

    with pytest.raises(ValidationError, match="included in the late report"):
        LateRecoveryReportRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                "evidence_refs": (_digest("different-evidence"),),
            }
        )
    with pytest.raises(ValidationError, match="digest mismatch"):
        LateRecoveryReportRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                "report_digest": _digest("forged-late-report"),
            }
        )

    forged_legacy = legacy.model_dump(mode="python", exclude={"report_digest"})
    forged_legacy["operation_reason_code"] = "RECONCILIATION_QUERY_FAILED"
    forged_legacy["report_digest"] = legacy.report_digest
    with pytest.raises(ValidationError, match="Legacy late reports"):
        LateRecoveryReportRecord.model_validate(forged_legacy)


def test_reconciliation_and_recovery_are_bounded_and_evidence_carrying() -> None:
    started = ReconciliationAttemptRecord(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        intent_hash=_digest("intent"),
        dispatch_id="dispatch:test",
        recovery_id="recovery:test",
        attempt=1,
        lease_id="lease:reconcile",
        fencing_token=8,
        evidence_refs=(_digest("request"),),
        started_at=_NOW,
    )
    assert started.outcome is None
    assert started.completed_at is None

    invalid_started = started.model_dump(mode="python")
    invalid_started["version"] = 99
    with pytest.raises(ValidationError, match="version zero"):
        ReconciliationAttemptRecord.model_validate(invalid_started)

    incomplete_committed = {
        **started.model_dump(mode="python"),
        "outcome": ReconciliationOutcome.COMMITTED,
        "completed_at": _NOW + timedelta(seconds=1),
        "evidence_refs": (_digest("observation"),),
        "completion_evidence_refs": (_digest("observation"),),
        "version": 1,
    }
    with pytest.raises(ValidationError, match="receipt and verification"):
        ReconciliationAttemptRecord.model_validate(incomplete_committed)

    attempt = ReconciliationAttemptRecord(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        intent_hash=_digest("intent"),
        dispatch_id="dispatch:test",
        recovery_id="recovery:test",
        attempt=1,
        lease_id="lease:reconcile",
        fencing_token=8,
        outcome=ReconciliationOutcome.UNKNOWN,
        effect_receipt_ref=_digest("unverified-effect-receipt"),
        operation_evidence_ref=_digest("query"),
        evidence_refs=(_digest("query"),),
        completion_evidence_refs=(_digest("query"),),
        started_at=_NOW,
        completed_at=_NOW + timedelta(seconds=1),
        next_attempt_not_before=_NOW + timedelta(seconds=5),
        version=1,
    )
    assert attempt.outcome is ReconciliationOutcome.UNKNOWN

    recovery_permit = RecoveryPermit.create(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        intent_hash=_digest("intent"),
        recovery_id="recovery:test",
        recovery_action_transaction_id="transaction:recovery",
        recovery_action_intent_hash=_digest("recovery-intent"),
        recovery_action_digest=_digest("recovery-action"),
        adapter_manifest_digest=_digest("adapter"),
        recovery_kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        target_id="dispatch:test",
        target_owner_version=2,
        target_owner_history_sequence=4,
        target_owner_history_digest=_digest("target-owner-history"),
        target_evidence_ref=_digest("dispatch-record"),
        target_version_guard="version:before",
        authorization_round_id="authorization-round:recovery",
        authorization_round_digest=_digest("authorization-round:recovery"),
        authority_decision_digest=_digest("recovery-authority"),
        policy_decision_digest=_digest("recovery-policy"),
        policy_snapshot_digest=_digest("recovery-policy-snapshot"),
        capability_reservation_digest=_digest("recovery-reservation"),
        reservation_version=1,
        owner_version=0,
        owner_history_sequence=0,
        owner_history_digest=_digest("recovery-owner-history"),
        approval_required=False,
        approval_evidence_ref=_digest("recovery-approval-not-required"),
        lease_id="lease:reconcile",
        worker_id="worker:reconcile",
        fencing_token=8,
        issued_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )
    work = RecoveryWorkRecord(
        tenant_id="tenant:test",
        transaction_id="transaction:test",
        intent_hash=_digest("intent"),
        recovery_id="recovery:test",
        root_recovery_id="recovery:test",
        recovery_ordinal=1,
        max_recovery_attempts=3,
        not_before=_NOW,
        recovery_action_transaction_id="transaction:recovery",
        recovery_action_intent_hash=_digest("recovery-intent"),
        recovery_action_digest=_digest("recovery-action"),
        adapter_manifest_digest=_digest("adapter"),
        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        target_id="dispatch:test",
        target_owner_version=2,
        target_owner_history_sequence=4,
        target_owner_history_digest=_digest("target-owner-history"),
        target_evidence_ref=_digest("dispatch-record"),
        target_version_guard="version:before",
        state=RecoveryWorkState.PENDING,
        authorization_round_id="authorization-round:recovery",
        authorization_round_digest=_digest("authorization-round:recovery"),
        authority_decision_digest=_digest("recovery-authority"),
        policy_decision_digest=_digest("recovery-policy"),
        policy_snapshot_digest=_digest("recovery-policy-snapshot"),
        capability_reservation_digest=_digest("recovery-reservation"),
        reservation_version=0,
        owner_version=0,
        owner_history_sequence=0,
        owner_history_digest=_digest("recovery-owner-history"),
        approval_required=False,
        approval_evidence_ref=_digest("recovery-approval-not-required"),
        deadline=recovery_permit.deadline,
        created_at=_NOW,
        updated_at=_NOW,
    )
    assert work.permit is None

    pending_payload = work.model_dump(mode="python")
    with pytest.raises(ValidationError, match="update precedes creation"):
        RecoveryWorkRecord.model_validate(
            {**pending_payload, "updated_at": work.created_at - timedelta(seconds=1)}
        )
    with pytest.raises(ValidationError, match="must appear together"):
        RecoveryWorkRecord.model_validate(
            {**pending_payload, "reason_code": "EVIDENCE_UNAVAILABLE:ARTIFACT_STORE"}
        )
    unavailable_ref = _digest("unavailable-recovery-record")
    with pytest.raises(ValidationError, match="typed, terminal, and outside"):
        RecoveryWorkRecord.model_validate(
            {
                **pending_payload,
                "reason_code": "EVIDENCE_UNAVAILABLE:ARTIFACT_STORE",
                "unavailable_record_digest": unavailable_ref,
            }
        )
    with pytest.raises(ValidationError, match="created before its deadline"):
        RecoveryWorkRecord.model_validate(
            {
                **pending_payload,
                "created_at": work.deadline,
                "updated_at": work.deadline,
            }
        )
    with pytest.raises(ValidationError, match="within its retry window"):
        RecoveryWorkRecord.model_validate(
            {**pending_payload, "not_before": work.created_at + timedelta(seconds=1)}
        )
    with pytest.raises(ValidationError, match="exceeds its durable attempt bound"):
        RecoveryWorkRecord.model_validate({**pending_payload, "recovery_ordinal": 4})
    with pytest.raises(ValidationError, match="establish its own lineage root"):
        RecoveryWorkRecord.model_validate({**pending_payload, "root_recovery_id": "recovery:other"})
    with pytest.raises(ValidationError, match="distinct predecessor and root"):
        RecoveryWorkRecord.model_validate({**pending_payload, "recovery_ordinal": 2})
    with pytest.raises(ValidationError, match="approval ID does not match"):
        RecoveryWorkRecord.model_validate({**pending_payload, "approval_required": True})
    with pytest.raises(ValidationError, match="digest and version must appear together"):
        RecoveryWorkRecord.model_validate({**pending_payload, "reservation_version": None})
    with pytest.raises(ValidationError, match="execution bindings must be all present"):
        RecoveryWorkRecord.model_validate({**pending_payload, "lease_id": "lease:partial"})
    with pytest.raises(ValidationError, match="must be unclaimed version zero"):
        RecoveryWorkRecord.model_validate({**pending_payload, "version": 1})
    with pytest.raises(ValidationError, match="requires a worker permit"):
        RecoveryWorkRecord.model_validate(
            {
                **pending_payload,
                "state": RecoveryWorkState.RUNNING,
                "version": 1,
                "attempt": 1,
            }
        )
    with pytest.raises(ValidationError, match="Odd recovery reservation version"):
        RecoveryWorkRecord.model_validate(
            {
                **pending_payload,
                "state": RecoveryWorkState.REVIEW_REQUIRED,
                "reservation_version": 1,
                "reason_code": "RECOVERY_AUTHORIZATION_DENIED",
                "evidence_refs": (_digest("denial"),),
            }
        )

    same_transaction = work.model_dump(mode="python")
    same_transaction["recovery_action_transaction_id"] = work.transaction_id
    with pytest.raises(ValidationError, match="separate normalized transaction"):
        RecoveryWorkRecord.model_validate(same_transaction)

    even_permit = recovery_permit.model_dump(mode="python")
    even_permit["reservation_version"] = 2
    with pytest.raises(ValidationError, match="committed odd"):
        RecoveryPermit.model_validate(even_permit)

    noncanonical_permit = recovery_permit.model_dump(mode="python")
    noncanonical_permit["target_version_guard"] = "cafe\u0301"
    with pytest.raises(ValidationError, match="Unicode NFC"):
        RecoveryPermit.model_validate(noncanonical_permit)

    odd_pending = work.model_dump(mode="python")
    odd_pending["reservation_version"] = 3
    with pytest.raises(ValidationError, match="reserved even"):
        RecoveryWorkRecord.model_validate(odd_pending)

    noncanonical_work = work.model_dump(mode="python")
    noncanonical_work["target_version_guard"] = "cafe\u0301"
    with pytest.raises(ValidationError, match="Unicode NFC"):
        RecoveryWorkRecord.model_validate(noncanonical_work)

    running = RecoveryWorkRecord.model_validate(
        {
            **work.model_dump(mode="python"),
            "state": RecoveryWorkState.RUNNING,
            "permit": recovery_permit,
            "permit_ref": canonical_digest(recovery_permit),
            "lease_id": "lease:reconcile",
            "worker_id": "worker:reconcile",
            "fencing_token": 8,
            "reservation_version": 1,
            "version": 1,
            "attempt": 1,
        }
    )
    assert running.permit is not None

    with pytest.raises(ValidationError, match="Pending recovery work cannot carry"):
        RecoveryWorkRecord.model_validate(
            {
                **running.model_dump(mode="python"),
                "state": RecoveryWorkState.PENDING,
                "version": 0,
                "attempt": 0,
                "updated_at": running.created_at,
            }
        )
    with pytest.raises(ValidationError, match="cannot predate its work item"):
        RecoveryWorkRecord.model_validate(
            {
                **running.model_dump(mode="python"),
                "created_at": running.created_at + timedelta(seconds=1),
                "updated_at": running.updated_at + timedelta(seconds=1),
            }
        )
    with pytest.raises(ValidationError, match="artifact ref is inconsistent"):
        RecoveryWorkRecord.model_validate(
            {**running.model_dump(mode="python"), "permit_ref": _digest("forged-permit-ref")}
        )
    with pytest.raises(ValidationError, match="Successful recovery requires"):
        RecoveryWorkRecord.model_validate(
            {
                **running.model_dump(mode="python"),
                "state": RecoveryWorkState.SUCCEEDED,
                "version": 2,
            }
        )
    with pytest.raises(ValidationError, match="Successful recovery must advance"):
        RecoveryWorkRecord.model_validate(
            {
                **running.model_dump(mode="python"),
                "state": RecoveryWorkState.SUCCEEDED,
                "evidence_refs": (_digest("completion"),),
            }
        )
    with pytest.raises(ValidationError, match="Closed recovery work requires"):
        RecoveryWorkRecord.model_validate({**pending_payload, "state": RecoveryWorkState.FAILED})
    with pytest.raises(ValidationError, match="Executed recovery failure must advance"):
        RecoveryWorkRecord.model_validate(
            {
                **running.model_dump(mode="python"),
                "state": RecoveryWorkState.FAILED,
                "reason_code": "RECOVERY_EFFECT_FAILED",
                "evidence_refs": (_digest("failure"),),
            }
        )
    with pytest.raises(ValidationError, match="Scheduled recovery retry must retain"):
        RecoveryWorkRecord.model_validate(
            {
                **pending_payload,
                "state": RecoveryWorkState.RETRY_SCHEDULED,
                "reason_code": "RECOVERY_RETRY",
                "evidence_refs": (_digest("retry"),),
            }
        )

    unadvanced_running = running.model_dump(mode="python")
    unadvanced_running["version"] = 0
    with pytest.raises(ValidationError, match="advance its claim and attempt"):
        RecoveryWorkRecord.model_validate(unadvanced_running)

    first_claim_without_attempt = running.model_dump(mode="python")
    first_claim_without_attempt["attempt"] = 0
    with pytest.raises(ValidationError, match="advance its claim and attempt"):
        RecoveryWorkRecord.model_validate(first_claim_without_attempt)

    claim_at_deadline = running.model_dump(mode="python")
    claim_at_deadline["updated_at"] = running.deadline
    with pytest.raises(ValidationError, match="permit is valid"):
        RecoveryWorkRecord.model_validate(claim_at_deadline)

    unclaimed_review = work.model_dump(mode="python")
    unclaimed_review.update(
        {
            "state": RecoveryWorkState.REVIEW_REQUIRED,
            "capability_reservation_digest": None,
            "reservation_version": None,
            "reason_code": "recovery.authorization_denied",
            "evidence_refs": (_digest("recovery-denial"),),
        }
    )
    assert RecoveryWorkRecord.model_validate(unclaimed_review).version == 0
    unclaimed_review["version"] = 1
    assert RecoveryWorkRecord.model_validate(unclaimed_review).version == 1
    unclaimed_review["attempt"] = 1
    with pytest.raises(ValidationError, match="cannot report an execution attempt"):
        RecoveryWorkRecord.model_validate(unclaimed_review)

    payload = running.model_dump(mode="python")
    payload["lease_id"] = "lease:orphan"
    with pytest.raises(ValidationError, match="bindings differ"):
        RecoveryWorkRecord.model_validate(payload)

    approval_tamper = running.model_dump(mode="python")
    approval_tamper["approval_required"] = True
    approval_tamper["approval_id"] = "approval:forged"
    with pytest.raises(ValidationError, match="bindings differ"):
        RecoveryWorkRecord.model_validate(approval_tamper)

    target_owner_tamper = running.model_dump(mode="python")
    target_owner_tamper["target_owner_version"] = 3
    with pytest.raises(ValidationError, match="bindings differ"):
        RecoveryWorkRecord.model_validate(target_owner_tamper)

    forged_values = recovery_permit.model_dump(mode="python")
    forged_values["fencing_token"] = True
    forged_unsigned = RecoveryPermit.model_construct(**forged_values)
    forged_values["permit_digest"] = canonical_digest(forged_unsigned.digest_material())
    forged_permit = RecoveryPermit.model_construct(**forged_values)
    forged_running = running.model_dump(mode="python")
    forged_running["permit"] = forged_permit
    forged_running["permit_ref"] = canonical_digest(forged_permit)
    with pytest.raises(ValidationError, match="valid integer"):
        RecoveryWorkRecord.model_validate(forged_running)
