from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from agentkernel.adapters.base import EffectPlan
from agentkernel.authority import (
    AuthorityEvaluationVerdict,
    AuthorityReasonCode,
    CapabilityReservationPlan,
    EnforcedAuthorityDecision,
    ResourceAuthorityDecision,
)
from agentkernel.canonical import canonical_digest, canonical_json_bytes, canonical_json_text
from agentkernel.domain.enums import (
    AuthorizationRoundPurpose,
    AuthorizationVerdict,
    CommitDispatchState,
    ReconciliationOutcome,
    RecoveryWorkKind,
    RecoveryWorkState,
    ResourceAccessMode,
    ResourceUseKind,
    RiskClass,
    StageMaterialState,
    TransactionState,
    VerificationPhase,
)
from agentkernel.domain.models import (
    RECOVERY_ACTION_BINDING_ARGUMENT,
    ActionProposal,
    AuthenticatedActionContext,
    CommitPermit,
    InspectionPermit,
    NormalizedAction,
    RecoveryActionBinding,
    ResourceUse,
    SemanticArgument,
    StagePermit,
    VerificationPermit,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.policy import AggregatePolicyDecision, PolicyLayer
from agentkernel.storage.control import (
    CapabilityReservationState,
    DecisionKind,
    IntentAttemptState,
    IntentDisposition,
    SQLiteControlStore,
    decision_snapshot_digest,
)
from agentkernel.storage.enforced import (
    EnforcedStoreDisposition,
    EnforcedTransactionProjection,
    RecoveryAuthorizationResult,
    RecoveryHandoffFailureEvidenceStatus,
    SQLiteEnforcedTransactionStore,
    capability_reservation_digest,
    capability_reservation_plan_digest,
    preview_committed_capability_reservation,
)
from agentkernel.storage.sqlite import MIGRATIONS, SQLiteJournal
from agentkernel.transactions.contracts import (
    AuthorizationRoundRecord,
    CommitDispatchRecord,
    EnforcedTransactionRecord,
    LateRecoveryReportRecord,
    ReconciliationAttemptRecord,
    RecoveryWorkRecord,
    StageMaterialRecord,
)
from agentkernel.transactions.state_machine import TransitionEvent
from tests.unit.test_policy_aggregation import (
    _grant,
    _layer,
    _policy_resource_input,
    _resource,
    evaluate_policy_layers,
)

pytestmark = pytest.mark.integration

_NOW = datetime(2031, 2, 3, 12, tzinfo=UTC)
_PUBLISHED_LEGACY_DIGESTS = {
    1: "sha256:c621aaf41e48d6de6b89154575165e8fd19d034e8a48a1d14dd96a12be03041c",
    2: "sha256:18a9e79676b67150c04fd841013de2d48d5c3ae5cc1f2b2a4dc4312edc4d4ef9",
    3: "sha256:816733d3184e356a3ec48b1d681e32c4e9bdef2d1685fa4e76aa12410c8ae5f9",
}
_CURRENT_PRE_V5_DIGEST = "sha256:a4ed9604b50f86717579f2f02076321a33090d4e92e921665ee2ca2daa7f8b2f"


def _digest(name: str) -> str:
    return canonical_digest({"test": name})


def _rewrite_transaction_event_evidence(
    store: SQLiteEnforcedTransactionStore,
    event: object,
    *,
    evidence_refs: tuple[str, ...],
) -> None:
    current = event
    event_type = type(current)
    tampered = event_type.create(  # type: ignore[attr-defined]
        **current.model_dump(  # type: ignore[attr-defined]
            mode="python",
            exclude={"event_digest", "evidence_refs"},
        ),
        evidence_refs=evidence_refs,
    )
    trigger_row = store._connection.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
        "AND name = 'enforced_transaction_events_no_update'"
    ).fetchone()
    assert trigger_row is not None
    assert trigger_row[0] is not None
    with store._immediate():
        store._execute("DROP TRIGGER enforced_transaction_events_no_update")
        store._execute(
            "UPDATE enforced_transaction_events SET evidence_refs_json = ?, "
            "event_digest = ?, event_json = ? WHERE tenant_id = ? "
            "AND transaction_id = ? AND sequence = ?",
            (
                canonical_json_text(tampered.evidence_refs),
                tampered.event_digest,
                canonical_json_text(tampered),
                tampered.tenant_id,
                tampered.transaction_id,
                tampered.sequence,
            ),
        )
        store._execute(str(trigger_row[0]))


def _rewrite_recovery_work_binding(
    store: SQLiteEnforcedTransactionStore,
    work: RecoveryWorkRecord,
    *,
    target_owner_history_digest: str,
) -> RecoveryWorkRecord:
    """Simulate a canonical row-level rewrite of one immutable recovery binding."""

    altered_values: dict[str, object] = {
        **work.model_dump(mode="python"),
        "target_owner_history_digest": target_owner_history_digest,
    }
    projected_column = "target_owner_history_digest"
    projected_value: object = target_owner_history_digest
    if work.permit is not None:
        # Keep the embedded permit internally valid while altering a different immutable
        # authorization-time binding. Cross-record validation must still detect this.
        altered_deadline = work.deadline + timedelta(microseconds=1)
        altered_values["target_owner_history_digest"] = work.target_owner_history_digest
        altered_values["deadline"] = altered_deadline
        projected_column = "deadline"
        projected_value = altered_deadline.isoformat().replace("+00:00", "Z")
    altered = RecoveryWorkRecord.model_validate(altered_values)
    trigger_row = store._connection.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
        "AND name = 'enforced_recovery_work_binding_immutable'"
    ).fetchone()
    assert trigger_row is not None
    assert trigger_row[0] is not None
    with store._immediate():
        store._execute("DROP TRIGGER enforced_recovery_work_binding_immutable")
        store._execute(
            f"UPDATE enforced_recovery_work SET {projected_column} = ?, "  # noqa: S608
            "record_digest = ?, record_json = ? WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ?",
            (
                projected_value,
                canonical_digest(altered),
                canonical_json_text(altered),
                altered.tenant_id,
                altered.transaction_id,
                altered.recovery_id,
            ),
        )
        store._execute(str(trigger_row[0]))
    return altered


def _rewrite_late_report_operation(
    store: SQLiteEnforcedTransactionStore,
    report: LateRecoveryReportRecord,
    *,
    operation_evidence_ref: str,
    operation_reason_code: str | None = None,
) -> LateRecoveryReportRecord:
    values = report.model_dump(
        mode="python",
        exclude={
            "operation_evidence_ref",
            "operation_reason_code",
            "report_digest",
        },
    )
    altered = LateRecoveryReportRecord.create(
        **values,
        operation_evidence_ref=operation_evidence_ref,
        operation_reason_code=operation_reason_code,
    )
    trigger_rows = store._connection.execute(
        "SELECT name, sql FROM sqlite_schema WHERE type = 'trigger' "
        "AND tbl_name = 'enforced_late_recovery_reports' AND sql IS NOT NULL"
    ).fetchall()
    with store._immediate():
        for row in trigger_rows:
            store._execute(f'DROP TRIGGER "{row["name"]!s}"')
        store._execute(
            "UPDATE enforced_late_recovery_reports SET operation_evidence_ref = ?, "
            "operation_reason_code = ?, report_digest = ?, report_json = ? "
            "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ?",
            (
                altered.operation_evidence_ref,
                altered.operation_reason_code,
                altered.report_digest,
                canonical_json_text(altered),
                altered.tenant_id,
                altered.transaction_id,
                altered.recovery_id,
            ),
        )
        for row in trigger_rows:
            store._execute(str(row["sql"]))
    return altered


def _rewrite_reconciliation_attempt_operation(
    store: SQLiteEnforcedTransactionStore,
    attempt: ReconciliationAttemptRecord,
    *,
    operation_evidence_ref: str,
    operation_reason_code: str | None = None,
) -> ReconciliationAttemptRecord:
    altered = ReconciliationAttemptRecord.model_validate(
        {
            **attempt.model_dump(mode="python"),
            "operation_evidence_ref": operation_evidence_ref,
            "operation_reason_code": operation_reason_code,
        }
    )
    trigger_rows = store._connection.execute(
        "SELECT name, sql FROM sqlite_schema WHERE type = 'trigger' "
        "AND tbl_name = 'enforced_reconciliation_attempts' AND sql IS NOT NULL"
    ).fetchall()
    with store._immediate():
        for row in trigger_rows:
            store._execute(f'DROP TRIGGER "{row["name"]!s}"')
        store._execute(
            "UPDATE enforced_reconciliation_attempts SET operation_evidence_ref = ?, "
            "operation_reason_code = ?, record_digest = ?, record_json = ? "
            "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
            "AND attempt = ?",
            (
                altered.operation_evidence_ref,
                altered.operation_reason_code,
                canonical_digest(altered.canonical_record_json()),
                canonical_json_text(altered.canonical_record_json()),
                altered.tenant_id,
                altered.transaction_id,
                altered.recovery_id,
                altered.attempt,
            ),
        )
        for row in trigger_rows:
            store._execute(str(row["sql"]))
    return altered


def _rewrite_reconciliation_attempt_started_at(
    store: SQLiteEnforcedTransactionStore,
    attempt: ReconciliationAttemptRecord,
    *,
    started_at: datetime,
) -> ReconciliationAttemptRecord:
    """Rewrite one canonical attempt row without changing its STARTED event."""

    altered = ReconciliationAttemptRecord.model_validate(
        {
            **attempt.model_dump(mode="python"),
            "started_at": started_at,
        }
    )
    trigger_row = store._connection.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
        "AND name = 'enforced_reconciliation_binding_immutable'"
    ).fetchone()
    assert trigger_row is not None
    assert trigger_row[0] is not None
    with store._immediate():
        store._execute("DROP TRIGGER enforced_reconciliation_binding_immutable")
        updated = store._execute(
            "UPDATE enforced_reconciliation_attempts SET started_at = ?, "
            "record_digest = ?, record_json = ? WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ? AND attempt = ?",
            (
                started_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                canonical_digest(altered.canonical_record_json()),
                canonical_json_text(altered.canonical_record_json()),
                altered.tenant_id,
                altered.transaction_id,
                altered.recovery_id,
                altered.attempt,
            ),
        )
        assert updated.rowcount == 1
        store._execute(str(trigger_row[0]))
    return altered


def _delete_reconciliation_attempt(
    store: SQLiteEnforcedTransactionStore,
    *,
    tenant_id: str,
    transaction_id: str,
    recovery_id: str,
    attempt: int,
) -> None:
    """Simulate deletion after bypassing the append-only database guard."""

    trigger_row = store._connection.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
        "AND name = 'enforced_reconciliation_attempts_no_delete'"
    ).fetchone()
    assert trigger_row is not None
    assert trigger_row[0] is not None
    with store._immediate():
        store._execute("DROP TRIGGER enforced_reconciliation_attempts_no_delete")
        deleted = store._execute(
            "DELETE FROM enforced_reconciliation_attempts WHERE tenant_id = ? "
            "AND transaction_id = ? AND recovery_id = ? AND attempt = ?",
            (tenant_id, transaction_id, recovery_id, attempt),
        )
        assert deleted.rowcount == 1
        store._execute(str(trigger_row[0]))


def _stored_recovery_authorization(
    store: SQLiteEnforcedTransactionStore,
    work: RecoveryWorkRecord,
) -> tuple[
    AuthorizationRoundRecord,
    EnforcedAuthorityDecision,
    AggregatePolicyDecision,
]:
    authorization_round = store.get_authorization_round(
        tenant_id=work.tenant_id,
        controlled_transaction_id=work.transaction_id,
        round_id=work.authorization_round_id,
    )
    authority = EnforcedAuthorityDecision.model_validate(
        store.get_decision_snapshot(
            tenant_id=work.tenant_id,
            kind=DecisionKind.AUTHORITY,
            decision_id=authorization_round.authority_decision_id,
        ).decision
    )
    policy = AggregatePolicyDecision.model_validate(
        store.get_decision_snapshot(
            tenant_id=work.tenant_id,
            kind=DecisionKind.POLICY,
            decision_id=authorization_round.policy_decision_id,
        ).decision
    )
    return authorization_round, authority, policy


def _retry_recovery_authorization(
    store: SQLiteEnforcedTransactionStore,
    work: RecoveryWorkRecord,
    *,
    capability_ids: tuple[str, ...],
) -> RecoveryAuthorizationResult:
    authorization_round, authority, policy = _stored_recovery_authorization(store, work)
    handoff = store.get_recovery_action_handoff(
        tenant_id=work.tenant_id,
        target_transaction_id=work.transaction_id,
        recovery_id=work.recovery_id,
    )
    assert handoff is not None
    return store.authorize_recovery(
        work,
        authorization_round=authorization_round,
        authority_decision=authority,
        policy_decision=policy,
        capability_ids=capability_ids,
        handoff_failure_evidence_ref=handoff.failure_evidence_ref,
        handoff_failure_evidence_status=handoff.failure_evidence_status,
        handoff_failure_reason_code=handoff.failure_reason_code,
    )


def _rewrite_intent_head_evidence(
    store: SQLiteEnforcedTransactionStore,
    *,
    tenant_id: str,
    intent_hash: str,
    transaction_id: str,
    evidence_digest: str,
) -> None:
    owner = store._connection.execute(
        "SELECT * FROM enforced_intent_owners WHERE tenant_id = ? AND intent_hash = ?",
        (tenant_id, intent_hash),
    ).fetchone()
    assert owner is not None
    sequence = int(owner["history_head_sequence"])
    row = store._connection.execute(
        "SELECT * FROM enforced_intent_attempt_history WHERE tenant_id = ? "
        "AND intent_hash = ? AND sequence = ?",
        (tenant_id, intent_hash, sequence),
    ).fetchone()
    assert row is not None
    assert str(row["transaction_id"]) == transaction_id
    payload: dict[str, object] = {
        "profile": "agentkernel.intent-attempt-history/v2",
        "tenant_id": tenant_id,
        "intent_hash": intent_hash,
        "sequence": sequence,
        "transaction_id": transaction_id,
        "event_type": str(row["event_type"]),
        "disposition": None if row["disposition"] is None else str(row["disposition"]),
        "attempt_state": str(row["attempt_state"]),
        "owner_transaction_id": str(row["owner_transaction_id"]),
        "owner_version": int(row["owner_version"]),
        "effective_idempotency_key": str(row["effective_idempotency_key"]),
        "evidence_digest": evidence_digest,
        "previous_history_digest": (
            None if row["previous_history_digest"] is None else str(row["previous_history_digest"])
        ),
        "recorded_at": str(row["recorded_at"]),
    }
    history_digest = canonical_digest(payload)
    trigger_row = store._connection.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
        "AND name = 'enforced_intent_history_no_update'"
    ).fetchone()
    assert trigger_row is not None
    assert trigger_row[0] is not None
    with store._immediate():
        store._execute("DROP TRIGGER enforced_intent_history_no_update")
        store._execute(
            "UPDATE enforced_intent_attempt_history SET evidence_digest = ?, "
            "history_digest = ? WHERE tenant_id = ? AND intent_hash = ? AND sequence = ?",
            (evidence_digest, history_digest, tenant_id, intent_hash, sequence),
        )
        store._execute(
            "UPDATE enforced_intent_attempts SET evidence_digest = ? WHERE tenant_id = ? "
            "AND intent_hash = ? AND transaction_id = ?",
            (evidence_digest, tenant_id, intent_hash, transaction_id),
        )
        store._execute(
            "UPDATE enforced_intent_owners SET history_head_digest = ? WHERE tenant_id = ? "
            "AND intent_hash = ? AND history_head_sequence = ?",
            (history_digest, tenant_id, intent_hash, sequence),
        )
        store._execute(str(trigger_row[0]))


def _round_artifacts(label: str) -> dict[str, str]:
    return {
        "authority_snapshot_ref": _digest(f"artifact:authority-snapshot:{label}"),
        "authority_context_ref": _digest(f"artifact:authority-context:{label}"),
        "authority_decision_ref": _digest(f"artifact:authority-decision:{label}"),
        "policy_inputs_ref": _digest(f"artifact:policy-inputs:{label}"),
        "policy_snapshot_ref": _digest(f"artifact:policy-snapshot:{label}"),
        "policy_decision_ref": _digest(f"artifact:policy-decision:{label}"),
    }


def _create_v4_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        for version, sql in MIGRATIONS[:4]:
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, digest, applied_at) VALUES (?, ?, ?)",
                (
                    version,
                    canonical_digest({"version": version, "sql": sql}),
                    "2031-02-03T00:00:00.000000Z",
                ),
            )
        connection.commit()
    finally:
        connection.close()


def _create_v5_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        for version, sql in MIGRATIONS[:5]:
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, digest, applied_at) VALUES (?, ?, ?)",
                (
                    version,
                    canonical_digest({"version": version, "sql": sql}),
                    "2031-02-03T00:00:00.000000Z",
                ),
            )
        connection.commit()
    finally:
        connection.close()


def _copy_legacy_compatible_rows_to_v4(source_path: Path, target_path: Path) -> None:
    """Copy the common v4 columns from a real populated store in dependency order."""

    tables = (
        "enforced_tenants",
        "enforced_principals",
        "enforced_goals",
        "enforced_runs",
        "enforced_normalized_actions",
        "enforced_resource_uses",
        "enforced_transactions",
        "enforced_transaction_events",
        "enforced_intent_owners",
        "enforced_intent_attempts",
        "enforced_intent_attempt_history",
    )
    source = sqlite3.connect(source_path)
    target = sqlite3.connect(target_path)
    try:
        target.execute("PRAGMA foreign_keys = OFF")
        for table in tables:
            target_columns = tuple(
                str(row[1]) for row in target.execute(f'PRAGMA table_info("{table}")').fetchall()
            )
            source_columns = {
                str(row[1]) for row in source.execute(f'PRAGMA table_info("{table}")').fetchall()
            }
            assert target_columns
            assert set(target_columns) <= source_columns
            rendered_columns = ", ".join(f'"{column}"' for column in target_columns)
            select_sql = f'SELECT {rendered_columns} FROM "{table}"'  # noqa: S608  # nosec B608
            rows = source.execute(select_sql).fetchall()
            if rows:
                placeholders = ", ".join("?" for _ in target_columns)
                insert_sql = (
                    f'INSERT INTO "{table}" ({rendered_columns}) '  # noqa: S608  # nosec B608
                    f"VALUES ({placeholders})"
                )
                target.executemany(insert_sql, rows)
        target.commit()
        target.execute("PRAGMA foreign_keys = ON")
        assert target.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        source.close()
        target.close()


def _context(tenant: str = "tenant:test") -> AuthenticatedActionContext:
    suffix = tenant.rsplit(":", 1)[-1]
    return AuthenticatedActionContext(
        tenant_id=tenant,
        principal_id=f"principal:{suffix}",
        goal_id=f"goal:{suffix}",
        run_id=f"run:{suffix}",
        trace_id=f"trace:{suffix}",
        actor_id="service:coordinator",
        on_behalf_of=f"principal:{suffix}",
        agent_id=f"agent:{suffix}",
        configuration_digest=_digest(f"configuration:{tenant}"),
    )


def _new_record(
    context: AuthenticatedActionContext,
    transaction_id: str = "transaction:test",
) -> EnforcedTransactionRecord:
    return EnforcedTransactionRecord(
        tenant_id=context.tenant_id,
        transaction_id=transaction_id,
        principal_id=context.principal_id,
        goal_id=context.goal_id,
        run_id=context.run_id,
        trace_id=context.trace_id,
        actor_id=context.actor_id,
        on_behalf_of=context.on_behalf_of,
        agent_id=context.agent_id,
        request_digest=_digest(f"request:{transaction_id}"),
        state=TransactionState.NEW,
        version=0,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _action(
    context: AuthenticatedActionContext,
    transaction_id: str = "transaction:test",
) -> NormalizedAction:
    resource = ResourceUse(
        authority_action="fs.write",
        access_mode=ResourceAccessMode.WRITE,
        canonical_resource="fs://workspace/result.txt",
        effect_domain="filesystem",
        purpose="v4 integration test",
        use_kind=ResourceUseKind.AUTHORITATIVE_EFFECT,
        destination_external=False,
    )
    return NormalizedAction.create(
        context=context,
        transaction_id=transaction_id,
        deadline=_NOW + timedelta(minutes=10),
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
        resource_uses=(resource,),
    )


def _strict_decisions(
    action: NormalizedAction,
    *,
    capability_ids: tuple[str, ...],
    label: str,
    evaluated_at: datetime,
    modes: tuple[str, ...],
    authorization_verdict: AuthorizationVerdict = AuthorizationVerdict.ELIGIBLE,
) -> tuple[EnforcedAuthorityDecision, AggregatePolicyDecision]:
    snapshot_digest = _digest(f"authority-snapshot:{label}")
    authority_allowed = authorization_verdict is not AuthorizationVerdict.DENIED
    authority_capability_ids = (
        capability_ids if capability_ids else (f"capability:evidence:{label}",)
    )
    authority_verdict = (
        AuthorityEvaluationVerdict.ALLOW if authority_allowed else AuthorityEvaluationVerdict.DENY
    )
    authority_reason = (
        AuthorityReasonCode.AUTHORITY_GRANTED
        if authority_allowed
        else AuthorityReasonCode.AUTHORITY_MISSING
    )
    resource_decisions = tuple(
        ResourceAuthorityDecision.create(
            resource_index=index,
            resource_use=resource_use,
            effective_data_classes=resource_use.data_classes,
            verdict=authority_verdict,
            reason_code=authority_reason,
            capability_chain_ids=(authority_capability_ids if authority_allowed else ()),
        )
        for index, resource_use in enumerate(action.resource_uses)
    )
    reservation_plan = (
        CapabilityReservationPlan.create(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            authority_snapshot_digest=snapshot_digest,
            capability_ids=authority_capability_ids,
        )
        if authority_allowed
        else None
    )
    authority_values: dict[str, object] = {
        "tenant_id": action.tenant_id,
        "transaction_id": action.transaction_id,
        "intent_hash": action.intent_hash,
        "authority_snapshot_tenant_id": action.tenant_id,
        "authority_snapshot_id": f"snapshot:authority:{label}",
        "authority_snapshot_revision": 1,
        "authority_snapshot_as_of": evaluated_at,
        "authority_snapshot_digest": snapshot_digest,
        "expected_authority_snapshot_digest": snapshot_digest,
        "evaluation_context_digest": _digest(f"authority-context:{label}"),
        "evaluated_at": evaluated_at,
        "verdict": authority_verdict,
        "reason_code": authority_reason,
        "resource_decisions": resource_decisions,
        "reservation_plan": reservation_plan,
        "provenance_used_as_authority": False,
    }
    authority = EnforcedAuthorityDecision.model_validate(
        {
            **authority_values,
            "decision_digest": canonical_digest(authority_values),
        }
    )
    resource_inputs = tuple(
        _policy_resource_input(action, resource_use) for resource_use in action.resource_uses
    )
    policy = evaluate_policy_layers(
        capability_valid=authority_allowed,
        layers=(
            _layer(
                PolicyLayer.SYSTEM,
                _grant(
                    f"grant-{label.replace(':', '-')}",
                    modes=modes,
                    resource="fs://workspace/**",
                ),
            ),
        ),
        resources=resource_inputs,
        authority_decision=authority,
        unknown_facts=(
            (f"unknown:{label}",) if authorization_verdict is AuthorizationVerdict.UNKNOWN else ()
        ),
    )
    expected_policy_verdict = {
        AuthorizationVerdict.ELIGIBLE: "ELIGIBLE",
        AuthorizationVerdict.DENIED: "DENY",
        AuthorizationVerdict.UNKNOWN: "DENY",
    }[authorization_verdict]
    assert policy.verdict.value == expected_policy_verdict
    return authority, policy


def _proposal(action: NormalizedAction) -> ActionProposal:
    return ActionProposal(
        goal_id=action.goal_id,
        transaction_id=action.transaction_id,
        agent_id=action.agent_id,
        adapter=action.adapter,
        adapter_version=action.adapter_version,
        operation=action.operation,
        arguments={"path": "README.md", "content": "test"},
        deadline=action.deadline,
        idempotency_key=action.idempotency_key,
    )


def _effect_plan(
    action: NormalizedAction,
    *,
    plan_id: str,
    base_version: str = "version:before",
) -> EffectPlan:
    return EffectPlan(
        plan_id=plan_id,
        proposal=_proposal(action),
        canonical_resource="fs://workspace/result.txt",
        base_version=base_version,
        intent_hash=action.intent_hash,
        risk_class=action.risk_floor,
        effect_domains=action.effect_domains,
        semantic_arguments={"path": "README.md", "content": "test"},
    )


def _bootstrap_planned(
    store: SQLiteEnforcedTransactionStore,
    context: AuthenticatedActionContext,
    transaction_id: str = "transaction:test",
) -> tuple[EnforcedTransactionRecord, NormalizedAction]:
    store.register_action_context(context, registered_at=_NOW)
    record = _new_record(context, transaction_id)
    action = _action(context, transaction_id)
    assert store.create_enforced_transaction(record).disposition is EnforcedStoreDisposition.CREATED
    planned = store.plan_and_acquire_intent(
        action,
        expected_version=0,
        planned_at=_NOW + timedelta(seconds=1),
    )
    assert planned.disposition is EnforcedStoreDisposition.PLANNED
    return planned.transaction, action


def _eligible_round(
    store: SQLiteEnforcedTransactionStore,
    action: NormalizedAction,
    *,
    round_id: str = "authorization:stage",
) -> tuple[
    AuthorizationRoundRecord,
    EnforcedAuthorityDecision,
    AggregatePolicyDecision,
    tuple[str, ...],
]:
    capability_ids = ("capability:test",)
    store.register_capability_budget(
        tenant_id=action.tenant_id,
        capability_id=capability_ids[0],
        goal_id=action.goal_id,
        run_id=action.run_id,
        max_uses=2,
        registered_at=_NOW,
    )
    history = store.list_intent_history(
        tenant_id=action.tenant_id,
        intent_hash=action.intent_hash,
    )
    head = history[-1]
    evaluated_at = _NOW + timedelta(seconds=2)
    authority, policy = _strict_decisions(
        action,
        capability_ids=capability_ids,
        label="stage",
        evaluated_at=evaluated_at,
        modes=("read", "stage"),
    )
    authority_id = "decision:authority:stage"
    policy_id = "decision:policy:stage"
    authority_record_digest = decision_snapshot_digest(
        tenant_id=action.tenant_id,
        kind=DecisionKind.AUTHORITY,
        decision_id=authority_id,
        transaction_id=action.transaction_id,
        intent_hash=action.intent_hash,
        decision=authority,
    )
    policy_record_digest = decision_snapshot_digest(
        tenant_id=action.tenant_id,
        kind=DecisionKind.POLICY,
        decision_id=policy_id,
        transaction_id=action.transaction_id,
        intent_hash=action.intent_hash,
        decision=policy,
    )
    predicted = store.preview_capability_chain_reservation(
        tenant_id=action.tenant_id,
        goal_id=action.goal_id,
        run_id=action.run_id,
        intent_hash=action.intent_hash,
        capability_ids=capability_ids,
        reserved_at=_NOW + timedelta(seconds=2),
    )
    record = AuthorizationRoundRecord.create(
        tenant_id=action.tenant_id,
        controlled_transaction_id=action.transaction_id,
        subject_transaction_id=action.transaction_id,
        subject_intent_hash=action.intent_hash,
        subject_normalized_action_digest=canonical_digest(action),
        round_id=round_id,
        purpose=AuthorizationRoundPurpose.STAGING,
        verdict=AuthorizationVerdict.ELIGIBLE,
        authority_snapshot_id=authority.authority_snapshot_id,
        authority_snapshot_digest=authority.authority_snapshot_digest,
        authority_snapshot_ref=_digest("artifact:authority-snapshot:stage"),
        authority_context_ref=_digest("artifact:authority-context:stage"),
        authority_decision_id=authority_id,
        authority_decision_record_digest=authority_record_digest,
        authority_decision_digest=authority.decision_digest,
        authority_decision_ref=_digest("artifact:authority-decision:stage"),
        policy_decision_id=policy_id,
        policy_decision_record_digest=policy_record_digest,
        policy_decision_digest=policy.aggregate_digest,
        policy_inputs_ref=_digest("artifact:policy-inputs:stage"),
        policy_snapshot_digest=policy.policy_snapshot.snapshot_digest,
        policy_snapshot_ref=_digest("artifact:policy-snapshot:stage"),
        policy_decision_ref=_digest("artifact:policy-decision:stage"),
        capability_reservation_plan_digest=capability_reservation_plan_digest(
            tenant_id=action.tenant_id,
            goal_id=action.goal_id,
            run_id=action.run_id,
            intent_hash=action.intent_hash,
            capability_ids=capability_ids,
        ),
        capability_reservation_digest=capability_reservation_digest(predicted),
        reservation_version=0,
        reservation_goal_id=action.goal_id,
        reservation_run_id=action.run_id,
        owner_version=head.owner_version,
        owner_history_sequence=head.sequence,
        owner_history_digest=head.history_digest,
        allowed_modes=policy.allowed_modes,
        obligations=policy.obligations,
        reason_code=policy.reason_code,
        evaluated_at=evaluated_at,
        authority_valid_until=_NOW + timedelta(minutes=9),
    )
    return record, authority, policy, capability_ids


def _stage_to_verified(
    store: SQLiteEnforcedTransactionStore,
    context: AuthenticatedActionContext,
    *,
    transaction_id: str = "transaction:test",
) -> tuple[NormalizedAction, StageMaterialRecord, tuple[str, ...]]:
    _, action = _bootstrap_planned(store, context, transaction_id)
    round_record, authority, policy, capability_ids = _eligible_round(store, action)
    store.authorize_for_staging(
        round_record,
        authority_decision=authority,
        policy_decision=policy,
        capability_ids=capability_ids,
        expected_transaction_version=1,
    )
    lease = store.acquire_staging_lease(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        lease_id=f"lease:stage:{transaction_id.rsplit(':', 1)[-1]}",
        worker_id="worker:stage",
        acquired_at=_NOW + timedelta(seconds=3),
        expires_at=_NOW + timedelta(minutes=5),
        expected_transaction_version=2,
    ).lease
    inspection = InspectionPermit.create(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        intent_hash=action.intent_hash,
        normalized_action_digest=canonical_digest(action),
        proposal_ref=canonical_digest(_proposal(action)),
        adapter_manifest_digest=action.adapter_manifest_digest,
        authorization_round_id=round_record.round_id,
        authorization_round_digest=round_record.round_digest,
        lease_id=lease.lease_id,
        worker_id=lease.worker_id,
        fencing_token=lease.fencing_token,
        issued_at=_NOW + timedelta(seconds=4),
        deadline=lease.expires_at,
    )
    plan = _effect_plan(action, plan_id=f"plan:{transaction_id}")
    stage_permit = StagePermit.create(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        intent_hash=action.intent_hash,
        normalized_action_digest=canonical_digest(action),
        adapter_manifest_digest=action.adapter_manifest_digest,
        authorization_round_id=round_record.round_id,
        authorization_round_digest=round_record.round_digest,
        inspection_permit_digest=inspection.permit_digest,
        inspection_permit_ref=canonical_digest(inspection),
        plan_digest=canonical_digest(plan),
        plan_ref=canonical_digest(plan),
        stage_id=f"stage:{transaction_id.rsplit(':', 1)[-1]}",
        lease_id=lease.lease_id,
        worker_id=lease.worker_id,
        fencing_token=lease.fencing_token,
        target_version_guard="version:before",
        issued_at=_NOW + timedelta(seconds=5),
        deadline=lease.expires_at,
    )
    material = StageMaterialRecord(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        stage_id=stage_permit.stage_id,
        lease_id=stage_permit.lease_id,
        fencing_token=stage_permit.fencing_token,
        intent_hash=action.intent_hash,
        normalized_action_digest=canonical_digest(action),
        adapter_manifest_digest=action.adapter_manifest_digest,
        plan_digest=stage_permit.plan_digest,
        plan_ref=stage_permit.plan_ref,
        inspection_permit_digest=inspection.permit_digest,
        inspection_permit_ref=canonical_digest(inspection),
        stage_permit_digest=stage_permit.permit_digest,
        stage_permit_ref=canonical_digest(stage_permit),
        state=StageMaterialState.ALLOCATED,
        target_version_guard=stage_permit.target_version_guard,
        version=0,
        created_at=_NOW + timedelta(seconds=5),
        updated_at=_NOW + timedelta(seconds=5),
    )
    store.allocate_stage_material(
        material,
        inspection_permit=inspection,
        stage_permit=stage_permit,
    )
    store.record_staged_material(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        expected_material_version=0,
        base_state_digest=_digest(f"base:{transaction_id}"),
        staged_effect_ref=_digest(f"staged-effect:{transaction_id}"),
        recorded_at=_NOW + timedelta(seconds=6),
    )
    store.record_stage_execution(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        expected_material_version=1,
        expected_transaction_version=3,
        staged_receipt_ref=_digest(f"staged-receipt:{transaction_id}"),
        staged_state_digest=_digest(f"staged-state:{transaction_id}"),
        recorded_at=_NOW + timedelta(seconds=7),
    )
    verification_permit = VerificationPermit.create(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        intent_hash=action.intent_hash,
        normalized_action_digest=canonical_digest(action),
        adapter_manifest_digest=action.adapter_manifest_digest,
        authorization_round_id=round_record.round_id,
        authorization_round_digest=round_record.round_digest,
        lease_id=lease.lease_id,
        worker_id=lease.worker_id,
        fencing_token=lease.fencing_token,
        phase=VerificationPhase.STAGED,
        subject_ref=_digest(f"staged-receipt:{transaction_id}"),
        authority_permit_digest=stage_permit.permit_digest,
        authority_permit_ref=canonical_digest(stage_permit),
        subject_permit_digest=stage_permit.permit_digest,
        subject_permit_ref=canonical_digest(stage_permit),
        issued_at=_NOW + timedelta(seconds=8),
        deadline=lease.expires_at,
    )
    result = store.record_stage_verification(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        expected_material_version=2,
        expected_transaction_version=4,
        verification_permit=verification_permit,
        verification_permit_ref=canonical_digest(verification_permit),
        verification_ref=_digest(f"staged-verification:{transaction_id}"),
        passed=True,
        recorded_at=_NOW + timedelta(seconds=8),
    )
    return action, result.material, capability_ids


def _precommit_round(
    store: SQLiteEnforcedTransactionStore,
    action: NormalizedAction,
    capability_ids: tuple[str, ...],
) -> tuple[AuthorizationRoundRecord, EnforcedAuthorityDecision, AggregatePolicyDecision]:
    reservation = store._read_capability_chain(
        tenant_id=action.tenant_id,
        goal_id=action.goal_id,
        run_id=action.run_id,
        intent_hash=action.intent_hash,
    )
    assert reservation is not None
    history = store.list_intent_history(
        tenant_id=action.tenant_id,
        intent_hash=action.intent_hash,
    )
    head = history[-1]
    evaluated_at = _NOW + timedelta(seconds=10)
    authority, policy = _strict_decisions(
        action,
        capability_ids=capability_ids,
        label="precommit",
        evaluated_at=evaluated_at,
        modes=("commit_reversible",),
    )
    authority_id = "decision:authority:precommit"
    policy_id = "decision:policy:precommit"
    round_record = AuthorizationRoundRecord.create(
        tenant_id=action.tenant_id,
        controlled_transaction_id=action.transaction_id,
        subject_transaction_id=action.transaction_id,
        subject_intent_hash=action.intent_hash,
        subject_normalized_action_digest=canonical_digest(action),
        round_id="authorization:precommit",
        purpose=AuthorizationRoundPurpose.PRECOMMIT,
        verdict=AuthorizationVerdict.ELIGIBLE,
        authority_snapshot_id=authority.authority_snapshot_id,
        authority_snapshot_digest=authority.authority_snapshot_digest,
        authority_snapshot_ref=_digest("artifact:authority-snapshot:precommit"),
        authority_context_ref=_digest("artifact:authority-context:precommit"),
        authority_decision_id=authority_id,
        authority_decision_record_digest=decision_snapshot_digest(
            tenant_id=action.tenant_id,
            kind=DecisionKind.AUTHORITY,
            decision_id=authority_id,
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            decision=authority,
        ),
        authority_decision_digest=authority.decision_digest,
        authority_decision_ref=_digest("artifact:authority-decision:precommit"),
        policy_decision_id=policy_id,
        policy_decision_record_digest=decision_snapshot_digest(
            tenant_id=action.tenant_id,
            kind=DecisionKind.POLICY,
            decision_id=policy_id,
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            decision=policy,
        ),
        policy_decision_digest=policy.aggregate_digest,
        policy_inputs_ref=_digest("artifact:policy-inputs:precommit"),
        policy_snapshot_digest=policy.policy_snapshot.snapshot_digest,
        policy_snapshot_ref=_digest("artifact:policy-snapshot:precommit"),
        policy_decision_ref=_digest("artifact:policy-decision:precommit"),
        capability_reservation_plan_digest=capability_reservation_plan_digest(
            tenant_id=action.tenant_id,
            goal_id=action.goal_id,
            run_id=action.run_id,
            intent_hash=action.intent_hash,
            capability_ids=capability_ids,
        ),
        capability_reservation_digest=capability_reservation_digest(reservation),
        reservation_version=reservation.version,
        reservation_goal_id=action.goal_id,
        reservation_run_id=action.run_id,
        owner_version=head.owner_version,
        owner_history_sequence=head.sequence,
        owner_history_digest=head.history_digest,
        allowed_modes=policy.allowed_modes,
        obligations=policy.obligations,
        reason_code=policy.reason_code,
        evaluated_at=evaluated_at,
        authority_valid_until=_NOW + timedelta(minutes=9),
    )
    return round_record, authority, policy


def _begin_dispatch(
    store: SQLiteEnforcedTransactionStore,
    action: NormalizedAction,
    stage: StageMaterialRecord,
    capability_ids: tuple[str, ...],
    idempotency_key: str | None = None,
    approval_required: bool = False,
    approval_id: str | None = None,
    approval_evidence_ref: str | None = None,
) -> CommitDispatchRecord:
    store.apply_control_transition(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        expected_version=5,
        transition_event=TransitionEvent.NO_APPROVAL_REQUIRED,
        recorded_at=_NOW + timedelta(seconds=9),
        evidence_refs=(_digest("no-approval"),),
    )
    round_record, authority, policy = _precommit_round(store, action, capability_ids)
    authorized = store.authorize_for_precommit(
        round_record,
        authority_decision=authority,
        policy_decision=policy,
        capability_ids=capability_ids,
        expected_transaction_version=6,
    )
    assert authorized.transaction.state is TransactionState.READY_TO_COMMIT
    assert authorized.disposition is EnforcedStoreDisposition.STORED
    assert (
        store.authorize_for_precommit(
            round_record,
            authority_decision=authority,
            policy_decision=policy,
            capability_ids=capability_ids,
            expected_transaction_version=6,
        ).disposition
        is EnforcedStoreDisposition.EXACT_RETRY
    )
    reservation = store._read_capability_chain(
        tenant_id=action.tenant_id,
        goal_id=action.goal_id,
        run_id=action.run_id,
        intent_hash=action.intent_hash,
    )
    assert reservation is not None
    committed = preview_committed_capability_reservation(reservation)
    lease = store.get_worker_lease(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        lease_id=stage.lease_id,
    )
    permit_deadline = min(action.deadline, lease.expires_at).astimezone(UTC)
    precommit_plan = _effect_plan(action, plan_id="plan:precommit")
    precommit_plan_ref = canonical_digest(precommit_plan)
    precommit_inspection = InspectionPermit.create(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        intent_hash=action.intent_hash,
        normalized_action_digest=canonical_digest(action),
        proposal_ref=canonical_digest(precommit_plan.proposal),
        adapter_manifest_digest=action.adapter_manifest_digest,
        authorization_round_id=round_record.round_id,
        authorization_round_digest=round_record.round_digest,
        lease_id=lease.lease_id,
        worker_id=lease.worker_id,
        fencing_token=lease.fencing_token,
        issued_at=_NOW + timedelta(seconds=10),
        deadline=permit_deadline,
    )
    precommit_inspection_ref = canonical_digest(precommit_inspection)
    permit = CommitPermit.create(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        intent_hash=action.intent_hash,
        normalized_action_digest=canonical_digest(action),
        dispatch_id="dispatch:test",
        stage_id=stage.stage_id,
        plan_digest=stage.plan_digest,
        plan_ref=stage.plan_ref,
        stage_permit_digest=stage.stage_permit_digest,
        stage_permit_ref=stage.stage_permit_ref,
        lease_id=stage.lease_id,
        worker_id="worker:stage",
        fencing_token=stage.fencing_token,
        idempotency_key=idempotency_key or action.idempotency_key,
        target_version_guard=stage.target_version_guard,
        staged_receipt_ref=stage.staged_receipt_ref,
        staged_state_digest=stage.staged_state_digest,
        staged_verification_permit_digest=stage.verification_permit_digest,
        staged_verification_permit_ref=stage.verification_permit_ref,
        staged_verification_ref=stage.verification_ref,
        precommit_inspection_permit_digest=precommit_inspection.permit_digest,
        precommit_inspection_permit_ref=precommit_inspection_ref,
        precommit_plan_digest=canonical_digest(precommit_plan),
        precommit_plan_ref=precommit_plan_ref,
        approval_required=approval_required,
        approval_id=approval_id,
        approval_evidence_ref=approval_evidence_ref or _digest("no-approval"),
        adapter_manifest_digest=action.adapter_manifest_digest,
        authority_decision_digest=round_record.authority_decision_digest,
        policy_decision_digest=round_record.policy_decision_digest,
        policy_snapshot_digest=round_record.policy_snapshot_digest,
        authorization_round_id=round_record.round_id,
        authorization_round_digest=round_record.round_digest,
        capability_reservation_digest=capability_reservation_digest(committed),
        reservation_version=committed.version,
        owner_version=round_record.owner_version,
        owner_history_sequence=round_record.owner_history_sequence,
        owner_history_digest=round_record.owner_history_digest,
        issued_at=_NOW + timedelta(seconds=11),
        deadline=permit_deadline,
    )
    dispatch = CommitDispatchRecord(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        intent_hash=action.intent_hash,
        dispatch_id=permit.dispatch_id,
        owner_version=permit.owner_version,
        permit=permit,
        permit_ref=canonical_digest(permit),
        state=CommitDispatchState.DISPATCHED,
        version=0,
        created_at=_NOW + timedelta(seconds=11),
        updated_at=_NOW + timedelta(seconds=11),
    )
    result = store.begin_commit_dispatch(
        dispatch,
        precommit_inspection_permit=precommit_inspection,
        precommit_inspection_permit_ref=precommit_inspection_ref,
        precommit_plan=precommit_plan,
        precommit_plan_ref=precommit_plan_ref,
        expected_transaction_version=6,
    )
    assert result.disposition is EnforcedStoreDisposition.COMMIT_NOW
    assert (
        store.begin_commit_dispatch(
            dispatch,
            precommit_inspection_permit=precommit_inspection,
            precommit_inspection_permit_ref=precommit_inspection_ref,
            precommit_plan=precommit_plan,
            precommit_plan_ref=precommit_plan_ref,
            expected_transaction_version=6,
        ).disposition
        is EnforcedStoreDisposition.EXACT_RETRY
    )
    with pytest.raises(AgentKernelError) as stale_authorization:
        store.authorize_for_precommit(
            round_record,
            authority_decision=authority,
            policy_decision=policy,
            capability_ids=capability_ids,
            expected_transaction_version=6,
        )
    assert stale_authorization.value.code is ErrorCode.VERSION_CONFLICT
    return dispatch


def _recovery_action(
    context: AuthenticatedActionContext,
    original: NormalizedAction,
    *,
    kind: RecoveryWorkKind,
    generation: int = 1,
    binding: RecoveryActionBinding | None = None,
) -> NormalizedAction:
    kind_token = kind.value.lower()
    token = kind_token if generation == 1 else f"{kind_token}:{generation}"
    transaction_id = f"transaction:recovery:{token}"
    binding_resource = original.resource_uses[0].canonical_resource
    semantic_arguments = original.semantic_arguments
    if binding is not None:
        binding_bytes = canonical_json_bytes(binding)
        semantic_arguments = (
            *original.semantic_arguments,
            SemanticArgument(
                argument_name=RECOVERY_ACTION_BINDING_ARGUMENT,
                resource=binding_resource,
                digest=canonical_digest(binding),
                size_bytes=len(binding_bytes),
                media_type="application/vnd.agentkernel.recovery-binding+json",
            ),
        )
    return NormalizedAction.create(
        context=context,
        transaction_id=transaction_id,
        deadline=(_NOW + timedelta(minutes=10) if binding is None else binding.absolute_deadline),
        idempotency_key=f"idempotency:recovery:{token}",
        adapter=original.adapter,
        adapter_version=original.adapter_version,
        adapter_manifest_digest=original.adapter_manifest_digest,
        operation=original.operation,
        normalizer_implementation=original.normalizer_implementation,
        normalizer_version=original.normalizer_version,
        normalizer_digest=original.normalizer_digest,
        operation_schema_ref=original.operation_schema_ref,
        operation_schema_digest=original.operation_schema_digest,
        risk_floor=original.risk_floor,
        effect_domains=original.effect_domains,
        resource_uses=original.resource_uses,
        semantic_arguments=semantic_arguments,
        provenance=original.provenance,
    )


def _authorize_recovery_work(
    store: SQLiteEnforcedTransactionStore,
    context: AuthenticatedActionContext,
    original: NormalizedAction,
    target: StageMaterialRecord | CommitDispatchRecord,
    *,
    kind: RecoveryWorkKind,
    generation: int = 1,
    predecessor: RecoveryWorkRecord | None = None,
    authorized_at: datetime | None = None,
    max_recovery_attempts: int | None = None,
    verdict: AuthorizationVerdict = AuthorizationVerdict.ELIGIBLE,
    authority_valid_until: datetime | None = None,
) -> RecoveryWorkRecord:
    kind_token = kind.value.lower()
    token = kind_token if generation == 1 else f"{kind_token}:{generation}"
    authorized_at = authorized_at or (_NOW + timedelta(seconds=16))
    target_head = store.list_intent_history(
        tenant_id=original.tenant_id,
        intent_hash=original.intent_hash,
    )[-1]
    if isinstance(target, StageMaterialRecord):
        target_id = target.stage_id
        target_version_guard = target.target_version_guard
        target_owner_version = target_head.owner_version
        target_owner_history_sequence = target_head.sequence
        target_owner_history_digest = target_head.history_digest
    else:
        target_id = target.dispatch_id
        target_version_guard = target.permit.target_version_guard
        target_owner_version = target.permit.owner_version
        target_owner_history_sequence = target.permit.owner_history_sequence
        target_owner_history_digest = target.permit.owner_history_digest
    recovery_id = f"recovery:{token}:test"
    if predecessor is None:
        root_recovery_id = recovery_id
        predecessor_recovery_id = None
        recovery_ordinal = 1
        max_recovery_attempts_value = (
            max_recovery_attempts
            if max_recovery_attempts is not None
            else (3 if kind is RecoveryWorkKind.RECONCILE_DISPATCH else 1)
        )
        not_before = authorized_at
        deadline = store.get_transaction_recovery_deadline(
            tenant_id=original.tenant_id,
            transaction_id=original.transaction_id,
        )
    else:
        attempt = store.get_reconciliation_attempt(
            tenant_id=predecessor.tenant_id,
            transaction_id=predecessor.transaction_id,
            recovery_id=predecessor.recovery_id,
            attempt=predecessor.attempt,
        )
        assert attempt.next_attempt_not_before is not None
        root_recovery_id = predecessor.root_recovery_id
        predecessor_recovery_id = predecessor.recovery_id
        recovery_ordinal = predecessor.recovery_ordinal + 1
        max_recovery_attempts_value = predecessor.max_recovery_attempts
        not_before = attempt.next_attempt_not_before
        deadline = predecessor.deadline
    binding = RecoveryActionBinding(
        target_transaction_id=original.transaction_id,
        target_intent_hash=original.intent_hash,
        target_normalized_action_digest=canonical_digest(original),
        recovery_kind=kind,
        target_id=target_id,
        target_evidence_ref=canonical_digest(target),
        target_version_guard=target_version_guard,
        target_owner_version=target_owner_version,
        target_owner_history_sequence=target_owner_history_sequence,
        target_owner_history_digest=target_owner_history_digest,
        adapter_manifest_digest=original.adapter_manifest_digest,
        risk_class=original.risk_floor,
        effect_domains=original.effect_domains,
        resource_uses_digest=canonical_digest(original.resource_uses),
        recovery_id=recovery_id,
        root_recovery_id=root_recovery_id,
        predecessor_recovery_id=predecessor_recovery_id,
        recovery_ordinal=recovery_ordinal,
        max_recovery_attempts=max_recovery_attempts_value,
        not_before=not_before,
        absolute_deadline=deadline,
    )
    current_target = store.get_enforced_transaction(
        original.tenant_id,
        original.transaction_id,
    )
    if isinstance(target, StageMaterialRecord):
        handoff_claim = store.acquire_recovery_handoff_lease(
            tenant_id=original.tenant_id,
            transaction_id=original.transaction_id,
            expected_transaction_version=current_target.version,
            stage_id=target.stage_id,
            expected_stage_version=target.version,
            stage_target_ref=canonical_digest(target),
            lease_id=f"lease:handoff:{token}",
            worker_id="worker:test:handoff",
            acquired_at=authorized_at,
            expires_at=min(deadline, authorized_at + timedelta(minutes=1)),
            binding=binding,
        )
    else:
        handoff_claim = store.acquire_recovery_authorization_lease(
            tenant_id=original.tenant_id,
            transaction_id=original.transaction_id,
            expected_transaction_version=current_target.version,
            kind=kind,
            dispatch_id=target.dispatch_id,
            dispatch_target_ref=canonical_digest(target),
            recovery_id=recovery_id,
            lease_id=f"lease:handoff:{token}",
            worker_id="worker:test:handoff",
            acquired_at=authorized_at,
            expires_at=min(deadline, authorized_at + timedelta(minutes=1)),
            binding=binding,
        )
    recovery_action = _recovery_action(
        context,
        original,
        kind=kind,
        generation=generation,
        binding=binding,
    )
    acquisition = store.register_recovery_action(
        recovery_action,
        registered_at=authorized_at,
        binding=binding,
    )
    assert acquisition.disposition is IntentDisposition.ACQUIRED
    capability_ids = (
        (f"capability:recovery:{token}",) if verdict is AuthorizationVerdict.ELIGIBLE else ()
    )
    if capability_ids:
        store.register_capability_budget(
            tenant_id=recovery_action.tenant_id,
            capability_id=capability_ids[0],
            goal_id=recovery_action.goal_id,
            run_id=recovery_action.run_id,
            max_uses=1,
            registered_at=_NOW,
        )
    subject_head = store.list_intent_history(
        tenant_id=recovery_action.tenant_id,
        intent_hash=recovery_action.intent_hash,
    )[-1]
    authority, policy = _strict_decisions(
        recovery_action,
        capability_ids=capability_ids,
        label=f"recovery:{token}",
        evaluated_at=authorized_at,
        modes=("stage",),
        authorization_verdict=verdict,
    )
    predicted = (
        store.preview_capability_chain_reservation(
            tenant_id=recovery_action.tenant_id,
            goal_id=recovery_action.goal_id,
            run_id=recovery_action.run_id,
            intent_hash=recovery_action.intent_hash,
            capability_ids=capability_ids,
            reserved_at=authorized_at,
        )
        if capability_ids
        else None
    )
    round_record = AuthorizationRoundRecord.create(
        tenant_id=original.tenant_id,
        controlled_transaction_id=original.transaction_id,
        subject_transaction_id=recovery_action.transaction_id,
        subject_intent_hash=recovery_action.intent_hash,
        subject_normalized_action_digest=canonical_digest(recovery_action),
        round_id=f"authorization:recovery:{token}",
        purpose=AuthorizationRoundPurpose.RECOVERY,
        verdict=verdict,
        authority_snapshot_id=authority.authority_snapshot_id,
        authority_snapshot_digest=authority.authority_snapshot_digest,
        authority_snapshot_ref=_digest(f"artifact:authority-snapshot:recovery:{token}"),
        authority_context_ref=_digest(f"artifact:authority-context:recovery:{token}"),
        authority_decision_id=f"decision:authority:recovery:{token}",
        authority_decision_record_digest=decision_snapshot_digest(
            tenant_id=recovery_action.tenant_id,
            kind=DecisionKind.AUTHORITY,
            decision_id=f"decision:authority:recovery:{token}",
            transaction_id=recovery_action.transaction_id,
            intent_hash=recovery_action.intent_hash,
            decision=authority,
        ),
        authority_decision_digest=authority.decision_digest,
        authority_decision_ref=_digest(f"artifact:authority-decision:recovery:{token}"),
        policy_decision_id=f"decision:policy:recovery:{token}",
        policy_decision_record_digest=decision_snapshot_digest(
            tenant_id=recovery_action.tenant_id,
            kind=DecisionKind.POLICY,
            decision_id=f"decision:policy:recovery:{token}",
            transaction_id=recovery_action.transaction_id,
            intent_hash=recovery_action.intent_hash,
            decision=policy,
        ),
        policy_decision_digest=policy.aggregate_digest,
        policy_inputs_ref=_digest(f"artifact:policy-inputs:recovery:{token}"),
        policy_snapshot_digest=policy.policy_snapshot.snapshot_digest,
        policy_snapshot_ref=_digest(f"artifact:policy-snapshot:recovery:{token}"),
        policy_decision_ref=_digest(f"artifact:policy-decision:recovery:{token}"),
        capability_reservation_plan_digest=(
            capability_reservation_plan_digest(
                tenant_id=recovery_action.tenant_id,
                goal_id=recovery_action.goal_id,
                run_id=recovery_action.run_id,
                intent_hash=recovery_action.intent_hash,
                capability_ids=capability_ids,
            )
            if predicted is not None
            else None
        ),
        capability_reservation_digest=(
            capability_reservation_digest(predicted) if predicted is not None else None
        ),
        reservation_version=None if predicted is None else predicted.version,
        reservation_goal_id=(None if predicted is None else recovery_action.goal_id),
        reservation_run_id=(None if predicted is None else recovery_action.run_id),
        owner_version=subject_head.owner_version,
        owner_history_sequence=subject_head.sequence,
        owner_history_digest=subject_head.history_digest,
        allowed_modes=policy.allowed_modes,
        obligations=policy.obligations,
        reason_code=(
            authority.reason_code.value
            if verdict is AuthorizationVerdict.DENIED
            else policy.reason_code
        ),
        evaluated_at=authorized_at,
        authority_valid_until=(
            (authority_valid_until or recovery_action.deadline)
            if verdict is AuthorizationVerdict.ELIGIBLE
            else None
        ),
    )
    handoff_failure_ref = (
        None
        if verdict is AuthorizationVerdict.ELIGIBLE
        else _digest(f"artifact:recovery-handoff-failure:{token}")
    )
    terminal_evidence_refs: tuple[str, ...] = (canonical_digest(binding),)
    if handoff_failure_ref is not None:
        terminal_evidence_refs = tuple(
            sorted(
                (
                    round_record.round_digest,
                    canonical_digest(binding),
                    handoff_failure_ref,
                )
            )
        )
    work = RecoveryWorkRecord(
        tenant_id=original.tenant_id,
        transaction_id=original.transaction_id,
        intent_hash=original.intent_hash,
        recovery_id=recovery_id,
        root_recovery_id=root_recovery_id,
        predecessor_recovery_id=predecessor_recovery_id,
        recovery_ordinal=recovery_ordinal,
        max_recovery_attempts=max_recovery_attempts_value,
        not_before=not_before,
        recovery_action_transaction_id=recovery_action.transaction_id,
        recovery_action_intent_hash=recovery_action.intent_hash,
        recovery_action_digest=canonical_digest(recovery_action),
        adapter_manifest_digest=recovery_action.adapter_manifest_digest,
        kind=kind,
        target_id=target_id,
        target_owner_version=target_owner_version,
        target_owner_history_sequence=target_owner_history_sequence,
        target_owner_history_digest=target_owner_history_digest,
        target_evidence_ref=canonical_digest(target),
        target_version_guard=target_version_guard,
        state={
            AuthorizationVerdict.ELIGIBLE: RecoveryWorkState.PENDING,
            AuthorizationVerdict.DENIED: RecoveryWorkState.FAILED,
            AuthorizationVerdict.UNKNOWN: RecoveryWorkState.REVIEW_REQUIRED,
        }[verdict],
        authorization_round_id=round_record.round_id,
        authorization_round_digest=round_record.round_digest,
        authority_decision_digest=round_record.authority_decision_digest,
        policy_decision_digest=round_record.policy_decision_digest,
        policy_snapshot_digest=round_record.policy_snapshot_digest,
        capability_reservation_digest=(
            None if predicted is None else capability_reservation_digest(predicted)
        ),
        reservation_version=None if predicted is None else predicted.version,
        owner_version=subject_head.owner_version,
        owner_history_sequence=subject_head.sequence,
        owner_history_digest=subject_head.history_digest,
        approval_required=False,
        approval_evidence_ref=_digest(f"approval:recovery:{token}:not-required"),
        deadline=deadline,
        attempt=0,
        version=0,
        evidence_refs=terminal_evidence_refs,
        reason_code=(
            None if verdict is AuthorizationVerdict.ELIGIBLE else round_record.reason_code
        ),
        created_at=authorized_at,
        updated_at=authorized_at,
    )
    authorized = store.authorize_recovery(
        work,
        authorization_round=round_record,
        authority_decision=authority,
        policy_decision=policy,
        capability_ids=capability_ids,
        handoff_lease=handoff_claim.lease,
        handoff_failure_evidence_ref=handoff_failure_ref,
        handoff_failure_evidence_status=(
            RecoveryHandoffFailureEvidenceStatus.NONE
            if verdict is AuthorizationVerdict.ELIGIBLE
            else RecoveryHandoffFailureEvidenceStatus.AVAILABLE
        ),
        handoff_failure_reason_code=(
            None if verdict is AuthorizationVerdict.ELIGIBLE else round_record.reason_code
        ),
    )
    assert authorized.work.state is work.state
    assert authorized.reservation == predicted
    return work


def _claim_unknown_reconciliation(
    store: SQLiteEnforcedTransactionStore,
    context: AuthenticatedActionContext,
    *,
    max_recovery_attempts: int = 3,
    authority_valid_until: datetime | None = None,
) -> tuple[NormalizedAction, RecoveryWorkRecord]:
    action, stage, capability_ids = _stage_to_verified(store, context)
    _begin_dispatch(store, action, stage, capability_ids)
    unknown = store.classify_dispatch_outcome(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        expected_dispatch_version=0,
        expected_transaction_version=7,
        classification=ReconciliationOutcome.UNKNOWN,
        evidence_refs=(_digest("dispatch:unknown"),),
        reason_code="DISPATCH_OUTCOME_UNKNOWN",
        recorded_at=_NOW + timedelta(seconds=13),
        recovery_timeout=timedelta(minutes=10),
    )
    work = _authorize_recovery_work(
        store,
        context,
        action,
        unknown.dispatch,
        kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        max_recovery_attempts=max_recovery_attempts,
        authority_valid_until=authority_valid_until,
    )
    preview = store.preview_recovery_claim(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=work.recovery_id,
        expected_work_version=0,
        lease_id="lease:recovery:reconcile:1",
        worker_id="worker:reconcile",
        acquired_at=_NOW + timedelta(seconds=17),
        expires_at=_NOW + timedelta(minutes=5),
    )
    store.claim_recovery(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=work.recovery_id,
        expected_work_version=0,
        lease_id=preview.lease.lease_id,
        worker_id=preview.lease.worker_id,
        acquired_at=preview.lease.acquired_at,
        expires_at=preview.lease.expires_at,
        permit=preview.permit,
        permit_ref=preview.permit_ref,
    )
    return action, work


def _pending_effect_recovery(
    store: SQLiteEnforcedTransactionStore,
    context: AuthenticatedActionContext,
    *,
    kind: RecoveryWorkKind,
    authority_valid_until: datetime | None = None,
) -> tuple[NormalizedAction, RecoveryWorkRecord]:
    action, stage, capability_ids = _stage_to_verified(store, context)
    _begin_dispatch(store, action, stage, capability_ids)
    classified = store.classify_dispatch_outcome(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        expected_dispatch_version=0,
        expected_transaction_version=7,
        classification=ReconciliationOutcome.PARTIAL_OR_INVALID,
        evidence_refs=(_digest(f"dispatch:partial:{kind.value}"),),
        reason_code="DISPATCH_PARTIAL_OR_INVALID",
        recorded_at=_NOW + timedelta(seconds=13),
        recovery_timeout=timedelta(minutes=10),
    )
    assert classified.transaction.state is TransactionState.FAILED
    work = _authorize_recovery_work(
        store,
        context,
        action,
        classified.dispatch,
        kind=kind,
        authority_valid_until=authority_valid_until,
    )
    return action, work


def _start_unknown_reconciliation(
    store: SQLiteEnforcedTransactionStore,
    context: AuthenticatedActionContext,
    *,
    max_recovery_attempts: int = 3,
) -> tuple[NormalizedAction, RecoveryWorkRecord]:
    action, work = _claim_unknown_reconciliation(
        store,
        context,
        max_recovery_attempts=max_recovery_attempts,
    )
    store.start_reconciliation(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=work.recovery_id,
        expected_work_version=1,
        evidence_refs=(_digest("reconciliation:started"),),
        started_at=_NOW + timedelta(seconds=18),
    )
    return action, work


def _reclaim_started_reconciliation_to_attempt_three(
    store: SQLiteEnforcedTransactionStore,
    context: AuthenticatedActionContext,
) -> tuple[NormalizedAction, RecoveryWorkRecord, dict[str, object]]:
    action, proposed = _start_unknown_reconciliation(store, context)
    running_one = store.get_recovery_work(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=proposed.recovery_id,
    )
    assert running_one.permit_ref is not None
    preview_two = store.preview_recovery_reclaim(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=proposed.recovery_id,
        expected_work_version=1,
        lease_id="lease:recovery:reconcile:lineage:2",
        worker_id="worker:reconcile:lineage:2",
        acquired_at=_NOW + timedelta(minutes=5, seconds=1),
        expires_at=_NOW + timedelta(minutes=6),
    )
    expiry_one = _digest("reconciliation:lineage:attempt:1:expired")
    store.reclaim_expired_recovery(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=proposed.recovery_id,
        expected_work_version=1,
        lease_id=preview_two.lease.lease_id,
        worker_id=preview_two.lease.worker_id,
        acquired_at=preview_two.lease.acquired_at,
        expires_at=preview_two.lease.expires_at,
        permit=preview_two.permit,
        permit_ref=preview_two.permit_ref,
        evidence_refs=tuple(sorted({running_one.permit_ref, preview_two.permit_ref, expiry_one})),
        operation_evidence_ref=expiry_one,
        operation_reason_code="RECOVERY_LEASE_EXPIRED",
    )
    store.start_reconciliation(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=proposed.recovery_id,
        expected_work_version=2,
        evidence_refs=(_digest("reconciliation:lineage:attempt:2:started"),),
        started_at=preview_two.lease.acquired_at + timedelta(seconds=1),
    )
    running_two = store.get_recovery_work(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=proposed.recovery_id,
    )
    assert running_two.permit_ref is not None
    preview_three = store.preview_recovery_reclaim(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=proposed.recovery_id,
        expected_work_version=2,
        lease_id="lease:recovery:reconcile:lineage:3",
        worker_id="worker:reconcile:lineage:3",
        acquired_at=_NOW + timedelta(minutes=6, seconds=1),
        expires_at=_NOW + timedelta(minutes=7),
    )
    expiry_two = _digest("reconciliation:lineage:attempt:2:expired")
    reclaim_three_arguments: dict[str, object] = {
        "tenant_id": action.tenant_id,
        "transaction_id": action.transaction_id,
        "recovery_id": proposed.recovery_id,
        "expected_work_version": 2,
        "lease_id": preview_three.lease.lease_id,
        "worker_id": preview_three.lease.worker_id,
        "acquired_at": preview_three.lease.acquired_at,
        "expires_at": preview_three.lease.expires_at,
        "permit": preview_three.permit,
        "permit_ref": preview_three.permit_ref,
        "evidence_refs": tuple(
            sorted({running_two.permit_ref, preview_three.permit_ref, expiry_two})
        ),
        "operation_evidence_ref": expiry_two,
        "operation_reason_code": "RECOVERY_LEASE_EXPIRED",
    }
    reclaimed = store.reclaim_expired_recovery(  # type: ignore[arg-type]
        **reclaim_three_arguments
    )
    assert reclaimed.work.attempt == 3
    return action, reclaimed.work, reclaim_three_arguments


def _claim_discard_for_late_report(
    store: SQLiteEnforcedTransactionStore,
    context: AuthenticatedActionContext,
    *,
    authority_valid_until: datetime,
) -> tuple[NormalizedAction, StageMaterialRecord, RecoveryWorkRecord]:
    action, stage, capability_ids = _stage_to_verified(store, context)
    _begin_dispatch(store, action, stage, capability_ids)
    absence = _digest("dispatch:no-effect:late")
    store.classify_dispatch_outcome(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        expected_dispatch_version=0,
        expected_transaction_version=7,
        classification=ReconciliationOutcome.NO_EFFECT,
        evidence_refs=(absence,),
        no_effect_evidence_ref=absence,
        recorded_at=_NOW + timedelta(seconds=13),
        recovery_timeout=timedelta(minutes=10),
    )
    proposed = _authorize_recovery_work(
        store,
        context,
        action,
        stage,
        kind=RecoveryWorkKind.DISCARD_STAGING,
        authority_valid_until=authority_valid_until,
    )
    preview = store.preview_recovery_claim(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=proposed.recovery_id,
        expected_work_version=0,
        lease_id="lease:recovery:discard:late",
        worker_id="worker:recovery:late",
        acquired_at=_NOW + timedelta(seconds=17),
        expires_at=_NOW + timedelta(minutes=5),
    )
    assert preview.permit.deadline == authority_valid_until
    claimed = store.claim_recovery(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        recovery_id=proposed.recovery_id,
        expected_work_version=0,
        lease_id=preview.lease.lease_id,
        worker_id=preview.lease.worker_id,
        acquired_at=preview.lease.acquired_at,
        expires_at=preview.lease.expires_at,
        permit=preview.permit,
        permit_ref=preview.permit_ref,
    )
    return action, stage, claimed.work


def test_v5_migration_preserves_published_v1_through_v3_and_current_v4_baseline(
    tmp_path: Path,
) -> None:
    assert {
        version: canonical_digest({"version": version, "sql": sql})
        for version, sql in MIGRATIONS[:3]
    } == _PUBLISHED_LEGACY_DIGESTS
    version, sql = MIGRATIONS[3]
    assert version == 4
    assert canonical_digest({"version": version, "sql": sql}) == _CURRENT_PRE_V5_DIGEST
    path = tmp_path / "v5.db"
    with SQLiteJournal(path) as journal:
        assert journal.schema_version() == 7

    connection = sqlite3.connect(path)
    try:
        names = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_schema WHERE type = 'table'")
        }
    finally:
        connection.close()
    assert {
        "enforced_transactions",
        "enforced_transaction_events",
        "enforced_authorization_rounds",
        "enforced_worker_leases",
        "enforced_stage_material",
        "enforced_commit_dispatches",
        "enforced_dispatch_outcomes",
        "enforced_reconciliation_attempts",
        "enforced_recovery_work",
    } <= names


def test_v6_migrates_a_v5_database_with_typed_outage_bindings(tmp_path: Path) -> None:
    path = tmp_path / "v5-to-v6.db"
    _create_v5_database(path)

    with SQLiteJournal(path) as migrated:
        assert migrated.schema_version() == 7

    connection = sqlite3.connect(path)
    try:
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_schema WHERE type = 'table'")
        }
        dispatch_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(enforced_commit_dispatches)")
        }
        outcome_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(enforced_dispatch_outcomes)")
        }
        recovery_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(enforced_recovery_work)")
        }
    finally:
        connection.close()
    assert {
        "enforced_dispatch_evidence_unavailable_reports",
        "enforced_dispatch_evidence_unavailable_bindings",
        "enforced_recovery_evidence_unavailable_reports",
    } <= tables
    assert "unavailable_record_digest" in dispatch_columns
    assert "unavailable_record_digest" in outcome_columns
    assert "unavailable_record_digest" in recovery_columns


def test_v5_migration_backfills_populated_v4_intent_history_atomically(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "populated-v5-source.db"
    with SQLiteEnforcedTransactionStore(source_path) as source_store:
        context = _context("tenant:migration")
        record, action = _bootstrap_planned(
            source_store,
            context,
            transaction_id="transaction:migration",
        )
        history_before = source_store.list_intent_history(
            tenant_id=action.tenant_id,
            intent_hash=action.intent_hash,
        )
        assert record.state is TransactionState.PLANNED
        assert len(history_before) == 1

    legacy_path = tmp_path / "populated-v4.db"
    _create_v4_database(legacy_path)
    _copy_legacy_compatible_rows_to_v4(source_path, legacy_path)
    with sqlite3.connect(legacy_path) as legacy_connection:
        legacy_head = legacy_connection.execute(
            "SELECT history_digest FROM enforced_intent_attempt_history"
        ).fetchone()
        assert legacy_head == (history_before[0].history_digest,)

    with SQLiteJournal(legacy_path) as migrated:
        assert migrated.schema_version() == 7
    with sqlite3.connect(legacy_path) as migrated_connection:
        assert migrated_connection.execute("PRAGMA foreign_key_check").fetchall() == []
        owner_key = migrated_connection.execute(
            "SELECT effective_idempotency_key FROM enforced_intent_owners"
        ).fetchone()
        history_row = migrated_connection.execute(
            "SELECT effective_idempotency_key, history_digest FROM enforced_intent_attempt_history"
        ).fetchone()
        assert owner_key == (action.idempotency_key,)
        assert history_row == (action.idempotency_key, history_before[0].history_digest)

    with SQLiteEnforcedTransactionStore(legacy_path) as reopened:
        assert (
            reopened.get_enforced_transaction(
                action.tenant_id,
                action.transaction_id,
            ).state
            is TransactionState.PLANNED
        )
        history_after = reopened.list_intent_history(
            tenant_id=action.tenant_id,
            intent_hash=action.intent_hash,
        )
        assert tuple(item.history_digest for item in history_after) == (
            history_before[0].history_digest,
        )
        assert history_after[0].effective_idempotency_key == action.idempotency_key


def test_public_decision_digest_matches_durable_snapshot_profile() -> None:
    document: dict[str, object] = {"verdict": "ALLOW", "nested": {"b": 2, "a": 1}}
    public = decision_snapshot_digest(
        tenant_id="tenant:test",
        kind=DecisionKind.AUTHORITY,
        decision_id="decision:test",
        transaction_id="transaction:test",
        intent_hash=_digest("intent:test"),
        decision=document,
    )
    assert public == SQLiteControlStore._decision_digest(
        tenant_id="tenant:test",
        kind=DecisionKind.AUTHORITY,
        decision_id="decision:test",
        transaction_id="transaction:test",
        intent_hash=_digest("intent:test"),
        decision=document,  # type: ignore[arg-type]
    )


def test_native_policy_unknown_maps_to_unknown_and_binds_aggregate_digest(
    tmp_path: Path,
) -> None:
    policy = evaluate_policy_layers(
        capability_valid=True,
        layers=(),
        resources=(_resource(),),
    )
    action = policy.normalized_action
    authority = policy.authority_decision
    record = AuthorizationRoundRecord.create(
        tenant_id=action.tenant_id,
        controlled_transaction_id=action.transaction_id,
        subject_transaction_id=action.transaction_id,
        subject_intent_hash=action.intent_hash,
        subject_normalized_action_digest=canonical_digest(action),
        round_id="authorization:native-policy-unknown",
        purpose=AuthorizationRoundPurpose.STAGING,
        verdict=AuthorizationVerdict.UNKNOWN,
        authority_snapshot_id=authority.authority_snapshot_id,
        authority_snapshot_digest=authority.authority_snapshot_digest,
        **_round_artifacts("native-policy-unknown"),
        authority_decision_id="decision:native-authority",
        authority_decision_record_digest=decision_snapshot_digest(
            tenant_id=action.tenant_id,
            kind=DecisionKind.AUTHORITY,
            decision_id="decision:native-authority",
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            decision=authority,
        ),
        authority_decision_digest=authority.decision_digest,
        policy_decision_id="decision:native-policy",
        policy_decision_record_digest=decision_snapshot_digest(
            tenant_id=action.tenant_id,
            kind=DecisionKind.POLICY,
            decision_id="decision:native-policy",
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            decision=policy,
        ),
        policy_decision_digest=policy.aggregate_digest,
        policy_snapshot_digest=policy.policy_snapshot.snapshot_digest,
        owner_version=0,
        owner_history_sequence=0,
        owner_history_digest=_digest("native-owner-history"),
        reason_code=ErrorCode.POLICY_UNKNOWN.value,
        evaluated_at=authority.evaluated_at,
    )
    with SQLiteEnforcedTransactionStore(tmp_path / "native-policy.db") as store:
        store._assert_round_decision_semantics(
            record,
            action=action,
            authority=authority,
            policy=policy,
            capability_ids=(),
        )
        tampered = AuthorizationRoundRecord.create(
            **{
                **record.model_dump(mode="python", exclude={"round_digest"}),
                "policy_decision_digest": _digest("tampered-policy-inner"),
            }
        )
        with pytest.raises(AgentKernelError) as captured:
            store._assert_round_decision_semantics(
                tampered,
                action=action,
                authority=authority,
                policy=policy,
                capability_ids=(),
            )
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_ingress_requires_pre_registered_authenticated_identity_and_is_atomic(
    tmp_path: Path,
) -> None:
    context = _context()
    record = _new_record(context)
    path = tmp_path / "identity.db"
    with SQLiteEnforcedTransactionStore(path) as store:
        with pytest.raises(AgentKernelError) as captured:
            store.create_enforced_transaction(record)
        assert captured.value.code is ErrorCode.AUTHORITY_MISSING
        assert (
            store._connection.execute("SELECT COUNT(*) FROM enforced_transactions").fetchone()[0]
            == 0
        )
        assert store._connection.execute("SELECT COUNT(*) FROM enforced_tenants").fetchone()[0] == 0

        store.register_action_context(context, registered_at=_NOW)
        created = store.create_enforced_transaction(record)
        assert created.disposition is EnforcedStoreDisposition.CREATED
        assert created.transaction.state is TransactionState.NEW
        retry = store.create_enforced_transaction(record)
        assert retry.disposition is EnforcedStoreDisposition.EXACT_RETRY
        assert (
            len(store.list_enforced_transaction_events(context.tenant_id, record.transaction_id))
            == 1
        )


def test_atomic_admission_retries_by_immutable_request_after_progression(
    tmp_path: Path,
) -> None:
    context = _context()
    record = _new_record(context)
    with SQLiteEnforcedTransactionStore(tmp_path / "atomic-admission.db") as store:
        created = store.admit_enforced_transaction(context, record)
        assert created.disposition is EnforcedStoreDisposition.CREATED
        assert store._connection.execute("SELECT COUNT(*) FROM enforced_runs").fetchone()[0] == 1
        later_ingress = EnforcedTransactionRecord.model_validate(
            {
                **record.model_dump(mode="python"),
                "created_at": _NOW + timedelta(seconds=1),
                "updated_at": _NOW + timedelta(seconds=1),
            }
        )
        assert (
            store.admit_enforced_transaction(context, later_ingress).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        action = _action(context)
        planned = store.plan_and_acquire_intent(
            action,
            expected_version=0,
            planned_at=_NOW + timedelta(seconds=2),
        )
        progressed = store.admit_enforced_transaction(context, later_ingress)
        assert progressed.disposition is EnforcedStoreDisposition.EXACT_RETRY
        assert progressed.transaction == planned.transaction
        conflicting = EnforcedTransactionRecord.model_validate(
            {
                **later_ingress.model_dump(mode="python"),
                "request_digest": _digest("different-request"),
            }
        )
        with pytest.raises(AgentKernelError) as captured:
            store.admit_enforced_transaction(context, conflicting)
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize("tamper", ["mapping", "authority", "snapshot"])
def test_authorization_semantic_tampering_fails_before_reservation(
    tmp_path: Path,
    tamper: str,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(tmp_path / f"round-{tamper}.db") as store:
        _, action = _bootstrap_planned(store, context)
        record, authority, policy, capability_ids = _eligible_round(store, action)
        changed_authority = authority
        changed_policy: object = policy
        if tamper == "mapping":
            changed_policy = policy.model_dump(mode="python", exclude={"aggregate_digest"})
        elif tamper == "authority":
            changed_authority, _ = _strict_decisions(
                action,
                capability_ids=capability_ids,
                label="tampered-authority",
                evaluated_at=record.evaluated_at,
                modes=("read", "stage"),
            )
        else:
            _, changed_policy = _strict_decisions(
                action,
                capability_ids=capability_ids,
                label="tampered-policy",
                evaluated_at=record.evaluated_at,
                modes=("read", "stage"),
            )
        with pytest.raises(AgentKernelError) as captured:
            store.authorize_for_staging(
                record,
                authority_decision=changed_authority,  # type: ignore[arg-type]
                policy_decision=changed_policy,  # type: ignore[arg-type]
                capability_ids=capability_ids,
                expected_transaction_version=1,
            )
        assert captured.value.code is (
            ErrorCode.VALIDATION_ERROR if tamper == "mapping" else ErrorCode.INTEGRITY_ERROR
        )
        budget = store.get_capability_budget(
            tenant_id=action.tenant_id,
            capability_id=capability_ids[0],
            goal_id=action.goal_id,
            run_id=action.run_id,
        )
        assert budget.reserved_uses == 0
        assert (
            store._connection.execute(
                "SELECT COUNT(*) FROM enforced_authorization_rounds"
            ).fetchone()[0]
            == 0
        )


def test_staging_authorization_exact_retry_rejects_tamper_and_progression(
    tmp_path: Path,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(tmp_path / "staging-retry.db") as store:
        _, action = _bootstrap_planned(store, context)
        record, authority, policy, capability_ids = _eligible_round(store, action)
        stored = store.authorize_for_staging(
            record,
            authority_decision=authority,
            policy_decision=policy,
            capability_ids=capability_ids,
            expected_transaction_version=1,
        )
        assert stored.disposition is EnforcedStoreDisposition.STORED
        forged_authority = {
            **authority.model_dump(mode="python"),
            "decision_digest": _digest("forged-authority"),
        }
        with pytest.raises(AgentKernelError):
            store.authorize_for_staging(
                record,
                authority_decision=forged_authority,
                policy_decision=policy,
                capability_ids=capability_ids,
                expected_transaction_version=1,
            )
        with pytest.raises(AgentKernelError):
            store.authorize_for_staging(
                record,
                authority_decision=authority,
                policy_decision=policy,
                capability_ids=(*capability_ids, "capability:forged"),
                expected_transaction_version=1,
            )
        store.acquire_staging_lease(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            lease_id="lease:advanced",
            worker_id="worker:advanced",
            acquired_at=_NOW + timedelta(seconds=3),
            expires_at=_NOW + timedelta(minutes=5),
            expected_transaction_version=2,
        )
        with pytest.raises(AgentKernelError) as captured:
            store.authorize_for_staging(
                record,
                authority_decision=authority,
                policy_decision=policy,
                capability_ids=capability_ids,
                expected_transaction_version=1,
            )
        assert captured.value.code is ErrorCode.VERSION_CONFLICT


def test_plan_authorize_lease_and_private_stage_survive_reopen(tmp_path: Path) -> None:
    path = tmp_path / "staging.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        _, action = _bootstrap_planned(store, context)
        round_record, authority, policy, capability_ids = _eligible_round(store, action)
        authorized = store.authorize_for_staging(
            round_record,
            authority_decision=authority,
            policy_decision=policy,
            capability_ids=capability_ids,
            expected_transaction_version=1,
        )
        assert authorized.transaction.state is TransactionState.AUTHORIZED_TO_STAGE
        assert authorized.reservation is not None
        assert authorized.reservation.state is CapabilityReservationState.RESERVED

        lease_result = store.acquire_staging_lease(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            lease_id="lease:stage",
            worker_id="worker:stage",
            acquired_at=_NOW + timedelta(seconds=3),
            expires_at=_NOW + timedelta(minutes=5),
            expected_transaction_version=2,
        )
        assert lease_result.disposition is EnforcedStoreDisposition.STAGE_NOW
        assert lease_result.lease.fencing_token == 1

        inspection = InspectionPermit.create(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            normalized_action_digest=canonical_digest(action),
            proposal_ref=canonical_digest(_proposal(action)),
            adapter_manifest_digest=action.adapter_manifest_digest,
            authorization_round_id=round_record.round_id,
            authorization_round_digest=round_record.round_digest,
            lease_id=lease_result.lease.lease_id,
            worker_id=lease_result.lease.worker_id,
            fencing_token=lease_result.lease.fencing_token,
            issued_at=_NOW + timedelta(seconds=4),
            deadline=lease_result.lease.expires_at,
        )
        plan = _effect_plan(action, plan_id="plan:test")
        stage_permit = StagePermit.create(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            normalized_action_digest=canonical_digest(action),
            adapter_manifest_digest=action.adapter_manifest_digest,
            authorization_round_id=round_record.round_id,
            authorization_round_digest=round_record.round_digest,
            inspection_permit_digest=inspection.permit_digest,
            inspection_permit_ref=canonical_digest(inspection),
            plan_digest=canonical_digest(plan),
            plan_ref=canonical_digest(plan),
            stage_id="stage:test",
            lease_id=lease_result.lease.lease_id,
            worker_id=lease_result.lease.worker_id,
            fencing_token=lease_result.lease.fencing_token,
            target_version_guard="version:before",
            issued_at=_NOW + timedelta(seconds=5),
            deadline=lease_result.lease.expires_at,
        )
        material = StageMaterialRecord(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            stage_id=stage_permit.stage_id,
            lease_id=stage_permit.lease_id,
            fencing_token=stage_permit.fencing_token,
            intent_hash=action.intent_hash,
            normalized_action_digest=canonical_digest(action),
            adapter_manifest_digest=action.adapter_manifest_digest,
            plan_digest=stage_permit.plan_digest,
            plan_ref=stage_permit.plan_ref,
            inspection_permit_digest=inspection.permit_digest,
            inspection_permit_ref=canonical_digest(inspection),
            stage_permit_digest=stage_permit.permit_digest,
            stage_permit_ref=canonical_digest(stage_permit),
            state=StageMaterialState.ALLOCATED,
            target_version_guard=stage_permit.target_version_guard,
            version=0,
            created_at=_NOW + timedelta(seconds=5),
            updated_at=_NOW + timedelta(seconds=5),
        )
        store.allocate_stage_material(
            material,
            inspection_permit=inspection,
            stage_permit=stage_permit,
        )
        staged = store.record_staged_material(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_material_version=0,
            base_state_digest=_digest("base"),
            staged_effect_ref=_digest("staged-effect"),
            recorded_at=_NOW + timedelta(seconds=6),
        )
        assert staged.transaction.state is TransactionState.STAGING
        executed = store.record_stage_execution(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_material_version=1,
            expected_transaction_version=3,
            staged_receipt_ref=_digest("staged-receipt"),
            staged_state_digest=_digest("staged-state"),
            recorded_at=_NOW + timedelta(seconds=7),
        )
        assert executed.material.state is StageMaterialState.EXECUTED
        assert executed.transaction.state is TransactionState.STAGED
        verification_permit = VerificationPermit.create(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            normalized_action_digest=canonical_digest(action),
            adapter_manifest_digest=action.adapter_manifest_digest,
            authorization_round_id=round_record.round_id,
            authorization_round_digest=round_record.round_digest,
            lease_id=lease_result.lease.lease_id,
            worker_id=lease_result.lease.worker_id,
            fencing_token=lease_result.lease.fencing_token,
            phase=VerificationPhase.STAGED,
            subject_ref=_digest("staged-receipt"),
            authority_permit_digest=stage_permit.permit_digest,
            authority_permit_ref=canonical_digest(stage_permit),
            subject_permit_digest=stage_permit.permit_digest,
            subject_permit_ref=canonical_digest(stage_permit),
            issued_at=_NOW + timedelta(seconds=8),
            deadline=lease_result.lease.expires_at,
        )
        verified = store.record_stage_verification(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_material_version=2,
            expected_transaction_version=4,
            verification_permit=verification_permit,
            verification_permit_ref=canonical_digest(verification_permit),
            verification_ref=_digest("staged-verification"),
            passed=True,
            recorded_at=_NOW + timedelta(seconds=8),
        )
        assert verified.material.state is StageMaterialState.VERIFIED
        assert verified.transaction.state is TransactionState.STAGE_VERIFIED

    with SQLiteEnforcedTransactionStore(path) as reopened:
        assert (
            reopened.get_stage_material(
                tenant_id=context.tenant_id,
                transaction_id="transaction:test",
            ).state
            is StageMaterialState.VERIFIED
        )
        assert (
            reopened.get_enforced_transaction(
                context.tenant_id,
                "transaction:test",
            ).state
            is TransactionState.STAGE_VERIFIED
        )


@pytest.mark.parametrize(
    ("classification", "expected_state"),
    [
        (ReconciliationOutcome.PARTIAL_OR_INVALID, CommitDispatchState.PARTIAL_OR_INVALID),
        (ReconciliationOutcome.UNKNOWN, CommitDispatchState.IN_DOUBT),
    ],
)
def test_effect_receipt_does_not_imply_commit(
    tmp_path: Path,
    classification: ReconciliationOutcome,
    expected_state: CommitDispatchState,
) -> None:
    path = tmp_path / f"receipt-{classification.value}.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        action, stage, capability_ids = _stage_to_verified(store, context)
        _begin_dispatch(store, action, stage, capability_ids)
        receipt = _digest(f"effect-receipt:{classification.value}")
        attached = store.attach_receipt(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_dispatch_version=0,
            effect_receipt_ref=receipt,
            evidence_refs=(receipt,),
            recorded_at=_NOW + timedelta(seconds=12),
        )
        result = store.classify_dispatch_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_dispatch_version=attached.dispatch.version,
            expected_transaction_version=7,
            classification=classification,
            effect_receipt_ref=receipt,
            evidence_refs=(receipt, _digest(f"observation:{classification.value}")),
            reason_code=f"{classification.value}_OBSERVED",
            recorded_at=_NOW + timedelta(seconds=13),
            recovery_timeout=timedelta(minutes=10),
        )
        assert result.dispatch.state is expected_state
        assert result.dispatch.effect_receipt_ref == receipt
        assert result.dispatch.committed_verification_ref is None
        assert result.transaction.state is (
            TransactionState.FAILED
            if classification is ReconciliationOutcome.PARTIAL_OR_INVALID
            else TransactionState.IN_DOUBT
        )
        retry_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "expected_dispatch_version": attached.dispatch.version,
            "expected_transaction_version": 7,
            "classification": classification,
            "effect_receipt_ref": receipt,
            "evidence_refs": (
                receipt,
                _digest(f"observation:{classification.value}"),
            ),
            "reason_code": f"{classification.value}_OBSERVED",
            "recorded_at": _NOW + timedelta(seconds=13),
            "recovery_timeout": timedelta(minutes=10),
        }
        assert (
            store.classify_dispatch_outcome(**retry_arguments).disposition  # type: ignore[arg-type]
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        mutations: tuple[dict[str, object], ...] = (
            {"reason_code": "CHANGED_REASON"},
            {"evidence_refs": (_digest("changed-evidence"),)},
            {"effect_receipt_ref": _digest("changed-receipt")},
            {"committed_verification_ref": _digest("forged-verification")},
            {"no_effect_evidence_ref": _digest("forged-absence")},
            {"classification": ReconciliationOutcome.COMMITTED},
            {"recorded_at": _NOW + timedelta(seconds=14)},
        )
        for mutation in mutations:
            with pytest.raises(AgentKernelError):
                store.classify_dispatch_outcome(  # type: ignore[arg-type]
                    **{**retry_arguments, **mutation}
                )


def test_committed_classification_persists_semantic_verification_permit(
    tmp_path: Path,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(tmp_path / "committed-verification.db") as store:
        action, stage, capability_ids = _stage_to_verified(store, context)
        dispatch = _begin_dispatch(store, action, stage, capability_ids)
        effect_receipt_ref = _digest("effect-receipt:committed")
        attached = store.attach_receipt(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_dispatch_version=0,
            effect_receipt_ref=effect_receipt_ref,
            evidence_refs=(_digest("receipt-observed"),),
            recorded_at=_NOW + timedelta(seconds=12),
        )
        assert attached.dispatch.state is CommitDispatchState.DISPATCHED
        verification_permit = VerificationPermit.create(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            normalized_action_digest=canonical_digest(action),
            adapter_manifest_digest=action.adapter_manifest_digest,
            authorization_round_id=dispatch.permit.authorization_round_id,
            authorization_round_digest=dispatch.permit.authorization_round_digest,
            lease_id=dispatch.permit.lease_id,
            worker_id=dispatch.permit.worker_id,
            fencing_token=dispatch.permit.fencing_token,
            phase=VerificationPhase.COMMITTED,
            subject_ref=effect_receipt_ref,
            authority_permit_digest=dispatch.permit.permit_digest,
            authority_permit_ref=dispatch.permit_ref,
            subject_permit_digest=dispatch.permit.permit_digest,
            subject_permit_ref=dispatch.permit_ref,
            issued_at=_NOW + timedelta(seconds=12),
            deadline=dispatch.permit.deadline,
        )
        verification_permit_ref = canonical_digest(verification_permit)
        verification_ref = _digest("committed-verification-report")
        committed = store.classify_dispatch_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_dispatch_version=1,
            expected_transaction_version=7,
            classification=ReconciliationOutcome.COMMITTED,
            evidence_refs=(verification_ref,),
            recorded_at=_NOW + timedelta(seconds=13),
            effect_receipt_ref=effect_receipt_ref,
            committed_verification_permit=verification_permit,
            committed_verification_permit_ref=verification_permit_ref,
            committed_verification_ref=verification_ref,
        )
        assert committed.dispatch.state is CommitDispatchState.COMMITTED
        assert (
            committed.dispatch.committed_verification_permit_digest
            == verification_permit.permit_digest
        )
        assert committed.outcome.committed_verification_permit_ref == verification_permit_ref
        assert verification_permit.permit_digest in committed.outcome.evidence_refs
        assert verification_permit_ref in committed.outcome.evidence_refs
        assert verification_ref in committed.outcome.evidence_refs
        assert (
            store.classify_dispatch_outcome(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                expected_dispatch_version=1,
                expected_transaction_version=7,
                classification=ReconciliationOutcome.COMMITTED,
                evidence_refs=(verification_ref,),
                recorded_at=_NOW + timedelta(seconds=13),
                effect_receipt_ref=effect_receipt_ref,
                committed_verification_permit=verification_permit,
                committed_verification_permit_ref=verification_permit_ref,
                committed_verification_ref=verification_ref,
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        with pytest.raises(AgentKernelError):
            store.classify_dispatch_outcome(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                expected_dispatch_version=1,
                expected_transaction_version=7,
                classification=ReconciliationOutcome.COMMITTED,
                evidence_refs=(_digest("forged-report"),),
                recorded_at=_NOW + timedelta(seconds=13),
                effect_receipt_ref=effect_receipt_ref,
                committed_verification_permit=verification_permit,
                committed_verification_permit_ref=verification_permit_ref,
                committed_verification_ref=_digest("forged-report"),
            )


@pytest.mark.parametrize("surface", ["dispatch", "outcome"])
def test_committed_verification_projection_tampering_fails_closed(
    tmp_path: Path,
    surface: str,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(
        tmp_path / f"committed-verification-tamper-{surface}.db"
    ) as store:
        action, stage, capability_ids = _stage_to_verified(store, context)
        dispatch = _begin_dispatch(store, action, stage, capability_ids)
        effect_receipt_ref = _digest(f"effect-receipt:tamper:{surface}")
        verification_permit = VerificationPermit.create(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            normalized_action_digest=canonical_digest(action),
            adapter_manifest_digest=action.adapter_manifest_digest,
            authorization_round_id=dispatch.permit.authorization_round_id,
            authorization_round_digest=dispatch.permit.authorization_round_digest,
            lease_id=dispatch.permit.lease_id,
            worker_id=dispatch.permit.worker_id,
            fencing_token=dispatch.permit.fencing_token,
            phase=VerificationPhase.COMMITTED,
            subject_ref=effect_receipt_ref,
            authority_permit_digest=dispatch.permit.permit_digest,
            authority_permit_ref=dispatch.permit_ref,
            subject_permit_digest=dispatch.permit.permit_digest,
            subject_permit_ref=dispatch.permit_ref,
            issued_at=_NOW + timedelta(seconds=12),
            deadline=dispatch.permit.deadline,
        )
        verification_permit_ref = canonical_digest(verification_permit)
        verification_ref = _digest(f"committed-verification-report:{surface}")
        store.classify_dispatch_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_dispatch_version=0,
            expected_transaction_version=7,
            classification=ReconciliationOutcome.COMMITTED,
            evidence_refs=(verification_ref,),
            recorded_at=_NOW + timedelta(seconds=13),
            effect_receipt_ref=effect_receipt_ref,
            committed_verification_permit=verification_permit,
            committed_verification_permit_ref=verification_permit_ref,
            committed_verification_ref=verification_ref,
        )

        if surface == "dispatch":
            store._connection.execute(
                "UPDATE enforced_commit_dispatches "
                "SET committed_verification_ref = ? WHERE tenant_id = ? AND transaction_id = ?",
                (_digest("forged:dispatch:verification"), action.tenant_id, action.transaction_id),
            )
        else:
            store._connection.execute("DROP TRIGGER enforced_dispatch_outcomes_no_update")
            store._connection.execute(
                "UPDATE enforced_dispatch_outcomes "
                "SET committed_verification_ref = ? WHERE tenant_id = ? AND transaction_id = ? "
                "AND classification = 'COMMITTED'",
                (_digest("forged:outcome:verification"), action.tenant_id, action.transaction_id),
            )

        with pytest.raises(AgentKernelError) as tampered:
            store.get_commit_dispatch(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
        assert tampered.value.code is ErrorCode.INTEGRITY_ERROR


def test_reconciliation_committed_verification_projection_tampering_fails_closed(
    tmp_path: Path,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(
        tmp_path / "reconciliation-verification-tamper.db"
    ) as store:
        action, proposed = _start_unknown_reconciliation(store, context)
        work = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
        )
        dispatch = store.get_commit_dispatch(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        assert work.permit is not None
        assert work.permit_ref is not None
        effect_receipt_ref = _digest("reconciliation:effect-receipt:committed")
        verification_permit = VerificationPermit.create(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            intent_hash=action.intent_hash,
            normalized_action_digest=canonical_digest(action),
            adapter_manifest_digest=action.adapter_manifest_digest,
            authorization_round_id=work.permit.authorization_round_id,
            authorization_round_digest=work.permit.authorization_round_digest,
            lease_id=work.permit.lease_id,
            worker_id=work.permit.worker_id,
            fencing_token=work.permit.fencing_token,
            phase=VerificationPhase.COMMITTED,
            subject_ref=effect_receipt_ref,
            authority_permit_digest=work.permit.permit_digest,
            authority_permit_ref=work.permit_ref,
            subject_permit_digest=dispatch.permit.permit_digest,
            subject_permit_ref=dispatch.permit_ref,
            issued_at=_NOW + timedelta(seconds=18),
            deadline=work.permit.deadline.astimezone(UTC),
        )
        verification_permit_ref = canonical_digest(verification_permit)
        verification_ref = _digest("reconciliation:committed:verification-report")
        committed = store.finish_reconciliation(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_attempt_version=0,
            outcome=ReconciliationOutcome.COMMITTED,
            evidence_refs=(verification_ref,),
            operation_evidence_ref=verification_ref,
            completed_at=_NOW + timedelta(seconds=19),
            effect_receipt_ref=effect_receipt_ref,
            committed_verification_permit=verification_permit,
            committed_verification_permit_ref=verification_permit_ref,
            committed_verification_ref=verification_ref,
        )
        assert committed.transaction.state is TransactionState.COMMITTED
        assert (
            committed.attempt.committed_verification_permit_digest
            == verification_permit.permit_digest
        )

        store._connection.execute(
            "UPDATE enforced_reconciliation_attempts "
            "SET committed_verification_ref = ? WHERE tenant_id = ? AND transaction_id = ? "
            "AND recovery_id = ? AND attempt = 1",
            (
                _digest("forged:reconciliation:verification"),
                action.tenant_id,
                action.transaction_id,
                proposed.recovery_id,
            ),
        )
        with pytest.raises(AgentKernelError) as tampered:
            store.get_reconciliation_attempt(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
                attempt=1,
            )
        assert tampered.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize("tamper", ["idempotency", "approval-evidence", "late-approval"])
def test_commit_permit_tampering_fails_before_dispatch(
    tmp_path: Path,
    tamper: str,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(tmp_path / f"commit-{tamper}.db") as store:
        action, stage, capability_ids = _stage_to_verified(store, context)
        kwargs: dict[str, object] = {}
        if tamper == "idempotency":
            kwargs["idempotency_key"] = "idempotency:forged"
        elif tamper == "approval-evidence":
            kwargs["approval_evidence_ref"] = _digest("forged-approval-evidence")
        else:
            kwargs.update(
                approval_required=True,
                approval_id="approval:late",
                approval_evidence_ref=_digest("no-approval"),
            )
        with pytest.raises(AgentKernelError) as captured:
            _begin_dispatch(store, action, stage, capability_ids, **kwargs)  # type: ignore[arg-type]
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR
        assert (
            store.get_enforced_transaction(
                action.tenant_id,
                action.transaction_id,
            ).state
            is TransactionState.READY_TO_COMMIT
        )
        reservation = store._read_capability_chain(
            tenant_id=action.tenant_id,
            goal_id=action.goal_id,
            run_id=action.run_id,
            intent_hash=action.intent_hash,
        )
        assert reservation is not None
        assert reservation.state is CapabilityReservationState.RESERVED
        assert (
            store._connection.execute("SELECT COUNT(*) FROM enforced_commit_dispatches").fetchone()[
                0
            ]
            == 0
        )


def test_precommit_denial_is_audited_and_aborts_before_dispatch(tmp_path: Path) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(tmp_path / "precommit-denied.db") as store:
        action, _, _ = _stage_to_verified(store, context)
        store.apply_control_transition(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_version=5,
            transition_event=TransitionEvent.NO_APPROVAL_REQUIRED,
            recorded_at=_NOW + timedelta(seconds=9),
            evidence_refs=(_digest("no-approval"),),
        )
        head = store.list_intent_history(
            tenant_id=action.tenant_id,
            intent_hash=action.intent_hash,
        )[-1]
        evaluated_at = _NOW + timedelta(seconds=10)
        authority, policy = _strict_decisions(
            action,
            capability_ids=(),
            label="precommit-denied",
            evaluated_at=evaluated_at,
            modes=("commit_reversible",),
            authorization_verdict=AuthorizationVerdict.DENIED,
        )
        record = AuthorizationRoundRecord.create(
            tenant_id=action.tenant_id,
            controlled_transaction_id=action.transaction_id,
            subject_transaction_id=action.transaction_id,
            subject_intent_hash=action.intent_hash,
            subject_normalized_action_digest=canonical_digest(action),
            round_id="authorization:precommit:denied",
            purpose=AuthorizationRoundPurpose.PRECOMMIT,
            verdict=AuthorizationVerdict.DENIED,
            authority_snapshot_id=authority.authority_snapshot_id,
            authority_snapshot_digest=authority.authority_snapshot_digest,
            **_round_artifacts("precommit-denied"),
            authority_decision_id="decision:authority:precommit-denied",
            authority_decision_record_digest=decision_snapshot_digest(
                tenant_id=action.tenant_id,
                kind=DecisionKind.AUTHORITY,
                decision_id="decision:authority:precommit-denied",
                transaction_id=action.transaction_id,
                intent_hash=action.intent_hash,
                decision=authority,
            ),
            authority_decision_digest=authority.decision_digest,
            policy_decision_id="decision:policy:precommit-denied",
            policy_decision_record_digest=decision_snapshot_digest(
                tenant_id=action.tenant_id,
                kind=DecisionKind.POLICY,
                decision_id="decision:policy:precommit-denied",
                transaction_id=action.transaction_id,
                intent_hash=action.intent_hash,
                decision=policy,
            ),
            policy_decision_digest=policy.aggregate_digest,
            policy_snapshot_digest=policy.policy_snapshot.snapshot_digest,
            owner_version=head.owner_version,
            owner_history_sequence=head.sequence,
            owner_history_digest=head.history_digest,
            reason_code=authority.reason_code.value,
            evaluated_at=evaluated_at,
        )
        denied = store.record_precommit_denial(
            record,
            authority_decision=authority,
            policy_decision=policy,
            expected_transaction_version=6,
            recovery_timeout=timedelta(minutes=10),
        )
        assert denied.transaction.state is TransactionState.ABORTING
        assert denied.transaction.capability_reservation_digest is not None
        assert (
            store.record_precommit_denial(
                record,
                authority_decision=authority,
                policy_decision=policy,
                expected_transaction_version=6,
                recovery_timeout=timedelta(minutes=10),
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        with store._immediate():
            current = store._get_enforced_transaction_tx(
                action.tenant_id,
                action.transaction_id,
            )
            store._apply_transition_tx(
                current,
                expected_version=7,
                transition_event=TransitionEvent.STAGING_DISCARD_FAILED,
                recorded_at=_NOW + timedelta(seconds=11),
                evidence_refs=(_digest("discard-failed"),),
                reason_code="DISCARD_FAILED",
            )
        with pytest.raises(AgentKernelError) as stale_denial:
            store.record_precommit_denial(
                record,
                authority_decision=authority,
                policy_decision=policy,
                expected_transaction_version=6,
                recovery_timeout=timedelta(minutes=10),
            )
        assert stale_denial.value.code is ErrorCode.VERSION_CONFLICT
        assert (
            store._connection.execute("SELECT COUNT(*) FROM enforced_commit_dispatches").fetchone()[
                0
            ]
            == 0
        )


def test_no_effect_stage_discard_requires_separate_fenced_recovery(tmp_path: Path) -> None:
    path = tmp_path / "discard-recovery.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        action, stage, capability_ids = _stage_to_verified(store, context)
        _begin_dispatch(store, action, stage, capability_ids)
        no_effect = _digest("dispatch:no-effect")
        classified = store.classify_dispatch_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_dispatch_version=0,
            expected_transaction_version=7,
            classification=ReconciliationOutcome.NO_EFFECT,
            evidence_refs=(no_effect,),
            no_effect_evidence_ref=no_effect,
            recorded_at=_NOW + timedelta(seconds=13),
            recovery_timeout=timedelta(minutes=10),
        )
        assert classified.transaction.state is TransactionState.ABORTING
        proposed = _authorize_recovery_work(
            store,
            context,
            action,
            stage,
            kind=RecoveryWorkKind.DISCARD_STAGING,
        )
        claim_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": proposed.recovery_id,
            "expected_work_version": 0,
            "lease_id": "lease:recovery:discard",
            "worker_id": "worker:recovery",
            "acquired_at": _NOW + timedelta(seconds=17),
            "expires_at": _NOW + timedelta(minutes=5),
        }
        preview = store.preview_recovery_claim(**claim_arguments)  # type: ignore[arg-type]
        assert (
            store.get_recovery_work(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
            ).state
            is RecoveryWorkState.PENDING
        )
        claimed = store.claim_recovery(  # type: ignore[arg-type]
            **claim_arguments,
            permit=preview.permit,
            permit_ref=preview.permit_ref,
        )
        assert claimed.disposition is EnforcedStoreDisposition.RECOVERY_NOW
        assert claimed.work.state is RecoveryWorkState.RUNNING
        assert claimed.work.reservation_version == 1
        retry = store.claim_recovery(  # type: ignore[arg-type]
            **claim_arguments,
            permit=preview.permit,
            permit_ref=preview.permit_ref,
        )
        assert retry.disposition is EnforcedStoreDisposition.EXACT_RETRY
        completion_refs = tuple(
            sorted((_digest("stage:discarded:wrapper"), _digest("stage:discarded:operation")))
        )
        wrapper_ref, operation_ref = completion_refs
        finished = store.finish_recovery(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=1,
            succeeded=True,
            evidence_refs=completion_refs,
            operation_evidence_ref=operation_ref,
            completed_at=_NOW + timedelta(seconds=18),
        )
        assert finished.work.state is RecoveryWorkState.SUCCEEDED
        assert finished.work.version == 2
        assert finished.transaction.state is TransactionState.ABORTED
        assert finished.lease.released_at == _NOW + timedelta(seconds=18)
        assert finished.lease.version == 1
        finished_stage = store.get_stage_material(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        assert finished_stage.version == 4
        assert finished_stage.discard_evidence_ref == operation_ref
        assert operation_ref != wrapper_ref
        retry_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": proposed.recovery_id,
            "expected_work_version": 1,
            "succeeded": True,
            "evidence_refs": completion_refs,
            "operation_evidence_ref": operation_ref,
            "completed_at": _NOW + timedelta(seconds=18),
        }
        assert (
            store.finish_recovery(**retry_arguments).disposition  # type: ignore[arg-type]
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        with pytest.raises(AgentKernelError) as stale_completion:
            store.finish_recovery(  # type: ignore[arg-type]
                **{**retry_arguments, "expected_work_version": 999}
            )
        assert stale_completion.value.code is ErrorCode.VERSION_CONFLICT
        for mutation in (
            {"evidence_refs": (_digest("changed-discard-evidence"),)},
            {"operation_evidence_ref": wrapper_ref},
            {"completed_at": _NOW + timedelta(seconds=19)},
            {"succeeded": False, "reason_code": "CHANGED_STATUS"},
            {"reason_code": "FORGED_REASON"},
        ):
            with pytest.raises(AgentKernelError):
                store.finish_recovery(  # type: ignore[arg-type]
                    **{**retry_arguments, **mutation}
                )

    with SQLiteEnforcedTransactionStore(path) as reopened:
        assert (
            reopened.get_recovery_work(
                tenant_id=context.tenant_id,
                transaction_id="transaction:test",
                recovery_id="recovery:discard_staging:test",
            ).state
            is RecoveryWorkState.SUCCEEDED
        )


def test_late_discard_report_is_fenced_exact_and_preserves_operation_evidence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "late-discard.db"
    context = _context()
    authority_deadline = _NOW + timedelta(seconds=18)
    refs = tuple(sorted((_digest("late:observation"), _digest("late:operation-report"))))
    observation_ref, operation_ref = refs
    reason_code = "LATE_RECOVERY_REPORT"
    with SQLiteEnforcedTransactionStore(path) as store:
        action, _, running = _claim_discard_for_late_report(
            store,
            context,
            authority_valid_until=authority_deadline,
        )
        assert running.lease_id is not None
        lease = store.get_worker_lease(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            lease_id=running.lease_id,
        )
        with pytest.raises(AgentKernelError) as renewal:
            store.renew_worker_lease(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                lease_id=lease.lease_id,
                expected_version=lease.version,
                renewed_at=_NOW + timedelta(seconds=17, milliseconds=500),
                expires_at=_NOW + timedelta(minutes=6),
            )
        assert renewal.value.code is ErrorCode.AUTHORITY_MISSING

        with pytest.raises(AgentKernelError) as normal_finish:
            store.finish_recovery(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=running.recovery_id,
                expected_work_version=1,
                succeeded=True,
                evidence_refs=(operation_ref,),
                operation_evidence_ref=operation_ref,
                completed_at=authority_deadline,
            )
        assert normal_finish.value.code is ErrorCode.DEADLINE_EXCEEDED

        late = store.record_late_recovery_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=running.recovery_id,
            expected_work_version=1,
            evidence_refs=(operation_ref, observation_ref),
            operation_evidence_ref=operation_ref,
            reported_at=authority_deadline,
            reason_code=reason_code,
        )
        assert late.work.state is RecoveryWorkState.REVIEW_REQUIRED
        assert late.transaction.state is TransactionState.RECOVERY_FAILED
        assert late.lease.released_at == authority_deadline
        assert late.reconciliation_attempt is None
        assert (
            store.get_stage_material(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            ).discard_evidence_ref
            == operation_ref
        )
        assert operation_ref != observation_ref
        assert (
            store.get_active_recovery_work(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            == ()
        )

        retry = store.record_late_recovery_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=running.recovery_id,
            expected_work_version=1,
            evidence_refs=(observation_ref, operation_ref),
            operation_evidence_ref=operation_ref,
            reported_at=authority_deadline,
            reason_code=reason_code,
        )
        assert retry.disposition is EnforcedStoreDisposition.EXACT_RETRY
        handoff = store.get_recovery_action_handoff(
            tenant_id=action.tenant_id,
            target_transaction_id=action.transaction_id,
            recovery_id=running.recovery_id,
        )
        assert handoff is not None
        assert handoff.closed_at == authority_deadline
        assert handoff.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.AVAILABLE
        assert handoff.failure_evidence_ref == operation_ref
        with pytest.raises(AgentKernelError) as stale_late:
            store.record_late_recovery_outcome(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=running.recovery_id,
                expected_work_version=999,
                evidence_refs=(observation_ref, operation_ref),
                operation_evidence_ref=operation_ref,
                reported_at=authority_deadline,
                reason_code=reason_code,
            )
        assert stale_late.value.code is ErrorCode.VERSION_CONFLICT
        with pytest.raises(AgentKernelError) as changed_subset:
            store.record_late_recovery_outcome(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=running.recovery_id,
                expected_work_version=1,
                evidence_refs=(operation_ref,),
                operation_evidence_ref=operation_ref,
                reported_at=authority_deadline,
                reason_code=reason_code,
            )
        assert changed_subset.value.code is ErrorCode.INTEGRITY_ERROR
        with pytest.raises(AgentKernelError) as changed_operation:
            store.record_late_recovery_outcome(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=running.recovery_id,
                expected_work_version=1,
                evidence_refs=(operation_ref, observation_ref),
                operation_evidence_ref=observation_ref,
                reported_at=authority_deadline,
                reason_code=reason_code,
            )
        assert changed_operation.value.code is ErrorCode.INTEGRITY_ERROR
        with pytest.raises(AgentKernelError):
            store.preview_recovery_reclaim(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=running.recovery_id,
                expected_work_version=2,
                lease_id="lease:forbidden-reclaim",
                worker_id="worker:forbidden-reclaim",
                acquired_at=authority_deadline + timedelta(seconds=1),
                expires_at=authority_deadline + timedelta(minutes=1),
            )

    with SQLiteEnforcedTransactionStore(path) as reopened:
        assert (
            reopened.get_recovery_work(
                tenant_id=context.tenant_id,
                transaction_id="transaction:test",
                recovery_id="recovery:discard_staging:test",
            ).state
            is RecoveryWorkState.REVIEW_REQUIRED
        )


@pytest.mark.parametrize(
    "kind",
    [RecoveryWorkKind.ROLLBACK, RecoveryWorkKind.COMPENSATE],
)
def test_pending_effect_revalidation_deadline_settles_target_and_handoff(
    tmp_path: Path,
    kind: RecoveryWorkKind,
) -> None:
    context = _context()
    path = tmp_path / f"pending-deadline-{kind.value.lower()}.db"
    deadline = _NOW + timedelta(seconds=20)
    with SQLiteEnforcedTransactionStore(path) as store:
        action, work = _pending_effect_recovery(
            store,
            context,
            kind=kind,
            authority_valid_until=deadline,
        )
        evidence_ref = _digest(f"pending-deadline:{kind.value}")
        arguments = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": work.recovery_id,
            "expected_work_version": work.version,
            "target_state": RecoveryWorkState.REVIEW_REQUIRED,
            "evidence_refs": (evidence_ref,),
            "reason_code": ErrorCode.DEADLINE_EXCEEDED.value,
            "recorded_at": deadline,
            "handoff_failure_evidence_ref": evidence_ref,
            "handoff_failure_evidence_status": (RecoveryHandoffFailureEvidenceStatus.AVAILABLE),
            "handoff_failure_reason_code": ErrorCode.DEADLINE_EXCEEDED.value,
        }
        settled = store.fail_recovery_revalidation(**arguments)  # type: ignore[arg-type]
        assert settled.work.state is RecoveryWorkState.REVIEW_REQUIRED
        assert (
            store.get_enforced_transaction(action.tenant_id, action.transaction_id).state
            is TransactionState.RECOVERY_FAILED
        )
        recovery_action = store.get_normalized_action(
            work.tenant_id,
            work.recovery_action_transaction_id,
        ).action
        assert (
            store.get_capability_chain(
                tenant_id=work.tenant_id,
                goal_id=recovery_action.goal_id,
                run_id=recovery_action.run_id,
                intent_hash=work.recovery_action_intent_hash,
            ).state
            is CapabilityReservationState.RELEASED
        )
        handoff = store.get_recovery_action_handoff(
            tenant_id=work.tenant_id,
            target_transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert handoff is not None
        assert handoff.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.AVAILABLE
        assert handoff.failure_evidence_ref == evidence_ref
        assert (
            store.fail_recovery_revalidation(**arguments).disposition  # type: ignore[arg-type]
            is EnforcedStoreDisposition.EXACT_RETRY
        )

    with SQLiteEnforcedTransactionStore(path) as reopened:
        assert (
            reopened.get_enforced_transaction(context.tenant_id, action.transaction_id).state
            is TransactionState.RECOVERY_FAILED
        )


@pytest.mark.parametrize(
    "kind",
    [RecoveryWorkKind.ROLLBACK, RecoveryWorkKind.COMPENSATE],
)
def test_pending_effect_deadline_evidence_outage_is_terminal_and_exact(
    tmp_path: Path,
    kind: RecoveryWorkKind,
) -> None:
    context = _context()
    path = tmp_path / f"pending-unavailable-{kind.value.lower()}.db"
    deadline = _NOW + timedelta(seconds=20)
    with SQLiteEnforcedTransactionStore(path) as store:
        action, work = _pending_effect_recovery(
            store,
            context,
            kind=kind,
            authority_valid_until=deadline,
        )
        supporting_ref = _digest(f"pending-unavailable:{kind.value}")
        reason_code = f"{ErrorCode.EVIDENCE_UNAVAILABLE.value}:ARTIFACT_STORE_OUTAGE"
        arguments = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": work.recovery_id,
            "expected_work_version": work.version,
            "boundary": "RECOVERY_DEADLINE",
            "supporting_refs": (supporting_ref,),
            "reported_at": deadline,
            "reason_code": reason_code,
        }
        settled = store.terminalize_recovery_evidence_unavailable(  # type: ignore[arg-type]
            **arguments
        )
        assert settled.work.state is RecoveryWorkState.REVIEW_REQUIRED
        assert settled.disposition is EnforcedStoreDisposition.REVIEW_REQUIRED
        assert (
            store.get_enforced_transaction(action.tenant_id, action.transaction_id).state
            is TransactionState.RECOVERY_FAILED
        )
        handoff = store.get_recovery_action_handoff(
            tenant_id=work.tenant_id,
            target_transaction_id=work.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert handoff is not None
        assert handoff.failure_evidence_status is RecoveryHandoffFailureEvidenceStatus.UNAVAILABLE
        assert handoff.failure_evidence_ref is None
        assert handoff.failure_reason_code == reason_code
        assert (
            store.terminalize_recovery_evidence_unavailable(  # type: ignore[arg-type]
                **arguments
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )

    with SQLiteEnforcedTransactionStore(path) as reopened:
        assert (
            reopened.get_enforced_transaction(context.tenant_id, action.transaction_id).state
            is TransactionState.RECOVERY_FAILED
        )


@pytest.mark.parametrize(
    ("kind", "expected_state"),
    [
        (RecoveryWorkKind.ROLLBACK, TransactionState.RECOVERY_FAILED),
        (RecoveryWorkKind.COMPENSATE, TransactionState.COMPENSATION_FAILED),
    ],
)
def test_claimed_effect_setup_failure_settles_target_and_is_exact(
    tmp_path: Path,
    kind: RecoveryWorkKind,
    expected_state: TransactionState,
) -> None:
    context = _context()
    path = tmp_path / f"setup-failure-{kind.value.lower()}.db"
    with SQLiteEnforcedTransactionStore(path) as store:
        action, proposed = _pending_effect_recovery(store, context, kind=kind)
        preview = store.preview_recovery_claim(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=proposed.version,
            lease_id=f"lease:setup:{kind.value.lower()}",
            worker_id="worker:setup",
            acquired_at=_NOW + timedelta(seconds=17),
            expires_at=_NOW + timedelta(minutes=5),
        )
        claimed = store.claim_recovery(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=proposed.version,
            lease_id=preview.lease.lease_id,
            worker_id=preview.lease.worker_id,
            acquired_at=preview.lease.acquired_at,
            expires_at=preview.lease.expires_at,
            permit=preview.permit,
            permit_ref=preview.permit_ref,
        ).work
        failure_ref = _digest(f"setup-failure:{kind.value}")
        arguments = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": claimed.recovery_id,
            "expected_work_version": claimed.version,
            "failure_evidence_ref": failure_ref,
            "reason_code": "RECOVERY_SETUP_FAILED",
            "recorded_at": _NOW + timedelta(seconds=18),
        }
        settled = store.fail_claimed_recovery_setup(**arguments)  # type: ignore[arg-type]
        assert settled.state is RecoveryWorkState.REVIEW_REQUIRED
        assert (
            store.get_enforced_transaction(action.tenant_id, action.transaction_id).state
            is expected_state
        )
        assert store.get_worker_lease(
            tenant_id=claimed.tenant_id,
            transaction_id=claimed.transaction_id,
            lease_id=claimed.lease_id,
        ).released_at == _NOW + timedelta(seconds=18)
        assert store.fail_claimed_recovery_setup(**arguments) == settled  # type: ignore[arg-type]

    with SQLiteEnforcedTransactionStore(path) as reopened:
        assert (
            reopened.get_enforced_transaction(context.tenant_id, action.transaction_id).state
            is expected_state
        )


@pytest.mark.parametrize(
    "kind",
    [RecoveryWorkKind.ROLLBACK, RecoveryWorkKind.COMPENSATE],
)
def test_recovery_completion_report_rejects_changed_operation_identity(
    tmp_path: Path,
    kind: RecoveryWorkKind,
) -> None:
    context = _context()
    path = tmp_path / f"completion-{kind.value.lower()}.db"
    with SQLiteEnforcedTransactionStore(path) as store:
        action, stage, capability_ids = _stage_to_verified(store, context)
        _begin_dispatch(store, action, stage, capability_ids)
        classified = store.classify_dispatch_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_dispatch_version=0,
            expected_transaction_version=7,
            classification=ReconciliationOutcome.PARTIAL_OR_INVALID,
            evidence_refs=(_digest(f"dispatch:partial:{kind.value}"),),
            reason_code="DISPATCH_PARTIAL_OR_INVALID",
            recorded_at=_NOW + timedelta(seconds=13),
            recovery_timeout=timedelta(minutes=10),
        )
        assert classified.transaction.state is TransactionState.FAILED
        proposed = _authorize_recovery_work(
            store,
            context,
            action,
            classified.dispatch,
            kind=kind,
        )
        preview = store.preview_recovery_claim(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=0,
            lease_id=f"lease:recovery:{kind.value.lower()}",
            worker_id="worker:recovery",
            acquired_at=_NOW + timedelta(seconds=17),
            expires_at=_NOW + timedelta(minutes=5),
        )
        claimed = store.claim_recovery(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=0,
            lease_id=preview.lease.lease_id,
            worker_id=preview.lease.worker_id,
            acquired_at=preview.lease.acquired_at,
            expires_at=preview.lease.expires_at,
            permit=preview.permit,
            permit_ref=preview.permit_ref,
        )
        refs = tuple(
            sorted(
                (
                    _digest(f"completion:{kind.value}:wrapper"),
                    _digest(f"completion:{kind.value}:operation"),
                )
            )
        )
        wrapper_ref, operation_ref = refs
        arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": proposed.recovery_id,
            "expected_work_version": claimed.work.version,
            "succeeded": True,
            "evidence_refs": refs,
            "operation_evidence_ref": operation_ref,
            "completed_at": _NOW + timedelta(seconds=18),
        }
        finished = store.finish_recovery(**arguments)  # type: ignore[arg-type]
        assert finished.work.state is RecoveryWorkState.SUCCEEDED
        assert (
            store.finish_recovery(**arguments).disposition  # type: ignore[arg-type]
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        with pytest.raises(AgentKernelError) as changed_operation:
            store.finish_recovery(  # type: ignore[arg-type]
                **{**arguments, "operation_evidence_ref": wrapper_ref}
            )
        assert changed_operation.value.code is ErrorCode.INTEGRITY_ERROR

    with SQLiteEnforcedTransactionStore(path) as reopened:
        assert (
            reopened.get_recovery_work(
                tenant_id=context.tenant_id,
                transaction_id="transaction:test",
                recovery_id=f"recovery:{kind.value.lower()}:test",
            ).state
            is RecoveryWorkState.SUCCEEDED
        )


def test_recovery_completion_report_rolls_back_atomically_on_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "completion-report-crash.db"
    context = _context()
    operation_ref = _digest("completion-crash:operation")
    with SQLiteEnforcedTransactionStore(path) as store:
        action, stage, running = _claim_discard_for_late_report(
            store,
            context,
            authority_valid_until=_NOW + timedelta(minutes=1),
        )

        def crash_before_commit(
            _store: SQLiteEnforcedTransactionStore,
            _work: RecoveryWorkRecord,
            *,
            released_at: datetime,
        ) -> object:
            del released_at
            raise RuntimeError("injected recovery completion crash")

        monkeypatch.setattr(
            SQLiteEnforcedTransactionStore,
            "_release_recovery_lease_tx",
            crash_before_commit,
        )
        with pytest.raises(RuntimeError, match="completion crash"):
            store.finish_recovery(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=running.recovery_id,
                expected_work_version=running.version,
                succeeded=True,
                evidence_refs=(operation_ref,),
                operation_evidence_ref=operation_ref,
                completed_at=_NOW + timedelta(seconds=18),
            )
        persisted = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=running.recovery_id,
        )
        assert persisted.state is RecoveryWorkState.RUNNING
        assert persisted.version == running.version
        assert (
            store._connection.execute(
                "SELECT COUNT(*) FROM enforced_recovery_completion_reports"
            ).fetchone()[0]
            == 0
        )
        assert (
            store.get_stage_material(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            == stage
        )
        assert persisted.lease_id is not None
        assert (
            store.get_worker_lease(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                lease_id=persisted.lease_id,
            ).released_at
            is None
        )


def test_late_recovery_report_rolls_back_atomically_on_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "late-report-crash.db"
    context = _context()
    authority_deadline = _NOW + timedelta(seconds=18)
    operation_ref = _digest("late-crash:operation")
    with SQLiteEnforcedTransactionStore(path) as store:
        action, _, running = _claim_discard_for_late_report(
            store,
            context,
            authority_valid_until=authority_deadline,
        )

        def crash_before_commit(
            _store: SQLiteEnforcedTransactionStore,
            _work: RecoveryWorkRecord,
            *,
            released_at: datetime,
        ) -> object:
            del released_at
            raise RuntimeError("injected late-report crash")

        monkeypatch.setattr(
            SQLiteEnforcedTransactionStore,
            "_release_recovery_lease_tx",
            crash_before_commit,
        )
        with pytest.raises(RuntimeError, match="late-report crash"):
            store.record_late_recovery_outcome(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=running.recovery_id,
                expected_work_version=1,
                evidence_refs=(operation_ref,),
                operation_evidence_ref=operation_ref,
                reported_at=authority_deadline,
                reason_code="LATE_RECOVERY_REPORT",
            )
        persisted = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=running.recovery_id,
        )
        assert persisted.state is RecoveryWorkState.RUNNING
        assert persisted.version == 1
        assert (
            store.get_enforced_transaction(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            ).state
            is TransactionState.ABORTING
        )
        assert (
            store._connection.execute(
                "SELECT COUNT(*) FROM enforced_late_recovery_reports"
            ).fetchone()[0]
            == 0
        )
        assert persisted.lease_id is not None
        assert (
            store.get_worker_lease(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                lease_id=persisted.lease_id,
            ).released_at
            is None
        )


def test_expired_recovery_reclaim_is_previewed_fenced_and_evidence_bound(
    tmp_path: Path,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(tmp_path / "recovery-reclaim.db") as store:
        action, stage, capability_ids = _stage_to_verified(store, context)
        _begin_dispatch(store, action, stage, capability_ids)
        absence = _digest("dispatch:no-effect:reclaim")
        store.classify_dispatch_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_dispatch_version=0,
            expected_transaction_version=7,
            classification=ReconciliationOutcome.NO_EFFECT,
            evidence_refs=(absence,),
            no_effect_evidence_ref=absence,
            recorded_at=_NOW + timedelta(seconds=13),
            recovery_timeout=timedelta(minutes=10),
        )
        proposed = _authorize_recovery_work(
            store,
            context,
            action,
            stage,
            kind=RecoveryWorkKind.DISCARD_STAGING,
        )
        initial_preview = store.preview_recovery_claim(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=0,
            lease_id="lease:recovery:discard:expired",
            worker_id="worker:recovery:expired",
            acquired_at=_NOW + timedelta(seconds=17),
            expires_at=_NOW + timedelta(seconds=18),
        )
        initial = store.claim_recovery(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=0,
            lease_id=initial_preview.lease.lease_id,
            worker_id=initial_preview.lease.worker_id,
            acquired_at=initial_preview.lease.acquired_at,
            expires_at=initial_preview.lease.expires_at,
            permit=initial_preview.permit,
            permit_ref=initial_preview.permit_ref,
        )
        before_preview = initial.work

        reclaim_preview = store.preview_recovery_reclaim(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=1,
            lease_id="lease:recovery:discard:replacement",
            worker_id="worker:recovery:replacement",
            acquired_at=_NOW + timedelta(seconds=19),
            expires_at=_NOW + timedelta(minutes=1),
        )
        assert reclaim_preview.work == before_preview
        assert reclaim_preview.lease.fencing_token > initial.lease.fencing_token
        assert (
            store.get_recovery_work(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
            )
            == before_preview
        )
        with pytest.raises(AgentKernelError) as absent_preview_lease:
            store.get_worker_lease(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                lease_id=reclaim_preview.lease.lease_id,
            )
        assert absent_preview_lease.value.code is ErrorCode.VALIDATION_ERROR

        expiry_evidence = _digest("recovery:discard:lease-expired")
        evidence_refs = tuple(
            sorted(
                {
                    initial_preview.permit_ref,
                    reclaim_preview.permit_ref,
                    expiry_evidence,
                }
            )
        )
        with pytest.raises(AgentKernelError) as stale_permit:
            store.reclaim_expired_recovery(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
                expected_work_version=1,
                lease_id=reclaim_preview.lease.lease_id,
                worker_id=reclaim_preview.lease.worker_id,
                acquired_at=reclaim_preview.lease.acquired_at,
                expires_at=reclaim_preview.lease.expires_at,
                permit=initial_preview.permit,
                permit_ref=initial_preview.permit_ref,
                evidence_refs=evidence_refs,
            )
        assert stale_permit.value.code is ErrorCode.INTEGRITY_ERROR
        with pytest.raises(AgentKernelError) as missing_history:
            store.reclaim_expired_recovery(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
                expected_work_version=1,
                lease_id=reclaim_preview.lease.lease_id,
                worker_id=reclaim_preview.lease.worker_id,
                acquired_at=reclaim_preview.lease.acquired_at,
                expires_at=reclaim_preview.lease.expires_at,
                permit=reclaim_preview.permit,
                permit_ref=reclaim_preview.permit_ref,
                evidence_refs=(reclaim_preview.permit_ref, expiry_evidence),
            )
        assert missing_history.value.code is ErrorCode.INTEGRITY_ERROR
        assert (
            store.get_recovery_work(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
            )
            == before_preview
        )

        reclaimed = store.reclaim_expired_recovery(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=1,
            lease_id=reclaim_preview.lease.lease_id,
            worker_id=reclaim_preview.lease.worker_id,
            acquired_at=reclaim_preview.lease.acquired_at,
            expires_at=reclaim_preview.lease.expires_at,
            permit=reclaim_preview.permit,
            permit_ref=reclaim_preview.permit_ref,
            evidence_refs=evidence_refs,
        )
        assert reclaimed.work.version == 2
        assert reclaimed.work.attempt == 2
        assert reclaimed.work.permit == reclaim_preview.permit
        assert reclaimed.work.evidence_refs == evidence_refs
        assert reclaimed.lease.fencing_token == reclaim_preview.lease.fencing_token
        assert (
            store.get_worker_lease(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                lease_id=initial.lease.lease_id,
            ).released_at
            == reclaim_preview.lease.acquired_at
        )
        assert (
            store.reclaim_expired_recovery(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
                expected_work_version=1,
                lease_id=reclaim_preview.lease.lease_id,
                worker_id=reclaim_preview.lease.worker_id,
                acquired_at=reclaim_preview.lease.acquired_at,
                expires_at=reclaim_preview.lease.expires_at,
                permit=reclaim_preview.permit,
                permit_ref=reclaim_preview.permit_ref,
                evidence_refs=evidence_refs,
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )


def test_late_reconciliation_before_start_stays_in_doubt_without_redispatch(
    tmp_path: Path,
) -> None:
    context = _context()
    authority_deadline = _NOW + timedelta(seconds=18)
    with SQLiteEnforcedTransactionStore(tmp_path / "late-reconcile-before-start.db") as store:
        action, work = _claim_unknown_reconciliation(
            store,
            context,
            authority_valid_until=authority_deadline,
        )
        with pytest.raises(AgentKernelError) as late_start:
            store.start_reconciliation(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=work.recovery_id,
                expected_work_version=1,
                evidence_refs=(_digest("late-reconcile:start"),),
                started_at=authority_deadline,
            )
        assert late_start.value.code is ErrorCode.DEADLINE_EXCEEDED
        report_ref = _digest("late-reconcile:before-start:report")
        late = store.record_late_recovery_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=work.recovery_id,
            expected_work_version=1,
            evidence_refs=(report_ref,),
            operation_evidence_ref=report_ref,
            reported_at=authority_deadline,
            reason_code="LATE_RECONCILIATION_REPORT",
        )
        assert late.reconciliation_attempt is None
        assert late.transaction.state is TransactionState.IN_DOUBT
        assert late.work.state is RecoveryWorkState.REVIEW_REQUIRED
        assert (
            store.list_reconciliation_attempts(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            == ()
        )
        assert (
            store.get_active_recovery_work(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            == ()
        )


def test_late_started_reconciliation_closes_unknown_without_retry(tmp_path: Path) -> None:
    context = _context()
    reported_at = _NOW + timedelta(minutes=5)
    with SQLiteEnforcedTransactionStore(tmp_path / "late-reconcile-started.db") as store:
        action, work = _start_unknown_reconciliation(store, context)
        with pytest.raises(AgentKernelError) as normal_finish:
            store.finish_reconciliation(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=work.recovery_id,
                expected_attempt_version=0,
                outcome=ReconciliationOutcome.UNKNOWN,
                evidence_refs=(_digest("late-reconcile:normal-finish"),),
                operation_evidence_ref=_digest("late-reconcile:normal-finish"),
                completed_at=reported_at,
                reason_code="RECONCILIATION_STILL_UNKNOWN",
            )
        assert normal_finish.value.code is ErrorCode.DEADLINE_EXCEEDED
        report_ref = _digest("late-reconcile:started:report")
        late = store.record_late_recovery_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=work.recovery_id,
            expected_work_version=1,
            evidence_refs=(report_ref,),
            operation_evidence_ref=report_ref,
            reported_at=reported_at,
            reason_code="LATE_RECONCILIATION_REPORT",
        )
        assert late.reconciliation_attempt is not None
        assert late.reconciliation_attempt.outcome is ReconciliationOutcome.UNKNOWN
        assert late.reconciliation_attempt.next_attempt_not_before is None
        assert late.transaction.state is TransactionState.IN_DOUBT
        assert late.work.state is RecoveryWorkState.REVIEW_REQUIRED
        assert (
            store.get_active_recovery_work(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            == ()
        )


def test_reconciliation_is_durably_started_resumable_and_exact_retry_bound(
    tmp_path: Path,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(tmp_path / "reconciliation.db") as store:
        action, stage, capability_ids = _stage_to_verified(store, context)
        _begin_dispatch(store, action, stage, capability_ids)
        unknown = store.classify_dispatch_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_dispatch_version=0,
            expected_transaction_version=7,
            classification=ReconciliationOutcome.UNKNOWN,
            evidence_refs=(_digest("dispatch:unknown"),),
            reason_code="DISPATCH_OUTCOME_UNKNOWN",
            recorded_at=_NOW + timedelta(seconds=13),
            recovery_timeout=timedelta(minutes=10),
        )
        proposed = _authorize_recovery_work(
            store,
            context,
            action,
            unknown.dispatch,
            kind=RecoveryWorkKind.RECONCILE_DISPATCH,
        )
        claim_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": proposed.recovery_id,
            "expected_work_version": 0,
            "lease_id": "lease:recovery:reconcile",
            "worker_id": "worker:reconcile",
            "acquired_at": _NOW + timedelta(seconds=17),
            "expires_at": _NOW + timedelta(minutes=5),
        }
        preview = store.preview_recovery_claim(**claim_arguments)  # type: ignore[arg-type]
        claimed = store.claim_recovery(  # type: ignore[arg-type]
            **claim_arguments,
            permit=preview.permit,
            permit_ref=preview.permit_ref,
        )
        assert claimed.disposition is EnforcedStoreDisposition.STORED
        started = store.start_reconciliation(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=1,
            evidence_refs=(_digest("reconciliation:started"),),
            started_at=_NOW + timedelta(seconds=18),
        )
        assert started.disposition is EnforcedStoreDisposition.RECONCILE_NOW
        assert started.transaction.state is TransactionState.RECONCILING
        assert (
            store.start_reconciliation(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
                expected_work_version=1,
                evidence_refs=(_digest("reconciliation:started"),),
                started_at=_NOW + timedelta(seconds=18),
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        assert (
            store.start_reconciliation(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
                expected_work_version=1,
                evidence_refs=(_digest("reconciliation:started"),),
                started_at=_NOW + timedelta(seconds=18, milliseconds=500),
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        assert (
            len(
                store.get_active_recovery_work(
                    tenant_id=action.tenant_id,
                    transaction_id=action.transaction_id,
                )
            )
            == 1
        )
        assert (
            store.get_started_reconciliation_attempt(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            == started.attempt
        )
        page = store.scan_recovery_candidates(
            tenant_id=action.tenant_id,
            observed_at=_NOW + timedelta(seconds=18),
            limit=10,
        )
        assert action.transaction_id in {record.transaction_id for record in page.records}
        assert proposed.recovery_id in {work.recovery_id for work in page.active_work}
        assert started.attempt in page.started_reconciliation

        absence = _digest("reconciliation:no-effect")
        extra_one = _digest("reconciliation:completion-extra-one")
        extra_two = _digest("reconciliation:completion-extra-two")
        finish_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": proposed.recovery_id,
            "expected_attempt_version": 0,
            "outcome": ReconciliationOutcome.NO_EFFECT,
            "evidence_refs": (absence, extra_one, extra_two),
            "operation_evidence_ref": absence,
            "completed_at": _NOW + timedelta(seconds=19),
            "no_effect_evidence_ref": absence,
        }
        finished = store.finish_reconciliation(**finish_arguments)  # type: ignore[arg-type]
        assert finished.transaction.state is TransactionState.ABORTING
        assert (
            store.finish_reconciliation(**finish_arguments).disposition  # type: ignore[arg-type]
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        assert (
            store.finish_reconciliation(  # type: ignore[arg-type]
                **{
                    **finish_arguments,
                    "evidence_refs": (
                        extra_two,
                        absence,
                        extra_one,
                        extra_two,
                    ),
                }
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        with pytest.raises(AgentKernelError) as omitted_completion_evidence:
            store.finish_reconciliation(  # type: ignore[arg-type]
                **{**finish_arguments, "evidence_refs": (absence,)}
            )
        assert omitted_completion_evidence.value.code is ErrorCode.INTEGRITY_ERROR
        with pytest.raises(AgentKernelError) as stale_attempt:
            store.finish_reconciliation(  # type: ignore[arg-type]
                **{**finish_arguments, "expected_attempt_version": 999}
            )
        assert stale_attempt.value.code is ErrorCode.VERSION_CONFLICT
        for mutation in (
            {"outcome": ReconciliationOutcome.COMMITTED},
            {"evidence_refs": (_digest("changed-reconcile-evidence"),)},
            {"completed_at": _NOW + timedelta(seconds=20)},
            {"effect_receipt_ref": _digest("forged-effect-receipt")},
            {"committed_verification_ref": _digest("forged-commit-verification")},
            {"no_effect_evidence_ref": _digest("changed-absence")},
            {"next_attempt_not_before": _NOW + timedelta(seconds=30)},
            {"reason_code": "FORGED_REASON"},
        ):
            with pytest.raises(AgentKernelError):
                store.finish_reconciliation(  # type: ignore[arg-type]
                    **{**finish_arguments, **mutation}
                )


@pytest.mark.parametrize("tamper", ["target-capability", "start-event-evidence"])
def test_reconciliation_started_exact_retry_rejects_bound_graph_tamper(
    tmp_path: Path,
    tamper: str,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(tmp_path / f"started-{tamper}.db") as store:
        action, work = _start_unknown_reconciliation(store, context)
        retry_arguments = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": work.recovery_id,
            "expected_work_version": 1,
            "evidence_refs": (_digest("reconciliation:started"),),
            "started_at": _NOW + timedelta(seconds=18),
        }
        if tamper == "target-capability":
            with store._immediate():
                store._execute(
                    "UPDATE enforced_capability_chain_reservations SET version = version + 2 "
                    "WHERE tenant_id = ? AND goal_id = ? AND run_id = ? "
                    "AND intent_hash = ?",
                    (
                        action.tenant_id,
                        action.goal_id,
                        action.run_id,
                        action.intent_hash,
                    ),
                )
        else:
            event = store.list_enforced_transaction_events(
                action.tenant_id,
                action.transaction_id,
            )[-1]
            assert event.event == TransitionEvent.RECONCILIATION_STARTED.value
            _rewrite_transaction_event_evidence(
                store,
                event,
                evidence_refs=tuple(
                    sorted({*event.evidence_refs, _digest("forged:start-event-evidence")})
                ),
            )

        with pytest.raises(AgentKernelError) as captured:
            store.start_reconciliation(**retry_arguments)  # type: ignore[arg-type]
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_expired_started_reconciliation_reclaim_closes_attempt_and_allows_attempt_two(
    tmp_path: Path,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(tmp_path / "reconciliation-reclaim.db") as store:
        action, proposed = _start_unknown_reconciliation(store, context)
        running = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
        )
        assert running.state is RecoveryWorkState.RUNNING
        assert running.permit_ref is not None
        assert running.lease_id is not None

        reclaim_preview = store.preview_recovery_reclaim(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=1,
            lease_id="lease:recovery:reconcile:reclaimed",
            worker_id="worker:reconcile:reclaimed",
            acquired_at=_NOW + timedelta(minutes=5, seconds=1),
            expires_at=_NOW + timedelta(minutes=6),
        )
        expiry_evidence = _digest("reconciliation:lease-expired")
        evidence_refs = tuple(
            sorted(
                {
                    running.permit_ref,
                    reclaim_preview.permit_ref,
                    expiry_evidence,
                }
            )
        )
        reclaim_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": proposed.recovery_id,
            "expected_work_version": 1,
            "lease_id": reclaim_preview.lease.lease_id,
            "worker_id": reclaim_preview.lease.worker_id,
            "acquired_at": reclaim_preview.lease.acquired_at,
            "expires_at": reclaim_preview.lease.expires_at,
            "permit": reclaim_preview.permit,
            "permit_ref": reclaim_preview.permit_ref,
            "evidence_refs": evidence_refs,
            "operation_evidence_ref": expiry_evidence,
            "operation_reason_code": "RECOVERY_LEASE_EXPIRED",
        }
        reclaimed = store.reclaim_expired_recovery(  # type: ignore[arg-type]
            **reclaim_arguments
        )
        assert reclaimed.work.version == 2
        assert reclaimed.work.attempt == 2
        assert reclaimed.lease.fencing_token > running.fencing_token
        reclaimed_projection = store.get_transaction_projection(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        first_attempt = store.get_reconciliation_attempt(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            attempt=1,
        )
        assert reclaimed_projection.reconciliation_attempts == (first_attempt,)
        assert (
            store.get_enforced_transaction(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            ).state
            is TransactionState.IN_DOUBT
        )
        assert first_attempt.outcome is ReconciliationOutcome.UNKNOWN
        assert first_attempt.completed_at == reclaim_preview.lease.acquired_at
        assert first_attempt.next_attempt_not_before == reclaim_preview.lease.acquired_at
        assert first_attempt.version == 1
        assert first_attempt.operation_evidence_ref == expiry_evidence
        assert first_attempt.operation_reason_code == "RECOVERY_LEASE_EXPIRED"
        assert (
            store.reclaim_expired_recovery(  # type: ignore[arg-type]
                **reclaim_arguments
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        with pytest.raises(AgentKernelError) as changed_operation:
            store.reclaim_expired_recovery(  # type: ignore[arg-type]
                **{
                    **reclaim_arguments,
                    "operation_evidence_ref": reclaim_preview.permit_ref,
                    "operation_reason_code": None,
                }
            )
        assert changed_operation.value.code is ErrorCode.INTEGRITY_ERROR
        assert (
            store.get_started_reconciliation_attempt(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            is None
        )

        second_attempt = store.start_reconciliation(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=2,
            evidence_refs=(_digest("reconciliation:attempt:2:started"),),
            started_at=reclaim_preview.lease.acquired_at + timedelta(seconds=1),
        )
        assert second_attempt.attempt.attempt == 2
        assert second_attempt.attempt.lease_id == reclaim_preview.lease.lease_id
        assert second_attempt.attempt.fencing_token == reclaim_preview.lease.fencing_token
        assert second_attempt.transaction.state is TransactionState.RECONCILING
        assert store.get_transaction_projection(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        ).reconciliation_attempts == (first_attempt, second_attempt.attempt)
        assert (
            store.get_started_reconciliation_attempt(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            == second_attempt.attempt
        )

        tampered_first = ReconciliationAttemptRecord.model_validate(
            {
                **first_attempt.model_dump(mode="python"),
                "operation_evidence_ref": reclaim_preview.permit_ref,
            }
        )
        with store._immediate():
            store._execute(
                "UPDATE enforced_reconciliation_attempts SET operation_evidence_ref = ?, "
                "record_digest = ?, record_json = ? WHERE tenant_id = ? "
                "AND transaction_id = ? AND recovery_id = ? AND attempt = ?",
                (
                    tampered_first.operation_evidence_ref,
                    canonical_digest(tampered_first.canonical_record_json()),
                    canonical_json_text(tampered_first.canonical_record_json()),
                    tampered_first.tenant_id,
                    tampered_first.transaction_id,
                    tampered_first.recovery_id,
                    tampered_first.attempt,
                ),
            )
        with pytest.raises(AgentKernelError) as historical_tamper:
            store.get_transaction_projection(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
        assert historical_tamper.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize("lifecycle", ["running", "terminal-no-effect"])
def test_current_reconciliation_started_at_tamper_rejects_projection_and_reopen(
    tmp_path: Path,
    lifecycle: str,
) -> None:
    path = tmp_path / f"forged-current-reconciliation-start-{lifecycle}.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        action, proposed = _start_unknown_reconciliation(store, context)
        if lifecycle == "terminal-no-effect":
            no_effect_evidence = _digest("forged-current-start:no-effect")
            store.finish_reconciliation(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
                expected_attempt_version=0,
                outcome=ReconciliationOutcome.NO_EFFECT,
                evidence_refs=(no_effect_evidence,),
                operation_evidence_ref=no_effect_evidence,
                completed_at=_NOW + timedelta(seconds=19),
                no_effect_evidence_ref=no_effect_evidence,
            )

        current = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
        )
        attempt = store.get_reconciliation_attempt(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=current.recovery_id,
            attempt=current.attempt,
        )
        events_before = store.list_enforced_transaction_events(
            action.tenant_id,
            action.transaction_id,
        )
        started_event = next(
            event
            for event in events_before
            if event.event == TransitionEvent.RECONCILIATION_STARTED.value
        )
        assert started_event.recorded_at == attempt.started_at

        altered = _rewrite_reconciliation_attempt_started_at(
            store,
            attempt,
            started_at=attempt.started_at + timedelta(milliseconds=500),
        )
        assert (
            store.get_reconciliation_attempt(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=current.recovery_id,
                attempt=current.attempt,
            )
            == altered
        )
        assert (
            store.list_enforced_transaction_events(
                action.tenant_id,
                action.transaction_id,
            )
            == events_before
        )

        with pytest.raises(AgentKernelError) as projection:
            store.get_transaction_projection(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
        assert projection.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize(
    "lifecycle",
    ["running-reconciling", "retry-scheduled", "late-review-required"],
)
def test_current_reconciliation_attempt_deletion_rejects_projection_and_reopen(
    tmp_path: Path,
    lifecycle: str,
) -> None:
    path = tmp_path / f"missing-current-reconciliation-attempt-{lifecycle}.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        action, proposed = _start_unknown_reconciliation(store, context)
        if lifecycle == "running-reconciling":
            expected_work_state = RecoveryWorkState.RUNNING
            expected_transaction_state = TransactionState.RECONCILING
        elif lifecycle == "retry-scheduled":
            next_attempt = _NOW + timedelta(seconds=30)
            unknown_evidence = _digest("missing-current:retry-scheduled:unknown")
            store.finish_reconciliation(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
                expected_attempt_version=0,
                outcome=ReconciliationOutcome.UNKNOWN,
                evidence_refs=(unknown_evidence,),
                operation_evidence_ref=unknown_evidence,
                completed_at=_NOW + timedelta(seconds=19),
                next_attempt_not_before=next_attempt,
                reason_code="RECONCILIATION_STILL_UNKNOWN",
            )
            expected_work_state = RecoveryWorkState.RETRY_SCHEDULED
            expected_transaction_state = TransactionState.IN_DOUBT
        else:
            reported_at = _NOW + timedelta(minutes=5)
            report_evidence = _digest("missing-current:late-review:report")
            late = store.record_late_recovery_outcome(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
                expected_work_version=1,
                evidence_refs=(report_evidence,),
                operation_evidence_ref=report_evidence,
                reported_at=reported_at,
                reason_code="LATE_RECONCILIATION_REPORT",
            )
            assert late.reconciliation_attempt is not None
            assert (
                store.get_late_recovery_report(
                    tenant_id=action.tenant_id,
                    transaction_id=action.transaction_id,
                    recovery_id=proposed.recovery_id,
                )
                is not None
            )
            expected_work_state = RecoveryWorkState.REVIEW_REQUIRED
            expected_transaction_state = TransactionState.IN_DOUBT

        current = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
        )
        assert current.attempt == 1
        assert current.state is expected_work_state
        assert (
            store.get_enforced_transaction(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            ).state
            is expected_transaction_state
        )
        intact = store.get_transaction_projection(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        assert any(
            attempt.recovery_id == current.recovery_id and attempt.attempt == current.attempt
            for attempt in intact.reconciliation_attempts
        )

        _delete_reconciliation_attempt(
            store,
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=current.recovery_id,
            attempt=current.attempt,
        )

        with pytest.raises(AgentKernelError) as projection:
            store.get_transaction_projection(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
        assert projection.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize("lifecycle", ["claimed", "reclaimed"])
def test_prestart_running_in_doubt_allows_absent_current_attempt(
    tmp_path: Path,
    lifecycle: str,
) -> None:
    path = tmp_path / f"prestart-running-in-doubt-{lifecycle}.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        if lifecycle == "claimed":
            action, proposed = _claim_unknown_reconciliation(store, context)
        else:
            action, proposed, _arguments = _reclaim_started_reconciliation_to_attempt_three(
                store, context
            )
        current = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
        )
        assert current.state is RecoveryWorkState.RUNNING
        assert (
            store.get_enforced_transaction(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            ).state
            is TransactionState.IN_DOUBT
        )
        attempts = store.list_reconciliation_attempts(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        assert all(
            attempt.recovery_id != current.recovery_id or attempt.attempt < current.attempt
            for attempt in attempts
        )
        assert (
            store.get_started_reconciliation_attempt(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            is None
        )
        projection = store.get_transaction_projection(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        assert projection.record.state is TransactionState.IN_DOUBT
        assert current in projection.recovery_work

    with SQLiteEnforcedTransactionStore(path) as reopened:
        projection = reopened.get_transaction_projection(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        assert projection.record.state is TransactionState.IN_DOUBT
        assert current in projection.recovery_work
        assert all(
            attempt.recovery_id != current.recovery_id or attempt.attempt < current.attempt
            for attempt in projection.reconciliation_attempts
        )


@pytest.mark.parametrize(
    ("outcome", "expected_work_state", "deleted_generation"),
    [
        (ReconciliationOutcome.NO_EFFECT, RecoveryWorkState.SUCCEEDED, "current"),
        (ReconciliationOutcome.NO_EFFECT, RecoveryWorkState.SUCCEEDED, "historical"),
        (ReconciliationOutcome.UNKNOWN, RecoveryWorkState.REVIEW_REQUIRED, "current"),
        (ReconciliationOutcome.UNKNOWN, RecoveryWorkState.REVIEW_REQUIRED, "historical"),
    ],
)
def test_terminal_reclaimed_reconciliation_requires_complete_attempt_lineage(
    tmp_path: Path,
    outcome: ReconciliationOutcome,
    expected_work_state: RecoveryWorkState,
    deleted_generation: str,
) -> None:
    path = tmp_path / (f"terminal-reclaimed-{deleted_generation}-attempt-{outcome.value}.db")
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        action, proposed = _start_unknown_reconciliation(store, context)
        running = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
        )
        assert running.permit_ref is not None
        reclaim_preview = store.preview_recovery_reclaim(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=1,
            lease_id=f"lease:recovery:reconcile:current:{outcome.value}",
            worker_id="worker:reconcile:current",
            acquired_at=_NOW + timedelta(minutes=5, seconds=1),
            expires_at=_NOW + timedelta(minutes=6),
        )
        expiry_evidence = _digest(f"reconciliation:current:{outcome.value}:expired")
        store.reclaim_expired_recovery(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=1,
            lease_id=reclaim_preview.lease.lease_id,
            worker_id=reclaim_preview.lease.worker_id,
            acquired_at=reclaim_preview.lease.acquired_at,
            expires_at=reclaim_preview.lease.expires_at,
            permit=reclaim_preview.permit,
            permit_ref=reclaim_preview.permit_ref,
            evidence_refs=tuple(
                sorted(
                    {
                        running.permit_ref,
                        reclaim_preview.permit_ref,
                        expiry_evidence,
                    }
                )
            ),
            operation_evidence_ref=expiry_evidence,
            operation_reason_code="RECOVERY_LEASE_EXPIRED",
        )
        store.start_reconciliation(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
            expected_work_version=2,
            evidence_refs=(_digest(f"reconciliation:current:{outcome.value}:started"),),
            started_at=reclaim_preview.lease.acquired_at + timedelta(seconds=1),
        )
        terminal_evidence = _digest(f"reconciliation:current:{outcome.value}:terminal")
        terminal_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": proposed.recovery_id,
            "expected_attempt_version": 0,
            "outcome": outcome,
            "evidence_refs": (terminal_evidence,),
            "operation_evidence_ref": terminal_evidence,
            "completed_at": reclaim_preview.lease.acquired_at + timedelta(seconds=2),
        }
        if outcome is ReconciliationOutcome.NO_EFFECT:
            terminal_arguments["no_effect_evidence_ref"] = terminal_evidence
        else:
            terminal_arguments["reason_code"] = "RECONCILIATION_STILL_UNKNOWN"
        store.finish_reconciliation(**terminal_arguments)  # type: ignore[arg-type]

        terminal_work = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=proposed.recovery_id,
        )
        assert terminal_work.attempt == 2
        assert terminal_work.state is expected_work_state
        assert {
            attempt.attempt
            for attempt in store.list_reconciliation_attempts(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
        } == {1, 2}

        trigger_sql = store._connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
            "AND name = 'enforced_reconciliation_attempts_no_delete'"
        ).fetchone()[0]
        with store._immediate():
            store._execute("DROP TRIGGER enforced_reconciliation_attempts_no_delete")
            store._execute(
                "DELETE FROM enforced_reconciliation_attempts WHERE tenant_id = ? "
                "AND transaction_id = ? AND recovery_id = ? AND attempt = ?",
                (
                    action.tenant_id,
                    action.transaction_id,
                    proposed.recovery_id,
                    terminal_work.attempt if deleted_generation == "current" else 1,
                ),
            )
            store._execute(str(trigger_sql))

        with pytest.raises(AgentKernelError) as projection:
            store.get_transaction_projection(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
        assert projection.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize("retry_boundary", ["reclaim", "start", "finish"])
def test_reconciliation_exact_retry_revalidates_all_historical_attempts(
    tmp_path: Path,
    retry_boundary: str,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(
        tmp_path / f"reconciliation-lineage-exact-retry-{retry_boundary}.db"
    ) as store:
        action, work, reclaim_arguments = _reclaim_started_reconciliation_to_attempt_three(
            store,
            context,
        )
        start_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": work.recovery_id,
            "expected_work_version": 3,
            "evidence_refs": (_digest("reconciliation:lineage:attempt:3:started"),),
            "started_at": work.updated_at + timedelta(seconds=1),
        }
        finish_arguments: dict[str, object] | None = None
        if retry_boundary in {"start", "finish"}:
            store.start_reconciliation(**start_arguments)  # type: ignore[arg-type]
        if retry_boundary == "finish":
            terminal_evidence = _digest("reconciliation:lineage:attempt:3:no-effect")
            finish_arguments = {
                "tenant_id": action.tenant_id,
                "transaction_id": action.transaction_id,
                "recovery_id": work.recovery_id,
                "expected_attempt_version": 0,
                "outcome": ReconciliationOutcome.NO_EFFECT,
                "evidence_refs": (terminal_evidence,),
                "operation_evidence_ref": terminal_evidence,
                "completed_at": work.updated_at + timedelta(seconds=2),
                "no_effect_evidence_ref": terminal_evidence,
            }
            store.finish_reconciliation(**finish_arguments)  # type: ignore[arg-type]

        trigger_sql = store._connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
            "AND name = 'enforced_reconciliation_attempts_no_delete'"
        ).fetchone()[0]
        with store._immediate():
            store._execute("DROP TRIGGER enforced_reconciliation_attempts_no_delete")
            store._execute(
                "DELETE FROM enforced_reconciliation_attempts WHERE tenant_id = ? "
                "AND transaction_id = ? AND recovery_id = ? AND attempt = 1",
                (action.tenant_id, action.transaction_id, work.recovery_id),
            )
            store._execute(str(trigger_sql))

        def retry() -> None:
            if retry_boundary == "reclaim":
                store.reclaim_expired_recovery(  # type: ignore[arg-type]
                    **reclaim_arguments
                )
            elif retry_boundary == "start":
                store.start_reconciliation(**start_arguments)  # type: ignore[arg-type]
            else:
                assert finish_arguments is not None
                store.finish_reconciliation(**finish_arguments)  # type: ignore[arg-type]

        with pytest.raises(AgentKernelError) as rejected:
            retry()
        assert rejected.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize(
    "tamper",
    [
        "lease-version",
        "lease-interval",
        "finish-event-evidence",
        "transaction-reason",
        "action-intent-evidence",
    ],
)
def test_reconciliation_finished_exact_retry_rejects_terminal_graph_tamper(
    tmp_path: Path,
    tamper: str,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(tmp_path / f"finished-{tamper}.db") as store:
        action, running = _start_unknown_reconciliation(store, context)
        absence = _digest(f"reconciliation:finished:{tamper}:no-effect")
        finish_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": running.recovery_id,
            "expected_attempt_version": 0,
            "outcome": ReconciliationOutcome.NO_EFFECT,
            "evidence_refs": (absence,),
            "operation_evidence_ref": absence,
            "completed_at": _NOW + timedelta(seconds=19),
            "no_effect_evidence_ref": absence,
        }
        store.finish_reconciliation(**finish_arguments)  # type: ignore[arg-type]
        terminal = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=running.recovery_id,
        )
        assert terminal.lease_id is not None

        if tamper in {"lease-version", "lease-interval"}:
            lease = store.get_worker_lease(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                lease_id=terminal.lease_id,
            )
            altered = type(lease).model_validate(
                {
                    **lease.model_dump(mode="python"),
                    **(
                        {"version": lease.version + 1}
                        if tamper == "lease-version"
                        else {"expires_at": terminal.deadline + timedelta(seconds=1)}
                    ),
                }
            )
            with store._immediate():
                store._update_worker_lease_tx(lease, altered)
        elif tamper == "finish-event-evidence":
            event = store.list_enforced_transaction_events(
                action.tenant_id,
                action.transaction_id,
            )[-1]
            assert event.event == TransitionEvent.RECONCILIATION_NO_EFFECT.value
            _rewrite_transaction_event_evidence(
                store,
                event,
                evidence_refs=tuple(
                    sorted({*event.evidence_refs, _digest("forged:finish-event-evidence")})
                ),
            )
        elif tamper == "transaction-reason":
            transaction = store.get_enforced_transaction(
                action.tenant_id,
                action.transaction_id,
            )
            altered_transaction = EnforcedTransactionRecord.model_validate(
                {
                    **transaction.model_dump(mode="python"),
                    "reason_code": "FORGED_RECONCILIATION_REASON",
                }
            )
            with store._immediate():
                store._execute(
                    "UPDATE enforced_transactions SET reason_code = ?, record_digest = ?, "
                    "record_json = ? WHERE tenant_id = ? AND transaction_id = ?",
                    (
                        altered_transaction.reason_code,
                        canonical_digest(altered_transaction),
                        canonical_json_text(altered_transaction),
                        action.tenant_id,
                        action.transaction_id,
                    ),
                )
        else:
            _rewrite_intent_head_evidence(
                store,
                tenant_id=terminal.tenant_id,
                intent_hash=terminal.recovery_action_intent_hash,
                transaction_id=terminal.recovery_action_transaction_id,
                evidence_digest=_digest("forged:finish-action-intent"),
            )

        with pytest.raises(AgentKernelError) as captured:
            store.finish_reconciliation(**finish_arguments)  # type: ignore[arg-type]
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize(
    "tamper",
    ["completion-evidence", "unavailable-event-evidence", "action-intent-evidence"],
)
def test_reconciliation_unavailable_exact_retry_rejects_association_tamper(
    tmp_path: Path,
    tamper: str,
) -> None:
    path = tmp_path / f"reconciliation-unavailable-{tamper}.db"
    context = _context()
    supporting_ref = _digest(f"reconciliation:unavailable:{tamper}")
    reason_code = "EVIDENCE_UNAVAILABLE:RECONCILIATION_EVIDENCE_MISSING"
    terminal_arguments: dict[str, object] = {
        "tenant_id": context.tenant_id,
        "transaction_id": "transaction:test",
        "expected_work_version": 1,
        "boundary": "RECONCILIATION_EVIDENCE",
        "supporting_refs": (supporting_ref,),
        "reported_at": _NOW + timedelta(seconds=19),
        "reason_code": reason_code,
    }
    with SQLiteEnforcedTransactionStore(path) as store:
        action, running = _start_unknown_reconciliation(store, context)
        terminal_arguments["tenant_id"] = action.tenant_id
        terminal_arguments["transaction_id"] = action.transaction_id
        terminal_arguments["recovery_id"] = running.recovery_id
        result = store.terminalize_recovery_evidence_unavailable(
            **terminal_arguments  # type: ignore[arg-type]
        )
        assert result.reconciliation_attempt is not None
        assert result.event is not None
        if tamper == "completion-evidence":
            attempt = result.reconciliation_attempt
            forged_ref = _digest("forged:unavailable-completion")
            altered_attempt = type(attempt).model_validate(
                {
                    **attempt.model_dump(mode="python"),
                    "completion_evidence_refs": (forged_ref,),
                    "evidence_refs": tuple(
                        sorted(
                            {
                                *(ref for ref in attempt.evidence_refs if ref != supporting_ref),
                                forged_ref,
                            }
                        )
                    ),
                }
            )
            with store._immediate():
                store._execute(
                    "UPDATE enforced_reconciliation_attempts SET evidence_refs_json = ?, "
                    "completion_evidence_refs_json = ?, record_digest = ?, record_json = ? "
                    "WHERE tenant_id = ? AND transaction_id = ? AND recovery_id = ? "
                    "AND attempt = ?",
                    (
                        canonical_json_text(altered_attempt.evidence_refs),
                        canonical_json_text(altered_attempt.completion_evidence_refs),
                        canonical_digest(altered_attempt),
                        canonical_json_text(altered_attempt),
                        altered_attempt.tenant_id,
                        altered_attempt.transaction_id,
                        altered_attempt.recovery_id,
                        altered_attempt.attempt,
                    ),
                )
        elif tamper == "unavailable-event-evidence":
            _rewrite_transaction_event_evidence(
                store,
                result.event,
                evidence_refs=tuple(
                    sorted(
                        {
                            *result.event.evidence_refs,
                            _digest("forged:unavailable-event"),
                        }
                    )
                ),
            )
        else:
            _rewrite_intent_head_evidence(
                store,
                tenant_id=result.work.tenant_id,
                intent_hash=result.work.recovery_action_intent_hash,
                transaction_id=result.work.recovery_action_transaction_id,
                evidence_digest=_digest("forged:unavailable-action-intent"),
            )

        with pytest.raises(AgentKernelError) as captured:
            store.terminalize_recovery_evidence_unavailable(
                **terminal_arguments  # type: ignore[arg-type]
            )
        assert captured.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


def test_recovery_target_accepts_historical_dispatch_owner_but_rejects_tamper_and_transfer(
    tmp_path: Path,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(tmp_path / "recovery-owner-generation.db") as store:
        action, proposed = _start_unknown_reconciliation(store, context)
        current_history = store.list_intent_history(
            tenant_id=action.tenant_id,
            intent_hash=action.intent_hash,
        )
        assert proposed.target_owner_history_sequence < current_history[-1].sequence
        store._assert_recovery_target_owner_tx(proposed)

        tampered = RecoveryWorkRecord.model_validate(
            {
                **proposed.model_dump(mode="python"),
                "target_owner_history_digest": _digest("forged:target-owner-history"),
            }
        )
        with pytest.raises(AgentKernelError) as forged_history:
            store._assert_recovery_target_owner_tx(tampered)
        assert forged_history.value.code is ErrorCode.VERSION_CONFLICT

        attempt = store.get_intent_attempt(
            tenant_id=action.tenant_id,
            intent_hash=action.intent_hash,
            transaction_id=action.transaction_id,
        )
        store.record_intent_attempt_state(
            tenant_id=action.tenant_id,
            intent_hash=action.intent_hash,
            transaction_id=action.transaction_id,
            expected_version=attempt.version,
            state=IntentAttemptState.NO_EFFECT_CONFIRMED,
            evidence_digest=_digest("owner-transfer:no-effect"),
            recorded_at=_NOW + timedelta(minutes=5),
        )
        replacement = _action(context, "transaction:replacement-owner")
        store.put_normalized_action(
            replacement,
            recorded_at=_NOW + timedelta(minutes=5, milliseconds=1),
        )
        controlled_state = store.get_enforced_transaction(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        ).state
        with store._immediate():
            store._execute(
                "UPDATE enforced_transactions SET state = 'ABORTED' "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (action.tenant_id, action.transaction_id),
            )
            acquisition = store._acquire_intent_tx(
                tenant_id=action.tenant_id,
                intent_hash=action.intent_hash,
                transaction_id=replacement.transaction_id,
                attempted_at=(
                    (_NOW + timedelta(minutes=5, milliseconds=2))
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z")
                ),
                expected_owner_version=proposed.target_owner_version,
            )
            store._execute(
                "UPDATE enforced_transactions SET state = ? "
                "WHERE tenant_id = ? AND transaction_id = ?",
                (controlled_state.value, action.tenant_id, action.transaction_id),
            )
        assert acquisition.disposition is IntentDisposition.TRANSFERRED_NO_EFFECT

        with pytest.raises(AgentKernelError) as transferred_owner:
            store.preview_recovery_reclaim(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=proposed.recovery_id,
                expected_work_version=1,
                lease_id="lease:recovery:transferred-owner",
                worker_id="worker:recovery:transferred-owner",
                acquired_at=_NOW + timedelta(minutes=5, seconds=1),
                expires_at=_NOW + timedelta(minutes=6),
            )
        assert transferred_owner.value.code is ErrorCode.VERSION_CONFLICT


def test_unknown_reconciliation_schedules_and_authorizes_fresh_generation(
    tmp_path: Path,
) -> None:
    context = _context()
    path = tmp_path / "reconciliation-retry.db"
    _create_v4_database(path)
    with SQLiteEnforcedTransactionStore(path) as store:
        assert store.schema_version == 7
        action, initial = _start_unknown_reconciliation(store, context)
        next_attempt = _NOW + timedelta(seconds=30)
        initial_finish_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": initial.recovery_id,
            "expected_attempt_version": 0,
            "outcome": ReconciliationOutcome.UNKNOWN,
            "evidence_refs": (_digest("reconciliation:still-unknown"),),
            "operation_evidence_ref": _digest("reconciliation:still-unknown"),
            "completed_at": _NOW + timedelta(seconds=19),
            "next_attempt_not_before": next_attempt,
            "reason_code": "RECONCILIATION_STILL_UNKNOWN",
        }
        finished = store.finish_reconciliation(  # type: ignore[arg-type]
            **initial_finish_arguments
        )
        assert finished.transaction.state is TransactionState.IN_DOUBT
        scheduled = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=initial.recovery_id,
        )
        assert scheduled.state is RecoveryWorkState.RETRY_SCHEDULED
        assert scheduled.deadline == initial.deadline
        outcomes_before_retry = store.list_dispatch_outcomes(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        current_dispatch = store.get_commit_dispatch(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        successor = _authorize_recovery_work(
            store,
            context,
            action,
            current_dispatch,
            kind=RecoveryWorkKind.RECONCILE_DISPATCH,
            generation=2,
            predecessor=scheduled,
            authorized_at=next_attempt,
        )
        assert (
            store.finish_reconciliation(  # type: ignore[arg-type]
                **initial_finish_arguments
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        assert successor.recovery_ordinal == 2
        assert successor.root_recovery_id == initial.recovery_id
        assert successor.predecessor_recovery_id == initial.recovery_id
        assert successor.deadline == initial.deadline
        assert (
            store.get_recovery_work(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=initial.recovery_id,
            ).state
            is RecoveryWorkState.RETRIED
        )
        preview = store.preview_recovery_claim(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=successor.recovery_id,
            expected_work_version=0,
            lease_id="lease:recovery:reconcile:2",
            worker_id="worker:reconcile:2",
            acquired_at=next_attempt + timedelta(seconds=1),
            expires_at=_NOW + timedelta(minutes=6),
        )
        assert preview.lease.fencing_token > scheduled.fencing_token
        assert preview.permit.deadline == preview.lease.expires_at
        assert (
            store.claim_recovery(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=successor.recovery_id,
                expected_work_version=0,
                lease_id=preview.lease.lease_id,
                worker_id=preview.lease.worker_id,
                acquired_at=preview.lease.acquired_at,
                expires_at=preview.lease.expires_at,
                permit=preview.permit,
                permit_ref=preview.permit_ref,
            ).lease.fencing_token
            == preview.lease.fencing_token
        )
        assert (
            store.list_dispatch_outcomes(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            == outcomes_before_retry
        )
        started = store.start_reconciliation(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=successor.recovery_id,
            expected_work_version=1,
            evidence_refs=(_digest("reconciliation:successor:started"),),
            started_at=next_attempt + timedelta(seconds=2),
        )
        assert started.attempt.attempt == 1
        completed = store.finish_reconciliation(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=successor.recovery_id,
            expected_attempt_version=0,
            outcome=ReconciliationOutcome.UNKNOWN,
            evidence_refs=(_digest("reconciliation:successor:unknown"),),
            operation_evidence_ref=_digest("reconciliation:successor:unknown"),
            completed_at=next_attempt + timedelta(seconds=3),
            reason_code="RECONCILIATION_STILL_UNKNOWN",
        )
        assert completed.transaction.state is TransactionState.IN_DOUBT
        attempts = store.list_reconciliation_attempts(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        assert {(attempt.recovery_id, attempt.attempt) for attempt in attempts} == {
            (initial.recovery_id, 1),
            (successor.recovery_id, 1),
        }
    with SQLiteEnforcedTransactionStore(path) as reopened:
        attempts = reopened.list_reconciliation_attempts(
            tenant_id=context.tenant_id,
            transaction_id="transaction:test",
        )
        assert len(attempts) == 2


@pytest.mark.parametrize(
    "tamper",
    ["predecessor-successor-digest", "successor-lineage", "successor-handoff-lease"],
)
def test_reconciliation_successor_full_lineage_tamper_rejects_retry_and_reopen(
    tmp_path: Path,
    tamper: str,
) -> None:
    path = tmp_path / f"reconciliation-successor-{tamper}-tamper.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        action, initial = _start_unknown_reconciliation(store, context)
        next_attempt = _NOW + timedelta(seconds=30)
        finish_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": initial.recovery_id,
            "expected_attempt_version": 0,
            "outcome": ReconciliationOutcome.UNKNOWN,
            "evidence_refs": (_digest("reconciliation:tamper:unknown"),),
            "operation_evidence_ref": _digest("reconciliation:tamper:unknown"),
            "completed_at": _NOW + timedelta(seconds=19),
            "next_attempt_not_before": next_attempt,
            "reason_code": "RECONCILIATION_STILL_UNKNOWN",
        }
        store.finish_reconciliation(**finish_arguments)  # type: ignore[arg-type]
        scheduled = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=initial.recovery_id,
        )
        successor = _authorize_recovery_work(
            store,
            context,
            action,
            store.get_commit_dispatch(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            ),
            kind=RecoveryWorkKind.RECONCILE_DISPATCH,
            generation=2,
            predecessor=scheduled,
            authorized_at=next_attempt,
        )
        progressed = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=initial.recovery_id,
        )
        successor_digest = canonical_digest(successor)
        assert progressed.state is RecoveryWorkState.RETRIED
        assert successor_digest in progressed.evidence_refs
        if tamper == "predecessor-successor-digest":
            forged = RecoveryWorkRecord.model_validate(
                {
                    **progressed.model_dump(mode="python"),
                    "evidence_refs": tuple(
                        sorted(
                            {
                                *(
                                    ref
                                    for ref in progressed.evidence_refs
                                    if ref != successor_digest
                                ),
                                _digest("reconciliation:forged-successor"),
                            }
                        )
                    ),
                }
            )
            with store._immediate():
                store._update_recovery_work_tx(progressed, forged)
        elif tamper == "successor-lineage":
            forged = RecoveryWorkRecord.model_validate(
                {
                    **successor.model_dump(mode="python"),
                    "root_recovery_id": "recovery:forged-successor-root",
                }
            )
            trigger_row = store._connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
                "AND name = 'enforced_recovery_work_binding_immutable'"
            ).fetchone()
            assert trigger_row is not None
            assert trigger_row[0] is not None
            with store._immediate():
                store._execute("DROP TRIGGER enforced_recovery_work_binding_immutable")
                store._execute(
                    "UPDATE enforced_recovery_work SET root_recovery_id = ?, "
                    "record_digest = ?, record_json = ? WHERE tenant_id = ? "
                    "AND transaction_id = ? AND recovery_id = ?",
                    (
                        forged.root_recovery_id,
                        canonical_digest(forged),
                        canonical_json_text(forged),
                        forged.tenant_id,
                        forged.transaction_id,
                        forged.recovery_id,
                    ),
                )
                store._execute(str(trigger_row[0]))
        else:
            successor_handoff = store._assert_recovery_work_handoff_tx(successor)
            handoff_lease = store.get_worker_lease(
                tenant_id=successor.tenant_id,
                transaction_id=successor.transaction_id,
                lease_id=successor_handoff.handoff_lease_id,
            )
            forged_lease = type(handoff_lease).model_validate(
                {
                    **handoff_lease.model_dump(mode="python"),
                    "version": handoff_lease.version + 1,
                }
            )
            with store._immediate():
                store._update_worker_lease_tx(handoff_lease, forged_lease)

        with pytest.raises(AgentKernelError) as exact_retry:
            store.finish_reconciliation(  # type: ignore[arg-type]
                **finish_arguments
            )
        assert exact_retry.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


def test_reconciliation_generation_tamper_fails_on_reopen(tmp_path: Path) -> None:
    path = tmp_path / "reconciliation-generation-tamper.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        _start_unknown_reconciliation(store, context)

    connection = sqlite3.connect(path)
    try:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
            "AND name = 'enforced_reconciliation_binding_immutable'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER enforced_reconciliation_binding_immutable")
        connection.execute(
            "UPDATE enforced_reconciliation_attempts SET recovery_id = ?",
            ("recovery:forged-generation",),
        )
        connection.execute(trigger_sql)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AgentKernelError) as captured:
        SQLiteEnforcedTransactionStore(path)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_transaction_projection_is_one_snapshot_across_concurrent_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "status-snapshot-race.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as setup:
        action, stage, capability_ids = _stage_to_verified(setup, context)
        dispatch = _begin_dispatch(setup, action, stage, capability_ids)

    effect_receipt_ref = _digest("snapshot-race:effect-receipt")
    verification_ref = _digest("snapshot-race:verification")
    verification_permit = VerificationPermit.create(
        tenant_id=action.tenant_id,
        transaction_id=action.transaction_id,
        intent_hash=action.intent_hash,
        normalized_action_digest=canonical_digest(action),
        adapter_manifest_digest=action.adapter_manifest_digest,
        authorization_round_id=dispatch.permit.authorization_round_id,
        authorization_round_digest=dispatch.permit.authorization_round_digest,
        lease_id=dispatch.permit.lease_id,
        worker_id=dispatch.permit.worker_id,
        fencing_token=dispatch.permit.fencing_token,
        phase=VerificationPhase.COMMITTED,
        subject_ref=effect_receipt_ref,
        authority_permit_digest=dispatch.permit.permit_digest,
        authority_permit_ref=dispatch.permit_ref,
        subject_permit_digest=dispatch.permit.permit_digest,
        subject_permit_ref=dispatch.permit_ref,
        issued_at=_NOW + timedelta(seconds=12),
        deadline=dispatch.permit.deadline,
    )
    verification_permit_ref = canonical_digest(verification_permit)
    stores_ready = threading.Barrier(2)
    first_component_read = threading.Event()
    writer_finished = threading.Event()
    reader_store: SQLiteEnforcedTransactionStore | None = None
    original_get = SQLiteEnforcedTransactionStore._get_enforced_transaction_tx

    def pause_after_first_component(
        store: SQLiteEnforcedTransactionStore,
        tenant_id: str,
        transaction_id: str,
    ) -> EnforcedTransactionRecord:
        record = original_get(store, tenant_id, transaction_id)
        if store is reader_store:
            first_component_read.set()
            if not writer_finished.wait(timeout=10):
                raise AssertionError("writer did not commit while reader snapshot was open")
        return record

    monkeypatch.setattr(
        SQLiteEnforcedTransactionStore,
        "_get_enforced_transaction_tx",
        pause_after_first_component,
    )

    def read_projection() -> EnforcedTransactionProjection:
        nonlocal reader_store
        with SQLiteEnforcedTransactionStore(path) as opened:
            reader_store = opened
            stores_ready.wait(timeout=10)
            return opened.get_transaction_projection(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )

    def commit_writer() -> None:
        with SQLiteEnforcedTransactionStore(path) as writer:
            stores_ready.wait(timeout=10)
            if not first_component_read.wait(timeout=10):
                raise AssertionError("reader did not establish its first snapshot component")
            try:
                attached = writer.attach_receipt(
                    tenant_id=action.tenant_id,
                    transaction_id=action.transaction_id,
                    expected_dispatch_version=0,
                    effect_receipt_ref=effect_receipt_ref,
                    evidence_refs=(effect_receipt_ref,),
                    recorded_at=_NOW + timedelta(seconds=12),
                )
                writer.classify_dispatch_outcome(
                    tenant_id=action.tenant_id,
                    transaction_id=action.transaction_id,
                    expected_dispatch_version=attached.dispatch.version,
                    expected_transaction_version=7,
                    classification=ReconciliationOutcome.COMMITTED,
                    evidence_refs=(verification_ref,),
                    recorded_at=_NOW + timedelta(seconds=13),
                    effect_receipt_ref=effect_receipt_ref,
                    committed_verification_permit=verification_permit,
                    committed_verification_permit_ref=verification_permit_ref,
                    committed_verification_ref=verification_ref,
                )
            finally:
                writer_finished.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        reader_future = executor.submit(read_projection)
        writer_future = executor.submit(commit_writer)
        projection = reader_future.result(timeout=20)
        writer_future.result(timeout=20)

    assert projection.record.state is TransactionState.COMMITTING
    assert projection.record.version == 7
    assert projection.action == action
    assert projection.stage == stage
    assert projection.dispatch is not None
    assert projection.dispatch.state is CommitDispatchState.DISPATCHED
    assert projection.dispatch.version == 0
    assert projection.dispatch.effect_receipt_ref is None
    assert projection.recovery_work == ()
    assert projection.event_count == projection.record.version + 1 == 8

    with SQLiteEnforcedTransactionStore(path) as reopened:
        current = reopened.get_transaction_projection(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        assert current.record.state is TransactionState.COMMITTED
        assert current.record.version == 8
        assert current.dispatch is not None
        assert current.dispatch.state is CommitDispatchState.COMMITTED
        assert current.dispatch.version == 2
        assert current.event_count == current.record.version + 1 == 9
        with pytest.raises(AgentKernelError) as wrong_tenant:
            reopened.get_transaction_projection(
                tenant_id="tenant:other",
                transaction_id=action.transaction_id,
            )
        assert wrong_tenant.value.code is ErrorCode.VALIDATION_ERROR
        with pytest.raises(AgentKernelError) as unknown:
            reopened.get_transaction_projection(
                tenant_id=action.tenant_id,
                transaction_id="transaction:unknown",
            )
        assert unknown.value.code is ErrorCode.VALIDATION_ERROR


def test_unknown_reconciliation_at_limit_escalates_to_review(tmp_path: Path) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(tmp_path / "reconciliation-limit.db") as store:
        action, work = _start_unknown_reconciliation(
            store,
            context,
            max_recovery_attempts=1,
        )
        store.finish_reconciliation(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=work.recovery_id,
            expected_attempt_version=0,
            outcome=ReconciliationOutcome.UNKNOWN,
            evidence_refs=(_digest("reconciliation:limit-unknown"),),
            operation_evidence_ref=_digest("reconciliation:limit-unknown"),
            completed_at=_NOW + timedelta(seconds=19),
            next_attempt_not_before=_NOW + timedelta(seconds=30),
            reason_code="RECONCILIATION_ATTEMPTS_EXHAUSTED",
        )
        reviewed = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=work.recovery_id,
        )
        assert reviewed.state is RecoveryWorkState.REVIEW_REQUIRED
        assert (
            store.get_active_recovery_work(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            == ()
        )
        first_scan = store.scan_recovery_candidates(
            tenant_id=action.tenant_id,
            observed_at=_NOW + timedelta(seconds=31),
        )
        second_scan = store.scan_recovery_candidates(
            tenant_id=action.tenant_id,
            observed_at=_NOW + timedelta(seconds=31),
        )
        assert first_scan == second_scan
        assert first_scan.active_work == ()

        current_dispatch = store.get_commit_dispatch(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )
        with pytest.raises(AgentKernelError) as bypass:
            _authorize_recovery_work(
                store,
                context,
                action,
                current_dispatch,
                kind=RecoveryWorkKind.RECONCILE_DISPATCH,
                generation=2,
                authorized_at=_NOW + timedelta(seconds=31),
                max_recovery_attempts=3,
            )
        assert bypass.value.code is ErrorCode.VERSION_CONFLICT
        assert (
            store.get_recovery_work(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=work.recovery_id,
            )
            == reviewed
        )


@pytest.mark.parametrize(
    ("verdict", "expected_state"),
    [
        (AuthorizationVerdict.DENIED, RecoveryWorkState.FAILED),
        (AuthorizationVerdict.UNKNOWN, RecoveryWorkState.REVIEW_REQUIRED),
    ],
)
def test_ineligible_reconciliation_successor_closes_lineage_without_executable_work(
    tmp_path: Path,
    verdict: AuthorizationVerdict,
    expected_state: RecoveryWorkState,
) -> None:
    context = _context()
    with SQLiteEnforcedTransactionStore(
        tmp_path / f"reconciliation-successor-{verdict.value.lower()}.db"
    ) as store:
        action, initial = _start_unknown_reconciliation(store, context)
        next_attempt = _NOW + timedelta(seconds=30)
        store.finish_reconciliation(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=initial.recovery_id,
            expected_attempt_version=0,
            outcome=ReconciliationOutcome.UNKNOWN,
            evidence_refs=(_digest(f"reconciliation:{verdict.value}:unknown"),),
            operation_evidence_ref=_digest(f"reconciliation:{verdict.value}:unknown"),
            completed_at=_NOW + timedelta(seconds=19),
            next_attempt_not_before=next_attempt,
            reason_code="RECONCILIATION_STILL_UNKNOWN",
        )
        scheduled = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=initial.recovery_id,
        )
        current_dispatch = store.get_commit_dispatch(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
        )

        successor = _authorize_recovery_work(
            store,
            context,
            action,
            current_dispatch,
            kind=RecoveryWorkKind.RECONCILE_DISPATCH,
            generation=2,
            predecessor=scheduled,
            authorized_at=next_attempt,
            verdict=verdict,
        )

        assert successor.state is expected_state
        assert (
            store.get_recovery_work(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=initial.recovery_id,
            ).state
            is RecoveryWorkState.RETRIED
        )
        assert (
            store.get_enforced_transaction(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            ).state
            is TransactionState.IN_DOUBT
        )
        assert (
            store.get_active_recovery_work(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            == ()
        )

        with pytest.raises(AgentKernelError) as bypass:
            _authorize_recovery_work(
                store,
                context,
                action,
                current_dispatch,
                kind=RecoveryWorkKind.RECONCILE_DISPATCH,
                generation=3,
                authorized_at=next_attempt + timedelta(seconds=1),
                max_recovery_attempts=3,
            )
        assert bypass.value.code is ErrorCode.VERSION_CONFLICT
        assert (
            store.get_active_recovery_work(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
            )
            == ()
        )


@pytest.mark.parametrize(
    "verdict",
    [
        AuthorizationVerdict.ELIGIBLE,
        AuthorizationVerdict.DENIED,
        AuthorizationVerdict.UNKNOWN,
    ],
)
def test_recovery_authorization_exact_retry_rejects_coherent_work_binding_tamper(
    tmp_path: Path,
    verdict: AuthorizationVerdict,
) -> None:
    path = tmp_path / f"authorization-binding-{verdict.value.lower()}.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        action, stage, capability_ids = _stage_to_verified(store, context)
        _begin_dispatch(store, action, stage, capability_ids)
        absence = _digest(f"authorization-binding:{verdict.value}:no-effect")
        store.classify_dispatch_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_dispatch_version=0,
            expected_transaction_version=7,
            classification=ReconciliationOutcome.NO_EFFECT,
            evidence_refs=(absence,),
            no_effect_evidence_ref=absence,
            recorded_at=_NOW + timedelta(seconds=13),
            recovery_timeout=timedelta(minutes=10),
        )
        initial = _authorize_recovery_work(
            store,
            context,
            action,
            stage,
            kind=RecoveryWorkKind.DISCARD_STAGING,
            verdict=verdict,
        )
        recovery_capability_ids = (
            ("capability:recovery:discard_staging",)
            if verdict is AuthorizationVerdict.ELIGIBLE
            else ()
        )
        if verdict is AuthorizationVerdict.ELIGIBLE:
            preview = store.preview_recovery_claim(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=initial.recovery_id,
                expected_work_version=0,
                lease_id="lease:authorization-binding",
                worker_id="worker:authorization-binding",
                acquired_at=_NOW + timedelta(seconds=17),
                expires_at=_NOW + timedelta(minutes=5),
            )
            store.claim_recovery(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=initial.recovery_id,
                expected_work_version=0,
                lease_id=preview.lease.lease_id,
                worker_id=preview.lease.worker_id,
                acquired_at=preview.lease.acquired_at,
                expires_at=preview.lease.expires_at,
                permit=preview.permit,
                permit_ref=preview.permit_ref,
            )

        assert (
            _retry_recovery_authorization(
                store,
                initial,
                capability_ids=recovery_capability_ids,
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        authorization_round, authority, policy = _stored_recovery_authorization(
            store,
            initial,
        )
        recovery_action = store.get_normalized_action(
            initial.tenant_id,
            initial.recovery_action_transaction_id,
        ).action
        changed_authority, changed_policy = _strict_decisions(
            recovery_action,
            capability_ids=recovery_capability_ids,
            label=f"recovery-changed:{verdict.value}",
            evaluated_at=authorization_round.evaluated_at,
            modes=("stage",),
            authorization_verdict=verdict,
        )
        handoff = store.get_recovery_action_handoff(
            tenant_id=initial.tenant_id,
            target_transaction_id=initial.transaction_id,
            recovery_id=initial.recovery_id,
        )
        assert handoff is not None
        with pytest.raises(AgentKernelError) as changed_authority_retry:
            store.authorize_recovery(
                initial,
                authorization_round=authorization_round,
                authority_decision=changed_authority,
                policy_decision=policy,
                capability_ids=recovery_capability_ids,
                handoff_failure_evidence_ref=handoff.failure_evidence_ref,
                handoff_failure_evidence_status=handoff.failure_evidence_status,
                handoff_failure_reason_code=handoff.failure_reason_code,
            )
        assert changed_authority_retry.value.code is ErrorCode.INTEGRITY_ERROR
        with pytest.raises(AgentKernelError) as changed_policy_retry:
            store.authorize_recovery(
                initial,
                authorization_round=authorization_round,
                authority_decision=authority,
                policy_decision=changed_policy,
                capability_ids=recovery_capability_ids,
                handoff_failure_evidence_ref=handoff.failure_evidence_ref,
                handoff_failure_evidence_status=handoff.failure_evidence_status,
                handoff_failure_reason_code=handoff.failure_reason_code,
            )
        assert changed_policy_retry.value.code is ErrorCode.INTEGRITY_ERROR
        if verdict is AuthorizationVerdict.ELIGIBLE:
            with pytest.raises(AgentKernelError) as changed_capabilities_retry:
                store.authorize_recovery(
                    initial,
                    authorization_round=authorization_round,
                    authority_decision=authority,
                    policy_decision=policy,
                    capability_ids=tuple(sorted((*recovery_capability_ids, "capability:forged"))),
                )
            assert changed_capabilities_retry.value.code is ErrorCode.INTEGRITY_ERROR
        current = store.get_recovery_work(
            tenant_id=initial.tenant_id,
            transaction_id=initial.transaction_id,
            recovery_id=initial.recovery_id,
        )
        _rewrite_recovery_work_binding(
            store,
            current,
            target_owner_history_digest=_digest(
                f"authorization-binding:{verdict.value}:forged-owner-history"
            ),
        )
        with pytest.raises(AgentKernelError) as exact_retry:
            _retry_recovery_authorization(
                store,
                initial,
                capability_ids=recovery_capability_ids,
            )
        assert exact_retry.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize(
    "kind",
    [RecoveryWorkKind.ROLLBACK, RecoveryWorkKind.COMPENSATE],
)
def test_recovery_revalidation_exact_retry_rejects_coherent_work_binding_tamper(
    tmp_path: Path,
    kind: RecoveryWorkKind,
) -> None:
    path = tmp_path / f"revalidation-binding-{kind.value.lower()}.db"
    context = _context()
    deadline = _NOW + timedelta(seconds=20)
    with SQLiteEnforcedTransactionStore(path) as store:
        action, pending = _pending_effect_recovery(
            store,
            context,
            kind=kind,
            authority_valid_until=deadline,
        )
        failure_ref = _digest(f"revalidation-binding:{kind.value}:failure")
        arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": pending.recovery_id,
            "expected_work_version": 0,
            "target_state": RecoveryWorkState.REVIEW_REQUIRED,
            "evidence_refs": (failure_ref,),
            "reason_code": ErrorCode.DEADLINE_EXCEEDED.value,
            "recorded_at": deadline,
            "handoff_failure_evidence_ref": failure_ref,
            "handoff_failure_evidence_status": (RecoveryHandoffFailureEvidenceStatus.AVAILABLE),
            "handoff_failure_reason_code": ErrorCode.DEADLINE_EXCEEDED.value,
        }
        store.fail_recovery_revalidation(**arguments)  # type: ignore[arg-type]
        assert (
            store.fail_recovery_revalidation(  # type: ignore[arg-type]
                **arguments
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        with pytest.raises(AgentKernelError) as stale_retry:
            store.fail_recovery_revalidation(  # type: ignore[arg-type]
                **{**arguments, "expected_work_version": 999}
            )
        assert stale_retry.value.code is ErrorCode.VERSION_CONFLICT
        terminal = store.get_recovery_work(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=pending.recovery_id,
        )
        _rewrite_recovery_work_binding(
            store,
            terminal,
            target_owner_history_digest=_digest(
                f"revalidation-binding:{kind.value}:forged-owner-history"
            ),
        )
        with pytest.raises(AgentKernelError) as exact_retry:
            store.fail_recovery_revalidation(**arguments)  # type: ignore[arg-type]
        assert exact_retry.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize(
    "kind",
    [RecoveryWorkKind.ROLLBACK, RecoveryWorkKind.COMPENSATE],
)
def test_recovery_claim_exact_retry_rejects_coherent_work_binding_tamper(
    tmp_path: Path,
    kind: RecoveryWorkKind,
) -> None:
    path = tmp_path / f"claim-binding-{kind.value.lower()}.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        action, pending = _pending_effect_recovery(store, context, kind=kind)
        arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": pending.recovery_id,
            "expected_work_version": 0,
            "lease_id": f"lease:claim-binding:{kind.value.lower()}",
            "worker_id": "worker:claim-binding",
            "acquired_at": _NOW + timedelta(seconds=17),
            "expires_at": _NOW + timedelta(minutes=5),
        }
        preview = store.preview_recovery_claim(**arguments)  # type: ignore[arg-type]
        claim_arguments = {
            **arguments,
            "permit": preview.permit,
            "permit_ref": preview.permit_ref,
        }
        claimed = store.claim_recovery(  # type: ignore[arg-type]
            **claim_arguments
        )
        assert (
            store.claim_recovery(  # type: ignore[arg-type]
                **claim_arguments
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        _rewrite_recovery_work_binding(
            store,
            claimed.work,
            target_owner_history_digest=_digest(f"claim-binding:{kind.value}:forged-owner-history"),
        )
        with pytest.raises(AgentKernelError) as exact_retry:
            store.claim_recovery(**claim_arguments)  # type: ignore[arg-type]
        assert exact_retry.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize(
    "kind",
    [RecoveryWorkKind.ROLLBACK, RecoveryWorkKind.COMPENSATE],
)
def test_failed_recovery_finish_exact_retry_rejects_coherent_work_binding_tamper(
    tmp_path: Path,
    kind: RecoveryWorkKind,
) -> None:
    path = tmp_path / f"finish-failed-binding-{kind.value.lower()}.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        action, pending = _pending_effect_recovery(store, context, kind=kind)
        claim_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": pending.recovery_id,
            "expected_work_version": 0,
            "lease_id": f"lease:finish-failed:{kind.value.lower()}",
            "worker_id": "worker:finish-failed",
            "acquired_at": _NOW + timedelta(seconds=17),
            "expires_at": _NOW + timedelta(minutes=5),
        }
        preview = store.preview_recovery_claim(  # type: ignore[arg-type]
            **claim_arguments
        )
        claimed = store.claim_recovery(  # type: ignore[arg-type]
            **claim_arguments,
            permit=preview.permit,
            permit_ref=preview.permit_ref,
        )
        operation_ref = _digest(f"finish-failed:{kind.value}:operation")
        finish_arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": pending.recovery_id,
            "expected_work_version": claimed.work.version,
            "succeeded": False,
            "evidence_refs": (operation_ref,),
            "operation_evidence_ref": operation_ref,
            "completed_at": _NOW + timedelta(seconds=18),
            "reason_code": "RECOVERY_OPERATION_FAILED",
        }
        finished = store.finish_recovery(**finish_arguments)  # type: ignore[arg-type]
        assert finished.work.state is RecoveryWorkState.FAILED
        assert finished.lease.version == 1
        assert (
            store.finish_recovery(  # type: ignore[arg-type]
                **finish_arguments
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        with pytest.raises(AgentKernelError) as changed_result:
            store.finish_recovery(  # type: ignore[arg-type]
                **{
                    **finish_arguments,
                    "succeeded": True,
                    "reason_code": None,
                }
            )
        assert changed_result.value.code is ErrorCode.INTEGRITY_ERROR
        _rewrite_recovery_work_binding(
            store,
            finished.work,
            target_owner_history_digest=_digest(f"finish-failed:{kind.value}:forged-owner-history"),
        )
        with pytest.raises(AgentKernelError) as exact_retry:
            store.finish_recovery(**finish_arguments)  # type: ignore[arg-type]
        assert exact_retry.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize(
    "kind",
    [RecoveryWorkKind.ROLLBACK, RecoveryWorkKind.COMPENSATE],
)
def test_claimed_setup_failure_retry_rejects_coherent_work_binding_tamper(
    tmp_path: Path,
    kind: RecoveryWorkKind,
) -> None:
    path = tmp_path / f"setup-failure-binding-{kind.value.lower()}.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        action, pending = _pending_effect_recovery(store, context, kind=kind)
        preview = store.preview_recovery_claim(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=pending.recovery_id,
            expected_work_version=0,
            lease_id=f"lease:setup-failure-binding:{kind.value.lower()}",
            worker_id="worker:setup-failure-binding",
            acquired_at=_NOW + timedelta(seconds=17),
            expires_at=_NOW + timedelta(minutes=5),
        )
        claimed = store.claim_recovery(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=pending.recovery_id,
            expected_work_version=0,
            lease_id=preview.lease.lease_id,
            worker_id=preview.lease.worker_id,
            acquired_at=preview.lease.acquired_at,
            expires_at=preview.lease.expires_at,
            permit=preview.permit,
            permit_ref=preview.permit_ref,
        ).work
        failure_ref = _digest(f"setup-failure-binding:{kind.value}:operation")
        arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": pending.recovery_id,
            "expected_work_version": claimed.version,
            "failure_evidence_ref": failure_ref,
            "reason_code": "RECOVERY_SETUP_FAILED",
            "recorded_at": _NOW + timedelta(seconds=18),
        }
        terminal = store.fail_claimed_recovery_setup(  # type: ignore[arg-type]
            **arguments
        )
        assert terminal.state is RecoveryWorkState.REVIEW_REQUIRED
        assert (
            store.fail_claimed_recovery_setup(  # type: ignore[arg-type]
                **arguments
            )
            == terminal
        )
        _rewrite_recovery_work_binding(
            store,
            terminal,
            target_owner_history_digest=_digest(
                f"setup-failure-binding:{kind.value}:forged-owner-history"
            ),
        )
        with pytest.raises(AgentKernelError) as exact_retry:
            store.fail_claimed_recovery_setup(  # type: ignore[arg-type]
                **arguments
            )
        assert exact_retry.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


def test_recovery_reclaim_exact_retry_rejects_coherent_work_binding_tamper(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reclaim-binding-discard.db"
    context = _context()
    with SQLiteEnforcedTransactionStore(path) as store:
        action, stage, capability_ids = _stage_to_verified(store, context)
        _begin_dispatch(store, action, stage, capability_ids)
        absence = _digest("reclaim-binding:no-effect")
        store.classify_dispatch_outcome(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            expected_dispatch_version=0,
            expected_transaction_version=7,
            classification=ReconciliationOutcome.NO_EFFECT,
            evidence_refs=(absence,),
            no_effect_evidence_ref=absence,
            recorded_at=_NOW + timedelta(seconds=13),
            recovery_timeout=timedelta(minutes=10),
        )
        pending = _authorize_recovery_work(
            store,
            context,
            action,
            stage,
            kind=RecoveryWorkKind.DISCARD_STAGING,
        )
        initial_preview = store.preview_recovery_claim(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=pending.recovery_id,
            expected_work_version=0,
            lease_id="lease:reclaim-binding:initial",
            worker_id="worker:reclaim-binding:initial",
            acquired_at=_NOW + timedelta(seconds=17),
            expires_at=_NOW + timedelta(seconds=18),
        )
        initial = store.claim_recovery(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=pending.recovery_id,
            expected_work_version=0,
            lease_id=initial_preview.lease.lease_id,
            worker_id=initial_preview.lease.worker_id,
            acquired_at=initial_preview.lease.acquired_at,
            expires_at=initial_preview.lease.expires_at,
            permit=initial_preview.permit,
            permit_ref=initial_preview.permit_ref,
        )
        reclaim_preview = store.preview_recovery_reclaim(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=pending.recovery_id,
            expected_work_version=1,
            lease_id="lease:reclaim-binding:replacement",
            worker_id="worker:reclaim-binding:replacement",
            acquired_at=_NOW + timedelta(seconds=19),
            expires_at=_NOW + timedelta(minutes=5),
        )
        assert initial.work.permit_ref is not None
        expiry_ref = _digest("reclaim-binding:lease-expired")
        evidence_refs = tuple(
            sorted(
                {
                    initial.work.permit_ref,
                    reclaim_preview.permit_ref,
                    expiry_ref,
                }
            )
        )
        arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": pending.recovery_id,
            "expected_work_version": 1,
            "lease_id": reclaim_preview.lease.lease_id,
            "worker_id": reclaim_preview.lease.worker_id,
            "acquired_at": reclaim_preview.lease.acquired_at,
            "expires_at": reclaim_preview.lease.expires_at,
            "permit": reclaim_preview.permit,
            "permit_ref": reclaim_preview.permit_ref,
            "evidence_refs": evidence_refs,
        }
        reclaimed = store.reclaim_expired_recovery(  # type: ignore[arg-type]
            **arguments
        )
        assert reclaimed.work.version == 2
        assert reclaimed.lease.version == 0
        assert (
            store.reclaim_expired_recovery(  # type: ignore[arg-type]
                **arguments
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        with pytest.raises(AgentKernelError) as stale_retry:
            store.reclaim_expired_recovery(  # type: ignore[arg-type]
                **{**arguments, "expected_work_version": 999}
            )
        assert stale_retry.value.code is ErrorCode.VERSION_CONFLICT
        with pytest.raises(AgentKernelError) as changed_evidence:
            store.reclaim_expired_recovery(  # type: ignore[arg-type]
                **{
                    **arguments,
                    "evidence_refs": tuple(
                        sorted({*evidence_refs, _digest("reclaim-binding:changed")})
                    ),
                }
            )
        assert changed_evidence.value.code is ErrorCode.INTEGRITY_ERROR
        _rewrite_recovery_work_binding(
            store,
            reclaimed.work,
            target_owner_history_digest=_digest("reclaim-binding:forged-owner-history"),
        )
        with pytest.raises(AgentKernelError) as exact_retry:
            store.reclaim_expired_recovery(  # type: ignore[arg-type]
                **arguments
            )
        assert exact_retry.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.parametrize(
    "kind",
    [
        RecoveryWorkKind.ROLLBACK,
        RecoveryWorkKind.COMPENSATE,
        RecoveryWorkKind.RECONCILE_DISPATCH,
    ],
)
def test_late_recovery_exact_retry_rejects_coherent_work_binding_tamper(
    tmp_path: Path,
    kind: RecoveryWorkKind,
) -> None:
    path = tmp_path / f"late-binding-{kind.value.lower()}.db"
    context = _context()
    deadline = _NOW + timedelta(seconds=18)
    with SQLiteEnforcedTransactionStore(path) as store:
        if kind is RecoveryWorkKind.RECONCILE_DISPATCH:
            action, pending = _claim_unknown_reconciliation(
                store,
                context,
                authority_valid_until=deadline,
            )
            store.start_reconciliation(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=pending.recovery_id,
                expected_work_version=1,
                evidence_refs=(_digest("late-binding:reconciliation-started"),),
                started_at=_NOW + timedelta(seconds=17, milliseconds=500),
            )
        else:
            action, pending = _pending_effect_recovery(
                store,
                context,
                kind=kind,
                authority_valid_until=deadline,
            )
            preview = store.preview_recovery_claim(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=pending.recovery_id,
                expected_work_version=0,
                lease_id=f"lease:late-binding:{kind.value.lower()}",
                worker_id="worker:late-binding",
                acquired_at=_NOW + timedelta(seconds=17),
                expires_at=_NOW + timedelta(minutes=5),
            )
            store.claim_recovery(
                tenant_id=action.tenant_id,
                transaction_id=action.transaction_id,
                recovery_id=pending.recovery_id,
                expected_work_version=0,
                lease_id=preview.lease.lease_id,
                worker_id=preview.lease.worker_id,
                acquired_at=preview.lease.acquired_at,
                expires_at=preview.lease.expires_at,
                permit=preview.permit,
                permit_ref=preview.permit_ref,
            )
        operation_ref = _digest(f"late-binding:{kind.value}:operation")
        wrapper_ref = _digest(f"late-binding:{kind.value}:wrapper")
        arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": pending.recovery_id,
            "expected_work_version": 1,
            "evidence_refs": (operation_ref, wrapper_ref),
            "operation_evidence_ref": operation_ref,
            "reported_at": deadline,
            "reason_code": (
                "LATE_RECONCILIATION_REPORT"
                if kind is RecoveryWorkKind.RECONCILE_DISPATCH
                else "LATE_RECOVERY_REPORT"
            ),
        }
        late = store.record_late_recovery_outcome(  # type: ignore[arg-type]
            **arguments
        )
        assert late.work.state is RecoveryWorkState.REVIEW_REQUIRED
        assert late.lease is not None
        assert late.lease.version == 1
        if late.reconciliation_attempt is not None:
            assert late.reconciliation_attempt.operation_evidence_ref == operation_ref
            assert late.reconciliation_attempt.operation_reason_code is None
        assert (
            store.record_late_recovery_outcome(  # type: ignore[arg-type]
                **arguments
            ).disposition
            is EnforcedStoreDisposition.EXACT_RETRY
        )
        with pytest.raises(AgentKernelError) as changed_operation:
            store.record_late_recovery_outcome(  # type: ignore[arg-type]
                **{**arguments, "operation_evidence_ref": wrapper_ref}
            )
        assert changed_operation.value.code is ErrorCode.INTEGRITY_ERROR
        _rewrite_recovery_work_binding(
            store,
            late.work,
            target_owner_history_digest=_digest(f"late-binding:{kind.value}:forged-owner-history"),
        )
        with pytest.raises(AgentKernelError) as exact_retry:
            store.record_late_recovery_outcome(  # type: ignore[arg-type]
                **arguments
            )
        assert exact_retry.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


def test_late_report_exact_retry_rejects_alternate_operation_from_same_evidence_set(
    tmp_path: Path,
) -> None:
    path = tmp_path / "late-report-operation-tamper.db"
    context = _context()
    deadline = _NOW + timedelta(seconds=18)
    with SQLiteEnforcedTransactionStore(path) as store:
        action, _stage, running = _claim_discard_for_late_report(
            store,
            context,
            authority_valid_until=deadline,
        )
        operation_ref = _digest("late-report-operation:authoritative")
        alternate_ref = _digest("late-report-operation:alternate")
        arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": running.recovery_id,
            "expected_work_version": 1,
            "evidence_refs": (operation_ref, alternate_ref),
            "operation_evidence_ref": operation_ref,
            "operation_reason_code": "RECOVERY_EXECUTION_FAILED",
            "reported_at": deadline,
            "reason_code": "LATE_RECOVERY_REPORT",
        }
        store.record_late_recovery_outcome(**arguments)  # type: ignore[arg-type]
        report = store.get_late_recovery_report(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=running.recovery_id,
        )
        assert report is not None
        assert report.operation_evidence_ref == operation_ref
        assert report.operation_reason_code == "RECOVERY_EXECUTION_FAILED"
        _rewrite_late_report_operation(
            store,
            report,
            operation_evidence_ref=alternate_ref,
            operation_reason_code=None,
        )
        with pytest.raises(AgentKernelError) as exact_retry:
            store.record_late_recovery_outcome(  # type: ignore[arg-type]
                **arguments
            )
        assert exact_retry.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR


def test_late_reconciliation_exact_retry_rejects_attempt_operation_pair_tamper(
    tmp_path: Path,
) -> None:
    path = tmp_path / "late-reconciliation-attempt-operation-tamper.db"
    context = _context()
    deadline = _NOW + timedelta(seconds=18)
    with SQLiteEnforcedTransactionStore(path) as store:
        action, pending = _claim_unknown_reconciliation(
            store,
            context,
            authority_valid_until=deadline,
        )
        store.start_reconciliation(
            tenant_id=action.tenant_id,
            transaction_id=action.transaction_id,
            recovery_id=pending.recovery_id,
            expected_work_version=1,
            evidence_refs=(_digest("late-attempt-operation:started"),),
            started_at=_NOW + timedelta(seconds=17, milliseconds=500),
        )
        operation_ref = _digest("late-attempt-operation:authoritative")
        alternate_ref = _digest("late-attempt-operation:alternate")
        arguments: dict[str, object] = {
            "tenant_id": action.tenant_id,
            "transaction_id": action.transaction_id,
            "recovery_id": pending.recovery_id,
            "expected_work_version": 1,
            "evidence_refs": (operation_ref, alternate_ref),
            "operation_evidence_ref": operation_ref,
            "reported_at": deadline,
            "reason_code": "LATE_RECONCILIATION_REPORT",
        }
        late = store.record_late_recovery_outcome(  # type: ignore[arg-type]
            **arguments
        )
        assert late.reconciliation_attempt is not None
        assert late.reconciliation_attempt.operation_evidence_ref == operation_ref
        _rewrite_reconciliation_attempt_operation(
            store,
            late.reconciliation_attempt,
            operation_evidence_ref=alternate_ref,
        )
        with pytest.raises(AgentKernelError) as exact_retry:
            store.record_late_recovery_outcome(  # type: ignore[arg-type]
                **arguments
            )
        assert exact_retry.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as reopened:
        SQLiteEnforcedTransactionStore(path)
    assert reopened.value.code is ErrorCode.INTEGRITY_ERROR
