"""Single-node SQLite WAL transaction journal and event store."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import JsonValue

from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import TERMINAL_TRANSACTION_STATES
from agentkernel.domain.models import EffectReceipt, EventEnvelope, TransactionRecord
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.ledger import make_event
from agentkernel.transactions.state_machine import TransitionEvent, apply_transition

_INITIAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    digest TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    transaction_id TEXT PRIMARY KEY,
    goal_id TEXT NOT NULL,
    state TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 0),
    intent_hash TEXT,
    intended_outcome TEXT,
    record_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS transactions_state_idx ON transactions(state);

CREATE TABLE IF NOT EXISTS intents (
    intent_hash TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    reserved_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
    receipt_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    event_id TEXT NOT NULL UNIQUE,
    transaction_id TEXT,
    event_hash TEXT NOT NULL,
    previous_event_hash TEXT,
    event_json TEXT NOT NULL,
    PRIMARY KEY (run_id, sequence)
);
"""

MIGRATIONS: tuple[tuple[int, str], ...] = ((1, _INITIAL_SCHEMA),)

_CAPABILITY_USE_SCHEMA = """
CREATE TABLE IF NOT EXISTS capability_uses (
    capability_id TEXT PRIMARY KEY,
    uses INTEGER NOT NULL CHECK (uses >= 0),
    updated_at TEXT NOT NULL
);
"""

MIGRATIONS = (*MIGRATIONS, (2, _CAPABILITY_USE_SCHEMA))

_ENFORCED_CONTROL_SCHEMA = """
CREATE TABLE enforced_tenants (
    tenant_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id)
);

CREATE TABLE enforced_principals (
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, principal_id),
    FOREIGN KEY (tenant_id) REFERENCES enforced_tenants(tenant_id)
);

CREATE TABLE enforced_goals (
    tenant_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, goal_id),
    UNIQUE (tenant_id, principal_id, goal_id),
    FOREIGN KEY (tenant_id, principal_id)
        REFERENCES enforced_principals(tenant_id, principal_id)
);

CREATE TABLE enforced_runs (
    tenant_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    UNIQUE (tenant_id, goal_id, run_id),
    UNIQUE (tenant_id, principal_id, goal_id, run_id),
    FOREIGN KEY (tenant_id, principal_id, goal_id)
        REFERENCES enforced_goals(tenant_id, principal_id, goal_id)
);

CREATE TABLE enforced_normalized_actions (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    action_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id),
    UNIQUE (tenant_id, transaction_id, intent_hash),
    FOREIGN KEY (tenant_id, principal_id, goal_id, run_id)
        REFERENCES enforced_runs(tenant_id, principal_id, goal_id, run_id)
);

CREATE INDEX enforced_normalized_actions_intent_idx
    ON enforced_normalized_actions(tenant_id, intent_hash);

CREATE TABLE enforced_resource_uses (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    canonical_resource TEXT NOT NULL,
    resource_use_digest TEXT NOT NULL,
    resource_use_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, ordinal),
    UNIQUE (tenant_id, transaction_id, resource_use_digest),
    FOREIGN KEY (tenant_id, transaction_id)
        REFERENCES enforced_normalized_actions(tenant_id, transaction_id)
);

CREATE INDEX enforced_resource_uses_resource_idx
    ON enforced_resource_uses(tenant_id, canonical_resource);

CREATE TABLE enforced_intent_owners (
    tenant_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    owner_transaction_id TEXT NOT NULL,
    owner_version INTEGER NOT NULL CHECK (owner_version >= 0),
    history_head_sequence INTEGER NOT NULL DEFAULT -1 CHECK (history_head_sequence >= -1),
    history_head_digest TEXT,
    acquired_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, intent_hash),
    FOREIGN KEY (tenant_id, owner_transaction_id, intent_hash)
        REFERENCES enforced_normalized_actions(tenant_id, transaction_id, intent_hash),
    CHECK (
        (history_head_sequence = -1 AND history_head_digest IS NULL)
        OR (history_head_sequence >= 0 AND history_head_digest IS NOT NULL)
    )
);

CREATE TABLE enforced_intent_attempts (
    tenant_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    attempt_state TEXT NOT NULL CHECK (
        attempt_state IN (
            'ACTIVE',
            'RECONCILE_REQUIRED',
            'COMMITTED',
            'NO_EFFECT_CONFIRMED',
            'REVIEW_REQUIRED'
        )
    ),
    state_version INTEGER NOT NULL CHECK (state_version >= 0),
    evidence_digest TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, intent_hash, transaction_id),
    FOREIGN KEY (tenant_id, transaction_id, intent_hash)
        REFERENCES enforced_normalized_actions(tenant_id, transaction_id, intent_hash)
);

CREATE TABLE enforced_intent_attempt_history (
    tenant_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    transaction_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('ACQUIRE', 'STATE_CHANGED')),
    disposition TEXT CHECK (
        disposition IS NULL OR disposition IN (
            'ACQUIRED',
            'SAME_TRANSACTION',
            'ALIAS_ACTIVE',
            'ALIAS_RECONCILE',
            'ALIAS_COMMITTED',
            'TRANSFERRED_NO_EFFECT',
            'REVIEW_REQUIRED'
        )
    ),
    attempt_state TEXT NOT NULL,
    owner_transaction_id TEXT NOT NULL,
    owner_version INTEGER NOT NULL CHECK (owner_version >= 0),
    evidence_digest TEXT,
    previous_history_digest TEXT,
    history_digest TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, intent_hash, sequence),
    UNIQUE (tenant_id, intent_hash, history_digest),
    FOREIGN KEY (tenant_id, intent_hash)
        REFERENCES enforced_intent_owners(tenant_id, intent_hash),
    FOREIGN KEY (tenant_id, intent_hash, transaction_id)
        REFERENCES enforced_intent_attempts(tenant_id, intent_hash, transaction_id)
);

CREATE TABLE enforced_capability_budgets (
    tenant_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    max_uses INTEGER NOT NULL CHECK (max_uses > 0),
    reserved_uses INTEGER NOT NULL DEFAULT 0 CHECK (reserved_uses >= 0),
    committed_uses INTEGER NOT NULL DEFAULT 0 CHECK (committed_uses >= 0),
    version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    registration_digest TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, capability_id, goal_id, run_id),
    FOREIGN KEY (tenant_id, goal_id, run_id)
        REFERENCES enforced_runs(tenant_id, goal_id, run_id),
    CHECK (reserved_uses + committed_uses <= max_uses)
);

CREATE TABLE enforced_capability_chain_reservations (
    tenant_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    reservation_state TEXT NOT NULL CHECK (
        reservation_state IN ('RESERVED', 'COMMITTED', 'RELEASED')
    ),
    activation_owner_transaction_id TEXT,
    activation_owner_version INTEGER CHECK (activation_owner_version >= 0),
    activation_history_sequence INTEGER CHECK (activation_history_sequence >= 0),
    activation_history_digest TEXT,
    release_history_sequence INTEGER CHECK (release_history_sequence >= 0),
    release_history_digest TEXT,
    version INTEGER NOT NULL CHECK (version >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, goal_id, run_id, intent_hash),
    FOREIGN KEY (tenant_id, goal_id, run_id)
        REFERENCES enforced_runs(tenant_id, goal_id, run_id),
    FOREIGN KEY (tenant_id, intent_hash, activation_owner_transaction_id)
        REFERENCES enforced_intent_attempts(tenant_id, intent_hash, transaction_id),
    CHECK (
        (activation_owner_transaction_id IS NULL
            AND activation_owner_version IS NULL
            AND activation_history_sequence IS NULL
            AND activation_history_digest IS NULL)
        OR (activation_owner_transaction_id IS NOT NULL
            AND activation_owner_version IS NOT NULL
            AND activation_history_sequence IS NOT NULL
            AND activation_history_digest IS NOT NULL)
    ),
    CHECK (
        (release_history_sequence IS NULL AND release_history_digest IS NULL)
        OR (release_history_sequence IS NOT NULL AND release_history_digest IS NOT NULL)
    ),
    CHECK (
        reservation_state = 'RELEASED'
        OR (release_history_sequence IS NULL AND release_history_digest IS NULL)
    )
);

CREATE TABLE enforced_capability_use_reservations (
    tenant_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    chain_ordinal INTEGER NOT NULL CHECK (chain_ordinal >= 0),
    request_digest TEXT NOT NULL,
    reservation_state TEXT NOT NULL CHECK (
        reservation_state IN ('RESERVED', 'COMMITTED', 'RELEASED')
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, capability_id, goal_id, run_id, intent_hash),
    UNIQUE (tenant_id, goal_id, run_id, intent_hash, chain_ordinal),
    FOREIGN KEY (tenant_id, capability_id, goal_id, run_id)
        REFERENCES enforced_capability_budgets(tenant_id, capability_id, goal_id, run_id),
    FOREIGN KEY (tenant_id, goal_id, run_id, intent_hash)
        REFERENCES enforced_capability_chain_reservations(tenant_id, goal_id, run_id, intent_hash)
);

CREATE TABLE enforced_decision_snapshots (
    tenant_id TEXT NOT NULL,
    decision_kind TEXT NOT NULL CHECK (decision_kind IN ('AUTHORITY', 'POLICY')),
    decision_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    decision_digest TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, decision_kind, decision_id),
    UNIQUE (tenant_id, decision_kind, decision_digest),
    FOREIGN KEY (tenant_id, transaction_id, intent_hash)
        REFERENCES enforced_normalized_actions(tenant_id, transaction_id, intent_hash)
);

CREATE INDEX enforced_decision_snapshots_transaction_idx
    ON enforced_decision_snapshots(tenant_id, transaction_id, decision_kind);

CREATE TRIGGER enforced_normalized_actions_no_update
BEFORE UPDATE ON enforced_normalized_actions
BEGIN
    SELECT RAISE(ABORT, 'enforced normalized actions are immutable');
END;

CREATE TRIGGER enforced_normalized_actions_no_delete
BEFORE DELETE ON enforced_normalized_actions
BEGIN
    SELECT RAISE(ABORT, 'enforced normalized actions are immutable');
END;

CREATE TRIGGER enforced_resource_uses_no_update
BEFORE UPDATE ON enforced_resource_uses
BEGIN
    SELECT RAISE(ABORT, 'enforced resource uses are immutable');
END;

CREATE TRIGGER enforced_resource_uses_no_delete
BEFORE DELETE ON enforced_resource_uses
BEGIN
    SELECT RAISE(ABORT, 'enforced resource uses are immutable');
END;

CREATE TRIGGER enforced_intent_history_no_update
BEFORE UPDATE ON enforced_intent_attempt_history
BEGIN
    SELECT RAISE(ABORT, 'enforced intent history is immutable');
END;

CREATE TRIGGER enforced_intent_history_no_delete
BEFORE DELETE ON enforced_intent_attempt_history
BEGIN
    SELECT RAISE(ABORT, 'enforced intent history is immutable');
END;

CREATE TRIGGER enforced_decision_snapshots_no_update
BEFORE UPDATE ON enforced_decision_snapshots
BEGIN
    SELECT RAISE(ABORT, 'enforced decision snapshots are immutable');
END;

CREATE TRIGGER enforced_decision_snapshots_no_delete
BEFORE DELETE ON enforced_decision_snapshots
BEGIN
    SELECT RAISE(ABORT, 'enforced decision snapshots are immutable');
END;

CREATE TRIGGER enforced_capability_budget_binding_immutable
BEFORE UPDATE ON enforced_capability_budgets
WHEN NEW.tenant_id != OLD.tenant_id
    OR NEW.capability_id != OLD.capability_id
    OR NEW.goal_id != OLD.goal_id
    OR NEW.run_id != OLD.run_id
    OR NEW.max_uses != OLD.max_uses
    OR NEW.registration_digest != OLD.registration_digest
    OR NEW.registered_at != OLD.registered_at
BEGIN
    SELECT RAISE(ABORT, 'enforced capability budget binding is immutable');
END;
"""

MIGRATIONS = (*MIGRATIONS, (3, _ENFORCED_CONTROL_SCHEMA))

_ENFORCED_TRANSACTION_SCHEMA = """
ALTER TABLE enforced_capability_chain_reservations
    ADD COLUMN reuse_without_budget INTEGER NOT NULL DEFAULT 0
    CHECK (reuse_without_budget IN (0, 1));

CREATE UNIQUE INDEX enforced_normalized_actions_full_binding_uq
    ON enforced_normalized_actions(
        tenant_id, transaction_id, intent_hash, action_digest
    );

CREATE UNIQUE INDEX enforced_decision_snapshots_full_binding_uq
    ON enforced_decision_snapshots(
        tenant_id, decision_kind, decision_id, transaction_id,
        intent_hash, decision_digest
    );

CREATE TABLE enforced_transactions (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    on_behalf_of TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    intent_hash TEXT,
    normalized_action_digest TEXT,
    adapter TEXT,
    operation TEXT,
    adapter_manifest_digest TEXT,
    state TEXT NOT NULL CHECK (
        state IN (
            'NEW', 'PLANNED', 'REJECTED', 'AUTHORIZED_TO_STAGE', 'STAGING',
            'STAGED', 'STAGE_VERIFIED', 'AWAITING_APPROVAL', 'READY_TO_COMMIT',
            'COMMITTING', 'COMMITTED', 'FAILED', 'ABORTING', 'ABORTED',
            'STALE_STATE', 'ROLLING_BACK', 'ROLLED_BACK', 'COMPENSATING',
            'COMPENSATED', 'COMPENSATION_FAILED', 'RECOVERY_FAILED',
            'IN_DOUBT', 'RECONCILING'
        )
    ),
    version INTEGER NOT NULL CHECK (version >= 0),
    deadline TEXT,
    authorization_round_id TEXT,
    authorization_round_digest TEXT,
    authority_decision_digest TEXT,
    policy_decision_digest TEXT,
    policy_snapshot_digest TEXT,
    capability_reservation_digest TEXT,
    allowed_modes_json TEXT NOT NULL,
    obligations_json TEXT NOT NULL,
    intended_outcome TEXT CHECK (
        intended_outcome IS NULL OR intended_outcome IN ('ABORTED', 'STALE_STATE')
    ),
    reason_code TEXT,
    event_head_sequence INTEGER NOT NULL CHECK (event_head_sequence >= 0),
    event_head_digest TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id),
    UNIQUE (tenant_id, transaction_id, request_digest),
    UNIQUE (
        tenant_id, transaction_id, intent_hash, normalized_action_digest
    ),
    FOREIGN KEY (tenant_id, principal_id, goal_id, run_id)
        REFERENCES enforced_runs(tenant_id, principal_id, goal_id, run_id),
    FOREIGN KEY (
        tenant_id, transaction_id, intent_hash, normalized_action_digest
    ) REFERENCES enforced_normalized_actions(
        tenant_id, transaction_id, intent_hash, action_digest
    ),
    CHECK (event_head_sequence = version),
    CHECK (
        (intent_hash IS NULL AND normalized_action_digest IS NULL)
        OR (intent_hash IS NOT NULL AND normalized_action_digest IS NOT NULL)
    )
);

CREATE INDEX enforced_transactions_recovery_scan_idx
    ON enforced_transactions(tenant_id, state, updated_at, transaction_id);

CREATE INDEX enforced_transactions_intent_idx
    ON enforced_transactions(tenant_id, intent_hash, transaction_id);

CREATE TABLE enforced_transaction_events (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    transaction_version INTEGER NOT NULL CHECK (transaction_version >= 0),
    event_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    event TEXT NOT NULL,
    source_state TEXT,
    target_state TEXT NOT NULL,
    intended_outcome TEXT,
    actor_id TEXT NOT NULL,
    on_behalf_of TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    previous_event_digest TEXT,
    event_digest TEXT NOT NULL,
    event_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, sequence),
    UNIQUE (tenant_id, event_id),
    UNIQUE (tenant_id, transaction_id, event_digest),
    FOREIGN KEY (tenant_id, transaction_id)
        REFERENCES enforced_transactions(tenant_id, transaction_id),
    CHECK (sequence = transaction_version)
);

CREATE TABLE enforced_authorization_rounds (
    tenant_id TEXT NOT NULL,
    controlled_transaction_id TEXT NOT NULL,
    round_id TEXT NOT NULL,
    subject_transaction_id TEXT NOT NULL,
    subject_intent_hash TEXT NOT NULL,
    subject_normalized_action_digest TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('STAGING', 'PRECOMMIT', 'RECOVERY')),
    verdict TEXT NOT NULL CHECK (verdict IN ('ELIGIBLE', 'DENIED', 'UNKNOWN')),
    authority_snapshot_id TEXT NOT NULL,
    authority_snapshot_digest TEXT NOT NULL,
    authority_decision_kind TEXT NOT NULL DEFAULT 'AUTHORITY'
        CHECK (authority_decision_kind = 'AUTHORITY'),
    authority_decision_id TEXT NOT NULL,
    authority_decision_record_digest TEXT NOT NULL,
    authority_decision_digest TEXT NOT NULL,
    policy_decision_kind TEXT NOT NULL DEFAULT 'POLICY'
        CHECK (policy_decision_kind = 'POLICY'),
    policy_decision_id TEXT NOT NULL,
    policy_decision_record_digest TEXT NOT NULL,
    policy_decision_digest TEXT NOT NULL,
    policy_snapshot_digest TEXT NOT NULL,
    capability_reservation_plan_digest TEXT,
    capability_reservation_digest TEXT,
    reservation_version INTEGER CHECK (reservation_version >= 0),
    reservation_goal_id TEXT,
    reservation_run_id TEXT,
    owner_version INTEGER NOT NULL CHECK (owner_version >= 0),
    owner_history_sequence INTEGER NOT NULL CHECK (owner_history_sequence >= 0),
    owner_history_digest TEXT NOT NULL,
    allowed_modes_json TEXT NOT NULL,
    obligations_json TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    evaluated_at TEXT NOT NULL,
    round_digest TEXT NOT NULL,
    round_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, controlled_transaction_id, round_id),
    UNIQUE (tenant_id, round_id),
    UNIQUE (tenant_id, controlled_transaction_id, round_digest),
    FOREIGN KEY (tenant_id, controlled_transaction_id)
        REFERENCES enforced_transactions(tenant_id, transaction_id),
    FOREIGN KEY (
        tenant_id, subject_transaction_id, subject_intent_hash,
        subject_normalized_action_digest
    ) REFERENCES enforced_normalized_actions(
        tenant_id, transaction_id, intent_hash, action_digest
    ),
    FOREIGN KEY (
        tenant_id, authority_decision_kind, authority_decision_id,
        subject_transaction_id, subject_intent_hash,
        authority_decision_record_digest
    ) REFERENCES enforced_decision_snapshots(
        tenant_id, decision_kind, decision_id, transaction_id,
        intent_hash, decision_digest
    ),
    FOREIGN KEY (
        tenant_id, policy_decision_kind, policy_decision_id,
        subject_transaction_id, subject_intent_hash,
        policy_decision_record_digest
    ) REFERENCES enforced_decision_snapshots(
        tenant_id, decision_kind, decision_id, transaction_id,
        intent_hash, decision_digest
    ),
    FOREIGN KEY (
        tenant_id, reservation_goal_id, reservation_run_id, subject_intent_hash
    ) REFERENCES enforced_capability_chain_reservations(
        tenant_id, goal_id, run_id, intent_hash
    ),
    CHECK (
        (capability_reservation_plan_digest IS NULL
            AND capability_reservation_digest IS NULL
            AND reservation_version IS NULL
            AND reservation_goal_id IS NULL
            AND reservation_run_id IS NULL)
        OR (capability_reservation_plan_digest IS NOT NULL
            AND capability_reservation_digest IS NOT NULL
            AND reservation_version IS NOT NULL
            AND reservation_goal_id IS NOT NULL
            AND reservation_run_id IS NOT NULL)
    )
);

CREATE TABLE enforced_worker_leases (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (
        purpose IN ('STAGING', 'RECONCILIATION', 'RECOVERY')
    ),
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    version INTEGER NOT NULL CHECK (version >= 0),
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    released_at TEXT,
    record_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, lease_id),
    UNIQUE (tenant_id, transaction_id, fencing_token),
    FOREIGN KEY (tenant_id, transaction_id)
        REFERENCES enforced_transactions(tenant_id, transaction_id)
);

CREATE UNIQUE INDEX enforced_worker_leases_one_active_uq
    ON enforced_worker_leases(tenant_id, transaction_id)
    WHERE released_at IS NULL;

CREATE UNIQUE INDEX enforced_worker_leases_full_binding_uq
    ON enforced_worker_leases(
        tenant_id, transaction_id, lease_id, fencing_token
    );

CREATE INDEX enforced_worker_leases_expiry_idx
    ON enforced_worker_leases(tenant_id, expires_at, transaction_id, lease_id)
    WHERE released_at IS NULL;

CREATE TABLE enforced_stage_material (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    stage_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    intent_hash TEXT NOT NULL,
    normalized_action_digest TEXT NOT NULL,
    adapter_manifest_digest TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    plan_ref TEXT NOT NULL,
    inspection_permit_digest TEXT NOT NULL,
    inspection_permit_ref TEXT NOT NULL,
    stage_permit_digest TEXT NOT NULL,
    stage_permit_ref TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN (
            'ALLOCATED', 'STAGED', 'EXECUTED', 'VERIFIED',
            'DISCARDED', 'DISCARD_FAILED'
        )
    ),
    base_state_digest TEXT,
    target_version_guard TEXT NOT NULL,
    staged_effect_ref TEXT,
    staged_receipt_ref TEXT,
    staged_state_digest TEXT,
    verification_permit_digest TEXT,
    verification_permit_ref TEXT,
    verification_ref TEXT,
    discard_evidence_ref TEXT,
    version INTEGER NOT NULL CHECK (version >= 0),
    record_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, stage_id),
    UNIQUE (tenant_id, transaction_id),
    UNIQUE (tenant_id, transaction_id, stage_id, lease_id, fencing_token),
    FOREIGN KEY (
        tenant_id, transaction_id, intent_hash, normalized_action_digest
    ) REFERENCES enforced_normalized_actions(
        tenant_id, transaction_id, intent_hash, action_digest
    ),
    FOREIGN KEY (tenant_id, transaction_id, lease_id, fencing_token)
        REFERENCES enforced_worker_leases(
            tenant_id, transaction_id, lease_id, fencing_token
        )
);

CREATE TABLE enforced_commit_dispatches (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    dispatch_id TEXT NOT NULL,
    owner_version INTEGER NOT NULL CHECK (owner_version >= 0),
    stage_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    idempotency_key TEXT NOT NULL,
    permit_ref TEXT NOT NULL,
    permit_digest TEXT NOT NULL,
    permit_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN (
            'DISPATCHED', 'COMMITTED', 'NO_EFFECT', 'PARTIAL_OR_INVALID',
            'IN_DOUBT', 'REVIEW_REQUIRED'
        )
    ),
    effect_receipt_ref TEXT,
    committed_verification_permit_digest TEXT,
    committed_verification_permit_ref TEXT,
    committed_verification_ref TEXT,
    no_effect_evidence_ref TEXT,
    outcome_evidence_refs_json TEXT NOT NULL,
    outcome_head_sequence INTEGER NOT NULL CHECK (outcome_head_sequence >= 0),
    outcome_head_digest TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 0),
    record_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, dispatch_id),
    UNIQUE (tenant_id, transaction_id),
    UNIQUE (tenant_id, intent_hash, owner_version),
    UNIQUE (
        tenant_id, transaction_id, intent_hash, owner_version, dispatch_id
    ),
    UNIQUE (tenant_id, idempotency_key, owner_version),
    FOREIGN KEY (tenant_id, transaction_id)
        REFERENCES enforced_transactions(tenant_id, transaction_id),
    FOREIGN KEY (tenant_id, intent_hash, transaction_id)
        REFERENCES enforced_intent_attempts(
            tenant_id, intent_hash, transaction_id
        ),
    FOREIGN KEY (tenant_id, transaction_id, stage_id, lease_id, fencing_token)
        REFERENCES enforced_stage_material(
            tenant_id, transaction_id, stage_id, lease_id, fencing_token
        )
);

CREATE INDEX enforced_commit_dispatches_scan_idx
    ON enforced_commit_dispatches(tenant_id, state, updated_at, transaction_id);

CREATE TABLE enforced_dispatch_outcomes (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    owner_version INTEGER NOT NULL CHECK (owner_version >= 0),
    dispatch_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    outcome_id TEXT NOT NULL,
    source_state TEXT,
    target_state TEXT NOT NULL,
    classification TEXT CHECK (
        classification IS NULL OR classification IN (
            'COMMITTED', 'NO_EFFECT', 'PARTIAL_OR_INVALID', 'UNKNOWN'
        )
    ),
    effect_receipt_ref TEXT,
    committed_verification_permit_digest TEXT,
    committed_verification_permit_ref TEXT,
    committed_verification_ref TEXT,
    no_effect_evidence_ref TEXT,
    evidence_refs_json TEXT NOT NULL,
    reason_code TEXT,
    previous_outcome_digest TEXT,
    outcome_digest TEXT NOT NULL,
    outcome_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, dispatch_id, sequence),
    UNIQUE (tenant_id, outcome_id),
    UNIQUE (tenant_id, transaction_id, dispatch_id, outcome_digest),
    FOREIGN KEY (
        tenant_id, transaction_id, intent_hash, owner_version, dispatch_id
    ) REFERENCES enforced_commit_dispatches(
        tenant_id, transaction_id, intent_hash, owner_version, dispatch_id
    )
);

CREATE TABLE enforced_reconciliation_attempts (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    dispatch_id TEXT NOT NULL,
    recovery_id TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    lease_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    outcome TEXT CHECK (
        outcome IS NULL OR outcome IN (
            'COMMITTED', 'NO_EFFECT', 'PARTIAL_OR_INVALID', 'UNKNOWN'
        )
    ),
    effect_receipt_ref TEXT,
    committed_verification_permit_digest TEXT,
    committed_verification_permit_ref TEXT,
    committed_verification_ref TEXT,
    no_effect_evidence_ref TEXT,
    evidence_refs_json TEXT NOT NULL,
    completion_evidence_refs_json TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    next_attempt_not_before TEXT,
    version INTEGER NOT NULL CHECK (version >= 0),
    record_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    CHECK (
        (outcome IS NULL AND completion_evidence_refs_json IS NULL)
        OR (outcome IS NOT NULL AND completion_evidence_refs_json IS NOT NULL)
    ),
    PRIMARY KEY (tenant_id, transaction_id, dispatch_id, attempt),
    UNIQUE (tenant_id, recovery_id, attempt),
    FOREIGN KEY (tenant_id, transaction_id, dispatch_id)
        REFERENCES enforced_commit_dispatches(
            tenant_id, transaction_id, dispatch_id
        ),
    FOREIGN KEY (tenant_id, transaction_id, lease_id, fencing_token)
        REFERENCES enforced_worker_leases(
            tenant_id, transaction_id, lease_id, fencing_token
        )
);

CREATE UNIQUE INDEX enforced_reconciliation_one_started_uq
    ON enforced_reconciliation_attempts(tenant_id, transaction_id, dispatch_id)
    WHERE completed_at IS NULL;

CREATE TABLE enforced_recovery_work (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    recovery_id TEXT NOT NULL,
    root_recovery_id TEXT NOT NULL,
    predecessor_recovery_id TEXT,
    recovery_ordinal INTEGER NOT NULL CHECK (recovery_ordinal > 0),
    max_recovery_attempts INTEGER NOT NULL CHECK (max_recovery_attempts > 0),
    not_before TEXT NOT NULL,
    recovery_action_transaction_id TEXT NOT NULL,
    recovery_action_intent_hash TEXT NOT NULL,
    recovery_action_digest TEXT NOT NULL,
    adapter_manifest_digest TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (
        kind IN (
            'DISCARD_STAGING', 'RECONCILE_DISPATCH', 'ROLLBACK', 'COMPENSATE'
        )
    ),
    target_id TEXT NOT NULL,
    target_owner_version INTEGER NOT NULL CHECK (target_owner_version >= 0),
    target_owner_history_sequence INTEGER NOT NULL
        CHECK (target_owner_history_sequence >= 0),
    target_owner_history_digest TEXT NOT NULL,
    target_evidence_ref TEXT NOT NULL,
    target_version_guard TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN (
            'PENDING', 'RUNNING', 'RETRY_SCHEDULED', 'RETRIED',
            'SUCCEEDED', 'FAILED', 'REVIEW_REQUIRED'
        )
    ),
    authorization_round_id TEXT NOT NULL,
    authorization_round_digest TEXT NOT NULL,
    authority_decision_digest TEXT NOT NULL,
    policy_decision_digest TEXT NOT NULL,
    policy_snapshot_digest TEXT NOT NULL,
    capability_reservation_digest TEXT,
    reservation_version INTEGER CHECK (reservation_version >= 0),
    owner_version INTEGER NOT NULL CHECK (owner_version >= 0),
    owner_history_sequence INTEGER NOT NULL CHECK (owner_history_sequence >= 0),
    owner_history_digest TEXT NOT NULL,
    approval_required INTEGER NOT NULL CHECK (approval_required IN (0, 1)),
    approval_id TEXT,
    approval_evidence_ref TEXT NOT NULL,
    permit_ref TEXT,
    permit_digest TEXT,
    permit_json TEXT,
    lease_id TEXT,
    worker_id TEXT,
    fencing_token INTEGER CHECK (fencing_token > 0),
    deadline TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt >= 0),
    version INTEGER NOT NULL CHECK (version >= 0),
    evidence_refs_json TEXT NOT NULL,
    reason_code TEXT,
    record_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, recovery_id),
    UNIQUE (tenant_id, recovery_id),
    UNIQUE (
        tenant_id, transaction_id, root_recovery_id, recovery_ordinal
    ),
    FOREIGN KEY (tenant_id, transaction_id)
        REFERENCES enforced_transactions(tenant_id, transaction_id),
    FOREIGN KEY (tenant_id, transaction_id, predecessor_recovery_id)
        REFERENCES enforced_recovery_work(
            tenant_id, transaction_id, recovery_id
        ),
    FOREIGN KEY (
        tenant_id, recovery_action_transaction_id, recovery_action_intent_hash,
        recovery_action_digest
    ) REFERENCES enforced_normalized_actions(
        tenant_id, transaction_id, intent_hash, action_digest
    ),
    FOREIGN KEY (tenant_id, transaction_id, authorization_round_id)
        REFERENCES enforced_authorization_rounds(
            tenant_id, controlled_transaction_id, round_id
        ),
    FOREIGN KEY (tenant_id, transaction_id, lease_id, fencing_token)
        REFERENCES enforced_worker_leases(
            tenant_id, transaction_id, lease_id, fencing_token
        ),
    CHECK (
        (capability_reservation_digest IS NULL AND reservation_version IS NULL)
        OR (capability_reservation_digest IS NOT NULL AND reservation_version IS NOT NULL)
    ),
    CHECK (
        (permit_ref IS NULL AND permit_digest IS NULL AND permit_json IS NULL
            AND lease_id IS NULL AND worker_id IS NULL AND fencing_token IS NULL)
        OR (permit_ref IS NOT NULL AND permit_digest IS NOT NULL
            AND permit_json IS NOT NULL AND lease_id IS NOT NULL
            AND worker_id IS NOT NULL AND fencing_token IS NOT NULL)
    ),
    CHECK (
        state != 'PENDING'
        OR (reservation_version IS NOT NULL AND reservation_version % 2 = 0
            AND permit_ref IS NULL)
    ),
    CHECK (
        state != 'RUNNING'
        OR (reservation_version IS NOT NULL AND reservation_version % 2 = 1
            AND permit_ref IS NOT NULL)
    ),
    CHECK (recovery_ordinal <= max_recovery_attempts),
    CHECK (
        (recovery_ordinal = 1 AND root_recovery_id = recovery_id
            AND predecessor_recovery_id IS NULL)
        OR (recovery_ordinal > 1 AND root_recovery_id != recovery_id
            AND predecessor_recovery_id IS NOT NULL
            AND predecessor_recovery_id != recovery_id)
    )
);

CREATE INDEX enforced_recovery_work_scan_idx
    ON enforced_recovery_work(
        tenant_id, state, deadline, updated_at, transaction_id, recovery_id
    );

CREATE TRIGGER enforced_transactions_no_delete
BEFORE DELETE ON enforced_transactions
BEGIN
    SELECT RAISE(ABORT, 'enforced transactions are append-preserving');
END;

CREATE TRIGGER enforced_transactions_binding_immutable
BEFORE UPDATE ON enforced_transactions
WHEN NEW.tenant_id != OLD.tenant_id
    OR NEW.transaction_id != OLD.transaction_id
    OR NEW.principal_id != OLD.principal_id
    OR NEW.goal_id != OLD.goal_id
    OR NEW.run_id != OLD.run_id
    OR NEW.trace_id != OLD.trace_id
    OR NEW.actor_id != OLD.actor_id
    OR NEW.on_behalf_of != OLD.on_behalf_of
    OR NEW.agent_id != OLD.agent_id
    OR NEW.request_digest != OLD.request_digest
    OR NEW.created_at != OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'enforced transaction identity is immutable');
END;

CREATE TRIGGER enforced_transaction_events_no_update
BEFORE UPDATE ON enforced_transaction_events
BEGIN
    SELECT RAISE(ABORT, 'enforced transaction events are immutable');
END;

CREATE TRIGGER enforced_transaction_events_no_delete
BEFORE DELETE ON enforced_transaction_events
BEGIN
    SELECT RAISE(ABORT, 'enforced transaction events are immutable');
END;

CREATE TRIGGER enforced_authorization_rounds_no_update
BEFORE UPDATE ON enforced_authorization_rounds
BEGIN
    SELECT RAISE(ABORT, 'enforced authorization rounds are immutable');
END;

CREATE TRIGGER enforced_authorization_rounds_no_delete
BEFORE DELETE ON enforced_authorization_rounds
BEGIN
    SELECT RAISE(ABORT, 'enforced authorization rounds are immutable');
END;

CREATE TRIGGER enforced_worker_leases_no_delete
BEFORE DELETE ON enforced_worker_leases
BEGIN
    SELECT RAISE(ABORT, 'enforced worker leases are append-preserving');
END;

CREATE TRIGGER enforced_worker_leases_binding_immutable
BEFORE UPDATE ON enforced_worker_leases
WHEN NEW.tenant_id != OLD.tenant_id
    OR NEW.transaction_id != OLD.transaction_id
    OR NEW.lease_id != OLD.lease_id
    OR NEW.worker_id != OLD.worker_id
    OR NEW.purpose != OLD.purpose
    OR NEW.fencing_token != OLD.fencing_token
    OR NEW.acquired_at != OLD.acquired_at
BEGIN
    SELECT RAISE(ABORT, 'enforced worker lease identity is immutable');
END;

CREATE TRIGGER enforced_stage_material_no_delete
BEFORE DELETE ON enforced_stage_material
BEGIN
    SELECT RAISE(ABORT, 'enforced stage material is append-preserving');
END;

CREATE TRIGGER enforced_stage_material_binding_immutable
BEFORE UPDATE ON enforced_stage_material
WHEN NEW.tenant_id != OLD.tenant_id
    OR NEW.transaction_id != OLD.transaction_id
    OR NEW.stage_id != OLD.stage_id
    OR NEW.lease_id != OLD.lease_id
    OR NEW.fencing_token != OLD.fencing_token
    OR NEW.intent_hash != OLD.intent_hash
    OR NEW.normalized_action_digest != OLD.normalized_action_digest
    OR NEW.adapter_manifest_digest != OLD.adapter_manifest_digest
    OR NEW.plan_digest != OLD.plan_digest
    OR NEW.plan_ref != OLD.plan_ref
    OR NEW.inspection_permit_digest != OLD.inspection_permit_digest
    OR NEW.inspection_permit_ref != OLD.inspection_permit_ref
    OR NEW.stage_permit_digest != OLD.stage_permit_digest
    OR NEW.stage_permit_ref != OLD.stage_permit_ref
    OR NEW.target_version_guard != OLD.target_version_guard
    OR NEW.created_at != OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'enforced stage material binding is immutable');
END;

CREATE TRIGGER enforced_commit_dispatches_no_delete
BEFORE DELETE ON enforced_commit_dispatches
BEGIN
    SELECT RAISE(ABORT, 'enforced commit dispatches are append-preserving');
END;

CREATE TRIGGER enforced_commit_dispatches_binding_immutable
BEFORE UPDATE ON enforced_commit_dispatches
WHEN NEW.tenant_id != OLD.tenant_id
    OR NEW.transaction_id != OLD.transaction_id
    OR NEW.intent_hash != OLD.intent_hash
    OR NEW.dispatch_id != OLD.dispatch_id
    OR NEW.owner_version != OLD.owner_version
    OR NEW.stage_id != OLD.stage_id
    OR NEW.lease_id != OLD.lease_id
    OR NEW.fencing_token != OLD.fencing_token
    OR NEW.idempotency_key != OLD.idempotency_key
    OR NEW.permit_ref != OLD.permit_ref
    OR NEW.permit_digest != OLD.permit_digest
    OR NEW.permit_json != OLD.permit_json
    OR NEW.created_at != OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'enforced commit dispatch identity is immutable');
END;

CREATE TRIGGER enforced_dispatch_outcomes_no_update
BEFORE UPDATE ON enforced_dispatch_outcomes
BEGIN
    SELECT RAISE(ABORT, 'enforced dispatch outcomes are immutable');
END;

CREATE TRIGGER enforced_dispatch_outcomes_no_delete
BEFORE DELETE ON enforced_dispatch_outcomes
BEGIN
    SELECT RAISE(ABORT, 'enforced dispatch outcomes are immutable');
END;

CREATE TRIGGER enforced_reconciliation_attempts_no_delete
BEFORE DELETE ON enforced_reconciliation_attempts
BEGIN
    SELECT RAISE(ABORT, 'enforced reconciliation attempts are append-preserving');
END;

CREATE TRIGGER enforced_reconciliation_binding_immutable
BEFORE UPDATE ON enforced_reconciliation_attempts
WHEN NEW.tenant_id != OLD.tenant_id
    OR NEW.transaction_id != OLD.transaction_id
    OR NEW.intent_hash != OLD.intent_hash
    OR NEW.dispatch_id != OLD.dispatch_id
    OR NEW.recovery_id != OLD.recovery_id
    OR NEW.attempt != OLD.attempt
    OR NEW.lease_id != OLD.lease_id
    OR NEW.fencing_token != OLD.fencing_token
    OR NEW.started_at != OLD.started_at
BEGIN
    SELECT RAISE(ABORT, 'enforced reconciliation attempt identity is immutable');
END;

CREATE TRIGGER enforced_recovery_work_no_delete
BEFORE DELETE ON enforced_recovery_work
BEGIN
    SELECT RAISE(ABORT, 'enforced recovery work is append-preserving');
END;

CREATE TRIGGER enforced_recovery_work_binding_immutable
BEFORE UPDATE ON enforced_recovery_work
WHEN NEW.tenant_id != OLD.tenant_id
    OR NEW.transaction_id != OLD.transaction_id
    OR NEW.intent_hash != OLD.intent_hash
    OR NEW.recovery_id != OLD.recovery_id
    OR NEW.root_recovery_id != OLD.root_recovery_id
    OR NEW.predecessor_recovery_id IS NOT OLD.predecessor_recovery_id
    OR NEW.recovery_ordinal != OLD.recovery_ordinal
    OR NEW.max_recovery_attempts != OLD.max_recovery_attempts
    OR NEW.not_before != OLD.not_before
    OR NEW.recovery_action_transaction_id != OLD.recovery_action_transaction_id
    OR NEW.recovery_action_intent_hash != OLD.recovery_action_intent_hash
    OR NEW.recovery_action_digest != OLD.recovery_action_digest
    OR NEW.adapter_manifest_digest != OLD.adapter_manifest_digest
    OR NEW.kind != OLD.kind
    OR NEW.target_id != OLD.target_id
    OR NEW.target_owner_version != OLD.target_owner_version
    OR NEW.target_owner_history_sequence != OLD.target_owner_history_sequence
    OR NEW.target_owner_history_digest != OLD.target_owner_history_digest
    OR NEW.target_evidence_ref != OLD.target_evidence_ref
    OR NEW.target_version_guard != OLD.target_version_guard
    OR NEW.authorization_round_id != OLD.authorization_round_id
    OR NEW.authorization_round_digest != OLD.authorization_round_digest
    OR NEW.authority_decision_digest != OLD.authority_decision_digest
    OR NEW.policy_decision_digest != OLD.policy_decision_digest
    OR NEW.policy_snapshot_digest != OLD.policy_snapshot_digest
    OR NEW.owner_version != OLD.owner_version
    OR NEW.owner_history_sequence != OLD.owner_history_sequence
    OR NEW.owner_history_digest != OLD.owner_history_digest
    OR NEW.approval_required != OLD.approval_required
    OR NEW.approval_id IS NOT OLD.approval_id
    OR NEW.approval_evidence_ref != OLD.approval_evidence_ref
    OR NEW.deadline != OLD.deadline
    OR NEW.created_at != OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'enforced recovery work binding is immutable');
END;

CREATE TRIGGER enforced_stage_verification_permit_insert
BEFORE INSERT ON enforced_stage_material
WHEN (NEW.verification_ref IS NULL) != (NEW.verification_permit_ref IS NULL)
    OR (NEW.verification_permit_ref IS NULL)
        != (NEW.verification_permit_digest IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'stage verification evidence requires its permit artifact');
END;

CREATE TRIGGER enforced_stage_verification_permit_update
BEFORE UPDATE ON enforced_stage_material
WHEN (NEW.verification_ref IS NULL) != (NEW.verification_permit_ref IS NULL)
    OR (NEW.verification_permit_ref IS NULL)
        != (NEW.verification_permit_digest IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'stage verification evidence requires its permit artifact');
END;

CREATE TRIGGER enforced_dispatch_verification_permit_insert
BEFORE INSERT ON enforced_commit_dispatches
WHEN (NEW.committed_verification_ref IS NULL)
    != (NEW.committed_verification_permit_ref IS NULL)
    OR (NEW.committed_verification_permit_ref IS NULL)
        != (NEW.committed_verification_permit_digest IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'committed verification evidence requires its permit artifact');
END;

CREATE TRIGGER enforced_dispatch_verification_permit_update
BEFORE UPDATE ON enforced_commit_dispatches
WHEN (NEW.committed_verification_ref IS NULL)
    != (NEW.committed_verification_permit_ref IS NULL)
    OR (NEW.committed_verification_permit_ref IS NULL)
        != (NEW.committed_verification_permit_digest IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'committed verification evidence requires its permit artifact');
END;

CREATE TRIGGER enforced_outcome_verification_permit_insert
BEFORE INSERT ON enforced_dispatch_outcomes
WHEN (NEW.committed_verification_ref IS NULL)
    != (NEW.committed_verification_permit_ref IS NULL)
    OR (NEW.committed_verification_permit_ref IS NULL)
        != (NEW.committed_verification_permit_digest IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'dispatch outcome verification requires its permit artifact');
END;

CREATE TRIGGER enforced_outcome_verification_permit_update
BEFORE UPDATE ON enforced_dispatch_outcomes
WHEN (NEW.committed_verification_ref IS NULL)
    != (NEW.committed_verification_permit_ref IS NULL)
    OR (NEW.committed_verification_permit_ref IS NULL)
        != (NEW.committed_verification_permit_digest IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'dispatch outcome verification requires its permit artifact');
END;

CREATE TRIGGER enforced_reconciliation_verification_permit_insert
BEFORE INSERT ON enforced_reconciliation_attempts
WHEN (NEW.committed_verification_ref IS NULL)
    != (NEW.committed_verification_permit_ref IS NULL)
    OR (NEW.committed_verification_permit_ref IS NULL)
        != (NEW.committed_verification_permit_digest IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'reconciliation verification requires its permit artifact');
END;

CREATE TRIGGER enforced_reconciliation_verification_permit_update
BEFORE UPDATE ON enforced_reconciliation_attempts
WHEN (NEW.committed_verification_ref IS NULL)
    != (NEW.committed_verification_permit_ref IS NULL)
    OR (NEW.committed_verification_permit_ref IS NULL)
        != (NEW.committed_verification_permit_digest IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'reconciliation verification requires its permit artifact');
END;
"""

MIGRATIONS = (*MIGRATIONS, (4, _ENFORCED_TRANSACTION_SCHEMA))

_ENFORCED_AUTHORITY_AND_RECOVERY_V5_SCHEMA = """
ALTER TABLE enforced_authorization_rounds
    ADD COLUMN authority_snapshot_ref TEXT;
ALTER TABLE enforced_authorization_rounds
    ADD COLUMN authority_context_ref TEXT;
ALTER TABLE enforced_authorization_rounds
    ADD COLUMN authority_decision_ref TEXT;
ALTER TABLE enforced_authorization_rounds
    ADD COLUMN policy_inputs_ref TEXT;
ALTER TABLE enforced_authorization_rounds
    ADD COLUMN policy_snapshot_ref TEXT;
ALTER TABLE enforced_authorization_rounds
    ADD COLUMN policy_decision_ref TEXT;
ALTER TABLE enforced_authorization_rounds
    ADD COLUMN authority_valid_until TEXT;

ALTER TABLE enforced_intent_owners
    ADD COLUMN effective_idempotency_key TEXT;
UPDATE enforced_intent_owners
SET effective_idempotency_key = COALESCE(
    NULLIF((
        SELECT json_extract(action.action_json, '$.idempotency_key')
        FROM enforced_normalized_actions AS action
        WHERE action.tenant_id = enforced_intent_owners.tenant_id
          AND action.transaction_id = enforced_intent_owners.owner_transaction_id
          AND action.intent_hash = enforced_intent_owners.intent_hash
    ), ''),
    intent_hash
);

DROP TRIGGER enforced_intent_history_no_update;
ALTER TABLE enforced_intent_attempt_history
    ADD COLUMN effective_idempotency_key TEXT;
UPDATE enforced_intent_attempt_history
SET effective_idempotency_key = COALESCE(
    NULLIF((
        SELECT json_extract(action.action_json, '$.idempotency_key')
        FROM enforced_normalized_actions AS action
        WHERE action.tenant_id = enforced_intent_attempt_history.tenant_id
          AND action.transaction_id = enforced_intent_attempt_history.transaction_id
          AND action.intent_hash = enforced_intent_attempt_history.intent_hash
    ), ''),
    intent_hash
);
CREATE TRIGGER enforced_intent_history_no_update
BEFORE UPDATE ON enforced_intent_attempt_history
BEGIN
    SELECT RAISE(ABORT, 'enforced intent history is immutable');
END;

DROP TRIGGER enforced_decision_snapshots_no_update;
ALTER TABLE enforced_decision_snapshots
    ADD COLUMN decision_row_digest TEXT;
CREATE TRIGGER enforced_decision_snapshots_no_update
BEFORE UPDATE ON enforced_decision_snapshots
WHEN NOT (
    OLD.decision_row_digest IS NULL
    AND NEW.decision_row_digest IS NOT NULL
    AND NEW.tenant_id = OLD.tenant_id
    AND NEW.decision_kind = OLD.decision_kind
    AND NEW.decision_id = OLD.decision_id
    AND NEW.transaction_id = OLD.transaction_id
    AND NEW.intent_hash = OLD.intent_hash
    AND NEW.decision_digest = OLD.decision_digest
    AND NEW.decision_json = OLD.decision_json
    AND NEW.recorded_at = OLD.recorded_at
)
BEGIN
    SELECT RAISE(ABORT, 'enforced decision snapshots are immutable');
END;

DROP TRIGGER enforced_reconciliation_attempts_no_delete;
DROP TRIGGER enforced_reconciliation_binding_immutable;
DROP TRIGGER enforced_reconciliation_verification_permit_insert;
DROP TRIGGER enforced_reconciliation_verification_permit_update;
DROP INDEX enforced_reconciliation_one_started_uq;

ALTER TABLE enforced_reconciliation_attempts
    RENAME TO enforced_reconciliation_attempts_v4;

CREATE TABLE enforced_reconciliation_attempts (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    dispatch_id TEXT NOT NULL,
    recovery_id TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    lease_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
    outcome TEXT CHECK (
        outcome IS NULL OR outcome IN (
            'COMMITTED', 'NO_EFFECT', 'PARTIAL_OR_INVALID', 'UNKNOWN'
        )
    ),
    effect_receipt_ref TEXT,
    committed_verification_permit_digest TEXT,
    committed_verification_permit_ref TEXT,
    committed_verification_ref TEXT,
    no_effect_evidence_ref TEXT,
    evidence_refs_json TEXT NOT NULL,
    completion_evidence_refs_json TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    next_attempt_not_before TEXT,
    version INTEGER NOT NULL CHECK (version >= 0),
    record_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    CHECK (
        (outcome IS NULL AND completion_evidence_refs_json IS NULL)
        OR (outcome IS NOT NULL AND completion_evidence_refs_json IS NOT NULL)
    ),
    PRIMARY KEY (tenant_id, transaction_id, recovery_id, attempt),
    UNIQUE (tenant_id, recovery_id, attempt),
    FOREIGN KEY (tenant_id, transaction_id, dispatch_id)
        REFERENCES enforced_commit_dispatches(
            tenant_id, transaction_id, dispatch_id
        ),
    FOREIGN KEY (tenant_id, transaction_id, lease_id, fencing_token)
        REFERENCES enforced_worker_leases(
            tenant_id, transaction_id, lease_id, fencing_token
        )
);

INSERT INTO enforced_reconciliation_attempts(
    tenant_id, transaction_id, intent_hash, dispatch_id, recovery_id,
    attempt, lease_id, fencing_token, outcome, effect_receipt_ref,
    committed_verification_permit_digest, committed_verification_permit_ref,
    committed_verification_ref, no_effect_evidence_ref, evidence_refs_json,
    completion_evidence_refs_json,
    started_at, completed_at, next_attempt_not_before, version,
    record_digest, record_json
)
SELECT
    tenant_id, transaction_id, intent_hash, dispatch_id, recovery_id,
    attempt, lease_id, fencing_token, outcome, effect_receipt_ref,
    committed_verification_permit_digest, committed_verification_permit_ref,
    committed_verification_ref, no_effect_evidence_ref, evidence_refs_json,
    completion_evidence_refs_json,
    started_at, completed_at, next_attempt_not_before, version,
    record_digest, record_json
FROM enforced_reconciliation_attempts_v4;

DROP TABLE enforced_reconciliation_attempts_v4;

CREATE UNIQUE INDEX enforced_reconciliation_one_started_uq
    ON enforced_reconciliation_attempts(tenant_id, transaction_id, dispatch_id)
    WHERE completed_at IS NULL;

CREATE TRIGGER enforced_reconciliation_attempts_no_delete
BEFORE DELETE ON enforced_reconciliation_attempts
BEGIN
    SELECT RAISE(ABORT, 'enforced reconciliation attempts are append-preserving');
END;

CREATE TRIGGER enforced_reconciliation_binding_immutable
BEFORE UPDATE ON enforced_reconciliation_attempts
WHEN NEW.tenant_id != OLD.tenant_id
    OR NEW.transaction_id != OLD.transaction_id
    OR NEW.intent_hash != OLD.intent_hash
    OR NEW.dispatch_id != OLD.dispatch_id
    OR NEW.recovery_id != OLD.recovery_id
    OR NEW.attempt != OLD.attempt
    OR NEW.lease_id != OLD.lease_id
    OR NEW.fencing_token != OLD.fencing_token
    OR NEW.started_at != OLD.started_at
BEGIN
    SELECT RAISE(ABORT, 'enforced reconciliation attempt identity is immutable');
END;

CREATE TRIGGER enforced_reconciliation_verification_permit_insert
BEFORE INSERT ON enforced_reconciliation_attempts
WHEN (NEW.committed_verification_ref IS NULL)
    != (NEW.committed_verification_permit_ref IS NULL)
    OR (NEW.committed_verification_permit_ref IS NULL)
        != (NEW.committed_verification_permit_digest IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'reconciliation verification requires its permit artifact');
END;

CREATE TRIGGER enforced_reconciliation_verification_permit_update
BEFORE UPDATE ON enforced_reconciliation_attempts
WHEN (NEW.committed_verification_ref IS NULL)
    != (NEW.committed_verification_permit_ref IS NULL)
    OR (NEW.committed_verification_permit_ref IS NULL)
        != (NEW.committed_verification_permit_digest IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'reconciliation verification requires its permit artifact');
END;

CREATE TABLE enforced_recovery_completion_reports (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    recovery_id TEXT NOT NULL,
    succeeded INTEGER NOT NULL CHECK (succeeded IN (0, 1)),
    operation_evidence_ref TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    reason_code TEXT,
    terminal_work_digest TEXT NOT NULL,
    report_digest TEXT NOT NULL,
    report_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, recovery_id),
    FOREIGN KEY (tenant_id, transaction_id, recovery_id)
        REFERENCES enforced_recovery_work(tenant_id, transaction_id, recovery_id)
);

CREATE TRIGGER enforced_recovery_completion_reports_no_update
BEFORE UPDATE ON enforced_recovery_completion_reports
BEGIN
    SELECT RAISE(ABORT, 'recovery completion reports are immutable');
END;

CREATE TRIGGER enforced_recovery_completion_reports_no_delete
BEFORE DELETE ON enforced_recovery_completion_reports
BEGIN
    SELECT RAISE(ABORT, 'recovery completion reports are append-only');
END;

CREATE TABLE enforced_late_recovery_reports (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    recovery_id TEXT NOT NULL,
    operation_evidence_ref TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    reported_at TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    terminal_work_digest TEXT NOT NULL,
    report_digest TEXT NOT NULL,
    report_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, recovery_id),
    FOREIGN KEY (tenant_id, transaction_id, recovery_id)
        REFERENCES enforced_recovery_work(tenant_id, transaction_id, recovery_id)
);

CREATE TRIGGER enforced_late_recovery_reports_no_update
BEFORE UPDATE ON enforced_late_recovery_reports
BEGIN
    SELECT RAISE(ABORT, 'late recovery reports are immutable');
END;

CREATE TRIGGER enforced_late_recovery_reports_no_delete
BEFORE DELETE ON enforced_late_recovery_reports
BEGIN
    SELECT RAISE(ABORT, 'late recovery reports are append-only');
END;
"""

MIGRATIONS = (*MIGRATIONS, (5, _ENFORCED_AUTHORITY_AND_RECOVERY_V5_SCHEMA))

_ENFORCED_RECOVERY_ACTION_HANDOFF_V6_SCHEMA = """
ALTER TABLE enforced_transactions ADD COLUMN recovery_deadline TEXT;
ALTER TABLE enforced_recovery_work ADD COLUMN unavailable_record_digest TEXT;
ALTER TABLE enforced_commit_dispatches ADD COLUMN unavailable_record_digest TEXT;
ALTER TABLE enforced_dispatch_outcomes ADD COLUMN unavailable_record_digest TEXT;

CREATE TRIGGER enforced_recovery_work_unavailable_record_lifecycle
BEFORE UPDATE OF unavailable_record_digest ON enforced_recovery_work
WHEN NEW.unavailable_record_digest IS NOT OLD.unavailable_record_digest
    AND NOT (
        OLD.unavailable_record_digest IS NULL
        AND NEW.unavailable_record_digest IS NOT NULL
        AND NEW.state = 'REVIEW_REQUIRED'
        AND NEW.reason_code LIKE 'EVIDENCE_UNAVAILABLE:%'
        AND NEW.version = OLD.version + 1
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid unavailable recovery record lifecycle');
END;

CREATE TRIGGER enforced_commit_dispatch_unavailable_record_lifecycle
BEFORE UPDATE OF unavailable_record_digest ON enforced_commit_dispatches
WHEN NEW.unavailable_record_digest IS NOT OLD.unavailable_record_digest
    AND NOT (
        OLD.unavailable_record_digest IS NULL
        AND NEW.unavailable_record_digest IS NOT NULL
        AND NEW.state = 'IN_DOUBT'
        AND NEW.version = OLD.version + 1
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid unavailable dispatch record lifecycle');
END;

CREATE TRIGGER enforced_transactions_recovery_deadline_immutable
BEFORE UPDATE OF recovery_deadline ON enforced_transactions
WHEN OLD.recovery_deadline IS NOT NULL
    AND NEW.recovery_deadline IS NOT OLD.recovery_deadline
BEGIN
    SELECT RAISE(ABORT, 'transaction recovery deadline is immutable');
END;

CREATE TABLE enforced_transaction_recovery_deadlines (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    transaction_version INTEGER NOT NULL CHECK (transaction_version > 0),
    absolute_deadline TEXT NOT NULL,
    deadline_ref TEXT NOT NULL,
    record_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id),
    UNIQUE (tenant_id, deadline_ref),
    FOREIGN KEY (tenant_id, transaction_id)
        REFERENCES enforced_transactions(tenant_id, transaction_id),
    FOREIGN KEY (tenant_id, transaction_id, transaction_version)
        REFERENCES enforced_transaction_events(tenant_id, transaction_id, sequence)
);

CREATE TRIGGER enforced_transaction_recovery_deadlines_no_update
BEFORE UPDATE ON enforced_transaction_recovery_deadlines
BEGIN
    SELECT RAISE(ABORT, 'transaction recovery deadlines are immutable');
END;

CREATE TRIGGER enforced_transaction_recovery_deadlines_no_delete
BEFORE DELETE ON enforced_transaction_recovery_deadlines
BEGIN
    SELECT RAISE(ABORT, 'transaction recovery deadlines are append-only');
END;

CREATE TABLE enforced_recovery_handoff_terminal_heads (
    tenant_id TEXT PRIMARY KEY,
    terminal_sequence INTEGER NOT NULL CHECK (terminal_sequence >= 1),
    updated_at TEXT NOT NULL
);

CREATE TRIGGER enforced_recovery_handoff_terminal_heads_valid_update
BEFORE UPDATE ON enforced_recovery_handoff_terminal_heads
WHEN NEW.tenant_id != OLD.tenant_id
    OR NEW.terminal_sequence != OLD.terminal_sequence + 1
BEGIN
    SELECT RAISE(ABORT, 'invalid recovery handoff terminal head update');
END;

CREATE TRIGGER enforced_recovery_handoff_terminal_heads_no_delete
BEFORE DELETE ON enforced_recovery_handoff_terminal_heads
BEGIN
    SELECT RAISE(ABORT, 'recovery handoff terminal heads are durable');
END;

CREATE TABLE enforced_recovery_action_handoffs (
    tenant_id TEXT NOT NULL,
    target_transaction_id TEXT NOT NULL,
    recovery_id TEXT NOT NULL,
    recovery_kind TEXT NOT NULL CHECK (
        recovery_kind IN (
            'DISCARD_STAGING', 'ROLLBACK', 'COMPENSATE', 'RECONCILE_DISPATCH'
        )
    ),
    target_id TEXT NOT NULL,
    target_evidence_ref TEXT NOT NULL,
    binding_ref TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    handoff_lease_id TEXT NOT NULL,
    handoff_worker_id TEXT NOT NULL,
    handoff_fencing_token INTEGER NOT NULL CHECK (handoff_fencing_token >= 1),
    recovery_action_transaction_id TEXT,
    recovery_action_intent_hash TEXT,
    recovery_action_digest TEXT,
    created_at TEXT NOT NULL,
    attached_at TEXT,
    closed_at TEXT,
    terminal_sequence INTEGER CHECK (
        terminal_sequence IS NULL OR terminal_sequence >= 1
    ),
    failure_evidence_status TEXT NOT NULL DEFAULT 'NONE' CHECK (
        failure_evidence_status IN ('NONE', 'AVAILABLE', 'UNAVAILABLE')
    ),
    failure_evidence_ref TEXT,
    failure_reason_code TEXT,
    PRIMARY KEY (tenant_id, target_transaction_id, recovery_id),
    UNIQUE (tenant_id, binding_ref),
    UNIQUE (tenant_id, recovery_action_transaction_id),
    UNIQUE (tenant_id, terminal_sequence),
    FOREIGN KEY (tenant_id, target_transaction_id)
        REFERENCES enforced_transactions(tenant_id, transaction_id),
    FOREIGN KEY (
        tenant_id, target_transaction_id,
        handoff_lease_id, handoff_fencing_token
    ) REFERENCES enforced_worker_leases(
        tenant_id, transaction_id, lease_id, fencing_token
    ),
    FOREIGN KEY (
        tenant_id, recovery_action_transaction_id,
        recovery_action_intent_hash, recovery_action_digest
    ) REFERENCES enforced_normalized_actions(
        tenant_id, transaction_id, intent_hash, action_digest
    ),
    CHECK (
        (recovery_action_transaction_id IS NULL
            AND recovery_action_intent_hash IS NULL
            AND recovery_action_digest IS NULL
            AND attached_at IS NULL)
        OR (recovery_action_transaction_id IS NOT NULL
            AND recovery_action_intent_hash IS NOT NULL
            AND recovery_action_digest IS NOT NULL
            AND attached_at IS NOT NULL)
    ),
    CHECK (
        (closed_at IS NULL
            AND terminal_sequence IS NULL
            AND failure_evidence_status = 'NONE'
            AND failure_evidence_ref IS NULL
            AND failure_reason_code IS NULL)
        OR (closed_at IS NOT NULL
            AND terminal_sequence IS NOT NULL
            AND failure_reason_code IS NOT NULL
            AND (
                (failure_evidence_status = 'AVAILABLE'
                    AND failure_evidence_ref IS NOT NULL)
                OR (failure_evidence_status = 'UNAVAILABLE'
                    AND failure_evidence_ref IS NULL)
            ))
    )
);

CREATE INDEX enforced_recovery_action_handoffs_target_idx
    ON enforced_recovery_action_handoffs(
        tenant_id, target_transaction_id, recovery_kind, target_id
    );

CREATE INDEX enforced_recovery_action_handoffs_evidence_audit_idx
    ON enforced_recovery_action_handoffs(
        tenant_id, terminal_sequence
    )
    WHERE terminal_sequence IS NOT NULL;

CREATE TRIGGER enforced_recovery_action_handoffs_valid_update
BEFORE UPDATE ON enforced_recovery_action_handoffs
WHEN NEW.tenant_id != OLD.tenant_id
    OR NEW.target_transaction_id != OLD.target_transaction_id
    OR NEW.recovery_id != OLD.recovery_id
    OR NEW.recovery_kind != OLD.recovery_kind
    OR NEW.target_id != OLD.target_id
    OR NEW.target_evidence_ref != OLD.target_evidence_ref
    OR NEW.binding_ref != OLD.binding_ref
    OR NEW.binding_json != OLD.binding_json
    OR NEW.created_at != OLD.created_at
    OR OLD.closed_at IS NOT NULL
    OR NOT (
        (
            OLD.recovery_action_transaction_id IS NULL
            AND OLD.attached_at IS NULL
            AND NEW.recovery_action_transaction_id IS NOT NULL
            AND NEW.recovery_action_intent_hash IS NOT NULL
            AND NEW.recovery_action_digest IS NOT NULL
            AND NEW.attached_at IS NOT NULL
            AND NEW.closed_at IS NULL
            AND NEW.terminal_sequence IS NULL
            AND NEW.failure_evidence_status = 'NONE'
            AND NEW.failure_evidence_ref IS NULL
            AND NEW.failure_reason_code IS NULL
        )
        OR (
            NEW.recovery_action_transaction_id IS OLD.recovery_action_transaction_id
            AND NEW.recovery_action_intent_hash IS OLD.recovery_action_intent_hash
            AND NEW.recovery_action_digest IS OLD.recovery_action_digest
            AND NEW.attached_at IS OLD.attached_at
            AND OLD.closed_at IS NULL
            AND NEW.closed_at IS NOT NULL
            AND OLD.terminal_sequence IS NULL
            AND NEW.terminal_sequence IS NOT NULL
            AND NEW.failure_reason_code IS NOT NULL
            AND (
                (NEW.failure_evidence_status = 'AVAILABLE'
                    AND NEW.failure_evidence_ref IS NOT NULL)
                OR (NEW.failure_evidence_status = 'UNAVAILABLE'
                    AND NEW.failure_evidence_ref IS NULL)
            )
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid recovery action handoff lifecycle update');
END;

CREATE TRIGGER enforced_recovery_action_handoffs_valid_lease_insert
BEFORE INSERT ON enforced_recovery_action_handoffs
WHEN NOT EXISTS (
    SELECT 1 FROM enforced_worker_leases AS lease
    WHERE lease.tenant_id = NEW.tenant_id
        AND lease.transaction_id = NEW.target_transaction_id
        AND lease.lease_id = NEW.handoff_lease_id
        AND lease.worker_id = NEW.handoff_worker_id
        AND lease.fencing_token = NEW.handoff_fencing_token
        AND lease.purpose = 'RECOVERY'
        AND lease.acquired_at = NEW.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'recovery handoff lease identity is invalid');
END;

CREATE TRIGGER enforced_recovery_action_handoffs_lease_no_update
BEFORE UPDATE OF handoff_lease_id, handoff_worker_id, handoff_fencing_token
ON enforced_recovery_action_handoffs
BEGIN
    SELECT RAISE(ABORT, 'recovery handoff lease identity is immutable');
END;

CREATE TRIGGER enforced_recovery_action_handoffs_no_delete
BEFORE DELETE ON enforced_recovery_action_handoffs
BEGIN
    SELECT RAISE(ABORT, 'recovery action handoffs are append-only');
END;

CREATE TABLE enforced_dispatch_evidence_unavailable_reports (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    dispatch_id TEXT NOT NULL,
    boundary TEXT NOT NULL CHECK (
        boundary IN ('POST_DISPATCH_CLASSIFICATION', 'RECOVERY_SCANNER_CLASSIFICATION')
    ),
    evidence_status TEXT NOT NULL CHECK (evidence_status = 'UNAVAILABLE'),
    operation_evidence_ref TEXT CHECK (operation_evidence_ref IS NULL),
    supporting_refs_json TEXT NOT NULL,
    reported_at TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, dispatch_id),
    UNIQUE (tenant_id, record_digest),
    FOREIGN KEY (tenant_id, transaction_id, dispatch_id)
        REFERENCES enforced_commit_dispatches(tenant_id, transaction_id, dispatch_id)
);

CREATE TRIGGER enforced_dispatch_evidence_unavailable_reports_valid_insert
BEFORE INSERT ON enforced_dispatch_evidence_unavailable_reports
WHEN NOT EXISTS (
    SELECT 1 FROM enforced_commit_dispatches AS dispatch
    JOIN enforced_dispatch_outcomes AS outcome
        ON outcome.tenant_id = dispatch.tenant_id
        AND outcome.transaction_id = dispatch.transaction_id
        AND outcome.dispatch_id = dispatch.dispatch_id
        AND outcome.sequence = dispatch.version
    JOIN enforced_worker_leases AS lease
        ON lease.tenant_id = dispatch.tenant_id
        AND lease.transaction_id = dispatch.transaction_id
        AND lease.lease_id = dispatch.lease_id
    WHERE dispatch.tenant_id = NEW.tenant_id
        AND dispatch.transaction_id = NEW.transaction_id
        AND dispatch.dispatch_id = NEW.dispatch_id
        AND dispatch.state = 'IN_DOUBT'
        AND dispatch.unavailable_record_digest = NEW.record_digest
        AND dispatch.updated_at = NEW.reported_at
        AND outcome.classification = 'UNKNOWN'
        AND outcome.unavailable_record_digest = NEW.record_digest
        AND outcome.recorded_at = NEW.reported_at
        AND lease.released_at = NEW.reported_at
)
BEGIN
    SELECT RAISE(ABORT, 'unavailable dispatch evidence lacks terminal association');
END;

CREATE TRIGGER enforced_dispatch_evidence_unavailable_reports_no_update
BEFORE UPDATE ON enforced_dispatch_evidence_unavailable_reports
BEGIN
    SELECT RAISE(ABORT, 'unavailable dispatch evidence is immutable');
END;

CREATE TRIGGER enforced_dispatch_evidence_unavailable_reports_no_delete
BEFORE DELETE ON enforced_dispatch_evidence_unavailable_reports
BEGIN
    SELECT RAISE(ABORT, 'unavailable dispatch evidence is append-only');
END;

CREATE TABLE enforced_dispatch_evidence_unavailable_bindings (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    dispatch_id TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    outcome_sequence INTEGER NOT NULL CHECK (outcome_sequence > 0),
    outcome_digest TEXT NOT NULL,
    event_sequence INTEGER NOT NULL CHECK (event_sequence > 0),
    event_digest TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, dispatch_id),
    FOREIGN KEY (tenant_id, transaction_id, dispatch_id)
        REFERENCES enforced_dispatch_evidence_unavailable_reports(
            tenant_id, transaction_id, dispatch_id
        ),
    FOREIGN KEY (tenant_id, transaction_id, dispatch_id, outcome_sequence)
        REFERENCES enforced_dispatch_outcomes(
            tenant_id, transaction_id, dispatch_id, sequence
        ),
    FOREIGN KEY (tenant_id, transaction_id, event_sequence)
        REFERENCES enforced_transaction_events(tenant_id, transaction_id, sequence)
);

CREATE TRIGGER enforced_dispatch_evidence_unavailable_bindings_valid_insert
BEFORE INSERT ON enforced_dispatch_evidence_unavailable_bindings
WHEN NOT EXISTS (
    SELECT 1 FROM enforced_dispatch_evidence_unavailable_reports
    WHERE tenant_id = NEW.tenant_id
        AND transaction_id = NEW.transaction_id
        AND dispatch_id = NEW.dispatch_id
        AND record_digest = NEW.record_digest
)
OR NOT EXISTS (
    SELECT 1 FROM enforced_dispatch_outcomes
    WHERE tenant_id = NEW.tenant_id
        AND transaction_id = NEW.transaction_id
        AND dispatch_id = NEW.dispatch_id
        AND sequence = NEW.outcome_sequence
        AND outcome_digest = NEW.outcome_digest
        AND unavailable_record_digest = NEW.record_digest
)
OR NOT EXISTS (
    SELECT 1 FROM enforced_transaction_events
    WHERE tenant_id = NEW.tenant_id
        AND transaction_id = NEW.transaction_id
        AND sequence = NEW.event_sequence
        AND event_digest = NEW.event_digest
)
BEGIN
    SELECT RAISE(ABORT, 'unavailable dispatch evidence binding is invalid');
END;

CREATE TRIGGER enforced_dispatch_evidence_unavailable_bindings_no_update
BEFORE UPDATE ON enforced_dispatch_evidence_unavailable_bindings
BEGIN
    SELECT RAISE(ABORT, 'unavailable dispatch evidence binding is immutable');
END;

CREATE TRIGGER enforced_dispatch_evidence_unavailable_bindings_no_delete
BEFORE DELETE ON enforced_dispatch_evidence_unavailable_bindings
BEGIN
    SELECT RAISE(ABORT, 'unavailable dispatch evidence binding is append-only');
END;

CREATE TABLE enforced_recovery_evidence_unavailable_reports (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    recovery_id TEXT NOT NULL,
    boundary TEXT NOT NULL,
    evidence_status TEXT NOT NULL CHECK (evidence_status = 'UNAVAILABLE'),
    operation_evidence_ref TEXT CHECK (operation_evidence_ref IS NULL),
    supporting_refs_json TEXT NOT NULL,
    reported_at TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, recovery_id),
    UNIQUE (tenant_id, record_digest),
    FOREIGN KEY (tenant_id, transaction_id, recovery_id)
        REFERENCES enforced_recovery_work(tenant_id, transaction_id, recovery_id)
);

CREATE TRIGGER enforced_recovery_evidence_unavailable_reports_valid_insert
BEFORE INSERT ON enforced_recovery_evidence_unavailable_reports
WHEN NOT EXISTS (
    SELECT 1 FROM enforced_recovery_work AS work
    JOIN enforced_worker_leases AS lease
        ON lease.tenant_id = work.tenant_id
        AND lease.transaction_id = work.transaction_id
        AND lease.lease_id = work.lease_id
    WHERE work.tenant_id = NEW.tenant_id
        AND work.transaction_id = NEW.transaction_id
        AND work.recovery_id = NEW.recovery_id
        AND work.state = 'REVIEW_REQUIRED'
        AND work.reason_code = NEW.reason_code
        AND work.updated_at = NEW.reported_at
        AND work.unavailable_record_digest = NEW.record_digest
        AND lease.released_at = NEW.reported_at
)
OR EXISTS (
    SELECT 1 FROM enforced_recovery_completion_reports
    WHERE tenant_id = NEW.tenant_id
        AND transaction_id = NEW.transaction_id
        AND recovery_id = NEW.recovery_id
)
OR EXISTS (
    SELECT 1 FROM enforced_late_recovery_reports
    WHERE tenant_id = NEW.tenant_id
        AND transaction_id = NEW.transaction_id
        AND recovery_id = NEW.recovery_id
)
BEGIN
    SELECT RAISE(ABORT, 'unavailable recovery evidence lacks terminal work settlement');
END;

CREATE TRIGGER enforced_recovery_evidence_unavailable_reports_no_update
BEFORE UPDATE ON enforced_recovery_evidence_unavailable_reports
BEGIN
    SELECT RAISE(ABORT, 'unavailable recovery evidence reports are immutable');
END;

CREATE TRIGGER enforced_recovery_evidence_unavailable_reports_no_delete
BEFORE DELETE ON enforced_recovery_evidence_unavailable_reports
BEGIN
    SELECT RAISE(ABORT, 'unavailable recovery evidence reports are append-only');
END;

CREATE TABLE enforced_recovery_evidence_unavailable_event_bindings (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    recovery_id TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    event_sequence INTEGER NOT NULL CHECK (event_sequence >= 0),
    event_digest TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id, recovery_id),
    UNIQUE (tenant_id, transaction_id, event_sequence),
    FOREIGN KEY (tenant_id, transaction_id, recovery_id)
        REFERENCES enforced_recovery_evidence_unavailable_reports(
            tenant_id, transaction_id, recovery_id
        ),
    FOREIGN KEY (tenant_id, transaction_id, event_sequence)
        REFERENCES enforced_transaction_events(tenant_id, transaction_id, sequence)
);

CREATE TRIGGER enforced_recovery_evidence_unavailable_event_bindings_valid_insert
BEFORE INSERT ON enforced_recovery_evidence_unavailable_event_bindings
WHEN NOT EXISTS (
    SELECT 1 FROM enforced_recovery_evidence_unavailable_reports
    WHERE tenant_id = NEW.tenant_id
        AND transaction_id = NEW.transaction_id
        AND recovery_id = NEW.recovery_id
        AND record_digest = NEW.record_digest
)
OR NOT EXISTS (
    SELECT 1 FROM enforced_transaction_events
    WHERE tenant_id = NEW.tenant_id
        AND transaction_id = NEW.transaction_id
        AND sequence = NEW.event_sequence
        AND event_digest = NEW.event_digest
)
BEGIN
    SELECT RAISE(ABORT, 'unavailable recovery event binding differs from durable records');
END;

CREATE TRIGGER enforced_recovery_evidence_unavailable_event_bindings_no_update
BEFORE UPDATE ON enforced_recovery_evidence_unavailable_event_bindings
BEGIN
    SELECT RAISE(ABORT, 'unavailable recovery event bindings are immutable');
END;

CREATE TRIGGER enforced_recovery_evidence_unavailable_event_bindings_no_delete
BEFORE DELETE ON enforced_recovery_evidence_unavailable_event_bindings
BEGIN
    SELECT RAISE(ABORT, 'unavailable recovery event bindings are append-only');
END;

CREATE TABLE enforced_recovery_handoff_evidence_audits (
    tenant_id TEXT PRIMARY KEY,
    current_cycle INTEGER NOT NULL CHECK (current_cycle >= 1),
    current_cycle_high_watermark INTEGER NOT NULL CHECK (
        current_cycle_high_watermark >= 0
    ),
    cursor_terminal_sequence INTEGER NOT NULL CHECK (
        cursor_terminal_sequence >= 0
    ),
    current_cycle_failure_count INTEGER NOT NULL CHECK (
        current_cycle_failure_count >= 0
    ),
    last_completed_cycle INTEGER,
    last_completed_at TEXT,
    last_completed_high_watermark INTEGER CHECK (
        last_completed_high_watermark IS NULL
        OR last_completed_high_watermark >= 0
    ),
    last_completed_failure_count INTEGER CHECK (
        last_completed_failure_count IS NULL OR last_completed_failure_count >= 0
    ),
    version INTEGER NOT NULL CHECK (version >= 0),
    event_head_sequence INTEGER NOT NULL CHECK (event_head_sequence >= 0),
    event_head_digest TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        cursor_terminal_sequence <= current_cycle_high_watermark
    ),
    CHECK (
        (last_completed_cycle IS NULL
            AND last_completed_at IS NULL
            AND last_completed_high_watermark IS NULL
            AND last_completed_failure_count IS NULL)
        OR (last_completed_cycle IS NOT NULL
            AND last_completed_at IS NOT NULL
            AND last_completed_high_watermark IS NOT NULL
            AND last_completed_failure_count IS NOT NULL
            AND last_completed_cycle <= current_cycle)
    ),
    CHECK (
        (cursor_terminal_sequence = current_cycle_high_watermark
            AND last_completed_cycle = current_cycle
            AND last_completed_high_watermark = current_cycle_high_watermark
            AND last_completed_failure_count = current_cycle_failure_count)
        OR (cursor_terminal_sequence < current_cycle_high_watermark
            AND (last_completed_cycle IS NULL OR last_completed_cycle < current_cycle))
    )
);

CREATE TRIGGER enforced_recovery_handoff_evidence_audits_valid_update
BEFORE UPDATE ON enforced_recovery_handoff_evidence_audits
WHEN NEW.tenant_id != OLD.tenant_id
    OR NEW.version != OLD.version + 1
    OR NEW.event_head_sequence != OLD.event_head_sequence + 1
    OR NEW.event_head_sequence != NEW.version
    OR NEW.current_cycle < OLD.current_cycle
    OR NEW.current_cycle > OLD.current_cycle + 1
    OR NOT (
        (NEW.current_cycle = OLD.current_cycle
            AND NEW.current_cycle_high_watermark = OLD.current_cycle_high_watermark
            AND NEW.cursor_terminal_sequence > OLD.cursor_terminal_sequence
            AND NEW.current_cycle_failure_count >= OLD.current_cycle_failure_count)
        OR (NEW.current_cycle = OLD.current_cycle + 1
            AND OLD.cursor_terminal_sequence = OLD.current_cycle_high_watermark
            AND NEW.current_cycle_high_watermark >= OLD.current_cycle_high_watermark
            AND NEW.cursor_terminal_sequence = 0
            AND NEW.current_cycle_failure_count = 0)
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid recovery handoff evidence audit update');
END;

CREATE TRIGGER enforced_recovery_handoff_evidence_audits_no_delete
BEFORE DELETE ON enforced_recovery_handoff_evidence_audits
BEGIN
    SELECT RAISE(ABORT, 'recovery handoff evidence audit checkpoints are durable');
END;

CREATE TABLE enforced_recovery_handoff_evidence_audit_events (
    tenant_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    checkpoint_digest TEXT NOT NULL,
    checkpoint_json TEXT NOT NULL,
    previous_event_digest TEXT,
    event_digest TEXT NOT NULL,
    event_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, sequence)
);

CREATE TRIGGER enforced_recovery_handoff_evidence_audit_events_valid_insert
BEFORE INSERT ON enforced_recovery_handoff_evidence_audit_events
WHEN NOT EXISTS (
    SELECT 1 FROM enforced_recovery_handoff_evidence_audits
    WHERE tenant_id = NEW.tenant_id
        AND event_head_sequence = NEW.sequence
        AND event_head_digest = NEW.event_digest
        AND record_digest = NEW.checkpoint_digest
        AND record_json = NEW.checkpoint_json
)
BEGIN
    SELECT RAISE(ABORT, 'recovery handoff evidence audit event differs from its head');
END;

CREATE TRIGGER enforced_recovery_handoff_evidence_audit_events_no_update
BEFORE UPDATE ON enforced_recovery_handoff_evidence_audit_events
BEGIN
    SELECT RAISE(ABORT, 'recovery handoff evidence audit events are immutable');
END;

CREATE TRIGGER enforced_recovery_handoff_evidence_audit_events_no_delete
BEFORE DELETE ON enforced_recovery_handoff_evidence_audit_events
BEGIN
    SELECT RAISE(ABORT, 'recovery handoff evidence audit events are append-only');
END;
"""

MIGRATIONS = (*MIGRATIONS, (6, _ENFORCED_RECOVERY_ACTION_HANDOFF_V6_SCHEMA))

_ENFORCED_PENDING_RECOVERY_EVIDENCE_V7_SCHEMA = r"""
ALTER TABLE enforced_reconciliation_attempts
ADD COLUMN operation_evidence_ref TEXT;

ALTER TABLE enforced_reconciliation_attempts
ADD COLUMN operation_reason_code TEXT;

ALTER TABLE enforced_late_recovery_reports
ADD COLUMN operation_reason_code TEXT;

CREATE TRIGGER enforced_reconciliation_operation_evidence_valid_insert
BEFORE INSERT ON enforced_reconciliation_attempts
WHEN json_extract(NEW.record_json, '$.schema_version') != '1.1'
    OR json_extract(NEW.record_json, '$.operation_evidence_ref')
        IS NOT NEW.operation_evidence_ref
    OR json_extract(NEW.record_json, '$.operation_reason_code')
        IS NOT NEW.operation_reason_code
BEGIN
    SELECT RAISE(ABORT, 'reconciliation operation evidence differs from its record');
END;

CREATE TRIGGER enforced_reconciliation_operation_evidence_valid_update
BEFORE UPDATE ON enforced_reconciliation_attempts
WHEN json_extract(NEW.record_json, '$.schema_version') != '1.1'
    OR json_extract(NEW.record_json, '$.operation_evidence_ref')
        IS NOT NEW.operation_evidence_ref
    OR json_extract(NEW.record_json, '$.operation_reason_code')
        IS NOT NEW.operation_reason_code
BEGIN
    SELECT RAISE(ABORT, 'reconciliation operation evidence differs from its record');
END;

CREATE TRIGGER enforced_late_recovery_reports_operation_reason_valid_insert
BEFORE INSERT ON enforced_late_recovery_reports
WHEN json_extract(NEW.report_json, '$.schema_version') != '1.1'
    OR json_extract(NEW.report_json, '$.operation_reason_code')
        IS NOT NEW.operation_reason_code
    OR (NEW.operation_reason_code IS NOT NULL AND trim(NEW.operation_reason_code) = '')
BEGIN
    SELECT RAISE(ABORT, 'late recovery operation reason differs from its report');
END;

DROP TRIGGER enforced_recovery_evidence_unavailable_reports_valid_insert;

CREATE TRIGGER enforced_recovery_evidence_unavailable_reports_valid_insert
BEFORE INSERT ON enforced_recovery_evidence_unavailable_reports
WHEN NOT EXISTS (
    SELECT 1 FROM enforced_recovery_work AS work
    LEFT JOIN enforced_worker_leases AS lease
        ON lease.tenant_id = work.tenant_id
        AND lease.transaction_id = work.transaction_id
        AND lease.lease_id = work.lease_id
    WHERE work.tenant_id = NEW.tenant_id
        AND work.transaction_id = NEW.transaction_id
        AND work.recovery_id = NEW.recovery_id
        AND work.state = 'REVIEW_REQUIRED'
        AND work.reason_code = NEW.reason_code
        AND work.updated_at = NEW.reported_at
        AND work.unavailable_record_digest = NEW.record_digest
        AND (
            (
                work.lease_id IS NULL
                AND work.permit_ref IS NULL
                AND work.worker_id IS NULL
                AND work.fencing_token IS NULL
                AND work.attempt = 0
            )
            OR (
                work.lease_id IS NOT NULL
                AND (
                    (
                        NEW.boundary = 'RECOVERY_LEASE_RELEASED'
                        AND lease.released_at IS NOT NULL
                        AND lease.released_at <= NEW.reported_at
                    )
                    OR (
                        NEW.boundary != 'RECOVERY_LEASE_RELEASED'
                        AND lease.released_at = NEW.reported_at
                    )
                )
            )
        )
)
OR EXISTS (
    SELECT 1 FROM enforced_recovery_completion_reports
    WHERE tenant_id = NEW.tenant_id
        AND transaction_id = NEW.transaction_id
        AND recovery_id = NEW.recovery_id
)
OR EXISTS (
    SELECT 1 FROM enforced_late_recovery_reports
    WHERE tenant_id = NEW.tenant_id
        AND transaction_id = NEW.transaction_id
        AND recovery_id = NEW.recovery_id
)
BEGIN
    SELECT RAISE(ABORT, 'unavailable recovery evidence lacks terminal work settlement');
END;
"""

MIGRATIONS = (*MIGRATIONS, (7, _ENFORCED_PENDING_RECOVERY_EVIDENCE_V7_SCHEMA))

_SCHEMA_MIGRATIONS_BOOTSTRAP = (
    "CREATE TABLE IF NOT EXISTS schema_migrations "
    "(version INTEGER PRIMARY KEY, digest TEXT NOT NULL, applied_at TEXT NOT NULL)"
)
_MIGRATION_MARKER_SQL = (
    "INSERT INTO schema_migrations(version, digest, applied_at) "
    "VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"
)
_TRANSACTION_CONTROL_KEYWORDS = frozenset(
    {"BEGIN", "COMMIT", "END", "RELEASE", "ROLLBACK", "SAVEPOINT"}
)


@dataclass(frozen=True, slots=True)
class _PreparedMigration:
    version: int
    digest: str
    statements: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _SchemaObject:
    object_type: str
    name: str
    table_name: str
    create_sql: str | None
    columns: tuple[tuple[int, str, str, int, str | None, int, int], ...] = ()
    foreign_keys: tuple[tuple[int, int, str, str, str | None, str, str, str], ...] = ()
    table_flags: tuple[int, int, int] | None = None
    index_properties: tuple[int, str, int] | None = None
    index_columns: tuple[tuple[int, int, str | None, int, str, int], ...] = ()

    def fingerprint_material(self) -> dict[str, object]:
        return {
            "object_type": self.object_type,
            "name": self.name,
            "table_name": self.table_name,
            "create_sql": self.create_sql,
            "columns": self.columns,
            "foreign_keys": self.foreign_keys,
            "table_flags": self.table_flags,
            "index_properties": self.index_properties,
            "index_columns": self.index_columns,
        }


def _skip_sql_trivia(sql: str) -> tuple[int, bool]:
    """Return the first non-comment position and whether block comments are complete."""

    position = 0
    while position < len(sql):
        if sql[position].isspace():
            position += 1
            continue
        if sql.startswith("--", position):
            newline = sql.find("\n", position + 2)
            if newline == -1:
                return len(sql), True
            position = newline + 1
            continue
        if sql.startswith("/*", position):
            comment_end = sql.find("*/", position + 2)
            if comment_end == -1:
                return len(sql), False
            position = comment_end + 2
            continue
        break
    return position, True


def _leading_sql_keyword(statement: str) -> str | None:
    position, comments_complete = _skip_sql_trivia(statement)
    if not comments_complete:
        return None
    keyword_end = position
    while keyword_end < len(statement) and statement[keyword_end].isalpha():
        keyword_end += 1
    if keyword_end == position:
        return None
    return statement[position:keyword_end].upper()


def _split_migration_sql(version: int, sql: str) -> tuple[str, ...]:
    """Split one migration deterministically and reject unsafe or incomplete SQL."""

    statements: list[str] = []
    pending: list[str] = []
    for character in sql:
        pending.append(character)
        if character != ";":
            continue
        candidate = "".join(pending)
        if not sqlite3.complete_statement(candidate):
            continue
        keyword = _leading_sql_keyword(candidate)
        if keyword is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Migration contains an invalid SQL statement",
                details={"version": version, "statement": len(statements) + 1},
            )
        if keyword in _TRANSACTION_CONTROL_KEYWORDS:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Migration contains transaction-control SQL",
                details={"version": version, "statement": len(statements) + 1},
            )
        statements.append(candidate.strip())
        pending.clear()

    remainder = "".join(pending)
    remainder_position, comments_complete = _skip_sql_trivia(remainder)
    if not comments_complete or remainder_position != len(remainder):
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Migration SQL is incomplete",
            details={"version": version, "statement": len(statements) + 1},
        )
    if not statements:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Migration does not contain an SQL statement",
            details={"version": version},
        )
    return tuple(statements)


def _prepare_migrations() -> tuple[_PreparedMigration, ...]:
    prepared: list[_PreparedMigration] = []
    previous_version = 0
    for version, sql in MIGRATIONS:
        if version <= previous_version:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Migration versions must be positive and strictly increasing",
                details={"version": version},
            )
        prepared.append(
            _PreparedMigration(
                version=version,
                digest=canonical_digest({"version": version, "sql": sql}),
                statements=_split_migration_sql(version, sql),
            )
        )
        previous_version = version
    return tuple(prepared)


def _canonical_schema_sql(sql: object) -> str | None:
    """Normalize insignificant whitespace while preserving every SQL token and literal."""

    if sql is None:
        return None
    source = str(sql).strip()
    rendered: list[str] = []
    quote_end: str | None = None
    pending_space = False
    position = 0
    while position < len(source):
        character = source[position]
        if quote_end is not None:
            rendered.append(character)
            if character == quote_end:
                if (
                    quote_end != "]"
                    and position + 1 < len(source)
                    and source[position + 1] == quote_end
                ):
                    rendered.append(source[position + 1])
                    position += 2
                    continue
                quote_end = None
            position += 1
            continue
        if character.isspace():
            pending_space = True
            position += 1
            continue
        if pending_space and rendered and rendered[-1] not in "(," and character not in "),;":
            rendered.append(" ")
        pending_space = False
        rendered.append(character)
        if character in {"'", '"', "`"}:
            quote_end = character
        elif character == "[":
            quote_end = "]"
        position += 1
    return "".join(rendered)


def _collect_schema_manifest(connection: sqlite3.Connection) -> tuple[_SchemaObject, ...]:
    """Describe every migration-managed object using SQLite's live catalog and pragmas."""

    table_flags = {
        str(row["name"]): (int(row["ncol"]), int(row["wr"]), int(row["strict"]))
        for row in connection.execute("PRAGMA main.table_list").fetchall()
        if str(row["schema"]) == "main"
    }
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM main.sqlite_schema "
        "WHERE type IN ('table', 'index', 'trigger', 'view') "
        "AND (name NOT LIKE 'sqlite_%' OR name LIKE 'sqlite_autoindex_%') "
        "ORDER BY type, name"
    ).fetchall()
    manifest: list[_SchemaObject] = []
    for row in rows:
        object_type = str(row["type"])
        name = str(row["name"])
        table_name = str(row["tbl_name"])
        columns: tuple[tuple[int, str, str, int, str | None, int, int], ...] = ()
        foreign_keys: tuple[tuple[int, int, str, str, str | None, str, str, str], ...] = ()
        flags: tuple[int, int, int] | None = None
        index_properties: tuple[int, str, int] | None = None
        index_columns: tuple[tuple[int, int, str | None, int, str, int], ...] = ()
        if object_type == "table":
            columns = tuple(
                (
                    int(column["cid"]),
                    str(column["name"]),
                    str(column["type"]),
                    int(column["notnull"]),
                    None if column["dflt_value"] is None else str(column["dflt_value"]),
                    int(column["pk"]),
                    int(column["hidden"]),
                )
                for column in connection.execute(
                    'SELECT cid, name, type, "notnull", dflt_value, pk, hidden '
                    "FROM pragma_table_xinfo(?) ORDER BY cid",
                    (name,),
                ).fetchall()
            )
            foreign_keys = tuple(
                (
                    int(foreign_key["id"]),
                    int(foreign_key["seq"]),
                    str(foreign_key["table"]),
                    str(foreign_key["from"]),
                    None if foreign_key["to"] is None else str(foreign_key["to"]),
                    str(foreign_key["on_update"]),
                    str(foreign_key["on_delete"]),
                    str(foreign_key["match"]),
                )
                for foreign_key in connection.execute(
                    'SELECT id, seq, "table", "from", "to", on_update, '
                    'on_delete, "match" FROM pragma_foreign_key_list(?) ORDER BY id, seq',
                    (name,),
                ).fetchall()
            )
            flags = table_flags.get(name)
        elif object_type == "index":
            properties = connection.execute(
                'SELECT "unique", origin, partial FROM pragma_index_list(?) WHERE name = ?',
                (table_name, name),
            ).fetchone()
            if properties is not None:
                index_properties = (
                    int(properties["unique"]),
                    str(properties["origin"]),
                    int(properties["partial"]),
                )
            index_columns = tuple(
                (
                    int(column["seqno"]),
                    int(column["cid"]),
                    None if column["name"] is None else str(column["name"]),
                    int(column["desc"]),
                    str(column["coll"]),
                    int(column["key"]),
                )
                for column in connection.execute(
                    'SELECT seqno, cid, name, "desc", coll, key '
                    "FROM pragma_index_xinfo(?) ORDER BY seqno",
                    (name,),
                ).fetchall()
            )
        manifest.append(
            _SchemaObject(
                object_type=object_type,
                name=name,
                table_name=table_name,
                create_sql=_canonical_schema_sql(row["sql"]),
                columns=columns,
                foreign_keys=foreign_keys,
                table_flags=flags,
                index_properties=index_properties,
                index_columns=index_columns,
            )
        )
    return tuple(manifest)


def _expected_schema_manifest(
    migrations: tuple[_PreparedMigration, ...],
) -> tuple[_SchemaObject, ...]:
    """Materialize trusted migration source in an isolated SQLite database."""

    expected = sqlite3.connect(":memory:", isolation_level=None)
    try:
        expected.row_factory = sqlite3.Row
        expected.execute("PRAGMA foreign_keys = OFF")
        expected.execute(_SCHEMA_MIGRATIONS_BOOTSTRAP)
        for migration in migrations:
            for statement in migration.statements:
                expected.execute(statement)
            expected.execute(_MIGRATION_MARKER_SQL, (migration.version, migration.digest))
        return _collect_schema_manifest(expected)
    finally:
        expected.close()


@dataclass(frozen=True, slots=True)
class IntentReservation:
    intent_hash: str
    transaction_id: str
    created: bool
    previous_transaction_id: str | None = None


class SQLiteJournal:
    """Durable single-process journal with optimistic transaction versioning."""

    def __init__(self, path: Path) -> None:
        self._path = path.resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self._path, isolation_level=None, timeout=5.0)
        try:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            mode = self._enable_wal_with_retry()
            if str(mode).lower() != "wal":
                raise AgentKernelError(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "SQLite journal could not enable WAL mode",
                )
            self._apply_migrations()
        except BaseException:
            self._connection.close()
            raise

    def _enable_wal_with_retry(self) -> object:
        """Enable WAL despite SQLite's immediate first-open journal-mode lock race."""

        deadline = time.monotonic() + 5.0
        delay = 0.01
        while True:
            try:
                row = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()
                if row is None:
                    raise AgentKernelError(
                        ErrorCode.EVIDENCE_UNAVAILABLE,
                        "SQLite did not report a journal mode",
                    )
                return row[0]
            except sqlite3.OperationalError as error:
                code = getattr(error, "sqlite_errorcode", None)
                primary_code = code & 0xFF if isinstance(code, int) else None
                locked = primary_code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
                if not locked:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AgentKernelError(
                        ErrorCode.EVIDENCE_UNAVAILABLE,
                        "SQLite journal-mode initialization remained locked",
                        details={"sqlite": getattr(error, "sqlite_errorname", "SQLITE_BUSY")},
                        retryable=True,
                    ) from error
                time.sleep(min(delay, remaining))
                delay = min(delay * 2, 0.1)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def journal_mode(self) -> str:
        row = self._connection.execute("PRAGMA journal_mode").fetchone()
        return str(row[0]).lower()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> SQLiteJournal:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _execute_migration_statement(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> None:
        """Execute one already-validated migration step inside the active transaction."""

        self._connection.execute(statement, parameters)

    def _check_migration_invariants(self, version: int) -> None:
        missing_parent = self._connection.execute(
            'SELECT child.name AS child_table, foreign_key."table" AS parent_table '
            "FROM main.sqlite_schema AS child "
            "JOIN pragma_foreign_key_list(child.name, 'main') AS foreign_key "
            "LEFT JOIN main.sqlite_schema AS parent "
            "ON parent.type = 'table' "
            'AND parent.name = foreign_key."table" COLLATE NOCASE '
            "WHERE child.type = 'table' "
            "AND child.name NOT LIKE 'sqlite_%' "
            "AND parent.name IS NULL LIMIT 1"
        ).fetchone()
        if missing_parent is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Migration declares a foreign key to a missing table",
                details={
                    "version": version,
                    "table": str(missing_parent["child_table"]),
                    "referenced_table": str(missing_parent["parent_table"]),
                },
            )
        self._check_database_integrity(version=version)

    def _check_database_integrity(self, *, version: int) -> None:
        foreign_key_violation = self._connection.execute("PRAGMA foreign_key_check").fetchone()
        if foreign_key_violation is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "SQLite data violates a foreign-key invariant",
                details={
                    "version": version,
                    "table": str(foreign_key_violation[0]),
                    "rowid": foreign_key_violation[1],
                    "referenced_table": str(foreign_key_violation[2]),
                    "foreign_key_id": int(foreign_key_violation[3]),
                },
            )
        integrity_row = self._connection.execute("PRAGMA integrity_check").fetchone()
        if integrity_row is None or str(integrity_row[0]).lower() != "ok":
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "SQLite data violates an integrity invariant",
                details={
                    "version": version,
                    "result": None if integrity_row is None else str(integrity_row[0]),
                },
            )

    def _validate_live_schema(
        self,
        expected: tuple[_SchemaObject, ...],
        *,
        version: int,
    ) -> None:
        actual = _collect_schema_manifest(self._connection)
        expected_by_key = {(item.object_type, item.name): item for item in expected}
        actual_by_key = {(item.object_type, item.name): item for item in actual}
        missing = sorted(set(expected_by_key) - set(actual_by_key))
        unexpected = sorted(set(actual_by_key) - set(expected_by_key))
        if missing or unexpected:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Live SQLite schema object set differs from migration source",
                details={
                    "version": version,
                    "missing": [f"{kind}:{name}" for kind, name in missing],
                    "unexpected": [f"{kind}:{name}" for kind, name in unexpected],
                },
            )
        for key in sorted(expected_by_key):
            expected_object = expected_by_key[key]
            actual_object = actual_by_key[key]
            if actual_object != expected_object:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Live SQLite schema object differs from migration source",
                    details={
                        "version": version,
                        "object_type": key[0],
                        "object_name": key[1],
                        "expected_fingerprint": canonical_digest(
                            expected_object.fingerprint_material()
                        ),
                        "actual_fingerprint": canonical_digest(
                            actual_object.fingerprint_material()
                        ),
                    },
                )

    @staticmethod
    def _validate_applied_migration_rows(
        migrations: tuple[_PreparedMigration, ...],
        applied_rows: list[sqlite3.Row],
    ) -> None:
        """Reject provenance drift before deciding whether an upgrade is pending."""

        for index, row in enumerate(applied_rows):
            version = int(row["version"])
            if index >= len(migrations) or version != migrations[index].version:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Applied migration sequence differs from source",
                    details={"version": version},
                )
            if str(row["digest"]) != migrations[index].digest:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Applied migration digest differs from source",
                    details={"version": version},
                )

    def _current_schema_is_valid(
        self,
        migrations: tuple[_PreparedMigration, ...],
    ) -> bool:
        """Validate an already-current database under a concurrent read snapshot."""

        self._connection.execute("BEGIN")
        try:
            migration_table = self._connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_migrations'"
            ).fetchone()
            if migration_table is None:
                self._connection.execute("COMMIT")
                return False
            applied_rows = self._connection.execute(
                "SELECT version, digest FROM schema_migrations ORDER BY version"
            ).fetchall()
            if not applied_rows:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Existing SQLite schema has an empty migration provenance ledger",
                )
            self._validate_applied_migration_rows(migrations, applied_rows)
            if len(applied_rows) != len(migrations):
                self._connection.execute("COMMIT")
                return False
            current_version = migrations[-1].version
            self._validate_live_schema(
                _expected_schema_manifest(migrations),
                version=current_version,
            )
            self._check_database_integrity(version=current_version)
            self._connection.execute("COMMIT")
            return True
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def _apply_migrations(self) -> None:
        migrations = _prepare_migrations()
        if self._current_schema_is_valid(migrations):
            return
        try:
            self._connection.execute("BEGIN EXCLUSIVE")
        except sqlite3.OperationalError as error:
            code = getattr(error, "sqlite_errorcode", None)
            primary_code = code & 0xFF if isinstance(code, int) else None
            if primary_code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                raise AgentKernelError(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "SQLite migration lock is temporarily unavailable",
                    details={"sqlite": getattr(error, "sqlite_errorname", "SQLITE_BUSY")},
                    retryable=True,
                ) from error
            raise
        try:
            migration_table = self._connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_migrations'"
            ).fetchone()
            if migration_table is None:
                preexisting = self._connection.execute(
                    "SELECT type, name FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name LIMIT 1"
                ).fetchone()
                if preexisting is not None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Unversioned non-empty SQLite schema cannot be adopted",
                        details={
                            "object_type": str(preexisting["type"]),
                            "object_name": str(preexisting["name"]),
                        },
                    )
            self._connection.execute(_SCHEMA_MIGRATIONS_BOOTSTRAP)
            applied_rows = self._connection.execute(
                "SELECT version, digest FROM schema_migrations ORDER BY version"
            ).fetchall()
            if migration_table is not None and not applied_rows:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Existing SQLite schema has an empty migration provenance ledger",
                )
            self._validate_applied_migration_rows(migrations, applied_rows)
            if len(applied_rows) == len(migrations):
                self._connection.execute("COMMIT")
                if not self._current_schema_is_valid(migrations):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Current SQLite migration ledger disappeared during validation",
                    )
                return

            if applied_rows:
                applied_migrations = migrations[: len(applied_rows)]
                applied_version = applied_migrations[-1].version
                self._validate_live_schema(
                    _expected_schema_manifest(applied_migrations),
                    version=applied_version,
                )
                self._check_database_integrity(version=applied_version)

            for migration in migrations[len(applied_rows) :]:
                for statement in migration.statements:
                    self._execute_migration_statement(statement)
                self._check_migration_invariants(migration.version)
                self._execute_migration_statement(
                    _MIGRATION_MARKER_SQL,
                    (migration.version, migration.digest),
                )
            current_version = migrations[-1].version
            self._validate_live_schema(
                _expected_schema_manifest(migrations),
                version=current_version,
            )
            self._check_database_integrity(version=current_version)
            self._connection.execute("COMMIT")
        except BaseException:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def schema_version(self) -> int:
        row = self._connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return int(row[0] or 0)

    def _next_event_position(self, run_id: str) -> tuple[int, str | None]:
        row = self._connection.execute(
            "SELECT sequence, event_hash FROM events WHERE run_id = ? "
            "ORDER BY sequence DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        if row is None:
            return 0, None
        return int(row["sequence"]) + 1, str(row["event_hash"])

    def _insert_event(self, event: EventEnvelope) -> None:
        self._connection.execute(
            "INSERT INTO events(run_id, sequence, event_id, transaction_id, event_hash, "
            "previous_event_hash, event_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event.run_id,
                event.sequence,
                event.event_id,
                event.transaction_id,
                event.event_hash,
                event.previous_event_hash,
                event.model_dump_json(),
            ),
        )

    def create_transaction(
        self,
        record: TransactionRecord,
        *,
        run_id: str,
        actor: str,
        on_behalf_of: str,
    ) -> EventEnvelope:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                "INSERT INTO transactions(transaction_id, goal_id, state, version, intent_hash, "
                "intended_outcome, record_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    record.transaction_id,
                    record.goal_id,
                    record.state.value,
                    record.version,
                    record.intent_hash,
                    record.intended_outcome.value if record.intended_outcome else None,
                    record.model_dump_json(),
                ),
            )
            sequence, previous_hash = self._next_event_position(run_id)
            event = make_event(
                run_id=run_id,
                transaction_id=record.transaction_id,
                sequence=sequence,
                logical_time=sequence,
                wall_time=record.created_at,
                event_type="transaction.created",
                actor=actor,
                on_behalf_of=on_behalf_of,
                payload={"state": record.state.value, "version": record.version},
                previous_event_hash=previous_hash,
            )
            self._insert_event(event)
            self._connection.execute("COMMIT")
            return event
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def append_event(
        self,
        *,
        run_id: str,
        wall_time: datetime,
        event_type: str,
        actor: str,
        on_behalf_of: str,
        payload: dict[str, JsonValue],
        transaction_id: str | None = None,
    ) -> EventEnvelope:
        """Append non-transition evidence under the authoritative per-run sequence."""

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            sequence, previous_hash = self._next_event_position(run_id)
            event = make_event(
                run_id=run_id,
                transaction_id=transaction_id,
                sequence=sequence,
                logical_time=sequence,
                wall_time=wall_time,
                event_type=event_type,
                actor=actor,
                on_behalf_of=on_behalf_of,
                payload=payload,
                previous_event_hash=previous_hash,
            )
            self._insert_event(event)
            self._connection.execute("COMMIT")
            return event
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def get_transaction(self, transaction_id: str) -> TransactionRecord:
        row = self._connection.execute(
            "SELECT record_json FROM transactions WHERE transaction_id = ?", (transaction_id,)
        ).fetchone()
        if row is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Unknown transaction",
                details={"transaction_id": transaction_id},
            )
        return TransactionRecord.model_validate_json(row["record_json"])

    def set_transaction_intent(
        self,
        transaction_id: str,
        *,
        intent_hash: str,
    ) -> TransactionRecord:
        """Bind the inspected intent to a NEW transaction before staging begins."""

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.get_transaction(transaction_id)
            if current.state.value != "NEW" or current.intent_hash is not None:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Intent can only be bound once while a transaction is NEW",
                )
            updated = current.model_copy(update={"intent_hash": intent_hash})
            cursor = self._connection.execute(
                "UPDATE transactions SET intent_hash = ?, record_json = ? "
                "WHERE transaction_id = ? AND version = ?",
                (intent_hash, updated.model_dump_json(), transaction_id, current.version),
            )
            if cursor.rowcount != 1:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Could not bind transaction intent",
                )
            self._connection.execute("COMMIT")
            return updated
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def transition(
        self,
        transaction_id: str,
        *,
        expected_version: int,
        transition_event: TransitionEvent,
        now: datetime,
        run_id: str,
        actor: str,
        on_behalf_of: str,
        reason_code: str | None = None,
    ) -> tuple[TransactionRecord, EventEnvelope]:
        """CAS a transaction and append its transition event in the same DB transaction."""

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.get_transaction(transaction_id)
            if current.version != expected_version:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Transaction version changed",
                    details={"expected": expected_version, "actual": current.version},
                    retryable=True,
                )
            decision = apply_transition(
                current.state,
                transition_event,
                current_intended_outcome=current.intended_outcome,
            )
            updated = current.model_copy(
                update={
                    "state": decision.target,
                    "version": current.version + 1,
                    "intended_outcome": decision.intended_outcome,
                    "updated_at": now,
                    "reason_code": reason_code or decision.rule_id,
                }
            )
            cursor = self._connection.execute(
                "UPDATE transactions SET state = ?, version = ?, intended_outcome = ?, "
                "record_json = ? WHERE transaction_id = ? AND version = ?",
                (
                    updated.state.value,
                    updated.version,
                    updated.intended_outcome.value if updated.intended_outcome else None,
                    updated.model_dump_json(),
                    transaction_id,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Transaction compare-and-swap failed",
                    retryable=True,
                )
            sequence, previous_hash = self._next_event_position(run_id)
            event = make_event(
                run_id=run_id,
                transaction_id=transaction_id,
                sequence=sequence,
                logical_time=sequence,
                wall_time=now,
                event_type="transaction.transitioned",
                actor=actor,
                on_behalf_of=on_behalf_of,
                payload={
                    "from": current.state.value,
                    "to": updated.state.value,
                    "event": transition_event.value,
                    "rule_id": decision.rule_id,
                    "version": updated.version,
                },
                previous_event_hash=previous_hash,
            )
            self._insert_event(event)
            self._connection.execute("COMMIT")
            return updated, event
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def reserve_intent(
        self,
        *,
        intent_hash: str,
        transaction_id: str,
        reserved_at: datetime,
    ) -> IntentReservation:
        """Atomically reserve one normalized intent and return the existing owner on conflict."""

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            cursor = self._connection.execute(
                "INSERT OR IGNORE INTO intents(intent_hash, transaction_id, reserved_at) "
                "VALUES (?, ?, ?)",
                (intent_hash, transaction_id, reserved_at.isoformat()),
            )
            row = self._connection.execute(
                "SELECT transaction_id FROM intents WHERE intent_hash = ?", (intent_hash,)
            ).fetchone()
            if row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Intent reservation disappeared inside its transaction",
                )
            owner = str(row["transaction_id"])
            previous_owner: str | None = None
            created = cursor.rowcount == 1
            if owner != transaction_id:
                owner_row = self._connection.execute(
                    "SELECT state FROM transactions WHERE transaction_id = ?",
                    (owner,),
                ).fetchone()
                receipt_row = self._connection.execute(
                    "SELECT 1 FROM receipts WHERE transaction_id = ? LIMIT 1",
                    (owner,),
                ).fetchone()
                safe_no_effect_states = {
                    "REJECTED",
                    "ABORTED",
                    "STALE_STATE",
                }
                if (
                    owner_row is not None
                    and str(owner_row["state"]) in safe_no_effect_states
                    and receipt_row is None
                ):
                    updated = self._connection.execute(
                        "UPDATE intents SET transaction_id = ?, reserved_at = ? "
                        "WHERE intent_hash = ? AND transaction_id = ?",
                        (transaction_id, reserved_at.isoformat(), intent_hash, owner),
                    )
                    if updated.rowcount == 1:
                        previous_owner = owner
                        owner = transaction_id
                        created = True
            self._connection.execute("COMMIT")
            return IntentReservation(
                intent_hash,
                owner,
                created,
                previous_transaction_id=previous_owner,
            )
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def try_consume_capability_use(self, capability_id: str, max_uses: int) -> bool:
        """Atomically consume one durable capability use without exceeding its budget."""

        if max_uses < 1:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Capability use budget must be positive",
            )
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT uses FROM capability_uses WHERE capability_id = ?",
                (capability_id,),
            ).fetchone()
            uses = int(row["uses"]) if row is not None else 0
            if uses >= max_uses:
                self._connection.execute("COMMIT")
                return False
            self._connection.execute(
                "INSERT INTO capability_uses(capability_id, uses, updated_at) "
                "VALUES (?, 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) "
                "ON CONFLICT(capability_id) DO UPDATE SET "
                "uses = capability_uses.uses + 1, "
                "updated_at = excluded.updated_at",
                (capability_id,),
            )
            self._connection.execute("COMMIT")
            return True
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def link_transaction_supersession(
        self,
        transaction_id: str,
        *,
        previous_transaction_id: str,
    ) -> TransactionRecord:
        """Persist the audit link created when a no-effect intent attempt is retried."""

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.get_transaction(transaction_id)
            if current.state.value != "NEW" or current.supersedes_transaction_id is not None:
                raise AgentKernelError(
                    ErrorCode.ILLEGAL_TRANSITION,
                    "Only a new unlinked transaction can supersede a no-effect attempt",
                )
            updated = current.model_copy(
                update={"supersedes_transaction_id": previous_transaction_id}
            )
            cursor = self._connection.execute(
                "UPDATE transactions SET record_json = ? WHERE transaction_id = ? AND version = ?",
                (updated.model_dump_json(), transaction_id, current.version),
            )
            if cursor.rowcount != 1:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Could not persist transaction supersession link",
                )
            self._connection.execute("COMMIT")
            return updated
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise

    def append_receipt(self, receipt: EffectReceipt) -> None:
        """Append an immutable effect receipt; receipt IDs cannot be overwritten."""

        try:
            self._connection.execute(
                "INSERT INTO receipts(receipt_id, transaction_id, receipt_json, created_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    receipt.receipt_id,
                    receipt.transaction_id,
                    receipt.model_dump_json(),
                    receipt.created_at.isoformat(),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Receipt is not appendable",
                details={"receipt_id": receipt.receipt_id},
            ) from error

    def list_events(self, run_id: str) -> tuple[EventEnvelope, ...]:
        rows = self._connection.execute(
            "SELECT event_json FROM events WHERE run_id = ? ORDER BY sequence", (run_id,)
        ).fetchall()
        return tuple(EventEnvelope.model_validate_json(row["event_json"]) for row in rows)

    def list_non_terminal(self) -> tuple[TransactionRecord, ...]:
        terminals = tuple(state.value for state in TERMINAL_TRANSACTION_STATES)
        rows = self._connection.execute(
            "SELECT record_json FROM transactions "
            "WHERE state NOT IN (?, ?, ?, ?, ?, ?, ?, ?) ORDER BY transaction_id",
            terminals,
        ).fetchall()
        return tuple(TransactionRecord.model_validate_json(row["record_json"]) for row in rows)
