"""Reference reversible adapter used to prove the effect boundary contract."""

from __future__ import annotations

import threading
import unicodedata
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Literal, cast

from pydantic import JsonValue

from agentkernel.adapters.base import (
    AdapterManifest,
    AdapterObservation,
    ArtifactReader,
    BlockingCancellation,
    CommitContext,
    EffectPlan,
    EvidenceClock,
    EvidenceStore,
    OperationManifest,
    ReadOnlyContext,
    ReconcileReport,
    ReconcileStatus,
    RecoveryContext,
    StageContext,
    StagedEffect,
    StagedReceipt,
    VerifyContext,
    implementation_digest_for_modules,
    load_canonical_model_artifact,
    put_adapter_observation,
    run_blocking_quiescent,
    validate_active_deadline,
    validate_canonical_artifact,
    validate_fencing_token,
    validate_normalized_action_artifact,
    validate_permit_artifact,
    validate_recovery_action_artifacts,
)
from agentkernel.canonical import canonical_digest, canonical_json_bytes
from agentkernel.domain.enums import (
    RecoveryWorkKind,
    RiskClass,
    VerificationPhase,
    VerificationStatus,
)
from agentkernel.domain.models import (
    ActionProposal,
    AuthenticatedActionContext,
    CommitPermit,
    EffectReceipt,
    InspectionPermit,
    IntentRecord,
    NormalizedAction,
    RecoveryPermit,
    RecoveryReport,
    StagePermit,
    VerificationPermit,
    VerificationReport,
)
from agentkernel.errors import AgentKernelError, ErrorCode, UnsupportedSemantics
from agentkernel.ids import new_id
from agentkernel.normalization.base import AdmittedOperation
from agentkernel.normalization.mock import (
    MOCK_SET_VALUES_NORMALIZER_MANIFEST,
    MockSetValuesNormalizer,
)

_EMBEDDED_TENANT_ID = "tenant:embedded"


@dataclass(slots=True)
class _MemoryDispatch:
    tenant_id: str
    status: Literal["PREPARED", "NO_EFFECT", "COMMITTED", "ROLLED_BACK"]
    dispatch_id: str
    owner_version: int
    owner_history_sequence: int
    owner_history_digest: str
    normalized_action_digest: str
    permit_digest: str
    stage_id: str
    staged_state_digest: str
    receipt: EffectReceipt
    before_state: dict[str, str]
    before_version: int
    after_state: dict[str, str]
    after_version: int
    classification_ref: str | None = None


@dataclass(slots=True)
class VersionedMemoryTarget:
    state: dict[str, str] = field(default_factory=dict)
    version: int = 0
    transaction_fences: dict[tuple[str, str], int] = field(default_factory=dict, repr=False)
    intent_fences: dict[tuple[str, str], tuple[int, int]] = field(
        default_factory=dict,
        repr=False,
    )
    dispatches: dict[tuple[str, str, int], _MemoryDispatch] = field(
        default_factory=dict,
        repr=False,
    )
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    @property
    def digest(self) -> str:
        return canonical_digest(self.state)


class MockReversibleAdapter:
    """Apply dictionary updates only during explicit coordinator-authorized commit."""

    def __init__(
        self,
        target: VersionedMemoryTarget,
        *,
        require_permits: bool = False,
        artifacts: ArtifactReader | None = None,
        clock: EvidenceClock | None = None,
    ) -> None:
        if require_permits and not isinstance(artifacts, EvidenceStore):
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Enforced mock effects require a writable evidence store",
            )
        self._target = target
        self._artifacts = artifacts
        self._evidence_store = artifacts if isinstance(artifacts, EvidenceStore) else None
        self._clock = clock or EvidenceClock()
        self._requires_permits = require_permits
        self._stages: dict[str, StagedEffect | StagedReceipt] = {}
        self._stage_permits: dict[str, StagePermit] = {}
        self.manifest = AdapterManifest(
            name="mock",
            version="0.2.0",
            implementation_digest=implementation_digest_for_modules(
                "agentkernel.adapters.base",
                "agentkernel.adapters.mock",
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
                    normalizer=MOCK_SET_VALUES_NORMALIZER_MANIFEST,
                )
            },
        )

    @property
    def target(self) -> VersionedMemoryTarget:
        return self._target

    @property
    def requires_permits(self) -> bool:
        return self._requires_permits

    @property
    def implementation_modules(self) -> tuple[str, ...]:
        return ("agentkernel.adapters.base", "agentkernel.adapters.mock")

    def _run_locked[MockResultT](
        self,
        operation: Callable[[], MockResultT],
        cancellation: BlockingCancellation,
    ) -> MockResultT:
        with self._target.lock:
            cancellation.raise_if_requested()
            return operation()

    def _fault_point(self, name: str) -> None:
        """Override only in crash-injection tests; production behavior is a no-op."""

        del name

    @staticmethod
    def _dispatch_digest(dispatch: _MemoryDispatch) -> str:
        return canonical_digest(
            {
                "tenant_id": dispatch.tenant_id,
                "status": dispatch.status,
                "dispatch_id": dispatch.dispatch_id,
                "owner_version": dispatch.owner_version,
                "owner_history_sequence": dispatch.owner_history_sequence,
                "owner_history_digest": dispatch.owner_history_digest,
                "normalized_action_digest": dispatch.normalized_action_digest,
                "permit_digest": dispatch.permit_digest,
                "stage_id": dispatch.stage_id,
                "staged_state_digest": dispatch.staged_state_digest,
                "receipt": dispatch.receipt,
                "before_state": dispatch.before_state,
                "before_version": dispatch.before_version,
                "after_state": dispatch.after_state,
                "after_version": dispatch.after_version,
                "classification_ref": dispatch.classification_ref,
            }
        )

    def _record_observation(
        self,
        *,
        evidence_kind: Literal[
            "staged_verification",
            "committed_verification",
            "discard_staging",
            "rollback",
            "compensation",
            "reconciliation",
        ],
        tenant_id: str,
        transaction_id: str,
        intent_hash: str,
        normalized_action_digest: str,
        subject_ref: str,
        operation_permit_ref: str,
        authority_permit_ref: str,
        subject_authority_ref: str,
        operation_status: str,
        observed_state_digest: str,
        durable_state_digest: str,
        dispatch: _MemoryDispatch | None = None,
        dispatch_id: str | None = None,
        owner_version: int | None = None,
        owner_history_sequence: int | None = None,
        owner_history_digest: str | None = None,
    ) -> tuple[str, ...]:
        if not self.requires_permits:
            return ()
        if self._evidence_store is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Enforced mock observation store is unavailable",
            )
        explicit_generation = (
            dispatch_id,
            owner_version,
            owner_history_sequence,
            owner_history_digest,
        )
        if dispatch is not None:
            if any(value is not None for value in explicit_generation):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Adapter observation received two dispatch generations",
                )
            dispatch_id = dispatch.dispatch_id
            owner_version = dispatch.owner_version
            owner_history_sequence = dispatch.owner_history_sequence
            owner_history_digest = dispatch.owner_history_digest
        observation = AdapterObservation(
            evidence_kind=evidence_kind,
            adapter=self.manifest.name,
            adapter_manifest_digest=self.manifest.digest,
            tenant_id=tenant_id,
            transaction_id=transaction_id,
            intent_hash=intent_hash,
            normalized_action_digest=normalized_action_digest,
            subject_ref=subject_ref,
            operation_permit_ref=operation_permit_ref,
            authority_permit_ref=authority_permit_ref,
            subject_authority_ref=subject_authority_ref,
            operation_status=operation_status,
            observed_state_digest=observed_state_digest,
            durable_state_digest=durable_state_digest,
            dispatch_id=dispatch_id,
            owner_version=owner_version,
            owner_history_sequence=owner_history_sequence,
            owner_history_digest=owner_history_digest,
            observed_at=self._clock.now(),
        )
        return (put_adapter_observation(self._evidence_store, observation),)

    def _attach_recovery_observation(
        self,
        report: RecoveryReport,
        *,
        evidence_kind: Literal["discard_staging", "rollback"],
        ctx: RecoveryContext,
        transaction_id: str,
        intent_hash: str,
        normalized_action_digest: str,
        subject_ref: str,
        durable_state_digest: str,
        dispatch: _MemoryDispatch | None = None,
    ) -> RecoveryReport:
        if ctx.permit is None or ctx.permit_ref is None:
            return report
        refs = self._record_observation(
            evidence_kind=evidence_kind,
            tenant_id=ctx.permit.tenant_id,
            transaction_id=transaction_id,
            intent_hash=intent_hash,
            normalized_action_digest=normalized_action_digest,
            subject_ref=subject_ref,
            operation_permit_ref=ctx.permit_ref,
            authority_permit_ref=ctx.permit_ref,
            subject_authority_ref=ctx.permit.target_evidence_ref,
            operation_status=report.status.value,
            observed_state_digest=(
                report.restored_state_digest
                or canonical_digest(
                    {
                        "observation": "unavailable",
                        "residual_effects": report.residual_effects,
                    }
                )
            ),
            durable_state_digest=durable_state_digest,
            dispatch=dispatch,
        )
        return report.model_copy(update={"evidence_refs": refs})

    def _dispatch_for_generation(
        self,
        tenant_id: str,
        intent_hash: str,
        owner_version: int,
    ) -> _MemoryDispatch | None:
        dispatch = self._target.dispatches.get((tenant_id, intent_hash, owner_version))
        if dispatch is not None:
            self._validate_dispatch_evidence(intent_hash, dispatch)
        return dispatch

    def _latest_dispatch(self, tenant_id: str, intent_hash: str) -> _MemoryDispatch | None:
        generations = [
            (owner_version, dispatch)
            for (
                candidate_tenant,
                candidate_intent,
                owner_version,
            ), dispatch in self._target.dispatches.items()
            if candidate_tenant == tenant_id and candidate_intent == intent_hash
        ]
        if not generations:
            return None
        dispatch = max(generations, key=lambda item: item[0])[1]
        self._validate_dispatch_evidence(intent_hash, dispatch)
        return dispatch

    def _dispatch_for_receipt(
        self,
        tenant_id: str,
        receipt: EffectReceipt,
    ) -> _MemoryDispatch | None:
        dispatch = next(
            (
                dispatch
                for dispatch in self._target.dispatches.values()
                if dispatch.tenant_id == tenant_id and dispatch.receipt == receipt
            ),
            None,
        )
        if dispatch is not None:
            self._validate_dispatch_evidence(receipt.intent_hash, dispatch)
        return dispatch

    def _validate_dispatch_evidence(
        self,
        intent_hash: str,
        dispatch: _MemoryDispatch,
    ) -> None:
        if dispatch.status != "NO_EFFECT" or not self.requires_permits:
            return
        if self._artifacts is None or dispatch.classification_ref is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Mock NO_EFFECT dispatch lacks its observation artifact",
            )
        content = self._artifacts.get(dispatch.classification_ref)
        try:
            observation = AdapterObservation.model_validate_json(content)
        except (UnicodeDecodeError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Mock dispatch observation is invalid",
            ) from error
        recovery_authority = load_canonical_model_artifact(
            observation.operation_permit_ref,
            RecoveryPermit,
            self._artifacts,
            label="Mock reconciliation observation permit",
        )
        validate_recovery_action_artifacts(
            recovery_authority,
            self._artifacts,
            manifest=self.manifest,
            recovery_kind=RecoveryWorkKind.RECONCILE_DISPATCH,
            target_transaction_id=dispatch.receipt.transaction_id,
            target_intent_hash=intent_hash,
            target_normalized_action_digest=dispatch.normalized_action_digest,
            target_id=dispatch.dispatch_id,
            target_evidence_ref=recovery_authority.target_evidence_ref,
            target_version_guard=str(dispatch.before_version),
            target_owner_version=dispatch.owner_version,
            target_owner_history_sequence=dispatch.owner_history_sequence,
            target_owner_history_digest=dispatch.owner_history_digest,
        )
        if (
            canonical_json_bytes(observation) != content
            or observation.evidence_kind != "reconciliation"
            or observation.adapter != self.manifest.name
            or observation.adapter_manifest_digest != self.manifest.digest
            or observation.tenant_id != dispatch.tenant_id
            or recovery_authority.tenant_id != dispatch.tenant_id
            or observation.transaction_id != dispatch.receipt.transaction_id
            or observation.intent_hash != intent_hash
            or observation.normalized_action_digest != dispatch.normalized_action_digest
            or observation.authority_permit_ref != observation.operation_permit_ref
            or observation.subject_authority_ref != recovery_authority.target_evidence_ref
            or recovery_authority.recovery_kind is not RecoveryWorkKind.RECONCILE_DISPATCH
            or recovery_authority.target_id != dispatch.dispatch_id
            or observation.operation_status != ReconcileStatus.NO_EFFECT.value
            or observation.observed_state_digest != canonical_digest(dispatch.before_state)
            or observation.dispatch_id != dispatch.dispatch_id
            or observation.owner_version != dispatch.owner_version
            or observation.owner_history_sequence != dispatch.owner_history_sequence
            or observation.owner_history_digest != dispatch.owner_history_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Mock dispatch observation differs from its durable generation",
            )

    def _accept_transaction_fence(
        self,
        tenant_id: str,
        transaction_id: str,
        token: int,
    ) -> None:
        with self._target.lock:
            validate_fencing_token(token)
            key = (tenant_id, transaction_id)
            highwater = self._target.transaction_fences.get(key, 0)
            if token < highwater:
                raise AgentKernelError(
                    ErrorCode.AUTHORITY_REVOKED,
                    "Worker fencing token is stale",
                )
            self._target.transaction_fences[key] = max(token, highwater)

    def _accept_intent_fence(
        self,
        tenant_id: str,
        intent_hash: str,
        owner_version: int,
        token: int,
    ) -> None:
        with self._target.lock:
            validate_fencing_token(token)
            key = (tenant_id, intent_hash)
            current_owner, highwater = self._target.intent_fences.get(key, (-1, 0))
            if owner_version < current_owner or (
                owner_version == current_owner and token < highwater
            ):
                raise AgentKernelError(
                    ErrorCode.AUTHORITY_REVOKED,
                    "Intent owner generation or worker fencing token is stale",
                )
            if owner_version > current_owner:
                self._target.intent_fences[key] = (owner_version, token)
            else:
                self._target.intent_fences[key] = (
                    owner_version,
                    max(token, highwater),
                )

    def _require_permit(self, permit: object | None) -> None:
        if self.requires_permits and permit is None:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Enforced adapter dispatch requires a coordinator permit",
            )

    def _admit_inspection(
        self,
        proposal: ActionProposal,
        ctx: ReadOnlyContext,
    ) -> str:
        self._require_permit(ctx.permit)
        if ctx.permit is None:
            return ""
        permit = ctx.permit
        validate_active_deadline(ctx.deadline)
        validate_permit_artifact(permit, cast("str", ctx.permit_ref), self._artifacts)
        if (
            ctx.normalized_action is None
            or ctx.normalized_action_ref is None
            or ctx.proposal is None
            or ctx.proposal_ref is None
        ):
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Enforced inspection requires normalized action and proposal artifacts",
            )
        if ctx.proposal != proposal or permit.proposal_ref != ctx.proposal_ref:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Inspection proposal differs from its durable artifact binding",
            )
        validate_normalized_action_artifact(
            ctx.normalized_action,
            ctx.normalized_action_ref,
            self._artifacts,
            permit_digest=permit.normalized_action_digest,
            proposal=proposal,
            proposal_ref=ctx.proposal_ref,
            manifest=self.manifest,
        )
        action = ctx.normalized_action
        normalizer = MockSetValuesNormalizer()
        expected = normalizer.normalize(
            proposal=proposal,
            context=AuthenticatedActionContext(
                tenant_id=action.tenant_id,
                principal_id=action.principal_id,
                goal_id=action.goal_id,
                run_id=action.run_id,
                trace_id=action.trace_id,
                actor_id=action.actor_id,
                on_behalf_of=action.on_behalf_of,
                agent_id=action.agent_id,
                configuration_digest=action.configuration_digest,
            ),
            operation=AdmittedOperation(
                adapter=self.manifest.name,
                adapter_version=self.manifest.version,
                adapter_manifest_digest=self.manifest.digest,
                operation=proposal.operation,
                risk_floor=self.manifest.operations[proposal.operation].risk_floor,
                effect_domains=self.manifest.operations[proposal.operation].effect_domains,
                normalizer_manifest=MOCK_SET_VALUES_NORMALIZER_MANIFEST,
                configuration_digest=action.configuration_digest,
            ),
            provenance=action.provenance,
        )
        if (
            proposal.adapter != self.manifest.name
            or proposal.adapter_version != self.manifest.version
            or proposal.transaction_id != permit.transaction_id
            or action.tenant_id != permit.tenant_id
            or action.intent_hash != permit.intent_hash
            or permit.adapter_manifest_digest != self.manifest.digest
            or expected != action
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Inspection permit does not bind this adapter proposal",
            )
        self._accept_transaction_fence(
            permit.tenant_id,
            permit.transaction_id,
            permit.fencing_token,
        )
        return action.intent_hash

    def _admit_stage(self, plan: EffectPlan, ctx: StageContext) -> StagePermit | None:
        self._require_permit(ctx.permit)
        if ctx.permit is None:
            return None
        permit = ctx.permit
        validate_active_deadline(ctx.deadline)
        validate_permit_artifact(permit, cast("str", ctx.permit_ref), self._artifacts)
        validate_canonical_artifact(plan, permit.plan_ref, self._artifacts, label="Effect plan")
        inspection = load_canonical_model_artifact(
            permit.inspection_permit_ref,
            InspectionPermit,
            self._artifacts,
            label="Inspection permit",
        )
        if ctx.normalized_action is None or ctx.normalized_action_ref is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Enforced stage requires the normalized action artifact",
            )
        validate_normalized_action_artifact(
            ctx.normalized_action,
            ctx.normalized_action_ref,
            self._artifacts,
            permit_digest=permit.normalized_action_digest,
            proposal=plan.proposal,
            proposal_ref=inspection.proposal_ref,
            manifest=self.manifest,
        )
        if (
            permit.adapter_manifest_digest != self.manifest.digest
            or permit.tenant_id != inspection.tenant_id
            or permit.tenant_id != ctx.normalized_action.tenant_id
            or permit.transaction_id != plan.proposal.transaction_id
            or permit.intent_hash != plan.intent_hash
            or permit.plan_digest != canonical_digest(plan)
            or permit.target_version_guard != plan.base_version
            or permit.inspection_permit_digest != inspection.permit_digest
            or inspection.transaction_id != permit.transaction_id
            or inspection.intent_hash != permit.intent_hash
            or inspection.normalized_action_digest != permit.normalized_action_digest
            or inspection.proposal_ref != canonical_digest(plan.proposal)
            or inspection.adapter_manifest_digest != permit.adapter_manifest_digest
            or inspection.authorization_round_id != permit.authorization_round_id
            or inspection.authorization_round_digest != permit.authorization_round_digest
            or inspection.lease_id != permit.lease_id
            or inspection.worker_id != permit.worker_id
            or inspection.fencing_token != permit.fencing_token
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stage permit does not bind the inspected effect plan",
            )
        self._accept_transaction_fence(
            permit.tenant_id,
            permit.transaction_id,
            permit.fencing_token,
        )
        return permit

    def _admit_commit(self, receipt: StagedReceipt, ctx: CommitContext) -> None:
        self._require_permit(ctx.permit)
        if ctx.permit is None:
            self._accept_intent_fence(
                _EMBEDDED_TENANT_ID,
                receipt.staged.plan.intent_hash,
                0,
                ctx.fencing_token,
            )
            return
        permit = ctx.permit
        validate_active_deadline(ctx.deadline)
        validate_permit_artifact(permit, cast("str", ctx.permit_ref), self._artifacts)
        validate_canonical_artifact(
            receipt.staged.plan,
            permit.plan_ref,
            self._artifacts,
            label="Effect plan",
        )
        validate_canonical_artifact(
            receipt,
            permit.staged_receipt_ref,
            self._artifacts,
            label="Staged receipt",
        )
        stage_permit = load_canonical_model_artifact(
            permit.stage_permit_ref,
            StagePermit,
            self._artifacts,
            label="Stage permit",
        )
        inspection = load_canonical_model_artifact(
            stage_permit.inspection_permit_ref,
            InspectionPermit,
            self._artifacts,
            label="Inspection permit",
        )
        staged_verification = load_canonical_model_artifact(
            permit.staged_verification_ref,
            VerificationReport,
            self._artifacts,
            label="Staged verification",
        )
        staged_verification_permit = load_canonical_model_artifact(
            permit.staged_verification_permit_ref,
            VerificationPermit,
            self._artifacts,
            label="Staged verification permit",
        )
        precommit_inspection = load_canonical_model_artifact(
            permit.precommit_inspection_permit_ref,
            InspectionPermit,
            self._artifacts,
            label="Precommit inspection permit",
        )
        precommit_plan = load_canonical_model_artifact(
            permit.precommit_plan_ref,
            EffectPlan,
            self._artifacts,
            label="Precommit effect plan",
        )
        if self._artifacts is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Approval evidence is unavailable",
            )
        self._artifacts.get(permit.approval_evidence_ref)
        if ctx.normalized_action is None or ctx.normalized_action_ref is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Enforced commit requires the normalized action artifact",
            )
        validate_normalized_action_artifact(
            ctx.normalized_action,
            ctx.normalized_action_ref,
            self._artifacts,
            permit_digest=permit.normalized_action_digest,
            proposal=receipt.staged.plan.proposal,
            proposal_ref=inspection.proposal_ref,
            manifest=self.manifest,
        )
        plan = receipt.staged.plan
        recorded_stage_permit = self._stage_permits.get(receipt.staged.stage_id)
        durable_dispatch = self._dispatch_for_generation(
            permit.tenant_id,
            plan.intent_hash,
            permit.owner_version,
        )
        if (
            permit.adapter_manifest_digest != self.manifest.digest
            or permit.tenant_id != ctx.normalized_action.tenant_id
            or permit.tenant_id != stage_permit.tenant_id
            or permit.tenant_id != inspection.tenant_id
            or permit.transaction_id != plan.proposal.transaction_id
            or permit.intent_hash != plan.intent_hash
            or permit.stage_id != receipt.staged.stage_id
            or permit.plan_digest != canonical_digest(plan)
            or permit.stage_permit_digest != stage_permit.permit_digest
            or stage_permit.normalized_action_digest != permit.normalized_action_digest
            or inspection.normalized_action_digest != permit.normalized_action_digest
            or inspection.proposal_ref != canonical_digest(plan.proposal)
            or (recorded_stage_permit != stage_permit and durable_dispatch is None)
            or (
                durable_dispatch is not None
                and (
                    durable_dispatch.receipt.transaction_id != plan.proposal.transaction_id
                    or durable_dispatch.receipt.intent_hash != plan.intent_hash
                )
            )
            or permit.staged_state_digest != receipt.staged_state_digest
            or staged_verification.status is not VerificationStatus.PASS
            or permit.staged_verification_permit_digest != staged_verification_permit.permit_digest
            or staged_verification_permit.phase is not VerificationPhase.STAGED
            or staged_verification_permit.subject_ref != permit.staged_receipt_ref
            or staged_verification_permit.authority_permit_digest != stage_permit.permit_digest
            or staged_verification_permit.authority_permit_ref != permit.stage_permit_ref
            or staged_verification_permit.subject_permit_digest != stage_permit.permit_digest
            or staged_verification_permit.subject_permit_ref != permit.stage_permit_ref
            or staged_verification_permit.normalized_action_digest
            != permit.normalized_action_digest
            or staged_verification_permit.adapter_manifest_digest != permit.adapter_manifest_digest
            or permit.precommit_inspection_permit_digest != precommit_inspection.permit_digest
            or precommit_inspection.transaction_id != permit.transaction_id
            or precommit_inspection.intent_hash != permit.intent_hash
            or precommit_inspection.normalized_action_digest != permit.normalized_action_digest
            or precommit_inspection.proposal_ref != inspection.proposal_ref
            or precommit_inspection.adapter_manifest_digest != permit.adapter_manifest_digest
            or precommit_inspection.authorization_round_id != permit.authorization_round_id
            or precommit_inspection.authorization_round_digest != permit.authorization_round_digest
            or precommit_inspection.lease_id != permit.lease_id
            or precommit_inspection.worker_id != permit.worker_id
            or precommit_inspection.fencing_token != permit.fencing_token
            or permit.precommit_plan_digest != canonical_digest(precommit_plan)
            or precommit_plan.proposal != plan.proposal
            or precommit_plan.intent_hash != plan.intent_hash
            or precommit_plan.canonical_resource != plan.canonical_resource
            or precommit_plan.base_version != plan.base_version
            or precommit_plan.risk_class is not plan.risk_class
            or precommit_plan.effect_domains != plan.effect_domains
            or precommit_plan.semantic_arguments != plan.semantic_arguments
            or ctx.target_version_guard != plan.base_version
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Commit permit does not bind the verified staged receipt",
            )
        self._accept_intent_fence(
            permit.tenant_id,
            permit.intent_hash,
            permit.owner_version,
            permit.fencing_token,
        )

    def _admit_recovery(
        self,
        ctx: RecoveryContext,
        *,
        kind: RecoveryWorkKind,
        transaction_id: str | None = None,
        intent_hash: str | None = None,
        target_id: str | None = None,
        target_version_guard: str | None = None,
        target_normalized_action_digest: str | None = None,
        target_owner_version: int | None = None,
        target_owner_history_sequence: int | None = None,
        target_owner_history_digest: str | None = None,
    ) -> NormalizedAction | None:
        self._require_permit(ctx.permit)
        if ctx.permit is None:
            return None
        permit = ctx.permit
        validate_active_deadline(ctx.deadline)
        validate_permit_artifact(permit, cast("str", ctx.permit_ref), self._artifacts)
        if self._artifacts is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Recovery evidence is unavailable",
            )
        self._artifacts.get(permit.target_evidence_ref)
        self._artifacts.get(permit.approval_evidence_ref)
        if (
            permit.adapter_manifest_digest != self.manifest.digest
            or permit.recovery_kind is not kind
            or (transaction_id is not None and permit.transaction_id != transaction_id)
            or (intent_hash is not None and permit.intent_hash != intent_hash)
            or (target_id is not None and permit.target_id != target_id)
            or (
                target_version_guard is not None
                and permit.target_version_guard != target_version_guard
            )
            or (
                target_owner_version is not None
                and permit.target_owner_version != target_owner_version
            )
            or (
                target_owner_history_sequence is not None
                and permit.target_owner_history_sequence != target_owner_history_sequence
            )
            or (
                target_owner_history_digest is not None
                and permit.target_owner_history_digest != target_owner_history_digest
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery permit does not bind this recovery operation",
            )
        _, _, target_action = validate_recovery_action_artifacts(
            permit,
            self._artifacts,
            manifest=self.manifest,
            recovery_kind=kind,
            target_transaction_id=permit.transaction_id,
            target_intent_hash=permit.intent_hash,
            target_normalized_action_digest=target_normalized_action_digest,
            target_id=permit.target_id,
            target_evidence_ref=permit.target_evidence_ref,
            target_version_guard=permit.target_version_guard,
            target_owner_version=permit.target_owner_version,
            target_owner_history_sequence=permit.target_owner_history_sequence,
            target_owner_history_digest=permit.target_owner_history_digest,
        )
        if kind is RecoveryWorkKind.DISCARD_STAGING:
            self._accept_transaction_fence(
                permit.tenant_id,
                permit.transaction_id,
                permit.fencing_token,
            )
        else:
            self._accept_intent_fence(
                permit.tenant_id,
                permit.intent_hash,
                permit.target_owner_version,
                permit.fencing_token,
            )
        return target_action

    def _admit_verification(
        self,
        subject: StagedReceipt | EffectReceipt,
        ctx: VerifyContext,
        *,
        phase: VerificationPhase,
    ) -> None:
        self._require_permit(ctx.permit)
        if ctx.permit is None:
            return
        permit = ctx.permit
        validate_active_deadline(ctx.deadline)
        validate_permit_artifact(permit, cast("str", ctx.permit_ref), self._artifacts)
        validate_canonical_artifact(
            subject,
            cast("str", ctx.subject_ref),
            self._artifacts,
            label="Verification subject",
        )
        if ctx.normalized_action is None or ctx.normalized_action_ref is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Enforced verification requires the normalized action artifact",
            )
        if permit.phase is VerificationPhase.STAGED:
            stage_subject_permit = load_canonical_model_artifact(
                permit.subject_permit_ref,
                StagePermit,
                self._artifacts,
                label="Subject stage permit",
            )
            if (
                permit.authority_permit_ref != permit.subject_permit_ref
                or permit.authority_permit_digest != permit.subject_permit_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Staged verification requires the stage permit as both authorities",
                )
            subject_permit: StagePermit | CommitPermit = stage_subject_permit
            authority_permit: StagePermit | CommitPermit | RecoveryPermit = stage_subject_permit
            if not isinstance(subject, StagedReceipt):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Staged verification permit cannot verify a committed receipt",
                )
            plan = subject.staged.plan
            inspection = load_canonical_model_artifact(
                stage_subject_permit.inspection_permit_ref,
                InspectionPermit,
                self._artifacts,
                label="Inspection permit",
            )
            subject_permit_matches = (
                stage_subject_permit.plan_digest == canonical_digest(plan)
                and stage_subject_permit.plan_ref == canonical_digest(plan)
                and stage_subject_permit.stage_id == subject.staged.stage_id
                and stage_subject_permit.target_version_guard == plan.base_version
            )
            owner_version: int | None = None
        else:
            commit_subject_permit = load_canonical_model_artifact(
                permit.subject_permit_ref,
                CommitPermit,
                self._artifacts,
                label="Subject commit permit",
            )
            if not isinstance(subject, EffectReceipt):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Committed verification permit cannot verify a staged receipt",
                )
            plan = load_canonical_model_artifact(
                commit_subject_permit.plan_ref,
                EffectPlan,
                self._artifacts,
                label="Effect plan",
            )
            stage_permit = load_canonical_model_artifact(
                commit_subject_permit.stage_permit_ref,
                StagePermit,
                self._artifacts,
                label="Stage permit",
            )
            inspection = load_canonical_model_artifact(
                stage_permit.inspection_permit_ref,
                InspectionPermit,
                self._artifacts,
                label="Inspection permit",
            )
            subject_permit_matches = (
                commit_subject_permit.plan_digest == canonical_digest(plan)
                and subject.transaction_id == plan.proposal.transaction_id
                and subject.intent_hash == plan.intent_hash
                and subject.adapter == self.manifest.name
                and subject.operation == plan.proposal.operation
                and subject.target_version_before == commit_subject_permit.target_version_guard
            )
            subject_permit = commit_subject_permit
            if permit.authority_permit_ref == permit.subject_permit_ref:
                authority_permit = commit_subject_permit
                owner_version = commit_subject_permit.owner_version
            else:
                recovery_authority = load_canonical_model_artifact(
                    permit.authority_permit_ref,
                    RecoveryPermit,
                    self._artifacts,
                    label="Verification recovery authority",
                )
                authority_permit = recovery_authority
                owner_version = recovery_authority.target_owner_version
                if (
                    recovery_authority.recovery_kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                    or recovery_authority.transaction_id != commit_subject_permit.transaction_id
                    or recovery_authority.intent_hash != commit_subject_permit.intent_hash
                    or recovery_authority.target_id != commit_subject_permit.dispatch_id
                    or recovery_authority.target_owner_version
                    != commit_subject_permit.owner_version
                    or recovery_authority.target_owner_history_sequence
                    != commit_subject_permit.owner_history_sequence
                    or recovery_authority.target_owner_history_digest
                    != commit_subject_permit.owner_history_digest
                    or recovery_authority.target_version_guard
                    != commit_subject_permit.target_version_guard
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery verification authority does not bind the subject dispatch",
                    )
        validate_normalized_action_artifact(
            ctx.normalized_action,
            ctx.normalized_action_ref,
            self._artifacts,
            permit_digest=permit.normalized_action_digest,
            proposal=plan.proposal,
            proposal_ref=inspection.proposal_ref,
            manifest=self.manifest,
        )
        if (
            permit.phase is not phase
            or permit.subject_ref != canonical_digest(subject)
            or permit.subject_permit_ref != canonical_digest(subject_permit)
            or permit.subject_permit_digest != subject_permit.permit_digest
            or permit.authority_permit_ref != canonical_digest(authority_permit)
            or permit.authority_permit_digest != authority_permit.permit_digest
            or permit.adapter_manifest_digest != self.manifest.digest
            or permit.tenant_id != authority_permit.tenant_id
            or permit.tenant_id != subject_permit.tenant_id
            or permit.transaction_id != plan.proposal.transaction_id
            or permit.intent_hash != plan.intent_hash
            or permit.normalized_action_digest != ctx.normalized_action_ref
            or permit.authorization_round_id != authority_permit.authorization_round_id
            or permit.authorization_round_digest != authority_permit.authorization_round_digest
            or permit.lease_id != authority_permit.lease_id
            or permit.worker_id != authority_permit.worker_id
            or permit.fencing_token != authority_permit.fencing_token
            or permit.issued_at < authority_permit.issued_at
            or permit.deadline > authority_permit.deadline
            or not subject_permit_matches
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Verification permit does not bind its authority, subject, and normalized action",
            )
        if owner_version is None:
            self._accept_transaction_fence(
                permit.tenant_id,
                permit.transaction_id,
                permit.fencing_token,
            )
        else:
            self._accept_intent_fence(
                permit.tenant_id,
                permit.intent_hash,
                owner_version,
                permit.fencing_token,
            )

    async def inspect(self, proposal: ActionProposal, ctx: ReadOnlyContext) -> EffectPlan:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._inspect_locked(proposal, ctx), cancellation
            )
        )

    def _inspect_locked(
        self,
        proposal: ActionProposal,
        ctx: ReadOnlyContext,
    ) -> EffectPlan:
        if (
            proposal.adapter != self.manifest.name
            or proposal.adapter_version != self.manifest.version
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Proposal adapter identity does not match the memory implementation",
            )
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
        values_input = cast("dict[str, str]", raw_values)
        if any(
            unicodedata.normalize("NFC", value) != value
            for item in values_input.items()
            for value in item
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Memory keys and values must use Unicode NFC",
            )
        admitted_intent = self._admit_inspection(proposal, ctx)
        intent_hash = admitted_intent or canonical_digest(
            {
                "operation": proposal.operation,
                "canonical_resource": "memory://mock/target",
                "semantic_arguments": {"values": values_input},
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
            semantic_arguments={"values": cast("dict[str, JsonValue]", values_input)},
        )

    async def stage(self, plan: EffectPlan, ctx: StageContext) -> StagedEffect:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._stage_locked(plan, ctx), cancellation
            )
        )

    def _stage_locked(self, plan: EffectPlan, ctx: StageContext) -> StagedEffect:
        permit = self._admit_stage(plan, ctx)
        stage_id = permit.stage_id if permit is not None else new_id("stage")
        existing = self._stages.get(stage_id)
        if existing is not None:
            staged = existing.staged if isinstance(existing, StagedReceipt) else existing
            if staged.plan != plan:
                raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Stage ID was reused")
            return staged
        staged = StagedEffect(
            stage_id=stage_id,
            plan=plan,
            base_state_digest=self._target.digest,
            private_state={"state": cast("dict[str, JsonValue]", deepcopy(self._target.state))},
        )
        self._stages[stage_id] = staged
        if permit is not None:
            self._stage_permits[stage_id] = permit
        return staged

    async def execute(self, staged: StagedEffect, ctx: StageContext) -> StagedReceipt:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._execute_locked(staged, ctx), cancellation
            )
        )

    def _execute_locked(
        self,
        staged: StagedEffect,
        ctx: StageContext,
    ) -> StagedReceipt:
        permit = self._admit_stage(staged.plan, ctx)
        if permit is not None and staged.stage_id != permit.stage_id:
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Stage ID differs from its permit")
        existing = self._stages.get(staged.stage_id)
        if isinstance(existing, StagedReceipt):
            return existing
        if existing != staged:
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Unknown or changed memory stage")
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
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._verify_staged_locked(receipt, ctx), cancellation
            )
        )

    def _verify_staged_locked(
        self,
        receipt: StagedReceipt,
        ctx: VerifyContext,
    ) -> VerificationReport:
        self._admit_verification(receipt, ctx, phase=VerificationPhase.STAGED)
        state = receipt.private_state.get("state")
        status = (
            VerificationStatus.PASS
            if state is not None
            and self._stages.get(receipt.staged.stage_id) == receipt
            and canonical_digest(state) == receipt.staged_state_digest
            else VerificationStatus.FAIL
        )
        evidence_refs = (
            self._record_observation(
                evidence_kind="staged_verification",
                tenant_id=ctx.permit.tenant_id,
                transaction_id=receipt.staged.plan.proposal.transaction_id,
                intent_hash=receipt.staged.plan.intent_hash,
                normalized_action_digest=ctx.permit.normalized_action_digest,
                subject_ref=cast("str", ctx.subject_ref),
                operation_permit_ref=cast("str", ctx.permit_ref),
                authority_permit_ref=ctx.permit.authority_permit_ref,
                subject_authority_ref=ctx.permit.subject_permit_ref,
                operation_status=status.value,
                observed_state_digest=(
                    canonical_digest(state)
                    if state is not None
                    else canonical_digest({"stage": receipt.staged.stage_id, "state": "missing"})
                ),
                durable_state_digest=canonical_digest(
                    {
                        "stage": self._stages.get(receipt.staged.stage_id),
                        "stage_permit": self._stage_permits.get(receipt.staged.stage_id),
                    }
                ),
            )
            if ctx.permit is not None
            else ()
        )
        return VerificationReport(
            status=status,
            verifier="adapter.mock.staged",
            summary=(
                "Staged state digest matches" if status is VerificationStatus.PASS else "Mismatch"
            ),
            evidence_refs=evidence_refs,
        )

    async def commit(self, receipt: StagedReceipt, ctx: CommitContext) -> EffectReceipt:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._commit_locked(receipt, ctx, cancellation), cancellation
            )
        )

    def _commit_locked(
        self,
        receipt: StagedReceipt,
        ctx: CommitContext,
        cancellation: BlockingCancellation,
    ) -> EffectReceipt:
        self._admit_commit(receipt, ctx)
        tenant_id = ctx.permit.tenant_id if ctx.permit is not None else _EMBEDDED_TENANT_ID
        intent_hash = receipt.staged.plan.intent_hash
        owner_version = ctx.permit.owner_version if ctx.permit is not None else 0
        owner_history_sequence = ctx.permit.owner_history_sequence if ctx.permit is not None else 0
        owner_history_digest = (
            ctx.permit.owner_history_digest
            if ctx.permit is not None
            else canonical_digest(
                {
                    "tenant_id": tenant_id,
                    "mock_owner": "legacy",
                    "intent": intent_hash,
                }
            )
        )
        dispatch_id = (
            ctx.permit.dispatch_id
            if ctx.permit is not None
            else f"dispatch_{intent_hash.removeprefix('sha256:')}"
        )
        permit_digest = (
            ctx.permit.permit_digest
            if ctx.permit is not None
            else canonical_digest({"tenant_id": tenant_id, "mock_commit": intent_hash})
        )
        normalized_action_digest = (
            ctx.permit.normalized_action_digest if ctx.permit is not None else intent_hash
        )
        existing = self._dispatch_for_generation(tenant_id, intent_hash, owner_version)
        if existing is not None:
            if (
                existing.dispatch_id != dispatch_id
                or existing.owner_history_sequence != owner_history_sequence
                or existing.owner_history_digest != owner_history_digest
                or existing.permit_digest != permit_digest
                or existing.stage_id != receipt.staged.stage_id
                or existing.staged_state_digest != receipt.staged_state_digest
                or existing.normalized_action_digest != normalized_action_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Dispatch retry differs from its durable generation",
                )
            if (
                existing.status == "COMMITTED"
                and self._target.version == existing.after_version
                and self._target.state == existing.after_state
            ):
                return existing.receipt
            raise AgentKernelError(
                ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                "A prepared dispatch must be reconciled and cannot be resent",
                reconcilable=True,
                review_required=True,
            )
        latest = self._latest_dispatch(tenant_id, intent_hash)
        if latest is not None and (
            owner_version <= latest.owner_version
            or owner_history_sequence <= latest.owner_history_sequence
            or latest.status != "NO_EFFECT"
        ):
            raise AgentKernelError(
                ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                "A later mock dispatch requires prior durable NO_EFFECT evidence",
                reconcilable=True,
                review_required=True,
            )
        if self._stages.get(receipt.staged.stage_id) != receipt:
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Staged receipt is not registered")
        if ctx.target_version_guard != receipt.staged.plan.base_version:
            raise AgentKernelError(ErrorCode.STALE_STATE, "Commit context guard differs from plan")
        if str(self._target.version) != receipt.staged.plan.base_version:
            raise AgentKernelError(ErrorCode.STALE_STATE, "Authoritative target version changed")

        before_state = deepcopy(self._target.state)
        before_version = self._target.version
        after_state = cast("dict[str, str]", deepcopy(receipt.private_state["state"]))
        created_at = self._clock.now()
        prior_times = tuple(item.receipt.created_at for item in self._target.dispatches.values())
        if prior_times and created_at < max(prior_times):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Evidence clock precedes a durable mock dispatch timestamp",
            )
        effect_receipt = EffectReceipt(
            receipt_id=new_id("receipt"),
            transaction_id=receipt.staged.plan.proposal.transaction_id,
            adapter=self.manifest.name,
            operation=receipt.staged.plan.proposal.operation,
            intent_hash=intent_hash,
            target_version_before=str(before_version),
            target_version_after=canonical_digest(after_state),
            effect_digest=canonical_digest({"before": before_state, "after": after_state}),
            created_at=created_at,
        )
        dispatch = _MemoryDispatch(
            tenant_id=tenant_id,
            status="PREPARED",
            dispatch_id=dispatch_id,
            owner_version=owner_version,
            owner_history_sequence=owner_history_sequence,
            owner_history_digest=owner_history_digest,
            normalized_action_digest=normalized_action_digest,
            permit_digest=permit_digest,
            stage_id=receipt.staged.stage_id,
            staged_state_digest=receipt.staged_state_digest,
            receipt=effect_receipt,
            before_state=before_state,
            before_version=before_version,
            after_state=deepcopy(after_state),
            after_version=before_version + 1,
        )
        self._fault_point("commit.before_dispatch")
        if ctx.permit is not None:
            validate_active_deadline(ctx.deadline)
        cancellation.raise_if_requested()
        self._target.dispatches[(tenant_id, intent_hash, owner_version)] = dispatch
        self._fault_point("commit.after_prepared")
        self._target.state = after_state
        self._target.version = dispatch.after_version
        self._fault_point("commit.after_effect")
        dispatch.status = "COMMITTED"
        self._stages.pop(receipt.staged.stage_id, None)
        self._stage_permits.pop(receipt.staged.stage_id, None)
        return effect_receipt

    async def verify_committed(
        self,
        receipt: EffectReceipt,
        ctx: VerifyContext,
    ) -> VerificationReport:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._verify_committed_locked(receipt, ctx), cancellation
            )
        )

    def _verify_committed_locked(
        self,
        receipt: EffectReceipt,
        ctx: VerifyContext,
    ) -> VerificationReport:
        self._admit_verification(receipt, ctx, phase=VerificationPhase.COMMITTED)
        tenant_id = ctx.permit.tenant_id if ctx.permit is not None else _EMBEDDED_TENANT_ID
        dispatch = self._dispatch_for_receipt(tenant_id, receipt)
        status = (
            VerificationStatus.PASS
            if dispatch is not None
            and dispatch.status == "COMMITTED"
            and dispatch.receipt == receipt
            and self._target.version == dispatch.after_version
            and self._target.state == dispatch.after_state
            else VerificationStatus.FAIL
        )
        evidence_refs = (
            self._record_observation(
                evidence_kind="committed_verification",
                tenant_id=ctx.permit.tenant_id,
                transaction_id=receipt.transaction_id,
                intent_hash=receipt.intent_hash,
                normalized_action_digest=ctx.permit.normalized_action_digest,
                subject_ref=cast("str", ctx.subject_ref),
                operation_permit_ref=cast("str", ctx.permit_ref),
                authority_permit_ref=ctx.permit.authority_permit_ref,
                subject_authority_ref=ctx.permit.subject_permit_ref,
                operation_status=status.value,
                observed_state_digest=self._target.digest,
                durable_state_digest=(
                    self._dispatch_digest(dispatch)
                    if dispatch is not None
                    else canonical_digest({"dispatch": "missing"})
                ),
                dispatch=dispatch,
            )
            if ctx.permit is not None
            else ()
        )
        return VerificationReport(
            status=status,
            verifier="adapter.mock.committed",
            summary="Authoritative receipt and target version match",
            evidence_refs=evidence_refs,
        )

    async def abort(
        self,
        staged: StagedEffect | StagedReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._abort_locked(staged, ctx), cancellation
            )
        )

    def _abort_locked(
        self,
        staged: StagedEffect | StagedReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        effect = staged.staged if isinstance(staged, StagedReceipt) else staged
        stage_permit = self._stage_permits.get(effect.stage_id)
        self._admit_recovery(
            ctx,
            kind=RecoveryWorkKind.DISCARD_STAGING,
            transaction_id=effect.plan.proposal.transaction_id,
            intent_hash=effect.plan.intent_hash,
            target_id=effect.stage_id,
            target_version_guard=effect.plan.base_version,
            target_normalized_action_digest=(
                stage_permit.normalized_action_digest if stage_permit is not None else None
            ),
        )
        durable_state_digest = canonical_digest(
            {"stage": self._stages.get(effect.stage_id), "stage_permit": stage_permit}
        )
        report = self._discard_stage(effect.stage_id)
        if stage_permit is None:
            return report
        return self._attach_recovery_observation(
            report,
            evidence_kind="discard_staging",
            ctx=ctx,
            transaction_id=effect.plan.proposal.transaction_id,
            intent_hash=effect.plan.intent_hash,
            normalized_action_digest=stage_permit.normalized_action_digest,
            subject_ref=(
                ctx.permit.target_evidence_ref
                if ctx.permit is not None
                else canonical_digest(effect)
            ),
            durable_state_digest=durable_state_digest,
        )

    async def abort_stage(self, stage_id: str, ctx: RecoveryContext) -> RecoveryReport:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._abort_stage_locked(stage_id, ctx), cancellation
            )
        )

    def _abort_stage_locked(self, stage_id: str, ctx: RecoveryContext) -> RecoveryReport:
        existing = self._stages.get(stage_id)
        effect = existing.staged if isinstance(existing, StagedReceipt) else existing
        stage_permit = self._stage_permits.get(stage_id)
        self._admit_recovery(
            ctx,
            kind=RecoveryWorkKind.DISCARD_STAGING,
            transaction_id=effect.plan.proposal.transaction_id if effect is not None else None,
            intent_hash=effect.plan.intent_hash if effect is not None else None,
            target_id=stage_id,
            target_version_guard=effect.plan.base_version if effect is not None else None,
            target_normalized_action_digest=(
                stage_permit.normalized_action_digest if stage_permit is not None else None
            ),
        )
        durable_state_digest = canonical_digest({"stage": existing, "stage_permit": stage_permit})
        report = self._discard_stage(stage_id)
        if effect is None or stage_permit is None:
            return report
        return self._attach_recovery_observation(
            report,
            evidence_kind="discard_staging",
            ctx=ctx,
            transaction_id=effect.plan.proposal.transaction_id,
            intent_hash=effect.plan.intent_hash,
            normalized_action_digest=stage_permit.normalized_action_digest,
            subject_ref=(
                ctx.permit.target_evidence_ref
                if ctx.permit is not None
                else canonical_digest(effect)
            ),
            durable_state_digest=durable_state_digest,
        )

    def _discard_stage(self, stage_id: str) -> RecoveryReport:
        self._stages.pop(stage_id, None)
        self._stage_permits.pop(stage_id, None)
        return RecoveryReport(
            status=VerificationStatus.PASS,
            strategy="discard_staged_memory",
            restored_state_digest=self._target.digest,
        )

    async def rollback(self, receipt: EffectReceipt, ctx: RecoveryContext) -> RecoveryReport:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._rollback_locked(receipt, ctx), cancellation
            )
        )

    def _rollback_locked(
        self,
        receipt: EffectReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        tenant_id = ctx.permit.tenant_id if ctx.permit is not None else _EMBEDDED_TENANT_ID
        dispatch = self._dispatch_for_receipt(tenant_id, receipt)
        self._admit_recovery(
            ctx,
            kind=RecoveryWorkKind.ROLLBACK,
            transaction_id=receipt.transaction_id,
            intent_hash=receipt.intent_hash,
            target_id=dispatch.dispatch_id if dispatch is not None else None,
            target_version_guard=receipt.target_version_before,
            target_normalized_action_digest=(
                dispatch.normalized_action_digest if dispatch is not None else None
            ),
            target_owner_version=dispatch.owner_version if dispatch is not None else None,
            target_owner_history_sequence=(
                dispatch.owner_history_sequence if dispatch is not None else None
            ),
            target_owner_history_digest=(
                dispatch.owner_history_digest if dispatch is not None else None
            ),
        )
        if dispatch is None or dispatch.receipt != receipt:
            return RecoveryReport(
                status=VerificationStatus.UNKNOWN,
                strategy="restore_memory_snapshot",
                residual_effects=("missing_snapshot",),
            )

        def finalize(report: RecoveryReport) -> RecoveryReport:
            return self._attach_recovery_observation(
                report,
                evidence_kind="rollback",
                ctx=ctx,
                transaction_id=receipt.transaction_id,
                intent_hash=receipt.intent_hash,
                normalized_action_digest=dispatch.normalized_action_digest,
                subject_ref=canonical_digest(receipt),
                durable_state_digest=self._dispatch_digest(dispatch),
                dispatch=dispatch,
            )

        if dispatch.status == "ROLLED_BACK" and self._target.state == dispatch.before_state:
            return finalize(
                RecoveryReport(
                    status=VerificationStatus.PASS,
                    strategy="restore_memory_snapshot",
                    restored_state_digest=self._target.digest,
                )
            )
        if (
            self._target.version != dispatch.after_version
            or self._target.state != dispatch.after_state
        ):
            return finalize(
                RecoveryReport(
                    status=VerificationStatus.UNKNOWN,
                    strategy="restore_memory_snapshot",
                    restored_state_digest=self._target.digest,
                    residual_effects=("target_version_changed_after_commit",),
                )
            )
        self._target.state = deepcopy(dispatch.before_state)
        self._target.version += 1
        dispatch.status = "ROLLED_BACK"
        return finalize(
            RecoveryReport(
                status=VerificationStatus.PASS,
                strategy="restore_memory_snapshot",
                restored_state_digest=self._target.digest,
            )
        )

    async def reconcile(self, intent: IntentRecord, ctx: RecoveryContext) -> ReconcileReport:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._reconcile_locked(intent, ctx), cancellation
            )
        )

    def _reconcile_locked(
        self,
        intent: IntentRecord,
        ctx: RecoveryContext,
    ) -> ReconcileReport:
        dispatch = (
            self._dispatch_for_generation(
                ctx.permit.tenant_id,
                intent.intent_hash,
                ctx.permit.target_owner_version,
            )
            if ctx.permit is not None
            else self._latest_dispatch(_EMBEDDED_TENANT_ID, intent.intent_hash)
        )
        target_version_guard = (
            str(dispatch.before_version)
            if dispatch is not None
            else ctx.permit.target_version_guard
            if ctx.permit is not None
            else None
        )
        target_action = self._admit_recovery(
            ctx,
            kind=RecoveryWorkKind.RECONCILE_DISPATCH,
            transaction_id=intent.transaction_id,
            intent_hash=intent.intent_hash,
            target_id=(
                dispatch.dispatch_id
                if dispatch is not None
                else ctx.permit.target_id
                if ctx.permit is not None
                else None
            ),
            target_version_guard=target_version_guard,
            target_normalized_action_digest=(
                dispatch.normalized_action_digest if dispatch is not None else None
            ),
            target_owner_version=dispatch.owner_version if dispatch is not None else None,
            target_owner_history_sequence=(
                dispatch.owner_history_sequence if dispatch is not None else None
            ),
            target_owner_history_digest=(
                dispatch.owner_history_digest if dispatch is not None else None
            ),
        )
        if dispatch is None:
            if ctx.permit is None or ctx.permit_ref is None or target_action is None:
                return ReconcileReport(status=ReconcileStatus.UNKNOWN)
            permit = ctx.permit
            observed_state_digest = self._target.digest
            durable_state_digest = canonical_digest(
                {
                    "profile": "agentkernel.adapter.dispatch-absence/v1",
                    "adapter_manifest_digest": self.manifest.digest,
                    "tenant_id": permit.tenant_id,
                    "intent_hash": intent.intent_hash,
                    "dispatch_id": permit.target_id,
                    "owner_version": permit.target_owner_version,
                    "owner_history_sequence": permit.target_owner_history_sequence,
                    "owner_history_digest": permit.target_owner_history_digest,
                    "reservation_present": False,
                }
            )
            evidence = self._record_observation(
                evidence_kind="reconciliation",
                tenant_id=permit.tenant_id,
                transaction_id=intent.transaction_id,
                intent_hash=intent.intent_hash,
                normalized_action_digest=canonical_digest(target_action),
                subject_ref=canonical_digest(intent),
                operation_permit_ref=ctx.permit_ref,
                authority_permit_ref=ctx.permit_ref,
                subject_authority_ref=permit.target_evidence_ref,
                operation_status=ReconcileStatus.NO_EFFECT.value,
                observed_state_digest=observed_state_digest,
                durable_state_digest=durable_state_digest,
                dispatch_id=permit.target_id,
                owner_version=permit.target_owner_version,
                owner_history_sequence=permit.target_owner_history_sequence,
                owner_history_digest=permit.target_owner_history_digest,
            )
            return ReconcileReport(
                status=ReconcileStatus.NO_EFFECT,
                evidence_refs=evidence,
            )
        target_matches = (
            self._target.version == dispatch.after_version
            and self._target.state == dispatch.after_state
        )
        base_matches = (
            self._target.version == dispatch.before_version
            and self._target.state == dispatch.before_state
        )
        if target_matches:
            outcome = (
                ReconcileStatus.UNKNOWN
                if dispatch.status in {"NO_EFFECT", "ROLLED_BACK"}
                else ReconcileStatus.COMMITTED
            )
        elif base_matches:
            outcome = (
                ReconcileStatus.UNKNOWN
                if dispatch.status == "COMMITTED"
                else ReconcileStatus.NO_EFFECT
            )
        else:
            outcome = ReconcileStatus.PARTIAL_OR_INVALID
        evidence = (
            self._record_observation(
                evidence_kind="reconciliation",
                tenant_id=ctx.permit.tenant_id,
                transaction_id=intent.transaction_id,
                intent_hash=intent.intent_hash,
                normalized_action_digest=dispatch.normalized_action_digest,
                subject_ref=canonical_digest(intent),
                operation_permit_ref=cast("str", ctx.permit_ref),
                authority_permit_ref=cast("str", ctx.permit_ref),
                subject_authority_ref=ctx.permit.target_evidence_ref,
                operation_status=outcome.value,
                observed_state_digest=self._target.digest,
                durable_state_digest=self._dispatch_digest(dispatch),
                dispatch=dispatch,
            )
            if ctx.permit is not None
            else ()
        )
        if target_matches:
            if dispatch.status in {"NO_EFFECT", "ROLLED_BACK"}:
                return ReconcileReport(
                    status=ReconcileStatus.UNKNOWN,
                    evidence_refs=evidence,
                )
            dispatch.status = "COMMITTED"
            return ReconcileReport(
                status=ReconcileStatus.COMMITTED,
                receipt=dispatch.receipt,
                evidence_refs=evidence,
            )
        if base_matches:
            if dispatch.status == "COMMITTED":
                return ReconcileReport(
                    status=ReconcileStatus.UNKNOWN,
                    evidence_refs=evidence,
                )
            if dispatch.status not in {"NO_EFFECT", "ROLLED_BACK"}:
                dispatch.status = "NO_EFFECT"
                dispatch.classification_ref = evidence[-1] if evidence else None
            return ReconcileReport(status=ReconcileStatus.NO_EFFECT, evidence_refs=evidence)
        return ReconcileReport(
            status=ReconcileStatus.PARTIAL_OR_INVALID,
            receipt=dispatch.receipt,
            evidence_refs=evidence,
        )

    async def compensate(self, receipt: EffectReceipt, ctx: RecoveryContext) -> RecoveryReport:
        del receipt, ctx

        def unsupported(_cancellation: BlockingCancellation) -> RecoveryReport:
            raise UnsupportedSemantics("compensate")

        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(lambda: unsupported(cancellation), cancellation)
        )
