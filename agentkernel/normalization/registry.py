"""Reviewed pure-normalizer admission with exact manifest and configuration pinning."""

from __future__ import annotations

import re
from dataclasses import dataclass

from pydantic import ValidationError

from agentkernel.adapters.base import AdapterManifest, NormalizerManifest
from agentkernel.canonical import canonical_digest
from agentkernel.domain.models import (
    ActionProposal,
    AuthenticatedActionContext,
    NormalizedAction,
    NormalizedProvenance,
    ProvenanceRecord,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.normalization.base import AdmittedOperation, PureActionNormalizer
from agentkernel.normalization.limits import bounded_json_size

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_PROVENANCE_RECORDS = 256


@dataclass(frozen=True, slots=True)
class RegisteredNormalizer:
    normalizer: PureActionNormalizer
    manifest_digest: str
    configuration_digest: str
    reviewed: bool


def _argument_size(arguments: object, *, max_bytes: int) -> int:
    return bounded_json_size(arguments, max_bytes=max_bytes)


def _bind_provenance(
    proposal: ActionProposal,
    records: tuple[ProvenanceRecord, ...],
) -> tuple[NormalizedProvenance, ...]:
    expected_ids = proposal.provenance_ids
    actual_ids = tuple(record.provenance_id for record in records)
    if len(set(expected_ids)) != len(expected_ids) or len(set(actual_ids)) != len(actual_ids):
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Action provenance identifiers must be unique",
        )
    if set(expected_ids) != set(actual_ids):
        raise AgentKernelError(
            ErrorCode.EVIDENCE_UNAVAILABLE,
            "Action provenance records do not exactly match the proposal",
        )
    for record in records:
        if (
            len(set(record.data_classes)) != len(record.data_classes)
            or record.data_classes != tuple(sorted(record.data_classes))
            or len(set(record.parent_ids)) != len(record.parent_ids)
            or record.parent_ids != tuple(sorted(record.parent_ids))
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Provenance data classes and parent identifiers must be sorted and unique",
            )
    try:
        return tuple(
            sorted(
                (
                    NormalizedProvenance(
                        provenance_id=record.provenance_id,
                        trust=record.trust,
                        data_classes=tuple(sorted(record.data_classes)),
                        record_digest=canonical_digest(record),
                        integrity_ref=record.integrity_ref,
                    )
                    for record in records
                ),
                key=lambda binding: binding.provenance_id,
            )
        )
    except ValueError as error:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Action provenance is not in canonical form",
        ) from error


class NormalizerRegistry:
    """Resolve reviewed normalizers only when every admitted pin matches exactly."""

    def __init__(self) -> None:
        self._normalizers: dict[tuple[str, str], RegisteredNormalizer] = {}

    def register(
        self,
        adapter: str,
        operation: str,
        normalizer: PureActionNormalizer,
        *,
        reviewed: bool = False,
    ) -> str:
        key = (adapter, operation)
        if key in self._normalizers:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Normalizer is already registered for this adapter operation",
                details={"adapter": adapter, "operation": operation},
            )
        manifest = normalizer.manifest
        if not isinstance(manifest, NormalizerManifest):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Normalizer exposes invalid manifest metadata",
            )
        if not _DIGEST_PATTERN.fullmatch(normalizer.configuration_digest):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Normalizer exposes an invalid configuration digest",
            )
        registration = RegisteredNormalizer(
            normalizer=normalizer,
            manifest_digest=manifest.digest,
            configuration_digest=normalizer.configuration_digest,
            reviewed=reviewed,
        )
        self._normalizers[key] = registration
        return registration.manifest_digest

    def resolve(
        self,
        adapter: str,
        operation: str,
        *,
        expected_manifest: NormalizerManifest,
        expected_configuration_digest: str,
        enforcement_profile: bool,
    ) -> PureActionNormalizer:
        registration = self._normalizers.get((adapter, operation))
        if registration is None:
            raise AgentKernelError(
                ErrorCode.UNKNOWN_ADAPTER,
                "No pure normalizer is registered for this adapter operation",
                details={"adapter": adapter, "operation": operation},
            )
        current_manifest = registration.normalizer.manifest
        current_configuration_digest = registration.normalizer.configuration_digest
        if (
            registration.manifest_digest != expected_manifest.digest
            or current_manifest != expected_manifest
            or current_manifest.digest != registration.manifest_digest
            or registration.configuration_digest != expected_configuration_digest
            or current_configuration_digest != registration.configuration_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Normalizer manifest, schema, version, implementation, or configuration mismatch",
                details={"adapter": adapter, "operation": operation},
            )
        if enforcement_profile and not registration.reviewed:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Unreviewed normalizers cannot enter an enforcement profile",
                details={"adapter": adapter, "operation": operation},
            )
        return registration.normalizer

    def normalize(
        self,
        proposal: ActionProposal,
        context: AuthenticatedActionContext,
        *,
        adapter_manifest: AdapterManifest,
        expected_adapter_manifest_digest: str,
        provenance_records: tuple[ProvenanceRecord, ...],
        enforcement_profile: bool = True,
    ) -> NormalizedAction:
        """Validate all pins and invoke the admitted synchronous pure normalizer."""

        if len(provenance_records) > _MAX_PROVENANCE_RECORDS:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Normalization provenance record count exceeds the admitted limit",
            )

        try:
            adapter_manifest = AdapterManifest.model_validate(
                adapter_manifest.model_dump(mode="python")
            )
        except (AttributeError, TypeError, ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter manifest is not a valid canonical admission contract",
            ) from error
        if adapter_manifest.digest != expected_adapter_manifest_digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter manifest does not match the admitted digest",
                details={"adapter": proposal.adapter},
            )
        if (
            proposal.adapter != adapter_manifest.name
            or proposal.adapter_version != adapter_manifest.version
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Proposal adapter identity does not match the admitted manifest",
            )
        _argument_size(proposal.arguments, max_bytes=16_777_216)
        try:
            proposal = ActionProposal.model_validate(proposal.model_dump(mode="python"))
            context = AuthenticatedActionContext.model_validate(context.model_dump(mode="python"))
            provenance_records = tuple(
                ProvenanceRecord.model_validate(record.model_dump(mode="python"))
                for record in provenance_records
            )
        except (AttributeError, TypeError, ValidationError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Normalization inputs are not canonical public contracts",
            ) from error
        if proposal.goal_id != context.goal_id or proposal.agent_id != context.agent_id:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Proposal identity does not match its authenticated context",
            )
        operation_manifest = adapter_manifest.operations.get(proposal.operation)
        if operation_manifest is None:
            raise AgentKernelError(
                ErrorCode.UNKNOWN_ADAPTER,
                "Proposal operation is absent from the admitted adapter manifest",
                details={"adapter": proposal.adapter, "operation": proposal.operation},
            )
        normalizer_manifest = operation_manifest.normalizer
        if normalizer_manifest is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Enforced normalization requires complete normalizer metadata",
                details={"adapter": proposal.adapter, "operation": proposal.operation},
            )
        _argument_size(
            proposal.arguments,
            max_bytes=normalizer_manifest.max_argument_bytes,
        )
        normalizer = self.resolve(
            proposal.adapter,
            proposal.operation,
            expected_manifest=normalizer_manifest,
            expected_configuration_digest=context.configuration_digest,
            enforcement_profile=enforcement_profile,
        )
        provenance = _bind_provenance(proposal, provenance_records)
        try:
            admitted_operation = AdmittedOperation(
                adapter=adapter_manifest.name,
                adapter_version=adapter_manifest.version,
                adapter_manifest_digest=expected_adapter_manifest_digest,
                operation=proposal.operation,
                risk_floor=operation_manifest.risk_floor,
                effect_domains=operation_manifest.effect_domains,
                normalizer_manifest=normalizer_manifest,
                configuration_digest=context.configuration_digest,
            )
        except ValueError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Admitted operation metadata is not canonical",
            ) from error
        try:
            candidate = normalizer.normalize(
                proposal=proposal,
                context=context,
                operation=admitted_operation,
                provenance=provenance,
            )
        except AgentKernelError:
            raise
        except Exception as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Pure normalizer failed without producing an admitted result",
            ) from error
        try:
            normalized = NormalizedAction.model_validate(candidate.model_dump(mode="python"))
        except (AttributeError, TypeError, ValidationError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Pure normalizer returned an invalid normalized action",
            ) from error
        self._validate_result(
            normalized,
            proposal=proposal,
            context=context,
            operation=admitted_operation,
            provenance=provenance,
        )
        return normalized

    @staticmethod
    def _validate_result(
        normalized: NormalizedAction,
        *,
        proposal: ActionProposal,
        context: AuthenticatedActionContext,
        operation: AdmittedOperation,
        provenance: tuple[NormalizedProvenance, ...],
    ) -> None:
        manifest = operation.normalizer_manifest
        expected = (
            normalized.transaction_id == proposal.transaction_id
            and normalized.deadline == proposal.deadline
            and normalized.idempotency_key == proposal.idempotency_key
            and normalized.trace_id == context.trace_id
            and normalized.tenant_id == context.tenant_id
            and normalized.principal_id == context.principal_id
            and normalized.goal_id == context.goal_id
            and normalized.run_id == context.run_id
            and normalized.actor_id == context.actor_id
            and normalized.on_behalf_of == context.on_behalf_of
            and normalized.agent_id == context.agent_id
            and normalized.adapter == operation.adapter
            and normalized.adapter_version == operation.adapter_version
            and normalized.adapter_manifest_digest == operation.adapter_manifest_digest
            and normalized.operation == operation.operation
            and normalized.normalizer_implementation == manifest.implementation
            and normalized.normalizer_version == manifest.version
            and normalized.normalizer_digest == manifest.implementation_digest
            and normalized.operation_schema_ref == manifest.schema_ref
            and normalized.operation_schema_digest == manifest.schema_digest
            and normalized.configuration_digest == operation.configuration_digest
            and normalized.risk_floor == operation.risk_floor
            and normalized.effect_domains == operation.effect_domains
            and normalized.provenance == provenance
            and len(normalized.resource_uses) <= manifest.max_resources
        )
        if not expected:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Pure normalizer output does not match its admitted operation or context",
            )
