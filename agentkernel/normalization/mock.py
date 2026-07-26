"""Pure normalization for the reference in-memory ``set_values`` operation."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from urllib.parse import quote

from pydantic import ConfigDict, Field, StrictStr, ValidationError

from agentkernel.adapters.base import NormalizerManifest, implementation_digest_for_modules
from agentkernel.canonical import canonical_digest, sha256_digest
from agentkernel.domain.enums import ResourceAccessMode, ResourceUseKind
from agentkernel.domain.models import (
    ActionProposal,
    AuthenticatedActionContext,
    NormalizedAction,
    NormalizedProvenance,
    ResourceUse,
    SemanticArgument,
    StrictModel,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.normalization.base import AdmittedOperation

_MAX_VALUES = 256
_MAX_ARGUMENT_BYTES = 1_048_576


class SetValuesArguments(StrictModel):
    """Bounded ingress schema for the reference memory adapter."""

    model_config = ConfigDict(strict=True)
    values: dict[StrictStr, StrictStr] = Field(min_length=1, max_length=_MAX_VALUES)


MOCK_SET_VALUES_NORMALIZER_MANIFEST = NormalizerManifest(
    schema_ref="agentkernel.io/schemas/v1alpha1/SetValuesArguments",
    schema_digest=canonical_digest(SetValuesArguments.model_json_schema(mode="validation")),
    implementation="mock.set_values",
    version="1.0.0",
    implementation_digest=implementation_digest_for_modules("agentkernel.normalization.mock"),
    max_resources=_MAX_VALUES + 2,
    max_argument_bytes=_MAX_ARGUMENT_BYTES,
)


@dataclass(frozen=True, slots=True)
class MockSetValuesNormalizer:
    """Normalize reference memory updates without reading the mutable target."""

    manifest: NormalizerManifest = MOCK_SET_VALUES_NORMALIZER_MANIFEST

    @property
    def configuration_digest(self) -> str:
        return canonical_digest({"profile": "agentkernel.mock-target/v1"})

    def normalize(
        self,
        *,
        proposal: ActionProposal,
        context: AuthenticatedActionContext,
        operation: AdmittedOperation,
        provenance: tuple[NormalizedProvenance, ...],
    ) -> NormalizedAction:
        if (
            proposal.adapter != "mock"
            or proposal.operation != "set_values"
            or proposal.adapter_version != operation.adapter_version
            or operation.adapter != "mock"
            or operation.operation != "set_values"
            or operation.effect_domains != ("memory",)
            or operation.normalizer_manifest != self.manifest
            or operation.configuration_digest != self.configuration_digest
            or context.configuration_digest != self.configuration_digest
            or proposal.goal_id != context.goal_id
            or proposal.agent_id != context.agent_id
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Mock normalization inputs do not match admitted metadata",
            )
        try:
            arguments = SetValuesArguments.model_validate(proposal.arguments)
        except ValidationError as error:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "set_values requires exactly one bounded string-to-string values object",
            ) from error
        if any(
            not item or unicodedata.normalize("NFC", item) != item
            for pair in arguments.values.items()
            for item in pair
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Memory keys and values must be non-empty Unicode NFC",
            )
        provenance_ids = tuple(binding.provenance_id for binding in provenance)
        inherited_classes = tuple(
            sorted({item for binding in provenance for item in binding.data_classes})
        )
        broad = "memory://mock/target"
        uses = [
            ResourceUse(
                authority_action="memory.read",
                access_mode=ResourceAccessMode.READ,
                canonical_resource=broad,
                effect_domain="memory",
                purpose="capture_memory_precondition",
                use_kind=ResourceUseKind.PRECONDITION_READ,
                destination_external=False,
            ),
            ResourceUse(
                authority_action="memory.read",
                access_mode=ResourceAccessMode.READ,
                canonical_resource=broad,
                effect_domain="memory",
                data_classes=inherited_classes,
                purpose="verify_committed_memory",
                provenance_ids=provenance_ids,
                use_kind=ResourceUseKind.VERIFIER_READ,
                destination_external=False,
            ),
        ]
        semantic_arguments: list[SemanticArgument] = []
        for key, value in arguments.values.items():
            resource = f"memory://mock/target/{quote(key, safe='-._~')}"
            encoded = value.encode("utf-8", errors="strict")
            uses.append(
                ResourceUse(
                    authority_action="memory.write",
                    access_mode=ResourceAccessMode.WRITE,
                    canonical_resource=resource,
                    effect_domain="memory",
                    data_classes=inherited_classes,
                    purpose="apply_requested_value",
                    provenance_ids=provenance_ids,
                    use_kind=ResourceUseKind.AUTHORITATIVE_EFFECT,
                    destination_external=False,
                )
            )
            semantic_arguments.append(
                SemanticArgument(
                    argument_name="values",
                    resource=resource,
                    digest=sha256_digest(encoded),
                    size_bytes=len(encoded),
                    media_type="text/plain;charset=utf-8",
                    provenance_ids=provenance_ids,
                )
            )
        return NormalizedAction.create(
            context=context,
            transaction_id=proposal.transaction_id,
            deadline=proposal.deadline,
            idempotency_key=proposal.idempotency_key,
            adapter=operation.adapter,
            adapter_version=operation.adapter_version,
            adapter_manifest_digest=operation.adapter_manifest_digest,
            operation=operation.operation,
            normalizer_implementation=self.manifest.implementation,
            normalizer_version=self.manifest.version,
            normalizer_digest=self.manifest.implementation_digest,
            operation_schema_ref=self.manifest.schema_ref,
            operation_schema_digest=self.manifest.schema_digest,
            risk_floor=operation.risk_floor,
            effect_domains=operation.effect_domains,
            resource_uses=tuple(sorted(uses, key=lambda use: use.sort_key())),
            semantic_arguments=tuple(
                sorted(semantic_arguments, key=lambda argument: argument.sort_key())
            ),
            provenance=provenance,
        )
