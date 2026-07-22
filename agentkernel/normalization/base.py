"""Pure normalization boundary and immutable admitted-operation facts."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import Field, field_validator

from agentkernel.adapters.base import NormalizerManifest
from agentkernel.domain.enums import RiskClass
from agentkernel.domain.models import (
    ActionProposal,
    AuthenticatedActionContext,
    Digest,
    Identifier,
    NonEmptyStr,
    NormalizedAction,
    NormalizedProvenance,
    StrictModel,
)


class AdmittedOperation(StrictModel):
    """Manifest and configuration facts admitted before pure normalization.

    This value deliberately contains no adapter instance, target path, target handle, or
    callback. A normalizer can therefore use only proposal, identity, provenance, and pinned
    manifest/configuration data.
    """

    adapter: Identifier
    adapter_version: NonEmptyStr
    adapter_manifest_digest: Digest
    operation: NonEmptyStr
    risk_floor: RiskClass
    effect_domains: tuple[NonEmptyStr, ...] = Field(min_length=1, max_length=64)
    normalizer_manifest: NormalizerManifest
    configuration_digest: Digest

    @field_validator("effect_domains")
    @classmethod
    def _effect_domains_are_canonical(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values) or values != tuple(sorted(values)):
            raise ValueError("effect_domains must be sorted and unique")
        return values


@runtime_checkable
class PureActionNormalizer(Protocol):
    """Synchronous, deterministic normalizer with no authoritative target access."""

    @property
    def manifest(self) -> NormalizerManifest: ...

    @property
    def configuration_digest(self) -> str: ...

    def normalize(
        self,
        *,
        proposal: ActionProposal,
        context: AuthenticatedActionContext,
        operation: AdmittedOperation,
        provenance: tuple[NormalizedProvenance, ...],
    ) -> NormalizedAction: ...
