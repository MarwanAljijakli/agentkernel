"""Adapter admission with exact manifest-digest pinning."""

from __future__ import annotations

from dataclasses import dataclass

from agentkernel.adapters.base import (
    EffectAdapter,
    OperationManifest,
    implementation_digest_for_modules,
)
from agentkernel.canonical import canonical_json_bytes
from agentkernel.errors import AgentKernelError, ErrorCode


@dataclass(frozen=True, slots=True)
class RegisteredAdapter:
    adapter: EffectAdapter
    manifest_digest: str
    implementation_digest: str
    implementation_modules: tuple[str, ...]
    requires_permits: bool
    reviewed: bool


@dataclass(frozen=True, slots=True)
class AdmittedAdapterOperation:
    """Immutable admission snapshot plus the implementation selected to execute it."""

    adapter: EffectAdapter
    adapter_name: str
    adapter_version: str
    manifest_digest: str
    manifest_bytes: bytes
    implementation_digest: str
    operation_name: str
    operation: OperationManifest
    requires_permits: bool
    reviewed: bool


class AdapterRegistry:
    """Keep reviewed TCB admission separate from discovery or plugin loading."""

    def __init__(self) -> None:
        self._adapters: dict[str, RegisteredAdapter] = {}

    def register(self, adapter: EffectAdapter, *, reviewed: bool = False) -> str:
        name = adapter.manifest.name
        if name in self._adapters:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Adapter name is already registered",
                details={"adapter": name},
            )
        modules = tuple(adapter.implementation_modules)
        measured = implementation_digest_for_modules(*modules)
        if adapter.manifest.implementation_digest != measured:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter manifest does not measure its installed implementation bytes",
                details={"adapter": name},
            )
        digest = adapter.manifest.digest
        self._adapters[name] = RegisteredAdapter(
            adapter=adapter,
            manifest_digest=digest,
            implementation_digest=measured,
            implementation_modules=modules,
            requires_permits=adapter.requires_permits,
            reviewed=reviewed,
        )
        return digest

    def lookup(self, name: str) -> RegisteredAdapter:
        """Return one admitted registration after revalidating all immutable pins."""

        registration = self._adapters.get(name)
        if registration is None:
            raise AgentKernelError(
                ErrorCode.UNKNOWN_ADAPTER,
                "Adapter is not registered",
                details={"adapter": name},
            )
        self._validate_registration(registration)
        return registration

    @staticmethod
    def _validate_registration(registration: RegisteredAdapter) -> None:
        adapter = registration.adapter
        current_modules = tuple(adapter.implementation_modules)
        current_implementation_digest = implementation_digest_for_modules(*current_modules)
        if (
            current_modules != registration.implementation_modules
            or current_implementation_digest != registration.implementation_digest
            or adapter.manifest.implementation_digest != current_implementation_digest
            or adapter.manifest.digest != registration.manifest_digest
            or adapter.requires_permits != registration.requires_permits
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter admission pins changed after registration",
                details={"adapter": adapter.manifest.name},
            )

    def resolve(
        self,
        name: str,
        *,
        expected_digest: str,
        enforcement_profile: bool,
    ) -> EffectAdapter:
        registration = self.lookup(name)
        if registration.manifest_digest != expected_digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter manifest changed or does not match the authorized digest",
                details={"adapter": name},
            )
        if enforcement_profile and not registration.reviewed:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Unreviewed adapters cannot enter an enforcement profile",
                details={"adapter": name},
            )
        if enforcement_profile and not registration.requires_permits:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Adapters without mandatory permits cannot enter an enforcement profile",
                details={"adapter": name},
            )
        return registration.adapter

    def resolve_admitted(
        self,
        name: str,
        operation: str,
        *,
        enforcement_profile: bool = True,
    ) -> AdmittedAdapterOperation:
        """Resolve from registry-owned pins without accepting a request-supplied digest."""

        registration = self.lookup(name)
        manifest = registration.adapter.manifest
        admitted_operation = manifest.operations.get(operation)
        if admitted_operation is None:
            raise AgentKernelError(
                ErrorCode.UNKNOWN_ADAPTER,
                "Adapter operation is not admitted",
                details={"adapter": name, "operation": operation},
            )
        if enforcement_profile and (
            not registration.reviewed
            or not registration.requires_permits
            or admitted_operation.normalizer is None
        ):
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Adapter operation lacks reviewed permit and normalizer admission",
                details={"adapter": name, "operation": operation},
            )
        return AdmittedAdapterOperation(
            adapter=registration.adapter,
            adapter_name=manifest.name,
            adapter_version=manifest.version,
            manifest_digest=registration.manifest_digest,
            manifest_bytes=canonical_json_bytes(
                manifest.model_dump(mode="python", exclude_none=True)
            ),
            implementation_digest=registration.implementation_digest,
            operation_name=operation,
            operation=admitted_operation,
            requires_permits=registration.requires_permits,
            reviewed=registration.reviewed,
        )
