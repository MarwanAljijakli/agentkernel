"""Adapter admission with exact manifest-digest pinning."""

from __future__ import annotations

from dataclasses import dataclass

from agentkernel.adapters.base import EffectAdapter
from agentkernel.errors import AgentKernelError, ErrorCode


@dataclass(frozen=True, slots=True)
class RegisteredAdapter:
    adapter: EffectAdapter
    manifest_digest: str
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
        digest = adapter.manifest.digest
        self._adapters[name] = RegisteredAdapter(adapter, digest, reviewed)
        return digest

    def resolve(
        self,
        name: str,
        *,
        expected_digest: str,
        enforcement_profile: bool,
    ) -> EffectAdapter:
        registration = self._adapters.get(name)
        if registration is None:
            raise AgentKernelError(
                ErrorCode.UNKNOWN_ADAPTER,
                "Adapter is not registered",
                details={"adapter": name},
            )
        current_digest = registration.adapter.manifest.digest
        if (
            registration.manifest_digest != expected_digest
            or current_digest != registration.manifest_digest
        ):
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
        return registration.adapter
