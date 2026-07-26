"""Lexical, configuration-only normalization for filesystem ``write_files``."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import quote, urlsplit

from pydantic import ConfigDict, Field, StrictStr, ValidationError, field_validator

from agentkernel.adapters.base import NormalizerManifest
from agentkernel.canonical import canonical_digest, sha256_digest
from agentkernel.domain.enums import ResourceAccessMode, ResourceUseKind
from agentkernel.domain.models import (
    MAX_CANONICAL_RESOURCE_CHARACTERS,
    MAX_RESOURCE_DATA_CLASSES,
    ActionProposal,
    AuthenticatedActionContext,
    CanonicalResource,
    NonEmptyStr,
    NormalizedAction,
    NormalizedProvenance,
    ResourceUse,
    SemanticArgument,
    StrictModel,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.normalization.base import AdmittedOperation
from agentkernel.normalization.limits import bounded_json_size

_MAX_FILES = 256
_DEFAULT_MAX_ARGUMENT_BYTES = 1_048_576
_DEFAULT_MAX_RESOURCES = _MAX_FILES + 2
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_WINDOWS_INVALID_CHARACTERS = frozenset('<>"|?*')
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CLOCK$", "CON", "CONIN$", "CONOUT$", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
    | {"COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"}
)


class WriteFilesArguments(StrictModel):
    """Strict bounded ingress schema for the filesystem write operation."""

    model_config = ConfigDict(strict=True)

    files: dict[StrictStr, StrictStr] = Field(min_length=1, max_length=_MAX_FILES)


class FilesystemNormalizerConfig(StrictModel):
    """Deployment-owned logical filesystem mapping used without target inspection."""

    schema_version: Literal["1.0"] = "1.0"
    resource_root: CanonicalResource = "fs://workspace"
    path_case_mode: Literal["sensitive", "insensitive"] = "sensitive"
    workspace_data_classes: tuple[NonEmptyStr, ...] = ("project_data",)
    max_path_bytes: int = Field(default=4096, ge=1, le=4096)
    max_segment_bytes: int = Field(default=255, ge=1, le=255)

    @field_validator("resource_root")
    @classmethod
    def _resource_root_is_a_concrete_fs_root(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "fs" or value.endswith(("/**", "/")):
            raise ValueError("Filesystem normalizer resource_root must be a concrete fs URI")
        return value

    @field_validator("workspace_data_classes")
    @classmethod
    def _data_classes_are_canonical(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if (
            len(values) > MAX_RESOURCE_DATA_CLASSES
            or any(unicodedata.normalize("NFC", value) != value for value in values)
            or len(set(values)) != len(values)
            or values != tuple(sorted(values))
        ):
            raise ValueError("workspace_data_classes must be NFC, sorted, and unique")
        return values

    @property
    def digest(self) -> str:
        return canonical_digest(self)


# This pre-release value is a reviewed contract/profile pin, not a measurement or signature of
# installed Python bytes. Package-artifact admission must replace it before an A1/AK-073 claim.
FILESYSTEM_WRITE_FILES_NORMALIZER_MANIFEST = NormalizerManifest(
    schema_ref="agentkernel.io/schemas/v1alpha1/WriteFilesArguments",
    schema_digest=canonical_digest(WriteFilesArguments.model_json_schema(mode="validation")),
    implementation="filesystem.write_files",
    version="1.0.0",
    implementation_digest=canonical_digest(
        {
            "implementation": "filesystem.write_files",
            "profile": "lexical-portable-path-v1",
            "semantic-content": "sha256-and-utf8-size-only",
            "resource-uses": "per-file-write-plus-full-tree-precondition-and-verifier-read",
            "verifier-dataflow": "inherits-request-provenance-labels",
        }
    ),
    max_resources=_DEFAULT_MAX_RESOURCES,
    max_argument_bytes=_DEFAULT_MAX_ARGUMENT_BYTES,
)


def _encoded_argument_size(arguments: object, *, max_bytes: int) -> int:
    return bounded_json_size(
        arguments,
        max_bytes=max_bytes,
        subject="write_files arguments",
    )


def _normalize_relative_path(
    raw: str,
    *,
    path_case_mode: Literal["sensitive", "insensitive"],
    max_path_bytes: int,
    max_segment_bytes: int,
) -> tuple[str, str]:
    if not raw or unicodedata.normalize("NFC", raw) != raw:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "write_files path must be non-empty Unicode NFC",
        )
    if (
        raw.startswith("/")
        or raw.endswith("/")
        or "//" in raw
        or "\\" in raw
        or ":" in raw
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
        or any(character in _WINDOWS_INVALID_CHARACTERS for character in raw)
        or _PERCENT_ESCAPE.search(raw)
    ):
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "write_files path is not a canonical portable relative path",
        )
    try:
        path_size = len(raw.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as error:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "write_files path is not valid UTF-8",
        ) from error
    if path_size > max_path_bytes:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "write_files path exceeds the configured byte limit",
        )
    parts = raw.split("/")
    portable_parts: list[str] = []
    for part in parts:
        if part in {"", ".", ".."}:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "write_files path escapes or aliases its configured scope",
            )
        try:
            segment_size = len(part.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as error:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "write_files path segment is not valid UTF-8",
            ) from error
        if segment_size > max_segment_bytes:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "write_files path segment exceeds the configured byte limit",
            )
        reserved_stem = part.split(".", 1)[0].rstrip(" .").upper()
        if part.endswith((" ", ".")) or reserved_stem in _WINDOWS_RESERVED_NAMES:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "write_files path has a non-portable operating-system alias",
            )
        portable_parts.append(
            part if path_case_mode == "sensitive" else unicodedata.normalize("NFC", part.casefold())
        )
    # The admitted deployment configuration, not the host running normalization, defines
    # resource identity. This keeps normalization pure while preventing cross-request aliases
    # on case-insensitive targets.
    return raw, "/".join(portable_parts)


def _canonical_file_uri(resource_root: str, relative_path: str) -> str:
    encoded = "/".join(
        quote(part, safe="-._~", encoding="utf-8", errors="strict")
        for part in relative_path.split("/")
    )
    canonical_resource = f"{resource_root}/{encoded}"
    if len(canonical_resource) > MAX_CANONICAL_RESOURCE_CHARACTERS:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "write_files path exceeds the canonical resource URI limit after encoding",
        )
    return canonical_resource


def _validate_path_set(paths: tuple[tuple[str, str], ...]) -> None:
    portable_to_original: dict[str, str] = {}
    for original, portable in paths:
        previous = portable_to_original.get(portable)
        if previous is not None and previous != original:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "write_files contains a case or Unicode path alias",
            )
        portable_to_original[portable] = original
    ordered = sorted(portable_to_original)
    for index, portable in enumerate(ordered[:-1]):
        if ordered[index + 1].startswith(f"{portable}/"):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "A requested file path cannot also be another file's parent",
            )


@dataclass(frozen=True, slots=True)
class FilesystemWriteFilesNormalizer:
    """Pure ``write_files`` normalizer; it performs no filesystem or process calls."""

    config: FilesystemNormalizerConfig = field(default_factory=FilesystemNormalizerConfig)
    manifest: NormalizerManifest = field(
        default_factory=lambda: FILESYSTEM_WRITE_FILES_NORMALIZER_MANIFEST
    )

    @property
    def configuration_digest(self) -> str:
        return self.config.digest

    def normalize(
        self,
        *,
        proposal: ActionProposal,
        context: AuthenticatedActionContext,
        operation: AdmittedOperation,
        provenance: tuple[NormalizedProvenance, ...],
    ) -> NormalizedAction:
        self._validate_bindings(proposal, context, operation, provenance)
        raw_files = proposal.arguments.get("files")
        if isinstance(raw_files, dict) and len(raw_files) > _MAX_FILES:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "write_files file count exceeds the operation limit",
            )
        _encoded_argument_size(
            proposal.arguments,
            max_bytes=self.manifest.max_argument_bytes,
        )
        try:
            arguments = WriteFilesArguments.model_validate(proposal.arguments)
        except ValidationError as error:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "write_files requires exactly one bounded path-to-string files object",
            ) from error
        normalized_paths = tuple(
            _normalize_relative_path(
                path,
                path_case_mode=self.config.path_case_mode,
                max_path_bytes=self.config.max_path_bytes,
                max_segment_bytes=self.config.max_segment_bytes,
            )
            for path in arguments.files
        )
        _validate_path_set(normalized_paths)
        if len(normalized_paths) + 2 > self.manifest.max_resources:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "write_files expands beyond the admitted resource-use limit",
            )

        provenance_ids = tuple(binding.provenance_id for binding in provenance)
        inherited_data_classes = tuple(
            sorted(
                set(self.config.workspace_data_classes).union(
                    *(binding.data_classes for binding in provenance)
                )
            )
        )
        if len(inherited_data_classes) > MAX_RESOURCE_DATA_CLASSES:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "write_files provenance expands beyond the resource data-class limit",
            )
        broad_resource = f"{self.config.resource_root}/**"
        resource_uses = [
            ResourceUse(
                authority_action="fs.read",
                access_mode=ResourceAccessMode.READ,
                canonical_resource=broad_resource,
                effect_domain="filesystem",
                data_classes=self.config.workspace_data_classes,
                purpose="capture_workspace_precondition",
                provenance_ids=(),
                use_kind=ResourceUseKind.PRECONDITION_READ,
                destination_external=False,
            ),
            ResourceUse(
                authority_action="fs.read",
                access_mode=ResourceAccessMode.READ,
                canonical_resource=broad_resource,
                effect_domain="filesystem",
                data_classes=inherited_data_classes,
                purpose="verify_committed_workspace",
                provenance_ids=provenance_ids,
                use_kind=ResourceUseKind.VERIFIER_READ,
                destination_external=False,
            ),
        ]
        semantic_arguments: list[SemanticArgument] = []
        for relative_path, canonical_path in normalized_paths:
            resource = _canonical_file_uri(self.config.resource_root, canonical_path)
            try:
                content_bytes = arguments.files[relative_path].encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "write_files content is not valid UTF-8",
                ) from error
            resource_uses.append(
                ResourceUse(
                    authority_action="fs.write",
                    access_mode=ResourceAccessMode.WRITE,
                    canonical_resource=resource,
                    effect_domain="filesystem",
                    data_classes=inherited_data_classes,
                    purpose="apply_requested_content",
                    provenance_ids=provenance_ids,
                    use_kind=ResourceUseKind.AUTHORITATIVE_EFFECT,
                    destination_external=False,
                )
            )
            semantic_arguments.append(
                SemanticArgument(
                    argument_name="files",
                    resource=resource,
                    digest=sha256_digest(content_bytes),
                    size_bytes=len(content_bytes),
                    media_type="text/plain;charset=utf-8",
                    provenance_ids=provenance_ids,
                )
            )
        ordered_uses = tuple(sorted(resource_uses, key=lambda use: use.sort_key()))
        ordered_arguments = tuple(
            sorted(semantic_arguments, key=lambda argument: argument.sort_key())
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
            resource_uses=ordered_uses,
            semantic_arguments=ordered_arguments,
            provenance=provenance,
        )

    def _validate_bindings(
        self,
        proposal: ActionProposal,
        context: AuthenticatedActionContext,
        operation: AdmittedOperation,
        provenance: tuple[NormalizedProvenance, ...],
    ) -> None:
        provenance_ids = tuple(binding.provenance_id for binding in provenance)
        if (
            proposal.operation != "write_files"
            or proposal.adapter != operation.adapter
            or proposal.adapter_version != operation.adapter_version
            or proposal.goal_id != context.goal_id
            or proposal.agent_id != context.agent_id
            or operation.operation != proposal.operation
            or operation.effect_domains != ("filesystem",)
            or operation.normalizer_manifest != self.manifest
            or operation.configuration_digest != self.configuration_digest
            or context.configuration_digest != self.configuration_digest
            or len(set(proposal.provenance_ids)) != len(proposal.provenance_ids)
            or tuple(sorted(proposal.provenance_ids)) != provenance_ids
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "write_files proposal, context, provenance, or admitted metadata mismatch",
            )
