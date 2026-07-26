"""Pure normalization for the allowlisted staged-process operation."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Annotated, Literal, cast
from urllib.parse import quote, urlsplit

from pydantic import (
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from agentkernel.adapters.base import NormalizerManifest
from agentkernel.canonical import canonical_digest, canonical_json_bytes, sha256_digest
from agentkernel.domain.enums import ResourceAccessMode, ResourceUseKind
from agentkernel.domain.models import (
    MAX_CANONICAL_RESOURCE_CHARACTERS,
    MAX_RESOURCE_DATA_CLASSES,
    ActionProposal,
    AuthenticatedActionContext,
    CanonicalResource,
    Digest,
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

_MAX_COMMANDS = 64
_MAX_ARGV_ITEMS = 256
_MAX_WORKSPACE_READS = 256
_MAX_WORKSPACE_WRITES = 256
_MAX_ARGUMENT_BYTES = 262_144
_MAX_TEXT_BYTES = 16_384
_MAX_AGGREGATE_BYTES = 65_536
_MAX_PROCESS_RESOURCES = 2 + _MAX_WORKSPACE_READS + (2 * _MAX_WORKSPACE_WRITES)
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_WINDOWS_INVALID_CHARACTERS = frozenset('<>"|?*')
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CLOCK$", "CON", "CONIN$", "CONOUT$", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
    | {"COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"}
)
_EMPTY_FIXED_ENVIRONMENT_DIGEST = canonical_digest({})

ProcessCommandId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$"),
]
ProcessCommandVersion = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=64,
        pattern=r"^[0-9]+(?:\.[0-9]+){0,3}(?:-[a-z0-9][a-z0-9.-]*)?$",
    ),
]


def _resource_limit(subject: str, limit: str, maximum: int) -> AgentKernelError:
    return AgentKernelError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        f"{subject} exceeds the admitted {limit} limit",
        details={"limit": limit, "maximum": maximum},
    )


class RunAllowlistedArguments(StrictModel):
    """Strict JSON shape accepted by ``process.run_allowlisted``.

    The executable, executable path, command version, shell mode, and process lookup rules
    are intentionally absent. They are deployment-owned command-definition facts.
    """

    model_config = ConfigDict(strict=True)

    command_id: ProcessCommandId
    argv: Annotated[tuple[StrictStr, ...], Field(max_length=_MAX_ARGV_ITEMS)]
    cwd: StrictStr
    env: Annotated[dict[StrictStr, StrictStr], Field(max_length=0)]
    workspace_reads: Annotated[tuple[StrictStr, ...], Field(max_length=_MAX_WORKSPACE_READS)]
    workspace_writes: Annotated[tuple[StrictStr, ...], Field(max_length=_MAX_WORKSPACE_WRITES)]


class ProcessCommandDefinition(StrictModel):
    """Immutable deployment-owned identity and bounds for one logical command."""

    model_config = ConfigDict(strict=True)

    command_id: ProcessCommandId
    version: ProcessCommandVersion
    executable_digest: Digest
    fixed_environment_digest: Digest = Field(
        default=_EMPTY_FIXED_ENVIRONMENT_DIGEST,
        description=(
            "Digest of the deployment-owned fixed environment; the process worker must "
            "recompute it from an empty inherited environment before launch"
        ),
    )
    allow_workspace_reads: StrictBool = False
    allow_workspace_writes: StrictBool = False
    max_argv_items: int = Field(default=64, ge=0, le=_MAX_ARGV_ITEMS)
    max_argv_item_bytes: int = Field(default=4096, ge=1, le=_MAX_TEXT_BYTES)
    max_argv_bytes: int = Field(default=32_768, ge=1, le=_MAX_AGGREGATE_BYTES)
    max_workspace_reads: int = Field(default=0, ge=0, le=_MAX_WORKSPACE_READS)
    max_workspace_writes: int = Field(default=0, ge=0, le=_MAX_WORKSPACE_WRITES)

    @model_validator(mode="after")
    def _bounds_are_coherent(self) -> ProcessCommandDefinition:
        if self.max_argv_item_bytes > self.max_argv_bytes:
            raise ValueError("max_argv_item_bytes cannot exceed max_argv_bytes")
        if self.allow_workspace_reads != (self.max_workspace_reads > 0):
            raise ValueError(
                "allow_workspace_reads and max_workspace_reads must enable or disable together"
            )
        if self.allow_workspace_writes != (self.max_workspace_writes > 0):
            raise ValueError(
                "allow_workspace_writes and max_workspace_writes must enable or disable together"
            )
        return self

    @property
    def digest(self) -> str:
        """Bind executable and fixed-environment identities plus every command bound."""

        return canonical_digest(self)


class ProcessNormalizerConfig(StrictModel):
    """Immutable, target-independent configuration for process normalization."""

    model_config = ConfigDict(strict=True)

    schema_version: Literal["1.0"] = "1.0"
    resource_root: CanonicalResource = "fs://workspace"
    path_case_mode: Literal["sensitive"] = "sensitive"
    workspace_data_classes: tuple[NonEmptyStr, ...] = ("project_data",)
    max_path_bytes: int = Field(default=4096, ge=1, le=4096)
    max_segment_bytes: int = Field(default=255, ge=1, le=255)
    commands: Annotated[
        tuple[ProcessCommandDefinition, ...], Field(min_length=1, max_length=_MAX_COMMANDS)
    ]

    @field_validator("resource_root")
    @classmethod
    def _resource_root_is_concrete(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "fs" or parsed.path or value.endswith(("/**", "/")):
            raise ValueError("Process resource_root must be a concrete filesystem authority")
        return value

    @field_validator("workspace_data_classes")
    @classmethod
    def _data_classes_are_canonical(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if (
            len(values) > MAX_RESOURCE_DATA_CLASSES
            or any(not unicodedata.is_normalized("NFC", value) for value in values)
            or any(
                unicodedata.category(character).startswith("C")
                for value in values
                for character in value
            )
            or values != tuple(sorted(set(values)))
        ):
            raise ValueError("workspace_data_classes must be NFC, control-free, sorted, and unique")
        return values

    @field_validator("commands")
    @classmethod
    def _commands_are_canonical(
        cls, values: tuple[ProcessCommandDefinition, ...]
    ) -> tuple[ProcessCommandDefinition, ...]:
        command_ids = tuple(command.command_id for command in values)
        if command_ids != tuple(sorted(set(command_ids))):
            raise ValueError("commands must be sorted and unique by command_id")
        return values

    @property
    def digest(self) -> str:
        """Canonical deployment-configuration identity used by admission."""

        return canonical_digest(self)


PROCESS_RUN_ALLOWLISTED_NORMALIZER_MANIFEST = NormalizerManifest(
    schema_ref="agentkernel.io/schemas/v1alpha1/RunAllowlistedArguments",
    schema_digest=canonical_digest(RunAllowlistedArguments.model_json_schema(mode="validation")),
    implementation="process.run_allowlisted",
    version="1.0.0",
    implementation_digest=canonical_digest(
        {
            "implementation": "process.run_allowlisted",
            "profile": "linux-ext4-sensitive-logical-command-v1",
            "arguments": "bounded-argv-cwd-empty-env-and-exact-workspace-resources",
            "resolution": "adapter-owned-fixed-environment-no-shell-no-path-lookup",
            "resource-uses": "exact-process-execute-cwd-read-and-declared-workspace-uses",
        }
    ),
    max_resources=_MAX_PROCESS_RESOURCES,
    max_argument_bytes=_MAX_ARGUMENT_BYTES,
)


def _preflight_arguments(arguments: Mapping[str, object]) -> dict[str, object]:
    """Apply cheap cardinality/byte guards before tuple or model allocation."""

    cardinality_fields = (
        ("argv", _MAX_ARGV_ITEMS, "argv item count"),
        ("workspace_reads", _MAX_WORKSPACE_READS, "workspace read count"),
        ("workspace_writes", _MAX_WORKSPACE_WRITES, "workspace write count"),
    )
    for field_name, maximum, subject in cardinality_fields:
        raw_value = arguments.get(field_name)
        if (
            type(raw_value) in {list, tuple}
            and len(cast("list[object] | tuple[object, ...]", raw_value)) > maximum
        ):
            raise _resource_limit("run_allowlisted arguments", subject, maximum)
    raw_env = arguments.get("env")
    if type(raw_env) is dict and raw_env:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "run_allowlisted does not accept proposal-controlled environment entries",
        )

    bounded_json_size(
        arguments,
        max_bytes=PROCESS_RUN_ALLOWLISTED_NORMALIZER_MANIFEST.max_argument_bytes,
        subject="run_allowlisted arguments",
    )

    prepared = dict(arguments)
    for field_name in ("argv", "workspace_reads", "workspace_writes"):
        raw_value = prepared.get(field_name)
        if type(raw_value) in {list, tuple}:
            prepared[field_name] = tuple(cast("list[object] | tuple[object, ...]", raw_value))
    return prepared


def _validate_security_text(
    value: str,
    *,
    subject: str,
    max_bytes: int,
    allow_empty: bool,
) -> int:
    if (not value and not allow_empty) or len(value) > max_bytes:
        if len(value) > max_bytes:
            raise _resource_limit(subject, "UTF-8 bytes", max_bytes)
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, f"{subject} must not be empty")
    if not unicodedata.is_normalized("NFC", value):
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, f"{subject} must use Unicode NFC")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            f"{subject} contains a forbidden control or non-text code point",
        )
    try:
        encoded_size = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as error:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR, f"{subject} is not valid UTF-8"
        ) from error
    if encoded_size > max_bytes:
        raise _resource_limit(subject, "UTF-8 bytes", max_bytes)
    return encoded_size


def _normalize_relative_path(
    raw: str,
    *,
    allow_workspace_root: bool,
    max_path_bytes: int,
    max_segment_bytes: int,
) -> tuple[str, str]:
    if raw == "" and allow_workspace_root:
        return "", ""
    _validate_security_text(
        raw,
        subject="run_allowlisted workspace path",
        max_bytes=max_path_bytes,
        allow_empty=False,
    )
    if (
        raw.startswith("/")
        or raw.endswith("/")
        or "//" in raw
        or "\\" in raw
        or ":" in raw
        or any(character in _WINDOWS_INVALID_CHARACTERS for character in raw)
        or _PERCENT_ESCAPE.search(raw)
    ):
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "run_allowlisted path is not a canonical portable relative path",
        )

    portable_parts: list[str] = []
    for part in raw.split("/"):
        if part in {"", ".", ".."}:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "run_allowlisted path escapes or aliases the workspace",
            )
        _validate_security_text(
            part,
            subject="run_allowlisted path segment",
            max_bytes=max_segment_bytes,
            allow_empty=False,
        )
        reserved_stem = part.split(".", 1)[0].rstrip(" .").upper()
        if part.endswith((" ", ".")) or reserved_stem in _WINDOWS_RESERVED_NAMES:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "run_allowlisted path has a non-portable operating-system alias",
            )
        portable_parts.append(part)
    return raw, "/".join(portable_parts)


def _workspace_resource(resource_root: str, portable_path: str) -> str:
    if not portable_path:
        return resource_root
    encoded = "/".join(
        quote(part, safe="-._~", encoding="utf-8", errors="strict")
        for part in portable_path.split("/")
    )
    resource = f"{resource_root}/{encoded}"
    if len(resource) > MAX_CANONICAL_RESOURCE_CHARACTERS:
        raise _resource_limit(
            "run_allowlisted workspace path",
            "canonical resource URI characters after encoding",
            MAX_CANONICAL_RESOURCE_CHARACTERS,
        )
    return resource


def _process_resource(command: ProcessCommandDefinition) -> str:
    # ``CanonicalResource`` requires generic path delimiters such as ``@`` to be encoded.
    identity = quote(
        f"{command.command_id}@{command.version}",
        safe="-._~",
        encoding="ascii",
        errors="strict",
    )
    return f"process://allowlist/{identity}"


@dataclass(frozen=True, slots=True)
class ProcessRunAllowlistedNormalizer:
    """Normalize an allowlisted process request without target or executable access."""

    config: ProcessNormalizerConfig
    manifest: NormalizerManifest = field(
        default_factory=lambda: PROCESS_RUN_ALLOWLISTED_NORMALIZER_MANIFEST
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
        prepared = _preflight_arguments(proposal.arguments)
        try:
            arguments = RunAllowlistedArguments.model_validate(prepared)
        except ValidationError as error:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "run_allowlisted requires exactly command_id, argv, cwd, env, "
                "workspace_reads, and workspace_writes with strict JSON types",
            ) from error

        command = next(
            (
                definition
                for definition in self.config.commands
                if definition.command_id == arguments.command_id
            ),
            None,
        )
        if command is None:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "The requested logical command is not in the admitted allowlist",
            )
        self._validate_command_arguments(arguments, command)

        cwd = _normalize_relative_path(
            arguments.cwd,
            allow_workspace_root=True,
            max_path_bytes=self.config.max_path_bytes,
            max_segment_bytes=self.config.max_segment_bytes,
        )
        reads = tuple(
            _normalize_relative_path(
                path,
                allow_workspace_root=False,
                max_path_bytes=self.config.max_path_bytes,
                max_segment_bytes=self.config.max_segment_bytes,
            )
            for path in arguments.workspace_reads
        )
        writes = tuple(
            _normalize_relative_path(
                path,
                allow_workspace_root=False,
                max_path_bytes=self.config.max_path_bytes,
                max_segment_bytes=self.config.max_segment_bytes,
            )
            for path in arguments.workspace_writes
        )
        canonical_reads = tuple(sorted(set(reads), key=lambda value: value[1]))
        canonical_writes = tuple(sorted(set(writes), key=lambda value: value[1]))

        provenance_ids = tuple(binding.provenance_id for binding in provenance)
        inherited_data_classes = tuple(
            sorted(
                set(self.config.workspace_data_classes).union(
                    *(binding.data_classes for binding in provenance)
                )
            )
        )
        if len(inherited_data_classes) > MAX_RESOURCE_DATA_CLASSES:
            raise _resource_limit(
                "run_allowlisted provenance",
                "resource data-class count",
                MAX_RESOURCE_DATA_CLASSES,
            )

        process_resource = _process_resource(command)
        cwd_resource = _workspace_resource(self.config.resource_root, cwd[1])
        uses: list[ResourceUse] = [
            ResourceUse(
                authority_action="process.exec",
                access_mode=ResourceAccessMode.EXECUTE,
                canonical_resource=process_resource,
                effect_domain="process",
                data_classes=inherited_data_classes,
                purpose="execute_admitted_logical_command",
                provenance_ids=provenance_ids,
                use_kind=ResourceUseKind.PROCESS_EXECUTION,
                destination_external=False,
            ),
            ResourceUse(
                authority_action="fs.read",
                access_mode=ResourceAccessMode.READ,
                canonical_resource=cwd_resource,
                effect_domain="filesystem",
                data_classes=inherited_data_classes,
                purpose="enter_declared_staged_working_directory",
                provenance_ids=provenance_ids,
                use_kind=ResourceUseKind.PRECONDITION_READ,
                destination_external=False,
            ),
        ]
        semantic_arguments = [
            _semantic_argument(
                "argv",
                process_resource,
                canonical_json_bytes(arguments.argv),
                provenance_ids,
                "application/vnd.agentkernel.process.argv+json",
            ),
            _semantic_argument(
                "cwd",
                cwd_resource,
                cwd[1].encode("utf-8", errors="strict"),
                provenance_ids,
                "text/plain;charset=utf-8",
            ),
            _semantic_argument(
                "fixed_environment",
                process_resource,
                canonical_json_bytes(
                    {"fixed_environment_digest": command.fixed_environment_digest}
                ),
                (),
                "application/vnd.agentkernel.process.fixed-environment-reference+json",
            ),
        ]
        for _original, portable in canonical_reads:
            resource = _workspace_resource(self.config.resource_root, portable)
            uses.append(
                ResourceUse(
                    authority_action="fs.read",
                    access_mode=ResourceAccessMode.READ,
                    canonical_resource=resource,
                    effect_domain="filesystem",
                    data_classes=inherited_data_classes,
                    purpose="supply_declared_process_input",
                    provenance_ids=provenance_ids,
                    use_kind=ResourceUseKind.PRECONDITION_READ,
                    destination_external=False,
                )
            )
            semantic_arguments.append(
                _semantic_argument(
                    "workspace_reads",
                    resource,
                    portable.encode("utf-8", errors="strict"),
                    provenance_ids,
                    "text/plain;charset=utf-8",
                )
            )
        for _original, portable in canonical_writes:
            resource = _workspace_resource(self.config.resource_root, portable)
            uses.extend(
                (
                    ResourceUse(
                        authority_action="fs.write",
                        access_mode=ResourceAccessMode.WRITE,
                        canonical_resource=resource,
                        effect_domain="filesystem",
                        data_classes=inherited_data_classes,
                        purpose="apply_declared_staged_process_output",
                        provenance_ids=provenance_ids,
                        use_kind=ResourceUseKind.AUTHORITATIVE_EFFECT,
                        destination_external=False,
                    ),
                    ResourceUse(
                        authority_action="fs.read",
                        access_mode=ResourceAccessMode.READ,
                        canonical_resource=resource,
                        effect_domain="filesystem",
                        data_classes=inherited_data_classes,
                        purpose="verify_declared_process_output",
                        provenance_ids=provenance_ids,
                        use_kind=ResourceUseKind.VERIFIER_READ,
                        destination_external=False,
                    ),
                )
            )
            semantic_arguments.append(
                _semantic_argument(
                    "workspace_writes",
                    resource,
                    portable.encode("utf-8", errors="strict"),
                    provenance_ids,
                    "text/plain;charset=utf-8",
                )
            )

        if len(uses) > self.manifest.max_resources:
            raise _resource_limit(
                "run_allowlisted expansion",
                "resource-use count",
                self.manifest.max_resources,
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

    def _validate_bindings(
        self,
        proposal: ActionProposal,
        context: AuthenticatedActionContext,
        operation: AdmittedOperation,
        provenance: tuple[NormalizedProvenance, ...],
    ) -> None:
        try:
            validated_config = ProcessNormalizerConfig.model_validate(
                self.config.model_dump(mode="python")
            )
        except (AttributeError, TypeError, ValidationError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Process normalizer configuration failed strict revalidation",
            ) from error
        provenance_ids = tuple(binding.provenance_id for binding in provenance)
        if (
            validated_config != self.config
            or self.manifest != PROCESS_RUN_ALLOWLISTED_NORMALIZER_MANIFEST
            or proposal.adapter != "process"
            or proposal.operation != "run_allowlisted"
            or proposal.adapter != operation.adapter
            or proposal.adapter_version != operation.adapter_version
            or proposal.goal_id != context.goal_id
            or proposal.agent_id != context.agent_id
            or operation.operation != proposal.operation
            or operation.effect_domains != ("filesystem", "process")
            or operation.normalizer_manifest != self.manifest
            or operation.configuration_digest != self.configuration_digest
            or context.configuration_digest != self.configuration_digest
            or len(set(proposal.provenance_ids)) != len(proposal.provenance_ids)
            or tuple(sorted(proposal.provenance_ids)) != provenance_ids
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "run_allowlisted proposal, context, provenance, schema, or admission mismatch",
            )

    @staticmethod
    def _validate_command_arguments(
        arguments: RunAllowlistedArguments,
        command: ProcessCommandDefinition,
    ) -> None:
        if len(arguments.argv) > command.max_argv_items:
            raise _resource_limit("run_allowlisted argv", "item count", command.max_argv_items)
        argv_bytes = 0
        for value in arguments.argv:
            argv_bytes += _validate_security_text(
                value,
                subject="run_allowlisted argv item",
                max_bytes=command.max_argv_item_bytes,
                allow_empty=True,
            )
            if argv_bytes > command.max_argv_bytes:
                raise _resource_limit(
                    "run_allowlisted argv",
                    "aggregate UTF-8 bytes",
                    command.max_argv_bytes,
                )

        if arguments.env:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "run_allowlisted does not accept proposal-controlled environment entries",
            )

        if arguments.workspace_reads and not command.allow_workspace_reads:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "The command definition does not admit workspace reads",
            )
        if arguments.workspace_writes and not command.allow_workspace_writes:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "The command definition does not admit workspace writes",
            )
        if len(arguments.workspace_reads) > command.max_workspace_reads:
            raise _resource_limit(
                "run_allowlisted workspace reads",
                "path count",
                command.max_workspace_reads,
            )
        if len(arguments.workspace_writes) > command.max_workspace_writes:
            raise _resource_limit(
                "run_allowlisted workspace writes",
                "path count",
                command.max_workspace_writes,
            )


def _semantic_argument(
    name: str,
    resource: str,
    payload: bytes,
    provenance_ids: tuple[str, ...],
    media_type: str,
) -> SemanticArgument:
    return SemanticArgument(
        argument_name=name,
        resource=resource,
        digest=sha256_digest(payload),
        size_bytes=len(payload),
        media_type=media_type,
        provenance_ids=provenance_ids,
    )
