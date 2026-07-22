"""Immutable public and durable AgentKernel data contracts."""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from enum import StrEnum
from ipaddress import ip_address
from typing import Annotated, Literal, Self
from urllib.parse import SplitResult, quote, unquote_to_bytes, urlsplit

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)

from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import (
    ActionState,
    IntendedOutcome,
    ProvenanceTrust,
    ResourceAccessMode,
    ResourceUseKind,
    RiskClass,
    TransactionState,
    VerificationStatus,
)

ApiVersion = Literal["agentkernel.io/v1alpha1"]
SchemaVersion = Literal["1.0"]
NonEmptyStr = Annotated[str, StringConstraints(min_length=1, max_length=512)]
Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,255}$")]
Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
_CANONICAL_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*$")
_FS_AUTHORITY = re.compile(r"^[a-z][a-z0-9.-]{0,127}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HEX_DIGITS = frozenset("0123456789ABCDEFabcdef")
_UNRESERVED_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_WINDOWS_INVALID_CHARACTERS = frozenset('<>"|?*')
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CLOCK$", "CON", "CONIN$", "CONOUT$", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
    | {"COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"}
)
_MAX_RESOURCE_USES = 4096
_MAX_SEMANTIC_ARGUMENTS = 4096
_MAX_PROVENANCE_BINDINGS = 256
MAX_RESOURCE_DATA_CLASSES = 64
MAX_CANONICAL_RESOURCE_CHARACTERS = 8192


def _validate_percent_encoding(value: str) -> None:
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if index + 2 >= len(value) or any(
            character not in _HEX_DIGITS for character in value[index + 1 : index + 3]
        ):
            raise ValueError("Canonical resource URI contains an invalid percent escape")
        escape = value[index + 1 : index + 3]
        if escape != escape.upper():
            raise ValueError("Canonical resource URI percent escapes must use uppercase hex")
        if int(escape, 16) in _UNRESERVED_BYTES:
            raise ValueError("Canonical resource URI must not encode an unreserved character")
        index += 3


def _validate_fs_uri_path(path: str) -> None:
    if not path:
        return
    if not path.startswith("/") or path.endswith("/") or "//" in path:
        raise ValueError("Canonical filesystem URI path is not in canonical form")
    segments = path.removeprefix("/").split("/")
    for index, encoded_segment in enumerate(segments):
        if encoded_segment == "**" and index == len(segments) - 1:
            continue
        try:
            decoded_segment = unquote_to_bytes(encoded_segment).decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise ValueError("Canonical filesystem URI path is not valid UTF-8") from error
        if (
            not decoded_segment
            or decoded_segment in {".", ".."}
            or "/" in decoded_segment
            or "\\" in decoded_segment
            or ":" in decoded_segment
            or any(ord(character) < 32 or ord(character) == 127 for character in decoded_segment)
            or any(character in _WINDOWS_INVALID_CHARACTERS for character in decoded_segment)
            or unicodedata.normalize("NFC", decoded_segment) != decoded_segment
        ):
            raise ValueError("Canonical filesystem URI path contains an alias")
        reserved_stem = decoded_segment.split(".", 1)[0].rstrip(" .").upper()
        if decoded_segment.endswith((" ", ".")) or reserved_stem in _WINDOWS_RESERVED_NAMES:
            raise ValueError("Canonical filesystem URI path contains an OS-reserved alias")
        if (
            quote(decoded_segment, safe="-._~", encoding="utf-8", errors="strict")
            != encoded_segment
        ):
            raise ValueError("Canonical filesystem URI path is not safely percent-encoded")


def _canonical_network_authority(parsed: SplitResult) -> str:
    hostname = parsed.hostname
    netloc = parsed.netloc
    username = parsed.username
    password = parsed.password
    if (
        not isinstance(hostname, str)
        or not hostname
        or username is not None
        or password is not None
    ):
        raise ValueError("Canonical resource URI has an invalid or credential-bearing authority")
    if hostname != hostname.lower() or hostname.endswith("."):
        raise ValueError("Canonical resource URI hostname must be lowercase without a trailing dot")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Canonical resource URI has an invalid port") from error

    if ":" in hostname:
        try:
            address = ip_address(hostname)
        except ValueError as error:
            raise ValueError("Canonical resource URI has an invalid IP address") from error
        if address.version != 6 or hostname != address.compressed:
            raise ValueError("Canonical resource URI IPv6 address is not compressed")
        rendered_host = f"[{hostname}]"
    else:
        labels = hostname.split(".")
        if not all(_DNS_LABEL.fullmatch(label) for label in labels):
            raise ValueError("Canonical resource URI has an invalid DNS or IPv4 authority")
        if all(label.isdigit() for label in labels):
            try:
                address = ip_address(hostname)
            except ValueError as error:
                raise ValueError("Canonical resource URI has an invalid IPv4 address") from error
            if address.version != 4 or hostname != str(address):
                raise ValueError("Canonical resource URI IPv4 address is not canonical")
        rendered_host = hostname

    rendered = rendered_host if port is None else f"{rendered_host}:{port}"
    if netloc != rendered:
        raise ValueError("Canonical resource URI authority is not in canonical form")
    return rendered


def _validate_generic_uri_path(path: str) -> None:
    if not path or not path.startswith("/") or (path != "/" and path.endswith("/")) or "//" in path:
        raise ValueError("Canonical resource URI path is not in canonical form")
    if path == "/":
        return
    for encoded_segment in path.removeprefix("/").split("/"):
        try:
            decoded_segment = unquote_to_bytes(encoded_segment).decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise ValueError("Canonical resource URI path is not valid UTF-8") from error
        if (
            not decoded_segment
            or decoded_segment in {".", ".."}
            or "/" in decoded_segment
            or "\\" in decoded_segment
            or any(ord(character) < 32 or ord(character) == 127 for character in decoded_segment)
            or unicodedata.normalize("NFC", decoded_segment) != decoded_segment
        ):
            raise ValueError("Canonical resource URI path contains an alias")
        if (
            quote(decoded_segment, safe="-._~", encoding="utf-8", errors="strict")
            != encoded_segment
        ):
            raise ValueError("Canonical resource URI path is not safely percent-encoded")


def _canonical_resource_uri(value: str) -> str:
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("Canonical resource URI must be Unicode NFC")
    try:
        value.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError("Canonical resource URI must percent-encode non-ASCII text") from error
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("Canonical resource URI contains a control character")
    if "\\" in value or any(character.isspace() for character in value):
        raise ValueError("Canonical resource URI contains a non-canonical character")
    _validate_percent_encoding(value)
    parsed = urlsplit(value)
    rendered_scheme = value.split(":", 1)[0]
    if (
        not parsed.scheme
        or rendered_scheme != parsed.scheme
        or not _CANONICAL_URI_SCHEME.fullmatch(parsed.scheme)
    ):
        raise ValueError("Canonical resource URI requires a lowercase scheme")
    if not parsed.netloc:
        raise ValueError("Canonical resource URI requires an authority")
    if parsed.scheme == "fs":
        if parsed.query or parsed.fragment or not _FS_AUTHORITY.fullmatch(parsed.netloc):
            raise ValueError("Canonical filesystem URI has an invalid authority or suffix")
        _validate_fs_uri_path(parsed.path)
    else:
        if parsed.query or parsed.fragment:
            raise ValueError("Canonical resource URI cannot contain a query or fragment")
        _canonical_network_authority(parsed)
        if (parsed.scheme, parsed.port) in {("http", 80), ("https", 443)}:
            raise ValueError("Canonical resource URI must omit its scheme's default port")
        _validate_generic_uri_path(parsed.path)
    return value


CanonicalResource = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_CANONICAL_RESOURCE_CHARACTERS),
    AfterValidator(_canonical_resource_uri),
]


class StrictModel(BaseModel):
    """Shared trust-boundary behavior for every serialized contract."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
    )


def _require_sorted_unique_strings(
    values: tuple[str, ...],
    *,
    field_name: str,
) -> tuple[str, ...]:
    try:
        for value in values:
            value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field_name} must contain only valid UTF-8 strings") from error
    if any(unicodedata.normalize("NFC", value) != value for value in values):
        raise ValueError(f"{field_name} must contain only Unicode NFC strings")
    if len(set(values)) != len(values) or values != tuple(sorted(values)):
        raise ValueError(f"{field_name} must be sorted and unique")
    return values


class AuthenticatedActionContext(StrictModel):
    """Identity and deployment facts authenticated outside untrusted proposal data."""

    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    tenant_id: Identifier
    principal_id: Identifier
    goal_id: Identifier
    run_id: Identifier
    trace_id: Identifier
    actor_id: Identifier
    on_behalf_of: Identifier
    agent_id: Identifier
    configuration_digest: Digest


class ResourceUse(StrictModel):
    """One independently authorizable use of one canonical resource."""

    authority_action: NonEmptyStr
    access_mode: ResourceAccessMode
    canonical_resource: CanonicalResource
    effect_domain: NonEmptyStr
    data_classes: Annotated[
        tuple[NonEmptyStr, ...], Field(max_length=MAX_RESOURCE_DATA_CLASSES)
    ] = ()
    purpose: NonEmptyStr
    provenance_ids: Annotated[
        tuple[Identifier, ...], Field(max_length=_MAX_PROVENANCE_BINDINGS)
    ] = ()
    use_kind: ResourceUseKind
    destination_external: bool

    @field_validator("data_classes", "provenance_ids")
    @classmethod
    def _canonical_string_tuple(cls, values: tuple[str, ...], info: object) -> tuple[str, ...]:
        field_name = getattr(info, "field_name", "tuple")
        return _require_sorted_unique_strings(values, field_name=field_name)

    @field_validator("authority_action", "effect_domain", "purpose")
    @classmethod
    def _canonical_text(cls, value: str) -> str:
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError("Resource-use text must be Unicode NFC")
        return value

    @model_validator(mode="after")
    def _scoped_resources_are_read_only_observation_boundaries(self) -> Self:
        if self.canonical_resource.endswith("/**") and (
            self.access_mode is not ResourceAccessMode.READ
            or self.use_kind
            not in {ResourceUseKind.PRECONDITION_READ, ResourceUseKind.VERIFIER_READ}
            or self.destination_external
        ):
            raise ValueError(
                "A terminal resource scope is allowed only for local precondition or verifier reads"
            )
        return self

    def sort_key(self) -> tuple[object, ...]:
        """Return the stable order used by normalized action projections."""

        return (
            self.canonical_resource,
            self.authority_action,
            self.access_mode.value,
            self.effect_domain,
            self.use_kind.value,
            self.purpose,
            self.destination_external,
            self.data_classes,
            self.provenance_ids,
        )


class SemanticArgument(StrictModel):
    """Non-secret metadata binding one semantic argument value to its artifact digest."""

    argument_name: NonEmptyStr
    resource: CanonicalResource
    digest: Digest
    size_bytes: Annotated[int, Field(ge=0, le=1_073_741_824)]
    media_type: NonEmptyStr
    provenance_ids: Annotated[
        tuple[Identifier, ...], Field(max_length=_MAX_PROVENANCE_BINDINGS)
    ] = ()

    @field_validator("provenance_ids")
    @classmethod
    def _canonical_provenance_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _require_sorted_unique_strings(values, field_name="provenance_ids")

    @field_validator("argument_name", "media_type")
    @classmethod
    def _canonical_text(cls, value: str) -> str:
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError("Semantic argument metadata must be Unicode NFC")
        return value

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.argument_name,
            self.resource,
            self.digest,
            self.size_bytes,
            self.media_type,
            self.provenance_ids,
        )


class NormalizedProvenance(StrictModel):
    """Trusted provenance facts and an integrity binding to their complete source record."""

    provenance_id: Identifier
    trust: ProvenanceTrust
    data_classes: Annotated[
        tuple[NonEmptyStr, ...], Field(max_length=MAX_RESOURCE_DATA_CLASSES)
    ] = ()
    record_digest: Digest
    integrity_ref: Digest | None = None

    @field_validator("data_classes")
    @classmethod
    def _canonical_data_classes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _require_sorted_unique_strings(values, field_name="data_classes")


class _NormalizedIntentFields(StrictModel):
    tenant_id: Identifier
    principal_id: Identifier
    goal_id: Identifier
    run_id: Identifier
    actor_id: Identifier
    on_behalf_of: Identifier
    agent_id: Identifier
    adapter: Identifier
    adapter_version: NonEmptyStr
    adapter_manifest_digest: Digest
    operation: NonEmptyStr
    normalizer_implementation: Identifier
    normalizer_version: NonEmptyStr
    normalizer_digest: Digest
    operation_schema_ref: NonEmptyStr
    operation_schema_digest: Digest
    configuration_digest: Digest
    risk_floor: RiskClass
    effect_domains: Annotated[
        tuple[NonEmptyStr, ...], Field(min_length=1, max_length=MAX_RESOURCE_DATA_CLASSES)
    ]
    resource_uses: Annotated[
        tuple[ResourceUse, ...], Field(min_length=1, max_length=_MAX_RESOURCE_USES)
    ]
    semantic_arguments: Annotated[
        tuple[SemanticArgument, ...], Field(max_length=_MAX_SEMANTIC_ARGUMENTS)
    ] = ()
    provenance: Annotated[
        tuple[NormalizedProvenance, ...], Field(max_length=_MAX_PROVENANCE_BINDINGS)
    ] = ()

    @field_validator(
        "adapter_version",
        "operation",
        "normalizer_version",
        "operation_schema_ref",
    )
    @classmethod
    def _canonical_identity_text(cls, value: str) -> str:
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError("Normalized intent text must be Unicode NFC")
        return value

    @field_validator("effect_domains")
    @classmethod
    def _canonical_effect_domains(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _require_sorted_unique_strings(values, field_name="effect_domains")

    @field_validator("resource_uses")
    @classmethod
    def _canonical_resource_uses(cls, values: tuple[ResourceUse, ...]) -> tuple[ResourceUse, ...]:
        keys = tuple(value.sort_key() for value in values)
        if len(set(keys)) != len(keys) or keys != tuple(sorted(keys)):
            raise ValueError("resource_uses must be sorted and unique")
        return values

    @field_validator("semantic_arguments")
    @classmethod
    def _canonical_semantic_arguments(
        cls, values: tuple[SemanticArgument, ...]
    ) -> tuple[SemanticArgument, ...]:
        keys = tuple(value.sort_key() for value in values)
        identities = tuple((value.argument_name, value.resource) for value in values)
        if (
            len(set(keys)) != len(keys)
            or len(set(identities)) != len(identities)
            or keys != tuple(sorted(keys))
        ):
            raise ValueError("semantic_arguments must be sorted and unique")
        return values

    @field_validator("provenance")
    @classmethod
    def _canonical_provenance(
        cls, values: tuple[NormalizedProvenance, ...]
    ) -> tuple[NormalizedProvenance, ...]:
        ids = tuple(value.provenance_id for value in values)
        if len(set(ids)) != len(ids) or ids != tuple(sorted(ids)):
            raise ValueError("provenance must be sorted and unique by provenance_id")
        return values

    @model_validator(mode="after")
    def _resource_facts_are_declared(self) -> Self:
        effect_domains = set(self.effect_domains)
        provenance_by_id = {binding.provenance_id: binding for binding in self.provenance}
        provenance_ids = set(provenance_by_id)
        resource_ids = {use.canonical_resource for use in self.resource_uses}
        if any(use.effect_domain not in effect_domains for use in self.resource_uses):
            raise ValueError("Every resource use must name a declared effect domain")
        if any(not set(use.provenance_ids) <= provenance_ids for use in self.resource_uses):
            raise ValueError("Resource use references unknown provenance")
        for use in self.resource_uses:
            inherited_data_classes = {
                data_class
                for provenance_id in use.provenance_ids
                for data_class in provenance_by_id[provenance_id].data_classes
            }
            if not inherited_data_classes <= set(use.data_classes):
                raise ValueError(
                    "Resource use must declare every data class inherited from its provenance"
                )
        if any(
            not set(argument.provenance_ids) <= provenance_ids
            for argument in self.semantic_arguments
        ):
            raise ValueError("Semantic argument references unknown provenance")
        if any(argument.resource not in resource_ids for argument in self.semantic_arguments):
            raise ValueError("Semantic argument references an undeclared resource")
        argument_provenance_by_resource: dict[str, set[str]] = {}
        for argument in self.semantic_arguments:
            argument_provenance_by_resource.setdefault(argument.resource, set()).update(
                argument.provenance_ids
            )
        if any(
            not argument_provenance_by_resource.get(use.canonical_resource, set())
            <= set(use.provenance_ids)
            for use in self.resource_uses
            if use.canonical_resource in argument_provenance_by_resource
        ):
            raise ValueError(
                "Every resource use must inherit provenance from semantic arguments "
                "for that resource"
            )
        return self


class NormalizedIntentProjection(_NormalizedIntentFields):
    """Versioned semantic identity material used to calculate ``intent_hash``."""

    intent_profile: Literal["agentkernel.intent/v1alpha1"] = "agentkernel.intent/v1alpha1"


class NormalizedAction(_NormalizedIntentFields):
    """Immutable normalized action plus non-semantic request/trace transport facts."""

    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    transaction_id: Identifier
    trace_id: Identifier
    deadline: AwareDatetime
    idempotency_key: NonEmptyStr | None = None
    intent_hash: Digest

    @field_validator("idempotency_key")
    @classmethod
    def _canonical_idempotency_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise ValueError("Normalized action idempotency key must be valid UTF-8") from error
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError("Normalized action idempotency key must use Unicode NFC")
        return value

    def intent_projection(self) -> NormalizedIntentProjection:
        """Project only stable semantic identity fields using the pinned profile."""

        return NormalizedIntentProjection(
            tenant_id=self.tenant_id,
            principal_id=self.principal_id,
            goal_id=self.goal_id,
            run_id=self.run_id,
            actor_id=self.actor_id,
            on_behalf_of=self.on_behalf_of,
            agent_id=self.agent_id,
            adapter=self.adapter,
            adapter_version=self.adapter_version,
            adapter_manifest_digest=self.adapter_manifest_digest,
            operation=self.operation,
            normalizer_implementation=self.normalizer_implementation,
            normalizer_version=self.normalizer_version,
            normalizer_digest=self.normalizer_digest,
            operation_schema_ref=self.operation_schema_ref,
            operation_schema_digest=self.operation_schema_digest,
            configuration_digest=self.configuration_digest,
            risk_floor=self.risk_floor,
            effect_domains=self.effect_domains,
            resource_uses=self.resource_uses,
            semantic_arguments=self.semantic_arguments,
            provenance=self.provenance,
        )

    @model_validator(mode="after")
    def _intent_hash_matches_projection(self) -> Self:
        if self.intent_hash != canonical_digest(self.intent_projection()):
            raise ValueError("NormalizedAction has a mismatched intent_hash")
        return self

    @classmethod
    def create(
        cls,
        *,
        context: AuthenticatedActionContext,
        transaction_id: Identifier,
        deadline: datetime,
        idempotency_key: NonEmptyStr | None,
        adapter: Identifier,
        adapter_version: NonEmptyStr,
        adapter_manifest_digest: Digest,
        operation: NonEmptyStr,
        normalizer_implementation: Identifier,
        normalizer_version: NonEmptyStr,
        normalizer_digest: Digest,
        operation_schema_ref: NonEmptyStr,
        operation_schema_digest: Digest,
        risk_floor: RiskClass,
        effect_domains: tuple[NonEmptyStr, ...],
        resource_uses: tuple[ResourceUse, ...],
        semantic_arguments: tuple[SemanticArgument, ...] = (),
        provenance: tuple[NormalizedProvenance, ...] = (),
    ) -> Self:
        """Build and hash one validated action; callers never supply ``intent_hash``."""

        projection = NormalizedIntentProjection(
            tenant_id=context.tenant_id,
            principal_id=context.principal_id,
            goal_id=context.goal_id,
            run_id=context.run_id,
            actor_id=context.actor_id,
            on_behalf_of=context.on_behalf_of,
            agent_id=context.agent_id,
            adapter=adapter,
            adapter_version=adapter_version,
            adapter_manifest_digest=adapter_manifest_digest,
            operation=operation,
            normalizer_implementation=normalizer_implementation,
            normalizer_version=normalizer_version,
            normalizer_digest=normalizer_digest,
            operation_schema_ref=operation_schema_ref,
            operation_schema_digest=operation_schema_digest,
            configuration_digest=context.configuration_digest,
            risk_floor=risk_floor,
            effect_domains=effect_domains,
            resource_uses=resource_uses,
            semantic_arguments=semantic_arguments,
            provenance=provenance,
        )
        return cls(
            **projection.model_dump(mode="python", exclude={"intent_profile"}),
            transaction_id=transaction_id,
            trace_id=context.trace_id,
            deadline=deadline,
            idempotency_key=idempotency_key,
            intent_hash=canonical_digest(projection),
        )


create_normalized_action = NormalizedAction.create


class GoalRecord(StrictModel):
    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    goal_id: Identifier
    principal_id: Identifier
    text: Annotated[str, StringConstraints(min_length=1, max_length=32_768)]
    resource_scope: tuple[NonEmptyStr, ...] = ()
    created_at: AwareDatetime
    deadline: AwareDatetime | None = None
    budget: dict[str, Annotated[int, Field(ge=0)]] = Field(default_factory=dict)


class CapabilityGrant(StrictModel):
    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    capability_id: Identifier
    token_version: Annotated[int, Field(ge=1)] = 1
    key_id: Identifier
    issuer: Identifier
    subject: Identifier
    audience: Identifier
    goal_id: Identifier
    run_id: Identifier
    actions: tuple[NonEmptyStr, ...]
    resources: tuple[NonEmptyStr, ...]
    conditions: dict[str, JsonValue] = Field(default_factory=dict)
    data_classes: tuple[NonEmptyStr, ...] = ()
    issued_at: AwareDatetime
    not_before: AwareDatetime
    expires_at: AwareDatetime
    max_uses: Annotated[int, Field(ge=1)] = 1
    delegation_depth_remaining: Annotated[int, Field(ge=0)] = 0
    parent_capability: Identifier | None = None
    nonce: NonEmptyStr
    signature: NonEmptyStr


class ProvenanceRecord(StrictModel):
    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    provenance_id: Identifier
    source: NonEmptyStr
    acquisition_step: NonEmptyStr
    trust: ProvenanceTrust
    data_classes: Annotated[
        tuple[NonEmptyStr, ...], Field(max_length=MAX_RESOURCE_DATA_CLASSES)
    ] = ()
    parent_ids: Annotated[tuple[Identifier, ...], Field(max_length=_MAX_PROVENANCE_BINDINGS)] = ()
    transformations: Annotated[
        tuple[NonEmptyStr, ...], Field(max_length=_MAX_PROVENANCE_BINDINGS)
    ] = ()
    integrity_ref: Digest | None = None

    @field_validator("data_classes", "parent_ids")
    @classmethod
    def _canonical_provenance_sets(
        cls,
        values: tuple[str, ...],
        info: object,
    ) -> tuple[str, ...]:
        return _require_sorted_unique_strings(
            values,
            field_name=str(getattr(info, "field_name", "provenance set")),
        )

    @field_validator("source", "acquisition_step")
    @classmethod
    def _canonical_provenance_text(cls, value: str) -> str:
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise ValueError("Provenance text must be valid UTF-8") from error
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError("Provenance text must use Unicode NFC")
        return value

    @field_validator("transformations")
    @classmethod
    def _canonical_transformation_sequence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise ValueError("Provenance transformations must be valid UTF-8") from error
            if unicodedata.normalize("NFC", value) != value:
                raise ValueError("Provenance transformations must use Unicode NFC")
        return values


class ActionProposal(StrictModel):
    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    goal_id: Identifier
    transaction_id: Identifier
    agent_id: Identifier
    adapter: Identifier
    adapter_version: NonEmptyStr
    operation: NonEmptyStr
    arguments: Annotated[dict[str, JsonValue], Field(max_length=4_096)]
    provenance_ids: Annotated[tuple[Identifier, ...], Field(max_length=256)] = ()
    capability_refs: Annotated[tuple[Identifier, ...], Field(max_length=256)] = ()
    deadline: AwareDatetime
    idempotency_key: NonEmptyStr | None = None

    @field_validator("adapter_version", "operation", "idempotency_key")
    @classmethod
    def _canonical_semantic_text(cls, value: str | None, info: object) -> str | None:
        if value is None:
            return None
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise ValueError("Action proposal semantic text must be valid UTF-8") from error
        if unicodedata.normalize("NFC", value) != value:
            field_name = getattr(info, "field_name", "semantic text")
            raise ValueError(f"Action proposal {field_name} must use Unicode NFC")
        return value


class TransactionRecord(StrictModel):
    schema_version: SchemaVersion = "1.0"
    transaction_id: Identifier
    goal_id: Identifier
    state: TransactionState = TransactionState.NEW
    version: Annotated[int, Field(ge=0)] = 0
    intent_hash: Digest | None = None
    intended_outcome: IntendedOutcome | None = None
    policy_digest: Digest | None = None
    capability_digest: Digest | None = None
    adapter_manifest_digest: Digest | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime
    reason_code: NonEmptyStr | None = None
    supersedes_transaction_id: Identifier | None = None


class ActionExecutionRecord(StrictModel):
    schema_version: SchemaVersion = "1.0"
    transaction_id: Identifier
    action_id: Identifier
    ordinal: Annotated[int, Field(ge=0)]
    dependency_ordinals: tuple[Annotated[int, Field(ge=0)], ...] = ()
    intent_hash: Digest
    adapter: Identifier
    adapter_version: NonEmptyStr
    adapter_digest: Digest
    risk_class: RiskClass
    state: ActionState = ActionState.PENDING
    version: Annotated[int, Field(ge=0)] = 0
    idempotency_key: NonEmptyStr
    target_version_guard: NonEmptyStr | None = None
    staged_receipt_ref: Digest | None = None
    effect_receipt_ref: Digest | None = None
    recovery_receipt_ref: Digest | None = None
    reason_code: NonEmptyStr | None = None


class IntentRecord(StrictModel):
    schema_version: SchemaVersion = "1.0"
    intent_hash: Digest
    transaction_id: Identifier
    action_id: Identifier | None = None
    idempotency_key: NonEmptyStr
    dispatched: bool = False
    outcome_receipt_ref: Digest | None = None
    created_at: AwareDatetime


class VerificationReport(StrictModel):
    schema_version: SchemaVersion = "1.0"
    status: VerificationStatus
    verifier: Identifier
    summary: Annotated[str, StringConstraints(max_length=4096)] = ""
    evidence_refs: tuple[Digest, ...] = ()


class EffectReceipt(StrictModel):
    schema_version: SchemaVersion = "1.0"
    receipt_id: Identifier
    transaction_id: Identifier
    adapter: Identifier
    operation: NonEmptyStr
    intent_hash: Digest
    target_version_before: NonEmptyStr
    target_version_after: NonEmptyStr
    effect_digest: Digest
    created_at: AwareDatetime


class RecoveryReport(StrictModel):
    schema_version: SchemaVersion = "1.0"
    status: VerificationStatus
    strategy: NonEmptyStr
    restored_state_digest: Digest | None = None
    residual_effects: tuple[NonEmptyStr, ...] = ()
    evidence_refs: tuple[Digest, ...] = ()


class Artifact(StrictModel):
    schema_version: SchemaVersion = "1.0"
    digest: Digest
    media_type: NonEmptyStr
    size_bytes: Annotated[int, Field(ge=0)]
    created_at: AwareDatetime
    storage_ref: NonEmptyStr


class EventEnvelope(StrictModel):
    schema_version: SchemaVersion = "1.0"
    event_id: Identifier
    run_id: Identifier
    transaction_id: Identifier | None = None
    sequence: Annotated[int, Field(ge=0)]
    logical_time: Annotated[int, Field(ge=0)]
    wall_time: AwareDatetime
    event_type: NonEmptyStr
    actor: Identifier
    on_behalf_of: Identifier
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    artifact_refs: tuple[Digest, ...] = ()
    previous_event_hash: Digest | None = None
    event_hash: Digest
    signature_ref: NonEmptyStr | None = None


class PolicyDefault(StrEnum):
    DENY = "deny"
    ABSTAIN = "abstain"


class PolicyEffect(StrEnum):
    GRANT = "grant"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_SHADOW = "require_shadow"


class PolicyRule(StrictModel):
    rule_id: Identifier
    effect: PolicyEffect
    modes: Annotated[tuple[NonEmptyStr, ...], Field(max_length=16)] = ()
    when: Annotated[dict[str, JsonValue], Field(min_length=1, max_length=1)]


class PolicyBundle(StrictModel):
    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    kind: Literal["PolicyBundle"] = "PolicyBundle"
    name: Identifier
    version: NonEmptyStr
    default: PolicyDefault = PolicyDefault.DENY
    rules: Annotated[tuple[PolicyRule, ...], Field(max_length=2_048)]

    @field_validator("version")
    @classmethod
    def _canonical_version(cls, value: str) -> str:
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise ValueError("Policy bundle version must be valid UTF-8") from error
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError("Policy bundle version must use Unicode NFC")
        return value


class BenchmarkTask(StrictModel):
    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    kind: Literal["BenchmarkTask"] = "BenchmarkTask"
    task_id: Identifier
    version: NonEmptyStr
    license: NonEmptyStr
    environment: dict[str, JsonValue]
    goal: Annotated[str, StringConstraints(min_length=1, max_length=32_768)]
    authority: dict[str, JsonValue]
    budgets: dict[str, Annotated[int, Field(ge=0)]]
    invariants: tuple[NonEmptyStr, ...]
    success: tuple[NonEmptyStr, ...]
    forbidden_actions: tuple[NonEmptyStr, ...] = ()
    labels: dict[str, NonEmptyStr] = Field(default_factory=dict)


def utc_now() -> datetime:
    """Provide an injectable-friendly default for application composition only."""

    return datetime.now().astimezone()
