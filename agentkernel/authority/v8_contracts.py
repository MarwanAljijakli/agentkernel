"""Canonical v8 authority-selection and bounded-input observation contracts.

This module is deliberately pure.  It defines content-bound selection material and the
closed canonical observations produced by the bounded authority-input gate, but performs
no provider, transport, storage, or evaluator work.
"""

from __future__ import annotations

import unicodedata
from enum import StrEnum
from typing import Annotated, Any, Literal, Self, cast

from pydantic import (
    BeforeValidator,
    ConfigDict,
    Field,
    GetCoreSchemaHandler,
    TypeAdapter,
    model_validator,
)
from pydantic.config import ExtraValues
from pydantic_core import CoreSchema, core_schema

from agentkernel.canonical import canonical_digest
from agentkernel.domain.models import (
    ApiVersion,
    Digest,
    Identifier,
    SchemaVersion,
    StrictModel,
    StrictNonNegativeInt,
    StrictPositiveInt,
)

MAX_SELECTED_ENDPOINT_GRANTS_V8 = 256
AUTHORITY_INPUT_BYTE_LIMIT_V8 = 8_388_608
AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8 = AUTHORITY_INPUT_BYTE_LIMIT_V8 + 1
_MINIMUM_COMPLETE_GZIP_WIRE_BYTES = 20

_IDENTIFIER_MAX_CHARACTERS = 256
_DIGEST_CHARACTERS = 71
_SHORT_CANONICAL_TEXT_MAX_CHARACTERS = 64
_RAW_FIELD_NAME_MAX_CHARACTERS = 64
_EMPTY_SHA256_DIGEST = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

_BoundedAuthorityInputLengthV8 = Annotated[
    StrictNonNegativeInt,
    Field(le=AUTHORITY_INPUT_BYTE_LIMIT_V8),
]
_PositiveBoundedAuthorityInputLengthV8 = Annotated[
    StrictPositiveInt,
    Field(le=AUTHORITY_INPUT_BYTE_LIMIT_V8),
]
_OverflowPrefixPositiveLengthV8 = Annotated[
    StrictPositiveInt,
    Field(le=AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8),
]
_OverflowPrefixNonNegativeLengthV8 = Annotated[
    StrictNonNegativeInt,
    Field(le=AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8),
]
_ConfiguredAuthorityInputLimitV8 = Annotated[
    StrictPositiveInt,
    Field(
        ge=AUTHORITY_INPUT_BYTE_LIMIT_V8,
        le=AUTHORITY_INPUT_BYTE_LIMIT_V8,
    ),
]
_FirstExcessObservedCountV8 = Annotated[
    StrictPositiveInt,
    Field(
        ge=AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8,
        le=AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8,
    ),
]


class _V8StrictModel(StrictModel):
    """StrictModel profile that also revalidates restored/embedded model instances."""

    model_config = ConfigDict(revalidate_instances="always")

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source_type: Any,
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Place exact-instance storage inspection outside Pydantic's model normalization."""

        schema = handler(source_type)

        def inspect_exact_instance(value: Any) -> Any:
            if type(value) is cls:
                return _exact_model_field_mapping(
                    value,
                    model_name=cls.__name__,
                    field_names=tuple(cls.model_fields),
                )
            return value

        return core_schema.no_info_before_validator_function(
            inspect_exact_instance,
            schema,
        )

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        """Inspect exact instance storage before Pydantic can normalize hidden state."""

        if type(obj) is cls:
            obj = _exact_model_field_mapping(
                obj,
                model_name=cls.__name__,
                field_names=tuple(cls.model_fields),
            )
        return super().model_validate(
            obj,
            strict=strict,
            extra=extra,
            from_attributes=from_attributes,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )


def _raw_model_mapping(
    value: object,
    *,
    model_name: str,
    allowed_fields: frozenset[str],
) -> dict[str, object]:
    """Accept only a bounded built-in mapping before Pydantic touches its values."""

    if type(value) is not dict:
        raise ValueError(f"{model_name} input must be a built-in dict")
    raw_mapping = cast("dict[object, object]", value)
    if len(raw_mapping) > len(allowed_fields):
        raise ValueError(f"{model_name} input has too many fields")
    for field_name in raw_mapping:
        if (
            type(field_name) is not str
            or len(field_name) > _RAW_FIELD_NAME_MAX_CHARACTERS
            or field_name not in allowed_fields
        ):
            raise ValueError(f"{model_name} input contains an unsupported field")
    return cast("dict[str, object]", raw_mapping)


def _exact_model_field_mapping(
    value: object,
    *,
    model_name: str,
    field_names: tuple[str, ...],
) -> dict[str, object]:
    """Project restored fields without a serializer that could erase poisoned subtypes."""

    expected_fields = frozenset(field_names)
    try:
        stored_fields = object.__getattribute__(value, "__dict__")
        fields_set = object.__getattribute__(value, "__pydantic_fields_set__")
        extra_fields = object.__getattribute__(value, "__pydantic_extra__")
        private_fields = object.__getattribute__(value, "__pydantic_private__")
    except AttributeError as error:
        raise ValueError(f"{model_name} has invalid model storage") from error
    if type(stored_fields) is not dict or len(stored_fields) != len(expected_fields):
        raise ValueError(f"{model_name} contains an unsupported stored field")
    for stored_field_name in stored_fields:
        if type(stored_field_name) is not str or stored_field_name not in expected_fields:
            raise ValueError(f"{model_name} contains an unsupported stored field")
    if (
        type(fields_set) is not set
        or len(fields_set) > len(expected_fields)
        or any(
            type(field_name) is not str or field_name not in expected_fields
            for field_name in fields_set
        )
        or extra_fields is not None
        or private_fields is not None
    ):
        raise ValueError(f"{model_name} contains unsupported model state")

    projected: dict[str, object] = {}
    for field_name in field_names:
        try:
            projected[field_name] = object.__getattribute__(value, field_name)
        except AttributeError as error:
            raise ValueError(f"{model_name} is missing a canonical field") from error
    return projected


def _preflight_text_field(
    raw_mapping: dict[str, object],
    field_name: str,
    *,
    max_characters: int,
) -> None:
    if field_name not in raw_mapping:
        return
    value = raw_mapping[field_name]
    if type(value) is not str:
        raise ValueError(f"{field_name} must be a built-in str")
    if len(value) > max_characters:
        raise ValueError(f"{field_name} exceeds its raw text bound")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field_name} must be valid UTF-8") from error
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{field_name} must use Unicode NFC")


def _preflight_literal_field(
    raw_mapping: dict[str, object],
    field_name: str,
    expected: str,
) -> None:
    if field_name not in raw_mapping:
        return
    _preflight_text_field(
        raw_mapping,
        field_name,
        max_characters=_SHORT_CANONICAL_TEXT_MAX_CHARACTERS,
    )
    if raw_mapping[field_name] != expected:
        raise ValueError(f"{field_name} has an unsupported value")


def _preflight_enum_field(
    raw_mapping: dict[str, object],
    field_name: str,
    enum_type: type[StrEnum],
) -> None:
    if field_name not in raw_mapping:
        return
    value = raw_mapping[field_name]
    if type(value) is enum_type:
        return
    if type(value) is not str:
        raise ValueError(f"{field_name} must be a built-in str or the exact enum type")
    if len(value) > _SHORT_CANONICAL_TEXT_MAX_CHARACTERS:
        raise ValueError(f"{field_name} exceeds its raw text bound")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field_name} must be valid UTF-8") from error


def _preflight_integer_field(raw_mapping: dict[str, object], field_name: str) -> None:
    if field_name in raw_mapping and type(raw_mapping[field_name]) is not int:
        raise ValueError(f"{field_name} must be an exact built-in int")


class SelectedEndpointGrantBindingV8(_V8StrictModel):
    """One explicitly selected endpoint bound to the exact admitted grant content."""

    capability_id: Identifier
    grant_digest: Digest

    @model_validator(mode="before")
    @classmethod
    def _preflight_raw_input(cls, value: object) -> object:
        if type(value) is cls:
            value = _exact_model_field_mapping(
                value,
                model_name=cls.__name__,
                field_names=("capability_id", "grant_digest"),
            )
        raw_mapping = _raw_model_mapping(
            value,
            model_name=cls.__name__,
            allowed_fields=frozenset({"capability_id", "grant_digest"}),
        )
        _preflight_text_field(
            raw_mapping,
            "capability_id",
            max_characters=_IDENTIFIER_MAX_CHARACTERS,
        )
        _preflight_text_field(
            raw_mapping,
            "grant_digest",
            max_characters=_DIGEST_CHARACTERS,
        )
        return raw_mapping


class IngressAuthoritySelectionOriginV8(_V8StrictModel):
    """Ingress selection provenance bound to both persisted request artifacts."""

    kind: Literal["INGRESS"] = "INGRESS"
    request_digest: Digest
    proposal_artifact_digest: Digest

    @model_validator(mode="before")
    @classmethod
    def _preflight_raw_input(cls, value: object) -> object:
        if type(value) is cls:
            value = _exact_model_field_mapping(
                value,
                model_name=cls.__name__,
                field_names=("kind", "request_digest", "proposal_artifact_digest"),
            )
        raw_mapping = _raw_model_mapping(
            value,
            model_name=cls.__name__,
            allowed_fields=frozenset({"kind", "request_digest", "proposal_artifact_digest"}),
        )
        _preflight_literal_field(raw_mapping, "kind", "INGRESS")
        _preflight_text_field(
            raw_mapping,
            "request_digest",
            max_characters=_DIGEST_CHARACTERS,
        )
        _preflight_text_field(
            raw_mapping,
            "proposal_artifact_digest",
            max_characters=_DIGEST_CHARACTERS,
        )
        return raw_mapping


class RecoveryAuthoritySelectionOriginV8(_V8StrictModel):
    """Recovery selection provenance bound to the new recovery action binding."""

    kind: Literal["RECOVERY"] = "RECOVERY"
    recovery_action_binding_digest: Digest

    @model_validator(mode="before")
    @classmethod
    def _preflight_raw_input(cls, value: object) -> object:
        if type(value) is cls:
            value = _exact_model_field_mapping(
                value,
                model_name=cls.__name__,
                field_names=("kind", "recovery_action_binding_digest"),
            )
        raw_mapping = _raw_model_mapping(
            value,
            model_name=cls.__name__,
            allowed_fields=frozenset({"kind", "recovery_action_binding_digest"}),
        )
        _preflight_literal_field(raw_mapping, "kind", "RECOVERY")
        _preflight_text_field(
            raw_mapping,
            "recovery_action_binding_digest",
            max_characters=_DIGEST_CHARACTERS,
        )
        return raw_mapping


def _preflight_authority_selection_origin_union(value: object) -> dict[str, object]:
    """Inspect origin material before the tagged union reads its discriminator."""

    if type(value) is IngressAuthoritySelectionOriginV8:
        value = _exact_model_field_mapping(
            value,
            model_name=IngressAuthoritySelectionOriginV8.__name__,
            field_names=("kind", "request_digest", "proposal_artifact_digest"),
        )
    elif type(value) is RecoveryAuthoritySelectionOriginV8:
        value = _exact_model_field_mapping(
            value,
            model_name=RecoveryAuthoritySelectionOriginV8.__name__,
            field_names=("kind", "recovery_action_binding_digest"),
        )
    raw_mapping = _raw_model_mapping(
        value,
        model_name="AuthoritySelectionOriginV8",
        allowed_fields=frozenset(
            {
                "kind",
                "request_digest",
                "proposal_artifact_digest",
                "recovery_action_binding_digest",
            }
        ),
    )
    _preflight_text_field(
        raw_mapping,
        "kind",
        max_characters=_SHORT_CANONICAL_TEXT_MAX_CHARACTERS,
    )
    return raw_mapping


AuthoritySelectionOriginV8 = Annotated[
    IngressAuthoritySelectionOriginV8 | RecoveryAuthoritySelectionOriginV8,
    Field(discriminator="kind"),
    BeforeValidator(_preflight_authority_selection_origin_union),
]
_AUTHORITY_SELECTION_ORIGIN_ADAPTER: TypeAdapter[AuthoritySelectionOriginV8] = TypeAdapter(
    AuthoritySelectionOriginV8
)


def _validated_origin(
    value: object,
) -> IngressAuthoritySelectionOriginV8 | RecoveryAuthoritySelectionOriginV8:
    raw_mapping = _preflight_authority_selection_origin_union(value)
    return _AUTHORITY_SELECTION_ORIGIN_ADAPTER.validate_python(raw_mapping)


def validate_authority_selection_origin_v8(value: object) -> AuthoritySelectionOriginV8:
    """Restore one closed origin variant through a built-in raw mapping preflight."""

    return _validated_origin(value)


def _validated_endpoint_bindings(
    value: object,
) -> tuple[SelectedEndpointGrantBindingV8, ...]:
    if type(value) not in {list, tuple}:
        raise ValueError("selected_endpoint_grants must be a built-in list or tuple")
    raw_items = cast("list[object] | tuple[object, ...]", value)
    if len(raw_items) > MAX_SELECTED_ENDPOINT_GRANTS_V8:
        raise ValueError("selected_endpoint_grants exceeds the 256-item bound")

    bindings: list[SelectedEndpointGrantBindingV8] = []
    for raw_item in raw_items:
        item_to_validate = (
            _exact_model_field_mapping(
                raw_item,
                model_name=SelectedEndpointGrantBindingV8.__name__,
                field_names=("capability_id", "grant_digest"),
            )
            if type(raw_item) is SelectedEndpointGrantBindingV8
            else raw_item
        )
        bindings.append(SelectedEndpointGrantBindingV8.model_validate(item_to_validate))

    capability_ids = tuple(binding.capability_id for binding in bindings)
    if len(set(capability_ids)) != len(capability_ids):
        raise ValueError("selected_endpoint_grants contains a repeated capability_id")
    return tuple(bindings)


def _origin_material(
    origin: IngressAuthoritySelectionOriginV8 | RecoveryAuthoritySelectionOriginV8,
) -> dict[str, object]:
    if type(origin) is IngressAuthoritySelectionOriginV8:
        return {
            "kind": "INGRESS",
            "request_digest": origin.request_digest,
            "proposal_artifact_digest": origin.proposal_artifact_digest,
        }
    if type(origin) is RecoveryAuthoritySelectionOriginV8:
        return {
            "kind": "RECOVERY",
            "recovery_action_binding_digest": origin.recovery_action_binding_digest,
        }
    raise ValueError("Authority selection origin has an unsupported concrete type")


def _binding_material(binding: SelectedEndpointGrantBindingV8) -> dict[str, object]:
    return {
        "capability_id": binding.capability_id,
        "grant_digest": binding.grant_digest,
    }


_SELECTION_FIELDS = frozenset(
    {
        "api_version",
        "schema_version",
        "tenant_id",
        "subject_transaction_id",
        "normalized_action_digest",
        "deployment_profile_digest",
        "selected_endpoint_grants",
        "origin",
        "selection_digest",
    }
)


def _preflight_selection_raw(value: object, *, model_name: str) -> dict[str, object]:
    raw_mapping = _raw_model_mapping(
        value,
        model_name=model_name,
        allowed_fields=_SELECTION_FIELDS,
    )
    _preflight_literal_field(raw_mapping, "api_version", "agentkernel.io/v1alpha1")
    _preflight_literal_field(raw_mapping, "schema_version", "1.0")
    _preflight_text_field(
        raw_mapping,
        "tenant_id",
        max_characters=_IDENTIFIER_MAX_CHARACTERS,
    )
    _preflight_text_field(
        raw_mapping,
        "subject_transaction_id",
        max_characters=_IDENTIFIER_MAX_CHARACTERS,
    )
    for field_name in (
        "normalized_action_digest",
        "deployment_profile_digest",
        "selection_digest",
    ):
        _preflight_text_field(
            raw_mapping,
            field_name,
            max_characters=_DIGEST_CHARACTERS,
        )

    normalized = dict(raw_mapping)
    if "selected_endpoint_grants" in raw_mapping:
        normalized["selected_endpoint_grants"] = _validated_endpoint_bindings(
            raw_mapping["selected_endpoint_grants"]
        )
    if "origin" in raw_mapping:
        normalized["origin"] = _validated_origin(raw_mapping["origin"])
    return normalized


def _selection_material(selection: AuthoritySelection) -> dict[str, object]:
    return {
        "api_version": selection.api_version,
        "schema_version": selection.schema_version,
        "tenant_id": selection.tenant_id,
        "subject_transaction_id": selection.subject_transaction_id,
        "normalized_action_digest": selection.normalized_action_digest,
        "deployment_profile_digest": selection.deployment_profile_digest,
        "selected_endpoint_grants": tuple(
            _binding_material(binding) for binding in selection.selected_endpoint_grants
        ),
        "origin": _origin_material(selection.origin),
    }


class AuthoritySelection(_V8StrictModel):
    """Content identity for the authority endpoints selected for one subject action."""

    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    schema_version: SchemaVersion = "1.0"
    tenant_id: Identifier
    subject_transaction_id: Identifier
    normalized_action_digest: Digest
    deployment_profile_digest: Digest
    selected_endpoint_grants: Annotated[
        tuple[SelectedEndpointGrantBindingV8, ...],
        Field(max_length=MAX_SELECTED_ENDPOINT_GRANTS_V8),
    ]
    origin: AuthoritySelectionOriginV8
    selection_digest: Digest

    @model_validator(mode="before")
    @classmethod
    def _preflight_raw_input(cls, value: object) -> object:
        if type(value) is cls:
            value = _exact_model_field_mapping(
                value,
                model_name=cls.__name__,
                field_names=(
                    "api_version",
                    "schema_version",
                    "tenant_id",
                    "subject_transaction_id",
                    "normalized_action_digest",
                    "deployment_profile_digest",
                    "selected_endpoint_grants",
                    "origin",
                    "selection_digest",
                ),
            )
        return _preflight_selection_raw(value, model_name=cls.__name__)

    @model_validator(mode="after")
    def _canonical_selection(self) -> Self:
        capability_ids = tuple(binding.capability_id for binding in self.selected_endpoint_grants)
        if capability_ids != tuple(sorted(capability_ids)):
            raise ValueError("selected_endpoint_grants must be strictly ordered by capability_id")
        if len(set(capability_ids)) != len(capability_ids):
            raise ValueError("selected_endpoint_grants contains a repeated capability_id")

        material = _selection_material(self)
        _preflight_selection_raw(material, model_name=f"{type(self).__name__} digest material")
        if self.selection_digest != canonical_digest(material):
            raise ValueError("Authority selection has a mismatched selection_digest")
        return self

    @classmethod
    def create(
        cls,
        *,
        tenant_id: Identifier,
        subject_transaction_id: Identifier,
        normalized_action_digest: Digest,
        deployment_profile_digest: Digest,
        selected_endpoint_grants: tuple[SelectedEndpointGrantBindingV8, ...],
        origin: AuthoritySelectionOriginV8,
    ) -> Self:
        """Construct a sorted selection only after validating the complete bounded input."""

        if cls is not AuthoritySelection:
            raise TypeError("AuthoritySelection.create cannot construct a contract subclass")
        validated_bindings = _validated_endpoint_bindings(selected_endpoint_grants)
        validated_origin = _validated_origin(origin)
        sorted_bindings = tuple(
            sorted(validated_bindings, key=lambda binding: binding.capability_id)
        )
        material: dict[str, object] = {
            "api_version": "agentkernel.io/v1alpha1",
            "schema_version": "1.0",
            "tenant_id": tenant_id,
            "subject_transaction_id": subject_transaction_id,
            "normalized_action_digest": normalized_action_digest,
            "deployment_profile_digest": deployment_profile_digest,
            "selected_endpoint_grants": tuple(
                _binding_material(binding) for binding in sorted_bindings
            ),
            "origin": _origin_material(validated_origin),
        }
        _preflight_selection_raw(material, model_name=f"{cls.__name__} factory material")
        return cls.model_validate({**material, "selection_digest": canonical_digest(material)})


_REUSE_PROFILE_FIELDS = frozenset(
    {
        "api_version",
        "schema_version",
        "tenant_id",
        "deployment_profile_digest",
        "selected_endpoint_grants",
        "reuse_profile_digest",
    }
)


def _preflight_reuse_profile_raw(value: object, *, model_name: str) -> dict[str, object]:
    raw_mapping = _raw_model_mapping(
        value,
        model_name=model_name,
        allowed_fields=_REUSE_PROFILE_FIELDS,
    )
    _preflight_literal_field(raw_mapping, "api_version", "agentkernel.io/v1alpha1")
    _preflight_literal_field(raw_mapping, "schema_version", "1.0")
    _preflight_text_field(
        raw_mapping,
        "tenant_id",
        max_characters=_IDENTIFIER_MAX_CHARACTERS,
    )
    _preflight_text_field(
        raw_mapping,
        "deployment_profile_digest",
        max_characters=_DIGEST_CHARACTERS,
    )
    _preflight_text_field(
        raw_mapping,
        "reuse_profile_digest",
        max_characters=_DIGEST_CHARACTERS,
    )

    normalized = dict(raw_mapping)
    if "selected_endpoint_grants" in raw_mapping:
        normalized["selected_endpoint_grants"] = _validated_endpoint_bindings(
            raw_mapping["selected_endpoint_grants"]
        )
    return normalized


def _reuse_profile_material(profile: AuthoritySelectionReuseProfileV8) -> dict[str, object]:
    return {
        "api_version": profile.api_version,
        "schema_version": profile.schema_version,
        "tenant_id": profile.tenant_id,
        "deployment_profile_digest": profile.deployment_profile_digest,
        "selected_endpoint_grants": tuple(
            _binding_material(binding) for binding in profile.selected_endpoint_grants
        ),
    }


class AuthoritySelectionReuseProfileV8(_V8StrictModel):
    """The independently digested selection inputs that may be reused across subjects."""

    api_version: ApiVersion = "agentkernel.io/v1alpha1"
    schema_version: SchemaVersion = "1.0"
    tenant_id: Identifier
    deployment_profile_digest: Digest
    selected_endpoint_grants: Annotated[
        tuple[SelectedEndpointGrantBindingV8, ...],
        Field(max_length=MAX_SELECTED_ENDPOINT_GRANTS_V8),
    ]
    reuse_profile_digest: Digest

    @model_validator(mode="before")
    @classmethod
    def _preflight_raw_input(cls, value: object) -> object:
        if type(value) is cls:
            value = _exact_model_field_mapping(
                value,
                model_name=cls.__name__,
                field_names=(
                    "api_version",
                    "schema_version",
                    "tenant_id",
                    "deployment_profile_digest",
                    "selected_endpoint_grants",
                    "reuse_profile_digest",
                ),
            )
        return _preflight_reuse_profile_raw(value, model_name=cls.__name__)

    @model_validator(mode="after")
    def _canonical_profile(self) -> Self:
        capability_ids = tuple(binding.capability_id for binding in self.selected_endpoint_grants)
        if capability_ids != tuple(sorted(capability_ids)):
            raise ValueError("selected_endpoint_grants must be strictly ordered by capability_id")
        if len(set(capability_ids)) != len(capability_ids):
            raise ValueError("selected_endpoint_grants contains a repeated capability_id")

        material = _reuse_profile_material(self)
        _preflight_reuse_profile_raw(
            material,
            model_name=f"{type(self).__name__} digest material",
        )
        if self.reuse_profile_digest != canonical_digest(material):
            raise ValueError(
                "Authority selection reuse profile has a mismatched reuse_profile_digest"
            )
        return self

    @classmethod
    def from_selection(cls, selection: AuthoritySelection) -> Self:
        """Copy only the independently reusable fields from a validated full selection."""

        if cls is not AuthoritySelectionReuseProfileV8:
            raise TypeError(
                "AuthoritySelectionReuseProfileV8.from_selection cannot construct "
                "a contract subclass"
            )
        if type(selection) is not AuthoritySelection:
            raise ValueError("selection must be an exact AuthoritySelection")
        validated_selection = AuthoritySelection.model_validate(selection)
        material: dict[str, object] = {
            "api_version": "agentkernel.io/v1alpha1",
            "schema_version": "1.0",
            "tenant_id": validated_selection.tenant_id,
            "deployment_profile_digest": validated_selection.deployment_profile_digest,
            "selected_endpoint_grants": tuple(
                _binding_material(binding)
                for binding in validated_selection.selected_endpoint_grants
            ),
        }
        _preflight_reuse_profile_raw(
            material,
            model_name=f"{cls.__name__} factory material",
        )
        return cls.model_validate({**material, "reuse_profile_digest": canonical_digest(material)})


class TransportEncodingV8(StrEnum):
    """Supported authority-input content encodings."""

    IDENTITY = "IDENTITY"
    GZIP = "GZIP"


class AuthorityInputPhaseV8(StrEnum):
    """Stable phases at which the bounded authority-input gate may terminate."""

    BEFORE_RESPONSE = "BEFORE_RESPONSE"
    WIRE_READ = "WIRE_READ"
    CONTENT_DECODE = "CONTENT_DECODE"
    UTF8_DECODE = "UTF8_DECODE"
    JSON_SCAN = "JSON_SCAN"
    RESPONSE_FINALIZE = "RESPONSE_FINALIZE"


class AuthorityInputTerminationReasonV8(StrEnum):
    """Stable, evidence-safe streaming termination identifiers."""

    DISCONNECTED = "DISCONNECTED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    CANCELLED = "CANCELLED"
    SOURCE_PROTOCOL_VIOLATION = "SOURCE_PROTOCOL_VIOLATION"
    CONTROL_SIGNAL_FAILURE = "CONTROL_SIGNAL_FAILURE"
    TRANSFER_FRAMING_FAILED = "TRANSFER_FRAMING_FAILED"
    DECOMPRESSION_FAILED = "DECOMPRESSION_FAILED"
    TRUNCATED_COMPRESSED_STREAM = "TRUNCATED_COMPRESSED_STREAM"
    TRAILING_COMPRESSED_DATA = "TRAILING_COMPRESSED_DATA"
    INVALID_UTF8 = "INVALID_UTF8"
    INVALID_JSON = "INVALID_JSON"
    ROOT_NOT_OBJECT = "ROOT_NOT_OBJECT"
    DUPLICATE_OBJECT_KEY = "DUPLICATE_OBJECT_KEY"
    LONE_SURROGATE = "LONE_SURROGATE"
    NONCANONICAL_NUMBER = "NONCANONICAL_NUMBER"
    DEPTH_LIMIT_EXCEEDED = "DEPTH_LIMIT_EXCEEDED"
    NODE_LIMIT_EXCEEDED = "NODE_LIMIT_EXCEEDED"
    CONTAINER_LIMIT_EXCEEDED = "CONTAINER_LIMIT_EXCEEDED"
    SCALAR_LIMIT_EXCEEDED = "SCALAR_LIMIT_EXCEEDED"
    AGGREGATE_SCALAR_LIMIT_EXCEEDED = "AGGREGATE_SCALAR_LIMIT_EXCEEDED"


class OverflowBoundaryV8(StrEnum):
    """The only byte counters that can produce a canonical overflow witness."""

    UNCOMPRESSED_WIRE = "UNCOMPRESSED_WIRE"
    COMPRESSED_WIRE = "COMPRESSED_WIRE"
    DECOMPRESSED = "DECOMPRESSED"


_NO_RESPONSE_PHASE_REASON_MATRIX: dict[
    AuthorityInputPhaseV8,
    frozenset[AuthorityInputTerminationReasonV8],
] = {
    AuthorityInputPhaseV8.BEFORE_RESPONSE: frozenset(
        {
            AuthorityInputTerminationReasonV8.DISCONNECTED,
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
        }
    ),
    AuthorityInputPhaseV8.WIRE_READ: frozenset(
        {
            AuthorityInputTerminationReasonV8.DISCONNECTED,
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION,
            AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE,
            AuthorityInputTerminationReasonV8.TRANSFER_FRAMING_FAILED,
        }
    ),
    AuthorityInputPhaseV8.RESPONSE_FINALIZE: frozenset(
        {AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM}
    ),
}

_INCOMPLETE_PHASE_REASON_MATRIX: dict[
    AuthorityInputPhaseV8,
    frozenset[AuthorityInputTerminationReasonV8],
] = {
    AuthorityInputPhaseV8.WIRE_READ: frozenset(
        {
            AuthorityInputTerminationReasonV8.DISCONNECTED,
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.SOURCE_PROTOCOL_VIOLATION,
            AuthorityInputTerminationReasonV8.CONTROL_SIGNAL_FAILURE,
            AuthorityInputTerminationReasonV8.TRANSFER_FRAMING_FAILED,
        }
    ),
    AuthorityInputPhaseV8.CONTENT_DECODE: frozenset(
        {
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.DECOMPRESSION_FAILED,
        }
    ),
    AuthorityInputPhaseV8.UTF8_DECODE: frozenset(
        {
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.INVALID_UTF8,
        }
    ),
    AuthorityInputPhaseV8.JSON_SCAN: frozenset(
        {
            AuthorityInputTerminationReasonV8.DEADLINE_EXCEEDED,
            AuthorityInputTerminationReasonV8.CANCELLED,
            AuthorityInputTerminationReasonV8.INVALID_JSON,
            AuthorityInputTerminationReasonV8.ROOT_NOT_OBJECT,
            AuthorityInputTerminationReasonV8.DUPLICATE_OBJECT_KEY,
            AuthorityInputTerminationReasonV8.LONE_SURROGATE,
            AuthorityInputTerminationReasonV8.NONCANONICAL_NUMBER,
            AuthorityInputTerminationReasonV8.DEPTH_LIMIT_EXCEEDED,
            AuthorityInputTerminationReasonV8.NODE_LIMIT_EXCEEDED,
            AuthorityInputTerminationReasonV8.CONTAINER_LIMIT_EXCEEDED,
            AuthorityInputTerminationReasonV8.SCALAR_LIMIT_EXCEEDED,
            AuthorityInputTerminationReasonV8.AGGREGATE_SCALAR_LIMIT_EXCEEDED,
        }
    ),
    AuthorityInputPhaseV8.RESPONSE_FINALIZE: frozenset(
        {
            AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM,
            AuthorityInputTerminationReasonV8.TRAILING_COMPRESSED_DATA,
        }
    ),
}

_GZIP_ONLY_TERMINATION_REASONS = frozenset(
    {
        AuthorityInputTerminationReasonV8.DECOMPRESSION_FAILED,
        AuthorityInputTerminationReasonV8.TRUNCATED_COMPRESSED_STREAM,
        AuthorityInputTerminationReasonV8.TRAILING_COMPRESSED_DATA,
    }
)


def _preflight_observation_raw(
    value: object,
    *,
    model_name: str,
    allowed_fields: frozenset[str],
    literal_kind: str,
    enum_fields: tuple[tuple[str, type[StrEnum]], ...] = (),
    digest_fields: tuple[str, ...] = (),
    integer_fields: tuple[str, ...] = (),
) -> dict[str, object]:
    raw_mapping = _raw_model_mapping(
        value,
        model_name=model_name,
        allowed_fields=allowed_fields,
    )
    _preflight_literal_field(raw_mapping, "kind", literal_kind)
    for field_name, enum_type in enum_fields:
        _preflight_enum_field(raw_mapping, field_name, enum_type)
    for field_name in digest_fields:
        _preflight_text_field(
            raw_mapping,
            field_name,
            max_characters=_DIGEST_CHARACTERS,
        )
    for field_name in integer_fields:
        _preflight_integer_field(raw_mapping, field_name)
    return raw_mapping


class NoResponseObservationV8(_V8StrictModel):
    """Evidence that the gate accepted zero response-body wire bytes."""

    kind: Literal["NO_RESPONSE"] = "NO_RESPONSE"
    failure_phase: AuthorityInputPhaseV8

    @model_validator(mode="before")
    @classmethod
    def _preflight_raw_input(cls, value: object) -> object:
        if type(value) is cls:
            value = _exact_model_field_mapping(
                value,
                model_name=cls.__name__,
                field_names=("kind", "failure_phase"),
            )
        return _preflight_observation_raw(
            value,
            model_name=cls.__name__,
            allowed_fields=frozenset({"kind", "failure_phase"}),
            literal_kind="NO_RESPONSE",
            enum_fields=(("failure_phase", AuthorityInputPhaseV8),),
        )

    @model_validator(mode="after")
    def _canonical_phase(self) -> Self:
        if self.failure_phase not in _NO_RESPONSE_PHASE_REASON_MATRIX:
            raise ValueError("NO_RESPONSE uses an unsupported failure phase")
        return self

    @classmethod
    def from_termination(
        cls,
        *,
        failure_phase: AuthorityInputPhaseV8,
        termination_reason: AuthorityInputTerminationReasonV8,
        transport_encoding: TransportEncodingV8,
        observed_wire_prefix_length: int,
        observed_decompressed_prefix_length: int,
    ) -> Self:
        """Construct a no-response observation only for one closed streaming pairing."""

        if cls is not NoResponseObservationV8:
            raise TypeError(
                "NoResponseObservationV8.from_termination cannot construct a contract subclass"
            )
        if type(failure_phase) is not AuthorityInputPhaseV8:
            raise ValueError("failure_phase must be an exact AuthorityInputPhaseV8")
        if type(termination_reason) is not AuthorityInputTerminationReasonV8:
            raise ValueError(
                "termination_reason must be an exact AuthorityInputTerminationReasonV8"
            )
        if type(transport_encoding) is not TransportEncodingV8:
            raise ValueError("transport_encoding must be an exact TransportEncodingV8")
        if (
            type(observed_wire_prefix_length) is not int
            or type(observed_decompressed_prefix_length) is not int
        ):
            raise ValueError("No-response counters must be exact built-in integers")
        if observed_wire_prefix_length != 0 or observed_decompressed_prefix_length != 0:
            raise ValueError("NO_RESPONSE requires both accepted byte counters to be zero")

        allowed_reasons = _NO_RESPONSE_PHASE_REASON_MATRIX.get(failure_phase, frozenset())
        if termination_reason not in allowed_reasons:
            raise ValueError("NO_RESPONSE uses an unsupported phase/reason pairing")
        if (
            failure_phase is AuthorityInputPhaseV8.RESPONSE_FINALIZE
            and transport_encoding is not TransportEncodingV8.GZIP
        ):
            raise ValueError("The response-finalize NO_RESPONSE case requires declared GZIP")
        return cls(failure_phase=failure_phase)


class CompleteBoundedResponseObservationV8(_V8StrictModel):
    """Evidence for a clean transport EOF within both applicable byte bounds."""

    kind: Literal["COMPLETE_BOUNDED_RESPONSE"] = "COMPLETE_BOUNDED_RESPONSE"
    transport_encoding: TransportEncodingV8
    complete_wire_digest: Digest
    complete_wire_length: _BoundedAuthorityInputLengthV8
    complete_decompressed_digest: Digest
    complete_decompressed_length: _BoundedAuthorityInputLengthV8

    @model_validator(mode="before")
    @classmethod
    def _preflight_raw_input(cls, value: object) -> object:
        if type(value) is cls:
            value = _exact_model_field_mapping(
                value,
                model_name=cls.__name__,
                field_names=(
                    "kind",
                    "transport_encoding",
                    "complete_wire_digest",
                    "complete_wire_length",
                    "complete_decompressed_digest",
                    "complete_decompressed_length",
                ),
            )
        return _preflight_observation_raw(
            value,
            model_name=cls.__name__,
            allowed_fields=frozenset(
                {
                    "kind",
                    "transport_encoding",
                    "complete_wire_digest",
                    "complete_wire_length",
                    "complete_decompressed_digest",
                    "complete_decompressed_length",
                }
            ),
            literal_kind="COMPLETE_BOUNDED_RESPONSE",
            enum_fields=(("transport_encoding", TransportEncodingV8),),
            digest_fields=(
                "complete_wire_digest",
                "complete_decompressed_digest",
            ),
            integer_fields=(
                "complete_wire_length",
                "complete_decompressed_length",
            ),
        )

    @model_validator(mode="after")
    def _canonical_lengths_and_identity(self) -> Self:
        if (
            self.complete_wire_length > AUTHORITY_INPUT_BYTE_LIMIT_V8
            or self.complete_decompressed_length > AUTHORITY_INPUT_BYTE_LIMIT_V8
        ):
            raise ValueError("Complete response exceeds an authority-input byte limit")
        if self.complete_wire_length == 0 and self.complete_wire_digest != _EMPTY_SHA256_DIGEST:
            raise ValueError("A zero-length complete wire body requires the empty SHA-256")
        if (
            self.complete_decompressed_length == 0
            and self.complete_decompressed_digest != _EMPTY_SHA256_DIGEST
        ):
            raise ValueError("A zero-length complete decompressed body requires the empty SHA-256")
        if self.transport_encoding is TransportEncodingV8.IDENTITY:
            if (
                self.complete_wire_length != self.complete_decompressed_length
                or self.complete_wire_digest != self.complete_decompressed_digest
            ):
                raise ValueError(
                    "IDENTITY complete response must repeat its wire digest and length"
                )
        elif self.complete_wire_length < _MINIMUM_COMPLETE_GZIP_WIRE_BYTES:
            raise ValueError("Complete GZIP response is shorter than one valid member")
        return self


class IncompleteBoundedResponseObservationV8(_V8StrictModel):
    """Evidence for a bounded accepted prefix before proven transport completion."""

    kind: Literal["INCOMPLETE_BOUNDED_RESPONSE"] = "INCOMPLETE_BOUNDED_RESPONSE"
    termination_phase: AuthorityInputPhaseV8
    termination_reason: AuthorityInputTerminationReasonV8
    transport_encoding: TransportEncodingV8
    observed_wire_prefix_digest: Digest
    observed_wire_prefix_length: _PositiveBoundedAuthorityInputLengthV8
    observed_decompressed_prefix_digest: Digest
    observed_decompressed_prefix_length: _BoundedAuthorityInputLengthV8

    @model_validator(mode="before")
    @classmethod
    def _preflight_raw_input(cls, value: object) -> object:
        if type(value) is cls:
            value = _exact_model_field_mapping(
                value,
                model_name=cls.__name__,
                field_names=(
                    "kind",
                    "termination_phase",
                    "termination_reason",
                    "transport_encoding",
                    "observed_wire_prefix_digest",
                    "observed_wire_prefix_length",
                    "observed_decompressed_prefix_digest",
                    "observed_decompressed_prefix_length",
                ),
            )
        return _preflight_observation_raw(
            value,
            model_name=cls.__name__,
            allowed_fields=frozenset(
                {
                    "kind",
                    "termination_phase",
                    "termination_reason",
                    "transport_encoding",
                    "observed_wire_prefix_digest",
                    "observed_wire_prefix_length",
                    "observed_decompressed_prefix_digest",
                    "observed_decompressed_prefix_length",
                }
            ),
            literal_kind="INCOMPLETE_BOUNDED_RESPONSE",
            enum_fields=(
                ("termination_phase", AuthorityInputPhaseV8),
                ("termination_reason", AuthorityInputTerminationReasonV8),
                ("transport_encoding", TransportEncodingV8),
            ),
            digest_fields=(
                "observed_wire_prefix_digest",
                "observed_decompressed_prefix_digest",
            ),
            integer_fields=(
                "observed_wire_prefix_length",
                "observed_decompressed_prefix_length",
            ),
        )

    @model_validator(mode="after")
    def _canonical_prefix_and_termination(self) -> Self:
        if (
            self.observed_wire_prefix_length > AUTHORITY_INPUT_BYTE_LIMIT_V8
            or self.observed_decompressed_prefix_length > AUTHORITY_INPUT_BYTE_LIMIT_V8
        ):
            raise ValueError("Incomplete response exceeds an authority-input byte limit")
        if (
            self.observed_decompressed_prefix_length == 0
            and self.observed_decompressed_prefix_digest != _EMPTY_SHA256_DIGEST
        ):
            raise ValueError("A zero-length decompressed prefix requires the empty SHA-256")
        allowed_reasons = _INCOMPLETE_PHASE_REASON_MATRIX.get(
            self.termination_phase,
            frozenset(),
        )
        if self.termination_reason not in allowed_reasons:
            raise ValueError("Incomplete response uses an unsupported phase/reason pairing")
        if (
            self.termination_reason in _GZIP_ONLY_TERMINATION_REASONS
            and self.transport_encoding is not TransportEncodingV8.GZIP
        ):
            raise ValueError("This incomplete termination reason requires GZIP")
        if self.transport_encoding is TransportEncodingV8.IDENTITY and (
            self.observed_wire_prefix_length != self.observed_decompressed_prefix_length
            or self.observed_wire_prefix_digest != self.observed_decompressed_prefix_digest
        ):
            raise ValueError(
                "IDENTITY incomplete response must repeat its prefix digest and length"
            )
        return self


class OverflowPrefixObservationV8(_V8StrictModel):
    """Evidence through the first byte beyond one transport byte boundary."""

    kind: Literal["OVERFLOW_PREFIX"] = "OVERFLOW_PREFIX"
    transport_encoding: TransportEncodingV8
    observed_wire_prefix_digest: Digest
    observed_wire_prefix_length: _OverflowPrefixPositiveLengthV8
    observed_decompressed_prefix_digest: Digest
    observed_decompressed_prefix_length: _OverflowPrefixNonNegativeLengthV8
    exceeded_boundary: OverflowBoundaryV8
    configured_limit: _ConfiguredAuthorityInputLimitV8 = AUTHORITY_INPUT_BYTE_LIMIT_V8
    first_excess_observed_count: _FirstExcessObservedCountV8 = AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8

    @model_validator(mode="before")
    @classmethod
    def _preflight_raw_input(cls, value: object) -> object:
        if type(value) is cls:
            value = _exact_model_field_mapping(
                value,
                model_name=cls.__name__,
                field_names=(
                    "kind",
                    "transport_encoding",
                    "observed_wire_prefix_digest",
                    "observed_wire_prefix_length",
                    "observed_decompressed_prefix_digest",
                    "observed_decompressed_prefix_length",
                    "exceeded_boundary",
                    "configured_limit",
                    "first_excess_observed_count",
                ),
            )
        return _preflight_observation_raw(
            value,
            model_name=cls.__name__,
            allowed_fields=frozenset(
                {
                    "kind",
                    "transport_encoding",
                    "observed_wire_prefix_digest",
                    "observed_wire_prefix_length",
                    "observed_decompressed_prefix_digest",
                    "observed_decompressed_prefix_length",
                    "exceeded_boundary",
                    "configured_limit",
                    "first_excess_observed_count",
                }
            ),
            literal_kind="OVERFLOW_PREFIX",
            enum_fields=(
                ("transport_encoding", TransportEncodingV8),
                ("exceeded_boundary", OverflowBoundaryV8),
            ),
            digest_fields=(
                "observed_wire_prefix_digest",
                "observed_decompressed_prefix_digest",
            ),
            integer_fields=(
                "observed_wire_prefix_length",
                "observed_decompressed_prefix_length",
                "configured_limit",
                "first_excess_observed_count",
            ),
        )

    @model_validator(mode="after")
    def _canonical_overflow_shape(self) -> Self:
        if self.configured_limit != AUTHORITY_INPUT_BYTE_LIMIT_V8:
            raise ValueError("Overflow configured_limit must equal the v8 byte limit")
        if self.first_excess_observed_count != AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8:
            raise ValueError("Overflow first_excess_observed_count must equal the first excess")
        if (
            self.observed_decompressed_prefix_length == 0
            and self.observed_decompressed_prefix_digest != _EMPTY_SHA256_DIGEST
        ):
            raise ValueError(
                "A zero-length decompressed overflow prefix requires the empty SHA-256"
            )

        if self.transport_encoding is TransportEncodingV8.IDENTITY:
            if self.exceeded_boundary is not OverflowBoundaryV8.UNCOMPRESSED_WIRE:
                raise ValueError("IDENTITY overflow requires UNCOMPRESSED_WIRE")
            if (
                self.observed_wire_prefix_length != AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
                or self.observed_decompressed_prefix_length != AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
                or self.observed_wire_prefix_digest != self.observed_decompressed_prefix_digest
            ):
                raise ValueError(
                    "IDENTITY overflow must repeat the witness prefix digest and length"
                )
            return self

        if self.exceeded_boundary is OverflowBoundaryV8.COMPRESSED_WIRE:
            if (
                self.observed_wire_prefix_length != AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
                or self.observed_decompressed_prefix_length > AUTHORITY_INPUT_BYTE_LIMIT_V8
            ):
                raise ValueError("GZIP compressed-wire overflow has invalid prefix lengths")
            return self
        if self.exceeded_boundary is OverflowBoundaryV8.DECOMPRESSED:
            if (
                self.observed_wire_prefix_length > AUTHORITY_INPUT_BYTE_LIMIT_V8
                or self.observed_decompressed_prefix_length != AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8
            ):
                raise ValueError("GZIP decompressed overflow has invalid prefix lengths")
            return self
        raise ValueError("GZIP overflow uses an unsupported byte boundary")


_AUTHORITY_INPUT_OBSERVATION_TYPES_V8 = (
    NoResponseObservationV8,
    CompleteBoundedResponseObservationV8,
    IncompleteBoundedResponseObservationV8,
    OverflowPrefixObservationV8,
)
_AUTHORITY_INPUT_OBSERVATION_FIELDS_V8 = frozenset(
    field_name
    for observation_type in _AUTHORITY_INPUT_OBSERVATION_TYPES_V8
    for field_name in observation_type.model_fields
)


def _preflight_authority_input_observation_union(value: object) -> dict[str, object]:
    """Inspect observation material before the tagged union reads its discriminator."""

    if type(value) in _AUTHORITY_INPUT_OBSERVATION_TYPES_V8:
        concrete_type = cast("type[_V8StrictModel]", type(value))
        value = _exact_model_field_mapping(
            value,
            model_name=concrete_type.__name__,
            field_names=tuple(concrete_type.model_fields),
        )
    raw_mapping = _raw_model_mapping(
        value,
        model_name="AuthorityInputObservationV8",
        allowed_fields=_AUTHORITY_INPUT_OBSERVATION_FIELDS_V8,
    )
    _preflight_text_field(
        raw_mapping,
        "kind",
        max_characters=_SHORT_CANONICAL_TEXT_MAX_CHARACTERS,
    )
    return raw_mapping


AuthorityInputObservationV8 = Annotated[
    NoResponseObservationV8
    | CompleteBoundedResponseObservationV8
    | IncompleteBoundedResponseObservationV8
    | OverflowPrefixObservationV8,
    Field(discriminator="kind"),
    BeforeValidator(_preflight_authority_input_observation_union),
]
_AUTHORITY_INPUT_OBSERVATION_ADAPTER: TypeAdapter[AuthorityInputObservationV8] = TypeAdapter(
    AuthorityInputObservationV8
)


def validate_authority_input_observation_v8(value: object) -> AuthorityInputObservationV8:
    """Restore one closed observation variant after an exact raw-type preflight."""

    raw_mapping = _preflight_authority_input_observation_union(value)
    return _AUTHORITY_INPUT_OBSERVATION_ADAPTER.validate_python(raw_mapping)


__all__ = [
    "AUTHORITY_INPUT_BYTE_LIMIT_V8",
    "AUTHORITY_INPUT_FIRST_EXCESS_COUNT_V8",
    "MAX_SELECTED_ENDPOINT_GRANTS_V8",
    "AuthorityInputObservationV8",
    "AuthorityInputPhaseV8",
    "AuthorityInputTerminationReasonV8",
    "AuthoritySelection",
    "AuthoritySelectionOriginV8",
    "AuthoritySelectionReuseProfileV8",
    "CompleteBoundedResponseObservationV8",
    "IncompleteBoundedResponseObservationV8",
    "IngressAuthoritySelectionOriginV8",
    "NoResponseObservationV8",
    "OverflowBoundaryV8",
    "OverflowPrefixObservationV8",
    "RecoveryAuthoritySelectionOriginV8",
    "SelectedEndpointGrantBindingV8",
    "TransportEncodingV8",
    "validate_authority_input_observation_v8",
    "validate_authority_selection_origin_v8",
]
