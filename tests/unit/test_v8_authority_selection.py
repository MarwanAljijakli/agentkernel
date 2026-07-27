from __future__ import annotations

import hashlib
from typing import Any

import pytest
from agentkernel.authority.v8_contracts import (
    MAX_SELECTED_ENDPOINT_GRANTS_V8,
    AuthoritySelection,
    AuthoritySelectionOriginV8,
    AuthoritySelectionReuseProfileV8,
    IngressAuthoritySelectionOriginV8,
    RecoveryAuthoritySelectionOriginV8,
    SelectedEndpointGrantBindingV8,
    validate_authority_selection_origin_v8,
)
from agentkernel.canonical import canonical_digest, canonical_json_bytes
from pydantic import TypeAdapter, ValidationError


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


def _bytes_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


TENANT = "tenant.alpha"
SUBJECT = "transaction.subject"
ACTION_DIGEST = _digest("normalized-action")
PROFILE_DIGEST = _digest("deployment-profile")
REQUEST_DIGEST = _digest("request")
PROPOSAL_DIGEST = _digest("proposal-artifact")
RECOVERY_BINDING_DIGEST = _digest("recovery-action-binding")


def _binding(
    capability_id: str,
    *,
    grant_label: str | None = None,
) -> SelectedEndpointGrantBindingV8:
    return SelectedEndpointGrantBindingV8(
        capability_id=capability_id,
        grant_digest=_digest(grant_label or capability_id),
    )


def _ingress_origin() -> IngressAuthoritySelectionOriginV8:
    return IngressAuthoritySelectionOriginV8(
        request_digest=REQUEST_DIGEST,
        proposal_artifact_digest=PROPOSAL_DIGEST,
    )


def _selection(
    *,
    tenant_id: str = TENANT,
    subject_transaction_id: str = SUBJECT,
    normalized_action_digest: str = ACTION_DIGEST,
    deployment_profile_digest: str = PROFILE_DIGEST,
    bindings: tuple[SelectedEndpointGrantBindingV8, ...] = (),
    origin: (IngressAuthoritySelectionOriginV8 | RecoveryAuthoritySelectionOriginV8 | None) = None,
) -> AuthoritySelection:
    return AuthoritySelection.create(
        tenant_id=tenant_id,
        subject_transaction_id=subject_transaction_id,
        normalized_action_digest=normalized_action_digest,
        deployment_profile_digest=deployment_profile_digest,
        selected_endpoint_grants=bindings,
        origin=origin or _ingress_origin(),
    )


def _rehash_selection_payload(payload: dict[str, Any]) -> dict[str, Any]:
    material = {key: value for key, value in payload.items() if key != "selection_digest"}
    return {**material, "selection_digest": canonical_digest(material)}


def _rehash_reuse_payload(payload: dict[str, Any]) -> dict[str, Any]:
    material = {key: value for key, value in payload.items() if key != "reuse_profile_digest"}
    return {**material, "reuse_profile_digest": canonical_digest(material)}


def test_ingress_selection_has_golden_canonical_bytes_and_digest() -> None:
    binding = _binding("capability.alpha", grant_label="grant-alpha")
    selection = _selection(bindings=(binding,))

    unsigned_bytes = (
        b'{"api_version":"agentkernel.io/v1alpha1",'
        + f'"deployment_profile_digest":"{PROFILE_DIGEST}",'.encode()
        + f'"normalized_action_digest":"{ACTION_DIGEST}",'.encode()
        + b'"origin":{"kind":"INGRESS",'
        + f'"proposal_artifact_digest":"{PROPOSAL_DIGEST}",'.encode()
        + f'"request_digest":"{REQUEST_DIGEST}"'.encode()
        + b"}"
        + b',"schema_version":"1.0","selected_endpoint_grants":['
        + b'{"capability_id":"capability.alpha",'
        + f'"grant_digest":"{binding.grant_digest}"'.encode()
        + b"}]"
        + f',"subject_transaction_id":"{SUBJECT}","tenant_id":"{TENANT}"'.encode()
        + b"}"
    )
    expected_digest = _bytes_digest(unsigned_bytes)
    complete_bytes = (
        b'{"api_version":"agentkernel.io/v1alpha1",'
        + f'"deployment_profile_digest":"{PROFILE_DIGEST}",'.encode()
        + f'"normalized_action_digest":"{ACTION_DIGEST}",'.encode()
        + b'"origin":{"kind":"INGRESS",'
        + f'"proposal_artifact_digest":"{PROPOSAL_DIGEST}",'.encode()
        + f'"request_digest":"{REQUEST_DIGEST}"'.encode()
        + b"}"
        + b',"schema_version":"1.0","selected_endpoint_grants":['
        + b'{"capability_id":"capability.alpha",'
        + f'"grant_digest":"{binding.grant_digest}"'.encode()
        + b"}]"
        + f',"selection_digest":"{expected_digest}",'.encode()
        + f'"subject_transaction_id":"{SUBJECT}","tenant_id":"{TENANT}"'.encode()
        + b"}"
    )

    assert expected_digest == (
        "sha256:53124327123fd255df602a6ee6c1269102e8bd8d0c2dde922531bae8cdc52e70"
    )
    assert selection.selection_digest == expected_digest
    assert canonical_json_bytes(selection) == complete_bytes


def test_recovery_selection_has_golden_canonical_bytes_and_digest() -> None:
    origin = RecoveryAuthoritySelectionOriginV8(
        recovery_action_binding_digest=RECOVERY_BINDING_DIGEST
    )
    selection = _selection(origin=origin)

    unsigned_bytes = (
        b'{"api_version":"agentkernel.io/v1alpha1",'
        + f'"deployment_profile_digest":"{PROFILE_DIGEST}",'.encode()
        + f'"normalized_action_digest":"{ACTION_DIGEST}",'.encode()
        + b'"origin":{"kind":"RECOVERY",'
        + f'"recovery_action_binding_digest":"{RECOVERY_BINDING_DIGEST}"'.encode()
        + b'},"schema_version":"1.0","selected_endpoint_grants":[]'
        + f',"subject_transaction_id":"{SUBJECT}","tenant_id":"{TENANT}"'.encode()
        + b"}"
    )
    expected_digest = _bytes_digest(unsigned_bytes)

    assert expected_digest == (
        "sha256:e5100dce7ad4fa0e5d5ebca9eb3d5e18a1de2eedcb68645c3843e932d8315c5d"
    )
    assert selection.selection_digest == expected_digest
    assert (
        canonical_json_bytes(
            {
                key: value
                for key, value in selection.model_dump().items()
                if key != "selection_digest"
            }
        )
        == unsigned_bytes
    )


@pytest.mark.parametrize("count", [0, 1, MAX_SELECTED_ENDPOINT_GRANTS_V8])
def test_selection_factory_accepts_explicit_bounded_endpoint_counts(count: int) -> None:
    bindings = tuple(
        _binding(f"capability.{index:03d}", grant_label=f"grant-{index}") for index in range(count)
    )

    selection = _selection(bindings=bindings)

    assert len(selection.selected_endpoint_grants) == count


def test_selection_requires_explicit_endpoint_field_and_origin() -> None:
    payload = _selection().model_dump(mode="python")
    payload.pop("selected_endpoint_grants")
    with pytest.raises(ValidationError):
        AuthoritySelection.model_validate(payload)

    payload = _selection().model_dump(mode="python")
    payload.pop("origin")
    with pytest.raises(ValidationError):
        AuthoritySelection.model_validate(payload)

    payload = _selection().model_dump(mode="python")
    payload["origin"] = None
    with pytest.raises(ValidationError):
        AuthoritySelection.model_validate(payload)


def test_selection_rejects_257_endpoints_before_nested_validation() -> None:
    oversized = tuple(
        _binding(f"capability.{index:03d}") for index in range(MAX_SELECTED_ENDPOINT_GRANTS_V8 + 1)
    )
    with pytest.raises(ValueError, match="256-item bound"):
        _selection(bindings=oversized)

    payload = _selection().model_dump(mode="python")
    payload["selected_endpoint_grants"] = [
        {"not": "a binding"} for _ in range(MAX_SELECTED_ENDPOINT_GRANTS_V8 + 1)
    ]
    with pytest.raises(ValidationError, match="256-item bound"):
        AuthoritySelection.model_validate(payload)


def test_factory_sorts_only_after_rejecting_duplicate_ids() -> None:
    first = _binding("capability.a", grant_label="grant-a")
    second = _binding("capability.b", grant_label="grant-b")
    selection = _selection(bindings=(second, first))
    assert tuple(binding.capability_id for binding in selection.selected_endpoint_grants) == (
        "capability.a",
        "capability.b",
    )

    repeated_same = (first, first)
    with pytest.raises(ValueError, match="repeated capability_id"):
        _selection(bindings=repeated_same)

    repeated_different = (
        first,
        SelectedEndpointGrantBindingV8(
            capability_id=first.capability_id,
            grant_digest=_digest("different-grant"),
        ),
    )
    with pytest.raises(ValueError, match="repeated capability_id"):
        _selection(bindings=repeated_different)


def test_direct_selection_input_must_already_be_sorted_and_unique() -> None:
    first = _binding("capability.a")
    second = _binding("capability.b")
    selection = _selection(bindings=(first, second))

    unordered = selection.model_dump(mode="python")
    unordered["selected_endpoint_grants"] = list(reversed(unordered["selected_endpoint_grants"]))
    with pytest.raises(ValidationError, match="strictly ordered"):
        AuthoritySelection.model_validate(_rehash_selection_payload(unordered))

    for duplicate in (
        [first.model_dump(), first.model_dump()],
        [
            first.model_dump(),
            {
                "capability_id": first.capability_id,
                "grant_digest": _digest("different-grant"),
            },
        ],
    ):
        duplicated = selection.model_dump(mode="python")
        duplicated["selected_endpoint_grants"] = duplicate
        with pytest.raises(ValidationError, match="repeated capability_id"):
            AuthoritySelection.model_validate(_rehash_selection_payload(duplicated))


def test_selection_rejects_self_digest_tampering() -> None:
    payload = _selection(bindings=(_binding("capability.a"),)).model_dump(mode="python")
    payload["selection_digest"] = _digest("tampered")
    with pytest.raises(ValidationError, match="mismatched selection_digest"):
        AuthoritySelection.model_validate(payload)


def test_every_selection_input_changes_the_full_digest() -> None:
    base_binding = _binding("capability.a")
    base = _selection(bindings=(base_binding,))
    mutations = (
        _selection(tenant_id="tenant.beta", bindings=(base_binding,)),
        _selection(subject_transaction_id="transaction.other", bindings=(base_binding,)),
        _selection(normalized_action_digest=_digest("other-action"), bindings=(base_binding,)),
        _selection(
            deployment_profile_digest=_digest("other-profile"),
            bindings=(base_binding,),
        ),
        _selection(bindings=(_binding("capability.b"),)),
        _selection(
            bindings=(
                SelectedEndpointGrantBindingV8(
                    capability_id=base_binding.capability_id,
                    grant_digest=_digest("other-grant"),
                ),
            )
        ),
        _selection(
            bindings=(base_binding,),
            origin=IngressAuthoritySelectionOriginV8(
                request_digest=_digest("other-request"),
                proposal_artifact_digest=PROPOSAL_DIGEST,
            ),
        ),
        _selection(
            bindings=(base_binding,),
            origin=IngressAuthoritySelectionOriginV8(
                request_digest=REQUEST_DIGEST,
                proposal_artifact_digest=_digest("other-proposal"),
            ),
        ),
        _selection(
            bindings=(base_binding,),
            origin=RecoveryAuthoritySelectionOriginV8(
                recovery_action_binding_digest=RECOVERY_BINDING_DIGEST
            ),
        ),
    )

    assert all(item.selection_digest != base.selection_digest for item in mutations)
    assert len({item.selection_digest for item in mutations}) == len(mutations)


def test_reuse_profile_is_independent_of_subject_action_and_origin() -> None:
    bindings = (_binding("capability.a"), _binding("capability.b"))
    ingress = _selection(bindings=bindings)
    recovery = _selection(
        subject_transaction_id="transaction.recovery",
        normalized_action_digest=_digest("recovery-action"),
        bindings=bindings,
        origin=RecoveryAuthoritySelectionOriginV8(
            recovery_action_binding_digest=RECOVERY_BINDING_DIGEST
        ),
    )

    ingress_profile = AuthoritySelectionReuseProfileV8.from_selection(ingress)
    recovery_profile = AuthoritySelectionReuseProfileV8.from_selection(recovery)

    assert ingress.selection_digest != recovery.selection_digest
    assert ingress_profile == recovery_profile
    assert ingress_profile.reuse_profile_digest == recovery_profile.reuse_profile_digest
    assert set(AuthoritySelectionReuseProfileV8.model_fields) == {
        "api_version",
        "schema_version",
        "tenant_id",
        "deployment_profile_digest",
        "selected_endpoint_grants",
        "reuse_profile_digest",
    }
    assert "selection_digest" not in ingress_profile.model_dump()


def test_profile_artifact_digest_changes_both_independent_digests() -> None:
    binding = _binding("capability.a")
    first = _selection(bindings=(binding,))
    second = _selection(
        deployment_profile_digest=_digest("same-label-different-artifact"),
        bindings=(binding,),
    )

    first_reuse = AuthoritySelectionReuseProfileV8.from_selection(first)
    second_reuse = AuthoritySelectionReuseProfileV8.from_selection(second)

    assert first.selection_digest != second.selection_digest
    assert first_reuse.reuse_profile_digest != second_reuse.reuse_profile_digest
    payload = first.model_dump(mode="python")
    payload["deployment_profile_id"] = "same-mutable-label"
    with pytest.raises(ValidationError):
        AuthoritySelection.model_validate(payload)


def test_reuse_profile_validates_order_uniqueness_and_digest_on_restore() -> None:
    profile = AuthoritySelectionReuseProfileV8.from_selection(
        _selection(bindings=(_binding("capability.a"), _binding("capability.b")))
    )

    unordered = profile.model_dump(mode="python")
    unordered["selected_endpoint_grants"] = list(reversed(unordered["selected_endpoint_grants"]))
    with pytest.raises(ValidationError, match="strictly ordered"):
        AuthoritySelectionReuseProfileV8.model_validate(_rehash_reuse_payload(unordered))

    tampered = profile.model_dump(mode="python")
    tampered["reuse_profile_digest"] = _digest("tampered-reuse")
    with pytest.raises(ValidationError, match="mismatched reuse_profile_digest"):
        AuthoritySelectionReuseProfileV8.model_validate(tampered)


def test_origin_union_is_closed_and_discriminator_checked() -> None:
    adapter: TypeAdapter[AuthoritySelectionOriginV8] = TypeAdapter(AuthoritySelectionOriginV8)
    ingress = {
        "kind": "INGRESS",
        "request_digest": REQUEST_DIGEST,
        "proposal_artifact_digest": PROPOSAL_DIGEST,
    }
    recovery = {
        "kind": "RECOVERY",
        "recovery_action_binding_digest": RECOVERY_BINDING_DIGEST,
    }

    assert isinstance(adapter.validate_python(ingress), IngressAuthoritySelectionOriginV8)
    assert isinstance(
        validate_authority_selection_origin_v8(recovery),
        RecoveryAuthoritySelectionOriginV8,
    )
    for invalid in (
        {**ingress, "recovery_action_binding_digest": RECOVERY_BINDING_DIGEST},
        {**recovery, "request_digest": REQUEST_DIGEST},
        {**ingress, "kind": "UNKNOWN"},
        {key: value for key, value in ingress.items() if key != "kind"},
        None,
    ):
        with pytest.raises((ValidationError, ValueError)):
            validate_authority_selection_origin_v8(invalid)


def test_origin_union_preflights_kind_before_discriminator_callbacks() -> None:
    class CallbackString(str):
        calls = 0

        def __hash__(self) -> int:
            type(self).calls += 1
            return super().__hash__()

        def __eq__(self, other: object) -> bool:
            type(self).calls += 1
            return super().__eq__(other)

    adapter: TypeAdapter[AuthoritySelectionOriginV8] = TypeAdapter(AuthoritySelectionOriginV8)
    payload = {
        "kind": CallbackString("INGRESS"),
        "request_digest": REQUEST_DIGEST,
        "proposal_artifact_digest": PROPOSAL_DIGEST,
    }
    CallbackString.calls = 0

    with pytest.raises(ValidationError, match="built-in str"):
        adapter.validate_python(payload)
    assert CallbackString.calls == 0

    with pytest.raises(ValidationError, match="raw text bound"):
        adapter.validate_python({**payload, "kind": "I" * 65})


def test_origin_union_inspects_exact_model_storage_before_discriminator_lookup() -> None:
    class CallbackStringKey(str):
        calls = 0

        def __hash__(self) -> int:
            type(self).calls += 1
            return super().__hash__()

        def __eq__(self, other: object) -> bool:
            type(self).calls += 1
            return super().__eq__(other)

    poisoned = _ingress_origin().model_copy()
    stored_fields = object.__getattribute__(poisoned, "__dict__")
    kind = stored_fields.pop("kind")
    stored_fields[CallbackStringKey("kind")] = kind
    CallbackStringKey.calls = 0

    with pytest.raises(ValidationError):
        TypeAdapter(AuthoritySelectionOriginV8).validate_python(poisoned)
    assert CallbackStringKey.calls == 0


def test_selection_and_reuse_profile_restore_from_canonical_json() -> None:
    selection = _selection(bindings=(_binding("capability.a"),))
    profile = AuthoritySelectionReuseProfileV8.from_selection(selection)

    assert AuthoritySelection.model_validate_json(selection.model_dump_json()) == selection
    assert (
        AuthoritySelectionReuseProfileV8.model_validate_json(profile.model_dump_json()) == profile
    )


def test_selection_schema_has_no_proposal_capability_refs_or_mutable_profile_label() -> None:
    schema = AuthoritySelection.model_json_schema()
    properties = schema["properties"]
    assert "capability_refs" not in properties
    assert "deployment_profile_id" not in properties
    assert properties["selected_endpoint_grants"]["maxItems"] == 256
    assert "selected_endpoint_grants" in schema["required"]
    assert "origin" in schema["required"]


def test_raw_python_preflight_rejects_container_and_scalar_subclasses() -> None:
    class DictSubclass(dict[str, object]):
        pass

    class TupleSubclass(tuple[object, ...]):
        pass

    class StringSubclass(str):
        pass

    selection = _selection()
    with pytest.raises(ValidationError, match="built-in dict"):
        AuthoritySelection.model_validate(DictSubclass(selection.model_dump(mode="python")))

    payload = selection.model_dump(mode="python")
    payload["selected_endpoint_grants"] = TupleSubclass()
    with pytest.raises(ValidationError, match="built-in list or tuple"):
        AuthoritySelection.model_validate(payload)

    payload = selection.model_dump(mode="python")
    payload["tenant_id"] = StringSubclass(TENANT)
    with pytest.raises(ValidationError, match="built-in str"):
        AuthoritySelection.model_validate(payload)


def test_factories_revalidate_constructed_models_before_hashing() -> None:
    forged_binding = SelectedEndpointGrantBindingV8.model_construct(
        capability_id=123,  # type: ignore[arg-type]
        grant_digest=_digest("grant"),
    )
    with pytest.raises(ValidationError, match="built-in str"):
        SelectedEndpointGrantBindingV8.model_validate(forged_binding)
    with pytest.raises(ValidationError, match="built-in str"):
        _selection(bindings=(forged_binding,))

    valid = _selection()
    forged_selection = AuthoritySelection.model_construct(
        api_version=valid.api_version,
        schema_version=valid.schema_version,
        tenant_id=valid.tenant_id,
        subject_transaction_id=valid.subject_transaction_id,
        normalized_action_digest=valid.normalized_action_digest,
        deployment_profile_digest=valid.deployment_profile_digest,
        selected_endpoint_grants=valid.selected_endpoint_grants,
        origin=valid.origin,
        selection_digest=_digest("forged"),
    )
    with pytest.raises(ValidationError, match="mismatched selection_digest"):
        AuthoritySelection.model_validate(forged_selection)
    with pytest.raises(ValidationError, match="mismatched selection_digest"):
        AuthoritySelectionReuseProfileV8.from_selection(forged_selection)


def test_selection_reopen_rejects_nested_subtype_and_container_poison_before_dump() -> None:
    class ExtendedBinding(SelectedEndpointGrantBindingV8):
        capability_refs: tuple[str, ...] = ("proposal:untrusted",)

    class TupleSubclass(tuple[object, ...]):
        pass

    valid = _selection(bindings=(_binding("capability.a"),))
    extended_binding = ExtendedBinding(
        capability_id="capability.a",
        grant_digest=_digest("capability.a"),
    )

    for poisoned_bindings in (
        (extended_binding,),
        TupleSubclass(valid.selected_endpoint_grants),
    ):
        poisoned_selection = AuthoritySelection.model_construct(
            api_version=valid.api_version,
            schema_version=valid.schema_version,
            tenant_id=valid.tenant_id,
            subject_transaction_id=valid.subject_transaction_id,
            normalized_action_digest=valid.normalized_action_digest,
            deployment_profile_digest=valid.deployment_profile_digest,
            selected_endpoint_grants=poisoned_bindings,  # type: ignore[arg-type]
            origin=valid.origin,
            selection_digest=valid.selection_digest,
        )
        with pytest.raises(ValidationError):
            AuthoritySelection.model_validate(poisoned_selection)
        with pytest.raises(ValidationError):
            AuthoritySelectionReuseProfileV8.from_selection(poisoned_selection)


def test_exact_model_storage_rejects_unsigned_fields_before_projection() -> None:
    valid_binding = _binding("capability.a")
    poisoned_binding = valid_binding.model_copy(update={"capability_refs": ("proposal:untrusted",)})
    with pytest.raises(ValueError, match="unsupported stored field"):
        SelectedEndpointGrantBindingV8.model_validate(poisoned_binding)
    with pytest.raises(ValueError, match="unsupported stored field"):
        _selection(bindings=(poisoned_binding,))

    valid_origin = _ingress_origin()
    poisoned_origin = valid_origin.model_copy(update={"unsigned_policy": "allow"})
    with pytest.raises(ValueError, match="unsupported stored field"):
        validate_authority_selection_origin_v8(poisoned_origin)
    with pytest.raises(ValueError, match="unsupported stored field"):
        AuthoritySelection.create(
            tenant_id=TENANT,
            subject_transaction_id=SUBJECT,
            normalized_action_digest=ACTION_DIGEST,
            deployment_profile_digest=PROFILE_DIGEST,
            selected_endpoint_grants=(valid_binding,),
            origin=poisoned_origin,
        )

    valid_selection = _selection(bindings=(valid_binding,))
    poisoned_selection = valid_selection.model_copy(update={"unsigned_policy": "allow"})
    with pytest.raises(ValueError, match="unsupported stored field"):
        AuthoritySelection.model_validate(poisoned_selection)
    with pytest.raises(ValueError, match="unsupported stored field"):
        AuthoritySelectionReuseProfileV8.from_selection(poisoned_selection)

    valid_profile = AuthoritySelectionReuseProfileV8.from_selection(valid_selection)
    poisoned_profile = valid_profile.model_copy(update={"unsigned_policy": "allow"})
    with pytest.raises(ValueError, match="unsupported stored field"):
        AuthoritySelectionReuseProfileV8.model_validate(poisoned_profile)


def test_selection_factory_rejects_equal_string_subclass_storage_keys() -> None:
    class StringKey(str):
        pass

    poisoned_binding = _binding("capability.a").model_copy()
    stored_fields = object.__getattribute__(poisoned_binding, "__dict__")
    capability_id = stored_fields.pop("capability_id")
    stored_fields[StringKey("capability_id")] = capability_id

    with pytest.raises(ValueError, match="unsupported stored field"):
        _selection(bindings=(poisoned_binding,))

    poisoned_fields_set = _binding("capability.a").model_copy()
    object.__setattr__(
        poisoned_fields_set,
        "__pydantic_fields_set__",
        {StringKey("capability_id"), "grant_digest"},
    )
    with pytest.raises(ValueError, match="unsupported model state"):
        _selection(bindings=(poisoned_fields_set,))


def test_oversized_model_storage_fails_before_callback_capable_key_hashing() -> None:
    class CallbackKey:
        calls = 0

        def __hash__(self) -> int:
            type(self).calls += 1
            return 1

        def __eq__(self, other: object) -> bool:
            type(self).calls += 1
            return False

    poisoned_binding = _binding("capability.a").model_copy()
    callback_key = CallbackKey()
    stored_fields = object.__getattribute__(poisoned_binding, "__dict__")
    stored_fields[callback_key] = "untrusted"
    CallbackKey.calls = 0

    with pytest.raises(ValueError, match="unsupported stored field"):
        _selection(bindings=(poisoned_binding,))
    assert CallbackKey.calls == 0


@pytest.mark.parametrize(
    ("storage_attribute", "poisoned_value"),
    [
        ("__pydantic_fields_set__", {"capability_id", "grant_digest", "unsigned_policy"}),
        ("__pydantic_extra__", {"unsigned_policy": "allow"}),
        ("__pydantic_private__", {"_unsigned_policy": "allow"}),
    ],
)
def test_selection_factory_rejects_all_hidden_model_storage(
    storage_attribute: str,
    poisoned_value: object,
) -> None:
    poisoned_binding = _binding("capability.a").model_copy()
    object.__setattr__(poisoned_binding, storage_attribute, poisoned_value)

    with pytest.raises(ValueError, match="unsupported model state"):
        _selection(bindings=(poisoned_binding,))
    with pytest.raises(ValidationError, match="unsupported model state"):
        TypeAdapter(SelectedEndpointGrantBindingV8).validate_python(poisoned_binding)

    poisoned_origin = _ingress_origin().model_copy()
    object.__setattr__(poisoned_origin, storage_attribute, poisoned_value)
    with pytest.raises(ValueError, match="unsupported model state"):
        validate_authority_selection_origin_v8(poisoned_origin)
    with pytest.raises(ValidationError, match="unsupported model state"):
        TypeAdapter(IngressAuthoritySelectionOriginV8).validate_python(poisoned_origin)
    with pytest.raises(ValidationError, match="unsupported model state"):
        TypeAdapter(AuthoritySelectionOriginV8).validate_python(poisoned_origin)

    valid_selection = _selection(bindings=(_binding("capability.a"),))
    poisoned_selection = valid_selection.model_copy()
    object.__setattr__(poisoned_selection, storage_attribute, poisoned_value)
    with pytest.raises(ValueError, match="unsupported model state"):
        AuthoritySelection.model_validate(poisoned_selection)
    with pytest.raises(ValueError, match="unsupported model state"):
        AuthoritySelectionReuseProfileV8.from_selection(poisoned_selection)
    with pytest.raises(ValidationError, match="unsupported model state"):
        TypeAdapter(AuthoritySelection).validate_python(poisoned_selection)

    valid_profile = AuthoritySelectionReuseProfileV8.from_selection(valid_selection)
    poisoned_profile = valid_profile.model_copy()
    object.__setattr__(poisoned_profile, storage_attribute, poisoned_value)
    with pytest.raises(ValueError, match="unsupported model state"):
        AuthoritySelectionReuseProfileV8.model_validate(poisoned_profile)
    with pytest.raises(ValidationError, match="unsupported model state"):
        TypeAdapter(AuthoritySelectionReuseProfileV8).validate_python(poisoned_profile)


def test_closed_selection_factories_reject_polymorphic_contract_subclasses() -> None:
    class ExtendedSelection(AuthoritySelection):
        capability_refs: tuple[str, ...] = ("proposal:untrusted",)

    class ExtendedReuseProfile(AuthoritySelectionReuseProfileV8):
        unsigned_policy: str = "allow"

    selection = _selection(bindings=(_binding("capability.a"),))
    with pytest.raises(TypeError, match="contract subclass"):
        ExtendedSelection.create(
            tenant_id=selection.tenant_id,
            subject_transaction_id=selection.subject_transaction_id,
            normalized_action_digest=selection.normalized_action_digest,
            deployment_profile_digest=selection.deployment_profile_digest,
            selected_endpoint_grants=selection.selected_endpoint_grants,
            origin=selection.origin,
        )
    with pytest.raises(TypeError, match="contract subclass"):
        ExtendedReuseProfile.from_selection(selection)


def test_reuse_profile_golden_and_each_bound_field_change_its_digest() -> None:
    binding = _binding("capability.alpha", grant_label="grant-alpha")
    profile = AuthoritySelectionReuseProfileV8.from_selection(_selection(bindings=(binding,)))
    unsigned_bytes = (
        b'{"api_version":"agentkernel.io/v1alpha1",'
        + f'"deployment_profile_digest":"{PROFILE_DIGEST}",'.encode()
        + b'"schema_version":"1.0","selected_endpoint_grants":['
        + b'{"capability_id":"capability.alpha",'
        + f'"grant_digest":"{binding.grant_digest}"'.encode()
        + b"}]"
        + f',"tenant_id":"{TENANT}"'.encode()
        + b"}"
    )
    expected_digest = _bytes_digest(unsigned_bytes)

    assert (
        expected_digest == "sha256:4e02134f24e3e61cb683902030f8fc173f188b5a484e5a01e7c7e60338494efd"
    )
    assert profile.reuse_profile_digest == expected_digest
    assert (
        canonical_json_bytes(
            {
                key: value
                for key, value in profile.model_dump().items()
                if key != "reuse_profile_digest"
            }
        )
        == unsigned_bytes
    )

    mutations = (
        _selection(tenant_id="tenant.beta", bindings=(binding,)),
        _selection(bindings=(_binding("capability.beta", grant_label="grant-alpha"),)),
        _selection(bindings=(_binding("capability.alpha", grant_label="grant-beta"),)),
    )
    assert all(
        AuthoritySelectionReuseProfileV8.from_selection(mutated).reuse_profile_digest
        != profile.reuse_profile_digest
        for mutated in mutations
    )


def test_selection_and_reuse_profile_are_immutable_and_have_canonical_field_order() -> None:
    selection = _selection()
    profile = AuthoritySelectionReuseProfileV8.from_selection(selection)

    assert list(selection.model_dump()) == [
        "api_version",
        "schema_version",
        "tenant_id",
        "subject_transaction_id",
        "normalized_action_digest",
        "deployment_profile_digest",
        "selected_endpoint_grants",
        "origin",
        "selection_digest",
    ]
    assert list(profile.model_dump()) == [
        "api_version",
        "schema_version",
        "tenant_id",
        "deployment_profile_digest",
        "selected_endpoint_grants",
        "reuse_profile_digest",
    ]
    field_name = "tenant_id"
    with pytest.raises(ValidationError):
        setattr(selection, field_name, "tenant.changed")
    with pytest.raises(ValidationError):
        setattr(profile, field_name, "tenant.changed")
