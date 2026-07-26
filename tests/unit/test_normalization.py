from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import agentkernel.normalization.filesystem as filesystem_normalization
import pytest
from agentkernel.adapters.base import AdapterManifest, NormalizerManifest, OperationManifest
from agentkernel.authority import (
    AuthorityEvaluationContext,
    AuthorityEvaluationVerdict,
    AuthorityEvaluator,
    AuthoritySnapshot,
    CapabilityBudgetState,
    CapabilityKeyVersion,
    EnforcedCapabilityGrant,
)
from agentkernel.canonical import canonical_digest, sha256_digest
from agentkernel.domain.enums import (
    ProvenanceTrust,
    ResourceAccessMode,
    ResourceUseKind,
    RiskClass,
)
from agentkernel.domain.models import (
    ActionProposal,
    AuthenticatedActionContext,
    NormalizedAction,
    NormalizedIntentProjection,
    NormalizedProvenance,
    PolicyBundle,
    PolicyDefault,
    PolicyEffect,
    PolicyRule,
    ProvenanceRecord,
    ResourceUse,
    SemanticArgument,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.normalization import (
    FilesystemNormalizerConfig,
    FilesystemWriteFilesNormalizer,
    NormalizerRegistry,
    WriteFilesArguments,
)
from agentkernel.normalization.limits import bounded_json_size
from agentkernel.policy import (
    MAX_RESOURCE_USES,
    PolicyContext,
    PolicyLayer,
    PolicyLayerInput,
    PolicyLayerSnapshot,
    PolicyResourceInput,
    PolicyVerdict,
    compile_policy,
    evaluate_policy_layers,
)
from pydantic import BaseModel, ValidationError

_NOW = datetime(2026, 7, 22, 12, tzinfo=UTC)
_DIGEST_ZERO = "sha256:" + "0" * 64


def _provenance(provenance_id: str = "prov_input") -> ProvenanceRecord:
    return ProvenanceRecord(
        provenance_id=provenance_id,
        source="artifact:request",
        acquisition_step="step_capture",
        trust=ProvenanceTrust.AUTHORIZED_USER,
        data_classes=("project_data", "public"),
        integrity_ref=canonical_digest({"source": provenance_id}),
    )


def _proposal(
    files: dict[str, str] | None = None,
    *,
    transaction_id: str = "tx_normalize",
    goal_id: str = "goal_normalize",
    agent_id: str = "agent:scripted:test",
    provenance_ids: tuple[str, ...] = ("prov_input",),
    deadline: datetime = _NOW + timedelta(minutes=5),
    idempotency_key: str | None = "idem-normalize",
    arguments: dict[str, object] | None = None,
) -> ActionProposal:
    payload = arguments if arguments is not None else {"files": files or {"src/app.py": "ok"}}
    return ActionProposal(
        goal_id=goal_id,
        transaction_id=transaction_id,
        agent_id=agent_id,
        adapter="filesystem",
        adapter_version="0.1.0",
        operation="write_files",
        arguments=payload,
        provenance_ids=provenance_ids,
        capability_refs=("cap_files",),
        deadline=deadline,
        idempotency_key=idempotency_key,
    )


def _context(
    normalizer: FilesystemWriteFilesNormalizer,
    **updates: str,
) -> AuthenticatedActionContext:
    values = {
        "tenant_id": "tenant_local",
        "principal_id": "principal:user",
        "goal_id": "goal_normalize",
        "run_id": "run_normalize",
        "trace_id": "trace_normalize",
        "actor_id": "service:kernel",
        "on_behalf_of": "principal:user",
        "agent_id": "agent:scripted:test",
        "configuration_digest": normalizer.configuration_digest,
    }
    values.update(updates)
    return AuthenticatedActionContext(**values)


def _adapter_manifest(normalizer_manifest: NormalizerManifest | None) -> AdapterManifest:
    return AdapterManifest(
        name="filesystem",
        version="0.1.0",
        implementation_digest=canonical_digest(
            {"implementation": "FilesystemAdapter", "protocol": "v1alpha1"}
        ),
        operations={
            "write_files": OperationManifest(
                risk_floor=RiskClass.REVERSIBLE,
                effect_domains=("filesystem",),
                staging=True,
                commit=True,
                abort=True,
                rollback=True,
                reconcile=True,
                normalizer=normalizer_manifest,
            )
        },
    )


def _registry(
    normalizer: FilesystemWriteFilesNormalizer,
    *,
    reviewed: bool = True,
) -> NormalizerRegistry:
    registry = NormalizerRegistry()
    registry.register("filesystem", "write_files", normalizer, reviewed=reviewed)
    return registry


def _normalize(
    proposal: ActionProposal,
    *,
    normalizer: FilesystemWriteFilesNormalizer | None = None,
    context: AuthenticatedActionContext | None = None,
    records: tuple[ProvenanceRecord, ...] = (_provenance(),),
    adapter_manifest: AdapterManifest | None = None,
    reviewed: bool = True,
    enforcement_profile: bool = True,
) -> NormalizedAction:
    active_normalizer = normalizer or FilesystemWriteFilesNormalizer()
    active_context = context or _context(active_normalizer)
    manifest = adapter_manifest or _adapter_manifest(active_normalizer.manifest)
    return _registry(active_normalizer, reviewed=reviewed).normalize(
        proposal,
        active_context,
        adapter_manifest=manifest,
        expected_adapter_manifest_digest=manifest.digest,
        provenance_records=records,
        enforcement_profile=enforcement_profile,
    )


def test_write_files_normalizes_per_resource_without_retaining_content() -> None:
    canary = "SECRET-CONTENT-MUST-NOT-BE-IN-NORMALIZED-ACTION"
    action = _normalize(
        _proposal(
            {
                "src/app.py": canary,
                "docs/café report.txt": "documentation",
            }
        )
    )

    writes = tuple(
        use for use in action.resource_uses if use.use_kind is ResourceUseKind.AUTHORITATIVE_EFFECT
    )
    broad_reads = tuple(
        use
        for use in action.resource_uses
        if use.use_kind in {ResourceUseKind.PRECONDITION_READ, ResourceUseKind.VERIFIER_READ}
    )

    assert len(action.resource_uses) == 4
    assert {use.canonical_resource for use in writes} == {
        "fs://workspace/src/app.py",
        "fs://workspace/docs/caf%C3%A9%20report.txt",
    }
    assert all(use.authority_action == "fs.write" for use in writes)
    assert all(use.access_mode is ResourceAccessMode.WRITE for use in writes)
    assert all(use.destination_external is False for use in writes)
    assert {use.use_kind for use in broad_reads} == {
        ResourceUseKind.PRECONDITION_READ,
        ResourceUseKind.VERIFIER_READ,
    }
    assert all(use.authority_action == "fs.read" for use in broad_reads)
    assert all(use.access_mode is ResourceAccessMode.READ for use in broad_reads)
    assert all(use.canonical_resource == "fs://workspace/**" for use in broad_reads)
    precondition = next(
        use for use in broad_reads if use.use_kind is ResourceUseKind.PRECONDITION_READ
    )
    verifier = next(use for use in broad_reads if use.use_kind is ResourceUseKind.VERIFIER_READ)
    assert precondition.data_classes == ("project_data",)
    assert precondition.provenance_ids == ()
    assert verifier.data_classes == ("project_data", "public")
    assert verifier.provenance_ids == ("prov_input",)
    assert {argument.digest for argument in action.semantic_arguments} == {
        sha256_digest(canary.encode()),
        sha256_digest(b"documentation"),
    }
    assert canary not in action.model_dump_json()
    assert all(not isinstance(value, dict) for value in action.__dict__.values())


def test_normalization_performs_no_filesystem_network_or_process_io(monkeypatch) -> None:
    normalizer = FilesystemWriteFilesNormalizer()
    proposal = _proposal({"src/app.py": "content"})
    context = _context(normalizer)
    manifest = _adapter_manifest(normalizer.manifest)
    registry = _registry(normalizer)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("normalization attempted I/O")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(Path, "stat", forbidden)
    monkeypatch.setattr(Path, "iterdir", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(os, "scandir", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    action = registry.normalize(
        proposal,
        context,
        adapter_manifest=manifest,
        expected_adapter_manifest_digest=manifest.digest,
        provenance_records=(_provenance(),),
    )
    assert action.intent_hash.startswith("sha256:")


def test_hash_and_tuple_order_are_deterministic_and_transport_fields_are_excluded() -> None:
    normalizer = FilesystemWriteFilesNormalizer()
    first = _normalize(
        _proposal(
            {"z.txt": "last", "a.txt": "first"},
            transaction_id="tx_first",
            deadline=_NOW + timedelta(minutes=1),
            idempotency_key="idem-first",
        ),
        normalizer=normalizer,
        context=_context(normalizer, trace_id="trace_first"),
    )
    second = _normalize(
        _proposal(
            {"a.txt": "first", "z.txt": "last"},
            transaction_id="tx_second",
            deadline=_NOW + timedelta(hours=1),
            idempotency_key="idem-second",
        ),
        normalizer=normalizer,
        context=_context(normalizer, trace_id="trace_second"),
    )

    assert first.intent_hash == second.intent_hash
    assert first.resource_uses == second.resource_uses
    assert first.semantic_arguments == second.semantic_arguments
    projection = first.intent_projection().model_dump(mode="python")
    assert {
        "tenant_id",
        "principal_id",
        "goal_id",
        "run_id",
        "actor_id",
        "on_behalf_of",
        "agent_id",
        "adapter",
        "adapter_version",
        "adapter_manifest_digest",
        "operation",
        "normalizer_version",
        "normalizer_digest",
        "operation_schema_digest",
        "configuration_digest",
        "risk_floor",
        "effect_domains",
        "resource_uses",
        "semantic_arguments",
        "provenance",
    } <= projection.keys()
    assert {
        "transaction_id",
        "deadline",
        "idempotency_key",
        "trace_id",
        "target_version",
        "display_metadata",
    }.isdisjoint(projection)

    different_run = _normalize(
        _proposal({"a.txt": "first", "z.txt": "last"}),
        normalizer=normalizer,
        context=_context(normalizer, run_id="run_other"),
    )
    assert different_run.intent_hash != first.intent_hash


def test_content_bytes_are_not_unicode_normalized() -> None:
    composed = _normalize(_proposal({"note.txt": "café"}))
    decomposed = _normalize(_proposal({"note.txt": "café"}))
    assert composed.intent_hash != decomposed.intent_hash
    assert composed.semantic_arguments[0].digest != decomposed.semantic_arguments[0].digest


def test_model_validation_rejects_tampered_intent_hash() -> None:
    action = _normalize(_proposal())
    payload = action.model_dump(mode="python")
    payload["intent_hash"] = _DIGEST_ZERO
    with pytest.raises(ValidationError, match="mismatched intent_hash"):
        NormalizedAction.model_validate(payload)


def test_normalized_action_rejects_noncanonical_idempotency_key_alias() -> None:
    action = _normalize(_proposal(idempotency_key="café"))
    payload = action.model_dump(mode="python")
    payload["idempotency_key"] = "cafe\u0301"

    with pytest.raises(ValidationError, match="must use Unicode NFC"):
        NormalizedAction.model_validate(payload)


@pytest.mark.parametrize(
    "path",
    [
        "../secret.txt",
        "dir/../secret.txt",
        "dir/./file.txt",
        "/absolute.txt",
        "dir//file.txt",
        "dir\\file.txt",
        "C:/drive.txt",
        "file.txt:stream",
        "CON",
        "CON .txt",
        "CLOCK$",
        "nul.txt",
        "dir/COM1.log",
        "trailing.",
        "trailing ",
        "question?.txt",
        "encoded%2Fslash.txt",
        "%2e%2e/secret.txt",
        "café.txt",
    ],
)
def test_path_alias_traversal_and_encoded_attacks_are_rejected(path: str) -> None:
    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal({path: "content"}))
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize(
    "files",
    [
        {"Readme.md": "one", "README.md": "two"},
        {"Straße.txt": "one", "STRASSE.txt": "two"},
        {"Parent": "file", "parent/child.txt": "child"},
    ],
)
def test_case_insensitive_alias_and_parent_child_conflicts_are_rejected(
    files: dict[str, str],
) -> None:
    normalizer = FilesystemWriteFilesNormalizer(
        config=FilesystemNormalizerConfig(path_case_mode="insensitive")
    )
    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal(files), normalizer=normalizer)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_parent_child_conflict_is_rejected_on_case_sensitive_targets() -> None:
    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal({"parent": "file", "parent/child.txt": "child"}))
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_admitted_case_mode_controls_cross_request_resource_identity() -> None:
    sensitive = FilesystemWriteFilesNormalizer(
        config=FilesystemNormalizerConfig(path_case_mode="sensitive")
    )
    sensitive_upper = _normalize(_proposal({"README.md": "same"}), normalizer=sensitive)
    sensitive_lower = _normalize(_proposal({"readme.md": "same"}), normalizer=sensitive)
    assert sensitive_upper.intent_hash != sensitive_lower.intent_hash
    assert (
        sensitive_upper.semantic_arguments[0].resource
        != sensitive_lower.semantic_arguments[0].resource
    )

    insensitive = FilesystemWriteFilesNormalizer(
        config=FilesystemNormalizerConfig(path_case_mode="insensitive")
    )
    insensitive_upper = _normalize(_proposal({"README.md": "same"}), normalizer=insensitive)
    insensitive_lower = _normalize(_proposal({"readme.md": "same"}), normalizer=insensitive)
    assert insensitive_upper.intent_hash == insensitive_lower.intent_hash
    assert insensitive_upper.semantic_arguments[0].resource == "fs://workspace/readme.md"
    assert insensitive_upper.resource_uses == insensitive_lower.resource_uses


def test_count_argument_resource_and_path_bounds_fail_closed() -> None:
    too_many = {f"file-{index:03}.txt": "x" for index in range(257)}
    with pytest.raises(AgentKernelError) as count_error:
        _normalize(_proposal(too_many))
    assert count_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    default = FilesystemWriteFilesNormalizer()
    small_argument_manifest = default.manifest.model_copy(update={"max_argument_bytes": 50})
    small_argument = FilesystemWriteFilesNormalizer(manifest=small_argument_manifest)
    with pytest.raises(AgentKernelError) as argument_error:
        _normalize(_proposal({"file.txt": "x" * 80}), normalizer=small_argument)
    assert argument_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    small_resource_manifest = default.manifest.model_copy(update={"max_resources": 3})
    small_resource = FilesystemWriteFilesNormalizer(manifest=small_resource_manifest)
    with pytest.raises(AgentKernelError) as resource_error:
        _normalize(
            _proposal({"one.txt": "1", "two.txt": "2"}),
            normalizer=small_resource,
        )
    assert resource_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED

    with pytest.raises(AgentKernelError) as segment_error:
        _normalize(_proposal({f"{'a' * 256}.txt": "x"}))
    assert segment_error.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_advertised_max_file_batch_fits_the_policy_aggregation_boundary() -> None:
    action = _normalize(_proposal({f"file-{index:03}.txt": "x" for index in range(256)}))
    assert len(action.resource_uses) == 258
    assert len(action.resource_uses) <= MAX_RESOURCE_USES
    policy = compile_policy(
        PolicyBundle(
            name="filesystem-boundary",
            version="1.0.0",
            default=PolicyDefault.ABSTAIN,
            rules=(
                PolicyRule(
                    rule_id="workspace",
                    effect=PolicyEffect.GRANT,
                    modes=("read", "stage"),
                    when={"resource_within": "fs://workspace/**"},
                ),
            ),
        )
    )
    capability = EnforcedCapabilityGrant.create(
        tenant_id=action.tenant_id,
        capability_id="cap:filesystem-boundary",
        token_version=1,
        key_id="key:filesystem-boundary",
        issuer=action.principal_id,
        subject=action.agent_id,
        audience="service:agentkernel",
        goal_id=action.goal_id,
        run_id=action.run_id,
        actions=("fs.read", "fs.write"),
        resource_scopes=("fs://workspace/**",),
        data_classes=("project_data", "public"),
        issued_at=_NOW - timedelta(minutes=2),
        not_before=_NOW - timedelta(minutes=1),
        expires_at=_NOW + timedelta(hours=1),
        max_uses=1,
        nonce="nonce:filesystem-boundary",
    )
    authority_snapshot = AuthoritySnapshot.create(
        tenant_id=action.tenant_id,
        snapshot_id="snapshot:filesystem-boundary",
        revision=1,
        as_of=_NOW,
        capabilities=(capability,),
        accepted_key_versions=(
            CapabilityKeyVersion(
                tenant_id=action.tenant_id,
                key_id=capability.key_id,
                token_version=capability.token_version,
            ),
        ),
        budget_states=(
            CapabilityBudgetState(
                tenant_id=action.tenant_id,
                capability_id=capability.capability_id,
                goal_id=action.goal_id,
                run_id=action.run_id,
                max_uses=capability.max_uses,
            ),
        ),
    )
    authority_decision = AuthorityEvaluator().evaluate(
        action=action,
        context=AuthorityEvaluationContext(
            tenant_id=action.tenant_id,
            principal_id=action.principal_id,
            subject=action.agent_id,
            audience=capability.audience,
            goal_id=action.goal_id,
            run_id=action.run_id,
            actor_id=action.actor_id,
            on_behalf_of=action.on_behalf_of,
            configuration_digest=action.configuration_digest,
            evaluated_at=_NOW,
            authority_snapshot_digest=authority_snapshot.snapshot_digest,
        ),
        snapshot=authority_snapshot,
    )
    assert authority_decision.verdict is AuthorityEvaluationVerdict.ALLOW
    provenance_by_id = {value.provenance_id: value for value in action.provenance}
    resources = tuple(
        PolicyResourceInput(
            resource_index=index,
            resource_use_ref=canonical_digest(resource_use),
            resource_use=resource_use,
            context=PolicyContext(
                action=resource_use.authority_action,
                resource=resource_use.canonical_resource,
                provenance_trust=tuple(
                    sorted(
                        {
                            provenance_by_id[provenance_id].trust
                            for provenance_id in resource_use.provenance_ids
                        },
                        key=lambda trust: trust.value,
                    )
                ),
                requested_scope_expands=False,
                data_classes=resource_use.data_classes,
                destination_external=resource_use.destination_external,
                risk_class=action.risk_floor,
            ),
        )
        for index, resource_use in enumerate(action.resource_uses)
    )
    layer = PolicyLayerInput(
        layer=PolicyLayer.SYSTEM,
        scope_id="scope:system",
        policy=policy,
    )
    decision = evaluate_policy_layers(
        normalized_action=action,
        authority_decision=authority_decision,
        policy_snapshot=PolicyLayerSnapshot.create((layer.identity,)),
        layers=(layer,),
        resources=resources,
    )

    assert decision.verdict is PolicyVerdict.ELIGIBLE
    assert len(decision.resource_decisions) == 258


def test_bounded_json_size_matches_compact_utf8_json_for_accepted_input() -> None:
    value = {
        "escaped": 'quote" slash\\ newline\n',
        "unicode": "مَرْحَبًا café 😀",
        "values": [None, True, False, -42, 1.25],
    }
    expected = len(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )

    assert bounded_json_size(value, max_bytes=expected) == expected


@pytest.mark.parametrize(
    "limit_kind",
    ["depth", "collection", "nodes"],
)
def test_direct_model_arguments_are_structurally_bounded(limit_kind: str) -> None:
    if limit_kind == "depth":
        nested: object = "x"
        for _ in range(34):
            nested = [nested]
        arguments: object = {"files": nested}
    elif limit_kind == "collection":
        arguments = {"files": [None] * 4_097}
    else:
        arguments = {"files": {f"key-{index}": [None, None] for index in range(4_000)}}
    proposal = _proposal().model_copy(update={"arguments": arguments})

    with pytest.raises(AgentKernelError) as captured:
        _normalize(proposal)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_oversized_direct_string_is_rejected_without_whole_payload_serialization(
    monkeypatch,
) -> None:
    arguments = {"files": {"large.txt": "x" * 1_000_000}}

    def forbidden_json_dump(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("whole-payload JSON serialization was attempted")

    monkeypatch.setattr(json, "dumps", forbidden_json_dump)
    with pytest.raises(AgentKernelError) as captured:
        bounded_json_size(arguments, max_bytes=64)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_filesystem_count_limit_runs_before_operation_size_walk(monkeypatch) -> None:
    proposal = _proposal({f"file-{index:03}.txt": "x" for index in range(257)})

    def forbidden_size_walk(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("operation size walk ran before the cheap file-count guard")

    monkeypatch.setattr(filesystem_normalization, "_encoded_argument_size", forbidden_size_walk)
    with pytest.raises(AgentKernelError) as captured:
        _normalize(proposal)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_direct_oversized_non_json_bytes_fail_on_budget_before_conversion() -> None:
    with pytest.raises(AgentKernelError) as captured:
        bounded_json_size({"payload": bytearray(1_000_000)}, max_bytes=64)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


@pytest.mark.parametrize(
    ("arguments", "expected_code"),
    [
        ({"files": {"a.txt": "x"}, "unexpected": True}, ErrorCode.VALIDATION_ERROR),
        ({"files": ["a.txt"]}, ErrorCode.VALIDATION_ERROR),
        ({"files": {"a.txt": 1}}, ErrorCode.VALIDATION_ERROR),
        ({"files": {}}, ErrorCode.VALIDATION_ERROR),
    ],
)
def test_operation_arguments_are_strict(
    arguments: dict[str, object], expected_code: ErrorCode
) -> None:
    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal(arguments=arguments))
    assert captured.value.code is expected_code


@pytest.mark.parametrize(
    ("proposal_update", "context_update"),
    [
        ({"goal_id": "goal_other"}, {}),
        ({"agent_id": "agent:other"}, {}),
        ({}, {"goal_id": "goal_other"}),
        ({}, {"agent_id": "agent:other"}),
    ],
)
def test_authenticated_context_mismatch_is_rejected(
    proposal_update: dict[str, str],
    context_update: dict[str, str],
) -> None:
    normalizer = FilesystemWriteFilesNormalizer()
    proposal = _proposal(**proposal_update)
    context = _context(normalizer, **context_update)
    with pytest.raises(AgentKernelError) as captured:
        _normalize(proposal, normalizer=normalizer, context=context)
    assert captured.value.code is ErrorCode.AUTHORITY_MISSING


def test_provenance_records_must_match_exactly_and_bind_the_complete_record() -> None:
    proposal = _proposal(provenance_ids=("prov_a", "prov_b"))
    records = (_provenance("prov_b"), _provenance("prov_a"))
    action = _normalize(proposal, records=records)
    assert tuple(binding.provenance_id for binding in action.provenance) == (
        "prov_a",
        "prov_b",
    )
    assert all(binding.record_digest.startswith("sha256:") for binding in action.provenance)

    with pytest.raises(AgentKernelError) as missing:
        _normalize(proposal, records=(_provenance("prov_a"),))
    assert missing.value.code is ErrorCode.EVIDENCE_UNAVAILABLE

    with pytest.raises(AgentKernelError) as extra:
        _normalize(proposal, records=(*records, _provenance("prov_extra")))
    assert extra.value.code is ErrorCode.EVIDENCE_UNAVAILABLE

    duplicate_proposal = _proposal(provenance_ids=("prov_a", "prov_a"))
    with pytest.raises(AgentKernelError) as duplicate:
        _normalize(duplicate_proposal, records=(_provenance("prov_a"),))
    assert duplicate.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize(
    "updates",
    [
        {"data_classes": ("public", "project_data")},
        {"data_classes": ("project_data", "project_data")},
        {"parent_ids": ("prov_z", "prov_a")},
        {"parent_ids": ("prov_a", "prov_a")},
    ],
)
def test_provenance_set_like_fields_must_be_canonical_before_digest(
    updates: dict[str, tuple[str, ...]],
) -> None:
    noncanonical = _provenance().model_copy(update=updates)
    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal(), records=(noncanonical,))
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_registry_requires_review_but_retains_explicit_a0_compatibility() -> None:
    normalizer = FilesystemWriteFilesNormalizer()
    proposal = _proposal()
    context = _context(normalizer)
    manifest = _adapter_manifest(normalizer.manifest)
    registry = _registry(normalizer, reviewed=False)

    with pytest.raises(AgentKernelError) as captured:
        registry.normalize(
            proposal,
            context,
            adapter_manifest=manifest,
            expected_adapter_manifest_digest=manifest.digest,
            provenance_records=(_provenance(),),
        )
    assert captured.value.code is ErrorCode.AUTHORITY_MISSING

    action = registry.normalize(
        proposal,
        context,
        adapter_manifest=manifest,
        expected_adapter_manifest_digest=manifest.digest,
        provenance_records=(_provenance(),),
        enforcement_profile=False,
    )
    assert action.operation == "write_files"


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("schema_ref", "agentkernel.io/schemas/v1alpha1/OtherArguments"),
        ("schema_digest", _DIGEST_ZERO),
        ("implementation", "filesystem.other"),
        ("version", "9.9.9"),
        ("implementation_digest", _DIGEST_ZERO),
        ("max_resources", 257),
        ("max_argument_bytes", 999_999),
    ],
)
def test_registry_rejects_every_normalizer_manifest_pin_mismatch(
    field_name: str,
    replacement: object,
) -> None:
    normalizer = FilesystemWriteFilesNormalizer()
    tampered = normalizer.manifest.model_copy(update={field_name: replacement})
    adapter_manifest = _adapter_manifest(tampered)
    with pytest.raises(AgentKernelError) as captured:
        _registry(normalizer).normalize(
            _proposal(),
            _context(normalizer),
            adapter_manifest=adapter_manifest,
            expected_adapter_manifest_digest=adapter_manifest.digest,
            provenance_records=(_provenance(),),
        )
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_registry_rejects_adapter_digest_config_and_missing_metadata() -> None:
    normalizer = FilesystemWriteFilesNormalizer()
    manifest = _adapter_manifest(normalizer.manifest)
    registry = _registry(normalizer)

    with pytest.raises(AgentKernelError) as adapter_error:
        registry.normalize(
            _proposal(),
            _context(normalizer),
            adapter_manifest=manifest,
            expected_adapter_manifest_digest=_DIGEST_ZERO,
            provenance_records=(_provenance(),),
        )
    assert adapter_error.value.code is ErrorCode.INTEGRITY_ERROR

    with pytest.raises(AgentKernelError) as config_error:
        registry.normalize(
            _proposal(),
            _context(normalizer, configuration_digest=_DIGEST_ZERO),
            adapter_manifest=manifest,
            expected_adapter_manifest_digest=manifest.digest,
            provenance_records=(_provenance(),),
        )
    assert config_error.value.code is ErrorCode.INTEGRITY_ERROR

    missing = _adapter_manifest(None)
    with pytest.raises(AgentKernelError) as metadata_error:
        registry.normalize(
            _proposal(),
            _context(normalizer),
            adapter_manifest=missing,
            expected_adapter_manifest_digest=missing.digest,
            provenance_records=(_provenance(),),
        )
    assert metadata_error.value.code is ErrorCode.INTEGRITY_ERROR


def test_registry_rejects_duplicate_registration() -> None:
    normalizer = FilesystemWriteFilesNormalizer()
    registry = _registry(normalizer)
    with pytest.raises(AgentKernelError) as captured:
        registry.register("filesystem", "write_files", normalizer, reviewed=True)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize("noncanonical", ["cafe\u0301", "\ud800"])
def test_adapter_manifest_rejects_noncanonical_operation_semantics(
    noncanonical: str,
) -> None:
    normalizer = FilesystemWriteFilesNormalizer()
    operation = OperationManifest(
        risk_floor=RiskClass.READ_ONLY,
        effect_domains=("filesystem",),
        staging=False,
        commit=False,
        abort=False,
        rollback=False,
        reconcile=False,
        normalizer=normalizer.manifest,
    )

    with pytest.raises(ValidationError):
        AdapterManifest(
            name="filesystem",
            version="1.0.0",
            implementation_digest=_DIGEST_ZERO,
            operations={noncanonical: operation},
        )

    with pytest.raises(ValidationError):
        type(operation).model_validate(
            operation.model_dump(mode="python") | {"preconditions": (noncanonical,)}
        )


def test_registry_revalidates_bypassed_manifest_and_proposal_instances() -> None:
    normalizer = FilesystemWriteFilesNormalizer()
    valid = _adapter_manifest(normalizer.manifest)
    operation = valid.operations["write_files"]
    nfc_manifest = valid.model_copy(update={"operations": {"café": operation}})
    bypassed_manifest = valid.model_copy(update={"operations": {"cafe\u0301": operation}})
    assert nfc_manifest.digest == bypassed_manifest.digest

    with pytest.raises(AgentKernelError) as manifest_error:
        _registry(normalizer).normalize(
            _proposal(),
            _context(normalizer),
            adapter_manifest=bypassed_manifest,
            expected_adapter_manifest_digest=bypassed_manifest.digest,
            provenance_records=(_provenance(),),
        )
    assert manifest_error.value.code is ErrorCode.INTEGRITY_ERROR

    bypassed_proposal = _proposal().model_copy(update={"operation": "write_files\u0301"})
    with pytest.raises(AgentKernelError) as proposal_error:
        _registry(normalizer).normalize(
            bypassed_proposal,
            _context(normalizer),
            adapter_manifest=valid,
            expected_adapter_manifest_digest=valid.digest,
            provenance_records=(_provenance(),),
        )
    assert proposal_error.value.code is ErrorCode.VALIDATION_ERROR


def test_unexpected_normalizer_failure_is_a_stable_fail_closed_error() -> None:
    normalizer = FilesystemWriteFilesNormalizer()

    class BrokenNormalizer:
        manifest = normalizer.manifest
        configuration_digest = normalizer.configuration_digest

        def normalize(self, **_kwargs: object) -> NormalizedAction:
            raise ValueError("implementation detail that must not cross the boundary")

    registry = NormalizerRegistry()
    registry.register("filesystem", "write_files", BrokenNormalizer(), reviewed=True)
    manifest = _adapter_manifest(normalizer.manifest)

    with pytest.raises(AgentKernelError) as captured:
        registry.normalize(
            _proposal(),
            _context(normalizer),
            adapter_manifest=manifest,
            expected_adapter_manifest_digest=manifest.digest,
            provenance_records=(_provenance(),),
        )

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    assert "implementation detail" not in str(captured.value)


@pytest.mark.parametrize(
    "resource",
    [
        "fs://workspace/café.txt",
        "fs://workspace/caf%c3%a9.txt",
        "fs://workspace/%61.txt",
        "fs://workspace/%2E%2E/secret.txt",
        "fs://workspace/encoded%2Fslash.txt",
        "fs://workspace/%00",
        "fs://workspace/CON",
        "FS://workspace/file.txt",
        "fs://Workspace/file.txt",
        "http://EXAMPLE.com:80/safe/../admin",
        "http://example.com/safe//x",
        "https://user@example.com/private",
        "https://example.com:443/private",
    ],
)
def test_resource_use_rejects_noncanonical_uris(resource: str) -> None:
    with pytest.raises(ValidationError):
        ResourceUse(
            authority_action="fs.read",
            access_mode=ResourceAccessMode.READ,
            canonical_resource=resource,
            effect_domain="filesystem",
            purpose="test",
            use_kind=ResourceUseKind.PRECONDITION_READ,
            destination_external=False,
        )


def test_path_within_utf8_limit_but_over_encoded_uri_limit_is_rejected_at_ingress() -> None:
    segment = f"{' ' * 254}a"
    path = "/".join(segment for _ in range(16))
    assert len(path.encode("utf-8")) == 4095

    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal({path: "content"}))

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert "canonical resource URI limit" in str(captured.value)


def test_provenance_union_over_resource_label_limit_is_rejected_at_ingress() -> None:
    records = tuple(
        ProvenanceRecord(
            provenance_id=f"prov_{index:03}",
            source="artifact:request",
            acquisition_step="step_capture",
            trust=ProvenanceTrust.AUTHORIZED_USER,
            data_classes=(f"class_{index:03}",),
            integrity_ref=canonical_digest({"source": index}),
        )
        for index in range(65)
    )
    proposal = _proposal(
        {"secret.txt": "content"},
        provenance_ids=tuple(record.provenance_id for record in records),
    )

    with pytest.raises(AgentKernelError) as captured:
        _normalize(proposal, records=records)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert "data-class limit" in str(captured.value)


def test_full_tree_verifier_inherits_sensitive_output_provenance() -> None:
    record = ProvenanceRecord(
        provenance_id="prov_secret",
        source="artifact:request",
        acquisition_step="step_capture",
        trust=ProvenanceTrust.AUTHORIZED_USER,
        data_classes=("credential",),
        integrity_ref=canonical_digest({"source": "secret"}),
    )
    action = _normalize(
        _proposal({"secret.txt": "content"}, provenance_ids=(record.provenance_id,)),
        records=(record,),
    )
    verifier = next(
        use for use in action.resource_uses if use.use_kind is ResourceUseKind.VERIFIER_READ
    )

    assert verifier.canonical_resource == "fs://workspace/**"
    assert verifier.data_classes == ("credential", "project_data")
    assert verifier.provenance_ids == (record.provenance_id,)


@pytest.mark.parametrize(
    ("field_name", "values"),
    [
        ("data_classes", tuple(f"class_{index:03}" for index in range(65))),
        ("parent_ids", tuple(f"prov_{index:03}" for index in range(257))),
        ("transformations", tuple(f"step_{index:03}" for index in range(257))),
    ],
)
def test_public_provenance_record_rejects_oversized_collections(
    field_name: str,
    values: tuple[str, ...],
) -> None:
    payload = _provenance().model_dump(mode="python")
    payload[field_name] = values

    with pytest.raises(ValidationError, match="too_long"):
        ProvenanceRecord.model_validate(payload)


def test_registry_rejects_provenance_record_count_before_record_revalidation() -> None:
    records = tuple(_provenance(f"prov_{index:03}") for index in range(257))

    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal(), records=records)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert "record count" in str(captured.value)


def test_provenance_record_rejects_same_digest_non_nfc_data_class_alias() -> None:
    composed = ProvenanceRecord.model_validate(
        {
            **_provenance().model_dump(mode="python"),
            "data_classes": ("café",),
        }
    )
    bypassed = composed.model_copy(update={"data_classes": ("cafe\u0301",)})
    assert canonical_digest(composed) == canonical_digest(bypassed)

    with pytest.raises(ValidationError, match="Unicode NFC"):
        ProvenanceRecord.model_validate(bypassed.model_dump(mode="python"))

    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal(), records=(bypassed,))
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_normalized_contracts_are_strict_frozen_and_ordered() -> None:
    action = _normalize(_proposal({"b.txt": "b", "a.txt": "a"}))
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AuthenticatedActionContext.model_validate(
            {**_context(FilesystemWriteFilesNormalizer()).model_dump(), "unknown": True}
        )
    with pytest.raises(ValidationError, match="Instance is frozen"):
        action.intent_hash = _DIGEST_ZERO

    payload = action.model_dump(mode="python")
    payload["resource_uses"] = tuple(reversed(payload["resource_uses"]))
    with pytest.raises(ValidationError, match="sorted and unique"):
        NormalizedAction.model_validate(payload)

    extra = action.model_dump(mode="python")
    extra["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        NormalizedAction.model_validate(extra)


def test_resource_use_cannot_hide_data_classes_inherited_from_provenance() -> None:
    action = _normalize(_proposal({"secret.txt": "content"}))
    payload = action.model_dump(mode="python")
    original = next(
        use for use in action.resource_uses if use.use_kind is ResourceUseKind.AUTHORITATIVE_EFFECT
    )
    forged = ResourceUse.model_validate(
        {
            **original.model_dump(mode="python"),
            "data_classes": ("public",),
        }
    )
    payload["resource_uses"] = tuple(
        sorted(
            (forged if use == original else use for use in action.resource_uses),
            key=lambda use: use.sort_key(),
        )
    )

    with pytest.raises(ValidationError, match="every data class inherited"):
        NormalizedAction.model_validate(payload)


def test_resource_use_cannot_drop_semantic_argument_provenance() -> None:
    action = _normalize(_proposal({"secret.txt": "content"}))
    payload = action.model_dump(mode="python")
    original = next(
        use for use in action.resource_uses if use.use_kind is ResourceUseKind.AUTHORITATIVE_EFFECT
    )
    forged = ResourceUse.model_validate(
        {
            **original.model_dump(mode="python"),
            "data_classes": ("public",),
            "provenance_ids": (),
        }
    )
    payload["resource_uses"] = tuple(
        sorted(
            (forged if use == original else use for use in action.resource_uses),
            key=lambda use: use.sort_key(),
        )
    )

    with pytest.raises(ValidationError, match="inherit provenance from semantic arguments"):
        NormalizedAction.model_validate(payload)


@pytest.mark.parametrize(
    "model",
    [
        AuthenticatedActionContext,
        ResourceUse,
        SemanticArgument,
        NormalizedProvenance,
        NormalizedIntentProjection,
        NormalizedAction,
        NormalizerManifest,
        WriteFilesArguments,
        FilesystemNormalizerConfig,
    ],
    ids=lambda model: model.__name__,
)
def test_public_normalization_schemas_reject_unknown_fields(
    model: type[BaseModel],
) -> None:
    schema = model.model_json_schema(mode="validation")
    assert schema["additionalProperties"] is False
    assert all(
        definition.get("additionalProperties") is False
        for definition in schema.get("$defs", {}).values()
        if definition.get("type") == "object"
    )


def test_write_files_manifest_pins_the_exported_operation_schema() -> None:
    exported = json.loads(
        Path("schemas/v1alpha1/WriteFilesArguments.schema.json").read_text(encoding="utf-8")
    )
    assert FilesystemWriteFilesNormalizer().manifest.schema_digest == canonical_digest(exported)


def test_absent_normalizer_extension_preserves_a0_manifest_digest() -> None:
    manifest = _adapter_manifest(None)
    legacy_material = manifest.model_dump(mode="python", exclude_none=True)
    assert manifest.digest == canonical_digest(legacy_material)
