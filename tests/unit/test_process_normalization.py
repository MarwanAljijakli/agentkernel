from __future__ import annotations

import builtins
import os
import shutil
import socket
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import agentkernel.normalization.process as process_normalization
import pytest
from agentkernel.adapters.base import NormalizerManifest
from agentkernel.canonical import canonical_digest
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
    NormalizedProvenance,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.normalization.base import AdmittedOperation
from agentkernel.normalization.process import (
    PROCESS_RUN_ALLOWLISTED_NORMALIZER_MANIFEST,
    ProcessCommandDefinition,
    ProcessNormalizerConfig,
    ProcessRunAllowlistedNormalizer,
    RunAllowlistedArguments,
)
from pydantic import BaseModel, ValidationError

_NOW = datetime(2026, 7, 23, 12, tzinfo=UTC)
_DIGEST_ZERO = "sha256:" + "0" * 64
_EXECUTABLE_DIGEST = "sha256:" + "1" * 64
_ADAPTER_DIGEST = "sha256:" + "2" * 64
_FIXED_ENVIRONMENT_DIGEST = "sha256:" + "3" * 64


def _command(**updates: object) -> ProcessCommandDefinition:
    values: dict[str, object] = {
        "command_id": "pytest",
        "version": "8.3.5",
        "executable_digest": _EXECUTABLE_DIGEST,
        "fixed_environment_digest": _FIXED_ENVIRONMENT_DIGEST,
        "allow_workspace_reads": True,
        "allow_workspace_writes": True,
        "max_argv_items": 16,
        "max_argv_item_bytes": 256,
        "max_argv_bytes": 1024,
        "max_workspace_reads": 8,
        "max_workspace_writes": 8,
    }
    values.update(updates)
    return ProcessCommandDefinition.model_validate(values)


def _config(
    command: ProcessCommandDefinition | None = None,
    **updates: object,
) -> ProcessNormalizerConfig:
    values: dict[str, object] = {
        "commands": (command or _command(),),
        "workspace_data_classes": ("project_data",),
    }
    values.update(updates)
    return ProcessNormalizerConfig.model_validate(values)


def _normalizer(
    command: ProcessCommandDefinition | None = None,
    **config_updates: object,
) -> ProcessRunAllowlistedNormalizer:
    return ProcessRunAllowlistedNormalizer(_config(command, **config_updates))


def _arguments(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "command_id": "pytest",
        "argv": ["-q", "tests/unit"],
        "cwd": "repo",
        "env": {},
        "workspace_reads": ["pyproject.toml", "tests/unit/test_example.py"],
        "workspace_writes": ["reports/test-results.json"],
    }
    values.update(updates)
    return values


def _proposal(
    arguments: dict[str, object] | None = None,
    **updates: object,
) -> ActionProposal:
    values: dict[str, object] = {
        "goal_id": "goal_process",
        "transaction_id": "tx_process",
        "agent_id": "agent:scripted:test",
        "adapter": "process",
        "adapter_version": "0.1.0",
        "operation": "run_allowlisted",
        "arguments": arguments or _arguments(),
        "provenance_ids": ("prov_input",),
        "capability_refs": ("cap_process",),
        "deadline": _NOW + timedelta(minutes=5),
        "idempotency_key": "idem-process",
    }
    values.update(updates)
    return ActionProposal.model_validate(values)


def _provenance(
    provenance_id: str = "prov_input",
    *,
    data_classes: tuple[str, ...] = ("credential", "public"),
) -> NormalizedProvenance:
    return NormalizedProvenance(
        provenance_id=provenance_id,
        trust=ProvenanceTrust.AUTHORIZED_USER,
        data_classes=data_classes,
        record_digest=canonical_digest({"source": provenance_id}),
    )


def _context(
    normalizer: ProcessRunAllowlistedNormalizer,
    **updates: object,
) -> AuthenticatedActionContext:
    values: dict[str, object] = {
        "tenant_id": "tenant_local",
        "principal_id": "principal:user",
        "goal_id": "goal_process",
        "run_id": "run_process",
        "trace_id": "trace_process",
        "actor_id": "service:kernel",
        "on_behalf_of": "principal:user",
        "agent_id": "agent:scripted:test",
        "configuration_digest": normalizer.configuration_digest,
    }
    values.update(updates)
    return AuthenticatedActionContext.model_validate(values)


def _operation(
    normalizer: ProcessRunAllowlistedNormalizer,
    **updates: object,
) -> AdmittedOperation:
    values: dict[str, object] = {
        "adapter": "process",
        "adapter_version": "0.1.0",
        "adapter_manifest_digest": _ADAPTER_DIGEST,
        "operation": "run_allowlisted",
        "risk_floor": RiskClass.REVERSIBLE,
        "effect_domains": ("filesystem", "process"),
        "normalizer_manifest": normalizer.manifest,
        "configuration_digest": normalizer.configuration_digest,
    }
    values.update(updates)
    return AdmittedOperation.model_validate(values)


def _normalize(
    proposal: ActionProposal | None = None,
    *,
    normalizer: ProcessRunAllowlistedNormalizer | None = None,
    context: AuthenticatedActionContext | None = None,
    operation: AdmittedOperation | None = None,
    provenance: tuple[NormalizedProvenance, ...] = (_provenance(),),
) -> NormalizedAction:
    active_normalizer = normalizer or _normalizer()
    return active_normalizer.normalize(
        proposal=proposal or _proposal(),
        context=context or _context(active_normalizer),
        operation=operation or _operation(active_normalizer),
        provenance=provenance,
    )


def test_run_allowlisted_normalizes_exact_resources_and_command_identity() -> None:
    canary = "SYNTHETIC-ARGV-SECRET-MUST-NOT-BE-RETAINED"
    action = _normalize(_proposal(_arguments(argv=["-q", canary])))

    execution = next(
        use for use in action.resource_uses if use.use_kind is ResourceUseKind.PROCESS_EXECUTION
    )
    assert execution.canonical_resource == "process://allowlist/pytest%408.3.5"
    assert execution.authority_action == "process.exec"
    assert execution.access_mode is ResourceAccessMode.EXECUTE
    assert execution.effect_domain == "process"
    assert execution.destination_external is False

    filesystem_uses = tuple(
        use for use in action.resource_uses if use.effect_domain == "filesystem"
    )
    assert {use.canonical_resource for use in filesystem_uses} == {
        "fs://workspace/repo",
        "fs://workspace/pyproject.toml",
        "fs://workspace/tests/unit/test_example.py",
        "fs://workspace/reports/test-results.json",
    }
    assert all(not use.canonical_resource.endswith("/**") for use in filesystem_uses)
    assert {
        use.use_kind
        for use in filesystem_uses
        if use.canonical_resource == "fs://workspace/reports/test-results.json"
    } == {ResourceUseKind.AUTHORITATIVE_EFFECT, ResourceUseKind.VERIFIER_READ}
    assert all(use.provenance_ids == ("prov_input",) for use in action.resource_uses)
    assert all(
        use.data_classes == ("credential", "project_data", "public") for use in action.resource_uses
    )
    assert {argument.argument_name for argument in action.semantic_arguments} == {
        "argv",
        "cwd",
        "fixed_environment",
        "workspace_reads",
        "workspace_writes",
    }
    fixed_environment = next(
        argument
        for argument in action.semantic_arguments
        if argument.argument_name == "fixed_environment"
    )
    assert fixed_environment.provenance_ids == ()
    assert all(
        argument.provenance_ids == ("prov_input",)
        for argument in action.semantic_arguments
        if argument.argument_name != "fixed_environment"
    )
    assert canary not in action.model_dump_json()


def test_normalization_is_deterministic_for_set_and_mapping_order() -> None:
    first = _normalize(
        _proposal(
            _arguments(
                workspace_reads=["tests/unit/test_example.py", "pyproject.toml"],
            )
        )
    )
    second = _normalize(
        _proposal(
            _arguments(
                workspace_reads=["pyproject.toml", "tests/unit/test_example.py"],
            )
        )
    )

    assert first.intent_hash == second.intent_hash
    assert first.resource_uses == second.resource_uses
    assert first.semantic_arguments == second.semantic_arguments


def test_configuration_and_command_digests_bind_all_deployment_owned_identity() -> None:
    command = _command()
    config = _config(command)
    changed_version = _config(_command(version="8.3.6"))
    changed_executable = _config(_command(executable_digest=_DIGEST_ZERO))
    changed_environment = _config(_command(fixed_environment_digest=_DIGEST_ZERO))

    assert command.digest == canonical_digest(command)
    assert config.digest == canonical_digest(config)
    assert config.digest != changed_version.digest
    assert config.digest != changed_executable.digest
    assert config.digest != changed_environment.digest
    assert _normalize(normalizer=ProcessRunAllowlistedNormalizer(config)).configuration_digest == (
        config.digest
    )


@pytest.mark.parametrize("field_name", ["executable", "executable_path", "path", "shell"])
def test_proposal_cannot_supply_executable_resolution_or_shell_fields(field_name: str) -> None:
    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal(_arguments(**{field_name: "/bin/sh"})))

    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_command_version_and_executable_identity_come_only_from_allowlisted_config() -> None:
    action = _normalize(_proposal(_arguments(command_id="pytest")))
    assert set(_proposal().arguments) == {
        "command_id",
        "argv",
        "cwd",
        "env",
        "workspace_reads",
        "workspace_writes",
    }
    assert action.resource_uses[-1].canonical_resource == "process://allowlist/pytest%408.3.5"

    changed_version_normalizer = _normalizer(_command(version="8.3.6"))
    changed_version = _normalize(normalizer=changed_version_normalizer)
    assert changed_version.resource_uses[-1].canonical_resource == (
        "process://allowlist/pytest%408.3.6"
    )
    changed_executable_normalizer = _normalizer(_command(executable_digest=_DIGEST_ZERO))
    changed_executable = _normalize(normalizer=changed_executable_normalizer)
    assert changed_executable.resource_uses[-1].canonical_resource == (
        "process://allowlist/pytest%408.3.5"
    )
    assert changed_executable.intent_hash != action.intent_hash
    changed_environment_normalizer = _normalizer(_command(fixed_environment_digest=_DIGEST_ZERO))
    changed_environment = _normalize(normalizer=changed_environment_normalizer)
    assert changed_environment.resource_uses[-1].canonical_resource == (
        "process://allowlist/pytest%408.3.5"
    )
    assert changed_environment.intent_hash != action.intent_hash

    with pytest.raises(AgentKernelError) as unknown:
        _normalize(_proposal(_arguments(command_id="ruff")))
    assert unknown.value.code is ErrorCode.AUTHORITY_MISSING

    with pytest.raises(AgentKernelError) as path_like:
        _normalize(_proposal(_arguments(command_id="bin/pytest")))
    assert path_like.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize(
    "environment_name",
    [
        "LANG",
        "HOME",
        "Path",
        "PATH",
        "PATHEXT",
        "COMSPEC",
        "SHELL",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONWARNINGS",
        "NODE_OPTIONS",
        "BASH_ENV",
        "ENV",
        "RUBYOPT",
        "PERL5OPT",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "BASH_FUNC_PAYLOAD",
    ],
)
def test_proposal_controlled_environment_is_always_rejected(
    environment_name: str,
) -> None:
    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal(_arguments(env={environment_name: "attacker-controlled"})))
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_fixed_environment_identity_is_deployment_owned_and_defaults_to_empty() -> None:
    command = ProcessCommandDefinition(
        command_id="pytest",
        version="8.3.5",
        executable_digest=_EXECUTABLE_DIGEST,
    )
    assert command.fixed_environment_digest == canonical_digest({})

    normalizer = _normalizer(command)
    action = _normalize(
        _proposal(_arguments(env={}, workspace_reads=[], workspace_writes=[])),
        normalizer=normalizer,
    )
    assert action.operation == "run_allowlisted"
    environment_argument = next(
        argument
        for argument in action.semantic_arguments
        if argument.argument_name == "fixed_environment"
    )
    assert environment_argument.media_type.endswith("fixed-environment-reference+json")


def test_environment_schema_and_command_config_expose_no_dynamic_environment_knobs() -> None:
    argument_schema = RunAllowlistedArguments.model_json_schema(mode="validation")
    command_schema = ProcessCommandDefinition.model_json_schema(mode="validation")

    assert argument_schema["properties"]["env"]["maxProperties"] == 0
    assert "allowed_env_names" not in command_schema["properties"]
    assert "max_env_items" not in command_schema["properties"]
    assert "max_env_value_bytes" not in command_schema["properties"]
    assert "max_env_bytes" not in command_schema["properties"]


def test_global_count_bound_runs_before_size_walk_or_model_copy(monkeypatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("expensive validation ran before the cheap count guard")

    monkeypatch.setattr(process_normalization, "bounded_json_size", forbidden)
    monkeypatch.setattr(RunAllowlistedArguments, "model_validate", forbidden)
    oversized = _proposal(_arguments(argv=["x"] * 257))

    with pytest.raises(AgentKernelError) as captured:
        _normalize(oversized)
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_command_byte_bound_runs_before_canonical_payload_allocation(monkeypatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("canonical payload allocation ran before command byte bounds")

    command = _command(max_argv_item_bytes=8, max_argv_bytes=8)
    normalizer = _normalizer(command)
    monkeypatch.setattr(process_normalization, "canonical_json_bytes", forbidden)

    with pytest.raises(AgentKernelError) as captured:
        _normalize(
            _proposal(_arguments(argv=["012345678"])),
            normalizer=normalizer,
        )
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


@pytest.mark.parametrize(
    "arguments",
    [
        _arguments(argv=["cafe\u0301"]),
        _arguments(argv=["line\nbreak"]),
        _arguments(argv=["nul\x00byte"]),
        _arguments(argv=["zero\u200dwidth"]),
        _arguments(cwd="cafe\u0301"),
        _arguments(cwd="repo/line\nbreak"),
    ],
)
def test_non_nfc_nul_controls_and_format_codepoints_are_rejected(
    arguments: dict[str, object],
) -> None:
    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal(arguments))
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize(
    "cwd",
    [
        ".",
        "./src",
        "src/../outside",
        "../outside",
        "/absolute",
        "C:/absolute",
        "src\\module",
        "src//module",
        "src/",
        "CON",
        "aux.txt",
        "src/%2E%2E",
        "src:stream",
        "trailing.",
    ],
)
def test_cwd_rejects_traversal_absolute_and_portability_aliases(cwd: str) -> None:
    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal(_arguments(cwd=cwd)))
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_empty_cwd_is_the_only_canonical_workspace_root_representation() -> None:
    action = _normalize(_proposal(_arguments(cwd="")))
    cwd = next(
        argument for argument in action.semantic_arguments if argument.argument_name == "cwd"
    )
    assert cwd.resource == "fs://workspace"


def test_percent_encoding_expansion_has_a_stable_canonical_resource_limit() -> None:
    segment = f"{' ' * 254}a"
    path = "/".join(segment for _ in range(16))
    assert len(path.encode("utf-8")) == 4095

    with pytest.raises(AgentKernelError) as captured:
        _normalize(_proposal(_arguments(cwd=path, workspace_reads=[], workspace_writes=[])))
    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert "canonical resource URI" in str(captured.value)


def test_linux_ext4_profile_preserves_case_across_separate_intents() -> None:
    upper = _normalize(
        _proposal(
            _arguments(
                cwd="Repo",
                workspace_reads=["Source/Input.py"],
                workspace_writes=["Reports/Output.json"],
            )
        )
    )
    lower = _normalize(
        _proposal(
            _arguments(
                cwd="repo",
                workspace_reads=["source/input.py"],
                workspace_writes=["reports/output.json"],
            )
        )
    )

    assert upper.intent_hash != lower.intent_hash
    assert upper.resource_uses != lower.resource_uses
    assert upper.semantic_arguments != lower.semantic_arguments
    assert "fs://workspace/Repo" in {use.canonical_resource for use in upper.resource_uses}
    assert "fs://workspace/repo" in {use.canonical_resource for use in lower.resource_uses}


def test_linux_ext4_profile_allows_distinct_case_sensitive_resources_in_one_action() -> None:
    action = _normalize(
        _proposal(
            _arguments(
                cwd="Repo",
                workspace_reads=["repo"],
                workspace_writes=["Reports/output.json", "reports/output.json"],
            )
        )
    )
    resources = {use.canonical_resource for use in action.resource_uses}
    assert "fs://workspace/Repo" in resources
    assert "fs://workspace/repo" in resources
    assert "fs://workspace/Reports/output.json" in resources
    assert "fs://workspace/reports/output.json" in resources


def test_case_insensitive_configuration_is_rejected_until_verified_by_an_adapter() -> None:
    case_schema = ProcessNormalizerConfig.model_json_schema(mode="validation")["properties"][
        "path_case_mode"
    ]
    assert case_schema["const"] == "sensitive"
    assert case_schema["default"] == "sensitive"

    with pytest.raises(ValidationError):
        _config(path_case_mode="insensitive")


@pytest.mark.parametrize(
    "resource_root",
    ["fs://workspace?", "fs://workspace#", "fs://workspace?#"],
)
def test_resource_root_rejects_empty_query_and_fragment_aliases(
    resource_root: str,
) -> None:
    with pytest.raises(ValidationError, match="query or fragment"):
        _config(resource_root=resource_root)


def test_workspace_declarations_are_exact_bounded_and_command_gated() -> None:
    command = _command(
        allow_workspace_reads=False,
        allow_workspace_writes=False,
        max_workspace_reads=0,
        max_workspace_writes=0,
    )
    normalizer = _normalizer(command)
    with pytest.raises(AgentKernelError) as captured:
        _normalize(
            _proposal(_arguments(workspace_reads=["input.txt"], workspace_writes=[])),
            normalizer=normalizer,
        )
    assert captured.value.code is ErrorCode.AUTHORITY_MISSING

    action = _normalize(
        _proposal(_arguments(workspace_reads=[], workspace_writes=[])),
        normalizer=normalizer,
    )
    assert {use.canonical_resource for use in action.resource_uses} == {
        "fs://workspace/repo",
        "process://allowlist/pytest%408.3.5",
    }


def test_all_resource_and_semantic_uses_inherit_complete_provenance() -> None:
    provenance = (
        _provenance("prov_a", data_classes=("credential",)),
        _provenance("prov_b", data_classes=("external",)),
    )
    proposal = _proposal(provenance_ids=("prov_a", "prov_b"))
    action = _normalize(proposal, provenance=provenance)

    assert all(use.provenance_ids == ("prov_a", "prov_b") for use in action.resource_uses)
    assert all(
        use.data_classes == ("credential", "external", "project_data")
        for use in action.resource_uses
    )
    assert all(
        argument.provenance_ids == ("prov_a", "prov_b")
        for argument in action.semantic_arguments
        if argument.argument_name != "fixed_environment"
    )
    assert (
        next(
            argument
            for argument in action.semantic_arguments
            if argument.argument_name == "fixed_environment"
        ).provenance_ids
        == ()
    )

    with pytest.raises(AgentKernelError) as missing:
        _normalize(proposal, provenance=(provenance[0],))
    assert missing.value.code is ErrorCode.INTEGRITY_ERROR


def test_normalization_does_not_touch_files_processes_network_or_path_lookup(monkeypatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("pure process normalization attempted ambient I/O")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(os, "stat", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)

    action = _normalize()
    assert action.operation == "run_allowlisted"


@pytest.mark.parametrize(
    ("binding", "expected_code"),
    [
        ("context_config", ErrorCode.INTEGRITY_ERROR),
        ("operation_config", ErrorCode.INTEGRITY_ERROR),
        ("schema_digest", ErrorCode.INTEGRITY_ERROR),
        ("schema_ref", ErrorCode.INTEGRITY_ERROR),
        ("implementation", ErrorCode.INTEGRITY_ERROR),
    ],
)
def test_manifest_schema_and_configuration_mismatches_fail_closed(
    binding: str,
    expected_code: ErrorCode,
) -> None:
    normalizer = _normalizer()
    context = _context(normalizer)
    operation = _operation(normalizer)
    active_normalizer = normalizer
    if binding == "context_config":
        context = _context(normalizer, configuration_digest=_DIGEST_ZERO)
    elif binding == "operation_config":
        operation = _operation(normalizer, configuration_digest=_DIGEST_ZERO)
    else:
        tampered_manifest = normalizer.manifest.model_copy(
            update={binding: _DIGEST_ZERO if binding == "schema_digest" else "process.other"}
        )
        if binding == "implementation":
            active_normalizer = ProcessRunAllowlistedNormalizer(
                normalizer.config,
                tampered_manifest,
            )
        operation = _operation(active_normalizer, normalizer_manifest=tampered_manifest)

    with pytest.raises(AgentKernelError) as captured:
        _normalize(
            normalizer=active_normalizer,
            context=context,
            operation=operation,
        )
    assert captured.value.code is expected_code


def test_bypassed_or_noncanonical_configuration_fails_strict_revalidation() -> None:
    valid = _config()
    invalid_command = _command().model_copy(update={"command_id": "Zed"})
    bypassed = valid.model_copy(update={"commands": (invalid_command,)})
    normalizer = ProcessRunAllowlistedNormalizer(bypassed)
    with pytest.raises(AgentKernelError) as captured:
        _normalize(
            normalizer=normalizer,
            context=_context(normalizer),
            operation=_operation(normalizer),
        )
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_process_configuration_models_are_strict_frozen_and_deeply_immutable() -> None:
    command = _command()
    config = _config(command)

    with pytest.raises(ValidationError, match="valid integer"):
        _command(max_argv_items="16")
    with pytest.raises(ValidationError, match="valid tuple"):
        ProcessNormalizerConfig.model_validate({"commands": [command]})
    with pytest.raises(ValidationError, match="Instance is frozen"):
        command.version = "9.0.0"
    with pytest.raises(ValidationError, match="Instance is frozen"):
        config.commands = ()
    assert isinstance(config.commands, tuple)
    assert command.fixed_environment_digest == _FIXED_ENVIRONMENT_DIGEST


@pytest.mark.parametrize("data_class", ["line\nbreak", "nul\x00byte", "zero\u200dwidth"])
def test_configuration_data_classes_reject_controls_and_format_codepoints(
    data_class: str,
) -> None:
    with pytest.raises(ValidationError):
        _config(workspace_data_classes=(data_class,))


@pytest.mark.parametrize(
    "model",
    [RunAllowlistedArguments, ProcessCommandDefinition, ProcessNormalizerConfig],
    ids=lambda model: model.__name__,
)
def test_process_normalization_schemas_reject_unknown_fields(
    model: type[BaseModel],
) -> None:
    schema = model.model_json_schema(mode="validation")
    assert schema["additionalProperties"] is False
    assert all(
        definition.get("additionalProperties") is False
        for definition in schema.get("$defs", {}).values()
        if definition.get("type") == "object"
    )


def test_manifest_pins_exact_argument_schema_and_resource_bounds() -> None:
    manifest = PROCESS_RUN_ALLOWLISTED_NORMALIZER_MANIFEST
    assert manifest.schema_digest == canonical_digest(
        RunAllowlistedArguments.model_json_schema(mode="validation")
    )
    assert manifest.max_resources == 770
    assert manifest.max_argument_bytes == 262_144


def test_admitted_effect_domains_require_explicit_filesystem_and_process_uses() -> None:
    normalizer = _normalizer()
    with pytest.raises(AgentKernelError) as captured:
        _normalize(
            normalizer=normalizer,
            operation=_operation(normalizer, effect_domains=("process",)),
        )
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR

    action = _normalize(normalizer=normalizer)
    assert {use.effect_domain for use in action.resource_uses} == {
        "filesystem",
        "process",
    }


def test_normalizer_manifest_cannot_be_replaced_even_when_admission_matches_it() -> None:
    normalizer = _normalizer()
    tampered = NormalizerManifest.model_validate(
        normalizer.manifest.model_dump(mode="python")
        | {"max_argument_bytes": normalizer.manifest.max_argument_bytes - 1}
    )
    replaced = ProcessRunAllowlistedNormalizer(normalizer.config, tampered)

    with pytest.raises(AgentKernelError) as captured:
        _normalize(
            normalizer=replaced,
            context=_context(replaced),
            operation=_operation(replaced),
        )
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
