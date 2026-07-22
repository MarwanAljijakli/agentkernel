"""Stable, non-interactive command-line entry point for the foundation release."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import platform
import re
import shutil
import sqlite3
import subprocess  # nosec B404
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any, Never

from pydantic import BaseModel

from agentkernel import __version__
from agentkernel.demo import DemoReport, run_demo
from agentkernel.domain.models import (
    ActionExecutionRecord,
    ActionProposal,
    Artifact,
    BenchmarkTask,
    CapabilityGrant,
    EffectReceipt,
    EventEnvelope,
    GoalRecord,
    IntentRecord,
    PolicyBundle,
    ProvenanceRecord,
    RecoveryReport,
    TransactionRecord,
    VerificationReport,
)
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.ledger import validate_chain
from agentkernel.model_gateway.gateway import (
    MessagePart,
    ModelInferenceReceipt,
    ModelInferenceRequest,
    ModelResponse,
)
from agentkernel.sandbox.docker import DockerSandbox

SCHEMA_MODELS: tuple[type[BaseModel], ...] = (
    GoalRecord,
    ActionProposal,
    CapabilityGrant,
    ProvenanceRecord,
    PolicyBundle,
    TransactionRecord,
    ActionExecutionRecord,
    IntentRecord,
    EventEnvelope,
    Artifact,
    EffectReceipt,
    VerificationReport,
    RecoveryReport,
    BenchmarkTask,
    DemoReport,
    MessagePart,
    ModelInferenceRequest,
    ModelResponse,
    ModelInferenceReceipt,
)

_REQUIRED_DOCKER_CONTROLS = (
    "non_root_user",
    "read_only_root",
    "network_none",
    "all_capabilities_dropped",
    "no_new_privileges",
    "pids_limited",
    "memory_limited",
    "cpu_limited",
    "no_host_mounts",
    "bounded_tmpfs",
)
_CLI_MAX_DEPTH = 8
_CLI_MAX_ITEMS = 256
_CLI_MAX_TEXT_BYTES = 4096
_SENSITIVE_FIELD_NAMES = frozenset(
    {"stdout", "stderr", "prompt", "payload", "content", "message", "details"}
)
_SAFE_SENSITIVE_CLI_KEYS = frozenset({"protected_read_canary_count", "secret_found_in_evidence"})
_SENSITIVE_WORD_RE = re.compile(
    r"(?i)(?:^|[_-])(?:secret|token|password|canary|private[_-]?key|api[_-]?key)(?:[_-]|$)"
)
_LONG_HEX_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32,}(?![0-9a-f])")
_LONG_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/])")
_SAFE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_IMAGE_RE = re.compile(r"^[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")
_DOCKER_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]{1,32})?$")


def _redacted_text_summary(value: str) -> dict[str, object]:
    encoded = value.encode("utf-8", errors="replace")
    return {
        "redacted": True,
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _redacted_value_summary(value: Any) -> dict[str, object]:
    try:
        serialized = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            default=lambda item: type(item).__name__,
        ).encode("utf-8", errors="replace")
    except (TypeError, ValueError):
        serialized = type(value).__name__.encode("ascii", errors="replace")
    return {
        "redacted": True,
        "bytes": len(serialized),
        "sha256": hashlib.sha256(serialized).hexdigest(),
    }


def _looks_sensitive(value: str) -> bool:
    if _SAFE_DIGEST_RE.fullmatch(value) or _SAFE_IMAGE_RE.fullmatch(value):
        return False
    return bool(
        _SENSITIVE_WORD_RE.search(value)
        or _LONG_HEX_RE.search(value)
        or _LONG_BASE64_RE.search(value)
    )


def _sanitize_cli_value(
    value: Any,
    *,
    field_name: str | None = None,
    depth: int = 0,
) -> Any:
    """Return a bounded JSON-safe projection without echoing tainted tool text."""

    if depth > _CLI_MAX_DEPTH:
        return {"redacted": True, "reason": "depth_limit"}
    if field_name is not None and field_name.casefold() in _SENSITIVE_FIELD_NAMES:
        return _redacted_value_summary(value)
    if isinstance(value, BaseModel):
        return _sanitize_cli_value(value.model_dump(mode="json"), depth=depth)
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for ordinal, (raw_key, item) in enumerate(value.items()):
            if ordinal >= _CLI_MAX_ITEMS:
                sanitized["_truncated"] = True
                break
            key = str(raw_key)
            if (
                (_looks_sensitive(key) and key not in _SAFE_SENSITIVE_CLI_KEYS)
                or len(key.encode("utf-8", errors="replace")) > 128
                or any(not character.isprintable() for character in key)
            ):
                key = f"redacted_field_{ordinal}"
            sanitized[key] = _sanitize_cli_value(
                item,
                field_name=key,
                depth=depth + 1,
            )
        return sanitized
    if isinstance(value, list | tuple):
        items = [_sanitize_cli_value(item, depth=depth + 1) for item in value[:_CLI_MAX_ITEMS]]
        if len(value) > _CLI_MAX_ITEMS:
            items.append({"redacted": True, "reason": "item_limit"})
        return items
    if isinstance(value, str):
        encoded = value.encode("utf-8", errors="replace")
        if len(encoded) > _CLI_MAX_TEXT_BYTES or _looks_sensitive(value):
            return _redacted_text_summary(value)
        if any(not character.isprintable() and character not in "\n\r\t" for character in value):
            return _redacted_text_summary(value)
        return value
    if value is None or isinstance(value, bool | int | float):
        return value
    return {"redacted": True, "type": type(value).__name__}


def _emit_json(value: Any) -> None:
    print(json.dumps(_sanitize_cli_value(value), ensure_ascii=False, indent=2, sort_keys=True))


def _emit_lines(*lines: str) -> None:
    for line in lines:
        sanitized = _sanitize_cli_value(line)
        if isinstance(sanitized, str):
            print(sanitized)
        else:
            print(json.dumps(sanitized, sort_keys=True))


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Invalid command-line arguments",
        )


def _docker_probe() -> dict[str, Any]:
    executable = shutil.which("docker")
    if executable is None:
        return {"available": False, "reason": "docker_cli_missing"}
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            [executable, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"available": False, "reason": type(error).__name__}
    if completed.returncode != 0:
        return {"available": False, "reason": "engine_unavailable"}
    server_version = completed.stdout.strip()
    if not _DOCKER_VERSION_RE.fullmatch(server_version):
        return {"available": False, "reason": "docker_output_invalid"}
    return {"available": True, "server_version": server_version}


def doctor_report(*, verify_container: bool = False) -> dict[str, Any]:
    """Inspect effective prerequisites without silently upgrading assurance."""

    docker = _docker_probe()
    linux = sys.platform.startswith("linux")
    python_supported = sys.version_info[:2] == (3, 12)
    sqlite_supported = sqlite3.sqlite_version_info >= (3, 35, 0)
    contained_ready = bool(linux and docker["available"])
    container_verified = False
    missing_controls = list(_REQUIRED_DOCKER_CONTROLS)
    verification_error: str | None = None
    if verify_container and contained_ready:
        try:
            result = DockerSandbox().run_python("print('doctor-control-verification')")
            controls = result.controls.model_dump(mode="json", exclude={"backend", "image"})
            missing_controls = [name for name in _REQUIRED_DOCKER_CONTROLS if not controls[name]]
            container_verified = result.exit_code == 0 and not missing_controls
        except AgentKernelError as error:
            verification_error = type(error).__name__
            effective = error.details
            present_control_keys = {
                name for name in _REQUIRED_DOCKER_CONTROLS if isinstance(effective.get(name), bool)
            }
            if present_control_keys:
                missing_controls = [
                    name for name in _REQUIRED_DOCKER_CONTROLS if not effective[name]
                ]
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            verification_error = type(error).__name__
    return {
        "agentkernel_version": __version__,
        "profile": "A0",
        "claim": "Recorded and inspected",
        "python": {
            "version": platform.python_version(),
            "supported": python_supported,
        },
        "platform": {"system": platform.system(), "linux_reference": linux},
        "sqlite": {"version": sqlite3.sqlite_version, "supported": sqlite_supported},
        "docker": docker,
        "controls": {
            "container_profile_verified": container_verified,
            "a2_prerequisites_present": contained_ready,
            "missing_effective_controls": missing_controls,
            "verification_error": verification_error,
        },
        "limitations": [
            "Embedded mode is inspection/development only.",
            "Docker presence alone does not verify an effective sandbox profile.",
            "A1+ authority and policy enforcement is not implemented in Phase 0.",
        ],
    }


def export_schemas(output: Path) -> int:
    output.mkdir(parents=True, exist_ok=True)
    for model in SCHEMA_MODELS:
        schema = model.model_json_schema(mode="validation")
        target = output / f"{model.__name__}.schema.json"
        target.write_text(
            json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return len(SCHEMA_MODELS)


def _validate_ledger(path: Path) -> int:
    events: list[EventEnvelope] = []
    try:
        events.extend(
            EventEnvelope.model_validate_json(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    except (OSError, ValueError):
        _emit_json({"valid": False, "error_code": "LEDGER_INPUT_INVALID"})
        return 2
    result = validate_chain(events)
    _emit_json(asdict(result))
    return 0 if result.valid else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(prog="agentkernel")
    parser.add_argument("--version", action="version", version=__version__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    doctor = subcommands.add_parser("doctor", help="inspect effective local prerequisites")
    doctor.add_argument("--json", action="store_true", dest="as_json")
    doctor.add_argument("--require-contained", action="store_true")

    schema = subcommands.add_parser("schema", help="work with versioned public schemas")
    schema_commands = schema.add_subparsers(dest="schema_command", required=True)
    schema_export = schema_commands.add_parser("export", help="write JSON Schema files")
    schema_export.add_argument("--output", type=Path, default=Path("schemas/v1alpha1"))

    ledger = subcommands.add_parser("ledger", help="inspect tamper-evident event streams")
    ledger_commands = ledger.add_subparsers(dest="ledger_command", required=True)
    ledger_validate = ledger_commands.add_parser("validate", help="validate an event JSONL chain")
    ledger_validate.add_argument("path", type=Path)

    demo = subcommands.add_parser("demo", help="run the deterministic no-key A0 demonstration")
    demo.add_argument("--root", type=Path, help="retain artifacts under an empty directory")
    demo.add_argument("--json", action="store_true", dest="as_json")

    sandbox = subcommands.add_parser("sandbox", help="inspect supported isolation backends")
    sandbox_commands = sandbox.add_subparsers(dest="sandbox_command", required=True)
    sandbox_verify = sandbox_commands.add_parser(
        "verify-docker", help="create and inspect the default no-network container profile"
    )
    sandbox_verify.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _run_command(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "doctor":
        doctor_data = doctor_report(verify_container=args.require_contained)
        if args.as_json:
            _emit_json(doctor_data)
        else:
            _emit_lines(
                f"AgentKernel {doctor_data['agentkernel_version']} — {doctor_data['profile']}",
                str(doctor_data["claim"]),
                f"Python supported: {doctor_data['python']['supported']}",
                f"Docker engine available: {doctor_data['docker']['available']}",
                "Container profile verified: "
                f"{str(doctor_data['controls']['container_profile_verified']).lower()}",
            )
        if args.require_contained and not doctor_data["controls"]["container_profile_verified"]:
            return 2
        return 0
    if args.command == "schema" and args.schema_command == "export":
        exported = export_schemas(args.output)
        _emit_json({"exported_schema_count": exported})
        return 0
    if args.command == "ledger" and args.ledger_command == "validate":
        return _validate_ledger(args.path)
    if args.command == "demo":
        if args.root is None:
            with tempfile.TemporaryDirectory(prefix="agentkernel-demo-") as temporary:
                demo_report = asyncio.run(run_demo(Path(temporary)))
        else:
            demo_report = asyncio.run(run_demo(args.root))
        if args.as_json:
            _emit_json(demo_report)
        else:
            _emit_lines(
                f"AgentKernel demo — {demo_report.assurance_profile}",
                demo_report.assurance_claim,
                f"Protected read dispatches: {demo_report.protected_read_canary_count}",
                f"External network dispatches: {demo_report.external_network_dispatch_count}",
                f"Transaction: {demo_report.committed_transaction_state.value}",
                f"Ledger valid: {str(demo_report.ledger_valid).lower()}",
                f"Replay {demo_report.replay.level.value} matched: "
                f"{str(demo_report.replay.matched).lower()}",
            )
        return 0
    if args.command == "sandbox" and args.sandbox_command == "verify-docker":
        sandbox_result = DockerSandbox().run_python("print('container-controls-ok')")
        if args.as_json:
            _emit_json(sandbox_result)
        else:
            _emit_lines(
                "Docker container controls verified",
                f"Image: {sandbox_result.controls.image}",
                f"All required controls: {str(sandbox_result.controls.all_required).lower()}",
            )
        return 0 if sandbox_result.exit_code == 0 else 1
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    """Run one CLI command and render expected failures without raw exception data."""

    try:
        return _run_command(argv)
    except AgentKernelError as error:
        _emit_json(
            {
                "ok": False,
                "error_code": error.code.value,
                "retryable": error.retryable,
                "reconcilable": error.reconcilable,
                "review_required": error.review_required,
            }
        )
        return 2
    except (OSError, UnicodeError):
        _emit_json({"ok": False, "error_code": "CLI_IO_ERROR"})
        return 2
