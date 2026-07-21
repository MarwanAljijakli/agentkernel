"""Stable, non-interactive command-line entry point for the foundation release."""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import shutil
import sqlite3
import subprocess  # nosec B404
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

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
from agentkernel.errors import AgentKernelError
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
    return {"available": True, "server_version": completed.stdout.strip()}


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
        print(json.dumps({"valid": False, "error_code": "LEDGER_INPUT_INVALID"}))
        return 2
    result = validate_chain(events)
    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.valid else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentkernel")
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


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "doctor":
        doctor_data = doctor_report(verify_container=args.require_contained)
        if args.as_json:
            print(json.dumps(doctor_data, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            print(f"AgentKernel {doctor_data['agentkernel_version']} — {doctor_data['profile']}")
            print(doctor_data["claim"])
            print(f"Python supported: {doctor_data['python']['supported']}")
            print(f"Docker engine available: {doctor_data['docker']['available']}")
            print(
                "Container profile verified: "
                f"{str(doctor_data['controls']['container_profile_verified']).lower()}"
            )
        if args.require_contained and not doctor_data["controls"]["container_profile_verified"]:
            return 2
        return 0
    if args.command == "schema" and args.schema_command == "export":
        exported = export_schemas(args.output)
        print(json.dumps({"exported_schema_count": exported}, sort_keys=True))
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
            print(demo_report.model_dump_json(indent=2))
        else:
            print(f"AgentKernel demo — {demo_report.assurance_profile}")
            print(demo_report.assurance_claim)
            print(f"Protected read dispatches: {demo_report.protected_read_canary_count}")
            print(f"External network dispatches: {demo_report.external_network_dispatch_count}")
            print(f"Transaction: {demo_report.committed_transaction_state.value}")
            print(f"Ledger valid: {str(demo_report.ledger_valid).lower()}")
            print(f"Replay L2 matched: {str(demo_report.replay.matched).lower()}")
        return 0
    if args.command == "sandbox" and args.sandbox_command == "verify-docker":
        sandbox_result = DockerSandbox().run_python("print('container-controls-ok')")
        if args.as_json:
            print(sandbox_result.model_dump_json(indent=2))
        else:
            print("Docker container controls verified")
            print(f"Image: {sandbox_result.controls.image}")
            print(f"All required controls: {str(sandbox_result.controls.all_required).lower()}")
        return 0 if sandbox_result.exit_code == 0 else 1
    return 2
