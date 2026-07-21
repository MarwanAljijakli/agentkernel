from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from agentkernel import cli
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.ledger import make_event
from agentkernel.sandbox.docker import DockerControlReport, SandboxResult


def test_doctor_never_silently_claims_containment(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_docker_probe", lambda: {"available": True, "server_version": "test"})
    exit_code = cli.main(["doctor", "--json"])
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["profile"] == "A0"
    assert report["controls"]["container_profile_verified"] is False


def test_schema_export_writes_versioned_contracts(tmp_path: Path) -> None:
    output = tmp_path / "schemas" / "v1alpha1"
    assert cli.main(["schema", "export", "--output", str(output)]) == 0
    proposal_schema = json.loads(
        (output / "ActionProposal.schema.json").read_text(encoding="utf-8")
    )
    assert proposal_schema["additionalProperties"] is False
    assert "api_version" in proposal_schema["properties"]


def test_ledger_validate_command(tmp_path: Path, capsys) -> None:
    event = make_event(
        run_id="run_cli",
        sequence=0,
        logical_time=0,
        wall_time=datetime(2026, 1, 1, tzinfo=UTC),
        event_type="test",
        actor="service:test",
        on_behalf_of="principal:test",
        event_id="evt_cli",
    )
    path = tmp_path / "events.jsonl"
    path.write_text(event.model_dump_json() + "\n", encoding="utf-8")
    assert cli.main(["ledger", "validate", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True


def test_require_contained_runs_effective_control_verification(monkeypatch, capsys) -> None:
    controls = DockerControlReport(
        image="python@sha256:" + "a" * 64,
        non_root_user=True,
        read_only_root=True,
        network_none=True,
        all_capabilities_dropped=True,
        no_new_privileges=True,
        pids_limited=True,
        memory_limited=True,
        cpu_limited=True,
        no_host_mounts=True,
        bounded_tmpfs=True,
    )

    class _VerifiedSandbox:
        def run_python(self, source: str) -> SandboxResult:
            assert source
            return SandboxResult(exit_code=0, stdout="ok\n", stderr="", controls=controls)

    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "_docker_probe", lambda: {"available": True})
    monkeypatch.setattr(cli, "DockerSandbox", _VerifiedSandbox)

    exit_code = cli.main(["doctor", "--json", "--require-contained"])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert report["controls"]["container_profile_verified"] is True
    assert report["controls"]["missing_effective_controls"] == []


def test_ledger_validation_redacts_untrusted_parser_values(tmp_path: Path, capsys) -> None:
    canary = "SECRET_CANARY_DO_NOT_PRINT"
    path = tmp_path / "malformed.jsonl"
    path.write_text(json.dumps({"sequence": canary}) + "\n", encoding="utf-8")

    assert cli.main(["ledger", "validate", str(path)]) == 2
    output = capsys.readouterr().out
    assert canary not in output
    assert json.loads(output) == {"valid": False, "error_code": "LEDGER_INPUT_INVALID"}


def test_schema_export_does_not_echo_a_sensitive_output_path(tmp_path: Path, capsys) -> None:
    canary = "SECRET_CANARY_DO_NOT_PRINT"
    output = tmp_path / canary

    assert cli.main(["schema", "export", "--output", str(output)]) == 0
    rendered = capsys.readouterr().out

    assert canary not in rendered
    assert json.loads(rendered)["exported_schema_count"] == len(cli.SCHEMA_MODELS)


def test_doctor_names_the_missing_effective_container_control(monkeypatch, capsys) -> None:
    class _IncompleteSandbox:
        def run_python(self, source: str):
            assert source
            controls = {
                "non_root_user": True,
                "read_only_root": False,
                "network_none": True,
                "all_capabilities_dropped": True,
                "no_new_privileges": True,
                "pids_limited": True,
                "memory_limited": True,
                "cpu_limited": True,
                "no_host_mounts": True,
                "bounded_tmpfs": True,
            }
            raise AgentKernelError(
                ErrorCode.SANDBOX_FAILED,
                "synthetic incomplete control profile",
                details=controls,
            )

    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "_docker_probe", lambda: {"available": True})
    monkeypatch.setattr(cli, "DockerSandbox", _IncompleteSandbox)

    exit_code = cli.main(["doctor", "--json", "--require-contained"])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert report["controls"]["container_profile_verified"] is False
    assert report["controls"]["missing_effective_controls"] == ["read_only_root"]
