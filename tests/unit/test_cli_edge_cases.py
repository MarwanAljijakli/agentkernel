from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import agentkernel
import pytest
from agentkernel import cli
from agentkernel.sandbox.docker import DockerControlReport, SandboxResult
from agentkernel.transactions.enforced import EnforcedTransactionCoordinator


def test_cli_sanitizer_bounds_cycles_depth_items_keys_text_and_unknown_values() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    summary = cli._redacted_value_summary(cyclic)
    assert summary["redacted"] is True
    assert summary["bytes"] == len("list")

    assert cli._sanitize_cli_value("safe", depth=cli._CLI_MAX_DEPTH + 1) == {
        "redacted": True,
        "reason": "depth_limit",
    }

    many_items = {f"key_{index}": index for index in range(cli._CLI_MAX_ITEMS + 1)}
    sanitized_mapping = cli._sanitize_cli_value(many_items)
    assert sanitized_mapping["_truncated"] is True
    assert "key_256" not in sanitized_mapping

    sanitized_keys = cli._sanitize_cli_value(
        {
            "password": "do-not-echo",
            "x" * 129: "long-key",
            "control\x01key": "control-key",
            "secret_found_in_evidence": False,
        }
    )
    assert "password" not in sanitized_keys
    assert "redacted_field_0" in sanitized_keys
    assert "redacted_field_1" in sanitized_keys
    assert "redacted_field_2" in sanitized_keys
    assert sanitized_keys["secret_found_in_evidence"] is False

    sanitized_sequence = cli._sanitize_cli_value(list(range(cli._CLI_MAX_ITEMS + 1)))
    assert sanitized_sequence[-1] == {"redacted": True, "reason": "item_limit"}

    control_text = cli._sanitize_cli_value("safe\x00unsafe")
    assert control_text["redacted"] is True
    assert cli._sanitize_cli_value(object()) == {"redacted": True, "type": "object"}


def test_emit_lines_redacts_sensitive_content_without_suppressing_safe_lines(capsys) -> None:
    cli._emit_lines("safe line", "secret_token=do-not-print")
    output = capsys.readouterr().out
    assert "safe line" in output
    assert "do-not-print" not in output
    assert '"redacted": true' in output


@pytest.mark.parametrize(
    ("runner", "expected_reason"),
    [
        (lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")), "OSError"),
        (
            lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=""),
            "engine_unavailable",
        ),
        (
            lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="not a version"),
            "docker_output_invalid",
        ),
    ],
)
def test_docker_probe_reports_bounded_failure_categories(
    monkeypatch: pytest.MonkeyPatch,
    runner: object,
    expected_reason: str,
) -> None:
    monkeypatch.setattr(cli.shutil, "which", lambda _name: "docker")
    monkeypatch.setattr(cli.subprocess, "run", runner)
    assert cli._docker_probe() == {"available": False, "reason": expected_reason}


def test_docker_probe_handles_missing_cli_timeout_and_valid_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli.shutil, "which", lambda _name: None)
    assert cli._docker_probe() == {"available": False, "reason": "docker_cli_missing"}

    monkeypatch.setattr(cli.shutil, "which", lambda _name: "docker")

    def timeout(*_args: object, **_kwargs: object) -> object:
        raise subprocess.TimeoutExpired("docker", 5)

    monkeypatch.setattr(cli.subprocess, "run", timeout)
    assert cli._docker_probe() == {"available": False, "reason": "TimeoutExpired"}

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="27.5.1\n"),
    )
    assert cli._docker_probe() == {"available": True, "server_version": "27.5.1"}


def test_doctor_categorizes_unexpected_control_probe_shape_without_leaking_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _MalformedSandbox:
        def run_python(self, _source: str) -> SandboxResult:
            raise ValueError("untrusted backend output")

    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "_docker_probe", lambda: {"available": True})
    monkeypatch.setattr(cli, "DockerSandbox", _MalformedSandbox)

    report = cli.doctor_report(verify_container=True)
    assert report["controls"]["verification_error"] == "ValueError"
    assert report["controls"]["container_profile_verified"] is False


def test_doctor_plain_text_workflow_is_safe_and_actionable(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    monkeypatch.setattr(cli, "_docker_probe", lambda: {"available": False})
    assert cli.main(["doctor"]) == 0
    output = capsys.readouterr().out
    assert "AgentKernel" in output
    assert "Container profile verified: false" in output


def test_demo_plain_text_uses_an_ephemeral_root_when_none_is_supplied(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    observed_roots: list[Path] = []

    async def fake_demo(root: Path) -> object:
        observed_roots.append(root)
        return SimpleNamespace(
            assurance_profile="A0",
            assurance_claim="Recorded and inspected",
            protected_read_canary_count=0,
            external_network_dispatch_count=0,
            committed_transaction_state=SimpleNamespace(value="COMMITTED"),
            ledger_valid=True,
            replay=SimpleNamespace(level=SimpleNamespace(value="L1"), matched=True),
        )

    monkeypatch.setattr(cli, "run_demo", fake_demo)
    assert cli.main(["demo"]) == 0
    assert observed_roots
    assert not observed_roots[0].exists()
    assert "Transaction: COMMITTED" in capsys.readouterr().out


def test_sandbox_plain_text_workflow_reports_effective_controls(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    controls = DockerControlReport(
        image="python@sha256:" + ("a" * 64),
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

    class _Sandbox:
        def run_python(self, _source: str) -> SandboxResult:
            return SandboxResult(exit_code=0, stdout="ok\n", stderr="", controls=controls)

    monkeypatch.setattr(cli, "DockerSandbox", _Sandbox)
    assert cli.main(["sandbox", "verify-docker"]) == 0
    output = capsys.readouterr().out
    assert "Docker container controls verified" in output
    assert "All required controls: true" in output


def test_main_maps_io_failures_to_a_stable_nonsecret_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        cli,
        "_run_command",
        lambda _argv: (_ for _ in ()).throw(OSError("SECRET_CANARY_DO_NOT_PRINT")),
    )
    assert cli.main(["doctor"]) == 2
    output = capsys.readouterr().out
    assert "SECRET_CANARY_DO_NOT_PRINT" not in output
    assert "CLI_IO_ERROR" in output


def test_python_module_entrypoint_delegates_arguments_and_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[list[str]] = []

    def fake_main(arguments: list[str]) -> int:
        observed.append(arguments)
        return 7

    monkeypatch.setattr(cli, "main", fake_main)
    monkeypatch.setattr(sys, "argv", ["agentkernel", "doctor", "--json"])
    with pytest.raises(SystemExit) as captured:
        runpy.run_module("agentkernel.__main__", run_name="__main__")
    assert captured.value.code == 7
    assert observed == [["doctor", "--json"]]


def test_public_package_lazy_exports_and_unknown_attribute_contract() -> None:
    assert agentkernel.EnforcedTransactionCoordinator is EnforcedTransactionCoordinator
    with pytest.raises(AttributeError, match="does_not_exist"):
        agentkernel.__getattr__("does_not_exist")
