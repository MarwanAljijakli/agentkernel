from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence

import pytest
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.sandbox import docker as docker_module
from agentkernel.sandbox.docker import DockerSandbox


class _FakeDockerSandbox(DockerSandbox):
    def __init__(self, *, complete_controls: bool = True) -> None:
        super().__init__(max_output_bytes=8)
        self.complete_controls = complete_controls
        self.calls: list[tuple[str, ...]] = []

    def _invoke(
        self,
        arguments: Sequence[str],
        *,
        timeout: int | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        del timeout, check
        call = tuple(arguments)
        self.calls.append(call)
        if call[0] == "create":
            return subprocess.CompletedProcess(call, 0, stdout="container-1\n", stderr="")
        if call[0] == "inspect":
            document = [
                {
                    "HostConfig": {
                        "ReadonlyRootfs": self.complete_controls,
                        "NetworkMode": "none",
                        "CapDrop": ["ALL"],
                        "SecurityOpt": ["no-new-privileges:true"],
                        "PidsLimit": 64,
                        "Memory": 1024,
                        "NanoCpus": 1,
                        "Tmpfs": {"/tmp": "rw,size=1024"},  # noqa: S108
                    },
                    "Config": {"User": "65534:65534"},
                    "Mounts": [],
                }
            ]
            return subprocess.CompletedProcess(
                call,
                0,
                stdout=json.dumps(document),
                stderr="",
            )
        if call[0] == "start":
            return subprocess.CompletedProcess(call, 0, stdout="long-output\n", stderr="err")
        return subprocess.CompletedProcess(call, 0, stdout="", stderr="")


def test_run_python_inspects_controls_before_start_and_always_removes() -> None:
    sandbox = _FakeDockerSandbox()

    result = sandbox.run_python("print('ok')")

    assert result.controls.all_required is True
    assert result.output_truncated is True
    assert result.stdout == "long-out"
    assert result.stderr == ""
    assert [call[0] for call in sandbox.calls] == ["create", "inspect", "start", "rm"]


def test_run_python_refuses_missing_effective_control_and_removes_container() -> None:
    sandbox = _FakeDockerSandbox(complete_controls=False)

    with pytest.raises(AgentKernelError) as captured:
        sandbox.run_python("print('never starts')")

    assert captured.value.code is ErrorCode.SANDBOX_FAILED
    assert [call[0] for call in sandbox.calls] == ["create", "inspect", "rm"]


def test_invoke_fails_closed_when_docker_cli_is_missing(monkeypatch) -> None:
    monkeypatch.setattr(docker_module.shutil, "which", lambda _name: None)
    sandbox = DockerSandbox()

    with pytest.raises(AgentKernelError) as captured:
        sandbox._invoke(["info"])

    assert captured.value.code is ErrorCode.SANDBOX_FAILED


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (subprocess.TimeoutExpired("docker", 1), ErrorCode.DEADLINE_EXCEEDED),
        (OSError("synthetic start failure"), ErrorCode.SANDBOX_FAILED),
    ],
)
def test_invoke_redacts_process_start_failures(monkeypatch, failure: Exception, expected) -> None:
    monkeypatch.setattr(
        docker_module.shutil,
        "which",
        lambda _name: "C:/synthetic/docker.exe",
    )

    def _raise(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(docker_module.subprocess, "run", _raise)
    sandbox = DockerSandbox()

    with pytest.raises(AgentKernelError) as captured:
        sandbox._invoke(["info"])

    assert captured.value.code is expected
    assert "synthetic start failure" not in captured.value.message
