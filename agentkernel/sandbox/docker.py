"""Docker container-isolation backend for bounded local experiments."""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
from collections.abc import Sequence

from agentkernel.domain.models import NonEmptyStr, StrictModel
from agentkernel.errors import AgentKernelError, ErrorCode

DEFAULT_IMAGE = "python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
_CONTAINER_TEMP = "/tmp"  # nosec B108


class DockerControlReport(StrictModel):
    backend: str = "docker"
    image: NonEmptyStr
    non_root_user: bool
    read_only_root: bool
    network_none: bool
    all_capabilities_dropped: bool
    no_new_privileges: bool
    pids_limited: bool
    memory_limited: bool
    cpu_limited: bool
    no_host_mounts: bool
    bounded_tmpfs: bool

    @property
    def all_required(self) -> bool:
        return all(
            (
                self.non_root_user,
                self.read_only_root,
                self.network_none,
                self.all_capabilities_dropped,
                self.no_new_privileges,
                self.pids_limited,
                self.memory_limited,
                self.cpu_limited,
                self.no_host_mounts,
                self.bounded_tmpfs,
            )
        )


class SandboxResult(StrictModel):
    exit_code: int
    stdout: str
    stderr: str
    controls: DockerControlReport
    timed_out: bool = False
    output_truncated: bool = False


class DockerSandbox:
    """Create, inspect, then run a no-network container with no host mounts."""

    def __init__(
        self,
        *,
        image: str = DEFAULT_IMAGE,
        timeout_seconds: int = 15,
        max_output_bytes: int = 65_536,
    ) -> None:
        self._docker = shutil.which("docker")
        self._image = image
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes

    def _invoke(
        self,
        arguments: Sequence[str],
        *,
        timeout: int | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        if self._docker is None:
            raise AgentKernelError(ErrorCode.SANDBOX_FAILED, "Docker CLI is unavailable")
        try:
            completed = subprocess.run(  # noqa: S603  # nosec B603
                [self._docker, *arguments],
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout or self._timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            raise AgentKernelError(
                ErrorCode.DEADLINE_EXCEEDED,
                "Docker command exceeded its deadline",
            ) from error
        except OSError as error:
            raise AgentKernelError(
                ErrorCode.SANDBOX_FAILED, "Docker command failed to start"
            ) from error
        if check and completed.returncode != 0:
            raise AgentKernelError(
                ErrorCode.SANDBOX_FAILED,
                "Docker command failed",
                details={"stderr": completed.stderr[-2048:]},
            )
        return completed

    def _inspect_controls(self, container_id: str) -> DockerControlReport:
        inspection = self._invoke(["inspect", container_id])
        document = json.loads(inspection.stdout)[0]
        host = document["HostConfig"]
        config = document["Config"]
        security_options = {str(value).lower() for value in host.get("SecurityOpt") or []}
        capabilities = {str(value).upper() for value in host.get("CapDrop") or []}
        tmpfs = host.get("Tmpfs") or {}
        return DockerControlReport(
            image=self._image,
            non_root_user=str(config.get("User", "")) not in {"", "0", "root", "0:0"},
            read_only_root=bool(host.get("ReadonlyRootfs")),
            network_none=str(host.get("NetworkMode", "")) == "none",
            all_capabilities_dropped="ALL" in capabilities,
            no_new_privileges=any("no-new-privileges" in option for option in security_options),
            pids_limited=int(host.get("PidsLimit") or 0) > 0,
            memory_limited=int(host.get("Memory") or 0) > 0,
            cpu_limited=int(host.get("NanoCpus") or 0) > 0,
            no_host_mounts=not document.get("Mounts"),
            bounded_tmpfs=_CONTAINER_TEMP in tmpfs and "size=" in str(tmpfs[_CONTAINER_TEMP]),
        )

    def run_python(self, source: str) -> SandboxResult:
        """Run trusted test source under a verified container profile.

        This demonstrates container controls only. It is not the future hostile-agent harness,
        because Python code can still access files that belong to the container image itself.
        """

        created = self._invoke(
            [
                "create",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--pids-limit",
                "64",
                "--memory",
                "128m",
                "--cpus",
                "0.50",
                "--tmpfs",
                f"{_CONTAINER_TEMP}:rw,noexec,nosuid,nodev,size=16777216",
                "--user",
                "65534:65534",
                "--workdir",
                _CONTAINER_TEMP,
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--entrypoint",
                "python",
                self._image,
                "-I",
                "-S",
                "-c",
                source,
            ]
        )
        container_id = created.stdout.strip()
        if not container_id:
            raise AgentKernelError(ErrorCode.SANDBOX_FAILED, "Docker returned no container ID")
        try:
            controls = self._inspect_controls(container_id)
            if not controls.all_required:
                raise AgentKernelError(
                    ErrorCode.SANDBOX_FAILED,
                    "Effective container controls do not match the required profile",
                    details=controls.model_dump(mode="json"),
                )
            completed = self._invoke(
                ["start", "--attach", container_id],
                timeout=self._timeout_seconds,
                check=False,
            )
            stdout = completed.stdout
            stderr = completed.stderr
            combined_bytes = len(stdout.encode()) + len(stderr.encode())
            truncated = combined_bytes > self._max_output_bytes
            if truncated:
                stdout = stdout.encode()[: self._max_output_bytes].decode(errors="replace")
                stderr = ""
            return SandboxResult(
                exit_code=completed.returncode,
                stdout=stdout,
                stderr=stderr,
                controls=controls,
                output_truncated=truncated,
            )
        finally:
            self._invoke(["rm", "--force", container_id], check=False)
