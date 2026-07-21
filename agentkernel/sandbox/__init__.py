"""Pluggable sandbox backends with evidence-based control reporting."""

from agentkernel.sandbox.docker import (
    DEFAULT_IMAGE,
    DockerControlReport,
    DockerSandbox,
    SandboxResult,
)

__all__ = ["DEFAULT_IMAGE", "DockerControlReport", "DockerSandbox", "SandboxResult"]
