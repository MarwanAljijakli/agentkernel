"""Local content-addressed artifact storage for the single-node profile."""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from agentkernel.canonical import sha256_digest
from agentkernel.domain.models import Artifact
from agentkernel.errors import AgentKernelError, ErrorCode


class LocalArtifactStore:
    """Store immutable blobs by plaintext digest under a configured root."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()

    @property
    def root(self) -> Path:
        return self._root

    def _path_for(self, digest: str) -> Path:
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Invalid SHA-256 digest")
        hexadecimal = digest.removeprefix("sha256:")
        try:
            bytes.fromhex(hexadecimal)
        except ValueError as error:
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Invalid SHA-256 digest") from error
        path = self._root / "sha256" / hexadecimal[:2] / hexadecimal[2:4] / hexadecimal
        resolved_parent = path.parent.resolve()
        if not resolved_parent.is_relative_to(self._root):
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Artifact path escaped the store")
        return path

    def put(self, content: bytes, *, media_type: str = "application/octet-stream") -> Artifact:
        digest = sha256_digest(content)
        path = self._path_for(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            existing = path.read_bytes()
            if existing != content:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Existing artifact content does not match its digest",
                )
        else:
            descriptor, temporary_name = tempfile.mkstemp(prefix=".artifact-", dir=path.parent)
            try:
                with os.fdopen(descriptor, "wb") as temporary:
                    temporary.write(content)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                Path(temporary_name).replace(path)
            finally:
                temporary_path = Path(temporary_name)
                if temporary_path.exists():
                    temporary_path.unlink()

        return Artifact(
            digest=digest,
            media_type=media_type,
            size_bytes=len(content),
            created_at=datetime.now(UTC),
            storage_ref=str(path.relative_to(self._root).as_posix()),
        )

    def get(self, digest: str) -> bytes:
        path = self._path_for(digest)
        try:
            content = path.read_bytes()
        except FileNotFoundError as error:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Artifact is not available",
                details={"digest": digest},
            ) from error
        if sha256_digest(content) != digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Artifact content failed digest validation",
                details={"digest": digest},
            )
        return content
