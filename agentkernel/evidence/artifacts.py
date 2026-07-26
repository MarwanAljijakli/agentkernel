"""Local content-addressed artifact storage for the single-node profile."""

from __future__ import annotations

import os
import secrets
import stat
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import TypeVar, cast

from pydantic import BaseModel, ValidationError

from agentkernel.adapters.base import EvidenceClock
from agentkernel.canonical import canonical_json_bytes, sha256_digest
from agentkernel.domain.models import Artifact
from agentkernel.errors import AgentKernelError, ErrorCode

_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _effective_user_id() -> int:
    getter = cast("Callable[[], int] | None", getattr(os, "geteuid", None))
    if getter is None:
        raise AgentKernelError(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "POSIX artifact ownership checks are unavailable",
        )
    return getter()


def _fsync_directory(path: Path) -> None:
    """Persist a directory entry where the host supports directory handles."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if os.name == "nt" and error.errno in {13, 22}:
            return
        raise
    try:
        os.fsync(descriptor)
    except OSError as error:
        if os.name == "nt" and error.errno in {1, 13, 22}:
            return
        raise
    finally:
        os.close(descriptor)


class LocalArtifactStore:
    """Store immutable blobs under a bounded local profile (16 MiB by default)."""

    def __init__(
        self,
        root: Path,
        *,
        max_artifact_bytes: int = 16_777_216,
        clock: EvidenceClock | None = None,
    ) -> None:
        if (
            type(max_artifact_bytes) is not int
            or max_artifact_bytes <= 0
            or max_artifact_bytes > 1_073_741_824
        ):
            raise ValueError("max_artifact_bytes must be an integer from 1 byte through 1 GiB")
        candidate = root.absolute()
        candidate.parent.mkdir(parents=True, exist_ok=True)
        if candidate.exists() and (
            candidate.is_symlink() or candidate.is_junction() or not candidate.is_dir()
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Artifact root must be a real directory",
            )
        with suppress(FileExistsError):
            candidate.mkdir(mode=0o700)
            _fsync_directory(candidate.parent)
        self._root = candidate.resolve(strict=True)
        self._max_artifact_bytes = max_artifact_bytes
        self._clock = clock or EvidenceClock()
        self._validate_directory(self._root, expected_parent=self._root.parent)
        root_metadata = self._root.stat()
        self._root_identity = (root_metadata.st_dev, root_metadata.st_ino)

    @property
    def root(self) -> Path:
        return self._root

    @staticmethod
    def _digest_parts(digest: str) -> tuple[str, str, str, str]:
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Invalid SHA-256 digest")
        hexadecimal = digest.removeprefix("sha256:")
        try:
            bytes.fromhex(hexadecimal)
        except ValueError as error:
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Invalid SHA-256 digest") from error
        return "sha256", hexadecimal[:2], hexadecimal[2:4], hexadecimal

    @staticmethod
    def _validate_private_fd(descriptor: int, *, root_device: int) -> os.stat_result:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != root_device
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_uid != _effective_user_id()
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Artifact directory handle is not owner-private or scoped",
            )
        return metadata

    @contextmanager
    def _digest_parent_handle(
        self,
        digest: str,
        *,
        create: bool,
    ) -> Iterator[tuple[int, str]]:
        parts = self._digest_parts(digest)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            current = os.open(self._root, flags)
        except OSError as error:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Artifact root is not safely reachable",
            ) from error
        try:
            root_metadata = self._validate_private_fd(
                current,
                root_device=self._root_identity[0],
            )
            if (root_metadata.st_dev, root_metadata.st_ino) != self._root_identity:
                raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Artifact root was replaced")
            for part in parts[:-1]:
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=current)
                        os.fsync(current)
                    except FileExistsError:
                        pass
                try:
                    child = os.open(part, flags, dir_fd=current)
                except FileNotFoundError as error:
                    raise AgentKernelError(
                        ErrorCode.EVIDENCE_UNAVAILABLE,
                        "Artifact shard is not available",
                    ) from error
                except OSError as error:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Artifact shard is linked, missing, or inaccessible",
                    ) from error
                try:
                    self._validate_private_fd(child, root_device=root_metadata.st_dev)
                except BaseException:
                    os.close(child)
                    raise
                os.close(current)
                current = child
            yield current, parts[-1]
        finally:
            os.close(current)

    def _read_blob_fd(self, parent_fd: int, name: str, digest: str) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError as error:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Artifact is not available",
            ) from error
        except OSError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Artifact blob cannot be opened without following links",
            ) from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) & 0o077
                or before.st_uid != _effective_user_id()
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Artifact blob metadata violates the immutable private profile",
                )
            if before.st_size > self._max_artifact_bytes:
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Artifact exceeds the configured size limit",
                )
            chunks: list[bytes] = []
            size = 0
            while size <= self._max_artifact_bytes:
                chunk = os.read(
                    descriptor,
                    min(1024 * 1024, self._max_artifact_bytes + 1 - size),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) or size != after.st_size:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Artifact blob changed during bounded read",
                )
        finally:
            os.close(descriptor)
        if size > self._max_artifact_bytes:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Artifact exceeds the configured size limit",
            )
        content = b"".join(chunks)
        if sha256_digest(content) != digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Artifact content failed digest validation",
                details={"digest": digest},
            )
        return content

    def _validate_directory(self, path: Path, *, expected_parent: Path) -> Path:
        try:
            metadata = path.lstat()
        except FileNotFoundError as error:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Artifact storage directory is unavailable",
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or path.is_symlink()
            or path.is_junction()
            or path.resolve(strict=True).parent != expected_parent.resolve(strict=True)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Artifact storage contains a linked or non-directory component",
            )
        if os.name == "posix" and (
            stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_uid != _effective_user_id()
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Artifact storage directories must be owner-private (0700)",
            )
        return path

    def _ensure_directory(self, path: Path, *, parent: Path) -> Path:
        with suppress(FileExistsError):
            path.mkdir(mode=0o700)
            _fsync_directory(parent)
        return self._validate_directory(path, expected_parent=parent)

    def _path_for(self, digest: str, *, create_parents: bool = False) -> Path:
        algorithm, first_pair, second_pair, hexadecimal = self._digest_parts(digest)
        first = self._root / algorithm
        second = first / first_pair
        parent = second / second_pair
        if create_parents:
            self._ensure_directory(first, parent=self._root)
            self._ensure_directory(second, parent=first)
            self._ensure_directory(parent, parent=second)
        else:
            self._validate_directory(first, expected_parent=self._root)
            self._validate_directory(second, expected_parent=first)
            self._validate_directory(parent, expected_parent=second)
        return parent / hexadecimal

    def _validate_blob(self, path: Path) -> os.stat_result:
        try:
            metadata = path.lstat()
        except FileNotFoundError as error:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Artifact is not available",
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or path.is_junction()
            or path.resolve(strict=True).parent != path.parent.resolve(strict=True)
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Artifact blob is linked or is not a regular file",
            )
        if metadata.st_size > self._max_artifact_bytes:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Artifact exceeds the configured size limit",
            )
        if os.name == "posix" and (
            stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_uid != _effective_user_id()
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Artifact blob permissions or ownership are not private",
            )
        return metadata

    def put(self, content: bytes, *, media_type: str = "application/octet-stream") -> Artifact:
        if len(content) > self._max_artifact_bytes:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Artifact exceeds the configured size limit",
            )
        created_at = self._clock.now()
        digest = sha256_digest(content)
        if os.name == "posix":
            self._put_posix(digest, content)
            storage_ref = "/".join(self._digest_parts(digest))
            return Artifact(
                digest=digest,
                media_type=media_type,
                size_bytes=len(content),
                created_at=created_at,
                storage_ref=storage_ref,
            )
        path = self._path_for(digest, create_parents=True)
        if path.exists() or path.is_symlink():
            self._validate_blob(path)
            existing = self.get(digest)
            if existing != content:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Existing artifact content does not match its digest",
                )
        else:
            descriptor, temporary_name = tempfile.mkstemp(prefix=".artifact-", dir=path.parent)
            temporary_path = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as temporary:
                    temporary.write(content)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                try:
                    os.link(temporary_path, path, follow_symlinks=False)
                except FileExistsError:
                    existing = self.get(digest)
                    if existing != content:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Concurrent artifact publication conflicts with its digest",
                        ) from None
                else:
                    _fsync_directory(path.parent)
                self._validate_blob(path)
                if self.get(digest) != content:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Published artifact failed immutable read-back",
                    )
            finally:
                with suppress(FileNotFoundError):
                    temporary_path.unlink()

        return Artifact(
            digest=digest,
            media_type=media_type,
            size_bytes=len(content),
            created_at=created_at,
            storage_ref=str(path.relative_to(self._root).as_posix()),
        )

    def _put_posix(self, digest: str, content: bytes) -> None:
        with self._digest_parent_handle(digest, create=True) as (parent_fd, name):
            temporary_name = f".artifact-{secrets.token_hex(16)}"
            descriptor = -1
            try:
                descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=parent_fd,
                )
                view = memoryview(content)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short artifact write")
                    view = view[written:]
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                try:
                    os.link(
                        temporary_name,
                        name,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError:
                    if self._read_blob_fd(parent_fd, name, digest) != content:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Concurrent artifact publication conflicts with its digest",
                        ) from None
                else:
                    os.fsync(parent_fd)
                if self._read_blob_fd(parent_fd, name, digest) != content:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Published artifact failed immutable read-back",
                    )
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=parent_fd)
                os.fsync(parent_fd)

    def put_model(
        self,
        model: BaseModel,
        *,
        media_type: str = "application/vnd.agentkernel.canonical+json",
    ) -> Artifact:
        """Persist the exact AK-CJ-1 bytes for a validated model."""

        return self.put(canonical_json_bytes(model), media_type=media_type)

    def get(self, digest: str) -> bytes:
        if os.name == "posix":
            with self._digest_parent_handle(digest, create=False) as (parent_fd, name):
                return self._read_blob_fd(parent_fd, name, digest)
        path = self._path_for(digest)
        self._validate_blob(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Artifact is not available",
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Artifact blob is not a regular file",
                )
            if metadata.st_size > self._max_artifact_bytes:
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Artifact exceeds the configured size limit",
                )
            with os.fdopen(descriptor, "rb") as source:
                descriptor = -1
                content = source.read(self._max_artifact_bytes + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(content) > self._max_artifact_bytes:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Artifact exceeds the configured size limit",
            )
        if sha256_digest(content) != digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Artifact content failed digest validation",
                details={"digest": digest},
            )
        return content

    def get_model(self, digest: str, model_type: type[_ModelT]) -> _ModelT:
        """Load a model only when its stored bytes are already the exact canonical form."""

        content = self.get(digest)
        try:
            model = model_type.model_validate_json(content)
        except ValidationError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Artifact does not contain the requested model",
                details={"digest": digest},
            ) from error
        if canonical_json_bytes(model) != content:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Model artifact bytes are not canonical",
                details={"digest": digest},
            )
        return model
