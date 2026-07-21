"""Filesystem snapshot and diff primitives with explicit completeness limits."""

from __future__ import annotations

import os
import stat
import unicodedata
from enum import StrEnum
from pathlib import Path, PurePosixPath

from agentkernel.canonical import canonical_digest, sha256_digest
from agentkernel.domain.models import Digest, NonEmptyStr, StrictModel
from agentkernel.errors import AgentKernelError, ErrorCode

_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


class EntryKind(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"


class ChangeKind(StrEnum):
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"


class TreeEntry(StrictModel):
    path: NonEmptyStr
    kind: EntryKind
    content_digest: Digest | None = None
    size_bytes: int = 0
    mode: int


class FilesystemSnapshot(StrictModel):
    schema_version: str = "1.0"
    backend: str = "filesystem"
    completeness: str = "content_size_and_posix_mode"
    entries: tuple[TreeEntry, ...]
    digest: Digest


class FileChange(StrictModel):
    path: NonEmptyStr
    kind: ChangeKind
    before: TreeEntry | None = None
    after: TreeEntry | None = None


class TreeDiff(StrictModel):
    base_digest: Digest
    target_digest: Digest
    changes: tuple[FileChange, ...]
    digest: Digest


def normalize_relative_path(raw: str) -> str:
    """Normalize a portable relative path without accessing a broader resource."""

    normalized = unicodedata.normalize("NFC", raw)
    if (
        not normalized
        or any(ord(character) < 32 for character in normalized)
        or "\\" in normalized
        or ":" in normalized
    ):
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Path is not a portable relative path")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Path escapes or aliases its scope")
    rendered = path.as_posix()
    if rendered != normalized:
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Path is not in canonical form")
    for part in path.parts:
        if part.endswith((" ", ".")) or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Path has a non-portable operating-system alias",
            )
    if len(rendered.encode("utf-8")) > 4096:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED, "Path exceeds the configured limit"
        )
    return rendered


def portable_path_key(path: str) -> str:
    """Return the case-insensitive portable identity used to reject path aliases."""

    return "/".join(part.casefold() for part in PurePosixPath(normalize_relative_path(path)).parts)


def resolve_scoped_path(root: Path, relative: str) -> Path:
    """Resolve a normalized path while rejecting links, junctions, and nested mounts."""

    normalized = normalize_relative_path(relative)
    root = root.resolve(strict=True)
    root_device = root.stat().st_dev
    current = root
    for part in PurePosixPath(normalized).parts:
        current = current / part
        try:
            metadata = current.lstat()
        except (FileNotFoundError, NotADirectoryError):
            # A non-directory ancestor makes the requested descendant absent, but
            # does not move its lexical path outside the already-validated root.
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Symbolic links are outside the initial filesystem assurance boundary",
                details={"path": normalized},
            )
        if current.is_junction() or current.is_mount() or metadata.st_dev != root_device:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Reparse points and nested mount boundaries are outside the filesystem scope",
                details={"path": normalized},
            )
    resolved_parent = current.parent.resolve(strict=False)
    if not resolved_parent.is_relative_to(root):
        raise AgentKernelError(ErrorCode.AUTHORITY_MISSING, "Path is outside the workspace")
    return current


def _walk(root: Path, directory: Path, entries: list[TreeEntry], *, root_device: int) -> None:
    with os.scandir(directory) as iterator:
        children = sorted(iterator, key=lambda entry: unicodedata.normalize("NFC", entry.name))
    for child in children:
        path = Path(child.path)
        relative = normalize_relative_path(path.relative_to(root).as_posix())
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if child.is_symlink():
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Filesystem snapshots reject symbolic links in the initial profile",
                details={"path": relative},
            )
        if path.is_junction() or path.is_mount() or metadata.st_dev != root_device:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Filesystem snapshots reject junctions, reparse points, and nested mounts",
                details={"path": relative},
            )
        if child.is_dir(follow_symlinks=False):
            entries.append(TreeEntry(path=relative, kind=EntryKind.DIRECTORY, mode=mode))
            _walk(root, path, entries, root_device=root_device)
            continue
        if not child.is_file(follow_symlinks=False):
            raise AgentKernelError(
                ErrorCode.UNSUPPORTED_SEMANTICS,
                "Filesystem snapshot found an unsupported entry type",
                details={"path": relative},
            )
        before = child.stat(follow_symlinks=False)
        content = path.read_bytes()
        after = child.stat(follow_symlinks=False)
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ino,
        ):
            raise AgentKernelError(ErrorCode.STALE_STATE, "File changed during snapshot")
        entries.append(
            TreeEntry(
                path=relative,
                kind=EntryKind.FILE,
                content_digest=sha256_digest(content),
                size_bytes=len(content),
                mode=mode,
            )
        )


def snapshot_tree(root: Path) -> FilesystemSnapshot:
    if root.is_symlink() or root.is_junction():
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Snapshot root cannot be a symbolic link or junction",
        )
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Snapshot root must be a directory")
    entries: list[TreeEntry] = []
    _walk(resolved, resolved, entries, root_device=resolved.stat().st_dev)
    portable_paths: dict[str, str] = {}
    for entry in entries:
        key = portable_path_key(entry.path)
        previous = portable_paths.get(key)
        if previous is not None and previous != entry.path:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Filesystem snapshot contains a non-portable path alias",
                details={"path": entry.path},
            )
        portable_paths[key] = entry.path
    ordered = tuple(sorted(entries, key=lambda entry: entry.path))
    digest = canonical_digest([entry.model_dump(mode="python") for entry in ordered])
    return FilesystemSnapshot(entries=ordered, digest=digest)


def diff_snapshots(before: FilesystemSnapshot, after: FilesystemSnapshot) -> TreeDiff:
    before_by_path = {entry.path: entry for entry in before.entries}
    after_by_path = {entry.path: entry for entry in after.entries}
    changes: list[FileChange] = []
    for path in sorted(before_by_path.keys() | after_by_path.keys()):
        previous = before_by_path.get(path)
        current = after_by_path.get(path)
        if previous is None:
            changes.append(FileChange(path=path, kind=ChangeKind.CREATED, after=current))
        elif current is None:
            changes.append(FileChange(path=path, kind=ChangeKind.DELETED, before=previous))
        elif previous != current:
            changes.append(
                FileChange(path=path, kind=ChangeKind.MODIFIED, before=previous, after=current)
            )
    material = {
        "base_digest": before.digest,
        "target_digest": after.digest,
        "changes": [change.model_dump(mode="python") for change in changes],
    }
    return TreeDiff(
        base_digest=before.digest,
        target_digest=after.digest,
        changes=tuple(changes),
        digest=canonical_digest(material),
    )
