"""Fenced, journaled filesystem adapter for the local v1alpha1 profile."""

from __future__ import annotations

import errno
import hashlib
import inspect
import json
import os
import shutil
import sqlite3
import stat
import sys
import threading
import time
import unicodedata
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext, suppress
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal, Self, cast

from pydantic import JsonValue, model_validator

from agentkernel.adapters.base import (
    AdapterManifest,
    AdapterObservation,
    ArtifactReader,
    BlockingCancellation,
    CommitContext,
    EffectPlan,
    EvidenceClock,
    EvidenceStore,
    OperationManifest,
    ReadOnlyContext,
    ReconcileReport,
    ReconcileStatus,
    RecoveryContext,
    StageContext,
    StagedEffect,
    StagedReceipt,
    VerifyContext,
    implementation_digest_for_modules,
    load_canonical_model_artifact,
    put_adapter_observation,
    run_blocking_quiescent,
    validate_active_deadline,
    validate_canonical_artifact,
    validate_fencing_token,
    validate_normalized_action_artifact,
    validate_permit_artifact,
    validate_recovery_action_artifacts,
)
from agentkernel.canonical import canonical_digest, canonical_json_bytes, sha256_digest
from agentkernel.domain.enums import (
    RecoveryWorkKind,
    RiskClass,
    VerificationPhase,
    VerificationStatus,
)
from agentkernel.domain.models import (
    ActionProposal,
    AuthenticatedActionContext,
    CommitPermit,
    EffectReceipt,
    InspectionPermit,
    IntentRecord,
    NormalizedAction,
    RecoveryPermit,
    RecoveryReport,
    StagePermit,
    StrictModel,
    VerificationPermit,
    VerificationReport,
)
from agentkernel.errors import AgentKernelError, ErrorCode, UnsupportedSemantics
from agentkernel.ids import new_id
from agentkernel.normalization.base import AdmittedOperation
from agentkernel.normalization.filesystem import (
    FILESYSTEM_WRITE_FILES_NORMALIZER_MANIFEST,
    FilesystemNormalizerConfig,
    FilesystemWriteFilesNormalizer,
)
from agentkernel.snapshots.filesystem import (
    ChangeKind,
    EntryKind,
    FileChange,
    FilesystemSnapshot,
    TreeDiff,
    TreeEntry,
    diff_snapshots,
    normalize_relative_path,
    portable_path_key,
    resolve_scoped_path,
    snapshot_tree,
)

FILESYSTEM_ADAPTER_VERSION = "0.2.0"
_EMBEDDED_TENANT_ID = "tenant:embedded"
# Deliberately outside the public Identifier grammar (which must begin with a letter).
# This row is written only by the v2-to-v3 migration and is a read-only, conservative
# high-water mark for legacy fences that cannot be attributed to a tenant.
_LEGACY_TENANT_ID = "!agentkernel-internal:legacy-adapter-v2"


def _reject_internal_legacy_tenant(tenant_id: str) -> None:
    if tenant_id == _LEGACY_TENANT_ID:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "The internal legacy fence namespace cannot be used by a live tenant",
        )


def _is_embedded_v2_dispatch_identity(
    *,
    intent_hash: str,
    owner_version: int,
    owner_history_sequence: int,
    owner_history_digest: str,
    dispatch_id: str,
    permit_digest: str,
    normalized_action_digest: str,
    fence_owner_version: int,
    fencing_token: int,
    target_version_guard: str,
) -> bool:
    """Recognize the exact tenant-free identity emitted by the embedded v2 path."""

    return (
        owner_version == 0
        and fence_owner_version == owner_version
        and owner_history_sequence == 0
        and normalized_action_digest == intent_hash
        and dispatch_id == f"dispatch_{intent_hash.removeprefix('sha256:')}"
        and owner_history_digest
        == canonical_digest(
            {
                "tenant_id": _EMBEDDED_TENANT_ID,
                "owner": "legacy",
                "intent_hash": intent_hash,
            }
        )
        and permit_digest
        == canonical_digest(
            {
                "tenant_id": _EMBEDDED_TENANT_ID,
                "intent_hash": intent_hash,
                "fencing_token": fencing_token,
                "target_version_guard": target_version_guard,
            }
        )
    )


class _StageManifest(StrictModel):
    schema_version: Literal[2] = 2
    status: Literal["PREPARING", "READY", "EXECUTED"]
    stage_id: str
    plan: EffectPlan
    plan_digest: str
    stage_permit: StagePermit | None = None
    stage_permit_ref: str | None = None
    base_state_digest: str
    staged_receipt: StagedReceipt | None = None


class _RecoveryManifest(StrictModel):
    schema_version: Literal[4] = 4
    tenant_id: str
    status: Literal[
        "PREPARED",
        "EFFECT_STARTED",
        "NO_EFFECT",
        "PARTIAL_OR_UNKNOWN",
        "COMMITTED",
        "ROLLED_BACK",
    ]
    dispatch_id: str
    owner_version: int
    owner_history_sequence: int
    owner_history_digest: str
    permit_digest: str
    normalized_action_digest: str
    effect_receipt: EffectReceipt
    stage_id: str
    staged_state_digest: str
    base_snapshot: FilesystemSnapshot
    backup_evidence_format: Literal["PER_CHANGE_V2", "FULL_TREE_V1"] = "PER_CHANGE_V2"
    target_evidence_status: Literal[
        "VERIFIED_SNAPSHOT",
        "HISTORICAL_TARGET_UNAVAILABLE",
    ] = "VERIFIED_SNAPSHOT"
    target_snapshot: FilesystemSnapshot | None
    diff: TreeDiff | None
    applied_paths: tuple[str, ...] = ()
    restored_paths: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _target_evidence_is_explicit_and_status_bound(self) -> Self:
        if len(set(self.applied_paths)) != len(self.applied_paths) or len(
            set(self.restored_paths)
        ) != len(self.restored_paths):
            raise ValueError("Recovery path evidence cannot contain duplicates")
        if self.target_evidence_status == "VERIFIED_SNAPSHOT":
            if self.target_snapshot is None or self.diff is None:
                raise ValueError("Verified recovery target evidence must be complete")
            return self
        if (
            self.status not in {"COMMITTED", "ROLLED_BACK"}
            or self.target_snapshot is not None
            or self.diff is not None
            or self.applied_paths
            or self.restored_paths
        ):
            raise ValueError(
                "Unavailable historical target evidence is valid only for a terminal legacy state"
            )
        return self


class _RecoveryManifestV3(StrictModel):
    """Exact complete-evidence manifest shape emitted before schema v4."""

    schema_version: Literal[3] = 3
    tenant_id: str
    status: Literal[
        "PREPARED",
        "EFFECT_STARTED",
        "NO_EFFECT",
        "PARTIAL_OR_UNKNOWN",
        "COMMITTED",
        "ROLLED_BACK",
    ]
    dispatch_id: str
    owner_version: int
    owner_history_sequence: int
    owner_history_digest: str
    permit_digest: str
    normalized_action_digest: str
    effect_receipt: EffectReceipt
    stage_id: str
    staged_state_digest: str
    base_snapshot: FilesystemSnapshot
    target_snapshot: FilesystemSnapshot
    diff: TreeDiff
    applied_paths: tuple[str, ...] = ()
    restored_paths: tuple[str, ...] = ()


class _StageManifestV1(StrictModel):
    """Exact manifest shape emitted by the 0.1.0 adapter."""

    status: Literal["PREPARING", "READY", "EXECUTED"]
    stage_id: str
    plan: EffectPlan
    plan_digest: str
    stage_permit: StagePermit | None = None
    stage_permit_ref: str | None = None
    base_state_digest: str
    staged_receipt: StagedReceipt | None = None


class _RecoveryManifestV1(StrictModel):
    """Exact recovery-manifest shape emitted by the 0.1.0 adapter."""

    status: Literal["PREPARED", "COMMITTED", "ROLLED_BACK"]
    effect_receipt: EffectReceipt
    stage_id: str
    staged_state_digest: str


class _RecoveryManifestV2(StrictModel):
    """Exact recovery-manifest shape emitted by the 0.2.0 adapter."""

    schema_version: Literal[2] = 2
    status: Literal[
        "PREPARED",
        "EFFECT_STARTED",
        "NO_EFFECT",
        "PARTIAL_OR_UNKNOWN",
        "COMMITTED",
        "ROLLED_BACK",
    ]
    dispatch_id: str
    owner_version: int
    owner_history_sequence: int
    owner_history_digest: str
    permit_digest: str
    normalized_action_digest: str
    effect_receipt: EffectReceipt
    stage_id: str
    staged_state_digest: str
    base_snapshot: FilesystemSnapshot
    target_snapshot: FilesystemSnapshot
    diff: TreeDiff
    applied_paths: tuple[str, ...] = ()
    restored_paths: tuple[str, ...] = ()


def _verified_recovery_evidence(
    manifest: _RecoveryManifest,
) -> tuple[FilesystemSnapshot, TreeDiff]:
    target = manifest.target_snapshot
    diff = manifest.diff
    if manifest.target_evidence_status != "VERIFIED_SNAPSHOT" or target is None or diff is None:
        raise AgentKernelError(
            ErrorCode.EVIDENCE_UNAVAILABLE,
            "Historical recovery target evidence is unavailable",
        )
    return target, diff


_RECOVERY_MANIFEST_SUCCESSORS: dict[str, frozenset[str]] = {
    "PREPARED": frozenset(
        {
            "PREPARED",
            "EFFECT_STARTED",
            "NO_EFFECT",
            "PARTIAL_OR_UNKNOWN",
            "COMMITTED",
            "ROLLED_BACK",
        }
    ),
    "EFFECT_STARTED": frozenset(
        {"EFFECT_STARTED", "PARTIAL_OR_UNKNOWN", "COMMITTED", "ROLLED_BACK"}
    ),
    "PARTIAL_OR_UNKNOWN": frozenset({"PARTIAL_OR_UNKNOWN", "COMMITTED", "ROLLED_BACK"}),
    "COMMITTED": frozenset({"COMMITTED", "ROLLED_BACK"}),
    "NO_EFFECT": frozenset({"NO_EFFECT"}),
    "ROLLED_BACK": frozenset({"ROLLED_BACK"}),
}


def _validate_recovery_manifest_replacement(
    current: _RecoveryManifest,
    replacement: _RecoveryManifest,
) -> None:
    immutable_fields = {
        "status",
        "applied_paths",
        "restored_paths",
    }
    if (
        current.model_dump(mode="python", exclude=immutable_fields)
        != replacement.model_dump(mode="python", exclude=immutable_fields)
        or replacement.status not in _RECOVERY_MANIFEST_SUCCESSORS[current.status]
        or replacement.applied_paths[: len(current.applied_paths)] != current.applied_paths
        or replacement.restored_paths[: len(current.restored_paths)] != current.restored_paths
    ):
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Recovery manifest replacement regressed or changed durable identity",
        )


_LEGACY_OWNER_HISTORY_DIGEST = canonical_digest({"filesystem_owner_history": "legacy-v1"})
_LEGACY_PERMIT_DIGEST = canonical_digest({"filesystem_commit_permit": "legacy-v1"})


class _DispatchReservation(StrictModel):
    tenant_id: str
    intent_hash: str
    owner_version: int
    owner_history_sequence: int
    owner_history_digest: str
    dispatch_id: str
    transaction_id: str
    stage_id: str
    staged_state_digest: str
    permit_digest: str
    normalized_action_digest: str
    receipt: EffectReceipt
    status: Literal[
        "RESERVED",
        "PREPARED",
        "EFFECT_STARTED",
        "NO_EFFECT",
        "PARTIAL_OR_UNKNOWN",
        "COMMITTED",
        "ROLLED_BACK",
    ]
    classification_ref: str | None = None
    row_digest: str
    created_at: datetime
    updated_at: datetime


_METADATA_SCHEMA_VERSION = 3
_MAX_FILES = 256
_MAX_TOTAL_CONTENT_BYTES = 1_048_576
_MAX_MANIFEST_BYTES = 67_108_864
_MAX_SNAPSHOT_ENTRIES = 100_000
_MAX_SNAPSHOT_CONTENT_BYTES = 1_073_741_824
_PRIVATE_LOCK_TIMEOUT_SECONDS = 10.0
_METADATA_SCHEMA_V2_SQL_DIGESTS = {
    "adapter_dispatches": "sha256:c7a7193e4132cce7bde6327af4c5faa155424616eb18f4fea285a0bb5df4ab5b",
    "adapter_dispatches_identity_immutable": (
        "sha256:ea49b3d51c95c90fb37235ebe17d6757dc88b4fd044d8ceedda3ef51348acc7d"
    ),
    "adapter_dispatches_legal_transition": (
        "sha256:2760cd096721a5442aadd52dd17321220ada3f5e395346460b93ab1b8e156ae5"
    ),
    "adapter_schema_metadata": (
        "sha256:e7e48afe7e3f74eb6afa7c09e9ecb979540995da56f15cdd758585dc83a3ba7e"
    ),
    "intent_fences": "sha256:9a916304158686458ef4071f0a98d1cdde7e6ee8530f6cad0ce6f61e03b798c5",
    "transaction_fences": (
        "sha256:7fa8375a8ad02a44a3e22c1bb17160295d69d41bfd26dd878fdde9c76269d599"
    ),
}
_METADATA_SCHEMA_SQL_DIGESTS = {
    "adapter_dispatches": "sha256:c4457063ba8b195880588dfa8ac1b2b6d217fa2e03f790eaded73544f7933ae7",
    "adapter_dispatches_identity_immutable": (
        "sha256:74e4aad96a1d31d9420fdc71eba4cefced02029e23be083241ec2fa5bacd232e"
    ),
    "adapter_dispatches_legal_transition": (
        "sha256:2760cd096721a5442aadd52dd17321220ada3f5e395346460b93ab1b8e156ae5"
    ),
    "adapter_schema_metadata": (
        "sha256:e7e48afe7e3f74eb6afa7c09e9ecb979540995da56f15cdd758585dc83a3ba7e"
    ),
    "intent_fences": "sha256:935d190dd1d78731760941d351e35415a54d977650d523a0e54272282cdcb595",
    "transaction_fences": (
        "sha256:f4d45fe6c60bc0cbf74b2c0ee3752e119d12ed7941b9835fb30f411e443db0ba"
    ),
}
_POSIX_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_POSIX_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


if sys.platform == "win32":

    def _fchmod(descriptor: int, mode: int) -> None:
        del descriptor, mode
        raise AgentKernelError(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "Handle-relative mode changes are unavailable on native Windows",
        )

else:

    def _fchmod(descriptor: int, mode: int) -> None:
        os.fchmod(descriptor, mode)


def _require_handle_relative_backend() -> None:
    """Fail closed unless every syscall used by the enforced POSIX backend is available."""

    if os.name != "posix" or not getattr(os, "O_NOFOLLOW", 0) or not getattr(os, "O_DIRECTORY", 0):
        raise AgentKernelError(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "Enforced filesystem effects require a POSIX O_NOFOLLOW backend",
        )
    required_dir_fd = (os.open, os.stat, os.mkdir, os.unlink, os.rmdir, os.rename)
    if any(operation not in os.supports_dir_fd for operation in required_dir_fd):
        raise AgentKernelError(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "Enforced filesystem effects require complete dir_fd syscall support",
        )
    replace_parameters = inspect.signature(os.replace).parameters
    if not {"src_dir_fd", "dst_dir_fd"} <= set(replace_parameters):
        raise AgentKernelError(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "Enforced filesystem effects require handle-relative atomic replacement",
        )
    if os.stat not in os.supports_follow_symlinks:
        raise AgentKernelError(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "Enforced filesystem effects require no-follow stat support",
        )
    if os.listdir not in os.supports_fd or any(
        not hasattr(os, operation)
        for operation in ("dup", "fchmod", "fstat", "fsync", "read", "write")
    ):
        raise AgentKernelError(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "Enforced filesystem effects require fd traversal, durability, and mode controls",
        )


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino, first.st_mode) == (
        second.st_dev,
        second.st_ino,
        second.st_mode,
    )


def _open_verified_root(path: Path, identity: tuple[int, int]) -> int:
    """Open one captured directory root without following its final component."""

    try:
        descriptor = os.open(path, _POSIX_DIRECTORY_FLAGS)
    except OSError as error:
        raise AgentKernelError(
            ErrorCode.STALE_STATE,
            "A captured filesystem root is no longer safely reachable",
        ) from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != identity:
        os.close(descriptor)
        raise AgentKernelError(
            ErrorCode.STALE_STATE,
            "A captured filesystem root was replaced",
        )
    return descriptor


def _open_child_directory(parent_fd: int, name: str, *, root_device: int) -> int:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(name, _POSIX_DIRECTORY_FLAGS, dir_fd=parent_fd)
    except (FileNotFoundError, NotADirectoryError):
        raise
    except OSError as error:
        raise AgentKernelError(
            ErrorCode.STALE_STATE,
            "A filesystem ancestor became linked or inaccessible",
        ) from error
    after = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(after.st_mode)
        or after.st_dev != root_device
        or not _same_file_identity(before, after)
    ):
        os.close(descriptor)
        raise AgentKernelError(
            ErrorCode.STALE_STATE,
            "A filesystem ancestor changed during handle-relative traversal",
        )
    return descriptor


def _open_parent_directory(root_fd: int, relative: str) -> tuple[int, str]:
    normalized = normalize_relative_path(relative)
    parts = PurePosixPath(normalized).parts
    current = os.dup(root_fd)
    root_device = os.fstat(root_fd).st_dev
    try:
        for part in parts[:-1]:
            child = _open_child_directory(current, part, root_device=root_device)
            os.close(current)
            current = child
        return current, parts[-1]
    except BaseException:
        os.close(current)
        raise


def _read_regular_file_at(
    parent_fd: int,
    name: str,
    *,
    root_device: int,
    expected: os.stat_result | None = None,
    deadline: datetime | None = None,
) -> tuple[str, int, int]:
    """Hash a regular file through a no-follow fd and prove stable identity/content size."""

    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(name, _POSIX_FILE_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise AgentKernelError(
            ErrorCode.STALE_STATE,
            "A filesystem file became linked or inaccessible",
        ) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != root_device
            or not _same_file_identity(before, opened)
            or (expected is not None and not _same_file_identity(expected, opened))
        ):
            raise AgentKernelError(
                ErrorCode.STALE_STATE,
                "A filesystem file changed during no-follow open",
            )
        if opened.st_size > _MAX_SNAPSHOT_CONTENT_BYTES:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Filesystem file exceeds the deterministic snapshot byte limit",
            )
        digest = hashlib.sha256()
        size = 0
        while True:
            if deadline is not None:
                validate_active_deadline(deadline)
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            not _same_file_identity(opened, after)
            or opened.st_size != after.st_size
            or opened.st_mtime_ns != after.st_mtime_ns
            or size != after.st_size
        ):
            raise AgentKernelError(ErrorCode.STALE_STATE, "File changed during guarded read")
        return f"sha256:{digest.hexdigest()}", size, stat.S_IMODE(after.st_mode)
    finally:
        os.close(descriptor)


def _entry_at_fd(
    root_fd: int,
    relative: str,
    *,
    deadline: datetime | None = None,
) -> TreeEntry | None:
    parent_fd, leaf = _open_parent_directory(root_fd, relative)
    root_device = os.fstat(root_fd).st_dev
    try:
        try:
            metadata = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            return None
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            child = _open_child_directory(parent_fd, leaf, root_device=root_device)
            os.close(child)
            return TreeEntry(path=relative, kind=EntryKind.DIRECTORY, mode=mode)
        if not stat.S_ISREG(metadata.st_mode):
            raise AgentKernelError(ErrorCode.STALE_STATE, "Target became linked or special")
        digest, size, opened_mode = _read_regular_file_at(
            parent_fd,
            leaf,
            root_device=root_device,
            expected=metadata,
            deadline=deadline,
        )
        return TreeEntry(
            path=relative,
            kind=EntryKind.FILE,
            content_digest=digest,
            size_bytes=size,
            mode=opened_mode,
        )
    finally:
        os.close(parent_fd)


def _snapshot_tree_fd(
    root_fd: int,
    *,
    deadline: datetime | None = None,
) -> FilesystemSnapshot:
    root_device = os.fstat(root_fd).st_dev
    entries: list[TreeEntry] = []
    total_content_bytes = 0

    def walk(directory_fd: int, prefix: str) -> None:
        nonlocal total_content_bytes
        if deadline is not None:
            validate_active_deadline(deadline)
        try:
            names = sorted(
                os.listdir(directory_fd),
                key=lambda name: unicodedata.normalize("NFC", name),
            )
        except OSError as error:
            raise AgentKernelError(
                ErrorCode.STALE_STATE,
                "Directory changed during snapshot",
            ) from error
        for name in names:
            if deadline is not None:
                validate_active_deadline(deadline)
            relative = normalize_relative_path(f"{prefix}/{name}" if prefix else name)
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                raise AgentKernelError(
                    ErrorCode.STALE_STATE,
                    "Filesystem entry changed during snapshot",
                    details={"path": relative},
                ) from error
            if metadata.st_dev != root_device:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Filesystem snapshots reject nested device boundaries",
                    details={"path": relative},
                )
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISDIR(metadata.st_mode):
                child = _open_child_directory(directory_fd, name, root_device=root_device)
                try:
                    entries.append(TreeEntry(path=relative, kind=EntryKind.DIRECTORY, mode=mode))
                    if len(entries) > _MAX_SNAPSHOT_ENTRIES:
                        raise AgentKernelError(
                            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                            "Filesystem snapshot exceeds its entry limit",
                        )
                    walk(child, relative)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise AgentKernelError(
                    ErrorCode.UNSUPPORTED_SEMANTICS,
                    "Filesystem snapshot found a linked or unsupported entry",
                    details={"path": relative},
                )
            if (
                metadata.st_size < 0
                or total_content_bytes + metadata.st_size > _MAX_SNAPSHOT_CONTENT_BYTES
            ):
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Filesystem snapshot exceeds its aggregate content byte limit",
                )
            digest, size, opened_mode = _read_regular_file_at(
                directory_fd,
                name,
                root_device=root_device,
                expected=metadata,
                deadline=deadline,
            )
            total_content_bytes += size
            entries.append(
                TreeEntry(
                    path=relative,
                    kind=EntryKind.FILE,
                    content_digest=digest,
                    size_bytes=size,
                    mode=opened_mode,
                )
            )
            if len(entries) > _MAX_SNAPSHOT_ENTRIES:
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Filesystem snapshot exceeds its entry limit",
                )

    walk(root_fd, "")
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
    snapshot = FilesystemSnapshot(
        entries=ordered,
        digest=canonical_digest([entry.model_dump(mode="python") for entry in ordered]),
    )
    _validate_snapshot_limits(snapshot)
    return snapshot


def _fsync_fd(descriptor: int) -> None:
    os.fsync(descriptor)


def _ensure_parent_directory(root_fd: int, relative: str) -> tuple[int, str]:
    """Create private-tree ancestors through an already trusted root fd."""

    normalized = normalize_relative_path(relative)
    parts = PurePosixPath(normalized).parts
    current = os.dup(root_fd)
    root_device = os.fstat(root_fd).st_dev
    try:
        for part in parts[:-1]:
            try:
                child = _open_child_directory(current, part, root_device=root_device)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=current)
                _fsync_fd(current)
                child = _open_child_directory(current, part, root_device=root_device)
            os.close(current)
            current = child
        return current, parts[-1]
    except BaseException:
        os.close(current)
        raise


def _atomic_copy_file_at(
    source_root_fd: int,
    destination_root_fd: int,
    relative: str,
    *,
    mode: int,
    create_destination_parents: bool = False,
    deadline: datetime | None = None,
) -> None:
    """Copy a no-follow source fd to an atomic destination under pinned roots."""

    source_parent, source_name = _open_parent_directory(source_root_fd, relative)
    if create_destination_parents:
        destination_parent, destination_name = _ensure_parent_directory(
            destination_root_fd,
            relative,
        )
    else:
        destination_parent, destination_name = _open_parent_directory(
            destination_root_fd,
            relative,
        )
    source_fd = -1
    temporary_fd = -1
    temporary_name = f".{destination_name}.{new_id('tmp')}"
    try:
        source_before = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
        source_fd = os.open(source_name, _POSIX_FILE_FLAGS, dir_fd=source_parent)
        source_opened = os.fstat(source_fd)
        if (
            not stat.S_ISREG(source_opened.st_mode)
            or not _same_file_identity(source_before, source_opened)
            or source_opened.st_dev != os.fstat(source_root_fd).st_dev
        ):
            raise AgentKernelError(ErrorCode.STALE_STATE, "Copy source changed during open")
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=destination_parent,
        )
        copied = 0
        while True:
            if deadline is not None:
                validate_active_deadline(deadline)
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(temporary_fd, view)
                if written <= 0:
                    raise OSError(errno.EIO, "short filesystem write")
                copied += written
                view = view[written:]
        source_after = os.fstat(source_fd)
        if (
            not _same_file_identity(source_opened, source_after)
            or source_opened.st_size != source_after.st_size
            or source_opened.st_mtime_ns != source_after.st_mtime_ns
            or copied != source_after.st_size
        ):
            raise AgentKernelError(ErrorCode.STALE_STATE, "Copy source changed during read")
        _fchmod(temporary_fd, mode)
        _fsync_fd(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        os.replace(
            temporary_name,
            destination_name,
            src_dir_fd=destination_parent,
            dst_dir_fd=destination_parent,
        )
        _fsync_fd(destination_parent)
    except OSError as error:
        raise AgentKernelError(
            ErrorCode.STALE_STATE,
            "Handle-relative atomic copy failed",
        ) from error
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if temporary_fd >= 0:
            os.close(temporary_fd)
        with suppress(FileNotFoundError):
            os.unlink(temporary_name, dir_fd=destination_parent)
        os.close(source_parent)
        os.close(destination_parent)


def _atomic_write_content_at(
    root_fd: int,
    relative: str,
    content: bytes,
    *,
    mode: int,
    deadline: datetime,
) -> None:
    parent_fd, leaf = _ensure_parent_directory(root_fd, relative)
    temporary_name = f".{leaf}.{new_id('tmp')}"
    descriptor = -1
    try:
        validate_active_deadline(deadline)
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
            validate_active_deadline(deadline)
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(errno.EIO, "short filesystem write")
            view = view[written:]
        _fchmod(descriptor, mode)
        _fsync_fd(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary_name,
            leaf,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        _fsync_fd(parent_fd)
    except OSError as error:
        raise AgentKernelError(ErrorCode.STALE_STATE, "Atomic staged write failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary_name, dir_fd=parent_fd)
        os.close(parent_fd)


def _copy_tree_at(source_fd: int, destination_fd: int, *, deadline: datetime) -> FilesystemSnapshot:
    expected = _snapshot_tree_fd(source_fd, deadline=deadline)
    directory_entries: list[TreeEntry] = []
    for entry in expected.entries:
        validate_active_deadline(deadline)
        if entry.kind is EntryKind.DIRECTORY:
            parent_fd, leaf = _ensure_parent_directory(destination_fd, entry.path)
            try:
                os.mkdir(leaf, 0o700, dir_fd=parent_fd)
                _fsync_fd(parent_fd)
            finally:
                os.close(parent_fd)
            directory_entries.append(entry)
            continue
        _atomic_copy_file_at(
            source_fd,
            destination_fd,
            entry.path,
            mode=entry.mode,
            create_destination_parents=True,
            deadline=deadline,
        )
    root_device = os.fstat(destination_fd).st_dev
    for entry in reversed(directory_entries):
        validate_active_deadline(deadline)
        parent_fd, leaf = _open_parent_directory(destination_fd, entry.path)
        child_fd = -1
        try:
            child_fd = _open_child_directory(parent_fd, leaf, root_device=root_device)
            _fchmod(child_fd, entry.mode)
            _fsync_fd(child_fd)
        finally:
            if child_fd >= 0:
                os.close(child_fd)
            os.close(parent_fd)
    actual = _snapshot_tree_fd(destination_fd, deadline=deadline)
    if actual.digest != expected.digest:
        raise AgentKernelError(ErrorCode.STALE_STATE, "Scoped handle-relative copy changed")
    return actual


def _remove_private_tree_at(parent_fd: int, name: str, *, root_device: int) -> None:
    child_fd = _open_child_directory(parent_fd, name, root_device=root_device)
    opened = os.fstat(child_fd)
    try:
        # ``Path.iterdir`` cannot preserve the verified directory handle.
        for child_name in os.listdir(child_fd):  # noqa: PTH208
            metadata = os.stat(child_name, dir_fd=child_fd, follow_symlinks=False)
            if metadata.st_dev != root_device:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Private cleanup crossed a filesystem device boundary",
                )
            if stat.S_ISDIR(metadata.st_mode):
                _remove_private_tree_at(
                    child_fd,
                    child_name,
                    root_device=root_device,
                )
            elif stat.S_ISREG(metadata.st_mode):
                os.unlink(child_name, dir_fd=child_fd)
                _fsync_fd(child_fd)
            else:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Private cleanup found a linked or special entry",
                )
        before_remove = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_file_identity(opened, before_remove):
            raise AgentKernelError(
                ErrorCode.STALE_STATE,
                "Private cleanup root changed before removal",
            )
    finally:
        os.close(child_fd)
    os.rmdir(name, dir_fd=parent_fd)
    _fsync_fd(parent_fd)


def _fsync_directory(path: Path) -> None:
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


def _effective_user_id() -> int:
    get_effective_user_id = getattr(os, "geteuid", None)
    return -1 if not callable(get_effective_user_id) else int(get_effective_user_id())


def _validate_private_directory(path: Path, *, parent: Path) -> Path:
    """Validate one existing private-state directory without following aliases."""

    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise AgentKernelError(
            ErrorCode.EVIDENCE_UNAVAILABLE,
            "Adapter private state is unavailable",
        ) from error
    private_profile_invalid = os.name == "posix" and (
        metadata.st_uid != _effective_user_id() or stat.S_IMODE(metadata.st_mode) != 0o700
    )
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or path.is_junction()
        or path.is_mount()
        or metadata.st_dev != parent.stat().st_dev
        or path.resolve(strict=True).parent != parent.resolve(strict=True)
        or private_profile_invalid
    ):
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Adapter private state contains a linked, foreign, or non-private directory",
        )
    return path


def _ensure_private_directory(path: Path, *, parent: Path) -> Path:
    if os.name != "posix":
        with suppress(FileExistsError):
            path.mkdir()
            _fsync_directory(parent)
        return _validate_private_directory(path, parent=parent)

    if path.parent.resolve(strict=True) != parent.resolve(strict=True):
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Adapter private directory escaped its expected parent",
        )
    parent_fd = -1
    child_fd = -1
    try:
        parent_fd = os.open(parent, _POSIX_DIRECTORY_FLAGS)
        parent_metadata = os.fstat(parent_fd)
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent_fd)
            _fsync_fd(parent_fd)
        except FileExistsError:
            pass
        child_fd = os.open(path.name, _POSIX_DIRECTORY_FLAGS, dir_fd=parent_fd)
        child_metadata = os.fstat(child_fd)
        if (
            not stat.S_ISDIR(child_metadata.st_mode)
            or child_metadata.st_dev != parent_metadata.st_dev
            or child_metadata.st_uid != _effective_user_id()
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter private directory has a foreign owner or filesystem",
            )
        if stat.S_IMODE(child_metadata.st_mode) != 0o700:
            _fchmod(child_fd, 0o700)
            _fsync_fd(child_fd)
            _fsync_fd(parent_fd)
    except AgentKernelError:
        raise
    except OSError as error:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Adapter private directory could not be created or hardened",
        ) from error
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
    return _validate_private_directory(path, parent=parent)


def _try_lock_descriptor(descriptor: int) -> bool:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            attributes = vars(__import__("msvcrt"))
            locking = cast("Callable[[int, int, int], None]", attributes["locking"])
            locking(descriptor, int(attributes["LK_NBLCK"]), 1)
        else:
            attributes = vars(__import__("fcntl"))
            flock = cast("Callable[[int, int], None]", attributes["flock"])
            flock(
                descriptor,
                int(attributes["LOCK_EX"]) | int(attributes["LOCK_NB"]),
            )
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK} or getattr(
            error, "winerror", None
        ) in {33, 36}:
            return False
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Adapter private-state lock could not be acquired",
        ) from error
    return True


def _unlock_descriptor(descriptor: int) -> None:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            attributes = vars(__import__("msvcrt"))
            locking = cast("Callable[[int, int, int], None]", attributes["locking"])
            locking(descriptor, int(attributes["LK_UNLCK"]), 1)
        else:
            attributes = vars(__import__("fcntl"))
            flock = cast("Callable[[int, int], None]", attributes["flock"])
            flock(descriptor, int(attributes["LOCK_UN"]))
    except OSError as error:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Adapter private-state lock could not be released",
        ) from error


@contextmanager
def _recovery_manifest_lock(directory: Path) -> Iterator[None]:
    """Serialize recovery-manifest reads and replacements across adapter processes."""

    directory = _validate_private_directory(directory, parent=directory.parent)
    path = directory / ".manifest.lock"
    descriptor = -1
    acquired = False
    try:
        descriptor = os.open(
            path,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        opened = os.fstat(descriptor)
        linked = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _same_file_identity(opened, linked)
            or path.is_symlink()
            or path.is_junction()
            or opened.st_dev != directory.stat().st_dev
            or opened.st_nlink != 1
            or (os.name == "posix" and opened.st_uid != _effective_user_id())
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter private-state lock is linked, foreign, or not regular",
            )
        if os.name == "posix" and stat.S_IMODE(opened.st_mode) != 0o600:
            fchmod = getattr(os, "fchmod", None)
            if not callable(fchmod):
                raise AgentKernelError(
                    ErrorCode.UNSUPPORTED_SEMANTICS,
                    "POSIX private-state mode hardening is unavailable",
                )
            fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        if opened.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        elif opened.st_size != 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter private-state lock has invalid durable content",
            )
        deadline = time.monotonic() + _PRIVATE_LOCK_TIMEOUT_SECONDS
        while not _try_lock_descriptor(descriptor):
            if time.monotonic() >= deadline:
                raise AgentKernelError(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "Adapter private-state lock acquisition timed out",
                )
            time.sleep(0.01)
        acquired = True
        if not _same_file_identity(os.fstat(descriptor), path.lstat()):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter private-state lock changed during acquisition",
            )
        yield
    except AgentKernelError:
        raise
    except OSError as error:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Adapter private-state lock is unavailable",
        ) from error
    finally:
        try:
            if acquired:
                _unlock_descriptor(descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def _remove_private_tree(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or path.is_junction():
        raise AgentKernelError(
            ErrorCode.ROLLBACK_FAILED,
            "Linked private staging data was quarantined instead of followed",
            review_required=True,
        )
    parent = path.parent
    try:
        shutil.rmtree(path)
        _fsync_directory(parent)
    except OSError as error:
        raise AgentKernelError(
            ErrorCode.ROLLBACK_FAILED,
            "Private staging data could not be removed",
            review_required=True,
        ) from error
    if path.exists():
        raise AgentKernelError(
            ErrorCode.ROLLBACK_FAILED,
            "Private staging data remains after cleanup",
            review_required=True,
        )


def _atomic_write_bytes(path: Path, content: bytes, *, mode: int | None = None) -> None:
    # Keep the private name independent of the destination name. Besides avoiding disclosure in
    # directory listings, this preserves enough Windows MAX_PATH headroom for the atomic sibling
    # even when the caller's destination itself is still representable.
    temporary = path.with_name(f".{new_id('tmp')}")
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            descriptor = -1
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
        if mode is not None:
            temporary.chmod(mode)
        temporary.replace(path)
        _fsync_directory(path.parent)
    except FileNotFoundError as error:
        raise AgentKernelError(
            ErrorCode.STALE_STATE,
            "Atomic write path became unavailable",
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()


def _atomic_copy_file(source: Path, destination: Path, *, mode: int) -> None:
    before = source.stat(follow_symlinks=False)
    content = source.read_bytes()
    after = source.stat(follow_symlinks=False)
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (
        after.st_size,
        after.st_mtime_ns,
        after.st_ino,
    ):
        raise AgentKernelError(ErrorCode.STALE_STATE, "Source file changed during copy")
    _atomic_write_bytes(destination, content, mode=mode)


def _atomic_write_model(path: Path, model: StrictModel) -> None:
    content = canonical_json_bytes(model)
    if len(content) > _MAX_MANIFEST_BYTES:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "Adapter private manifest exceeds its durable byte limit",
        )
    _atomic_write_bytes(path, content, mode=0o600)


def _read_stable_private_bytes(path: Path) -> bytes:
    """Read one bounded regular private file without following aliases."""

    descriptor = -1
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or path.is_junction():
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter manifest is linked or not a regular file",
            )
        if metadata.st_size > _MAX_MANIFEST_BYTES:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Adapter private manifest exceeds its durable byte limit",
            )
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        if not _same_file_identity(metadata, opened) or opened.st_size > _MAX_MANIFEST_BYTES:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter private manifest changed during no-follow open",
            )
        chunks: list[bytes] = []
        size = 0
        while size <= _MAX_MANIFEST_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, _MAX_MANIFEST_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > _MAX_MANIFEST_BYTES:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Adapter private manifest exceeds its durable byte limit",
            )
        after = os.fstat(descriptor)
        if (
            not _same_file_identity(opened, after)
            or opened.st_size != after.st_size
            or opened.st_mtime_ns != after.st_mtime_ns
            or size != after.st_size
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter private manifest changed during bounded read",
            )
        return b"".join(chunks)
    except AgentKernelError:
        raise
    except OSError as error:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Adapter private manifest is unreadable",
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _parse_canonical_model[ModelT: StrictModel](
    content: bytes,
    model_type: type[ModelT],
    *,
    serializer: Callable[[ModelT], bytes | tuple[bytes, ...]] = canonical_json_bytes,
) -> ModelT:
    try:
        model = model_type.model_validate_json(content)
    except ValueError as error:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Adapter private manifest is unreadable",
        ) from error
    serialized = serializer(model)
    accepted_content = (serialized,) if isinstance(serialized, bytes) else serialized
    if content not in accepted_content:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Adapter private manifest is not canonical",
        )
    return model


def _read_canonical_model[ModelT: StrictModel](
    path: Path,
    model_type: type[ModelT],
    *,
    serializer: Callable[[ModelT], bytes | tuple[bytes, ...]] = canonical_json_bytes,
) -> ModelT:
    return _parse_canonical_model(
        _read_stable_private_bytes(path),
        model_type,
        serializer=serializer,
    )


def _historical_v1_recovery_bytes(model: _RecoveryManifestV1) -> tuple[bytes, bytes]:
    """Reproduce the POSIX and Windows bytes emitted by the 0.1.0 text writer."""

    payload = json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return payload + b"\n", payload + b"\r\n"


def _read_versioned_manifest[CurrentT: StrictModel, PreviousT: StrictModel](
    path: Path,
    current_type: type[CurrentT],
    previous_type: type[PreviousT],
) -> CurrentT:
    """Load v2 or atomically upgrade the exact canonical 0.1.0 shape."""

    try:
        return _read_canonical_model(path, current_type)
    except AgentKernelError as current_error:
        try:
            previous = _read_canonical_model(path, previous_type)
            upgraded = current_type.model_validate(
                {"schema_version": 2, **previous.model_dump(mode="python")}
            )
        except (AgentKernelError, ValueError) as previous_error:
            raise current_error from previous_error
        _atomic_write_model(path, upgraded)
        return _read_canonical_model(path, current_type)


def _read_recovery_manifest(
    content: bytes,
    tenant_for_v2: Callable[[_RecoveryManifestV2], str],
    upgrade_v1: Callable[[_RecoveryManifestV1], _RecoveryManifest],
) -> tuple[_RecoveryManifest, bool, Literal["v1", "v2", "v3", "v4"]]:
    """Load v4 or prepare an exact earlier manifest for post-validation replacement."""

    try:
        return _parse_canonical_model(content, _RecoveryManifest), False, "v4"
    except AgentKernelError as current_error:
        try:
            previous_v3 = _parse_canonical_model(content, _RecoveryManifestV3)
            upgraded = _RecoveryManifest.model_validate(
                {
                    "schema_version": 4,
                    "target_evidence_status": "VERIFIED_SNAPSHOT",
                    **previous_v3.model_dump(mode="python", exclude={"schema_version"}),
                }
            )
            source_generation: Literal["v1", "v2", "v3"] = "v3"
        except (AgentKernelError, ValueError):
            try:
                previous_v2 = _parse_canonical_model(content, _RecoveryManifestV2)
                upgraded = _RecoveryManifest.model_validate(
                    {
                        "schema_version": 4,
                        "tenant_id": tenant_for_v2(previous_v2),
                        "target_evidence_status": "VERIFIED_SNAPSHOT",
                        **previous_v2.model_dump(mode="python", exclude={"schema_version"}),
                    }
                )
                source_generation = "v2"
            except (AgentKernelError, ValueError):
                try:
                    previous_v1 = _parse_canonical_model(
                        content,
                        _RecoveryManifestV1,
                        serializer=_historical_v1_recovery_bytes,
                    )
                    upgraded = upgrade_v1(previous_v1)
                    source_generation = "v1"
                except (AgentKernelError, ValueError) as v1_error:
                    raise current_error from v1_error
        return upgraded, True, source_generation


def _validate_snapshot_limits(snapshot: FilesystemSnapshot) -> None:
    if len(snapshot.entries) > _MAX_SNAPSHOT_ENTRIES:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "Filesystem snapshot exceeds its entry limit",
        )
    if len(canonical_json_bytes(snapshot)) > _MAX_MANIFEST_BYTES:
        raise AgentKernelError(
            ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            "Filesystem snapshot exceeds its canonical byte limit",
        )


def _copy_scoped_tree(
    source: Path,
    destination: Path,
    *,
    deadline: datetime | None,
) -> FilesystemSnapshot:
    """Copy only snapshot-admitted entries, fsync them, and prove the copy."""

    expected = snapshot_tree(source)
    destination.mkdir(mode=0o700)
    _fsync_directory(destination.parent)
    try:
        directory_modes: list[tuple[Path, int]] = []
        for entry in expected.entries:
            if deadline is not None:
                validate_active_deadline(deadline)
            target = resolve_scoped_path(destination, entry.path)
            if entry.kind is EntryKind.DIRECTORY:
                target.mkdir(parents=True, exist_ok=False)
                _fsync_directory(target.parent)
                directory_modes.append((target, entry.mode))
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            origin = resolve_scoped_path(source, entry.path)
            _atomic_copy_file(origin, target, mode=entry.mode)
        for directory, mode in reversed(directory_modes):
            if deadline is not None:
                validate_active_deadline(deadline)
            directory.chmod(mode)
            _fsync_directory(directory)
        actual = snapshot_tree(destination)
        if actual.digest != expected.digest:
            raise AgentKernelError(
                ErrorCode.STALE_STATE,
                "Filesystem changed while creating a scoped copy",
            )
        return actual
    except BaseException:
        _remove_private_tree(destination)
        raise


def _entry_at(root: Path, relative: str) -> TreeEntry | None:
    path = resolve_scoped_path(root, relative)
    try:
        metadata = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    if path.is_symlink() or path.is_junction() or path.is_mount():
        raise AgentKernelError(ErrorCode.STALE_STATE, "Target path became a linked boundary")
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISDIR(metadata.st_mode):
        return TreeEntry(path=relative, kind=EntryKind.DIRECTORY, mode=mode)
    if not stat.S_ISREG(metadata.st_mode):
        raise AgentKernelError(ErrorCode.STALE_STATE, "Target path became a special file")
    before = path.stat(follow_symlinks=False)
    content = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (
        after.st_size,
        after.st_mtime_ns,
        after.st_ino,
    ):
        raise AgentKernelError(ErrorCode.STALE_STATE, "Target file changed during guard read")
    return TreeEntry(
        path=relative,
        kind=EntryKind.FILE,
        content_digest=sha256_digest(content),
        size_bytes=len(content),
        mode=mode,
    )


def _forward_changes(diff: TreeDiff) -> tuple[FileChange, ...]:
    created_directories = sorted(
        (
            change
            for change in diff.changes
            if change.after is not None
            and change.after.kind is EntryKind.DIRECTORY
            and change.before is None
        ),
        key=lambda change: (change.path.count("/"), change.path),
    )
    written_files = sorted(
        (
            change
            for change in diff.changes
            if change.after is not None and change.after.kind is EntryKind.FILE
        ),
        key=lambda change: change.path,
    )
    deleted_files = sorted(
        (
            change
            for change in diff.changes
            if change.kind is ChangeKind.DELETED
            and change.before is not None
            and change.before.kind is EntryKind.FILE
        ),
        key=lambda change: change.path,
    )
    deleted_directories = sorted(
        (
            change
            for change in diff.changes
            if change.kind is ChangeKind.DELETED
            and change.before is not None
            and change.before.kind is EntryKind.DIRECTORY
        ),
        key=lambda change: (-change.path.count("/"), change.path),
    )
    changed_directories = sorted(
        (
            change
            for change in diff.changes
            if change.before is not None
            and change.after is not None
            and change.after.kind is EntryKind.DIRECTORY
        ),
        key=lambda change: (-change.path.count("/"), change.path),
    )
    return tuple(
        created_directories
        + written_files
        + deleted_files
        + deleted_directories
        + changed_directories
    )


class FilesystemAdapter:
    """Promote a verified per-file diff under durable permits and recovery guards.

    The declared snapshot covers file content, size, directory presence, and POSIX mode bits.
    It does not claim restoration of ACLs, xattrs, alternate data streams, open-file state, or
    resistance to a malicious writer that already controls the trusted adapter host.
    """

    def __init__(
        self,
        *,
        workspace: Path,
        state_root: Path,
        require_permits: bool = False,
        artifacts: ArtifactReader | None = None,
        clock: EvidenceClock | None = None,
        normalizer_config: FilesystemNormalizerConfig | None = None,
    ) -> None:
        if require_permits and os.name == "nt":
            raise AgentKernelError(
                ErrorCode.UNSUPPORTED_SEMANTICS,
                "Native Windows lacks the admitted handle-relative filesystem backend; "
                "use Linux, WSL, or the container profile for enforced effects",
            )
        if require_permits:
            _require_handle_relative_backend()
            if not isinstance(artifacts, EvidenceStore):
                raise AgentKernelError(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "Enforced filesystem effects require a writable evidence store",
                )
        if workspace.is_symlink() or workspace.is_junction():
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Workspace root cannot be a symbolic link or junction",
            )
        self._workspace = workspace.resolve(strict=True)
        workspace_metadata = self._workspace.stat()
        self._workspace_identity = (workspace_metadata.st_dev, workspace_metadata.st_ino)
        if state_root.exists() and (state_root.is_symlink() or state_root.is_junction()):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Adapter state root cannot be a symbolic link or junction",
            )
        self._state_root = state_root.resolve()
        if self._state_root.is_relative_to(self._workspace):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Adapter state must live outside the authoritative workspace",
            )
        self._state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._state_root = _ensure_private_directory(
            self._state_root,
            parent=self._state_root.parent,
        )
        if self._state_root.stat().st_dev != self._workspace.stat().st_dev:
            raise AgentKernelError(
                ErrorCode.UNSUPPORTED_SEMANTICS,
                "Workspace recovery requires state storage on the same filesystem device",
            )
        self._stages_root = _ensure_private_directory(
            self._state_root / "stages",
            parent=self._state_root,
        )
        self._recovery_root = _ensure_private_directory(
            self._state_root / "recovery",
            parent=self._state_root,
        )
        stages_metadata = self._stages_root.stat()
        recovery_metadata = self._recovery_root.stat()
        self._stages_identity = (stages_metadata.st_dev, stages_metadata.st_ino)
        self._recovery_identity = (recovery_metadata.st_dev, recovery_metadata.st_ino)
        self._metadata_path = self._state_root / "adapter.sqlite3"
        self._artifacts = artifacts
        self._evidence_store = artifacts if isinstance(artifacts, EvidenceStore) else None
        self._clock = clock or EvidenceClock()
        self._requires_permits = require_permits
        self._normalizer_config = normalizer_config or FilesystemNormalizerConfig()
        self._boundary_lock = threading.RLock()
        self._recovery_by_receipt: dict[tuple[str, str], _RecoveryManifest] = {}
        self._recovery_by_generation: dict[tuple[str, str, int], _RecoveryManifest] = {}
        self._recovery_by_intent: dict[tuple[str, str], _RecoveryManifest] = {}
        self.manifest = AdapterManifest(
            name="filesystem",
            version=FILESYSTEM_ADAPTER_VERSION,
            implementation_digest=implementation_digest_for_modules(
                "agentkernel.adapters.base",
                "agentkernel.adapters.filesystem",
                "agentkernel.snapshots.filesystem",
            ),
            operations={
                "write_files": OperationManifest(
                    risk_floor=RiskClass.REVERSIBLE,
                    effect_domains=("filesystem",),
                    staging=True,
                    commit=True,
                    abort=True,
                    rollback=True,
                    reconcile=True,
                    preconditions=("target_version_matches",),
                    staged_postconditions=("content_hashes_match", "paths_within_scope"),
                    committed_postconditions=("workspace_hash_matches_staged",),
                    normalizer=FILESYSTEM_WRITE_FILES_NORMALIZER_MANIFEST,
                )
            },
        )
        self._initialize_metadata()
        self._load_recovery_manifests()

    def _record_observation(
        self,
        *,
        evidence_kind: Literal[
            "staged_verification",
            "committed_verification",
            "discard_staging",
            "rollback",
            "compensation",
            "reconciliation",
        ],
        tenant_id: str,
        transaction_id: str,
        intent_hash: str,
        normalized_action_digest: str,
        subject_ref: str,
        operation_permit_ref: str,
        authority_permit_ref: str,
        subject_authority_ref: str,
        operation_status: str,
        observed_state_digest: str,
        durable_state_digest: str,
        dispatch: _DispatchReservation | None = None,
        dispatch_id: str | None = None,
        owner_version: int | None = None,
        owner_history_sequence: int | None = None,
        owner_history_digest: str | None = None,
    ) -> tuple[str, ...]:
        if not self.requires_permits:
            return ()
        if self._evidence_store is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Enforced filesystem observation store is unavailable",
            )
        explicit_generation = (
            dispatch_id,
            owner_version,
            owner_history_sequence,
            owner_history_digest,
        )
        if dispatch is not None:
            if any(value is not None for value in explicit_generation):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Adapter observation received two dispatch generations",
                )
            dispatch_id = dispatch.dispatch_id
            owner_version = dispatch.owner_version
            owner_history_sequence = dispatch.owner_history_sequence
            owner_history_digest = dispatch.owner_history_digest
        observation = AdapterObservation(
            evidence_kind=evidence_kind,
            adapter=self.manifest.name,
            adapter_manifest_digest=self.manifest.digest,
            tenant_id=tenant_id,
            transaction_id=transaction_id,
            intent_hash=intent_hash,
            normalized_action_digest=normalized_action_digest,
            subject_ref=subject_ref,
            operation_permit_ref=operation_permit_ref,
            authority_permit_ref=authority_permit_ref,
            subject_authority_ref=subject_authority_ref,
            operation_status=operation_status,
            observed_state_digest=observed_state_digest,
            durable_state_digest=durable_state_digest,
            dispatch_id=dispatch_id,
            owner_version=owner_version,
            owner_history_sequence=owner_history_sequence,
            owner_history_digest=owner_history_digest,
            observed_at=self._clock.now(),
        )
        return (put_adapter_observation(self._evidence_store, observation),)

    def _attach_recovery_observation(
        self,
        report: RecoveryReport,
        *,
        evidence_kind: Literal["discard_staging", "rollback"],
        ctx: RecoveryContext,
        transaction_id: str,
        intent_hash: str,
        normalized_action_digest: str,
        subject_ref: str,
        durable_state_digest: str,
        dispatch: _DispatchReservation | None = None,
    ) -> RecoveryReport:
        if ctx.permit is None or ctx.permit_ref is None:
            return report
        evidence_refs = self._record_observation(
            evidence_kind=evidence_kind,
            tenant_id=ctx.permit.tenant_id,
            transaction_id=transaction_id,
            intent_hash=intent_hash,
            normalized_action_digest=normalized_action_digest,
            subject_ref=subject_ref,
            operation_permit_ref=ctx.permit_ref,
            authority_permit_ref=ctx.permit_ref,
            subject_authority_ref=ctx.permit.target_evidence_ref,
            operation_status=report.status.value,
            observed_state_digest=(
                report.restored_state_digest
                or canonical_digest(
                    {
                        "observation": "unavailable",
                        "residual_effects": report.residual_effects,
                    }
                )
            ),
            durable_state_digest=durable_state_digest,
            dispatch=dispatch,
        )
        return report.model_copy(update={"evidence_refs": evidence_refs})

    @property
    def workspace(self) -> Path:
        return self._workspace

    @property
    def requires_permits(self) -> bool:
        return self._requires_permits

    @property
    def implementation_modules(self) -> tuple[str, ...]:
        return (
            "agentkernel.adapters.base",
            "agentkernel.adapters.filesystem",
            "agentkernel.snapshots.filesystem",
        )

    def _run_locked[FilesystemResultT](
        self,
        operation: Callable[[], FilesystemResultT],
        cancellation: BlockingCancellation,
    ) -> FilesystemResultT:
        with self._boundary_lock:
            cancellation.raise_if_requested()
            return operation()

    @property
    def durability_control(self) -> str:
        return "file-only-unverified-directory-sync" if os.name == "nt" else "full"

    @contextmanager
    def _workspace_handle(self) -> Iterator[int]:
        descriptor = _open_verified_root(self._workspace, self._workspace_identity)
        try:
            yield descriptor
        finally:
            os.close(descriptor)

    @contextmanager
    def _stage_workspace_handle(self, stage_id: str) -> Iterator[int]:
        stages_fd = _open_verified_root(self._stages_root, self._stages_identity)
        stage_fd = -1
        workspace_fd = -1
        try:
            root_device = os.fstat(stages_fd).st_dev
            stage_fd = _open_child_directory(
                stages_fd,
                self._stage_key(stage_id),
                root_device=root_device,
            )
            workspace_fd = _open_child_directory(
                stage_fd,
                "workspace",
                root_device=root_device,
            )
            yield workspace_fd
        finally:
            if workspace_fd >= 0:
                os.close(workspace_fd)
            if stage_fd >= 0:
                os.close(stage_fd)
            os.close(stages_fd)

    @contextmanager
    def _stage_parent_handle(self, stage_id: str) -> Iterator[int]:
        stages_fd = _open_verified_root(self._stages_root, self._stages_identity)
        stage_fd = -1
        try:
            stage_fd = _open_child_directory(
                stages_fd,
                self._stage_key(stage_id),
                root_device=os.fstat(stages_fd).st_dev,
            )
            yield stage_fd
        finally:
            if stage_fd >= 0:
                os.close(stage_fd)
            os.close(stages_fd)

    @contextmanager
    def _backup_handle(self, receipt_id: str) -> Iterator[int]:
        recovery_fd = _open_verified_root(self._recovery_root, self._recovery_identity)
        receipt_fd = -1
        backup_fd = -1
        try:
            root_device = os.fstat(recovery_fd).st_dev
            receipt_fd = _open_child_directory(
                recovery_fd,
                receipt_id,
                root_device=root_device,
            )
            backup_fd = _open_child_directory(
                receipt_fd,
                "backup",
                root_device=root_device,
            )
            yield backup_fd
        finally:
            if backup_fd >= 0:
                os.close(backup_fd)
            if receipt_fd >= 0:
                os.close(receipt_fd)
            os.close(recovery_fd)

    def _snapshot_workspace(self, *, deadline: datetime | None = None) -> FilesystemSnapshot:
        if self.requires_permits:
            with self._workspace_handle() as descriptor:
                return _snapshot_tree_fd(descriptor, deadline=deadline)
        snapshot = snapshot_tree(self._workspace)
        _validate_snapshot_limits(snapshot)
        return snapshot

    def _remove_stage_tree(self, stage_id: str) -> None:
        if not self.requires_permits:
            _remove_private_tree(self._stage_parent(stage_id))
            return
        stages_fd = _open_verified_root(self._stages_root, self._stages_identity)
        try:
            key = self._stage_key(stage_id)
            try:
                os.stat(key, dir_fd=stages_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            _remove_private_tree_at(
                stages_fd,
                key,
                root_device=os.fstat(stages_fd).st_dev,
            )
        finally:
            os.close(stages_fd)

    def _fault_point(self, name: str) -> None:
        """Override only in crash-injection tests; production behavior is a no-op."""

        del name

    def _connect_metadata(self) -> sqlite3.Connection:
        if self._metadata_path.exists() and (
            self._metadata_path.is_symlink()
            or self._metadata_path.is_junction()
            or not self._metadata_path.is_file()
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem adapter metadata is linked or not a regular file",
            )
        connection = sqlite3.connect(self._metadata_path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _tenant_for_legacy_action_digest(
        self,
        digest: str,
        *,
        expected_intent_hash: str,
        expected_transaction_id: str,
        expected_operation: str,
        embedded_fallback: bool = False,
    ) -> str:
        if self._artifacts is None:
            if embedded_fallback:
                return _EMBEDDED_TENANT_ID
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Legacy tenant-bound dispatch lacks its normalized-action artifact store",
            )
        try:
            content = self._artifacts.get(digest)
            action = NormalizedAction.model_validate_json(content)
        except (AgentKernelError, UnicodeDecodeError, ValueError):
            if embedded_fallback:
                return _EMBEDDED_TENANT_ID
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Legacy tenant-bound dispatch lacks its normalized-action artifact",
            ) from None
        if (
            canonical_json_bytes(action) != content
            or canonical_digest(action) != digest
            or action.intent_hash != expected_intent_hash
            or action.transaction_id != expected_transaction_id
            or action.adapter != self.manifest.name
            or action.operation != expected_operation
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Legacy dispatch normalized action is not canonical or bound to the dispatch",
            )
        return action.tenant_id

    def _tenant_for_legacy_recovery_manifest(self, manifest: _RecoveryManifestV2) -> str:
        receipt = manifest.effect_receipt
        connection = self._connect_metadata()
        try:
            fence = connection.execute(
                """
                SELECT owner_version, highwater FROM intent_fences
                WHERE tenant_id = ? AND intent_hash = ?
                """,
                (_EMBEDDED_TENANT_ID, receipt.intent_hash),
            ).fetchone()
        finally:
            connection.close()
        embedded_fallback = bool(
            fence is not None
            and _is_embedded_v2_dispatch_identity(
                intent_hash=receipt.intent_hash,
                owner_version=manifest.owner_version,
                owner_history_sequence=manifest.owner_history_sequence,
                owner_history_digest=manifest.owner_history_digest,
                dispatch_id=manifest.dispatch_id,
                permit_digest=manifest.permit_digest,
                normalized_action_digest=manifest.normalized_action_digest,
                fence_owner_version=cast("int", fence[0]),
                fencing_token=cast("int", fence[1]),
                target_version_guard=receipt.target_version_before,
            )
        )
        return self._tenant_for_legacy_action_digest(
            manifest.normalized_action_digest,
            expected_intent_hash=receipt.intent_hash,
            expected_transaction_id=receipt.transaction_id,
            expected_operation=receipt.operation,
            embedded_fallback=embedded_fallback,
        )

    def _upgrade_recovery_manifest_v1(
        self,
        previous: _RecoveryManifestV1,
    ) -> _RecoveryManifest:
        """Reconstruct v4 evidence from the exact 0.1.0 full-tree backup contract."""

        receipt = previous.effect_receipt
        if receipt.adapter != self.manifest.name or receipt.operation != "write_files":
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical recovery receipt belongs to another adapter operation",
            )
        directory = _ensure_private_directory(
            self._recovery_root / receipt.receipt_id,
            parent=self._recovery_root,
        )
        backup = directory / "backup"
        if not backup.exists() and not backup.is_symlink():
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical recovery record lacks its full-tree backup",
            )
        backup = _validate_private_directory(backup, parent=directory)
        base_snapshot = snapshot_tree(backup)
        _validate_snapshot_limits(base_snapshot)
        if base_snapshot.digest != receipt.target_version_before:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical recovery backup does not match its receipt",
            )
        if previous.staged_state_digest != receipt.target_version_after:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical staged state does not match its receipt",
            )

        current_snapshot = self._snapshot_workspace()
        target_snapshot: FilesystemSnapshot | None = (
            current_snapshot if current_snapshot.digest == receipt.target_version_after else None
        )
        historical_stage_present = False
        if target_snapshot is None:
            historical_stage = self._stages_root / previous.stage_id
            if historical_stage.exists() or historical_stage.is_symlink():
                historical_stage_present = True
                historical_stage = _ensure_private_directory(
                    historical_stage,
                    parent=self._stages_root,
                )
                staged_workspace = _ensure_private_directory(
                    historical_stage / "workspace",
                    parent=historical_stage,
                )
                candidate = snapshot_tree(staged_workspace)
                _validate_snapshot_limits(candidate)
                if candidate.digest == receipt.target_version_after:
                    target_snapshot = candidate
        if target_snapshot is None:
            if not historical_stage_present and previous.status in {"COMMITTED", "ROLLED_BACK"}:
                return _RecoveryManifest(
                    schema_version=4,
                    tenant_id=_EMBEDDED_TENANT_ID,
                    status=previous.status,
                    dispatch_id=f"dispatch_{receipt.intent_hash.removeprefix('sha256:')}",
                    owner_version=0,
                    owner_history_sequence=0,
                    owner_history_digest=_LEGACY_OWNER_HISTORY_DIGEST,
                    permit_digest=_LEGACY_PERMIT_DIGEST,
                    normalized_action_digest=receipt.intent_hash,
                    effect_receipt=receipt,
                    stage_id=previous.stage_id,
                    staged_state_digest=previous.staged_state_digest,
                    base_snapshot=base_snapshot,
                    backup_evidence_format="FULL_TREE_V1",
                    target_evidence_status="HISTORICAL_TARGET_UNAVAILABLE",
                    target_snapshot=None,
                    diff=None,
                )
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical recovery record lacks its verified target snapshot",
            )
        if receipt.target_version_after != target_snapshot.digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical staged state does not match its receipt",
            )
        diff = diff_snapshots(base_snapshot, target_snapshot)
        if diff.digest != receipt.effect_digest:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Historical recovery snapshots do not match the effect digest",
            )
        changed_paths = tuple(change.path for change in diff.changes)
        current_entries = {entry.path: entry for entry in current_snapshot.entries}
        applied_paths = tuple(
            change.path
            for change in diff.changes
            if current_entries.get(change.path) == change.after
        )
        upgraded_status: Literal[
            "PREPARED",
            "EFFECT_STARTED",
            "NO_EFFECT",
            "PARTIAL_OR_UNKNOWN",
            "COMMITTED",
            "ROLLED_BACK",
        ] = previous.status
        if previous.status == "PREPARED" and current_snapshot.digest not in {
            base_snapshot.digest,
            target_snapshot.digest,
        }:
            upgraded_status = "PARTIAL_OR_UNKNOWN"
        return _RecoveryManifest(
            schema_version=4,
            tenant_id=_EMBEDDED_TENANT_ID,
            status=upgraded_status,
            dispatch_id=f"dispatch_{receipt.intent_hash.removeprefix('sha256:')}",
            owner_version=0,
            owner_history_sequence=0,
            owner_history_digest=_LEGACY_OWNER_HISTORY_DIGEST,
            permit_digest=_LEGACY_PERMIT_DIGEST,
            normalized_action_digest=receipt.intent_hash,
            effect_receipt=receipt,
            stage_id=previous.stage_id,
            staged_state_digest=previous.staged_state_digest,
            base_snapshot=base_snapshot,
            backup_evidence_format="FULL_TREE_V1",
            target_evidence_status="VERIFIED_SNAPSHOT",
            target_snapshot=target_snapshot,
            diff=diff,
            applied_paths=applied_paths,
            restored_paths=(
                changed_paths
                if previous.status == "ROLLED_BACK"
                and current_snapshot.digest == base_snapshot.digest
                else ()
            ),
        )

    def _initialize_metadata(self) -> None:
        connection = self._connect_metadata()
        try:
            mode = cast("str", connection.execute("PRAGMA journal_mode=WAL").fetchone()[0])
            if mode.lower() != "wal":
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Filesystem adapter metadata did not enter WAL mode",
                )
            connection.execute("BEGIN EXCLUSIVE")
            current_version = cast("int", connection.execute("PRAGMA user_version").fetchone()[0])
            if current_version > _METADATA_SCHEMA_VERSION:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Filesystem adapter metadata schema is newer than this implementation",
                )
            existing_objects = {
                cast("str", name): cast("str", kind)
                for kind, name in connection.execute(
                    """
                    SELECT type, name FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'trigger')
                    """
                ).fetchall()
            }
            legacy_objects = {
                "transaction_fences": "table",
                "intent_fences": "table",
            }
            if current_version in {0, 1} and existing_objects not in ({}, legacy_objects):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Unknown or tampered pre-v2 filesystem metadata cannot be adopted",
                )
            if current_version in {0, 1} and existing_objects == legacy_objects:
                self._validate_legacy_metadata_schema(connection)
            if current_version == 2:
                self._validate_metadata_schema_v2(connection)
            if current_version == _METADATA_SCHEMA_VERSION:
                self._validate_metadata_schema(connection)
            else:
                self._migrate_metadata_to_v3(connection, current_version=current_version)
            connection.execute(f"PRAGMA user_version = {_METADATA_SCHEMA_VERSION}")
            self._validate_metadata_schema(connection)
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _create_metadata_schema_v3(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE transaction_fences (
                tenant_id TEXT NOT NULL,
                transaction_id TEXT NOT NULL,
                highwater INTEGER NOT NULL CHECK(highwater > 0),
                updated_at TEXT NOT NULL,
                PRIMARY KEY(tenant_id, transaction_id)
            ) STRICT
            """
        )
        connection.execute(
            """
            CREATE TABLE intent_fences (
                tenant_id TEXT NOT NULL,
                intent_hash TEXT NOT NULL,
                owner_version INTEGER NOT NULL CHECK(owner_version >= 0),
                highwater INTEGER NOT NULL CHECK(highwater > 0),
                updated_at TEXT NOT NULL,
                PRIMARY KEY(tenant_id, intent_hash)
            ) STRICT
            """
        )
        connection.execute(
            """
            CREATE TABLE adapter_dispatches (
                tenant_id TEXT NOT NULL,
                intent_hash TEXT NOT NULL,
                owner_version INTEGER NOT NULL CHECK(owner_version >= 0),
                owner_history_sequence INTEGER NOT NULL CHECK(owner_history_sequence >= 0),
                owner_history_digest TEXT NOT NULL,
                dispatch_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                transaction_id TEXT NOT NULL,
                stage_id TEXT NOT NULL,
                staged_state_digest TEXT NOT NULL,
                permit_digest TEXT NOT NULL,
                normalized_action_digest TEXT NOT NULL,
                receipt_json BLOB NOT NULL,
                status TEXT NOT NULL CHECK(status IN (
                    'RESERVED', 'PREPARED', 'EFFECT_STARTED', 'NO_EFFECT', 'PARTIAL_OR_UNKNOWN',
                    'COMMITTED', 'ROLLED_BACK'
                )),
                classification_json BLOB,
                classification_ref TEXT,
                row_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(tenant_id, intent_hash, owner_version),
                UNIQUE(tenant_id, dispatch_id),
                UNIQUE(tenant_id, receipt_id),
                CHECK((status = 'NO_EFFECT') = (classification_json IS NOT NULL)),
                CHECK((classification_json IS NULL) = (classification_ref IS NULL))
            ) STRICT
            """
        )
        connection.execute(
            """
            CREATE TRIGGER adapter_dispatches_identity_immutable
            BEFORE UPDATE ON adapter_dispatches
            WHEN OLD.tenant_id != NEW.tenant_id
                OR OLD.intent_hash != NEW.intent_hash
                OR OLD.owner_version != NEW.owner_version
                OR OLD.owner_history_sequence != NEW.owner_history_sequence
                OR OLD.owner_history_digest != NEW.owner_history_digest
                OR OLD.dispatch_id != NEW.dispatch_id
                OR OLD.receipt_id != NEW.receipt_id
                OR OLD.transaction_id != NEW.transaction_id
                OR OLD.stage_id != NEW.stage_id
                OR OLD.staged_state_digest != NEW.staged_state_digest
                OR OLD.permit_digest != NEW.permit_digest
                OR OLD.normalized_action_digest != NEW.normalized_action_digest
                OR OLD.receipt_json != NEW.receipt_json
                OR OLD.created_at != NEW.created_at
            BEGIN
                SELECT RAISE(ABORT, 'adapter dispatch identity is immutable');
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER adapter_dispatches_legal_transition
            BEFORE UPDATE OF status ON adapter_dispatches
            WHEN NOT (
                OLD.status = NEW.status
                OR (OLD.status = 'RESERVED' AND NEW.status IN (
                    'PREPARED', 'NO_EFFECT', 'PARTIAL_OR_UNKNOWN'
                ))
                OR (OLD.status = 'PREPARED' AND NEW.status IN (
                    'EFFECT_STARTED', 'NO_EFFECT', 'PARTIAL_OR_UNKNOWN',
                    'COMMITTED', 'ROLLED_BACK'
                ))
                OR (OLD.status = 'EFFECT_STARTED' AND NEW.status IN (
                    'PARTIAL_OR_UNKNOWN', 'COMMITTED', 'ROLLED_BACK'
                ))
                OR (OLD.status = 'PARTIAL_OR_UNKNOWN' AND NEW.status IN (
                    'NO_EFFECT', 'COMMITTED', 'ROLLED_BACK'
                ))
                OR (OLD.status = 'COMMITTED' AND NEW.status = 'ROLLED_BACK')
            )
            BEGIN
                SELECT RAISE(ABORT, 'illegal adapter dispatch transition');
            END
            """
        )
        connection.execute(
            """
            CREATE TABLE adapter_schema_metadata (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                schema_version INTEGER NOT NULL CHECK(schema_version > 0),
                updated_at TEXT NOT NULL
            ) STRICT
            """
        )

    def _migrate_metadata_to_v3(
        self,
        connection: sqlite3.Connection,
        *,
        current_version: int,
    ) -> None:
        transaction_tenants: dict[str, set[str]] = {}
        intent_tenants: dict[str, set[str]] = {}
        legacy_dispatch_rows: list[tuple[object, ...]] = []
        if current_version == 2:
            legacy_dispatch_rows = connection.execute(
                """
                SELECT intent_hash, owner_version, owner_history_sequence, owner_history_digest,
                       dispatch_id, receipt_id, transaction_id, stage_id, staged_state_digest,
                       permit_digest, normalized_action_digest, receipt_json, status,
                       classification_json, classification_ref, row_digest, created_at, updated_at
                FROM adapter_dispatches
                ORDER BY intent_hash, owner_version
                """
            ).fetchall()
            connection.execute("DROP TRIGGER adapter_dispatches_identity_immutable")
            connection.execute("DROP TRIGGER adapter_dispatches_legal_transition")
            connection.execute("ALTER TABLE adapter_dispatches RENAME TO adapter_dispatches_v2")
            connection.execute("DROP TABLE adapter_schema_metadata")
        if current_version in {0, 1, 2} and self._metadata_table_exists(
            connection,
            "transaction_fences",
        ):
            connection.execute("ALTER TABLE transaction_fences RENAME TO transaction_fences_v2")
            connection.execute("ALTER TABLE intent_fences RENAME TO intent_fences_v2")
        self._create_metadata_schema_v3(connection)
        for row in legacy_dispatch_rows:
            tenant_id, transaction_id, intent_hash = self._migrate_dispatch_row_v2(connection, row)
            transaction_tenants.setdefault(transaction_id, set()).add(tenant_id)
            intent_tenants.setdefault(intent_hash, set()).add(tenant_id)
        if self._metadata_table_exists(connection, "transaction_fences_v2"):
            for transaction_id, highwater, updated_at in connection.execute(
                "SELECT transaction_id, highwater, updated_at FROM transaction_fences_v2"
            ).fetchall():
                tenants = transaction_tenants.get(cast("str", transaction_id), {_LEGACY_TENANT_ID})
                connection.executemany(
                    """
                    INSERT INTO transaction_fences(
                        tenant_id, transaction_id, highwater, updated_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        (tenant_id, transaction_id, highwater, updated_at)
                        for tenant_id in sorted(tenants)
                    ),
                )
            for intent_hash, owner_version, highwater, updated_at in connection.execute(
                "SELECT intent_hash, owner_version, highwater, updated_at FROM intent_fences_v2"
            ).fetchall():
                tenants = intent_tenants.get(cast("str", intent_hash), {_LEGACY_TENANT_ID})
                connection.executemany(
                    """
                    INSERT INTO intent_fences(
                        tenant_id, intent_hash, owner_version, highwater, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        (tenant_id, intent_hash, owner_version, highwater, updated_at)
                        for tenant_id in sorted(tenants)
                    ),
                )
            connection.execute("DROP TABLE transaction_fences_v2")
            connection.execute("DROP TABLE intent_fences_v2")
        if self._metadata_table_exists(connection, "adapter_dispatches_v2"):
            connection.execute("DROP TABLE adapter_dispatches_v2")
        now = self._clock.now().isoformat()
        connection.execute(
            """
            INSERT INTO adapter_schema_metadata(singleton, schema_version, updated_at)
            VALUES (1, ?, ?)
            """,
            (_METADATA_SCHEMA_VERSION, now),
        )

    @staticmethod
    def _metadata_table_exists(connection: sqlite3.Connection, name: str) -> bool:
        return (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (name,),
            ).fetchone()
            is not None
        )

    def _migrate_dispatch_row_v2(
        self,
        connection: sqlite3.Connection,
        row: tuple[object, ...],
    ) -> tuple[str, str, str]:
        (
            intent_hash,
            owner_version,
            owner_history_sequence,
            owner_history_digest,
            dispatch_id,
            receipt_id,
            transaction_id,
            stage_id,
            staged_state_digest,
            permit_digest,
            normalized_action_digest,
            receipt_json,
            status,
            classification_json,
            classification_ref,
            row_digest,
            created_at,
            updated_at,
        ) = row
        if not isinstance(receipt_json, bytes):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Legacy dispatch receipt is not bytes",
            )
        try:
            receipt = EffectReceipt.model_validate_json(receipt_json)
            created = datetime.fromisoformat(cast("str", created_at))
            updated = datetime.fromisoformat(cast("str", updated_at))
        except (TypeError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Legacy dispatch contains invalid canonical values",
            ) from error
        classification_bytes = cast("bytes | None", classification_json)
        classification_digest = cast("str | None", classification_ref)
        if classification_bytes is not None and (
            not isinstance(classification_bytes, bytes)
            or sha256_digest(classification_bytes) != classification_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Legacy dispatch classification digest mismatch",
            )
        if classification_bytes is not None:
            try:
                parsed_classification = json.loads(classification_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Legacy dispatch classification is invalid JSON",
                ) from error
            if canonical_json_bytes(parsed_classification) != classification_bytes:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Legacy dispatch classification is not canonical",
                )
        old_digest = canonical_digest(
            {
                "intent_hash": intent_hash,
                "owner_version": owner_version,
                "owner_history_sequence": owner_history_sequence,
                "owner_history_digest": owner_history_digest,
                "dispatch_id": dispatch_id,
                "transaction_id": transaction_id,
                "stage_id": stage_id,
                "staged_state_digest": staged_state_digest,
                "permit_digest": permit_digest,
                "normalized_action_digest": normalized_action_digest,
                "receipt": receipt,
                "status": status,
                "classification_ref": classification_digest,
                "created_at": created,
                "updated_at": updated,
            }
        )
        if (
            canonical_json_bytes(receipt) != receipt_json
            or receipt.receipt_id != receipt_id
            or receipt.intent_hash != intent_hash
            or receipt.transaction_id != transaction_id
            or receipt.adapter != self.manifest.name
            or receipt.operation != "write_files"
            or cast("str", created_at) != created.isoformat()
            or cast("str", updated_at) != updated.isoformat()
            or created.utcoffset() != UTC.utcoffset(created)
            or updated.utcoffset() != UTC.utcoffset(updated)
            or row_digest != old_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Legacy dispatch failed its immutable identity binding",
            )
        legacy_fence = connection.execute(
            """
            SELECT owner_version, highwater FROM intent_fences_v2
            WHERE intent_hash = ?
            """,
            (intent_hash,),
        ).fetchone()
        embedded_fallback = bool(
            legacy_fence is not None
            and _is_embedded_v2_dispatch_identity(
                intent_hash=intent_hash,
                owner_version=cast("int", owner_version),
                owner_history_sequence=cast("int", owner_history_sequence),
                owner_history_digest=cast("str", owner_history_digest),
                dispatch_id=cast("str", dispatch_id),
                permit_digest=cast("str", permit_digest),
                normalized_action_digest=cast("str", normalized_action_digest),
                fence_owner_version=cast("int", legacy_fence[0]),
                fencing_token=cast("int", legacy_fence[1]),
                target_version_guard=receipt.target_version_before,
            )
        )
        tenant_id = self._tenant_for_legacy_action_digest(
            cast("str", normalized_action_digest),
            expected_intent_hash=intent_hash,
            expected_transaction_id=transaction_id,
            expected_operation=receipt.operation,
            embedded_fallback=embedded_fallback,
        )
        new_digest = self._dispatch_row_digest(
            tenant_id=tenant_id,
            intent_hash=intent_hash,
            owner_version=cast("int", owner_version),
            owner_history_sequence=cast("int", owner_history_sequence),
            owner_history_digest=cast("str", owner_history_digest),
            dispatch_id=cast("str", dispatch_id),
            transaction_id=transaction_id,
            stage_id=cast("str", stage_id),
            staged_state_digest=cast("str", staged_state_digest),
            permit_digest=cast("str", permit_digest),
            normalized_action_digest=cast("str", normalized_action_digest),
            receipt=receipt,
            status=cast("str", status),
            classification_ref=classification_digest,
            created_at=created,
            updated_at=updated,
        )
        connection.execute(
            """
            INSERT INTO adapter_dispatches(
                tenant_id, intent_hash, owner_version, owner_history_sequence,
                owner_history_digest, dispatch_id, receipt_id, transaction_id,
                stage_id, staged_state_digest, permit_digest, normalized_action_digest,
                receipt_json, status, classification_json, classification_ref,
                row_digest, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                intent_hash,
                owner_version,
                owner_history_sequence,
                owner_history_digest,
                dispatch_id,
                receipt_id,
                transaction_id,
                stage_id,
                staged_state_digest,
                permit_digest,
                normalized_action_digest,
                receipt_json,
                status,
                classification_json,
                classification_ref,
                new_digest,
                created_at,
                updated_at,
            ),
        )
        return tenant_id, transaction_id, intent_hash

    @staticmethod
    def _validate_legacy_metadata_schema(connection: sqlite3.Connection) -> None:
        objects = {
            cast("str", name): cast("str", sql or "")
            for name, sql in connection.execute(
                """
                SELECT name, sql FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%' AND type = 'table'
                """
            ).fetchall()
        }
        expected = {"transaction_fences", "intent_fences"}
        if set(objects) != expected or any(
            sha256_digest(" ".join(objects[name].upper().split()).encode("utf-8"))
            != _METADATA_SCHEMA_V2_SQL_DIGESTS[name]
            for name in expected
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Legacy filesystem metadata schema was tampered",
            )

    @staticmethod
    def _validate_metadata_schema_v2(connection: sqlite3.Connection) -> None:
        expected_columns = {
            "transaction_fences": ("transaction_id", "highwater", "updated_at"),
            "intent_fences": ("intent_hash", "owner_version", "highwater", "updated_at"),
            "adapter_dispatches": (
                "intent_hash",
                "owner_version",
                "owner_history_sequence",
                "owner_history_digest",
                "dispatch_id",
                "receipt_id",
                "transaction_id",
                "stage_id",
                "staged_state_digest",
                "permit_digest",
                "normalized_action_digest",
                "receipt_json",
                "status",
                "classification_json",
                "classification_ref",
                "row_digest",
                "created_at",
                "updated_at",
            ),
            "adapter_schema_metadata": ("singleton", "schema_version", "updated_at"),
        }
        objects = {
            cast("str", name): (cast("str", kind), cast("str", sql or ""))
            for kind, name, sql in connection.execute(
                """
                SELECT type, name, sql FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'trigger')
                """
            ).fetchall()
        }
        expected_objects = set(expected_columns) | {
            "adapter_dispatches_identity_immutable",
            "adapter_dispatches_legal_transition",
        }
        if set(objects) != expected_objects:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem adapter metadata has unexpected schema objects",
            )
        if any(
            sha256_digest(" ".join(objects[name][1].upper().split()).encode("utf-8"))
            != _METADATA_SCHEMA_V2_SQL_DIGESTS[name]
            for name in expected_objects
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem adapter metadata DDL differs from the pinned schema",
            )
        for table, columns in expected_columns.items():
            actual = tuple(
                cast("str", row[1])
                for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            )
            if actual != columns or objects[table][0] != "table":
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Filesystem adapter metadata columns differ from schema v2",
                    details={"table": table},
                )
        dispatch_sql = " ".join(objects["adapter_dispatches"][1].upper().split())
        required_dispatch_constraints = (
            "PRIMARY KEY(INTENT_HASH, OWNER_VERSION)",
            "UNIQUE(DISPATCH_ID)",
            "UNIQUE(RECEIPT_ID)",
            "CHECK((STATUS = 'NO_EFFECT') = (CLASSIFICATION_JSON IS NOT NULL))",
            "CHECK((CLASSIFICATION_JSON IS NULL) = (CLASSIFICATION_REF IS NULL))",
        )
        if any(fragment not in dispatch_sql for fragment in required_dispatch_constraints):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem dispatch schema lost a required integrity constraint",
            )
        for trigger in (
            "adapter_dispatches_identity_immutable",
            "adapter_dispatches_legal_transition",
        ):
            if objects[trigger][0] != "trigger" or "RAISE(ABORT" not in objects[trigger][1].upper():
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Filesystem dispatch integrity trigger is missing or changed",
                    details={"trigger": trigger},
                )
        metadata_rows = connection.execute(
            "SELECT singleton, schema_version, updated_at FROM adapter_schema_metadata"
        ).fetchall()
        if len(metadata_rows) != 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem schema metadata must contain one exact row",
            )
        singleton, schema_version, updated_at = metadata_rows[0]
        try:
            parsed_updated_at = datetime.fromisoformat(cast("str", updated_at))
        except (TypeError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem schema metadata timestamp is invalid",
            ) from error
        if (
            singleton != 1
            or schema_version != 2
            or parsed_updated_at.tzinfo is None
            or parsed_updated_at.utcoffset() != UTC.utcoffset(parsed_updated_at)
            or updated_at != parsed_updated_at.isoformat()
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem schema metadata row is not canonical v2 state",
            )

    @staticmethod
    def _validate_metadata_schema(connection: sqlite3.Connection) -> None:
        expected_columns = {
            "transaction_fences": ("tenant_id", "transaction_id", "highwater", "updated_at"),
            "intent_fences": (
                "tenant_id",
                "intent_hash",
                "owner_version",
                "highwater",
                "updated_at",
            ),
            "adapter_dispatches": (
                "tenant_id",
                "intent_hash",
                "owner_version",
                "owner_history_sequence",
                "owner_history_digest",
                "dispatch_id",
                "receipt_id",
                "transaction_id",
                "stage_id",
                "staged_state_digest",
                "permit_digest",
                "normalized_action_digest",
                "receipt_json",
                "status",
                "classification_json",
                "classification_ref",
                "row_digest",
                "created_at",
                "updated_at",
            ),
            "adapter_schema_metadata": ("singleton", "schema_version", "updated_at"),
        }
        objects = {
            cast("str", name): (cast("str", kind), cast("str", sql or ""))
            for kind, name, sql in connection.execute(
                """
                SELECT type, name, sql FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'trigger')
                """
            ).fetchall()
        }
        expected_objects = set(expected_columns) | {
            "adapter_dispatches_identity_immutable",
            "adapter_dispatches_legal_transition",
        }
        if set(objects) != expected_objects:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem adapter metadata has unexpected schema objects",
            )
        if any(
            sha256_digest(" ".join(objects[name][1].upper().split()).encode("utf-8"))
            != _METADATA_SCHEMA_SQL_DIGESTS[name]
            for name in expected_objects
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem adapter metadata DDL differs from the pinned schema",
            )
        for table, columns in expected_columns.items():
            actual = tuple(
                cast("str", row[1])
                for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            )
            if actual != columns or objects[table][0] != "table":
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Filesystem adapter metadata columns differ from schema v3",
                    details={"table": table},
                )
        dispatch_sql = " ".join(objects["adapter_dispatches"][1].upper().split())
        required_dispatch_constraints = (
            "PRIMARY KEY(TENANT_ID, INTENT_HASH, OWNER_VERSION)",
            "UNIQUE(TENANT_ID, DISPATCH_ID)",
            "UNIQUE(TENANT_ID, RECEIPT_ID)",
            "CHECK((STATUS = 'NO_EFFECT') = (CLASSIFICATION_JSON IS NOT NULL))",
            "CHECK((CLASSIFICATION_JSON IS NULL) = (CLASSIFICATION_REF IS NULL))",
        )
        if any(fragment not in dispatch_sql for fragment in required_dispatch_constraints):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem dispatch schema lost a required tenant-scoped constraint",
            )
        for trigger in (
            "adapter_dispatches_identity_immutable",
            "adapter_dispatches_legal_transition",
        ):
            if objects[trigger][0] != "trigger" or "RAISE(ABORT" not in objects[trigger][1].upper():
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Filesystem dispatch integrity trigger is missing or changed",
                    details={"trigger": trigger},
                )
        metadata_rows = connection.execute(
            "SELECT singleton, schema_version, updated_at FROM adapter_schema_metadata"
        ).fetchall()
        if len(metadata_rows) != 1:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem schema metadata must contain one exact row",
            )
        singleton, schema_version, updated_at = metadata_rows[0]
        try:
            parsed_updated_at = datetime.fromisoformat(cast("str", updated_at))
        except (TypeError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem schema metadata timestamp is invalid",
            ) from error
        if (
            singleton != 1
            or schema_version != _METADATA_SCHEMA_VERSION
            or parsed_updated_at.tzinfo is None
            or parsed_updated_at.utcoffset() != UTC.utcoffset(parsed_updated_at)
            or updated_at != parsed_updated_at.isoformat()
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem schema metadata row is not canonical v3 state",
            )

    def _accept_transaction_fence(
        self,
        tenant_id: str,
        transaction_id: str,
        token: int,
    ) -> None:
        connection = self._connect_metadata()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._accept_transaction_fence_locked(connection, tenant_id, transaction_id, token)
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _accept_intent_fence(
        self,
        tenant_id: str,
        intent_hash: str,
        owner_version: int,
        token: int,
    ) -> None:
        connection = self._connect_metadata()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._accept_intent_fence_locked(
                connection,
                tenant_id,
                intent_hash,
                owner_version,
                token,
            )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _capture_metadata_time_locked(self, connection: sqlite3.Connection) -> datetime:
        """Capture one clock value and reject regression behind any durable transition."""

        captured = self._clock.now()
        rows = connection.execute(
            """
            SELECT MAX(updated_at) FROM adapter_schema_metadata
            UNION ALL SELECT MAX(updated_at) FROM transaction_fences
            UNION ALL SELECT MAX(updated_at) FROM intent_fences
            UNION ALL SELECT MAX(updated_at) FROM adapter_dispatches
            """
        ).fetchall()
        for (raw_timestamp,) in rows:
            if raw_timestamp is None:
                continue
            try:
                durable = datetime.fromisoformat(cast("str", raw_timestamp))
            except (TypeError, ValueError) as error:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Durable adapter clock watermark is invalid",
                ) from error
            if (
                durable.tzinfo is None
                or durable.utcoffset() != UTC.utcoffset(durable)
                or raw_timestamp != durable.isoformat()
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Durable adapter clock watermark is not canonical UTC",
                )
            if captured < durable:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Evidence clock precedes a durable adapter timestamp",
                )
        return captured

    def _accept_transaction_fence_locked(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        transaction_id: str,
        token: int,
    ) -> None:
        _reject_internal_legacy_tenant(tenant_id)
        validate_fencing_token(token)
        row = connection.execute(
            """
            SELECT MAX(highwater) FROM transaction_fences
            WHERE tenant_id IN (?, ?) AND transaction_id = ?
            """,
            (tenant_id, _LEGACY_TENANT_ID, transaction_id),
        ).fetchone()
        if row is not None and row[0] is not None and token < cast("int", row[0]):
            raise AgentKernelError(
                ErrorCode.AUTHORITY_REVOKED,
                "Worker fencing token is stale",
            )
        connection.execute(
            """
            INSERT INTO transaction_fences(tenant_id, transaction_id, highwater, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(tenant_id, transaction_id) DO UPDATE SET
                highwater = MAX(transaction_fences.highwater, excluded.highwater),
                updated_at = excluded.updated_at
            """,
            (
                tenant_id,
                transaction_id,
                token,
                self._capture_metadata_time_locked(connection).isoformat(),
            ),
        )

    def _accept_intent_fence_locked(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        intent_hash: str,
        owner_version: int,
        token: int,
    ) -> None:
        _reject_internal_legacy_tenant(tenant_id)
        validate_fencing_token(token)
        row = connection.execute(
            """
            SELECT owner_version, highwater FROM intent_fences
            WHERE tenant_id IN (?, ?) AND intent_hash = ?
            ORDER BY owner_version DESC, highwater DESC LIMIT 1
            """,
            (tenant_id, _LEGACY_TENANT_ID, intent_hash),
        ).fetchone()
        if row is not None:
            current_owner, highwater = cast("tuple[int, int]", row)
            if owner_version < current_owner or (
                owner_version == current_owner and token < highwater
            ):
                raise AgentKernelError(
                    ErrorCode.AUTHORITY_REVOKED,
                    "Intent owner generation or worker fencing token is stale",
                )
        connection.execute(
            """
            INSERT INTO intent_fences(
                tenant_id, intent_hash, owner_version, highwater, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, intent_hash) DO UPDATE SET
                owner_version = excluded.owner_version,
                highwater = CASE
                    WHEN excluded.owner_version > intent_fences.owner_version
                        THEN excluded.highwater
                    ELSE MAX(intent_fences.highwater, excluded.highwater)
                END,
                updated_at = excluded.updated_at
            """,
            (
                tenant_id,
                intent_hash,
                owner_version,
                token,
                self._capture_metadata_time_locked(connection).isoformat(),
            ),
        )

    @staticmethod
    def _assert_transaction_fence_locked(
        connection: sqlite3.Connection,
        tenant_id: str,
        transaction_id: str,
        token: int,
    ) -> None:
        _reject_internal_legacy_tenant(tenant_id)
        row = connection.execute(
            """
            SELECT MAX(highwater) FROM transaction_fences
            WHERE tenant_id IN (?, ?) AND transaction_id = ?
            """,
            (tenant_id, _LEGACY_TENANT_ID, transaction_id),
        ).fetchone()
        if row != (token,):
            raise AgentKernelError(ErrorCode.AUTHORITY_REVOKED, "Worker fence is no longer current")

    @staticmethod
    def _assert_intent_fence_locked(
        connection: sqlite3.Connection,
        tenant_id: str,
        intent_hash: str,
        owner_version: int,
        token: int,
    ) -> None:
        _reject_internal_legacy_tenant(tenant_id)
        row = connection.execute(
            """
            SELECT owner_version, highwater FROM intent_fences
            WHERE tenant_id IN (?, ?) AND intent_hash = ?
            ORDER BY owner_version DESC, highwater DESC LIMIT 1
            """,
            (tenant_id, _LEGACY_TENANT_ID, intent_hash),
        ).fetchone()
        if row != (owner_version, token):
            raise AgentKernelError(
                ErrorCode.AUTHORITY_REVOKED,
                "Intent owner generation or worker fence is no longer current",
            )

    @contextmanager
    def _transaction_effect_boundary(
        self,
        tenant_id: str,
        transaction_id: str,
        token: int,
    ) -> Iterator[sqlite3.Connection]:
        with self._boundary_lock:
            connection = self._connect_metadata()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._accept_transaction_fence_locked(
                    connection,
                    tenant_id,
                    transaction_id,
                    token,
                )
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()

    @contextmanager
    def _intent_effect_boundary(
        self,
        tenant_id: str,
        intent_hash: str,
        owner_version: int,
        token: int,
    ) -> Iterator[sqlite3.Connection]:
        with self._boundary_lock:
            connection = self._connect_metadata()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._accept_intent_fence_locked(
                    connection,
                    tenant_id,
                    intent_hash,
                    owner_version,
                    token,
                )
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()

    @contextmanager
    def _metadata_effect_boundary(self) -> Iterator[sqlite3.Connection]:
        with self._boundary_lock:
            connection = self._connect_metadata()
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()

    @staticmethod
    def _dispatch_row_digest(
        *,
        tenant_id: str,
        intent_hash: str,
        owner_version: int,
        owner_history_sequence: int,
        owner_history_digest: str,
        dispatch_id: str,
        transaction_id: str,
        stage_id: str,
        staged_state_digest: str,
        permit_digest: str,
        normalized_action_digest: str,
        receipt: EffectReceipt,
        status: str,
        classification_ref: str | None,
        created_at: datetime,
        updated_at: datetime,
    ) -> str:
        return canonical_digest(
            {
                "tenant_id": tenant_id,
                "intent_hash": intent_hash,
                "owner_version": owner_version,
                "owner_history_sequence": owner_history_sequence,
                "owner_history_digest": owner_history_digest,
                "dispatch_id": dispatch_id,
                "transaction_id": transaction_id,
                "stage_id": stage_id,
                "staged_state_digest": staged_state_digest,
                "permit_digest": permit_digest,
                "normalized_action_digest": normalized_action_digest,
                "receipt": receipt,
                "status": status,
                "classification_ref": classification_ref,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )

    def _load_dispatch_row(
        self,
        row: tuple[object, ...],
    ) -> _DispatchReservation:
        (
            tenant_id,
            intent_hash,
            owner_version,
            owner_history_sequence,
            owner_history_digest,
            dispatch_id,
            receipt_id,
            transaction_id,
            stage_id,
            staged_state_digest,
            permit_digest,
            normalized_action_digest,
            receipt_json,
            status,
            classification_json,
            classification_ref,
            row_digest,
            created_at,
            updated_at,
        ) = row
        if not isinstance(receipt_json, bytes):
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Dispatch receipt is not bytes")
        try:
            receipt = EffectReceipt.model_validate_json(receipt_json)
            created = datetime.fromisoformat(cast("str", created_at))
            updated = datetime.fromisoformat(cast("str", updated_at))
        except (TypeError, ValueError) as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Dispatch row contains invalid canonical values",
            ) from error
        if (
            created.tzinfo is None
            or updated.tzinfo is None
            or created.utcoffset() != UTC.utcoffset(created)
            or updated.utcoffset() != UTC.utcoffset(updated)
            or cast("str", created_at) != created.isoformat()
            or cast("str", updated_at) != updated.isoformat()
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Dispatch timestamps are not exact canonical aware ISO values",
            )
        if canonical_json_bytes(receipt) != receipt_json:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Dispatch receipt JSON is not canonical",
            )
        classification_bytes = cast("bytes | None", classification_json)
        classification_digest = cast("str | None", classification_ref)
        parsed_classification: object | None = None
        if classification_bytes is not None:
            if (
                not isinstance(classification_bytes, bytes)
                or sha256_digest(classification_bytes) != classification_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Dispatch classification evidence digest mismatch",
                )
            try:
                parsed_classification = json.loads(classification_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Dispatch classification evidence is invalid JSON",
                ) from error
            if canonical_json_bytes(parsed_classification) != classification_bytes:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Dispatch classification evidence is not canonical",
                )
        if parsed_classification is not None and (
            not isinstance(parsed_classification, dict)
            or set(parsed_classification)
            != {
                "classification",
                "dispatch_id",
                "evidence_ref",
                "intent_hash",
                "observed_state_digest",
                "owner_version",
            }
            or parsed_classification.get("classification") != "NO_EFFECT"
            or parsed_classification.get("dispatch_id") != dispatch_id
            or parsed_classification.get("intent_hash") != intent_hash
            or parsed_classification.get("owner_version") != owner_version
            or parsed_classification.get("observed_state_digest") != receipt.target_version_before
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Dispatch NO_EFFECT evidence is not bound to its generation",
            )
        if parsed_classification is not None and self.requires_permits:
            if self._artifacts is None:
                raise AgentKernelError(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "Dispatch classification observation store is unavailable",
                )
            evidence_ref = parsed_classification.get("evidence_ref")
            if not isinstance(evidence_ref, str):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Dispatch classification observation reference is invalid",
                )
            observation_bytes = self._artifacts.get(evidence_ref)
            try:
                observation = AdapterObservation.model_validate_json(observation_bytes)
            except (UnicodeDecodeError, ValueError) as error:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Dispatch classification observation is invalid",
                ) from error
            recovery_authority = load_canonical_model_artifact(
                observation.operation_permit_ref,
                RecoveryPermit,
                self._artifacts,
                label="Reconciliation observation permit",
            )
            validate_recovery_action_artifacts(
                recovery_authority,
                self._artifacts,
                manifest=self.manifest,
                recovery_kind=RecoveryWorkKind.RECONCILE_DISPATCH,
                target_transaction_id=cast("str", transaction_id),
                target_intent_hash=cast("str", intent_hash),
                target_normalized_action_digest=cast("str", normalized_action_digest),
                target_id=cast("str", dispatch_id),
                target_evidence_ref=recovery_authority.target_evidence_ref,
                target_version_guard=receipt.target_version_before,
                target_owner_version=cast("int", owner_version),
                target_owner_history_sequence=cast("int", owner_history_sequence),
                target_owner_history_digest=cast("str", owner_history_digest),
            )
            if (
                canonical_json_bytes(observation) != observation_bytes
                or observation.evidence_kind != "reconciliation"
                or observation.adapter != self.manifest.name
                or observation.adapter_manifest_digest != self.manifest.digest
                or observation.tenant_id != tenant_id
                or recovery_authority.tenant_id != tenant_id
                or observation.transaction_id != transaction_id
                or observation.intent_hash != intent_hash
                or observation.normalized_action_digest != normalized_action_digest
                or observation.authority_permit_ref != observation.operation_permit_ref
                or observation.subject_authority_ref != recovery_authority.target_evidence_ref
                or recovery_authority.recovery_kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                or recovery_authority.target_id != dispatch_id
                or observation.operation_status != ReconcileStatus.NO_EFFECT.value
                or observation.observed_state_digest != receipt.target_version_before
                or observation.dispatch_id != dispatch_id
                or observation.owner_version != owner_version
                or observation.owner_history_sequence != owner_history_sequence
                or observation.owner_history_digest != owner_history_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Dispatch classification observation differs from its durable generation",
                )
        expected_digest = self._dispatch_row_digest(
            tenant_id=cast("str", tenant_id),
            intent_hash=cast("str", intent_hash),
            owner_version=cast("int", owner_version),
            owner_history_sequence=cast("int", owner_history_sequence),
            owner_history_digest=cast("str", owner_history_digest),
            dispatch_id=cast("str", dispatch_id),
            transaction_id=cast("str", transaction_id),
            stage_id=cast("str", stage_id),
            staged_state_digest=cast("str", staged_state_digest),
            permit_digest=cast("str", permit_digest),
            normalized_action_digest=cast("str", normalized_action_digest),
            receipt=receipt,
            status=cast("str", status),
            classification_ref=classification_digest,
            created_at=created,
            updated_at=updated,
        )
        if (
            receipt.receipt_id != receipt_id
            or receipt.intent_hash != intent_hash
            or receipt.transaction_id != transaction_id
            or row_digest != expected_digest
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Dispatch row failed its immutable identity or digest binding",
            )
        return _DispatchReservation(
            tenant_id=cast("str", tenant_id),
            intent_hash=intent_hash,
            owner_version=cast("int", owner_version),
            owner_history_sequence=cast("int", owner_history_sequence),
            owner_history_digest=cast("str", owner_history_digest),
            dispatch_id=cast("str", dispatch_id),
            transaction_id=transaction_id,
            stage_id=cast("str", stage_id),
            staged_state_digest=cast("str", staged_state_digest),
            permit_digest=cast("str", permit_digest),
            normalized_action_digest=cast("str", normalized_action_digest),
            receipt=receipt,
            status=cast(
                "Literal['RESERVED', 'PREPARED', 'EFFECT_STARTED', 'NO_EFFECT', "
                "'PARTIAL_OR_UNKNOWN', "
                "'COMMITTED', 'ROLLED_BACK']",
                status,
            ),
            classification_ref=classification_digest,
            row_digest=row_digest,
            created_at=created,
            updated_at=updated,
        )

    @staticmethod
    def _dispatch_select_sql() -> str:
        return """
            SELECT tenant_id, intent_hash, owner_version, owner_history_sequence,
                   owner_history_digest,
                   dispatch_id, receipt_id, transaction_id, stage_id, staged_state_digest,
                   permit_digest, normalized_action_digest, receipt_json, status,
                   classification_json,
                   classification_ref, row_digest, created_at, updated_at
            FROM adapter_dispatches
        """

    def _reserve_dispatch(
        self,
        *,
        receipt: StagedReceipt,
        ctx: CommitContext,
        base_snapshot: FilesystemSnapshot,
        target_snapshot: FilesystemSnapshot,
        diff: TreeDiff,
    ) -> tuple[_DispatchReservation, bool]:
        plan = receipt.staged.plan
        permit = ctx.permit
        tenant_id = permit.tenant_id if permit is not None else _EMBEDDED_TENANT_ID
        owner_version = permit.owner_version if permit is not None else 0
        owner_history_sequence = permit.owner_history_sequence if permit is not None else 0
        owner_history_digest = (
            permit.owner_history_digest
            if permit is not None
            else canonical_digest(
                {
                    "tenant_id": tenant_id,
                    "owner": "legacy",
                    "intent_hash": plan.intent_hash,
                }
            )
        )
        dispatch_id = (
            permit.dispatch_id
            if permit is not None
            else f"dispatch_{plan.intent_hash.removeprefix('sha256:')}"
        )
        permit_digest = (
            permit.permit_digest
            if permit is not None
            else canonical_digest(
                {
                    "tenant_id": tenant_id,
                    "intent_hash": plan.intent_hash,
                    "fencing_token": ctx.fencing_token,
                    "target_version_guard": ctx.target_version_guard,
                }
            )
        )
        normalized_action_digest = (
            permit.normalized_action_digest if permit is not None else plan.intent_hash
        )
        connection = self._connect_metadata()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._accept_intent_fence_locked(
                connection,
                tenant_id,
                plan.intent_hash,
                owner_version,
                ctx.fencing_token,
            )
            rows = connection.execute(
                self._dispatch_select_sql()
                + " WHERE tenant_id = ? AND intent_hash = ? ORDER BY owner_version DESC",
                (tenant_id, plan.intent_hash),
            ).fetchall()
            existing = self._load_dispatch_row(rows[0]) if rows else None
            if existing is not None and existing.owner_version == owner_version:
                if (
                    existing.dispatch_id != dispatch_id
                    or existing.transaction_id != plan.proposal.transaction_id
                    or existing.stage_id != receipt.staged.stage_id
                    or existing.staged_state_digest != receipt.staged_state_digest
                    or existing.permit_digest != permit_digest
                    or existing.normalized_action_digest != normalized_action_digest
                    or existing.receipt.target_version_before != base_snapshot.digest
                    or existing.receipt.target_version_after != target_snapshot.digest
                    or existing.receipt.effect_digest != diff.digest
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Dispatch retry differs from its durable reservation",
                    )
                connection.execute("COMMIT")
                return existing, False
            if existing is not None and (
                owner_version <= existing.owner_version
                or existing.status != "NO_EFFECT"
                or existing.classification_ref is None
                or owner_history_sequence <= existing.owner_history_sequence
            ):
                raise AgentKernelError(
                    ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                    "A later dispatch generation requires prior durable NO_EFFECT evidence",
                    reconcilable=True,
                    review_required=True,
                )
            created_at = self._capture_metadata_time_locked(connection)
            effect_receipt = EffectReceipt(
                receipt_id=new_id("receipt"),
                transaction_id=plan.proposal.transaction_id,
                adapter=self.manifest.name,
                operation=plan.proposal.operation,
                intent_hash=plan.intent_hash,
                target_version_before=base_snapshot.digest,
                target_version_after=target_snapshot.digest,
                effect_digest=diff.digest,
                created_at=created_at,
            )
            row_digest = self._dispatch_row_digest(
                tenant_id=tenant_id,
                intent_hash=plan.intent_hash,
                owner_version=owner_version,
                owner_history_sequence=owner_history_sequence,
                owner_history_digest=owner_history_digest,
                dispatch_id=dispatch_id,
                transaction_id=plan.proposal.transaction_id,
                stage_id=receipt.staged.stage_id,
                staged_state_digest=receipt.staged_state_digest,
                permit_digest=permit_digest,
                normalized_action_digest=normalized_action_digest,
                receipt=effect_receipt,
                status="RESERVED",
                classification_ref=None,
                created_at=created_at,
                updated_at=created_at,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO adapter_dispatches(
                        tenant_id, intent_hash, owner_version, owner_history_sequence,
                        owner_history_digest, dispatch_id, receipt_id, transaction_id, stage_id,
                        staged_state_digest, permit_digest, normalized_action_digest,
                        receipt_json, status,
                        classification_json,
                        classification_ref, row_digest, created_at, updated_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', NULL, NULL, ?, ?, ?
                    )
                    """,
                    (
                        tenant_id,
                        plan.intent_hash,
                        owner_version,
                        owner_history_sequence,
                        owner_history_digest,
                        dispatch_id,
                        effect_receipt.receipt_id,
                        plan.proposal.transaction_id,
                        receipt.staged.stage_id,
                        receipt.staged_state_digest,
                        permit_digest,
                        normalized_action_digest,
                        canonical_json_bytes(effect_receipt),
                        row_digest,
                        created_at.isoformat(),
                        created_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Dispatch identity collides with an existing durable reservation",
                ) from error
            connection.execute("COMMIT")
            return (
                _DispatchReservation(
                    tenant_id=tenant_id,
                    intent_hash=plan.intent_hash,
                    owner_version=owner_version,
                    owner_history_sequence=owner_history_sequence,
                    owner_history_digest=owner_history_digest,
                    dispatch_id=dispatch_id,
                    transaction_id=plan.proposal.transaction_id,
                    stage_id=receipt.staged.stage_id,
                    staged_state_digest=receipt.staged_state_digest,
                    permit_digest=permit_digest,
                    normalized_action_digest=normalized_action_digest,
                    receipt=effect_receipt,
                    status="RESERVED",
                    row_digest=row_digest,
                    created_at=created_at,
                    updated_at=created_at,
                ),
                True,
            )
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _update_dispatch_status_locked(
        self,
        connection: sqlite3.Connection,
        reservation: _DispatchReservation,
        status: Literal[
            "RESERVED",
            "PREPARED",
            "EFFECT_STARTED",
            "NO_EFFECT",
            "PARTIAL_OR_UNKNOWN",
            "COMMITTED",
            "ROLLED_BACK",
        ],
        *,
        classification: dict[str, object] | None = None,
    ) -> _DispatchReservation:
        classification_json = (
            canonical_json_bytes(classification) if classification is not None else None
        )
        classification_ref = (
            sha256_digest(classification_json) if classification_json is not None else None
        )
        updated_at = self._capture_metadata_time_locked(connection)
        row_digest = self._dispatch_row_digest(
            tenant_id=reservation.tenant_id,
            intent_hash=reservation.intent_hash,
            owner_version=reservation.owner_version,
            owner_history_sequence=reservation.owner_history_sequence,
            owner_history_digest=reservation.owner_history_digest,
            dispatch_id=reservation.dispatch_id,
            transaction_id=reservation.transaction_id,
            stage_id=reservation.stage_id,
            staged_state_digest=reservation.staged_state_digest,
            permit_digest=reservation.permit_digest,
            normalized_action_digest=reservation.normalized_action_digest,
            receipt=reservation.receipt,
            status=status,
            classification_ref=classification_ref,
            created_at=reservation.created_at,
            updated_at=updated_at,
        )
        cursor = connection.execute(
            """
            UPDATE adapter_dispatches
            SET status = ?, classification_json = ?, classification_ref = ?,
                row_digest = ?, updated_at = ?
            WHERE tenant_id = ? AND intent_hash = ? AND owner_version = ? AND row_digest = ?
            """,
            (
                status,
                classification_json,
                classification_ref,
                row_digest,
                updated_at.isoformat(),
                reservation.tenant_id,
                reservation.intent_hash,
                reservation.owner_version,
                reservation.row_digest,
            ),
        )
        if cursor.rowcount != 1:
            raise AgentKernelError(
                ErrorCode.VERSION_CONFLICT,
                "Dispatch reservation changed before its status transition",
            )
        return reservation.model_copy(
            update={
                "status": status,
                "classification_ref": classification_ref,
                "row_digest": row_digest,
                "updated_at": updated_at,
            }
        )

    def _transition_dispatch_durable(
        self,
        reservation: _DispatchReservation,
        status: Literal[
            "RESERVED",
            "PREPARED",
            "EFFECT_STARTED",
            "NO_EFFECT",
            "PARTIAL_OR_UNKNOWN",
            "COMMITTED",
            "ROLLED_BACK",
        ],
        *,
        classification: dict[str, object] | None = None,
    ) -> _DispatchReservation:
        connection = self._connect_metadata()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                self._dispatch_select_sql()
                + " WHERE tenant_id = ? AND intent_hash = ? AND owner_version = ?",
                (reservation.tenant_id, reservation.intent_hash, reservation.owner_version),
            ).fetchone()
            if row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Dispatch reservation disappeared before transition",
                )
            current = self._load_dispatch_row(row)
            if current.row_digest != reservation.row_digest:
                raise AgentKernelError(
                    ErrorCode.VERSION_CONFLICT,
                    "Dispatch reservation changed before transition",
                )
            updated = self._update_dispatch_status_locked(
                connection,
                current,
                status,
                classification=classification,
            )
            connection.execute("COMMIT")
            return updated
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _dispatch_for_generation(
        self,
        tenant_id: str,
        intent_hash: str,
        owner_version: int,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> _DispatchReservation | None:
        owned_connection = connection is None
        active = connection or self._connect_metadata()
        try:
            row = active.execute(
                self._dispatch_select_sql()
                + " WHERE tenant_id = ? AND intent_hash = ? AND owner_version = ?",
                (tenant_id, intent_hash, owner_version),
            ).fetchone()
            return self._load_dispatch_row(row) if row is not None else None
        finally:
            if owned_connection:
                active.close()

    def _latest_dispatch(
        self,
        tenant_id: str,
        intent_hash: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> _DispatchReservation | None:
        owned_connection = connection is None
        active = connection or self._connect_metadata()
        try:
            row = active.execute(
                self._dispatch_select_sql() + " WHERE tenant_id = ? AND intent_hash = ? "
                "ORDER BY owner_version DESC LIMIT 1",
                (tenant_id, intent_hash),
            ).fetchone()
            return self._load_dispatch_row(row) if row is not None else None
        finally:
            if owned_connection:
                active.close()

    def _dispatch_for_receipt(
        self,
        tenant_id: str,
        receipt_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> _DispatchReservation | None:
        owned_connection = connection is None
        active = connection or self._connect_metadata()
        try:
            row = active.execute(
                self._dispatch_select_sql() + " WHERE tenant_id = ? AND receipt_id = ?",
                (tenant_id, receipt_id),
            ).fetchone()
            return self._load_dispatch_row(row) if row is not None else None
        finally:
            if owned_connection:
                active.close()

    @staticmethod
    def _validate_manifest_dispatch_binding(
        manifest: _RecoveryManifest,
        reservation: _DispatchReservation,
    ) -> None:
        receipt = manifest.effect_receipt
        if (
            reservation.tenant_id != manifest.tenant_id
            or reservation.dispatch_id != manifest.dispatch_id
            or reservation.intent_hash != receipt.intent_hash
            or reservation.owner_version != manifest.owner_version
            or reservation.owner_history_sequence != manifest.owner_history_sequence
            or reservation.owner_history_digest != manifest.owner_history_digest
            or reservation.permit_digest != manifest.permit_digest
            or reservation.normalized_action_digest != manifest.normalized_action_digest
            or reservation.transaction_id != receipt.transaction_id
            or reservation.stage_id != manifest.stage_id
            or reservation.staged_state_digest != manifest.staged_state_digest
            or reservation.receipt != receipt
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery manifest differs from its durable dispatch generation",
            )

    def _bind_or_backfill_manifest_dispatch(
        self,
        manifest: _RecoveryManifest,
        *,
        allow_legacy_backfill: bool,
    ) -> _DispatchReservation:
        """Bind recovery evidence to its durable dispatch, backfilling only exact legacy v1."""

        connection = self._connect_metadata()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                self._dispatch_select_sql() + " WHERE tenant_id = ? AND dispatch_id = ?",
                (manifest.tenant_id, manifest.dispatch_id),
            ).fetchone()
            if row is None:
                if (
                    not allow_legacy_backfill
                    or manifest.backup_evidence_format != "FULL_TREE_V1"
                    or manifest.tenant_id != _EMBEDDED_TENANT_ID
                    or manifest.dispatch_id
                    != f"dispatch_{manifest.effect_receipt.intent_hash.removeprefix('sha256:')}"
                    or manifest.owner_version != 0
                    or manifest.owner_history_sequence != 0
                    or manifest.owner_history_digest != _LEGACY_OWNER_HISTORY_DIGEST
                    or manifest.permit_digest != _LEGACY_PERMIT_DIGEST
                    or manifest.normalized_action_digest != manifest.effect_receipt.intent_hash
                    or manifest.effect_receipt.adapter != self.manifest.name
                    or manifest.effect_receipt.operation != "write_files"
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery manifest lacks its durable dispatch reservation",
                    )
                created_at = manifest.effect_receipt.created_at
                status = manifest.status
                row_digest = self._dispatch_row_digest(
                    tenant_id=manifest.tenant_id,
                    intent_hash=manifest.effect_receipt.intent_hash,
                    owner_version=0,
                    owner_history_sequence=0,
                    owner_history_digest=_LEGACY_OWNER_HISTORY_DIGEST,
                    dispatch_id=manifest.dispatch_id,
                    transaction_id=manifest.effect_receipt.transaction_id,
                    stage_id=manifest.stage_id,
                    staged_state_digest=manifest.staged_state_digest,
                    permit_digest=_LEGACY_PERMIT_DIGEST,
                    normalized_action_digest=manifest.normalized_action_digest,
                    receipt=manifest.effect_receipt,
                    status=status,
                    classification_ref=None,
                    created_at=created_at,
                    updated_at=created_at,
                )
                try:
                    connection.execute(
                        """
                        INSERT INTO adapter_dispatches(
                            tenant_id, intent_hash, owner_version, owner_history_sequence,
                            owner_history_digest, dispatch_id, receipt_id, transaction_id, stage_id,
                            staged_state_digest, permit_digest,
                            normalized_action_digest, receipt_json, status,
                            classification_json, classification_ref, row_digest,
                            created_at, updated_at
                        ) VALUES (
                            ?, ?, 0, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?
                        )
                        """,
                        (
                            manifest.tenant_id,
                            manifest.effect_receipt.intent_hash,
                            _LEGACY_OWNER_HISTORY_DIGEST,
                            manifest.dispatch_id,
                            manifest.effect_receipt.receipt_id,
                            manifest.effect_receipt.transaction_id,
                            manifest.stage_id,
                            manifest.staged_state_digest,
                            _LEGACY_PERMIT_DIGEST,
                            manifest.normalized_action_digest,
                            canonical_json_bytes(manifest.effect_receipt),
                            status,
                            row_digest,
                            created_at.isoformat(),
                            created_at.isoformat(),
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Legacy recovery manifest conflicts with durable dispatch identity",
                    ) from error
                row = connection.execute(
                    self._dispatch_select_sql() + " WHERE tenant_id = ? AND dispatch_id = ?",
                    (manifest.tenant_id, manifest.dispatch_id),
                ).fetchone()
            if row is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery dispatch could not be loaded",
                )
            reservation = self._load_dispatch_row(row)
            self._validate_manifest_dispatch_binding(manifest, reservation)
            connection.execute("COMMIT")
            return reservation
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _require_permit(self, permit: object | None) -> None:
        if self.requires_permits and permit is None:
            raise AgentKernelError(
                ErrorCode.AUTHORITY_MISSING,
                "Enforced adapter dispatch requires a coordinator permit",
            )

    def _stage_key(self, stage_id: str) -> str:
        return canonical_digest({"stage_id": stage_id}).removeprefix("sha256:")

    def _stage_parent(self, stage_id: str) -> Path:
        return self._stages_root / self._stage_key(stage_id)

    def _stage_manifest_path(self, stage_id: str) -> Path:
        return self._stage_parent(stage_id) / "manifest.json"

    def _load_stage_manifest(self, stage_id: str) -> _StageManifest | None:
        parent = self._stage_parent(stage_id)
        if not parent.exists():
            return None
        _ensure_private_directory(parent, parent=self._stages_root)
        path = parent / "manifest.json"
        if not path.exists():
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem stage lacks its durable manifest",
            )
        workspace = parent / "workspace"
        if workspace.exists() or workspace.is_symlink():
            _ensure_private_directory(workspace, parent=parent)
        manifest = _read_versioned_manifest(path, _StageManifest, _StageManifestV1)
        files = manifest.plan.semantic_arguments.get("files")
        if (
            manifest.stage_id != stage_id
            or manifest.plan_digest != canonical_digest(manifest.plan)
            or not isinstance(files, dict)
            or not all(
                isinstance(path_value, str)
                and normalize_relative_path(path_value) == path_value
                and isinstance(content, str)
                and unicodedata.normalize("NFC", content) == content
                for path_value, content in files.items()
            )
            or (manifest.stage_permit is None) != (manifest.stage_permit_ref is None)
            or (
                manifest.stage_permit is not None
                and manifest.stage_permit_ref != canonical_digest(manifest.stage_permit)
            )
            or (manifest.status == "EXECUTED") != (manifest.staged_receipt is not None)
        ):
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Filesystem stage manifest mismatch")
        return manifest

    def _persist_stage_manifest(self, manifest: _StageManifest) -> None:
        parent = _validate_private_directory(
            self._stage_parent(manifest.stage_id),
            parent=self._stages_root,
        )
        _atomic_write_model(parent / "manifest.json", manifest)

    def _cache_recovery_manifest(self, manifest: _RecoveryManifest) -> None:
        receipt = manifest.effect_receipt
        receipt_key = (manifest.tenant_id, receipt.receipt_id)
        generation = (manifest.tenant_id, receipt.intent_hash, manifest.owner_version)
        intent_key = (manifest.tenant_id, receipt.intent_hash)
        cached_receipt = self._recovery_by_receipt.get(receipt_key)
        cached_generation = self._recovery_by_generation.get(generation)
        if cached_receipt is not None and (
            cached_receipt.dispatch_id != manifest.dispatch_id
            or cached_receipt.owner_version != manifest.owner_version
            or cached_receipt.effect_receipt != receipt
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery receipt identity changed on durable storage",
            )
        if cached_generation is not None and (
            cached_generation.dispatch_id != manifest.dispatch_id
            or cached_generation.effect_receipt.receipt_id != receipt.receipt_id
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Duplicate durable filesystem dispatch generation metadata",
            )
        self._recovery_by_receipt[receipt_key] = manifest
        self._recovery_by_generation[generation] = manifest
        latest = self._recovery_by_intent.get(intent_key)
        if latest is None or latest.owner_version <= manifest.owner_version:
            self._recovery_by_intent[intent_key] = manifest

    def _load_recovery_manifest_directory(
        self,
        directory: Path,
        *,
        connection: sqlite3.Connection | None = None,
        _cas_attempt: int = 0,
    ) -> _RecoveryManifest:
        if _cas_attempt >= 8:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Recovery manifest kept changing during bounded migration",
            )
        directory = _ensure_private_directory(directory, parent=self._recovery_root)
        path = directory / "manifest.json"
        if not path.exists():
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem recovery directory lacks its durable manifest",
            )
        backup = directory / "backup"
        if backup.exists() or backup.is_symlink():
            _ensure_private_directory(backup, parent=directory)
        with _recovery_manifest_lock(directory):
            source_content = _read_stable_private_bytes(path)
        manifest, needs_upgrade, source_generation = _read_recovery_manifest(
            source_content,
            self._tenant_for_legacy_recovery_manifest,
            self._upgrade_recovery_manifest_v1,
        )
        receipt = manifest.effect_receipt
        full_tree_backup_bound = True
        if manifest.backup_evidence_format == "FULL_TREE_V1":
            if not backup.exists() and not backup.is_symlink():
                full_tree_backup_bound = False
            else:
                backup_snapshot = snapshot_tree(backup)
                _validate_snapshot_limits(backup_snapshot)
                full_tree_backup_bound = backup_snapshot == manifest.base_snapshot
        legacy_manifest_identity = (
            manifest.tenant_id == _EMBEDDED_TENANT_ID
            and manifest.dispatch_id == f"dispatch_{receipt.intent_hash.removeprefix('sha256:')}"
            and manifest.owner_version == 0
            and manifest.owner_history_sequence == 0
            and manifest.owner_history_digest == _LEGACY_OWNER_HISTORY_DIGEST
            and manifest.permit_digest == _LEGACY_PERMIT_DIGEST
            and manifest.normalized_action_digest == receipt.intent_hash
            and receipt.adapter == self.manifest.name
            and receipt.operation == "write_files"
        )
        structurally_bound = (
            directory.name == receipt.receipt_id
            and receipt.adapter == self.manifest.name
            and receipt.operation == "write_files"
            and receipt.target_version_before == manifest.base_snapshot.digest
            and receipt.target_version_after == manifest.staged_state_digest
            and full_tree_backup_bound
            and (manifest.backup_evidence_format != "FULL_TREE_V1" or legacy_manifest_identity)
        )
        if manifest.target_evidence_status == "VERIFIED_SNAPSHOT":
            target_snapshot, diff = _verified_recovery_evidence(manifest)
            expected_diff = diff_snapshots(manifest.base_snapshot, target_snapshot)
            changed_paths = {change.path for change in diff.changes}
            structurally_bound = structurally_bound and (
                receipt.target_version_after == target_snapshot.digest
                and manifest.staged_state_digest == target_snapshot.digest
                and diff == expected_diff
                and receipt.effect_digest == diff.digest
                and set(manifest.applied_paths).issubset(changed_paths)
                and set(manifest.restored_paths).issubset(changed_paths)
            )
        else:
            structurally_bound = structurally_bound and (
                manifest.status in {"COMMITTED", "ROLLED_BACK"}
                and manifest.backup_evidence_format == "FULL_TREE_V1"
                and legacy_manifest_identity
            )
        if not structurally_bound:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem recovery metadata failed its structural bindings",
            )
        if connection is None:
            self._bind_or_backfill_manifest_dispatch(
                manifest,
                allow_legacy_backfill=source_generation == "v1",
            )
        else:
            reservation = self._dispatch_for_generation(
                manifest.tenant_id,
                receipt.intent_hash,
                manifest.owner_version,
                connection=connection,
            )
            if reservation is None:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery manifest lacks its durable dispatch reservation",
                )
            self._validate_manifest_dispatch_binding(manifest, reservation)
        self._fault_point("recovery_migration.before_compare_and_swap")
        source_changed = False
        with _recovery_manifest_lock(directory):
            if _read_stable_private_bytes(path) != source_content:
                source_changed = True
            elif needs_upgrade:
                _atomic_write_model(path, manifest)
                manifest = _read_canonical_model(path, _RecoveryManifest)
        if source_changed:
            return self._load_recovery_manifest_directory(
                directory,
                connection=connection,
                _cas_attempt=_cas_attempt + 1,
            )
        self._cache_recovery_manifest(manifest)
        return manifest

    def _load_recovery_manifest_by_receipt(
        self,
        tenant_id: str,
        receipt_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> _RecoveryManifest | None:
        directory = self._recovery_root / receipt_id
        if directory.parent != self._recovery_root or directory.name != receipt_id:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery receipt escaped its private state root",
            )
        reservation = self._dispatch_for_receipt(
            tenant_id,
            receipt_id,
            connection=connection,
        )
        manifest_optional = reservation is not None and (
            reservation.status == "RESERVED"
            or (reservation.status == "NO_EFFECT" and reservation.classification_ref is not None)
        )
        if not directory.exists() and not directory.is_symlink():
            if reservation is not None and not manifest_optional:
                raise AgentKernelError(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "Durable dispatch lost its recovery manifest",
                )
            if (tenant_id, receipt_id) in self._recovery_by_receipt:
                raise AgentKernelError(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "Previously observed recovery evidence disappeared",
                )
            return None
        directory = _ensure_private_directory(directory, parent=self._recovery_root)
        manifest_path = directory / "manifest.json"
        if not manifest_path.exists():
            backup = directory / "backup"
            if backup.exists() or backup.is_symlink():
                _ensure_private_directory(backup, parent=directory)
            if (tenant_id, receipt_id) in self._recovery_by_receipt:
                raise AgentKernelError(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "Previously observed recovery evidence disappeared",
                )
            if manifest_optional:
                return None
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Filesystem recovery directory lacks its durable manifest",
            )
        return self._load_recovery_manifest_directory(
            directory,
            connection=connection,
        )

    def _load_recovery_manifest_by_generation(
        self,
        tenant_id: str,
        intent_hash: str,
        owner_version: int,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> _RecoveryManifest | None:
        reservation = self._dispatch_for_generation(
            tenant_id,
            intent_hash,
            owner_version,
            connection=connection,
        )
        generation = (tenant_id, intent_hash, owner_version)
        if reservation is None:
            if generation in self._recovery_by_generation:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Previously observed dispatch reservation disappeared",
                )
            return None
        manifest = self._load_recovery_manifest_by_receipt(
            tenant_id,
            reservation.receipt.receipt_id,
            connection=connection,
        )
        if manifest is not None and (
            manifest.tenant_id != tenant_id
            or manifest.effect_receipt.intent_hash != intent_hash
            or manifest.owner_version != owner_version
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery generation lookup returned different durable evidence",
            )
        return manifest

    def _load_latest_recovery_manifest(
        self,
        tenant_id: str,
        intent_hash: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> _RecoveryManifest | None:
        reservation = self._latest_dispatch(tenant_id, intent_hash, connection=connection)
        if reservation is None:
            if (tenant_id, intent_hash) in self._recovery_by_intent:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Previously observed dispatch history disappeared",
                )
            return None
        return self._load_recovery_manifest_by_generation(
            tenant_id,
            intent_hash,
            reservation.owner_version,
            connection=connection,
        )

    def _load_recovery_manifests(self) -> None:
        for directory in sorted(self._recovery_root.iterdir()):
            manifest_path = directory / "manifest.json"
            if not manifest_path.exists():
                verified_directory = _ensure_private_directory(
                    directory,
                    parent=self._recovery_root,
                )
                backup = verified_directory / "backup"
                if backup.exists() or backup.is_symlink():
                    _ensure_private_directory(backup, parent=verified_directory)
                connection = self._connect_metadata()
                try:
                    rows = connection.execute(
                        self._dispatch_select_sql() + " WHERE receipt_id = ?",
                        (verified_directory.name,),
                    ).fetchall()
                    reservations = tuple(self._load_dispatch_row(row) for row in rows)
                finally:
                    connection.close()
                if len(reservations) == 1 and (
                    reservations[0].status == "RESERVED"
                    or (
                        reservations[0].status == "NO_EFFECT"
                        and reservations[0].classification_ref is not None
                    )
                ):
                    continue
            self._load_recovery_manifest_directory(directory)

    def _persist_recovery_manifest(self, manifest: _RecoveryManifest) -> None:
        manifest = _RecoveryManifest.model_validate(manifest.model_dump(mode="python"))
        receipt = manifest.effect_receipt
        directory = self._recovery_root / receipt.receipt_id
        directory = _ensure_private_directory(directory, parent=self._recovery_root)
        path = directory / "manifest.json"
        with _recovery_manifest_lock(directory):
            if path.exists() or path.is_symlink():
                current = _read_canonical_model(path, _RecoveryManifest)
                _validate_recovery_manifest_replacement(current, manifest)
            elif (manifest.tenant_id, receipt.receipt_id) in self._recovery_by_receipt:
                raise AgentKernelError(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "Previously observed recovery manifest disappeared before replacement",
                )
            _atomic_write_model(path, manifest)
        self._cache_recovery_manifest(manifest)

    def _backup_path(self, receipt_id: str) -> Path:
        receipt_directory = _validate_private_directory(
            self._recovery_root / receipt_id,
            parent=self._recovery_root,
        )
        backup = receipt_directory / "backup"
        if not backup.exists() and not backup.is_symlink():
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Filesystem recovery backup is unavailable",
            )
        return _validate_private_directory(backup, parent=receipt_directory)

    def _admit_inspection(
        self,
        proposal: ActionProposal,
        ctx: ReadOnlyContext,
    ) -> str:
        self._require_permit(ctx.permit)
        if ctx.permit is None:
            return ""
        permit = ctx.permit
        validate_active_deadline(ctx.deadline)
        validate_permit_artifact(permit, cast("str", ctx.permit_ref), self._artifacts)
        if (
            ctx.normalized_action is None
            or ctx.normalized_action_ref is None
            or ctx.proposal is None
            or ctx.proposal_ref is None
        ):
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Enforced inspection requires normalized action and proposal artifacts",
            )
        if ctx.proposal != proposal or permit.proposal_ref != ctx.proposal_ref:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Inspection proposal differs from its durable artifact binding",
            )
        validate_normalized_action_artifact(
            ctx.normalized_action,
            ctx.normalized_action_ref,
            self._artifacts,
            permit_digest=permit.normalized_action_digest,
            proposal=proposal,
            proposal_ref=ctx.proposal_ref,
            manifest=self.manifest,
        )
        action = ctx.normalized_action
        normalizer = FilesystemWriteFilesNormalizer(config=self._normalizer_config)
        expected = normalizer.normalize(
            proposal=proposal,
            context=AuthenticatedActionContext(
                tenant_id=action.tenant_id,
                principal_id=action.principal_id,
                goal_id=action.goal_id,
                run_id=action.run_id,
                trace_id=action.trace_id,
                actor_id=action.actor_id,
                on_behalf_of=action.on_behalf_of,
                agent_id=action.agent_id,
                configuration_digest=action.configuration_digest,
            ),
            operation=AdmittedOperation(
                adapter=self.manifest.name,
                adapter_version=self.manifest.version,
                adapter_manifest_digest=self.manifest.digest,
                operation=proposal.operation,
                risk_floor=self.manifest.operations[proposal.operation].risk_floor,
                effect_domains=self.manifest.operations[proposal.operation].effect_domains,
                normalizer_manifest=FILESYSTEM_WRITE_FILES_NORMALIZER_MANIFEST,
                configuration_digest=action.configuration_digest,
            ),
            provenance=action.provenance,
        )
        if (
            proposal.adapter != self.manifest.name
            or proposal.adapter_version != self.manifest.version
            or proposal.transaction_id != permit.transaction_id
            or action.tenant_id != permit.tenant_id
            or action.intent_hash != permit.intent_hash
            or permit.adapter_manifest_digest != self.manifest.digest
            or expected != action
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Inspection permit does not bind this filesystem proposal",
            )
        self._accept_transaction_fence(
            permit.tenant_id,
            permit.transaction_id,
            permit.fencing_token,
        )
        return action.intent_hash

    def _admit_stage(self, plan: EffectPlan, ctx: StageContext) -> StagePermit | None:
        self._require_permit(ctx.permit)
        if ctx.permit is None:
            return None
        permit = ctx.permit
        validate_active_deadline(ctx.deadline)
        validate_permit_artifact(permit, cast("str", ctx.permit_ref), self._artifacts)
        validate_canonical_artifact(plan, permit.plan_ref, self._artifacts, label="Effect plan")
        inspection = load_canonical_model_artifact(
            permit.inspection_permit_ref,
            InspectionPermit,
            self._artifacts,
            label="Inspection permit",
        )
        if ctx.normalized_action is None or ctx.normalized_action_ref is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Enforced stage requires the normalized action artifact",
            )
        validate_normalized_action_artifact(
            ctx.normalized_action,
            ctx.normalized_action_ref,
            self._artifacts,
            permit_digest=permit.normalized_action_digest,
            proposal=plan.proposal,
            proposal_ref=inspection.proposal_ref,
            manifest=self.manifest,
        )
        if (
            permit.adapter_manifest_digest != self.manifest.digest
            or permit.tenant_id != inspection.tenant_id
            or permit.tenant_id != ctx.normalized_action.tenant_id
            or permit.transaction_id != plan.proposal.transaction_id
            or permit.intent_hash != plan.intent_hash
            or permit.plan_digest != canonical_digest(plan)
            or permit.target_version_guard != plan.base_version
            or permit.inspection_permit_digest != inspection.permit_digest
            or inspection.transaction_id != permit.transaction_id
            or inspection.intent_hash != permit.intent_hash
            or inspection.normalized_action_digest != permit.normalized_action_digest
            or inspection.proposal_ref != canonical_digest(plan.proposal)
            or inspection.adapter_manifest_digest != permit.adapter_manifest_digest
            or inspection.authorization_round_id != permit.authorization_round_id
            or inspection.authorization_round_digest != permit.authorization_round_digest
            or inspection.lease_id != permit.lease_id
            or inspection.worker_id != permit.worker_id
            or inspection.fencing_token != permit.fencing_token
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Stage permit does not bind the inspected filesystem plan",
            )
        self._accept_transaction_fence(
            permit.tenant_id,
            permit.transaction_id,
            permit.fencing_token,
        )
        return permit

    def _admit_commit(self, receipt: StagedReceipt, ctx: CommitContext) -> None:
        self._require_permit(ctx.permit)
        if ctx.permit is None:
            self._accept_intent_fence(
                _EMBEDDED_TENANT_ID,
                receipt.staged.plan.intent_hash,
                0,
                ctx.fencing_token,
            )
            return
        permit = ctx.permit
        validate_active_deadline(ctx.deadline)
        validate_permit_artifact(permit, cast("str", ctx.permit_ref), self._artifacts)
        validate_canonical_artifact(
            receipt.staged.plan,
            permit.plan_ref,
            self._artifacts,
            label="Effect plan",
        )
        validate_canonical_artifact(
            receipt,
            permit.staged_receipt_ref,
            self._artifacts,
            label="Staged receipt",
        )
        stage_permit = load_canonical_model_artifact(
            permit.stage_permit_ref,
            StagePermit,
            self._artifacts,
            label="Stage permit",
        )
        inspection = load_canonical_model_artifact(
            stage_permit.inspection_permit_ref,
            InspectionPermit,
            self._artifacts,
            label="Inspection permit",
        )
        staged_verification = load_canonical_model_artifact(
            permit.staged_verification_ref,
            VerificationReport,
            self._artifacts,
            label="Staged verification",
        )
        staged_verification_permit = load_canonical_model_artifact(
            permit.staged_verification_permit_ref,
            VerificationPermit,
            self._artifacts,
            label="Staged verification permit",
        )
        precommit_inspection = load_canonical_model_artifact(
            permit.precommit_inspection_permit_ref,
            InspectionPermit,
            self._artifacts,
            label="Precommit inspection permit",
        )
        precommit_plan = load_canonical_model_artifact(
            permit.precommit_plan_ref,
            EffectPlan,
            self._artifacts,
            label="Precommit effect plan",
        )
        if self._artifacts is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Approval evidence is unavailable",
            )
        self._artifacts.get(permit.approval_evidence_ref)
        if ctx.normalized_action is None or ctx.normalized_action_ref is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Enforced commit requires the normalized action artifact",
            )
        validate_normalized_action_artifact(
            ctx.normalized_action,
            ctx.normalized_action_ref,
            self._artifacts,
            permit_digest=permit.normalized_action_digest,
            proposal=receipt.staged.plan.proposal,
            proposal_ref=inspection.proposal_ref,
            manifest=self.manifest,
        )
        manifest = self._load_stage_manifest(receipt.staged.stage_id)
        plan = receipt.staged.plan
        durable_dispatch = self._latest_dispatch(permit.tenant_id, plan.intent_hash)
        if (
            (
                (
                    manifest is None
                    or manifest.status != "EXECUTED"
                    or manifest.staged_receipt != receipt
                    or manifest.stage_permit != stage_permit
                )
                and durable_dispatch is None
            )
            or (
                durable_dispatch is not None
                and (
                    durable_dispatch.stage_id != receipt.staged.stage_id
                    or durable_dispatch.transaction_id != plan.proposal.transaction_id
                    or durable_dispatch.intent_hash != plan.intent_hash
                    or durable_dispatch.staged_state_digest != receipt.staged_state_digest
                    or durable_dispatch.dispatch_id != permit.dispatch_id
                    or durable_dispatch.owner_version != permit.owner_version
                    or (durable_dispatch.owner_history_sequence != permit.owner_history_sequence)
                    or durable_dispatch.owner_history_digest != permit.owner_history_digest
                    or durable_dispatch.permit_digest != permit.permit_digest
                    or (
                        durable_dispatch.normalized_action_digest != permit.normalized_action_digest
                    )
                    or durable_dispatch.receipt.target_version_before != plan.base_version
                )
            )
            or permit.adapter_manifest_digest != self.manifest.digest
            or permit.tenant_id != ctx.normalized_action.tenant_id
            or permit.tenant_id != stage_permit.tenant_id
            or permit.tenant_id != inspection.tenant_id
            or permit.transaction_id != plan.proposal.transaction_id
            or permit.intent_hash != plan.intent_hash
            or permit.stage_id != receipt.staged.stage_id
            or permit.plan_digest != canonical_digest(plan)
            or permit.stage_permit_digest != stage_permit.permit_digest
            or stage_permit.normalized_action_digest != permit.normalized_action_digest
            or inspection.normalized_action_digest != permit.normalized_action_digest
            or inspection.proposal_ref != canonical_digest(plan.proposal)
            or permit.staged_state_digest != receipt.staged_state_digest
            or staged_verification.status is not VerificationStatus.PASS
            or permit.staged_verification_permit_digest != staged_verification_permit.permit_digest
            or staged_verification_permit.phase is not VerificationPhase.STAGED
            or staged_verification_permit.subject_ref != permit.staged_receipt_ref
            or staged_verification_permit.authority_permit_digest != stage_permit.permit_digest
            or staged_verification_permit.authority_permit_ref != permit.stage_permit_ref
            or staged_verification_permit.subject_permit_digest != stage_permit.permit_digest
            or staged_verification_permit.subject_permit_ref != permit.stage_permit_ref
            or staged_verification_permit.normalized_action_digest
            != permit.normalized_action_digest
            or staged_verification_permit.adapter_manifest_digest != permit.adapter_manifest_digest
            or permit.precommit_inspection_permit_digest != precommit_inspection.permit_digest
            or precommit_inspection.transaction_id != permit.transaction_id
            or precommit_inspection.intent_hash != permit.intent_hash
            or precommit_inspection.normalized_action_digest != permit.normalized_action_digest
            or precommit_inspection.proposal_ref != inspection.proposal_ref
            or precommit_inspection.adapter_manifest_digest != permit.adapter_manifest_digest
            or precommit_inspection.authorization_round_id != permit.authorization_round_id
            or precommit_inspection.authorization_round_digest != permit.authorization_round_digest
            or precommit_inspection.lease_id != permit.lease_id
            or precommit_inspection.worker_id != permit.worker_id
            or precommit_inspection.fencing_token != permit.fencing_token
            or permit.precommit_plan_digest != canonical_digest(precommit_plan)
            or precommit_plan.proposal != plan.proposal
            or precommit_plan.intent_hash != plan.intent_hash
            or precommit_plan.canonical_resource != plan.canonical_resource
            or precommit_plan.base_version != plan.base_version
            or precommit_plan.risk_class is not plan.risk_class
            or precommit_plan.effect_domains != plan.effect_domains
            or precommit_plan.semantic_arguments != plan.semantic_arguments
            or ctx.target_version_guard != plan.base_version
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Commit permit does not bind the verified filesystem stage",
            )
        self._accept_intent_fence(
            permit.tenant_id,
            permit.intent_hash,
            permit.owner_version,
            permit.fencing_token,
        )

    def _admit_recovery(
        self,
        ctx: RecoveryContext,
        *,
        kind: RecoveryWorkKind,
        transaction_id: str | None = None,
        intent_hash: str | None = None,
        target_id: str | None = None,
        target_version_guard: str | None = None,
        target_normalized_action_digest: str | None = None,
        target_owner_version: int | None = None,
        target_owner_history_sequence: int | None = None,
        target_owner_history_digest: str | None = None,
    ) -> NormalizedAction | None:
        self._require_permit(ctx.permit)
        if ctx.permit is None:
            return None
        permit = ctx.permit
        validate_active_deadline(ctx.deadline)
        validate_permit_artifact(permit, cast("str", ctx.permit_ref), self._artifacts)
        if self._artifacts is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Recovery evidence is unavailable",
            )
        self._artifacts.get(permit.target_evidence_ref)
        self._artifacts.get(permit.approval_evidence_ref)
        if (
            permit.adapter_manifest_digest != self.manifest.digest
            or permit.recovery_kind is not kind
            or (transaction_id is not None and permit.transaction_id != transaction_id)
            or (intent_hash is not None and permit.intent_hash != intent_hash)
            or (target_id is not None and permit.target_id != target_id)
            or (
                target_version_guard is not None
                and permit.target_version_guard != target_version_guard
            )
            or (
                target_owner_version is not None
                and permit.target_owner_version != target_owner_version
            )
            or (
                target_owner_history_sequence is not None
                and permit.target_owner_history_sequence != target_owner_history_sequence
            )
            or (
                target_owner_history_digest is not None
                and permit.target_owner_history_digest != target_owner_history_digest
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Recovery permit does not bind this filesystem recovery operation",
            )
        _, _, target_action = validate_recovery_action_artifacts(
            permit,
            self._artifacts,
            manifest=self.manifest,
            recovery_kind=kind,
            target_transaction_id=permit.transaction_id,
            target_intent_hash=permit.intent_hash,
            target_normalized_action_digest=target_normalized_action_digest,
            target_id=permit.target_id,
            target_evidence_ref=permit.target_evidence_ref,
            target_version_guard=permit.target_version_guard,
            target_owner_version=permit.target_owner_version,
            target_owner_history_sequence=permit.target_owner_history_sequence,
            target_owner_history_digest=permit.target_owner_history_digest,
        )
        if kind is RecoveryWorkKind.DISCARD_STAGING:
            self._accept_transaction_fence(
                permit.tenant_id,
                permit.transaction_id,
                permit.fencing_token,
            )
        else:
            self._accept_intent_fence(
                permit.tenant_id,
                permit.intent_hash,
                permit.target_owner_version,
                permit.fencing_token,
            )
        return target_action

    def _admit_verification(
        self,
        subject: StagedReceipt | EffectReceipt,
        ctx: VerifyContext,
        *,
        phase: VerificationPhase,
    ) -> int | None:
        self._require_permit(ctx.permit)
        if ctx.permit is None:
            return None
        permit = ctx.permit
        validate_active_deadline(ctx.deadline)
        validate_permit_artifact(permit, cast("str", ctx.permit_ref), self._artifacts)
        validate_canonical_artifact(
            subject,
            cast("str", ctx.subject_ref),
            self._artifacts,
            label="Verification subject",
        )
        if ctx.normalized_action is None or ctx.normalized_action_ref is None:
            raise AgentKernelError(
                ErrorCode.EVIDENCE_UNAVAILABLE,
                "Enforced verification requires the normalized action artifact",
            )
        if permit.phase is VerificationPhase.STAGED:
            stage_subject_permit = load_canonical_model_artifact(
                permit.subject_permit_ref,
                StagePermit,
                self._artifacts,
                label="Subject stage permit",
            )
            if (
                permit.authority_permit_ref != permit.subject_permit_ref
                or permit.authority_permit_digest != permit.subject_permit_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Staged verification requires the stage permit as both authorities",
                )
            subject_permit: StagePermit | CommitPermit = stage_subject_permit
            authority_permit: StagePermit | CommitPermit | RecoveryPermit = stage_subject_permit
            if not isinstance(subject, StagedReceipt):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Staged verification permit cannot verify a committed receipt",
                )
            plan = subject.staged.plan
            inspection = load_canonical_model_artifact(
                stage_subject_permit.inspection_permit_ref,
                InspectionPermit,
                self._artifacts,
                label="Inspection permit",
            )
            subject_permit_matches = (
                stage_subject_permit.plan_digest == canonical_digest(plan)
                and stage_subject_permit.plan_ref == canonical_digest(plan)
                and stage_subject_permit.stage_id == subject.staged.stage_id
                and stage_subject_permit.target_version_guard == plan.base_version
            )
            owner_version: int | None = None
        else:
            commit_subject_permit = load_canonical_model_artifact(
                permit.subject_permit_ref,
                CommitPermit,
                self._artifacts,
                label="Subject commit permit",
            )
            if not isinstance(subject, EffectReceipt):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Committed verification permit cannot verify a staged receipt",
                )
            plan = load_canonical_model_artifact(
                commit_subject_permit.plan_ref,
                EffectPlan,
                self._artifacts,
                label="Effect plan",
            )
            stage_permit = load_canonical_model_artifact(
                commit_subject_permit.stage_permit_ref,
                StagePermit,
                self._artifacts,
                label="Stage permit",
            )
            inspection = load_canonical_model_artifact(
                stage_permit.inspection_permit_ref,
                InspectionPermit,
                self._artifacts,
                label="Inspection permit",
            )
            subject_permit_matches = (
                commit_subject_permit.plan_digest == canonical_digest(plan)
                and subject.transaction_id == plan.proposal.transaction_id
                and subject.intent_hash == plan.intent_hash
                and subject.adapter == self.manifest.name
                and subject.operation == plan.proposal.operation
                and subject.target_version_before == commit_subject_permit.target_version_guard
            )
            subject_permit = commit_subject_permit
            if permit.authority_permit_ref == permit.subject_permit_ref:
                authority_permit = commit_subject_permit
                owner_version = commit_subject_permit.owner_version
            else:
                recovery_authority = load_canonical_model_artifact(
                    permit.authority_permit_ref,
                    RecoveryPermit,
                    self._artifacts,
                    label="Verification recovery authority",
                )
                authority_permit = recovery_authority
                owner_version = recovery_authority.target_owner_version
                if (
                    recovery_authority.recovery_kind is not RecoveryWorkKind.RECONCILE_DISPATCH
                    or recovery_authority.transaction_id != commit_subject_permit.transaction_id
                    or recovery_authority.intent_hash != commit_subject_permit.intent_hash
                    or recovery_authority.target_id != commit_subject_permit.dispatch_id
                    or recovery_authority.target_owner_version
                    != commit_subject_permit.owner_version
                    or recovery_authority.target_owner_history_sequence
                    != commit_subject_permit.owner_history_sequence
                    or recovery_authority.target_owner_history_digest
                    != commit_subject_permit.owner_history_digest
                    or recovery_authority.target_version_guard
                    != commit_subject_permit.target_version_guard
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Recovery verification authority does not bind the subject dispatch",
                    )
        validate_normalized_action_artifact(
            ctx.normalized_action,
            ctx.normalized_action_ref,
            self._artifacts,
            permit_digest=permit.normalized_action_digest,
            proposal=plan.proposal,
            proposal_ref=inspection.proposal_ref,
            manifest=self.manifest,
        )
        if (
            permit.phase is not phase
            or permit.subject_ref != canonical_digest(subject)
            or permit.subject_permit_ref != canonical_digest(subject_permit)
            or permit.subject_permit_digest != subject_permit.permit_digest
            or permit.authority_permit_ref != canonical_digest(authority_permit)
            or permit.authority_permit_digest != authority_permit.permit_digest
            or permit.adapter_manifest_digest != self.manifest.digest
            or permit.tenant_id != authority_permit.tenant_id
            or permit.tenant_id != subject_permit.tenant_id
            or permit.transaction_id != plan.proposal.transaction_id
            or permit.intent_hash != plan.intent_hash
            or permit.normalized_action_digest != ctx.normalized_action_ref
            or permit.authorization_round_id != authority_permit.authorization_round_id
            or permit.authorization_round_digest != authority_permit.authorization_round_digest
            or permit.lease_id != authority_permit.lease_id
            or permit.worker_id != authority_permit.worker_id
            or permit.fencing_token != authority_permit.fencing_token
            or permit.issued_at < authority_permit.issued_at
            or permit.deadline > authority_permit.deadline
            or not subject_permit_matches
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Verification permit does not bind its authority, subject, and normalized action",
            )
        return owner_version

    async def inspect(self, proposal: ActionProposal, ctx: ReadOnlyContext) -> EffectPlan:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._inspect_sync(proposal, ctx), cancellation
            )
        )

    def _inspect_sync(self, proposal: ActionProposal, ctx: ReadOnlyContext) -> EffectPlan:
        if (
            proposal.adapter != self.manifest.name
            or proposal.adapter_version != self.manifest.version
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Proposal adapter identity does not match the filesystem implementation",
            )
        if proposal.operation != "write_files":
            raise UnsupportedSemantics(proposal.operation)
        raw_files = proposal.arguments.get("files")
        if not isinstance(raw_files, dict) or not all(
            isinstance(path, str) and isinstance(content, str)
            for path, content in raw_files.items()
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "write_files requires a path-to-string files object",
            )
        files_input = cast("dict[str, str]", raw_files)
        if not files_input or len(files_input) > _MAX_FILES:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "write_files file count exceeds the adapter limit",
            )
        if sum(len(content.encode("utf-8")) for content in files_input.values()) > (
            _MAX_TOTAL_CONTENT_BYTES
        ):
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "write_files content exceeds the admitted aggregate byte limit",
            )
        if any(
            unicodedata.normalize("NFC", content) != content for content in files_input.values()
        ):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Filesystem text content must use Unicode NFC",
            )
        normalized_files: dict[str, str] = {}
        portable_paths: dict[str, str] = {}
        for raw_path, content in files_input.items():
            normalized = normalize_relative_path(raw_path)
            portable = portable_path_key(normalized)
            if portable in portable_paths:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Duplicate or non-portable aliased path",
                )
            portable_paths[portable] = normalized
            normalized_files[normalized] = content
        ordered_paths = sorted(portable_paths)
        for index, path in enumerate(ordered_paths[:-1]):
            if ordered_paths[index + 1].startswith(f"{path}/"):
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "A file path cannot also be the parent of another requested file",
                )
        admitted_intent = self._admit_inspection(proposal, ctx)
        intent_hash = admitted_intent or canonical_digest(
            {
                "operation": proposal.operation,
                "canonical_resource": f"{self._normalizer_config.resource_root}/**",
                "semantic_arguments": {"files": normalized_files},
                "goal": proposal.goal_id,
                "principal": proposal.agent_id,
                "adapter_protocol_version": self.manifest.version,
            }
        )
        boundary = (
            self._transaction_effect_boundary(
                ctx.permit.tenant_id,
                ctx.permit.transaction_id,
                ctx.permit.fencing_token,
            )
            if ctx.permit is not None
            else nullcontext(None)
        )
        with boundary as connection:
            if connection is not None and ctx.permit is not None:
                self._assert_transaction_fence_locked(
                    connection,
                    ctx.permit.tenant_id,
                    ctx.permit.transaction_id,
                    ctx.permit.fencing_token,
                )
            if ctx.permit is not None:
                base = self._snapshot_workspace(deadline=ctx.deadline)
            else:
                for normalized in normalized_files:
                    resolve_scoped_path(self._workspace, normalized)
                base = snapshot_tree(self._workspace)
                _validate_snapshot_limits(base)
        return EffectPlan(
            plan_id=new_id("plan"),
            proposal=proposal,
            canonical_resource=f"{self._normalizer_config.resource_root}/**",
            base_version=base.digest,
            intent_hash=intent_hash,
            risk_class=RiskClass.REVERSIBLE,
            effect_domains=("filesystem",),
            semantic_arguments={"files": cast("dict[str, JsonValue]", normalized_files)},
        )

    async def stage(self, plan: EffectPlan, ctx: StageContext) -> StagedEffect:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(lambda: self._stage_sync(plan, ctx), cancellation)
        )

    def _stage_sync(self, plan: EffectPlan, ctx: StageContext) -> StagedEffect:
        permit = self._admit_stage(plan, ctx)
        if permit is None:
            return self._stage_impl(plan, ctx, permit, None)
        with self._transaction_effect_boundary(
            permit.tenant_id,
            permit.transaction_id,
            permit.fencing_token,
        ) as connection:
            return self._stage_impl(plan, ctx, permit, connection)

    def _stage_impl(
        self,
        plan: EffectPlan,
        ctx: StageContext,
        permit: StagePermit | None,
        connection: sqlite3.Connection | None,
    ) -> StagedEffect:
        if permit is not None:
            validate_active_deadline(ctx.deadline)
        if connection is not None and permit is not None:
            self._assert_transaction_fence_locked(
                connection,
                permit.tenant_id,
                permit.transaction_id,
                permit.fencing_token,
            )
        stage_id = permit.stage_id if permit is not None else new_id("stage")
        existing = self._load_stage_manifest(stage_id)
        if existing is not None:
            if (
                existing.plan != plan
                or existing.stage_permit != permit
                or existing.stage_permit_ref
                != (canonical_digest(permit) if permit is not None else None)
            ):
                raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Stage ID was reused")
            if existing.status == "PREPARING":
                raise AgentKernelError(
                    ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                    "Interrupted stage must be explicitly discarded",
                    reconcilable=True,
                )
            return StagedEffect(
                stage_id=stage_id,
                plan=plan,
                base_state_digest=existing.base_state_digest,
                private_state={"stage_token": self._stage_key(stage_id)},
            )
        stage_parent = _ensure_private_directory(
            self._stage_parent(stage_id),
            parent=self._stages_root,
        )
        preparing = _StageManifest(
            status="PREPARING",
            stage_id=stage_id,
            plan=plan,
            plan_digest=canonical_digest(plan),
            stage_permit=permit,
            stage_permit_ref=canonical_digest(permit) if permit is not None else None,
            base_state_digest=plan.base_version,
        )
        self._persist_stage_manifest(preparing)
        self._fault_point("stage.after_manifest")
        if permit is not None:
            with (
                self._workspace_handle() as workspace_fd,
                self._stage_parent_handle(stage_id) as stage_parent_fd,
            ):
                current = _snapshot_tree_fd(workspace_fd, deadline=ctx.deadline)
                if current.digest != plan.base_version:
                    _remove_private_tree(stage_parent)
                    raise AgentKernelError(
                        ErrorCode.STALE_STATE,
                        "Authoritative workspace changed",
                    )
                os.mkdir("workspace", 0o700, dir_fd=stage_parent_fd)
                _fsync_fd(stage_parent_fd)
                stage_fd = _open_child_directory(
                    stage_parent_fd,
                    "workspace",
                    root_device=os.fstat(stage_parent_fd).st_dev,
                )
                try:
                    copied = _copy_tree_at(
                        workspace_fd,
                        stage_fd,
                        deadline=ctx.deadline,
                    )
                finally:
                    os.close(stage_fd)
        else:
            current = snapshot_tree(self._workspace)
            _validate_snapshot_limits(current)
            if current.digest != plan.base_version:
                _remove_private_tree(stage_parent)
                raise AgentKernelError(ErrorCode.STALE_STATE, "Authoritative workspace changed")
            stage_path = stage_parent / "workspace"
            copied = _copy_scoped_tree(self._workspace, stage_path, deadline=None)
        _validate_snapshot_limits(copied)
        if copied.digest != plan.base_version:
            _remove_private_tree(stage_parent)
            raise AgentKernelError(ErrorCode.STALE_STATE, "Stage base differs from inspected base")
        self._persist_stage_manifest(preparing.model_copy(update={"status": "READY"}))
        return StagedEffect(
            stage_id=stage_id,
            plan=plan,
            base_state_digest=plan.base_version,
            private_state={"stage_token": self._stage_key(stage_id)},
        )

    async def execute(self, staged: StagedEffect, ctx: StageContext) -> StagedReceipt:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._execute_sync(staged, ctx), cancellation
            )
        )

    def _execute_sync(self, staged: StagedEffect, ctx: StageContext) -> StagedReceipt:
        permit = self._admit_stage(staged.plan, ctx)
        if permit is None:
            return self._execute_impl(staged, ctx, permit, None)
        with self._transaction_effect_boundary(
            permit.tenant_id,
            permit.transaction_id,
            permit.fencing_token,
        ) as connection:
            return self._execute_impl(staged, ctx, permit, connection)

    def _execute_impl(
        self,
        staged: StagedEffect,
        ctx: StageContext,
        permit: StagePermit | None,
        connection: sqlite3.Connection | None,
    ) -> StagedReceipt:
        if permit is not None:
            validate_active_deadline(ctx.deadline)
        if permit is not None and staged.stage_id != permit.stage_id:
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Stage ID differs from its permit")
        manifest = self._load_stage_manifest(staged.stage_id)
        if manifest is None or manifest.plan != staged.plan or manifest.stage_permit != permit:
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Unknown or changed filesystem stage")
        if manifest.status == "EXECUTED":
            if manifest.staged_receipt is None:
                raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Executed stage lacks a receipt")
            return manifest.staged_receipt
        if manifest.status != "READY":
            raise AgentKernelError(
                ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                "Interrupted stage must be discarded before retry",
                reconcilable=True,
            )
        stage_parent = _validate_private_directory(
            self._stage_parent(staged.stage_id),
            parent=self._stages_root,
        )
        stage_path = _ensure_private_directory(stage_parent / "workspace", parent=stage_parent)
        files = cast("dict[str, str]", staged.plan.semantic_arguments["files"])
        if permit is not None:
            with self._stage_workspace_handle(staged.stage_id) as stage_fd:
                if (
                    _snapshot_tree_fd(stage_fd, deadline=ctx.deadline).digest
                    != staged.base_state_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Stage base changed before execution",
                    )
                for relative, content in files.items():
                    validate_active_deadline(ctx.deadline)
                    if connection is not None:
                        self._assert_transaction_fence_locked(
                            connection,
                            permit.tenant_id,
                            permit.transaction_id,
                            permit.fencing_token,
                        )
                    _atomic_write_content_at(
                        stage_fd,
                        relative,
                        content.encode("utf-8"),
                        mode=0o644,
                        deadline=ctx.deadline,
                    )
                snapshot = _snapshot_tree_fd(stage_fd, deadline=ctx.deadline)
        else:
            if snapshot_tree(stage_path).digest != staged.base_state_digest:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Stage base changed before execution",
                )
            for relative, content in files.items():
                target = resolve_scoped_path(stage_path, relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                _atomic_write_bytes(target, content.encode("utf-8"), mode=0o644)
            snapshot = snapshot_tree(stage_path)
        _validate_snapshot_limits(snapshot)
        receipt = StagedReceipt(
            receipt_id=new_id("staged"),
            staged=staged,
            staged_state_digest=snapshot.digest,
            private_state={"stage_token": self._stage_key(staged.stage_id)},
        )
        self._persist_stage_manifest(
            manifest.model_copy(update={"status": "EXECUTED", "staged_receipt": receipt})
        )
        return receipt

    async def verify_staged(self, receipt: StagedReceipt, ctx: VerifyContext) -> VerificationReport:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._verify_staged_sync(receipt, ctx), cancellation
            )
        )

    def _verify_staged_sync(
        self,
        receipt: StagedReceipt,
        ctx: VerifyContext,
    ) -> VerificationReport:
        owner_version = self._admit_verification(
            receipt,
            ctx,
            phase=VerificationPhase.STAGED,
        )
        if ctx.permit is None:
            return self._verify_staged_impl(receipt, ctx)
        if owner_version is not None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Staged verification unexpectedly resolved an intent-owner fence",
            )
        with self._transaction_effect_boundary(
            ctx.permit.tenant_id,
            ctx.permit.transaction_id,
            ctx.permit.fencing_token,
        ) as connection:
            self._assert_transaction_fence_locked(
                connection,
                ctx.permit.tenant_id,
                ctx.permit.transaction_id,
                ctx.permit.fencing_token,
            )
            return self._verify_staged_impl(receipt, ctx)

    def _verify_staged_impl(
        self,
        receipt: StagedReceipt,
        ctx: VerifyContext,
    ) -> VerificationReport:
        manifest = self._load_stage_manifest(receipt.staged.stage_id)
        if manifest is None or manifest.staged_receipt != receipt:
            evidence_refs = (
                self._record_observation(
                    evidence_kind="staged_verification",
                    tenant_id=ctx.permit.tenant_id,
                    transaction_id=receipt.staged.plan.proposal.transaction_id,
                    intent_hash=receipt.staged.plan.intent_hash,
                    normalized_action_digest=ctx.permit.normalized_action_digest,
                    subject_ref=cast("str", ctx.subject_ref),
                    operation_permit_ref=cast("str", ctx.permit_ref),
                    authority_permit_ref=ctx.permit.authority_permit_ref,
                    subject_authority_ref=ctx.permit.subject_permit_ref,
                    operation_status=VerificationStatus.UNKNOWN.value,
                    observed_state_digest=canonical_digest(
                        {"stage": receipt.staged.stage_id, "observation": "unavailable"}
                    ),
                    durable_state_digest=canonical_digest(
                        {"stage": receipt.staged.stage_id, "manifest": "missing"}
                    ),
                )
                if ctx.permit is not None
                else ()
            )
            return VerificationReport(
                status=VerificationStatus.UNKNOWN,
                verifier="adapter.filesystem.staged",
                summary="Staging tree or durable receipt is unavailable",
                evidence_refs=evidence_refs,
            )
        if ctx.permit is not None:
            with self._stage_workspace_handle(receipt.staged.stage_id) as stage_fd:
                actual = _snapshot_tree_fd(stage_fd, deadline=ctx.deadline)
        else:
            stage_parent = _validate_private_directory(
                self._stage_parent(receipt.staged.stage_id),
                parent=self._stages_root,
            )
            stage_path = _ensure_private_directory(
                stage_parent / "workspace",
                parent=stage_parent,
            )
            actual = snapshot_tree(stage_path)
        status = (
            VerificationStatus.PASS
            if actual.digest == receipt.staged_state_digest
            else VerificationStatus.FAIL
        )
        self._fault_point("verify_staged.before_observation")
        evidence_refs = (
            self._record_observation(
                evidence_kind="staged_verification",
                tenant_id=ctx.permit.tenant_id,
                transaction_id=receipt.staged.plan.proposal.transaction_id,
                intent_hash=receipt.staged.plan.intent_hash,
                normalized_action_digest=ctx.permit.normalized_action_digest,
                subject_ref=cast("str", ctx.subject_ref),
                operation_permit_ref=cast("str", ctx.permit_ref),
                authority_permit_ref=ctx.permit.authority_permit_ref,
                subject_authority_ref=ctx.permit.subject_permit_ref,
                operation_status=status.value,
                observed_state_digest=actual.digest,
                durable_state_digest=canonical_digest(manifest),
            )
            if ctx.permit is not None
            else ()
        )
        return VerificationReport(
            status=status,
            verifier="adapter.filesystem.staged",
            summary="Staged workspace digest matches the durable receipt",
            evidence_refs=evidence_refs,
        )

    def _prepare_backup(
        self,
        receipt_id: str,
        diff: TreeDiff,
        *,
        workspace_fd: int | None = None,
        deadline: datetime | None = None,
    ) -> Path:
        recovery_directory = _ensure_private_directory(
            self._recovery_root / receipt_id,
            parent=self._recovery_root,
        )
        backup = _ensure_private_directory(
            recovery_directory / "backup",
            parent=recovery_directory,
        )
        if workspace_fd is not None:
            with self._backup_handle(receipt_id) as backup_fd:
                for change in diff.changes:
                    if change.before is None or change.before.kind is not EntryKind.FILE:
                        continue
                    if _entry_at_fd(workspace_fd, change.path, deadline=deadline) != change.before:
                        raise AgentKernelError(
                            ErrorCode.STALE_STATE,
                            "Recovery source changed before its no-follow backup",
                        )
                    _atomic_copy_file_at(
                        workspace_fd,
                        backup_fd,
                        change.path,
                        mode=change.before.mode,
                        create_destination_parents=True,
                        deadline=deadline,
                    )
                    if _entry_at_fd(backup_fd, change.path, deadline=deadline) != change.before:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Recovery backup failed its content binding",
                        )
            return backup
        for change in diff.changes:
            if change.before is None or change.before.kind is not EntryKind.FILE:
                continue
            source = resolve_scoped_path(self._workspace, change.path)
            target = resolve_scoped_path(backup, change.path)
            target.parent.mkdir(parents=True, exist_ok=True)
            _atomic_copy_file(source, target, mode=change.before.mode)
            if _entry_at(backup, change.path) != change.before:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Recovery backup failed its content binding",
                )
        return backup

    def _apply_change_at(
        self,
        change: FileChange,
        workspace_fd: int,
        stage_fd: int,
        *,
        deadline: datetime,
    ) -> None:
        if _entry_at_fd(workspace_fd, change.path, deadline=deadline) != change.before:
            raise AgentKernelError(
                ErrorCode.STALE_STATE,
                "Per-file commit guard no longer matches the inspected state",
            )
        self._fault_point(f"commit.before_handle_effect:{change.path}")
        parent_fd, leaf = _open_parent_directory(workspace_fd, change.path)
        try:
            if change.after is None:
                if change.before is not None and change.before.kind is EntryKind.DIRECTORY:
                    os.rmdir(leaf, dir_fd=parent_fd)
                else:
                    os.unlink(leaf, dir_fd=parent_fd)
                _fsync_fd(parent_fd)
            elif change.after.kind is EntryKind.DIRECTORY:
                if change.before is None:
                    os.mkdir(leaf, change.after.mode, dir_fd=parent_fd)
                    _fsync_fd(parent_fd)
                child_fd = _open_child_directory(
                    parent_fd,
                    leaf,
                    root_device=os.fstat(workspace_fd).st_dev,
                )
                try:
                    _fchmod(child_fd, change.after.mode)
                    _fsync_fd(child_fd)
                finally:
                    os.close(child_fd)
            else:
                _atomic_copy_file_at(
                    stage_fd,
                    workspace_fd,
                    change.path,
                    mode=change.after.mode,
                    deadline=deadline,
                )
        except OSError as error:
            raise AgentKernelError(
                ErrorCode.STALE_STATE,
                "Handle-relative filesystem effect failed",
            ) from error
        finally:
            os.close(parent_fd)
        if _entry_at_fd(workspace_fd, change.path, deadline=deadline) != change.after:
            raise AgentKernelError(
                ErrorCode.VERIFICATION_FAILED,
                "Per-file commit postcondition failed",
            )

    def _apply_change(self, change: FileChange, stage_path: Path) -> None:
        if _entry_at(self._workspace, change.path) != change.before:
            raise AgentKernelError(
                ErrorCode.STALE_STATE,
                "Per-file commit guard no longer matches the inspected state",
            )
        target = resolve_scoped_path(self._workspace, change.path)
        if change.after is None:
            if change.before is not None and change.before.kind is EntryKind.DIRECTORY:
                target.rmdir()
            else:
                target.unlink()
            _fsync_directory(target.parent)
        elif change.after.kind is EntryKind.DIRECTORY:
            if change.before is None:
                target.mkdir()
            target.chmod(change.after.mode)
            _fsync_directory(target.parent)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            source = resolve_scoped_path(stage_path, change.path)
            _atomic_copy_file(source, target, mode=change.after.mode)
        if _entry_at(self._workspace, change.path) != change.after:
            raise AgentKernelError(
                ErrorCode.VERIFICATION_FAILED,
                "Per-file commit postcondition failed",
            )

    def _validate_backup(self, manifest: _RecoveryManifest) -> bool:
        try:
            _, diff = _verified_recovery_evidence(manifest)
            backup = self._backup_path(manifest.effect_receipt.receipt_id)
            backup_snapshot = snapshot_tree(backup)
            if manifest.backup_evidence_format == "FULL_TREE_V1":
                return backup_snapshot == manifest.base_snapshot
            expected_files = {
                change.path
                for change in diff.changes
                if change.before is not None and change.before.kind is EntryKind.FILE
            }
            allowed_directories: set[str] = set()
            for path in expected_files:
                parent = Path(path).parent
                while parent.as_posix() != ".":
                    allowed_directories.add(parent.as_posix())
                    parent = parent.parent
            if any(
                (entry.kind is EntryKind.FILE and entry.path not in expected_files)
                or (entry.kind is EntryKind.DIRECTORY and entry.path not in allowed_directories)
                for entry in backup_snapshot.entries
            ):
                return False
            for change in diff.changes:
                if change.before is None or change.before.kind is not EntryKind.FILE:
                    continue
                if _entry_at(backup, change.path) != change.before:
                    return False
        except AgentKernelError:
            return False
        return True

    @staticmethod
    def _snapshot_is_guarded(
        manifest: _RecoveryManifest,
        current: FilesystemSnapshot,
    ) -> bool:
        try:
            target_snapshot, diff = _verified_recovery_evidence(manifest)
        except AgentKernelError:
            return False
        base = {entry.path: entry for entry in manifest.base_snapshot.entries}
        target = {entry.path: entry for entry in target_snapshot.entries}
        actual = {entry.path: entry for entry in current.entries}
        changed = {change.path for change in diff.changes}
        for path in base.keys() | target.keys() | actual.keys():
            observed = actual.get(path)
            if path in changed:
                if observed not in {base.get(path), target.get(path)}:
                    return False
            elif observed != base.get(path) or base.get(path) != target.get(path):
                return False
        return True

    def _validate_backup_fd(
        self,
        manifest: _RecoveryManifest,
        backup_fd: int,
        *,
        deadline: datetime,
    ) -> bool:
        try:
            _, diff = _verified_recovery_evidence(manifest)
            backup_snapshot = _snapshot_tree_fd(backup_fd, deadline=deadline)
            if manifest.backup_evidence_format == "FULL_TREE_V1":
                return backup_snapshot == manifest.base_snapshot
            expected_files = {
                change.path
                for change in diff.changes
                if change.before is not None and change.before.kind is EntryKind.FILE
            }
            allowed_directories: set[str] = set()
            for path in expected_files:
                parent = PurePosixPath(path).parent
                while parent.as_posix() != ".":
                    allowed_directories.add(parent.as_posix())
                    parent = parent.parent
            if any(
                (entry.kind is EntryKind.FILE and entry.path not in expected_files)
                or (entry.kind is EntryKind.DIRECTORY and entry.path not in allowed_directories)
                for entry in backup_snapshot.entries
            ):
                return False
            return all(
                change.before is None
                or change.before.kind is not EntryKind.FILE
                or _entry_at_fd(backup_fd, change.path, deadline=deadline) == change.before
                for change in diff.changes
            )
        except AgentKernelError:
            return False

    def _current_is_guarded(self, manifest: _RecoveryManifest) -> bool:
        try:
            current = snapshot_tree(self._workspace)
        except AgentKernelError:
            return False
        return self._snapshot_is_guarded(manifest, current)

    def _restore_change_at(
        self,
        change: FileChange,
        workspace_fd: int,
        backup_fd: int,
        *,
        deadline: datetime,
    ) -> None:
        current = _entry_at_fd(workspace_fd, change.path, deadline=deadline)
        if current == change.before:
            return
        if current != change.after:
            raise AgentKernelError(
                ErrorCode.ROLLBACK_FAILED,
                "Per-file rollback guard detected later or unknown work",
                review_required=True,
            )
        self._fault_point(f"rollback.before_handle_effect:{change.path}")
        parent_fd, leaf = _open_parent_directory(workspace_fd, change.path)
        try:
            if change.before is None:
                if change.after is not None and change.after.kind is EntryKind.DIRECTORY:
                    os.rmdir(leaf, dir_fd=parent_fd)
                else:
                    os.unlink(leaf, dir_fd=parent_fd)
                _fsync_fd(parent_fd)
            elif change.before.kind is EntryKind.DIRECTORY:
                if change.after is None:
                    os.mkdir(leaf, change.before.mode, dir_fd=parent_fd)
                    _fsync_fd(parent_fd)
                child_fd = _open_child_directory(
                    parent_fd,
                    leaf,
                    root_device=os.fstat(workspace_fd).st_dev,
                )
                try:
                    _fchmod(child_fd, change.before.mode)
                    _fsync_fd(child_fd)
                finally:
                    os.close(child_fd)
            else:
                _atomic_copy_file_at(
                    backup_fd,
                    workspace_fd,
                    change.path,
                    mode=change.before.mode,
                    create_destination_parents=True,
                    deadline=deadline,
                )
        except OSError as error:
            raise AgentKernelError(
                ErrorCode.ROLLBACK_FAILED,
                "Handle-relative rollback effect failed",
                review_required=True,
            ) from error
        finally:
            os.close(parent_fd)
        if _entry_at_fd(workspace_fd, change.path, deadline=deadline) != change.before:
            raise AgentKernelError(
                ErrorCode.ROLLBACK_FAILED,
                "Per-file rollback postcondition failed",
                review_required=True,
            )

    def _restore_change(self, change: FileChange, backup: Path) -> None:
        current = _entry_at(self._workspace, change.path)
        if current == change.before:
            return
        if current != change.after:
            raise AgentKernelError(
                ErrorCode.ROLLBACK_FAILED,
                "Per-file rollback guard detected later or unknown work",
                review_required=True,
            )
        target = resolve_scoped_path(self._workspace, change.path)
        if change.before is None:
            if change.after is not None and change.after.kind is EntryKind.DIRECTORY:
                target.rmdir()
            else:
                target.unlink()
            _fsync_directory(target.parent)
        elif change.before.kind is EntryKind.DIRECTORY:
            if change.after is None:
                target.mkdir()
            target.chmod(change.before.mode)
            _fsync_directory(target.parent)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            source = resolve_scoped_path(backup, change.path)
            _atomic_copy_file(source, target, mode=change.before.mode)
        if _entry_at(self._workspace, change.path) != change.before:
            raise AgentKernelError(
                ErrorCode.ROLLBACK_FAILED,
                "Per-file rollback postcondition failed",
                review_required=True,
            )

    def _rollback_manifest(
        self,
        manifest: _RecoveryManifest,
        *,
        deadline: datetime,
        enforce_deadline: bool,
    ) -> RecoveryReport:
        try:
            _, diff = _verified_recovery_evidence(manifest)
        except AgentKernelError:
            return RecoveryReport(
                status=VerificationStatus.ERROR,
                strategy="guarded_per_file_restore",
                restored_state_digest=snapshot_tree(self._workspace).digest,
                residual_effects=("historical_target_evidence_unavailable",),
            )
        if not self._validate_backup(manifest):
            return RecoveryReport(
                status=VerificationStatus.ERROR,
                strategy="guarded_per_file_restore",
                restored_state_digest=snapshot_tree(self._workspace).digest,
                residual_effects=("backup_integrity_mismatch",),
            )
        if not self._current_is_guarded(manifest):
            return RecoveryReport(
                status=VerificationStatus.UNKNOWN,
                strategy="guarded_per_file_restore",
                restored_state_digest=snapshot_tree(self._workspace).digest,
                residual_effects=("target_version_changed_after_commit",),
            )
        backup = self._backup_path(manifest.effect_receipt.receipt_id)
        current_manifest = manifest
        for change in reversed(_forward_changes(diff)):
            if enforce_deadline:
                try:
                    validate_active_deadline(deadline)
                except AgentKernelError as error:
                    with suppress(AgentKernelError):
                        self._persist_recovery_manifest(
                            current_manifest.model_copy(update={"status": "PARTIAL_OR_UNKNOWN"})
                        )
                    raise AgentKernelError(
                        ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                        "Recovery deadline expired at a per-file boundary",
                        reconcilable=True,
                        review_required=True,
                    ) from error
            self._restore_change(change, backup)
            restored = tuple(dict.fromkeys((*current_manifest.restored_paths, change.path)))
            current_manifest = current_manifest.model_copy(update={"restored_paths": restored})
            self._persist_recovery_manifest(current_manifest)
            self._fault_point(f"rollback.after_change:{change.path}")
        actual = snapshot_tree(self._workspace)
        if actual.digest != manifest.base_snapshot.digest:
            return RecoveryReport(
                status=VerificationStatus.FAIL,
                strategy="guarded_per_file_restore",
                restored_state_digest=actual.digest,
                residual_effects=("restored_snapshot_mismatch",),
            )
        current_manifest = current_manifest.model_copy(update={"status": "ROLLED_BACK"})
        self._persist_recovery_manifest(current_manifest)
        return RecoveryReport(
            status=VerificationStatus.PASS,
            strategy="guarded_per_file_restore",
            restored_state_digest=actual.digest,
        )

    def _rollback_manifest_with_handles(
        self,
        manifest: _RecoveryManifest,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        permit = ctx.permit
        if permit is None:
            raise AgentKernelError(ErrorCode.AUTHORITY_MISSING, "Recovery permit is required")
        receipt = manifest.effect_receipt
        with self._intent_effect_boundary(
            manifest.tenant_id,
            receipt.intent_hash,
            manifest.owner_version,
            permit.fencing_token,
        ) as connection:
            authoritative = self._load_recovery_manifest_by_receipt(
                manifest.tenant_id,
                receipt.receipt_id,
                connection=connection,
            )
            if authoritative is None or authoritative.effect_receipt != receipt:
                raise AgentKernelError(
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    "Rollback recovery manifest is unavailable",
                )
            manifest = authoritative
            reservation = self._dispatch_for_generation(
                manifest.tenant_id,
                manifest.effect_receipt.intent_hash,
                manifest.owner_version,
                connection=connection,
            )
            if (
                reservation is None
                or reservation.dispatch_id != manifest.dispatch_id
                or reservation.receipt != manifest.effect_receipt
                or reservation.owner_history_sequence != manifest.owner_history_sequence
                or reservation.owner_history_digest != manifest.owner_history_digest
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Rollback manifest differs from its durable dispatch generation",
                )
            with (
                self._workspace_handle() as workspace_fd,
                self._backup_handle(receipt.receipt_id) as backup_fd,
            ):
                current = _snapshot_tree_fd(workspace_fd, deadline=ctx.deadline)
                if reservation.status in {"ROLLED_BACK", "NO_EFFECT"}:
                    return RecoveryReport(
                        status=(
                            VerificationStatus.PASS
                            if current.digest == manifest.base_snapshot.digest
                            else VerificationStatus.UNKNOWN
                        ),
                        strategy="guarded_per_file_restore",
                        restored_state_digest=current.digest,
                        residual_effects=(
                            ()
                            if current.digest == manifest.base_snapshot.digest
                            else ("target_changed_after_rollback",)
                        ),
                    )
                _, diff = _verified_recovery_evidence(manifest)
                if not self._validate_backup_fd(
                    manifest,
                    backup_fd,
                    deadline=ctx.deadline,
                ):
                    return RecoveryReport(
                        status=VerificationStatus.ERROR,
                        strategy="guarded_per_file_restore",
                        restored_state_digest=current.digest,
                        residual_effects=("backup_integrity_mismatch",),
                    )
                if not self._snapshot_is_guarded(manifest, current):
                    return RecoveryReport(
                        status=VerificationStatus.UNKNOWN,
                        strategy="guarded_per_file_restore",
                        restored_state_digest=current.digest,
                        residual_effects=("target_version_changed_after_commit",),
                    )
                current_manifest = manifest
                try:
                    for change in reversed(_forward_changes(diff)):
                        validate_active_deadline(ctx.deadline)
                        self._assert_intent_fence_locked(
                            connection,
                            manifest.tenant_id,
                            manifest.effect_receipt.intent_hash,
                            manifest.owner_version,
                            permit.fencing_token,
                        )
                        self._restore_change_at(
                            change,
                            workspace_fd,
                            backup_fd,
                            deadline=ctx.deadline,
                        )
                        restored = tuple(
                            dict.fromkeys((*current_manifest.restored_paths, change.path))
                        )
                        current_manifest = current_manifest.model_copy(
                            update={"restored_paths": restored}
                        )
                        self._persist_recovery_manifest(current_manifest)
                        self._fault_point(f"rollback.after_change:{change.path}")
                except AgentKernelError:
                    with suppress(AgentKernelError):
                        self._persist_recovery_manifest(
                            current_manifest.model_copy(update={"status": "PARTIAL_OR_UNKNOWN"})
                        )
                    raise
                actual = _snapshot_tree_fd(workspace_fd, deadline=ctx.deadline)
                if actual.digest != manifest.base_snapshot.digest:
                    return RecoveryReport(
                        status=VerificationStatus.FAIL,
                        strategy="guarded_per_file_restore",
                        restored_state_digest=actual.digest,
                        residual_effects=("restored_snapshot_mismatch",),
                    )
                rolled_back = current_manifest.model_copy(update={"status": "ROLLED_BACK"})
                self._persist_recovery_manifest(rolled_back)
                self._update_dispatch_status_locked(connection, reservation, "ROLLED_BACK")
                return RecoveryReport(
                    status=VerificationStatus.PASS,
                    strategy="guarded_per_file_restore",
                    restored_state_digest=actual.digest,
                )

    def _commit_with_handles(
        self,
        receipt: StagedReceipt,
        ctx: CommitContext,
        cancellation: BlockingCancellation,
    ) -> EffectReceipt:
        """Enforced commit using pinned roots and no-follow handle-relative mutations."""

        with (
            self._workspace_handle() as workspace_fd,
            self._stage_workspace_handle(receipt.staged.stage_id) as stage_fd,
        ):
            current = _snapshot_tree_fd(workspace_fd, deadline=ctx.deadline)
            if current.digest != receipt.staged.plan.base_version:
                raise AgentKernelError(ErrorCode.STALE_STATE, "Authoritative workspace changed")
            staged = _snapshot_tree_fd(stage_fd, deadline=ctx.deadline)
            if staged.digest != receipt.staged_state_digest:
                raise AgentKernelError(
                    ErrorCode.VERIFICATION_FAILED,
                    "Staging tree changed after verification",
                )
            diff = diff_snapshots(current, staged)
            self._fault_point("commit.before_dispatch")
            if ctx.permit is not None:
                validate_active_deadline(ctx.deadline)
            cancellation.raise_if_requested()
            reservation, created = self._reserve_dispatch(
                receipt=receipt,
                ctx=ctx,
                base_snapshot=current,
                target_snapshot=staged,
                diff=diff,
            )
            if not created:
                if (
                    reservation.status == "COMMITTED"
                    and _snapshot_tree_fd(workspace_fd, deadline=ctx.deadline).digest
                    == reservation.receipt.target_version_after
                ):
                    return reservation.receipt
                raise AgentKernelError(
                    ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                    "A durable filesystem dispatch cannot be resent and must be reconciled",
                    reconcilable=True,
                    review_required=True,
                )
            self._prepare_backup(
                reservation.receipt.receipt_id,
                diff,
                workspace_fd=workspace_fd,
                deadline=ctx.deadline,
            )
            self._fault_point("commit.after_backup_before_manifest")
            manifest = _RecoveryManifest(
                tenant_id=reservation.tenant_id,
                status="PREPARED",
                dispatch_id=reservation.dispatch_id,
                owner_version=reservation.owner_version,
                owner_history_sequence=reservation.owner_history_sequence,
                owner_history_digest=reservation.owner_history_digest,
                permit_digest=reservation.permit_digest,
                normalized_action_digest=reservation.normalized_action_digest,
                effect_receipt=reservation.receipt,
                stage_id=receipt.staged.stage_id,
                staged_state_digest=receipt.staged_state_digest,
                base_snapshot=current,
                target_snapshot=staged,
                diff=diff,
            )
            self._persist_recovery_manifest(manifest)
            self._fault_point("commit.after_manifest_before_prepared")
            current_manifest = manifest
            active_reservation = self._transition_dispatch_durable(
                reservation,
                "PREPARED",
            )
            self._fault_point("commit.after_prepared")
            changes = _forward_changes(diff)
            if changes:
                active_reservation = self._transition_dispatch_durable(
                    active_reservation,
                    "EFFECT_STARTED",
                )
                current_manifest = current_manifest.model_copy(update={"status": "EFFECT_STARTED"})
                self._persist_recovery_manifest(current_manifest)
                self._fault_point("commit.after_effect_started")
            try:
                with self._intent_effect_boundary(
                    reservation.tenant_id,
                    receipt.staged.plan.intent_hash,
                    reservation.owner_version,
                    ctx.fencing_token,
                ) as connection:
                    row = connection.execute(
                        self._dispatch_select_sql()
                        + " WHERE tenant_id = ? AND intent_hash = ? AND owner_version = ?",
                        (
                            reservation.tenant_id,
                            reservation.intent_hash,
                            reservation.owner_version,
                        ),
                    ).fetchone()
                    if (
                        row is None
                        or self._load_dispatch_row(row).row_digest != active_reservation.row_digest
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Dispatch reservation changed before the effect boundary",
                        )
                    if (
                        _snapshot_tree_fd(workspace_fd, deadline=ctx.deadline).digest
                        != current.digest
                        or _snapshot_tree_fd(stage_fd, deadline=ctx.deadline).digest
                        != staged.digest
                    ):
                        raise AgentKernelError(
                            ErrorCode.STALE_STATE,
                            "Filesystem changed before the serialized effect boundary",
                        )
                    for change in changes:
                        validate_active_deadline(ctx.deadline)
                        self._assert_intent_fence_locked(
                            connection,
                            reservation.tenant_id,
                            reservation.intent_hash,
                            reservation.owner_version,
                            ctx.fencing_token,
                        )
                        self._apply_change_at(
                            change,
                            workspace_fd,
                            stage_fd,
                            deadline=ctx.deadline,
                        )
                        applied = tuple(
                            dict.fromkeys((*current_manifest.applied_paths, change.path))
                        )
                        current_manifest = current_manifest.model_copy(
                            update={"applied_paths": applied}
                        )
                        self._persist_recovery_manifest(current_manifest)
                        self._fault_point(f"commit.after_change:{change.path}")
                    final = _snapshot_tree_fd(workspace_fd, deadline=ctx.deadline)
                    if final.digest != staged.digest:
                        raise AgentKernelError(
                            ErrorCode.VERIFICATION_FAILED,
                            "Committed workspace does not match the staged workspace",
                        )
                    self._fault_point("commit.after_effect")
                    committed = current_manifest.model_copy(update={"status": "COMMITTED"})
                    self._persist_recovery_manifest(committed)
                    self._update_dispatch_status_locked(
                        connection,
                        active_reservation,
                        "COMMITTED",
                    )
            except Exception as error:
                with suppress(AgentKernelError):
                    self._persist_recovery_manifest(
                        current_manifest.model_copy(update={"status": "PARTIAL_OR_UNKNOWN"})
                    )
                with suppress(AgentKernelError):
                    self._transition_dispatch_durable(
                        active_reservation,
                        "PARTIAL_OR_UNKNOWN",
                    )
                raise AgentKernelError(
                    ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                    "Filesystem commit failed after durable dispatch; authorized recovery required",
                    reconcilable=True,
                    review_required=True,
                ) from error
            self._fault_point("commit.after_committed")
        try:
            self._remove_stage_tree(receipt.staged.stage_id)
        except AgentKernelError as error:
            raise AgentKernelError(
                ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                "Effect committed but verified staging cleanup failed",
                reconcilable=True,
                review_required=True,
            ) from error
        return reservation.receipt

    async def commit(self, receipt: StagedReceipt, ctx: CommitContext) -> EffectReceipt:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._commit_sync(receipt, ctx, cancellation), cancellation
            )
        )

    def _commit_sync(
        self,
        receipt: StagedReceipt,
        ctx: CommitContext,
        cancellation: BlockingCancellation,
    ) -> EffectReceipt:
        self._admit_commit(receipt, ctx)
        if ctx.target_version_guard != receipt.staged.plan.base_version:
            raise AgentKernelError(ErrorCode.STALE_STATE, "Commit guard differs from staged base")
        tenant_id = ctx.permit.tenant_id if ctx.permit is not None else _EMBEDDED_TENANT_ID
        owner_version = ctx.permit.owner_version if ctx.permit is not None else 0
        existing = self._dispatch_for_generation(
            tenant_id,
            receipt.staged.plan.intent_hash,
            owner_version,
        )
        if existing is not None:
            expected_dispatch_id = (
                ctx.permit.dispatch_id
                if ctx.permit is not None
                else f"dispatch_{receipt.staged.plan.intent_hash.removeprefix('sha256:')}"
            )
            expected_permit_digest = (
                ctx.permit.permit_digest
                if ctx.permit is not None
                else canonical_digest(
                    {
                        "tenant_id": tenant_id,
                        "intent_hash": receipt.staged.plan.intent_hash,
                        "fencing_token": ctx.fencing_token,
                        "target_version_guard": ctx.target_version_guard,
                    }
                )
            )
            expected_normalized_action_digest = (
                ctx.permit.normalized_action_digest
                if ctx.permit is not None
                else receipt.staged.plan.intent_hash
            )
            if (
                existing.dispatch_id != expected_dispatch_id
                or existing.transaction_id != receipt.staged.plan.proposal.transaction_id
                or existing.stage_id != receipt.staged.stage_id
                or existing.staged_state_digest != receipt.staged_state_digest
                or existing.permit_digest != expected_permit_digest
                or existing.normalized_action_digest != expected_normalized_action_digest
                or existing.receipt.target_version_before != receipt.staged.plan.base_version
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Commit retry differs from its durable dispatch generation",
                )
            actual = self._snapshot_workspace(deadline=ctx.deadline).digest
            if existing.status == "COMMITTED" and actual == existing.receipt.target_version_after:
                return existing.receipt
            raise AgentKernelError(
                ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                "A durable filesystem dispatch cannot be resent and must be reconciled",
                reconcilable=True,
                review_required=True,
            )
        if self.requires_permits:
            return self._commit_with_handles(receipt, ctx, cancellation)
        current = snapshot_tree(self._workspace)
        _validate_snapshot_limits(current)
        if current.digest != receipt.staged.plan.base_version:
            raise AgentKernelError(ErrorCode.STALE_STATE, "Authoritative workspace changed")
        stage_parent = _validate_private_directory(
            self._stage_parent(receipt.staged.stage_id),
            parent=self._stages_root,
        )
        stage_path = _ensure_private_directory(stage_parent / "workspace", parent=stage_parent)
        staged = snapshot_tree(stage_path)
        _validate_snapshot_limits(staged)
        if staged.digest != receipt.staged_state_digest:
            raise AgentKernelError(
                ErrorCode.VERIFICATION_FAILED,
                "Staging tree changed after verification",
            )
        diff = diff_snapshots(current, staged)
        self._fault_point("commit.before_dispatch")
        if ctx.permit is not None:
            validate_active_deadline(ctx.deadline)
        cancellation.raise_if_requested()
        reservation, created = self._reserve_dispatch(
            receipt=receipt,
            ctx=ctx,
            base_snapshot=current,
            target_snapshot=staged,
            diff=diff,
        )
        if not created:
            if reservation.status == "COMMITTED":
                actual = snapshot_tree(self._workspace).digest
                if actual == reservation.receipt.target_version_after:
                    return reservation.receipt
            raise AgentKernelError(
                ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                "A durable filesystem dispatch cannot be resent and must be reconciled",
                reconcilable=True,
                review_required=True,
            )
        self._prepare_backup(reservation.receipt.receipt_id, diff)
        self._fault_point("commit.after_backup_before_manifest")
        manifest = _RecoveryManifest(
            tenant_id=reservation.tenant_id,
            status="PREPARED",
            dispatch_id=reservation.dispatch_id,
            owner_version=reservation.owner_version,
            owner_history_sequence=reservation.owner_history_sequence,
            owner_history_digest=reservation.owner_history_digest,
            permit_digest=reservation.permit_digest,
            normalized_action_digest=reservation.normalized_action_digest,
            effect_receipt=reservation.receipt,
            stage_id=receipt.staged.stage_id,
            staged_state_digest=receipt.staged_state_digest,
            base_snapshot=current,
            target_snapshot=staged,
            diff=diff,
        )
        self._persist_recovery_manifest(manifest)
        self._fault_point("commit.after_manifest_before_prepared")
        current_manifest = manifest
        active_reservation = self._transition_dispatch_durable(reservation, "PREPARED")
        self._fault_point("commit.after_prepared")
        changes = _forward_changes(diff)
        if changes:
            active_reservation = self._transition_dispatch_durable(
                active_reservation,
                "EFFECT_STARTED",
            )
            current_manifest = current_manifest.model_copy(update={"status": "EFFECT_STARTED"})
            self._persist_recovery_manifest(current_manifest)
            self._fault_point("commit.after_effect_started")
        owner_version = ctx.permit.owner_version if ctx.permit is not None else 0
        try:
            with self._intent_effect_boundary(
                reservation.tenant_id,
                receipt.staged.plan.intent_hash,
                owner_version,
                ctx.fencing_token,
            ) as connection:
                row = connection.execute(
                    self._dispatch_select_sql()
                    + " WHERE tenant_id = ? AND intent_hash = ? AND owner_version = ?",
                    (
                        reservation.tenant_id,
                        reservation.intent_hash,
                        reservation.owner_version,
                    ),
                ).fetchone()
                if (
                    row is None
                    or self._load_dispatch_row(row).row_digest != active_reservation.row_digest
                ):
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Dispatch reservation changed before the effect boundary",
                    )
                guarded_current = snapshot_tree(self._workspace)
                guarded_stage = snapshot_tree(stage_path)
                if (
                    guarded_current.digest != current.digest
                    or guarded_stage.digest != staged.digest
                ):
                    raise AgentKernelError(
                        ErrorCode.STALE_STATE,
                        "Filesystem changed before the serialized effect boundary",
                    )
                for change in changes:
                    if ctx.permit is not None:
                        validate_active_deadline(ctx.deadline)
                    self._assert_intent_fence_locked(
                        connection,
                        reservation.tenant_id,
                        reservation.intent_hash,
                        reservation.owner_version,
                        ctx.fencing_token,
                    )
                    self._apply_change(change, stage_path)
                    applied = tuple(dict.fromkeys((*current_manifest.applied_paths, change.path)))
                    current_manifest = current_manifest.model_copy(
                        update={"applied_paths": applied}
                    )
                    self._persist_recovery_manifest(current_manifest)
                    self._fault_point(f"commit.after_change:{change.path}")
                final = snapshot_tree(self._workspace)
                if final.digest != staged.digest:
                    raise AgentKernelError(
                        ErrorCode.VERIFICATION_FAILED,
                        "Committed workspace does not match the staged workspace",
                    )
                self._fault_point("commit.after_effect")
                committed = current_manifest.model_copy(update={"status": "COMMITTED"})
                self._persist_recovery_manifest(committed)
                self._update_dispatch_status_locked(
                    connection,
                    active_reservation,
                    "COMMITTED",
                )
        except Exception as error:
            with suppress(AgentKernelError):
                self._persist_recovery_manifest(
                    current_manifest.model_copy(update={"status": "PARTIAL_OR_UNKNOWN"})
                )
            with suppress(AgentKernelError):
                self._transition_dispatch_durable(
                    active_reservation,
                    "PARTIAL_OR_UNKNOWN",
                )
            raise AgentKernelError(
                ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                "Filesystem commit failed after durable dispatch; authorized recovery required",
                reconcilable=True,
                review_required=True,
            ) from error
        self._fault_point("commit.after_committed")
        try:
            _remove_private_tree(stage_parent)
        except AgentKernelError as error:
            raise AgentKernelError(
                ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                "Effect committed but verified staging cleanup failed",
                reconcilable=True,
                review_required=True,
            ) from error
        return reservation.receipt

    async def verify_committed(
        self,
        receipt: EffectReceipt,
        ctx: VerifyContext,
    ) -> VerificationReport:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._verify_committed_sync(receipt, ctx), cancellation
            )
        )

    def _verify_committed_sync(
        self,
        receipt: EffectReceipt,
        ctx: VerifyContext,
    ) -> VerificationReport:
        owner_version = self._admit_verification(
            receipt,
            ctx,
            phase=VerificationPhase.COMMITTED,
        )
        if ctx.permit is None:
            return self._verify_committed_impl(receipt, ctx)
        if owner_version is None:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Committed verification lost its intent-owner fence",
            )
        with self._intent_effect_boundary(
            ctx.permit.tenant_id,
            ctx.permit.intent_hash,
            owner_version,
            ctx.permit.fencing_token,
        ) as connection:
            self._assert_intent_fence_locked(
                connection,
                ctx.permit.tenant_id,
                ctx.permit.intent_hash,
                owner_version,
                ctx.permit.fencing_token,
            )
            return self._verify_committed_impl(receipt, ctx, connection=connection)

    def _verify_committed_impl(
        self,
        receipt: EffectReceipt,
        ctx: VerifyContext,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> VerificationReport:
        manifest = self._load_recovery_manifest_by_receipt(
            ctx.permit.tenant_id if ctx.permit is not None else _EMBEDDED_TENANT_ID,
            receipt.receipt_id,
            connection=connection,
        )
        reservation = (
            self._dispatch_for_generation(
                manifest.tenant_id,
                receipt.intent_hash,
                manifest.owner_version,
                connection=connection,
            )
            if manifest is not None
            else None
        )
        if ctx.permit is not None:
            with self._workspace_handle() as workspace_fd:
                actual = _snapshot_tree_fd(workspace_fd, deadline=ctx.deadline).digest
        else:
            actual = snapshot_tree(self._workspace).digest
        status = (
            VerificationStatus.PASS
            if manifest is not None
            and manifest.status == "COMMITTED"
            and manifest.effect_receipt == receipt
            and reservation is not None
            and reservation.status == "COMMITTED"
            and reservation.receipt == receipt
            and actual == receipt.target_version_after
            else VerificationStatus.FAIL
        )
        self._fault_point("verify_committed.before_observation")
        evidence_refs = (
            self._record_observation(
                evidence_kind="committed_verification",
                tenant_id=ctx.permit.tenant_id,
                transaction_id=receipt.transaction_id,
                intent_hash=receipt.intent_hash,
                normalized_action_digest=ctx.permit.normalized_action_digest,
                subject_ref=cast("str", ctx.subject_ref),
                operation_permit_ref=cast("str", ctx.permit_ref),
                authority_permit_ref=ctx.permit.authority_permit_ref,
                subject_authority_ref=ctx.permit.subject_permit_ref,
                operation_status=status.value,
                observed_state_digest=actual,
                durable_state_digest=canonical_digest(
                    {
                        "manifest": manifest,
                        "reservation": reservation,
                    }
                ),
                dispatch=reservation,
            )
            if ctx.permit is not None
            else ()
        )
        return VerificationReport(
            status=status,
            verifier="adapter.filesystem.committed",
            summary="Authoritative workspace matches the committed staged digest",
            evidence_refs=evidence_refs,
        )

    async def abort(
        self,
        staged: StagedEffect | StagedReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._abort_sync(staged, ctx), cancellation
            )
        )

    def _abort_sync(
        self,
        staged: StagedEffect | StagedReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        effect = staged.staged if isinstance(staged, StagedReceipt) else staged
        manifest = self._load_stage_manifest(effect.stage_id)
        normalized_action_digest = (
            manifest.stage_permit.normalized_action_digest
            if manifest is not None and manifest.stage_permit is not None
            else None
        )
        self._admit_recovery(
            ctx,
            kind=RecoveryWorkKind.DISCARD_STAGING,
            transaction_id=effect.plan.proposal.transaction_id,
            intent_hash=effect.plan.intent_hash,
            target_id=effect.stage_id,
            target_version_guard=effect.plan.base_version,
            target_normalized_action_digest=normalized_action_digest,
        )
        return self._discard_stage(effect.stage_id, ctx)

    async def abort_stage(self, stage_id: str, ctx: RecoveryContext) -> RecoveryReport:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._abort_stage_sync(stage_id, ctx), cancellation
            )
        )

    def _abort_stage_sync(self, stage_id: str, ctx: RecoveryContext) -> RecoveryReport:
        manifest = self._load_stage_manifest(stage_id)
        self._admit_recovery(
            ctx,
            kind=RecoveryWorkKind.DISCARD_STAGING,
            target_id=stage_id,
            transaction_id=(
                manifest.plan.proposal.transaction_id if manifest is not None else None
            ),
            intent_hash=manifest.plan.intent_hash if manifest is not None else None,
            target_version_guard=(manifest.plan.base_version if manifest is not None else None),
            target_normalized_action_digest=(
                manifest.stage_permit.normalized_action_digest
                if manifest is not None and manifest.stage_permit is not None
                else None
            ),
        )
        if (
            ctx.permit is not None
            and manifest is not None
            and (
                ctx.permit.transaction_id != manifest.plan.proposal.transaction_id
                or ctx.permit.intent_hash != manifest.plan.intent_hash
                or ctx.permit.target_version_guard != manifest.plan.base_version
            )
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Discard permit differs from the durable stage",
            )
        return self._discard_stage(stage_id, ctx)

    def _discard_stage(
        self,
        stage_id: str,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        manifest = self._load_stage_manifest(stage_id)

        def finalize(report: RecoveryReport) -> RecoveryReport:
            if ctx.permit is None or manifest is None or manifest.stage_permit is None:
                return report
            return self._attach_recovery_observation(
                report,
                evidence_kind="discard_staging",
                ctx=ctx,
                transaction_id=manifest.plan.proposal.transaction_id,
                intent_hash=manifest.plan.intent_hash,
                normalized_action_digest=manifest.stage_permit.normalized_action_digest,
                # Stage allocation is durable before adapter dispatch.  A crash inside
                # ``stage`` can therefore require cleanup before a StagedEffect artifact
                # exists; the public StageMaterial target remains reconstructible then.
                subject_ref=ctx.permit.target_evidence_ref,
                durable_state_digest=canonical_digest(manifest),
            )

        if ctx.permit is not None:
            try:
                with self._transaction_effect_boundary(
                    ctx.permit.tenant_id,
                    ctx.permit.transaction_id,
                    ctx.permit.fencing_token,
                ) as connection:
                    self._assert_transaction_fence_locked(
                        connection,
                        ctx.permit.tenant_id,
                        ctx.permit.transaction_id,
                        ctx.permit.fencing_token,
                    )
                    self._remove_stage_tree(stage_id)
                    with self._workspace_handle() as workspace_fd:
                        restored = _snapshot_tree_fd(
                            workspace_fd,
                            deadline=ctx.deadline,
                        ).digest
            except AgentKernelError:
                return finalize(
                    RecoveryReport(
                        status=VerificationStatus.ERROR,
                        strategy="discard_private_stage",
                        residual_effects=("staging_tree_cleanup_failed",),
                    )
                )
            return finalize(
                RecoveryReport(
                    status=VerificationStatus.PASS,
                    strategy="discard_private_stage",
                    restored_state_digest=restored,
                )
            )
        parent = self._stage_parent(stage_id)
        if parent.exists():
            try:
                _validate_private_directory(parent, parent=self._stages_root)
                self._remove_stage_tree(stage_id)
            except AgentKernelError:
                return finalize(
                    RecoveryReport(
                        status=VerificationStatus.ERROR,
                        strategy="discard_private_stage",
                        restored_state_digest=snapshot_tree(self._workspace).digest,
                        residual_effects=("staging_tree_cleanup_failed",),
                    )
                )
        return finalize(
            RecoveryReport(
                status=VerificationStatus.PASS,
                strategy="discard_private_stage",
                restored_state_digest=snapshot_tree(self._workspace).digest,
            )
        )

    async def rollback(self, receipt: EffectReceipt, ctx: RecoveryContext) -> RecoveryReport:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._rollback_sync(receipt, ctx), cancellation
            )
        )

    def _rollback_sync(
        self,
        receipt: EffectReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        tenant_id = ctx.permit.tenant_id if ctx.permit is not None else _EMBEDDED_TENANT_ID
        manifest = self._load_recovery_manifest_by_receipt(tenant_id, receipt.receipt_id)
        self._admit_recovery(
            ctx,
            kind=RecoveryWorkKind.ROLLBACK,
            transaction_id=receipt.transaction_id,
            intent_hash=receipt.intent_hash,
            target_id=manifest.dispatch_id if manifest is not None else None,
            target_version_guard=receipt.target_version_before,
            target_normalized_action_digest=(
                manifest.normalized_action_digest if manifest is not None else None
            ),
            target_owner_version=(manifest.owner_version if manifest is not None else None),
            target_owner_history_sequence=(
                manifest.owner_history_sequence if manifest is not None else None
            ),
            target_owner_history_digest=(
                manifest.owner_history_digest if manifest is not None else None
            ),
        )
        if manifest is None or manifest.effect_receipt != receipt:
            return RecoveryReport(
                status=VerificationStatus.UNKNOWN,
                strategy="guarded_per_file_restore",
                residual_effects=("missing_backup",),
            )

        def finalize(report: RecoveryReport) -> RecoveryReport:
            observed_manifest = self._load_recovery_manifest_by_receipt(
                tenant_id,
                receipt.receipt_id,
            )
            observed_reservation = self._dispatch_for_generation(
                tenant_id,
                receipt.intent_hash,
                manifest.owner_version,
            )
            return self._attach_recovery_observation(
                report,
                evidence_kind="rollback",
                ctx=ctx,
                transaction_id=receipt.transaction_id,
                intent_hash=receipt.intent_hash,
                normalized_action_digest=manifest.normalized_action_digest,
                subject_ref=canonical_digest(receipt),
                durable_state_digest=canonical_digest(
                    {
                        "manifest": observed_manifest,
                        "reservation": observed_reservation,
                    }
                ),
                dispatch=observed_reservation,
            )

        if ctx.permit is not None:
            try:
                return finalize(self._rollback_manifest_with_handles(manifest, ctx))
            except AgentKernelError as error:
                if error.code in {
                    ErrorCode.EVIDENCE_UNAVAILABLE,
                    ErrorCode.INTEGRITY_ERROR,
                    ErrorCode.STALE_STATE,
                }:
                    return finalize(
                        RecoveryReport(
                            status=VerificationStatus.ERROR,
                            strategy="guarded_per_file_restore",
                            residual_effects=("recovery_evidence_unavailable_or_changed",),
                        )
                    )
                raise
        if manifest.status == "ROLLED_BACK":
            actual = snapshot_tree(self._workspace).digest
            return finalize(
                RecoveryReport(
                    status=(
                        VerificationStatus.PASS
                        if actual == receipt.target_version_before
                        else VerificationStatus.UNKNOWN
                    ),
                    strategy="guarded_per_file_restore",
                    restored_state_digest=actual,
                    residual_effects=(
                        ()
                        if actual == receipt.target_version_before
                        else ("target_changed_after_rollback",)
                    ),
                )
            )
        return finalize(
            self._rollback_manifest(
                manifest,
                deadline=ctx.deadline,
                enforce_deadline=ctx.permit is not None,
            )
        )

    def _classify_dispatch_snapshot(
        self,
        connection: sqlite3.Connection,
        reservation: _DispatchReservation,
        manifest: _RecoveryManifest | None,
        actual: FilesystemSnapshot,
        intent: IntentRecord,
        ctx: RecoveryContext,
    ) -> ReconcileReport:
        receipt = reservation.receipt
        if actual.digest == receipt.target_version_after:
            outcome = (
                ReconcileStatus.UNKNOWN
                if reservation.status in {"ROLLED_BACK", "NO_EFFECT"}
                else ReconcileStatus.COMMITTED
            )
        elif actual.digest == receipt.target_version_before:
            if (
                reservation.status == "COMMITTED"
                or reservation.status
                in {
                    "EFFECT_STARTED",
                    "PARTIAL_OR_UNKNOWN",
                }
                or (
                    reservation.status == "PREPARED"
                    and (manifest is None or bool(manifest.applied_paths))
                )
            ):
                outcome = ReconcileStatus.UNKNOWN
            else:
                outcome = ReconcileStatus.NO_EFFECT
        elif manifest is not None and self._snapshot_is_guarded(manifest, actual):
            outcome = ReconcileStatus.PARTIAL_OR_INVALID
        else:
            outcome = ReconcileStatus.UNKNOWN
        evidence = (
            self._record_observation(
                evidence_kind="reconciliation",
                tenant_id=ctx.permit.tenant_id,
                transaction_id=intent.transaction_id,
                intent_hash=intent.intent_hash,
                normalized_action_digest=reservation.normalized_action_digest,
                subject_ref=canonical_digest(intent),
                operation_permit_ref=cast("str", ctx.permit_ref),
                authority_permit_ref=cast("str", ctx.permit_ref),
                subject_authority_ref=ctx.permit.target_evidence_ref,
                operation_status=outcome.value,
                observed_state_digest=actual.digest,
                durable_state_digest=canonical_digest(
                    {"manifest": manifest, "reservation": reservation}
                ),
                dispatch=reservation,
            )
            if ctx.permit is not None
            else ()
        )
        if actual.digest == receipt.target_version_after:
            if reservation.status in {"ROLLED_BACK", "NO_EFFECT"}:
                return ReconcileReport(
                    status=ReconcileStatus.UNKNOWN,
                    evidence_refs=evidence,
                )
            if reservation.status != "COMMITTED":
                self._update_dispatch_status_locked(connection, reservation, "COMMITTED")
            if manifest is not None and manifest.status not in {
                "COMMITTED",
                "NO_EFFECT",
                "ROLLED_BACK",
            }:
                self._persist_recovery_manifest(manifest.model_copy(update={"status": "COMMITTED"}))
            return ReconcileReport(
                status=ReconcileStatus.COMMITTED,
                receipt=receipt,
                evidence_refs=evidence,
            )
        if actual.digest == receipt.target_version_before:
            if reservation.status == "COMMITTED":
                return ReconcileReport(
                    status=ReconcileStatus.UNKNOWN,
                    evidence_refs=evidence,
                )
            if reservation.status in {"EFFECT_STARTED", "PARTIAL_OR_UNKNOWN"} or (
                reservation.status == "PREPARED"
                and (manifest is None or bool(manifest.applied_paths))
            ):
                return ReconcileReport(
                    status=ReconcileStatus.UNKNOWN,
                    evidence_refs=evidence,
                )
            if reservation.status not in {"NO_EFFECT", "ROLLED_BACK"}:
                classification = {
                    "classification": "NO_EFFECT",
                    "dispatch_id": reservation.dispatch_id,
                    "evidence_ref": evidence[-1] if evidence else reservation.row_digest,
                    "intent_hash": reservation.intent_hash,
                    "observed_state_digest": actual.digest,
                    "owner_version": reservation.owner_version,
                }
                self._update_dispatch_status_locked(
                    connection,
                    reservation,
                    "NO_EFFECT",
                    classification=classification,
                )
                if manifest is not None:
                    self._persist_recovery_manifest(
                        manifest.model_copy(update={"status": "NO_EFFECT"})
                    )
            return ReconcileReport(
                status=ReconcileStatus.NO_EFFECT,
                evidence_refs=evidence,
            )
        if manifest is not None and self._snapshot_is_guarded(manifest, actual):
            return ReconcileReport(
                status=ReconcileStatus.PARTIAL_OR_INVALID,
                receipt=receipt,
                evidence_refs=evidence,
            )
        return ReconcileReport(status=ReconcileStatus.UNKNOWN, evidence_refs=evidence)

    async def reconcile(self, intent: IntentRecord, ctx: RecoveryContext) -> ReconcileReport:
        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(
                lambda: self._reconcile_sync(intent, ctx), cancellation
            )
        )

    def _reconcile_sync(
        self,
        intent: IntentRecord,
        ctx: RecoveryContext,
    ) -> ReconcileReport:
        permit = ctx.permit
        if permit is not None:
            manifest = self._load_recovery_manifest_by_generation(
                permit.tenant_id,
                intent.intent_hash,
                permit.target_owner_version,
            )
            reservation = self._dispatch_for_generation(
                permit.tenant_id,
                intent.intent_hash,
                permit.target_owner_version,
            )
        else:
            manifest = self._load_latest_recovery_manifest(
                _EMBEDDED_TENANT_ID,
                intent.intent_hash,
            )
            reservation = (
                self._dispatch_for_generation(
                    _EMBEDDED_TENANT_ID,
                    intent.intent_hash,
                    manifest.owner_version,
                )
                if manifest is not None
                else None
            )
        guard = reservation.receipt.target_version_before if reservation is not None else None
        target_action = self._admit_recovery(
            ctx,
            kind=RecoveryWorkKind.RECONCILE_DISPATCH,
            transaction_id=intent.transaction_id,
            intent_hash=intent.intent_hash,
            target_id=(
                reservation.dispatch_id
                if reservation is not None
                else permit.target_id
                if permit is not None
                else None
            ),
            target_version_guard=(
                guard
                if guard is not None
                else permit.target_version_guard
                if permit is not None
                else None
            ),
            target_normalized_action_digest=(
                manifest.normalized_action_digest if manifest is not None else None
            ),
            target_owner_version=(reservation.owner_version if reservation is not None else None),
            target_owner_history_sequence=(
                reservation.owner_history_sequence if reservation is not None else None
            ),
            target_owner_history_digest=(
                reservation.owner_history_digest if reservation is not None else None
            ),
        )
        if permit is None and reservation is None:
            return ReconcileReport(status=ReconcileStatus.UNKNOWN)
        boundary = (
            self._intent_effect_boundary(
                permit.tenant_id,
                permit.intent_hash,
                permit.target_owner_version,
                permit.fencing_token,
            )
            if permit is not None
            else self._metadata_effect_boundary()
        )
        current_reservation = reservation
        try:
            with boundary as connection:
                if permit is not None:
                    current = self._dispatch_for_generation(
                        permit.tenant_id,
                        intent.intent_hash,
                        permit.target_owner_version,
                        connection=connection,
                    )
                    current_reservation = current
                    if current is None:
                        if target_action is None or ctx.permit_ref is None:
                            raise AgentKernelError(
                                ErrorCode.EVIDENCE_UNAVAILABLE,
                                "Authorized reconciliation evidence is unavailable",
                            )
                        if reservation is not None or manifest is not None:
                            raise AgentKernelError(
                                ErrorCode.INTEGRITY_ERROR,
                                "Dispatch evidence disappeared before reconciliation",
                            )
                        with self._workspace_handle() as workspace_fd:
                            actual = _snapshot_tree_fd(workspace_fd, deadline=ctx.deadline)
                        durable_state_digest = canonical_digest(
                            {
                                "profile": "agentkernel.adapter.dispatch-absence/v1",
                                "adapter_manifest_digest": self.manifest.digest,
                                "tenant_id": permit.tenant_id,
                                "intent_hash": intent.intent_hash,
                                "dispatch_id": permit.target_id,
                                "owner_version": permit.target_owner_version,
                                "owner_history_sequence": (permit.target_owner_history_sequence),
                                "owner_history_digest": permit.target_owner_history_digest,
                                "reservation_present": False,
                            }
                        )
                        evidence = self._record_observation(
                            evidence_kind="reconciliation",
                            tenant_id=permit.tenant_id,
                            transaction_id=intent.transaction_id,
                            intent_hash=intent.intent_hash,
                            normalized_action_digest=canonical_digest(target_action),
                            subject_ref=canonical_digest(intent),
                            operation_permit_ref=ctx.permit_ref,
                            authority_permit_ref=ctx.permit_ref,
                            subject_authority_ref=permit.target_evidence_ref,
                            operation_status=ReconcileStatus.NO_EFFECT.value,
                            observed_state_digest=actual.digest,
                            durable_state_digest=durable_state_digest,
                            dispatch_id=permit.target_id,
                            owner_version=permit.target_owner_version,
                            owner_history_sequence=permit.target_owner_history_sequence,
                            owner_history_digest=permit.target_owner_history_digest,
                        )
                        return ReconcileReport(
                            status=ReconcileStatus.NO_EFFECT,
                            evidence_refs=evidence,
                        )
                    manifest = self._load_recovery_manifest_by_generation(
                        permit.tenant_id,
                        intent.intent_hash,
                        permit.target_owner_version,
                        connection=connection,
                    )
                else:
                    if reservation is None:
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Legacy reconciliation lost its dispatch reservation",
                        )
                    current = self._dispatch_for_generation(
                        reservation.tenant_id,
                        reservation.intent_hash,
                        reservation.owner_version,
                        connection=connection,
                    )
                    current_reservation = current
                    manifest = self._load_recovery_manifest_by_generation(
                        reservation.tenant_id,
                        reservation.intent_hash,
                        reservation.owner_version,
                        connection=connection,
                    )
                if current is None:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Dispatch generation changed before reconciliation",
                    )
                if permit is not None:
                    if target_action is None or (
                        permit.target_id != current.dispatch_id
                        or permit.target_owner_version != current.owner_version
                        or (permit.target_owner_history_sequence != current.owner_history_sequence)
                        or permit.target_owner_history_digest != current.owner_history_digest
                        or permit.target_version_guard != current.receipt.target_version_before
                        or canonical_digest(target_action) != current.normalized_action_digest
                    ):
                        raise AgentKernelError(
                            ErrorCode.INTEGRITY_ERROR,
                            "Reconciliation permit differs from the durable dispatch generation",
                        )
                    with self._workspace_handle() as workspace_fd:
                        actual = _snapshot_tree_fd(workspace_fd, deadline=ctx.deadline)
                else:
                    actual = snapshot_tree(self._workspace)
                    _validate_snapshot_limits(actual)
                return self._classify_dispatch_snapshot(
                    connection,
                    current,
                    manifest,
                    actual,
                    intent,
                    ctx,
                )
        except AgentKernelError as error:
            if error.code in {
                ErrorCode.STALE_STATE,
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
            }:
                if permit is not None and current_reservation is None:
                    raise
                return ReconcileReport(
                    status=ReconcileStatus.UNKNOWN,
                    evidence_refs=(
                        self._record_observation(
                            evidence_kind="reconciliation",
                            tenant_id=permit.tenant_id,
                            transaction_id=intent.transaction_id,
                            intent_hash=intent.intent_hash,
                            normalized_action_digest=(current_reservation.normalized_action_digest),
                            subject_ref=canonical_digest(intent),
                            operation_permit_ref=cast("str", ctx.permit_ref),
                            authority_permit_ref=cast("str", ctx.permit_ref),
                            subject_authority_ref=permit.target_evidence_ref,
                            operation_status=ReconcileStatus.UNKNOWN.value,
                            observed_state_digest=canonical_digest(
                                {"observation": "unavailable", "error": error.code.value}
                            ),
                            durable_state_digest=canonical_digest(
                                {"manifest": manifest, "reservation": current_reservation}
                            ),
                            dispatch=current_reservation,
                        )
                        if permit is not None and current_reservation is not None
                        else ()
                    ),
                )
            raise

    async def compensate(self, receipt: EffectReceipt, ctx: RecoveryContext) -> RecoveryReport:
        del receipt, ctx

        def unsupported(_cancellation: BlockingCancellation) -> RecoveryReport:
            raise UnsupportedSemantics("compensate")

        return await run_blocking_quiescent(
            lambda cancellation: self._run_locked(lambda: unsupported(cancellation), cancellation)
        )
