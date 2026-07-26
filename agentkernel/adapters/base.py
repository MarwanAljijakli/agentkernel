"""Explicit stage/execute/verify/commit/recovery adapter protocol."""

from __future__ import annotations

import asyncio
import os
import stat
import sys
import threading
import unicodedata
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from importlib.util import find_spec
from pathlib import Path
from typing import Annotated, Protocol, cast, runtime_checkable

from pydantic import BaseModel, Field, JsonValue, ValidationError, field_validator

from agentkernel.canonical import canonical_digest, canonical_json_bytes, sha256_digest
from agentkernel.domain.enums import RecoveryWorkKind, RiskClass, VerificationPhase
from agentkernel.domain.models import (
    RECOVERY_ACTION_BINDING_ARGUMENT,
    ActionProposal,
    Artifact,
    CommitPermit,
    Digest,
    EffectReceipt,
    Identifier,
    InspectionPermit,
    IntentRecord,
    NonEmptyStr,
    NormalizedAction,
    RecoveryActionBinding,
    RecoveryPermit,
    StagePermit,
    StrictModel,
    VerificationPermit,
    VerificationReport,
)
from agentkernel.domain.models import (
    AdapterObservation as _AdapterObservation,
)
from agentkernel.domain.models import (
    RecoveryReport as _RecoveryReport,
)
from agentkernel.errors import AgentKernelError, ErrorCode

AdapterObservation = _AdapterObservation
RecoveryReport = _RecoveryReport


class BlockingCancellation:
    """Thread-safe cancellation signal for pre-effect linearization points."""

    def __init__(self) -> None:
        self._requested = threading.Event()

    def request(self) -> None:
        self._requested.set()

    @property
    def requested(self) -> bool:
        return self._requested.is_set()

    def raise_if_requested(self) -> None:
        if self._requested.is_set():
            raise asyncio.CancelledError


async def run_blocking_quiescent[BlockingResultT](
    operation: Callable[[BlockingCancellation], BlockingResultT],
) -> BlockingResultT:
    """Run a blocking adapter boundary without abandoning it on cancellation.

    Adapter effect methods are synchronous critical sections.  A caller cancellation
    must become observable to the event loop, but returning while the worker still owns
    a target or journal lock would allow recovery to race an in-flight effect.  Shield
    the worker, wait through repeated cancellation until it is quiescent, retrieve any
    worker exception, and then preserve the caller's cancellation.
    """

    cancellation = BlockingCancellation()
    worker = asyncio.create_task(asyncio.to_thread(operation, cancellation))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        cancellation.request()
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except BaseException:
                break
        if worker.done():
            with suppress(asyncio.CancelledError):
                worker.exception()
        raise


def _canonical_manifest_text(value: str, *, field_name: str) -> str:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field_name} must be valid UTF-8") from error
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{field_name} must use Unicode NFC")
    return value


class NormalizerManifest(StrictModel):
    """Pinned pure-normalizer admission metadata for one operation schema.

    ``implementation_digest`` is only as strong as the admission pipeline that produced it.
    A declarative pre-release pin is not evidence of installed-byte measurement or signing.
    """

    schema_ref: NonEmptyStr
    schema_digest: Digest
    implementation: Identifier
    version: NonEmptyStr
    implementation_digest: Digest
    max_resources: Annotated[int, Field(ge=1, le=4096)]
    max_argument_bytes: Annotated[int, Field(ge=1, le=16_777_216)]

    @field_validator("schema_ref", "version")
    @classmethod
    def _text_is_unicode_nfc(cls, value: str) -> str:
        return _canonical_manifest_text(value, field_name="Normalizer manifest text")

    @property
    def digest(self) -> str:
        """Digest the complete normalizer contract, including its resource bounds."""

        return canonical_digest(self)


class OperationManifest(StrictModel):
    risk_floor: RiskClass
    effect_domains: Annotated[tuple[NonEmptyStr, ...], Field(max_length=64)]
    idempotency: NonEmptyStr = "intent_hash"
    staging: bool
    commit: bool
    abort: bool
    rollback: bool
    reconcile: bool
    compensate: bool = False
    preconditions: Annotated[tuple[NonEmptyStr, ...], Field(max_length=256)] = ()
    staged_postconditions: Annotated[tuple[NonEmptyStr, ...], Field(max_length=256)] = ()
    committed_postconditions: Annotated[tuple[NonEmptyStr, ...], Field(max_length=256)] = ()
    normalizer: NormalizerManifest | None = None

    @field_validator("idempotency")
    @classmethod
    def _canonical_idempotency(cls, value: str) -> str:
        return _canonical_manifest_text(value, field_name="Operation idempotency mode")

    @field_validator(
        "effect_domains",
        "preconditions",
        "staged_postconditions",
        "committed_postconditions",
    )
    @classmethod
    def _canonical_semantic_sets(cls, values: tuple[str, ...], info: object) -> tuple[str, ...]:
        field_name = getattr(info, "field_name", "operation manifest tuple")
        if values != tuple(sorted(set(values))):
            raise ValueError(f"{field_name} must be sorted and unique")
        for value in values:
            _canonical_manifest_text(value, field_name=field_name)
        return values


class AdapterManifest(StrictModel):
    api_version: str = "agentkernel.io/v1alpha1"
    name: Identifier
    version: NonEmptyStr
    implementation_digest: Digest
    operations: Annotated[
        dict[NonEmptyStr, OperationManifest], Field(min_length=1, max_length=1_024)
    ]

    @field_validator("api_version", "version")
    @classmethod
    def _canonical_text(cls, value: str, info: object) -> str:
        return _canonical_manifest_text(
            value,
            field_name=getattr(info, "field_name", "adapter manifest text"),
        )

    @field_validator("operations")
    @classmethod
    def _canonical_operation_names(
        cls,
        values: dict[str, OperationManifest],
    ) -> dict[str, OperationManifest]:
        for operation in values:
            _canonical_manifest_text(operation, field_name="Adapter operation name")
        return values

    @property
    def digest(self) -> str:
        """Digest the exact versioned manifest admitted to the registry."""

        # Excluding only absent optional extensions preserves the A0 manifest identity.
        return canonical_digest(self.model_dump(mode="python", exclude_none=True))


class EffectPlan(StrictModel):
    plan_id: Identifier
    proposal: ActionProposal
    canonical_resource: NonEmptyStr
    base_version: NonEmptyStr
    intent_hash: Digest
    risk_class: RiskClass
    effect_domains: tuple[NonEmptyStr, ...]
    semantic_arguments: dict[str, JsonValue] = Field(default_factory=dict)


class StagedEffect(StrictModel):
    stage_id: Identifier
    plan: EffectPlan
    base_state_digest: Digest
    private_state: dict[str, JsonValue] = Field(default_factory=dict)


class StagedReceipt(StrictModel):
    receipt_id: Identifier
    staged: StagedEffect
    staged_state_digest: Digest
    private_state: dict[str, JsonValue] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ReadOnlyContext:
    deadline: datetime
    worker_id: str | None = None
    permit: InspectionPermit | None = None
    permit_ref: str | None = None
    normalized_action: NormalizedAction | None = None
    normalized_action_ref: str | None = None
    proposal: ActionProposal | None = None
    proposal_ref: str | None = None

    def __post_init__(self) -> None:
        permit_fields = (
            self.worker_id,
            self.permit,
            self.permit_ref,
            self.normalized_action,
            self.normalized_action_ref,
            self.proposal,
            self.proposal_ref,
        )
        if any(value is not None for value in permit_fields) and not all(
            value is not None for value in permit_fields
        ):
            raise ValueError("Inspection worker, permit, and artifact ref must appear together")
        if self.permit is not None:
            normalized_action = cast("NormalizedAction", self.normalized_action)
            proposal = cast("ActionProposal", self.proposal)
            InspectionPermit.model_validate(self.permit.model_dump(mode="python"))
            NormalizedAction.model_validate(normalized_action.model_dump(mode="python"))
            ActionProposal.model_validate(proposal.model_dump(mode="python"))
        if self.permit is not None and (
            self.worker_id != self.permit.worker_id
            or self.deadline != self.permit.deadline
            or self.permit_ref != canonical_digest(self.permit)
            or self.normalized_action_ref != canonical_digest(normalized_action)
            or self.permit.normalized_action_digest != self.normalized_action_ref
            or self.proposal_ref != canonical_digest(proposal)
            or self.permit.proposal_ref != self.proposal_ref
        ):
            raise ValueError("Inspection context differs from its coordinator permit")


@dataclass(frozen=True, slots=True)
class StageContext:
    deadline: datetime
    worker_id: str
    permit: StagePermit | None = None
    permit_ref: str | None = None
    normalized_action: NormalizedAction | None = None
    normalized_action_ref: str | None = None

    def __post_init__(self) -> None:
        permit_fields = (
            self.permit,
            self.permit_ref,
            self.normalized_action,
            self.normalized_action_ref,
        )
        if any(value is not None for value in permit_fields) and not all(
            value is not None for value in permit_fields
        ):
            raise ValueError(
                "Stage permit, normalized action, and artifact refs must appear together"
            )
        if self.permit is None:
            return
        normalized_action = cast("NormalizedAction", self.normalized_action)
        StagePermit.model_validate(self.permit.model_dump(mode="python"))
        NormalizedAction.model_validate(normalized_action.model_dump(mode="python"))
        if (
            self.worker_id != self.permit.worker_id
            or self.deadline != self.permit.deadline
            or self.permit_ref != canonical_digest(self.permit)
            or self.normalized_action_ref != canonical_digest(normalized_action)
            or self.permit.normalized_action_digest != self.normalized_action_ref
        ):
            raise ValueError("Stage context differs from its coordinator permit")


@dataclass(frozen=True, slots=True)
class VerifyContext:
    deadline: datetime
    read_only: bool = True
    worker_id: str | None = None
    phase: VerificationPhase | None = None
    permit: VerificationPermit | None = None
    permit_ref: str | None = None
    normalized_action: NormalizedAction | None = None
    normalized_action_ref: str | None = None
    subject_ref: str | None = None

    def __post_init__(self) -> None:
        bound_fields = (
            self.permit,
            self.permit_ref,
            self.worker_id,
            self.phase,
            self.normalized_action,
            self.normalized_action_ref,
            self.subject_ref,
        )
        if any(value is not None for value in bound_fields) and not all(
            value is not None for value in bound_fields
        ):
            raise ValueError(
                "Verification permit, normalized action, subject, and artifact refs "
                "must appear together"
            )
        if not self.read_only:
            raise ValueError("Adapter verification context must be read-only")
        if self.permit is None:
            return
        normalized_action = cast("NormalizedAction", self.normalized_action)
        VerificationPermit.model_validate(self.permit.model_dump(mode="python"))
        NormalizedAction.model_validate(normalized_action.model_dump(mode="python"))
        if (
            self.deadline != self.permit.deadline
            or self.worker_id != self.permit.worker_id
            or self.phase is not self.permit.phase
            or self.permit_ref != canonical_digest(self.permit)
            or self.normalized_action_ref != canonical_digest(normalized_action)
            or self.permit.normalized_action_digest != self.normalized_action_ref
            or self.subject_ref != self.permit.subject_ref
        ):
            raise ValueError("Verification context differs from its coordinator permit")


@dataclass(frozen=True, slots=True)
class CommitContext:
    deadline: datetime
    fencing_token: int
    idempotency_key: str
    target_version_guard: str
    permit: CommitPermit | None = None
    permit_ref: str | None = None
    normalized_action: NormalizedAction | None = None
    normalized_action_ref: str | None = None

    def __post_init__(self) -> None:
        permit_fields = (
            self.permit,
            self.permit_ref,
            self.normalized_action,
            self.normalized_action_ref,
        )
        if any(value is not None for value in permit_fields) and not all(
            value is not None for value in permit_fields
        ):
            raise ValueError(
                "Commit permit, normalized action, and artifact refs must appear together"
            )
        if self.permit is None:
            return
        normalized_action = cast("NormalizedAction", self.normalized_action)
        CommitPermit.model_validate(self.permit.model_dump(mode="python"))
        NormalizedAction.model_validate(normalized_action.model_dump(mode="python"))
        if (
            self.deadline != self.permit.deadline
            or self.fencing_token != self.permit.fencing_token
            or self.idempotency_key != self.permit.idempotency_key
            or self.target_version_guard != self.permit.target_version_guard
            or self.permit_ref != canonical_digest(self.permit)
            or self.normalized_action_ref != canonical_digest(normalized_action)
            or self.permit.normalized_action_digest != self.normalized_action_ref
        ):
            raise ValueError("Commit context differs from its coordinator permit")


@dataclass(frozen=True, slots=True)
class RecoveryContext:
    deadline: datetime
    authority_ref: str
    worker_id: str | None = None
    permit: RecoveryPermit | None = None
    permit_ref: str | None = None

    def __post_init__(self) -> None:
        permit_fields = (self.worker_id, self.permit, self.permit_ref)
        if any(value is not None for value in permit_fields) and not all(
            value is not None for value in permit_fields
        ):
            raise ValueError("Recovery worker, permit, and artifact ref must appear together")
        if self.permit is not None:
            RecoveryPermit.model_validate(self.permit.model_dump(mode="python"))
        if self.permit is not None and (
            self.worker_id != self.permit.worker_id
            or self.deadline != self.permit.deadline
            or self.authority_ref != self.permit.authorization_round_digest
            or self.permit_ref != canonical_digest(self.permit)
        ):
            raise ValueError("Recovery context differs from its coordinator permit")


class ReconcileStatus(StrEnum):
    COMMITTED = "COMMITTED"
    NO_EFFECT = "NO_EFFECT"
    PARTIAL_OR_INVALID = "PARTIAL_OR_INVALID"
    UNKNOWN = "UNKNOWN"


class ReconcileReport(StrictModel):
    status: ReconcileStatus
    receipt: EffectReceipt | None = None
    evidence_refs: tuple[Digest, ...] = ()


Permit = InspectionPermit | StagePermit | CommitPermit | VerificationPermit | RecoveryPermit


@runtime_checkable
class ArtifactReader(Protocol):
    """Minimal read-only evidence boundary exposed to an enforced adapter."""

    def get(self, digest: str) -> bytes: ...


@runtime_checkable
class EvidenceStore(ArtifactReader, Protocol):
    """Trusted read/write evidence boundary required by enforced adapters."""

    def put(
        self,
        content: bytes,
        *,
        media_type: str = "application/octet-stream",
    ) -> Artifact: ...


class EvidenceClock:
    """Injectable UTC clock that fails closed if its source moves backwards."""

    def __init__(self, source: Callable[[], datetime] | None = None) -> None:
        self._source = source or (lambda: datetime.now(UTC))
        self._last: datetime | None = None
        self._lock = threading.RLock()

    def now(self) -> datetime:
        with self._lock:
            captured = self._source()
            if captured.tzinfo is None or captured.utcoffset() != UTC.utcoffset(captured):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Evidence clock must return an aware UTC timestamp",
                )
            if self._last is not None and captured < self._last:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Evidence clock moved backwards",
                )
            self._last = captured
            return captured


def put_adapter_observation(
    store: EvidenceStore,
    observation: AdapterObservation,
) -> str:
    """Publish and read back one exact canonical adapter observation."""

    content = canonical_json_bytes(observation)
    artifact = store.put(
        content,
        media_type="application/vnd.agentkernel.adapter-observation+json",
    )
    expected = sha256_digest(content)
    if artifact.digest != expected or store.get(expected) != content:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Adapter observation failed immutable evidence read-back",
        )
    return expected


def implementation_digest_for_modules(*module_names: str) -> str:
    """Measure a stable logical set of installed Python source bytes.

    Logical module names, byte sizes, and SHA-256 values are hashed instead of absolute paths,
    so the result is reproducible across installation roots. Namespace packages, bytecode-only
    modules, and mutable/non-file origins fail closed.
    """

    if not module_names or tuple(sorted(set(module_names))) != module_names:
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Implementation module names must be sorted and unique",
        )
    measured: list[dict[str, object]] = []
    for module_name in module_names:
        spec = find_spec(module_name)
        origin = None if spec is None else spec.origin
        if origin is None or origin in {"built-in", "frozen"}:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter implementation module has no measurable source artifact",
                details={"module": module_name},
            )
        path = Path(origin)
        descriptor = -1
        try:
            metadata_before = path.lstat()
            if not stat.S_ISREG(metadata_before.st_mode) or path.is_symlink() or path.is_junction():
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Adapter implementation source is linked or not a regular file",
                    details={"module": module_name},
                )
            if os.name == "nt":
                descriptor = _open_windows_source_handle(path)
            else:
                nofollow = getattr(os, "O_NOFOLLOW", None)
                if nofollow is None:
                    raise AgentKernelError(
                        ErrorCode.UNSUPPORTED_SEMANTICS,
                        "Source-byte admission requires no-follow file opens",
                    )
                descriptor = os.open(
                    path,
                    os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0),
                )
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != metadata_before.st_dev
                or opened.st_ino != metadata_before.st_ino
                or opened.st_size != metadata_before.st_size
            ):
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Adapter implementation source changed before its no-follow open",
                    details={"module": module_name},
                )
            if opened.st_size > 16_777_216:
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Adapter implementation source exceeds the admission byte limit",
                    details={"module": module_name},
                )
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1_048_576))
                if not chunk:
                    raise AgentKernelError(
                        ErrorCode.INTEGRITY_ERROR,
                        "Adapter implementation source ended during measurement",
                        details={"module": module_name},
                    )
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            metadata_after = os.fstat(descriptor)
            path_after = path.lstat()
        except OSError as error:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter implementation source artifact is unavailable",
                details={"module": module_name},
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if (
            metadata_before.st_dev != metadata_after.st_dev
            or metadata_before.st_ino != metadata_after.st_ino
            or metadata_before.st_size != metadata_after.st_size
            or metadata_before.st_mtime_ns != metadata_after.st_mtime_ns
            or metadata_before.st_dev != path_after.st_dev
            or metadata_before.st_ino != path_after.st_ino
            or metadata_before.st_size != path_after.st_size
            or metadata_before.st_mtime_ns != path_after.st_mtime_ns
            or not stat.S_ISREG(path_after.st_mode)
            or len(content) != metadata_after.st_size
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Adapter implementation source changed during measurement",
                details={"module": module_name},
            )
        measured.append(
            {
                "module": module_name,
                "size_bytes": len(content),
                "sha256": sha256_digest(content),
            }
        )
    return canonical_digest({"profile": "agentkernel.python-source-set/v1", "modules": measured})


if sys.platform == "win32":

    def _open_windows_source_handle(path: Path) -> int:
        """Open one source file without traversing a Windows reparse point."""

        # These imports are type-checked only for the Windows target.
        import ctypes  # noqa: PLC0415
        import msvcrt  # noqa: PLC0415
        from ctypes import wintypes  # noqa: PLC0415

        class _ByHandleFileInformation(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", wintypes.DWORD),
                ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME),
                ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD),
                ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD),
                ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD),
                ("nFileIndexLow", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        create_file.restype = wintypes.HANDLE
        handle = create_file(
            str(path),
            0x80000000,  # GENERIC_READ
            0x00000007,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            None,
            3,  # OPEN_EXISTING
            0x00200080,  # FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if handle == invalid_handle:
            raise OSError(ctypes.get_last_error(), "CreateFileW failed")
        try:
            information = _ByHandleFileInformation()
            if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
                raise OSError(ctypes.get_last_error(), "GetFileInformationByHandle failed")
            if information.dwFileAttributes & 0x00000400:  # FILE_ATTRIBUTE_REPARSE_POINT
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Adapter implementation source is a Windows reparse point",
                )
            descriptor = msvcrt.open_osfhandle(
                int(handle),
                os.O_RDONLY | getattr(os, "O_BINARY", 0),
            )
            handle = None
            return descriptor
        finally:
            if handle is not None:
                kernel32.CloseHandle(handle)

else:

    def _open_windows_source_handle(path: Path) -> int:
        del path
        raise AgentKernelError(
            ErrorCode.UNSUPPORTED_SEMANTICS,
            "Windows source handles are unavailable on this platform",
        )


def validate_permit_artifact(
    permit: Permit,
    permit_ref: str,
    artifacts: ArtifactReader | None,
) -> None:
    """Require the durable artifact at ``permit_ref`` to be this exact canonical permit."""

    validate_canonical_artifact(permit, permit_ref, artifacts, label="Permit")


def validate_normalized_action_artifact(
    action: NormalizedAction,
    action_ref: str,
    artifacts: ArtifactReader | None,
    *,
    permit_digest: str,
    proposal: ActionProposal,
    proposal_ref: str,
    manifest: AdapterManifest,
) -> None:
    """Bind raw transport data to the exact normalized action authorized by a permit."""

    validate_canonical_artifact(action, action_ref, artifacts, label="Normalized action")
    validate_canonical_artifact(proposal, proposal_ref, artifacts, label="Action proposal")
    if (
        action_ref != permit_digest
        or action.intent_hash != canonical_digest(action.intent_projection())
        or action.adapter_manifest_digest != manifest.digest
        or action.adapter != manifest.name
        or action.adapter_version != manifest.version
        or action.transaction_id != proposal.transaction_id
        or action.goal_id != proposal.goal_id
        or action.agent_id != proposal.agent_id
        or action.adapter != proposal.adapter
        or action.adapter_version != proposal.adapter_version
        or action.operation != proposal.operation
        or action.deadline != proposal.deadline
        or action.idempotency_key != proposal.idempotency_key
        or tuple(binding.provenance_id for binding in action.provenance)
        != tuple(sorted(proposal.provenance_ids))
    ):
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Normalized action does not bind the permitted proposal and adapter manifest",
        )


def validate_recovery_action_artifacts(
    permit: RecoveryPermit,
    artifacts: ArtifactReader | None,
    *,
    manifest: AdapterManifest,
    recovery_kind: RecoveryWorkKind,
    target_transaction_id: str,
    target_intent_hash: str,
    target_normalized_action_digest: str | None,
    target_id: str,
    target_evidence_ref: str,
    target_version_guard: str,
    target_owner_version: int,
    target_owner_history_sequence: int,
    target_owner_history_digest: str,
) -> tuple[NormalizedAction, RecoveryActionBinding, NormalizedAction]:
    """Validate the recovery action, its semantic binding, and original target action."""

    recovery_action = load_canonical_model_artifact(
        permit.recovery_action_digest,
        NormalizedAction,
        artifacts,
        label="Recovery normalized action",
    )
    binding_arguments = tuple(
        argument
        for argument in recovery_action.semantic_arguments
        if argument.argument_name == RECOVERY_ACTION_BINDING_ARGUMENT
    )
    remaining_arguments = tuple(
        argument
        for argument in recovery_action.semantic_arguments
        if argument.argument_name != RECOVERY_ACTION_BINDING_ARGUMENT
    )
    if len(binding_arguments) != 1:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Recovery normalized action lacks one exact semantic binding",
        )
    binding_argument = binding_arguments[0]
    binding = load_canonical_model_artifact(
        binding_argument.digest,
        RecoveryActionBinding,
        artifacts,
        label="Recovery action binding",
    )
    target_action = load_canonical_model_artifact(
        binding.target_normalized_action_digest,
        NormalizedAction,
        artifacts,
        label="Recovery target normalized action",
    )
    if artifacts is None:
        raise AgentKernelError(
            ErrorCode.EVIDENCE_UNAVAILABLE,
            "Recovery semantic evidence is unavailable",
        )
    binding_bytes = artifacts.get(binding_argument.digest)
    same_target_semantics = (
        recovery_action.tenant_id == target_action.tenant_id
        and recovery_action.principal_id == target_action.principal_id
        and recovery_action.goal_id == target_action.goal_id
        and recovery_action.run_id == target_action.run_id
        and recovery_action.actor_id == target_action.actor_id
        and recovery_action.on_behalf_of == target_action.on_behalf_of
        and recovery_action.agent_id == target_action.agent_id
        and recovery_action.adapter == target_action.adapter
        and recovery_action.adapter_version == target_action.adapter_version
        and recovery_action.adapter_manifest_digest == target_action.adapter_manifest_digest
        and recovery_action.operation == target_action.operation
        and recovery_action.normalizer_implementation == target_action.normalizer_implementation
        and recovery_action.normalizer_version == target_action.normalizer_version
        and recovery_action.normalizer_digest == target_action.normalizer_digest
        and recovery_action.operation_schema_ref == target_action.operation_schema_ref
        and recovery_action.operation_schema_digest == target_action.operation_schema_digest
        and recovery_action.configuration_digest == target_action.configuration_digest
        and recovery_action.risk_floor is target_action.risk_floor
        and recovery_action.effect_domains == target_action.effect_domains
        and recovery_action.resource_uses == target_action.resource_uses
        and remaining_arguments == target_action.semantic_arguments
        and recovery_action.provenance == target_action.provenance
    )
    if (
        permit.recovery_action_digest != canonical_digest(recovery_action)
        or recovery_action.tenant_id != permit.tenant_id
        or recovery_action.transaction_id != permit.recovery_action_transaction_id
        or recovery_action.intent_hash != permit.recovery_action_intent_hash
        or recovery_action.adapter != manifest.name
        or recovery_action.adapter_version != manifest.version
        or recovery_action.adapter_manifest_digest != manifest.digest
        or recovery_action.deadline != binding.absolute_deadline
        or binding_argument.size_bytes != len(binding_bytes)
        or binding_argument.media_type != "application/vnd.agentkernel.canonical+json"
        or binding.target_transaction_id != target_transaction_id
        or binding.target_intent_hash != target_intent_hash
        or (
            target_normalized_action_digest is not None
            and binding.target_normalized_action_digest != target_normalized_action_digest
        )
        or binding.recovery_kind is not recovery_kind
        or binding.target_id != target_id
        or binding.target_evidence_ref != target_evidence_ref
        or binding.target_version_guard != target_version_guard
        or binding.target_owner_version != target_owner_version
        or binding.target_owner_history_sequence != target_owner_history_sequence
        or binding.target_owner_history_digest != target_owner_history_digest
        or binding.adapter_manifest_digest != manifest.digest
        or binding.risk_class is not target_action.risk_floor
        or binding.effect_domains != target_action.effect_domains
        or binding.resource_uses_digest != canonical_digest(target_action.resource_uses)
        or binding.recovery_id != permit.recovery_id
        or permit.issued_at < binding.not_before
        or permit.deadline > binding.absolute_deadline
        or target_action.transaction_id != target_transaction_id
        or target_action.intent_hash != target_intent_hash
        or not same_target_semantics
    ):
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Recovery authority does not bind the exact normalized action and target semantics",
        )
    return recovery_action, binding, target_action


def validate_canonical_artifact(
    value: object,
    artifact_ref: str,
    artifacts: ArtifactReader | None,
    *,
    label: str,
) -> None:
    """Require one referenced artifact to contain exactly ``value`` in AK-CJ-1 bytes."""

    expected = canonical_json_bytes(value)
    if sha256_digest(expected) != artifact_ref:
        raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, f"{label} artifact digest mismatch")
    if artifacts is None:
        raise AgentKernelError(
            ErrorCode.EVIDENCE_UNAVAILABLE,
            "Enforced adapter dispatch requires a read-only artifact store",
        )
    actual = artifacts.get(artifact_ref)
    if actual != expected:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            f"{label} artifact bytes are not the authorized canonical value",
        )


def load_canonical_model_artifact[ArtifactModelT: BaseModel](
    artifact_ref: str,
    model_type: type[ArtifactModelT],
    artifacts: ArtifactReader | None,
    *,
    label: str,
) -> ArtifactModelT:
    """Load and validate a typed model without accepting alternate JSON encodings."""

    if artifacts is None:
        raise AgentKernelError(
            ErrorCode.EVIDENCE_UNAVAILABLE,
            "Enforced adapter dispatch requires a read-only artifact store",
        )
    content = artifacts.get(artifact_ref)
    try:
        model = model_type.model_validate_json(content)
    except ValidationError as error:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            f"{label} artifact has the wrong schema",
        ) from error
    if canonical_json_bytes(model) != content or sha256_digest(content) != artifact_ref:
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            f"{label} artifact is not exact canonical evidence",
        )
    return model


def validate_active_deadline(deadline: datetime) -> None:
    """Fail a worker dispatch after its absolute, timezone-aware deadline."""

    if deadline.tzinfo is None or deadline.utcoffset() is None:
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Adapter deadline must be aware")
    if datetime.now(UTC) >= deadline:
        raise AgentKernelError(ErrorCode.DEADLINE_EXCEEDED, "Adapter permit deadline expired")


def validate_fencing_token(token: int) -> None:
    """Reject bools and non-positive values at the adapter boundary."""

    if type(token) is not int or token <= 0:
        raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Fencing token must be a positive int")


@runtime_checkable
class EffectAdapter(Protocol):
    """The only trusted lifecycle through which an R1+ effect may occur.

    A commit implementation may raise ``STALE_STATE`` only when its target-version guard proves
    that this transaction has not performed an authoritative mutation. Any failure after the
    first possible mutation must use an ambiguous/verification failure so the coordinator can
    persist ``IN_DOUBT`` or recovery-required state.
    """

    manifest: AdapterManifest

    @property
    def requires_permits(self) -> bool: ...

    @property
    def implementation_modules(self) -> tuple[str, ...]: ...

    async def inspect(self, proposal: ActionProposal, ctx: ReadOnlyContext) -> EffectPlan: ...

    async def stage(self, plan: EffectPlan, ctx: StageContext) -> StagedEffect: ...

    async def execute(self, staged: StagedEffect, ctx: StageContext) -> StagedReceipt: ...

    async def verify_staged(
        self, receipt: StagedReceipt, ctx: VerifyContext
    ) -> VerificationReport: ...

    async def commit(self, receipt: StagedReceipt, ctx: CommitContext) -> EffectReceipt: ...

    async def verify_committed(
        self, receipt: EffectReceipt, ctx: VerifyContext
    ) -> VerificationReport: ...

    async def abort(
        self,
        staged: StagedEffect | StagedReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport: ...

    async def abort_stage(self, stage_id: str, ctx: RecoveryContext) -> RecoveryReport: ...

    async def rollback(self, receipt: EffectReceipt, ctx: RecoveryContext) -> RecoveryReport: ...

    async def reconcile(self, intent: IntentRecord, ctx: RecoveryContext) -> ReconcileReport: ...

    async def compensate(self, receipt: EffectReceipt, ctx: RecoveryContext) -> RecoveryReport: ...
