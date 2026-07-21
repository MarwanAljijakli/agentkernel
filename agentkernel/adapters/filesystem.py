"""Snapshot-staged reversible filesystem adapter for the local v1alpha1 profile."""

from __future__ import annotations

import json
import shutil
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from pydantic import JsonValue

from agentkernel.adapters.base import (
    AdapterManifest,
    CommitContext,
    EffectPlan,
    OperationManifest,
    ReadOnlyContext,
    ReconcileReport,
    ReconcileStatus,
    RecoveryContext,
    StageContext,
    StagedEffect,
    StagedReceipt,
    VerifyContext,
)
from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import RiskClass, VerificationStatus
from agentkernel.domain.models import (
    ActionProposal,
    EffectReceipt,
    IntentRecord,
    RecoveryReport,
    StrictModel,
    VerificationReport,
)
from agentkernel.errors import AgentKernelError, ErrorCode, UnsupportedSemantics
from agentkernel.ids import new_id
from agentkernel.snapshots.filesystem import (
    ChangeKind,
    EntryKind,
    diff_snapshots,
    normalize_relative_path,
    portable_path_key,
    resolve_scoped_path,
    snapshot_tree,
)


class _RecoveryManifest(StrictModel):
    status: Literal["PREPARED", "COMMITTED", "ROLLED_BACK"]
    effect_receipt: EffectReceipt
    stage_id: str
    staged_state_digest: str


def _validate_private_directory(path: Path, *, parent: Path) -> Path:
    """Validate one existing private-state directory without following aliases."""

    if (
        not path.is_dir()
        or path.is_symlink()
        or path.is_junction()
        or path.is_mount()
        or path.lstat().st_dev != parent.stat().st_dev
    ):
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Adapter private state contains a linked or foreign directory",
        )
    resolved = path.resolve(strict=True)
    if resolved.parent != parent.resolve(strict=True):
        raise AgentKernelError(
            ErrorCode.INTEGRITY_ERROR,
            "Adapter private state escapes its parent directory",
        )
    return path


def _ensure_private_directory(path: Path, *, parent: Path) -> Path:
    with suppress(FileExistsError):
        path.mkdir()
    return _validate_private_directory(path, parent=parent)


def _remove_private_tree(path: Path) -> None:
    if not path.exists():
        return
    try:
        shutil.rmtree(path)
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


def _copy_scoped_tree(source: Path, destination: Path) -> None:
    """Copy only entries admitted by the snapshot boundary, then verify the copy."""

    expected = snapshot_tree(source)
    destination.mkdir()
    try:
        directory_modes: list[tuple[Path, int]] = []
        for entry in expected.entries:
            target = resolve_scoped_path(destination, entry.path)
            if entry.kind is EntryKind.DIRECTORY:
                target.mkdir(parents=True, exist_ok=False)
                directory_modes.append((target, entry.mode))
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            origin = resolve_scoped_path(source, entry.path)
            shutil.copy2(origin, target)
        for directory, mode in reversed(directory_modes):
            directory.chmod(mode)
        actual = snapshot_tree(destination)
        if actual.digest != expected.digest:
            raise AgentKernelError(
                ErrorCode.STALE_STATE,
                "Filesystem changed while creating a scoped copy",
            )
    except BaseException:
        _remove_private_tree(destination)
        raise


class FilesystemAdapter:
    """Stage writes in a full local tree copy and commit only the verified diff.

    This adapter's declared snapshot covers file content, size, directory presence, and POSIX
    mode bits. It does not claim restoration of ACLs, xattrs, alternate data streams, open-file
    state, or hostile concurrent writers. Recovery state must be outside the workspace on the
    same filesystem device so replacement renames do not cross a device boundary.
    """

    def __init__(self, *, workspace: Path, state_root: Path) -> None:
        if workspace.is_symlink() or workspace.is_junction():
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Workspace root cannot be a symbolic link or junction",
            )
        self._workspace = workspace.resolve(strict=True)
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
        self._state_root.mkdir(parents=True, exist_ok=True)
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
        self._stage_paths: dict[str, Path] = {}
        self._recovery_by_receipt: dict[str, _RecoveryManifest] = {}
        self._recovery_by_intent: dict[str, _RecoveryManifest] = {}
        self.manifest = AdapterManifest(
            name="filesystem",
            version="0.1.0",
            implementation_digest=canonical_digest(
                {"implementation": "FilesystemAdapter", "protocol": "v1alpha1"}
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
                )
            },
        )
        self._load_recovery_manifests()

    def _load_recovery_manifests(self) -> None:
        for directory in sorted(self._recovery_root.iterdir()):
            _validate_private_directory(directory, parent=self._recovery_root)
            path = directory / "manifest.json"
            if not path.exists():
                continue
            try:
                manifest = _RecoveryManifest.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Filesystem recovery metadata is unreadable",
                ) from error
            receipt = manifest.effect_receipt
            if path.parent.name != receipt.receipt_id:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Filesystem recovery metadata is stored under the wrong receipt",
                )
            if receipt.intent_hash in self._recovery_by_intent:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Duplicate durable filesystem intent metadata",
                )
            self._recovery_by_receipt[receipt.receipt_id] = manifest
            self._recovery_by_intent[receipt.intent_hash] = manifest

    def _persist_recovery_manifest(self, manifest: _RecoveryManifest) -> None:
        receipt = manifest.effect_receipt
        directory = self._recovery_root / receipt.receipt_id
        directory = _ensure_private_directory(directory, parent=self._recovery_root)
        target = directory / "manifest.json"
        temporary = directory / "manifest.json.tmp"
        temporary.write_text(
            json.dumps(manifest.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(target)
        self._recovery_by_receipt[receipt.receipt_id] = manifest
        self._recovery_by_intent[receipt.intent_hash] = manifest

    def _stage_path(self, stage_id: str) -> Path | None:
        stage_parent = self._stages_root / stage_id
        if not stage_parent.exists():
            return None
        _validate_private_directory(stage_parent, parent=self._stages_root)
        candidate = self._stage_paths.get(stage_id, stage_parent / "workspace")
        if not candidate.exists():
            return None
        return _validate_private_directory(candidate, parent=stage_parent)

    def _backup_path(self, receipt_id: str) -> Path:
        receipt_directory = _validate_private_directory(
            self._recovery_root / receipt_id,
            parent=self._recovery_root,
        )
        return _validate_private_directory(
            receipt_directory / "backup",
            parent=receipt_directory,
        )

    @property
    def workspace(self) -> Path:
        return self._workspace

    async def inspect(self, proposal: ActionProposal, ctx: ReadOnlyContext) -> EffectPlan:
        del ctx
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
        normalized_files: dict[str, str] = {}
        portable_paths: dict[str, str] = {}
        for raw_path, content in files_input.items():
            normalized = normalize_relative_path(raw_path)
            resolve_scoped_path(self._workspace, normalized)
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
        base = snapshot_tree(self._workspace)
        intent_hash = canonical_digest(
            {
                "operation": proposal.operation,
                "canonical_resource": "fs://workspace/**",
                "semantic_arguments": {"files": normalized_files},
                "goal": proposal.goal_id,
                "principal": proposal.agent_id,
                "adapter_protocol_version": self.manifest.version,
            }
        )
        return EffectPlan(
            plan_id=new_id("plan"),
            proposal=proposal,
            canonical_resource="fs://workspace/**",
            base_version=base.digest,
            intent_hash=intent_hash,
            risk_class=RiskClass.REVERSIBLE,
            effect_domains=("filesystem",),
            semantic_arguments={"files": cast("dict[str, JsonValue]", normalized_files)},
        )

    async def stage(self, plan: EffectPlan, ctx: StageContext) -> StagedEffect:
        del ctx
        stage_id = new_id("stage")
        stage_parent = self._stages_root / stage_id
        stage_parent = _ensure_private_directory(stage_parent, parent=self._stages_root)
        stage_path = stage_parent / "workspace"
        try:
            _copy_scoped_tree(self._workspace, stage_path)
        except BaseException as error:
            try:
                _remove_private_tree(stage_parent)
            except AgentKernelError as cleanup_error:
                raise cleanup_error from error
            if isinstance(error, AgentKernelError) and error.code is ErrorCode.ROLLBACK_FAILED:
                raise AgentKernelError(
                    ErrorCode.EXECUTION_FAILED,
                    "Stage creation failed after verified cleanup",
                ) from error
            raise
        staged = StagedEffect(
            stage_id=stage_id,
            plan=plan,
            base_state_digest=plan.base_version,
            private_state={"stage_token": stage_parent.name},
        )
        self._stage_paths[staged.stage_id] = stage_path
        return staged

    async def execute(self, staged: StagedEffect, ctx: StageContext) -> StagedReceipt:
        del ctx
        stage_path = self._stage_path(staged.stage_id)
        if stage_path is None:
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Unknown filesystem stage")
        files = cast("dict[str, str]", staged.plan.semantic_arguments["files"])
        for relative, content in files.items():
            target = resolve_scoped_path(stage_path, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(f".{target.name}.{new_id('tmp')}")
            temporary.write_text(content, encoding="utf-8", newline="\n")
            temporary.replace(target)
        snapshot = snapshot_tree(stage_path)
        return StagedReceipt(
            receipt_id=new_id("staged"),
            staged=staged,
            staged_state_digest=snapshot.digest,
            private_state={"stage_token": stage_path.parent.name},
        )

    async def verify_staged(self, receipt: StagedReceipt, ctx: VerifyContext) -> VerificationReport:
        del ctx
        stage_path = self._stage_path(receipt.staged.stage_id)
        if stage_path is None:
            return VerificationReport(
                status=VerificationStatus.UNKNOWN,
                verifier="adapter.filesystem.staged",
                summary="Staging tree is unavailable",
            )
        actual = snapshot_tree(stage_path)
        status = (
            VerificationStatus.PASS
            if actual.digest == receipt.staged_state_digest
            else VerificationStatus.FAIL
        )
        return VerificationReport(
            status=status,
            verifier="adapter.filesystem.staged",
            summary="Staged workspace digest matches the receipt",
        )

    def _restore_backup(self, backup: Path) -> None:
        replacement_parent = Path(tempfile.mkdtemp(prefix="restore-", dir=self._state_root))
        replacement = replacement_parent / "workspace"
        _copy_scoped_tree(backup, replacement)
        displaced = self._state_root / new_id("displaced")
        self._workspace.rename(displaced)
        try:
            replacement.rename(self._workspace)
        except BaseException:
            displaced.rename(self._workspace)
            raise
        shutil.rmtree(displaced)
        shutil.rmtree(replacement_parent, ignore_errors=True)

    async def commit(self, receipt: StagedReceipt, ctx: CommitContext) -> EffectReceipt:
        existing_manifest = self._recovery_by_intent.get(receipt.staged.plan.intent_hash)
        if existing_manifest is not None:
            existing = existing_manifest.effect_receipt
            actual = snapshot_tree(self._workspace).digest
            if actual == existing.target_version_after:
                return existing
            if actual != existing.target_version_before:
                raise AgentKernelError(
                    ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                    "Workspace differs from both durable pre-commit and committed states",
                    reconcilable=True,
                    review_required=True,
                )
        if ctx.target_version_guard != receipt.staged.plan.base_version:
            raise AgentKernelError(ErrorCode.STALE_STATE, "Commit guard differs from staged base")
        current = snapshot_tree(self._workspace)
        if current.digest != receipt.staged.plan.base_version:
            raise AgentKernelError(ErrorCode.STALE_STATE, "Authoritative workspace changed")
        stage_path = self._stage_path(receipt.staged.stage_id)
        if stage_path is None:
            raise AgentKernelError(ErrorCode.INTEGRITY_ERROR, "Staging tree is unavailable")
        staged = snapshot_tree(stage_path)
        if staged.digest != receipt.staged_state_digest:
            raise AgentKernelError(
                ErrorCode.VERIFICATION_FAILED, "Staging tree changed after verify"
            )
        diff = diff_snapshots(current, staged)
        if existing_manifest is None:
            receipt_id = new_id("receipt")
            recovery_directory = self._recovery_root / receipt_id
            recovery_directory = _ensure_private_directory(
                recovery_directory,
                parent=self._recovery_root,
            )
            backup = recovery_directory / "backup"
            try:
                _copy_scoped_tree(self._workspace, backup)
            except BaseException:
                recovery_directory.rmdir()
                raise
            effect_receipt = EffectReceipt(
                receipt_id=receipt_id,
                transaction_id=receipt.staged.plan.proposal.transaction_id,
                adapter=self.manifest.name,
                operation=receipt.staged.plan.proposal.operation,
                intent_hash=receipt.staged.plan.intent_hash,
                target_version_before=current.digest,
                target_version_after=staged.digest,
                effect_digest=diff.digest,
                created_at=datetime.now(UTC),
            )
            manifest = _RecoveryManifest(
                status="PREPARED",
                effect_receipt=effect_receipt,
                stage_id=receipt.staged.stage_id,
                staged_state_digest=receipt.staged_state_digest,
            )
            self._persist_recovery_manifest(manifest)
        else:
            manifest = existing_manifest
            effect_receipt = manifest.effect_receipt
            try:
                backup = self._backup_path(effect_receipt.receipt_id)
            except AgentKernelError:
                raise AgentKernelError(
                    ErrorCode.INTEGRITY_ERROR,
                    "Durable pre-commit metadata is missing its backup",
                ) from None
        try:
            for change in diff.changes:
                if change.kind is ChangeKind.DELETED:
                    continue
                if change.after is None or change.after.kind is EntryKind.DIRECTORY:
                    continue
                source = resolve_scoped_path(stage_path, change.path)
                target = resolve_scoped_path(self._workspace, change.path)
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = target.with_name(f".{target.name}.{new_id('tmp')}")
                shutil.copy2(source, temporary)
                temporary.replace(target)
        except BaseException:
            self._restore_backup(backup)
            self._persist_recovery_manifest(manifest.model_copy(update={"status": "ROLLED_BACK"}))
            raise
        final = snapshot_tree(self._workspace)
        if final.digest != staged.digest:
            self._restore_backup(backup)
            self._persist_recovery_manifest(manifest.model_copy(update={"status": "ROLLED_BACK"}))
            raise AgentKernelError(
                ErrorCode.VERIFICATION_FAILED,
                "Committed workspace does not match the staged workspace",
            )
        manifest = manifest.model_copy(update={"status": "COMMITTED"})
        self._persist_recovery_manifest(manifest)
        try:
            _remove_private_tree(stage_path.parent)
        except AgentKernelError as error:
            raise AgentKernelError(
                ErrorCode.EXTERNAL_RESULT_IN_DOUBT,
                "Effect committed but verified staging cleanup failed",
                reconcilable=True,
                review_required=True,
            ) from error
        self._stage_paths.pop(receipt.staged.stage_id, None)
        return effect_receipt

    async def verify_committed(
        self, receipt: EffectReceipt, ctx: VerifyContext
    ) -> VerificationReport:
        del ctx
        manifest = self._recovery_by_receipt.get(receipt.receipt_id)
        actual = snapshot_tree(self._workspace).digest
        status = (
            VerificationStatus.PASS
            if manifest is not None
            and manifest.effect_receipt == receipt
            and actual == receipt.target_version_after
            else VerificationStatus.FAIL
        )
        return VerificationReport(
            status=status,
            verifier="adapter.filesystem.committed",
            summary="Authoritative workspace matches the committed staged digest",
        )

    async def abort(
        self,
        staged: StagedEffect | StagedReceipt,
        ctx: RecoveryContext,
    ) -> RecoveryReport:
        del ctx
        stage_id = staged.staged.stage_id if isinstance(staged, StagedReceipt) else staged.stage_id
        stage_path = self._stage_paths.pop(stage_id, None)
        if stage_path is None:
            stage_path = self._stage_path(stage_id)
        if stage_path is not None:
            try:
                _remove_private_tree(stage_path.parent)
            except AgentKernelError:
                return RecoveryReport(
                    status=VerificationStatus.ERROR,
                    strategy="discard_staged_tree",
                    restored_state_digest=snapshot_tree(self._workspace).digest,
                    residual_effects=("staging_tree_cleanup_failed",),
                )
        return RecoveryReport(
            status=VerificationStatus.PASS,
            strategy="discard_staged_tree",
            restored_state_digest=snapshot_tree(self._workspace).digest,
        )

    async def rollback(self, receipt: EffectReceipt, ctx: RecoveryContext) -> RecoveryReport:
        del ctx
        manifest = self._recovery_by_receipt.get(receipt.receipt_id)
        try:
            backup = self._backup_path(receipt.receipt_id)
        except AgentKernelError:
            backup = None
        if manifest is None or manifest.effect_receipt != receipt or backup is None:
            return RecoveryReport(
                status=VerificationStatus.UNKNOWN,
                strategy="restore_complete_tree_snapshot",
                residual_effects=("missing_backup",),
            )
        current = snapshot_tree(self._workspace).digest
        if current != receipt.target_version_after:
            return RecoveryReport(
                status=VerificationStatus.UNKNOWN,
                strategy="restore_complete_tree_snapshot",
                restored_state_digest=current,
                residual_effects=("target_version_changed_after_commit",),
            )
        expected = snapshot_tree(backup).digest
        if expected != receipt.target_version_before:
            return RecoveryReport(
                status=VerificationStatus.ERROR,
                strategy="restore_complete_tree_snapshot",
                restored_state_digest=current,
                residual_effects=("backup_integrity_mismatch",),
            )
        self._restore_backup(backup)
        actual = snapshot_tree(self._workspace).digest
        self._persist_recovery_manifest(manifest.model_copy(update={"status": "ROLLED_BACK"}))
        return RecoveryReport(
            status=(VerificationStatus.PASS if actual == expected else VerificationStatus.FAIL),
            strategy="restore_complete_tree_snapshot",
            restored_state_digest=actual,
        )

    async def reconcile(self, intent: IntentRecord, ctx: ReadOnlyContext) -> ReconcileReport:
        del ctx
        manifest = self._recovery_by_intent.get(intent.intent_hash)
        if manifest is None:
            return ReconcileReport(status=ReconcileStatus.NO_EFFECT)
        receipt = manifest.effect_receipt
        actual = snapshot_tree(self._workspace).digest
        if actual == receipt.target_version_after:
            return ReconcileReport(status=ReconcileStatus.COMMITTED, receipt=receipt)
        if actual == receipt.target_version_before:
            return ReconcileReport(status=ReconcileStatus.NO_EFFECT, receipt=receipt)
        return ReconcileReport(status=ReconcileStatus.PARTIAL_OR_INVALID, receipt=receipt)

    async def compensate(self, receipt: EffectReceipt, ctx: RecoveryContext) -> RecoveryReport:
        del receipt, ctx
        raise UnsupportedSemantics("compensate")
