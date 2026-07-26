"""Capture and verify cross-platform coverage evidence before union reporting."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from coverage import Coverage, CoverageData
from coverage.exceptions import CoverageException
from coverage.results import should_fail_under

SCHEMA_VERSION = 3
MANIFEST_NAME = "coverage-evidence.json"
SOURCE_SNAPSHOT_NAME = "source-snapshot.json"
SOURCE_SNAPSHOT_SCHEMA_VERSION = 1
ROOT_EXECUTION_CONTROLS = (
    ".coveragerc",
    "conftest.py",
    "pytest.ini",
    "setup.cfg",
    "sitecustomize.py",
    "tox.ini",
    "usercustomize.py",
)
SNAPSHOT_EXCLUDED_FILES = frozenset(
    {
        ".coverage",
        "coverage.xml",
    }
)
SNAPSHOT_EXCLUDED_ROOTS = frozenset(
    {
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "htmlcov",
        "test-results",
    }
)
UNION_ONLY_EXCLUDED_ROOT = "downloaded-coverage"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SOURCE_SNAPSHOT_BYTES = 64 * 1024
MAX_COVERAGE_BYTES = 128 * 1024 * 1024
_LANE_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,30}[a-z0-9])?")
_COMMIT_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_WORKFLOW_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_MANIFEST_KEYS = {
    "schema_version",
    "lane",
    "commit_sha",
    "workflow_run_id",
    "workflow_run_attempt",
    "source_digest",
    "source_file_count",
    "source_snapshot_file",
    "source_snapshot_sha256",
    "coverage_file",
    "coverage_sha256",
    "coverage_bytes",
    "coverage_has_arcs",
    "coverage_measured_file_count",
    "coverage_arc_count",
    "test_scope",
}
_SOURCE_SNAPSHOT_KEYS = {
    "schema_version",
    "lane",
    "commit_sha",
    "workflow_run_id",
    "workflow_run_attempt",
    "source_digest",
    "source_file_count",
}


class CoverageEvidenceError(ValueError):
    """Raised when coverage evidence is unsafe, malformed, stale, or mismatched."""


@dataclass(frozen=True)
class _LoadedSourceSnapshot:
    lane: str
    commit_sha: str
    workflow_run_id: str
    workflow_run_attempt: str
    source_digest: str
    source_file_count: int
    raw: bytes


def _validate_identifier(value: str, pattern: re.Pattern[str], label: str) -> str:
    if pattern.fullmatch(value) is None:
        raise CoverageEvidenceError(f"invalid {label}")
    return value


def _validate_positive_integer_text(value: str, label: str) -> str:
    if not value.isascii() or not value.isdecimal() or int(value) < 1:
        raise CoverageEvidenceError(f"invalid {label}")
    return value


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _absolute_path(path: Path) -> Path:
    # ``resolve`` would follow a malicious final symlink before the later lstat check.
    candidate = path if path.is_absolute() else Path.cwd() / path
    normalized_parts: list[str] = []
    for component in candidate.parts:
        if component == candidate.anchor or component in {"", "."}:
            continue
        if component == "..":
            if not normalized_parts:
                raise CoverageEvidenceError("path escapes its filesystem root")
            normalized_parts.pop()
            continue
        normalized_parts.append(component)
    return Path(candidate.anchor, *normalized_parts)


def _lstat_or_none(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CoverageEvidenceError(f"path could not be inspected safely: {path.name}") from exc


def _repo_child_path(repo_root: Path, path: Path, label: str) -> Path:
    target = _absolute_path(path)
    if target == repo_root or not target.is_relative_to(repo_root):
        raise CoverageEvidenceError(f"{label} must be a child of the repository")
    current = repo_root
    for component in target.relative_to(repo_root).parts[:-1]:
        current /= component
        metadata = _lstat_or_none(current)
        if metadata is None:
            break
        if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
            raise CoverageEvidenceError(f"{label} has a non-regular parent directory")
    return target


def _regular_file_bytes(path: Path, *, maximum_bytes: int | None = None) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise CoverageEvidenceError(f"required regular file is unavailable: {path.name}") from exc
    if not stat.S_ISREG(before.st_mode) or _is_reparse_point(before):
        raise CoverageEvidenceError(f"non-regular or linked file rejected: {path.name}")
    if maximum_bytes is not None and before.st_size > maximum_bytes:
        raise CoverageEvidenceError(f"file exceeds allowed size: {path.name}")

    try:
        contents = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise CoverageEvidenceError(f"file could not be read safely: {path.name}") from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise CoverageEvidenceError(f"file changed while it was read: {path.name}")
    if len(contents) != before.st_size:
        raise CoverageEvidenceError(f"file size changed while it was read: {path.name}")
    return contents


def _digest_bytes(contents: bytes) -> str:
    return f"sha256:{hashlib.sha256(contents).hexdigest()}"


def _run_git(repo_root: Path, args: Sequence[str], *, stdin: bytes | None = None) -> bytes:
    git_executable = shutil.which("git")
    if git_executable is None:
        raise CoverageEvidenceError("Git is required to bind coverage evidence")
    try:
        result = subprocess.run(  # noqa: S603 - fixed Git binary with internal arguments only.
            [git_executable, "-C", os.fspath(repo_root), *args],
            input=stdin,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise CoverageEvidenceError("Git is required to bind coverage evidence") from exc
    if result.returncode != 0:
        raise CoverageEvidenceError("repository Git metadata is unavailable")
    return result.stdout


def repository_head(repo_root: Path) -> str:
    """Return the repository's exact checked-out commit."""

    raw = _run_git(repo_root, ["rev-parse", "--verify", "HEAD"])
    try:
        head = raw.decode("ascii").strip().lower()
    except UnicodeDecodeError as exc:
        raise CoverageEvidenceError("repository HEAD is not a valid commit SHA") from exc
    return _validate_identifier(head, _COMMIT_PATTERN, "repository HEAD")


def validate_run_context(
    *,
    repo_root: Path,
    lane: str,
    commit_sha: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> tuple[str, str, str, str]:
    """Validate lane identifiers and bind the declared commit to Git HEAD."""

    root = repo_root.resolve(strict=True)
    validated_lane = _validate_identifier(lane, _LANE_PATTERN, "lane")
    validated_commit = _validate_identifier(commit_sha.lower(), _COMMIT_PATTERN, "commit SHA")
    validated_run = _validate_identifier(workflow_run_id, _WORKFLOW_ID_PATTERN, "workflow run ID")
    validated_attempt = _validate_positive_integer_text(
        workflow_run_attempt, "workflow run attempt"
    )
    if repository_head(root) != validated_commit:
        raise CoverageEvidenceError("declared commit SHA does not match repository HEAD")
    return validated_lane, validated_commit, validated_run, validated_attempt


def _decode_git_paths(raw: bytes) -> set[str]:
    paths: set[str] = set()
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        relative = os.fsdecode(encoded).replace("\\", "/")
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts or relative in {"", "."}:
            raise CoverageEvidenceError("Git returned an unsafe source path")
        paths.add(relative)
    return paths


def _snapshot_path_is_excluded(relative: str, *, for_union: bool) -> bool:
    if relative in SNAPSHOT_EXCLUDED_FILES:
        return True
    root_component, separator, _remainder = relative.partition("/")
    if separator and root_component in SNAPSHOT_EXCLUDED_ROOTS:
        return True
    return bool(separator and for_union and root_component == UNION_ONLY_EXCLUDED_ROOT)


def _source_files(repo_root: Path, *, for_union: bool = False) -> list[Path]:
    tracked = _decode_git_paths(_run_git(repo_root, ["ls-files", "-z", "--cached"]))
    untracked = _decode_git_paths(
        _run_git(repo_root, ["ls-files", "-z", "--others", "--exclude-standard"])
    )
    relative_paths = {
        relative
        for relative in tracked | untracked
        if not _snapshot_path_is_excluded(relative, for_union=for_union)
    }
    # These root-level files can execute code or alter test/coverage behavior. A local,
    # untracked .git/info/exclude entry must not make them invisible to release evidence.
    for relative in ROOT_EXECUTION_CONTROLS:
        if _lstat_or_none(repo_root / relative) is not None:
            relative_paths.add(relative)
    if not relative_paths:
        raise CoverageEvidenceError("source snapshot contains no repository files")

    files: list[Path] = []
    for relative in sorted(relative_paths):
        path = _repo_child_path(repo_root, repo_root / Path(relative), "source snapshot entry")
        metadata = _lstat_or_none(path)
        if metadata is None:
            raise CoverageEvidenceError(f"tracked source file is unavailable: {relative}")
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(metadata):
            raise CoverageEvidenceError(f"non-regular source file rejected: {relative}")
        files.append(path)
    return files


def _git_blob_digest(repo_root: Path, relative: str, contents: bytes) -> str:
    raw = _run_git(
        repo_root,
        ["hash-object", "--filters", "--stdin", f"--path={relative}"],
        stdin=contents,
    )
    try:
        object_id = raw.decode("ascii").strip().lower()
    except UnicodeDecodeError as exc:
        raise CoverageEvidenceError("Git returned an invalid source object ID") from exc
    return _validate_identifier(object_id, _COMMIT_PATTERN, "source object ID")


def compute_source_snapshot(repo_root: Path, *, for_union: bool = False) -> tuple[str, int]:
    """Digest tracked and repository-wide non-ignored files using Git clean filters."""

    root = repo_root.resolve(strict=True)
    records: list[dict[str, object]] = []
    for path in _source_files(root, for_union=for_union):
        contents = _regular_file_bytes(path)
        relative = path.relative_to(root).as_posix()
        records.append(
            {
                "path": relative,
                "git_blob": _git_blob_digest(root, relative, contents),
            }
        )
    canonical = json.dumps(
        {"schema_version": SCHEMA_VERSION, "files": records},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _digest_bytes(canonical), len(records)


def _load_source_snapshot(path: Path) -> _LoadedSourceSnapshot:
    raw = _regular_file_bytes(path, maximum_bytes=MAX_SOURCE_SNAPSHOT_BYTES)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CoverageEvidenceError("source snapshot is not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != _SOURCE_SNAPSHOT_KEYS:
        raise CoverageEvidenceError("source snapshot fields are not exact")
    record = cast("dict[str, object]", value)
    canonical = (
        json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")
    if raw != canonical:
        raise CoverageEvidenceError("source snapshot is not canonical")

    schema_version = record["schema_version"]
    source_file_count = record["source_file_count"]
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != SOURCE_SNAPSHOT_SCHEMA_VERSION
    ):
        raise CoverageEvidenceError("unsupported source snapshot schema")
    if (
        isinstance(source_file_count, bool)
        or not isinstance(source_file_count, int)
        or source_file_count < 1
    ):
        raise CoverageEvidenceError("source snapshot file count is invalid")

    string_values: dict[str, str] = {}
    for key in (
        "lane",
        "commit_sha",
        "workflow_run_id",
        "workflow_run_attempt",
        "source_digest",
    ):
        candidate = record[key]
        if not isinstance(candidate, str):
            raise CoverageEvidenceError(f"source snapshot field is not a string: {key}")
        string_values[key] = candidate

    return _LoadedSourceSnapshot(
        lane=_validate_identifier(string_values["lane"], _LANE_PATTERN, "lane"),
        commit_sha=_validate_identifier(string_values["commit_sha"], _COMMIT_PATTERN, "commit SHA"),
        workflow_run_id=_validate_identifier(
            string_values["workflow_run_id"],
            _WORKFLOW_ID_PATTERN,
            "workflow run ID",
        ),
        workflow_run_attempt=_validate_positive_integer_text(
            string_values["workflow_run_attempt"], "workflow run attempt"
        ),
        source_digest=_validate_identifier(
            string_values["source_digest"], _DIGEST_PATTERN, "source digest"
        ),
        source_file_count=source_file_count,
        raw=raw,
    )


def _require_snapshot_context(
    snapshot: _LoadedSourceSnapshot,
    *,
    lane: str,
    commit_sha: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> None:
    if snapshot.lane != lane:
        raise CoverageEvidenceError("source snapshot lane mismatch")
    if snapshot.commit_sha != commit_sha:
        raise CoverageEvidenceError("source snapshot commit SHA mismatch")
    if snapshot.workflow_run_id != workflow_run_id:
        raise CoverageEvidenceError("source snapshot workflow run ID mismatch")
    if snapshot.workflow_run_attempt != workflow_run_attempt:
        raise CoverageEvidenceError("source snapshot workflow run attempt mismatch")


def _require_source_snapshot_path(
    repo_root: Path,
    path: Path,
    *,
    lane: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    label: str,
) -> Path:
    target = _repo_child_path(repo_root, path, label)
    expected = (
        repo_root
        / "test-results"
        / "coverage-raw"
        / lane
        / f"run-{workflow_run_id}-attempt-{workflow_run_attempt}"
        / SOURCE_SNAPSHOT_NAME
    )
    if target != expected:
        raise CoverageEvidenceError(f"{label} path is not canonical for this run")
    return target


def record_source_snapshot(
    *,
    repo_root: Path,
    output_file: Path,
    lane: str,
    commit_sha: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> str:
    """Persist a run-bound source snapshot and return its complete checksum."""

    lane, commit_sha, workflow_run_id, workflow_run_attempt = validate_run_context(
        repo_root=repo_root,
        lane=lane,
        commit_sha=commit_sha,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
    )
    root = repo_root.resolve(strict=True)
    destination = _require_source_snapshot_path(
        root,
        output_file,
        lane=lane,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        label="source snapshot output",
    )
    if _lstat_or_none(destination) is not None:
        raise CoverageEvidenceError("source snapshot output must be absent")
    source_digest, source_file_count = compute_source_snapshot(root)
    record: dict[str, object] = {
        "schema_version": SOURCE_SNAPSHOT_SCHEMA_VERSION,
        "lane": lane,
        "commit_sha": commit_sha,
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "source_digest": source_digest,
        "source_file_count": source_file_count,
    }

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        if _lstat_or_none(temporary) is not None:
            raise CoverageEvidenceError("temporary source snapshot output already exists")
        _write_canonical_json(temporary, record)
        loaded = _load_source_snapshot(temporary)
        _require_snapshot_context(
            loaded,
            lane=lane,
            commit_sha=commit_sha,
            workflow_run_id=workflow_run_id,
            workflow_run_attempt=workflow_run_attempt,
        )
        temporary.replace(destination)
    except BaseException:
        if _lstat_or_none(temporary) is not None:
            temporary.unlink()
        raise
    return _digest_bytes(loaded.raw)


def _coverage_filename(lane: str) -> str:
    return f".coverage.{lane}"


def _inspect_coverage_data(contents: bytes, lane: str) -> tuple[int, int]:
    try:
        with tempfile.TemporaryDirectory(prefix="agentkernel-coverage-validate-") as temporary:
            data_path = Path(temporary) / ".coverage"
            data_path.write_bytes(contents)
            data = CoverageData(basename=os.fspath(data_path))
            data.read()
            has_arcs = data.has_arcs()
            measured_files = sorted(data.measured_files())
            arc_count = sum(len(data.arcs(filename) or ()) for filename in measured_files)
    except (CoverageException, OSError, ValueError) as exc:
        raise CoverageEvidenceError(f"coverage data is unreadable for lane {lane}") from exc
    if not has_arcs:
        raise CoverageEvidenceError(f"coverage data does not contain branch arcs for lane {lane}")
    if not measured_files:
        raise CoverageEvidenceError(f"coverage data has no measured files for lane {lane}")
    if arc_count < 1:
        raise CoverageEvidenceError(f"coverage data has no recorded arcs for lane {lane}")
    return len(measured_files), arc_count


def _write_canonical_json(path: Path, value: dict[str, object]) -> None:
    contents = (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")
    path.write_bytes(contents)


def capture_evidence(
    *,
    repo_root: Path,
    coverage_file: Path,
    source_snapshot_file: Path,
    expected_source_snapshot_sha256: str,
    output_dir: Path,
    lane: str,
    commit_sha: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
) -> Path:
    """Copy a successful lane's coverage data into a self-verifying evidence directory."""

    lane, commit_sha, workflow_run_id, workflow_run_attempt = validate_run_context(
        repo_root=repo_root,
        lane=lane,
        commit_sha=commit_sha,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
    )
    root = repo_root.resolve(strict=True)
    expected_snapshot_checksum = _validate_identifier(
        expected_source_snapshot_sha256,
        _DIGEST_PATTERN,
        "expected source snapshot checksum",
    )
    source_snapshot = _load_source_snapshot(
        _require_source_snapshot_path(
            root,
            source_snapshot_file,
            lane=lane,
            workflow_run_id=workflow_run_id,
            workflow_run_attempt=workflow_run_attempt,
            label="source snapshot input",
        )
    )
    if _digest_bytes(source_snapshot.raw) != expected_snapshot_checksum:
        raise CoverageEvidenceError("source snapshot checksum does not match parent-held value")
    _require_snapshot_context(
        source_snapshot,
        lane=lane,
        commit_sha=commit_sha,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
    )
    source_digest, source_file_count = compute_source_snapshot(root)
    if (
        source_digest != source_snapshot.source_digest
        or source_file_count != source_snapshot.source_file_count
    ):
        raise CoverageEvidenceError("source changed between pre-test snapshot and coverage capture")

    raw_coverage = _regular_file_bytes(
        _repo_child_path(root, coverage_file, "coverage data"),
        maximum_bytes=MAX_COVERAGE_BYTES,
    )
    if not raw_coverage:
        raise CoverageEvidenceError("coverage data must not be empty")
    measured_file_count, arc_count = _inspect_coverage_data(raw_coverage, lane)
    coverage_sha256 = _digest_bytes(raw_coverage)
    evidence_filename = _coverage_filename(lane)

    destination = _repo_child_path(root, output_dir, "coverage evidence output")
    if _lstat_or_none(destination) is not None:
        raise CoverageEvidenceError("coverage evidence output must be absent before capture")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".coverage-evidence-", dir=str(destination.parent)))
    try:
        coverage_destination = temporary / evidence_filename
        coverage_destination.write_bytes(raw_coverage)
        if _digest_bytes(_regular_file_bytes(coverage_destination)) != coverage_sha256:
            raise CoverageEvidenceError("copied coverage checksum mismatch")
        snapshot_destination = temporary / SOURCE_SNAPSHOT_NAME
        snapshot_destination.write_bytes(source_snapshot.raw)
        if _digest_bytes(_regular_file_bytes(snapshot_destination)) != expected_snapshot_checksum:
            raise CoverageEvidenceError("copied source snapshot checksum mismatch")
        manifest: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "lane": lane,
            "commit_sha": commit_sha,
            "workflow_run_id": workflow_run_id,
            "workflow_run_attempt": workflow_run_attempt,
            "source_digest": source_digest,
            "source_file_count": source_file_count,
            "source_snapshot_file": SOURCE_SNAPSHOT_NAME,
            "source_snapshot_sha256": expected_snapshot_checksum,
            "coverage_file": evidence_filename,
            "coverage_sha256": coverage_sha256,
            "coverage_bytes": len(raw_coverage),
            "coverage_has_arcs": True,
            "coverage_measured_file_count": measured_file_count,
            "coverage_arc_count": arc_count,
            "test_scope": "tests",
        }
        _write_canonical_json(temporary / MANIFEST_NAME, manifest)
        validate_run_context(
            repo_root=root,
            lane=lane,
            commit_sha=commit_sha,
            workflow_run_id=workflow_run_id,
            workflow_run_attempt=workflow_run_attempt,
        )
        final_source_digest, final_source_file_count = compute_source_snapshot(root)
        if final_source_digest != source_digest or final_source_file_count != source_file_count:
            raise CoverageEvidenceError(
                "source changed between pre-test snapshot and coverage capture"
            )
        temporary.replace(destination)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    return destination / MANIFEST_NAME


def _load_manifest(evidence_dir: Path) -> dict[str, object]:
    raw = _regular_file_bytes(evidence_dir / MANIFEST_NAME, maximum_bytes=MAX_MANIFEST_BYTES)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CoverageEvidenceError("coverage evidence manifest is not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != _MANIFEST_KEYS:
        raise CoverageEvidenceError("coverage evidence manifest fields are not exact")
    manifest = cast("dict[str, object]", value)
    canonical = (
        json.dumps(manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")
    if raw != canonical:
        raise CoverageEvidenceError("coverage evidence manifest is not canonical")
    return manifest


def _required_string(manifest: dict[str, object], key: str) -> str:
    value = manifest[key]
    if not isinstance(value, str):
        raise CoverageEvidenceError(f"manifest field is not a string: {key}")
    return value


def _required_integer(manifest: dict[str, object], key: str) -> int:
    value = manifest[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CoverageEvidenceError(f"manifest field is not a non-negative integer: {key}")
    return value


def _required_bool(manifest: dict[str, object], key: str) -> bool:
    value = manifest[key]
    if not isinstance(value, bool):
        raise CoverageEvidenceError(f"manifest field is not a boolean: {key}")
    return value


def _verify_manifest(
    *,
    repo_root: Path,
    evidence_dir: Path,
    expected_commit_sha: str,
    expected_workflow_run_id: str,
    expected_workflow_run_attempt: str,
    expected_source_digest: str,
    expected_source_file_count: int,
) -> tuple[str, str, bytes]:
    directory = _repo_child_path(repo_root, evidence_dir, "coverage evidence input")
    directory_metadata = _lstat_or_none(directory)
    if (
        directory_metadata is None
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or _is_reparse_point(directory_metadata)
    ):
        raise CoverageEvidenceError("coverage evidence input must be a regular directory")
    manifest = _load_manifest(directory)
    if _required_integer(manifest, "schema_version") != SCHEMA_VERSION:
        raise CoverageEvidenceError("unsupported coverage evidence schema")
    if _required_string(manifest, "test_scope") != "tests":
        raise CoverageEvidenceError("coverage evidence does not represent the full test scope")

    lane = _validate_identifier(_required_string(manifest, "lane"), _LANE_PATTERN, "lane")
    commit_sha = _validate_identifier(
        _required_string(manifest, "commit_sha"), _COMMIT_PATTERN, "commit SHA"
    )
    workflow_run_id = _validate_identifier(
        _required_string(manifest, "workflow_run_id"),
        _WORKFLOW_ID_PATTERN,
        "workflow run ID",
    )
    workflow_run_attempt = _validate_positive_integer_text(
        _required_string(manifest, "workflow_run_attempt"), "workflow run attempt"
    )
    source_digest = _validate_identifier(
        _required_string(manifest, "source_digest"), _DIGEST_PATTERN, "source digest"
    )
    coverage_sha256 = _validate_identifier(
        _required_string(manifest, "coverage_sha256"), _DIGEST_PATTERN, "coverage checksum"
    )
    source_snapshot_sha256 = _validate_identifier(
        _required_string(manifest, "source_snapshot_sha256"),
        _DIGEST_PATTERN,
        "source snapshot checksum",
    )
    source_file_count = _required_integer(manifest, "source_file_count")
    coverage_bytes = _required_integer(manifest, "coverage_bytes")
    coverage_has_arcs = _required_bool(manifest, "coverage_has_arcs")
    coverage_measured_file_count = _required_integer(manifest, "coverage_measured_file_count")
    coverage_arc_count = _required_integer(manifest, "coverage_arc_count")
    if coverage_bytes < 1:
        raise CoverageEvidenceError(f"coverage data is empty for lane {lane}")
    if not coverage_has_arcs or coverage_measured_file_count < 1 or coverage_arc_count < 1:
        raise CoverageEvidenceError(f"coverage metadata is empty for lane {lane}")

    if commit_sha != expected_commit_sha:
        raise CoverageEvidenceError(f"commit SHA mismatch for lane {lane}")
    if workflow_run_id != expected_workflow_run_id:
        raise CoverageEvidenceError(f"workflow run ID mismatch for lane {lane}")
    if workflow_run_attempt != expected_workflow_run_attempt:
        raise CoverageEvidenceError(f"workflow run attempt mismatch for lane {lane}")
    if source_digest != expected_source_digest or source_file_count != expected_source_file_count:
        raise CoverageEvidenceError(f"source snapshot mismatch for lane {lane}")

    source_snapshot_filename = _required_string(manifest, "source_snapshot_file")
    if source_snapshot_filename != SOURCE_SNAPSHOT_NAME:
        raise CoverageEvidenceError(f"unsafe source snapshot filename for lane {lane}")
    source_snapshot = _load_source_snapshot(directory / source_snapshot_filename)
    _require_snapshot_context(
        source_snapshot,
        lane=lane,
        commit_sha=commit_sha,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
    )
    if (
        source_snapshot.source_digest != source_digest
        or source_snapshot.source_file_count != source_file_count
    ):
        raise CoverageEvidenceError(f"source snapshot manifest mismatch for lane {lane}")
    if _digest_bytes(source_snapshot.raw) != source_snapshot_sha256:
        raise CoverageEvidenceError(f"source snapshot checksum mismatch for lane {lane}")

    coverage_filename = _required_string(manifest, "coverage_file")
    expected_filename = _coverage_filename(lane)
    if coverage_filename != expected_filename or Path(coverage_filename).name != coverage_filename:
        raise CoverageEvidenceError(f"unsafe or non-canonical coverage filename for lane {lane}")

    expected_entries = {MANIFEST_NAME, source_snapshot_filename, coverage_filename}
    actual_entries = {entry.name for entry in directory.iterdir()}
    if actual_entries != expected_entries:
        raise CoverageEvidenceError(
            f"coverage evidence directory has unexpected entries for {lane}"
        )
    coverage_contents = _regular_file_bytes(
        directory / coverage_filename, maximum_bytes=MAX_COVERAGE_BYTES
    )
    if len(coverage_contents) != coverage_bytes:
        raise CoverageEvidenceError(f"coverage byte count mismatch for lane {lane}")
    if _digest_bytes(coverage_contents) != coverage_sha256:
        raise CoverageEvidenceError(f"coverage checksum mismatch for lane {lane}")
    measured_file_count, arc_count = _inspect_coverage_data(coverage_contents, lane)
    if measured_file_count != coverage_measured_file_count or arc_count != coverage_arc_count:
        raise CoverageEvidenceError(f"coverage metadata mismatch for lane {lane}")
    return lane, coverage_filename, coverage_contents


def verify_and_stage_evidence(
    *,
    repo_root: Path,
    evidence_dirs: Sequence[Path],
    output_dir: Path,
    expected_lanes: Sequence[str],
    commit_sha: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    for_union: bool = False,
) -> list[Path]:
    """Verify exact lane evidence and stage only matching data for coverage.py combine."""

    root = repo_root.resolve(strict=True)
    expected_commit = _validate_identifier(commit_sha.lower(), _COMMIT_PATTERN, "commit SHA")
    if repository_head(root) != expected_commit:
        raise CoverageEvidenceError("declared commit SHA does not match repository HEAD")
    expected_run = _validate_identifier(workflow_run_id, _WORKFLOW_ID_PATTERN, "workflow run ID")
    expected_attempt = _validate_positive_integer_text(workflow_run_attempt, "workflow run attempt")
    expected_lane_set = {
        _validate_identifier(lane, _LANE_PATTERN, "lane") for lane in expected_lanes
    }
    if len(expected_lane_set) != len(expected_lanes) or not expected_lane_set:
        raise CoverageEvidenceError("expected lanes must be a non-empty unique set")
    if len(evidence_dirs) != len(expected_lane_set):
        raise CoverageEvidenceError("evidence directory count does not match expected lanes")

    source_digest, source_file_count = compute_source_snapshot(root, for_union=for_union)
    verified: dict[str, tuple[str, bytes]] = {}
    for evidence_dir in evidence_dirs:
        lane, filename, contents = _verify_manifest(
            repo_root=root,
            evidence_dir=evidence_dir,
            expected_commit_sha=expected_commit,
            expected_workflow_run_id=expected_run,
            expected_workflow_run_attempt=expected_attempt,
            expected_source_digest=source_digest,
            expected_source_file_count=source_file_count,
        )
        if lane not in expected_lane_set:
            raise CoverageEvidenceError(f"unexpected coverage lane: {lane}")
        if lane in verified:
            raise CoverageEvidenceError(f"duplicate coverage lane: {lane}")
        verified[lane] = (filename, contents)
    if set(verified) != expected_lane_set:
        missing = ",".join(sorted(expected_lane_set - set(verified)))
        raise CoverageEvidenceError(f"missing coverage lanes: {missing}")

    destination = _repo_child_path(root, output_dir, "coverage combine staging output")
    if _lstat_or_none(destination) is not None:
        raise CoverageEvidenceError("coverage combine staging output must be absent")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".coverage-combine-", dir=str(destination.parent)))
    try:
        staged: list[Path] = []
        for lane in sorted(verified):
            filename, contents = verified[lane]
            staged_path = temporary / filename
            staged_path.write_bytes(contents)
            if _regular_file_bytes(staged_path) != contents:
                raise CoverageEvidenceError(f"staged coverage checksum mismatch for lane {lane}")
            staged.append(staged_path)
        temporary.replace(destination)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    return [destination / path.name for path in staged]


def enforce_union_coverage(
    *,
    repo_root: Path,
    evidence_root: Path,
    output_dir: Path,
    expected_lanes: Sequence[str],
    commit_sha: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    fail_under: float = 85.0,
) -> float:
    """Verify both lane databases, combine them, and enforce the branch-coverage gate."""

    if not math.isfinite(fail_under) or not 0 <= fail_under <= 100:
        raise CoverageEvidenceError("coverage threshold must be between 0 and 100")
    root = repo_root.resolve(strict=True)
    expected_commit = _validate_identifier(commit_sha.lower(), _COMMIT_PATTERN, "commit SHA")
    expected_run = _validate_identifier(workflow_run_id, _WORKFLOW_ID_PATTERN, "workflow run ID")
    expected_attempt = _validate_positive_integer_text(workflow_run_attempt, "workflow run attempt")
    lanes = [_validate_identifier(lane, _LANE_PATTERN, "lane") for lane in expected_lanes]
    if len(set(lanes)) != len(lanes) or not lanes:
        raise CoverageEvidenceError("expected lanes must be a non-empty unique set")
    if repository_head(root) != expected_commit:
        raise CoverageEvidenceError("declared commit SHA does not match repository HEAD")

    evidence_base = _repo_child_path(root, evidence_root, "coverage evidence root")
    destination = _repo_child_path(root, output_dir, "coverage union output")
    evidence_dirs = [
        evidence_base / lane / f"run-{expected_run}-attempt-{expected_attempt}" for lane in lanes
    ]
    if any(
        evidence_dir == destination
        or evidence_dir.is_relative_to(destination)
        or destination.is_relative_to(evidence_dir)
        for evidence_dir in evidence_dirs
    ):
        raise CoverageEvidenceError("coverage union output overlaps lane evidence")

    clean_paths(repo_root=root, paths=[destination])
    staging = destination / "merge-input"
    verify_and_stage_evidence(
        repo_root=root,
        evidence_dirs=evidence_dirs,
        output_dir=staging,
        expected_lanes=lanes,
        commit_sha=expected_commit,
        workflow_run_id=expected_run,
        workflow_run_attempt=expected_attempt,
        for_union=True,
    )

    data_file = destination / ".coverage"
    report_file = destination / "coverage-union.txt"
    xml_file = destination / "coverage-union.xml"
    previous_directory = Path.cwd()
    try:
        os.chdir(root)
        coverage = Coverage(
            data_file=os.fspath(data_file),
            config_file=os.fspath(root / "pyproject.toml"),
        )
        coverage.combine(data_paths=[os.fspath(staging)], strict=True, keep=True)
        coverage.save()
        _inspect_coverage_data(
            _regular_file_bytes(data_file, maximum_bytes=MAX_COVERAGE_BYTES),
            "union",
        )
        with report_file.open("w", encoding="utf-8", newline="\n") as report:
            total = coverage.report(file=report)
        coverage.xml_report(outfile=os.fspath(xml_file))
    except (CoverageException, OSError, ValueError) as exc:
        raise CoverageEvidenceError("coverage union could not be produced") from exc
    finally:
        os.chdir(previous_directory)

    precision = coverage.config.precision
    if should_fail_under(total, fail_under, precision):
        raise CoverageEvidenceError(
            f"coverage union {total:.{precision}f}% is below {fail_under:.{precision}f}%"
        )
    return total


def clean_paths(*, repo_root: Path, paths: Sequence[Path]) -> None:
    """Remove only explicitly named stale evidence directories within the repository."""

    root = repo_root.resolve(strict=True)
    for path in paths:
        target = _repo_child_path(root, path, "cleanup target")
        metadata = _lstat_or_none(target)
        if metadata is None:
            continue
        if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
            raise CoverageEvidenceError("cleanup target must be a regular directory")
        shutil.rmtree(target)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture = subparsers.add_parser("capture")
    capture.add_argument("--repo-root", type=Path, required=True)
    capture.add_argument("--coverage-file", type=Path, required=True)
    capture.add_argument("--source-snapshot-file", type=Path, required=True)
    capture.add_argument("--expected-source-snapshot-sha256", required=True)
    capture.add_argument("--output-dir", type=Path, required=True)
    capture.add_argument("--lane", required=True)
    capture.add_argument("--commit-sha", required=True)
    capture.add_argument("--workflow-run-id", required=True)
    capture.add_argument("--workflow-run-attempt", required=True)

    snapshot = subparsers.add_parser(
        "snapshot",
        help="record a canonical run-bound source snapshot immediately before tests",
    )
    snapshot.add_argument("--repo-root", type=Path, required=True)
    snapshot.add_argument("--output-file", type=Path, required=True)
    snapshot.add_argument("--lane", required=True)
    snapshot.add_argument("--commit-sha", required=True)
    snapshot.add_argument("--workflow-run-id", required=True)
    snapshot.add_argument("--workflow-run-attempt", required=True)

    validate_context = subparsers.add_parser(
        "validate-context",
        help="validate lane identifiers and require the declared commit to equal Git HEAD",
    )
    validate_context.add_argument("--repo-root", type=Path, required=True)
    validate_context.add_argument("--lane", required=True)
    validate_context.add_argument("--commit-sha", required=True)
    validate_context.add_argument("--workflow-run-id", required=True)
    validate_context.add_argument("--workflow-run-attempt", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--repo-root", type=Path, required=True)
    verify.add_argument("--input-dir", type=Path, action="append", required=True)
    verify.add_argument("--output-dir", type=Path, required=True)
    verify.add_argument("--lane", action="append", required=True)
    verify.add_argument("--commit-sha", required=True)
    verify.add_argument("--workflow-run-id", required=True)
    verify.add_argument("--workflow-run-attempt", required=True)

    union = subparsers.add_parser(
        "union",
        help="verify lane-scoped evidence, combine it, and enforce branch coverage",
    )
    union.add_argument("--repo-root", type=Path, required=True)
    union.add_argument(
        "--evidence-root",
        type=Path,
        default=Path("test-results/coverage-evidence"),
    )
    union.add_argument("--output-dir", type=Path, required=True)
    union.add_argument("--lane", action="append")
    union.add_argument("--commit-sha", required=True)
    union.add_argument("--workflow-run-id", default="local")
    union.add_argument("--workflow-run-attempt", default="1")
    union.add_argument("--fail-under", type=float, default=85.0)

    clean = subparsers.add_parser("clean")
    clean.add_argument("--repo-root", type=Path, required=True)
    clean.add_argument("--path", type=Path, action="append", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the coverage evidence command-line interface."""

    args = _parser().parse_args(argv)
    try:
        if args.command == "capture":
            manifest = capture_evidence(
                repo_root=args.repo_root,
                coverage_file=args.coverage_file,
                source_snapshot_file=args.source_snapshot_file,
                expected_source_snapshot_sha256=args.expected_source_snapshot_sha256,
                output_dir=args.output_dir,
                lane=args.lane,
                commit_sha=args.commit_sha,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
            )
            sys.stdout.write(f"captured coverage evidence: {manifest.as_posix()}\n")
        elif args.command == "snapshot":
            snapshot_checksum = record_source_snapshot(
                repo_root=args.repo_root,
                output_file=args.output_file,
                lane=args.lane,
                commit_sha=args.commit_sha,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
            )
            sys.stdout.write(f"{snapshot_checksum}\n")
        elif args.command == "validate-context":
            validate_run_context(
                repo_root=args.repo_root,
                lane=args.lane,
                commit_sha=args.commit_sha,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
            )
            sys.stdout.write("validated coverage run context\n")
        elif args.command == "verify":
            staged = verify_and_stage_evidence(
                repo_root=args.repo_root,
                evidence_dirs=args.input_dir,
                output_dir=args.output_dir,
                expected_lanes=args.lane,
                commit_sha=args.commit_sha,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
            )
            sys.stdout.write(f"verified and staged {len(staged)} coverage lanes\n")
        elif args.command == "union":
            total = enforce_union_coverage(
                repo_root=args.repo_root,
                evidence_root=args.evidence_root,
                output_dir=args.output_dir,
                expected_lanes=args.lane or ["linux", "windows"],
                commit_sha=args.commit_sha,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
                fail_under=args.fail_under,
            )
            sys.stdout.write(f"coverage union passed at {total:.2f}%\n")
        else:
            clean_paths(repo_root=args.repo_root, paths=args.path)
    except (CoverageEvidenceError, OSError) as exc:
        sys.stderr.write(f"coverage evidence error: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
