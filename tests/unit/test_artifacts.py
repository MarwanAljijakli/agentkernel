from __future__ import annotations

import errno
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from agentkernel.adapters.base import EvidenceClock
from agentkernel.canonical import canonical_json_bytes
from agentkernel.domain.models import ActionProposal
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.evidence.artifacts import LocalArtifactStore


def test_artifact_round_trip_and_deduplication(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    first = store.put(b"evidence", media_type="text/plain")
    second = store.put(b"evidence", media_type="text/plain")
    assert first.digest == second.digest
    assert store.get(first.digest) == b"evidence"


def test_corrupted_artifact_is_detected(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    artifact = store.put(b"original")
    (store.root / artifact.storage_ref).write_bytes(b"corrupted")
    with pytest.raises(AgentKernelError) as captured:
        store.get(artifact.digest)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_put_never_heals_or_overwrites_a_corrupted_existing_blob(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    artifact = store.put(b"original")
    blob = store.root / artifact.storage_ref
    blob.write_bytes(b"corrupted")

    with pytest.raises(AgentKernelError) as captured:
        store.put(b"original")

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    assert blob.read_bytes() == b"corrupted"


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_artifact_directories_and_blobs_are_owner_private(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    artifact = store.put(b"private")
    blob = store.root / artifact.storage_ref

    assert stat.S_IMODE(store.root.stat().st_mode) & 0o077 == 0
    assert stat.S_IMODE(blob.parent.stat().st_mode) & 0o077 == 0
    assert stat.S_IMODE(blob.stat().st_mode) & 0o077 == 0


@pytest.mark.parametrize(
    "digest",
    ["sha256:../escape", "sha256:" + "g" * 64, "md5:" + "0" * 64],
)
def test_invalid_digest_cannot_address_a_path(tmp_path: Path, digest: str) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    with pytest.raises(AgentKernelError) as captured:
        store.get(digest)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_model_round_trip_preserves_exact_canonical_bytes(
    tmp_path: Path,
    proposal: ActionProposal,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")

    artifact = store.put_model(proposal)

    assert store.get(artifact.digest) == canonical_json_bytes(proposal)
    assert store.get_model(artifact.digest, ActionProposal) == proposal


def test_get_model_rejects_valid_but_noncanonical_json(
    tmp_path: Path,
    proposal: ActionProposal,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    noncanonical = proposal.model_dump_json(indent=2).encode("utf-8")
    artifact = store.put(noncanonical, media_type="application/json")

    with pytest.raises(AgentKernelError) as captured:
        store.get_model(artifact.digest, ActionProposal)

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_artifact_blob_cannot_be_replaced_by_a_symlink(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    artifact = store.put(b"original")
    blob = store.root / artifact.storage_ref
    outside = tmp_path / "outside"
    outside.write_bytes(b"original")
    blob.unlink()
    try:
        blob.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is not permitted for this test user")

    with pytest.raises(AgentKernelError) as captured:
        store.get(artifact.digest)

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_artifact_blob_must_be_a_regular_file(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    artifact = store.put(b"original")
    blob = store.root / artifact.storage_ref
    blob.unlink()
    blob.mkdir()

    with pytest.raises(AgentKernelError) as captured:
        store.get(artifact.digest)

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


@pytest.mark.skipif(os.name != "posix", reason="POSIX no-follow parent contract")
def test_artifact_put_rejects_a_swapped_symlink_shard_parent(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    store.put(b"first")
    algorithm_directory = store.root / "sha256"
    original_directory = store.root / "sha256-original"
    algorithm_directory.rename(original_directory)
    outside = tmp_path / "outside"
    outside.mkdir()
    algorithm_directory.symlink_to(outside, target_is_directory=True)

    with pytest.raises(AgentKernelError) as captured:
        store.put(b"second")

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    assert list(outside.iterdir()) == []


def test_artifact_size_limit_rejects_before_put(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts", max_artifact_bytes=8)

    with pytest.raises(AgentKernelError) as captured:
        store.put(b"123456789")

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_oversized_replacement_is_rejected_before_read(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts", max_artifact_bytes=8)
    artifact = store.put(b"small")
    blob = store.root / artifact.storage_ref
    blob.write_bytes(b"123456789")

    with pytest.raises(AgentKernelError) as captured:
        store.get(artifact.digest)

    assert captured.value.code is ErrorCode.RESOURCE_LIMIT_EXCEEDED
    assert captured.value.details == {}


def test_put_propagates_durability_io_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")

    def fail_fsync(_descriptor: int) -> None:
        raise OSError(errno.EIO, "injected durability failure")

    monkeypatch.setattr(os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="injected durability failure") as captured:
        store.put(b"must-be-durable")
    assert captured.value.errno == errno.EIO


def test_evidence_clock_is_deterministic_and_rejects_regression(tmp_path: Path) -> None:
    instant = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
    values = iter((instant, instant, instant - timedelta(microseconds=1)))
    clock = EvidenceClock(lambda: next(values))
    store = LocalArtifactStore(tmp_path / "artifacts", clock=clock)

    first = store.put(b"first")
    second = store.put(b"second")

    assert first.created_at == instant
    assert second.created_at == instant
    with pytest.raises(AgentKernelError) as captured:
        store.put(b"third")
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
