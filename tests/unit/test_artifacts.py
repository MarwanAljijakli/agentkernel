from __future__ import annotations

from pathlib import Path

import pytest
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


@pytest.mark.parametrize(
    "digest",
    ["sha256:../escape", "sha256:" + "g" * 64, "md5:" + "0" * 64],
)
def test_invalid_digest_cannot_address_a_path(tmp_path: Path, digest: str) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    with pytest.raises(AgentKernelError) as captured:
        store.get(digest)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR
