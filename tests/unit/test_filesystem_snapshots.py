from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.snapshots.filesystem import (
    ChangeKind,
    diff_snapshots,
    normalize_relative_path,
    resolve_scoped_path,
    snapshot_tree,
)


@pytest.mark.parametrize(
    "raw",
    [
        "../secret",
        "/absolute",
        "nested\\windows",
        "stream:ads",
        "",
        "a/../b",
        "foo.",
        "foo ",
        "CON.txt",
        "a//b",
        "./a",
        "control\x01name",
    ],
)
def test_unsafe_relative_paths_are_rejected(raw: str) -> None:
    with pytest.raises(AgentKernelError) as captured:
        normalize_relative_path(raw)
    assert captured.value.code is ErrorCode.VALIDATION_ERROR


def test_snapshot_and_typed_diff_are_deterministic(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "a.txt").write_text("before", encoding="utf-8")
    before = snapshot_tree(workspace)
    (workspace / "a.txt").write_text("after", encoding="utf-8")
    (workspace / "b.txt").write_text("created", encoding="utf-8")
    after = snapshot_tree(workspace)
    diff = diff_snapshots(before, after)
    assert [(change.path, change.kind) for change in diff.changes] == [
        ("a.txt", ChangeKind.MODIFIED),
        ("b.txt", ChangeKind.CREATED),
    ]
    assert diff.base_digest == before.digest
    assert diff.target_digest == after.digest


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="platform has no symlink API")
def test_symlink_is_outside_initial_snapshot_boundary(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = workspace / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is not permitted for this test user")
    with pytest.raises(AgentKernelError, match="symbolic links"):
        snapshot_tree(workspace)
    with pytest.raises(AgentKernelError, match="Symbolic links"):
        resolve_scoped_path(workspace, "link.txt")


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junction regression is Windows-only")
def test_junction_cannot_cross_the_workspace_boundary(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside secret", encoding="utf-8")
    junction = workspace / "junction"
    command_processor = Path(os.environ["SYSTEMROOT"]) / "System32" / "cmd.exe"
    created = subprocess.run(  # noqa: S603
        [str(command_processor), "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        check=False,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip("junction creation is not permitted for this test user")

    with pytest.raises(AgentKernelError, match="junctions"):
        snapshot_tree(workspace)
    with pytest.raises(AgentKernelError, match="Reparse points"):
        resolve_scoped_path(workspace, "junction/secret.txt")


def test_snapshot_rejects_casefold_aliases_on_case_sensitive_filesystems(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "A.txt").write_text("upper", encoding="utf-8")
    try:
        (workspace / "a.txt").write_text("lower", encoding="utf-8")
    except OSError:
        pytest.skip("filesystem is case-insensitive")
    if len(list(workspace.iterdir())) != 2:
        pytest.skip("filesystem is case-insensitive")

    with pytest.raises(AgentKernelError, match="path alias"):
        snapshot_tree(workspace)


def test_resolve_scoped_path_treats_descendant_below_file_as_absent(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "file").write_text("not a directory", encoding="utf-8")

    resolved = resolve_scoped_path(workspace, "file/descendant/result.txt")

    assert resolved == workspace / "file" / "descendant" / "result.txt"
