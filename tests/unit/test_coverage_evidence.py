from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from coverage import CoverageData
from scripts.coverage_evidence import (
    MANIFEST_NAME,
    ROOT_EXECUTION_CONTROLS,
    SOURCE_SNAPSHOT_NAME,
    CoverageEvidenceError,
    capture_evidence,
    compute_source_snapshot,
    enforce_union_coverage,
    record_source_snapshot,
    repository_head,
    verify_and_stage_evidence,
)
from scripts.coverage_evidence import (
    main as coverage_evidence_main,
)

WORKFLOW_RUN_ID = "12345"
WORKFLOW_RUN_ATTEMPT = "2"
GIT_EXECUTABLE = shutil.which("git")


def _git(root: Path, *args: str) -> str:
    assert GIT_EXECUTABLE is not None
    result = subprocess.run(  # noqa: S603 - fixed Git binary and test-controlled arguments.
        [GIT_EXECUTABLE, "-C", os.fspath(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repo(root: Path) -> Path:
    source = root / "agentkernel"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_value.py").write_text("def test_value(): pass\n", encoding="utf-8")
    scripts = root / "scripts"
    scripts.mkdir()
    (scripts / "check.ps1").write_text("# check\n", encoding="utf-8")
    (scripts / "check.sh").write_text("# check\n", encoding="utf-8")
    (scripts / "coverage_evidence.py").write_text("# tool\n", encoding="utf-8")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text("name: test\n", encoding="utf-8")
    for directory, filename in (
        ("docs", "guide.md"),
        ("policies", "default.json"),
        ("requirements", "traceability.json"),
        ("schemas", "model.json"),
    ):
        path = root / directory
        path.mkdir()
        (path / filename).write_text("{}\n", encoding="utf-8")
    (root / "README.md").write_text("# test\n", encoding="utf-8")
    (root / ".gitattributes").write_text(
        "* text=auto eol=lf\n*.ps1 text eol=crlf\n",
        encoding="utf-8",
    )
    (root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        "[tool.coverage.run]\n"
        "branch = true\n"
        "relative_files = true\n"
        'source = ["agentkernel"]\n'
        "\n"
        "[tool.coverage.report]\n"
        "fail_under = 85\n"
        "precision = 2\n",
        encoding="utf-8",
    )
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "coverage@example.invalid")
    _git(root, "config", "user.name", "Coverage Test")
    _git(root, "add", ".")
    _git(root, "commit", "--quiet", "-m", "fixture")
    return root


def _run_segment() -> str:
    return f"run-{WORKFLOW_RUN_ID}-attempt-{WORKFLOW_RUN_ATTEMPT}"


def _raw_dir(root: Path, lane: str) -> Path:
    return root / "test-results" / "coverage-raw" / lane / _run_segment()


def _record_snapshot(
    root: Path,
    lane: str,
    *,
    workflow_run_id: str = WORKFLOW_RUN_ID,
    workflow_run_attempt: str = WORKFLOW_RUN_ATTEMPT,
) -> tuple[Path, str]:
    snapshot = _raw_dir(root, lane) / SOURCE_SNAPSHOT_NAME
    checksum = record_source_snapshot(
        repo_root=root,
        output_file=snapshot,
        lane=lane,
        commit_sha=repository_head(root),
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
    )
    return snapshot, checksum


def _write_coverage(root: Path, lane: str, *, branch: bool = True) -> Path:
    raw = _raw_dir(root, lane) / ".coverage"
    raw.parent.mkdir(parents=True, exist_ok=True)
    data = CoverageData(basename=os.fspath(raw))
    data.set_context(lane)
    measured_file = "agentkernel/__init__.py"
    if branch:
        data.add_arcs({measured_file: [(-1, 1), (1, -1)]})
    else:
        data.add_lines({measured_file: [1]})
    data.write()
    return raw


def _evidence_dir(root: Path, lane: str) -> Path:
    return root / "test-results" / "coverage-evidence" / lane / _run_segment()


def _capture_after_snapshot(
    root: Path,
    lane: str,
    snapshot: Path,
    expected_snapshot_checksum: str,
    *,
    evidence: Path | None = None,
    branch: bool = True,
) -> Path:
    raw = _write_coverage(root, lane, branch=branch)
    destination = evidence or _evidence_dir(root, lane)
    capture_evidence(
        repo_root=root,
        coverage_file=raw,
        source_snapshot_file=snapshot,
        expected_source_snapshot_sha256=expected_snapshot_checksum,
        output_dir=destination,
        lane=lane,
        commit_sha=repository_head(root),
        workflow_run_id=WORKFLOW_RUN_ID,
        workflow_run_attempt=WORKFLOW_RUN_ATTEMPT,
    )
    return destination


def _capture(
    root: Path,
    lane: str,
    *,
    evidence: Path | None = None,
    branch: bool = True,
) -> Path:
    snapshot, expected_snapshot_checksum = _record_snapshot(root, lane)
    return _capture_after_snapshot(
        root,
        lane,
        snapshot,
        expected_snapshot_checksum,
        evidence=evidence,
        branch=branch,
    )


def _verify(root: Path, evidence_dirs: list[Path]) -> list[Path]:
    return verify_and_stage_evidence(
        repo_root=root,
        evidence_dirs=evidence_dirs,
        output_dir=root / "test-results" / "combine",
        expected_lanes=["linux", "windows"],
        commit_sha=repository_head(root),
        workflow_run_id=WORKFLOW_RUN_ID,
        workflow_run_attempt=WORKFLOW_RUN_ATTEMPT,
    )


def _write_manifest(path: Path, manifest: dict[str, object]) -> None:
    path.write_bytes(
        (json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    )


def test_matching_real_lane_databases_are_staged_with_unique_names(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    linux = _capture(root, "linux")
    windows = _capture(root, "windows")

    staged = _verify(root, [windows, linux])

    assert len(staged) == 2
    assert all(path.name.startswith(".coverage.") for path in staged)
    assert len({path.name for path in staged}) == 2
    for path in staged:
        data = CoverageData(basename=os.fspath(path))
        data.read()
        assert data.has_arcs()
        assert data.measured_files() == {"agentkernel/__init__.py"}
        assert data.arcs("agentkernel/__init__.py")


def test_verify_rejects_coverage_checksum_mismatch(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    linux = _capture(root, "linux")
    windows = _capture(root, "windows")
    manifest = json.loads((linux / MANIFEST_NAME).read_text(encoding="utf-8"))
    coverage_path = linux / manifest["coverage_file"]
    captured = coverage_path.read_bytes()
    coverage_path.write_bytes(bytes([captured[0] ^ 0xFF]) + captured[1:])

    with pytest.raises(CoverageEvidenceError, match="checksum mismatch"):
        _verify(root, [linux, windows])

    assert not (root / "test-results" / "combine").exists()


def test_verify_rejects_checksum_valid_but_corrupt_lane_database(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    linux = _capture(root, "linux")
    windows = _capture(root, "windows")
    manifest_path = linux / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    corrupt = b"checksum-valid but not CoverageData"
    (linux / manifest["coverage_file"]).write_bytes(corrupt)
    manifest["coverage_bytes"] = len(corrupt)
    manifest["coverage_sha256"] = f"sha256:{hashlib.sha256(corrupt).hexdigest()}"
    _write_manifest(manifest_path, manifest)

    with pytest.raises(CoverageEvidenceError, match="coverage data is unreadable"):
        _verify(root, [linux, windows])

    assert not (root / "test-results" / "combine").exists()


def test_capture_rejects_corrupt_or_line_only_database(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    snapshot, snapshot_checksum = _record_snapshot(root, "linux")
    corrupt = _raw_dir(root, "linux") / "corrupt.coverage"
    corrupt.write_bytes(b"not CoverageData")

    with pytest.raises(CoverageEvidenceError, match="coverage data is unreadable"):
        capture_evidence(
            repo_root=root,
            coverage_file=corrupt,
            source_snapshot_file=snapshot,
            expected_source_snapshot_sha256=snapshot_checksum,
            output_dir=root / "test-results" / "corrupt-evidence",
            lane="linux",
            commit_sha=repository_head(root),
            workflow_run_id=WORKFLOW_RUN_ID,
            workflow_run_attempt=WORKFLOW_RUN_ATTEMPT,
        )

    with pytest.raises(CoverageEvidenceError, match="does not contain branch arcs"):
        _capture(root, "line-only", branch=False)


def test_verify_rejects_source_snapshot_mismatch(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    linux = _capture(root, "linux")
    windows = _capture(root, "windows")
    (root / "agentkernel" / "__init__.py").write_text("VALUE = 2\n", encoding="utf-8")

    with pytest.raises(CoverageEvidenceError, match="source snapshot mismatch"):
        _verify(root, [linux, windows])

    assert not (root / "test-results" / "combine").exists()


def test_verify_rejects_test_suite_snapshot_mismatch(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    linux = _capture(root, "linux")
    windows = _capture(root, "windows")
    (root / "tests" / "test_value.py").write_text(
        "def test_value(): assert False\n",
        encoding="utf-8",
    )

    with pytest.raises(CoverageEvidenceError, match="source snapshot mismatch"):
        _verify(root, [linux, windows])

    assert not (root / "test-results" / "combine").exists()


@pytest.mark.parametrize(
    "relative_path",
    [
        ".github/workflows/ci.yml",
        "docs/guide.md",
        "policies/default.json",
        "requirements/traceability.json",
        "schemas/model.json",
        "scripts/check.sh",
        "README.md",
        "pyproject.toml",
    ],
)
def test_snapshot_covers_all_tracked_project_surfaces(tmp_path: Path, relative_path: str) -> None:
    root = _repo(tmp_path / "repo")
    linux = _capture(root, "linux")
    windows = _capture(root, "windows")
    target = root / relative_path
    target.write_text(target.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")

    with pytest.raises(CoverageEvidenceError, match="source snapshot mismatch"):
        _verify(root, [linux, windows])


def test_snapshot_covers_new_untracked_project_files(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    linux = _capture(root, "linux")
    windows = _capture(root, "windows")
    (root / "schemas" / "new.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(CoverageEvidenceError, match="source snapshot mismatch"):
        _verify(root, [linux, windows])


def test_snapshot_forces_every_known_root_control_despite_info_exclude(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "repo")
    expected_controls = (
        ".coveragerc",
        "conftest.py",
        "pytest.ini",
        "setup.cfg",
        "sitecustomize.py",
        "tox.ini",
        "usercustomize.py",
    )
    assert expected_controls == ROOT_EXECUTION_CONTROLS
    (root / ".git" / "info" / "exclude").write_text(
        "".join(f"/{name}\n" for name in expected_controls),
        encoding="utf-8",
    )
    previous_digest, previous_count = compute_source_snapshot(root)

    for control in expected_controls:
        (root / control).write_text(f"# {control}\n", encoding="utf-8")
        digest, count = compute_source_snapshot(root)
        assert digest != previous_digest
        assert count == previous_count + 1
        previous_digest, previous_count = digest, count


@pytest.mark.parametrize("change", ["addition", "removal"])
def test_capture_rejects_hidden_untracked_hook_addition_or_removal(
    tmp_path: Path,
    change: str,
) -> None:
    root = _repo(tmp_path / "repo")
    hook = root / "conftest.py"
    (root / ".git" / "info" / "exclude").write_text("/conftest.py\n", encoding="utf-8")
    if change == "removal":
        hook.write_text("def pytest_configure(): pass\n", encoding="utf-8")
    snapshot, snapshot_checksum = _record_snapshot(root, "linux")
    if change == "addition":
        hook.write_text("def pytest_configure(): pass\n", encoding="utf-8")
    else:
        hook.unlink()

    with pytest.raises(
        CoverageEvidenceError,
        match="source changed between pre-test snapshot and coverage capture",
    ):
        _capture_after_snapshot(root, "linux", snapshot, snapshot_checksum)

    assert not _evidence_dir(root, "linux").exists()


def test_capture_rejects_tracked_mutation_after_pre_test_snapshot(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    snapshot, snapshot_checksum = _record_snapshot(root, "linux")
    (root / "agentkernel" / "__init__.py").write_text("VALUE = 2\n", encoding="utf-8")

    with pytest.raises(
        CoverageEvidenceError,
        match="source changed between pre-test snapshot and coverage capture",
    ):
        _capture_after_snapshot(root, "linux", snapshot, snapshot_checksum)

    assert not _evidence_dir(root, "linux").exists()


def test_capture_rejects_coordinated_source_and_snapshot_rewrite(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "repo")
    snapshot_path, parent_held_checksum = _record_snapshot(root, "linux")
    (root / "agentkernel" / "__init__.py").write_text("VALUE = 2\n", encoding="utf-8")
    replacement_digest, replacement_count = compute_source_snapshot(root)
    replacement = json.loads(snapshot_path.read_text(encoding="utf-8"))
    replacement["source_digest"] = replacement_digest
    replacement["source_file_count"] = replacement_count
    _write_manifest(snapshot_path, replacement)
    replacement_checksum = f"sha256:{hashlib.sha256(snapshot_path.read_bytes()).hexdigest()}"
    assert replacement_checksum != parent_held_checksum

    with pytest.raises(
        CoverageEvidenceError,
        match="source snapshot checksum does not match parent-held value",
    ):
        _capture_after_snapshot(
            root,
            "linux",
            snapshot_path,
            parent_held_checksum,
        )

    assert not _evidence_dir(root, "linux").exists()


def test_capture_rejects_substituted_or_tampered_pre_test_snapshot(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    linux_snapshot, linux_snapshot_checksum = _record_snapshot(root, "linux")
    substituted = _raw_dir(root, "windows") / SOURCE_SNAPSHOT_NAME
    substituted.parent.mkdir(parents=True)
    shutil.copyfile(linux_snapshot, substituted)

    with pytest.raises(CoverageEvidenceError, match="source snapshot lane mismatch"):
        _capture_after_snapshot(root, "windows", substituted, linux_snapshot_checksum)
    assert not _evidence_dir(root, "windows").exists()

    snapshot = json.loads(linux_snapshot.read_text(encoding="utf-8"))
    snapshot["source_digest"] = "sha256:" + ("f" * 64)
    _write_manifest(linux_snapshot, snapshot)
    with pytest.raises(
        CoverageEvidenceError,
        match="source snapshot checksum does not match parent-held value",
    ):
        _capture_after_snapshot(
            root,
            "linux",
            linux_snapshot,
            linux_snapshot_checksum,
        )
    assert not _evidence_dir(root, "linux").exists()


def test_verify_rejects_canonical_tampered_snapshot_with_updated_manifest_checksum(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "repo")
    linux = _capture(root, "linux")
    windows = _capture(root, "windows")
    snapshot_path = linux / SOURCE_SNAPSHOT_NAME
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    snapshot["source_digest"] = "sha256:" + ("f" * 64)
    _write_manifest(snapshot_path, snapshot)
    manifest_path = linux / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_snapshot_sha256"] = (
        f"sha256:{hashlib.sha256(snapshot_path.read_bytes()).hexdigest()}"
    )
    _write_manifest(manifest_path, manifest)

    with pytest.raises(CoverageEvidenceError, match="source snapshot manifest mismatch"):
        _verify(root, [linux, windows])

    assert not (root / "test-results" / "combine").exists()


def test_source_snapshot_output_path_is_exact_for_lane_and_run(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")

    with pytest.raises(CoverageEvidenceError, match="path is not canonical for this run"):
        record_source_snapshot(
            repo_root=root,
            output_file=root / "test-results" / SOURCE_SNAPSHOT_NAME,
            lane="linux",
            commit_sha=repository_head(root),
            workflow_run_id=WORKFLOW_RUN_ID,
            workflow_run_attempt=WORKFLOW_RUN_ATTEMPT,
        )


def test_capture_allows_only_named_generated_output_churn(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    outputs = (
        root / "test-results" / "generated" / "result.log",
        root / ".coverage",
        root / "coverage.xml",
        root / "htmlcov" / "index.html",
        root / ".pytest_cache" / "v" / "cache" / "nodeids",
        root / ".mypy_cache" / "3.12" / "cache.json",
        root / ".ruff_cache" / "content",
        root / ".venv" / "generated-state",
    )
    for output in outputs:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("before\n", encoding="utf-8")
    snapshot, snapshot_checksum = _record_snapshot(root, "linux")
    for output in outputs:
        output.write_text("after\n", encoding="utf-8")

    evidence = _capture_after_snapshot(root, "linux", snapshot, snapshot_checksum)

    assert (evidence / MANIFEST_NAME).is_file()
    assert (evidence / SOURCE_SNAPSHOT_NAME).is_file()


def test_capture_rejects_unexpected_root_output_not_a_broad_extension(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "repo")
    snapshot, snapshot_checksum = _record_snapshot(root, "linux")
    (root / "raw-linux.coverage").write_text("unexpected\n", encoding="utf-8")

    with pytest.raises(
        CoverageEvidenceError,
        match="source changed between pre-test snapshot and coverage capture",
    ):
        _capture_after_snapshot(root, "linux", snapshot, snapshot_checksum)

    assert not _evidence_dir(root, "linux").exists()


@pytest.mark.parametrize("script_name", ["check.ps1", "check.sh"])
def test_check_scripts_snapshot_immediately_before_pytest_and_bind_capture(
    script_name: str,
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    script = (project_root / "scripts" / script_name).read_text(encoding="utf-8")
    snapshot_index = script.index("coverage_evidence.py snapshot")
    pytest_index = script.index("coverage run")
    capture_index = script.index("coverage_evidence.py capture")

    assert snapshot_index < pytest_index < capture_index
    assert "--source-snapshot-file" in script[capture_index:]
    assert "--expected-source-snapshot-sha256" in script[capture_index:]
    assert '"$coverageSourceSnapshotSha256"' in script or (
        '"$COVERAGE_SOURCE_SNAPSHOT_SHA256"' in script
    )
    snapshot_command = script[snapshot_index:pytest_index]
    for context_flag in (
        "--lane",
        "--commit-sha",
        "--workflow-run-id",
        "--workflow-run-attempt",
    ):
        assert context_flag in snapshot_command


def test_cli_records_snapshot_then_captures_bound_evidence(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = _repo(tmp_path / "repo")
    lane = "linux"
    snapshot = _raw_dir(root, lane) / SOURCE_SNAPSHOT_NAME
    head = repository_head(root)
    context_arguments = [
        "--lane",
        lane,
        "--commit-sha",
        head,
        "--workflow-run-id",
        WORKFLOW_RUN_ID,
        "--workflow-run-attempt",
        WORKFLOW_RUN_ATTEMPT,
    ]

    assert (
        coverage_evidence_main(
            [
                "snapshot",
                "--repo-root",
                os.fspath(root),
                "--output-file",
                os.fspath(snapshot),
                *context_arguments,
            ]
        )
        == 0
    )
    snapshot_output = capsys.readouterr()
    snapshot_lines = snapshot_output.out.splitlines()
    assert snapshot_output.err == ""
    assert len(snapshot_lines) == 1
    snapshot_checksum = snapshot_lines[0]
    assert snapshot_checksum.startswith("sha256:")
    assert len(snapshot_checksum) == 71
    assert all(character in "0123456789abcdef" for character in snapshot_checksum[7:])
    coverage_file = _write_coverage(root, lane)
    evidence = _evidence_dir(root, lane)
    assert (
        coverage_evidence_main(
            [
                "capture",
                "--repo-root",
                os.fspath(root),
                "--coverage-file",
                os.fspath(coverage_file),
                "--source-snapshot-file",
                os.fspath(snapshot),
                "--expected-source-snapshot-sha256",
                snapshot_checksum,
                "--output-dir",
                os.fspath(evidence),
                *context_arguments,
            ]
        )
        == 0
    )
    assert (evidence / MANIFEST_NAME).is_file()


def test_snapshot_uses_git_canonical_line_endings(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    script = root / "scripts" / "check.ps1"
    script.write_bytes(b"# check\r\n")
    windows_digest = compute_source_snapshot(root)
    script.write_bytes(b"# check\n")
    linux_digest = compute_source_snapshot(root)

    assert windows_digest == linux_digest


def test_verify_rejects_manifest_source_digest_mismatch(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    linux = _capture(root, "linux")
    windows = _capture(root, "windows")
    manifest_path = linux / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_digest"] = "sha256:" + ("f" * 64)
    _write_manifest(manifest_path, manifest)

    with pytest.raises(CoverageEvidenceError, match="source snapshot mismatch"):
        _verify(root, [linux, windows])


def test_capture_and_verify_require_declared_commit_to_equal_head(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    snapshot, snapshot_checksum = _record_snapshot(root, "commit-check")
    raw = _write_coverage(root, "commit-check")

    with pytest.raises(CoverageEvidenceError, match="does not match repository HEAD"):
        capture_evidence(
            repo_root=root,
            coverage_file=raw,
            source_snapshot_file=snapshot,
            expected_source_snapshot_sha256=snapshot_checksum,
            output_dir=root / "test-results" / "evidence-commit-check",
            lane="commit-check",
            commit_sha="2" * 40,
            workflow_run_id=WORKFLOW_RUN_ID,
            workflow_run_attempt=WORKFLOW_RUN_ATTEMPT,
        )

    linux = _capture(root, "linux")
    windows = _capture(root, "windows")
    with pytest.raises(CoverageEvidenceError, match="does not match repository HEAD"):
        verify_and_stage_evidence(
            repo_root=root,
            evidence_dirs=[linux, windows],
            output_dir=root / "test-results" / "combine",
            expected_lanes=["linux", "windows"],
            commit_sha="2" * 40,
            workflow_run_id=WORKFLOW_RUN_ID,
            workflow_run_attempt=WORKFLOW_RUN_ATTEMPT,
        )


def test_verify_rejects_stale_workflow_or_manifest_commit(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    linux = _capture(root, "linux")
    windows = _capture(root, "windows")

    with pytest.raises(CoverageEvidenceError, match="workflow run ID mismatch"):
        verify_and_stage_evidence(
            repo_root=root,
            evidence_dirs=[linux, windows],
            output_dir=root / "test-results" / "combine",
            expected_lanes=["linux", "windows"],
            commit_sha=repository_head(root),
            workflow_run_id="99999",
            workflow_run_attempt=WORKFLOW_RUN_ATTEMPT,
        )

    manifest_path = linux / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["commit_sha"] = "2" * 40
    _write_manifest(manifest_path, manifest)
    with pytest.raises(CoverageEvidenceError, match="commit SHA mismatch"):
        _verify(root, [linux, windows])


def test_local_union_gate_combines_two_verified_real_databases(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    lane_evidence_root = root / "test-results" / "coverage-evidence"
    evidence_root = root / "downloaded-coverage" / "coverage-evidence"
    run_segment = _run_segment()
    captured: dict[str, Path] = {}
    for lane in ("linux", "windows"):
        captured[lane] = _capture(
            root,
            lane,
            evidence=lane_evidence_root / lane / run_segment,
        )
    for lane, source in captured.items():
        shutil.copytree(source, evidence_root / lane / run_segment)

    output = root / "test-results" / "coverage-union" / run_segment
    total = enforce_union_coverage(
        repo_root=root,
        evidence_root=evidence_root,
        output_dir=output,
        expected_lanes=["linux", "windows"],
        commit_sha=repository_head(root),
        workflow_run_id=WORKFLOW_RUN_ID,
        workflow_run_attempt=WORKFLOW_RUN_ATTEMPT,
        fail_under=85,
    )

    assert total == pytest.approx(100.0)
    assert (output / ".coverage").is_file()
    assert (output / "coverage-union.txt").is_file()
    assert (output / "coverage-union.xml").is_file()
    assert len(list((output / "merge-input").glob(".coverage.*"))) == 2


def test_local_union_gate_cannot_ignore_a_checksum_valid_corrupt_lane(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path / "repo")
    evidence_root = root / "test-results" / "coverage-evidence"
    run_segment = _run_segment()
    evidence: dict[str, Path] = {}
    for lane in ("linux", "windows"):
        evidence[lane] = _capture(
            root,
            lane,
            evidence=evidence_root / lane / run_segment,
        )
    manifest_path = evidence["windows"] / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    corrupt = b"valid checksum, invalid coverage database"
    (evidence["windows"] / manifest["coverage_file"]).write_bytes(corrupt)
    manifest["coverage_bytes"] = len(corrupt)
    manifest["coverage_sha256"] = f"sha256:{hashlib.sha256(corrupt).hexdigest()}"
    _write_manifest(manifest_path, manifest)

    output = root / "test-results" / "coverage-union" / run_segment
    with pytest.raises(CoverageEvidenceError, match="coverage data is unreadable"):
        enforce_union_coverage(
            repo_root=root,
            evidence_root=evidence_root,
            output_dir=output,
            expected_lanes=["linux", "windows"],
            commit_sha=repository_head(root),
            workflow_run_id=WORKFLOW_RUN_ID,
            workflow_run_attempt=WORKFLOW_RUN_ATTEMPT,
            fail_under=85,
        )

    assert not (output / ".coverage").exists()
