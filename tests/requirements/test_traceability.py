from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "requirements" / "traceability.json"
REGISTRY = ROOT / "requirements" / "id-registry.json"
POLICY = ROOT / "requirements" / "traceability-policy.json"
SCHEMA = ROOT / "requirements" / "traceability.schema.json"
SPEC = ROOT / "requirements" / "source" / "AgentKernel_Full_Project_Specification.md"
MARKDOWN = ROOT / "docs" / "project" / "requirements-traceability.md"
VALIDATOR = ROOT / "scripts" / "validate_traceability.py"
GENERATOR = ROOT / "scripts" / "build_traceability.py"


def _run(
    *extra: str,
    manifest: Path = MANIFEST,
    registry: Path = REGISTRY,
    policy: Path = POLICY,
    schema: Path = SCHEMA,
    spec: Path = SPEC,
    markdown: Path = MARKDOWN,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(VALIDATOR),
            "--manifest",
            str(manifest),
            "--registry",
            str(registry),
            "--policy",
            str(policy),
            "--schema",
            str(schema),
            "--spec",
            str(spec),
            "--markdown",
            str(markdown),
            *extra,
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )


def _write_json(path: Path, value: Any) -> Path:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def _mutated_manifest(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    *,
    name: str = "traceability.json",
) -> Path:
    value = deepcopy(json.loads(MANIFEST.read_text(encoding="utf-8")))
    mutate(value)
    return _write_json(tmp_path / name, value)


def _mutated_registry(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    *,
    name: str = "id-registry.json",
) -> Path:
    value = deepcopy(json.loads(REGISTRY.read_text(encoding="utf-8")))
    mutate(value)
    return _write_json(tmp_path / name, value)


def _mutated_policy(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
) -> Path:
    value = deepcopy(json.loads(POLICY.read_text(encoding="utf-8")))
    mutate(value)
    return _write_json(tmp_path / "traceability-policy.json", value)


def test_committed_traceability_manifest_is_valid_against_schema_and_source() -> None:
    completed = _run("--json")

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "catalog_rows": 446,
        "errors": [],
        "release_readiness": "FAIL",
        "source_rows": 360,
        "total_rows": 806,
        "validation": "PASS",
    }


def test_release_completeness_uses_external_mandatory_map_and_remains_red(
    tmp_path: Path,
) -> None:
    def mutate(value: dict[str, Any]) -> None:
        row = next(row for row in value["requirements"] if row["id"] == "AK-001")
        row["mandatory"] = False

    completed = _run(
        "--require-complete",
        manifest=_mutated_manifest(tmp_path, mutate),
    )

    assert completed.returncode == 1
    assert "manifest mandatory flag differs from external policy" in completed.stderr
    assert "release gate incomplete" in completed.stderr


def test_baseline_does_not_overclaim_unproven_atomic_behaviors() -> None:
    value = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in value["requirements"]}
    conservative_ids = {
        "AK-002",
        "AK-003",
        "AK-005",
        "AK-006",
        "AK-012",
        "AK-013",
        "REL-R01-D03",
        "REL-R01-G05",
        "REL-R01-G06",
        "COMP-ADAPTER-FILESYSTEM",
        "COMP-MODEL-LOCAL",
        "COMP-STORE-SQLITE",
        "COMP-ARTIFACT-LOCAL",
        "USR-002",
        "USR-008",
    }

    assert all(
        rows[requirement_id]["status"] == "partially implemented"
        for requirement_id in conservative_ids
    )
    assert all(
        row["status"] == "partially implemented"
        for requirement_id, row in rows.items()
        if requirement_id.startswith("SM-TX-")
    )


def test_traceability_bundle_points_to_its_first_containing_commit() -> None:
    rows = {
        row["id"]: row for row in json.loads(MANIFEST.read_text(encoding="utf-8"))["requirements"]
    }

    assert rows["USR-002"]["status"] == "partially implemented"
    assert rows["USR-002"]["last_verified_commit"] == "1f1c6a243e51b5552bcdb1304af8bf0a486f7de7"
    assert rows["USR-002"]["last_verified_date"] == "2026-07-22"


def test_current_only_traceability_path_cannot_claim_baseline_commit(tmp_path: Path) -> None:
    def mutate(value: dict[str, Any]) -> None:
        row = next(row for row in value["requirements"] if row["id"] == "USR-002")
        row["last_verified_commit"] = "a7292ea9ca157fdcb76369d9e61977c7316c8782"
        row["last_verified_date"] = "2026-07-22"

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 1
    assert "evidence path is absent from its verified commit" in completed.stderr


def test_current_only_test_name_cannot_claim_baseline_commit(tmp_path: Path) -> None:
    def mutate(value: dict[str, Any]) -> None:
        row = next(row for row in value["requirements"] if row["id"] == "USR-002")
        row["implementation_evidence"] = ["agentkernel/canonical.py"]
        row["verification_evidence"] = [
            "test_traceability_bundle_points_to_its_first_containing_commit"
        ]
        row["last_verified_commit"] = "a7292ea9ca157fdcb76369d9e61977c7316c8782"
        row["last_verified_date"] = "2026-07-22"

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 1
    assert "evidence test is absent from its verified commit" in completed.stderr


def test_test_name_prefix_collision_matches_neither_working_tree_nor_commit(
    tmp_path: Path,
) -> None:
    claimed_prefix = "test_" + "mapping_order_and_unicode_normalization_are"

    def mutate(value: dict[str, Any]) -> None:
        row = next(row for row in value["requirements"] if row["id"] == "USR-002")
        row["implementation_evidence"] = ["agentkernel/canonical.py"]
        row["verification_evidence"] = [claimed_prefix]
        row["last_verified_commit"] = "a7292ea9ca157fdcb76369d9e61977c7316c8782"
        row["last_verified_date"] = "2026-07-22"

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 1
    assert "evidence references a missing test" in completed.stderr
    assert "evidence test is absent from its verified commit" in completed.stderr


def test_paths_present_in_baseline_commit_are_accepted(tmp_path: Path) -> None:
    def mutate(value: dict[str, Any]) -> None:
        row = next(row for row in value["requirements"] if row["id"] == "USR-002")
        row["implementation_evidence"] = ["agentkernel/canonical.py"]
        row["verification_evidence"] = ["tests/unit/test_canonical.py"]
        row["last_verified_commit"] = "a7292ea9ca157fdcb76369d9e61977c7316c8782"
        row["last_verified_date"] = "2026-07-22"

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 0, completed.stderr


def test_last_verified_commit_and_date_pairing_is_required(tmp_path: Path) -> None:
    def mutate(value: dict[str, Any]) -> None:
        row = next(row for row in value["requirements"] if row["id"] == "USR-002")
        row["last_verified_commit"] = "a7292ea9ca157fdcb76369d9e61977c7316c8782"
        row["last_verified_date"] = ""

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 1
    assert "last verified commit/date must be paired" in completed.stderr


@pytest.mark.parametrize("location", ["root", "metadata", "row", "source"])
def test_json_schema_rejects_additional_properties(tmp_path: Path, location: str) -> None:
    def mutate(value: dict[str, Any]) -> None:
        targets = {
            "root": value,
            "metadata": value["metadata"],
            "row": value["requirements"][0],
            "source": value["requirements"][0]["source"],
        }
        targets[location]["unexpected"] = True

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 1
    assert "JSON Schema violation" in completed.stderr
    assert "additionalProperties" in completed.stderr


@pytest.mark.parametrize(
    ("field", "invalid"),
    [("project", 42), ("source_sha256", 42), ("source_line_count", "3241")],
)
def test_json_schema_rejects_invalid_metadata_types(
    tmp_path: Path, field: str, invalid: Any
) -> None:
    def mutate(value: dict[str, Any]) -> None:
        value["metadata"][field] = invalid

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 1
    assert f"$.metadata.{field}" in completed.stderr


def test_line_start_must_not_exceed_line_end(tmp_path: Path) -> None:
    def mutate(value: dict[str, Any]) -> None:
        source = value["requirements"][0]["source"]
        source["line_start"] = source["line_end"] + 1

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 1
    assert "source line range is outside the specification" in completed.stderr


@pytest.mark.parametrize("target", ["metadata", "row"])
def test_format_checker_rejects_invalid_iso_dates(tmp_path: Path, target: str) -> None:
    def mutate(value: dict[str, Any]) -> None:
        if target == "metadata":
            value["metadata"]["baseline_date"] = "2026-02-31"
        else:
            row = next(
                row for row in value["requirements"] if row["status"] == "implemented and verified"
            )
            row["last_verified_date"] = "2026-02-31"

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 1
    assert "(format)" in completed.stderr


def test_verified_commit_must_be_existing_40_hex_commit(tmp_path: Path) -> None:
    def mutate(value: dict[str, Any]) -> None:
        row = next(
            row for row in value["requirements"] if row["status"] == "implemented and verified"
        )
        row["last_verified_commit"] = "0" * 40

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 1
    assert "not an existing 40-hex commit" in completed.stderr


@pytest.mark.parametrize(
    ("evidence", "expected"),
    [
        ("placeholder", "placeholder or is not meaningful"),
        ("tests/does_not_exist.py", "missing repository path"),
        ("https://user:password@example.com/proof", "unreasonable URL"),
    ],
)
def test_verified_evidence_rejects_placeholders_missing_paths_and_credential_urls(
    tmp_path: Path, evidence: str, expected: str
) -> None:
    def mutate(value: dict[str, Any]) -> None:
        row = next(
            row for row in value["requirements"] if row["status"] == "implemented and verified"
        )
        row["implementation_evidence"] = [evidence]

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 1
    assert expected in completed.stderr


def test_invalid_status_and_missing_blocker_fields_are_schema_rejected(tmp_path: Path) -> None:
    invalid_status = _mutated_manifest(
        tmp_path,
        lambda value: value["requirements"][0].__setitem__("status", "done"),
        name="invalid-status.json",
    )

    def block_without_reason(value: dict[str, Any]) -> None:
        row = next(row for row in value["requirements"] if row["status"] == "missing")
        row["status"] = "blocked"

    invalid_blocker = _mutated_manifest(tmp_path, block_without_reason, name="invalid-blocker.json")

    assert "$.requirements[0].status" in _run(manifest=invalid_status).stderr
    blocker_result = _run(manifest=invalid_blocker)
    assert "blocker_reason" in blocker_result.stderr
    assert "blocker_action" in blocker_result.stderr


def test_verified_status_requires_evidence_and_verification_provenance(tmp_path: Path) -> None:
    def mutate(value: dict[str, Any]) -> None:
        row = next(row for row in value["requirements"] if row["status"] == "missing")
        row["status"] = "implemented and verified"

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 1
    assert "implementation_evidence" in completed.stderr
    assert "verification_evidence" in completed.stderr
    assert "last_verified_commit" in completed.stderr
    assert "last_verified_date" in completed.stderr


def test_personal_path_in_evidence_is_rejected_without_echoing_it(tmp_path: Path) -> None:
    def mutate(value: dict[str, Any]) -> None:
        row = next(row for row in value["requirements"] if row["status"] == "partially implemented")
        row["implementation_evidence"] = ["/home/private-user/proof.txt"]

    completed = _run(manifest=_mutated_manifest(tmp_path, mutate))

    assert completed.returncode == 1
    assert "exposes a personal path" in completed.stderr
    assert "private-user" not in completed.stderr


def test_duplicate_or_missing_frozen_ids_are_rejected(tmp_path: Path) -> None:
    def duplicate(value: dict[str, Any]) -> None:
        value["requirements"].append(deepcopy(value["requirements"][0]))

    duplicate_result = _run(manifest=_mutated_manifest(tmp_path, duplicate, name="duplicate.json"))

    def remove_ak(value: dict[str, Any]) -> None:
        value["requirements"] = [row for row in value["requirements"] if row["id"] != "AK-077"]

    missing_result = _run(manifest=_mutated_manifest(tmp_path, remove_ak, name="missing.json"))

    assert "duplicate IDs" in duplicate_result.stderr
    assert "AK catalog must contain exactly AK-001..AK-077" in missing_result.stderr


def test_renaming_id_in_manifest_and_registry_cannot_rebase_frozen_epoch(tmp_path: Path) -> None:
    replacement = "METRIC-REPORT-99"

    def rename_manifest(value: dict[str, Any]) -> None:
        value["requirements"][-1]["id"] = replacement

    def rename_registry(value: dict[str, Any]) -> None:
        value["ids"][-1] = replacement

    completed = _run(
        manifest=_mutated_manifest(tmp_path, rename_manifest),
        registry=_mutated_registry(tmp_path, rename_registry),
    )

    assert completed.returncode == 1
    assert "frozen epoch prefix was removed, renamed, or reordered" in completed.stderr
    assert "external mandatory-ID map does not cover" in completed.stderr


def test_external_policy_digest_prevents_simultaneous_policy_rewrite(tmp_path: Path) -> None:
    def mutate(value: dict[str, Any]) -> None:
        value["mandatory_by_id"]["AK-001"] = False
        value["optional_ids"].append("AK-001")

    completed = _run(policy=_mutated_policy(tmp_path, mutate))

    assert completed.returncode == 1
    assert "policy digest differs from the frozen validator constant" in completed.stderr


def test_tombstone_cannot_delete_or_invent_an_id(tmp_path: Path) -> None:
    def mutate(value: dict[str, Any]) -> None:
        value["tombstones"] = [
            {
                "id": "REMOVED-ID",
                "reason": "Superseded by a clearer atomic requirement",
                "retired_date": "2026-07-22",
                "replacement_id": None,
            }
        ]

    completed = _run(registry=_mutated_registry(tmp_path, mutate))

    assert completed.returncode == 1
    assert "tombstoned IDs must remain" in completed.stderr


def test_generator_rejects_registry_rename_or_reorder(tmp_path: Path) -> None:
    registry = _mutated_registry(
        tmp_path,
        lambda value: value["ids"].__setitem__(0, "REL-RENAMED"),
    )
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(GENERATOR),
            "--spec",
            str(SPEC),
            "--manifest",
            str(tmp_path / "generated.json"),
            "--registry",
            str(registry),
            "--policy",
            str(POLICY),
            "--markdown",
            str(tmp_path / "generated.md"),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 1
    assert "Append-only ID violation" in completed.stderr


def test_generator_accepts_only_prefix_append_from_legacy_registry(tmp_path: Path) -> None:
    value = json.loads(REGISTRY.read_text(encoding="utf-8"))
    value.pop("frozen_epoch")
    value["ids"] = value["ids"][:-1]
    registry = _write_json(tmp_path / "legacy-registry.json", value)
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(GENERATOR),
            "--spec",
            str(SPEC),
            "--manifest",
            str(tmp_path / "generated.json"),
            "--registry",
            str(registry),
            "--policy",
            str(POLICY),
            "--markdown",
            str(tmp_path / "generated.md"),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(registry.read_text(encoding="utf-8"))["ids"][-1] == "METRIC-REPORT-08"


def test_generator_and_validator_reject_modified_specification(tmp_path: Path) -> None:
    tampered = tmp_path / SPEC.name
    tampered.write_bytes(SPEC.read_bytes() + b"\n")
    validator_result = _run(spec=tampered)
    generator_result = subprocess.run(  # noqa: S603
        [sys.executable, str(GENERATOR), "--spec", str(tampered)],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )

    assert "not the frozen audited revision" in validator_result.stderr
    assert generator_result.returncode == 1
    assert "Specification digest mismatch" in generator_result.stderr


def test_source_quote_and_section_tampering_is_rejected(tmp_path: Path) -> None:
    for requirement_id, field in (("REL-R01-D02", "quote"), ("INV-SEC-01", "section")):

        def mutate(
            value: dict[str, Any], requirement_id: str = requirement_id, field: str = field
        ) -> None:
            row = next(row for row in value["requirements"] if row["id"] == requirement_id)
            row["source"][field] += " tampered"

        completed = _run(
            manifest=_mutated_manifest(tmp_path, mutate, name=f"{requirement_id}.json")
        )

        assert completed.returncode == 1
        assert f"{requirement_id}: source" in completed.stderr


def test_benchmark_ranges_metrics_and_dataset_schema_are_atomic_and_missing() -> None:
    value = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in value["requirements"]}
    ranges = [(1372, 1378), (1380, 1386), (1388, 1394), (1396, 1402), (1404, 1410), (1412, 1418)]
    for index, expected_range in enumerate(ranges, 1):
        row = rows[f"BENCH-ENV-{index:02d}"]
        assert (row["source"]["line_start"], row["source"]["line_end"]) == expected_range
        assert all(
            label in row["summary"] for label in ("Capabilities:", "Tasks:", "Objective checks:")
        )

    expected_metric_ids = {
        *(f"METRIC-PROD-{index:02d}" for index in range(1, 14)),
        *(f"METRIC-OPS-{index:02d}" for index in range(1, 11)),
        *(f"METRIC-SEC-{index:02d}" for index in range(1, 9)),
        *(f"METRIC-REPORT-{index:02d}" for index in range(1, 9)),
    }
    assert len(expected_metric_ids) == 39
    assert all(
        rows[requirement_id]["status"] == "missing" for requirement_id in expected_metric_ids
    )
    assert rows["DATA-SCHEMA-01"]["source"]["line_start"] == 1712
    assert rows["DATA-SCHEMA-01"]["status"] == "missing"


def test_source_quotes_preserve_em_dash_without_mojibake() -> None:
    rows = {
        row["id"]: row for row in json.loads(MANIFEST.read_text(encoding="utf-8"))["requirements"]
    }
    for requirement_id in ("AK-071", "AK-077"):
        assert "—" in rows[requirement_id]["source"]["quote"]
        assert "\u0101\u20ac\u201d" not in rows[requirement_id]["source"]["quote"]


def test_golden_regeneration_is_byte_identical(tmp_path: Path) -> None:
    registry = tmp_path / REGISTRY.name
    policy = tmp_path / POLICY.name
    shutil.copyfile(REGISTRY, registry)
    shutil.copyfile(POLICY, policy)
    generated_manifest = tmp_path / MANIFEST.name
    generated_markdown = tmp_path / MARKDOWN.name
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(GENERATOR),
            "--spec",
            str(SPEC),
            "--manifest",
            str(generated_manifest),
            "--registry",
            str(registry),
            "--policy",
            str(policy),
            "--markdown",
            str(generated_markdown),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert generated_manifest.read_bytes() == MANIFEST.read_bytes()
    assert registry.read_bytes() == REGISTRY.read_bytes()
    assert generated_markdown.read_bytes() == MARKDOWN.read_bytes()


def test_generated_public_artifacts_use_canonical_lf_bytes() -> None:
    for path in (MANIFEST, REGISTRY, POLICY, MARKDOWN):
        assert b"\r\n" not in path.read_bytes(), path.name
