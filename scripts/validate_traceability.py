# ruff: noqa: E501, PERF401, T201
"""Validate AgentKernel's frozen requirements traceability baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import date
from functools import cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_NAME = "AgentKernel_Full_Project_Specification.md"
EXPECTED_SPEC_SHA256 = "b5bef98ca2397b87cff8a87f950488dc6f224610fa0d40b6d8bbf63d5f626bd8"
EXPECTED_SPEC_LINE_COUNT = 3241
EXPECTED_POLICY_SHA256 = "538a4cc18de1b0daab293ea5e90f3f7676f6f88e706850a5991440acbe2782d4"
FROZEN_EPOCH_NAME = "specification-baseline-2026-07-22"
FROZEN_EPOCH_COUNT = 806
FROZEN_EPOCH_IDS_SHA256 = "63faa9fe58c474f437e13e7d852460ae6b9a3ced1034bcdea482d720a3e7165b"
BASELINE_COMMIT = "a7292ea9ca157fdcb76369d9e61977c7316c8782"
TOMBSTONE_POLICY = (
    "append-only; existing IDs remain ordered forever; retirement adds a tombstone "
    "without deleting the row or changing its mandatory classification"
)
DEFAULT_MANIFEST = REPO_ROOT / "requirements" / "traceability.json"
DEFAULT_REGISTRY = REPO_ROOT / "requirements" / "id-registry.json"
DEFAULT_POLICY = REPO_ROOT / "requirements" / "traceability-policy.json"
DEFAULT_SCHEMA = REPO_ROOT / "requirements" / "traceability.schema.json"
DEFAULT_SPEC = REPO_ROOT / "requirements" / "source" / SPEC_NAME
DEFAULT_MARKDOWN = REPO_ROOT / "docs" / "project" / "requirements-traceability.md"

ALLOWED_STATUSES = {
    "implemented and verified",
    "partially implemented",
    "missing",
    "blocked",
}
PHASE_IDS = {"REL-P0", "REL-R01", "REL-R02", "REL-R03", "REL-R04", "REL-R10"}
ROADMAP_COUNTS = {
    "REL-P0": 14,
    "REL-R01": 21,
    "REL-R02": 16,
    "REL-R03": 14,
    "REL-R04": 14,
    "REL-R10": 14,
}
PERSONAL_PATH = re.compile(
    r"(?i)(?:[a-z]:[\\/]+users[\\/]+[^\\/\s]+|/(?:users|home)/[^/\s]+|\\\\[^\\\s]+\\(?:users|home)\\[^\\\s]+)"
)
PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|tbd|todo|fixme|n/?a|none|unknown|placeholder|fake(?:\s+evidence)?|later|future(?:\s+work)?)$"
)
URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+")
REPO_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.-])((?:(?:agentkernel|tests|docs|requirements|schemas|scripts|policies|\.github)/[A-Za-z0-9_./-]+)|(?:README|SECURITY|CONTRIBUTING|GOVERNANCE|ROADMAP|CODE_OF_CONDUCT|NOTICE|LICENSE|CITATION)\.(?:md|cff)|pyproject\.toml|uv\.lock)"
)
TEST_REFERENCE_PATTERN = re.compile(r"\btest_[a-zA-Z0-9_]+\b(?!\.py)")
GIT_EXECUTABLE = shutil.which("git")


def _numbered(prefix: str, count: int) -> set[str]:
    return {f"{prefix}{index:02d}" for index in range(1, count + 1)}


COMPONENT_IDS = {
    "COMP-SVC-KERNELAPI",
    "COMP-SVC-AUTHORITYSERVICE",
    "COMP-SVC-POLICYSERVICE",
    "COMP-SVC-TRANSACTIONSERVICE",
    "COMP-SVC-EXECUTIONBROKER",
    "COMP-SVC-MODELGATEWAY",
    "COMP-SVC-EVIDENCESERVICE",
    "COMP-SVC-APPROVALSERVICE",
    "COMP-SVC-REPLAYSERVICE",
    "COMP-SVC-BENCHMARKSERVICE",
    "COMP-SVC-TRACEWORLDSERVICE",
    "COMP-ADAPTER-FILESYSTEM",
    "COMP-ADAPTER-PROCESS",
    "COMP-ADAPTER-GIT",
    "COMP-ADAPTER-SQLITE",
    "COMP-ADAPTER-POSTGRES",
    "COMP-ADAPTER-HTTP",
    "COMP-ADAPTER-EMAIL",
    "COMP-ADAPTER-BROWSER",
    "COMP-HARNESS-A1",
    "COMP-HARNESS-A2",
    "COMP-MODEL-LOCAL",
    "COMP-MODEL-EXTERNAL",
    "COMP-STORE-SQLITE",
    "COMP-STORE-POSTGRES",
    "COMP-ARTIFACT-LOCAL",
    "COMP-ARTIFACT-S3",
    "COMP-SANDBOX-DOCKER",
    "COMP-SANDBOX-PLUGGABLE",
    "COMP-INTEGRATION-MCP",
    "COMP-INTEGRATION-SDK",
    "COMP-RECOVERY-SCANNER",
    "COMP-SAGA",
    "COMP-Z3",
    "COMP-TRACEWORLD",
}

EXPECTED_CATALOG_IDS = set().union(
    _numbered("SM-TX-", 38),
    _numbered("SM-ACT-", 23),
    _numbered("POL-AGG-", 12),
    _numbered("SAGA-ORDER-", 9),
    _numbered("SAGA-AGG-", 8),
    _numbered("COMP-API-", 8),
    COMPONENT_IDS,
    {f"EXP-H{index}" for index in range(1, 7)},
    _numbered("EXP-DISC-", 8),
    _numbered("BENCH-ENV-", 6),
    _numbered("BENCH-BASE-", 6),
    _numbered("BENCH-VAR-", 7),
    _numbered("CLI-", 17),
    _numbered("DOC-REQ-", 12),
    _numbered("DOC-QG-", 7),
    _numbered("OPS-STORE-", 10),
    _numbered("OPS-SVC-", 10),
    _numbered("OPS-DASH-", 8),
    _numbered("OPS-DR-", 6),
    _numbered("OPS-COMPAT-", 6),
    _numbered("PKG-SUPPLY-", 8),
    _numbered("PKG-REL-", 4),
    _numbered("NFR-PERF-", 5),
    _numbered("NFR-REL-", 4),
    _numbered("NFR-USE-", 4),
    {"NFR-PORT-01"},
    _numbered("TEST-UNIT-", 8),
    _numbered("TEST-PROP-", 7),
    _numbered("TEST-INT-", 9),
    _numbered("TEST-SEC-", 12),
    _numbered("TEST-REPLAY-", 5),
    _numbered("TEST-STATIC-", 7),
    _numbered("TEST-CI-", 7),
    _numbered("TEST-EVID-", 7),
    {"TEST-CONTRACT-01", "TEST-CHAOS-01", "TEST-E2E-01"},
    _numbered("DATA-UNIT-", 11),
    _numbered("DATA-SRC-", 5),
    _numbered("DATA-PRIV-", 7),
    _numbered("DATA-QG-", 8),
    {"DATA-SCHEMA-01"},
    _numbered("TRACE-STAGE-", 7),
    _numbered("TRACE-METRIC-", 10),
    {f"USR-{index:03d}" for index in range(1, 26)},
    _numbered("METRIC-PROD-", 13),
    _numbered("METRIC-OPS-", 10),
    _numbered("METRIC-SEC-", 8),
    _numbered("METRIC-REPORT-", 8),
)
if len(EXPECTED_CATALOG_IDS) != 446:
    raise RuntimeError(f"Internal expected catalog set has {len(EXPECTED_CATALOG_IDS)} IDs")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ids_digest(ids: Sequence[str]) -> str:
    return _sha256("\n".join(ids).encode("utf-8"))


def _load_json_bytes(path: Path) -> tuple[Any, bytes]:
    try:
        raw = path.read_bytes()
        return json.loads(raw.decode("utf-8")), raw
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read JSON {path.name}: {exc.__class__.__name__}") from exc


def _load_json(path: Path) -> Any:
    return _load_json_bytes(path)[0]


def _json_path(parts: Sequence[Any]) -> str:
    result = "$"
    for part in parts:
        result += f"[{part}]" if isinstance(part, int) else f".{part}"
    return result


def _validate_schema(manifest: Any, schema_path: Path, errors: list[str]) -> bool:
    try:
        schema = _load_json(schema_path)
        Draft202012Validator.check_schema(schema)
    except (ValueError, SchemaError) as exc:
        errors.append(f"Cannot apply traceability JSON Schema: {exc.__class__.__name__}")
        return False
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    schema_errors = sorted(validator.iter_errors(manifest), key=lambda error: list(error.path))
    for error in schema_errors:
        errors.append(
            f"JSON Schema violation at {_json_path(list(error.absolute_path))} ({error.validator})"
        )
    return not schema_errors


def _valid_iso_date(value: str) -> bool:
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


@cache
def _commit_exists(commit: str) -> bool:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None or GIT_EXECUTABLE is None:
        return False
    completed = subprocess.run(  # noqa: S603
        [GIT_EXECUTABLE, "-C", str(REPO_ROOT), "cat-file", "-e", f"{commit}^{{commit}}"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    return completed.returncode == 0


@cache
def _commit_tree_paths(commit: str) -> tuple[str, ...]:
    if GIT_EXECUTABLE is None or not _commit_exists(commit):
        return ()
    completed = subprocess.run(  # noqa: S603
        [
            GIT_EXECUTABLE,
            "-C",
            str(REPO_ROOT),
            "ls-tree",
            "-r",
            "--name-only",
            commit,
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    return tuple(completed.stdout.splitlines()) if completed.returncode == 0 else ()


@cache
def _path_exists_at_commit(commit: str, relative_path: str) -> bool:
    normalized = relative_path.rstrip("/")
    return any(
        path == normalized or path.startswith(f"{normalized}/")
        for path in _commit_tree_paths(commit)
    )


@cache
def _test_references_at_commit(commit: str) -> frozenset[str]:
    if GIT_EXECUTABLE is None or not _commit_exists(commit):
        return frozenset()
    completed = subprocess.run(  # noqa: S603
        [
            GIT_EXECUTABLE,
            "-C",
            str(REPO_ROOT),
            "grep",
            "-h",
            "-I",
            "-e",
            "test_",
            commit,
            "--",
            "tests",
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        return frozenset()
    return frozenset(TEST_REFERENCE_PATTERN.findall(completed.stdout))


@cache
def _working_test_references() -> frozenset[str]:
    text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((REPO_ROOT / "tests").rglob("*.py"))
    )
    return frozenset(TEST_REFERENCE_PATTERN.findall(text))


def _test_reference_exists_at_commit(commit: str, reference: str) -> bool:
    return reference in _test_references_at_commit(commit)


def _validate_evidence_text(
    value: str, requirement_id: str, commit: str, errors: list[str]
) -> None:
    cleaned = value.strip()
    if len(cleaned) < 8 or PLACEHOLDER.fullmatch(cleaned):
        errors.append(f"{requirement_id}: evidence contains a placeholder or is not meaningful")
        return
    for raw_url in URL_PATTERN.findall(cleaned):
        parsed = urlparse(raw_url.rstrip(".,;:)"))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
            errors.append(f"{requirement_id}: evidence contains an unreasonable URL")
    for match in REPO_PATH_PATTERN.finditer(cleaned):
        relative = match.group(1).rstrip(".,;:)")
        candidate = (REPO_ROOT / Path(relative)).resolve()
        try:
            candidate.relative_to(REPO_ROOT)
        except ValueError:
            errors.append(f"{requirement_id}: evidence path escapes the repository")
            continue
        if not candidate.exists():
            errors.append(f"{requirement_id}: evidence references a missing repository path")
        if commit and not _path_exists_at_commit(commit, Path(relative).as_posix()):
            errors.append(f"{requirement_id}: evidence path is absent from its verified commit")
    if TEST_REFERENCE_PATTERN.search(cleaned):
        working_references = _working_test_references()
        for reference in TEST_REFERENCE_PATTERN.findall(cleaned):
            if reference not in working_references:
                errors.append(f"{requirement_id}: evidence references a missing test")
            if commit and not _test_reference_exists_at_commit(commit, reference):
                errors.append(f"{requirement_id}: evidence test is absent from its verified commit")


def _validate_statuses(rows: Sequence[dict[str, Any]], errors: list[str]) -> None:
    for row in rows:
        requirement_id = row["id"]
        status = row["status"]
        implementation = row["implementation_evidence"]
        verification = row["verification_evidence"]
        if status not in ALLOWED_STATUSES:
            errors.append(f"{requirement_id}: invalid status")
            continue
        if status == "implemented and verified":
            if not implementation:
                errors.append(f"{requirement_id}: verified status requires implementation evidence")
            if not verification:
                errors.append(f"{requirement_id}: verified status requires verification evidence")
        if status == "partially implemented" and not implementation:
            errors.append(f"{requirement_id}: partial status requires implementation evidence")
        if status == "blocked":
            if not row["blocker_reason"] or not row["blocker_action"]:
                errors.append(f"{requirement_id}: blocked status requires reason and action")
        elif row["blocker_reason"] or row["blocker_action"]:
            errors.append(f"{requirement_id}: non-blocked row must not carry blocker fields")

        commit = row["last_verified_commit"]
        verified_date = row["last_verified_date"]
        if bool(commit) != bool(verified_date):
            errors.append(f"{requirement_id}: last verified commit/date must be paired")
        if commit and not _commit_exists(commit):
            errors.append(
                f"{requirement_id}: last verified commit is not an existing 40-hex commit"
            )
        if verified_date and not _valid_iso_date(verified_date):
            errors.append(f"{requirement_id}: last verified date is not a valid ISO date")
        for evidence in (*implementation, *verification):
            _validate_evidence_text(evidence, requirement_id, commit, errors)


def _validate_ids(rows: Sequence[dict[str, Any]], errors: list[str]) -> set[str]:
    ids = [row["id"] for row in rows]
    counts = Counter(ids)
    duplicates = sorted(value for value, count in counts.items() if count > 1)
    if duplicates:
        errors.append(f"duplicate IDs: {duplicates}")
    id_set = set(ids)
    for row in rows:
        requirement_id = row["id"]
        for related in row["related_ids"]:
            if related not in id_set:
                errors.append(f"{requirement_id}: related ID does not exist")
        for dependency in row["dependencies"]:
            if (
                dependency.startswith(("REL-", "AK-", "INV-", "DOD-", "NEG-", "USR-"))
                and dependency not in id_set
            ):
                errors.append(f"{requirement_id}: dependency ID does not exist")
    return id_set


def _validate_source_counts(rows: Sequence[dict[str, Any]], errors: list[str]) -> None:
    source_rows = [row for row in rows if row["baseline_source_row"]]
    if len(source_rows) != 360:
        errors.append(f"baseline source row count must be 360, found {len(source_rows)}")

    normative = [
        row for row in source_rows if row["normative_class"] in {"MUST", "MUST NOT", "SHALL"}
    ]
    normative_counts = Counter(row["normative_class"] for row in normative)
    expected_normative = {"MUST": 117, "MUST NOT": 32, "SHALL": 1}
    if len(normative) != 150 or dict(normative_counts) != expected_normative:
        errors.append("normative source occurrence counts differ from the frozen baseline")
    if any(row["source"]["line_start"] == 12 for row in normative):
        errors.append("normative keyword-definition line 12 must be excluded")
    if any(re.fullmatch(r"NORM-S\d{2}-\d{3}", row["id"]) is None for row in normative):
        errors.append("every normative occurrence ID must match NORM-Sxx-NNN")

    phase_rows = [row for row in source_rows if row["normative_class"] == "phase-or-release"]
    if {row["id"] for row in phase_rows} != PHASE_IDS:
        errors.append("phase/release parent IDs differ from the frozen set")

    roadmap = [
        row
        for row in source_rows
        if row["normative_class"] in {"roadmap-deliverable", "roadmap-exit-gate"}
    ]
    if len(roadmap) != 93:
        errors.append(f"roadmap child row count must be 93, found {len(roadmap)}")
    actual_roadmap: defaultdict[str, int] = defaultdict(int)
    for row in roadmap:
        parent_match = re.fullmatch(r"(REL-(?:P0|R01|R02|R03|R04|R10))-[DG]\d{2}", row["id"])
        if parent_match is None:
            errors.append(f"invalid roadmap child ID: {row['id']}")
        else:
            actual_roadmap[parent_match.group(1)] += 1
    if dict(actual_roadmap) != ROADMAP_COUNTS:
        errors.append("roadmap distribution differs from the frozen baseline")

    expected_ak = {f"AK-{index:03d}" for index in range(1, 78)}
    actual_ak = {row["id"] for row in source_rows if re.fullmatch(r"AK-\d{3}", row["id"])}
    if actual_ak != expected_ak:
        errors.append("AK catalog must contain exactly AK-001..AK-077")
    for prefix, count in (("INV-SEC-", 14), ("NEG-REL-", 10), ("DOD-", 10)):
        actual = {row["id"] for row in source_rows if row["id"].startswith(prefix)}
        if actual != _numbered(prefix, count):
            errors.append(f"{prefix} IDs differ from the frozen set")


def _validate_catalogs(rows: Sequence[dict[str, Any]], errors: list[str]) -> None:
    actual = {row["id"] for row in rows if not row["baseline_source_row"]}
    if actual != EXPECTED_CATALOG_IDS:
        errors.append(
            "catalog IDs differ from the exact frozen set: "
            f"missing={sorted(EXPECTED_CATALOG_IDS - actual)}, extra={sorted(actual - EXPECTED_CATALOG_IDS)}"
        )


def _validate_policy(
    policy_path: Path, rows: Sequence[dict[str, Any]], errors: list[str]
) -> dict[str, bool]:
    try:
        policy_value, raw = _load_json_bytes(policy_path)
    except ValueError as exc:
        errors.append(str(exc))
        return {}
    if _sha256(raw) != EXPECTED_POLICY_SHA256:
        errors.append(
            "external mandatory-ID policy digest differs from the frozen validator constant"
        )
    if not isinstance(policy_value, dict):
        errors.append("external mandatory-ID policy root must be an object")
        return {}
    expected_keys = {
        "schema_version",
        "source_sha256",
        "frozen_epoch",
        "id_order_sha256",
        "optional_ids",
        "mandatory_by_id",
    }
    if set(policy_value) != expected_keys:
        errors.append("external mandatory-ID policy fields differ from the frozen schema")
    if policy_value.get("schema_version") != "1.0.0":
        errors.append("external mandatory-ID policy version is unsupported")
    if policy_value.get("source_sha256") != EXPECTED_SPEC_SHA256:
        errors.append("external mandatory-ID policy references an unaudited specification")
    expected_epoch = {
        "name": FROZEN_EPOCH_NAME,
        "count": FROZEN_EPOCH_COUNT,
        "ids_sha256": FROZEN_EPOCH_IDS_SHA256,
    }
    if policy_value.get("frozen_epoch") != expected_epoch:
        errors.append("external mandatory-ID policy frozen epoch differs from the validator")
    mandatory = policy_value.get("mandatory_by_id")
    if not isinstance(mandatory, dict) or any(
        not isinstance(key, str) or not isinstance(value, bool) for key, value in mandatory.items()
    ):
        errors.append("external mandatory-ID map must map IDs to booleans")
        return {}
    ids = [row["id"] for row in rows]
    if set(mandatory) != set(ids):
        errors.append("external mandatory-ID map does not cover the exact manifest ID set")
    if policy_value.get("id_order_sha256") != _ids_digest(ids):
        errors.append("manifest ID order differs from the external mandatory-ID policy")
    optional_ids = policy_value.get("optional_ids")
    expected_optional = [
        requirement_id for requirement_id in ids if not mandatory.get(requirement_id, True)
    ]
    if optional_ids != expected_optional:
        errors.append("external optional-ID list differs from its mandatory map")
    for row in rows:
        if mandatory.get(row["id"]) != row["mandatory"]:
            errors.append(f"{row['id']}: manifest mandatory flag differs from external policy")
    return mandatory


def _validate_metadata(
    manifest: Mapping[str, Any],
    rows: Sequence[dict[str, Any]],
    mandatory_by_id: Mapping[str, bool],
    errors: list[str],
) -> None:
    metadata = manifest["metadata"]
    if metadata["source_sha256"] != EXPECTED_SPEC_SHA256:
        errors.append("metadata source digest differs from the audited specification")
    if metadata["source_line_count"] != EXPECTED_SPEC_LINE_COUNT:
        errors.append("metadata source line count differs from the audited specification")
    if metadata["baseline_commit"] != BASELINE_COMMIT or not _commit_exists(
        metadata["baseline_commit"]
    ):
        errors.append("metadata baseline commit is not the frozen existing commit")
    if not _valid_iso_date(metadata["baseline_date"]):
        errors.append("metadata baseline date is not a valid ISO date")
    if metadata["allowed_statuses"] != [
        "implemented and verified",
        "partially implemented",
        "missing",
        "blocked",
    ]:
        errors.append("metadata allowed statuses differ from the exact four-state vocabulary")
    source_count = sum(row["baseline_source_row"] for row in rows)
    if metadata["source_row_count"] != source_count:
        errors.append("metadata source row count does not match rows")
    if metadata["catalog_row_count"] != len(rows) - source_count:
        errors.append("metadata catalog row count does not match rows")
    if metadata["total_row_count"] != len(rows):
        errors.append("metadata total row count does not match rows")
    status_counts = Counter(row["status"] for row in rows)
    expected_statuses = {
        status: status_counts[status] for status in manifest["metadata"]["allowed_statuses"]
    }
    if metadata["status_counts"] != expected_statuses:
        errors.append("metadata status counts do not match rows")
    rows_by_id = {row["id"]: row for row in rows}
    complete = bool(mandatory_by_id) and all(
        not mandatory
        or rows_by_id.get(requirement_id, {}).get("status") == "implemented and verified"
        for requirement_id, mandatory in mandatory_by_id.items()
    )
    expected_readiness = "PASS" if complete else "FAIL"
    if metadata["release_readiness"] != expected_readiness:
        errors.append("release readiness disagrees with the external mandatory-ID policy")


def _validate_tombstones(
    tombstones: Any,
    ids: Sequence[str],
    mandatory_by_id: Mapping[str, bool],
    errors: list[str],
) -> None:
    if not isinstance(tombstones, list):
        errors.append("registry tombstones must be an array")
        return
    seen: set[str] = set()
    id_set = set(ids)
    for entry in tombstones:
        if not isinstance(entry, dict) or set(entry) != {
            "id",
            "reason",
            "retired_date",
            "replacement_id",
        }:
            errors.append("registry tombstone fields are invalid")
            continue
        retired_id = entry.get("id")
        if (
            not isinstance(retired_id, str)
            or retired_id not in id_set
            or retired_id not in mandatory_by_id
        ):
            errors.append("tombstoned IDs must remain in the registry, manifest, and mandatory map")
            continue
        if retired_id in seen:
            errors.append("registry contains a duplicate tombstone")
        seen.add(retired_id)
        if not isinstance(entry.get("reason"), str) or len(entry["reason"].strip()) < 8:
            errors.append("registry tombstone requires a meaningful reason")
        retired_date = entry.get("retired_date")
        if not isinstance(retired_date, str) or not _valid_iso_date(retired_date):
            errors.append("registry tombstone requires a valid ISO date")
        replacement = entry.get("replacement_id")
        if replacement is not None and (
            not isinstance(replacement, str)
            or replacement == retired_id
            or replacement not in id_set
        ):
            errors.append("registry tombstone replacement is invalid")


def _validate_registry(
    registry_path: Path,
    rows: Sequence[dict[str, Any]],
    mandatory_by_id: Mapping[str, bool],
    errors: list[str],
) -> None:
    try:
        registry = _load_json(registry_path)
    except ValueError as exc:
        errors.append(str(exc))
        return
    if not isinstance(registry, dict):
        errors.append("ID registry root must be an object")
        return
    expected_keys = {
        "schema_version",
        "policy",
        "baseline_commit",
        "source_sha256",
        "frozen_epoch",
        "ids",
        "baseline_source_ids",
        "tombstones",
    }
    if set(registry) != expected_keys:
        errors.append("ID registry fields differ from the required append-only format")
    if registry.get("schema_version") != "1.1.0" or registry.get("policy") != TOMBSTONE_POLICY:
        errors.append("ID registry version or tombstone policy is invalid")
    if (
        registry.get("baseline_commit") != BASELINE_COMMIT
        or registry.get("source_sha256") != EXPECTED_SPEC_SHA256
    ):
        errors.append("ID registry baseline provenance differs from frozen constants")
    ids = registry.get("ids")
    if not isinstance(ids, list) or any(not isinstance(value, str) for value in ids):
        errors.append("ID registry must contain an IDs array of strings")
        return
    expected_epoch = {
        "name": FROZEN_EPOCH_NAME,
        "count": FROZEN_EPOCH_COUNT,
        "ids_sha256": FROZEN_EPOCH_IDS_SHA256,
    }
    if registry.get("frozen_epoch") != expected_epoch:
        errors.append("ID registry frozen epoch metadata differs from validator constants")
    if (
        len(ids) < FROZEN_EPOCH_COUNT
        or _ids_digest(ids[:FROZEN_EPOCH_COUNT]) != FROZEN_EPOCH_IDS_SHA256
    ):
        errors.append("ID registry frozen epoch prefix was removed, renamed, or reordered")
    manifest_ids = [row["id"] for row in rows]
    if ids != manifest_ids:
        errors.append("manifest ID order/content differs from append-only ID registry")
    if len(ids) != len(set(ids)):
        errors.append("ID registry contains duplicate IDs")
    baseline_ids = [row["id"] for row in rows if row["baseline_source_row"]]
    if registry.get("baseline_source_ids") != baseline_ids:
        errors.append("baseline source IDs differ from the ID registry")
    _validate_tombstones(registry.get("tombstones"), ids, mandatory_by_id, errors)


def _strings(value: Any) -> Sequence[str]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, dict):
        return tuple(item for child in value.values() for item in _strings(child))
    if isinstance(value, list):
        return tuple(item for child in value for item in _strings(child))
    return ()


def _validate_public_content(values: Sequence[Any], markdown_path: Path, errors: list[str]) -> None:
    for value in values:
        if any(PERSONAL_PATH.search(item) for item in _strings(value)):
            errors.append("public traceability data exposes a personal path")
            break
    try:
        markdown = markdown_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        errors.append("cannot read generated traceability Markdown")
    else:
        if PERSONAL_PATH.search(markdown):
            errors.append("generated traceability Markdown exposes a personal path")


def _heading_sections(lines: Sequence[str]) -> list[str]:
    sections: list[str] = []
    top = "Document preamble"
    sub = top
    for raw in lines:
        top_match = re.match(r"^## (\d+)\.\s+(.*)$", raw)
        appendix_match = re.match(r"^## Appendix ([A-Z]):\s*(.*)$", raw)
        sub_match = re.match(r"^#{3,6}\s+(.+)$", raw)
        if top_match:
            top = f"{int(top_match.group(1))}. {re.sub(r'\s+', ' ', top_match.group(2).strip())}"
            sub = top
        elif appendix_match:
            top = f"Appendix {appendix_match.group(1)}: {re.sub(r'\s+', ' ', appendix_match.group(2).strip())}"
            sub = top
        elif sub_match:
            sub = re.sub(r"\s+", " ", sub_match.group(1).strip())
        sections.append(sub)
    return sections


def _split_table(raw: str) -> list[str]:
    return [re.sub(r"\s+", " ", cell.strip()) for cell in raw.strip().strip("|").split("|")]


def _validate_semantic_catalog_rows(
    rows_by_id: Mapping[str, dict[str, Any]], lines: Sequence[str], errors: list[str]
) -> None:
    bench_ranges = {
        "BENCH-ENV-01": (1372, 1378),
        "BENCH-ENV-02": (1380, 1386),
        "BENCH-ENV-03": (1388, 1394),
        "BENCH-ENV-04": (1396, 1402),
        "BENCH-ENV-05": (1404, 1410),
        "BENCH-ENV-06": (1412, 1418),
    }
    for requirement_id, (start, end) in bench_ranges.items():
        row = rows_by_id.get(requirement_id)
        if row is None:
            continue
        title = re.sub(r"^####\s+17\.2\.\d+\s+", "", lines[start - 1]).strip()
        expected_summary = f"{title}: " + " ".join(
            re.sub(r"\s+", " ", lines[line_number - 1].strip())
            for line_number in (start + 2, start + 4, end)
        )
        if row["source"]["line_start"] != start or row["source"]["line_end"] != end:
            errors.append(
                f"{requirement_id}: benchmark source range omits capability/task/check data"
            )
        if row["summary"] != expected_summary:
            errors.append(f"{requirement_id}: benchmark summary omits capability/task/check data")

    data_schema = rows_by_id.get("DATA-SCHEMA-01")
    if data_schema is not None and (
        data_schema["source"]["line_start"] != 1712
        or data_schema["source"]["line_end"] != 1712
        or data_schema["summary"] != re.sub(r"\s+", " ", lines[1711].strip())
    ):
        errors.append("DATA-SCHEMA-01 does not map exactly to the schema/migration requirement")

    metric_ranges = (
        ("METRIC-PROD-", 2450, 13, True),
        ("METRIC-OPS-", 2466, 10, False),
        ("METRIC-SEC-", 2479, 8, False),
        ("METRIC-REPORT-", 2490, 8, False),
    )
    for prefix, first_line, count, table in metric_ranges:
        for index in range(1, count + 1):
            requirement_id = f"{prefix}{index:02d}"
            row = rows_by_id.get(requirement_id)
            if row is None:
                continue
            line_number = first_line + index - 1
            expected_summary = (
                ": ".join(_split_table(lines[line_number - 1]))
                if table
                else re.sub(r"\s+", " ", lines[line_number - 1][2:].strip())
            )
            if (
                row["source"]["line_start"] != line_number
                or row["source"]["line_end"] != line_number
                or row["summary"] != expected_summary
                or row["status"] == "implemented and verified"
            ):
                errors.append(
                    f"{requirement_id}: metric mapping/status differs from the atomic source row"
                )


def _validate_spec(
    manifest: Mapping[str, Any], rows: Sequence[dict[str, Any]], spec_path: Path, errors: list[str]
) -> None:
    try:
        source_bytes = spec_path.read_bytes()
        source_text = source_bytes.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        errors.append(f"cannot read specification: {exc.__class__.__name__}")
        return
    digest = _sha256(source_bytes)
    if digest != EXPECTED_SPEC_SHA256:
        errors.append("provided specification is not the frozen audited revision")
    if manifest["metadata"]["source_sha256"] != digest:
        errors.append("specification digest does not match manifest metadata")
    lines = source_text.splitlines()
    if len(lines) != EXPECTED_SPEC_LINE_COUNT or manifest["metadata"]["source_line_count"] != len(
        lines
    ):
        errors.append("specification line count does not match the frozen revision")
    sections = _heading_sections(lines)
    for row in rows:
        source = row["source"]
        if source["kind"] != "specification":
            continue
        start = source["line_start"]
        end = source["line_end"]
        requirement_id = row["id"]
        if start < 1 or end < start or end > len(lines):
            errors.append(f"{requirement_id}: source line range is outside the specification")
            continue
        expected_quote = re.sub(r"\s+", " ", " ".join(lines[start - 1 : end]).strip())
        if source["quote"] != expected_quote:
            errors.append(f"{requirement_id}: source quote does not match lines {start}..{end}")
        if source["section"] != sections[start - 1]:
            errors.append(f"{requirement_id}: source section does not match its line")
        if source["document"] != SPEC_NAME:
            errors.append(f"{requirement_id}: source document name is not canonical")

    occurrences: list[tuple[int, str, int, str]] = []
    pattern = re.compile(r"\b(?:MUST NOT|MUST|SHALL)\b")
    for line_number, raw in enumerate(lines, 1):
        if line_number == 12:
            continue
        for occurrence, match in enumerate(pattern.finditer(raw), 1):
            occurrences.append(
                (line_number, match.group(0), occurrence, re.sub(r"\s+", " ", raw.strip()))
            )
    if len(occurrences) != 150 or Counter(item[1] for item in occurrences) != Counter(
        {"MUST": 117, "MUST NOT": 32, "SHALL": 1}
    ):
        errors.append("source normative occurrence positions differ from the frozen revision")
    manifest_norm = [
        (
            row["source"]["line_start"],
            row["source"]["keyword"],
            row["source"]["occurrence"],
            row["source"]["quote"],
        )
        for row in rows
        if row["normative_class"] in {"MUST", "MUST NOT", "SHALL"}
    ]
    if manifest_norm != occurrences:
        errors.append("manifest normative source mapping differs from specification occurrences")
    source_ak = {match.group(1) for raw in lines if (match := re.match(r"^\| (AK-\d{3}) \|", raw))}
    if source_ak != {f"AK-{index:03d}" for index in range(1, 78)}:
        errors.append("source specification no longer contains exactly AK-001..AK-077")
    _validate_semantic_catalog_rows({row["id"]: row for row in rows}, lines, errors)


def validate(
    manifest_path: Path,
    registry_path: Path,
    *,
    policy_path: Path = DEFAULT_POLICY,
    schema_path: Path = DEFAULT_SCHEMA,
    spec_path: Path | None = DEFAULT_SPEC,
    markdown_path: Path = DEFAULT_MARKDOWN,
    require_complete: bool = False,
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    try:
        manifest = _load_json(manifest_path)
    except ValueError as exc:
        return [str(exc)], {}
    if not _validate_schema(manifest, schema_path, errors):
        return errors, manifest if isinstance(manifest, dict) else {}
    if not isinstance(manifest, dict):
        return ["manifest root must be an object"], {}
    rows = manifest["requirements"]
    _validate_ids(rows, errors)
    _validate_statuses(rows, errors)
    _validate_source_counts(rows, errors)
    _validate_catalogs(rows, errors)
    mandatory_by_id = _validate_policy(policy_path, rows, errors)
    _validate_metadata(manifest, rows, mandatory_by_id, errors)
    _validate_registry(registry_path, rows, mandatory_by_id, errors)
    policy_value = _load_json(policy_path) if policy_path.is_file() else {}
    registry_value = _load_json(registry_path) if registry_path.is_file() else {}
    _validate_public_content((manifest, policy_value, registry_value), markdown_path, errors)
    if spec_path is not None:
        _validate_spec(manifest, rows, spec_path, errors)
    if require_complete and mandatory_by_id:
        rows_by_id = {row["id"]: row for row in rows}
        incomplete = [
            requirement_id
            for requirement_id, mandatory in mandatory_by_id.items()
            if mandatory
            and rows_by_id.get(requirement_id, {}).get("status") != "implemented and verified"
        ]
        if incomplete:
            errors.append(
                f"release gate incomplete: {len(incomplete)} mandatory requirements are not implemented and verified"
            )
    return errors, manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)
    errors, manifest = validate(
        args.manifest,
        args.registry,
        policy_path=args.policy,
        schema_path=args.schema,
        spec_path=args.spec,
        markdown_path=args.markdown,
        require_complete=args.require_complete,
    )
    metadata = manifest.get("metadata", {}) if isinstance(manifest, dict) else {}
    result = {
        "validation": "FAIL" if errors else "PASS",
        "release_readiness": metadata.get("release_readiness", "UNKNOWN"),
        "source_rows": metadata.get("source_row_count"),
        "catalog_rows": metadata.get("catalog_row_count"),
        "total_rows": metadata.get("total_row_count"),
        "errors": errors,
    }
    if args.json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif errors:
        print("Traceability validation: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
    else:
        print(
            "Traceability validation: PASS; "
            f"release readiness: {result['release_readiness']}; "
            f"rows: {result['source_rows']} source + {result['catalog_rows']} catalog/user = {result['total_rows']}"
        )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
