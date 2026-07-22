# ruff: noqa: E501, S106, T201
"""Build the AgentKernel requirements traceability baseline from specification data.

The specification is input data, not executable instructions.  This script deliberately
extracts only requirements-oriented structures and writes public artifacts without embedding
the source machine path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ALLOWED_STATUSES = (
    "implemented and verified",
    "partially implemented",
    "missing",
    "blocked",
)
SPEC_NAME = "AgentKernel_Full_Project_Specification.md"
EXPECTED_SPEC_SHA256 = "b5bef98ca2397b87cff8a87f950488dc6f224610fa0d40b6d8bbf63d5f626bd8"
DEFAULT_SPEC_PATH = Path("requirements/source") / SPEC_NAME
BASELINE_COMMIT = "a7292ea9ca157fdcb76369d9e61977c7316c8782"
BASELINE_DATE = "2026-07-22"
CI_EVIDENCE = "GitHub Actions CI run 29852865780 succeeded on " + BASELINE_COMMIT
CODEQL_ALERT = (
    "GitHub code-scanning alert #1 (py/clear-text-storage-sensitive-data) is open at high "
    "severity on main as of 2026-07-22"
)


@dataclass(frozen=True)
class Evidence:
    status: str
    implementation: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()
    last_verified_commit: str = ""
    last_verified_date: str = ""


def baseline_verified(*, implementation: Sequence[str], verification: Sequence[str]) -> Evidence:
    return Evidence(
        "implemented and verified",
        tuple(implementation),
        tuple(verification),
        BASELINE_COMMIT,
        BASELINE_DATE,
    )


def baseline_partial(
    *, implementation: Sequence[str], verification: Sequence[str] = ()
) -> Evidence:
    return Evidence(
        "partially implemented",
        tuple(implementation),
        tuple(verification),
        BASELINE_COMMIT if verification else "",
        BASELINE_DATE if verification else "",
    )


def uncommitted_partial(
    *, implementation: Sequence[str], verification: Sequence[str] = ()
) -> Evidence:
    return Evidence("partially implemented", tuple(implementation), tuple(verification))


def committed_partial(
    *,
    implementation: Sequence[str],
    verification: Sequence[str],
    commit: str,
    verified_date: str,
) -> Evidence:
    return Evidence(
        "partially implemented",
        tuple(implementation),
        tuple(verification),
        commit,
        verified_date,
    )


MISSING = Evidence("missing")


def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _find_line(lines: Sequence[str], marker: str, *, start: int = 1) -> int:
    for line_number in range(start, len(lines) + 1):
        if marker in lines[line_number - 1]:
            return line_number
    raise ValueError(f"Source marker was not found: {marker!r}")


def _heading_context(lines: Sequence[str]) -> tuple[list[str], list[str]]:
    sections: list[str] = []
    codes: list[str] = []
    top = "Document preamble"
    sub = top
    code = "S00"
    for raw in lines:
        top_match = re.match(r"^## (\d+)\.\s+(.*)$", raw)
        appendix_match = re.match(r"^## Appendix ([A-Z]):\s*(.*)$", raw)
        sub_match = re.match(r"^#{3,6}\s+(.+)$", raw)
        if top_match:
            number = int(top_match.group(1))
            code = f"S{number:02d}"
            top = f"{number}. {_clean(top_match.group(2))}"
            sub = top
        elif appendix_match:
            number = 40 + (ord(appendix_match.group(1)) - ord("A"))
            code = f"S{number:02d}"
            top = f"Appendix {appendix_match.group(1)}: {_clean(appendix_match.group(2))}"
            sub = top
        elif sub_match:
            sub = _clean(sub_match.group(1))
        sections.append(sub)
        codes.append(code)
    return sections, codes


def _source(
    lines: Sequence[str],
    sections: Sequence[str],
    line_number: int | None,
    *,
    line_end: int | None = None,
    quote: str | None = None,
    keyword: str | None = None,
    occurrence: int | None = None,
    document: str = SPEC_NAME,
    kind: str = "specification",
) -> dict[str, Any]:
    if line_number is None:
        section = "Authoritative user objective"
        normalized_quote = _clean(quote or "")
        resolved_end = None
    else:
        section = sections[line_number - 1]
        resolved_end = line_end or line_number
        normalized_quote = _clean(
            quote if quote is not None else " ".join(lines[line_number - 1 : resolved_end])
        )
    return {
        "kind": kind,
        "document": document,
        "section": section,
        "line_start": line_number,
        "line_end": resolved_end,
        "keyword": keyword,
        "occurrence": occurrence,
        "quote": normalized_quote,
    }


def _category_for_section(section: str) -> str:
    match = re.match(r"(\d+)", section)
    number = int(match.group(1)) if match else 0
    if number in {8, 10, 11, 21, 22}:
        return "runtime-and-transactions"
    if number in {9, 23, 31}:
        return "architecture-and-engineering"
    if number in {12, 13, 25}:
        return "security-authority-and-policy"
    if number in {14, 15, 16}:
        return "sandbox-replay-and-faults"
    if number in {17, 26, 27}:
        return "benchmark-and-verification"
    if number in {18, 19, 20}:
        return "traceworld-and-data"
    if number in {28, 29, 30}:
        return "operations-and-public-usability"
    if number in {24, 35, 36, 39}:
        return "release-and-acceptance"
    if number in {32, 33, 34}:
        return "risk-and-nonfunctional"
    return "product-and-governance"


def _release_for_section(section: str) -> list[str]:
    if section.startswith("13"):
        return ["R03", "R10"]
    if section.startswith(("18", "19", "20")):
        return ["R04", "R10"]
    if section.startswith(("17", "22")):
        return ["R02", "R10"]
    if section.startswith(("14", "15", "16")):
        return ["R01", "R02", "R10"]
    if section.startswith(("28", "29", "30", "33", "34")):
        return ["R10"]
    return ["R10"]


def _components_for_text(text: str) -> list[str]:
    lowered = text.lower()
    candidates = {
        "adapter": "adapters",
        "capabilit": "authority",
        "policy": "policy",
        "transaction": "transactions",
        "saga": "transactions/saga",
        "journal": "storage/journal",
        "sandbox": "sandbox",
        "model": "model-gateway-or-traceworld",
        "traceworld": "traceworld",
        "benchmark": "benchmark",
        "dataset": "dataset",
        "replay": "replay",
        "event": "evidence",
        "artifact": "artifacts",
        "cli": "cli",
        "documentation": "documentation",
        "secret": "secret-handling",
        "z3": "policy/z3",
        "solver": "policy/z3",
        "worker": "execution-worker",
        "harness": "agent-harness",
        "recovery": "recovery",
    }
    result = [value for key, value in candidates.items() if key in lowered]
    return sorted(set(result)) or ["project"]


def _profiles_for_text(text: str) -> list[str]:
    found = re.findall(r"(?<!\w)A[0-5]\+?(?!\w)", text)
    return sorted(set(found)) or ["all-applicable"]


def _platforms_for_text(text: str) -> list[str]:
    lowered = text.lower()
    platforms: list[str] = []
    for needle, value in (
        ("linux", "linux"),
        ("windows", "windows"),
        ("docker", "docker"),
        ("kubernetes", "kubernetes"),
        ("postgres", "postgresql"),
        ("sqlite", "sqlite"),
        ("s3", "s3-compatible"),
    ):
        if needle in lowered:
            platforms.append(value)
    return sorted(set(platforms)) or ["platform-neutral"]


def _row(
    *,
    requirement_id: str,
    summary: str,
    mandatory: bool,
    normative_class: str,
    category: str,
    source: dict[str, Any],
    release_gate: Sequence[str],
    component: Sequence[str],
    profile: Sequence[str] = ("all-applicable",),
    platform: Sequence[str] = ("platform-neutral",),
    dependencies: Sequence[str] = (),
    pass_condition: str | None = None,
    verification_method: str = "Automated test or explicitly named review artifact",
    artifact: Sequence[str] = ("Retained test/review evidence",),
    evidence: Evidence = MISSING,
    related_ids: Sequence[str] = (),
    baseline_source_row: bool = False,
) -> dict[str, Any]:
    return {
        "id": requirement_id,
        "summary": _clean(summary),
        "mandatory": mandatory,
        "normative_class": normative_class,
        "category": category,
        "source": source,
        "release_gate": list(release_gate),
        "component": list(component),
        "profile": list(profile),
        "platform": list(platform),
        "dependencies": list(dependencies),
        "pass_condition": _clean(pass_condition or summary),
        "verification_method": verification_method,
        "artifact": list(artifact),
        "implementation_evidence": list(evidence.implementation),
        "verification_evidence": list(evidence.verification),
        "status": evidence.status,
        "blocker_reason": "",
        "blocker_action": "",
        "related_ids": list(related_ids),
        "last_verified_commit": evidence.last_verified_commit,
        "last_verified_date": evidence.last_verified_date,
        "baseline_source_row": baseline_source_row,
    }


NORM_EVIDENCE: dict[tuple[int, int], Evidence] = {
    (27, 1): baseline_verified(
        implementation=(
            "README.md; docs/concepts/assurance-levels.md; docs/security/threat-model.md",
        ),
        verification=("Manual claim-boundary review of the baseline documentation",),
    ),
    (31, 1): baseline_partial(
        implementation=(
            "Python 3.12/uv/Pydantic/asyncio/SQLite/local artifacts/Docker are present",
        ),
        verification=(CI_EVIDENCE,),
    ),
    (42, 1): baseline_partial(
        implementation=("agentkernel/sandbox/docker.py exposes a bounded Docker backend",),
        verification=(
            "tests/unit/test_docker_backend_unit.py; tests/integration/test_docker_sandbox.py",
        ),
    ),
    (43, 1): baseline_verified(
        implementation=("agentkernel/canonical.py; docs/adr/0001-canonical-json.md",),
        verification=("tests/unit/test_canonical.py; tests/unit/test_ledger.py",),
    ),
    (49, 2): baseline_partial(
        implementation=(
            "README.md and docs/adr/0002-project-and-distribution-names.md disclaim affiliation; the required public-release name checks are not retained as evidence",
        ),
        verification=("Manual baseline documentation review",),
    ),
    (84, 1): baseline_partial(
        implementation=(
            "The no-key scripted runtime path is present; AgentKernel Bench is absent",
        ),
        verification=("tests/end_to_end/test_no_key_demo.py",),
    ),
    (84, 2): baseline_partial(
        implementation=("Documentation makes TraceWorld advisory; TraceWorld is not implemented",),
        verification=("Manual review of README.md and docs/architecture.md",),
    ),
    (104, 1): baseline_partial(
        implementation=(
            "A0 path rejects missing authority; no confined A1+ enforcement path exists",
        ),
        verification=("tests/unit/test_authority.py; tests/end_to_end/test_no_key_demo.py",),
    ),
    (157, 1): baseline_partial(
        implementation=("Deterministic authority/policy checks exist in the A0 path",),
        verification=("tests/unit/test_authority.py; tests/unit/test_policy.py",),
    ),
    (179, 1): baseline_verified(
        implementation=("README.md and threat model explicitly reject universal-safety claims",),
        verification=("Manual baseline documentation review",),
    ),
    (179, 2): baseline_verified(
        implementation=("docs/concepts/assurance-levels.md declares backend/profile boundaries",),
        verification=("Manual baseline documentation review",),
    ),
    (319, 1): baseline_partial(
        implementation=("RiskClass and adapter manifests exist for current adapters",),
        verification=(
            "tests/contract/test_mock_adapter.py; tests/contract/test_filesystem_adapter.py",
        ),
    ),
    (335, 1): baseline_partial(
        implementation=(
            "agentkernel/transactions/state_machine.py and versioned domain enums/schemas encode the structural rules; a durable CAS-plus-event proof for every transition is absent",
        ),
        verification=("tests/unit/test_state_machine.py; tests/unit/test_models.py",),
    ),
    (378, 1): baseline_partial(
        implementation=(
            "IN_DOUBT and STALE_STATE exist; general redispatch/recovery scanner is absent",
        ),
        verification=("tests/integration/test_coordinator.py",),
    ),
    (522, 1): baseline_partial(
        implementation=("Current coordinator revalidates target version and adapter identity",),
        verification=("tests/integration/test_coordinator.py",),
    ),
    (532, 1): baseline_partial(
        implementation=(
            "Current filesystem/mock path discards stale staged work and links a retry",
        ),
        verification=("test_target_drift_aborts_as_stale_before_commit_dispatch",),
    ),
    (532, 2): baseline_partial(
        implementation=("Unversioned blind promotion is rejected in the current adapter path",),
        verification=("test_target_drift_aborts_as_stale_before_commit_dispatch",),
    ),
    (647, 1): baseline_partial(
        implementation=(
            "Strict Pydantic contracts and filesystem canonicalization exist; network normalization does not",
        ),
        verification=("tests/unit/test_models.py; tests/unit/test_filesystem_snapshots.py",),
    ),
    (659, 1): baseline_partial(
        implementation=(
            "Traversal, symlink/junction, case-fold and replacement checks exist for filesystem scope",
        ),
        verification=(
            "tests/unit/test_filesystem_snapshots.py; tests/contract/test_filesystem_adapter.py",
        ),
    ),
    (688, 1): baseline_partial(
        implementation=(
            "Typed adapter lifecycle exists for mock and filesystem; full adapter set is absent",
        ),
        verification=(
            "tests/contract/test_mock_adapter.py; tests/contract/test_filesystem_adapter.py",
        ),
    ),
    (703, 1): baseline_partial(
        implementation=(
            "Durable CAS coordinator covers the current single-action A0 path; scanner/saga are absent",
        ),
        verification=(
            "tests/integration/test_coordinator.py; tests/integration/test_sqlite_journal.py",
        ),
    ),
    (719, 1): baseline_partial(
        implementation=("Mock and filesystem execute paths preserve authoritative state",),
        verification=(
            "tests/contract/test_mock_adapter.py; tests/contract/test_filesystem_adapter.py",
        ),
    ),
    (719, 2): baseline_partial(
        implementation=("Explicit commit is the authoritative boundary for current adapters",),
        verification=("test_explicit_commit_is_the_only_authoritative_effect",),
    ),
    (737, 1): baseline_partial(
        implementation=("Filesystem content-addressed snapshots and typed diffs exist",),
        verification=("tests/unit/test_filesystem_snapshots.py",),
    ),
    (769, 1): baseline_partial(
        implementation=(
            "Coordinator aborts current staged work on UNKNOWN verification; the ERROR branch is not equivalently proven",
        ),
        verification=("test_unknown_verification_fails_closed",),
    ),
    (819, 2): baseline_partial(
        implementation=(
            "Local demo uses ScriptedLocalModel and contains no TraceWorld dependency; model failure, timeout, and absence fallbacks are not all implemented and tested",
        ),
        verification=(
            "tests/security/test_model_gateway.py; tests/end_to_end/test_no_key_demo.py",
        ),
    ),
    (837, 2): baseline_partial(
        implementation=(
            "Model message parts retain provenance; durable external budget/retry path is absent",
        ),
        verification=("tests/security/test_model_gateway.py",),
    ),
    (1147, 1): baseline_verified(
        implementation=("README and assurance docs call the Docker backend container isolation",),
        verification=("Manual baseline documentation review",),
    ),
    (1168, 1): baseline_verified(
        implementation=("DockerSandbox inspects effective controls and fails closed",),
        verification=(
            "tests/unit/test_docker_backend_unit.py; tests/integration/test_docker_sandbox.py",
        ),
    ),
    (1225, 1): baseline_partial(
        implementation=("Versioned append-only EventEnvelope and SQLite event storage exist",),
        verification=("tests/unit/test_ledger.py; tests/integration/test_sqlite_journal.py",),
    ),
    (1247, 1): baseline_partial(
        implementation=(
            "Canonical event hashing includes schema version; distributed causal sets/signing are absent",
        ),
        verification=("tests/unit/test_ledger.py",),
    ),
    (1266, 2): baseline_partial(
        implementation=("Current demo and CLI paths redact synthetic secrets",),
        verification=("tests/unit/test_cli.py; tests/end_to_end/test_no_key_demo.py",),
    ),
    (1278, 1): baseline_partial(
        implementation=(
            "The scripted demo replay report records L1 action comparison and divergences; L2 environment reconstruction is absent",
        ),
        verification=("tests/end_to_end/test_no_key_demo.py",),
    ),
    (1288, 1): baseline_partial(
        implementation=(
            "The scripted demo replay is non-authoritative and has no external dispatch",
        ),
        verification=("tests/end_to_end/test_no_key_demo.py",),
    ),
    (1288, 2): baseline_partial(
        implementation=(
            "No external-effect replay implementation exists in the current bounded path",
        ),
        verification=("tests/end_to_end/test_no_key_demo.py",),
    ),
    (1358, 1): baseline_partial(
        implementation=("The current demonstration uses synthetic local canaries",),
        verification=("tests/end_to_end/test_no_key_demo.py",),
    ),
    (1358, 2): baseline_partial(
        implementation=(
            "No public benchmark exists; existing fixtures contain no live destination",
        ),
        verification=("Manual baseline fixture review",),
    ),
    (1816, 1): baseline_verified(
        implementation=("TransactionSession requires explicit commit and aborts on context exit",),
        verification=("test_context_exit_without_commit_aborts_and_preserves_target",),
    ),
    (1859, 1): baseline_partial(
        implementation=(
            "Adapter protocol declares unsupported semantics for the current adapters",
        ),
        verification=(
            "tests/contract/test_mock_adapter.py; tests/contract/test_filesystem_adapter.py",
        ),
    ),
    (1859, 2): baseline_partial(
        implementation=("Unsupported semantics fail with typed errors in the current adapter set",),
        verification=(
            "tests/contract/test_mock_adapter.py; tests/contract/test_filesystem_adapter.py",
        ),
    ),
    (1861, 2): baseline_partial(
        implementation=("Context exit abort is covered; the full crash-boundary matrix is absent",),
        verification=("test_context_exit_without_commit_aborts_and_preserves_target",),
    ),
    (2320, 1): baseline_verified(
        implementation=(
            "docs/security/threat-model.md documents hash-chain suffix-deletion limits",
        ),
        verification=("Manual baseline threat-model review",),
    ),
    (2324, 1): baseline_verified(
        implementation=(
            "SECURITY.md contains private reporting, supported versions, targets, disclosure, safe harbor, and severity",
        ),
        verification=("Manual baseline SECURITY.md review",),
    ),
    (2505, 1): baseline_verified(
        implementation=("README local quick start requires no cloud account or API key",),
        verification=("tests/end_to_end/test_no_key_demo.py; " + CI_EVIDENCE,),
    ),
    (2802, 1): baseline_verified(
        implementation=(
            "Current demo report emits assurance_profile=A0 and doctor avoids containment claims",
        ),
        verification=("tests/end_to_end/test_no_key_demo.py; tests/unit/test_cli.py",),
    ),
    (3138, 1): baseline_partial(
        implementation=(
            "A harmless deterministic local demo exists; the under-one-minute public release proof is not retained",
        ),
        verification=("tests/end_to_end/test_no_key_demo.py",),
    ),
}


PHASES = (
    ("REL-P0", "Phase 0", "P0"),
    ("REL-R01", "Release 0.1", "R01"),
    ("REL-R02", "Release 0.2", "R02"),
    ("REL-R03", "Release 0.3", "R03"),
    ("REL-R04", "Release 0.4", "R04"),
    ("REL-R10", "Release 1.0", "R10"),
)


PHASE_EVIDENCE: dict[str, Evidence] = {
    "REL-P0": baseline_verified(
        implementation=("All Phase 0 deliverables and gates listed below are present",),
        verification=("Focused Phase 0 tests plus " + CI_EVIDENCE,),
    ),
    "REL-R01": baseline_partial(
        implementation=(
            "Filesystem A0 vertical slice, local model gateway, and Docker control probe exist",
        ),
        verification=("README.md status table and baseline tests",),
    ),
}


PHASE0_ROADMAP_EVIDENCE: dict[str, Evidence] = {
    "REL-P0-D01": baseline_verified(
        implementation=(
            "README.md; docs/architecture.md; docs/security/threat-model.md; docs/adr/0000-template.md; CONTRIBUTING.md; SECURITY.md",
        ),
        verification=("Manual baseline documentation inventory",),
    ),
    "REL-P0-D02": baseline_verified(
        implementation=(
            "pyproject.toml; uv.lock; scripts/check.sh; scripts/check.ps1; .github/workflows",
        ),
        verification=(CI_EVIDENCE,),
    ),
    "REL-P0-D03": baseline_verified(
        implementation=("agentkernel/domain/models.py; schemas/v1alpha1",),
        verification=("tests/unit/test_models.py; tests/unit/test_exported_schemas.py",),
    ),
    "REL-P0-D04": baseline_verified(
        implementation=("agentkernel/transactions/state_machine.py",),
        verification=("tests/unit/test_state_machine.py",),
    ),
    "REL-P0-D05": baseline_verified(
        implementation=("agentkernel/adapters/base.py; agentkernel/adapters/mock.py",),
        verification=("tests/contract/test_mock_adapter.py",),
    ),
    "REL-P0-D06": baseline_verified(
        implementation=("agentkernel/canonical.py; agentkernel/evidence/artifacts.py",),
        verification=("tests/unit/test_canonical.py; tests/unit/test_artifacts.py",),
    ),
    "REL-P0-D07": baseline_verified(
        implementation=("agentkernel/storage/sqlite.py",),
        verification=("test_wal_migrations_and_records_survive_reopen",),
    ),
    "REL-P0-D08": baseline_verified(
        implementation=("agentkernel/errors.py; agentkernel/cli.py",),
        verification=("tests/unit/test_cli.py; tests/unit/test_models.py",),
    ),
    "REL-P0-D09": baseline_verified(
        implementation=("Layered package boundaries",),
        verification=("tests/architecture/test_import_boundaries.py",),
    ),
    "REL-P0-G01": baseline_verified(
        implementation=("Versioned Pydantic models and deterministic schema export",),
        verification=("tests/unit/test_models.py; tests/unit/test_exported_schemas.py",),
    ),
    "REL-P0-G02": baseline_verified(
        implementation=("Normative transition table rejects unlisted transitions",),
        verification=("tests/unit/test_state_machine.py",),
    ),
    "REL-P0-G03": baseline_verified(
        implementation=("SHA-256 hash-chained event ledger",),
        verification=("tests/unit/test_ledger.py",),
    ),
    "REL-P0-G04": baseline_verified(
        implementation=("Pinned Linux CI workflow and locked environment",),
        verification=(CI_EVIDENCE,),
    ),
    "REL-P0-G05": baseline_verified(
        implementation=("Adapter protocol and registry-bound effect modules",),
        verification=(
            "tests/architecture/test_import_boundaries.py; tests/contract/test_mock_adapter.py",
        ),
    ),
}


ROADMAP_EVIDENCE: dict[str, Evidence] = {
    **PHASE0_ROADMAP_EVIDENCE,
    "REL-R01-D01": baseline_partial(
        implementation=("Filesystem adapter exists; allowlisted process adapter is absent",),
        verification=("tests/contract/test_filesystem_adapter.py",),
    ),
    "REL-R01-D03": baseline_partial(
        implementation=(
            "agentkernel/model_gateway/gateway.py provides deterministic scripted inference and hard-disabled external dispatch; a real local/offline model backend is absent",
        ),
        verification=("tests/security/test_model_gateway.py",),
    ),
    "REL-R01-D04": baseline_verified(
        implementation=("Filesystem copy-on-write staging under an out-of-workspace state root",),
        verification=("tests/contract/test_filesystem_adapter.py",),
    ),
    "REL-R01-D05": baseline_partial(
        implementation=(
            "Commit/abort/rollback and durable records exist; recovery scanner is absent",
        ),
        verification=(
            "tests/integration/test_coordinator.py; tests/contract/test_filesystem_adapter.py",
        ),
    ),
    "REL-R01-D06": baseline_verified(
        implementation=("Coarse capability grants and provenance labels",),
        verification=("tests/unit/test_authority.py",),
    ),
    "REL-R01-D07": baseline_verified(
        implementation=("Deterministic policy evaluator and bounded YAML loader",),
        verification=("tests/unit/test_policy.py",),
    ),
    "REL-R01-D08": baseline_verified(
        implementation=("Docker container control backend with network disabled",),
        verification=(
            "tests/unit/test_docker_backend_unit.py; tests/integration/test_docker_sandbox.py",
        ),
    ),
    "REL-R01-D09": baseline_partial(
        implementation=(
            "Event ledger and scripted L1 replay exist; L2 environment reconstruction and general inspect/explain/replay services do not",
        ),
        verification=("tests/unit/test_ledger.py; tests/end_to_end/test_no_key_demo.py",),
    ),
    "REL-R01-D12": baseline_verified(
        implementation=(
            "Deterministic disposable demo repository embeds a synthetic exfiltration instruction",
        ),
        verification=("tests/end_to_end/test_no_key_demo.py",),
    ),
    "REL-R01-D13": baseline_verified(
        implementation=("README quick start and scripted no-key demo",),
        verification=("tests/end_to_end/test_no_key_demo.py; " + CI_EVIDENCE,),
    ),
    "REL-R01-G05": baseline_partial(
        implementation=(
            "Normal filesystem rollback restores a captured workspace digest; rollback after a failed staged or authoritative partial commit is not proven",
        ),
        verification=("test_filesystem_stage_commit_verify_and_rollback",),
    ),
    "REL-R01-G06": baseline_partial(
        implementation=(
            "Scripted L1 replay compares normalized action and final workspace hashes; the demo does not reconstruct a network-disabled environment",
        ),
        verification=("test_no_key_cli_demo_denies_attack_commits_and_replays",),
    ),
    "REL-R01-G07": baseline_verified(
        implementation=("README and assurance documentation label Docker as container isolation",),
        verification=("Manual baseline documentation review",),
    ),
    "REL-R03-D02": baseline_partial(
        implementation=(
            "Coarse provenance labels exist; fine-grained flow/declassification does not",
        ),
        verification=("tests/unit/test_authority.py",),
    ),
    "REL-R03-D05": baseline_partial(
        implementation=("Deterministic policy tests exist; mutation testing/Z3 parity do not",),
        verification=("tests/unit/test_policy.py",),
    ),
    "REL-R03-D07": baseline_partial(
        implementation=("Adapter digest/review admission exists; cryptographic signing does not",),
        verification=("tests/contract/test_mock_adapter.py",),
    ),
    "REL-R10-D07": baseline_partial(
        implementation=("Unsigned wheel/sdist build and checksum automation exists",),
        verification=(".github/workflows/release-build.yml",),
    ),
    "REL-R10-D08": baseline_partial(
        implementation=(
            "Foundation documentation exists; comprehensive guides/integrations do not",
        ),
        verification=("Manual baseline documentation inventory",),
    ),
    "REL-R10-G05": Evidence(
        "missing",
        verification=(CODEQL_ALERT,),
    ),
}


AK_EVIDENCE: dict[str, Evidence] = {
    "AK-002": baseline_partial(
        implementation=(
            "The authority layer rejects a manufactured protected-path proposal before dispatch; an integrated agent-generated attack proposal is not proven",
        ),
        verification=("tests/end_to_end/test_no_key_demo.py; tests/unit/test_authority.py",),
    ),
    "AK-003": baseline_partial(
        implementation=(
            "Project-data provenance cannot expand authority for a manufactured proposal; integrated model/agent consumption of adversarial project data is not proven",
        ),
        verification=("test_project_data_cannot_expand_authority; no-key demo tests",),
    ),
    "AK-004": baseline_partial(
        implementation=(
            "Docker network-none blocks a public-IP probe; full DNS/loopback/metadata matrix is absent",
        ),
        verification=("tests/integration/test_docker_sandbox.py",),
    ),
    "AK-005": baseline_partial(
        implementation=(
            "Filesystem staging applies a staged single-file write on explicit commit; an exact multi-file staged-diff test is absent",
        ),
        verification=("test_filesystem_stage_commit_verify_and_rollback",),
    ),
    "AK-006": baseline_partial(
        implementation=(
            "Pre-commit cancellation/deadline paths avoid authoritative effects, but NEW plus deadline reaches REJECTED rather than the required ABORTING then ABORTED path",
        ),
        verification=("test_every_precommit_state_exits_without_authoritative_effect",),
    ),
    "AK-007": baseline_partial(
        implementation=(
            "Exact filesystem restoration is tested; the named partial-write fault schedule is absent",
        ),
        verification=("test_filesystem_stage_commit_verify_and_rollback",),
    ),
    "AK-008": baseline_partial(
        implementation=(
            "Durable non-terminal records exist; automatic recovery scanner/crash matrix is absent",
        ),
        verification=("tests/integration/test_sqlite_journal.py",),
    ),
    "AK-009": baseline_partial(
        implementation=(
            "SQLite intent reservation has one owner; end-to-end duplicate submission is incomplete",
        ),
        verification=("test_intent_reservation_has_one_owner",),
    ),
    "AK-010": baseline_partial(
        implementation=(
            "Lost acknowledgement durably enters IN_DOUBT; retry/reconcile flow is incomplete",
        ),
        verification=("test_lost_commit_acknowledgement_is_persisted_in_doubt",),
    ),
    "AK-011": baseline_verified(
        implementation=("UNKNOWN staged verification aborts and blocks commit",),
        verification=("test_unknown_verification_fails_closed",),
    ),
    "AK-012": baseline_partial(
        implementation=(
            "The hash-chain validator reports the first modified event in a three-event fixture; the exact completed-trace event-20 criterion is not tested",
        ),
        verification=("test_mutation_reports_first_broken_sequence",),
    ),
    "AK-013": baseline_partial(
        implementation=(
            "The scripted demo compares L1 action/final-state hashes, but does not run L2 environment reconstruction inside OS-level no-egress confinement",
        ),
        verification=("test_no_key_cli_demo_denies_attack_commits_and_replays",),
    ),
    "AK-015": baseline_partial(
        implementation=(
            "Unknown policy fields/predicates and duplicate YAML keys fail; size/depth fuzz gate is absent",
        ),
        verification=("tests/unit/test_policy.py",),
    ),
    "AK-016": baseline_verified(
        implementation=(
            "Current reversible adapters separate stage/execute/commit/verify/rollback",
        ),
        verification=(
            "tests/contract/test_mock_adapter.py; tests/contract/test_filesystem_adapter.py",
        ),
    ),
    "AK-017": baseline_partial(
        implementation=(
            "Synthetic-secret output/evidence checks cover the current demo and selected CLI paths",
        ),
        verification=("tests/unit/test_cli.py; tests/end_to_end/test_no_key_demo.py",),
    ),
    "AK-018": baseline_partial(
        implementation=(
            "Current CI runs quality/security/unit/integration/e2e checks; full R0.1 suites are absent",
        ),
        verification=(CI_EVIDENCE,),
    ),
    "AK-020": baseline_verified(
        implementation=("doctor names missing Docker controls and refuses requested containment",),
        verification=("tests/unit/test_cli.py; tests/unit/test_docker_backend_unit.py",),
    ),
    "AK-025": baseline_verified(
        implementation=("Target drift produces STALE_STATE without promoting the staged effect",),
        verification=("test_target_drift_aborts_as_stale_before_commit_dispatch",),
    ),
    "AK-043": Evidence("missing", verification=(CODEQL_ALERT,)),
    "AK-064": baseline_partial(
        implementation=("An A0 no-key demo works; v1 attack/recovery/replay flow is incomplete",),
        verification=("tests/end_to_end/test_no_key_demo.py",),
    ),
    "AK-067": Evidence("missing", verification=(CODEQL_ALERT,)),
    "AK-068": baseline_partial(
        implementation=(
            "Current documentation scopes A0 claims; future release documentation is absent",
        ),
        verification=("Manual baseline documentation review",),
    ),
    "AK-070": baseline_partial(
        implementation=(
            "Internal prompt succeeds locally and external mock receives zero requests",
        ),
        verification=("tests/security/test_model_gateway.py",),
    ),
    "AK-071": baseline_partial(
        implementation=(
            "Current R1 adapters preserve stage boundary; full crash matrix is absent",
        ),
        verification=("tests/contract; test_lost_commit_acknowledgement_is_persisted_in_doubt",),
    ),
    "AK-073": baseline_partial(
        implementation=(
            "Review admission/digest pinning and TCB documentation exist; A1+ harness does not",
        ),
        verification=("tests/contract/test_mock_adapter.py; docs/security/threat-model.md",),
    ),
    "AK-074": baseline_partial(
        implementation=(
            "Expiry and atomic multi-use budgets exist; signed binding/revocation matrix does not",
        ),
        verification=("tests/unit/test_authority.py",),
    ),
    "AK-075": baseline_partial(
        implementation=(
            "Normative transition table and precommit cancellation paths are tested; crash matrix is absent",
        ),
        verification=("tests/unit/test_state_machine.py; tests/integration/test_coordinator.py",),
    ),
}


def _extract_roadmap(lines: Sequence[str], sections: Sequence[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    expected_counts = {
        "P0": (9, 5),
        "R01": (14, 7),
        "R02": (10, 6),
        "R03": (9, 5),
        "R04": (9, 5),
        "R10": (9, 5),
    }
    heading_markers = {
        "P0": "### Phase 0:",
        "R01": "### Release 0.1:",
        "R02": "### Release 0.2:",
        "R03": "### Release 0.3:",
        "R04": "### Release 0.4:",
        "R10": "### Release 1.0:",
    }
    for phase_id, label, gate in PHASES:
        heading_line = _find_line(lines, heading_markers[gate])
        next_heading = next(
            (
                line_number
                for line_number in range(heading_line + 1, len(lines) + 1)
                if lines[line_number - 1].startswith("### ")
            ),
            len(lines) + 1,
        )
        objective_line = _find_line(lines, "**Objective:**", start=heading_line)
        objective = _clean(lines[objective_line - 1].split("**Objective:**", 1)[1])
        parent_evidence = PHASE_EVIDENCE.get(phase_id, MISSING)
        rows.append(
            _row(
                requirement_id=phase_id,
                summary=f"{label}: {objective}",
                mandatory=True,
                normative_class="phase-or-release",
                category="roadmap-parent",
                source=_source(lines, sections, heading_line),
                release_gate=(gate,),
                component=("project",),
                pass_condition=f"Every mandatory deliverable and exit gate for {label} is implemented and verified",
                verification_method="Aggregate child-row status and retained release evidence",
                artifact=("Release evidence bundle",),
                evidence=parent_evidence,
                related_ids=(),
                baseline_source_row=True,
            )
        )
        deliverable_start = _find_line(lines, "Deliverables:", start=objective_line)
        gate_start = _find_line(lines, "Exit gate:", start=deliverable_start)
        deliverables = [
            (number, _clean(lines[number - 1][2:]))
            for number in range(deliverable_start + 1, gate_start)
            if lines[number - 1].startswith("- ")
        ]
        exits = [
            (number, _clean(lines[number - 1][2:]))
            for number in range(gate_start + 1, next_heading)
            if lines[number - 1].startswith("- ")
        ]
        if (len(deliverables), len(exits)) != expected_counts[gate]:
            raise ValueError(f"Unexpected {gate} roadmap counts: {(len(deliverables), len(exits))}")
        for prefix, items, row_class in (
            ("D", deliverables, "roadmap-deliverable"),
            ("G", exits, "roadmap-exit-gate"),
        ):
            for index, (line_number, summary) in enumerate(items, 1):
                requirement_id = f"{phase_id}-{prefix}{index:02d}"
                mandatory = not summary.lower().startswith("optional ")
                rows.append(
                    _row(
                        requirement_id=requirement_id,
                        summary=summary,
                        mandatory=mandatory,
                        normative_class=row_class,
                        category="roadmap",
                        source=_source(lines, sections, line_number),
                        release_gate=(gate,),
                        component=_components_for_text(summary),
                        profile=_profiles_for_text(summary),
                        platform=_platforms_for_text(summary),
                        dependencies=(phase_id,),
                        pass_condition=summary,
                        artifact=("Milestone implementation and verification evidence",),
                        evidence=ROADMAP_EVIDENCE.get(requirement_id, MISSING),
                        related_ids=(phase_id,),
                        baseline_source_row=True,
                    )
                )
    return rows


def _extract_normative(
    lines: Sequence[str], sections: Sequence[str], codes: Sequence[str]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    counters: defaultdict[str, int] = defaultdict(int)
    pattern = re.compile(r"\b(?:MUST NOT|MUST|SHALL)\b")
    for line_number, text in enumerate(lines, 1):
        if line_number == 12:
            continue
        for occurrence, match in enumerate(pattern.finditer(text), 1):
            code = codes[line_number - 1]
            counters[code] += 1
            requirement_id = f"NORM-{code}-{counters[code]:03d}"
            evidence = NORM_EVIDENCE.get((line_number, occurrence), MISSING)
            related: list[str] = []
            ak_match = re.search(r"AK-\d{3}", text)
            if ak_match:
                related.append(ak_match.group(0))
            rows.append(
                _row(
                    requirement_id=requirement_id,
                    summary=f"{match.group(0)} occurrence {occurrence}: {_clean(text)}",
                    mandatory=True,
                    normative_class=match.group(0),
                    category=_category_for_section(sections[line_number - 1]),
                    source=_source(
                        lines,
                        sections,
                        line_number,
                        keyword=match.group(0),
                        occurrence=occurrence,
                    ),
                    release_gate=_release_for_section(sections[line_number - 1]),
                    component=_components_for_text(text),
                    profile=_profiles_for_text(text),
                    platform=_platforms_for_text(text),
                    pass_condition=text,
                    evidence=evidence,
                    related_ids=related,
                    baseline_source_row=True,
                )
            )
    return rows


def _split_table(raw: str) -> list[str]:
    return [_clean(cell) for cell in raw.strip().strip("|").split("|")]


def _extract_ak(lines: Sequence[str], sections: Sequence[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, raw in enumerate(lines, 1):
        match = re.match(r"^\| (AK-\d{3}) \|", raw)
        if not match:
            continue
        requirement_id = match.group(1)
        number = int(requirement_id[-3:])
        cells = _split_table(raw)
        if len(cells) == 5:
            summary = f"Given {cells[1]}; when {cells[2]}; then {cells[3]}"
            pass_condition = cells[3]
            artifact = (cells[4],)
        else:
            summary = cells[1]
            pass_condition = cells[1]
            artifact = ("Automated criterion evidence",)
        if number <= 20:
            gate = "R01"
            parent = "REL-R01"
        elif number <= 32:
            gate = "R02"
            parent = "REL-R02"
        elif number <= 43:
            gate = "R03"
            parent = "REL-R03"
        elif number <= 56:
            gate = "R04"
            parent = "REL-R04"
        elif number <= 68:
            gate = "R10"
            parent = "REL-R10"
        else:
            gate = "R10"
            parent = "REL-R10"
        related = [parent]
        rows.append(
            _row(
                requirement_id=requirement_id,
                summary=summary,
                mandatory=True,
                normative_class="acceptance-criterion",
                category="acceptance",
                source=_source(lines, sections, line_number),
                release_gate=(gate,),
                component=_components_for_text(raw),
                profile=_profiles_for_text(raw),
                platform=_platforms_for_text(raw),
                dependencies=(parent,),
                pass_condition=pass_condition,
                artifact=artifact,
                evidence=AK_EVIDENCE.get(requirement_id, MISSING),
                related_ids=related,
                baseline_source_row=True,
            )
        )
    return rows


def _numbered_rows_between(
    lines: Sequence[str], start_marker: str, end_marker: str, *, start: int = 1
) -> list[tuple[int, str]]:
    start_line = _find_line(lines, start_marker, start=start)
    end_line = _find_line(lines, end_marker, start=start_line + 1)
    return [
        (line_number, _clean(re.sub(r"^\d+\.\s+", "", lines[line_number - 1])))
        for line_number in range(start_line + 1, end_line)
        if re.match(r"^\d+\.\s+", lines[line_number - 1])
    ]


def _bullet_rows_between(
    lines: Sequence[str], start_marker: str, end_marker: str, *, start: int = 1
) -> list[tuple[int, str]]:
    start_line = _find_line(lines, start_marker, start=start)
    end_line = _find_line(lines, end_marker, start=start_line + 1)
    return [
        (line_number, _clean(lines[line_number - 1][2:]))
        for line_number in range(start_line + 1, end_line)
        if lines[line_number - 1].startswith("- ")
    ]


def _catalog_rows(
    lines: Sequence[str],
    sections: Sequence[str],
    *,
    prefix: str,
    items: Iterable[tuple[int, str]],
    category: str,
    release_gate: Sequence[str],
    component: Sequence[str],
    mandatory: bool = True,
    evidence_by_index: dict[int, Evidence] | None = None,
    digits: int = 2,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    evidence_by_index = evidence_by_index or {}
    for index, (line_number, summary) in enumerate(items, 1):
        requirement_id = f"{prefix}{index:0{digits}d}"
        result.append(
            _row(
                requirement_id=requirement_id,
                summary=summary,
                mandatory=mandatory,
                normative_class="atomic-catalog-requirement",
                category=category,
                source=_source(lines, sections, line_number),
                release_gate=release_gate,
                component=component,
                profile=_profiles_for_text(summary),
                platform=_platforms_for_text(summary),
                pass_condition=summary,
                evidence=evidence_by_index.get(index, MISSING),
            )
        )
    return result


def _table_after(
    lines: Sequence[str], header: str, *, start: int = 1
) -> list[tuple[int, list[str]]]:
    header_line = _find_line(lines, header, start=start)
    rows: list[tuple[int, list[str]]] = []
    for line_number in range(header_line + 2, len(lines) + 1):
        raw = lines[line_number - 1]
        if not raw.startswith("|"):
            break
        rows.append((line_number, _split_table(raw)))
    return rows


COMPONENT_SPECS = (
    (
        "COMP-ADAPTER-FILESYSTEM",
        "filesystem and allowlisted process adapters",
        "Filesystem effect adapter",
        "R01",
        True,
    ),
    (
        "COMP-ADAPTER-PROCESS",
        "filesystem and allowlisted process adapters",
        "Allowlisted real process-execution adapter",
        "R01",
        True,
    ),
    ("COMP-ADAPTER-GIT", "Git, SQLite/PostgreSQL test, HTTP mock", "Git adapter", "R02", True),
    (
        "COMP-ADAPTER-SQLITE",
        "Git, SQLite/PostgreSQL test, HTTP mock",
        "SQLite database adapter",
        "R02",
        True,
    ),
    (
        "COMP-ADAPTER-POSTGRES",
        "Git, SQLite/PostgreSQL test, HTTP mock",
        "PostgreSQL test adapter",
        "R02",
        True,
    ),
    (
        "COMP-ADAPTER-HTTP",
        "Git, SQLite/PostgreSQL test, HTTP mock",
        "HTTP mock/service adapter",
        "R02",
        True,
    ),
    (
        "COMP-ADAPTER-EMAIL",
        "Git, SQLite/PostgreSQL test, HTTP mock",
        "Local email-sink adapter",
        "R02",
        True,
    ),
    (
        "COMP-ADAPTER-BROWSER",
        "Git, SQLite/PostgreSQL test, HTTP mock",
        "Browser benchmark adapter",
        "R02",
        True,
    ),
    (
        "COMP-HARNESS-A1",
        "confined agent harness with no ambient",
        "Integrated A1 policy-checked confined agent harness",
        "R01",
        True,
    ),
    (
        "COMP-HARNESS-A2",
        "confined agent harness with no ambient",
        "Integrated A2 contained execution path",
        "R01",
        True,
    ),
    (
        "COMP-MODEL-LOCAL",
        "model gateway with scripted/local inference",
        "Scripted and local/offline model support",
        "R01",
        True,
    ),
    (
        "COMP-MODEL-EXTERNAL",
        "external-provider gateway profiles",
        "External-model gateway with durable intent, idempotency, and reconciliation",
        "R02",
        True,
    ),
    ("COMP-STORE-SQLITE", "SQLite in WAL mode", "SQLite WAL metadata backend", "P0", True),
    (
        "COMP-STORE-POSTGRES",
        "PostgreSQL metadata",
        "PostgreSQL production metadata backend",
        "R02",
        True,
    ),
    (
        "COMP-ARTIFACT-LOCAL",
        "Content-addressed local blob storage",
        "Content-addressed local artifact backend",
        "P0",
        True,
    ),
    (
        "COMP-ARTIFACT-S3",
        "S3-compatible artifact",
        "S3-compatible distributed artifact backend",
        "R02",
        True,
    ),
    (
        "COMP-SANDBOX-DOCKER",
        "Docker Engine as the first OCI sandbox",
        "Docker/OCI Linux sandbox backend",
        "R01",
        True,
    ),
    (
        "COMP-SANDBOX-PLUGGABLE",
        "allow later backends such as Podman",
        "Pluggable sandbox interface for stronger backends",
        "R01",
        True,
    ),
    (
        "COMP-INTEGRATION-MCP",
        "first framework integrations: MCP",
        "MCP integration inside the confined harness",
        "R02",
        True,
    ),
    (
        "COMP-INTEGRATION-SDK",
        "one mainstream agent SDK",
        "One mainstream agent-SDK integration inside the confined harness",
        "R02",
        True,
    ),
    (
        "COMP-RECOVERY-SCANNER",
        "crash recovery by scanning non-terminal",
        "Recovery scanner and restart reconciliation",
        "R01",
        True,
    ),
    (
        "COMP-SAGA",
        "saga transactions with durable per-action",
        "Durable saga coordinator and cross-domain recovery",
        "R02",
        True,
    ),
    ("COMP-Z3", "typed policy IR and Z3", "Z3-backed formal policy/authority checks", "R03", True),
    (
        "COMP-TRACEWORLD",
        "TraceWorld dataset and baselines",
        "TraceWorld dataset, training, evaluation, and inference",
        "R04",
        True,
    ),
)


COMPONENT_EVIDENCE: dict[str, Evidence] = {
    "COMP-ADAPTER-FILESYSTEM": baseline_partial(
        implementation=(
            "agentkernel/adapters/filesystem.py passes focused contract/security tests; crash recovery and full user-flow coverage are incomplete",
        ),
        verification=("tests/contract/test_filesystem_adapter.py",),
    ),
    "COMP-MODEL-LOCAL": baseline_partial(
        implementation=(
            "agentkernel/model_gateway/gateway.py contains ScriptedLocalModel only; a real local/offline inference backend is absent",
        ),
        verification=("tests/security/test_model_gateway.py",),
    ),
    "COMP-STORE-SQLITE": baseline_partial(
        implementation=(
            "agentkernel/storage/sqlite.py passes WAL, migration, CAS, reservation, and reopen tests; full recovery and user-flow coverage are incomplete",
        ),
        verification=("tests/integration/test_sqlite_journal.py",),
    ),
    "COMP-ARTIFACT-LOCAL": baseline_partial(
        implementation=(
            "agentkernel/evidence/artifacts.py passes focused round-trip, corruption, and traversal tests; full recovery and user-flow coverage are incomplete",
        ),
        verification=("tests/unit/test_artifacts.py",),
    ),
    "COMP-SANDBOX-DOCKER": baseline_partial(
        implementation=(
            "Docker backend/control probe exists; integrated hostile-agent A2 path does not",
        ),
        verification=(
            "tests/unit/test_docker_backend_unit.py; tests/integration/test_docker_sandbox.py",
        ),
    ),
}


def _component_catalog(lines: Sequence[str], sections: Sequence[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    service_items = _bullet_rows_between(
        lines,
        "interfaces MUST exist for these logical services:",
        "---",
        start=450,
    )
    for index, (line_number, summary) in enumerate(service_items, 1):
        name_match = re.match(r"`([^`]+)`", summary)
        slug = re.sub(
            r"[^A-Z0-9]+", "-", (name_match.group(1) if name_match else str(index)).upper()
        ).strip("-")
        rows.append(
            _row(
                requirement_id=f"COMP-SVC-{slug}",
                summary=summary,
                mandatory=True,
                normative_class="component-catalog",
                category="logical-service",
                source=_source(lines, sections, line_number),
                release_gate=("R10",),
                component=(slug.lower(),),
                pass_condition=summary,
            )
        )
    for requirement_id, marker, summary, gate, mandatory in COMPONENT_SPECS:
        line_number = _find_line(lines, marker)
        rows.append(
            _row(
                requirement_id=requirement_id,
                summary=summary,
                mandatory=mandatory,
                normative_class="component-catalog",
                category="adapter-backend-or-runtime-component",
                source=_source(lines, sections, line_number),
                release_gate=(gate,),
                component=(requirement_id.lower(),),
                profile=_profiles_for_text(summary),
                platform=_platforms_for_text(lines[line_number - 1] + " " + summary),
                pass_condition=f"{summary} passes its contract, security, recovery, and user-flow tests",
                evidence=COMPONENT_EVIDENCE.get(requirement_id, MISSING),
            )
        )
    return rows


def _catalogs(lines: Sequence[str], sections: Sequence[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    tx_table = _table_after(
        lines,
        "| From | Event/guard | To | Required durable action |",
        start=330,
    )
    tx_items = [
        (line_number, f"{cells[0]} -- {cells[1]} -> {cells[2]}; {cells[3]}")
        for line_number, cells in tx_table
    ]
    tx_evidence = {
        index: baseline_partial(
            implementation=(
                "The structural transaction transition is encoded; its required durable action is not proven end-to-end for this row",
            ),
            verification=("tests/unit/test_state_machine.py",),
        )
        for index in range(1, len(tx_items) + 1)
    }
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="SM-TX-",
            items=tx_items,
            category="transaction-state-transition",
            release_gate=("P0",),
            component=("transactions/state-machine",),
            evidence_by_index=tx_evidence,
        )
    )
    action_table = _table_after(
        lines,
        "| From | Event/guard | To | Durable requirement |",
        start=540,
    )
    action_items = [
        (line_number, f"{cells[0]} -- {cells[1]} -> {cells[2]}; {cells[3]}")
        for line_number, cells in action_table
    ]
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="SM-ACT-",
            items=action_items,
            category="saga-action-transition",
            release_gate=("R02",),
            component=("transactions/saga",),
        )
    )
    policy_items = _numbered_rows_between(
        lines,
        "The compiler and evaluator MUST apply these rules identically:",
        "The precedence list",
    )
    policy_partial = {
        index: baseline_partial(
            implementation=(
                "A deterministic subset exists; Z3 parity and the complete algebra are absent",
            ),
            verification=("tests/unit/test_policy.py",),
        )
        for index in range(1, len(policy_items) + 1)
    }
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="POL-AGG-",
            items=policy_items,
            category="policy-aggregation",
            release_gate=("R03",),
            component=("policy", "policy/z3"),
            evidence_by_index=policy_partial,
        )
    )
    saga_items = _numbered_rows_between(
        lines,
        "The coordinator MUST apply these rules:",
        "The aggregate transaction state is derived as follows:",
    )
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="SAGA-ORDER-",
            items=saga_items,
            category="saga-ordering",
            release_gate=("R02",),
            component=("transactions/saga", "recovery"),
        )
    )
    aggregate_items = _bullet_rows_between(
        lines,
        "The aggregate transaction state is derived as follows:",
        "The per-action journal is authoritative",
    )
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="SAGA-AGG-",
            items=aggregate_items,
            category="saga-aggregate-state",
            release_gate=("R02",),
            component=("transactions/saga",),
        )
    )

    hypotheses = _table_after(lines, "| ID | Hypothesis | Primary comparison | Primary metric |")
    for line_number, cells in hypotheses:
        rows.append(
            _row(
                requirement_id=f"EXP-{cells[0]}",
                summary=f"{cells[1]} Comparison: {cells[2]}. Metric: {cells[3]}.",
                mandatory=True,
                normative_class="registered-hypothesis",
                category="experiment",
                source=_source(lines, sections, line_number),
                release_gate=("R02", "R04", "R10"),
                component=("benchmark", "traceworld"),
                pass_condition=f"A preregistered experiment evaluates {cells[0]} with {cells[3]}",
            )
        )
    discipline = _bullet_rows_between(lines, "### 6.3 Required experimental discipline", "---")
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="EXP-DISC-",
            items=discipline,
            category="experimental-discipline",
            release_gate=("R02", "R04", "R10"),
            component=("benchmark", "traceworld"),
        )
    )

    for index in range(1, 7):
        marker = f"#### 17.2.{index} "
        line_number = _find_line(lines, marker)
        title = _clean(lines[line_number - 1].split(marker, 1)[1])
        capabilities_line = _find_line(lines, "Capabilities:", start=line_number)
        tasks_line = _find_line(lines, "Tasks:", start=capabilities_line)
        objective_line = _find_line(lines, "Objective checks:", start=line_number)
        if not line_number < capabilities_line < tasks_line < objective_line:
            raise ValueError(f"Malformed benchmark environment {index}")
        summary = f"{title}: " + " ".join(
            _clean(lines[source_line - 1])
            for source_line in (capabilities_line, tasks_line, objective_line)
        )
        rows.append(
            _row(
                requirement_id=f"BENCH-ENV-{index:02d}",
                summary=summary,
                mandatory=True,
                normative_class="benchmark-environment",
                category="benchmark",
                source=_source(lines, sections, line_number, line_end=objective_line),
                release_gate=("R02", "R10"),
                component=("benchmark", title.lower()),
                pass_condition=f"The {title} environment provisions deterministically and its objective checks grade final state read-only",
            )
        )
    scenario_items = _bullet_rows_between(
        lines, "At least these variants are required:", "### 17.5 Grading"
    )
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="BENCH-VAR-",
            items=scenario_items,
            category="benchmark-scenario-variant",
            release_gate=("R02", "R10"),
            component=("benchmark",),
        )
    )
    baseline_items = _numbered_rows_between(
        lines, "Required baselines:", "Model-provider comparisons"
    )
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="BENCH-BASE-",
            items=baseline_items,
            category="benchmark-baseline",
            release_gate=("R02", "R04", "R10"),
            component=("benchmark", "traceworld"),
        )
    )

    data_units = _bullet_rows_between(lines, "### 19.1 Dataset units", "### 19.2 Data sources")
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="DATA-UNIT-",
            items=data_units,
            category="dataset-unit",
            release_gate=("R04", "R10"),
            component=("dataset",),
        )
    )
    data_sources = _numbered_rows_between(lines, "### 19.2 Data sources", "### 19.3 Paired")
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="DATA-SRC-",
            items=data_sources,
            category="dataset-source",
            release_gate=("R04", "R10"),
            component=("dataset",),
        )
    )
    privacy = _bullet_rows_between(
        lines, "### 19.5 Privacy and redaction", "### 19.6 Dataset format"
    )
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="DATA-PRIV-",
            items=privacy,
            category="dataset-privacy",
            release_gate=("R04", "R10"),
            component=("dataset", "redaction"),
        )
    )
    quality = _bullet_rows_between(lines, "### 19.7 Dataset quality gates", "---")
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="DATA-QG-",
            items=quality,
            category="dataset-quality-gate",
            release_gate=("R04", "R10"),
            component=("dataset",),
        )
    )

    training = _numbered_rows_between(lines, "### 20.1 Training stages", "### 20.2 Losses")
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="TRACE-STAGE-",
            items=training,
            category="traceworld-training-stage",
            release_gate=("R04", "R10"),
            component=("traceworld",),
        )
    )
    metrics = _bullet_rows_between(
        lines, "### 20.4 Required metrics", "### 20.5 Model release artifacts"
    )
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="TRACE-METRIC-",
            items=metrics,
            category="traceworld-metric",
            release_gate=("R04", "R10"),
            component=("traceworld",),
        )
    )

    cli_start = _find_line(lines, "Minimum commands:")
    code_start = _find_line(lines, "```text", start=cli_start)
    code_end = _find_line(lines, "```", start=code_start + 1)
    cli_items = [
        (line_number, _clean(lines[line_number - 1]))
        for line_number in range(code_start + 1, code_end)
        if lines[line_number - 1].startswith("agentkernel ")
    ]
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="CLI-",
            items=cli_items,
            category="cli-command",
            release_gate=("R10",),
            component=("cli",),
        )
    )
    service_api = _bullet_rows_between(
        lines, "### 21.5 Service API requirements", "### 21.6 Integration adapters"
    )
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="COMP-API-",
            items=service_api,
            category="service-api-contract",
            release_gate=("R10",),
            component=("api",),
        )
    )
    storage_invariants = _bullet_rows_between(
        lines, "### 22.2 Storage invariants", "### 22.3 Retention"
    )
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="OPS-STORE-",
            items=storage_invariants,
            category="storage-invariant",
            release_gate=("R02", "R10"),
            component=("storage",),
        )
    )

    test_sections = (
        ("TEST-UNIT-", "#### Unit tests", "#### Property-based tests", "unit-test"),
        ("TEST-PROP-", "#### Property-based tests", "#### Adapter contract tests", "property-test"),
        ("TEST-INT-", "#### Integration tests", "#### Security tests", "integration-test"),
        ("TEST-SEC-", "#### Security tests", "#### Replay tests", "security-test"),
        ("TEST-REPLAY-", "#### Replay tests", "#### Chaos and recovery tests", "replay-test"),
        (
            "TEST-STATIC-",
            "### 26.2 Static and dynamic analysis",
            "No tool result alone",
            "static-analysis",
        ),
        ("TEST-CI-", "### 26.3 CI matrix", "### 26.4 Test evidence", "ci-matrix"),
        ("TEST-EVID-", "CI MUST archive:", "Flaky tests MUST", "test-evidence"),
    )
    for prefix, start_marker, end_marker, category in test_sections:
        items = _bullet_rows_between(lines, start_marker, end_marker)
        rows.extend(
            _catalog_rows(
                lines,
                sections,
                prefix=prefix,
                items=items,
                category=category,
                release_gate=("R10",),
                component=("testing",),
            )
        )
    for requirement_id, marker, summary in (
        (
            "TEST-CONTRACT-01",
            "Every adapter runs a shared suite",
            "Every adapter passes the shared truthfulness, stage, commit, recovery, deadline, redaction, and undeclared-effect contract suite",
        ),
        (
            "TEST-CHAOS-01",
            "Inject process kills and storage/network errors",
            "Chaos tests cover process/storage/network failure on both sides of every effect boundary",
        ),
        (
            "TEST-E2E-01",
            "Run the no-key demo and representative tasks",
            "Fresh-machine end-to-end tests assert final state and forbidden effects for every benchmark environment",
        ),
    ):
        line_number = _find_line(lines, marker)
        rows.append(
            _row(
                requirement_id=requirement_id,
                summary=summary,
                mandatory=True,
                normative_class="testing-catalog",
                category="testing",
                source=_source(lines, sections, line_number),
                release_gate=("R10",),
                component=("testing",),
                pass_condition=summary,
                evidence=(
                    baseline_partial(
                        implementation=(
                            "Current mock/filesystem contracts and A0 demo cover a bounded subset",
                        ),
                        verification=("tests/contract; tests/end_to_end",),
                    )
                    if requirement_id in {"TEST-CONTRACT-01", "TEST-E2E-01"}
                    else MISSING
                ),
            )
        )

    team_services = _bullet_rows_between(lines, "Minimum services:", "Control, agent-harness")
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="OPS-SVC-",
            items=team_services,
            category="operations-service",
            release_gate=("R10",),
            component=("operations",),
        )
    )
    dashboards = _bullet_rows_between(lines, "Required dashboards:", "### 28.5 Backup")
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="OPS-DASH-",
            items=dashboards,
            category="observability-dashboard",
            release_gate=("R10",),
            component=("observability",),
        )
    )
    disaster = _bullet_rows_between(
        lines, "### 28.5 Backup, restore, and disaster recovery", "### 28.6 Upgrade"
    )
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="OPS-DR-",
            items=disaster,
            category="disaster-recovery",
            release_gate=("R10",),
            component=("operations", "recovery"),
        )
    )
    compatibility = _bullet_rows_between(lines, "### 28.6 Upgrade and compatibility", "---")
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="OPS-COMPAT-",
            items=compatibility,
            category="upgrade-and-compatibility",
            release_gate=("R10",),
            component=("operations", "schemas"),
        )
    )

    docs = _bullet_rows_between(
        lines, "### 29.1 Required documents", "### 29.2 Documentation quality gates"
    )
    doc_evidence: dict[int, Evidence] = {
        1: baseline_partial(
            implementation=(
                "README has value explanation and A0 no-key quick start; complete release quick start is absent",
            ),
            verification=("tests/end_to_end/test_no_key_demo.py",),
        ),
        2: baseline_partial(
            implementation=(
                "Assurance and architecture concepts exist; several concept guides are absent",
            ),
            verification=("Manual documentation inventory",),
        ),
        5: baseline_verified(
            implementation=("SECURITY.md, threat model, TCB, limitations, and profiles exist",),
            verification=("Manual baseline documentation review",),
        ),
        10: baseline_verified(
            implementation=("ADR template and two accepted ADRs exist at the baseline",),
            verification=("Manual docs/adr inventory",),
        ),
    }
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="DOC-REQ-",
            items=docs,
            category="required-documentation",
            release_gate=("R10",),
            component=("documentation",),
            evidence_by_index=doc_evidence,
        )
    )
    doc_quality = _bullet_rows_between(lines, "### 29.2 Documentation quality gates", "---")
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="DOC-QG-",
            items=doc_quality,
            category="documentation-quality-gate",
            release_gate=("R10",),
            component=("documentation", "testing"),
        )
    )

    supply_chain = _bullet_rows_between(lines, "### 25.6 Supply-chain security", "### 25.7 Denial")
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="PKG-SUPPLY-",
            items=supply_chain,
            category="supply-chain",
            release_gate=("R10",),
            component=("packaging", "security"),
        )
    )
    release_hygiene = _bullet_rows_between(lines, "### 31.6 Commit and release hygiene", "---")
    rows.extend(
        _catalog_rows(
            lines,
            sections,
            prefix="PKG-REL-",
            items=release_hygiene,
            category="release-packaging",
            release_gate=("R10",),
            component=("packaging", "release"),
        )
    )

    nfr_sections = (
        (
            "NFR-PERF-",
            "### 33.1 Performance targets",
            "These are initial engineering budgets",
            "performance",
        ),
        ("NFR-REL-", "### 33.2 Reliability targets", "### 33.3 Accessibility", "reliability"),
        ("NFR-USE-", "### 33.3 Accessibility and usability", "### 33.4 Portability", "usability"),
    )
    for prefix, start_marker, end_marker, category in nfr_sections:
        items = _bullet_rows_between(lines, start_marker, end_marker)
        rows.extend(
            _catalog_rows(
                lines,
                sections,
                prefix=prefix,
                items=items,
                category=f"nonfunctional-{category}",
                release_gate=("R10",),
                component=("nonfunctional",),
            )
        )
    portability_line = _find_line(lines, "Linux is the security and production reference platform")
    rows.append(
        _row(
            requirement_id="NFR-PORT-01",
            summary=lines[portability_line - 1],
            mandatory=True,
            normative_class="nonfunctional-requirement",
            category="nonfunctional-portability",
            source=_source(lines, sections, portability_line),
            release_gate=("R10",),
            component=("platform-support",),
            platform=("linux", "windows", "macos", "docker", "wsl2"),
            pass_condition="Linux is verified as reference; unsupported Windows/macOS controls visibly downgrade or refuse assurance",
        )
    )
    rows.extend(_component_catalog(lines, sections))
    return rows


def _supplemental_catalogs(lines: Sequence[str], sections: Sequence[str]) -> list[dict[str, Any]]:
    """Append requirements discovered after the original stable-ID epoch."""
    rows: list[dict[str, Any]] = []

    schema_line = _find_line(lines, "Schema versions and migration tools are mandatory.")
    schema_summary = _clean(lines[schema_line - 1])
    rows.append(
        _row(
            requirement_id="DATA-SCHEMA-01",
            summary=schema_summary,
            mandatory=True,
            normative_class="dataset-schema-requirement",
            category="traceworld-and-data",
            source=_source(lines, sections, schema_line),
            release_gate=("R04", "R10"),
            component=("dataset", "migration"),
            pass_condition=(
                "Published dataset formats have explicit schema versions and executable migration tools"
            ),
            artifact=("Versioned dataset schemas, migrations, and compatibility tests",),
        )
    )

    product_metrics = _table_after(lines, "| Metric | Definition |", start=2444)
    if len(product_metrics) != 13:
        raise ValueError(f"Expected 13 product metrics, found {len(product_metrics)}")
    for index, (line_number, cells) in enumerate(product_metrics, 1):
        if len(cells) != 2:
            raise ValueError(f"Malformed product metric at line {line_number}")
        summary = f"{cells[0]}: {cells[1]}"
        rows.append(
            _row(
                requirement_id=f"METRIC-PROD-{index:02d}",
                summary=summary,
                mandatory=True,
                normative_class="product-metric",
                category="metrics-and-evaluation",
                source=_source(lines, sections, line_number),
                release_gate=("R02", "R04", "R10"),
                component=("benchmark", "observability"),
                pass_condition=f"The product metric is computed exactly as defined: {summary}",
                artifact=("Versioned metric definition and retained benchmark report",),
            )
        )

    bullet_groups = (
        (
            "METRIC-OPS-",
            "### 27.2 Operational metrics",
            "### 27.3 Security and privacy metrics",
            10,
            "operational-metric",
            ("observability", "operations"),
        ),
        (
            "METRIC-SEC-",
            "### 27.3 Security and privacy metrics",
            "### 27.4 Reporting rules",
            8,
            "security-and-privacy-metric",
            ("observability", "security"),
        ),
        (
            "METRIC-REPORT-",
            "### 27.4 Reporting rules",
            "---",
            8,
            "metric-reporting-rule",
            ("benchmark", "reporting"),
        ),
    )
    for prefix, start_marker, end_marker, expected, _row_class, component in bullet_groups:
        items = _bullet_rows_between(lines, start_marker, end_marker, start=2444)
        if len(items) != expected:
            raise ValueError(f"Expected {expected} {prefix} rows, found {len(items)}")
        rows.extend(
            _catalog_rows(
                lines,
                sections,
                prefix=prefix,
                items=items,
                category="metrics-and-evaluation",
                release_gate=("R02", "R04", "R10"),
                component=component,
            )
        )

    if len(rows) != 40:
        raise ValueError(f"Expected 40 supplemental catalog rows, found {len(rows)}")
    return rows


USER_REQUIREMENTS = (
    (
        "USR-001",
        "Starting procedure",
        "Audit the complete specification, repository, applicable instructions, documentation, tests, issue trackers, git history, and CI state",
        ("REL-P0",),
    ),
    (
        "USR-002",
        "Traceability",
        "Maintain a rich machine-readable matrix with stable IDs, exact source references, statuses, evidence, dependencies, and blockers",
        ("REL-P0",),
    ),
    (
        "USR-003",
        "A1/A2",
        "Integrate real A1 policy-checked and A2 contained agent harness workflows",
        ("COMP-HARNESS-A1", "COMP-HARNESS-A2"),
    ),
    (
        "USR-004",
        "Effects",
        "Implement a real allowlisted process adapter and required filesystem/process/network/other effect adapters",
        ("COMP-ADAPTER-PROCESS", "AK-021"),
    ),
    (
        "USR-005",
        "Transactions",
        "Implement transactional staging, commit, abort, rollback, reconciliation, crash recovery, and saga ordering",
        ("AK-024", "AK-071", "AK-077"),
    ),
    (
        "USR-006",
        "Authority and evidence",
        "Implement durable authority, capability budgets, policy decisions, receipts, and audit evidence",
        ("AK-034", "AK-074"),
    ),
    (
        "USR-007",
        "External models",
        "Implement safe external-model integration with durable idempotency and reconciliation",
        ("COMP-MODEL-EXTERNAL", "AK-070"),
    ),
    (
        "USR-008",
        "Offline models",
        "Support the specified scripted and local/offline model workflows without paid keys",
        ("COMP-MODEL-LOCAL", "AK-001"),
    ),
    (
        "USR-009",
        "Fault and recovery",
        "Verify fault schedules, cancellation races, deadlines, restarts, reconciliation, and recovery",
        ("AK-006", "AK-008", "AK-023", "AK-077"),
    ),
    (
        "USR-010",
        "Replay",
        "Implement deterministic replay and proposal/counterfactual replay with non-authoritative defaults",
        ("AK-013", "AK-014"),
    ),
    (
        "USR-011",
        "Research",
        "Implement benchmarks, equal-budget baselines, TraceWorld, datasets, Z3 checks, and distributed recovery where specified",
        ("REL-R02", "REL-R03", "REL-R04", "REL-R10"),
    ),
    (
        "USR-012",
        "Public contracts",
        "Implement public APIs, CLI workflows, configuration, schemas, migrations, and runnable examples",
        ("CLI-01", "AK-057"),
    ),
    (
        "USR-013",
        "Operations",
        "Implement observability, redaction, diagnostics, troubleshooting, backup, restore, and incident operations",
        ("AK-059", "AK-065", "AK-066"),
    ),
    (
        "USR-014",
        "Supply chain",
        "Implement packaging, release automation, provenance, SBOMs, signing, and supply-chain controls",
        ("AK-061",),
    ),
    (
        "USR-015",
        "No placeholders",
        "Do not leave production-path TODOs, placeholders, silent fallbacks, fake integrations, or mock-only proof where real behavior is required",
        ("NEG-REL-01", "AK-021"),
    ),
    (
        "USR-016",
        "Milestone loop",
        "For each milestone define acceptance, test the real flow, run quality/security gates, and repair findings",
        ("NORM-S36-001",),
    ),
    (
        "USR-017",
        "Independent review",
        "For each milestone obtain an independent correctness/security reviewer and a separate acceptance verifier",
        ("DOD-09",),
    ),
    (
        "USR-018",
        "Publish each milestone",
        "Commit and push coherent milestone changes and confirm GitHub CI on the pushed commit",
        ("PKG-REL-01",),
    ),
    (
        "USR-019",
        "Cross-platform release gate",
        "Require clean Windows, Linux, Docker, real end-to-end, security, benchmark, package, container, and fresh-public-clone verification",
        ("AK-001", "AK-061", "DOD-08"),
    ),
    (
        "USR-020",
        "Public usability",
        "Enable an unfamiliar user to install, run A0/A1/A2, inspect evidence/recovery, benchmark, and extend an adapter",
        ("DOD-10", "DOC-REQ-01"),
    ),
    (
        "USR-021",
        "Community",
        "Maintain professional README, architecture, threat model, tutorials, API/adapter docs, governance, security, code of conduct, changelog, roadmap, templates, citation, license, and compatibility policy",
        ("REL-R10-D08", "DOC-REQ-01"),
    ),
    (
        "USR-022",
        "Stable v1 restriction",
        "Do not create stable v1 until every mandatory row and all exact release gates pass on the release commit",
        ("REL-R10", "AK-067"),
    ),
    (
        "USR-023",
        "Publication authority",
        "Use only authorized free/local/GitHub publication paths; do not spend money, message people, disclose secrets, or pretend registry publication succeeded",
        ("PKG-REL-03",),
    ),
    (
        "USR-024",
        "Blocker semantics",
        "Record an exact externally caused blocker, attempts, evidence, and minimum required action; never mark the wider project complete while blocked",
        ("DOD-08",),
    ),
    (
        "USR-025",
        "Truthful closeout",
        "Report stable release URLs, exact commit/checksums, all-pass traceability, platform/security/benchmark results, independent evidence, and first-run instructions only after all gates pass",
        ("REL-R10", "AK-061", "AK-067"),
    ),
)


USER_EVIDENCE: dict[str, Evidence] = {
    "USR-001": baseline_partial(
        implementation=(
            "Specification/repository/history/CI were audited for this baseline; issue-state evidence is maintained by the root delivery workflow",
        ),
        verification=("Traceability generation audit on 2026-07-22",),
    ),
    "USR-002": committed_partial(
        implementation=(
            "The traceability manifest, append-only registry, policy, schema, validator, and tests are retained in the repository",
        ),
        verification=(
            "scripts/validate_traceability.py and tests/requirements/test_traceability.py",
        ),
        commit="1f1c6a243e51b5552bcdb1304af8bf0a486f7de7",
        verified_date="2026-07-22",
    ),
    "USR-008": baseline_partial(
        implementation=(
            "A scripted no-key workflow exists; a supported real local/offline model workflow is absent",
        ),
        verification=(
            "tests/security/test_model_gateway.py; tests/end_to_end/test_no_key_demo.py",
        ),
    ),
    "USR-021": baseline_partial(
        implementation=(
            "README, architecture, threat model, governance, security, conduct, roadmap, issue/PR templates, citation, and license exist; required guides/changelog/release policy are incomplete",
        ),
        verification=("Manual baseline repository inventory",),
    ),
    "USR-022": baseline_partial(
        implementation=(
            "README/ROADMAP prohibit premature v1 claims; automated full-release gate is not complete",
        ),
        verification=("Manual documentation review; " + CODEQL_ALERT,),
    ),
}


def _user_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for requirement_id, section, quote, related in USER_REQUIREMENTS:
        rows.append(
            _row(
                requirement_id=requirement_id,
                summary=quote,
                mandatory=True,
                normative_class="authoritative-user-requirement",
                category="user-objective",
                source=_source(
                    (),
                    (),
                    None,
                    quote=quote,
                    document="authoritative-user-objective",
                    kind="user-objective",
                )
                | {"section": section},
                release_gate=("R10",),
                component=_components_for_text(quote),
                profile=_profiles_for_text(quote),
                platform=_platforms_for_text(quote),
                pass_condition=quote,
                evidence=USER_EVIDENCE.get(requirement_id, MISSING),
                related_ids=related,
            )
        )
    return rows


def _extract_numbered_section(
    lines: Sequence[str],
    sections: Sequence[str],
    *,
    heading: str,
    end_marker: str,
    prefix: str,
    normative_class: str,
    category: str,
    expected: int,
    release_gate: Sequence[str],
) -> list[dict[str, Any]]:
    items = _numbered_rows_between(lines, heading, end_marker)
    if len(items) != expected:
        raise ValueError(f"Expected {expected} rows for {prefix}, found {len(items)}")
    return [
        _row(
            requirement_id=f"{prefix}{index:02d}",
            summary=summary,
            mandatory=True,
            normative_class=normative_class,
            category=category,
            source=_source(lines, sections, line_number),
            release_gate=release_gate,
            component=_components_for_text(summary),
            profile=_profiles_for_text(summary),
            platform=_platforms_for_text(summary),
            pass_condition=summary,
            related_ids=(),
            baseline_source_row=True,
        )
        for index, (line_number, summary) in enumerate(items, 1)
    ]


def _negative_rows(lines: Sequence[str], sections: Sequence[str]) -> list[dict[str, Any]]:
    items = _bullet_rows_between(lines, "A release MUST be rejected if any", "---", start=2900)
    if len(items) != 10:
        raise ValueError(f"Expected 10 negative release gates, found {len(items)}")
    rows: list[dict[str, Any]] = []
    for index, (line_number, summary) in enumerate(items, 1):
        rows.append(
            _row(
                requirement_id=f"NEG-REL-{index:02d}",
                summary=summary,
                mandatory=True,
                normative_class="negative-release-gate",
                category="release-rejection",
                source=_source(lines, sections, line_number),
                release_gate=("R10",),
                component=_components_for_text(summary),
                profile=_profiles_for_text(summary),
                platform=_platforms_for_text(summary),
                pass_condition=f"Release automation rejects the release when this condition is true: {summary}",
                baseline_source_row=True,
            )
        )
    return rows


def _markdown(manifest: dict[str, Any]) -> str:
    rows = manifest["requirements"]
    source_rows = [row for row in rows if row["baseline_source_row"]]
    catalogs = [row for row in rows if not row["baseline_source_row"]]
    status_counts = Counter(row["status"] for row in rows)
    source_counts = Counter(row["category"] for row in source_rows)
    catalog_counts = Counter(row["category"] for row in catalogs)
    release_lines = []
    for phase_id, label, gate in PHASES:
        phase_rows = [row for row in rows if gate in row["release_gate"]]
        counts = Counter(row["status"] for row in phase_rows)
        release_lines.append(
            f"| `{phase_id}` | {label} | {counts['implemented and verified']} | "
            f"{counts['partially implemented']} | {counts['missing']} | {counts['blocked']} |"
        )
    catalog_lines = [
        f"| `{category}` | {count} |" for category, count in sorted(catalog_counts.items())
    ]
    return "\n".join(
        [
            "# AgentKernel requirements traceability baseline",
            "",
            "> This is a generated summary. The authoritative row-level ledger is "
            "[`requirements/traceability.json`](../../requirements/traceability.json).",
            "",
            "## Baseline result",
            "",
            f"- Specification revision digest: `{manifest['metadata']['source_sha256']}`.",
            f"- Implementation baseline: `{manifest['metadata']['baseline_commit']}`.",
            f"- Source-derived rows before catalogs: **{len(source_rows)}**.",
            f"- Catalog and authoritative user rows: **{len(catalogs)}**.",
            f"- Total rows: **{len(rows)}**.",
            "- Stable release readiness: **FAIL**.",
            "- Reason: mandatory rows remain partial/missing and a high-severity CodeQL alert is open. "
            "No stable v1 release is supported by this baseline.",
            "",
            "The four allowed status strings are exact: `implemented and verified`, "
            "`partially implemented`, `missing`, and `blocked`. No row is marked blocked unless an "
            "external reason and minimum action are both recorded.",
            "",
            "## Source-row completeness",
            "",
            "| Source group | Count |",
            "| --- | ---: |",
            "| Normative keyword occurrences | 150 |",
            "| Phase/release parents | 6 |",
            "| Roadmap deliverable/exit rows | 93 |",
            "| `AK-*` acceptance criteria | 77 |",
            "| Negative release criteria | 10 |",
            "| Security invariants | 14 |",
            "| Definition of Done rows | 10 |",
            "| **Total** | **360** |",
            "",
            "Normative occurrence accounting excludes the keyword-definition line and contains "
            "117 `MUST`, 32 `MUST NOT`, and one `SHALL`. Roadmap child distribution is "
            "P0=14, R01=21, R02=16, R03=14, R04=14, R10=14.",
            "",
            "## Current status totals",
            "",
            "| Status | Rows |",
            "| --- | ---: |",
            *[f"| {status} | {status_counts[status]} |" for status in ALLOWED_STATUSES],
            "",
            "## Release-oriented view",
            "",
            "A row can relate to more than one release, so this table is not additive.",
            "",
            "| ID | Gate | Implemented + verified | Partial | Missing | Blocked |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
            *release_lines,
            "",
            "## Explicit catalogs",
            "",
            "| Catalog category | Rows |",
            "| --- | ---: |",
            *catalog_lines,
            "",
            "The catalogs explicitly enumerate transaction and saga transitions, policy "
            "aggregation, adapters/backends, H1-H6, benchmark environments/baselines, CLI "
            "commands, datasets, TraceWorld, testing, operations, documentation, packaging, "
            "non-functional requirements, and authoritative user requirements.",
            "",
            "## Validation",
            "",
            "```bash",
            "python scripts/validate_traceability.py",
            "python scripts/validate_traceability.py --require-complete  # expected to fail today",
            "```",
            "",
            "IDs in `requirements/id-registry.json` are append-only. Existing IDs must never be "
            "renumbered or reused; later rows are appended with new IDs. The validator also pins "
            "the frozen epoch and `requirements/traceability-policy.json`, so changing the manifest "
            "and registry together cannot rebase IDs or make mandatory rows optional.",
            "",
            "## Known release blockers versus implementation gaps",
            "",
            "There is no externally blocked row in this baseline. Missing A1/A2 confinement, the "
            "process and heterogeneous adapters, recovery scanner/saga, Z3, benchmark/data/TraceWorld, "
            "distributed operations, release artifacts, clean cross-platform verification, and the "
            "open high CodeQL finding are implementation or verification work—not external blockers.",
            "",
            f"Source category count checksum: `{_sha256(json.dumps(dict(sorted(source_counts.items())), sort_keys=True).encode())}`.",
            "",
        ]
    )


def build_manifest(spec_path: Path) -> dict[str, Any]:
    source_bytes = spec_path.read_bytes()
    source_sha256 = _sha256(source_bytes)
    if source_sha256 != EXPECTED_SPEC_SHA256:
        raise ValueError(
            "Specification digest mismatch: expected the frozen audited revision "
            f"{EXPECTED_SPEC_SHA256}, found {source_sha256}"
        )
    text = source_bytes.decode("utf-8")
    lines = text.splitlines()
    sections, codes = _heading_context(lines)

    roadmap = _extract_roadmap(lines, sections)
    normative = _extract_normative(lines, sections, codes)
    acceptance = _extract_ak(lines, sections)
    invariants = _extract_numbered_section(
        lines,
        sections,
        heading="### 25.3 Security invariants",
        end_marker="### 25.4 Secret handling",
        prefix="INV-SEC-",
        normative_class="security-invariant",
        category="security-invariant",
        expected=14,
        release_gate=("R10",),
    )
    negatives = _negative_rows(lines, sections)
    dod = _extract_numbered_section(
        lines,
        sections,
        heading="## 39. Definition of Done",
        end_marker="---",
        prefix="DOD-",
        normative_class="definition-of-done",
        category="definition-of-done",
        expected=10,
        release_gate=("R10",),
    )
    source_rows = roadmap + normative + acceptance + invariants + negatives + dod
    if len(source_rows) != 360:
        raise ValueError(f"Expected 360 source rows, found {len(source_rows)}")
    rows = source_rows + _catalogs(lines, sections) + _user_rows()
    rows.extend(_supplemental_catalogs(lines, sections))
    status_counts = Counter(row["status"] for row in rows)
    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "metadata": {
            "project": "AgentKernel",
            "source_document": SPEC_NAME,
            "source_sha256": source_sha256,
            "source_line_count": len(lines),
            "baseline_commit": BASELINE_COMMIT,
            "baseline_date": BASELINE_DATE,
            "id_policy": "append-only; never renumber or reuse an existing ID",
            "allowed_statuses": list(ALLOWED_STATUSES),
            "source_row_count": len(source_rows),
            "catalog_row_count": len(rows) - len(source_rows),
            "total_row_count": len(rows),
            "status_counts": {status: status_counts[status] for status in ALLOWED_STATUSES},
            "release_readiness": "FAIL",
            "release_readiness_reasons": [
                "Mandatory rows are not all implemented and verified",
                CODEQL_ALERT,
                "Clean Windows/Linux/Docker/public-clone full release verification is absent",
            ],
        },
        "requirements": rows,
    }
    return manifest


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


def _ids_digest(ids: Sequence[str]) -> str:
    return _sha256("\n".join(ids).encode("utf-8"))


def _build_registry(rows: Sequence[dict[str, Any]], existing: dict[str, Any]) -> dict[str, Any]:
    ids = [row["id"] for row in rows]
    old_ids = existing.get("ids")
    if not isinstance(old_ids, list) or any(not isinstance(value, str) for value in old_ids):
        raise ValueError("Existing ID registry must contain an ids array of strings")
    if ids[: len(old_ids)] != old_ids:
        raise ValueError(
            "Append-only ID violation: existing IDs were removed, renamed, reordered, or reused"
        )

    tombstones = existing.get("tombstones", [])
    if not isinstance(tombstones, list):
        raise TypeError("Existing ID registry tombstones must be an array")
    tombstone_ids: set[str] = set()
    for entry in tombstones:
        if not isinstance(entry, dict) or set(entry) != {
            "id",
            "reason",
            "retired_date",
            "replacement_id",
        }:
            raise ValueError("Each tombstone must have id, reason, retired_date, replacement_id")
        retired_id = entry.get("id")
        if not isinstance(retired_id, str) or retired_id not in old_ids or retired_id not in ids:
            raise ValueError("A tombstoned ID must remain in both the registry and manifest")
        if retired_id in tombstone_ids:
            raise ValueError(f"Duplicate tombstone for {retired_id}")
        tombstone_ids.add(retired_id)
        replacement = entry.get("replacement_id")
        if replacement is not None and (
            not isinstance(replacement, str) or replacement == retired_id or replacement not in ids
        ):
            raise ValueError(f"Invalid tombstone replacement for {retired_id}")
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            raise ValueError(f"Tombstone {retired_id} requires a reason")
        if not isinstance(entry.get("retired_date"), str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}", entry["retired_date"]
        ):
            raise ValueError(f"Tombstone {retired_id} requires an ISO retirement date")

    frozen_epoch = existing.get("frozen_epoch")
    if frozen_epoch is None:
        frozen_epoch = {
            "name": "specification-baseline-2026-07-22",
            "count": len(ids),
            "ids_sha256": _ids_digest(ids),
        }
    elif not isinstance(frozen_epoch, dict):
        raise ValueError("Existing registry frozen_epoch must be an object")
    else:
        count = frozen_epoch.get("count")
        digest = frozen_epoch.get("ids_sha256")
        if (
            not isinstance(count, int)
            or count < 1
            or count > len(old_ids)
            or digest != _ids_digest(old_ids[:count])
        ):
            raise ValueError("Existing registry frozen epoch does not match its ID prefix")

    return {
        "schema_version": "1.1.0",
        "policy": (
            "append-only; existing IDs remain ordered forever; retirement adds a tombstone "
            "without deleting the row or changing its mandatory classification"
        ),
        "baseline_commit": BASELINE_COMMIT,
        "source_sha256": EXPECTED_SPEC_SHA256,
        "frozen_epoch": frozen_epoch,
        "ids": ids,
        "baseline_source_ids": [row["id"] for row in rows if row["baseline_source_row"]],
        "tombstones": tombstones,
    }


def _build_policy(rows: Sequence[dict[str, Any]], registry: dict[str, Any]) -> dict[str, Any]:
    ids = [row["id"] for row in rows]
    mandatory_by_id = {row["id"]: row["mandatory"] for row in rows}
    return {
        "schema_version": "1.0.0",
        "source_sha256": EXPECTED_SPEC_SHA256,
        "frozen_epoch": registry["frozen_epoch"],
        "id_order_sha256": _ids_digest(ids),
        "optional_ids": [
            requirement_id for requirement_id in ids if not mandatory_by_id[requirement_id]
        ],
        "mandatory_by_id": mandatory_by_id,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--spec", type=Path, default=DEFAULT_SPEC_PATH, help="Path to specification input data"
    )
    parser.add_argument("--manifest", type=Path, default=Path("requirements/traceability.json"))
    parser.add_argument("--registry", type=Path, default=Path("requirements/id-registry.json"))
    parser.add_argument(
        "--policy", type=Path, default=Path("requirements/traceability-policy.json")
    )
    parser.add_argument(
        "--initialize-policy",
        action="store_true",
        help="Create or deliberately replace the external mandatory-ID policy",
    )
    parser.add_argument(
        "--source-copy",
        type=Path,
        help="Optionally retain the validated specification bytes at this repository path",
    )
    parser.add_argument(
        "--markdown",
        type=Path,
        default=Path("docs/project/requirements-traceability.md"),
    )
    args = parser.parse_args()
    manifest = build_manifest(args.spec)
    if not args.registry.is_file():
        raise ValueError(
            "The append-only registry is missing; restore it before generation instead of rebasing IDs"
        )
    existing_registry = json.loads(args.registry.read_text(encoding="utf-8"))
    if not isinstance(existing_registry, dict):
        raise TypeError("Existing ID registry root must be an object")
    registry = _build_registry(manifest["requirements"], existing_registry)
    policy = _build_policy(manifest["requirements"], registry)
    if args.initialize_policy:
        _write_json(args.policy, policy)
    else:
        if not args.policy.is_file():
            raise ValueError("The external mandatory-ID policy is missing")
        existing_policy = json.loads(args.policy.read_text(encoding="utf-8"))
        if existing_policy != policy:
            raise ValueError(
                "Generated IDs or mandatory classifications differ from the frozen external policy"
            )

    _write_json(args.manifest, manifest)
    _write_json(args.registry, registry)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.write_bytes(_markdown(manifest).encode("utf-8"))
    if args.source_copy is not None:
        source_bytes = args.spec.read_bytes()
        if _sha256(source_bytes) != EXPECTED_SPEC_SHA256:
            raise ValueError("Refusing to retain an unaudited specification revision")
        args.source_copy.parent.mkdir(parents=True, exist_ok=True)
        args.source_copy.write_bytes(source_bytes)
    print(
        json.dumps(
            {
                "manifest": str(args.manifest),
                "registry": str(args.registry),
                "policy": str(args.policy),
                "markdown": str(args.markdown),
                "source_rows": manifest["metadata"]["source_row_count"],
                "catalog_rows": manifest["metadata"]["catalog_row_count"],
                "total_rows": manifest["metadata"]["total_row_count"],
                "release_readiness": manifest["metadata"]["release_readiness"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
