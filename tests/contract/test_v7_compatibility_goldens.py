from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
from agentkernel.authority.evaluator import AuthoritySnapshot
from agentkernel.canonical import canonical_json_bytes
from agentkernel.domain.models import (
    ActionProposal,
    InspectionPermit,
    IntentRecord,
    NormalizedAction,
    NormalizedIntentProjection,
    RecoveryActionBinding,
    RecoveryPermit,
    StagePermit,
    TransactionRecord,
    VerificationPermit,
)
from agentkernel.storage import sqlite as sqlite_storage
from agentkernel.transactions.contracts import (
    AuthorizationRoundRecord,
    CommitPermit,
    RecoveryWorkRecord,
)
from pydantic import BaseModel

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE_PATH = _REPOSITORY_ROOT / "tests" / "fixtures" / "v7_compatibility_goldens.json"
_SCHEMA_ROOT = _REPOSITORY_ROOT / "schemas" / "v1alpha1"
_DESIGN_SHA256 = "sha256:63f8b2525cebbefb5cdef9366ea90a803858390629bbcf2343b02905722bcc18"
_SOURCE_BASELINE_COMMIT = "d3d64eb5414ef70ebbdfb6827aa4fb31e659e337"

_DOCUMENT_MODELS: dict[str, type[BaseModel]] = {
    "ActionProposal": ActionProposal,
    "NormalizedIntentProjection": NormalizedIntentProjection,
    "NormalizedAction": NormalizedAction,
    "IntentRecord": IntentRecord,
    "AuthoritySnapshot": AuthoritySnapshot,
    "AuthorizationRoundRecord.v1.0": AuthorizationRoundRecord,
    "AuthorizationRoundRecord.v1.1": AuthorizationRoundRecord,
    "InspectionPermit": InspectionPermit,
    "StagePermit": StagePermit,
    "VerificationPermit": VerificationPermit,
    "CommitPermit": CommitPermit,
    "RecoveryActionBinding": RecoveryActionBinding,
    "RecoveryPermit": RecoveryPermit,
    "RecoveryWorkRecord.PENDING": RecoveryWorkRecord,
    "RecoveryWorkRecord.RUNNING": RecoveryWorkRecord,
}


def _load_fixture() -> dict[str, Any]:
    loaded = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise TypeError("v7 compatibility fixture must be a JSON object")
    return loaded


def _mapping(value: object, *, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{field_name} must be a JSON object")
    return value


def _decode_document(name: str, entry: Mapping[str, Any]) -> bytes:
    encoded = entry.get("canonical_utf8_base64")
    if not isinstance(encoded, str):
        raise TypeError(f"{name} canonical bytes must be literal base64 text")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise AssertionError(f"{name} canonical base64 is invalid") from error

    expected_length = entry.get("canonical_byte_length")
    if len(raw) != expected_length:
        raise AssertionError(f"{name} canonical byte length changed")
    actual_sha256 = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    if actual_sha256 != entry.get("canonical_sha256"):
        raise AssertionError(f"{name} canonical SHA-256 changed")
    return raw


def _assert_document_golden(
    name: str,
    entry: Mapping[str, Any],
    model_type: type[BaseModel],
) -> None:
    if entry.get("model") != model_type.__name__:
        raise AssertionError(f"{name} model discriminator changed")
    raw = _decode_document(name, entry)
    restored = model_type.model_validate_json(raw)
    if canonical_json_bytes(restored) != raw:
        raise AssertionError(f"{name} no longer round-trips to its literal canonical bytes")


def _assert_schema_goldens(
    manifest: Mapping[str, Any],
    *,
    read_bytes: Callable[[str], bytes],
) -> None:
    if len(manifest) != 71:
        raise AssertionError("v7 schema manifest must freeze exactly 71 legacy schemas")
    for relative_name in sorted(manifest):
        if Path(relative_name).name != relative_name or not relative_name.endswith(".schema.json"):
            raise AssertionError(f"invalid legacy schema path: {relative_name}")
        entry = _mapping(manifest[relative_name], field_name=relative_name)
        raw = read_bytes(relative_name)
        if len(raw) != entry.get("raw_byte_length"):
            raise AssertionError(f"{relative_name} raw byte length changed")
        actual_sha256 = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        if actual_sha256 != entry.get("raw_sha256"):
            raise AssertionError(f"{relative_name} raw SHA-256 changed")


def _assert_migration_goldens(
    migrations: Sequence[tuple[int, str]],
    manifest: Mapping[str, Any],
) -> None:
    if len(manifest) != 7:
        raise AssertionError("migration manifest must freeze exactly versions 1 through 7")
    if len(migrations) != 7:
        raise AssertionError(
            "legacy MIGRATIONS must remain exactly v1 through v7; v8 requires a separate path"
        )
    prefix = tuple(migrations)
    if tuple(version for version, _sql in prefix) != tuple(range(1, 8)):
        raise AssertionError("the current migration prefix is no longer exactly v1 through v7")

    for version, sql in prefix:
        entry = _mapping(manifest.get(str(version)), field_name=f"migration {version}")
        material = canonical_json_bytes({"version": version, "sql": sql})
        actual_sha256 = f"sha256:{hashlib.sha256(material).hexdigest()}"
        if actual_sha256 != entry.get("canonical_material_sha256"):
            raise AssertionError(f"migration {version} digest changed")
        statement_count = len(sqlite_storage._split_migration_sql(version, sql))
        if statement_count != entry.get("statement_count"):
            raise AssertionError(f"migration {version} statement count changed")


def test_fixture_is_bound_to_the_approved_v7_compatibility_gate() -> None:
    fixture = _load_fixture()

    assert fixture["format"] == "agentkernel.v7-compatibility-goldens/v1"
    assert fixture["legacy_schema_version"] == 7
    assert fixture["design_sha256"] == _DESIGN_SHA256
    assert fixture["source_baseline_commit"] == _SOURCE_BASELINE_COMMIT


@pytest.mark.parametrize("name", sorted(_DOCUMENT_MODELS))
def test_legacy_document_has_literal_canonical_bytes_and_round_trips(name: str) -> None:
    documents = _mapping(_load_fixture().get("documents"), field_name="documents")

    assert set(documents) == set(_DOCUMENT_MODELS)
    entry = _mapping(documents[name], field_name=name)
    _assert_document_golden(name, entry, _DOCUMENT_MODELS[name])


def test_legacy_document_byte_mutation_sentinel_fails() -> None:
    documents = _mapping(_load_fixture().get("documents"), field_name="documents")
    original = _mapping(documents["ActionProposal"], field_name="ActionProposal")
    mutated = dict(original)
    raw = bytearray(_decode_document("ActionProposal", original))
    marker = raw.index(b"transaction:test")
    raw[marker] = ord("u")
    mutated["canonical_utf8_base64"] = base64.b64encode(raw).decode("ascii")

    with pytest.raises(AssertionError, match="canonical SHA-256 changed"):
        _assert_document_golden("ActionProposal", mutated, ActionProposal)


def test_transaction_row_canary_matches_the_exact_legacy_write_codec() -> None:
    fixture = _load_fixture()
    canaries = _mapping(fixture.get("row_canaries"), field_name="row_canaries")
    entry = _mapping(
        canaries.get("TransactionRecord.model_dump_json"),
        field_name="TransactionRecord.model_dump_json",
    )
    encoded = entry.get("persisted_utf8_base64")
    if not isinstance(encoded, str):
        raise TypeError("TransactionRecord row canary must contain literal base64")
    raw = base64.b64decode(encoded, validate=True)

    assert entry["model"] == "TransactionRecord"
    assert entry["storage_column"] == "transactions.record_json"
    assert len(raw) == entry["raw_byte_length"]
    assert f"sha256:{hashlib.sha256(raw).hexdigest()}" == entry["raw_sha256"]
    restored = TransactionRecord.model_validate_json(raw)
    assert restored.model_dump_json().encode("utf-8") == raw


def test_all_v7_schema_files_retain_their_raw_sha256() -> None:
    manifest = _mapping(_load_fixture().get("schemas"), field_name="schemas")
    frozen_names = set(manifest)
    current_names = {
        path.relative_to(_SCHEMA_ROOT).as_posix() for path in _SCHEMA_ROOT.rglob("*.schema.json")
    }

    # v8 schemas are additive; the frozen v7 set must remain present and byte-identical.
    assert frozen_names <= current_names
    _assert_schema_goldens(
        manifest,
        read_bytes=lambda relative_name: (_SCHEMA_ROOT / relative_name).read_bytes(),
    )


def test_raw_schema_byte_mutation_sentinel_fails() -> None:
    manifest = _mapping(_load_fixture().get("schemas"), field_name="schemas")
    target = sorted(manifest)[0]

    def read_mutated(relative_name: str) -> bytes:
        raw = (_SCHEMA_ROOT / relative_name).read_bytes()
        if relative_name == target:
            return bytes((raw[0] ^ 1,)) + raw[1:]
        return raw

    with pytest.raises(AssertionError, match="raw SHA-256 changed"):
        _assert_schema_goldens(manifest, read_bytes=read_mutated)


def test_migrations_v1_through_v7_retain_exact_digests_and_statement_counts() -> None:
    manifest = _mapping(_load_fixture().get("migrations"), field_name="migrations")

    _assert_migration_goldens(sqlite_storage.MIGRATIONS, manifest)


def test_migration_sql_mutation_sentinel_fails() -> None:
    manifest = _mapping(_load_fixture().get("migrations"), field_name="migrations")
    mutated = list(sqlite_storage.MIGRATIONS)
    version, sql = mutated[3]
    mutated[3] = (version, f"{sql}\n-- g0 compatibility sentinel")

    with pytest.raises(AssertionError, match="migration 4 digest changed"):
        _assert_migration_goldens(mutated, manifest)


def test_appending_v8_to_the_legacy_auto_migration_path_fails() -> None:
    manifest = _mapping(_load_fixture().get("migrations"), field_name="migrations")
    unsafe_auto_upgrade = (*sqlite_storage.MIGRATIONS, (8, "SELECT 1;"))

    with pytest.raises(AssertionError, match="v8 requires a separate path"):
        _assert_migration_goldens(unsafe_auto_upgrade, manifest)


def test_migration_statement_count_sentinel_fails() -> None:
    source = _mapping(_load_fixture().get("migrations"), field_name="migrations")
    manifest = {
        version: dict(_mapping(entry, field_name=version)) for version, entry in source.items()
    }
    manifest["1"]["statement_count"] += 1

    with pytest.raises(AssertionError, match="migration 1 statement count changed"):
        _assert_migration_goldens(sqlite_storage.MIGRATIONS, manifest)
