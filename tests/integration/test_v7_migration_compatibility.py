from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from agentkernel.canonical import canonical_json_bytes
from agentkernel.domain.models import TransactionRecord
from agentkernel.storage import sqlite as sqlite_storage
from agentkernel.storage.sqlite import SQLiteJournal

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE_PATH = _REPOSITORY_ROOT / "tests" / "fixtures" / "v7_compatibility_goldens.json"
_TRANSACTION_ID = "transaction:g0-v7-row-canary"
_APPLIED_AT = "2030-01-01T00:00:00.000Z"


def _load_fixture() -> dict[str, Any]:
    loaded = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise TypeError("v7 compatibility fixture must be a JSON object")
    return loaded


def _mapping(value: object, *, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{field_name} must be a JSON object")
    return value


def _canary_record(fixture: Mapping[str, Any]) -> tuple[bytes, TransactionRecord]:
    canaries = _mapping(fixture.get("row_canaries"), field_name="row_canaries")
    entry = _mapping(
        canaries.get("TransactionRecord.model_dump_json"),
        field_name="TransactionRecord.model_dump_json",
    )
    encoded = entry.get("persisted_utf8_base64")
    if not isinstance(encoded, str):
        raise TypeError("TransactionRecord row canary must contain base64 bytes")
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) != entry.get("raw_byte_length"):
        raise AssertionError("TransactionRecord row canary length changed")
    if f"sha256:{hashlib.sha256(raw).hexdigest()}" != entry.get("raw_sha256"):
        raise AssertionError("TransactionRecord row canary digest changed")
    record = TransactionRecord.model_validate_json(raw)
    if record.model_dump_json().encode("utf-8") != raw:
        raise AssertionError("TransactionRecord row canary no longer matches the write codec")
    return raw, record


def _checked_prefix(
    target_version: int,
    fixture: Mapping[str, Any],
) -> tuple[tuple[int, str], ...]:
    if len(sqlite_storage.MIGRATIONS) != 7:
        raise AssertionError(
            "legacy MIGRATIONS must remain exactly v1 through v7; v8 requires a separate path"
        )
    manifest = _mapping(fixture.get("migrations"), field_name="migrations")
    prefix = tuple(sqlite_storage.MIGRATIONS[:target_version])
    if tuple(version for version, _sql in prefix) != tuple(range(1, target_version + 1)):
        raise AssertionError(f"migration prefix through v{target_version} is not contiguous")
    for version, sql in prefix:
        entry = _mapping(manifest.get(str(version)), field_name=f"migration {version}")
        material = canonical_json_bytes({"version": version, "sql": sql})
        actual_sha256 = f"sha256:{hashlib.sha256(material).hexdigest()}"
        if actual_sha256 != entry.get("canonical_material_sha256"):
            raise AssertionError(f"migration {version} no longer matches the frozen prefix")
        if len(sqlite_storage._split_migration_sql(version, sql)) != entry.get("statement_count"):
            raise AssertionError(f"migration {version} statement count changed")
    return prefix


def _assert_canary_row(connection: sqlite3.Connection, expected: bytes) -> None:
    row = connection.execute(
        "SELECT CAST(record_json AS BLOB) FROM transactions WHERE transaction_id = ?",
        (_TRANSACTION_ID,),
    ).fetchone()
    if row is None or bytes(row[0]) != expected:
        raise AssertionError("legacy canonical row bytes changed during migration")


def _apply_frozen_prefix(
    database_path: Path,
    *,
    target_version: int,
    fixture: Mapping[str, Any],
) -> tuple[bytes, TransactionRecord]:
    prefix = _checked_prefix(target_version, fixture)
    canary, record = _canary_record(fixture)
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        for version, sql in prefix:
            connection.executescript(sql)
            migration = _mapping(
                _mapping(fixture.get("migrations"), field_name="migrations").get(str(version)),
                field_name=f"migration {version}",
            )
            connection.execute(
                "INSERT INTO schema_migrations(version, digest, applied_at) VALUES (?, ?, ?)",
                (version, migration["canonical_material_sha256"], _APPLIED_AT),
            )
            if version == 1:
                connection.execute(
                    "INSERT INTO transactions("
                    "transaction_id, goal_id, state, version, record_json"
                    ") VALUES (?, ?, ?, ?, ?)",
                    (
                        record.transaction_id,
                        record.goal_id,
                        record.state.value,
                        record.version,
                        canary.decode("utf-8"),
                    ),
                )
            connection.commit()
            _assert_canary_row(connection, canary)

        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        connection.close()
    return canary, record


def _migration_ledger_rows(database_path: Path) -> list[tuple[int, str, str]]:
    connection = sqlite3.connect(database_path)
    try:
        rows = connection.execute(
            "SELECT version, digest, applied_at FROM schema_migrations ORDER BY version"
        ).fetchall()
    finally:
        connection.close()
    return [(int(version), str(digest), str(applied_at)) for version, digest, applied_at in rows]


def _expected_migration_digests(
    *,
    fixture: Mapping[str, Any],
) -> list[tuple[int, str]]:
    manifest = _mapping(fixture.get("migrations"), field_name="migrations")
    return [
        (
            version,
            _mapping(manifest[str(version)], field_name=str(version))["canonical_material_sha256"],
        )
        for version in range(1, 8)
    ]


def _assert_persisted_row_bytes(database_path: Path, canary: bytes) -> None:
    connection = sqlite3.connect(database_path)
    try:
        _assert_canary_row(connection, canary)
    finally:
        connection.close()


@pytest.mark.integration
def test_sqlite_journal_write_path_emits_the_frozen_transaction_row_bytes(
    tmp_path: Path,
) -> None:
    fixture = _load_fixture()
    canary, expected_record = _canary_record(fixture)
    database_path = tmp_path / "current-v7-write-codec.db"

    with SQLiteJournal(database_path) as journal:
        journal.create_transaction(
            expected_record,
            run_id="run:g0-v7-row-canary",
            actor="service:g0",
            on_behalf_of="principal:g0",
        )
        assert journal.schema_version() == 7
        assert journal.get_transaction(_TRANSACTION_ID) == expected_record

    _assert_persisted_row_bytes(database_path, canary)

    with SQLiteJournal(database_path) as reopened:
        assert reopened.schema_version() == 7
        assert reopened.get_transaction(_TRANSACTION_ID) == expected_record

    _assert_persisted_row_bytes(database_path, canary)


@pytest.mark.integration
@pytest.mark.parametrize("target_version", range(1, 8))
def test_each_frozen_prefix_upgrades_opens_and_reopens_without_rewriting_legacy_bytes(
    tmp_path: Path,
    target_version: int,
) -> None:
    fixture = _load_fixture()
    database_path = tmp_path / f"legacy-prefix-v{target_version}.db"
    canary, expected_record = _apply_frozen_prefix(
        database_path,
        target_version=target_version,
        fixture=fixture,
    )
    _checked_prefix(7, fixture)
    expected_digests = _expected_migration_digests(fixture=fixture)
    prefix_rows = _migration_ledger_rows(database_path)

    assert [(version, digest) for version, digest, _applied_at in prefix_rows] == (
        expected_digests[:target_version]
    )
    _assert_persisted_row_bytes(database_path, canary)

    with SQLiteJournal(database_path) as journal:
        assert journal.schema_version() == 7
        restored = journal.get_transaction(_TRANSACTION_ID)
        assert restored == expected_record
        assert restored.model_dump_json().encode("utf-8") == canary

    first_open_rows = _migration_ledger_rows(database_path)
    assert first_open_rows[:target_version] == prefix_rows
    assert [(version, digest) for version, digest, _applied_at in first_open_rows] == (
        expected_digests
    )
    _assert_persisted_row_bytes(database_path, canary)

    with SQLiteJournal(database_path) as reopened:
        assert reopened.schema_version() == 7
        restored_again = reopened.get_transaction(_TRANSACTION_ID)
        assert restored_again == expected_record
        assert restored_again.model_dump_json().encode("utf-8") == canary

    assert _migration_ledger_rows(database_path) == first_open_rows
    _assert_persisted_row_bytes(database_path, canary)
