from __future__ import annotations

import agentkernel.storage.sqlite as sqlite_storage
import pytest
from agentkernel.errors import AgentKernelError, ErrorCode


@pytest.mark.security
@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("  -- comment without newline", (28, True)),
        ("/* complete */ SELECT 1", (15, True)),
        ("/* incomplete", (13, False)),
        ("\n\t SELECT 1", (3, True)),
    ],
)
def test_sql_trivia_parser_handles_complete_and_incomplete_comments(
    sql: str,
    expected: tuple[int, bool],
) -> None:
    assert sqlite_storage._skip_sql_trivia(sql) == expected


@pytest.mark.security
@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ("-- comment\n CREATE TABLE test(value TEXT);", "CREATE"),
        ("/* incomplete", None),
        ("  123", None),
    ],
)
def test_leading_sql_keyword_ignores_only_complete_trivia(
    statement: str,
    expected: str | None,
) -> None:
    assert sqlite_storage._leading_sql_keyword(statement) == expected


@pytest.mark.security
@pytest.mark.parametrize(
    ("sql", "message"),
    [
        ("-- comment only", "does not contain"),
        ("/* comment only */", "does not contain"),
        ("/* incomplete", "incomplete"),
        ("CREATE TABLE test(value TEXT)", "incomplete"),
        ("BEGIN;", "transaction-control"),
        ("COMMIT;", "transaction-control"),
        ("123;", "invalid SQL statement"),
    ],
)
def test_migration_splitter_rejects_ambiguous_or_transactional_source(
    sql: str,
    message: str,
) -> None:
    with pytest.raises(AgentKernelError, match=message) as captured:
        sqlite_storage._split_migration_sql(99, sql)
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
    assert captured.value.details["version"] == 99


@pytest.mark.security
def test_migration_splitter_preserves_semicolons_inside_literals_and_triggers() -> None:
    sql = """
    CREATE TABLE probe(value TEXT PRIMARY KEY);
    INSERT INTO probe(value) VALUES ('inside;a;literal');
    CREATE TRIGGER probe_guard BEFORE DELETE ON probe BEGIN
      SELECT RAISE(ABORT, 'no;delete');
    END;
    """
    statements = sqlite_storage._split_migration_sql(99, sql)
    assert len(statements) == 3
    assert "inside;a;literal" in statements[1]
    assert statements[2].startswith("CREATE TRIGGER")
    assert statements[2].endswith("END;")


@pytest.mark.security
@pytest.mark.parametrize("versions", [((0, "SELECT 1;"),), ((2, "SELECT 1;"), (1, "SELECT 2;"))])
def test_migration_preparation_requires_positive_strictly_increasing_versions(
    monkeypatch: pytest.MonkeyPatch,
    versions: tuple[tuple[int, str], ...],
) -> None:
    monkeypatch.setattr(sqlite_storage, "MIGRATIONS", versions)
    with pytest.raises(AgentKernelError, match="strictly increasing") as captured:
        sqlite_storage._prepare_migrations()
    assert captured.value.code is ErrorCode.INTEGRITY_ERROR


def test_schema_sql_canonicalizer_preserves_quoted_tokens_while_folding_trivia() -> None:
    assert sqlite_storage._canonical_schema_sql(None) is None
    assert (
        sqlite_storage._canonical_schema_sql(
            "  CREATE   TABLE [odd name] (value TEXT DEFAULT 'a  b''c', `other` TEXT);  "
        )
        == "CREATE TABLE [odd name] (value TEXT DEFAULT 'a  b''c',`other` TEXT);"
    )
