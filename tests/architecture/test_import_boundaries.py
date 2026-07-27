from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2] / "agentkernel"
V8_AUTHORITY_BOUNDARY = (
    ROOT / "authority" / "v8_contracts.py",
    ROOT / "authority" / "v8_streaming.py",
)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


@pytest.mark.parametrize("path", sorted((ROOT / "domain").glob("*.py")), ids=lambda path: path.name)
def test_domain_has_no_infrastructure_dependency(path: Path) -> None:
    forbidden = (
        "agentkernel.adapters",
        "agentkernel.storage",
        "agentkernel.transactions",
        "sqlite3",
        "subprocess",
    )
    assert not {
        name for name in _imports(path) if any(name.startswith(prefix) for prefix in forbidden)
    }


@pytest.mark.parametrize(
    "path", sorted((ROOT / "adapters").glob("*.py")), ids=lambda path: path.name
)
def test_adapters_cannot_mutate_journal_or_evidence(path: Path) -> None:
    forbidden = ("agentkernel.storage", "agentkernel.transactions", "agentkernel.evidence")
    assert not {
        name for name in _imports(path) if any(name.startswith(prefix) for prefix in forbidden)
    }


@pytest.mark.parametrize("path", V8_AUTHORITY_BOUNDARY, ids=lambda path: path.name)
def test_v8_authority_input_boundary_has_no_lifecycle_or_effect_dependency(path: Path) -> None:
    assert path.is_file()
    forbidden = (
        "agentkernel.adapters",
        "agentkernel.api",
        "agentkernel.authority.evaluator",
        "agentkernel.authority.service",
        "agentkernel.model_gateway",
        "agentkernel.storage",
        "agentkernel.transactions",
    )
    assert not {
        name for name in _imports(path) if any(name.startswith(prefix) for prefix in forbidden)
    }


def test_v8_streaming_boundary_does_not_delegate_json_parsing_or_use_recursion() -> None:
    path = ROOT / "authority" / "v8_streaming.py"
    assert path.is_file()
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    forbidden_parser_imports = {
        "ijson",
        "json",
        "msgspec",
        "orjson",
        "rapidjson",
        "simdjson",
        "ujson",
    }
    assert not {
        name for name in _imports(path) if name.split(".", 1)[0] in forbidden_parser_imports
    }

    recursive_calls: set[str] = set()
    for function in (
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    ):
        for node in ast.walk(function):
            if isinstance(node, ast.Call) and (
                (isinstance(node.func, ast.Name) and node.func.id == function.name)
                or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == function.name
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in {"cls", "self"}
                )
            ):
                recursive_calls.add(function.name)
    assert recursive_calls == set()
