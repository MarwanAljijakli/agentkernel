from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2] / "agentkernel"


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
