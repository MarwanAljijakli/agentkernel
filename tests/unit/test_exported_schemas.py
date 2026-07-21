from __future__ import annotations

import json
from pathlib import Path

import pytest
from agentkernel.cli import SCHEMA_MODELS
from pydantic import BaseModel


@pytest.mark.parametrize("model", SCHEMA_MODELS, ids=lambda model: model.__name__)
def test_committed_schema_matches_model(model: type[BaseModel]) -> None:
    path = Path("schemas/v1alpha1") / f"{model.__name__}.schema.json"
    committed = json.loads(path.read_text(encoding="utf-8"))
    assert committed == model.model_json_schema(mode="validation")
