from __future__ import annotations

import json
from pathlib import Path
from typing import get_type_hints

import pytest
from agentkernel.api import KernelAPI
from agentkernel.cli import SCHEMA_MODELS, export_schemas
from pydantic import BaseModel

_G1A_SCHEMA_NAMES = (
    "SelectedEndpointGrantBindingV8",
    "IngressAuthoritySelectionOriginV8",
    "RecoveryAuthoritySelectionOriginV8",
    "AuthoritySelection",
    "AuthoritySelectionReuseProfileV8",
    "NoResponseObservationV8",
    "CompleteBoundedResponseObservationV8",
    "IncompleteBoundedResponseObservationV8",
    "OverflowPrefixObservationV8",
)


def _public_kernel_api_request_models() -> tuple[type[BaseModel], ...]:
    models: list[type[BaseModel]] = []
    for name, method in KernelAPI.__dict__.items():
        if name.startswith("_") or not callable(method):
            continue
        parameter_hints = tuple(
            hint for parameter, hint in get_type_hints(method).items() if parameter != "return"
        )
        assert len(parameter_hints) == 1, f"KernelAPI.{name} must have one request contract"
        model = parameter_hints[0]
        assert isinstance(model, type), f"KernelAPI.{name} request must be a model type"
        assert issubclass(model, BaseModel), f"KernelAPI.{name} request must be a Pydantic model"
        models.append(model)
    return tuple(models)


def test_every_public_kernel_api_request_is_exported_in_logical_order(
    tmp_path: Path,
) -> None:
    request_models = _public_kernel_api_request_models()
    exported_requests = tuple(model for model in SCHEMA_MODELS if model in request_models)
    generated = tmp_path / "schemas"

    assert exported_requests == request_models
    assert export_schemas(generated) == len(SCHEMA_MODELS)
    for model in request_models:
        assert Path("schemas/v1alpha1", f"{model.__name__}.schema.json").is_file()
        assert Path(generated, f"{model.__name__}.schema.json").is_file()


@pytest.mark.parametrize("model", SCHEMA_MODELS, ids=lambda model: model.__name__)
def test_committed_schema_matches_model(model: type[BaseModel]) -> None:
    path = Path("schemas/v1alpha1") / f"{model.__name__}.schema.json"
    committed = json.loads(path.read_text(encoding="utf-8"))
    assert committed == model.model_json_schema(mode="validation")


def test_g1a_exports_only_its_nine_additive_canonical_model_schemas() -> None:
    exported_names = tuple(model.__name__ for model in SCHEMA_MODELS)

    assert exported_names[-len(_G1A_SCHEMA_NAMES) :] == _G1A_SCHEMA_NAMES
    assert not {
        "AuthorityInputGateResultV8",
        "AuthorityInputTerminationV8",
        "BoundedAuthorityInputFailureV8",
        "BoundedAuthorityInputSuccessV8",
        "BoundedJsonDocumentV8",
        "SourceDataV8",
        "SourceDisconnectedV8",
        "SourceEofV8",
        "SourceFramingFailureV8",
    } & set(exported_names)
