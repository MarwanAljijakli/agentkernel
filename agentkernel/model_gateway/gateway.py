"""Local/scripted inference and fail-closed external prompt egress."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from pydantic import Field

from agentkernel.canonical import canonical_digest
from agentkernel.domain.enums import ProvenanceTrust
from agentkernel.domain.models import Digest, Identifier, NonEmptyStr, StrictModel
from agentkernel.errors import AgentKernelError, ErrorCode


class MessagePart(StrictModel):
    text: str
    provenance_ids: tuple[Identifier, ...]
    provenance_trust: ProvenanceTrust
    data_classes: Annotated[tuple[NonEmptyStr, ...], Field(min_length=1, max_length=64)]


class ModelInferenceRequest(StrictModel):
    request_id: Identifier
    goal_id: Identifier
    run_id: Identifier
    agent_id: Identifier
    provider: NonEmptyStr
    model: NonEmptyStr
    purpose: NonEmptyStr
    parts: Annotated[tuple[MessagePart, ...], Field(min_length=1, max_length=128)]
    external: bool
    region: NonEmptyStr | None = None
    retention: NonEmptyStr = "none"
    training_use: bool = False
    token_budget: Annotated[int, Field(ge=1, le=1_000_000)]


class ModelResponse(StrictModel):
    request_id: Identifier
    text: str
    provenance_trust: ProvenanceTrust = ProvenanceTrust.MODEL_GENERATED
    provider: NonEmptyStr
    model: NonEmptyStr


class ModelInferenceReceipt(StrictModel):
    request_id: Identifier
    prompt_digest: Digest
    response_digest: Digest
    provider: NonEmptyStr
    model: NonEmptyStr
    external: bool
    redacted: bool = True


class ScriptedLocalModel:
    """Deterministic no-key model used by public demos and tests."""

    def __init__(self, response_text: str) -> None:
        self._response_text = response_text
        self.request_count = 0

    async def infer(self, request: ModelInferenceRequest) -> ModelResponse:
        self.request_count += 1
        return ModelResponse(
            request_id=request.request_id,
            text=self._response_text,
            provider=request.provider,
            model=request.model,
        )


class MockExternalTransport:
    """A test transport whose request count proves whether dispatch occurred."""

    def __init__(self) -> None:
        self.request_count = 0

    async def infer(self, request: ModelInferenceRequest) -> ModelResponse:
        self.request_count += 1
        return ModelResponse(
            request_id=request.request_id,
            text="mock external response",
            provider=request.provider,
            model=request.model,
        )


@dataclass(frozen=True, slots=True)
class GatewayResult:
    response: ModelResponse
    receipt: ModelInferenceReceipt


class ModelGateway:
    """Run the admitted local model and refuse every external provider dispatch."""

    def __init__(
        self,
        *,
        local_model: ScriptedLocalModel,
        external_transport: MockExternalTransport | None = None,
    ) -> None:
        self._local_model = local_model
        self._external_transport = external_transport

    async def infer(self, request: ModelInferenceRequest) -> GatewayResult:
        prompt_material = {
            "goal_id": request.goal_id,
            "run_id": request.run_id,
            "agent_id": request.agent_id,
            "provider": request.provider,
            "model": request.model,
            "external": request.external,
            "purpose": request.purpose,
            "parts": [part.model_dump(mode="python") for part in request.parts],
            "region": request.region,
            "retention": request.retention,
            "training_use": request.training_use,
            "token_budget": request.token_budget,
        }
        prompt_digest = canonical_digest(prompt_material)
        if request.external:
            raise AgentKernelError(
                ErrorCode.UNSUPPORTED_SEMANTICS,
                "External model dispatch is disabled until durable intent and reconciliation exist",
                details={"prompt_digest": prompt_digest},
            )
        if request.provider != "local-scripted":
            raise AgentKernelError(
                ErrorCode.POLICY_DENIED,
                "Local inference must use an admitted local provider",
            )
        response = await self._local_model.infer(request)
        if response.provenance_trust is not ProvenanceTrust.MODEL_GENERATED:
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Model responses must remain labeled model_generated",
            )
        if (
            response.request_id != request.request_id
            or response.provider != request.provider
            or response.model != request.model
        ):
            raise AgentKernelError(
                ErrorCode.INTEGRITY_ERROR,
                "Model response identity does not match the authorized request",
            )
        receipt = ModelInferenceReceipt(
            request_id=request.request_id,
            prompt_digest=prompt_digest,
            response_digest=canonical_digest(
                {"text": response.text, "provenance": response.provenance_trust.value}
            ),
            provider=request.provider,
            model=request.model,
            external=request.external,
        )
        return GatewayResult(response=response, receipt=receipt)
