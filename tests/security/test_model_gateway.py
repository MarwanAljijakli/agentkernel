from __future__ import annotations

import pytest
from agentkernel.domain.enums import ProvenanceTrust
from agentkernel.errors import AgentKernelError, ErrorCode
from agentkernel.model_gateway.gateway import (
    MessagePart,
    MockExternalTransport,
    ModelGateway,
    ModelInferenceRequest,
    ModelResponse,
    ScriptedLocalModel,
)


def _request(*, external: bool, provider: str = "local-scripted") -> ModelInferenceRequest:
    return ModelInferenceRequest(
        request_id="model_request_1",
        goal_id="goal_demo",
        run_id="run_model_demo",
        agent_id="agent:model-demo",
        provider=provider,
        model="scripted-v1",
        purpose="local_demo",
        parts=(
            MessagePart(
                text="classify this synthetic internal canary",
                provenance_ids=("prov_internal_1",),
                provenance_trust=ProvenanceTrust.AUTHORIZED_USER,
                data_classes=("internal",),
            ),
        ),
        external=external,
        retention="none",
        training_use=False,
        token_budget=100,
    )


@pytest.mark.asyncio
@pytest.mark.security
async def test_internal_prompt_succeeds_locally_without_external_dispatch() -> None:
    local = ScriptedLocalModel("local result")
    external = MockExternalTransport()
    gateway = ModelGateway(local_model=local, external_transport=external)

    result = await gateway.infer(_request(external=False))

    assert result.response.text == "local result"
    assert result.response.provenance_trust is ProvenanceTrust.MODEL_GENERATED
    assert result.receipt.external is False
    assert result.receipt.redacted is True
    assert "synthetic internal canary" not in result.receipt.model_dump_json()
    assert local.request_count == 1
    assert external.request_count == 0


@pytest.mark.asyncio
@pytest.mark.security
async def test_external_dispatch_is_disabled_even_when_a_transport_is_present() -> None:
    external = MockExternalTransport()
    gateway = ModelGateway(
        local_model=ScriptedLocalModel("local result"),
        external_transport=external,
    )

    with pytest.raises(AgentKernelError) as captured:
        await gateway.infer(_request(external=True, provider="external-mock"))

    assert captured.value.code is ErrorCode.UNSUPPORTED_SEMANTICS
    assert external.request_count == 0


@pytest.mark.asyncio
@pytest.mark.security
async def test_retrying_the_same_external_request_never_dispatches() -> None:
    external = MockExternalTransport()
    gateway = ModelGateway(
        local_model=ScriptedLocalModel("local result"),
        external_transport=external,
    )
    request = _request(external=True, provider="external-mock")

    for _attempt in range(2):
        with pytest.raises(AgentKernelError) as captured:
            await gateway.infer(request)
        assert captured.value.code is ErrorCode.UNSUPPORTED_SEMANTICS

    assert external.request_count == 0


@pytest.mark.asyncio
@pytest.mark.security
async def test_unadmitted_local_provider_is_denied() -> None:
    local = ScriptedLocalModel("local result")
    gateway = ModelGateway(local_model=local)

    with pytest.raises(AgentKernelError) as captured:
        await gateway.infer(_request(external=False, provider="other-local"))

    assert captured.value.code is ErrorCode.POLICY_DENIED
    assert local.request_count == 0


class _MismatchedLocalModel(ScriptedLocalModel):
    async def infer(self, request: ModelInferenceRequest) -> ModelResponse:
        self.request_count += 1
        return ModelResponse(
            request_id="different_request",
            text="mismatched response",
            provider=request.provider,
            model=request.model,
        )


@pytest.mark.asyncio
@pytest.mark.security
async def test_mismatched_local_response_identity_fails_closed() -> None:
    gateway = ModelGateway(local_model=_MismatchedLocalModel("unused"))

    with pytest.raises(AgentKernelError) as captured:
        await gateway.infer(_request(external=False))

    assert captured.value.code is ErrorCode.INTEGRITY_ERROR
