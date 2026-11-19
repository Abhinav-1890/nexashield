
"""Secure LLM gateway routes for NexaShield."""

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.detectors.routes import (
    InspectBlockRequest,
    InspectRequest,
    inspect_endpoint,
)
from backend.gateway.providers import get_llm_provider
from backend.gateway.output_verifier import verify_output

logger = logging.getLogger("nexashield.gateway")

router = APIRouter(
    prefix="/gateway",
    tags=["llm-gateway"],
)


class GatewayRequest(BaseModel):
    content: str = Field(
        min_length=1,
        max_length=20_000,
    )


class GatewayResponse(BaseModel):
    response: str
    provider: str
    model: str
    risk_score: float
    risk_level: str
    policy_action: str
    sanitized: bool
    findings: list[dict[str, Any]]
    output_risk_score: float
    output_risk_level: str
    output_sanitized: bool
    output_findings: list[dict[str, Any]]


@router.post(
    "/chat",
    response_model=GatewayResponse,
    status_code=status.HTTP_200_OK,
)
def gateway_chat(request: GatewayRequest) -> GatewayResponse:
    """Inspect input, generate a response, verify output, then return it."""

    # 1. Inspect the incoming prompt.
    try:
        inspection = inspect_endpoint(
            InspectRequest(
                blocks=[
                    InspectBlockRequest(
                        source="user",
                        content=request.content,
                    )
                ]
            )
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Gateway input inspection failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Input inspection failed. Request was not forwarded.",
        ) from exc

    if not inspection.blocks:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security inspection returned no result.",
        )

    inspected = inspection.blocks[0]

    # 2. Fail closed if an input detector is unavailable.
    if inspection.unavailable_detectors:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "message": (
                    "Required input security detectors are unavailable. "
                    "Request was not forwarded."
                ),
                "unavailable_detectors": (
                    inspection.unavailable_detectors
                ),
            },
        )

    # 3. Enforce input policy.
    if inspected.policy.action == "block":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Request blocked by NexaShield policy.",
                "risk_score": inspected.risk.score,
                "risk_level": inspected.risk.level,
                "policy_action": inspected.policy.action,
            },
        )

    # 4. Forward only inspected and redacted input.
    forwarded_prompt = inspected.redacted_content

    sanitized = (
        forwarded_prompt != request.content
        or inspected.policy.action == "sanitize"
    )

    # 5. Resolve the provider after input security checks.
    try:
        provider = get_llm_provider()
    except RuntimeError as exc:
        logger.exception("LLM provider configuration failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM provider is not available.",
        ) from exc

    # 6. Generate the response.
    try:
        response_text = provider.generate(forwarded_prompt)
    except Exception as exc:
        logger.exception("LLM provider request failed")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The configured LLM provider request failed.",
        ) from exc

    # 7. Verify generated output before returning it.
    try:
        output = verify_output(response_text)
    except Exception as exc:
        logger.exception("LLM output verification failed")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "Output verification failed. "
                "The generated response was not returned."
            ),
        ) from exc

    # 8. Return only verified and sanitized output.
    return GatewayResponse(
        response=output.content,
        provider=provider.name,
        model=provider.model,
        risk_score=inspected.risk.score,
        risk_level=inspected.risk.level,
        policy_action=inspected.policy.action,
        sanitized=sanitized,
        findings=[
            finding.model_dump()
            for finding in inspected.findings
        ],
        output_risk_score=output.risk_score,
        output_risk_level=output.risk_level,
        output_sanitized=output.sanitized,
        output_findings=[
            finding.__dict__
            for finding in output.findings
        ],
    )
