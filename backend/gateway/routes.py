
"""Secure LLM gateway routes for NexaShield."""

import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.detectors.routes import (
    InspectBlockRequest,
    InspectRequest,
    inspect_endpoint,
)
from backend.gateway.providers import get_llm_provider

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
    findings: list[dict]


@router.post(
    "/chat",
    response_model=GatewayResponse,
    status_code=status.HTTP_200_OK,
)
def gateway_chat(request: GatewayRequest) -> GatewayResponse:
    """Inspect, enforce policy, and then forward to an LLM provider."""

    # 1. Inspect the prompt using the existing inspection pipeline.
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
        logger.exception("Gateway inspection failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security inspection failed. Request was not forwarded.",
        ) from exc

    if not inspection.blocks:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security inspection returned no result.",
        )

    inspected = inspection.blocks[0]

    # 2. Fail closed if a required detector is unavailable.
    if inspection.unavailable_detectors:
        logger.error(
            "Gateway blocked request because detectors are unavailable: %s",
            inspection.unavailable_detectors,
        )

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "message": (
                    "Required security detectors are unavailable. "
                    "Request was not forwarded."
                ),
                "unavailable_detectors": (
                    inspection.unavailable_detectors
                ),
            },
        )

    # 3. Enforce the policy decision.
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

    # 4. Use the redacted content for all permitted forwarding.
    # This prevents original PII/secrets from reaching the provider.
    forwarded_prompt = inspected.redacted_content

    sanitized = (
        forwarded_prompt != request.content
        or inspected.policy.action == "sanitize"
    )

    # 5. Resolve provider only after security checks pass.
    try:
        provider = get_llm_provider()
    except RuntimeError as exc:
        logger.exception("LLM provider configuration failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM provider is not available.",
        ) from exc

    # 6. Forward the inspected prompt.
    try:
        response_text = provider.generate(forwarded_prompt)
    except Exception as exc:
        logger.exception("LLM provider request failed")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The configured LLM provider request failed.",
        ) from exc

    return GatewayResponse(
        response=response_text,
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
    )
