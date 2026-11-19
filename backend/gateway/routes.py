
"""Secure LLM gateway with input/output verification and audit logging."""

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.audit.models import create_audit_event
from backend.audit.service import (
    AuditPersistenceError,
    record_audit_event,
)
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
    content: str = Field(min_length=1, max_length=20_000)


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


def _audit_gateway_event(**kwargs: Any) -> None:
    """Persist a gateway event and enforce required audit mode."""

    try:
        event = create_audit_event(
            event_type="gateway",
            source="llm_gateway",
            **kwargs,
        )
        record_audit_event(event)

    except AuditPersistenceError as exc:
        logger.exception("Required gateway audit failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Required audit persistence failed.",
        ) from exc


@router.post(
    "/chat",
    response_model=GatewayResponse,
    status_code=status.HTTP_200_OK,
)
def gateway_chat(request: GatewayRequest) -> GatewayResponse:
    """Inspect input, generate, verify output, audit and return."""

    # 1. Inspect incoming prompt.
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

    request_id = inspection.request_id
    inspected = inspection.blocks[0]

    common_audit = {
        "request_id": request_id,
        "provider": None,
        "model": None,
        "input_risk_score": inspected.risk.score,
        "input_risk_level": inspected.risk.level,
        "policy_action": inspected.policy.action,
        "input_sanitized": (
            inspected.redacted_content != request.content
            or inspected.policy.action == "sanitize"
        ),
        "findings": [
            finding.model_dump()
            for finding in inspected.findings
        ],
        "unavailable_detectors": inspection.unavailable_detectors,
    }

    # 2. Fail closed if any required input detector is unavailable.
    if inspection.unavailable_detectors:
        _audit_gateway_event(
            **common_audit,
            status="failed",
            failure_code="input_detector_unavailable",
        )

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "message": "Required input security detectors are unavailable.",
                "unavailable_detectors": inspection.unavailable_detectors,
            },
        )

    # 3. Enforce input policy.
    if inspected.policy.action == "block":
        _audit_gateway_event(
            **common_audit,
            status="blocked",
            failure_code="input_policy_block",
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Request blocked by NexaShield policy.",
                "risk_score": inspected.risk.score,
                "risk_level": inspected.risk.level,
                "policy_action": inspected.policy.action,
            },
        )

    forwarded_prompt = inspected.redacted_content
    sanitized = common_audit["input_sanitized"]

    # 4. Resolve provider only after security checks.
    try:
        provider = get_llm_provider()
    except RuntimeError as exc:
        logger.exception("LLM provider configuration failed")

        _audit_gateway_event(
            **common_audit,
            status="failed",
            failure_code="provider_configuration_failed",
        )

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM provider is not available.",
        ) from exc

    # 5. Generate response.
    try:
        response_text = provider.generate(forwarded_prompt)
    except Exception as exc:
        logger.exception("LLM provider request failed")

        _audit_gateway_event(
            **{
                **common_audit,
                "provider": provider.name,
                "model": provider.model,
            },
            status="failed",
            failure_code="provider_request_failed",
        )

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The configured LLM provider request failed.",
        ) from exc

    # 6. Verify output before returning it.
    try:
        output = verify_output(response_text)
    except Exception as exc:
        logger.exception("LLM output verification failed")

        _audit_gateway_event(
            **{
                **common_audit,
                "provider": provider.name,
                "model": provider.model,
            },
            status="failed",
            failure_code="output_verification_failed",
        )

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "Output verification failed. "
                "The generated response was not returned."
            ),
        ) from exc

    output_findings = [
        finding.__dict__
        for finding in output.findings
    ]

    # 7. Record the verified gateway transaction.
    _audit_gateway_event(
        **{
            **common_audit,
            "provider": provider.name,
            "model": provider.model,
            "output_risk_score": output.risk_score,
            "output_risk_level": output.risk_level,
            "output_sanitized": output.sanitized,
            "findings": (
                common_audit["findings"] + output_findings
            ),
        },
        status="success",
    )

    # 8. Return only verified output.
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
        output_findings=output_findings,
    )
