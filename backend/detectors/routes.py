
"""FastAPI route for NexaShield security inspection."""

from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.audit.models import create_audit_event
from backend.audit.service import record_audit_event
from backend.detectors.findings import SecurityFinding
from backend.detectors.pipeline import detect_all_with_status
from backend.detectors.redaction import redact_sensitive_data
from backend.normalization.models import ContentBlock, normalize_blocks
from backend.risk_scoring.scorer import calculate_risk
from backend.policy.engine import enforce_policy


router = APIRouter(tags=["inspection"])

ContentSource = Literal["system", "user", "retrieved", "tool"]


class InspectBlockRequest(BaseModel):
    source: ContentSource
    content: str = Field(min_length=1, max_length=20_000)


class InspectRequest(BaseModel):
    blocks: list[InspectBlockRequest] = Field(min_length=1, max_length=50)


class FindingResponse(BaseModel):
    category: str
    severity: str
    start: int
    end: int
    detector: str
    rule_id: str | None = None
    injection_category: str | None = None
    evidence: str | None = None
    confidence: float | None = None


class RiskResponse(BaseModel):
    score: float
    level: str
    factors: list[str]


class PolicyResponse(BaseModel):
    action: str
    reason: str


class InspectBlockResponse(BaseModel):
    source: ContentSource
    redacted_content: str
    findings: list[FindingResponse]
    redaction_count: int
    risk: RiskResponse
    policy: PolicyResponse


class InspectMetadataResponse(BaseModel):
    transformations: list[str]
    suspicious_characters: list[str]


class InspectResponse(BaseModel):
    blocks: list[InspectBlockResponse]
    metadata: list[InspectMetadataResponse]
    unavailable_detectors: list[str] = Field(default_factory=list)
    request_id: str


@router.post(
    "/inspect",
    response_model=InspectResponse,
    status_code=status.HTTP_200_OK,
)
def inspect_endpoint(
    request: InspectRequest,
    *,
    persist_audit: bool = True,
) -> InspectResponse:
    """Normalize, inspect, score risk, enforce policy, redact and audit."""

    request_id = uuid4().hex

    total_length = sum(
        len(block.content)
        for block in request.blocks
    )

    if total_length > 50_000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Combined input exceeds the 50000-character limit.",
        )

    blocks = [
        ContentBlock(
            source=block.source,
            content=block.content,
        )
        for block in request.blocks
    ]

    unavailable_detectors: set[str] = set()

    try:
        normalized = normalize_blocks(blocks)
        inspected_blocks = []
        audit_findings = []
        audit_scores = []
        audit_levels = []
        audit_actions = []
        audit_sanitized = False

        for block in normalized.blocks:
            findings, block_unavailable = detect_all_with_status(
                block.content,
                source=block.source,
            )

            unavailable_detectors.update(block_unavailable)

            risk = calculate_risk(findings)
            policy = enforce_policy(risk)

            redaction_findings = [
                finding
                for finding in findings
                if finding.category in {
                    "email",
                    "phone",
                    "api_key",
                    "access_token",
                    "password",
                    "secret",
                }
            ]

            redaction = redact_sensitive_data(
                block.content,
                redaction_findings,
            )

            audit_findings.extend(findings)
            audit_scores.append(risk.score)
            audit_levels.append(risk.level)
            audit_actions.append(policy.action)
            audit_sanitized = (
                audit_sanitized or redaction.redaction_count > 0
            )

            inspected_blocks.append(
                InspectBlockResponse(
                    source=block.source,
                    redacted_content=redaction.redacted_text,
                    findings=[
                        FindingResponse(
                            category=finding.category,
                            severity=finding.severity,
                            start=finding.start,
                            end=finding.end,
                            detector=finding.detector,
                            rule_id=finding.rule_id,
                            injection_category=finding.injection_category,
                            evidence=finding.evidence,
                            confidence=finding.confidence,
                        )
                        for finding in findings
                    ],
                    redaction_count=redaction.redaction_count,
                    risk=RiskResponse(
                        score=risk.score,
                        level=risk.level,
                        factors=list(risk.factors),
                    ),
                    policy=PolicyResponse(
                        action=policy.action,
                        reason=policy.reason,
                    ),
                )
            )

        overall_action = (
            "block" if "block" in audit_actions
            else "sanitize" if "sanitize" in audit_actions
            else "allow"
        )

        event = create_audit_event(
            event_type="inspection",
            status="success",
            request_id=request_id,
            source="inspection_api",
            input_risk_score=max(audit_scores, default=0.0),
            input_risk_level=(
                "high" if "high" in audit_levels
                else "medium" if "medium" in audit_levels
                else "low"
            ),
            policy_action=overall_action,
            input_sanitized=audit_sanitized,
            findings=audit_findings,
            unavailable_detectors=sorted(unavailable_detectors),
        )

        if persist_audit:
            record_audit_event(event)

    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Inspection or required audit persistence failed.",
        ) from exc

    return InspectResponse(
        blocks=inspected_blocks,
        metadata=[
            InspectMetadataResponse(
                transformations=list(result.transformations),
                suspicious_characters=list(result.suspicious_characters),
            )
            for result in normalized.results
        ],
        unavailable_detectors=sorted(unavailable_detectors),
        request_id=request_id,
    )
