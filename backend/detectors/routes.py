
"""FastAPI route for NexaShield security inspection."""

from typing import Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

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


@router.post(
    "/inspect",
    response_model=InspectResponse,
    status_code=status.HTTP_200_OK,
)
def inspect_endpoint(request: InspectRequest) -> InspectResponse:
    """Normalize, inspect, score risk, enforce policy, and redact."""

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

        for block in normalized.blocks:

            # Run all available security detectors.
            findings, block_unavailable = detect_all_with_status(
                block.content,
                source=block.source,
            )

            unavailable_detectors.update(block_unavailable)

            # Calculate normalized LARVA risk score (0.0–1.0).
            risk = calculate_risk(findings)

            # Apply LARVA policy thresholds.
            policy = enforce_policy(risk)

            # Redact sensitive information only.
            # Prompt-injection findings are reported, not redacted.
            redaction_findings = [
                finding
                for finding in findings
                if finding.category != "prompt_injection"
            ]

            redaction = redact_sensitive_data(
                block.content,
                redaction_findings,
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

    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
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
    )
