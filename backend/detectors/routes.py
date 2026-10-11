"""FastAPI route for NexaShield sensitive-data inspection."""

from typing import Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.detectors.findings import SecurityFinding
from backend.detectors.pipeline import detect_sensitive_data
from backend.detectors.redaction import redact_sensitive_data
from backend.normalization.models import ContentBlock, normalize_blocks

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


class InspectBlockResponse(BaseModel):
    source: ContentSource
    redacted_content: str
    findings: list[FindingResponse]
    redaction_count: int


class InspectMetadataResponse(BaseModel):
    transformations: list[str]
    suspicious_characters: list[str]


class InspectResponse(BaseModel):
    blocks: list[InspectBlockResponse]
    metadata: list[InspectMetadataResponse]


@router.post(
    "/inspect",
    response_model=InspectResponse,
    status_code=status.HTTP_200_OK,
)
def inspect_endpoint(request: InspectRequest) -> InspectResponse:
    """Normalize input, detect sensitive data, and return redacted content."""
    total_length = sum(len(block.content) for block in request.blocks)

    if total_length > 50_000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Combined input exceeds the 50000-character limit.",
        )

    blocks = [
        ContentBlock(source=block.source, content=block.content)
        for block in request.blocks
    ]

    try:
        normalized = normalize_blocks(blocks)

        inspected_blocks = []
        for block in normalized.blocks:
            findings: list[SecurityFinding] = detect_sensitive_data(
                block.content
            )
            redaction = redact_sensitive_data(block.content, findings)

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
                        )
                        for finding in findings
                    ],
                    redaction_count=redaction.redaction_count,
                )
            )

    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
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
    )
