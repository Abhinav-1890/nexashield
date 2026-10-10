
"""FastAPI routes for NexaShield input normalization."""

from typing import Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, ValidationError

from backend.normalization.models import ContentBlock, normalize_blocks

router = APIRouter(tags=["normalization"])

ContentSource = Literal["system", "user", "retrieved", "tool"]


class ContentBlockRequest(BaseModel):
    source: ContentSource
    content: str = Field(min_length=1, max_length=20_000)


class NormalizeRequest(BaseModel):
    blocks: list[ContentBlockRequest] = Field(min_length=1, max_length=50)


class NormalizedBlockResponse(BaseModel):
    source: ContentSource
    content: str


class BlockMetadataResponse(BaseModel):
    transformations: list[str]
    suspicious_characters: list[str]


class NormalizeResponse(BaseModel):
    blocks: list[NormalizedBlockResponse]
    metadata: list[BlockMetadataResponse]


@router.post(
    "/normalize",
    response_model=NormalizeResponse,
    status_code=status.HTTP_200_OK,
)
def normalize_endpoint(request: NormalizeRequest) -> NormalizeResponse:
    """Normalize structured text without returning original prompt content."""
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
        result = normalize_blocks(blocks)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    return NormalizeResponse(
        blocks=[
            NormalizedBlockResponse(source=block.source, content=block.content)
            for block in result.blocks
        ],
        metadata=[
            BlockMetadataResponse(
                transformations=list(item.transformations),
                suspicious_characters=list(item.suspicious_characters),
            )
            for item in result.results
        ],
    )
