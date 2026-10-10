
"""Structured input models for NexaShield."""

from dataclasses import dataclass
from typing import Literal

from backend.normalization.normalizer import (
    NormalizationResult,
    normalize_input,
)

ContentSource = Literal["system", "user", "retrieved", "tool"]


@dataclass(frozen=True)
class ContentBlock:
    """A text block with an explicit source label."""

    source: ContentSource
    content: str


@dataclass(frozen=True)
class StructuredNormalizationResult:
    """Normalized blocks with their source labels preserved."""

    blocks: tuple[ContentBlock, ...]
    results: tuple[NormalizationResult, ...]


def normalize_blocks(
    blocks: list[ContentBlock],
    *,
    max_block_length: int = 20_000,
    max_total_length: int = 50_000,
) -> StructuredNormalizationResult:
    """Normalize each content block independently."""
    if not blocks:
        raise ValueError("At least one content block is required.")

    allowed_sources = {"system", "user", "retrieved", "tool"}

    total_length = 0
    normalized_blocks = []
    results = []

    for block in blocks:
        if not isinstance(block, ContentBlock):
            raise TypeError("Each item must be a ContentBlock.")

        if block.source not in allowed_sources:
            raise ValueError(f"Unsupported content source: {block.source}")

        total_length += len(block.content)

        if total_length > max_total_length:
            raise ValueError(
                f"Combined input exceeds the {max_total_length}-character limit."
            )

        result = normalize_input(
            block.content,
            max_length=max_block_length,
        )

        normalized_blocks.append(
            ContentBlock(
                source=block.source,
                content=result.normalized_text,
            )
        )
        results.append(result)

    return StructuredNormalizationResult(
        blocks=tuple(normalized_blocks),
        results=tuple(results),
    )
