
"""Input normalization utilities for NexaShield."""

import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class NormalizationResult:
    """Original input, normalized text, and transformation metadata."""

    original_text: str
    normalized_text: str
    transformations: tuple[str, ...]
    suspicious_characters: tuple[str, ...]


# Common invisible formatting characters that may hide prompt content.
_INVISIBLE_FORMATTING = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space / BOM
}

# Control characters are examined separately from ordinary whitespace.
_ALLOWED_WHITESPACE = {"\n", "\r", "\t"}


def normalize_input(
    text: str,
    *,
    max_length: int = 20_000,
) -> NormalizationResult:
    """
    Normalize text for downstream security analysis.

    The original input is preserved. Suspicious characters are reported
    rather than silently removed from the original.
    """
    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    if max_length < 1:
        raise ValueError("max_length must be at least 1.")

    if not text.strip():
        raise ValueError("Input must not be empty.")

    if len(text) > max_length:
        raise ValueError(f"Input exceeds the {max_length}-character limit.")

    transformations = []
    suspicious = []

    # NFKC standardizes compatible Unicode representations.
    normalized = unicodedata.normalize("NFKC", text)
    if normalized != text:
        transformations.append("unicode_nfkc")

    # Record invisible formatting characters before removing them
    # from the analysis copy.
    for char in normalized:
        if char in _INVISIBLE_FORMATTING and char not in suspicious:
            suspicious.append(char)

    if suspicious:
        normalized = "".join(
            char for char in normalized if char not in _INVISIBLE_FORMATTING
        )
        transformations.append("removed_invisible_formatting")

    # Report unexpected control characters. Preserve common whitespace.
    for char in normalized:
        if (
            unicodedata.category(char) == "Cc"
            and char not in _ALLOWED_WHITESPACE
            and char not in suspicious
        ):
            suspicious.append(char)

    # Normalize line endings and trim leading/trailing whitespace.
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    trimmed = normalized.strip()
    if trimmed != normalized:
        transformations.append("trimmed_whitespace")
    normalized = trimmed

    # Collapse repeated horizontal whitespace without joining separate lines.
    lines = normalized.split("\n")
    cleaned_lines = [" ".join(line.split()) for line in lines]
    cleaned = "\n".join(cleaned_lines)

    if cleaned != normalized:
        transformations.append("collapsed_whitespace")
    normalized = cleaned

    return NormalizationResult(
        original_text=text,
        normalized_text=normalized,
        transformations=tuple(transformations),
        suspicious_characters=tuple(suspicious),
    )
