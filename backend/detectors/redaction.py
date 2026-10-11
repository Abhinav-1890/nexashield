
"""Redact sensitive spans identified by NexaShield detectors."""

from dataclasses import dataclass

from backend.detectors.findings import SecurityFinding


@dataclass(frozen=True)
class RedactionResult:
    """Redacted text and the number of findings processed."""

    redacted_text: str
    redaction_count: int


_PLACEHOLDERS = {
    "email": "[REDACTED_EMAIL]",
    "phone": "[REDACTED_PHONE]",
    "api_key": "[REDACTED_API_KEY]",
    "access_token": "[REDACTED_ACCESS_TOKEN]",
    "password": "[REDACTED_PASSWORD]",
    "secret": "[REDACTED_SECRET]",
}


def redact_sensitive_data(
    text: str,
    findings: list[SecurityFinding],
) -> RedactionResult:
    """Replace detected spans while preserving all other text."""
    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    if not isinstance(findings, list):
        raise TypeError("findings must be a list.")

    # Validate all spans before modifying the text.
    for finding in findings:
        if not isinstance(finding, SecurityFinding):
            raise TypeError("Each finding must be a SecurityFinding.")

        if finding.end > len(text):
            raise ValueError("Finding span exceeds input length.")

    # Merge overlapping spans so text is never duplicated or corrupted.
    spans = sorted(findings, key=lambda item: (item.start, item.end))
    merged: list[tuple[int, int, str]] = []

    for finding in spans:
        placeholder = _PLACEHOLDERS.get(
            finding.category,
            "[REDACTED_SENSITIVE_DATA]",
        )

        if merged and finding.start < merged[-1][1]:
            start, end, existing_placeholder = merged[-1]
            merged[-1] = (
                start,
                max(end, finding.end),
                existing_placeholder,
            )
        else:
            merged.append((finding.start, finding.end, placeholder))

    # Build from the original text to preserve exact unaffected content.
    parts = []
    cursor = 0

    for start, end, placeholder in merged:
        parts.append(text[cursor:start])
        parts.append(placeholder)
        cursor = end

    parts.append(text[cursor:])

    return RedactionResult(
        redacted_text="".join(parts),
        redaction_count=len(merged),
    )
