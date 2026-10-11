
"""Rule-based detection of common secrets in text."""

import re

from backend.detectors.findings import SecurityFinding


# Generic assignment patterns detect password-like fields without
# attempting to validate whether a password is real or active.
_PASSWORD_PATTERN = re.compile(
    r"""(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*"""
    r"""(?:"[^"\r\n]{1,256}"|'[^'\r\n]{1,256}'|[^\s,;]{1,256})"""
)

# These are heuristic patterns, not exhaustive vendor-specific validators.
_API_KEY_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|secret[_-]?key)\b\s*[:=]\s*"
    r"""["']?([A-Za-z0-9_\-]{16,})"""
)

_TOKEN_PATTERN = re.compile(
    r"(?i)\b(?:access[_-]?token|auth[_-]?token|bearer)\b\s*[:= ]\s*"
    r"""["']?([A-Za-z0-9._~+/=-]{16,})"""
)


def detect_secrets(text: str) -> list[SecurityFinding]:
    """Return secret-like findings without storing matched values."""
    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    findings: list[SecurityFinding] = []

    for match in _PASSWORD_PATTERN.finditer(text):
        findings.append(
            SecurityFinding(
                category="password",
                severity="high",
                start=match.start(),
                end=match.end(),
                detector="secret_detector",
            )
        )

    for match in _API_KEY_PATTERN.finditer(text):
        # Capture only the credential value, excluding the field name.
        start, end = match.span(1)
        findings.append(
            SecurityFinding(
                category="api_key",
                severity="critical",
                start=start,
                end=end,
                detector="secret_detector",
            )
        )

    for match in _TOKEN_PATTERN.finditer(text):
        start, end = match.span(1)
        findings.append(
            SecurityFinding(
                category="access_token",
                severity="critical",
                start=start,
                end=end,
                detector="secret_detector",
            )
        )

    # Deduplicate overlapping findings and return deterministic ordering.
    unique = {
        (item.category, item.start, item.end): item
        for item in findings
    }

    return sorted(unique.values(), key=lambda item: (item.start, item.end))
