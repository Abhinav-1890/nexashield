
"""Rule-based detection of common personally identifiable information."""

import re

from backend.detectors.findings import SecurityFinding


_EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
    r"(?<![.,;:!?])"
)



# Candidate detection only; this does not prove that a number is a phone number.
_PHONE_PATTERN = re.compile(
    r"(?<!\w)(?:\+?\d[\d().\-\s]{7,}\d)(?!\w)"
)


def detect_pii(text: str) -> list[SecurityFinding]:
    """Return email and phone candidates without storing matched values."""
    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    findings: list[SecurityFinding] = []

    for match in _EMAIL_PATTERN.finditer(text):
        findings.append(
            SecurityFinding(
                category="email",
                severity="medium",
                start=match.start(),
                end=match.end(),
                detector="pii_detector",
            )
        )

    for match in _PHONE_PATTERN.finditer(text):
        candidate = match.group()
        digits = sum(char.isdigit() for char in candidate)

        # Avoid flagging short numeric values as phone numbers.
        if 8 <= digits <= 15:
            findings.append(
                SecurityFinding(
                    category="phone",
                    severity="medium",
                    start=match.start(),
                    end=match.end(),
                    detector="pii_detector",
                )
            )

    findings.sort(key=lambda finding: (finding.start, finding.end))
    return findings
