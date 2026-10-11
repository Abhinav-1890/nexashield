
"""Unified rule-based detection pipeline for NexaShield."""

from backend.detectors.findings import SecurityFinding
from backend.detectors.pii_detector import detect_pii
from backend.detectors.secret_detector import detect_secrets


def detect_sensitive_data(text: str) -> list[SecurityFinding]:
    """Run PII and secret detectors and return ordered findings."""
    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    findings = detect_pii(text) + detect_secrets(text)

    return sorted(
        findings,
        key=lambda item: (item.start, item.end, item.category),
    )
