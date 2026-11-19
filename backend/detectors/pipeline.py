
"""Unified detection pipeline for NexaShield."""

import logging

from backend.classifier.model import detect_ml_injection
from backend.classifier.wolf_defender import detect_wolf_injection
from backend.detectors.findings import SecurityFinding
from backend.detectors.injection_detector import detect_injection
from backend.detectors.pii_detector import detect_pii
from backend.detectors.secret_detector import detect_secrets

logger = logging.getLogger("nexashield.pipeline")


def detect_sensitive_data(text: str) -> list[SecurityFinding]:
    """Run PII and secret detectors only."""
    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    findings = detect_pii(text) + detect_secrets(text)

    return sorted(
        findings,
        key=lambda item: (item.start, item.end, item.category),
    )


def detect_all_with_status(
    text: str,
    source: str = "user",
) -> tuple[list[SecurityFinding], list[str]]:
    """Run detectors and report any unavailable optional layers."""

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    pii_findings = detect_pii(text)
    secret_findings = detect_secrets(text)

    rule_findings = detect_injection(text, source=source)

    if any(
        finding.category == "prompt_injection"
        for finding in rule_findings
    ):
        rf_findings = []
    else:
        rf_findings = detect_ml_injection(text)

    unavailable_detectors: list[str] = []
    wolf_findings: list[SecurityFinding] = []

    try:
        wolf_findings = detect_wolf_injection(text)
    except RuntimeError:
        logger.exception(
            "Wolf Defender unavailable; continuing with other detectors."
        )
        unavailable_detectors.append("wolf_defender")

    findings = (
        pii_findings
        + secret_findings
        + rule_findings
        + rf_findings
        + wolf_findings
    )

    findings.sort(
        key=lambda item: (
            item.start,
            item.end,
            item.category,
            item.rule_id or "",
            item.detector,
        )
    )

    return findings, unavailable_detectors


def detect_all(
    text: str,
    source: str = "user",
) -> list[SecurityFinding]:
    """Run all available detectors and return findings."""
    findings, _ = detect_all_with_status(text, source)
    return findings
