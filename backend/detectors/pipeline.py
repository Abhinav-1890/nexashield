
"""Unified detection pipeline for NexaShield."""

from backend.classifier.model import detect_ml_injection
from backend.classifier.wolf_defender import detect_wolf_injection

from backend.detectors.findings import SecurityFinding
from backend.detectors.injection_detector import detect_injection
from backend.detectors.pii_detector import detect_pii
from backend.detectors.secret_detector import detect_secrets


def detect_sensitive_data(text: str) -> list[SecurityFinding]:
    """Run PII and secret detectors only."""

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    findings = detect_pii(text) + detect_secrets(text)

    return sorted(
        findings,
        key=lambda item: (
            item.start,
            item.end,
            item.category,
        ),
    )


def detect_all(
    text: str,
    source: str = "user",
) -> list[SecurityFinding]:
    """Run all NexaShield security detectors.

    Detection layers:
        1. PII detection
        2. Secret detection
        3. Rule-based prompt-injection detection
        4. Random Forest prompt-injection detection
        5. Wolf Defender semantic prompt-injection detection

    The Random Forest detector is skipped when a rule-based
    injection finding already exists, preserving Phase 4B behavior.

    Wolf Defender runs independently to identify semantic attacks
    and provide an additional detector signal.

    Detectors only report findings. They never make policy decisions.
    """

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    pii_findings = detect_pii(text)
    secret_findings = detect_secrets(text)

    rule_findings = detect_injection(
        text,
        source=source,
    )

    if any(
        finding.category == "prompt_injection"
        for finding in rule_findings
    ):
        rf_findings = []
    else:
        rf_findings = detect_ml_injection(text)

    wolf_findings = detect_wolf_injection(text)

    findings = (
        pii_findings
        + secret_findings
        + rule_findings
        + rf_findings
        + wolf_findings
    )

    return sorted(
        findings,
        key=lambda item: (
            item.start,
            item.end,
            item.category,
            item.rule_id or "",
            item.detector,
        ),
    )
