
"""Unified detection pipeline for NexaShield."""

from backend.classifier.model import detect_ml_injection

from backend.detectors.findings import SecurityFinding
from backend.detectors.injection_detector import detect_injection
from backend.detectors.pii_detector import detect_pii
from backend.detectors.secret_detector import detect_secrets


def detect_sensitive_data(text: str) -> list[SecurityFinding]:
    """Run PII and secret detectors only.

    Preserved from Phase 3 for callers that only need PII/secret
    detection, such as the redaction module.
    """

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    findings = (
        detect_pii(text)
        + detect_secrets(text)
    )

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
    """Run all NexaShield detectors.

    Detection layers:
        1. PII detection
        2. Secret detection
        3. Rule-based prompt-injection detection
        4. ML-based prompt-injection detection

    The ML detector is skipped when the rule-based detector
    has already identified prompt injection in the same block.
    This avoids duplicate injection findings.

    All detectors only report findings. They do not block,
    allow, or make policy decisions.
    """

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    # Layer 1: PII detection
    pii_findings = detect_pii(text)

    # Layer 2: Secret detection
    secret_findings = detect_secrets(text)

    # Layer 3: Rule-based injection detection
    rule_findings = detect_injection(
        text,
        source=source,
    )

    # Layer 4: ML-based injection detection
    if any(
        finding.category == "prompt_injection"
        for finding in rule_findings
    ):
        ml_findings = []

    else:
        ml_findings = detect_ml_injection(text)

    findings = (
        pii_findings
        + secret_findings
        + rule_findings
        + ml_findings
    )

    # Deterministic ordering
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
