"""Unified rule-based detection pipeline for NexaShield."""

from backend.detectors.findings import SecurityFinding
from backend.detectors.injection_detector import detect_injection
from backend.detectors.pii_detector import detect_pii
from backend.detectors.secret_detector import detect_secrets


def detect_sensitive_data(text: str) -> list[SecurityFinding]:
    """Run PII and secret detectors and return ordered findings.

    Preserved from Phase 3 for callers that only need PII/secret detection
    (e.g. redaction, which must not touch prompt-injection spans).
    """
    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    findings = detect_pii(text) + detect_secrets(text)

    return sorted(
        findings,
        key=lambda item: (item.start, item.end, item.category),
    )


def detect_all(text: str, source: str = "user") -> list[SecurityFinding]:
    """Run every Phase 4A detector and return a single ordered finding list.

    Combines PII, secret, and rule-based prompt-injection findings.

    `source` is forwarded to the injection detector. Only "retrieved" and
    "tool" sources trigger the indirect-injection rules. A caller-supplied
    source label is metadata, not proof of trust — a future policy engine
    will weigh source alongside findings.

    This function only REPORTS findings. It never blocks, allows, or
    decides. Policy decisions belong to a future phase.

    Findings are sorted by (start, end, category, rule_id) so output order
    is fully deterministic even when multiple rules fire on the same span.
    """
    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    findings = (
        detect_pii(text)
        + detect_secrets(text)
        + detect_injection(text, source=source)
    )

    return sorted(
        findings,
        key=lambda item: (
            item.start,
            item.end,
            item.category,
            item.rule_id or "",
        ),
    )