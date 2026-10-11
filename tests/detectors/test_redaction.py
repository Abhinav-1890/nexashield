
import pytest

from backend.detectors.findings import SecurityFinding
from backend.detectors.redaction import redact_sensitive_data


def test_redacts_email():
    text = "Contact test@example.com for help."
    finding = SecurityFinding(
        category="email",
        severity="medium",
        start=8,
        end=24,
        detector="pii_detector",
    )

    result = redact_sensitive_data(text, [finding])

    assert result.redacted_text == "Contact [REDACTED_EMAIL] for help."
    assert result.redaction_count == 1


def test_redacts_api_key():
    text = "api_key=AbCdEfGhIjKlMnOpQrSt"
    start = text.index("AbCdEfGhIjKlMnOpQrSt")
    finding = SecurityFinding(
        category="api_key",
        severity="critical",
        start=start,
        end=len(text),
        detector="secret_detector",
    )

    result = redact_sensitive_data(text, [finding])

    assert result.redacted_text == "api_key=[REDACTED_API_KEY]"


def test_preserves_unaffected_text():
    text = "Before test@example.com after"
    start = text.index("test@example.com")
    finding = SecurityFinding(
        category="email",
        severity="medium",
        start=start,
        end=start + len("test@example.com"),
        detector="pii_detector",
    )

    result = redact_sensitive_data(text, [finding])

    assert result.redacted_text.startswith("Before ")
    assert result.redacted_text.endswith(" after")


def test_handles_overlapping_findings():
    text = "abcdefghij"
    findings = [
        SecurityFinding(
            category="secret",
            severity="high",
            start=2,
            end=7,
            detector="test",
        ),
        SecurityFinding(
            category="password",
            severity="high",
            start=5,
            end=9,
            detector="test",
        ),
    ]

    result = redact_sensitive_data(text, findings)

    assert result.redacted_text == "ab[REDACTED_SECRET]j"
    assert result.redaction_count == 1


def test_rejects_out_of_bounds_span():
    finding = SecurityFinding(
        category="email",
        severity="medium",
        start=2,
        end=20,
        detector="test",
    )

    with pytest.raises(ValueError, match="exceeds input length"):
        redact_sensitive_data("short", [finding])


def test_rejects_non_string_input():
    with pytest.raises(TypeError, match="must be a string"):
        redact_sensitive_data(123, [])


def test_rejects_invalid_finding_type():
    with pytest.raises(TypeError, match="SecurityFinding"):
        redact_sensitive_data("hello", ["not a finding"])


def test_empty_findings_preserve_text():
    text = "Nothing sensitive here."

    result = redact_sensitive_data(text, [])

    assert result.redacted_text == text
    assert result.redaction_count == 0
