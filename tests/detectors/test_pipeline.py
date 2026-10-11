
import pytest

from backend.detectors.pipeline import detect_sensitive_data


def test_detects_pii_and_secrets_together():
    text = (
        "Contact test@example.com. "
        "Use api_key=AbCdEfGhIjKlMnOpQrSt"
    )

    findings = detect_sensitive_data(text)
    categories = {finding.category for finding in findings}

    assert "email" in categories
    assert "api_key" in categories


def test_returns_findings_in_position_order():
    text = "api_key=AbCdEfGhIjKlMnOpQrSt and test@example.com"

    findings = detect_sensitive_data(text)

    assert findings
    assert [f.start for f in findings] == sorted(
        f.start for f in findings
    )


def test_does_not_flag_ordinary_text():
    assert detect_sensitive_data("A normal sentence.") == []


def test_rejects_non_string_input():
    with pytest.raises(TypeError, match="must be a string"):
        detect_sensitive_data(123)


from backend.detectors.redaction import redact_sensitive_data


def test_detect_and_redact_pii_and_secret_together():
    text = (
        "Contact test@example.com. "
        "Use api_key=AbCdEfGhIjKlMnOpQrSt"
    )

    findings = detect_sensitive_data(text)
    result = redact_sensitive_data(text, findings)

    assert "test@example.com" not in result.redacted_text
    assert "AbCdEfGhIjKlMnOpQrSt" not in result.redacted_text
    assert "[REDACTED_EMAIL]" in result.redacted_text
    assert "[REDACTED_API_KEY]" in result.redacted_text
    assert result.redaction_count == 2
