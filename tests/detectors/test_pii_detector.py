
import pytest

from backend.detectors.pii_detector import detect_pii


def test_detects_email_address():
    text = "Contact test.user@example.com for support."

    findings = detect_pii(text)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "email"
    assert text[finding.start:finding.end] == "test.user@example.com"
    assert finding.detector == "pii_detector"


def test_detects_phone_number_candidate():
    text = "Call +1 (212) 555-0198 today."

    findings = detect_pii(text)

    phone_findings = [f for f in findings if f.category == "phone"]
    assert len(phone_findings) == 1
    assert text[phone_findings[0].start:phone_findings[0].end] == (
        "+1 (212) 555-0198"
    )


def test_detects_multiple_pii_findings_in_order():
    text = "test@example.com; +1 212 555 0198"

    findings = detect_pii(text)

    assert len(findings) == 2
    assert findings[0].category == "email"
    assert findings[1].category == "phone"
    assert findings[0].start < findings[1].start


def test_does_not_flag_ordinary_text():
    findings = detect_pii("Hello, this is an ordinary sentence.")

    assert findings == []


def test_rejects_non_string_input():
    with pytest.raises(TypeError, match="must be a string"):
        detect_pii(123)


def test_finding_does_not_store_the_matched_value():
    findings = detect_pii("test@example.com")

    assert len(findings) == 1
    assert not hasattr(findings[0], "value")
    assert not hasattr(findings[0], "matched_text")
