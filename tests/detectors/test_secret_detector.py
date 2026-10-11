
import pytest

from backend.detectors.secret_detector import detect_secrets


def test_detects_password_assignment():
    text = 'password="Example-Password-123"'

    findings = detect_secrets(text)

    assert len(findings) == 1
    assert findings[0].category == "password"
    assert findings[0].severity == "high"
    assert findings[0].detector == "secret_detector"


def test_detects_api_key_assignment():
    text = "api_key=AbCdEfGhIjKlMnOpQrSt"

    findings = detect_secrets(text)

    assert len(findings) == 1
    assert findings[0].category == "api_key"
    assert findings[0].severity == "critical"
    assert text[findings[0].start:findings[0].end] == (
        "AbCdEfGhIjKlMnOpQrSt"
    )


def test_detects_access_token_assignment():
    text = "access_token=AbCdEfGhIjKlMnOpQrSt"

    findings = detect_secrets(text)

    assert len(findings) == 1
    assert findings[0].category == "access_token"
    assert findings[0].severity == "critical"


def test_does_not_flag_ordinary_text():
    findings = detect_secrets("This is a normal sentence.")

    assert findings == []


def test_rejects_non_string_input():
    with pytest.raises(TypeError, match="must be a string"):
        detect_secrets(123)


def test_finding_does_not_store_secret_value():
    findings = detect_secrets("api_key=AbCdEfGhIjKlMnOpQrSt")

    assert len(findings) == 1
    assert not hasattr(findings[0], "value")
    assert not hasattr(findings[0], "matched_text")
