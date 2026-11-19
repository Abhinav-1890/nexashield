
from types import SimpleNamespace

import pytest

from backend.audit.models import create_audit_event
from backend.audit.service import (
    AuditPersistenceError,
    record_audit_event,
)
from backend.detectors.findings import SecurityFinding


def test_audit_event_contains_request_metadata():
    event = create_audit_event(
        event_type="gateway",
        status="success",
        request_id="test-request-123",
        input_risk_score=0.1,
        output_risk_score=0.0,
        policy_action="allow",
    )

    assert event["request_id"] == "test-request-123"
    assert event["event_type"] == "gateway"
    assert event["status"] == "success"
    assert event["input_risk_score"] == 0.1
    assert event["output_risk_score"] == 0.0
    assert event["policy_action"] == "allow"
    assert event["timestamp"].tzinfo is not None


def test_audit_event_excludes_sensitive_evidence():
    finding = SecurityFinding(
        category="api_key",
        severity="high",
        start=0,
        end=20,
        detector="secret.pattern",
        evidence="SECRET_API_KEY_VALUE",
        confidence=0.99,
    )

    event = create_audit_event(
        event_type="inspection",
        status="success",
        findings=[finding],
    )

    assert len(event["findings"]) == 1
    assert "category" in event["findings"][0]
    assert "detector" in event["findings"][0]
    assert "evidence" not in event["findings"][0]
    assert "SECRET_API_KEY_VALUE" not in str(event)


def test_optional_audit_failure_does_not_raise(monkeypatch):
    monkeypatch.setattr(
        "backend.audit.service.get_settings",
        lambda: SimpleNamespace(audit_required=False),
    )

    def fail_insert(event):
        raise RuntimeError("MongoDB unavailable")

    monkeypatch.setattr(
        "backend.audit.service.mongo_store.insert_audit_event",
        fail_insert,
    )

    assert record_audit_event({"event_id": "test"}) is False


def test_optional_audit_failure_does_not_log_exception_text(
    monkeypatch,
    caplog,
):
    monkeypatch.setattr(
        "backend.audit.service.get_settings",
        lambda: SimpleNamespace(audit_required=False),
    )

    secret = "do-not-log-this-secret"

    def fail_insert(event):
        raise RuntimeError(secret)

    monkeypatch.setattr(
        "backend.audit.service.mongo_store.insert_audit_event",
        fail_insert,
    )

    record_audit_event({"event_id": "safe-event-id"})

    assert secret not in caplog.text
    assert "safe-event-id" in caplog.text
    assert "error_type=RuntimeError" in caplog.text


def test_required_audit_failure_raises(monkeypatch):
    monkeypatch.setattr(
        "backend.audit.service.get_settings",
        lambda: SimpleNamespace(audit_required=True),
    )

    def fail_insert(event):
        raise RuntimeError("MongoDB unavailable")

    monkeypatch.setattr(
        "backend.audit.service.mongo_store.insert_audit_event",
        fail_insert,
    )

    with pytest.raises(AuditPersistenceError):
        record_audit_event({"event_id": "test"})


def test_audit_event_has_unique_event_ids():
    first = create_audit_event(
        event_type="inspection",
        status="success",
    )
    second = create_audit_event(
        event_type="inspection",
        status="success",
    )

    assert first["event_id"] != second["event_id"]
