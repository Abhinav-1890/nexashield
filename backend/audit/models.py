
"""Privacy-safe audit event construction."""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def create_audit_event(
    *,
    event_type: str,
    status: str,
    request_id: str | None = None,
    source: str = "gateway",
    provider: str | None = None,
    model: str | None = None,
    input_risk_score: float | None = None,
    input_risk_level: str | None = None,
    output_risk_score: float | None = None,
    output_risk_level: str | None = None,
    policy_action: str | None = None,
    input_sanitized: bool = False,
    output_sanitized: bool = False,
    findings: list[Any] | None = None,
    unavailable_detectors: list[str] | None = None,
    failure_code: str | None = None,
) -> dict[str, Any]:
    """Build an audit document without storing prompt or response text."""

    safe_findings = []

    for finding in findings or []:
        if hasattr(finding, "model_dump"):
            finding = finding.model_dump()
        elif hasattr(finding, "__dict__"):
            finding = finding.__dict__

        if not isinstance(finding, dict):
            continue

        # Explicit allowlist: never persist evidence or matched text.
        safe_findings.append({
            key: finding[key]
            for key in (
                "category",
                "severity",
                "detector",
                "rule_id",
                "injection_category",
                "confidence",
            )
            if key in finding and finding[key] is not None
        })

    return {
        "event_id": uuid4().hex,
        "request_id": request_id or uuid4().hex,
        "timestamp": datetime.now(timezone.utc),
        "event_type": event_type,
        "status": status,
        "source": source,
        "provider": provider,
        "model": model,
        "input_risk_score": input_risk_score,
        "input_risk_level": input_risk_level,
        "output_risk_score": output_risk_score,
        "output_risk_level": output_risk_level,
        "policy_action": policy_action,
        "input_sanitized": input_sanitized,
        "output_sanitized": output_sanitized,
        "findings": safe_findings,
        "unavailable_detectors": unavailable_detectors or [],
        "failure_code": failure_code,
    }
