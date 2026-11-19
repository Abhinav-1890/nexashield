
from backend.detectors.findings import SecurityFinding
from backend.risk_scoring.scorer import (
    SafetyAssessment,
    calculate_risk,
)
from backend.policy.engine import enforce_policy


def make_finding(
    category="email",
    severity="medium",
    start=0,
    end=20,
    detector="test.detector",
):
    return SecurityFinding(
        category=category,
        severity=severity,
        start=start,
        end=end,
        detector=detector,
    )


def test_safe_content_has_zero_risk_and_is_allowed():
    risk = calculate_risk([])
    decision = enforce_policy(risk)

    assert risk.score == 0.0
    assert risk.level == "low"
    assert decision.action == "allow"


def test_prompt_injection_is_blocked():
    finding = make_finding(
        category="prompt_injection",
        severity="high",
    )

    risk = calculate_risk([finding])
    decision = enforce_policy(risk)

    assert risk.score > 0.70
    assert risk.level == "high"
    assert decision.action == "block"


def test_sensitive_information_is_sanitized():
    finding = make_finding(
        category="email",
        severity="medium",
    )

    risk = calculate_risk([finding])
    decision = enforce_policy(risk)

    assert 0.40 < risk.score <= 0.70
    assert risk.level == "medium"
    assert decision.action == "sanitize"


def test_unsafe_safety_assessment_increases_risk():
    safe_risk = calculate_risk([])

    unsafe_risk = calculate_risk(
        [],
        SafetyAssessment(
            verdict="unsafe",
            hazard_categories=("S9",),
        ),
    )

    assert unsafe_risk.score > safe_risk.score
    assert unsafe_risk.level == "high"
    assert "unsafe" in " ".join(
        unsafe_risk.factors
    ).lower()


def test_overlapping_findings_are_not_double_counted():
    findings = [
        make_finding(
            category="prompt_injection",
            severity="high",
            start=0,
            end=32,
            detector="rule.injection",
        ),
        make_finding(
            category="prompt_injection",
            severity="high",
            start=0,
            end=70,
            detector="ml.wolf_defender",
        ),
        make_finding(
            category="prompt_injection",
            severity="high",
            start=37,
            end=69,
            detector="rule.injection",
        ),
    ]

    risk = calculate_risk(findings)

    assert risk.score == 0.80
    assert len([
        factor for factor in risk.factors
        if "detected at" in factor
    ]) == 1


def test_multiple_detectors_add_corroboration():
    findings = [
        make_finding(
            category="prompt_injection",
            severity="high",
            start=0,
            end=30,
            detector="rule.injection",
        ),
        make_finding(
            category="prompt_injection",
            severity="high",
            start=0,
            end=30,
            detector="ml.wolf_defender",
        ),
    ]

    risk = calculate_risk(findings)

    assert risk.score == 0.80
    assert any(
        "corroborated" in factor
        for factor in risk.factors
    )


def test_risk_score_stays_within_normalized_range():
    findings = [
        make_finding(
            category="prompt_injection",
            severity="critical",
            start=index * 10,
            end=index * 10 + 5,
            detector=f"detector.{index}",
        )
        for index in range(10)
    ]

    risk = calculate_risk(findings)

    assert 0.0 <= risk.score <= 1.0
    assert risk.level == "high"
    assert enforce_policy(risk).action == "block"


def test_policy_threshold_boundaries():
    from backend.risk_scoring.scorer import RiskAssessment

    assert enforce_policy(
        RiskAssessment(0.40, "low", ())
    ).action == "allow"

    assert enforce_policy(
        RiskAssessment(0.41, "medium", ())
    ).action == "sanitize"

    assert enforce_policy(
        RiskAssessment(0.70, "medium", ())
    ).action == "sanitize"

    assert enforce_policy(
        RiskAssessment(0.71, "high", ())
    ).action == "block"
