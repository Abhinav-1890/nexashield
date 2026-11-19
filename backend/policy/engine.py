
"""Deterministic LARVA policy enforcement for NexaShield."""

from dataclasses import dataclass
from typing import Literal

from backend.risk_scoring.scorer import RiskAssessment


PolicyAction = Literal["allow", "sanitize", "block"]


@dataclass(frozen=True)
class PolicyDecision:
    action: PolicyAction
    reason: str


def enforce_policy(
    risk: RiskAssessment,
) -> PolicyDecision:
    """Apply documented LARVA risk thresholds."""

    if risk.score <= 0.40:
        return PolicyDecision(
            action="allow",
            reason="Low risk: content is permitted.",
        )

    if risk.score <= 0.70:
        return PolicyDecision(
            action="sanitize",
            reason="Medium risk: content requires sanitization.",
        )

    return PolicyDecision(
        action="block",
        reason="High risk: content is blocked.",
    )
