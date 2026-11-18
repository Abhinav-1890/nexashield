
"""Shared finding models for NexaShield security detectors."""

from dataclasses import dataclass
from typing import Literal


FindingCategory = Literal[
    "email",
    "phone",
    "api_key",
    "access_token",
    "password",
    "secret",
    "prompt_injection",
]

Severity = Literal[
    "low",
    "medium",
    "high",
    "critical",
]


@dataclass(frozen=True)
class SecurityFinding:
    """A detector finding that does not contain the matched secret value."""

    category: FindingCategory
    severity: Severity
    start: int
    end: int
    detector: str

    rule_id: str | None = None
    injection_category: str | None = None
    evidence: str | None = None
    confidence: float | None = None

    def __post_init__(self) -> None:

        if self.start < 0:
            raise ValueError(
                "start must be non-negative."
            )

        if self.end <= self.start:
            raise ValueError(
                "end must be greater than start."
            )

        if not self.detector.strip():
            raise ValueError(
                "detector must not be empty."
            )

        if (
            self.rule_id is not None
            and not self.rule_id.strip()
        ):
            raise ValueError(
                "rule_id, if provided, must not be empty."
            )

        if (
            self.injection_category is not None
            and not self.injection_category.strip()
        ):
            raise ValueError(
                "injection_category, if provided, must not be empty."
            )

        if (
            self.evidence is not None
            and len(self.evidence) > 200
        ):
            raise ValueError(
                "evidence must be 200 characters or fewer."
            )

        if self.confidence is not None:
            if not 0.0 <= self.confidence <= 1.0:
                raise ValueError(
                    "confidence must be between 0 and 1."
                )
