
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
]

Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class SecurityFinding:
    """A detector finding that does not contain the matched secret value."""

    category: FindingCategory
    severity: Severity
    start: int
    end: int
    detector: str

    def __post_init__(self) -> None:
        if self.start < 0:
            raise ValueError("start must be non-negative.")

        if self.end <= self.start:
            raise ValueError("end must be greater than start.")

        if not self.detector.strip():
            raise ValueError("detector must not be empty.")
