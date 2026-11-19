
"""Explainable LARVA risk scoring for NexaShield."""

from dataclasses import dataclass
from typing import Literal

from backend.detectors.findings import SecurityFinding


RiskLevel = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class SafetyAssessment:
    """Normalized result from an optional external safety classifier."""

    verdict: Literal["safe", "unsafe"]
    hazard_categories: tuple[str, ...] = ()


@dataclass(frozen=True)
class RiskAssessment:
    """Normalized risk assessment."""

    score: float
    level: RiskLevel
    factors: tuple[str, ...]


# Contributions are normalized to the range 0.0–1.0.
SEVERITY_WEIGHTS = {
    "low": 0.42,
    "medium": 0.50,
    "high": 0.65,
    "critical": 0.70,
}

INJECTION_MINIMUM_SCORE = 0.75
UNSAFE_SAFETY_SCORE = 0.80
CORROBORATION_BONUS = 0.05


def _merge_overlapping_findings(
    findings: list[SecurityFinding],
) -> list[dict]:
    """Merge overlapping findings belonging to the same category."""

    grouped: dict[str, list[SecurityFinding]] = {}

    for finding in findings:
        grouped.setdefault(finding.category, []).append(finding)

    merged = []

    for category, items in grouped.items():
        items.sort(key=lambda item: (item.start, item.end))

        current = None

        for finding in items:
            if current is None:
                current = {
                    "category": category,
                    "start": finding.start,
                    "end": finding.end,
                    "severity": finding.severity,
                    "detectors": {finding.detector},
                }
                continue

            if finding.start <= current["end"]:
                current["end"] = max(current["end"], finding.end)

                if (
                    SEVERITY_WEIGHTS[finding.severity]
                    > SEVERITY_WEIGHTS[current["severity"]]
                ):
                    current["severity"] = finding.severity

                current["detectors"].add(finding.detector)
            else:
                merged.append(current)

                current = {
                    "category": category,
                    "start": finding.start,
                    "end": finding.end,
                    "severity": finding.severity,
                    "detectors": {finding.detector},
                }

        if current is not None:
            merged.append(current)

    return sorted(
        merged,
        key=lambda item: (
            item["start"],
            item["end"],
            item["category"],
        ),
    )


def calculate_risk(
    findings: list[SecurityFinding],
    safety_assessment: SafetyAssessment | None = None,
) -> RiskAssessment:
    """Calculate an explainable normalized LARVA risk score."""

    factors: list[str] = []
    contributions: list[float] = []

    merged_findings = _merge_overlapping_findings(findings)

    for finding in merged_findings:
        contribution = SEVERITY_WEIGHTS[finding["severity"]]

        if finding["category"] == "prompt_injection":
            contribution = max(
                contribution,
                INJECTION_MINIMUM_SCORE,
            )

        detectors = sorted(finding["detectors"])

        if len(detectors) > 1:
            contribution = min(
                contribution + CORROBORATION_BONUS,
                0.95,
            )

        contributions.append(contribution)

        factors.append(
            f"{finding['category']} detected at "
            f"{finding['start']}:{finding['end']} "
            f"({', '.join(detectors)})"
        )

        if len(detectors) > 1:
            factors.append(
                "Multiple detectors corroborated the same finding"
            )

    if safety_assessment is not None:
        if safety_assessment.verdict == "unsafe":
            contributions.append(UNSAFE_SAFETY_SCORE)

            categories = ", ".join(
                safety_assessment.hazard_categories
            )

            factors.append(
                "External safety classifier reported unsafe content"
                + (f" ({categories})" if categories else "")
            )

    # Combine independent signals without exceeding 1.0.
    remaining_risk = 1.0

    for contribution in contributions:
        remaining_risk *= 1.0 - contribution

    score = round(1.0 - remaining_risk, 4)

    if score <= 0.40:
        level: RiskLevel = "low"
    elif score <= 0.70:
        level = "medium"
    else:
        level = "high"

    return RiskAssessment(
        score=score,
        level=level,
        factors=tuple(factors),
    )
