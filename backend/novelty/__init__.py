"""NexaShield semantic novelty detection."""

from backend.novelty.detector import (
    calculate_novelty,
    detect_novelty,
)

__all__ = [
    "calculate_novelty",
    "detect_novelty",
]