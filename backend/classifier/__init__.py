
"""Machine-learning classifiers used by NexaShield."""

from backend.classifier.model import detect_ml_injection
from backend.classifier.wolf_defender import detect_wolf_injection

__all__ = [
    "detect_ml_injection",
    "detect_wolf_injection",
]
