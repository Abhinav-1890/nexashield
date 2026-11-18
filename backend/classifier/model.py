
"""Pretrained Random Forest prompt-injection classifier."""

from functools import lru_cache
import logging
import os
from pathlib import Path

import joblib

from backend.detectors.findings import SecurityFinding

logger = logging.getLogger("nexashield.classifier")

ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "rf_core.joblib"
VECTORIZER_PATH = ARTIFACT_DIR / "tfidf_core.joblib"

DEFAULT_THRESHOLD = 0.85


@lru_cache(maxsize=1)
def _load_artifacts():
    """Load the local model and vectorizer once per process."""

    if not MODEL_PATH.is_file():
        raise RuntimeError(
            f"Classifier model not found: {MODEL_PATH.name}"
        )

    if not VECTORIZER_PATH.is_file():
        raise RuntimeError(
            f"Classifier vectorizer not found: {VECTORIZER_PATH.name}"
        )

    try:
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)

    except Exception as exc:
        logger.exception("Could not load classifier artifacts")
        raise RuntimeError(
            "Could not load prompt-injection classifier."
        ) from exc

    if not hasattr(model, "predict_proba"):
        raise RuntimeError(
            "Classifier does not support predict_proba()."
        )

    if not hasattr(model, "classes_") or 1 not in model.classes_:
        raise RuntimeError(
            "Classifier does not contain the injection class (1)."
        )

    if not hasattr(vectorizer, "transform"):
        raise RuntimeError(
            "Invalid TF-IDF vectorizer artifact."
        )

    return model, vectorizer


def _get_threshold() -> float:
    """Read and validate the configurable injection threshold."""

    raw_value = os.getenv(
        "NEXASHIELD_ML_THRESHOLD",
        str(DEFAULT_THRESHOLD),
    )

    try:
        threshold = float(raw_value)

    except ValueError as exc:
        raise ValueError(
            "NEXASHIELD_ML_THRESHOLD must be a number between 0 and 1."
        ) from exc

    if not 0.0 <= threshold <= 1.0:
        raise ValueError(
            "NEXASHIELD_ML_THRESHOLD must be between 0 and 1."
        )

    return threshold


def detect_ml_injection(text: str) -> list[SecurityFinding]:
    """Detect prompt injection using the pretrained ML classifier.

    The classifier returns a finding when the predicted injection
    probability meets or exceeds the configured threshold.

    This function only reports findings. It never blocks requests
    or makes policy decisions.

    The model classifies the complete input, so the finding spans
    the complete input rather than a specific token range.
    """

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    if not text.strip():
        return []

    threshold = _get_threshold()
    model, vectorizer = _load_artifacts()

    try:
        features = vectorizer.transform([text])

        probabilities = model.predict_proba(features)[0]

        injection_index = list(model.classes_).index(1)

        confidence = float(probabilities[injection_index])

    except Exception as exc:
        logger.exception(
            "Prompt-injection model inference failed"
        )

        raise RuntimeError(
            "Prompt-injection model inference failed."
        ) from exc

    if confidence < threshold:
        return []

    severity = (
        "high"
        if confidence >= 0.95
        else "medium"
    )

    return [
        SecurityFinding(
            category="prompt_injection",
            severity=severity,
            start=0,
            end=len(text),
            detector="ml.random_forest",
            injection_category="ml_classification",
            evidence=(
                "ML injection probability exceeded "
                "configured threshold"
            ),
            confidence=confidence,
        )
    ]
