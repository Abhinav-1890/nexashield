
"""Wolf Defender Small v2.1 semantic prompt-injection classifier."""

from functools import lru_cache
import logging
import os
from pathlib import Path

import numpy as np
import torch

from backend.detectors.findings import SecurityFinding

logger = logging.getLogger("nexashield.wolf_defender")

MODEL_DIR = (
    Path(__file__).resolve().parent
    / "artifacts"
    / "wolf_defender"
)

DEFAULT_THRESHOLD = 0.15
MODEL_WINDOW_SIZE = 2048
WINDOW_OVERLAP = 64


@lru_cache(maxsize=1)
def _load_model():
    """Load the local Wolf Defender model and tokenizer once."""

    if not MODEL_DIR.is_dir():
        raise RuntimeError(
            "Wolf Defender model directory was not found."
        )

    required_files = (
        "config.json",
        "model.safetensors",
        "tokenizer.json",
    )

    for filename in required_files:
        if not (MODEL_DIR / filename).is_file():
            raise RuntimeError(
                f"Wolf Defender file missing: {filename}"
            )

    try:
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
        )

        tokenizer = AutoTokenizer.from_pretrained(
            MODEL_DIR,
            local_files_only=True,
        )

        model = AutoModelForSequenceClassification.from_pretrained(
            MODEL_DIR,
            local_files_only=True,
            attn_implementation="eager",
        )

        model.eval()
        model.config.reference_compile = False

        labels = model.config.id2label

        if labels.get(0) != "BENIGN" or labels.get(1) != "INJECTION":
            raise RuntimeError(
                "Wolf Defender model labels are not as expected."
            )

        return tokenizer, model

    except RuntimeError:
        raise

    except Exception as exc:
        logger.exception("Could not load Wolf Defender model")
        raise RuntimeError(
            "Could not load Wolf Defender model."
        ) from exc


def _get_threshold() -> float:
    """Read and validate the Wolf Defender threshold."""

    raw_value = os.getenv(
        "NEXASHIELD_WOLF_THRESHOLD",
        str(DEFAULT_THRESHOLD),
    )

    try:
        threshold = float(raw_value)
    except ValueError as exc:
        raise ValueError(
            "NEXASHIELD_WOLF_THRESHOLD must be a number "
            "between 0 and 1."
        ) from exc

    if not 0.0 <= threshold <= 1.0:
        raise ValueError(
            "NEXASHIELD_WOLF_THRESHOLD must be between 0 and 1."
        )

    return threshold


def _document_injection_probability(
    text: str,
    tokenizer,
    model,
) -> tuple[float, int]:
    """Score a complete document using official sliding-window pooling."""

    tokens = tokenizer.encode(
        text,
        add_special_tokens=False,
        truncation=False,
    )

    windows = []
    start = 0
    content_window_size = MODEL_WINDOW_SIZE - 2

    while True:
        end = min(
            start + content_window_size,
            len(tokens),
        )

        windows.append(tokens[start:end])

        if end == len(tokens):
            break

        start = end - WINDOW_OVERLAP

    logits = []

    for window in windows:
        input_ids = (
            [tokenizer.cls_token_id]
            + window
            + [tokenizer.sep_token_id]
        )

        input_tensor = torch.tensor(
            [input_ids],
            dtype=torch.long,
        )

        attention_mask = torch.ones_like(input_tensor)

        with torch.inference_mode():
            output = model(
                input_ids=input_tensor,
                attention_mask=attention_mask,
            )

        logits.append(
            output.logits[0].float().cpu().numpy()
        )

    values = np.stack(logits).astype(np.float32)

    temperature = 1.0 if len(values) == 1 else 0.1

    maximum = values.max(axis=0)

    pooled = maximum + temperature * (
        np.log(
            np.exp(
                (values - maximum) / temperature
            ).sum(axis=0)
        )
        - np.log(len(values))
    )

    probabilities = np.exp(
        pooled - pooled.max()
    )

    probabilities /= probabilities.sum()

    return float(probabilities[1]), len(windows)


def detect_wolf_injection(
    text: str,
) -> list[SecurityFinding]:
    """Detect semantic prompt injection without making policy decisions."""

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    if not text.strip():
        return []

    threshold = _get_threshold()
    tokenizer, model = _load_model()

    try:
        confidence, _ = _document_injection_probability(
            text,
            tokenizer,
            model,
        )

    except Exception as exc:
        logger.exception(
            "Wolf Defender inference failed"
        )

        raise RuntimeError(
            "Wolf Defender inference failed."
        ) from exc

    # The official threshold comparison is strict.
    if confidence <= threshold:
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
            detector="ml.wolf_defender",
            injection_category="semantic_ml_classification",
            evidence=(
                "Wolf Defender semantic injection probability "
                "exceeded configured threshold"
            ),
            confidence=confidence,
        )
    ]
