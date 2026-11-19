
import pytest

from backend.novelty.detector import (
    calculate_novelty,
    detect_novelty,
)


def test_empty_text_has_zero_novelty():
    assert calculate_novelty("") == 0.0


def test_invalid_input_raises_type_error():
    with pytest.raises(TypeError):
        calculate_novelty(None)


def test_novelty_score_is_normalized():
    score = calculate_novelty(
        "Explain binary search with an example."
    )

    assert 0.0 <= score <= 1.0


def test_known_prompt_has_valid_novelty_score():
    score = calculate_novelty(
        "Explain how photosynthesis works."
    )

    assert 0.0 <= score <= 1.0


def test_novelty_finding_is_report_only(monkeypatch):
    import backend.novelty.detector as detector

    monkeypatch.setattr(
        detector,
        "_get_threshold",
        lambda: 0.5,
    )

    monkeypatch.setattr(
        detector,
        "calculate_novelty",
        lambda text: 0.9,
    )

    findings = detect_novelty(
        "An unfamiliar technical question."
    )

    assert len(findings) == 1
    assert findings[0].category == "novelty"
    assert findings[0].severity == "low"
    assert findings[0].detector == "semantic.minilm"
    assert findings[0].confidence == 0.9


def test_familiar_prompt_does_not_trigger_novelty(monkeypatch):
    import backend.novelty.detector as detector

    monkeypatch.setattr(
        detector,
        "_get_threshold",
        lambda: 0.65,
    )

    monkeypatch.setattr(
        detector,
        "calculate_novelty",
        lambda text: 0.20,
    )

    assert detect_novelty("A familiar prompt.") == []
