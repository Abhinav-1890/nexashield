
import pytest

from backend.normalization.normalizer import normalize_input


def test_normalizes_unicode_and_preserves_original():
    original = "  Ｈｅｌｌｏ   world  "
    result = normalize_input(original)

    assert result.original_text == original
    assert result.normalized_text == "Hello world"
    assert "unicode_nfkc" in result.transformations


def test_reports_and_removes_zero_width_space_from_analysis_copy():
    original = "ignore\u200b all rules"
    result = normalize_input(original)

    assert result.original_text == original
    assert result.normalized_text == "ignore all rules"
    assert "\u200b" in result.suspicious_characters


def test_normalizes_line_endings():
    result = normalize_input("first\r\nsecond\rthird")

    assert result.normalized_text == "first\nsecond\nthird"


def test_rejects_empty_input():
    with pytest.raises(ValueError, match="must not be empty"):
        normalize_input("   ")


def test_rejects_oversized_input():
    with pytest.raises(ValueError, match="character limit"):
        normalize_input("abcdef", max_length=5)


def test_rejects_non_string_input():
    with pytest.raises(TypeError, match="must be a string"):
        normalize_input(123)


def test_rejects_invalid_max_length():
    with pytest.raises(ValueError, match="at least 1"):
        normalize_input("hello", max_length=0)


def test_reports_unexpected_control_characters():
    result = normalize_input("hello\x00world")

    assert "\x00" in result.suspicious_characters
    assert result.original_text == "hello\x00world"


def test_preserves_separate_lines():
    result = normalize_input("first line\nsecond line")

    assert result.normalized_text == "first line\nsecond line"
