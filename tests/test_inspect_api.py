from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_inspect_redacts_email_and_api_key():
    response = client.post(
        "/inspect",
        json={
            "blocks": [
                {
                    "source": "user",
                    "content": (
                        "Contact test@example.com. "
                        "Use api_key=AbCdEfGhIjKlMnOpQrSt"
                    ),
                }
            ]
        },
    )

    assert response.status_code == 200
    data = response.json()
    block = data["blocks"][0]

    assert "test@example.com" not in response.text
    assert "AbCdEfGhIjKlMnOpQrSt" not in response.text
    assert "[REDACTED_EMAIL]" in block["redacted_content"]
    assert "[REDACTED_API_KEY]" in block["redacted_content"]
    assert block["redaction_count"] == 2
    assert len(block["findings"]) >= 2


def test_inspect_preserves_source_and_safe_text():
    response = client.post(
        "/inspect",
        json={
            "blocks": [
                {
                    "source": "user",
                    "content": "Explain how photosynthesis works.",
                }
            ]
        },
    )

    assert response.status_code == 200
    block = response.json()["blocks"][0]

    assert block["source"] == "user"
    assert block["redacted_content"] == "Explain how photosynthesis works."
    assert block["findings"] == []
    assert block["redaction_count"] == 0


def test_inspect_rejects_invalid_source():
    response = client.post(
        "/inspect",
        json={
            "blocks": [
                {
                    "source": "unknown",
                    "content": "Hello",
                }
            ]
        },
    )

    assert response.status_code == 422


def test_inspect_rejects_whitespace_only_content():
    response = client.post(
        "/inspect",
        json={
            "blocks": [
                {
                    "source": "user",
                    "content": "   \n   ",
                }
            ]
        },
    )

    assert response.status_code == 422


def test_inspect_rejects_excessive_combined_input():
    response = client.post(
        "/inspect",
        json={
            "blocks": [
                {"source": "user", "content": "a" * 20_000},
                {"source": "retrieved", "content": "b" * 20_000},
                {"source": "tool", "content": "c" * 10_001},
            ]
        },
    )

    assert response.status_code == 413


def test_inspect_handles_multiple_blocks_independently():
    response = client.post(
        "/inspect",
        json={
            "blocks": [
                {
                    "source": "user",
                    "content": "My email is person@example.com",
                },
                {
                    "source": "retrieved",
                    "content": "This paragraph contains no sensitive data.",
                },
            ]
        },
    )

    assert response.status_code == 200
    blocks = response.json()["blocks"]

    assert len(blocks) == 2
    assert blocks[0]["source"] == "user"
    assert "[REDACTED_EMAIL]" in blocks[0]["redacted_content"]
    assert blocks[1]["source"] == "retrieved"
    assert blocks[1]["findings"] == []
