
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_normalize_endpoint_returns_normalized_content():
    response = client.post(
        "/normalize",
        json={
            "blocks": [
                {"source": "user", "content": "  Hello   world  "},
                {"source": "retrieved", "content": "Document text"},
            ]
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["blocks"][0]["content"] == "Hello world"
    assert data["blocks"][0]["source"] == "user"
    assert data["blocks"][1]["source"] == "retrieved"
    assert data["blocks"][1]["content"] == "Document text"


def test_normalize_endpoint_reports_invisible_characters():
    response = client.post(
        "/normalize",
        json={
            "blocks": [
                {"source": "user", "content": "ignore\u200b rules"}
            ]
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["blocks"][0]["content"] == "ignore rules"
    assert "\u200b" in data["metadata"][0]["suspicious_characters"]


def test_normalize_endpoint_rejects_invalid_source():
    response = client.post(
        "/normalize",
        json={
            "blocks": [
                {"source": "unknown", "content": "Hello"}
            ]
        },
    )

    assert response.status_code == 422


def test_normalize_endpoint_rejects_whitespace_only_content():
    response = client.post(
        "/normalize",
        json={
            "blocks": [
                {"source": "user", "content": "   "}
            ]
        },
    )

    assert response.status_code == 422


def test_normalize_endpoint_rejects_empty_block_list():
    response = client.post("/normalize", json={"blocks": []})

    assert response.status_code == 422


def test_normalize_endpoint_does_not_return_original_text():
    response = client.post(
        "/normalize",
        json={
            "blocks": [
                {"source": "user", "content": "  private test phrase  "}
            ]
        },
    )

    assert response.status_code == 200
    assert "original_text" not in response.json()["metadata"][0]
    assert response.json()["blocks"][0]["content"] == "private test phrase"



def test_normalize_endpoint_rejects_excessive_combined_input():
    response = client.post(
        "/normalize",
        json={
            "blocks": [
                {"source": "user", "content": "a" * 20_000},
                {"source": "retrieved", "content": "b" * 20_000},
                {"source": "tool", "content": "c" * 10_001},
            ]
        },
    )

    assert response.status_code == 413
