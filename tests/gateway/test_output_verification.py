
from fastapi.testclient import TestClient

from backend.main import app
from backend.gateway import routes


client = TestClient(app)


class OutputProvider:
    name = "test"
    model = "test-model"

    def __init__(self, output: str):
        self.output = output
        self.calls = []

    def generate(self, prompt: str) -> str:
        self.calls.append(prompt)
        return self.output


def test_gateway_redacts_email_from_llm_output(monkeypatch):
    provider = OutputProvider(
        "The user's email is abhinav@example.com."
    )

    monkeypatch.setattr(
        routes,
        "get_llm_provider",
        lambda: provider,
    )

    response = client.post(
        "/gateway/chat",
        json={"content": "Explain binary search."},
    )

    assert response.status_code == 200

    data = response.json()

    assert "abhinav@example.com" not in data["response"]
    assert "[REDACTED_EMAIL]" in data["response"]

    assert data["output_sanitized"] is True
    assert data["output_risk_score"] > 0
    assert len(data["output_findings"]) >= 1


def test_gateway_returns_clean_output_unchanged(monkeypatch):
    provider = OutputProvider("Binary search has O(log n) time complexity.")

    monkeypatch.setattr(
        routes,
        "get_llm_provider",
        lambda: provider,
    )

    response = client.post(
        "/gateway/chat",
        json={"content": "Explain binary search."},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["response"] == provider.output
    assert data["output_sanitized"] is False
    assert data["output_findings"] == []
    assert data["output_risk_score"] == 0.0


def test_gateway_does_not_return_output_if_verification_fails(
    monkeypatch,
):
    provider = OutputProvider("Potentially sensitive response.")

    monkeypatch.setattr(
        routes,
        "get_llm_provider",
        lambda: provider,
    )

    def failed_verification(text):
        raise RuntimeError("Simulated verifier failure.")

    monkeypatch.setattr(
        routes,
        "verify_output",
        failed_verification,
    )

    response = client.post(
        "/gateway/chat",
        json={"content": "Explain binary search."},
    )

    assert response.status_code == 502
    assert "response" not in response.json()
    assert len(provider.calls) == 1
