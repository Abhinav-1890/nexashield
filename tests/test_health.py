from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_health_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "nexashield"}


def test_openapi_is_available():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "NexaShield"


def test_db_health_does_not_expose_secrets_when_unconfigured(monkeypatch):
    from backend.main import get_settings

    class FakeSettings:
        mongodb_uri = ""

    monkeypatch.setattr("backend.main.get_settings", lambda: FakeSettings())
    response = client.get("/health/db")
    assert response.status_code == 503
    assert "MONGODB_URI" in response.json()["detail"]
    assert "password" not in response.text.lower()
