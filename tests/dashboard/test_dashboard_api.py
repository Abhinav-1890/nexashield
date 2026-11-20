from fastapi.testclient import TestClient

from backend.dashboard import routes
from backend.detectors.routes import InspectResponse
from backend.main import app


client = TestClient(app)


class FakeDashboardStore:
    def dashboard_overview(self, days=30):
        return {
            "source": "security_audit_logs",
            "range_days": days,
            "metrics": {
                "total_requests": 2,
                "threats_blocked": 1,
                "requests_allowed": 1,
                "requests_sanitized": 0,
                "average_risk_score": 0.5,
            },
            "decisions": [],
        }

    def audit_activity(self, days=30):
        return [{"date": "2026-01-01", "requests": 2, "blocked": 1, "allowed": 1}]

    def threat_categories(self, days=30):
        return [{"category": "prompt_injection", "count": 1}]

    def audit_logs(self, **kwargs):
        return {"items": [{"event_id": "safe-id"}], "total": 1, "has_next": False}


def test_dashboard_endpoints_return_backend_sourced_shapes(monkeypatch):
    monkeypatch.setattr(routes, "mongo_store", FakeDashboardStore())

    assert client.get("/dashboard/overview").json()["metrics"]["total_requests"] == 2
    assert client.get("/dashboard/activity").json()["items"][0]["blocked"] == 1
    assert client.get("/dashboard/threat-categories").json()["items"][0]["category"] == "prompt_injection"
    assert client.get("/dashboard/recent-events").json()["items"][0]["event_id"] == "safe-id"
    assert client.get("/dashboard/audit-logs").json()["total"] == 1


def test_dashboard_errors_are_explicit(monkeypatch):
    class UnavailableStore:
        def dashboard_overview(self, days=30):
            raise RuntimeError("database unavailable")

    monkeypatch.setattr(routes, "mongo_store", UnavailableStore())
    response = client.get("/dashboard/overview")

    assert response.status_code == 503
    assert response.json()["detail"] == "Dashboard data is temporarily unavailable."


def test_test_inspect_uses_pipeline_without_persisting(monkeypatch):
    captured = {}
    monkeypatch.setattr(routes, "get_settings", lambda: type("S", (), {"app_env": "development"})())

    def fake_inspect(request, **kwargs):
        captured.update(kwargs)
        return InspectResponse(
            blocks=[],
            metadata=[],
            unavailable_detectors=[],
            request_id="test-request",
        )

    monkeypatch.setattr(routes, "inspect_endpoint", fake_inspect)

    response = client.post(
        "/dashboard/test-inspect",
        json={"blocks": [{"source": "user", "content": "controlled test"}]},
    )

    assert response.status_code == 200
    assert response.json()["request_id"] == "test-request"
    assert captured == {"persist_audit": False}
