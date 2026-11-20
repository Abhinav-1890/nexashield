"""Privacy-safe, read-only analytics endpoints backed by audit events."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, status

from backend.core.config import get_settings
from backend.db.mongo import mongo_store
from backend.detectors.routes import InspectRequest, InspectResponse, inspect_endpoint

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
logger = logging.getLogger("nexashield.dashboard")


@router.post("/test-inspect", response_model=InspectResponse)
def test_inspect(request: InspectRequest) -> InspectResponse:
    """Run the real inspection pipeline without writing TEST telemetry."""

    if get_settings().app_env.lower() == "production":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Test inspection is disabled in production.",
        )
    return inspect_endpoint(request, persist_audit=False)


def _service_error(endpoint: str, exc: Exception) -> HTTPException:
    cause_type = type(exc.__cause__).__name__ if exc.__cause__ else "none"
    logger.error(
        "Dashboard database request failed endpoint=%s error_type=%s cause_type=%s",
        endpoint,
        type(exc).__name__,
        cause_type,
    )
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Dashboard data is temporarily unavailable.",
    )


@router.get("/overview")
def overview(days: int = Query(default=30, ge=1, le=365)) -> dict[str, Any]:
    try:
        return mongo_store.dashboard_overview(days=days)
    except Exception as exc:
        raise _service_error("overview", exc)


@router.get("/activity")
def activity(days: int = Query(default=30, ge=1, le=365)) -> dict[str, Any]:
    try:
        return {
            "source": "security_audit_logs",
            "days": days,
            "items": mongo_store.audit_activity(days=days),
        }
    except Exception as exc:
        raise _service_error("activity", exc)


@router.get("/threat-categories")
def threat_categories(days: int = Query(default=30, ge=1, le=365)) -> dict[str, Any]:
    try:
        return {
            "source": "security_audit_logs.findings",
            "days": days,
            "items": mongo_store.threat_categories(days=days),
        }
    except Exception as exc:
        raise _service_error("threat-categories", exc)


@router.get("/recent-events")
def recent_events(limit: int = Query(default=8, ge=1, le=50)) -> dict[str, Any]:
    try:
        return {
            "source": "security_audit_logs",
            "items": mongo_store.audit_logs(limit=limit, skip=0)["items"],
        }
    except Exception as exc:
        raise _service_error("recent-events", exc)


@router.get("/audit-logs")
def audit_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    search: str | None = Query(default=None, max_length=100),
    event_type: str | None = Query(default=None, max_length=40),
    event_status: str | None = Query(default=None, alias="status", max_length=40),
    policy_action: str | None = Query(default=None, max_length=40),
    category: str | None = Query(default=None, max_length=40),
    sort_by: Literal["timestamp", "risk", "status"] = Query(default="timestamp"),
    sort_dir: Literal["asc", "desc"] = Query(default="desc"),
) -> dict[str, Any]:
    try:
        result = mongo_store.audit_logs(
            limit=page_size,
            skip=(page - 1) * page_size,
            search=search,
            event_type=event_type,
            event_status=event_status,
            policy_action=policy_action,
            finding_category=category,
            sort_by=sort_by,
            sort_dir=sort_dir,
        )
        return {
            "source": "security_audit_logs",
            "page": page,
            "page_size": page_size,
            **result,
        }
    except Exception as exc:
        raise _service_error("audit-logs", exc)


@router.get("/health")
def dashboard_health() -> dict[str, Any]:
    settings = get_settings()
    try:
        database_connected = mongo_store.ping()
    except Exception as exc:
        cause_type = type(exc.__cause__).__name__ if exc.__cause__ else "none"
        logger.error(
            "Dashboard database request failed endpoint=health error_type=%s cause_type=%s",
            type(exc).__name__,
            cause_type,
        )
        database_connected = False

    return {
        "source": "runtime",
        "database": {
            "status": "connected" if database_connected else "unavailable",
            "audit_collection": "security_audit_logs",
        },
        "audit_required": settings.audit_required,
        "detectors": [
            {"id": "rule_based", "label": "Rule-based detector", "status": "available"},
            {"id": "pii", "label": "PII detector", "status": "available"},
            {"id": "secrets", "label": "Secret detector", "status": "available"},
            {"id": "output_verifier", "label": "Output verifier", "status": "available"},
            {"id": "random_forest", "label": "Random Forest classifier", "status": "runtime"},
            {"id": "wolf_defender", "label": "Wolf Defender", "status": "runtime"},
            {"id": "novelty", "label": "Semantic novelty detector", "status": "runtime"},
        ],
    }
