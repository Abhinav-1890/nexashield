import logging

from fastapi import FastAPI, HTTPException, status

from backend.core.config import get_settings
from backend.db.mongo import mongo_store
from backend.normalization.routes import router as normalization_router
from backend.detectors.routes import router as inspection_router

settings = get_settings()
logging.basicConfig(level=settings.log_level.upper())
logger = logging.getLogger("nexashield")

app = FastAPI(
    title=settings.app_name,
    description="Modular runtime security gateway for LLM applications.",
    version="0.1.0",
)

app.include_router(normalization_router)
app.include_router(inspection_router)

@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    """Liveness endpoint; intentionally independent of external services."""
    return {"status": "ok", "service": "nexashield"}


@app.get("/health/db", tags=["health"])
def database_health() -> dict[str, str]:
    """Check Atlas connectivity without exposing connection details."""
    if not get_settings().mongodb_uri:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MongoDB is not configured. Set MONGODB_URI in the environment.",
        )

    try:
        connected = mongo_store.ping()
    except Exception:
        # Deliberately avoid returning exception details, which could leak config.
        logger.exception("MongoDB health check failed")
        connected = False

    if not connected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MongoDB is not reachable. Check Atlas network access and credentials.",
        )

    return {"status": "ok", "database": "connected"}
