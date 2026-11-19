
"""Audit persistence and failure policy."""

import logging
from typing import Any

from backend.core.config import get_settings
from backend.db.mongo import mongo_store

logger = logging.getLogger("nexashield.audit")


class AuditPersistenceError(RuntimeError):
    """Raised when a required audit event cannot be persisted."""


def record_audit_event(event: dict[str, Any]) -> bool:
    """
    Persist an audit event.

    Returns True when persisted.
    In optional mode, persistence failures are logged and return False.
    In required mode, persistence failures raise AuditPersistenceError.
    """

    settings = get_settings()

    try:
        mongo_store.insert_audit_event(event)
        return True

    except Exception as exc:
        # Keep operational logs privacy-safe: do not emit driver exception text,
        # which may contain server details or provider-supplied data.
        logger.error(
            "Audit event persistence failed. Event ID: %s; error_type=%s",
            event.get("event_id", "unknown"),
            type(exc).__name__,
        )

        if settings.audit_required:
            raise AuditPersistenceError(
                "Required audit persistence failed."
            ) from exc

        return False
