
from datetime import datetime, timedelta, timezone
import re
from threading import Lock
from typing import Any

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from backend.core.config import get_settings


class MongoStore:
    """MongoDB connection wrapper and audit persistence."""

    def __init__(self) -> None:
        self._client: MongoClient | None = None
        self._client_lock = Lock()

    def _get_client(self) -> MongoClient:
        """Return the process-level thread-safe MongoDB client/pool."""

        settings = get_settings()
        if not settings.mongodb_uri:
            raise RuntimeError("MongoDB is not configured.")

        with self._client_lock:
            if self._client is None:
                self._client = MongoClient(
                    settings.mongodb_uri,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                    socketTimeoutMS=5000,
                    waitQueueTimeoutMS=5000,
                    maxPoolSize=20,
                    retryReads=True,
                    retryWrites=True,
                    appname="NexaShield",
                )
            return self._client

    def ping(self) -> bool:
        settings = get_settings()

        if not settings.mongodb_uri:
            return False

        try:
            client = self._get_client()
            client.admin.command("ping")
            return True
        except PyMongoError:
            return False

    def insert_audit_event(self, event: dict[str, Any]) -> None:
        """Insert one privacy-safe event into the audit collection."""

        settings = get_settings()

        if not settings.mongodb_uri:
            raise RuntimeError("MongoDB is not configured.")

        try:
            client = self._get_client()
            database = client[settings.mongodb_database]
            collection = database["security_audit_logs"]

            result = collection.insert_one(event)
            if not result.acknowledged:
                raise RuntimeError(
                    "MongoDB did not acknowledge the security audit event."
                )

        except PyMongoError as exc:
            raise RuntimeError(
                "Could not persist the security audit event."
            ) from exc


    @staticmethod
    def _audit_projection() -> dict[str, int]:
        """Return the safe audit fields exposed to dashboard consumers."""

        return {
            "_id": 0,
            "event_id": 1,
            "request_id": 1,
            "timestamp": 1,
            "event_type": 1,
            "status": 1,
            "source": 1,
            "provider": 1,
            "model": 1,
            "input_risk_score": 1,
            "input_risk_level": 1,
            "output_risk_score": 1,
            "output_risk_level": 1,
            "policy_action": 1,
            "input_sanitized": 1,
            "output_sanitized": 1,
            "findings": 1,
            "unavailable_detectors": 1,
            "failure_code": 1,
        }

    @staticmethod
    def _date_filter(days: int) -> dict[str, Any]:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        return {"timestamp": {"$gte": since}}

    def _with_collection(self, callback):
        settings = get_settings()
        if not settings.mongodb_uri:
            raise RuntimeError("MongoDB is not configured.")
        try:
            client = self._get_client()
            return callback(client[settings.mongodb_database]["security_audit_logs"])
        except PyMongoError as exc:
            raise RuntimeError("Could not read security audit events.") from exc

    def dashboard_overview(self, days: int = 30) -> dict[str, Any]:
        date_filter = self._date_filter(days)

        def query(collection):
            total = collection.count_documents(date_filter)
            blocked = collection.count_documents({**date_filter, "policy_action": "block"})
            allowed = collection.count_documents({**date_filter, "policy_action": "allow"})
            sanitized = collection.count_documents({**date_filter, "policy_action": "sanitize"})
            average = list(collection.aggregate([
                {"$match": date_filter},
                {"$group": {"_id": None, "value": {"$avg": "$input_risk_score"}}},
            ]))
            return {
                "source": "security_audit_logs",
                "range_days": days,
                "metrics": {
                    "total_requests": total,
                    "threats_blocked": blocked,
                    "requests_allowed": allowed,
                    "requests_sanitized": sanitized,
                    "average_risk_score": round(float(average[0]["value"]), 3) if average and average[0].get("value") is not None else 0.0,
                },
                "decisions": [
                    {"name": "Allowed", "value": allowed, "color": "#64e6a4"},
                    {"name": "Sanitized", "value": sanitized, "color": "#f4b860"},
                    {"name": "Blocked", "value": blocked, "color": "#ff6b78"},
                ],
            }

        return self._with_collection(query)

    def audit_activity(self, days: int = 30) -> list[dict[str, Any]]:
        date_filter = self._date_filter(days)

        def query(collection):
            pipeline = [
                {"$match": date_filter},
                {"$group": {
                    "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                    "requests": {"$sum": 1},
                    "blocked": {"$sum": {"$cond": [{"$eq": ["$policy_action", "block"]}, 1, 0]}},
                    "allowed": {"$sum": {"$cond": [{"$eq": ["$policy_action", "allow"]}, 1, 0]}},
                }},
                {"$sort": {"_id": 1}},
            ]
            return [
                {"date": row["_id"], "requests": row["requests"], "blocked": row["blocked"], "allowed": row["allowed"]}
                for row in collection.aggregate(pipeline)
            ]

        return self._with_collection(query)

    def threat_categories(self, days: int = 30) -> list[dict[str, Any]]:
        date_filter = self._date_filter(days)

        def query(collection):
            pipeline = [
                {"$match": date_filter},
                {"$unwind": "$findings"},
                {"$group": {"_id": "$findings.category", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10},
            ]
            return [{"category": row["_id"], "count": row["count"]} for row in collection.aggregate(pipeline)]

        return self._with_collection(query)

    def audit_logs(
        self,
        *,
        limit: int,
        skip: int,
        search: str | None = None,
        event_type: str | None = None,
        event_status: str | None = None,
        policy_action: str | None = None,
        finding_category: str | None = None,
        sort_by: str = "timestamp",
        sort_dir: str = "desc",
    ) -> dict[str, Any]:
        query: dict[str, Any] = {}
        if search:
            safe_search = re.escape(search)
            query["$or"] = [
                {field: {"$regex": safe_search, "$options": "i"}}
                for field in ("event_id", "request_id", "event_type", "status", "source", "provider", "model", "failure_code")
            ]
        if event_type:
            query["event_type"] = event_type
        if event_status:
            query["status"] = event_status
        if policy_action:
            query["policy_action"] = policy_action
        if finding_category:
            query["findings.category"] = finding_category

        sort_field = {
            "timestamp": "timestamp",
            "risk": "input_risk_score",
            "status": "status",
        }.get(sort_by, "timestamp")
        sort_direction = 1 if sort_dir == "asc" else -1

        def query_collection(collection):
            cursor = (
                collection.find(query, self._audit_projection())
                .sort(sort_field, sort_direction)
                .skip(skip)
                .limit(limit)
            )
            items = list(cursor)
            return items, collection.count_documents(query)

        items, total = self._with_collection(query_collection)
        normalized = []
        for item in items:
            if isinstance(item.get("timestamp"), datetime):
                item["timestamp"] = item["timestamp"].isoformat()
            normalized.append(item)
        return {
            "items": normalized,
            "total": total,
            "has_next": skip + len(normalized) < total,
        }


mongo_store = MongoStore()
