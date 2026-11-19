
from typing import Any

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from backend.core.config import get_settings


class MongoStore:
    """MongoDB connection wrapper and audit persistence."""

    def __init__(self) -> None:
        self._client: MongoClient | None = None

    def ping(self) -> bool:
        settings = get_settings()

        if not settings.mongodb_uri:
            return False

        client = MongoClient(
            settings.mongodb_uri,
            serverSelectionTimeoutMS=3000,
            connectTimeoutMS=3000,
            appname="NexaShield",
        )

        try:
            client.admin.command("ping")
            return True
        except PyMongoError:
            return False
        finally:
            client.close()

    def insert_audit_event(self, event: dict[str, Any]) -> None:
        """Insert one privacy-safe event into the audit collection."""

        settings = get_settings()

        if not settings.mongodb_uri:
            raise RuntimeError("MongoDB is not configured.")

        client = MongoClient(
            settings.mongodb_uri,
            serverSelectionTimeoutMS=3000,
            connectTimeoutMS=3000,
            appname="NexaShield",
        )

        try:
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

        finally:
            client.close()


mongo_store = MongoStore()
