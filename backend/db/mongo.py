from pymongo import MongoClient
from pymongo.errors import PyMongoError

from backend.core.config import get_settings


class MongoStore:
    """Small MongoDB connection wrapper. Does not connect until requested."""

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


mongo_store = MongoStore()
