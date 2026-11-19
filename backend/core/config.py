
from functools import lru_cache

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "NexaShield"
    app_env: str = "development"
    log_level: str = "INFO"

    mongodb_uri: str = ""
    mongodb_database: str = "nexashield"

    # Fail closed when audit persistence fails if enabled.
    # Accept the documented variable while retaining the normal environment
    # source precedence over values loaded from .env.
    audit_required: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "NEXASHIELD_AUDIT_REQUIRED",
            "audit_required",
        ),
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
