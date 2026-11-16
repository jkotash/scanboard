"""Settings. Everything is configured through environment variables."""

from functools import lru_cache

from fastapi import Request
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:////data/scanboard.db"
    admin_token: str  # required: the app refuses to start without it
    log_level: str = "INFO"
    base_url: str = "http://localhost:8000"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # values come from the environment


def settings_dep(request: Request) -> Settings:
    """FastAPI dependency: the settings the running app was created with."""
    return request.app.state.settings
