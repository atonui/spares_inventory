"""Application settings loaded from environment or .env."""
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    SMTP_SERVER: str
    SMTP_PORT: int
    SMTP_USERNAME: str
    SMTP_PASSWORD: str
    FRONTEND_URL: str
    CSRF_SECRET: str
    COOKIE_SECURE: bool = True
    CORS_ALLOWED_ORIGINS: List[str] = ["https://sparesinventory-production.up.railway.app"]

    @field_validator("CORS_ALLOWED_ORIGINS")
    @classmethod
    def reject_wildcard_origins(cls, origins):
        if any("*" in origin for origin in origins):
            raise ValueError("Credentialed CORS requires exact origins; wildcards are not allowed")
        return origins

    model_config = SettingsConfigDict(env_file=".env")
