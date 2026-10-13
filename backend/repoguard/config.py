"""Validated configuration; importing this module performs no external I/O."""

from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="REPOGUARD_", extra="ignore")

    environment: Literal["local", "test", "production"] = "local"
    database_url: str = "sqlite:///./repoguard.db"
    redis_url: str = "redis://localhost:6379/0"
    fixture_mode: bool = True
    webhook_secret: SecretStr | None = None
    github_app_id: int | None = Field(default=None, gt=0)
    github_private_key: SecretStr | None = None
    llm_enabled: bool = False
    llm_endpoint: str | None = None
    llm_api_key: SecretStr | None = None
    validator_url: str | None = None
    validator_secret: SecretStr | None = None
    validator_image: str | None = None
    max_archive_bytes: int = Field(default=10_000_000, ge=1024, le=100_000_000)
    max_expanded_bytes: int = Field(default=40_000_000, ge=1024, le=500_000_000)
    max_file_bytes: int = Field(default=1_000_000, ge=1024, le=5_000_000)
    max_files: int = Field(default=2000, ge=1, le=10_000)
    job_timeout_seconds: int = Field(default=120, ge=10, le=600)

    @model_validator(mode="after")
    def production_boundary(self) -> "Settings":
        if self.environment == "production":
            if self.fixture_mode or not self.database_url.startswith("postgresql+psycopg://"):
                raise ValueError("production requires PostgreSQL and fixture_mode=false")
            if self.webhook_secret is None or len(self.webhook_secret.get_secret_value()) < 32:
                raise ValueError("production requires a strong webhook secret")
        return self
