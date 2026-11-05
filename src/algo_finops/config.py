from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="IAC_",
        env_file=".env",
        extra="ignore",
    )

    github_webhook_secret: str = ""
    github_token: str = ""
    github_app_id: str = ""
    github_app_private_key: str = ""
    token_encryption_key: str = ""
    database_url: str = "sqlite+aiosqlite:///./iac.db"
    workspace_root: Path = Path("./.workspaces")
    sandbox_provider: Literal["auto", "local", "docker"] = "local"
    sandbox_image: str = "alpine:3.20"
    clone_depth: int = 1
    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "INFO"
    max_index_files: int = Field(default=20_000, ge=100)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
