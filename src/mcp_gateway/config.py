"""Runtime settings, loaded from environment variables (see .env.example)."""

from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    gateway_transport: str = "stdio"
    gateway_host: str = "127.0.0.1"
    gateway_port: int = 8000
    gateway_policy_path: Path = Path("policies/policy.example.yaml")
    # Global kill switch: when true, every role is forced read-only. Default is safe.
    gateway_read_only: bool = True
    gateway_log_level: str = "INFO"
    # Role used for every call until Phase 3 derives it from the validated token. Server-side
    # config only: it is never read from tool arguments.
    gateway_role: str = "analyst"
    # Target DB, SELECT-only role. SecretStr so the DSN never shows up in repr or logs.
    target_db_ro_url: SecretStr | None = None
