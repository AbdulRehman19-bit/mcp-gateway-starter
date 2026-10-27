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
    # stdio ONLY: the local user is trusted and gets this role. Over http the role comes
    # exclusively from the validated token. Never read from tool arguments.
    gateway_role: str = "analyst"
    # Public URL of this server (OAuth protected-resource metadata). Default: host:port.
    gateway_public_url: str | None = None
    # OAuth resource-server settings (http transport). Issuer/JWKS come from the external IdP.
    oauth_issuer: str | None = None
    oauth_audience: str = "mcp-gateway"
    oauth_jwks_url: str | None = None
    oauth_clock_skew_seconds: int = 30
    # Target DB, SELECT-only role. SecretStr so the DSN never shows up in repr or logs.
    target_db_ro_url: SecretStr | None = None
