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
    # Comma-separated hostnames allowed to serve the JWKS over plain http (private networks
    # only, e.g. "keycloak" in docker compose). Empty = https or loopback only.
    oauth_jwks_http_allowed_hosts: str = ""

    def jwks_http_hosts(self) -> frozenset[str]:
        return frozenset(
            h.strip().lower() for h in self.oauth_jwks_http_allowed_hosts.split(",") if h.strip()
        )

    # Target DB, SELECT-only role. SecretStr so the DSN never shows up in repr or logs.
    target_db_ro_url: SecretStr | None = None
    # Limited read-write role. Only used when writes are enabled (GATEWAY_READ_ONLY=false).
    target_db_rw_url: SecretStr | None = None
    # Server-side GitHub token (fine-grained PAT limited to the policy's repos; Issues
    # read, plus write only if github_add_comment is enabled). Unset = unauthenticated reads.
    github_token: SecretStr | None = None
    # Gateway's own DB: approvals (gateway_app) and the INSERT-only audit writer (gateway_audit).
    gateway_db_url: SecretStr | None = None
    gateway_audit_db_url: SecretStr | None = None
