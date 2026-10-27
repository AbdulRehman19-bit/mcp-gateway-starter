"""Policy schema. Pure data + validation; no I/O besides reading the YAML file.

Design: default deny. Anything not listed in the policy is not allowed.
"""

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

RiskTier = Literal["low", "medium", "high"]

# Tools for the approval workflow itself; they are gated by role, not by risk tier.
APPROVER_TOOLS = frozenset({"list_approvals", "decide_approval"})

# Never lowered by policy: deleting or bulk-changing data, or sending data out of the gateway
# (a GitHub comment can leak into a public repo), always needs a human.
DESTRUCTIVE_TOOLS = frozenset({"delete_record", "bulk_update", "github_add_comment"})
GITHUB_TOOLS = frozenset({"github_list_issues", "github_get_issue", "github_add_comment"})
REPO_PATTERN = r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$"


class _Strict(BaseModel):
    # Unknown keys are errors: a typo in a policy file must not silently widen access.
    model_config = ConfigDict(extra="forbid")


class Defaults(_Strict):
    read_only: bool = True
    max_rows: int = Field(default=500, ge=1, le=10_000)
    statement_timeout_ms: int = Field(default=5_000, ge=100, le=60_000)


class TableRule(_Strict):
    columns: list[str] = Field(default_factory=lambda: ["*"])
    deny_columns: list[str] = Field(default_factory=list)
    mask_columns: list[str] = Field(default_factory=list)
    writable_columns: list[str] = Field(default_factory=list)
    # delete_record may only target tables that opt in; default is no.
    deletable: bool = False


class SchemaRule(_Strict):
    tables: dict[str, TableRule] = Field(default_factory=dict)


class RolePolicy(_Strict):
    read_only: bool = True
    tools: list[str] = Field(default_factory=list)
    approval_required: list[str] = Field(default_factory=list)
    # Approver scoping: requests from these roles may be listed and decided by this role.
    # Empty means "none": a role with decide_approval but no approves_roles is a policy error.
    approves_roles: list[str] = Field(default_factory=list)
    schemas: dict[str, SchemaRule] = Field(default_factory=dict)


class RiskTiers(_Strict):
    low: list[str] = Field(default_factory=list)
    medium: list[str] = Field(default_factory=list)
    high: list[str] = Field(default_factory=list)

    def tier_of(self, tool: str) -> RiskTier | None:
        # Highest tier wins, so even an unvalidated overlap can never lower a tool's risk.
        if tool in self.high:
            return "high"
        if tool in self.medium:
            return "medium"
        if tool in self.low:
            return "low"
        return None


class Approvals(_Strict):
    ttl_minutes: int = Field(default=30, ge=1, le=1_440)
    # Rule 7 is not configurable: the requester can never approve their own request.
    require_different_approver: Literal[True] = True


class GithubPolicy(_Strict):
    # Exact owner/name pairs the gateway may touch. Anything else is denied before any request.
    repos: list[str] = Field(min_length=1, max_length=200)
    max_text_chars: int = Field(default=4_000, ge=100, le=20_000)

    @model_validator(mode="after")
    def _check_repos(self) -> "GithubPolicy":
        for repo in self.repos:
            if not re.fullmatch(REPO_PATTERN, repo) or ".." in repo:
                raise ValueError(f"invalid repository name: {repo!r}")
        return self


class Connectors(_Strict):
    github: GithubPolicy | None = None


class RateLimit(_Strict):
    per_minute: int = Field(ge=1, le=100_000)
    burst: int = Field(ge=1, le=10_000)


class Limits(_Strict):
    """Per-user, per-tool call limits (token buckets). Anything not listed uses `default`."""

    default: RateLimit = Field(default_factory=lambda: RateLimit(per_minute=120, burst=30))
    tools: dict[str, RateLimit] = Field(default_factory=dict)


class Policy(_Strict):
    version: Literal[1]
    defaults: Defaults = Field(default_factory=Defaults)
    risk: RiskTiers = Field(default_factory=RiskTiers)
    approvals: Approvals = Field(default_factory=Approvals)
    limits: Limits = Field(default_factory=Limits)
    connectors: Connectors = Field(default_factory=Connectors)
    scope_to_role: dict[str, str] = Field(default_factory=dict)
    roles: dict[str, RolePolicy] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_references(self) -> "Policy":
        tiers = (self.risk.low, self.risk.medium, self.risk.high)
        listed = [t for tier in tiers for t in tier]
        dupes = sorted({t for t in listed if listed.count(t) > 1})
        if dupes:
            raise ValueError(f"tools listed in more than one risk tier: {dupes}")
        weak = sorted(t for t in DESTRUCTIVE_TOOLS if t in listed and t not in self.risk.high)
        if weak:
            raise ValueError(f"destructive tools must be in the high tier: {weak}")
        uses_github = any(t in GITHUB_TOOLS for r in self.roles.values() for t in r.tools)
        if uses_github and self.connectors.github is None:
            raise ValueError("roles use github_* tools but connectors.github is not configured")
        known = set(listed) | APPROVER_TOOLS | {"ping"}
        stray_limits = sorted(t for t in self.limits.tools if t not in known)
        if stray_limits:
            raise ValueError(f"limits name tools that do not exist: {stray_limits}")
        for role_name, role in self.roles.items():
            # Approver tools are registered separately; every other tool needs a risk tier.
            unknown = [
                t for t in role.tools if t not in APPROVER_TOOLS and self.risk.tier_of(t) is None
            ]
            if unknown:
                raise ValueError(f"role '{role_name}' uses tools with no risk tier: {unknown}")
            unknown_roles = [r for r in role.approves_roles if r not in self.roles]
            if unknown_roles:
                raise ValueError(f"role '{role_name}' approves unknown roles: {unknown_roles}")
            if "decide_approval" in role.tools and not role.approves_roles:
                raise ValueError(
                    f"role '{role_name}' can decide approvals but approves_roles is empty"
                )
            stray = [t for t in role.approval_required if t not in role.tools]
            if stray:
                raise ValueError(
                    f"role '{role_name}' approval_required lists unknown tools: {stray}"
                )
        for scope, role_name in self.scope_to_role.items():
            if role_name not in self.roles:
                raise ValueError(f"scope '{scope}' maps to unknown role '{role_name}'")
        return self


def load_policy(path: Path) -> Policy:
    """Load and validate a policy file. Raises on any problem (fail closed)."""
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return Policy.model_validate(raw)
