"""Policy schema. Pure data + validation; no I/O besides reading the YAML file.

Design: default deny. Anything not listed in the policy is not allowed.
"""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

RiskTier = Literal["low", "medium", "high"]

# Tools for the approval workflow itself; they are gated by role, not by risk tier.
APPROVER_TOOLS = frozenset({"list_approvals", "decide_approval"})


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


class SchemaRule(_Strict):
    tables: dict[str, TableRule] = Field(default_factory=dict)


class RolePolicy(_Strict):
    read_only: bool = True
    tools: list[str] = Field(default_factory=list)
    approval_required: list[str] = Field(default_factory=list)
    schemas: dict[str, SchemaRule] = Field(default_factory=dict)


class RiskTiers(_Strict):
    low: list[str] = Field(default_factory=list)
    medium: list[str] = Field(default_factory=list)
    high: list[str] = Field(default_factory=list)

    def tier_of(self, tool: str) -> RiskTier | None:
        if tool in self.low:
            return "low"
        if tool in self.medium:
            return "medium"
        if tool in self.high:
            return "high"
        return None


class Approvals(_Strict):
    ttl_minutes: int = Field(default=30, ge=1, le=1_440)
    require_different_approver: bool = True


class Policy(_Strict):
    version: Literal[1]
    defaults: Defaults = Field(default_factory=Defaults)
    risk: RiskTiers = Field(default_factory=RiskTiers)
    approvals: Approvals = Field(default_factory=Approvals)
    scope_to_role: dict[str, str] = Field(default_factory=dict)
    roles: dict[str, RolePolicy] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_references(self) -> "Policy":
        for role_name, role in self.roles.items():
            # Approver tools are registered separately; every other tool needs a risk tier.
            unknown = [
                t for t in role.tools if t not in APPROVER_TOOLS and self.risk.tier_of(t) is None
            ]
            if unknown:
                raise ValueError(f"role '{role_name}' uses tools with no risk tier: {unknown}")
        for scope, role_name in self.scope_to_role.items():
            if role_name not in self.roles:
                raise ValueError(f"scope '{scope}' maps to unknown role '{role_name}'")
        return self


def load_policy(path: Path) -> Policy:
    """Load and validate a policy file. Raises on any problem (fail closed)."""
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return Policy.model_validate(raw)
