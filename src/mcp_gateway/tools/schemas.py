"""Pydantic input models for tools. Strict: unknown fields are rejected."""

from pydantic import BaseModel, ConfigDict, Field

IDENT = r"^[A-Za-z_][A-Za-z0-9_]{0,62}$"


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ListTablesInput(_Input):
    pass


class DescribeTableInput(_Input):
    table: str = Field(pattern=IDENT)
    schema_name: str = Field(default="public", pattern=IDENT)


class RunQueryInput(_Input):
    sql: str = Field(min_length=1, max_length=10_000)
    limit: int | None = Field(default=None, ge=1, le=10_000)
