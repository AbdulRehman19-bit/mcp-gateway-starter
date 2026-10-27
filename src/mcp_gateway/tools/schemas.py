"""Pydantic input models for tools. Strict: unknown fields are rejected."""

from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    StringConstraints,
    field_validator,
)

IDENT = r"^[A-Za-z_][A-Za-z0-9_]{0,62}$"
UUID_RE = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ListTablesInput(_Input):
    pass


# Strict scalars only: bool is rejected as an int, and no nested structures reach the DB.
Scalar = StrictStr | StrictInt | StrictFloat | StrictBool | None
PrimaryKey = StrictInt | Annotated[StrictStr, StringConstraints(min_length=1, max_length=200)]
ColumnName = Annotated[str, StringConstraints(pattern=IDENT)]
ApprovalId = Annotated[str, StringConstraints(pattern=UUID_RE)]


class _WriteInput(BaseModel):
    # No whitespace stripping: written values must reach the database exactly as sent.
    model_config = ConfigDict(extra="forbid")


class UpdateRecordInput(_WriteInput):
    table: str = Field(pattern=IDENT)
    schema_name: str = Field(default="public", pattern=IDENT)
    pk: PrimaryKey
    changes: dict[ColumnName, Scalar] = Field(min_length=1, max_length=10)
    dry_run: bool = False
    approval_id: ApprovalId | None = None

    @field_validator("changes")
    @classmethod
    def _bounded_values(cls, v: dict[str, Any]) -> dict[str, Any]:
        for value in v.values():
            if isinstance(value, str) and len(value) > 10_000:
                raise ValueError("value too long")
        return v


class DeleteRecordInput(_WriteInput):
    table: str = Field(pattern=IDENT)
    schema_name: str = Field(default="public", pattern=IDENT)
    pk: PrimaryKey
    dry_run: bool = False
    approval_id: ApprovalId | None = None


class ListApprovalsInput(_Input):
    pass


class DecideApprovalInput(_Input):
    approval_id: ApprovalId
    decision: Literal["approve", "deny"]
    reason: str | None = Field(default=None, max_length=500)


class DescribeTableInput(_Input):
    table: str = Field(pattern=IDENT)
    schema_name: str = Field(default="public", pattern=IDENT)


class RunQueryInput(_Input):
    sql: str = Field(min_length=1, max_length=10_000)
    limit: int | None = Field(default=None, ge=1, le=10_000)
