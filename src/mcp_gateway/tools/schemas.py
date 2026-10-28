"""Pydantic input models for tools. Strict: unknown fields are rejected."""

from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
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
            if isinstance(value, str):
                if len(value) > 10_000:
                    raise ValueError("value too long")
                _storable_text(value)
        return v


class DeleteRecordInput(_WriteInput):
    table: str = Field(pattern=IDENT)
    schema_name: str = Field(default="public", pattern=IDENT)
    pk: PrimaryKey
    dry_run: bool = False
    approval_id: ApprovalId | None = None


REPO = r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$"


def _no_dot_segments(value: str) -> str:
    # "." and ".." fit the character class but are path traversal, not repository names.
    if any(part in (".", "..") for part in value.split("/")) or ".." in value:
        raise ValueError("invalid repository name")
    return value


Repo = Annotated[str, StringConstraints(pattern=REPO), AfterValidator(_no_dot_segments)]


class GithubListIssuesInput(_Input):
    repo: Repo
    state: Literal["open", "closed", "all"] = "open"
    limit: StrictInt = Field(default=20, ge=1, le=50)


class GithubGetIssueInput(_Input):
    repo: Repo
    number: StrictInt = Field(ge=1, le=10**9)


def _storable_text(value: str) -> str:
    """NUL and lone surrogates cannot be stored (jsonb) or sent; refuse them up front."""
    if "\x00" in value or any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise ValueError("text contains NUL or surrogate characters")
    return value


def _comment_text(value: str) -> str:
    _storable_text(value)
    if not value.strip():
        raise ValueError("comment is blank")  # would burn an approval for nothing
    return value


class GithubAddCommentInput(_WriteInput):
    repo: Repo
    number: StrictInt = Field(ge=1, le=10**9)
    body: Annotated[StrictStr, AfterValidator(_comment_text)] = Field(
        min_length=1, max_length=4_000
    )
    dry_run: bool = False
    approval_id: ApprovalId | None = None


class ListApprovalsInput(_Input):
    # Oldest first, one page at a time, so no request can be pushed out of an approver's view.
    offset: int = Field(default=0, ge=0, le=1_000_000)


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
