from typing import Any

import pytest
from pydantic import ValidationError

from mcp_gateway.tools.schemas import DescribeTableInput, RunQueryInput


@pytest.mark.parametrize(
    "table", ["", "a b", "orders;drop", 'a"b', "1abc", "x" * 64, "ord-ers", "a.b"]
)
def test_describe_rejects_bad_identifiers(table: str) -> None:
    with pytest.raises(ValidationError):
        DescribeTableInput(table=table)


def test_describe_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        DescribeTableInput.model_validate({"table": "orders", "role": "admin"})


@pytest.mark.parametrize(
    "kw",
    [
        {"sql": ""},
        {"sql": "x" * 10_001},
        {"sql": "SELECT 1", "limit": 0},
        {"sql": "SELECT 1", "limit": 10**9},
        {"sql": 5},
    ],
)
def test_run_query_rejects_bad_input(kw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        RunQueryInput.model_validate(kw)


def test_run_query_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        RunQueryInput.model_validate({"sql": "SELECT 1", "user": "root"})
