"""Rate limiting through the handler pipeline and the auth verifier."""

import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from mcp_gateway.audit.sink import Auditor, MemorySink
from mcp_gateway.auth.roles import Identity
from mcp_gateway.auth.verifier import JwtTokenVerifier
from mcp_gateway.connectors.postgres import QueryResult
from mcp_gateway.policy import Policy, load_policy
from mcp_gateway.policy.evaluator import allowed_tables
from mcp_gateway.ratelimit import RateLimiter
from mcp_gateway.tools.handlers import ToolFailure, ToolService

EXAMPLE = load_policy(Path(__file__).parents[1] / "policies" / "policy.example.yaml")
CATALOG = {("public", "orders"): {"id": "integer"}, ("public", "customers"): {"id": "integer"}}
ALICE = Identity("alice", "analyst", frozenset())
BOB = Identity("bob", "analyst", frozenset())


class Clock:
    def __init__(self) -> None:
        self.t = 5000.0

    def __call__(self) -> float:
        return self.t


class Reader:
    calls = 0

    async def run_query(self, sql: str, *, limit: int | None = None) -> QueryResult:
        Reader.calls += 1
        return QueryResult(columns=[], rows=[], truncated=False)


def make(
    policy: Policy = EXAMPLE,
) -> tuple[ToolService, list[Identity | None], Clock, MemorySink]:
    who: list[Identity | None] = [ALICE]
    clock, sink = Clock(), MemorySink()
    allowed = {r: allowed_tables(policy, r, CATALOG) for r in policy.roles}
    svc = ToolService(
        Reader(),  # type: ignore[arg-type]
        policy,
        allowed,
        lambda: who[0],
        auditor=Auditor(sink),
        limiter=RateLimiter(clock=clock),
    )
    return svc, who, clock, sink


async def test_calls_beyond_the_policy_burst_are_denied_and_audited() -> None:
    svc, _, _, sink = make()
    burst = EXAMPLE.limits.tools["run_query"].burst
    for _ in range(burst):
        await svc.run_query("SELECT id FROM orders")
    Reader.calls = 0
    with pytest.raises(ToolFailure, match=r"Rate limit exceeded\. Retry in \d+ s"):
        await svc.run_query("SELECT id FROM orders")
    assert Reader.calls == 0  # cut off before any database work
    last = sink.records[-1]
    assert last["decision"] == "deny"
    assert last["reason"].startswith("rate_limited retry_after=")
    assert (last["subject"], last["role"], last["tool"]) == ("alice", "analyst", "run_query")


async def test_limit_recovers_over_time() -> None:
    svc, _, clock, _ = make()
    rl = EXAMPLE.limits.tools["run_query"]
    for _ in range(rl.burst):
        await svc.run_query("SELECT id FROM orders")
    with pytest.raises(ToolFailure):
        await svc.run_query("SELECT id FROM orders")
    clock.t += 60.0 / rl.per_minute  # one token's worth of time
    await svc.run_query("SELECT id FROM orders")


async def test_users_and_tools_have_separate_buckets() -> None:
    svc, who, _, _ = make()
    for _ in range(EXAMPLE.limits.tools["run_query"].burst):
        await svc.run_query("SELECT id FROM orders")
    with pytest.raises(ToolFailure):
        await svc.run_query("SELECT id FROM orders")
    await svc.list_tables()  # different tool, own bucket
    who[0] = BOB
    await svc.run_query("SELECT id FROM orders")  # different user, own bucket


async def test_limits_apply_to_every_tool_including_denied_ones() -> None:
    svc, _, _, sink = make()
    for _ in range(EXAMPLE.limits.tools["update_record"].burst):
        with pytest.raises(ToolFailure, match="Not permitted"):
            await svc.update_record("orders", 1, {"status": "x"})  # analyst lacks the tool
    with pytest.raises(ToolFailure, match="Rate limit"):
        await svc.update_record("orders", 1, {"status": "x"})
    assert sink.records[-1]["reason"].startswith("rate_limited")


async def test_dry_run_counts_against_the_same_limit() -> None:
    raw = EXAMPLE.model_dump()
    raw["limits"]["tools"]["delete_record"] = {"per_minute": 1, "burst": 2}
    svc, who, _, _ = make(Policy.model_validate(raw))
    who[0] = Identity("bob", "operator", frozenset())
    outcomes: list[str] = []
    for _ in range(3):
        try:
            await svc.delete_record("orders", 1, dry_run=True)
        except ToolFailure as exc:  # writes are not configured here, but the token is spent
            outcomes.append(str(exc))
    assert len(outcomes) == 3
    assert "Rate limit" not in outcomes[0]
    assert "Rate limit" in outcomes[2]


async def test_unauthenticated_calls_do_not_consume_anyones_bucket() -> None:
    svc, who, _, _ = make()
    who[0] = None
    for _ in range(50):
        with pytest.raises(ToolFailure, match="Not permitted"):
            await svc.list_tables()
    who[0] = ALICE
    await svc.list_tables()


def test_policy_limits_are_validated() -> None:
    for bad in (
        {"default": {"per_minute": 0, "burst": 1}},
        {"default": {"per_minute": 10, "burst": 0}},
        {"tools": {"made_up_tool": {"per_minute": 1, "burst": 1}}},
        {"tools": {"run_query": {"per_minute": 1, "burst": 1, "extra": 1}}},
    ):
        raw = EXAMPLE.model_dump()
        raw["limits"] = {**raw["limits"], **bad}
        with pytest.raises(ValidationError):
            Policy.model_validate(raw)


def test_policy_without_limits_gets_safe_defaults() -> None:
    raw = EXAMPLE.model_dump()
    del raw["limits"]
    assert Policy.model_validate(raw).limits.default.burst == 30


# ---- failed-authentication audit flood ---------------------------------------------------------

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class NoKeys:
    async def get_key(self, kid: str) -> Any | None:
        return None


class GoodKeys:
    async def get_key(self, kid: str) -> Any:
        return KEY.public_key()


def _garbage() -> str:
    return jwt.encode({"sub": "x"}, KEY, "RS256", headers={"kid": "k"})


def _verifier(keys: Any, sink: MemorySink, limiter: RateLimiter) -> JwtTokenVerifier:
    return JwtTokenVerifier(
        EXAMPLE,
        keys,
        issuer="i",
        audience="a",
        auditor=Auditor(sink),
        deny_limiter=limiter,
    )


async def test_failed_auth_audit_flood_is_bounded_and_summarised() -> None:
    clock, sink = Clock(), MemorySink()
    v = _verifier(NoKeys(), sink, RateLimiter(clock=clock))
    for _ in range(1_000):
        assert await v.verify_token(_garbage()) is None  # always denied
    assert 100 <= len(sink.records) <= 101  # the burst budget, not 1000 rows
    clock.t += 30
    assert await v.verify_token(_garbage()) is None
    assert "similar denials not stored" in sink.records[-1]["reason"]


async def test_a_real_login_is_still_audited_during_a_denial_flood() -> None:
    now = int(time.time())
    token = jwt.encode(
        {"iss": "i", "aud": "a", "sub": "alice", "iat": now, "exp": now + 300, "scope": "db:read"},
        KEY,
        "RS256",
        headers={"kid": "k"},
    )
    clock, sink = Clock(), MemorySink()
    shared = RateLimiter(clock=clock)
    attacker = _verifier(NoKeys(), sink, shared)
    user = _verifier(GoodKeys(), sink, shared)
    for _ in range(500):
        await attacker.verify_token(_garbage())
    assert await user.verify_token(token) is not None
    assert sink.records[-1]["decision"] == "allow"  # successes are never throttled


# ---- review fixes: audit budgets never hide the log trail ----------------------------------------


async def test_every_denial_is_still_logged_as_json_during_a_flood() -> None:
    import structlog

    clock, sink = Clock(), MemorySink()
    v = _verifier(NoKeys(), sink, RateLimiter(clock=clock))
    with structlog.testing.capture_logs() as logs:
        for _ in range(500):
            await v.verify_token(_garbage())
    assert len(logs) == 500  # nothing is lost from the JSON log
    assert len(sink.records) < 110  # only the database rows are budgeted


async def test_denials_of_validly_signed_tokens_are_always_stored() -> None:
    now = int(time.time())

    def signed(**over: Any) -> str:
        claims = {"iss": "i", "aud": "a", "sub": "alice", "iat": now, "exp": now + 300,
                  "scope": "db:read", **over}  # fmt: skip
        return jwt.encode(claims, KEY, "RS256", headers={"kid": "k"})

    clock, sink = Clock(), MemorySink()
    shared = RateLimiter(clock=clock)
    attacker = _verifier(NoKeys(), sink, shared)
    user = _verifier(GoodKeys(), sink, shared)
    for _ in range(500):  # exhaust the unsigned-denial budget
        await attacker.verify_token(_garbage())
    before = len(sink.records)
    bad = [
        signed(aud="someone-else"),
        signed(scope="admin"),
        signed(scope="db:read db:write"),
        signed(exp=now - 3600),
        signed(iss="http://evil"),
    ]
    for token in bad:
        assert await user.verify_token(token) is None
    stored = sink.records[before:]
    assert len(stored) == len(bad)  # a targeted attack with real credentials leaves a trace
    assert {r["decision"] for r in stored} == {"deny"}
    assert all(r["subject"] == "alice" for r in stored)


async def test_repeat_logins_are_budgeted_per_subject_but_still_logged() -> None:
    import structlog

    now = int(time.time())
    token = jwt.encode(
        {"iss": "i", "aud": "a", "sub": "alice", "iat": now, "exp": now + 300, "scope": "db:read"},
        KEY, "RS256", headers={"kid": "k"},
    )  # fmt: skip
    sink = MemorySink()
    v = _verifier(GoodKeys(), sink, RateLimiter())
    with structlog.testing.capture_logs() as logs:
        for _ in range(200):
            assert await v.verify_token(token) is not None
    assert len(logs) == 200
    assert 5 <= len(sink.records) <= 8  # a few rows, not one per HTTP request


async def test_rate_limit_denials_are_logged_always_but_stored_within_a_budget() -> None:
    import structlog

    svc, _, _, sink = make()
    burst = EXAMPLE.limits.tools["run_query"].burst
    for _ in range(burst):
        await svc.run_query("SELECT id FROM orders")
    allowed_rows = len(sink.records)
    with structlog.testing.capture_logs() as logs:
        for _ in range(300):
            with pytest.raises(ToolFailure, match="Rate limit"):
                await svc.run_query("SELECT id FROM orders")
    assert len(logs) == 300  # every denial is in the JSON log
    stored = len(sink.records) - allowed_rows
    assert 1 <= stored <= 4  # but a hammering user cannot flood the table
    assert all(r["reason"].startswith("rate_limited") for r in sink.records[allowed_rows:])


def test_token_errors_know_whether_the_signature_was_verified() -> None:
    from mcp_gateway.auth.validator import TokenError, peek_header, validate_token

    now = int(time.time())
    good = jwt.encode(
        {"iss": "i", "aud": "OTHER", "sub": "a", "iat": now, "exp": now + 60},
        KEY, "RS256", headers={"kid": "k"},
    )  # fmt: skip
    with pytest.raises(TokenError) as wrong_aud:
        validate_token(good, KEY.public_key(), alg="RS256", issuer="i", audience="a")
    assert wrong_aud.value.signed is True
    forged = jwt.encode(
        {"iss": "i", "aud": "a", "sub": "a", "iat": now, "exp": now + 60},
        rsa.generate_private_key(public_exponent=65537, key_size=2048), "RS256",
        headers={"kid": "k"},
    )  # fmt: skip
    with pytest.raises(TokenError) as bad_sig:
        validate_token(forged, KEY.public_key(), alg="RS256", issuer="i", audience="a")
    assert bad_sig.value.signed is False
    with pytest.raises(TokenError) as junk:
        peek_header("garbage")
    assert junk.value.signed is False
