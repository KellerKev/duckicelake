"""Brokers act as the end user: every MCP/SMCP call to the governance core is
delegated with the caller's principal AND account, the MCP listener rejects
unauthenticated callers instead of running them as a default principal, and
SMCP clients reach an owned catalog only through an explicit account mapping."""
from __future__ import annotations

import asyncio

import pytest

from duckicelake import mcp_server as ms
from duckicelake.auth import AuthConfig, issue_token


class _Resp:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


@pytest.fixture()
def recorded(monkeypatch):
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((url, dict(params or {})))
        return _Resp({"namespaces": [["sales"]], "identifiers": [{"name": "t"}]})

    monkeypatch.setattr(ms.httpx, "get", fake_get)
    return calls


def _executor():
    cfg = ms.MCPConfig()
    cfg.broker = ""            # no token fetch in unit tests
    return ms.GovernedExecutor(cfg, settings=object())


def test_every_governance_call_is_delegated_with_the_account(recorded):
    ex = _executor()
    ex.list_namespaces("acme__main", "alice", "acct-1")
    ex.list_tables("acme__main", "sales", "alice", "acct-1")
    ex._vend("acme__main", "sales", "alice", "acct-1", table="t")
    assert len(recorded) == 3
    for _, params in recorded:
        assert params["delegate"] == "1" and params["principal"] == "alice"
        assert params["account"] == "acct-1" and params["actor"] == "agent"
    assert recorded[2][1]["table"] == "t"


def test_caller_params_cannot_override_the_delegation(recorded):
    ex = _executor()
    ex.gov_get("/v1/x/namespaces", "alice", "acct-1",
               {"account": "other", "principal": "root", "delegate": "0"})
    params = recorded[0][1]
    assert (params["account"], params["principal"], params["delegate"]) == ("acct-1", "alice", "1")


def test_no_account_means_no_account_param(recorded):
    _executor().list_namespaces("lake", "alice", None)
    assert "account" not in recorded[0][1]


def _run_middleware(monkeypatch, authz: str | None):
    cfg = AuthConfig(jwt_secret=b"test-secret-32-bytes-xxxxxxxxxxx", clients={"c": {"secret": "s", "scope": "*:r", "roles": "", "account": ""}},
                     ttl_seconds=300, issuer="duckicelake")
    monkeypatch.setattr(ms, "load_auth_config", lambda: cfg)
    seen, sent = {}, []

    async def app(scope, receive, send):
        seen["caller"] = ms._CURRENT_CALLER.get()

    async def send(msg):
        sent.append(msg)

    headers = [(b"authorization", authz.encode())] if authz else []
    asyncio.run(ms._AuthMiddleware(app)({"type": "http", "headers": headers}, None, send))
    return cfg, seen, sent


def test_mcp_rejects_missing_or_bad_bearer(monkeypatch):
    for authz in (None, "Bearer not-a-jwt"):
        _, seen, sent = _run_middleware(monkeypatch, authz)
        assert "caller" not in seen
        assert sent[0]["status"] == 401


def test_mcp_pins_sub_and_account(monkeypatch):
    cfg = AuthConfig(jwt_secret=b"test-secret-32-bytes-xxxxxxxxxxx", clients={"c": {"secret": "s", "scope": "*:r", "roles": "", "account": ""}},
                     ttl_seconds=300, issuer="duckicelake")
    tok = issue_token(cfg, "alice", scope="*:r", roles="", account="acct-1")["access_token"]
    _, seen, sent = _run_middleware(monkeypatch, f"Bearer {tok}")
    assert seen["caller"] == ("alice", "acct-1") and not sent


def test_smcp_account_mapping(monkeypatch):
    si = pytest.importorskip("duckicelake.smcp_interface")
    monkeypatch.setenv("DUCKICELAKE_SMCP_ACCOUNTS", " bot-a = acct-1 ,bad, bot-b=acct-2")
    tok = si._CURRENT_CLIENT.set("bot-a")
    try:
        assert si.resolve_caller() == ("bot-a", "acct-1")
    finally:
        si._CURRENT_CLIENT.reset(tok)
    tok = si._CURRENT_CLIENT.set("unmapped")
    try:
        assert si.resolve_caller() == ("unmapped", None)
    finally:
        si._CURRENT_CLIENT.reset(tok)
