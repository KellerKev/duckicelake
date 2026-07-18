"""Unit tests for the SMCP interface (no network, no live gov).

Skipped unless SMCP is importable (put the KellerKev/smcp checkout on
PYTHONPATH). Covers: the 4 governed tools register with the right schemas, the
caller's verified JWT `client_id` reaches a handler via the identity node +
contextvar, and the config is fail-closed against weak secrets.
"""
from __future__ import annotations

import secrets

import pytest

pytest.importorskip("smcp_server")   # SMCP not on PYTHONPATH -> skip this module

from smcp_config import SMCPConfig            # noqa: E402
from smcp_server import SMCPServer            # noqa: E402

from duckicelake.mcp_server import MCPConfig  # noqa: E402
from duckicelake import smcp_interface as si  # noqa: E402


def _cfg() -> SMCPConfig:
    """A valid 'Simple' (HS256) config with strong random secrets."""
    return SMCPConfig(
        node_id="duckicelake-test",
        api_key=secrets.token_urlsafe(24),
        secret_key=secrets.token_urlsafe(32),
        jwt_secret=secrets.token_urlsafe(32),
        kdf_salt=secrets.token_urlsafe(16),
    )


def test_registers_the_four_governed_tools():
    server, _ = si.build_server(smcp_cfg=_cfg(), mcp_cfg=MCPConfig())
    caps = server.node.capabilities
    assert set(caps) == {"list_namespaces", "list_tables", "describe_table", "query"}
    # the query tool declares its params + required list
    qp = caps["query"].parameters
    assert set(qp["required"]) == {"catalog", "namespace", "table", "sql"}
    assert qp["sql"]["type"] == "string"


def test_caller_identity_reaches_the_handler():
    # A probe tool records resolve_principal(); the identity node must publish
    # the verified JWT client_id into the contextvar before dispatch.
    server, _ = si.build_server(smcp_cfg=_cfg(), mcp_cfg=MCPConfig())
    node = server.node
    seen = {}
    server.register_tool("probe", "probe", {},
                         lambda: seen.update(principal=si.resolve_principal()) or "ok")
    token = node.security.generate_jwt("alice", ["tool_invoke"])
    ok, res = node.authorize_and_invoke("probe", {}, token)
    assert ok and res == "ok"
    assert seen["principal"] == "alice"
    # contextvar is reset after the call (no leak to the next request)
    assert si.resolve_principal() == "smcp-guest"


def test_unauthenticated_call_is_refused():
    server, _ = si.build_server(smcp_cfg=_cfg(), mcp_cfg=MCPConfig())
    node = server.node
    server.register_tool("probe", "probe", {}, lambda: "ok")
    ok, res = node.authorize_and_invoke("probe", {}, None)   # no token
    assert ok is False


def test_config_is_fail_closed_on_weak_secret():
    weak = SMCPConfig(node_id="x", api_key="k", secret_key="short",
                      jwt_secret="short", kdf_salt="short")
    with pytest.raises(ValueError):
        SMCPServer(weak)
