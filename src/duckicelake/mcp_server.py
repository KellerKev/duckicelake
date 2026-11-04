"""MCP interface for duckicelake — a governed, agent-facing query surface.

Connecting over MCP *is* the "an AI agent is accessing" signal: every call this
server makes to the governance core is stamped `actor=agent, channel=mcp`, so
the actor-aware policies (see docs/actor_aware_governance.md) apply — extra
masking and read-only — without the caller having to assert anything.

Crucially, the tools **execute queries server-side and return rows only**: the
agent never receives the DuckLake DSN or S3 credentials, so it cannot reach a
base table behind a masked view. That closes the cooperative-masking gap of the
raw ducklake-credentials path.

This server is a trusted delegation *broker*: it authenticates to the
governance core with a broker-scoped service token and asserts the acting
principal on the caller's behalf. It runs as its own listener; wiring it into a
deployment (port, process supervisor, per-user principal resolution) is a
deployment concern — see `main()` and `resolve_principal`.

Config (env):
  DUCKICELAKE_URL             governance base url (default http://127.0.0.1:8181)
  DUCKICELAKE_MCP_BROKER      "client_id:secret" — a broker-scoped OAuth client
                              (scope `broker *:r`; it needs no admin scope)
  DUCKICELAKE_MCP_PRINCIPAL   acting principal when auth is off (dev)
  DUCKICELAKE_MCP_HOST/PORT   listener bind (default 127.0.0.1:8790)
"""
from __future__ import annotations

import contextvars
import os
import threading
import time
from typing import Any
from urllib.parse import quote

import duckdb
import httpx

from .auth import load_auth_config, verify_bearer
from .config import Settings, load_settings
from .governed import setup_governed
from .sqlsafe import check_no_denied_functions, check_single_select, qi

# The end user of the in-flight MCP request — (principal, account) from the
# caller's verified bearer, set by the auth middleware. Every governance call
# delegates as this user (the server holds a *broker* token separately); the
# account is what the governance core checks the catalog's owner against.
_CURRENT_CALLER: contextvars.ContextVar[tuple[str, str | None] | None] = \
    contextvars.ContextVar("mcp_caller", default=None)

# Exactly one statement, and only a query: the vended attach is READ_ONLY and
# the reader role is RLS-scoped, but a second statement (ATTACH, SET, COPY …)
# must never reach the connection. DESCRIBE/SHOW/VALUES parse as SELECT.
_QUERY_TYPES = (duckdb.StatementType.SELECT,)
_MAX_ROWS = 500


def _seg(value: str) -> str:
    """One URL path segment: a catalog/namespace/table name can't add
    segments, a query string or dot-segments to the gov request path."""
    return quote(value, safe="")


class MCPConfig:
    def __init__(self) -> None:
        self.gov_url = os.environ.get("DUCKICELAKE_URL", "http://127.0.0.1:8181").rstrip("/")
        self.broker = os.environ.get("DUCKICELAKE_MCP_BROKER", "")
        self.default_principal = os.environ.get("DUCKICELAKE_MCP_PRINCIPAL", "agent")
        self.host = os.environ.get("DUCKICELAKE_MCP_HOST", "127.0.0.1")
        self.port = int(os.environ.get("DUCKICELAKE_MCP_PORT", "8790"))


class GovernedExecutor:
    """Vends governed credentials (actor=agent) and runs read-only SQL
    server-side, returning rows only. One instance is shared across tools.

    `channel` is the session-context channel tag stamped on the vend
    (`channel:<v>`); defaults to `mcp`. The SMCP interface constructs it with
    `channel="smcp"`. Either way it's an agent session (extra masking + airtight
    file-layer + read-only)."""

    def __init__(self, config: MCPConfig, settings: Settings | None = None,
                 channel: str = "mcp") -> None:
        self.cfg = config
        self.settings = settings or load_settings()
        self.channel = channel
        self._tok: str | None = None
        self._tok_exp = 0.0
        self._lock = threading.Lock()

    # ---- governance-core client (as a broker) ------------------------------
    def _broker_token(self) -> str | None:
        if not self.cfg.broker or ":" not in self.cfg.broker:
            return None
        with self._lock:
            if self._tok and time.time() < self._tok_exp - 60:
                return self._tok
            cid, _, sec = self.cfg.broker.partition(":")
            r = httpx.post(f"{self.cfg.gov_url}/v1/oauth/tokens", data={
                "grant_type": "client_credentials",
                "client_id": cid, "client_secret": sec}, timeout=15.0)
            r.raise_for_status()
            body = r.json()
            self._tok = body["access_token"]
            self._tok_exp = time.time() + int(body.get("expires_in", 3600))
            return self._tok

    def _headers(self) -> dict:
        tok = self._broker_token()
        return {"Authorization": f"Bearer {tok}"} if tok else {}

    def gov_get(self, path: str, principal: str, account: str | None,
                params: dict | None = None) -> Any:
        """GET on the governance core AS the end user: every call is delegated
        (principal + account + agent session), so the core gates the catalog
        on the user's account — never on the broker's own identity."""
        delegation = {"delegate": "1", "principal": principal,
                      "actor": "agent", "channel": self.channel}
        if account:
            delegation["account"] = account
        r = httpx.get(f"{self.cfg.gov_url}{path}", params={**(params or {}), **delegation},
                      headers=self._headers(), timeout=30.0)
        r.raise_for_status()
        return r.json()

    def _vend(self, catalog_id: str, namespace: str, principal: str,
              account: str | None, table: str | None) -> dict:
        """Fetch a governed DuckLake-direct credential bundle for an AGENT."""
        return self.gov_get(
            f"/v1/{_seg(catalog_id)}/namespaces/{_seg(namespace)}/ducklake-credentials",
            principal, account, {"table": table} if table else None)

    def list_namespaces(self, catalog_id: str, principal: str,
                        account: str | None = None) -> list[str]:
        out = self.gov_get(f"/v1/{_seg(catalog_id)}/namespaces", principal, account)
        return [".".join(n) for n in out.get("namespaces", [])]

    def list_tables(self, catalog_id: str, namespace: str, principal: str,
                    account: str | None = None) -> list[str]:
        out = self.gov_get(f"/v1/{_seg(catalog_id)}/namespaces/{_seg(namespace)}/tables",
                           principal, account)
        return [i["name"] for i in out.get("identifiers", [])]

    def describe_table(self, catalog_id: str, namespace: str, table: str,
                       principal: str, account: str | None = None) -> dict:
        return self.query(catalog_id, namespace, table,
                          f"DESCRIBE {qi(namespace)}.{qi(table)}", principal, account)

    def _conn_for(self, bundle: dict, catalog_id: str,
                  namespace: str) -> duckdb.DuckDBPyConnection:
        """A DuckDB connection ATTACHed to the vended (RLS reader, READ_ONLY)
        DuckLake catalog, reading S3 only with the vended (scoped) credentials
        — never the proxy's own. When the vend carries a masking route
        (`post_attach_sql`), unqualified names resolve to the masked view;
        otherwise we default the search path to the namespace so plain
        `FROM <table>` resolves. Row-level RLS is always enforced by the reader
        role regardless.

        After setup the connection is locked down: file/network access only
        under the catalog's data path, no further configuration changes — so
        agent SQL can't read local files (the process env, config, keys) or
        other objects in the bucket."""
        con = duckdb.connect(":memory:")
        try:
            setup_governed(con, self.settings, bundle, catalog_id, namespace)
        except BaseException:
            con.close()
            raise
        return con

    def query(self, catalog_id: str, namespace: str, table: str | None,
              sql: str, principal: str, account: str | None = None) -> dict:
        try:
            check_single_select(sql or "", "query", allow=_QUERY_TYPES)
            check_no_denied_functions(sql, "query")
        except ValueError as e:
            return {"error": f"{e} (read-only SELECT/DESCRIBE/SHOW only)"}
        if not table:
            # A namespace-wide agent vend isn't table-routed, so it can't carry
            # the per-table masked view; require the primary table.
            return {"error": "`table` (the query's primary table) is required"}
        # Vend per-table so column masking (the masked view) is routed; without
        # a table the vend applies row-RLS only. `table` is the query's primary
        # table; multi-table joins fall back to base columns (row-RLS still
        # applies) — prefer one governed table per call for airtight masking.
        try:
            bundle = self._vend(catalog_id, namespace, principal, account, table=table)
        except httpx.HTTPStatusError as e:
            return {"error": f"governance refused the request ({e.response.status_code})"}
        try:
            con = self._conn_for(bundle, catalog_id, namespace)
        except PermissionError as e:
            return {"error": str(e)}
        try:
            cur = con.execute(sql)
            cols = [d[0] for d in (cur.description or [])]
            rows = cur.fetchmany(_MAX_ROWS)
            more = cur.fetchone() is not None
            return {"columns": cols,
                    "rows": [[_json_safe(v) for v in r] for r in rows],
                    "row_count": len(rows), "truncated": more,
                    "governed": True, "actor": "agent"}
        finally:
            con.close()


def _json_safe(v: Any) -> Any:
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    return str(v)


def resolve_caller(config: MCPConfig) -> tuple[str, str | None]:
    """(principal, account) of the in-flight call: the `sub` and `account`
    claims of the caller's verified bearer (set by the auth middleware), else
    the configured default principal with no account (auth-off dev only —
    with auth on, the middleware rejects unauthenticated requests)."""
    return _CURRENT_CALLER.get() or (config.default_principal, None)


def resolve_principal(config: MCPConfig) -> str:
    return resolve_caller(config)[0]


class _AuthMiddleware:
    """ASGI middleware: with auth on, verify the caller's bearer against the
    governance auth config and pin its (sub, account) as the request's end
    user; a missing or invalid bearer is a 401 (never a fallback principal).
    With auth off (dev) requests pass through as the default principal."""

    def __init__(self, app) -> None:
        self.app = app
        self._auth = load_auth_config()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self._auth.enabled:
            await self.app(scope, receive, send)
            return
        authz = None
        for k, v in scope.get("headers", []):
            if k == b"authorization":
                authz = v.decode()
                break
        try:
            claims = verify_bearer(self._auth, authz)
        except Exception:
            claims = {}
        if not claims.get("sub"):
            await _unauthorized(send)
            return
        token = _CURRENT_CALLER.set((claims["sub"], claims.get("account") or None))
        try:
            await self.app(scope, receive, send)
        finally:
            _CURRENT_CALLER.reset(token)


async def _unauthorized(send) -> None:
    body = b'{"error":"unauthorized"}'
    await send({"type": "http.response.start", "status": 401,
                "headers": [(b"content-type", b"application/json"),
                            (b"www-authenticate", b"Bearer"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def build_server(config: MCPConfig | None = None):
    """Construct the FastMCP server with the governed tools registered."""
    from mcp.server.fastmcp import FastMCP

    cfg = config or MCPConfig()
    ex = GovernedExecutor(cfg)
    mcp = FastMCP("duckicelake", host=cfg.host, port=cfg.port)

    @mcp.tool()
    def list_namespaces(catalog: str) -> list[str]:
        """List schemas (namespaces) in a catalog."""
        return ex.list_namespaces(catalog, *resolve_caller(cfg))

    @mcp.tool()
    def list_tables(catalog: str, namespace: str) -> list[str]:
        """List tables in a catalog namespace."""
        return ex.list_tables(catalog, namespace, *resolve_caller(cfg))

    @mcp.tool()
    def describe_table(catalog: str, namespace: str, table: str) -> dict:
        """Columns + types of a table (governed: reflects the masked view)."""
        return ex.describe_table(catalog, namespace, table, *resolve_caller(cfg))

    @mcp.tool()
    def query(catalog: str, namespace: str, table: str, sql: str) -> dict:
        """Run a read-only SQL query against `table`. Results are governed for
        an agent — row-filtered and column-masked — and returned as rows (never
        raw credentials). `table` names the query's primary table so masking is
        routed; write `FROM <table>` unqualified."""
        return ex.query(catalog, namespace, table, sql, *resolve_caller(cfg))

    return mcp


def build_app(config: MCPConfig | None = None):
    """The streamable-HTTP ASGI app with per-caller auth middleware."""
    from .config import apply_file_config
    apply_file_config()   # inject [oauth]/etc. from duckicelake.toml/.env into env
    cfg = config or MCPConfig()
    app = build_server(cfg).streamable_http_app()
    app.add_middleware(_AuthMiddleware)
    return cfg, app


def main() -> None:
    import uvicorn
    cfg, app = build_app()
    uvicorn.run(app, host=cfg.host, port=cfg.port)


if __name__ == "__main__":
    main()
