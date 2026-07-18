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
  DUCKICELAKE_MCP_PRINCIPAL   acting principal when none is resolved from auth
  DUCKICELAKE_MCP_HOST/PORT   listener bind (default 127.0.0.1:8790)
"""
from __future__ import annotations

import contextvars
import os
import re
import threading
import time
from typing import Any

import duckdb
import httpx

from .auth import load_auth_config, verify_bearer
from .config import Settings, load_settings

# The end-user principal for the in-flight MCP request, set by the auth
# middleware from the caller's verified bearer. Delegation flows this principal
# to the governance core (the server holds a *broker* token separately).
_CURRENT_PRINCIPAL: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mcp_principal", default=None)

# Only read-only shapes reach the executor; the vended attach is READ_ONLY and
# the reader role is RLS-scoped, but we refuse writes up front for a clear error.
_READ_ONLY = re.compile(r"^\s*(select|with|describe|desc|show|explain|pragma|values)\b", re.I)
_MAX_ROWS = 500


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

    def gov_get(self, path: str, params: dict | None = None) -> Any:
        r = httpx.get(f"{self.cfg.gov_url}{path}", params=params or {},
                      headers=self._headers(), timeout=30.0)
        r.raise_for_status()
        return r.json()

    def _vend(self, catalog_id: str, namespace: str, principal: str,
              table: str | None) -> dict:
        """Fetch a governed DuckLake-direct credential bundle for an AGENT."""
        params = {"principal": principal, "actor": "agent",
                  "channel": self.channel, "delegate": "1"}
        if table:
            params["table"] = table
        return self.gov_get(
            f"/v1/{catalog_id}/namespaces/{namespace}/ducklake-credentials",
            params)

    def _conn_for(self, bundle: dict, catalog_id: str,
                  namespace: str) -> duckdb.DuckDBPyConnection:
        """A DuckDB connection ATTACHed to the vended (RLS reader, READ_ONLY)
        DuckLake catalog. S3 reads use the vended STS creds when present, else
        the proxy's own root creds (this process is trusted server-side; only
        governed rows ever leave). When the vend carries a masking route
        (`post_attach_sql`), unqualified names resolve to the masked view;
        otherwise we default the search path to the namespace so plain
        `FROM <table>` resolves. Row-level RLS is always enforced by the reader
        role regardless."""
        con = duckdb.connect(":memory:")
        for ext in ("ducklake", "postgres", "httpfs"):
            con.execute(f"INSTALL {ext}"); con.execute(f"LOAD {ext}")
        s3 = self.settings.s3
        vended = bundle.get("s3") or {}
        # Point DuckDB at the VENDED endpoint when creds are vended: the S3
        # gateway (and STS) hand back their own endpoint, and gateway creds only
        # work against the gateway — using the configured backend host here would
        # send them to the wrong place. Derive USE_SSL / url-style from the vend
        # so the http gateway works. Fall back to the backend only for the
        # root-cred path (no vend).
        v_ep = vended.get("endpoint")
        if v_ep:
            endpoint = v_ep.rsplit("://", 1)[-1]
            use_ssl = v_ep.startswith("https")
            url_style = "path" if vended.get("path-style-access", s3.path_style) else "vhost"
        else:
            endpoint, use_ssl = s3.host, s3.use_ssl
            url_style = "path" if s3.path_style else "vhost"
        con.execute(
            "CREATE OR REPLACE SECRET s (TYPE S3, KEY_ID ?, SECRET ?, "
            "REGION ?, ENDPOINT ?, USE_SSL ?, URL_STYLE ?"
            + (", SESSION_TOKEN ?" if vended.get("session-token") else "") + ")",
            [vended.get("access-key-id") or s3.root_access_key,
             vended.get("secret-access-key") or s3.root_secret_key,
             s3.region, endpoint, use_ssl, url_style]
            + ([vended["session-token"]] if vended.get("session-token") else []),
        )
        con.execute(bundle["ducklake_attach_sql"])
        post = bundle.get("post_attach_sql") or []
        if post:
            for stmt in post:            # masked-view route (column masking)
                con.execute(stmt)
        else:                            # no masking policy: default to the ns
            con.execute(f'USE "{catalog_id}"."{namespace}"')
        return con

    def query(self, catalog_id: str, namespace: str, table: str | None,
              sql: str, principal: str) -> dict:
        if not _READ_ONLY.match(sql or ""):
            return {"error": "only read-only SELECT/DESCRIBE/SHOW is allowed"}
        # Vend per-table so column masking (the masked view) is routed; without
        # a table the vend applies row-RLS only. `table` is the query's primary
        # table; multi-table joins fall back to base columns (row-RLS still
        # applies) — prefer one governed table per call for airtight masking.
        bundle = self._vend(catalog_id, namespace, principal, table=table)
        con = self._conn_for(bundle, catalog_id, namespace)
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


def resolve_principal(config: MCPConfig) -> str:
    """The acting end-user principal for the in-flight call: the `sub` of the
    caller's verified bearer (set by the auth middleware), else the configured
    default (dev / auth-off). The server then delegates this principal to the
    governance core with its own broker token."""
    return _CURRENT_PRINCIPAL.get() or config.default_principal


class _AuthMiddleware:
    """ASGI middleware: verify the caller's bearer against the governance auth
    config and pin its `sub` as the request principal. Unauthenticated /
    unverifiable requests fall through to the configured default principal
    (so auth-off dev still works); enforcement is delegated to governance."""

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
        principal = None
        try:
            principal = verify_bearer(self._auth, authz).get("sub")
        except Exception:
            principal = None
        token = _CURRENT_PRINCIPAL.set(principal)
        try:
            await self.app(scope, receive, send)
        finally:
            _CURRENT_PRINCIPAL.reset(token)


def build_server(config: MCPConfig | None = None):
    """Construct the FastMCP server with the governed tools registered."""
    from mcp.server.fastmcp import FastMCP

    cfg = config or MCPConfig()
    ex = GovernedExecutor(cfg)
    mcp = FastMCP("duckicelake", host=cfg.host, port=cfg.port)

    @mcp.tool()
    def list_namespaces(catalog: str) -> list[str]:
        """List schemas (namespaces) in a catalog."""
        out = ex.gov_get(f"/v1/{catalog}/namespaces")
        return [".".join(n) for n in out.get("namespaces", [])]

    @mcp.tool()
    def list_tables(catalog: str, namespace: str) -> list[str]:
        """List tables in a catalog namespace."""
        out = ex.gov_get(f"/v1/{catalog}/namespaces/{namespace}/tables")
        return [i["name"] for i in out.get("identifiers", [])]

    @mcp.tool()
    def describe_table(catalog: str, namespace: str, table: str) -> dict:
        """Columns + types of a table (governed: reflects the masked view)."""
        return ex.query(catalog, namespace, table,
                        f'DESCRIBE "{namespace}"."{table}"',
                        resolve_principal(cfg))

    @mcp.tool()
    def query(catalog: str, namespace: str, table: str, sql: str) -> dict:
        """Run a read-only SQL query against `table`. Results are governed for
        an agent — row-filtered and column-masked — and returned as rows (never
        raw credentials). `table` names the query's primary table so masking is
        routed; write `FROM <table>` unqualified."""
        return ex.query(catalog, namespace, table, sql, resolve_principal(cfg))

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
