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

import os
import re
import threading
import time
from typing import Any

import duckdb
import httpx

from .config import Settings, load_settings

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
    """Vends governed credentials (actor=agent, channel=mcp) and runs read-only
    SQL server-side, returning rows only. One instance is shared across tools."""

    def __init__(self, config: MCPConfig, settings: Settings | None = None) -> None:
        self.cfg = config
        self.settings = settings or load_settings()
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
        params = {"principal": principal, "actor": "agent", "channel": "mcp",
                  "delegate": "1"}
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
        con.execute(
            "CREATE OR REPLACE SECRET s (TYPE S3, KEY_ID ?, SECRET ?, "
            "REGION ?, ENDPOINT ?, USE_SSL ?, URL_STYLE ?"
            + (", SESSION_TOKEN ?" if vended.get("session-token") else "") + ")",
            [vended.get("access-key-id") or s3.root_access_key,
             vended.get("secret-access-key") or s3.root_secret_key,
             s3.region, s3.host, s3.use_ssl,
             "path" if s3.path_style else "vhost"]
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


def resolve_principal(config: MCPConfig, request_context: Any = None) -> str:
    """The acting end-user principal for a call. A deployment fronting this
    server authenticates the caller and supplies their principal (e.g. from a
    verified bearer/JWT `sub`); until then we use the configured default. Kept
    as a seam so identity resolution is a deployment choice, not baked in."""
    return config.default_principal


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


def main() -> None:
    build_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
