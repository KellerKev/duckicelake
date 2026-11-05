"""SMCP (Secure MCP) interface for duckicelake — the governed tool surface over
an authenticated, per-message-encrypted transport.

Same governed tools as `duckicelake.mcp_server` (list_namespaces, list_tables,
describe_table, query, query_result_set, fetch_result_set) and the same broker-delegated agent governance
(actor=agent, channel=smcp — so airtight file-layer masking + read-only apply),
but reached over SMCP (github.com/KellerKev/smcp): api_key/JWT auth (RS256 in
production so clients can't forge tokens), replay protection, and authenticated
per-message payload encryption — so the tools run safely across a network and
between agents, unlike MCP's local-trusted transport.

SMCP ships as flat top-level modules (`import smcp_server`, `smcp_core`,
`smcp_config`) — put the checkout on PYTHONPATH. The SMCP-side config (secrets,
RS256 keys, host/port) is an SMCP TOML loaded via `SMCPConfig.load` (the
`security.*` block, incl. RS256, is file-only — env can't set it); the
duckicelake side (gov url, broker, principal) comes from `DUCKICELAKE_*` env,
mirroring `mcp_server.MCPConfig`.
"""
from __future__ import annotations

import asyncio
import contextvars
import logging
import os

from .mcp_server import GovernedExecutor, MCPConfig

log = logging.getLogger("duckicelake")

# The SMCP-authenticated caller (verified JWT `client_id`) for the in-flight
# tool call. SMCP does not pass identity to a handler, so `_IdentityNode`
# publishes it here around each authorize_and_invoke; the governed tools
# delegate to the governance core as this principal.
_CURRENT_CLIENT: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "smcp_client", default=None)


def resolve_principal() -> str:
    """Acting principal: the caller's verified SMCP `client_id`, else the
    configured default (a principal with no grants → sees no data)."""
    return _CURRENT_CLIENT.get() or os.environ.get(
        "DUCKICELAKE_SMCP_PRINCIPAL", "smcp-guest")


def _accounts() -> dict[str, str]:
    """DUCKICELAKE_SMCP_ACCOUNTS="client_id=account_id,…" — the tenant each
    SMCP client acts for. SMCP identities carry no account, so this mapping is
    the only thing that lets a client reach an account-owned catalog."""
    out = {}
    for pair in os.environ.get("DUCKICELAKE_SMCP_ACCOUNTS", "").split(","):
        cid, sep, acct = pair.strip().partition("=")
        if sep and cid.strip() and acct.strip():
            out[cid.strip()] = acct.strip()
    return out


def resolve_caller() -> tuple[str, str | None]:
    """(principal, account) the governed tools delegate as. An unmapped
    client has no account → reaches unowned catalogs only."""
    client = _CURRENT_CLIENT.get()
    return resolve_principal(), (_accounts().get(client) if client else None)


def _build_identity_node(cfg):
    """An `SMCPNode` that publishes the verified caller identity into a
    contextvar around the guarded invocation, so governed handlers can delegate
    as that principal (SMCP hands a handler only its params, never identity).
    Reconstructed from config with the same args `SMCPServer` uses, minus its
    demo built-in tools — this node carries ONLY duckicelake's governed tools."""
    from smcp_core import SMCPNode

    class _IdentityNode(SMCPNode):
        def authorize_and_invoke(self, tool_name, parameters, token):
            tok = _CURRENT_CLIENT.set(self._client_id_for(token))
            try:
                return super().authorize_and_invoke(tool_name, parameters, token)
            finally:
                _CURRENT_CLIENT.reset(tok)

    return _IdentityNode(
        cfg.node_id, cfg.secret_key, cfg.jwt_secret,
        getattr(cfg, "kdf_salt", ""), api_key=cfg.api_key,
        jwt_algorithm=cfg.security.jwt_algorithm,
        jwt_private_key_path=cfg.security.jwt_private_key_path,
        jwt_public_key_path=cfg.security.jwt_public_key_path,
    )


def build_server(smcp_cfg=None, mcp_cfg: MCPConfig | None = None):
    """Construct the `SMCPServer` with duckicelake's governed tools
    registered on an identity-aware node. Returns (server, smcp_cfg)."""
    from smcp_config import SMCPConfig
    from smcp_server import SMCPServer

    smcp_cfg = smcp_cfg or SMCPConfig.load(
        config_file=os.environ.get("DUCKICELAKE_SMCP_CONFIG"))
    ex = GovernedExecutor(mcp_cfg or MCPConfig(), channel="smcp")

    server = SMCPServer(smcp_cfg)                 # fail-closed config validation
    server.node = _build_identity_node(smcp_cfg)  # drop demo built-ins; ours only

    def q(catalog, namespace, table, sql):
        return ex.query(catalog, namespace, table, sql, *resolve_caller())

    server.register_tool(
        "list_namespaces", "List schemas (namespaces) in a catalog.",
        {"catalog": {"type": "string"}, "required": ["catalog"]},
        lambda catalog: ex.list_namespaces(catalog, *resolve_caller()))

    server.register_tool(
        "list_tables", "List tables in a catalog namespace.",
        {"catalog": {"type": "string"}, "namespace": {"type": "string"},
         "required": ["catalog", "namespace"]},
        lambda catalog, namespace: ex.list_tables(catalog, namespace, *resolve_caller()))

    server.register_tool(
        "describe_table",
        "Columns + types of a table (governed: reflects the masked view).",
        {"catalog": {"type": "string"}, "namespace": {"type": "string"},
         "table": {"type": "string"}, "required": ["catalog", "namespace", "table"]},
        lambda catalog, namespace, table: ex.describe_table(
            catalog, namespace, table, *resolve_caller()))

    server.register_tool(
        "query",
        "Run a read-only SQL query against `table`. Results are governed for an "
        "agent — row-filtered and column-masked — and returned as rows (never raw "
        "credentials). `table` names the query's primary table; write "
        "`FROM <table>` unqualified so masking routes (a qualified base-table name "
        "is denied for an agent).",
        {"catalog": {"type": "string"}, "namespace": {"type": "string"},
         "table": {"type": "string"}, "sql": {"type": "string"},
         "required": ["catalog", "namespace", "table", "sql"]},
        q)

    server.register_tool(
        "query_result_set",
        "Run a read-only SQL query whose result may be large. The full result is "
        "materialized (governed for an agent: row-filtered, column-masked) and "
        "cached; returns its id, row count, columns and the first `preview_rows` "
        "rows. Page with fetch_result_set. `include_credentials` adds the Parquet "
        "paths and a short-lived S3 credential that reads this result only.",
        {"catalog": {"type": "string"}, "namespace": {"type": "string"},
         "sql": {"type": "string"}, "preview_rows": {"type": "integer"},
         "include_credentials": {"type": "boolean"},
         "required": ["catalog", "namespace", "sql"]},
        lambda catalog, namespace, sql, preview_rows=20, include_credentials=False:
            ex.query_result_set(catalog, namespace, sql, *resolve_caller(),
                                preview_rows=preview_rows,
                                include_credentials=include_credentials))

    server.register_tool(
        "fetch_result_set",
        "Rows [offset, offset+limit) of a result set from query_result_set "
        "(limit at most 1000). `next_offset` is null on the last page.",
        {"catalog": {"type": "string"}, "namespace": {"type": "string"},
         "result_set_id": {"type": "string"}, "offset": {"type": "integer"},
         "limit": {"type": "integer"}, "include_credentials": {"type": "boolean"},
         "required": ["catalog", "namespace", "result_set_id"]},
        lambda catalog, namespace, result_set_id, offset=0, limit=500,
        include_credentials=False:
            ex.fetch_result_set(catalog, namespace, result_set_id, *resolve_caller(),
                                offset=offset, limit=limit,
                                include_credentials=include_credentials))

    return server, smcp_cfg


def main() -> None:
    from .config import apply_file_config
    apply_file_config()   # inject duckicelake.toml/.env DUCKICELAKE_* into env
    logging.basicConfig(
        level=os.environ.get("DUCKICELAKE_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    server, cfg = build_server()
    host, port = cfg.server.host, cfg.server.port
    log.info("duckicelake SMCP interface on %s:%s (channel=smcp, agent-governed; "
             "%d tools)", host, port, len(server.node.capabilities))
    asyncio.run(server.start(host=host, port=port))


if __name__ == "__main__":
    main()
