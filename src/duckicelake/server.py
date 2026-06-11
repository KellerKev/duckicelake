"""FastAPI app exposing the Iceberg v3 REST Catalog API backed by DuckLake.

Implements the subset of the Apache Iceberg REST Catalog OpenAPI spec needed
for namespace and table lifecycle, which is enough for clients like PyIceberg
to connect, enumerate, create, and drop tables. Full commit semantics (manifest
list rewrites, snapshot lineage) are out of scope for this prototype and
return a 501.

Iceberg spec reference: https://github.com/apache/iceberg/blob/main/open-api/rest-catalog-open-api.yaml
"""
from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any

import duckdb
from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .auth import (
    AuthConfig,
    load_auth_config,
    make_bearer_dependency,
    oauth_token_endpoint,
)
from .auth import claims_from_request
from .catalog import DuckLakeCatalog
from .config import load_settings
from .governance import GovernanceStore
from .masking_views import (
    MASK_SCHEMA_PREFIX,
    MASK_VIEW_PREFIX,
    MaskingViewManager,
)
from .governance_api import build_governance_router
from .policies import PolicyEngine, apply_plan_to_metadata, mask_signature
from .iceberg import build_table_metadata, schema_to_columns_ddl
from .materialize import materialize_all
from .notify import run_listener as run_notify_listener
from .models import (
    CommitTableRequest,
    ConfigResponse,
    CreateNamespaceRequest,
    CreateNamespaceResponse,
    CreateTableRequest,
    GetNamespaceResponse,
    ListNamespacesResponse,
    ListTablesResponse,
    LoadTableResponse,
    RenameTableRequest,
    TableIdentifier,
)
from .observability import (
    COMMIT_TOTAL,
    metrics_endpoint as _metrics_endpoint,
    metrics_middleware,
    setup_logging,
)
from .sts import vend_credentials


setup_logging()


log = logging.getLogger("duckicelake")


# Per Iceberg REST spec, namespace path params are multipart namespaces
# joined by 0x1F (unit separator). Clients URL-encode that as %1F.
NAMESPACE_SEP = "\x1f"


def _parse_namespace(ns_path: str) -> list[str]:
    if not ns_path:
        raise HTTPException(status_code=400, detail="Namespace is required")
    return ns_path.split(NAMESPACE_SEP)


def _iceberg_error(status: int, message: str, type_: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"message": message, "type": type_, "code": status}},
    )


settings = load_settings()
catalog = DuckLakeCatalog(settings)
auth_cfg: AuthConfig = load_auth_config()
require_bearer = make_bearer_dependency(auth_cfg)

# Phase 2 governance enforcement. The store/engine share the catalog's PG
# pool; they're consulted on the read path (LoadTable) to mask columns +
# filter rows per principal. No-op when no governance objects are authored.
governance_store = GovernanceStore(catalog)
policy_engine = PolicyEngine(governance_store)
# Phase 3: ad-hoc masking views — one physical DuckLake view per
# (table, mask-signature), materialized on the read path so both
# DuckLake-direct and view-capable REST clients can execute the mask.
masking_view_manager = MaskingViewManager(catalog, settings)


# `DUCKICELAKE_SUPPRESS_ROOT_CREDS=1` omits the root S3 key pair from every
# response config. Default off (the demo flow hands out root MinIO keys),
# but any deployment relying on the governance cooperative boundary must
# set it — with root keys in client hands, masking is bypassable in one line.
SUPPRESS_ROOT_CREDS = os.environ.get("DUCKICELAKE_SUPPRESS_ROOT_CREDS", "0") == "1"

# Transparent DuckLake-direct masking (`SET search_path` onto a
# `__masked_{sig}` schema, returned as post_attach_sql by the
# ducklake-credentials endpoint). Probe-verified to work
# (scripts/probe_searchpath.py); the flag is an opt-out in case a DuckDB
# release regresses unqualified-name resolution across attached schemas.
# The by-name `masked_view` in the response works regardless.
TRANSPARENT_MASKING = os.environ.get("DUCKICELAKE_TRANSPARENT_MASKING", "1") == "1"

# `DUCKICELAKE_REQUIRE_AUTH=1` fails startup when no OAuth clients are
# configured — a safety-belt for production deploys so ops can't
# accidentally ship a server that's silently auth-off. Dev default is
# unset; the demo flow keeps its current "auth disabled when no clients"
# behaviour.
if os.environ.get("DUCKICELAKE_REQUIRE_AUTH", "0") == "1" and not auth_cfg.enabled:
    raise RuntimeError(
        "DUCKICELAKE_REQUIRE_AUTH=1 but no OAuth clients configured. "
        "Set DUCKICELAKE_OAUTH_CLIENTS (or _CLIENTS_FILE) + "
        "DUCKICELAKE_OAUTH_JWT_SECRET, or unset REQUIRE_AUTH for dev."
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio
    catalog.connect()
    log.info("DuckLake catalog connected: %s", settings.ducklake_uri)
    # Eager DuckLake-to-Iceberg materialisation listener. Elects one
    # worker via PG advisory lock; the others poll the lock so they take
    # over if the elected worker dies. See src/duckicelake/notify.py.
    listener_task = asyncio.create_task(
        run_notify_listener(catalog), name="duckicelake-notify-listener",
    )
    try:
        yield
    finally:
        listener_task.cancel()
        try:
            await listener_task
        except (asyncio.CancelledError, Exception):
            # CancelledError is the normal shutdown path; any other
            # exception we've already logged inside the listener itself.
            pass
        catalog.close()


app = FastAPI(
    title="duckicelake",
    description="Iceberg v3 REST Catalog proxy on top of DuckLake",
    version="0.1.0",
    lifespan=lifespan,
)


# Paths excluded from Bearer auth even when auth is enabled:
#   - /v1/config: clients call this to discover the OAuth endpoint
#   - /v1/oauth/tokens: the token exchange endpoint itself
#   - /docs, /openapi.json: FastAPI auto-docs (dev convenience)
#   - /healthz, /readyz, /metrics: liveness + scrape endpoints. Auth on
#     these would defeat the ops tooling that consumes them.
_AUTH_EXEMPT_PATHS = {
    "/v1/config", "/v1/oauth/tokens", "/openapi.json",
    "/healthz", "/readyz", "/metrics",
}


# Metrics middleware runs on every request; tracks per-route latency and
# count. Registered before the auth middleware so even rejected requests
# still show up in the latency histogram.
app.middleware("http")(metrics_middleware)


@app.middleware("http")
async def bearer_auth_middleware(request: Request, call_next):
    """Enforce Bearer auth + scope check on `/v1/*` routes when any OAuth
    clients are configured. If none are configured, pass through — matches
    the dev default where the demo stack runs without auth.
    """
    if not auth_cfg.enabled:
        return await call_next(request)
    path = request.url.path
    if path in _AUTH_EXEMPT_PATHS or path.startswith("/docs"):
        return await call_next(request)
    if not path.startswith("/v1/"):
        return await call_next(request)
    try:
        from .auth import verify_bearer, scope_allows, request_namespace
        claims = verify_bearer(auth_cfg, request.headers.get("authorization"))
        scope = claims.get("scope", "")
        ns = request_namespace(path)
        if not scope_allows(scope, ns, request.method):
            return _iceberg_error(
                403,
                f"token scope {scope!r} does not allow "
                f"{request.method} on namespace {ns!r}",
                "ForbiddenException",
            )
    except HTTPException as e:
        return _iceberg_error(e.status_code, str(e.detail), "UnauthorizedException")
    return await call_next(request)


@app.post("/v1/oauth/tokens")
async def oauth_tokens(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: str | None = Form(default=None),
) -> dict:
    """Iceberg REST OAuth2 client-credentials token endpoint.

    Returns 401 if auth is disabled — prevents issuing tokens that the
    middleware wouldn't require, which would be confusing.
    """
    if not auth_cfg.enabled:
        raise HTTPException(
            status_code=501,
            detail="OAuth is not enabled on this server",
        )
    return await oauth_token_endpoint(
        auth_cfg, grant_type=grant_type, client_id=client_id,
        client_secret=client_secret, scope=scope,
    )


# ---- governance layer (Phase 1, experimental) -------------------------
# Snowflake-shaped authoring surface + audit. Additive: mounted as its own
# router so the core Iceberg REST surface above is untouched. No enforcement
# yet — see GOVERNANCE.md and src/duckicelake/governance.py.
app.include_router(build_governance_router(catalog, settings, auth_cfg))


# ---- error handling ---------------------------------------------------

@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    detail = str(exc.detail)
    detail_lower = detail.lower()
    if exc.status_code == 409:
        # 409 covers two distinct Iceberg exception classes; pick by detail.
        if "already exists" in detail_lower:
            type_ = "AlreadyExistsException"
        else:
            # Optimistic-concurrency commit failures (assert-ref-snapshot-id,
            # assert-table-uuid, assert-create) — the canonical Iceberg type.
            type_ = "CommitFailedException"
    else:
        type_ = {
            400: "BadRequestException",
            401: "UnauthorizedException",
            403: "ForbiddenException",
            404: "NoSuchNamespaceException",
            501: "NotImplementedException",
        }.get(exc.status_code, "ServiceFailure")
    return _iceberg_error(exc.status_code, detail, type_)


@app.exception_handler(duckdb.Error)
async def duckdb_exc_handler(request: Request, exc: duckdb.Error):
    log.exception("DuckDB error on %s", request.url.path)
    msg = str(exc)
    lower = msg.lower()
    if "already exists" in lower:
        return _iceberg_error(409, msg, "AlreadyExistsException")
    if "does not exist" in lower or "not found" in lower:
        return _iceberg_error(404, msg, "NoSuchTableException")
    return _iceberg_error(500, msg, "ServiceFailure")


# ---- config -----------------------------------------------------------

SUPPORTED_ENDPOINTS = [
    "GET /v1/config",
    "GET /v1/{prefix}/namespaces",
    "POST /v1/{prefix}/namespaces",
    "GET /v1/{prefix}/namespaces/{namespace}",
    "DELETE /v1/{prefix}/namespaces/{namespace}",
    "HEAD /v1/{prefix}/namespaces/{namespace}",
    "GET /v1/{prefix}/namespaces/{namespace}/tables",
    "POST /v1/{prefix}/namespaces/{namespace}/tables",
    "GET /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "HEAD /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "DELETE /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "POST /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "POST /v1/{prefix}/tables/rename",
    "GET /v1/{prefix}/namespaces/{namespace}/views",
    "POST /v1/{prefix}/namespaces/{namespace}/views",
    "GET /v1/{prefix}/namespaces/{namespace}/views/{view}",
    "DELETE /v1/{prefix}/namespaces/{namespace}/views/{view}",
    # --- Phase 3 governance: DuckLake-direct credential vending ---
    "GET /v1/{prefix}/namespaces/{namespace}/ducklake-credentials",
    # --- Phase 1 governance layer (experimental) ---
    "POST /v1/{prefix}/governance/tags",
    "POST /v1/{prefix}/governance/object-tags",
    "POST /v1/{prefix}/governance/masking-policies",
    "POST /v1/{prefix}/governance/row-access-policies",
    "POST /v1/{prefix}/governance/policy-attachments",
    "POST /v1/{prefix}/governance/roles",
    "POST /v1/{prefix}/governance/role-grants",
    "POST /v1/{prefix}/governance/object-grants",
    "GET /v1/{prefix}/governance/effective-policies",
    "GET /v1/{prefix}/governance/audit",
]


# ---- health + metrics -------------------------------------------------

@app.get("/healthz")
def healthz():
    """Liveness: always 200 if the process is up. Used by orchestrators
    to decide whether to restart the container."""
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    """Readiness: 200 only when we can serve real traffic. Checks
    Postgres via the pool with a cheap `SELECT 1` — returns 503 with a
    specific reason when it fails. DuckDB read conn is checked lazily
    since they reconnect on use."""
    if catalog._pg_pool is None:
        return JSONResponse(
            {"status": "not-ready", "reason": "pg pool not initialised"},
            status_code=503,
        )
    try:
        with catalog.pg_cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
    except Exception as e:
        return JSONResponse(
            {"status": "not-ready", "reason": f"postgres probe failed: {e}"},
            status_code=503,
        )
    return {"status": "ready"}


@app.get("/metrics")
def metrics():
    """Prometheus scrape endpoint. See observability.py for the metric
    definitions. Plain-text exposition format per prometheus_client."""
    return _metrics_endpoint(catalog)


@app.get("/v1/config", response_model=ConfigResponse)
def get_config(warehouse: str | None = None) -> ConfigResponse:
    # Many Iceberg clients use a "prefix" in the URL to scope requests to a
    # specific warehouse. We return the catalog name so paths become
    # /v1/<catalog>/namespaces/...
    return ConfigResponse(
        defaults={
            "warehouse": warehouse or settings.catalog_name,
        },
        overrides={
            "prefix": settings.catalog_name,
        },
        endpoints=SUPPORTED_ENDPOINTS,
    )


# ---- namespaces --------------------------------------------------------

def _check_prefix(prefix: str) -> None:
    if prefix != settings.catalog_name:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown catalog prefix '{prefix}'",
        )


@app.get("/v1/{prefix}/namespaces", response_model=ListNamespacesResponse)
def list_namespaces(prefix: str, parent: str | None = None) -> ListNamespacesResponse:
    _check_prefix(prefix)
    parent_list = parent.split(NAMESPACE_SEP) if parent else None
    # Transparent-masking schemas (`__masked_{sig}`) are plumbing, not user
    # namespaces — keep REST enumeration clean. (DuckLake-direct clients
    # still see them in PG; that visibility is inherent.)
    return ListNamespacesResponse(namespaces=[
        n for n in catalog.list_namespaces(parent_list)
        if not n[0].startswith(MASK_SCHEMA_PREFIX)
    ])


@app.post(
    "/v1/{prefix}/namespaces",
    response_model=CreateNamespaceResponse,
    status_code=200,
)
def create_namespace(
    prefix: str, req: CreateNamespaceRequest
) -> CreateNamespaceResponse:
    _check_prefix(prefix)
    if req.namespace and req.namespace[0].startswith(MASK_SCHEMA_PREFIX):
        raise HTTPException(
            status_code=400,
            detail=f"Namespaces starting with '{MASK_SCHEMA_PREFIX}' are "
                   "reserved for governance masking schemas",
        )
    if catalog.namespace_exists(req.namespace):
        raise HTTPException(
            status_code=409,
            detail=f"Namespace already exists: {req.namespace}",
        )
    catalog.create_namespace(req.namespace)
    return CreateNamespaceResponse(namespace=req.namespace, properties=req.properties)


@app.get("/v1/{prefix}/namespaces/{namespace}", response_model=GetNamespaceResponse)
def get_namespace(prefix: str, namespace: str) -> GetNamespaceResponse:
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.namespace_exists(ns):
        raise HTTPException(status_code=404, detail=f"Namespace does not exist: {ns}")
    return GetNamespaceResponse(namespace=ns, properties={})


@app.head("/v1/{prefix}/namespaces/{namespace}")
def head_namespace(prefix: str, namespace: str):
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.namespace_exists(ns):
        raise HTTPException(status_code=404, detail=f"Namespace does not exist: {ns}")
    return Response(status_code=204)


@app.delete("/v1/{prefix}/namespaces/{namespace}", status_code=204)
def drop_namespace(prefix: str, namespace: str):
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.namespace_exists(ns):
        raise HTTPException(status_code=404, detail=f"Namespace does not exist: {ns}")
    catalog.drop_namespace(ns)
    return Response(status_code=204)


# ---- tables ------------------------------------------------------------

@app.get(
    "/v1/{prefix}/namespaces/{namespace}/tables",
    response_model=ListTablesResponse,
)
def list_tables(prefix: str, namespace: str) -> ListTablesResponse:
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.namespace_exists(ns):
        raise HTTPException(status_code=404, detail=f"Namespace does not exist: {ns}")
    rows = catalog.list_tables(ns)
    return ListTablesResponse(
        identifiers=[TableIdentifier(namespace=ns, name=r[1]) for r in rows]
    )


@app.post(
    "/v1/{prefix}/namespaces/{namespace}/tables",
    response_model=LoadTableResponse,
    status_code=200,
)
def create_table(
    prefix: str,
    namespace: str,
    req: CreateTableRequest,
    x_iceberg_access_delegation: str | None = Header(default=None),
) -> LoadTableResponse:
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.namespace_exists(ns):
        raise HTTPException(status_code=404, detail=f"Namespace does not exist: {ns}")
    if catalog.table_exists(ns, req.name):
        raise HTTPException(
            status_code=409,
            detail=f"Table already exists: {ns}.{req.name}",
        )
    if req.stage_create:
        raise HTTPException(status_code=501, detail="stage-create is not supported")

    ddl, _last_id = schema_to_columns_ddl(req.schema_)
    catalog.create_table(ns, req.name, ddl)
    return _build_load_response(
        ns, req.name,
        properties=req.properties,
        delegation_header=x_iceberg_access_delegation,
        read_only=False,
    )


@app.get(
    "/v1/{prefix}/namespaces/{namespace}/tables/{table}",
    response_model=LoadTableResponse,
)
def load_table(
    prefix: str,
    namespace: str,
    table: str,
    request: Request,
    snapshot_id: int | None = None,   # time-travel
    x_iceberg_access_delegation: str | None = Header(default=None),
) -> LoadTableResponse:
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.table_exists(ns, table):
        raise HTTPException(
            status_code=404, detail=f"Table does not exist: {ns}.{table}"
        )
    return _build_load_response(
        ns, table,
        delegation_header=x_iceberg_access_delegation,
        read_only=True,
        snapshot_id_override=snapshot_id,
        principal_claims=claims_from_request(auth_cfg, request),
    )


@app.head("/v1/{prefix}/namespaces/{namespace}/tables/{table}")
def head_table(prefix: str, namespace: str, table: str):
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.table_exists(ns, table):
        raise HTTPException(
            status_code=404, detail=f"Table does not exist: {ns}.{table}"
        )
    return Response(status_code=204)


@app.delete(
    "/v1/{prefix}/namespaces/{namespace}/tables/{table}", status_code=204
)
def drop_table(
    prefix: str, namespace: str, table: str, purgeRequested: bool = False
):
    """DROP TABLE. When `purgeRequested=true`, also delete every S3 object
    under the table's prefix — Parquet data files, delete files, manifest
    Avros, metadata JSONs. Without purge, DuckLake's own
    `ducklake_cleanup_old_files` eventually reclaims tombstoned data files;
    the metadata Avros become orphans unless purged."""
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.table_exists(ns, table):
        raise HTTPException(
            status_code=404, detail=f"Table does not exist: {ns}.{table}"
        )
    catalog.drop_table(ns, table)
    catalog.invalidate_metadata_cache(ns, table)
    if purgeRequested:
        n = catalog.purge_table_objects(ns, table)
        log.info("purge %s.%s: %d S3 objects removed", ns[0], table, n)
    return Response(status_code=204)


# ---- admin ------------------------------------------------------------

@app.post(
    "/v1/{prefix}/admin/namespaces/{namespace}/tables/{table}/compact",
    status_code=200,
)
def compact_table(prefix: str, namespace: str, table: str) -> dict[str, Any]:
    """Trigger DuckLake compaction + file cleanup on a table.

    Safe to schedule on a cron — each call is idempotent and returns
    quickly when there's nothing to compact. Requires a token with
    write scope on the target namespace.
    """
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.table_exists(ns, table):
        raise HTTPException(
            status_code=404, detail=f"Table does not exist: {ns}.{table}"
        )
    result = catalog.compact_table(ns, table)
    catalog.invalidate_metadata_cache(ns, table)
    log.info("compact %s.%s: %s", ns[0], table, result)
    return result


# ---- views -----------------------------------------------------------

@app.get("/v1/{prefix}/namespaces/{namespace}/views")
def list_views(prefix: str, namespace: str) -> dict[str, Any]:
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.namespace_exists(ns):
        raise HTTPException(status_code=404, detail=f"Namespace does not exist: {ns}")
    # Masking views stay out of enumeration (they're advertised per-principal
    # via the `duckicelake.masking-view-name` LoadTable property) but remain
    # loadable/droppable by name. Filtered here, not in catalog.list_views —
    # gc_orphans needs the unfiltered list.
    names = [n for n in catalog.list_views(ns) if not n.startswith(MASK_VIEW_PREFIX)]
    return {"identifiers": [{"namespace": ns, "name": n} for n in names]}


@app.post("/v1/{prefix}/namespaces/{namespace}/views", status_code=200)
def create_view(prefix: str, namespace: str, body: dict[str, Any]) -> dict[str, Any]:
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.namespace_exists(ns):
        raise HTTPException(status_code=404, detail=f"Namespace does not exist: {ns}")
    name = body["name"]
    if name.startswith(MASK_VIEW_PREFIX):
        raise HTTPException(
            status_code=400,
            detail=f"View names starting with '{MASK_VIEW_PREFIX}' are reserved "
                   "for governance masking views",
        )
    view_version = body.get("view-version") or {}
    reps = view_version.get("representations", [])
    sqls = [r["sql"] for r in reps if r.get("type") == "sql" and r.get("dialect", "").lower() in ("", "duckdb", "postgresql", "spark", "trino")]
    if not sqls:
        raise HTTPException(status_code=400, detail="view requires a sql representation")
    if catalog.view_exists(ns, name):
        raise HTTPException(status_code=409, detail=f"View already exists: {ns}.{name}")
    catalog.create_view(ns, name, sqls[0])
    return _build_view_response(ns, name)


@app.get("/v1/{prefix}/namespaces/{namespace}/views/{view}")
def load_view(prefix: str, namespace: str, view: str) -> dict[str, Any]:
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.view_exists(ns, view):
        raise HTTPException(status_code=404, detail=f"View does not exist: {ns}.{view}")
    return _build_view_response(ns, view)


@app.delete("/v1/{prefix}/namespaces/{namespace}/views/{view}", status_code=204)
def drop_view(prefix: str, namespace: str, view: str):
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.view_exists(ns, view):
        raise HTTPException(status_code=404, detail=f"View does not exist: {ns}.{view}")
    catalog.drop_view(ns, view)
    return Response(status_code=204)


def _build_view_response(ns: list[str], view: str) -> dict[str, Any]:
    """Iceberg View metadata. SQL comes from information_schema.views;
    schema comes from information_schema.columns on the view itself —
    DuckDB resolves the view once so we get back concrete types."""
    sql = catalog.get_view_definition(ns, view) or ""
    view_uuid = catalog.table_uuid(ns, view)
    # Concrete schema from information_schema.columns.
    columns = catalog.get_columns(ns, view)
    from .types import duckdb_type_to_iceberg
    view_schema = {
        "schema-id": 0,
        "type": "struct",
        "fields": [
            {
                "id": i + 1,
                "name": c.name,
                "required": not c.is_nullable,
                "type": duckdb_type_to_iceberg(c.data_type),
            }
            for i, c in enumerate(columns)
        ],
    }
    md = {
        "view-uuid": view_uuid,
        "format-version": 1,
        "location": f"s3://{settings.s3.bucket}/{settings.s3.table_prefix(ns[0], view)}".rstrip("/"),
        "schemas": [view_schema],
        "current-schema-id": 0,
        "current-version-id": 1,
        "versions": [{
            "version-id": 1,
            "schema-id": 0,
            "timestamp-ms": int(time.time() * 1000),
            "default-namespace": ns,
            "summary": {"operation": "create"},
            "representations": [{"type": "sql", "sql": sql, "dialect": "duckdb"}],
        }],
        "version-log": [{"version-id": 1, "timestamp-ms": int(time.time() * 1000)}],
        "properties": {},
    }
    return {
        "metadata-location": f"s3://{settings.s3.bucket}/{settings.s3.table_prefix(ns[0], view)}metadata/view.json",
        "metadata": md,
        "config": _base_s3_config(),
    }


# ---- DuckLake-direct credentials (governance Phase 3) ------------------

@app.get("/v1/{prefix}/namespaces/{namespace}/ducklake-credentials")
def ducklake_credentials(
    prefix: str,
    namespace: str,
    request: Request,
    table: str | None = None,
    duration_seconds: int = 3600,
    principal: str | None = None,
) -> dict[str, Any]:
    """Vend everything a DuckLake-direct DuckDB client needs, with the
    caller's masking applied cooperatively:

      * the Postgres DSN / ATTACH statement for the DuckLake catalog,
      * read-only S3 creds scoped to the table's (or namespace's) data
        prefix — prefix- not file-scoped, so files committed after vending
        stay readable for the session's lifetime,
      * the caller's masking view (`masked_view`) when a policy applies,
      * `post_attach_sql` that re-routes *unqualified* queries to the
        masked view via DuckDB `SET search_path` (`transparent: true`).

    GET + namespace-scoped path so read-only `ns:r` tokens (the LLM-agent
    shape) pass the bearer middleware. `principal` is honored only when
    auth is off (dev/test; same precedent as governance/effective-policies).

    Fail-open like the LoadTable path: a governance error degrades to
    unmasked vending (audited as error_unmasked), never a 500. The masking
    here is cooperative — see GOVERNANCE.md for the boundary.
    """
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.namespace_exists(ns):
        raise HTTPException(status_code=404, detail=f"Namespace does not exist: {ns}")
    if table is not None and not catalog.table_exists(ns, table):
        raise HTTPException(status_code=404, detail=f"Table does not exist: {ns}.{table}")

    claims = claims_from_request(auth_cfg, request)
    sub = claims.get("sub") or "anonymous"
    if principal and not auth_cfg.enabled:
        sub = principal

    alias = settings.catalog_name
    out: dict[str, Any] = {
        "ducklake_dsn": settings.pg_dsn,
        "ducklake_attach_sql": (
            f"ATTACH '{settings.ducklake_uri}' AS {alias} "
            f"(DATA_PATH '{settings.ducklake_data_path}')"
        ),
        "post_attach_sql": [],
        "masked_view": None,
        "mask_signature": None,
        "transparent": False,
    }

    decision = "ok"
    masked_cols: list[str] = []
    applied: list[str] = []
    row_filtered = False
    try:
        roles = sorted(
            set(claims.get("roles") or [])
            | set(governance_store.roles_for_principal(sub))
        )
        if table is not None:
            plan = policy_engine.plan_for(
                principal=sub, roles=roles, schema=ns[0], table=table,
            )
            if not plan.is_empty():
                masked_cols = plan.masked_columns
                applied = plan.applied_policies
                row_filtered = plan.row_filter is not None
                view = masking_view_manager.ensure_view_for_plan(ns, table, plan)
                if view:
                    decision = "masked"
                    out["masked_view"] = f"{ns[0]}.{view}"
                    out["mask_signature"] = mask_signature(plan)
                    if TRANSPARENT_MASKING:
                        schema = masking_view_manager.ensure_transparent_schema(
                            ns, table, plan,
                        )
                        if schema:
                            out["transparent"] = True
                            out["post_attach_sql"] = [
                                f"SET search_path = '{alias}.{schema},{alias}.{ns[0]}'"
                            ]
                else:
                    # plan demands masking but no view could be materialized
                    # — fail-open, flag it in the audit trail
                    decision = "error_unmasked"
    except Exception:
        log.exception("ducklake-credentials governance failed for %s.%s "
                      "— vending unmasked", ns[0], table)
        decision = "error_unmasked"

    s3 = settings.s3
    read_prefixes = (
        [s3.table_prefix(ns[0], table)] if table is not None
        else [f"{s3.data_prefix}{ns[0]}/"]
    )
    try:
        creds = vend_credentials(
            s3,
            namespace=ns[0],
            table=table or "*",
            read_only=True,
            read_prefixes=read_prefixes,
            duration_seconds=max(900, min(43200, duration_seconds)),
            principal=sub,
        )
        out["s3"] = {
            "endpoint": s3.endpoint,
            "region": s3.region,
            "path-style-access": s3.path_style,
            "access-key-id": creds.access_key_id,
            "secret-access-key": creds.secret_access_key,
            "session-token": creds.session_token,
            "expiration": creds.expiration_iso,
        }
    except Exception:
        log.exception("ducklake-credentials STS vending failed for %s — %s",
                      ns[0], "falling back to root keys"
                      if not SUPPRESS_ROOT_CREDS else "no creds returned")
        if SUPPRESS_ROOT_CREDS:
            out["s3"] = None
            decision = "error_no_creds"
        else:
            out["s3"] = {
                "endpoint": s3.endpoint,
                "region": s3.region,
                "path-style-access": s3.path_style,
                "access-key-id": s3.root_access_key,
                "secret-access-key": s3.root_secret_key,
                "session-token": None,
                "expiration": None,
            }
            decision = "error_unmasked" if decision != "masked" else decision

    try:
        governance_store.audit_load(
            principal=sub,
            object_=f"{ns[0]}.{table or '*'}",
            masked_cols=masked_cols,
            applied_policies=applied,
            row_filtered=row_filtered,
            operation="ducklake_credentials",
            decision=decision,
            detail={
                "transparent": out["transparent"],
                "masked_view": out["masked_view"],
            },
        )
    except Exception:
        log.exception("ducklake-credentials audit failed")

    return out


@app.post("/v1/{prefix}/tables/rename", status_code=204)
def rename_table(prefix: str, req: RenameTableRequest):
    _check_prefix(prefix)
    if not catalog.table_exists(req.source.namespace, req.source.name):
        raise HTTPException(
            status_code=404,
            detail=f"Source table does not exist: {req.source.namespace}.{req.source.name}",
        )
    if catalog.table_exists(req.destination.namespace, req.destination.name):
        raise HTTPException(
            status_code=409,
            detail=f"Destination table exists: {req.destination.namespace}.{req.destination.name}",
        )
    catalog.rename_table(
        req.source.namespace, req.source.name,
        req.destination.namespace, req.destination.name,
    )
    return Response(status_code=204)


@app.post(
    "/v1/{prefix}/namespaces/{namespace}/tables/{table}",
    response_model=LoadTableResponse,
)
def commit_table(
    prefix: str, namespace: str, table: str, req: CommitTableRequest
) -> LoadTableResponse:
    """Commit updates to a table.

    Supported updates (schema-DDL subset):
      - set-properties / remove-properties / assign-uuid (accepted, not persisted)
      - add-schema + set-current-schema: diffs the new schema against the
        current one and issues ADD COLUMN / DROP COLUMN via DuckLake. Type
        changes and renames aren't supported — safer to return 501 than
        silently corrupt.

    Data-plane commits (add-snapshot, set-snapshot-ref) still return 501.
    """
    _check_prefix(prefix)
    ns = _parse_namespace(namespace)
    if not catalog.table_exists(ns, table):
        raise HTTPException(
            status_code=404, detail=f"Table does not exist: {ns}.{table}"
        )

    # Enforce optimistic-concurrency requirements from the client FIRST.
    # If the caller asserted "table is at snapshot N" and DuckLake has
    # advanced past that, we refuse the commit. The client retries with a
    # fresh read. This is how Iceberg handles concurrent writers.
    _check_requirements(ns, table, req.requirements)

    # Pre-scan: writes targeted at a non-main branch (add-snapshot +
    # set-snapshot-ref type=branch, name != main) 501 right away so we
    # don't walk the client's manifest chain for nothing.
    has_add_snapshot = any(u.get("action") == "add-snapshot" for u in req.updates)
    branch_write_target: str | None = None
    for u in req.updates:
        if u.get("action") != "set-snapshot-ref":
            continue
        if (u.get("type") or "").lower() != "branch":
            continue
        ref = u.get("ref-name")
        if ref and ref != "main":
            branch_write_target = ref
            break
    if has_add_snapshot and branch_write_target:
        raise HTTPException(
            status_code=501,
            detail=(
                f"writes to non-main branch {branch_write_target!r} are "
                f"not supported. DuckLake has a single linear history; "
                f"named branches are exposed as read-only pointers."
            ),
        )

    new_schema: dict[str, Any] | None = None
    pending_add_paths: list[str] = []
    pending_remove_paths: list[str] = []
    pending_pos_deletes: list[Any] = []  # PositionDeleteSpec
    pending_eq_deletes: list[Any] = []   # EqualityDeleteSpec
    pending_partition_spec: dict[str, Any] | None = None
    pending_sort_order: dict[str, Any] | None = None
    pending_remove_snapshot_ids: list[int] = []
    pending_properties_set: dict[str, str] = {}
    pending_properties_remove: list[str] = []
    pending_tag: tuple[str, int, str] | None = None   # (ref_name, snapshot_id, ref_type)
    pending_tag_remove: str | None = None

    for u in req.updates:
        action = u.get("action")
        if action == "set-properties":
            pending_properties_set.update(u.get("updates") or {})
            continue
        if action == "remove-properties":
            pending_properties_remove.extend(u.get("removals") or [])
            continue
        if action == "assign-uuid":
            # We derive table UUIDs deterministically from the qualified
            # name; the client's assigned-uuid is accepted but not persisted.
            continue
        if action == "upgrade-format-version":
            # v3 writes now work through the `pyiceberg_v3` shim; accept
            # the upgrade so the client's next `append()` uses v3 manifest
            # writers. We persist the requested version in a sidecar so
            # LoadTable emits it on subsequent reads. Reject >3 loudly.
            want = u.get("format-version")
            if want is None:
                continue
            want = int(want)
            if want > 3:
                raise HTTPException(
                    status_code=501,
                    detail=(
                        f"upgrade-format-version to {want} not supported "
                        f"(Iceberg spec tops out at 3 today)."
                    ),
                )
            pending_properties_set["duckicelake.format-version"] = str(want)
            continue
        if action == "remove-snapshot":
            sid = u.get("snapshot-id")
            if sid is None:
                raise HTTPException(400, "remove-snapshot requires snapshot-id")
            pending_remove_snapshot_ids.append(int(sid))
            continue
        if action == "remove-snapshot-ref":
            ref = u.get("ref-name") or "main"
            if ref == "main":
                raise HTTPException(
                    status_code=409,
                    detail="cannot remove the 'main' ref — it tracks DuckLake's HEAD",
                )
            pending_tag_remove = ref
            continue
        if action == "set-snapshot-ref":
            ref_name = u.get("ref-name")
            ref_type = (u.get("type") or "branch").lower()
            sid = u.get("snapshot-id")
            if ref_name == "main":
                # Main tracks DuckLake's HEAD; ignore the client's assertion.
                continue
            if ref_type not in {"tag", "branch"}:
                raise HTTPException(
                    status_code=400,
                    detail=f"unknown ref type: {ref_type!r}",
                )
            if sid is None:
                raise HTTPException(400, "set-snapshot-ref requires snapshot-id")
            # Branches other than main are tracked as read-only named
            # pointers — DuckLake has no native branching so writes to
            # these refs still 501. Tags are the normal case.
            pending_tag = (ref_name, int(sid), ref_type)
            continue
        if action in {"add-statistics", "remove-statistics"}:
            # We synthesise stats from DuckLake's own column stats; client
            # statistics files (sketches, etc.) aren't persisted. Accept
            # the commit so clients don't error, but we don't act on them.
            continue
        if action == "add-schema":
            new_schema = u.get("schema")
            continue
        if action == "set-current-schema":
            continue
        if action == "set-snapshot-ref":
            # DuckLake is the single writer; its HEAD is the only `main`
            # that matters. The client's intended ref will match whatever
            # DuckLake commits below.
            continue
        if action == "add-partition-spec":
            pending_partition_spec = u.get("spec") or {}
            continue
        if action == "set-default-spec":
            # Implicit when add-partition-spec ran; nothing to do here.
            continue
        if action == "add-sort-order":
            pending_sort_order = u.get("sort-order") or {}
            continue
        if action == "set-default-sort-order":
            continue
        if action == "set-location":
            # DuckLake owns file layout via DATA_PATH (set at attach time).
            # Per-table location overrides aren't expressible without
            # re-attaching with a different DATA_PATH. Reject loudly.
            raise HTTPException(
                status_code=501,
                detail=(
                    "set-location is not supported. DuckLake controls data "
                    "file layout via the catalog's DATA_PATH; tables can't "
                    "individually relocate. To move data, drop and recreate "
                    "with a new DATA_PATH on the DuckLake attach side."
                ),
            )
        if action == "add-snapshot":
            snapshot = u.get("snapshot") or {}
            manifest_list = snapshot.get("manifest-list")
            client_snapshot_id = snapshot.get("snapshot-id")
            if not manifest_list or client_snapshot_id is None:
                raise HTTPException(
                    status_code=400,
                    detail="add-snapshot requires snapshot.manifest-list and snapshot-id",
                )
            from .read_manifest import extract_commit_changes
            changes = extract_commit_changes(
                manifest_list, settings.s3,
                snapshot_id=int(client_snapshot_id),
            )
            pending_add_paths.extend(changes.added_data_paths)
            pending_remove_paths.extend(changes.removed_data_paths)
            pending_pos_deletes.extend(changes.position_deletes)
            pending_eq_deletes.extend(changes.equality_deletes)
            continue
        if action in {
            "set-default-partition-spec",
            "set-statistics", "remove-statistics",
        }:
            # These aren't expressible through DuckLake today. Return a
            # structured 501 rather than accepting silently — see MISSING.md.
            raise HTTPException(
                status_code=501,
                detail=(
                    f"commit action '{action}' is not supported on a "
                    f"DuckLake-backed catalog. Partition/sort/statistics "
                    f"mutations and snapshot-removal must go through "
                    f"DuckLake directly."
                ),
            )
        raise HTTPException(
            status_code=501,
            detail=f"Unknown commit update: {action}",
        )

    # Wrap all PG-side mutations in one Postgres transaction so a mid-
    # commit failure rolls back cleanly. DuckDB-side calls (add_data_files,
    # expire_snapshots, ALTER TABLE, COPY) are on a separate connection and
    # manage their own DuckLake transactions; their side effects aren't
    # rolled back by this scope, but DuckLake itself enforces per-call
    # atomicity on the snapshot allocator.
    with catalog.commit_transaction():
        if new_schema is not None:
            _apply_schema_diff(ns, table, new_schema)

        if pending_partition_spec is not None:
            _apply_partition_spec(ns, table, pending_partition_spec)

        if pending_sort_order is not None:
            _apply_sort_order(ns, table, pending_sort_order)

        # Order matters: add new data first so the new snapshot it creates is
        # the basis for any subsequent tombstones / delete-file registrations
        # in this commit. Non-append commits below produce additional
        # DuckLake snapshots; the next LoadTable materialises one Iceberg
        # snapshot per DuckLake snapshot so the client sees the chain.

        if pending_add_paths:
            catalog.add_data_files(ns, table, pending_add_paths)

        if pending_remove_paths:
            catalog.tombstone_data_files(
                ns, table, pending_remove_paths,
                change_msg=f"deleted_from_table:iceberg_overwrite",
            )

        if pending_pos_deletes:
            specs = [
                {
                    "path": d.path,
                    "target_data_file": d.target_data_file,
                    "delete_count": d.delete_count,
                    "file_size_bytes": d.file_size_bytes,
                }
                for d in pending_pos_deletes
            ]
            catalog.register_delete_files(
                ns, table, specs,
                change_msg=f"deleted_from_table:iceberg_position_delete",
            )

        if pending_eq_deletes:
            for eq in pending_eq_deletes:
                names_by_id = catalog.column_names_by_ids(ns, table, eq.equality_field_ids)
                col_names = [names_by_id[i] for i in eq.equality_field_ids if i in names_by_id]
                if not col_names:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"equality-delete file {eq.path!r} references field-ids "
                            f"{eq.equality_field_ids} none of which are in the current "
                            f"schema of {ns[0]}.{table}"
                        ),
                    )
                catalog.apply_equality_delete(ns, table, eq.path, col_names)

        if pending_remove_snapshot_ids:
            catalog.expire_snapshots(pending_remove_snapshot_ids)

        if pending_properties_set or pending_properties_remove:
            catalog.upsert_table_properties(
                ns, table,
                set_map=pending_properties_set,
                remove=pending_properties_remove,
            )

        if pending_tag is not None:
            catalog.upsert_tag(
                ns, table, pending_tag[0], pending_tag[1], ref_type=pending_tag[2]
            )

        if pending_tag_remove is not None:
            catalog.remove_tag(ns, table, pending_tag_remove)

    # Bust the in-process metadata cache so the follow-up _build_load_response
    # does a full materialise and re-primes the cache at the new snapshot id.
    # This keeps post-commit reads fast while guaranteeing correctness.
    catalog.invalidate_metadata_cache(ns, table)

    # Eager materialise: _build_load_response calls materialize_all, which
    # writes all the snapshot/manifest Avros + the new vN.metadata.json and
    # primes the in-process cache. Subsequent readers hit the cache with no
    # S3 / no manifest-generation cost.
    COMMIT_TOTAL.labels("ok").inc()
    return _build_load_response(ns, table)


def _check_requirements(
    ns: list[str], table: str, requirements: list[dict[str, Any]],
) -> None:
    """Validate client-supplied `requirements[]` on a CommitTable.

    Supports:
      - `assert-create`: table must not already exist (CreateTable path)
      - `assert-table-uuid`: table UUID matches
      - `assert-ref-snapshot-id`: the specified ref points at the given
        snapshot-id (or is null when caller expects a fresh table)
      - `assert-last-assigned-field-id` and friends (currently no-op — we
        don't track them; would require wiring DuckLake schema versions
        through more carefully)

    Unknown requirement types raise 400 so clients see the problem, not 412.
    """
    for r in requirements:
        t = r.get("type")
        if t == "assert-create":
            if catalog.table_exists(ns, table):
                raise HTTPException(
                    status_code=409,
                    detail=f"assert-create failed: {ns[0]}.{table} already exists",
                )
        elif t == "assert-table-uuid":
            want = r.get("uuid")
            got = catalog.table_uuid(ns, table)
            if want != got:
                raise HTTPException(
                    status_code=409,
                    detail=f"assert-table-uuid failed: have {got}, client expected {want}",
                )
        elif t == "assert-ref-snapshot-id":
            # Currently we only track `main` (DuckLake's HEAD).
            ref = r.get("ref", "main")
            if ref != "main":
                raise HTTPException(
                    status_code=400,
                    detail=f"only the 'main' ref is supported; got {ref!r}",
                )
            expected = r.get("snapshot-id")
            current = catalog.current_ducklake_snapshot(ns, table)
            if expected != current:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"CommitFailedException: assert-ref-snapshot-id=main "
                        f"expected {expected}, current is {current}"
                    ),
                )
        elif t in {"assert-last-assigned-field-id",
                   "assert-last-assigned-partition-id",
                   "assert-default-spec-id",
                   "assert-default-sort-order-id",
                   "assert-current-schema-id"}:
            # Accept but don't enforce — we haven't wired these through to
            # DuckLake's schema-versions tracking yet. A client that cares
            # about these won't see divergence because DuckLake is the only
            # writer.
            continue
        else:
            raise HTTPException(
                status_code=400,
                detail=f"unknown commit requirement: {t}",
            )


def _apply_partition_spec(ns: list[str], table: str, spec: dict[str, Any]) -> None:
    """Translate Iceberg add-partition-spec → DuckLake ALTER TABLE …
    SET PARTITIONED BY (…).

    Iceberg transforms that DuckLake can express (identity / year / month /
    day / hour / bucket[N]) flow into the native DuckLake partition spec.
    Transforms DuckLake can't express (truncate[N], void) are recorded in
    a sidecar and synthesised per-file from source column stats at
    emission time — the Iceberg spec round-trips correctly even though
    DuckLake's physical partitioning omits those fields.
    """
    from .partition_sort import (
        IcebergPartitionField,
        UnsupportedPartitionTransform,
        iceberg_partition_fields_to_alter_clause,
        is_native_ducklake_transform,
    )
    snap = catalog.current_ducklake_snapshot(ns, table) or 0
    cols = catalog.columns_at(ns, table, snap)
    col_name_by_id = {c.column_id: c.column_name for c in cols}

    raw_fields = spec.get("fields", [])
    fields = [
        IcebergPartitionField(
            name=str(f.get("name", "")),
            source_id=int(f["source-id"]),
            transform=str(f["transform"]),
            field_id=int(f.get("field-id", 1000 + i)),
        )
        for i, f in enumerate(raw_fields)
    ]

    native_fields = [f for f in fields if is_native_ducklake_transform(f.transform)]
    synthetic_fields = [f for f in fields if not is_native_ducklake_transform(f.transform)]

    # Reject `void` — pure no-op in DuckLake and no real use case.
    for f in synthetic_fields:
        if f.transform.strip().lower() == "void":
            raise HTTPException(
                status_code=501,
                detail=(
                    "Iceberg `void` partition transform is a semantic no-op "
                    "(drops the field from the spec). Submit a new "
                    "add-partition-spec without the field instead."
                ),
            )

    try:
        clause = iceberg_partition_fields_to_alter_clause(native_fields, col_name_by_id)
    except UnsupportedPartitionTransform as e:
        raise HTTPException(status_code=501, detail=str(e))

    catalog.set_partition_spec(ns, table, clause)

    # Sidecar: store the FULL iceberg spec when any synthetic fields are
    # present; otherwise clear it so materialize falls back to DuckLake's
    # native spec (keeps the hot path simple for the common case).
    if synthetic_fields:
        native_positions = {id(f): i for i, f in enumerate(native_fields)}
        sidecar_fields = []
        for pos, f in enumerate(fields):
            dk_idx = native_positions.get(id(f))
            sidecar_fields.append({
                "field-id": f.field_id,
                "source-id": f.source_id,
                "transform": f.transform,
                "name": f.name or f"{col_name_by_id.get(f.source_id, 'col')}_trunc",
                "position": pos,
                "ducklake_key_index": dk_idx,
            })
        catalog.upsert_iceberg_partition_spec(ns, table, sidecar_fields)
    else:
        catalog.upsert_iceberg_partition_spec(ns, table, [])


def _apply_sort_order(ns: list[str], table: str, sort_order: dict[str, Any]) -> None:
    """Translate Iceberg add-sort-order → direct mutation of
    `ducklake_sort_info` + `ducklake_sort_expression`."""
    from .partition_sort import normalize_iceberg_sort_fields
    fields = normalize_iceberg_sort_fields(sort_order.get("fields", []))
    catalog.set_sort_order(ns, table, fields)


def _apply_schema_diff(ns: list[str], table: str, new_schema: dict[str, Any]) -> None:
    """Translate an Iceberg `add-schema` into DuckDB ADD/DROP COLUMN.

    We match columns by `id` (field-id). Columns in the new schema with an
    id not present today are added. Columns present today but missing from
    the new schema are dropped. Type or required-ness changes require a
    full rewrite and are rejected.
    """
    from .types import iceberg_type_to_duckdb, ducklake_type_to_iceberg

    current = catalog.columns_at(
        ns, table, catalog.current_ducklake_snapshot(ns, table) or 0
    )
    current_by_id = {c.column_id: c for c in current}
    new_by_id = {f["id"]: f for f in new_schema.get("fields", [])}

    for fid, f in new_by_id.items():
        if fid in current_by_id:
            # Exists — verify type compatibility (loosely).
            cur = current_by_id[fid]
            cur_ice = ducklake_type_to_iceberg(cur.column_type)
            new_ice = f["type"]
            if isinstance(cur_ice, str) and isinstance(new_ice, str) and cur_ice != new_ice:
                raise HTTPException(
                    status_code=501,
                    detail=f"Type change for column '{f['name']}' not supported: {cur_ice} → {new_ice}",
                )
            continue
        # New column.
        ddl_type = iceberg_type_to_duckdb(f["type"])
        default = f.get("write-default") or f.get("initial-default")
        catalog.add_column(
            ns, table, f["name"], ddl_type,
            nullable=not bool(f.get("required", False)),
            default_value=repr(default) if isinstance(default, str) else default,
        )

    for fid, cur in current_by_id.items():
        if fid not in new_by_id:
            catalog.drop_column(ns, table, cur.column_name)


# ---- helpers -----------------------------------------------------------

def _latest_metadata_location(metadata_prefix: str) -> str:
    """Resolve the current vN.metadata.json URL via version-hint.text.

    Called during LoadTable; read-only S3 op. materialize_all writes
    version-hint.text on every snapshot to make this cheap.
    """
    s3 = settings.s3
    import boto3
    from botocore.exceptions import ClientError
    c = boto3.client(
        "s3", endpoint_url=s3.endpoint, region_name=s3.region,
        aws_access_key_id=s3.root_access_key,
        aws_secret_access_key=s3.root_secret_key,
    )
    try:
        body = c.get_object(Bucket=s3.bucket, Key=f"{metadata_prefix}version-hint.text")["Body"].read()
        n = int(body.decode("utf-8").strip())
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in {"404", "NoSuchKey"}:
            n = 1
        else:
            raise
    return f"s3://{s3.bucket}/{metadata_prefix}v{n}.metadata.json"


def _wants_vended_credentials(header: str | None) -> bool:
    if not header:
        return False
    return any(
        token.strip().lower() == "vended-credentials"
        for token in header.split(",")
    )


def _base_s3_config() -> dict[str, str]:
    """Static S3 client config every Iceberg client gets, vended creds or not."""
    s3 = settings.s3
    cfg = {
        "s3.endpoint": s3.endpoint,
        "s3.region": s3.region,
        "s3.path-style-access": "true" if s3.path_style else "false",
        # DuckDB-style keys (the iceberg extension reads these as-is).
        "s3.url-style": "path" if s3.path_style else "vhost",
    }
    if not SUPPRESS_ROOT_CREDS:
        # Demo/dev convenience only — root keys in client hands make every
        # governance masking layer bypassable. Production sets
        # DUCKICELAKE_SUPPRESS_ROOT_CREDS=1 and clients rely on vended creds.
        cfg["s3.access-key-id"] = s3.root_access_key
        cfg["s3.secret-access-key"] = s3.root_secret_key
    return cfg


def _build_load_response(
    ns: list[str],
    table: str,
    properties: dict[str, str] | None = None,
    *,
    delegation_header: str | None = None,
    read_only: bool = True,
    snapshot_id_override: int | None = None,
    principal_claims: dict | None = None,
) -> LoadTableResponse:
    columns = catalog.get_columns(ns, table)
    uuid = catalog.table_uuid(ns, table)
    s3 = settings.s3
    table_prefix = s3.table_prefix(ns[0], table)
    loc = f"s3://{s3.bucket}/{table_prefix}".rstrip("/")
    metadata_prefix = f"{table_prefix}metadata/"
    # metadata-location always points at the LATEST vN.metadata.json —
    # resolved from version-hint.text (written by materialize_all on each
    # write). Non-REST readers (Hive-style) also look at version-hint
    # themselves; REST clients just follow this URI.
    metadata_location = _latest_metadata_location(metadata_prefix)

    base_metadata = build_table_metadata(
        table_uuid=uuid,
        location=loc,
        columns=columns,
        properties=properties,
    )

    # Materialise the full snapshot chain from DuckLake so clients see
    # history, stats, and position deletes.
    metadata = materialize_all(
        catalog=catalog,
        ns=ns,
        table=table,
        base_metadata=base_metadata,
        metadata_prefix=metadata_prefix,
    )

    # Time-travel: if the caller asked for a specific snapshot via
    # ?snapshot-id=N, pin current-snapshot-id to that (it must be one we
    # materialised).
    if snapshot_id_override is not None:
        if not any(s["snapshot-id"] == snapshot_id_override for s in metadata.get("snapshots", [])):
            raise HTTPException(
                status_code=400,
                detail=f"Unknown snapshot-id for {ns[0]}.{table}: {snapshot_id_override}",
            )
        metadata = dict(metadata)
        metadata["current-snapshot-id"] = snapshot_id_override
        metadata["refs"] = {"main": {"type": "branch", "snapshot-id": snapshot_id_override}}

    # ---- Phase 2 governance enforcement (read path only) ----
    # When the caller supplied principal claims (the GET LoadTable path),
    # consult the policy engine and stamp the returned metadata with the
    # per-principal masking / row-filter signals. No-op when nothing is
    # governed. Wrapped defensively: governance must never break a read.
    principal_for_creds: str | None = None
    if principal_claims is not None:
        principal_for_creds = principal_claims.get("sub") or "anonymous"
        try:
            # Roles are the UNION of the JWT claim (operator-configured via
            # DUCKICELAKE_OAUTH_CLIENTS) and the sidecar role grants — either
            # source can carry an unmasked-role bypass.
            roles = sorted(
                set(principal_claims.get("roles") or [])
                | set(governance_store.roles_for_principal(principal_for_creds))
            )
            plan = policy_engine.plan_for(
                principal=principal_for_creds,
                roles=roles,
                schema=ns[0], table=table,
            )
            if not plan.is_empty():
                metadata = apply_plan_to_metadata(metadata, plan)
                # Phase 3: materialize the plan's masking view so cooperative
                # clients (DuckLake-direct, view-capable REST engines) can
                # execute the mask; advertise it via a table property.
                view_name = masking_view_manager.ensure_view_for_plan(
                    ns, table, plan
                )
                if view_name:
                    metadata["properties"]["duckicelake.masking-view-name"] = view_name
                governance_store.audit_load(
                    principal=principal_for_creds, object_=f"{ns[0]}.{table}",
                    masked_cols=plan.masked_columns,
                    applied_policies=plan.applied_policies,
                    row_filtered=plan.row_filter is not None,
                )
        except Exception:
            log.exception("governance enforcement failed for %s.%s — serving unmasked",
                          ns[0], table)

    config_out: dict[str, str] = _base_s3_config()
    if _wants_vended_credentials(delegation_header):
        snap = metadata.get("current-snapshot-id") or 0
        # Vended creds must cover *everything* a client may do with this
        # table during the token's lifetime. The Iceberg REST spec doesn't
        # distinguish read vs write at vending time — the same header
        # `X-Iceberg-Access-Delegation: vended-credentials` is sent on
        # both GET LoadTable (reader) and POST CreateTable / commit
        # (writer). PyIceberg fetches creds via LoadTable then uses them
        # for subsequent writes. So we always vend write-capable creds
        # here. RBAC (per-token capability scoping) is the right way to
        # restrict this and is on the to-do list.
        data_files = catalog.data_files_at(ns, table, snap)
        delete_files = catalog.delete_files_at(ns, table, snap)
        allow_uris = [f.file_path for f in data_files] + [f.file_path for f in delete_files]
        allow_uris.append(f"s3://{s3.bucket}/{metadata_prefix}*")
        creds = vend_credentials(
            s3,
            namespace=ns[0],
            table=table,
            read_only=False,           # see comment above
            data_file_uris=allow_uris,
            principal=principal_for_creds,
        )
        config_out.update(
            {
                "s3.access-key-id": creds.access_key_id,
                "s3.secret-access-key": creds.secret_access_key,
                "s3.session-token": creds.session_token,
                "s3.remote-signing-enabled": "false",
                "s3.credentials-expiration": creds.expiration_iso,
            }
        )

    return LoadTableResponse(
        metadata_location=metadata_location,
        metadata=metadata,
        config=config_out,
    )
