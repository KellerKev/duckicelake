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
from datetime import datetime, timedelta, timezone
from typing import Any

import duckdb
from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse

from .auth import (
    AuthConfig,
    is_admin_scope,
    load_auth_config,
    make_bearer_dependency,
    oauth_token_endpoint,
)
from .auth import claims_from_request
from .catalog import DuckLakeCatalog
from .registry import CatalogContext, CatalogRegistry, UnknownCatalog
from .config import apply_file_config, load_settings, redact_password
from .governance import GovernanceStore
from .masked_export import MaskedExportManager
from .masking_views import (
    MASK_SCHEMA_PREFIX,
    MASK_VIEW_PREFIX,
    MaskingViewManager,
)
from .governance_api import build_governance_router
from .pg_rls import (
    ensure_rls,
    gc_expired_roles,
    provision_principal_role,
    rearm_rls_if_needed,
)
from .policies import PolicyEngine, _masked_projection, apply_plan_to_metadata, mask_signature
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
    S3_SIGN_TOTAL,
    metrics_endpoint as _metrics_endpoint,
    metrics_middleware,
    setup_logging,
)
from . import signer as signer_mod
from .signer import S3SignRequest, S3SignResponse
from .sts import vend_credentials


# File-based config (.env / duckicelake.toml) must be in os.environ before
# anything reads DUCKICELAKE_* — including setup_logging (LOG_FORMAT/LEVEL).
apply_file_config()

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
auth_cfg: AuthConfig = load_auth_config()
require_bearer = make_bearer_dependency(auth_cfg)

if settings.s3.sts_disabled:
    log.info(
        "STS disabled (DUCKICELAKE_STS_ENDPOINT=none): REST clients get "
        "remote signing via /v1/{prefix}/aws/s3/sign; DuckLake-direct "
        "clients need registered static keys + generated bucket policies "
        "(python -m duckicelake.hetzner_policy).")
    if not settings.suppress_root_creds:
        log.warning(
            "STS is disabled AND suppress_root_creds=0 — ducklake-"
            "credentials will fall back to handing ROOT S3 keys to "
            "principals without a registered static key. This bypasses "
            "all storage-layer governance. Dev only; never production.")

# Multi-catalog registry. Each isolated catalog (account-scoped) gets its own
# DuckLakeCatalog + governance managers, bundled in a CatalogContext and
# resolved per request from the Iceberg REST {prefix}. The default catalog
# (settings.catalog_name) is pre-registered; the module-level names below alias
# its members so background components (the notify listener) and helpers that
# aren't yet per-catalog keep operating on the default catalog unchanged.
registry = CatalogRegistry(settings)
_default_ctx = registry.register_default()
catalog = _default_ctx.catalog
governance_store = _default_ctx.store
policy_engine = _default_ctx.policy_engine
masking_view_manager = _default_ctx.masking_view_manager
masked_export_manager = _default_ctx.masked_export_manager

#: Set True once lifespan `ensure_rls` succeeds. When `rls_enabled` is on
#: but this stays False (RLS DDL failed at startup), ducklake-credentials
#: fails CLOSED — it refuses to vend rather than hand out the owning,
#: RLS-bypassing DSN.
_rls_ready = False


#: Table-property namespace reserved for proxy-stamped governance state
#: (masking signals, the file-layer RLS interlock, format-version). Client
#: commits must not write here — a write token could otherwise flip off
#: `duckicelake.file-layer-masking` and disable RLS file-hiding, or forge
#: masking signals. Set these out-of-band (governance authoring / ops).
_RESERVED_PROPERTY_PREFIX = "duckicelake."


def _reject_reserved_table_name(name: str) -> None:
    """Tables/views named like a masking view (`__mask_*`) collide with
    governance plumbing: they'd be hidden from REST listings and swept by
    gc_orphans as 'stale masking views'. Reject at every creation/rename
    entry point."""
    if name.startswith(MASK_VIEW_PREFIX):
        raise HTTPException(
            status_code=400,
            detail=f"Names starting with '{MASK_VIEW_PREFIX}' are reserved "
                   "for governance masking views",
        )


def _reject_reserved_property_keys(keys) -> None:
    bad = sorted(k for k in keys if k.startswith(_RESERVED_PROPERTY_PREFIX))
    if bad:
        raise HTTPException(
            status_code=403,
            detail=(f"property keys under '{_RESERVED_PROPERTY_PREFIX}' are "
                    f"reserved for governance and cannot be set via commit: "
                    f"{', '.join(bad)}"),
        )


def _audit_credentials_denied(ctx: "CatalogContext", sub: str, ns: list[str],
                              table: str | None, decision: str) -> None:
    """Best-effort audit of a fail-closed credential denial."""
    try:
        ctx.store.audit_load(
            principal=sub, object_=f"{ns[0]}.{table or '*'}",
            masked_cols=[], applied_policies=[], row_filtered=False,
            operation="ducklake_credentials", decision=decision, detail={})
    except Exception:
        log.exception("audit of credential denial failed")


def _ensure_file_layer_properties(ctx: "CatalogContext", ns: list[str], table: str, plan) -> None:
    """Write the Phase-3a interlock properties so RLS hides base file rows
    from non-bypass principals. Best-effort — the masked-prefix credential
    scope is the primary enforcement; RLS is defense-in-depth."""
    try:
        bypass = ctx.policy_engine.file_layer_bypass_roles(plan)
        ctx.catalog.upsert_table_properties(ns, table, set_map={
            "duckicelake.file-layer-masking": "true",
            "duckicelake.file-layer-bypass-roles": ",".join(bypass),
        })
        ctx.catalog.invalidate_metadata_cache(ns, table)
    except Exception:
        log.exception("file-layer property stamping failed for %s.%s",
                      ns[0], table)


def _stamped_file_layer(catalog_obj, ns: list[str], table: str | None) -> bool:
    """Is the table stamped `duckicelake.file-layer-masking`?

    Consulted when governance PLANNING itself throws (roles fetch / plan_for
    on a PG hiccup): the fail-open except would otherwise leave
    `file_layer_required` False and skip the airtight-tier deny — serving
    base bytes for a file-layer table. Errs on the safe side: if even the
    property read fails, treat the table as file-layer (deny). The stamp is
    reserved (clients cannot set/clear `duckicelake.*` keys) and maintained
    by `_ensure_file_layer_properties`."""
    if table is None:
        return False
    try:
        props = catalog_obj.get_table_properties(ns, table)
        return props.get("duckicelake.file-layer-masking") == "true"
    except Exception:
        log.exception("cannot read file-layer stamp for %s.%s — "
                      "assuming file-layer (fail closed)", ns[0], table)
        return True


def _file_layer_deny_prefixes(ctx: "CatalogContext", ns: list[str], roles: list[str]) -> list[str] | None:
    """For namespace-level vending: base prefixes of file-layer tables the
    principal is masked on (Deny beats the namespace Allow). Enumerates
    *every* table in the namespace — not just already-exported ones — so a
    file-layer table that no principal has materialized yet is still carved
    out (its base bytes must never be vended raw). `roles` is the caller's
    already-resolved JWT∪sidecar union. Returns None when there's simply
    nothing to deny; **raises** on any error so the caller fails CLOSED
    (we must never vend a namespace-wide grant we couldn't fully scope)."""
    tables = [t for (_s, t) in ctx.catalog.list_tables(ns)]
    deny: list[str] = []
    for t in tables:
        plan = ctx.policy_engine.plan_for(principal="__deny_probe__",
                                          roles=roles, schema=ns[0], table=t)
        if plan.file_layer and not plan.is_empty():
            deny.append(settings.s3.table_prefix(ns[0], t, ctx.ref.data_prefix))
    return deny or None


# Root-key suppression + transparent masking live on Settings
# (config.py) so they're configurable via env, .env, or duckicelake.toml.
# Suppression defaults ON: with root keys in client hands, the governance
# masking layer is bypassable in one line.

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
    registry.ensure_table()
    log.info("DuckLake catalog connected: %s",
             redact_password(settings.ducklake_uri))
    # Phase 3a: reader role + RLS on the ducklake_* catalog tables for
    # vended DuckLake-direct credentials. An RLS setup error never stops
    # the proxy, but it does arm the fail-CLOSED gate: if RLS isn't ready,
    # ducklake-credentials refuses to vend rather than handing out the
    # owning (RLS-bypassing) DSN.
    global _rls_ready
    if settings.rls_enabled:
        try:
            ensure_rls(catalog, settings)
            _rls_ready = True
        except Exception:
            log.exception("RLS setup failed — ducklake-credentials will "
                          "REFUSE to vend (fail-closed) until RLS is armed")
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
        # Closes every cached catalog context — the default (module
        # `catalog`) plus any lazily-attached per-account catalogs.
        registry.close_all()


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
    if path.endswith("/aws/s3/sign"):
        # Remote-signer requests: AUTHN only. The scope gate below keys on
        # the HTTP method (always POST here), but read-vs-write is decided
        # by the *S3* method inside the body — a read-only `ns:x:r` token
        # must be able to POST sign requests for GETs. The signer endpoint
        # does its own per-object, per-S3-method authorization.
        try:
            from .auth import verify_bearer
            verify_bearer(auth_cfg, request.headers.get("authorization"))
        except HTTPException as e:
            return _iceberg_error(
                e.status_code, str(e.detail), "UnauthorizedException")
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


# ---- governance layer -------------------------------------------------
# Authoring surface + audit. Additive: mounted as its own router so the core
# Iceberg REST surface above is untouched. Enforcement lives on the read
# paths (policies.py / masking_views.py / masked_export.py / pg_rls.py).

def _resync_table_governance(ctx: "CatalogContext", ns: list[str], table: str) -> None:
    """Detaching a policy / untagging changes a table's policy set, so its
    masking views + pre-masked exports are now stale and the file-layer
    interlock properties may no longer apply. Drop them (best-effort) — the
    next masked read recreates whatever is still needed and re-stamps the
    properties; if nothing's masked anymore the table is simply clean."""
    try:
        ctx.masking_view_manager.gc_orphans(ns, table, keep=set())
    except Exception:
        log.exception("resync: view gc failed for %s.%s", ns[0], table)
    try:
        ctx.masked_export_manager.gc_table(ns, table, keep=set())
    except Exception:
        log.exception("resync: export gc failed for %s.%s", ns[0], table)
    try:
        ctx.catalog.upsert_table_properties(ns, table, remove=[
            "duckicelake.file-layer-masking",
            "duckicelake.file-layer-bypass-roles"])
        ctx.catalog.invalidate_metadata_cache(ns, table)
    except Exception:
        log.exception("resync: property clear failed for %s.%s", ns[0], table)


# The governance router is bound to the default catalog (per-catalog governance
# authoring lands with the account-scoped decision API); its resync callback
# operates on the default context.
app.include_router(build_governance_router(
    catalog, settings, auth_cfg,
    on_table_policy_change=lambda ns, table: _resync_table_governance(_default_ctx, ns, table)))


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
    # --- governance authoring layer ---
    "POST /v1/{prefix}/governance/tags",
    "DELETE /v1/{prefix}/governance/tags/{ns}/{name}",
    "POST /v1/{prefix}/governance/object-tags",
    "DELETE /v1/{prefix}/governance/object-tags",
    "POST /v1/{prefix}/governance/masking-policies",
    "DELETE /v1/{prefix}/governance/masking-policies/{name}",
    "POST /v1/{prefix}/governance/row-access-policies",
    "DELETE /v1/{prefix}/governance/row-access-policies/{name}",
    "POST /v1/{prefix}/governance/policy-attachments",
    "DELETE /v1/{prefix}/governance/policy-attachments",
    "POST /v1/{prefix}/governance/roles",
    "DELETE /v1/{prefix}/governance/roles/{name}",
    "POST /v1/{prefix}/governance/role-grants",
    "DELETE /v1/{prefix}/governance/role-grants",
    "POST /v1/{prefix}/governance/object-grants",
    "DELETE /v1/{prefix}/governance/object-grants",
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
def get_config(request: Request, warehouse: str | None = None) -> ConfigResponse:
    # Many Iceberg clients use a "prefix" in the URL to scope requests to a
    # specific warehouse. We return the catalog name so paths become
    # /v1/<catalog>/namespaces/... A client that asks for a provisioned
    # (non-default) warehouse gets ITS prefix back — same resolution +
    # account authorization as every /v1/{prefix}/ route. Anything that
    # doesn't resolve (or isn't the caller's) falls back to the DEFAULT
    # prefix, never a 404: clients send OPAQUE warehouse hints here (the
    # DuckDB iceberg ext passes its ATTACH string, e.g. the bucket name),
    # and unknown-vs-unauthorized must stay indistinguishable anyway.
    prefix = settings.catalog_name
    if warehouse and warehouse != settings.catalog_name:
        try:
            prefix = resolve_catalog(warehouse, request).catalog_id
        except HTTPException:
            prefix = settings.catalog_name
    return ConfigResponse(
        defaults={
            "warehouse": warehouse or settings.catalog_name,
        },
        overrides={
            "prefix": prefix,
        },
        endpoints=SUPPORTED_ENDPOINTS,
    )


# ---- catalog provisioning (qod integration) ----------------------------
# Registers an isolated catalog: its own Postgres METADATA_SCHEMA + S3
# data_prefix. Called by the orchestration layer when an account/catalog is
# created. The (metadata_schema, data_prefix) names are derived + validated
# upstream by the orchestration layer's naming contract; here they are trusted.
# Control-plane op: gated behind an admin-scope token (_require_admin).

def _require_admin(request: Request) -> None:
    """Provisioning is a control-plane operation — require a superuser-scope
    token (`*` / `*:*:*`) when auth is enabled. Dev (auth off) passes, same
    as every other endpoint."""
    if not auth_cfg.enabled:
        return
    claims = claims_from_request(auth_cfg, request)
    if not is_admin_scope(claims.get("scope", "")):
        raise HTTPException(
            status_code=403,
            detail="catalog provisioning requires an admin-scoped token")


class ProvisionCatalogRequest(BaseModel):
    catalog_id: str = Field(..., description="Iceberg REST {prefix} for this catalog")
    metadata_schema: str
    data_prefix: str
    account_id: str | None = None
    create_default_namespace: bool = True


class CatalogInfo(BaseModel):
    catalog_id: str
    metadata_schema: str
    data_prefix: str


@app.post("/v1/catalogs", response_model=CatalogInfo, status_code=201)
def provision_catalog(req: ProvisionCatalogRequest, request: Request) -> CatalogInfo:
    _require_admin(request)
    ctx = registry.provision(
        req.catalog_id, req.metadata_schema, req.data_prefix, req.account_id
    )
    if req.create_default_namespace and not ctx.catalog.namespace_exists(["default"]):
        ctx.catalog.create_namespace(["default"])
    return CatalogInfo(
        catalog_id=ctx.catalog_id,
        metadata_schema=ctx.ref.metadata_schema or "",
        data_prefix=ctx.ref.data_prefix,
    )


# ---- namespaces --------------------------------------------------------

def resolve_catalog(prefix: str, request: Request) -> CatalogContext:
    """FastAPI dependency: resolve the Iceberg REST {prefix} to its isolated
    catalog context (the default catalog or a provisioned per-account one).
    404 if the prefix has no registered catalog OR the caller's account may
    not reach it — same status so an outsider can't probe which catalog ids
    exist. Handlers that depend on this rebind their local `catalog`/managers
    to the resolved context."""
    try:
        ctx = registry.get(prefix)
    except UnknownCatalog:
        raise HTTPException(status_code=404, detail=f"Unknown catalog prefix '{prefix}'")
    # Account → catalog authorization (the REST-layer hard tenant boundary;
    # per-catalog PG reader roles + disjoint S3 prefixes back it below).
    # Enforced only when auth is on. Unowned catalogs (account_id NULL —
    # incl. the default) stay reachable to every authenticated caller;
    # admin-scope tokens reach everything.
    if auth_cfg.enabled and ctx.account_id is not None:
        claims = claims_from_request(auth_cfg, request)
        if (claims.get("account") != ctx.account_id
                and not is_admin_scope(claims.get("scope", ""))):
            raise HTTPException(
                status_code=404, detail=f"Unknown catalog prefix '{prefix}'")
    return ctx


@app.get("/v1/{prefix}/namespaces", response_model=ListNamespacesResponse)
def list_namespaces(
    prefix: str, parent: str | None = None,
    ctx: CatalogContext = Depends(resolve_catalog),
) -> ListNamespacesResponse:
    catalog = ctx.catalog
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
    prefix: str, req: CreateNamespaceRequest,
    ctx: CatalogContext = Depends(resolve_catalog),
) -> CreateNamespaceResponse:
    catalog = ctx.catalog
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
def get_namespace(
    prefix: str, namespace: str,
    ctx: CatalogContext = Depends(resolve_catalog),
) -> GetNamespaceResponse:
    catalog = ctx.catalog
    ns = _parse_namespace(namespace)
    if not catalog.namespace_exists(ns):
        raise HTTPException(status_code=404, detail=f"Namespace does not exist: {ns}")
    return GetNamespaceResponse(namespace=ns, properties={})


@app.head("/v1/{prefix}/namespaces/{namespace}")
def head_namespace(
    prefix: str, namespace: str,
    ctx: CatalogContext = Depends(resolve_catalog),
):
    catalog = ctx.catalog
    ns = _parse_namespace(namespace)
    if not catalog.namespace_exists(ns):
        raise HTTPException(status_code=404, detail=f"Namespace does not exist: {ns}")
    return Response(status_code=204)


@app.delete("/v1/{prefix}/namespaces/{namespace}", status_code=204)
def drop_namespace(
    prefix: str, namespace: str,
    ctx: CatalogContext = Depends(resolve_catalog),
):
    catalog = ctx.catalog
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
def list_tables(
    prefix: str, namespace: str,
    ctx: CatalogContext = Depends(resolve_catalog),
) -> ListTablesResponse:
    catalog = ctx.catalog
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
    request: Request,
    x_iceberg_access_delegation: str | None = Header(default=None),
    ctx: CatalogContext = Depends(resolve_catalog),
) -> LoadTableResponse:
    catalog = ctx.catalog
    ns = _parse_namespace(namespace)
    if not catalog.namespace_exists(ns):
        raise HTTPException(status_code=404, detail=f"Namespace does not exist: {ns}")
    _reject_reserved_table_name(req.name)
    if catalog.table_exists(ns, req.name):
        raise HTTPException(
            status_code=409,
            detail=f"Table already exists: {ns}.{req.name}",
        )
    if req.stage_create:
        raise HTTPException(status_code=501, detail="stage-create is not supported")

    ddl, _last_id = schema_to_columns_ddl(req.schema_)
    catalog.create_table(ns, req.name, ddl)
    # RLS rearm covers new ducklake_* tables for the default catalog. Per-catalog
    # RLS is armed by the credentials path (P1c-B); skip here for non-default.
    if settings.rls_enabled and _rls_ready and ctx.catalog_id == settings.catalog_name:
        rearm_rls_if_needed(catalog, settings)
    return _build_load_response(
        ctx, ns, req.name,
        properties=req.properties,
        delegation_header=x_iceberg_access_delegation,
        read_only=False,
        request=request,
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
    ctx: CatalogContext = Depends(resolve_catalog),
) -> LoadTableResponse:
    catalog = ctx.catalog
    ns = _parse_namespace(namespace)
    if not catalog.table_exists(ns, table):
        raise HTTPException(
            status_code=404, detail=f"Table does not exist: {ns}.{table}"
        )
    return _build_load_response(
        ctx, ns, table,
        delegation_header=x_iceberg_access_delegation,
        read_only=True,
        snapshot_id_override=snapshot_id,
        principal_claims=claims_from_request(auth_cfg, request),
        request=request,
    )


@app.head("/v1/{prefix}/namespaces/{namespace}/tables/{table}")
def head_table(
    prefix: str, namespace: str, table: str,
    ctx: CatalogContext = Depends(resolve_catalog),
):
    catalog = ctx.catalog
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
    prefix: str, namespace: str, table: str, purgeRequested: bool = False,
    ctx: CatalogContext = Depends(resolve_catalog),
):
    """DROP TABLE. When `purgeRequested=true`, also delete every S3 object
    under the table's prefix — Parquet data files, delete files, manifest
    Avros, metadata JSONs. Without purge, DuckLake's own
    `ducklake_cleanup_old_files` eventually reclaims tombstoned data files;
    the metadata Avros become orphans unless purged."""
    catalog = ctx.catalog
    ns = _parse_namespace(namespace)
    if not catalog.table_exists(ns, table):
        raise HTTPException(
            status_code=404, detail=f"Table does not exist: {ns}.{table}"
        )
    catalog.drop_table(ns, table)
    catalog.invalidate_metadata_cache(ns, table)
    # Purge the table's governance rows (tags / attachments / grants) so a
    # later table reusing the name can't silently inherit a stale mask, and
    # resync to drop its masking views/exports/props. Always — governance
    # rows orphan on any drop, not only a purge-requested one.
    ctx.store.purge_table_governance(None, schema=ns[0], table=table)
    _resync_table_governance(ctx, ns, table)
    if purgeRequested:
        n = catalog.purge_table_objects(ns, table)
        log.info("purge %s.%s: %d S3 objects removed", ns[0], table, n)
        # file-layer masked exports live under a separate prefix
        ctx.masked_export_manager.purge_table(ns, table)
    return Response(status_code=204)


# ---- admin ------------------------------------------------------------

@app.post(
    "/v1/{prefix}/admin/namespaces/{namespace}/tables/{table}/compact",
    status_code=200,
)
def compact_table(
    prefix: str, namespace: str, table: str,
    ctx: CatalogContext = Depends(resolve_catalog),
) -> dict[str, Any]:
    """Trigger DuckLake compaction + file cleanup on a table.

    Safe to schedule on a cron — each call is idempotent and returns
    quickly when there's nothing to compact. Requires a token with
    write scope on the target namespace.
    """
    catalog = ctx.catalog
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
def list_views(
    prefix: str, namespace: str,
    ctx: CatalogContext = Depends(resolve_catalog),
) -> dict[str, Any]:
    catalog = ctx.catalog
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
def create_view(
    prefix: str, namespace: str, body: dict[str, Any],
    ctx: CatalogContext = Depends(resolve_catalog),
) -> dict[str, Any]:
    catalog = ctx.catalog
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
    return _build_view_response(ns, name, ctx)


@app.get("/v1/{prefix}/namespaces/{namespace}/views/{view}")
def load_view(
    prefix: str, namespace: str, view: str,
    ctx: CatalogContext = Depends(resolve_catalog),
) -> dict[str, Any]:
    catalog = ctx.catalog
    ns = _parse_namespace(namespace)
    if not catalog.view_exists(ns, view):
        raise HTTPException(status_code=404, detail=f"View does not exist: {ns}.{view}")
    return _build_view_response(ns, view, ctx)


@app.delete("/v1/{prefix}/namespaces/{namespace}/views/{view}", status_code=204)
def drop_view(
    prefix: str, namespace: str, view: str,
    ctx: CatalogContext = Depends(resolve_catalog),
):
    catalog = ctx.catalog
    ns = _parse_namespace(namespace)
    if not catalog.view_exists(ns, view):
        raise HTTPException(status_code=404, detail=f"View does not exist: {ns}.{view}")
    catalog.drop_view(ns, view)
    return Response(status_code=204)


def _build_view_response(ns: list[str], view: str, ctx: CatalogContext) -> dict[str, Any]:
    """Iceberg View metadata. SQL comes from information_schema.views;
    schema comes from information_schema.columns on the view itself —
    DuckDB resolves the view once so we get back concrete types."""
    catalog = ctx.catalog
    # Per-catalog S3 prefix for the view's advertised location.
    vp = f"{ctx.ref.data_prefix}{ns[0]}/{view}/"
    sql = catalog.get_view_definition(ns, view) or ""
    view_uuid = catalog.table_uuid(ns, view)
    # Concrete schema from information_schema.columns. Binding can fail
    # transiently (e.g. a just-materialized masking view racing the
    # listener, or a base-table change mid-flight) — the SQL representation
    # is the load-bearing part of a view response, so degrade to an empty
    # schema instead of failing the load.
    try:
        columns = catalog.get_columns(ns, view)
    except duckdb.Error:
        log.exception("view column resolution failed for %s.%s — "
                      "serving SQL representation with empty schema",
                      ns[0], view)
        columns = []
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
        "location": f"s3://{settings.s3.bucket}/{vp}".rstrip("/"),
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
        "metadata-location": f"s3://{settings.s3.bucket}/{vp}metadata/view.json",
        "metadata": md,
        "config": _base_s3_config(),
    }


# ---- Remote signing (no-STS backends, e.g. Hetzner) --------------------

def _handle_sign(ctx: "CatalogContext", req: S3SignRequest,
                 request: Request) -> S3SignResponse:
    """Shared body of the sign routes: authenticate, authorize the exact
    (S3 method, object) against governance, then SigV4-sign with root keys.
    Fail CLOSED on every deny — the signer is the airtight tier."""
    claims = claims_from_request(auth_cfg, request)
    parsed = signer_mod.parse_s3_uri(req.uri, settings.s3)
    if parsed is None:
        S3_SIGN_TOTAL.labels(decision="sign_denied_endpoint").inc()
        raise HTTPException(
            status_code=403,
            detail="refusing to sign a request for a foreign endpoint")
    bucket, key = parsed
    decision = signer_mod.authorize_sign(
        ctx, settings, claims, req.method, bucket, key)
    S3_SIGN_TOTAL.labels(decision=decision.reason).inc()
    if not decision.allowed:
        sub = claims.get("sub") or "anonymous"
        try:
            ctx.store.audit_load(
                principal=sub, object_=f"s3://{bucket}/{key}",
                masked_cols=[], applied_policies=[], row_filtered=False,
                operation="s3_sign", decision=decision.reason,
                detail={"method": req.method})
        except Exception:
            log.exception("audit of sign denial failed")
        raise HTTPException(
            status_code=403,
            detail=f"signing denied: {decision.reason}")
    return signer_mod.sign_v4(settings.s3, req.method, req.uri, req.headers)


@app.post("/v1/{prefix}/aws/s3/sign", response_model=S3SignResponse)
def sign_s3_request(
    prefix: str, req: S3SignRequest, request: Request,
    ctx: CatalogContext = Depends(resolve_catalog),
) -> S3SignResponse:
    """Iceberg REST remote signer (s3-signer-open-api.yaml). Emitted to
    clients as `s3.signer.endpoint` in no-STS mode; also useful against
    STS-capable backends for engines that prefer remote signing."""
    return _handle_sign(ctx, req, request)


@app.post("/v1/aws/s3/sign", response_model=S3SignResponse)
def sign_s3_request_default(req: S3SignRequest, request: Request) -> S3SignResponse:
    """Spec-default signer path (no {prefix}) for clients that ignore the
    emitted `s3.signer.endpoint`. Resolves the catalog by longest
    data-prefix match of the requested key; falls back to the default
    catalog. The account gate still runs via resolve_catalog."""
    target = registry.settings.catalog_name
    parsed = signer_mod.parse_s3_uri(req.uri, settings.s3)
    if parsed is not None:
        _, key = parsed
        best = ""
        for cid, ref in registry.list_refs():
            if ref.data_prefix and key.startswith(ref.data_prefix) \
                    and len(ref.data_prefix) > len(best):
                best, target = ref.data_prefix, cid
    ctx = resolve_catalog(target, request)
    return _handle_sign(ctx, req, request)


# ---- DuckLake-direct credentials (governance Phase 3) ------------------

def _arm_default_rls() -> bool:
    """True when the DEFAULT catalog's RLS is armed on this worker.

    Startup arms it once in lifespan; a worker that lost the (now
    advisory-lock-serialized) startup DDL race or hit a transient PG error
    must NOT 503 vends until restart — retry `ensure_rls` here (idempotent,
    cheap when already applied) and flip `_rls_ready` on success. This makes
    the default path self-heal the same way non-default catalogs do."""
    global _rls_ready
    if _rls_ready:
        rearm_rls_if_needed(catalog, settings)
        return True
    try:
        ensure_rls(catalog, settings)
        _rls_ready = True
        return True
    except Exception:
        log.exception("default-catalog RLS re-arm failed — still fail-closed")
        return False


@app.get("/v1/{prefix}/namespaces/{namespace}/ducklake-credentials")
def ducklake_credentials(
    prefix: str,
    namespace: str,
    request: Request,
    table: str | None = None,
    duration_seconds: int = 3600,
    principal: str | None = None,
    ctx: CatalogContext = Depends(resolve_catalog),
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
    here is cooperative-client masking: a client that queries the base
    table directly still reads cleartext (file-layer masking is the
    airtight tier).
    """
    catalog = ctx.catalog
    governance_store = ctx.store
    policy_engine = ctx.policy_engine
    masking_view_manager = ctx.masking_view_manager
    masked_export_manager = ctx.masked_export_manager
    ns = _parse_namespace(namespace)
    if not catalog.namespace_exists(ns):
        raise HTTPException(status_code=404, detail=f"Namespace does not exist: {ns}")
    if table is not None and not catalog.table_exists(ns, table):
        raise HTTPException(status_code=404, detail=f"Table does not exist: {ns}.{table}")

    claims = claims_from_request(auth_cfg, request)
    sub = claims.get("sub") or "anonymous"
    if principal and not auth_cfg.enabled:
        sub = principal

    # Per-catalog ATTACH: alias = the catalog id, DATA_PATH = the catalog's S3
    # prefix, and METADATA_SCHEMA so the client's ducklake_* resolve to THIS
    # catalog's isolated metadata (omitted for the default catalog).
    alias = ctx.catalog_id
    data_path = settings.data_path_for(ctx.ref)
    meta_opt = (f", METADATA_SCHEMA '{ctx.ref.metadata_schema}'"
                if ctx.ref.metadata_schema else "")
    # Upper bound from config (default 43200 = the AWS absolute max). Note
    # AWS additionally REJECTS durations above the role's MaxSessionDuration
    # rather than clamping like MinIO — sts.py retries once at 3600 on that.
    clamped = max(900, min(settings.s3.sts_max_duration, duration_seconds))
    out: dict[str, Any] = {
        "ducklake_dsn": settings.pg_dsn,
        "ducklake_data_path": data_path,
        "ducklake_attach_sql": (
            f"ATTACH '{settings.ducklake_uri}' AS {alias} "
            f"(DATA_PATH '{data_path}'{meta_opt})"
        ),
        "post_attach_sql": [],
        "masked_view": None,
        "mask_signature": None,
        "transparent": False,
        "file_layer": False,
        "pg_role": None,
        "pg_valid_until": None,
        # Governed distributed-scan spec (?table only): a map-reduce reader that
        # scans Parquet file subsets in parallel must NOT bypass masking. For the
        # cooperative/view tier we vend the masked projection + row filter to
        # apply over read_parquet; for the airtight file tier we vend the
        # pre-masked export files to read directly (base bytes stay denied).
        "mask_projection": None,   # SELECT list to apply over read_parquet, or null
        "row_filter": None,        # WHERE predicate to apply, or null
        "scan_files": None,        # explicit file list (file-layer export), or null
    }

    # Phase 3a: vend a per-principal RLS-governed reader role instead of
    # the owning DSN. FAIL CLOSED: when RLS is enabled but isn't armed
    # (startup DDL failed) or the reader role can't be provisioned, we
    # refuse — handing out the owning (RLS-bypassing) DSN would expose the
    # whole catalog. Only when rls_enabled is False (operator opt-out, dev)
    # do we vend the owner DSN by design.
    reader_dsn_ok = False
    is_default = ctx.catalog_id == settings.catalog_name
    if settings.rls_enabled:
        # Arm RLS for THIS catalog. The default catalog is armed at startup
        # and self-heals here if that failed (_arm_default_rls); a per-account
        # catalog is armed lazily on its first vend (ensure_rls is
        # idempotent). FAIL CLOSED if arming fails — vending the owning DSN
        # would bypass RLS and expose the catalog.
        armed = False
        if is_default:
            armed = _arm_default_rls()
        else:
            try:
                ensure_rls(catalog, settings)
                armed = True
            except Exception:
                log.exception("per-catalog RLS arming failed for %s", ctx.catalog_id)
        if not armed:
            _audit_credentials_denied(ctx, sub, ns, table, "error_rls_not_armed")
            raise HTTPException(
                status_code=503,
                detail="row-level security is not armed; refusing to vend "
                       "DuckLake credentials (fail-closed)")
        try:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=clamped)
            pg_role, pg_password = provision_principal_role(
                catalog, settings, sub, expires_at)
            reader_dsn = settings.pg_dsn_for(pg_role, pg_password)
            out["ducklake_dsn"] = reader_dsn
            out["ducklake_attach_sql"] = (
                f"ATTACH 'ducklake:postgres:{reader_dsn}' AS {alias} "
                f"(DATA_PATH '{data_path}'{meta_opt}, READ_ONLY)"
            )
            out["pg_role"] = pg_role
            out["pg_valid_until"] = expires_at.isoformat()
            reader_dsn_ok = True
            gc_expired_roles(catalog)
        except Exception:
            log.exception("reader-role provisioning failed for %s — refusing "
                          "to vend the owner DSN (fail-closed)", sub)
            _audit_credentials_denied(ctx, sub, ns, table, "error_reader_role_failed")
            raise HTTPException(
                status_code=503,
                detail="could not provision an RLS reader role; refusing to "
                       "vend (fail-closed)")

    decision = "ok"
    masked_cols: list[str] = []
    applied: list[str] = []
    row_filtered = False
    export = None
    file_layer_required = False
    roles: list[str] = list(claims.get("roles") or [])
    try:
        roles = sorted(
            set(roles)
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
                file_layer_required = plan.file_layer
                if plan.file_layer:
                    # Phase 4: materialize (or reuse) the masked Parquet
                    # export; on failure fall back to a possibly-stale
                    # pointer (still masked, one snapshot behind), then to
                    # catalog-level masking.
                    export = (
                        masked_export_manager.ensure_export_for_plan(
                            ns, table, plan)
                        or masked_export_manager.current_export(
                            ns, table, mask_signature(plan))
                    )
                view = masking_view_manager.ensure_view_for_plan(
                    ns, table, plan, export=export)
                # Governed distributed-scan spec: file-layer -> the pre-masked
                # export files (base bytes stay S3-denied); view/cooperative tier
                # -> the masked projection + row filter to apply over read_parquet.
                if plan.file_layer:
                    if export is not None:
                        out["scan_files"] = [
                            f"s3://{settings.s3.bucket}/{k}"
                            for k, _ in masked_export_manager.list_export_files(export.prefix)
                        ]
                else:
                    _masks = {m.column: m.mask_expr for m in plan.masks}
                    out["mask_projection"] = (
                        _masked_projection(plan.columns, _masks) if _masks else None)
                    out["row_filter"] = plan.row_filter
                if view:
                    decision = "masked_file_layer" if export else "masked"
                    out["masked_view"] = f"{ns[0]}.{view}"
                    out["mask_signature"] = mask_signature(plan)
                    out["file_layer"] = export is not None
                    if export is not None:
                        _ensure_file_layer_properties(ctx, ns, table, plan)
                    if settings.transparent_masking:
                        schema = masking_view_manager.ensure_transparent_schema(
                            ns, table, plan, export=export,
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
        else:
            # Catalog-wide transparent masking: a DuckLake-direct ATTACH is
            # catalog-wide, so mask EVERY view-tier-policied table in the
            # namespace and route them all through one search_path. Unqualified
            # refs in arbitrary / multi-table queries then resolve to masked
            # views — the whole-namespace analogue of ?table, so the single-node
            # reader (which can't name one table) no longer reads cleartext.
            # File-layer tables are skipped here; their base bytes stay S3-denied
            # below (airtight), so omitting their view can't leak.
            schemas: list[str] = []
            for _, tbl in catalog.list_tables(ns):
                tplan = policy_engine.plan_for(
                    principal=sub, roles=roles, schema=ns[0], table=tbl)
                if tplan.is_empty() or tplan.file_layer:
                    continue
                if masking_view_manager.ensure_view_for_plan(ns, tbl, tplan) is None:
                    continue
                sch = masking_view_manager.ensure_transparent_schema(ns, tbl, tplan)
                if sch and sch not in schemas:
                    schemas.append(sch)
                masked_cols.extend(tplan.masked_columns)
                applied.extend(tplan.applied_policies)
            if schemas and settings.transparent_masking:
                out["transparent"] = True
                out["post_attach_sql"] = [
                    "SET search_path = '"
                    + ",".join(f"{alias}.{s}" for s in schemas)
                    + f",{alias}.{ns[0]}'"
                ]
                decision = "masked"
    except Exception:
        log.exception("ducklake-credentials governance failed for %s.%s — "
                      "fail-open only for the cooperative tier", ns[0], table)
        decision = "error_unmasked"
        # B3: planning failed pre-classification — consult the reserved
        # property stamp so a file-layer table still hits the deny below.
        file_layer_required = (
            file_layer_required or _stamped_file_layer(catalog, ns, table))

    # FAIL CLOSED: a file-layer-masked principal whose export couldn't be
    # materialized must not be vended base-prefix creds. Refuse.
    if file_layer_required and export is None:
        _audit_credentials_denied(ctx, sub, ns, table, "error_file_layer_denied")
        raise HTTPException(
            status_code=503,
            detail=(f"file-layer masking for {ns[0]}.{table} could not be "
                    f"materialized; refusing to vend base credentials"))

    # Strict mode (DUCKICELAKE_GOVERNANCE_FAIL_CLOSED=1): the COOPERATIVE
    # tier also fails closed. `error_unmasked` marks both failure shapes —
    # planning threw, or the plan demanded masking and no view materialized.
    if settings.governance_fail_closed and decision == "error_unmasked":
        _audit_credentials_denied(ctx, sub, ns, table, "error_governance_denied")
        raise HTTPException(
            status_code=503,
            detail=(f"governance enforcement for {ns[0]}.{table} failed and "
                    "this deployment is configured fail-closed "
                    "(DUCKICELAKE_GOVERNANCE_FAIL_CLOSED); refusing to vend"))

    s3 = settings.s3
    deny_prefixes: list[str] | None = None
    if table is not None:
        if export is not None:
            # file-layer: ONLY the masked sig prefix — base bytes are
            # physically unreadable with these credentials. Key on the
            # export's own sig (not out["mask_signature"], which is only
            # set when the view also materialized) so a view-creation
            # failure can't scope creds to a `.../None/` prefix.
            read_prefixes = [s3.masked_sig_prefix(ns[0], table, export.sig, ctx.ref.data_prefix)]
        else:
            read_prefixes = [s3.table_prefix(ns[0], table, ctx.ref.data_prefix)]
    elif not ctx.policy_engine.store.has_file_layer_policies():
        # No specific table AND no file-layer masking anywhere in the catalog
        # (the common case): a DuckLake-direct ATTACH is CATALOG-wide, so scope
        # reads to the whole catalog data prefix. The catalog (account) is the
        # S3 isolation boundary, not the namespace — scoping to one namespace
        # silently 403s any query whose tables live in a different schema
        # (e.g. a wrong default namespace, or a cross-schema JOIN). No carve-out
        # scan needed (nothing is file-layer masked). Per-table least-privilege
        # is still available via ?table=.
        read_prefixes = [ctx.ref.data_prefix]
    else:
        # File-layer masking exists in this catalog: keep the tighter
        # per-namespace scope so a masked table's base bytes can't be read raw
        # via a catalog-wide grant. Carve out the file-layer-masked tables in
        # THIS namespace (fail-closed). Cross-namespace reads here require
        # vending for the right namespace (or ?table=).
        read_prefixes = [f"{ctx.ref.data_prefix}{ns[0]}/"]
        try:
            deny_prefixes = _file_layer_deny_prefixes(ctx, ns, roles)
        except Exception:
            log.exception("file-layer deny-prefix scan failed for %s — "
                          "refusing namespace-wide vend (fail-closed)", ns[0])
            _audit_credentials_denied(ctx, sub, ns, None, "error_deny_scan_failed")
            raise HTTPException(
                status_code=503,
                detail="could not compute file-layer credential carve-outs; "
                       "refusing namespace-wide vend (fail-closed)")
    sts_degraded = False
    if s3.sts_disabled:
        # No STS on this backend (Hetzner): DuckLake-direct clients can't
        # remote-sign (DuckDB httpfs), so the compensation tier is a
        # per-principal STATIC key scoped server-side by a generated bucket
        # policy (python -m duckicelake.hetzner_policy). The proxy vends
        # the key id (+ secret only when the operator opted into storing
        # it); enforcement lives in the bucket policy, not a session policy.
        masked_principal = export is not None or file_layer_required
        entry = None
        try:
            entry = governance_store.static_key_for_principal(sub)
        except Exception:
            log.exception("static-key lookup failed for %s", sub)
        if entry is not None and not masked_principal:
            out["s3"] = {
                "endpoint": s3.endpoint,
                "region": s3.region,
                "path-style-access": s3.path_style,
                "access-key-id": entry.access_key_id,
                "secret-access-key": entry.secret_access_key,
                "session-token": None,
                "expiration": None,
                "static-key": True,
                "enforcement": "bucket-policy",
            }
            decision = ("static_key_bucket_policy"
                        if decision == "ok" else decision)
        elif entry is not None and masked_principal:
            # A static key can only serve a masked principal if the bucket
            # policy already carves them to the CURRENT masked sig prefix —
            # unverifiable at vend time, and sig rotation makes it stale.
            # Fail closed rather than risk base-byte reads.
            out["s3"] = None
            decision = "error_no_sts_masked"
            _audit_credentials_denied(ctx, sub, ns, table, decision)
        elif settings.suppress_root_creds:
            out["s3"] = None
            decision = "error_no_sts"
            _audit_credentials_denied(ctx, sub, ns, table, decision)
        else:
            # Dev opt-in semantics preserved (suppress_root_creds=0) — but
            # never for masked principals, caught above. Loud by design.
            log.warning("no-STS mode with suppress_root_creds=0: vending "
                        "ROOT keys to %s — dev only", sub)
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
    else:
        try:
            creds = vend_credentials(
                s3,
                namespace=ns[0],
                table=table or "*",
                read_only=True,
                read_prefixes=read_prefixes,
                deny_prefixes=deny_prefixes,
                duration_seconds=clamped,
                principal=sub,
                data_prefix=ctx.ref.data_prefix,
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
            sts_degraded = creds.degraded
        except Exception:
            log.exception(
                "ducklake-credentials STS vending failed for %s — %s",
                ns[0], "falling back to root keys"
                if not settings.suppress_root_creds else "no creds returned")
            if settings.suppress_root_creds:
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
                decision = ("error_unmasked"
                            if decision != "masked" else decision)

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
                "reader_dsn": reader_dsn_ok,
                "file_layer": out["file_layer"],
                "sts_degraded": sts_degraded,
            },
        )
    except Exception:
        log.exception("ducklake-credentials audit failed")

    return out


@app.post("/v1/{prefix}/tables/rename", status_code=204)
def rename_table(
    prefix: str, req: RenameTableRequest,
    ctx: CatalogContext = Depends(resolve_catalog),
):
    catalog = ctx.catalog
    _reject_reserved_table_name(req.destination.name)
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
    # Governance rows key on (schema, table[, column]) names — carry them to
    # the new name so the mask keeps applying (else it silently lapses), then
    # resync both ends so stale masking views/exports for the old name go and
    # the new name rematerializes on next read.
    ctx.store.rename_table_governance(
        None, src_schema=req.source.namespace[0], src_table=req.source.name,
        dst_schema=req.destination.namespace[0], dst_table=req.destination.name)
    _resync_table_governance(ctx, req.source.namespace, req.source.name)
    _resync_table_governance(ctx, req.destination.namespace, req.destination.name)
    return Response(status_code=204)


@app.post(
    "/v1/{prefix}/namespaces/{namespace}/tables/{table}",
    response_model=LoadTableResponse,
)
def commit_table(
    prefix: str, namespace: str, table: str, req: CommitTableRequest,
    request: Request,
    ctx: CatalogContext = Depends(resolve_catalog),
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
    # Per-request catalog context: the commit runs against the resolved
    # catalog's DuckLake attach / metadata schema / data prefix.
    catalog = ctx.catalog
    masking_view_manager = ctx.masking_view_manager
    masked_export_manager = ctx.masked_export_manager
    ns = _parse_namespace(namespace)
    if not catalog.table_exists(ns, table):
        raise HTTPException(
            status_code=404, detail=f"Table does not exist: {ns}.{table}"
        )

    # Enforce optimistic-concurrency requirements from the client FIRST.
    # If the caller asserted "table is at snapshot N" and DuckLake has
    # advanced past that, we refuse the commit. The client retries with a
    # fresh read. This is how Iceberg handles concurrent writers.
    _check_requirements(catalog, ns, table, req.requirements)

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
            updates = u.get("updates") or {}
            _reject_reserved_property_keys(updates.keys())
            pending_properties_set.update(updates)
            continue
        if action == "remove-properties":
            removals = u.get("removals") or []
            _reject_reserved_property_keys(removals)
            pending_properties_remove.extend(removals)
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
    schema_changed = False
    with catalog.commit_transaction():
        if new_schema is not None:
            _apply_schema_diff(ctx, ns, table, new_schema)
            schema_changed = True

        if pending_partition_spec is not None:
            _apply_partition_spec(catalog, ns, table, pending_partition_spec)

        if pending_sort_order is not None:
            _apply_sort_order(catalog, ns, table, pending_sort_order)

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

    if schema_changed:
        # Masking views and masked exports project the pre-change column
        # set; their signatures fold the columns in, so they're all stale.
        # Drop them (best-effort) — the next masked read recreates at the
        # new signature. Deliberately OUTSIDE the commit transaction: the
        # gc reads catalog tables and issues DuckDB DDL, and doing that
        # while holding the commit tx's locks deadlocks against the notify
        # listener (observed live; PG can't detect it because the tx waits
        # in Python).
        try:
            masking_view_manager.gc_orphans(ns, table, keep=set())
            masked_export_manager.gc_table(ns, table, keep=set())
        except Exception:
            log.exception("post-schema-change masking GC failed for %s.%s",
                          ns[0], table)

    # Commit audit: land data commits in the same duckicelake_governance_audit
    # trail governed reads use, so "who wrote what, when" is queryable rather
    # than a log line. Best-effort (audit_load swallows its own failures) and
    # AFTER the transaction — a failed audit must never roll back a commit.
    try:
        commit_sub = (claims_from_request(auth_cfg, request).get("sub")
                      or "anonymous")
        ctx.store.audit_load(
            principal=commit_sub, object_=f"{ns[0]}.{table}",
            masked_cols=[], applied_policies=[], row_filtered=False,
            operation="commit_table", decision="ok",
            detail={
                "added_files": len(pending_add_paths),
                "removed_files": len(pending_remove_paths),
                "pos_delete_files": len(pending_pos_deletes),
                "eq_delete_files": len(pending_eq_deletes),
                "expired_snapshots": len(pending_remove_snapshot_ids),
                "schema_changed": schema_changed,
                "properties_set": sorted(pending_properties_set),
                "properties_removed": sorted(pending_properties_remove),
                "tag_set": pending_tag[0] if pending_tag else None,
                "tag_removed": pending_tag_remove,
            })
    except Exception:
        log.exception("commit audit failed for %s.%s", ns[0], table)

    # Eager materialise: _build_load_response calls materialize_all, which
    # writes all the snapshot/manifest Avros + the new vN.metadata.json and
    # primes the in-process cache. Subsequent readers hit the cache with no
    # S3 / no manifest-generation cost.
    COMMIT_TOTAL.labels("ok").inc()
    return _build_load_response(ctx, ns, table, request=request)


def _check_requirements(
    catalog: DuckLakeCatalog, ns: list[str], table: str,
    requirements: list[dict[str, Any]],
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


def _apply_partition_spec(catalog: DuckLakeCatalog, ns: list[str], table: str,
                          spec: dict[str, Any]) -> None:
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


def _apply_sort_order(catalog: DuckLakeCatalog, ns: list[str], table: str,
                      sort_order: dict[str, Any]) -> None:
    """Translate Iceberg add-sort-order → direct mutation of
    `ducklake_sort_info` + `ducklake_sort_expression`."""
    from .partition_sort import normalize_iceberg_sort_fields
    fields = normalize_iceberg_sort_fields(sort_order.get("fields", []))
    catalog.set_sort_order(ns, table, fields)


def _apply_schema_diff(ctx: "CatalogContext", ns: list[str], table: str,
                       new_schema: dict[str, Any]) -> None:
    """Translate an Iceberg `add-schema` into DuckDB ADD/DROP COLUMN.

    We match columns by `id` (field-id). Columns in the new schema with an
    id not present today are added. Columns present today but missing from
    the new schema are dropped. Type or required-ness changes require a
    full rewrite and are rejected.
    """
    from .types import iceberg_type_to_duckdb, ducklake_type_to_iceberg

    catalog = ctx.catalog
    governance_store = ctx.store
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
            # Same field-id, new name → a column rename. Apply it, then carry
            # the column's governance rows (tags / column-target masks) to the
            # new name; otherwise the mask silently detaches (a LEAK).
            if cur.column_name != f["name"]:
                catalog.rename_column(ns, table, cur.column_name, f["name"])
                governance_store.rename_column_governance(
                    None, schema=ns[0], table=table,
                    old_column=cur.column_name, new_column=f["name"])
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
    from botocore.exceptions import ClientError

    from . import s3util
    c = s3util.s3_client(s3)
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


def _wants_remote_signing(header: str | None) -> bool:
    if not header:
        return False
    return any(
        token.strip().lower() == "remote-signing"
        for token in header.split(",")
    )


def _remote_signing_config(request: Request | None,
                           ctx: CatalogContext) -> dict[str, str]:
    """Config keys that route a client's S3 I/O through the proxy signer.
    Emits BOTH activation switches: `s3.remote-signing-enabled` (Java
    S3FileIO) and `s3.signer=S3V4RestSigner` (PyIceberg FsspecFileIO —
    which ignores the Java flag)."""
    base = (settings.public_url
            or (str(request.base_url) if request is not None else "")
            ).rstrip("/")
    return {
        "s3.remote-signing-enabled": "true",
        "s3.signer": "S3V4RestSigner",
        "s3.signer.uri": base,
        "s3.signer.endpoint": f"v1/{ctx.catalog_id}/aws/s3/sign",
        # PyIceberg's pyarrow FileIO has no signer support; fsspec does.
        "py-io-impl": "pyiceberg.io.fsspec.FsspecFileIO",
    }


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
    if not settings.suppress_root_creds:
        # Demo/dev convenience only — root keys in client hands make every
        # governance masking layer bypassable. Production sets
        # DUCKICELAKE_SUPPRESS_ROOT_CREDS=1 and clients rely on vended creds.
        cfg["s3.access-key-id"] = s3.root_access_key
        cfg["s3.secret-access-key"] = s3.root_secret_key
    return cfg


def _build_load_response(
    ctx: CatalogContext,
    ns: list[str],
    table: str,
    properties: dict[str, str] | None = None,
    *,
    delegation_header: str | None = None,
    read_only: bool = True,
    snapshot_id_override: int | None = None,
    principal_claims: dict | None = None,
    request: Request | None = None,
) -> LoadTableResponse:
    # Per-request catalog context; managers below are bound to this catalog.
    catalog = ctx.catalog
    policy_engine = ctx.policy_engine
    governance_store = ctx.store
    masking_view_manager = ctx.masking_view_manager
    masked_export_manager = ctx.masked_export_manager
    data_prefix = ctx.ref.data_prefix
    columns = catalog.get_columns(ns, table)
    uuid = catalog.table_uuid(ns, table)
    s3 = settings.s3
    table_prefix = s3.table_prefix(ns[0], table, data_prefix)
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
    requested_historical = False
    if snapshot_id_override is not None:
        if not any(s["snapshot-id"] == snapshot_id_override for s in metadata.get("snapshots", [])):
            raise HTTPException(
                status_code=400,
                detail=f"Unknown snapshot-id for {ns[0]}.{table}: {snapshot_id_override}",
            )
        # Did the caller ask for a snapshot other than the live one? File-layer
        # masking can't honor that (see the deny below) — capture it before we
        # repoint current-snapshot-id.
        requested_historical = snapshot_id_override != metadata.get("current-snapshot-id")
        metadata = dict(metadata)
        metadata["current-snapshot-id"] = snapshot_id_override
        metadata["refs"] = {"main": {"type": "branch", "snapshot-id": snapshot_id_override}}

    # ---- Phase 2 governance enforcement (read path only) ----
    # When the caller supplied principal claims (the GET LoadTable path),
    # consult the policy engine and stamp the returned metadata with the
    # per-principal masking / row-filter signals. No-op when nothing is
    # governed. Wrapped defensively: governance must never break a read.
    principal_for_creds: str | None = None
    file_layer_export = None
    file_layer_required = False
    governance_error = False
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
                file_layer_required = plan.file_layer
                metadata = apply_plan_to_metadata(metadata, plan)
                # Phase 4: file-layer plans get masked Parquet exports + SHADOW
                # metadata pointing at them — every Iceberg reader (incl. the
                # DuckDB iceberg ext) reads masked bytes. Decide the export
                # FIRST (export survives only if BOTH the export and its
                # shadow metadata materialize), then materialize the view once
                # with that final decision — otherwise a shadow failure would
                # leave the view repointed at a masked prefix the base-scoped
                # creds can't read, advertised on base metadata.
                if plan.file_layer and requested_historical:
                    # File-layer masked exports are current-state only — we
                    # don't materialize per-historical-snapshot masked Parquet.
                    # Don't build/serve a current-state export here; the
                    # time-travel deny fires after the try (fail closed).
                    file_layer_export = None
                elif plan.file_layer:
                    file_layer_export = (
                        masked_export_manager.ensure_export_for_plan(
                            ns, table, plan)
                        or masked_export_manager.current_export(
                            ns, table, mask_signature(plan))
                    )
                    if file_layer_export is not None:
                        shadow = masked_export_manager.shadow_metadata(
                            ns, table, file_layer_export)
                        if shadow is not None:
                            _ensure_file_layer_properties(ctx, ns, table, plan)
                            metadata_location, metadata = shadow
                            metadata = apply_plan_to_metadata(metadata, plan)
                        else:
                            # no shadow → degrade to catalog-level masking on
                            # BASE metadata; don't repoint the view to a
                            # masked prefix the base creds won't cover
                            file_layer_export = None
                # Phase 3: materialize the plan's masking view (read_parquet
                # body iff file_layer_export survived; else expression SELECT)
                # so cooperative clients can execute the mask; advertise it.
                view_name = masking_view_manager.ensure_view_for_plan(
                    ns, table, plan, export=file_layer_export
                )
                if view_name:
                    metadata["properties"]["duckicelake.masking-view-name"] = view_name
                elif file_layer_export is None:
                    # the plan demands masking but its view could not be
                    # materialized — the cooperative tier is degraded to
                    # advisory-signals-only (strict mode denies below)
                    governance_error = True
                governance_store.audit_load(
                    principal=principal_for_creds, object_=f"{ns[0]}.{table}",
                    masked_cols=plan.masked_columns,
                    applied_policies=plan.applied_policies,
                    row_filtered=plan.row_filter is not None,
                    decision=("masked_file_layer"
                              if file_layer_export is not None else None),
                    detail={"file_layer": file_layer_export is not None},
                )
        except Exception:
            log.exception("governance enforcement failed for %s.%s — "
                          "fail-open only for the cooperative tier", ns[0], table)
            file_layer_export = None
            governance_error = True
            # B3: planning itself failed BEFORE the plan could classify the
            # table, so file_layer_required may be a stale False. Consult the
            # reserved property stamp — a file-layer table must fail CLOSED
            # even when we couldn't compute its plan.
            file_layer_required = (
                file_layer_required or _stamped_file_layer(catalog, ns, table))

        # FAIL CLOSED for the airtight tier: a file-layer-masked principal
        # whose masked export / shadow metadata could not be materialized
        # must NOT fall through to base metadata + base-prefix creds. Deny
        # the read rather than leak raw bytes. (The catalog-level cooperative
        # tier keeps serving advisory signals + base creds — that's only
        # reached when plan.file_layer is False.)
        if file_layer_required and requested_historical:
            # Time-travel on a file-layer table: the masked export is
            # current-state only, so we can't vend a historical snapshot
            # without either leaking unmasked history or silently serving the
            # current snapshot under the requested id. Deny (fail closed).
            try:
                governance_store.audit_load(
                    principal=principal_for_creds, object_=f"{ns[0]}.{table}",
                    masked_cols=[], applied_policies=[], row_filtered=False,
                    operation="load_table",
                    decision="error_file_layer_timetravel_denied",
                    detail={"file_layer": True,
                            "requested_snapshot": snapshot_id_override})
            except Exception:
                log.exception("audit of file-layer time-travel denial failed")
            raise HTTPException(
                status_code=501,
                detail=(f"file-layer masking for {ns[0]}.{table} does not "
                        f"support time-travel reads; snapshot "
                        f"{snapshot_id_override} is not the current snapshot"),
            )

        if file_layer_required and file_layer_export is None:
            try:
                governance_store.audit_load(
                    principal=principal_for_creds, object_=f"{ns[0]}.{table}",
                    masked_cols=[], applied_policies=[], row_filtered=False,
                    operation="load_table", decision="error_file_layer_denied",
                    detail={"file_layer": True})
            except Exception:
                log.exception("audit of file-layer denial failed")
            raise HTTPException(
                status_code=503,
                detail=(f"file-layer masking for {ns[0]}.{table} could not be "
                        f"materialized; refusing to serve base data"),
            )

        # Strict mode (DUCKICELAKE_GOVERNANCE_FAIL_CLOSED=1): the COOPERATIVE
        # tier also fails closed — a governance error (planning threw, or a
        # demanded masking view could not be materialized) denies the read
        # instead of serving base metadata with advisory-only signals.
        if settings.governance_fail_closed and governance_error:
            try:
                governance_store.audit_load(
                    principal=principal_for_creds, object_=f"{ns[0]}.{table}",
                    masked_cols=[], applied_policies=[], row_filtered=False,
                    operation="load_table", decision="error_governance_denied",
                    detail={"strict": True})
            except Exception:
                log.exception("audit of strict governance denial failed")
            raise HTTPException(
                status_code=503,
                detail=(f"governance enforcement for {ns[0]}.{table} failed "
                        "and this deployment is configured fail-closed "
                        "(DUCKICELAKE_GOVERNANCE_FAIL_CLOSED); refusing to "
                        "serve"),
            )

    config_out: dict[str, str] = _base_s3_config()
    wants_delegation = (_wants_vended_credentials(delegation_header)
                        or _wants_remote_signing(delegation_header))
    if wants_delegation and settings.s3.sts_disabled:
        # No STS on this backend (Hetzner): answer BOTH delegation header
        # values with remote signing. Masked file-layer and normal
        # principals get the SAME config — per-object authorization lives
        # in the signer, which re-derives the plan/sig on every request
        # (and shadow metadata already points masked principals at the
        # __masked__ prefix). No static keys are emitted; revocation is
        # immediate.
        config_out.update(_remote_signing_config(request, ctx))
    elif _wants_vended_credentials(delegation_header) and file_layer_export is not None:
        # Masked file-layer principal: READ-ONLY creds on the masked sig
        # prefix only — never the base table's bytes (and never write).
        creds = vend_credentials(
            s3,
            namespace=ns[0],
            table=table,
            read_only=True,
            read_prefixes=[s3.masked_sig_prefix(
                ns[0], table, file_layer_export.sig, data_prefix)],
            principal=principal_for_creds,
            data_prefix=data_prefix,
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
    elif _wants_vended_credentials(delegation_header):
        # Vended creds must cover *everything* a client may do with this
        # table during the token's lifetime. The Iceberg REST spec doesn't
        # distinguish read vs write at vending time — the same header
        # `X-Iceberg-Access-Delegation: vended-credentials` is sent on
        # both GET LoadTable (reader) and POST CreateTable / commit
        # (writer). PyIceberg fetches creds via LoadTable then uses them
        # for subsequent writes. So we always vend write-capable creds
        # here — and a write-mode session policy is prefix-scoped by
        # construction (we can't predict the filenames a writer will
        # upload), so no per-file key list is passed. RBAC (per-token
        # capability scoping) is the right way to restrict this and is on
        # the to-do list.
        creds = vend_credentials(
            s3,
            namespace=ns[0],
            table=table,
            read_only=False,           # see comment above
            principal=principal_for_creds,
            data_prefix=data_prefix,
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
