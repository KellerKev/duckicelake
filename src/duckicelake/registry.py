"""Multi-catalog registry (qod integration).

The proxy can serve many isolated DuckLake catalogs from one process. Each is
described by a `CatalogRef` (alias + S3 data_prefix + Postgres METADATA_SCHEMA)
and bundled with its own governance managers in a `CatalogContext`. A
`CatalogRegistry` resolves a catalog id (the Iceberg REST `{prefix}`) to its
context, building + caching lazily and bounding how many are attached at once.

Resolution source: the `public.duckicelake_catalog` sidecar table, populated by
`provision()` when the orchestration layer creates an account/catalog. The
default catalog (settings.catalog_name) resolves directly from settings so
single-catalog deployments need no registry rows.
"""
from __future__ import annotations

import contextvars
import os
import re
import threading
import time
from collections import OrderedDict

import psycopg

from .catalog import DuckLakeCatalog
from .config import CatalogRef, Settings
from .governance import GovernanceStore
from .masked_export import MaskedExportManager
from .masking_views import MaskingViewManager
from .policies import PolicyEngine
from .sqlsafe import qi


#: Contexts handed out during the current request: [(registry, ctx), ...].
#: Set by `CatalogLeaseMiddleware`; `CatalogRegistry.get` appends to it. The
#: list object is shared with threadpool workers (contextvars are copied, the
#: list is not), so leases taken in sync handlers land here too.
_REQUEST_LEASES: contextvars.ContextVar[list | None] = contextvars.ContextVar(
    "duckicelake_catalog_leases", default=None)


class CatalogLeaseMiddleware:
    """Pure-ASGI middleware: every catalog context a request resolves stays
    open until the response has been fully sent. Eviction (LRU cap or idle
    timeout) of a context still leased by a request defers the close to the
    last release instead of closing connections under a running query."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        held: list = []
        token = _REQUEST_LEASES.set(held)
        try:
            return await self.app(scope, receive, send)
        finally:
            _REQUEST_LEASES.reset(token)
            for reg, ctx in held:
                reg.release(ctx)


def ensure_catalog_registry_table(cur) -> None:
    """Create the cross-catalog registry table (idempotent). Lives in `public`
    because it is catalog-independent control state."""
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS public.duckicelake_catalog (
            catalog_id      TEXT PRIMARY KEY,
            metadata_schema TEXT NOT NULL,
            data_prefix     TEXT NOT NULL,
            account_id      TEXT,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )


class CatalogContext:
    """All per-catalog state: the DuckLake catalog plus the governance managers
    bound to it. Mirrors the manager wiring server.py used for the single
    global catalog, but one set per isolated catalog."""

    def __init__(self, settings: Settings, ref: CatalogRef,
                 account_id: str | None = None) -> None:
        self.ref = ref
        # Owning tenant (registry row's account_id). None = unowned: the
        # default catalog or a shared catalog — reachable by any
        # authenticated caller. Set → resolve_catalog requires a matching
        # `account` claim (or an admin-scope token); mismatch is a 404.
        self.account_id = account_id
        self.catalog = DuckLakeCatalog(settings, ref)
        self.store = GovernanceStore(self.catalog)
        self.policy_engine = PolicyEngine(
            self.store, agent_file_layer=settings.agent_file_layer,
            airtight_channels=settings.airtight_channels)
        self.masking_view_manager = MaskingViewManager(self.catalog, settings)
        self.masked_export_manager = MaskedExportManager(
            self.catalog, settings,
            store=self.store, view_manager=self.masking_view_manager,
        )
        self._connected = False
        # Request leases (see CatalogLeaseMiddleware) and whether the
        # registry dropped this context while it was still leased.
        self._leases = 0
        self._retired = False

    @property
    def catalog_id(self) -> str:
        return self.ref.catalog_name

    def connect(self) -> "CatalogContext":
        if not self._connected:
            self.catalog.connect()
            self._connected = True
        return self

    def close(self) -> None:
        if self._connected:
            self.catalog.close()
            self._connected = False


class UnknownCatalog(KeyError):
    """Raised when a catalog id has no registry entry (→ 404 at the edge)."""


_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,63}$")
_PREFIX_SEG_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _check_catalog_names(catalog_id: str, metadata_schema: str, data_prefix: str) -> None:
    """Catalog id + metadata schema end up in ATTACH strings, a libpq
    `-c search_path` option and PG DDL; the data prefix scopes every
    credential vended for the catalog. Keep all three to a strict shape so
    none of them can carry quoting, option or path tricks."""
    for value, what in ((catalog_id, "catalog_id"), (metadata_schema, "metadata_schema")):
        if not _NAME_RE.match(value or ""):
            raise ValueError(f"{what} must match {_NAME_RE.pattern}")
    segs = (data_prefix or "").split("/")
    if (not data_prefix.endswith("/") or segs[-1] != ""
            or not all(_PREFIX_SEG_RE.match(x) and x not in (".", "..") for x in segs[:-1])
            or segs[0].startswith("__masked")):
        raise ValueError(
            "data_prefix must be '/'-separated segments of [A-Za-z0-9_.-] "
            "ending in '/', with no '.'/'..' segments")


#: Top-level prefixes of the bucket that hold data which is not a catalog's (backups,
#: other applications, the default catalog's root). A catalog whose data prefix starts
#: with one of these is never deleted. DUCKICELAKE_PROTECTED_PREFIXES adds more.
_PROTECTED_DEFAULT = ("backups", "levitate", "pycorner", "streamgen", "cvinfo", "uplevate",
                      "eutonomous", "course", "duckicelake-test", "results", "__masked__")


def protected_prefixes() -> set[str]:
    extra = os.environ.get("DUCKICELAKE_PROTECTED_PREFIXES", "")
    return set(_PROTECTED_DEFAULT) | {p.strip().strip("/") for p in extra.split(",") if p.strip()}


class CatalogRegistry:
    def __init__(self, settings: Settings, max_active: int | None = None) -> None:
        self.settings = settings
        self._ctxs: "OrderedDict[str, CatalogContext]" = OrderedDict()
        self._lock = threading.RLock()
        self._max = (
            int(os.environ.get("DUCKICELAKE_MAX_ACTIVE_CATALOGS", "32"))
            if max_active is None else max_active
        )
        # Close catalogs nobody touched for this long (their DuckDB attaches
        # and Postgres pools), so connections track active tenants, not every
        # tenant this process ever served. 0 disables. Never the default.
        self._idle_s = float(os.environ.get("DUCKICELAKE_CATALOG_IDLE_SECONDS", "1800"))
        self._last_used: dict[str, float] = {}
        # Evicted while a request still held them; closed on last release.
        self._retired: dict[str, CatalogContext] = {}

    # ---- resolution ----------------------------------------------------
    def _pg(self):
        return psycopg.connect(self.settings.pg_dsn, autocommit=True)

    def ensure_table(self) -> None:
        with self._pg() as c, c.cursor() as cur:
            ensure_catalog_registry_table(cur)

    def resolve_ref(self, catalog_id: str) -> CatalogRef | None:
        resolved = self._resolve_row(catalog_id)
        return resolved[0] if resolved else None

    def _resolve_row(self, catalog_id: str) -> tuple[CatalogRef, str | None] | None:
        """(ref, account_id) for a catalog id, or None if unregistered. The
        default catalog resolves from settings — no registry row, no account
        (it is settings-owned and reachable by every authenticated caller)."""
        if catalog_id == self.settings.catalog_name:
            return self.settings.default_catalog_ref(), None
        with self._pg() as c, c.cursor() as cur:
            ensure_catalog_registry_table(cur)
            row = cur.execute(
                "SELECT metadata_schema, data_prefix, account_id "
                "FROM public.duckicelake_catalog WHERE catalog_id = %s",
                [catalog_id],
            ).fetchone()
        if row is None:
            return None
        ref = CatalogRef(catalog_id, data_prefix=row[1], metadata_schema=row[0])
        return ref, row[2]

    def list_refs(self) -> list[tuple[str, CatalogRef]]:
        """(catalog_id, ref) for every registered catalog, default included.
        Used by the bare remote-signer route to resolve a catalog from an
        object key by longest data-prefix match."""
        out: list[tuple[str, CatalogRef]] = [
            (self.settings.catalog_name, self.settings.default_catalog_ref())]
        try:
            with self._pg() as c, c.cursor() as cur:
                ensure_catalog_registry_table(cur)
                rows = cur.execute(
                    "SELECT catalog_id, metadata_schema, data_prefix "
                    "FROM public.duckicelake_catalog").fetchall()
        except Exception:
            return out
        for cid, meta_schema, data_prefix in rows:
            out.append((cid, CatalogRef(cid, data_prefix=data_prefix,
                                        metadata_schema=meta_schema)))
        return out

    # ---- lifecycle -----------------------------------------------------
    def register_default(self) -> CatalogContext:
        """Build (unconnected) the default catalog context and register it, so
        the server can wire its module globals at import and connect in
        lifespan — matching the prior single-catalog flow."""
        with self._lock:
            cid = self.settings.catalog_name
            ctx = self._ctxs.get(cid)
            if ctx is None:
                ctx = CatalogContext(self.settings, self.settings.default_catalog_ref())
                self._ctxs[cid] = ctx
            return ctx

    def get(self, catalog_id: str) -> CatalogContext:
        """Return the connected context for a catalog id. Raises UnknownCatalog
        if it has no registry entry. Inside a request (CatalogLeaseMiddleware)
        the context is leased until the response is sent."""
        with self._lock:
            self._evict_idle_locked()
            ctx = self._ctxs.get(catalog_id) or self._revive_locked(catalog_id)
            if ctx is not None:
                self._ctxs.move_to_end(catalog_id)
                self._last_used[catalog_id] = time.monotonic()
                self._lease_locked(ctx)
        if ctx is None:
            resolved = self._resolve_row(catalog_id)
            if resolved is None:
                raise UnknownCatalog(catalog_id)
            ref, account_id = resolved
            ctx = CatalogContext(self.settings, ref, account_id=account_id)
            with self._lock:
                # Another thread may have built it meanwhile.
                existing = self._ctxs.get(catalog_id) or self._revive_locked(catalog_id)
                if existing is not None:
                    ctx = existing
                else:
                    self._ctxs[catalog_id] = ctx
                self._ctxs.move_to_end(catalog_id)
                self._last_used[catalog_id] = time.monotonic()
                self._lease_locked(ctx)
                self._evict_locked()
        ctx.connect()
        return ctx

    def _lease_locked(self, ctx: CatalogContext) -> None:
        held = _REQUEST_LEASES.get()
        if held is not None:
            ctx._leases += 1
            held.append((self, ctx))

    def release(self, ctx: CatalogContext) -> None:
        """Drop one request lease; closes the context if the registry already
        evicted it and this was the last holder."""
        with self._lock:
            ctx._leases = max(0, ctx._leases - 1)
            if ctx._retired and ctx._leases == 0:
                self._retired.pop(ctx.catalog_id, None)
                ctx._retired = False
                self._close_ctx(ctx)

    def _revive_locked(self, catalog_id: str) -> CatalogContext | None:
        """An evicted context still leased (not yet closed) is reused rather
        than opening a second set of connections for the same catalog."""
        ctx = self._retired.pop(catalog_id, None)
        if ctx is not None:
            ctx._retired = False
            self._ctxs[catalog_id] = ctx
        return ctx

    def default(self) -> CatalogContext:
        return self.get(self.settings.catalog_name)

    def provision(
        self, catalog_id: str, metadata_schema: str, data_prefix: str,
        account_id: str | None = None,
    ) -> CatalogContext:
        """Create the Postgres metadata schema + register the catalog, then
        return its (connected) context. Idempotent on catalog_id."""
        _check_catalog_names(catalog_id, metadata_schema, data_prefix)
        with self._pg() as c, c.cursor() as cur:
            ensure_catalog_registry_table(cur)
            cur.execute(f'CREATE SCHEMA IF NOT EXISTS {qi(metadata_schema)}')
            cur.execute(
                "INSERT INTO public.duckicelake_catalog "
                "(catalog_id, metadata_schema, data_prefix, account_id) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT (catalog_id) DO NOTHING",
                [catalog_id, metadata_schema, data_prefix, account_id],
            )
        return self.get(catalog_id)

    # ---- deprovisioning + usage ------------------------------------------
    def _owned_ref(self, catalog_id: str) -> CatalogRef:
        """The registered ref of a catalog it is safe to delete or measure on its own,
        else ValueError / UnknownCatalog.

        The bucket is shared with data that is not ours (other prefixes at its root), so
        everything that deletes is held to the narrowest shape: never the default
        catalog, a data prefix of at least two segments whose first one is not a protected
        top-level prefix, not overlapping any other catalog's prefix or the default data
        prefix, and a metadata schema of its own."""
        if catalog_id == self.settings.catalog_name:
            raise ValueError("the default catalog is never deprovisioned")
        resolved = self._resolve_row(catalog_id)
        if resolved is None:
            raise UnknownCatalog(catalog_id)
        ref = resolved[0]
        meta, prefix = ref.metadata_schema or "", ref.data_prefix or ""
        _check_catalog_names(catalog_id, meta, prefix)
        segs = prefix.split("/")
        if len(segs) < 3 or not all(segs[:-1]):
            raise ValueError(f"data prefix {prefix!r} is too broad to delete")
        if segs[0] in protected_prefixes():
            raise ValueError(f"data prefix {prefix!r} is under a protected prefix")
        if meta == "public" or meta.startswith("pg_") or meta == "information_schema":
            raise ValueError(f"metadata schema {meta!r} is not a catalog's own")
        default_prefix = self.settings.s3.data_prefix or ""
        if not default_prefix or prefix.startswith(default_prefix) or default_prefix.startswith(prefix):
            raise ValueError(f"data prefix {prefix!r} overlaps the default catalog")
        for other_id, other in self.list_refs():
            if other_id in (catalog_id, self.settings.catalog_name):
                continue
            op = other.data_prefix or ""
            if op.startswith(prefix) or prefix.startswith(op) or other.metadata_schema == meta:
                raise ValueError(f"catalog {catalog_id!r} shares storage with {other_id!r}")
        return ref

    def _objects(self, prefix: str):
        from .s3util import s3_client
        client = s3_client(self.settings.s3)
        token = None
        while True:
            kw = {"Bucket": self.settings.s3.bucket, "Prefix": prefix, "MaxKeys": 1000}
            if token:
                kw["ContinuationToken"] = token
            r = client.list_objects_v2(**kw)
            yield client, r.get("Contents") or []
            if not r.get("IsTruncated"):
                return
            token = r.get("NextContinuationToken")

    def usage(self, catalog_id: str) -> dict:
        """Bytes and objects the catalog holds in S3 (its data, deletes, masked exports)."""
        ref = self._owned_ref(catalog_id)
        total = count = 0
        for _client, objs in self._objects(ref.data_prefix):
            count += len(objs)
            total += sum(int(o.get("Size") or 0) for o in objs)
        return {"catalog_id": catalog_id, "bytes": total, "objects": count,
                "data_prefix": ref.data_prefix}

    def _delete_prefix(self, prefix: str) -> tuple[int, int]:
        deleted = size = 0
        for client, objs in self._objects(prefix):
            keys = [o["Key"] for o in objs if str(o.get("Key", "")).startswith(prefix)]
            if not keys:
                continue
            r = client.delete_objects(Bucket=self.settings.s3.bucket,
                                      Delete={"Objects": [{"Key": k} for k in keys], "Quiet": True})
            errs = r.get("Errors") or []
            if errs:
                raise RuntimeError(f"S3 refused {len(errs)} deletes, first: {errs[0]}")
            deleted += len(keys)
            size += sum(int(o.get("Size") or 0) for o in objs)
        return deleted, size

    def deprovision(self, catalog_id: str) -> dict:
        """Delete a catalog for good: its S3 objects, its Postgres metadata schema, its
        per-catalog reader/writer groups and predicate functions, then the registry row.
        Every step is idempotent and the row goes last, so a failure part-way is finished
        by calling again. Contexts cached in other worker processes fail on their next use
        and age out; nothing routes to a deleted account's catalogs any more."""
        from psycopg import sql as psql

        from . import pg_rls
        ref = self._owned_ref(catalog_id)
        meta, prefix = ref.metadata_schema, ref.data_prefix
        with self._lock:
            if catalog_id in self._ctxs:
                self._close_locked(catalog_id)
            ctx = self._retired.pop(catalog_id, None)
            if ctx is not None:
                self._close_ctx(ctx)
        objects, size = self._delete_prefix(prefix)
        left: list[str] = []
        groups = [pg_rls._group_for(self.settings, meta),
                  pg_rls._writer_group_for(self.settings, meta)]
        with self._pg() as c, c.cursor() as cur:
            cur.execute("SET lock_timeout = '20s'")
            cur.execute(psql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(psql.Identifier(meta)))
            for fn in pg_rls._fn_names(meta):
                cur.execute(psql.SQL("DROP FUNCTION IF EXISTS public.{}()").format(psql.Identifier(fn)))
            for g in groups:
                if not cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [g]).fetchone():
                    continue
                try:
                    cur.execute(psql.SQL("DROP OWNED BY {}").format(psql.Identifier(g)))
                    cur.execute(psql.SQL("DROP ROLE {}").format(psql.Identifier(g)))
                except psycopg.Error as e:
                    left.append(f"{g}: {type(e).__name__}")
        # anything a still-open writer put there while the schema went
        more, more_size = self._delete_prefix(prefix)
        with self._pg() as c, c.cursor() as cur:
            cur.execute("DELETE FROM public.duckicelake_catalog WHERE catalog_id = %s", [catalog_id])
        return {"catalog_id": catalog_id, "deleted_objects": objects + more,
                "deleted_bytes": size + more_size, "metadata_schema": meta,
                "data_prefix": prefix, "roles_left": left}

    def _evict_locked(self) -> None:
        """Close + drop least-recently-used contexts beyond the cap. Never
        evicts the default catalog (held for background components)."""
        default_id = self.settings.catalog_name
        while len(self._ctxs) > self._max:
            for cid in list(self._ctxs.keys()):
                if cid == default_id:
                    continue
                self._close_locked(cid)
                break
            else:
                break  # only the default remains

    def _close_locked(self, cid: str) -> None:
        ctx = self._ctxs.pop(cid)
        self._last_used.pop(cid, None)
        if ctx._leases > 0:
            # A request is still using it: close on its last release.
            ctx._retired = True
            self._retired[cid] = ctx
            return
        self._close_ctx(ctx)

    @staticmethod
    def _close_ctx(ctx: CatalogContext) -> None:
        try:
            ctx.close()
        except Exception:
            pass

    def _evict_idle_locked(self) -> None:
        if self._idle_s <= 0:
            return
        cutoff = time.monotonic() - self._idle_s
        default_id = self.settings.catalog_name
        for cid in [c for c, t in self._last_used.items()
                    if t < cutoff and c != default_id and c in self._ctxs]:
            self._close_locked(cid)

    def close_all(self) -> None:
        with self._lock:
            for ctx in [*self._ctxs.values(), *self._retired.values()]:
                try:
                    ctx.close()
                except Exception:
                    pass
            self._ctxs.clear()
            self._retired.clear()
            self._last_used.clear()
