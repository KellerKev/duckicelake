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

import os
import threading
from collections import OrderedDict

import psycopg

from .catalog import DuckLakeCatalog
from .config import CatalogRef, Settings
from .governance import GovernanceStore
from .masked_export import MaskedExportManager
from .masking_views import MaskingViewManager
from .policies import PolicyEngine


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
        self.policy_engine = PolicyEngine(self.store)
        self.masking_view_manager = MaskingViewManager(self.catalog, settings)
        self.masked_export_manager = MaskedExportManager(
            self.catalog, settings,
            store=self.store, view_manager=self.masking_view_manager,
        )
        self._connected = False

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


class CatalogRegistry:
    def __init__(self, settings: Settings, max_active: int | None = None) -> None:
        self.settings = settings
        self._ctxs: "OrderedDict[str, CatalogContext]" = OrderedDict()
        self._lock = threading.RLock()
        self._max = (
            int(os.environ.get("DUCKICELAKE_MAX_ACTIVE_CATALOGS", "32"))
            if max_active is None else max_active
        )

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
        if it has no registry entry."""
        with self._lock:
            ctx = self._ctxs.get(catalog_id)
            if ctx is not None:
                self._ctxs.move_to_end(catalog_id)
        if ctx is None:
            resolved = self._resolve_row(catalog_id)
            if resolved is None:
                raise UnknownCatalog(catalog_id)
            ref, account_id = resolved
            ctx = CatalogContext(self.settings, ref, account_id=account_id)
            with self._lock:
                # Another thread may have built it meanwhile.
                existing = self._ctxs.get(catalog_id)
                if existing is not None:
                    ctx = existing
                else:
                    self._ctxs[catalog_id] = ctx
                self._ctxs.move_to_end(catalog_id)
                self._evict_locked()
        ctx.connect()
        return ctx

    def default(self) -> CatalogContext:
        return self.get(self.settings.catalog_name)

    def provision(
        self, catalog_id: str, metadata_schema: str, data_prefix: str,
        account_id: str | None = None,
    ) -> CatalogContext:
        """Create the Postgres metadata schema + register the catalog, then
        return its (connected) context. Idempotent on catalog_id."""
        with self._pg() as c, c.cursor() as cur:
            ensure_catalog_registry_table(cur)
            cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{metadata_schema}"')
            cur.execute(
                "INSERT INTO public.duckicelake_catalog "
                "(catalog_id, metadata_schema, data_prefix, account_id) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT (catalog_id) DO NOTHING",
                [catalog_id, metadata_schema, data_prefix, account_id],
            )
        return self.get(catalog_id)

    def _evict_locked(self) -> None:
        """Close + drop least-recently-used contexts beyond the cap. Never
        evicts the default catalog (held for background components)."""
        default_id = self.settings.catalog_name
        while len(self._ctxs) > self._max:
            for cid in list(self._ctxs.keys()):
                if cid == default_id:
                    continue
                ctx = self._ctxs.pop(cid)
                try:
                    ctx.close()
                except Exception:
                    pass
                break
            else:
                break  # only the default remains

    def close_all(self) -> None:
        with self._lock:
            for ctx in self._ctxs.values():
                try:
                    ctx.close()
                except Exception:
                    pass
            self._ctxs.clear()
