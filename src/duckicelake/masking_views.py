"""Phase 3 — ad-hoc DuckLake masking views.

One physical DuckLake view per (table, mask-signature), named
`__mask_{table}__{sig}` in the base table's namespace. Principals whose
effective plans share a mask shape share the view (Snowflake-Horizon-style
ad-hoc masking). The view persists in `ducklake_view`, so both read paths
can execute it:

  * DuckLake-direct DuckDB sessions run it natively (the stored SQL keeps
    the base table unqualified — it resolves against the client's own
    attached catalog).
  * Iceberg-REST clients with view support (PyIceberg/Trino/Spark) load it
    via `GET …/views/__mask_{table}__{sig}`.

Transparent mode adds a `__masked_{sig}` DuckLake *schema* holding a view
named exactly `{table}`, so a cooperative client that puts that schema first
on its DuckDB `search_path` gets masked rows from unqualified queries.

Everything here is fail-open: a governance error must never break a read,
so every method that touches the catalog logs and degrades to "no view".
This is cooperative-client masking — see GOVERNANCE.md for the boundary.
"""
from __future__ import annotations

import logging

from .catalog import DuckLakeCatalog
from .config import Settings
from .policies import TablePolicyPlan, mask_signature

log = logging.getLogger("duckicelake.masking_views")

#: Reserved prefixes — user view/namespace creation with these is rejected.
MASK_VIEW_PREFIX = "__mask_"
MASK_SCHEMA_PREFIX = "__masked_"

#: Per-table opt-out property: skip view materialization entirely.
MASKING_DISABLED_PROP = "duckicelake.masking-disabled"


def mask_view_name(table: str, sig: str) -> str:
    return f"{MASK_VIEW_PREFIX}{table}__{sig}"


def mask_schema_name(sig: str) -> str:
    return f"{MASK_SCHEMA_PREFIX}{sig}"


class MaskingViewManager:
    """Materialize / discover / garbage-collect masking views."""

    def __init__(self, catalog: DuckLakeCatalog, settings: Settings) -> None:
        self.catalog = catalog
        self.settings = settings

    # ---- pure naming ----------------------------------------------------

    def view_name_for_plan(self, ns: list[str], table: str,
                           plan: TablePolicyPlan) -> str | None:
        """Name the plan's masking view without touching the database."""
        sig = mask_signature(plan)
        return mask_view_name(table, sig) if sig else None

    # ---- materialization -------------------------------------------------

    def _view_sql(self, plan: TablePolicyPlan, export) -> str:
        """The view body. With a file-layer export, the view reads the
        pre-masked Parquet directly — the base table is never touched (its
        bytes are not even credentialed for masked principals). Without
        one, the Phase-3 expression SELECT computes the mask client-side."""
        if export is not None:
            return (f"SELECT * FROM read_parquet("
                    f"'s3://{self.settings.s3.bucket}/{export.prefix}*.parquet')")
        return plan.view_sql

    def ensure_view_for_plan(self, ns: list[str], table: str,
                             plan: TablePolicyPlan,
                             export=None) -> str | None:
        """Idempotently materialize the plan's masking view; return its name.

        Empty plan, per-table opt-out, or any catalog error → None (callers
        treat that as "no view available" and serve unmasked signals only).
        `export` (a masked_export.MaskedExport) switches the body to the
        pre-masked Parquet glob; the view is repointed whenever the export's
        snap dir changes.
        """
        sig = mask_signature(plan)
        if not sig or not plan.view_sql:
            return None
        name = mask_view_name(table, sig)
        try:
            if self._masking_disabled(ns, table):
                return None
            if not self._view_current(ns, name, export):
                # Phase-3 body goes in verbatim: the unqualified
                # "schema"."table" reference is load-bearing for
                # DuckLake-direct resolution.
                self.catalog.create_view(ns, name, self._view_sql(plan, export),
                                         replace=True)
            return name
        except Exception:
            log.exception(
                "masking view materialization failed for %s.%s (sig %s) "
                "— serving without view", ns[0], table, sig,
            )
            return None

    def ensure_transparent_schema(self, ns: list[str], table: str,
                                  plan: TablePolicyPlan,
                                  export=None) -> str | None:
        """Materialize the `__masked_{sig}` schema holding a view named
        `{table}`, for search_path-based transparent routing. Returns the
        schema name, or None on empty plan / opt-out / error."""
        sig = mask_signature(plan)
        if not sig or not plan.view_sql:
            return None
        schema = mask_schema_name(sig)
        try:
            if self._masking_disabled(ns, table):
                return None
            if not self.catalog.namespace_exists([schema]):
                self.catalog.create_namespace([schema])
            if not self._view_current([schema], table, export):
                self.catalog.create_view([schema], table,
                                         self._view_sql(plan, export),
                                         replace=True)
            return schema
        except Exception:
            log.exception(
                "transparent mask schema materialization failed for %s.%s "
                "(sig %s)", ns[0], table, sig,
            )
            return None

    def _view_current(self, ns: list[str], name: str, export) -> bool:
        """Does the stored view exist and (for file-layer) reference the
        export's live snap dir? A stale reference triggers a repoint via
        CREATE OR REPLACE — transactional for clients (ducklake_view is
        snapshot-versioned)."""
        if not self.catalog.view_exists(ns, name):
            return False
        defn = self.catalog.get_view_definition(ns, name) or ""
        if export is None:
            # fail-open path: if a previous file-layer body lingers, force a
            # repoint back to the expression SELECT — otherwise the view
            # would read a masked prefix the (base-scoped) creds don't cover
            return "/__masked__/" not in defn
        return export.prefix in defn

    # ---- cleanup ---------------------------------------------------------

    def gc_orphans(self, ns: list[str], table: str, keep: set[str]) -> int:
        """Drop `__mask_{table}__*` views (and their transparent schemas)
        whose names are not in `keep`. Best-effort; returns dropped count."""
        prefix = f"{MASK_VIEW_PREFIX}{table}__"
        dropped = 0
        try:
            stale = [v for v in self.catalog.list_views(ns)
                     if v.startswith(prefix) and v not in keep]
        except Exception:
            log.exception("gc_orphans: listing views failed for %s", ns[0])
            return 0
        for name in stale:
            sig = name[len(prefix):]
            try:
                self.catalog.drop_view(ns, name)
                dropped += 1
            except Exception:
                log.exception("gc_orphans: drop view %s.%s failed", ns[0], name)
                continue
            self._drop_transparent_schema(sig, table)
        return dropped

    # ---- internals ---------------------------------------------------------

    def _masking_disabled(self, ns: list[str], table: str) -> bool:
        props = self.catalog.get_table_properties(ns, table)
        return props.get(MASKING_DISABLED_PROP, "").lower() == "true"

    def _drop_transparent_schema(self, sig: str, table: str) -> None:
        """Drop the stale signature's transparent view + schema (if empty)."""
        schema = mask_schema_name(sig)
        try:
            if not self.catalog.namespace_exists([schema]):
                return
            if self.catalog.view_exists([schema], table):
                self.catalog.drop_view([schema], table)
            # Only remove the schema once nothing else lives in it.
            if not self.catalog.list_views([schema]) \
                    and not self.catalog.list_tables([schema]):
                self.catalog.drop_namespace([schema])
        except Exception:
            log.exception("gc_orphans: cleanup of schema %s failed", schema)
