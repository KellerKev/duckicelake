"""Eager DuckLake-to-Iceberg materialisation listener.

DuckLake-direct writes (DuckDB sessions ATTACHing `ducklake:` and
running INSERT/UPDATE/DELETE) commit straight into
`public.ducklake_snapshot` without going through the REST proxy. The
lazy LoadTable path in `_build_load_response` still materialises them
on first read, so readers always see correct data — they just pay the
materialisation cost on the request path.

This module closes that latency gap. A Postgres `AFTER INSERT` trigger
on `ducklake_snapshot` fires `NOTIFY duckicelake_snapshot` with the new
`snapshot_id`. One elected worker per fleet runs an async LISTEN loop
and calls `materialise_table()` for every table the snapshot touched.

Election is by `pg_try_advisory_lock` on a fixed key — N proxy workers
race; one wins and listens, the rest poll the lock so they take over
if the elected worker dies. On startup the elected worker runs a
catch-up scan over any DuckLake snapshots missing from
`duckicelake_materialisation_log`, so a brief outage doesn't leave
snapshots eagerly-unmaterialised (lazy LoadTable still recovers them
either way).
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING

import psycopg

from .materialize import materialise_table

if TYPE_CHECKING:
    from .catalog import DuckLakeCatalog

log = logging.getLogger("duckicelake.notify")

# Fixed advisory-lock key. Any int64 works; we pick something obviously
# project-namespaced so collisions with future locks are unlikely. The
# constant is identical across workers — that's the point: they race
# for the same lock.
_ADVISORY_LOCK_KEY = 0x6475636B696365  # "duckice" in hex-ASCII, truncated
_LISTEN_CHANNEL = "duckicelake_snapshot"
_LOCK_RETRY_SECONDS = 5.0
_CATCHUP_LOOKBACK_MINUTES = 60

# Lazily-built per-process MaskedExportManager (Phase 4 eager refresh).
# Constructed from the catalog's settings; keyed on the catalog instance
# so tests with their own catalogs don't share state.
_EXPORT_MANAGERS: dict[int, object] = {}


def _export_manager(catalog: "DuckLakeCatalog"):
    mgr = _EXPORT_MANAGERS.get(id(catalog))
    if mgr is None:
        from .governance import GovernanceStore
        from .masked_export import MaskedExportManager
        from .masking_views import MaskingViewManager
        # store= so listener-driven eager refreshes are audited the same as
        # request-path exports (operation=masked_export); view_manager= so a
        # refreshed export repoints the masking views onto the new snap dir.
        mgr = MaskedExportManager(
            catalog, catalog.settings,
            store=GovernanceStore(catalog),
            view_manager=MaskingViewManager(catalog, catalog.settings),
        )
        _EXPORT_MANAGERS[id(catalog)] = mgr
    return mgr


def _disabled() -> bool:
    """Operators can opt out of the eager listener entirely (e.g.
    single-node dev, or when running the proxy as a sidecar where
    something else owns the LISTEN connection).
    """
    return os.environ.get("DUCKICELAKE_DISABLE_NOTIFY", "0") == "1"


async def _materialise_snapshot(
    catalog: "DuckLakeCatalog",
    snapshot_id: int,
) -> None:
    """Materialise every table touched by `snapshot_id`. Updates the
    log row to `done` or `failed`. `materialize_all` is byte-identical
    idempotent, so duplicate notifies are safe.
    """
    # `tables_touched_by_snapshot` is sync (PG pool) — quick enough to
    # run on the event loop, but keeping it consistent with the rest
    # via `to_thread` avoids holding the loop on slow PG roundtrips.
    touched = await asyncio.to_thread(
        catalog.tables_touched_by_snapshot, snapshot_id
    )
    if not touched:
        # Schema-only snapshots (no data file motion) — common for DDL
        # commits. Nothing to materialise; record `done` so the
        # catch-up scan doesn't re-pick this snapshot.
        await asyncio.to_thread(
            catalog.record_materialisation,
            snapshot_id,
            status="done",
            iceberg_snapshot_id=snapshot_id,
        )
        return

    last_err: Exception | None = None
    for schema, table in touched:
        try:
            await asyncio.to_thread(
                materialise_table, catalog, [schema], table,
            )
            log.info(
                "eagerly materialised %s.%s for ducklake_snapshot=%s",
                schema, table, snapshot_id,
            )
        except Exception as e:
            # One table failing shouldn't block the others — log it and
            # keep going. The lazy LoadTable path still recovers any
            # table whose eager materialisation failed.
            log.exception(
                "eager materialisation of %s.%s failed for snapshot=%s",
                schema, table, snapshot_id,
            )
            last_err = e
        # Phase 4: refresh the table's masked Parquet exports (file-layer
        # masking) at the new snapshot. Own guard — an export failure must
        # never mark the materialisation failed; the request path lazily
        # heals (or serves the previous export, still masked).
        try:
            await asyncio.to_thread(
                _export_manager(catalog).refresh_known_sigs,
                [schema], table,
            )
        except Exception:
            log.exception(
                "masked-export refresh of %s.%s failed for snapshot=%s",
                schema, table, snapshot_id,
            )

    status = "failed" if last_err is not None else "done"
    await asyncio.to_thread(
        catalog.record_materialisation,
        snapshot_id,
        status=status,
        iceberg_snapshot_id=snapshot_id if status == "done" else None,
        error=str(last_err) if last_err is not None else None,
    )


async def _catchup(catalog: "DuckLakeCatalog") -> None:
    """Process any DuckLake snapshots that don't yet have a `done` row
    in our log within the lookback window. Belt-and-braces for the case
    where the listener was down across a DuckLake commit.
    """
    pending = await asyncio.to_thread(
        catalog.pending_materialisations, _CATCHUP_LOOKBACK_MINUTES,
    )
    if not pending:
        return
    log.info(
        "catch-up scan: %d unmaterialised DuckLake snapshots in last %dm",
        len(pending), _CATCHUP_LOOKBACK_MINUTES,
    )
    for snap_id in pending:
        await _materialise_snapshot(catalog, snap_id)


async def _ensure_trigger_installed(catalog: "DuckLakeCatalog") -> None:
    """Install the PG trigger + the materialisation log table.

    Runs once at listener startup. Calls into the catalog's sync sidecar
    DDL via a thread so we don't block the loop.
    """
    def _sync():
        with catalog.pg_cursor() as cur:
            catalog._ensure_materialisation_sidecar(cur)
    await asyncio.to_thread(_sync)


async def _listen_loop(
    catalog: "DuckLakeCatalog",
    conn: psycopg.AsyncConnection,
) -> None:
    """Drive the LISTEN/NOTIFY async iterator and dispatch each NOTIFY.

    Reuses the same connection that holds the advisory lock — if the
    connection dies, the lock auto-releases AND the loop exits, which
    is exactly what we want (one PG connection per elected worker
    instead of two).
    """
    await conn.execute(f"LISTEN {_LISTEN_CHANNEL}")
    log.info("notify listener LISTEN %s established", _LISTEN_CHANNEL)
    async for notify in conn.notifies():
        try:
            snap_id = int(notify.payload)
        except ValueError:
            log.warning(
                "ignoring NOTIFY with non-int payload: %r", notify.payload,
            )
            continue
        # Fire-and-forget per snapshot so a slow materialisation
        # doesn't back-pressure the queue. Errors are logged inside
        # _materialise_snapshot; the task is fully self-contained.
        asyncio.create_task(_materialise_snapshot(catalog, snap_id))


async def _try_acquire_lock(conn: psycopg.AsyncConnection) -> bool:
    """Returns True iff this connection now holds the fleet-wide advisory
    lock. Session-scoped: lock auto-releases when the conn closes."""
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT pg_try_advisory_lock(%s)", (_ADVISORY_LOCK_KEY,),
        )
        row = await cur.fetchone()
    return bool(row and row[0])


async def run_listener(catalog: "DuckLakeCatalog") -> None:
    """Top-level entry point: elect this worker via advisory lock, run
    catch-up, then LISTEN until cancelled.

    Cancellation (lifespan shutdown) is propagated as a normal
    `asyncio.CancelledError` to the LISTEN connection, which closes
    cleanly and releases the lock for the next election round.
    """
    if _disabled():
        log.info(
            "notify listener disabled via DUCKICELAKE_DISABLE_NOTIFY=1"
        )
        return

    # Install trigger first so even non-elected workers don't crash if
    # they're the first to boot. Concurrent workers are serialized by the
    # advisory lock inside _ensure_materialisation_sidecar — bare
    # CREATE OR REPLACE FUNCTION here raced (`tuple concurrently updated`).
    try:
        await _ensure_trigger_installed(catalog)
    except Exception:
        log.exception("failed to install duckicelake_snapshot trigger")
        return

    dsn = catalog.pg_conninfo()
    while True:
        # Hold the advisory lock for the duration of one listener
        # session. If we don't get it, sleep and retry — the elected
        # worker might die, and we want to take over without a restart.
        try:
            lock_conn = await psycopg.AsyncConnection.connect(
                dsn, autocommit=True,
            )
        except Exception:
            log.exception("notify listener: PG connect failed")
            await asyncio.sleep(_LOCK_RETRY_SECONDS)
            continue

        try:
            got = await _try_acquire_lock(lock_conn)
            if not got:
                await lock_conn.close()
                await asyncio.sleep(_LOCK_RETRY_SECONDS)
                continue

            log.info(
                "notify listener elected (advisory lock=%d)",
                _ADVISORY_LOCK_KEY,
            )
            # Catch-up before starting the live loop so the elected
            # worker covers any commit that landed during the previous
            # worker's absence.
            try:
                await _catchup(catalog)
            except Exception:
                log.exception("catch-up scan failed; continuing to LISTEN")

            try:
                await _listen_loop(catalog, lock_conn)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("LISTEN loop crashed; will re-elect")
            finally:
                await lock_conn.close()  # releases the advisory lock
        except asyncio.CancelledError:
            await lock_conn.close()
            raise
