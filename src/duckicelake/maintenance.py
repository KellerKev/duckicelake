"""Scheduled DuckLake maintenance for every catalog this proxy serves.

DuckLake only cleans up when asked: without it, expired snapshots, their
metadata rows (including statistics of long-dropped tables, which every
commit re-reads) and unreferenced files pile up forever. Each catalog is
maintained once per `maintenance_hours`, by one worker at a time; the last
run is recorded in Postgres so restarts and multiple workers don't repeat it.
"""
from __future__ import annotations

import hashlib
import logging

import psycopg

log = logging.getLogger("duckicelake.maintenance")

_LOCK = int.from_bytes(hashlib.sha256(b"duckicelake:maintenance").digest()[:8],
                       "big", signed=True)


def _ensure(con) -> None:
    con.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_maintenance_run (
            catalog_id TEXT PRIMARY KEY,
            last_run   TIMESTAMPTZ NOT NULL,
            result     JSONB
        )""")


def due_catalogs(con, catalog_ids: list[str], every_hours: float) -> list[str]:
    _ensure(con)
    last = dict(con.execute(
        "SELECT catalog_id, last_run > now() - make_interval(secs => %s) "
        "FROM public.duckicelake_maintenance_run", (every_hours * 3600,)).fetchall())
    return [c for c in catalog_ids if not last.get(c)]


def run_due(settings, registry) -> dict[str, dict]:
    """Maintain every catalog that is due. Returns {catalog_id: result}."""
    import json
    if settings.maintenance_hours <= 0:
        return {}
    out: dict[str, dict] = {}
    with psycopg.connect(settings.pg_dsn, autocommit=True) as con:
        if not con.execute("SELECT pg_try_advisory_lock(%s)", (_LOCK,)).fetchone()[0]:
            return {}
        try:
            ids = [cid for cid, _ref in registry.list_refs()]
            for cid in due_catalogs(con, ids, settings.maintenance_hours):
                try:
                    res = registry.get(cid).catalog.maintain(
                        retain_days=settings.snapshot_retention_days,
                        file_grace_hours=settings.file_grace_hours)
                except Exception as e:
                    log.exception("maintenance failed for %s", cid)
                    res = {"error": str(e)[:300]}
                con.execute(
                    "INSERT INTO public.duckicelake_maintenance_run VALUES (%s, now(), %s) "
                    "ON CONFLICT (catalog_id) DO UPDATE SET last_run = now(), result = EXCLUDED.result",
                    (cid, json.dumps(res)))
                out[cid] = res
                log.info("maintenance %s: %s", cid, res)
        finally:
            con.execute("SELECT pg_advisory_unlock(%s)", (_LOCK,))
    return out
