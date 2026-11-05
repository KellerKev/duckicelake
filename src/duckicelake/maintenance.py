"""Scheduled DuckLake maintenance for every catalog this proxy serves.

DuckLake only cleans up when asked: without it, small files from frequent
small writes, expired snapshots, their metadata rows (including statistics
of long-dropped tables, which every commit re-reads) and unreferenced files
pile up forever. Two schedules, one worker at a time across processes:

  * `run_due` — the full pass, once per `maintenance_hours` per catalog
    (compact, expire, clean up files and orphans, metadata indexes); the
    last run is recorded in Postgres so restarts and multiple workers
    don't repeat it.
  * `run_compaction` — every `compaction_check_seconds`: a cheap metadata
    query per catalog finds tables with many small files or delete-heavy
    files, and only those are compacted (auto-compaction).
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
            refs = registry.list_refs()
            ids = [cid for cid, _ref in refs]
            paths = [settings.data_path_for(ref) for _cid, ref in refs]
            for cid in due_catalogs(con, ids, settings.maintenance_hours):
                try:
                    res = registry.get(cid).catalog.maintain(
                        retain_days=settings.snapshot_retention_days,
                        file_grace_hours=settings.file_grace_hours,
                        delete_ratio=settings.compaction_delete_ratio,
                        orphans=settings.orphan_sweep,
                        indexes=settings.catalog_indexes,
                        other_data_paths=paths)
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


def run_compaction(settings, registry) -> dict[str, dict]:
    """Compact the tables that need it in every catalog. Skipped while
    another worker holds the maintenance lock (a full pass compacts too)."""
    if settings.compaction_check_seconds <= 0:
        return {}
    out: dict[str, dict] = {}
    with psycopg.connect(settings.pg_dsn, autocommit=True) as con:
        if not con.execute("SELECT pg_try_advisory_lock(%s)", (_LOCK,)).fetchone()[0]:
            return {}
        try:
            for cid, _ref in registry.list_refs():
                try:
                    cat = registry.get(cid).catalog
                    tables = cat.compaction_candidates(
                        min_files=settings.compaction_min_files,
                        small_file_bytes=settings.compaction_small_file_bytes,
                        delete_ratio=settings.compaction_delete_ratio)
                    if not tables:
                        continue
                    res = cat.compact(tables, delete_ratio=settings.compaction_delete_ratio)
                    res["tables"] = [f"{s}.{t}" for s, t in tables]
                except Exception as e:
                    log.exception("compaction failed for %s", cid)
                    res = {"error": str(e)[:300]}
                out[cid] = res
                if res.get("files_merged") or res.get("files_rewritten") or res.get("error"):
                    log.info("compaction %s: %s", cid, res)
        finally:
            con.execute("SELECT pg_advisory_unlock(%s)", (_LOCK,))
    return out
