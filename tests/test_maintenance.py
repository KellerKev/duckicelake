"""Scheduled maintenance expires old snapshots — dropping the metadata of
tables dropped since, including their column statistics — and records each
run so workers and restarts don't repeat it."""
from __future__ import annotations

import dataclasses
import uuid

import psycopg

from duckicelake import maintenance
from duckicelake.catalog import DuckLakeCatalog
from duckicelake.registry import CatalogRegistry

from conftest import TEST_S3_ROOT


def _dead_stats(settings, schema: str) -> int:
    with psycopg.connect(settings.pg_dsn) as c:
        return c.execute(
            f"""SELECT count(*) FROM "{schema}".ducklake_table_column_stats s
                WHERE NOT EXISTS (SELECT 1 FROM "{schema}".ducklake_table t
                                  WHERE t.table_id = s.table_id AND t.end_snapshot IS NULL)"""
        ).fetchone()[0]


def test_maintain_drops_dead_table_metadata(settings):
    """On a catalog of its own: expiring every snapshot must not disturb
    other tests sharing the default test catalog."""
    cid = f"mt_{uuid.uuid4().hex[:6]}"
    schema = f"dl_{cid}"
    reg = CatalogRegistry(settings)
    try:
        ctx = reg.provision(cid, schema, f"{TEST_S3_ROOT}{cid}/")
        ctx.catalog.create_namespace(["s"])
        with ctx.catalog.cursor() as c:
            c.execute(f'CREATE TABLE "{cid}"."s"."gone" (id INTEGER, v VARCHAR)')
            c.execute(f'INSERT INTO "{cid}"."s"."gone" VALUES (1, \'a\')')
            c.execute(f'DROP TABLE "{cid}"."s"."gone"')
        assert _dead_stats(settings, schema) > 0
        res = ctx.catalog.maintain(retain_days=0, file_grace_hours=0)
        assert res["snapshots_expired"] > 0
        assert _dead_stats(settings, schema) == 0
    finally:
        reg.close_all()
        with psycopg.connect(settings.pg_dsn, autocommit=True) as c:
            c.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            c.execute("DELETE FROM public.duckicelake_catalog WHERE catalog_id = %s", [cid])


def test_run_due_records_runs_and_respects_interval(settings, monkeypatch):
    s = dataclasses.replace(settings, maintenance_hours=24, snapshot_retention_days=7)
    reg = CatalogRegistry(s)
    ran: list[str] = []
    monkeypatch.setattr(DuckLakeCatalog, "maintain",
                        lambda self, **k: ran.append(self._ref.catalog_name) or {"ok": 1})
    with psycopg.connect(s.pg_dsn, autocommit=True) as c:
        c.execute("DROP TABLE IF EXISTS public.duckicelake_maintenance_run")
    try:
        first = maintenance.run_due(s, reg)
        assert s.catalog_name in first and s.catalog_name in ran
        ran.clear()
        assert maintenance.run_due(s, reg) == {} and ran == []     # not due again yet
    finally:
        reg.close_all()
