"""Auto-compaction, the orphan sweep and the metadata indexes — each on a
catalog of its own, so rewriting files can't disturb other tests."""
from __future__ import annotations

import dataclasses
import uuid

import psycopg
import pytest

from duckicelake import maintenance, s3util
from duckicelake.registry import CatalogRegistry

from conftest import TEST_S3_ROOT

MIN_FILES = 8


@pytest.fixture
def lake(settings):
    cid = f"cp_{uuid.uuid4().hex[:6]}"
    schema = f"dl_{cid}"
    prefix = f"{TEST_S3_ROOT}{cid}/"
    reg = CatalogRegistry(settings)
    ctx = reg.provision(cid, schema, prefix)
    ctx.catalog.create_namespace(["s"])
    try:
        yield reg, ctx, cid, schema, prefix
    finally:
        reg.close_all()
        with psycopg.connect(settings.pg_dsn, autocommit=True) as c:
            c.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            c.execute("DELETE FROM public.duckicelake_catalog WHERE catalog_id = %s", [cid])
        s3c = s3util.s3_client(settings.s3)
        for page in s3c.get_paginator("list_objects_v2").paginate(
                Bucket=settings.s3.bucket, Prefix=prefix):
            objs = [{"Key": o["Key"]} for o in page.get("Contents") or []]
            if objs:
                s3c.delete_objects(Bucket=settings.s3.bucket, Delete={"Objects": objs})


def _small_writes(ctx, cid: str, table: str, n: int) -> None:
    with ctx.catalog.cursor() as c:
        c.execute(f'CREATE TABLE "{cid}"."s"."{table}" (id INTEGER, v VARCHAR)')
        for i in range(n):
            c.execute(f'INSERT INTO "{cid}"."s"."{table}" '
                      f"SELECT i, 'v' || i FROM range({i * 10}, {i * 10 + 10}) r(i)")


def _live_files(settings, schema: str, table: str) -> int:
    with psycopg.connect(settings.pg_dsn) as c:
        return c.execute(
            f"""SELECT count(*) FROM "{schema}".ducklake_data_file f
                JOIN "{schema}".ducklake_table t USING (table_id)
                WHERE t.table_name = %s AND t.end_snapshot IS NULL
                  AND f.end_snapshot IS NULL""", (table,)).fetchone()[0]


def _candidates(ctx):
    return ctx.catalog.compaction_candidates(
        min_files=MIN_FILES, small_file_bytes=64 << 20, delete_ratio=0.2)


def test_small_files_are_found_and_merged(settings, lake):
    _reg, ctx, cid, schema, _ = lake
    _small_writes(ctx, cid, "t", MIN_FILES + 2)
    _small_writes(ctx, cid, "few", 2)
    assert _candidates(ctx) == [("s", "t")]          # "few" is under the threshold

    res = ctx.catalog.compact(_candidates(ctx))
    assert res["files_merged"] == MIN_FILES + 2
    assert _live_files(settings, schema, "t") == 1
    assert _live_files(settings, schema, "few") == 2     # untouched
    with ctx.catalog.cursor() as c:
        assert c.execute(f'SELECT count(*), sum(id) FROM "{cid}"."s"."t"').fetchone() == (
            (MIN_FILES + 2) * 10, sum(range((MIN_FILES + 2) * 10)))
    assert _candidates(ctx) == []
    # nothing left to do → no new snapshot
    with ctx.catalog.pg_cursor() as cur:
        before = cur.execute(f'SELECT max(snapshot_id) FROM "{schema}".ducklake_snapshot').fetchone()
        ctx.catalog.compact([("s", "t")])
        after = cur.execute(f'SELECT max(snapshot_id) FROM "{schema}".ducklake_snapshot').fetchone()
    assert before == after


def test_delete_heavy_files_are_rewritten(settings, lake):
    _reg, ctx, cid, schema, _ = lake
    _small_writes(ctx, cid, "d", 1)
    with ctx.catalog.cursor() as c:
        c.execute(f'DELETE FROM "{cid}"."s"."d" WHERE id % 2 = 0')
    assert _candidates(ctx) == [("s", "d")]
    res = ctx.catalog.compact([("s", "d")], delete_ratio=0.2)
    assert res["files_rewritten"] == 1
    with psycopg.connect(settings.pg_dsn) as c:
        assert c.execute(f'SELECT count(*) FROM "{schema}".ducklake_delete_file '
                         "WHERE end_snapshot IS NULL").fetchone()[0] == 0
    with ctx.catalog.cursor() as c:
        assert c.execute(f'SELECT count(*) FROM "{cid}"."s"."d"').fetchone()[0] == 5


def test_auto_compact_false_opts_a_table_out(settings, lake):
    _reg, ctx, cid, schema, _ = lake
    _small_writes(ctx, cid, "keep", MIN_FILES)
    with ctx.catalog.cursor() as c:
        c.execute(f"CALL \"{cid}\".set_option('auto_compact', false, "
                  "table_name => 'keep', schema => 's')")
    assert _candidates(ctx) == []
    ctx.catalog.compact(None)
    assert _live_files(settings, schema, "keep") == MIN_FILES


def test_run_compaction_compacts_only_what_needs_it(settings, lake):
    reg, ctx, cid, schema, _ = lake
    _small_writes(ctx, cid, "t", MIN_FILES)

    class OneCatalog:                      # leave the suite's other catalogs alone
        def list_refs(self):
            return [(cid, ctx.ref)]

        def get(self, catalog_id):
            return reg.get(catalog_id)

    s = dataclasses.replace(settings, compaction_min_files=MIN_FILES)
    out = maintenance.run_compaction(s, OneCatalog())
    assert out[cid]["tables"] == ["s.t"] and out[cid]["files_merged"] == MIN_FILES
    assert maintenance.run_compaction(s, OneCatalog()) == {}       # nothing due


def test_orphan_sweep_deletes_only_ducklake_data_files(settings, lake):
    """DuckLake calls every untracked Parquet file under the data path an
    orphan; masked exports, Iceberg metadata and foreign files live there
    too and must survive."""
    _reg, ctx, cid, _schema, prefix = lake
    _small_writes(ctx, cid, "t", 1)
    s3c = s3util.s3_client(settings.s3)
    b = settings.s3.bucket
    keys = {
        "orphan": f"{prefix}s/t/ducklake-{uuid.uuid4()}.parquet",
        "export": f"{prefix}__masked__/s/t/abc/snap-1-x/part-0.parquet",
        "iceberg": f"{prefix}s/t/metadata/ducklake-{uuid.uuid4()}.parquet",
        "foreign": f"{prefix}s/t/00000-0-{uuid.uuid4()}.parquet",
    }
    for k in keys.values():
        s3c.put_object(Bucket=b, Key=k, Body=b"PAR1")
    n = ctx.catalog.sweep_orphans(older_than_hours=-1)
    assert n == 1

    def exists(k):
        try:
            s3c.head_object(Bucket=b, Key=k)
            return True
        except Exception:
            return False
    assert not exists(keys["orphan"])
    assert all(exists(keys[k]) for k in ("export", "iceberg", "foreign"))
    with ctx.catalog.cursor() as c:                 # committed data untouched
        assert c.execute(f'SELECT count(*) FROM "{cid}"."s"."t"').fetchone()[0] == 10


def test_orphan_sweep_skips_nested_catalog_paths(settings, lake):
    _reg, ctx, cid, _schema, prefix = lake
    _small_writes(ctx, cid, "t", 1)
    s3c = s3util.s3_client(settings.s3)
    nested = f"{prefix}s/other/"
    key = f"{nested}ducklake-{uuid.uuid4()}.parquet"
    s3c.put_object(Bucket=settings.s3.bucket, Key=key, Body=b"PAR1")
    n = ctx.catalog.sweep_orphans(
        older_than_hours=-1,
        other_data_paths=[f"s3://{settings.s3.bucket}/{nested}"])
    assert n == 0
    s3c.head_object(Bucket=settings.s3.bucket, Key=key)


def test_metadata_indexes_are_created_once(settings, lake):
    _reg, ctx, _cid, schema, _ = lake
    assert ctx.catalog.ensure_metadata_indexes() > 0
    assert ctx.catalog.ensure_metadata_indexes() == 0
    with psycopg.connect(settings.pg_dsn) as c:
        names = {r[0] for r in c.execute(
            "SELECT indexname FROM pg_indexes WHERE schemaname = %s", (schema,)).fetchall()}
    assert {"duckicelake_ix_table_table_id", "duckicelake_ix_data_file_table_id",
            "duckicelake_ix_file_column_stats_table_id"} <= names


def test_full_maintenance_compacts_and_reports(settings, lake):
    _reg, ctx, cid, schema, _ = lake
    _small_writes(ctx, cid, "t", 3)
    res = ctx.catalog.maintain(retain_days=7, file_grace_hours=24)
    assert res["files_merged"] == 3 and "orphans_deleted" in res and "indexes_created" in res
    assert _live_files(settings, schema, "t") == 1
