"""Eager DuckLake-to-Iceberg materialisation via PG NOTIFY.

A DuckLake-direct write (DuckDB ATTACHing `ducklake:` and INSERTing)
should produce a metadata.json on S3 within ~1s — without any
LoadTable request driving the lazy path.

Tests assume the conftest proxy is running (which spawns the notify
listener via lifespan). The listener acquires the advisory lock on
boot, runs the catch-up scan, and starts LISTEN-ing.
"""
from __future__ import annotations

import time
import uuid

from duckicelake import s3util
import duckdb
import psycopg
import pytest


def _ns(suffix: str) -> str:
    return f"notify_{suffix}_{uuid.uuid4().hex[:6]}"


def _wait_for(predicate, timeout: float = 10.0, interval: float = 0.25):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    return last


def test_sidecar_and_trigger_installed(settings):
    """Listener startup installs the trigger + log table idempotently."""
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute(
            "SELECT to_regclass('public.duckicelake_materialisation_log')"
        )
        assert cur.fetchone()[0] is not None
        cur.execute(
            """
            SELECT 1 FROM pg_trigger
            WHERE tgname = 'duckicelake_snapshot_notify'
              AND NOT tgisinternal
            """
        )
        assert cur.fetchone() is not None


def test_tables_touched_by_snapshot(client, settings):
    """Helper resolves snapshot → (schema, table) via the data-file join."""
    from duckicelake.catalog import DuckLakeCatalog

    ns = _ns("touch")
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    client.post(
        f"/v1/lake/namespaces/{ns}/tables",
        json={
            "name": "t1",
            "schema": {
                "type": "struct", "schema-id": 0,
                "fields": [
                    {"id": 1, "name": "x", "required": True, "type": "long"},
                ],
            },
        },
    ).raise_for_status()

    # Add a data file via DuckLake-direct INSERT — the catch is that
    # this happens inside the proxy's DuckDB session, so we use a fresh
    # `ducklake:postgres:` ATTACH in our own DuckDB.
    s3 = settings.s3
    con = duckdb.connect(":memory:")
    for ext in ("ducklake", "postgres", "httpfs"):
        con.execute(f"INSTALL {ext}")
        con.execute(f"LOAD {ext}")
    con.execute(
        f"""
        CREATE OR REPLACE SECRET ext_s3 (
            TYPE S3, KEY_ID '{s3.root_access_key}',
            SECRET '{s3.root_secret_key}', REGION '{s3.region}',
            ENDPOINT '{s3.host}', USE_SSL {str(s3.use_ssl).lower()},
            URL_STYLE '{"path" if s3.path_style else "vhost"}'
        )
        """
    )
    con.execute(
        f"ATTACH 'ducklake:postgres:{settings.pg_dsn}' AS lk "
        f"(DATA_PATH 's3://{s3.bucket}/{s3.data_prefix}', "
        f" DATA_INLINING_ROW_LIMIT 0)"
    )
    con.execute(f'USE lk."{ns}"')
    con.execute("INSERT INTO t1 VALUES (1), (2), (3)")
    con.close()

    # Inspect the most recent ducklake_snapshot — the DuckLake-direct
    # INSERT above produced it.
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute(
            "SELECT max(snapshot_id) FROM public.ducklake_snapshot"
        )
        latest_snap = cur.fetchone()[0]
    assert latest_snap is not None

    catalog = DuckLakeCatalog(settings)
    catalog.connect()
    try:
        touched = catalog.tables_touched_by_snapshot(latest_snap)
        assert (ns, "t1") in touched
    finally:
        catalog.close()


def test_ducklake_direct_write_triggers_eager_materialisation(client, settings):
    """End-to-end: a DuckLake-direct INSERT triggers NOTIFY → listener
    runs materialise_table → metadata.json appears on S3 → log row is
    'done'. All without any LoadTable request."""
    ns = _ns("eager")
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    client.post(
        f"/v1/lake/namespaces/{ns}/tables",
        json={
            "name": "t1",
            "schema": {
                "type": "struct", "schema-id": 0,
                "fields": [
                    {"id": 1, "name": "x", "required": True, "type": "long"},
                ],
            },
        },
    ).raise_for_status()

    # Capture the metadata key set BEFORE the DuckLake-direct write so
    # we can detect a new vN.metadata.json arriving without a LoadTable.
    s3 = settings.s3
    s3c = s3util.s3_client(s3)
    metadata_prefix = f"{s3.data_prefix}{ns}/t1/metadata/"
    before = {
        o["Key"]
        for page in s3c.get_paginator("list_objects_v2")
                       .paginate(Bucket=s3.bucket, Prefix=metadata_prefix)
        for o in page.get("Contents", [])
    }

    # DuckLake-direct write.
    con = duckdb.connect(":memory:")
    for ext in ("ducklake", "postgres", "httpfs"):
        con.execute(f"INSTALL {ext}")
        con.execute(f"LOAD {ext}")
    con.execute(
        f"""
        CREATE OR REPLACE SECRET ext_s3 (
            TYPE S3, KEY_ID '{s3.root_access_key}',
            SECRET '{s3.root_secret_key}', REGION '{s3.region}',
            ENDPOINT '{s3.host}', USE_SSL {str(s3.use_ssl).lower()},
            URL_STYLE '{"path" if s3.path_style else "vhost"}'
        )
        """
    )
    con.execute(
        f"ATTACH 'ducklake:postgres:{settings.pg_dsn}' AS lk "
        f"(DATA_PATH 's3://{s3.bucket}/{s3.data_prefix}', "
        f" DATA_INLINING_ROW_LIMIT 0)"
    )
    con.execute(f'USE lk."{ns}"')
    con.execute("INSERT INTO t1 VALUES (1), (2), (3)")
    con.close()

    # Wait for either: (a) a new vN.metadata.json under the table
    # prefix, or (b) a `done` row in the materialisation log. Both
    # should occur; checking either is enough.
    def _new_metadata():
        after = {
            o["Key"]
            for page in s3c.get_paginator("list_objects_v2")
                           .paginate(Bucket=s3.bucket, Prefix=metadata_prefix)
            for o in page.get("Contents", [])
        }
        # Wait specifically for the vN.metadata.json — the materialisation
        # writes manifest `.avro` files first, so on an eventually-consistent
        # backend (Hetzner) a plain "any new key" check races and returns the
        # manifests before the metadata.json is listed.
        return {k for k in (after - before) if k.endswith(".metadata.json")}

    diff = _wait_for(_new_metadata, timeout=30.0)
    assert diff, (
        "expected a new vN.metadata.json under "
        f"{metadata_prefix} after DuckLake-direct INSERT; saw none"
    )

    # And the log row should be 'done'.
    def _log_done():
        with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
            cur.execute(
                """
                SELECT ducklake_snapshot_id, status
                FROM public.duckicelake_materialisation_log
                WHERE status = 'done'
                ORDER BY materialised_at DESC LIMIT 1
                """
            )
            return cur.fetchone()

    row = _wait_for(_log_done, timeout=30.0)
    assert row is not None, "no 'done' row in duckicelake_materialisation_log"
