"""Probe: can a DuckLake-direct DuckDB session be transparently re-routed to
a masking schema for *unqualified* table names?

Two variants, decided before wiring `transparent=true` into the
ducklake-credentials endpoint (governance Phase 3):

  1. DuckDB-side `SET search_path = '<cat>.__masked_x,<cat>.<ns>'` after
     ATTACH — expected to work (DuckDB resolves unqualified relations
     through its own catalog search path).
  2. libpq `options=-c search_path=…` smuggled into the ATTACH DSN —
     expected to be a no-op: it sets the *Postgres* session path used for
     DuckLake metadata queries, not DuckDB's binder.

Run with the pixi stack up (Postgres + MinIO):  pixi run python scripts/probe_searchpath.py
Exit code 0 if variant 1 works (transparent mode shippable), 1 otherwise.
"""
from __future__ import annotations

import sys
import uuid

import duckdb

sys.path.insert(0, "src")
from duckicelake.config import load_settings  # noqa: E402


def _attach(con: duckdb.DuckDBPyConnection, dsn: str, s3, alias: str) -> None:
    for ext in ("ducklake", "postgres", "httpfs"):
        con.execute(f"INSTALL {ext}")
        con.execute(f"LOAD {ext}")
    con.execute(
        f"""
        CREATE OR REPLACE SECRET probe_s3 (
            TYPE S3, KEY_ID '{s3.root_access_key}',
            SECRET '{s3.root_secret_key}', REGION '{s3.region}',
            ENDPOINT '{s3.host}', USE_SSL {str(s3.use_ssl).lower()},
            URL_STYLE '{"path" if s3.path_style else "vhost"}'
        )
        """
    )
    con.execute(
        f"ATTACH 'ducklake:postgres:{dsn}' AS {alias} "
        f"(DATA_PATH 's3://{s3.bucket}/{s3.data_prefix}', "
        f" DATA_INLINING_ROW_LIMIT 0)"
    )


def main() -> int:
    settings = load_settings()
    s3 = settings.s3
    tag = uuid.uuid4().hex[:6]
    base = f"probe_base_{tag}"
    masked = f"probe_masked_{tag}"

    setup = duckdb.connect(":memory:")
    _attach(setup, settings.pg_dsn, s3, "lk")
    setup.execute(f'CREATE SCHEMA lk."{base}"')
    setup.execute(f'CREATE TABLE lk."{base}".events(email VARCHAR)')
    setup.execute(f'INSERT INTO lk."{base}".events VALUES (\'alice@x.com\')')
    setup.execute(f'CREATE SCHEMA lk."{masked}"')
    setup.execute(
        f'CREATE VIEW lk."{masked}".events AS '
        f'SELECT left(email,2)||\'***\' AS email FROM "{base}".events'
    )
    setup.close()

    verdicts: dict[str, bool] = {}

    # Variant 1: DuckDB-side SET search_path
    con = duckdb.connect(":memory:")
    _attach(con, settings.pg_dsn, s3, "lk")
    try:
        con.execute(f"SET search_path = 'lk.{masked},lk.{base}'")
        row = con.execute("SELECT email FROM events").fetchone()
        verdicts["duckdb_set_search_path"] = row is not None and row[0] == "al***"
        print(f"variant 1 (SET search_path): SELECT email FROM events -> {row}")
    except Exception as exc:  # noqa: BLE001
        verdicts["duckdb_set_search_path"] = False
        print(f"variant 1 (SET search_path) failed: {exc}")
    finally:
        con.close()

    # Variant 2: libpq options=-c search_path in the ATTACH DSN
    con = duckdb.connect(":memory:")
    dsn2 = f"{settings.pg_dsn} options=-csearch_path={masked},{base},public"
    try:
        _attach(con, dsn2, s3, "lk2")
        row = con.execute("SELECT email FROM events").fetchone()
        verdicts["libpq_options_search_path"] = row is not None and row[0] == "al***"
        print(f"variant 2 (DSN options): SELECT email FROM events -> {row}")
    except Exception as exc:  # noqa: BLE001
        verdicts["libpq_options_search_path"] = False
        print(f"variant 2 (DSN options) failed: {exc}")
    finally:
        con.close()

    # cleanup
    cleanup = duckdb.connect(":memory:")
    _attach(cleanup, settings.pg_dsn, s3, "lk")
    cleanup.execute(f'DROP VIEW lk."{masked}".events')
    cleanup.execute(f'DROP SCHEMA lk."{masked}"')
    cleanup.execute(f'DROP TABLE lk."{base}".events')
    cleanup.execute(f'DROP SCHEMA lk."{base}"')
    cleanup.close()

    print(f"\nverdicts: {verdicts}")
    transparent_ok = verdicts["duckdb_set_search_path"]
    print("transparent mode shippable (post_attach_sql SET search_path):",
          transparent_ok)
    return 0 if transparent_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
