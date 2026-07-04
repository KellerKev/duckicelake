#!/usr/bin/env python3
"""Idempotently seed 3 rows into analytics.events via DuckLake-direct.

Called by governance_demo.sh so the lakesh demo has real bytes to mask.
Writes through the same DuckLake path a client would; the proxy's eager
materialiser turns the commit into an Iceberg snapshot ~1s later.
"""
from __future__ import annotations

import duckdb

from duckicelake.config import load_settings

ROWS = [
    (1, "alice@example.com", "EU"),
    (2, "bob@personal.io", "US"),
    (3, "carol@work.net", "EU"),
]


def main() -> int:
    s = load_settings()
    s3 = s.s3
    con = duckdb.connect(":memory:")
    for ext in ("ducklake", "postgres", "httpfs"):
        con.execute(f"INSTALL {ext}")
        con.execute(f"LOAD {ext}")
    con.execute(
        """
        CREATE OR REPLACE SECRET demo_s3 (
            TYPE S3, KEY_ID ?, SECRET ?, REGION ?, ENDPOINT ?,
            USE_SSL ?, URL_STYLE ?)
        """,
        [s3.root_access_key, s3.root_secret_key, s3.region, s3.host,
         s3.use_ssl, "path" if s3.path_style else "vhost"],
    )
    con.execute(
        f"ATTACH 'ducklake:postgres:{s.pg_dsn}' AS lake "
        f"(DATA_PATH 's3://{s3.bucket}/{s3.data_prefix}', "
        f" DATA_INLINING_ROW_LIMIT 0)"
    )
    n = con.execute('SELECT count(*) FROM lake."analytics"."events"').fetchone()[0]
    if n == 0:
        con.executemany('INSERT INTO lake."analytics"."events" VALUES (?, ?, ?)',
                        ROWS)
        print(f"seeded {len(ROWS)} rows into analytics.events")
    else:
        print(f"analytics.events already has {n} rows")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
