"""SQL proof for the governance demo: show masked vs unmasked *rows*.

Phase 2 stamps masking signals into LoadTable metadata and emits the
view-fallback SQL. This script makes that concrete by running the SQL and
printing rows:

  1. Fetches the **live** policy decision for a principal from the running
     proxy (`effective-policies`) — this reflects the real tag / policy /
     role state you authored, and differs per principal (bob masked, alice
     not).
  2. Applies that engine-generated SQL to the sample rows so you can see the
     masking take effect: full emails vs `al***`.

The rows are loaded into a local DuckDB rather than read DuckLake-direct on
purpose — reading the live catalog concurrently with the proxy's async
materialisation listener is flaky, and the data isn't what we're proving
here (the policy decision + masking transform are). The same view SQL runs
unchanged against the real `analytics.events` table.

Usage:  pixi run python scripts/sql_proof.py [principal]      # default: bob
Env:    BASE   proxy base URL (default http://127.0.0.1:8181)
"""
from __future__ import annotations

import os
import sys

import duckdb
import httpx

BASE = os.environ.get("BASE", "http://127.0.0.1:8181")
PREFIX = "lake"
SCHEMA, TABLE = "analytics", "events"
PRINCIPAL = sys.argv[1] if len(sys.argv) > 1 else "bob"

# Illustrative rows (same shape as analytics.events: id, email, country).
SAMPLE = [
    (1, "alice@example.com", "EU"),
    (2, "bob@personal.io", "US"),
    (3, "carol@work.net", "EU"),
]


def _print_table(title: str, sql: str, con) -> None:
    res = con.execute(sql)
    rows = res.fetchall()
    cols = [d[0] for d in res.description]
    print(f"\n--- {title} ---")
    print(f"    SQL: {sql}")
    widths = [max(len(str(c)), *(len(str(r[i])) for r in rows)) if rows else len(str(c))
              for i, c in enumerate(cols)]
    line = "  " + " | ".join(str(c).ljust(widths[i]) for i, c in enumerate(cols))
    print(line)
    print("  " + "-" * (len(line) - 2))
    for r in rows:
        print("  " + " | ".join(str(v).ljust(widths[i]) for i, v in enumerate(r)))


def main() -> int:
    # 1. Live policy decision from the proxy (reflects the real catalog).
    try:
        eff = httpx.get(
            f"{BASE}/v1/{PREFIX}/governance/effective-policies",
            params={"table": f"{SCHEMA}.{TABLE}", "principal": PRINCIPAL}, timeout=30,
        )
    except Exception as e:  # noqa: BLE001
        print(f"!! cannot reach proxy at {BASE}: {e}", file=sys.stderr)
        return 1
    if eff.status_code >= 400:
        print(f"!! effective-policies failed: HTTP {eff.status_code}: {eff.text}",
              file=sys.stderr)
        return 1
    enforcement = eff.json().get("enforcement", {})
    view_sql = enforcement.get("view_sql")
    masked_cols = enforcement.get("masked_columns", [])
    print(f"live policy decision for principal '{PRINCIPAL}': "
          f"masked_columns={masked_cols}")

    # 2. Load the sample rows into a local DuckDB (deterministic; no catalog race).
    con = duckdb.connect(":memory:")
    con.execute(f'CREATE SCHEMA "{SCHEMA}"')
    con.execute(f'CREATE TABLE "{SCHEMA}"."{TABLE}" (id BIGINT, email VARCHAR, country VARCHAR)')
    con.executemany(f'INSERT INTO "{SCHEMA}"."{TABLE}" VALUES (?, ?, ?)', SAMPLE)

    _print_table("UNMASKED base table (what a privileged reader / unmasked role sees)",
                 f'SELECT id, email, country FROM "{SCHEMA}"."{TABLE}" ORDER BY id', con)

    if view_sql:
        _print_table(f"MASKED projection for principal '{PRINCIPAL}' "
                     f"(engine-generated view-fallback SQL, fetched live)",
                     f"{view_sql} ORDER BY id", con)
        print(f"\n=> '{PRINCIPAL}' sees masked email (al***); the base rows are unchanged.")
    else:
        print(f"\n=> principal '{PRINCIPAL}' has no masking "
              f"(holds an unmasked role) — sees the base table above as-is.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
