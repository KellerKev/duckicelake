"""Optional sample-data seed for a local/dev stack.

    pixi run seed                     # load the sample dataset (data only)
    pixi run seed-governed            # ...and author the demo masking policy

Creates the `analytics.customers` + `analytics.orders` tables (matching the
README worked example) and inserts a handful of rows in two batches, so there
are >=2 snapshots and the time-travel query examples are real. Idempotent —
re-running skips a table that already has rows.

`--with-governance` additionally authors the demo masking policy in-process
(no running proxy needed): a `pii.email` tag on `customers.email`, a
`mask_email` masking policy bypassed by the `pii_reader` role, and a grant of
that role to principal `alice`. So `alice` reads cleartext email and everyone
else sees it masked.
"""
from __future__ import annotations

import argparse

from .bootstrap import ensure_bucket
from .catalog import DuckLakeCatalog
from .config import load_settings

NAMESPACE = "analytics"

# (table, columns DDL, list of VALUES-row literals) — DuckLake assigns Iceberg
# field-ids on create; the proxy materialises metadata from the catalog tables.
TABLES: dict[str, str] = {
    "customers": (
        '"id" BIGINT, "email" VARCHAR, "phone" VARCHAR, '
        '"country" VARCHAR, "mrr" DOUBLE'
    ),
    "orders": (
        '"id" BIGINT, "customer_id" BIGINT, "amount" DOUBLE, '
        '"status" VARCHAR, "created_at" VARCHAR'
    ),
}

CUSTOMERS_ROWS = [
    "(1, 'alice@example.com',  '+1-202-555-0143', 'US', 1200.0)",
    "(2, 'bob@personal.io',    '+44-20-7946-0958', 'GB', 0.0)",
    "(3, 'carol@work.net',     '+49-30-901820',    'DE', 540.0)",
    "(4, 'dan@startup.dev',    '+1-415-555-0199',  'US', 89.0)",
    "(5, 'eve@altmail.fr',     '+33-1-70180090',   'FR', 320.0)",
    "(6, 'frank@corp.co.uk',   '+44-161-496-0142', 'GB', 4800.0)",
    "(7, 'grace@studio.de',    '+49-89-12345678',  'DE', 0.0)",
    "(8, 'heidi@indie.fr',     '+33-4-91130000',   'FR', 150.0)",
]

# Two batches → two snapshots with data, so time-travel has something to show.
ORDERS_BATCH_1 = [
    "(101, 1, 49.00,  'paid',     '2026-01-04')",
    "(102, 1, 12.50,  'paid',     '2026-01-19')",
    "(103, 3, 540.00, 'paid',     '2026-02-02')",
    "(104, 4, 89.00,  'refunded', '2026-02-11')",
    "(105, 5, 320.00, 'paid',     '2026-02-23')",
    "(106, 6, 4800.0, 'paid',     '2026-03-01')",
    "(107, 6, 99.00,  'pending',  '2026-03-15')",
    "(108, 8, 150.00, 'paid',     '2026-03-22')",
]
ORDERS_BATCH_2 = [
    "(109, 1, 49.00,  'paid',     '2026-04-02')",
    "(110, 3, 18.00,  'pending',  '2026-04-10')",
    "(111, 4, 89.00,  'paid',     '2026-04-18')",
    "(112, 5, 25.00,  'refunded', '2026-04-25')",
    "(113, 6, 4800.0, 'paid',     '2026-05-01')",
    "(114, 7, 60.00,  'pending',  '2026-05-09')",
    "(115, 8, 150.00, 'paid',     '2026-05-20')",
]


def _qual(cat: DuckLakeCatalog, table: str) -> str:
    return f'"{cat.settings.catalog_name}"."{NAMESPACE}"."{table}"'


def _row_count(cat: DuckLakeCatalog, table: str) -> int:
    with cat.cursor() as c:
        return c.execute(f"SELECT count(*) FROM {_qual(cat, table)}").fetchone()[0]


def _insert(cat: DuckLakeCatalog, table: str, rows: list[str]) -> None:
    with cat.cursor() as c:
        c.execute(f"INSERT INTO {_qual(cat, table)} VALUES {', '.join(rows)}")


def seed_data(cat: DuckLakeCatalog) -> dict[str, int]:
    """Create the sample namespace + tables and insert rows (idempotent).
    Returns the final row count per table."""
    if not cat.namespace_exists([NAMESPACE]):
        cat.create_namespace([NAMESPACE])
        print(f"Created namespace '{NAMESPACE}'.")

    for table, ddl in TABLES.items():
        if not cat.table_exists([NAMESPACE], table):
            cat.create_table([NAMESPACE], table, ddl)
            print(f"Created table '{NAMESPACE}.{table}'.")

    counts: dict[str, int] = {}

    if _row_count(cat, "customers") == 0:
        _insert(cat, "customers", CUSTOMERS_ROWS)
        print(f"Inserted {len(CUSTOMERS_ROWS)} rows into {NAMESPACE}.customers.")
    else:
        print(f"{NAMESPACE}.customers already has rows — skipping insert.")
    counts["customers"] = _row_count(cat, "customers")

    if _row_count(cat, "orders") == 0:
        # Two separate commits → two snapshots with data (time-travel demo).
        _insert(cat, "orders", ORDERS_BATCH_1)
        _insert(cat, "orders", ORDERS_BATCH_2)
        n = len(ORDERS_BATCH_1) + len(ORDERS_BATCH_2)
        print(f"Inserted {n} rows into {NAMESPACE}.orders (in 2 snapshots).")
    else:
        print(f"{NAMESPACE}.orders already has rows — skipping insert.")
    counts["orders"] = _row_count(cat, "orders")

    return counts


def seed_governance(cat: DuckLakeCatalog) -> None:
    """Author the demo masking policy in-process (no proxy required).

    Imported lazily so the data-only seed has no governance dependency on
    branches/builds where the governance layer isn't present."""
    from .governance import GovernanceStore

    store = GovernanceStore(cat)
    who = "seed"
    store.create_tag(who, "pii", "email", None)
    store.assign_object_tag(
        who, object_kind="column", schema_name=NAMESPACE,
        object_name="customers", column_name="email",
        tag_ns="pii", tag_name="email", tag_value=None)
    store.create_masking_policy(
        who, "mask_email", "(val VARCHAR)", "left(val,2)||'***'",
        unmasked_roles=["pii_reader"])
    store.attach_policy(
        who, policy_kind="masking", policy_name="mask_email",
        target_kind="tag", tag_ns="pii", tag_name="email")
    store.create_role(who, "pii_reader")
    store.grant_role(who, "pii_reader", "alice")
    print("Authored governance: pii.email tag + mask_email policy + "
          "pii_reader role (granted to 'alice').")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Load optional sample data.")
    ap.add_argument(
        "--with-governance", action="store_true",
        help="also author the demo masking policy (pii.email / mask_email).")
    args = ap.parse_args(argv)

    settings = load_settings()
    ensure_bucket(settings)

    cat = DuckLakeCatalog(settings)
    cat.connect()
    try:
        counts = seed_data(cat)
        if args.with_governance:
            seed_governance(cat)
    finally:
        cat.close()

    print()
    print("Sample data ready:")
    for table, n in counts.items():
        print(f"  {NAMESPACE}.{table}: {n} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
