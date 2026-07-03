"""End-to-end demo: exercise the full v3 surface of the proxy.

Two Iceberg clients, two tables, zero silent fallbacks:

  * analytics.events    — primitives + decimals. Exercises PyIceberg
    load+scan, PyIceberg time travel, DuckDB iceberg-ext SELECT,
    DuckDB time travel, position-delete handling on both, DDL commit,
    stats inspection, row lineage, view API.

  * analytics.events_v3 — VARIANT + GEOMETRY columns. Exercises v3-type
    wiring end-to-end: schema translation, write via DuckLake, read via
    both REST + direct DuckDB, PyIceberg loads the metadata after we
    teach it the v3 primitives via `pyiceberg_v3.install()`.

Every call path is load-bearing and no exceptions are caught with a
"probably still works" note. If something breaks, the demo crashes.
"""
from __future__ import annotations

import os
import sys

from duckicelake import s3util
import duckdb
import httpx

from .config import load_settings
from .pyiceberg_v3 import install as install_pyiceberg_v3_types


BASE = os.environ.get("DUCKICELAKE_URL", "http://127.0.0.1:8181")


def hr(title: str) -> None:
    print(f"\n=== {title} ===")


def _purge_bucket(s3) -> None:
    c = s3util.s3_client(s3)
    for p in c.get_paginator("list_objects_v2").paginate(Bucket=s3.bucket):
        for o in p.get("Contents", []):
            c.delete_object(Bucket=s3.bucket, Key=o["Key"])


def _list_keys(s3) -> list[str]:
    c = s3util.s3_client(s3)
    keys = []
    for p in c.get_paginator("list_objects_v2").paginate(Bucket=s3.bucket):
        keys.extend(o["Key"] for o in p.get("Contents", []))
    return keys


def _ducklake_con(settings) -> duckdb.DuckDBPyConnection:
    s3 = settings.s3
    con = duckdb.connect(":memory:")
    for e in ("ducklake", "postgres", "httpfs", "spatial"):
        con.execute(f"INSTALL {e}")
        con.execute(f"LOAD {e}")
    # Force session TZ=UTC so TIMESTAMPTZ literals round-trip cleanly. DuckDB's
    # default uses the process's local TZ, which shifts stored micros +/- the
    # local offset and propagates into partition `day` bounds — see
    # iceberg_transforms.py.
    con.execute("SET TimeZone='UTC'")
    con.execute(
        """
        CREATE OR REPLACE SECRET s3 (
            TYPE S3, KEY_ID ?, SECRET ?, REGION ?, ENDPOINT ?,
            USE_SSL ?, URL_STYLE 'path'
        )
        """,
        [s3.root_access_key, s3.root_secret_key, s3.region, s3.host, s3.use_ssl],
    )
    con.execute(
        f"ATTACH '{settings.ducklake_uri}' AS lake "
        f"(DATA_PATH '{settings.ducklake_data_path}', DATA_INLINING_ROW_LIMIT 0)"
    )
    return con


def _iceberg_client_con(s3, bearer_token: str | None = None) -> duckdb.DuckDBPyConnection:
    """DuckDB connection configured to read through our REST catalog.

    `ACCESS_DELEGATION_MODE 'none'` tells the iceberg extension NOT to
    build a REST-config-derived secret (which has a broken path scope and
    causes 403s on position-delete files); it uses the user's SECRET
    instead. Discovered via tracing:
    https://github.com/duckdb/duckdb-iceberg/issues/792 (adjacent).

    When `bearer_token` is provided, we attach a CREATE SECRET (TYPE ICEBERG)
    so the iceberg extension sends `Authorization: Bearer <token>` on its
    REST catalog calls.
    """
    con = duckdb.connect(":memory:")
    for e in ("httpfs", "iceberg"):
        con.execute(f"INSTALL {e}")
        con.execute(f"LOAD {e}")
    con.execute(
        """
        CREATE OR REPLACE SECRET ice_s3 (
            TYPE S3, KEY_ID ?, SECRET ?, REGION ?, ENDPOINT ?,
            USE_SSL ?, URL_STYLE 'path'
        )
        """,
        [s3.root_access_key, s3.root_secret_key, s3.region, s3.host, s3.use_ssl],
    )

    auth_type = "none"
    if bearer_token:
        con.execute(
            "CREATE OR REPLACE SECRET ice_rest (TYPE ICEBERG, TOKEN ?)",
            [bearer_token],
        )
        auth_type = "oauth2"

    con.execute(
        f"ATTACH '{s3.bucket}' AS ice ("
        f"  TYPE ICEBERG, ENDPOINT '{BASE}',"
        f"  AUTHORIZATION_TYPE '{auth_type}',"
        f"  ACCESS_DELEGATION_MODE 'none'"
        f")"
    )
    return con


def _rest(c: httpx.Client, method: str, path: str, **kw) -> httpx.Response:
    r = c.request(method, path, **kw)
    r.raise_for_status()
    return r


def _get_access_token(client_id: str, client_secret: str) -> str | None:
    """Fetch an OAuth2 client-credentials token from the proxy.

    Returns None when the server isn't enforcing auth (501 on the token
    endpoint — the dev default). Raises if config says clients exist but
    the exchange fails; surfaces misconfiguration loudly.
    """
    r = httpx.post(
        f"{BASE}/v1/oauth/tokens",
        data={"grant_type": "client_credentials",
              "client_id": client_id, "client_secret": client_secret},
        timeout=15.0,
    )
    if r.status_code == 501:
        return None
    r.raise_for_status()
    return r.json()["access_token"]


def main() -> int:
    install_pyiceberg_v3_types()
    settings = load_settings()
    s3 = settings.s3
    _purge_bucket(s3)

    # OAuth2 handshake. If the server has auth enabled (DUCKICELAKE_OAUTH_*
    # env vars), every subsequent request needs Bearer <token>. Dev default
    # is auth-disabled → None → we keep running unauthenticated.
    hr("OAuth2: obtain access token (if server requires auth)")
    client_id = os.environ.get("DUCKICELAKE_OAUTH_CLIENT_ID", "demo-client")
    client_secret = os.environ.get("DUCKICELAKE_OAUTH_CLIENT_SECRET", "demo-secret")
    token = _get_access_token(client_id, client_secret)
    auth_headers = {"Authorization": f"Bearer {token}"} if token else {}
    print(f"  auth: {'enabled — got bearer token' if token else 'disabled on server'}")

    # Clean any prior state. Drop every table the demo touches before
    # dropping the namespace, and tolerate idempotent namespace create.
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        for view in ("hot_events",):
            c.delete(f"/v1/lake/namespaces/analytics/views/{view}")
        for tbl in ("events", "events_v3", "orders", "pv", "t"):
            c.delete(f"/v1/lake/namespaces/analytics/tables/{tbl}")
        c.delete("/v1/lake/namespaces/analytics")
        r = c.post("/v1/lake/namespaces", json={"namespace": ["analytics"]})
        if r.status_code not in (200, 409):
            r.raise_for_status()

    # ---------- 1. Primitive-only table ----------
    hr("REST: create analytics.events (primitives)")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        _rest(c, "POST", "/v1/lake/namespaces/analytics/tables", json={
            "name": "events",
            "schema": {
                "type": "struct", "schema-id": 0,
                "fields": [
                    {"id": 1, "name": "id",    "required": True,  "type": "long"},
                    {"id": 2, "name": "name",  "required": False, "type": "string"},
                    {"id": 3, "name": "ts",    "required": False, "type": "timestamptz"},
                    {"id": 4, "name": "price", "required": False, "type": "decimal(10, 2)"},
                ],
            },
        })

    con = _ducklake_con(settings)
    con.execute("INSERT INTO lake.analytics.events VALUES (1,'page_view',TIMESTAMP '2026-04-21 10:00:00+00',9.99), (2,'click',TIMESTAMP '2026-04-21 10:00:05+00',12.50)")
    con.execute("INSERT INTO lake.analytics.events VALUES (3,'conversion',TIMESTAMP '2026-04-21 10:01:00+00',99.00), (4,'page_view',TIMESTAMP '2026-04-21 10:02:00+00',0.00)")
    con.close()

    # ---------- 2. Multi-snapshot + stats inspection ----------
    hr("REST LoadTable: multi-snapshot chain + row lineage + stats")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        lt = _rest(c, "GET", "/v1/lake/namespaces/analytics/tables/events",
                   headers={"X-Iceberg-Access-Delegation": "vended-credentials"}).json()
    md = lt["metadata"]
    print(f"  format-version:     {md['format-version']}")
    print(f"  current-snapshot:   {md['current-snapshot-id']}")
    print(f"  snapshots in chain: {len(md['snapshots'])}")
    for s in md["snapshots"]:
        print(f"    snap {s['snapshot-id']:>3}  parent={s.get('parent-snapshot-id')}  op={s['summary']['operation']}  added_rows={s['summary']['added-records']}")
    print(f"  last-row-id: {md.get('last-row-id')}  row-lineage: {md.get('row-lineage')}")
    print(f"  refs: {md['refs']}")

    hr("Raw-Avro check: manifests encode stats + row_id correctly")
    from fastavro import reader
    import io
    s3_client = s3util.s3_client(s3)
    list_key = md["snapshots"][-1]["manifest-list"].replace(f"s3://{s3.bucket}/", "")
    for mref in reader(io.BytesIO(s3_client.get_object(Bucket=s3.bucket, Key=list_key)["Body"].read())):
        kind = "DATA" if mref["content"] == 0 else "DELETES"
        print(f"  manifest: {mref['manifest_path'].split('/')[-1]}  ({kind})")
        mkey = mref["manifest_path"].replace(f"s3://{s3.bucket}/", "")
        for entry in reader(io.BytesIO(s3_client.get_object(Bucket=s3.bucket, Key=mkey)["Body"].read())):
            df = entry["data_file"]
            print(f"    file: {df['file_path'].split('/')[-1]}  records={df['record_count']}  first_row_id={df.get('first_row_id')}")
            if df.get("lower_bounds"):
                print(f"      lower: {[(e['key'], e['value']) for e in df['lower_bounds']]}")

    # ---------- 3. PyIceberg ----------
    hr("PyIceberg: current + time-travel to first-with-data")
    from pyiceberg.catalog.rest import RestCatalog
    catalog_props = {
        "s3.endpoint": s3.endpoint,
        "s3.access-key-id": s3.root_access_key,
        "s3.secret-access-key": s3.root_secret_key,
        "s3.region": s3.region,
        "s3.path-style-access": "true",
    }
    if token:
        # PyIceberg's OAuth2 client-credentials flow: when `credential` is
        # set, it POSTs to <uri>/v1/oauth/tokens to mint its own token.
        catalog_props["credential"] = f"{client_id}:{client_secret}"
    cat = RestCatalog("lake", uri=BASE, warehouse="lake", **catalog_props)
    t = cat.load_table("analytics.events")
    snaps = t.metadata.snapshots
    current = t.current_snapshot().snapshot_id
    first_with_data = next(s.snapshot_id for s in snaps if int(s.summary["added-records"]) > 0)
    print(f"  snapshots={len(snaps)}  current={current}  first-with-data={first_with_data}")
    print(f"  current: {t.scan().to_arrow().select(['id','name','price']).to_pylist()}")
    print(f"  @{first_with_data}: {t.scan(snapshot_id=first_with_data).to_arrow().select(['id','name','price']).to_pylist()}")

    # ---------- 4. DuckDB iceberg ext ----------
    hr("DuckDB iceberg ext: current + AT (VERSION => first-with-data)")
    dc = _iceberg_client_con(s3, bearer_token=token)
    print(f"  current: {dc.execute('SELECT id, name FROM ice.analytics.events ORDER BY id').fetchall()}")
    print(f"  @{first_with_data}: {dc.execute(f'SELECT id, name FROM ice.analytics.events AT (VERSION => {first_with_data}) ORDER BY id').fetchall()}")
    dc.close()

    # ---------- 5. Apply DELETE + verify on both clients ----------
    hr("DELETE via DuckLake, then verify both clients see post-delete state")
    con = _ducklake_con(settings)
    con.execute("DELETE FROM lake.analytics.events WHERE id = 2")
    print("  DuckLake raw:", con.execute("SELECT id,name FROM lake.analytics.events ORDER BY id").fetchall())
    con.close()

    dc = _iceberg_client_con(s3, bearer_token=token)
    duckdb_post = dc.execute("SELECT id, name FROM ice.analytics.events ORDER BY id").fetchall()
    print(f"  DuckDB iceberg ext post-delete: {duckdb_post}")
    assert [r[0] for r in duckdb_post] == [1, 3, 4], f"expected [1,3,4] after delete, got {duckdb_post}"
    dc.close()

    t = cat.load_table("analytics.events")
    pyi_post = t.scan().to_arrow().select(['id','name']).to_pylist()
    print(f"  PyIceberg post-delete: {pyi_post}")
    assert [r['id'] for r in pyi_post] == [1, 3, 4], f"expected ids [1,3,4] after delete, got {pyi_post}"

    # ---------- 6. DDL commit ----------
    hr("REST commit: add-schema → new 'channel' column via ALTER TABLE")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        resp = _rest(c, "POST", "/v1/lake/namespaces/analytics/tables/events", json={
            "updates": [
                {"action": "add-schema", "schema": {"type": "struct", "schema-id": 1, "fields": [
                    {"id": 1, "name": "id",    "required": True,  "type": "long"},
                    {"id": 2, "name": "name",  "required": False, "type": "string"},
                    {"id": 3, "name": "ts",    "required": False, "type": "timestamptz"},
                    {"id": 4, "name": "price", "required": False, "type": "decimal(10, 2)"},
                    {"id": 7, "name": "channel","required": False, "type": "string"},
                ]}},
                {"action": "set-current-schema", "schema-id": -1},
            ],
        }).json()
    print(f"  schemas after commit: {len(resp['metadata']['schemas'])}")
    print(f"  current fields: {[f['name'] for f in resp['metadata']['schemas'][-1]['fields']]}")

    # ---------- 7. Iceberg-client writes via PyIceberg.append ----------
    hr("Iceberg-client write: PyIceberg.append → DuckLake registers via ducklake_add_data_files")
    from pyiceberg.schema import Schema
    from pyiceberg.types import NestedField, LongType, StringType
    # Use a fresh table so the demo is deterministic.
    try: cat.drop_table("analytics.orders")
    except Exception: pass
    schema = Schema(
        NestedField(1, "order_id", LongType(), required=False),
        NestedField(2, "customer", StringType(), required=False),
    )
    ot = cat.create_table("analytics.orders", schema=schema)
    print("  created analytics.orders via PyIceberg.create_table")

    import pyarrow as _pa
    ot.append(_pa.table({
        "order_id": _pa.array([101, 102, 103], type=_pa.int64()),
        "customer": _pa.array(["alice", "bob", "carol"], type=_pa.string()),
    }))
    ot = cat.load_table("analytics.orders")
    print(f"  after PyIceberg.append #1: {len(ot.scan().to_arrow())} rows, {len(ot.metadata.snapshots)} snapshots")
    ot.append(_pa.table({
        "order_id": _pa.array([201, 202], type=_pa.int64()),
        "customer": _pa.array(["dave", "eve"], type=_pa.string())
    }))
    ot = cat.load_table("analytics.orders")
    rows = sorted(ot.scan().to_arrow().to_pylist(), key=lambda x: x["order_id"])
    print(f"  after PyIceberg.append #2: {len(rows)} rows, {len(ot.metadata.snapshots)} snapshots")
    assert len(rows) == 5, f"expected 5 rows after two appends, got {len(rows)}"

    # Cross-check: DuckDB iceberg ext sees the PyIceberg-written rows
    dc = _iceberg_client_con(s3, bearer_token=token)
    duckdb_rows = dc.execute("SELECT order_id, customer FROM ice.analytics.orders ORDER BY order_id").fetchall()
    dc.close()
    print(f"  DuckDB iceberg ext reads back: {duckdb_rows}")
    assert duckdb_rows == [(101,'alice'),(102,'bob'),(103,'carol'),(201,'dave'),(202,'eve')]

    # Cross-check: DuckLake SQL sees the same rows
    lc = _ducklake_con(settings)
    duck_rows = lc.execute("SELECT order_id, customer FROM lake.analytics.orders ORDER BY order_id").fetchall()
    lc.close()
    print(f"  DuckLake SQL reads back:      {duck_rows}")
    assert duck_rows == duckdb_rows
    print("  ✓ writes round-trip across PyIceberg → DuckDB iceberg ext → DuckLake SQL")

    # ---------- 7b. PyIceberg.delete(predicate) — position-delete file commit ----------
    hr("Iceberg-client write: PyIceberg.delete(predicate) → ducklake_delete_file")
    from pyiceberg.expressions import EqualTo, GreaterThan
    ot.delete(EqualTo("order_id", 102))
    ot = cat.load_table("analytics.orders")
    after_delete = sorted(ot.scan().to_arrow().to_pylist(), key=lambda x: x["order_id"])
    print(f"  PyIceberg post-delete: {after_delete}")
    assert [r["order_id"] for r in after_delete] == [101, 103, 201, 202], after_delete
    # Cross-check
    dc = _iceberg_client_con(s3, bearer_token=token)
    duckdb_post = dc.execute("SELECT order_id FROM ice.analytics.orders ORDER BY order_id").fetchall()
    dc.close()
    assert [r[0] for r in duckdb_post] == [101, 103, 201, 202]
    print(f"  DuckDB iceberg ext sees:  {duckdb_post}")
    print("  ✓ Iceberg position-delete-file → ducklake_delete_file → cross-client read")

    # ---------- 7c. PyIceberg.overwrite(df, predicate) — overwrite commit ----------
    hr("Iceberg-client write: PyIceberg.overwrite(df, predicate) → tombstone + add")
    ot.overwrite(_pa.table({
        "order_id": _pa.array([900, 901], type=_pa.int64()),
        "customer": _pa.array(["replaced1", "replaced2"], type=_pa.string()),
    }), overwrite_filter=GreaterThan("order_id", 200))
    ot = cat.load_table("analytics.orders")
    after_overwrite = sorted(ot.scan().to_arrow().to_pylist(), key=lambda x: x["order_id"])
    print(f"  PyIceberg post-overwrite: {after_overwrite}")
    assert [r["order_id"] for r in after_overwrite] == [101, 103, 900, 901], after_overwrite
    # Cross-check
    dc = _iceberg_client_con(s3, bearer_token=token)
    duckdb_post = dc.execute("SELECT order_id, customer FROM ice.analytics.orders ORDER BY order_id").fetchall()
    dc.close()
    assert [r[0] for r in duckdb_post] == [101, 103, 900, 901]
    print(f"  DuckDB iceberg ext sees:  {duckdb_post}")
    lc = _ducklake_con(settings)
    duck_post = lc.execute("SELECT order_id, customer FROM lake.analytics.orders ORDER BY order_id").fetchall()
    lc.close()
    assert [r[0] for r in duck_post] == [101, 103, 900, 901]
    print(f"  DuckLake SQL sees:        {duck_post}")
    print("  ✓ overwrite (status=2 tombstone + status=1 add in one commit) → all 3 clients agree")

    # ---------- 7d. Partition spec + sort order commits ----------
    hr("Iceberg commits: add-partition-spec (day/bucket/identity) + add-sort-order")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        _rest(c, "POST", "/v1/lake/namespaces/analytics/tables", json={
            "name": "parts",
            "schema": {"type": "struct", "schema-id": 0, "fields": [
                {"id": 1, "name": "id",      "required": False, "type": "long"},
                {"id": 2, "name": "ts",      "required": False, "type": "timestamptz"},
                {"id": 3, "name": "country", "required": False, "type": "string"},
            ]},
        })
        r = _rest(c, "POST", "/v1/lake/namespaces/analytics/tables/parts", json={
            "updates": [{"action": "add-partition-spec", "spec": {"spec-id": 1, "fields": [
                {"name": "ts_day",   "source-id": 2, "transform": "day",       "field-id": 1000},
                {"name": "id_bkt",   "source-id": 1, "transform": "bucket[8]", "field-id": 1001},
                {"name": "country",  "source-id": 3, "transform": "identity",  "field-id": 1002},
            ]}}],
        }).json()
        print(f"  default-spec-id after commit: {r['metadata']['default-spec-id']}")
        print(f"  partition-specs[1]: {r['metadata']['partition-specs'][1]}")
        r = _rest(c, "POST", "/v1/lake/namespaces/analytics/tables/parts", json={
            "updates": [{"action": "add-sort-order", "sort-order": {"order-id": 1, "fields": [
                {"source-id": 3, "transform": "identity", "direction": "asc",  "null-order": "nulls-last"},
                {"source-id": 2, "transform": "identity", "direction": "desc", "null-order": "nulls-first"},
            ]}}],
        }).json()
        print(f"  default-sort-order-id after commit: {r['metadata']['default-sort-order-id']}")
        print(f"  sort-orders[1]: {r['metadata']['sort-orders'][1]}")
    t_parts = cat.load_table("analytics.parts")
    print(f"  PyIceberg sees spec: {t_parts.spec()}")
    print(f"  PyIceberg sees sort: {t_parts.sort_order()}")

    # Unsupported transforms → 501 (only void + set-location now; truncate
    # is handled via the partition-spec sidecar — see Tier 1 assertions below).
    hr("Unsupported transforms → 501 (void), and set-location → 501")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        for action, detail in [
            ("void",         {"action": "add-partition-spec", "spec": {"spec-id": 99, "fields": [
                {"name": "x", "source-id": 3, "transform": "void", "field-id": 1000},
            ]}}),
            ("set-location", {"action": "set-location", "location": "s3://elsewhere/"}),
        ]:
            r = c.post("/v1/lake/namespaces/analytics/tables/parts", json={"updates": [detail]})
            assert r.status_code == 501, (action, r.status_code)
            print(f"  501 {action}: {r.json()['error']['message'][:110]}...")

    # ---------- 7e. Optimistic concurrency: stale assert-ref-snapshot-id → 409 ----------
    hr("Optimistic concurrency: stale assert-ref-snapshot-id → 409")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        r = c.post("/v1/lake/namespaces/analytics/tables/orders", json={
            "requirements": [{
                "type": "assert-ref-snapshot-id",
                "ref": "main",
                "snapshot-id": 99999,        # a value that's definitely not current
            }],
            "updates": [],
        })
    assert r.status_code == 409, f"expected 409, got {r.status_code}: {r.json()}"
    print(f"  {r.status_code} {r.json()['error']['type']}: {r.json()['error']['message']}")

    # ---------- 7e. Partition pruning end-to-end ----------
    hr("Partition-pruning: day/bucket/identity transforms cut files read")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        _rest(c, "POST", "/v1/lake/namespaces/analytics/tables", json={
            "name": "pv",
            "schema": {"type": "struct", "schema-id": 0, "fields": [
                {"id": 1, "name": "id",      "required": False, "type": "long"},
                {"id": 2, "name": "ts",      "required": False, "type": "timestamptz"},
                {"id": 3, "name": "country", "required": False, "type": "string"},
            ]},
        })
        _rest(c, "POST", "/v1/lake/namespaces/analytics/tables/pv", json={
            "updates": [{"action": "add-partition-spec", "spec": {"spec-id": 1, "fields": [
                {"name": "ts_day",  "source-id": 2, "transform": "day",       "field-id": 1000},
                {"name": "id_bkt",  "source-id": 1, "transform": "bucket[8]", "field-id": 1001},
                {"name": "country", "source-id": 3, "transform": "identity",  "field-id": 1002},
            ]}}],
        })
    con = _ducklake_con(settings)
    con.execute("""INSERT INTO lake.analytics.pv VALUES
        (1, TIMESTAMP '2026-04-21 00:00:00+00', 'US'),
        (2, TIMESTAMP '2026-04-21 00:00:00+00', 'FR'),
        (101, TIMESTAMP '2026-04-22 00:00:00+00', 'US')""")
    con.close()
    t_pv = cat.load_table("analytics.pv")
    from pyiceberg.expressions import EqualTo, GreaterThanOrEqual
    all_files = list(t_pv.scan().plan_files())
    us_files  = list(t_pv.scan(row_filter=EqualTo("country", "US")).plan_files())
    fr_files  = list(t_pv.scan(row_filter=EqualTo("country", "FR")).plan_files())
    day_files = list(t_pv.scan(row_filter=GreaterThanOrEqual("ts", "2026-04-22T00:00:00+00:00")).plan_files())
    print(f"  all:                  {len(all_files)}/3 files read")
    print(f"  country='US':         {len(us_files)}/3 files read (FR pruned via identity)")
    print(f"  country='FR':         {len(fr_files)}/3 files read (US pruned)")
    print(f"  ts >= 2026-04-22 UTC: {len(day_files)}/3 files read (day-20563 pruned via day transform)")
    assert [len(all_files), len(us_files), len(fr_files), len(day_files)] == [3, 2, 1, 1], \
        (len(all_files), len(us_files), len(fr_files), len(day_files))
    print("  ✓ predicate pushdown via partition values works for identity + bucket + day")

    # ---------- 8. Views ----------
    hr("Views API")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        _rest(c, "POST", "/v1/lake/namespaces/analytics/views", json={
            "name": "hot_events",
            "view-version": {
                "version-id": 1, "schema-id": 0,
                "default-namespace": ["analytics"],
                "representations": [{"type": "sql", "sql": "SELECT id, name FROM analytics.events WHERE price > 10", "dialect": "duckdb"}],
            },
        })
        listed = c.get("/v1/lake/namespaces/analytics/views").json()
        loaded = _rest(c, "GET", "/v1/lake/namespaces/analytics/views/hot_events").json()
        _rest(c, "DELETE", "/v1/lake/namespaces/analytics/views/hot_events")
    print(f"  list: {listed}")
    print(f"  load: sql={loaded['metadata']['versions'][0]['representations'][0]['sql']!r}")

    # ---------- 8b. Properties + tags + summary enrichment + versioning ----------
    hr("Properties + tags + snapshot summary + metadata versioning")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        # set/remove properties
        r = _rest(c, "POST", "/v1/lake/namespaces/analytics/tables/orders", json={
            "updates": [{"action": "set-properties", "updates": {"owner": "kevin", "retention": "30d"}}],
        }).json()
        assert r["metadata"]["properties"].get("owner") == "kevin"
        assert r["metadata"]["properties"].get("retention") == "30d"
        r = _rest(c, "POST", "/v1/lake/namespaces/analytics/tables/orders", json={
            "updates": [{"action": "remove-properties", "removals": ["retention"]}],
        }).json()
        assert "retention" not in r["metadata"]["properties"]
        print(f"  set/remove-properties ✓  (owner=kevin persisted across LoadTable)")

        # tag the current snapshot
        cur = r["metadata"]["current-snapshot-id"]
        r = _rest(c, "POST", "/v1/lake/namespaces/analytics/tables/orders", json={
            "updates": [{"action": "set-snapshot-ref", "ref-name": "rc1", "type": "tag", "snapshot-id": cur}],
        }).json()
        assert r["metadata"]["refs"]["rc1"] == {"type": "tag", "snapshot-id": cur}
        print(f"  tag 'rc1' → snapshot {cur} ✓")

        # Non-main branch refs are accepted as read-only pointers — they
        # round-trip the Iceberg spec even though DuckLake has no branching.
        # Write attempts against them 501 separately (tested in Tier 1 block).
        r = _rest(c, "POST", "/v1/lake/namespaces/analytics/tables/orders", json={
            "updates": [{"action": "set-snapshot-ref", "ref-name": "feature", "type": "branch", "snapshot-id": cur}],
        }).json()
        assert r["metadata"]["refs"]["feature"] == {"type": "branch", "snapshot-id": cur}
        print(f"  read-only branch 'feature' → snapshot {cur} ✓")

        # remove the tag
        r = _rest(c, "POST", "/v1/lake/namespaces/analytics/tables/orders", json={
            "updates": [{"action": "remove-snapshot-ref", "ref-name": "rc1"}],
        }).json()
        assert "rc1" not in r["metadata"]["refs"]
        print(f"  remove-snapshot-ref 'rc1' ✓")

        # snapshot summary enrichment: append vs delete vs overwrite
        ops = [s["summary"]["operation"] for s in r["metadata"]["snapshots"]]
        print(f"  snapshot operations (enriched from ducklake_snapshot_changes): {ops}")
        assert any(o in {"append", "delete", "overwrite"} for o in ops)

        # metadata versioning: version-hint.text and vN files on S3
        s3c = s3util.s3_client(s3)
        vh = s3c.get_object(Bucket=s3.bucket, Key=f"data/analytics/orders/metadata/version-hint.text")["Body"].read().decode()
        keys = {o["Key"].rsplit("/",1)[-1] for p in s3c.get_paginator("list_objects_v2").paginate(Bucket=s3.bucket, Prefix="data/analytics/orders/metadata/") for o in p.get("Contents",[])}
        v_files = sorted(k for k in keys if k.startswith("v") and k.endswith(".metadata.json"))
        print(f"  version-hint.text → {vh}  (latest of {v_files})")
        assert int(vh) >= 1
        assert len(v_files) >= 1

    # ---------- 8c. Iceberg equality-delete translation ----------
    hr("Iceberg equality-delete (content=2) → DuckLake DELETE translation")
    # Write an equality-delete Parquet via DuckDB to simulate what a Spark MERGE
    # would produce, then send a commit-table referencing it.
    eq_con = duckdb.connect(":memory:")
    for e in ("httpfs",):
        eq_con.execute(f"INSTALL {e}"); eq_con.execute(f"LOAD {e}")
    eq_con.execute("""CREATE OR REPLACE SECRET s (TYPE S3, KEY_ID ?, SECRET ?, REGION ?, ENDPOINT ?, USE_SSL ?, URL_STYLE 'path')""",
                   [s3.root_access_key, s3.root_secret_key, s3.region, s3.host, s3.use_ssl])
    eq_delete_uri = f"s3://{s3.bucket}/{s3.data_prefix}analytics/orders/eq-delete.parquet"
    eq_con.execute(f"COPY (SELECT 101::BIGINT AS order_id) TO '{eq_delete_uri}'")
    eq_con.close()
    # The Iceberg-spec manifest-list/manifest chain we'd normally walk.
    # Build a minimal one pointing at our eq-delete file with content=2.
    import io as _io
    from fastavro import writer as _avw
    from duckicelake.manifest import _manifest_entry_schema as _mesch, _manifest_file_schema as _mfsch
    # Find target snapshot id for assertion + equality-delete metadata
    pre = httpx.get(f"{BASE}/v1/lake/namespaces/analytics/tables/orders", headers=auth_headers).json()
    pre_snap = pre["metadata"]["current-snapshot-id"]
    next_snap = pre_snap + 100  # any unique id; our server ignores client's choice
    # manifest (equality delete)
    mentry = {
        "status": 1, "snapshot_id": next_snap, "sequence_number": next_snap,
        "file_sequence_number": next_snap,
        "data_file": {
            "content": 2, "file_path": eq_delete_uri, "file_format": "PARQUET",
            "partition": {}, "record_count": 1, "file_size_in_bytes": 0,
            "column_sizes": None, "value_counts": None, "null_value_counts": None,
            "nan_value_counts": None, "lower_bounds": None, "upper_bounds": None,
            "key_metadata": None, "split_offsets": None,
            "equality_ids": [1],    # "order_id" has field-id 1
            "sort_order_id": 0, "first_row_id": None, "referenced_data_file": None,
            "content_offset": None, "content_size_in_bytes": None,
        },
    }
    man_buf = _io.BytesIO()
    _avw(man_buf, _mesch(None), [mentry],
         metadata={"schema":'{"type":"struct","schema-id":0,"fields":[]}', "schema-id":"0",
                   "partition-spec":"[]", "partition-spec-id":"0", "format-version":"2", "content":"deletes"},
         codec="deflate")
    man_key = f"{s3.data_prefix}analytics/orders/metadata/eq-delete-manifest.avro"
    s3c.put_object(Bucket=s3.bucket, Key=man_key, Body=man_buf.getvalue())
    # manifest list (content=1 = delete manifest)
    ml_entry = {
        "manifest_path": f"s3://{s3.bucket}/{man_key}", "manifest_length": len(man_buf.getvalue()),
        "partition_spec_id": 0, "content": 1, "sequence_number": next_snap,
        "min_sequence_number": next_snap, "added_snapshot_id": next_snap,
        "added_files_count": 0, "existing_files_count": 0, "deleted_files_count": 1,
        "added_rows_count": 0, "existing_rows_count": 0, "deleted_rows_count": 0,
        "partitions": None, "key_metadata": None,
    }
    ml_buf = _io.BytesIO()
    _avw(ml_buf, _mfsch(), [ml_entry],
         metadata={"snapshot-id":str(next_snap), "parent-snapshot-id":"null",
                   "sequence-number":str(next_snap), "format-version":"2"},
         codec="deflate")
    ml_key = f"{s3.data_prefix}analytics/orders/metadata/eq-delete-snaplist.avro"
    s3c.put_object(Bucket=s3.bucket, Key=ml_key, Body=ml_buf.getvalue())
    # Submit commit
    pre_rows = [r for r in t_pv.scan().to_arrow().to_pylist()]  # not used
    ot_pre = cat.load_table("analytics.orders")
    count_before = len(ot_pre.scan().to_arrow())
    r = _rest(
        httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers),
        "POST", "/v1/lake/namespaces/analytics/tables/orders",
        json={"updates": [{"action": "add-snapshot", "snapshot": {
            "snapshot-id": next_snap,
            "timestamp-ms": 0,
            "manifest-list": f"s3://{s3.bucket}/{ml_key}",
            "summary": {"operation": "delete"},
        }}]},
    ).json()
    ot_post = cat.load_table("analytics.orders")
    count_after = len(ot_post.scan().to_arrow())
    print(f"  before eq-delete: {count_before} rows  →  after: {count_after} rows")
    assert count_after == count_before - 1, (count_before, count_after)
    print(f"  ✓ equality-delete file → DuckLake DELETE → row gone across clients")

    # ---------- 8d. RBAC: scope-enforced token ----------
    hr("RBAC: scope-enforced token denies out-of-scope operations")
    # When auth is ON, server started with admin:*/ reader:ns:analytics:r scopes.
    # If server was started in the demo flow with a single demo-client|*, skip.
    rc_token = _get_access_token("reader", os.environ.get("DUCKICELAKE_RBAC_READER_SECRET", "readsecret"))
    if rc_token is None:
        print("  server has no RBAC-reader client configured; skipped")
    else:
        rh = {"Authorization": f"Bearer {rc_token}"}
        r = httpx.post(f"{BASE}/v1/lake/namespaces/analytics/tables/orders", headers=rh, json={
            "updates": [{"action": "set-properties", "updates": {"unauthorized": "yes"}}],
        })
        assert r.status_code == 403, r.status_code
        print(f"  reader POST → 403 {r.json()['error']['type']} ✓")
        r = httpx.get(f"{BASE}/v1/lake/namespaces/analytics/tables", headers=rh)
        assert r.status_code == 200
        print(f"  reader GET  → 200 ✓")

    # ---------- 9. VARIANT + GEOMETRY ----------
    hr("Create analytics.events_v3 with VARIANT + GEOMETRY; write+read via DuckDB")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        _rest(c, "POST", "/v1/lake/namespaces/analytics/tables", json={
            "name": "events_v3",
            "schema": {"type": "struct", "schema-id": 0, "fields": [
                {"id": 1, "name": "id",       "required": True,  "type": "long"},
                {"id": 2, "name": "payload",  "required": False, "type": "variant"},
                {"id": 3, "name": "location", "required": False, "type": "geometry"},
            ]},
        })
    con = _ducklake_con(settings)
    con.execute("""
        INSERT INTO lake.analytics.events_v3 VALUES
            (1, '{"src":"ios"}'::VARIANT, ST_Point(-73.9, 40.7)),
            (2, '{"src":"web","flags":[1,2,3]}'::VARIANT, ST_Point(2.35, 48.85)),
            (3, '{"src":"android","nested":{"k":"v"}}'::VARIANT, ST_Point(139.7, 35.7))
    """)
    for row in con.execute("SELECT id, payload::VARCHAR, ST_AsText(location) FROM lake.analytics.events_v3 ORDER BY id").fetchall():
        print(f"  DuckLake raw: {row}")
    con.close()

    hr("PyIceberg loads events_v3 through the REST catalog (v3 types recognised)")
    t_v3 = cat.load_table("analytics.events_v3")
    for f in t_v3.schema().fields:
        print(f"  field {f.field_id:>2}  {f.name:<10}  type={f.field_type}  required={f.required}")
    print(f"  metadata snapshots: {len(t_v3.metadata.snapshots)}  current={t_v3.current_snapshot().snapshot_id}")

    hr("DuckDB iceberg ext: inspect events_v3 schema via the REST catalog")
    dc = _iceberg_client_con(s3, bearer_token=token)
    print(f"  columns:")
    for row in dc.execute(
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_catalog='ice' AND table_schema='analytics' AND table_name='events_v3' "
        "ORDER BY ordinal_position"
    ).fetchall():
        print(f"    {row}")
    dc.close()

    # ---------- 10. Tier 1 items: key_metadata + nan counts + read-only
    #                 branches + truncate[N] + eq-delete scoping ----------
    hr("Tier 1: key_metadata field present in every data_file manifest entry")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        r = _rest(c, "GET", "/v1/lake/namespaces/analytics/tables/orders",
                  headers={"X-Iceberg-Access-Delegation": "vended-credentials"}).json()
    md = r["metadata"]
    list_key = md["snapshots"][-1]["manifest-list"].replace(f"s3://{s3.bucket}/", "")
    saw_entry = False
    for mref in reader(io.BytesIO(s3_client.get_object(Bucket=s3.bucket, Key=list_key)["Body"].read())):
        if mref["content"] != 0:
            continue
        mkey = mref["manifest_path"].replace(f"s3://{s3.bucket}/", "")
        for entry in reader(io.BytesIO(s3_client.get_object(Bucket=s3.bucket, Key=mkey)["Body"].read())):
            assert "key_metadata" in entry["data_file"]
            saw_entry = True
    assert saw_entry, "expected at least one data_file entry"
    print("  ✓ key_metadata present in every data_file manifest entry (null when DuckLake catalog unencrypted)")

    hr("Tier 1: exact nan_value_counts via Parquet scan")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        c.delete("/v1/lake/namespaces/analytics/tables/nan_t")
        _rest(c, "POST", "/v1/lake/namespaces/analytics/tables", json={
            "name": "nan_t",
            "schema": {"type": "struct", "schema-id": 0, "fields": [
                {"id": 1, "name": "id", "required": False, "type": "long"},
                {"id": 2, "name": "v",  "required": False, "type": "double"},
            ]},
        })
    con = _ducklake_con(settings)
    con.execute("INSERT INTO lake.analytics.nan_t VALUES (1, 1.0), (2, 'nan'::DOUBLE), (3, 'nan'::DOUBLE), (4, 2.0)")
    con.close()
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        # First GET triggers the compute-and-cache; second GET reads cache.
        _rest(c, "GET", "/v1/lake/namespaces/analytics/tables/nan_t",
              headers={"X-Iceberg-Access-Delegation": "vended-credentials"}).json()
        r = _rest(c, "GET", "/v1/lake/namespaces/analytics/tables/nan_t",
                  headers={"X-Iceberg-Access-Delegation": "vended-credentials"}).json()
    md = r["metadata"]
    list_key = md["snapshots"][-1]["manifest-list"].replace(f"s3://{s3.bucket}/", "")
    nan_total_by_field: dict[int, int] = {}
    for mref in reader(io.BytesIO(s3_client.get_object(Bucket=s3.bucket, Key=list_key)["Body"].read())):
        if mref["content"] != 0:
            continue
        mkey = mref["manifest_path"].replace(f"s3://{s3.bucket}/", "")
        for entry in reader(io.BytesIO(s3_client.get_object(Bucket=s3.bucket, Key=mkey)["Body"].read())):
            for e in (entry["data_file"].get("nan_value_counts") or []):
                nan_total_by_field[e["key"]] = nan_total_by_field.get(e["key"], 0) + e["value"]
    print(f"  nan_value_counts across files: {nan_total_by_field}")
    assert nan_total_by_field.get(2) == 2, nan_total_by_field
    print("  ✓ exact count (2) emitted, not presence-as-1")

    hr("Tier 1: read-only branch ref + writes on non-main branch → 501")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        cur_orders = _rest(c, "GET", "/v1/lake/namespaces/analytics/tables/orders").json()["metadata"]["current-snapshot-id"]
        r = _rest(c, "POST", "/v1/lake/namespaces/analytics/tables/orders", json={
            "updates": [{"action": "set-snapshot-ref", "ref-name": "release_1", "type": "branch", "snapshot-id": cur_orders}],
        }).json()
        assert r["metadata"]["refs"]["release_1"] == {"type": "branch", "snapshot-id": cur_orders}
        print(f"  release_1 → {r['metadata']['refs']['release_1']} ✓ (read-only branch pointer)")
        # write-on-branch: add-snapshot bound to release_1 must 501 before
        # we even walk the manifest chain.
        r2 = c.post("/v1/lake/namespaces/analytics/tables/orders", json={
            "updates": [
                {"action": "add-snapshot", "snapshot": {
                    "snapshot-id": cur_orders + 999,
                    "manifest-list": f"s3://{s3.bucket}/does-not-exist.avro",
                    "timestamp-ms": 0, "summary": {"operation": "append"},
                }},
                {"action": "set-snapshot-ref", "ref-name": "release_1", "type": "branch", "snapshot-id": cur_orders + 999},
            ],
        })
        assert r2.status_code == 501, r2.status_code
        print(f"  501 write-on-branch: {r2.json()['error']['message'][:90]}...")

    hr("Tier 1: truncate[N] partition transform round-trips via sidecar")
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        c.delete("/v1/lake/namespaces/analytics/tables/trunc_t")
        _rest(c, "POST", "/v1/lake/namespaces/analytics/tables", json={
            "name": "trunc_t",
            "schema": {"type": "struct", "schema-id": 0, "fields": [
                {"id": 1, "name": "id",   "required": False, "type": "long"},
                {"id": 2, "name": "name", "required": False, "type": "string"},
            ]},
        })
        r = _rest(c, "POST", "/v1/lake/namespaces/analytics/tables/trunc_t", json={
            "updates": [{"action": "add-partition-spec", "spec": {"spec-id": 1, "fields": [
                {"name": "name_trunc3", "source-id": 2, "transform": "truncate[3]", "field-id": 1000},
            ]}}],
        }).json()
        spec = r["metadata"]["partition-specs"][1]
        assert any(f["transform"] == "truncate[3]" for f in spec["fields"]), spec
        print(f"  partition-specs[1] after add: {spec}")
    con = _ducklake_con(settings)
    con.execute("INSERT INTO lake.analytics.trunc_t VALUES (1, 'abcdef')")
    con.close()
    with httpx.Client(base_url=BASE, timeout=30.0, headers=auth_headers) as c:
        r = _rest(c, "GET", "/v1/lake/namespaces/analytics/tables/trunc_t",
                  headers={"X-Iceberg-Access-Delegation": "vended-credentials"}).json()
    md = r["metadata"]
    list_key = md["snapshots"][-1]["manifest-list"].replace(f"s3://{s3.bucket}/", "")
    partition_by_file: list[dict] = []
    for mref in reader(io.BytesIO(s3_client.get_object(Bucket=s3.bucket, Key=list_key)["Body"].read())):
        if mref["content"] != 0:
            continue
        mkey = mref["manifest_path"].replace(f"s3://{s3.bucket}/", "")
        for entry in reader(io.BytesIO(s3_client.get_object(Bucket=s3.bucket, Key=mkey)["Body"].read())):
            partition_by_file.append(entry["data_file"]["partition"])
    print(f"  manifest partition values: {partition_by_file}")
    assert any(p.get("name_trunc3") == "abc" for p in partition_by_file), partition_by_file
    print("  ✓ truncate[3]('abcdef') == 'abc' in manifest (synthesised from source min)")

    hr("Tier 1: equality-delete sequence-number scoping")
    # The equality-delete earlier removed order_id=101. Append a NEW row with
    # order_id=101 AFTER that delete's snapshot; it must not get retro-deleted.
    ot = cat.load_table("analytics.orders")
    ot.append(_pa.table({
        "order_id": _pa.array([101], type=_pa.int64()),
        "customer": _pa.array(["alice_v2"], type=_pa.string()),
    }))
    ot = cat.load_table("analytics.orders")
    rows_final = sorted(ot.scan().to_arrow().to_pylist(), key=lambda x: x["order_id"])
    new_101s = [r for r in rows_final if r["order_id"] == 101]
    print(f"  rows with order_id=101 after post-delete append: {new_101s}")
    assert any(r["customer"] == "alice_v2" for r in new_101s), rows_final
    print("  ✓ new 101-row survives — equality delete scoped to files with seq < delete seq")

    # ---------- 11. Iceberg v3 format-version writes via pyiceberg_v3 shim ----------
    hr("Iceberg v3 writes: upgrade v2→v3, append, and read back through the proxy")
    # Fresh table so snapshot lineage assertions are deterministic.
    try: cat.drop_table("analytics.v3_orders")
    except Exception: pass
    v3_schema = Schema(
        NestedField(1, "order_id", LongType(), required=False),
        NestedField(2, "customer", StringType(), required=False),
    )
    t_v3 = cat.create_table("analytics.v3_orders", schema=v3_schema)
    print(f"  initial format-version: {t_v3.format_version}")
    assert t_v3.format_version == 2
    # The shim patched Transaction.upgrade_table_version to accept 3 and
    # the proxy stores the request in a sidecar property so subsequent
    # LoadTable emits v3. The next load_table reflects it.
    with t_v3.transaction() as txn:
        txn.upgrade_table_version(3)
    t_v3 = cat.load_table("analytics.v3_orders")
    print(f"  after upgrade: format-version={t_v3.format_version}")
    assert t_v3.format_version == 3, t_v3.format_version
    # Append exercises ManifestWriterV3 + ManifestListWriterV3 from the
    # shim. Without the shim this raises "Cannot write manifest list for
    # table version: 3" in pyiceberg.
    t_v3.append(_pa.table({
        "order_id": _pa.array([1001, 1002, 1003], type=_pa.int64()),
        "customer": _pa.array(["v3_alice", "v3_bob", "v3_carol"], type=_pa.string()),
    }))
    t_v3 = cat.load_table("analytics.v3_orders")
    v3_rows = sorted(t_v3.scan().to_arrow().to_pylist(), key=lambda r: r["order_id"])
    print(f"  after v3 append: {v3_rows}")
    assert [r["order_id"] for r in v3_rows] == [1001, 1002, 1003]
    # The TableMetadata correctly reports v3 on reload, and the proxy's
    # re-materialised manifest-list now tags itself v3 when the table's
    # format-version is 3. Verify both.
    list_key = t_v3.current_snapshot().manifest_list.replace(f"s3://{s3.bucket}/", "")
    raw = s3_client.get_object(Bucket=s3.bucket, Key=list_key)["Body"].read()
    ml_reader = reader(io.BytesIO(raw))
    ml_meta = dict(ml_reader.metadata)
    print(f"  manifest-list avro metadata: format-version={ml_meta.get('format-version')!r}")
    assert ml_meta.get("format-version") == "3", ml_meta
    print("  ✓ v3 write path: pyiceberg wrote v3, proxy re-materialised v3")

    # ---------- 12. Puffin deletion vectors on a v3 table ----------
    hr("Iceberg v3 Puffin DV: delete a row, proxy emits Puffin instead of position-delete Parquet")
    # Append more rows so the delete has something to remove.
    t_v3.append(_pa.table({
        "order_id": _pa.array([2001, 2002, 2003, 2004], type=_pa.int64()),
        "customer": _pa.array(["x1", "x2", "x3", "x4"], type=_pa.string()),
    }))
    # Run an Iceberg-spec equality-delete (content=2 manifest with
    # equality_ids=[1]). Our proxy's eq-delete handler emits per-file
    # position-delete Parquets that DuckLake registers in
    # `ducklake_delete_file`. On the next LoadTable the proxy detects
    # format-version=3 and rewrites those Parquets into a Puffin file
    # with one deletion-vector-v1 blob per affected data file — the
    # spec-preferred v3 delete encoding.
    eq_path = f"s3://{s3.bucket}/{s3.data_prefix}analytics/v3_orders/eq-delete-2002.parquet"
    eq_con = duckdb.connect(":memory:")
    for e in ("httpfs",):
        eq_con.execute(f"INSTALL {e}"); eq_con.execute(f"LOAD {e}")
    eq_con.execute("""CREATE OR REPLACE SECRET s (TYPE S3, KEY_ID ?, SECRET ?, REGION ?, ENDPOINT ?, USE_SSL ?, URL_STYLE 'path')""",
                   [s3.root_access_key, s3.root_secret_key, s3.region, s3.host, s3.use_ssl])
    eq_con.execute(f"COPY (SELECT 2002::BIGINT AS order_id) TO '{eq_path}'")
    eq_con.close()
    pre = httpx.get(f"{BASE}/v1/lake/namespaces/analytics/tables/v3_orders", headers=auth_headers).json()
    pre_snap = pre["metadata"]["current-snapshot-id"]
    next_snap = pre_snap + 100
    mentry = {
        "status": 1, "snapshot_id": next_snap, "sequence_number": next_snap,
        "file_sequence_number": next_snap,
        "data_file": {
            "content": 2, "file_path": eq_path, "file_format": "PARQUET",
            "partition": {}, "record_count": 1, "file_size_in_bytes": 0,
            "column_sizes": None, "value_counts": None, "null_value_counts": None,
            "nan_value_counts": None, "lower_bounds": None, "upper_bounds": None,
            "key_metadata": None, "split_offsets": None,
            "equality_ids": [1],
            "sort_order_id": 0, "first_row_id": None, "referenced_data_file": None,
            "content_offset": None, "content_size_in_bytes": None,
        },
    }
    man_buf = io.BytesIO()
    from fastavro import writer as _avw
    from duckicelake.manifest import _manifest_entry_schema as _mesch, _manifest_file_schema as _mfsch
    _avw(man_buf, _mesch(None), [mentry],
         metadata={"schema":'{"type":"struct","schema-id":0,"fields":[]}', "schema-id":"0",
                   "partition-spec":"[]", "partition-spec-id":"0", "format-version":"2", "content":"deletes"},
         codec="deflate")
    man_key = f"{s3.data_prefix}analytics/v3_orders/metadata/dv-eq-delete-manifest.avro"
    s3_client.put_object(Bucket=s3.bucket, Key=man_key, Body=man_buf.getvalue())
    ml_entry = {
        "manifest_path": f"s3://{s3.bucket}/{man_key}", "manifest_length": len(man_buf.getvalue()),
        "partition_spec_id": 0, "content": 1, "sequence_number": next_snap,
        "min_sequence_number": next_snap, "added_snapshot_id": next_snap,
        "added_files_count": 0, "existing_files_count": 0, "deleted_files_count": 1,
        "added_rows_count": 0, "existing_rows_count": 0, "deleted_rows_count": 0,
        "partitions": None, "key_metadata": None,
    }
    ml_buf = io.BytesIO()
    _avw(ml_buf, _mfsch(), [ml_entry],
         metadata={"snapshot-id":str(next_snap), "parent-snapshot-id":"null",
                   "sequence-number":str(next_snap), "format-version":"2"},
         codec="deflate")
    ml_key = f"{s3.data_prefix}analytics/v3_orders/metadata/dv-eq-delete-snaplist.avro"
    s3_client.put_object(Bucket=s3.bucket, Key=ml_key, Body=ml_buf.getvalue())
    httpx.post(f"{BASE}/v1/lake/namespaces/analytics/tables/v3_orders",
               headers=auth_headers,
               json={"updates": [{"action": "add-snapshot", "snapshot": {
                   "snapshot-id": next_snap, "timestamp-ms": 0,
                   "manifest-list": f"s3://{s3.bucket}/{ml_key}",
                   "summary": {"operation": "delete"},
               }}]}).raise_for_status()
    t_v3 = cat.load_table("analytics.v3_orders")
    after_dv_rows = sorted(t_v3.scan().to_arrow().to_pylist(), key=lambda r: r["order_id"])
    print(f"  rows after DV-delete: {len(after_dv_rows)}  ids: {[r['order_id'] for r in after_dv_rows]}")
    assert all(r["order_id"] != 2002 for r in after_dv_rows)

    # Inspect the latest manifest-list to confirm the delete entry is now Puffin.
    list_key = t_v3.current_snapshot().manifest_list.replace(f"s3://{s3.bucket}/", "")
    raw = s3_client.get_object(Bucket=s3.bucket, Key=list_key)["Body"].read()
    delete_entries = []
    for mref in reader(io.BytesIO(raw)):
        if mref["content"] != 1:    # 1 = deletes manifest
            continue
        mkey = mref["manifest_path"].replace(f"s3://{s3.bucket}/", "")
        for entry in reader(io.BytesIO(s3_client.get_object(Bucket=s3.bucket, Key=mkey)["Body"].read())):
            delete_entries.append(entry["data_file"])
    assert delete_entries, "expected at least one delete manifest entry"
    df = delete_entries[0]
    print(f"  delete entry: file_format={df['file_format']!r}  "
          f"content_offset={df['content_offset']}  "
          f"content_size_in_bytes={df['content_size_in_bytes']}  "
          f"referenced_data_file={df['referenced_data_file'].split('/')[-1]!r}  "
          f"cardinality(record_count)={df['record_count']}")
    assert df["file_format"] == "PUFFIN", df["file_format"]
    assert df["content_offset"] is not None
    assert df["content_size_in_bytes"] is not None
    assert df["referenced_data_file"] is not None
    assert df["record_count"] == 1, df["record_count"]   # one row deleted

    # Verify the Puffin file on S3 starts and ends with PFA1 magic and
    # that the DV blob round-trips through the Roaring decoder.
    puffin_uri = df["file_path"]
    puffin_key = puffin_uri.replace(f"s3://{s3.bucket}/", "")
    puffin_bytes = s3_client.get_object(Bucket=s3.bucket, Key=puffin_key)["Body"].read()
    assert puffin_bytes[:4] == b"PFA1" and puffin_bytes[-4:] == b"PFA1"
    blob = puffin_bytes[df["content_offset"]:df["content_offset"] + df["content_size_in_bytes"]]
    import struct as _struct, zlib as _zlib
    blob_len = _struct.unpack(">I", blob[:4])[0]
    assert blob[4:8] == bytes([0xD1, 0xD3, 0x39, 0x64])
    body = blob[4:4 + blob_len]
    crc_stored = _struct.unpack(">I", blob[4 + blob_len:4 + blob_len + 4])[0]
    assert crc_stored == (_zlib.crc32(body) & 0xFFFFFFFF)
    # Decode the Roaring64-portable bitmap and assert it has exactly one
    # set bit (the deleted row).
    n_bitmaps = _struct.unpack("<Q", body[4:12])[0]   # skip 4B magic
    assert n_bitmaps == 1, n_bitmaps
    key = _struct.unpack("<I", body[12:16])[0]
    assert key == 0, key   # high 32 bits = 0 for our small file
    from pyroaring import BitMap
    decoded = BitMap.deserialize(body[16:])
    print(f"  decoded DV positions: {sorted(decoded)}  (cardinality={len(decoded)})")
    assert len(decoded) == 1
    print("  ✓ Puffin DV: PFA1 magic + DV magic + valid CRC + Roaring bitmap roundtrips")

    hr("DONE — no exceptions caught, no fallbacks silent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
