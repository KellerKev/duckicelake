"""Result-set cache: a query runs as the caller (masks + filters applied),
lands as Parquet under the results root, and comes back as file paths plus a
credential that reads only that result. Identical queries over unchanged data
and governance are reused; anything else gets a fresh result."""
from __future__ import annotations

from datetime import timedelta

import uuid

import duckdb
import psycopg
import pytest

from duckicelake import result_sets, s3util
from duckicelake.result_sets import analyse

from test_governance_phase3 import (
    _author_demo_policy, _make_table, _ns, _root_duckdb, _seed_rows,
)

pytestmark = pytest.mark.usefixtures("client")


def _read(res: dict, sql_tail: str = "") -> list[tuple]:
    """Read a result set exactly as a client would: its files, its creds."""
    s3c = res["s3"]
    con = duckdb.connect()
    con.execute("LOAD httpfs")
    con.execute(
        "CREATE SECRET r (TYPE S3, KEY_ID ?, SECRET ?, REGION ?, ENDPOINT ?, "
        "USE_SSL ?, URL_STYLE 'path')",
        [s3c["access-key-id"], s3c["secret-access-key"], s3c["region"],
         s3c["endpoint"].rsplit("://", 1)[-1], s3c["endpoint"].startswith("https")])
    try:
        return con.execute(
            f"SELECT * FROM read_parquet(?) {sql_tail}", [res["files"]]).fetchall()
    finally:
        con.close()


def _rs(client, ns, sql, principal, params=None, **extra):
    r = client.post(f"/v1/lake/namespaces/{ns}/result-sets",
                    params={"principal": principal, **(params or {})},
                    json={"sql": sql, **extra})
    return r


# Unique per test: role grants live in the shared test catalog, and other
# test files expect a plain "bob" to be masked.
BOB = ALICE = ""


@pytest.fixture(autouse=True)
def _principals():
    global BOB, ALICE
    tag = uuid.uuid4().hex[:6]
    BOB, ALICE = f"bob_{tag}", f"alice_{tag}"


@pytest.fixture
def masked_ns(client, settings):
    ns = _ns("rs")
    _make_table(client, ns, "events")
    _author_demo_policy(client, ns, "events")
    client.post("/v1/lake/governance/roles", json={"name": "pii_reader"}).raise_for_status()
    client.post("/v1/lake/governance/role-grants",
                json={"role": "pii_reader", "principal": ALICE}).raise_for_status()
    _seed_rows(settings, ns)
    return ns


def test_result_is_masked_for_the_caller_and_reused(client, masked_ns):
    ns = masked_ns
    sql = "SELECT id, email FROM events ORDER BY id"
    bob = _rs(client, ns, sql, BOB)
    assert bob.status_code == 200, bob.text
    bob = bob.json()
    assert bob["status"] == "materialized" and bob["reusable"] and bob["row_count"] == 2
    assert [c["name"] for c in bob["columns"]] == ["id", "email"]
    assert _read(bob) == [(1, "al***"), (2, "bo***")]

    again = _rs(client, ns, sql + " ;", BOB).json()       # trailing ; normalized
    assert again["status"] == "hit" and again["id"] == bob["id"] and again["use_count"] == 2

    alice = _rs(client, ns, sql, ALICE).json()
    assert alice["id"] != bob["id"]                          # never shared across users
    assert _read(alice) == [(1, "alice@example.com"), (2, "bob@example.com")]


@pytest.mark.parametrize("ctx", [{"actor": "agent", "channel": "mcp"},
                                 {"actor": "human", "channel": "console"}])
def test_airtight_sessions_get_masked_results_and_no_base_reads(client, masked_ns, ctx):
    """Agents and console sessions run arbitrary SQL, so their session is
    file-layer (masked export only): the result is masked and naming the
    base table can't read it raw."""
    ns = masked_ns
    params = {**ctx, "delegate": "1"}
    res = _rs(client, ns, "SELECT id, email FROM events ORDER BY id", BOB, params)
    assert res.status_code == 200, res.text
    assert _read(res.json()) == [(1, "al***"), (2, "bo***")]
    raw = _rs(client, ns, f'SELECT email FROM lake."{ns}".events', BOB, params)
    assert raw.status_code == 400 or all(
        r[0].endswith("***") for r in _read(raw.json()))


def test_new_data_or_governance_change_builds_a_new_result(client, settings, masked_ns):
    ns = masked_ns
    sql = "SELECT count(*) AS n FROM events"
    first = _rs(client, ns, sql, BOB).json()
    assert _read(first) == [(2,)]

    con = _root_duckdb(settings)
    con.execute(f"INSERT INTO lake.\"{ns}\".events VALUES (3, 'carol@example.com')")
    con.close()
    second = _rs(client, ns, sql, BOB).json()
    assert second["status"] == "materialized" and second["id"] != first["id"]
    # (not read yet: the gateway caches a result's liveness for a few seconds)

    # bob gains pii_reader: the governance version moves, the old result is
    # no longer served (refresh 410, its credential stops working)
    client.post("/v1/lake/governance/role-grants",
                json={"role": "pii_reader", "principal": BOB}).raise_for_status()
    third = _rs(client, ns, sql, BOB).json()
    assert third["id"] != second["id"] and _read(third) == [(3,)]
    r = client.get(f"/v1/lake/namespaces/{ns}/result-sets/{second['id']}",
                   params={"principal": BOB})
    assert r.status_code == 410
    with pytest.raises(duckdb.Error):
        _read(second)


def test_credential_reads_only_its_own_result(client, settings, masked_ns):
    ns = masked_ns
    bob = _rs(client, ns, "SELECT email FROM events", BOB).json()
    alice = _rs(client, ns, "SELECT email FROM events", ALICE).json()
    # bob's credential pointed at alice's (cleartext) result → denied
    with pytest.raises(duckdb.Error):
        _read({**alice, "s3": bob["s3"]})
    # ...and at the base table's files → denied
    base = f"s3://{settings.s3.bucket}/{settings.s3.data_prefix}{ns}/events/*.parquet"
    with pytest.raises(duckdb.Error):
        _read({**bob, "files": [base]})
    # bob may refresh his own result, not alice's
    assert client.get(f"/v1/lake/namespaces/{ns}/result-sets/{alice['id']}",
                      params={"principal": BOB}).status_code == 404
    ok = client.get(f"/v1/lake/namespaces/{ns}/result-sets/{bob['id']}",
                    params={"principal": BOB})
    assert ok.status_code == 200 and ok.json()["use_count"] == 2


def test_volatile_queries_are_not_reused(client, masked_ns):
    ns = masked_ns
    sql = "SELECT id, now() AS t FROM events"
    a = _rs(client, ns, sql, BOB).json()
    b = _rs(client, ns, sql, BOB).json()
    assert a["reusable"] is False and b["status"] == "materialized" and a["id"] != b["id"]


def test_lookup_mode_and_bad_sql(client, masked_ns):
    ns = masked_ns
    sql = "SELECT max(id) AS m FROM events"
    miss = _rs(client, ns, sql, BOB, mode="lookup").json()
    assert miss == {"status": "miss", "reusable": True}
    built = _rs(client, ns, sql, BOB).json()
    hit = _rs(client, ns, sql, BOB, mode="lookup").json()
    assert hit["status"] == "hit" and hit["id"] == built["id"]
    assert _rs(client, ns, "DELETE FROM events", BOB).status_code == 400
    assert _rs(client, ns, "SELECT 1; SELECT 2", BOB).status_code == 400


def test_sweep_purges_expired_results(client, settings, masked_ns):
    ns = masked_ns
    res = _rs(client, ns, "SELECT id FROM events", BOB).json()
    s3c = s3util.s3_client(settings.s3)
    key = res["files"][0].split(f"s3://{settings.s3.bucket}/", 1)[1]
    s3c.head_object(Bucket=settings.s3.bucket, Key=key)
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c:
        c.execute("UPDATE public.duckicelake_result_set SET expires_at = now() - interval '1 second' "
                  "WHERE id = %s", (res["id"],))
    stats = result_sets.sweep(settings, [(settings.catalog_name,
                                          settings.default_catalog_ref())], s3c)
    assert stats["purged"] >= 1
    with pytest.raises(Exception):
        s3c.head_object(Bucket=settings.s3.bucket, Key=key)
    with psycopg.connect(settings.pg_dsn) as c:
        assert c.execute("SELECT count(*) FROM public.duckicelake_result_set WHERE id = %s",
                         (res["id"],)).fetchone()[0] == 0


def test_sweep_removes_orphaned_objects(settings):
    s3c = s3util.s3_client(settings.s3)
    key = f"{settings.s3.results_root}{settings.catalog_name}/orphan0123/part-0.parquet"
    s3c.put_object(Bucket=settings.s3.bucket, Key=key, Body=b"x")
    stats = result_sets.sweep(settings, [(settings.catalog_name, settings.default_catalog_ref())],
                              s3c, orphan_grace=timedelta(seconds=-60))
    assert stats["orphans"] >= 1


def test_results_root_is_outside_every_data_prefix(settings):
    assert not settings.s3.results_root.startswith(settings.s3.data_prefix)


def test_lifecycle_merge_keeps_foreign_rules(settings):
    class FakeS3:
        class exceptions:
            ClientError = Exception

        def get_bucket_lifecycle_configuration(self, Bucket):
            return {"Rules": [{"ID": "backups", "Filter": {"Prefix": "backups/"},
                               "Status": "Enabled", "Expiration": {"Days": 30}},
                              {"ID": "duckicelake-results", "Status": "Disabled"}]}

    merged = result_sets.apply_lifecycle(settings, FakeS3(), dry_run=True)
    assert [r["ID"] for r in merged] == ["backups", "duckicelake-results"]
    ours = merged[1]
    assert ours["Filter"]["Prefix"] == settings.s3.results_root and ours["Status"] == "Enabled"
    assert ours["NoncurrentVersionExpiration"] == {"NoncurrentDays": 1}


@pytest.mark.parametrize("sql, tables, volatile, tf", [
    ("SELECT * FROM main.events e JOIN x.y USING (a)", {("", "main", "events"), ("", "x", "y")}, False, False),
    ("WITH c AS (SELECT * FROM t) SELECT * FROM c", {("", "", "t"), ("", "", "c")}, False, False),
    ("SELECT random() FROM t", {("", "", "t")}, True, False),
    ("SELECT current_date AS d FROM t", {("", "", "t")}, True, False),
    ("SELECT * FROM range(3)", set(), False, True),
])
def test_analyse(sql, tables, volatile, tf):
    shape = analyse(sql)
    assert set(shape.tables) == tables and shape.volatile == volatile
    assert shape.table_functions == tf
    if "WITH c" in sql:
        assert shape.ctes == {"c"}
