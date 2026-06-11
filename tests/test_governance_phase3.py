"""Phase 3 governance tests — ad-hoc DuckLake masking views.

Layers (grown stage by stage):
  * `test_view_manager_*` — the MaskingViewManager primitive against the
    live catalog (a direct DuckLakeCatalog beside the session proxy, the
    test_notify_materialise.py pattern).
  * `test_loadtable_*` / `test_reserved_*` — the REST read path.
  * `test_ducklake_credentials_*` — the DuckLake-direct vending endpoint,
    including the load-bearing proof that a roleless principal ATTACHing
    the vended DSN + creds gets masked rows.
"""
from __future__ import annotations

import uuid

import boto3
import duckdb
import psycopg
import pytest

from duckicelake.catalog import DuckLakeCatalog
from duckicelake.masking_views import MaskingViewManager, mask_view_name
from duckicelake.policies import build_plan, mask_signature


def _ns(suffix: str) -> str:
    return f"gp3_{suffix}_{uuid.uuid4().hex[:6]}"


SCHEMA_JSON = {
    "type": "struct", "schema-id": 0,
    "fields": [
        {"id": 1, "name": "id", "required": True, "type": "long"},
        {"id": 2, "name": "email", "required": False, "type": "string"},
    ],
}


def _mask_plan(ns: str, table: str, *, roles=(), body="left(val,2)||'***'",
               columns=("id", "email")):
    """A pure plan masking `email` on ns.table for a roleless principal."""
    return build_plan(
        principal="bob", roles=list(roles), schema=ns, table=table,
        columns=list(columns),
        object_tags=[{"object_kind": "column", "schema_name": ns,
                      "object_name": table, "column_name": "email",
                      "tag_ns": "pii", "tag_name": "email", "tag_value": None}],
        attachments=[{"policy_kind": "masking", "policy_name": "mask_email",
                      "target_kind": "tag", "tag_ns": "pii", "tag_name": "email",
                      "schema_name": None, "object_name": None,
                      "column_name": None, "columns": None}],
        masking_bodies={"mask_email": {"signature": "(val VARCHAR)",
                                       "body": body,
                                       "unmasked_roles": ["pii_reader"]}},
        row_bodies={},
    )


@pytest.fixture
def direct_catalog(settings):
    c = DuckLakeCatalog(settings)
    c.connect()
    yield c
    c.close()


def _make_table(client, ns: str, table: str) -> None:
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    client.post(f"/v1/lake/namespaces/{ns}/tables",
                json={"name": table, "schema": SCHEMA_JSON}).raise_for_status()


def _live_view_rows(dsn: str, ns: str, name: str) -> int:
    with psycopg.connect(dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute(
            """
            SELECT count(*) FROM public.ducklake_view v
            JOIN public.ducklake_schema s USING(schema_id)
            WHERE s.schema_name = %s AND v.view_name = %s
              AND v.end_snapshot IS NULL AND s.end_snapshot IS NULL
            """,
            (ns, name),
        )
        return cur.fetchone()[0]


# ---- the materialization primitive -----------------------------------------

def test_view_manager_idempotent(client, settings, direct_catalog):
    ns = _ns("idem")
    _make_table(client, ns, "events")
    mgr = MaskingViewManager(direct_catalog, settings)
    plan = _mask_plan(ns, "events")

    name1 = mgr.ensure_view_for_plan([ns], "events", plan)
    name2 = mgr.ensure_view_for_plan([ns], "events", plan)
    assert name1 == name2 == mask_view_name("events", mask_signature(plan))
    # exactly one live ducklake_view row despite two ensure calls
    assert _live_view_rows(settings.pg_dsn, ns, name1) == 1
    assert mgr.view_name_for_plan([ns], "events", plan) == name1


def test_view_manager_empty_plan_is_none(client, settings, direct_catalog):
    ns = _ns("empty")
    _make_table(client, ns, "events")
    mgr = MaskingViewManager(direct_catalog, settings)
    # pii_reader bypasses the policy → empty plan → no view
    plan = _mask_plan(ns, "events", roles=["pii_reader"])
    assert plan.is_empty()
    assert mgr.view_name_for_plan([ns], "events", plan) is None
    assert mgr.ensure_view_for_plan([ns], "events", plan) is None


def test_view_manager_respects_masking_disabled(client, settings, direct_catalog):
    ns = _ns("optout")
    _make_table(client, ns, "events")
    direct_catalog.upsert_table_properties(
        [ns], "events", set_map={"duckicelake.masking-disabled": "true"})
    mgr = MaskingViewManager(direct_catalog, settings)
    plan = _mask_plan(ns, "events")
    assert mgr.ensure_view_for_plan([ns], "events", plan) is None
    assert _live_view_rows(settings.pg_dsn, ns,
                           mask_view_name("events", mask_signature(plan))) == 0


def test_view_manager_gc_orphans(client, settings, direct_catalog):
    ns = _ns("gc")
    _make_table(client, ns, "events")
    mgr = MaskingViewManager(direct_catalog, settings)

    old_plan = _mask_plan(ns, "events")
    new_plan = _mask_plan(ns, "events", body="'***'")   # policy body changed
    old_name = mgr.ensure_view_for_plan([ns], "events", old_plan)
    new_name = mgr.ensure_view_for_plan([ns], "events", new_plan)
    assert old_name != new_name

    dropped = mgr.gc_orphans([ns], "events", keep={new_name})
    assert dropped == 1
    assert _live_view_rows(settings.pg_dsn, ns, old_name) == 0
    assert _live_view_rows(settings.pg_dsn, ns, new_name) == 1


def test_view_manager_transparent_schema(client, settings, direct_catalog):
    ns = _ns("transp")
    _make_table(client, ns, "events")
    mgr = MaskingViewManager(direct_catalog, settings)
    plan = _mask_plan(ns, "events")

    # the credentials endpoint always materializes both: the namespace view
    # (gc anchors on it) and the transparent schema
    mgr.ensure_view_for_plan([ns], "events", plan)
    schema = mgr.ensure_transparent_schema([ns], "events", plan)
    assert schema == f"__masked_{mask_signature(plan)}"
    # the schema holds a view named exactly like the base table
    assert _live_view_rows(settings.pg_dsn, schema, "events") == 1
    # idempotent
    assert mgr.ensure_transparent_schema([ns], "events", plan) == schema

    # gc of the signature also removes the transparent schema
    mgr.gc_orphans([ns], "events", keep=set())
    assert _live_view_rows(settings.pg_dsn, schema, "events") == 0


# ---- REST read path (stage 2) ----------------------------------------------

def _author_demo_policy(client, ns: str, table: str) -> None:
    """pii.email tag on ns.table.email + mask_email policy attached to the
    tag, bypassed by the pii_reader role (the test_governance.py shape)."""
    client.post("/v1/lake/governance/tags",
                json={"namespace": "pii", "name": "email"}).raise_for_status()
    client.post("/v1/lake/governance/object-tags",
                json={"object-kind": "column", "schema": ns, "object": table,
                      "column": "email", "tag-namespace": "pii",
                      "tag-name": "email"}).raise_for_status()
    client.post("/v1/lake/governance/masking-policies",
                json={"name": "mask_email", "signature": "(val VARCHAR)",
                      "body": "left(val,2)||'***'",
                      "unmasked-roles": ["pii_reader"]}).raise_for_status()
    client.post("/v1/lake/governance/policy-attachments",
                json={"policy-kind": "masking", "policy-name": "mask_email",
                      "target-kind": "tag", "tag-namespace": "pii",
                      "tag-name": "email"}).raise_for_status()


def test_loadtable_materializes_and_stamps_view(client, settings):
    """A masked LoadTable materializes the masking view and advertises it
    via the duckicelake.masking-view-name property; the view is loadable
    over REST but hidden from list_views."""
    ns = _ns("stamp")
    _make_table(client, ns, "events")
    _author_demo_policy(client, ns, "events")

    md = client.get(f"/v1/lake/namespaces/{ns}/tables/events").json()["metadata"]
    view_name = md["properties"].get("duckicelake.masking-view-name")
    assert view_name and view_name.startswith("__mask_events__")
    # Phase-2 advisory stamping is intact alongside the new property
    assert md["properties"]["duckicelake.masked-columns"] == "email"

    # physically materialized…
    assert _live_view_rows(settings.pg_dsn, ns, view_name) == 1
    # …loadable by name over REST (the PyIceberg/Trino path)…
    v = client.get(f"/v1/lake/namespaces/{ns}/views/{view_name}")
    assert v.status_code == 200, v.text
    rep = v.json()["metadata"]["versions"][0]["representations"][0]
    # DuckLake stores the SQL as DuckDB rebound it (normalized quoting), so
    # assert the mask semantics rather than the exact text
    assert "left" in rep["sql"].lower() and "'***'" in rep["sql"]
    # …but hidden from enumeration
    listed = client.get(f"/v1/lake/namespaces/{ns}/views").json()["identifiers"]
    assert view_name not in [i["name"] for i in listed]


def test_reserved_prefixes_rejected(client):
    ns = _ns("resv")
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    r = client.post(f"/v1/lake/namespaces/{ns}/views",
                    json={"name": "__mask_x", "view-version": {
                        "representations": [{"type": "sql", "sql": "SELECT 1",
                                             "dialect": "duckdb"}]}})
    assert r.status_code == 400
    r = client.post("/v1/lake/namespaces",
                    json={"namespace": ["__masked_deadbeef"]})
    assert r.status_code == 400


def test_masked_namespaces_hidden_from_listing(client, settings, direct_catalog):
    ns = _ns("hidden")
    _make_table(client, ns, "events")
    mgr = MaskingViewManager(direct_catalog, settings)
    plan = _mask_plan(ns, "events")
    schema = mgr.ensure_transparent_schema([ns], "events", plan)
    assert schema is not None
    namespaces = client.get("/v1/lake/namespaces").json()["namespaces"]
    flat = [n[0] for n in namespaces]
    assert ns in flat
    assert schema not in flat


# ---- DuckLake-direct credential vending (stage 3) ---------------------------

def _root_duckdb(settings) -> duckdb.DuckDBPyConnection:
    """A DuckLake-direct session with root creds (operator shape) — used to
    seed rows the way the demo does."""
    s3 = settings.s3
    con = duckdb.connect(":memory:")
    for ext in ("ducklake", "postgres", "httpfs"):
        con.execute(f"INSTALL {ext}")
        con.execute(f"LOAD {ext}")
    con.execute(
        f"""
        CREATE OR REPLACE SECRET root_s3 (
            TYPE S3, KEY_ID '{s3.root_access_key}',
            SECRET '{s3.root_secret_key}', REGION '{s3.region}',
            ENDPOINT '{s3.host}', USE_SSL {str(s3.use_ssl).lower()},
            URL_STYLE '{"path" if s3.path_style else "vhost"}'
        )
        """
    )
    con.execute(
        f"ATTACH 'ducklake:postgres:{settings.pg_dsn}' AS lake "
        f"(DATA_PATH 's3://{s3.bucket}/{s3.data_prefix}', "
        f" DATA_INLINING_ROW_LIMIT 0)"
    )
    return con


def _vended_duckdb(settings, vended: dict) -> duckdb.DuckDBPyConnection:
    """A DuckLake-direct session shaped exactly like a client following the
    ducklake-credentials response: returned ATTACH + vended S3 creds."""
    s3c = vended["s3"]
    con = duckdb.connect(":memory:")
    for ext in ("ducklake", "postgres", "httpfs"):
        con.execute(f"INSTALL {ext}")
        con.execute(f"LOAD {ext}")
    host = s3c["endpoint"].rsplit("://", 1)[-1]
    con.execute(
        f"""
        CREATE OR REPLACE SECRET vended_s3 (
            TYPE S3, KEY_ID '{s3c["access-key-id"]}',
            SECRET '{s3c["secret-access-key"]}',
            SESSION_TOKEN '{s3c["session-token"]}',
            REGION '{s3c["region"]}', ENDPOINT '{host}',
            USE_SSL {str(s3c["endpoint"].startswith("https")).lower()},
            URL_STYLE '{"path" if s3c["path-style-access"] else "vhost"}'
        )
        """
    )
    con.execute(vended["ducklake_attach_sql"])
    for stmt in vended["post_attach_sql"]:
        con.execute(stmt)
    return con


def _seed_rows(settings, ns: str) -> None:
    con = _root_duckdb(settings)
    con.execute(
        f'INSERT INTO lake."{ns}".events VALUES '
        f"(1, 'alice@example.com'), (2, 'bob@example.com')"
    )
    con.close()


def test_ducklake_credentials_masked_vs_privileged(client, settings):
    """The load-bearing proof: bob (no roles) sees masked rows through the
    vended view — transparently for unqualified queries — while alice
    (pii_reader via sidecar grant) gets no view and reads cleartext. The
    qualified base table stays readable: this is the cooperative-client
    boundary, documented in GOVERNANCE.md."""
    ns = _ns("cred")
    _make_table(client, ns, "events")
    _author_demo_policy(client, ns, "events")
    client.post("/v1/lake/governance/roles",
                json={"name": "pii_reader"}).raise_for_status()
    client.post("/v1/lake/governance/role-grants",
                json={"role": "pii_reader", "principal": "alice"}).raise_for_status()
    _seed_rows(settings, ns)

    # ---- bob: roleless → masked ----
    r = client.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials",
                   params={"table": "events", "principal": "bob"})
    assert r.status_code == 200, r.text
    bob = r.json()
    assert bob["masked_view"] == f"{ns}.__mask_events__{bob['mask_signature']}"
    assert bob["transparent"] is True and bob["post_attach_sql"]
    assert bob["s3"]["session-token"]

    con = _vended_duckdb(settings, bob)
    # transparent: unqualified query resolves to the masking view
    emails = {r0[0] for r0 in
              con.execute("SELECT email FROM events").fetchall()}
    assert emails == {"al***", "bo***"}
    # by-name fallback works too
    sch, view = bob["masked_view"].split(".", 1)
    emails = {r0[0] for r0 in con.execute(
        f'SELECT email FROM lake."{sch}"."{view}"').fetchall()}
    assert emails == {"al***", "bo***"}
    # cooperative boundary: the qualified base table is still cleartext —
    # ad-hoc views cannot stop a client that names the base table directly
    raw = {r0[0] for r0 in con.execute(
        f'SELECT email FROM lake."{ns}".events').fetchall()}
    assert raw == {"alice@example.com", "bob@example.com"}
    con.close()

    # ---- alice: pii_reader (sidecar grant) → unmasked, no view ----
    r = client.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials",
                   params={"table": "events", "principal": "alice"})
    alice = r.json()
    assert alice["masked_view"] is None
    assert alice["transparent"] is False and not alice["post_attach_sql"]

    con = _vended_duckdb(settings, alice)
    raw = {r0[0] for r0 in con.execute(
        f'SELECT email FROM lake."{ns}".events').fetchall()}
    assert raw == {"alice@example.com", "bob@example.com"}
    con.close()

    # the vending decisions were audited with the new operation
    audit = client.get("/v1/lake/governance/audit").json()["entries"]
    vends = [e for e in audit if e["operation"] == "ducklake_credentials"]
    assert any(e["principal"] == "bob" and e["decision"] == "masked"
               for e in vends)
    assert any(e["principal"] == "alice" and e["decision"] == "ok"
               for e in vends)


def test_ducklake_credentials_sts_prefix_scoping(client, settings):
    """Vended creds are table-prefix-scoped: own table readable (including
    files committed AFTER vending — the live-session fix), sibling tables
    403."""
    ns = _ns("scope")
    _make_table(client, ns, "events")
    _make_table_only(client, ns, "secrets")
    _seed_rows(settings, ns)
    con = _root_duckdb(settings)
    con.execute(f'INSERT INTO lake."{ns}".secrets VALUES (1, \'topsecret@x.com\')')
    con.close()

    creds = client.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials",
                       params={"table": "events", "principal": "bob"}).json()
    s3c = creds["s3"]
    s3 = settings.s3
    vended = boto3.client(
        "s3", endpoint_url=s3c["endpoint"], region_name=s3c["region"],
        aws_access_key_id=s3c["access-key-id"],
        aws_secret_access_key=s3c["secret-access-key"],
        aws_session_token=s3c["session-token"],
    )
    root = boto3.client(
        "s3", endpoint_url=s3.endpoint, region_name=s3.region,
        aws_access_key_id=s3.root_access_key,
        aws_secret_access_key=s3.root_secret_key,
    )

    def _keys(prefix: str) -> list[str]:
        out = []
        for p in root.get_paginator("list_objects_v2").paginate(
                Bucket=s3.bucket, Prefix=prefix):
            out += [o["Key"] for o in p.get("Contents", [])]
        return out

    own = _keys(s3.table_prefix(ns, "events"))
    other = _keys(s3.table_prefix(ns, "secrets"))
    assert own and other, "expected parquet files for both tables"

    vended.get_object(Bucket=s3.bucket, Key=own[0])          # own table: 200
    import botocore.exceptions
    with pytest.raises(botocore.exceptions.ClientError) as exc:
        vended.get_object(Bucket=s3.bucket, Key=other[0])    # sibling: denied
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 403

    # a file committed AFTER vending stays readable (prefix, not file list)
    before = set(own)
    _seed_rows(settings, ns)
    new = [k for k in _keys(s3.table_prefix(ns, "events")) if k not in before]
    assert new, "post-vend commit should add a data file"
    vended.get_object(Bucket=s3.bucket, Key=new[0])           # still 200


def _make_table_only(client, ns: str, table: str) -> None:
    client.post(f"/v1/lake/namespaces/{ns}/tables",
                json={"name": table, "schema": SCHEMA_JSON}).raise_for_status()


def test_schema_change_drops_stale_masking_views(client, settings):
    """ADD COLUMN via commit_table garbage-collects masking views built
    against the old column set; the next masked LoadTable recreates the
    view at the new signature."""
    ns = _ns("alter")
    _make_table(client, ns, "events")
    _author_demo_policy(client, ns, "events")

    md = client.get(f"/v1/lake/namespaces/{ns}/tables/events").json()["metadata"]
    old_view = md["properties"]["duckicelake.masking-view-name"]
    assert _live_view_rows(settings.pg_dsn, ns, old_view) == 1

    wider = {
        "type": "struct", "schema-id": 1,
        "fields": SCHEMA_JSON["fields"] + [
            {"id": 3, "name": "country", "required": False, "type": "string"},
        ],
    }
    client.post(
        f"/v1/lake/namespaces/{ns}/tables/events",
        json={"requirements": [],
              "updates": [{"action": "add-schema", "schema": wider},
                          {"action": "set-current-schema", "schema-id": -1}]},
    ).raise_for_status()

    # stale view gone…
    assert _live_view_rows(settings.pg_dsn, ns, old_view) == 0
    # …and the next masked load materializes a fresh one at a new signature
    md = client.get(f"/v1/lake/namespaces/{ns}/tables/events").json()["metadata"]
    new_view = md["properties"]["duckicelake.masking-view-name"]
    assert new_view != old_view
    assert _live_view_rows(settings.pg_dsn, ns, new_view) == 1


def test_ducklake_credentials_namespace_only(client, settings):
    """Without ?table the endpoint vends namespace-prefix creds and no view
    (transparent mode v1 requires a table)."""
    ns = _ns("nstop")
    _make_table(client, ns, "events")
    r = client.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials",
                   params={"principal": "bob"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["masked_view"] is None
    assert body["transparent"] is False
    assert body["s3"]["session-token"]
    assert "ATTACH" in body["ducklake_attach_sql"]


def test_fail_open_on_unmaterializable_view(client, settings):
    """A policy whose mask body is invalid SQL produces a plan whose view
    cannot be created (DuckDB binds views at CREATE). Reads must survive:
    LoadTable 200 with advisory signals but no view; the credentials
    endpoint 200 with the failure audited as error_unmasked."""
    ns = _ns("brkn")
    tag = f"broken_{uuid.uuid4().hex[:6]}"
    _make_table(client, ns, "events")
    # isolated tag + policy names — the policy body is broken on purpose
    # and must not leak into other tests' tables
    client.post("/v1/lake/governance/tags",
                json={"namespace": "pii", "name": tag}).raise_for_status()
    client.post("/v1/lake/governance/object-tags",
                json={"object-kind": "column", "schema": ns, "object": "events",
                      "column": "email", "tag-namespace": "pii",
                      "tag-name": tag}).raise_for_status()
    client.post("/v1/lake/governance/masking-policies",
                json={"name": f"mask_{tag}", "signature": "(val VARCHAR)",
                      "body": "no_such_function_xyz(val)",
                      "unmasked-roles": ["pii_reader"]}).raise_for_status()
    client.post("/v1/lake/governance/policy-attachments",
                json={"policy-kind": "masking", "policy-name": f"mask_{tag}",
                      "target-kind": "tag", "tag-namespace": "pii",
                      "tag-name": tag}).raise_for_status()

    # LoadTable still 200: advisory stamping present, no view advertised
    r = client.get(f"/v1/lake/namespaces/{ns}/tables/events")
    assert r.status_code == 200, r.text
    props = r.json()["metadata"]["properties"]
    assert props["duckicelake.masked-columns"] == "email"
    assert "duckicelake.masking-view-name" not in props

    # credentials endpoint still 200, vending unmasked, audited as such
    r = client.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials",
                   params={"table": "events", "principal": "bob"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["masked_view"] is None
    assert body["s3"] is not None

    audit = client.get("/v1/lake/governance/audit").json()["entries"]
    vends = [e for e in audit if e["operation"] == "ducklake_credentials"
             and e["object"] == f"{ns}.events"]
    assert vends and vends[0]["decision"] == "error_unmasked"


# ---- Phase 3a: PG reader role + RLS -----------------------------------------

from datetime import datetime, timedelta, timezone

from duckicelake import pg_rls


def _vend(client, ns: str, sub: str, table: str = "events") -> dict:
    r = client.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials",
                   params={"table": table, "principal": sub})
    assert r.status_code == 200, r.text
    return r.json()


def test_rls_principal_role_name_pure():
    a = pg_rls.principal_role_name("bob")
    b = pg_rls.principal_role_name("bob")
    assert a == b and a.startswith("duckicelake_p_bob_") and len(a) <= 63
    hostile = pg_rls.principal_role_name("Robert'); DROP TABLE x;-- " + "x" * 100)
    assert len(hostile) <= 63
    # same sanitized form, different subs → distinct roles
    assert pg_rls.principal_role_name("a.b") != pg_rls.principal_role_name("a_b")


def test_rls_ensure_idempotent(settings, direct_catalog):
    pg_rls.ensure_rls(direct_catalog, settings)
    pg_rls.ensure_rls(direct_catalog, settings)
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute(
            "SELECT tablename, count(*) FROM pg_policies "
            "WHERE policyname = 'duckicelake_rls' GROUP BY tablename")
        rows = dict(cur.fetchall())
        # exactly one policy per policied table, on the expected anchors
        assert all(n == 1 for n in rows.values())
        assert "ducklake_table" in rows and "ducklake_data_file" in rows
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s",
                    (settings.reader_group_role,))
        assert cur.fetchone()
        # inlined-data payload tables carry no reader grant
        cur.execute("""
            SELECT count(*) FROM information_schema.role_table_grants
            WHERE grantee = %s AND table_name LIKE 'ducklake\\_inlined\\_data\\_%%'
              AND table_name <> 'ducklake_inlined_data_tables'
        """, (settings.reader_group_role,))
        assert cur.fetchone()[0] == 0


def test_rls_vended_dsn_is_reader(client, settings):
    ns = _ns("rdsn")
    _make_table(client, ns, "events")
    body = _vend(client, ns, "bob")
    assert body["pg_role"] and body["pg_role"].startswith("duckicelake_p_bob_")
    assert "password=" in body["ducklake_dsn"]
    assert f"user={body['pg_role']}" in body["ducklake_dsn"]
    assert "READ_ONLY" in body["ducklake_attach_sql"]
    assert body["pg_valid_until"] is not None
    with psycopg.connect(body["ducklake_dsn"], autocommit=True) as c, c.cursor() as cur:
        cur.execute("SELECT session_user, public.duckicelake_session_principal()")
        role, principal = cur.fetchone()
        assert role == body["pg_role"] and principal == "bob"
        # governance sidecars are not readable by the reader
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("SELECT count(*) FROM public.duckicelake_role_grant")


def test_rls_object_grant_allowlist(client, settings):
    """An explicit select object-grant flips the table to allowlist:
    ungranted principals can't even see it; granted ones and the owner
    are unaffected."""
    ns = _ns("acl")
    _make_table(client, ns, "events")
    _seed_rows(settings, ns)
    client.post("/v1/lake/governance/roles",
                json={"name": "analysts"}).raise_for_status()
    client.post("/v1/lake/governance/object-grants",
                json={"object-kind": "table", "schema": ns, "object": "events",
                      "privilege": "select", "role": "analysts"}).raise_for_status()
    client.post("/v1/lake/governance/role-grants",
                json={"role": "analysts", "principal": "alice"}).raise_for_status()

    bob = _vend(client, ns, "bob")
    con = _vended_duckdb(settings, bob)
    with pytest.raises(duckdb.Error, match="does not exist"):
        con.execute(f'SELECT count(*) FROM lake."{ns}".events')
    con.close()

    alice = _vend(client, ns, "alice")
    con = _vended_duckdb(settings, alice)
    assert con.execute(f'SELECT count(*) FROM lake."{ns}".events').fetchone()[0] == 2
    con.close()

    # the owner (proxy) is never affected — RLS is not FORCEd
    con = _root_duckdb(settings)
    assert con.execute(f'SELECT count(*) FROM lake."{ns}".events').fetchone()[0] == 2
    con.close()


def test_rls_file_layer_interlock(client, settings, direct_catalog):
    """The dormant Phase-4 contract: the two table properties hide base
    file rows from non-bypass principals; bypass roles and the owner are
    unaffected. (Phase 4 sets these when masked exports exist.)"""
    ns = _ns("ilock")
    _make_table(client, ns, "events")
    _seed_rows(settings, ns)
    client.post("/v1/lake/governance/roles",
                json={"name": "pii_reader"}).raise_for_status()
    client.post("/v1/lake/governance/role-grants",
                json={"role": "pii_reader", "principal": "alice"}).raise_for_status()
    direct_catalog.upsert_table_properties([ns], "events", set_map={
        "duckicelake.file-layer-masking": "true",
        "duckicelake.file-layer-bypass-roles": "pii_reader",
    })

    bob = _vend(client, ns, "bob")
    con = _vended_duckdb(settings, bob)
    assert con.execute(f'SELECT count(*) FROM lake."{ns}".events').fetchone()[0] == 0
    con.close()

    alice = _vend(client, ns, "alice")
    con = _vended_duckdb(settings, alice)
    assert con.execute(f'SELECT count(*) FROM lake."{ns}".events').fetchone()[0] == 2
    con.close()

    con = _root_duckdb(settings)
    assert con.execute(f'SELECT count(*) FROM lake."{ns}".events').fetchone()[0] == 2
    con.close()


def test_rls_reader_is_readonly(client, settings):
    ns = _ns("rro")
    _make_table(client, ns, "events")
    bob = _vend(client, ns, "bob")
    con = _vended_duckdb(settings, bob)
    with pytest.raises(duckdb.Error, match="read-only"):
        con.execute(f'INSERT INTO lake."{ns}".events VALUES (9, \'x@x.com\')')
    con.close()
    # PG-level belt-and-braces: direct INSERT as the reader role is denied
    with psycopg.connect(bob["ducklake_dsn"], autocommit=True) as c, c.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("INSERT INTO public.ducklake_metadata VALUES ('x','y',1,NULL)")


def test_rls_revend_rotates(client, settings):
    ns = _ns("rot")
    _make_table(client, ns, "events")
    first = _vend(client, ns, "carol")
    second = _vend(client, ns, "carol")
    assert first["pg_role"] == second["pg_role"]
    assert first["ducklake_dsn"] != second["ducklake_dsn"]   # new password
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute("SELECT expires_at FROM public.duckicelake_pg_principal "
                    "WHERE pg_role = %s", (first["pg_role"],))
        assert cur.fetchone()[0] >= datetime.now(timezone.utc) + timedelta(minutes=50)
    # rotated creds still connect (trust auth in dev; verifies bookkeeping)
    con = _vended_duckdb(settings, second)
    con.execute("SELECT 1")
    con.close()


def test_rls_gc_expired_roles(settings, direct_catalog):
    role, _pw = pg_rls.provision_principal_role(
        direct_catalog, settings, "ghost-principal",
        datetime.now(timezone.utc) - timedelta(days=30))
    pg_rls.gc_expired_roles(direct_catalog)
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
        assert cur.fetchone() is None        # past drop grace → dropped
        cur.execute("SELECT 1 FROM public.duckicelake_pg_principal "
                    "WHERE pg_role = %s", (role,))
        assert cur.fetchone() is None
