"""Phase 3 governance tests — ad-hoc DuckLake masking views.

Layers (grown stage by stage):
  * `test_view_manager_*` — the MaskingViewManager primitive against the
    live catalog (a direct DuckLakeCatalog beside the session proxy, the
    test_notify_materialise.py pattern).
"""
from __future__ import annotations

import uuid

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
