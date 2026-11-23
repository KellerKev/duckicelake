"""Lineage (lineage.py / lineage_api.py): commit harvest with trusted writer
attribution, access events from vends, result-set query edges, ingest of
OpenLineage RunEvents, and the graph. Live proxy; unique namespaces in the
shared `lake` catalog, every assertion filtered to them."""
from __future__ import annotations

import uuid

import pytest

from duckicelake import lineage
from test_governance_phase3 import (SCHEMA_JSON, _make_table, _make_table_only,  # noqa: F401
                                    _vended_duckdb, direct_catalog)


# ---- pure ---------------------------------------------------------------

@pytest.mark.parametrize("text, want", [
    ('created_table:"s"."t",inlined_insert:3', [("created_table", ["s", "t"]),
                                                ("inlined_insert", "3")]),
    ('created_table:"s"."my.t,x"', [("created_table", ["s", "my.t,x"])]),
    ('created_view:"a""b"."c"', [("created_view", ['a"b', "c"])]),
    ("dropped_table:12", [("dropped_table", "12")]),
    ("", []),
    (None, []),
    ('created_table:"unterminated', [("unparsed", 'created_table:"unterminated')]),
])
def test_parse_changes(text, want):
    assert lineage.parse_changes(text) == want


def test_parent_facet_from_commit_extra_info():
    rid = str(uuid.uuid4())
    f = lineage._parent_facet(f'{{"openlineage": {{"run_id": "{rid}", "job_name": "j", '
                              f'"job_namespace": "levitate"}}}}')
    assert f["run"]["runId"] == rid and f["job"] == {"namespace": "levitate", "name": "j"}
    assert lineage._parent_facet('{"job": "x"}') is None
    assert lineage._parent_facet("not json") is None


def _run_event(inputs, outputs, *, ns="duckicelake://localhost/lake", job="etl.step"):
    return {"eventType": "COMPLETE", "eventTime": "2026-11-23T10:00:00Z",
            "producer": "https://example.test/producer",
            "run": {"runId": str(uuid.uuid4())},
            "job": {"namespace": "levitate", "name": job},
            "inputs": [{"namespace": ns, "name": n} for n in inputs],
            "outputs": [{"namespace": ns, "name": n} for n in outputs]}


@pytest.mark.parametrize("mutate, msg", [
    (lambda e: e["run"].update(runId="nope"), "UUID"),
    (lambda e: e.update(eventTime="yesterday"), "ISO-8601"),
    (lambda e: e["job"].pop("name"), "job.namespace"),
    (lambda e: e["inputs"].append({"name": "x"}), "namespace and name"),
    (lambda e: e.update(eventType="DONE"), "run state"),
])
def test_validate_run_event_rejects(mutate, msg):
    e = _run_event(["a.b"], ["a.c"])
    mutate(e)
    with pytest.raises(lineage.IngestError, match=msg):
        lineage.validate_run_event(e)


# ---- live ---------------------------------------------------------------

def _ns(s: str) -> str:
    return f"lin_{s}_{uuid.uuid4().hex[:6]}"


def _ds_ns(client) -> str:
    """This catalog's dataset namespace (it carries the public host)."""
    return client.get("/v1/lake/lineage", params={"dataset": "x.y"}).json()["namespace"]


def _events(client, dataset, kind=None):
    params = {"dataset": dataset, "limit": 5000}
    if kind:
        params["kind"] = kind
    r = client.get("/v1/lake/lineage/events", params=params)
    assert r.status_code == 200, r.text
    return r.json()["events"]


def test_vended_write_is_attributed_to_its_principal(client, settings):
    ns = _ns("wr")
    _make_table(client, ns, "events")
    who = f"ingest_{uuid.uuid4().hex[:6]}"
    body = client.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials",
                      params={"write": 1, "principal": who, "table": "events"}).json()
    assert body["lineage_namespace"] == _ds_ns(client)
    con = _vended_duckdb(settings, body)
    alias = body["ducklake_attach_sql"].split(" AS ", 1)[1].split()[0]
    con.execute(f"INSERT INTO {alias}.\"{ns}\".events VALUES (1, 'a@x.io')")
    con.close()

    commits = _events(client, f"{ns}.events", "commit")
    created = [e for e in commits
               if e["event"]["outputs"][0]["facets"].get("lifecycleStateChange", {})
               .get("lifecycleStateChange") == "CREATE"]
    assert created, commits
    writes = [e for e in commits if e["principal"] == who]
    assert len(writes) == 1, commits
    ev = writes[0]["event"]
    assert ev["job"]["name"] == "duckicelake.commit"
    assert ev["outputs"][0]["facets"]["duckicelake_write"]["operations"] == ["insert"]
    writer = ev["run"]["facets"]["duckicelake_commit"]["writer"]
    assert writer["principal"] == who and writer["via"] == "vended"

    access = _events(client, f"{ns}.events", "access")
    assert any(a["principal"] == who
               and a["event"]["job"]["name"] == "duckicelake.access.ducklake_credentials"
               for a in access), access


def test_rename_and_drop_lifecycle(client, settings, direct_catalog):  # noqa: F811
    ns = _ns("ren")
    _make_table(client, ns, "events")
    alias = settings.catalog_name
    with direct_catalog.cursor() as c:
        c.execute(f'ALTER TABLE "{alias}"."{ns}".events RENAME TO events2')
        c.execute(f'DROP TABLE "{alias}"."{ns}".events2')
    evs = _events(client, f"{ns}.events2", "commit")
    states = [e["event"]["outputs"][0]["facets"]["lifecycleStateChange"] for e in evs]
    assert [s["lifecycleStateChange"] for s in states] == ["RENAME", "DROP"], states
    assert states[0]["previousIdentifier"]["name"] == f"{ns}.events"


def test_result_set_links_its_input_tables(client):
    ns = _ns("rs")
    _make_table(client, ns, "events")
    r = client.post(f"/v1/lake/namespaces/{ns}/result-sets", params={"principal": "carol"},
                    json={"sql": "WITH x AS (SELECT * FROM events) SELECT count(*) FROM x"})
    assert r.status_code in (200, 201), r.text
    q = _events(client, f"{ns}.events", "query")
    assert len(q) == 1, q
    ev = q[0]["event"]
    assert [d["name"] for d in ev["inputs"]] == [f"{ns}.events"]     # the CTE is not a table
    assert ev["outputs"][0]["namespace"].endswith("/result-sets")
    assert q[0]["principal"] == "carol"


def test_ingest_builds_the_graph(client):
    ns = _ns("ing")
    a, b, c = f"{ns}.raw", f"{ns}.clean", f"{ns}.report"
    dns = _ds_ns(client)
    r = client.post("/v1/lake/lineage", json={"events": [
        _run_event([a], [b], job="clean", ns=dns),
        _run_event([b], [c], job="report", ns=dns),
    ]})
    assert r.status_code == 201, r.text
    up = client.get("/v1/lake/lineage", params={"dataset": c, "direction": "upstream"}).json()
    assert {a, b, c} <= set(up["nodes"])
    assert {(e["from"], e["to"]) for e in up["edges"]} >= {(a, b), (b, c)}
    down = client.get("/v1/lake/lineage", params={"dataset": a, "direction": "downstream"}).json()
    assert c in down["nodes"]
    stored = _events(client, c, "ingest")[0]["event"]
    assert stored["run"]["facets"]["duckicelake_ingest"]["principal"]   # caller stamped
    # a dataset outside this catalog is kept under its full name
    client.post("/v1/lake/lineage", json=_run_event([a], [c], ns="s3://other")
                ).raise_for_status()
    assert _events(client, f"s3://other/{c}", "ingest")
    # bad events are refused whole
    bad = client.post("/v1/lake/lineage", json=[_run_event([a], [b]), {"run": {}}])
    assert bad.status_code == 400
    assert client.post("/v1/lake/lineage", content=b"{nope").status_code == 400


def test_events_cursor_and_ndjson(client):
    ns = _ns("cur")
    dns = _ds_ns(client)
    client.post("/v1/lake/lineage", json=[_run_event([f"{ns}.a"], [f"{ns}.b"], ns=dns),
                                          _run_event([f"{ns}.b"], [f"{ns}.c"], ns=dns)]
                ).raise_for_status()
    first = client.get("/v1/lake/lineage/events",
                       params={"dataset": f"{ns}.b", "limit": 1}).json()
    rest = client.get("/v1/lake/lineage/events",
                      params={"dataset": f"{ns}.b", "after_id": first["last_id"]}).json()
    assert len(first["events"]) == 1 and len(rest["events"]) == 1
    nd = client.get("/v1/lake/lineage/events", params={"dataset": f"{ns}.b", "format": "ndjson"})
    assert nd.headers["content-type"].startswith("application/x-ndjson")
    assert len(nd.text.strip().splitlines()) == 2


def test_rest_commit_attribution(client, settings, direct_catalog):  # noqa: F811
    """A REST commit runs on the proxy's own connection, so the trigger sees
    the proxy role; the commit handler names the caller for the snapshots it
    made on its table (lineage.attribute_commit)."""
    ns = _ns("rest")
    _make_table(client, ns, "events")
    before = lineage.current_snapshot_id(direct_catalog)
    alias = settings.catalog_name
    with direct_catalog.cursor() as c:     # enough rows to land as a Parquet file
        c.execute(f'INSERT INTO "{alias}"."{ns}".events '
                  "SELECT i, 'u' || i || '@x.io' FROM range(5000) t(i)")
    lineage.attribute_commit(direct_catalog, principal="rest_writer",
                             table=(ns, "events"), after_snapshot=before)
    writes = [e for e in _events(client, f"{ns}.events", "commit")
              if e["event"]["outputs"][0]["facets"].get("duckicelake_write")]
    assert [w["principal"] for w in writes] == ["rest_writer"], writes
    assert writes[0]["event"]["run"]["facets"]["duckicelake_commit"]["writer"]["via"] == "rest"


def test_replace_is_one_overwrite(client, settings, direct_catalog):  # noqa: F811
    ns = _ns("rep")
    _make_table(client, ns, "events")
    alias = settings.catalog_name
    with direct_catalog.cursor() as c:
        c.execute(f'CREATE OR REPLACE TABLE "{alias}"."{ns}".events AS SELECT 1 AS id')
    states = [e["event"]["outputs"] for e in _events(client, f"{ns}.events", "commit")]
    assert [o[0]["facets"]["lifecycleStateChange"]["lifecycleStateChange"] for o in states] \
        == ["CREATE", "OVERWRITE"], states
    assert len(states[1]) == 1          # not a dropped table and a created one


def test_names_are_matched_ignoring_case(client):
    """A producer that folds case (Levitate reports the tables a write read in
    lowercase) still links to the table: the event is stored under the name
    the catalog has, and a lookup by any spelling finds it."""
    ns = _ns("case")
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    for t in ("RawOrders", "Report"):
        client.post(f"/v1/lake/namespaces/{ns}/tables",
                    json={"name": t, "schema": SCHEMA_JSON}).raise_for_status()
    dns = _ds_ns(client)
    client.post("/v1/lake/lineage", json=_run_event(
        [f"{ns}.raworders"], [f"{ns}.REPORT"], ns=dns)).raise_for_status()
    g = client.get("/v1/lake/lineage", params={"dataset": f"{ns}.report"}).json()
    assert g["dataset"] == f"{ns}.Report"
    assert [(e["from"], e["to"]) for e in g["edges"]] == [(f"{ns}.RawOrders", f"{ns}.Report")]
    # the same node as the table's own commit, so both show up together
    kinds = {e["kind"] for e in _events(client, f"{ns}.rawORDERS")}
    assert kinds >= {"commit", "ingest"}, kinds
    stored = _events(client, f"{ns}.Report", "ingest")[0]["event"]
    assert stored["inputs"][0]["name"] == f"{ns}.RawOrders"
    assert stored["run"]["facets"]["duckicelake_ingest"]["renamed"] == {
        f"{ns}.raworders": f"{ns}.RawOrders", f"{ns}.REPORT": f"{ns}.Report"}


def _carried(client, ns):
    got = client.get("/v1/lake/lineage/carried-tags")
    assert got.status_code == 200, got.text
    return sorted((r["table"], r["tag"]) for r in got.json()["carried"] if r["schema"] == ns)


def _carrying(ns, table, tags, dns, run_id=None):
    e = _run_event([f"{ns}.src"], [f"{ns}.{table}"], ns=dns)
    e["outputs"][0]["facets"] = {"duckicelake_carriedTags": {"tags": tags}}
    if run_id:
        e["run"]["runId"] = run_id
    return e


def test_carried_tags_follow_the_table(client, settings, direct_catalog):  # noqa: F811
    ns = _ns("car")
    _make_table(client, ns, "copy")
    _make_table_only(client, ns, "other")
    dns = _ds_ns(client)
    alias = settings.catalog_name
    client.post("/v1/lake/lineage", json=[
        _carrying(ns, "COPY", ["PII.Email"], dns),
        _carrying(ns, "copy", ["tier.gold"], dns),
        _carrying(ns, "other", ["pii.email"], dns)]).raise_for_status()
    assert _carried(client, ns) == [("copy", "pii.email"), ("copy", "tier.gold"),
                                    ("other", "pii.email")]
    assert client.get("/v1/lake/lineage", params={"dataset": f"{ns}.copy"}
                      ).json()["carried_tags"] == ["pii.email", "tier.gold"]

    # an insert changes nothing; a rename takes the tags along
    with direct_catalog.cursor() as c:
        c.execute(f'INSERT INTO "{alias}"."{ns}".copy VALUES (1, \'a@x.io\')')
        c.execute(f'ALTER TABLE "{alias}"."{ns}".copy RENAME TO copy2')
    assert _carried(client, ns) == [("copy2", "pii.email"), ("copy2", "tier.gold"),
                                    ("other", "pii.email")]

    # replaced by anyone, with anything: it starts afresh. The run that made
    # the replacing commit keeps what it reported, even when its report was
    # there before the commit was read.
    run_id = str(uuid.uuid4())
    client.post("/v1/lake/lineage", json=_carrying(ns, "copy2", ["tier.silver"], dns, run_id)
                ).raise_for_status()
    extra = '{"openlineage": {"run_id": "%s", "job_name": "j", "job_namespace": "t"}}' % run_id
    with direct_catalog.cursor() as c:
        c.execute("BEGIN")
        c.execute(f'CALL "{alias}".set_commit_message(\'t\', \'replace\', extra_info => ?)', [extra])
        c.execute(f'CREATE OR REPLACE TABLE "{alias}"."{ns}".copy2 AS SELECT 1 AS id')
        c.execute("COMMIT")
        c.execute(f'DROP TABLE "{alias}"."{ns}".other')
    assert _carried(client, ns) == [("copy2", "tier.silver")]

    bad = _carrying(ns, "copy2", "pii.email", dns)
    assert client.post("/v1/lake/lineage", json=bad).status_code == 400


def test_unpoliced_load_table_is_an_access_event(client):
    """No policy applies, so the audit trail has no row for the read; lineage
    records it, once per principal and table in the dedup window."""
    ns = _ns("plain")
    _make_table(client, ns, "events")
    for _ in range(3):
        client.get(f"/v1/lake/namespaces/{ns}/tables/events").raise_for_status()
    access = [a for a in _events(client, f"{ns}.events", "access")
              if a["event"]["job"]["name"] == "duckicelake.access.load_table"]
    assert 1 <= len(access) <= 4, access       # at most one per proxy worker
    facet = access[0]["event"]["run"]["facets"]["duckicelake_access"]
    assert facet["decision"] == "ok" and facet["channel"] == "rest"
    audit = client.get("/v1/lake/governance/audit", params={"limit": 500}).json()["entries"]
    assert not [e for e in audit if e["operation"] == "load_table"
                and e["object"] == f"{ns}.events"]


def test_commit_without_a_recorded_writer(client, settings, direct_catalog):  # noqa: F811
    """A commit from before the writer trigger existed: the event says nobody
    was recorded, unless the audit trail shows exactly one principal
    committing that table through REST at that moment."""
    alias = settings.catalog_name
    sc = direct_catalog.sidecar_sql

    def write_without_trigger_row(ns, auditors):
        before = lineage.current_snapshot_id(direct_catalog)
        with direct_catalog.cursor() as c:
            c.execute(f'INSERT INTO "{alias}"."{ns}".events VALUES (1, \'a@x.io\')')
        with direct_catalog.pg_cursor() as cur:
            cur.execute(f"DELETE FROM {sc}.duckicelake_snapshot_writer WHERE snapshot_id > %s",
                        (before,))
            for who in auditors:
                cur.execute(
                    f"INSERT INTO {sc}.duckicelake_governance_audit "
                    "(principal_sub, operation, object, decision) VALUES (%s, 'commit_table', %s, 'ok')",
                    (who, f"{ns}.events"))
        writes = [e for e in _events(client, f"{ns}.events", "commit")
                  if e["event"]["outputs"][0]["facets"].get("duckicelake_write")]
        assert len(writes) == 1, writes
        return writes[0]["principal"], writes[0]["event"]["run"]["facets"]["duckicelake_commit"]["writer"]

    for label, auditors, want in (("none", [], (None, None, False)),
                                  ("one", ["etl@x.io"], ("etl@x.io", "audit", True)),
                                  ("two", ["a@x.io", "b@x.io"], (None, None, False))):
        ns = _ns("old" + label)
        _make_table(client, ns, "events")
        _events(client, f"{ns}.events")           # harvest the create first
        principal, writer = write_without_trigger_row(ns, auditors)
        assert (principal, writer["via"], writer["recorded"]) == want, (label, writer)


def test_writer_trigger_never_waits_long_for_a_busy_table(settings, direct_catalog, monkeypatch):  # noqa: F811
    """Creating the trigger locks ducklake_snapshot against writers. Behind a
    client's open transaction that would queue every later commit, so it
    gives up quickly and is tried again later; once there, it is left alone."""
    import time

    import psycopg
    sc = direct_catalog.sidecar_sql
    schema = direct_catalog.sidecar_schema
    monkeypatch.setattr(lineage, "TRIGGER_LOCK_TIMEOUT_MS", 300)

    def has_trigger(cur):
        cur.execute("SELECT count(*) FROM pg_trigger WHERE tgname = 'duckicelake_snapshot_writer' "
                    "AND tgrelid = to_regclass(%s)", (f"{sc}.ducklake_snapshot",))
        return cur.fetchone()[0] == 1

    with direct_catalog.pg_cursor() as cur:
        lineage.ensure_lineage_sidecars(cur, schema)
        assert has_trigger(cur)
        cur.execute(f"DROP TRIGGER duckicelake_snapshot_writer ON {sc}.ducklake_snapshot")
        lineage.reset_lineage_cache()
        try:
            with psycopg.connect(settings.pg_dsn) as busy:       # a writer's open transaction
                busy.execute(f"LOCK TABLE {sc}.ducklake_snapshot IN ROW EXCLUSIVE MODE")
                t0 = time.monotonic()
                lineage.ensure_lineage_sidecars(cur, schema)
                assert time.monotonic() - t0 < 5
                assert not has_trigger(cur) and schema in lineage._TRIGGER_PENDING
                lineage.ensure_lineage_sidecars(cur, schema)      # not due yet: no new try
                assert not has_trigger(cur)
                busy.rollback()
            lineage._TRIGGER_PENDING[schema] = 0                 # due
            lineage.ensure_lineage_sidecars(cur, schema)
            assert has_trigger(cur) and schema not in lineage._TRIGGER_PENDING
            cur.execute("SHOW lock_timeout")
            assert cur.fetchone()[0] in ("0", "0ms")
        finally:
            lineage.reset_lineage_cache()
            lineage.ensure_lineage_sidecars(cur, schema)
            assert has_trigger(cur)
