"""Lineage (lineage.py / lineage_api.py): commit harvest with trusted writer
attribution, access events from vends, result-set query edges, ingest of
OpenLineage RunEvents, and the graph. Live proxy; unique namespaces in the
shared `lake` catalog, every assertion filtered to them."""
from __future__ import annotations

import uuid

import pytest

from duckicelake import lineage
from test_governance_phase3 import _make_table, _vended_duckdb, direct_catalog  # noqa: F401


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
