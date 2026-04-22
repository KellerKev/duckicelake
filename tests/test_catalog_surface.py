"""Smoke: the REST surface responds on the expected endpoints with the
shape clients actually use. Not exhaustive — the big cross-client check
lives in `duckdb_client.py`. These tests exist so CI fails fast on
regressions.
"""
from __future__ import annotations

import uuid


def _ns(suffix: str) -> str:
    """Unique namespace per test so the session-scoped proxy doesn't
    leak state across tests."""
    return f"it_{suffix}_{uuid.uuid4().hex[:6]}"


def test_config_endpoint(client):
    r = client.get("/v1/config")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["defaults"]["warehouse"] == "lake"
    assert body["overrides"]["prefix"] == "lake"
    assert any("namespaces" in ep for ep in body["endpoints"])


def test_health_and_readiness(client):
    assert client.get("/healthz").status_code == 200
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


def test_metrics_endpoint_scrapable(client):
    # Trigger at least one request so we have labels populated.
    client.get("/v1/config")
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers.get("content-type", "")
    body = r.text
    # Prometheus-format metric lines we rely on.
    assert "duckicelake_requests_total" in body
    assert "duckicelake_request_seconds" in body
    assert "duckicelake_metadata_cache_size" in body


def test_namespace_lifecycle(client):
    ns = _ns("nslc")
    r = client.post("/v1/lake/namespaces", json={"namespace": [ns]})
    assert r.status_code == 200, r.text
    r = client.get(f"/v1/lake/namespaces/{ns}")
    assert r.status_code == 200
    # list should include it
    names = [n[0] for n in client.get("/v1/lake/namespaces").json()["namespaces"]]
    assert ns in names
    # drop
    assert client.delete(f"/v1/lake/namespaces/{ns}").status_code == 204
    assert client.get(f"/v1/lake/namespaces/{ns}").status_code == 404


def test_table_create_load_drop(client):
    ns = _ns("tbl")
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    schema = {
        "type": "struct", "schema-id": 0,
        "fields": [
            {"id": 1, "name": "id",   "required": True,  "type": "long"},
            {"id": 2, "name": "name", "required": False, "type": "string"},
        ],
    }
    r = client.post(
        f"/v1/lake/namespaces/{ns}/tables",
        json={"name": "t1", "schema": schema},
    )
    assert r.status_code == 200, r.text
    md = r.json()["metadata"]
    assert md["format-version"] in (2, 3)
    assert len(md["schemas"]) >= 1

    r = client.get(f"/v1/lake/namespaces/{ns}/tables/t1")
    assert r.status_code == 200
    assert r.json()["metadata"]["table-uuid"]

    # drop with purge — should 204 and subsequent load 404
    r = client.delete(f"/v1/lake/namespaces/{ns}/tables/t1?purgeRequested=true")
    assert r.status_code == 204
    assert client.get(f"/v1/lake/namespaces/{ns}/tables/t1").status_code == 404

    client.delete(f"/v1/lake/namespaces/{ns}")


def test_set_and_get_properties(client):
    ns = _ns("props")
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    client.post(f"/v1/lake/namespaces/{ns}/tables", json={
        "name": "t", "schema": {"type": "struct", "schema-id": 0, "fields": [
            {"id": 1, "name": "id", "required": False, "type": "long"},
        ]},
    }).raise_for_status()
    r = client.post(f"/v1/lake/namespaces/{ns}/tables/t", json={
        "updates": [{"action": "set-properties", "updates": {"owner": "ci", "retention": "14d"}}],
    })
    assert r.status_code == 200
    props = r.json()["metadata"]["properties"]
    assert props.get("owner") == "ci"
    assert props.get("retention") == "14d"

    # Reload — properties persist via sidecar.
    props2 = client.get(f"/v1/lake/namespaces/{ns}/tables/t").json()["metadata"]["properties"]
    assert props2.get("owner") == "ci"

    client.delete(f"/v1/lake/namespaces/{ns}/tables/t?purgeRequested=true")
    client.delete(f"/v1/lake/namespaces/{ns}")


def test_unknown_prefix_is_404(client):
    r = client.get("/v1/not-a-catalog/namespaces")
    assert r.status_code == 404


def test_set_location_is_501(client):
    ns = _ns("loc")
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    client.post(f"/v1/lake/namespaces/{ns}/tables", json={
        "name": "t", "schema": {"type": "struct", "schema-id": 0, "fields": [
            {"id": 1, "name": "id", "required": False, "type": "long"},
        ]},
    }).raise_for_status()
    r = client.post(f"/v1/lake/namespaces/{ns}/tables/t", json={
        "updates": [{"action": "set-location", "location": "s3://elsewhere/"}],
    })
    assert r.status_code == 501
    assert r.json()["error"]["type"] == "NotImplementedException"
    client.delete(f"/v1/lake/namespaces/{ns}/tables/t?purgeRequested=true")
    client.delete(f"/v1/lake/namespaces/{ns}")


def test_compact_endpoint_returns_ok(client):
    """Admin compaction on an empty table should succeed (nothing to
    compact, but the procedure is idempotent)."""
    ns = _ns("cpc")
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    client.post(f"/v1/lake/namespaces/{ns}/tables", json={
        "name": "t", "schema": {"type": "struct", "schema-id": 0, "fields": [
            {"id": 1, "name": "id", "required": False, "type": "long"},
        ]},
    }).raise_for_status()
    r = client.post(f"/v1/lake/admin/namespaces/{ns}/tables/t/compact")
    assert r.status_code == 200, r.text
    body = r.json()
    # Both sub-ops should be reported, though we don't assert 'ok' —
    # DuckLake versions differ in which procs require live files.
    assert "merge" in body and "cleanup" in body
    client.delete(f"/v1/lake/namespaces/{ns}/tables/t?purgeRequested=true")
    client.delete(f"/v1/lake/namespaces/{ns}")
