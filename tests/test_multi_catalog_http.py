"""HTTP-level multi-catalog routing + isolation (qod integration).

Drives the running proxy: provision an isolated catalog over REST, then prove
that namespaces created under one catalog's {prefix} are invisible under
another's — the account boundary enforced through the Iceberg REST surface.
"""
from __future__ import annotations

import boto3
import psycopg
import pytest

TENANT = {
    "catalog_id": "tenant_x",
    "metadata_schema": "dl_tenantx__http",
    "data_prefix": "tenant_x/http/",
}
NS_DEFAULT = "mc_http_default"
NS_TENANT = "mc_http_tenant"


def _drop_ns_with_tables(client, prefix: str, ns: str) -> None:
    """Drop every table in the namespace (purge), then the namespace itself.
    A bare namespace-delete fails on a non-empty namespace, which would leak
    state into later tests (409 on re-create)."""
    r = client.get(f"/v1/{prefix}/namespaces/{ns}/tables")
    if r.status_code == 200:
        for ident in r.json().get("identifiers", []):
            client.delete(
                f"/v1/{prefix}/namespaces/{ns}/tables/{ident['name']}",
                params={"purgeRequested": "true"})
    client.delete(f"/v1/{prefix}/namespaces/{ns}")


@pytest.fixture()
def provisioned(client, settings):
    default_prefix = settings.catalog_name
    # Provision the tenant catalog (idempotent).
    r = client.post("/v1/catalogs", json=TENANT)
    assert r.status_code in (201, 409), r.text
    # Clean any leftovers from a prior run.
    for prefix, ns in ((default_prefix, NS_DEFAULT), (TENANT["catalog_id"], NS_TENANT)):
        _drop_ns_with_tables(client, prefix, ns)
    yield default_prefix
    for prefix, ns in ((default_prefix, NS_DEFAULT), (TENANT["catalog_id"], NS_TENANT)):
        _drop_ns_with_tables(client, prefix, ns)
    # NOTE: we deliberately do NOT drop the tenant metadata schema here. The
    # running proxy caches the catalog context (with its DuckLake ATTACH); if we
    # dropped the schema out from under it, a re-provision in the same session
    # would resurface a stale ATTACH. Provisioning is idempotent, so leaving the
    # schema is correct and re-run safe. S3 objects under the tenant prefix are
    # cleaned (harmless, keeps MinIO tidy).
    s3 = settings.s3
    cl = boto3.client("s3", endpoint_url=s3.endpoint, region_name=s3.region,
                      aws_access_key_id=s3.root_access_key,
                      aws_secret_access_key=s3.root_secret_key)
    for p in cl.get_paginator("list_objects_v2").paginate(
        Bucket=s3.bucket, Prefix=TENANT["data_prefix"]
    ):
        for o in p.get("Contents", []):
            cl.delete_object(Bucket=s3.bucket, Key=o["Key"])


def _ns_names(client, prefix):
    r = client.get(f"/v1/{prefix}/namespaces")
    assert r.status_code == 200, r.text
    return {n[0] for n in r.json()["namespaces"]}


def test_namespaces_isolated_across_catalogs(provisioned, client):
    default_prefix = provisioned
    tenant_prefix = TENANT["catalog_id"]

    assert client.post(f"/v1/{default_prefix}/namespaces",
                       json={"namespace": [NS_DEFAULT]}).status_code == 200
    assert client.post(f"/v1/{tenant_prefix}/namespaces",
                       json={"namespace": [NS_TENANT]}).status_code == 200

    default_ns = _ns_names(client, default_prefix)
    tenant_ns = _ns_names(client, tenant_prefix)

    assert NS_DEFAULT in default_ns and NS_DEFAULT not in tenant_ns
    assert NS_TENANT in tenant_ns and NS_TENANT not in default_ns


def test_unknown_prefix_404(provisioned, client):
    assert client.get("/v1/no_such_catalog/namespaces").status_code == 404


def test_views_routed_to_catalog_with_per_catalog_location(provisioned, client):
    tenant_prefix = TENANT["catalog_id"]
    assert client.post(f"/v1/{tenant_prefix}/namespaces",
                       json={"namespace": [NS_TENANT]}).status_code == 200
    body = {
        "name": "v1",
        "view-version": {
            "representations": [
                {"type": "sql", "sql": "SELECT 1 AS x", "dialect": "duckdb"}
            ]
        },
    }
    r = client.post(f"/v1/{tenant_prefix}/namespaces/{NS_TENANT}/views", json=body)
    assert r.status_code == 200, r.text
    # The view's advertised location lives under THIS catalog's data prefix,
    # not the default catalog's.
    assert "/tenant_x/http/" in r.json()["metadata"]["location"]

    views = client.get(f"/v1/{tenant_prefix}/namespaces/{NS_TENANT}/views").json()
    assert any(i["name"] == "v1" for i in views["identifiers"])

    # Drop the view so the fixture can drop the namespace cleanly.
    client.delete(f"/v1/{tenant_prefix}/namespaces/{NS_TENANT}/views/v1")


def test_ducklake_credentials_per_catalog(provisioned, client, settings):
    tenant_prefix = TENANT["catalog_id"]
    assert client.post(f"/v1/{tenant_prefix}/namespaces",
                       json={"namespace": [NS_TENANT]}).status_code == 200
    r = client.get(f"/v1/{tenant_prefix}/namespaces/{NS_TENANT}/ducklake-credentials")
    assert r.status_code == 200, r.text
    body = r.json()
    # A per-principal reader role was provisioned, and the vended ATTACH points
    # at THIS catalog's metadata schema + data prefix.
    assert body["pg_role"], body
    assert f"METADATA_SCHEMA '{TENANT['metadata_schema']}'" in body["ducklake_attach_sql"]
    assert "/tenant_x/http/" in body["ducklake_data_path"]
    assert "READ_ONLY" in body["ducklake_attach_sql"]


def test_reader_role_cross_account_isolated(provisioned, client):
    """The vended tenant reader can read its own catalog's metadata but is
    DENIED the default catalog's — cross-account isolation at the PG layer."""
    tenant_prefix = TENANT["catalog_id"]
    client.post(f"/v1/{tenant_prefix}/namespaces", json={"namespace": [NS_TENANT]})
    body = client.get(
        f"/v1/{tenant_prefix}/namespaces/{NS_TENANT}/ducklake-credentials").json()
    reader_dsn = body["ducklake_dsn"]

    with psycopg.connect(reader_dsn, autocommit=True) as c:
        # Own catalog's metadata: visible (rows RLS-filtered, but readable).
        n = c.execute(
            f'SELECT count(*) FROM "{TENANT["metadata_schema"]}".ducklake_schema'
        ).fetchone()[0]
        assert n >= 0
        # Default catalog's metadata: the tenant group has NO grant on it.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT count(*) FROM public.ducklake_schema").fetchone()


def test_table_create_load_routed_to_catalog(provisioned, client):
    tenant_prefix = TENANT["catalog_id"]
    assert client.post(f"/v1/{tenant_prefix}/namespaces",
                       json={"namespace": [NS_TENANT]}).status_code == 200
    schema = {
        "type": "struct", "schema-id": 0,
        "fields": [
            {"id": 1, "name": "id", "required": True, "type": "long"},
            {"id": 2, "name": "v", "required": False, "type": "string"},
        ],
    }
    r = client.post(f"/v1/{tenant_prefix}/namespaces/{NS_TENANT}/tables",
                    json={"name": "t1", "schema": schema})
    assert r.status_code == 200, r.text
    # The table's metadata location is under THIS catalog's data prefix.
    assert "/tenant_x/http/" in r.json()["metadata"]["location"]

    lr = client.get(f"/v1/{tenant_prefix}/namespaces/{NS_TENANT}/tables/t1")
    assert lr.status_code == 200
    assert "/tenant_x/http/" in lr.json()["metadata"]["location"]

    tables = client.get(f"/v1/{tenant_prefix}/namespaces/{NS_TENANT}/tables").json()
    assert any(i["name"] == "t1" for i in tables["identifiers"])

    # Drop+purge so the fixture can drop the namespace cleanly.
    client.delete(
        f"/v1/{tenant_prefix}/namespaces/{NS_TENANT}/tables/t1?purgeRequested=true")


# ---- Stage 3 (merge-stabilization): account authz + gated provisioning -----
#
# The session proxy runs auth-DISABLED (dev default), so the enforcement
# paths are exercised in-process: import the server module, swap in an
# enabled AuthConfig, and call the dependency/gate directly with real JWTs.

import types
import uuid as _uuid

from duckicelake.auth import AuthConfig, issue_token


def _enabled_cfg() -> AuthConfig:
    return AuthConfig(
        jwt_secret=b"test-secret-32-bytes-xxxxxxxxxxx",
        clients={"svc": {"secret": "s", "scope": "*:*:*", "roles": "",
                         "account": ""}},
        ttl_seconds=300,
        issuer="duckicelake",
    )


def _req_with_token(cfg, *, scope, account="", sub="tester"):
    tok = issue_token(cfg, sub, scope=scope,
                      roles="", account=account)["access_token"]
    return types.SimpleNamespace(headers={"authorization": f"Bearer {tok}"})


def test_account_scoped_catalog_access(monkeypatch, settings):
    """Cross-account access to a provisioned catalog is a 404 (not 403 — the
    prefix must not leak existence); the owning account and admin-scope
    tokens pass; the default catalog stays reachable to everyone."""
    import duckicelake.server as srv
    from fastapi import HTTPException

    cid = f"authz_{_uuid.uuid4().hex[:6]}"
    srv.registry.provision(cid, f"dl_{cid}__main", f"{cid}/main/", "acme")
    cfg = _enabled_cfg()
    monkeypatch.setattr(srv, "auth_cfg", cfg)
    try:
        # owning account → resolved
        ctx = srv.resolve_catalog(
            cid, _req_with_token(cfg, scope="ns:*:rw", account="acme"))
        assert ctx.catalog_id == cid and ctx.account_id == "acme"

        # wrong account → 404 (indistinguishable from unknown prefix)
        try:
            srv.resolve_catalog(
                cid, _req_with_token(cfg, scope="ns:*:rw", account="globex"))
            assert False, "cross-account access must 404"
        except HTTPException as e:
            assert e.status_code == 404

        # no account claim at all → 404
        try:
            srv.resolve_catalog(cid, _req_with_token(cfg, scope="ns:*:rw"))
            assert False, "account-less token must not reach an owned catalog"
        except HTTPException as e:
            assert e.status_code == 404

        # admin-scope token (control plane) reaches any catalog
        ctx = srv.resolve_catalog(cid, _req_with_token(cfg, scope="*:*:*"))
        assert ctx.catalog_id == cid

        # the default catalog has no owner → any authenticated caller
        ctx = srv.resolve_catalog(
            settings.catalog_name,
            _req_with_token(cfg, scope="ns:*:rw", account="globex"))
        assert ctx.catalog_id == settings.catalog_name
    finally:
        # drop the provisioned schema so reruns start clean
        with psycopg.connect(settings.pg_dsn, autocommit=True) as c:
            c.execute(f'DROP SCHEMA IF EXISTS "dl_{cid}__main" CASCADE')
            c.execute("DELETE FROM public.duckicelake_catalog WHERE catalog_id = %s",
                      [cid])


def test_provisioning_requires_admin_scope(monkeypatch):
    """POST /v1/catalogs is a control-plane op: with auth enabled, a
    non-admin token gets 403; an admin-scope token passes the gate."""
    import duckicelake.server as srv
    from fastapi import HTTPException

    cfg = _enabled_cfg()
    monkeypatch.setattr(srv, "auth_cfg", cfg)

    try:
        srv._require_admin(_req_with_token(cfg, scope="ns:*:rw", account="acme"))
        assert False, "non-admin token must not provision catalogs"
    except HTTPException as e:
        assert e.status_code == 403

    srv._require_admin(_req_with_token(cfg, scope="*:*:*"))  # no raise


def test_provisioning_open_when_auth_disabled(client, settings):
    """Dev default (auth off): provisioning stays reachable — matches every
    other endpoint's dev semantics. (The live session proxy runs auth-off.)"""
    cid = f"devprov_{_uuid.uuid4().hex[:6]}"
    try:
        r = client.post("/v1/catalogs", json={
            "catalog_id": cid, "metadata_schema": f"dl_{cid}__main",
            "data_prefix": f"{cid}/main/", "account_id": "acme",
            "create_default_namespace": False})
        assert r.status_code == 201, r.text
        # and with auth off, the account_id does not block access (dev semantics)
        r = client.get(f"/v1/{cid}/namespaces")
        assert r.status_code == 200, r.text
    finally:
        with psycopg.connect(settings.pg_dsn, autocommit=True) as c:
            c.execute(f'DROP SCHEMA IF EXISTS "dl_{cid}__main" CASCADE')
            c.execute("DELETE FROM public.duckicelake_catalog WHERE catalog_id = %s",
                      [cid])


# ---- Stage 4 (merge-stabilization): multi-catalog REST writes --------------

def test_commit_table_routed_to_catalog(provisioned, client, settings):
    """commit_table used to be default-catalog-only (explicit 404 for other
    prefixes). An add-schema commit against a tenant catalog must run in THAT
    catalog: the new column lands in its metadata schema, and the default
    catalog's same-named table is untouched."""
    default_prefix = provisioned
    tenant_prefix = TENANT["catalog_id"]
    schema = {
        "type": "struct", "schema-id": 0,
        "fields": [
            {"id": 1, "name": "id", "required": True, "type": "long"},
            {"id": 2, "name": "v", "required": False, "type": "string"},
        ],
    }
    for prefix, ns in ((default_prefix, NS_DEFAULT), (tenant_prefix, NS_TENANT)):
        assert client.post(f"/v1/{prefix}/namespaces",
                           json={"namespace": [ns]}).status_code == 200
        r = client.post(f"/v1/{prefix}/namespaces/{ns}/tables",
                        json={"name": "ct", "schema": schema})
        assert r.status_code == 200, r.text

    wider = {
        "type": "struct", "schema-id": 1,
        "fields": schema["fields"] + [
            {"id": 3, "name": "country", "required": False, "type": "string"},
        ],
    }
    r = client.post(
        f"/v1/{tenant_prefix}/namespaces/{NS_TENANT}/tables/ct",
        json={"requirements": [],
              "updates": [{"action": "add-schema", "schema": wider},
                          {"action": "set-current-schema", "schema-id": -1}]})
    assert r.status_code == 200, r.text
    fields = {f["name"] for f in r.json()["metadata"]["schemas"][-1]["fields"]}
    assert "country" in fields

    # physically landed in the TENANT metadata schema…
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute(
            f"""SELECT count(*) FROM "{TENANT['metadata_schema']}".ducklake_column
                WHERE column_name = 'country' AND end_snapshot IS NULL""")
        assert cur.fetchone()[0] == 1, "column must exist in tenant metadata"
        # …and NOT in the default catalog's copy of the same-named table
        cur.execute(
            """SELECT count(*) FROM public.ducklake_column col
               JOIN public.ducklake_table t USING (table_id)
               JOIN public.ducklake_schema s ON s.schema_id = t.schema_id
               WHERE s.schema_name = %s AND t.table_name = 'ct'
                 AND col.column_name = 'country' AND col.end_snapshot IS NULL
                 AND t.end_snapshot IS NULL AND s.end_snapshot IS NULL""",
            (NS_DEFAULT,))
        assert cur.fetchone()[0] == 0, "default catalog must be untouched"


def test_config_returns_per_catalog_prefix(provisioned, client, settings):
    """/v1/config?warehouse=<tenant> answers with THAT catalog's prefix
    (P1d parity). An UNRESOLVED warehouse falls back to the default prefix
    with 200 — clients send opaque warehouse hints here (the DuckDB iceberg
    ext passes its ATTACH string, e.g. the bucket name), so a 404 would
    break every such attach."""
    r = client.get("/v1/config", params={"warehouse": TENANT["catalog_id"]})
    assert r.status_code == 200, r.text
    assert r.json()["overrides"]["prefix"] == TENANT["catalog_id"]

    r = client.get("/v1/config")
    assert r.json()["overrides"]["prefix"] == settings.catalog_name

    # opaque / unknown warehouse hint → default prefix, never 404
    r = client.get("/v1/config", params={"warehouse": "lakehouse"})
    assert r.status_code == 200, r.text
    assert r.json()["overrides"]["prefix"] == settings.catalog_name
