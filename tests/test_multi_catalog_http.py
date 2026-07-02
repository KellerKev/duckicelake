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


@pytest.fixture()
def provisioned(client, settings):
    default_prefix = settings.catalog_name
    # Provision the tenant catalog (idempotent).
    r = client.post("/v1/catalogs", json=TENANT)
    assert r.status_code in (201, 409), r.text
    # Clean any leftovers from a prior run.
    for prefix, ns in ((default_prefix, NS_DEFAULT), (TENANT["catalog_id"], NS_TENANT)):
        client.delete(f"/v1/{prefix}/namespaces/{ns}")
    yield default_prefix
    for prefix, ns in ((default_prefix, NS_DEFAULT), (TENANT["catalog_id"], NS_TENANT)):
        client.delete(f"/v1/{prefix}/namespaces/{ns}")
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
