"""Per-catalog isolation (qod integration).

Two DuckLakeCatalog instances share the SAME Postgres database and S3 bucket
but are pinned to distinct metadata schemas + data prefixes via CatalogRef.
Proves the hard tenant boundary: neither catalog can see the other's tables or
rows, and their Parquet lands under disjoint S3 prefixes.
"""
from __future__ import annotations

import boto3
import psycopg
import pytest

from duckicelake.catalog import DuckLakeCatalog
from duckicelake.config import CatalogRef


def _s3(settings):
    s3 = settings.s3
    return boto3.client(
        "s3", endpoint_url=s3.endpoint, region_name=s3.region,
        aws_access_key_id=s3.root_access_key,
        aws_secret_access_key=s3.root_secret_key,
    )


def _keys_under(client, bucket, prefix):
    out = []
    for p in client.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.extend(o["Key"] for o in p.get("Contents", []))
    return out


def _make_catalog(settings, ref: CatalogRef) -> DuckLakeCatalog:
    """Provision the metadata schema (P1c will own this), then attach an
    isolated catalog and seed one row into sales.orders."""
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c:
        c.execute(f'CREATE SCHEMA IF NOT EXISTS "{ref.metadata_schema}"')
    cat = DuckLakeCatalog(settings, ref)
    cat.connect()
    # Idempotent against a dirty start: an interrupted previous run leaves the
    # tenant schema populated (teardown never ran), and 'sales' already exists.
    if not cat.namespace_exists(["sales"]):
        cat.create_namespace(["sales"])
    return cat


@pytest.fixture()
def two_catalogs(settings):
    refs = {
        "acme": CatalogRef("lake", "acme/main/", "dl_acme__main"),
        "globex": CatalogRef("lake", "globex/main/", "dl_globex__main"),
    }
    cats = {}
    s3 = _s3(settings)
    try:
        for name, ref in refs.items():
            cats[name] = _make_catalog(settings, ref)
        yield cats, refs
    finally:
        for cat in cats.values():
            try:
                cat.close()
            except Exception:
                pass
        with psycopg.connect(settings.pg_dsn, autocommit=True) as c:
            for ref in refs.values():
                c.execute(f'DROP SCHEMA IF EXISTS "{ref.metadata_schema}" CASCADE')
        for ref in refs.values():
            for k in _keys_under(s3, settings.s3.bucket, ref.data_prefix):
                s3.delete_object(Bucket=settings.s3.bucket, Key=k)


def _seed(cat: DuckLakeCatalog, order_id: int) -> None:
    with cat.cursor() as c:
        c.execute('CREATE TABLE "lake"."sales"."orders" (id INTEGER, amount INTEGER)')
        c.execute(f'INSERT INTO "lake"."sales"."orders" VALUES ({order_id}, {order_id * 100})')


def _ids(cat: DuckLakeCatalog) -> list[int]:
    with cat.cursor() as c:
        return sorted(r[0] for r in c.execute('SELECT id FROM "lake"."sales"."orders"').fetchall())


def test_metadata_lands_in_distinct_schemas(two_catalogs, settings):
    _cats, refs = two_catalogs
    with psycopg.connect(settings.pg_dsn) as c:
        for ref in refs.values():
            n = c.execute(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema = %s AND table_name LIKE 'ducklake_%%'",
                [ref.metadata_schema],
            ).fetchone()[0]
            assert n > 0, f"no ducklake_* metadata tables in {ref.metadata_schema}"


def test_row_level_isolation_between_catalogs(two_catalogs):
    cats, _ = two_catalogs
    _seed(cats["acme"], 1)
    _seed(cats["globex"], 2)
    # Each catalog sees ONLY its own row — no cross-account bleed.
    assert _ids(cats["acme"]) == [1]
    assert _ids(cats["globex"]) == [2]


def test_data_prefixes_are_disjoint(two_catalogs, settings):
    cats, refs = two_catalogs
    _seed(cats["acme"], 1)
    _seed(cats["globex"], 2)
    s3 = _s3(settings)
    acme_keys = _keys_under(s3, settings.s3.bucket, refs["acme"].data_prefix)
    globex_keys = _keys_under(s3, settings.s3.bucket, refs["globex"].data_prefix)
    assert acme_keys, "acme wrote no objects under its prefix"
    assert globex_keys, "globex wrote no objects under its prefix"
    # No key belongs to both prefixes.
    assert not (set(acme_keys) & set(globex_keys))
    assert all(k.startswith("acme/main/") for k in acme_keys)
    assert all(k.startswith("globex/main/") for k in globex_keys)
