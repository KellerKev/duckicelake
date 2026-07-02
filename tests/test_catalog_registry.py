"""CatalogRegistry: provisioning, resolution, caching, and isolation."""
from __future__ import annotations

import boto3
import psycopg
import pytest

from duckicelake.registry import CatalogRegistry, UnknownCatalog


CATALOGS = {
    "acme_reg": ("dl_acme__reg", "acme_reg/main/"),
    "globex_reg": ("dl_globex__reg", "globex_reg/main/"),
}


def _s3(settings):
    s3 = settings.s3
    return boto3.client(
        "s3", endpoint_url=s3.endpoint, region_name=s3.region,
        aws_access_key_id=s3.root_access_key,
        aws_secret_access_key=s3.root_secret_key,
    )


@pytest.fixture()
def registry(settings):
    reg = CatalogRegistry(settings)
    try:
        yield reg
    finally:
        reg.close_all()
        s3 = _s3(settings)
        with psycopg.connect(settings.pg_dsn, autocommit=True) as c:
            for cid, (schema, prefix) in CATALOGS.items():
                c.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
                c.execute("DELETE FROM public.duckicelake_catalog WHERE catalog_id = %s", [cid])
                for p in s3.get_paginator("list_objects_v2").paginate(
                    Bucket=settings.s3.bucket, Prefix=prefix
                ):
                    for o in p.get("Contents", []):
                        s3.delete_object(Bucket=settings.s3.bucket, Key=o["Key"])


def _seed(ctx, order_id):
    cat = ctx.catalog_id  # ATTACH alias == catalog id
    ctx.catalog.create_namespace(["sales"])
    with ctx.catalog.cursor() as c:
        c.execute(f'CREATE TABLE "{cat}"."sales"."orders" (id INTEGER)')
        c.execute(f'INSERT INTO "{cat}"."sales"."orders" VALUES ({order_id})')


def _ids(ctx):
    cat = ctx.catalog_id
    with ctx.catalog.cursor() as c:
        return sorted(r[0] for r in c.execute(f'SELECT id FROM "{cat}"."sales"."orders"').fetchall())


def test_provision_resolve_cache_and_isolation(registry, settings):
    a = registry.provision("acme_reg", *CATALOGS["acme_reg"])
    g = registry.provision("globex_reg", *CATALOGS["globex_reg"])
    # provisioning wrote a registry row resolvable independently
    assert registry.resolve_ref("acme_reg").metadata_schema == "dl_acme__reg"
    # get() returns the SAME cached, connected context
    assert registry.get("acme_reg") is a

    _seed(a, 1)
    _seed(g, 2)
    assert _ids(a) == [1]
    assert _ids(g) == [2]


def test_unknown_catalog_raises(registry):
    with pytest.raises(UnknownCatalog):
        registry.get("no_such_catalog")


def test_default_resolves_from_settings(registry, settings):
    ctx = registry.default()
    assert ctx.catalog_id == settings.catalog_name
    assert ctx.ref.metadata_schema is None  # default uses the extension's schema
