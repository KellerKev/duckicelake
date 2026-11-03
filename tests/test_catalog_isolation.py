"""Governance is per catalog. Two catalogs share one Postgres database and the
same namespace/table names, but each keeps its own tags, policies,
attachments, roles, grants, table properties and masked-export pointers — so
one tenant can't overwrite, drop, rename or inherit another's governance."""
from __future__ import annotations

import uuid

import psycopg
import pytest

from duckicelake.auth import AuthConfig, issue_token
from duckicelake.governance import GovernanceStore
from duckicelake.policies import PolicyEngine

from test_multi_catalog import two_catalogs  # noqa: F401  (fixture)


def _orders(cat):
    with cat.cursor() as c:
        c.execute(f'CREATE TABLE IF NOT EXISTS "{cat.ref.catalog_name}"."sales"."orders" '
                  '(id INTEGER, email VARCHAR, amount INTEGER)')


def _mask(store, body, roles=None, column="email"):
    store.create_masking_policy("admin", "pii", "(val VARCHAR)", body, roles)
    store.attach_policy("admin", policy_kind="masking", policy_name="pii",
                        target_kind="column", schema_name="sales",
                        object_name="orders", column_name=column)


def _masks(store, roles=()):
    plan = PolicyEngine(store).plan_for(principal="carol", roles=list(roles),
                                        schema="sales", table="orders")
    return {m.column: m.mask_expr for m in plan.masks}


@pytest.fixture()
def stores(two_catalogs):  # noqa: F811
    cats, refs = two_catalogs
    for cat in cats.values():
        _orders(cat)
    return {k: GovernanceStore(c) for k, c in cats.items()}, cats, refs


def test_sidecars_live_in_each_catalogs_schema(stores, settings):
    st, cats, refs = stores
    _mask(st["acme"], "'***'")
    with psycopg.connect(settings.pg_dsn) as c:
        def n(schema, table):   # sidecars are created lazily: absent == 0
            if c.execute("SELECT to_regclass(%s)",
                         (f'"{schema}".duckicelake_{table}',)).fetchone()[0] is None:
                return 0
            return c.execute(
                f'SELECT count(*) FROM "{schema}".duckicelake_{table}').fetchone()[0]
        assert n(refs["acme"].metadata_schema, "masking_policy") == 1
        assert n(refs["acme"].metadata_schema, "policy_attachment") == 1
        assert n(refs["globex"].metadata_schema, "masking_policy") == 0
        assert c.execute(
            "SELECT to_regclass('public.duckicelake_masking_policy') IS NULL "
            "OR (SELECT count(*) = 0 FROM public.duckicelake_masking_policy)").fetchone()[0]


def test_same_policy_name_in_two_catalogs_is_independent(stores):
    st, _, _ = stores
    _mask(st["acme"], "'***'")
    _mask(st["globex"], "'redacted'")      # same name: no conflict, no overwrite
    assert "'***'" in _masks(st["acme"])["email"]
    assert "'redacted'" in _masks(st["globex"])["email"]


def test_drop_and_rename_touch_only_their_own_catalog(stores):
    st, _, _ = stores
    _mask(st["acme"], "'***'")
    _mask(st["globex"], "'***'")
    st["acme"].purge_table_governance("admin", schema="sales", table="orders")
    assert st["acme"].tables_with_policies("sales") == []
    assert st["globex"].tables_with_policies("sales") == ["orders"]
    assert "email" in _masks(st["globex"])
    st["globex"].rename_table_governance("admin", src_schema="sales", src_table="orders",
                                         dst_schema="sales", dst_table="orders_v2")
    assert st["globex"].tables_with_policies("sales") == ["orders_v2"]
    assert st["acme"].tables_with_policies("sales") == []


def test_role_grants_are_per_catalog(stores):
    st, _, _ = stores
    st["acme"].create_role("admin", "pii_reader")
    st["acme"].grant_role("admin", "pii_reader", "alice")
    assert st["acme"].roles_for_principal("alice") == ["pii_reader"]
    assert st["globex"].roles_for_principal("alice") == []
    # the bypass role exempts alice in acme only
    _mask(st["acme"], "'***'", roles=["pii_reader"])
    _mask(st["globex"], "'***'", roles=["pii_reader"])
    assert _masks(st["acme"], st["acme"].roles_for_principal("alice")) == {}
    assert "email" in _masks(st["globex"], st["globex"].roles_for_principal("alice"))


def test_table_properties_are_per_catalog(stores):
    _, cats, _ = stores
    cats["acme"].upsert_table_properties(["sales"], "orders", set_map={"k": "acme"})
    assert cats["acme"].get_table_properties(["sales"], "orders").get("k") == "acme"
    assert "k" not in cats["globex"].get_table_properties(["sales"], "orders")


def test_governance_api_is_tenant_gated(monkeypatch, settings):
    """Authoring goes to the catalog in the URL, and only for its account."""
    import duckicelake.server as srv
    from fastapi.testclient import TestClient

    cid = f"gov_{uuid.uuid4().hex[:6]}"
    srv.registry.provision(cid, f"dl_{cid}__main", f"duckicelake-test/{cid}/main/", "acct-a")
    cfg = AuthConfig(jwt_secret=b"test-secret-32-bytes-xxxxxxxxxxx",
                     clients={"c": {"secret": "s", "scope": "*:rw", "roles": "", "account": ""}},
                     ttl_seconds=300, issuer="duckicelake")
    monkeypatch.setattr(srv, "auth_cfg", cfg)
    body = {"name": "p1", "signature_sql": "(v VARCHAR)", "body_sql": "'x'"}

    def post(account):
        tok = issue_token(cfg, "u", scope="*:rw", roles="", account=account)["access_token"]
        return client.post(f"/v1/{cid}/governance/masking-policies", json=body,
                           headers={"Authorization": f"Bearer {tok}"})
    try:
        with TestClient(srv.app) as client:
            assert post("acct-b").status_code == 404
            assert post("acct-a").status_code == 200
        def names(ctx):
            with ctx.catalog.pg_cursor() as cur:
                cur.execute(f"SELECT name FROM {ctx.catalog.sidecar_sql}.duckicelake_masking_policy")
                return [r[0] for r in cur.fetchall()]
        assert names(srv.registry.get(cid)) == ["p1"]
        assert "p1" not in names(srv._default_ctx)
    finally:
        with psycopg.connect(settings.pg_dsn, autocommit=True) as c:
            c.execute(f'DROP SCHEMA IF EXISTS "dl_{cid}__main" CASCADE')
        from duckicelake.governance import reset_sidecar_cache
        reset_sidecar_cache()


def test_upgrade_migration_copies_shared_rows_to_matching_catalogs(settings):
    """Pre-isolation rows in public are copied to each catalog that has the
    object (so its effective policy is unchanged), never deleted from public,
    and re-running is a no-op."""
    import duckicelake.server as srv
    from duckicelake.governance import reset_sidecar_cache
    from duckicelake.migrate_sidecars import migrate

    cid = f"mig_{uuid.uuid4().hex[:6]}"
    meta = f"dl_{cid}__main"
    srv.registry.provision(cid, meta, f"duckicelake-test/{cid}/main/", "acct-m")
    ctx = srv.registry.get(cid)
    if not ctx.catalog.namespace_exists(["sales"]):
        ctx.catalog.create_namespace(["sales"])
    _orders(ctx.catalog)
    shared = srv._default_ctx.store        # writes the shared (public) tables
    shared.create_role("admin", "mig_reader")
    shared.grant_role("admin", "mig_reader", "alice")
    shared.create_masking_policy("admin", "mig_pii", "(val VARCHAR)", "'***'", ["mig_reader"])
    for table in ("orders", "not_here"):
        shared.attach_policy("admin", policy_kind="masking", policy_name="mig_pii",
                             target_kind="column", schema_name="sales",
                             object_name=table, column_name="email")
    try:
        got = {(c, n): k for c, n, k in migrate(apply=True) if c == cid}
        assert got[(cid, "masking_policy")] >= 1 and got[(cid, "role_grant")] >= 1
        assert got[(cid, "policy_attachment")] == 1          # orders only
        with psycopg.connect(settings.pg_dsn) as c:
            rows = c.execute(f'SELECT object_name FROM "{meta}".duckicelake_policy_attachment '
                             "WHERE policy_name = 'mig_pii'").fetchall()
            assert rows == [("orders",)]
            assert c.execute("SELECT count(*) FROM public.duckicelake_policy_attachment "
                             "WHERE policy_name = 'mig_pii'").fetchone()[0] == 2
        assert ctx.store.roles_for_principal("alice") == ["mig_reader"]
        # idempotent
        with psycopg.connect(settings.pg_dsn) as c:
            before = c.execute(f'SELECT count(*) FROM "{meta}".duckicelake_policy_attachment'
                               ).fetchone()[0]
        migrate(apply=True)
        with psycopg.connect(settings.pg_dsn) as c:
            assert c.execute(f'SELECT count(*) FROM "{meta}".duckicelake_policy_attachment'
                             ).fetchone()[0] == before
    finally:
        with psycopg.connect(settings.pg_dsn, autocommit=True) as c:
            c.execute(f'DROP SCHEMA IF EXISTS "{meta}" CASCADE')
            c.execute("DELETE FROM public.duckicelake_policy_attachment WHERE policy_name = 'mig_pii'")
            c.execute("DELETE FROM public.duckicelake_masking_policy WHERE name = 'mig_pii'")
            c.execute("DELETE FROM public.duckicelake_role_grant WHERE role_name = 'mig_reader'")
            c.execute("DELETE FROM public.duckicelake_role WHERE role_name = 'mig_reader'")
        reset_sidecar_cache()
