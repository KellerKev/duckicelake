"""Security-audit regression tests: the governance layer must FAIL CLOSED on
the airtight (file-layer) tier — an internal failure denies the read rather
than leaking base bytes. (Catalog-level masking stays cooperative/fail-open;
that's covered by test_fail_open_on_unmaterializable_view in phase3.)"""
from __future__ import annotations

import uuid

from test_governance_phase3 import _make_table, _make_table_only  # noqa: F401
from test_governance_phase3 import _ns as _p3ns  # noqa: F401


def _ns(s: str) -> str:
    return f"gsec_{s}_{uuid.uuid4().hex[:6]}"


def _author_broken_file_layer_policy(client, ns: str, table: str) -> str:
    """A file-layer masking policy whose body is invalid SQL — the masked
    Parquet export COPY will fail at runtime, so no export materializes."""
    tag = f"flbroken_{uuid.uuid4().hex[:6]}"
    client.post("/v1/lake/governance/tags",
                json={"namespace": "pii", "name": tag}).raise_for_status()
    client.post("/v1/lake/governance/object-tags",
                json={"object-kind": "column", "schema": ns, "object": table,
                      "column": "email", "tag-namespace": "pii",
                      "tag-name": tag}).raise_for_status()
    client.post("/v1/lake/governance/masking-policies",
                json={"name": f"mask_{tag}", "signature": "(val VARCHAR)",
                      "body": "no_such_function_xyz(val)",
                      "unmasked-roles": ["pii_reader"],
                      "file-layer-masking": True}).raise_for_status()
    client.post("/v1/lake/governance/policy-attachments",
                json={"policy-kind": "masking", "policy-name": f"mask_{tag}",
                      "target-kind": "tag", "tag-namespace": "pii",
                      "tag-name": tag}).raise_for_status()
    return tag


def test_file_layer_denies_read_when_export_fails(client, settings):
    """L1/L7: a file-layer-masked principal whose masked export can't be
    built must be DENIED (503), never served base metadata + base creds."""
    ns = _ns("flfail")
    _make_table(client, ns, "events")
    _author_broken_file_layer_policy(client, ns, "events")

    # REST LoadTable (anonymous → no roles → masked, file-layer) → 503, not
    # a 200 carrying base metadata + vended base creds.
    r = client.get(f"/v1/lake/namespaces/{ns}/tables/events",
                   headers={"X-Iceberg-Access-Delegation": "vended-credentials"})
    assert r.status_code == 503, r.text

    # DuckLake-direct credentials for the same masked principal → 503, no creds.
    r = client.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials",
                   params={"table": "events", "principal": "bob"})
    assert r.status_code == 503, r.text

    # the denial is audited
    audit = client.get("/v1/lake/governance/audit").json()["entries"]
    denials = [e for e in audit if e.get("decision") == "error_file_layer_denied"
               and e["object"] == f"{ns}.events"]
    assert denials, "expected an error_file_layer_denied audit entry"


def test_catalog_level_still_fails_open(client, settings):
    """Contrast: a NON-file-layer broken mask stays cooperative — LoadTable
    still 200 (advisory signals, no view). Confirms we only flipped the
    airtight tier."""
    ns = _ns("coop")
    tag = f"brk_{uuid.uuid4().hex[:6]}"
    _make_table(client, ns, "events")
    client.post("/v1/lake/governance/tags",
                json={"namespace": "pii", "name": tag}).raise_for_status()
    client.post("/v1/lake/governance/object-tags",
                json={"object-kind": "column", "schema": ns, "object": "events",
                      "column": "email", "tag-namespace": "pii",
                      "tag-name": tag}).raise_for_status()
    client.post("/v1/lake/governance/masking-policies",
                json={"name": f"mask_{tag}", "signature": "(val VARCHAR)",
                      "body": "no_such_function_xyz(val)",
                      "unmasked-roles": ["pii_reader"]}).raise_for_status()  # no file-layer
    client.post("/v1/lake/governance/policy-attachments",
                json={"policy-kind": "masking", "policy-name": f"mask_{tag}",
                      "target-kind": "tag", "tag-namespace": "pii",
                      "tag-name": tag}).raise_for_status()
    r = client.get(f"/v1/lake/namespaces/{ns}/tables/events")
    assert r.status_code == 200, r.text
    assert r.json()["metadata"]["properties"]["duckicelake.masked-columns"] == "email"


# ---- Stage B: RLS grant lockdown -------------------------------------------

import psycopg
from psycopg import sql as _sql

from test_governance_phase3 import direct_catalog  # noqa: F401,E402
from duckicelake import pg_rls  # noqa: E402


def test_files_scheduled_for_deletion_not_granted(client, settings, direct_catalog):
    """L4: the deletion queue exposes base data-file paths of hidden tables;
    the reader group must not be granted it, and a reader can't SELECT it."""
    pg_rls.ensure_rls(direct_catalog, settings)
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute("""
            SELECT count(*) FROM information_schema.role_table_grants
            WHERE grantee=%s AND table_schema='public'
              AND table_name='ducklake_files_scheduled_for_deletion'
        """, (settings.reader_group_role,))
        assert cur.fetchone()[0] == 0, "deletion queue must not be granted to readers"

    from datetime import datetime, timedelta, timezone
    role, pw = pg_rls.provision_principal_role(
        direct_catalog, settings, "leaktest",
        datetime.now(timezone.utc) + timedelta(hours=1))
    with psycopg.connect(settings.pg_dsn_for(role, pw), autocommit=True) as c, c.cursor() as cur:
        try:
            cur.execute("SELECT * FROM public.ducklake_files_scheduled_for_deletion")
            assert False, "reader should not be able to read the deletion queue"
        except psycopg.errors.InsufficientPrivilege:
            pass


def test_rearm_closes_coverage_gap(client, settings, direct_catalog):
    """A1: a ducklake_* table lacking a reader grant (simulating one created
    after startup) is re-granted+policied by rearm_rls_if_needed."""
    pg_rls.ensure_rls(direct_catalog, settings)
    grp = settings.reader_group_role
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
        # simulate a post-startup gap: revoke the grant on a policied table
        cur.execute(_sql.SQL("REVOKE SELECT ON public.ducklake_table FROM {}")
                    .format(_sql.Identifier(grp)))
        cur.execute("""SELECT count(*) FROM information_schema.role_table_grants
                       WHERE grantee=%s AND table_name='ducklake_table'""", (grp,))
        assert cur.fetchone()[0] == 0
    assert pg_rls.rearm_rls_if_needed(direct_catalog, settings) is True
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute("""SELECT count(*) FROM information_schema.role_table_grants
                       WHERE grantee=%s AND table_name='ducklake_table'""", (grp,))
        assert cur.fetchone()[0] == 1, "rearm should restore the grant"
    # no gap now → no-op
    assert pg_rls.rearm_rls_if_needed(direct_catalog, settings) is False


# ---- Stage 1 (merge-stabilization): multi-worker startup DDL race ----------

from concurrent.futures import ThreadPoolExecutor

from duckicelake.catalog import DuckLakeCatalog, pg_advisory_lock
from duckicelake import governance as _gov


def test_concurrent_ensure_rls_no_ddl_race(settings):
    """B2: four sessions running ensure_rls simultaneously used to raise
    `tuple concurrently updated` (unserialized CREATE OR REPLACE FUNCTION /
    GRANT on shared objects — observed live under uvicorn --workers 4). The
    blocking advisory lock must serialize them: no exception, two rounds."""
    cats = [DuckLakeCatalog(settings) for _ in range(4)]
    try:
        for c in cats:
            c.connect()
        _gov.reset_sidecar_cache()   # force the sidecar-DDL path once too
        for _round in range(2):
            with ThreadPoolExecutor(max_workers=4) as ex:
                futures = [ex.submit(pg_rls.ensure_rls, c, settings)
                           for c in cats]
                for f in futures:
                    f.result()       # raises if any worker hit the DDL race
    finally:
        for c in cats:
            try:
                c.close()
            except Exception:
                pass


def test_advisory_lock_released_after_failed_tx(settings, direct_catalog):
    """The lock helper must not leak a held session lock when the guarded DDL
    aborts a non-autocommit transaction (a leaked lock on a pooled connection
    would block every later ensure on that key forever)."""
    with direct_catalog.pg_cursor(autocommit=False) as cur:
        try:
            with pg_advisory_lock(cur, "duckicelake:test:leak"):
                cur.execute("SELECT no_such_function_xyz()")
        except Exception:
            pass
    # a second session can acquire it immediately → it was released
    import hashlib as _h
    key = int.from_bytes(
        _h.sha256(b"duckicelake:test:leak").digest()[:8], "big", signed=True)
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_lock(%s)", (key,))
        assert cur.fetchone()[0] is True, "lock leaked by failed-tx path"
        cur.execute("SELECT pg_advisory_unlock(%s)", (key,))


def test_default_vend_self_heals(monkeypatch):
    """B1: a worker whose startup ensure_rls failed must not 503 vends until
    restart — the vend path retries, arms, and flips _rls_ready."""
    import duckicelake.server as srv

    calls = {"n": 0}

    def flaky_ensure_rls(cat, st):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("simulated lost startup race")

    monkeypatch.setattr(srv, "ensure_rls", flaky_ensure_rls)
    monkeypatch.setattr(srv, "rearm_rls_if_needed", lambda c, s: False)
    monkeypatch.setattr(srv, "_rls_ready", False)

    assert srv._arm_default_rls() is False        # startup-shaped failure
    assert srv._rls_ready is False                # still fail-closed
    assert srv._arm_default_rls() is True         # retry self-heals
    assert srv._rls_ready is True
    assert srv._arm_default_rls() is True         # now takes the rearm path
    assert calls["n"] == 2                        # ensure_rls not re-run once armed
