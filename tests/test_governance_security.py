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
