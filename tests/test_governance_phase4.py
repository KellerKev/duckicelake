"""Phase 4 governance tests — file-layer masking (masked Parquet exports).

Live-stack patterns from test_governance_phase3.py: direct DuckLakeCatalog
beside the session proxy, root/vended DuckDB ATTACH helpers, boto3 byte
proofs.
"""
from __future__ import annotations

import uuid

import duckdb
import pytest

from conftest import requires_sts
from duckicelake.catalog import DuckLakeCatalog
from duckicelake.masked_export import MaskedExportManager
from duckicelake.policies import build_plan, mask_signature

from test_governance_phase3 import (  # noqa: F401  (fixtures/helpers)
    SCHEMA_JSON,
    _make_table,
    _root_duckdb,
    _vended_duckdb,
    direct_catalog,
)


def _ns(suffix: str) -> str:
    return f"gp4_{suffix}_{uuid.uuid4().hex[:6]}"


def _file_plan(ns: str, table: str, *, roles=(), body="left(val,2)||'***'",
               columns=("id", "email"), row_filter=None):
    """A pure plan masking `email` with file_layer_masking=true."""
    row_bodies = {}
    attachments = [{"policy_kind": "masking", "policy_name": "mask_email",
                    "target_kind": "tag", "tag_ns": "pii", "tag_name": "email",
                    "schema_name": None, "object_name": None,
                    "column_name": None, "columns": None}]
    if row_filter:
        attachments.append({"policy_kind": "row_access", "policy_name": "rf",
                            "target_kind": "table", "tag_ns": None,
                            "tag_name": None, "schema_name": ns,
                            "object_name": table, "column_name": None,
                            "columns": list(columns)})
        row_bodies["rf"] = {"signature": "(x VARCHAR)", "body": row_filter,
                            "unmasked_roles": []}
    return build_plan(
        principal="bob", roles=list(roles), schema=ns, table=table,
        columns=list(columns),
        object_tags=[{"object_kind": "column", "schema_name": ns,
                      "object_name": table, "column_name": "email",
                      "tag_ns": "pii", "tag_name": "email", "tag_value": None}],
        attachments=attachments,
        masking_bodies={"mask_email": {"signature": "(val VARCHAR)",
                                       "body": body,
                                       "unmasked_roles": ["pii_reader"],
                                       "file_layer_masking": True}},
        row_bodies=row_bodies,
    )


def _seed(settings, ns: str, table: str = "events") -> None:
    con = _root_duckdb(settings)
    con.execute(
        f'INSERT INTO lake."{ns}"."{table}" VALUES '
        f"(1, 'alice@example.com'), (2, 'bob@personal.io'), (3, 'carol@work.net')"
    )
    con.close()


def _read_export(settings, prefix: str) -> list[tuple]:
    s3 = settings.s3
    con = duckdb.connect(":memory:")
    con.execute("INSTALL httpfs"); con.execute("LOAD httpfs")
    con.execute(
        f"""
        CREATE SECRET r (TYPE S3, KEY_ID '{s3.root_access_key}',
            SECRET '{s3.root_secret_key}', REGION '{s3.region}',
            ENDPOINT '{s3.host}', USE_SSL {str(s3.use_ssl).lower()},
            URL_STYLE '{"path" if s3.path_style else "vhost"}')
        """
    )
    rows = con.execute(
        f"SELECT * FROM read_parquet('s3://{s3.bucket}/{prefix}*.parquet') "
        f"ORDER BY 1"
    ).fetchall()
    con.close()
    return rows


# ---- the exporter core (stage B1) -------------------------------------------

def test_export_masks_and_applies_deletes(client, settings, direct_catalog):
    """The load-bearing correctness proof: the export carries masked bytes
    and does NOT resurrect deleted rows (current-state export applies
    position deletes by construction)."""
    ns = _ns("core")
    _make_table(client, ns, "events")
    _seed(settings, ns)
    con = _root_duckdb(settings)
    con.execute(f'DELETE FROM lake."{ns}".events WHERE id = 2')
    con.close()

    mgr = MaskedExportManager(direct_catalog, settings)
    plan = _file_plan(ns, "events")
    export = mgr.ensure_export_for_plan([ns], "events", plan)
    assert export is not None
    assert export.prefix.startswith(
        f"{settings.s3.data_prefix}__masked__/{ns}/events/{export.sig}/snap-")

    rows = _read_export(settings, export.prefix)
    assert rows == [(1, "al***"), (3, "ca***")]   # masked, deleted row absent


def test_export_idempotent_until_new_snapshot(client, settings, direct_catalog):
    ns = _ns("idem")
    _make_table(client, ns, "events")
    _seed(settings, ns)
    mgr = MaskedExportManager(direct_catalog, settings)
    plan = _file_plan(ns, "events")

    first = mgr.ensure_export_for_plan([ns], "events", plan)
    second = mgr.ensure_export_for_plan([ns], "events", plan)
    assert first.prefix == second.prefix          # same snapshot → same dir

    _seed(settings, ns)                            # new DuckLake snapshot
    third = mgr.ensure_export_for_plan([ns], "events", plan)
    assert third.prefix != first.prefix
    assert third.snapshot > first.snapshot
    assert len(_read_export(settings, third.prefix)) == 6


def test_export_applies_row_filter(client, settings, direct_catalog):
    ns = _ns("rf")
    _make_table(client, ns, "events")
    _seed(settings, ns)
    mgr = MaskedExportManager(direct_catalog, settings)
    plan = _file_plan(ns, "events", row_filter="id <> 3")
    export = mgr.ensure_export_for_plan([ns], "events", plan)
    rows = _read_export(settings, export.prefix)
    assert rows == [(1, "al***"), (2, "bo***")]


def test_export_refused_for_session_tokens(client, settings, direct_catalog):
    ns = _ns("sess")
    _make_table(client, ns, "events")
    _seed(settings, ns)
    mgr = MaskedExportManager(direct_catalog, settings)
    plan = _file_plan(ns, "events",
                      body="CASE WHEN current_user='x' THEN val ELSE '***' END")
    assert mgr.ensure_export_for_plan([ns], "events", plan) is None


def test_refresh_known_sigs_and_drift(client, settings, direct_catalog):
    """The listener hook: a known sig re-exports at the new snapshot; a
    drifted recipe (policy body change → sig mismatch) is dropped."""
    ns = _ns("refr")
    _make_table(client, ns, "events")
    _seed(settings, ns)
    mgr = MaskedExportManager(direct_catalog, settings)
    plan = _file_plan(ns, "events")
    first = mgr.ensure_export_for_plan([ns], "events", plan)

    _seed(settings, ns)
    mgr.refresh_known_sigs([ns], "events")
    refreshed = mgr.current_export([ns], "events", first.sig)
    assert refreshed.snapshot > first.snapshot

    # simulate policy drift: rewrite the stored recipe's mask expr so the
    # recomputed signature mismatches → refresh drops the export
    import psycopg, json as _json
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute(
            "UPDATE public.duckicelake_masked_export "
            "SET masks_json = %s WHERE schema_name=%s AND table_name=%s AND sig=%s",
            (_json.dumps([{"column": "email", "mask_expr": "'zzz'",
                           "policy_name": "mask_email"}]), ns, "events", first.sig),
        )
    mgr.refresh_known_sigs([ns], "events")
    assert mgr.current_export([ns], "events", first.sig) is None
    assert mgr.list_export_files(
        settings.s3.masked_sig_prefix(ns, "events", first.sig)) == []


def test_gc_and_purge(client, settings, direct_catalog):
    ns = _ns("gc")
    _make_table(client, ns, "events")
    _seed(settings, ns)
    mgr = MaskedExportManager(direct_catalog, settings)
    export = mgr.ensure_export_for_plan([ns], "events", _file_plan(ns, "events"))
    assert mgr.list_export_files(export.prefix)

    assert mgr.gc_table([ns], "events", keep=set()) == 1
    assert mgr.current_export([ns], "events", export.sig) is None
    assert mgr.list_export_files(export.prefix) == []


# ---- DuckLake-direct hard enforcement (stage B2) -----------------------------

import boto3
import botocore.exceptions

from duckicelake import s3util
from duckicelake.config import load_settings


def _author_file_layer_policy(client, ns: str, table: str) -> None:
    """pii.flemail tag + mask_email_fl policy with file-layer-masking=true,
    bypassed by pii_reader. Distinct names from the phase-3 tests so the
    flag never leaks into their (catalog-level) expectations."""
    client.post("/v1/lake/governance/tags",
                json={"namespace": "pii", "name": "flemail"}).raise_for_status()
    client.post("/v1/lake/governance/object-tags",
                json={"object-kind": "column", "schema": ns, "object": table,
                      "column": "email", "tag-namespace": "pii",
                      "tag-name": "flemail"}).raise_for_status()
    client.post("/v1/lake/governance/masking-policies",
                json={"name": "mask_email_fl", "signature": "(val VARCHAR)",
                      "body": "left(val,2)||'***'",
                      "unmasked-roles": ["pii_reader"],
                      "file-layer-masking": True}).raise_for_status()
    client.post("/v1/lake/governance/policy-attachments",
                json={"policy-kind": "masking", "policy-name": "mask_email_fl",
                      "target-kind": "tag", "tag-namespace": "pii",
                      "tag-name": "flemail"}).raise_for_status()
    client.post("/v1/lake/governance/roles",
                json={"name": "pii_reader"}).raise_for_status()


def _vend(client, ns: str, sub: str, table: str | None = "events") -> dict:
    params = {"principal": sub}
    if table:
        params["table"] = table
    r = client.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials",
                   params=params)
    assert r.status_code == 200, r.text
    return r.json()


def _s3_client_from(creds_s3: dict):
    return boto3.client(
        "s3", endpoint_url=creds_s3["endpoint"], region_name=creds_s3["region"],
        aws_access_key_id=creds_s3["access-key-id"],
        aws_secret_access_key=creds_s3["secret-access-key"],
        aws_session_token=creds_s3["session-token"],
        config=s3util.boto_config(load_settings().s3),
    )


def _base_keys(settings, ns: str, table: str = "events") -> list[str]:
    s3 = settings.s3
    root = s3util.s3_client(s3)
    keys = []
    for p in root.get_paginator("list_objects_v2").paginate(
            Bucket=s3.bucket, Prefix=s3.table_prefix(ns, table)):
        keys += [o["Key"] for o in p.get("Contents", [])
                 if o["Key"].endswith(".parquet")]
    return keys


def test_file_layer_end_to_end(client, settings):
    """THE Phase-4 proof: bob's vended credentials physically cannot read
    base bytes (403) but read masked bytes; unqualified and by-name queries
    return masked rows from the pre-masked Parquet; the base table is empty
    for him even by name (RLS interlock). Alice (bypass) is untouched."""
    ns = _ns("e2e")
    _make_table(client, ns, "events")
    _author_file_layer_policy(client, ns, "events")
    client.post("/v1/lake/governance/role-grants",
                json={"role": "pii_reader", "principal": "alice"}).raise_for_status()
    _seed(settings, ns)

    bob = _vend(client, ns, "bob")
    assert bob["file_layer"] is True
    assert bob["masked_view"] and bob["transparent"] is True
    sig = bob["mask_signature"]

    # ---- byte-level proof ----
    s3c = _s3_client_from(bob["s3"])
    base = _base_keys(settings, ns)
    assert base, "expected base parquet files"
    with pytest.raises(botocore.exceptions.ClientError) as exc:
        s3c.get_object(Bucket=settings.s3.bucket, Key=base[0])
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 403
    masked_prefix = settings.s3.masked_sig_prefix(ns, "events", sig)
    masked_keys = [k for k, _ in
                   MaskedExportManager(
                       DuckLakeCatalog(settings), settings
                   )._list_keys(masked_prefix) if k.endswith(".parquet")]
    assert masked_keys
    s3c.get_object(Bucket=settings.s3.bucket, Key=masked_keys[0])  # 200

    # ---- query-level proof ----
    con = _vended_duckdb(settings, bob)
    emails = {r[0] for r in con.execute("SELECT email FROM events").fetchall()}
    assert emails == {"al***", "bo***", "ca***"}
    sch, view = bob["masked_view"].split(".", 1)
    emails = {r[0] for r in con.execute(
        f'SELECT email FROM lake."{sch}"."{view}"').fetchall()}
    assert emails == {"al***", "bo***", "ca***"}
    # base table by name: RLS interlock hides its file rows → empty
    assert con.execute(
        f'SELECT count(*) FROM lake."{ns}".events').fetchone()[0] == 0
    con.close()

    # ---- alice (bypass): untouched ----
    alice = _vend(client, ns, "alice")
    assert alice["file_layer"] is False and alice["masked_view"] is None
    con = _vended_duckdb(settings, alice)
    raw = {r[0] for r in con.execute(
        f'SELECT email FROM lake."{ns}".events').fetchall()}
    assert raw == {"alice@example.com", "bob@personal.io", "carol@work.net"}
    con.close()

    # ---- audited ----
    audit = client.get("/v1/lake/governance/audit").json()["entries"]
    assert any(e["operation"] == "ducklake_credentials"
               and e["principal"] == "bob"
               and e["decision"] == "masked_file_layer" for e in audit)
    assert any(e["operation"] == "masked_export" for e in audit)


def test_namespace_vend_denies_file_layer_base(client, settings):
    """Namespace-level vending carves the file-layer table's base prefix
    out of the namespace allow (IAM Deny) for masked principals; an
    ungoverned sibling table stays readable."""
    ns = _ns("nsdeny")
    _make_table(client, ns, "events")
    client.post(f"/v1/lake/namespaces/{ns}/tables",
                json={"name": "open_t", "schema": SCHEMA_JSON}).raise_for_status()
    _author_file_layer_policy(client, ns, "events")
    _seed(settings, ns)
    _seed(settings, ns, "open_t")
    # NB: no table-scoped vend first — the deny must hold even when the
    # file-layer table was never exported (deny is derived from the policy,
    # not from an existing export row). Regression for the namespace-vend gap.

    nsbob = _vend(client, ns, "bob", table=None)
    s3c = _s3_client_from(nsbob["s3"])
    with pytest.raises(botocore.exceptions.ClientError) as exc:
        s3c.get_object(Bucket=settings.s3.bucket,
                       Key=_base_keys(settings, ns)[0])
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 403
    open_keys = _base_keys(settings, ns, "open_t")
    s3c.get_object(Bucket=settings.s3.bucket, Key=open_keys[0])  # 200


# ---- eager refresh via the notify listener (stage B3) ------------------------

import time


def _wait_for(fn, timeout=15.0, interval=0.3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(interval)
    return None


def test_listener_refreshes_export_for_existing_creds(client, settings):
    """A DuckLake-direct write AFTER vending: the elected listener
    re-exports the known sig at the new snapshot and repoints the view —
    bob's already-vended session and creds (sig-prefix grant covers future
    snap dirs) see the new row, masked, without re-vending."""
    ns = _ns("listen")
    _make_table(client, ns, "events")
    _author_file_layer_policy(client, ns, "events")
    _seed(settings, ns)
    bob = _vend(client, ns, "bob")
    assert bob["file_layer"] is True

    con = _vended_duckdb(settings, bob)
    assert con.execute("SELECT count(*) FROM events").fetchone()[0] == 3

    # post-vend write through the root path → NOTIFY → listener refresh
    root = _root_duckdb(settings)
    root.execute(f'INSERT INTO lake."{ns}".events VALUES (4, \'dave@new.org\')')
    root.close()

    def _sees_new_row():
        try:
            rows = dict(con.execute(
                "SELECT id, email FROM events").fetchall())
            return rows if 4 in rows else None
        except Exception:
            return None

    rows = _wait_for(_sees_new_row)
    assert rows, "listener did not refresh the masked export in time"
    assert rows[4] == "da***"            # new row arrives masked
    con.close()


# ---- lifecycle hooks (stage B4) ----------------------------------------------

def test_schema_change_drops_masked_exports(client, settings, direct_catalog):
    ns = _ns("alter")
    _make_table(client, ns, "events")
    _author_file_layer_policy(client, ns, "events")
    _seed(settings, ns)
    bob = _vend(client, ns, "bob")
    assert bob["file_layer"] is True
    sig = bob["mask_signature"]
    mgr = MaskedExportManager(direct_catalog, settings)
    assert mgr.current_export([ns], "events", sig) is not None

    wider = {
        "type": "struct", "schema-id": 1,
        "fields": SCHEMA_JSON["fields"] + [
            {"id": 3, "name": "country", "required": False, "type": "string"},
        ],
    }
    client.post(
        f"/v1/lake/namespaces/{ns}/tables/events",
        json={"requirements": [],
              "updates": [{"action": "add-schema", "schema": wider},
                          {"action": "set-current-schema", "schema-id": -1}]},
    ).raise_for_status()

    assert mgr.current_export([ns], "events", sig) is None
    # next vend recreates at the new (column-folded) signature
    bob2 = _vend(client, ns, "bob")
    assert bob2["file_layer"] is True and bob2["mask_signature"] != sig


def test_drop_table_purges_masked_prefix(client, settings, direct_catalog):
    ns = _ns("drop")
    _make_table(client, ns, "events")
    _author_file_layer_policy(client, ns, "events")
    _seed(settings, ns)
    _vend(client, ns, "bob")
    mgr = MaskedExportManager(direct_catalog, settings)
    masked_root = settings.s3.masked_table_prefix(ns, "events")
    assert mgr._list_keys(masked_root)

    r = client.delete(f"/v1/lake/namespaces/{ns}/tables/events",
                      params={"purgeRequested": "true"})
    assert r.status_code == 204
    assert mgr._list_keys(masked_root) == []


# ---- REST shadow Iceberg metadata (stage B5) ---------------------------------

@requires_sts
def test_rest_shadow_metadata_end_to_end(client, settings):
    """The REST half of Phase 4: LoadTable for a masked principal returns
    SHADOW metadata whose manifests point exclusively at masked Parquet,
    with read-only masked-prefix STS — and the DuckDB iceberg extension
    (no views, no scan planning) reads masked bytes through it. The test
    stack runs auth-off, so the REST caller is `anonymous` (no roles →
    masked)."""
    ns = _ns("rest")
    _make_table(client, ns, "events")
    _author_file_layer_policy(client, ns, "events")
    _seed(settings, ns)

    r = client.get(f"/v1/lake/namespaces/{ns}/tables/events",
                   headers={"X-Iceberg-Access-Delegation": "vended-credentials"})
    assert r.status_code == 200, r.text
    body = r.json()
    md = body["metadata"]
    masked_root = f"s3://{settings.s3.bucket}/" \
                  f"{settings.s3.masked_table_prefix(ns, 'events')}"

    # metadata + manifest chain live under the masked prefix
    assert body["metadata-location"].startswith(masked_root)
    assert md["properties"]["duckicelake.masked"] == "true"
    snap = md["snapshots"][0]
    assert snap["manifest-list"].startswith(masked_root)
    assert md["properties"]["duckicelake.masked-columns"] == "email"

    # vended creds: masked bytes 200, base bytes 403, and read-only
    cfg = body["config"]
    assert cfg.get("s3.session-token"), "expected vended STS creds"
    s3c = _s3_client_from({
        "endpoint": settings.s3.endpoint, "region": settings.s3.region,
        "access-key-id": cfg["s3.access-key-id"],
        "secret-access-key": cfg["s3.secret-access-key"],
        "session-token": cfg["s3.session-token"],
    })
    with pytest.raises(botocore.exceptions.ClientError) as exc:
        s3c.get_object(Bucket=settings.s3.bucket,
                       Key=_base_keys(settings, ns)[0])
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 403

    # the load-bearing reader proof: DuckDB iceberg extension over the
    # shadow metadata with the vended creds sees masked bytes
    con = duckdb.connect(":memory:")
    for e in ("iceberg", "httpfs"):
        con.execute(f"INSTALL {e}"); con.execute(f"LOAD {e}")
    con.execute(
        f"""
        CREATE SECRET vend (TYPE S3, KEY_ID '{cfg["s3.access-key-id"]}',
            SECRET '{cfg["s3.secret-access-key"]}',
            SESSION_TOKEN '{cfg["s3.session-token"]}',
            REGION '{settings.s3.region}', ENDPOINT '{settings.s3.host}',
            USE_SSL {str(settings.s3.use_ssl).lower()}, URL_STYLE 'path')
        """
    )
    emails = {r0[0] for r0 in con.execute(
        f"SELECT email FROM iceberg_scan('{body['metadata-location']}')"
    ).fetchall()}
    con.close()
    assert emails == {"al***", "bo***", "ca***"}


def test_rest_shadow_only_for_masked_principals(client, settings, direct_catalog):
    """A bypass principal's REST LoadTable keeps BASE metadata. The test
    stack is auth-off (anonymous), so grant anonymous the bypass role."""
    ns = _ns("restbp")
    _make_table(client, ns, "events")
    _author_file_layer_policy(client, ns, "events")
    client.post("/v1/lake/governance/role-grants",
                json={"role": "pii_reader",
                      "principal": "anonymous"}).raise_for_status()
    _seed(settings, ns)
    try:
        r = client.get(f"/v1/lake/namespaces/{ns}/tables/events")
        assert r.status_code == 200, r.text
        body = r.json()
        assert "__masked__" not in (body.get("metadata-location") or "")
        assert "duckicelake.masked" not in body["metadata"]["properties"]
    finally:
        # don't leak anonymous's bypass into other tests
        import psycopg
        with psycopg.connect(settings.pg_dsn, autocommit=True) as c, c.cursor() as cur:
            cur.execute("DELETE FROM public.duckicelake_role_grant "
                        "WHERE role_name='pii_reader' AND principal_sub='anonymous'")


# ---- code-review regression fixes -------------------------------------------

def test_reserved_property_keys_rejected_on_commit(client, settings):
    """A write token must not flip governance state via a normal commit:
    set/remove-properties on a duckicelake.* key is 403 (the file-layer RLS
    interlock lives in such a property)."""
    ns = _ns("rprop")
    _make_table(client, ns, "events")
    for updates in (
        {"action": "set-properties",
         "updates": {"duckicelake.file-layer-masking": "false"}},
        {"action": "remove-properties",
         "removals": ["duckicelake.file-layer-bypass-roles"]},
    ):
        r = client.post(f"/v1/lake/namespaces/{ns}/tables/events",
                        json={"requirements": [], "updates": [updates]})
        assert r.status_code == 403, r.text
    # an ordinary user property still works
    r = client.post(f"/v1/lake/namespaces/{ns}/tables/events",
                    json={"requirements": [],
                          "updates": [{"action": "set-properties",
                                       "updates": {"owner": "team-x"}}]})
    assert r.status_code == 200, r.text


# ---- A2: file-layer time-travel is denied (fail closed) --------------------

def test_file_layer_time_travel_denied(client, settings):
    """A2: a file-layer masked principal asking for a historical snapshot
    must be DENIED (501) — the masked export is current-state only, so the
    alternative is silently serving the current snapshot under the old id."""
    ns = _ns("tt")
    _make_table(client, ns, "events")
    _seed(settings, ns)          # snapshot A
    _seed(settings, ns)          # snapshot B (current)

    # Read the real snapshot history BEFORE authoring the mask (anonymous +
    # no policy → base metadata with the full snapshot list).
    md = client.get(f"/v1/lake/namespaces/{ns}/tables/events").json()["metadata"]
    current = md["current-snapshot-id"]
    historical = [s["snapshot-id"] for s in md["snapshots"]
                  if s["snapshot-id"] != current]
    assert historical, "need ≥2 snapshots for a time-travel read"

    _author_file_layer_policy(client, ns, "events")

    # masked (anonymous) + historical snapshot → 501, never the current export
    r = client.get(f"/v1/lake/namespaces/{ns}/tables/events",
                   params={"snapshot_id": historical[0]},
                   headers={"X-Iceberg-Access-Delegation": "vended-credentials"})
    assert r.status_code == 501, r.text

    # the deny is audited distinctly from the generic file-layer denial
    audit = client.get("/v1/lake/governance/audit").json()["entries"]
    assert any(e.get("decision") == "error_file_layer_timetravel_denied"
               and e["object"] == f"{ns}.events" for e in audit)

    # the CURRENT snapshot (not historical) is still served masked, not denied
    r = client.get(f"/v1/lake/namespaces/{ns}/tables/events",
                   params={"snapshot_id": current})
    assert r.status_code == 200, r.text


# ---- A3: retention keeps a recently-served dir past the count cap ----------

def test_retention_grace_keeps_recent_dir(settings, direct_catalog):
    """A3: a snap dir that exceeds the count cap but is younger than the
    grace window survives, so a slow reader's in-flight glob isn't deleted
    out from under it. With grace=0 it's swept (count cap alone)."""
    s3 = settings.s3
    root = s3util.s3_client(s3)
    sig = "deadbeef0000"
    schema, table = "gp4ret", f"t_{uuid.uuid4().hex[:6]}"
    sig_prefix = s3.masked_sig_prefix(schema, table, sig)
    old_dir = f"{sig_prefix}snap-1-aaaa/"
    live_dir = f"{sig_prefix}snap-2-bbbb/"
    for d in (old_dir, live_dir):
        root.put_object(Bucket=s3.bucket, Key=f"{d}part-0.parquet", Body=b"x")

    mgr = MaskedExportManager(direct_catalog, settings)
    mgr.retain_snap_dirs = 1          # count cap would drop snap-1...

    def _exists(prefix: str) -> bool:
        r = root.list_objects_v2(Bucket=s3.bucket, Prefix=prefix)
        return r.get("KeyCount", 0) > 0

    mgr.retain_grace_seconds = 3900   # ...but it's brand new → grace keeps it
    mgr._retain(schema, table, sig, keep_prefix=live_dir)
    assert _exists(old_dir), "recent dir must survive the count cap"
    assert _exists(live_dir)

    mgr.retain_grace_seconds = 0      # no grace → count cap sweeps snap-1
    mgr._retain(schema, table, sig, keep_prefix=live_dir)
    assert not _exists(old_dir), "with no grace the over-cap dir is swept"
    assert _exists(live_dir)

    root.delete_object(Bucket=s3.bucket, Key=f"{live_dir}part-0.parquet")


def test_reserved_table_names_rejected(client):
    ns = _ns("rname")
    _make_table(client, ns, "events")   # creates ns + a real table
    # create a __mask_*-named table → 400
    r = client.post(f"/v1/lake/namespaces/{ns}/tables",
                    json={"name": "__mask_events__deadbeef", "schema": SCHEMA_JSON})
    assert r.status_code == 400, r.text
    # rename a real table INTO a reserved name → 400
    r = client.post("/v1/lake/tables/rename",
                    json={"source": {"namespace": [ns], "name": "events"},
                          "destination": {"namespace": [ns],
                                          "name": "__mask_x__beef"}})
    assert r.status_code == 400, r.text
