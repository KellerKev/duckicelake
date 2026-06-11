"""Phase 4 governance tests — file-layer masking (masked Parquet exports).

Live-stack patterns from test_governance_phase3.py: direct DuckLakeCatalog
beside the session proxy, root/vended DuckDB ATTACH helpers, boto3 byte
proofs.
"""
from __future__ import annotations

import uuid

import duckdb
import pytest

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
    assert export.prefix.startswith(f"data/__masked__/{ns}/events/{export.sig}/snap-")

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
