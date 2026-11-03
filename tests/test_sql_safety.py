"""Client-supplied text never runs as SQL on the owner connection, client
paths never escape the table location, and the agent executor is locked down.

Unit checks for the sqlsafe helpers, then each attack shape against the live
test proxy: identifier / default / view-body / policy-body injection, commit
paths outside the table prefix, an agent's namespace-wide vend, and agent SQL
reaching local files or a second statement.
"""
from __future__ import annotations

import io
import uuid

import boto3
import duckdb
import pytest
from fastavro import parse_schema, writer

from duckicelake import s3util
from duckicelake.config import load_settings
from duckicelake.iceberg import schema_to_columns_ddl
from duckicelake.mcp_server import GovernedExecutor, MCPConfig
from duckicelake.policies import _qualify_expr
from duckicelake.read_manifest import check_under_prefix
from duckicelake.registry import _check_catalog_names
from duckicelake.sqlsafe import (check_identifier, check_no_denied_functions,
                                 check_single_select, literal, qi)

from conftest import PROXY_URL
from test_governance_phase3 import SCHEMA_JSON, _make_table, _root_duckdb

EVIL = 'x" INT); COPY (SELECT 1) TO \'/tmp/pwned.csv\'; --'


def _ns(suffix: str) -> str:
    return f"sqls_{suffix}_{uuid.uuid4().hex[:6]}"


# ---- unit -------------------------------------------------------------------

def test_quoting_helpers():
    assert qi('a"b') == '"a""b"'
    assert literal("it's") == "'it''s'"
    assert literal(True) == "TRUE" and literal(3) == "3" and literal(1.5) == "1.5"
    for bad in (float("nan"), {"a": 1}, [1]):
        with pytest.raises(ValueError):
            literal(bad)


def test_check_identifier():
    assert check_identifier('odd "name"; --', "column") == 'odd "name"; --'
    for bad in ("", "a\x00b", "a\nb"):
        with pytest.raises(ValueError):
            check_identifier(bad, "column")
    for bad in ("a/b", "..", "__masked__x", "__masked_abc"):
        with pytest.raises(ValueError):
            check_identifier(bad, "table", reserved=True)


def test_check_single_select():
    check_single_select("WITH a AS (SELECT 1) SELECT * FROM a")
    for bad in ("SELECT 1; COPY (SELECT 1) TO 'x'", "COPY t TO 'x'",
                "ATTACH 'x'", "SELECT (", ""):
        with pytest.raises(ValueError):
            check_single_select(bad)


def test_denied_functions_found_anywhere_in_the_tree():
    check_no_denied_functions("SELECT upper(email) FROM events WHERE id > 1")
    check_no_denied_functions('DESCRIBE "ns"."t"')
    for bad in ("SELECT * FROM \"POSTGRES_SCAN\"/**/('h', 'public', 't')",
                "SELECT (SELECT max(x) FROM postgres_query('db', 'select 1')) AS z",
                "WITH a AS (SELECT * FROM query('SELECT 1')) SELECT * FROM a",
                "SELECT * FROM t JOIN query_table('x') USING (id)",
                "PRAGMA version"):
        with pytest.raises(ValueError):
            check_no_denied_functions(bad)


def test_column_ddl_and_mask_expr_are_quoted():
    ddl, _ = schema_to_columns_ddl({"fields": [
        {"id": 1, "name": EVIL, "type": "long", "required": False}]})
    stmts = duckdb.extract_statements(f"CREATE TABLE t ({ddl})")
    assert len(stmts) == 1
    # a backslash in a name must not act as a regex group reference
    assert _qualify_expr("upper(val)", 'a"b\\1') == 'upper("a""b\\1")'


def test_paths_must_stay_under_table_location():
    loc = "s3://b/data/ns/t/"
    check_under_prefix(f"{loc}data/f.parquet", loc, "data file")
    for bad in ("s3://b/data/ns/other/f.parquet", f"{loc}../other/f.parquet",
                f"{loc}data//f.parquet", "s3://b/data/ns/t-other/f.parquet"):
        with pytest.raises(ValueError):
            check_under_prefix(bad, loc, "data file")


def test_catalog_names_are_strict():
    _check_catalog_names("acme__main", "dl_acme__main", "acme/main/")
    for bad in (('a"b', "s", "p/"), ("a", "s;x", "p/"), ("a", "s", "../p/"),
                ("a", "s", "p"), ("a", "s", "/p/"), ("a", "s", "__masked__/x/")):
        with pytest.raises(ValueError):
            _check_catalog_names(*bad)


# ---- REST edge --------------------------------------------------------------

def test_hostile_column_name_is_just_a_name(client):
    ns = _ns("col")
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    schema = {"type": "struct", "schema-id": 0, "fields": [
        {"id": 1, "name": EVIL, "required": False, "type": "long"}]}
    r = client.post(f"/v1/lake/namespaces/{ns}/tables", json={"name": "t", "schema": schema})
    assert r.status_code == 200, r.text
    names = [f["name"] for f in r.json()["metadata"]["schemas"][-1]["fields"]]
    assert names == [EVIL]


@pytest.mark.parametrize("ns_name", ["a/b", "__masked__x", "bad\x01name"])
def test_reserved_or_unsafe_namespace_rejected(client, ns_name):
    r = client.post("/v1/lake/namespaces", json={"namespace": [ns_name]})
    assert r.status_code == 400, r.text


def test_unsafe_table_name_rejected(client):
    ns = _ns("tbl")
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    r = client.post(f"/v1/lake/namespaces/{ns}/tables",
                    json={"name": "../escape", "schema": SCHEMA_JSON})
    assert r.status_code == 400, r.text


def test_view_body_must_be_one_select(client):
    ns = _ns("view")
    _make_table(client, ns, "t")
    body = {"name": "v", "schema": SCHEMA_JSON, "view-version": {
        "version-id": 1, "schema-id": 0, "timestamp-ms": 0, "summary": {},
        "default-namespace": [ns], "representations": [{
            "type": "sql", "dialect": "duckdb",
            "sql": f'SELECT * FROM "{ns}"."t"; ATTACH \':memory:\' AS pwn'}]}}
    r = client.post(f"/v1/lake/namespaces/{ns}/views", json=body)
    assert r.status_code == 400, r.text


def test_policy_body_must_be_one_expression(client):
    r = client.post("/v1/lake/governance/masking-policies", json={
        "name": f"evil_{uuid.uuid4().hex[:6]}", "signature": "(val VARCHAR)",
        "body": "val) AS x FROM t; COPY (SELECT 1) TO '/tmp/x'; SELECT (1"})
    assert r.status_code == 400, r.text


def test_string_default_is_a_literal(client, settings):
    ns = _ns("dflt")
    _make_table(client, ns, "t")
    meta = client.get(f"/v1/lake/namespaces/{ns}/tables/t").json()["metadata"]
    schema = dict(meta["schemas"][-1])
    hostile = "a'b\\' || (SELECT 1) || '"
    schema["fields"] = schema["fields"] + [
        {"id": 3, "name": "note", "required": False, "type": "string",
         "write-default": hostile}]
    schema["schema-id"] = schema.get("schema-id", 0) + 1
    r = client.post(f"/v1/lake/namespaces/{ns}/tables/t", json={
        "requirements": [], "updates": [
            {"action": "add-schema", "schema": schema},
            {"action": "set-current-schema", "schema-id": -1}]})
    assert r.status_code == 200, r.text
    con = _root_duckdb(settings)
    con.execute(f'INSERT INTO lake."{ns}"."t" (id) VALUES (1)')
    assert con.execute(f'SELECT note FROM lake."{ns}"."t"').fetchone()[0] == hostile
    con.close()


def _manifest_list(uri_of_manifest: str, snapshot_id: int) -> bytes:
    schema = parse_schema({"type": "record", "name": "manifest_file", "fields": [
        {"name": "manifest_path", "type": "string"},
        {"name": "added_snapshot_id", "type": "long"},
        {"name": "content", "type": "int"}]})
    buf = io.BytesIO()
    writer(buf, schema, [{"manifest_path": uri_of_manifest,
                          "added_snapshot_id": snapshot_id, "content": 0}])
    return buf.getvalue()


@pytest.mark.parametrize("where", ["manifest-list", "manifest"])
def test_commit_paths_outside_table_location_rejected(client, settings, where):
    """A writer must not be able to make the proxy read (with root creds) or
    register objects outside its own table — another table, another tenant."""
    ns = _ns("cmt")
    _make_table(client, ns, "t")
    s3 = settings.s3
    loc = f"s3://{s3.bucket}/{s3.table_prefix(ns, 't')}"
    outside = f"s3://{s3.bucket}/{s3.table_prefix(ns, 'victim')}metadata/m.avro"
    c = s3util.s3_client(s3)
    if where == "manifest-list":
        ml_uri = outside
    else:
        ml_uri = f"{loc}metadata/snap-1.avro"
        c.put_object(Bucket=s3.bucket, Key=ml_uri.split("/", 3)[3],
                     Body=_manifest_list(outside, 1))
    r = client.post(f"/v1/lake/namespaces/{ns}/tables/t", json={
        "requirements": [], "updates": [{"action": "add-snapshot", "snapshot": {
            "snapshot-id": 1, "timestamp-ms": 0, "manifest-list": ml_uri,
            "summary": {"operation": "append"}}}]})
    assert r.status_code == 400, r.text
    assert "outside the table location" in r.text


# ---- agent sessions ---------------------------------------------------------

def _cooperative_mask(client, ns: str, table: str) -> None:
    """A role-gated, NOT file-layer mask on `email` — the case where the old
    namespace-wide shortcut vended catalog-wide base access to an agent."""
    tag = f"em_{uuid.uuid4().hex[:6]}"
    pol = f"m_{uuid.uuid4().hex[:6]}"
    client.post("/v1/lake/governance/tags", json={"namespace": "pii", "name": tag}).raise_for_status()
    client.post("/v1/lake/governance/object-tags", json={
        "object-kind": "column", "schema": ns, "object": table, "column": "email",
        "tag-namespace": "pii", "tag-name": tag}).raise_for_status()
    client.post("/v1/lake/governance/masking-policies", json={
        "name": pol, "signature": "(val VARCHAR)", "body": "'***'",
        "unmasked-roles": ["pii_reader"]}).raise_for_status()
    client.post("/v1/lake/governance/policy-attachments", json={
        "policy-kind": "masking", "policy-name": pol, "target-kind": "tag",
        "tag-namespace": "pii", "tag-name": tag}).raise_for_status()


def _seeded_masked_table(client, settings, suffix: str) -> str:
    ns = _ns(suffix)
    _make_table(client, ns, "events")
    con = _root_duckdb(settings)
    con.execute(f"INSERT INTO lake.\"{ns}\".\"events\" VALUES (1, 'alice@example.com')")
    con.close()
    _cooperative_mask(client, ns, "events")
    return ns


def test_agent_namespace_vend_cannot_read_base_bytes(client, settings):
    ns = _seeded_masked_table(client, settings, "agns")
    r = client.get(f"/v1/lake/namespaces/{ns}/ducklake-credentials", params={
        "principal": "bob", "delegate": "1", "actor": "agent"})
    assert r.status_code == 200, r.text
    v = r.json()["s3"]
    assert v and v.get("access-key-id"), r.json()
    s3 = settings.s3
    gw = boto3.client("s3", endpoint_url=v["endpoint"], region_name=s3.region,
                      aws_access_key_id=v["access-key-id"],
                      aws_secret_access_key=v["secret-access-key"],
                      aws_session_token=v.get("session-token"),
                      config=s3util.boto_config(s3))
    base = s3.table_prefix(ns, "events")
    root = s3util.s3_client(s3)
    keys = [o["Key"] for o in root.list_objects_v2(
        Bucket=s3.bucket, Prefix=base).get("Contents", []) if o["Key"].endswith(".parquet")]
    assert keys, "seed wrote no parquet"
    with pytest.raises(Exception) as e:
        gw.get_object(Bucket=s3.bucket, Key=keys[0])["Body"].read()
    assert "403" in str(e.value) or "AccessDenied" in str(e.value)


@pytest.fixture(scope="module")
def executor():
    cfg = MCPConfig()
    cfg.gov_url = PROXY_URL
    cfg.broker = ""
    return GovernedExecutor(cfg, settings=load_settings())


def test_agent_executor_rejects_extra_statements(client, settings, executor):
    ns = _seeded_masked_table(client, settings, "exst")
    out = executor.query("lake", ns, "events",
                         "SELECT 1; ATTACH ':memory:' AS pwn", "bob")
    assert "error" in out and "one SELECT" in out["error"]


def test_agent_executor_refuses_postgres_scan(client, settings, executor):
    # postgres_scan opens its own connection from a DSN and isn't covered by
    # enable_external_access — it must never be callable from agent SQL
    ns = _seeded_masked_table(client, settings, "expg")
    out = executor.query("lake", ns, "events",
                         "SELECT * FROM postgres_scan('host=127.0.0.1 port=55432 "
                         "dbname=ducklake_test user=ducklake', 'public', 'duckicelake_role')",
                         "bob")
    assert "error" in out and "postgres_scan" in out["error"]


def test_agent_executor_requires_table(client, settings, executor):
    ns = _seeded_masked_table(client, settings, "extb")
    out = executor.query("lake", ns, "", "SELECT 1", "bob")
    assert "error" in out


def test_agent_executor_masks_and_is_locked_down(client, settings, executor):
    ns = _seeded_masked_table(client, settings, "exlk")
    out = executor.query("lake", ns, "events", "SELECT email FROM events", "bob")
    assert out.get("rows") == [["***"]], out
    for sql in ("SELECT * FROM read_text('/proc/self/environ')",
                f"SELECT * FROM read_parquet('s3://{settings.s3.bucket}/*/*.parquet')"):
        with pytest.raises(duckdb.Error):
            executor.query("lake", ns, "events", sql, "bob")


def test_hostile_names_in_tool_paths_stay_one_segment(executor):
    # `catalog` can't add path segments / a query string to the gov request
    with pytest.raises(Exception) as e:
        executor.list_tables("lake/governance/audit?x=", "y")
    assert "404" in str(e.value)
