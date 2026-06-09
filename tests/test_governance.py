"""Phase 1 governance layer tests.

Two layers:
  * `test_resolve_*` — pure unit tests over `resolve_effective_policies`,
    no Postgres / MinIO needed (the logic is a pure function).
  * `test_governance_*` — integration tests through the live proxy, mirroring
    the Phase 1 verification steps in `duckicelake_governance.md`: author a
    tag + masking policy + attachment + role-grant via REST, then confirm
    the audit trail recorded it and `effective-policies` derives the set.
"""
from __future__ import annotations

import uuid

from duckicelake.governance import resolve_effective_policies
from duckicelake.policies import (
    apply_plan_to_metadata,
    build_masked_view_sql,
    build_plan,
)


def _ns(suffix: str) -> str:
    return f"gov_{suffix}_{uuid.uuid4().hex[:6]}"


def _mask_inputs(unmasked_roles):
    """Shared fixture data: events(id, email), email tagged pii.email, a
    masking policy attached to that tag."""
    return dict(
        schema="analytics", table="events", columns=["id", "email"],
        object_tags=[{"object_kind": "column", "schema_name": "analytics",
                      "object_name": "events", "column_name": "email",
                      "tag_ns": "pii", "tag_name": "email", "tag_value": None}],
        attachments=[{"policy_kind": "masking", "policy_name": "mask_email",
                      "target_kind": "tag", "tag_ns": "pii", "tag_name": "email",
                      "schema_name": None, "object_name": None,
                      "column_name": None, "columns": None}],
        masking_bodies={"mask_email": {"signature": "(val VARCHAR)",
                                       "body": "left(val,2)||'***'",
                                       "unmasked_roles": unmasked_roles}},
        row_bodies={},
    )


# ---- pure resolution -------------------------------------------------------

def test_resolve_tag_cascade_and_masking():
    """A masking policy attached to a tag masks every column carrying that
    tag, including via schema/table cascade."""
    out = resolve_effective_policies(
        principal="agent-1",
        schema="analytics",
        table="events",
        columns=["id", "email", "country"],
        roles_for_principal=["agent"],
        object_tags=[
            # email column is tagged pii.email directly
            {"object_kind": "column", "schema_name": "analytics",
             "object_name": "events", "column_name": "email",
             "tag_ns": "pii", "tag_name": "email", "tag_value": None},
            # schema-level tag cascades to all columns
            {"object_kind": "schema", "schema_name": "analytics",
             "object_name": "", "column_name": "",
             "tag_ns": "data", "tag_name": "internal", "tag_value": None},
        ],
        attachments=[
            {"policy_kind": "masking", "policy_name": "mask_email",
             "target_kind": "tag", "tag_ns": "pii", "tag_name": "email",
             "schema_name": None, "object_name": None, "column_name": None,
             "columns": None},
        ],
        masking_bodies={"mask_email": {"signature": "(val VARCHAR)",
                                       "body": "'***'"}},
        row_bodies={},
    )
    by_col = {c["column"]: c for c in out["column_masks"]}
    # email picks up the mask via the pii.email tag
    assert "mask_email" in [p["name"] for p in by_col["email"]["masking_policies"]]
    # every column carries the cascading schema tag
    assert all("data.internal" in c["tags"] for c in out["column_masks"])
    assert out["roles"] == ["agent"]


def test_resolve_row_access_via_table_and_tag():
    out = resolve_effective_policies(
        principal="p", schema="s", table="t", columns=["region"],
        roles_for_principal=[],
        object_tags=[
            {"object_kind": "table", "schema_name": "s", "object_name": "t",
             "column_name": "", "tag_ns": "geo", "tag_name": "restricted",
             "tag_value": None},
        ],
        attachments=[
            {"policy_kind": "row_access", "policy_name": "by_region",
             "target_kind": "table", "tag_ns": None, "tag_name": None,
             "schema_name": "s", "object_name": "t", "column_name": None,
             "columns": ["region"]},
            {"policy_kind": "row_access", "policy_name": "geo_gate",
             "target_kind": "tag", "tag_ns": "geo", "tag_name": "restricted",
             "schema_name": None, "object_name": None, "column_name": None,
             "columns": None},
        ],
        masking_bodies={},
        row_bodies={"by_region": {"signature": "(region VARCHAR)", "body": "true"},
                    "geo_gate": {"signature": "(region VARCHAR)", "body": "true"}},
    )
    names = {p["name"]: p["via"] for p in out["row_access_policies"]}
    assert names["by_region"] == "table"
    assert names["geo_gate"].startswith("tag:geo.restricted")


def test_resolve_empty_when_no_governance():
    out = resolve_effective_policies(
        principal="p", schema="s", table="t", columns=["a", "b"],
        roles_for_principal=[], object_tags=[], attachments=[],
        masking_bodies={}, row_bodies={},
    )
    assert out["column_masks"] == []
    assert out["row_access_policies"] == []


# ---- Phase 2 enforcement: pure plan ---------------------------------------

def test_plan_masks_when_principal_lacks_unmasked_role():
    plan = build_plan(principal="agent-1", roles=["agent"],
                      **_mask_inputs(unmasked_roles=["pii_reader"]))
    assert plan.masked_columns == ["email"]
    assert not plan.is_empty()
    mask = plan.masks[0]
    # `val` token rewritten to the quoted column for the view SQL
    assert mask.mask_expr == 'left("email",2)||\'***\''
    assert 'left("email",2)' in plan.view_sql
    assert plan.view_sql.startswith('SELECT "id", left("email",2)')


def test_plan_bypasses_when_principal_holds_unmasked_role():
    plan = build_plan(principal="human-1", roles=["pii_reader"],
                      **_mask_inputs(unmasked_roles=["pii_reader"]))
    assert plan.masked_columns == []
    assert plan.is_empty()


def test_plan_combines_row_filters():
    plan = build_plan(
        principal="p", roles=[], schema="s", table="t", columns=["region"],
        object_tags=[],
        attachments=[{"policy_kind": "row_access", "policy_name": "eu_only",
                      "target_kind": "table", "tag_ns": None, "tag_name": None,
                      "schema_name": "s", "object_name": "t",
                      "column_name": None, "columns": ["region"]}],
        masking_bodies={},
        row_bodies={"eu_only": {"signature": "(region VARCHAR)",
                                "body": "region = 'EU'", "unmasked_roles": []}},
    )
    assert plan.row_filter == "(region = 'EU')"
    assert plan.view_sql.endswith("WHERE (region = 'EU')")


def test_apply_plan_to_metadata_stamps_signals():
    plan = build_plan(principal="agent-1", roles=["agent"],
                      **_mask_inputs(unmasked_roles=["pii_reader"]))
    metadata = {
        "schemas": [{"schema-id": 0, "fields": [
            {"id": 1, "name": "id", "type": "long"},
            {"id": 2, "name": "email", "type": "string"},
        ]}],
        "properties": {"existing": "kept"},
    }
    out = apply_plan_to_metadata(metadata, plan)
    # original untouched (deep-copied)
    assert "doc" not in metadata["schemas"][0]["fields"][1]
    props = out["properties"]
    assert props["existing"] == "kept"
    assert props["duckicelake.masked-columns"] == "email"
    assert props["duckicelake.mask.email"] == 'left("email",2)||\'***\''
    assert props["duckicelake.policy-principal"] == "agent-1"
    email_field = next(f for f in out["schemas"][0]["fields"] if f["name"] == "email")
    assert "masked by policy" in email_field["doc"]


def test_build_masked_view_sql_passthrough_for_unmasked_cols():
    sql = build_masked_view_sql(schema="s", table="t", columns=["a", "b", "c"],
                                masks={"b": "'***'"}, row_filter=None)
    assert sql == 'SELECT "a", \'***\' AS "b", "c" FROM "s"."t"'


# ---- integration through the proxy ----------------------------------------

def test_governance_authoring_and_audit(client):
    """End-to-end Phase 1: author objects via REST, confirm audit + the
    derived policy set. Requires the live proxy (pixi stack)."""
    ns = _ns("auth")
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    schema = {
        "type": "struct", "schema-id": 0,
        "fields": [
            {"id": 1, "name": "id", "required": True, "type": "long"},
            {"id": 2, "name": "email", "required": False, "type": "string"},
        ],
    }
    client.post(f"/v1/lake/namespaces/{ns}/tables",
                json={"name": "events", "schema": schema}).raise_for_status()

    # tag + policy + attachment + role-grant
    assert client.post("/v1/lake/governance/tags",
                       json={"namespace": "pii", "name": "email"}).status_code == 200
    assert client.post("/v1/lake/governance/object-tags",
                       json={"object-kind": "column", "schema": ns,
                             "object": "events", "column": "email",
                             "tag-namespace": "pii", "tag-name": "email"}).status_code == 200
    assert client.post("/v1/lake/governance/masking-policies",
                       json={"name": "mask_email", "signature": "(val VARCHAR)",
                             "body": "'***'"}).status_code == 200
    assert client.post("/v1/lake/governance/policy-attachments",
                       json={"policy-kind": "masking", "policy-name": "mask_email",
                             "target-kind": "tag", "tag-namespace": "pii",
                             "tag-name": "email"}).status_code == 200
    assert client.post("/v1/lake/governance/roles",
                       json={"name": "agent"}).status_code == 200
    assert client.post("/v1/lake/governance/role-grants",
                       json={"role": "agent", "principal": "agent-1"}).status_code == 200

    # effective-policies derives the masking set + the principal's role
    eff = client.get("/v1/lake/governance/effective-policies",
                     params={"table": f"{ns}.events", "principal": "agent-1"})
    assert eff.status_code == 200, eff.text
    body = eff.json()
    assert body["roles"] == ["agent"]
    email = next(c for c in body["column_masks"] if c["column"] == "email")
    assert "mask_email" in [p["name"] for p in email["masking_policies"]]

    # audit trail recorded the authoring operations
    audit = client.get("/v1/lake/governance/audit").json()["entries"]
    ops = {e["operation"] for e in audit}
    assert {"create_tag", "create_masking_policy", "attach_policy",
            "grant_role"} <= ops


def test_governance_loadtable_enforcement(client):
    """Phase 2: LoadTable for a principal lacking the unmasked role returns
    metadata stamped with the per-principal masking signals + the decision
    is audited. The proxy runs auth-off in tests, so the caller is the
    anonymous principal with no roles → email is masked."""
    ns = _ns("enf")
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    schema = {
        "type": "struct", "schema-id": 0,
        "fields": [
            {"id": 1, "name": "id", "required": True, "type": "long"},
            {"id": 2, "name": "email", "required": False, "type": "string"},
        ],
    }
    client.post(f"/v1/lake/namespaces/{ns}/tables",
                json={"name": "people", "schema": schema}).raise_for_status()

    client.post("/v1/lake/governance/tags",
                json={"namespace": "pii", "name": "email"}).raise_for_status()
    client.post("/v1/lake/governance/object-tags",
                json={"object-kind": "column", "schema": ns, "object": "people",
                      "column": "email", "tag-namespace": "pii",
                      "tag-name": "email"}).raise_for_status()
    client.post("/v1/lake/governance/masking-policies",
                json={"name": "mask_email", "signature": "(val VARCHAR)",
                      "body": "'***'", "unmasked-roles": ["pii_reader"]}).raise_for_status()
    client.post("/v1/lake/governance/policy-attachments",
                json={"policy-kind": "masking", "policy-name": "mask_email",
                      "target-kind": "tag", "tag-namespace": "pii",
                      "tag-name": "email"}).raise_for_status()

    # effective-policies shows the enforcement decision for anonymous
    eff = client.get("/v1/lake/governance/effective-policies",
                     params={"table": f"{ns}.people", "principal": "anonymous"}).json()
    assert eff["enforcement"]["masked_columns"] == ["email"]

    # LoadTable returns metadata carrying the masking signals
    r = client.get(f"/v1/lake/namespaces/{ns}/tables/people")
    assert r.status_code == 200, r.text
    md = r.json()["metadata"]
    assert md["properties"]["duckicelake.masked-columns"] == "email"
    assert "duckicelake.mask.email" in md["properties"]
    email_field = next(
        f for sch in md["schemas"] for f in sch["fields"] if f["name"] == "email"
    )
    assert "masked by policy" in email_field.get("doc", "")

    # the LoadTable masking decision was audited
    audit = client.get("/v1/lake/governance/audit").json()["entries"]
    loads = [e for e in audit if e["operation"] == "load_table"]
    assert any(e["masked_cols"] == ["email"] for e in loads)
