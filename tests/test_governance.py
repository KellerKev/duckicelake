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


def _ns(suffix: str) -> str:
    return f"gov_{suffix}_{uuid.uuid4().hex[:6]}"


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
