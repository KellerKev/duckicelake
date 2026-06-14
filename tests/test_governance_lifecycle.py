"""Governance authoring lifecycle: the one-mask-per-column invariant and the
delete/detach/revoke surface. Live proxy (session fixture), REST only."""
from __future__ import annotations

import uuid

import psycopg

from test_governance_phase3 import SCHEMA_JSON, _make_table, _author_demo_policy


def _ns(s: str) -> str:
    return f"glc_{s}_{uuid.uuid4().hex[:6]}"


def _mk_policy(client, name, body="left(val,2)||'***'"):
    return client.post("/v1/lake/governance/masking-policies",
                       json={"name": name, "signature": "(val VARCHAR)",
                             "body": body})


# ---- Stage 1: one-mask-per-column invariant --------------------------------

def test_second_mask_direct_on_column_rejected(client):
    ns = _ns("dup_direct")
    _make_table(client, ns, "events")
    _author_demo_policy(client, ns, "events")          # email masked via pii.email tag
    _mk_policy(client, "mask_email_2", "'xxx'").raise_for_status()
    # attach a *different* mask directly to the already-masked column → 409
    r = client.post("/v1/lake/governance/policy-attachments",
                    json={"policy-kind": "masking", "policy-name": "mask_email_2",
                          "target-kind": "column", "schema": ns,
                          "object": "events", "column": "email"})
    assert r.status_code == 409, r.text
    assert "only one masking policy" in r.text


def test_second_mask_via_new_tag_rejected(client):
    ns = _ns("dup_tag")
    _make_table(client, ns, "events")
    _author_demo_policy(client, ns, "events")          # email masked via pii.email
    _mk_policy(client, "mask_email_2", "'xxx'").raise_for_status()
    client.post("/v1/lake/governance/tags",
                json={"namespace": "pii", "name": "email2"}).raise_for_status()
    client.post("/v1/lake/governance/policy-attachments",
                json={"policy-kind": "masking", "policy-name": "mask_email_2",
                      "target-kind": "tag", "tag-namespace": "pii",
                      "tag-name": "email2"}).raise_for_status()
    # tagging the already-masked column with the second mask-bearing tag → 409
    r = client.post("/v1/lake/governance/object-tags",
                    json={"object-kind": "column", "schema": ns, "object": "events",
                          "column": "email", "tag-namespace": "pii", "tag-name": "email2"})
    assert r.status_code == 409, r.text


def test_reattach_same_policy_is_idempotent(client):
    ns = _ns("reattach")
    _make_table(client, ns, "events")
    _author_demo_policy(client, ns, "events")
    # re-POST the identical attachment — no second mask, just an upsert
    r = client.post("/v1/lake/governance/policy-attachments",
                    json={"policy-kind": "masking", "policy-name": "mask_email",
                          "target-kind": "tag", "tag-namespace": "pii",
                          "tag-name": "email"})
    assert r.status_code == 200, r.text


def test_distinct_columns_each_get_a_mask(client):
    """The invariant is per-column — two different columns can each carry
    their own (different) mask."""
    ns = _ns("twocol")
    _make_table(client, ns, "events")            # id, email
    _author_demo_policy(client, ns, "events")    # mask on email
    _mk_policy(client, "mask_id", "'REDACTED'").raise_for_status()
    r = client.post("/v1/lake/governance/policy-attachments",
                    json={"policy-kind": "masking", "policy-name": "mask_id",
                          "target-kind": "column", "schema": ns,
                          "object": "events", "column": "id"})
    assert r.status_code == 200, r.text
    eff = client.get("/v1/lake/governance/effective-policies",
                     params={"table": f"{ns}.events", "principal": "nobody"}).json()
    assert set(eff["enforcement"]["masked_columns"]) == {"id", "email"}


# ---- Stage 2: delete / detach / revoke -------------------------------------

from test_governance_phase3 import _live_view_rows, _root_duckdb, _vended_duckdb


def test_delete_policy_refused_while_attached(client):
    ns = _ns("del_attached")
    _make_table(client, ns, "events")
    _author_demo_policy(client, ns, "events")          # mask_email attached to pii.email
    # deleting while still attached → 409
    r = client.delete("/v1/lake/governance/masking-policies/mask_email")
    assert r.status_code == 409, r.text
    assert "detach" in r.text
    # detach, then delete succeeds
    d = client.request("DELETE", "/v1/lake/governance/policy-attachments",
                       json={"policy-kind": "masking", "policy-name": "mask_email",
                             "target-kind": "tag", "tag-namespace": "pii",
                             "tag-name": "email"})
    assert d.status_code == 200, d.text
    r = client.delete("/v1/lake/governance/masking-policies/mask_email")
    assert r.status_code == 200, r.text
    # gone
    assert client.delete("/v1/lake/governance/masking-policies/mask_email").status_code == 404


def test_detach_flips_column_back_to_cleartext(client, settings):
    """Detaching the mask removes it from the next LoadTable, and the stale
    masking view is GC'd by the resync hook."""
    ns = _ns("detach_clear")
    _make_table(client, ns, "events")
    _author_demo_policy(client, ns, "events")
    md = client.get(f"/v1/lake/namespaces/{ns}/tables/events").json()["metadata"]
    view = md["properties"]["duckicelake.masking-view-name"]
    assert md["properties"]["duckicelake.masked-columns"] == "email"
    assert _live_view_rows(settings.pg_dsn, ns, view) == 1

    client.request("DELETE", "/v1/lake/governance/policy-attachments",
                   json={"policy-kind": "masking", "policy-name": "mask_email",
                         "target-kind": "tag", "tag-namespace": "pii",
                         "tag-name": "email"}).raise_for_status()

    md = client.get(f"/v1/lake/namespaces/{ns}/tables/events").json()["metadata"]
    assert "duckicelake.masked-columns" not in md["properties"]   # unmasked now
    assert _live_view_rows(settings.pg_dsn, ns, view) == 0        # stale view dropped


def test_untag_removes_mask(client):
    ns = _ns("untag")
    _make_table(client, ns, "events")
    _author_demo_policy(client, ns, "events")
    eff = client.get("/v1/lake/governance/effective-policies",
                     params={"table": f"{ns}.events", "principal": "x"}).json()
    assert eff["enforcement"]["masked_columns"] == ["email"]
    # untag the column → mask no longer reaches it
    client.request("DELETE", "/v1/lake/governance/object-tags",
                   json={"object-kind": "column", "schema": ns, "object": "events",
                         "column": "email", "tag-namespace": "pii",
                         "tag-name": "email"}).raise_for_status()
    eff = client.get("/v1/lake/governance/effective-policies",
                     params={"table": f"{ns}.events", "principal": "x"}).json()
    assert eff["enforcement"]["masked_columns"] == []


def test_delete_tag_refused_while_in_use(client):
    ns = _ns("del_tag")
    _make_table(client, ns, "events")
    _author_demo_policy(client, ns, "events")
    # tag is assigned + attached → 409
    assert client.delete("/v1/lake/governance/tags/pii/email").status_code == 409


def test_revoke_role_flips_principal_back_to_masked(client):
    ns = _ns("revoke")
    _make_table(client, ns, "events")
    _author_demo_policy(client, ns, "events")
    client.post("/v1/lake/governance/roles",
                json={"name": "pii_reader"}).raise_for_status()
    client.post("/v1/lake/governance/role-grants",
                json={"role": "pii_reader", "principal": "vip"}).raise_for_status()
    eff = client.get("/v1/lake/governance/effective-policies",
                     params={"table": f"{ns}.events", "principal": "vip"}).json()
    assert eff["enforcement"]["masked_columns"] == []      # bypassed
    client.request("DELETE", "/v1/lake/governance/role-grants",
                   json={"role": "pii_reader", "principal": "vip"}).raise_for_status()
    eff = client.get("/v1/lake/governance/effective-policies",
                     params={"table": f"{ns}.events", "principal": "vip"}).json()
    assert eff["enforcement"]["masked_columns"] == ["email"]   # masked again


def test_delete_role_refused_while_granted(client):
    ns = _ns("del_role")
    client.post("/v1/lake/governance/roles", json={"name": "tmp_role"}).raise_for_status()
    client.post("/v1/lake/governance/role-grants",
                json={"role": "tmp_role", "principal": "p"}).raise_for_status()
    assert client.delete("/v1/lake/governance/roles/tmp_role").status_code == 409
    client.request("DELETE", "/v1/lake/governance/role-grants",
                   json={"role": "tmp_role", "principal": "p"}).raise_for_status()
    assert client.delete("/v1/lake/governance/roles/tmp_role").status_code == 200
