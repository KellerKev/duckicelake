"""Governance as a declarative spec: export, plan, apply (governance_spec.py).

Pure tests for parsing / export / diff, then live-proxy tests. Every live
test provisions its own catalog, so a pruning import can only ever touch
governance that test authored."""
from __future__ import annotations

import uuid

import pytest
import yaml

from conftest import TEST_S3_ROOT
from duckicelake import governance_spec as gs
from test_governance_phase3 import SCHEMA_JSON


# ---- pure ---------------------------------------------------------------

SPEC = {
    "version": 1,
    "kind": "duckicelake/governance",
    "tags": [{"tag": "pii.email"}, {"tag": "tier.level", "allowed_values": ["b", "a"]}],
    "roles": [{"role": "pii_reader", "members": ["alice@acme.test"]}, {"role": "analyst"}],
    "grants": [{"role": "analyst", "privilege": "SELECT",
                "on": {"schema": "sales", "table": "customers"}}],
    "tag_assignments": [{"tag": "pii.email",
                         "on": {"schema": "sales", "table": "customers", "column": "email"}}],
    "masking_policies": [{
        "name": "mask_email", "signature": "(val VARCHAR)", "body": "left(val,2)||'***'",
        "unmasked_roles": ["pii_reader"], "attach": [{"tag": "pii.email"}]}],
    "row_access_policies": [{
        "name": "eu_only", "signature": "(region VARCHAR)", "body": "region = 'EU'",
        "attach": [{"on": {"schema": "sales", "table": "orders"}, "columns": ["region"]}]}],
}


def test_parse_export_round_trip_is_stable():
    st = gs.parse_document(SPEC)
    doc = gs.to_document(st)
    assert gs.parse_document(doc) == st
    # deterministic text: exporting twice gives identical YAML
    assert gs.dump_yaml(doc) == gs.dump_yaml(gs.to_document(gs.parse_document(doc)))
    assert doc["tags"][1] == {"tag": "tier.level", "allowed_values": ["a", "b"]}


def test_digest_ignores_formatting_and_order():
    shuffled = dict(SPEC, roles=list(reversed(SPEC["roles"])))
    assert gs.spec_digest(SPEC) == gs.spec_digest(shuffled)
    assert gs.spec_digest(SPEC) == gs.spec_digest(yaml.safe_load(gs.dump_yaml(SPEC)))


@pytest.mark.parametrize("mutate, msg", [
    (lambda d: d["masking_policies"][0].update(unmaksed_roles=["x"]), "unknown key"),
    (lambda d: d.update(version=2), "version"),
    (lambda d: d["masking_policies"][0].update(body="1); DROP TABLE x; SELECT (1"),
     "exactly one SELECT"),
    (lambda d: d["masking_policies"][0]["attach"].append(
        {"on": {"schema": "sales", "table": "customers"}}), "attaches to a column"),
    (lambda d: d["row_access_policies"][0]["attach"].append(
        {"on": {"schema": "s", "table": "t", "column": "c"}}), "attaches to a table"),
    (lambda d: d["roles"].append({"role": "analyst"}), "duplicate"),
    (lambda d: d["grants"][0]["on"].update(column="email"), "not a column"),
    (lambda d: d["tags"].append({"tag": "nodot"}), "namespace.name"),
])
def test_parse_rejects(mutate, msg):
    import copy
    d = copy.deepcopy(SPEC)
    mutate(d)
    with pytest.raises(gs.SpecError, match=msg):
        gs.parse_document(d)


def test_yaml_aliases_rejected():
    with pytest.raises(gs.SpecError, match="aliases"):
        gs.load_document("version: 1\nroles:\n- &r {role: a}\n- *r\n")


def test_validate_dangling_references():
    st = gs.parse_document(SPEC)
    bad = gs.parse_document({**SPEC, "tags": [{"tag": "tier.level"}]})   # pii.email gone
    with pytest.raises(gs.SpecError, match="pii.email is not defined"):
        gs.validate(bad, bad)
    no_role = gs.parse_document({**SPEC, "roles": [{"role": "pii_reader"}]})
    with pytest.raises(gs.SpecError, match="role 'analyst' is not defined"):
        gs.validate(no_role, no_role)
    assert gs.validate(st, st) == []


def test_validate_warns_on_unheld_bypass_role():
    d = {**SPEC, "roles": [{"role": "pii_reader"}, {"role": "analyst"}]}
    st = gs.parse_document(d)
    assert any("nobody holds unmasked role 'pii_reader'" in w for w in gs.validate(st, st))


def test_diff_orders_and_prunes():
    cur = gs.parse_document(SPEC)
    want = gs.parse_document({**SPEC, "row_access_policies": [], "grants": []})
    assert gs.diff(cur, want, prune=False) == []
    ops = [(c.op, c.section) for c in gs.diff(cur, want, prune=True)]
    # dependents go first: the attachment before its policy
    assert ops == [("delete", "attachments"), ("delete", "grants"), ("delete", "row_access")]
    changed = gs.parse_document({**SPEC, "masking_policies": [
        {**SPEC["masking_policies"][0], "body": "'***'"}]})
    [c] = gs.diff(cur, changed, prune=True)
    assert (c.op, c.section, c.key) == ("update", "masking", "mask_email")


# ---- live ---------------------------------------------------------------

@pytest.fixture()
def cat(client):
    """A fresh catalog of its own, with sales.customers(id, email) in it."""
    h = uuid.uuid4().hex[:8]
    cid = f"gspec_{h}"
    r = client.post("/v1/catalogs", json={
        "catalog_id": cid, "metadata_schema": f"dl_gspec_{h}",
        "data_prefix": f"{TEST_S3_ROOT}gspec_{h}/"})
    assert r.status_code in (200, 201), r.text
    client.post(f"/v1/{cid}/namespaces", json={"namespace": ["sales"]}).raise_for_status()
    client.post(f"/v1/{cid}/namespaces/sales/tables",
                json={"name": "customers", "schema": SCHEMA_JSON}).raise_for_status()
    return cid


def _spec(**over) -> dict:
    d = {
        "version": 1,
        "tags": [{"tag": "pii.email"}],
        "roles": [{"role": "pii_reader", "members": ["alice"]}],
        "tag_assignments": [{"tag": "pii.email",
                             "on": {"schema": "sales", "table": "customers", "column": "email"}}],
        "masking_policies": [{"name": "mask_email", "signature": "(val VARCHAR)",
                              "body": "left(val,2)||'***'", "unmasked_roles": ["pii_reader"],
                              "attach": [{"tag": "pii.email"}]}],
    }
    d.update(over)
    return d


def _post(client, cid, spec, **params):
    body = spec if isinstance(spec, str) else yaml.safe_dump(spec)
    return client.post(f"/v1/{cid}/governance/spec", params=params, content=body,
                       headers={"content-type": "application/json"})   # as the console proxy sends


def _masked(client, cid, principal):
    eff = client.get(f"/v1/{cid}/governance/effective-policies",
                     params={"table": "sales.customers", "principal": principal}).json()
    return eff["enforcement"]["masked_columns"]


def _version(client, cid):
    return client.get(f"/v1/{cid}/governance/spec", params={"format": "json"}
                      ).json()["governance_version"]


def test_plan_changes_nothing_apply_enforces(client, cat):
    v0 = _version(client, cat)
    plan = _post(client, cat, _spec())
    assert plan.status_code == 200, plan.text
    p = plan.json()
    assert p["mode"] == "plan" and p["summary"] == {"create": 6, "update": 0, "delete": 0}
    assert _version(client, cat) == v0
    assert _masked(client, cat, "bob") == []

    r = _post(client, cat, _spec(), mode="apply", if_version=p["base_version"],
              source="git:abc123")
    assert r.status_code == 200, r.text
    assert _masked(client, cat, "bob") == ["email"]
    assert _masked(client, cat, "alice") == []          # holds the bypass role
    audit = client.get(f"/v1/{cat}/governance/audit").json()["entries"]
    imp = [e for e in audit if e["operation"] == "import_governance_spec"]
    assert imp[0]["decision"] == "ok"
    assert imp[0]["detail"]["source"] == "git:abc123"
    assert imp[0]["detail"]["digest"] == p["digest"]
    # each change is audited individually too
    assert any(e["operation"] == "attach_policy" for e in audit)


def test_export_import_round_trip_is_a_no_op(client, cat):
    _post(client, cat, _spec(), mode="apply").raise_for_status()
    exported = client.get(f"/v1/{cat}/governance/spec")
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("application/yaml")
    again = _post(client, cat, exported.text, prune="true")
    assert again.status_code == 200, again.text
    assert again.json()["changes"] == []


def test_prune_removes_what_the_spec_lacks(client, cat):
    _post(client, cat, _spec(), mode="apply").raise_for_status()
    # authored outside the spec, through the normal REST surface
    client.post(f"/v1/{cat}/governance/roles", json={"name": "stray"}).raise_for_status()
    without_mask = _spec(masking_policies=[], tag_assignments=[])

    additive = _post(client, cat, without_mask, mode="apply").json()
    assert additive["summary"]["delete"] == 0
    assert _masked(client, cat, "bob") == ["email"]

    pruned = _post(client, cat, without_mask, mode="apply", prune="true")
    assert pruned.status_code == 200, pruned.text
    deleted = {(c["kind"], c["target"]) for c in pruned.json()["changes"] if c["op"] == "delete"}
    assert ("role", "stray") in deleted
    assert ("masking_policy", "mask_email") in deleted
    assert _masked(client, cat, "bob") == []
    assert pruned.json()["resync"] == [["sales", "customers"]]


def test_invariant_conflict_rolls_back_everything(client, cat):
    two_masks = _spec(masking_policies=[
        _spec()["masking_policies"][0],
        {"name": "mask_email_2", "signature": "(val VARCHAR)", "body": "'x'",
         "attach": [{"on": {"schema": "sales", "table": "customers", "column": "email"}}]},
    ])
    v0 = _version(client, cat)
    for mode in ("plan", "apply"):
        r = _post(client, cat, two_masks, mode=mode)
        assert r.status_code == 409, r.text
        assert "only one masking policy" in r.text
    assert _version(client, cat) == v0        # not even the tag or role landed


def test_stale_plan_is_refused(client, cat):
    p = _post(client, cat, _spec()).json()
    client.post(f"/v1/{cat}/governance/roles", json={"name": "meanwhile"}).raise_for_status()
    r = _post(client, cat, _spec(), mode="apply", if_version=p["base_version"])
    assert r.status_code == 409 and "plan again" in r.text


def test_bad_specs_are_400(client, cat):
    assert _post(client, cat, "version: 1\nrolez: []\n").status_code == 400
    assert _post(client, cat, "{not yaml: [").status_code == 400
    undefined = _spec(tags=[])
    r = _post(client, cat, undefined)
    assert r.status_code == 400 and "not defined in tags" in r.text
    assert _post(client, cat, _spec(), mode="destroy").status_code == 400


def test_missing_objects_are_warnings(client, cat):
    spec = _spec(tag_assignments=[
        {"tag": "pii.email", "on": {"schema": "sales", "table": "customers", "column": "emial"}}])
    r = _post(client, cat, spec)
    assert r.status_code == 200, r.text
    assert "sales.customers.emial: no such column (yet)" in r.json()["warnings"]
