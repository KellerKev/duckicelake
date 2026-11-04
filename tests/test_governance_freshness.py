"""Caches keyed on governance must see every governance change: the version
moves on adds, edits and deletes alike (Postgres statement triggers), the
policy-candidate set honours schema-level tag cascade, and a concurrent first
read of a file-layer export waits for it instead of failing."""
from __future__ import annotations

import threading
import time
import uuid

import psycopg
import pytest

from duckicelake.catalog import DuckLakeCatalog
from duckicelake.governance import GovernanceStore
from duckicelake.masked_export import MaskedExportManager, _lock_key

from test_governance_phase3 import SCHEMA_JSON


@pytest.fixture
def store(settings):
    c = DuckLakeCatalog(settings)
    c.connect()
    yield GovernanceStore(c)
    c.close()


def test_stamp_moves_on_grant_and_revoke(client, store):
    role, who = f"r_{uuid.uuid4().hex[:6]}", f"u_{uuid.uuid4().hex[:6]}"
    client.post("/v1/lake/governance/roles", json={"name": role}).raise_for_status()
    s0 = store.governance_stamp()
    client.post("/v1/lake/governance/role-grants",
                json={"role": role, "principal": who}).raise_for_status()
    s1 = store.governance_stamp()
    client.request("DELETE", "/v1/lake/governance/role-grants",
                   json={"role": role, "principal": who}).raise_for_status()
    s2 = store.governance_stamp()
    assert s0 != s1 != s2 and s0 != s2


def test_stamp_moves_on_direct_sql_update(settings, store):
    """Any writer — not just the API — invalidates (e.g. an operator's psql)."""
    s0 = store.governance_stamp()
    with psycopg.connect(settings.pg_dsn, autocommit=True) as c:
        c.execute(f"UPDATE {store._sc}.duckicelake_masking_policy SET name = name WHERE false")
    assert store.governance_stamp() != s0


def test_schema_tag_makes_every_table_a_policy_candidate(client, store):
    ns = f"fr_{uuid.uuid4().hex[:6]}"
    client.post("/v1/lake/namespaces", json={"namespace": [ns]}).raise_for_status()
    for t in ("a", "b"):
        client.post(f"/v1/lake/namespaces/{ns}/tables",
                    json={"name": t, "schema": SCHEMA_JSON}).raise_for_status()
    assert store.tables_with_policies(ns) == []
    tag = f"t{uuid.uuid4().hex[:6]}"
    client.post("/v1/lake/governance/tags", json={"namespace": "sec", "name": tag}).raise_for_status()
    client.post("/v1/lake/governance/object-tags",
                json={"object-kind": "schema", "schema": ns, "object": "", "column": "",
                      "tag-namespace": "sec", "tag-name": tag}).raise_for_status()
    pol = f"rap_{tag}"
    client.post("/v1/lake/governance/row-access-policies",
                json={"name": pol, "signature": "()", "body": "false"}).raise_for_status()
    client.post("/v1/lake/governance/policy-attachments",
                json={"policy-kind": "row_access", "policy-name": pol, "target-kind": "tag",
                      "tag-namespace": "sec", "tag-name": tag}).raise_for_status()
    assert sorted(store.tables_with_policies(ns)) == ["a", "b"]


def test_export_loser_waits_for_the_first_export(settings, store):
    """Two first reads of one export shape: the one that loses the lock race
    waits for the winner's export instead of returning nothing (→ 503)."""
    mgr = MaskedExportManager(store.catalog, settings, store=store)
    ns, table, sig = "w_ns", "w_t", "s1"
    key = _lock_key(mgr._sc, ns, table, sig)
    import types
    published = types.SimpleNamespace(snapshot=1)
    calls = []
    mgr.current_export = lambda *_a: published if calls else None   # appears once the winner is done
    with psycopg.connect(settings.pg_dsn, autocommit=True) as holder:
        holder.execute("SELECT pg_advisory_lock(%s)", (key,))
        out = {}
        t = threading.Thread(target=lambda: out.setdefault(
            "r", mgr._export([ns], table, plan=None, sig=sig, snap=1)))
        t.start()
        time.sleep(1.0)
        assert t.is_alive()               # waiting, not giving up
        calls.append(1)                   # winner published its export...
        holder.execute("SELECT pg_advisory_unlock(%s)", (key,))   # ...and let go
        t.join(10)
    assert out.get("r") is published
