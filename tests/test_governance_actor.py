"""Actor/channel context-aware governance (pure, no infra).

A session's context (actor: human|agent, channel: rest|mcp) is asserted by a
trusted broker and appended to the effective role set as `actor:<v>` /
`channel:<v>` tags. Policies drive on those tags via the existing
`unmasked_roles` bypass — "roles-inversion": grant humans the bypass tag,
withhold it from agents, and a sensitive column masks for agents while staying
cleartext for humans. This test proves the decision layer without any DB.
"""
from __future__ import annotations

from duckicelake.auth import is_admin_scope, is_broker_scope
from duckicelake.policies import build_plan, mask_signature


def _plan(roles):
    """Plan for a column masked by a policy whose bypass tag is `actor:human`."""
    return build_plan(
        principal="alice", roles=list(roles), schema="obs", table="host_metrics",
        columns=["ts", "host"],
        object_tags=[{"object_kind": "column", "schema_name": "obs",
                      "object_name": "host_metrics", "column_name": "host",
                      "tag_ns": "pii", "tag_name": "host", "tag_value": None}],
        attachments=[{"policy_kind": "masking", "policy_name": "mask_host",
                      "target_kind": "tag", "tag_ns": "pii", "tag_name": "host",
                      "schema_name": None, "object_name": None,
                      "column_name": None, "columns": None}],
        masking_bodies={"mask_host": {"signature": "(val VARCHAR)",
                                      "body": "'***'",
                                      "unmasked_roles": ["actor:human"]}},
        row_bodies={},
    )


def test_broker_scope_recognition():
    assert is_broker_scope("broker")          # explicit least-privilege grant
    assert is_broker_scope("*")               # superuser implies broker
    assert is_broker_scope("ns:x:r broker")   # among other scopes
    assert not is_broker_scope("ns:x:r")      # a plain read token cannot delegate
    assert not is_broker_scope("")
    # broker is not admin: a broker-only token is not a superuser
    assert not is_admin_scope("broker")


def test_human_bypasses_agent_is_masked():
    human = _plan(["actor:human", "channel:rest"])
    agent = _plan(["actor:agent", "channel:mcp"])
    assert human.masked_columns == []          # holds the bypass tag -> cleartext
    assert agent.masked_columns == ["host"]    # lacks it -> masked


def test_context_plans_do_not_collide():
    # Different effective masks must yield different signatures, else agent and
    # human sessions would share one materialized view / cached credential.
    human = _plan(["actor:human", "channel:rest"])
    agent = _plan(["actor:agent", "channel:mcp"])
    assert mask_signature(human) != mask_signature(agent)


def test_channel_can_gate_instead_of_actor():
    # The same inversion works on the channel axis: bypass only over REST.
    def _plan_channel(roles):
        return build_plan(
            principal="alice", roles=list(roles), schema="obs",
            table="host_metrics", columns=["ts", "host"],
            object_tags=[{"object_kind": "column", "schema_name": "obs",
                          "object_name": "host_metrics", "column_name": "host",
                          "tag_ns": "pii", "tag_name": "host", "tag_value": None}],
            attachments=[{"policy_kind": "masking", "policy_name": "mask_host",
                          "target_kind": "tag", "tag_ns": "pii",
                          "tag_name": "host", "schema_name": None,
                          "object_name": None, "column_name": None,
                          "columns": None}],
            masking_bodies={"mask_host": {"signature": "(val VARCHAR)",
                                          "body": "'***'",
                                          "unmasked_roles": ["channel:rest"]}},
            row_bodies={})
    assert _plan_channel(["channel:rest"]).masked_columns == []
    assert _plan_channel(["channel:mcp"]).masked_columns == ["host"]
