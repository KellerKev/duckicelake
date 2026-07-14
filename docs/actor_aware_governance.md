# Actor-aware governance (broker delegation + session context)

duckicelake policies can react to **session context** — who/what is driving a
request — so an author can tighten access when an AI agent is involved (extra
masking, read-only) while a human sees normal results. This is built on the
existing role/`unmasked_roles` machinery; no new policy schema is required.

## 1. Trusted-broker delegation

Under auth-on, the caller's identity is normally the token `sub`. A gateway that
fronts duckicelake for many end users needs to speak for them. A token holding
the **`broker`** scope (a superuser `*` token also qualifies) may assert, per
request, the effective `principal` and the session context:

```
GET /v1/{catalog}/namespaces/{ns}/ducklake-credentials
      ?principal=<end-user>&actor=<human|agent>&channel=<rest|mcp>
```

`is_broker_scope()` gates this. A **non-broker** token can never assert another
principal or a context — its `principal`/`actor`/`channel` params are ignored and
it is treated as the direct principal with the default `human`/`rest` context.
Dev/auth-off keeps honoring `principal` as before.

## 2. Context tags

The asserted context is appended to the caller's effective role set as synthetic
tags (defaults `actor:human`, `channel:rest`):

- `actor:human` | `actor:agent`
- `channel:rest` | `channel:mcp`

They flow through the existing `plan_for → build_plan → _bypasses` path, so
policies can drive on them with no engine change. The credential cache key
includes the context, and `mask_signature` is plan-derived, so agent and human
sessions never share a masked view or a cached credential.

## 3. Authoring: roles-inversion masking

Because `unmasked_roles` grants a **bypass** (cleartext), you make a column
sensitive-to-agents by granting the bypass tag to humans and withholding it from
agents:

```sql
-- mask a column for everyone whose context is not human
-- (agents over any channel are masked; humans see cleartext)
duckicelake_masking_policy(name='mask_host', signature_sql='(val VARCHAR)',
                           body_sql="'***'", unmasked_roles=ARRAY['actor:human'])
```

Gate on the channel instead to mask anything arriving over MCP:

```sql
unmasked_roles = ARRAY['channel:rest']   -- only REST callers see cleartext
```

Combine with real roles as usual, e.g. `ARRAY['actor:human','pii_reader']` — any
listed role bypasses.

## 4. Read-only for agents

Agent sessions are read-only at the data plane: a `write=1` DuckLake-direct vend
is refused (403, audited `error_agent_readonly`) when `actor:agent` is present,
regardless of token scope. Reads apply the masking above.

## 5. Notes / limits

- The DuckLake-direct credential tier is cooperative — a client that holds the
  vended DSN can still read base tables. For airtight enforcement against agents,
  serve them results-only through a server-side executor (they never receive the
  DSN), and/or use file-layer masking.
- Row-level RLS re-resolves identity inside Postgres from the vended reader role;
  a context that must change *row* visibility (not just column masking) needs the
  context folded into the vended role identity (future work).
