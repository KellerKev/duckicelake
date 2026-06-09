# Governance layer (experimental)

Snowflake-style tagging + RBAC + masking for duckicelake. The design and
phasing live in [`duckicelake_governance.md`](duckicelake_governance.md).
This document tracks what is **actually implemented** on the
`experimental_governance` branch.

> **Status: Phase 1 only.** The authoring surface + audit trail are live.
> **Nothing is enforced yet** — no column is masked, no row is filtered, no
> credential is withheld. Phase 1 is pure foundation, zero behavioural risk
> to the existing read/write paths.

## What Phase 1 ships

| Piece | Where |
|---|---|
| Governance sidecar tables (`duckicelake_tag`, `_object_tag`, `_masking_policy`, `_row_access_policy`, `_policy_attachment`, `_role`, `_role_grant`, `_object_owner`, `_object_grant`, `_governance_audit`) | [src/duckicelake/governance.py](src/duckicelake/governance.py) |
| CRUD + audit store (`GovernanceStore`) | [src/duckicelake/governance.py](src/duckicelake/governance.py) |
| Pure effective-policy resolver (`resolve_effective_policies`) | [src/duckicelake/governance.py](src/duckicelake/governance.py) |
| REST authoring router | [src/duckicelake/governance_api.py](src/duckicelake/governance_api.py) |
| JWT `roles` claim | [src/duckicelake/auth.py](src/duckicelake/auth.py) |
| Tests | [tests/test_governance.py](tests/test_governance.py) |

The sidecars follow the existing `duckicelake_*` convention — created on
demand via `ensure_governance_sidecars`, mutated with `ON CONFLICT` upserts,
borrowing the catalog's Postgres pool. The REST router is mounted additively
in [server.py](src/duckicelake/server.py) via `include_router`, so the core
Iceberg REST surface is untouched.

## REST surface

All under `/v1/{prefix}/governance` (prefix = catalog name, default `lake`).
Authoring routes live under `/v1/` so the existing bearer-auth middleware
gates them; because the paths carry no `namespaces` segment they require a
**wildcard-scoped** (`*:*:*`) token — governance authoring is admin-only by
construction in Phase 1.

```
POST /v1/{prefix}/governance/tags                 {namespace, name, allowed-values?}
POST /v1/{prefix}/governance/object-tags          {object-kind, schema, object?, column?, tag-namespace, tag-name, value?}
POST /v1/{prefix}/governance/masking-policies      {name, signature, body}
POST /v1/{prefix}/governance/row-access-policies   {name, signature, body}
POST /v1/{prefix}/governance/policy-attachments    {policy-kind, policy-name, target-kind, tag-namespace?, tag-name?, schema?, object?, column?, columns?}
POST /v1/{prefix}/governance/roles                 {name}
POST /v1/{prefix}/governance/role-grants           {role, principal}
POST /v1/{prefix}/governance/object-grants         {object-kind, schema, object?, privilege, role}
GET  /v1/{prefix}/governance/effective-policies?table=schema.table&principal=sub
GET  /v1/{prefix}/governance/audit?limit=200
```

`object-kind` ∈ `{schema, table, view, column}`; `policy-kind` ∈
`{masking, row_access}`; `target-kind` ∈ `{tag, column, table}`.

## JWT roles

Clients can be configured with governance roles, surfaced in the token's
`roles` claim (a JSON array). Phase 1 only carries them; Phase 2's policy
engine reads them to decide masking.

```
# env grammar: id:secret|scope|roles   (scope + roles both optional)
DUCKICELAKE_OAUTH_CLIENTS="agent:s3cr3t|ns:analytics:r|agent"

# clients file: {"agent": {"secret": "...", "scope": "...", "roles": ["agent"]}}
```

## Try it

```bash
P=/v1/lake/governance
curl -X POST localhost:8181$P/tags                -d '{"namespace":"pii","name":"email"}' -H 'content-type: application/json'
curl -X POST localhost:8181$P/object-tags         -d '{"object-kind":"column","schema":"analytics","object":"events","column":"email","tag-namespace":"pii","tag-name":"email"}' -H 'content-type: application/json'
curl -X POST localhost:8181$P/masking-policies    -d '{"name":"mask_email","signature":"(val VARCHAR)","body":"'\''***'\''"}' -H 'content-type: application/json'
curl -X POST localhost:8181$P/policy-attachments  -d '{"policy-kind":"masking","policy-name":"mask_email","target-kind":"tag","tag-namespace":"pii","tag-name":"email"}' -H 'content-type: application/json'
curl -X POST localhost:8181$P/roles               -d '{"name":"agent"}' -H 'content-type: application/json'
curl -X POST localhost:8181$P/role-grants         -d '{"role":"agent","principal":"agent-1"}' -H 'content-type: application/json'

curl "localhost:8181$P/effective-policies?table=analytics.events&principal=agent-1"
curl "localhost:8181$P/audit"
```

## Not yet implemented (Phase 2+)

- **Phase 2** — Iceberg REST enforcement: thread principal claims into
  `_build_load_response`, schema-rewrite / view-fallback masking, Trino/Spark
  property fast-path, STS vending tightening (`policies.py`).
- **Phase 3** — DuckLake-direct enforcement: Postgres RLS on
  `ducklake_table`/`_column`/`_data_file` + credential gating.
- **Phase 4** — pre-masked physical files (airtight, 2× storage).
- **Phase 5** — LLM-agent surface (`agent` role, `lakesh mcp --as agent`).
