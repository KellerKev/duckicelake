# Brainstorm: Snowflake-style tagging + RBAC + masking on duckicelake

## Context

User asked: can we introduce data tagging / classification with tag-based
column masking + row access policies, modeled on Snowflake, applied to
**both** Iceberg REST clients **and** DuckLake-direct clients (DuckDB
sessions ATTACHing `ducklake:`). Specifically interested in LLM-agent
use cases — keep agents from seeing PII while letting humans-via-same-
API see everything.

The brainstorm is the deliverable here. Implementation is staged so the
user can pick a phase to actually build.

## What Snowflake actually provides (the target shape)

Three orthogonal primitives that compose:

1. **Object tags** — `(namespace, name, allowed_values?)`. Assigned to
   schemas / tables / views / columns. Hierarchical: a tag on a schema
   cascades to its tables and columns unless overridden. Tags are
   strings; the security value is the *consistency* they impose ("every
   column holding email PII is tagged `pii.email`").
2. **Masking policies** — named SQL UDFs: `(val TYPE [, args…]) RETURNS
   TYPE`. Body inspects `CURRENT_ROLE()` / `CURRENT_USER()` and returns
   either `val` or a masked variant. Attached to a column directly *or*
   to a tag (which transitively masks every column with that tag).
3. **Row access policies** — named SQL UDFs: `(col_a TYPE, col_b TYPE…)
   RETURNS BOOLEAN`. Body checks the row + role; `true` keeps the row.
   Attached to a table on `(column-list)`. Engine adds the predicate to
   every scan.

Roles + grants tie principals to "can see unmasked" via the policy
bodies, not via a separate ACL system.

The valuable property: **policies live next to the data, applied
uniformly across every engine that respects the catalog**. That's
exactly what's broken about a proxy-only approach if any client can
bypass the proxy.

## Where duckicelake stands today

(from exploration — file:line citations preserved)

- **Identity is thin**. JWT carries `sub` + `scope` only
  ([auth.py:150-157](src/duckicelake/auth.py#L150)). No roles, groups,
  or custom claims.
- **Principal is middleware-only**, never reaches handlers
  ([server.py:149-176](src/duckicelake/server.py#L149)). Adding a
  FastAPI dependency that exposes claims into `load_table()` etc. is
  cheap.
- **Sidecar pattern is established** — `duckicelake_*` tables created
  on-demand ([catalog.py:904](src/duckicelake/catalog.py#L904)). New
  sidecars for tags / policies / grants fit the convention without
  ceremony.
- **STS vending is per-file path-scoped** ([sts.py:37-102](src/duckicelake/sts.py#L37))
  — coarse but real. Today the demo hands clients root keys; production
  must vend per-principal STS only.
- **Iceberg views ARE implemented** ([catalog.py:1779-1784](src/duckicelake/catalog.py#L1779))
  — viable masking vector (return a masked view instead of base table).
- **No row-filter / column-mask property is referenced anywhere** in
  the codebase. Clean slate.
- **DuckLake-direct clients bypass everything** — they ATTACH
  `ducklake:postgres:` with raw PG + S3 creds.

## The honest enforcement matrix

| Surface | Iceberg REST clients (PyIceberg, Trino, Spark, DuckDB iceberg-ext) | DuckLake-direct clients (DuckDB ducklake-ext) |
|---|---|---|
| **Column masking via schema rewrite at LoadTable** | Works for every engine (they all read the returned schema). | **Bypassed** — clients read `ducklake_column` from PG directly. |
| **Column masking via Iceberg view** | Works on engines that handle views (PyIceberg/Trino/Spark do; DuckDB iceberg-ext partial). | **Bypassed** — `ducklake.events` is the base table, not the view. |
| **Row filter via `iceberg.row-filter` property** | Trino + Spark honor; PyIceberg + DuckDB iceberg-ext ignore. | **Bypassed**. |
| **Row filter via view** | Same as column masking via view. | **Bypassed**. |
| **STS scope reduction** (refuse creds to files containing classified columns) | Works for any engine that uses our vended creds — *iff* root keys are not in client hands. | Works iff DuckLake-direct clients also fetch creds from the proxy (i.e. no root keys distributed). |
| **PG row-level security on `ducklake_data_file`** | N/A (proxy doesn't go through this) | **Works** — DuckDB ducklake-ext queries `ducklake_data_file` to discover files; if PG hides rows the client never sees those files. |
| **Pre-masked physical files** (write a redacted copy at write time) | Works for any reader, any engine, any access path. | Works. **Expensive** + only at file granularity. |

The standout insight: **PG row-level security on `ducklake_data_file`
+ `ducklake_column`** is the only mechanism that catches DuckLake-direct
clients with similar leverage to what schema rewrites give us for REST
clients. It's the missing leg.

## Proposed phased build

### Phase 1 — Governance objects (foundation; no enforcement yet)

Snowflake-shaped vocabulary, sidecar-backed. Just authoring + audit;
nothing is enforced.

**New sidecars** ([catalog.py:904](src/duckicelake/catalog.py#L904)
pattern):

```
duckicelake_tag                 -- tag definitions (ns, name, allowed_values?)
duckicelake_object_tag          -- (object_kind, schema, name, column?, tag_ns, tag_name, tag_value)
duckicelake_masking_policy      -- (name, signature_sql, body_sql)
duckicelake_row_access_policy   -- (name, signature_sql, body_sql)
duckicelake_policy_attachment   -- attach policy to a tag, or to (table, column), or to (table, [cols])
duckicelake_role                -- (role_name)
duckicelake_role_grant          -- (role_name, principal_sub)        # which principals hold the role
duckicelake_object_owner        -- (object_kind, schema, name, role_name)
duckicelake_object_grant        -- (object_kind, schema, name, privilege, role_name)
duckicelake_governance_audit    -- (ts, principal_sub, operation, object, decision, masked_cols, applied_policies)
```

**REST surface** (Snowflake CLI-shaped):

```
POST   /v1/{prefix}/governance/tags
POST   /v1/{prefix}/governance/object-tags
POST   /v1/{prefix}/governance/masking-policies
POST   /v1/{prefix}/governance/row-access-policies
POST   /v1/{prefix}/governance/policy-attachments
POST   /v1/{prefix}/governance/roles
POST   /v1/{prefix}/governance/role-grants
POST   /v1/{prefix}/governance/object-grants
GET    /v1/{prefix}/governance/effective-policies?principal=…&table=…
```

**JWT extension** — add `roles: string[]` claim ([auth.py:150-157](src/duckicelake/auth.py#L150)).
Validation reuses existing scope mechanism; roles are checked by the
policy engine in Phase 2.

**Audit log already partly designed** — already noted in
[MISSING.md](MISSING.md) under observability. Wire it now so Phase 1
ships a useful artefact (operators can see who tagged what) even before
enforcement.

End of Phase 1: catalog has a complete governance model authoring
surface + audit trail. Zero enforcement. Useful for compliance review
and as the foundation for Phases 2/3.

### Phase 2 — Iceberg REST enforcement (schema rewrite + view fallback)

Threads principal claims into `_build_load_response`
([server.py:1162](src/duckicelake/server.py#L1162)). Adds a policy
engine module `src/duckicelake/policies.py`:

- **Column masking**: at LoadTable, walk each column's effective tags →
  attached masking policies. If policy applies (principal's roles
  miss the unmasked clause), rewrite the column's `type` in the
  returned schema:
  - Static masks (`NULL`, `'***'`, `LEFT(val,2) || '***'`) — replace
    the literal in the column's Iceberg `doc` so engines surface "this
    is masked"; for actually replacing the rendered bytes, use the view
    fallback (next bullet) since Iceberg readers fetch bytes themselves.
  - UDF masks — must use the view fallback; schema rewrite alone
    can't apply a function to the bytes.
- **View fallback**: when a policy needs computation (UDF mask, row
  filter on non-Trino engines), the catalog synthesises a per-principal
  view `events__masked_for_role_<role>` in DuckDB and returns its
  metadata instead of the base table. PyIceberg + DuckDB iceberg-ext
  both honor Iceberg views ([catalog.py:1779](src/duckicelake/catalog.py#L1779)).
- **Trino/Spark fast-path**: set `iceberg.row-filter` and the
  column-mask table properties in the returned metadata when the
  principal needs row/col masking. Saves a view round-trip on engines
  that honor the property.
- **STS vending tightens**: `vend_credentials()` ([sts.py:131](src/duckicelake/sts.py#L131))
  takes a principal arg; refuses to vend creds for files containing
  columns the principal can't see (per the policy engine) until those
  columns are physically pre-masked (Phase 4).

End of Phase 2: every Iceberg REST client respects column/row policies
within the limits of what its engine honors. Trino/Spark do
property-based; PyIceberg/DuckDB do view-based. Audit log records the
masking decision per LoadTable.

### Phase 3 — DuckLake-direct enforcement (PG RLS + cred gating)

The hard one. Two prongs that compose:

**3a. PG row-level security on the DuckLake catalog tables.** Create a
distinct PG role `duckicelake_ducklake_reader` that DuckLake-direct
clients must connect as (root role becomes operator-only). Apply RLS
to `ducklake_table`, `ducklake_column`, `ducklake_data_file`:

```sql
CREATE POLICY rls_table_visibility ON public.ducklake_table
  FOR SELECT
  USING ( duckicelake_principal_can_see_table(table_id) );
```

`duckicelake_principal_can_see_table()` is a Postgres function backed
by the Phase 1 sidecars. The principal id is set per session via
`SET LOCAL duckicelake.principal = '<sub>'` (proxy injects this when
vending the PG connection string; clients can't override).

Effect: a DuckLake-direct client whose principal lacks a role can't
even *see* the table in `ducklake_table`. Whole columns can be hidden
via RLS on `ducklake_column`. Whole files can be hidden via RLS on
`ducklake_data_file`. **Row masking is still impossible** at this layer
— rows live in Parquet, not PG.

**3b. Cred gating.** Production must not distribute the demo's root
S3 keys. The proxy becomes the *only* dispenser of S3 creds (REST and
DuckLake-direct both fetch). DuckLake-direct clients call a new
endpoint `POST /v1/{prefix}/ducklake/credentials` returning a PG DSN
template (with the principal-scoped role) + STS S3 creds. Document in
MISSING.md that "raw root key distribution" is the prod no-go.

End of Phase 3: DuckLake-direct clients are capped at "table /
column / file visibility per principal". Row-level enforcement on
direct clients is honestly best-effort (column-mask at file split is
the closest, see Phase 4).

### Phase 4 — Pre-masked physical files (the airtight option)

For the truly sensitive case (LLM agents must never see PII bytes):
on write, the catalog produces *two* Parquet copies — full + masked —
under separate S3 prefixes. The policy engine vends only the masked
prefix to principals without unmasked roles, *regardless of engine or
access path*. Expensive (2x storage on classified tables) but the only
mechanism that survives a determined client with raw PG access.

Hook point: the eager materialisation listener
([notify.py](src/duckicelake/notify.py) — already built) is the right
place. Every commit it sees, it consults the policy engine; if any
column on the table has an active masking policy that requires
pre-redaction, it writes the masked variant alongside the original.

Recommend gating Phase 4 behind a per-table property — most tables
shouldn't pay for it.

### Phase 5 (longer term) — LLM-agent specific surface

Specifically for the user's "agents see safe view, humans see
everything via the same API" goal:

- New `agent` role with deny-by-default tag→mask attachments for
  common PII taxonomies (`pii.*`, `phi.*`, `secrets.*`).
- `lakesh mcp` ([the companion repo](https://github.com/KellerKev/lakesh))
  already has the MCP-server primitive. Add a `lakesh mcp --as agent`
  flag that always uses the `agent` role JWT, so admins can't
  accidentally configure an unsafe MCP server. Audit every MCP-driven
  query with the `agent` principal stamped.
- Document: "any LLM-accessible client should authenticate with a role
  that has the `pii.*` tag-policy attachment", so the configuration
  story is "give the agent a role, the tags do the rest". Snowflake's
  own story.

## What I do NOT recommend

- **Bolting an ACL-only RBAC system in parallel to the tag-based
  policy model.** Pick the tag-based model; explicit per-column ACLs
  are an escape hatch but should not be the default. Snowflake learned
  this; the tag model wins on hygiene.
- **Rewriting the manifest list per principal.** Considered. Doesn't
  work — clients can fetch the underlying Parquet by URL once they have
  any manifest reference. Manifest rewriting is brittle and bypassable.
- **A whole separate catalog-instance-per-role.** Multi-tenancy at the
  catalog level is a real ops nightmare; in-catalog policies are
  drastically lighter.

## Critical files / reuse opportunities

| Need | Existing | Location |
|---|---|---|
| Sidecar DDL pattern | `_ensure_sidecar` | [catalog.py:904](src/duckicelake/catalog.py#L904) |
| Principal middleware | `bearer_auth_middleware` | [server.py:149](src/duckicelake/server.py#L149) |
| LoadTable assembly | `_build_load_response` | [server.py:1162](src/duckicelake/server.py#L1162) |
| Iceberg view emission | (catalog view path) | [catalog.py:1779](src/duckicelake/catalog.py#L1779) |
| STS vending | `vend_credentials` | [sts.py:131](src/duckicelake/sts.py#L131) |
| Schema build | `build_table_metadata` | [iceberg.py:46](src/duckicelake/iceberg.py#L46) |
| Materialise hook | `notify._materialise_snapshot` | [notify.py](src/duckicelake/notify.py) |

## Verification (would apply once a phase is built)

- **Phase 1**: create tag + policy via REST; query
  `duckicelake_governance_audit` to confirm authoring is logged; query
  `GET /v1/.../governance/effective-policies` to show derived policy
  set for a principal.
- **Phase 2**: same DuckLake-direct INSERT as the existing
  [tests/test_notify_materialise.py](tests/test_notify_materialise.py),
  then `LoadTable` as principal A (sees all columns) vs principal B
  (sees masked email). PyIceberg scan of both confirms physical
  byte-difference between the responses.
- **Phase 3**: connect to PG as `duckicelake_ducklake_reader` with
  `SET duckicelake.principal = '<sub-without-pii-role>'` and confirm
  `SELECT * FROM ducklake_column WHERE table_id = X` returns fewer
  rows than as a privileged principal. DuckLake-direct `SELECT *`
  through this session physically can't see the masked columns.
- **Phase 4**: on a commit that mutates a tagged column, verify two
  Parquet files appear under separate S3 prefixes; verify principal
  scope vending refuses the unmasked prefix to a non-privileged
  principal.

## Recommended path

**Build Phase 1 first** — it's pure foundation, zero risk to existing
behaviour, gives you a complete Snowflake-shaped authoring surface +
audit trail. Six new sidecars + their REST endpoints + JWT `roles`
claim.

**Then Phase 2** for Iceberg REST enforcement. Gets you "LLM agents
authenticating with the `agent` role see masked columns" through any
PyIceberg/Trino/Spark/DuckDB client that uses the REST catalog.

**Phases 3+ when DuckLake-direct hardening becomes the bottleneck.**
Until then, gate DuckLake-direct in production by simply not handing
out its connection details to untrusted clients.

This phasing avoids the trap of building airtight enforcement
(Phase 4) before there's a model to express what to enforce
(Phases 1-2). Each phase is independently shippable.
