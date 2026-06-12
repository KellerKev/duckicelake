# Governance layer (experimental)

Snowflake-style tagging + RBAC + masking for duckicelake. The design and
phasing live in [`duckicelake_governance.md`](duckicelake_governance.md).
This document tracks what is **actually implemented** on the
`experimental_governance` branch.

> **Status: Phases 1 + 2 + 3 + 3a + 4.** Phase 1 = authoring surface +
> audit. Phase 2 = Iceberg REST enforcement at LoadTable (per-principal
> column masking + row filter signals, audited). Phase 3 = ad-hoc masking
> views executed by both read paths + the DuckLake-direct credential
> endpoint. Phase 3a = per-principal PG reader roles + RLS on the
> `ducklake_*` catalog tables. Phase 4 = **file-layer masking**: policies
> flagged `file-layer-masking` are materialized as masked Parquet, with
> masked-prefix-only credentials and shadow Iceberg metadata — byte-level
> enforcement for every engine that reads Parquet directly. The LLM-agent
> surface (Phase 5) is not yet built.

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

## What Phase 2 ships — Iceberg REST enforcement

| Piece | Where |
|---|---|
| Policy engine: per-principal plan, view-SQL generation, metadata stamping | [src/duckicelake/policies.py](src/duckicelake/policies.py) |
| LoadTable enforcement (read path) threading principal claims | `_build_load_response` in [server.py](src/duckicelake/server.py) |
| `unmasked_roles` bypass on masking / row-access policies | [governance.py](src/duckicelake/governance.py) |
| STS vending: principal-stamped session names | [sts.py](src/duckicelake/sts.py) |

**How enforcement is decided.** At `GET LoadTable` the proxy reads the
caller's claims (`sub` + `roles`), asks the `PolicyEngine` for the table's
plan, and stamps the returned metadata. The bypass is **declarative**: a
principal holding any role in a policy's `unmasked-roles` sees unmasked data.
This replaces evaluating Snowflake's `CURRENT_ROLE()` in the policy body —
the body is used purely as the masked-value / filter expression.

**What gets stamped** (per masked principal):

- Column `doc` annotation on every masked field (universal "this is governed" signal).
- `duckicelake.masked-columns` = comma-list; `duckicelake.mask.<col>` = the masked SQL expression.
- `duckicelake.row-filter` **and** `iceberg.row-filter` (the Trino/Spark fast-path key) when a row policy applies.
- `duckicelake.masking-view-sql` — the `SELECT` a PyIceberg/DuckDB deployment materialises as an Iceberg view for byte-level masking.
- One `load_table` row in the audit trail recording the masked columns + applied policies.

**Honest enforcement limits (by engine).** An Iceberg REST client reads the
Parquet bytes itself, so editing metadata cannot mask bytes on its own:

- **Trino / Spark** — honor the `iceberg.row-filter` + column-mask properties → real enforcement.
- **PyIceberg / DuckDB** — ignore those properties; byte-level masking needs the emitted view SQL materialised as an Iceberg view, or pre-masked files (Phase 4). Phase 2 emits the view SQL + annotations; wiring the view-materialisation round-trip is the remaining Phase 2→3 step.
- **STS** — sessions are now principal-stamped for MinIO audit. Coarse credential withholding for masked principals is file-granularity and lands with Phase 4.

Enforcement is **read-path only** (`GET LoadTable`); create/commit responses
are unchanged. It is fully defensive — any error in the policy engine logs
and serves unmasked rather than failing the read.

## What Phase 3 ships — ad-hoc masking views (both read paths)

| Piece | Where |
|---|---|
| `MaskingViewManager`: materialization, transparent schemas, GC | [src/duckicelake/masking_views.py](src/duckicelake/masking_views.py) |
| `mask_signature` (per-table mask-shape identity) | [src/duckicelake/policies.py](src/duckicelake/policies.py) |
| LoadTable view materialization + `duckicelake.masking-view-name` stamp | `_build_load_response` in [server.py](src/duckicelake/server.py) |
| `GET …/ducklake-credentials` vending endpoint | [server.py](src/duckicelake/server.py) |
| Prefix-scoped read-only STS (`read_prefixes`) | [src/duckicelake/sts.py](src/duckicelake/sts.py) |
| `search_path` transparency probe | [scripts/probe_searchpath.py](scripts/probe_searchpath.py) |
| Tests | [tests/test_governance_phase3.py](tests/test_governance_phase3.py) |

**The primitive.** One physical DuckLake view per (table, mask-signature):
`__mask_{table}__{sig}` in the base table's namespace. The signature hashes
the effective mask shape — masked columns + expressions, row filter, base
column set, table identity — so principals with the same effective mask
share one view, and an `ADD/DROP COLUMN` or policy edit automatically rotates
to a fresh view (stale ones are garbage-collected on schema change). The
stored SQL keeps the base table reference unqualified, so a DuckLake-direct
client resolves it against its own attached catalog. Row filters are applied
in a nested subquery, so they see **raw** column values (Snowflake row-policy
semantics) and never collide with mask aliases.

**Iceberg REST path.** A masked LoadTable materializes the caller's view and
advertises it via the `duckicelake.masking-view-name` table property (all
Phase 2 stamping unchanged). View-capable engines (PyIceberg / Trino / Spark)
load it at `GET …/views/__mask_{table}__{sig}` and execute the mask
themselves. The DuckDB `iceberg` extension has **no view support** — steer
DuckDB users to the DuckLake-direct path below.

**DuckLake-direct path.**

```
GET /v1/{prefix}/namespaces/{ns}/ducklake-credentials?table=events
```

returns everything a DuckLake-direct DuckDB session needs:

```jsonc
{
  "ducklake_dsn": "...", "ducklake_data_path": "s3://lakehouse/data/",
  "ducklake_attach_sql": "ATTACH 'ducklake:postgres:...' AS lake (DATA_PATH '...')",
  "post_attach_sql": ["SET search_path = 'lake.__masked_<sig>,lake.<ns>'"],
  "masked_view": "<ns>.__mask_events__<sig>", "mask_signature": "<sig>",
  "transparent": true,
  "s3": { "endpoint": "...", "access-key-id": "...", "secret-access-key": "...",
          "session-token": "...", "expiration": "..." }
}
```

- The S3 creds are **read-only and prefix-scoped to the table's data path**
  (namespace path when `?table` is omitted) — prefix, not per-file, so files
  committed after vending stay readable for the session's lifetime; clients
  re-fetch on `expiration`.
- A client that runs `post_attach_sql` gets masking **transparently**: DuckDB's
  `SET search_path` resolves unqualified names through a `__masked_{sig}`
  schema holding a view named exactly like the table (probe-verified; the
  libpq `options=-c search_path` DSN trick does *not* work — it sets the
  Postgres session path, not DuckDB's binder). Opt out with
  `DUCKICELAKE_TRANSPARENT_MASKING=0`; the by-name `masked_view` always works.
- GET + namespace-scoped path, so a read-only `ns:r` token (the LLM-agent
  shape) passes the bearer middleware. When auth is off, a `principal` query
  param is honored for dev/test (same precedent as `effective-policies`).
- Vending decisions are audited as `operation=ducklake_credentials` with
  `decision` ∈ `{ok, masked, error_unmasked, error_no_creds}`.

**Roles are unioned.** Enforcement paths use the union of the JWT `roles`
claim (operator-configured via `DUCKICELAKE_OAUTH_CLIENTS`) and the sidecar
role grants. `effective-policies` remains store-only — it inspects arbitrary
principals by name and cannot know their JWT claims, so it may under-report
roles for JWT-only principals.

**Hygiene.** `__mask_*` views and `__masked_*` schemas are reserved prefixes
(user creation → 400) and are hidden from REST `list_views` /
`list_namespaces`; they remain loadable/droppable by name. DuckLake-direct
clients still see them in PG — that visibility is inherent. Per-table opt-out:
set table property `duckicelake.masking-disabled=true` to skip view
materialization.

**The boundary — read this.** The masking *views* are **cooperative-client
masking**: the view computes the mask in the *client's* engine, which must
read the raw base bytes. Consequences:

- Response configs **omit the root MinIO key pair by default**
  (`suppress_root_creds`, settable via env / `.env` / `duckicelake.toml`);
  clients rely on vended creds. Only flip it off for dev stacks that don't
  care about the masking boundary.
- The PG side is hardened by Phase 3a below (per-principal reader roles +
  RLS); byte-level enforcement for masked columns is Phase 4 (file-layer
  masking, pre-masked Parquet).

Everything stays **fail-open**: any governance error on either path logs,
serves unmasked, and audits the failure — it never breaks a read.

## What Phase 3a ships — PG reader roles + RLS on the DuckLake catalog

| Piece | Where |
|---|---|
| Reader group + per-principal roles, predicate functions, RLS policies | [src/duckicelake/pg_rls.py](src/duckicelake/pg_rls.py) |
| Startup `ensure_rls` + reader-DSN vending | [server.py](src/duckicelake/server.py) (lifespan + ducklake-credentials) |
| `duckicelake_pg_principal` sidecar (pg_role → principal) | created by `ensure_rls` |

`ducklake-credentials` no longer vends the owning PG role. Each principal
gets its own LOGIN role `duckicelake_p_<sub>_<sha8>` — member of the NOLOGIN
group `duckicelake_reader` that carries all SELECT grants and is the target
of every RLS policy — with a random per-vend password (returned once, never
persisted; PG keeps the SCRAM verifier) and `VALID UNTIL` aligned to the STS
expiry. The ATTACH statement is `READ_ONLY`. RLS predicates resolve the
principal from `session_user` via the sidecar — unforgeable after
authentication. Expired roles are lazily NOLOGIN'd, then dropped.

**Visibility model (v1).** Default-ALLOW — an ungoverned lake behaves as
before. An explicit `select` **object-grant** (on the table or its schema)
flips that table to allowlist: visible only to principals holding a granted
role. File rows (`ducklake_data_file` & friends) are additionally hidden when
the table carries `duckicelake.file-layer-masking=true` and the principal
holds none of `duckicelake.file-layer-bypass-roles` — the **Phase-4
interlock**, dormant until file-layer masking sets those properties. Plain
masking policies never hide files: the Phase-3 view executes against the base
table in the client's engine, so hiding its files would break exactly the
principals the view serves. No per-column hiding in v1 (it would break the
views' binder). RLS is never `FORCE`d — the proxy's owning connection
bypasses it.

**Limits, stated honestly:**

- **Dev trust-auth cannot enforce authentication.** The pixi stack is
  `initdb --auth=trust` on a unix socket: any local process can connect as
  any role, including the owner. The predicates are fully exercised and
  tested; the *authentication* only becomes real under production auth:

  ```
  # postgresql.conf: password_encryption = scram-sha-256, TLS on
  # pg_hba.conf (order matters):
  hostssl ducklake ducklake             <proxy-host>/32  scram-sha-256  # owner: proxy only
  host    ducklake ducklake             0.0.0.0/0        reject
  hostssl ducklake +duckicelake_reader  <client-cidr>    scram-sha-256  # all vended principals
  ```

  The proxy's prod role: non-superuser owner of the `ducklake_*` tables with
  `CREATEROLE` (PG ≥ 16 auto-grants ADMIN on roles it creates).
- **Data inlining is incompatible with the vended reader path.** Dynamic
  `ducklake_inlined_data_*` payload tables carry raw rows with nothing to
  police, so readers get no grant on them (verified live: granting them
  bypasses every predicate). Write DuckLake-direct with
  `DATA_INLINING_ROW_LIMIT 0` (the proxy's REST path never inlines).
- Each vend mints its own nonce-suffixed role (`duckicelake_p_<sub>_<sha8>_<nonce>`)
  with its own password + `VALID UNTIL`, so concurrent vends for one
  principal never invalidate each other's just-returned secret; all map to
  the same principal and are GC'd by expiry. `VALID UNTIL` is checked at
  connect time only (same semantics as STS expiry).
- `ducklake_snapshot_changes` is **not granted** to readers — its
  `changes_made` column embeds qualified table names, which would leak the
  existence of allowlist-hidden tables. Consequence: vended readers can't
  call `lake.snapshots()` (time-travel introspection); normal reads are
  unaffected.
- `ducklake_view` is not row-filtered in v1: masking-view SQL bodies (and
  views referencing hidden tables) remain enumerable by readers. Tracked
  as follow-up hardening.

## What Phase 4 ships — file-layer masking (byte-level, every engine)

| Piece | Where |
|---|---|
| Masked Parquet exporter (per table + mask-signature), refresh, GC | [src/duckicelake/masked_export.py](src/duckicelake/masked_export.py) |
| `file-layer-masking` policy flag | [governance.py](src/duckicelake/governance.py) / [governance_api.py](src/duckicelake/governance_api.py) |
| Shadow Iceberg metadata + read-only masked STS at LoadTable | [server.py](src/duckicelake/server.py) `_build_load_response` |
| Masked-prefix credential vending + IAM Deny carve-outs | [server.py](src/duckicelake/server.py) / [sts.py](src/duckicelake/sts.py) |
| Eager refresh on every DuckLake commit | [notify.py](src/duckicelake/notify.py) |
| Tests | [tests/test_governance_phase4.py](tests/test_governance_phase4.py) |

**Why it exists (researched before building).** No alternative gives
byte-level column masking to engines that read Parquet directly: DuckDB has
no per-column Parquet encryption (`column_keys` unsupported, no roadmap) and
no Iceberg REST scan-planning client (open issue) — and scan planning could
only *point* engines at files, which still requires masked files to point
at. STS/RLS can deny, not transform. Pre-masked copies are the only
mechanism; the cost is storage.

**How.** Set `"file-layer-masking": true` on a masking policy. For each
(table, mask-signature) some principal actually requests, the proxy COPYs a
**current-state export** — mask expressions and row filter applied,
position/equality deletes resolved by construction, Iceberg field-ids
stamped — to:

```
{data_prefix}__masked__/{ns}/{table}/{sig}/snap-{N}-{tok}/part-*.parquet
```

The sig prefix is the credential boundary. Each DuckLake commit eagerly
re-exports recently-requested sigs (notify listener) and atomically
repoints the masking views; clients glob one immutable snap dir and never
see a half-written state (retention keeps current + previous;
`DUCKICELAKE_MASKED_RETAIN_SNAP_DIRS`).

**Both read paths get masked bytes:**

- *DuckLake-direct*: the `__mask_{table}__{sig}` view becomes
  `SELECT * FROM read_parquet('s3://…/{sig}/snap-N-…/*.parquet')`; vended
  creds cover **only** the masked sig prefix → base bytes are physically
  403. Namespace-level vends carve file-layer tables' base prefixes out
  with IAM Deny. The Phase-3a interlock properties are stamped, so RLS also
  hides base file rows — the base table reads as *empty* even by name.
- *Iceberg REST*: LoadTable returns **shadow metadata** — a real
  metadata.json + manifests built over the export (single snapshot, no
  deletes, no stats) — plus read-only masked-prefix STS. Every Iceberg
  reader, including the DuckDB `iceberg` extension (no views, no scan
  planning), transparently scans masked bytes. Bypass-role principals keep
  base metadata and the normal vend.

**Boundaries and behavior:**

- Masked principals lose time travel (current-state export) — by design;
  historic snapshots predating a policy are themselves a leak vector.
- Policies whose expressions depend on the session (`current_user`, …)
  are refused for export (the exporter's identity must not freeze into
  bytes) — they fall back to catalog-level masking.
- Storage: +1 table copy per active mask-signature (×2 transiently during
  repoint); every commit on a flagged table re-exports each live sig —
  size parts via `DUCKICELAKE_MASKED_EXPORT_FILE_SIZE`, idle sigs age out
  after `DUCKICELAKE_MASKED_EXPORT_TTL_DAYS`.
- Fail-open as always: export or shadow-metadata failure degrades to
  catalog-level masking (audited `error_file_layer_fallback`); decisions
  are audited as `masked_file_layer` / `operation=masked_export`.
- Schema changes and DROP TABLE purge exports; signatures fold the column
  set, so the next masked read rebuilds at the new shape.

## REST surface

All under `/v1/{prefix}/governance` (prefix = catalog name, default `lake`).
Authoring routes live under `/v1/` so the existing bearer-auth middleware
gates them; because the paths carry no `namespaces` segment they require a
**wildcard-scoped** (`*:*:*`) token — governance authoring is admin-only by
construction in Phase 1.

```
POST /v1/{prefix}/governance/tags                 {namespace, name, allowed-values?}
POST /v1/{prefix}/governance/object-tags          {object-kind, schema, object?, column?, tag-namespace, tag-name, value?}
POST /v1/{prefix}/governance/masking-policies      {name, signature, body, unmasked-roles?, file-layer-masking?}
POST /v1/{prefix}/governance/row-access-policies   {name, signature, body, unmasked-roles?}
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

## Not yet implemented

> Naming note: the phase numbering here follows
> [`duckicelake_governance.md`](duckicelake_governance.md). The implemented
> ad-hoc-views phase was planned in a file named `governance_phase2.md`, but
> it is **Phase 3** in this numbering (its credential-gating half), built
> before the PG-RLS half.

- **Phase 5** — LLM-agent surface (`agent` role, `lakesh mcp --as agent`).
- A per-principal aggregated transparent schema (one `SET search_path` entry
  covering *all* of a principal's masked tables) — today transparent mode is
  per-table.
- Listener-side export debounce for hot-write file-layer tables (today:
  one re-export per commit per live sig).
