# Governance — Next phase: make DuckDB honor masking on both read paths (ad-hoc views)

> Naming note: this is the **next** governance phase to build. In the
> GOVERNANCE.md phase numbering it's "Phase 3" (Phases 1–2 — authoring +
> Iceberg-REST property stamping — are already implemented on
> `experimental_governance`). Saved here as `governance_phase2.md` per request.

## Context

Phases 1–2 (branch `experimental_governance`) gave us a governance model
(tags, masking/row policies, roles) and Phase-2 enforcement that *stamps*
per-principal masking signals into the Iceberg `LoadTable` metadata. But
those signals are **advisory**: DuckDB reads Parquet bytes directly through
both its `iceberg` and `ducklake` extensions and ignores them, so an LLM
agent / BI tool querying via DuckDB still sees raw PII.

This phase makes DuckDB actually return masked rows, using **Snowflake-Horizon-style
ad-hoc masking views** — a DuckLake `VIEW` that embeds the policy's mask SQL.

**Confirmed constraints (researched):**
- DuckLake supports `CREATE VIEW` natively; it persists to the Postgres
  `ducklake_view` table and the DuckDB **`ducklake`** extension executes it.
  → a DuckLake-direct client running the view gets masked rows. ✅
- The DuckDB **`iceberg`** extension does **not** support Iceberg view
  objects (tables only). PyIceberg / Trino / Spark do. → DuckDB-over-REST
  cannot be masked by a view; it keeps the Phase-2 advisory properties and
  is steered to the DuckLake-direct path. (Documented gap.)
- A view computes the mask in the **client's** engine, which must read the
  raw base bytes. So this is **cooperative-client masking** (agents, BI,
  lakesh) — a determined client with direct catalog+S3 creds can bypass it.
  Airtight masking (pre-masked physical files) is an explicit **later tier**,
  out of scope here. This boundary must be documented.

**Decisions (user-confirmed):** ad-hoc views now (airtight later); build the
transparent DuckLake-direct credential endpoint (probe `search_path`, fall
back to returning the masked-view name).

## Approach

One new primitive — a **per-mask-signature DuckLake masking view** — reused
by both read paths. Reuse the existing `PolicyEngine` plan and
`build_masked_view_sql`; add materialization, a DuckLake-direct credential
endpoint, and Iceberg view-metadata serving. All enforcement stays
**fail-open** (errors → serve unmasked, never break a read), matching the
existing discipline at `server.py` `_build_load_response`.

Key grounding fact: `policies.build_masked_view_sql` emits
`SELECT … FROM "schema"."table"` **unqualified**, which is exactly what a
DuckLake-direct client needs (it resolves against its own attached DuckLake
catalog). Do **not** inject a catalog alias into the stored view SQL.

## Stages

### 0. Mask signature (pure) — `src/duckicelake/policies.py`
- Add `mask_signature(plan, column_set) -> str`: stable short sha256 hex over
  canonicalized `(sorted (col, mask_expr), row_filter, sorted base columns)`.
  Folding the base column-set in means an ADD/DROP COLUMN yields a fresh
  signature → fresh view automatically. Empty plan → `""` (no view).
- Principals with the same effective mask share one physical view.

### 1. View materialization primitive — `src/duckicelake/masking_views.py` (new)
`MaskingViewManager(catalog, policy_engine, settings)`:
- `ensure_view_for_plan(ns, table, plan) -> str | None`: empty plan → `None`;
  else `sig = mask_signature(...)`, name `__mask_{table}__{sig}` in the base
  table's namespace; idempotent (`catalog.view_exists` → return; else
  `catalog.create_view(ns, name, plan.view_sql, replace=True)` — pass
  `plan.view_sql` **as-is**). Wrap try/except → log + return `None`.
- `view_name_for_plan(ns, table, plan) -> str | None`: pure name (no DB).
- `gc_orphans(ns, table, keep: set[str])`: drop `__mask_{table}__*` views not
  in `keep` (best-effort).
- Reuses `catalog.create_view/view_exists/drop_view/list_views`
  (`catalog.py:1730–1789`).

### 2. Hook materialization into the read path — `src/duckicelake/server.py`
- Module-level `masking_view_manager = MaskingViewManager(...)` beside
  `policy_engine`/`governance_store`.
- In `_build_load_response`, inside the existing governance `try` (right after
  `apply_plan_to_metadata`): `name = masking_view_manager.ensure_view_for_plan(ns, table, plan)`
  and stamp `metadata.properties["duckicelake.masking-view-name"] = name` so
  cooperative clients can discover it. Keep all Phase-2 property stamping
  (Trino/Spark fast-path) unchanged.
- Standardize the role source: `_build_load_response` currently uses the JWT
  `roles` claim while `effective-policies` uses
  `governance_store.roles_for_principal(sub)`. Switch the read path to
  `roles_for_principal(sub)` (authoritative sidecar grants) so all paths agree.

### 3. DuckLake-direct transparent routing — `src/duckicelake/server.py` (+ catalog/sts reuse)
New `POST /v1/{prefix}/ducklake/credentials` (Bearer-gated by existing
middleware):
- `sub = claims_from_request(...).get("sub")`; `roles = governance_store.roles_for_principal(sub)`.
- Body `{namespace, table}` (optional, to pre-warm a table's view).
- `plan = policy_engine.plan_for(sub, roles, ns, table)`;
  `view = masking_view_manager.ensure_view_for_plan([ns], table, plan)`.
- S3 creds via `sts.vend_credentials(s3, namespace=ns, table=table,
  read_only=True, data_file_uris=<live base files>, principal=sub)` (reuse the
  read-only branch already in `_build_load_response`; the client needs raw
  base-file read to execute the view).
- Postgres DSN from `settings.pg_dsn` / `catalog._pg_conninfo()`. **Transparency
  probe gates the shape:** first run a one-time probe (script in Stage 6); if
  DuckDB honors `search_path` for unqualified relations against a DuckLake
  schema, also create a `__masked_{sig}` DuckLake schema holding a view named
  exactly `{table}` and return DSN with `options=-c search_path=__masked_{sig},{ns},public`
  (so `SELECT * FROM events` auto-masks). If the probe fails, return the
  explicit `masked_view` identifier (`{ns}.__mask_{table}__{sig}`) and
  `transparent=false`.
- Response: `{ducklake_dsn, ducklake_attach_uri, masked_view, mask_signature,
  transparent, s3:{endpoint,region,access-key-id,secret-access-key,session-token,expiration}}`.
- Audit via `governance_store.audit_load(..., operation="ducklake_credentials")`
  (add optional `operation`/`decision` kwargs to `audit_load`, default
  preserves current call sites).
- Fail-open: any governance error → return DSN + unmasked creds,
  `masked_view=null`, audit `decision="error_unmasked"`. Never 500.

### 4. Iceberg-REST path — `src/duckicelake/server.py`
- Thread `request: Request` into `load_view(...)` and decode claims (for
  audit/consistency); `_build_view_response` stays the metadata builder.
- For PyIceberg/Trino/Spark: the masking view is now materialized and
  loadable at `GET …/views/__mask_{table}__{sig}` (they execute it).
- Optional transparent `LoadTable→view` redirect for masked principals,
  gated **off** by default behind `DUCKICELAKE_MASK_REDIRECT_LOADTABLE`
  (returning `_build_view_response` instead of table metadata changes object
  type and can break clients). Property fast-path stays unconditional.
- Document the DuckDB-`iceberg` no-view gap in GOVERNANCE.md.

### 5. Safety / audit / gating
- All new read-path/credential logic wrapped → log + serve unmasked on error.
- Per-table opt-out property `duckicelake.masking-disabled=true` skips view
  materialization.
- `commit_table` schema-change branch: call `masking_view_manager.gc_orphans`
  after column add/drop (stale-signature cleanup); cache already invalidated.

### 6. Verification (isolated stack: proxy :8181, MinIO :9100, PG `./.pgsock`)
- **Probe first** — `scripts/probe_searchpath.py`: ATTACH DuckLake with
  `options=-c search_path=__masked_x,analytics`, create `__masked_x.events`
  view, check whether `SELECT * FROM events` resolves to it. Decides Stage-3
  transparent vs by-name.
- **`tests/test_governance_phase3.py`** (new, uses session proxy + in-process
  DuckDB):
  - Primitive idempotency: `ensure_view_for_plan` twice → one `ducklake_view`
    row, stable name; empty plan → `None`.
  - **DuckLake-direct proof (load-bearing):** author the demo policy via the
    `client` fixture; `POST /ducklake/credentials` as **bob** (no roles) and
    **alice** (`pii_reader`); ATTACH the returned DSN; bob's masked query →
    `al***`, alice → cleartext. Assert qualified `analytics.events` for bob
    still returns cleartext and document it as the cooperative boundary.
  - REST view metadata: `GET …/views/__mask_events__<sig>` returns the masking
    SQL; redirect flag on → view-shaped LoadTable, off → table + properties.
  - Invalidation: change `mask_email` body → new signature/view; `gc_orphans`
    drops the stale one.
- Update `scripts/lakesh_demo.sh` to call `POST /ducklake/credentials` and use
  the returned `masked_view`/transparent DSN, replacing the manual
  catalog-prefix rewrite hack.
- Re-run full suite (`pixi run pytest -q tests/`) — expect prior 32 + new.

### 7. Docs — `GOVERNANCE.md`
- New phase section: ad-hoc views, the credential endpoint, transparent
  routing, and the two explicit boundaries — cooperative-client masking (not
  airtight; pre-masked files are a later tier) and DuckDB-`iceberg` has no
  view support (steer DuckDB users to DuckLake-direct).

## Critical files
- `src/duckicelake/masking_views.py` (new) — materialization, signature, GC.
- `src/duckicelake/server.py` — read-path hook, `POST /ducklake/credentials`,
  `load_view` principal threading, redirect gate, role-source switch.
- `src/duckicelake/policies.py` — `mask_signature`; confirm unqualified view SQL.
- `src/duckicelake/governance.py` — `audit_load` `operation`/`decision` kwargs.
- `src/duckicelake/catalog.py` — reuse `create_view`/`view_exists`; helper for
  DSN-with-`search_path` + optional `__masked_{sig}` schema.
- `scripts/probe_searchpath.py` (new), `tests/test_governance_phase3.py` (new),
  `scripts/lakesh_demo.sh`, `GOVERNANCE.md`.

## Key risks
1. **`search_path` may not reroute DuckDB's catalog binder** (highest). Probe
   first; documented by-name fallback always works.
2. **Cooperative-only boundary** — shared `ducklake` PG role; a determined
   direct client can read the base table. Document; airtight = later phase.
3. **Orphan views** as signatures churn — `gc_orphans` + opportunistic cleanup.
4. **Materialization-listener concurrency** intermittently failing view column
   resolution — wrap + fail-open.
5. **LoadTable→view redirect** breaking clients — default off.

## Worktree / branch
Continue on `experimental_governance` (do not touch `main`). Commit per stage.

## Design-review corrections (applied during implementation)

A pre-implementation design review code-verified the draft and changed it in
these ways (the implementation follows this list where it conflicts with the
stages above):

1. **`search_path`-in-DSN replaced.** libpq `options=-c search_path=…` sets the
   *Postgres* session path (DuckLake metadata queries), not DuckDB's binder —
   it cannot reroute `SELECT * FROM events`. Transparent mode instead returns
   `post_attach_sql` (client-side `SET search_path = 'lake.__masked_{sig},lake.{ns}'`
   against a `__masked_{sig}` DuckLake schema holding a view named `{table}`).
2. **Endpoint moved** to `GET /v1/{prefix}/namespaces/{ns}/ducklake-credentials?table=…`:
   the drafted `POST /v1/{prefix}/ducklake/credentials` 403s every
   namespace-scoped token (`request_namespace()` finds no namespace segment;
   POST needs `w` capability).
3. **STS scoping is table-data-prefix, not per-file list.** `read_only=True`
   with no file list vends GetObject-nothing, and a snapshot-pinned file list
   goes stale on the first post-issuance commit (DuckLake clients discover
   files live from PG). New `read_prefixes` mode on `vend_credentials`.
4. **Role source is the UNION** of the JWT `roles` claim and
   `roles_for_principal(sub)` — a hard switch would silently re-mask
   principals whose roles are configured via `DUCKICELAKE_OAUTH_CLIENTS`.
5. **Row filters nest**: `SELECT <proj> FROM (SELECT * FROM "s"."t" WHERE
   <filter>) AS "t"` — flat WHERE after mask aliases has engine-dependent
   alias-vs-base-column resolution once views are executed.
6. **`DUCKICELAKE_MASK_REDIRECT_LOADTABLE` cut** (was draft Stage 4): a
   view-shaped LoadTable violates the REST object model for near-zero value.
7. **`DUCKICELAKE_SUPPRESS_ROOT_CREDS` added** (default off): omits the root
   key pair from `_base_s3_config()`; without it every response hands out
   root MinIO keys and the cooperative boundary is bypassable in one line.
8. **Transparent mode v1 requires `table`**; namespace-only calls return
   creds + DSN with `transparent=false`, `masked_view=null`.
9. **Dev-only `principal` query param** on the credentials endpoint, honored
   only when auth is disabled (precedent: `effective-policies`).
