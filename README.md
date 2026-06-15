# duckicelake

<p align="center">
  <img src="assets/duckicelake-logo.svg" alt="duckicelake — ducks around an iceberg in a lake" width="640"/>
</p>

An **Iceberg REST Catalog** proxy on top of **DuckLake**, with
MinIO-backed object storage and real STS credential vending. Materialises
DuckLake's snapshot / schema / stats state into Iceberg-spec manifests on
demand, so standard Iceberg clients (PyIceberg, DuckDB's `iceberg`
extension, Trino, Spark) read rows directly from S3 — and write back via
register-in-place commits that DuckLake atomically records.

> **This branch** (`experimental_governance`) additionally ships a
> tag-based **governance layer** — object tags, RBAC, column masking and
> row-access policies, enforced on *both* read paths (Iceberg REST and
> DuckLake-direct) and aimed squarely at the "LLM agents must never see
> PII" use case. See the Governance section below.

## ⭐ Hybrid write model — write via either path, read from anywhere

The defining feature: **clients can write via the Iceberg REST path
*or* via DuckLake-direct, and Iceberg readers see both within ~1s**.
No "sync job", no manual rewrite step, no second-class write path.

- **Iceberg REST writes** (PyIceberg / Trino / Spark `commit-table`):
  manifest chain + `metadata.json` built inline as part of the commit.
- **DuckLake-direct writes** (DuckDB sessions ATTACHing `ducklake:` and
  running `INSERT` / `UPDATE` / `DELETE`): a Postgres `LISTEN`/`NOTIFY`
  hook fires on the DuckLake commit and the proxy eagerly materialises
  the full Iceberg metadata chain on S3 — manifest, manifest-list,
  versioned `vN.metadata.json`, and position-delete manifest when an
  UPDATE/DELETE produces one. A fresh PyIceberg / Trino / Spark reader
  hits a warm S3 chain on its first `LoadTable`; nobody waits on
  materialisation.
- **Correctness floor**: the lazy `LoadTable` path stays in place. If
  the listener is disabled (`DUCKICELAKE_DISABLE_NOTIFY=1`), crashes,
  or misses a notification, the next reader still gets correct data —
  the eager path is a pure latency optimisation, not the source of
  truth.
- **Single elected listener per fleet** via PG advisory lock; other
  workers poll and take over if the elected one dies. Startup catch-up
  scan walks any DuckLake snapshots that landed during a listener
  outage. See [`src/duckicelake/notify.py`](src/duckicelake/notify.py).

### Requirements

> **PostgreSQL is required as the DuckLake metastore.**
> The proxy talks to DuckLake's catalog tables through a psycopg pool
> (this is true regardless of the eager hook). The hybrid write model
> additionally relies on PostgreSQL-specific machinery —
> `LISTEN` / `NOTIFY`, an `AFTER INSERT` trigger on
> `ducklake_snapshot`, and `pg_try_advisory_lock` for single-listener
> election. DuckLake itself supports other backends (SQLite, MySQL,
> DuckDB), but those would forgo the eager path: writes are still
> visible through the lazy `LoadTable` materialisation, just without
> the ~1s warm-S3 guarantee. Switching backends is not currently
> wired through the proxy's config.

## 🛡️ Governance: tags, RBAC, masking (experimental)

Tag-based governance enforced by the catalog — authored once, applied per
principal, across **both read paths and every engine**. Enforcement is
layered, and you choose the tier per masking policy:

- **Catalog-level (default).** Cooperative engines get masking signals in
  the table metadata plus an executed masking *view*. Cheap, no extra
  storage. A determined client that names the base table directly can still
  read raw — fine for trusted BI / analysts.
- **File-layer (`file-layer-masking: true`).** The bytes themselves are
  pre-masked and served via shadow Iceberg metadata + scoped credentials,
  so an engine that reads Parquet directly (the DuckDB `iceberg` extension,
  PyIceberg, anything holding the vended creds) **physically cannot reach
  the unmasked data**. Airtight; costs one masked copy per mask shape.

Everything below is **implemented and tested** (an 80-test suite plus live
end-to-end runs — see *What's verified*).

### A worked example — policies in, masked SQL out

Take `analytics.customers`:

```text
 id │ email             │ phone        │ country │ mrr
────┼───────────────────┼──────────────┼─────────┼──────
  1 │ alice@example.com │ 415-555-0101 │ EU      │ 2400
  2 │ bob@personal.io   │ 212-555-0148 │ US      │ 1800
  3 │ carol@work.net    │ 020-555-8018 │ EU      │ 5200
```

Author four policies over REST — masks use `val` as the column value, a
row policy is a boolean keep-predicate, and `unmasked-roles` lists who
bypasses each one:

```bash
P=localhost:8181/v1/lake/governance; H='content-type:application/json'

# tag the sensitive columns, then attach a mask to each tag
curl -sX POST $P/tags        -H $H -d '{"namespace":"pii","name":"email"}'
curl -sX POST $P/tags        -H $H -d '{"namespace":"pii","name":"phone"}'
curl -sX POST $P/object-tags -H $H -d '{"object-kind":"column","schema":"analytics","object":"customers","column":"email","tag-namespace":"pii","tag-name":"email"}'
curl -sX POST $P/object-tags -H $H -d '{"object-kind":"column","schema":"analytics","object":"customers","column":"phone","tag-namespace":"pii","tag-name":"phone"}'

curl -sX POST $P/masking-policies -H $H -d '{"name":"mask_email","signature":"(val VARCHAR)","body":"left(val, 2) || '\''***'\''","unmasked-roles":["pii_reader"]}'
curl -sX POST $P/masking-policies -H $H -d '{"name":"mask_phone","signature":"(val VARCHAR)","body":"'\''***-***-'\'' || right(val, 4)","unmasked-roles":["pii_reader"]}'
curl -sX POST $P/policy-attachments -H $H -d '{"policy-kind":"masking","policy-name":"mask_email","target-kind":"tag","tag-namespace":"pii","tag-name":"email"}'
curl -sX POST $P/policy-attachments -H $H -d '{"policy-kind":"masking","policy-name":"mask_phone","target-kind":"tag","tag-namespace":"pii","tag-name":"phone"}'

# row policy: non-EU rows are hidden unless you hold global_reader
curl -sX POST $P/row-access-policies -H $H -d '{"name":"eu_only","signature":"(country VARCHAR)","body":"country = '\''EU'\''","unmasked-roles":["global_reader"]}'
curl -sX POST $P/policy-attachments  -H $H -d '{"policy-kind":"row_access","policy-name":"eu_only","target-kind":"table","schema":"analytics","object":"customers","columns":["country"]}'

# roles + who holds them
curl -sX POST $P/roles       -H $H -d '{"name":"pii_reader"}'
curl -sX POST $P/roles       -H $H -d '{"name":"global_reader"}'
curl -sX POST $P/role-grants -H $H -d '{"role":"pii_reader","principal":"analyst_eu"}'
curl -sX POST $P/role-grants -H $H -d '{"role":"pii_reader","principal":"admin"}'
curl -sX POST $P/role-grants -H $H -d '{"role":"global_reader","principal":"admin"}'
```

Now the same `SELECT * FROM analytics.customers` resolves differently per
caller. The proxy rewrites each read into a masking view — `GET
…/governance/effective-policies?table=analytics.customers&principal=…`
returns the exact SQL, shown here with the rows it yields.

**`agent`** (no roles) — both columns masked, non-EU rows dropped:

```sql
SELECT "id",
       left("email", 2) || '***'       AS "email",
       '***-***-' || right("phone", 4) AS "phone",
       "country", "mrr"
FROM (SELECT * FROM "analytics"."customers" WHERE (country = 'EU')) AS "customers"
```
```text
 id │ email   │ phone        │ country │ mrr
────┼─────────┼──────────────┼─────────┼──────
  1 │ al***   │ ***-***-0101 │ EU      │ 2400
  3 │ ca***   │ ***-***-8018 │ EU      │ 5200
```

**`analyst_eu`** (holds `pii_reader`) — masks bypassed, row filter still
applies (no `global_reader`):

```sql
SELECT "id", "email", "phone", "country", "mrr"
FROM (SELECT * FROM "analytics"."customers" WHERE (country = 'EU')) AS "customers"
```
```text
 id │ email             │ phone        │ country │ mrr
────┼───────────────────┼──────────────┼─────────┼──────
  1 │ alice@example.com │ 415-555-0101 │ EU      │ 2400
  3 │ carol@work.net    │ 020-555-8018 │ EU      │ 5200
```

**`admin`** (holds both) — no policy applies, so no view is generated; the
read hits the base table unchanged:

```sql
SELECT * FROM "analytics"."customers"   -- all 3 rows, cleartext
```

Same table, same query, one set of policies — the result is shaped by who's
asking. Switch `mask_email` to `"file-layer-masking": true` and the `agent`
view above is served from **pre-masked Parquet** instead, so even a client
reading the files directly only ever sees `al***`.

### How row-access policies work

A masking policy rewrites a *column*; a **row-access policy drops whole
rows**. Its `body` is a boolean **keep-predicate** over the row — a row
survives only if the predicate is true. Attach it to a **table** (naming
the columns it reads) or to a **tag** on the table/schema.

**They stack with `AND`.** Add a second policy and a row must satisfy
*both*. With `eu_only` (`country = 'EU'`) and `min_mrr` (`mrr >= 2000`)
attached, the proxy nests them ahead of any masking (predicates joined in
policy-name order):

```sql
SELECT "id", left("email", 2) || '***' AS "email", …
FROM (SELECT * FROM "analytics"."customers"
      WHERE (country = 'EU') AND (mrr >= 2000)) AS "customers"
```

**The filter sees RAW values, before masking.** Because the predicate runs
in the inner subquery, you can filter on a column whose output is masked —
e.g. a policy `body` of `email LIKE '%@work.net'` keeps Carol's row even
though her `email` comes back as `ca***`. (This matches how a SQL engine's
row policies see unmasked data.)

**Bypass is per-policy.** Each policy carries its own `unmasked-roles`, so a
principal can hold the row filter's bypass yet still be column-masked, or
vice-versa — `analyst_eu` above is unmasked but still EU-only.

### Working with tags & policies

**Change a policy — just re-POST it.** Names are the key; a repeat POST is an
upsert. Widen who bypasses `mask_email`, or swap its body, with no delete:

```bash
curl -sX POST $P/masking-policies -H $H -d '{"name":"mask_email","signature":"(val VARCHAR)","body":"regexp_replace(val, ''[^@]+'', ''***'')","unmasked-roles":["pii_reader","support"]}'
```

The masking view / pre-masked export carries a signature of the mask shape,
so it **rotates automatically** — the next read picks up the new body; the
stale view/export is garbage-collected. Re-POSTing an `object-tag` or a
`policy-attachment` upserts it the same way.

**Delete — detach first (references block the delete).** A policy that's
still attached, or a tag that's still in use, returns **409**; remove the
references, then delete:

```bash
# detach the mask from its tag, THEN delete the policy
curl -sX DELETE $P/policy-attachments  -H $H -d '{"policy-kind":"masking","policy-name":"mask_email","target-kind":"tag","tag-namespace":"pii","tag-name":"email"}'
curl -sX DELETE $P/masking-policies/mask_email          # 409 while still attached
curl -sX DELETE $P/object-tags         -H $H -d '{"object-kind":"column","schema":"analytics","object":"customers","column":"email","tag-namespace":"pii","tag-name":"email"}'
curl -sX DELETE $P/tags/pii/email                       # 409 while still assigned/attached
curl -sX DELETE $P/role-grants         -H $H -d '{"role":"pii_reader","principal":"analyst_eu"}'
curl -sX DELETE $P/object-grants       -H $H -d '{"object-kind":"table","schema":"analytics","object":"customers","privilege":"select","role":"analysts"}'
```

Detaching a mask, untagging a column, or revoking a grant flips the affected
reads back to cleartext on the **next** request, and the proxy drops the now-
stale masking views / pre-masked exports for those tables automatically.

### How policies compose

- **Can one tag carry multiple policies?** Yes — a tag can hold several
  attachments (a masking policy *and* a row-access policy, or masks for
  different columns). But **a column resolves to exactly one masking
  policy**: attaching a second mask that would reach an already-masked
  column (directly or via a tag) is rejected with **409**. Row-access
  policies have no such limit — they stack with `AND`.
- **Tag cascade accumulates.** Tags at schema → table → column *union* (a
  column-level tag doesn't erase a broader one); a column is governed by
  every policy on any tag it carries plus any direct column attachment —
  subject to the one-mask rule.
- **Masking + row-access compose in one view.** Row filters run first on raw
  rows; the surviving rows are projected through the column masks. Bypass is
  evaluated independently per policy.
- **A principal's effective policy** = their roles (JWT claim ∪ sidecar
  grants) resolved against the table's tags/policies → at most one mask per
  column + the `AND` of all non-bypassed row filters. Inspect it live:
  `GET …/governance/effective-policies?table=analytics.customers&principal=…`
  returns both the *derived* set and the *enforced* plan (masked columns,
  row filter, the generated view SQL).

**The model.** Object tags (`pii.email`, hierarchical cascade
schema → table → column), masking policies + row-access policies (SQL
bodies with a declarative `unmasked-roles` bypass), policy attachments
(to a tag or directly to columns/tables), roles + grants, and a complete
audit trail — all stored in `duckicelake_*` Postgres sidecars and authored
over REST (`/v1/{prefix}/governance/*`).

**Iceberg-REST enforcement.** At `LoadTable` the proxy resolves the
caller's principal + roles (JWT `roles` claim ∪ sidecar grants) into a
per-table enforcement plan and stamps the returned metadata — column `doc`
annotations, `duckicelake.mask.<col>` expressions, `iceberg.row-filter`
(the Trino/Spark fast-path key), and the generated masking-view SQL. Every
decision is audited.

**Executed masking views, both read paths.** The engine materialises one
physical DuckLake view per (table, mask-signature) — `__mask_{table}__{sig}` —
that *executes* the mask:

- View-capable REST engines (PyIceberg / Trino / Spark) load it via
  `GET …/views/…`; LoadTable advertises the caller's view name via the
  `duckicelake.masking-view-name` property.
- DuckLake-direct DuckDB clients call
  `GET /v1/{prefix}/namespaces/{ns}/ducklake-credentials?table=…` and get
  the PG DSN + ATTACH statement, **read-only prefix-scoped STS creds**
  (files committed after vending stay readable), their masked view name,
  and `post_attach_sql` that makes masking **transparent** for unqualified
  queries (`SET search_path` onto a `__masked_{sig}` schema).
- Policy or schema changes rotate the signature; stale views are
  garbage-collected. Per-table opt-out via the
  `duckicelake.masking-disabled` property.

**Per-principal reader roles + row-level security.** `ducklake-credentials`
vends a **per-principal, per-vend Postgres LOGIN role**
(`duckicelake_p_<sub>_<sha8>_<nonce>`, random password, `VALID UNTIL` = the
STS expiry, `READ_ONLY` attach) instead of the owning role — a fresh role
per vend, so concurrent vends for one principal never invalidate each
other's secret; all map to the same principal and are GC'd by expiry.
Row-level security on the `ducklake_*` catalog tables enforces visibility:
explicit `select` object-grants flip a table to allowlist (ungranted
principals can't even see it), and the same machinery hides base file rows
for file-layer-masked tables. The RLS check is a set-membership test
(`table_id NOT IN (SELECT … hidden …)`) Postgres evaluates **once per scan
and hashes** — not a per-row function call — so it stays cheap on large
catalogs.

**File-layer masking — byte-level, every engine.** Set
`"file-layer-masking": true` on a masking policy and the proxy materialises
the mask **physically** — per-(table, mask-signature) current-state Parquet
exports under `data/__masked__/…` (deletes and row filters applied by
construction, Iceberg field-ids stamped), eagerly refreshed on every
DuckLake commit. Masked principals then get:

- *DuckLake-direct*: the masking view reads the pre-masked Parquet, creds
  cover **only** the masked prefix (base bytes physically 403), and RLS
  hides base file rows — the base table is empty even by name.
- *Iceberg REST*: LoadTable returns **shadow Iceberg metadata** built over
  the export + read-only masked-prefix STS — so even the DuckDB `iceberg`
  extension (no views, no scan planning) transparently scans masked bytes.

This is the only byte-level mechanism available for engines that read
Parquet directly: DuckDB has no per-column Parquet encryption and no REST
scan-planning client, so pre-masked copies are the path. The default stays
catalog-level only.

Everything is **fail-open** (a governance error never breaks a read — it
serves unmasked and audits the failure) and **root S3 keys are no longer
embedded in responses by default**: clients see only vended credentials.

**Hardening & boundaries** (audited by two adversarial review passes):

- **Reserved governance state can't be forged or disabled by a client.**
  `set/remove-properties` on any `duckicelake.*` key is rejected (403) — a
  write token can't flip off `duckicelake.file-layer-masking` to disable
  RLS file-hiding. `__mask_*` table/view names are rejected at create and
  rename so user objects can't collide with masking-view plumbing.
- **Masked principals never reach base bytes.** Vended creds scope to the
  masked-signature prefix only; namespace-level vends add explicit IAM
  *Deny* on every file-layer table's base prefix — derived from the policy,
  so a table that was authored but never yet exported is still denied.
- **Injection-safe SQL.** Identifiers and string literals (table/column
  names, S3 paths) are escaped in the export `COPY` / `read_parquet` /
  `FIELD_IDS` paths, which run as the owning role with root creds.
- **Catalog hygiene.** The reader role is never granted the tables that
  would bypass or undermine RLS: inlined-data payloads (raw rows, no
  `table_id` to police), `ducklake_snapshot_changes` (leaks hidden tables'
  names), and `ducklake_files_scheduled_for_deletion` (base data-file paths
  of hidden / file-layer tables). RLS coverage re-arms automatically if a
  new `ducklake_*` system table appears after startup. Governance sidecar
  DDL runs once per process, not per request. *Known residual disclosure
  (low):* a reader can still see `ducklake_schema` (namespace names) and
  `ducklake_view` (view definitions, incl. masking-view SQL) — the DuckLake
  extension needs both to resolve and execute the masking views; neither
  exposes row data. RLS-filtering those is tracked follow-up.
- **Policies follow the catalog, not stale names.** Governance rows key on
  `(schema, table, column)`, so a rename or drop would otherwise orphan them
  — a mask silently lapsing (leak) or a recreated name inheriting a stale
  mask. `rename_table` carries the table's tags/attachments/grants to the new
  name; an `add-schema` column rename (same field-id, new name) carries the
  column's tag + column-target masks to the new name; `drop_table` purges
  them; all resync the masking views/exports. And an attachment the resolver
  would ignore (masking→`table`,
  row-access→`column`) is rejected at attach (400) so a no-op can't
  masquerade as protection.
- **Honest about the dev/prod gap.** The catalog-level masking views are
  cooperative (a client with the base table name + base creds reads raw);
  file-layer masking is the airtight tier for tables that opt in. The dev
  stack runs Postgres `trust` auth, so RLS *authentication* is only real
  under production `scram-sha-256` + TLS — the `pg_hba` recipe is in
  [OPERATIONS.md](OPERATIONS.md).

Try it against a running stack:

```bash
./scripts/governance_demo.sh    # author tags/policies/roles via REST + SQL proof
./scripts/lakesh_demo.sh        # lakesh: unmasked REST read vs vended masked view
pixi run pytest -q tests/test_governance.py tests/test_governance_phase3.py tests/test_governance_phase4.py
```

The LLM-agent story this is built for: give the agent's token a role
without the `unmasked-roles` bypass (or no roles at all), point it at the
proxy — REST or `ducklake-credentials` — and it reads `al***` where a
human analyst holding `pii_reader` reads `alice@example.com`, through the
same API, with every access audited.

### What's verified

Beyond the 80-test `pytest` suite, the governance layer has been exercised
end-to-end against a live local stack (proxy + MinIO + Postgres). All of
the following are confirmed working:

- **Byte-level masking on every read engine.** With a file-layer policy
  active, a masked principal's vended credentials get **403** on the base
  Parquet keys and **200** on the masked copies; the masked values come
  back through the raw S3 path, the **DuckDB `iceberg` extension**
  (`iceberg_scan` over the shadow metadata), and **PyIceberg** — none of
  them DuckDB-specific, all reading `al***` instead of the real address.
- **DuckLake-direct masking.** `lakesh` and a plain DuckDB session reading
  through the vended reader-role DSN see masked rows via the materialized
  view (transparent for unqualified queries).
- **The adversarial cases hold.** A write token cannot disable governance
  (`set/remove-properties` on `duckicelake.*` → 403); `__mask_*` table/view
  names are rejected (400); a namespace-level credential vend denies the
  base bytes of a file-layer table **even if it was never exported**.
- **RLS enforces visibility and stays cheap.** An ungranted principal can't
  see an allowlisted table at all; a granted one and the owner can; the
  policy check plans as a once-per-scan hashed sub-plan, not a per-row
  function call.
- **Concurrency & lifecycle.** 10 simultaneous credential vends for one
  principal yield 10 independent roles that all authenticate (no
  password-rotation race); a post-vend write shows up masked in an already
  open session within ~1s (eager refresh); schema changes rotate the mask
  signature and `DROP TABLE … purgeRequested=true` removes the masked
  copies.
- **Performance.** Export materialization and masked scans are on par with
  base scans on a 1M-row table; re-vending reuses the existing export.

## Current state (this branch)

`experimental_governance` is not yet merged to `main`. Everything in the
governance section above is **implemented and tested** — to be concrete,
shipped today:

| Capability | Status |
|---|---|
| Tags, masking + row-access policies, roles, grants, audit — authored over REST | ✅ |
| Iceberg-REST `LoadTable` enforcement (per-principal masking signals in metadata) | ✅ |
| Executed DuckLake masking views + `ducklake-credentials` vending, both read paths | ✅ |
| Per-principal Postgres reader roles + row-level security on the `ducklake_*` catalog | ✅ |
| File-layer masking — pre-masked Parquet + shadow Iceberg metadata (byte-level, every engine) | ✅ |

The branch has been through two adversarial code-review passes; the
security/correctness findings (reserved-property protection, reserved-name
guards, namespace-vend deny derivation, injection-safe export SQL,
fail-open everywhere) and the performance follow-ups (set-based RLS
predicate, per-vend roles, once-per-process sidecar DDL, batched S3
deletes) are all fixed and regression-tested.

**Known boundaries / not yet done:**

- **Auth in dev is `trust`.** RLS *authentication* is only real under
  production Postgres `scram-sha-256` + TLS (the predicate logic is fully
  exercised in dev; the `pg_hba` recipe is in [OPERATIONS.md](OPERATIONS.md)).
  Data inlining must be off for the vended reader path.
- **An LLM-agent convenience layer** — a dedicated `agent` role convention
  and MCP integration so an agent is masked by default — is designed but
  not built.
- Smaller follow-ups remain open: a per-principal aggregated transparent
  schema, and debounced re-export for hot-write file-layer tables.

## Demos

Three short real-terminal recordings (vhs / ttyd, no animation, no mocks):

### 🎯 Architectural proof — Iceberg view on top of DuckLake _(with code on screen)_

Every step shows its source first, then runs it. Same Parquet on S3,
same Postgres rows; two extension paths (Iceberg REST via PyIceberg +
DuckDB iceberg-ext, and DuckLake direct via DuckDB ducklake-ext) see
exactly the same data. A row written via DuckLake direct appears in
both Iceberg readers automatically. Ends with the snapshot-id identity
check: `DuckLake HEAD == Iceberg current-snapshot-id == ducklake.snapshot-id` property.

![duckicelake architectural proof demo](demo_videos/duckicelake-demo_with_code.gif)

📥 Full quality:
[`duckicelake-demo_with_code.mp4`](demo_videos/duckicelake-demo_with_code.mp4) (2:52 · 1700×1080 · 3.5 MB)

### Companion: `lakesh`

`lakesh` is a small DuckDB-powered SQL shell for Iceberg REST catalogs
(and DuckLake direct). Profile-based connection management, an
interactive REPL with `psql`-style meta-commands, one-shot `exec` mode
for scripts, and an MCP server so LLM agents can query your catalogs
through the same plumbing. It pairs naturally with duckicelake — just
point it at the proxy. Source + docs at
[github.com/KellerKev/lakesh](https://github.com/KellerKev/lakesh).

![lakesh companion demo](demo_videos/lakesh-companion-demo.gif)

📥 Full quality:
[`lakesh-companion-demo.mp4`](demo_videos/lakesh-companion-demo.mp4) (0:55 · 1700×1000 · 1.3 MB)

---

```
  Iceberg REST client (PyIceberg, DuckDB iceberg ext, Trino, Spark, …)
              │  HTTP (Iceberg OpenAPI v3)
              ▼
       FastAPI proxy (duckicelake.server)  ──▶ Prometheus /metrics
       │     │     │                       ──▶ /healthz /readyz
       │     │     │                       ──▶ JSON logs
       │     │     │
       │     │     │  STS AssumeRole (per-table session policy)
       │     │     ▼
       │     │   MinIO STS  ──▶ vended creds (s3.access-key-id, …)
       │     │
       │     │  SQL via DuckDB+ducklake (write conn + read pool)
       │     ▼
       │  Postgres (psycopg pool)
       │     ├── ducklake_*       — schemas, tables, columns, snapshots, stats, deletes
       │     └── duckicelake_*    — properties, tags, branches, partition-spec sidecar,
       │                            nan_value_count cache, format-version override
       │
       │  S3 / MinIO direct (object I/O)
       ▼
   data/<ns>/<tbl>/                       ── Parquet data files (DuckLake)
   data/<ns>/<tbl>/                       ── Parquet position-delete files (v2)
   data/<ns>/<tbl>/                       ── eq-delete & v3 Puffin DV (.puffin)
   data/<ns>/<tbl>/metadata/
        ├── vN.metadata.json              ── TableMetadata, versioned per commit
        ├── version-hint.text             ── Hive-style pointer to vN
        ├── snap-<id>-<uuid>.avro         ── manifest list (one per snapshot)
        ├── <id>-<uuid>-m0-data.avro      ── data manifest (stats + row_id + key_metadata)
        └── <id>-<uuid>-m1-deletes.avro   ── delete / DV manifest (when applicable)
```

Everything runs out of a single `pixi` environment — no Docker.

## What's in the box

### Iceberg REST surface

- All catalog ops: `/v1/config`, namespace CRUD, table CRUD, rename,
  views CRUD.
- `LoadTable` returns inline TableMetadata + (optionally) vended STS
  creds via `X-Iceberg-Access-Delegation: vended-credentials`.
- `LoadTable?snapshot-id=N` pins a historical snapshot for time-travel.
- Format-version 2 by default; **v3 writes work end-to-end** through
  the [`pyiceberg_v3`](src/duckicelake/pyiceberg_v3.py) shim — see
  the v3 section below.
- Full Iceberg `commit-table` action set:

  | Action | Translation |
  |---|---|
  | `add-snapshot` (append/overwrite/replace/delete) | `ducklake_add_data_files()` + tombstone via `UPDATE ducklake_data_file.end_snapshot` |
  | position-delete file (content=1) | `INSERT INTO ducklake_delete_file`; for v3 tables, materialize rewrites these into a Puffin file with one `deletion-vector-v1` blob per data file |
  | equality-delete file (content=2) | per-file scan via `read_parquet(..., file_row_number=true)` → emit Iceberg position-delete Parquets scoped to files with `begin_snapshot < commit_snap` (Iceberg-spec sequence-number scoping) |
  | `add-schema` + `set-current-schema` | diff by field-id → `ALTER TABLE ADD/DROP COLUMN` |
  | `add-partition-spec` (identity / year / month / day / hour / bucket) | `ALTER TABLE … SET PARTITIONED BY (…)` |
  | `add-partition-spec` (truncate[N]) | sidecar `duckicelake_table_partition_field`; per-file values synthesised from source `min_value` at emit time |
  | `add-sort-order` | direct INSERT into `ducklake_sort_info` + `ducklake_sort_expression` |
  | `set-properties` / `remove-properties` | sidecar `duckicelake_table_property` |
  | `set-snapshot-ref type=tag` | sidecar `duckicelake_table_tag` (`ref_type='tag'`) |
  | `set-snapshot-ref type=branch` (non-main) | sidecar entry as **read-only branch pointer**; writes targeting a non-main branch 501 |
  | `remove-snapshot-ref` / `remove-snapshot` | sidecar delete / `ducklake_expire_snapshots` |
  | `upgrade-format-version` to 2 or 3 | sidecar `duckicelake.format-version` property; materialize emits matching Avro schemas |
  | `assign-uuid` / `add-statistics` / `remove-statistics` | accepted no-ops (we derive UUID + synthesise stats from DuckLake) |
  | `set-location` | **501** (DuckLake owns layout via attach-time DATA_PATH) |
  | `void` partition transform | **501** (drop the field from a fresh spec instead) |

### Snapshot chain + per-file metadata

- One Iceberg snapshot per DuckLake commit, linked via
  `parent-snapshot-id`, with `summary.operation` enriched from
  `ducklake_snapshot_changes.changes_made` (append/delete/overwrite/replace).
- `snapshot-log[]`, `metadata-log[]`, `refs.main` always tracking
  DuckLake HEAD; tags + read-only branches via sidecar.
- Per-file column stats: `value_counts`, `null_value_counts`,
  `nan_value_counts` (exact, computed via `read_parquet(... WHERE
  isnan(col))` and cached in `duckicelake_file_nan_count`), and
  `lower_bounds` / `upper_bounds` with Iceberg-spec binary encoding
  (LE for ints/floats/timestamps, BE two's-complement for decimals,
  UTF-8 strings, 16-byte BE UUIDs).
- Row lineage (v3): `first_row_id` per manifest entry, `last-row-id`
  + `row-lineage: true` in TableMetadata.
- `key_metadata` surfaced from `ducklake_data_file.encryption_key`
  (null on unencrypted catalogs).

### Partition pruning end-to-end

Per-file partition values land in the manifest Avro with Iceberg-correct
semantics:
- `identity`, `bucket[N]` — DuckLake's stored values pass through (the
  Murmur3 hash aligns with Iceberg's `(murmur3 & INT_MAX) % N`).
- `year` / `month` / `day` / `hour` — recomputed server-side from source
  column `min_value` because DuckLake's semantics differ.
- `truncate[N]` — synthesised from source `min_value` via
  `iceberg_transforms.apply_truncate` (DuckLake has no native truncate).

Verified: PyIceberg pushdown prunes `country='US'` from 3 files → 2
read; `ts >= 2026-04-22 UTC` from 3 files → 1 read.

### Iceberg v3 writes (via the shim)

PyIceberg 0.11.1 still raises `Cannot write manifest list for table
version: 3`. The fix PR upstream
([iceberg-python#3070](https://github.com/apache/iceberg-python/pull/3070))
stalled in March 2026.

[`pyiceberg_v3.install()`](src/duckicelake/pyiceberg_v3.py) vendors
that PR's essentials as a monkey-patch: `ManifestWriterV3` /
`ManifestListWriterV3` subclasses, `write_manifest` /
`write_manifest_list` factory dispatch, `SUPPORTED_TABLE_FORMAT_VERSION`
bumped to 3 (in both `pyiceberg.table.metadata` and
`pyiceberg.table.update`), `DataFile.from_args` rewired so default
arg resolves dynamically (else V2-shape records flow into V3
writers and IndexError), client-side gates patched in
`Transaction.upgrade_table_version` + `_apply_table_update` for
`UpgradeFormatVersionUpdate` (seeds `next_row_id=0`) +
`AddSnapshotUpdate` (synthesises `first_row_id`).

Call once before any `RestCatalog` operation:

```python
from duckicelake.pyiceberg_v3 import install
install()
```

The same shim also adds the v3 primitive types (`variant`, `geometry`,
`geography`) that PyIceberg's pydantic validator otherwise rejects.

The proxy itself accepts `upgrade-format-version` to 3 and
re-materialises manifests + manifest-list in V3 Avro shape (with
`first_row_id` field) when the table's format-version is 3.

### v3 Puffin deletion vectors

For format-version 3 tables, the proxy rewrites position-delete
Parquets into a single Puffin file per snapshot containing one
`deletion-vector-v1` blob per affected data file:
- Roaring64 portable serialisation (Iceberg-spec compatible: 8B
  little-endian count of 32-bit bitmaps, then per-bucket key + CRoaring
  portable bytes).
- Magic `D1 D3 39 64`, big-endian length + CRC-32 framing per spec.
- Footer: `PFA1` magic + UTF-8 JSON FileMetadata + size + flags + magic.
- Manifest entry carries `file_format=puffin`, `content_offset`,
  `content_size_in_bytes`, `referenced_data_file`, and
  `record_count` (= cardinality).

V2 tables keep the legacy Parquet position-delete shape — readers that
only understand v2 still work.

### v3 type wiring

| Iceberg | DuckDB |
|---|---|
| `variant` | `VARIANT` |
| `geometry` / `geography` | `GEOMETRY` (via the `spatial` extension) |
| `timestamp_ns` / `timestamptz_ns` | `TIMESTAMP_NS` |
| `decimal(p, s)`, `uuid`, `date`, `time`, `boolean`, all numerics | direct |

PyIceberg and the demo show v3 types loading + reading round-trip;
DuckDB's `iceberg` ext currently surfaces `variant` / `geometry` as
`UNKNOWN` (upstream gap in `duckdb-iceberg` 1.5.x).

### OAuth2 + RBAC

- `POST /v1/oauth/tokens` issues HMAC-signed JWTs; middleware enforces
  `Authorization: Bearer` on every `/v1/*` route except `/v1/config`,
  `/v1/oauth/tokens`, `/healthz`, `/readyz`, `/metrics`, `/openapi.json`.
- Scope grammar embedded in the JWT: `ns:<name>:<cap>` (per-namespace)
  or `*` (superuser). `cap ∈ {r, w, rw, *}`. Catalog-level writes
  (create / drop namespace) require a wildcard-namespace scope.
- Configure via `DUCKICELAKE_OAUTH_CLIENTS="id:secret|scope,id2:sec2|scope2"`
  or `DUCKICELAKE_OAUTH_CLIENTS_FILE=<path>` (JSON).
- `DUCKICELAKE_REQUIRE_AUTH=1` → server refuses to start if no clients
  configured. Production safety belt.
- PyIceberg consumes via `credential="id:secret"`, DuckDB via
  `CREATE SECRET (TYPE ICEBERG, TOKEN '<token>')`.

### STS credential vending

`X-Iceberg-Access-Delegation: vended-credentials` triggers real MinIO
`AssumeRole` with a session policy scoped to the table's data-file
keys + its `metadata/*` prefix. Returns
`s3.access-key-id` / `s3.secret-access-key` / `s3.session-token` /
`s3.credentials-expiration` in the LoadTable `config` map.

**Root keys are not embedded by default.** Response configs carry only
endpoint/region/url-style; clients are expected to use vended credentials
(the delegation header, or `GET …/ducklake-credentials` for
DuckLake-direct). Dev stacks that want the old
convenience set `suppress_root_creds = false` in `duckicelake.toml` (or
`DUCKICELAKE_SUPPRESS_ROOT_CREDS=0`).

### Throughput / scale

- Postgres `ConnectionPool` (psycopg-pool) — most LoadTable work hits
  PG directly (info-schema queries moved off DuckDB to bypass the
  write-conn lock).
- DuckDB read pool (separate from the write conn) for parallel scans
  during equality-delete handling.
- Single `boto3` S3 client per process — built once at startup,
  thread-safe, pools its own HTTPS connections.
- Single Postgres transaction per commit (`commit_transaction()`
  context with `contextvars`-driven shared cursor).
- In-process LRU metadata cache keyed on `(ns, table) → (snap_id,
  metadata)`, bounded via `DUCKICELAKE_CACHE_MAX` (default 1024).
- Eager materialise at commit time so post-commit reads hit cache.
- Per-snapshot S3 writes parallelised via a thread pool; `head_object`
  before `put_object` skips re-uploads of byte-identical content.
- Per-file equality-delete scans run in parallel across the read pool.
- Endpoints are sync `def` (FastAPI runs them in its threadpool, so
  blocking I/O doesn't pin the event loop). `pixi run serve-hi` boots
  4 uvicorn workers.

Measured: ~349 req/s on cache-hit LoadTable at concurrency 32 on one
machine.

### Observability

- `/metrics` — Prometheus exposition. Per-endpoint latency histograms,
  request counts by status class, commit outcomes, in-process cache
  size + hit/miss counters, PG pool in-use / idle.
- `/healthz` — liveness (always 200 if the process is up).
- `/readyz` — readiness (200 only when Postgres responds to
  `SELECT 1`).
- JSON-formatted logs by default (`DUCKICELAKE_LOG_FORMAT=json`); flip
  to `text` for dev. Configurable level via `DUCKICELAKE_LOG_LEVEL`.

### Admin

- `DELETE /v1/{prefix}/.../tables/{tbl}?purgeRequested=true` — DROP
  TABLE plus delete every S3 object under the table prefix (data,
  delete files, manifests, metadata JSON).
- `POST /v1/{prefix}/admin/namespaces/{ns}/tables/{tbl}/compact` —
  wraps `ducklake_merge_adjacent_files` + `ducklake_cleanup_old_files`.
  Idempotent; safe to cron.

### Tests + CI

- 78 `pytest` tests covering the REST surface, cache LRU, metrics
  endpoint, Puffin writer byte-level structure, the eager-materialisation
  listener, config-file loading, and the governance layer end-to-end —
  including the byte-level proofs that a masked principal's vended
  credentials cannot read base Parquet (403) while masked copies, the
  RLS-governed reader role, and the shadow Iceberg metadata all serve
  masked rows; a privileged principal reads cleartext throughout.
- GitHub Actions workflow at [.github/workflows/ci.yml](.github/workflows/ci.yml)
  runs `backends-up` + `pytest` + the full `duckdb-client` demo on
  every push.

## Architectural decisions

See [ARCHITECTURE.md](ARCHITECTURE.md) for full rationale — short
version:

- **Single-writer invariant**: every commit ends as rows in DuckLake's
  Postgres tables inside one transaction. No two writers race on
  catalog state. DuckLake's `ducklake_add_data_files` allocator
  serialises file additions; our `register_delete_files` /
  `tombstone_data_files` mirror the same pattern with explicit
  snapshot allocation under a PG lock.
- **Lazy materialisation, content-addressed cache**: keyed on DuckLake
  snapshot id. UniForm had to go eager because HMS gave them no lazy
  hook; we own the REST surface so we cache + invalidate cleanly.
- **Iceberg snapshot-id == DuckLake snapshot-id**, deterministic. No
  random int64s like UniForm — direct correlation makes ops debuggable.
- **Equality deletes are spec-scoped**: per-file scan + emit, scoped
  to files with `begin_snapshot < commit_snap`. Files added after the
  delete are never retro-deleted.
- **Read-only branches over no branches**: DuckLake has no native
  branching. We expose named refs as read-only pointers (covers
  pinning + release labelling); writes targeting a non-main branch 501.

## Quickstart

```bash
pixi install
pixi run backends-up     # Postgres + MinIO
pixi run ducklake-init   # creates bucket + default namespace
pixi run serve           # Iceberg REST catalog on :8181 (single worker, --reload)
# OR
pixi run serve-hi        # 4 uvicorn workers, no reload — closer to prod shape
```

In another terminal:

```bash
pixi run smoke           # catalog-only smoke
pixi run duckdb-client   # the full demo (20+ assertion blocks)
pixi run test            # pytest integration suite
```

Teardown: `pixi run backends-down`.

## Endpoint summary

| Method | Path | Notes |
|---|---|---|
| GET | `/v1/config` | catalog prefix + endpoint allowlist |
| GET | `/healthz`, `/readyz`, `/metrics` | ops endpoints (auth-exempt) |
| POST | `/v1/oauth/tokens` | OAuth2 client-credentials token endpoint |
| GET / POST / DELETE | `/v1/{prefix}/namespaces[/{ns}]` | schema CRUD |
| GET / HEAD | `/v1/{prefix}/namespaces/{ns}` | exists / load |
| GET | `/v1/{prefix}/namespaces/{ns}/tables` | list |
| POST | `/v1/{prefix}/namespaces/{ns}/tables` | create with Iceberg schema |
| GET / HEAD | `/v1/{prefix}/namespaces/{ns}/tables/{tbl}` | LoadTable; `?snapshot-id=N` for time-travel |
| DELETE | `/v1/{prefix}/namespaces/{ns}/tables/{tbl}` | DROP TABLE; `?purgeRequested=true` to clean S3 |
| POST | `/v1/{prefix}/namespaces/{ns}/tables/{tbl}` | commit (full action set above) |
| POST | `/v1/{prefix}/tables/rename` | same-namespace rename |
| GET / POST / DELETE | `/v1/{prefix}/namespaces/{ns}/views[/{v}]` | view CRUD (SQL stored in DuckLake); `__mask_*` names reserved + hidden from listings |
| GET | `/v1/{prefix}/namespaces/{ns}/ducklake-credentials` | DuckLake-direct vending: DSN + scoped STS creds + masked view + transparent routing (`?table=`) |
| POST | `/v1/{prefix}/governance/{tags, object-tags, masking-policies, row-access-policies, policy-attachments, roles, role-grants, object-grants}` | governance authoring (admin-scoped); re-POST = upsert |
| DELETE | same paths (policies/tags/roles by name in the path; attachments/object-tags/grants by body) | delete / detach / untag / revoke; 409 while still referenced |
| GET | `/v1/{prefix}/governance/effective-policies` | derived policy set + enforced plan for `?table=…&principal=…` |
| GET | `/v1/{prefix}/governance/audit` | governance + enforcement audit trail |
| POST | `/v1/{prefix}/admin/namespaces/{ns}/tables/{tbl}/compact` | DuckLake compaction + file cleanup |

## Layout

```
duckicelake/
├── pixi.toml                     # one-env stack (Postgres, MinIO, Python, deps)
├── pyproject.toml
├── README.md / ARCHITECTURE.md / OPERATIONS.md / MISSING.md
├── .github/workflows/ci.yml      # CI: backends-up + pytest + demo
├── scripts/
│   ├── pg.sh                     # Postgres lifecycle
│   ├── minio.sh                  # MinIO lifecycle
│   ├── governance_demo.sh        # author tags/policies/roles via REST + SQL proof
│   ├── lakesh_demo.sh            # lakesh against the governed catalog (vended creds)
│   ├── sql_proof.py              # masked-vs-unmasked rows from the live policy SQL
│   └── probe_searchpath.py       # DuckDB search_path transparency probe (file-layer transparent routing)
├── duckicelake.toml.example      # config-file template (env ↔ TOML key map)
├── src/duckicelake/
│   ├── config.py                 # settings: env > .env > duckicelake.toml
│   ├── auth.py                   # OAuth2 + JWT + scope grammar + roles claim
│   ├── catalog.py                # DuckLake wrapper: PG pool + DuckDB read/write split
│   │                             #   + sidecar tables + LRU metadata cache + S3 client
│   ├── governance.py             # governance sidecars: tags/policies/roles/grants/audit
│   ├── governance_api.py         # REST authoring router (/v1/{prefix}/governance/*)
│   ├── policies.py               # policy engine: per-principal plan, mask signature,
│   │                             #   masked-view SQL, metadata stamping
│   ├── masking_views.py          # ad-hoc DuckLake masking views: materialise/GC/transparent
│   ├── masked_export.py          # file-layer masking: masked Parquet exports + shadow metadata
│   ├── pg_rls.py                 # per-principal PG reader roles + RLS on ducklake_*
│   ├── notify.py                 # eager materialisation listener (LISTEN/NOTIFY + election)
│   ├── types.py                  # Iceberg ↔ DuckDB ↔ DuckLake type translation
│   ├── bounds.py                 # Iceberg binary bound encoders
│   ├── iceberg.py                # TableMetadata scaffold
│   ├── manifest.py               # Iceberg v2/v3 Avro writers (data + delete + DV manifests)
│   ├── partition_sort.py         # Iceberg ↔ DuckLake partition / sort translation
│   ├── iceberg_transforms.py     # day/month/year/hour/bucket/truncate value computation
│   ├── puffin.py                 # v3 Puffin writer for deletion-vector-v1 blobs
│   ├── pyiceberg_v3.py           # client-side shim: v3 types + v3 manifest writers
│   ├── materialize.py            # full snapshot-chain materialiser (lazy + cached)
│   ├── read_manifest.py          # parses client-supplied manifest chains on commit
│   ├── sts.py                    # MinIO STS AssumeRole + session policies (file/prefix scoped)
│   ├── observability.py          # Prometheus metrics + JSON logging
│   ├── models.py                 # Pydantic REST request/response models
│   ├── server.py                 # FastAPI app: endpoints + middleware + handlers
│   ├── bootstrap.py              # `pixi run ducklake-init`
│   ├── smoke.py                  # catalog-only smoke
│   └── duckdb_client.py          # full demo with assertions across all features
└── tests/
    ├── conftest.py               # session-scoped uvicorn + clean-state fixtures
    ├── test_catalog_surface.py   # REST surface smoke
    ├── test_cache_and_observability.py
    ├── test_config.py            # config-file loading + precedence + root-key suppression
    ├── test_governance.py        # authoring, audit, plan, LoadTable stamping
    ├── test_governance_phase3.py # masking views, ducklake-credentials, STS scoping, RLS, fail-open
    ├── test_governance_phase4.py # file-layer masking: exports, byte proofs, shadow metadata
    ├── test_notify_materialise.py# eager materialisation end-to-end
    └── test_puffin.py            # byte-level Puffin writer tests
```

## Configuration

Every `DUCKICELAKE_*` setting can come from, in precedence order:

1. real environment variables,
2. a `.env` file in the working directory (`DUCKICELAKE_*` keys only),
3. `./duckicelake.toml` — or the file `DUCKICELAKE_CONFIG_FILE` points at.

See [duckicelake.toml.example](duckicelake.toml.example) for the TOML key
map: top-level `key` ↔ `DUCKICELAKE_KEY`, `[section] key` ↔
`DUCKICELAKE_SECTION_KEY` (so `[s3] endpoint` is `DUCKICELAKE_S3_ENDPOINT`),
booleans as `true`/`false`. File values are injected at startup without
overriding the real environment, so they also feed auth, logging, and the
notify listener. `duckicelake.toml` and `.env` are gitignored — they may
carry secrets.

| Var | Default | Purpose |
|---|---|---|
| `DUCKICELAKE_PG_HOST` | `<repo>/.pgsock` | Postgres host (pixi-managed local socket by default) |
| `DUCKICELAKE_PG_PORT` | `55432` | |
| `DUCKICELAKE_PG_USER` | `ducklake` | |
| `DUCKICELAKE_PG_DATABASE` | `ducklake` | |
| `DUCKICELAKE_CATALOG` | `lake` | DuckLake catalog name (used as REST `prefix`) |
| `DUCKICELAKE_S3_ENDPOINT` | `http://127.0.0.1:9000` | |
| `DUCKICELAKE_S3_REGION` | `us-east-1` | |
| `DUCKICELAKE_S3_BUCKET` | `lakehouse` | |
| `DUCKICELAKE_S3_ROOT_KEY` / `_ROOT_SECRET` | `minioadmin` | dev defaults; production: IAM role / IRSA / Vault |
| `DUCKICELAKE_S3_PREFIX` | `data/` | |
| `DUCKICELAKE_S3_PATH_STYLE` | `1` | path-style addressing (MinIO) |
| `DUCKICELAKE_CONFIG_FILE` | *(unset → `./duckicelake.toml`)* | alternate TOML config path |
| `DUCKICELAKE_SUPPRESS_ROOT_CREDS` | `1` | omit root S3 keys from response configs; `0` is dev-only (bypasses governance masking) |
| `DUCKICELAKE_TRANSPARENT_MASKING` | `1` | `SET search_path` transparent routing from `ducklake-credentials` |
| `DUCKICELAKE_RLS` | `1` | per-principal PG reader roles + RLS on `ducklake_*` for vended credentials |
| `DUCKICELAKE_READER_GROUP_ROLE` | `duckicelake_reader` | NOLOGIN group carrying reader grants + RLS targets |
| `DUCKICELAKE_MASKED_RETAIN_SNAP_DIRS` | `2` | snap dirs kept per mask-signature (file-layer masking) |
| `DUCKICELAKE_MASKED_EXPORT_TTL_DAYS` | `7` | idle signatures stop being eagerly refreshed |
| `DUCKICELAKE_MASKED_EXPORT_FILE_SIZE` | `256MB` | parquet part size for masked exports |
| `DUCKICELAKE_DISABLE_NOTIFY` | *(unset)* | `1` → disable the eager materialisation listener |
| `DUCKICELAKE_DEFAULT_FORMAT_VERSION` | `2` | flip to `3` once your writer ecosystem supports it |
| `DUCKICELAKE_CACHE_MAX` | `1024` | LRU cap for in-process metadata cache |
| `DUCKICELAKE_LOG_FORMAT` | `json` | `json` for prod, `text` for dev |
| `DUCKICELAKE_LOG_LEVEL` | `INFO` | |
| `DUCKICELAKE_REQUIRE_AUTH` | *(unset)* | `1` → fail boot if no OAuth clients configured |
| `DUCKICELAKE_OAUTH_CLIENTS` | *(empty → auth disabled)* | `id1:secret1\|scope1,id2:secret2\|scope2` |
| `DUCKICELAKE_OAUTH_CLIENTS_FILE` | *(empty)* | JSON file alternative |
| `DUCKICELAKE_OAUTH_JWT_SECRET` | *required when clients are configured* | HMAC key |
| `DUCKICELAKE_OAUTH_TTL_SECONDS` | `3600` | |
| `DUCKICELAKE_OAUTH_ISSUER` | `duckicelake` | |

## DuckDB iceberg extension: configuration notes

Three things worth knowing (all handled automatically by
[duckdb_client.py::_iceberg_client_con](src/duckicelake/duckdb_client.py)):

- **Attach with `ACCESS_DELEGATION_MODE 'none'`**. Without this, the
  iceberg extension builds its own S3 secret from the REST `config` with
  a path-scoped lifetime, and a `use_ssl`/`path-style-access` conflation
  in its config parser produces signatures MinIO rejects on delete-file
  HEAD. With `'none'`, the extension uses the regular `CREATE SECRET
  (TYPE S3, ...)` like any other httpfs operation.
- **Don't set `allow_moved_paths=true`** on `iceberg_scan`. It engages
  a debug path-joiner (`IcebergUtils::GetFullPath`) that mangles
  absolute `s3://` URIs.
- **Snapshot `timestamp-ms` must be ≤ client's transaction-start.**
  `IcebergTableEntry::GetSnapshot` uses transaction-start time as the
  snapshot-lookup anchor. We backdate DuckLake snapshots by 1s on write
  to win the race.

## What's left out

See [MISSING.md](MISSING.md) for the punch list. The Iceberg spec
surface is effectively complete; remaining gaps are:

- **Architectural** (DuckLake-blocked): true divergent branches,
  per-table `set-location`, real KMS envelope encryption.
- **Governance**: tags/RBAC/masking, catalog row-level security, and
  file-layer (byte-level) masking are implemented and tested; remaining
  gaps are the LLM-agent convenience layer, a per-principal aggregated
  transparent schema, and debounced re-export for hot-write tables.
- **Upstream** (other-project-blocked): Spark v3-format writes (Spark
  3.x), DuckDB iceberg-ext v3 features, DuckDB session TZ shifting
  timestamp stats.
- **Production-readiness ops** (deployment work, not code): HA backends,
  TLS / ingress, secret management, backup automation, distributed
  tracing, shipped Grafana dashboards, audit log table, Spark / Trino
  integration tests, sustained-load + chaos benchmarks, multi-platform CI.
