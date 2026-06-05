# duckicelake

An **Iceberg REST Catalog** proxy on top of **DuckLake v1.0**, with
MinIO-backed object storage and real STS credential vending. Materialises
DuckLake's snapshot / schema / stats state into Iceberg-spec manifests on
demand, so standard Iceberg clients (PyIceberg, DuckDB's `iceberg`
extension, Trino, Spark) read rows directly from S3 — and write back via
register-in-place commits that DuckLake atomically records.

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

### Iceberg spec coverage tour _(no code on screen)_

Seven scenes walking through what the catalog actually implements:
create / append, DuckDB-iceberg-ext readback, time travel via PyIceberg
+ DuckDB `AT (VERSION =>)`, schema evolution via REST `commit-table {
add-schema + set-current-schema }`, `PyIceberg.delete(predicate)`,
upgrade-format-version 2 → 3 via the `pyiceberg_v3` shim, final
TableMetadata tour with refs/schemas/snapshots.

![duckicelake feature tour](demo_videos/duckicelake-demo_no_code.gif)

📥 Full quality:
[`duckicelake-demo_no_code.mp4`](demo_videos/duckicelake-demo_no_code.mp4) (1:13 · 1700×1050 · 0.7 MB)

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

- 19 `pytest` integration tests covering REST surface, cache LRU,
  metrics endpoint, Puffin writer byte-level structure.
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
| GET / POST / DELETE | `/v1/{prefix}/namespaces/{ns}/views[/{v}]` | view CRUD (SQL stored in DuckLake) |
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
│   └── minio.sh                  # MinIO lifecycle
├── src/duckicelake/
│   ├── config.py                 # env-driven settings
│   ├── auth.py                   # OAuth2 + JWT + scope grammar
│   ├── catalog.py                # DuckLake wrapper: PG pool + DuckDB read/write split
│   │                             #   + sidecar tables + LRU metadata cache + S3 client
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
│   ├── sts.py                    # MinIO STS AssumeRole + session policies
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
    └── test_puffin.py            # byte-level Puffin writer tests
```

## Configuration

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
- **Upstream** (other-project-blocked): Spark v3-format writes (Spark
  3.x), DuckDB iceberg-ext v3 features, DuckDB session TZ shifting
  timestamp stats.
- **Production-readiness ops** (deployment work, not code): HA backends,
  TLS / ingress, secret management, backup automation, distributed
  tracing, shipped Grafana dashboards, audit log table, Spark / Trino
  integration tests, sustained-load + chaos benchmarks, multi-platform CI.
