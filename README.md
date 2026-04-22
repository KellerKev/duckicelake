# duckicelake

An **Iceberg v3 REST Catalog** proxy on top of **DuckLake v1.0**, with
MinIO-backed object storage and real STS credential vending. Materialises
DuckLake's snapshot/schema/stats state into Iceberg-spec manifests on
demand, so standard Iceberg clients (PyIceberg, DuckDB's `iceberg`
extension) read rows directly from S3.

```
  Iceberg REST client (PyIceberg, DuckDB iceberg ext, Trino, Spark, …)
              │  HTTP (Iceberg OpenAPI v3)
              ▼
       FastAPI proxy (duckicelake.server)
          │                     │
          │  SQL                │  STS AssumeRole (scoped session policy)
          ▼                     ▼
   DuckDB + ducklake       MinIO STS
          ├──▶ Postgres    (mints per-request temp credentials)
          │    (ducklake_* metadata: snapshots, schemas, stats, deletes)
          └──▶ MinIO S3 API
               ├── data/<ns>/<tbl>/ducklake-<uuid>.parquet              (data)
               ├── data/<ns>/<tbl>/ducklake-<uuid>-delete.parquet       (position deletes)
               └── data/<ns>/<tbl>/metadata/
                     ├── v1.metadata.json                 (TableMetadata, format-version=3)
                     ├── snap-<id>-<uuid>.avro            (manifest list, one per snapshot)
                     ├── <id>-<uuid>-m0-data.avro         (data manifest with stats + row_id)
                     └── <id>-<uuid>-m1-deletes.avro      (position-delete manifest)
                   ▲
                   │ Vended creds let clients read all of these
                   │ directly from S3, without the proxy on the data path.
```

Everything runs out of a single `pixi` environment — no Docker.

## Architectural decisions

See [ARCHITECTURE.md](ARCHITECTURE.md) for full rationale — summary:

- **Write path:** Iceberg-client writes work via **register-in-place**.
  Every commit action in the Iceberg REST spec is either translated to
  a DuckLake operation (append / delete / overwrite / replace, position
  deletes, equality deletes, partition specs — including `truncate[N]`
  via a sidecar — sort orders, schema evolution, properties, tags,
  read-only branches, snapshot removal) or rejected with a specific
  501 for the architectural reasons (set-location, writes on non-main
  branches, `void` transform, v3 format-version writes). Full mapping
  in [ARCHITECTURE.md](ARCHITECTURE.md). **Partition pruning** works
  end-to-end: per-file partition values land in manifests with Iceberg-
  correct semantics (time-based transforms recomputed server-side where
  DuckLake diverges; truncate values synthesised from source min).

  All preserve the single-writer invariant: every commit ends as rows
  in DuckLake's Postgres tables inside one transaction, never two
  writers racing. `set-location` returns 501 because DuckLake owns
  file layout via the catalog's attach-time `DATA_PATH`.
- **Equality deletes** are spec-scoped: the proxy scans each live data
  file for rows matching the delete keys and emits per-file Iceberg
  position-delete Parquets registered against those files only. Data
  files written in later snapshots are never retro-deleted.
- **`key_metadata`** is surfaced from `ducklake_data_file.encryption_key`
  in every manifest entry (null for unencrypted catalogs). Real KMS
  envelope integration remains on the deferred list.
- **`nan_value_counts`** are exact — computed by a one-shot DuckDB
  `read_parquet(... WHERE isnan(col))` scan the first time a float
  column is materialised with `contains_nan=true`, then cached.
- **Materialisation is lazy** (read-time, content-addressed cache keyed
  on DuckLake snapshot id). UniForm had to go eager because HMS/REST
  gave them no lazy hook; we own the REST surface so we can avoid the
  staleness window their async pattern introduces.
- **Iceberg snapshot-id == DuckLake snapshot-id**, deterministically.
  UniForm uses random int64s (a wart from reusing iceberg-core); we
  correlate explicitly and expose it as a property.

## What works end-to-end

- **Iceberg REST Catalog, format-version 3**
  - `/v1/config`, namespace CRUD, table CRUD, rename
  - `LoadTable` returns inline TableMetadata (no client re-fetch from S3 needed)
  - `LoadTable?snapshot-id=N` pins a historical snapshot for time-travel
  - `CommitTable` supports `add-schema` / `set-current-schema` /
    `set-properties` updates (DDL via REST)
  - **Views API**: create / list / load / drop
- **Snapshot chain, materialised from DuckLake**
  - One Iceberg snapshot per DuckLake commit, linked via `parent-snapshot-id`
  - `snapshot-log`, `refs.main` branch, sequence numbers
  - Client-side `AT (VERSION => N)` time travel works for both PyIceberg
    and DuckDB iceberg ext
- **Per-file column statistics in manifests**
  - `value_counts`, `null_value_counts`, `nan_value_counts`
  - `lower_bounds` / `upper_bounds` with Iceberg-spec binary encoding
    (little-endian for ints/floats/timestamps, big-endian two's-complement
    for decimals, UTF-8 for strings, 16-byte BE for UUIDs)
  - Pulled from `ducklake_file_column_stats` per data file
- **Row lineage** (Iceberg v3)
  - `first_row_id` on each manifest entry (from DuckLake's `row_id_start`)
  - `last-row-id` + `row-lineage: true` in TableMetadata
- **Position-delete files** — `ducklake_delete_file` translated into
  `content=1` manifest entries with `referenced_data_file` populated
- **Schema evolution**
  - Historical schemas via `ducklake_column.begin_snapshot / end_snapshot`
  - `schemas[]` in TableMetadata carries all versions the table has had
  - REST commit `add-schema` + `set-current-schema` diffs column IDs and
    issues ADD / DROP COLUMN through DuckLake
  - `initial-default` and `write-default` propagated
- **Iceberg v3 types**
  - `variant` ↔ DuckDB `VARIANT`
  - `geometry` / `geography` ↔ DuckDB `GEOMETRY` (via the `spatial` extension)
  - `timestamp_ns` / `timestamptz_ns` ↔ DuckDB `TIMESTAMP_NS`
  - `decimal(p, s)`, `uuid`, `date`, `time`, `boolean`, and all primitive numerics
- **OAuth2 client-credentials auth with RBAC scopes** (opt-in)
  - `POST /v1/oauth/tokens` issues HMAC-signed JWTs; middleware enforces
    `Authorization: Bearer` on every `/v1/*` route except `/v1/config`
    and the token endpoint itself.
  - **Scope grammar** embedded in the JWT: `ns:<name>:<cap>` (per-namespace
    permission) or `*` (superuser). `cap ∈ {r, w, rw, *}`. Catalog-level
    writes (create namespace, drop namespace) require a wildcard-
    namespace scope. Readers see 403 Forbidden on out-of-scope paths.
  - Configure via `DUCKICELAKE_OAUTH_CLIENTS="id:secret|scope,id2:sec2|scope2"`
    or `DUCKICELAKE_OAUTH_CLIENTS_FILE=<path>` (JSON). Scope defaults to `*`.
  - PyIceberg consumes via `credential="id:secret"`, DuckDB via
    `CREATE SECRET (TYPE ICEBERG, TOKEN '<token>')`.
- **STS credential vending**
  - `X-Iceberg-Access-Delegation: vended-credentials` triggers real MinIO
    `AssumeRole` with a session policy scoped to the table's specific
    data-file keys + its `metadata/*` prefix
  - `s3.access-key-id` / `s3.secret-access-key` / `s3.session-token` /
    `s3.credentials-expiration` in the Iceberg `config` map

## Error discipline

No silent fallbacks. `pixi run duckdb-client` is assertion-based: if any
client returns the wrong rows, the demo fails. The only `except` clauses
in `src/` are:

- [bounds.py](src/duckicelake/bounds.py) catches its own
  `UnsupportedBoundType` to cleanly omit columns that don't have an
  Iceberg-spec bound encoding (variant, geometry, geography). Parse errors
  for types we *do* claim to handle propagate.
- [bootstrap.py](src/duckicelake/bootstrap.py) catches `ClientError` with
  error code 404 to detect "bucket doesn't exist yet → create it". Other
  codes re-raise.
- [smoke.py](src/duckicelake/smoke.py) catches `Exception` from `resp.json()`
  in a pretty-printer to fall back to raw text on non-JSON bodies.

## Demo output (abridged)

`pixi run duckdb-client`:

```
=== REST LoadTable: multi-snapshot chain + row lineage + stats ===
  format-version:     3
  current-snapshot:   12
  snapshots in chain: 3
    snap  10  parent=None  op=append  added_rows=0
    snap  11  parent=10    op=append  added_rows=2
    snap  12  parent=11    op=append  added_rows=4
  last-row-id: 4  row-lineage: True
  refs: {'main': {'type': 'branch', 'snapshot-id': 12}}

=== PyIceberg: current scan + time-travel to first-with-data ===
  snapshots=3  current=12  first-with-data=11
  current: [{'id':1,'name':'page_view','price':Decimal('9.99')}, ...]
  @11:     [{'id':1,'name':'page_view'}, {'id':2,'name':'click'}]

=== DuckDB iceberg ext: current + AT (VERSION => first-with-data) ===
  current: [(1,'page_view'), (2,'click'), (3,'conversion'), (4,'page_view')]
  @11:     [(1,'page_view'), (2,'click')]

=== DELETE via DuckLake, then verify both clients see post-delete state ===
  DuckLake raw:                   [(1,'page_view'), (3,'conversion'), (4,'page_view')]
  DuckDB iceberg ext post-delete: [(1,'page_view'), (3,'conversion'), (4,'page_view')]
  PyIceberg post-delete:          [{'id':1,'name':'page_view'}, {'id':3,'name':'conversion'}, {'id':4,'name':'page_view'}]

=== REST commit: add-schema → new 'channel' column via ALTER TABLE ===
  schemas after commit: 2
  current fields: ['id','name','ts','price','channel']

=== Create analytics.events_v3 with VARIANT + GEOMETRY; write+read via DuckDB ===
  (1, '{"src":"ios"}',                        'POINT (-73.9 40.7)')
  (2, '{"src":"web","flags":[1,2,3]}',        'POINT (2.35 48.85)')
  (3, '{"src":"android","nested":{"k":"v"}}', 'POINT (139.7 35.7)')

=== PyIceberg loads events_v3 through the REST catalog (v3 types recognised) ===
  field  1  id         type=long      required=True
  field  2  payload    type=variant   required=False
  field  3  location   type=geometry  required=False
```

## Quickstart

```bash
pixi install
pixi run backends-up     # Postgres + MinIO
pixi run ducklake-init   # creates bucket + default namespace
pixi run serve           # Iceberg REST catalog on :8181
```

In another terminal:

```bash
pixi run smoke           # catalog-only smoke
pixi run duckdb-client   # the full v3 demo
```

Teardown: `pixi run backends-down`.

## Endpoint summary

| Method   | Path                                                  | Notes |
|----------|-------------------------------------------------------|-------|
| GET      | `/v1/config`                                          | catalog prefix + endpoint allowlist |
| GET/POST/DELETE | `/v1/{prefix}/namespaces[/{ns}]`               | schema CRUD |
| GET      | `/v1/{prefix}/namespaces/{ns}/tables`                 | list |
| POST     | `/v1/{prefix}/namespaces/{ns}/tables`                 | CREATE TABLE with Iceberg schema |
| GET      | `/v1/{prefix}/namespaces/{ns}/tables/{tbl}`           | LoadTable; optional `?snapshot-id=N` |
| DELETE   | `/v1/{prefix}/namespaces/{ns}/tables/{tbl}`           | DROP TABLE |
| POST     | `/v1/{prefix}/namespaces/{ns}/tables/{tbl}`           | commit: add-schema, set-current-schema, set-properties |
| POST     | `/v1/{prefix}/tables/rename`                          | same-namespace rename |
| GET/POST/DELETE | `/v1/{prefix}/namespaces/{ns}/views[/{v}]`     | view CRUD (SQL stored in DuckDB) |

## Layout

```
duckicelake/
├── pixi.toml
├── pyproject.toml
├── MISSING.md               # what's deferred + client rough spots
├── scripts/
│   ├── pg.sh                # Postgres lifecycle
│   └── minio.sh             # MinIO lifecycle
└── src/duckicelake/
    ├── config.py            # settings
    ├── catalog.py           # DuckLake wrapper; snapshot/schema/stats queries
    ├── types.py             # Iceberg ↔ DuckDB ↔ DuckLake type translation
    ├── bounds.py            # Iceberg binary bound encoders
    ├── iceberg.py           # TableMetadata scaffold
    ├── manifest.py          # Iceberg v2 Avro writers (data + delete manifests)
    ├── materialize.py       # full snapshot-chain materialiser
    ├── sts.py               # MinIO STS AssumeRole + session policies
    ├── models.py            # Pydantic REST models
    ├── server.py            # FastAPI app (catalog + views + DDL commits)
    ├── bootstrap.py         # pixi run ducklake-init
    ├── smoke.py             # catalog smoke
    └── duckdb_client.py     # full v3 demo
```

## Configuration (env vars)

| Var                          | Default                       |
|------------------------------|-------------------------------|
| `DUCKICELAKE_PG_HOST`        | `<repo>/.pgsock`              |
| `DUCKICELAKE_PG_PORT`        | `55432`                       |
| `DUCKICELAKE_PG_USER`        | `ducklake`                    |
| `DUCKICELAKE_PG_DATABASE`    | `ducklake`                    |
| `DUCKICELAKE_CATALOG`        | `lake`                        |
| `DUCKICELAKE_S3_ENDPOINT`    | `http://127.0.0.1:9000`       |
| `DUCKICELAKE_S3_REGION`      | `us-east-1`                   |
| `DUCKICELAKE_S3_BUCKET`      | `lakehouse`                   |
| `DUCKICELAKE_S3_ROOT_KEY`    | `minioadmin`                  |
| `DUCKICELAKE_S3_ROOT_SECRET` | `minioadmin`                  |
| `DUCKICELAKE_S3_PREFIX`      | `data/`                       |
| `DUCKICELAKE_OAUTH_CLIENTS`  | *(empty → auth disabled)* — `id1:secret1,id2:secret2` |
| `DUCKICELAKE_OAUTH_CLIENTS_FILE` | *(empty)* — JSON file alternative |
| `DUCKICELAKE_OAUTH_JWT_SECRET` | *required when clients are configured* — HMAC key |
| `DUCKICELAKE_OAUTH_TTL_SECONDS` | `3600`                      |
| `DUCKICELAKE_OAUTH_ISSUER`   | `duckicelake`                 |

## DuckDB iceberg extension: configuration notes

Three things worth knowing (all handled automatically by
[duckdb_client.py::_iceberg_client_con](src/duckicelake/duckdb_client.py)):

- **Attach with `ACCESS_DELEGATION_MODE 'none'`**. Without this, the iceberg
  extension builds its own S3 secret from the REST `config` with a path-
  scoped lifetime, and a use_ssl/path-style-access conflation in its config
  parser produces signatures MinIO rejects on delete-file HEAD. Setting
  `ACCESS_DELEGATION_MODE 'none'` takes an early return in
  `IcebergTableEntry::PrepareIcebergScanFromEntry` so DuckDB uses the
  regular `CREATE SECRET (TYPE S3, ...)` like any other httpfs operation.
- **Don't set `allow_moved_paths=true`** on `iceberg_scan`. It engages a
  debug path-joiner (`IcebergUtils::GetFullPath`) that mangles absolute
  `s3://` URIs. With it off (default), the extension follows absolute
  manifest-list URIs correctly.
- **Snapshot `timestamp-ms` must be ≤ client's transaction-start**.
  `IcebergTableEntry::GetSnapshot` uses transaction-start time as the
  snapshot-lookup anchor. We backdate DuckLake snapshots by 1s on write to
  win the race; see [manifest.py::build_snapshot](src/duckicelake/manifest.py).

## PyIceberg: teaching it v3 types

PyIceberg 0.10/0.11 hard-codes a list of Iceberg primitive types in a
pydantic validator and rejects `variant` / `geometry` / `geography` at
`load_table` time. [`pyiceberg_v3.install()`](src/duckicelake/pyiceberg_v3.py)
monkey-patches `IcebergType.handle_primitive_type` at startup to recognise
these as minimal `PrimitiveType` subclasses. Call it once in client code
before any `RestCatalog` operation.

## What's left out

See [MISSING.md](MISSING.md) for the honest punch list. Headline items
are Puffin deletion vectors, true divergent branches, per-table
`set-location`, full KMS envelope encryption, and v3 format-version
writes (pending PyIceberg/Spark writer support).
