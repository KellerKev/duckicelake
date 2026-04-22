# Architecture decisions

## How Iceberg-client writes work

Iceberg writers — PyIceberg `Table.append()`, `Table.add_files()`, and
the equivalent on Spark/Trino/Flink/DuckDB — go through this path:

1. **Client uploads Parquet** via its own FileIO using credentials we
   vended on `LoadTable`. Files land somewhere under
   `s3://<bucket>/<data_prefix>/<ns>/<table>/data/...`.
2. **Client uploads its own manifest + manifest-list Avros** alongside,
   computing per-file stats from the Parquet footers it just wrote.
3. **Client POSTs `commit-table { updates: [add-snapshot] }`** with the
   manifest-list URI.
4. **Proxy reads the manifest-list** ([read_manifest.py](src/duckicelake/read_manifest.py)),
   filters to manifests whose `added_snapshot_id` matches this commit
   (skipping inherited ones — they're already registered), extracts the
   list of newly-added data-file paths.
5. **Proxy calls `ducklake_add_data_files()`** ([catalog.py](src/duckicelake/catalog.py))
   with that list. DuckLake re-reads each Parquet footer for record
   count + per-column stats, allocates row IDs, inserts rows into
   `ducklake_data_file` + `ducklake_file_column_stats`, and bumps its
   snapshot counter — **all inside one Postgres transaction**.
6. **Next `LoadTable` materialises a fresh Iceberg snapshot chain**
   (lazy, content-addressed), advertising the new state to all clients.

PyIceberg's `add_files` (register existing Parquet) goes through the
exact same code path — same `add-snapshot` shape, just with files the
client uploaded earlier.

### Why this works

- **Single writer to Postgres.** DuckLake is the only thing that touches
  `ducklake_*` tables. Our commit handler is just a translator that
  invokes a DuckLake procedure. There is no race between two metadata
  writers.
- **DuckLake takes ownership of files.** Once registered, compaction and
  expiration treat them like files DuckLake wrote itself. The client's
  staging location becomes the canonical home (no copy needed).
- **No trust in client-supplied stats.** The Iceberg manifest the client
  wrote claims `record_count`, `lower_bounds`, etc. We ignore those and
  let DuckLake re-read the Parquet footer. PyIceberg, Polaris, Nessie,
  and Lakekeeper all already trust footer stats — we trust them once,
  via DuckLake.
- **Optimistic concurrency works.** Iceberg's
  `assert-ref-snapshot-id` requirement is checked against
  `current_ducklake_snapshot()` before applying. Two clients racing on
  the same table: first wins, second gets 409 with
  `CommitFailedException`. Standard Iceberg semantics.

### Verified end-to-end

`pixi run duckdb-client` exercises:

```
=== Iceberg-client write: PyIceberg.append → DuckLake registers via ducklake_add_data_files ===
  created analytics.orders via PyIceberg.create_table
  after PyIceberg.append #1: 3 rows, 2 snapshots
  after PyIceberg.append #2: 5 rows, 3 snapshots
  DuckDB iceberg ext reads back: [(101, 'alice'), …, (202, 'eve')]
  DuckLake SQL reads back:      [(101, 'alice'), …, (202, 'eve')]
  ✓ writes round-trip across PyIceberg → DuckDB iceberg ext → DuckLake SQL

=== Optimistic concurrency: stale assert-ref-snapshot-id → 409 ===
  409 CommitFailedException: assert-ref-snapshot-id=main expected 99999, current is 10
```

### Three write operations are now supported

| Iceberg op       | What client does                                        | What proxy translates to |
|------------------|---------------------------------------------------------|--------------------------|
| `append`         | Uploads Parquet, manifest with status=1 entries         | `ducklake_add_data_files()` |
| `delete(pred)`   | Uploads (file_path, pos) Parquet, content=1 manifest    | INSERT into `ducklake_delete_file` (direct Postgres) |
| `overwrite(...)` | Uploads new Parquet (status=1) + tombstones (status=2)  | `ducklake_add_data_files()` + UPDATE `end_snapshot` |

[server.py::commit_table](src/duckicelake/server.py) parses the manifest
chain in [read_manifest.py::extract_commit_changes](src/duckicelake/read_manifest.py)
and dispatches each operation type to a corresponding handler in
[catalog.py](src/duckicelake/catalog.py).

The `delete` and `overwrite` paths use **direct Postgres mutation**
(INSERT into `ducklake_delete_file`, UPDATE `ducklake_data_file.end_snapshot`)
because DuckLake doesn't expose public procedures for these — verified
by reading the v1.0 source. The patterns we use match what DuckLake
itself does internally:

- `UPDATE ducklake_data_file SET end_snapshot = N` is the canonical
  tombstone — used by DuckLake's own compaction and overwrite paths
  (`ducklake_metadata_manager.cpp:1984` / `4176`).
- The position-delete Parquet schema is `(file_path: VARCHAR, pos:
  BIGINT)` — DuckLake's reader accepts exactly the Iceberg-standard
  format (`ducklake_delete_filter.cpp:151-165`).
- Snapshot allocation: read the latest `ducklake_snapshot` row, INSERT
  a new one with bumped `next_file_id`, write a `ducklake_snapshot_changes`
  audit record. All inside one psycopg transaction.

This is **undocumented DuckLake territory** — it relies on schema
internals that DuckLake is free to change. We tag every direct INSERT/UPDATE
with a comment pointing at the source line in DuckLake that does the
same thing, so a future schema break is at least debuggable.

### Verified end-to-end

```
=== Iceberg-client write: PyIceberg.delete(predicate) → ducklake_delete_file ===
  PyIceberg post-delete: [101, 103, 201, 202]
  DuckDB iceberg ext sees: [(101,), (103,), (201,), (202,)]
  ✓ Iceberg position-delete-file → ducklake_delete_file → cross-client read

=== Iceberg-client write: PyIceberg.overwrite(df, predicate) → tombstone + add ===
  PyIceberg post-overwrite: [101, 103, 900:replaced1, 901:replaced2]
  DuckDB iceberg ext sees: same
  DuckLake SQL sees:       same
  ✓ overwrite (status=2 tombstone + status=1 add in one commit) → all 3 clients agree
```

### Partition spec + sort order commits

| Iceberg op              | Proxy translation |
|-------------------------|-------------------|
| `add-partition-spec`    | `ALTER TABLE … SET PARTITIONED BY (…)` via DuckDB SQL |
| `add-sort-order`        | INSERT into `ducklake_sort_info` + `ducklake_sort_expression` (direct Postgres) |
| `set-default-spec`      | no-op — `ALTER SET PARTITIONED BY` makes the new spec default already |
| `set-default-sort-order`| no-op — same pattern |

Transform mapping (Iceberg → DuckLake):

| Iceberg         | DuckLake           | Notes |
|-----------------|--------------------|-------|
| `identity`      | bare column ref    | |
| `year` / `month` / `day` / `hour` | same              | |
| `bucket[N]`     | `bucket(N, col)`   | |
| `truncate[N]`   | sidecar spec       | Stored in `duckicelake_table_partition_field`; values synthesised per file from source `min_value` at emit time (DuckLake itself doesn't physically partition on truncate). |
| `void`          | **501**            | Drop the field from the new spec instead — no semantic upside to accepting. |

Current partition spec + sort order are read back on every `LoadTable`
and advertised as `partition-specs[1]` (spec-id 0 is always empty) and
`sort-orders[1]` respectively, with `default-spec-id` / `default-sort-
order-id` pointing at them. PyIceberg's `table.spec()` and
`table.sort_order()` return the same info.

`set-location` returns 501 — DuckLake owns file layout via the
catalog's `DATA_PATH` (set at attach time). Per-table location overrides
aren't expressible; moving data requires a fresh attach.

### All commit actions, mapped

| Iceberg op | Proxy translation |
|---|---|
| `add-snapshot` (append) | `ducklake_add_data_files()` |
| `add-snapshot` (overwrite, replace, delete) | tombstone + add in one commit |
| `add-snapshot` targeting non-main branch | 501 (DuckLake has no branching) |
| position-delete file (content=1) | INSERT into `ducklake_delete_file`; for v3 tables, materialize rewrites these into a single Puffin file with one `deletion-vector-v1` blob per data file (Roaring64 bitmap) and emits the manifest entry with `file_format=puffin` + `content_offset` + `content_size_in_bytes` |
| equality-delete file (content=2) | per-file scan → emit Iceberg position-delete Parquets → register (seq-scoped: files with `begin_snapshot < commit_snap` only) |
| `add-schema` + `set-current-schema` | ALTER TABLE ADD/DROP COLUMN (diff by field-id) |
| `add-partition-spec` native-only | `ALTER TABLE … SET PARTITIONED BY (…)` |
| `add-partition-spec` with truncate[N] | sidecar `duckicelake_table_partition_field` (values synthesised from source min_value at emit) |
| `add-partition-spec` with void | 501 (no-op — drop the field from the new spec instead) |
| `add-sort-order` | direct INSERT into `ducklake_sort_info` + `ducklake_sort_expression` |
| `set-properties` / `remove-properties` | sidecar `duckicelake_table_property` table |
| `set-snapshot-ref` type=tag | sidecar `duckicelake_table_tag` table |
| `set-snapshot-ref` type=branch ref=main | no-op (main follows DuckLake HEAD) |
| `set-snapshot-ref` type=branch ref=other | sidecar entry with `ref_type='branch'` — read-only pointer; writes targeting it 501 |
| `remove-snapshot-ref` | sidecar row delete |
| `remove-snapshot` | `ducklake_expire_snapshots(catalog, versions := […])` |
| `assign-uuid` | accepted no-op (we derive UUID deterministically) |
| `upgrade-format-version` to ≤2 | accepted no-op; to 3 → 501 (writer ecosystem not ready) |
| `add-statistics` / `remove-statistics` | accepted no-op (we synthesise stats from DuckLake) |
| `set-location` | 501 (DuckLake owns layout via attach-time DATA_PATH) |
| manifest `key_metadata` | surfaced from `ducklake_data_file.encryption_key` when catalog is encrypted, null otherwise |
| manifest `nan_value_counts` | exact count via DuckDB `read_parquet(... WHERE isnan(col))` scan, cached in `duckicelake_file_nan_count` sidecar |

### LoadTable response includes

Everything needed for Iceberg readers in one round-trip:

- `format-version: 2` (writer-friendly; v3 fields as tolerated extras)
- `schemas[]` with full history
- `partition-specs[]` with the current spec at `default-spec-id`
- `sort-orders[]` similarly
- `properties{}` — user-provided via `set-properties`, plus
  `ducklake.snapshot-id` (the canonical-id correlate, UniForm-style)
- `refs{}` — `main` always points at DuckLake HEAD; tags from sidecar
- `snapshots[]` — one per DuckLake snapshot with per-file stats
  (`lower_bounds`/`upper_bounds`/counts), per-file partition values
  (`day`/`month`/`year`/`hour` recomputed from source bounds since
  DuckLake's semantics differ), and row-lineage `first_row_id`
- `snapshot-log[]` — ordered history; `summary.operation` reflects
  DuckLake's `ducklake_snapshot_changes.changes_made` (append/delete/
  overwrite/replace)
- `metadata-log[]` — every `vN.metadata.json` we've published
- `metadata-location` — resolves from `version-hint.text` so non-REST
  readers can follow the convention

### Partition pruning works

Per-file partition values land in the manifest Avro with Iceberg-correct
semantics. Verified with PyIceberg pushdown:

```
country='US':         2/3 files read  (FR pruned via identity)
country='FR':         1/3 files read  (US pruned)
ts >= 2026-04-22 UTC: 1/3 files read  (day-20563 pruned via day transform)
```

The partition-value pipeline:

1. **Avro schema** for `data_file.partition` is dynamic —
   [manifest.py::_partition_avro_schema](src/duckicelake/manifest.py) emits
   one Avro field per partition-spec field with the Iceberg-correct type
   (`day`/`month`/`year`/`hour`/`bucket[N]` → `int`; `identity` preserves
   source type; `null`-able per Iceberg spec).
2. **Per-file values** come from `ducklake_file_partition_value` for
   `identity` and `bucket[N]` (DuckLake's hash aligns with Iceberg's
   `(murmur3 & INT_MAX) % N` — verified).
3. **Time-based values are recomputed** from the file's source-column
   `min_value` in `ducklake_file_column_stats`, because DuckLake's
   `day`/`month`/`year`/`hour` store day-of-month / month-of-year /
   calendar-year / hour-of-day respectively — *not* Iceberg's
   days-since-epoch / months-since-epoch / years-since-1970 /
   hours-since-epoch. [iceberg_transforms.py](src/duckicelake/iceberg_transforms.py)
   does the conversion.

One session-TZ gotcha worth knowing: DuckDB's default TZ is the process's
local TZ. TIMESTAMPTZ micros round-trip correctly only when the session
TZ matches what the caller wrote. The demo and any production caller
should `SET TimeZone='UTC'` on the DuckDB connection used for writes.

### Earlier (now-revised) reasoning

A previous iteration of this doc claimed write rejection was the
correct design pattern, citing UniForm and XTable. That conflated two
things — UniForm rejects writes because Delta is the canonical writer
**and** because no `delta_add_data_files`-equivalent existed in their
target. The DuckLake project landed
[`ducklake_add_data_files()`](https://ducklake.select/docs/stable/duckdb/metadata/adding_files)
to do exactly the register-in-place operation, and Iceberg's own
`Table.add_files` is built around the same shape. Combined, the path
fits cleanly: clients submit a normal `add-snapshot` commit, the proxy
translates it into a DuckLake procedure call, DuckLake remains the
sole writer of catalog state, and snapshot identity stays
deterministic.

## Why materialisation is lazy (read-time), not eager (commit-time)

Same as before: we own the REST surface so we materialise on read,
content-addressed on `ducklake_snapshot.snapshot_id`. UniForm had to go
eager because HMS/REST is pull-only. Lazy avoids the staleness window,
ref-counting/queueing, and write-amp on idle tables. See
[materialize.py::materialize_all](src/duckicelake/materialize.py).

## Why snapshot-ids are deterministic on DuckLake ids

Same as before: we use `ducklake_snapshot.snapshot_id` directly as the
Iceberg snapshot-id, not random int64s like UniForm/iceberg-core. This
gets us byte-deterministic re-materialisation (the cache trivially
works), immediate correlation with DuckLake's catalog, and the
mechanics of the new write path (where DuckLake allocates the snap-id
and we surface it back) come for free.

## Format-version is 2 (writeable), not 3

We declare format-version 2 by default. PyIceberg 0.11 still raises
`Cannot write manifest list for table version: 3` and Spark/Trino are
in similar shape. v3-specific fields we already populate
(`row-lineage`, `last-row-id`, variant/geometry types in the schema)
are tolerated as extras by v2 readers. Bumping back to 3 is a one-line
change once writer support across the ecosystem catches up.

## Source pointers

- Write path: [server.py::commit_table](src/duckicelake/server.py),
  [read_manifest.py](src/duckicelake/read_manifest.py),
  [catalog.py::add_data_files](src/duckicelake/catalog.py)
- Optimistic concurrency: [server.py::_check_requirements](src/duckicelake/server.py)
- STS write policy (multipart-upload-aware): [sts.py::_scoped_policy](src/duckicelake/sts.py)
- Lazy materialisation: [materialize.py::materialize_all](src/duckicelake/materialize.py)
- OAuth2: [auth.py](src/duckicelake/auth.py)
