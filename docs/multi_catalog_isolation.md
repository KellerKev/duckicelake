# Multi-catalog isolation (qod integration)

## Goal

Today the proxy serves exactly one DuckLake catalog: a single `catalog_name`
("lake"), one `pg_database`, one S3 `bucket` + `data_prefix`, attached once by a
process-global `DuckLakeCatalog`. The qod integration needs the proxy to serve
**many isolated catalogs from one instance**, one per tenant, where a tenant's
data is invisible to every other tenant.

Isolation model (chosen): **one Postgres schema + one S3 prefix per catalog**,
inside the shared Postgres database and shared bucket.

## Enabling primitive (verified)

DuckLake's `ATTACH` accepts `METADATA_SCHEMA`:

```sql
ATTACH 'ducklake:postgres:<dsn>' AS cat
  (DATA_PATH 's3://<bucket>/<tenant>/<catalog>/',
   METADATA_SCHEMA '<tenant-schema>',
   DATA_INLINING_ROW_LIMIT 0);
```

This places that catalog's `ducklake_*` metadata tables in `<tenant-schema>` and
its Parquet under a disjoint prefix. Confirmed on the installed extension
(`ducklake 415a9ebd`): the option is accepted; an unknown option errors with
"Unsupported option". `DATA_INLINING_ROW_LIMIT 0` stays a hard invariant (RLS
coverage depends on no inlined data — see `pg_rls.py`).

## Naming contract

The metadata-schema and data-prefix names are derived deterministically by the
orchestration layer and handed to the proxy per request — the proxy does not
invent them. Contract: `metadata_schema = dl_<slug>__<catalog>`,
`data_prefix = <slug>/<catalog>/`, slug/catalog are `^[a-z][a-z0-9_]{1,30}$`
with no `__`. The proxy treats `(metadata_schema, data_prefix)` as opaque,
validated identifiers.

## Where single-catalog is assumed today

| Location | Assumption |
|---|---|
| `config.py` `Settings.catalog_name` / `pg_database` / `s3.data_prefix` | one global catalog |
| `config.py` `ducklake_data_path`, `S3Settings.table_prefix/masked_*_prefix` | one data root |
| `catalog.py` `DuckLakeCatalog` (process singleton) | one DuckDB write conn + read pool + metadata cache, all for one catalog |
| `catalog.py` `_build_duckdb_conn` (ATTACH at ~L215) | one ATTACH, no `METADATA_SCHEMA` |
| `catalog.py` `_cat()` | one catalog alias |
| `catalog.py` metadata cache keyed `(ns, table)` | not catalog-aware |
| `server.py` `/v1/config` + `ducklake-credentials` (ATTACH strings ~L900/937) | one catalog/data path |
| `pg_rls.py` | RLS policies target `ducklake_*` in the default schema |
| `masked_export.py` / `sts.py` | export + STS prefixes rooted at the single `data_prefix` |

## Proposed shape

1. **CatalogRef** — a small value object `(catalog_id, metadata_schema,
   data_prefix)`. Replaces the single global identity. The Iceberg REST
   `{prefix}` path segment maps to a `catalog_id`; the authenticated principal's
   account constrains which `catalog_id`s are reachable (cross-account access =
   404, the hard boundary).

2. **Catalog registry** instead of one `DuckLakeCatalog`. Options:
   - (a) one `DuckLakeCatalog` instance per active catalog, lazily built and
     LRU-evicted (bounded number of attached catalogs per process); or
   - (b) one shared connection that `ATTACH`es each catalog under a distinct
     alias on demand and `USE`s the right one per request.
   Lean (a) for isolation clarity; cap concurrent attachments, evict idle.
   The metadata cache key gains `catalog_id`.

3. **Per-catalog ATTACH** adds `METADATA_SCHEMA` + the catalog's `DATA_PATH`.
   `S3Settings` gains a per-catalog `data_prefix` override (or prefix helpers
   take a `CatalogRef`). `table_prefix`/`masked_*_prefix` compose under it.

4. **pg_rls** per-catalog: reader group + RLS policies are created against the
   catalog's metadata schema; per-principal LOGIN roles are scoped so a reader
   can only see its own account's schema. Account is the outer guard; RLS +
   masking remain the intra-account guard.

5. **Bootstrap/provisioning**: a "create catalog" entry point that creates the
   Postgres schema, runs the DuckLake init against it, and arms RLS — invoked by
   the orchestration layer when an account/catalog is created.

6. **Backward compatibility**: keep a default `CatalogRef` equal to today's
   single-catalog config (default `metadata_schema = public`/current,
   `data_prefix` unchanged) so the existing 80-test suite passes unchanged while
   the multi-catalog path is added alongside.

## Phasing

- **P1a** — introduce `CatalogRef` + thread it through `_build_duckdb_conn`
  ATTACH (add `METADATA_SCHEMA`) and the prefix helpers, with a default ref
  preserving current behavior. No routing change yet; tests green.
- **P1b** — registry of catalogs keyed by `catalog_id`; map Iceberg REST
  `{prefix}` → ref; account constrains reachable refs.
- **P1c** — per-catalog provisioning (schema create + DuckLake init + RLS arm)
  and per-catalog `pg_rls`/`masked_export`/`sts` prefixes.
- **P1d** — `ducklake-credentials` and `/v1/config` emit the per-catalog
  ATTACH (schema + prefix), so DuckLake-direct and the FlightSQL gateway attach
  the right isolated catalog.

## Open questions

- Attachment cap + eviction policy when an instance serves many tenants.
- Whether per-account reader roles are minted per-catalog or per-account
  (a principal with several catalogs in one account).
- Connection-pool sizing across catalogs (today: one write conn + 2 read +
  a PG pool, all single-catalog).
