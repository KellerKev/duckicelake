# Operations runbook

Target audience: SREs / ops engineers running `duckicelake` in front of a
shared lakehouse. Not a tutorial — assumes you've already got it working
via the README and need to turn it into something on-call-worthy.

## Deployment topology

```
          load balancer / ingress (TLS termination, rate limit)
                             │
             ┌───────────────┼───────────────┐
             ▼               ▼               ▼
         duckicelake    duckicelake    duckicelake        ← N FastAPI workers
          (worker 1)    (worker 2)    (worker 3)            (stateless)
             │               │               │
             └──────┬────────┼───────┬───────┘
                    ▼        ▼       ▼
              ┌─────────┐  ┌──────────────┐
              │ Postgres│  │   S3 / MinIO │
              │  (HA)   │  │   (HA/quorum)│
              └─────────┘  └──────────────┘
```

Workers are fully stateless except the in-process metadata cache (which
is a read-through hint, not authoritative). Scale horizontally behind
any L7 load balancer. All coordination flows through Postgres —
DuckLake's snapshot allocator serialises writes atomically regardless of
how many workers race on the same table.

## Minimum environment

| Variable                            | Recommended for prod                 |
|-------------------------------------|--------------------------------------|
| `DUCKICELAKE_PG_HOST`               | PgBouncer VIP or RDS endpoint        |
| `DUCKICELAKE_PG_PORT`               | `5432`                               |
| `DUCKICELAKE_PG_USER`               | Dedicated role, no superuser         |
| `DUCKICELAKE_PG_DATABASE`           | Dedicated DB per environment         |
| `DUCKICELAKE_CATALOG`               | `lake` (or per-env)                  |
| `DUCKICELAKE_S3_ENDPOINT`           | `https://s3.<region>.amazonaws.com`  |
| `DUCKICELAKE_S3_REGION`             | Real region                          |
| `DUCKICELAKE_S3_BUCKET`             | Dedicated bucket with versioning on  |
| `DUCKICELAKE_S3_ROOT_KEY/SECRET`    | IAM role creds via IRSA / Vault / EC2 IAM |
| `DUCKICELAKE_S3_PREFIX`             | `catalog/` or per-tenant             |
| `DUCKICELAKE_OAUTH_CLIENTS_FILE`    | Mounted secret with JSON of clients  |
| `DUCKICELAKE_OAUTH_JWT_SECRET`      | 32+ bytes random, rotate quarterly   |
| `DUCKICELAKE_OAUTH_TTL_SECONDS`     | `3600`                               |
| `DUCKICELAKE_REQUIRE_AUTH`          | `1` — safety belt, fails boot if auth is off |
| `DUCKICELAKE_LOG_FORMAT`            | `json`                               |
| `DUCKICELAKE_LOG_LEVEL`             | `INFO` (drop to `DEBUG` per incident) |
| `DUCKICELAKE_CACHE_MAX`             | `1024` default; raise for >1k tables |

Start with:
```
pixi run serve-hi   # uvicorn --workers 4 --log-level warning
```
or equivalent gunicorn/uvicorn invocation behind your process manager.
`--workers` should roughly equal CPU cores, bounded by Postgres pool
capacity (each worker opens its own pool of up to 16 conns).

## Liveness / readiness / metrics

| Path        | Purpose                                         | HTTP probe |
|-------------|-------------------------------------------------|------------|
| `/healthz`  | Liveness — 200 if the process is alive          | Every 10 s |
| `/readyz`   | Readiness — 200 only if Postgres responds       | Every 5 s  |
| `/metrics`  | Prometheus scrape                               | Every 15 s |

All three are exempt from auth. Keep them reachable from your orchestrator's probe source but **not** from the public ingress — anyone hitting `/metrics` gets a detailed fingerprint of your workload.

### Dashboards

Minimum useful set:
- `histogram_quantile(0.95, rate(duckicelake_request_seconds_bucket[5m]))` by endpoint
- `rate(duckicelake_requests_total{status!~"2.."}[5m])` by endpoint — error rate
- `rate(duckicelake_commit_total{outcome="ok"}[5m])` — commit rate
- `duckicelake_metadata_cache_size / duckicelake_metadata_cache_max` — cache pressure
- `duckicelake_pg_pool_in_use / (duckicelake_pg_pool_in_use + duckicelake_pg_pool_idle)` — PG saturation

### Alerting (SLO-style)

- **Availability**: `/readyz` failing on >50% of workers for 2 min → page.
- **Latency**: p95 LoadTable > 1s for 5 min → warn.
- **Commit errors**: any non-auth 5xx on `POST /v1/*/tables/*` → page.
- **Cache eviction rate**: `duckicelake_metadata_cache_size` plateaued at `_max` with continuous misses → warn; consider raising `DUCKICELAKE_CACHE_MAX`.
- **PG pool exhaustion**: `pool_in_use == pool_size` for 30 s → warn.

## Backup & restore

**Authoritative state** lives in two places:
1. **Postgres** — `ducklake_*` + `duckicelake_*` schema tables. Both sets must be snapshotted together; restoring one without the other produces a coherent DuckLake view but loses sidecar properties/tags/partition specs/nan counts.
2. **S3** — Parquet data files + Avro manifests + `vN.metadata.json` + `version-hint.text`.

Recommended backup cadence:
- Postgres: continuous WAL archive + daily base backup. Use your managed DB's snapshot feature; RTO is usually under an hour.
- S3: enable versioning on the bucket and a 90-day lifecycle transition to Glacier. A separate cross-region replication target for disaster recovery.

**Point-in-time recovery**:
1. Roll Postgres back to the chosen timestamp.
2. For any S3 objects deleted after that timestamp, restore from the bucket's version-delete marker (all our deletes are soft via versioning, assuming you enabled it).
3. Restart workers so the in-process cache rebuilds from the restored state.

**What you don't need to back up**: the workers themselves. They're stateless.

## Upgrades

### Rolling worker upgrade
1. Bump image/version on one worker at a time.
2. Drain via load balancer before stopping (SIGTERM, uvicorn honours it for ~30s grace).
3. Confirm `/readyz` returns 200 on the new worker, then move to the next.

DuckLake catalog schema changes between DuckLake versions are handled automatically by DuckLake at ATTACH. Our sidecar tables (`duckicelake_*`) use `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE IF NOT EXISTS ADD COLUMN` migrations inside `_ensure_sidecar`, run on first use. Safe to roll forward.

**Never run mixed DuckLake versions against the same Postgres catalog** — direct-Postgres mutations we issue for tombstones/sort/delete files assume the DuckLake schema the binary was built against.

### Postgres failover
Standard managed-DB procedure. Our workers survive transient disconnects via `psycopg_pool`'s reconnect-on-failure, but a primary failover of >30s will cause in-flight requests to 5xx. Ingress-level retries mitigate.

## Compaction

DuckLake's compaction isn't automatic. Schedule per-table:
```bash
curl -XPOST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$DUCKICELAKE/v1/lake/admin/namespaces/$NS/tables/$TBL/compact"
```
Response is `{schema, table, merge, cleanup}` with each sub-op reporting `"ok"` or an error string. Safe to run on a cron — each call is idempotent.

Recommended: hourly for hot tables, daily for cold tables. Tables with heavy position-delete/equality-delete churn benefit most; read-only tables get no benefit.

## Storage lifecycle

S3 objects under `<data_prefix>/<ns>/<tbl>/`:

| Pattern                            | Written by              | Ownership after |
|------------------------------------|-------------------------|-----------------|
| `ducklake-<uuid>.parquet`          | DuckLake or client write | DuckLake — freed by `ducklake_cleanup_old_files` once tombstoned past retention |
| `ducklake-<uuid>-delete.parquet`   | Client (pos-delete)     | Same             |
| `ducklake-eqdel-<id>-<uuid>.parquet` | Proxy (eq-delete)     | Same             |
| `metadata/snap-*.avro`, `*-m[01]-*.avro` | Proxy materialise | Proxy only — reclaimed by DROP TABLE purge |
| `metadata/vN.metadata.json`        | Proxy materialise       | Same             |
| `metadata/version-hint.text`       | Proxy materialise       | Same             |

Lifecycle rule suggestions (AWS S3):
- `metadata/*` keys older than 30 days but not the current `vN.metadata.json` — transition to IA, delete at 180 days.
- Non-current Parquet versions (if versioning is on): delete at 30 days.
- Table prefix stays permanent; DROP TABLE with `purgeRequested=true` cleans it explicitly.

## Auth / RBAC

Production defaults:
- `DUCKICELAKE_REQUIRE_AUTH=1` — startup fails if no clients configured.
- JWT secret rotated via blue/green deploy: bring up new workers with new secret + dual-accept; drain old; remove old secret. TTL of existing tokens drains naturally.
- Per-scope grammar in the clients file:
  ```json
  {
    "spark-etl":     {"secret": "...", "scope": "*"},
    "dbt-reader":    {"secret": "...", "scope": "ns:analytics:r,ns:raw:r"},
    "pyiceberg-job": {"secret": "...", "scope": "ns:analytics:rw"}
  }
  ```
- Token inspection: decode without verification to debug scope issues:
  ```
  echo $TOKEN | cut -d. -f2 | base64 -d | jq
  ```

### Governance reader roles (Phase 3a)

`ducklake-credentials` vends per-principal PG roles
(`duckicelake_p_<sub>_<sha8>`, group `duckicelake_reader`) with RLS on the
`ducklake_*` catalog tables. The dev stack's trust-auth cannot enforce
authentication — production must run Postgres with
`password_encryption = scram-sha-256` + TLS and pg_hba in this order:

```
hostssl ducklake ducklake             <proxy-host>/32  scram-sha-256  # owner: proxy only
host    ducklake ducklake             0.0.0.0/0        reject
hostssl ducklake +duckicelake_reader  <client-cidr>    scram-sha-256  # all vended principals
```

The proxy's role: non-superuser owner of the `ducklake_*` tables with
`CREATEROLE`. Vended passwords are per-request, never persisted, and expire
with the STS creds (`VALID UNTIL`, connect-time check). Mandate
`log_statement = none` (or `ddl`-exclusion) for the proxy role so `ALTER
ROLE … PASSWORD` never lands in server logs. Expired roles are GC'd lazily
by the proxy; `SELECT * FROM duckicelake_pg_principal` shows the live set.

### Owner-role authentication (password)

The owning role connects by socket `trust` in dev and can use cert/ident in
prod. For managed Postgres (RDS, Supabase, Neon, Cloud SQL) that requires a
scram password, set **`DUCKICELAKE_PG_PASSWORD`** (or `[pg] password` in
`duckicelake.toml`) — it flows into every owner connection via `pg_dsn` and
is redacted (`password=***`) from the startup log and `bootstrap` output.
The value is embedded in a libpq conninfo *and* a DuckDB `ATTACH` string
literal, so it must be **conninfo-safe: no spaces, quotes, or backslashes**
(the proxy refuses to start otherwise). Keep `log_statement = none` for the
proxy role as above.

**Caveat — RLS off:** with `DUCKICELAKE_RLS=0`, `ducklake-credentials` vends
the *owner* DSN to clients (the documented cooperative fallback); that DSN
now carries the owner password. Keep RLS **on** in production so clients only
ever receive per-principal reader roles.

## Known operational risks

1. **DuckLake schema drift**: direct Postgres INSERT/UPDATE of `ducklake_delete_file`, `ducklake_sort_info`, `ducklake_data_file.end_snapshot`. A minor DuckLake version bump that changes these could silently break commits. **Mitigation**: pin DuckLake in `pixi.toml`, subscribe to DuckLake release notes, run the full integration suite before any version bump.
2. **In-process cache divergence between workers**: after a commit, the committing worker's cache is primed; other workers miss once, re-materialise, then hit. No correctness issue — just a small latency spike on first post-commit read from other workers. Tune `DUCKICELAKE_CACHE_MAX` down if RSS matters more than cold-start latency.
3. **Equality-delete amplification**: each call emits one position-delete Parquet per affected data file. Without compaction the `ducklake-eqdel-*` files accumulate; scan performance degrades. Fix: run compact on a cron.
4. **DROP TABLE without purge**: leaks `metadata/*` Avros until a human cleans them up. Recommend wrapping at the client level — always pass `?purgeRequested=true` unless you specifically want to recover.
5. **Version-hint race**: if a worker crashes after writing `vN.metadata.json` but before `version-hint.text`, the next LoadTable rematerialises to `vN+1` (correct), but the `vN` file is orphaned. Bucket lifecycle eventually reclaims it.

## Troubleshooting

### Cold start is slow
First request after deploy rematerialises every loaded table. Expected. If it matters, warm the cache with a scripted GET-all-tables after each deploy.

### Clients see stale metadata
Check `duckicelake_commit_total` + `/readyz` on the committing worker — the commit may have failed after the PG tx commit but before the S3 write landed. Rare (atomicity is in PG, not S3), but possible on crash. Force-refresh via a write-no-op commit.

### High latency on a single table
- Check manifest Avro size on S3 (`aws s3 ls s3://bucket/prefix/metadata/`). If >50 MB, compact.
- Check Parquet count. If >1000 data files, compact.
- Check `duckicelake_file_nan_count` sidecar size — a pathological table with many float columns each flagged as containing NaN triggers one DuckDB scan per (file, column) first time.

### PG pool saturation
Raise `min_size`/`max_size` on the pool, or (better) add PgBouncer in front of Postgres and point workers at it. Our `psycopg_pool` itself caps at `max_size=16` per worker.

### Auth errors spike
`duckicelake_requests_total{status="4xx"}` by endpoint → if `/v1/oauth/tokens` 4xx rate jumps, check `DUCKICELAKE_OAUTH_CLIENTS` load — misconfigured env produces `501` on token endpoint, and clients retry-loop.

## Pin versions

`pixi.toml` pins:
- `duckdb` / `python-duckdb` — pin to minor; bump explicitly after running full tests.
- `psycopg` / `psycopg-pool` — pin to minor.
- `pyiceberg` — loose pin (`>=0.10,<1`) but test against upstream before each release.
- `boto3` / `botocore` — loose pin; AWS-side API rarely breaks.

For each deploy, record the exact `pixi.lock` content in your deploy log so rollback is byte-deterministic.
