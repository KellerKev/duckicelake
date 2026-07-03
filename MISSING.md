# Missing / Deferred

Short, honest punch list of what's not in duckicelake — with reasons.

## Genuinely blocked on DuckLake / architecture

**`void` partition transform.** Iceberg's "drop the field from the spec"
no-op. Zero semantic gain in DuckLake's model — submit a fresh
`add-partition-spec` without the field instead. 501.

**True divergent branches.** DuckLake has no branching concept — all
snapshots form a single chain. See
[DuckLake discussion #194](https://github.com/duckdb/ducklake/discussions/194);
no roadmap. We synthesise `main` (always DuckLake HEAD) + named **tags**
and **read-only branches** via a sidecar table, which covers most Iceberg
branch-use-cases (snapshot pinning, release-name labeling,
`AT (VERSION => 'release_1')`). A `set-snapshot-ref` with `type: branch`
on a non-main ref is accepted as a read-only pointer; writes targeting
that branch 501.

**Per-table `set-location`.** DuckLake owns file layout via the
catalog's attach-time `DATA_PATH`. Per-table overrides aren't
expressible; DuckLake
[issue #580](https://github.com/duckdb/ducklake/issues/580)
and [PR #126](https://github.com/duckdb/ducklake/pull/126) confirm the
current state (schema-relative paths were added but absolute per-table
write locations are still frozen). 501.

**Full KMS envelope encryption.** Iceberg supports per-file
`key_metadata` for KMS-unwrapped DEKs. DuckLake writes per-file
encryption keys and exposes them in `ducklake_data_file.encryption_key`;
we surface those bytes in the manifest's `key_metadata` field, which
closes the metadata gap for compliance-aware readers. A real AWS
KMS / Vault / Azure KV envelope would require DuckLake core changes.

**Spark v3-format writes.** Spark 3.x can't write v3 manifest lists;
Spark 4.0 has native v3 write. We can't patch Spark from here. PyIceberg
clients running our `pyiceberg_v3` shim work fine; Trino similarly
depends on its own `iceberg-core` upgrade.

**DuckDB iceberg-extension v3 features.** DuckDB 1.5.x reads
v3 manifests but treats `variant` / `geometry` as `UNKNOWN` and is
read-only on v3. Use PyIceberg for v3-typed scans, or DuckDB's native
spatial / VARIANT types directly on DuckLake (bypassing the Iceberg
layer). Tracked upstream in `duckdb-iceberg`.

## Upstream-side quirks we work around

**DuckDB session TZ for timestamp stats.** DuckDB's default TZ is
process-local. TIMESTAMPTZ micros in stats get shifted by the local
offset, which then propagates into the `day` partition-bound. Writers
should `SET TimeZone='UTC'` for predictable stats
([duckdb #6604](https://github.com/duckdb/duckdb/issues/6604)). Demo
does this automatically; document it for any custom client code.

## Production-readiness gaps

The Iceberg spec surface is effectively complete; what's left is
deployment / operational work on top of a correct catalog. The items
below describe what you still need before putting duckicelake in front
of real users. Most are external config, not code changes to this repo.

### Ops infrastructure (hard blockers)

**HA backends.** Single Postgres, single S3 endpoint (the dev stack's
MinIO). Workers are stateless and scale horizontally, but they all talk
to one backend. If PG goes down, everything 503s. Production needs RDS
Multi-AZ / Patroni for Postgres and an HA, STS-capable S3 backend (or
MinIO with quorum if self-hosting). Out of scope for this repo; flagged
in [OPERATIONS.md](OPERATIONS.md).

**TLS + ingress.** Uvicorn serves HTTP. You need nginx/envoy/ALB in front
for TLS termination, rate limiting, WAF, request-size caps. Standard L7
gateway config — not built-in and not planned.

**Secret management.** `DUCKICELAKE_OAUTH_JWT_SECRET` + S3 root creds are
env vars. Production needs Vault / AWS Secrets Manager / IRSA / Azure KV
feeding them, plus a documented rotation runbook (dual-accept → drain
old workers → remove old secret).

**Root-key distribution is the prod no-go.** Response configs omit the root
MinIO key pair **by default** (`suppress_root_creds = true`); clients rely
on vended STS creds (`X-Iceberg-Access-Delegation` on the REST path, the
`ducklake-credentials` endpoint for DuckLake-direct). Flipping it off
(`DUCKICELAKE_SUPPRESS_ROOT_CREDS=0` or `suppress_root_creds = false` in
`duckicelake.toml`) makes the governance masking layer bypassable in one
line — dev-only. The vended PG DSN is a per-principal RLS-governed reader
role — but the dev stack's trust-auth means PG *authentication* is only
real under production scram+TLS; see the pg_hba recipe in
[OPERATIONS.md](OPERATIONS.md).

**Backup automation.** [OPERATIONS.md](OPERATIONS.md) describes the shape
(`pg_dump` of `ducklake_*` + `duckicelake_*` schema, S3 versioning, cross-
region replication, lifecycle rules). You still have to schedule it,
test restore, and alert on backup failures.

### Data-integrity risks

**Direct-Postgres writes to DuckLake internal tables.**
`tombstone_data_files`, `register_delete_files`, `set_sort_order`,
equality-delete + Puffin DV emission all INSERT/UPDATE directly into
`ducklake_*` tables because DuckLake doesn't expose public procs for
these operations. DuckLake is pre-1.0-stable on schema. A minor version
bump could silently break commits. **Mitigation**: pin the exact DuckLake
version in `pixi.toml`, run the full pytest + demo suites against new
DuckLake versions before upgrading, subscribe to DuckLake release notes.

**No two-phase commit across DuckDB / PG / S3.** We have one PG
transaction per commit for sidecar ops (`commit_transaction()`
context), but DuckDB-side `ducklake_add_data_files` calls and S3
manifest writes are separate. A process crash between them leaves
orphaned files (S3 manifests) or orphaned metadata (DuckLake rows with
no S3 data file). DuckLake's own `ducklake_cleanup_old_files` reclaims
data-file orphans eventually; our manifest Avros linger until
`DROP TABLE ?purgeRequested=true` or a scripted sweep.

**Cross-worker cache coherence.** Each worker has its own in-process
LRU. Property / tag / partition-spec sidecar writes don't bump
DuckLake's snapshot id, so the committing worker primes its cache but
other workers serve stale metadata until they hit and re-read the
sidecar (mitigation baked in via the cache-hit sidecar-refresh path).
For low-concurrency catalogs this is fine; for 100+-worker fleets,
consider replacing the in-process LRU with a shared Redis cache.

### Observability gaps

**No distributed tracing.** Prometheus metrics + JSON logs are in but
there are no OpenTelemetry spans. Debugging a slow commit that touches
DuckDB + PG + S3 means correlating logs by timestamp. ~half-day to add
`opentelemetry-instrumentation-fastapi` + `opentelemetry-instrumentation-psycopg`
+ an OTLP exporter.

**No shipped dashboards.** [OPERATIONS.md](OPERATIONS.md) lists the
PromQL queries for an SLO dashboard (p95 LoadTable latency, commit
error rate, cache hit-rate, pool saturation) but the Grafana JSON isn't
in the repo. An operator builds them on first deploy.

### Testing gaps

**No Spark / Trino integration tests.** The pytest suite covers
PyIceberg + DuckDB iceberg-ext + REST-direct + the Puffin writer. Real
production deployments will also connect Spark and Trino, which catch
different bugs (v2 vs v3 shape divergences, partition-spec edge cases,
write-mode properties). Run `spark-iceberg` or a Trino Docker image
against the proxy before shipping to users.

**No live AWS STS run.** The STS vending path is AWS-shaped (regional
STS endpoint, configurable role ARN, session-policy size degradation,
MaxSessionDuration retry — unit-tested), but has **not been run against
live AWS STS**. Before shipping on AWS: smoke the vend → read → write
flow against a real role.

**Hetzner: live-verified 2026-07-03** against a real Hetzner bucket
(fsn1): pre-provisioned-bucket bootstrap, DuckDB httpfs TLS writes,
LoadTable → remote-signing config, signed GET/PUT (UNSIGNED-PAYLOAD
accepted by Ceph RGW), file-layer masked export materialized on
Hetzner with base-bytes denial + masked-bytes reads through the signer,
no-STS fail-closed vending, and the **bucket-policy tier applied live
on a throwaway bucket**: `PutBucketPolicy` accepted the generated
per-key Principal ARN (`arn:aws:iam:::user/p<project>:<key>`), the
masked-base **Deny carve-out was enforced** (AccessDenied even for the
bucket-owning key) while allowed and masked-copy prefixes stayed
readable, the policy stayed bucket-local, and deleting it restored
access. Still unverified live: cross-key isolation with a *second*
access key granted Allow-only access (Hetzner has no API for S3
credential creation — Console-only — so that needs a manually minted
key). Notes from the live run: default botocore checksums did NOT trip
the documented `AccessDenied` on `put_object` (Hetzner may have added
checksum support; `when_required` stays configured — correct on every
backend), and `CreateBucket`/`DeleteBucket` work via the S3 API with
~2s visibility propagation.

**No sustained-load benchmarks.** We measured ~349 req/s once, 4 workers,
cache-hit. No p99 latency tracking, no soak tests, no pool-saturation
tests. `locust` / `k6` hitting `/v1/.../tables/<t>` at realistic
concurrency will surface the actual ceiling + any slow leaks.

**No chaos testing.** Kill a worker mid-commit, fail over Postgres,
partition the network to S3, inject 503s. Toxiproxy between workers
and each backend catches a lot of partial-failure bugs.

**Single-platform CI.** [.github/workflows/ci.yml](.github/workflows/ci.yml)
runs `ubuntu-latest`. [pixi.toml](pixi.toml) declares `osx-arm64`,
`osx-64`, `linux-64`, `linux-aarch64`. Matrix-test those before claiming
multi-platform support.

### Concrete pre-prod punch list (ROI order)

- **Day 1** — pin DuckLake exact version. Set `DUCKICELAKE_REQUIRE_AUTH=1`
  + configure OAuth clients. Put TLS + rate limiting in front (nginx /
  envoy / ingress). Deploy Postgres HA. Enable S3 versioning +
  cross-region replication.
- **Day 2** — wire OpenTelemetry tracing. Build Grafana dashboards from
  the `/metrics` queries in [OPERATIONS.md](OPERATIONS.md).
- **Day 3** — run Spark + Trino against the proxy, fix what breaks.
  Smoke the credential path against your REAL backend (AWS STS or
  Hetzner remote signing). Matrix-test CI across your target platforms.
- **Day 4** — load-test with realistic concurrency + payload shapes.
  Tune `DUCKICELAKE_CACHE_MAX`, `psycopg_pool` `max_size`, uvicorn
  worker count. Document the tuned values in your deploy config.
- **Day 5** — chaos-test via Toxiproxy. Rehearse Postgres failover +
  S3-unavailable scenarios. Write + rehearse the restore runbook.

After that, you're at "ready for real users" for small-to-medium
internal deployments. Multi-tenant isolation is implemented (per-catalog
PG schemas + S3 prefixes + account-scoped routing — see the README's
Multi-catalog section); enterprise-regulated workloads (full KMS
envelope, Spark-write branches, SOC 2 audit automation) still need
upstream work we can't do here.

## Everything else

Everything else in the Iceberg REST spec is now either implemented
(see [ARCHITECTURE.md](ARCHITECTURE.md)) or falls under one of the
categories above. If a commit action you care about hits a 501 in
practice and isn't in this doc, it's a gap — open an issue.
