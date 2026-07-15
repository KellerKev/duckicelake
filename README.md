# duckicelake

<p align="center">
  <img src="assets/duckicelake-logo.svg" alt="duckicelake — ducks around an iceberg in a lake" width="640"/>
</p>

<p align="center">
  <b>The governed lakehouse catalog where masking is enforced on the bytes — not in the query.</b><br/>
  An Iceberg REST catalog on DuckLake, with credential vending, byte-level
  PII masking, and an audit trail for every read. Built so nothing —
  human, engine, or LLM agent — can read data it shouldn't.
</p>

---

## The problem

Every lakehouse governance story has the same hole: **the engine reads the
Parquet files, not your policies.** Catalog-level masking rewrites SQL —
which works right up until a client skips the view and opens the file. And
the moment you hand out storage credentials, the catalog is out of the
loop entirely. With LLM agents joining the query path, "please don't look
at the PII" is not a security model.

duckicelake closes that hole, along with two related ones:

1. **Masking that survives any engine.** Policies are enforced down to the
   bytes on object storage — an engine that never sends you SQL still
   can't read what it shouldn't.
2. **Storage-credential enforcement on any S3.** Scoped credentials on
   backends with STS, per-request remote signing on backends without —
   the catalog stays in the loop either way.
3. **A lakehouse you can just `INSERT INTO`.** Write with plain SQL in
   DuckDB *or* via Iceberg REST; readers on either path see it about a
   second later. No sync job.

Under the hood it's an **Iceberg REST Catalog** proxy on top of
**DuckLake**: DuckLake's snapshot/schema/stats state is materialised into
Iceberg-spec manifests on demand, so standard clients — PyIceberg, DuckDB's
`iceberg` extension, Trino, Spark — read Parquet straight from S3 and
write back through spec commits. One `pixi` environment, no Docker.

## See it in 60 seconds

```bash
pixi install
pixi run backends-up && pixi run ducklake-init && pixi run seed-governed
pixi run serve            # Iceberg REST catalog on :8181 — keep it running
```

In a second terminal:

```bash
SLEEP=0 pixi run demo     # authors tags/policies/roles over REST, then
                          # proves the mask: same query, per-principal rows
```

![duckicelake demo](demo_videos/duckicelake-demo_no_code.gif)

📥 Full quality: [`duckicelake-demo_no_code.mp4`](demo_videos/duckicelake-demo_no_code.mp4)
· with source on screen: [`duckicelake-demo_with_code.mp4`](demo_videos/duckicelake-demo_with_code.mp4) (2:52)

## Three hard problems, solved

### 1 · Masking enforced on the bytes — every engine, no exceptions

Tag a column `pii.email`, attach a mask, and flip
`"file-layer-masking": true`. From that point the proxy maintains
**pre-masked Parquet copies** of the table and serves masked principals
**shadow Iceberg metadata** that points at them — while their vended
credentials cover *only* the masked prefix. The base files return **403 at
the storage layer**.

That means the mask holds even for engines that never execute your SQL:

- the DuckDB `iceberg` extension (no view support, no scan planning) scans
  masked bytes transparently through the shadow metadata,
- PyIceberg and raw S3 reads get `al***` because that's what's *in the
  files they're allowed to touch*,
- and a DuckLake-direct DuckDB session gets a reader role whose row-level
  security hides the base files entirely,
- and **Apache Spark** and **Trino**, connecting via the Iceberg REST
  catalog with vended credentials (`uri` + `token`, nothing engine-specific),
  load the shadow metadata + scoped session creds and read masked values —
  verified end-to-end on real AWS S3 (see [Receipts](#receipts)).

No other open catalog we've found does this. Catalog-level masking (view
rewriting) is common; **masked physical copies + shadow metadata +
credential scoping is not.** The cheap tier is still there — policies
default to catalog-level (masking views + metadata signals, no extra
storage) and you opt tables into byte-level per policy.

**What this means for the ecosystem:** governance lives in the catalog and
the object store, *not* the engine. Any Iceberg-REST reader — Spark, Trino,
DuckDB, PyIceberg, and whatever ships next — gets correct masked results with
zero engine-side policy code and no trust placed in the engine, across any
S3-compatible backend (verified on MinIO, Hetzner, and AWS). Governance stops
being per-engine integration work and becomes a property of the table.

One policy set, per-principal results:

```bash
P=localhost:8181/v1/lake/governance; H='content-type:application/json'
curl -sX POST $P/tags        -H $H -d '{"namespace":"pii","name":"email"}'
curl -sX POST $P/object-tags -H $H -d '{"object-kind":"column","schema":"analytics","object":"customers","column":"email","tag-namespace":"pii","tag-name":"email"}'
curl -sX POST $P/masking-policies   -H $H -d '{"name":"mask_email","signature":"(val VARCHAR)","body":"left(val, 2) || '\''***'\''","unmasked-roles":["pii_reader"]}'
curl -sX POST $P/policy-attachments -H $H -d '{"policy-kind":"masking","policy-name":"mask_email","target-kind":"tag","tag-namespace":"pii","tag-name":"email"}'
curl -sX POST $P/roles       -H $H -d '{"name":"pii_reader"}'
curl -sX POST $P/role-grants -H $H -d '{"role":"pii_reader","principal":"alice"}'
```

Now `SELECT * FROM analytics.customers` answers differently by caller —
same table, same query:

```text
 principal bob (no roles)              principal alice (pii_reader)
 id │ email          │ mrr             id │ email             │ mrr
────┼────────────────┼──────          ────┼───────────────────┼──────
  1 │ al***          │ 2400             1 │ alice@example.com │ 2400
  2 │ bo***          │ 1800             2 │ bob@personal.io   │ 1800
```

Row-access policies stack the same way (boolean keep-predicates, `AND`-ed,
evaluated on raw values before masking), and every decision lands in the
audit trail. Full model — tag cascade, one-mask-per-column, upsert/rotate
semantics, the hardening list from two adversarial review passes — in
[docs/REFERENCE.md](docs/REFERENCE.md#governance-reference).

*Receipts:* [`masked_export.py`](src/duckicelake/masked_export.py) ·
byte-proof tests in [`test_governance_phase4.py`](tests/test_governance_phase4.py)
(masked principal's creds: 403 on base keys, 200 on masked copies) ·
run `SLEEP=0 pixi run demo` and read the SQL it prints.

### 2 · Credential enforcement on any S3 — with or without STS

Vended credentials are how the byte-level guarantees reach clients, so the
proxy speaks **three enforcement dialects** and picks per backend:

| Backend has… | Enforcement | How |
|---|---|---|
| STS `AssumeRole` (MinIO, AWS) | per-table/per-export **session policies** | [`sts.py`](src/duckicelake/sts.py) — prefix-scoped creds, Deny carve-outs for masked tables, policy-size degradation handled |
| No STS (e.g. Hetzner) | **remote signing** — every S3 request authorized against governance, SigV4-signed server-side | [`signer.py`](src/duckicelake/signer.py) — Iceberg REST signer protocol; root keys never leave the proxy; revocation is immediate |
| No STS, DuckDB-direct clients | static keys scoped by **generated bucket policies** | [`hetzner_policy.py`](src/duckicelake/hetzner_policy.py) — derives Allow/Deny from live governance state, `--apply` puts it on the bucket |

The no-STS path was **verified against live Hetzner Object Storage
(2026-07-03)**: the full multipart lifecycle through the signer, PyIceberg
driving its own `S3V4RestSigner` against the proxy, file-layer masked
exports materialised on Hetzner with base-byte denial, and the generated
bucket policy enforced — details in [OPERATIONS.md](OPERATIONS.md) and
[MISSING.md](MISSING.md). AWS runs the same code path but hasn't been
exercised against live AWS yet; it's unit-tested only.

For **file-layer masking on a no-STS backend**, a masked reader needs a
**confined static key** (registered `confined=true`) so the proxy can vend it
the masked export instead of failing closed — otherwise the masked table reads
empty. Setup + guarantees in
[docs/file_layer_no_sts.md](docs/file_layer_no_sts.md).

### 3 · `INSERT INTO` your lakehouse

Two write paths, one table, no sync job:

- **Iceberg REST commits** (PyIceberg / Trino / Spark): manifest chain +
  `metadata.json` built inline as part of the commit.
- **Plain SQL** (DuckDB `ATTACH 'ducklake:…'`, then `INSERT` / `UPDATE` /
  `DELETE`): a Postgres `LISTEN`/`NOTIFY` hook fires on the DuckLake
  commit and the proxy eagerly materialises the full Iceberg metadata
  chain on S3 — so a fresh PyIceberg/Trino/Spark reader hits a warm chain
  on its first `LoadTable`, **about a second after the write**.

The eager path is a latency optimisation, not the source of truth: if the
listener is off or dies, the lazy `LoadTable` materialisation still serves
correct data. One listener per fleet is elected via PG advisory lock, with
a startup catch-up scan ([`notify.py`](src/duckicelake/notify.py)).

![architectural proof — same data via Iceberg REST and DuckLake direct](demo_videos/duckicelake-demo_with_code.gif)

The recording ends on the identity check: `DuckLake HEAD == Iceberg
current-snapshot-id`, deterministically. Snapshot ids aren't random, so the
two systems' state lines up directly when you're debugging.

## What makes it different

| | Typical REST catalog + catalog-level masking | duckicelake |
|---|---|---|
| Where masking is enforced | SQL rewrite in the query path | **the bytes on object storage** (plus SQL rewrite for the cheap tier) |
| Engine that reads Parquet directly | sees cleartext | sees masked copies; base prefix 403s |
| Storage credentials | static keys or vendor-specific vending | scoped STS, per-request remote signing, or generated bucket policies — backend's choice |
| Writes | Iceberg commits only | Iceberg commits **and** plain SQL, converging in ~1s |
| LLM agents | prompt-level "please behave" | masked and audited at the catalog; read-only MCP front door |
| Every read audited | rarely | yes — including credential vends, sign requests, and commits |

Every row of that table is backed by a runnable script or test in this
repo — see [Receipts](#receipts).

## The ecosystem: duckicelake + lakesh + agents

```
  Claude / any MCP agent          humans (REPL / scripts)
            │                              │
            ▼                              ▼
      lakesh mcp  (read-only default)   lakesh / psql-style shell
            └──────────────┬──────────────┘
                           ▼
                duckicelake proxy :8181
        masking · row policies · RBAC · audit
        vended scoped credentials / remote signing
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
           S3 (Parquet)        Postgres (DuckLake)
```

[**lakesh**](https://github.com/KellerKev/lakesh) is the companion CLI: a
DuckDB-powered SQL shell for Iceberg REST and DuckLake catalogs, with
connection profiles, OAuth2 token handling, a psql-style REPL, one-shot
`exec` for scripts — and an **MCP server** so LLM agents query the catalog
through the same governed plumbing. Its DuckLake profile accepts the STS
session tokens duckicelake vends, so a governed principal's session is one
`lakesh -p governed` away.

The agent story, end to end: give the agent's token a role without the
`unmasked-roles` bypass, point `lakesh mcp` at the proxy, and the agent
reads `al***` where an analyst holding `pii_reader` reads
`alice@example.com` — through the same API, every access audited, and the
MCP server refuses writes unless you explicitly opt in
(`LAKESH_MCP_WRITE=1`). **Agents can't see PII by construction, not by
prompt.**

### Actor-aware sessions — no separate agent token needed

You don't have to mint a distinct agent principal. A trusted **broker** (a
gateway fronting the proxy for many end users) can assert, per request, both the
effective `principal` *and* a session **context** — `actor=human|agent`,
`channel=rest|mcp` — with `delegate=1`. The context rides into the policy engine
as synthetic `actor:*` / `channel:*` role tags, so the same `unmasked-roles`
machinery drives it: grant humans the bypass tag, withhold it from agents, and a
sensitive column masks for an agent while a human sees cleartext — same user,
same token, decided by *who's driving the session*. Agent sessions are also
read-only at the data plane (write vends refused). Delegation is opt-in, so
existing callers are unaffected. See
[docs/actor_aware_governance.md](docs/actor_aware_governance.md).

duckicelake also ships a **native governed MCP server** (`duckicelake.mcp_server`)
where connecting *is* the agent signal: every call is stamped `actor=agent,
channel=mcp`, and its tools (`list_namespaces`, `list_tables`, `describe_table`,
`query`) execute read-only SQL **server-side and return rows only** — the agent
never receives the DSN or S3 credentials, so it can't slip past a masked view to
the base table.

```bash
pixi run demo-lakesh      # lakesh: REST read vs the vended masked view
```

![lakesh companion demo](demo_videos/lakesh-companion-demo.gif)

📥 Full quality: [`lakesh-companion-demo.mp4`](demo_videos/lakesh-companion-demo.mp4) (0:55)

## Defense in depth

Two enforcement tiers, chosen per policy:

- **Cooperative (default).** Masking views + metadata signals; DuckLake-
  direct sessions get transparent masking via `SET search_path`, so
  unqualified queries hit the masked view without the client changing a
  line. Cheap, no extra storage; a client that names the base table with
  base credentials can still read raw — right for trusted analysts.
- **Airtight (`file-layer-masking: true`).** Pre-masked Parquet + shadow
  metadata + credentials that physically can't reach base bytes + PG
  row-level security hiding the base files (per-principal, per-vend LOGIN
  roles; the RLS predicate plans as a once-per-scan hashed set-membership
  test, not a per-row call).

Failure posture is tiered too: the airtight surfaces and the credential
vend **always fail closed**; the cooperative tier fails open by default
(a governance error degrades to unmasked-with-audit) and
`DUCKICELAKE_GOVERNANCE_FAIL_CLOSED=1` hardens it. Reserved
`duckicelake.*` properties can't be forged by write tokens, export SQL is
injection-escaped, and renames/drops carry or purge their policies so
masks never silently lapse. The full hardening inventory — audited in two
adversarial review passes — is in
[docs/REFERENCE.md](docs/REFERENCE.md#governance-reference).

## Receipts

Claims above, and where they're proven:

- **180+ pytest tests across 18 files**, all against a live
  proxy + MinIO + Postgres stack — including the byte-proofs (masked
  principal's creds 403 on base Parquet, 200 on masked copies), the
  fail-closed regression suite, STS policy-degradation units, and the
  remote-signing path end-to-end with PyIceberg's own signer class.
  [CI](.github/workflows/ci.yml) runs the suite **plus** the full
  `duckdb-client` e2e demo (20+ assertion blocks) on every push.
- **~349 req/s** cache-hit LoadTable at concurrency 32 on one machine;
  **~1s** read-after-write across paths; masked scans **on par with base
  scans** at 1M rows; 4-worker fleet survives killing a worker mid-run.
- **Hetzner Object Storage: live-verified** full sweep (2026-07-03) —
  remote signing, multipart, byte-level masking on real object storage,
  bucket-policy enforcement.
- **Real AWS S3 + STS: live-verified** (eu-central-1, 2026-07-07) — the
  STS path a no-STS backend can't exercise. `AssumeRole` vends per-request
  session credentials scoped by an inline policy, and **AWS enforces it**:
  a masked principal's creds read the masked export (200) and get **403 on
  the raw base Parquet**. Confirmed through *external query engines*, not
  just DuckDB — **Apache Spark 3.5** and **Trino 446** each read the table
  via the Iceberg REST catalog with vended credentials and saw only masked
  values. The same governance ran unchanged across three storage backends
  (MinIO, Hetzner, AWS); only `[s3]`/`[sts]` config differs.
- **Iceberg v3, early**: v3 writes end-to-end (via the
  [`pyiceberg_v3`](src/duckicelake/pyiceberg_v3.py) shim), deletion
  vectors written as **spec-correct Puffin files** byte-by-byte
  ([`puffin.py`](src/duckicelake/puffin.py), verified in
  [`test_puffin.py`](tests/test_puffin.py)), `VARIANT`/`GEOMETRY` types.
- **Multi-tenant**: one proxy serves many isolated catalogs (own PG
  schema + S3 prefix + reader roles per tenant, account-scoped routing) —
  [docs/REFERENCE.md](docs/REFERENCE.md#multi-catalog-isolated-per-tenant-catalogs).
- **Known gaps, written down.** [MISSING.md](MISSING.md) lists what's
  *not* done — worth reading before you deploy.

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
pixi run seed-governed   # sample data + a demo mask (bob masked, alice not)
pixi run smoke           # catalog-only smoke
pixi run duckdb-client   # the full e2e demo (20+ assertion blocks)
pixi run demo            # governance walkthrough + masked-vs-clear SQL proof
pixi run test            # the pytest suite
```

Everything runs out of a single `pixi` environment — no Docker. Teardown:
`pixi run backends-down`. Production backends (real S3 + STS, or Hetzner
with remote signing) are a config swap — see
[docs/REFERENCE.md](docs/REFERENCE.md#requirements) and
[OPERATIONS.md](OPERATIONS.md).

## Query it

**PyIceberg**

```python
from pyiceberg.catalog.rest import RestCatalog

cat = RestCatalog(
    "lake", uri="http://127.0.0.1:8181", warehouse="lake",
    **{"s3.endpoint": "http://127.0.0.1:9000",
       "s3.access-key-id": "minioadmin", "s3.secret-access-key": "minioadmin",
       "s3.region": "us-east-1", "s3.path-style-access": "true"})
print(cat.load_table("analytics.customers").scan().to_arrow().to_pandas())
```

**DuckDB iceberg extension**

```sql
INSTALL httpfs; LOAD httpfs; INSTALL iceberg; LOAD iceberg;
CREATE OR REPLACE SECRET ice_s3 (
    TYPE S3, KEY_ID 'minioadmin', SECRET 'minioadmin',
    REGION 'us-east-1', ENDPOINT '127.0.0.1:9000',
    USE_SSL false, URL_STYLE 'path');
ATTACH 'lake' AS ice (
    TYPE ICEBERG, ENDPOINT 'http://127.0.0.1:8181',
    AUTHORIZATION_TYPE 'none', ACCESS_DELEGATION_MODE 'none');
SELECT * FROM ice.analytics.customers;
```

**lakesh**

```bash
lakesh config init && lakesh doctor
lakesh exec -q 'SELECT count(*) FROM analytics.customers'
lakesh                    # REPL: \l, \d analytics, SELECT …
```

Time-travel, joins across snapshots, per-client footnotes, and the
governed-read walkthrough: [docs/REFERENCE.md](docs/REFERENCE.md#sample-data--querying).

## Current state

Alpha. Shipped and tested today: the full Iceberg
REST surface (v2 + v3), the hybrid write model, tags/RBAC/masking/row
policies with both enforcement tiers, per-principal reader roles + RLS,
credential vending across all three backend dialects, multi-catalog
tenancy, OAuth2, audit, Prometheus observability.

Known boundaries — the short version (full list in
[MISSING.md](MISSING.md)):

- Dev-stack Postgres runs `trust` auth; RLS *authentication* is only real
  under production `scram-sha-256` + TLS ([OPERATIONS.md](OPERATIONS.md)
  has the recipe).
- AWS STS is code-correct and unit-tested but not yet run against live
  AWS; Hetzner is live-verified.
- Not yet built: a dedicated agent-role convention layer, Spark/Trino
  integration tests, HA/ops hardening (tracing, dashboards, chaos runs).

## Docs map

| Doc | What's in it |
|---|---|
| [docs/REFERENCE.md](docs/REFERENCE.md) | the full reference: [requirements](docs/REFERENCE.md#requirements), [what's in the box](docs/REFERENCE.md#whats-in-the-box), [governance internals](docs/REFERENCE.md#governance-reference), [endpoints](docs/REFERENCE.md#endpoint-summary), [configuration](docs/REFERENCE.md#configuration), [layout](docs/REFERENCE.md#layout), [AWS setup](docs/REFERENCE.md#running-against-real-aws-s3--sts) |
| [OPERATIONS.md](OPERATIONS.md) | production runbook — HA, pg_hba, backups, Hetzner, PromQL |
| [ARCHITECTURE.md](ARCHITECTURE.md) | design rationale + Iceberg spec coverage |
| [MISSING.md](MISSING.md) | what's not done yet |
| [docs/multi_catalog_isolation.md](docs/multi_catalog_isolation.md) | multi-tenant isolation design |
| [docs/actor_aware_governance.md](docs/actor_aware_governance.md) | actor-aware sessions — broker delegation, actor/channel context, native MCP |
| [github.com/KellerKev/lakesh](https://github.com/KellerKev/lakesh) | the companion SQL shell + MCP server |
