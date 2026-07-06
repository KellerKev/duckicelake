# File-layer masking without STS (e.g. Hetzner Object Storage)

## The problem

File-layer masking is the **airtight** tier: the proxy materialises per-`(table,
mask-signature)` masked Parquet exports under `data/__masked__/…`, and masked
principals are meant to read *those* while the raw base bytes are physically
`403`. On backends with **STS**, a masked principal gets a short-lived session
token scoped to the masked-signature prefix, so this is turnkey.

Backends with **no STS at all** (Hetzner Object Storage) have no per-request
scoped tokens — only long-lived **static keys** whose access is governed by the
bucket policy (see [REFERENCE.md](REFERENCE.md), no-STS section). A masked
principal can't be handed a scoped STS token, and `ducklake-credentials`
**fails closed** for a masked principal holding a plain static key: it can't
prove at vend time that the key is confined to the *current* masked-signature
prefix (signatures rotate when a policy changes), so it refuses rather than risk
a base-byte read. The consequence is that the masked export is unreadable too —
the table returns **zero rows** for that principal. Airtight, but unusable.

## Confined static keys

A **confined** static key resolves this. Register the reader's key with
`confined=true` to *attest* that the bucket policy keeps it confined:

- **Deny** `s3:GetObject` on every file-layer table's **base** prefix, and
- **Allow** `s3:GetObject` on only the **current masked-signature export**
  prefix (plus any non-file-layer prefixes the principal may read).

That layout is exactly what `python -m duckicelake.hetzner_policy` emits, and it
is kept current as signatures rotate by re-running it. Given the attestation,
`ducklake-credentials` **vends the key to file-layer-masked principals**
(`"enforcement": "bucket-policy-confined"`) instead of failing closed: the raw
bytes stay physically unreadable, so serving the masked export is safe.

```jsonc
// POST /v1/{prefix}/governance/static-s3-keys
{
  "principal": "alice",
  "access-key-id": "KU2MB3JY2B1ZX374EYHU",
  "secret-access-key": "…",      // optional; enables turnkey vending
  "confined": true
}
```

`confined` defaults to `false` (the pre-existing fail-closed behaviour), so
nothing changes for existing keys until you opt in.

### Confinement strength

- **Cross-project key (strongest).** Mint the reader key in a *different*
  Hetzner project. Cross-project keys start with **no** access, so the `Allow`
  statements are *positive* confinement — the key can reach exactly the granted
  prefixes and nothing else.
- **Same-project key.** Project-scoped keys already have full bucket access, so
  `Allow` is redundant and only the **`Deny` carve-outs** enforce. Still
  airtight for the raw base prefix, but the `Deny` denies that prefix to
  **every** principal sharing the key — you can't have one principal masked and
  another see raw on the same key. Use cross-project keys for per-principal
  differentiation.

## Turnkey setup

For a table `<schema>.<table>` in catalog `<catalog>`, masked for principals who
hold key `<key>`:

```bash
# 1. Register the reader key(s) as confined
curl -XPOST …/v1/lake/governance/static-s3-keys \
  -d '{"principal":"alice","access-key-id":"<key>","secret-access-key":"…","confined":true}'

# 2. Author a file-layer masking policy + attach it (via tag or column)
curl -XPOST …/v1/lake/governance/masking-policies \
  -d '{"name":"mask_amt","signature":"(val DOUBLE)","body":"0.0","file-layer-masking":true}'
curl -XPOST …/v1/lake/governance/policy-attachments \
  -d '{"policy-kind":"masking","policy-name":"mask_amt","target-kind":"tag",
       "tag-namespace":"pii","tag-name":"secret"}'

# 3. Materialise the export (any vend for the table does this)
curl …/v1/<catalog>/namespaces/<schema>/ducklake-credentials?table=<table>&principal=alice

# 4. Lay down the bucket policy (Deny base + Allow masked-sig)
python -m duckicelake.hetzner_policy --apply --catalog <catalog>
```

## How reads resolve (readable **and** airtight)

- **Unqualified reference** (`SELECT … FROM events`): the transparent-masking
  `search_path` routes it to the masked view, which reads the **export** —
  masked values, **readable** with the confined key. The catalog-wide vend
  (a `?table`-less DuckLake-direct ATTACH, e.g. a query engine that can't name a
  single table) also routes every file-layer table to its export view, so
  single-node / multi-table readers get masked data, not an empty base read.
- **Schema-qualified reference** (`SELECT … FROM main.events`): resolves to the
  raw **base** table, whose bytes the bucket policy **denies** → the read
  returns nothing (never cleartext). This is the airtight guarantee the
  cooperative (view-only) tier can't give.

## Cross-catalog note (multi-tenant)

Governance authoring is gated to the **default** catalog (`settings.catalog_name`,
e.g. `lake`), but policies key by `(schema, table)` and apply to per-account
catalogs (e.g. `acme__main`). Two consequences:

- The masked-export SELECT is qualified against the catalog the export
  connection actually ATTACHes (`ref.catalog_name`), not the global default —
  otherwise it fails with *"Catalog 'lake' does not exist"* and silently falls
  back to cooperative masking.
- `hetzner_policy` scans **one** catalog's tables per run, so apply it per
  account catalog: `--catalog acme__main`. (A multi-catalog sweep over all
  provisioned catalogs is a reasonable enhancement.)

## Caveats & operations

- **Re-run `hetzner_policy` when a policy changes.** A new mask shape rotates the
  signature → a new export prefix. Until the bucket policy is re-applied to
  `Allow` the new prefix, masked reads fail **closed** (empty), never leak.
- **Distributed over a single export file** falls back to single-node execution
  (still masked + readable); sharding kicks in once an export spans ≥2 files.
- **Time travel is denied** on file-layer tables (there's no per-historical
  masked export) — see [REFERENCE.md](REFERENCE.md).
