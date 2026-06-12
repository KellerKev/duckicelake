#!/usr/bin/env bash
# Query the governed duckicelake catalog through `lakesh`
# (https://github.com/KellerKev/lakesh) — the DuckDB-powered SQL CLI for
# Iceberg REST / DuckLake catalogs.
#
# Prereqs:
#   - a duckicelake proxy running (default :8181) with the governance demo
#     already authored — run ./scripts/governance_demo.sh first.
#   - `lakesh` on PATH  (pip install -e '.[dev]' in the lakesh repo)
#   - `jq`
#
# This shows lakesh going through the real Iceberg REST -> DuckDB iceberg-ext
# path: an UNMASKED base query, then the masking the proxy decided for a
# principal, applied via the engine-generated view SQL fetched live.
#
# Tunables:
#   BASE=http://127.0.0.1:8181     proxy base URL
#   S3_ENDPOINT=http://127.0.0.1:9100   object store the proxy serves (MUST match)
#   PRINCIPAL=bob                  principal to resolve masking for
#   SLEEP=10                       seconds between steps (0 to go fast)
set -uo pipefail

BASE="${BASE:-http://127.0.0.1:8181}"
S3_ENDPOINT="${S3_ENDPOINT:-http://127.0.0.1:9100}"
PRINCIPAL="${PRINCIPAL:-bob}"
SLEEP="${SLEEP:-10}"
WAREHOUSE="lake"
CAT="ice"                         # lakesh attaches the REST catalog under this alias
P="$BASE/v1/$WAREHOUSE/governance"

step() { echo; echo "==== $* ===="; }
pause() { [ "$SLEEP" -gt 0 ] && { echo "(sleeping ${SLEEP}s…)"; sleep "$SLEEP"; } || true; }

command -v lakesh >/dev/null 2>&1 || { echo "!! lakesh not on PATH — pip install it from the lakesh repo" >&2; exit 1; }
command -v jq     >/dev/null 2>&1 || { echo "!! jq not on PATH" >&2; exit 1; }
curl -fsS "$BASE/healthz" >/dev/null 2>&1 || { echo "!! proxy not reachable at $BASE" >&2; exit 1; }

# ---- 1. write a lakesh profile pointing at the proxy ----------------------
step "1. write a lakesh profile (proxy=$BASE, s3=$S3_ENDPOINT)"
CFG="$(mktemp -t lakesh_duckicelake.XXXXXX.toml)"
cat > "$CFG" <<EOF
default = "duckicelake"

[profiles.duckicelake]
uri       = "$BASE"
warehouse = "$WAREHOUSE"

[profiles.duckicelake.s3]
endpoint   = "$S3_ENDPOINT"
region     = "us-east-1"
access_key = "minioadmin"
secret_key = "minioadmin"
path_style = true
EOF
export LAKESH_CONFIG="$CFG"
echo "wrote $CFG"
pause

# ---- 2. connectivity ------------------------------------------------------
step "2. lakesh doctor (REST /v1/config + attach + list namespaces)"
lakesh doctor -p duckicelake
pause

# ---- 3. list tables -------------------------------------------------------
step "3. lakesh exec — list tables in analytics"
lakesh exec -p duckicelake -q "SELECT table_name FROM information_schema.tables WHERE table_schema='analytics'"
pause

# ---- 4. UNMASKED base query ----------------------------------------------
step "4. lakesh exec — base query (UNMASKED: DuckDB reads the Parquet bytes)"
echo "NOTE: DuckDB's iceberg extension reads bytes directly, so the proxy's"
echo "      mask *properties* are advisory on this path (Trino/Spark honor"
echo "      them). Byte-level masking for DuckDB comes from the view SQL below."
lakesh exec -p duckicelake -q "SELECT id, email, country FROM $CAT.analytics.events ORDER BY id"
pause

# ---- 5. fetch DuckLake-direct credentials for the principal ----------------
step "5. GET /ducklake-credentials for principal '$PRINCIPAL' (governance Phase 3)"
CREDS=$(curl -fsS "$BASE/v1/$WAREHOUSE/namespaces/analytics/ducklake-credentials?table=events&principal=$PRINCIPAL")
echo "$CREDS" | jq '{masked_view, mask_signature, transparent, post_attach_sql}'
MASKED_VIEW=$(echo "$CREDS" | jq -r '.masked_view // empty')

if [ -z "$MASKED_VIEW" ]; then
  echo "principal '$PRINCIPAL' has no masking (holds an unmasked role) — sees the base table above."
else
  # ---- 6. DuckLake-direct profile from the vended response ----------------
  # The proxy materialized the principal's masking view as a real DuckLake
  # view and vended prefix-scoped read-only S3 creds — no manual SQL
  # rewriting (the old catalog-prefix hack) needed anymore.
  step "6. lakesh exec — DuckLake-direct, MASKED for '$PRINCIPAL'"
  DCAT=$(echo "$CREDS" | jq -r '.ducklake_attach_sql' | sed -E "s/.* AS ([a-zA-Z0-9_]+) .*/\1/")
  cat >> "$CFG" <<EOF

[profiles.governed_direct]
type         = "ducklake"
postgres_dsn = "$(echo "$CREDS" | jq -r '.ducklake_dsn')"
data_path    = "$(echo "$CREDS" | jq -r '.ducklake_data_path')"
catalog      = "$DCAT"

[profiles.governed_direct.s3]
endpoint      = "$(echo "$CREDS" | jq -r '.s3.endpoint')"
region        = "$(echo "$CREDS" | jq -r '.s3.region')"
access_key    = "$(echo "$CREDS" | jq -r '.s3["access-key-id"]')"
secret_key    = "$(echo "$CREDS" | jq -r '.s3["secret-access-key"]')"
session_token = "$(echo "$CREDS" | jq -r '.s3["session-token"]')"
path_style    = true
EOF
  VIEW_NS=${MASKED_VIEW%%.*}
  VIEW_NAME=${MASKED_VIEW#*.}
  lakesh exec -p governed_direct \
    -q "SELECT * FROM $DCAT.\"$VIEW_NS\".\"$VIEW_NAME\" ORDER BY id"
  echo
  echo "=> '$PRINCIPAL' sees masked email (al***) through the vended masking view;"
  echo "   the base rows in step 4 are unchanged. Clients that run the returned"
  echo "   post_attach_sql (SET search_path) get this masking transparently for"
  echo "   unqualified queries. Cooperative boundary: a client that names the"
  echo "   base table directly still reads cleartext (cooperative boundary)."
fi

rm -f "$CFG"
echo; echo "==== done ===="
