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

# ---- 5. masking the proxy decided for the principal -----------------------
step "5. masking decided by the proxy for principal '$PRINCIPAL'"
VIEW_SQL=$(curl -fsS "$P/effective-policies?table=analytics.events&principal=$PRINCIPAL" \
            | jq -r '.enforcement.view_sql // empty')
if [ -z "$VIEW_SQL" ]; then
  echo "principal '$PRINCIPAL' has no masking (holds an unmasked role) — sees the base table above."
else
  echo "engine-generated view SQL (fetched live):"
  echo "    $VIEW_SQL"
  # The proxy emits the table unqualified ("analytics"."events"); lakesh
  # attaches the REST catalog as '$CAT', so qualify the reference.
  LAKESH_SQL=${VIEW_SQL//\"analytics\".\"events\"/$CAT.\"analytics\".\"events\"}
  step "6. lakesh exec — same query, MASKED for '$PRINCIPAL'"
  lakesh exec -p duckicelake -q "$LAKESH_SQL ORDER BY id"
  echo
  echo "=> '$PRINCIPAL' sees masked email (al***); the base rows in step 4 are unchanged."
fi

rm -f "$CFG"
echo; echo "==== done ===="
