#!/usr/bin/env bash
# Phase 1 + 2 governance walkthrough against a running proxy.
#
#   pixi run serve            # (or however the proxy is started) on :8181
#   ./scripts/governance_demo.sh
#
# Sets up a pii.email tag + masking policy on analytics.events, then shows
# the policy resolved for a masked principal (bob) vs an unmasked one
# (alice, who holds the bypass role), the masked LoadTable metadata, and the
# audit trail. Idempotent — safe to re-run.
#
# Tunables:
#   BASE=http://127.0.0.1:8181   proxy base URL
#   SLEEP=10                     seconds between steps (set 0 to go fast)
set -uo pipefail

BASE="${BASE:-http://127.0.0.1:8181}"
SLEEP="${SLEEP:-10}"
P="$BASE/v1/lake/governance"
CT='Content-Type: application/json'

# jq is nice-to-have; fall back to raw output if it's missing.
if command -v jq >/dev/null 2>&1; then JQ=(jq); else JQ=(cat); fi

step() { echo; echo "==== $* ===="; }
pause() { [ "$SLEEP" -gt 0 ] && { echo "(sleeping ${SLEEP}s…)"; sleep "$SLEEP"; } || true; }

# POST helper: url, json-body. Prints body + HTTP code. Returns non-zero on
# an HTTP error (>=400) so the caller decides — `|| true` for idempotent
# creates (409 already-exists), `|| exit 1` for must-succeed steps.
post() {
  local url="$1" body="$2" out code
  out=$(curl -sS -w $'\n%{http_code}' -X POST "$url" -H "$CT" --data "$body")
  code="${out##*$'\n'}"; body="${out%$'\n'*}"
  echo "$body  [HTTP $code]"
  [ "$code" -lt 400 ] || { echo "   (HTTP $code)" >&2; return 1; }
}

# GET helper: url [jq-filter]
get() {
  local url="$1" filter="${2:-.}" out code
  out=$(curl -sS -w $'\n%{http_code}' "$url")
  code="${out##*$'\n'}"; out="${out%$'\n'*}"
  if [ "$code" -ge 400 ]; then echo "!! GET $url -> HTTP $code"; echo "$out"; return 1; fi
  echo "$out" | "${JQ[@]}" "$filter" 2>/dev/null || echo "$out"
}

# ---- 0. proxy reachable? --------------------------------------------------
step "0. health check ($BASE)"
if ! curl -fsS "$BASE/healthz" >/dev/null 2>&1; then
  echo "!! proxy not reachable at $BASE — start it first (pixi run serve)" >&2
  exit 1
fi
echo "proxy OK"
pause

# ---- 1. namespace + table -------------------------------------------------
step "1. create namespace analytics + table events(id, email, country)"
echo "(409 already-exists is fine — the script is idempotent)"
post "$BASE/v1/lake/namespaces" '{"namespace":["analytics"]}' || true
post "$BASE/v1/lake/namespaces/analytics/tables" \
  '{"name":"events","schema":{"type":"struct","schema-id":0,"fields":[
     {"id":1,"name":"id","required":true,"type":"long"},
     {"id":2,"name":"email","required":false,"type":"string"},
     {"id":3,"name":"country","required":false,"type":"string"}]}}' || true

# Seed 3 rows via DuckLake-direct (idempotent) so the lakesh demo below has
# real bytes to mask. Uses the same eager-materialise path a client would.
REPO="$(cd "$(dirname "$0")/.." && pwd)"
if command -v pixi >/dev/null 2>&1; then
  ( cd "$REPO" && pixi run --quiet python scripts/seed_events.py ) \
    2>&1 | grep -vE "WARN|deprecated|[│╭╰·]|platforms =|replace this with" || true
fi
pause

# ---- 2. tag the email column ---------------------------------------------
step "2. define tag pii.email + tag the email column"
post "$P/tags" '{"namespace":"pii","name":"email"}'
post "$P/object-tags" \
  '{"object-kind":"column","schema":"analytics","object":"events","column":"email","tag-namespace":"pii","tag-name":"email"}'
pause

# ---- 3. masking policy ----------------------------------------------------
step "3. masking policy mask_email (first 2 chars + ***), bypassed by role pii_reader"
post "$P/masking-policies" \
  '{"name":"mask_email","signature":"(val VARCHAR)","body":"left(val,2)||'\''***'\''","unmasked-roles":["pii_reader"]}'
pause

# ---- 4. attach policy to the tag -----------------------------------------
step "4. attach mask_email to the pii.email tag (covers every column with that tag)"
post "$P/policy-attachments" \
  '{"policy-kind":"masking","policy-name":"mask_email","target-kind":"tag","tag-namespace":"pii","tag-name":"email"}'
pause

# ---- 5. role + grant ------------------------------------------------------
step "5. create role pii_reader + grant it to principal alice"
post "$P/roles" '{"name":"pii_reader"}'
post "$P/role-grants" '{"role":"pii_reader","principal":"alice"}'
pause

# ---- 6. resolve for a MASKED principal -----------------------------------
step "6. effective-policies for 'bob' (no roles) — email IS masked"
get "$P/effective-policies?table=analytics.events&principal=bob" '.enforcement'
pause

# ---- 7. resolve for an UNMASKED principal --------------------------------
step "7. effective-policies for 'alice' (holds pii_reader) — nothing masked"
get "$P/effective-policies?table=analytics.events&principal=alice" '{roles, enforcement}'
pause

# ---- 8. LoadTable shows the masking stamped into client-facing metadata ---
step "8. LoadTable (anonymous → no roles) — masking signals in returned metadata"
get "$BASE/v1/lake/namespaces/analytics/tables/events" '{
  masked_columns: .metadata.properties["duckicelake.masked-columns"],
  mask_email:     .metadata.properties["duckicelake.mask.email"],
  view_sql:       .metadata.properties["duckicelake.masking-view-sql"],
  email_doc: (.metadata.schemas[0].fields[] | select(.name=="email") | .doc)}'
pause

# ---- 9. audit trail -------------------------------------------------------
step "9. audit trail (most recent first)"
get "$P/audit?limit=8" '.entries[] | {operation, object, decision, masked_cols}'
pause

# ---- 10. SQL proof: masked vs unmasked rows ------------------------------
step "10. SQL proof — masked vs unmasked rows (bob is masked, alice is not)"
# Runs scripts/sql_proof.py: fetches the live per-principal masking SQL from
# the proxy and applies it to sample rows. Needs the pixi env (duckdb+httpx).
REPO="$(cd "$(dirname "$0")/.." && pwd)"
if command -v pixi >/dev/null 2>&1; then
  echo "--- principal bob (no roles → email MASKED) ---"
  ( cd "$REPO" && BASE="$BASE" pixi run --quiet python scripts/sql_proof.py bob ) \
    2>&1 | grep -vE "WARN|deprecated|[│╭╰·]|platforms =|replace this with"
  echo
  echo "--- principal alice (holds pii_reader → UNMASKED) ---"
  ( cd "$REPO" && BASE="$BASE" pixi run --quiet python scripts/sql_proof.py alice ) \
    2>&1 | grep -vE "WARN|deprecated|[│╭╰·]|platforms =|replace this with"
else
  echo "(skipped — 'pixi' not on PATH; run: pixi run python scripts/sql_proof.py bob)"
fi

echo; echo "==== done ===="
