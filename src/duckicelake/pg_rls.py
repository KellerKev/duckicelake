"""Phase 3a — Postgres row-level security for DuckLake-direct readers.

The ducklake-credentials endpoint used to vend the *owning* PG role: a
DuckLake-direct client could see (and, modulo READ_ONLY, touch) the whole
catalog. This module gives each vended principal its own PG identity and
puts RLS between that identity and the `ducklake_*` catalog tables:

  * `duckicelake_reader` — NOLOGIN group role carrying all SELECT grants;
    every RLS policy is `FOR SELECT TO duckicelake_reader`.
  * `duckicelake_p_<sub>_<sha8>` — per-principal LOGIN role, member of the
    group, created on demand at vend time with a random password (returned
    once in the response, never persisted — PG keeps only the SCRAM
    verifier) and `VALID UNTIL` aligned to the STS expiry.
  * RLS predicates resolve the principal from **session_user** via the
    `duckicelake_pg_principal` sidecar — unforgeable after authentication
    (`SET ROLE` can only narrow to the group, and the lookup keys on the
    login role).

Visibility model (v1):
  * default-ALLOW — an ungoverned lake behaves exactly as before;
  * a table flips to allowlist when an explicit `select` object-grant
    exists for it (or its schema) in `duckicelake_object_grant`: visible
    iff the principal holds a granted role via `duckicelake_role_grant`;
  * base data/delete-file rows are additionally hidden when the table
    carries `duckicelake.file-layer-masking=true` and the principal holds
    none of `duckicelake.file-layer-bypass-roles` — the Phase 4 interlock.
    Plain masking policies never hide files: the Phase 3 masking view
    executes against the base table in the client's engine, so hiding its
    files would break exactly the principals the view exists for.

Policies are applied per classification (discovered live, so new DuckLake
versions are picked up by the next ensure pass):
  * has `table_id` + `data_file_id` → `duckicelake_can_see_files(table_id)`
  * has `table_id` only            → `duckicelake_can_see_table(table_id)`
Never `FORCE` — the proxy connects as the owning role and bypasses RLS.
Per-column hiding is deliberately absent in v1 (a partial `ducklake_column`
set breaks the masking views' binder).

Dev honesty: the pixi stack is trust-auth on a unix socket, so anyone can
connect as any role — the predicates are fully exercised but authentication
is only enforceable under prod scram+TLS (see OPERATIONS.md for the pg_hba
recipe). Vending is fail-CLOSED: when RLS can't be armed the server refuses
to vend (503, self-healing retry per request) — it never falls back to the
owner DSN.
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone

from psycopg import errors as pg_errors
from psycopg import sql

from .catalog import DuckLakeCatalog, pg_advisory_lock
from .config import Settings
from .governance import ensure_governance_sidecars

log = logging.getLogger("duckicelake.pg_rls")

ROLE_PREFIX = "duckicelake_p_"

#: Tables with table_id but NO data_file_id → table-visibility predicate.
#: Tables with both → file-visibility predicate. Discovered live in
#: ensure_rls; these names are only used in tests/docs.

_POLICY_NAME = "duckicelake_rls"


def principal_role_name(sub: str, nonce: str = "") -> str:
    """Collision-proof PG LOGIN-role name for a principal sub.

    Hostile subs are sanitized to [a-z0-9_]; the sha8 of the raw sub keeps
    two subs that sanitize identically from colliding. A per-vend `nonce`
    makes each vend its own role: concurrent vends for the same principal
    no longer race to ALTER one shared password (which invalidated the
    earlier vend's just-returned secret). All such roles map to the same
    principal in `duckicelake_pg_principal` and are GC'd by expiry. Always
    ≤ 63 bytes: 14 (prefix) + 24 + 1 + 8 + 1 + 6.
    """
    sanitized = re.sub(r"[^a-z0-9_]", "_", sub.lower())[:24]
    digest = hashlib.sha256(sub.encode()).hexdigest()[:8]
    suffix = f"_{nonce}" if nonce else ""
    return f"{ROLE_PREFIX}{sanitized}_{digest}{suffix}"


def _ensure_principal_sidecar(cur) -> None:
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_pg_principal (
            pg_role       TEXT PRIMARY KEY,
            principal_sub TEXT NOT NULL,
            expires_at    TIMESTAMPTZ,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)


def _meta_schema(catalog: DuckLakeCatalog) -> str:
    """The Postgres schema holding this catalog's ducklake_* tables — the
    per-account metadata schema, or 'public' for the default catalog."""
    return catalog.ref.metadata_schema or "public"


def _suffix(meta_schema: str) -> str:
    """Per-catalog name suffix for the reader group + predicate functions.
    Empty for the default catalog (preserves the original names); a short
    stable hash otherwise (keeps role/function names ≤63 bytes)."""
    if meta_schema == "public":
        return ""
    return "_" + hashlib.sha256(meta_schema.encode()).hexdigest()[:10]


def _group_for(settings: Settings, meta_schema: str) -> str:
    return settings.reader_group_role + _suffix(meta_schema)


def _fn_names(meta_schema: str) -> tuple[str, str]:
    suf = _suffix(meta_schema)
    return (f"duckicelake_hidden_table_ids{suf}",
            f"duckicelake_hidden_file_table_ids{suf}")


def _ensure_session_principal_fn(cur) -> None:
    """Catalog-independent: resolve session_user → principal_sub from the
    shared public sidecar. One function serves every catalog."""
    cur.execute("""
        CREATE OR REPLACE FUNCTION public.duckicelake_session_principal()
        RETURNS text
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $$
            SELECT principal_sub FROM public.duckicelake_pg_principal
            WHERE pg_role = session_user
        $$
    """)


def _ensure_functions(cur, meta_schema: str) -> None:
    """SECURITY DEFINER predicate helpers for ONE catalog's metadata schema,
    owned by the proxy's (owning) role so readers never need SELECT on the
    governance sidecars and the lookups bypass RLS (no recursion).

    The ducklake_* metadata tables are read from `meta_schema`; the governance
    sidecars (object_grant / role_grant / table_property / pg_principal) stay
    in public (cross-catalog). Function names are per-schema (see `_fn_names`)
    so each catalog gets its own hidden-set predicates.

    Visibility is expressed as a *hidden-set* SRF rather than a per-row
    boolean: the RLS policy is `table_id NOT IN (SELECT … hidden …)`, an
    uncorrelated subquery Postgres evaluates ONCE per scan (then hashes),
    instead of a function invoked per row."""
    _ensure_session_principal_fn(cur)
    hidden_table_fn, hidden_file_fn = _fn_names(meta_schema)
    m = f'"{meta_schema}"'  # trusted, validated identifier
    # Tables flipped to allowlist by an explicit select object-grant that
    # the session principal does NOT satisfy (holds none of the granting
    # roles). Ungoverned (no-grant) tables are absent → visible by default.
    cur.execute(f"""
        CREATE OR REPLACE FUNCTION public.{hidden_table_fn}()
        RETURNS SETOF bigint
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $$
            SELECT t.table_id
            FROM {m}.ducklake_table t
            JOIN {m}.ducklake_schema s USING (schema_id)
            WHERE t.end_snapshot IS NULL
              AND EXISTS (
                SELECT 1 FROM public.duckicelake_object_grant og
                WHERE lower(og.privilege) = 'select'
                  AND ((og.object_kind = 'table'
                        AND og.schema_name = s.schema_name
                        AND og.object_name = t.table_name)
                       OR (og.object_kind = 'schema'
                           AND og.schema_name = s.schema_name)))
              AND NOT EXISTS (
                SELECT 1 FROM public.duckicelake_object_grant og
                JOIN public.duckicelake_role_grant rg ON rg.role_name = og.role_name
                WHERE lower(og.privilege) = 'select'
                  AND rg.principal_sub = public.duckicelake_session_principal()
                  AND ((og.object_kind = 'table'
                        AND og.schema_name = s.schema_name
                        AND og.object_name = t.table_name)
                       OR (og.object_kind = 'schema'
                           AND og.schema_name = s.schema_name)))
        $$
    """)
    # File-row hidden set: the table-hidden set, PLUS file-layer-masked
    # tables (duckicelake.file-layer-masking=true) whose bypass-role list
    # the principal doesn't satisfy — the Phase-4 interlock.
    cur.execute(f"""
        CREATE OR REPLACE FUNCTION public.{hidden_file_fn}()
        RETURNS SETOF bigint
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $$
            SELECT public.{hidden_table_fn}()
            UNION
            SELECT t.table_id
            FROM {m}.ducklake_table t
            JOIN {m}.ducklake_schema s USING (schema_id)
            JOIN public.duckicelake_table_property p
              ON p.schema_name = s.schema_name
             AND p.table_name = t.table_name
             AND p.key = 'duckicelake.file-layer-masking'
             AND lower(p.value) = 'true'
            WHERE t.end_snapshot IS NULL
              AND NOT EXISTS (
                SELECT 1
                FROM public.duckicelake_table_property bp
                CROSS JOIN unnest(string_to_array(bp.value, ',')) AS r(role_name)
                JOIN public.duckicelake_role_grant rg
                  ON rg.role_name = trim(r.role_name)
                WHERE bp.schema_name = s.schema_name
                  AND bp.table_name = t.table_name
                  AND bp.key = 'duckicelake.file-layer-bypass-roles'
                  AND rg.principal_sub = public.duckicelake_session_principal())
        $$
    """)


def _classify_tables(cur, meta_schema: str) -> tuple[list[str], list[str]]:
    """Live classification of <meta_schema>.ducklake_* tables → (table-scoped,
    file-scoped) lists, by their key columns."""
    cur.execute("""
        SELECT t.table_name,
               bool_or(c.column_name = 'table_id')     AS has_table_id,
               bool_or(c.column_name = 'data_file_id') AS has_file_id
        FROM information_schema.tables t
        JOIN information_schema.columns c USING (table_schema, table_name)
        WHERE t.table_schema = %s
          AND t.table_name LIKE 'ducklake\\_%%'
          AND t.table_type = 'BASE TABLE'
        GROUP BY t.table_name
    """, (meta_schema,))
    table_scoped, file_scoped = [], []
    for name, has_tid, has_fid in cur.fetchall():
        if has_tid and has_fid:
            file_scoped.append(name)
        elif has_tid:
            table_scoped.append(name)
    return sorted(table_scoped), sorted(file_scoped)


def ensure_rls(catalog: DuckLakeCatalog, settings: Settings) -> None:
    """Idempotent: group role, grants, sidecar, predicate functions, and
    one RLS policy per classified ducklake_* table. Safe to call on every
    startup; follows the _ensure_materialisation_sidecar DDL discipline.

    Serialized ACROSS WORKERS by a blocking advisory lock: concurrent
    CREATE OR REPLACE FUNCTION / GRANT on the same shared objects raises
    `tuple concurrently updated` (observed under uvicorn --workers 4).
    Losers wait, then find the idempotent DDL already applied. The key folds
    the metadata schema so distinct catalogs don't serialize each other."""
    meta = _meta_schema(catalog)
    group = _group_for(settings, meta)
    hidden_table_fn, hidden_file_fn = _fn_names(meta)
    with catalog.pg_cursor() as cur:
        with pg_advisory_lock(cur, f"duckicelake:ensure_rls:{meta}"):
            table_scoped, file_scoped = _ensure_rls_locked(
                catalog, cur, meta, group, hidden_table_fn, hidden_file_fn)
    log.info("RLS ensured: group=%s, %d table-scoped + %d file-scoped policies",
             group, len(table_scoped), len(file_scoped))


def _preflight_ownership(cur, meta: str) -> None:
    """Actionable error when the proxy's role cannot ALTER the ducklake_*
    tables (brownfield deployment: DuckLake attached under a different role).
    `ENABLE ROW LEVEL SECURITY` requires table ownership; without this check
    the failure surfaces as a cryptic permission-denied mid-DDL and wedges
    the fail-closed vend gate. Superusers own everything effectively —
    skipped."""
    cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
    row = cur.fetchone()
    if row and row[0]:
        return
    cur.execute("""
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = %s AND c.relkind = 'r'
          AND c.relname LIKE 'ducklake\\_%%'
          AND NOT pg_has_role(current_user, c.relowner, 'USAGE')
        ORDER BY c.relname
    """, (meta,))
    foreign = [r[0] for r in cur.fetchall()]
    if foreign:
        sample = ", ".join(foreign[:5]) + ("…" if len(foreign) > 5 else "")
        raise RuntimeError(
            f"RLS pre-flight: {len(foreign)} ducklake_* tables in schema "
            f"'{meta}' are not owned by the proxy role — ENABLE ROW LEVEL "
            f"SECURITY requires ownership. Fix: ALTER TABLE ... OWNER TO "
            f"<proxy-role> (see OPERATIONS.md, owner-role prerequisites). "
            f"Tables: {sample}")


def _ensure_rls_locked(catalog: DuckLakeCatalog, cur, meta: str, group: str,
                       hidden_table_fn: str, hidden_file_fn: str,
                       ) -> tuple[list[str], list[str]]:
    """The DDL body of ensure_rls — caller holds the advisory lock."""
    _preflight_ownership(cur, meta)
    # Sidecars the predicate functions reference must exist before any
    # reader query can invoke them (always in public, cross-catalog).
    ensure_governance_sidecars(cur)
    catalog._ensure_sidecar(cur)
    _ensure_principal_sidecar(cur)

    try:
        cur.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(
            sql.Identifier(group)))
    except pg_errors.DuplicateObject:
        pass
    # Reader needs USAGE on its own metadata schema (the ducklake_* tables)
    # and on public (the SECURITY DEFINER predicate functions live there).
    for sch in {meta, "public"}:
        cur.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
            sql.Identifier(sch), sql.Identifier(group)))

    _ensure_functions(cur, meta)

    table_scoped, file_scoped = _classify_tables(cur, meta)

    # Readers may SELECT every ducklake_* catalog table IN THIS SCHEMA
    # (rows filtered by RLS below). Per-catalog group → a tenant reader can
    # never reach another catalog's metadata schema. No grants on
    # duckicelake_* sidecars — the SECURITY DEFINER functions read those.
    for name in table_scoped + file_scoped + _unpolicied_tables(cur, meta):
        cur.execute(sql.SQL("GRANT SELECT ON {}.{} TO {}").format(
            sql.Identifier(meta), sql.Identifier(name), sql.Identifier(group)))

    # Heal any historical over-grant on the never-grant tables:
    # inlined-data payloads (raw rows, no table_id to police), the
    # name-leaking snapshot_changes, and files_scheduled_for_deletion
    # (base data-file paths of hidden tables). See _unpolicied_tables.
    cur.execute("""
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = %s AND table_type = 'BASE TABLE'
          AND ((table_name LIKE 'ducklake\\_inlined\\_data\\_%%'
                AND table_name <> 'ducklake_inlined_data_tables')
               OR table_name = 'ducklake_snapshot_changes'
               OR table_name = 'ducklake_files_scheduled_for_deletion')
    """, (meta,))
    for (name,) in cur.fetchall():
        cur.execute(sql.SQL("REVOKE SELECT ON {}.{} FROM {}").format(
            sql.Identifier(meta), sql.Identifier(name), sql.Identifier(group)))

    # Set-membership predicate: the SRF subquery is uncorrelated, so
    # Postgres runs it once per scan and hashes the result — not a
    # per-row function call.
    for name, predicate in (
        [(n, f"table_id NOT IN (SELECT public.{hidden_table_fn}())")
         for n in table_scoped]
        + [(n, f"table_id NOT IN (SELECT public.{hidden_file_fn}())")
           for n in file_scoped]
    ):
        cur.execute(sql.SQL(
            "ALTER TABLE {}.{} ENABLE ROW LEVEL SECURITY"
        ).format(sql.Identifier(meta), sql.Identifier(name)))
        cur.execute(sql.SQL("DROP POLICY IF EXISTS {} ON {}.{}").format(
            sql.Identifier(_POLICY_NAME), sql.Identifier(meta), sql.Identifier(name)))
        cur.execute(sql.SQL(
            "CREATE POLICY {} ON {}.{} FOR SELECT TO {} USING ({})"
        ).format(
            sql.Identifier(_POLICY_NAME), sql.Identifier(meta),
            sql.Identifier(name), sql.Identifier(group), sql.SQL(predicate),
        ))

    # Drop the old per-row scalar predicates on upgrade — the policies
    # above now reference the set-returning SRFs instead. Best-effort;
    # files-variant first (it depended on the table-variant).
    for fn in ("duckicelake_can_see_files(bigint)",
               "duckicelake_can_see_table(bigint)"):
        try:
            cur.execute(f"DROP FUNCTION IF EXISTS public.{fn}")
        except Exception:
            log.debug("could not drop legacy predicate %s", fn)

    return table_scoped, file_scoped


def rearm_rls_if_needed(catalog: DuckLakeCatalog, settings: Settings) -> bool:
    """`ensure_rls` runs once at startup and grants/policies per-table, so a
    `ducklake_*` table created LATER (e.g. a DuckLake version introducing a
    new system table) would be unpolicied. This cheap guard — one
    information_schema query — re-arms RLS only when such a coverage gap
    exists: a `ducklake_*` base table that is neither granted to the reader
    group nor on the intentional never-grant list. Best-effort; returns True
    if it re-armed. (New *user* tables don't need this — their rows land in
    the already-policied ducklake_data_file/_table.)"""
    meta = _meta_schema(catalog)
    group = _group_for(settings, meta)
    try:
        with catalog.pg_cursor(autocommit=False) as cur:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (group,))
            if cur.fetchone() is None:
                return False   # RLS never armed; ensure_rls (startup) owns that
            # %% — this query binds a param, so literal % must be doubled.
            cur.execute("""
                SELECT count(*) FROM information_schema.tables t
                WHERE t.table_schema = %s AND t.table_type = 'BASE TABLE'
                  AND t.table_name LIKE 'ducklake\\_%%'
                  AND t.table_name NOT LIKE 'ducklake\\_inlined\\_data\\_%%'
                  AND t.table_name NOT IN ('ducklake_snapshot_changes',
                                           'ducklake_files_scheduled_for_deletion')
                  AND NOT EXISTS (
                    SELECT 1 FROM information_schema.role_table_grants g
                    WHERE g.grantee = %s AND g.table_schema = %s
                      AND g.table_name = t.table_name)
            """, (meta, group, meta))
            gap = cur.fetchone()[0]
        if gap:
            log.info("RLS coverage gap (%d ungranted ducklake_* tables) — re-arming", gap)
            ensure_rls(catalog, settings)
            return True
    except Exception:
        log.exception("rearm_rls_if_needed failed")
    return False


def _unpolicied_tables(cur, meta_schema: str) -> list[str]:
    """ducklake_* base tables that get SELECT grants but no RLS policy
    (no table_id key — schema/snapshot/metadata plumbing the extension
    needs wholesale)."""
    cur.execute("""
        SELECT t.table_name
        FROM information_schema.tables t
        WHERE t.table_schema = %s
          AND t.table_name LIKE 'ducklake\\_%%'
          AND t.table_type = 'BASE TABLE'
          -- Dynamic inlined-data payload tables (ducklake_inlined_data_<id>_<id>)
          -- get NO reader grant: they carry raw row data with no table_id to
          -- police, so granting them would bypass every predicate (verified
          -- live — inlined inserts leaked through RLS). Consequence: the
          -- vended reader path requires data inlining
          -- to be off on the write path (the registry ducklake_inlined_data_tables
          -- itself has table_id and is policied normally).
          AND t.table_name NOT LIKE 'ducklake\\_inlined\\_data\\_%%'
          -- ducklake_snapshot_changes embeds qualified table NAMES in its
          -- changes_made column — granting it would leak the existence of
          -- allowlist-hidden tables. Readers lose `lake.snapshots()`
          -- introspection (verified: normal reads are unaffected), which is
          -- consistent with masked principals having no time travel anyway.
          AND t.table_name <> 'ducklake_snapshot_changes'
          -- ducklake_files_scheduled_for_deletion has data_file_id but no
          -- table_id, so it can't be RLS-filtered by our table_id predicate.
          -- It exposes base data-file S3 paths of allowlist-hidden /
          -- file-layer tables (files pending compaction/expiry). A read-only
          -- principal never processes the deletion queue, so it gets NO grant.
          AND t.table_name <> 'ducklake_files_scheduled_for_deletion'
          AND NOT EXISTS (
            SELECT 1 FROM information_schema.columns c
            WHERE c.table_schema = t.table_schema
              AND c.table_name = t.table_name
              AND c.column_name = 'table_id'
          )
    """, (meta_schema,))
    return sorted(r[0] for r in cur.fetchall())


def provision_principal_role(
    catalog: DuckLakeCatalog,
    settings: Settings,
    sub: str,
    expires_at: datetime,
) -> tuple[str, str]:
    """Mint a fresh per-vend LOGIN role for the principal; returns
    (role, password).

    Each vend gets its own nonce-suffixed role + password + VALID UNTIL, so
    concurrent vends for the same principal never invalidate each other's
    just-returned secret (the old shared-role ALTER PASSWORD raced). All of
    a principal's vend-roles map to the same principal_sub and are GC'd by
    expiry. The plaintext is never stored; PG keeps the SCRAM verifier.
    """
    role = principal_role_name(sub, secrets.token_hex(3))
    password = secrets.token_hex(24)
    # Join the per-catalog reader group so the principal can only reach THIS
    # catalog's metadata schema (cross-account isolation at the PG layer).
    group = _group_for(settings, _meta_schema(catalog))
    with catalog.pg_cursor() as cur:
        _ensure_principal_sidecar(cur)
        try:
            cur.execute(sql.SQL("CREATE ROLE {} IN ROLE {}").format(
                sql.Identifier(role), sql.Identifier(group)))
        except pg_errors.DuplicateObject:
            pass
        cur.execute(sql.SQL(
            "ALTER ROLE {} LOGIN PASSWORD {} VALID UNTIL {}"
        ).format(
            sql.Identifier(role),
            sql.Literal(password),
            sql.Literal(expires_at.isoformat()),
        ))
        cur.execute(
            """
            INSERT INTO public.duckicelake_pg_principal
                (pg_role, principal_sub, expires_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (pg_role) DO UPDATE
              SET principal_sub = EXCLUDED.principal_sub,
                  expires_at = EXCLUDED.expires_at
            """,
            (role, sub, expires_at),
        )
    return role, password


def gc_expired_roles(
    catalog: DuckLakeCatalog,
    *,
    nologin_grace: timedelta = timedelta(hours=24),
    drop_grace: timedelta = timedelta(days=7),
) -> None:
    """Lazy lifecycle: expired roles lose LOGIN after a grace period and
    are dropped (with their mapping row) after a longer one. Best-effort —
    piggybacked on vends, never blocks them."""
    now = datetime.now(timezone.utc)
    try:
        with catalog.pg_cursor() as cur:
            _ensure_principal_sidecar(cur)
            cur.execute(
                "SELECT pg_role, expires_at FROM public.duckicelake_pg_principal "
                "WHERE expires_at IS NOT NULL AND expires_at < %s",
                (now - nologin_grace,),
            )
            for role, expires_at in cur.fetchall():
                try:
                    if expires_at < now - drop_grace:
                        cur.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(
                            sql.Identifier(role)))
                        cur.execute(
                            "DELETE FROM public.duckicelake_pg_principal "
                            "WHERE pg_role = %s", (role,))
                    else:
                        cur.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(
                            sql.Identifier(role)))
                except Exception:
                    log.exception("role GC failed for %s", role)
    except Exception:
        log.exception("role GC sweep failed")
