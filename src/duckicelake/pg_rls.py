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
is only enforceable under prod scram+TLS (see GOVERNANCE.md for the pg_hba
recipe). All entry points are fail-open: an RLS setup error must never
break vending; callers fall back to the owner DSN and audit the fact.
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone

from psycopg import errors as pg_errors
from psycopg import sql

from .catalog import DuckLakeCatalog
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


def _ensure_functions(cur) -> None:
    """SECURITY DEFINER predicate helpers, owned by the proxy's (owning)
    role so readers never need SELECT on the governance sidecars and the
    lookups bypass RLS (no recursion).

    Visibility is expressed as a *hidden-set* SRF rather than a per-row
    boolean: the RLS policy is `table_id NOT IN (SELECT … hidden …)`, an
    uncorrelated subquery Postgres evaluates ONCE per scan (then hashes),
    instead of a function invoked per row — the difference between one
    lookup and ~100k on a large catalog. The hidden set is bounded (only
    grant-gated / file-masked tables the principal can't see), and a
    dropped/unknown table_id is never in it → stays visible, matching the
    old per-row semantics exactly."""
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
    # Tables flipped to allowlist by an explicit select object-grant that
    # the session principal does NOT satisfy (holds none of the granting
    # roles). Ungoverned (no-grant) tables are absent → visible by default.
    cur.execute("""
        CREATE OR REPLACE FUNCTION public.duckicelake_hidden_table_ids()
        RETURNS SETOF bigint
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $$
            SELECT t.table_id
            FROM public.ducklake_table t
            JOIN public.ducklake_schema s USING (schema_id)
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
    cur.execute("""
        CREATE OR REPLACE FUNCTION public.duckicelake_hidden_file_table_ids()
        RETURNS SETOF bigint
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $$
            SELECT public.duckicelake_hidden_table_ids()
            UNION
            SELECT t.table_id
            FROM public.ducklake_table t
            JOIN public.ducklake_schema s USING (schema_id)
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


def _classify_tables(cur) -> tuple[list[str], list[str]]:
    """Live classification of public.ducklake_* tables → (table-scoped,
    file-scoped) lists, by their key columns."""
    cur.execute("""
        SELECT t.table_name,
               bool_or(c.column_name = 'table_id')     AS has_table_id,
               bool_or(c.column_name = 'data_file_id') AS has_file_id
        FROM information_schema.tables t
        JOIN information_schema.columns c USING (table_schema, table_name)
        WHERE t.table_schema = 'public'
          AND t.table_name LIKE 'ducklake\\_%'
          AND t.table_type = 'BASE TABLE'
        GROUP BY t.table_name
    """)
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
    startup; follows the _ensure_materialisation_sidecar DDL discipline."""
    group = settings.reader_group_role
    with catalog.pg_cursor() as cur:
        # Sidecars the predicate functions reference must exist before any
        # reader query can invoke them.
        ensure_governance_sidecars(cur)
        catalog._ensure_sidecar(cur)
        _ensure_principal_sidecar(cur)

        try:
            cur.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(
                sql.Identifier(group)))
        except pg_errors.DuplicateObject:
            pass
        cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
            sql.Identifier(group)))

        _ensure_functions(cur)

        table_scoped, file_scoped = _classify_tables(cur)

        # Readers may SELECT every ducklake_* catalog table (rows filtered
        # by RLS below). No grants on duckicelake_* sidecars — the
        # SECURITY DEFINER functions read those on the readers' behalf.
        for name in table_scoped + file_scoped + _unpolicied_tables(cur):
            cur.execute(sql.SQL("GRANT SELECT ON public.{} TO {}").format(
                sql.Identifier(name), sql.Identifier(group)))

        # Heal any historical over-grant on inlined-data payload tables and
        # the name-leaking snapshot_changes table (see _unpolicied_tables).
        cur.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
              AND ((table_name LIKE 'ducklake\\_inlined\\_data\\_%'
                    AND table_name <> 'ducklake_inlined_data_tables')
                   OR table_name = 'ducklake_snapshot_changes')
        """)
        for (name,) in cur.fetchall():
            cur.execute(sql.SQL("REVOKE SELECT ON public.{} FROM {}").format(
                sql.Identifier(name), sql.Identifier(group)))

        # Set-membership predicate: the SRF subquery is uncorrelated, so
        # Postgres runs it once per scan and hashes the result — not a
        # per-row function call.
        for name, predicate in (
            [(n, "table_id NOT IN (SELECT public.duckicelake_hidden_table_ids())")
             for n in table_scoped]
            + [(n, "table_id NOT IN (SELECT public.duckicelake_hidden_file_table_ids())")
               for n in file_scoped]
        ):
            cur.execute(sql.SQL(
                "ALTER TABLE public.{} ENABLE ROW LEVEL SECURITY"
            ).format(sql.Identifier(name)))
            cur.execute(sql.SQL("DROP POLICY IF EXISTS {} ON public.{}").format(
                sql.Identifier(_POLICY_NAME), sql.Identifier(name)))
            cur.execute(sql.SQL(
                "CREATE POLICY {} ON public.{} FOR SELECT TO {} USING ({})"
            ).format(
                sql.Identifier(_POLICY_NAME), sql.Identifier(name),
                sql.Identifier(group), sql.SQL(predicate),
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

    log.info("RLS ensured: group=%s, %d table-scoped + %d file-scoped policies",
             group, len(table_scoped), len(file_scoped))


def _unpolicied_tables(cur) -> list[str]:
    """ducklake_* base tables that get SELECT grants but no RLS policy
    (no table_id key — schema/snapshot/metadata plumbing the extension
    needs wholesale)."""
    cur.execute("""
        SELECT t.table_name
        FROM information_schema.tables t
        WHERE t.table_schema = 'public'
          AND t.table_name LIKE 'ducklake\\_%'
          AND t.table_type = 'BASE TABLE'
          -- Dynamic inlined-data payload tables (ducklake_inlined_data_<id>_<id>)
          -- get NO reader grant: they carry raw row data with no table_id to
          -- police, so granting them would bypass every predicate (verified
          -- live — inlined inserts leaked through RLS). Consequence, documented
          -- in GOVERNANCE.md: the vended reader path requires data inlining
          -- to be off on the write path (the registry ducklake_inlined_data_tables
          -- itself has table_id and is policied normally).
          AND t.table_name NOT LIKE 'ducklake\\_inlined\\_data\\_%'
          -- ducklake_snapshot_changes embeds qualified table NAMES in its
          -- changes_made column — granting it would leak the existence of
          -- allowlist-hidden tables. Readers lose `lake.snapshots()`
          -- introspection (verified: normal reads are unaffected), which is
          -- consistent with masked principals having no time travel anyway.
          AND t.table_name <> 'ducklake_snapshot_changes'
          AND NOT EXISTS (
            SELECT 1 FROM information_schema.columns c
            WHERE c.table_schema = t.table_schema
              AND c.table_name = t.table_name
              AND c.column_name = 'table_id'
          )
    """)
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
    group = settings.reader_group_role
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
