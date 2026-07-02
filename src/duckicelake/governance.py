"""Governance authoring + audit — the tag/policy/role model.

This module is the authoring + storage foundation: a complete surface for
tags, masking / row-access policies, policy attachments, roles, grants and
an audit trail. It does not enforce anything by itself — enforcement lives
in `policies.py` (metadata signals + masking views), `masked_export.py`
(file-layer masking) and `pg_rls.py` (catalog row-level security). Keeping
authoring separate means the model can be reviewed independently of how any
particular engine is made to honor it.

Storage follows the established `duckicelake_*` Postgres sidecar convention
(see `DuckLakeCatalog._ensure_sidecar`): tables are created on demand, keyed
by name, mutated via `ON CONFLICT` upserts. The store borrows the catalog's
pg connection pool rather than opening its own.

`resolve_effective_policies` is a *pure* function over already-fetched rows
so it is unit-testable without Postgres; the store fetches the rows then
delegates to it.
"""
from __future__ import annotations

import json
from typing import Any

from .catalog import DuckLakeCatalog, pg_advisory_lock


# Object kinds a tag / policy can target.
OBJECT_KINDS = {"schema", "table", "view", "column"}
POLICY_KINDS = {"masking", "row_access"}


class GovernanceConflict(Exception):
    """An authoring op that violates a governance invariant — a second mask
    on a column, or deleting/altering an object that is still referenced.
    The API maps it to HTTP 409."""
# Where a policy attachment points: a tag (transitive), a single column, or
# a whole table (row-access on a column-list).
ATTACH_TARGETS = {"tag", "column", "table"}

# Which targets each policy kind actually honors at resolution time. A
# masking policy applies via a tag or a single column; a row-access policy
# applies to a whole table or via a (table/schema) tag. Any other pairing —
# masking→table, row_access→column — is silently ignored by the resolver, so
# an attachment to it is a no-op that looks like protection. Reject at attach.
VALID_ATTACH_TARGETS = {
    "masking": {"tag", "column"},
    "row_access": {"tag", "table"},
}


#: Process-level guard so the ~14 sidecar DDL statements (incl. ALTER TABLE
#: ADD COLUMN, which takes a brief ACCESS EXCLUSIVE lock even as a no-op)
#: run once per process instead of on every GovernanceStore call — a single
#: masked LoadTable would otherwise re-run them 3-4× and serialize concurrent
#: requests on catalog locks. The proxy's schema is never wiped mid-process;
#: tests that wipe Postgres call `reset_sidecar_cache()` (via conftest) to
#: keep the flag honest.
_SIDECARS_ENSURED = False


def reset_sidecar_cache() -> None:
    """Forget that the governance sidecars were ensured — call after wiping
    the `public` schema so the next ensure re-creates them."""
    global _SIDECARS_ENSURED
    _SIDECARS_ENSURED = False


def ensure_governance_sidecars(cur) -> None:
    """Create the Phase 1 governance sidecar tables if absent.

    Idempotent and cheap after the first call per process (guarded by
    `_SIDECARS_ENSURED`), matching the catalog's `_ensure_sidecar`
    discipline. All tables carry the `duckicelake_` prefix so their proxy
    origin is obvious in the PG schema. The first call per process is
    serialized ACROSS workers by a blocking advisory lock — the per-process
    flag can't stop N workers racing the same CREATE/ALTER DDL at startup
    (`tuple concurrently updated`)."""
    global _SIDECARS_ENSURED
    if _SIDECARS_ENSURED:
        return
    with pg_advisory_lock(cur, "duckicelake:governance_sidecars"):
        _ensure_governance_sidecars_ddl(cur)
    _SIDECARS_ENSURED = True


def _ensure_governance_sidecars_ddl(cur) -> None:
    # --- tag definitions -------------------------------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_tag (
            tag_ns         VARCHAR NOT NULL,
            tag_name       VARCHAR NOT NULL,
            allowed_values TEXT[],            -- NULL = free-form
            created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (tag_ns, tag_name)
        )
    """)
    # --- tag assignments to objects -------------------------------------
    # column_name is NOT NULL with an '' sentinel so it can sit in the PK
    # (Postgres PKs reject NULLs). '' means "the object itself", a real
    # name means "that column".
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_object_tag (
            object_kind  VARCHAR NOT NULL,
            schema_name  VARCHAR NOT NULL,
            object_name  VARCHAR NOT NULL DEFAULT '',
            column_name  VARCHAR NOT NULL DEFAULT '',
            tag_ns       VARCHAR NOT NULL,
            tag_name     VARCHAR NOT NULL,
            tag_value    VARCHAR,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (object_kind, schema_name, object_name, column_name, tag_ns, tag_name)
        )
    """)
    # --- masking policies (named UDF-shaped definitions) ----------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_masking_policy (
            name          VARCHAR PRIMARY KEY,
            signature_sql VARCHAR NOT NULL,   -- e.g. "(val VARCHAR)"
            body_sql      VARCHAR NOT NULL,    -- e.g. "CASE WHEN ... THEN val ELSE '***' END"
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    # --- row access policies --------------------------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_row_access_policy (
            name          VARCHAR PRIMARY KEY,
            signature_sql VARCHAR NOT NULL,   -- e.g. "(region VARCHAR)"
            body_sql      VARCHAR NOT NULL,    -- RETURNS BOOLEAN body
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    # Phase 2 enforcement column: roles that *bypass* the policy. In
    # Snowflake the policy body inspects CURRENT_ROLE(); rather than execute
    # SQL per-principal we make the bypass set explicit + declarative. A
    # principal holding any role in `unmasked_roles` sees unmasked data /
    # unfiltered rows. `body_sql` stays the masked-value / filter expression
    # used to synthesise the view-fallback SQL. NULL/empty = nobody bypasses.
    for _pt in ("duckicelake_masking_policy", "duckicelake_row_access_policy"):
        cur.execute(
            f"ALTER TABLE public.{_pt} "
            f"ADD COLUMN IF NOT EXISTS unmasked_roles TEXT[]"
        )
    # Phase 4: file-layer masking. When true, the proxy ALSO materializes
    # the mask physically as masked Parquet copies (one per table +
    # mask-signature) so engines that read Parquet directly get masked
    # bytes. Default false = catalog-level masking only (views + signals).
    cur.execute(
        "ALTER TABLE public.duckicelake_masking_policy "
        "ADD COLUMN IF NOT EXISTS file_layer_masking BOOLEAN NOT NULL DEFAULT false"
    )
    # --- policy attachments ---------------------------------------------
    # A masking policy attaches to a tag or a single column; a row-access
    # policy attaches to a table on a column-list. `columns` holds the
    # row-access column-list; tag_* / column_name carry the other targets.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_policy_attachment (
            id          BIGSERIAL PRIMARY KEY,
            policy_kind VARCHAR NOT NULL,      -- 'masking' | 'row_access'
            policy_name VARCHAR NOT NULL,
            target_kind VARCHAR NOT NULL,      -- 'tag' | 'column' | 'table'
            tag_ns      VARCHAR,
            tag_name    VARCHAR,
            schema_name VARCHAR,
            object_name VARCHAR,
            column_name VARCHAR,
            columns     TEXT[],
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    # A given (policy, target) pair should only attach once. Partial-ish
    # uniqueness via a COALESCE'd expression index over the target columns.
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS duckicelake_policy_attachment_uq
        ON public.duckicelake_policy_attachment (
            policy_kind, policy_name, target_kind,
            COALESCE(tag_ns, ''), COALESCE(tag_name, ''),
            COALESCE(schema_name, ''), COALESCE(object_name, ''),
            COALESCE(column_name, '')
        )
    """)
    # --- roles + grants --------------------------------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_role (
            role_name  VARCHAR PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_role_grant (
            role_name     VARCHAR NOT NULL,
            principal_sub VARCHAR NOT NULL,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (role_name, principal_sub)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_object_owner (
            object_kind VARCHAR NOT NULL,
            schema_name VARCHAR NOT NULL,
            object_name VARCHAR NOT NULL DEFAULT '',
            role_name   VARCHAR NOT NULL,
            PRIMARY KEY (object_kind, schema_name, object_name)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_object_grant (
            object_kind VARCHAR NOT NULL,
            schema_name VARCHAR NOT NULL,
            object_name VARCHAR NOT NULL DEFAULT '',
            privilege   VARCHAR NOT NULL,
            role_name   VARCHAR NOT NULL,
            PRIMARY KEY (object_kind, schema_name, object_name, privilege, role_name)
        )
    """)
    # --- audit log -------------------------------------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_governance_audit (
            id               BIGSERIAL PRIMARY KEY,
            ts               TIMESTAMPTZ NOT NULL DEFAULT now(),
            principal_sub    VARCHAR,
            operation        VARCHAR NOT NULL,
            object           VARCHAR,
            decision         VARCHAR,
            masked_cols      TEXT[],
            applied_policies TEXT[],
            detail           JSONB
        )
    """)


# ---------------------------------------------------------------------------
# Pure resolution — no DB. Operates on already-fetched plain rows so it can
# be unit-tested in isolation (see tests/test_governance.py).
# ---------------------------------------------------------------------------

def resolve_effective_policies(
    *,
    principal: str,
    schema: str,
    table: str,
    columns: list[str],
    roles_for_principal: list[str],
    object_tags: list[dict],
    attachments: list[dict],
    masking_bodies: dict[str, dict],
    row_bodies: dict[str, dict],
) -> dict:
    """Derive the policy set that *would* apply to `schema.table` for
    `principal`. Phase 1: descriptive only — we report the derived set, we
    do not evaluate the role clauses or mask anything.

    Tag cascade mirrors Snowflake: a tag on a schema cascades to its tables
    and columns; a tag on a table cascades to its columns; a column tag is
    the most specific. More specific assignments are additive here (we list
    every matching policy) — Phase 2 decides precedence when it enforces.
    """
    def _tags_on(object_kind: str, object_name: str, column_name: str) -> list[tuple[str, str]]:
        out = []
        for ot in object_tags:
            if (
                ot["object_kind"] == object_kind
                and ot["schema_name"] == schema
                and ot["object_name"] == object_name
                and ot["column_name"] == column_name
            ):
                out.append((ot["tag_ns"], ot["tag_name"]))
        return out

    # Tags that cascade onto every column of this table:
    #   schema-level tags + table-level tags (column_name == '').
    cascading_tags: list[tuple[str, str]] = []
    cascading_tags += _tags_on("schema", "", "")
    cascading_tags += _tags_on("table", table, "")

    def _masking_for_tag(tag_ns: str, tag_name: str) -> list[str]:
        return [
            a["policy_name"]
            for a in attachments
            if a["policy_kind"] == "masking"
            and a["target_kind"] == "tag"
            and a.get("tag_ns") == tag_ns
            and a.get("tag_name") == tag_name
        ]

    def _masking_for_column(col: str) -> list[str]:
        return [
            a["policy_name"]
            for a in attachments
            if a["policy_kind"] == "masking"
            and a["target_kind"] == "column"
            and a.get("schema_name") == schema
            and a.get("object_name") == table
            and a.get("column_name") == col
        ]

    column_masks = []
    for col in columns:
        tags = list(cascading_tags) + _tags_on("column", table, col)
        # de-dup tags preserving order
        seen = set()
        tags = [t for t in tags if not (t in seen or seen.add(t))]
        policy_names: list[str] = []
        for (tns, tnm) in tags:
            policy_names += _masking_for_tag(tns, tnm)
        policy_names += _masking_for_column(col)
        policy_names = list(dict.fromkeys(policy_names))  # de-dup, keep order
        if not tags and not policy_names:
            continue
        column_masks.append({
            "column": col,
            "tags": [f"{tns}.{tnm}" for (tns, tnm) in tags],
            "masking_policies": [
                {"name": p, **masking_bodies.get(p, {})} for p in policy_names
            ],
        })

    # Row-access policies: attached directly to the table, or via a tag
    # that sits on the table or its schema.
    row_policies = []
    table_tag_set = set(cascading_tags)
    for a in attachments:
        if a["policy_kind"] != "row_access":
            continue
        via = None
        if a["target_kind"] == "table" and a.get("schema_name") == schema and a.get("object_name") == table:
            via = "table"
        elif a["target_kind"] == "tag" and (a.get("tag_ns"), a.get("tag_name")) in table_tag_set:
            via = f"tag:{a.get('tag_ns')}.{a.get('tag_name')}"
        if via is None:
            continue
        row_policies.append({
            "name": a["policy_name"],
            "via": via,
            "columns": a.get("columns") or [],
            **row_bodies.get(a["policy_name"], {}),
        })

    return {
        "principal": principal,
        "roles": roles_for_principal,
        "table": f"{schema}.{table}",
        "column_masks": column_masks,
        "row_access_policies": row_policies,
        "note": (
            "The derived governance policy set for this principal on this "
            "table. The proxy enforces it on every read — see the "
            "`enforcement` field for the masked columns, row filter, and "
            "masking-view SQL actually applied."
        ),
    }


class GovernanceStore:
    """CRUD + audit over the Phase 1 sidecars, backed by the catalog's PG
    pool. One instance per process; methods are stateless wrappers around
    `catalog.pg_cursor()`.
    """

    def __init__(self, catalog: DuckLakeCatalog) -> None:
        self.catalog = catalog

    # -- audit ------------------------------------------------------------

    def audit(
        self,
        cur,
        *,
        principal: str | None,
        operation: str,
        object_: str | None = None,
        decision: str = "ok",
        masked_cols: list[str] | None = None,
        applied_policies: list[str] | None = None,
        detail: dict | None = None,
    ) -> None:
        """Append one row to the governance audit trail. Takes an open
        cursor so it joins the caller's transaction (authoring + its audit
        row commit atomically)."""
        cur.execute(
            """
            INSERT INTO public.duckicelake_governance_audit
                (principal_sub, operation, object, decision,
                 masked_cols, applied_policies, detail)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
            """,
            (
                principal,
                operation,
                object_,
                decision,
                masked_cols,
                applied_policies,
                json.dumps(detail) if detail is not None else None,
            ),
        )

    def audit_load(self, *, principal: str, object_: str, masked_cols: list[str],
                   applied_policies: list[str], row_filtered: bool,
                   operation: str = "load_table", decision: str | None = None,
                   detail: dict | None = None) -> None:
        """Record an enforced read-path decision (LoadTable, or Phase 3's
        ducklake-credentials vending via `operation`/`decision`/`detail`).
        Best-effort — a failure here must never break the read path, so
        callers wrap it. Defaults preserve the Phase 2 LoadTable shape."""
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            self.audit(
                cur, principal=principal, operation=operation,
                object_=object_,
                decision=decision
                or ("masked" if (masked_cols or row_filtered) else "ok"),
                masked_cols=masked_cols or None,
                applied_policies=applied_policies or None,
                detail={"row_filtered": row_filtered, **(detail or {})},
            )

    def list_audit(self, limit: int = 200) -> list[dict]:
        with self.catalog.pg_cursor(autocommit=False) as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                """
                SELECT id, ts, principal_sub, operation, object, decision,
                       masked_cols, applied_policies, detail
                FROM public.duckicelake_governance_audit
                ORDER BY id DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
        return [
            {
                "id": r[0],
                "ts": r[1].isoformat() if r[1] else None,
                "principal": r[2],
                "operation": r[3],
                "object": r[4],
                "decision": r[5],
                "masked_cols": r[6],
                "applied_policies": r[7],
                "detail": r[8],
            }
            for r in rows
        ]

    def has_file_layer_policies(self) -> bool:
        """True if this catalog defines ANY file-layer masking policy. Lets
        catalog-wide credential vending skip the expensive per-table carve-out
        scan when there are none (the common case) — one indexed PG read on the
        metadata pool instead of a plan_for per table across every namespace."""
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute("SELECT EXISTS(SELECT 1 FROM public.duckicelake_masking_policy "
                        "WHERE file_layer_masking)")
            return bool(cur.fetchone()[0])

    # -- tags -------------------------------------------------------------

    def create_tag(self, principal: str, tag_ns: str, tag_name: str,
                   allowed_values: list[str] | None) -> None:
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                """
                INSERT INTO public.duckicelake_tag (tag_ns, tag_name, allowed_values)
                VALUES (%s, %s, %s)
                ON CONFLICT (tag_ns, tag_name) DO UPDATE
                  SET allowed_values = EXCLUDED.allowed_values
                """,
                (tag_ns, tag_name, allowed_values),
            )
            self.audit(cur, principal=principal, operation="create_tag",
                       object_=f"{tag_ns}.{tag_name}",
                       detail={"allowed_values": allowed_values})

    def assign_object_tag(self, principal: str, *, object_kind: str,
                          schema_name: str, object_name: str, column_name: str,
                          tag_ns: str, tag_name: str, tag_value: str | None) -> None:
        # If this tag already carries a masking policy, assigning it must not
        # give any newly-tagged column a second mask (one-mask-per-column).
        with self.catalog.pg_cursor(autocommit=False) as cur:
            ensure_governance_sidecars(cur)
            tag_masks = self._masking_policies_on_tag(cur, tag_ns, tag_name)
        if tag_masks:
            affected = self._expand_tag_rows(
                [(object_kind, schema_name, object_name, column_name)])
            for p in tag_masks:
                self._assert_columns_unmasked(affected, p)
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                """
                INSERT INTO public.duckicelake_object_tag
                    (object_kind, schema_name, object_name, column_name,
                     tag_ns, tag_name, tag_value)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (object_kind, schema_name, object_name, column_name, tag_ns, tag_name)
                  DO UPDATE SET tag_value = EXCLUDED.tag_value
                """,
                (object_kind, schema_name, object_name, column_name,
                 tag_ns, tag_name, tag_value),
            )
            target = ".".join(p for p in (schema_name, object_name, column_name) if p)
            self.audit(cur, principal=principal, operation="assign_object_tag",
                       object_=target,
                       detail={"tag": f"{tag_ns}.{tag_name}", "value": tag_value,
                               "object_kind": object_kind})

    # -- policies ---------------------------------------------------------

    def create_masking_policy(self, principal: str, name: str,
                              signature_sql: str, body_sql: str,
                              unmasked_roles: list[str] | None = None,
                              file_layer_masking: bool = False) -> None:
        self._create_policy("duckicelake_masking_policy", "create_masking_policy",
                            principal, name, signature_sql, body_sql, unmasked_roles,
                            file_layer_masking=file_layer_masking)

    def create_row_access_policy(self, principal: str, name: str,
                                 signature_sql: str, body_sql: str,
                                 unmasked_roles: list[str] | None = None) -> None:
        self._create_policy("duckicelake_row_access_policy", "create_row_access_policy",
                            principal, name, signature_sql, body_sql, unmasked_roles)

    def _create_policy(self, table: str, op: str, principal: str, name: str,
                       signature_sql: str, body_sql: str,
                       unmasked_roles: list[str] | None,
                       file_layer_masking: bool | None = None) -> None:
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            if file_layer_masking is None:
                # row-access policies have no file_layer column
                cur.execute(
                    f"""
                    INSERT INTO public.{table} (name, signature_sql, body_sql, unmasked_roles)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (name) DO UPDATE
                      SET signature_sql = EXCLUDED.signature_sql,
                          body_sql = EXCLUDED.body_sql,
                          unmasked_roles = EXCLUDED.unmasked_roles
                    """,
                    (name, signature_sql, body_sql, unmasked_roles),
                )
            else:
                cur.execute(
                    f"""
                    INSERT INTO public.{table}
                        (name, signature_sql, body_sql, unmasked_roles, file_layer_masking)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (name) DO UPDATE
                      SET signature_sql = EXCLUDED.signature_sql,
                          body_sql = EXCLUDED.body_sql,
                          unmasked_roles = EXCLUDED.unmasked_roles,
                          file_layer_masking = EXCLUDED.file_layer_masking
                    """,
                    (name, signature_sql, body_sql, unmasked_roles, file_layer_masking),
                )
            self.audit(cur, principal=principal, operation=op, object_=name,
                       detail={"signature": signature_sql,
                               "unmasked_roles": unmasked_roles,
                               **({"file_layer_masking": file_layer_masking}
                                  if file_layer_masking is not None else {})})

    def attach_policy(self, principal: str, *, policy_kind: str, policy_name: str,
                      target_kind: str, tag_ns: str | None = None,
                      tag_name: str | None = None, schema_name: str | None = None,
                      object_name: str | None = None, column_name: str | None = None,
                      columns: list[str] | None = None) -> None:
        # One-mask-per-column invariant: reject a masking attachment that
        # would give any column a second (different) mask. Checked before
        # the insert; re-attaching the same policy is fine (excluded).
        if policy_kind == "masking":
            if target_kind == "column":
                affected = [(schema_name, object_name, column_name)]
            elif target_kind == "tag":
                with self.catalog.pg_cursor(autocommit=False) as cur:
                    affected = self._columns_carrying_tag(cur, tag_ns, tag_name)
            else:
                affected = []
            if affected:
                self._assert_columns_unmasked(affected, policy_name)
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                """
                INSERT INTO public.duckicelake_policy_attachment
                    (policy_kind, policy_name, target_kind, tag_ns, tag_name,
                     schema_name, object_name, column_name, columns)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (policy_kind, policy_name, target_kind,
                             COALESCE(tag_ns, ''), COALESCE(tag_name, ''),
                             COALESCE(schema_name, ''), COALESCE(object_name, ''),
                             COALESCE(column_name, ''))
                  DO UPDATE SET columns = EXCLUDED.columns
                """,
                (policy_kind, policy_name, target_kind, tag_ns, tag_name,
                 schema_name, object_name, column_name, columns),
            )
            self.audit(cur, principal=principal, operation="attach_policy",
                       object_=policy_name,
                       applied_policies=[policy_name],
                       detail={"policy_kind": policy_kind, "target_kind": target_kind,
                               "tag": f"{tag_ns}.{tag_name}" if tag_ns else None,
                               "column": column_name, "columns": columns})

    # -- roles + grants ---------------------------------------------------

    def create_role(self, principal: str, role_name: str) -> None:
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                "INSERT INTO public.duckicelake_role (role_name) VALUES (%s) "
                "ON CONFLICT (role_name) DO NOTHING",
                (role_name,),
            )
            self.audit(cur, principal=principal, operation="create_role",
                       object_=role_name)

    def grant_role(self, principal: str, role_name: str, principal_sub: str) -> None:
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                """
                INSERT INTO public.duckicelake_role_grant (role_name, principal_sub)
                VALUES (%s, %s)
                ON CONFLICT (role_name, principal_sub) DO NOTHING
                """,
                (role_name, principal_sub),
            )
            self.audit(cur, principal=principal, operation="grant_role",
                       object_=role_name, detail={"grantee": principal_sub})

    def grant_object(self, principal: str, *, object_kind: str, schema_name: str,
                     object_name: str, privilege: str, role_name: str) -> None:
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                """
                INSERT INTO public.duckicelake_object_grant
                    (object_kind, schema_name, object_name, privilege, role_name)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (object_kind, schema_name, object_name, privilege, role_name)
                  DO NOTHING
                """,
                (object_kind, schema_name, object_name, privilege, role_name),
            )
            target = ".".join(p for p in (schema_name, object_name) if p)
            self.audit(cur, principal=principal, operation="grant_object",
                       object_=target,
                       detail={"privilege": privilege, "role": role_name})

    # -- delete / detach / revoke ----------------------------------------
    # Deletes refuse while the object is still referenced (409 via
    # GovernanceConflict); the caller detaches/untags/revokes first. Methods
    # whose effect changes a *table's* policy set return the affected
    # (schema, table) pairs so the server can resync masking artifacts.

    def delete_masking_policy(self, principal: str, name: str) -> int:
        return self._delete_policy("duckicelake_masking_policy", "masking",
                                   "delete_masking_policy", principal, name)

    def delete_row_access_policy(self, principal: str, name: str) -> int:
        return self._delete_policy("duckicelake_row_access_policy", "row_access",
                                   "delete_row_access_policy", principal, name)

    def _delete_policy(self, table: str, kind: str, op: str,
                       principal: str, name: str) -> int:
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                "SELECT count(*) FROM public.duckicelake_policy_attachment "
                "WHERE policy_kind = %s AND policy_name = %s", (kind, name))
            attached = cur.fetchone()[0]
            if attached:
                raise GovernanceConflict(
                    f"policy '{name}' is still attached to {attached} target(s) "
                    f"— detach it before deleting")
            cur.execute(f"DELETE FROM public.{table} WHERE name = %s", (name,))
            deleted = cur.rowcount
            if deleted:
                self.audit(cur, principal=principal, operation=op, object_=name)
            return deleted

    def detach_policy(self, principal: str, *, policy_kind: str, policy_name: str,
                      target_kind: str, tag_ns: str | None = None,
                      tag_name: str | None = None, schema_name: str | None = None,
                      object_name: str | None = None, column_name: str | None = None,
                      ) -> list[tuple[str, str]]:
        affected = self._attachment_affected_tables(
            target_kind, tag_ns, tag_name, schema_name, object_name)
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                """
                DELETE FROM public.duckicelake_policy_attachment
                WHERE policy_kind = %s AND policy_name = %s AND target_kind = %s
                  AND COALESCE(tag_ns,'')      = COALESCE(%s,'')
                  AND COALESCE(tag_name,'')    = COALESCE(%s,'')
                  AND COALESCE(schema_name,'') = COALESCE(%s,'')
                  AND COALESCE(object_name,'') = COALESCE(%s,'')
                  AND COALESCE(column_name,'') = COALESCE(%s,'')
                """,
                (policy_kind, policy_name, target_kind, tag_ns, tag_name,
                 schema_name, object_name, column_name),
            )
            deleted = cur.rowcount
            if deleted:
                self.audit(cur, principal=principal, operation="detach_policy",
                           object_=policy_name,
                           detail={"policy_kind": policy_kind,
                                   "target_kind": target_kind})
        return affected if deleted else []

    def remove_object_tag(self, principal: str, *, object_kind: str,
                          schema_name: str, object_name: str, column_name: str,
                          tag_ns: str, tag_name: str) -> list[tuple[str, str]]:
        affected = sorted({(s, t) for s, t, _ in self._expand_tag_rows(
            [(object_kind, schema_name, object_name, column_name)])})
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                """
                DELETE FROM public.duckicelake_object_tag
                WHERE object_kind = %s AND schema_name = %s AND object_name = %s
                  AND column_name = %s AND tag_ns = %s AND tag_name = %s
                """,
                (object_kind, schema_name, object_name, column_name,
                 tag_ns, tag_name),
            )
            deleted = cur.rowcount
            if deleted:
                self.audit(cur, principal=principal, operation="remove_object_tag",
                           object_=".".join(p for p in (schema_name, object_name,
                                                        column_name) if p),
                           detail={"tag": f"{tag_ns}.{tag_name}"})
        return affected if deleted else []

    def delete_tag(self, principal: str, tag_ns: str, tag_name: str) -> int:
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute("SELECT count(*) FROM public.duckicelake_object_tag "
                        "WHERE tag_ns = %s AND tag_name = %s", (tag_ns, tag_name))
            uses = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM public.duckicelake_policy_attachment "
                        "WHERE target_kind = 'tag' AND tag_ns = %s AND tag_name = %s",
                        (tag_ns, tag_name))
            atts = cur.fetchone()[0]
            if uses or atts:
                raise GovernanceConflict(
                    f"tag {tag_ns}.{tag_name} is still in use "
                    f"({uses} assignment(s), {atts} attachment(s)) — remove those first")
            cur.execute("DELETE FROM public.duckicelake_tag "
                        "WHERE tag_ns = %s AND tag_name = %s", (tag_ns, tag_name))
            deleted = cur.rowcount
            if deleted:
                self.audit(cur, principal=principal, operation="delete_tag",
                           object_=f"{tag_ns}.{tag_name}")
            return deleted

    def delete_role(self, principal: str, role_name: str) -> int:
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute("SELECT count(*) FROM public.duckicelake_role_grant "
                        "WHERE role_name = %s", (role_name,))
            grants = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM public.duckicelake_object_grant "
                        "WHERE role_name = %s", (role_name,))
            ogrants = cur.fetchone()[0]
            if grants or ogrants:
                raise GovernanceConflict(
                    f"role '{role_name}' is still granted "
                    f"({grants} principal grant(s), {ogrants} object grant(s)) "
                    f"— revoke those first")
            cur.execute("DELETE FROM public.duckicelake_role WHERE role_name = %s",
                        (role_name,))
            deleted = cur.rowcount
            if deleted:
                self.audit(cur, principal=principal, operation="delete_role",
                           object_=role_name)
            return deleted

    def revoke_role(self, principal: str, role_name: str, principal_sub: str) -> int:
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute("DELETE FROM public.duckicelake_role_grant "
                        "WHERE role_name = %s AND principal_sub = %s",
                        (role_name, principal_sub))
            deleted = cur.rowcount
            if deleted:
                self.audit(cur, principal=principal, operation="revoke_role",
                           object_=role_name, detail={"grantee": principal_sub})
            return deleted

    def revoke_object_grant(self, principal: str, *, object_kind: str,
                            schema_name: str, object_name: str, privilege: str,
                            role_name: str) -> int:
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                "DELETE FROM public.duckicelake_object_grant "
                "WHERE object_kind = %s AND schema_name = %s AND object_name = %s "
                "AND privilege = %s AND role_name = %s",
                (object_kind, schema_name, object_name, privilege, role_name))
            deleted = cur.rowcount
            if deleted:
                self.audit(cur, principal=principal, operation="revoke_object_grant",
                           object_=".".join(p for p in (schema_name, object_name) if p),
                           detail={"privilege": privilege, "role": role_name})
            return deleted

    # -- catalog-drift carry / purge --------------------------------------

    def rename_table_governance(self, principal: str | None, *, src_schema: str,
                                src_table: str, dst_schema: str,
                                dst_table: str) -> None:
        """Carry a table's governance rows when the catalog renames/moves it.
        Tags, attachments, and grants key on (schema, table[, column]) names,
        so without this a rename silently orphans them and the mask stops
        applying — a LEAK. Tag-target attachments aren't table-specific and
        are left as-is; only the per-table object rows move. (object_tag /
        object_grant rows for the table itself and its columns carry
        object_name = table; schema-level rows carry object_name = '' and are
        untouched.)"""
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                "UPDATE public.duckicelake_object_tag "
                "SET schema_name = %s, object_name = %s "
                "WHERE schema_name = %s AND object_name = %s",
                (dst_schema, dst_table, src_schema, src_table))
            cur.execute(
                "UPDATE public.duckicelake_policy_attachment "
                "SET schema_name = %s, object_name = %s "
                "WHERE target_kind IN ('table', 'column') "
                "  AND schema_name = %s AND object_name = %s",
                (dst_schema, dst_table, src_schema, src_table))
            cur.execute(
                "UPDATE public.duckicelake_object_grant "
                "SET schema_name = %s, object_name = %s "
                "WHERE schema_name = %s AND object_name = %s",
                (dst_schema, dst_table, src_schema, src_table))
            self.audit(cur, principal=principal,
                       operation="rename_table_governance",
                       object_=f"{src_schema}.{src_table}",
                       detail={"to": f"{dst_schema}.{dst_table}"})

    def rename_column_governance(self, principal: str | None, *, schema: str,
                                 table: str, old_column: str,
                                 new_column: str) -> None:
        """Carry a column's governance rows when an `add-schema` renames the
        column (same field-id, new name). Tags and column-target attachments
        key on `column_name`, so without this the rename detaches the mask —
        a LEAK. Tag-target masks ride the tag, not the name, and are untouched
        (the column keeps its tag rows, which move here)."""
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                "UPDATE public.duckicelake_object_tag SET column_name = %s "
                "WHERE object_kind = 'column' AND schema_name = %s "
                "  AND object_name = %s AND column_name = %s",
                (new_column, schema, table, old_column))
            cur.execute(
                "UPDATE public.duckicelake_policy_attachment SET column_name = %s "
                "WHERE target_kind = 'column' AND schema_name = %s "
                "  AND object_name = %s AND column_name = %s",
                (new_column, schema, table, old_column))
            self.audit(cur, principal=principal,
                       operation="rename_column_governance",
                       object_=f"{schema}.{table}.{old_column}",
                       detail={"to": new_column})

    def purge_table_governance(self, principal: str | None, *, schema: str,
                               table: str) -> None:
        """Drop a table's governance rows when the catalog drops the table,
        so a later table reusing the name doesn't silently inherit a stale
        mask / row-filter / grant. Tag-target attachments (not table-specific)
        are left intact."""
        with self.catalog.pg_cursor() as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                "DELETE FROM public.duckicelake_object_tag "
                "WHERE schema_name = %s AND object_name = %s",
                (schema, table))
            cur.execute(
                "DELETE FROM public.duckicelake_policy_attachment "
                "WHERE target_kind IN ('table', 'column') "
                "  AND schema_name = %s AND object_name = %s",
                (schema, table))
            cur.execute(
                "DELETE FROM public.duckicelake_object_grant "
                "WHERE schema_name = %s AND object_name = %s",
                (schema, table))
            self.audit(cur, principal=principal,
                       operation="purge_table_governance",
                       object_=f"{schema}.{table}")

    def _attachment_affected_tables(self, target_kind, tag_ns, tag_name,
                                    schema_name, object_name) -> list[tuple[str, str]]:
        if target_kind == "tag":
            with self.catalog.pg_cursor(autocommit=False) as cur:
                cols = self._columns_carrying_tag(cur, tag_ns, tag_name)
            return sorted({(s, t) for s, t, _ in cols})
        if target_kind in ("column", "table") and schema_name and object_name:
            return [(schema_name, object_name)]
        return []

    def roles_for_principal(self, principal_sub: str) -> list[str]:
        with self.catalog.pg_cursor(autocommit=False) as cur:
            ensure_governance_sidecars(cur)
            cur.execute(
                "SELECT role_name FROM public.duckicelake_role_grant "
                "WHERE principal_sub = %s ORDER BY role_name",
                (principal_sub,),
            )
            return [r[0] for r in cur.fetchall()]

    # -- effective policy view -------------------------------------------

    def effective_policies(self, *, principal: str, schema: str, table: str) -> dict:
        """Fetch the rows needed to derive the policy set for principal +
        table, then delegate to the pure `resolve_effective_policies`."""
        inp = self.resolution_inputs(schema, table)
        roles = self.roles_for_principal(principal)
        return resolve_effective_policies(
            principal=principal, schema=schema, table=table,
            columns=inp["columns"], roles_for_principal=roles,
            object_tags=inp["object_tags"], attachments=inp["attachments"],
            masking_bodies=inp["masking_bodies"], row_bodies=inp["row_bodies"],
        )

    @staticmethod
    def _fetch_object_tags(cur, schema: str, table: str) -> list[dict]:
        # Schema-level (cascades to all its tables), plus everything scoped
        # to this exact table (table-level + column-level rows).
        cur.execute(
            """
            SELECT object_kind, schema_name, object_name, column_name,
                   tag_ns, tag_name, tag_value
            FROM public.duckicelake_object_tag
            WHERE schema_name = %s
              AND (object_kind = 'schema' OR object_name = %s)
            ORDER BY object_kind, object_name, column_name, tag_ns, tag_name
            """,
            (schema, table),
        )
        cols = ["object_kind", "schema_name", "object_name", "column_name",
                "tag_ns", "tag_name", "tag_value"]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    @staticmethod
    def _fetch_attachments(cur) -> list[dict]:
        cur.execute(
            """
            SELECT policy_kind, policy_name, target_kind, tag_ns, tag_name,
                   schema_name, object_name, column_name, columns
            FROM public.duckicelake_policy_attachment
            ORDER BY policy_kind, policy_name, target_kind,
                     tag_ns, tag_name, schema_name, object_name, column_name
            """
        )
        cols = ["policy_kind", "policy_name", "target_kind", "tag_ns", "tag_name",
                "schema_name", "object_name", "column_name", "columns"]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    @staticmethod
    def _fetch_policy_bodies(cur, table: str) -> dict[str, dict]:
        if table == "duckicelake_masking_policy":
            cur.execute(
                f"SELECT name, signature_sql, body_sql, unmasked_roles, "
                f"file_layer_masking FROM public.{table}"
            )
            return {
                r[0]: {"signature": r[1], "body": r[2],
                       "unmasked_roles": r[3] or [],
                       "file_layer_masking": bool(r[4])}
                for r in cur.fetchall()
            }
        cur.execute(
            f"SELECT name, signature_sql, body_sql, unmasked_roles FROM public.{table}"
        )
        return {
            r[0]: {"signature": r[1], "body": r[2], "unmasked_roles": r[3] or []}
            for r in cur.fetchall()
        }

    def resolution_inputs(self, schema: str, table: str) -> dict:
        """Fetch every row needed to derive policies for `schema.table`.

        Shared by `effective_policies` (descriptive) and the Phase 2
        `PolicyEngine` (enforcing) so both see an identical model.
        """
        columns = [c.name for c in self.catalog.get_columns([schema], table)]
        with self.catalog.pg_cursor(autocommit=False) as cur:
            ensure_governance_sidecars(cur)
            object_tags = self._fetch_object_tags(cur, schema, table)
            attachments = self._fetch_attachments(cur)
            masking_bodies = self._fetch_policy_bodies(cur, "duckicelake_masking_policy")
            row_bodies = self._fetch_policy_bodies(cur, "duckicelake_row_access_policy")
        return {
            "columns": columns,
            "object_tags": object_tags,
            "attachments": attachments,
            "masking_bodies": masking_bodies,
            "row_bodies": row_bodies,
        }

    # -- one-mask-per-column invariant -----------------------------------

    def _masks_by_column(self, schema: str, table: str) -> dict[str, set[str]]:
        """Masking-policy names currently reaching each column of a table
        (via tags or direct attachment), independent of any principal."""
        inp = self.resolution_inputs(schema, table)
        derived = resolve_effective_policies(
            principal="__invariant__", schema=schema, table=table,
            columns=inp["columns"], roles_for_principal=[],
            object_tags=inp["object_tags"], attachments=inp["attachments"],
            masking_bodies=inp["masking_bodies"], row_bodies=inp["row_bodies"],
        )
        return {c["column"]: {p["name"] for p in c["masking_policies"]}
                for c in derived["column_masks"]}

    def _table_columns(self, schema: str, table: str) -> list[str]:
        try:
            return [c.name for c in self.catalog.get_columns([schema], table)]
        except Exception:
            return []   # table doesn't exist yet → nothing to mask

    def _assert_columns_unmasked(self, affected: list[tuple[str, str, str]],
                                 policy_name: str) -> None:
        """409 if any (schema, table, column) already carries a masking
        policy other than `policy_name` — a column may have only one mask."""
        from collections import defaultdict
        by_table: dict[tuple[str, str], list[str]] = defaultdict(list)
        for sch, tbl, col in affected:
            by_table[(sch, tbl)].append(col)
        for (sch, tbl), cols in by_table.items():
            masks = self._masks_by_column(sch, tbl)
            for col in cols:
                others = masks.get(col, set()) - {policy_name}
                if others:
                    raise GovernanceConflict(
                        f"column {sch}.{tbl}.{col} is already masked by policy "
                        f"'{sorted(others)[0]}'; a column may have only one "
                        f"masking policy — detach the existing one first"
                    )

    def _columns_carrying_tag(self, cur, tag_ns: str, tag_name: str
                              ) -> list[tuple[str, str, str]]:
        """Every (schema, table, column) the tag currently reaches, expanding
        schema/table-level assignments to their columns."""
        cur.execute(
            "SELECT object_kind, schema_name, object_name, column_name "
            "FROM public.duckicelake_object_tag "
            "WHERE tag_ns = %s AND tag_name = %s",
            (tag_ns, tag_name),
        )
        return self._expand_tag_rows(cur.fetchall())

    def _expand_tag_rows(self, rows) -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []
        for kind, sch, obj, col in rows:
            if kind == "column":
                out.append((sch, obj, col))
            elif kind == "table":
                out += [(sch, obj, c) for c in self._table_columns(sch, obj)]
            elif kind == "schema":
                for (_s, tbl) in self.catalog.list_tables([sch]):
                    out += [(sch, tbl, c) for c in self._table_columns(sch, tbl)]
        return out

    def _masking_policies_on_tag(self, cur, tag_ns: str, tag_name: str) -> list[str]:
        cur.execute(
            "SELECT policy_name FROM public.duckicelake_policy_attachment "
            "WHERE policy_kind = 'masking' AND target_kind = 'tag' "
            "AND tag_ns = %s AND tag_name = %s",
            (tag_ns, tag_name),
        )
        return [r[0] for r in cur.fetchall()]
