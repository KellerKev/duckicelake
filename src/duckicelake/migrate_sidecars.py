"""One-off upgrade: copy pre-isolation sidecar rows into each catalog's schema.

Before per-catalog sidecars, every catalog read its governance (tags,
policies, attachments, roles, grants, static keys) and table sidecars
(properties, refs, partition specs) from shared `public.duckicelake_*`
tables. Those now live in each catalog's own metadata schema; the default
catalog keeps `public`. This copies the old shared rows into every
non-default catalog so each keeps EXACTLY the policy it saw before the
upgrade, then each catalog's governance evolves independently:

* definitions (tags, masking / row-access policies, roles, role grants,
  static S3 keys) → copied to every catalog;
* object-keyed rows (object tags, policy attachments, owners, object grants,
  table properties / refs / partition fields) → copied only to catalogs where
  that schema (or schema.table) exists; tag-target attachments, which name
  no object, go everywhere;
* runtime state (audit, materialisation log, NaN counts, masked-export
  pointers) → not copied; each catalog rebuilds its own lazily.

Nothing is deleted from `public` (it stays the default catalog's). Existing
rows in a catalog's schema win (ON CONFLICT DO NOTHING), so re-running is
safe. Dry run by default:

    python -m duckicelake.migrate_sidecars            # report
    python -m duckicelake.migrate_sidecars --apply    # copy
"""
from __future__ import annotations

import argparse

import psycopg
from psycopg import sql

from .catalog import DuckLakeCatalog
from .config import load_settings
from .governance import ensure_governance_sidecars
from .registry import CatalogRegistry

DEFINITIONS = ("tag", "masking_policy", "row_access_policy", "role", "role_grant",
               "static_s3_key")
# table -> (schema column, object column | None, kind column | None)
OBJECT_KEYED = {
    "object_tag": ("schema_name", "object_name", "object_kind"),
    "policy_attachment": ("schema_name", "object_name", "target_kind"),
    "object_owner": ("schema_name", "object_name", "object_kind"),
    "object_grant": ("schema_name", "object_name", "object_kind"),
    "table_property": ("schema_name", "table_name", None),
    "table_tag": ("schema_name", "table_name", None),
    "table_partition_field": ("schema_name", "table_name", None),
}
_SKIP_COLUMNS = {"id"}   # serial keys are re-assigned in the target


def _columns(cur, schema: str, table: str) -> list[str]:
    cur.execute("SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
                (schema, table))
    return [r[0] for r in cur.fetchall() if r[0] not in _SKIP_COLUMNS]


def _exists(cur, schema: str, table: str) -> bool:
    cur.execute("SELECT to_regclass(%s)", (f'"{schema}"."{table}"',))
    return cur.fetchone()[0] is not None


def _object_filter(meta: str, schema_col: str, obj_col: str, kind_col: str | None,
                   kind_table: str) -> sql.Composable:
    """WHERE clause keeping rows whose object exists in the catalog `meta`."""
    m = sql.Identifier(meta)
    schema_live = sql.SQL(
        "EXISTS (SELECT 1 FROM {m}.ducklake_schema s WHERE s.end_snapshot IS NULL "
        "AND s.schema_name = src.{sc})").format(m=m, sc=sql.Identifier(schema_col))
    table_live = sql.SQL(
        "EXISTS (SELECT 1 FROM {m}.ducklake_table t JOIN {m}.ducklake_schema s "
        "USING (schema_id) WHERE t.end_snapshot IS NULL AND s.end_snapshot IS NULL "
        "AND s.schema_name = src.{sc} AND t.table_name = src.{oc})").format(
            m=m, sc=sql.Identifier(schema_col), oc=sql.Identifier(obj_col))
    if kind_col is None:                 # table sidecars: always table-scoped
        return table_live
    k = sql.Identifier(kind_col)
    if kind_table == "policy_attachment":
        # tag targets name no object; table/column targets need the table
        return sql.SQL("(src.{k} = 'tag' OR {t})").format(k=k, t=table_live)
    return sql.SQL("((src.{k} = 'schema' AND {s}) OR (src.{k} <> 'schema' AND {t}))").format(
        k=k, s=schema_live, t=table_live)


def migrate(apply: bool) -> list[tuple[str, str, int]]:
    settings = load_settings()
    registry = CatalogRegistry(settings)
    report = []
    with psycopg.connect(settings.pg_dsn, autocommit=False) as conn, conn.cursor() as cur:
        for cid, ref in registry.list_refs():
            meta = ref.metadata_schema
            if not meta or meta == "public":
                continue
            cur.execute("SELECT 1 FROM pg_namespace WHERE nspname = %s", (meta,))
            if cur.fetchone() is None:     # registered but never attached
                continue
            if apply:
                ensure_governance_sidecars(cur, meta)
                DuckLakeCatalog(settings, ref)._ensure_sidecar(cur)
            for name in DEFINITIONS + tuple(OBJECT_KEYED):
                table = f"duckicelake_{name}"
                if not _exists(cur, "public", table):
                    continue
                cols = _columns(cur, "public", table)
                where = sql.SQL("TRUE")
                if name in OBJECT_KEYED:
                    where = _object_filter(meta, *OBJECT_KEYED[name], kind_table=name)
                select = sql.SQL("SELECT {cols} FROM public.{t} src WHERE {w}").format(
                    cols=sql.SQL(", ").join(sql.SQL("src.") + sql.Identifier(c) for c in cols),
                    t=sql.Identifier(table), w=where)
                cur.execute(sql.SQL("SELECT count(*) FROM ({}) q").format(select))
                n = cur.fetchone()[0]
                if n and apply:
                    cur.execute(sql.SQL("INSERT INTO {m}.{t} ({cols}) {sel} ON CONFLICT DO NOTHING")
                                .format(m=sql.Identifier(meta), t=sql.Identifier(table),
                                        cols=sql.SQL(", ").join(map(sql.Identifier, cols)),
                                        sel=select))
                if n:
                    report.append((cid, name, n))
        if apply:
            conn.commit()
        else:
            conn.rollback()
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--apply", action="store_true", help="copy (default: dry run)")
    args = ap.parse_args()
    rows = migrate(args.apply)
    for cid, name, n in rows:
        print(f"{'copied' if args.apply else 'would copy'} {n:4d}  {cid}: duckicelake_{name}")
    if not rows:
        print("nothing to copy")


if __name__ == "__main__":
    main()
