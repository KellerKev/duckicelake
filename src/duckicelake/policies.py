"""Phase 2 policy engine — Iceberg REST enforcement.

Turns the Phase 1 governance model into a per-principal *enforcement plan*
for a table at LoadTable time, and applies that plan to the Iceberg
TableMetadata the proxy returns.

Enforcement reality (see GOVERNANCE.md): an Iceberg REST client reads the
Parquet bytes itself, so the proxy cannot mask bytes by editing metadata
alone. Phase 2 therefore emits, per principal:

  * **Trino/Spark fast-path** — `iceberg.row-filter` + `duckicelake.mask.*`
    table properties those engines can honor directly.
  * **Schema annotation** — masked columns get a `doc` note so any client
    surfaces "this column is governed".
  * **A view-fallback SQL string** — the SELECT that masks/filters, which a
    PyIceberg/DuckDB deployment materialises as an Iceberg view (the only
    byte-level vector for those engines; Phase 4 covers pre-masked files).

The bypass decision is declarative: a principal holding any role in a
policy's `unmasked_roles` sees unmasked data. This stands in for Snowflake's
`CURRENT_ROLE()` check in the policy body — we don't execute the body
per-principal, we evaluate the role set and use the body purely as the
masked-value / filter expression for the view SQL.

The `build_plan` / `apply_plan_to_metadata` / `build_masked_view_sql`
functions are pure and unit-tested without Postgres.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field

from .governance import GovernanceStore, resolve_effective_policies


_VAL_TOKEN = re.compile(r"\bval\b")


@dataclass
class MaskDecision:
    column: str
    policy_name: str
    mask_expr: str   # SQL expression for the masked value (token `val` = the column)
    doc: str


@dataclass
class TablePolicyPlan:
    principal: str
    roles: list[str]
    schema: str
    table: str
    masks: list[MaskDecision] = field(default_factory=list)
    row_filter: str | None = None       # combined SQL predicate (true => keep row)
    row_policies: list[str] = field(default_factory=list)
    view_sql: str | None = None
    columns: list[str] = field(default_factory=list)   # base-table column set

    @property
    def masked_columns(self) -> list[str]:
        return [m.column for m in self.masks]

    @property
    def applied_policies(self) -> list[str]:
        return sorted({m.policy_name for m in self.masks} | set(self.row_policies))

    def is_empty(self) -> bool:
        return not self.masks and self.row_filter is None


def _bypasses(roles: list[str], unmasked_roles: list[str] | None) -> bool:
    """True if the principal's roles let it skip the policy."""
    if not unmasked_roles:
        return False
    return bool(set(roles) & set(unmasked_roles))


def _qualify_expr(body_sql: str, column: str) -> str:
    """Render a policy body as a concrete column expression.

    The standalone token `val` (Snowflake's masking-policy argument
    convention) is replaced with the quoted column. Bodies with no `val`
    (e.g. `'***'`, `NULL`) are constant masks and pass through unchanged.
    """
    return _VAL_TOKEN.sub(f'"{column}"', body_sql)


def build_plan(
    *,
    principal: str,
    roles: list[str],
    schema: str,
    table: str,
    columns: list[str],
    object_tags: list[dict],
    attachments: list[dict],
    masking_bodies: dict[str, dict],
    row_bodies: dict[str, dict],
) -> TablePolicyPlan:
    """Pure: derive the enforcement plan for one principal + table."""
    # Reuse the Phase 1 resolver to get the *derived* policy set, then apply
    # the bypass decision to turn "applies" into "actually masks for this
    # principal".
    derived = resolve_effective_policies(
        principal=principal, schema=schema, table=table, columns=columns,
        roles_for_principal=roles, object_tags=object_tags,
        attachments=attachments, masking_bodies=masking_bodies,
        row_bodies=row_bodies,
    )

    plan = TablePolicyPlan(principal=principal, roles=roles, schema=schema,
                           table=table, columns=list(columns))

    for col in derived["column_masks"]:
        for pol in col["masking_policies"]:
            body = masking_bodies.get(pol["name"], {})
            if _bypasses(roles, body.get("unmasked_roles")):
                continue
            expr = _qualify_expr(body.get("body", "NULL"), col["column"])
            plan.masks.append(MaskDecision(
                column=col["column"],
                policy_name=pol["name"],
                mask_expr=expr,
                doc=f"[masked by policy '{pol['name']}' — principal lacks an unmasked role]",
            ))
            break   # one mask per column is enough; first applicable wins

    predicates: list[str] = []
    for rp in derived["row_access_policies"]:
        body = row_bodies.get(rp["name"], {})
        if _bypasses(roles, body.get("unmasked_roles")):
            continue
        plan.row_policies.append(rp["name"])
        pred = body.get("body")
        if pred:
            predicates.append(f"({pred})")
    if predicates:
        plan.row_filter = " AND ".join(predicates)

    if not plan.is_empty():
        plan.view_sql = build_masked_view_sql(
            schema=schema, table=table, columns=columns,
            masks={m.column: m.mask_expr for m in plan.masks},
            row_filter=plan.row_filter,
        )
    return plan


def build_masked_view_sql(
    *,
    schema: str,
    table: str,
    columns: list[str],
    masks: dict[str, str],
    row_filter: str | None,
) -> str:
    """The view-fallback SELECT: masked columns replaced by their expression,
    the row filter applied in a nested subquery. The nesting matters now that
    views are executed, not advisory: a filter referencing a masked column
    must see the *raw* value (Snowflake row-policy semantics), and a flat
    WHERE after the mask aliases resolves alias-vs-base-column differently
    per engine. The base table stays unqualified — a DuckLake-direct client
    resolves it against its own attached catalog."""
    projected = []
    for c in columns:
        if c in masks:
            projected.append(f'{masks[c]} AS "{c}"')
        else:
            projected.append(f'"{c}"')
    source = f'"{schema}"."{table}"'
    if row_filter:
        source = f'(SELECT * FROM {source} WHERE {row_filter}) AS "{table}"'
    return f'SELECT {", ".join(projected)} FROM {source}'


def mask_signature(plan: TablePolicyPlan, columns: list[str] | None = None) -> str:
    """Stable short id for a plan's *effective mask shape* on a table.

    Principals whose plans mask the same columns the same way (and share the
    row filter) get the same signature → one physical masking view serves
    them all. The base column set is folded in so an ADD/DROP COLUMN yields
    a fresh signature (and therefore a fresh view) automatically. The table
    identity is folded in too: the transparent `__masked_{sig}` schema is
    global, so two same-shaped tables in different namespaces must not
    collide on it. Empty plan → "" (no view needed).
    """
    if plan.is_empty():
        return ""
    cols = plan.columns if columns is None else columns
    canonical = json.dumps([
        plan.schema,
        plan.table,
        sorted((m.column, m.mask_expr) for m in plan.masks),
        plan.row_filter,
        sorted(cols),
    ], separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


def apply_plan_to_metadata(metadata: dict, plan: TablePolicyPlan) -> dict:
    """Return a copy of `metadata` carrying the plan's enforcement signals:
    column `doc` annotations + Trino/Spark + duckicelake table properties.
    Does NOT mutate bytes (impossible from metadata) — see module docstring.
    """
    if plan.is_empty():
        return metadata
    md = copy.deepcopy(metadata)

    masked = {m.column: m for m in plan.masks}
    for sch in md.get("schemas", []):
        for f in sch.get("fields", []):
            dec = masked.get(f.get("name"))
            if dec is not None:
                existing = f.get("doc")
                f["doc"] = f"{existing} {dec.doc}".strip() if existing else dec.doc

    props = dict(md.get("properties", {}))
    if plan.masks:
        props["duckicelake.masked-columns"] = ",".join(sorted(masked))
        for col, dec in masked.items():
            # Trino/Spark column-mask fast-path + the masked expression.
            props[f"duckicelake.mask.{col}"] = dec.mask_expr
    if plan.row_filter:
        props["duckicelake.row-filter"] = plan.row_filter
        props["iceberg.row-filter"] = plan.row_filter      # Trino/Spark key
    if plan.view_sql:
        props["duckicelake.masking-view-sql"] = plan.view_sql
    props["duckicelake.policy-principal"] = plan.principal
    md["properties"] = props
    return md


class PolicyEngine:
    """DB-backed front door: fetch the model for a table, build the plan."""

    def __init__(self, store: GovernanceStore) -> None:
        self.store = store

    def plan_for(self, *, principal: str, roles: list[str],
                 schema: str, table: str) -> TablePolicyPlan:
        inp = self.store.resolution_inputs(schema, table)
        return build_plan(
            principal=principal, roles=roles, schema=schema, table=table,
            columns=inp["columns"], object_tags=inp["object_tags"],
            attachments=inp["attachments"], masking_bodies=inp["masking_bodies"],
            row_bodies=inp["row_bodies"],
        )
