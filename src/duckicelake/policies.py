"""Phase 2 policy engine — Iceberg REST enforcement.

Turns the Phase 1 governance model into a per-principal *enforcement plan*
for a table at LoadTable time, and applies that plan to the Iceberg
TableMetadata the proxy returns.

Enforcement reality: an Iceberg REST client reads the
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
import logging
import re
from dataclasses import dataclass, field

from .governance import GovernanceStore, resolve_effective_policies

log = logging.getLogger("duckicelake.policies")


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
    # Phase 4: any applied (non-bypassed) mask policy demands the mask be
    # materialized physically as masked Parquet copies.
    file_layer: bool = False
    # Union of unmasked_roles across the applied file-layer policies — the
    # roles RLS should let read base file rows (the interlock bypass).
    # Captured here during build_plan so callers needn't re-fetch the model.
    file_layer_bypass: list[str] = field(default_factory=list)

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


def _qi(name: str) -> str:
    """Quote a SQL identifier, escaping any embedded double-quote so a
    column/table name like `a"b` can't break out of the quoting."""
    return '"' + name.replace('"', '""') + '"'


def _ql(value: str) -> str:
    """Quote a SQL string literal, escaping embedded single-quotes."""
    return "'" + value.replace("'", "''") + "'"


def _masked_projection(columns: list[str], masks: dict[str, str]) -> str:
    """The shared SELECT projection for both the masking view and the
    file-layer export: masked columns become their (trusted, admin-authored)
    mask expression aliased back to the column; others pass through. Column
    identifiers are escaped; mask expressions are SQL by design."""
    projected = []
    for c in columns:
        if c in masks:
            projected.append(f'{masks[c]} AS {_qi(c)}')
        else:
            projected.append(_qi(c))
    return ", ".join(projected)


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
        # A column resolves to exactly one masking policy — the authoring
        # layer rejects a second mask on a column (409). This is the read-path
        # safety net: pick the non-bypassed policy with the lowest name so the
        # outcome is deterministic even if two ever coexist (legacy data), and
        # warn loudly. (Read path stays fail-open — never raises.)
        applicable = sorted(
            (pol for pol in col["masking_policies"]
             if not _bypasses(roles, masking_bodies.get(pol["name"], {})
                              .get("unmasked_roles"))),
            key=lambda p: p["name"],
        )
        if not applicable:
            continue
        if len(applicable) > 1:
            log.warning(
                "column %s.%s.%s resolves to %d masking policies %s — "
                "applying %r (lowest name); authoring should have rejected this",
                schema, table, col["column"], len(applicable),
                [p["name"] for p in applicable], applicable[0]["name"],
            )
        pol = applicable[0]
        body = masking_bodies.get(pol["name"], {})
        expr = _qualify_expr(body.get("body", "NULL"), col["column"])
        plan.masks.append(MaskDecision(
            column=col["column"],
            policy_name=pol["name"],
            mask_expr=expr,
            doc=f"[masked by policy '{pol['name']}' — principal lacks an unmasked role]",
        ))
        if body.get("file_layer_masking"):
            plan.file_layer = True
            for r in body.get("unmasked_roles") or []:
                if r not in plan.file_layer_bypass:
                    plan.file_layer_bypass.append(r)

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
    source = f'{_qi(schema)}.{_qi(table)}'
    if row_filter:
        source = f'(SELECT * FROM {source} WHERE {row_filter}) AS {_qi(table)}'
    return f'SELECT {_masked_projection(columns, masks)} FROM {source}'


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
    canonical_parts: list = [
        plan.schema,
        plan.table,
        sorted((m.column, m.mask_expr) for m in plan.masks),
        plan.row_filter,
        sorted(cols),
    ]
    # Folded only when set, so pre-Phase-4 signatures stay byte-identical.
    # Toggling the flag must rotate the signature: the view body and the
    # credential scope both key on it and would otherwise disagree.
    if plan.file_layer:
        canonical_parts.append("file_layer")
    canonical = json.dumps(canonical_parts, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


#: Session-dependent SQL tokens that cannot be baked into physical bytes —
#: a file-layer export with any of these in a mask/filter body is refused
#: (fail-open to catalog-level masking).
_SESSION_TOKENS = re.compile(
    r"\b(current_user|session_user|current_setting|current_role|user)\b",
    re.IGNORECASE,
)


def plan_is_exportable(plan: TablePolicyPlan) -> bool:
    """File-layer exports bake the mask into Parquet; expressions that
    depend on the executing session would freeze the *exporter's* identity
    into the bytes."""
    bodies = [m.mask_expr for m in plan.masks]
    if plan.row_filter:
        bodies.append(plan.row_filter)
    return not any(_SESSION_TOKENS.search(b) for b in bodies)


def build_masked_export_select(
    plan: TablePolicyPlan,
    *,
    catalog_name: str,
    snapshot_id: int | None = None,
) -> str:
    """The SELECT a file-layer export COPYs: same projection/filter
    semantics as the masking view, but fully qualified against the proxy's
    attached catalog and optionally pinned to a DuckLake snapshot so the
    export is exactly attributable."""
    masks = {m.column: m.mask_expr for m in plan.masks}
    source = f'{_qi(catalog_name)}.{_qi(plan.schema)}.{_qi(plan.table)}'
    if snapshot_id is not None:
        source += f" AT (VERSION => {int(snapshot_id)})"
    if plan.row_filter:
        source = (f'(SELECT * FROM {source} WHERE {plan.row_filter}) '
                  f'AS {_qi(plan.table)}')
    return f'SELECT {_masked_projection(plan.columns, masks)} FROM {source}'


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

    @staticmethod
    def file_layer_bypass_roles(plan: TablePolicyPlan) -> list[str]:
        """The roles RLS should let read base file rows (the interlock
        bypass), written into `duckicelake.file-layer-bypass-roles`.
        build_plan already captured this union on the plan, so this is a
        pure read — no second model fetch on the hot path."""
        return sorted(set(plan.file_layer_bypass))
