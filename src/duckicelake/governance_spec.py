"""Governance as a declarative spec: export a catalog's policy intent to a
git-friendly document, and plan/apply a document back onto a catalog.

The spec covers authored intent: tags, roles and their members, object
grants, tag assignments, masking and row-access policies with their
attachments. It leaves out what is not intent: static S3 keys (credentials),
object owners (set by table creation, not authored), and the audit trail.

    version: 1
    kind: duckicelake/governance
    catalog: acme__main            # informational; import ignores it
    tags:
    - tag: pii.email
      allowed_values: [a, b]       # omitted = free-form
    roles:
    - role: pii_reader
      members: [alice@acme.test]
    grants:
    - role: analyst
      privilege: SELECT
      on: {schema: sales, table: customers}
    tag_assignments:
    - tag: pii.email
      on: {schema: sales, table: customers, column: email}
      value: null                  # optional
    masking_policies:
    - name: mask_email
      signature: (val VARCHAR)
      body: left(val, 2) || '***'
      unmasked_roles: [pii_reader]
      file_layer: false
      attach:
      - tag: pii.email
      - on: {schema: sales, table: customers, column: email}
    row_access_policies:
    - name: eu_only
      signature: (region VARCHAR)
      body: region = 'EU'
      attach:
      - on: {schema: sales, table: orders}
        columns: [region]

An object reference (`on`) names a schema, optionally a `table` or `view`,
and optionally a `column` of that table. A tag is `ns.name`, or
`{namespace: ..., name: ...}` when the namespace itself holds a dot.

Import is all-or-nothing: every change runs through the same store methods
as the REST authoring surface (so the one-mask-per-column invariant, body
checks and per-change audit rows all apply) inside ONE Postgres
transaction. A plan is that same run, rolled back — so a plan that passes
is exactly what apply will do, invariants included. Without `prune` the
import only adds and updates; with `prune` the spec is authoritative and
anything the catalog has that the spec lacks is removed.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import yaml

from .governance import (
    OBJECT_KINDS,
    GovernanceConflict,
    GovernanceStore,
    ensure_governance_sidecars,
)
from .sqlsafe import check_single_select

SPEC_VERSION = 1
SPEC_KIND = "duckicelake/governance"
MAX_SPEC_BYTES = 1 << 20


class SpecError(ValueError):
    """The document is not a valid governance spec (HTTP 400)."""


class VersionConflict(Exception):
    """Governance changed since the plan was made (HTTP 409)."""

    def __init__(self, expected: str, actual: str) -> None:
        super().__init__(
            f"governance version is {actual}, the plan was made at {expected} — "
            f"plan again")
        self.expected = expected
        self.actual = actual


class _DryRun(Exception):
    """Raised inside the transaction to roll a plan back."""


# ---------------------------------------------------------------------------
# State: the normalized governance model, comparable key by key.
# ---------------------------------------------------------------------------

# Keys (all strings; None where a field does not apply):
#   tags         (ns, name)                                   -> allowed_values tuple | None
#   roles        role                                         -> None
#   members      (role, principal)                            -> None
#   grants       (object_kind, schema, object, privilege, role) -> None
#   assignments  (object_kind, schema, object, column, ns, name) -> value | None
#   masking      name -> (signature, body, unmasked_roles tuple, file_layer bool)
#   row_access   name -> (signature, body, unmasked_roles tuple)
#   attachments  (policy_kind, policy, target_kind, tag_ns, tag_name,
#                 schema, object, column)                     -> columns tuple | None

SECTIONS = ("tags", "roles", "members", "grants", "assignments",
            "masking", "row_access", "attachments")


@dataclass
class State:
    tags: dict = field(default_factory=dict)
    roles: dict = field(default_factory=dict)
    members: dict = field(default_factory=dict)
    grants: dict = field(default_factory=dict)
    assignments: dict = field(default_factory=dict)
    masking: dict = field(default_factory=dict)
    row_access: dict = field(default_factory=dict)
    attachments: dict = field(default_factory=dict)


def _n(v):
    """'' and None both mean 'not set' in the sidecars."""
    return v if v not in ("", None) else None


def _roles_tuple(v) -> tuple:
    return tuple(sorted(set(v or ())))


def read_state(store: GovernanceStore) -> State:
    """The catalog's current governance, normalized. Joins the caller's
    transaction when one is active."""
    sc = store._sc
    s = State()
    with store.catalog.pg_cursor() as cur:
        ensure_governance_sidecars(cur, store.catalog.sidecar_schema)
        cur.execute(f"SELECT tag_ns, tag_name, allowed_values FROM {sc}.duckicelake_tag")
        for ns, name, allowed in cur.fetchall():
            s.tags[(ns, name)] = tuple(sorted(allowed)) if allowed is not None else None
        cur.execute(f"SELECT role_name FROM {sc}.duckicelake_role")
        for (r,) in cur.fetchall():
            s.roles[r] = None
        cur.execute(f"SELECT role_name, principal_sub FROM {sc}.duckicelake_role_grant")
        for r, p in cur.fetchall():
            s.members[(r, p)] = None
        cur.execute(f"SELECT object_kind, schema_name, object_name, privilege, role_name "
                    f"FROM {sc}.duckicelake_object_grant")
        for k, sch, obj, priv, r in cur.fetchall():
            s.grants[(k, sch, obj or "", priv, r)] = None
        cur.execute(f"SELECT object_kind, schema_name, object_name, column_name, "
                    f"tag_ns, tag_name, tag_value FROM {sc}.duckicelake_object_tag")
        for k, sch, obj, col, ns, name, val in cur.fetchall():
            s.assignments[(k, sch, obj or "", col or "", ns, name)] = val
        cur.execute(f"SELECT name, signature_sql, body_sql, unmasked_roles, "
                    f"file_layer_masking FROM {sc}.duckicelake_masking_policy")
        for name, sig, body, roles, fl in cur.fetchall():
            s.masking[name] = (sig, body, _roles_tuple(roles), bool(fl))
        cur.execute(f"SELECT name, signature_sql, body_sql, unmasked_roles "
                    f"FROM {sc}.duckicelake_row_access_policy")
        for name, sig, body, roles in cur.fetchall():
            s.row_access[name] = (sig, body, _roles_tuple(roles))
        cur.execute(f"SELECT policy_kind, policy_name, target_kind, tag_ns, tag_name, "
                    f"schema_name, object_name, column_name, columns "
                    f"FROM {sc}.duckicelake_policy_attachment")
        for pk, pn, tk, tns, tnm, sch, obj, col, cols in cur.fetchall():
            key = (pk, pn, tk, _n(tns), _n(tnm), _n(sch), _n(obj), _n(col))
            s.attachments[key] = tuple(cols) if cols else None
    return s


# ---------------------------------------------------------------------------
# Export: State -> document
# ---------------------------------------------------------------------------

def _tag_out(ns: str, name: str):
    return {"namespace": ns, "name": name} if "." in ns else f"{ns}.{name}"


def _ref_out(kind: str, schema: str, obj: str | None, col: str | None) -> dict:
    if kind == "column":
        return {"schema": schema, "table": obj, "column": col}
    if kind == "view":
        return {"schema": schema, "view": obj}
    if kind == "table":
        return {"schema": schema, "table": obj}
    return {"schema": schema}


def _attach_out(key: tuple, columns) -> dict:
    pk, _pn, tk, tns, tnm, sch, obj, col = key
    if tk == "tag":
        out: dict = {"tag": _tag_out(tns, tnm)}
    elif tk == "column":
        out = {"on": _ref_out("column", sch, obj, col)}
    else:
        out = {"on": _ref_out("table", sch, obj, None)}
    if columns:
        out["columns"] = list(columns)
    return out


def to_document(state: State, catalog: str | None = None) -> dict:
    """A deterministic document for `state`. Every tag and role the catalog
    USES is listed, even one only ever referenced by a grant or assignment
    (the store does not require a definition row) — so the document stands
    on its own, and importing it creates any such missing definitions."""
    tags = set(state.tags)
    tags |= {(k[4], k[5]) for k in state.assignments}
    tags |= {(k[3], k[4]) for k in state.attachments if k[2] == "tag"}
    roles = set(state.roles) | {r for r, _ in state.members} | {k[4] for k in state.grants}

    doc: dict[str, Any] = {"version": SPEC_VERSION, "kind": SPEC_KIND}
    if catalog:
        doc["catalog"] = catalog

    doc["tags"] = []
    for ns, name in sorted(tags):
        e: dict = {"tag": _tag_out(ns, name)}
        allowed = state.tags.get((ns, name))
        if allowed is not None:
            e["allowed_values"] = list(allowed)
        doc["tags"].append(e)

    doc["roles"] = []
    for r in sorted(roles):
        e = {"role": r}
        members = sorted(p for (rr, p) in state.members if rr == r)
        if members:
            e["members"] = members
        doc["roles"].append(e)

    doc["grants"] = [
        {"role": r, "privilege": priv, "on": _ref_out(k, sch, obj, None)}
        for (k, sch, obj, priv, r) in sorted(state.grants, key=lambda g: (g[4], g[1], g[2], g[3], g[0]))
    ]

    doc["tag_assignments"] = []
    for key in sorted(state.assignments, key=lambda a: (a[4], a[5], a[1], a[2], a[3], a[0])):
        k, sch, obj, col, ns, name = key
        e = {"tag": _tag_out(ns, name), "on": _ref_out(k, sch, obj, col)}
        val = state.assignments[key]
        if val is not None:
            e["value"] = val
        doc["tag_assignments"].append(e)

    def _attaches(kind: str, name: str) -> list[dict]:
        keys = sorted((k for k in state.attachments if k[0] == kind and k[1] == name),
                      key=lambda k: tuple(x or "" for x in k))
        return [_attach_out(k, state.attachments[k]) for k in keys]

    doc["masking_policies"] = []
    for name in sorted(state.masking):
        sig, body, roles_, fl = state.masking[name]
        e = {"name": name, "signature": sig, "body": body}
        if roles_:
            e["unmasked_roles"] = list(roles_)
        if fl:
            e["file_layer"] = True
        att = _attaches("masking", name)
        if att:
            e["attach"] = att
        doc["masking_policies"].append(e)

    doc["row_access_policies"] = []
    for name in sorted(state.row_access):
        sig, body, roles_ = state.row_access[name]
        e = {"name": name, "signature": sig, "body": body}
        if roles_:
            e["unmasked_roles"] = list(roles_)
        att = _attaches("row_access", name)
        if att:
            e["attach"] = att
        doc["row_access_policies"].append(e)
    # Attachments of a policy that no longer exists do nothing and have no
    # policy to sit under; they are left out (a pruning import removes them).
    return doc


def dump_yaml(doc: dict) -> str:
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False,
                          allow_unicode=True, width=100)


# ---------------------------------------------------------------------------
# Parse: document -> State (strict: unknown keys and duplicates are errors,
# because a typo in a security spec must not silently mean "no policy")
# ---------------------------------------------------------------------------

class _NoAliasLoader(yaml.SafeLoader):
    """YAML without anchors/aliases: no alias expansion bombs, and a spec
    reads the same to a reviewer as to the parser."""

    def fetch_alias(self):
        raise SpecError("YAML aliases are not allowed in a governance spec")


def load_document(text: str | bytes) -> dict:
    if isinstance(text, bytes):
        if len(text) > MAX_SPEC_BYTES:
            raise SpecError(f"spec is larger than {MAX_SPEC_BYTES} bytes")
        text = text.decode("utf-8")
    elif len(text.encode("utf-8")) > MAX_SPEC_BYTES:
        raise SpecError(f"spec is larger than {MAX_SPEC_BYTES} bytes")
    try:
        doc = yaml.load(text, Loader=_NoAliasLoader)   # noqa: S506 - SafeLoader subclass
    except SpecError:
        raise
    except yaml.YAMLError as e:
        raise SpecError(f"spec does not parse: {e}") from None
    if not isinstance(doc, dict):
        raise SpecError("spec must be a mapping")
    return doc


def _keys(d: Any, path: str, allowed: set[str], required: set[str] = frozenset()) -> dict:
    if not isinstance(d, dict):
        raise SpecError(f"{path}: expected a mapping")
    extra = set(d) - allowed
    if extra:
        raise SpecError(f"{path}: unknown key(s) {sorted(extra)}; allowed: {sorted(allowed)}")
    missing = required - set(d)
    if missing:
        raise SpecError(f"{path}: missing {sorted(missing)}")
    return d


def _str(v: Any, path: str) -> str:
    if not isinstance(v, str) or not v.strip():
        raise SpecError(f"{path}: expected a non-empty string")
    return v


def _str_list(v: Any, path: str) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list):
        raise SpecError(f"{path}: expected a list of strings")
    return [_str(x, f"{path}[{i}]") for i, x in enumerate(v)]


def _list(doc: dict, key: str) -> list:
    v = doc.get(key)
    if v is None:
        return []
    if not isinstance(v, list):
        raise SpecError(f"{key}: expected a list")
    return v


def _tag_in(v: Any, path: str) -> tuple[str, str]:
    if isinstance(v, dict):
        d = _keys(v, path, {"namespace", "name"}, {"namespace", "name"})
        return _str(d["namespace"], f"{path}.namespace"), _str(d["name"], f"{path}.name")
    s = _str(v, path)
    if "." not in s:
        raise SpecError(f"{path}: a tag is 'namespace.name', got {s!r}")
    ns, name = s.split(".", 1)
    if not ns or not name:
        raise SpecError(f"{path}: a tag is 'namespace.name', got {s!r}")
    return ns, name


def _ref_in(v: Any, path: str) -> tuple[str, str, str, str]:
    """-> (object_kind, schema, object, column) with '' for unset."""
    d = _keys(v, path, {"schema", "table", "view", "column"}, {"schema"})
    schema = _str(d["schema"], f"{path}.schema")
    if "table" in d and "view" in d:
        raise SpecError(f"{path}: give either table or view, not both")
    obj = d.get("table", d.get("view"))
    obj = _str(obj, f"{path}.{'table' if 'table' in d else 'view'}") if obj is not None else ""
    col = _str(d["column"], f"{path}.column") if "column" in d else ""
    if col and not obj:
        raise SpecError(f"{path}: a column needs its table")
    kind = "column" if col else ("view" if "view" in d else ("table" if obj else "schema"))
    return kind, schema, obj, col


def _put(section: dict, key, value, path: str) -> None:
    if key in section:
        raise SpecError(f"{path}: duplicate entry")
    section[key] = value


def _check_body(body: str, kind: str, path: str) -> None:
    sql = (f"SELECT ({body}) AS masked" if kind == "masking"
           else f"SELECT 1 WHERE ({body})")
    try:
        check_single_select(sql, f"{path}.body")
    except ValueError as e:
        raise SpecError(str(e)) from None


def parse_document(doc: dict) -> State:
    _keys(doc, "spec", {"version", "kind", "catalog", "tags", "roles", "grants",
                        "tag_assignments", "masking_policies", "row_access_policies"},
          {"version"})
    if doc["version"] != SPEC_VERSION:
        raise SpecError(f"version: this server reads spec version {SPEC_VERSION}, "
                        f"got {doc['version']!r}")
    if doc.get("kind", SPEC_KIND) != SPEC_KIND:
        raise SpecError(f"kind: expected {SPEC_KIND!r}")
    s = State()

    for i, e in enumerate(_list(doc, "tags")):
        p = f"tags[{i}]"
        _keys(e, p, {"tag", "allowed_values"}, {"tag"})
        allowed = e.get("allowed_values")
        _put(s.tags, _tag_in(e["tag"], f"{p}.tag"),
             tuple(sorted(_str_list(allowed, f"{p}.allowed_values"))) if allowed is not None else None,
             p)

    for i, e in enumerate(_list(doc, "roles")):
        p = f"roles[{i}]"
        _keys(e, p, {"role", "members"}, {"role"})
        role = _str(e["role"], f"{p}.role")
        _put(s.roles, role, None, p)
        for j, m in enumerate(_str_list(e.get("members"), f"{p}.members")):
            _put(s.members, (role, m), None, f"{p}.members[{j}]")

    for i, e in enumerate(_list(doc, "grants")):
        p = f"grants[{i}]"
        _keys(e, p, {"role", "privilege", "on"}, {"role", "privilege", "on"})
        kind, sch, obj, col = _ref_in(e["on"], f"{p}.on")
        if col:
            raise SpecError(f"{p}.on: grants are on a schema, table or view, not a column")
        assert kind in OBJECT_KINDS
        _put(s.grants, (kind, sch, obj, _str(e["privilege"], f"{p}.privilege"),
                        _str(e["role"], f"{p}.role")), None, p)

    for i, e in enumerate(_list(doc, "tag_assignments")):
        p = f"tag_assignments[{i}]"
        _keys(e, p, {"tag", "on", "value"}, {"tag", "on"})
        ns, name = _tag_in(e["tag"], f"{p}.tag")
        kind, sch, obj, col = _ref_in(e["on"], f"{p}.on")
        val = e.get("value")
        if val is not None and not isinstance(val, str):
            val = str(val)
        _put(s.assignments, (kind, sch, obj, col, ns, name), val, p)

    for kind, key in (("masking", "masking_policies"), ("row_access", "row_access_policies")):
        allowed = {"name", "signature", "body", "unmasked_roles", "attach"}
        if kind == "masking":
            allowed.add("file_layer")
        for i, e in enumerate(_list(doc, key)):
            p = f"{key}[{i}]"
            _keys(e, p, allowed, {"name", "signature", "body"})
            name = _str(e["name"], f"{p}.name")
            sig = _str(e["signature"], f"{p}.signature")
            body = _str(e["body"], f"{p}.body")
            _check_body(body, kind, p)
            roles_ = _roles_tuple(_str_list(e.get("unmasked_roles"), f"{p}.unmasked_roles"))
            if kind == "masking":
                fl = e.get("file_layer", False)
                if not isinstance(fl, bool):
                    raise SpecError(f"{p}.file_layer: expected true or false")
                _put(s.masking, name, (sig, body, roles_, fl), p)
            else:
                _put(s.row_access, name, (sig, body, roles_), p)
            att = e.get("attach") or []
            if not isinstance(att, list):
                raise SpecError(f"{p}.attach: expected a list")
            for j, a in enumerate(att):
                ap = f"{p}.attach[{j}]"
                _put(s.attachments, *_attach_in(kind, name, a, ap), ap)
    return s


def _attach_in(kind: str, policy: str, a: Any, path: str):
    allowed = {"tag", "on"} | ({"columns"} if kind == "row_access" else set())
    d = _keys(a, path, allowed)
    if ("tag" in d) == ("on" in d):
        raise SpecError(f"{path}: give exactly one of tag or on")
    cols = _str_list(d.get("columns"), f"{path}.columns") or None
    if "tag" in d:
        ns, name = _tag_in(d["tag"], f"{path}.tag")
        return (kind, policy, "tag", ns, name, None, None, None), (tuple(cols) if cols else None)
    okind, sch, obj, col = _ref_in(d["on"], f"{path}.on")
    if kind == "masking":
        if okind != "column":
            raise SpecError(f"{path}.on: a masking policy attaches to a column (or a tag)")
        return ("masking", policy, "column", None, None, sch, obj, col), None
    if okind != "table":
        raise SpecError(f"{path}.on: a row-access policy attaches to a table (or a tag)")
    return ("row_access", policy, "table", None, None, sch, obj, None), (tuple(cols) if cols else None)


# ---------------------------------------------------------------------------
# Diff + validation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Change:
    op: str          # create | update | delete
    section: str     # one of SECTIONS
    key: Any
    before: Any = None
    after: Any = None

    def describe(self) -> dict:
        return {"op": self.op, "kind": _KIND_LABEL[self.section],
                "target": _target(self.section, self.key),
                **({"before": _jsonable(self.before)} if self.op != "create" else {}),
                **({"after": _jsonable(self.after)} if self.op != "delete" else {})}


_KIND_LABEL = {
    "tags": "tag", "roles": "role", "members": "role_member", "grants": "grant",
    "assignments": "tag_assignment", "masking": "masking_policy",
    "row_access": "row_access_policy", "attachments": "policy_attachment",
}


def _jsonable(v):
    if isinstance(v, tuple):
        return [_jsonable(x) for x in v]
    return v


def _dotted(*parts) -> str:
    return ".".join(p for p in parts if p)


def _target(section: str, k) -> str:
    if section == "tags":
        return _dotted(*k)
    if section == "roles":
        return k
    if section == "members":
        return f"{k[0]} <- {k[1]}"
    if section == "grants":
        return f"{k[3]} on {k[0]} {_dotted(k[1], k[2])} to {k[4]}"
    if section == "assignments":
        return f"{_dotted(k[4], k[5])} on {k[0]} {_dotted(k[1], k[2], k[3])}"
    if section in ("masking", "row_access"):
        return k
    pk, pn, tk, tns, tnm, sch, obj, col = k
    where = _dotted(tns, tnm) if tk == "tag" else _dotted(sch, obj, col)
    return f"{pk} {pn} -> {tk} {where}"


# Removals run first (dependents before what they depend on), then creates
# and updates (definitions before what references them).
REMOVE_ORDER = ("attachments", "assignments", "grants", "members",
                "row_access", "masking", "tags", "roles")
ADD_ORDER = ("roles", "tags", "members", "grants", "masking", "row_access",
             "assignments", "attachments")


def diff(current: State, desired: State, *, prune: bool) -> list[Change]:
    out: list[Change] = []
    if prune:
        for sec in REMOVE_ORDER:
            cur, want = getattr(current, sec), getattr(desired, sec)
            for k in sorted(set(cur) - set(want), key=_sort_key):
                out.append(Change("delete", sec, k, before=cur[k]))
    for sec in ADD_ORDER:
        cur, want = getattr(current, sec), getattr(desired, sec)
        for k in sorted(want, key=_sort_key):
            if k not in cur:
                out.append(Change("create", sec, k, after=want[k]))
            elif cur[k] != want[k]:
                out.append(Change("update", sec, k, before=cur[k], after=want[k]))
    return out


def _sort_key(k):
    if isinstance(k, tuple):
        return tuple("" if x is None else str(x) for x in k)
    return (str(k),)


def final_state(current: State, desired: State, *, prune: bool) -> State:
    if prune:
        return desired
    merged = State()
    for sec in SECTIONS:
        getattr(merged, sec).update(getattr(current, sec))
        getattr(merged, sec).update(getattr(desired, sec))
    return merged


def validate(final: State, desired: State) -> list[str]:
    """Reference checks on the state the import would leave behind. A
    dangling reference that would make protection silently not apply is an
    error; anything merely suspicious is a warning."""
    errors: list[str] = []
    warnings: list[str] = []
    for k in final.attachments:
        pk, pn = k[0], k[1]
        if pn not in (final.masking if pk == "masking" else final.row_access):
            if k in desired.attachments:
                errors.append(f"{_target('attachments', k)}: no {pk} policy named {pn!r}")
        if k[2] == "tag" and (k[3], k[4]) not in final.tags and k in desired.attachments:
            errors.append(f"{_target('attachments', k)}: tag {_dotted(k[3], k[4])} "
                          f"is not defined in tags")
    for k in desired.assignments:
        if (k[4], k[5]) not in final.tags:
            errors.append(f"tag_assignment {_target('assignments', k)}: tag "
                          f"{_dotted(k[4], k[5])} is not defined in tags")
        allowed = final.tags.get((k[4], k[5]))
        val = desired.assignments[k]
        if allowed is not None and val is not None and val not in allowed:
            warnings.append(f"tag_assignment {_target('assignments', k)}: value {val!r} "
                            f"is not one of the tag's allowed_values")
    for (r, p) in desired.members:
        if r not in final.roles:
            errors.append(f"member {p}: role {r!r} is not defined in roles")
    for k in desired.grants:
        if k[4] not in final.roles:
            errors.append(f"grant {_target('grants', k)}: role {k[4]!r} is not defined in roles")
    held = {r for r, _ in final.members}
    for sec in ("masking", "row_access"):
        for name, v in getattr(desired, sec).items():
            for r in v[2]:
                if r not in final.roles:
                    warnings.append(f"{_KIND_LABEL[sec]} {name}: unmasked role {r!r} is not "
                                    f"a defined role")
                elif r not in held:
                    warnings.append(f"{_KIND_LABEL[sec]} {name}: nobody holds unmasked role {r!r}")
    if errors:
        raise SpecError("; ".join(errors))
    return warnings


def object_warnings(store: GovernanceStore, desired: State) -> list[str]:
    """References to schemas, tables or columns the catalog does not have
    (yet). Not errors: governance may be authored before the data lands."""
    out: list[str] = []
    tables: dict[str, set[str]] = {}
    columns: dict[tuple[str, str], set[str] | None] = {}

    def _tables(sch: str) -> set[str]:
        if sch not in tables:
            try:
                tables[sch] = {t for (_s, t) in store.catalog.list_tables([sch])}
            except Exception:
                tables[sch] = set()
        return tables[sch]

    def _cols(sch: str, tbl: str) -> set[str] | None:
        if (sch, tbl) not in columns:
            try:
                columns[(sch, tbl)] = {c.name for c in store.catalog.get_columns([sch], tbl)}
            except Exception:
                columns[(sch, tbl)] = None
        return columns[(sch, tbl)]

    refs: set[tuple[str, str, str]] = set()
    for k in desired.assignments:
        refs.add((k[1], k[2], k[3]))
    for k in desired.grants:
        if k[0] in ("table",):
            refs.add((k[1], k[2], ""))
    for k in desired.attachments:
        if k[2] in ("column", "table"):
            refs.add((k[5], k[6], k[7] or ""))
    for sch, obj, col in sorted(refs):
        if not obj:
            continue
        if obj not in _tables(sch):
            out.append(f"{_dotted(sch, obj)}: no such table (yet)")
            continue
        if col:
            cols = _cols(sch, obj)
            if cols is not None and col not in cols:
                out.append(f"{_dotted(sch, obj, col)}: no such column (yet)")
    return out


# ---------------------------------------------------------------------------
# Plan / apply
# ---------------------------------------------------------------------------

def _execute(store: GovernanceStore, principal: str, ch: Change) -> list[tuple[str, str]]:
    """One change through the regular store method. Returns tables whose
    policy set shrank (to resync their masking artifacts after commit)."""
    k, sec = ch.key, ch.section
    if ch.op == "delete":
        if sec == "attachments":
            return store.detach_policy(
                principal, policy_kind=k[0], policy_name=k[1], target_kind=k[2],
                tag_ns=k[3], tag_name=k[4], schema_name=k[5], object_name=k[6],
                column_name=k[7])
        if sec == "assignments":
            return store.remove_object_tag(
                principal, object_kind=k[0], schema_name=k[1], object_name=k[2],
                column_name=k[3], tag_ns=k[4], tag_name=k[5])
        if sec == "grants":
            store.revoke_object_grant(principal, object_kind=k[0], schema_name=k[1],
                                      object_name=k[2], privilege=k[3], role_name=k[4])
        elif sec == "members":
            store.revoke_role(principal, k[0], k[1])
        elif sec == "masking":
            store.delete_masking_policy(principal, k)
        elif sec == "row_access":
            store.delete_row_access_policy(principal, k)
        elif sec == "tags":
            store.delete_tag(principal, k[0], k[1])
        elif sec == "roles":
            store.delete_role(principal, k)
        return []
    v = ch.after
    if sec == "roles":
        store.create_role(principal, k)
    elif sec == "tags":
        store.create_tag(principal, k[0], k[1], list(v) if v is not None else None)
    elif sec == "members":
        store.grant_role(principal, k[0], k[1])
    elif sec == "grants":
        store.grant_object(principal, object_kind=k[0], schema_name=k[1], object_name=k[2],
                           privilege=k[3], role_name=k[4])
    elif sec == "masking":
        store.create_masking_policy(principal, k, v[0], v[1], list(v[2]) or None,
                                    file_layer_masking=v[3])
    elif sec == "row_access":
        store.create_row_access_policy(principal, k, v[0], v[1], list(v[2]) or None)
    elif sec == "assignments":
        store.assign_object_tag(principal, object_kind=k[0], schema_name=k[1],
                                object_name=k[2], column_name=k[3], tag_ns=k[4],
                                tag_name=k[5], tag_value=v)
    elif sec == "attachments":
        store.attach_policy(principal, policy_kind=k[0], policy_name=k[1], target_kind=k[2],
                            tag_ns=k[3], tag_name=k[4], schema_name=k[5], object_name=k[6],
                            column_name=k[7], columns=list(v) if v else None)
        if ch.op == "update" and k[2] == "table":
            # row-access column list changed: the old filter's artifacts are stale
            return [(k[5], k[6])]
    return []


def spec_digest(doc: dict) -> str:
    """Content hash of the normalized desired state — the same spec gives
    the same digest however it is formatted, so an audit row can be matched
    to the git revision it came from."""
    st = parse_document(doc)
    norm = {sec: sorted(([_jsonable(k), _jsonable(v)] for k, v in getattr(st, sec).items()),
                        key=lambda kv: json.dumps(kv, default=str))
            for sec in SECTIONS}
    return hashlib.sha256(json.dumps(norm, sort_keys=True, default=str).encode()).hexdigest()


def run(store: GovernanceStore, doc: dict, *, principal: str, apply: bool,
        prune: bool = False, if_version: str | None = None,
        source: str | None = None) -> dict:
    """Plan (apply=False) or apply a governance spec, all in one Postgres
    transaction. A plan executes every change exactly like apply and then
    rolls back, so it reports invariant conflicts (409) apply would hit."""
    desired = parse_document(doc)
    digest = spec_digest(doc)
    result: dict = {}
    sc = store._sc
    _ensure_committed(store)
    try:
        with store.catalog.commit_transaction():
            with store.catalog.pg_cursor() as cur:
                ensure_governance_sidecars(cur, store.catalog.sidecar_schema)
                # Lock the version row: concurrent authoring waits for us (its
                # trigger updates this row), and the check below is exact.
                cur.execute(f"SELECT v FROM {sc}.duckicelake_governance_version "
                            "WHERE id = 1 FOR UPDATE")
                row = cur.fetchone()
                version = str(row[0]) if row else ""
            if if_version is not None and if_version != version:
                raise VersionConflict(if_version, version)
            current = read_state(store)
            changes = diff(current, desired, prune=prune)
            warnings = validate(final_state(current, desired, prune=prune), desired)
            warnings += object_warnings(store, desired)
            resync: set[tuple[str, str]] = set()
            for ch in changes:
                try:
                    resync.update(_execute(store, principal, ch))
                except GovernanceConflict as e:
                    d = ch.describe()
                    raise GovernanceConflict(
                        f"{d['op']} {d['kind']} {d['target']}: {e}") from None
            counts = {op: sum(1 for c in changes if c.op == op)
                      for op in ("create", "update", "delete")}
            with store.catalog.pg_cursor() as cur:
                store.audit(cur, principal=principal, operation="import_governance_spec",
                            object_=None, decision="ok" if apply else "plan",
                            detail={"digest": digest, "prune": prune, "source": source,
                                    "base_version": version, **counts})
            result = {
                "mode": "apply" if apply else "plan",
                "prune": prune,
                "base_version": version,
                "digest": digest,
                "summary": counts,
                "changes": [c.describe() for c in changes],
                "warnings": warnings,
                "resync": sorted(resync),
            }
            if not apply:
                raise _DryRun
    except _DryRun:
        pass
    return result


def _ensure_committed(store: GovernanceStore) -> None:
    """Create the sidecars in a transaction of their own. Inside a plan's
    transaction the DDL would roll back with it while the per-process
    'ensured' cache kept believing the tables exist."""
    with store.catalog.pg_cursor() as cur:
        ensure_governance_sidecars(cur, store.catalog.sidecar_schema)


def export(store: GovernanceStore, catalog: str | None = None) -> tuple[dict, str]:
    """(document, governance version it reflects), read in one snapshot."""
    _ensure_committed(store)
    with store.catalog.commit_transaction():
        with store.catalog.pg_cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            ensure_governance_sidecars(cur, store.catalog.sidecar_schema)
            cur.execute(f"SELECT v FROM {store._sc}.duckicelake_governance_version WHERE id = 1")
            row = cur.fetchone()
        state = read_state(store)
    return to_document(state, catalog), (str(row[0]) if row else "")


# ---------------------------------------------------------------------------
# CLI — a thin HTTP client for git / CI use:
#   python -m duckicelake.governance_spec export acme__main > governance.yaml
#   python -m duckicelake.governance_spec plan   acme__main governance.yaml [--prune]
#   python -m duckicelake.governance_spec apply  acme__main governance.yaml [--prune] [--source REV]
# DUCKICELAKE_URL (default http://localhost:8181) and DUCKICELAKE_TOKEN (an
# admin token) say where and as whom. `apply` plans first and pins the apply
# to that plan's governance version, so it never applies a plan it did not show.
# ---------------------------------------------------------------------------

def _print_plan(res: dict, out) -> None:
    s = res["summary"]
    print(f"{res['mode']}: {s['create']} to create, {s['update']} to update, "
          f"{s['delete']} to delete (governance version {res['base_version']}"
          f"{', prune' if res['prune'] else ''})", file=out)
    sign = {"create": "+", "update": "~", "delete": "-"}
    for c in res["changes"]:
        print(f"  {sign[c['op']]} {c['kind']}: {c['target']}", file=out)
    for w in res["warnings"]:
        print(f"  warning: {w}", file=out)


def main(argv: list[str] | None = None) -> int:
    import argparse
    import os
    import sys

    import httpx

    ap = argparse.ArgumentParser(prog="python -m duckicelake.governance_spec",
                                 description="Export, plan or apply a catalog's governance spec.")
    ap.add_argument("command", choices=("export", "plan", "apply"))
    ap.add_argument("catalog", help="catalog prefix, e.g. acme__main")
    ap.add_argument("file", nargs="?", help="spec file (plan/apply); '-' for stdin")
    ap.add_argument("--prune", action="store_true",
                    help="the spec is authoritative: remove what it lacks")
    ap.add_argument("--source", help="recorded in the audit row, e.g. a git revision")
    ap.add_argument("--format", choices=("yaml", "json"), default="yaml")
    a = ap.parse_args(argv)

    base = os.environ.get("DUCKICELAKE_URL", "http://localhost:8181").rstrip("/")
    headers = {}
    if os.environ.get("DUCKICELAKE_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['DUCKICELAKE_TOKEN']}"
    url = f"{base}/v1/{a.catalog}/governance/spec"
    with httpx.Client(headers=headers, timeout=120.0) as cl:
        if a.command == "export":
            r = cl.get(url, params={"format": a.format})
            if r.status_code != 200:
                print(f"error {r.status_code}: {r.text}", file=sys.stderr)
                return 1
            sys.stdout.write(r.text if a.format == "yaml" else json.dumps(r.json(), indent=2) + "\n")
            return 0
        if not a.file:
            ap.error(f"{a.command} needs a spec file")
        body = sys.stdin.buffer.read() if a.file == "-" else open(a.file, "rb").read()
        params = {"prune": str(a.prune).lower()}
        if a.source:
            params["source"] = a.source
        r = cl.post(url, params={**params, "mode": "plan"}, content=body,
                    headers={"content-type": "application/yaml"})
        if r.status_code != 200:
            print(f"error {r.status_code}: {r.text}", file=sys.stderr)
            return 1
        plan = r.json()
        _print_plan(plan, sys.stdout)
        if a.command == "plan" or not plan["changes"]:
            return 0
        r = cl.post(url, params={**params, "mode": "apply",
                                 "if_version": plan["base_version"]},
                    content=body, headers={"content-type": "application/yaml"})
        if r.status_code != 200:
            print(f"error {r.status_code}: {r.text}", file=sys.stderr)
            return 1
        print(f"applied ({len(r.json()['changes'])} changes)")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
