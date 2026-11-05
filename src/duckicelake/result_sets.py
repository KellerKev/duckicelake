"""Query result-set cache.

The proxy runs a caller's SELECT itself — in a DuckDB session built from the
exact credential bundle the caller would be vended (RLS reader, masking route,
scoped S3 credential, locked down; see governed.py) — writes the result as
Parquet under `{results_root}{catalog}/{id}/`, and hands back the file paths
plus a short-lived gateway credential that can read that one result set and
nothing else. Masked or filtered data is therefore materialized once per
query and principal, instead of copying whole tables.

Reuse: a result is keyed on everything that could change it — the catalog,
who is asking and in which session context, the query text and default
namespace, the catalog's governance version, and a fingerprint of every table
the query reads (falling back to the catalog's latest snapshot when the query
reads something we can't fingerprint, e.g. a view). Queries calling volatile
functions (now(), random(), ...) are materialized but never reused.

"Who is asking" is the principal's *governance class* when the result can be
shared (`result_share`): what a governed session returns depends only on the
roles granted to the principal in this catalog (masks, row filters and
Postgres RLS table visibility all key on them), the roles carried on the
token, the session context and the token scope — so principals equal in all
of those get the same bytes and share one result. It falls back to the
principal itself when anything could make two such sessions differ: a policy
body or the query calling a session function (current_user, ...), or a
table function. Every principal served a shared result is recorded as a
reader of it; the gateway serves it to its builder and its readers only.

Retention (Postgres, swept in the background): a result unused for
`result_idle_hours` is purged; each reuse extends it that long again; every
result is purged `result_max_days` after it was built. A bucket lifecycle
rule on the results root backs this up (see `lifecycle_rules`).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import duckdb
import psycopg

from .catalog import pg_advisory_lock
from .config import work_dir
from .governed import setup_governed
from .sqlsafe import check_no_denied_functions, check_single_select, ql, qi

log = logging.getLogger("duckicelake.result_sets")

#: Bumped when the materialized layout changes, so old results never match.
FORMAT_VERSION = 1

#: Functions whose value differs between runs of the same query on the same
#: data: such results are materialized for the caller but never reused.
VOLATILE_FUNCTIONS = frozenset({
    "now", "current_timestamp", "get_current_timestamp", "transaction_timestamp",
    "current_date", "today", "current_time", "get_current_time", "localtime",
    "localtimestamp", "current_localtime", "current_localtimestamp",
    "random", "uuid", "gen_random_uuid", "uuidv4", "uuidv7", "setseed",
    "nextval", "currval", "current_query", "txid_current",
})

#: Functions whose value depends on the executing session: a query calling
#: one is never shared between principals.
SESSION_FUNCTIONS = frozenset({
    "current_user", "session_user", "user", "current_role", "current_setting",
    "getvariable", "current_schema", "current_schemas", "current_database",
    "current_catalog", "pg_backend_pid",
})

_SIDECAR_DONE: set[str] = set()
_SLOTS_LOCK = threading.Lock()
_SLOTS: dict[int, threading.BoundedSemaphore] = {}


class Rejected(Exception):
    """A request the cache refuses; carries the HTTP status for the edge."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


# ---- storage --------------------------------------------------------------

def ensure_result_sidecar(cur, schema: str) -> None:
    if schema in _SIDECAR_DONE:
        return
    sc = qi(schema)
    with pg_advisory_lock(cur, f"duckicelake:result_sets:{schema}"):
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {sc}.duckicelake_result_set (
                id               TEXT PRIMARY KEY,
                cache_key        TEXT NOT NULL,
                reusable         BOOLEAN NOT NULL,
                principal        TEXT NOT NULL,
                namespace        TEXT NOT NULL,
                sql              TEXT NOT NULL,
                governance_stamp TEXT NOT NULL,
                prefix           TEXT NOT NULL,
                files            JSONB NOT NULL,
                columns          JSONB NOT NULL,
                row_count        BIGINT NOT NULL,
                bytes            BIGINT NOT NULL,
                use_count        BIGINT NOT NULL DEFAULT 1,
                created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
                last_used_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
                expires_at       TIMESTAMPTZ NOT NULL,
                hard_expires_at  TIMESTAMPTZ NOT NULL
            )
        """)
        cur.execute(f"CREATE INDEX IF NOT EXISTS duckicelake_result_set_key "
                    f"ON {sc}.duckicelake_result_set (cache_key)")
        cur.execute(f"CREATE INDEX IF NOT EXISTS duckicelake_result_set_exp "
                    f"ON {sc}.duckicelake_result_set (expires_at)")
        cur.execute(f"ALTER TABLE {sc}.duckicelake_result_set "
                    "ADD COLUMN IF NOT EXISTS shared BOOLEAN NOT NULL DEFAULT false")
        # Principals other than the builder a shared result was served to.
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {sc}.duckicelake_result_set_reader (
                rs_id         TEXT NOT NULL REFERENCES {sc}.duckicelake_result_set (id)
                                  ON DELETE CASCADE,
                principal     TEXT NOT NULL,
                first_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                PRIMARY KEY (rs_id, principal)
            )
        """)
    _SIDECAR_DONE.add(schema)


_COLS = ("id, reusable, principal, namespace, governance_stamp, prefix, files, columns, "
         "row_count, bytes, use_count, created_at, expires_at, hard_expires_at, shared")

#: SQL: `principal` may read result `id` (its builder, or a recorded reader).
_MAY_READ = ("(principal = %s OR EXISTS (SELECT 1 FROM {sc}.duckicelake_result_set_reader r "
             "WHERE r.rs_id = id AND r.principal = %s))")


@dataclass
class ResultSet:
    id: str
    reusable: bool
    principal: str
    namespace: str
    governance_stamp: str
    prefix: str
    files: list[dict]
    columns: list[dict]
    row_count: int
    bytes: int
    use_count: int
    created_at: datetime
    expires_at: datetime
    hard_expires_at: datetime
    shared: bool = False

    @classmethod
    def from_row(cls, r) -> "ResultSet":
        return cls(*r)


# ---- query analysis -------------------------------------------------------

@dataclass
class QueryShape:
    tables: list[tuple[str, str, str]] = field(default_factory=list)  # (catalog, schema, name)
    ctes: set[str] = field(default_factory=set)
    functions: set[str] = field(default_factory=set)
    table_functions: bool = False
    parsed: bool = True

    @property
    def volatile(self) -> bool:
        return bool(self.functions & VOLATILE_FUNCTIONS)

    @property
    def session_dependent(self) -> bool:
        return bool(self.functions & SESSION_FUNCTIONS)


_PARSER = threading.local()


def analyse(sql: str) -> QueryShape:
    """Tables, CTE names and functions a query references (parse only)."""
    con = getattr(_PARSER, "con", None)
    if con is None:
        con = _PARSER.con = duckdb.connect()
    raw = con.execute("SELECT json_serialize_sql(?)", [sql]).fetchone()[0]
    tree = json.loads(raw)
    shape = QueryShape()
    if tree.get("error"):
        shape.parsed = False
        return shape

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            t = node.get("type")
            if t == "BASE_TABLE" and node.get("table_name"):
                shape.tables.append((node.get("catalog_name") or "",
                                     node.get("schema_name") or "",
                                     node["table_name"]))
            elif t == "TABLE_FUNCTION":
                shape.table_functions = True
            if node.get("class") == "FUNCTION" and node.get("function_name"):
                shape.functions.add(str(node["function_name"]).lower())
            elif node.get("class") == "COLUMN_REF":
                # `current_date`, `current_timestamp`, ... parse as bare
                # column refs and bind to the function later.
                names = node.get("column_names") or []
                if len(names) == 1 and str(names[0]).lower() in (
                        VOLATILE_FUNCTIONS | SESSION_FUNCTIONS):
                    shape.functions.add(str(names[0]).lower())
            cte = node.get("cte_map")
            if isinstance(cte, dict):
                for entry in cte.get("map") or []:
                    if isinstance(entry, dict) and entry.get("key"):
                        shape.ctes.add(str(entry["key"]))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(tree.get("statements"))
    return shape


def _table_fingerprint(cur, m: str, schema: str, name: str) -> list | None:
    """A DuckLake table's data + schema version: its id, the live data and
    delete files (ids only ever grow, so a fingerprint can't recur after
    maintenance) and its columns. None when it isn't a plain table with all
    rows in files (a view, unknown, or inlined rows)."""
    row = cur.execute(
        f"""SELECT t.table_id FROM {m}.ducklake_table t
            JOIN {m}.ducklake_schema s ON s.schema_id = t.schema_id
            WHERE s.schema_name = %s AND t.table_name = %s
              AND t.end_snapshot IS NULL AND s.end_snapshot IS NULL""",
        (schema, name)).fetchone()
    if row is None:
        return None
    tid = row[0]
    inlined = cur.execute(
        f"SELECT 1 FROM {m}.ducklake_inlined_data_tables WHERE table_id = %s LIMIT 1",
        (tid,)).fetchone()
    if inlined is not None:
        return None
    files = cur.execute(
        f"""SELECT count(*), COALESCE(max(data_file_id), -1), COALESCE(sum(record_count), 0)
            FROM {m}.ducklake_data_file WHERE table_id = %s AND end_snapshot IS NULL""",
        (tid,)).fetchone()
    deletes = cur.execute(
        f"""SELECT count(*), COALESCE(max(delete_file_id), -1)
            FROM {m}.ducklake_delete_file WHERE table_id = %s AND end_snapshot IS NULL""",
        (tid,)).fetchone()
    cols = cur.execute(
        f"""SELECT md5(COALESCE(string_agg(column_id || ':' || column_name || ':' || column_type,
                                           ',' ORDER BY column_id), ''))
            FROM {m}.ducklake_column WHERE table_id = %s AND end_snapshot IS NULL""",
        (tid,)).fetchone()
    return [schema, name, tid, *map(int, files), *map(int, deletes), cols[0]]


def data_version(catalog, catalog_id: str, namespace: str, shape: QueryShape) -> dict:
    """What the result's data depends on: per-table fingerprints when every
    reference is a plain table of this catalog, else the catalog's latest
    snapshot id (any commit invalidates — always correct, less reuse)."""
    m = catalog.sidecar_sql      # the catalog's DuckLake metadata schema
    with catalog.pg_cursor() as cur:
        fps: list | None = []
        if shape.table_functions or not shape.parsed or not shape.tables:
            fps = None
        else:
            for cat, schema, name in shape.tables:
                if not schema and not cat and name in shape.ctes:
                    continue
                if cat and cat != catalog_id:
                    fps = None
                    break
                fp = _table_fingerprint(cur, m, schema or namespace, name)
                if fp is None:
                    fps = None
                    break
                fps.append(fp)
        if fps is not None:
            return {"tables": sorted(fps, key=lambda f: (f[0], f[1]))}
        snap = cur.execute(f"SELECT max(snapshot_id) FROM {m}.ducklake_snapshot").fetchone()[0]
        return {"snapshot": snap}


def session_dependent_policies(catalog) -> bool:
    """Does any policy of this catalog read the executing session? Then two
    principals with the same roles can still see different rows or values."""
    from .policies import SESSION_TOKENS
    sc = catalog.sidecar_sql
    with catalog.pg_cursor() as cur:
        bodies = [r[0] for r in cur.execute(
            f"SELECT body_sql FROM {sc}.duckicelake_masking_policy UNION ALL "
            f"SELECT body_sql FROM {sc}.duckicelake_row_access_policy").fetchall()]
    return any(SESSION_TOKENS.search(b or "") for b in bodies)


def cache_key(material: dict) -> str:
    raw = json.dumps({"v": FORMAT_VERSION, **material}, sort_keys=True,
                     separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def normalize_sql(sql: str) -> str:
    return sql.strip().rstrip(";").strip()


# ---- the cache ------------------------------------------------------------

@dataclass(frozen=True)
class Caller:
    sub: str
    actor: str
    channel: str
    token_roles: tuple
    scope: str


def _slots(n: int) -> threading.BoundedSemaphore:
    with _SLOTS_LOCK:
        if n not in _SLOTS:
            _SLOTS[n] = threading.BoundedSemaphore(max(1, n))
        return _SLOTS[n]


class ResultSetCache:
    def __init__(self, ctx, settings) -> None:
        self.ctx = ctx
        self.settings = settings
        self.catalog = ctx.catalog
        self.schema = ctx.catalog.sidecar_schema
        self.sc = ctx.catalog.sidecar_sql

    # -- rows ---------------------------------------------------------------
    def _cursor(self):
        return self.catalog.pg_cursor()

    def _ensure(self, cur) -> None:
        ensure_result_sidecar(cur, self.schema)

    def lookup(self, key: str) -> ResultSet | None:
        with self._cursor() as cur:
            self._ensure(cur)
            r = cur.execute(
                f"""SELECT {_COLS} FROM {self.sc}.duckicelake_result_set
                    WHERE cache_key = %s AND reusable
                      AND expires_at > now() AND hard_expires_at > now()
                    ORDER BY created_at DESC LIMIT 1""", (key,)).fetchone()
        return ResultSet.from_row(r) if r else None

    def get(self, rs_id: str, principal: str) -> ResultSet | None:
        with self._cursor() as cur:
            self._ensure(cur)
            r = cur.execute(
                f"""SELECT {_COLS} FROM {self.sc}.duckicelake_result_set
                    WHERE id = %s AND {_MAY_READ.format(sc=self.sc)}
                      AND expires_at > now() AND hard_expires_at > now()""",
                (rs_id, principal, principal)).fetchone()
        return ResultSet.from_row(r) if r else None

    def add_reader(self, rs: ResultSet, principal: str) -> bool:
        """Record `principal` as a reader of a shared result; True when this
        is their first use of it."""
        if principal == rs.principal:
            return False
        with self._cursor() as cur:
            r = cur.execute(
                f"""INSERT INTO {self.sc}.duckicelake_result_set_reader (rs_id, principal)
                    VALUES (%s, %s) ON CONFLICT DO NOTHING RETURNING 1""",
                (rs.id, principal)).fetchone()
        return r is not None

    def _serve_hit(self, hit: ResultSet, caller: "Caller", namespace: str) -> dict:
        if hit.principal != caller.sub and self.add_reader(hit, caller.sub):
            try:
                self.ctx.store.audit_load(
                    principal=caller.sub, object_=f"{namespace}.<query>", masked_cols=[],
                    applied_policies=[], row_filtered=False, operation="result_set",
                    decision="shared",
                    detail={"id": hit.id, "built_by": hit.principal, "rows": hit.row_count})
            except Exception:
                pass
        return self._response(self.touch(hit), caller, "hit")

    def touch(self, rs: ResultSet) -> ResultSet:
        """A reuse: extend the idle window (never past the hard limit)."""
        idle = timedelta(hours=self.settings.result_idle_hours)
        with self._cursor() as cur:
            r = cur.execute(
                f"""UPDATE {self.sc}.duckicelake_result_set
                    SET last_used_at = now(), use_count = use_count + 1,
                        expires_at = LEAST(now() + %s, hard_expires_at)
                    WHERE id = %s RETURNING expires_at, use_count""",
                (idle, rs.id)).fetchone()
        if r:
            rs.expires_at, rs.use_count = r
        return rs

    # -- entry points ---------------------------------------------------------
    def request(self, caller: Caller, namespace: str, sql: str, *,
                vend: Callable[[], dict], lookup_only: bool = False) -> dict:
        """Serve `sql` for `caller` from the cache, materializing on a miss
        (unless `lookup_only`)."""
        sql = normalize_sql(sql or "")
        try:
            check_single_select(sql, "query")
            check_no_denied_functions(sql, "query")
        except ValueError as e:
            raise Rejected(400, f"{e} (a single read-only SELECT)")
        shape = analyse(sql)
        # Read governance BEFORE deriving anything from it (see governance_stamp).
        stamp = self.ctx.store.governance_stamp()
        granted = sorted(self.ctx.store.roles_for_principal(caller.sub))
        shared = self.shareable(shape, caller, namespace, granted)
        material = {
            "cat": self.ctx.catalog_id, "actor": caller.actor,
            "channel": caller.channel, "roles": list(caller.token_roles),
            "ns": namespace, "sql": sql, "gov": stamp,
            "data": data_version(self.catalog, self.ctx.catalog_id, namespace, shape),
        }
        if shared:
            # The governance class: everything a governed session's output
            # depends on besides the query and the data (module docstring).
            material["class"] = {"granted": granted, "scope": caller.scope or ""}
        else:
            material["sub"] = caller.sub
        key = cache_key(material)
        reusable = shape.parsed and not shape.volatile

        if reusable:
            hit = self.lookup(key)
            if hit is not None:
                return self._serve_hit(hit, caller, namespace)
        if lookup_only:
            return {"status": "miss", "reusable": reusable}

        slots = _slots(self.settings.result_concurrency)
        if not slots.acquire(timeout=30):
            raise Rejected(429, "too many result sets are being built; retry shortly")
        try:
            with self._cursor() as lock_cur:
                # Single-flight per key across workers: the second identical
                # request waits for the first and then reuses its result.
                lock = int.from_bytes(bytes.fromhex(key[:16]), "big", signed=True)
                lock_cur.execute(
                    f"SET lock_timeout = '{int(self.settings.result_timeout_seconds * 1000)}ms'")
                try:
                    lock_cur.execute("SELECT pg_advisory_lock(%s)", (lock,))
                except psycopg.errors.LockNotAvailable:
                    raise Rejected(503, "an identical result set is still being built")
                finally:
                    lock_cur.execute("RESET lock_timeout")
                try:
                    if reusable:
                        hit = self.lookup(key)
                        if hit is not None:
                            return self._serve_hit(hit, caller, namespace)
                    rs = self._materialize(caller, namespace, sql, key, reusable, stamp, vend,
                                           shared=shared and reusable)
                finally:
                    lock_cur.execute("SELECT pg_advisory_unlock(%s)", (lock,))
        finally:
            slots.release()
        return self._response(rs, caller, "materialized")

    def shareable(self, shape: QueryShape, caller: Caller, namespace: str,
                  granted: list[str]) -> bool:
        """May this query's result be shared within a governance class? Not
        when the query or a policy that applies to it reads the executing
        session. Each table's plan is built for the caller exactly as the
        vend builds it; a reference that isn't a plain table of this catalog
        (a view, say) falls back to checking every policy in the catalog."""
        from .policies import plan_is_exportable
        if not self.settings.result_share:
            return False
        if not shape.parsed or shape.table_functions or shape.session_dependent:
            return False
        roles = sorted(set(caller.token_roles) | set(granted)
                       | {f"actor:{caller.actor}", f"channel:{caller.channel}"})
        for cat, schema, name in shape.tables:
            if not schema and not cat and name in shape.ctes:
                continue
            if cat and cat != self.ctx.catalog_id:
                return False
            schema = schema or namespace
            if not self.catalog.table_exists([schema], name):
                return not session_dependent_policies(self.catalog)
            plan = self.ctx.policy_engine.plan_for(
                principal=caller.sub, roles=roles, schema=schema, table=name)
            if not plan_is_exportable(plan):
                return False
        return True

    def refresh(self, caller: Caller, rs_id: str) -> dict:
        """Fresh credentials for a live result set the caller owns (a reuse:
        extends it). Gone once governance changed since it was built."""
        rs = self.get(rs_id, caller.sub)
        if rs is None:
            raise Rejected(404, "unknown or expired result set")
        if rs.governance_stamp != self.ctx.store.governance_stamp():
            raise Rejected(410, "governance changed since this result was built; run the query again")
        return self._response(self.touch(rs), caller, "hit")

    # -- materialization ------------------------------------------------------
    def _materialize(self, caller: Caller, namespace: str, sql: str, key: str,
                     reusable: bool, stamp: str, vend: Callable[[], dict], *,
                     shared: bool = False) -> ResultSet:
        settings = self.settings
        bundle = vend()       # exactly the session this caller would be vended
        rs_id = hashlib.sha256(os.urandom(16)).hexdigest()[:24]
        prefix = f"{settings.s3.results_root}{self.ctx.catalog_id}/{rs_id}/"
        tmp = tempfile.mkdtemp(prefix="rs-", dir=work_dir(settings, "results"))
        out = os.path.join(tmp, "part-0.parquet")
        con = duckdb.connect(":memory:")
        timer = threading.Timer(settings.result_timeout_seconds, con.interrupt)
        try:
            try:
                setup_governed(con, settings, bundle, self.ctx.catalog_id, namespace,
                               extra_dirs=[tmp + "/"],
                               memory_limit=settings.result_memory_limit,
                               threads=settings.result_threads,
                               spill_dir=os.path.join(tmp, "spill"))
            except PermissionError as e:
                raise Rejected(503, str(e))
            cap = int(settings.result_max_rows)
            timer.start()
            try:
                n = con.execute(
                    f"COPY (SELECT * FROM ({sql}) AS q LIMIT {cap + 1}) TO {ql(out)} "
                    "(FORMAT PARQUET, COMPRESSION ZSTD)").fetchone()[0]
            except duckdb.InterruptException:
                raise Rejected(504, f"query exceeded {settings.result_timeout_seconds:.0f}s")
            except duckdb.Error as e:
                raise Rejected(400, f"query failed: {str(e).splitlines()[0][:300]}")
            finally:
                timer.cancel()
            if n > cap:
                raise Rejected(413, f"result exceeds {cap} rows; narrow the query")
            cols = [{"name": r[0], "type": r[1]} for r in con.execute(
                f"DESCRIBE SELECT * FROM read_parquet({ql(out)})").fetchall()]
        finally:
            con.close()
        try:
            size = os.path.getsize(out)
            obj = f"{prefix}part-0.parquet"
            self.catalog._s3_client.upload_file(out, settings.s3.bucket, obj)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        now = datetime.now(timezone.utc)
        hard = now + timedelta(days=settings.result_max_days)
        expires = min(now + timedelta(hours=settings.result_idle_hours), hard)
        files = [{"key": obj, "bytes": size}]
        with self._cursor() as cur:
            self._ensure(cur)
            r = cur.execute(
                f"""INSERT INTO {self.sc}.duckicelake_result_set
                    (id, cache_key, reusable, principal, namespace, sql, governance_stamp,
                     prefix, files, columns, row_count, bytes, expires_at, hard_expires_at,
                     shared)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING {_COLS}""",
                (rs_id, key, reusable, caller.sub, namespace, sql, stamp, prefix,
                 json.dumps(files), json.dumps(cols), int(n), size, expires, hard, shared),
            ).fetchone()
        rs = ResultSet.from_row(r)
        try:
            self.ctx.store.audit_load(
                principal=caller.sub, object_=f"{namespace}.<query>", masked_cols=[],
                applied_policies=[], row_filtered=False, operation="result_set",
                decision="materialized",
                detail={"id": rs_id, "rows": int(n), "bytes": size, "reusable": reusable,
                        "shared": shared})
        except Exception:
            pass
        return rs

    # -- response ---------------------------------------------------------------
    def _response(self, rs: ResultSet, caller: Caller, status: str) -> dict:
        from .s3_gateway import mint_credentials
        s = self.settings
        gw = mint_credentials(
            s, sub=caller.sub, scope=caller.scope or "", roles=[],
            catalog_id=self.ctx.catalog_id, read_prefixes=[rs.prefix],
            extra_claims={"rs": rs.id})
        return {
            "id": rs.id,
            "status": status,
            "reusable": rs.reusable,
            "row_count": rs.row_count,
            "bytes": rs.bytes,
            "columns": rs.columns,
            "files": [f"s3://{s.s3.bucket}/{f['key']}" for f in rs.files],
            "created_at": rs.created_at.isoformat(),
            "expires_at": rs.expires_at.isoformat(),
            "hard_expires_at": rs.hard_expires_at.isoformat(),
            "use_count": rs.use_count,
            "shared": rs.shared,
            "s3": {
                "endpoint": s.s3_gateway_url,
                "region": s.s3.region,
                "path-style-access": s.s3.path_style,
                "access-key-id": gw["access_key_id"],
                "secret-access-key": gw["secret_access_key"],
                "session-token": None,
                "expiration": gw["expiration_iso"],
                "enforcement": "gateway",
            },
        }


def is_servable(ctx, rs_id: str, principal: str) -> bool:
    """For the gateway: may `principal` read result set `rs_id` right now?
    It must exist, be theirs (built by them, or served to them as a shared
    result), be live, and have been built under the catalog's current
    governance."""
    cat = ctx.catalog
    with cat.pg_cursor() as cur:
        ensure_result_sidecar(cur, cat.sidecar_schema)
        r = cur.execute(
            f"""SELECT governance_stamp FROM {cat.sidecar_sql}.duckicelake_result_set
                WHERE id = %s AND {_MAY_READ.format(sc=cat.sidecar_sql)}
                  AND expires_at > now() AND hard_expires_at > now()""",
            (rs_id, principal, principal)).fetchone()
    return r is not None and r[0] == ctx.store.governance_stamp()


# ---- retention --------------------------------------------------------------

_SWEEP_LOCK = int.from_bytes(hashlib.sha256(b"duckicelake:result_sweep").digest()[:8],
                             "big", signed=True)


def _delete_prefix(s3c, bucket: str, prefix: str) -> int:
    n = 0
    for page in s3c.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        objs = [{"Key": o["Key"]} for o in page.get("Contents") or []]
        if objs:
            s3c.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
            n += len(objs)
    return n


def sweep(settings, refs: list, s3c, *, orphan_grace: timedelta = timedelta(hours=1)) -> dict:
    """Purge expired result sets (idle or past the hard limit) of every
    catalog in `refs` [(catalog_id, CatalogRef)], plus orphaned objects (a
    crash between upload and insert). One sweeper at a time across workers."""
    stats = {"purged": 0, "objects": 0, "orphans": 0}
    with psycopg.connect(settings.pg_dsn, autocommit=True) as con:
        if not con.execute("SELECT pg_try_advisory_lock(%s)", (_SWEEP_LOCK,)).fetchone()[0]:
            return {**stats, "skipped": True}
        try:
            for catalog_id, ref in refs:
                schema = ref.metadata_schema or "public"
                if con.execute("SELECT to_regclass(%s)",
                               (f"{qi(schema)}.duckicelake_result_set",)).fetchone()[0] is None:
                    continue
                sc = qi(schema)
                rows = con.execute(
                    f"""SELECT id, prefix FROM {sc}.duckicelake_result_set
                        WHERE expires_at <= now() OR hard_expires_at <= now()""").fetchall()
                for rs_id, prefix in rows:
                    # Row first: nothing can be served or reused from here on.
                    con.execute(f"DELETE FROM {sc}.duckicelake_result_set WHERE id = %s", (rs_id,))
                    stats["objects"] += _delete_prefix(s3c, settings.s3.bucket, prefix)
                    stats["purged"] += 1
                live = {r[0] for r in con.execute(
                    f"SELECT id FROM {sc}.duckicelake_result_set").fetchall()}
                root = f"{settings.s3.results_root}{catalog_id}/"
                cutoff = datetime.now(timezone.utc) - orphan_grace
                stale: set[str] = set()
                for page in s3c.get_paginator("list_objects_v2").paginate(
                        Bucket=settings.s3.bucket, Prefix=root):
                    for o in page.get("Contents") or []:
                        rs_id = o["Key"][len(root):].split("/", 1)[0]
                        if rs_id not in live and o["LastModified"] < cutoff:
                            stale.add(rs_id)
                for rs_id in stale:
                    stats["orphans"] += _delete_prefix(s3c, settings.s3.bucket, f"{root}{rs_id}/")
        finally:
            con.execute("SELECT pg_advisory_unlock(%s)", (_SWEEP_LOCK,))
    if stats["purged"] or stats["orphans"]:
        log.info("result-set sweep: %s", stats)
    return stats


def lifecycle_rules(settings) -> list[dict]:
    """Bucket lifecycle backstop for the results root: current objects die a
    day after the hard limit even if the sweeper never runs, and — on a
    versioned bucket — purged objects' old versions are gone after a day
    instead of lingering as recoverable masked data."""
    return [{
        "ID": "duckicelake-results",
        "Filter": {"Prefix": settings.s3.results_root},
        "Status": "Enabled",
        "Expiration": {"Days": int(settings.result_max_days) + 1},
        "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
        "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
    }]


def apply_lifecycle(settings, s3c, *, dry_run: bool = False) -> list[dict]:
    """Merge `lifecycle_rules` into the bucket's lifecycle configuration,
    keeping every other rule untouched (the bucket may be shared)."""
    try:
        current = s3c.get_bucket_lifecycle_configuration(Bucket=settings.s3.bucket)["Rules"]
    except s3c.exceptions.ClientError as e:
        if "NoSuchLifecycleConfiguration" not in str(e):
            raise
        current = []
    ours = {r["ID"] for r in lifecycle_rules(settings)}
    merged = [r for r in current if r.get("ID") not in ours] + lifecycle_rules(settings)
    if not dry_run:
        s3c.put_bucket_lifecycle_configuration(
            Bucket=settings.s3.bucket, LifecycleConfiguration={"Rules": merged})
    return merged


if __name__ == "__main__":       # python -m duckicelake.result_sets lifecycle [--apply]
    import sys

    from . import s3util
    from .config import apply_file_config, load_settings
    apply_file_config()
    s = load_settings()
    if sys.argv[1:2] != ["lifecycle"]:
        raise SystemExit("usage: python -m duckicelake.result_sets lifecycle [--apply]")
    print(json.dumps(apply_lifecycle(s, s3util.s3_client(s.s3), dry_run="--apply" not in sys.argv),
                     indent=1, default=str))
