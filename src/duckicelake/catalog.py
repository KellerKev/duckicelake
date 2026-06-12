"""DuckLake catalog wrapper.

Holds a single DuckDB connection with the `ducklake` extension attached on top
of Postgres metadata + a local data path. Exposes namespace/table operations
that the Iceberg REST server layers on top of.

DuckDB connections are single-threaded internally, so we serialize access with
a lock. For a prototype this is fine; a production version would use a pool or
per-request short-lived connections.
"""
from __future__ import annotations

import contextvars
import os
import queue
import threading
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

import boto3
import duckdb
import psycopg
from psycopg_pool import ConnectionPool

from .config import Settings


# Active commit-scoped cursor. When set (via `commit_transaction()`),
# every `pg_cursor()` call within the same context uses this cursor
# instead of acquiring a fresh connection from the pool — so an entire
# Iceberg commit runs as one Postgres transaction. DuckDB-side operations
# (add_data_files, expire_snapshots, ALTER, COPY) aren't affected —
# they run on their own connection with their own DuckLake transaction.
_ACTIVE_PG_CUR: contextvars.ContextVar = contextvars.ContextVar(
    "duckicelake_active_pg_cursor", default=None
)


def _join_path(base: str, piece: str, relative: bool) -> str:
    """DuckLake-style path composition: absolute pieces replace; relative
    pieces append onto `base` with a single / separator."""
    if not relative:
        return piece
    return f"{base.rstrip('/')}/{piece.lstrip('/')}"


@dataclass
class ColumnInfo:
    name: str
    data_type: str
    is_nullable: bool
    ordinal: int


@dataclass
class DuckLakeColumn:
    """DuckLake's column row, the authoritative source for schema evolution."""
    column_id: int
    column_name: str
    column_type: str
    column_order: int
    begin_snapshot: int
    end_snapshot: int | None
    initial_default: str | None
    default_value: str | None
    nulls_allowed: bool


@dataclass
class DuckLakeDataFile:
    """Resolved data file + stats pulled from DuckLake catalog."""
    data_file_id: int
    file_path: str            # fully-resolved s3://... URI
    file_size_bytes: int
    record_count: int
    begin_snapshot: int
    end_snapshot: int | None
    row_id_start: int | None
    encryption_key: str | None = None  # DuckLake's per-file encryption key (VARCHAR) or None


@dataclass
class DuckLakeDeleteFile:
    delete_file_id: int
    data_file_id: int
    file_path: str
    file_size_bytes: int
    delete_count: int
    begin_snapshot: int
    end_snapshot: int | None


@dataclass
class DuckLakeColumnStat:
    column_id: int
    value_count: int | None
    null_count: int | None
    min_value: str | None
    max_value: str | None
    contains_nan: bool | None


@dataclass
class DuckLakeSnapshot:
    snapshot_id: int
    snapshot_time: "object"   # datetime with tz
    schema_version: int | None


@dataclass
class TableIdResolved:
    table_id: int
    schema_id: int


class DuckLakeCatalog:
    # DuckDB read pool size. Each connection re-ATTACHes the DuckLake
    # catalog, so keep this modest. Only used for pure-read paths
    # (list_views / get_view_definition / columns-via-info-schema fallback).
    # Most reads now go straight to Postgres via the pg pool, so 2 is plenty.
    _DUCKDB_READ_POOL_SIZE = 2

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lock = threading.Lock()                 # serialises the DuckDB write conn
        self._conn: duckdb.DuckDBPyConnection | None = None  # DuckDB write conn
        self._read_conns: queue.Queue | None = None   # DuckDB read pool
        self._export_lock = threading.Lock()          # serialises file-layer COPY exports
        self._export_conn: duckdb.DuckDBPyConnection | None = None
        self._pg_pool: ConnectionPool | None = None   # Postgres pool
        self._s3_client: Any = None                   # shared boto3 S3 client
        # Bounded LRU metadata cache keyed on (ns, table) → (snapshot_id, metadata).
        # Max entries tunable via DUCKICELAKE_CACHE_MAX (default 1024) — at ~50 KB
        # per entry that's ~50 MB of RSS at full occupancy, which we consider
        # cheap for any realistic deployment. Entries are invalidated from the
        # commit path; eviction is LRU via OrderedDict.move_to_end on hit.
        self._metadata_cache_max = int(os.environ.get("DUCKICELAKE_CACHE_MAX", "1024"))
        self._metadata_cache: OrderedDict[tuple[str, str], tuple[int, dict]] = OrderedDict()
        self._metadata_cache_lock = threading.Lock()
        # Observability counters — read by /metrics. Thread-safe via GIL for
        # simple ints; no lock needed on ++ with the lock already held in
        # cache methods.
        self._cache_hits = 0
        self._cache_misses = 0

    # ---- connection management -----------------------------------------

    def connect(self) -> None:
        if self._conn is not None:
            return
        self._conn = self._build_duckdb_conn()

        # DuckDB read pool — small fixed-size queue of ATTACHed read conns.
        # Each pops an entry, uses, pushes back. Worst-case blocks at
        # queue.get() under saturation; that's desirable backpressure vs
        # unbounded conn creation.
        read_q: queue.Queue = queue.Queue(maxsize=self._DUCKDB_READ_POOL_SIZE)
        for _ in range(self._DUCKDB_READ_POOL_SIZE):
            read_q.put(self._build_duckdb_conn())
        self._read_conns = read_q

        # Postgres connection pool for metadata reads + commit transactions.
        # Most LoadTable work is pure PG (ducklake_* tables + our sidecars),
        # so a real pool unlocks concurrency that `psycopg.connect()` per
        # call would serialise on connection setup.
        self._pg_pool = ConnectionPool(
            conninfo=self._pg_conninfo(),
            min_size=2,
            max_size=16,
            open=True,
            timeout=10.0,
        )

        # Shared boto3 S3 client — thread-safe, pools its own HTTPS conns.
        # Building it per-request (the old path) re-did botocore session
        # init + TLS handshakes for every LoadTable.
        s3 = self.settings.s3
        self._s3_client = boto3.client(
            "s3",
            endpoint_url=s3.endpoint,
            region_name=s3.region,
            aws_access_key_id=s3.root_access_key,
            aws_secret_access_key=s3.root_secret_key,
        )

    def _build_duckdb_conn(self) -> duckdb.DuckDBPyConnection:
        conn = duckdb.connect(":memory:")
        for ext in ("ducklake", "postgres", "httpfs", "spatial"):
            conn.execute(f"INSTALL {ext}")
            conn.execute(f"LOAD {ext}")

        # Proxy's own S3 credentials — per-connection so any COPY path works.
        s3 = self.settings.s3
        conn.execute(
            """
            CREATE OR REPLACE SECRET proxy_s3 (
                TYPE S3,
                KEY_ID ?, SECRET ?,
                REGION ?, ENDPOINT ?,
                USE_SSL ?, URL_STYLE ?
            )
            """,
            [
                s3.root_access_key,
                s3.root_secret_key,
                s3.region,
                s3.host,
                s3.use_ssl,
                "path" if s3.path_style else "vhost",
            ],
        )

        conn.execute(
            f"ATTACH '{self.settings.ducklake_uri}' AS {self._cat()} "
            f"(DATA_PATH '{self.settings.ducklake_data_path}', "
            f" DATA_INLINING_ROW_LIMIT 0)"
        )
        conn.execute(f"USE {self._cat()}")
        return conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        if self._read_conns is not None:
            while not self._read_conns.empty():
                try:
                    self._read_conns.get_nowait().close()
                except queue.Empty:
                    break
            self._read_conns = None
        if self._export_conn is not None:
            self._export_conn.close()
            self._export_conn = None
        if self._pg_pool is not None:
            self._pg_pool.close()
            self._pg_pool = None
        self._s3_client = None

    def _cat(self) -> str:
        # Catalog name is trusted from settings (not user input), so simple quoting is fine.
        return f'"{self.settings.catalog_name}"'

    @property
    def s3_client(self):
        """Shared boto3 S3 client. Created on `connect()`."""
        if self._s3_client is None:
            self.connect()
        return self._s3_client

    @contextmanager
    def cursor(self) -> Iterator[duckdb.DuckDBPyConnection]:
        """DuckDB write connection — serialised by a process lock.

        Use only for mutations (DDL, ducklake_add_data_files, COPY writes).
        Pure reads should go through `pg_cursor()` or `read_cursor()`.
        """
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        with self._lock:
            yield self._conn

    @contextmanager
    def read_cursor(self) -> Iterator[duckdb.DuckDBPyConnection]:
        """DuckDB read connection drawn from the read pool.

        Multiple concurrent readers are fine — each pops a dedicated conn
        off the queue, uses it, and returns it. Saturation blocks.
        """
        if self._read_conns is None:
            self.connect()
        assert self._read_conns is not None
        conn = self._read_conns.get()
        try:
            yield conn
        finally:
            self._read_conns.put(conn)

    @contextmanager
    def export_cursor(self) -> Iterator[duckdb.DuckDBPyConnection]:
        """Dedicated DuckDB connection for long-running COPY exports
        (governance file-layer masking). Deliberately NOT the write conn —
        a multi-minute COPY there would hold `_lock` and block every
        commit — and not the small read pool, which REST reads depend on.
        Lazily built, serialized by its own lock (exports are naturally
        sequential: the notify listener is single-elected and request-path
        exports take a PG advisory lock)."""
        with self._export_lock:
            if self._export_conn is None:
                self._export_conn = self._build_duckdb_conn()
            yield self._export_conn

    @contextmanager
    def pg_cursor(self, *, autocommit: bool = True) -> Iterator[psycopg.Cursor]:
        """Postgres cursor from the pool. Auto-commits on exit by default.

        Use for anything that was previously `with psycopg.connect(...):`.
        If a `commit_transaction()` is active in the same context, yields
        the commit's shared cursor instead so callers end up in one tx.
        For one-off multi-statement transactions, use `pg_transaction()`.
        """
        shared = _ACTIVE_PG_CUR.get()
        if shared is not None:
            yield shared
            return
        if self._pg_pool is None:
            self.connect()
        assert self._pg_pool is not None
        with self._pg_pool.connection() as conn:
            conn.autocommit = autocommit
            with conn.cursor() as cur:
                yield cur

    @contextmanager
    def pg_transaction(self) -> Iterator[psycopg.Cursor]:
        """Cursor bound to a single transaction. Commits on clean exit,
        rolls back on exception."""
        if self._pg_pool is None:
            self.connect()
        assert self._pg_pool is not None
        with self._pg_pool.connection() as conn:
            conn.autocommit = False
            try:
                with conn.cursor() as cur:
                    yield cur
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    @contextmanager
    def commit_transaction(self) -> Iterator[None]:
        """Scope: every PG-side catalog method called inside this context
        shares a single Postgres transaction. Rolls back on exception.

        Enables atomic multi-step Iceberg commits on the PG side (tombstones
        + register-delete + property upsert + tag upsert in one tx). DuckDB
        operations inside the scope are unaffected — they're on a separate
        connection with their own DuckLake transactions.
        """
        if self._pg_pool is None:
            self.connect()
        assert self._pg_pool is not None
        with self._pg_pool.connection() as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                token = _ACTIVE_PG_CUR.set(cur)
                try:
                    yield
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
                finally:
                    _ACTIVE_PG_CUR.reset(token)

    # ---- in-process metadata cache ------------------------------------

    def cached_metadata(
        self, ns: list[str], table: str, current_snap_id: int,
    ) -> dict | None:
        """Return cached TableMetadata if cached snapshot matches current."""
        key = (ns[0], table)
        with self._metadata_cache_lock:
            entry = self._metadata_cache.get(key)
            if entry and entry[0] == current_snap_id:
                self._metadata_cache.move_to_end(key)       # LRU touch
                self._cache_hits += 1
                return entry[1]
            self._cache_misses += 1
        return None

    def put_cached_metadata(
        self, ns: list[str], table: str, snap_id: int, metadata: dict,
    ) -> None:
        key = (ns[0], table)
        with self._metadata_cache_lock:
            self._metadata_cache[key] = (snap_id, metadata)
            self._metadata_cache.move_to_end(key)
            while len(self._metadata_cache) > self._metadata_cache_max:
                self._metadata_cache.popitem(last=False)    # evict LRU

    def invalidate_metadata_cache(self, ns: list[str], table: str) -> None:
        key = (ns[0], table)
        with self._metadata_cache_lock:
            self._metadata_cache.pop(key, None)

    def metadata_cache_stats(self) -> dict[str, int]:
        """Snapshot of cache counters for /metrics. Thread-safe read."""
        with self._metadata_cache_lock:
            return {
                "size": len(self._metadata_cache),
                "max": self._metadata_cache_max,
                "hits": self._cache_hits,
                "misses": self._cache_misses,
            }

    # ---- namespaces ----------------------------------------------------

    def list_namespaces(self, parent: list[str] | None = None) -> list[list[str]]:
        # DuckLake is flat — no nesting. Query `ducklake_schema` directly
        # rather than going through DuckDB's information_schema (avoids
        # the DuckDB write-conn lock entirely for this read).
        if parent:
            return []
        with self.pg_cursor() as cur:
            cur.execute(
                "SELECT schema_name FROM public.ducklake_schema "
                "WHERE end_snapshot IS NULL ORDER BY schema_name"
            )
            return [[r[0]] for r in cur.fetchall()]

    def namespace_exists(self, ns: list[str]) -> bool:
        if len(ns) != 1:
            return False
        with self.pg_cursor() as cur:
            cur.execute(
                "SELECT 1 FROM public.ducklake_schema "
                "WHERE schema_name = %s AND end_snapshot IS NULL",
                (ns[0],),
            )
            return cur.fetchone() is not None

    def create_namespace(self, ns: list[str]) -> None:
        if len(ns) != 1:
            raise ValueError("Nested namespaces are not supported by DuckLake")
        with self.cursor() as c:
            c.execute(f'CREATE SCHEMA {self._cat()}."{ns[0]}"')

    def drop_namespace(self, ns: list[str]) -> None:
        if len(ns) != 1:
            raise ValueError("Nested namespaces are not supported by DuckLake")
        with self.cursor() as c:
            c.execute(f'DROP SCHEMA {self._cat()}."{ns[0]}"')

    # ---- tables --------------------------------------------------------

    def list_tables(self, ns: list[str]) -> list[tuple[str, str]]:
        if len(ns) != 1:
            return []
        with self.pg_cursor() as cur:
            cur.execute(
                """
                SELECT t.table_name
                FROM public.ducklake_table t
                JOIN public.ducklake_schema s USING(schema_id)
                WHERE s.schema_name = %s
                  AND t.end_snapshot IS NULL
                  AND s.end_snapshot IS NULL
                ORDER BY t.table_name
                """,
                (ns[0],),
            )
            return [(ns[0], r[0]) for r in cur.fetchall()]

    def table_exists(self, ns: list[str], name: str) -> bool:
        if len(ns) != 1:
            return False
        with self.pg_cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM public.ducklake_table t
                JOIN public.ducklake_schema s USING(schema_id)
                WHERE s.schema_name = %s AND t.table_name = %s
                  AND t.end_snapshot IS NULL AND s.end_snapshot IS NULL
                """,
                (ns[0], name),
            )
            return cur.fetchone() is not None

    def get_columns(self, ns: list[str], name: str) -> list[ColumnInfo]:
        """Return live column info.

        Tables: read `ducklake_column` directly (fast path — no DuckDB).
        Views: DuckLake doesn't store resolved view column types, so we
        fall back to DuckDB's information_schema via the read pool.
        """
        if len(ns) != 1:
            return []
        with self.pg_cursor() as cur:
            cur.execute(
                """
                SELECT c.column_name, c.column_type, c.nulls_allowed, c.column_order
                FROM public.ducklake_column c
                JOIN public.ducklake_table  t
                  ON t.table_id = c.table_id AND t.end_snapshot IS NULL
                JOIN public.ducklake_schema s
                  ON s.schema_id = t.schema_id AND s.end_snapshot IS NULL
                WHERE s.schema_name = %s AND t.table_name = %s
                  AND c.end_snapshot IS NULL
                  AND c.parent_column IS NULL
                ORDER BY c.column_order
                """,
                (ns[0], name),
            )
            rows = cur.fetchall()
        if rows:
            return [
                ColumnInfo(
                    name=r[0], data_type=r[1],
                    is_nullable=bool(r[2]), ordinal=int(r[3]),
                )
                for r in rows
            ]
        # Not a table — try as a view (schema resolved by DuckDB).
        with self.read_cursor() as c:
            rows = c.execute(
                "SELECT column_name, data_type, is_nullable, ordinal_position "
                "FROM information_schema.columns "
                "WHERE table_catalog = ? AND table_schema = ? AND table_name = ? "
                "ORDER BY ordinal_position",
                [self.settings.catalog_name, ns[0], name],
            ).fetchall()
        return [
            ColumnInfo(name=r[0], data_type=r[1], is_nullable=(r[2] == "YES"), ordinal=r[3])
            for r in rows
        ]

    def create_table(
        self,
        ns: list[str],
        name: str,
        columns_ddl: str,
    ) -> None:
        """Create a table. `columns_ddl` is a ready-to-use column list like
        `"a" INTEGER, "b" VARCHAR`. Callers translate Iceberg schemas into this."""
        if len(ns) != 1:
            raise ValueError("Nested namespaces are not supported by DuckLake")
        stmt = f'CREATE TABLE {self._cat()}."{ns[0]}"."{name}" ({columns_ddl})'
        with self.cursor() as c:
            c.execute(stmt)

    def drop_table(self, ns: list[str], name: str) -> None:
        with self.cursor() as c:
            c.execute(f'DROP TABLE {self._cat()}."{ns[0]}"."{name}"')

    def purge_table_objects(self, ns: list[str], name: str) -> int:
        """Delete every S3 object under the table's prefix.

        Handles Parquet data files, position/equality-delete Parquets, the
        `metadata/*` Avros + `vN.metadata.json` + `version-hint.text`, and
        any leftover orphans. Used by DROP TABLE when the caller sets
        `purgeRequested=true`. Safe to call before or after DROP TABLE
        since it's prefix-based.

        Returns the number of S3 keys deleted.
        """
        s3 = self.settings.s3
        client = self.s3_client
        prefix = s3.table_prefix(ns[0], name)
        deleted = 0
        pages = client.get_paginator("list_objects_v2").paginate(
            Bucket=s3.bucket, Prefix=prefix,
        )
        batch: list[dict] = []

        def _flush() -> int:
            nonlocal batch
            if not batch:
                return 0
            client.delete_objects(
                Bucket=s3.bucket,
                Delete={"Objects": batch, "Quiet": True},
            )
            n = len(batch)
            batch = []
            return n

        for page in pages:
            for obj in page.get("Contents") or []:
                batch.append({"Key": obj["Key"]})
                if len(batch) >= 1000:
                    deleted += _flush()
        deleted += _flush()
        return deleted

    def compact_table(self, ns: list[str], name: str) -> dict[str, Any]:
        """Trigger DuckLake's built-in compaction + file-cleanup for a table.

        Wraps two DuckLake procedures (DuckLake 0.3+ signatures):
          - `ducklake_merge_adjacent_files(catalog, table_ref)` — rewrites
            small files into larger ones, collapsing position-delete
            files into their base data files where possible.
          - `ducklake_cleanup_old_files(catalog, dry_run, cleanup_all,
            older_than TIMESTAMPTZ)` — physically deletes S3 objects that
            DuckLake has marked as scheduled for deletion. We pass
            `cleanup_all=true` + a far-future timestamp so every
            already-scheduled object gets collected.

        Returns a summary dict; individual procedure failures are captured
        in the response rather than raised, so a partial success still
        returns useful info.
        """
        cat = self.settings.catalog_name
        out: dict[str, Any] = {"schema": ns[0], "table": name}
        with self.cursor() as c:
            # Scope the session to the target schema so merge_adjacent's
            # table-ref argument resolves correctly — fully-qualified
            # "schema.table" triggered a DuckLake catalog-lookup bug in
            # 1.0.x. Resetting USE in `finally` keeps us idempotent.
            c.execute(f'USE {self._cat()}."{ns[0]}"')
            try:
                try:
                    c.execute(
                        "CALL ducklake_merge_adjacent_files(?, ?)",
                        [cat, name],
                    )
                    out["merge"] = "ok"
                except duckdb.Error as e:
                    out["merge"] = f"error: {e}"
                try:
                    # `cleanup_all` and `older_than` are mutually exclusive
                    # in DuckLake — pass only one. `cleanup_all=TRUE`
                    # collects every already-scheduled object regardless
                    # of age, which is what an admin-triggered compact wants.
                    c.execute(
                        "CALL ducklake_cleanup_old_files(?, cleanup_all => TRUE)",
                        [cat],
                    )
                    out["cleanup"] = "ok"
                except duckdb.Error as e:
                    out["cleanup"] = f"error: {e}"
            finally:
                c.execute(f"USE {self._cat()}")
        return out

    def _live_data_file_id_by_abs_path(
        self, cur, table_id: int, ns: list[str], name: str
    ) -> dict[str, int]:
        """Map absolute s3:// data-file URI → data_file_id for live files.

        DuckLake's `path` is relative when `path_is_relative=true`, composed
        with schema.path + table.path + DATA_PATH on resolution. We reverse
        the composition by passing each stored row through the same
        `_resolve_full_path` we use for reads.
        """
        cur.execute(
            """
            SELECT data_file_id, path, path_is_relative
            FROM public.ducklake_data_file
            WHERE table_id = %s AND end_snapshot IS NULL
            """,
            (table_id,),
        )
        out: dict[str, int] = {}
        for df_id, path, is_rel in cur.fetchall():
            abs_path = self._resolve_full_path(ns, name, path, is_rel)
            out[abs_path] = int(df_id)
        return out

    def tombstone_data_files(
        self, ns: list[str], name: str, paths: list[str], *, change_msg: str | None = None,
    ) -> int:
        """Mark data files as removed at a fresh DuckLake snapshot.

        Mutates `ducklake_data_file.end_snapshot` directly — there's no
        public DuckLake procedure for this, but the UPDATE pattern is
        exactly what DuckLake itself uses for compaction and overwrites
        (`ducklake_metadata_manager.cpp:1984` in the v1.0 source). We
        also create a new ducklake_snapshot row so the change is
        snapshot-isolated, and a snapshot_changes record so audit
        readers see why.

        Returns the new DuckLake snapshot id. Raises if a path doesn't
        match any live data file (don't silently no-op — the caller's
        manifest claimed those files exist).
        """
        if not paths:
            raise ValueError("tombstone_data_files called with no paths")
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT t.table_id
                    FROM public.ducklake_table t
                    JOIN public.ducklake_schema s USING(schema_id)
                    WHERE s.schema_name = %s AND t.table_name = %s
                      AND t.end_snapshot IS NULL
                    """,
                    (ns[0], name),
                )
                row = cur.fetchone()
                if not row:
                    raise ValueError(f"No such table: {ns[0]}.{name}")
                table_id = int(row[0])

                live = self._live_data_file_id_by_abs_path(cur, table_id, ns, name)
                missing = [p for p in paths if p not in live]
                if missing:
                    raise ValueError(
                        f"tombstone: paths not live in DuckLake for "
                        f"{ns[0]}.{name} — already tombstoned or never "
                        f"registered: {missing[:3]}"
                        + (f"... ({len(missing)} total)" if len(missing) > 3 else "")
                    )

                target_ids = [live[p] for p in paths]
                new_snap = self._allocate_snapshot(cur)
                cur.execute(
                    """
                    UPDATE public.ducklake_data_file
                    SET end_snapshot = %s
                    WHERE table_id = %s AND end_snapshot IS NULL
                      AND data_file_id = ANY(%s)
                    """,
                    (new_snap, table_id, target_ids),
                )
                cur.execute(
                    "INSERT INTO public.ducklake_snapshot_changes "
                    "(snapshot_id, changes_made) VALUES (%s, %s)",
                    (new_snap, change_msg or f"deleted_from_table:{table_id}"),
                )
        return new_snap

    def register_delete_files(
        self,
        ns: list[str], name: str,
        delete_specs: list[dict],
        *, change_msg: str | None = None,
    ) -> int:
        """Register externally-written position-delete files into a fresh
        DuckLake snapshot.

        `delete_specs` is a list of dicts with keys:
          path                — absolute s3:// URI of the delete parquet
          target_data_file    — absolute s3:// URI of the data file the
                                deletes apply to (must be a live data file)
          delete_count        — number of (file_path, pos) rows in the parquet
          file_size_bytes     — size of the delete parquet
          footer_size_bytes   — Thrift footer length (read with pyarrow if unknown)

        DuckLake has no `ducklake_add_delete_files` procedure (verified in
        v1.0 source — only `ducklake_add_data_files` exists). We mirror the
        internal pattern: INSERT into `ducklake_delete_file` with
        `data_file_id` pointing at the affected data file, then bump a
        snapshot.

        The on-disk parquet schema must be Iceberg-standard
        `(file_path VARCHAR, pos BIGINT)` — DuckLake's reader accepts
        exactly that (`ducklake_delete_filter.cpp:151-165`).
        """
        if not delete_specs:
            raise ValueError("register_delete_files called with no specs")
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT t.table_id
                    FROM public.ducklake_table t
                    JOIN public.ducklake_schema s USING(schema_id)
                    WHERE s.schema_name = %s AND t.table_name = %s
                      AND t.end_snapshot IS NULL
                    """,
                    (ns[0], name),
                )
                row = cur.fetchone()
                if not row:
                    raise ValueError(f"No such table: {ns[0]}.{name}")
                table_id = int(row[0])

                live = self._live_data_file_id_by_abs_path(cur, table_id, ns, name)
                missing = [s["target_data_file"] for s in delete_specs if s["target_data_file"] not in live]
                if missing:
                    raise ValueError(
                        f"register_delete_files: target data files not live "
                        f"in DuckLake for {ns[0]}.{name}: {missing[:3]}"
                        + (f"... ({len(missing)} total)" if len(missing) > 3 else "")
                    )

                new_snap = self._allocate_snapshot(cur, n_files=len(delete_specs))

                # Allocate sequential file_ids — one per delete file.
                # The new snapshot's next_file_id was bumped by n_files in
                # _allocate_snapshot, so file ids [next_file_id - n_files,
                # next_file_id) are ours.
                cur.execute(
                    "SELECT next_file_id FROM public.ducklake_snapshot WHERE snapshot_id = %s",
                    (new_snap,),
                )
                next_file_id = int(cur.fetchone()[0])
                first_id = next_file_id - len(delete_specs)

                for i, spec in enumerate(delete_specs):
                    data_file_id = live[spec["target_data_file"]]
                    delete_path_abs = spec["path"]
                    cur.execute(
                        """
                        INSERT INTO public.ducklake_delete_file (
                            delete_file_id, table_id, begin_snapshot, end_snapshot,
                            data_file_id, path, path_is_relative, format,
                            delete_count, file_size_bytes, footer_size,
                            encryption_key, partial_max
                        ) VALUES (%s, %s, %s, NULL, %s, %s, FALSE, 'parquet',
                                  %s, %s, %s, NULL, NULL)
                        """,
                        (
                            first_id + i,
                            table_id,
                            new_snap,
                            data_file_id,
                            delete_path_abs,
                            int(spec["delete_count"]),
                            int(spec["file_size_bytes"]),
                            int(spec.get("footer_size_bytes", 0)),
                        ),
                    )

                cur.execute(
                    "INSERT INTO public.ducklake_snapshot_changes "
                    "(snapshot_id, changes_made) VALUES (%s, %s)",
                    (new_snap, change_msg or f"deleted_from_table:{table_id}"),
                )
        return new_snap

    def _allocate_snapshot(self, cur, *, n_files: int = 0) -> int:
        """Atomically allocate a new ducklake_snapshot id.

        Inherits schema_version + next_catalog_id from the most recent
        snapshot; bumps next_file_id by `n_files`. Returns the new id.
        Caller must already be inside a Postgres transaction.
        """
        cur.execute(
            """
            SELECT snapshot_id, schema_version, next_catalog_id, next_file_id
            FROM public.ducklake_snapshot
            ORDER BY snapshot_id DESC LIMIT 1
            """
        )
        cur_snap, schema_ver, next_cat_id, next_file_id = cur.fetchone()
        new_snap = int(cur_snap) + 1
        new_next_file_id = int(next_file_id) + n_files
        cur.execute(
            """
            INSERT INTO public.ducklake_snapshot
                (snapshot_id, snapshot_time, schema_version,
                 next_catalog_id, next_file_id)
            VALUES (%s, NOW(), %s, %s, %s)
            """,
            (new_snap, schema_ver, next_cat_id, new_next_file_id),
        )
        return new_snap

    def add_data_files(self, ns: list[str], name: str, paths: list[str]) -> None:
        """Register externally-written Parquet files as part of a DuckLake table.

        Backed by DuckLake's `ducklake_add_data_files` procedure, which reads
        Parquet footer metadata (stats, row counts) — no row scan — and
        inserts into `ducklake_data_file` + `ducklake_file_column_stats` as
        part of a new DuckLake snapshot. Ownership transfers to DuckLake
        after this call (files may be dropped by compaction/expire later).

        This is how we land writes from Iceberg clients: the client writes
        Parquet + manifest Avros to its staging location via its own FileIO,
        then `commit-table { add-snapshot }`. The proxy walks the manifest
        chain to extract file paths and hands them to this method.
        """
        if len(ns) != 1:
            raise ValueError("Nested namespaces not supported by DuckLake")
        if not paths:
            return
        with self.cursor() as c:
            # ducklake_add_data_files resolves the table name in the current
            # schema; USE scopes the search. Catalog + table are both bound
            # positionally to the procedure.
            c.execute(f'USE {self._cat()}."{ns[0]}"')
            try:
                c.execute(
                    "CALL ducklake_add_data_files(?, ?, ?)",
                    [self.settings.catalog_name, name, paths],
                )
            finally:
                # Return to default schema so subsequent catalog operations
                # aren't scoped to this namespace.
                c.execute(f"USE {self._cat()}")

    # ---- sidecar tables: properties + tags -----------------------------
    # DuckLake doesn't persist per-table key/value properties or Iceberg
    # branch/tag refs. We keep them in Postgres sidecar tables with the
    # `duckicelake_` prefix to make the origin obvious. Created on demand.

    def _ensure_sidecar(self, cur) -> None:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS public.duckicelake_table_property (
                schema_name VARCHAR NOT NULL,
                table_name VARCHAR NOT NULL,
                key VARCHAR NOT NULL,
                value VARCHAR NOT NULL,
                PRIMARY KEY (schema_name, table_name, key)
            )
        """)
        # Named-ref sidecar — serves both Iceberg tags and our synthesized
        # read-only branches. `ref_type` defaults to 'tag' for back-compat.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS public.duckicelake_table_tag (
                schema_name VARCHAR NOT NULL,
                table_name VARCHAR NOT NULL,
                tag_name VARCHAR NOT NULL,
                snapshot_id BIGINT NOT NULL,
                ref_type VARCHAR NOT NULL DEFAULT 'tag',
                PRIMARY KEY (schema_name, table_name, tag_name)
            )
        """)
        # Add the ref_type column if an older sidecar exists without it.
        cur.execute("""
            ALTER TABLE public.duckicelake_table_tag
            ADD COLUMN IF NOT EXISTS ref_type VARCHAR NOT NULL DEFAULT 'tag'
        """)
        # Per-file per-column exact NaN counts, populated lazily by
        # materialize_all when DuckLake's `contains_nan=true` flag
        # indicates a float column has NaNs. Iceberg expects an exact
        # count in nan_value_counts; DuckLake only tracks presence.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS public.duckicelake_file_nan_count (
                data_file_id BIGINT NOT NULL,
                column_id BIGINT NOT NULL,
                count BIGINT NOT NULL,
                PRIMARY KEY (data_file_id, column_id)
            )
        """)
        # Full Iceberg partition-spec sidecar. Used when the client's spec
        # contains transforms DuckLake can't express natively (truncate[N],
        # void) — we partition DuckLake by the subset it does support and
        # keep the full spec here for emission. For native-only specs this
        # sidecar is empty and materialize falls back to DuckLake's own
        # `ducklake_partition_column`.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS public.duckicelake_table_partition_field (
                schema_name VARCHAR NOT NULL,
                table_name VARCHAR NOT NULL,
                field_id INT NOT NULL,
                source_field_id INT NOT NULL,
                transform VARCHAR NOT NULL,
                name VARCHAR NOT NULL,
                position INT NOT NULL,
                ducklake_key_index INT,
                PRIMARY KEY (schema_name, table_name, field_id)
            )
        """)

    # ---- eager-materialisation sidecar --------------------------------
    # DuckLake-direct writes (DuckDB clients attaching `ducklake:` and
    # running INSERT/UPDATE/DELETE) commit straight into
    # public.ducklake_snapshot without going through the REST proxy. The
    # lazy LoadTable path still materialises them on first read, but
    # external readers pay that cost. The trigger + listener below
    # materialise eagerly so S3 metadata is warm immediately after the
    # DuckLake commit.

    def _ensure_materialisation_sidecar(self, cur) -> None:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS public.duckicelake_materialisation_log (
                ducklake_snapshot_id  BIGINT PRIMARY KEY,
                status                TEXT NOT NULL,
                iceberg_snapshot_id   BIGINT,
                error                 TEXT,
                materialised_at       TIMESTAMPTZ DEFAULT now()
            )
        """)
        # Notify function. Fires `NOTIFY duckicelake_snapshot, '<snap_id>'`
        # after every insert into ducklake_snapshot. CREATE OR REPLACE so
        # re-running on a newer proxy version cleanly updates the body.
        cur.execute("""
            CREATE OR REPLACE FUNCTION public.duckicelake_notify_snapshot()
            RETURNS trigger AS $$
            BEGIN
              PERFORM pg_notify('duckicelake_snapshot', NEW.snapshot_id::text);
              RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """)
        # Trigger creation guarded by an existence check, NOT a blind
        # DROP+CREATE: DROP TRIGGER takes ACCESS EXCLUSIVE on
        # ducklake_snapshot, and this ensure runs on every materialisation
        # touchpoint. A pending exclusive behind any long-lived reader tx
        # makes every later snapshot-allocator read queue up — observed as
        # a three-session deadlock with an in-flight commit_transaction
        # that calls into DuckDB DDL (PG can't detect it: the tx waits in
        # Python, not on a PG lock). The trigger body lives in the
        # CREATE OR REPLACE FUNCTION above, so updates don't need a
        # trigger re-create anyway.
        cur.execute("""
            SELECT 1 FROM pg_trigger
            WHERE tgname = 'duckicelake_snapshot_notify'
              AND tgrelid = 'public.ducklake_snapshot'::regclass
        """)
        if cur.fetchone() is None:
            cur.execute("""
                CREATE TRIGGER duckicelake_snapshot_notify
                AFTER INSERT ON public.ducklake_snapshot
                FOR EACH ROW
                EXECUTE FUNCTION public.duckicelake_notify_snapshot()
            """)

    def tables_touched_by_snapshot(
        self, snapshot_id: int,
    ) -> list[tuple[str, str]]:
        """Return (schema, table) pairs whose data files reference this
        DuckLake snapshot — either as `begin_snapshot` (file added) or
        `end_snapshot` (file expired). Used by the notify listener to
        decide which tables to materialise after each DuckLake commit.

        Mirrors the touched-snapshot CTE from list_snapshots but inverts
        the direction: snapshot → tables instead of table → snapshots.
        """
        with self.pg_cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT s.schema_name, t.table_name
                FROM public.ducklake_data_file d
                JOIN public.ducklake_table  t ON t.table_id = d.table_id
                JOIN public.ducklake_schema s ON s.schema_id = t.schema_id
                WHERE (d.begin_snapshot = %s OR d.end_snapshot = %s)
                  AND t.end_snapshot IS NULL
                  AND s.end_snapshot IS NULL
                """,
                (snapshot_id, snapshot_id),
            )
            return [(r[0], r[1]) for r in cur.fetchall()]

    def record_materialisation(
        self,
        snapshot_id: int,
        *,
        status: str,
        iceberg_snapshot_id: int | None = None,
        error: str | None = None,
    ) -> None:
        """Upsert a row in duckicelake_materialisation_log. status is one
        of 'pending' | 'done' | 'failed'."""
        with self.pg_cursor() as cur:
            self._ensure_materialisation_sidecar(cur)
            cur.execute(
                """
                INSERT INTO public.duckicelake_materialisation_log
                    (ducklake_snapshot_id, status, iceberg_snapshot_id,
                     error, materialised_at)
                VALUES (%s, %s, %s, %s, now())
                ON CONFLICT (ducklake_snapshot_id) DO UPDATE
                  SET status              = EXCLUDED.status,
                      iceberg_snapshot_id = EXCLUDED.iceberg_snapshot_id,
                      error               = EXCLUDED.error,
                      materialised_at     = EXCLUDED.materialised_at
                """,
                (snapshot_id, status, iceberg_snapshot_id, error),
            )

    def pending_materialisations(self, lookback_minutes: int = 60) -> list[int]:
        """Snapshot ids that exist in `ducklake_snapshot` but have no
        `done` row in our log within the lookback window. Driven by the
        catch-up scan on listener startup so a brief listener outage
        doesn't leave snapshots unmaterialised.
        """
        with self.pg_cursor() as cur:
            self._ensure_materialisation_sidecar(cur)
            cur.execute(
                """
                SELECT s.snapshot_id
                FROM public.ducklake_snapshot s
                LEFT JOIN public.duckicelake_materialisation_log l
                  ON l.ducklake_snapshot_id = s.snapshot_id
                  AND l.status = 'done'
                WHERE s.snapshot_id IS NOT NULL
                  AND s.snapshot_time > now() - (%s || ' minutes')::interval
                  AND l.ducklake_snapshot_id IS NULL
                ORDER BY s.snapshot_id
                """,
                (str(lookback_minutes),),
            )
            return [int(r[0]) for r in cur.fetchall()]

    def pg_conninfo(self) -> str:
        """Public accessor for the Postgres DSN. The notify listener
        needs an `psycopg.AsyncConnection` separate from the sync pool
        (LISTEN requires its own conn).
        """
        return self._pg_conninfo()

    def upsert_table_properties(
        self, ns: list[str], name: str,
        *,
        set_map: dict[str, str] | None = None,
        remove: list[str] | None = None,
    ) -> None:
        with self.pg_cursor() as cur:
                self._ensure_sidecar(cur)
                for k, v in (set_map or {}).items():
                    cur.execute(
                        """
                        INSERT INTO public.duckicelake_table_property
                            (schema_name, table_name, key, value)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (schema_name, table_name, key) DO UPDATE
                          SET value = EXCLUDED.value
                        """,
                        (ns[0], name, k, str(v)),
                    )
                for k in (remove or []):
                    cur.execute(
                        """
                        DELETE FROM public.duckicelake_table_property
                        WHERE schema_name = %s AND table_name = %s AND key = %s
                        """,
                        (ns[0], name, k),
                    )

    def get_table_properties(self, ns: list[str], name: str) -> dict[str, str]:
        with self.pg_cursor(autocommit=False) as cur:
                self._ensure_sidecar(cur)
                cur.execute(
                    """
                    SELECT key, value FROM public.duckicelake_table_property
                    WHERE schema_name = %s AND table_name = %s
                    """,
                    (ns[0], name),
                )
                return dict(cur.fetchall())

    def upsert_tag(
        self, ns: list[str], name: str, tag: str, snapshot_id: int,
        *, ref_type: str = "tag",
    ) -> None:
        with self.pg_cursor() as cur:
                self._ensure_sidecar(cur)
                cur.execute(
                    """
                    INSERT INTO public.duckicelake_table_tag
                        (schema_name, table_name, tag_name, snapshot_id, ref_type)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (schema_name, table_name, tag_name) DO UPDATE
                      SET snapshot_id = EXCLUDED.snapshot_id,
                          ref_type = EXCLUDED.ref_type
                    """,
                    (ns[0], name, tag, int(snapshot_id), ref_type),
                )

    def remove_tag(self, ns: list[str], name: str, tag: str) -> None:
        with self.pg_cursor() as cur:
                self._ensure_sidecar(cur)
                cur.execute(
                    """
                    DELETE FROM public.duckicelake_table_tag
                    WHERE schema_name = %s AND table_name = %s AND tag_name = %s
                    """,
                    (ns[0], name, tag),
                )

    def get_tags(self, ns: list[str], name: str) -> dict[str, tuple[int, str]]:
        """Return {ref_name: (snapshot_id, ref_type)} where ref_type is
        either 'tag' or 'branch'."""
        with self.pg_cursor(autocommit=False) as cur:
                self._ensure_sidecar(cur)
                cur.execute(
                    """
                    SELECT tag_name, snapshot_id, ref_type
                    FROM public.duckicelake_table_tag
                    WHERE schema_name = %s AND table_name = %s
                    """,
                    (ns[0], name),
                )
                return {r[0]: (int(r[1]), r[2]) for r in cur.fetchall()}

    def get_ref_type(self, ns: list[str], name: str, ref: str) -> str | None:
        """Return 'tag' / 'branch' / None for a named ref. `main` is always
        a branch — we handle that caller-side."""
        with self.pg_cursor(autocommit=False) as cur:
                self._ensure_sidecar(cur)
                cur.execute(
                    "SELECT ref_type FROM public.duckicelake_table_tag "
                    "WHERE schema_name=%s AND table_name=%s AND tag_name=%s",
                    (ns[0], name, ref),
                )
                r = cur.fetchone()
                return r[0] if r else None

    def upsert_nan_counts(
        self, entries: list[tuple[int, int, int]],
    ) -> None:
        """Bulk upsert (data_file_id, column_id, count) into the sidecar."""
        if not entries:
            return
        with self.pg_cursor() as cur:
                self._ensure_sidecar(cur)
                cur.executemany(
                    """
                    INSERT INTO public.duckicelake_file_nan_count
                        (data_file_id, column_id, count)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (data_file_id, column_id) DO UPDATE
                      SET count = EXCLUDED.count
                    """,
                    entries,
                )

    def get_nan_counts(self, data_file_ids: list[int]) -> dict[int, dict[int, int]]:
        """Map data_file_id → {column_id: exact_nan_count} from the sidecar."""
        if not data_file_ids:
            return {}
        with self.pg_cursor(autocommit=False) as cur:
                self._ensure_sidecar(cur)
                cur.execute(
                    """
                    SELECT data_file_id, column_id, count
                    FROM public.duckicelake_file_nan_count
                    WHERE data_file_id = ANY(%s)
                    """,
                    (data_file_ids,),
                )
                out: dict[int, dict[int, int]] = {}
                for dfid, cid, cnt in cur.fetchall():
                    out.setdefault(int(dfid), {})[int(cid)] = int(cnt)
        return out

    def compute_and_store_nan_counts(
        self,
        files: list[DuckLakeDataFile],
        needed: dict[int, dict[int, str]],
    ) -> None:
        """Scan each Parquet file for exact NaN counts per float column and
        persist into the sidecar.

        `needed` maps data_file_id → {column_id: column_name} for the
        (file, column) pairs DuckLake flagged `contains_nan=true` and that
        aren't already cached. DuckDB's httpfs reads the file; we ask it
        for `COUNT(*) FILTER (WHERE isnan(col))` per column in one pass.
        """
        if not files or not needed:
            return
        entries: list[tuple[int, int, int]] = []
        file_by_id = {f.data_file_id: f for f in files}
        with self.cursor() as c:
            for dfid, cols in needed.items():
                df = file_by_id.get(dfid)
                if df is None or not cols:
                    continue
                # Build a single SELECT that emits one column per field-id.
                select_parts = [
                    f"COUNT(*) FILTER (WHERE isnan(\"{cname}\")) AS c_{cid}"
                    for cid, cname in cols.items()
                ]
                sql = (
                    f"SELECT {', '.join(select_parts)} "
                    f"FROM read_parquet('{df.file_path}')"
                )
                row = c.execute(sql).fetchone()
                for (cid, _), count in zip(cols.items(), row):
                    entries.append((int(dfid), int(cid), int(count or 0)))
        self.upsert_nan_counts(entries)

    def upsert_iceberg_partition_spec(
        self, ns: list[str], name: str,
        fields: list[dict],
    ) -> None:
        """Replace the sidecar spec with `fields`.

        Each dict must have: field-id, source-id, transform, name, position,
        ducklake_key_index (int | None). Pass empty list to clear.
        """
        with self.pg_cursor() as cur:
                self._ensure_sidecar(cur)
                cur.execute(
                    "DELETE FROM public.duckicelake_table_partition_field "
                    "WHERE schema_name = %s AND table_name = %s",
                    (ns[0], name),
                )
                for f in fields:
                    cur.execute(
                        """
                        INSERT INTO public.duckicelake_table_partition_field
                            (schema_name, table_name, field_id, source_field_id,
                             transform, name, position, ducklake_key_index)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            ns[0], name,
                            int(f["field-id"]), int(f["source-id"]),
                            f["transform"], f["name"],
                            int(f["position"]),
                            (int(f["ducklake_key_index"])
                             if f.get("ducklake_key_index") is not None else None),
                        ),
                    )

    def get_iceberg_partition_spec(
        self, ns: list[str], name: str,
    ) -> list[dict]:
        """Return the sidecar Iceberg partition spec, ordered by position.
        Empty list means "fall back to DuckLake's native spec"."""
        with self.pg_cursor(autocommit=False) as cur:
                self._ensure_sidecar(cur)
                cur.execute(
                    """
                    SELECT field_id, source_field_id, transform, name,
                           position, ducklake_key_index
                    FROM public.duckicelake_table_partition_field
                    WHERE schema_name = %s AND table_name = %s
                    ORDER BY position
                    """,
                    (ns[0], name),
                )
                return [
                    {
                        "field-id": int(r[0]),
                        "source-id": int(r[1]),
                        "transform": r[2],
                        "name": r[3],
                        "position": int(r[4]),
                        "ducklake_key_index": int(r[5]) if r[5] is not None else None,
                    }
                    for r in cur.fetchall()
                ]

    def apply_equality_delete(
        self, ns: list[str], name: str,
        delete_file_s3_uri: str,
        equality_column_names: list[str],
    ) -> None:
        """Translate an Iceberg equality-delete file into spec-scoped
        per-file position-delete files.

        Iceberg semantics: equality deletes apply to data files with
        `sequence_number < delete's sequence_number`. The commit that
        carries this delete produces a fresh DuckLake snapshot; all files
        visible *now* (before that snap is allocated) are therefore older
        and in-scope. Files added later in the same commit are not.

        For each live data file we scan the Parquet via DuckDB's
        `read_parquet(..., file_row_number=true)`, join with the equality-
        delete keys, and COPY the (file_path, pos) hits out as an Iceberg
        position-delete Parquet. Then `register_delete_files` wires them
        into DuckLake as delete files against the matching data files.

        This replaces the earlier "DELETE FROM … WHERE IN (…)" approach,
        which was simpler but applied to the whole live table — breaking
        the Iceberg spec's historical scoping guarantee for snapshots
        written *after* the delete.
        """
        if not equality_column_names:
            raise ValueError("equality-delete requires equality_column_names")
        quoted_cols = ", ".join(f'"{c}"' for c in equality_column_names)

        snap = self.current_ducklake_snapshot(ns, name)
        if snap is None:
            return
        data_files = self.data_files_at(ns, name, snap)
        if not data_files:
            return

        # Where to put the position-delete parquets. Keep them under the
        # same table prefix DuckLake uses, so STS scoping and lifecycle
        # work without extra plumbing.
        s3 = self.settings.s3
        import uuid as _uuid

        # Parallelise per-file scan+COPY across the DuckDB read pool.
        # Each data file is independent — count, write, measure — so a
        # ThreadPoolExecutor over read_cursor() connections lets N files
        # process concurrently. Saturates on read pool size.
        import concurrent.futures as _cf

        def _process_file(df: DuckLakeDataFile) -> dict | None:
            with self.read_cursor() as c:
                count_sql = (
                    f"SELECT COUNT(*) FROM read_parquet('{df.file_path}') d "
                    f"WHERE ({quoted_cols}) IN (SELECT {quoted_cols} "
                    f"FROM read_parquet('{delete_file_s3_uri}'))"
                )
                (n_hits,) = c.execute(count_sql).fetchone()
                if not n_hits:
                    return None

                pos_key = (
                    f"{s3.table_prefix(ns[0], name)}"
                    f"ducklake-eqdel-{df.data_file_id}-{_uuid.uuid4().hex}.parquet"
                )
                pos_uri = f"s3://{s3.bucket}/{pos_key}"
                copy_sql = (
                    f"COPY ("
                    f"  SELECT '{df.file_path}' AS file_path, "
                    f"         file_row_number AS pos "
                    f"  FROM read_parquet('{df.file_path}', file_row_number=true) d "
                    f"  WHERE ({quoted_cols}) IN (SELECT {quoted_cols} "
                    f"         FROM read_parquet('{delete_file_s3_uri}'))"
                    f") TO '{pos_uri}' (FORMAT PARQUET)"
                )
                c.execute(copy_sql)
                (size_bytes,) = c.execute(
                    f"SELECT SUM(total_compressed_size) "
                    f"FROM parquet_metadata('{pos_uri}')"
                ).fetchone()
                return {
                    "path": pos_uri,
                    "target_data_file": df.file_path,
                    "delete_count": int(n_hits),
                    "file_size_bytes": int(size_bytes or 0),
                }

        specs: list[dict] = []
        with _cf.ThreadPoolExecutor(
            max_workers=self._DUCKDB_READ_POOL_SIZE
        ) as ex:
            for result in ex.map(_process_file, data_files):
                if result is not None:
                    specs.append(result)

        if specs:
            self.register_delete_files(
                ns, name, specs,
                change_msg="deleted_from_table:iceberg_equality_delete",
            )

    def column_names_by_ids(
        self, ns: list[str], name: str, column_ids: list[int],
    ) -> dict[int, str]:
        """Resolve a list of Iceberg field-ids (DuckLake column_ids) to names
        for the current live schema."""
        if not column_ids:
            return {}
        resolved = self.resolve_table(ns, name)
        if not resolved:
            return {}
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT column_id, column_name
                    FROM public.ducklake_column
                    WHERE table_id = %s AND end_snapshot IS NULL
                      AND column_id = ANY(%s)
                    """,
                    (resolved.table_id, [int(c) for c in column_ids]),
                )
                return {int(r[0]): r[1] for r in cur.fetchall()}

    def expire_snapshots(self, snapshot_ids: list[int]) -> None:
        """Hard-delete snapshots via DuckLake's built-in expire procedure.

        Wraps `ducklake_expire_snapshots(catalog, versions := [...])`.
        Used to implement Iceberg REST `remove-snapshot` / `remove-snapshot-ref`
        at commit time. Note: DuckLake actually tombstones + sweeps files
        later (via `ducklake_cleanup_old_files`) — this procedure only
        marks snapshots expired in metadata.
        """
        if not snapshot_ids:
            return
        with self.cursor() as c:
            arr_literal = "[" + ",".join(f"{int(s)}::UBIGINT" for s in snapshot_ids) + "]"
            c.execute(
                f"CALL ducklake_expire_snapshots('{self.settings.catalog_name}', "
                f"versions := {arr_literal})"
            )

    # ---- partitioning + sort orders ------------------------------------

    def set_partition_spec(
        self, ns: list[str], name: str, partition_clause: str,
    ) -> None:
        """ALTER TABLE … SET PARTITIONED BY (<partition_clause>).

        Empty `partition_clause` → unpartition. Non-empty must be in the
        DuckDB syntax accepted by DuckLake (e.g. `"day"("ts"), "id"`).
        """
        if len(ns) != 1:
            raise ValueError("Nested namespaces not supported by DuckLake")
        with self.cursor() as c:
            c.execute(f'USE {self._cat()}."{ns[0]}"')
            try:
                if partition_clause:
                    c.execute(
                        f'ALTER TABLE "{name}" SET PARTITIONED BY ({partition_clause})'
                    )
                else:
                    c.execute(f'ALTER TABLE "{name}" RESET PARTITIONED BY')
            finally:
                c.execute(f"USE {self._cat()}")

    def current_partition_spec_with_source_ids(
        self, ns: list[str], name: str,
    ) -> list[tuple[str, str, int]]:
        """Like current_partition_spec but also returns the source column_id
        for each partition field (needed to look up stats for transforms)."""
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT pc.partition_key_index, c.column_name,
                           pc.transform, pc.column_id
                    FROM public.ducklake_partition_column pc
                    JOIN public.ducklake_partition_info pi
                      ON pi.partition_id = pc.partition_id
                     AND pi.table_id = pc.table_id
                    JOIN public.ducklake_column c
                      ON c.column_id = pc.column_id
                     AND c.table_id = pc.table_id
                     AND c.end_snapshot IS NULL
                    JOIN public.ducklake_table t
                      ON t.table_id = pc.table_id
                     AND t.end_snapshot IS NULL
                    JOIN public.ducklake_schema s
                      ON s.schema_id = t.schema_id
                    WHERE s.schema_name = %s AND t.table_name = %s
                      AND pi.end_snapshot IS NULL
                    ORDER BY pc.partition_key_index
                    """,
                    (ns[0], name),
                )
                return [(r[1], r[2], int(r[3])) for r in cur.fetchall()]

    def partition_values_by_file(
        self, ns: list[str], name: str,
    ) -> dict[int, dict[int, str]]:
        """Map data_file_id → {partition_key_index: ducklake_partition_value}
        for the live partition spec."""
        resolved = self.resolve_table(ns, name)
        if not resolved:
            return {}
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT pv.data_file_id, pv.partition_key_index, pv.partition_value
                    FROM public.ducklake_file_partition_value pv
                    JOIN public.ducklake_data_file f
                      ON f.data_file_id = pv.data_file_id
                    WHERE pv.table_id = %s
                      AND f.end_snapshot IS NULL
                    """,
                    (resolved.table_id,),
                )
                out: dict[int, dict[int, str]] = {}
                for dfid, idx, val in cur.fetchall():
                    out.setdefault(int(dfid), {})[int(idx)] = val
        return out

    def current_partition_spec(
        self, ns: list[str], name: str,
    ) -> list[tuple[str, str]]:
        """Return [(column_name, ducklake_transform), ...] for the current
        live partition spec, in field order. Empty list if unpartitioned.
        """
        with self.pg_cursor(autocommit=False) as cur:
                # column_id is scoped per-table in DuckLake (NOT globally
                # unique) — different tables can reuse column_id=1, 2, 3.
                # Joining ducklake_column on column_id alone multiplies
                # rows across every table that has matching column_ids.
                # Always join on (column_id, table_id).
                cur.execute(
                    """
                    SELECT pc.partition_key_index, c.column_name, pc.transform
                    FROM public.ducklake_partition_column pc
                    JOIN public.ducklake_partition_info pi
                      ON pi.partition_id = pc.partition_id
                     AND pi.table_id = pc.table_id
                    JOIN public.ducklake_column c
                      ON c.column_id = pc.column_id
                     AND c.table_id = pc.table_id
                     AND c.end_snapshot IS NULL
                    JOIN public.ducklake_table t
                      ON t.table_id = pc.table_id
                     AND t.end_snapshot IS NULL
                    JOIN public.ducklake_schema s
                      ON s.schema_id = t.schema_id
                    WHERE s.schema_name = %s AND t.table_name = %s
                      AND pi.end_snapshot IS NULL
                    ORDER BY pc.partition_key_index
                    """,
                    (ns[0], name),
                )
                return [(r[1], r[2]) for r in cur.fetchall()]

    def set_sort_order(
        self,
        ns: list[str], name: str,
        fields: list,   # list[IcebergSortField]
    ) -> int:
        """Replace the live sort order with the provided field list.

        DuckLake has no SQL syntax for sort orders, so we mutate the
        bookkeeping tables directly: tombstone the previous sort_info
        row (if any), insert a new sort_info + sort_expression rows, and
        bump a snapshot. Same direct-Postgres pattern we use for delete
        files, with the same comment about being undocumented territory.
        """
        if len(ns) != 1:
            raise ValueError("Nested namespaces not supported by DuckLake")

        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT t.table_id
                    FROM public.ducklake_table t
                    JOIN public.ducklake_schema s USING(schema_id)
                    WHERE s.schema_name = %s AND t.table_name = %s
                      AND t.end_snapshot IS NULL
                    """,
                    (ns[0], name),
                )
                row = cur.fetchone()
                if not row:
                    raise ValueError(f"No such table: {ns[0]}.{name}")
                table_id = int(row[0])

                # Look up column names per source-id so we can use them
                # in the sort expression.
                cur.execute(
                    """
                    SELECT column_id, column_name
                    FROM public.ducklake_column
                    WHERE table_id = %s AND end_snapshot IS NULL
                      AND parent_column IS NULL
                    """,
                    (table_id,),
                )
                col_name_by_id = {int(c[0]): c[1] for c in cur.fetchall()}

                new_snap = self._allocate_snapshot(cur, n_files=0)

                # Tombstone the previous live sort_info, if any.
                cur.execute(
                    """
                    UPDATE public.ducklake_sort_info
                    SET end_snapshot = %s
                    WHERE table_id = %s AND end_snapshot IS NULL
                    RETURNING sort_id
                    """,
                    (new_snap, table_id),
                )
                tombstoned = cur.fetchall()

                if fields:
                    # Allocate next sort_id (just take MAX + 1; sort_ids
                    # are scoped per-table in DuckLake).
                    cur.execute(
                        "SELECT COALESCE(MAX(sort_id), -1) + 1 "
                        "FROM public.ducklake_sort_info WHERE table_id = %s",
                        (table_id,),
                    )
                    sort_id = int(cur.fetchone()[0])

                    cur.execute(
                        """
                        INSERT INTO public.ducklake_sort_info
                            (sort_id, table_id, begin_snapshot, end_snapshot)
                        VALUES (%s, %s, %s, NULL)
                        """,
                        (sort_id, table_id, new_snap),
                    )

                    for idx, f in enumerate(fields):
                        col_name = col_name_by_id.get(f.source_id)
                        if not col_name:
                            raise ValueError(
                                f"sort field source-id={f.source_id} not in "
                                f"current schema for {ns[0]}.{name}"
                            )
                        # Iceberg null-order is "nulls-first"/"nulls-last";
                        # DuckLake stores "nulls_first"/"nulls_last".
                        null_order = f.null_order.replace("-", "_")
                        cur.execute(
                            """
                            INSERT INTO public.ducklake_sort_expression
                                (sort_id, sort_key_index, expression,
                                 dialect, sort_direction, null_order)
                            VALUES (%s, %s, %s, 'duckdb', %s, %s)
                            """,
                            (sort_id, idx, f'"{col_name}"', f.direction, null_order),
                        )

                cur.execute(
                    "INSERT INTO public.ducklake_snapshot_changes "
                    "(snapshot_id, changes_made) VALUES (%s, %s)",
                    (new_snap, f"altered_table:{table_id}"),
                )
        return new_snap

    def current_sort_order(
        self, ns: list[str], name: str,
    ) -> list[tuple[str, str, str]]:
        """Return [(column_name, direction, null_order), ...] in key order.
        Empty list if no sort order is set.
        """
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT se.sort_key_index, se.expression,
                           se.sort_direction, se.null_order
                    FROM public.ducklake_sort_expression se
                    JOIN public.ducklake_sort_info si
                      ON si.sort_id = se.sort_id
                    JOIN public.ducklake_table t
                      ON t.table_id = si.table_id AND t.end_snapshot IS NULL
                    JOIN public.ducklake_schema s
                      ON s.schema_id = t.schema_id
                    WHERE s.schema_name = %s AND t.table_name = %s
                      AND si.end_snapshot IS NULL
                    ORDER BY se.sort_key_index
                    """,
                    (ns[0], name),
                )
                return [(r[1], r[2], r[3]) for r in cur.fetchall()]

    def add_column(self, ns: list[str], name: str, col_name: str, col_type_ddl: str,
                   nullable: bool = True, default_value: str | None = None) -> None:
        null_clause = "" if nullable else " NOT NULL"
        default_clause = f" DEFAULT {default_value}" if default_value is not None else ""
        stmt = (
            f'ALTER TABLE {self._cat()}."{ns[0]}"."{name}" '
            f'ADD COLUMN "{col_name}" {col_type_ddl}{null_clause}{default_clause}'
        )
        with self.cursor() as c:
            c.execute(stmt)

    def drop_column(self, ns: list[str], name: str, col_name: str) -> None:
        with self.cursor() as c:
            c.execute(
                f'ALTER TABLE {self._cat()}."{ns[0]}"."{name}" DROP COLUMN "{col_name}"'
            )

    # ---- views ---------------------------------------------------------

    def list_views(self, ns: list[str]) -> list[str]:
        if len(ns) != 1:
            return []
        with self.pg_cursor() as cur:
            cur.execute(
                """
                SELECT v.view_name
                FROM public.ducklake_view v
                JOIN public.ducklake_schema s USING(schema_id)
                WHERE s.schema_name = %s
                  AND v.end_snapshot IS NULL
                  AND s.end_snapshot IS NULL
                ORDER BY v.view_name
                """,
                (ns[0],),
            )
            return [r[0] for r in cur.fetchall()]

    def view_exists(self, ns: list[str], name: str) -> bool:
        if len(ns) != 1:
            return False
        with self.pg_cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM public.ducklake_view v
                JOIN public.ducklake_schema s USING(schema_id)
                WHERE s.schema_name = %s AND v.view_name = %s
                  AND v.end_snapshot IS NULL AND s.end_snapshot IS NULL
                """,
                (ns[0], name),
            )
            return cur.fetchone() is not None

    def get_view_definition(self, ns: list[str], name: str) -> str | None:
        with self.pg_cursor() as cur:
            cur.execute(
                """
                SELECT v.sql
                FROM public.ducklake_view v
                JOIN public.ducklake_schema s USING(schema_id)
                WHERE s.schema_name = %s AND v.view_name = %s
                  AND v.end_snapshot IS NULL AND s.end_snapshot IS NULL
                """,
                (ns[0], name),
            )
            r = cur.fetchone()
        return r[0] if r else None

    def create_view(self, ns: list[str], name: str, sql: str, replace: bool = False) -> None:
        keyword = "CREATE OR REPLACE VIEW" if replace else "CREATE VIEW"
        with self.cursor() as c:
            c.execute(
                f'{keyword} {self._cat()}."{ns[0]}"."{name}" AS {sql}'
            )

    def drop_view(self, ns: list[str], name: str) -> None:
        with self.cursor() as c:
            c.execute(f'DROP VIEW {self._cat()}."{ns[0]}"."{name}"')

    def rename_table(
        self, src_ns: list[str], src_name: str, dst_ns: list[str], dst_name: str
    ) -> None:
        if src_ns != dst_ns:
            raise ValueError("Cross-namespace rename not supported")
        with self.cursor() as c:
            c.execute(
                f'ALTER TABLE {self._cat()}."{src_ns[0]}"."{src_name}" '
                f'RENAME TO "{dst_name}"'
            )

    # ---- identity -----------------------------------------------------

    def _pg_conninfo(self) -> str:
        s = self.settings
        return (
            f"dbname={s.pg_database} host={s.pg_host} "
            f"port={s.pg_port} user={s.pg_user}"
        )

    def resolve_table(self, ns: list[str], name: str) -> TableIdResolved | None:
        """Look up DuckLake's table_id + schema_id for a qualified table name."""
        if len(ns) != 1:
            return None
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT t.table_id, s.schema_id
                    FROM public.ducklake_table t
                    JOIN public.ducklake_schema s USING(schema_id)
                    WHERE s.schema_name = %s AND t.table_name = %s
                      AND t.end_snapshot IS NULL
                    """,
                    (ns[0], name),
                )
                r = cur.fetchone()
        return TableIdResolved(int(r[0]), int(r[1])) if r else None

    def table_path_pieces(self, ns: list[str], name: str) -> tuple[str, bool, str, bool]:
        """Return (schema_path, schema_relative, table_path, table_relative).

        Used to compose file paths; pulled out so we can cache per call.
        """
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT s.path, s.path_is_relative, t.path, t.path_is_relative
                    FROM public.ducklake_table t
                    JOIN public.ducklake_schema s USING(schema_id)
                    WHERE s.schema_name = %s AND t.table_name = %s
                      AND t.end_snapshot IS NULL
                    """,
                    (ns[0], name),
                )
                r = cur.fetchone()
        if not r:
            raise ValueError(f"No such table: {ns[0]}.{name}")
        return r[0], r[1], r[2], r[3]

    def _resolve_full_path(self, ns: list[str], name: str, file_path: str, file_rel: bool) -> str:
        """Compose DATA_PATH + schema.path + table.path + file.path with relatives."""
        s_path, s_rel, t_path, t_rel = self.table_path_pieces(ns, name)
        base = self.settings.ducklake_data_path
        base = _join_path(base, s_path, s_rel)
        base = _join_path(base, t_path, t_rel)
        return _join_path(base, file_path, file_rel)

    # ---- snapshots -----------------------------------------------------

    def snapshot_changes_map(self) -> dict[int, str]:
        """Return snapshot_id → raw changes_made string from DuckLake.

        `changes_made` is DuckLake's free-form audit string, e.g.
        `inserted_into_table:3`, `deleted_from_table:3`, `altered_table:3`,
        `created_table:"analytics"."events"`. We parse it into an
        Iceberg `snapshot.summary.operation` value.
        """
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    "SELECT snapshot_id, changes_made FROM public.ducklake_snapshot_changes"
                )
                return {int(r[0]): (r[1] or "") for r in cur.fetchall()}

    def list_snapshots(self, ns: list[str], name: str) -> list[DuckLakeSnapshot]:
        """All DuckLake snapshots that ever touched this table, ordered asc."""
        resolved = self.resolve_table(ns, name)
        if not resolved:
            return []
        with self.pg_cursor(autocommit=False) as cur:
                # DuckLake doesn't have a direct snapshot↔table link table, so
                # we union everything that references this table_id in any of
                # the per-object history tables.
                # Union every per-object table that carries a (begin/end)
                # snapshot range scoped to this table_id. Missing any of
                # these means a commit type (partition spec, sort order)
                # silently fails to advance our notion of "current snap"
                # and cache hits return stale metadata.
                cur.execute(
                    """
                    WITH touched AS (
                      SELECT DISTINCT begin_snapshot AS snap FROM public.ducklake_data_file       WHERE table_id = %s
                      UNION SELECT end_snapshot                              FROM public.ducklake_data_file       WHERE table_id = %s AND end_snapshot IS NOT NULL
                      UNION SELECT begin_snapshot                            FROM public.ducklake_delete_file     WHERE table_id = %s
                      UNION SELECT end_snapshot                              FROM public.ducklake_delete_file     WHERE table_id = %s AND end_snapshot IS NOT NULL
                      UNION SELECT begin_snapshot                            FROM public.ducklake_column          WHERE table_id = %s
                      UNION SELECT end_snapshot                              FROM public.ducklake_column          WHERE table_id = %s AND end_snapshot IS NOT NULL
                      UNION SELECT begin_snapshot                            FROM public.ducklake_partition_info  WHERE table_id = %s
                      UNION SELECT end_snapshot                              FROM public.ducklake_partition_info  WHERE table_id = %s AND end_snapshot IS NOT NULL
                      UNION SELECT begin_snapshot                            FROM public.ducklake_sort_info       WHERE table_id = %s
                      UNION SELECT end_snapshot                              FROM public.ducklake_sort_info       WHERE table_id = %s AND end_snapshot IS NOT NULL
                    )
                    SELECT s.snapshot_id, s.snapshot_time, s.schema_version
                    FROM public.ducklake_snapshot s
                    JOIN touched t ON t.snap = s.snapshot_id
                    WHERE s.snapshot_id IS NOT NULL
                    ORDER BY s.snapshot_id
                    """,
                    (resolved.table_id,) * 10,
                )
                rows = cur.fetchall()
        return [
            DuckLakeSnapshot(snapshot_id=int(r[0]), snapshot_time=r[1], schema_version=r[2])
            for r in rows
        ]

    def data_files_at(
        self, ns: list[str], name: str, snapshot_id: int
    ) -> list[DuckLakeDataFile]:
        """Live data files visible at a given snapshot id."""
        resolved = self.resolve_table(ns, name)
        if not resolved:
            return []
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT data_file_id, path, path_is_relative, file_size_bytes,
                           record_count, begin_snapshot, end_snapshot, row_id_start,
                           encryption_key
                    FROM public.ducklake_data_file
                    WHERE table_id = %s
                      AND begin_snapshot <= %s
                      AND (end_snapshot IS NULL OR end_snapshot > %s)
                    ORDER BY data_file_id
                    """,
                    (resolved.table_id, snapshot_id, snapshot_id),
                )
                rows = cur.fetchall()
        out: list[DuckLakeDataFile] = []
        for dfid, path, rel, sz, rc, bs, es, rid, enc in rows:
            full = self._resolve_full_path(ns, name, path, rel)
            out.append(DuckLakeDataFile(
                data_file_id=int(dfid), file_path=full,
                file_size_bytes=int(sz), record_count=int(rc),
                begin_snapshot=int(bs), end_snapshot=int(es) if es is not None else None,
                row_id_start=int(rid) if rid is not None else None,
                encryption_key=enc if enc else None,
            ))
        return out

    def delete_files_at(
        self, ns: list[str], name: str, snapshot_id: int
    ) -> list[DuckLakeDeleteFile]:
        resolved = self.resolve_table(ns, name)
        if not resolved:
            return []
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT delete_file_id, data_file_id, path, path_is_relative,
                           file_size_bytes, delete_count,
                           begin_snapshot, end_snapshot
                    FROM public.ducklake_delete_file
                    WHERE table_id = %s
                      AND begin_snapshot <= %s
                      AND (end_snapshot IS NULL OR end_snapshot > %s)
                    ORDER BY delete_file_id
                    """,
                    (resolved.table_id, snapshot_id, snapshot_id),
                )
                rows = cur.fetchall()
        out: list[DuckLakeDeleteFile] = []
        for dfid, data_file_id, path, rel, sz, cnt, bs, es in rows:
            full = self._resolve_full_path(ns, name, path, rel)
            out.append(DuckLakeDeleteFile(
                delete_file_id=int(dfid),
                data_file_id=int(data_file_id),
                file_path=full,
                file_size_bytes=int(sz),
                delete_count=int(cnt),
                begin_snapshot=int(bs),
                end_snapshot=int(es) if es is not None else None,
            ))
        return out

    def column_stats(
        self, data_file_ids: list[int]
    ) -> dict[int, list[DuckLakeColumnStat]]:
        """Map data_file_id -> per-column stats for the given files."""
        if not data_file_ids:
            return {}
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT data_file_id, column_id, value_count, null_count,
                           min_value, max_value, contains_nan
                    FROM public.ducklake_file_column_stats
                    WHERE data_file_id = ANY(%s)
                    """,
                    (data_file_ids,),
                )
                rows = cur.fetchall()
        out: dict[int, list[DuckLakeColumnStat]] = {}
        for dfid, cid, vc, nc, mn, mx, nan in rows:
            out.setdefault(int(dfid), []).append(DuckLakeColumnStat(
                column_id=int(cid),
                value_count=int(vc) if vc is not None else None,
                null_count=int(nc) if nc is not None else None,
                min_value=mn, max_value=mx,
                contains_nan=bool(nan) if nan is not None else None,
            ))
        return out

    def columns_at(self, ns: list[str], name: str, snapshot_id: int) -> list[DuckLakeColumn]:
        """Columns visible to a table at the given snapshot id."""
        resolved = self.resolve_table(ns, name)
        if not resolved:
            return []
        with self.pg_cursor(autocommit=False) as cur:
                cur.execute(
                    """
                    SELECT column_id, column_name, column_type, column_order,
                           begin_snapshot, end_snapshot,
                           initial_default, default_value, nulls_allowed
                    FROM public.ducklake_column
                    WHERE table_id = %s
                      AND begin_snapshot <= %s
                      AND (end_snapshot IS NULL OR end_snapshot > %s)
                      AND parent_column IS NULL
                    ORDER BY column_order
                    """,
                    (resolved.table_id, snapshot_id, snapshot_id),
                )
                rows = cur.fetchall()
        return [
            DuckLakeColumn(
                column_id=int(r[0]), column_name=r[1], column_type=r[2],
                column_order=int(r[3]),
                begin_snapshot=int(r[4]),
                end_snapshot=int(r[5]) if r[5] is not None else None,
                initial_default=r[6], default_value=r[7],
                nulls_allowed=bool(r[8]),
            )
            for r in rows
        ]

    # ---- back-compat helpers ------------------------------------------

    def table_data_files(self, ns: list[str], name: str) -> list[str]:
        snap = self.current_ducklake_snapshot(ns, name)
        if snap is None:
            return []
        return [f.file_path for f in self.data_files_at(ns, name, snap)]

    def current_ducklake_snapshot(self, ns: list[str], name: str) -> int | None:
        snaps = self.list_snapshots(ns, name)
        return snaps[-1].snapshot_id if snaps else None

    def table_uuid(self, ns: list[str], name: str) -> str:
        """Return a stable UUID for a table.

        DuckLake stores per-table UUIDs internally; we read from the ducklake
        metadata schema in Postgres via DuckDB's attached postgres catalog.
        Falls back to a deterministic UUID derived from the qualified name.
        """
        import uuid as _uuid

        # Deterministic fallback keyed on catalog + namespace + name. Good enough
        # for the prototype; production would pull the real DuckLake table id.
        key = f"{self.settings.catalog_name}.{ns[0]}.{name}"
        return str(_uuid.uuid5(_uuid.NAMESPACE_URL, key))
