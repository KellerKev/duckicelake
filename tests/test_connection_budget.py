"""Postgres connections follow active tenants: idle catalogs are closed,
DuckDB attaches use a small reaped pool, read connections are built lazily,
and psycopg pools may shrink to zero."""
from __future__ import annotations

import time

from duckicelake.catalog import DuckLakeCatalog
from duckicelake.registry import _REQUEST_LEASES, CatalogRegistry


class _Ctx:
    def __init__(self, cid="x"):
        self.closed = False
        self.catalog_id = cid
        self._leases = 0
        self._retired = False

    def close(self):
        self.closed = True

    def connect(self):
        return self


def test_idle_catalogs_are_closed_but_never_the_default(settings, monkeypatch):
    reg = CatalogRegistry(settings, max_active=32)
    reg._idle_s = 60
    default, idle, busy = _Ctx(), _Ctx(), _Ctx()
    old = time.monotonic() - 3600
    reg._ctxs.update({settings.catalog_name: default, "idle": idle, "busy": busy})
    reg._last_used.update({settings.catalog_name: old, "idle": old,
                           "busy": time.monotonic()})
    with reg._lock:
        reg._evict_idle_locked()
    assert idle.closed and "idle" not in reg._ctxs and "idle" not in reg._last_used
    assert not busy.closed and not default.closed
    reg._idle_s = 0                     # disabled
    reg._last_used["busy"] = old
    with reg._lock:
        reg._evict_idle_locked()
    assert not busy.closed


def test_duckdb_attach_pool_is_small_and_reaped(settings):
    cat = DuckLakeCatalog(settings)
    conn = cat._build_duckdb_conn()
    try:
        def setting(name):
            return conn.execute("SELECT current_setting(?)", [name]).fetchone()[0]
        assert int(setting("pg_pool_max_connections")) == cat._DUCKDB_PG_POOL_MAX
        assert setting("pg_pool_enable_thread_local_cache") in (False, "false")
        assert int(setting("pg_pool_idle_timeout_millis")) == cat._DUCKDB_PG_IDLE_MS
    finally:
        conn.close()


def test_read_connections_are_lazy(settings):
    cat = DuckLakeCatalog(settings)
    cat.connect()
    try:
        slots = list(cat._read_conns.queue)
        assert slots and all(c is None for c in slots)
        with cat.read_cursor() as c:
            assert c.execute("SELECT 1").fetchone() == (1,)
        assert sum(c is not None for c in cat._read_conns.queue) == 1
        assert cat._pg_pool.min_size == cat._PG_POOL_MIN
    finally:
        cat.close()


def test_evicting_a_leased_catalog_defers_the_close(settings):
    """A request still holding a catalog keeps its connections open through
    an eviction; the last release closes it, and a re-get meanwhile reuses
    the same context instead of attaching twice."""
    reg = CatalogRegistry(settings, max_active=32)
    ctx = _Ctx("t1")
    reg._ctxs["t1"] = ctx
    reg._last_used["t1"] = time.monotonic()
    held: list = []
    token = _REQUEST_LEASES.set(held)
    try:
        assert reg.get("t1") is ctx
    finally:
        _REQUEST_LEASES.reset(token)
    assert ctx._leases == 1 and held == [(reg, ctx)]

    with reg._lock:
        reg._close_locked("t1")             # evicted mid-request
    assert not ctx.closed and "t1" not in reg._ctxs

    assert reg.get("t1") is ctx             # revived, not re-attached
    assert reg._ctxs["t1"] is ctx and not ctx._retired
    with reg._lock:
        reg._close_locked("t1")
    reg.release(ctx)
    assert ctx.closed and ctx._leases == 0 and "t1" not in reg._retired


def test_unleased_catalog_closes_at_once(settings):
    reg = CatalogRegistry(settings, max_active=32)
    ctx = _Ctx("t2")
    reg._ctxs["t2"] = ctx
    reg._last_used["t2"] = time.monotonic()
    assert reg.get("t2") is ctx and ctx._leases == 0   # no request scope
    with reg._lock:
        reg._close_locked("t2")
    assert ctx.closed


def test_new_ducklake_catalogs_are_pinned_to_spec_1_0(settings):
    """DuckDB 2.0 would create spec-1.1 catalogs that DuckDB 1.x clients
    cannot read; the server pins what it creates (a no-op on 1.x)."""
    import duckdb
    from duckicelake.catalog import pin_ducklake_spec
    conn = duckdb.connect()
    try:
        conn.execute("LOAD ducklake")
        pin_ducklake_spec(conn, "1.0")
        if duckdb.__version__.startswith("1."):
            return
        assert conn.execute(
            "SELECT current_setting('ducklake_default_version')").fetchone()[0] == "1.0"
    finally:
        conn.close()
