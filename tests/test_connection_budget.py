"""Postgres connections follow active tenants: idle catalogs are closed,
DuckDB attaches use a small reaped pool, read connections are built lazily,
and psycopg pools may shrink to zero."""
from __future__ import annotations

import time

from duckicelake.catalog import DuckLakeCatalog
from duckicelake.registry import CatalogRegistry


class _Ctx:
    def __init__(self):
        self.closed = False

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
