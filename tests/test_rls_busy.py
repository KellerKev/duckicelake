"""The vend path's RLS DDL must not queue behind an open transaction on the
catalog's metadata tables (any reader/writer session holding one would
otherwise stall the vend, and every query behind the DDL's lock request).
When RLS is already in place, the vend proceeds and the DDL is retried."""
from __future__ import annotations

import time

import psycopg

from duckicelake import pg_rls
from duckicelake.catalog import DuckLakeCatalog


def test_busy_tables_do_not_stall_an_armed_catalog(client, settings):
    cat = DuckLakeCatalog(settings)
    cat.connect()
    try:
        pg_rls.reset_rls_cache()
        pg_rls.ensure_rls_cached(cat, settings)            # arm (tables free)
        assert pg_rls.rls_fully_armed(cat, settings)
        pg_rls.reset_rls_cache()                           # as after a restart
        with psycopg.connect(settings.pg_dsn) as holder:   # open tx, like a slow client
            holder.execute("SELECT count(*) FROM public.ducklake_table").fetchone()
            t = time.monotonic()
            pg_rls.ensure_rls_cached(cat, settings)
            took = time.monotonic() - t
            assert took < pg_rls.RLS_DDL_LOCK_TIMEOUT_MS / 1000 + 5
            assert "public" in pg_rls._FULL_ARM_PENDING
        # tables free again: the next recheck completes the full arm
        pg_rls.ensure_rls_cached(cat, settings, recheck_every=0)
        assert "public" not in pg_rls._FULL_ARM_PENDING
    finally:
        pg_rls.reset_rls_cache()
        cat.close()
