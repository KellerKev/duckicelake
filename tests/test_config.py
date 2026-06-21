"""Config: the optional owner-role Postgres password (DUCKICELAKE_PG_PASSWORD).

Pure unit tests — no live backend; they monkeypatch the env var and inspect
the derived DSN / helpers.
"""
from __future__ import annotations

import pytest

from duckicelake.catalog import DuckLakeCatalog
from duckicelake.config import (
    load_settings,
    redact_password,
    validate_pg_password,
)


def test_pg_password_absent_by_default(monkeypatch):
    monkeypatch.delenv("DUCKICELAKE_PG_PASSWORD", raising=False)
    s = load_settings()
    assert s.pg_password is None
    assert "password=" not in s.pg_dsn
    assert "password=" not in s.ducklake_uri


def test_pg_password_blank_is_none(monkeypatch):
    monkeypatch.setenv("DUCKICELAKE_PG_PASSWORD", "")
    s = load_settings()
    assert s.pg_password is None
    assert "password=" not in s.pg_dsn


def test_pg_password_flows_into_dsn(monkeypatch):
    monkeypatch.setenv("DUCKICELAKE_PG_PASSWORD", "s3cret")
    s = load_settings()
    assert s.pg_password == "s3cret"
    # plain (not quoted): the DSN is embedded in a single-quoted DuckDB ATTACH
    # literal, so libpq quoting would break it; the value is conninfo-safe.
    assert "password=s3cret" in s.pg_dsn
    assert s.ducklake_uri == f"ducklake:postgres:{s.pg_dsn}"


def test_pg_password_unsafe_chars_rejected(monkeypatch):
    for bad in ("has space", "quote'd", "back\\slash", 'dquote"x'):
        monkeypatch.setenv("DUCKICELAKE_PG_PASSWORD", bad)
        with pytest.raises(ValueError, match="DUCKICELAKE_PG_PASSWORD"):
            load_settings()
    with pytest.raises(ValueError):
        validate_pg_password("a b")
    validate_pg_password("Aa1-_.:@/+=Safe")   # symbols that are fine → no raise


def test_pg_conninfo_delegates_to_pg_dsn(monkeypatch):
    monkeypatch.setenv("DUCKICELAKE_PG_PASSWORD", "pw123")
    s = load_settings()
    cat = DuckLakeCatalog(s)            # no connect() — just builds the DSN
    assert cat._pg_conninfo() == s.pg_dsn
    assert "password=pw123" in cat._pg_conninfo()


def test_redact_password():
    assert (redact_password("dbname=x user=u password=s3cret")
            == "dbname=x user=u password=***")
    assert (redact_password("dbname=x password=bare host=h")
            == "dbname=x password=*** host=h")
    assert (redact_password("ducklake:postgres:dbname=x user=u password=pw")
            == "ducklake:postgres:dbname=x user=u password=***")
    # nothing to redact
    assert (redact_password("ducklake:postgres:dbname=x user=u")
            == "ducklake:postgres:dbname=x user=u")
