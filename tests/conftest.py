"""pytest fixtures: spin up Postgres + MinIO + proxy once per session.

Each test runs against a clean namespace (`public` schema wiped + bucket
purged + catalog bootstrapped) so tests don't interfere. The proxy is
started via uvicorn as a subprocess — same path as `pixi run serve`.
"""
from __future__ import annotations

import os
import signal
import subprocess
import time

from duckicelake import s3util
import httpx
import psycopg
import pytest

from duckicelake.config import load_settings


# Disable the vend credential cache for the whole suite (proxy subprocess
# inherits this env): tests assert fresh per-vend state — an independent reader
# role each vend, and a current mask signature immediately after a schema change
# — which the 30s cache would otherwise serve stale. Set before load_settings /
# the proxy boots so the server reads it.
os.environ.setdefault("DUCKICELAKE_CRED_CACHE_TTL", "0")

# Isolation from any live deployment sharing this Postgres cluster / bucket.
# The suite wipes the `public` schema and purges S3 objects, so it may only
# ever touch a `*_test` database and keys under TEST_S3_ROOT. Defaults are set
# before the config file is read (real env > these > duckicelake.toml), and
# _assert_isolated refuses to run — before any wipe — if something overrode
# them to point at live state. Tenant-catalog tests root their data prefixes
# under TEST_S3_ROOT too, so one prefix-scoped purge covers everything.
TEST_S3_ROOT = "duckicelake-test/"
os.environ.setdefault("DUCKICELAKE_PG_DATABASE", "ducklake_test")
os.environ.setdefault("DUCKICELAKE_S3_PREFIX", f"{TEST_S3_ROOT}data/")


REPO = os.path.dirname(os.path.dirname(__file__))
PROXY_URL = "http://127.0.0.1:18181"     # distinct from the demo's 8181
PROXY_PORT = 18181

# Enable the S3 gateway on the main test proxy, pointed at itself. On a no-STS
# backend this is the credential tier the vend hands DuckLake-direct clients, so
# credential-dependent tests exercise it end-to-end instead of skipping. On an
# STS backend the gateway branch is dormant (the vend takes the STS path), so
# this is a no-op there. The static-key tier is tested by a separate gateway-off
# proxy (signing_proxy in test_remote_signing.py).
GATEWAY_SECRET = "integration-suite-gateway-secret"

# The baseline the suite is written against — auth off (auth tests patch it on
# per test), no OAuth clients, the gateway pointed at the test proxy — so a box
# whose duckicelake.toml is a live config still runs the suite as written.
for _k, _v in {
    "DUCKICELAKE_REQUIRE_AUTH": "0",
    "DUCKICELAKE_OAUTH_CLIENTS": "",
    "DUCKICELAKE_OAUTH_CLIENTS_FILE": "",
    "DUCKICELAKE_S3_GATEWAY_ENABLED": "1",
    "DUCKICELAKE_S3_GATEWAY_SECRET": GATEWAY_SECRET,
    "DUCKICELAKE_S3_GATEWAY_URL": PROXY_URL,
}.items():
    os.environ.setdefault(_k, _v)


def _wait_ready(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=2.0)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError(f"proxy did not become ready at {url} within {timeout}s")


def _assert_isolated(settings) -> None:
    db, prefix = settings.pg_database, settings.s3.data_prefix
    if not db.endswith("_test") or not prefix.startswith(TEST_S3_ROOT):
        pytest.exit(
            f"refusing to run: the suite wipes its database and bucket prefix, "
            f"but they point at pg_database={db!r}, s3 prefix={prefix!r}. Tests "
            f"need a '*_test' database and a prefix under {TEST_S3_ROOT!r}.",
            returncode=2,
        )


def _ensure_test_database(settings) -> None:
    """Create the (already guard-checked) `*_test` database if it's missing —
    pg-init only creates the app database."""
    db = settings.pg_database
    with psycopg.connect(settings.pg_dsn, dbname="postgres", autocommit=True) as c:
        if not c.execute("SELECT 1 FROM pg_database WHERE datname = %s", [db]).fetchone():
            c.execute(psycopg.sql.SQL("CREATE DATABASE {}").format(psycopg.sql.Identifier(db)))


def _wipe_postgres(dsn: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as c:
        # Re-checked against the live connection, not the config, so a DSN
        # built some other way still can't wipe a non-test database.
        if not c.info.dbname.endswith("_test"):
            raise RuntimeError(f"refusing to wipe non-test database {c.info.dbname!r}")
        with c.cursor() as cur:
            # Every user schema, not just public: tenant-catalog metadata
            # schemas (dl_*) would otherwise carry a stale DATA_PATH into the
            # next run.
            cur.execute(
                "SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg\\_%' "
                "AND nspname <> 'information_schema'"
            )
            for (schema,) in cur.fetchall():
                cur.execute(psycopg.sql.SQL("DROP SCHEMA {} CASCADE").format(
                    psycopg.sql.Identifier(schema)))
            cur.execute("CREATE SCHEMA public")
    # the wipe drops the governance sidecars — forget the process-level
    # "already ensured" flag so the next call re-creates them
    from duckicelake.governance import reset_sidecar_cache
    reset_sidecar_cache()


def _purge_bucket(s3) -> None:
    """Delete the suite's own objects — everything under TEST_S3_ROOT and
    nothing else in the (possibly shared) bucket."""
    if not s3.data_prefix.startswith(TEST_S3_ROOT):
        raise RuntimeError(f"refusing to purge non-test prefix {s3.data_prefix!r}")
    c = s3util.s3_client(s3)
    for p in c.get_paginator("list_objects_v2").paginate(
        Bucket=s3.bucket, Prefix=TEST_S3_ROOT
    ):
        for o in p.get("Contents", []):
            c.delete_object(Bucket=s3.bucket, Key=o["Key"])


@pytest.fixture(scope="session")
def settings():
    s = load_settings()
    _assert_isolated(s)
    return s


@pytest.fixture(scope="session")
def s3_settings(settings):
    return settings.s3


@pytest.fixture(scope="session", autouse=True)
def _proxy(settings):
    """Session-scoped proxy subprocess. Assumes pixi-managed Postgres +
    MinIO are already running (the CI workflow starts them before pytest)."""
    # Clean state before the proxy boots so it sees a fresh catalog.
    _ensure_test_database(settings)
    _wipe_postgres(settings.pg_dsn)
    _purge_bucket(settings.s3)
    # Bootstrap the default namespace via the same entry point as
    # `pixi run ducklake-init`.
    subprocess.run(
        ["python", "-m", "duckicelake.bootstrap"],
        check=True, capture_output=True, cwd=REPO,
    )
    proc = subprocess.Popen(
        [
            "uvicorn", "duckicelake.server:app",
            "--host", "127.0.0.1", "--port", str(PROXY_PORT),
            "--log-level", "warning",
        ],
        cwd=REPO,
        env=dict(
            os.environ,
            DUCKICELAKE_S3_GATEWAY_ENABLED="1",
            DUCKICELAKE_S3_GATEWAY_SECRET=GATEWAY_SECRET,
            DUCKICELAKE_S3_GATEWAY_URL=PROXY_URL,
        ),
    )
    try:
        _wait_ready(f"{PROXY_URL}/healthz")
        yield proc
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def clean_catalog(settings):
    """Function-scoped clean-slate: wipe Postgres + bucket, then
    bootstrap default namespace. Each test that needs a virgin catalog
    can depend on this fixture."""
    _wipe_postgres(settings.pg_dsn)
    _purge_bucket(settings.s3)
    subprocess.run(
        ["python", "-m", "duckicelake.bootstrap"],
        check=True, capture_output=True, cwd=REPO,
    )
    # The proxy process holds DuckDB/PG connections + an in-process
    # metadata cache that's now stale. Restart is the simplest reset —
    # but too heavy for per-test; instead we rely on unique namespace
    # names per test. Use this fixture only for tests that specifically
    # need a bare catalog.
    yield


@pytest.fixture
def client():
    with httpx.Client(base_url=PROXY_URL, timeout=30.0) as c:
        yield c


# Whether the configured backend has STS. The integration suite assumes an
# STS-capable main backend (MinIO/AWS) for its credential-vending assertions;
# on a no-STS backend (Hetzner) the proxy vends no session tokens, so those
# tests can't run. Such tests are marked `requires_sts` and skip there — the
# no-STS credential story (remote signing, the S3 gateway, static keys) is
# covered by its own unit/integration tests.
_SETTINGS = load_settings()
_assert_isolated(_SETTINGS)
STS_DISABLED = _SETTINGS.s3.sts_disabled

requires_sts = pytest.mark.skipif(
    STS_DISABLED,
    reason="requires an STS-capable S3 backend that vends session credentials; "
           "no-STS backends use remote signing / the S3 gateway instead",
)
