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


REPO = os.path.dirname(os.path.dirname(__file__))
PROXY_URL = "http://127.0.0.1:18181"     # distinct from the demo's 8181
PROXY_PORT = 18181


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


def _wipe_postgres(dsn: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as c:
        with c.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
            cur.execute("CREATE SCHEMA public")
    # the wipe drops the governance sidecars — forget the process-level
    # "already ensured" flag so the next call re-creates them
    from duckicelake.governance import reset_sidecar_cache
    reset_sidecar_cache()


def _purge_bucket(s3) -> None:
    c = s3util.s3_client(s3)
    for p in c.get_paginator("list_objects_v2").paginate(Bucket=s3.bucket):
        for o in p.get("Contents", []):
            c.delete_object(Bucket=s3.bucket, Key=o["Key"])


@pytest.fixture(scope="session")
def settings():
    return load_settings()


@pytest.fixture(scope="session")
def s3_settings(settings):
    return settings.s3


@pytest.fixture(scope="session", autouse=True)
def _proxy(settings):
    """Session-scoped proxy subprocess. Assumes pixi-managed Postgres +
    MinIO are already running (the CI workflow starts them before pytest)."""
    # Clean state before the proxy boots so it sees a fresh catalog.
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
STS_DISABLED = load_settings().s3.sts_disabled

requires_sts = pytest.mark.skipif(
    STS_DISABLED,
    reason="requires an STS-capable S3 backend that vends session credentials; "
           "no-STS backends use remote signing / the S3 gateway instead",
)
