"""Observability surface: Prometheus metrics + structured JSON logging.

Exposes:
  - `setup_logging()`: installs a JSON formatter on the root + `duckicelake`
    loggers so log lines are structured (timestamp, level, logger, message,
    any `extra={}` fields, plus exception info as a single `exc_info` field).
    Idempotent — safe to call multiple times.

  - Prometheus metric objects (`REQUEST_LATENCY`, `COMMIT_TOTAL`, etc.) and
    the `metrics_middleware()` helper that records per-request latency +
    status codes.

  - `metrics_endpoint()`: the `/metrics` handler. FastAPI app in server.py
    mounts it.

All metric labels are low-cardinality (endpoint template, method, status
class) — no per-table or per-namespace labels, which would explode
cardinality in a multi-tenant catalog.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

from fastapi import Request, Response
from fastapi.responses import PlainTextResponse
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from pythonjsonlogger import jsonlogger


# ---- logging --------------------------------------------------------------

_LOGGING_CONFIGURED = False


def setup_logging() -> None:
    """Install a JSON formatter on the `duckicelake` logger + root handler.

    Idempotent. Controlled by env:
      DUCKICELAKE_LOG_LEVEL   — default INFO
      DUCKICELAKE_LOG_FORMAT  — 'json' (default in prod) or 'text' (dev)
    """
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return
    level = os.environ.get("DUCKICELAKE_LOG_LEVEL", "INFO").upper()
    fmt = os.environ.get("DUCKICELAKE_LOG_FORMAT", "json").lower()
    handler = logging.StreamHandler()
    if fmt == "json":
        # Include exception traces in a structured `exc_info` field
        # rather than a multiline blob, so log aggregators can index it.
        handler.setFormatter(jsonlogger.JsonFormatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            rename_fields={"asctime": "ts", "levelname": "level", "name": "logger"},
        ))
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"
        ))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    logging.getLogger("duckicelake").setLevel(level)
    # Quiet uvicorn's own access log (we record our own via the middleware
    # so a double log line would be noise).
    logging.getLogger("uvicorn.access").handlers = [handler]
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    _LOGGING_CONFIGURED = True


# ---- metrics --------------------------------------------------------------

# Keep label cardinality tight. `endpoint` is the *route template* not the
# path, so `/v1/{prefix}/namespaces/{ns}/tables/{tbl}` stays one timeseries
# regardless of how many tables you have.

REQUEST_LATENCY = Histogram(
    "duckicelake_request_seconds",
    "End-to-end request latency, seconds",
    ["endpoint", "method", "status"],
    buckets=(.005, .01, .025, .05, .1, .25, .5, 1.0, 2.5, 5.0, 10.0),
)

REQUEST_COUNT = Counter(
    "duckicelake_requests_total",
    "Total HTTP requests",
    ["endpoint", "method", "status"],
)

COMMIT_TOTAL = Counter(
    "duckicelake_commit_total",
    "CommitTable calls, by outcome",
    ["outcome"],    # "ok", "error", "conflict"
)

MATERIALIZE_LATENCY = Histogram(
    "duckicelake_materialize_seconds",
    "materialize_all() duration, seconds",
    ["cache"],      # "hit", "miss"
)

CACHE_SIZE = Gauge(
    "duckicelake_metadata_cache_size",
    "In-process metadata cache occupancy",
)

CACHE_HITS = Gauge(
    "duckicelake_metadata_cache_hits_total",
    "In-process metadata cache hits, cumulative",
)

CACHE_MISSES = Gauge(
    "duckicelake_metadata_cache_misses_total",
    "In-process metadata cache misses, cumulative",
)

PG_POOL_IN_USE = Gauge(
    "duckicelake_pg_pool_in_use",
    "Postgres pool connections currently in use",
)

PG_POOL_IDLE = Gauge(
    "duckicelake_pg_pool_idle",
    "Postgres pool connections idle",
)


async def metrics_middleware(request: Request, call_next):
    """FastAPI middleware — records per-request latency + status class.

    Uses the matched route template for `endpoint`; falls back to raw
    path for 404s (which aren't matched).
    """
    t0 = time.perf_counter()
    response: Response = await call_next(request)
    elapsed = time.perf_counter() - t0
    route = request.scope.get("route")
    endpoint = getattr(route, "path", request.url.path)
    status_class = f"{response.status_code // 100}xx"
    REQUEST_LATENCY.labels(endpoint, request.method, status_class).observe(elapsed)
    REQUEST_COUNT.labels(endpoint, request.method, status_class).inc()
    return response


def refresh_pool_gauges(catalog) -> None:
    """Update pool/cache Gauges from the catalog's live state.

    Called lazily from `metrics_endpoint()` since pool stats are a
    point-in-time snapshot, not a counter we increment on every op.
    """
    pool = catalog._pg_pool
    if pool is not None:
        stats = pool.get_stats()
        # psycopg_pool stat keys: pool_size, pool_available, requests_waiting, ...
        PG_POOL_IN_USE.set(
            stats.get("pool_size", 0) - stats.get("pool_available", 0)
        )
        PG_POOL_IDLE.set(stats.get("pool_available", 0))
    cstats = catalog.metadata_cache_stats()
    CACHE_SIZE.set(cstats["size"])
    CACHE_HITS.set(cstats["hits"])
    CACHE_MISSES.set(cstats["misses"])


def metrics_endpoint(catalog) -> PlainTextResponse:
    """FastAPI handler body. Call as `return metrics_endpoint(catalog)`."""
    refresh_pool_gauges(catalog)
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
