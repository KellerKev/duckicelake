"""HTTP surface for lineage (see lineage.py).

  GET  /v1/{prefix}/lineage?dataset=schema.table[&depth=&direction=]
       dataset-level graph around one table + who touched it (admin)
  GET  /v1/{prefix}/lineage/events[?after_id=&limit=&dataset=&kind=&since=&format=ndjson]
       the raw OpenLineage events, in id order — a cursor for forwarding
       them to another lineage tool; order=desc gives the latest ones
       first instead (admin)
  POST /v1/{prefix}/lineage
       ingest OpenLineage RunEvents (one, a list, or {"events": [...]});
       the OpenLineage HTTP transport works with endpoint=v1/<prefix>/lineage
       (admin or broker; the caller is recorded on every event)
  GET  /v1/{prefix}/lineage/carried-tags
       the tags each table carries from what it was made of, as producers
       reported them in `duckicelake_carriedTags` (admin or broker)

Reads are admin-only like the audit trail: lineage names tables and the
principals that read and wrote them. Each read first harvests the catalog's
latest commits so the answer is current.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Callable

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool

from . import lineage
from .auth import AuthConfig, claims_from_request, is_admin_scope, is_broker_scope


def build_lineage_router(resolve_catalog, auth_cfg: AuthConfig | Callable[[], AuthConfig]
                         ) -> APIRouter:
    router = APIRouter(prefix="/v1/{prefix}/lineage", tags=["lineage"])

    def _cfg() -> AuthConfig:
        return auth_cfg() if callable(auth_cfg) else auth_cfg

    def _claims(request: Request) -> dict:
        cfg = _cfg()
        return claims_from_request(cfg, request) if cfg.enabled else {}

    def _require(request: Request, *, broker_ok: bool = False) -> None:
        cfg = _cfg()
        if not cfg.enabled:
            return
        scope = _claims(request).get("scope", "")
        if is_admin_scope(scope) or (broker_ok and is_broker_scope(scope)):
            return
        raise HTTPException(403, "lineage requires an admin token"
                            + (" or a broker token" if broker_ok else ""))

    def _principal(request: Request) -> str:
        claims = _claims(request)
        qp = request.query_params
        if (str(qp.get("delegate", "")).lower() in ("1", "true", "yes")
                and is_broker_scope(claims.get("scope", "")) and qp.get("principal")):
            return qp["principal"]
        return claims.get("sub") or "anonymous"

    def _fresh(ctx) -> None:
        try:
            lineage.harvest(ctx.catalog)
        except Exception:
            pass      # serve what is stored; the scheduled harvest retries

    @router.get("", status_code=200)
    def get_graph(prefix: str, request: Request, dataset: str, depth: int = 3,
                  direction: str = "both"):
        _require(request)
        ctx = resolve_catalog(prefix, request)
        if direction not in ("both", "upstream", "downstream"):
            raise HTTPException(400, "direction must be both, upstream or downstream")
        _fresh(ctx)
        return lineage.graph(ctx.catalog, dataset, depth=depth, direction=direction)

    @router.get("/events", status_code=200)
    def get_events(prefix: str, request: Request, after_id: int = 0, limit: int = 500,
                   dataset: str | None = None, kind: str | None = None,
                   since: str | None = None, format: str = "json", order: str = "asc"):
        _require(request)
        ctx = resolve_catalog(prefix, request)
        kinds = [k for k in (kind or "").split(",") if k] or None
        if kinds and set(kinds) - set(lineage.KINDS):
            raise HTTPException(400, f"kind must be among {list(lineage.KINDS)}")
        if format not in ("json", "ndjson"):
            raise HTTPException(400, "format must be json or ndjson")
        if order not in ("asc", "desc"):
            raise HTTPException(400, "order must be asc or desc")
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00")) if since else None
        except ValueError:
            raise HTTPException(400, "since must be an ISO-8601 timestamp")
        _fresh(ctx)
        rows = lineage.list_events(ctx.catalog, after_id=max(0, after_id),
                                   limit=max(1, min(limit, 5000)), dataset=dataset,
                                   kinds=kinds, since=since_dt, newest_first=order == "desc")
        if format == "ndjson":
            body = "".join(json.dumps(r["event"]) + "\n" for r in rows)
            headers = {"X-Last-Id": str(max(r["id"] for r in rows))} if rows else {}
            return Response(body, media_type="application/x-ndjson", headers=headers)
        return {"events": rows,
                "last_id": max((r["id"] for r in rows), default=after_id)}

    @router.get("/carried-tags", status_code=200)
    def get_carried_tags(prefix: str, request: Request):
        _require(request, broker_ok=True)
        ctx = resolve_catalog(prefix, request)
        _fresh(ctx)       # a replaced or dropped table must have lost its tags by now
        return {"carried": lineage.carried_tags(ctx.catalog)}

    @router.post("", status_code=201)
    async def post_events(prefix: str, request: Request):
        _require(request, broker_ok=True)
        ctx = resolve_catalog(prefix, request)
        raw = await request.body()
        if len(raw) > lineage.MAX_INGEST_BYTES:
            raise HTTPException(413, f"at most {lineage.MAX_INGEST_BYTES} bytes per request")
        try:
            body = json.loads(raw or b"null")
        except ValueError:
            raise HTTPException(400, "body must be JSON")
        events = body.get("events") if isinstance(body, dict) and "events" in body else body
        events = events if isinstance(events, list) else [events]
        if not events or len(events) > 500:
            raise HTTPException(400, "send 1 to 500 events")
        try:
            events = [lineage.validate_run_event(e) for e in events]
        except lineage.IngestError as e:
            raise HTTPException(400, str(e))
        principal = _principal(request)
        n = await run_in_threadpool(lineage.ingest, ctx.catalog, events, principal=principal)
        return {"accepted": n}

    return router
