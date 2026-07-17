"""S3 gateway — the no-STS "our-own" short-lived credential tier.

Backends without STS (Hetzner Object Storage) can't mint scoped temporary
credentials. REST/Iceberg clients are compensated by the remote signer
(`signer.py`); DuckLake-direct DuckDB clients historically fell back to a
long-lived static key + a coarse bucket policy. This module is the third
tier: the DuckLake-direct equivalent of the signer's airtight guarantees,
without any STS.

How it works:
  * We mint a short-lived S3 credential WE control. The access-key-id packs
    the caller's claims (`sub`, `scope`, `roles`, catalog, `exp`); the
    secret is `HMAC(gateway_secret, access-key-id)`. Both are STATELESS —
    nothing is stored, and a tampered key id yields a different required
    secret the caller can't compute, so forgery fails at SigV4 verification.
  * DuckDB points its httpfs `s3.endpoint` at this proxy (path-style) and
    signs each request with the minted credential.
  * The gateway VERIFIES the caller's SigV4 against the derived secret,
    applies the SAME per-request governance as the signer
    (`signer.authorize_sign`, fail-closed), RE-SIGNS with the backend root
    key (`signer.sign_v4`), and forwards the request to the real backend.

Properties: short-lived (`exp`), scoped (governance per request), live-
revocable (each request re-plans via `authorize_sign` → `_cached_plan`),
and the root key never leaves the proxy. The credential is bearer-grade
(anyone holding it can use it until `exp`), exactly like an STS session
token — the point is that it EXPIRES and is GOVERNED, unlike a static key.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import Response, StreamingResponse

from . import signer as signer_mod
from .config import Settings
from .observability import S3_SIGN_TOTAL

log = logging.getLogger("duckicelake")

# Credential id marker. base64url (alphabet `A-Za-z0-9-_`) never contains
# `/`, so the whole id is safe inside a SigV4 `Credential=<id>/date/...`
# scope. Kept short + unmistakable so verification can reject foreign keys
# (real STS/static keys, junk) before doing any crypto.
_PREFIX = "DLGW_"

# Hop-by-hop / framing response headers we must not copy verbatim when
# relaying the backend's response — the ASGI server owns these.
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}

# Top-level path segments that are real proxy routes, never S3 buckets.
# The explicit routes win in Starlette (registered first), but guard anyway.
_RESERVED_BUCKETS = {
    "v1", "docs", "redoc", "openapi.json", "healthz", "readyz", "metrics",
}


# ---- stateless credential mint / verify ------------------------------------

def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _derive_secret(secret_key: bytes, access_key_id: str) -> str:
    """The credential's secret = HMAC(gateway_secret, access-key-id). Only
    the proxy (holding `gateway_secret`) can compute it, which is what binds
    the packed claims: a caller who edits the key id to widen `scope` can't
    derive the matching secret, so their SigV4 won't verify."""
    mac = hmac.new(secret_key, access_key_id.encode("utf-8"), hashlib.sha256)
    return _b64u_encode(mac.digest())


def mint_credentials(settings: Settings, *, sub: str, scope: str,
                     roles: list[str], catalog_id: str,
                     read_prefixes: list[str] | None = None,
                     deny_prefixes: list[str] | None = None,
                     now: int | None = None) -> dict:
    """Mint a short-lived, scoped credential. Returns the `access-key-id`,
    `secret-access-key`, and `expiration` (ISO) to hand a DuckLake-direct
    client verbatim, plus the packed `claims` (for callers/tests).

    `read_prefixes` / `deny_prefixes` bake per-vend, least-privilege object
    scoping into the credential (the STS session-policy equivalent): the
    gateway serves keys under a read prefix and refuses any under a deny
    prefix, on top of the per-request governance. Omitted → unscoped (the
    caller's scope + governance are still enforced)."""
    if not settings.s3_gateway_secret:
        raise RuntimeError("s3 gateway secret is not configured")
    now = int(time.time() if now is None else now)
    exp = now + settings.s3_gateway_ttl
    claims = {
        "sub": sub,
        "scope": scope or "*:*:*",
        "roles": sorted(roles or []),
        "cat": catalog_id,
        "exp": exp,
    }
    # Only pack scoping keys when set — keeps the unscoped key id compact.
    if read_prefixes:
        claims["pfx"] = list(read_prefixes)
    if deny_prefixes:
        claims["deny"] = list(deny_prefixes)
    payload = _b64u_encode(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    access_key_id = _PREFIX + payload
    secret = _derive_secret(settings.s3_gateway_secret, access_key_id)
    return {
        "access_key_id": access_key_id,
        "secret_access_key": secret,
        "expiration_iso": datetime.fromtimestamp(exp, timezone.utc).isoformat(),
        "claims": claims,
    }


def is_gateway_key(access_key_id: str) -> bool:
    return access_key_id.startswith(_PREFIX)


def parse_credential(access_key_id: str) -> dict | None:
    """Decode packed claims from a gateway access-key-id. None when the id
    isn't ours or is malformed — the caller must then reject (never sign)."""
    if not access_key_id.startswith(_PREFIX):
        return None
    try:
        claims = json.loads(_b64u_decode(access_key_id[len(_PREFIX):]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(claims, dict) or "exp" not in claims:
        return None
    return claims


def _parse_authorization(header: str) -> tuple[str, str, list[str], str]:
    """Parse an AWS SigV4 `Authorization` header into
    (access_key_id, region, signed_headers, signature). Raises 403 on any
    shape we don't recognise."""
    prefix = "AWS4-HMAC-SHA256 "
    if not header.startswith(prefix):
        raise HTTPException(status_code=403, detail="unsupported authorization")
    fields: dict[str, str] = {}
    for part in header[len(prefix):].split(","):
        key, _, value = part.strip().partition("=")
        if key:
            fields[key] = value
    cred = fields.get("Credential", "")
    segs = cred.split("/")
    # <access-key-id>/<date>/<region>/<service>/aws4_request
    if len(segs) < 5 or segs[3] != "s3":
        raise HTTPException(status_code=403, detail="bad credential scope")
    signed = [h for h in fields.get("SignedHeaders", "").split(";") if h]
    sig = fields.get("Signature", "")
    if not signed or not sig:
        raise HTTPException(status_code=403, detail="missing signature")
    return segs[0], segs[2], signed, sig


def verify_sigv4(settings: Settings, *, method: str, host: str,
                 decoded_path: str, raw_query: str,
                 headers: dict[str, str], now: int | None = None) -> dict:
    """Verify the caller's SigV4 against the secret derived from the
    presented gateway access-key-id, and return the packed claims. Raises
    403 on a foreign/expired credential or a bad signature.

    Canonicalisation is delegated to botocore's own `S3SigV4Auth` so it is
    bit-for-bit what a botocore/DuckDB client produced when signing —
    reusing the reference implementation rather than re-deriving the spec.
    """
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    auth_header = headers.get("authorization")
    if not auth_header:
        raise HTTPException(status_code=403, detail="unsigned request")
    access_key_id, region, signed_headers, provided_sig = \
        _parse_authorization(auth_header)

    claims = parse_credential(access_key_id)
    if claims is None:
        raise HTTPException(status_code=403, detail="not a gateway credential")
    now = int(time.time() if now is None else now)
    if now >= int(claims.get("exp", 0)):
        raise HTTPException(status_code=403, detail="credential expired")

    amz_date = headers.get("x-amz-date")
    if not amz_date:
        raise HTTPException(status_code=403, detail="missing x-amz-date")

    secret = _derive_secret(settings.s3_gateway_secret, access_key_id)

    # Rebuild exactly what the client signed: only the SignedHeaders it
    # declared, its decoded path (botocore re-quotes) and raw query, its
    # timestamp. Any extra header would perturb the canonical request and
    # fail the compare — which is the point.
    signed_set = set(signed_headers)
    flat: dict[str, str] = {
        name: value for name, value in headers.items()
        if name.lower() in signed_set
    }
    if "host" not in {k.lower() for k in flat}:
        flat["Host"] = host
    url = f"http://{host}{decoded_path}"
    if raw_query:
        url += "?" + raw_query
    req = AWSRequest(method=method.upper(), url=url, headers=flat)
    req.context["timestamp"] = amz_date
    signer = S3SigV4Auth(Credentials(access_key_id, secret), "s3", region)
    canonical = signer.canonical_request(req)
    computed = signer.signature(signer.string_to_sign(req, canonical), req)
    if not hmac.compare_digest(computed, provided_sig):
        raise HTTPException(status_code=403, detail="signature mismatch")
    return claims


# ---- data plane ------------------------------------------------------------

def _relay_response_headers(backend: httpx.Response) -> dict[str, str]:
    return {
        k: v for k, v in backend.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }


def authorize_prefix(claims: dict, key: str) -> str | None:
    """Enforce the credential's per-vend object scoping (the STS session-policy
    equivalent): the key must sit under a `pfx` (read prefix) and under no
    `deny` prefix. Returns a denial reason, or None when allowed / unscoped."""
    for d in claims.get("deny") or []:
        if key.startswith(d):
            return "gateway_denied_prefix"
    pfx = claims.get("pfx")
    if pfx and not any(key.startswith(p) for p in pfx):
        return "gateway_denied_prefix"
    return None


def _s3_error(code: str, message: str, status: int = 403) -> Response:
    """An S3-style XML error so boto3/DuckDB surface a normal ClientError
    (e.g. AccessDenied) instead of choking on a JSON body."""
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f"<Error><Code>{code}</Code><Message>{message}</Message></Error>"
    )
    return Response(content=body, status_code=status, media_type="application/xml")


def register_gateway_routes(app, settings: Settings, registry, auth_cfg) -> None:
    """Mount the S3 data-plane routes on the existing app. No-op unless the
    gateway is enabled. Routes ride the same uvicorn/socat exposure as the
    catalog API; path-style S3 keys (`/{bucket}/{key}`) never collide with
    the `/v1/*` catalog routes (different first segment)."""
    if not settings.s3_gateway_enabled:
        return

    def _resolve_ctx(claims: dict, key: str):
        """The catalog context to govern against. Prefer the credential's
        own `cat` claim (we minted it); fall back to a longest-data-prefix
        match, then the default catalog — mirroring the bare signer route."""
        cat = claims.get("cat")
        if cat:
            try:
                return registry.get(cat)
            except Exception:
                log.warning("gateway cred names unknown catalog %r", cat)
        target = registry.settings.catalog_name
        best = ""
        for cid, ref in registry.list_refs():
            if ref.data_prefix and key.startswith(ref.data_prefix) \
                    and len(ref.data_prefix) > len(best):
                best, target = ref.data_prefix, cid
        return registry.get(target)

    def _deny(ctx, claims: dict, bucket: str, key: str, method: str,
              reason: str) -> Response:
        S3_SIGN_TOTAL.labels(decision=reason).inc()
        try:
            ctx.store.audit_load(
                principal=claims.get("sub") or "anonymous",
                object_=f"s3://{bucket}/{key}", masked_cols=[],
                applied_policies=[], row_filtered=False,
                operation="s3_gateway", decision=reason,
                detail={"method": method})
        except Exception:
            log.exception("audit of gateway denial failed")
        return _s3_error("AccessDenied", f"gateway denied: {reason}")

    async def _handle(request: Request, bucket: str, key: str) -> Response:
        method = request.method.upper()
        host = request.headers.get("host", "")
        raw_query = request.url.query
        # 1) Verify our SigV4 (identity + expiry + integrity). Surface a
        #    verification failure as an S3 error so boto3/DuckDB clients see a
        #    normal ClientError, not a JSON body.
        try:
            claims = verify_sigv4(
                settings, method=method, host=host,
                decoded_path=request.url.path, raw_query=raw_query,
                headers={k.lower(): v for k, v in request.headers.items()})
        except HTTPException as e:
            S3_SIGN_TOTAL.labels(decision="gateway_denied_verify").inc()
            return _s3_error("AccessDenied", str(e.detail), e.status_code)

        # 2) Governance — the exact per-request decision the signer makes —
        #    then the credential's per-vend prefix scoping. Bucket-level LIST
        #    (empty key) authorizes against its `prefix` query param.
        ctx = _resolve_ctx(claims, key)
        authz_key = key
        if not authz_key:
            authz_key = request.query_params.get("prefix", "")
        decision = signer_mod.authorize_sign(
            ctx, settings, claims, method, bucket, authz_key)
        if not decision.allowed:
            return _deny(ctx, claims, bucket, authz_key, method, decision.reason)
        pfx_reason = authorize_prefix(claims, authz_key)
        if pfx_reason:
            return _deny(ctx, claims, bucket, authz_key, method, pfx_reason)
        S3_SIGN_TOTAL.labels(decision="gateway_forward").inc()

        # 3) Re-sign with the backend ROOT key and forward.
        s3 = settings.s3
        real_uri = f"{s3.endpoint}/{bucket}"
        if key:
            real_uri += f"/{key}"
        if raw_query:
            real_uri += f"?{raw_query}"
        # Forward the client's headers (Host rewritten to the backend, our
        # Authorization dropped by sign_v4's _UNSIGNABLE filter). Preserve
        # x-amz-content-sha256/range verbatim so the re-signature covers
        # exactly what we send.
        fwd: dict[str, list[str]] = {}
        for name, value in request.headers.items():
            ln = name.lower()
            if ln in ("host", "authorization"):
                continue
            fwd.setdefault(name, []).append(value)
        fwd["Host"] = [s3.host]
        signed = signer_mod.sign_v4(s3, method, real_uri, fwd)
        out_headers = {k: ", ".join(v) for k, v in signed.headers.items()}

        body = await request.body()  # reads have none; bounded for writes
        client = httpx.AsyncClient(timeout=httpx.Timeout(120.0))
        try:
            backend_req = client.build_request(
                method, real_uri, headers=out_headers,
                content=body if body else None)
            backend = await client.send(backend_req, stream=True)
        except Exception:
            await client.aclose()
            log.exception("gateway forward to backend failed")
            raise HTTPException(status_code=502, detail="backend unreachable")

        relay = _relay_response_headers(backend)
        if method == "HEAD":
            # No streamed body on HEAD; close and return headers/status.
            await backend.aclose()
            await client.aclose()
            return Response(status_code=backend.status_code, headers=relay)

        async def _stream():
            try:
                async for chunk in backend.aiter_raw():
                    yield chunk
            finally:
                await backend.aclose()
                await client.aclose()

        return StreamingResponse(
            _stream(), status_code=backend.status_code, headers=relay)

    _methods = ["GET", "HEAD", "PUT", "POST", "DELETE"]

    @app.api_route("/{bucket}/{key:path}", methods=_methods, include_in_schema=False)
    async def s3_gateway_object(bucket: str, key: str, request: Request):
        if bucket in _RESERVED_BUCKETS:
            raise HTTPException(status_code=404, detail="not found")
        return await _handle(request, bucket, key)

    @app.api_route("/{bucket}", methods=_methods, include_in_schema=False)
    async def s3_gateway_bucket(bucket: str, request: Request):
        if bucket in _RESERVED_BUCKETS:
            raise HTTPException(status_code=404, detail="not found")
        return await _handle(request, bucket, "")

    log.info("S3 gateway enabled: DuckLake-direct clients get short-lived "
             "scoped credentials at %s (ttl=%ss)",
             settings.s3_gateway_url, settings.s3_gateway_ttl)
