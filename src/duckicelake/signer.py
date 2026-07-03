"""Iceberg REST remote signer — the no-STS credential-vending compensation.

Backends without STS (Hetzner Object Storage) can't mint scoped temporary
credentials, so REST clients instead send every S3 request here to be
SigV4-signed with the proxy's root keys AFTER a per-request governance
check. Root keys never leave the proxy; revocation is immediate (detach a
policy → the next sign call denies); and enforcement is per S3 *method*,
which is finer-grained than a write-capable STS vend.

Protocol: the `s3-signer-open-api.yaml` shapes used by both Java S3FileIO
(activated by `s3.remote-signing-enabled=true` + `s3.signer.uri/endpoint`)
and PyIceberg's FsspecFileIO (activated by `s3.signer=S3V4RestSigner`).
The client disables its own SigV4 and sends the payload unsigned, so we
sign `UNSIGNED-PAYLOAD` and return the auth headers for the client to
attach.

Authorization is STATELESS: re-derived from the governance store + policy
engine on every sign call (bounded by a small per-worker TTL cache).
Chosen over a grants table because the proxy runs multi-worker uvicorn
with no shared in-process state — per-worker grant dicts would be unsound,
and statelessness makes revocation immediate. The signer is the AIRTIGHT
tier: a governance error here denies (fail closed), unlike the cooperative
LoadTable path.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from .auth import scope_allows
from .config import S3Settings, Settings
from .policies import mask_signature

log = logging.getLogger("duckicelake")

READ_METHODS = {"GET", "HEAD"}
WRITE_METHODS = {"PUT", "POST", "DELETE"}

# Headers we must never sign: hop-by-hop, client-stack-rewritten, or the
# client's own (disabled) auth. Content-Length is recomputed by HTTP stacks
# and isn't part of the canonical request anyway.
_UNSIGNABLE = {
    "authorization", "connection", "expect", "accept-encoding",
    "user-agent", "content-length", "transfer-encoding",
}


class S3SignRequest(BaseModel):
    region: str
    uri: str
    method: str
    headers: dict[str, list[str]] = Field(default_factory=dict)
    # Java's S3SignRequest carries extra fields; accepted and ignored.
    properties: dict[str, str] | None = None
    body: str | None = None


class S3SignResponse(BaseModel):
    uri: str
    headers: dict[str, list[str]]


@dataclass(frozen=True)
class SignDecision:
    allowed: bool
    reason: str  # "signed" or a sign_denied_* audit decision string


def parse_s3_uri(uri: str, s3: S3Settings) -> tuple[str, str] | None:
    """Split an S3 REST URI into (bucket, key), accepting both path-style
    (`http://host/bucket/key`) and virtual-hosted (`http://bucket.host/key`)
    forms against the configured endpoint host. Any other netloc → None:
    the signer must never sign requests bound for foreign endpoints (a
    signed request to an attacker-controlled host would leak a valid
    root-key signature)."""
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None
    host = parts.netloc
    endpoint_host = s3.host
    path = parts.path.lstrip("/")
    if host == endpoint_host:
        bucket, _, key = path.partition("/")
        if not bucket:
            return None
        return bucket, key
    if host.endswith(f".{endpoint_host}"):
        bucket = host[: -len(endpoint_host) - 1]
        return bucket, path
    return None


# ---- per-worker plan cache -------------------------------------------------

_plan_cache: dict[tuple, tuple[float, object]] = {}


def _cached_plan(ctx, settings: Settings, sub: str, roles: list[str],
                 schema: str, table: str):
    """policy_engine.plan_for with a TTL cache. The cache bounds PG load
    under ranged-GET storms and equally bounds revocation staleness
    (settings.signer_cache_ttl seconds). Errors are NOT cached — a failing
    governance store keeps failing closed per request."""
    key = (id(ctx), sub, tuple(roles), schema, table)
    now = time.monotonic()
    hit = _plan_cache.get(key)
    if hit is not None and hit[0] > now:
        return hit[1]
    plan = ctx.policy_engine.plan_for(
        principal=sub, roles=roles, schema=schema, table=table)
    if len(_plan_cache) > 4096:  # bound worker memory under principal churn
        _plan_cache.clear()
    _plan_cache[key] = (now + settings.signer_cache_ttl, plan)
    return plan


def _split_table_key(rel: str) -> tuple[str, str] | None:
    """`{ns}/{table}/...` → (ns, table); None when the key is too shallow
    to belong to a table tree."""
    parts = rel.split("/")
    if len(parts) < 3:  # ns / table / at-least-a-filename
        return None
    return parts[0], parts[1]


def authorize_sign(ctx, settings: Settings, claims: dict,
                   method: str, bucket: str, key: str) -> SignDecision:
    """Decide whether the proxy will sign `method` on s3://{bucket}/{key}
    for the principal in `claims`.

    Mirrors the scoping an STS session policy would have encoded — table
    prefix allows, masked-sig-prefix reads for file-layer-masked
    principals, base-prefix denies — but enforced per request. Fail
    CLOSED on any governance error: the signer is the airtight tier.
    """
    method = method.upper()
    if method not in READ_METHODS | WRITE_METHODS:
        return SignDecision(False, "sign_denied_method")
    if bucket != settings.s3.bucket:
        return SignDecision(False, "sign_denied_bucket")
    dp = ctx.ref.data_prefix
    if not key.startswith(dp):
        return SignDecision(False, "sign_denied_prefix")
    rel = key[len(dp):]

    sub = claims.get("sub") or "anonymous"
    # Scope claim: only enforced when auth is on (claims carry a scope).
    # With auth off there is no token to scope — same posture as the REST
    # routes, where the middleware is a no-op.
    scope = claims.get("scope") or "*:*:*"

    def _roles() -> list[str]:
        # Same union as the LoadTable path: JWT roles claim + sidecar grants.
        return sorted(
            set(claims.get("roles") or [])
            | set(ctx.store.roles_for_principal(sub)))

    if rel.startswith("__masked__/"):
        # Masked export tree: `__masked__/{ns}/{table}/{sig}/...`. Readable
        # ONLY by principals whose current plan is file-layer and whose
        # mask signature matches this subtree; never writable through the
        # signer (exports are proxy-written).
        if method not in READ_METHODS:
            return SignDecision(False, "sign_denied_masked_write")
        parts = rel.split("/")
        if len(parts) < 5:
            return SignDecision(False, "sign_denied_masked_path")
        m_ns, m_table, m_sig = parts[1], parts[2], parts[3]
        try:
            plan = _cached_plan(ctx, settings, sub, _roles(), m_ns, m_table)
        except Exception:
            log.exception("signer governance lookup failed for %s.%s",
                          m_ns, m_table)
            return SignDecision(False, "sign_denied_governance_error")
        if not (plan.file_layer and mask_signature(plan) == m_sig):
            return SignDecision(False, "sign_denied_masked_scope")
        if not scope_allows(scope, m_ns, "GET"):
            return SignDecision(False, "sign_denied_token_scope")
        return SignDecision(True, "signed")

    split = _split_table_key(rel)
    if split is None:
        return SignDecision(False, "sign_denied_path")
    t_ns, t_table = split
    try:
        plan = _cached_plan(ctx, settings, sub, _roles(), t_ns, t_table)
    except Exception:
        log.exception("signer governance lookup failed for %s.%s",
                      t_ns, t_table)
        return SignDecision(False, "sign_denied_governance_error")
    if plan.file_layer and not plan.is_empty():
        # File-layer-masked principal must never touch base bytes — their
        # reads belong under __masked__/ (shadow metadata points them there).
        return SignDecision(False, "sign_denied_file_layer_base")
    # Per-REQUEST method granularity: reads need a read-capable scope,
    # writes a write-capable one ("POST" maps to cap 'w' in scope_allows).
    http_equiv = "GET" if method in READ_METHODS else "POST"
    if not scope_allows(scope, t_ns, http_equiv):
        return SignDecision(False, "sign_denied_token_scope")
    return SignDecision(True, "signed")


def sign_v4(s3: S3Settings, method: str, uri: str,
            headers: dict[str, list[str]]) -> S3SignResponse:
    """SigV4-sign the request with the proxy's root keys and return the
    auth headers for the client to attach. Payload is signed as
    UNSIGNED-PAYLOAD — remote-signing clients disable their own SigV4 and
    never send us the body (forced explicitly: botocore's https-only
    payload heuristic must not decide this on http dev stacks)."""
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    class _UnsignedPayloadAuth(S3SigV4Auth):
        # The client signs nothing and we never see its body, so the
        # canonical request MUST carry UNSIGNED-PAYLOAD. The base class
        # would hash the (empty) body for http:// URLs — a signature that
        # breaks the moment the client attaches a real PUT body.
        def payload(self, request):  # noqa: D102
            return "UNSIGNED-PAYLOAD"

    flat: dict[str, str] = {}
    for k, values in headers.items():
        lk = k.lower()
        if lk in _UNSIGNABLE or lk.startswith("x-forwarded-"):
            continue
        # Keep host, content-type/md5, range, and EVERY x-amz-* header —
        # Ceph RGW (Hetzner) requires all x-amz-* request headers signed.
        flat[k] = ", ".join(values)
    if "host" not in {k.lower() for k in flat}:
        flat["Host"] = urlsplit(uri).netloc

    req = AWSRequest(method=method.upper(), url=uri, headers=flat)
    # Sign with the SERVER's configured region, not the client-sent one:
    # the SigV4 credential scope must match what the backend expects even
    # when clients carry region="auto" (Hetzner) or a placeholder.
    creds = Credentials(s3.root_access_key, s3.root_secret_key)
    _UnsignedPayloadAuth(creds, "s3", s3.region).add_auth(req)
    return S3SignResponse(
        uri=uri,
        headers={k: [v] for k, v in req.headers.items()},
    )
