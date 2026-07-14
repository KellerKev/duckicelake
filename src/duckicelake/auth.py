"""OAuth2 client-credentials auth for the Iceberg REST catalog.

Iceberg REST spec §3 defines a minimal `POST /v1/oauth/tokens` exchange:
clients send `grant_type=client_credentials&client_id=X&client_secret=Y[&scope=]`
as form-urlencoded and get back `{access_token, token_type=Bearer, expires_in}`.
Subsequent requests include `Authorization: Bearer <token>`.

We issue short-lived HMAC-signed JWTs. A small signing key lives in an env
var (`DUCKICELAKE_OAUTH_JWT_SECRET`); client credentials come from
`DUCKICELAKE_OAUTH_CLIENTS` as a comma-separated list of `id:secret` pairs,
or via a `credentials` json file referenced by
`DUCKICELAKE_OAUTH_CLIENTS_FILE`.

Auth is **opt-in**. If no clients are configured, every request is
allowed — matching the dev default the rest of the stack assumes. Set any
of the env vars above to flip auth on for the whole server.

Two endpoints are always unauthenticated even when auth is enabled:
- `GET /v1/config` — clients use it to discover the OAuth endpoint.
- `POST /v1/oauth/tokens` — the OAuth endpoint itself.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

import jwt  # PyJWT
from fastapi import Form, HTTPException, Request


JWT_ALGORITHM = "HS256"
DEFAULT_TTL_SECONDS = 3600


@dataclass(frozen=True)
class AuthConfig:
    jwt_secret: bytes
    # client_id -> {"secret": str, "scope": str (space-separated caps),
    #               "roles": str (space-separated role names),
    #               "account": str (multi-catalog tenant id, "" = none)}
    # `roles` feeds the governance `roles` JWT claim (Phase 1 governance
    # layer). Empty string = no roles. The policy engine (Phase 2) reads
    # these to decide masking; in Phase 1 they're authored + carried only.
    # `account` feeds the `account` claim — resolve_catalog matches it
    # against a provisioned catalog's account_id (cross-account = 404).
    clients: dict[str, dict[str, str]]
    ttl_seconds: int
    issuer: str                 # "iss" claim — proxy identity

    @property
    def enabled(self) -> bool:
        return bool(self.clients)


# Scope grammar:
#   "ns:<name>:<cap>"    — permission on a specific namespace
#   "ns:*:<cap>"          — permission on all namespaces
#   "ns:<name>:*"         — all caps on a namespace
#   "*:*:*"               — superuser (grants everything)
#   cap ∈ {r, w, rw}       (r → read; w → write; rw → either)
#
# Multiple scopes are space-separated. Missing scope on an authenticated
# request = deny. Anonymous (auth disabled) = allow everything.
READ_ACTIONS = {"GET", "HEAD"}
WRITE_ACTIONS = {"POST", "PUT", "DELETE", "PATCH"}


def _parse_clients_env(raw: str) -> dict[str, dict[str, str]]:
    """Parse `id1:secret1|scope|roles|account,id2:secret2|scope,...` — empty
    entries ignored.

    `scope`, `roles`, and `account` are optional, in that order,
    `|`-delimited so secrets can still contain `:`. Defaults: scope `*:*:*`
    (superuser, for dev), roles empty, account empty. `roles` is a
    space-separated list of governance role names surfaced in the JWT
    `roles` claim; `account` is the multi-catalog tenant id surfaced as the
    `account` claim (matched against a catalog's account_id).
    """
    out: dict[str, dict[str, str]] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        # Split off optional scope + roles + account first.
        scope = "*:*:*"
        roles = ""
        account = ""
        if "|" in pair:
            fields = pair.split("|")
            pair = fields[0]
            if len(fields) >= 2 and fields[1].strip():
                scope = fields[1].strip()
            if len(fields) >= 3:
                roles = fields[2].strip()
            if len(fields) >= 4:
                account = fields[3].strip()
        if ":" not in pair:
            raise ValueError(
                f"DUCKICELAKE_OAUTH_CLIENTS entry missing ':' in {pair!r}"
            )
        cid, csecret = pair.split(":", 1)
        if not cid or not csecret:
            raise ValueError(f"empty id or secret in {pair!r}")
        out[cid] = {"secret": csecret, "scope": scope, "roles": roles,
                    "account": account}
    return out


def _parse_clients_file(path: str) -> dict[str, dict[str, str]]:
    """JSON file mapping client_id -> {"secret": ..., "scope": ..., "roles": ...}.
    Also accepts legacy str values (treated as secret with `*:*:*` scope).

    `roles` may be a list of strings or a single space-separated string;
    both are normalised to a space-separated string.
    """
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object of id->{{secret,scope,roles}}")
    out: dict[str, dict[str, str]] = {}
    for k, v in data.items():
        if not isinstance(k, str):
            raise ValueError(f"{path}: non-string id {k!r}")
        if isinstance(v, str):
            out[k] = {"secret": v, "scope": "*:*:*", "roles": "", "account": ""}
        elif isinstance(v, dict) and "secret" in v:
            raw_roles = v.get("roles", "")
            roles = " ".join(raw_roles) if isinstance(raw_roles, list) else str(raw_roles)
            out[k] = {
                "secret": str(v["secret"]),
                "scope": str(v.get("scope", "*:*:*")),
                "roles": roles.strip(),
                "account": str(v.get("account", "")).strip(),
            }
        else:
            raise ValueError(f"{path}: entry {k!r} must be str or {{secret, scope, roles, account}}")
    return out


def load_auth_config() -> AuthConfig:
    clients: dict[str, dict[str, str]] = {}
    env_clients = os.environ.get("DUCKICELAKE_OAUTH_CLIENTS", "")
    if env_clients:
        clients.update(_parse_clients_env(env_clients))
    file_clients = os.environ.get("DUCKICELAKE_OAUTH_CLIENTS_FILE", "")
    if file_clients:
        clients.update(_parse_clients_file(file_clients))

    # If any clients were declared, require an explicit JWT secret — don't
    # silently generate a per-process one that would let tokens outlive
    # restarts without the operator noticing.
    raw_secret = os.environ.get("DUCKICELAKE_OAUTH_JWT_SECRET", "").strip()
    if clients and not raw_secret:
        raise RuntimeError(
            "DUCKICELAKE_OAUTH_JWT_SECRET must be set when "
            "DUCKICELAKE_OAUTH_CLIENTS* is configured"
        )
    jwt_secret = raw_secret.encode("utf-8") if raw_secret else secrets.token_bytes(32)

    ttl = int(os.environ.get("DUCKICELAKE_OAUTH_TTL_SECONDS", str(DEFAULT_TTL_SECONDS)))
    if ttl <= 0:
        raise ValueError("DUCKICELAKE_OAUTH_TTL_SECONDS must be positive")

    issuer = os.environ.get("DUCKICELAKE_OAUTH_ISSUER", "duckicelake")

    return AuthConfig(
        jwt_secret=jwt_secret,
        clients=clients,
        ttl_seconds=ttl,
        issuer=issuer,
    )


# ---------- endpoint-agnostic helpers --------------------------------

def issue_token(
    cfg: AuthConfig,
    client_id: str,
    scope: str | None = None,
    roles: str | None = None,
    account: str | None = None,
) -> dict:
    now = int(time.time())
    payload: dict[str, object] = {
        "iss": cfg.issuer,
        "sub": client_id,
        "iat": now,
        "exp": now + cfg.ttl_seconds,
    }
    if scope:
        payload["scope"] = scope
    # Governance roles claim (Phase 1). Emitted as a list so the policy
    # engine can index it directly; absent when the client holds no roles.
    if roles:
        payload["roles"] = roles.split()
    # Multi-catalog tenant claim: resolve_catalog matches it against a
    # provisioned catalog's account_id (cross-account access = 404).
    if account:
        payload["account"] = account
    token = jwt.encode(payload, cfg.jwt_secret, algorithm=JWT_ALGORITHM)
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": cfg.ttl_seconds,
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
    }


def verify_bearer(cfg: AuthConfig, authorization_header: str | None) -> dict:
    if not authorization_header or not authorization_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authorization header required (Bearer token)",
        )
    token = authorization_header.split(" ", 1)[1].strip()
    try:
        return jwt.decode(
            token,
            cfg.jwt_secret,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["iat", "exp", "sub", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"invalid token: {e}")


# ---------- FastAPI token endpoint + dependency ---------------------

async def oauth_token_endpoint(
    cfg: AuthConfig,
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: str | None = Form(default=None),
) -> dict:
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=400,
            detail=f"unsupported grant_type: {grant_type}",
        )
    entry = cfg.clients.get(client_id)
    if entry is None or not hmac.compare_digest(entry["secret"], client_secret):
        raise HTTPException(status_code=401, detail="invalid client credentials")
    # If the client requested a scope, intersect with what's allowed.
    # v1 binds the full client scope — refining via
    # intersection would be a follow-up.
    effective_scope = entry.get("scope") or "*:*:*"
    effective_roles = entry.get("roles") or ""
    effective_account = entry.get("account") or ""
    return issue_token(
        cfg, client_id=client_id, scope=effective_scope, roles=effective_roles,
        account=effective_account,
    )


def claims_from_request(cfg: AuthConfig, request: Request) -> dict:
    """Best-effort decode of the caller's claims for attribution/audit.

    When auth is disabled returns an `anonymous` stub so callers always get
    a `sub`. When enabled the bearer middleware has already rejected bad
    tokens before the handler runs, so a decode failure here is unexpected
    and surfaces as 401.
    """
    if not cfg.enabled:
        return {"sub": "anonymous", "scope": "*:*:*", "roles": []}
    claims = verify_bearer(cfg, request.headers.get("authorization"))
    claims.setdefault("roles", [])
    return claims


def make_bearer_dependency(cfg: AuthConfig):
    """Returns a FastAPI dependency that enforces Bearer auth when enabled.

    When auth is disabled (no clients configured), the dependency is a no-op.
    """
    async def _dep(request: Request) -> None:
        if not cfg.enabled:
            return
        verify_bearer(cfg, request.headers.get("authorization"))
    return _dep


# ---- scope parsing + check ------------------------------------------

def _parse_scope(scope: str) -> list[tuple[str, str]]:
    """Parse a scope string into [(namespace_pattern, capability)] entries.

    Grammar:
      "*"                     — superuser (matches everything)
      "*:*:*"                 — same, alternate spelling
      "ns:<name>:<cap>"       — specific namespace
      "<name>:<cap>"          — shorthand
      "*:<cap>"               — any namespace, this capability
    `cap` ∈ {r, w, rw, *}.

    Unknown entries are ignored (forward-compat).
    """
    out: list[tuple[str, str]] = []
    for token in (scope or "").split():
        if token == "*" or token == "*:*:*":
            out.append(("*", "*"))
            continue
        parts = token.split(":")
        if len(parts) == 3 and parts[0] == "ns":
            _, ns, cap = parts
            out.append((ns, cap))
        elif len(parts) == 2:
            ns, cap = parts
            out.append((ns, cap))
    return out


def is_admin_scope(scope: str) -> bool:
    """True for a superuser/service token (`*`, `*:*` or `*:*:*`) — required
    for control-plane operations (catalog provisioning) and grants access to
    any account's catalog."""
    return ("*", "*") in _parse_scope(scope)


def is_broker_scope(scope: str) -> bool:
    """True for a trusted delegation broker.

    A broker is a gateway allowed to assert, per request, the effective
    `principal` and session context (actor/channel) on behalf of an end user —
    the standard secure-gateway/impersonation pattern. Granted by the bare
    `broker` scope token; a superuser (`*`) token implies it. Non-broker tokens
    can never spoof another principal or the session context.
    """
    if is_admin_scope(scope):
        return True
    return "broker" in (scope or "").split()


def scope_allows(scope: str, namespace: str | None, method: str) -> bool:
    """Does `scope` allow `method` on `namespace`?

    `namespace=None` covers catalog-scope endpoints (/v1/config,
    list-namespaces, POST namespaces — the last requires write). We match
    those against the wildcard `"*"` namespace pattern in the token.
    """
    required_cap = "w" if method in WRITE_ACTIONS else "r"
    for ns_pat, cap_pat in _parse_scope(scope):
        # For catalog-level requests (no namespace), only wildcard scopes apply.
        if namespace is None and ns_pat != "*":
            continue
        if ns_pat not in {"*", namespace or ""}:
            continue
        if cap_pat == "*" or cap_pat == "rw":
            return True
        if cap_pat == required_cap:
            return True
    return False


def request_namespace(path: str) -> str | None:
    """Extract the Iceberg REST namespace from a URL path, if any.

    Examples:
      /v1/lake/namespaces/analytics/tables/events  → "analytics"
      /v1/lake/namespaces/analytics                → "analytics"
      /v1/lake/namespaces                          → None (list-or-create)
      /v1/config                                    → None
    """
    parts = path.strip("/").split("/")
    try:
        i = parts.index("namespaces")
    except ValueError:
        return None
    if i + 1 < len(parts):
        return parts[i + 1]
    return None
