"""STS AssumeRole client for Iceberg credential vending.

Backends differ in where STS lives (see `S3Settings.sts_endpoint`):

- MinIO speaks the AWS STS protocol on the same endpoint as S3 — the
  default when `sts_endpoint` is unset.
- Real AWS serves STS at `sts.{region}.amazonaws.com` (`sts_endpoint =
  "aws"`), requires a real, assumable `sts_role_arn`, packs inline session
  policies to a 2048-character limit (we degrade per-file scoping to a
  table-prefix scope past ~1900 chars, and retry once on
  PackedPolicyTooLarge), and REJECTS DurationSeconds above the role's
  MaxSessionDuration where MinIO clamps (we retry once at 3600).
- Backends with no STS at all (`sts_endpoint = "none"`, e.g. Hetzner) must
  never reach this module — the server reroutes vending to remote signing /
  static keys.

We call AssumeRole with an inline session policy scoped to the target
table's prefix so the vended credentials can only touch that one table's
objects. boto3's STS client handles request signing / XML parsing.
Production use would want credential caching; skipped here for clarity.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

import boto3
from botocore.exceptions import ClientError

from .config import S3Settings

log = logging.getLogger("duckicelake")


# Back-compat alias; the configurable value lives on
# `S3Settings.sts_role_arn`. MinIO accepts any non-empty RoleArn when using
# root credentials; real AWS requires an existing role whose trust policy
# allows the base credentials to sts:AssumeRole it.
DEFAULT_ROLE_ARN = "arn:aws:iam::duckicelake:role/IcebergClient"

# AWS limits inline session policies to 2048 plaintext characters (and
# additionally enforces a packed-size quota). We degrade below the limit
# with margin; MinIO has no comparable cap so the guard is a no-op there
# in practice.
_POLICY_MAX = 1900


@dataclass(frozen=True)
class VendedCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration_iso: str
    # True when per-file read scoping was widened to a table-prefix scope
    # to fit the session-policy size limit. Callers stamp this into audit.
    degraded: bool = False


def _scoped_policy(
    bucket: str,
    write_prefix: str,
    read_only: bool,
    read_keys: list[str] | None = None,
    read_prefixes: list[str] | None = None,
    deny_prefixes: list[str] | None = None,
) -> dict:
    """Build an STS session policy.

    Scoping strategy:
    - `read_only=True` + `read_keys`: `s3:GetObject` scoped to the explicit
      list of existing data/delete file keys. Tightest possible read policy
      — a compromised token can't enumerate or fetch sibling tables' files.
      Right for snapshot-pinned readers (REST LoadTable); wrong for live
      DuckLake-direct sessions, which discover files from PG on every query
      and would 403 on any file committed after vending.
    - `read_only=True` + `read_prefixes`: `s3:GetObject` on `{prefix}*` —
      covers a table's current *and future* files. The DuckLake-direct
      shape (ducklake-credentials endpoint).
    - `read_only=False` (write): `s3:GetObject` widened to the DuckLake
      data prefix. An Iceberg writer HEADs its own newly-uploaded files
      before committing, and those files aren't in any pre-computed list
      yet — so key-scoping would break the write path. PutObject / delete
      are also prefix-scoped since we can't predict filenames.

    `ListBucket` is always prefix-scoped so neither token can enumerate
    siblings outside the DuckLake data path.

    `deny_prefixes` adds explicit Deny statements (Deny beats Allow in IAM
    evaluation; MinIO honors it) — used by governance file-layer masking to
    carve base-table bytes out of broader allows (namespace-level vending).
    """
    read_keys = read_keys or []
    statements: list[dict] = [
        {
            "Sid": "ListDuckLakePrefix",
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}"],
            "Condition": {
                "StringLike": {"s3:prefix": [f"{write_prefix}*", write_prefix]}
            },
        }
    ]

    if read_only:
        if read_keys:
            statements.append(
                {
                    "Sid": "ReadOwnFiles",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": [f"arn:aws:s3:::{bucket}/{k}" for k in read_keys],
                }
            )
        if read_prefixes:
            statements.append(
                {
                    "Sid": "ReadOwnPrefixes",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": [
                        f"arn:aws:s3:::{bucket}/{p}*" for p in read_prefixes
                    ],
                }
            )
    else:
        # MinIO's IAM action namespace is narrower than AWS's. Per-step
        # multipart-upload actions (`s3:CreateMultipartUpload`,
        # `s3:UploadPart`, `s3:CompleteMultipartUpload`) are rejected by
        # MinIO's policy parser as "unsupported action". `s3:PutObject`
        # alone covers single-part PUTs but MinIO's CreateMultipartUpload
        # endpoint requires a wildcard (`s3:*`) when the policy can't
        # reference the action by name. Until MinIO exposes the canonical
        # action names this is the workable scope.
        statements.append(
            {
                "Sid": "ReadWriteInDataPrefix",
                "Effect": "Allow",
                "Action": ["s3:*"],
                "Resource": [
                    f"arn:aws:s3:::{bucket}/{write_prefix}*",
                ],
            }
        )

    if deny_prefixes:
        statements.append(
            {
                "Sid": "DenyGovernedBasePrefixes",
                "Effect": "Deny",
                "Action": ["s3:GetObject"],
                "Resource": [
                    f"arn:aws:s3:::{bucket}/{p}*" for p in deny_prefixes
                ],
            }
        )

    return {"Version": "2012-10-17", "Statement": statements}


def _sts_client(s3: S3Settings):
    if s3.sts_disabled:
        raise RuntimeError(
            "STS is disabled (sts_endpoint='none'); vend_credentials must "
            "not be called — the server reroutes to remote signing / static "
            "keys in this mode.")
    # botocore's default SigV4 for service "sts" is what both real AWS and
    # MinIO's STS handler expect (the old forced signature_version="s3v4"
    # was unnecessary — verified against the MinIO suite).
    return boto3.client(
        "sts",
        endpoint_url=s3.resolved_sts_endpoint(),
        region_name=s3.region,
        aws_access_key_id=s3.root_access_key,
        aws_secret_access_key=s3.root_secret_key,
    )


def _session_name(session_name: str | None, principal: str | None,
                  namespace: str, table: str) -> str:
    """STS RoleSessionName must match [\\w+=,.@-]{2,64}. A principal sub /
    namespace / table can carry spaces, slashes, colons (OAuth client ids,
    `?principal=` overrides), which AssumeRole rejects with a ValidationError
    — turning an otherwise-fine vend into a 500. Sanitize out-of-charset
    characters to '_' and clamp to 64."""
    raw = session_name or f"ice-{principal or 'anon'}-{namespace}-{table}"
    cleaned = re.sub(r"[^\w+=,.@-]", "_", raw)[:64]
    return cleaned if len(cleaned) >= 2 else f"ice-{cleaned}"


def _keys_from_uris(uris: list[str], bucket: str) -> list[str]:
    prefix = f"s3://{bucket}/"
    keys = []
    for u in uris:
        if u.startswith(prefix):
            keys.append(u[len(prefix):])
        elif u.startswith("s3://"):
            # Different bucket — skip; we won't vend for it.
            continue
        else:
            # Relative path stored by DuckLake — just use it.
            keys.append(u.lstrip("/"))
    return keys


def _build_policy(
    s3: S3Settings,
    *,
    namespace: str,
    table: str,
    write_prefix: str,
    read_only: bool,
    read_keys: list[str],
    read_prefixes: list[str] | None,
    deny_prefixes: list[str] | None,
    data_prefix: str | None,
    force_degrade: bool = False,
) -> tuple[str, bool]:
    """Build the compact session-policy JSON, degrading per-file read
    scoping to a table-prefix scope when the policy would blow the AWS
    inline-session-policy size limit.

    Degradation only ever WIDENS the read scope from "these exact keys" to
    "this table's prefix" — still single-table. `deny_prefixes` are NEVER
    dropped or collapsed: the Deny carve-outs are the file-layer masking
    security boundary, so a policy that stays oversized even after
    degradation raises instead of shipping without them.
    """
    def _render(keys: list[str], prefixes: list[str] | None) -> str:
        policy = _scoped_policy(
            s3.bucket,
            write_prefix=write_prefix,
            read_only=read_only,
            read_keys=keys,
            read_prefixes=prefixes,
            deny_prefixes=deny_prefixes,
        )
        return json.dumps(policy, separators=(",", ":"))

    compact = _render(read_keys, read_prefixes)
    degraded = False
    if read_only and read_keys and (
            force_degrade or len(compact) > _POLICY_MAX):
        fallback = list(read_prefixes or [])
        table_prefix = s3.table_prefix(namespace, table, data_prefix)
        if table_prefix not in fallback:
            fallback.append(table_prefix)
        log.warning(
            "STS session policy for %s.%s too large (%d files, %d chars); "
            "degrading per-file read scope to table prefix %s",
            namespace, table, len(read_keys), len(compact), table_prefix)
        compact = _render([], fallback)
        degraded = True
    if len(compact) > _POLICY_MAX:
        raise ValueError(
            f"STS session policy for {namespace}.{table} is {len(compact)} "
            f"chars even after degradation (limit ~{_POLICY_MAX}; AWS caps "
            f"inline session policies at 2048). The deny-prefix list alone "
            f"exceeds the limit — reduce file-layer-masked table count per "
            f"namespace or vend per-table instead.")
    return compact, degraded


def vend_credentials(
    s3: S3Settings,
    *,
    namespace: str,
    table: str,
    read_only: bool = False,
    data_file_uris: list[str] | None = None,
    read_prefixes: list[str] | None = None,
    deny_prefixes: list[str] | None = None,
    duration_seconds: int = 3600,
    session_name: str | None = None,
    principal: str | None = None,
    data_prefix: str | None = None,
) -> VendedCredentials:
    """Mint temporary credentials for a single table.

    `duration_seconds` semantics differ by backend: MinIO CLAMPS out-of-range
    values (default build accepts 900–604800); real AWS REJECTS values above
    the role's MaxSessionDuration (default 3600, absolute max 43200) with a
    ValidationError — we retry once at 3600 when that happens.

    `data_file_uris` is the list of live data files for this table (pulled
    from DuckLake's `ducklake_data_file` catalog table). When provided with
    `read_only=True`, reads are restricted to exactly those object keys —
    unless the resulting session policy would exceed the AWS size limit, in
    which case scoping degrades to the table's prefix (`degraded=True` on
    the result). For writes we allow the DuckLake data-path prefix (we
    can't predict filenames).

    `read_prefixes` (read-only) grants GetObject on whole key prefixes —
    for long-lived DuckLake-direct sessions that must keep reading files
    committed after vending (see `_scoped_policy`).

    `principal` (governance) stamps the STS session name so backend audit
    logs attribute vended creds to a principal.
    """
    # Per-account catalog scopes writes to its own data prefix; default keeps
    # the single-catalog data prefix.
    write_prefix = data_prefix or s3.data_prefix  # DuckLake writes under this
    read_keys = _keys_from_uris(data_file_uris or [], s3.bucket)
    build = dict(
        namespace=namespace, table=table, write_prefix=write_prefix,
        read_only=read_only, read_keys=read_keys,
        read_prefixes=read_prefixes, deny_prefixes=deny_prefixes,
        data_prefix=data_prefix,
    )
    policy_json, degraded = _build_policy(s3, **build)
    sts = _sts_client(s3)
    role_arn = s3.sts_role_arn or DEFAULT_ROLE_ARN
    session = _session_name(session_name, principal, namespace, table)

    def _assume(policy: str, duration: int):
        return sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session,
            Policy=policy,
            DurationSeconds=duration,
        )

    try:
        resp = _assume(policy_json, duration_seconds)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "PackedPolicyTooLarge" and not degraded and read_keys \
                and read_only:
            # AWS's packed-size accounting can trip before our plaintext
            # estimate does — degrade to prefix scoping and retry once.
            policy_json, degraded = _build_policy(
                s3, force_degrade=True, **build)
            resp = _assume(policy_json, duration_seconds)
        elif (code == "ValidationError" and "DurationSeconds" in str(e)
                and duration_seconds > 3600):
            # AWS rejects durations above the role's MaxSessionDuration
            # (MinIO clamps instead). Retry once at the AWS default.
            log.warning(
                "STS rejected DurationSeconds=%d (role MaxSessionDuration "
                "too low?); retrying at 3600. Raise the role's "
                "MaxSessionDuration to allow longer sessions.",
                duration_seconds)
            resp = _assume(policy_json, 3600)
        else:
            _log_assume_role_error(code, role_arn)
            raise
    creds = resp["Credentials"]
    return VendedCredentials(
        access_key_id=creds["AccessKeyId"],
        secret_access_key=creds["SecretAccessKey"],
        session_token=creds["SessionToken"],
        expiration_iso=creds["Expiration"].isoformat(),
        degraded=degraded,
    )


def _log_assume_role_error(code: str, role_arn: str) -> None:
    """One clear operator-facing line per well-known AssumeRole failure."""
    if code == "AccessDenied":
        log.error(
            "STS AssumeRole denied: the base credentials are not allowed "
            "to sts:AssumeRole %s — fix the role's trust policy (it must "
            "allow the proxy's base-credential principal).", role_arn)
    elif code in {"InvalidClientTokenId", "ExpiredToken", "SignatureDoesNotMatch"}:
        log.error(
            "STS rejected the proxy's base credentials (%s) — check "
            "DUCKICELAKE_S3_ROOT_KEY/SECRET.", code)
    elif code == "MalformedPolicyDocument":
        log.error(
            "STS rejected the session policy as malformed — likely a "
            "backend that does not support an action/condition we emit.")
    elif code:
        log.error("STS AssumeRole failed with %s (role %s)", code, role_arn)
