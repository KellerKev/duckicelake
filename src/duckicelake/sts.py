"""MinIO STS AssumeRole client for Iceberg credential vending.

MinIO speaks the AWS STS protocol on the same endpoint as S3 (no separate STS
service). We call AssumeRole with an inline session policy scoped to the
target table's prefix so the vended credentials can only touch that one
table's objects.

We use boto3's STS client under the hood so the request signing / XML parsing
is handled by botocore. Production use would want credential caching and
retries, both skipped here for clarity.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

import boto3
from botocore.config import Config

from .config import S3Settings


# MinIO's built-in role. AWS would use a real RoleArn here; MinIO accepts any
# non-empty value for AssumeRole when using root credentials, but we pass a
# recognizable string for readability in minio's audit log.
DEFAULT_ROLE_ARN = "arn:aws:iam::duckicelake:role/IcebergClient"


@dataclass(frozen=True)
class VendedCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration_iso: str


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
    return boto3.client(
        "sts",
        endpoint_url=s3.endpoint,
        region_name=s3.region,
        aws_access_key_id=s3.root_access_key,
        aws_secret_access_key=s3.root_secret_key,
        config=Config(signature_version="s3v4"),
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
) -> VendedCredentials:
    """Mint temporary credentials for a single table.

    `duration_seconds` is clamped by MinIO — the default build accepts values
    between 900 (15 min) and 604800 (7 days).

    `data_file_uris` is the list of live data files for this table (pulled
    from DuckLake's `ducklake_data_file` catalog table). When provided,
    reads are restricted to exactly those object keys. For writes we still
    have to allow the DuckLake data-path prefix (we can't predict filenames).

    `read_prefixes` (read-only) grants GetObject on whole key prefixes —
    for long-lived DuckLake-direct sessions that must keep reading files
    committed after vending (see `_scoped_policy`).

    `principal` (governance) stamps the STS session name so MinIO audit logs
    attribute vended creds to a principal. The Phase 2 hook for *withholding*
    creds from principals who must be masked (coarse, file-granularity) lands
    with the pre-masked-file work in Phase 4 — see GOVERNANCE.md.
    """
    write_prefix = s3.data_prefix  # DuckLake writes everything under this
    read_keys = _keys_from_uris(data_file_uris or [], s3.bucket)
    policy = _scoped_policy(
        s3.bucket,
        write_prefix=write_prefix,
        read_only=read_only,
        read_keys=read_keys,
        read_prefixes=read_prefixes,
        deny_prefixes=deny_prefixes,
    )
    sts = _sts_client(s3)
    resp = sts.assume_role(
        RoleArn=DEFAULT_ROLE_ARN,
        RoleSessionName=_session_name(
            session_name, principal, namespace, table),
        Policy=json.dumps(policy),
        DurationSeconds=duration_seconds,
    )
    creds = resp["Credentials"]
    return VendedCredentials(
        access_key_id=creds["AccessKeyId"],
        secret_access_key=creds["SecretAccessKey"],
        session_token=creds["SessionToken"],
        expiration_iso=creds["Expiration"].isoformat(),
    )
