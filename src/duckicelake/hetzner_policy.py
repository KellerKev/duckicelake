"""Hetzner bucket-policy generator — the DuckLake-direct compensation tier
for no-STS backends.

Hetzner Object Storage has no STS, but its bucket policies (standard
`PutBucketPolicy`) can target a SPECIFIC access key as the Principal:

    arn:aws:iam:::user/p<project_id>:<access_key_id>

That is the one server-side per-principal enforcement primitive available,
so for clients that cannot remote-sign (DuckDB httpfs / the DuckDB iceberg
extension) we mirror the scoping an STS session policy would have carried
into a bucket policy: per registered principal, Allow ListBucket +
GetObject on their readable prefixes, Deny GetObject on the base prefixes
of file-layer-masked tables, Allow GetObject on their CURRENT masked sig
prefix instead.

Coarse and static by nature: keys are provisioned manually in the Hetzner
console, the policy must be re-applied after governance changes (mask
signatures rotate!), and the ~20 KB bucket-policy ceiling bounds the number
of registered principals. The remote-signing tier (signer.py) is the
dynamic, airtight one — this exists so DuckLake-direct readers aren't
locked out entirely.

CLI (dry-run prints the policy JSON; --apply PUTs it):

    python -m duckicelake.hetzner_policy [--apply] [--catalog ID]
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field

from . import s3util
from .config import Settings, load_settings

log = logging.getLogger("duckicelake")

# S3 bucket policies cap at 20 KB; warn well before.
_POLICY_WARN_BYTES = 15 * 1024
_POLICY_MAX_BYTES = 20 * 1024


@dataclass(frozen=True)
class PrincipalGrant:
    principal: str
    access_key_id: str
    list_prefixes: list[str] = field(default_factory=list)
    allow_prefixes: list[str] = field(default_factory=list)   # GetObject
    deny_prefixes: list[str] = field(default_factory=list)    # beats Allow


def principal_arn(project_id: str, access_key_id: str) -> str:
    """Hetzner's per-access-key Principal ARN. `project_id` is the id of
    the project that owns the S3 CREDENTIALS (not necessarily the bucket)."""
    return f"arn:aws:iam:::user/p{project_id}:{access_key_id}"


def grants_for_catalog(ctx, settings: Settings) -> list[PrincipalGrant]:
    """One grant per registered static-key principal, mirroring the
    read-prefix / deny-prefix selection of the ducklake-credentials
    endpoint: catalog-wide reads when nothing is file-layer masked;
    otherwise carve out every file-layer table's base prefix the principal
    is masked on and allow their current masked sig prefix instead."""
    from .policies import mask_signature

    s3 = settings.s3
    dp = ctx.ref.data_prefix
    grants: list[PrincipalGrant] = []
    for entry in ctx.store.list_static_keys():
        roles = ctx.store.roles_for_principal(entry.principal)
        allow = [dp]
        deny: list[str] = []
        # Scan every table for file-layer plans affecting this principal.
        for ns in ctx.catalog.list_namespaces(None):
            for (_s, t) in ctx.catalog.list_tables(ns):
                plan = ctx.policy_engine.plan_for(
                    principal=entry.principal, roles=roles,
                    schema=ns[0], table=t)
                if plan.file_layer and not plan.is_empty():
                    deny.append(s3.table_prefix(ns[0], t, dp))
                    allow.append(
                        s3.masked_sig_prefix(ns[0], t, mask_signature(plan), dp))
        grants.append(PrincipalGrant(
            principal=entry.principal,
            access_key_id=entry.access_key_id,
            list_prefixes=[dp],
            allow_prefixes=allow,
            deny_prefixes=deny,
        ))
    return grants


def build_bucket_policy(bucket: str, project_id: str,
                        grants: list[PrincipalGrant]) -> dict:
    """Pure: grants → bucket-policy document. Raises ValueError when the
    serialized policy would exceed the S3 20 KB limit."""
    if not project_id:
        raise ValueError(
            "hetzner_project_id is not configured (DUCKICELAKE_HETZNER_"
            "PROJECT_ID or [hetzner] project_id) — required to build "
            "per-access-key Principals.")
    statements: list[dict] = []
    for i, g in enumerate(grants):
        arn = principal_arn(project_id, g.access_key_id)
        prefixes = sorted(set(g.list_prefixes))
        statements.append({
            "Sid": f"List{i}",
            "Effect": "Allow",
            "Principal": {"AWS": arn},
            "Action": ["s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}"],
            "Condition": {"StringLike": {
                "s3:prefix": [x for p in prefixes for x in (f"{p}*", p)]}},
        })
        statements.append({
            "Sid": f"Read{i}",
            "Effect": "Allow",
            "Principal": {"AWS": arn},
            "Action": ["s3:GetObject"],
            "Resource": [f"arn:aws:s3:::{bucket}/{p}*"
                         for p in sorted(set(g.allow_prefixes))],
        })
        if g.deny_prefixes:
            statements.append({
                "Sid": f"DenyMaskedBase{i}",
                "Effect": "Deny",
                "Principal": {"AWS": arn},
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/{p}*"
                             for p in sorted(set(g.deny_prefixes))],
            })
    policy = {"Version": "2012-10-17", "Statement": statements}
    size = len(json.dumps(policy, separators=(",", ":")))
    if size > _POLICY_MAX_BYTES:
        raise ValueError(
            f"bucket policy is {size} bytes (limit {_POLICY_MAX_BYTES}); "
            f"too many registered principals / masked tables — reduce the "
            f"static-key registry or move those readers to remote signing.")
    if size > _POLICY_WARN_BYTES:
        log.warning("bucket policy is %d bytes — approaching the %d-byte "
                    "S3 limit", size, _POLICY_MAX_BYTES)
    return policy


def apply_bucket_policy(settings: Settings, policy: dict) -> None:
    client = s3util.s3_client(settings.s3)
    client.put_bucket_policy(
        Bucket=settings.s3.bucket,
        Policy=json.dumps(policy, separators=(",", ":")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m duckicelake.hetzner_policy",
        description="Generate (and optionally apply) the Hetzner bucket "
                    "policy for registered static-key principals.")
    parser.add_argument("--apply", action="store_true",
                        help="PUT the policy to the bucket (default: print)")
    parser.add_argument("--catalog", default=None,
                        help="catalog id (default: the default catalog)")
    args = parser.parse_args(argv)

    settings = load_settings()
    from .registry import CatalogRegistry
    registry = CatalogRegistry(settings)
    ctx = (registry.get(args.catalog) if args.catalog
           else registry.register_default().connect())
    try:
        grants = grants_for_catalog(ctx, settings)
        if not grants:
            print("No static keys registered "
                  "(POST /v1/{prefix}/governance/static-s3-keys first); "
                  "nothing to do.", file=sys.stderr)
            return 1
        policy = build_bucket_policy(
            settings.s3.bucket, settings.s3.hetzner_project_id, grants)
        if args.apply:
            apply_bucket_policy(settings, policy)
            print(f"Applied bucket policy to '{settings.s3.bucket}' "
                  f"({len(grants)} principals).")
        else:
            print(json.dumps(policy, indent=2))
    finally:
        ctx.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
