"""One-shot catalog bootstrap:
1. Ensure the S3 bucket exists.
2. Ensure the DuckLake catalog is attached and a default namespace exists.

Idempotent: safe to run repeatedly.
"""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from . import s3util
from .catalog import DuckLakeCatalog
from .config import load_settings, redact_password


def _head_ok(client, bucket: str) -> bool:
    """True only when head_bucket succeeds. 403 and 404 both count as
    "not confirmed" — backends disagree on the code for a missing-vs-denied
    bucket (Hetzner in particular), and the caller retries either way."""
    try:
        client.head_bucket(Bucket=bucket)
        return True
    except ClientError:
        return False


def ensure_bucket(settings, *, retries: int = 5, delay: float = 2.0) -> None:
    s3 = settings.s3
    client = s3util.s3_client(s3)
    if _head_ok(client, s3.bucket):
        print(f"S3 bucket '{s3.bucket}' already exists.")
        return
    try:
        client.create_bucket(Bucket=s3.bucket)
        print(f"Created S3 bucket '{s3.bucket}'.")
        return
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
            print(f"S3 bucket '{s3.bucket}' already exists.")
            return
        if code not in {"AccessDenied", "403", "InvalidAccessKeyId"}:
            raise
    # Bucket-create denied. On Hetzner this is normal for pre-provisioned
    # buckets (keys often lack create rights), and freshly issued keys can
    # return AccessDenied for a few seconds before they propagate — so
    # re-probe head_bucket with backoff before concluding it's broken.
    for _ in range(retries):
        time.sleep(delay)
        if _head_ok(client, s3.bucket):
            print(f"S3 bucket '{s3.bucket}' pre-provisioned; proceeding.")
            return
    raise RuntimeError(
        f"create_bucket was denied and head_bucket still fails for "
        f"'{s3.bucket}'. If the backend is Hetzner Object Storage: "
        f"pre-create the bucket in the SAME project as the access key "
        f"(keys are project-scoped) and allow ~30s for fresh keys to "
        f"propagate before retrying."
    )


def main() -> int:
    settings = load_settings()
    ensure_bucket(settings)

    cat = DuckLakeCatalog(settings)
    cat.connect()
    if not cat.namespace_exists(["default"]):
        cat.create_namespace(["default"])
        print("Created 'default' namespace.")
    else:
        print("'default' namespace already exists.")

    print(f"DuckLake catalog '{settings.catalog_name}' ready.")
    print(f"  Postgres:  {redact_password(settings.pg_dsn)}")
    print(f"  Data path: {settings.ducklake_data_path}")
    print(f"  S3:        {settings.s3.endpoint} bucket={settings.s3.bucket}")
    cat.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
