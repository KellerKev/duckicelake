"""One-shot catalog bootstrap:
1. Ensure the S3 bucket exists.
2. Ensure the DuckLake catalog is attached and a default namespace exists.

Idempotent: safe to run repeatedly.
"""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from .catalog import DuckLakeCatalog
from .config import load_settings


def ensure_bucket(settings) -> None:
    s3 = settings.s3
    client = boto3.client(
        "s3",
        endpoint_url=s3.endpoint,
        region_name=s3.region,
        aws_access_key_id=s3.root_access_key,
        aws_secret_access_key=s3.root_secret_key,
    )
    try:
        client.head_bucket(Bucket=s3.bucket)
        print(f"S3 bucket '{s3.bucket}' already exists.")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code not in {"404", "NoSuchBucket", "NoSuchBucketPolicy"}:
            raise
        client.create_bucket(Bucket=s3.bucket)
        print(f"Created S3 bucket '{s3.bucket}'.")


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
    print(f"  Postgres:  {settings.pg_dsn}")
    print(f"  Data path: {settings.ducklake_data_path}")
    print(f"  S3:        {settings.s3.endpoint} bucket={settings.s3.bucket}")
    cat.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
