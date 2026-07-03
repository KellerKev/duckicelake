"""Single boto3 S3-client factory for every server-side (and test/demo)
client in the tree.

Why a factory: botocore >= 1.36 (Jan 2025) adds request/response integrity
checksums by default (`x-amz-checksum-crc32` headers + `aws-chunked` payload
encoding). AWS and MinIO accept them; Hetzner Object Storage rejects them
with a *misleading* generic `AccessDenied` on any request with a body
(put_object, delete_objects, create_bucket). `when_required` restores the
pre-1.36 behavior — checksums only where the API demands them — and is
equally correct against AWS, MinIO, and Hetzner, so it is applied
unconditionally rather than behind a backend profile.

Path-style vs virtual-hosted addressing follows `S3Settings.path_style`
(MinIO and Hetzner both want path-style). Region is passed through as-is so
Hetzner's `"auto"` works (it's only used for the SigV4 credential scope).
"""
from __future__ import annotations

import boto3
from botocore.config import Config

from .config import S3Settings


def boto_config(s3: S3Settings) -> Config:
    return Config(
        signature_version="s3v4",
        s3={"addressing_style": "path" if s3.path_style else "virtual"},
        request_checksum_calculation="when_required",
        response_checksum_validation="when_required",
    )


def s3_client(s3: S3Settings):
    """Root-credentialed S3 client."""
    return boto3.client(
        "s3",
        endpoint_url=s3.endpoint,
        region_name=s3.region,
        aws_access_key_id=s3.root_access_key,
        aws_secret_access_key=s3.root_secret_key,
        config=boto_config(s3),
    )


def s3_client_for_keys(
    s3: S3Settings,
    access_key: str,
    secret_key: str,
    session_token: str | None = None,
):
    """S3 client for vended / static credentials (tests, demo harness)."""
    return boto3.client(
        "s3",
        endpoint_url=s3.endpoint,
        region_name=s3.region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        config=boto_config(s3),
    )
