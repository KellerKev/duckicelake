from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class S3Settings:
    endpoint: str              # http://127.0.0.1:9000
    region: str                # us-east-1
    bucket: str                # lakehouse
    root_access_key: str       # minioadmin
    root_secret_key: str       # minioadmin
    path_style: bool           # True for MinIO
    data_prefix: str           # e.g. "data/" — DuckLake writes under this

    @property
    def host(self) -> str:
        return self.endpoint.rsplit("://", 1)[-1]

    @property
    def use_ssl(self) -> bool:
        return self.endpoint.startswith("https://")

    def table_prefix(self, namespace: str, table: str) -> str:
        # Used for scoping STS policies to a specific table's objects.
        return f"{self.data_prefix}{namespace}/{table}/"


@dataclass(frozen=True)
class Settings:
    pg_host: str
    pg_port: int
    pg_user: str
    pg_database: str
    catalog_name: str
    s3: S3Settings

    @property
    def pg_dsn(self) -> str:
        return (
            f"dbname={self.pg_database} host={self.pg_host} "
            f"port={self.pg_port} user={self.pg_user}"
        )

    @property
    def ducklake_uri(self) -> str:
        return f"ducklake:postgres:{self.pg_dsn}"

    @property
    def ducklake_data_path(self) -> str:
        return f"s3://{self.s3.bucket}/{self.s3.data_prefix}"


def load_settings() -> Settings:
    s3 = S3Settings(
        endpoint=os.environ.get("DUCKICELAKE_S3_ENDPOINT", "http://127.0.0.1:9000"),
        region=os.environ.get("DUCKICELAKE_S3_REGION", "us-east-1"),
        bucket=os.environ.get("DUCKICELAKE_S3_BUCKET", "lakehouse"),
        root_access_key=os.environ.get("DUCKICELAKE_S3_ROOT_KEY", "minioadmin"),
        root_secret_key=os.environ.get("DUCKICELAKE_S3_ROOT_SECRET", "minioadmin"),
        path_style=os.environ.get("DUCKICELAKE_S3_PATH_STYLE", "1") == "1",
        data_prefix=os.environ.get("DUCKICELAKE_S3_PREFIX", "data/"),
    )
    return Settings(
        pg_host=os.environ.get("DUCKICELAKE_PG_HOST", str(REPO_ROOT / ".pgsock")),
        pg_port=int(os.environ.get("DUCKICELAKE_PG_PORT", "55432")),
        pg_user=os.environ.get("DUCKICELAKE_PG_USER", "ducklake"),
        pg_database=os.environ.get("DUCKICELAKE_PG_DATABASE", "ducklake"),
        catalog_name=os.environ.get("DUCKICELAKE_CATALOG", "lake"),
        s3=s3,
    )
