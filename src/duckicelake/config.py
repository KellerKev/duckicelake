from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


# Characters a password may not contain: the owner DSN is consumed BOTH by
# psycopg (space-delimited conninfo) AND by DuckDB's ducklake extension, which
# embeds the conninfo inside a single-quoted `ATTACH 'ducklake:postgres:…'`
# SQL literal — so a space splits tokens and a quote/backslash breaks the
# literal. libpq quoting can't satisfy the SQL-literal layer, so we forbid
# these rather than emit something that silently fails at ATTACH time.
_PW_UNSAFE = " '\"\\\t\r\n"


def validate_pg_password(pw: str) -> None:
    bad = sorted({c for c in pw if c in _PW_UNSAFE})
    if bad:
        names = ", ".join(repr(c) for c in bad)
        raise ValueError(
            "DUCKICELAKE_PG_PASSWORD may not contain whitespace, quotes, or "
            f"backslashes (found {names}); the value is embedded in a libpq "
            "conninfo and a DuckDB ATTACH string literal. Use a password "
            "without those characters.")


def redact_password(conninfo: str) -> str:
    """Mask the bare `password=…` value in a conninfo / DuckLake URI before
    logging or printing it."""
    return re.sub(r"(password=)(\S+)", r"\1***", conninfo)


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
    # Optional password for the owning PG role. Dev uses trust auth and prod
    # can use cert/ident, but managed Postgres (RDS, Supabase, Neon, Cloud
    # SQL, a password-protected container) needs scram with a password. Set
    # via DUCKICELAKE_PG_PASSWORD. When set, it flows into every owner
    # connection through `pg_dsn` (and `ducklake_uri`).
    pg_password: str | None = None

    @property
    def pg_dsn(self) -> str:
        dsn = (
            f"dbname={self.pg_database} host={self.pg_host} "
            f"port={self.pg_port} user={self.pg_user}"
        )
        if self.pg_password:
            dsn += f" password={self.pg_password}"
        return dsn

    @property
    def ducklake_uri(self) -> str:
        return f"ducklake:postgres:{self.pg_dsn}"

    @property
    def ducklake_data_path(self) -> str:
        return f"s3://{self.s3.bucket}/{self.s3.data_prefix}"


def load_settings() -> Settings:
    pg_password = os.environ.get("DUCKICELAKE_PG_PASSWORD") or None
    if pg_password:
        validate_pg_password(pg_password)
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
        pg_password=pg_password,
        catalog_name=os.environ.get("DUCKICELAKE_CATALOG", "lake"),
        s3=s3,
    )
