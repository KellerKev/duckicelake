"""Settings for the proxy.

Sources, highest precedence first:

1. real environment variables (`DUCKICELAKE_*`),
2. a `.env` file in the working directory (`KEY=VALUE` lines,
   `DUCKICELAKE_*` keys only),
3. a TOML config file — `$DUCKICELAKE_CONFIG_FILE` if set, else
   `./duckicelake.toml` (see `duckicelake.toml.example`).

File values are injected into `os.environ` (without overriding what's
already set) the first time settings load, so every consumer of the
`DUCKICELAKE_*` variables — auth, logging, the notify listener — picks
them up uniformly, not just the fields below.
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

ENV_PREFIX = "DUCKICELAKE_"


def _coerce(value: object) -> str:
    """TOML value → env-var string. Booleans use the '1'/'0' convention
    every DUCKICELAKE_* flag already follows."""
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def toml_file_env(path: Path) -> dict[str, str]:
    """Map a config TOML onto DUCKICELAKE_* env names.

    Top-level `key = …` → `DUCKICELAKE_KEY`; `[section]` `key = …` →
    `DUCKICELAKE_SECTION_KEY`. So `[s3] endpoint` is
    `DUCKICELAKE_S3_ENDPOINT`, top-level `suppress_root_creds` is
    `DUCKICELAKE_SUPPRESS_ROOT_CREDS`, etc.
    """
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    out: dict[str, str] = {}
    for key, value in raw.items():
        if isinstance(value, dict):
            for sub, subval in value.items():
                out[f"{ENV_PREFIX}{key}_{sub}".upper()] = _coerce(subval)
        else:
            out[f"{ENV_PREFIX}{key}".upper()] = _coerce(value)
    return out


def dotenv_file_env(path: Path) -> dict[str, str]:
    """Parse `KEY=VALUE` lines; only DUCKICELAKE_* keys are honored so a
    shared .env can't inject unrelated variables into the process."""
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        if not key.startswith(ENV_PREFIX):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key] = value
    return out


def apply_file_config(cwd: Path | None = None) -> list[str]:
    """Inject file-sourced config into os.environ via setdefault (real
    env always wins; .env beats the TOML). Returns the injected key names
    — callers/tests can use it to clean up. Safe to call repeatedly."""
    cwd = cwd or Path.cwd()
    injected: list[str] = []
    sources: list[dict[str, str]] = []
    dotenv = cwd / ".env"
    if dotenv.is_file():
        sources.append(dotenv_file_env(dotenv))
    toml_path = os.environ.get(f"{ENV_PREFIX}CONFIG_FILE", "")
    toml_file = Path(toml_path) if toml_path else cwd / "duckicelake.toml"
    if toml_file.is_file():
        sources.append(toml_file_env(toml_file))
    for source in sources:
        for key, value in source.items():
            if key not in os.environ:
                os.environ[key] = value
                injected.append(key)
    return injected


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
    # Omit the root S3 key pair from REST response configs. Default ON:
    # root keys in client hands make the governance masking layer
    # bypassable in one line (see GOVERNANCE.md). Demos / dev stacks that
    # want the old convenience set suppress_root_creds = false in
    # duckicelake.toml or DUCKICELAKE_SUPPRESS_ROOT_CREDS=0.
    suppress_root_creds: bool = True
    # Transparent DuckLake-direct masking (SET search_path onto a
    # __masked_{sig} schema via post_attach_sql). Probe-verified; the
    # flag is an opt-out in case a DuckDB release regresses.
    transparent_masking: bool = True

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
    apply_file_config()
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
        suppress_root_creds=os.environ.get(
            "DUCKICELAKE_SUPPRESS_ROOT_CREDS", "1") == "1",
        transparent_masking=os.environ.get(
            "DUCKICELAKE_TRANSPARENT_MASKING", "1") == "1",
    )
