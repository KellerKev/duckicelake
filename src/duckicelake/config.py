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
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

ENV_PREFIX = "DUCKICELAKE_"


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
    logging or printing it. (Values are always conninfo-safe — no spaces — so
    the token runs to the next space.)"""
    return re.sub(r"(password=)(\S+)", r"\1***", conninfo)


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


_FILE_CONFIG_APPLIED = False


def apply_file_config(cwd: Path | None = None) -> list[str]:
    """Inject file-sourced config into os.environ via setdefault (real
    env always wins; .env beats the TOML). Returns the injected key names
    — callers/tests can use it to clean up.

    The default (no-arg) invocation runs at most once per process — both
    the server import and load_settings() call it, and re-running would
    just re-setdefault the same keys. Passing an explicit `cwd` (tests)
    always runs, so callers can probe different config directories."""
    global _FILE_CONFIG_APPLIED
    explicit = cwd is not None
    if not explicit and _FILE_CONFIG_APPLIED:
        return []
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
    if not explicit:
        _FILE_CONFIG_APPLIED = True
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

    def table_prefix(self, namespace: str, table: str, data_prefix: str | None = None) -> str:
        # Used for scoping STS policies to a specific table's objects.
        # `data_prefix` overrides the default for a per-account catalog; None
        # keeps the single-catalog default (backward-compatible).
        return f"{data_prefix or self.data_prefix}{namespace}/{table}/"

    def masked_table_prefix(self, namespace: str, table: str, data_prefix: str | None = None) -> str:
        """Root of a table's file-layer masked exports. Deliberately under
        `data_prefix` (the vended ListBucket condition covers globbing)
        but disjoint from `table_prefix` — masked-only credentials must
        never reach base bytes, and DuckLake's own cleanup tooling must
        never encounter foreign Parquet inside a table dir."""
        return f"{data_prefix or self.data_prefix}__masked__/{namespace}/{table}/"

    def masked_sig_prefix(self, namespace: str, table: str, sig: str,
                          data_prefix: str | None = None) -> str:
        """One mask-signature's export tree: the credential boundary —
        masked principals are vended GetObject on exactly this prefix."""
        return f"{self.masked_table_prefix(namespace, table, data_prefix)}{sig}/"


@dataclass(frozen=True)
class CatalogRef:
    """Identifies one isolated DuckLake catalog within the shared backend.

    - `catalog_name`   — the DuckDB ATTACH alias.
    - `data_prefix`    — S3 key prefix under the shared bucket for this
                         catalog's Parquet (disjoint per catalog).
    - `metadata_schema`— Postgres schema holding this catalog's ducklake_*
                         metadata tables. `None` uses the extension default,
                         i.e. today's single-catalog behavior.

    The names are derived and validated by the orchestration layer; the proxy
    treats them as opaque, trusted identifiers.
    """
    catalog_name: str
    data_prefix: str
    metadata_schema: str | None = None


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
    # bypassable in one line. Demos / dev stacks that
    # want the old convenience set suppress_root_creds = false in
    # duckicelake.toml or DUCKICELAKE_SUPPRESS_ROOT_CREDS=0.
    suppress_root_creds: bool = True
    # Transparent DuckLake-direct masking (SET search_path onto a
    # __masked_{sig} schema via post_attach_sql). Probe-verified; the
    # flag is an opt-out in case a DuckDB release regresses.
    transparent_masking: bool = True
    # PG row-level security for DuckLake-direct readers: per-principal
    # LOGIN roles in a duckicelake_reader group, RLS policies on the
    # ducklake_* catalog tables. Opt-out flag; under dev trust-auth the
    # predicates run but authentication is not enforceable (only real
    # under production scram+TLS; see OPERATIONS.md for the pg_hba recipe).
    rls_enabled: bool = True
    # NOLOGIN group role carrying all reader grants + RLS targets.
    reader_group_role: str = "duckicelake_reader"
    # Strict mode: extend the airtight tier's fail-CLOSED posture to the
    # COOPERATIVE tier. When true, a governance error on a governed read
    # path — policy planning threw, or a demanded masking view could not be
    # materialized — DENIES the read/vend (503) instead of degrading to
    # unmasked-with-audit. Default false: the documented cooperative
    # behavior (a governance error never breaks a read). Trade-off when on:
    # a governance-sidecar outage takes governed reads down with it.
    governance_fail_closed: bool = False
    # Password for the owning PG role. Optional: dev uses trust auth and
    # production can use cert/ident, but managed Postgres (RDS, Supabase,
    # Neon, Cloud SQL, a password-protected container) needs scram with a
    # password. Set via DUCKICELAKE_PG_PASSWORD / [pg] password. When set, it
    # flows into every owner connection through `pg_dsn` (and `ducklake_uri`).
    pg_password: str | None = None

    def pg_dsn_for(self, user: str, password: str) -> str:
        """DSN for a vended (non-owner) PG role. Passwords we generate are
        token_hex — alphanumeric, no conninfo quoting needed (and DuckDB's
        `ducklake:postgres:` parser treats quotes literally, so quoting here
        would break the reader ATTACH)."""
        return (
            f"dbname={self.pg_database} host={self.pg_host} "
            f"port={self.pg_port} user={user} password={password}"
        )

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

    def default_catalog_ref(self) -> CatalogRef:
        """The single-catalog ref matching today's behavior (no
        METADATA_SCHEMA → extension default schema)."""
        return CatalogRef(self.catalog_name, self.s3.data_prefix, None)

    def data_path_for(self, ref: CatalogRef) -> str:
        """S3 data root for a given catalog ref (mirrors `ducklake_data_path`
        for the default ref)."""
        return f"s3://{self.s3.bucket}/{ref.data_prefix}"


def load_settings() -> Settings:
    apply_file_config()
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
        suppress_root_creds=os.environ.get(
            "DUCKICELAKE_SUPPRESS_ROOT_CREDS", "1") == "1",
        transparent_masking=os.environ.get(
            "DUCKICELAKE_TRANSPARENT_MASKING", "1") == "1",
        rls_enabled=os.environ.get("DUCKICELAKE_RLS", "1") == "1",
        governance_fail_closed=os.environ.get(
            "DUCKICELAKE_GOVERNANCE_FAIL_CLOSED", "0") == "1",
        reader_group_role=os.environ.get(
            "DUCKICELAKE_READER_GROUP_ROLE", "duckicelake_reader"),
    )
