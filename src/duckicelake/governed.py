"""A DuckDB session that sees exactly what a vended credential bundle allows.

Shared by every place the proxy runs caller SQL itself (the MCP/SMCP agent
executor, the result-set cache): the connection ATTACHes the vended RLS
reader (READ_ONLY), reads S3 only with the vended scoped credential — never
the proxy's own keys — applies the vend's masking route (`post_attach_sql`),
and is then locked down so the SQL can't reach local files, the process
environment, or other objects in the bucket.
"""
from __future__ import annotations

from typing import Iterable

import duckdb

from .config import Settings
from .sqlsafe import qi

#: Loaded before lockdown: once locked, nothing can be (auto)loaded. `icu`
#: carries time zones and collations since DuckDB 2.0.
EXTENSIONS = ("ducklake", "postgres", "httpfs", "icu")


def setup_governed(con: duckdb.DuckDBPyConnection, settings: Settings, bundle: dict,
                   catalog_id: str, namespace: str, *,
                   extra_dirs: Iterable[str] = (),
                   memory_limit: str | None = None,
                   threads: int | None = None) -> None:
    """Configure `con` from a `ducklake-credentials` bundle, then lock it.
    `extra_dirs` are additional allowed directories (e.g. a private local
    output directory the caller COPYs a result into). Raises PermissionError
    when the bundle carries no scoped S3 credential (fail closed)."""
    vended = bundle.get("s3") or {}
    if not vended.get("access-key-id"):
        raise PermissionError(
            f"no scoped S3 credentials were vended ({bundle.get('vend_status') or 'none'})")
    for ext in EXTENSIONS:
        con.execute(f"INSTALL {ext}")
        con.execute(f"LOAD {ext}")
    s3 = settings.s3
    # Point DuckDB at the VENDED endpoint: the S3 gateway (and STS) hand back
    # their own endpoint, and gateway creds only work against the gateway.
    v_ep = vended.get("endpoint")
    if v_ep:
        endpoint = v_ep.rsplit("://", 1)[-1]
        use_ssl = v_ep.startswith("https")
        url_style = "path" if vended.get("path-style-access", s3.path_style) else "vhost"
    else:
        endpoint, use_ssl = s3.host, s3.use_ssl
        url_style = "path" if s3.path_style else "vhost"
    con.execute(
        "CREATE OR REPLACE SECRET s (TYPE S3, KEY_ID ?, SECRET ?, "
        "REGION ?, ENDPOINT ?, USE_SSL ?, URL_STYLE ?"
        + (", SESSION_TOKEN ?" if vended.get("session-token") else "") + ")",
        [vended["access-key-id"], vended.get("secret-access-key"),
         s3.region, endpoint, use_ssl, url_style]
        + ([vended["session-token"]] if vended.get("session-token") else []),
    )
    con.execute(bundle["ducklake_attach_sql"])
    post = bundle.get("post_attach_sql") or []
    if post:
        for stmt in post:            # masked-view route (column masking)
            con.execute(stmt)
    else:                            # no masking policy: default to the ns
        con.execute(f"USE {qi(catalog_id)}.{qi(namespace)}")
    if memory_limit:
        con.execute("SET memory_limit = ?", [memory_limit])
    if threads:
        con.execute(f"SET threads = {int(threads)}")
    con.execute("SET allowed_directories = ?",
                [[bundle["ducklake_data_path"], *extra_dirs]])
    con.execute("SET enable_external_access = false")
    con.execute("SET lock_configuration = true")
