"""SQL quoting + validation for everything the proxy interpolates into SQL.

The write/export connections hold the catalog owner's ATTACH and root S3
credentials, so any client-supplied text that reaches them (namespace, table,
column and view names, column defaults, view bodies) must be either quoted
here or rejected before it gets that far.
"""
from __future__ import annotations

import math
import re
import threading
from typing import Any

import duckdb


def qi(name: str) -> str:
    """Quote a SQL identifier, escaping any embedded double-quote so a
    name like `a"b` can't break out of the quoting."""
    return '"' + name.replace('"', '""') + '"'


def ql(value: str) -> str:
    """Quote a SQL string literal, escaping embedded single-quotes."""
    return "'" + value.replace("'", "''") + "'"


def literal(value: Any) -> str:
    """Render a JSON scalar (an Iceberg column default) as a SQL literal.
    Strings are quoted; numbers must be finite; anything else is refused."""
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite default {value!r}")
        return repr(value)
    if isinstance(value, str):
        return ql(value)
    raise ValueError(f"unsupported default value type {type(value).__name__}")


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# Reserved for the governance machinery: masked-view schemas (`__masked_<sig>`)
# and the masked-export S3 area (`<data_prefix>__masked__/`). A client-created
# namespace or table under these names could shadow masking views or write
# into another table's masked exports.
_RESERVED_PREFIX = "__masked"


def check_identifier(name: Any, what: str, *, reserved: bool = False) -> str:
    """Validate a client-supplied identifier. Quoting (qi) is what makes it
    safe in SQL; this rejects names that are unsafe elsewhere — S3 key
    segments (`/`), logs/headers (control characters) — or that collide with
    governance-reserved names when `reserved` is set."""
    if not isinstance(name, str) or not name:
        raise ValueError(f"{what} name must be a non-empty string")
    if len(name) > 255:
        raise ValueError(f"{what} name is longer than 255 characters")
    if _CONTROL.search(name):
        raise ValueError(f"{what} name contains control characters")
    if reserved:
        if "/" in name or name in (".", ".."):
            raise ValueError(f"{what} name {name!r} is not a valid path segment")
        if name.startswith(_RESERVED_PREFIX):
            raise ValueError(
                f"{what} names starting with '{_RESERVED_PREFIX}' are reserved")
    return name


_parser = threading.local()


def _parse_con() -> duckdb.DuckDBPyConnection:
    # A private in-memory connection per thread: parsing never touches data,
    # and a shared connection used from several threads at once is an error
    # in newer DuckDB clients.
    con = getattr(_parser, "con", None)
    if con is None:
        con = _parser.con = duckdb.connect()
    return con


def check_single_select(sql: str, what: str = "query", *,
                        allow: tuple = (duckdb.StatementType.SELECT,)) -> str:
    """Parse (never execute) `sql` and require exactly one statement of an
    allowed type (SELECT by default), so text interpolated into `CREATE VIEW …
    AS` / `COPY (…)`, or agent SQL, can't smuggle in a second statement."""
    try:
        stmts = _parse_con().extract_statements(sql)
    except duckdb.Error as e:
        raise ValueError(f"{what} does not parse: {e}") from None
    if len(stmts) != 1 or stmts[0].type not in allow:
        raise ValueError(f"{what} must be exactly one SELECT statement")
    return sql
