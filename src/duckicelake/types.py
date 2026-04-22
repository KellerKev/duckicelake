"""Type translation between Iceberg and DuckDB / DuckLake.

Three vocabularies, three-way mapping:
- Iceberg spec types (what REST clients send and we emit on LoadTable):
    primitives: boolean, int, long, float, double, date, time, timestamp,
      timestamptz, timestamp_ns, timestamptz_ns, string, uuid, binary,
      fixed[N], decimal(p,s), variant, geometry, geography
    nested: struct<>, list<T>, map<K,V>
- DuckDB SQL types (used in CREATE TABLE / information_schema):
    BOOLEAN, INTEGER, BIGINT, VARCHAR, DECIMAL(p,s), DATE, TIME, TIMESTAMP,
    TIMESTAMP WITH TIME ZONE, TIMESTAMP_NS, UUID, BLOB, VARIANT, GEOMETRY, …
- DuckLake internal column_type strings (persisted in ducklake_column):
    int64, varchar, timestamptz, decimal(10,2), … — lowercased, mostly
    DuckDB-flavoured with a few historical names.

We need all three directions because different code paths consume different
sources.
"""
from __future__ import annotations

import re
from typing import Any


# --- Iceberg primitive -> DuckDB SQL type (CREATE TABLE) ---------------

_ICEBERG_TO_DUCKDB: dict[str, str] = {
    "boolean": "BOOLEAN",
    "int": "INTEGER",
    "long": "BIGINT",
    "float": "FLOAT",
    "double": "DOUBLE",
    "date": "DATE",
    "time": "TIME",
    "timestamp": "TIMESTAMP",
    "timestamptz": "TIMESTAMP WITH TIME ZONE",
    "timestamp_ns": "TIMESTAMP_NS",
    "timestamptz_ns": "TIMESTAMP_NS",
    "string": "VARCHAR",
    "uuid": "UUID",
    "binary": "BLOB",
    "variant": "VARIANT",
    "geometry": "GEOMETRY",
    "geography": "GEOMETRY",  # DuckDB's spatial has no distinct geography
}


# --- DuckDB type (upper, normalised) -> Iceberg primitive --------------

_DUCKDB_TO_ICEBERG: dict[str, str] = {
    "BOOLEAN": "boolean",
    "TINYINT": "int",
    "SMALLINT": "int",
    "INTEGER": "int",
    "BIGINT": "long",
    "HUGEINT": "long",
    "UTINYINT": "int",
    "USMALLINT": "int",
    "UINTEGER": "long",
    "UBIGINT": "long",
    "FLOAT": "float",
    "REAL": "float",
    "DOUBLE": "double",
    "DATE": "date",
    "TIME": "time",
    "TIMESTAMP": "timestamp",
    "TIMESTAMP WITH TIME ZONE": "timestamptz",
    "TIMESTAMPTZ": "timestamptz",
    "TIMESTAMP_NS": "timestamp_ns",
    "TIMESTAMP_MS": "timestamp",
    "TIMESTAMP_S":  "timestamp",
    "VARCHAR": "string",
    "TEXT": "string",
    "UUID": "uuid",
    "BLOB": "binary",
    "BYTEA": "binary",
    "VARIANT": "variant",
    "GEOMETRY": "geometry",
}


# --- DuckLake internal column_type -> Iceberg primitive -----------------
# (lowercased, pipe-to-DuckDB mapping)

_DUCKLAKE_TO_ICEBERG: dict[str, str] = {
    "bool": "boolean",
    "boolean": "boolean",
    "tinyint": "int",
    "smallint": "int",
    "int": "int",
    "integer": "int",
    "int32": "int",
    "int64": "long",
    "bigint": "long",
    "hugeint": "long",
    "float": "float",
    "float32": "float",
    "double": "double",
    "float64": "double",
    "date": "date",
    "time": "time",
    "timestamp": "timestamp",
    "timestamp_s": "timestamp",
    "timestamp_ms": "timestamp",
    "timestamp_ns": "timestamp_ns",
    "timestamptz": "timestamptz",
    "timestamp with time zone": "timestamptz",
    "varchar": "string",
    "string": "string",
    "text": "string",
    "uuid": "uuid",
    "blob": "binary",
    "binary": "binary",
    "variant": "variant",
    "geometry": "geometry",
    "geography": "geography",
}


_DECIMAL_RE = re.compile(r"^DECIMAL\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)$", re.IGNORECASE)
_FIXED_RE = re.compile(r"^fixed\[\s*(\d+)\s*\]$", re.IGNORECASE)


def iceberg_type_to_duckdb(t: Any) -> str:
    """Convert an Iceberg type to a DuckDB SQL type for CREATE TABLE."""
    if isinstance(t, dict):
        kind = t.get("type")
        if kind == "struct":
            fields = t.get("fields", [])
            parts = [
                f'"{f["name"]}" {iceberg_type_to_duckdb(f["type"])}'
                for f in fields
            ]
            return f"STRUCT({', '.join(parts)})"
        if kind == "list":
            return f"{iceberg_type_to_duckdb(t['element'])}[]"
        if kind == "map":
            k = iceberg_type_to_duckdb(t["key"])
            v = iceberg_type_to_duckdb(t["value"])
            return f"MAP({k}, {v})"
        raise ValueError(f"Unsupported Iceberg nested type: {t!r}")

    if not isinstance(t, str):
        raise ValueError(f"Unsupported Iceberg type: {t!r}")

    lower = t.lower()
    if lower in _ICEBERG_TO_DUCKDB:
        return _ICEBERG_TO_DUCKDB[lower]

    m = _DECIMAL_RE.match(t.upper())
    if m:
        return f"DECIMAL({int(m.group(1))}, {int(m.group(2))})"

    if _FIXED_RE.match(t):
        return "BLOB"

    raise ValueError(f"Unsupported Iceberg primitive type: {t!r}")


def duckdb_type_to_iceberg(t: str) -> Any:
    """Convert a DuckDB type (from information_schema.columns) to Iceberg."""
    upper = t.upper().strip()

    m = _DECIMAL_RE.match(upper)
    if m:
        return f"decimal({int(m.group(1))}, {int(m.group(2))})"

    if upper in _DUCKDB_TO_ICEBERG:
        return _DUCKDB_TO_ICEBERG[upper]

    return upper.lower()


def ducklake_type_to_iceberg(t: str) -> Any:
    """Convert a DuckLake internal column_type string to Iceberg.

    DuckLake stores lowercased names like 'int64', 'varchar', 'timestamptz',
    'decimal(10,2)'. Mostly overlapping with DuckDB but not always.
    """
    lower = t.lower().strip()

    m = re.match(r"^decimal\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)$", lower)
    if m:
        return f"decimal({int(m.group(1))}, {int(m.group(2))})"

    if lower in _DUCKLAKE_TO_ICEBERG:
        return _DUCKLAKE_TO_ICEBERG[lower]

    # Nested types — DuckLake stores them as DuckDB-style text; fall through
    # to the DuckDB mapper which handles upper-case.
    return duckdb_type_to_iceberg(t)
