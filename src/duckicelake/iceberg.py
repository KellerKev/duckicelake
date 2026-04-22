"""Iceberg v3 TableMetadata construction.

Given DuckLake's column list + data path, build the TableMetadata JSON
structure that the Iceberg REST catalog API hands back to clients.

We intentionally keep this minimal: one schema, empty partition spec, empty
sort order, no snapshots. Iceberg clients that only consult the catalog for
metadata (e.g. schema discovery) will work; clients that try to read data
files via snapshots won't find any — they'd need a snapshot wired up by the
commit endpoint, which is out of scope for this prototype.
"""
from __future__ import annotations

import time
from typing import Any

from .catalog import ColumnInfo
from .types import duckdb_type_to_iceberg


# Default format-version for newly created tables. v2 stays the default
# because most writer clients in the wild still only write v2 manifests.
# The proxy now accepts `upgrade-format-version` to 3 — PyIceberg clients
# that install `pyiceberg_v3` (our shim) or run a patched pyiceberg 0.12+
# can transition and write v3 from that point forward. Ops can flip the
# default to 3 via DUCKICELAKE_DEFAULT_FORMAT_VERSION when the writer
# ecosystem catches up broadly.
import os as _os
ICEBERG_FORMAT_VERSION = int(_os.environ.get("DUCKICELAKE_DEFAULT_FORMAT_VERSION", "2"))


def columns_to_schema(columns: list[ColumnInfo], schema_id: int = 0) -> dict[str, Any]:
    fields = []
    for i, col in enumerate(columns, start=1):
        fields.append(
            {
                "id": i,
                "name": col.name,
                "required": not col.is_nullable,
                "type": duckdb_type_to_iceberg(col.data_type),
            }
        )
    return {"schema-id": schema_id, "type": "struct", "fields": fields}


def build_table_metadata(
    *,
    table_uuid: str,
    location: str,
    columns: list[ColumnInfo],
    properties: dict[str, str] | None = None,
) -> dict[str, Any]:
    schema = columns_to_schema(columns, schema_id=0)
    now_ms = int(time.time() * 1000)
    last_column_id = max((f["id"] for f in schema["fields"]), default=0)

    return {
        "format-version": ICEBERG_FORMAT_VERSION,
        "table-uuid": table_uuid,
        "location": location,
        "last-sequence-number": 0,
        "last-updated-ms": now_ms,
        "last-column-id": last_column_id,
        "current-schema-id": 0,
        "schemas": [schema],
        "default-spec-id": 0,
        "partition-specs": [{"spec-id": 0, "fields": []}],
        "last-partition-id": 999,
        "default-sort-order-id": 0,
        "sort-orders": [{"order-id": 0, "fields": []}],
        "properties": properties or {},
        "current-snapshot-id": -1,
        "refs": {},
        "snapshots": [],
        "statistics": [],
        "partition-statistics": [],
        "snapshot-log": [],
        "metadata-log": [],
    }


def schema_to_columns_ddl(schema: dict[str, Any]) -> tuple[str, int]:
    """Translate an Iceberg create-table schema into a DuckDB column DDL string.

    Returns (ddl, last_column_id).
    """
    from .types import iceberg_type_to_duckdb

    fields = schema.get("fields", [])
    parts = []
    last_id = 0
    for f in fields:
        col_name = f["name"]
        col_type = iceberg_type_to_duckdb(f["type"])
        required = bool(f.get("required", False))
        null_clause = " NOT NULL" if required else ""
        parts.append(f'"{col_name}" {col_type}{null_clause}')
        last_id = max(last_id, int(f.get("id", 0)))
    return ", ".join(parts), last_id
