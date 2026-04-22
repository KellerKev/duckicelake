"""Write Iceberg manifest + manifest-list Avro files.

Supports v2 manifests (v3 clients read them fine) with:
- per-column stats (value/null/nan counts, lower/upper bounds)
- row lineage (first_row_id via `referenced_data_file` / file ordering)
- position delete files (content=1) alongside data files (content=0)

Hand-rolled Avro schemas per the Iceberg spec; field-ids matter for reader
correctness even though Avro doesn't use them during read.
"""
from __future__ import annotations

import datetime as _dt
import io
import json
import time
from dataclasses import dataclass, field as dc_field
from typing import Any

from fastavro import writer


# ---- schemas -----------------------------------------------------------

_PARTITION_EMPTY_SCHEMA = {"type": "record", "name": "r102", "fields": []}


def _partition_avro_schema(partition_fields: list[dict] | None) -> dict:
    """Build the Avro record schema for the `data_file.partition` field.

    Iceberg says: the partition struct's fields correspond 1:1 to the
    partition spec's fields, in order, with Avro types matching each
    transform's result type. Field-ids start at 1000.

    Empty list (or None) → empty record schema (unpartitioned tables).
    """
    if not partition_fields:
        return _PARTITION_EMPTY_SCHEMA
    fields_avro: list[dict] = []
    for pf in partition_fields:
        avro_type = pf["avro_type"]
        fields_avro.append({
            "name": pf["name"],
            # All partition fields are nullable per Iceberg — files can be
            # missing values for fields that don't apply to their content.
            "type": ["null", avro_type],
            "default": None,
            "field-id": pf["field_id"],
        })
    return {
        "type": "record",
        # Avro record names must be unique inside a schema; Iceberg writes
        # them with a predictable deterministic name so readers can match.
        "name": "r102",
        "fields": fields_avro,
    }


def _map_schema(name: str, key_id: int, key_type: str, value_id: int, value_type: Any) -> dict:
    return {
        "type": "array",
        "items": {
            "type": "record",
            "name": name,
            "fields": [
                {"name": "key",   "type": key_type, "field-id": key_id},
                {"name": "value", "type": value_type, "field-id": value_id},
            ],
        },
        "logicalType": "map",
    }


def _data_file_schema(partition_fields: list[dict] | None = None) -> dict[str, Any]:
    return {
        "type": "record",
        "name": "r2",
        "fields": [
            {"name": "content",            "type": "int", "default": 0, "field-id": 134},
            {"name": "file_path",          "type": "string", "field-id": 100},
            {"name": "file_format",        "type": "string", "field-id": 101},
            {"name": "partition",          "type": _partition_avro_schema(partition_fields), "field-id": 102},
            {"name": "record_count",       "type": "long", "field-id": 103},
            {"name": "file_size_in_bytes", "type": "long", "field-id": 104},
            {"name": "column_sizes",       "type": ["null", _map_schema("k117_v118", 117, "int", 118, "long")],  "default": None, "field-id": 108},
            {"name": "value_counts",       "type": ["null", _map_schema("k119_v120", 119, "int", 120, "long")],  "default": None, "field-id": 109},
            {"name": "null_value_counts",  "type": ["null", _map_schema("k121_v122", 121, "int", 122, "long")],  "default": None, "field-id": 110},
            {"name": "nan_value_counts",   "type": ["null", _map_schema("k138_v139", 138, "int", 139, "long")],  "default": None, "field-id": 137},
            {"name": "lower_bounds",       "type": ["null", _map_schema("k126_v127", 126, "int", 127, "bytes")], "default": None, "field-id": 125},
            {"name": "upper_bounds",       "type": ["null", _map_schema("k129_v130", 129, "int", 130, "bytes")], "default": None, "field-id": 128},
            {"name": "key_metadata",       "type": ["null", "bytes"], "default": None, "field-id": 131},
            {"name": "split_offsets",      "type": ["null", {"type": "array", "items": "long", "element-id": 133}], "default": None, "field-id": 132},
            {"name": "equality_ids",       "type": ["null", {"type": "array", "items": "int",  "element-id": 136}], "default": None, "field-id": 135},
            {"name": "sort_order_id",      "type": ["null", "int"], "default": None, "field-id": 140},
            {"name": "first_row_id",       "type": ["null", "long"], "default": None, "field-id": 142},
            {"name": "referenced_data_file", "type": ["null", "string"], "default": None, "field-id": 143},
            {"name": "content_offset",     "type": ["null", "long"], "default": None, "field-id": 144},
            {"name": "content_size_in_bytes", "type": ["null", "long"], "default": None, "field-id": 145},
        ],
    }


def _manifest_entry_schema(partition_fields: list[dict] | None = None) -> dict[str, Any]:
    return {
        "type": "record",
        "name": "manifest_entry",
        "fields": [
            {"name": "status",               "type": "int",               "field-id": 0},
            {"name": "snapshot_id",          "type": ["null", "long"], "default": None, "field-id": 1},
            {"name": "sequence_number",      "type": ["null", "long"], "default": None, "field-id": 3},
            {"name": "file_sequence_number", "type": ["null", "long"], "default": None, "field-id": 4},
            {"name": "data_file",            "type": _data_file_schema(partition_fields), "field-id": 2},
        ],
    }


def _manifest_file_schema(format_version: int = 2) -> dict[str, Any]:
    fields = [
        {"name": "manifest_path",        "type": "string", "field-id": 500},
        {"name": "manifest_length",      "type": "long",   "field-id": 501},
        {"name": "partition_spec_id",    "type": "int",    "field-id": 502},
        {"name": "content",              "type": "int",    "default": 0, "field-id": 517},
        {"name": "sequence_number",      "type": "long",   "field-id": 515},
        {"name": "min_sequence_number",  "type": "long",   "field-id": 516},
        {"name": "added_snapshot_id",    "type": "long",   "field-id": 503},
        {"name": "added_files_count",    "type": "int",    "field-id": 504},
        {"name": "existing_files_count", "type": "int",    "field-id": 505},
        {"name": "deleted_files_count",  "type": "int",    "field-id": 506},
        {"name": "added_rows_count",     "type": "long",   "field-id": 512},
        {"name": "existing_rows_count",  "type": "long",   "field-id": 513},
        {"name": "deleted_rows_count",   "type": "long",   "field-id": 514},
        {
            "name": "partitions",
            "type": ["null", {
                "type": "array",
                "items": {
                    "type": "record",
                    "name": "r508",
                    "fields": [
                        {"name": "contains_null", "type": "boolean", "field-id": 509},
                        {"name": "contains_nan",  "type": ["null", "boolean"], "default": None, "field-id": 518},
                        {"name": "lower_bound",   "type": ["null", "bytes"], "default": None, "field-id": 510},
                        {"name": "upper_bound",   "type": ["null", "bytes"], "default": None, "field-id": 511},
                    ],
                },
                "element-id": 508,
            }],
            "default": None,
            "field-id": 507,
        },
        {"name": "key_metadata", "type": ["null", "bytes"], "default": None, "field-id": 519},
    ]
    if format_version >= 3:
        # V3 adds `first_row_id` to the manifest-list record. Iceberg readers
        # that understand v3 use it for row lineage; v2-only readers ignore
        # the extra field.
        fields.append({
            "name": "first_row_id", "type": ["null", "long"],
            "default": None, "field-id": 520,
        })
    return {"type": "record", "name": "manifest_file", "fields": fields}


# ---- dataclasses callers pass in --------------------------------------

@dataclass
class DataFileStats:
    value_counts: dict[int, int] | None = None
    null_value_counts: dict[int, int] | None = None
    nan_value_counts: dict[int, int] | None = None
    lower_bounds: dict[int, bytes] | None = None
    upper_bounds: dict[int, bytes] | None = None


@dataclass
class DataFileInfo:
    file_path: str
    file_size_bytes: int
    record_count: int
    stats: DataFileStats = dc_field(default_factory=DataFileStats)
    first_row_id: int | None = None
    # Dict keyed on the Avro field NAME (same as partition-spec field name).
    # Value is the already-transform-applied partition value the Avro writer
    # will serialize — e.g. int days-since-epoch for a `day` partition.
    partition_values: dict[str, Any] = dc_field(default_factory=dict)
    # Iceberg `key_metadata` bytes for the Parquet file, surfaced from
    # DuckLake's `ducklake_data_file.encryption_key` VARCHAR. None for
    # unencrypted catalogs. Production deployments that wrap Parquet DEKs
    # via a KMS would put the wrapped blob here instead.
    key_metadata: bytes | None = None


@dataclass
class DeleteFileInfo:
    file_path: str
    file_size_bytes: int
    record_count: int          # = delete_count (cardinality for DV)
    referenced_data_file: str | None = None
    # v3 Puffin deletion-vector fields. When `file_format='puffin'`, the
    # manifest entry carries `content_offset` + `content_size_in_bytes`
    # pointing at the DV blob inside the Puffin file; readers decode the
    # Roaring bitmap there. Legacy position-delete Parquets leave these
    # None and `file_format='parquet'` (default).
    file_format: str = "parquet"
    content_offset: int | None = None
    content_size_in_bytes: int | None = None


# ---- writers ----------------------------------------------------------

def _map_to_avro(m: dict[int, Any] | None) -> list[dict[str, Any]] | None:
    if m is None:
        return None
    return [{"key": int(k), "value": v} for k, v in sorted(m.items())]


def _data_file_record(
    *, content: int, file_path: str, file_size_bytes: int, record_count: int,
    stats: DataFileStats = DataFileStats(),
    first_row_id: int | None = None,
    referenced_data_file: str | None = None,
    partition_values: dict[str, Any] | None = None,
    key_metadata: bytes | None = None,
    file_format: str = "PARQUET",
    content_offset: int | None = None,
    content_size_in_bytes: int | None = None,
) -> dict[str, Any]:
    return {
        "content": content,
        "file_path": file_path,
        "file_format": file_format,
        "partition": partition_values or {},
        "record_count": record_count,
        "file_size_in_bytes": file_size_bytes,
        "column_sizes": None,
        "value_counts":      _map_to_avro(stats.value_counts),
        "null_value_counts": _map_to_avro(stats.null_value_counts),
        "nan_value_counts":  _map_to_avro(stats.nan_value_counts),
        "lower_bounds":      _map_to_avro(stats.lower_bounds),
        "upper_bounds":      _map_to_avro(stats.upper_bounds),
        "key_metadata": key_metadata,
        "split_offsets": None,
        "equality_ids": None,
        "sort_order_id": 0,
        "first_row_id": first_row_id,
        "referenced_data_file": referenced_data_file,
        "content_offset": content_offset,
        "content_size_in_bytes": content_size_in_bytes,
    }


def _write_manifest(
    *,
    snapshot_id: int,
    sequence_number: int,
    schema_json: dict[str, Any],
    partition_spec_json: dict[str, Any],
    entries: list[dict[str, Any]],
    content_tag: str,
    partition_fields_avro: list[dict] | None = None,
    format_version: int = 2,
) -> bytes:
    buf = io.BytesIO()
    writer(
        buf,
        _manifest_entry_schema(partition_fields_avro),
        entries,
        metadata={
            "schema": json.dumps(schema_json),
            "schema-id": str(schema_json.get("schema-id", 0)),
            "partition-spec": json.dumps(partition_spec_json.get("fields", [])),
            "partition-spec-id": str(partition_spec_json.get("spec-id", 0)),
            "format-version": str(format_version),
            "content": content_tag,
        },
        codec="deflate",
    )
    return buf.getvalue()


def write_data_manifest_bytes(
    *,
    snapshot_id: int,
    sequence_number: int,
    schema_json: dict[str, Any],
    partition_spec_json: dict[str, Any],
    data_files: list[DataFileInfo],
    partition_fields_avro: list[dict] | None = None,
    format_version: int = 2,
) -> bytes:
    entries = []
    for f in data_files:
        entries.append({
            "status": 1,
            "snapshot_id": snapshot_id,
            "sequence_number": sequence_number,
            "file_sequence_number": sequence_number,
            "data_file": _data_file_record(
                content=0,
                file_path=f.file_path,
                file_size_bytes=f.file_size_bytes,
                record_count=f.record_count,
                stats=f.stats,
                first_row_id=f.first_row_id,
                partition_values=f.partition_values,
                key_metadata=f.key_metadata,
            ),
        })
    return _write_manifest(
        snapshot_id=snapshot_id,
        sequence_number=sequence_number,
        schema_json=schema_json,
        partition_spec_json=partition_spec_json,
        entries=entries,
        content_tag="data",
        partition_fields_avro=partition_fields_avro,
        format_version=format_version,
    )


def write_delete_manifest_bytes(
    *,
    snapshot_id: int,
    sequence_number: int,
    schema_json: dict[str, Any],
    partition_spec_json: dict[str, Any],
    delete_files: list[DeleteFileInfo],
    format_version: int = 2,
) -> bytes:
    entries = []
    for f in delete_files:
        entries.append({
            "status": 1,
            "snapshot_id": snapshot_id,
            "sequence_number": sequence_number,
            "file_sequence_number": sequence_number,
            "data_file": _data_file_record(
                content=1,  # position deletes (v2) or DV (v3 puffin)
                file_path=f.file_path,
                file_size_bytes=f.file_size_bytes,
                record_count=f.record_count,
                referenced_data_file=f.referenced_data_file,
                file_format=f.file_format.upper(),
                content_offset=f.content_offset,
                content_size_in_bytes=f.content_size_in_bytes,
            ),
        })
    return _write_manifest(
        snapshot_id=snapshot_id,
        sequence_number=sequence_number,
        schema_json=schema_json,
        partition_spec_json=partition_spec_json,
        entries=entries,
        content_tag="deletes",
        format_version=format_version,
    )


def write_manifest_list_bytes(
    *,
    snapshot_id: int,
    parent_snapshot_id: int | None,
    sequence_number: int,
    manifest_refs: list[tuple[str, int, str]],     # (path, length, "data"/"deletes")
    data_file_count: int,
    data_row_count: int,
    format_version: int = 2,
    first_row_id: int | None = None,
) -> bytes:
    """Serialise an Iceberg manifest-list Avro.

    `format_version` controls both the Avro schema and the `format-version`
    metadata entry. When 3, emits the v3-only `first_row_id` column on each
    entry (NULL for ours since DuckLake doesn't track row-lineage that way)
    and the Avro-level `first-row-id` metadata key (at the snapshot level).
    """
    entries = []
    for path, length, kind in manifest_refs:
        entry: dict[str, Any] = {
            "manifest_path": path,
            "manifest_length": length,
            "partition_spec_id": 0,
            "content": 0 if kind == "data" else 1,
            "sequence_number": sequence_number,
            "min_sequence_number": sequence_number,
            "added_snapshot_id": snapshot_id,
            "added_files_count": 1 if kind == "data" else 0,
            "existing_files_count": 0,
            "deleted_files_count": 1 if kind == "deletes" else 0,
            "added_rows_count": data_row_count if kind == "data" else 0,
            "existing_rows_count": 0,
            "deleted_rows_count": 0 if kind == "data" else 0,
            "partitions": None,
            "key_metadata": None,
        }
        if format_version >= 3:
            entry["first_row_id"] = None
        entries.append(entry)

    metadata = {
        "snapshot-id": str(snapshot_id),
        "parent-snapshot-id": "null" if parent_snapshot_id is None else str(parent_snapshot_id),
        "sequence-number": str(sequence_number),
        "format-version": str(format_version),
    }
    if format_version >= 3:
        metadata["first-row-id"] = str(first_row_id or 0)

    buf = io.BytesIO()
    writer(
        buf,
        _manifest_file_schema(format_version=format_version),
        entries,
        metadata=metadata,
        codec="deflate",
    )
    return buf.getvalue()


def build_snapshot(
    *,
    snapshot_id: int,
    parent_snapshot_id: int | None,
    sequence_number: int,
    manifest_list_path: str,
    added_files_count: int,
    added_rows_count: int,
    total_files: int,
    total_rows: int,
    schema_id: int = 0,
    timestamp_dt: _dt.datetime | None = None,
    operation: str = "append",
) -> dict[str, Any]:
    """Return a `snapshots[]` entry for TableMetadata.

    Two constraints on `timestamp-ms`:
    - must be <= client's transaction start time (DuckDB's
      `IcebergTableEntry::GetSnapshot` rejects otherwise) — we backdate by
      1s when the DuckLake snapshot time is "now" on the nose
    - must be monotonically non-decreasing across the snapshot chain
    """
    if timestamp_dt is not None:
        ts_ms = int(timestamp_dt.timestamp() * 1000)
    else:
        ts_ms = int(time.time() * 1000) - 1000

    snap: dict[str, Any] = {
        "snapshot-id": snapshot_id,
        "timestamp-ms": ts_ms,
        "sequence-number": sequence_number,
        "summary": {
            "operation": operation,
            "added-data-files": str(added_files_count),
            "added-records": str(added_rows_count),
            "total-data-files": str(total_files),
            "total-records": str(total_rows),
            "total-files-size": "0",
            "total-delete-files": "0",
            "total-position-deletes": "0",
            "total-equality-deletes": "0",
        },
        "manifest-list": manifest_list_path,
        "schema-id": schema_id,
    }
    if parent_snapshot_id is not None:
        snap["parent-snapshot-id"] = parent_snapshot_id
    return snap
