"""Translate Iceberg partition specs and sort orders to/from DuckLake.

Iceberg vocabulary (from PartitionField / SortField):
  transform: identity | year | month | day | hour | bucket[N] | truncate[L] | void

DuckLake vocabulary (from `ducklake_partition_column.transform` and the
`ALTER TABLE SET PARTITIONED BY` parser):
  identity | year | month | day | hour | bucket(N)

Truncate and void are NOT supported by DuckLake's partition implementation
(verified against the v1.0 source / tested with `ALTER TABLE`). Iceberg
specs that include them must be rejected at commit time.

For sort orders, DuckLake's storage is more permissive — it accepts
arbitrary SQL expressions in `ducklake_sort_expression.expression` along
with a dialect column. We pass through Iceberg sort transforms as
`identity` since Iceberg sort fields are typically sorted on the
identity-projected column.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


_BUCKET_RE = re.compile(r"^bucket\[(\d+)\]$")
_TRUNCATE_RE = re.compile(r"^truncate\[(\d+)\]$")


class UnsupportedPartitionTransform(Exception):
    """Raised when an Iceberg partition transform has no DuckLake equivalent."""


@dataclass
class IcebergPartitionField:
    name: str          # client-friendly name (we don't persist it; DuckLake uses col name)
    source_id: int     # Iceberg column field-id
    transform: str     # identity / year / month / day / hour / bucket[N] / truncate[L] / void
    field_id: int      # Iceberg partition-spec-internal id


def is_native_ducklake_transform(transform: str) -> bool:
    """True when `iceberg_transform_to_ducklake_sql` would accept the
    transform — i.e. DuckLake can express it in SET PARTITIONED BY."""
    t = transform.strip().lower()
    if t == "identity":
        return True
    if t in {"year", "month", "day", "hour"}:
        return True
    if _BUCKET_RE.match(t):
        return True
    return False


@dataclass
class IcebergSortField:
    source_id: int
    transform: str     # almost always 'identity' in practice
    direction: str     # asc | desc
    null_order: str    # nulls-first | nulls-last


def iceberg_transform_to_ducklake_sql(
    transform: str, column_name: str
) -> str:
    """Translate one Iceberg partition transform into the DuckDB syntax that
    `ALTER TABLE x SET PARTITIONED BY (...)` accepts.

    Raises UnsupportedPartitionTransform for transforms DuckLake can't express.
    """
    t = transform.strip().lower()

    if t == "identity":
        return f'"{column_name}"'
    if t in {"year", "month", "day", "hour"}:
        return f'{t}("{column_name}")'

    m = _BUCKET_RE.match(t)
    if m:
        return f'bucket({int(m.group(1))}, "{column_name}")'

    m = _TRUNCATE_RE.match(t)
    if m:
        raise UnsupportedPartitionTransform(
            f"Iceberg `truncate[N]` is not supported by DuckLake. "
            f"Use `identity` or one of year/month/day/hour/bucket[N]."
        )

    if t == "void":
        raise UnsupportedPartitionTransform(
            "Iceberg `void` (drop column from partition spec) is not "
            "supported. Drop the column from the partition spec by "
            "submitting a new `add-partition-spec` without it."
        )

    raise UnsupportedPartitionTransform(
        f"Unknown / unsupported Iceberg partition transform: {transform!r}. "
        f"DuckLake supports identity, year, month, day, hour, bucket[N]."
    )


def ducklake_transform_to_iceberg(transform: str) -> str:
    """Inverse: DuckLake's `ducklake_partition_column.transform` →
    Iceberg-spec transform string.
    """
    t = transform.strip().lower()
    if t == "identity":
        return "identity"
    if t in {"year", "month", "day", "hour"}:
        return t

    m = re.match(r"^bucket\((\d+)\)$", t)
    if m:
        return f"bucket[{int(m.group(1))}]"

    # Fallback: pass through. Reader-side treats unknown as identity.
    return "identity"


def iceberg_partition_fields_to_alter_clause(
    fields: list[IcebergPartitionField],
    column_name_by_id: dict[int, str],
) -> str:
    """Build the parenthesised expression list for
    `ALTER TABLE x SET PARTITIONED BY ( <here> )`.

    `column_name_by_id` maps the Iceberg `source-id` to the DuckLake column
    name (since Iceberg specs reference fields by id, not name).
    """
    if not fields:
        # Iceberg "set unpartitioned" — DuckLake supports clearing.
        return ""
    pieces: list[str] = []
    for f in fields:
        col_name = column_name_by_id.get(f.source_id)
        if not col_name:
            raise ValueError(
                f"partition-spec field source-id={f.source_id} not found in "
                f"current table schema"
            )
        pieces.append(iceberg_transform_to_ducklake_sql(f.transform, col_name))
    return ", ".join(pieces)


def normalize_iceberg_sort_fields(
    fields: list[dict],
) -> list[IcebergSortField]:
    """Coerce raw JSON sort-field dicts into typed records."""
    out = []
    for raw in fields:
        out.append(IcebergSortField(
            source_id=int(raw["source-id"]),
            transform=str(raw.get("transform", "identity")),
            direction=str(raw.get("direction", "asc")),
            null_order=str(raw.get("null-order", "nulls-last")),
        ))
    return out
