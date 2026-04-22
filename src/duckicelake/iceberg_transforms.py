"""Iceberg partition-transform computation.

DuckLake stores per-file partition values under its own naming conventions:
  - `identity`   — the source column value (matches Iceberg)
  - `bucket(N)`  — integer bucket ordinal, hashed compatibly with Iceberg
                   (verified: both give `(murmur3 & INT_MAX) % N` for int64s)
  - `day`        — DAY OF MONTH (1–31), not Iceberg's days-since-epoch
  - `month`      — MONTH OF YEAR (1–12), not months-since-epoch
  - `year`       — calendar YEAR (e.g. 2026), not years-since-1970
  - `hour`       — HOUR OF DAY (0–23), not hours-since-epoch

For the time-based transforms, we need to **recompute** Iceberg-semantic
values from the file's source-column `min_value` stat. DuckLake writes one
partitioned file per unique (day-of-month, bucket, identity) tuple — so
within a single DuckLake-written file, every row shares the same Iceberg
day/month/year/hour (modulo the rare edge case of a file spanning calendar
years that happen to have the same day-of-month; that's caller-visible as
the min/max bounds in the manifest).

For identity and bucket, DuckLake's value can be used verbatim.

All transforms return int32 or the native source type; Avro encodes those
directly into the manifest's `data_file.partition` substruct.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any


_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
_EPOCH_DATE = _dt.date(1970, 1, 1)


def _to_utc_dt(value: Any) -> _dt.datetime:
    """Coerce a DuckLake `min_value` stat (VARCHAR) into a UTC datetime.

    DuckLake writes timestamps as e.g. "2026-04-21 00:00:00+00" or
    "2026-04-21 00:00:00+02" depending on the local session TZ at write
    time. We normalise to UTC because Iceberg transform outputs are
    UTC-relative.
    """
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)
    s = str(value).strip()
    # DuckDB omits the minutes in the offset sometimes (`+00` rather than `+00:00`).
    # Python's fromisoformat needs the full offset.
    if len(s) >= 3 and (s[-3] in "+-") and ":" not in s[-3:]:
        s = s + ":00"
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    try:
        dt = _dt.datetime.fromisoformat(s)
    except ValueError:
        # Fall back to date-only.
        d = _dt.date.fromisoformat(s.split("T", 1)[0])
        return _dt.datetime(d.year, d.month, d.day, tzinfo=_dt.timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc)


def _to_date(value: Any) -> _dt.date:
    if isinstance(value, _dt.datetime):
        return value.astimezone(_dt.timezone.utc).date()
    if isinstance(value, _dt.date):
        return value
    s = str(value).strip()
    return _dt.date.fromisoformat(s.split(" ", 1)[0].split("T", 1)[0])


# ---- Iceberg transforms ------------------------------------------------


def apply_year(value: Any) -> int:
    """Years since 1970 — Iceberg `year` transform on a date/timestamp."""
    dt = _to_utc_dt(value) if _looks_like_timestamp(value) else _to_date(value)
    if isinstance(dt, _dt.datetime):
        return dt.year - 1970
    return dt.year - 1970


def apply_month(value: Any) -> int:
    """Months since 1970-01 — Iceberg `month` transform."""
    dt = _to_utc_dt(value) if _looks_like_timestamp(value) else _to_date(value)
    if isinstance(dt, _dt.datetime):
        return (dt.year - 1970) * 12 + (dt.month - 1)
    return (dt.year - 1970) * 12 + (dt.month - 1)


def apply_day(value: Any) -> int:
    """Days since 1970-01-01 — Iceberg `day` transform."""
    if _looks_like_timestamp(value):
        dt = _to_utc_dt(value)
        return (dt.date() - _EPOCH_DATE).days
    d = _to_date(value)
    return (d - _EPOCH_DATE).days


def apply_hour(value: Any) -> int:
    """Hours since 1970-01-01 00:00 UTC — Iceberg `hour` transform."""
    dt = _to_utc_dt(value)
    delta = dt - _EPOCH
    return int(delta.total_seconds() // 3600)


def apply_identity(value: Any) -> Any:
    """Identity — the source value. Type-coerce strings for primitives
    where DuckLake stats come back as VARCHAR."""
    # Let the caller type-cast in the Avro writer path.
    return value


def apply_truncate(value: Any, width: int, source_iceberg_type: str) -> Any:
    """Iceberg `truncate[L]` applied to a DuckLake min_value stat.

    - int/long: `v - ((v % L + L) % L)` (handles negatives per Iceberg spec).
    - decimal: round-towards-negative-infinity to `L`-unit multiple; we emit
      the scaled integer form that matches DuckLake's stored min.
    - string: first L Unicode code points.
    - binary: first L bytes (not yet wired here — binary min stats are rare).
    """
    t = source_iceberg_type.lower()
    if t in {"int", "long"}:
        v = int(value)
        return v - ((v % width + width) % width)
    if t.startswith("decimal"):
        # DuckLake stats store decimal values as their display string; parse
        # through Python Decimal so we don't lose precision.
        from decimal import Decimal
        d = Decimal(str(value))
        w = Decimal(width)
        # floor-divide then multiply, staying within Decimal arithmetic.
        return str(d - (d % w + w) % w)
    if t == "string":
        s = str(value)
        return s[:width]
    # Fallback: leave unchanged (caller sees identity).
    return value


def _looks_like_timestamp(value: Any) -> bool:
    if isinstance(value, _dt.datetime):
        return True
    if isinstance(value, _dt.date):
        return False
    s = str(value)
    return ":" in s  # crude: "2026-04-21 00:00:00+00" vs "2026-04-21"


# ---- DuckLake → Iceberg dispatcher -------------------------------------


def duckLake_stored_to_iceberg(
    ducklake_transform: str,
    ducklake_stored_value: str | None,
    source_min_value: str | None,
    source_iceberg_type: str,
) -> Any:
    """Compute the Iceberg-correct partition value for one (file, field).

    - `ducklake_transform` comes from `ducklake_partition_column.transform`
      (e.g. 'identity', 'day', 'month', 'year', 'hour', 'bucket(N)').
    - `ducklake_stored_value` is `ducklake_file_partition_value.partition_value`
      for this file and key. Trusted for `identity` and `bucket(N)` (both
      semantics-aligned with Iceberg). Ignored for time-based transforms
      (DuckLake's semantics differ; see module docstring).
    - `source_min_value` is the source column's `min_value` from
      `ducklake_file_column_stats`. Used to recompute time-based transforms.

    Returns a Python value Avro will encode; None if we can't determine it.
    """
    t = ducklake_transform.strip().lower()

    if t == "identity":
        if ducklake_stored_value is None:
            return None
        return _coerce_identity_value(ducklake_stored_value, source_iceberg_type)

    if t.startswith("bucket"):
        if ducklake_stored_value is None:
            return None
        return int(ducklake_stored_value)

    if t in {"year", "month", "day", "hour"}:
        if source_min_value is None:
            return None
        try:
            return {
                "year": apply_year,
                "month": apply_month,
                "day": apply_day,
                "hour": apply_hour,
            }[t](source_min_value)
        except Exception:
            return None

    # truncate[L] — stored DuckLake value unused (DuckLake doesn't
    # physically partition on truncate); compute from source min.
    import re as _re
    m = _re.match(r"^truncate\[(\d+)\]$", t)
    if m:
        if source_min_value is None:
            return None
        try:
            return apply_truncate(source_min_value, int(m.group(1)), source_iceberg_type)
        except Exception:
            return None

    return None


def _coerce_identity_value(s: str, iceberg_type: str) -> Any:
    """DuckLake stores all partition values as VARCHAR, even for int / bool
    / timestamp columns. Coerce back to the native type Avro expects.
    """
    t = iceberg_type.lower()
    try:
        if t in {"int", "long"}:
            return int(s)
        if t in {"float", "double"}:
            return float(s)
        if t == "boolean":
            return s.strip().lower() in {"true", "t", "1"}
        if t == "date":
            d = _to_date(s)
            return (d - _EPOCH_DATE).days
        if t in {"timestamp", "timestamptz"}:
            dt = _to_utc_dt(s)
            delta = dt - _EPOCH
            return int(delta.total_seconds() * 1_000_000) + (delta.microseconds % 1_000_000 if False else 0)
    except Exception:
        return None
    # string / uuid / binary / fallback
    return s


def iceberg_partition_field_avro_type(
    ducklake_transform: str, source_iceberg_type: str,
) -> str:
    """Return the Avro type string for a partition field given its
    DuckLake transform + source Iceberg type.

    Bucket always produces int. Time transforms all produce int (days/
    hours/months/years since epoch). Identity preserves source type.
    """
    t = ducklake_transform.strip().lower()
    if t in {"year", "month", "day", "hour"}:
        return "int"
    if t.startswith("bucket"):
        return "int"
    if t.startswith("truncate"):
        # truncate preserves source type.
        pass
    # identity
    st = source_iceberg_type.lower()
    if st == "int":
        return "int"
    if st == "long":
        return "long"
    if st == "float":
        return "float"
    if st == "double":
        return "double"
    if st == "boolean":
        return "boolean"
    if st == "date":
        return "int"   # days since epoch
    if st in {"timestamp", "timestamptz"}:
        return "long"  # micros since epoch
    if st == "string":
        return "string"
    if st == "uuid":
        return "string"
    if st == "binary":
        return "bytes"
    return "string"
