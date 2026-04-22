"""Iceberg single-value serialization for column bounds.

DuckLake stores per-file min/max values as VARCHAR strings in
`ducklake_file_column_stats`. Iceberg expects them as type-specific binary
encodings stored in the manifest `lower_bounds` / `upper_bounds` maps.

Reference: Apache Iceberg spec, Appendix D "Single-value serialization".

We support the primitive types we emit from DuckLake today. Nested types
(struct/list/map) aren't statistics-eligible in Iceberg anyway.
"""
from __future__ import annotations

import re
import struct
from datetime import date, datetime, time, timezone
from decimal import Decimal


_DATE_EPOCH = date(1970, 1, 1)


def _to_epoch_micros(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return int(delta.total_seconds() * 1_000_000) + (delta.microseconds % 1_000_000 if False else 0)


def _parse_datetime(s: str) -> datetime:
    """Parse DuckLake-style timestamp strings.

    Examples seen: '2026-04-21 08:00:00+00', '2026-04-21 08:00:00.123456+02'.
    """
    s = s.strip()
    # DuckDB emits the UTC offset without a colon; normalise for fromisoformat.
    if re.search(r"[+-]\d{2}$", s):
        s = s + ":00"
    elif re.search(r"[+-]\d{4}$", s):
        s = s[:-2] + ":" + s[-2:]
    # DuckDB separates date/time with a space; fromisoformat accepts that in 3.11+.
    return datetime.fromisoformat(s)


def _encode_date(s: str) -> bytes:
    d = date.fromisoformat(s.strip().split(" ")[0])
    return struct.pack("<i", (d - _DATE_EPOCH).days)


def _encode_time(s: str) -> bytes:
    t = time.fromisoformat(s.strip())
    micros = (t.hour * 3600 + t.minute * 60 + t.second) * 1_000_000 + t.microsecond
    return struct.pack("<q", micros)


def _encode_timestamp(s: str) -> bytes:
    dt = _parse_datetime(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = dt - epoch
    micros = delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds
    return struct.pack("<q", micros)


def _encode_decimal(s: str, precision: int, scale: int) -> bytes:
    d = Decimal(s.strip())
    unscaled = int(d.scaleb(scale))
    # Two's complement big-endian, minimum bytes.
    bit_length = max(unscaled.bit_length() + 1, 8)
    nbytes = (bit_length + 7) // 8
    return unscaled.to_bytes(nbytes, byteorder="big", signed=True)


_DECIMAL_RE = re.compile(r"^decimal\((\d+),\s*(\d+)\)$", re.IGNORECASE)


class UnsupportedBoundType(Exception):
    """Raised when an Iceberg type has no defined bound encoding.

    Callers catch this to skip the bound cleanly; distinct from a parse
    failure, which is a bug in the stats pipeline (wrong value for a type
    we claimed to handle) and propagates.
    """


# Iceberg types with no single-value binary form in the spec. Stats emit
# no bound for these; the field is omitted from `lower_bounds` / `upper_bounds`.
_UNBOUNDED_TYPES = frozenset({"variant", "geometry", "geography", "unknown"})


def encode_bound(iceberg_type: str, value: str) -> bytes:
    """Encode a VARCHAR stat value from DuckLake into Iceberg bound bytes.

    Raises `UnsupportedBoundType` if the Iceberg type has no defined bound
    encoding (variant, geometry, nested, …). Raises `ValueError` or the
    underlying parse/overflow error if `value` doesn't match the claimed
    type — that's a bug in our catalog pipeline and should be surfaced.
    """
    if value is None:
        raise ValueError("encode_bound called with value=None")

    t = iceberg_type.lower().strip()

    if t in _UNBOUNDED_TYPES:
        raise UnsupportedBoundType(t)

    if t == "boolean":
        v = value.strip().lower()
        return b"\x01" if v in {"true", "t", "1"} else b"\x00"
    if t == "int":
        return struct.pack("<i", int(value))
    if t == "long":
        return struct.pack("<q", int(value))
    if t == "float":
        return struct.pack("<f", float(value))
    if t == "double":
        return struct.pack("<d", float(value))
    if t == "date":
        return _encode_date(value)
    if t == "time":
        return _encode_time(value)
    if t in ("timestamp", "timestamptz", "timestamp_ns", "timestamptz_ns"):
        return _encode_timestamp(value)
    if t == "string":
        return value.encode("utf-8")
    if t == "uuid":
        import uuid
        return uuid.UUID(value.strip()).bytes  # big-endian per spec
    if t == "binary":
        # DuckLake writes BLOB stats as hex text; fall through to raw UTF-8
        # if hex parsing fails (rare: BLOB with non-hex content).
        stripped = value.replace(r"\x", "")
        try:
            return bytes.fromhex(stripped)
        except ValueError:
            return value.encode("utf-8")
    m = _DECIMAL_RE.match(t)
    if m:
        return _encode_decimal(value, int(m.group(1)), int(m.group(2)))

    # Nested types (struct/list/map): arrive here as dict after parsing, not
    # as string; bounds aren't defined.
    raise UnsupportedBoundType(t)
