"""Minimal Iceberg v3 Puffin writer for deletion-vector-v1 blobs.

Spec references:
  - Puffin file format: https://iceberg.apache.org/puffin-spec/
  - Deletion vector blob: blob type `deletion-vector-v1`, payload is
    `length | magic | roaring64 | crc32`.

What this writer emits:

1. A Puffin file with one or more `deletion-vector-v1` blobs, each one
   representing the set of deleted row positions in a data file.
2. Per blob: a Delta-compatible 64-bit Roaring bitmap. We serialise as
   the portable format expected by Iceberg readers (Spark, Trino,
   PyIceberg 0.11+): `uint64_LE(num_32bit_bitmaps) | [uint32_LE(key) |
   CRoaring_portable_bytes]...`. Most real-world data files stay under
   2^32 rows, so we emit a single 32-bit bitmap keyed on 0 — correct
   and compact.
3. A footer: magic + UTF-8 JSON `FileMetadata` + 4B payload size (LE) +
   4B flags (LE, bit0=0 since we never compress the footer) + magic.

What this writer does not emit (deliberate scope):
  - LZ4 compression of either blobs or footer. Spec-compliant to omit.
  - Column-statistics blobs (Iceberg has these too but DVs are the only
    Puffin blob type we need).
"""
from __future__ import annotations

import io
import json
import struct
import zlib
from dataclasses import dataclass
from typing import Iterable

from pyroaring import BitMap


# Puffin file magic: "PFA1" (bytes 0x50 0x46 0x41 0x31).
PUFFIN_MAGIC = b"PFA1"
# Deletion-vector payload magic: 0xD1 0xD3 0x39 0x64, big-endian.
DV_MAGIC = bytes([0xD1, 0xD3, 0x39, 0x64])


@dataclass
class DeletionVector:
    """One DV destined for a Puffin blob.

    `positions` are 0-based row positions in the referenced data file.
    `referenced_data_file` is the absolute URI of the data file the DV
    applies to.
    """
    referenced_data_file: str
    positions: set[int]

    @property
    def cardinality(self) -> int:
        return len(self.positions)


def _serialize_roaring64(positions: Iterable[int]) -> bytes:
    """Iceberg's 64-bit Roaring serialization: uint64_LE count then
    per-bitmap (uint32_LE key + CRoaring-portable bitmap)."""
    # Bucket positions by high-32-bit key. For datafiles under 2^32 rows
    # this collapses to one bucket with key=0.
    by_key: dict[int, BitMap] = {}
    for p in positions:
        if p < 0:
            raise ValueError("DV positions must be non-negative")
        key = p >> 32
        sub = p & 0xFFFFFFFF
        by_key.setdefault(key, BitMap()).add(sub)
    out = io.BytesIO()
    out.write(struct.pack("<Q", len(by_key)))
    # Spec: iterate keys in unsigned ascending order.
    for key in sorted(by_key):
        out.write(struct.pack("<I", key))
        out.write(by_key[key].serialize())
    return out.getvalue()


def _serialize_dv_blob(positions: Iterable[int]) -> bytes:
    """Full DV blob payload: length | magic | roaring64 | crc32.

    `length` is a 4-byte big-endian int giving the size of
    `magic + roaring64` (NOT including itself or the CRC).
    `crc32` is CRC-32 (zlib.crc32) over `magic + roaring64`.
    """
    vector = _serialize_roaring64(positions)
    body = DV_MAGIC + vector
    length = struct.pack(">I", len(body))
    crc = struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
    return length + body + crc


def write_puffin_file(dvs: list[DeletionVector]) -> tuple[bytes, list[dict]]:
    """Serialise a Puffin file with one `deletion-vector-v1` blob per DV.

    Returns `(file_bytes, blob_descriptors)` where each descriptor is a
    dict with keys `referenced_data_file`, `cardinality`, `offset`,
    `length` — exactly what the caller needs to fill in the Iceberg
    manifest's `data_file` record (file_format=puffin, content_offset,
    content_size_in_bytes, record_count).
    """
    if not dvs:
        raise ValueError("write_puffin_file: at least one DV required")

    body = io.BytesIO()
    body.write(PUFFIN_MAGIC)

    blobs_meta: list[dict] = []
    descriptors: list[dict] = []
    for dv in dvs:
        payload = _serialize_dv_blob(sorted(dv.positions))
        offset = body.tell()
        body.write(payload)
        length = len(payload)
        blobs_meta.append({
            "type": "deletion-vector-v1",
            "fields": [],
            # Snapshot/sequence -1 per spec: the DV is written per-commit
            # but isn't bound to a specific historical snapshot id here.
            "snapshot-id": -1,
            "sequence-number": -1,
            "offset": offset,
            "length": length,
            "properties": {
                "referenced-data-file": dv.referenced_data_file,
                "cardinality": str(dv.cardinality),
            },
        })
        descriptors.append({
            "referenced_data_file": dv.referenced_data_file,
            "cardinality": dv.cardinality,
            "offset": offset,
            "length": length,
        })

    # Footer JSON — uncompressed, UTF-8.
    footer_json = json.dumps({
        "blobs": blobs_meta,
    }, separators=(",", ":")).encode("utf-8")

    # Footer layout: magic | payload | payload_size (LE) | flags (LE) | magic
    body.write(PUFFIN_MAGIC)
    body.write(footer_json)
    body.write(struct.pack("<i", len(footer_json)))
    body.write(struct.pack("<I", 0))     # flags: uncompressed
    body.write(PUFFIN_MAGIC)

    return body.getvalue(), descriptors
