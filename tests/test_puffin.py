"""Unit tests for the Puffin deletion-vector writer.

End-to-end wiring (materialize → Puffin → manifest entry) is covered by
the demo's `Iceberg v3 Puffin DV` section. These tests cover byte-level
correctness so regressions surface without running the full stack.
"""
from __future__ import annotations

import struct
import zlib

import pytest
from pyroaring import BitMap

from duckicelake.puffin import (
    DV_MAGIC,
    PUFFIN_MAGIC,
    DeletionVector,
    _serialize_dv_blob,
    _serialize_roaring64,
    write_puffin_file,
)


def test_roaring64_single_bucket():
    """Positions < 2^32 should collapse to one bucket keyed on 0."""
    payload = _serialize_roaring64([0, 7, 100, 999_999])
    n_bitmaps = struct.unpack("<Q", payload[:8])[0]
    key = struct.unpack("<I", payload[8:12])[0]
    assert n_bitmaps == 1
    assert key == 0
    # The rest is a CRoaring-portable bitmap; check it round-trips.
    decoded = BitMap.deserialize(payload[12:])
    assert sorted(decoded) == [0, 7, 100, 999_999]


def test_roaring64_multi_bucket():
    """Positions spanning >32-bit should produce one bucket per high-32 key."""
    payload = _serialize_roaring64([1, 2**33, 2**33 + 5])
    n_bitmaps = struct.unpack("<Q", payload[:8])[0]
    assert n_bitmaps == 2    # keys 0 and 2


def test_dv_blob_structure():
    """Blob: 4B length (BE) | 4B magic | vector | 4B CRC32 (BE).
    Length covers magic + vector, not itself or the CRC."""
    blob = _serialize_dv_blob([0, 3])
    length = struct.unpack(">I", blob[:4])[0]
    assert blob[4:8] == DV_MAGIC
    body = blob[4:4 + length]
    crc_stored = struct.unpack(">I", blob[4 + length:4 + length + 4])[0]
    assert crc_stored == (zlib.crc32(body) & 0xFFFFFFFF)


def test_puffin_file_header_footer_magic():
    out, descriptors = write_puffin_file([
        DeletionVector("s3://bucket/data.parquet", {0, 1, 2}),
    ])
    assert out[:4] == PUFFIN_MAGIC
    assert out[-4:] == PUFFIN_MAGIC
    # Descriptor fields that materialize feeds into the manifest entry.
    d = descriptors[0]
    assert d["referenced_data_file"] == "s3://bucket/data.parquet"
    assert d["cardinality"] == 3
    assert d["offset"] == 4             # immediately after file magic
    assert d["length"] > 0


def test_puffin_file_multiple_dvs_distinct_offsets():
    out, descriptors = write_puffin_file([
        DeletionVector("s3://b/a.parquet", {1}),
        DeletionVector("s3://b/b.parquet", {2, 3}),
    ])
    assert len(descriptors) == 2
    assert descriptors[0]["offset"] == 4
    # Second blob must live past the first.
    assert descriptors[1]["offset"] == descriptors[0]["offset"] + descriptors[0]["length"]


def test_empty_dv_list_raises():
    with pytest.raises(ValueError):
        write_puffin_file([])


def test_footer_json_contains_blob_metadata():
    """Footer payload must include one blob per DV, with cardinality as a
    string (Puffin spec stores properties as strings)."""
    import json
    out, _ = write_puffin_file([
        DeletionVector("s3://b/x.parquet", {10, 20, 30}),
    ])
    # Footer layout (reverse): magic | flags(4) | size(4) | payload | magic
    footer_magic = out[-4:]
    assert footer_magic == PUFFIN_MAGIC
    flags = struct.unpack("<I", out[-8:-4])[0]
    assert flags == 0
    size = struct.unpack("<i", out[-12:-8])[0]
    payload = out[-12 - size:-12]
    meta = json.loads(payload.decode("utf-8"))
    assert len(meta["blobs"]) == 1
    blob = meta["blobs"][0]
    assert blob["type"] == "deletion-vector-v1"
    assert blob["snapshot-id"] == -1
    assert blob["sequence-number"] == -1
    assert blob["properties"]["referenced-data-file"] == "s3://b/x.parquet"
    assert blob["properties"]["cardinality"] == "3"
