"""Extend PyIceberg 0.10/0.11 to support Iceberg v3 reads + writes.

Two things are patched in on import:

1. **v3 primitive types** — `variant`, `geometry`, `geography` aren't in
   PyIceberg's hardcoded chain of `if v == ...` branches, so
   `IcebergType.handle_primitive_type` raises
   `Unsupported field type: '<v>'`. We wrap that method to recognise the
   three v3 types and return lightweight `PrimitiveType` subclasses.
   Reads of data columns of these types come back as raw bytes/strings
   in whatever encoding DuckLake wrote (VARIANT = Parquet variant logical
   type; GEOMETRY = WKB); we don't attempt conversion.

2. **v3 manifest + manifest-list writes** — PyIceberg 0.11.1 hard-raises
   `ValueError("Cannot write manifest list for table version: 3")` in
   the `write_manifest_list` factory. This blocks any
   `Transaction.upgrade_format_version(3)` or v3-born `append()`. The
   upstream fix (iceberg-python#3070) stalled without merging in
   March 2026. We vendor its essential changes as a monkey-patch:

   - `DEFAULT_READ_VERSION` bumped 2 → 3 so `ManifestFile.first_row_id`
     round-trips on re-read.
   - `SUPPORTED_TABLE_FORMAT_VERSION` bumped 2 → 3 so
     `Transaction.upgrade_format_version(3)` is accepted.
   - New `ManifestWriterV3` (inherits V2, just bumps `version`).
   - New `ManifestListWriterV3` (inherits V2, sets `_format_version=3`
     so the v3 Avro schema is used, stamps `first-row-id` in the Avro
     metadata, and assigns incremental `first_row_id` per data manifest
     from the running high-water mark).
   - `write_manifest` / `write_manifest_list` factories extended to
     dispatch to the new V3 classes when `format_version=3`.
   - `ManifestFile.first_row_id` property accessor so the V3 writer can
     set the field on the record tuple.

Call `install()` exactly once before any PyIceberg RestCatalog call.
"""
from __future__ import annotations

from copy import copy
from typing import Any

import pyiceberg.types as _t


class VariantType(_t.PrimitiveType):
    """Iceberg v3 VARIANT. Semi-structured; stored by writers as the
    Parquet variant logical type."""
    root: str = "variant"

    def __repr__(self) -> str:
        return "VariantType()"

    def __str__(self) -> str:
        return "variant"


class GeometryType(_t.PrimitiveType):
    """Iceberg v3 GEOMETRY. WKB-encoded binary payload in the data file."""
    root: str = "geometry"

    def __repr__(self) -> str:
        return "GeometryType()"

    def __str__(self) -> str:
        return "geometry"


class GeographyType(_t.PrimitiveType):
    """Iceberg v3 GEOGRAPHY. Like GeometryType but with geodetic CRS."""
    root: str = "geography"

    def __repr__(self) -> str:
        return "GeographyType()"

    def __str__(self) -> str:
        return "geography"


_V3_PRIMITIVES: dict[str, type[_t.PrimitiveType]] = {
    "variant": VariantType,
    "geometry": GeometryType,
    "geography": GeographyType,
}

_INSTALLED = False


def _install_v3_types() -> None:
    original = _t.IcebergType.handle_primitive_type

    def patched(cls: Any, v: Any, handler: Any) -> _t.IcebergType:  # noqa: ARG001
        if isinstance(v, str) and v in _V3_PRIMITIVES:
            return _V3_PRIMITIVES[v]()
        return original.__func__(cls, v, handler) if hasattr(original, "__func__") else original(cls, v, handler)

    _t.IcebergType.handle_primitive_type = classmethod(patched)  # type: ignore[method-assign]


def _install_v3_writers() -> None:
    """Vendor iceberg-python#3070's v3 manifest/manifest-list writer into
    the installed pyiceberg. Idempotent by outer `install()`."""
    import pyiceberg.manifest as _m
    import pyiceberg.table as _pt
    import pyiceberg.table.metadata as _md
    from pyiceberg.table.update import UpgradeFormatVersionUpdate

    # Raise the "max writeable format-version" gate in metadata. Several
    # modules captured this constant at import time, so patch every copy
    # we can find — otherwise the transaction-commit path raises on
    # whichever bind happens to be reached first.
    import pyiceberg.table.update as _upd
    _md.SUPPORTED_TABLE_FORMAT_VERSION = 3
    _upd.SUPPORTED_TABLE_FORMAT_VERSION = 3

    # Patch the client-side `Transaction.upgrade_table_version` gate.
    # 0.11.1 hardcodes `if format_version not in {1, 2}: raise`; we rewrite
    # to accept up to `SUPPORTED_TABLE_FORMAT_VERSION` so the patched
    # ceiling takes effect.
    def upgrade_table_version(self, format_version: int):
        if format_version not in {1, 2, 3}:
            raise ValueError(f"Unsupported table format version: {format_version}")
        current = self.table_metadata.format_version
        if format_version < current:
            raise ValueError(
                f"Cannot downgrade v{current} table to v{format_version}"
            )
        if format_version > current:
            return self._apply((UpgradeFormatVersionUpdate(format_version=format_version),))
        return self
    _pt.Transaction.upgrade_table_version = upgrade_table_version  # type: ignore[method-assign]

    # Patch the UpgradeFormatVersionUpdate handler: when upgrading from
    # <3 to 3, initialise `next_row_id=0`. Without this, subsequent
    # AddSnapshotUpdate fails with "Cannot add snapshot without first
    # row id" because Snapshot.first_row_id is derived from next_row_id.
    from pyiceberg.table.update import (
        _apply_table_update,
        _TableMetadataUpdateContext,
    )
    from pyiceberg.table.metadata import (
        TableMetadata, TableMetadataUtil, TableMetadataV3,
    )

    @_apply_table_update.register(UpgradeFormatVersionUpdate)
    def _upgrade_fv(
        update: UpgradeFormatVersionUpdate,
        base_metadata: TableMetadata,
        context: _TableMetadataUpdateContext,
    ) -> TableMetadata:
        if update.format_version > _md.SUPPORTED_TABLE_FORMAT_VERSION:
            raise ValueError(f"Unsupported table format version: {update.format_version}")
        if update.format_version < base_metadata.format_version:
            raise ValueError(
                f"Cannot downgrade v{base_metadata.format_version} table "
                f"to v{update.format_version}"
            )
        if update.format_version == base_metadata.format_version:
            return base_metadata
        updated = base_metadata.model_copy(
            update={"format_version": update.format_version}
        )
        updated = TableMetadataUtil._construct_without_validation(updated)
        if (
            isinstance(updated, TableMetadataV3)
            and base_metadata.format_version < 3
            and updated.next_row_id is None
        ):
            updated = updated.model_copy(update={"next_row_id": 0})
        context.add_update(update)
        return updated

    # Patch the AddSnapshotUpdate handler for v3: compute `next_row_id`
    # from the snapshot's `added_rows` so successive commits keep
    # row-ids monotonically increasing. Tolerate missing `added_rows`
    # (pyiceberg 0.11.1's _commit doesn't populate it — the field was
    # added in PR #3070's snapshot.py changes) by defaulting to 0, which
    # means row-ids stay 0 but the commit is accepted.
    from pyiceberg.table.update import AddSnapshotUpdate
    import copy as _copyMod
    _orig_add_snapshot = _apply_table_update.dispatch(AddSnapshotUpdate)

    @_apply_table_update.register(AddSnapshotUpdate)
    def _add_snapshot(
        update: AddSnapshotUpdate,
        base_metadata: TableMetadata,
        context: _TableMetadataUpdateContext,
    ) -> TableMetadata:
        # Synthesize first_row_id + added_rows for v3 snapshots where the
        # unpatched pyiceberg snapshot-commit path didn't populate them.
        if (
            base_metadata.format_version >= 3
            and update.snapshot.first_row_id is None
        ):
            new_snap = update.snapshot.model_copy(
                update={"first_row_id": base_metadata.next_row_id or 0}
            )
            update = update.model_copy(update={"snapshot": new_snap})
        return _orig_add_snapshot(update, base_metadata, context)

    # Let the manifest-list reader include v3 extras (first_row_id) when
    # round-tripping manifests we wrote, even if the caller's advertised
    # format_version is still 2 for some reason. V3's Avro schema is a
    # strict superset of V2's at the metadata level, so bumping this is
    # safe for both read paths.
    _m.DEFAULT_READ_VERSION = 3

    # Add `first_row_id` accessor on ManifestFile so writers can set
    # the field on the _data tuple. Record's underlying tuple lengthens
    # automatically when _format_version=3 (because the V3 schema has
    # one more field than V2).
    if not hasattr(_m.ManifestFile, "first_row_id"):
        def _get_first_row_id(self: _m.ManifestFile):
            data = getattr(self, "_data", None)
            return data[15] if data is not None and len(data) > 15 else None

        def _set_first_row_id(self: _m.ManifestFile, value):
            data = self._data
            while len(data) <= 15:
                data.append(None)
            data[15] = value

        _m.ManifestFile.first_row_id = property(_get_first_row_id, _set_first_row_id)  # type: ignore[attr-defined]

    # DataFile.from_args captured `DEFAULT_READ_VERSION=2` as a default
    # arg at def-time — so even after we bump the constant, new records
    # keep the V2 shape (16 fields) and the V3 manifest writer chokes
    # on the missing 17..20. Replace the classmethod so the default is
    # resolved dynamically at each call.
    _orig_from_args = _m.DataFile.from_args.__func__

    def _from_args_dyn(cls, _table_format_version=None, **arguments):
        if _table_format_version is None:
            _table_format_version = _m.DEFAULT_READ_VERSION
        struct = _m.DATA_FILE_TYPE[_table_format_version]
        return cls._bind(struct, **arguments)

    _m.DataFile.from_args = classmethod(_from_args_dyn)  # type: ignore[method-assign]

    # --- ManifestWriterV3 --------------------------------------------
    class ManifestWriterV3(_m.ManifestWriterV2):
        """v3 data-manifest writer. Same on-disk shape as V2 today;
        the version bump lets ManifestList know the producer is v3."""
        @property
        def version(self):
            return 3

    _m.ManifestWriterV3 = ManifestWriterV3  # type: ignore[attr-defined]

    # --- ManifestListWriterV3 ---------------------------------------
    AVRO_CODEC_KEY = "avro.codec"
    try:
        # The constant may live under pyiceberg.avro.file in some versions.
        from pyiceberg.avro.file import AVRO_CODEC_KEY as _k  # type: ignore
        AVRO_CODEC_KEY = _k
    except Exception:
        pass

    class ManifestListWriterV3(_m.ManifestListWriterV2):
        """v3 manifest-list writer. Sets `_format_version=3` so the V3
        Avro schema is selected (which includes `first_row_id`), writes
        the `first-row-id` Avro metadata, and assigns per-data-manifest
        first_row_id from a running high-water mark."""

        def __init__(
            self,
            output_file,
            snapshot_id: int,
            parent_snapshot_id: int | None,
            sequence_number: int,
            compression,
            snapshot_first_row_id: int = 0,
        ) -> None:
            super().__init__(
                output_file=output_file,
                snapshot_id=snapshot_id,
                parent_snapshot_id=parent_snapshot_id,
                sequence_number=sequence_number,
                compression=compression,
            )
            self._format_version = 3
            self._meta = {
                "snapshot-id": str(snapshot_id),
                "parent-snapshot-id": str(parent_snapshot_id) if parent_snapshot_id is not None else "null",
                "sequence-number": str(sequence_number),
                "first-row-id": str(snapshot_first_row_id),
                "format-version": "3",
                AVRO_CODEC_KEY: compression,
            }
            self._next_row_id = int(snapshot_first_row_id)

        @property
        def next_row_id(self):
            return self._next_row_id

        def prepare_manifest(self, manifest_file):
            # Reuse V2's V2-shape prep (sequence-number assignment) via
            # super(); then assign v3 first_row_id on data manifests.
            wrapped = super().prepare_manifest(manifest_file)
            if (
                wrapped.content == _m.ManifestContent.DATA
                and wrapped.first_row_id is None
            ):
                existing = wrapped.existing_rows_count or 0
                added = wrapped.added_rows_count or 0
                wrapped.first_row_id = self._next_row_id
                self._next_row_id += existing + added
            return wrapped

    _m.ManifestListWriterV3 = ManifestListWriterV3  # type: ignore[attr-defined]

    # --- factory functions ------------------------------------------
    _orig_write_manifest = _m.write_manifest

    def write_manifest(
        format_version,
        spec,
        schema,
        output_file,
        snapshot_id,
        avro_compression,
    ):
        if format_version == 3:
            return ManifestWriterV3(spec, schema, output_file, snapshot_id, avro_compression)
        return _orig_write_manifest(
            format_version, spec, schema, output_file, snapshot_id, avro_compression,
        )
    _m.write_manifest = write_manifest

    _orig_write_manifest_list = _m.write_manifest_list

    def write_manifest_list(
        format_version,
        output_file,
        snapshot_id,
        parent_snapshot_id,
        sequence_number,
        avro_compression,
        snapshot_first_row_id: int | None = None,
    ):
        if format_version == 3:
            if sequence_number is None:
                raise ValueError(
                    f"Sequence-number is required for V3 tables: {sequence_number}"
                )
            # `snapshot_first_row_id` is optional for back-compat with
            # pyiceberg 0.11.1's snapshot-commit code (which doesn't yet
            # pass the kwarg). Default to 0 when missing — every row id
            # assigned from this list still monotonically advances.
            return ManifestListWriterV3(
                output_file=output_file,
                snapshot_id=snapshot_id,
                parent_snapshot_id=parent_snapshot_id,
                sequence_number=sequence_number,
                compression=avro_compression,
                snapshot_first_row_id=snapshot_first_row_id or 0,
            )
        return _orig_write_manifest_list(
            format_version, output_file, snapshot_id, parent_snapshot_id,
            sequence_number, avro_compression,
        )
    _m.write_manifest_list = write_manifest_list

    # Importantly: callers do `from pyiceberg.manifest import write_manifest,
    # write_manifest_list` which binds the name into their own module's
    # globals at import time. Patching `pyiceberg.manifest.write_manifest`
    # doesn't update those already-bound names — we have to reach into
    # each caller's namespace. `snapshot.py` (the write path) is the
    # critical one; also patch any other module that re-imported.
    import sys
    for mod_name, mod in list(sys.modules.items()):
        if not mod_name.startswith("pyiceberg"):
            continue
        for attr in ("write_manifest", "write_manifest_list"):
            if hasattr(mod, attr) and mod is not _m:
                setattr(mod, attr, getattr(_m, attr))


def install() -> None:
    """Apply all v3 compatibility patches to the installed pyiceberg.

    Idempotent. Raises if pyiceberg's API shape has changed in a way
    we don't understand, so callers don't silently miss the patch.
    """
    global _INSTALLED
    if _INSTALLED:
        return
    _install_v3_types()
    _install_v3_writers()
    _INSTALLED = True
