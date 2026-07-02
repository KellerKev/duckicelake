"""Materialise Iceberg v2/v3 snapshot chain from DuckLake state.

DuckLake already has snapshots, deletes, column stats, and schema history —
this module reads all of it and emits the Iceberg shape:

  <table>/metadata/v{N}.metadata.json                      (TableMetadata)
  <table>/metadata/snap-<snap-id>-<uuid>.avro              (manifest list, one per snapshot)
  <table>/metadata/<snap-id>-<uuid>-m0-data.avro           (data manifest, one per snapshot)
  <table>/metadata/<snap-id>-<uuid>-m1-deletes.avro        (position-delete manifest, when deletes exist)

Deterministic filenames keyed on (snap_id, table_uuid) let us re-run
idempotently: filenames match on rerun, S3 PutObject overwrites.
"""
from __future__ import annotations

import concurrent.futures as _cf
import json
import uuid
from typing import Any, Iterable

import boto3
from botocore.exceptions import ClientError

from .bounds import UnsupportedBoundType, encode_bound
from .catalog import (
    DuckLakeColumn,
    DuckLakeColumnStat,
    DuckLakeDataFile,
    DuckLakeDeleteFile,
    DuckLakeSnapshot,
    DuckLakeCatalog,
)
from .config import S3Settings
from .manifest import (
    DataFileInfo,
    DataFileStats,
    DeleteFileInfo,
    build_snapshot,
    write_data_manifest_bytes,
    write_delete_manifest_bytes,
    write_manifest_list_bytes,
)


def _s3_client(s3: S3Settings):
    # Back-compat: still exported; materialize_all uses the shared
    # `catalog.s3_client` now. Kept so external callers don't break.
    return boto3.client(
        "s3",
        endpoint_url=s3.endpoint,
        region_name=s3.region,
        aws_access_key_id=s3.root_access_key,
        aws_secret_access_key=s3.root_secret_key,
    )


def _put(client, bucket: str, key: str, body: bytes) -> None:
    client.put_object(Bucket=bucket, Key=key, Body=body)


def _put_if_missing(client, bucket: str, key: str, body: bytes) -> None:
    """PUT the object only if it isn't already present at this key.

    All our manifest + manifest-list Avros are deterministic on
    (snapshot_id, table_uuid), so overwriting them would produce identical
    bytes. Skipping the write when S3 already has the key saves a round-
    trip per snapshot during re-materialisation.
    """
    if _object_exists(client, bucket, key):
        return
    client.put_object(Bucket=bucket, Key=key, Body=body)


def _object_exists(client, bucket: str, key: str) -> bool:
    try:
        client.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
            return False
        raise


def _read_cached_metadata(client, bucket: str, key: str) -> dict[str, Any] | None:
    """Return parsed v1.metadata.json if present, else None."""
    try:
        body = client.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in {"404", "NoSuchKey"}:
            return None
        raise
    return json.loads(body)


def _iceberg_type_for_column(col: DuckLakeColumn) -> Any:
    from .types import ducklake_type_to_iceberg
    return ducklake_type_to_iceberg(col.column_type)


def _columns_to_schema(cols: Iterable[DuckLakeColumn], schema_id: int) -> dict[str, Any]:
    fields = []
    for c in cols:
        field: dict[str, Any] = {
            "id": c.column_id,
            "name": c.column_name,
            "required": not c.nulls_allowed,
            "type": _iceberg_type_for_column(c),
        }
        if c.initial_default is not None:
            field["initial-default"] = c.initial_default
        if c.default_value is not None and c.default_value != "NULL":
            field["write-default"] = c.default_value
        fields.append(field)
    return {"schema-id": schema_id, "type": "struct", "fields": fields}


def _stats_by_column(
    file_id: int,
    stats_by_file: dict[int, list[DuckLakeColumnStat]],
    iceberg_type_by_col: dict[int, Any],
    *,
    exact_nan_by_file: dict[int, dict[int, int]] | None = None,
) -> DataFileStats:
    """Convert DuckLake file stats into an Iceberg-ready DataFileStats."""
    rows = stats_by_file.get(file_id, [])
    exact_for_file = (exact_nan_by_file or {}).get(file_id, {})
    value_counts: dict[int, int] = {}
    null_counts: dict[int, int] = {}
    nan_counts: dict[int, int] = {}
    lowers: dict[int, bytes] = {}
    uppers: dict[int, bytes] = {}
    for s in rows:
        if s.value_count is not None:
            value_counts[s.column_id] = s.value_count
        if s.null_count is not None:
            null_counts[s.column_id] = s.null_count
        if s.contains_nan:
            # Prefer the exact count we computed from the Parquet file;
            # fall back to presence-as-1 when we don't have one cached.
            nan_counts[s.column_id] = exact_for_file.get(s.column_id, 1)
        t = iceberg_type_by_col.get(s.column_id)
        if isinstance(t, str):
            try:
                if s.min_value is not None:
                    lowers[s.column_id] = encode_bound(t, s.min_value)
                if s.max_value is not None:
                    uppers[s.column_id] = encode_bound(t, s.max_value)
            except UnsupportedBoundType:
                # Iceberg has no bound encoding for this primitive (variant /
                # geometry / geography / unknown). Spec-compliant: omit the
                # column from lower_bounds/upper_bounds. Not an error.
                pass
            # Other exceptions (ValueError, OverflowError) propagate — if
            # DuckLake's stored stat doesn't parse for the declared type,
            # that's a real pipeline bug we want to surface.
    return DataFileStats(
        value_counts=value_counts or None,
        null_value_counts=null_counts or None,
        nan_value_counts=nan_counts or None,
        lower_bounds=lowers or None,
        upper_bounds=uppers or None,
    )


def materialize_all(
    *,
    catalog: DuckLakeCatalog,
    ns: list[str],
    table: str,
    base_metadata: dict[str, Any],
    metadata_prefix: str,
) -> dict[str, Any]:
    """Materialise the full snapshot chain for a table.

    Returns an updated TableMetadata with snapshots/snapshot-log/refs
    populated. Writes all manifest and manifest-list Avro files to S3.
    Also writes the resulting v1.metadata.json to `metadata_prefix +
    v1.metadata.json` so `metadata-location` is resolvable.
    """
    snaps = catalog.list_snapshots(ns, table)
    if not snaps:
        return base_metadata

    s3 = catalog.settings.s3
    client = catalog.s3_client                # shared boto3 client
    bucket = s3.bucket

    current_snap_id = snaps[-1].snapshot_id

    # In-process hot cache: (ns, table) → (snap_id, metadata). Bypass the
    # S3 round-trips entirely when the snapshot hasn't advanced. Commit
    # handlers invalidate this; partition-spec sidecar changes bust it too.
    cached = catalog.cached_metadata(ns, table, current_snap_id)
    if cached is not None and not catalog.get_iceberg_partition_spec(ns, table):
        cached = dict(cached)
        sidecar_props_hit = catalog.get_table_properties(ns, table)
        cached["properties"] = dict(cached.get("properties", {}))
        cached["properties"].update(base_metadata.get("properties") or {})
        cached["properties"].update(sidecar_props_hit)
        cached["properties"]["ducklake.snapshot-id"] = str(current_snap_id)
        # A format-version upgrade is a sidecar-prop write — it doesn't
        # bump DuckLake's snapshot id, so the cache can hold a pre-upgrade
        # `format-version`. Re-read from the sidecar on every serve.
        requested_fv_hit = sidecar_props_hit.get("duckicelake.format-version")
        if requested_fv_hit:
            try:
                cached["format-version"] = int(requested_fv_hit)
            except ValueError:
                pass
        refs = dict(cached.get("refs") or {})
        for ref_name, (snap, ref_type) in catalog.get_tags(ns, table).items():
            refs[ref_name] = {"type": ref_type, "snapshot-id": int(snap)}
        cached["refs"] = refs
        return cached

    # Metadata JSON versioning: each materialisation writes a new numbered
    # vN.metadata.json and updates `version-hint.text` to point at the
    # latest.
    metadata_version = _next_metadata_version(
        client, bucket, metadata_prefix, current_snap_id
    )
    metadata_key = f"{metadata_prefix}v{metadata_version}.metadata.json"
    # Content-addressed cache on S3: if the latest vN.metadata.json already
    # points at this DuckLake snapshot, re-use without rewriting manifests.
    latest_existing = _read_cached_metadata(
        client, bucket,
        f"{metadata_prefix}v{metadata_version - 1}.metadata.json"
        if metadata_version > 1 else metadata_key,
    )
    # The partition-spec sidecar (truncate[N] etc.) is orthogonal to
    # DuckLake's snapshot numbering — changes to it don't bump a DuckLake
    # snapshot. If the sidecar is populated, the cached metadata's spec
    # may be stale; fall through to full materialise so `iceberg_spec_fields`
    # gets re-emitted.
    has_sidecar_partition_spec = bool(catalog.get_iceberg_partition_spec(ns, table))
    if (
        latest_existing
        and latest_existing.get("current-snapshot-id") == current_snap_id
        and not has_sidecar_partition_spec
    ):
        # Cache hit on the *snapshot chain + manifests*. But properties and
        # tags live in sidecar tables and can change without a DuckLake
        # snapshot bump (they don't alter data). Always refresh them from
        # source when serving a cache hit.
        sidecar_props_s3hit = catalog.get_table_properties(ns, table)
        latest_existing["properties"] = dict(latest_existing.get("properties", {}))
        latest_existing["properties"].update(base_metadata.get("properties") or {})
        latest_existing["properties"].update(sidecar_props_s3hit)
        latest_existing["properties"]["ducklake.snapshot-id"] = str(current_snap_id)
        requested_fv_s3hit = sidecar_props_s3hit.get("duckicelake.format-version")
        if requested_fv_s3hit:
            try:
                latest_existing["format-version"] = int(requested_fv_s3hit)
            except ValueError:
                pass
        refs = dict(latest_existing.get("refs") or {})
        # Sidecar refs: tags + read-only branches. `main` stays whatever
        # the cached doc already has (it tracks DuckLake HEAD).
        for ref_name, (snap, ref_type) in catalog.get_tags(ns, table).items():
            refs[ref_name] = {"type": ref_type, "snapshot-id": int(snap)}
        latest_existing["refs"] = refs
        catalog.put_cached_metadata(ns, table, current_snap_id, latest_existing)
        return latest_existing

    # Stable-ish uuid so re-materialisation overwrites the same keys.
    table_uuid_str = base_metadata["table-uuid"]
    short_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"{ns[0]}.{table}")

    # Build every historical schema once; key by schema_version (== Iceberg schema-id for us).
    schema_by_version: dict[int, dict[str, Any]] = {}
    for snap in snaps:
        sv = snap.schema_version
        if sv is None or sv in schema_by_version:
            continue
        cols = catalog.columns_at(ns, table, snap.snapshot_id)
        if not cols:
            continue
        schema_by_version[sv] = _columns_to_schema(cols, schema_id=sv)
    if not schema_by_version:
        # Fallback: current schema only.
        cols = catalog.columns_at(ns, table, snaps[-1].snapshot_id)
        schema_by_version[0] = _columns_to_schema(cols, schema_id=0)

    # Partition spec — compute once for the current state and reuse
    # inside the per-snapshot loop. The spec applies to all snapshots in
    # this materialisation run; files written before the spec was set
    # simply have no rows in `ducklake_file_partition_value`, which we
    # surface as `null`s in the partition struct.
    from .partition_sort import ducklake_transform_to_iceberg
    from .iceberg_transforms import iceberg_partition_field_avro_type

    # Use the latest schema's ids to resolve partition source-id.
    latest_cols = catalog.columns_at(ns, table, snaps[-1].snapshot_id)
    field_id_by_name = {c.column_name: c.column_id for c in latest_cols}
    from .types import ducklake_type_to_iceberg as _dl2ice
    latest_iceberg_type_by_name = {c.column_name: _dl2ice(c.column_type) for c in latest_cols}

    duck_part_with_ids = catalog.current_partition_spec_with_source_ids(ns, table)
    sidecar_spec = catalog.get_iceberg_partition_spec(ns, table)
    partition_fields_avro: list[dict] = []
    # Per emitted field: (field_name, transform, source_col_id, ducklake_key_index).
    # `ducklake_key_index` is the position within DuckLake's native
    # partition spec — used to look up file-level stored partition values.
    # None means "synthetic" (e.g. truncate) — values come from source stats.
    partition_fields_for_values: list[tuple[str, str, int, int | None]] = []
    iceberg_spec_fields: list[dict[str, Any]] = []

    if sidecar_spec:
        # Sidecar spec is authoritative. Build emission per sidecar order;
        # fields with a ducklake_key_index resolve values via DuckLake's
        # stored partition values, synthetic fields (truncate) resolve via
        # source column min stats.
        source_name_by_id = {c.column_id: c.column_name for c in latest_cols}
        for f in sidecar_spec:
            transform = f["transform"]
            source_id = f["source-id"]
            field_name = f["name"]
            field_id = f["field-id"]
            dk_idx = f.get("ducklake_key_index")
            source_col_name = source_name_by_id.get(source_id, "col")
            source_type = latest_iceberg_type_by_name.get(source_col_name, "string")
            if not isinstance(source_type, str):
                source_type = "string"

            iceberg_spec_fields.append({
                "name": field_name,
                "transform": transform,
                "source-id": source_id,
                "field-id": field_id,
            })
            avro_type = iceberg_partition_field_avro_type(transform, source_type)
            partition_fields_avro.append({
                "name": field_name,
                "avro_type": avro_type,
                "field_id": field_id,
                "source_type": source_type,
                "ducklake_transform": transform,
                "source_col_id": source_id,
            })
            partition_fields_for_values.append((field_name, transform, source_id, dk_idx))
    else:
        seen_names: dict[str, int] = {}
        for i, (col_name, ducklake_transform, source_col_id) in enumerate(duck_part_with_ids):
            source_id = field_id_by_name.get(col_name)
            if source_id is None:
                continue
            iceberg_transform = ducklake_transform_to_iceberg(ducklake_transform)
            field_name = col_name if iceberg_transform == "identity" \
                else f"{col_name}_{iceberg_transform.split('[', 1)[0]}"
            base = field_name
            n = seen_names.get(base, 0)
            if n:
                field_name = f"{base}{n}"
            seen_names[base] = n + 1

            iceberg_spec_fields.append({
                "name": field_name,
                "transform": iceberg_transform,
                "source-id": source_id,
                "field-id": 1000 + i,
            })
            source_type = latest_iceberg_type_by_name.get(col_name, "string")
            if not isinstance(source_type, str):
                source_type = "string"
            avro_type = iceberg_partition_field_avro_type(ducklake_transform, source_type)
            partition_fields_avro.append({
                "name": field_name,
                "avro_type": avro_type,
                "field_id": 1000 + i,
                "source_type": source_type,
                "ducklake_transform": ducklake_transform,
                "source_col_id": source_col_id,
            })
            partition_fields_for_values.append((field_name, ducklake_transform, source_col_id, i))

    # DuckLake changes_made → Iceberg snapshot.summary.operation, so
    # clients filtering the snapshot log by operation get accurate results.
    changes_map = catalog.snapshot_changes_map()

    def _operation_from_changes(changes: str) -> str:
        """Infer the Iceberg-spec operation from a DuckLake changes_made string."""
        c = changes.lower()
        if c.startswith("created_table") or c.startswith("altered_table"):
            return "replace"          # schema-only snapshot
        if c.startswith("deleted_from_table"):
            return "delete"
        if c.startswith("inserted_into_table"):
            return "append"
        if c.startswith("overwrite_"):
            return "overwrite"
        # Fall back to append — least harmful default.
        return "append"

    snapshots_out: list[dict[str, Any]] = []
    snapshot_log: list[dict[str, Any]] = []
    parent_id: int | None = None
    last_row_id = 0
    total_files_so_far = 0
    total_rows_so_far = 0

    # Per-snapshot S3 writes fire into a thread pool. Each PUT is
    # independent — the Avro bytes are deterministic on
    # (snapshot_id, table_uuid) so collisions across concurrent
    # materialisers produce identical bodies. Using _put_if_missing
    # also short-circuits when a previous run already uploaded the file.
    pending_puts: list[_cf.Future] = []
    put_executor = _cf.ThreadPoolExecutor(max_workers=8)

    def _async_put(key: str, body: bytes) -> None:
        pending_puts.append(
            put_executor.submit(_put_if_missing, client, bucket, key, body)
        )

    # Effective Iceberg format-version for the Avro files written below.
    # Drives Avro schema choice (v3 adds `first_row_id` to manifest-list)
    # and the `format-version` metadata value embedded in every Avro.
    # Overridden by the `duckicelake.format-version` sidecar property set
    # via upgrade-format-version commits — same knob that drives
    # `metadata["format-version"]` in the TableMetadata doc.
    _effective_fv = int(base_metadata.get("format-version", 2))
    _fv_prop = catalog.get_table_properties(ns, table).get("duckicelake.format-version")
    if _fv_prop:
        try:
            _effective_fv = int(_fv_prop)
        except ValueError:
            pass

    for snap in snaps:
        snap_id = snap.snapshot_id
        data_files = catalog.data_files_at(ns, table, snap_id)
        delete_files = catalog.delete_files_at(ns, table, snap_id)

        # Schemas drive bounds typing: pick the active schema at this snap.
        schema_version = snap.schema_version or 0
        schema = schema_by_version.get(schema_version) or next(iter(schema_by_version.values()))
        iceberg_type_by_col = {f["id"]: f["type"] for f in schema["fields"]}

        stats_by_file = catalog.column_stats([f.data_file_id for f in data_files])

        # Lazy exact-NaN population: for files where DuckLake flagged
        # contains_nan=true on any float column, fill in exact counts
        # from the sidecar, computing + caching on first miss.
        float_cols_by_file: dict[int, dict[int, str]] = {}
        for df in data_files:
            for s in stats_by_file.get(df.data_file_id, []):
                if not s.contains_nan:
                    continue
                t = iceberg_type_by_col.get(s.column_id)
                if t not in {"float", "double"}:
                    continue
                col_name = next(
                    (c.column_name for c in catalog.columns_at(ns, table, snap_id)
                     if c.column_id == s.column_id),
                    None,
                )
                if col_name:
                    float_cols_by_file.setdefault(df.data_file_id, {})[s.column_id] = col_name
        exact_nan_cache = catalog.get_nan_counts(list(float_cols_by_file.keys()))
        # Compute any missing (data_file_id, column_id) exact counts.
        missing: dict[int, dict[int, str]] = {}
        for fid, cols in float_cols_by_file.items():
            already = exact_nan_cache.get(fid, {})
            need = {cid: cname for cid, cname in cols.items() if cid not in already}
            if need:
                missing[fid] = need
        if missing:
            missing_files = [df for df in data_files if df.data_file_id in missing]
            catalog.compute_and_store_nan_counts(missing_files, missing)
            # Re-read so we don't return presence-only 1s for freshly
            # computed entries.
            exact_nan_cache = catalog.get_nan_counts(list(float_cols_by_file.keys()))

        # For partitioned tables, compute each file's Iceberg partition
        # values. Bucket + identity pass through DuckLake's stored values;
        # time transforms (day/month/year/hour) get recomputed from the
        # source column's min_value stat because DuckLake's semantics
        # differ (see iceberg_transforms.py docstring).
        partition_values_by_file = (
            catalog.partition_values_by_file(ns, table)
            if partition_fields_for_values else {}
        )

        data_infos: list[DataFileInfo] = []
        for df in data_files:
            pvals: dict[str, Any] = {}
            if partition_fields_for_values:
                from .iceberg_transforms import duckLake_stored_to_iceberg
                stored = partition_values_by_file.get(df.data_file_id, {})
                file_col_stats = {s.column_id: s for s in stats_by_file.get(df.data_file_id, [])}
                for field_name, transform, source_col_id, dk_idx in partition_fields_for_values:
                    stored_val = stored.get(dk_idx) if dk_idx is not None else None
                    source_min = None
                    cstat = file_col_stats.get(source_col_id)
                    if cstat is not None:
                        source_min = cstat.min_value
                    source_type = iceberg_type_by_col.get(source_col_id, "string")
                    if not isinstance(source_type, str):
                        source_type = "string"
                    pvals[field_name] = duckLake_stored_to_iceberg(
                        transform, stored_val, source_min, source_type,
                    )

            # Surface DuckLake's per-file encryption key as Iceberg
            # `key_metadata` when present. DuckLake stores it as VARCHAR;
            # Iceberg expects bytes. UTF-8 encode; consumers treat as
            # opaque. When the catalog isn't encrypted, the column is
            # null and we emit null (same as before).
            key_md: bytes | None = None
            if df.encryption_key is not None:
                key_md = df.encryption_key.encode("utf-8")

            data_infos.append(DataFileInfo(
                file_path=df.file_path,
                file_size_bytes=df.file_size_bytes,
                record_count=df.record_count,
                stats=_stats_by_column(
                    df.data_file_id, stats_by_file, iceberg_type_by_col,
                    exact_nan_by_file=exact_nan_cache,
                ),
                first_row_id=df.row_id_start,
                partition_values=pvals,
                key_metadata=key_md,
            ))

        # Track row-lineage high-water mark for v3 `last-row-id`.
        for df in data_files:
            if df.row_id_start is not None:
                last_row_id = max(last_row_id, df.row_id_start + df.record_count)

        # Write a data manifest only when there are data files. Similarly
        # for deletes. Both go into the same manifest list.
        manifest_refs: list[tuple[str, int, str]] = []   # (uri, length, content)

        if data_infos:
            data_manifest_bytes = write_data_manifest_bytes(
                snapshot_id=snap_id,
                sequence_number=snap_id,
                schema_json=schema,
                partition_spec_json=(
                    {"spec-id": 1, "fields": [
                        {"name": pf["name"], "field-id": pf["field_id"]}
                        for pf in partition_fields_avro
                    ]}
                    if partition_fields_avro
                    else base_metadata["partition-specs"][0]
                ),
                data_files=data_infos,
                partition_fields_avro=partition_fields_avro or None,
                format_version=_effective_fv,
            )
            dkey = f"{metadata_prefix}{snap_id}-{short_uuid}-m0-data.avro"
            _async_put(dkey, data_manifest_bytes)
            manifest_refs.append((f"s3://{bucket}/{dkey}", len(data_manifest_bytes), "data"))

        # Build a data_file_id -> file_path map so we can fill in
        # position-delete target paths (Iceberg needs the full data-file URI,
        # not DuckLake's numeric id).
        data_file_path_by_id = {df.data_file_id: df.file_path for df in data_files}

        if _effective_fv >= 3 and delete_files:
            # v3 path: rewrite DuckLake's per-file position-delete Parquets
            # into a single Puffin file containing one deletion-vector-v1
            # blob per affected data file. The manifest entry for each
            # blob carries `file_format=puffin` + `content_offset` +
            # `content_size_in_bytes` pointing into the Puffin file. This
            # is the Iceberg-spec preferred delete encoding for v3 and
            # gives readers (Spark 4, Trino, future PyIceberg) a single
            # bitmap per data file rather than a chain of position-delete
            # Parquets to scan.
            from .puffin import DeletionVector, write_puffin_file
            positions_by_data_file: dict[str, set[int]] = {}
            with catalog.read_cursor() as rc:
                for ddf in delete_files:
                    target = data_file_path_by_id.get(ddf.data_file_id)
                    if target is None:
                        continue
                    rows = rc.execute(
                        f"SELECT pos FROM read_parquet('{ddf.file_path}')"
                    ).fetchall()
                    bucket_set = positions_by_data_file.setdefault(target, set())
                    for (p,) in rows:
                        bucket_set.add(int(p))
            if positions_by_data_file:
                dvs = [
                    DeletionVector(referenced_data_file=path, positions=positions)
                    for path, positions in sorted(positions_by_data_file.items())
                ]
                puffin_bytes, descriptors = write_puffin_file(dvs)
                pkey = f"{metadata_prefix}{snap_id}-{short_uuid}-dv.puffin"
                _async_put(pkey, puffin_bytes)
                puffin_uri = f"s3://{bucket}/{pkey}"
                delete_infos = [
                    DeleteFileInfo(
                        file_path=puffin_uri,
                        file_size_bytes=len(puffin_bytes),
                        record_count=d["cardinality"],
                        referenced_data_file=d["referenced_data_file"],
                        file_format="puffin",
                        content_offset=d["offset"],
                        content_size_in_bytes=d["length"],
                    )
                    for d in descriptors
                ]
            else:
                delete_infos = []
        else:
            # v2 (or v3 with no deletes): one manifest entry per DuckLake
            # position-delete Parquet, file_format=parquet (the legacy
            # Iceberg shape). Older readers handle this; v3 readers
            # accept both encodings.
            delete_infos = [
                DeleteFileInfo(
                    file_path=df.file_path,
                    file_size_bytes=df.file_size_bytes,
                    record_count=df.delete_count,
                    referenced_data_file=data_file_path_by_id.get(df.data_file_id),
                )
                for df in delete_files
            ]

        if delete_infos:
            delete_manifest_bytes = write_delete_manifest_bytes(
                snapshot_id=snap_id,
                sequence_number=snap_id,
                schema_json=schema,
                partition_spec_json=base_metadata["partition-specs"][0],
                delete_files=delete_infos,
                format_version=_effective_fv,
            )
            dkey = f"{metadata_prefix}{snap_id}-{short_uuid}-m1-deletes.avro"
            _async_put(dkey, delete_manifest_bytes)
            manifest_refs.append((f"s3://{bucket}/{dkey}", len(delete_manifest_bytes), "deletes"))

        if not manifest_refs:
            # A snapshot that touched only schema with no files still needs a
            # (possibly-empty) manifest list so the snapshot is reachable.
            manifest_refs = []

        list_bytes = write_manifest_list_bytes(
            snapshot_id=snap_id,
            parent_snapshot_id=parent_id,
            sequence_number=snap_id,
            manifest_refs=manifest_refs,
            data_file_count=sum(1 for r in manifest_refs if r[2] == "data"),
            data_row_count=sum(i.record_count for i in data_infos),
            format_version=_effective_fv,
            first_row_id=last_row_id if _effective_fv >= 3 else None,
        )
        list_key = f"{metadata_prefix}snap-{snap_id}-{short_uuid}.avro"
        _async_put(list_key, list_bytes)
        list_uri = f"s3://{bucket}/{list_key}"

        total_files_so_far = len(data_infos)
        total_rows_so_far = sum(i.record_count for i in data_infos)

        snapshots_out.append(build_snapshot(
            snapshot_id=snap_id,
            parent_snapshot_id=parent_id,
            sequence_number=snap_id,
            manifest_list_path=list_uri,
            added_files_count=len(data_infos),
            added_rows_count=sum(i.record_count for i in data_infos),
            total_files=total_files_so_far,
            total_rows=total_rows_so_far,
            schema_id=schema_version,
            timestamp_dt=snap.snapshot_time,
            operation=_operation_from_changes(changes_map.get(snap_id, "")),
        ))
        snapshot_log.append({
            "snapshot-id": snap_id,
            "timestamp-ms": snapshots_out[-1]["timestamp-ms"],
        })
        parent_id = snap_id

    # ---------- finalise TableMetadata --------------------------------
    current_snap = snapshots_out[-1]["snapshot-id"]
    metadata = dict(base_metadata)
    metadata["schemas"] = sorted(schema_by_version.values(), key=lambda s: s["schema-id"])
    metadata["current-schema-id"] = max(s["schema-id"] for s in metadata["schemas"])
    metadata["last-column-id"] = max(
        (f["id"] for s in metadata["schemas"] for f in s["fields"]), default=0
    )

    # Properties persisted in the `duckicelake_table_property` sidecar
    # (since DuckLake has no per-table key/value store).
    sidecar_props = catalog.get_table_properties(ns, table)
    if sidecar_props:
        metadata["properties"] = dict(metadata.get("properties") or {})
        metadata["properties"].update(sidecar_props)

    # Honour a previously-committed `upgrade-format-version`. Stored
    # under `duckicelake.format-version` in the sidecar so it survives
    # across materialises and is a reversible ops knob.
    requested_fv = (
        sidecar_props.get("duckicelake.format-version") if sidecar_props else None
    )
    if requested_fv:
        try:
            metadata["format-version"] = int(requested_fv)
        except ValueError:
            pass

    # Named refs via the `duckicelake_table_tag` sidecar. DuckLake has no
    # branch or tag concept natively; we synthesise refs here. `ref_type`
    # is 'tag' by default, 'branch' for read-only branches (see
    # set-snapshot-ref handling in server.py). Writes on non-main branches
    # still 501.
    sidecar_refs = catalog.get_tags(ns, table)

    # Partition spec was computed at the start of this function; publish
    # it in the final metadata doc.
    if iceberg_spec_fields:
        metadata["partition-specs"] = [
            {"spec-id": 0, "fields": []},
            {"spec-id": 1, "fields": iceberg_spec_fields},
        ]
        metadata["default-spec-id"] = 1
        metadata["last-partition-id"] = 1000 + len(iceberg_spec_fields) - 1

    duck_sort = catalog.current_sort_order(ns, table)
    if duck_sort:
        sort_fields = []
        for expr, direction, null_order in duck_sort:
            # Strip "<col>" quoting we wrote on insert.
            col_name = expr.strip().strip('"')
            source_id = field_id_by_name.get(col_name)
            if source_id is None:
                continue
            sort_fields.append({
                "transform": "identity",
                "source-id": source_id,
                "direction": direction,
                "null-order": null_order.replace("_", "-"),
            })
        metadata["sort-orders"] = [
            {"order-id": 0, "fields": []},
            {"order-id": 1, "fields": sort_fields},
        ]
        metadata["default-sort-order-id"] = 1
    metadata["snapshots"] = snapshots_out
    metadata["snapshot-log"] = snapshot_log
    metadata["current-snapshot-id"] = current_snap
    metadata["last-sequence-number"] = current_snap
    refs: dict[str, dict[str, Any]] = {
        "main": {"type": "branch", "snapshot-id": current_snap}
    }
    for ref_name, (snap, ref_type) in sidecar_refs.items():
        refs[ref_name] = {"type": ref_type, "snapshot-id": int(snap)}
    metadata["refs"] = refs
    if metadata.get("format-version", 2) >= 3:
        metadata["last-row-id"] = last_row_id
        metadata["row-lineage"] = True

    # Surface the canonical DuckLake snapshot id as a table property, the same
    # way Delta UniForm surfaces `delta-version`. Lets operators correlate
    # Iceberg-side state with DuckLake's catalog without reading manifests.
    metadata["properties"] = dict(metadata.get("properties") or {})
    metadata["properties"]["ducklake.snapshot-id"] = str(current_snap_id)

    # metadata-log entry — track every metadata version we've published.
    # Must be set *before* persisting so the on-disk file includes it.
    metadata.setdefault("metadata-log", []).append({
        "timestamp-ms": int(__import__('time').time() * 1000),
        "metadata-file": f"s3://{bucket}/{metadata_key}",
    })
    # Wait for every per-snapshot manifest write to land before publishing
    # the vN.metadata.json that references them. A version-hint pointing at
    # metadata whose manifests aren't yet on S3 would break Hive-style
    # readers that follow it. Re-raise the first exception if any PUT failed.
    for fut in _cf.as_completed(pending_puts):
        fut.result()
    put_executor.shutdown(wait=False)

    # Persist vN.metadata.json to S3 so metadata-location is resolvable.
    _put(client, bucket, metadata_key, json.dumps(metadata).encode("utf-8"))
    # version-hint.text — the Hive-compatible pointer to the latest
    # metadata version. Non-REST readers follow this to find the current
    # metadata file without a catalog round-trip.
    _put(
        client, bucket, f"{metadata_prefix}version-hint.text",
        str(metadata_version).encode("utf-8"),
    )

    # Prime the in-process cache. Next LoadTable for this (ns, table)
    # at the same DuckLake snapshot skips both S3 reads and manifest
    # regeneration.
    catalog.put_cached_metadata(ns, table, current_snap_id, metadata)

    return metadata


def _next_metadata_version(client, bucket: str, prefix: str, current_snap_id: int) -> int:
    """Return the version number to use for the next metadata JSON.

    Reads `version-hint.text` if present and returns next int. Otherwise
    enumerates vN.metadata.json files and picks max + 1. Defaults to 1.
    """
    try:
        body = client.get_object(Bucket=bucket, Key=f"{prefix}version-hint.text")["Body"].read()
        return int(body.decode("utf-8").strip()) + 1
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") not in {"404", "NoSuchKey"}:
            raise
    return 1


def materialise_table(
    catalog: DuckLakeCatalog,
    ns: list[str],
    table: str,
) -> dict[str, Any]:
    """Build base metadata for a table and run materialize_all against it.

    Mirrors the construction in server._build_load_response so the
    NOTIFY listener can materialise without going through the HTTP path.
    Returns the final metadata dict (same shape materialize_all returns).
    """
    from .iceberg import build_table_metadata

    columns = catalog.get_columns(ns, table)
    table_uuid = catalog.table_uuid(ns, table)
    s3 = catalog.settings.s3
    table_prefix = s3.table_prefix(ns[0], table, catalog.ref.data_prefix)
    loc = f"s3://{s3.bucket}/{table_prefix}".rstrip("/")
    metadata_prefix = f"{table_prefix}metadata/"

    base_metadata = build_table_metadata(
        table_uuid=table_uuid,
        location=loc,
        columns=columns,
        properties=None,
    )
    return materialize_all(
        catalog=catalog,
        ns=ns,
        table=table,
        base_metadata=base_metadata,
        metadata_prefix=metadata_prefix,
    )
