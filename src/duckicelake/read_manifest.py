"""Read Iceberg manifest-list + manifest Avro files back into Python.

On `commit-table { add-snapshot }` an Iceberg client has already written
its manifest chain and a `manifest-list` Avro pointing at it. The proxy
needs to extract:

  - **Added data file paths** (status=1 entries in data manifests) — fed
    to DuckLake's `ducklake_add_data_files()` for footer-stat-based
    registration.
  - **Removed data file paths** (status=2 entries in data manifests) —
    fed to a direct UPDATE on `ducklake_data_file.end_snapshot`. Used
    by `overwrite` and `delete` commits.
  - **Position-delete-file specs** (content=1 manifest entries) — fed
    to direct INSERT into `ducklake_delete_file`. Used by Iceberg
    merge-on-read deletes.

We don't interpret DataFile stats from the client's manifests — DuckLake
re-reads them from the Parquet footer itself.
"""
from __future__ import annotations

import io
from dataclasses import dataclass

from botocore.exceptions import ClientError

from . import s3util
from fastavro import reader

from .config import S3Settings


@dataclass
class PositionDeleteSpec:
    """A position-delete file the client uploaded and is asking us to register."""
    path: str                          # absolute s3:// URI of the delete parquet
    target_data_file: str              # absolute s3:// URI of the data file deletes apply to
    delete_count: int                  # rows in the delete parquet
    file_size_bytes: int


@dataclass
class EqualityDeleteSpec:
    """An equality-delete file — one row per key to delete, columns per
    Iceberg `equality_ids`. DuckLake doesn't store equality deletes
    natively; the server translates these to `DELETE FROM … WHERE (cols) IN (…)`.
    """
    path: str
    equality_field_ids: list[int]
    record_count: int
    file_size_bytes: int


@dataclass
class CommitChanges:
    added_data_paths: list[str]
    removed_data_paths: list[str]
    position_deletes: list[PositionDeleteSpec]
    equality_deletes: list[EqualityDeleteSpec]


def _s3_client(s3: S3Settings):
    return s3util.s3_client(s3)


def _read_s3(client, uri: str) -> bytes:
    if not uri.startswith("s3://"):
        raise ValueError(f"Expected s3:// URI, got {uri!r}")
    rest = uri[len("s3://"):]
    bucket, _, key = rest.partition("/")
    if not key:
        raise ValueError(f"URI has no key: {uri!r}")
    try:
        return client.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as e:
        raise RuntimeError(
            f"Proxy could not read {uri} with its root credentials: "
            f"{e.response.get('Error', {}).get('Code')}. The client-written "
            f"manifest chain must live in a bucket the proxy's root creds "
            f"can read."
        ) from e


def extract_commit_changes(
    manifest_list_uri: str,
    s3: S3Settings,
    *,
    snapshot_id: int,
) -> CommitChanges:
    """Walk a client manifest-list → triage into adds, removes, and delete-file specs.

    Snapshot-id filter: `manifest_file.added_snapshot_id == snapshot_id`
    so we only act on manifests new in this commit. Manifests inherited
    from prior snapshots reference files we've already registered with
    DuckLake; touching them would double-register / double-tombstone.
    """
    client = _s3_client(s3)
    ml_bytes = _read_s3(client, manifest_list_uri)

    added: list[str] = []
    removed: list[str] = []
    pos_deletes: list[PositionDeleteSpec] = []
    eq_deletes: list[EqualityDeleteSpec] = []

    for manifest_file in reader(io.BytesIO(ml_bytes)):
        if manifest_file.get("added_snapshot_id") != snapshot_id:
            continue

        manifest_path = manifest_file["manifest_path"]
        manifest_content = manifest_file.get("content", 0)
        m_bytes = _read_s3(client, manifest_path)

        for entry in reader(io.BytesIO(m_bytes)):
            # ManifestEntry.status: 0=EXISTING (carry-over), 1=ADDED, 2=DELETED
            status = entry.get("status", 1)
            df = entry.get("data_file") or {}
            df_content = df.get("content", 0)
            path = df.get("file_path")
            if not path:
                continue

            if manifest_content == 0 and df_content == 0:
                # Data manifest, data file
                if status == 1:
                    added.append(path)
                elif status == 2:
                    removed.append(path)
                # status=0 (EXISTING) handled by added_snapshot_id filter above
            elif manifest_content == 1 and df_content == 1:
                # Delete manifest, position-delete file
                if status != 1:
                    # EXISTING delete files are already registered; DELETED
                    # delete files mean the deletes were undone, which we'd
                    # need to UPDATE end_snapshot for — out of scope here.
                    continue
                target = df.get("referenced_data_file")
                if not target:
                    raise ValueError(
                        f"Iceberg position-delete file {path} has no "
                        f"`referenced_data_file` — without it we can't "
                        f"link the delete to a data file in DuckLake."
                    )
                pos_deletes.append(PositionDeleteSpec(
                    path=path,
                    target_data_file=target,
                    delete_count=int(df.get("record_count", 0)),
                    file_size_bytes=int(df.get("file_size_in_bytes", 0)),
                ))
            elif df_content == 2:
                # Equality-delete file. DuckLake doesn't support these
                # natively, but we translate them at commit time by reading
                # the file's equality rows and issuing DELETE statements
                # against DuckLake. See server.py::_apply_equality_deletes.
                if status != 1:
                    continue
                eq_ids = df.get("equality_ids") or []
                eq_deletes.append(EqualityDeleteSpec(
                    path=path,
                    equality_field_ids=[int(e) for e in eq_ids],
                    record_count=int(df.get("record_count", 0)),
                    file_size_bytes=int(df.get("file_size_in_bytes", 0)),
                ))
            # Other combinations (e.g. data-file in delete manifest) are
            # malformed per Iceberg spec and we silently skip.

    return CommitChanges(
        added_data_paths=added,
        removed_data_paths=removed,
        position_deletes=pos_deletes,
        equality_deletes=eq_deletes,
    )


# Back-compat shim kept for any caller that only wants the added paths.
def extract_data_file_paths(
    manifest_list_uri: str,
    s3: S3Settings,
    *,
    snapshot_id: int,
) -> list[str]:
    return extract_commit_changes(
        manifest_list_uri, s3, snapshot_id=snapshot_id,
    ).added_data_paths
