"""Phase 4 — file-layer masking: masked Parquet exports.

When a masking policy carries `file_layer_masking=true`, catalog-level
masking (views + metadata signals) is not enough: any engine that reads
Parquet directly still sees raw bytes. This module materializes the mask
*physically* — one per-snapshot current-state export per (table,
mask-signature):

    {data_prefix}__masked__/{ns}/{table}/{sig}/snap-{N}-{tok8}/*.parquet

Current-state export (not per-file copies) is correct by construction: the
exporting DuckDB engine applies position/equality deletes, the row filter,
and the mask expressions in one `COPY (SELECT …)` pinned `AT (VERSION =>
N)`. Masked readers lose time travel — acceptable (and a leak-vector
reduction). The sig directory is the credential boundary: masked
principals are vended GetObject on exactly that prefix, never the base
table's.

Atomicity without S3 rename: every attempt writes a fresh uniquified
`snap-{N}-{tok}` dir that nothing references; the "commit" is the sidecar
pointer upsert (+ the masking view repoint, done by the caller). Partials
are invisible and swept by retention. A PG advisory lock serializes
concurrent exporters per (ns, table, sig).

The sidecar row also stores the *recipe* (masks/filter/columns) so the
notify listener can eagerly refresh known signatures on new snapshots
without knowing any principal's JWT. A recomputed signature mismatch
(schema or policy changed) drops the export instead of refreshing it —
the next request lazily creates the new shape.

Everything is fail-open and audited: an export failure degrades to
catalog-level masking, never a broken read.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .catalog import DuckLakeCatalog
from .config import Settings
from .policies import (
    MaskDecision,
    TablePolicyPlan,
    _ql,
    _qi,
    build_masked_export_select,
    build_masked_view_sql,
    mask_signature,
    plan_is_exportable,
)

log = logging.getLogger("duckicelake.masked_export")

# Tuning knobs are read per-manager in __init__ (not at import) so file
# config (.env / duckicelake.toml, applied during load_settings) is honored
# — a module-level read would snapshot os.environ before apply_file_config
# runs and silently ignore the TOML values.
#   DUCKICELAKE_MASKED_RETAIN_SNAP_DIRS — snap dirs kept per sig (current +
#     previous): an in-flight glob of the just-replaced dir must not 404.
#   DUCKICELAKE_MASKED_EXPORT_TTL_DAYS — sigs idle this long stop being
#     eagerly refreshed by the listener (lazily re-created on next request).
#   DUCKICELAKE_MASKED_EXPORT_FILE_SIZE — DuckDB COPY FILE_SIZE_BYTES.


@dataclass
class MaskedExport:
    schema: str
    table: str
    sig: str
    snapshot: int
    prefix: str          # S3 key prefix of the live snap dir, ends with "/"


def _ensure_export_sidecar(cur) -> None:
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.duckicelake_masked_export (
            schema_name       VARCHAR NOT NULL,
            table_name        VARCHAR NOT NULL,
            sig               VARCHAR NOT NULL,
            masks_json        JSONB NOT NULL,
            row_filter        TEXT,
            columns_json      JSONB NOT NULL,
            current_snapshot  BIGINT,
            current_prefix    TEXT,
            updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (schema_name, table_name, sig)
        )
    """)


def _lock_key(ns: str, table: str, sig: str) -> int:
    digest = hashlib.sha256(f"{ns}.{table}.{sig}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


class MaskedExportManager:
    """Materialize / discover / refresh / GC masked Parquet exports."""

    def __init__(self, catalog: DuckLakeCatalog, settings: Settings,
                 store=None, view_manager=None) -> None:
        self.catalog = catalog
        self.settings = settings
        self.store = store                  # GovernanceStore, for audit (optional)
        self.view_manager = view_manager    # MaskingViewManager: repoint views
        #                                     to the fresh snap dir after export
        self.retain_snap_dirs = int(os.environ.get(
            "DUCKICELAKE_MASKED_RETAIN_SNAP_DIRS", "2"))
        # Never sweep a snap dir younger than this, regardless of the count
        # cap: a client that was vended creds + shadow metadata for a dir can
        # keep reading it until those creds expire. Default comfortably above
        # the 3600s STS credential TTL so an in-flight reader's dir is never
        # deleted out from under its glob (A3).
        self.retain_grace_seconds = int(os.environ.get(
            "DUCKICELAKE_MASKED_RETAIN_GRACE_SECONDS", "3900"))
        self.export_ttl_days = int(os.environ.get(
            "DUCKICELAKE_MASKED_EXPORT_TTL_DAYS", "7"))
        self.export_file_size = os.environ.get(
            "DUCKICELAKE_MASKED_EXPORT_FILE_SIZE", "256MB")

    # ---- discovery -------------------------------------------------------

    def current_export(self, ns: list[str], table: str,
                       sig: str) -> MaskedExport | None:
        with self.catalog.pg_cursor(autocommit=False) as cur:
            _ensure_export_sidecar(cur)
            cur.execute(
                """
                SELECT current_snapshot, current_prefix
                FROM public.duckicelake_masked_export
                WHERE schema_name = %s AND table_name = %s AND sig = %s
                  AND current_prefix IS NOT NULL
                """,
                (ns[0], table, sig),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return MaskedExport(schema=ns[0], table=table, sig=sig,
                            snapshot=row[0], prefix=row[1])

    def touch(self, ns: list[str], table: str, sig: str) -> None:
        """Mark the sig as recently requested (drives refresh TTL)."""
        try:
            with self.catalog.pg_cursor() as cur:
                _ensure_export_sidecar(cur)
                cur.execute(
                    """
                    UPDATE public.duckicelake_masked_export
                    SET last_requested_at = now()
                    WHERE schema_name = %s AND table_name = %s AND sig = %s
                    """,
                    (ns[0], table, sig),
                )
        except Exception:
            log.exception("touch failed for %s.%s sig %s", ns[0], table, sig)

    # ---- materialization ---------------------------------------------------

    def ensure_export_for_plan(self, ns: list[str], table: str,
                               plan: TablePolicyPlan) -> MaskedExport | None:
        """Idempotently materialize the plan's masked export at the table's
        current snapshot. Returns the live export, or None when the plan
        doesn't demand file-layer masking / can't be exported / fails
        (callers fail-open to catalog-level masking)."""
        if not plan.file_layer or plan.is_empty():
            return None
        if not plan_is_exportable(plan):
            log.warning("plan for %s.%s has session-dependent expressions — "
                        "refusing file-layer export", ns[0], table)
            return None
        sig = mask_signature(plan)
        try:
            snap = self.catalog.current_ducklake_snapshot(ns, table)
            if snap is None:
                return None
            existing = self.current_export(ns, table, sig)
            if existing is not None and existing.snapshot == snap:
                self.touch(ns, table, sig)
                return existing
            return self._export(ns, table, plan, sig, snap)
        except Exception:
            log.exception("masked export failed for %s.%s (sig %s) — "
                          "falling back to catalog-level masking",
                          ns[0], table, sig)
            self._audit(plan.principal, f"{ns[0]}.{table}", sig,
                        decision="error_file_layer_fallback", detail={})
            return None

    def _export(self, ns: list[str], table: str, plan: TablePolicyPlan,
                sig: str, snap: int) -> MaskedExport | None:
        s3 = self.settings.s3
        started = datetime.now(timezone.utc)
        with self.catalog.pg_cursor() as lock_cur:
            got = lock_cur.execute(
                "SELECT pg_try_advisory_lock(%s)", (_lock_key(ns[0], table, sig),)
            ).fetchone()[0]
            if not got:
                # someone else is exporting this sig right now — serve
                # whatever pointer exists (possibly one snapshot behind)
                return self.current_export(ns, table, sig)
            try:
                # re-check under the lock (loser-then-winner race)
                existing = self.current_export(ns, table, sig)
                if existing is not None and existing.snapshot == snap:
                    return existing

                tok = uuid.uuid4().hex[:8]
                prefix = (f"{s3.masked_sig_prefix(ns[0], table, sig, self.catalog.ref.data_prefix)}"
                          f"snap-{snap}-{tok}/")
                select = build_masked_export_select(
                    plan, catalog_name=self.settings.catalog_name,
                    snapshot_id=snap,
                )
                # Iceberg readers map parquet columns by FIELD ID, not name
                # — without explicit ids the shadow metadata's schema can't
                # bind and every column reads NULL. Ids are 1-based in
                # projection order, matching the shadow schema built from a
                # DESCRIBE of these very files. Column names are escaped
                # (_qi) so a name with a quote can't break out of FIELD_IDS.
                field_ids = ", ".join(
                    f'{_qi(c)}: {i}' for i, c in enumerate(plan.columns, start=1)
                )
                copy_target = _ql(f"s3://{s3.bucket}/{prefix.rstrip('/')}")
                with self.catalog.export_cursor() as con:
                    con.execute(
                        f"COPY ({select}) TO {copy_target} "
                        f"(FORMAT PARQUET, FILE_SIZE_BYTES '{self.export_file_size}', "
                        f"FILENAME_PATTERN 'part-{{i}}', "
                        f"FIELD_IDS {{{field_ids}}})"
                    )
                files = self.list_export_files(prefix)
                with self.catalog.pg_cursor() as cur:
                    _ensure_export_sidecar(cur)
                    cur.execute(
                        """
                        INSERT INTO public.duckicelake_masked_export
                            (schema_name, table_name, sig, masks_json,
                             row_filter, columns_json, current_snapshot,
                             current_prefix, updated_at, last_requested_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now(), now())
                        ON CONFLICT (schema_name, table_name, sig) DO UPDATE
                          SET masks_json = EXCLUDED.masks_json,
                              row_filter = EXCLUDED.row_filter,
                              columns_json = EXCLUDED.columns_json,
                              current_snapshot = EXCLUDED.current_snapshot,
                              current_prefix = EXCLUDED.current_prefix,
                              updated_at = now(),
                              last_requested_at = now()
                        """,
                        (ns[0], table, sig,
                         json.dumps([{"column": m.column,
                                      "mask_expr": m.mask_expr,
                                      "policy_name": m.policy_name}
                                     for m in plan.masks]),
                         plan.row_filter,
                         json.dumps(plan.columns),
                         snap, prefix),
                    )
                self._retain(ns[0], table, sig, keep_prefix=prefix)
                ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
                self._audit(plan.principal, f"{ns[0]}.{table}", sig,
                            decision="exported",
                            detail={"snapshot": snap, "prefix": prefix,
                                    "files": len(files), "duration_ms": ms})
                log.info("masked export %s.%s sig=%s snap=%s: %d files in %dms",
                         ns[0], table, sig, snap, len(files), ms)
                export = MaskedExport(schema=ns[0], table=table, sig=sig,
                                      snapshot=snap, prefix=prefix)
                self._repoint_views(ns, table, plan, export)
                return export
            finally:
                lock_cur.execute("SELECT pg_advisory_unlock(%s)",
                                 (_lock_key(ns[0], table, sig),))

    # ---- eager refresh -----------------------------------------------------

    def refresh_known_sigs(self, ns: list[str], table: str,
                           *, ttl: timedelta | None = None) -> None:
        """Re-export every recently-requested sig of the table at its new
        current snapshot (notify-listener hook). A recomputed signature
        mismatch (schema or policy drift) drops the export instead — the
        next request lazily creates the new shape."""
        if ttl is None:
            ttl = timedelta(days=self.export_ttl_days)
        try:
            with self.catalog.pg_cursor(autocommit=False) as cur:
                _ensure_export_sidecar(cur)
                cur.execute(
                    """
                    SELECT sig, masks_json, row_filter, columns_json
                    FROM public.duckicelake_masked_export
                    WHERE schema_name = %s AND table_name = %s
                      AND last_requested_at > %s
                    """,
                    (ns[0], table, datetime.now(timezone.utc) - ttl),
                )
                rows = cur.fetchall()
        except Exception:
            log.exception("refresh scan failed for %s.%s", ns[0], table)
            return
        if not rows:
            return
        live_cols = [c.name for c in self.catalog.get_columns(ns, table)]
        for sig, masks_json, row_filter, columns_json in rows:
            plan = self._plan_from_recipe(ns[0], table, masks_json,
                                          row_filter, live_cols)
            if mask_signature(plan) != sig:
                log.info("sig %s for %s.%s is stale (schema/policy drift) — "
                         "dropping export", sig, ns[0], table)
                self.gc_table(ns, table, keep=set(), only_sig=sig)
                continue
            self.ensure_export_for_plan(ns, table, plan)

    def _repoint_views(self, ns: list[str], table: str,
                       plan: TablePolicyPlan, export: MaskedExport) -> None:
        """After a fresh export, swing the masking view (and transparent
        schema view) onto the new snap dir — listener-driven refreshes
        must update what existing client sessions resolve. Best-effort."""
        if self.view_manager is None:
            return
        try:
            self.view_manager.ensure_view_for_plan(ns, table, plan,
                                                   export=export)
            if self.settings.transparent_masking:
                self.view_manager.ensure_transparent_schema(ns, table, plan,
                                                            export=export)
        except Exception:
            log.exception("view repoint failed for %s.%s sig %s",
                          ns[0], table, export.sig)

    @staticmethod
    def _plan_from_recipe(schema: str, table: str, masks_json,
                          row_filter: str | None,
                          columns: list[str]) -> TablePolicyPlan:
        masks = masks_json if isinstance(masks_json, list) else json.loads(masks_json)
        decisions = [MaskDecision(column=m["column"],
                                  policy_name=m.get("policy_name", ""),
                                  mask_expr=m["mask_expr"], doc="")
                     for m in masks]
        return TablePolicyPlan(
            principal="__refresh__", roles=[], schema=schema, table=table,
            masks=decisions,
            row_filter=row_filter,
            columns=list(columns),
            # view_sql is required by the view-manager guard; for
            # export-backed views it is also the fail-open expression body
            view_sql=build_masked_view_sql(
                schema=schema, table=table, columns=list(columns),
                masks={d.column: d.mask_expr for d in decisions},
                row_filter=row_filter,
            ),
            file_layer=True,
        )

    # ---- lifecycle ---------------------------------------------------------

    def gc_table(self, ns: list[str], table: str, keep: set[str],
                 *, only_sig: str | None = None) -> int:
        """Drop exports (sidecar rows + S3 prefixes) for sigs not in `keep`.
        Best-effort; returns dropped count."""
        dropped = 0
        try:
            with self.catalog.pg_cursor(autocommit=False) as cur:
                _ensure_export_sidecar(cur)
                cur.execute(
                    "SELECT sig FROM public.duckicelake_masked_export "
                    "WHERE schema_name = %s AND table_name = %s",
                    (ns[0], table),
                )
                sigs = [r[0] for r in cur.fetchall()]
        except Exception:
            log.exception("gc scan failed for %s.%s", ns[0], table)
            return 0
        for sig in sigs:
            if sig in keep or (only_sig is not None and sig != only_sig):
                continue
            try:
                self._delete_prefix(
                    self.settings.s3.masked_sig_prefix(ns[0], table, sig, self.catalog.ref.data_prefix))
                with self.catalog.pg_cursor() as cur:
                    cur.execute(
                        "DELETE FROM public.duckicelake_masked_export "
                        "WHERE schema_name = %s AND table_name = %s AND sig = %s",
                        (ns[0], table, sig),
                    )
                dropped += 1
            except Exception:
                log.exception("gc failed for %s.%s sig %s", ns[0], table, sig)
        return dropped

    def purge_table(self, ns: list[str], table: str) -> None:
        """DROP TABLE hook: remove every masked export of the table."""
        self.gc_table(ns, table, keep=set())
        try:
            self._delete_prefix(
                self.settings.s3.masked_table_prefix(ns[0], table, self.catalog.ref.data_prefix))
        except Exception:
            log.exception("masked-prefix purge failed for %s.%s", ns[0], table)

    def _retain(self, schema: str, table: str, sig: str,
                *, keep_prefix: str) -> None:
        """Keep the live snap dir + the previous one; sweep older/orphaned
        attempt dirs under the sig prefix. A dir younger than
        `retain_grace_seconds` is kept regardless of the count cap, so a dir
        that a slow reader was just vended creds for isn't deleted out from
        under its in-flight glob (A3)."""
        try:
            sig_prefix = self.settings.s3.masked_sig_prefix(schema, table, sig, self.catalog.ref.data_prefix)
            dirs: dict[str, list[str]] = {}
            newest_mtime: dict[str, datetime] = {}
            client = self.catalog.s3_client
            for page in client.get_paginator("list_objects_v2").paginate(
                    Bucket=self.settings.s3.bucket, Prefix=sig_prefix):
                for o in page.get("Contents", []):
                    rest = o["Key"][len(sig_prefix):]
                    if "/" not in rest:
                        continue
                    d = rest.split("/", 1)[0]
                    dirs.setdefault(d, []).append(o["Key"])
                    lm = o["LastModified"]
                    if d not in newest_mtime or lm > newest_mtime[d]:
                        newest_mtime[d] = lm
            # keep newest retain_snap_dirs by snapshot number (dir name is
            # snap-{N}-{tok}); the live dir always survives
            def snap_no(d: str) -> int:
                try:
                    return int(d.split("-")[1])
                except (IndexError, ValueError):
                    return -1
            live_dir = keep_prefix[len(sig_prefix):].strip("/")
            ordered = sorted(dirs, key=snap_no, reverse=True)
            now = datetime.now(timezone.utc)
            grace = timedelta(seconds=self.retain_grace_seconds)
            recent = {d for d, lm in newest_mtime.items() if now - lm < grace}
            keep = set(ordered[:self.retain_snap_dirs]) | {live_dir} | recent
            stale_keys = [k for d, keys in dirs.items() if d not in keep
                          for k in keys]
            self._delete_keys(stale_keys)
        except Exception:
            log.exception("retention sweep failed for %s.%s sig %s",
                          schema, table, sig)

    # ---- shadow Iceberg metadata (REST path) ---------------------------------

    def shadow_metadata(self, ns: list[str], table: str,
                        export: MaskedExport) -> tuple[str, dict] | None:
        """Real Iceberg TableMetadata over the masked export, so every
        Iceberg-REST reader — including the DuckDB iceberg extension, which
        has no view or scan-planning support — reads masked bytes
        transparently.

        One snapshot, data manifests only (a current-state export has no
        delete files by construction), no column stats (readers tolerate;
        no pruning on the redacted tier). The metadata tree lives INSIDE
        the export's snap dir, so it rotates and is retained/GC'd with it.
        Idempotent per snap dir: an existing metadata.json is reused.
        Returns (metadata_location, metadata) or None on any failure
        (caller falls back to catalog-level signals)."""
        try:
            s3 = self.settings.s3
            meta_prefix = f"{export.prefix}metadata/"
            meta_key = f"{meta_prefix}v1.metadata.json"
            client = self.catalog.s3_client
            location = f"s3://{s3.bucket}/{export.prefix.rstrip('/')}"
            meta_loc = f"s3://{s3.bucket}/{meta_key}"
            try:
                body = client.get_object(Bucket=s3.bucket, Key=meta_key)
                return meta_loc, json.loads(body["Body"].read())
            except Exception:
                pass    # not built yet

            glob = _ql(f"s3://{s3.bucket}/{export.prefix}*.parquet")
            with self.catalog.export_cursor() as con:
                described = con.execute(
                    f"DESCRIBE SELECT * FROM read_parquet({glob})"
                ).fetchall()
                per_file = con.execute(
                    f"SELECT file_name, num_rows, file_size_bytes "
                    f"FROM parquet_file_metadata({glob})"
                ).fetchall()

            from .catalog import ColumnInfo
            from .iceberg import build_table_metadata
            from .manifest import (
                DataFileInfo,
                build_snapshot,
                write_data_manifest_bytes,
                write_manifest_list_bytes,
            )

            columns = [ColumnInfo(name=r[0], data_type=r[1],
                                  is_nullable=True, ordinal=i)
                       for i, r in enumerate(described)]
            data_files = [
                DataFileInfo(file_path=fname, file_size_bytes=int(fsize),
                             record_count=int(nrows))
                for fname, nrows, fsize in per_file
            ]
            total_rows = sum(f.record_count for f in data_files)
            snap_id = export.snapshot

            md = build_table_metadata(
                table_uuid=str(uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"duckicelake-masked.{ns[0]}.{table}.{export.sig}")),
                location=location,
                columns=columns,
                properties={
                    "duckicelake.masked": "true",
                    "duckicelake.mask-signature": export.sig,
                    "duckicelake.base-table": f"{ns[0]}.{table}",
                },
            )
            schema_json = md["schemas"][0]

            manifest_bytes = write_data_manifest_bytes(
                snapshot_id=snap_id, sequence_number=1,
                schema_json=schema_json,
                partition_spec_json={"spec-id": 0, "fields": []},
                data_files=data_files,
                format_version=md["format-version"],
            )
            manifest_key = f"{meta_prefix}m0-{uuid.uuid4()}.avro"
            client.put_object(Bucket=s3.bucket, Key=manifest_key,
                              Body=manifest_bytes)

            mlist_bytes = write_manifest_list_bytes(
                snapshot_id=snap_id, parent_snapshot_id=None,
                sequence_number=1,
                manifest_refs=[(f"s3://{s3.bucket}/{manifest_key}",
                                len(manifest_bytes), "data")],
                data_file_count=len(data_files),
                data_row_count=total_rows,
                format_version=md["format-version"],
            )
            mlist_key = f"{meta_prefix}snap-{snap_id}-{uuid.uuid4()}.avro"
            client.put_object(Bucket=s3.bucket, Key=mlist_key,
                              Body=mlist_bytes)

            snap = build_snapshot(
                snapshot_id=snap_id, parent_snapshot_id=None,
                sequence_number=1,
                manifest_list_path=f"s3://{s3.bucket}/{mlist_key}",
                added_files_count=len(data_files),
                added_rows_count=total_rows,
                total_files=len(data_files), total_rows=total_rows,
            )
            md["snapshots"] = [snap]
            md["current-snapshot-id"] = snap_id
            md["last-sequence-number"] = 1
            md["refs"] = {"main": {"type": "branch", "snapshot-id": snap_id}}
            md["snapshot-log"] = [{"snapshot-id": snap_id,
                                   "timestamp-ms": snap["timestamp-ms"]}]

            client.put_object(Bucket=s3.bucket, Key=meta_key,
                              Body=json.dumps(md).encode())
            return meta_loc, md
        except Exception:
            log.exception("shadow metadata build failed for %s.%s sig %s",
                          ns[0], table, export.sig)
            return None

    # ---- S3 helpers ----------------------------------------------------------

    def _list_keys(self, prefix: str) -> list[tuple[str, int]]:
        client = self.catalog.s3_client
        out: list[tuple[str, int]] = []
        for page in client.get_paginator("list_objects_v2").paginate(
                Bucket=self.settings.s3.bucket, Prefix=prefix):
            out += [(o["Key"], o["Size"]) for o in page.get("Contents", [])]
        return out

    def list_export_files(self, snap_prefix: str) -> list[tuple[str, int]]:
        """(key, size) of the parquet parts in one snap dir."""
        return [(k, sz) for k, sz in self._list_keys(snap_prefix)
                if k.endswith(".parquet")]

    def _delete_keys(self, keys: list[str]) -> None:
        """Batch-delete via S3 DeleteObjects (≤1000 keys/call) — a masked
        export of a large table holds thousands of parts; per-key deletes
        would block the GC/listener path for minutes."""
        if not keys:
            return
        client = self.catalog.s3_client
        bucket = self.settings.s3.bucket
        for i in range(0, len(keys), 1000):
            client.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": k} for k in keys[i:i + 1000]],
                        "Quiet": True},
            )

    def _delete_prefix(self, prefix: str) -> None:
        self._delete_keys([k for k, _ in self._list_keys(prefix)])

    # ---- audit ---------------------------------------------------------------

    def _audit(self, principal: str, object_: str, sig: str,
               *, decision: str, detail: dict) -> None:
        if self.store is None:
            return
        try:
            self.store.audit_load(
                principal=principal, object_=object_,
                masked_cols=[], applied_policies=[], row_filtered=False,
                operation="masked_export", decision=decision,
                detail={"sig": sig, **detail},
            )
        except Exception:
            log.exception("masked-export audit failed")
