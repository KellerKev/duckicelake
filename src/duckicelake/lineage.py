"""Lineage as OpenLineage events, stored per catalog next to its audit trail.

Four sources, one table (`duckicelake_lineage_event` in the catalog's own
sidecar schema, so it goes wherever the catalog goes — including away, when
the catalog is deprovisioned):

  * commit  — harvested from DuckLake's own commit log
              (`ducklake_snapshot` + `ducklake_snapshot_changes`), so every
              write path is covered: Iceberg REST commits, DuckLake-direct
              writers, maintenance-free DDL. Datasets are the tables a
              snapshot created, wrote, altered, renamed or dropped. Who
              wrote it comes from `duckicelake_snapshot_writer`, filled by a
              trigger with the Postgres login role of the committing session
              (a vended per-principal role maps back to its principal) —
              unlike DuckLake's `author`, a client cannot set it. The
              harvest runs every minute and again right before maintenance
              expires snapshots, so no commit is lost.
  * access  — a credential vend or Iceberg LoadTable that was granted:
              the dataset as an input of a `duckicelake.access.*` job, with
              who, the masked columns and whether rows were filtered. These
              are access records, not input→output edges. A LoadTable of a
              table no policy applies to is recorded too, though the audit
              trail leaves it out (once per principal and table in five
              minutes: record_plain_access).
  * query   — a materialized result set: the tables the query read are its
              inputs, the result set its output.
  * ingest  — OpenLineage RunEvents POSTed by another producer (Levitate's
              warehouse writes, a Spark job with openlineage-spark, ...).
              Stored as sent, plus a facet naming the authenticated caller.

Real input→output edges exist where duckicelake saw the SQL (result sets) or
a producer reported them (ingest). A DuckLake-direct write alone has outputs
only; its producer can link it by putting `{"openlineage": {"run_id": ...,
"job_namespace": ..., "job_name": ...}}` in the DuckLake commit's
`extra_info`, which becomes the commit event's parent run facet.

Carried tags: a producer that copies tagged data can say which tags went with
it, in the output dataset's `duckicelake_carriedTags` facet (`{"tags": [...]}`).
duckicelake keeps them per table (`duckicelake_lineage_carried`) and forgets
them when the table is created anew, replaced or dropped, and moves them when
it is renamed — whoever did that, since it reads it from the commit log. It
enforces nothing with them; a broker reads them (GET .../lineage/carried-tags)
to treat a copy like its source.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Iterable
from urllib.parse import urlsplit

from psycopg import errors as pg_errors

from .catalog import pg_advisory_lock
from .sqlsafe import qi

if TYPE_CHECKING:
    from .catalog import DuckLakeCatalog

log = logging.getLogger("duckicelake.lineage")

PRODUCER = "https://github.com/KellerKev/duckicelake"
RUN_EVENT_SCHEMA = "https://openlineage.io/spec/2-0-2/OpenLineage.json#/$defs/RunEvent"
FACET_SCHEMA = f"{PRODUCER}/blob/main/docs/REFERENCE.md#lineage"
_LIFECYCLE_SCHEMA = ("https://openlineage.io/spec/facets/1-0-1/"
                     "LifecycleStateChangeDatasetFacet.json#/$defs/LifecycleStateChangeDatasetFacet")
_PARENT_SCHEMA = "https://openlineage.io/spec/facets/1-0-1/ParentRunFacet.json#/$defs/ParentRunFacet"
_JOBTYPE_SCHEMA = "https://openlineage.io/spec/facets/2-0-3/JobTypeJobFacet.json#/$defs/JobTypeJobFacet"

_RUN_NS = uuid.UUID("6f1c2d0e-8a59-4d7e-9b51-1c0de1a9e000")
KINDS = ("commit", "access", "query", "ingest")
MAX_INGEST_BYTES = 1 << 20

CARRIED_FACET = "duckicelake_carriedTags"
MAX_CARRIED_TAGS = 200

# Granted read-path decisions recorded as access events. Errors/denials stay
# in the audit trail only: lineage is about data that actually moved.
ACCESS_OPS = {"ducklake_credentials", "load_table"}

DATA_CHANGES = {"inserted_into_table": "insert", "inlined_insert": "insert",
                "deleted_from_table": "delete", "inlined_delete": "delete"}

_ENSURED: set[str] = set()
#: schema -> monotonic time of the next try to create its writer trigger,
#: for schemas whose snapshot table was too busy to take the lock
_TRIGGER_PENDING: dict[str, float] = {}
TRIGGER_RETRY_SECONDS = 30.0
TRIGGER_LOCK_TIMEOUT_MS = 3000


def reset_lineage_cache() -> None:
    _ENSURED.clear()
    _TRIGGER_PENDING.clear()
    _SEEN_ACCESS.clear()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Sidecars
# ---------------------------------------------------------------------------

def ensure_lineage_sidecars(cur, schema: str) -> None:
    """Create the lineage sidecars + the snapshot-writer trigger in `schema`
    (the catalog's DuckLake metadata schema). Once per process per schema;
    serialized across workers like the governance sidecars."""
    if schema in _ENSURED:
        due = _TRIGGER_PENDING.get(schema)
        if due is None or due > time.monotonic():
            return
    with pg_advisory_lock(cur, f"duckicelake:lineage_sidecars:{schema}"):
        if schema not in _ENSURED:
            _ddl(cur, qi(schema))
        in_place = _ensure_writer_trigger(cur, qi(schema))
    _ENSURED.add(schema)
    if in_place:
        _TRIGGER_PENDING.pop(schema, None)
    else:
        _TRIGGER_PENDING[schema] = time.monotonic() + TRIGGER_RETRY_SECONDS


def _ddl(cur, sc: str) -> None:
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {sc}.duckicelake_lineage_event (
            id            BIGSERIAL PRIMARY KEY,
            event_time    TIMESTAMPTZ NOT NULL,
            kind          VARCHAR NOT NULL,      -- commit | access | query | ingest
            principal     VARCHAR,
            job_namespace VARCHAR NOT NULL,
            job_name      VARCHAR NOT NULL,
            run_id        UUID NOT NULL,
            inputs        TEXT[] NOT NULL DEFAULT '{{}}',
            outputs       TEXT[] NOT NULL DEFAULT '{{}}',
            snapshot_id   BIGINT UNIQUE,         -- commit events only
            event         JSONB NOT NULL
        )
    """)
    for name, expr in (("inputs", "USING gin (inputs)"), ("outputs", "USING gin (outputs)"),
                       ("time", "(event_time)")):
        cur.execute(f"CREATE INDEX IF NOT EXISTS duckicelake_lineage_event_{name}_idx "
                    f"ON {sc}.duckicelake_lineage_event {expr}")
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {sc}.duckicelake_lineage_cursor (
            id               INT PRIMARY KEY CHECK (id = 1),
            last_snapshot_id BIGINT NOT NULL
        )
    """)
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {sc}.duckicelake_snapshot_writer (
            snapshot_id BIGINT PRIMARY KEY,
            pg_role     TEXT,
            principal   TEXT,
            via         TEXT,
            recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {sc}.duckicelake_lineage_carried (
            schema_name TEXT NOT NULL,
            table_name  TEXT NOT NULL,
            tag         TEXT NOT NULL,
            run_id      UUID,                    -- the run that last carried it
            at          TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (schema_name, table_name, tag)
        )
    """)


def _ensure_writer_trigger(cur, sc: str) -> bool:
    """The trigger that records who commits. Creating it locks
    `ducklake_snapshot` against writers, and that lock would wait behind any
    client's open transaction with every later commit queueing behind it. So:
    only when the trigger is missing, and for at most TRIGGER_LOCK_TIMEOUT_MS
    — False when the table was busy (the caller tries again later; commits
    made meanwhile have no recorded writer)."""
    cur.execute("SELECT to_regclass(%s)", (f"{sc}.ducklake_snapshot",))
    if cur.fetchone()[0] is None:
        return True   # not a DuckLake schema (yet); the harvest has nothing to read either
    # SECURITY DEFINER: the committing role (a vended writer) needs no grant on
    # the sidecar; inside, session_user is still that login role. Must never
    # fail a commit, hence the exception block.
    cur.execute(f"""
        CREATE OR REPLACE FUNCTION {sc}.duckicelake_record_snapshot_writer()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $$
        DECLARE p TEXT;
        BEGIN
            BEGIN
                SELECT principal_sub INTO p FROM public.duckicelake_pg_principal
                WHERE pg_role = session_user::text;
            EXCEPTION WHEN OTHERS THEN p := NULL;
            END;
            INSERT INTO {sc}.duckicelake_snapshot_writer (snapshot_id, pg_role, principal, via)
            VALUES (NEW.snapshot_id, session_user::text, p,
                    CASE WHEN p IS NULL THEN NULL ELSE 'vended' END)
            ON CONFLICT (snapshot_id) DO NOTHING;
            RETURN NULL;
        EXCEPTION WHEN OTHERS THEN
            RETURN NULL;
        END $$
    """)
    cur.execute("SELECT 1 FROM pg_trigger WHERE tgname = 'duckicelake_snapshot_writer' "
                "AND tgrelid = to_regclass(%s) AND NOT tgisinternal",
                (f"{sc}.ducklake_snapshot",))
    if cur.fetchone():
        return True
    cur.execute("SELECT current_setting('lock_timeout')")
    before = cur.fetchone()[0]
    try:
        with cur.connection.transaction():
            cur.execute("SELECT set_config('lock_timeout', %s, true)",
                        (f"{TRIGGER_LOCK_TIMEOUT_MS}ms",))
            cur.execute(f"""
                CREATE TRIGGER duckicelake_snapshot_writer
                AFTER INSERT ON {sc}.ducklake_snapshot
                FOR EACH ROW EXECUTE FUNCTION {sc}.duckicelake_record_snapshot_writer()
            """)
            cur.execute("SELECT set_config('lock_timeout', %s, true)", (before,))
    except pg_errors.LockNotAvailable:
        log.warning("lineage: %s.ducklake_snapshot is busy; the writer trigger will be "
                    "created on a later try", sc)
        return False
    except pg_errors.DuplicateObject:
        pass          # another worker created it in between
    return True


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------

def catalog_id_of(catalog: "DuckLakeCatalog") -> str:
    return catalog._ref.catalog_name


def dataset_namespace(catalog: "DuckLakeCatalog") -> str:
    """`duckicelake://<host>/<catalog>`: the host of the public URL when one
    is configured, so events forwarded elsewhere name datasets unambiguously."""
    pub = getattr(catalog.settings, "public_url", None)
    host = urlsplit(pub).netloc if pub else "localhost"
    return f"duckicelake://{host}/{catalog_id_of(catalog)}"


def canonical_names(cur, sc: str, names: Iterable[str]) -> dict[str, str]:
    """{name as given: the table's or view's name as the catalog spells it},
    for the `schema.table` names that match a current table or view when case
    is ignored (DuckDB resolves names that way, so producers that fold case
    still mean that table). A name with no match, or with several, is left
    out: it is kept as given."""
    wanted: dict[str, list[str]] = {}
    for n in names:
        if isinstance(n, str) and n:
            wanted.setdefault(n.lower(), []).append(n)
    if not wanted:
        return {}
    cur.execute("SELECT to_regclass(%s), to_regclass(%s)",
                (f"{sc}.ducklake_table", f"{sc}.ducklake_view"))
    has_table, has_view = cur.fetchone()
    if has_table is None:
        return {}
    sql = f"""
        SELECT s.schema_name || '.' || t.table_name
        FROM {sc}.ducklake_table t
        JOIN {sc}.ducklake_schema s ON s.schema_id = t.schema_id AND s.end_snapshot IS NULL
        WHERE t.end_snapshot IS NULL
          AND lower(s.schema_name || '.' || t.table_name) = ANY(%s)"""
    args: list = [list(wanted)]
    if has_view is not None:
        sql += f"""
        UNION
        SELECT s.schema_name || '.' || v.view_name
        FROM {sc}.ducklake_view v
        JOIN {sc}.ducklake_schema s ON s.schema_id = v.schema_id AND s.end_snapshot IS NULL
        WHERE v.end_snapshot IS NULL
          AND lower(s.schema_name || '.' || v.view_name) = ANY(%s)"""
        args.append(list(wanted))
    cur.execute(sql, args)
    found: dict[str, list[str]] = {}
    for (real,) in cur.fetchall():
        found.setdefault(real.lower(), []).append(real)
    out: dict[str, str] = {}
    for low, givens in wanted.items():
        reals = found.get(low) or []
        for g in givens:
            if g in reals:
                continue                      # already spelled as the catalog has it
            if len(reals) == 1:
                out[g] = reals[0]
    return out


def canonical_name(catalog: "DuckLakeCatalog", cur, name: str) -> str:
    try:
        return canonical_names(cur, catalog.sidecar_sql, [name]).get(name, name)
    except Exception:
        log.exception("lineage: could not resolve the name %s", name)
        return name


def _facet(**fields) -> dict:
    return {"_producer": PRODUCER, "_schemaURL": FACET_SCHEMA, **fields}


def _event(*, event_time: datetime, run_id: uuid.UUID, job_ns: str, job_name: str,
           job_type: str, run_facets: dict, inputs: list[dict], outputs: list[dict]) -> dict:
    return {
        "eventType": "COMPLETE",
        "eventTime": event_time.isoformat(),
        "producer": PRODUCER,
        "schemaURL": RUN_EVENT_SCHEMA,
        "run": {"runId": str(run_id), "facets": run_facets},
        "job": {"namespace": job_ns, "name": job_name,
                "facets": {"jobType": {"_producer": PRODUCER, "_schemaURL": _JOBTYPE_SCHEMA,
                                       "processingType": "BATCH", "integration": "DUCKICELAKE",
                                       "jobType": job_type}}},
        "inputs": inputs,
        "outputs": outputs,
    }


def _insert(cur, sc: str, *, kind: str, principal: str | None, event: dict,
            snapshot_id: int | None = None) -> None:
    ins = [d["name"] for d in event.get("inputs") or [] if isinstance(d, dict) and d.get("name")]
    outs = [d["name"] for d in event.get("outputs") or [] if isinstance(d, dict) and d.get("name")]
    cur.execute(
        f"""
        INSERT INTO {sc}.duckicelake_lineage_event
            (event_time, kind, principal, job_namespace, job_name, run_id,
             inputs, outputs, snapshot_id, event)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
        ON CONFLICT (snapshot_id) DO NOTHING
        """,
        (event["eventTime"], kind, principal, event["job"]["namespace"], event["job"]["name"],
         event["run"]["runId"], ins, outs, snapshot_id, json.dumps(event, default=str)),
    )


# ---------------------------------------------------------------------------
# Commit harvest
# ---------------------------------------------------------------------------

def parse_changes(text: str | None) -> list[tuple[str, Any]]:
    """`created_table:"s"."t",inlined_insert:3` → [("created_table", ["s","t"]),
    ("inlined_insert", "3")]. Quoted names may hold commas, dots and doubled
    quotes. Anything unparseable comes back as ("unparsed", text)."""
    if not text:
        return []
    out: list[tuple[str, Any]] = []
    i, n = 0, len(text)
    try:
        while i < n:
            j = text.index(":", i)
            kind = text[i:j]
            i = j + 1
            if i < n and text[i] == '"':
                names = []
                while True:
                    assert text[i] == '"'
                    i += 1
                    buf = []
                    while True:
                        c = text[i]
                        if c == '"':
                            if i + 1 < n and text[i + 1] == '"':
                                buf.append('"')
                                i += 2
                                continue
                            i += 1
                            break
                        buf.append(c)
                        i += 1
                    names.append("".join(buf))
                    if i < n and text[i] == ".":
                        i += 1
                        continue
                    break
                value: Any = names
            else:
                k = text.find(",", i)
                k = n if k < 0 else k
                value = text[i:k]
                i = k
            out.append((kind, value))
            if i < n:
                assert text[i] == ","
                i += 1
    except (ValueError, AssertionError, IndexError):
        return [("unparsed", text)]
    return out


def _table_at(cur, sc: str, table_id: int, snap: int) -> tuple[str, str] | None:
    cur.execute(
        f"""
        SELECT s.schema_name, t.table_name
        FROM {sc}.ducklake_table t
        JOIN {sc}.ducklake_schema s ON s.schema_id = t.schema_id
        WHERE t.table_id = %s AND t.begin_snapshot <= %s
          AND (t.end_snapshot IS NULL OR t.end_snapshot >= %s)
        ORDER BY t.begin_snapshot DESC, s.begin_snapshot DESC LIMIT 1
        """, (table_id, snap, snap))
    r = cur.fetchone()
    return (r[0], r[1]) if r else None


def _view_at(cur, sc: str, view_id: int, snap: int) -> tuple[str, str] | None:
    cur.execute(
        f"""
        SELECT s.schema_name, v.view_name
        FROM {sc}.ducklake_view v
        JOIN {sc}.ducklake_schema s ON s.schema_id = v.schema_id
        WHERE v.view_id = %s AND v.begin_snapshot <= %s
          AND (v.end_snapshot IS NULL OR v.end_snapshot >= %s)
        ORDER BY v.begin_snapshot DESC LIMIT 1
        """, (view_id, snap, snap))
    r = cur.fetchone()
    return (r[0], r[1]) if r else None


def _renamed_from(cur, sc: str, schema: str, table: str, snap: int) -> tuple[str, str] | None:
    """A `created_table` whose table id existed before this snapshot is a rename."""
    cur.execute(
        f"""
        SELECT ps.schema_name, p.table_name
        FROM {sc}.ducklake_table t
        JOIN {sc}.ducklake_schema s ON s.schema_id = t.schema_id
        JOIN {sc}.ducklake_table p ON p.table_id = t.table_id AND p.end_snapshot = %s
        JOIN {sc}.ducklake_schema ps ON ps.schema_id = p.schema_id
        WHERE t.begin_snapshot = %s AND s.schema_name = %s AND t.table_name = %s
        LIMIT 1
        """, (snap, snap, schema, table))
    r = cur.fetchone()
    return (r[0], r[1]) if r else None


def _datasets_for(cur, sc: str, snap: int, changes: list[tuple[str, Any]]) -> dict[str, dict]:
    """{"schema.table": {"ops": set, "lifecycle": str|None, "previous": str|None}}.
    A table dropped and created under the same name in one snapshot (CREATE OR
    REPLACE) is one dataset with lifecycle OVERWRITE."""
    ds: dict[str, dict] = {}
    created: dict[str, str] = {}      # lower name -> name, tables created here
    dropped: dict[str, str] = {}      # lower name -> name, tables dropped here

    def entry(name: str) -> dict:
        return ds.setdefault(name, {"ops": set(), "lifecycle": None, "previous": None})

    for kind, value in changes:
        try:
            if kind in ("created_table", "created_view") and isinstance(value, list) and len(value) == 2:
                name = f"{value[0]}.{value[1]}"
                prev = _renamed_from(cur, sc, value[0], value[1], snap) if kind == "created_table" else None
                e = entry(name)
                if prev:
                    e["lifecycle"], e["previous"] = "RENAME", f"{prev[0]}.{prev[1]}"
                else:
                    e["lifecycle"] = "CREATE"
                    if kind == "created_table":
                        created[name.lower()] = name
            elif kind in DATA_CHANGES or kind in ("altered_table", "dropped_table"):
                t = _table_at(cur, sc, int(value), snap)
                if not t:
                    continue
                name = f"{t[0]}.{t[1]}"
                if kind == "dropped_table":
                    dropped[name.lower()] = name
                    if name not in ds:
                        entry(name)["lifecycle"] = "DROP"
                    continue
                e = entry(name)
                if kind in DATA_CHANGES:
                    e["ops"].add(DATA_CHANGES[kind])
                else:
                    e["lifecycle"] = e["lifecycle"] or "ALTER"
            elif kind == "dropped_view":
                v = _view_at(cur, sc, int(value), snap)
                if v:
                    entry(f"{v[0]}.{v[1]}")["lifecycle"] = "DROP"
            # schema DDL, inline flushes, compaction: not dataset lineage
        except (ValueError, TypeError):
            continue
    for low, old in dropped.items():
        new = created.get(low)
        if new is None:
            if old in ds and ds[old]["lifecycle"] != "RENAME":
                ds[old]["lifecycle"] = "DROP"
            continue
        if old != new and old in ds:          # replaced under another spelling
            ds[new]["ops"] |= ds.pop(old)["ops"]
        ds[new]["lifecycle"] = "OVERWRITE"
    return ds


def _parent_facet(extra: str | None) -> dict | None:
    if not extra:
        return None
    try:
        info = json.loads(extra)
        ol = info.get("openlineage") if isinstance(info, dict) else None
        if not isinstance(ol, dict) or not ol.get("run_id") or not ol.get("job_name"):
            return None
        return {"_producer": PRODUCER, "_schemaURL": _PARENT_SCHEMA,
                "run": {"runId": str(uuid.UUID(str(ol["run_id"])))},
                "job": {"namespace": str(ol.get("job_namespace") or "default"),
                        "name": str(ol["job_name"])}}
    except (ValueError, TypeError, AttributeError):
        return None


def commit_event(catalog: "DuckLakeCatalog", *, snapshot_id: int, snapshot_time: datetime,
                 changes_text: str | None, datasets: dict[str, dict], author: str | None,
                 message: str | None, extra: str | None, pg_role: str | None,
                 principal: str | None, via: str | None) -> dict:
    ns = dataset_namespace(catalog)
    outputs = []
    for name in sorted(datasets):
        d = datasets[name]
        facets: dict = {}
        if d["lifecycle"]:
            lc: dict = {"_producer": PRODUCER, "_schemaURL": _LIFECYCLE_SCHEMA,
                        "lifecycleStateChange": d["lifecycle"]}
            if d["previous"]:
                lc["previousIdentifier"] = {"namespace": ns, "name": d["previous"]}
            facets["lifecycleStateChange"] = lc
        if d["ops"]:
            facets["duckicelake_write"] = _facet(operations=sorted(d["ops"]))
        outputs.append({"namespace": ns, "name": name, "facets": facets})
    run_facets: dict = {"duckicelake_commit": _facet(
        snapshotId=snapshot_id, changes=changes_text, author=author, commitMessage=message,
        writer={"pgRole": pg_role, "principal": principal, "via": via,
                # false: the commit predates the writer trigger (lineage was
                # switched on later), so nobody was recorded for it
                "recorded": pg_role is not None or via is not None})}
    parent = _parent_facet(extra)
    if parent:
        run_facets["parent"] = parent
    return _event(event_time=snapshot_time,
                  run_id=uuid.uuid5(_RUN_NS, f"{catalog_id_of(catalog)}/snapshot/{snapshot_id}"),
                  job_ns=ns, job_name="duckicelake.commit", job_type="COMMIT",
                  run_facets=run_facets, inputs=[], outputs=outputs)


def harvest(catalog: "DuckLakeCatalog", *, batch: int = 500, max_batches: int = 20,
            settle_seconds: float = 0) -> int:
    """Turn new DuckLake snapshots into commit events. Returns how many
    events were written. Safe to call from every worker: the cursor row is
    locked SKIP LOCKED, so one harvests while the others move on.
    `settle_seconds` leaves the newest snapshots for later, so a REST commit
    is attributed (attribute_commit) before it is harvested."""
    sc = catalog.sidecar_sql
    with catalog.pg_cursor() as cur:
        ensure_lineage_sidecars(cur, catalog.sidecar_schema)
    written = 0
    for _ in range(max_batches):
        n, more = _harvest_batch(catalog, sc, batch, settle_seconds)
        written += n
        if not more:
            break
    return written


def _harvest_batch(catalog: "DuckLakeCatalog", sc: str, batch: int,
                   settle_seconds: float = 0) -> tuple[int, bool]:
    with catalog.pg_transaction() as cur:
        cur.execute(f"INSERT INTO {sc}.duckicelake_lineage_cursor VALUES (1, -1) "
                    "ON CONFLICT (id) DO NOTHING")
        cur.execute(f"SELECT last_snapshot_id FROM {sc}.duckicelake_lineage_cursor "
                    "WHERE id = 1 FOR UPDATE SKIP LOCKED")
        row = cur.fetchone()
        if row is None:
            return 0, False          # another worker is harvesting this catalog
        last = row[0]
        cur.execute(
            f"""
            SELECT s.snapshot_id, s.snapshot_time, c.changes_made, c.author,
                   c.commit_message, c.commit_extra_info, w.pg_role, w.principal, w.via,
                   s.snapshot_time > now() - make_interval(secs => %s) AS young
            FROM {sc}.ducklake_snapshot s
            LEFT JOIN {sc}.ducklake_snapshot_changes c USING (snapshot_id)
            LEFT JOIN {sc}.duckicelake_snapshot_writer w USING (snapshot_id)
            WHERE s.snapshot_id > %s
            ORDER BY s.snapshot_id
            LIMIT %s
            """, (settle_seconds, last, batch))
        fetched = cur.fetchall()
        # Stop at the first snapshot still settling, in id order: the cursor
        # must never move past a snapshot that was not harvested.
        rows = []
        for r in fetched:
            if r[9]:
                break
            rows.append(r)
        if not rows:
            return 0, False
        written = 0
        for (snap, ts, changes, author, message, extra, pg_role, principal, via, _y) in rows:
            datasets = _datasets_for(cur, sc, snap, parse_changes(changes))
            if not datasets:
                continue
            # Savepoints: neither extra may cost the harvest its batch.
            if pg_role is None and principal is None:
                try:
                    with cur.connection.transaction():
                        principal = _writer_from_audit(cur, sc, ts, datasets)
                except Exception:
                    log.exception("lineage: audit lookup failed for snapshot %s", snap)
                via = "audit" if principal else None
            try:
                with cur.connection.transaction():
                    _carried_after_commit(cur, sc, ts, datasets, _parent_facet(extra))
            except Exception:
                log.exception("lineage: carried tags not updated for snapshot %s", snap)
            ev = commit_event(catalog, snapshot_id=snap, snapshot_time=ts, changes_text=changes,
                              datasets=datasets, author=author, message=message, extra=extra,
                              pg_role=pg_role, principal=principal, via=via)
            _insert(cur, sc, kind="commit", principal=principal, event=ev, snapshot_id=snap)
            written += 1
        top = rows[-1][0]
        cur.execute(f"UPDATE {sc}.duckicelake_lineage_cursor SET last_snapshot_id = %s "
                    "WHERE id = 1", (top,))
        # writer rows are only needed until their snapshot is harvested
        cur.execute(f"DELETE FROM {sc}.duckicelake_snapshot_writer WHERE snapshot_id <= %s", (top,))
        return written, len(rows) == batch == len(fetched)


def _writer_from_audit(cur, sc: str, ts: datetime, datasets: dict[str, dict]) -> str | None:
    """Who made a commit that has no recorded writer (it predates the trigger):
    the one principal the audit trail shows committing one of its tables
    through the Iceberg REST API at that moment. None when the audit trail
    has no such row or names more than one principal — a guess is worse than
    a blank. Commits made straight on DuckLake before the trigger existed
    stay without a writer: nothing recorded who made them."""
    cur.execute("SELECT to_regclass(%s)", (f"{sc}.duckicelake_governance_audit",))
    if cur.fetchone()[0] is None:
        return None
    cur.execute(
        f"""
        SELECT DISTINCT principal_sub FROM {sc}.duckicelake_governance_audit
        WHERE operation = 'commit_table' AND decision = 'ok' AND object = ANY(%s)
          AND ts BETWEEN %s::timestamptz - interval '5 seconds'
                     AND %s::timestamptz + interval '30 seconds'
        LIMIT 2
        """, (sorted(datasets), ts, ts))
    found = [r[0] for r in cur.fetchall()]
    return found[0] if len(found) == 1 and found[0] else None


def _carried_after_commit(cur, sc: str, ts: datetime, datasets: dict[str, dict],
                          parent: dict | None) -> None:
    """Keep the carried tags in step with what a commit did to its tables: a
    table created anew, replaced or dropped starts without the tags it
    carried before; a renamed one takes them along. The run that made the
    commit (its parent run facet) keeps what it reported itself, whichever
    of the two arrived first."""
    run_id = (parent or {}).get("run", {}).get("runId")
    tbl = f"{sc}.duckicelake_lineage_carried"
    for name, d in datasets.items():
        lc = d["lifecycle"]
        if lc in ("CREATE", "OVERWRITE", "DROP"):
            cur.execute(
                f"DELETE FROM {tbl} WHERE lower(schema_name || '.' || table_name) = lower(%s) "
                "AND at < %s AND (%s::uuid IS NULL OR run_id IS DISTINCT FROM %s::uuid)",
                (name, ts, run_id, run_id))
        elif lc == "RENAME" and d["previous"]:
            cur.execute(f"SELECT s.schema_name, t.table_name FROM {sc}.ducklake_table t "
                        f"JOIN {sc}.ducklake_schema s ON s.schema_id = t.schema_id "
                        "WHERE s.schema_name || '.' || t.table_name = %s LIMIT 1", (name,))
            new = cur.fetchone()
            if not new:
                continue
            cur.execute(
                f"""
                INSERT INTO {tbl} (schema_name, table_name, tag, run_id, at)
                SELECT %s, %s, tag, run_id, at FROM {tbl}
                WHERE lower(schema_name || '.' || table_name) = lower(%s) AND at < %s
                ON CONFLICT (schema_name, table_name, tag) DO NOTHING
                """, (new[0], new[1], d["previous"], ts))
            cur.execute(f"DELETE FROM {tbl} WHERE lower(schema_name || '.' || table_name) "
                        "= lower(%s) AND at < %s", (d["previous"], ts))


def attribute_commit(catalog: "DuckLakeCatalog", *, principal: str, table: tuple[str, str],
                     after_snapshot: int | None) -> None:
    """An Iceberg REST commit runs on the proxy's own connection, so the
    trigger records the proxy's role, not the caller. The commit handler
    names the caller here for the snapshots it just made on its table
    (best-effort; never raises)."""
    if after_snapshot is None:
        return
    sc = catalog.sidecar_sql
    try:
        with catalog.pg_cursor() as cur:
            ensure_lineage_sidecars(cur, catalog.sidecar_schema)
            cur.execute(
                f"""
                INSERT INTO {sc}.duckicelake_snapshot_writer AS w
                    (snapshot_id, pg_role, principal, via)
                SELECT DISTINCT s.snapshot_id, current_user, %s, 'rest'
                FROM {sc}.ducklake_snapshot s
                JOIN {sc}.ducklake_data_file d
                  ON d.begin_snapshot = s.snapshot_id OR d.end_snapshot = s.snapshot_id
                JOIN {sc}.ducklake_table t ON t.table_id = d.table_id
                JOIN {sc}.ducklake_schema sch ON sch.schema_id = t.schema_id
                WHERE s.snapshot_id > %s AND sch.schema_name = %s AND t.table_name = %s
                ON CONFLICT (snapshot_id) DO UPDATE
                  SET principal = EXCLUDED.principal, via = 'rest'
                  WHERE w.principal IS NULL
                """, (principal, after_snapshot, table[0], table[1]))
    except Exception:
        log.exception("lineage: REST commit attribution failed for %s.%s", *table)


def current_snapshot_id(catalog: "DuckLakeCatalog") -> int | None:
    try:
        with catalog.pg_cursor() as cur:
            cur.execute(f"SELECT max(snapshot_id) FROM {catalog.sidecar_sql}.ducklake_snapshot")
            return cur.fetchone()[0]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Access / query / ingest
# ---------------------------------------------------------------------------

def record_access(cur, catalog: "DuckLakeCatalog", *, principal: str, operation: str,
                  object_: str, decision: str, masked_cols: list[str] | None,
                  row_filtered: bool, detail: dict | None) -> None:
    """Called from GovernanceStore.audit_load inside its cursor (best-effort
    there). `object_` is `schema.table` or `schema.*` (a namespace vend)."""
    ensure_lineage_sidecars(cur, catalog.sidecar_schema)
    ns = dataset_namespace(catalog)
    whole_namespace = object_.endswith(".*")
    inputs = [] if whole_namespace else [{
        "namespace": ns, "name": object_,
        "facets": {"duckicelake_access": _facet(
            maskedColumns=sorted(masked_cols or []), rowFiltered=bool(row_filtered))}}]
    d = detail or {}
    run_facets = {"duckicelake_access": _facet(
        principal=principal, operation=operation, decision=decision,
        scope=("namespace:" + object_[:-2]) if whole_namespace else "table",
        actor=d.get("actor"), channel=d.get("channel"))}
    ev = _event(event_time=_now(), run_id=uuid.uuid4(), job_ns=ns,
                job_name=f"duckicelake.access.{operation}", job_type="ACCESS",
                run_facets=run_facets, inputs=inputs, outputs=[])
    _insert(cur, catalog.sidecar_sql, kind="access", principal=principal, event=ev)


_SEEN_ACCESS: dict[tuple, float] = {}
_SEEN_LOCK = threading.Lock()


def access_dedup_seconds() -> float:
    return float(os.environ.get("DUCKICELAKE_LINEAGE_ACCESS_DEDUP_SECONDS", "300"))


def record_plain_access(catalog: "DuckLakeCatalog", *, principal: str, operation: str,
                        object_: str, detail: dict | None = None) -> None:
    """A granted read that the audit trail does not record because no policy
    applies to the table (an Iceberg LoadTable): still an access event. An
    Iceberg client loads a table for every query it plans, so the same
    principal reading the same table is recorded once per
    DUCKICELAKE_LINEAGE_ACCESS_DEDUP_SECONDS (300; 0 records every load) per
    worker. Best-effort; never raises."""
    if disabled():
        return
    try:
        window = access_dedup_seconds()
        if window > 0:
            key = (catalog_id_of(catalog), principal, operation, object_,
                   (detail or {}).get("actor"), (detail or {}).get("channel"))
            now = time.monotonic()
            with _SEEN_LOCK:
                if _SEEN_ACCESS.get(key, 0) > now:
                    return
                if len(_SEEN_ACCESS) > 20000:
                    for k in [k for k, t in _SEEN_ACCESS.items() if t <= now]:
                        _SEEN_ACCESS.pop(k, None)
                    if len(_SEEN_ACCESS) > 20000:
                        _SEEN_ACCESS.clear()
                _SEEN_ACCESS[key] = now + window
        with catalog.pg_cursor() as cur:
            record_access(cur, catalog, principal=principal, operation=operation,
                          object_=object_, decision="ok", masked_cols=None,
                          row_filtered=False, detail=detail)
    except Exception:
        log.exception("lineage: access event failed for %s on %s", principal, object_)


def record_query(catalog: "DuckLakeCatalog", *, principal: str, namespace: str,
                 tables: Iterable[tuple[str, str]], result_set_id: str, rows: int,
                 actor: str | None = None, channel: str | None = None) -> None:
    """A materialized result set: the tables its query read → the result set."""
    ns = dataset_namespace(catalog)
    try:
        with catalog.pg_cursor() as cur:
            ensure_lineage_sidecars(cur, catalog.sidecar_schema)
            ev = _event(
                event_time=_now(), run_id=uuid.uuid4(), job_ns=ns,
                job_name="duckicelake.result_set", job_type="QUERY",
                run_facets={"duckicelake_query": _facet(principal=principal, namespace=namespace,
                                                        rows=rows, actor=actor, channel=channel)},
                inputs=[{"namespace": ns, "name": f"{s}.{t}"} for s, t in sorted(set(tables))],
                outputs=[{"namespace": f"{ns}/result-sets", "name": result_set_id}])
            _insert(cur, catalog.sidecar_sql, kind="query", principal=principal, event=ev)
    except Exception:
        log.exception("lineage: result-set event failed for %s", result_set_id)


class IngestError(ValueError):
    """Not an acceptable OpenLineage RunEvent (HTTP 400)."""


def _ds_list(v: Any, path: str) -> list[dict]:
    if v is None:
        return []
    if not isinstance(v, list):
        raise IngestError(f"{path}: expected a list")
    for i, d in enumerate(v):
        if not (isinstance(d, dict) and isinstance(d.get("namespace"), str)
                and isinstance(d.get("name"), str) and d["name"]):
            raise IngestError(f"{path}[{i}]: a dataset needs namespace and name")
    return v


def _carried_of(dataset: dict, path: str = "output") -> list[str]:
    """The tags an output dataset says it carries (its duckicelake_carriedTags
    facet), lowercased; [] when it has none."""
    facets = dataset.get("facets")
    facet = facets.get(CARRIED_FACET) if isinstance(facets, dict) else None
    if facet is None:
        return []
    tags = facet.get("tags") if isinstance(facet, dict) else None
    if (not isinstance(tags, list) or len(tags) > MAX_CARRIED_TAGS
            or not all(isinstance(t, str) and 0 < len(t) <= 200 for t in tags)):
        raise IngestError(f"{path}.facets.{CARRIED_FACET}: tags must be a list of at most "
                          f"{MAX_CARRIED_TAGS} names")
    return sorted({t.lower() for t in tags})


def validate_run_event(ev: Any) -> dict:
    if not isinstance(ev, dict):
        raise IngestError("event must be an object")
    if ev.get("eventType", "COMPLETE") not in ("START", "RUNNING", "COMPLETE", "ABORT",
                                               "FAIL", "OTHER"):
        raise IngestError("eventType is not an OpenLineage run state")
    try:
        datetime.fromisoformat(str(ev.get("eventTime")).replace("Z", "+00:00"))
    except ValueError:
        raise IngestError("eventTime must be an ISO-8601 timestamp") from None
    run, job = ev.get("run"), ev.get("job")
    if not isinstance(run, dict) or not run.get("runId"):
        raise IngestError("run.runId is required")
    try:
        uuid.UUID(str(run["runId"]))
    except ValueError:
        raise IngestError("run.runId must be a UUID") from None
    if not (isinstance(job, dict) and isinstance(job.get("namespace"), str)
            and isinstance(job.get("name"), str) and job["name"]):
        raise IngestError("job.namespace and job.name are required")
    _ds_list(ev.get("inputs"), "inputs")
    for i, d in enumerate(_ds_list(ev.get("outputs"), "outputs")):
        _carried_of(d, f"outputs[{i}]")
    if not isinstance(ev.get("producer"), str):
        raise IngestError("producer is required")
    return ev


def ingest(catalog: "DuckLakeCatalog", events: list[dict], *, principal: str) -> int:
    """Store producer-sent RunEvents. Datasets in this catalog's namespace
    are indexed by their table name — spelled as the catalog spells it, so a
    producer that folds case still links to the table's commits — others are
    kept by their full name. The authenticated caller is recorded in a facet
    the producer cannot set. Tags an output carries are kept per table."""
    ns = dataset_namespace(catalog)
    sc = catalog.sidecar_sql
    with catalog.pg_transaction() as cur:
        ensure_lineage_sidecars(cur, catalog.sidecar_schema)
        events = [json.loads(json.dumps(ev)) for ev in events]      # own copies
        real = canonical_names(cur, sc, {
            d["name"] for ev in events for side in ("inputs", "outputs")
            for d in ev.get(side) or [] if d["namespace"] == ns})
        for ev in events:
            ev.setdefault("eventType", "COMPLETE")
            renamed = {}
            for side in ("inputs", "outputs"):
                for d in ev.get(side) or []:
                    if d["namespace"] != ns:
                        d["_indexName"] = f"{d['namespace']}/{d['name']}"
                    elif d["name"] in real:
                        renamed[d["name"]] = real[d["name"]]
                        d["name"] = real[d["name"]]
            ev["run"].setdefault("facets", {})["duckicelake_ingest"] = _facet(
                principal=principal, receivedAt=_now().isoformat(),
                **({"renamed": renamed} if renamed else {}))
            for d in ev.get("outputs") or []:
                tags = _carried_of(d)
                if tags and d["namespace"] == ns and "." in d["name"]:
                    schema, table = _split_name(cur, sc, d["name"])
                    cur.executemany(
                        f"""
                        INSERT INTO {sc}.duckicelake_lineage_carried
                            (schema_name, table_name, tag, run_id)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (schema_name, table_name, tag)
                        DO UPDATE SET run_id = EXCLUDED.run_id, at = now()
                        """, [(schema, table, t, ev["run"]["runId"]) for t in tags])
            idx = {side: [d.pop("_indexName", d["name"]) for d in ev.get(side) or []]
                   for side in ("inputs", "outputs")}
            cur.execute(
                f"""
                INSERT INTO {catalog.sidecar_sql}.duckicelake_lineage_event
                    (event_time, kind, principal, job_namespace, job_name, run_id,
                     inputs, outputs, event)
                VALUES (%s, 'ingest', %s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (ev["eventTime"], principal, ev["job"]["namespace"], ev["job"]["name"],
                 ev["run"]["runId"], idx["inputs"], idx["outputs"], json.dumps(ev)))
    return len(events)


def _split_name(cur, sc: str, name: str) -> tuple[str, str]:
    """`schema.table` into its two parts: by the catalog's own tables when
    one matches (a name may hold dots), else at the first dot."""
    cur.execute("SELECT to_regclass(%s)", (f"{sc}.ducklake_table",))
    if cur.fetchone()[0] is not None:
        cur.execute(
            f"SELECT s.schema_name, t.table_name FROM {sc}.ducklake_table t "
            f"JOIN {sc}.ducklake_schema s ON s.schema_id = t.schema_id "
            "WHERE t.end_snapshot IS NULL AND s.schema_name || '.' || t.table_name = %s LIMIT 1",
            (name,))
        r = cur.fetchone()
        if r:
            return r[0], r[1]
    schema, _, table = name.partition(".")
    return schema, table


def carried_tags(catalog: "DuckLakeCatalog") -> list[dict]:
    """[{schema, table, tag}]: the tags each table carries from what it was
    made of, as producers reported them (see the module doc)."""
    with catalog.pg_cursor() as cur:
        ensure_lineage_sidecars(cur, catalog.sidecar_schema)
        cur.execute(f"SELECT schema_name, table_name, tag FROM "
                    f"{catalog.sidecar_sql}.duckicelake_lineage_carried ORDER BY 1, 2, 3")
        return [{"schema": r[0], "table": r[1], "tag": r[2]} for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def list_events(catalog: "DuckLakeCatalog", *, after_id: int = 0, limit: int = 500,
                dataset: str | None = None, kinds: list[str] | None = None,
                since: datetime | None = None, newest_first: bool = False) -> list[dict]:
    """Events in id order (a forwarding cursor: pass the last `id` back as
    `after_id`). `dataset` matches inputs or outputs. `newest_first` turns
    the order round (the latest `limit` events: for looking, not forwarding)."""
    where, args = ["id > %s"], [after_id]
    if dataset:
        where.append("(%s = ANY(inputs) OR %s = ANY(outputs))")
        args += [dataset, dataset]
    if kinds:
        where.append("kind = ANY(%s)")
        args.append(kinds)
    if since:
        where.append("event_time >= %s")
        args.append(since)
    with catalog.pg_cursor() as cur:
        ensure_lineage_sidecars(cur, catalog.sidecar_schema)
        if dataset:
            real = canonical_name(catalog, cur, dataset)
            args = [real if a is dataset else a for a in args]
        cur.execute(
            f"SELECT id, kind, principal, event FROM {catalog.sidecar_sql}.duckicelake_lineage_event "
            f"WHERE {' AND '.join(where)} ORDER BY id {'DESC' if newest_first else ''} "
            "LIMIT %s", (*args, limit))
        return [{"id": r[0], "kind": r[1], "principal": r[2], "event": r[3]}
                for r in cur.fetchall()]


def graph(catalog: "DuckLakeCatalog", dataset: str, *, depth: int = 3,
          direction: str = "both", limit: int = 2000) -> dict:
    """Dataset-level lineage around `dataset`, from events with both inputs
    and outputs (result sets, ingested jobs): upstream = what it was made
    from, downstream = what was made from it. Plus who touched it last."""
    sc = catalog.sidecar_sql
    edges: dict[tuple[str, str, str], dict] = {}
    with catalog.pg_cursor() as cur:
        ensure_lineage_sidecars(cur, catalog.sidecar_schema)
        dataset = canonical_name(catalog, cur, dataset)
        nodes = {dataset}
        for side, other in (("outputs", "inputs"), ("inputs", "outputs")):
            if direction == ("downstream" if side == "outputs" else "upstream"):
                continue
            frontier = {dataset}
            for _ in range(max(1, min(depth, 10))):
                if not frontier:
                    break
                cur.execute(
                    f"""
                    SELECT inputs, outputs, job_namespace, job_name, max(event_time), count(*)
                    FROM {sc}.duckicelake_lineage_event
                    WHERE {side} && %s AND cardinality(inputs) > 0 AND cardinality(outputs) > 0
                    GROUP BY inputs, outputs, job_namespace, job_name
                    LIMIT %s
                    """, (list(frontier), limit))
                nxt: set[str] = set()
                for ins, outs, jns, jname, last, cnt in cur.fetchall():
                    for i in ins:
                        for o in outs:
                            if (side == "outputs" and o in frontier) or (side == "inputs" and i in frontier):
                                key = (i, o, f"{jns}/{jname}")
                                e = edges.setdefault(key, {"from": i, "to": o, "job": f"{jns}/{jname}",
                                                           "runs": 0, "last": None})
                                e["runs"] += cnt
                                e["last"] = max(filter(None, [e["last"], last.isoformat()]))
                                new = i if side == "outputs" else o
                                if new not in nodes:
                                    nxt.add(new)
                nodes |= nxt
                frontier = nxt
        cur.execute(
            f"""
            SELECT kind, principal, job_name, max(event_time), count(*)
            FROM {sc}.duckicelake_lineage_event
            WHERE %s = ANY(inputs) OR %s = ANY(outputs)
            GROUP BY kind, principal, job_name ORDER BY max(event_time) DESC LIMIT 50
            """, (dataset, dataset))
        touched = [{"kind": k, "principal": p, "job": j, "last": t.isoformat(), "count": c}
                   for k, p, j, t, c in cur.fetchall()]
        cur.execute(f"SELECT tag FROM {sc}.duckicelake_lineage_carried "
                    "WHERE schema_name || '.' || table_name = %s ORDER BY 1", (dataset,))
        carried = [r[0] for r in cur.fetchall()]
    return {"dataset": dataset, "namespace": dataset_namespace(catalog),
            "nodes": sorted(nodes), "edges": sorted(edges.values(), key=lambda e: (e["from"], e["to"])),
            "touched_by": touched, "carried_tags": carried}


def purge(catalog: "DuckLakeCatalog", retention_days: int) -> int:
    if retention_days <= 0:
        return 0
    with catalog.pg_cursor() as cur:
        ensure_lineage_sidecars(cur, catalog.sidecar_schema)
        cur.execute(f"DELETE FROM {catalog.sidecar_sql}.duckicelake_lineage_event "
                    "WHERE event_time < now() - make_interval(days => %s)", (retention_days,))
        return cur.rowcount


def retention_days() -> int:
    return int(os.environ.get("DUCKICELAKE_LINEAGE_RETENTION_DAYS", "365"))


def disabled() -> bool:
    return os.environ.get("DUCKICELAKE_LINEAGE", "1") == "0"
