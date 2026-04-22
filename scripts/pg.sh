#!/usr/bin/env bash
# Postgres lifecycle helper. Uses an in-repo data dir + unix socket so this is
# completely isolated from any system Postgres install.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PGDATA="${PGDATA:-$ROOT/.pgdata}"
PGHOST_DIR="${PGHOST_DIR:-$ROOT/.pgsock}"
PGPORT="${PGPORT:-55432}"
PGUSER_DEFAULT="${PGUSER:-ducklake}"
PGDB_DEFAULT="${PGDATABASE:-ducklake}"
LOG="$PGDATA/postgres.log"

mkdir -p "$PGHOST_DIR"

cmd="${1:-help}"
shift || true

case "$cmd" in
  init)
    if [ -d "$PGDATA/base" ]; then
      echo "Postgres already initialized at $PGDATA"
      exit 0
    fi
    echo "Initializing Postgres cluster at $PGDATA ..."
    initdb -D "$PGDATA" -U "$PGUSER_DEFAULT" --auth=trust --encoding=UTF8 >/dev/null
    # Lock down: listen on unix socket only, custom port
    {
      echo "listen_addresses = ''"
      echo "unix_socket_directories = '$PGHOST_DIR'"
      echo "port = $PGPORT"
      echo "log_min_messages = warning"
    } >> "$PGDATA/postgresql.conf"
    echo "Initialized. Use 'pixi run pg-start'."
    ;;
  start)
    if [ ! -d "$PGDATA/base" ]; then
      "$0" init
    fi
    if pg_ctl -D "$PGDATA" status >/dev/null 2>&1; then
      echo "Postgres already running."
    else
      pg_ctl -D "$PGDATA" -l "$LOG" -w start
    fi
    # Ensure the ducklake database exists.
    if ! psql -h "$PGHOST_DIR" -p "$PGPORT" -U "$PGUSER_DEFAULT" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$PGDB_DEFAULT'" | grep -q 1; then
      createdb -h "$PGHOST_DIR" -p "$PGPORT" -U "$PGUSER_DEFAULT" "$PGDB_DEFAULT"
      echo "Created database '$PGDB_DEFAULT'."
    fi
    ;;
  stop)
    if pg_ctl -D "$PGDATA" status >/dev/null 2>&1; then
      pg_ctl -D "$PGDATA" -m fast -w stop
    else
      echo "Postgres not running."
    fi
    ;;
  status)
    pg_ctl -D "$PGDATA" status || true
    ;;
  psql)
    exec psql -h "$PGHOST_DIR" -p "$PGPORT" -U "$PGUSER_DEFAULT" -d "$PGDB_DEFAULT" "$@"
    ;;
  *)
    echo "Usage: $0 {init|start|stop|status|psql}"
    exit 1
    ;;
esac
