#!/usr/bin/env bash
# MinIO lifecycle helper. Self-contained: data goes in .miniodata, logs in
# .miniodata/minio.log. Default root creds are minioadmin/minioadmin — don't
# use this setup outside of local development.
#
# Bucket creation is handled by duckicelake.bootstrap via boto3, not here.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${MINIO_DATA:-$ROOT/.miniodata}"
LOG="$DATA/minio.log"
PIDFILE="$DATA/minio.pid"
API_PORT="${MINIO_API_PORT:-9000}"
CONSOLE_PORT="${MINIO_CONSOLE_PORT:-9001}"
ROOT_USER="${MINIO_ROOT_USER:-minioadmin}"
ROOT_PASS="${MINIO_ROOT_PASSWORD:-minioadmin}"

export MINIO_ROOT_USER="$ROOT_USER"
export MINIO_ROOT_PASSWORD="$ROOT_PASS"

mkdir -p "$DATA"

is_running() {
  [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

cmd="${1:-help}"
shift || true

case "$cmd" in
  start)
    if is_running; then
      echo "MinIO already running (pid $(cat "$PIDFILE"))."
    else
      echo "Starting MinIO on :$API_PORT (console :$CONSOLE_PORT) ..."
      nohup minio server \
        --address ":$API_PORT" \
        --console-address ":$CONSOLE_PORT" \
        "$DATA/storage" >>"$LOG" 2>&1 &
      echo $! >"$PIDFILE"
      for i in $(seq 1 40); do
        if curl -fsS "http://127.0.0.1:$API_PORT/minio/health/ready" >/dev/null 2>&1; then
          echo "MinIO ready."
          exit 0
        fi
        sleep 0.25
      done
      echo "MinIO did not become ready in time; see $LOG"
      exit 1
    fi
    ;;
  stop)
    if is_running; then
      kill "$(cat "$PIDFILE")" || true
      rm -f "$PIDFILE"
      echo "MinIO stopped."
    else
      echo "MinIO not running."
    fi
    ;;
  status)
    if is_running; then
      echo "MinIO running (pid $(cat "$PIDFILE"))."
    else
      echo "MinIO not running."
    fi
    ;;
  *)
    echo "Usage: $0 {start|stop|status}"
    exit 1
    ;;
esac
