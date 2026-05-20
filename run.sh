#!/usr/bin/env bash
# 127.0.0.1 にのみバインド = 外部公開しない
set -e
cd "$(dirname "$0")"
exec uvicorn app.main:app --host 127.0.0.1 --port 8765 "$@"
