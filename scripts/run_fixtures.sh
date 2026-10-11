#!/usr/bin/env bash
# Start both fixture servers in the background. Ctrl-C stops both.
set -euo pipefail
cd "$(dirname "$0")/.."
uv run python fixtures/clean_server.py &
uv run python fixtures/evil_server.py &
trap 'kill 0' INT TERM
wait
