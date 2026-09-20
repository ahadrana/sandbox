#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
RUN_DIR=$(pwd)/.stack
for f in "$RUN_DIR"/*.pid; do
  [ -e "$f" ] || continue
  kill "$(cat "$f")" 2>/dev/null || true
  rm -f "$f"
done
echo "stack stopped"
