#!/usr/bin/env bash
# Start the emulation stack for the agent harness: control-planed with an
# in-process local backend (no KVM, no host agents) + endpoint-proxyd.
# Idempotent: stops any previous stack first.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)/..
RUN_DIR=$(pwd)/.stack
mkdir -p "$RUN_DIR"

bash scripts/stop-stack.sh >/dev/null 2>&1 || true

GO=${GO:-$(command -v go)}
$GO build -o "$RUN_DIR/control-planed" "$ROOT/cmd/control-planed"
$GO build -o "$RUN_DIR/endpoint-proxyd" "$ROOT/cmd/endpoint-proxyd"

# dev-python: restart recipe used by the suspend/host-loss scenarios —
# terminal hook serves the workspace on 8020; start hook leaves a boot
# marker in hooks.log.
DEV_ENVIRONMENTS='[{"environment_id":"dev-python","start":["echo booted >> hooks.log"],"terminals":["python3 -m http.server 8020 --bind 127.0.0.1"]}]'
BACKEND=${BACKEND:-local}
CP_PORT=${CP_PORT:-8390}
PROXY_PORT=${PROXY_PORT:-8391}
TOKEN=${TOKEN:-dev-token}

SANDBOX_DEV_FAULTS=1 BACKEND="$BACKEND" DEV_ENVIRONMENTS="$DEV_ENVIRONMENTS" \
  TOKEN="$TOKEN" LISTEN_ADDR=":$CP_PORT" \
  nohup "$RUN_DIR/control-planed" > "$RUN_DIR/control-planed.log" 2>&1 &
echo $! > "$RUN_DIR/control-planed.pid"

TOKEN="$TOKEN" CONTROL_PLANE_URL="http://127.0.0.1:$CP_PORT" \
  ENDPOINT_DOMAIN=endpoints.local LISTEN_ADDR=":$PROXY_PORT" \
  nohup "$RUN_DIR/endpoint-proxyd" > "$RUN_DIR/endpoint-proxyd.log" 2>&1 &
echo $! > "$RUN_DIR/endpoint-proxyd.pid"

for url in "http://127.0.0.1:$CP_PORT/healthz" "http://127.0.0.1:$PROXY_PORT/healthz"; do
  for i in $(seq 1 50); do curl -sf "$url" >/dev/null 2>&1 && break; sleep 0.1; done
  curl -sf "$url" >/dev/null || { echo "stack failed: $url"; tail -5 "$RUN_DIR"/*.log; exit 1; }
done
echo "stack up: control-plane :$CP_PORT (backend=$BACKEND), endpoint-proxy :$PROXY_PORT"
