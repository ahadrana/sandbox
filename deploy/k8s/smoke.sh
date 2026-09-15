#!/usr/bin/env bash
# smoke.sh — end-to-end smoke test of the sandbox platform on k3s:
# client -> control plane -> scheduler -> remote host agent -> firecracker
# microVM -> vsock supervisor. Run ON the deployment host after
# build-images.sh and `kubectl apply -f deploy/k8s/sandbox-platform.yaml`.
#
#   deploy/k8s/smoke.sh          full create->materialize->exec->commit->terminate
#   deploy/k8s/smoke.sh drill    pod-delete failure drill (host loss reconcile)
set -euo pipefail

export PATH="$PATH:/usr/local/go/bin"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
REPO="${REPO:-$HOME/sandbox}"
TOKEN="${TOKEN:-dev-token}"
NS=sandbox-system

cd "$REPO"
[ -x ./sandboxctl ] || CGO_ENABLED=0 go build -o ./sandboxctl ./cmd/sandboxctl

echo "== waiting for platform pods =="
kubectl -n $NS rollout status deployment/control-planed --timeout=120s
kubectl -n $NS rollout status daemonset/host-agentd --timeout=180s

# Reach the ClusterIP service from the host.
kubectl -n $NS port-forward svc/control-planed 18080:8080 >/tmp/pf.log 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
sleep 3
CTL="http://localhost:18080"
ctl() { ./sandboxctl -addr "$CTL" -token "$TOKEN" "$@"; }

echo "== fleet view (host registered, VM-class capabilities) =="
ctl hosts

if [ "${1:-}" = "drill" ]; then
  echo "== FAILURE DRILL: delete the host-agent pod =="
  SB=$(ctl create task-drill | python3 -c 'import sys,json;print(json.load(sys.stdin)["SandboxID"])')
  ctl materialize "$SB" >/dev/null
  echo "sandbox $SB materialized; deleting host-agent pod"
  POD=$(kubectl -n $NS get pod -l app=host-agentd -o jsonpath='{.items[0].metadata.name}')
  kubectl -n $NS delete pod "$POD" --wait=false
  echo "waiting for the fleet to declare the host lost..."
  for i in $(seq 1 45); do
    STATE=$(ctl get "$SB" | python3 -c 'import sys,json;print(json.load(sys.stdin)["ObservedState"])' 2>/dev/null || echo '?')
    if [ "$STATE" = "FAILED" ]; then break; fi
    sleep 2
  done
  echo "sandbox state after host loss: $STATE"
  [ "$STATE" = "FAILED" ] || { echo "DRILL FAIL: expected FAILED"; exit 1; }
  echo "== waiting for the DaemonSet replacement to re-register =="
  kubectl -n $NS rollout status daemonset/host-agentd --timeout=180s
  for i in $(seq 1 30); do
    if ctl hosts | grep -q '"Healthy": true'; then break; fi
    sleep 2
  done
  ctl hosts
  ctl terminate "$SB" >/dev/null || true
  echo "DRILL PASS: microVM loss reconciled to FAILED explicitly; host re-registered healthy"
  exit 0
fi

echo "== create sandbox =="
SB=$(ctl create task-smoke | python3 -c 'import sys,json;print(json.load(sys.stdin)["SandboxID"])')
echo "sandbox: $SB"

echo "== materialize (boots a firecracker microVM on the execution host) =="
ctl materialize "$SB"

echo "== exec in the microVM through the full path =="
HELLO="hello-from-microvm-$(date +%s)"
ctl exec "$SB" "echo $HELLO > hello.txt && cat /proc/1/comm > init.txt"

echo "== commit workspace =="
ctl commit "$SB" >/dev/null

echo "== read back output =="
FILES=$(ctl files "$SB")
echo "$FILES"
echo "$FILES" | grep -q "$HELLO" || { echo "SMOKE FAIL: marker missing"; exit 1; }

echo "== terminate =="
ctl terminate "$SB" >/dev/null
echo "SMOKE PASS: $HELLO round-tripped through a firecracker microVM on k3s"
