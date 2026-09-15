#!/usr/bin/env bash
# build-images.sh — build the platform images and import them into k3s's
# containerd. Runs ON the deployment host (aarch64). No docker: images are
# scratch tars assembled by hand in docker-save format (k3s ctr imports it).
#
# host-agentd image: static host-agentd + firecracker + patched jailer (+
# its runtime libs) + sudoshim + guest-supervisor + kernel/rootfs artifacts.
# control-planed image: static control-planed only.
set -euo pipefail

REPO="${REPO:-$HOME/sandbox}"
ARTIFACTS="${FC_ARTIFACTS:-$HOME/fc-artifacts}"
TAG="${TAG:-dev}"
WORK="$(mktemp -d /tmp/sandbox-images-XXXX)"
trap 'rm -rf "$WORK"' EXIT
export PATH="$PATH:/usr/local/go/bin"

cd "$REPO"
echo "== building static binaries (linux/arm64) =="
for cmd in host-agentd control-planed; do
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$WORK/$cmd" "./cmd/$cmd"
done
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$WORK/guest-supervisor" ./runtime/guest-supervisor/cmd/guest-supervisor
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$WORK/sudo" ./deploy/sudoshim

mkimage() { # name entrypoint rootfsdir
  local name="$1" entry="$2" rootfs="$3"
  local layer="$WORK/$name.layer.tar"
  tar -C "$rootfs" --numeric-owner -cf "$layer" .
  local diffid; diffid="sha256:$(sha256sum "$layer" | cut -d' ' -f1)"
  local cfg="$WORK/$name.config.json"
  cat > "$cfg" <<EOF
{"architecture":"arm64","os":"linux",
 "config":{"Entrypoint":["$entry"],"Env":["PATH=/usr/local/bin:/bin"]},
 "rootfs":{"type":"layers","diff_ids":["$diffid"]},
 "history":[{"created_by":"build-images.sh scratch assembly"}]}
EOF
  local out="$WORK/$name.tar"
  ( cd "$WORK"
    cat > manifest.json <<EOF
[{"Config":"$name.config.json","RepoTags":["sandbox/$name:$TAG"],"Layers":["$name.layer.tar"]}]
EOF
    tar -cf "$name.tar" manifest.json "$name.config.json" "$name.layer.tar" )
  echo "== importing sandbox/$name:$TAG =="
  sudo -n k3s ctr images import "$out" >/dev/null
  sudo -n k3s ctr images ls | grep "sandbox/$name"
}

echo "== assembling host-agentd rootfs =="
HA="$WORK/rootfs-hostagent"
mkdir -p "$HA/opt/sandbox" "$HA/usr/local/bin" "$HA/var/lib/sandbox-fc" \
         "$HA/lib/aarch64-linux-gnu" "$HA/lib" "$HA/tmp"
chmod 1777 "$HA/tmp"
cp "$WORK/host-agentd" "$HA/host-agentd"
cp "$WORK/guest-supervisor" "$HA/opt/sandbox/guest-supervisor"
cp "$WORK/sudo" "$HA/usr/local/bin/sudo"
cp /usr/local/bin/firecracker /usr/local/bin/jailer "$HA/usr/local/bin/"
# jailer is dynamically linked; ship its loader + libs.
cp /lib/ld-linux-aarch64.so.1 "$HA/lib/"
cp /lib/aarch64-linux-gnu/libgcc_s.so.1 /lib/aarch64-linux-gnu/libc.so.6 "$HA/lib/aarch64-linux-gnu/"
# The backend shells out to coreutils/e2fsprogs for image ops (cp --reflink,
# mkfs.ext4/debugfs workspace image, e2fsck rootfs prep); ship them plus every
# shared library ldd reports, since the image is otherwise scratch. The egress
# datapath (Batch 1) additionally needs iproute2/iptables for the TAP + egress
# chains, conntrack-tools for the generation-bump conntrack flush, and procps
# sysctl for ip_forward / ip_unprivileged_port_start=0 (DNS proxy binds :53).
for bin in cp mkfs.ext4 debugfs e2fsck conntrack iptables ip sysctl; do
  src="$(command -v "$bin")"
  cp "$src" "$HA/usr/local/bin/"
  ldd "$src" | awk '/=> \// {print $3} /^\// {print $1}' | sort -u |
    while read -r lib; do cp -n "$lib" "$HA/lib/aarch64-linux-gnu/"; done
done
# iptables here is xtables-nft-multi: its match/target plugins are dlopen'd
# from the xtables dir (invisible to ldd), so ship the whole directory.
cp -r /usr/lib/aarch64-linux-gnu/xtables "$HA/lib/aarch64-linux-gnu/"
cp "$ARTIFACTS/vmlinux.bin" "$ARTIFACTS/rootfs.ext4" "$HA/opt/sandbox/"
mkimage host-agentd /host-agentd "$HA"

echo "== assembling control-planed rootfs =="
CP="$WORK/rootfs-control-plane"
mkdir -p "$CP"
cp "$WORK/control-planed" "$CP/control-planed"
mkimage control-planed /control-planed "$CP"

echo "== done =="
