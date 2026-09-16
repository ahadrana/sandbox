// Command host-agentd runs one Runtime Host (ADR 005): a HostAgent around
// the Firecracker backend, exposed over the host-agent HTTP/JSON RPC, that
// registers and heartbeats with the control plane. The pod is privileged +
// hostNetwork (firecracker needs /dev/kvm; the jailer needs namespaces and
// cgroups) — K8s manages host capacity only, never per-sandbox objects.
//
// Dev gaps: shared-token auth only, no TLS; workspace generations are
// fetched from the control plane's in-memory store.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	firecrackerbackend "github.com/agent-sandbox/platform/runtime/firecracker-backend"
	hostagent "github.com/agent-sandbox/platform/runtime/host-agent"
	"github.com/agent-sandbox/platform/runtime/host-agent/rpc"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// publishDenyPorts is the platform port deny-list for endpoint publishing
// (review H1): the backend defaults (apiserver 6443, platform dev port
// 8080, kubelet 10250) plus any comma-separated extras in
// FC_PUBLISH_DENY_PORTS (e.g. "9090,3000" for site services sharing the
// node's port space).
func publishDenyPorts() []int {
	out := append([]int{}, firecrackerbackend.DefaultPublishDenyPorts...)
	for _, tok := range strings.Split(os.Getenv("FC_PUBLISH_DENY_PORTS"), ",") {
		if p, err := strconv.Atoi(strings.TrimSpace(tok)); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// remoteWS resolves committed workspace generations from the control plane
// (the host's WorkspaceStore), so incarnation assembly uses the same
// artifacts the manager committed.
type remoteWS struct {
	url   string
	token string
}

func (w *remoteWS) Materialize(workspaceID string, generation int64) (map[string]string, error) {
	var out struct {
		Manifest map[string]string `json:"manifest"`
	}
	url := fmt.Sprintf("%s/internal/ws-materialize?workspace_id=%s&generation=%d", w.url, workspaceID, generation)
	// GET with token header: reuse PostJSON's transport rules via a direct call.
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if w.token != "" {
		req.Header.Set(rpc.TokenHeader, w.token)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ws-materialize: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Manifest, nil
}

func main() {
	listen := envOr("LISTEN_ADDR", ":8080")
	token := os.Getenv("TOKEN")
	hostID := envOr("HOST_ID", "")
	if hostID == "" {
		h, _ := os.Hostname()
		hostID = h
	}
	advertise := envOr("HOST_URL", "")             // e.g. http://<node-ip>:8080 (hostNetwork)
	controlPlane := os.Getenv("CONTROL_PLANE_URL") // e.g. http://control-planed:8080
	memCapacity := envInt("MEM_CAPACITY", 24<<30)
	slots := envInt("SLOTS", 16)

	backend, err := firecrackerbackend.New(firecrackerbackend.Config{
		Root:               envOr("FC_ROOT", "/var/lib/sandbox-fc"),
		KernelPath:         envOr("FC_KERNEL", "/opt/sandbox/vmlinux.bin"),
		RootfsPath:         envOr("FC_ROOTFS", "/opt/sandbox/rootfs.ext4"),
		FirecrackerBin:     envOr("FC_BIN", "/usr/local/bin/firecracker"),
		JailerBin:          envOr("FC_JAILER", "/usr/local/bin/jailer"),
		GuestSupervisorBin: envOr("FC_GUEST_SUPERVISOR", "/opt/sandbox/guest-supervisor"),
		Networking:         os.Getenv("FC_NETWORKING") == "true",
		// The daemon owns the host's fc networking: at pod start, any
		// platform-named TAP/chain belongs to a crashed predecessor (pod
		// teardown kills its VMMs), so the FM11 sweep is safe here — and
		// here only (default-off keeps test/dev backends on the same host
		// from destroying this daemon's live plumbing).
		SweepStaleNetworking: os.Getenv("FC_NETWORKING") == "true",
		PublishDenyPorts:     publishDenyPorts(),
		BootTimeout:          120 * time.Second,
		DefaultMemMiB:        256,
	})
	if err != nil {
		log.Fatalf("firecracker backend: %v", err)
	}
	log.Printf("firecracker backend up (jailer fallback: %q)", backend.JailerStatus())

	var ws hostagent.WorkspaceStore
	if controlPlane != "" {
		ws = &remoteWS{url: controlPlane, token: token}
	}
	agent := hostagent.New(hostID, backend, nil, ws, memCapacity, int(slots), 64)
	// Never let an endpoint binding publish the agent's own RPC port: the
	// DNAT would hijack heartbeats/RPC into a guest.
	if _, port, err := net.SplitHostPort(listen); err == nil {
		if p, err := strconv.Atoi(port); err == nil {
			agent.ProtectPorts(p)
		}
	}

	// Heartbeat: register once, then keep the control plane's liveness view
	// fresh. bootID identifies this agent process; the control plane
	// re-registers the host through the fleet's orphan-scrub path whenever a
	// new boot ID appears (pod restart → stale incarnations declared lost).
	if controlPlane != "" && advertise != "" {
		var boot [16]byte
		rand.Read(boot[:])
		bootID := fmt.Sprintf("boot-%x", boot[:])
		go func() {
			beat := map[string]string{"host_id": hostID, "url": advertise, "boot_id": bootID}
			for {
				if err := rpc.PostJSON(controlPlane+"/internal/heartbeat", token, beat, nil); err != nil {
					log.Printf("heartbeat: %v", err)
				}
				time.Sleep(2 * time.Second)
			}
		}()
	} else {
		log.Printf("CONTROL_PLANE_URL or HOST_URL unset; running standalone (no registration)")
	}

	log.Printf("host-agentd %s listening on %s (advertising %s)", hostID, listen, advertise)
	log.Fatal(http.ListenAndServe(listen, rpc.Handler(agent, token)))
}
