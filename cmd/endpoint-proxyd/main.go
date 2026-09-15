// Command endpoint-proxyd runs the ADR-007 ingress resume proxy against
// the deployed control plane (ADR-005): client traffic enters here, the
// proxy resolves the endpoint binding (X-Endpoint-Binding header, or
// "<logical-name>.<ENDPOINT_DOMAIN>" hostname), routes it through the
// control plane's gateway verdicts, single-flights resumes of suspended
// sandboxes, and forwards to the incarnation's host. All control-plane
// calls are plain HTTP with the shared dev token, exactly how host-agentd
// talks to control-planed.
//
// Dev gaps: shared-token auth only, no TLS; the upstream address is the
// host agent's node — publishing host:port -> guest:port is the
// firecracker backend's follow-up, so end-to-end guest reachability
// depends on it.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/agent-sandbox/platform/control-plane/resumeproxy"
	"github.com/agent-sandbox/platform/network"
	"github.com/agent-sandbox/platform/runtime/host-agent/rpc"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// cpClient is the proxy's control-plane client (token-authenticated HTTP,
// the same transport rules as host-agentd's heartbeat/materialize calls).
type cpClient struct {
	base  string
	token string
	hc    *http.Client
}

func (c *cpClient) get(path string, out interface{}) (int, error) {
	req, err := http.NewRequest(http.MethodGet, c.base+path, nil)
	if err != nil {
		return 0, err
	}
	if c.token != "" {
		req.Header.Set(rpc.TokenHeader, c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("%s", resp.Status)
	}
	return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
}

// Route implements resumeproxy.Router against GET /v1/route/{bindingID}
// (the control plane evaluates the gateway server-side).
func (c *cpClient) Route(bindingID string) network.RouteDecision {
	var dec network.RouteDecision
	if _, err := c.get("/v1/route/"+url.PathEscape(bindingID), &dec); err != nil {
		// Transport failure fails closed, like any gateway doubt.
		return network.RouteDecision{Reason: "route lookup: " + err.Error()}
	}
	return dec
}

// lookupBinding implements resumeproxy's hostname-resolution hook against
// GET /v1/bindings/{logical-name}.
func (c *cpClient) lookupBinding(logicalName string) (string, bool) {
	var b struct {
		BindingID string `json:"BindingID"`
	}
	status, err := c.get("/v1/bindings/"+url.PathEscape(logicalName), &b)
	if err != nil || b.BindingID == "" {
		if status != 0 && status != http.StatusNotFound {
			log.Printf("binding lookup %q: %v", logicalName, err)
		}
		return "", false
	}
	return b.BindingID, true
}

// resume implements resumeproxy.Resumer against
// POST /v1/sandboxes/{id}/resume.
func (c *cpClient) resume(sandboxID string) error {
	return rpc.PostJSON(c.base+"/v1/sandboxes/"+url.PathEscape(sandboxID)+"/resume", c.token, nil, nil)
}

// upstream implements resumeproxy.Upstream against
// GET /v1/sandboxes/{id}/address: the live incarnation's host address,
// dialed at the binding's target port.
func (c *cpClient) upstream(sandboxID string, port int) (string, error) {
	var addr struct {
		URL string `json:"url"`
	}
	if _, err := c.get("/v1/sandboxes/"+url.PathEscape(sandboxID)+"/address", &addr); err != nil {
		return "", err
	}
	u, err := url.Parse(addr.URL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("bad host url %q", addr.URL)
	}
	host := u.Hostname()
	if host == "" {
		host = u.Host
	}
	return fmt.Sprintf("%s:%d", host, port), nil
}

func main() {
	listen := envOr("LISTEN_ADDR", ":8080")
	token := os.Getenv("TOKEN")
	controlPlane := os.Getenv("CONTROL_PLANE_URL") // e.g. http://control-planed:8080
	endpointDomain := os.Getenv("ENDPOINT_DOMAIN") // e.g. endpoints.sandbox.local
	if controlPlane == "" {
		log.Fatal("CONTROL_PLANE_URL required")
	}
	cp := &cpClient{base: controlPlane, token: token, hc: &http.Client{Timeout: 15 * time.Second}}

	proxy := resumeproxy.New(resumeproxy.Config{
		Router:         cp,
		Resume:         cp.resume,
		Upstream:       cp.upstream,
		EndpointDomain: endpointDomain,
		LookupBinding:  cp.lookupBinding,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(proxy.Metrics())
	}))
	mux.Handle("/", proxy)

	log.Printf("endpoint-proxyd listening on %s (control plane %s, endpoint domain %q)", listen, controlPlane, endpointDomain)
	log.Fatal(http.ListenAndServe(listen, mux))
}
