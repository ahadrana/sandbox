// Command sandboxctl is a thin CLI over the control-plane client API
// (dev tool; the same calls are documented as curl in deploy/k8s/README.md).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/agent-sandbox/platform/runtime/host-agent/rpc"
)

func main() {
	addr := flag.String("addr", envOr("CONTROL_PLANE_ADDR", "http://localhost:8080"), "control-plane base URL")
	token := flag.String("token", envOr("TOKEN", "dev-token"), "shared dev token")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sandboxctl [-addr URL] [-token T] <create|materialize|exec|get|files|commit|terminate|hosts> [args]")
		os.Exit(2)
	}
	c := &client{base: *addr, token: *token}
	var out interface{}
	var err error
	switch args[0] {
	case "create":
		taskRef := "task-cli"
		if len(args) > 1 {
			taskRef = args[1]
		}
		out, err = c.call("POST", "/v1/sandboxes", map[string]interface{}{"task_ref": taskRef})
	case "materialize":
		out, err = c.call("POST", "/v1/sandboxes/"+args[1]+"/materialize", nil)
	case "exec":
		body := map[string]interface{}{}
		if len(args) > 2 {
			body["command"] = args[2]
		}
		out, err = c.call("POST", "/v1/sandboxes/"+args[1]+"/exec", body)
	case "get":
		out, err = c.call("GET", "/v1/sandboxes/"+args[1], nil)
	case "files":
		out, err = c.call("GET", "/v1/sandboxes/"+args[1]+"/files", nil)
	case "commit":
		out, err = c.call("POST", "/v1/sandboxes/"+args[1]+"/commit", nil)
	case "terminate":
		out, err = c.call("POST", "/v1/sandboxes/"+args[1]+"/terminate", nil)
	case "hosts":
		out, err = c.call("GET", "/v1/hosts", nil)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	pretty, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(pretty))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type client struct {
	base  string
	token string
}

func (c *client) call(method, path string, body interface{}) (interface{}, error) {
	var rdr io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set(rpc.TokenHeader, c.token)
	}
	// No timeout: exec blocks on the runtime through the fleet.
	resp, err := (&http.Client{Timeout: 0}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<30))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(data))
	}
	var out interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}
