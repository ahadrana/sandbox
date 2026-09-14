package firecrackerbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// apiClient is a minimal HTTP-over-unix-socket client for the Firecracker
// API (stdlib only). Every call carries a timeout.
type apiClient struct {
	hc   *http.Client
	sock string
}

func newAPIClient(sock string, timeout time.Duration) *apiClient {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", sock)
		},
		// Each apiClient is per-call; idle keep-alive connections would pile
		// up on the Firecracker API server ("Too many open connections").
		DisableKeepAlives: true,
	}
	return &apiClient{hc: &http.Client{Transport: tr, Timeout: timeout}, sock: sock}
}

// call issues a request and returns an error quoting the Firecracker fault
// message body on non-2xx responses.
func (c *apiClient) call(method, path string, body interface{}) error {
	var rdr io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, "http://d"+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("firecracker api %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return fmt.Errorf("firecracker api %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
}

func (c *apiClient) get(path string, out interface{}) error {
	resp, err := c.hc.Get("http://d" + path)
	if err != nil {
		return fmt.Errorf("firecracker api GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("firecracker api GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ping reports whether the API socket answers a basic request.
func (c *apiClient) ping() error {
	var mc struct {
		VCPUCount int `json:"vcpu_count"`
	}
	return c.get("/machine-config", &mc)
}

func (c *apiClient) setBootSource(kernelPath, bootArgs string) error {
	return c.call("PUT", "/boot-source", map[string]interface{}{
		"kernel_image_path": kernelPath,
		"boot_args":         bootArgs,
	})
}

func (c *apiClient) addDrive(id, path string, root, readOnly bool) error {
	return c.call("PUT", "/drives/"+id, map[string]interface{}{
		"drive_id":       id,
		"path_on_host":   path,
		"is_root_device": root,
		"is_read_only":   readOnly,
	})
}

func (c *apiClient) setMachineConfig(vcpus, memMiB int64) error {
	return c.call("PUT", "/machine-config", map[string]interface{}{
		"vcpu_count":   vcpus,
		"mem_size_mib": memMiB,
	})
}

func (c *apiClient) setVsock(cid uint32, udsPath string) error {
	return c.call("PUT", "/vsock", map[string]interface{}{
		"guest_cid": cid,
		"uds_path":  udsPath,
	})
}

func (c *apiClient) addNIC(id, hostDev, guestMAC string) error {
	return c.call("PUT", "/network-interfaces/"+id, map[string]interface{}{
		"iface_id":      id,
		"host_dev_name": hostDev,
		"guest_mac":     guestMAC,
	})
}

func (c *apiClient) action(actionType string) error {
	return c.call("PUT", "/actions", map[string]string{"action_type": actionType})
}

func (c *apiClient) setVMState(state string) error {
	return c.call("PATCH", "/vm", map[string]string{"state": state})
}

func (c *apiClient) snapshotCreate(memPath, statePath string) error {
	return c.call("PUT", "/snapshot/create", map[string]interface{}{
		"mem_file_path": memPath,
		"snapshot_path": statePath,
		"snapshot_type": "Full",
	})
}

func (c *apiClient) snapshotLoad(statePath, memPath, vsockUdsPath string, resume bool) error {
	return c.call("PUT", "/snapshot/load", map[string]interface{}{
		"snapshot_path": statePath,
		"resume_vm":     resume,
		"mem_backend": map[string]string{
			"backend_type": "File",
			"backend_path": memPath,
		},
		// The snapshot restores every device from its saved state, including
		// the vsock backend UDS path; point it at the fresh incarnation dir.
		"vsock_override": map[string]string{"uds_path": vsockUdsPath},
	})
}
