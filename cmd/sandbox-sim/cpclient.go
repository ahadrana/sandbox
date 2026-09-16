package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// CPClient is the sim's view of the control plane (plus endpoint-proxyd for
// data-path curls). *httpCPClient talks to the real daemons; tests
// substitute a fake.
type CPClient interface {
	Healthy() bool
	CreateSandbox(taskRef string) (*SandboxInfo, error)
	Materialize(id string) error
	Exec(id, command string, writes map[string]string) (*ExecResult, error)
	Suspend(id string) error
	Resume(id string) (*ResumeReport, error)
	GetSandbox(id string) (*SandboxInfo, error)
	CreateBinding(sandboxID string, targetPort int, logicalName string) (string, error)
	// EndpointGet performs one GET through endpoint-proxyd, identifying the
	// binding via the X-Endpoint-Binding header. Returns status + body.
	EndpointGet(bindingID string) (int, string, error)
}

// SandboxInfo is the subset of the control plane's sandbox record the sim
// tracks (capitalized keys match the daemon's Go-struct JSON encoding).
type SandboxInfo struct {
	SandboxID           string
	ObservedState       string
	ExecutionEpoch      int64
	WorkspaceGeneration int64
}

type ExecResult struct {
	State    string
	ExitCode int
}

type ResumeReport struct {
	PriorEpoch int64
	NewEpoch   int64
}

type httpCPClient struct {
	cp     string
	proxy  string
	token  string
	hc     *http.Client
	hcSlow *http.Client // resume/restore can take a while
}

func NewCPClient(cpURL, proxyURL, token string) CPClient {
	return &httpCPClient{
		cp: cpURL, proxy: proxyURL, token: token,
		hc:     &http.Client{Timeout: 30 * time.Second},
		hcSlow: &http.Client{Timeout: 90 * time.Second},
	}
}

func (c *httpCPClient) do(hc *http.Client, method, url string, in, out interface{}) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("X-Sandbox-Token", c.token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: %s: %s", method, url, resp.Status, bytes.TrimSpace(data))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *httpCPClient) Healthy() bool {
	req, err := http.NewRequest(http.MethodGet, c.cp+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (c *httpCPClient) CreateSandbox(taskRef string) (*SandboxInfo, error) {
	var out SandboxInfo
	err := c.do(c.hc, http.MethodPost, c.cp+"/v1/sandboxes", map[string]interface{}{"task_ref": taskRef}, &out)
	return &out, err
}

func (c *httpCPClient) Materialize(id string) error {
	return c.do(c.hcSlow, http.MethodPost, c.cp+"/v1/sandboxes/"+url.PathEscape(id)+"/materialize", map[string]interface{}{}, nil)
}

func (c *httpCPClient) Exec(id, command string, writes map[string]string) (*ExecResult, error) {
	var raw struct {
		State    string `json:"State"`
		ExitCode *int   `json:"ExitCode"`
	}
	in := map[string]interface{}{"command": command}
	if len(writes) > 0 {
		in["writes"] = writes
	}
	if err := c.do(c.hc, http.MethodPost, c.cp+"/v1/sandboxes/"+url.PathEscape(id)+"/exec", in, &raw); err != nil {
		return nil, err
	}
	out := &ExecResult{State: raw.State, ExitCode: -1}
	if raw.ExitCode != nil {
		out.ExitCode = *raw.ExitCode
	}
	return out, nil
}

func (c *httpCPClient) Suspend(id string) error {
	return c.do(c.hcSlow, http.MethodPost, c.cp+"/v1/sandboxes/"+url.PathEscape(id)+"/suspend", map[string]interface{}{}, nil)
}

func (c *httpCPClient) Resume(id string) (*ResumeReport, error) {
	var out ResumeReport
	err := c.do(c.hcSlow, http.MethodPost, c.cp+"/v1/sandboxes/"+url.PathEscape(id)+"/resume", map[string]interface{}{}, &out)
	return &out, err
}

func (c *httpCPClient) GetSandbox(id string) (*SandboxInfo, error) {
	var out SandboxInfo
	err := c.do(c.hc, http.MethodGet, c.cp+"/v1/sandboxes/"+url.PathEscape(id), nil, &out)
	return &out, err
}

func (c *httpCPClient) CreateBinding(sandboxID string, targetPort int, logicalName string) (string, error) {
	var out struct {
		BindingID string `json:"BindingID"`
	}
	err := c.do(c.hc, http.MethodPost, c.cp+"/v1/bindings", map[string]interface{}{
		"sandbox_id": sandboxID, "target_port": targetPort,
		"logical_name": logicalName, "auth_policy": "none", "ttl_seconds": 86400,
	}, &out)
	if err != nil {
		return "", err
	}
	if out.BindingID == "" {
		return "", fmt.Errorf("binding response carried no BindingID")
	}
	return out.BindingID, nil
}

func (c *httpCPClient) EndpointGet(bindingID string) (int, string, error) {
	req, err := http.NewRequest(http.MethodGet, c.proxy+"/", nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("X-Endpoint-Binding", bindingID)
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(data), err
}
