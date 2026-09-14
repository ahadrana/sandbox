package supervisor

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// This file defines the wire protocol between a host-side runtime backend
// and the in-guest supervisor daemon (cmd/guest-supervisor): length-prefixed
// JSON frames (4-byte big-endian length + JSON payload) over a vsock stream.
// One request/response pair per frame exchange; the host may hold many
// connections (e.g. one blocking Wait per connection).

// MaxFrameBytes bounds a single protocol frame (a 1 MiB ReadOutput chunk plus
// JSON/base64 overhead fits comfortably; workspace manifests are stage-sized).
const MaxFrameBytes = 64 << 20

// Operation names carried in Request.Op.
const (
	OpHealth              = "health"
	OpExec                = "exec"
	OpWait                = "wait"
	OpStatus              = "status"
	OpCancel              = "cancel"
	OpReadOutput          = "read_output"
	OpProcessInventory    = "process_inventory"
	OpTerminateBackground = "terminate_background"
	OpWriteFile           = "write_file"
	OpReadFile            = "read_file"
	OpWorkspaceFiles      = "workspace_files"
)

// Request is the single host→guest message shape; only the fields relevant
// to Op are populated.
type Request struct {
	Op          string            `json:"op"`
	ExecutionID string            `json:"execution_id,omitempty"`
	Command     string            `json:"command,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	Baseline    bool              `json:"baseline,omitempty"`
	Stderr      bool              `json:"stderr,omitempty"`
	Offset      int64             `json:"offset,omitempty"`
	MaxBytes    int               `json:"max_bytes,omitempty"`
	Path        string            `json:"path,omitempty"`
	// Content is file content for write_file; []byte so binary data
	// marshals to base64 instead of being mangled as UTF-8.
	Content []byte `json:"content,omitempty"`
}

// Response is the single guest→host message shape. Error carries the
// (stringified) failure when OK is false; well-known sentinel messages are
// mapped back to package errors by the host transport.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`

	// status / wait
	Status StatusResponse `json:"status,omitempty"`
	Result Result         `json:"result,omitempty"`

	// read_output / read_file
	Data []byte `json:"data,omitempty"`
	EOF  bool   `json:"eof,omitempty"`

	// process_inventory
	Processes     []ProcessInfo `json:"processes,omitempty"`
	BaselinePGIDs []int         `json:"baseline_pgids,omitempty"`

	// workspace_files (map values are []byte → base64 on the wire, so
	// binary files survive the JSON boundary unmangled)
	Files map[string][]byte `json:"files,omitempty"`
}

// Well-known error strings so the host can map back to sentinel errors.
const (
	ErrMsgNotFound    = "execution not found"
	ErrMsgTooLarge    = "requested chunk exceeds maximum"
	ErrMsgUnsupported = "operation unsupported by this backend"
)

// MapError converts a wire error string back to a sentinel error when known.
func MapError(msg string) error {
	switch msg {
	case ErrMsgNotFound:
		return ErrNotFound
	case ErrMsgTooLarge:
		return ErrTooLarge
	case ErrMsgUnsupported:
		return ErrUnsupported
	}
	return fmt.Errorf("guest supervisor: %s", msg)
}

// WireError renders err for the wire, preserving sentinel identity.
func WireError(err error) string {
	switch err {
	case ErrNotFound:
		return ErrMsgNotFound
	case ErrTooLarge:
		return ErrMsgTooLarge
	case ErrUnsupported:
		return ErrMsgUnsupported
	}
	return err.Error()
}

// WriteFrame writes one length-prefixed JSON frame.
func WriteFrame(w io.Writer, v interface{}) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(payload) > MaxFrameBytes {
		return fmt.Errorf("frame too large: %d bytes", len(payload))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// ReadFrame reads one length-prefixed JSON frame.
func ReadFrame(r io.Reader, v interface{}) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameBytes {
		return fmt.Errorf("frame too large: %d bytes", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	return json.Unmarshal(payload, v)
}
