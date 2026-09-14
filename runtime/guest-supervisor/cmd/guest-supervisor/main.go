//go:build linux

// Command guest-supervisor is the in-guest data-plane daemon for VM-class
// backends (DESIGN §6.8). It runs inside the microVM, listens on a vsock
// port, and executes commands under /workspace with the same semantics as
// the local backend's in-process supervisor: /bin/sh -c, Setpgid, output
// spilled to files, wait4 rusage, AGENT_SANDBOX_INCARNATION ownership marker.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

func main() {
	port := flag.Uint("port", 5000, "vsock port to listen on")
	cid := flag.Uint("cid", 0xFFFFFFFF, "vsock CID to bind (default ANY)")
	connect := flag.String("connect", "", "debug: dial cid:port and exchange a health frame instead of serving")
	workDir := flag.String("workdir", "/workspace", "working directory for executions")
	outDir := flag.String("outdir", "/tmp/guest-supervisor/output", "output spill directory")
	flag.Parse()

	if *connect != "" {
		var cCID, cPort uint32
		if _, err := fmt.Sscanf(*connect, "%d:%d", &cCID, &cPort); err != nil {
			log.Fatal(err)
		}
		if err := debugDial(cCID, cPort); err != nil {
			log.Fatal(err)
		}
		return
	}

	incarnationID := os.Getenv("AGENT_SANDBOX_INCARNATION_ID")
	if incarnationID == "" {
		log.Fatal("AGENT_SANDBOX_INCARNATION_ID is required")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}
	agent := newAgent(*workDir, *outDir, incarnationID)

	ln, err := listenVsock(uint32(*port), uint32(*cid))
	if err != nil {
		log.Fatalf("listen vsock port %d: %v", *port, err)
	}
	log.Printf("guest-supervisor listening on vsock port %d (incarnation %s)", *port, incarnationID)
	for {
		conn, err := ln.accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go serveConn(agent, conn)
	}
}

// serveConn handles one request/response pair per connection (the host opens
// a fresh connection per request, so a blocking Wait never starves Status).
func serveConn(agent *agent, conn *vsockConn) {
	defer conn.Close()
	var req supervisor.Request
	if err := supervisor.ReadFrame(conn, &req); err != nil {
		log.Printf("read request: %v", err)
		return
	}
	resp := agent.dispatch(req)
	if err := supervisor.WriteFrame(conn, resp); err != nil {
		log.Printf("write response: %v", err)
	}
}

func fail(err error) supervisor.Response {
	return supervisor.Response{OK: false, Error: supervisor.WireError(err)}
}

func (a *agent) dispatch(req supervisor.Request) supervisor.Response {
	switch req.Op {
	case supervisor.OpHealth:
		return supervisor.Response{OK: true}
	case supervisor.OpExec:
		err := a.Exec(supervisor.ExecRequest{
			ExecutionID: req.ExecutionID,
			Command:     req.Command,
			Env:         req.Env,
			Baseline:    req.Baseline,
		})
		if err != nil {
			return fail(err)
		}
		return supervisor.Response{OK: true}
	case supervisor.OpWait:
		res, err := a.Wait(req.ExecutionID)
		if err != nil {
			return fail(err)
		}
		return supervisor.Response{OK: true, Result: res}
	case supervisor.OpStatus:
		st, err := a.Status(req.ExecutionID)
		if err != nil {
			return fail(err)
		}
		return supervisor.Response{OK: true, Status: st}
	case supervisor.OpCancel:
		if err := a.Cancel(req.ExecutionID); err != nil {
			return fail(err)
		}
		return supervisor.Response{OK: true}
	case supervisor.OpReadOutput:
		chunk, err := a.ReadOutput(req.ExecutionID, req.Stderr, req.Offset, req.MaxBytes)
		if err != nil {
			return fail(err)
		}
		return supervisor.Response{OK: true, Data: chunk.Data, EOF: chunk.EOF}
	case supervisor.OpProcessInventory:
		inv, err := a.ProcessInventory()
		if err != nil {
			return fail(err)
		}
		return supervisor.Response{OK: true, Processes: inv, BaselinePGIDs: a.baselinePGIDList()}
	case supervisor.OpTerminateBackground:
		if err := a.TerminateBackground(); err != nil {
			return fail(err)
		}
		return supervisor.Response{OK: true}
	case supervisor.OpWriteFile:
		if err := a.WriteFile(req.Path, req.Content); err != nil {
			return fail(err)
		}
		return supervisor.Response{OK: true}
	case supervisor.OpReadFile:
		data, err := a.ReadFile(req.Path)
		if err != nil {
			return fail(err)
		}
		return supervisor.Response{OK: true, Data: data}
	case supervisor.OpWorkspaceFiles:
		files, err := a.WorkspaceFiles()
		if err != nil {
			return fail(err)
		}
		return supervisor.Response{OK: true, Files: files}
	}
	return fail(fmt.Errorf("unknown op %q", req.Op))
}
