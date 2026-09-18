// Command invcheck replays a LIVE control plane's durable event stream
// (GET /v1/events, cmd/control-planed) through the SandboxLab invariant
// engine (sandboxlab.NewLiveEngine) and prints the invariant report.
//
// Coverage honesty: a live feed carries only the event stream — the
// state-snapshot checkers (which need consistent manager/fleet/host world
// state) stay not-exercised, exactly as reported. Event-stream checkers
// (identity/epoch/commit-order/reset-emission/single-flight/binding and
// lifecycle rules — see docs/INVARIANTS.md) run at full strength.
//
// Modes: one-shot (-once: drain, report, exit) or follow (default: poll
// every -interval until -duration elapses or SIGINT/SIGTERM, then report).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/agent-sandbox/platform/domain"
	"github.com/agent-sandbox/platform/sandboxlab"
)

type eventsResponse struct {
	Events []domain.Event `json:"events"`
	Cursor int64          `json:"cursor"`
}

func main() {
	var (
		cpURL    = flag.String("cp", "http://localhost:8090", "control-plane base URL")
		token    = flag.String("token", "dev-token", "shared dev token")
		since    = flag.Int64("since", 0, "outbox cursor to start from")
		once     = flag.Bool("once", false, "drain available events, print report, exit")
		interval = flag.Duration("interval", 10*time.Second, "poll interval in follow mode")
		duration = flag.Duration("duration", 0, "stop after this long (0 = until signal)")
	)
	flag.Parse()

	hc := &http.Client{Timeout: 30 * time.Second}
	engine := sandboxlab.NewLiveEngine()
	cursor := *since
	total := 0

	poll := func() error {
		for {
			req, err := http.NewRequest(http.MethodGet,
				fmt.Sprintf("%s/v1/events?since=%d&limit=1000", *cpURL, cursor), nil)
			if err != nil {
				return err
			}
			req.Header.Set("X-Sandbox-Token", *token)
			resp, err := hc.Do(req)
			if err != nil {
				return err
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("events: %s: %.200s", resp.Status, body)
			}
			var er eventsResponse
			if err := json.Unmarshal(body, &er); err != nil {
				return fmt.Errorf("events decode: %w", err)
			}
			engine.Feed(er.Events)
			total += len(er.Events)
			cursor = er.Cursor
			if len(er.Events) < 1000 {
				return nil
			}
		}
	}

	deadline := time.Now().Add(*duration)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

loop:
	for {
		if err := poll(); err != nil {
			log.Printf("invcheck: poll: %v", err)
		}
		if *once {
			break
		}
		select {
		case <-stop:
			break loop
		case <-time.After(*interval):
		}
		if *duration > 0 && time.Now().After(deadline) {
			break
		}
	}

	report := engine.Report()
	fmt.Printf("invcheck: %d events fed from cursor %d\n", total, *since)
	fmt.Println(report.String())
	_, violations, _, _ := report.Counts()
	if violations > 0 {
		os.Exit(1)
	}
}
