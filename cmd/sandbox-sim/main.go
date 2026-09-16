// Command sandbox-sim is a simulation harness + live visualization UI for
// the sandbox platform: it drives N concurrent sandboxes against the
// deployed control plane (create, workload exec ticks, endpoint binding +
// curls through endpoint-proxyd, suspend/resume churn and resume storms),
// records every action in an in-memory ring buffer, and serves a
// self-contained dark-theme dashboard plus a /api/state JSON endpoint.
//
// Ground truth: the control plane has no list-sandboxes endpoint, so
// sandbox state is refreshed per-sandbox (GET /v1/sandboxes/{id}) and from
// the sim's own action results — the sim only knows the sandboxes it
// created.
package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var (
		cpURL    = flag.String("cp", "http://localhost:18080", "control-plane base URL")
		token    = flag.String("token", "dev-token", "shared dev token")
		proxyURL = flag.String("proxy", "http://localhost:18081", "endpoint-proxyd base URL")
		n        = flag.Int("sandboxes", 4, "number of concurrent sandboxes")
		uiAddr   = flag.String("ui", ":9100", "UI listen address")
		scenario = flag.String("scenario", "steady", "scenario: steady | churn | storm")
		seed     = flag.Int64("seed", 0, "random seed (0 = time-based)")
	)
	flag.Parse()
	if *seed != 0 {
		rand.Seed(*seed)
	} else {
		rand.Seed(time.Now().UnixNano())
	}

	cp := NewCPClient(*cpURL, *proxyURL, *token)
	sim := NewSim(cp, *scenario)
	log.Printf("sandbox-sim: control plane %s, proxy %s, %d sandboxes, scenario %s", *cpURL, *proxyURL, *n, *scenario)

	if err := sim.Setup(*n); err != nil {
		log.Fatalf("setup: %v", err)
	}
	sim.Run()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, dashboardHTML)
	})
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(sim.StateJSON())
	})
	go func() {
		log.Printf("sandbox-sim UI listening on %s", *uiAddr)
		if err := http.ListenAndServe(*uiAddr, mux); err != nil {
			log.Printf("ui server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
}
