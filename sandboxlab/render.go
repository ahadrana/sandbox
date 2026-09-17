package sandboxlab

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// render.go — the phase-5 replay UI as a baked artifact. replay.html is a
// fully self-contained page (inline CSS/JS, no external resources, works
// from file://); RenderReplayHTML injects the trace as one JSON-encoded
// string literal at the /*__TRACE_JSONL__*/ marker. encoding/json escapes
// <, > and & in string output, so the injection is safe inside <script>.

//go:embed replay.html
var replayTemplate []byte

const traceMarker = `/*__TRACE_JSONL__*/""`

// RenderReplayHTML bakes a v2 JSONL trace into the self-contained replay
// page. The trace is validated first so a bad file fails loudly instead of
// producing a broken page.
func RenderReplayHTML(traceJSONL []byte) ([]byte, error) {
	if _, err := ParseTraceV2(traceJSONL); err != nil {
		return nil, err
	}
	enc, err := json.Marshal(string(traceJSONL))
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(replayTemplate, []byte(traceMarker)) {
		return nil, fmt.Errorf("sandboxlab: replay template missing trace marker")
	}
	return bytes.Replace(replayTemplate, []byte(traceMarker), enc, 1), nil
}

// ReplayHandler serves RenderReplayHTML(traceJSONL) at every path.
func ReplayHandler(traceJSONL []byte) (http.Handler, error) {
	page, err := RenderReplayHTML(traceJSONL)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(page)))
		_, _ = w.Write(page)
	}), nil
}
