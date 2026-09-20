// Scenario contract: a task prompt (live-LLM mode), a deterministic script
// (scripted mode, CI), and assertions that check REAL observable outcomes
// (endpoint HTTP responses, control-plane events, sandbox records) — never
// the model's own claims.

import type { RunContext } from "../ctx.js";
import type { CPEvent } from "../cp.js";

export interface Assertion {
  name: string;
  check(ctx: RunContext): Promise<void>;
}

export interface Scenario {
  name: string;
  /** Environment ID the scenario's sandbox is created with ("" = none). */
  environment: string;
  /** Prompt for the live LLM driver. */
  task: string;
  /** Deterministic driver: the same tool sequence, no LLM. */
  script(ctx: RunContext): Promise<void>;
  assertions: Assertion[];
  /** Sandbox ports this scenario uses (stack hygiene documentation). */
  ports: number[];
}

export function expect(cond: boolean, msg: string): void {
  if (!cond) throw new Error("assertion failed: " + msg);
}

/** Poll fn until true or deadline; throws with what on timeout. */
export async function poll(what: string, timeoutMs: number, fn: () => Promise<boolean>): Promise<void> {
  const t0 = Date.now();
  for (;;) {
    if (await fn()) return;
    if (Date.now() - t0 > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 150));
  }
}

/** All control-plane events for this run's sandbox (from cursor 0). */
export async function sandboxEvents(ctx: RunContext): Promise<CPEvent[]> {
  const { events } = await ctx.cp.events(0, 1000);
  const id = ctx.state.sandboxId;
  return events.filter((e) => e.SandboxID === id || (e.Payload && e.Payload["sandbox_id"] === id));
}

export const SERVER_MARKER = "hello-from-sandbox";

/** The tiny python server an agent is asked to write in build-and-serve. */
export const SERVER_PY = `import http.server, socketserver

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = open("index.html", "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(("127.0.0.1", PORT), H).serve_forever()
`;

export function serverPy(port: number): string {
  return SERVER_PY.replace("PORT", String(port));
}
