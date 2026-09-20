# agent-harness

Agentic end-to-end validation harness for the sandbox platform: a real agent
loop (or a deterministic scripted driver) operates sandboxes through the
public control-plane HTTP API, and assertions check **observable outcomes**
(HTTP responses through the endpoint proxy, control-plane events, sandbox
records) — never the model's claims.

This is a Node/TypeScript toolchain, deliberately **outside the Go build**
(see docs/README.md). Node 20+, `npm install` once.

## Layout

- `src/cp.ts` — typed control-plane client (mirrors `cmd/sandbox-sim/cpclient.go`;
  auth header `X-Sandbox-Token`; adds `route()` and the dev fault endpoint).
- `src/tools.ts` — Vercel AI SDK tool wrappers (sandbox_create, sandbox_exec,
  sandbox_write_file/read_file, sandbox_suspend/resume, endpoint_bind,
  events_tail); every call logged with latency into the run log.
- `src/model.ts` — driver selection: `DRIVER=scripted` (default, no LLM) or
  `DRIVER=live` (`@ai-sdk/openai-compatible`; Together or DeepSeek via
  `LLM_PROVIDER`, key from `TOGETHER_API_KEY` / `DEEPSEEK_API_KEY`).
- `src/scenarios/` — one module per scenario: task prompt (live mode),
  deterministic script (scripted mode), assertions (both modes).
- `src/runner.ts` — runs scenarios, writes `runs/<name>-<ts>.jsonl`
  (steps, tool calls + latency, event batches, assertion verdicts), prints a
  PASS/FAIL summary, exit code reflects the verdict.
- `scripts/start-stack.sh` / `stop-stack.sh` — the emulation stack:
  control-planed with an **in-process local backend** (`BACKEND=local`, no
  KVM/host agents needed) + endpoint-proxyd, plus a static `dev-python`
  environment (restart recipe: start hook appends `hooks.log`, terminal hook
  runs `python3 -m http.server 8020`) and dev fault injection
  (`SANDBOX_DEV_FAULTS=1` → `POST /v1/dev/fault/kill-runtime`).

## Running

```sh
npm install
npm run typecheck          # tsc --noEmit
npm run stack              # build + start control-planed(:8390) + proxy(:8391)
npm run scenario:all       # all scenarios, scripted driver (CI)
npm run scenario -- host-loss-reset   # single scenario
npm run stack:stop
```

Live-LLM mode (exploratory; same assertions):

```sh
TOGETHER_API_KEY=... DRIVER=live LLM_MODEL=meta-llama/Llama-3.3-70B-Instruct-Turbo \
  npm run scenario -- build-and-serve
```

## Scenarios

- **build-and-serve** — create sandbox, write `server.py` + `index.html`,
  launch in background, bind endpoint; asserts the endpoint serves 200 with
  the marker through endpoint-proxyd.
- **suspend-resume-continuity** — sandbox on `dev-python` (hooks); suspend +
  resume; asserts the endpoint serves again with no agent re-creation AND the
  path is honest: continuity (epoch kept, no `ExecutionStateReset`) xor reset
  + hook self-heal.
- **host-loss-reset** — dev-fault kill (host crash path, INV-024); asserts
  sandbox FAILED explicitly, `ExecutionStateReset` + epoch bump on
  rematerialize, hooks rebuilt the service (endpoint 200), AND that the
  pre-reset binding is epoch-fenced (route denies "stale epoch fence") — the
  agent's recovery includes re-binding, which is platform metadata, not
  service re-creation.

## control-planed additions made for this harness (all dev-only, additive)

- `BACKEND=local|fake` env (default `fleet`, unchanged): in-process backend,
  no host agents; a pseudo-host entry keeps `/v1/sandboxes/{id}/address`
  working so endpoint-proxyd can dial `127.0.0.1:<target_port>` (local
  backend processes listen on the host directly — no DNAT needed).
- `POST /v1/sandboxes` accepts `environment_id`.
- `DEV_ENVIRONMENTS` (JSON): static environments with restart recipes
  (start/terminals hooks) served through the manager's `EnvironmentSource`.
- `SANDBOX_DEV_FAULTS=1` mounts `POST /v1/dev/fault/kill-runtime`.

## Metal-readiness checklist

When the KVM nodes return:

1. **Fleet topology instead of emulation**: run control-planed in default
   `BACKEND=fleet` mode on node 1 (`LISTEN_ADDR=:8090 TOKEN=...`), host-agentd
   with the firecracker backend, endpoint-proxyd as before. Point the harness
   at them: `CP_URL=http://<node1>:8090 PROXY_URL=http://<node1>:8091
   TOKEN=... npm run scenario:all`.
2. **Expected differences vs emulation**: real VM boot latency (seconds, not
   ms — polls already tolerate this); snapshot-class suspend RECLAIMS RAM
   (suspend-resume-continuity may take the checkpoint path — epoch retained,
   still no reset, still PASS); endpoint publish is real FC-PUB-* DNAT (not
   loopback); the dev fault endpoint should stay off in fleet mode — use
   host-agent kill / `Terminate` for fault drills instead.
3. **Environments**: `DEV_ENVIRONMENTS` is a static stand-in. On metal, build
   a real environment via the environment-builder (recipe.json persistence is
   covered by conformance); keep the same `dev-python` recipe for parity.
4. **Validation matrix**: scripted scenarios × backends (fake = control-plane
   determinism only, no real processes; local = emulated data path;
   firecracker = real isolation) — then `DRIVER=live` exploratory runs with a
   real key, watching `runs/*.jsonl` tool latencies and the agent's recovery
   behavior on host-loss.
5. **What should NOT differ**: all assertion semantics (endpoint 200s, event
   sequences, epoch arithmetic, fence behavior). A difference on metal is a
   platform bug, not a harness artifact.
