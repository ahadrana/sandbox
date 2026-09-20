// Scenario runner. Usage:
//   tsx src/runner.ts --all | <scenario-name>...
// Env:
//   CP_URL (default http://127.0.0.1:8390), PROXY_URL (default :8391),
//   TOKEN (default dev-token),
//   DRIVER=scripted (default, deterministic) | live (ToolLoopAgent + LLM)
//
// Every run writes agent-harness/runs/<scenario>-<ts>.jsonl with steps, tool
// calls (with latency), event batches, and assertion results, then prints a
// PASS/FAIL summary. Exit code 1 if any assertion fails.

import path from "node:path";
import { fileURLToPath } from "node:url";
import { ToolLoopAgent, stepCountIs } from "ai";
import { CPClient } from "./cp.js";
import { RunContext, RunLog } from "./ctx.js";
import { buildTools } from "./tools.js";
import { driverFromEnv, liveModel } from "./model.js";
import { scenarios } from "./scenarios/index.js";
import type { Scenario } from "./scenarios/common.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const runsDir = path.join(here, "..", "runs");

async function runLive(ctx: RunContext, scenario: Scenario): Promise<void> {
  const spec = liveModel();
  ctx.log.write({ kind: "llm", what: "driver", provider: spec.provider, model: spec.modelId });
  const agent = new ToolLoopAgent({
    model: spec.model,
    tools: buildTools(ctx),
    stopWhen: stepCountIs(30),
    instructions:
      "You are operating a sandbox platform via tools. Do the task precisely and stop when done. " +
      "Never claim a result you have not observed via a tool.",
  });
  const result = await agent.generate({ prompt: scenario.task });
  ctx.log.write({ kind: "llm", what: "final", text: result.text, steps: result.steps.length });
  console.log(`  [llm] ${result.steps.length} steps; final: ${result.text.slice(0, 200)}`);
}

async function runScenario(name: string, scenario: Scenario): Promise<boolean> {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const log = new RunLog(path.join(runsDir, `${scenario.name}-${ts}.jsonl`));
  const cp = new CPClient(
    process.env.CP_URL ?? "http://127.0.0.1:8390",
    process.env.TOKEN ?? "dev-token",
    process.env.PROXY_URL ?? "http://127.0.0.1:8391",
  );
  const ctx = new RunContext(cp, log, scenario.name);
  const driver = driverFromEnv();
  console.log(`\n=== ${scenario.name} (driver: ${driver}) — ${log.file}`);
  let failed = false;
  try {
    if (!(await cp.healthy())) throw new Error(`control plane not healthy at ${cp.base} (start it: npm run stack)`);
    if (driver === "live") await runLive(ctx, scenario);
    else await scenario.script(ctx);
  } catch (err) {
    failed = true;
    console.log(`  [driver] ERROR: ${err}`);
    ctx.log.write({ kind: "info", what: "driver error", error: String(err) });
  }
  for (const a of scenario.assertions) {
    if (failed) {
      console.log(`  SKIP ${a.name}`);
      ctx.log.write({ kind: "assertion", name: a.name, pass: false, skipped: true });
      continue;
    }
    try {
      await a.check(ctx);
      console.log(`  PASS ${a.name}`);
      ctx.log.write({ kind: "assertion", name: a.name, pass: true });
    } catch (err) {
      failed = true;
      console.log(`  FAIL ${a.name}: ${err}`);
      ctx.log.write({ kind: "assertion", name: a.name, pass: false, error: String(err) });
    }
  }
  // Hygiene: terminate the sandbox so its processes (and ports) are freed
  // for the next scenario.
  try {
    if (ctx.state.sandboxId) await cp.terminate(ctx.sandboxId());
  } catch {
    /* best effort */
  }
  console.log(`=== ${scenario.name}: ${failed ? "FAIL" : "PASS"}`);
  ctx.log.write({ kind: "info", what: "verdict", scenario: scenario.name, pass: !failed });
  log.close();
  return !failed;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const selected = args.includes("--all") ? scenarios : scenarios.filter((s) => args.includes(s.name));
  if (selected.length === 0) {
    console.error(`usage: tsx src/runner.ts --all | ${scenarios.map((s) => s.name).join(" | ")}`);
    process.exit(2);
  }
  const results: [string, boolean][] = [];
  for (const s of selected) results.push([s.name, await runScenario(s.name, s)]);
  console.log("\n=== summary");
  let ok = true;
  for (const [n, pass] of results) {
    console.log(`  ${pass ? "PASS" : "FAIL"} ${n}`);
    ok &&= pass;
  }
  process.exit(ok ? 0 : 1);
}

await main();
