// suspend-resume-continuity: sandbox on an environment whose terminal hook
// serves the workspace; after suspend+resume the agent must observe either
// continuity (epoch retained, no ExecutionStateReset, server still up) or a
// reset (ExecutionStateReset observed AND the hooks self-healed the service
// with NO agent re-creation). Assertions read the real endpoint + events.

import type { Scenario } from "./common.js";
import { SERVER_MARKER, expect, poll, sandboxEvents } from "./common.js";

// Must match the dev-python environment's terminal hook in
// scripts/start-stack.sh.
const PORT = 8020;

const scenario: Scenario = {
  name: "suspend-resume-continuity",
  environment: "dev-python",
  ports: [PORT],
  task: `Create a sandbox on environment dev-python (its hooks auto-start a web server on port ${PORT}), write an index.html containing "${SERVER_MARKER}", bind an endpoint, then suspend and resume the sandbox. Afterwards check events_tail: if you see ExecutionStateReset, the sandbox lost its processes — verify the environment hooks rebuilt the service (do NOT recreate it yourself). Report what you observed.`,
  async script(ctx) {
    ctx.step("create+materialize (env dev-python, hooks)");
    const sb = await ctx.cp.createSandbox("harness-suspend-resume", "dev-python");
    ctx.state.sandboxId = sb.SandboxID;
    await ctx.cp.materialize(sb.SandboxID);

    ctx.step("write index.html (committed via write op)");
    await ctx.cp.exec(sb.SandboxID, "true", { "index.html": `<h1>${SERVER_MARKER}</h1>` });

    ctx.step("bind endpoint");
    ctx.state.bindingId = await ctx.cp.createBinding(sb.SandboxID, PORT, "harness-web");

    ctx.step("baseline: endpoint serves before suspend");
    await poll("pre-suspend endpoint 200", 10_000, async () => {
      const { status, body } = await ctx.cp.endpointGet(ctx.bindingId());
      return status === 200 && body.includes(SERVER_MARKER);
    });

    ctx.step("suspend + resume");
    await ctx.cp.suspend(sb.SandboxID);
    const rep = await ctx.cp.resume(sb.SandboxID);
    ctx.state.lastResume = rep;
    await ctx.drainEvents("post-resume");
  },
  assertions: [
    {
      name: "endpoint serves 200 after resume with no agent re-creation",
      async check(ctx) {
        await poll("post-resume endpoint 200", 15_000, async () => {
          const { status, body } = await ctx.cp.endpointGet(ctx.bindingId());
          return status === 200 && body.includes(SERVER_MARKER);
        });
      },
    },
    {
      name: "resume path is honest: continuity (epoch kept, no reset) OR reset+hook self-heal",
      async check(ctx) {
        const rep = ctx.state.lastResume as { PriorEpoch: number; NewEpoch: number };
        const events = await sandboxEvents(ctx);
        const resets = events.filter((e) => e.EventType === "ExecutionStateReset");
        if (rep.NewEpoch === rep.PriorEpoch) {
          expect(resets.length === 0, "continuity resume emitted ExecutionStateReset");
        } else {
          expect(rep.NewEpoch === rep.PriorEpoch + 1, `epoch ${rep.PriorEpoch} -> ${rep.NewEpoch}`);
          expect(resets.length === 1, `want exactly one ExecutionStateReset, got ${resets.length}`);
          const hookRuns = events.filter((e) => e.EventType === "EnvironmentHooksStarted");
          expect(hookRuns.length >= 2, `hooks must re-run on epoch-creating resume (saw ${hookRuns.length})`);
        }
      },
    },
  ],
};

export default scenario;
