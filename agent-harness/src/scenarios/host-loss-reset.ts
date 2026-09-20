// host-loss-reset: inject a runtime kill (dev fault endpoint — the same
// code path as a host crash, INV-024); the sandbox goes FAILED, the agent
// must observe the loss, rematerialize, see ExecutionStateReset, and find
// the service rebuilt by the environment's restart recipe (hooks) — again
// without re-creating it.

import type { Scenario } from "./common.js";
import { SERVER_MARKER, expect, poll, sandboxEvents } from "./common.js";

const PORT = 8020; // dev-python terminal hook port (see start-stack.sh)

const scenario: Scenario = {
  name: "host-loss-reset",
  environment: "dev-python",
  ports: [PORT],
  task: `Create a sandbox on environment dev-python (its hooks auto-start a web server on port ${PORT}), write an index.html containing "${SERVER_MARKER}", and bind an endpoint. The platform will kill the sandbox's runtime underneath you (simulated host loss). Detect the failure (sandbox state / events_tail), rematerialize the sandbox, and verify via events_tail that ExecutionStateReset fired and the hooks rebuilt the service. Note: endpoint bindings are epoch-fenced — after an ExecutionStateReset the old binding is dead; bind a fresh endpoint. Do NOT restart the server yourself.`,
  async script(ctx) {
    ctx.step("create+materialize (env dev-python, hooks)");
    const sb = await ctx.cp.createSandbox("harness-host-loss", "dev-python");
    ctx.state.sandboxId = sb.SandboxID;
    await ctx.cp.materialize(sb.SandboxID);

    ctx.step("write index.html");
    await ctx.cp.exec(sb.SandboxID, "true", { "index.html": `<h1>${SERVER_MARKER}</h1>` });

    ctx.step("bind endpoint");
    ctx.state.bindingId = await ctx.cp.createBinding(sb.SandboxID, PORT, "harness-web");
    await poll("pre-fault endpoint 200", 10_000, async () => {
      const { status } = await ctx.cp.endpointGet(ctx.bindingId());
      return status === 200;
    });

    ctx.step("FAULT: kill runtime (simulated host loss)");
    await ctx.cp.killRuntime(sb.SandboxID);
    await ctx.drainEvents("post-fault");

    ctx.step("observe FAILED + rematerialize (agent recovery action)");
    const dead = await ctx.cp.getSandbox(sb.SandboxID);
    ctx.state.stateAfterFault = dead.ObservedState;
    const rep = await ctx.cp.materialize(sb.SandboxID);
    ctx.state.lastResume = rep;
    await ctx.drainEvents("post-rematerialize");

    // The gateway epoch-fences the pre-reset binding (fail-closed: "stale
    // epoch fence"), so recovery re-binds — the platform metadata step, not
    // service re-creation (hooks rebuilt the service itself).
    ctx.step("verify old binding fenced; re-bind at the new epoch");
    ctx.state.staleBindingId = ctx.state.bindingId;
    ctx.state.bindingId = await ctx.cp.createBinding(sb.SandboxID, PORT, "harness-web-2");
  },
  assertions: [
    {
      name: "fault marked the sandbox FAILED (explicit, not silent)",
      async check(ctx) {
        expect(ctx.state.stateAfterFault === "FAILED", `state after fault=${ctx.state.stateAfterFault}`);
      },
    },
    {
      name: "ExecutionStateReset emitted; epoch bumped 1 -> 2",
      async check(ctx) {
        const rep = ctx.state.lastResume as { PriorEpoch: number; NewEpoch: number };
        expect(rep.NewEpoch === rep.PriorEpoch + 1, `epoch ${rep.PriorEpoch} -> ${rep.NewEpoch}`);
        const events = await sandboxEvents(ctx);
        expect(events.filter((e) => e.EventType === "ExecutionStateReset").length === 1, "want one ExecutionStateReset");
        expect(events.filter((e) => e.EventType === "EnvironmentHooksCompleted").length >= 2, "hooks must re-run on rematerialize");
      },
    },
    {
      name: "pre-reset binding is epoch-fenced (route denies stale fence)",
      async check(ctx) {
        const dec = await ctx.cp.route(ctx.state.staleBindingId as string);
        expect(!dec.Allowed && dec.Reason.includes("stale epoch fence"), `old binding verdict: ${JSON.stringify(dec)}`);
      },
    },
    {
      name: "service reconstructed by hooks — endpoint 200 via re-bound endpoint, no agent re-creation",
      async check(ctx) {
        await poll("post-reset endpoint 200", 15_000, async () => {
          const { status, body } = await ctx.cp.endpointGet(ctx.bindingId());
          return status === 200 && body.includes(SERVER_MARKER);
        });
      },
    },
  ],
};

export default scenario;
