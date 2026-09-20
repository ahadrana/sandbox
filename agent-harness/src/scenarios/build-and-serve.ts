// build-and-serve: create a sandbox, write a small python HTTP server +
// index.html, start it in the background, bind an endpoint — the endpoint
// must serve 200 through the endpoint-proxyd stack.

import type { Scenario } from "./common.js";
import { SERVER_MARKER, expect, poll, serverPy } from "./common.js";

const PORT = 8010;

const scenario: Scenario = {
  name: "build-and-serve",
  environment: "",
  ports: [PORT],
  task: `Create a sandbox, write a python HTTP server (server.py) and an index.html containing "${SERVER_MARKER}", start the server in the background on port ${PORT} (bound to 127.0.0.1), bind an endpoint to that port, and confirm the endpoint URL serves the page.`,
  async script(ctx) {
    ctx.step("create+materialize");
    const sb = await ctx.cp.createSandbox("harness-build-and-serve");
    ctx.state.sandboxId = sb.SandboxID;
    await ctx.cp.materialize(sb.SandboxID);

    ctx.step("write server.py + index.html");
    await ctx.cp.exec(sb.SandboxID, "true", {
      "server.py": serverPy(PORT),
      "index.html": `<h1>${SERVER_MARKER}</h1>`,
    });

    ctx.step("start server in background");
    const ex = await ctx.cp.exec(sb.SandboxID, `nohup python3 server.py > /tmp/server.log 2>&1 & echo started`);
    expect(ex.State === "COMPLETED" && ex.ExitCode === 0, `server launch: ${ex.State} exit=${ex.ExitCode}`);

    ctx.step("bind endpoint");
    ctx.state.bindingId = await ctx.cp.createBinding(sb.SandboxID, PORT, "harness-web");
  },
  assertions: [
    {
      name: "endpoint serves 200 with the marker through the proxy",
      async check(ctx) {
        await poll("endpoint 200", 10_000, async () => {
          const { status, body } = await ctx.cp.endpointGet(ctx.bindingId());
          return status === 200 && body.includes(SERVER_MARKER);
        });
      },
    },
    {
      name: "sandbox is RUNNING-family after setup",
      async check(ctx) {
        const sb = await ctx.cp.getSandbox(ctx.sandboxId());
        expect(["RUNNING", "QUIESCENT", "BACKGROUND_ACTIVE"].includes(sb.ObservedState), `state=${sb.ObservedState}`);
      },
    },
  ],
};

export default scenario;
