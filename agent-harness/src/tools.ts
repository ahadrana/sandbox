// AI SDK tool definitions: thin typed wrappers over the control-plane HTTP
// API, shared by the live-LLM driver. Every call is logged (name, args,
// latency, result summary) and stashes identifiers into ctx.state so
// assertions check observable outcomes, not model claims.

import { tool } from "ai";
import { z } from "zod";
import type { RunContext } from "./ctx.js";

export function buildTools(ctx: RunContext) {
  const wrap = <A, R>(name: string, fn: (a: A) => Promise<R>) => {
    return async (a: A): Promise<R> => {
      const t0 = Date.now();
      try {
        const r = await fn(a);
        ctx.log.write({ kind: "tool", tool: name, args: a as unknown, latency_ms: Date.now() - t0, ok: true, result: summarize(r) });
        return r;
      } catch (err) {
        ctx.log.write({ kind: "tool", tool: name, args: a as unknown, latency_ms: Date.now() - t0, ok: false, error: String(err) });
        throw err;
      }
    };
  };
  const summarize = (r: unknown): unknown => {
    const s = JSON.stringify(r);
    return s.length > 300 ? s.slice(0, 300) + "…" : r;
  };

  return {
    sandbox_create: tool({
      description: "Create a sandbox for a task and boot it (materialize). Returns the sandbox record incl. SandboxID and ExecutionEpoch.",
      inputSchema: z.object({
        task_ref: z.string().describe("short task label"),
        environment_id: z.string().optional().describe("prepared environment id (carries the restart recipe/hooks)"),
      }),
      execute: wrap("sandbox_create", async ({ task_ref, environment_id }) => {
        const sb = await ctx.cp.createSandbox(task_ref, environment_id);
        await ctx.cp.materialize(sb.SandboxID);
        ctx.state.sandboxId = sb.SandboxID;
        return sb;
      }),
    }),
    sandbox_exec: tool({
      description: "Run a shell command in the sandbox (synchronous). Optionally writes files first (writes: path->content).",
      inputSchema: z.object({
        command: z.string(),
        writes: z.record(z.string(), z.string()).optional(),
      }),
      execute: wrap("sandbox_exec", async ({ command, writes }) => {
        return ctx.cp.exec(ctx.sandboxId(), command, writes);
      }),
    }),
    sandbox_write_file: tool({
      description: "Write a file into the sandbox workspace.",
      inputSchema: z.object({ path: z.string(), content: z.string() }),
      execute: wrap("sandbox_write_file", async ({ path, content }) => {
        return ctx.cp.exec(ctx.sandboxId(), "true", { [path]: content });
      }),
    }),
    sandbox_read_file: tool({
      description: "Read a file from the sandbox workspace.",
      inputSchema: z.object({ path: z.string() }),
      execute: wrap("sandbox_read_file", async ({ path }) => {
        const files = await ctx.cp.readFiles(ctx.sandboxId());
        return files[path] ?? null;
      }),
    }),
    sandbox_suspend: tool({
      description: "Suspend the sandbox (checkpoint if supported; workspace committed durably either way).",
      inputSchema: z.object({}),
      execute: wrap("sandbox_suspend", async () => {
        await ctx.cp.suspend(ctx.sandboxId());
        return { ok: true };
      }),
    }),
    sandbox_resume: tool({
      description: "Resume a suspended sandbox. Report tells whether the epoch reset (workspace-only recovery) or continuity was kept.",
      inputSchema: z.object({}),
      execute: wrap("sandbox_resume", async () => {
        const rep = await ctx.cp.resume(ctx.sandboxId());
        ctx.state.lastResume = rep;
        return rep;
      }),
    }),
    endpoint_bind: tool({
      description: "Bind a sandbox TCP port to a named public endpoint. Returns the BindingID; fetch it via the endpoint proxy with header X-Endpoint-Binding.",
      inputSchema: z.object({
        target_port: z.number().int().min(1).max(65535),
        logical_name: z.string(),
      }),
      execute: wrap("endpoint_bind", async ({ target_port, logical_name }) => {
        const id = await ctx.cp.createBinding(ctx.sandboxId(), target_port, logical_name);
        ctx.state.bindingId = id;
        return { binding_id: id, fetch_via: `${ctx.cp.proxyBase}/ with header X-Endpoint-Binding: ${id}` };
      }),
    }),
    events_tail: tool({
      description: "Read new control-plane events since the last call (sandbox lifecycle: hooks, suspend/resume, ExecutionStateReset, failures).",
      inputSchema: z.object({}),
      execute: wrap("events_tail", async () => {
        const events = await ctx.drainEvents("tool");
        return events.map((e) => ({ type: e.EventType, payload: e.Payload }));
      }),
    }),
  };
}

export type HarnessTools = ReturnType<typeof buildTools>;
