// Run context shared by scripted drivers, LLM tools, and assertions, plus
// the JSONL run log (one record per step/tool-call/assertion/event-batch).

import * as fs from "node:fs";
import * as path from "node:path";
import type { CPClient, CPEvent } from "./cp.js";

export interface LogRecord {
  at: string;
  kind: "step" | "tool" | "assertion" | "events" | "llm" | "info";
  [k: string]: unknown;
}

export class RunLog {
  private stream: fs.WriteStream;
  constructor(public file: string) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    this.stream = fs.createWriteStream(file, { flags: "w" });
  }
  write(rec: Omit<LogRecord, "at">): void {
    this.stream.write(JSON.stringify({ at: new Date().toISOString(), ...rec }) + "\n");
  }
  close(): void {
    this.stream.end();
  }
}

export class RunContext {
  /** Named state tools/scripts stash for assertions (sandboxId, bindingId, …). */
  state: Record<string, unknown> = {};
  /** Cursor into the control-plane event stream (per run). */
  eventCursor = 0;

  constructor(
    public cp: CPClient,
    public log: RunLog,
    public scenario: string,
  ) {}

  step(name: string, detail?: Record<string, unknown>): void {
    this.log.write({ kind: "step", step: name, ...detail });
    console.log(`  [step] ${name}${detail ? " " + JSON.stringify(detail) : ""}`);
  }

  /** Drain new control-plane events into the run log; returns them. */
  async drainEvents(why: string): Promise<CPEvent[]> {
    const { events, cursor } = await this.cp.events(this.eventCursor);
    this.eventCursor = cursor;
    const types = events.map((e) => e.EventType);
    this.log.write({ kind: "events", why, count: events.length, types });
    if (events.length > 0) console.log(`  [events:${why}] ${types.join(", ")}`);
    return events;
  }

  sandboxId(): string {
    const id = this.state.sandboxId;
    if (typeof id !== "string" || !id) throw new Error("no sandboxId in run state");
    return id;
  }
  bindingId(): string {
    const id = this.state.bindingId;
    if (typeof id !== "string" || !id) throw new Error("no bindingId in run state");
    return id;
  }
}
