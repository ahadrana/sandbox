// Typed client for the sandbox control-plane HTTP API. Mirrors
// cmd/sandbox-sim/cpclient.go: same endpoints, same auth header
// (X-Sandbox-Token), same capitalized Go-struct JSON field names.

export interface SandboxInfo {
  SandboxID: string;
  ObservedState: string;
  ExecutionEpoch: number;
  WorkspaceGeneration: number;
  EnvironmentID?: string;
}

export interface ResumeReport {
  PriorEpoch: number;
  NewEpoch: number;
  UncommittedStateLost: boolean;
}

export interface ExecResult {
  ExecutionID: string;
  State: string;
  ExitCode: number | null;
}

export interface CPEvent {
  EventID: string;
  EventType: string;
  SandboxID?: string;
  Payload: Record<string, unknown>;
}

export class CPError extends Error {
  constructor(public status: number, public path: string, body: string) {
    super(`${path}: HTTP ${status}: ${body}`);
  }
}

export class CPClient {
  constructor(
    public base: string,
    public token: string,
    public proxyBase: string,
  ) {}

  private async req<T>(method: string, path: string, body?: unknown, timeoutMs = 60_000): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.token) headers["X-Sandbox-Token"] = this.token;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const resp = await fetch(this.base + path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await resp.text();
    if (!resp.ok) throw new CPError(resp.status, path, text.trim().slice(0, 500));
    return (text ? JSON.parse(text) : {}) as T;
  }

  async healthy(): Promise<boolean> {
    try {
      const resp = await fetch(this.base + "/healthz", { signal: AbortSignal.timeout(3000) });
      return resp.status === 200;
    } catch {
      return false;
    }
  }

  createSandbox(taskRef: string, environmentId?: string): Promise<SandboxInfo> {
    return this.req("POST", "/v1/sandboxes", {
      task_ref: taskRef,
      ...(environmentId ? { environment_id: environmentId } : {}),
    });
  }

  materialize(id: string): Promise<ResumeReport> {
    return this.req("POST", `/v1/sandboxes/${id}/materialize`, {});
  }

  getSandbox(id: string): Promise<SandboxInfo> {
    return this.req("GET", `/v1/sandboxes/${id}`);
  }

  exec(id: string, command: string, writes?: Record<string, string>): Promise<ExecResult> {
    return this.req("POST", `/v1/sandboxes/${id}/exec`, {
      command,
      ...(writes ? { writes } : {}),
    });
  }

  /** Runtime workspace view: path -> content (committed + uncommitted). */
  async readFiles(id: string): Promise<Record<string, string>> {
    const out = await this.req<{ files: Record<string, string> }>("GET", `/v1/sandboxes/${id}/files`);
    return out.files ?? {};
  }

  suspend(id: string): Promise<void> {
    return this.req("POST", `/v1/sandboxes/${id}/suspend`, {});
  }

  resume(id: string): Promise<ResumeReport> {
    return this.req("POST", `/v1/sandboxes/${id}/resume`, {}, 120_000);
  }

  terminate(id: string): Promise<void> {
    return this.req("POST", `/v1/sandboxes/${id}/terminate`, {});
  }

  async createBinding(sandboxID: string, targetPort: number, logicalName: string): Promise<string> {
    const out = await this.req<{ BindingID: string }>("POST", "/v1/bindings", {
      sandbox_id: sandboxID,
      target_port: targetPort,
      logical_name: logicalName,
      auth_policy: "none",
      ttl_seconds: 86400,
    });
    if (!out.BindingID) throw new Error("binding response carried no BindingID");
    return out.BindingID;
  }

  /** GET through endpoint-proxyd, selecting the binding by header (as the sim does). */
  async endpointGet(bindingID: string, path = "/"): Promise<{ status: number; body: string }> {
    const resp = await fetch(this.proxyBase + path, {
      headers: { "X-Endpoint-Binding": bindingID },
      signal: AbortSignal.timeout(120_000), // endpoint resume can be slow
    });
    return { status: resp.status, body: await resp.text() };
  }

  async events(since: number, limit = 500): Promise<{ events: CPEvent[]; cursor: number }> {
    return this.req("GET", `/v1/events?since=${since}&limit=${limit}`);
  }

  /** Gateway route verdict for a binding (fail-closed; used by assertions). */
  route(bindingID: string): Promise<{ Allowed: boolean; Reason: string }> {
    return this.req("GET", `/v1/route/${bindingID}`);
  }

  /** Dev-only fault injection (control-planed with SANDBOX_DEV_FAULTS=1). */
  killRuntime(id: string): Promise<void> {
    return this.req("POST", "/v1/dev/fault/kill-runtime", { sandbox_id: id });
  }
}
