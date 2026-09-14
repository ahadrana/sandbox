# ADR-0001: Runtime isolation backend — Firecracker decision DEFERRED

- **Status:** accepted (decision deferred, mechanism accepted)
- **Date:** 2026-09-13
- **Deciders:** platform team

## Context

PLAN §9 calls for a strong-isolation backend with Firecracker as the primary
candidate. The development/CI environment has **no `/dev/kvm`** and no
Firecracker binary, so a VM-class backend cannot be built, run, or tested
here. User namespaces with `--map-root-user` and bubblewrap are available.

Relevant invariants: INV-026 (runtime substitutable), INV-027 (isolation
stronger than Kubernetes namespaces), FR-ISO-004 (stable interface),
FR-SEC-001 (no control-plane credentials in guest).

## Decision

1. **Firecracker-vs-alternatives (Kata/gVisor) is DEFERRED.** Rationale: no
   KVM in the dev environment; per PLAN §15 this decision is benchmark-driven
   and must be made after conformance + workload benchmarks exist, not before.
2. **Backend capability declarations are the contract, accepted now.**
   `backendinterface.Capabilities{IsolationClass: PROCESS|NAMESPACE|VM,
   SupportsPause, SupportsSnapshot, SupportsRestore, NetworkIsolated,
   HostCredentialFree}` is implemented by every backend (fake, local,
   isolated, fleet). Behavioral differences between backends MUST be
   expressed as declared capabilities; conformance tests skip on missing
   capabilities instead of failing on silent differences.
3. The strongest backend this environment supports —
   `runtime/isolated-backend` (bubblewrap: private mount namespace with only
   the incarnation workspace writable, read-only system binds, cleared
   environment, network/IPC/UTS namespace isolation) — is implemented behind
   the same `RuntimeBackend` interface and declares
   `IsolationClass: NAMESPACE`.

## Acceptance criteria for a future VM-class backend

A Firecracker (or alternative) backend is accepted when it:

- implements `backendinterface.Backend` + the supervisor data path with zero
  public-API surface changes and declares `IsolationClass: VM`;
- passes the full conformance suite run against it (skips only on declared
  missing capabilities);
- satisfies PLAN §9 security requirements: no host filesystem access beyond
  explicit devices/shares, no Kubernetes service-account credentials in the
  guest, metadata/control-plane endpoints blocked, cross-VM isolation tests,
  dedicated execution account/network boundaries where applicable;
- provides snapshot compatibility metadata for checkpoint restore (M8) or
  explicitly declares `SupportsSnapshot: false`;
- runs jailer/host hardening on dedicated execution nodes.

## Consequences

- Positive: the public contract (capabilities, not vendors) is fixed now;
  the suite already runs against two isolation classes.
- Negative: VM-class isolation is unproven; NAMESPACE isolation is not a
  hostile-code production boundary (INV-027 remains open).
- Follow-ups: Firecracker backend on KVM-capable hardware (M6 production
  path); cross-VM isolation and breakout suites (M11); benchmark
  Firecracker vs Kata/gVisor and finalize this ADR's deferred decision.

## Compliance

- [x] Does not weaken INV-005..INV-016 or make state loss silent
- [x] Conformance tests updated/added before semantic change
- [x] No vendor-specific concepts leak into the API (Firecracker appears
  nowhere in `backendinterface` or the public schema)
