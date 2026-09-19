# Backlog / Follow-up Queue

Consolidated from ADR follow-ups, code-review queues, and session decisions.
Ordered roughly by value. Last updated: 2026-09-19 (ADR-012 credential
surrogation spec; Muse-inspired items).

## Deprioritized by ADR-011 (the Cursor-model inversion)

- **Cross-kernel / cross-FC continuity restore experiment.** Was "potentially
  serious issue"; now a cohort-expansion *optimization* only (ADR-011 §Alternatives).
  Sandbox Snapshot resume makes kernel upgrades non-events for idle sandboxes.
  Revisit only if warm-resume-across-kernels proves economically important.
  (6.8↔7.0 experiment env still stands: nodes 1/2 run those kernels.)

## Active queue

1. **Credential surrogation** (Muse/Sentinel model; spec:
   [ADR-012](adr/012-credential-surrogation.md)): agent holds only surrogate
   tokens; per-host L7 egress proxy swaps in real credentials after
   authorizing. Phase 1 = broker surrogate minting + proxy insertion for
   allowlisted HTTPS destinations + fail-closed enforcement + swap audit.
   Estimate ~2–3 sessions.
2. **SSRF final-IP re-verification at connect time** for DNS-learned egress
   entries: re-check the resolved/final IP at connect, not just at DNS-answer
   learn time (TTL rebinding / answer-churn window). Small.
3. **MCP server + LLM driver** (`cmd/sandboxlab-mcp` + Together/DeepSeek tool-loop
   driver): LLM-driven adversarial exploration of sim + live fleet. Deferred from
   2026-09-17 session; design discussion in session history (two pieces: stdio MCP
   server exposing run_scenario/inject_fault/get_world_state/get_invariant_report,
   plus an OpenAI-compatible client loop since Together is not an MCP host).
4. **L7-aware egress policy** (method/path per capability claim): phase 2 of
   ADR-012; depends on the surrogation proxy hop.
5. **Human-in-the-loop approval flow** (capability-bound approvals for
   sensitive credential swaps/exec classes; ADR-012 phase 3): larger product
   decision — approval UX, timeout semantics, and audit shape need a product
   call before implementation.
6. **Batch 4 (CubeSandbox borrow list)**: P2 grab-bag — TAP pool pre-warming,
   flattened workspace generations + depth metrics, credential audit fingerprints
   (`fp-<sha256[:8]>`), guest-ready MMIO signal, sandboxctl client validation,
   jittered cache TTLs; plus P1.8 key-schema package for gateway-tier state push.
7. **Soak coverage of idle-reclaim churn** (ADR-011 step-3 follow-up): run the
   node-1 soak with IdleReclaimAfter shortened so automatic reclaim cycles are
   exercised longitudinally (current soak covered API-driven churn only).
8. **Jailer upstream PR** (aarch64 `midr_el1` sysfs patch): deferred by user
   2026-09-14; still deferred. Relationship groundwork for eventual Firecracker
   snapshot-portability conversations (ADR-011 §Alternatives).
9. **k3s two-node cluster**: join node 2 once its kernel is aligned/qualified
   (7.0 kubelet/cadvisor crash risk documented; standalone topology works today).
10. **True cross-machine RAM continuity proof**: needs matching kernels on both
    nodes (one reboot of node 2 to 6.8.0-1063-aws). Optional; validates ADR-009
    pull path machine-to-machine. Related to item 9's kernel decision.

## Rejected for now (explicit decisions, revisit triggers noted)

- **eBPF/LSM taint tracking** (Muse Sentinel-style kernel flow tainting):
  rejected-for-now per ADR-012 §7 — the L7 proxy already observes
  credentialed flows; mixed 6.8/7.0 kernels multiply the compatibility
  matrix; research-project scope. Revisit if the threat model extends to
  host-level insiders or off-proxy exfil channels.

## Accepted lows (won't fix unless promoted)

- L9 node-wide sysctl blast radius (dedicated-node enforcement is an ops decision)
- L11 dev shared-token SSRF posture (pre-production auth redesign covers it)
- L12 proxy caches unbounded (dev scale)
- L14 jail bind-mount flags rw/no-nodev (largely inherent)
- Pre-production auth generally: one shared token guards the data-path control
  surface; a real authN/Z design is a pre-production milestone, not a patch.

## Done recently (for reference)

- All CODE-REVIEW-2026-09-16 findings (batches A/B/C, commits e49f1f1..72c38a8)
- Cross-host checkpoint transfer, origin-host pinned + pull (ADR-008/009)
- Tools-image GC, CheckpointGuard plumbing, k8s conntrack/sysctl gaps
- Five sim-surfaced platform bugs (down-latch, IDGen collision, nil-host panic,
  sweep-foreign-resources, resume race) + two fleet bugs (CP deadlock,
  lost-host stall/false continuity)
- SandboxLab phases 1–5 + contention model; invariant engine on live traces
  (invcheck); 4h soak: 432 restores, 0 fails, 0 violations, no leaks
