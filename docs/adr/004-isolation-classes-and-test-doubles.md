# ADR 004 — One production isolation class; test doubles are contract-verified, not production backends

**Status:** Accepted
**Date:** 2026-09-14
**Context:** INV-026 requires runtime substitutability, and the platform now has four backends: fake, local (process), isolated (bwrap namespace), and firecracker (VM). The conformance gate (M6) runs the same contract scenarios against all of them, with differences expressed only as declared capabilities. A design question was raised: is backend swappability dangerous given Firecracker is the production target?

## Decision

1. **Production multi-tenant deployments offer exactly one isolation class: VM (Firecracker).** The local and isolated backends are development/test tooling and MUST NOT be exposed as production choices. FR-ISO-003 (stronger than Kubernetes namespaces) admits no alternative today; if a future VM-class backend (e.g. Kata, Cloud Hypervisor) is adopted, it must pass the identical conformance gate with capability-declared differences only.
2. **The runtime interface exists to keep the contract honest, not to offer a menu.** Fake/local backends are *test doubles*: their value is deterministic, fast verification of control-plane semantics (epochs, idempotency, durability, chaos) that would be impractical against real VMs. Their differences from the production backend must remain capability-declared, never silent.
3. **Semantic drift is the managed risk, and the enforcement is executable.** New shared semantics land in the conformance suite first (PLAN §17 rule 2); a backend that cannot satisfy them declares a capability gap. Any difference discovered in production behavior that is not covered by a declared capability is treated as a contract bug, not a backend feature.

## Consequences

- **Capability soup is rejected.** Callers must be able to rely on the core contract unconditionally; capabilities gate only continuity/performance properties (e.g. `CheckpointReclaimsMemory`), never correctness semantics (epochs, workspace durability, ownership, isolation boundaries).
- **Supervisor implementation duplication is a recognized liability.** The guest supervisor daemon (production data plane) and the local backend's in-process supervisor are two implementations of one semantic spec; a parity defect has already occurred (review FM12). Target end-state: the guest supervisor daemon is the single supervisor implementation; the local backend runs that same daemon on the host (unconfined or bwrap-confined) rather than reimplementing it. Tracked as a high-priority follow-up in `docs/CODE-REVIEW-FC-2026-09-14.md`.
- **Docs/deployment guidance** must state that non-VM backends are not production isolation (SECURITY.md reflects this; deployment docs must not present backend choice as a production configuration knob).
