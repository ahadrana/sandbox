# Code Review — Firecracker backend & related changes — 2026-09-14 (PM)

**Scope:** all changes since docs/CODE-REVIEW-2026-09-14.md — the review-fix commits plus the entire Firecracker backend (`runtime/firecracker-backend/`, `runtime/guest-supervisor/cmd/guest-supervisor/`, wire protocol, manager CheckpointReclaimsMemory changes, conformance wiring, ADR-001).
**Method:** three parallel deep reviewers; verified against ADR-001 and INVARIANTS.
**Status legend:** [ ] open, [x] fixed (reference fixing commit)

## High severity

- [x] **FH1 — `runtime/firecracker-backend/image.go:73-95` + `agent_linux.go:353` — debugfs script injection via workspace filenames.** Manifest paths are interpolated raw into a debugfs command script; `checkWorkspacePath` blocks `..`/absolute but not newlines/whitespace. A guest (root in VM) creates a file named with `\n` via supervisor `WriteFile`; the name round-trips through `WorkspaceFiles` → workspace commit → next materialize, and the injected debugfs command runs as the host backend user (`write`/`dump` = host file read/write). Agent-reachable host injection, same class as H7 in the previous review. Fix at both layers: reject newline/whitespace/metachars in workspace paths. **Fixed:** shared `supervisor.CheckWorkspacePath` (control/whitespace/backslash rejected — debugfs tokenization verified empirically on debugfs 1.47) enforced by the guest agent and the host image builder independently; regression tests `TestCheckWorkspacePathStrict`, `TestBuildWorkspaceImageRejectsMetachars`, `TestWorkspaceInjectionRoundTrip`.

## Medium severity

- [ ] **FM1 — `net.go:245` — no cross-VM/anti-spoofing isolation.** Egress chain matches only `-i <tap>` + destination; with DefaultAllow, guest A reaches guest B's /30 IP and host tap IPs directly (cross-tenant VM-to-VM). No `-s <guestIP>` source filter → guest (root) can spoof source IPs. Need a rule dropping tap-ingress to 192.168.0.0/16 (except own host IP) + source filter.
- [ ] **FM2 — `net.go` — IPv4-only enforcement.** No ip6tables chain; guest root can bring up IPv6 (link-local/ULA) and reach host services or IPv6 metadata endpoints (`fd00:ec2::254`) bypassing all policy. Disable IPv6 in-guest or mirror chains in ip6tables.
- [ ] **FM3 — `net.go:41-63,198` — hash-derived TAP/IP/chain names collide.** FNV32 % 8192 /30s: ~50% collision at ~110 live incarnations. On collision `setupNetworking` deletes the *other* VM's TAP ("delete leftover first"), breaking a running VM. Detect live collision and error, or use a unique counter.
- [ ] **FM4 — `net.go:146-179` — hostname policy resolved once at setup.** DNS rebinding TOCTOU between LookupIP and rule install; stale allow/deny entries. Document or re-resolve periodically.
- [ ] **FM5 — `backend.go:895` vs `561` — `Exec` races `Snapshot` pause.** Both check `inc.paused` under lock but act after unlock; an Exec in flight during pause fails with a confusing timeout while the wsMirror update still lands (dirty-tracking skew, INV-006). Per-incarnation op lock or re-check around the vsock call.
- [ ] **FM6 — `backend.go:658` + `jail.go` — jailed `Restore` leaks old jail + `/snap` bind mount.** `Restore` resets jailRoot without unmounting; `prepareJail`'s RemoveAll fails on the mountpoint (error ignored); repeated jailed restores stack mounts. Jailed restore is also never exercised by tests.
- [ ] **FM7 — `backend.go:148,210,280` + snapshot dirs — world-readable guest memory/workspace under /tmp.** Root/incarnation dirs 0755, console.log/drives 0644, snapshot dirs (full guest RAM) 0755. Any local user reads guest memory + tenant data. Should be 0700.
- [x] **FM8 — `backend.go:209` + `jail.go:186` — `IncarnationID` never validated.** `..` escapes Root; `cleanupJail` falls back to `sudo rm -rf <base>/firecracker/<id>` — root-deletion primitive if an unsanitized ID ever arrives. Also interpolated into systemd unit (image.go:169). Whitelist `[A-Za-z0-9._-]`. **Fixed:** `validateIncarnationID` (`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` + explicit `..` rejection) at the Create/Restore boundary before any filesystem, jailer, systemd, or sudo use; regression test `TestIncarnationIDValidation` (bad IDs error, no dirs created, Restore gated too).
- [ ] **FM9 — `manager.go:1415-1422` — reclaim-class checkpoint suspend doesn't free quota.** Handle stays in `m.handles`, so quota still counts the (terminated, RAM-reclaimed) sandbox as live; `preemptableLocked` can also pick the already-suspended sandbox and the preemption loop breaks on the illegal transition, failing a placement another victim could satisfy. Needs a conformance test pinning intended semantics.
- [ ] **FM10 — `vsock.go:101` + `manager.go:1051` — blocking `Wait` has no deadline and runs under the manager mutex.** A wedged guest supervisor with a live VMM hangs WaitExecution forever → entire control plane wedged. Generous-but-finite timeout or cancel path.
- [ ] **FM11 — `backend.go:256` — no crash recovery for host plumbing.** Backend process death leaks TAPs, FC-EGR chains, MASQUERADE, jail mounts/cgroups; `New()` does no sweep of `fc-tap-*`/`FC-EGR-*`. Startup sweep needed.
- [ ] **FM12 — `agent_linux.go:111-115` — data race on trackedExec fields** (pgid/startedAt/result written after publish, read without sync by Status/baselinePGIDs). Inherited parity defect from local supervisor; standalone daemon blast radius differs.
- [x] **FM13 — `protocol.go:47,70` + `agent_linux.go:381` — binary workspace files corrupted on the wire.** Files/Content are Go strings through encoding/json → invalid UTF-8 silently replaced with U+FFFD both directions. base64 the values or enforce text-only contract. **Fixed:** `Request.Content` and `Response.Files` values are now `[]byte` (automatic base64 through encoding/json); guest agent and host vsock transport convert at the boundary (lossless). Host manifest/wsMirror stay strings — verified the only content-carrying JSON boundary was the supervisor wire (the durable workspace store persists raw blob files + digest manifests, no content JSON). Regression test `TestBinaryWorkspaceRoundTrip` (all 256 byte values + invalid UTF-8: write → WorkspaceFiles → rematerialize → guest fs size, all byte-identical).

## Low severity

- [ ] **FL1 — `agent_linux.go:353-378` — workspace path check is lexical only; symlinks escape.** A symlink in /workspace redirects WriteFile/ReadFile outside the root; `WorkspaceFiles` ships `/etc/shadow`-class content to the host manifest. O_NOFOLLOW / skip non-regular files.
- [ ] **FL2 — `agent_linux.go:175` — `Cancel` group-kills without PID/PGID-reuse recheck** (TerminateBackground has markerOwned; Cancel doesn't). Same for per-PID kill after group kill in TerminateBackground.
- [ ] **FL3 — `agent_linux.go:103` — failed `cmd.Start` leaks waiters** (exec entry deleted but `t.done` never closed → Wait blocks forever). Parity defect with local.
- [ ] **FL4 — `agent_linux.go:205` — premature EOF with background writers** (EOF when main shell exits but descendants still append to spill files). Parity; doc note at minimum.
- [ ] **FL5 — `vsock_linux.go:38` + `main.go:52` — no idle timeout on accepted vsock connections**; stalled peer leaks goroutine+fd and busy-polls vCPU; EMFILE → permanent hot error-spin.
- [ ] **FL6 — `backend.go:658-670` — failed `Snapshot` leaves VM paused + partial dir** counted toward GC (wedge class). Also stale-checkpoint ambiguity on Terminate failure in checkpointSuspendLocked (manager.go:1415).
- [ ] **FL7 — `backend.go:734` + `net.go:256` — blocking sudo/kill work under backend-wide lock** (5s VMM-exit wait, 4 sudo calls) stalls all incarnations.
- [ ] **FL8 — `backend.go:84` — `netOnce` caches transient failure forever; MASQUERADE covers all of 192.168.0.0/16** (may NAT unrelated host networks).
- [ ] **FL9 — `backend.go:906,102` — per-incarnation maps grow unboundedly** (ops, wsMirror per file version).
- [ ] **FL10 — `conformance/firecracker_test.go:87` — guest build hardcodes GOARCH=arm64** → opaque 120s timeout on x86_64 hosts. Use runtime.GOARCH.
- [ ] **FL11 — `manager.go:565` — `materializeLocked` returns on `rt.Start` error without `rt.Terminate`** (lingering incarnation record/net state). Compare startup-failure path two lines below.
- [ ] **FL12 — `net.go:255-267`, `jail.go:173-190` — teardownNetworking locking inconsistency on `inc.net`**; spawnJailed failure after prepareJail leaves jail tree.
- [ ] **FL13 — `vsock_linux.go:161` — debugDial fd leak** (debug-only).

## Verified clean

- Snapshot capture ordering (pause → drive reflink → snapshotCreate); API client timeouts/connection discipline; raw-spawn failure-path cleanup; iptables command args never shell-interpolated; egress chain ordering + INPUT hook + teardown assertions; capability honesty (CheckpointReclaimsMemory real, NetworkIsolated gated); vsock framing/accept4/SIGURG rationale; checkpointSuspendLocked happy path + honest fallback (never false continuity); conformance wiring and assertions genuinely catch regressions; no Firecracker concepts leak into backendinterface.

## Fix order (proposed)

1. FH1 (host injection), FM8 (sudo rm -rf primitive), FM13 (data corruption)
2. FM1, FM2, FM3 (isolation claims)
3. FM10, FM9 (control-plane liveness/accounting), FM5 (Exec/Snapshot race)
4. FM6, FM7, FM11, FM4, FM12
5. Lows as touched

## Follow-up queue (after the findings above are fixed)

1. **HIGH — Remove supervisor implementation duplication** (per ADR-004). Today the guest supervisor daemon (`runtime/guest-supervisor/cmd/guest-supervisor/`) and the local backend's in-process supervisor (`runtime/local-backend/supervisor.go`) are two implementations of one semantic spec; a parity defect already occurred (FM12). Target: the guest supervisor daemon is the single supervisor implementation, and the local/isolated backends run that same daemon on the host (unconfined or bwrap-confined) instead of reimplementing it. Resolves the drift class that produced FM12, FL2, FL3, FL4 by construction.
2. Upstream the aarch64 jailer `midr_el1` patch (firecracker ≤1.17 hard-fails without `CONFIG_ARM64_CPUID_REGS`); the host runs a locally-built patched jailer until then.
3. Generalize `runtime/host-agent` (currently hard-typed to `*localbackend.Backend`) so a Firecracker backend can serve a fleet host — prerequisite for the real-K8s-fleet work.
4. Soak-run the remote conformance suite to attribute or clear the one unexplained flake observed in the first FC-enabled run.
