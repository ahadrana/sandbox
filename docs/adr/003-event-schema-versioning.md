# ADR-0003: Event and state schema versioning

- **Status:** accepted
- **Date:** 2026-09-13
- **Deciders:** platform team

## Context

Events are durable and replayed by consumers that may lag or reconnect
after upgrades. Schema changes must not break stored history or active
consumers (PLAN §17 rule 10, FR-AV-003).

## Decision

1. **`schema_version` semantics.** Every event carries `schema_version`
   (currently `1`). The version identifies the envelope+payload contract a
   consumer needs to interpret the event. It increments only on
   **breaking** changes.
2. **Additive-only changes.** Within a schema version, changes are
   additive: new event types, new payload keys, new enum values at the end
   of an enumeration. Existing keys keep their names, types, and meanings.
   Payloads are maps; consumers MUST ignore unknown keys and tolerate
   missing optional keys.
3. **Breaking changes require a version bump and dual-read.** Removing or
   reinterpreting a key, changing a type, or renaming an event type
   increments `schema_version`. During a transition the platform writes the
   new version and consumers read both; old events are never rewritten.
4. **Consumer compatibility rules.** A consumer must: dedup by
   `event_id`; order by `(aggregate_id, aggregate_version)`, not arrival
   time; skip events with a higher `schema_version` than it supports and
   surface that gap explicitly rather than silently misinterpreting.
5. **State-machine enums are append-only.** Sandbox/execution/endpoint
   states may gain new members; existing members never change meaning.
   Persisted states from older versions remain valid input to the state
   machine guards.

## Consequences

- The conformance suite's replay/dedup tests (consumer outage, duplicate
  delivery, control-plane restart) pin these rules.
- Bulk payloads (stdout/stderr) are never embedded in events — references
  only — so payload schemas stay small and stable.
