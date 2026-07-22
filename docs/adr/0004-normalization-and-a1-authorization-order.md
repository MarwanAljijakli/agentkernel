# ADR-0004: Pure normalization before A1 authorization and target inspection

- **Status:** Accepted
- **Date:** 2026-07-22
- **Deciders:** Project maintainer and implementation task authority
- **Consulted:** AgentKernel specification Sections 10, 11.1, 11.3, 12, 13, and 35;
  current coordinator, authority, policy, adapter, and SQLite implementations
- **Supersedes:** None
- **Superseded by:** None
- **Related acceptance criteria:** `AK-002`, `AK-003`, `AK-006`, `AK-009`,
  `AK-025`, `AK-034`, `AK-040`, `AK-042`, `AK-069`, `AK-071`, `AK-073`, and
  `AK-074`

## Context and problem statement

The Phase 0 embedded coordinator calls `adapter.inspect()` while the transaction is still
`NEW`, then stores the adapter-produced intent before transitioning to `PLANNED` and
unconditionally authorizing staging. That is truthful for the current `A0` development
slice, but it cannot become the `A1` flow unchanged.

An adapter's inspection is required to be side-effect-free, but it may still read an
authoritative target to calculate preconditions or a base version. The filesystem adapter,
for example, snapshots the workspace during inspection. Reading a target before checking
authority would violate “reject before the file is opened” and could disclose resource
existence or contents. Conversely, authority and policy need canonical operation/resource,
risk, provenance, and data-class facts before they can decide.

The current coarse authority service also consumes a capability use whenever `check()`
succeeds. Reusing that method for both staging authorization and mandatory pre-commit
revalidation would consume the budget twice and make retry behavior dependent on how many
internal checks happened rather than how many authorized intents were dispatched.

## Decision drivers

- no unauthorized target read merely to decide whether access is allowed;
- one canonical intent identity independent of mutable target state;
- authority, policy, provenance, and adapter admission evidence before worker dispatch;
- exact resource checks for multi-resource actions;
- idempotent, atomic capability-use accounting across retries and restarts;
- mandatory revalidation immediately before authoritative commit without double charging;
- preservation of the normative transaction state machine; and
- a clear boundary between trusted normalization and adapter precondition inspection.

## Decision

### Introduce a pure normalized action

The control plane introduces an immutable, versioned `NormalizedAction` contract. It is
derived only from:

- the strict action proposal;
- the admitted adapter manifest and operation schema;
- deployment configuration that maps logical adapter resources to canonical URI roots;
- trusted provenance records referenced by the proposal; and
- the authenticated goal, actor, principal, run, and tenant context.

Normalization must not open the target, follow attacker-controlled links, resolve a live
network destination, query a database row, or execute adapter code that can perform I/O.
Operation-specific pure normalizers are admitted with the adapter manifest and are covered
by the same digest/admission policy. They produce at least:

- adapter, adapter protocol version/digest, and operation;
- a bounded tuple of typed resource uses, each containing authority action, access mode,
  canonical resource, data scope, purpose, and whether the use is an authoritative effect,
  precondition read, verifier read, process execution, or egress;
- every explicit and implied resource affected or read, not only a common parent;
- normalized semantic arguments;
- risk floor and declared effect domains;
- provenance IDs/trust and inherited data classes;
- destination/purpose facts known without I/O;
- mandatory tenant, principal, goal, run, and agent bindings; and
- a canonical `intent_hash` that excludes mutable target versions and display metadata.

For a multi-file operation, every path becomes a separately checkable canonical resource.
A common workspace resource may be included for policy aggregation, but it cannot replace
per-resource authority checks. A write grant never implies authority to read or hash a
larger tree: snapshot, precondition, verifier, dependency, redirect, and derived-payload
reads are independent typed uses that must be normalized and authorized before inspection.

### A1 ordering

The enforced transaction path is:

1. perform only bounded ingress work needed to authenticate the channel, enforce request
   size/nesting limits, and safely extract run/transaction identity. If even a safe identity
   cannot be extracted, append a minimal redacted run-level ingress-rejection event and do
   not dispatch anything;
2. create the durable `NEW` transaction before validating deadline, adapter/version,
   operation schema, provenance references, manifest/normalizer digests, or semantic
   arguments;
3. pure-normalize and validate while the record remains `NEW`. Schema, semantic,
   provenance, or admission failure transitions `NEW -> REJECTED` with a stable reason and
   no adapter call. Cancellation, deadline expiry, or context exit is not a validation
   failure: it transitions `NEW -> ABORTING`, persists intended outcome `ABORTED`, records
   that no adapter ran, and completes through verified discard/no-effect handling;
4. atomically resolve the durable intent reservation according to the duplicate table
   below. A winning/new owner stores the `NormalizedAction` and intent and transitions
   `NEW -> PLANNED`; a losing alias stores the owner/outcome link and transitions directly
   `NEW -> REJECTED` without ever becoming eligible for authorization or dispatch;
5. evaluate the complete capability chain for every typed resource use and data scope;
6. evaluate and aggregate every applicable deterministic policy bundle;
7. durably append redacted authority/policy decisions and pin tenant, capability, policy,
   adapter, normalizer, configuration, and provenance digests;
8. on deny, unknown, missing evidence, or invalid provenance, transition only
   `PLANNED -> REJECTED`; do not call adapter inspection or acquire a worker lease;
9. on eligibility, persist obligations and transition to `AUTHORIZED_TO_STAGE`;
10. acquire a fenced worker lease and transition to `STAGING` before the first authorized
    `adapter.inspect()` call. Inspection may read only the pre-authorized typed uses and
    returns target guards/base versions without changing the normalized intent;
11. if inspection, staging, or isolated execution fails with no authoritative effect,
    use the legal `STAGING -> ABORTING` path, fence the worker, discard partial staging,
    verify the boundary, and finish `ABORTED` or `RECOVERY_FAILED`;
12. on success persist the staged receipt and transition `STAGING -> STAGED`; run the
    independent staged verifier, then transition to `STAGE_VERIFIED` only on `PASS`;
    `FAIL`, `UNKNOWN`, `ERROR`, cancellation, deadline, or context exit uses the normative
    abort path;
13. from `STAGE_VERIFIED`, create and validate any approval bound to the exact intent/diff
    through `AWAITING_APPROVAL`, or record no-approval-required, reaching
    `READY_TO_COMMIT` only through the normative transitions;
14. immediately before commit, revalidate the complete capability chain and every typed
    use, policies, bound approval, adapter/normalizer/configuration digests, intent owner,
    tenant binding, deadline, and target versions. A failure uses `ABORTING`; target drift
    produces the intended `STALE_STATE` outcome; and
15. atomically persist the durable dispatch material, fencing token, idempotency record,
    and `COMMITTING` transition before the adapter receives commit authority. Receipt and
    committed verification then select only the normative `COMMITTED`, `FAILED`, or
    `IN_DOUBT` paths and their required recovery/reconciliation flows.

If inspection reports a typed use, effect domain, resource, or risk below/absent from the
authorized normalized action, it is an integrity failure while in `STAGING`, followed by
the legal abort/discard path and a security event. The adapter cannot change `intent_hash`,
risk floor, or effect-domain facts after authorization.

### Duplicate intent dispositions

Reservation and owner lookup are one compare-and-swap operation. A different transaction
that loses reservation is a no-dispatch alias: it stores the owner/outcome reference and
terminates through the existing `NEW -> REJECTED` validation path with a stable
`DUPLICATE_INTENT` reason; the API returns the authoritative owner's status/outcome rather
than presenting the alias as a new effect. The disposition is:

| Existing owner | New submission behavior | Dispatch/use accounting |
| --- | --- | --- |
| active pre-commit | Link to owner and return its current status | no second dispatch or use |
| `IN_DOUBT`/`RECONCILING` | Link to owner and require its reconciliation | original intent is never resent |
| `COMMITTED` | Link to the immutable receipt and return the same outcome | no second dispatch or use |
| no-effect terminal (`REJECTED`, `ABORTED`, `STALE_STATE`) with no receipt | CAS-transfer ownership to a new transaction linked to the prior attempt | reuse the same intent-use reservation; revalidate current authority |
| recovery terminal or inconsistent/receipt-bearing state | Fail closed with integrity/review evidence | no dispatch |

An exact retry of an already-known transaction ID first verifies its stored request/intent
identity and returns that transaction; conflicting reuse of the ID is an integrity error.
Cross-transaction, concurrent, and post-restart tests must exercise every row.

### Capability-use accounting

Capability evaluation and capability-use reservation are separate operations:

- evaluation is pure and may run repeatedly for commit revalidation;
- the first authorized dispatch atomically reserves/consumes one use at every node of the
  effective delegation chain under an immutable key containing tenant, capability ID,
  bound goal/run, and `intent_hash`; transaction IDs and mutable target versions are not
  part of the charging identity;
- retrying or revalidating the same key returns the existing reservation and never consumes
  another use;
- a different intent/action consumes a new use only if the effective budget permits it;
- single-use nonces and global/multi-use ceilings are enforced in the same database
  transaction as the reservation; and
- revocation, expiry, wrong bindings, or a reduced effective chain still deny pre-commit
  dispatch even when an earlier stage reservation exists.

Release 0.1 may use a coarse grant model, but its reservation semantics must already be
durable and idempotent. Signed delegation-chain verification extends this contract in
Release 0.3 rather than replacing it.

### A0 compatibility

Embedded `A0` may retain an explicit development-only composition that invokes inspection
without enforcement, but it must report that limitation and cannot pass an
`enforcement_profile` flag. The public `A1+` API does not silently fall back to this path.

## Considered options

### Call `adapter.inspect()` before authority because it is read-only

Rejected. Read access is itself authority-sensitive, and inspection can reveal or hash a
protected target. “No effect” is not equivalent to “authorized read.”

### Put a caller-supplied canonical resource directly in the proposal

Rejected as the authority source. A proposal may carry a hint, but model-controlled text
cannot decide its own resource identity. The trusted operation normalizer derives and
validates canonical resources from typed arguments and deployment configuration.

### Consume a capability on every validation call

Rejected. It double-charges staging plus commit, is not idempotent across crashes, and can
turn internal retry timing into an authorization decision.

### Include target version in `intent_hash`

Rejected. Target version is a commit guard and precondition. Including it would make a stale
replan appear to be a different semantic intent and weaken duplicate-effect detection.

## Consequences

### Positive

- `AK-002` can prove rejection before adapter target access.
- Authority and policy see exact multi-resource effects before staging.
- Target drift remains a separate `STALE_STATE` guard rather than changing intent identity.
- Pre-commit revalidation is safe, repeatable, and does not consume extra budget.
- Adapter omissions or post-authorization effect expansion become explicit integrity errors.

### Negative and trade-offs

- Each effect operation needs a reviewed pure normalizer in addition to adapter lifecycle
  code.
- Existing adapter plans and coordinator construction must change during pre-alpha.
- Some targets, especially networks, require two phases: authorize canonical destination
  constraints first, then resolve/connect under a broker that rechecks the live address.
- Coarse workspace-wide actions may generate many canonical resource checks; limits and
  bounded collections are required.

## Security impact

This order prevents unauthorized read-before-check behavior, model-supplied resource
identity, adapter effect expansion after authorization, capability budget double-spending,
and retry-dependent authorization. Pure normalization joins the trusted computing base and
requires digest admission, size/depth limits, fuzzing, and path/Unicode/encoding tests.

## Data and privacy impact

The normalized record contains resource identities, labels, and content digests only when
needed. It must not copy secret content into events. Provenance and data classes come from a
trusted store; missing records fail closed. Network hostname resolution and provider prompt
transmission occur only after policy permits their declared destination/data class.

## Compatibility and migration

`NormalizedAction`, capability-use reservations, and persisted authorization material add
new pre-v1alpha contracts and a SQLite migration. Existing Phase 0 records remain readable
as `A0` history but cannot be upgraded retrospectively to `A1`. The migration is forward
tested and rollback-documented before a prerelease. Tenant identity is mandatory on every
new normalized action, intent/alias, decision, capability-use reservation, receipt, and
production access path; a deployment-scoped local tenant is still explicit rather than
implicit. Cross-tenant lookup or deduplication is forbidden.

## Operational impact

Recovery scanners can reconstruct the authorized normalized intent without re-reading
untrusted proposal text or consuming authority again. Diagnostics expose stable reason
codes and digests, while redacting arguments and resource details according to policy.

## Required validation evidence (not yet completed)

The following are release requirements, not evidence that already exists at the audit
baseline:

- An instrumented adapter proves `inspect()` is never called on validation, authority,
  policy, provenance, or admission denial.
- Property/security tests cover traversal, symlink/junction, case/Unicode, multi-resource
  scope, manifest/normalizer mismatch, and effect expansion.
- Capability reservation tests survive SQLite reopen and prove one use for repeated
  evaluation/retry of the same action, while distinct actions respect the maximum.
- Duplicate-owner tests cover active, committed, in-doubt, no-effect transfer, concurrent,
  cross-transaction, cross-tenant, and restart cases without duplicate dispatch or charging.
- Commit tests revoke/expire/narrow authority after staging and prove abort before
  authoritative dispatch.
- State traces contain `PLANNED` plus exact decision/pinned-digest evidence before
  `AUTHORIZED_TO_STAGE`.

## Rollout and rollback

Introduce the normalized contract and persistence behind the pre-alpha API, migrate the
mock and filesystem operations, then enable A1 tests. Keep A0 explicit until the entire
composition passes. If rollout fails, revert the prerelease commit and database copy; do
not interpret partially migrated records as A1 evidence.

## Revisit triggers

- an adapter cannot express its resources/effects without live target access;
- resource-set size exceeds bounded decision budgets;
- network, database, or browser adapters require a richer two-phase canonical identity;
- signed delegation/tenant policy in Release 0.3 changes reservation semantics; or
- cross-language normalizers need a new canonical profile.

## References

- [ADR-0001: Canonical JSON](0001-canonical-json.md)
- [ADR-0003: Specification interpretation and release gates](0003-specification-interpretation-and-release-gates.md)
- [Architecture](../architecture.md)
- [Threat model](../security/threat-model.md)
