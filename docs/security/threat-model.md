# AgentKernel Threat Model

- **Status:** design threat model with a bounded Phase 0/`A0` implementation
- **Last reviewed:** 2026-07-21
- **Applies to:** the target AgentKernel architecture and explicitly named future deployment profiles

This document defines what AgentKernel intends to protect, who or what may be adversarial, the boundaries that must enforce decisions, and the limits of those claims. Some controls now have bounded implementation evidence, but the target architecture is not complete. Current evidence and release status are tracked in the [roadmap](../../ROADMAP.md).

## Security objective

No agent proposal should produce an effect unless the runtime can establish its provenance, authenticated principal, bounded authority, deterministic policy result, execution boundary, expected state transition, and approval or recovery strategy.

This objective is narrower than “make arbitrary agents safe.” A formal policy model can establish properties only inside that model. A sandbox reduces effects only within measured controls. Replay covers only captured or virtualized nondeterminism.

## Protected assets

- user, organization, project, and tenant data;
- credentials, signing keys, secret-broker material, and approval identities;
- host filesystems, processes, devices, network identity, and cloud metadata;
- authoritative databases, repositories, communication systems, and external services;
- capability grants, revocations, policy bundles, adapter manifests, and configuration;
- transaction/action journals, idempotency records, receipts, and audit evidence;
- hidden benchmark tests, task labels, fault schedules, and submission infrastructure; and
- package, image, model, and dataset supply chains.

## Adversaries and failures in scope

- malicious instructions embedded in repositories, pages, email, documents, database content, tool descriptions, tool output, or memory;
- a compromised, adversarial, or simply incorrect model/agent;
- malicious model-generated code inside a declared sandbox;
- accidental defects in reviewed adapters or verifiers;
- a compromised execution worker attempting to expand its role;
- an unauthorized user or tenant guessing object identifiers;
- malicious benchmark submissions and poisoned fixtures; and
- supply-chain modification of dependencies, images, policies, adapters, models, datasets, or release artifacts.

Reliability failures are also security-relevant: timeouts after an external effect, duplicate delivery, stale state, partial commit, failed rollback, evidence-store outage, solver exhaustion, and crash recovery can all produce unauthorized or misreported outcomes.

## Trust boundaries and assumptions

### Trusted computing base

The intended initial trusted computing base includes schema validation, normalization, provenance and authority checks, policy evaluation, the transaction coordinator/journal, admitted adapters and their host boundary, the model gateway and secret broker, approval validation, evidence integrity logic, and sandbox configuration/launcher.

Reviewed adapters are part of the trusted computing base because they interpret plans and may hold short-lived credentials. A signature authenticates an adapter digest; it does not prove benign behavior. The base threat model does **not** claim resistance to a deliberately malicious adapter already reviewed and admitted.

### Untrusted components

Model output, generated code, external/project content, general tool output, third-party frameworks/plugins, code inside a sandbox, benchmark payloads, remote-service responses, and TraceWorld predictions are untrusted by default.

### Platform assumptions

- The Linux host kernel and the control-plane administrator are trusted in the base profile.
- Cryptographic primitives and protected key stores behave according to their documented contracts.
- The authenticated identity provider correctly establishes principal identity in profiles that depend on it.
- Stronger resistance to a hostile host, cloud administrator, or admitted malicious adapter requires a separately documented deployment profile.
- Windows/macOS development and mock backends are not assumed to provide the Linux reference isolation controls.

## Security invariants

1. Every action has an authenticated actor, on-behalf-of principal, goal, and typed adapter operation.
2. Effective access is no broader than the intersection of the complete capability chain.
3. Untrusted data cannot grant or expand authority.
4. Deterministic denial cannot be overridden by an agent or learned score.
5. In a supported `A1+` profile, the agent has no ambient filesystem, process, network, device, provider, or credential path outside the Kernel API.
6. External model inference is policy-checked data egress through the model gateway; credentials are brokered, not given to the agent.
7. Every `R1+` authoritative effect has a durable journal and commit intent before dispatch.
8. `R3` effects require explicit authority and approval unless narrowly preauthorized by policy.
9. Execution workers cannot mutate policy, capabilities, approvals, transaction decisions, or prior evidence.
10. Stage/isolated execute cannot mutate the authoritative target for an adapter claiming staged semantics.
11. Secrets do not enter model context, general logs, metrics labels, events, or replay exports by default.
12. Unknown verification is not success; an ambiguous external result blocks duplicate dispatch.
13. Replay cannot repeat an authoritative external effect without a new proposal and fresh authority.
14. Cross-tenant references fail even when identifiers are known.
15. Audit evidence survives task-state rollback.

## Threat analysis

| Threat | Intended defenses | Residual risk / required evidence |
| --- | --- | --- |
| Indirect prompt injection expands scope | Provenance labels; authority is distinct from content; capability and deterministic policy checks before access | Coarse provenance may over/under-classify; negative canary tests must prove no protected read or egress |
| Agent bypasses SDK with raw APIs | Confined harness; OS filesystem/process/device rules; default-deny network; only authenticated Kernel API route | SDK wrappers alone provide `A0`; syscall/FFI/socket/provider bypass suites are required for `A1+` |
| Capability forgery or confused deputy | Signed/opaque grants bound to issuer, subject, audience, goal, run, action, resource, time, use budget, and delegation chain | Key compromise and incorrect resource normalization remain critical; property and rotation/revocation tests required |
| Policy conflict, omission, or solver failure | Deny dominance; non-granting obligations; intersected constraints; typed bounded IR; fail closed on unknown/timeout | A correct solver cannot repair an incomplete real-world model; adapters and independent invariants remain necessary |
| Adapter omits or mislabels an effect | Typed manifest; risk floor; admitted digest; stage/commit conformance; independent state/security verifiers | Accidental omissions may remain; deliberately malicious admitted adapters are outside the base claim |
| TOCTOU between staging and commit | Version/ETag/hash guards plus authority, policy, approval, idempotency, and adapter-digest revalidation | Targets without version/reconciliation support cannot receive a strong automatic-promotion claim |
| Timeout after external effect causes duplicate | Durable intent reservation; pre-dispatch journal; target idempotency key; reconciliation; `IN_DOUBT` | Exactly-once is only intent handling unless the target provides equivalent semantics |
| Partial failure corrupts state | Snapshot or saga semantics; durable per-action receipts; reverse dependency recovery; verification and quarantine | Cross-system atomic rollback is not claimed; compensation may leave observable residual effects |
| Sandbox escape or unsafe configuration | Non-root, minimal mounts, dropped capabilities, seccomp/LSM, resource limits, no network, effective-control inspection, stronger backends for hostile work | Containers are not a hostile multi-tenant boundary; host-kernel compromise is out of base scope |
| Secret disclosure | Secret broker; purpose/destination-scoped short-lived credentials; prompt/data classification; redaction and export scans | Redaction is incomplete by nature; avoid collecting plaintext and use synthetic canaries |
| Evidence mutation, reordering, or deletion | Canonical event hashing, sequence, hash chain, signatures/checkpoints outside worker authority | Hash chains do not detect deletion of the newest uncheckpointed suffix; independent checkpoints are needed |
| Replay repeats a real effect | Default no-egress/non-authoritative replay; recorded receipts supplied instead of redispatch | Operator misuse requires explicit command separation, fresh authority, and negative integration tests |
| Cross-tenant data access | Tenant identity on every access path; service-side authorization; scoped stores/caches/telemetry | Misconfiguration across layers can leak data; full negative matrix required before team-server claims |
| Supply-chain compromise | Lockfiles, digest pinning, protected release CI, SBOM, signatures/provenance, isolated untrusted PRs | Scanner output is triage, not proof; build keys and maintainers remain high-value targets |
| Denial of service | Size/depth/rate budgets; bounded solver; sandbox quotas; deadlines/cancellation; bounded logs/artifacts/replay | Availability during coordinated resource exhaustion depends on deployment capacity and admission policy |
| TraceWorld is overtrusted | Advisory-only default; cannot create authority or override denial; calibration/OOD gates before restricted use | Distribution shift and false negatives persist; deterministic controls remain the foundation |

## Data and privacy threats

Replayability must not justify recording secrets or uncontrolled production data. Event and dataset pipelines should minimize content, use artifact references, separate raw and release tiers, encrypt access-controlled material, apply configurable retention, pseudonymize identifiers, scan exports, and preserve a deletion/lineage workflow.

External model calls transmit prompt parts, retrieved content, schemas, images, tool output, and metadata. That disclosure is irreversible. Provider retention, training, and residency declarations are policy inputs based on configuration/contracts; AgentKernel cannot independently prove them. Data requiring stronger guarantees must remain in an approved local inference boundary.

## Abuse prevention

Public examples and benchmark fixtures must use synthetic credentials, non-routable endpoints, local mail sinks, deterministic local sites, and disposable environments. The project should not ship instructions or adapters designed for credential theft, stealth, persistence, malware delivery, mass unsolicited messaging, autonomous financial transfer, surveillance, or destructive real-world automation.

## Explicit exclusions from the base claim

- universal correctness or safety of an autonomous agent;
- defense against a fully compromised host kernel or control-plane administrator;
- defense against a deliberately malicious adapter already admitted to the trusted computing base;
- faithful simulation of every external system;
- exactly-once external execution without target idempotency/reconciliation;
- rollback of disclosure, sent communication, publication, payment, or another irreversible effect;
- deterministic replay of uncaptured time, randomness, network behavior, hardware, or live model output; and
- production tenant isolation before its complete deployment evidence passes.

## Current gap register

The runtime now demonstrates an `A0` filesystem path and separately verifies named Docker controls. No claim should be made yet for:

- `A1+` enforcement or ambient-path confinement;
- an integrated hostile-agent Docker/OCI profile or sandbox escape resistance;
- external model dispatch, which is hard-disabled until durable intent and reconciliation exist;
- recovery guarantees outside the supported filesystem adapter boundary;
- provider credential brokering or prompt-egress enforcement;
- replay beyond whatever a specific test explicitly demonstrates;
- multi-tenant isolation, signed release artifacts, or production operations; or
- TraceWorld accuracy, calibration, or safety impact.

These are release-gated roadmap items, not hidden assumptions.

## Review triggers

Review and version this threat model when a new effect domain, adapter, sandbox backend, deployment mode, identity provider, policy semantic, cryptographic primitive, external model provider, dataset source, or assurance claim is introduced; after a material incident; and before each capability-gated release.

Material changes require an ADR, positive and negative tests, a compatibility assessment, and independent security review when the affected boundary is high risk. Vulnerabilities should be reported through [SECURITY.md](../../SECURITY.md).
