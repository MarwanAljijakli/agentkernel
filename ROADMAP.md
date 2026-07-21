# AgentKernel Roadmap

AgentKernel is developed through **evidence-gated capabilities**, not calendar promises. A phase is complete only when its observable exit conditions have retained test or review evidence. Code presence alone is not completion.

## Status legend

- **Active:** the current bounded development phase.
- **Planned:** accepted direction, not yet a verified public capability.
- **Exploratory:** research or design work that may change.
- **Released:** all named gates passed with published evidence. No milestone has this status yet.

## Current milestone: Phase 0 foundations + bounded 0.1 vertical slice

**Status: Active / pre-alpha**

Objective: establish the public contracts and repository discipline, then prove one bounded filesystem transaction path before widening the trusted computing base.

Phase 0 scope:

- project charter, threat model, assurance language, governance, contribution, and security policies;
- Python 3.12 package and quality-tooling foundation;
- strict, versioned schemas for core records;
- normative transaction states and generated transition/property tests;
- adapter lifecycle contract with explicit staging and authoritative commit;
- deterministic canonical JSON and SHA-256 content identity;
- append-only evidence and artifact-store interfaces;
- local SQLite metadata/journal foundation;
- stable error taxonomy and CLI skeleton; and
- architecture dependency tests.

Exit evidence required:

- deterministic schema round trips;
- rejection of illegal state transitions;
- detection of event-chain tampering;
- clean Linux CI from a fresh checkout; and
- proof that the implemented effectful adapter cannot execute outside the declared protocol in the supported path.

The current developer quick start exercises an `A0` no-key filesystem transaction and deterministic replay. A separate command verifies named Docker container controls. Neither demonstrates a confined autonomous agent, an integrated `A1+`/`A2` profile, or production readiness.

## Release 0.1 — killer core and no-key demonstration

**Status: In progress — filesystem vertical slice and Docker control probe implemented**

Objective: demonstrate transactional filesystem work and indirect-injection blocking locally without a paid model API.

Implemented in the bounded slice: transactional filesystem staging/commit/abort/rollback, coarse authority and provenance checks, deterministic policy, a scripted local model gateway with external dispatch hard-disabled, an inspectable network-denied Docker backend, hash-chained events, and an `L2` scripted replay. Still required for the `0.1` gate: durable external-inference intent/reconciliation before any external provider is enabled, a confined hostile-agent harness, allowlisted process adapter, integrated containment profile, fault schedules, and a small audited filesystem/coding benchmark.

The gate requires clean-environment proof that ambient bypass attempts are blocked, synthetic credential and model-egress canaries do not escape, failed staged work restores the declared state, and the supported demo reaches its declared replay level. Container isolation will be described as container isolation—not as a hostile multi-tenant guarantee.

## Release 0.2 — reliability laboratory

**Status: Planned**

Objective: support heterogeneous tools and reproducible reliability experiments.

Planned work includes Git, database, HTTP, email-sink, browser, and process adapters; deterministic network fixtures; generalized fault schedules; objective benchmark grading; durable saga action journals; reconciliation-before-recovery; PostgreSQL/S3-compatible backends; OpenTelemetry; and a deliberately small set of framework integrations.

The gate requires deterministic fault selection for scripted lanes, no duplicate timeout-after-send effect, truthful recovery or unrecovered state, correct `IN_DOUBT` saga ordering, equal-budget baselines, and reproducible reports with denominators and uncertainty.

## Release 0.3 — formal authority and policy analysis

**Status: Planned**

Objective: make authority and deterministic policy expressive, analyzable, explainable, and fail-closed.

Planned work includes signed, attenuating capabilities; revocation and delegation; provenance and information-flow labels; typed policy IR; Z3 constraint lowering; counterexamples and bounded solver behavior; bound approvals; adapter admission/digests; expanded authority-confusion tests; and an independent security review.

The gate requires property-based non-expansion evidence, denial on solver `unknown`/timeout in the default profile, bypass suites, approval invalidation after material changes, exact rule/fact explanations, and remediation of all release-blocking review findings.

## Release 0.4 — TraceWorld dataset and baselines

**Status: Exploratory / planned after runtime evidence**

Objective: publish a defensible trajectory dataset and simple-to-complex research baselines.

Data lineage, rights, redaction, group-disjoint splits, clean controls, causal-label rules, objective benchmark tasks, and leakage tests must exist before scale-up or model training. TraceWorld remains advisory and cannot grant authority or override policy.

The gate requires validated schemas and artifact references, audited redaction, split checksums, reproducible primary tables, prospective leakage tests, calibrated metrics, OOD evaluation, ablations, and model cards with explicit non-use.

## Release 1.0 — stable platform and research release

**Status: Planned; not available**

Objective: a stable runtime, benchmark, and research release suitable for external adoption under documented deployment profiles.

The gate includes stable API/schema compatibility, tested upgrade/rollback and disaster recovery, tenant isolation, signed and checksummed artifacts with SBOM/provenance, hidden evaluation governance, operational monitoring, incident-response exercises, independent security assessment, and no unresolved critical or high findings.

`v1` will not be declared because a package builds, a demo works once, or a target date arrives.

## Dependency order

Work should normally progress in this order; deviations require an ADR:

1. Schemas and domain invariants.
2. State machine and adapter protocol.
3. Durable journal and evidence ledger.
4. Mock adapter and commit-boundary contracts.
5. Filesystem staging, verification, commit, and recovery.
6. Deterministic authority and policy.
7. Confined harness, sandbox launcher, and process adapter.
8. Model gateway and egress checks.
9. No-key demo, CLI inspection, replay, and fault injection.
10. Benchmarks and additional adapters.
11. Z3/fine-grained authority and distributed services.
12. Dataset generation, then TraceWorld models.

## How status changes

A roadmap update that advances a capability must link the exact test, CI artifact, security review, reproducibility bundle, or release artifact that proves the gate. Regressions may move a capability backward. Claims in the README and release notes must be updated in the same change.
