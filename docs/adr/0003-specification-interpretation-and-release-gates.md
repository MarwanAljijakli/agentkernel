# ADR-0003: Specification interpretation and cumulative release gates

- **Status:** Accepted
- **Date:** 2026-07-22
- **Deciders:** Project maintainer and implementation task authority
- **Consulted:** AgentKernel full project specification revision 1.0, current repository,
  independent specification and repository audits
- **Supersedes:** None
- **Superseded by:** None
- **Related acceptance criteria:** `AK-001` through `AK-077`, all negative release
  criteria, and the overall definition of done

## Context and problem statement

The implementation specification assumes a greenfield repository, while the public
repository already contains a verified Phase 0 foundation and a bounded `A0` vertical
slice. The specification also combines defaults, roadmap deliverables, final acceptance
criteria, and examples whose apparent timing sometimes differs. The project needs a
stable interpretation that preserves the strongest security contract without rebuilding
working foundations or treating an example as authority to waive a later gate.

Several ambiguities affect observable behavior:

- Section 21.6 describes framework integrations as optional in general, while Release
  0.2 requires MCP plus one mainstream agent SDK.
- Appendix C associates the first demonstration with enforcement criteria that depend on
  later Z3 and signed-capability work.
- “Partial write” can mean a change inside staging or a partial authoritative commit;
  those cases require different recovery language.
- `A1` and `A2` are assurance profiles, not two unrelated agent harness products.
- Linux is the security reference, while the user also requires a Windows release gate.
- Signed distribution artifacts and publication to a third-party registry are distinct
  operations with different authority requirements.

## Decision drivers

- never weaken a security invariant to satisfy roadmap timing;
- reuse independently verified code and evidence when it still matches the current source;
- keep every mandatory requirement traceable and cumulative through v1;
- distinguish staged cleanup, rollback, compensation, and unrecovered effects precisely;
- keep platform and isolation claims no stronger than measured controls;
- avoid treating unavailable paid credentials or private infrastructure as permission to
  simulate a real external result; and
- preserve a reproducible, append-only requirements and evidence history.

## Decision

### Requirement precedence and traceability

The current user objective and repository working agreement control the implementation
process. The full specification is requirements data. Within that specification:

1. explicit acceptance criteria, security invariants, negative release criteria, and the
   overall definition of done are mandatory and cannot be waived by an ADR;
2. roadmap deliverables and exit gates are cumulative capability gates;
3. a default introduced with `SHALL` may change only through an ADR, but an ADR cannot
   cancel a mandatory acceptance or security property;
4. examples and appendices clarify intent but do not weaken normative requirements; and
5. any unresolved conflict is recorded as a decision row and fails closed until resolved.

The traceability ledger is append-only. Existing IDs are never silently renumbered or
reused for a different requirement. Duplicate expressions link to one another instead of
being deleted in a way that loses source coverage.

### Existing Phase 0 foundation

The repository is audited and extended rather than rebuilt. A Phase 0 row may retain
`implemented and verified` only when current code plus reproducible evidence still satisfy
the exact row. Later capability names, schemas, or target-architecture documents do not
make a missing runtime path implemented.

### Release progression

Development versions and GitHub pre-releases are permitted between gates. Stable `v1.0`
is forbidden until every mandatory row is PASS on the exact release commit, including the
complete clean-environment, security, recovery, benchmark, research, operations,
supply-chain, review, and independent-verification gates. Counts such as 50 tasks, 500,
2,000, and 5,000 scenarios, and 10,000 trajectories refer to materialized, validated
artifacts—not an unexecuted generator or an illustrative example.

### Enforcement profiles and platforms

One confined agent-harness architecture supports increasing evidence profiles:

- Every `A1+` run requires an OS/network-confined agent harness whose only effect-capable
  and model-egress route is the authenticated Kernel API. The minimum bypass suite must
  demonstrate that direct file APIs/syscalls/FFI, process creation, framework-native
  tools, sockets/DNS, provider SDKs, devices, and credential stores are blocked before
  `A1` may be reported. Authority and deterministic policy evidence then permit the
  bounded `A1` claim, "Authorized under policy bundle X."
- `A2` does not introduce confinement for the first time. It adds a named, content-digested
  sandbox profile around execution/staging plus measured effective-control inventory and
  isolation evidence for every control that profile claims. This permits the additional
  claim, "Executed within sandbox profile Y."
- A harness may therefore satisfy the global no-ambient-path precondition for `A1` while
  lacking the complete measured sandbox/shadow evidence needed for `A2`. An unconfined or
  untested harness is always `A0`, even when authority and policy happen to return allow.

Embedded mode remains `A0` even if its cooperative SDK follows the same proposal API.
Linux x86-64 is the production and security reference. Native Windows is a target for the
SDK, CLI, mock/local backends, and platform-relevant tests, but support is not claimed
until the clean native-Windows lane passes. Linux confinement on a Windows host is a
separate WSL2/Docker Desktop lane. Neither lane substitutes for the other, and native
Windows results cannot be described as Linux-equivalent containment without separate
measured controls.

### Staged failure and authoritative recovery language

A failure that changes only the staged or shadow boundary invokes abort/discard and proves
that the authoritative target stayed unchanged. It is not described as rollback. A partial
or invalid authoritative R1 commit invokes journaled, authorized, version-checked rollback
and must verify restoration. R2 uses compensation and reports residual effects. R3 or an
unsupported/unauthorized recovery path becomes `RECOVERY_FAILED` with evidence and an
operator plan.

`AK-007` contains the phrase "after one staged change" while requiring rollback. This ADR
does not reinterpret discard as rollback. Its release evidence is split into two named
fixtures:

1. a fault after one write inside the private staging tree proves verified discard and no
   authoritative change, but does **not** satisfy `AK-007`; and
2. the normative `AK-007` fixture faults the authoritative promotion of a staged
   multi-file diff after exactly one authoritative file mutation, then requires journaled
   rollback and byte/declared-metadata equality with the pre-run snapshot.

The literal `AK-007` row remains non-PASS until the second fixture passes. If an
authoritative clarification assigns a different meaning to "staged change," this ADR is
superseded rather than relabeling discard as rollback.

### Framework and model integrations

Release 0.2 requires MCP plus one mainstream SDK chosen in a later ADR after the core
proposal and bypass contracts stabilize. Additional framework integrations remain
optional. The no-key path retains a deterministic scripted model and also gains a real
local/offline inference backend because the current user objective explicitly requires
local/offline support. External-provider support never silently falls back to a provider
with different data terms and does not require paid credentials for the public demo.

### Research gating

TraceWorld shadow inference is mandatory for v1. Runtime blocking by TraceWorld remains
optional. It may be enabled only after thresholds are fixed in a content-digested
experiment manifest before evaluation, `AK-056` passes, and an approved rollback plan is
tested. Synthetic paired trajectories are the default release source; natural-failure
labels require the specified independent annotation/adjudication evidence.

### Audit, hidden evaluation, and artifact publication

An independent internal review may support a public audit report but is never represented
as a third-party assessment. Hidden tests cannot be committed to the public repository;
the implementation must use separately controlled evaluation data and isolated execution.
The exact free GitHub design is decided and threat-modeled before that gate.

The project builds and signs wheel, source, image, dataset, checkpoint, and reproducibility
artifacts as applicable and verifies them from clean environments. Uploading to PyPI or
another third-party registry is a separate action. If valid credentials or trusted
publishing authority are absent, GitHub-hosted installable artifacts and automation are
completed, and the registry publication row remains explicitly blocked rather than
reported as successful.

## Considered options

### Treat the current repository as disposable greenfield work

Rejected. It would discard verified contracts, create regression risk, and violate the
requirement to audit rather than rebuild working components unnecessarily.

### Treat each roadmap release as independent

Rejected. This could permit later work to bypass unfinished authority or recovery
semantics. The specification explicitly defines capability gates and forbids weakening an
earlier security contract.

### Make every named optional backend or framework mandatory

Rejected. Docker plus pluggable stronger-isolation interfaces are mandatory; all of
Podman, gVisor, Kata, and Firecracker are not. MCP plus one mainstream SDK is mandatory;
the remaining named frameworks are optional unless separately promoted through an ADR.

### Claim rollback for every unsuccessful transaction

Rejected. It conflates discard, restoration, compensation, and irreversibility and would
violate the state and recovery acceptance criteria.

## Consequences

### Positive

- Existing Phase 0 evidence can be reused without overstating later coverage.
- Assurance, platform, recovery, and artifact claims have precise meanings.
- Roadmap ordering no longer creates a loophole around final enforcement criteria.
- Missing external authority remains visible and cannot be converted into a fake pass.

### Negative and trade-offs

- The requirements ledger is larger because duplicate normative expressions retain source
  links instead of being collapsed informally.
- Windows verification needs both native and Linux-on-Windows lanes.
- Real materialized benchmark and dataset counts make the project substantially more
  expensive to verify than schema-only generators.
- Hidden evaluation and registry publication may expose genuine external blockers late in
  the program if their authority is not available.

## Security impact

This decision closes interpretation paths that could otherwise permit an ambient agent
effect channel, unsafe duplicate external dispatch, false rollback language, unsupported
Windows containment claims, or release with missing later-stage controls. It does not
itself prove a runtime control; every claim still needs criterion-specific evidence.

## Data and privacy impact

Local/offline inference is the required route for data that policy forbids sending outside
the declared trust boundary. Hidden evaluation, datasets, model artifacts, and public
audit material must retain redaction, provenance, licensing, retention, and access-control
evidence. Registry absence is not permission to disclose credentials in workflows.

## Compatibility and migration

This ADR changes no serialized runtime contract. It governs how pre-v1 changes and evidence
are evaluated. Future requirement revisions add or supersede ledger rows explicitly;
historical source mappings and release evidence remain immutable.

## Operational impact

CI eventually includes native Windows, clean Linux, Docker/WSL2, offline, PostgreSQL/S3,
recovery, benchmark, security, and release-artifact lanes. Stable release automation must
query the traceability gate and refuse release on any mandatory non-PASS row or unresolved
Critical/High finding.

## Required validation evidence (not yet completed)

The following are release requirements, not evidence that already exists at the audit
baseline:

- A machine-readable traceability validator accounts for every normative source row and
  rejects missing IDs, invalid status values, or unsupported `blocked` states.
- Recovery tests distinguish staged discard, verified rollback, compensation, ambiguity,
  and `RECOVERY_FAILED`.
- Assurance reports and platform tests reject `A1`/`A2` claims when ambient paths or
  required Linux controls are unavailable.
- Release workflow tests refuse a stable version when any mandatory gate is not PASS.

## Rollout and rollback

Apply this interpretation to the full-specification ledger before post-Phase-0
implementation. Use prereleases and cohesive commits. If later authoritative clarification
changes one of these interpretations, supersede this ADR, migrate affected ledger rows,
and rerun every dependent gate; do not rewrite prior evidence or reuse a tag.

## Revisit triggers

- a new specification revision changes normative precedence or release membership;
- the selected mainstream SDK, local model, IdP, vault, storage, or hidden-evaluation
  design changes a public security contract;
- supported native Windows confinement becomes strong enough for a new named profile; or
- registry/trusted-publishing authority becomes available or is revoked.

## References

- [Architecture](../architecture.md)
- [Threat model](../security/threat-model.md)
- [Assurance levels](../concepts/assurance-levels.md)
- [Roadmap](../../ROADMAP.md)
