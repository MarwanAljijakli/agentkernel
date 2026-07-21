# Contributing to AgentKernel

Thank you for helping build AgentKernel. The project welcomes focused contributions from software engineers, security practitioners, formal-methods researchers, benchmark authors, technical writers, and people new to open source.

AgentKernel is currently in **Phase 0 (pre-alpha)**. The first priority is a small, reviewable trusted core with executable contracts—not a large catalog of integrations. Public APIs may change before a stable release.

## Start here

Before proposing a change:

1. Read the [architecture](docs/architecture.md), [threat model](docs/security/threat-model.md), [assurance model](docs/concepts/assurance-levels.md), and [roadmap](ROADMAP.md).
2. Search existing issues and pull requests for related work.
3. Open or join a design issue before making a large change, a new adapter, or a change to a security contract.
4. Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md); do not open a public security issue.

Small documentation fixes, tests for documented behavior, and clearly scoped bug fixes normally do not need prior design discussion.

## Phase 0 contribution priorities

Contributions are most useful when they strengthen one of these foundation gates:

- strict, versioned public and durable schemas;
- the normative transaction state model and illegal-transition tests;
- deterministic canonicalization and content identity;
- adapter lifecycle contracts that separate staging from authoritative commit;
- append-only evidence and tamper detection;
- stable, machine-readable errors;
- architecture boundaries and security-negative tests; or
- documentation whose claims match retained evidence.

New effect domains, integration of Docker containment with an agent harness, distributed services, framework integrations, benchmark scale-up, and TraceWorld training must follow the dependency order in the [roadmap](ROADMAP.md).

## Development setup

AgentKernel targets Python 3.12 and uses `uv` for dependency management.

```bash
git clone https://github.com/MarwanAljijakli/agentkernel.git
cd agentkernel
uv sync
```

Run the focused test for your change early, then the relevant full checks:

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy agentkernel
uv run bandit -c pyproject.toml -r agentkernel
```

Dependency auditing may require current vulnerability data and network access:

```bash
uv run pip-audit
```

Do not regenerate or replace lockfiles merely to make unrelated changes. Never commit virtual environments, local state, credentials, model-provider keys, private fixtures, or raw production traces.

## Change workflow

1. Choose the smallest coherent behavior or contract.
2. State the observable acceptance condition and relevant roadmap/acceptance identifier when one exists.
3. Add a failing regression test or executable contract when practical.
4. Implement without broadening authority or weakening a failure mode.
5. Run focused checks, then all checks relevant to the changed boundary.
6. Review the diff for secrets, unsupported assurance claims, bypass paths, timeouts, idempotency, and recovery behavior.
7. Update documentation, the roadmap evidence, and an ADR when semantics change.
8. Submit a focused pull request with verification evidence and known limitations.

Pull requests should explain:

- the problem and user-visible outcome;
- the security and assurance impact;
- compatibility or migration impact;
- tests and exact commands run;
- failure paths considered;
- documentation or ADR changes; and
- anything intentionally deferred.

## Tests and evidence

Completion means the requested behavior was exercised at the relevant layer. A new file, a green import, or an implementer's confidence is not sufficient evidence.

- Schema changes need valid, invalid, boundary, round-trip, and compatibility cases.
- State-machine changes need every new legal transition plus representative illegal transitions and crash/cancellation boundaries.
- Authority and policy changes need positive and negative tests, unknown/timeout behavior, and a threat-model impact note.
- Adapter changes need the shared conformance suite, truthful reversibility, authoritative-target checks around stage/commit, and recovery/reconciliation cases.
- Evidence changes need mutation, reordering, truncation, redaction, and unavailable-store cases as applicable.
- Documentation examples must either run in CI or be labeled `conceptual`.

Never hide a failure behind an untracked retry. Record deterministic seeds for reproducible failures.

## Security-sensitive changes

Changes to authority, policy, sandboxing, model egress, adapters, transaction state, secrets, approvals, evidence integrity, or tenant boundaries require:

- a threat-model impact note;
- positive and negative tests;
- review by a core/security maintainer;
- compatibility and migration analysis; and
- an ADR for a material semantic change.

An adapter contribution additionally requires a complete manifest, declared effect domains and recovery limits, an owner, conformance evidence, and a maintenance commitment. An unreviewed plugin may propose work but must not be described as an admitted `A1+` trusted adapter.

## Documentation and claim language

Use precise language:

- say which authority and policy bundle permitted an action;
- name the sandbox profile whose controls were verified;
- state the invariants that were checked;
- distinguish rollback from compensation;
- name the achieved replay level and divergence points; and
- describe unknown or unavailable evidence explicitly.

Do not use unconditional claims such as “safe,” “fully verified,” “deterministic” for a live model, or “atomic” across systems without a real atomic protocol. See [assurance levels](docs/concepts/assurance-levels.md).

## AI-assisted contributions

AI tools may assist a contribution, but the human contributor remains accountable for every submitted line and claim. Review generated changes, run the tests, verify licenses and provenance, and disclose substantial AI assistance in the pull request when it helps reviewers assess the work. Do not send repository secrets, private traces, embargoed vulnerabilities, or third-party confidential data to an unapproved model provider.

## Commit sign-off (DCO)

AgentKernel uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Sign off each commit to certify that you have the right to contribute it under the project's license:

```bash
git commit -s -m "Short description of the change"
```

This adds a line like:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Use your own name and an email address you are authorized to use. A pull request with missing sign-offs may be held until the commits are corrected.

## Review and conduct

Maintainers may ask for a smaller scope, more evidence, clearer limitations, or an ADR. Review disagreement is resolved under [GOVERNANCE.md](GOVERNANCE.md). All participation must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Unless a file states otherwise, accepted contributions are licensed under Apache License 2.0 and remain subject to the DCO certification.
