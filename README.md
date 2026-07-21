# AgentKernel

**A transactional, policy-verifiable execution kernel and reliability laboratory for autonomous AI agents.**

AgentKernel explores a simple boundary: a model may *propose* an action, but a separate runtime must establish authority, apply deterministic policy, control the execution boundary, verify resulting state, and preserve evidence before reporting success.

The Python distribution is named `agentkernel-runtime` while the import package remains
`agentkernel`; the exact `agentkernel` distribution name is already occupied. AgentKernel is an
independent community project and is not affiliated with OpenAI, Anthropic, or another model
provider. See [ADR-0002](docs/adr/0002-project-and-distribution-names.md).

> [!IMPORTANT]
> **Project status: Phase 0 plus an A0 vertical demo — pre-alpha.** APIs and schemas may change without notice. There is no production release, no `v1` compatibility promise, and no general `A1+` assurance claim. The repository includes mock and filesystem adapters, a scripted local model gateway that hard-disables external dispatch, a deterministic no-key demonstration, and an inspectable Docker control backend. It does not yet include an OS-confined hostile-agent harness, an integrated `A2` execution path, AgentKernel Bench, or TraceWorld. Design documents describe intended contracts unless linked evidence proves an implementation.

## Why AgentKernel?

Most agent loops connect probabilistic output directly to tools that create deterministic side effects:

```text
model decision -> tool call -> real-world effect
```

AgentKernel is designed to place an explicit transaction boundary in that path:

```text
proposal
  -> normalize and bind provenance
  -> verify authority
  -> evaluate deterministic policy
  -> classify risk and reversibility
  -> stage or shadow the action
  -> verify state
  -> commit, abort, review, roll back, or compensate
  -> append tamper-evident evidence
```

This architecture deliberately separates four concerns:

- **Prevention:** reject actions without sufficient authority or policy permission.
- **Containment:** bound uncertain execution with an explicitly named isolation profile.
- **Recovery:** abort, roll back, reconcile, or compensate according to truthful adapter semantics.
- **Learning and evaluation:** measure outcomes from executable state and recorded trajectories.

AgentKernel does not claim that prompts are enforcement, that containers make arbitrary code harmless, that every external effect can be rolled back, or that a formal policy model proves the real world is safe.

## Current scope

| Area | Current public status |
| --- | --- |
| Phase 0 schemas, invariants, canonical data, journal, evidence, and adapter contracts | Implemented; acceptance evidence is still being completed |
| Transactional filesystem adapter and deterministic no-key A0 demo | Executable vertical slice; not the complete `0.1` release |
| Confined agent harness and allowlisted process adapter | Planned for release `0.1` |
| Docker/OCI control backend | Implemented and tested for non-root, read-only root, no network, dropped capabilities, no-new-privileges, bounded resources, and no host mounts; not yet an integrated hostile-agent `A2` profile |
| Reliability benchmark and heterogeneous adapters | Planned for release `0.2` |
| Z3-backed authority and policy analysis | Planned for release `0.3` |
| TraceWorld datasets and learned risk models | Planned for release `0.4`; advisory by design |
| Stable production platform | Release `1.0` goal; **not available** |

See the [roadmap](ROADMAP.md) for capability gates. Repository contents or passing unit tests alone do not satisfy a release gate; retained acceptance evidence is required.

## Phase 0 developer quick start

The current quick start installs the locked development environment and runs a scripted, local demonstration. It does **not** start the Docker backend or establish `A1+` enforcement. Its report is explicitly `A0` and distinguishes application-path evidence from OS/network confinement.

Prerequisites:

- Python 3.12
- [`uv`](https://docs.astral.sh/uv/)
- Git

```bash
git clone https://github.com/MarwanAljijakli/agentkernel.git
cd agentkernel
uv sync --frozen
uv run agentkernel doctor --json
uv run agentkernel demo
uv run pytest
```

The demo needs no cloud credentials and makes no network request. It consumes an untrusted synthetic repository instruction, denies the proposed protected-file read and external send before dispatch, stages and commits one authorized file change, validates the event chain, scans evidence for the synthetic secret, and reproduces the action/final-state hashes at the supported `L2` replay path. To retain the disposable workspace and machine-readable report:

```bash
uv run agentkernel demo --root .agentkernel/demo-run --json
```

The demo's zero-dispatch counters prove only the implemented application path. They do not prove that a hostile process is confined. The separate Docker verification command checks container controls, but it is not yet wired to a hostile-agent harness or claimed as an integrated `A2` run:

```bash
uv run agentkernel sandbox verify-docker --json
```

For a checkout that has not been published yet, begin with `uv sync` in the repository root. Linux x86-64 is the intended security and production reference platform. Foundation development may work on Windows or macOS, but unsupported controls must never be interpreted as containment.

## Design map

- [Architecture](docs/architecture.md) — planes, trust boundaries, component contracts, and lifecycle.
- [Threat model](docs/security/threat-model.md) — protected assets, adversaries, assumptions, and residual risks.
- [Assurance levels](docs/concepts/assurance-levels.md) — precise claim language for `A0` through `A5` and replay `L0` through `L4`.
- [Canonical JSON ADR](docs/adr/0001-canonical-json.md) — deterministic `AK-CJ-1` representation and hashing rules.
- [Roadmap](ROADMAP.md) — evidence-gated milestones without calendar promises.

The long-term project has four related, independently useful tracks:

1. **AgentKernel Runtime** — typed proposals, authority, policy, transactions, verification, recovery, and evidence.
2. **AgentKernel Environments** — reproducible sandboxes and shadow targets for files, code, databases, browsers, services, and communication.
3. **AgentKernel Bench** — controlled tasks, attacks, faults, objective verifiers, and reliability metrics.
4. **TraceWorld** — optional trajectory research for calibrated risk prediction, causal localization, and recovery ranking. It cannot grant authority or override a deterministic denial.

## Assurance and security posture

Assurance is a property of an individual run under a named configuration with retained evidence—not a property implied by installing the package. The current demo reports `A0: Recorded and inspected`; it does not claim policy-enforced `A1` or contained `A2`. Future reports must name achieved and degraded controls instead of returning an unexplained `safe: true`.

Do not use this pre-alpha project to protect production data, credentials, multi-tenant workloads, or irreversible external actions. To report a vulnerability privately, follow [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome from systems, security, formal methods, AI reliability, benchmark, documentation, and developer-tooling communities. Start with [CONTRIBUTING.md](CONTRIBUTING.md), follow the [Code of Conduct](CODE_OF_CONDUCT.md), and record material security-contract decisions with an [ADR](docs/adr/0000-template.md).

The project optimizes for enforceable boundaries, reproducible evidence, and honest limitations. Repository stars are welcome, but they are not a quality or acceptance metric.

## Research and citation

Research claims should be falsifiable, preregistered where appropriate, and reported with denominators, uncertainty, operational overhead, and negative results. Citation metadata is available in [CITATION.cff](CITATION.cff). No benchmark result, dataset, model checkpoint, or peer-reviewed security claim has been released yet.

## License

Source code and documentation in this repository are licensed under the [Apache License 2.0](LICENSE), unless a file states otherwise. Future datasets may require separate licenses and machine-readable provenance; none inherit a dataset license merely from this repository.
