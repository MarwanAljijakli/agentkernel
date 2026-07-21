# AgentKernel Governance

## 1. Purpose and current model

AgentKernel begins with a lightweight, maintainer-led governance model suitable for a pre-alpha project. The goal is fast, transparent decisions without weakening the security contract. Governance should evolve as the contributor and adopter community grows.

Until a public maintainers list is adopted, the repository owner serves as interim project lead and release manager. This bootstrap role is not a claim of unilateral technical correctness: security-sensitive changes still require evidence and the review rules below.

## 2. Roles

### Contributors

Anyone who participates constructively in issues, documentation, design, code, testing, research, or community support. Contributions must follow the Code of Conduct and DCO.

### Reviewers

Contributors trusted to review an area based on sustained, high-quality participation. Reviewers may approve changes in their area but cannot merge changes unless they are also maintainers.

### Maintainers

People accountable for repository quality, reviews, issue triage, releases, roadmap accuracy, and community health. Maintainers may merge changes, but must not self-approve security-critical work when an independent qualified reviewer is available.

### Security owner

A maintainer responsible for private vulnerability intake, severity decisions, embargo coordination, and ensuring that release-blocking findings remain blocked. The interim project lead holds this role until it is delegated publicly.

### Release manager

A maintainer who assembles evidence, confirms release gates, and coordinates artifacts. The role cannot waive a required gate.

One person may hold several roles during bootstrap, but the project must state where independence is absent. A requirement for an independent maintainer cannot be satisfied by the same person under a second title.

## 3. Decision process

Routine changes use lazy consensus through public issues and pull requests:

1. State the problem, alternatives, effects, and evidence.
2. Allow a reasonable review window proportional to impact.
3. Resolve actionable objections or record why they do not apply.
4. Merge when required checks and approvals pass.

Suggested minimum review windows are 72 hours for material architecture changes and 7 calendar days for governance or public security-contract changes. Maintainers may extend them for broad impact. Urgent vulnerability fixes may proceed privately under embargo, with a public decision record after disclosure.

If consensus is not possible, active maintainers vote. Each maintainer has one vote; a simple majority of non-conflicted votes decides, with at least two participating maintainers once the project has two or more. During single-maintainer bootstrap, the repository owner decides and records the trade-off publicly. Decisions that would violate a non-waivable release gate are invalid regardless of vote.

## 4. Architecture decision records

A material change to authority, policy aggregation, assurance language, transaction states, adapter semantics, sandbox boundaries, model egress, secrets, evidence integrity, replay, or compatibility requires an ADR using [the template](docs/adr/0000-template.md).

An accepted ADR records the decision at that time. Later changes supersede it with a new ADR instead of silently rewriting history. Implementation and verification evidence must be linked when available; an ADR is not proof that code satisfies the decision.

## 5. Appointment and removal

A contributor may be nominated as a reviewer or maintainer after sustained, constructive work and demonstrated judgment in the relevant boundaries. Existing maintainers decide publicly, considering technical quality, review quality, security mindset, reliability, inclusion, and availability—not employer or volume of commits alone.

A role may be made emeritus for inactivity or removed for repeated failure to meet responsibilities, undisclosed conflicts, violation of the Code of Conduct, mishandling private reports, or actions that put users at material risk. Removal requires a documented, conflict-free maintainer decision. Sensitive personal details should remain private while the outcome and project-impacting actions are recorded.

People may step down at any time. Access should be revoked promptly when responsibilities end.

## 6. Security and release authority

Releases are capability gates, not calendar promises.

- An unresolved **critical** or **high** security finding blocks release and cannot be waived.
- A **medium** finding may receive a written exception only with approval from the security owner and one independent maintainer, a named remediation owner, compensating controls, an appropriately public or embargoed rationale, and an expiry no later than 90 days.
- Renewing a medium exception requires a new review and cannot silently lower severity.
- During single-maintainer bootstrap, the independence requirement cannot be met, so a medium finding that needs an exception remains release-blocking.
- Failed or missing acceptance evidence cannot be converted to a pass by vote.
- Learned-model output cannot override a deterministic denial or create authority.

The release manager must publish the achieved assurance scope, known degraded controls, acceptance evidence, artifact checksums/signatures when applicable, and unresolved non-blocking limitations.

## 7. Roadmap and project scope

Maintainers keep [ROADMAP.md](ROADMAP.md) evidence-based. “Planned” is not a delivery promise; “implemented” is not “verified”; and a release is not complete until its gate has retained evidence.

New integrations and research work should not bypass dependency order. The small trusted core, objective verifiers, data lineage, and split controls come before ecosystem breadth, benchmark scale, or model training.

Repository stars, social reach, and employer attention are possible outcomes, not governance or acceptance metrics.

## 8. Conflicts of interest

Participants must disclose financial, employment, research, personal, or competitive interests that could reasonably affect a decision. A conflicted maintainer should recuse from the final approval or enforcement decision. Vendor-specific decisions should be evaluated against published, provider-neutral requirements.

## 9. Contribution rights and licensing

Contributions require Developer Certificate of Origin sign-off as described in [CONTRIBUTING.md](CONTRIBUTING.md). Accepted source and documentation contributions are licensed under Apache License 2.0 unless a file states otherwise.

Datasets, model weights, fixtures, and third-party content require separate provenance and license review. Repository licensing must not be assumed to grant rights the contributor does not hold.

## 10. Conduct and enforcement

All project spaces follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Enforcement decisions prioritize participant safety, confidentiality, proportionality, consistency, and conflicts of interest. Security reports follow [SECURITY.md](SECURITY.md).

## 11. Amending governance

Governance changes require a public pull request, a stated migration impact, and the review window in Section 3 unless responding to an urgent safety or legal requirement. The change takes effect when merged and should be summarized in the project decision history.
