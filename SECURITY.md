# Security Policy

AgentKernel treats vulnerability reports as a contribution to user safety. Please report suspected vulnerabilities privately and give maintainers a reasonable opportunity to investigate before public disclosure.

## Current support status

AgentKernel is in **Phase 0 (pre-alpha)** and has no production-supported release.

| Version or branch | Security status |
| --- | --- |
| `main` / unreleased Phase 0 | Receives best-effort security fixes; not approved for production use |
| Published releases | None yet |

The current repository makes no general `A1+` policy-enforcement, Docker containment, hostile-code isolation, or `v1` stability claim. Design documents describe intended controls; only evidence attached to a specific tested run can support an assurance statement.

## Report a vulnerability privately

Use GitHub's private vulnerability reporting channel:

<https://github.com/MarwanAljijakli/agentkernel/security/advisories/new>

Do **not** include exploit details, secrets, personal data, or a working proof of concept in a public issue or discussion. If private vulnerability reporting is not yet enabled on the repository, contact the repository owner through the private contact method listed on their GitHub profile and request a secure channel without disclosing sensitive details publicly.

Include, when available:

- affected commit, version, component, and configuration;
- the violated security invariant and realistic impact;
- minimal reproduction steps using synthetic data;
- whether the issue crosses an authority, sandbox, tenant, secret, evidence, or model-egress boundary;
- expected versus observed behavior;
- logs or traces after removing secrets and personal data;
- known mitigations; and
- your preferred name, credit, and disclosure coordination needs.

Please do not test against systems or data you do not own or have explicit permission to assess.

## Response targets

These are coordination targets, not guarantees or service-level agreements:

- acknowledge a report within 3 business days;
- provide an initial triage or request for more information within 7 business days;
- share a status update at least every 14 days while remediation is active; and
- coordinate a disclosure date after a fix and affected-user guidance are ready.

Complex issues, upstream dependencies, and embargoed ecosystem fixes may require more time. Maintainers will explain material delays. Security-sensitive benchmark fixtures may remain embargoed until users can update safely.

## Severity rubric

Severity considers exploitability, required privileges, affected assets, scope, detectability, and recovery—not only a numeric score.

- **Critical:** practical compromise of the control plane or signing authority; cross-tenant compromise; default escape from a claimed isolation boundary with host impact; or unauthorized irreversible effects at broad scale.
- **High:** reliable bypass of authority/policy/model-egress controls; secret disclosure; evidence forgery that defeats a stated guarantee; or duplicate/incorrect authoritative effects with serious impact.
- **Medium:** constrained bypass requiring uncommon conditions, meaningful denial of service, incomplete redaction, or a security-control weakness with material compensating controls.
- **Low:** defense-in-depth weakness, low-impact information disclosure, misleading diagnostics, or a hardening opportunity with limited practical impact.

Critical and high findings block a release and cannot be waived. A medium finding may receive a temporary exception only through the process in [GOVERNANCE.md](GOVERNANCE.md).

## Scope guidance

We especially want reports involving:

- capability forgery, scope expansion, replay, revocation, or confused-deputy behavior;
- fail-open policy, solver, verifier, approval, or model-egress paths;
- ambient filesystem, process, network, provider, device, or credential access in a profile that claims those paths are blocked;
- stage/commit separation, duplicate effects, `IN_DOUBT`, rollback, or compensation errors;
- sandbox configuration or escape affecting a declared profile;
- secret leakage through prompts, logs, events, artifacts, URLs, headers, or exceptions;
- event-chain integrity, signature/checkpoint handling, or replay contacting an authoritative target;
- cross-tenant access or insecure object references; and
- release, dependency, image, policy, adapter, model, or dataset supply-chain compromise.

Reports that generally do not qualify without additional security impact include unsupported platforms, missing product features, social engineering of maintainers, automated scanner output without a validated vulnerable path, and resource exhaustion caused only by intentionally disabling documented limits.

Third-party dependencies and services may have their own reporting processes. Please still report a reachable AgentKernel impact privately so maintainers can assess mitigations and coordinated disclosure.

## Safe-harbor intent

When you act in good faith, stay within systems and data you are authorized to test, avoid privacy violations and service disruption, use the minimum access needed to demonstrate the issue, and follow this policy, the project will not recommend or pursue legal action against you for the research. If your activity unintentionally exceeds these boundaries, stop, preserve evidence safely, and contact maintainers promptly.

This statement does not bind third parties and is not legal advice. It does not authorize testing of infrastructure, accounts, models, or data owned by anyone else.

## Disclosure and remediation

Maintainers will validate the affected boundary, assign severity, develop regression coverage, prepare a fix and migration guidance, and credit the reporter if desired. Public advisories should distinguish attempted from executed effects and state affected configurations, assurance impact, detection evidence, mitigations, and fixed versions.

Do not promise universal safety after a fix. Remediation evidence applies only to the tested threat, configuration, and boundary.
