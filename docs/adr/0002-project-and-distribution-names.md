# ADR-0002: Project and distribution names

- **Status:** Accepted for pre-alpha
- **Date:** 2026-07-21

## Context

The specification and repository use the working project name **AgentKernel**. The exact
`agentkernel` distribution name is already present on the Python Package Index, so publishing a
different project under that distribution identifier would create ambiguity and supply-chain
risk. A repository-name search and package-index check are useful engineering inputs, but they
are not trademark clearance.

## Decision

- Keep `AgentKernel` as the working repository and import-package name.
- Use `agentkernel-runtime` as the Python distribution name.
- Do not publish a package from the pre-alpha workflow; release automation builds artifacts only.
- State that this community project is not affiliated with OpenAI, Anthropic, or another model
  provider.
- Revisit the public name before a stable release if legal or ecosystem evidence changes.

## Consequences

Users install a future package by its distribution name but import `agentkernel`. Documentation
must keep that distinction explicit. No document may describe the name checks as legal approval
or guarantee that the working name will remain unchanged through `v1`.
