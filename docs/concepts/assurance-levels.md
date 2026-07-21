# Assurance Levels and Claim Language

- **Status:** normative documentation for how AgentKernel reports evidence
- **Current project posture:** bounded `A0` vertical slice; no general `A1+` runtime assurance profile is claimed

AgentKernel must never reduce a complex run to an unexplained `safe: true`. Assurance is a scoped claim about one run, adapter boundary, policy version, environment, and body of evidence. It is not inherited merely by installing the package or using the project name.

## Assurance profiles

| Profile | Minimum evidence | Permitted claim |
| --- | --- | --- |
| `A0` — Inspect-only | Proposal schema validated and the proposal recorded | “Recorded and inspected” |
| `A1` — Policy-checked | `A0`, authenticated actor/principal/goal, current capability chain, deterministic policy grant, obligations and unknowns resolved | “Authorized under policy bundle `<digest>`” |
| `A2` — Contained | `A1`, supported sandbox controls measured effective, ambient bypass paths tested/blocked | “Executed within sandbox profile `<name@digest>`” |
| `A3` — State-verified | `A2`, sufficiently complete supported snapshot/diff, staged and committed postconditions, declared invariants pass | “Verified against declared invariants `<ids>`” |
| `A4` — Recoverable | `A3`, durable journal plus tested rollback or compensation semantics for the named adapter boundary | “Recoverable within adapter boundary `<name@version>`” |
| `A5` — Reproducible | `A3`/`A4`, a declared replay level is achieved with divergence reporting | “Reproduced at replay level `Lx`” |

No profile means universal safety. `A4` does not make an irreversible effect reversible. `A5` does not imply that a live model provider will produce the same response again.

## Evidence rules

An assurance claim must include:

- run, transaction, goal, principal, and configuration identity;
- adapter and policy versions/digests;
- achieved profile and every unavailable, degraded, or unobserved control;
- authoritative target and resource scope;
- risk class and truthful recovery semantics;
- verifier identities, results, and evidence references;
- sandbox profile and effective-control checks for `A2+`;
- replay level and first divergence for `A5`; and
- any residual effect or unresolved ambiguity.

The achieved profile is the strongest level for which **all** mandatory properties have evidence. It is bounded by the weakest required component. For example, an `A3` filesystem step followed by an unverified external API step does not make the complete transaction `A3`.

Evidence can establish a condition (`PASS`), contradict it (`FAIL`), be incomplete (`UNKNOWN`), or fail to execute (`ERROR`). `UNKNOWN` and `ERROR` do not become `PASS`. Policy may reject, request review, or permit only a specifically documented lower profile.

## Downgrades and refusals

The runtime must downgrade or refuse a claim when, among other cases:

- the agent has an ambient effect path outside the Kernel API;
- a requested sandbox control is unsupported or not measured effective;
- a snapshot is partial but full restoration is required;
- an adapter manifest is unreviewed or its digest differs;
- policy, capability, approval, or target versions are stale;
- the verifier lacks required state evidence;
- evidence storage is unavailable for an effectful action;
- an external result is `IN_DOUBT`;
- replay contacts a live authoritative target or uncaptured nondeterminism diverges; or
- a trusted component has changed since validation.

A warning in an `A0` development mode does not satisfy an `A1+` enforcement requirement.

## Replay fidelity

Replay level is related to, but separate from, runtime assurance.

| Level | Name | Supported statement |
| --- | --- | --- |
| `L0` | Inspect | Events can be viewed; no re-execution claim |
| `L1` | Tool-result replay | Recorded model/tool results were supplied again in sequence |
| `L2` | Environment replay | Supported initial state and captured nondeterminism were reconstructed |
| `L3` | Deterministic component replay | Named components produced byte-equivalent normalized outputs under the recorded environment |
| `L4` | Counterfactual fork | A recorded prefix was reproduced and one declared variable changed; the future is not claimed to match the original |

Every replay report must identify the requested and achieved level, exact versus semantic comparisons, uncaptured inputs, and earliest divergence. Replay defaults to no egress and a non-authoritative environment. Re-executing an external effect requires a new proposal and fresh authority; replay itself must not send, publish, pay, or delete.

## Risk classes are not assurance levels

Risk describes the action; assurance describes the evidence around its handling.

| Risk | Meaning | Default handling intent |
| --- | --- | --- |
| `R0` | Read-only | Scoped access; verify absence of writes where practical |
| `R1` | Reversible | Stage, verify, commit, and verify rollback semantics |
| `R2` | Compensatable | Require a durable compensation plan and report residual effects |
| `R3` | Irreversible | Explicit capability and approval unless narrowly preauthorized |
| `R4` | Forbidden | Reject unconditionally |

An adapter declares a risk floor. Policy may raise handling requirements but cannot lower that floor. Sending non-public data outside the trust boundary is `R3`: deletion at the destination cannot undo disclosure.

## Example report shape

The following is **conceptual**, not evidence of a currently implemented command:

```json
{
  "run_id": "run_01...",
  "achieved_assurance": "A2",
  "claim": "Executed within sandbox profile network-denied@sha256:...",
  "policy_digest": "sha256:...",
  "adapter_digest": "sha256:...",
  "risk_class": "R1",
  "verification": "UNKNOWN",
  "degraded_controls": ["snapshot completeness not established"],
  "unavailable_controls": [],
  "residual_effects": [],
  "evidence_refs": ["sha256:..."]
}
```

Because verification is `UNKNOWN`, this example cannot claim `A3`. If the sandbox controls were also unverified, it would be limited to `A1` or lower.

## Current implementation statement

The current repository implements contracts, an embedded transactional filesystem path, hash-chained evidence, a deterministic scripted `L2` replay for that path, and a separate Docker control verifier. The public demo remains `A0` because it does not execute a hostile agent inside an integrated confinement boundary. It does not claim a general `A1+` path, sandbox escape resistance, cross-domain recoverability, or replay outside the named scripted scenario. A future release may claim a stronger profile only after its named acceptance evidence passes in a clean supported environment.
