# AgentKernel requirements traceability baseline

> This is a generated summary. The authoritative row-level ledger is [`requirements/traceability.json`](../../requirements/traceability.json).

## Baseline result

- Specification revision digest: `b5bef98ca2397b87cff8a87f950488dc6f224610fa0d40b6d8bbf63d5f626bd8`.
- Implementation baseline: `a7292ea9ca157fdcb76369d9e61977c7316c8782`.
- Source-derived rows before catalogs: **360**.
- Catalog and authoritative user rows: **446**.
- Total rows: **806**.
- Stable release readiness: **FAIL**.
- Reason: mandatory rows remain partial/missing and a high-severity CodeQL alert is open. No stable v1 release is supported by this baseline.

The four allowed status strings are exact: `implemented and verified`, `partially implemented`, `missing`, and `blocked`. No row is marked blocked unless an external reason and minimum action are both recorded.

## Source-row completeness

| Source group | Count |
| --- | ---: |
| Normative keyword occurrences | 150 |
| Phase/release parents | 6 |
| Roadmap deliverable/exit rows | 93 |
| `AK-*` acceptance criteria | 77 |
| Negative release criteria | 10 |
| Security invariants | 14 |
| Definition of Done rows | 10 |
| **Total** | **360** |

Normative occurrence accounting excludes the keyword-definition line and contains 117 `MUST`, 32 `MUST NOT`, and one `SHALL`. Roadmap child distribution is P0=14, R01=21, R02=16, R03=14, R04=14, R10=14.

## Current status totals

| Status | Rows |
| --- | ---: |
| implemented and verified | 55 |
| partially implemented | 147 |
| missing | 604 |
| blocked | 0 |

## Release-oriented view

A row can relate to more than one release, so this table is not additive.

| ID | Gate | Implemented + verified | Partial | Missing | Blocked |
| --- | --- | ---: | ---: | ---: | ---: |
| `REL-P0` | Phase 0 | 15 | 40 | 0 | 0 |
| `REL-R01` | Release 0.1 | 14 | 30 | 21 | 0 |
| `REL-R02` | Release 0.2 | 4 | 12 | 169 | 0 |
| `REL-R03` | Release 0.3 | 8 | 14 | 25 | 0 |
| `REL-R04` | Release 0.4 | 0 | 0 | 144 | 0 |
| `REL-R10` | Release 1.0 | 19 | 73 | 460 | 0 |

## Explicit catalogs

| Catalog category | Rows |
| --- | ---: |
| `adapter-backend-or-runtime-component` | 24 |
| `benchmark` | 6 |
| `benchmark-baseline` | 6 |
| `benchmark-scenario-variant` | 7 |
| `ci-matrix` | 7 |
| `cli-command` | 17 |
| `dataset-privacy` | 7 |
| `dataset-quality-gate` | 8 |
| `dataset-source` | 5 |
| `dataset-unit` | 11 |
| `disaster-recovery` | 6 |
| `documentation-quality-gate` | 7 |
| `experiment` | 6 |
| `experimental-discipline` | 8 |
| `integration-test` | 9 |
| `logical-service` | 11 |
| `metrics-and-evaluation` | 39 |
| `nonfunctional-performance` | 5 |
| `nonfunctional-portability` | 1 |
| `nonfunctional-reliability` | 4 |
| `nonfunctional-usability` | 4 |
| `observability-dashboard` | 8 |
| `operations-service` | 10 |
| `policy-aggregation` | 12 |
| `property-test` | 7 |
| `release-packaging` | 4 |
| `replay-test` | 5 |
| `required-documentation` | 12 |
| `saga-action-transition` | 23 |
| `saga-aggregate-state` | 8 |
| `saga-ordering` | 9 |
| `security-test` | 12 |
| `service-api-contract` | 8 |
| `static-analysis` | 7 |
| `storage-invariant` | 10 |
| `supply-chain` | 8 |
| `test-evidence` | 7 |
| `testing` | 3 |
| `traceworld-and-data` | 1 |
| `traceworld-metric` | 10 |
| `traceworld-training-stage` | 7 |
| `transaction-state-transition` | 38 |
| `unit-test` | 8 |
| `upgrade-and-compatibility` | 6 |
| `user-objective` | 25 |

The catalogs explicitly enumerate transaction and saga transitions, policy aggregation, adapters/backends, H1-H6, benchmark environments/baselines, CLI commands, datasets, TraceWorld, testing, operations, documentation, packaging, non-functional requirements, and authoritative user requirements.

## Validation

```bash
python scripts/validate_traceability.py
python scripts/validate_traceability.py --require-complete  # expected to fail today
```

IDs in `requirements/id-registry.json` are append-only. Existing IDs must never be renumbered or reused; later rows are appended with new IDs. The validator also pins the frozen epoch and `requirements/traceability-policy.json`, so changing the manifest and registry together cannot rebase IDs or make mandatory rows optional.

## Known release blockers versus implementation gaps

There is no externally blocked row in this baseline. Missing A1/A2 confinement, the process and heterogeneous adapters, recovery scanner/saga, Z3, benchmark/data/TraceWorld, distributed operations, release artifacts, clean cross-platform verification, and the open high CodeQL finding are implementation or verification work—not external blockers.

Source category count checksum: `f6e47473a5e85daef35502d5281555cc1c5569e154669cdce9f36031ceb830d7`.
