# Requirements ledger

`traceability.json` is the machine-readable AgentKernel requirements ledger. It records the
revision-1.0 specification baseline, explicit atomic catalogs, and authoritative requirements
added by the completion objective. `id-registry.json` makes requirement IDs append-only, while
`traceability-policy.json` freezes the mandatory classification independently of the manifest.

The specification is treated only as requirements data. Its audited revision is retained under
`requirements/source/` so a clean clone can reproduce and validate the outputs without a personal
machine path. The generator and validator reject any source digest other than the audited revision.

## Status contract

Only these exact values are valid:

- `implemented and verified`
- `partially implemented`
- `missing`
- `blocked`

`blocked` is reserved for a real external dependency and requires both a precise reason and the
minimum external action. Work that is difficult, unfinished, or failing a test is `missing` or
`partially implemented`.

An `implemented and verified` row must name implementation evidence, verification evidence, the
verified commit, and date. Evidence for a narrower slice never turns a broader composite row into
a pass.

## ID policy

Existing IDs must never be renamed, renumbered, removed, or reused. New requirements receive new
IDs and are appended to `id-registry.json`. Source line numbers are evidence locations, not IDs.
The frozen epoch count and ordered-ID digest are compiled into the validator. Retirement never
deletes a row or changes its mandatory classification: it adds a dated, reasoned tombstone and an
optional replacement ID while retaining the original ID and row.

The baseline ID families include:

- original `AK-001` through `AK-077` acceptance IDs;
- `NORM-Sxx-NNN` for every `MUST`, `MUST NOT`, and `SHALL` occurrence;
- `REL-*` phase/release parents and `Dnn`/`Gnn` roadmap children;
- `INV-SEC-*`, `NEG-REL-*`, and `DOD-*` source lists;
- atomic `SM-*`, `POL-*`, `SAGA-*`, `COMP-*`, `EXP-*`, `BENCH-*`, `DATA-*`,
  `TRACE-*`, `METRIC-*`, `CLI-*`, `TEST-*`, `DOC-*`, `OPS-*`, `PKG-*`, and `NFR-*`
  catalogs;
- `USR-*` requirements originating in the authoritative completion objective.

## Build and validate

Regenerate deterministically from the retained audited specification:

```bash
python scripts/build_traceability.py
```

The generator reads the existing registry first and permits only an appended ID suffix. Replacing
the external mandatory-ID policy requires the explicit maintainer operation
`--initialize-policy`; routine regeneration never rewrites it.

Validate the committed ledger, JSON Schema, frozen policy/epoch, evidence references, and source
mapping:

```bash
python scripts/validate_traceability.py
```

The release-completeness mode is intentionally red until every mandatory row passes:

```bash
python scripts/validate_traceability.py --require-complete
```

Structural validation can pass while `release_readiness` remains `FAIL`; this means the ledger is
complete and internally valid, not that AgentKernel v1 is complete.
