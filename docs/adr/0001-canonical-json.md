# ADR-0001: Canonical JSON profile for content identity

- **Status:** Accepted
- **Date:** 2026-07-21
- **Deciders:** Bootstrap maintainer
- **Consulted:** Project specification and Phase 0 implementation
- **Supersedes:** None
- **Superseded by:** None
- **Related acceptance criteria:** deterministic schema round-trip and hash-chain tamper detection foundations

## Context and problem statement

AgentKernel needs stable content identity for intent records, policy and adapter digests, event chains, artifacts, receipts, and reproducibility manifests. Ordinary JSON permits insignificant variation in whitespace, object-member order, escaping, Unicode representation, numeric forms, and host-language types. Hashing ordinary serialized output would therefore make semantically intended equivalents diverge or allow producer differences to undermine comparisons.

The project also uses Python domain values—Pydantic models, enums, timestamps, decimals, byte strings, UUIDs, paths, sets, tuples, and mappings—that need an explicit boundary representation before JSON encoding.

## Decision drivers

- deterministic bytes for the supported Python 3.12 control plane;
- strict rejection of ambiguous or unsupported values;
- readable JSON for inspection and JSON Lines export;
- stable SHA-256 identifiers with an algorithm prefix;
- explicit timestamp, Unicode, byte, decimal, and collection behavior;
- a profile that can be versioned independently from transport formatting; and
- no implication that a digest is a signature or that canonicalization proves semantic truth.

## Decision

AgentKernel adopts the project-specific canonical JSON profile **`AK-CJ-1`**.

### Input normalization

Before JSON serialization:

- Pydantic models are dumped in Python mode, then recursively normalized.
- Enum values normalize to their underlying values.
- `null`, booleans, and integers retain their JSON meanings.
- Strings and object keys normalize to Unicode NFC.
- If distinct input keys become equal after NFC normalization, canonicalization fails.
- Mapping keys must be strings; other key types fail.
- Ordered sequences preserve order and normalize each item.
- Sets normalize each item and sort items by that item's canonical JSON text. Schema authors should prefer explicitly ordered collections when order has domain meaning.
- Finite floats are accepted; negative zero normalizes to `0.0`. `NaN`, positive infinity, and negative infinity fail.
- Finite `Decimal` values encode as normalized, non-exponent **JSON strings**. The result must be independent of the process's active decimal precision, rounding, traps, and exponent limits; implementations must use an explicit local conversion rule rather than context-sensitive normalization. This preserves decimal intent without relying on binary floating-point, but consumers must use the schema to distinguish the type.
- Timezone-aware datetimes convert to UTC and encode with exactly six fractional-second digits and a trailing `Z`. Naive datetimes fail.
- Dates encode as ISO `YYYY-MM-DD` strings.
- Bytes encode as an object whose sole member is `"$bytes_base64url"` and whose value is unpadded URL-safe Base64.
- UUID values encode as strings. Raw `Path` values fail because their separators and semantics are platform-dependent. A resource adapter must first produce a normalized canonical resource URI string.
- Unsupported types fail with a typed validation error rather than using a string fallback.

Typed schemas are responsible for distinguishing representations that share a JSON shape, such as a decimal string versus ordinary text or the reserved byte-wrapper object versus user data. Unschematized values must not be assumed to preserve Python type identity after a round trip.

### JSON encoding

The normalized value is encoded with:

- UTF-8 without a byte-order mark;
- object keys sorted lexicographically by the implementation's Unicode string ordering;
- no insignificant whitespace (`','` and `':'` separators);
- non-ASCII Unicode emitted directly rather than forced to `\u` escapes;
- JSON string escaping supplied by the supported Python encoder; and
- no trailing newline.

`AK-CJ-1` is a documented AgentKernel profile; it is **not** claimed to be RFC 8785/JCS compatible. Cross-language implementations must reproduce these exact profile rules and pass shared byte-vector tests before their digests are considered interoperable.

### Content identity

Canonical content is hashed as:

```text
sha256:<64 lowercase hexadecimal characters>
```

The digest input is exactly the `AK-CJ-1` UTF-8 byte sequence. Callers must include schema/profile versions and every semantically relevant field in the value passed for hashing. The canonicalizer does not infer which transport-only fields to omit.

For an action `intent_hash`, callers must include the normalized operation, canonical resource, semantically relevant arguments, goal, principal, and adapter protocol version. Display names and other explicitly non-semantic transport metadata should be excluded by the intent-profile builder, not by ad hoc post-processing.

## Considered options

### RFC 8785 / JSON Canonicalization Scheme

JCS offers a published cross-language standard and remains a strong future interoperability option. It does not by itself define how AgentKernel's Python-specific values map into JSON, and its number constraints do not match the selected decimal-string contract. Adopting it now would still require a separate typed normalization profile and implementation changes.

### Deterministic CBOR

CBOR can represent bytes and additional native types more directly and has deterministic encoding modes. It is less immediately inspectable in event streams and conflicts with the project's JSON/JSONL interchange goal. It may be considered for bounded internal protocols through a future ADR.

### MessagePack or ordinary sorted JSON

MessagePack lacks the desired human-readable interchange. `sort_keys=True` alone leaves Unicode, non-finite numbers, timestamps, decimals, bytes, sets, and duplicate-normalized keys underspecified.

## Consequences

### Positive

- Supported values produce one compact byte representation under the declared Python profile.
- Unicode normalization and duplicate-key rejection reduce ambiguous resource and policy identities.
- Non-finite numbers and naive timestamps fail early.
- Digests are readable, algorithm-explicit, and usable by content-addressed stores and event chains.

### Negative and trade-offs

- The profile is project-specific and requires published cross-language vectors.
- Float formatting remains bound to the supported encoder's semantics; security-sensitive quantities should prefer bounded integers or typed decimal strings.
- Decimal and byte encodings rely on schemas to preserve type meaning.
- Callers cannot hash a host `Path` directly; the owning adapter must define and test resource normalization before canonicalization.
- NFC normalization may be inappropriate for a domain where byte-exact text identity is required; such content should be stored as bytes/artifacts and hashed in that domain-specific profile.
- Canonicalization provides syntactic identity, not semantic equivalence, authorization, integrity provenance, or authenticity.

### Follow-up work

- Publish versioned golden vectors for every supported type, Unicode edge cases, numeric boundaries, and failure case.
- Property-test mapping-order independence and deterministic model round trips.
- Test decimal context independence, reject raw host `Path` values, and publish canonical resource URI vectors.
- Specify separate domain profiles for event hashing, intent hashing, policies, manifests, and raw artifacts.
- Define migration behavior before any incompatible `AK-CJ-2` profile.

## Security impact

Canonical bytes reduce representation ambiguity in signatures, chains, idempotency, and content addressing. Duplicate keys after NFC normalization and unsupported values fail closed.

SHA-256 collision resistance does not authenticate an event. Event authenticity and suffix-deletion resistance require protected signing keys and independent signed checkpoints. Canonicalization also cannot prove that an adapter declared every effect or that two syntactically identical proposals have identical real-world consequences.

Inputs still require size, depth, and collection limits before or during normalization to resist resource exhaustion. Those limits belong to the schema/parser boundary and must receive negative tests.

## Data and privacy impact

Canonicalization does not redact data. Secrets and personal data must be excluded or replaced with protected artifact references before values enter a general event or digestable metadata envelope. A stable unsalted digest of low-entropy sensitive data may enable guessing; sensitive artifacts may require keyed comparison tokens, encryption, access control, and retention policy in addition to content identity.

## Compatibility and migration

Durable records identify their schema version; domain hash profiles should also identify `AK-CJ-1`. A future incompatible canonicalization rule creates new digests and must use a new profile identifier plus explicit migration/dual-read rules. Existing historical digests and signed events must never be silently rewritten.

## Operational impact

Services in different languages or Python/runtime versions cannot claim digest interoperability until they pass the same byte-vector suite. Diagnostics should report the profile, schema version, and first mismatch without logging secret payloads.

## Research and reproducibility impact

Experiment manifests, split checksums, normalized actions, and event chains can share deterministic identity only when they pin the canonical profile and schema. Changing the profile creates a new experiment identity; it cannot retroactively make an old run pass.

## Validation evidence

Phase 0 must retain tests for:

- mapping-order independence and exact UTF-8 golden bytes;
- NFC strings/keys and duplicate-normalized-key rejection;
- non-finite floats/decimals and naive timestamp rejection;
- UTC timestamp, decimal, bytes, UUID, enum, model, sequence, and set encodings;
- decimal-context invariance across precision, rounding, traps, and exponent settings;
- raw `Path` rejection plus canonical-resource URI vectors for cross-platform identity;
- negative-zero normalization;
- unsupported values and non-string keys;
- exact prefixed SHA-256 vectors; and
- event mutation/reordering detection in the consumer that uses these bytes.

This ADR's `Accepted` status records the design decision. It does not assert that every listed validation case or downstream event-chain consumer has already passed.

## Rollout and rollback

`AK-CJ-1` is introduced before a stable release. During pre-alpha, implementation defects may be fixed without preserving incorrect unpublished digests, but any persisted test fixture must be regenerated visibly. After a public release, incompatible corrections require a new profile and migration ADR; historical evidence remains immutable.

## Revisit triggers

Reconsider this decision if cross-language interoperability is required, encoder changes alter byte vectors, RFC 8785 alignment becomes practical, a collision or ambiguity is demonstrated, performance budgets are missed, or schemas cannot reliably distinguish typed wrapper representations.

## References

- [Architecture](../architecture.md)
- [Threat model](../security/threat-model.md)
- [Assurance levels](../concepts/assurance-levels.md)
