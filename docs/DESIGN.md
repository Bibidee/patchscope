# Patchscope design (v0.2.0)

Patchscope assesses whether one exact installed package coordinate falls within a submitted security advisory's stated version scope. It is a nonpayable, noncustodial Intelligent Contract: it does not install, patch, or block software.

## Deterministic evidence gate

The proposer supplies a supported ecosystem (`npm`, `pypi`, `cargo`, `nuget`, or `rubygems`), canonical package name, exact version, and HTTPS URL plus SHA-256 commitment for each artifact. Each validator fetches the raw bytes, checks the hash before UTF-8 decoding, and validates bounded JSON envelopes. Duplicate JSON keys, duplicate inventory coordinates, malformed records, unexpected fields, invalid encodings, empty/oversized bodies, HTTP policy failures, and digest mismatches cannot authorize a result.

The inventory format is exactly:

```json
{"format":"patchscope-inventory-v1","packages":[{"ecosystem":"npm","name":"example-lib","version":"1.4.2"}]}
```

The exact ecosystem/name/version must occur uniquely before semantic review. Absence, ecosystem/version mismatch, or ambiguity yields `inconclusive`; malformed inventory yields `invalid_artifact`.

The advisory format has exactly these fields: `format`, `advisory_id`, `ecosystem`, `package_name`, `affected_versions`, `fixed_versions`, `details`, `publisher`, and `reference_url`. Its format, advisory ID, ecosystem, and package name are checked against the proposal before LLM review. `fixed_versions` is a bounded list of exact canonical version strings, not a range expression. `publisher` and `reference_url` are caller-declared fields, not authenticated provenance. Patchscope does not implement package-manager-specific version-range parsers; validators interpret the bounded affected-scope text.

## Semantic decision and consensus

The model must return exactly `package_match`, `affected_version`, `evidence_quality`, `contradiction`, `confidence`, and `rationale`, with bounded enum values, integer confidence 0–100, and nonempty rationale no longer than 400 characters. The contract derives state; rationale is never authorization logic.

- `affected` requires verified artifact identity, `package_match=yes`, `affected_version=yes`, `evidence_quality=yes`, `contradiction=no`, confidence >= 80, and no exact installed-version match in `fixed_versions`.
- `not_affected` requires the same verified identity and quality conditions, with `affected_version=no`, `package_match=yes`, and an exact match between the installed version and a committed `fixed_versions` entry. This intentionally sacrifices some negative classifications rather than treating incomplete or unsupported range syntax as proof of exclusion.
- Every other valid semantic observation is `inconclusive`.
- Temporary fetch/provider errors and malformed model output are `retryable`; the fourth committed retryable review becomes terminal `review_exhausted`.
- Invalid artifact or schema conditions become `invalid_artifact`.

Leader and validators independently fetch and assess. For an authorization-bearing result (`affected` or `not_affected`), they must agree exactly on all four material semantic fields, the deterministic exact-fixed-version match, and be within 20 confidence points. Rationale may differ. For `inconclusive`, a confidence gap above 20 fails equivalence; otherwise differing semantic subfields are accepted because the outcome grants no authorization. Bounded retryable/invalid-artifact codes and identity outcomes must match exactly. Failed consensus/reverted transactions do not persist a review count.

The state getters preserve the reason for a non-authorizing identity result. Missing package, ecosystem mismatch, and version mismatch expose `package_match=no`; ambiguous inventory exposes `package_match=unclear`; a proposal/advisory identity mismatch exposes `identity_status=advisory_mismatch`, `evidence_quality=no`, and `contradiction=yes`.

## State and access

`pending` may transition to a review outcome, `retryable`, `invalid_artifact`, or proposer-only `cancelled`. `retryable` may be reviewed again up to four committed outcomes, or cancelled by the proposer. On the fourth committed retryable outcome, it becomes `review_exhausted` and is terminal. All review outcomes are terminal; no re-review or cancellation follows them. Case IDs are namespaced by proposer. Only the proposer and designated consumer may review; only the proposer may cancel. A proposer may register at most 64 cases for the lifetime of that address. Cancellation does not reclaim this cap or delete historical state.

## Security boundaries and limitations

Hash commitments prevent substitution after proposal but do not establish who created or published the bytes. The prompt treats artifact contents as untrusted JSON-escaped data; this is a mitigation, not a guarantee against model prompt injection. Confidence is model-supplied, not calibrated. Semantic judgments may be wrong or inconclusive.

HTTPS admission rejects malformed authority syntax and obvious local/internal hostnames, but the contract cannot guarantee DNS resolution safety, prevent rebinding, or establish redirects followed by the web runtime. The 16,000-byte check is applied after the runtime returns the response body, so it bounds processing, not necessarily network/runtime buffering. External host and model-provider availability can produce retryable outcomes. Consensus may fail or remain unresolved; there is no forced leader answer or safety-weakening fallback.

Patchscope neither authenticates publishers nor proves that a package is safe, discovers a machine's dependencies, executes remediation, manages permissions, holds funds, or controls a downstream application. Integrators must independently decide how to act on terminal contract results.
