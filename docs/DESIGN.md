# Patchscope design

Patchscope answers a narrow question: does a specific package/version in a submitted inventory fall within a submitted advisory’s explicitly described scope?

## Trust boundaries

The proposer selects the package identity, version, inventory URL/hash, advisory identifier, advisory URL/hash, summary, and consumer. These are claims, not identity proofs. The contract fetches both artifacts, verifies exact raw-byte SHA-256 before UTF-8 decoding, and passes only verified text plus the declared package/version to independent validators as untrusted quoted data. Instructions embedded in source artifacts are not reviewer instructions.

## Decision semantics

The structured observation contains `package_match`, `affected_version`, `evidence_quality`, `contradiction`, `confidence`, and `rationale`. The contract validates the exact bounded schema. It derives:

- `affected` only for package match yes, affected version yes, evidence quality yes, contradiction no, and confidence >= 80;
- `not_affected` only when evidence quality is yes, contradiction no, confidence >= 80, and either the package or version is explicitly outside scope;
- `inconclusive` for all other valid observations;
- `retryable` for temporary fetch/provider failures or malformed model output;
- `invalid_artifact` for invalid HTTP bodies, size/encoding errors, or hash mismatch.

Validators must agree on the derived state. For `affected` and `not_affected`, all four material fields must match exactly and confidence must be within 20 points. For `inconclusive`, a confidence gap above 20 fails equivalence; differing explanations or semantic subfields remain safe because neither result authorizes a downstream action. Rationale strings are never compared and never influence authorization. Error states must agree on the bounded error code.

## State machine

`pending -> affected | not_affected | inconclusive | retryable | invalid_artifact | cancelled`

`retryable -> affected | not_affected | inconclusive | retryable | invalid_artifact | cancelled`

Cancellation is proposer-only and permitted only before a terminal review result. Reviews are authorized for the proposer or designated consumer and capped at four per case. Case identifiers are namespaced by proposer.

## Non-goals and limitations

Patchscope does not discover dependencies, prove publisher identity, establish advisory authenticity, execute remediation, or guarantee that a package is safe. HTTPS validation cannot eliminate DNS rebinding or redirect risks, and remote sources or model execution may be unavailable. No escrow or funds are held.

