# Patchscope v0.2.0 security review

## Scope and verdict

This review covers the standalone contract, its Direct Mode tests, release preflight, and release documentation. The v0.2.0 changes harden exact package identity checks, strict evidence schemas, terminal retry exhaustion, and generated-ABI verification. The contract remains undeployed; this is not a live-chain certification or a claim that external evidence is authentic.

## Findings and disposition

| Finding | Severity | Remediation / disposition | Verification |
|---|---|---|---|
| Semantic decision previously depended on an LLM to establish the installed package identity. | High | The inventory now has a bounded canonical schema and deterministic exact ecosystem/name/version matching before semantic review. Absence or mismatch is inconclusive; malformed identity data cannot authorize. | Direct Mode identity, duplicate, malformed, and decision-boundary tests. |
| Package absence could be interpreted as `not_affected`. | High | `not_affected` now requires deterministic verified package identity plus `package_match=yes`; all other valid outcomes are non-authorizing. | Regression tests assert absent/mismatched coordinates cannot produce `not_affected` or `affected`. |
| Caller-provided advisory metadata could be mistaken for authenticated publisher identity. | Medium | Strict advisory envelope and identity matching are enforced. Publisher/reference remain explicitly caller-declared; no authenticity claim is made. | Advisory schema and identity tests; limitation documented. |
| Repeated retryable outcomes could leave a case reviewable at its review cap. | Medium | The fourth committed retryable result transitions to terminal `review_exhausted`; the getter exposes `can_review`. Failed/reverted consensus transactions do not persist an attempt count. | Direct Mode retry-exhaustion and read-state tests. |
| ABI generation could succeed without proving the committed ABI artifact was current. | Medium | Preflight generates schema in a temporary directory and compares generated JSON bytes to `artifacts/patchscope.abi.json` after normalizing platform-specific line endings. | Full preflight. |
| Obvious internal hostnames could pass the URL syntax check. | Medium | URL admission rejects malformed authorities and additional common local/internal suffixes. DNS resolution, rebinding, and redirect safety remain outside the contract's guarantee. | URL validation tests; external DNS/redirect limitations documented. |
| Prompt injection through fetched artifact text. | Medium | Artifacts are JSON-escaped before insertion and explicitly treated as untrusted data. This is defense-in-depth, not proof that an LLM is immune. | Hostile artifact test confirms no approval from the supplied failing semantic result; broader model robustness remains a residual risk. |

## Other controls reviewed

- Proposal is nonpayable; the contract holds no GEN and has no payout path.
- Case IDs are namespaced by proposer; the per-proposer lifetime cap is 64 and intentionally is not freed by cancellation.
- Review is limited to the proposer or designated consumer; cancellation is proposer-only and only allowed while pending/retryable.
- Final decisions are terminal; there is no re-review path after affected, not-affected, inconclusive, invalid-artifact, exhausted, or cancelled states.
- Validator equivalence compares exact material fields for authorizing outcomes, enforces a confidence-distance bound, and ignores rationale. Divergent non-authorizing inconclusive details can agree because they cannot grant authorization.
- Persistent fields needed by nondeterministic evaluation are copied into local values before `run_nondet_unsafe`; the callback itself does not mutate contract storage.

## Residual risks

1. SHA-256 proves byte integrity relative to a proposer commitment, not publisher identity, advisory truth, or inventory provenance.
2. Version-range interpretation is semantic rather than a package-manager-native parser. Ambiguous scope should remain inconclusive, but model judgments may still be wrong.
3. Model confidence is not calibrated; provider or validator behavior may be unavailable, malformed, divergent, or undetermined.
4. HTTPS hostname checks cannot guarantee safe DNS resolution, prevent rebinding, or establish redirect behavior. Runtime web-access semantics must be independently verified.
5. The response-size cap is checked after the runtime materializes the response body.
6. Prompt-injection defenses reduce risk but cannot guarantee model isolation from malicious content.
7. Storage is append-only for cases; the lifetime cap bounds one proposer's growth, not total contract-wide storage.
8. No StudioNet deployment, live lifecycle, or source-parity verification exists for v0.2.0 at this checkpoint.

## Release decision

Source-level release checks can establish syntax, Direct Mode behavior, lint, and ABI consistency. They cannot establish live deployment, live semantic success, or deployed-source parity. Treat Patchscope as **not yet submission-ready for any requirement that demands deployment evidence** until a separately authorized deployment and live verification are completed.
