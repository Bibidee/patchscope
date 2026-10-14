# Patchscope

Patchscope is a standalone GenLayer Intelligent Contract for assessing whether one exact installed software package version falls within a submitted security advisory's scope. It commits the inventory and advisory bytes by SHA-256, deterministically checks package coordinates, then asks independent GenLayer validators to assess advisory applicability. Contract code—not free-form model rationale—derives the final bounded state.

Patchscope is nonpayable and noncustodial. It does not scan a machine, install or patch software, authenticate an advisory publisher, or guarantee that software is safe.

## How a case works

1. The proposer supplies an ecosystem, canonical package name and exact version, inventory and advisory HTTPS URLs plus SHA-256 values, a summary, and a designated consumer.
2. The consumer or proposer can request review. Each validator fetches the committed bytes, verifies SHA-256 before UTF-8 decoding, validates the strict evidence envelopes, and independently performs the semantic scope assessment.
3. Validators must agree on the material decision fields and final outcome. The contract records `affected`, `not_affected`, `inconclusive`, `retryable`, `invalid_artifact`, `review_exhausted`, or `cancelled`.

The designated consumer is a review-authorized participant, not a payout recipient or an automatic software-control authority. Applications must independently decide what to do with a case result.

## Evidence formats

To avoid relying on an LLM to infer what package is installed, the inventory must be UTF-8 JSON with this exact shape:

```json
{"format":"patchscope-inventory-v1","packages":[{"ecosystem":"npm","name":"example-lib","version":"1.4.2"}]}
```

Supported ecosystem labels are `npm`, `pypi`, `cargo`, `nuget`, and `rubygems`. Names are lower-case canonical ASCII coordinates; Patchscope does not fold aliases. An exact, unique ecosystem/name/version match is required before semantic review. Missing, mismatched, ambiguous, duplicate, or malformed inventory records cannot produce `affected` or `not_affected`.

The advisory must also be a strict UTF-8 JSON envelope. It contains exactly `format`, `advisory_id`, `ecosystem`, `package_name`, `affected_versions`, `details`, `publisher`, and `reference_url`. Its ID, ecosystem, and package name must exactly match the proposal. `publisher` and `reference_url` are committed caller-declared provenance metadata, not publisher authentication. Validators interpret the stated version scope; the contract does not embed ecosystem-specific version-range engines.

## Decision and lifecycle

- `affected` requires verified inventory and advisory identity, model fields `package_match=yes`, `affected_version=yes`, `evidence_quality=yes`, `contradiction=no`, confidence at least 80, and validator agreement.
- `not_affected` requires the same verified identity and evidence conditions, with `affected_version=no` and `package_match=yes`.
- Package absence, ecosystem/version mismatch, ambiguous inventory, advisory identity mismatch, or uncertain semantics resolve to `inconclusive`.
- Temporary fetch/provider errors and malformed model objects are `retryable`; retryable outcomes consume one of four committed review decisions. A retryable result on the fourth review becomes terminal `review_exhausted`.
- Malformed evidence, HTTP policy errors, oversized bodies, invalid UTF-8, or hash mismatches become `invalid_artifact`.
- The proposer may cancel only while `pending` or `retryable`. Review access is limited to the original proposer and designated consumer. Case IDs are namespaced by proposer; each proposer has a lifetime cap of 64 cases.

## Why GenLayer

A single centralized verifier could selectively interpret one copy of an inventory or advisory. Patchscope binds exact artifact bytes and uses GenLayer's independent validator execution to repeat the evidence fetch and semantic assessment, then accepts only the bounded consensus result. This reduces reliance on one evaluator; it does not eliminate model error, coordinated failure, unavailable sources, or consensus failure.

## Security boundaries and limitations

- SHA-256 proves that fetched bytes match the proposal commitment; it does not prove who published them or that the source is authoritative.
- Artifact text is passed as JSON-escaped untrusted data with explicit prompt-injection instructions. Prompting and validator agreement reduce risk but cannot prove a model was uninfluenced by malicious content.
- HTTPS syntax checks reject malformed authorities and obvious local/internal names. The contract cannot resolve DNS, pin IPs, prevent DNS rebinding, or establish redirect policy. Those behaviors depend on the GenVM web runtime and must not be assumed safe without separate verification.
- The 16 KB body bound is checked after `gl.nondet.web.get` returns the response body. It prevents oversized content from being parsed or approved, but does not prove the runtime streamed or memory-bounded the download.
- Only committed review results increment the review counter. A transaction that fails consensus and reverts does not persist an attempt count; callers can retry such failed transactions at their own transaction cost.
- Cases are permanent records. The 64-case proposer cap is an intentional storage-growth limit and is not freed by cancellation or terminal review.
- Confidence is a model-supplied classification input, not a calibrated probability. Rationale is explanatory only.
- This standalone contract has no frontend, escrow, payouts, or deployment evidence at this release checkpoint.

## Development and verification

Python 3.12 and the pinned dependencies in `requirements.txt` are used for CI. Run `python -m pytest tests -q` and `python scripts/preflight.py`. Preflight requires exactly one deployable source, runs syntax compilation and Direct Mode tests, runs GenVM lint and schema generation into a temporary file, and fails unless the generated ABI bytes match the committed artifact.

Deployment status is maintained in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Security findings and residual risks are in [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).
