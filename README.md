# Patchscope

Patchscope is a standalone GenLayer Intelligent Contract for creating a hash-bound assessment of whether an exact software package version falls within the scope of a security advisory.

The proposer commits an inventory artifact and advisory artifact by HTTPS URL and SHA-256. Validators fetch and verify those exact bytes, then independently assess package identity, version scope, evidence quality, and material contradiction. The contract derives a bounded outcome in deterministic code: `affected`, `not_affected`, `inconclusive`, `retryable`, or `invalid_artifact`.

An `affected` result requires an exact package match, an explicitly affected version, usable evidence, no contradiction, confidence of at least 80, and equivalent validator decisions. Everything uncertain remains non-authorizing. Rationale is explanatory only.

## Why GenLayer

A single scanner or centralized model could selectively interpret an advisory or inventory. Patchscope uses GenLayer’s validator execution to independently fetch the same hash-committed evidence and compare bounded semantic decisions. The consensus rule ignores wording differences but rejects disagreement on the material fields or final outcome. This is evidence adjudication, not a guarantee that a package is safe or vulnerable.

## Lifecycle

`pending -> affected | not_affected | inconclusive | retryable | invalid_artifact | cancelled`

Only the proposer or designated consumer may request review. The proposer can cancel while the case is pending or retryable. Retryable cases may be reviewed again, up to the fixed review cap. Terminal decisions cannot be overwritten.

## Evidence model and limitations

- Inventory and advisory bodies are fetched as raw bytes, bounded, SHA-256 checked, then decoded as UTF-8.
- URLs must use HTTPS and obvious malformed/local host forms are rejected. Contract URL checks cannot guarantee DNS resolution, redirect behavior, or external host availability.
- Package/version semantics are not evaluated with an embedded package-manager implementation. Validators must rely on explicit evidence; ambiguous version ranges stay inconclusive.
- Consensus can disagree or become unavailable. `retryable` and `inconclusive` are deliberate safe outcomes, not approvals.
- Publisher identity and artifact authority are not independently certified by this contract.
- Patchscope does not patch software, block deployments, or replace a vulnerability scanner or security response process.

## Development

Python 3.12 is used by CI. Install pinned requirements, run `python -m pytest tests -q`, then `python scripts/preflight.py`. Preflight requires exactly one deployable contract source and performs syntax checks, genuine GenLayer Direct Mode tests, GenVM lint, and ABI/schema generation.

The contract currently has no deployment evidence and is intentionally marked **undeployed**. Do not treat local tests as proof of StudioNet behavior.

