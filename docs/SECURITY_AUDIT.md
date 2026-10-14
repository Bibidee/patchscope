# Patchscope v0.2.0 security review

## Scope and verdict

This review covers the standalone contract, its Direct Mode tests, release preflight, and the existing StudioNet deployment evidence. The v0.2.0 changes harden exact package identity checks, strict evidence schemas, terminal retry exhaustion, and generated-ABI verification.

**Verdict: SUBMISSION READY WITH DISCLOSED LIMITATIONS.** This is a bounded release assessment, not a claim of perfect security or a guarantee of any reviewer score. Deployment and live outcomes below are the records already captured in the repository; this documentation-only correction does not submit new chain transactions.

## Findings and disposition

| Finding | Severity | Remediation / disposition | Verification |
|---|---|---|---|
| Semantic decision previously depended on an LLM to establish the installed package identity. | High | The inventory now has a bounded canonical schema and deterministic exact ecosystem/name/version matching before semantic review. Absence or mismatch is inconclusive; malformed identity data cannot authorize. | Direct Mode identity, duplicate, malformed, and decision-boundary tests. |
| Package absence or an unsupported range interpretation could be mistaken for `not_affected`. | High | `not_affected` requires deterministic verified package identity, `package_match=yes`, and an exact installed-version match in the strict advisory `fixed_versions` list. A model's `affected_version=no` alone cannot establish exclusion. | Regression tests cover exact fixed versions, missing fixed-version evidence, and affected/fixed conflicts. |
| Caller-provided advisory metadata could be mistaken for authenticated publisher identity. | Medium | Strict advisory envelope and identity matching are enforced. Publisher/reference remain explicitly caller-declared; no authenticity claim is made. | Advisory schema and identity tests; limitation documented. |
| Repeated retryable outcomes could leave a case reviewable at its review cap. | Medium | The fourth committed retryable result transitions to terminal `review_exhausted`; the getter exposes `can_review`. Failed/reverted consensus transactions do not persist an attempt count. | Direct Mode retry-exhaustion and read-state tests. |
| ABI generation could succeed without proving the committed ABI artifact was current. | Medium | Preflight generates schema in a temporary directory and compares generated JSON bytes to `artifacts/patchscope.abi.json` after normalizing platform-specific line endings. | Full preflight. |
| Obvious internal hostnames could pass the URL syntax check. | Medium | URL admission rejects malformed authorities and additional common local/internal suffixes. DNS resolution, rebinding, and redirect safety remain outside the contract's guarantee. | URL validation tests; external DNS/redirect limitations documented. |
| Regex end anchors can accept a final newline in Python, weakening canonical coordinate validation. | Medium | Package names, versions, case IDs, digests, and parsed inventory/advisory coordinates use full-string matching; invalid terminal-newline examples are regression-tested. | Direct Mode proposal, inventory, and advisory schema tests reject terminal-newline coordinates. |
| Prompt injection through fetched artifact text. | Medium | Artifacts are JSON-escaped before insertion and explicitly treated as untrusted data. This is defense-in-depth, not proof that an LLM is immune. | Hostile-artifact test confirms no approval from the supplied failing semantic result; broader model robustness remains a residual risk. |

## Other controls reviewed

- Proposal is nonpayable; the contract holds no GEN and has no payout path.
- Case IDs are namespaced by proposer; the per-proposer lifetime cap is 64 and is not freed by cancellation.
- Review is limited to the proposer or designated consumer; cancellation is proposer-only and allowed only while pending/retryable.
- Final decisions are terminal; there is no re-review path after affected, not-affected, inconclusive, invalid-artifact, exhausted, or cancelled states.
- Validator equivalence compares exact material fields for authorizing outcomes, enforces a confidence-distance bound, and ignores rationale. Divergent non-authorizing inconclusive details can agree because they cannot grant authorization.
- Persistent fields needed by nondeterministic evaluation are copied into local values before `run_nondet_unsafe`; the callback itself does not mutate contract storage.

## Recorded StudioNet deployment and source verification

The existing v0.2.0 deployment is on GenLayer StudioNet, chain ID 61999:

- Contract: [0xcB716aA160F743AEeaAB62d05743b7557fCAADdc](https://explorer-studio.genlayer.com/address/0xcB716aA160F743AEeaAB62d05743b7557fCAADdc)
- Deployment transaction: [0xbc22d7b44a2586fbb397ea578c70e17bbdc96d157463a9f1b59c91462905918b](https://explorer-studio.genlayer.com/tx/0xbc22d7b44a2586fbb397ea578c70e17bbdc96d157463a9f1b59c91462905918b)
- Recorded finality: FINALIZED / MAJORITY_AGREE; GenVM execution succeeded.
- Frozen source: v0.2.0, 32,412 bytes; SHA-256 `75a8203918d522a7b246950c95784bb70453009e87d935a4f4dc192635847106`.
- Recorded source verification: deployed code was retrieved using `gen_getContractCode`, decoded, and compared byte-for-byte with the frozen repository source: VERIFIED.

## Recorded live lifecycle outcomes

The following transaction records are also listed in [docs/DEPLOYMENT.md](DEPLOYMENT.md). Together they demonstrate successful positive and negative classification, identity mismatch, artifact-integrity failure, and pending cancellation on StudioNet.

| Scenario | Proposal transaction | Review / cancel transaction | Recorded result |
|---|---|---|---|
| `PSM-LIVE-AFFECTED-20261014-02` | [0xbce20c5b41320beec697430897feda7b0b4ccf1c8f7592e1067cbbe0aab5df5d](https://explorer-studio.genlayer.com/tx/0xbce20c5b41320beec697430897feda7b0b4ccf1c8f7592e1067cbbe0aab5df5d) | [0xb8874f4909aeba0987d7deee4d76398c64d1e999a890c4e0720d81be96392fb8](https://explorer-studio.genlayer.com/tx/0xb8874f4909aeba0987d7deee4d76398c64d1e999a890c4e0720d81be96392fb8) | `affected`, confidence 95. |
| `PSM-LIVE-FIXED-20261014-01` | [0x82637d1af53cf1c2d4ea74e729ee7b878694370125869a10656823ef2e30224d](https://explorer-studio.genlayer.com/tx/0x82637d1af53cf1c2d4ea74e729ee7b878694370125869a10656823ef2e30224d) | [0x1039149b3ef2e4fea43bcbd9cc82119ec9b088b2882f64a6b28990a1112152a7](https://explorer-studio.genlayer.com/tx/0x1039149b3ef2e4fea43bcbd9cc82119ec9b088b2882f64a6b28990a1112152a7) | `not_affected`, confidence 100; exact fixed version `4.18.0`. |
| `PSM-LIVE-ADVISORY-MISMATCH-20261014-01` | [0x3d2fbeefd60ccb2aa4fec5a560cb8530a3dec89850e35a5008351443d48ed9b6](https://explorer-studio.genlayer.com/tx/0x3d2fbeefd60ccb2aa4fec5a560cb8530a3dec89850e35a5008351443d48ed9b6) | [0xada38cc06018470a95498e05b21b78bc3c5d401a3e4f9e0f837d73a7e00d1d84](https://explorer-studio.genlayer.com/tx/0xada38cc06018470a95498e05b21b78bc3c5d401a3e4f9e0f837d73a7e00d1d84) | `inconclusive`; `identity_status=advisory_mismatch`. |
| `PSM-LIVE-HASH-MISMATCH-20261014-01` | [0x74d6b0b32d894cb23e5c1ae92457d13d9768eca113f0a9d0da7f5254f453ec28](https://explorer-studio.genlayer.com/tx/0x74d6b0b32d894cb23e5c1ae92457d13d9768eca113f0a9d0da7f5254f453ec28) | [0x44121d6324d8f84813deb64b459379da9d912934bd354f543773b8f18d042372](https://explorer-studio.genlayer.com/tx/0x44121d6324d8f84813deb64b459379da9d912934bd354f543773b8f18d042372) | `invalid_artifact`; reason `hash_mismatch`. |
| `PSM-LIVE-CANCEL-20261014-01` | [0x222b5068a1f591f24cf494ee2470801d3ee70aa7a08eb8a0bf66fb4ad4fe6fff](https://explorer-studio.genlayer.com/tx/0x222b5068a1f591f24cf494ee2470801d3ee70aa7a08eb8a0bf66fb4ad4fe6fff) | [0xf6014b3d4a1be70552586a597cd257b12dadebf467f336c81cec357a21119b85](https://explorer-studio.genlayer.com/tx/0xf6014b3d4a1be70552586a597cd257b12dadebf467f336c81cec357a21119b85) | `cancelled` from `pending`. |

The recorded local release gate reports 111 tests passed, 0 skipped, 0 failed, with preflight, GenVM lint, and ABI/schema checks passing. GitHub Actions for the current main commit `d1b1d4e2995d4a46941b0bd5d3612e7818ee0c7f` completed successfully in [run 38559518418](https://github.com/Bibidee/patchscope/actions/runs/38559518418).

## Residual risks and limitations

1. SHA-256 proves byte integrity relative to a proposer commitment, not publisher identity, advisory truth, or inventory provenance.
2. Affected-range interpretation is semantic rather than a package-manager-native parser. The contract permits a positive affected result only with independent semantic agreement; negative classification is narrower and requires an exact committed fixed-version entry. Model judgments about affected ranges may still be wrong.
3. Model confidence is not calibrated; provider or validator behavior may be unavailable, malformed, divergent, or undetermined.
4. HTTPS hostname checks cannot guarantee safe DNS resolution, prevent rebinding, or establish redirect behavior. Runtime web-access semantics remain an external dependency.
5. The response-size cap is checked after the runtime materializes the response body.
6. Prompt-injection defenses reduce risk but cannot guarantee model isolation from malicious content.
7. Case storage is append-only; the per-proposer lifetime cap bounds one address's growth but not total contract-wide storage.
8. A live unrelated-wallet authorization test has not been demonstrated. Access-control checks are covered by Direct Mode tests; this review does not claim a separate live unauthorized-caller experiment.

## Release decision

Source-level security remediation, the recorded local release gate, GenVM validation, ABI verification, passing hosted CI, the finalized StudioNet deployment, recorded live lifecycle outcomes, and byte-for-byte source parity support **SUBMISSION READY WITH DISCLOSED LIMITATIONS**. This verdict is limited to the evidence listed above. It does not imply perfect security, guaranteed semantic correctness, or a promised reviewer score.
