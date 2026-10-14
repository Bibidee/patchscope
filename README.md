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

The advisory must also be a strict UTF-8 JSON envelope. It contains exactly `format`, `advisory_id`, `ecosystem`, `package_name`, `affected_versions`, `fixed_versions`, `details`, `publisher`, and `reference_url`. Its ID, ecosystem, and package name must exactly match the proposal. `fixed_versions` is a bounded list of exact version strings; it is not a range. `publisher` and `reference_url` are committed caller-declared provenance metadata, not publisher authentication. Validators interpret the stated affected-version scope; the contract does not embed ecosystem-specific version-range engines. A negative classification additionally requires the installed version to appear exactly in `fixed_versions`.

## Decision and lifecycle

- `affected` requires verified inventory and advisory identity, model fields `package_match=yes`, `affected_version=yes`, `evidence_quality=yes`, `contradiction=no`, confidence at least 80, and validator agreement. The exact installed version must not also be listed as fixed.
- `not_affected` requires the same verified identity and evidence conditions, with `affected_version=no`, `package_match=yes`, and the exact installed version present in the committed `fixed_versions` list. A semantic statement that a version is outside a range is not enough by itself.
- Package absence, ecosystem/version mismatch, ambiguous inventory, advisory identity mismatch, or uncertain semantics resolve to `inconclusive`. Read fields preserve the distinction: an inventory coordinate mismatch reports `package_match=no`, an ambiguous inventory reports `unclear`, and a mismatched advisory reports `evidence_quality=no` and `contradiction=yes` with `identity_status=advisory_mismatch`.
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
- This standalone contract has no frontend, escrow, or payouts. Verified StudioNet deployment and live-case evidence are recorded below.

## v0.2.0 StudioNet deployment and live evidence

The frozen v0.2.0 contract is deployed on GenLayer StudioNet (chain ID 61999).

- Contract: [0xcB716aA160F743AEeaAB62d05743b7557fCAADdc](https://explorer-studio.genlayer.com/address/0xcB716aA160F743AEeaAB62d05743b7557fCAADdc)
- Deployment transaction: [0xbc22d7b44a2586fbb397ea578c70e17bbdc96d157463a9f1b59c91462905918b](https://explorer-studio.genlayer.com/tx/0xbc22d7b44a2586fbb397ea578c70e17bbdc96d157463a9f1b59c91462905918b)
- Finality: FINALIZED / MAJORITY_AGREE; deployment GenVM execution succeeded.
- Source SHA-256: `75a8203918d522a7b246950c95784bb70453009e87d935a4f4dc192635847106` (32,412 bytes). Deployed code retrieved with `gen_getContractCode`, decoded, and compared byte-for-byte with the frozen repository source: VERIFIED.
- `get_info()`: Patchscope v0.2.0; `min_confidence=80`; `max_artifact_bytes=16000`; `max_reviews=4`; `max_cases_per_proposer=64`; `not_affected_requires_exact_fixed_version=true`.
- Local release gate: 111 tests passed, none skipped or failed; preflight, GenVM lint, and ABI/schema checks passed. GitHub Actions passed for the source/fixture baseline (runs [38549819757](https://github.com/Bibidee/patchscope/actions/runs/38549819757) and [38556337959](https://github.com/Bibidee/patchscope/actions/runs/38556337959)).

### Live case results

All writes were sent by the explicitly authorized `polyglot-deployer` account (`0x527da5f7022f14f7105e5f06cec1a8eff53556b5`); for this single-account demonstration it was both proposer and designated consumer. Each listed successful write finalized with MAJORITY_AGREE and successful leader execution.

| Case | Proposal transaction | Review / cancel transaction | Canonical result |
|---|---|---|---|
| `PSM-LIVE-AFFECTED-20261014-02` | [0xbce20c5b41320beec697430897feda7b0b4ccf1c8f7592e1067cbbe0aab5df5d](https://explorer-studio.genlayer.com/tx/0xbce20c5b41320beec697430897feda7b0b4ccf1c8f7592e1067cbbe0aab5df5d) | [0xb8874f4909aeba0987d7deee4d76398c64d1e999a890c4e0720d81be96392fb8](https://explorer-studio.genlayer.com/tx/0xb8874f4909aeba0987d7deee4d76398c64d1e999a890c4e0720d81be96392fb8) | `affected`, confidence 95; verified package identity, exact affected-version evidence, no contradiction. |
| `PSM-LIVE-FIXED-20261014-01` | [0x82637d1af53cf1c2d4ea74e729ee7b878694370125869a10656823ef2e30224d](https://explorer-studio.genlayer.com/tx/0x82637d1af53cf1c2d4ea74e729ee7b878694370125869a10656823ef2e30224d) | [0x1039149b3ef2e4fea43bcbd9cc82119ec9b088b2882f64a6b28990a1112152a7](https://explorer-studio.genlayer.com/tx/0x1039149b3ef2e4fea43bcbd9cc82119ec9b088b2882f64a6b28990a1112152a7) | `not_affected`, confidence 100; exact fixed version `4.18.0`. |
| `PSM-LIVE-ADVISORY-MISMATCH-20261014-01` | [0x3d2fbeefd60ccb2aa4fec5a560cb8530a3dec89850e35a5008351443d48ed9b6](https://explorer-studio.genlayer.com/tx/0x3d2fbeefd60ccb2aa4fec5a560cb8530a3dec89850e35a5008351443d48ed9b6) | [0xada38cc06018470a95498e05b21b78bc3c5d401a3e4f9e0f837d73a7e00d1d84](https://explorer-studio.genlayer.com/tx/0xada38cc06018470a95498e05b21b78bc3c5d401a3e4f9e0f837d73a7e00d1d84) | `inconclusive`; `identity_status=advisory_mismatch`. |
| `PSM-LIVE-HASH-MISMATCH-20261014-01` | [0x74d6b0b32d894cb23e5c1ae92457d13d9768eca113f0a9d0da7f5254f453ec28](https://explorer-studio.genlayer.com/tx/0x74d6b0b32d894cb23e5c1ae92457d13d9768eca113f0a9d0da7f5254f453ec28) | [0x44121d6324d8f84813deb64b459379da9d912934bd354f543773b8f18d042372](https://explorer-studio.genlayer.com/tx/0x44121d6324d8f84813deb64b459379da9d912934bd354f543773b8f18d042372) | `invalid_artifact`; rationale `hash_mismatch`. |
| `PSM-LIVE-CANCEL-20261014-01` | [0x222b5068a1f591f24cf494ee2470801d3ee70aa7a08eb8a0bf66fb4ad4fe6fff](https://explorer-studio.genlayer.com/tx/0x222b5068a1f591f24cf494ee2470801d3ee70aa7a08eb8a0bf66fb4ad4fe6fff) | [0xf6014b3d4a1be70552586a597cd257b12dadebf467f336c81cec357a21119b85](https://explorer-studio.genlayer.com/tx/0xf6014b3d4a1be70552586a597cd257b12dadebf467f336c81cec357a21119b85) | `cancelled` from `pending`. |

The immutable demonstration files are under [docs/live-fixtures/v0.2.0](docs/live-fixtures/v0.2.0). Their exact bytes are SHA-256 committed and tested on-chain: affected inventory `12488d08b4a62391fc8bf1ebc4bc0ae275661b5f75917da381d2a172bafb93ad`; fixed inventory `2fc980c6404ddb919019fc48a17ddca6388c885f8c652668f9e6dd84159e688a`; advisory `a9443a5fb5055bf716f1d8113940aae6042f6145c927c72b22b5234dea67d1aa`. These are controlled test fixtures copied from the cited advisory, not authenticated package inventories or publisher signatures; inventory provenance remains caller-declared.

A first CLI proposal-format trial, [0xab13670737d80187c6709680e869555262c33e320f64fc46ec60638738c22ffb](https://explorer-studio.genlayer.com/tx/0xab13670737d80187c6709680e869555262c33e320f64fc46ec60638738c22ffb), finalized with a missing-positional-arguments GenVM error because PowerShell grouped the argument array. A canonical read confirmed no case was created. The subsequent successful tests used GenLayerJS with separate typed arguments; this was a CLI invocation issue, not a contract change.

A second signer was not used, so live unauthorized-caller rejection was not attempted. Access-control behavior remains covered by the Direct Mode suite.

## Development and verification

Python 3.12 and the pinned dependencies in `requirements.txt` are used for CI. Run `python -m pytest tests -q` and `python scripts/preflight.py`. Preflight requires exactly one deployable source, runs syntax compilation and Direct Mode tests, runs GenVM lint and schema generation into a temporary file, and fails unless generated and committed ABI JSON match after normalizing platform-specific CRLF/LF line endings.

Deployment status is maintained in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Security findings and residual risks are in [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).
