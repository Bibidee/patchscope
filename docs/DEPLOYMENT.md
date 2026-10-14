# Deployment status

Patchscope v0.2.0 is deployed to GenLayer StudioNet (chain ID 61999).

## Frozen source and deployment

- Contract: [0xcB716aA160F743AEeaAB62d05743b7557fCAADdc](https://explorer-studio.genlayer.com/address/0xcB716aA160F743AEeaAB62d05743b7557fCAADdc)
- Deployment transaction: [0xbc22d7b44a2586fbb397ea578c70e17bbdc96d157463a9f1b59c91462905918b](https://explorer-studio.genlayer.com/tx/0xbc22d7b44a2586fbb397ea578c70e17bbdc96d157463a9f1b59c91462905918b)
- Deployment finality: FINALIZED / MAJORITY_AGREE; GenVM execution succeeded.
- Contract version: `0.2.0`.
- Source: 32,412 bytes; SHA-256 `75a8203918d522a7b246950c95784bb70453009e87d935a4f4dc192635847106`.
- Parity: deployed code retrieved with `gen_getContractCode`, decoded, and compared byte-for-byte with the frozen source: VERIFIED.
- `get_info()`: name `Patchscope`; version `0.2.0`; min confidence 80; maximum artifact size 16,000 bytes; maximum reviews 4; maximum cases per proposer 64; exact fixed-version requirement enabled.
- Local verification: 111 passed, 0 skipped, 0 failed; preflight, GenVM lint, and ABI/schema passed. GitHub Actions checks passed for the source/fixture baseline in [run 38549819757](https://github.com/Bibidee/patchscope/actions/runs/38549819757) and [run 38556337959](https://github.com/Bibidee/patchscope/actions/runs/38556337959).

## Live StudioNet verification

The authorized `polyglot-deployer` account (`0x527da5f7022f14f7105e5f06cec1a8eff53556b5`) submitted these test cases as both proposer and designated consumer. Each successful proposal/review/cancel transaction finalized with MAJORITY_AGREE and successful leader execution.

| Case | Proposal tx | Review/cancel tx | Canonical state |
|---|---|---|---|
| `PSM-LIVE-AFFECTED-20261014-02` | [0xbce20c5b41320beec697430897feda7b0b4ccf1c8f7592e1067cbbe0aab5df5d](https://explorer-studio.genlayer.com/tx/0xbce20c5b41320beec697430897feda7b0b4ccf1c8f7592e1067cbbe0aab5df5d) | [0xb8874f4909aeba0987d7deee4d76398c64d1e999a890c4e0720d81be96392fb8](https://explorer-studio.genlayer.com/tx/0xb8874f4909aeba0987d7deee4d76398c64d1e999a890c4e0720d81be96392fb8) | `affected`, confidence 95 |
| `PSM-LIVE-FIXED-20261014-01` | [0x82637d1af53cf1c2d4ea74e729ee7b878694370125869a10656823ef2e30224d](https://explorer-studio.genlayer.com/tx/0x82637d1af53cf1c2d4ea74e729ee7b878694370125869a10656823ef2e30224d) | [0x1039149b3ef2e4fea43bcbd9cc82119ec9b088b2882f64a6b28990a1112152a7](https://explorer-studio.genlayer.com/tx/0x1039149b3ef2e4fea43bcbd9cc82119ec9b088b2882f64a6b28990a1112152a7) | `not_affected`, confidence 100; exact fixed version 4.18.0 |
| `PSM-LIVE-ADVISORY-MISMATCH-20261014-01` | [0x3d2fbeefd60ccb2aa4fec5a560cb8530a3dec89850e35a5008351443d48ed9b6](https://explorer-studio.genlayer.com/tx/0x3d2fbeefd60ccb2aa4fec5a560cb8530a3dec89850e35a5008351443d48ed9b6) | [0xada38cc06018470a95498e05b21b78bc3c5d401a3e4f9e0f837d73a7e00d1d84](https://explorer-studio.genlayer.com/tx/0xada38cc06018470a95498e05b21b78bc3c5d401a3e4f9e0f837d73a7e00d1d84) | `inconclusive`, `advisory_mismatch` |
| `PSM-LIVE-HASH-MISMATCH-20261014-01` | [0x74d6b0b32d894cb23e5c1ae92457d13d9768eca113f0a9d0da7f5254f453ec28](https://explorer-studio.genlayer.com/tx/0x74d6b0b32d894cb23e5c1ae92457d13d9768eca113f0a9d0da7f5254f453ec28) | [0x44121d6324d8f84813deb64b459379da9d912934bd354f543773b8f18d042372](https://explorer-studio.genlayer.com/tx/0x44121d6324d8f84813deb64b459379da9d912934bd354f543773b8f18d042372) | `invalid_artifact`, `hash_mismatch` |
| `PSM-LIVE-CANCEL-20261014-01` | [0x222b5068a1f591f24cf494ee2470801d3ee70aa7a08eb8a0bf66fb4ad4fe6fff](https://explorer-studio.genlayer.com/tx/0x222b5068a1f591f24cf494ee2470801d3ee70aa7a08eb8a0bf66fb4ad4fe6fff) | [0xf6014b3d4a1be70552586a597cd257b12dadebf467f336c81cec357a21119b85](https://explorer-studio.genlayer.com/tx/0xf6014b3d4a1be70552586a597cd257b12dadebf467f336c81cec357a21119b85) | `cancelled` |

Fixture SHA-256 values: affected inventory `12488d08b4a62391fc8bf1ebc4bc0ae275661b5f75917da381d2a172bafb93ad`; fixed inventory `2fc980c6404ddb919019fc48a17ddca6388c885f8c652668f9e6dd84159e688a`; advisory `a9443a5fb5055bf716f1d8113940aae6042f6145c927c72b22b5234dea67d1aa`. The pinned fixture files are under [docs/live-fixtures/v0.2.0](live-fixtures/v0.2.0). They are controlled evidence examples, not authenticated package inventories or publisher signatures.

The initial malformed CLI argument trial [finalized with a missing-arguments GenVM error](https://explorer-studio.genlayer.com/tx/0xab13670737d80187c6709680e869555262c33e320f64fc46ec60638738c22ffb); a canonical read confirmed no case was created. Corrected lifecycle writes used GenLayerJS to preserve typed hashes and address calldata. This was a CLI invocation issue, not a contract defect.

Live use of a second signer was not authorized, so an unauthorized-caller transaction was not attempted. Access-control rejection is covered by the Direct Mode test suite.

## Reproducible local release gate

Use the pinned Python dependencies in `requirements.txt` and run:

```text
python -m pytest tests -q
python scripts/preflight.py
genvm-lint check contracts/patchscope.py --json
genvm-lint schema contracts/patchscope.py --output artifacts/patchscope.abi.json
```

Preflight fails fast if exactly one deployable source, syntax, tests, lint, or schema checks fail. The v0.2.0 advisory format includes a bounded `fixed_versions` array of exact version strings; `not_affected` requires the verified installed version to equal an entry in that list.