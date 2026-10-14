# Deployment status

Patchscope v0.2.0 is **undeployed**. There is no current address, deployment transaction, live review, or deployed-source parity claim. The repository must not be presented as a deployed release.

## Pre-deployment verification

Use the pinned Python dependencies in `requirements.txt`. Run:

```text
python -m pytest tests -q
python scripts/preflight.py
genvm-lint check contracts/patchscope.py --json
genvm-lint schema contracts/patchscope.py --output artifacts/patchscope.abi.json
```

The preflight is fail-fast: exactly one deployable contract source, Python compilation, the full test suite, GenVM lint, and schema generation in a temporary location followed by JSON-byte comparison with platform-specific CRLF/LF line endings normalized against the committed ABI artifact. A successful local gate is not deployment evidence.

## Deployment evidence required

Before deployment, freeze the source and record its raw SHA-256 and commit. Deploy only that exact source to GenLayer StudioNet (chain ID 61999) through a project-authorized signer. Verify a finalized successful deployment, record `get_info()`, retrieve the deployed source using a supported raw-source interface, and compare the bytes exactly. Then perform and record proposal, review, and terminal-state reads. A deployment address must not be called current until these checks have actually succeeded.

The local CLI is installed and reports StudioNet chain ID 61999. However, no Patchscope-designated signer is confirmed unlocked: the active account is not marked unlocked in the account list, and `genlayer account show` fails with `eth_getBalance: fetch failed`. A direct DNS check for `studio.genlayer.com` returned `Access is denied` in this execution environment. No deployment or lifecycle transaction was submitted; this does not establish that StudioNet itself is globally unavailable.

The v0.2.0 advisory JSON envelope includes a bounded `fixed_versions` array of exact version strings. `not_affected` is only available when the verified installed version exactly matches one of those entries; semantic interpretation of an affected range alone cannot establish a negative result. Do not deploy clients or fixtures using the older advisory envelope without this field.
