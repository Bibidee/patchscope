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

The preflight is fail-fast: exactly one deployable contract source, Python compilation, the full test suite, GenVM lint, and schema generation in a temporary location followed by byte-for-byte comparison with the committed ABI artifact. A successful local gate is not deployment evidence.

## Deployment evidence required

Before deployment, freeze the source and record its raw SHA-256 and commit. Deploy only that exact source to GenLayer StudioNet (chain ID 61999) through a project-authorized signer. Verify a finalized successful deployment, record `get_info()`, retrieve the deployed source using a supported raw-source interface, and compare the bytes exactly. Then perform and record proposal, review, and terminal-state reads. A deployment address must not be called current until these checks have actually succeeded.

No signer was authorized for this release pass. No transaction was submitted and no live RPC state is claimed.
