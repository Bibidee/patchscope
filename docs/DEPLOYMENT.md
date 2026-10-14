# Deployment status

Patchscope v0.1.0 is **undeployed**. No contract address, transaction, live review, or source-parity claim is asserted.

## Release gate

Before any deployment, freeze the contract source and record its raw SHA-256. Run `python -m pytest tests -q` and `python scripts/preflight.py`. Require all Direct Mode tests, GenVM lint, and ABI/schema generation to pass. Deploy only the exact frozen source to the explicitly selected StudioNet (chain ID 61999) through an authorized signer. Verify finalized execution, call `get_info()`, retrieve deployed source through a supported raw-source method, and compare it byte-for-byte before documenting an address as current.

Live lifecycle evidence is still outstanding and must not be implied by this local release gate.
