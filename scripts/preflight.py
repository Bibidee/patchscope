"""Fail-closed local release gate for Patchscope."""

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
EXPECTED = [CONTRACTS / "patchscope.py"]
SOURCES = sorted(CONTRACTS.glob("*.py"))
if SOURCES != EXPECTED:
    raise SystemExit(f"Expected exactly contracts/patchscope.py; found {[path.name for path in SOURCES]}")

for source in SOURCES:
    ast.parse(source.read_text(encoding="utf-8"), filename=str(source))

lint = shutil.which("genvm-lint") or shutil.which("genvm-lint.exe")
if not lint:
    candidate = Path(sys.executable).with_name("genvm-lint.exe" if os.name == "nt" else "genvm-lint")
    if candidate.exists():
        lint = str(candidate)
if not lint:
    raise SystemExit("genvm-lint not found; install pinned requirements")

env = os.environ.copy()
env["GENVM_VERSION"] = "v0.2.16"
local_genvm_root = ROOT / ".genvmroot"
local_runner = local_genvm_root / "runners" / "py-lib-genlayer-std" / "src" / "genlayer"
if local_runner.is_dir():
    # Supports an explicitly provisioned local SDK cache on hosts where the
    # linter's default user-cache path is inaccessible. The cache is ignored
    # and is never included in the release artifact.
    env["GENVMROOT"] = str(local_genvm_root)

def run(command):
    print("+", " ".join(str(part) for part in command), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True)


run([sys.executable, "-m", "compileall", "-q", "contracts", "tests"])
run([sys.executable, "-m", "pytest", "tests", "-q"])
run([lint, "check", str(EXPECTED[0]), "--json"])
schema = ROOT / "artifacts" / "patchscope.abi.json"
with tempfile.TemporaryDirectory(prefix="patchscope-abi-", dir=ROOT) as temporary_directory:
    generated_schema = Path(temporary_directory) / "patchscope.abi.json"
    run([lint, "schema", str(EXPECTED[0]), "--output", str(generated_schema)])
    # Python's Path.write_text in genvm-linter emits native line endings.
    # Canonicalize CRLF/LF before comparing so Windows and Linux validate the
    # same schema content without treating platform newline style as ABI.
    generated_bytes = generated_schema.read_bytes().replace(b"\r\n", b"\n")
    committed_bytes = schema.read_bytes().replace(b"\r\n", b"\n") if schema.exists() else b""
    if generated_bytes != committed_bytes:
        raise SystemExit("Generated ABI/schema differs from committed artifacts/patchscope.abi.json")
parsed = json.loads(committed_bytes.decode("utf-8"))
if not isinstance(parsed, dict) or not parsed:
    raise SystemExit("ABI/schema output was empty or invalid")
print("Patchscope preflight PASS: one deployable source, syntax, tests, GenVM lint, ABI/schema")
