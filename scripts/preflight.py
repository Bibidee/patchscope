"""Fail-closed local release gate for Patchscope."""

import ast
import json
import os
import shutil
import subprocess
import sys
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

def run(command):
    print("+", " ".join(str(part) for part in command), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True)


run([sys.executable, "-m", "compileall", "-q", "contracts", "tests"])
run([sys.executable, "-m", "pytest", "tests", "-q"])
run([lint, "check", str(EXPECTED[0]), "--json"])
schema = ROOT / "artifacts" / "patchscope.abi.json"
run([lint, "schema", str(EXPECTED[0]), "--output", str(schema)])
parsed = json.loads(schema.read_text(encoding="utf-8"))
if not isinstance(parsed, dict) or not parsed:
    raise SystemExit("ABI/schema output was empty or invalid")
print("Patchscope preflight PASS: one deployable source, syntax, tests, GenVM lint, ABI/schema")
