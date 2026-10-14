import hashlib
import json

import pytest


CONTRACT = "contracts/patchscope.py"
INVENTORY_URL = "https://packages.example.org/inventory.txt"
ADVISORY_URL = "https://security.example.net/advisory.txt"
INVENTORY = b"pkg:npm/example-lib@1.4.2\n"
ADVISORY = b"Example advisory: example-lib versions >=1.0.0 and <1.5.0 are affected. Fixed in 1.5.0."


def digest(raw):
    return "0x" + hashlib.sha256(raw).hexdigest()


def addr(value):
    return "0x" + value.hex() if isinstance(value, bytes) else value.as_hex


def deploy(direct_vm, direct_deploy, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.check_pickling = True
    return direct_deploy(CONTRACT, sdk_version="v0.2.16")


def propose(contract, direct_bob, **overrides):
    values = {
        "case_id": "PS-001",
        "package_name": "example-lib",
        "package_version": "1.4.2",
        "inventory_url": INVENTORY_URL,
        "inventory_hash": digest(INVENTORY),
        "advisory_id": "GHSA-EXAMPLE-0001",
        "advisory_url": ADVISORY_URL,
        "advisory_hash": digest(ADVISORY),
        "summary": "Check example-lib 1.4.2 against GHSA-EXAMPLE-0001",
        "consumer": direct_bob,
    }
    values.update(overrides)
    contract.propose(**values)
    return values


def observation(**overrides):
    value = {
        "package_match": "yes",
        "affected_version": "yes",
        "evidence_quality": "yes",
        "contradiction": "no",
        "confidence": 92,
        "rationale": "The inventory identifies example-lib 1.4.2 and the advisory includes versions below 1.5.0.",
    }
    value.update(overrides)
    return value


def mocks(direct_vm, result=None, inventory=INVENTORY, advisory=ADVISORY,
          inventory_status=200, advisory_status=200):
    direct_vm.mock_web(r"packages\.example\.org/inventory\.txt", {"status": inventory_status, "body": inventory})
    direct_vm.mock_web(r"security\.example\.net/advisory\.txt", {"status": advisory_status, "body": advisory})
    direct_vm.mock_llm(r"Return one JSON object with exactly these keys: package_match", json.dumps(result or observation()))


def test_valid_proposal_persists_exact_commitments(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    values = propose(contract, direct_bob)
    row = contract.get_case("PS-001", direct_alice)
    assert row["status"] == "pending"
    assert row["proposer"].lower() == addr(direct_alice).lower()
    assert row["consumer"].lower() == addr(direct_bob).lower()
    assert row["inventory_url"] == values["inventory_url"]
    assert row["inventory_hash"] == digest(INVENTORY)
    assert row["advisory_id"] == values["advisory_id"]
    assert row["advisory_url"] == values["advisory_url"]
    assert row["advisory_hash"] == digest(ADVISORY)
    assert row["summary"] == values["summary"]
    assert row["confidence"] == 0
    assert row["rationale"] == ""
    assert contract.get_info()["version"] == "0.1.0"


def test_duplicate_case_id_rejected(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    propose(contract, direct_bob)
    with direct_vm.expect_revert("Duplicate case ID"):
        propose(contract, direct_bob)


@pytest.mark.parametrize("case_id", ["", "bad id", "../escape", "x" * 97])
def test_bad_case_id_rejected(direct_vm, direct_deploy, direct_alice, direct_bob, case_id):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    with direct_vm.expect_revert("Invalid case ID"):
        propose(contract, direct_bob, case_id=case_id)


@pytest.mark.parametrize("field,value,message", [
    ("package_name", "", "Invalid package name"),
    ("package_version", "  ", "Invalid package version"),
    ("advisory_id", "", "Invalid advisory ID"),
    ("summary", "  \n ", "Invalid summary"),
    ("inventory_hash", "0x1234", "Invalid SHA-256"),
    ("advisory_hash", "0x" + "g" * 64, "Invalid SHA-256"),
    ("inventory_url", "http://packages.example.org/a", "Invalid inventory URL"),
    ("advisory_url", "https://user@security.example.net/a", "Invalid advisory URL"),
    ("advisory_url", "https://127.0.0.1/a", "Invalid advisory URL"),
    ("advisory_url", "https://node.internal/a", "Internal host"),
    ("advisory_url", "https://[::1]/a", "Invalid advisory URL"),
])
def test_invalid_proposal_fields_rejected(direct_vm, direct_deploy, direct_alice, direct_bob, field, value, message):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    with direct_vm.expect_revert(message):
        propose(contract, direct_bob, **{field: value})


def test_summary_limit_and_normalization(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    propose(contract, direct_bob, summary="  " + ("x" * 320) + "  ")
    assert len(contract.get_case("PS-001", direct_alice)["summary"]) == 320
    with direct_vm.expect_revert("Invalid summary"):
        propose(contract, direct_bob, case_id="PS-002", summary="x" * 321)


def test_unknown_case_rejected(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    with direct_vm.expect_revert("Case not found"):
        contract.get_case("missing", direct_alice)


def test_proposer_can_cancel_pending_only(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    propose(contract, direct_bob)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("Proposer only"):
        contract.cancel("PS-001", direct_alice)
    direct_vm.sender = direct_alice
    contract.cancel("PS-001", direct_alice)
    assert contract.get_case("PS-001", direct_alice)["status"] == "cancelled"
    with direct_vm.expect_revert("Case cannot be cancelled"):
        contract.cancel("PS-001", direct_alice)


def test_reviewed_case_cannot_be_cancelled(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    propose(contract, direct_bob)
    mocks(direct_vm)
    contract.review("PS-001", direct_alice)
    with direct_vm.expect_revert("Case cannot be cancelled"):
        contract.cancel("PS-001", direct_alice)


def test_retryable_case_can_be_cancelled_by_proposer(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    propose(contract, direct_bob)
    mocks(direct_vm, result={"not": "the required schema"})
    contract.review("PS-001", direct_alice)
    assert contract.get_case("PS-001", direct_alice)["status"] == "retryable"
    contract.cancel("PS-001", direct_alice)
    assert contract.get_case("PS-001", direct_alice)["status"] == "cancelled"


def test_actual_review_reaches_affected_with_verified_artifacts(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    propose(contract, direct_bob)
    mocks(direct_vm)
    contract.review("PS-001", direct_alice)
    row = contract.get_case("PS-001", direct_alice)
    assert row["status"] == "affected"
    assert row["package_match"] == "yes"
    assert row["affected_version"] == "yes"
    assert row["evidence_quality"] == "yes"
    assert row["contradiction"] == "no"
    assert row["confidence"] == 92
    assert row["review_count"] == 1


def _capture_review_validator(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    propose(contract, direct_bob)
    mocks(direct_vm, result=observation())
    contract.review("PS-001", direct_alice)
    direct_vm.clear_mocks()
    return contract


def test_real_validator_rejects_leader_approval_validator_inconclusive(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    _capture_review_validator(direct_vm, direct_deploy, direct_alice, direct_bob)
    mocks(direct_vm, result=observation(confidence=79))
    leader_result = {"kind": "result", "observation": observation()}
    assert direct_vm.run_validator(leader_result=leader_result) is False


def test_real_validator_rejects_leader_inconclusive_validator_approval(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    _capture_review_validator(direct_vm, direct_deploy, direct_alice, direct_bob)
    mocks(direct_vm, result=observation())
    leader_result = {"kind": "result", "observation": observation(confidence=79)}
    assert direct_vm.run_validator(leader_result=leader_result) is False


def test_real_validator_accepts_approval_with_different_rationale(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    _capture_review_validator(direct_vm, direct_deploy, direct_alice, direct_bob)
    mocks(direct_vm, result=observation(rationale="Independent explanation, same scope and decision."))
    leader_result = {"kind": "result", "observation": observation()}
    assert direct_vm.run_validator(leader_result=leader_result) is True


@pytest.mark.parametrize("result,expected", [
    (observation(confidence=79), "inconclusive"),
    (observation(affected_version="no"), "not_affected"),
    (observation(package_match="no", affected_version="unclear"), "not_affected"),
    (observation(package_match="unclear"), "inconclusive"),
    (observation(evidence_quality="unclear"), "inconclusive"),
    (observation(contradiction="yes"), "inconclusive"),
])
def test_review_derives_bounded_nonapproving_outcomes(direct_vm, direct_deploy, direct_alice, direct_bob, result, expected):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    propose(contract, direct_bob)
    mocks(direct_vm, result=result)
    contract.review("PS-001", direct_alice)
    assert contract.get_case("PS-001", direct_alice)["status"] == expected


@pytest.mark.parametrize("result", [
    {"package_match": "yes"},
    {**observation(), "unexpected": "extra"},
    observation(package_match="maybe"),
    observation(confidence=True),
    observation(confidence=-1),
    observation(confidence=101),
    observation(rationale=""),
    observation(rationale="x" * 401),
])
def test_malformed_model_output_is_retryable_and_never_authorizes(direct_vm, direct_deploy, direct_alice, direct_bob, result):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    propose(contract, direct_bob)
    mocks(direct_vm, result=result)
    contract.review("PS-001", direct_alice)
    row = contract.get_case("PS-001", direct_alice)
    assert row["status"] == "retryable"
    assert row["confidence"] == 0


@pytest.mark.parametrize("inventory,advisory,inventory_status,advisory_status", [
    (b"wrong inventory", ADVISORY, 200, 200),
    (INVENTORY, b"wrong advisory", 200, 200),
    (INVENTORY, ADVISORY, 503, 200),
    (INVENTORY, ADVISORY, 200, 429),
    (INVENTORY, ADVISORY, 404, 200),
    (INVENTORY, ADVISORY, 200, 404),
    (b"", ADVISORY, 200, 200),
    (INVENTORY, b"", 200, 200),
    (b"x" * 16001, ADVISORY, 200, 200),
    (INVENTORY, b"x" * 16001, 200, 200),
    (b"\xff", ADVISORY, 200, 200),
    (INVENTORY, b"\xff", 200, 200),
])
def test_artifact_failures_never_authorize(direct_vm, direct_deploy, direct_alice, direct_bob,
                                           inventory, advisory, inventory_status, advisory_status):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    propose(contract, direct_bob)
    mocks(direct_vm, inventory=inventory, advisory=advisory,
          inventory_status=inventory_status, advisory_status=advisory_status)
    contract.review("PS-001", direct_alice)
    row = contract.get_case("PS-001", direct_alice)
    assert row["status"] in ("retryable", "invalid_artifact")
    assert row["status"] not in ("affected", "not_affected")


def test_only_parties_can_review_and_terminal_result_cannot_be_reviewed_again(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    propose(contract, direct_bob)
    direct_vm.sender = direct_charlie
    with direct_vm.expect_revert("Proposer or designated consumer only"):
        contract.review("PS-001", direct_alice)
    direct_vm.sender = direct_alice
    mocks(direct_vm)
    contract.review("PS-001", direct_alice)
    with direct_vm.expect_revert("Case is not reviewable"):
        contract.review("PS-001", direct_alice)


@pytest.mark.parametrize("left,right,expected", [
    (observation(), observation(rationale="Different but equivalent explanatory wording."), True),
    (observation(), observation(affected_version="no"), False),
    (observation(confidence=99), observation(confidence=79), False),
    (observation(confidence=90), observation(confidence=80), True),
    (observation(confidence=81), observation(confidence=79), False),
    (observation(confidence=80), observation(confidence=79), False),
])
def test_validator_equivalence_materiality(direct_vm, direct_deploy, direct_alice, left, right, expected):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    import sys

    module = sys.modules[contract.__class__.__module__]
    assert module.equivalent({"kind": "result", "observation": left},
                             {"kind": "result", "observation": right}) is expected

