from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from contextproof.agent import DEFAULT_PROMPT_PATH
from contextproof.cli import discover_project_root
from contextproof.evaluator import (
    ContractTrustState,
    Decision,
    IdentityStatus,
    evaluate_context,
    load_identity,
    resolve_release_identity,
)
from evals.run_live import (
    PACKET_BASELINE_INSTRUCTIONS,
    _text_digest,
    build_case_repository,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = PROJECT_ROOT / "context"


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _reissue_contract(contracts: Path, contract_name: str) -> None:
    contract_path = contracts / contract_name
    trust_path = contracts / "trust-root.json"
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    digest = f"sha256:{hashlib.sha256(contract_path.read_bytes()).hexdigest()}"
    next(item for item in trust["contracts"] if item["path"] == contract_name)[
        "sha256"
    ] = digest
    _write_json(trust_path, trust)


def test_release_aliases_resolve_to_one_identity() -> None:
    identity = load_identity(CONTRACT_ROOT)
    result = resolve_release_identity(
        ["Orion 1.0.0", "orion-service-v1.0.0"], identity
    )
    assert result.status == IdentityStatus.ALIAS
    assert result.canonical_id == "release:orion:1.0.0"


def test_complete_repository_is_ready(complete_repository: Path) -> None:
    report = evaluate_context(complete_repository, contract_root=CONTRACT_ROOT)
    assert report.decision == Decision.READY
    assert report.contract_trust.state == ContractTrustState.VERIFIED
    assert report.contract_trust.issues == ()
    assert len(report.contract_trust.verified_contract_paths) == 4
    assert all(item.state.value == "satisfied" for item in report.requirements)


def test_missing_required_evidence_holds(complete_repository: Path) -> None:
    (complete_repository / "evidence" / "security-review.json").unlink()
    report = evaluate_context(complete_repository, contract_root=CONTRACT_ROOT)
    assert report.decision == Decision.HOLD
    requirement = next(
        item
        for item in report.requirements
        if item.requirement_id == "requirement:security-review"
    )
    assert requirement.state.value == "missing"


def test_malformed_evidence_fails_closed(complete_repository: Path) -> None:
    (complete_repository / "evidence" / "test-run.json").write_text(
        "not-json\n", encoding="utf-8"
    )
    report = evaluate_context(complete_repository, contract_root=CONTRACT_ROOT)
    assert report.decision == Decision.INDETERMINATE


def test_report_digest_is_stable(complete_repository: Path) -> None:
    first = evaluate_context(complete_repository, contract_root=CONTRACT_ROOT)
    second = evaluate_context(complete_repository, contract_root=CONTRACT_ROOT)
    assert first.report_digest == second.report_digest


def test_unsafe_evidence_path_fails_closed(
    complete_repository: Path, tmp_path: Path
) -> None:
    contracts = tmp_path / "context"
    shutil.copytree(CONTRACT_ROOT, contracts)
    policy_path = contracts / "policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["requirements"][0]["source"] = "../outside"
    _write_json(policy_path, policy)
    _reissue_contract(contracts, "policy.json")
    report = evaluate_context(complete_repository, contract_root=contracts)
    requirement = next(
        item
        for item in report.requirements
        if item.requirement_id == "requirement:artifact-bytes"
    )
    assert requirement.state.value == "indeterminate"
    assert report.decision == Decision.INDETERMINATE


def test_policy_target_must_resolve(complete_repository: Path, tmp_path: Path) -> None:
    contracts = tmp_path / "context"
    shutil.copytree(CONTRACT_ROOT, contracts)
    policy_path = contracts / "policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["target_references"] = ["unknown release"]
    _write_json(policy_path, policy)
    _reissue_contract(contracts, "policy.json")
    report = evaluate_context(complete_repository, contract_root=contracts)
    assert report.decision == Decision.INDETERMINATE
    assert report.contract_trust.state == ContractTrustState.INVALID
    assert "policy target does not match" in report.contract_trust.issues[0]


def test_reissued_incomplete_ontology_fails_closed(
    complete_repository: Path, tmp_path: Path
) -> None:
    contracts = tmp_path / "context"
    shutil.copytree(CONTRACT_ROOT, contracts)
    ontology_path = contracts / "ontology.json"
    ontology = json.loads(ontology_path.read_text(encoding="utf-8"))
    ontology["allowed_relations"] = []
    _write_json(ontology_path, ontology)
    _reissue_contract(contracts, "ontology.json")
    report = evaluate_context(complete_repository, contract_root=contracts)
    assert report.decision == Decision.INDETERMINATE
    assert report.contract_trust.state == ContractTrustState.INVALID
    assert "ontology omits a required relation" in report.contract_trust.issues


@pytest.mark.parametrize(
    ("fixture", "decision", "trust_state"),
    [
        ("tampered_policy", Decision.INDETERMINATE, ContractTrustState.INVALID),
        ("stale_policy", Decision.INDETERMINATE, ContractTrustState.STALE),
        ("unauthorized_owner", Decision.INDETERMINATE, ContractTrustState.INVALID),
        ("ambiguous_identity", Decision.INDETERMINATE, ContractTrustState.AMBIGUOUS),
        ("forged_security", Decision.HOLD, ContractTrustState.VERIFIED),
    ],
)
def test_hostile_governance_fixtures_fail_closed(
    tmp_path: Path,
    fixture: str,
    decision: Decision,
    trust_state: ContractTrustState,
) -> None:
    root = build_case_repository(fixture, tmp_path / fixture)
    report = evaluate_context(root, contract_root=root / "context")
    assert report.decision == decision
    assert report.contract_trust.state == trust_state
    if trust_state != ContractTrustState.VERIFIED:
        assert report.decision != Decision.READY
        assert report.requirements == ()


def test_published_v01_proof_result_is_coherent() -> None:
    result = json.loads(
        (PROJECT_ROOT / "docs" / "proof-result.v0.1.json").read_text(
            encoding="utf-8"
        )
    )
    assert result["proof_pass"] is True
    assert result["governed_passes"] == result["case_count"] == 3
    assert result["context_advantage_cases"] >= 1
    assert all(item["governed_pass"] for item in result["cases"])
    assert result["schema_version"] == "agent-context-proof-result-v0.1.0"
    assert all(
        str(item["oracle_report_digest"]).startswith("sha256:")
        for item in result["cases"]
    )


def test_v02_proof_result_is_bound_to_current_cases_and_trust_root(
    tmp_path: Path,
) -> None:
    result = json.loads(
        (PROJECT_ROOT / "docs" / "proof-result.v0.2.json").read_text(
            encoding="utf-8"
        )
    )
    case_digest = "sha256:" + hashlib.sha256(
        (PROJECT_ROOT / "evals" / "cases.jsonl").read_bytes()
    ).hexdigest()
    trust_digest = "sha256:" + hashlib.sha256(
        (CONTRACT_ROOT / "trust-root.json").read_bytes()
    ).hexdigest()
    assert result["schema_version"] == "agent-context-proof-result-v0.2.2"
    assert result["case_manifest_sha256"] == case_digest
    assert result["trust_root_sha256"] == trust_digest
    prompt_digest = "sha256:" + hashlib.sha256(
        DEFAULT_PROMPT_PATH.read_bytes()
    ).hexdigest()
    assert result["governed_prompt_sha256"] == prompt_digest
    assert result["repository_packet_instructions_sha256"] == _text_digest(
        PACKET_BASELINE_INSTRUCTIONS
    )
    assert result["proof_pass"] is True
    assert result["fixed_case_count"] == 8
    assert result["repeat_count"] == 3
    assert result["run_observations_per_path"] == 24
    assert result["governed_metrics"]["observed_exact_matches"] == 24
    assert result["governed_synthetic_hostile_false_ready_observations"] == 0
    assert all(
        item["governed_repeat_exact_matches"] == 3 for item in result["cases"]
    )
    assert all(len(set(item["governed_decisions"])) == 1 for item in result["cases"])
    metric_keys = {
        *result["governed_metrics"],
        *result["repository_packet_metrics"],
    }
    assert not any("ci95" in key or "wilson" in key for key in metric_keys)
    assert result["result_revision"]["model_calls_reexecuted"] is True

    manifest = {
        item["case_id"]: item
        for item in (
            json.loads(line)
            for line in (PROJECT_ROOT / "evals" / "cases.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        )
    }
    for recorded in result["cases"]:
        case = manifest[recorded["case_id"]]
        root = build_case_repository(case["fixture"], tmp_path / case["case_id"])
        report = evaluate_context(root, contract_root=root / "context")
        assert recorded["oracle_decision"] == report.decision.value
        assert recorded["oracle_trust_state"] == report.contract_trust.state.value
        assert recorded["oracle_report_digest"] == report.report_digest


def test_cli_discovers_checkout_from_nested_directory() -> None:
    assert discover_project_root(PROJECT_ROOT / "demo" / "repository") == PROJECT_ROOT
