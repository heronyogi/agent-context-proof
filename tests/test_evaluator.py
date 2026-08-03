from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from contextproof.cli import discover_project_root
from contextproof.evaluator import (
    Decision,
    IdentityStatus,
    evaluate_context,
    load_identity,
    resolve_release_identity,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = PROJECT_ROOT / "context"


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
    contracts.mkdir()
    for name in ("identity.json", "ownership.json", "ontology.json", "policy.json"):
        (contracts / name).write_bytes((CONTRACT_ROOT / name).read_bytes())
    policy_path = contracts / "policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["requirements"][0]["source"] = "../outside"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
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
    contracts.mkdir()
    for name in ("identity.json", "ownership.json", "ontology.json", "policy.json"):
        (contracts / name).write_bytes((CONTRACT_ROOT / name).read_bytes())
    policy_path = contracts / "policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["target_references"] = ["unknown release"]
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(ValueError, match="target identity"):
        evaluate_context(complete_repository, contract_root=contracts)


def test_published_proof_result_is_coherent(tmp_path: Path) -> None:
    result = json.loads(
        (PROJECT_ROOT / "docs" / "proof-result.v0.1.json").read_text(
            encoding="utf-8"
        )
    )
    assert result["proof_pass"] is True
    assert result["governed_passes"] == result["case_count"] == 3
    assert result["context_advantage_cases"] >= 1
    assert all(item["governed_pass"] for item in result["cases"])
    for item in result["cases"]:
        root = tmp_path / item["case_id"]
        shutil.copytree(PROJECT_ROOT / "demo" / "repository", root)
        if item["case_id"] == "missing_security_hold":
            (root / "evidence" / "security-review.json").unlink()
        elif item["case_id"] == "malformed_test_indeterminate":
            (root / "evidence" / "test-run.json").write_text(
                "not-json\n", encoding="utf-8"
            )
        report = evaluate_context(root, contract_root=CONTRACT_ROOT)
        assert report.decision.value == item["oracle_decision"]
        assert report.report_digest == item["oracle_report_digest"]


def test_cli_discovers_checkout_from_nested_directory() -> None:
    assert discover_project_root(PROJECT_ROOT / "demo" / "repository") == PROJECT_ROOT
