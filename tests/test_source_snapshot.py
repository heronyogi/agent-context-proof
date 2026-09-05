from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from test_fet001_producer import _evaluate

from contextproof import evaluator, federation
from contextproof.evaluator import ContractTrustState, Decision, evaluate_context

CONTEXT = Path(__file__).resolve().parents[1] / "context"


def _contracts(tmp_path: Path) -> Path:
    target = tmp_path / "contracts"
    shutil.copytree(CONTEXT, target)
    return target


def _block_security(repository: Path) -> Path:
    source = repository / "evidence/security-review.json"
    document = json.loads(source.read_bytes())
    document["status"] = "blocked"
    source.write_text(json.dumps(document))
    return source


def test_policy_replacement_cannot_change_already_hashed_decision(
    complete_repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contracts = _contracts(tmp_path)
    _block_security(complete_repository)
    policy_path = contracts / "policy.json"
    original_policy = policy_path.read_bytes()
    original = evaluator._read_source_bytes
    reads = []

    def replace_after_read(path: Path) -> bytes:
        raw = original(path)
        if path == policy_path:
            reads.append(path)
            replacement = json.loads(raw)
            replacement["requirements"] = [
                r
                for r in replacement["requirements"]
                if r["id"] != "requirement:security-review"
            ]
            path.write_text(json.dumps(replacement))
        return raw

    monkeypatch.setattr(evaluator, "_read_source_bytes", replace_after_read)
    report = evaluate_context(complete_repository, contract_root=contracts)
    assert report.decision == Decision.HOLD
    assert report.contract_trust.state == ContractTrustState.VERIFIED
    assert len(reads) == 1
    expected = "sha256:" + hashlib.sha256(original_policy).hexdigest()
    assert (
        dict(report.contract_trust.verified_contract_digests)["policy.json"] == expected
    )
    assert policy_path.read_bytes() != original_policy


def test_evidence_digest_and_value_share_the_same_read(
    complete_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _block_security(complete_repository)
    old_bytes = source.read_bytes()
    original = evaluator._read_source_bytes

    def replace_after_read(path: Path) -> bytes:
        raw = original(path)
        if path == source:
            replacement = json.loads(raw)
            replacement["status"] = "approved"
            path.write_text(json.dumps(replacement))
        return raw

    monkeypatch.setattr(evaluator, "_read_source_bytes", replace_after_read)
    report = evaluate_context(complete_repository, contract_root=CONTEXT)
    assert report.decision == Decision.HOLD
    item = next(
        e for e in report.evidence if e.requirement_id == "requirement:security-review"
    )
    assert item.source_digests == ("sha256:" + hashlib.sha256(old_bytes).hexdigest(),)
    assert item.observed["status"] == "blocked"


def test_federation_uses_report_policy_identity_after_replacement(
    complete_repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contracts = _contracts(tmp_path)
    expected = hashlib.sha256((contracts / "policy.json").read_bytes()).hexdigest()
    original = federation.evaluate_context

    def replace_after_evaluation(*args, **kwargs):
        report = original(*args, **kwargs)
        (contracts / "policy.json").write_text('{"replacement":true}')
        return report

    monkeypatch.setattr(federation, "evaluate_context", replace_after_evaluation)
    envelope = _evaluate(complete_repository, contract_root=contracts)
    assert envelope.policy_refs[0].sha256 == expected
    assert envelope.decision == "READY"


def test_oversized_and_nonregular_contract_sources_fail_closed(
    complete_repository: Path, tmp_path: Path
) -> None:
    contracts = _contracts(tmp_path)
    policy = contracts / "policy.json"
    policy.write_bytes(b" " * (evaluator.MAX_SOURCE_BYTES + 1))
    assert (
        evaluate_context(
            complete_repository, contract_root=contracts
        ).contract_trust.state
        == ContractTrustState.INVALID
    )
    policy.unlink()
    policy.symlink_to(CONTEXT / "policy.json")
    assert (
        evaluate_context(
            complete_repository, contract_root=contracts
        ).contract_trust.state
        == ContractTrustState.INVALID
    )
