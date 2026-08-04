from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

import evals.run_live as live_harness
from contextproof.agent import (
    AgentAnswer,
    AgentRunRecord,
    AnswerStatus,
    TokenUsage,
    ToolCallAudit,
)
from contextproof.evaluator import ContractTrustState, Decision, evaluate_context
from evals.run_live import (
    _path_metrics,
    build_case_repository,
    governed_result_matches_oracle,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _matching_record(oracle_decision: Decision, root: Path) -> AgentRunRecord:
    oracle = evaluate_context(root, contract_root=root / "context")
    evidence_paths = sorted(
        {path for item in oracle.evidence for path in item.source_paths}
    )
    source_digests = sorted(
        {digest for item in oracle.evidence for digest in item.source_digests}
    )
    return AgentRunRecord(
        model="simulated-model",
        answer=AgentAnswer(
            status=AnswerStatus.ANSWERED,
            target_release=oracle.target_release,
            decision=oracle_decision,
            summary="simulated answer",
            owner_id=oracle.owner_id,
            trust_state=oracle.contract_trust.state,
            trust_issues=list(oracle.contract_trust.issues),
            freshness=None,
            report_digest=oracle.report_digest,
            evidence_paths=evidence_paths,
            evidence_digests=source_digests,
            blocking_requirements=[],
        ),
        tool_calls=[
            ToolCallAudit(
                tool_name="inspect_release_context",
                requested_reference="Orion 1.0.0",
                status=AnswerStatus.ANSWERED,
                decision=oracle.decision,
                trust_state=oracle.contract_trust.state,
                report_digest=oracle.report_digest,
                evidence_paths=evidence_paths,
                source_digests=source_digests,
            )
        ],
        usage=TokenUsage(
            requests=2,
            input_tokens=0,
            output_tokens=0,
            total_tokens=0,
        ),
    )


def test_metrics_aggregate_nested_usage_from_saved_result_shape() -> None:
    fixture = json.loads(
        (PROJECT_ROOT / "tests" / "fixtures" / "live-result-shape.json").read_text(
            encoding="utf-8"
        )
    )
    governed = _path_metrics(fixture["cases"], prefix="governed")
    packet = _path_metrics(fixture["cases"], prefix="repository_packet")

    assert governed["observed_exact_matches"] == 2
    assert governed["observed_mean_model_requests"] == 2.0
    assert governed["observed_mean_input_tokens"] == 110.0
    assert governed["observed_mean_output_tokens"] == 25.0
    assert governed["observed_mean_total_tokens"] == 135.0
    assert packet["observed_mean_model_requests"] == 1.0
    assert packet["observed_mean_total_tokens"] == 270.0


def test_metrics_mark_false_ready_rate_not_applicable_for_all_ready_subset() -> None:
    fixture = json.loads(
        (PROJECT_ROOT / "tests" / "fixtures" / "live-result-shape.json").read_text(
            encoding="utf-8"
        )
    )
    ready_only = [
        item for item in fixture["cases"] if item["oracle_decision"] == "ready"
    ]

    governed = _path_metrics(ready_only, prefix="governed")

    assert governed["observed_non_ready_run_count"] == 0
    assert governed["observed_false_ready"] == 0
    assert governed["observed_false_ready_rate"] is None


def test_run_case_result_shape_aggregates_governed_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_run_agent(
        question: str,
        *,
        repository_root: str | Path,
        contract_root: str | Path,
        model: str,
    ) -> AgentRunRecord:
        del question, contract_root, model
        root = Path(repository_root)
        oracle = evaluate_context(root, contract_root=root / "context")
        return _matching_record(oracle.decision, root)

    async def fake_run_repository_packet(
        question: str,
        packet: dict[str, object],
        *,
        model: str,
    ) -> tuple[AgentAnswer, TokenUsage]:
        del question, packet, model
        return (
            AgentAnswer(
                status=AnswerStatus.ANSWERED,
                target_release="release:orion:1.0.0",
                decision=Decision.HOLD,
                summary="simulated packet answer",
                owner_id="owner:orion-release-team",
                trust_state=ContractTrustState.VERIFIED,
                trust_issues=[],
                freshness=None,
                report_digest=None,
                evidence_paths=[],
                evidence_digests=[],
                blocking_requirements=[],
            ),
            TokenUsage(
                requests=1,
                input_tokens=20,
                output_tokens=5,
                total_tokens=25,
            ),
        )

    monkeypatch.setattr(live_harness, "run_agent", fake_run_agent)
    monkeypatch.setattr(
        live_harness,
        "run_repository_packet",
        fake_run_repository_packet,
    )
    case = {
        "case_id": "missing_security_hold",
        "split": "development",
        "fixture": "missing_security",
        "question": "Is Orion 1.0.0 ready to release, and why?",
        "expected_decision": "hold",
        "expected_trust_state": "verified",
    }

    result = asyncio.run(live_harness.run_case(case, model="simulated-model", repeat=1))

    assert "usage" not in result
    assert result["governed"]["usage"] == {  # type: ignore[index]
        "requests": 2,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
    }
    metrics = _path_metrics([result], prefix="governed")
    assert metrics["observed_exact_matches"] == 1
    assert metrics["observed_mean_model_requests"] == 2.0
    assert metrics["observed_mean_total_tokens"] == 0.0


@pytest.mark.parametrize(
    "fixture",
    ["missing_security", "malformed_test"],
)
def test_model_ready_override_is_rejected(tmp_path: Path, fixture: str) -> None:
    root = build_case_repository(fixture, tmp_path / fixture)
    oracle = evaluate_context(root, contract_root=root / "context")
    assert oracle.decision in {Decision.HOLD, Decision.INDETERMINATE}

    matching = _matching_record(oracle.decision, root)
    assert governed_result_matches_oracle(matching, oracle)

    override = matching.model_copy(
        update={
            "answer": matching.answer.model_copy(
                update={"decision": Decision.READY}
            )
        }
    )
    assert override.answer.decision == Decision.READY
    assert override.tool_calls[0].decision == oracle.decision
    assert not governed_result_matches_oracle(override, oracle)
