from __future__ import annotations

from pathlib import Path

from contextproof.agent import (
    DEFAULT_PROMPT_PATH,
    AgentRuntime,
    AnswerStatus,
    build_agent,
    evaluate_release_reference,
)
from contextproof.evaluator import Decision

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_packaged_prompt_matches_documented_prompt() -> None:
    documented = PROJECT_ROOT / "docs" / "prompt.md"
    assert DEFAULT_PROMPT_PATH.read_bytes() == documented.read_bytes()


def test_agents_sdk_usage_types_construct() -> None:
    from agents.usage import Usage

    usage = Usage()
    assert usage.input_tokens == 0


def test_agent_exposes_one_read_only_tool() -> None:
    agent = build_agent()
    assert [tool.name for tool in agent.tools] == ["inspect_release_context"]


def test_tool_returns_exact_governed_decision(complete_repository: Path) -> None:
    runtime = AgentRuntime(
        repository_root=complete_repository,
        contract_root=PROJECT_ROOT / "context",
    )
    payload = evaluate_release_reference(runtime, "Orion 1.0.0")
    assert payload.status == AnswerStatus.ANSWERED
    assert payload.decision == Decision.READY
    assert len(runtime.tool_calls) == 1
    assert runtime.tool_calls[0].report_digest == payload.report_digest


def test_tool_refuses_unsupported_release(complete_repository: Path) -> None:
    runtime = AgentRuntime(
        repository_root=complete_repository,
        contract_root=PROJECT_ROOT / "context",
    )
    payload = evaluate_release_reference(runtime, "Orion 2.0.0")
    assert payload.status == AnswerStatus.UNSUPPORTED
    assert payload.decision is None
    assert len(runtime.tool_calls) == 1
