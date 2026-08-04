"""One-agent, one-tool interface over the deterministic context evaluator."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from agents import Agent, RunContextWrapper, Runner, function_tool, trace
from pydantic import BaseModel, ConfigDict, Field

from .evaluator import (
    ContractTrustState,
    Decision,
    Freshness,
    canonical_json,
    evaluate_context_envelope,
    load_trust_root,
    trusted_reference_matches,
)

DEFAULT_MODEL = "gpt-5.6-sol"
DEFAULT_PROMPT_PATH = Path(__file__).with_name("prompt.md")


class AnswerStatus(StrEnum):
    ANSWERED = "answered"
    UNSUPPORTED = "unsupported"


class AgentAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AnswerStatus
    target_release: str | None
    decision: Decision | None
    summary: str
    owner_id: str | None
    trust_state: ContractTrustState | None
    trust_issues: list[str] = Field(default_factory=list)
    freshness: Freshness | None
    report_digest: str | None
    evidence_paths: list[str] = Field(default_factory=list)
    evidence_digests: list[str] = Field(default_factory=list)
    blocking_requirements: list[str] = Field(default_factory=list)


class ToolRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requirement_id: str
    label: str
    state: str
    finding: str
    evidence_paths: list[str]
    source_digests: list[str]


class ToolPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AnswerStatus
    requested_reference: str
    supported_target: str
    decision: Decision | None = None
    owner_id: str | None = None
    trust_state: ContractTrustState | None = None
    trust_issues: list[str] = Field(default_factory=list)
    freshness: Freshness | None = None
    graph_digest: str | None = None
    report_digest: str | None = None
    requirements: list[ToolRequirement] = Field(default_factory=list)
    boundary: str


class ToolCallAudit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str
    requested_reference: str
    status: AnswerStatus
    decision: Decision | None
    trust_state: ContractTrustState | None
    report_digest: str | None
    evidence_paths: list[str] = Field(default_factory=list)
    source_digests: list[str] = Field(default_factory=list)


class TokenUsage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requests: int
    input_tokens: int
    output_tokens: int
    total_tokens: int


class AgentRunRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str
    answer: AgentAnswer
    tool_calls: list[ToolCallAudit]
    usage: TokenUsage


@dataclass
class AgentRuntime:
    repository_root: Path
    contract_root: Path
    tool_calls: list[ToolCallAudit] = field(default_factory=list)


def _instructions() -> str:
    return DEFAULT_PROMPT_PATH.read_text(encoding="utf-8")


def evaluate_release_reference(
    runtime: AgentRuntime, release_reference: str
) -> ToolPayload:
    envelope = evaluate_context_envelope(
        runtime.repository_root,
        contract_root=runtime.contract_root,
    )
    report = envelope.report
    try:
        trust_root = load_trust_root(runtime.contract_root)
    except (OSError, UnicodeError, ValueError):
        trust_root = None
    supported_target = report.target_release
    if trust_root is not None and not trusted_reference_matches(
        release_reference, trust_root
    ):
        payload = ToolPayload(
            status=AnswerStatus.UNSUPPORTED,
            requested_reference=release_reference,
            supported_target=supported_target,
            boundary=(
                "This tool evaluates only the governed Orion 1.0.0 policy and "
                "does not infer other releases."
            ),
        )
        runtime.tool_calls.append(
            ToolCallAudit(
                tool_name="inspect_release_context",
                requested_reference=release_reference,
                status=payload.status,
                decision=None,
                trust_state=None,
                report_digest=None,
                evidence_paths=[],
                source_digests=[],
            )
        )
        return payload

    evidence_by_id = {item.evidence_id: item for item in report.evidence}
    requirements = [
        ToolRequirement(
            requirement_id=item.requirement_id,
            label=item.label,
            state=item.state.value,
            finding=item.finding,
            evidence_paths=list(evidence_by_id[item.evidence_id].source_paths),
            source_digests=list(evidence_by_id[item.evidence_id].source_digests),
        )
        for item in report.requirements
    ]
    evidence_paths = sorted(
        {path for item in requirements for path in item.evidence_paths}
    )
    source_digests = sorted(
        {digest for item in requirements for digest in item.source_digests}
    )
    payload = ToolPayload(
        status=AnswerStatus.ANSWERED,
        requested_reference=release_reference,
        supported_target=report.target_release,
        decision=report.decision,
        owner_id=report.owner_id,
        trust_state=report.contract_trust.state,
        trust_issues=list(report.contract_trust.issues),
        freshness=envelope.execution_context.freshness,
        graph_digest=report.graph_digest,
        report_digest=report.report_digest,
        requirements=requirements,
        boundary=(
            "The decision covers only the declared repository policy. The model "
            "may summarize it but cannot change facts, identity, or state."
        ),
    )
    runtime.tool_calls.append(
        ToolCallAudit(
            tool_name="inspect_release_context",
            requested_reference=release_reference,
            status=payload.status,
            decision=payload.decision,
            trust_state=payload.trust_state,
            report_digest=payload.report_digest,
            evidence_paths=evidence_paths,
            source_digests=source_digests,
        )
    )
    return payload


@function_tool
def inspect_release_context(
    wrapper: RunContextWrapper[AgentRuntime], release_reference: str
) -> str:
    """Evaluate one release reference using exact governed repository evidence."""

    payload = evaluate_release_reference(wrapper.context, release_reference)
    return canonical_json(payload.model_dump(mode="json", exclude_none=True))


def build_agent(*, model: str = DEFAULT_MODEL) -> Agent[AgentRuntime]:
    return Agent[AgentRuntime](
        name="Governed repository context analyst",
        instructions=_instructions(),
        model=model,
        tools=[inspect_release_context],
        output_type=AgentAnswer,
    )


async def run_agent(
    question: str,
    *,
    repository_root: str | Path,
    contract_root: str | Path,
    model: str = DEFAULT_MODEL,
) -> AgentRunRecord:
    runtime = AgentRuntime(
        repository_root=Path(repository_root).resolve(),
        contract_root=Path(contract_root).resolve(),
    )
    with trace("Agent context proof: governed query"):
        result = await Runner.run(
            build_agent(model=model), question, context=runtime, max_turns=4
        )
    answer = result.final_output
    if not isinstance(answer, AgentAnswer):
        answer = AgentAnswer.model_validate(answer)
    usage = result.context_wrapper.usage
    return AgentRunRecord(
        model=model,
        answer=answer,
        tool_calls=runtime.tool_calls,
        usage=TokenUsage(
            requests=usage.requests,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            total_tokens=usage.total_tokens,
        ),
    )
