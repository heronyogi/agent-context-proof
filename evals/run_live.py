#!/usr/bin/env python3
"""Compare the governed agent path with retrieval-only context."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from agents import Agent, Runner, trace
from dotenv import load_dotenv

from contextproof.agent import DEFAULT_MODEL, AgentAnswer, run_agent
from contextproof.evaluator import Decision, evaluate_context_envelope

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = PROJECT_ROOT / "evals" / "results"
TOKEN = re.compile(r"[a-z0-9][a-z0-9_.-]+")


def build_case_repository(fixture: str, target: Path) -> Path:
    shutil.copytree(PROJECT_ROOT / "demo" / "repository", target, dirs_exist_ok=True)
    shutil.copytree(PROJECT_ROOT / "context", target / "context")
    if fixture == "missing_security":
        (target / "evidence" / "security-review.json").unlink()
    elif fixture == "malformed_test":
        (target / "evidence" / "test-run.json").write_text(
            "not-json\n", encoding="utf-8"
        )
    elif fixture != "complete":
        raise ValueError(f"unknown fixture: {fixture}")
    return target


def retrieval_packet(root: Path, question: str) -> dict[str, object]:
    query_terms = set(TOKEN.findall(question.casefold()))
    candidates: list[tuple[int, str, str]] = []
    skipped = {".git", ".venv", "__pycache__", "node_modules"}
    for path in root.rglob("*"):
        if (
            not path.is_file()
            or path.name.startswith(".env")
            or skipped.intersection(path.parts)
        ):
            continue
        try:
            if path.stat().st_size > 128_000:
                continue
            body = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        relative = path.relative_to(root).as_posix()
        searchable = f"{relative}\n{body[:8000]}".casefold()
        score = sum(searchable.count(term) for term in query_terms)
        if score:
            candidates.append((score, relative, body[:1600]))
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return {
        "query": question,
        "hits": [
            {"path": path, "excerpt": excerpt}
            for _, path, excerpt in candidates[:7]
        ],
    }


async def run_retrieval_only(
    question: str, packet: dict[str, object], *, model: str
) -> AgentAnswer:
    agent = Agent(
        name="Retrieval-only repository analyst",
        instructions=(
            "Answer only from the supplied lexical retrieval packet. You have no "
            "repository tools, policy executor, identity resolver, file inventory, "
            "or path-existence oracle. Use status=answered. Use decision=ready only "
            "if every governed requirement is explicitly proven. Use hold only for "
            "an explicit conflict or explicit proof of absence. Otherwise use "
            "indeterminate. Absence from the packet is not proof that a file is "
            "missing. Cite only hit paths. Set owner, freshness, and report digest "
            "to null because retrieval does not establish them."
        ),
        model=model,
        output_type=AgentAnswer,
    )
    prompt = json.dumps(
        {"question": question, "retrieval_packet": packet}, sort_keys=True
    )
    with trace("Agent context proof: retrieval-only query"):
        result = await Runner.run(agent, prompt, max_turns=2)
    output = result.final_output
    if isinstance(output, AgentAnswer):
        return output
    return AgentAnswer.model_validate(output)


async def run_case(case: dict[str, str], *, model: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="agent-context-proof-") as directory:
        root = build_case_repository(case["fixture"], Path(directory))
        contract_root = root / "context"
        oracle = evaluate_context_envelope(root, contract_root=contract_root).report
        if oracle.decision.value != case["expected_decision"]:
            raise AssertionError(
                f"fixture {case['case_id']} expected {case['expected_decision']} "
                f"but produced {oracle.decision.value}"
            )
        governed = await run_agent(
            case["question"],
            repository_root=root,
            contract_root=contract_root,
            model=model,
        )
        packet = retrieval_packet(root, case["question"])
        retrieval = await run_retrieval_only(case["question"], packet, model=model)
        governed_pass = (
            governed.answer.decision == oracle.decision
            and governed.answer.target_release == oracle.target_release
            and governed.answer.report_digest == oracle.report_digest
            and len(governed.tool_calls) == 1
            and governed.tool_calls[0].decision == oracle.decision
            and governed.tool_calls[0].report_digest == oracle.report_digest
        )
        retrieval_pass = retrieval.decision == oracle.decision
        return {
            "case_id": case["case_id"],
            "fixture": case["fixture"],
            "oracle_decision": oracle.decision.value,
            "oracle_report_digest": oracle.report_digest,
            "governed": governed.model_dump(mode="json"),
            "governed_pass": governed_pass,
            "retrieval_only": retrieval.model_dump(mode="json"),
            "retrieval_only_pass": retrieval_pass,
            "retrieval_hit_paths": [item["path"] for item in packet["hits"]],
        }


async def run_eval(model: str) -> int:
    cases = [
        json.loads(line)
        for line in (PROJECT_ROOT / "evals" / "cases.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    results = [await run_case(case, model=model) for case in cases]
    governed_passes = sum(bool(item["governed_pass"]) for item in results)
    retrieval_passes = sum(bool(item["retrieval_only_pass"]) for item in results)
    advantage_cases = sum(
        bool(item["governed_pass"]) and not bool(item["retrieval_only_pass"])
        for item in results
    )
    retrieval_false_ready = sum(
        item["retrieval_only"]["decision"] == Decision.READY.value
        and item["oracle_decision"] != Decision.READY.value
        for item in results
    )
    proof_pass = governed_passes == len(results) and advantage_cases >= 1
    payload = {
        "schema_version": "agent-context-proof-eval-v0.1.0",
        "model": model,
        "case_count": len(results),
        "governed_passes": governed_passes,
        "retrieval_only_passes": retrieval_passes,
        "context_advantage_cases": advantage_cases,
        "retrieval_only_false_ready": retrieval_false_ready,
        "proof_pass": proof_pass,
        "cases": results,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "latest.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if proof_pass else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=DEFAULT_MODEL)
    args = parser.parse_args()
    load_dotenv(PROJECT_ROOT / ".env.local", override=False)
    if not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY is required for the live comparison eval")
    return asyncio.run(run_eval(args.model))


if __name__ == "__main__":
    raise SystemExit(main())
