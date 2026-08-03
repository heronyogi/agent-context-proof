"""CLI for the live Agents SDK context proof."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from dotenv import load_dotenv

from .agent import DEFAULT_MODEL, run_agent
from .cli import discover_project_root


def main() -> int:
    project_root = discover_project_root(Path.cwd())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "question",
        nargs="?",
        default="Is Orion 1.0.0 ready to release, and why?",
    )
    parser.add_argument(
        "--repository-root", type=Path, default=project_root / "demo" / "repository"
    )
    parser.add_argument("--contract-root", type=Path, default=project_root / "context")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    load_dotenv(project_root / ".env.local", override=False)
    record = asyncio.run(
        run_agent(
            args.question,
            repository_root=args.repository_root,
            contract_root=args.contract_root,
            model=args.model,
        )
    )
    if args.json:
        print(json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True))
    else:
        answer = record.answer
        print(f"{answer.decision or answer.status}: {answer.summary}")
        for path in answer.evidence_paths:
            print(f"- {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
