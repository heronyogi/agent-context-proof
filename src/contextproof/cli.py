"""CLI for the deterministic context evaluator."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evaluator import Decision, evaluate_context_envelope


def discover_project_root(start: Path) -> Path:
    """Find a checkout containing the proof contracts and demo repository."""

    resolved = start.resolve()
    for candidate in (resolved, *resolved.parents):
        if (
            (candidate / "context" / "policy.json").is_file()
            and (candidate / "demo" / "repository").is_dir()
        ):
            return candidate
    return resolved


def main() -> int:
    project_root = discover_project_root(Path.cwd())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root", type=Path, default=project_root / "demo" / "repository"
    )
    parser.add_argument("--contract-root", type=Path, default=project_root / "context")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    envelope = evaluate_context_envelope(
        args.repository_root, contract_root=args.contract_root
    )
    if args.json:
        print(json.dumps(envelope.to_dict(), indent=2, sort_keys=True))
    else:
        report = envelope.report
        print(f"{report.decision.value.upper()}: {report.target_release}")
        print(f"report: {report.report_digest}")
        print(f"freshness: {envelope.execution_context.freshness.value}")
        for item in report.requirements:
            print(f"- {item.state.value}: {item.label}")
    if args.require_ready and envelope.report.decision != Decision.READY:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
