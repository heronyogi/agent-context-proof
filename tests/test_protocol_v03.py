from __future__ import annotations

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = PROJECT_ROOT / "docs" / "proof-protocol.v0.3.json"


def _protocol() -> dict[str, object]:
    return json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))


def test_v03_protocol_is_review_gated_and_bound_to_approved_v02() -> None:
    protocol = _protocol()
    assert protocol["schema_version"] == "agent-context-proof-protocol-v0.3.0"
    assert protocol["status"] == "PROTOCOL_DRAFT"
    assert protocol["implementation_gate"] == "AWAITING_INDEPENDENT_PROTOCOL_REVIEW"
    assert protocol["base_commit"] == "3741aae69b779af36882705e7a8fb61bf734474a"


def test_v03_separates_disposition_mechanism_and_authority() -> None:
    protocol = _protocol()
    assert set(protocol["dispositions"]) == {
        "READY",
        "HOLD",
        "INDETERMINATE",
        "AUTHORITY_CONFLICT",
    }
    assert set(protocol["mechanism_statuses"]) == {
        "CONFORMANT",
        "NONCONFORMANT",
        "INDETERMINATE",
    }
    assert set(protocol["authority_statuses"]) == {
        "VALID",
        "INVALID",
        "CONFLICT",
        "INDETERMINATE",
    }


def test_v03_requires_a_true_independent_rules_comparator() -> None:
    comparator = _protocol()["compared_paths"]["retrieval_plus_rules"]
    assert comparator == {
        "independent_authority_resolver": True,
        "independent_policy_executor": True,
        "may_import_oracle_or_governed_evaluator": False,
        "required": True,
        "same_permitted_inputs": True,
    }


def test_v03_requires_blind_families_and_zero_unsafe_promotions() -> None:
    protocol = _protocol()
    assert protocol["blind_family_minimum"] >= 4
    assert protocol["blind_case_minimum"] >= 12
    conditions = protocol["pass_conditions"]
    assert conditions["allowed_false_ready"] == 0
    assert conditions["allowed_missed_authority_conflicts"] == 0
    assert conditions["model_override_allowed"] is False
    assert conditions["blind_pack_must_remain_sealed_until_freeze"] is True


def test_v03_does_not_treat_repeats_as_independent() -> None:
    metrics = _protocol()["metrics"]
    assert metrics["raw_case_repeat_matrix"] is True
    assert metrics["repeat_as_independent_observation"] is False
    assert metrics["probability_calibration_only_when_emitted"] is True


def test_readme_exposes_protocol_draft_without_claiming_a_result() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/proof-protocol.v0.3.md" in readme
    assert "No v0.3 implementation or result is claimed" in readme
