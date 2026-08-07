from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from contextproof.evaluator import Decision, evaluate_context
from contextproof.federation import (
    CONTEXT_ENVELOPE_SCHEMA_SHA256,
    NO_DOWNSTREAM_AUTHORITY_LIMITATION,
    FederationEnvelopeError,
    canonical_envelope_sha256,
    evaluate_federated_context_envelope,
    is_envelope_expired,
    verify_envelope_sha256,
)
from evals.run_live import build_case_repository

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = ROOT / "context"
SCHEMA_PATH = ROOT / "federation/fet-001/schemas/context-envelope.v0.1.schema.json"
FIXTURES_PATH = ROOT / "federation/fet-001/fixtures/producer-envelopes.v0.1.json"
CREATED_AT = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)
EXPIRES_AT = CREATED_AT + timedelta(hours=1)


def _policy_digest(contract_root: Path = CONTRACT_ROOT) -> str:
    return hashlib.sha256((contract_root / "policy.json").read_bytes()).hexdigest()


def _evaluate(
    repository_root: Path,
    *,
    contract_root: Path = CONTRACT_ROOT,
    **overrides: object,
):
    arguments = {
        "subject_ref": "synthetic:orion-release",
        "purpose_id": "release-publish",
        "purpose_description": (
            "Evaluate context for publishing the synthetic release."
        ),
        "audience": ("release-operator",),
        "created_at": CREATED_AT,
        "expires_at": EXPIRES_AT,
    }
    arguments.update(overrides)
    return evaluate_federated_context_envelope(
        repository_root, contract_root=contract_root, **arguments
    )


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | set().union(*(_all_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value))
    return set()


def _assert_schema_conformant(envelope: object) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    payload = envelope.to_dict()
    assert list(Draft202012Validator(schema).iter_errors(payload)) == []


def test_vendored_schema_is_content_addressed_to_frozen_protocol() -> None:
    actual = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
    assert actual == CONTEXT_ENVELOPE_SCHEMA_SHA256


def test_public_producer_fixtures_validate_and_reproduce_digests() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    document = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))

    assert document["trial_id"] == "FET-001"
    assert document["fixture_class"] == "public-development"
    assert document["context_envelope_schema_sha256"] == (
        CONTEXT_ENVELOPE_SCHEMA_SHA256
    )
    assert {fixture["case_id"] for fixture in document["fixtures"]} == {
        "FET001-DEV-001",
        "FET001-DEV-003",
        "FET001-DEV-008",
    }
    for fixture in document["fixtures"]:
        assert list(validator.iter_errors(fixture["envelope"])) == []
        assert (
            canonical_envelope_sha256(fixture["envelope"])
            == (fixture["envelope_sha256"])
        )


def test_ready_report_builds_schema_conformant_bounded_envelope(
    complete_repository: Path,
) -> None:
    report = evaluate_context(complete_repository, contract_root=CONTRACT_ROOT)
    envelope = _evaluate(complete_repository)

    assert report.decision == Decision.READY
    _assert_schema_conformant(envelope)
    assert envelope.subject_scope == (report.target_release,)
    assert envelope.decision == "READY"
    assert envelope.trust_state == "verified"
    assert envelope.policy_refs[0].id == report.policy_id
    assert envelope.policy_refs[0].sha256 == _policy_digest()
    assert envelope.context_authority_refs[0].id == (
        report.contract_trust.trust_root_id
    )
    assert envelope.context_authority_refs[0].sha256 == (
        report.contract_trust.trust_root_digest.removeprefix("sha256:")
    )
    assert {item.id for item in envelope.evidence_refs} == {
        item.evidence_id for item in report.evidence
    }
    assert NO_DOWNSTREAM_AUTHORITY_LIMITATION in envelope.limitations
    assert {
        "permission",
        "authorization",
        "authorized_effects",
        "downstream_permission",
    }.isdisjoint(_all_keys(envelope.to_dict()))


def test_wrapper_is_deterministic_and_canonicalizes_set_like_inputs(
    complete_repository: Path,
) -> None:
    first = _evaluate(
        complete_repository,
        audience=("release-operator", "auditor"),
        limitations=("Visible limitation", "Another limitation"),
        disagreements=("Disputed provenance", "Incomplete witness"),
    )
    second = _evaluate(
        complete_repository,
        audience=("auditor", "release-operator", "auditor"),
        limitations=("Another limitation", "Visible limitation"),
        disagreements=("Incomplete witness", "Disputed provenance"),
    )

    assert first.to_dict() == second.to_dict()
    assert first.envelope_sha256 == second.envelope_sha256
    assert first.disagreements == ("Disputed provenance", "Incomplete witness")


def test_integrity_check_detects_post_export_mutation(
    complete_repository: Path,
) -> None:
    envelope = _evaluate(complete_repository)
    claimed = envelope.envelope_sha256
    modified = envelope.to_dict()
    modified["purpose"]["id"] = "release-analysis"

    assert verify_envelope_sha256(envelope, claimed)
    assert not verify_envelope_sha256(modified, claimed)
    assert not verify_envelope_sha256(envelope, "not-a-digest")


def test_canonicalization_rejects_floating_point_values(
    complete_repository: Path,
) -> None:
    modified = _evaluate(complete_repository).to_dict()
    modified["floating_value"] = 1.0

    with pytest.raises(FederationEnvelopeError, match="floating-point"):
        canonical_envelope_sha256(modified)
    assert not verify_envelope_sha256(modified, "0" * 64)


def test_expiry_boundary_is_closed_at_expires_at(
    complete_repository: Path,
) -> None:
    envelope = _evaluate(complete_repository)

    assert not is_envelope_expired(envelope, at=EXPIRES_AT - timedelta(seconds=1))
    assert is_envelope_expired(envelope, at=EXPIRES_AT)
    assert is_envelope_expired(envelope, at=EXPIRES_AT + timedelta(seconds=1))


def test_hold_preserves_missing_evidence_without_promoting_disposition(
    complete_repository: Path,
) -> None:
    (complete_repository / "evidence/security-review.json").unlink()
    report = evaluate_context(complete_repository, contract_root=CONTRACT_ROOT)
    envelope = _evaluate(complete_repository)

    assert report.decision == Decision.HOLD
    _assert_schema_conformant(envelope)
    assert envelope.decision == "HOLD"
    assert "required governed evidence is absent" in envelope.trust_issues
    assert any("unresolved requirements" in item for item in envelope.limitations)


def test_indeterminate_report_retains_stale_state_and_report_evidence(
    tmp_path: Path,
) -> None:
    case_root = build_case_repository("stale_policy", tmp_path / "stale")
    envelope = _evaluate(
        case_root,
        contract_root=case_root / "context",
        purpose_description="Evaluate the synthetic release.",
    )

    assert envelope.decision == "INDETERMINATE"
    _assert_schema_conformant(envelope)
    assert envelope.trust_state == "stale"
    assert envelope.evidence_refs[0].id == "context-report"
    assert any("cannot support" in item for item in envelope.limitations)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"subject_ref": "person:real"}, "synthetic reference"),
        ({"purpose_id": "Release Publish"}, "purpose_id"),
        ({"audience": ()}, "at least one"),
        ({"audience": "release-operator"}, "iterable of strings"),
        ({"expires_at": CREATED_AT}, "later than"),
    ],
)
def test_invalid_scope_and_lifetime_fail_closed(
    complete_repository: Path, overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(FederationEnvelopeError, match=message):
        _evaluate(complete_repository, **overrides)


def test_unrepresentable_missing_trust_state_fails_closed(
    complete_repository: Path, tmp_path: Path
) -> None:
    contracts = tmp_path / "context"
    shutil.copytree(CONTRACT_ROOT, contracts)
    (contracts / "trust-root.json").unlink()

    with pytest.raises(FederationEnvelopeError, match="not representable"):
        _evaluate(
            complete_repository,
            contract_root=contracts,
            purpose_description="Evaluate the synthetic release.",
        )


def test_high_level_evaluator_wraps_the_v02_decision(
    complete_repository: Path,
) -> None:
    envelope = evaluate_federated_context_envelope(
        complete_repository,
        contract_root=CONTRACT_ROOT,
        subject_ref="synthetic:orion-release",
        purpose_id="release-publish",
        purpose_description="Evaluate the synthetic release.",
        audience=("release-operator",),
        created_at=CREATED_AT,
        expires_at=EXPIRES_AT,
    )

    assert envelope.decision == "READY"
    assert verify_envelope_sha256(envelope, envelope.envelope_sha256)
