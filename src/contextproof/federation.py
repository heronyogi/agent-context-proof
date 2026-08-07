"""Deterministic FET-001 producer for the federated Context envelope."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .evaluator import ContextReport, Decision, RequirementState, evaluate_context

FET001_ENVELOPE_SCHEMA_VERSION = "0.1.0"
FET001_TRIAL_ID = "FET-001"
FEDERATED_CONTEXT_INTERFACE = "federated-context-envelope"
FEDERATED_CONTEXT_INTERFACE_VERSION = "0.1"
PRODUCER_SYSTEM_ID = "agent-context-integrity"
PRODUCER_SYSTEM_VERSION = "0.2.2"
SOURCE_INTERFACE = "governed-repository-decision"
SOURCE_INTERFACE_VERSION = "0.2"
CONTEXT_ENVELOPE_SCHEMA_SHA256 = (
    "d8fc7ba77eb6172a91dc212044dc3d7670f8db8ce260cc748bfaffc8f5ce9f6d"
)
NO_DOWNSTREAM_AUTHORITY_LIMITATION = (
    "The decision does not grant downstream action permission."
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SYNTHETIC_REF = re.compile(r"^synthetic:[a-z0-9-]+$")
_PURPOSE_ID = re.compile(r"^[a-z][a-z0-9-]+$")
_TRANSPORTABLE_TRUST_STATES = frozenset({"verified", "invalid", "stale", "ambiguous"})


class FederationEnvelopeError(ValueError):
    """Raised when a source decision cannot be represented without widening it."""


@dataclass(frozen=True)
class DigestReference:
    id: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "sha256": self.sha256}


@dataclass(frozen=True)
class ContextAuthorityReference:
    id: str
    kind: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "kind": self.kind, "sha256": self.sha256}


@dataclass(frozen=True)
class FederatedContextEnvelope:
    """Immutable transport value; it carries Context and never grants Authority."""

    subject_ref: str
    subject_scope: tuple[str, ...]
    purpose_id: str
    purpose_description: str
    audience: tuple[str, ...]
    decision: str
    trust_state: str
    trust_issues: tuple[str, ...]
    policy_refs: tuple[DigestReference, ...]
    evidence_refs: tuple[DigestReference, ...]
    context_authority_refs: tuple[ContextAuthorityReference, ...]
    limitations: tuple[str, ...]
    disagreements: tuple[str, ...]
    created_at: str
    expires_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope_schema": FET001_ENVELOPE_SCHEMA_VERSION,
            "trial_id": FET001_TRIAL_ID,
            "transport_interface": {
                "id": FEDERATED_CONTEXT_INTERFACE,
                "version": FEDERATED_CONTEXT_INTERFACE_VERSION,
            },
            "producer": {
                "system_id": PRODUCER_SYSTEM_ID,
                "system_version": PRODUCER_SYSTEM_VERSION,
                "source_interface": {
                    "id": SOURCE_INTERFACE,
                    "version": SOURCE_INTERFACE_VERSION,
                },
            },
            "subject": {
                "ref": self.subject_ref,
                "scope": list(self.subject_scope),
            },
            "purpose": {
                "id": self.purpose_id,
                "description": self.purpose_description,
                "audience": list(self.audience),
            },
            "decision": self.decision,
            "trust": {
                "state": self.trust_state,
                "issues": list(self.trust_issues),
            },
            "policy_refs": [item.to_dict() for item in self.policy_refs],
            "evidence_refs": [item.to_dict() for item in self.evidence_refs],
            "context_authority_refs": [
                item.to_dict() for item in self.context_authority_refs
            ],
            "limitations": list(self.limitations),
            "disagreements": list(self.disagreements),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    @property
    def envelope_sha256(self) -> str:
        return canonical_envelope_sha256(self)


def _payload(
    envelope: FederatedContextEnvelope | Mapping[str, Any],
) -> Mapping[str, Any]:
    return (
        envelope.to_dict()
        if isinstance(envelope, FederatedContextEnvelope)
        else envelope
    )


def canonical_envelope_json(
    envelope: FederatedContextEnvelope | Mapping[str, Any],
) -> str:
    """Serialize an envelope using the frozen FET-001 canonical form."""

    payload = _payload(envelope)
    _reject_floating_point(payload)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_envelope_sha256(
    envelope: FederatedContextEnvelope | Mapping[str, Any],
) -> str:
    encoded = canonical_envelope_json(envelope).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_envelope_sha256(
    envelope: FederatedContextEnvelope | Mapping[str, Any], claimed_sha256: str
) -> bool:
    if not isinstance(claimed_sha256, str) or not _SHA256.fullmatch(claimed_sha256):
        return False
    try:
        actual = canonical_envelope_sha256(envelope)
    except (FederationEnvelopeError, TypeError, ValueError):
        return False
    return hmac.compare_digest(actual, claimed_sha256)


def _reject_floating_point(value: object) -> None:
    if isinstance(value, float):
        raise FederationEnvelopeError(
            "floating-point values are outside the FET-001 canonical profile"
        )
    if isinstance(value, Mapping):
        for item in value.values():
            _reject_floating_point(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_floating_point(item)


def _bare_sha256(value: str | None, label: str) -> str:
    if not isinstance(value, str):
        raise FederationEnvelopeError(f"{label} is unavailable")
    bare = value.removeprefix("sha256:")
    if not _SHA256.fullmatch(bare):
        raise FederationEnvelopeError(f"{label} is not a lowercase SHA-256 digest")
    return bare


def _nonempty(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FederationEnvelopeError(f"{label} must be a non-empty string")
    return value.strip()


def _normalized_strings(values: Iterable[str], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise FederationEnvelopeError(f"{label} must be an iterable of strings")
    normalized = []
    for value in values:
        normalized.append(_nonempty(value, label))
    return tuple(sorted(set(normalized)))


def _utc_timestamp(value: datetime, label: str) -> str:
    if not isinstance(value, datetime):
        raise FederationEnvelopeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise FederationEnvelopeError(f"{label} must be timezone-aware")
    normalized = value.astimezone(UTC)
    if normalized.microsecond:
        raise FederationEnvelopeError(f"{label} must have whole-second precision")
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc_timestamp(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (TypeError, ValueError) as exc:
        raise FederationEnvelopeError("invalid FET-001 UTC timestamp") from exc


def _evidence_references(report: ContextReport) -> tuple[DigestReference, ...]:
    references = []
    for evidence in report.evidence:
        for index, source_digest in enumerate(evidence.source_digests, start=1):
            suffix = f"#{index}" if len(evidence.source_digests) > 1 else ""
            references.append(
                DigestReference(
                    id=f"{evidence.evidence_id}{suffix}",
                    sha256=_bare_sha256(source_digest, "evidence digest"),
                )
            )
    if not references:
        references.append(
            DigestReference(
                id="context-report",
                sha256=_bare_sha256(report.report_digest, "context report digest"),
            )
        )
    return tuple(sorted(references, key=lambda item: (item.id, item.sha256)))


def _context_issues(report: ContextReport) -> tuple[str, ...]:
    issues = list(report.contract_trust.issues)
    issues.extend(
        item.finding
        for item in report.requirements
        if item.state != RequirementState.SATISFIED
    )
    return _normalized_strings(issues, "trust issue")


def _build_federated_context_envelope(
    report: ContextReport,
    *,
    policy_sha256: str,
    subject_ref: str,
    purpose_id: str,
    purpose_description: str,
    audience: Iterable[str],
    created_at: datetime,
    expires_at: datetime,
    limitations: Iterable[str] = (),
    disagreements: Iterable[str] = (),
) -> FederatedContextEnvelope:
    """Wrap one v0.2 Context decision without creating downstream authority."""

    trust_state = report.contract_trust.state.value
    if trust_state not in _TRANSPORTABLE_TRUST_STATES:
        raise FederationEnvelopeError(
            f"source trust state is not representable in FET-001 v0.1: {trust_state}"
        )

    normalized_subject = _nonempty(subject_ref, "subject_ref")
    if not _SYNTHETIC_REF.fullmatch(normalized_subject):
        raise FederationEnvelopeError("subject_ref must be a synthetic reference")
    normalized_purpose = _nonempty(purpose_id, "purpose_id")
    if not _PURPOSE_ID.fullmatch(normalized_purpose):
        raise FederationEnvelopeError("purpose_id is outside the FET-001 profile")
    normalized_audience = _normalized_strings(audience, "audience")
    if not normalized_audience:
        raise FederationEnvelopeError("audience must contain at least one value")

    created = _utc_timestamp(created_at, "created_at")
    expires = _utc_timestamp(expires_at, "expires_at")
    if _parse_utc_timestamp(created) >= _parse_utc_timestamp(expires):
        raise FederationEnvelopeError("expires_at must be later than created_at")

    decision_limitations = list(limitations)
    decision_limitations.append(NO_DOWNSTREAM_AUTHORITY_LIMITATION)
    if report.decision == Decision.HOLD:
        decision_limitations.append(
            "The source decision is HOLD; unresolved requirements remain."
        )
    elif report.decision == Decision.INDETERMINATE:
        decision_limitations.append(
            "The source decision is INDETERMINATE and cannot support "
            "downstream reliance."
        )

    return FederatedContextEnvelope(
        subject_ref=normalized_subject,
        subject_scope=(_nonempty(report.target_release, "source target"),),
        purpose_id=normalized_purpose,
        purpose_description=_nonempty(purpose_description, "purpose_description"),
        audience=normalized_audience,
        decision=report.decision.value.upper(),
        trust_state=trust_state,
        trust_issues=_context_issues(report),
        policy_refs=(
            DigestReference(
                id=_nonempty(report.policy_id, "source policy id"),
                sha256=_bare_sha256(policy_sha256, "policy digest"),
            ),
        ),
        evidence_refs=_evidence_references(report),
        context_authority_refs=(
            ContextAuthorityReference(
                id=_nonempty(
                    report.contract_trust.trust_root_id, "source trust-root id"
                ),
                kind="trust-root",
                sha256=_bare_sha256(
                    report.contract_trust.trust_root_digest, "trust-root digest"
                ),
            ),
        ),
        limitations=_normalized_strings(decision_limitations, "limitation"),
        disagreements=_normalized_strings(disagreements, "disagreement"),
        created_at=created,
        expires_at=expires,
    )


def evaluate_federated_context_envelope(
    repository_root: str | Path,
    *,
    contract_root: str | Path,
    subject_ref: str,
    purpose_id: str,
    purpose_description: str,
    audience: Iterable[str],
    created_at: datetime,
    expires_at: datetime,
    limitations: Iterable[str] = (),
    disagreements: Iterable[str] = (),
    repository_label: str = "orion-demo",
) -> FederatedContextEnvelope:
    """Evaluate governed Context, then deterministically wrap the typed result."""

    contracts = Path(contract_root)
    report = evaluate_context(
        repository_root,
        contract_root=contracts,
        repository_label=repository_label,
    )
    policy_path = contracts / "policy.json"
    try:
        policy_sha256 = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise FederationEnvelopeError("source policy contract is unavailable") from exc
    return _build_federated_context_envelope(
        report,
        policy_sha256=policy_sha256,
        subject_ref=subject_ref,
        purpose_id=purpose_id,
        purpose_description=purpose_description,
        audience=audience,
        created_at=created_at,
        expires_at=expires_at,
        limitations=limitations,
        disagreements=disagreements,
    )


def is_envelope_expired(
    envelope: FederatedContextEnvelope | Mapping[str, Any], *, at: datetime
) -> bool:
    """Return true at and after the declared expiry boundary."""

    if at.tzinfo is None or at.utcoffset() is None:
        raise FederationEnvelopeError("expiry comparison time must be timezone-aware")
    expires_at = str(_payload(envelope).get("expires_at", ""))
    return at.astimezone(UTC) >= _parse_utc_timestamp(expires_at)
