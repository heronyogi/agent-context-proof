"""Governed repository context proof."""

from .evaluator import (
    ContractTrustState,
    Decision,
    Freshness,
    RequirementState,
    evaluate_context,
    evaluate_context_envelope,
)
from .federation import (
    FederatedContextEnvelope,
    FederationEnvelopeError,
    canonical_envelope_sha256,
    evaluate_federated_context_envelope,
    is_envelope_expired,
    verify_envelope_sha256,
)

__all__ = [
    "Decision",
    "ContractTrustState",
    "Freshness",
    "RequirementState",
    "evaluate_context",
    "evaluate_context_envelope",
    "FederatedContextEnvelope",
    "FederationEnvelopeError",
    "canonical_envelope_sha256",
    "evaluate_federated_context_envelope",
    "is_envelope_expired",
    "verify_envelope_sha256",
]
