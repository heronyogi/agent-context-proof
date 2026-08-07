# FET-001 producer implementation

This directory implements the producer side of the frozen FET-001 v0.1
protocol. It wraps `governed-repository-decision` v0.2 in the experimental
`federated-context-envelope` v0.1 transport interface.

The wrapper is deterministic and offline. Its caller must declare the synthetic
subject, purpose, audience, creation time, and expiry. The producer derives the
subject scope, decision, trust state, policy reference, evidence references,
and Context authority reference from the governed source result.

## Authority boundary

The envelope reports Context. It contains no downstream permission,
authorization, consent, effect, ranking, recommendation, or retention field. A
`READY` value therefore cannot authorize a consumer action. Authority remains
the downstream consumer's independent responsibility.

The producer rejects inputs that cannot be represented without changing their
meaning. In particular, a source trust state absent from the frozen transport
schema fails closed instead of being relabeled.

## Canonical artifacts

The local Context-envelope schema is byte-identical to the frozen catalog
artifact and has SHA-256
`d8fc7ba77eb6172a91dc212044dc3d7670f8db8ce260cc748bfaffc8f5ce9f6d`.

The public fixture export contains only producer envelopes from three frozen
development cases: `READY`, `HOLD`, and `INDETERMINATE`. It deliberately omits
consumer permissions, requested effects, expected outcomes, and receipts.

## Verification

Offline tests verify:

- schema provenance and fixture conformance;
- canonical serialization and digest integrity;
- exact derivation of subject scope;
- deterministic set-like fields;
- expiry at the declared boundary;
- preservation of `HOLD`, `INDETERMINATE`, limitations, and disagreements;
- rejection of invalid synthetic subjects, purposes, audiences, lifetimes, and
  unrepresentable trust states; and
- absence of downstream-authority fields.

No live model, provider API, production data, external effect, sealed case, or
experimental result is part of this implementation.
