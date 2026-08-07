# Context integrity system

## Identity

- System ID: `agent-context-integrity`
- Repository role: `system-root`
- Public implementation: Agent Context Proof
- Federation contract: v0.1.0

## Governing question

What repository decision is supported by governed context inside a declared
trust boundary?

## Primary invariant

The evaluator cannot return `READY` when governed contracts are untrusted,
stale, ambiguous, or missing required evidence.

## Boundary

The approved evaluator checks the integrity and internal consistency of
synthetic governed contracts, applies policy-scoped repository requirements,
and returns deterministic `READY`, `HOLD`, or `INDETERMINATE` decisions with
evidence paths and digests.

It does not establish:

- whether the declared trust root is legitimate in the real world;
- factual truth beyond the governed synthetic evidence;
- permission to retain, disclose, recommend, rank, or create an effect;
- production repository security; or
- whether another system may rely on or promote its result.

The v0.3 artifacts remain a protocol draft. They do not have an evaluator or
experimental result.

## Interface

The system provides `governed-repository-decision` v0.2 as a stable artifact: a
deterministic decision with trust state, governed evidence paths, and content
digests.

The system currently consumes no federated runtime interface and has no runtime
or evaluation dependency on another registered system.

## Relationship

Agent Authority Benchmark is a sibling system. A governed repository decision
may be relevant to a future authority adapter, but it does not transfer
permission to retain, disclose, recommend, rank, or create an external effect.

See [CONTRACTS.md](CONTRACTS.md) and [system.manifest.json](system.manifest.json)
for the machine-readable declaration.

## Public IP boundary

The system is based on observable contract integrity, declared authority
coordinates, policy requirements, evidence paths, and deterministic decisions.
It does not publish or require private ontology primitives, symbolic
registries, signatures, morphologies, derivation rules, composition laws,
correspondence, identities, or sealed cases.
