# Synthetic test fixtures

Files in this directory are public, synthetic, non-production test material.

`authority-ledger.v0.3.vectors.json` intentionally contains deterministic
private-key seeds labeled `TEST_ONLY`. They exist so independent conformance
implementations can reproduce Ed25519 keys, canonical payloads, digests, and
signatures byte for byte. They must never be used to authenticate real
authority, copied into a production trust store, or treated as secrets.

`live-result-shape.json` is a synthetic shape fixture and contains no live
result data.
