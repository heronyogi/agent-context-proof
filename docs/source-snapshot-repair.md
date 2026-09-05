# Exact source snapshot repair

This v0.2.1 implementation successor hashes and parses each contract, trust
root and evidence file from one bounded immutable byte buffer. It exposes the
verified contract digests in the report and builds FET policy references from
that report, without reopening policy paths. Historical protocols, retained
results, trust roots and FET wire schemas are unchanged. This is a v0.2 repair,
not implementation or execution of the separately gated v0.3 protocol.

Reads require close-on-exec, no-follow and nonblocking flags, reject non-regular
or over-2-MiB sources, and check descriptor identity, size and timestamps before
and after reading. Unsupported platforms fail closed. These are per-file
snapshots; they do not establish atomic contemporaneity across all repository
files, authenticate a trust root, or make an earlier snapshot current forever.

Regressions deterministically replace policy/evidence files after their read
and policy after evaluation. The returned semantic values and federation
digests stay bound to the exact bytes actually evaluated. No model or provider
execution is part of this change.
