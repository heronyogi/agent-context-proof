# Federation contracts

## Current dependency surface

This repository is independently runnable. Its manifest declares no federated
runtime-system or evaluation-system dependency.

## Provided artifact

`governed-repository-decision` v0.2 is stable within this experiment. A decision
is meaningful only with its trust state, policy, evidence paths, content
digests, limitations, and exact implementation boundary.

The artifact reports a bounded repository decision. It does not grant
permission to another system or establish that the declared authority is
legitimate outside the experiment.

## Future authority consumer

A future authority-integrity adapter may accept this system's artifact. The
consumer must preserve its version, purpose, trust state, evidence references,
limitations, and expiry when present. The consumer remains responsible for:

- establishing purpose-specific permission for every proposed effect;
- refusing incompatible, expired, disputed, or unverifiable artifacts;
- preserving unknown or indeterminate state; and
- observing and reporting its own consequential effects.

A `READY` repository decision cannot be silently promoted into permission to
retain, disclose, recommend, rank, or act.

## Failure behavior

An interface failure does not rewrite this system's evidence or result. A
consumer may continue through an independent path only when that path has
sufficient authority and evidence of its own.

The federation-wide rules live in
[Agent Governance Systems](https://github.com/heronyogi/agent-governance-systems).
