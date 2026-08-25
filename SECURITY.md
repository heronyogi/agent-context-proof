# Security policy

## Scope

Agent Context Proof is a synthetic research project. It is not a production
authorization service, trust-root distribution system, release gate, or
security boundary.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting channel when available. Do not
open a public issue containing credentials, private data, unpublished blind
cases, or an exploit against a deployed third-party system.

## Test-data and key boundary

- Use synthetic repositories, identities, releases, contracts, and evidence.
- Never place API keys or production credentials in fixtures or issue reports.
- The Ed25519 private seeds under `tests/fixtures/` are intentionally public
  conformance data. They must never authenticate production authority.
- Keep `.env.local`, generated live-evaluation results, and sealed cases local.
- Do not run hostile-contract fixtures against systems you do not own or
  control.

## Bounded claims

A passing deterministic run establishes only the behavior of the checked-in
synthetic mechanism and exact inputs. It does not authenticate a real-world
root, establish legal authority, validate a production deployment, or prove
general agent safety.
