# Contributing

Contributions are welcome when they sharpen a bounded claim, make a failure
mode reproducible, or improve the independence of the evaluation.

## Before opening a change

- Read the current repository state and non-claims in [README.md](README.md).
- For v0.3 protocol work, read the [reviewer guide](docs/v0.3-review-guide.md)
  and [case-authoring contract](docs/case-authoring.v0.3.md).
- Keep all identities, repositories, releases, keys, and evidence synthetic.
- Do not include credentials, private correspondence, production data, sealed
  cases, or private derivation machinery.

## Change boundaries

Keep each pull request focused on one protocol ambiguity, evaluator behavior,
test family, documentation correction, or federation interface. State:

- the exact claim or failure mode affected;
- what is normative and what is only an example;
- whether a schema, interface, prompt, case, or result boundary changed;
- how independence and leakage risks were handled; and
- the checks that were run.

A semantic change to a frozen review target creates a successor commit. Review
evidence and approval remain bound to the earlier SHA and do not transfer.
Tests, CI, or reviewer evidence do not themselves authorize implementation,
case sealing, production use, or a real-world authority claim.

## Development

Python 3.11 or newer is required.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ".[dev]"
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python scripts/generate_authority_vectors.py --check
```

The offline suite must make no model API request. Generated live-evaluation
results remain local and must not be committed.
