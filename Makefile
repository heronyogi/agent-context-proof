PYTHON ?= .venv/bin/python

.PHONY: install test lint verify demo agent eval diagrams

install:
	$(PYTHON) -m pip install ".[dev]"

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .

verify: test lint demo

demo:
	$(PYTHON) -m contextproof.cli --json

agent:
	$(PYTHON) -m contextproof.main --json

eval:
	$(PYTHON) evals/run_live.py

diagrams:
	$(PYTHON) scripts/generate_diagrams.py
