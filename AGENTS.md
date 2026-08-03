# Repository instructions

- Keep the deterministic evaluator independent of OpenAI and all other model providers.
- Treat files under `context/` as governed contracts and files under `demo/repository/` as evidence.
- Agent code may translate questions and summarize tool output; it may not invent facts or override a policy decision.
- Never commit `.env.local`, API keys, or generated live-eval results.
- Before finishing a change, run `python -m pytest` and `python -m ruff check .` from the project environment.
