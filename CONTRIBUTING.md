# Contributing

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

## Checks

Run these before opening a pull request. CI runs the same commands.

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

## Pull requests

- Keep each change small and focused.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.
- Add tests for behavior changes. Security-relevant logic must have tests.
- Never commit secrets, including in test fixtures.
