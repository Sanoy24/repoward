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

A live suite runs against real sandbox repositories. It is skipped by default and needs
`GITHUB_TOKEN`, `GITHUB_WRITE_TOKEN`, `REPOWARD_LIVE_REPO` and `REPOWARD_LIVE_PRIVATE_REPO`. It
merges real commits, so only point it at sandboxes:

```bash
uv run pytest -m live
```

## Pull requests

- Keep each change small and focused.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.
- Add tests for behavior changes. Security-relevant logic must have tests.
- Never commit secrets, including in test fixtures.
