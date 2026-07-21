#!/usr/bin/env sh
set -eu

uv sync --frozen
uv run ruff format --check .
uv run ruff check .
uv run mypy agentkernel
uv run bandit -q -r agentkernel
uv run pip-audit
uv run pytest --cov=agentkernel --cov-report=term-missing --cov-fail-under=85
uv run coverage report --fail-under=85
uv build
