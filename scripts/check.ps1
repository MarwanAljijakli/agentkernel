$ErrorActionPreference = 'Stop'

uv sync --frozen
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
uv run ruff format --check .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
uv run ruff check .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
uv run mypy agentkernel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
uv run bandit -q -r agentkernel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
uv run pip-audit
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
uv run pytest --cov=agentkernel --cov-report=term-missing --cov-fail-under=85
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
uv run coverage report --fail-under=85
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
uv build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
