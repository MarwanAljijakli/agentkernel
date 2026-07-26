#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

COVERAGE_LANE=${AGENTKERNEL_COVERAGE_LANE:-linux}
COVERAGE_COMMIT_SHA=${AGENTKERNEL_COVERAGE_COMMIT_SHA:-$(git rev-parse HEAD)}
COVERAGE_WORKFLOW_RUN_ID=${AGENTKERNEL_COVERAGE_WORKFLOW_RUN_ID:-local}
COVERAGE_WORKFLOW_RUN_ATTEMPT=${AGENTKERNEL_COVERAGE_WORKFLOW_RUN_ATTEMPT:-1}

uv sync --frozen
uv run python scripts/coverage_evidence.py validate-context \
  --repo-root . \
  --lane "$COVERAGE_LANE" \
  --commit-sha "$COVERAGE_COMMIT_SHA" \
  --workflow-run-id "$COVERAGE_WORKFLOW_RUN_ID" \
  --workflow-run-attempt "$COVERAGE_WORKFLOW_RUN_ATTEMPT"

COVERAGE_RUN_SEGMENT="run-$COVERAGE_WORKFLOW_RUN_ID-attempt-$COVERAGE_WORKFLOW_RUN_ATTEMPT"
COVERAGE_EVIDENCE_ROOT=test-results/coverage-evidence
COVERAGE_EVIDENCE_DIR="$COVERAGE_EVIDENCE_ROOT/$COVERAGE_LANE/$COVERAGE_RUN_SEGMENT"
COVERAGE_RAW_DIR="test-results/coverage-raw/$COVERAGE_LANE/$COVERAGE_RUN_SEGMENT"
COVERAGE_DATA_FILE="$COVERAGE_RAW_DIR/.coverage"
COVERAGE_SOURCE_SNAPSHOT_FILE="$COVERAGE_RAW_DIR/source-snapshot.json"
COVERAGE_UNION_DIR="test-results/coverage-union/$COVERAGE_RUN_SEGMENT"
JUNIT_PATH="test-results/junit-$COVERAGE_LANE.xml"

uv run ruff format --check .
uv run ruff check .
uv run mypy agentkernel
uv run bandit -q -r agentkernel
uv run pip-audit
uv run python scripts/validate_traceability.py

uv run python scripts/coverage_evidence.py clean \
  --repo-root . \
  --path "$COVERAGE_EVIDENCE_DIR" \
  --path "$COVERAGE_RAW_DIR"
mkdir -p "$COVERAGE_RAW_DIR"
COVERAGE_SOURCE_SNAPSHOT_SHA256=$(uv run python scripts/coverage_evidence.py snapshot \
  --repo-root . \
  --output-file "$COVERAGE_SOURCE_SNAPSHOT_FILE" \
  --lane "$COVERAGE_LANE" \
  --commit-sha "$COVERAGE_COMMIT_SHA" \
  --workflow-run-id "$COVERAGE_WORKFLOW_RUN_ID" \
  --workflow-run-attempt "$COVERAGE_WORKFLOW_RUN_ATTEMPT")
case "$COVERAGE_SOURCE_SNAPSHOT_SHA256" in
  sha256:*) ;;
  *)
    echo "Coverage source snapshot checksum is invalid." >&2
    exit 2
    ;;
esac
COVERAGE_SOURCE_SNAPSHOT_HEX=${COVERAGE_SOURCE_SNAPSHOT_SHA256#sha256:}
case "$COVERAGE_SOURCE_SNAPSHOT_HEX" in
  *[!0-9a-f]* | "")
    echo "Coverage source snapshot checksum is invalid." >&2
    exit 2
    ;;
esac
if [ "${#COVERAGE_SOURCE_SNAPSHOT_HEX}" -ne 64 ]; then
  echo "Coverage source snapshot checksum is invalid." >&2
  exit 2
fi
uv run coverage run --data-file="$COVERAGE_DATA_FILE" -m pytest --junitxml="$JUNIT_PATH"
uv run python scripts/coverage_evidence.py capture \
  --repo-root . \
  --coverage-file "$COVERAGE_DATA_FILE" \
  --source-snapshot-file "$COVERAGE_SOURCE_SNAPSHOT_FILE" \
  --expected-source-snapshot-sha256 "$COVERAGE_SOURCE_SNAPSHOT_SHA256" \
  --output-dir "$COVERAGE_EVIDENCE_DIR" \
  --lane "$COVERAGE_LANE" \
  --commit-sha "$COVERAGE_COMMIT_SHA" \
  --workflow-run-id "$COVERAGE_WORKFLOW_RUN_ID" \
  --workflow-run-attempt "$COVERAGE_WORKFLOW_RUN_ATTEMPT"

LINUX_EVIDENCE_DIR="$COVERAGE_EVIDENCE_ROOT/linux/$COVERAGE_RUN_SEGMENT"
WINDOWS_EVIDENCE_DIR="$COVERAGE_EVIDENCE_ROOT/windows/$COVERAGE_RUN_SEGMENT"
if [ -d "$LINUX_EVIDENCE_DIR" ] && [ -d "$WINDOWS_EVIDENCE_DIR" ]; then
  uv run python scripts/coverage_evidence.py union \
    --repo-root . \
    --evidence-root "$COVERAGE_EVIDENCE_ROOT" \
    --output-dir "$COVERAGE_UNION_DIR" \
    --lane linux \
    --lane windows \
    --commit-sha "$COVERAGE_COMMIT_SHA" \
    --workflow-run-id "$COVERAGE_WORKFLOW_RUN_ID" \
    --workflow-run-attempt "$COVERAGE_WORKFLOW_RUN_ATTEMPT" \
    --fail-under 85
else
  echo "Local coverage union pending the other platform lane."
fi

uv build
