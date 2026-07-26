$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    $coverageLane = if ($env:AGENTKERNEL_COVERAGE_LANE) {
        $env:AGENTKERNEL_COVERAGE_LANE
    } else {
        'windows'
    }
    $coverageCommitSha = if ($env:AGENTKERNEL_COVERAGE_COMMIT_SHA) {
        $env:AGENTKERNEL_COVERAGE_COMMIT_SHA
    } else {
        $commit = git rev-parse HEAD
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        $commit.Trim()
    }
    $coverageWorkflowRunId = if ($env:AGENTKERNEL_COVERAGE_WORKFLOW_RUN_ID) {
        $env:AGENTKERNEL_COVERAGE_WORKFLOW_RUN_ID
    } else {
        'local'
    }
    $coverageWorkflowRunAttempt = if ($env:AGENTKERNEL_COVERAGE_WORKFLOW_RUN_ATTEMPT) {
        $env:AGENTKERNEL_COVERAGE_WORKFLOW_RUN_ATTEMPT
    } else {
        '1'
    }
    uv sync --frozen
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    uv run python scripts/coverage_evidence.py validate-context --repo-root . --lane $coverageLane --commit-sha $coverageCommitSha --workflow-run-id $coverageWorkflowRunId --workflow-run-attempt $coverageWorkflowRunAttempt
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $coverageRunSegment = "run-$coverageWorkflowRunId-attempt-$coverageWorkflowRunAttempt"
    $coverageEvidenceRoot = 'test-results/coverage-evidence'
    $coverageEvidenceDir = "$coverageEvidenceRoot/$coverageLane/$coverageRunSegment"
    $coverageRawDir = "test-results/coverage-raw/$coverageLane/$coverageRunSegment"
    $coverageDataFile = "$coverageRawDir/.coverage"
    $coverageSourceSnapshotFile = "$coverageRawDir/source-snapshot.json"
    $coverageUnionDir = "test-results/coverage-union/$coverageRunSegment"
    $junitPath = "test-results/junit-$coverageLane.xml"

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
    uv run python scripts/validate_traceability.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    uv run python scripts/coverage_evidence.py clean --repo-root . --path $coverageEvidenceDir --path $coverageRawDir
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    New-Item -ItemType Directory -Path $coverageRawDir -Force | Out-Null
    $coverageSnapshotOutput = @(uv run python scripts/coverage_evidence.py snapshot --repo-root . --output-file $coverageSourceSnapshotFile --lane $coverageLane --commit-sha $coverageCommitSha --workflow-run-id $coverageWorkflowRunId --workflow-run-attempt $coverageWorkflowRunAttempt)
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if ($coverageSnapshotOutput.Count -ne 1) {
        Write-Error 'Coverage source snapshot command returned unexpected output.'
        exit 2
    }
    $coverageSourceSnapshotSha256 = [string]$coverageSnapshotOutput[0]
    if ($coverageSourceSnapshotSha256 -cnotmatch '^sha256:[0-9a-f]{64}$') {
        Write-Error 'Coverage source snapshot checksum is invalid.'
        exit 2
    }
    uv run coverage run --data-file=$coverageDataFile -m pytest --junitxml=$junitPath
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    uv run python scripts/coverage_evidence.py capture --repo-root . --coverage-file $coverageDataFile --source-snapshot-file $coverageSourceSnapshotFile --expected-source-snapshot-sha256 "$coverageSourceSnapshotSha256" --output-dir $coverageEvidenceDir --lane $coverageLane --commit-sha $coverageCommitSha --workflow-run-id $coverageWorkflowRunId --workflow-run-attempt $coverageWorkflowRunAttempt
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $linuxEvidenceDir = "$coverageEvidenceRoot/linux/$coverageRunSegment"
    $windowsEvidenceDir = "$coverageEvidenceRoot/windows/$coverageRunSegment"
    if (
        (Test-Path -LiteralPath $linuxEvidenceDir -PathType Container) -and
        (Test-Path -LiteralPath $windowsEvidenceDir -PathType Container)
    ) {
        uv run python scripts/coverage_evidence.py union --repo-root . --evidence-root $coverageEvidenceRoot --output-dir $coverageUnionDir --lane linux --lane windows --commit-sha $coverageCommitSha --workflow-run-id $coverageWorkflowRunId --workflow-run-attempt $coverageWorkflowRunAttempt --fail-under 85
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } else {
        Write-Host 'Local coverage union pending the other platform lane.'
    }

    uv build
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
