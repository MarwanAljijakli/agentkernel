from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

import yaml

if TYPE_CHECKING:
    from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIRECTORY = REPOSITORY_ROOT / ".github" / "workflows"
EXACT_HEAD_BRANCHES = ["main", "codex/**"]


def _load_workflow(name: str) -> dict[str, Any]:
    document = yaml.safe_load((WORKFLOW_DIRECTORY / name).read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return cast("dict[str, Any]", document)


def _events(workflow: dict[str, Any]) -> dict[str, Any]:
    events = workflow.get("on")
    if events is None:
        # PyYAML implements YAML 1.1 and therefore parses GitHub's `on` key as
        # the boolean True. Values remain safe-loaded; normalize only this key.
        events = cast("dict[Any, Any]", workflow).get(True)
    assert isinstance(events, dict)
    return cast("dict[str, Any]", events)


def _jobs(workflow: dict[str, Any]) -> dict[str, Any]:
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict)
    return cast("dict[str, Any]", jobs)


def _checkout_steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    checkouts: list[dict[str, Any]] = []
    for job in _jobs(workflow).values():
        assert isinstance(job, dict)
        steps = job.get("steps")
        assert isinstance(steps, list)
        for step in steps:
            assert isinstance(step, dict)
            uses = step.get("uses")
            if isinstance(uses, str) and uses.startswith("actions/checkout@"):
                checkouts.append(cast("dict[str, Any]", step))
    return checkouts


def test_ci_has_distinct_exact_head_and_pull_request_merge_gates() -> None:
    workflow = _load_workflow("ci.yml")
    events = _events(workflow)

    assert "pull_request_target" not in events
    assert "pull_request" in events
    push = events.get("push")
    assert isinstance(push, dict)
    assert push.get("branches") == EXACT_HEAD_BRANCHES

    platform_environment = _jobs(workflow)["platform-tests"]["env"]
    assert platform_environment["AGENTKERNEL_COVERAGE_COMMIT_SHA"] == "${{ github.sha }}"

    coverage_union = _jobs(workflow)["coverage-union"]
    union_environment = next(
        step["env"]
        for step in coverage_union["steps"]
        if step.get("name") == "Verify exact-run databases and enforce the union gate"
    )
    assert union_environment["COVERAGE_COMMIT_SHA"] == "${{ github.sha }}"

    checkouts = _checkout_steps(workflow)
    assert checkouts
    for checkout in checkouts:
        checkout_inputs = checkout["with"]
        assert checkout_inputs["ref"] == "${{ github.sha }}"
        assert checkout_inputs["persist-credentials"] is False

    concurrency = workflow["concurrency"]
    assert concurrency["group"] == (
        "ci-${{ github.event_name == 'pull_request' "
        "&& format('pr-{0}', github.event.pull_request.number) || github.sha }}"
    )
    assert concurrency["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}"


def test_codeql_preserves_pr_merge_analysis_and_adds_exact_head_push() -> None:
    workflow = _load_workflow("codeql.yml")
    events = _events(workflow)

    assert "pull_request_target" not in events
    assert "pull_request" in events
    push = events.get("push")
    assert isinstance(push, dict)
    assert push.get("branches") == EXACT_HEAD_BRANCHES

    permissions = workflow.get("permissions")
    assert permissions == {"contents": "read", "security-events": "write"}

    checkouts = _checkout_steps(workflow)
    assert len(checkouts) == 1
    checkout_inputs = checkouts[0]["with"]
    # GitHub binds github.sha to the push SHA for exact-head analysis and to
    # the synthetic merge for PRs; pin checkout to that immutable revision.
    assert checkout_inputs["ref"] == "${{ github.sha }}"
    assert checkout_inputs["persist-credentials"] is False
