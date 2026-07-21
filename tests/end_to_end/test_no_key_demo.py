from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from agentkernel.demo import run_demo
from agentkernel.domain.enums import TransactionState
from agentkernel.errors import AgentKernelError, ErrorCode


@pytest.mark.integration
def test_no_key_cli_demo_denies_attack_commits_and_replays(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "agentkernel", "demo", "--root", str(root), "--json"],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["assurance_profile"] == "A0"
    assert report["protected_read_canary_count"] == 0
    assert report["external_network_dispatch_count"] == 0
    assert report["committed_transaction_state"] == TransactionState.COMMITTED.value
    assert report["ledger_valid"] is True
    assert report["secret_found_in_evidence"] is False
    assert report["replay"]["level"] == "L2"
    assert report["replay"]["authoritative_effects"] is False
    assert report["replay"]["original_action_hash"] == report["replay"]["replay_action_hash"]
    assert (
        report["replay"]["original_final_state_hash"] == report["replay"]["replay_final_state_hash"]
    )
    assert report["replay"]["divergences"] == []
    assert (root / "repository" / "src" / "result.txt").read_text(encoding="utf-8") == (
        "verified\n"
    )
    assert "SYNTHETIC_DEMO_SECRET" not in (root / "demo-report.json").read_text(encoding="utf-8")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_no_key_demo_direct_execution_preserves_invariants(tmp_path: Path) -> None:
    root = tmp_path / "direct-demo"
    report = await run_demo(root)

    assert report.committed_transaction_state is TransactionState.COMMITTED
    assert report.protected_read_canary_count == 0
    assert report.external_network_dispatch_count == 0
    assert report.denied_reason_codes == (
        "AUTHORITY_MISSING",
        "POLICY_DENIED",
    )
    assert report.ledger_valid is True
    assert report.secret_found_in_evidence is False
    assert report.initial_workspace_hash != report.final_workspace_hash
    assert report.replay.divergences == ()


@pytest.mark.asyncio
async def test_demo_refuses_a_nonempty_target_directory(tmp_path: Path) -> None:
    root = tmp_path / "not-empty"
    root.mkdir()
    (root / "keep.txt").write_text("do not overwrite", encoding="utf-8")

    with pytest.raises(AgentKernelError) as captured:
        await run_demo(root)

    assert captured.value.code is ErrorCode.VALIDATION_ERROR
    assert (root / "keep.txt").read_text(encoding="utf-8") == "do not overwrite"
