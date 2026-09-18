"""Regression tests for durable progress through the actual tool/job/workflow path."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context

from snc_cribl_mcp.operations import version_control as vc
from snc_cribl_mcp.operations.version_control_jobs import VersionControlJobManager
from snc_cribl_mcp.tools.version_control import register

from .test_version_control import _Counted, _group_payload, _Harness, _install_harness
from .test_version_control_tools import _FakeApp, _wait_for_job


def _registered_tools(manager: VersionControlJobManager) -> _FakeApp:
    """Register production operations behind a test MCP surface."""
    app = _FakeApp()
    register(
        app,  # type: ignore[arg-type]
        status_impl=vc.collect_group_git_status,
        diff_impl=vc.collect_group_git_diff,
        leader_diff_impl=vc.collect_leader_git_diff,
        commit_impl=vc.commit_group_config,
        leader_commit_impl=vc.commit_leader_config,
        deploy_impl=vc.deploy_group_config,
        commit_deploy_impl=vc.commit_and_deploy_group,
        commit_deploy_all_impl=vc.commit_and_deploy_all,
        push_impl=vc.push_config_git,
        job_manager=manager,
    )
    return app


async def test_all_tool_reports_running_fleets_and_restores_terminal_detail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A real all-target job reports a running commit and every completed fleet, durably."""
    harness = _Harness(*((ProductsCore.EDGE, _group_payload(name, product=ProductsCore.EDGE)) for name in ["a", "b"]))
    _install_harness(monkeypatch, harness)
    database = tmp_path / "jobs.sqlite3"
    manager = VersionControlJobManager(database_path=database)
    app = _registered_tools(manager)
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    plan = await app.tools["commit_and_deploy_all"](ctx, server="test", product="edge", message="Rollout")
    started, release = threading.Event(), threading.Event()

    async def _slow_commit(**kwargs: Any) -> _Counted:  # noqa: ANN401 - forwards SDK keyword arguments
        started.set()
        if not release.wait(timeout=5):
            msg = "Test commit was not released"
            raise RuntimeError(msg)
        return await harness._commit(**kwargs)

    harness.client.versions.commits.create_async.side_effect = _slow_commit
    accepted = await app.tools["commit_and_deploy_all"](
        ctx,
        server="test",
        product="edge",
        message="Rollout",
        dry_run=False,
        expected_plan_sha256=plan["plan"]["plan_sha256"],
    )
    assert accepted["progress"]["unit"] == "fleets"
    job_id = accepted["job_id"]
    try:
        assert await asyncio.to_thread(started.wait, 2)
        running = await app.tools["get_config_deployment_job"](ctx, job_id=job_id, target="test")
        assert running["progress"]["total"] == 2
        assert running["progress"]["current_group"] == "a"
        assert running["target_detail"]["status"] == "running"
        fleet = await manager.get(job_id=job_id, target="edge:a")
        pending = await manager.get(job_id=job_id, target="edge:b")
        assert fleet["target_detail"]["status"] == "running"
        assert pending["target_detail"]["status"] == "pending"
    finally:
        release.set()
    completed = await _wait_for_job(manager, job_id)
    assert completed["progress"]["completed"] == completed["progress"]["total"] == 2
    assert completed["progress"]["succeeded"] == 2
    assert completed["progress"]["failed"] == completed["progress"]["skipped"] == 0
    assert completed["progress"]["leaders_completed"] == 1
    assert harness.deploy_order == ["a", "b"]
    manager.close()
    restored = VersionControlJobManager(database_path=database)
    assert (await restored.get(job_id=job_id))["progress"] == completed["progress"]
    assert (await restored.get(job_id=job_id, target="test"))["target_detail"]["status"] == "completed"
    assert (await restored.get(job_id=job_id, target="test"))["target_detail"]["progress"] == completed["progress"]
    assert (await restored.get(job_id=job_id, target="edge:a"))["target_detail"]["status"] == "deployed"
    restored.close()


@pytest.mark.parametrize("outcome", ["noop", "empty", "commit_failure", "deploy_failure", "push_failure", "stale"])
async def test_all_tool_counts_noops_failures_skips_and_empty_inventory(monkeypatch: pytest.MonkeyPatch, outcome: str) -> None:
    """Pollers can distinguish no-op/success/failure, including work stopped before deployment."""
    names = [] if outcome == "empty" else ["a", "b"]
    harness = _Harness(
        *(
            (
                ProductsCore.STREAM,
                _group_payload(
                    name,
                    product=ProductsCore.STREAM,
                    local_changes=0 if outcome == "noop" else 1,
                    deployed="commit-1" if outcome == "noop" else "commit-0",
                ),
            )
            for name in names
        )
    )
    _install_harness(monkeypatch, harness)
    harness.commit_error_for = "a" if outcome == "commit_failure" else None
    harness.deploy_error_for = "a" if outcome == "deploy_failure" else None
    harness.push_error = RuntimeError("push failed") if outcome == "push_failure" else None
    manager = VersionControlJobManager()
    app = _registered_tools(manager)
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    push = outcome == "push_failure"
    plan = await app.tools["commit_and_deploy_all"](ctx, server="test", product="stream", message="Rollout", push=push)
    accepted = await app.tools["commit_and_deploy_all"](
        ctx,
        server="test",
        product="stream",
        message="Rollout",
        push=push,
        dry_run=False,
        expected_plan_sha256="stale" if outcome == "stale" else plan["plan"]["plan_sha256"],
    )
    completed = await _wait_for_job(manager, accepted["job_id"])
    progress = completed["progress"]
    assert progress["unit"] == "fleets"
    assert progress["completed"] == progress["total"] == len(names)
    assert progress["running"] == 0
    assert progress["leaders_failed"] == int(outcome not in {"empty", "noop"})
    if outcome == "noop":
        assert progress["noop"] == 2
        assert progress["succeeded"] == 0
    elif outcome in {"commit_failure", "deploy_failure"}:
        assert progress["failed"] == progress["skipped"] == 1
        assert progress["succeeded"] == 0
    elif outcome == "push_failure":
        assert progress["succeeded"] == 2
        assert progress["failed"] == 0
    elif outcome == "stale":
        assert completed["status"] == "failed"
        assert progress["skipped"] == 2
        assert harness.commit_order == []
    detail = await manager.get(job_id=accepted["job_id"], target="test")
    assert detail["target_detail"]["status"] in {"completed", "partial_failure", "failed"}
    manager.close()


async def test_leader_tool_dry_run_then_async_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exposed Leader tool registers, plans inline and executes through the job manager."""
    harness = _Harness()
    harness.global_dirty = True
    _install_harness(monkeypatch, harness)
    manager = VersionControlJobManager()
    app = _registered_tools(manager)
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    args = {"server": "test", "message": "Resolve metadata", "files": ["local/cribl/groups.yml"]}
    plan = await app.tools["commit_leader_config"](ctx, **args)
    assert (await manager.get())["count"] == 0
    accepted = await app.tools["commit_leader_config"](
        ctx,
        **args,
        dry_run=False,
        expected_plan_sha256=plan["plan"]["plan_sha256"],
    )
    result = await _wait_for_job(manager, accepted["job_id"])
    assert result["result"]["status"] == "committed"
    assert harness.global_dirty is False
    manager.close()
