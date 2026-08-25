"""Unit tests for non-blocking version-control mutation jobs."""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest

from snc_cribl_mcp.operations.version_control_jobs import VersionControlJobManager


async def _wait_for_terminal(manager: VersionControlJobManager, job_id: str) -> dict[str, Any]:
    """Poll one job until it reaches a terminal state."""
    for _ in range(100):
        snapshot = await manager.get(job_id=job_id)
        if snapshot["status"] in {"completed", "failed"}:
            return snapshot
        await asyncio.sleep(0.01)
    msg = f"Timed out waiting for test job {job_id}."
    raise AssertionError(msg)


@pytest.mark.asyncio
async def test_blocking_mutation_runs_off_event_loop_and_returns_bounded_result() -> None:
    """A blocking SDK operation should not prevent job status polling."""
    manager = VersionControlJobManager()
    started = threading.Event()
    release = threading.Event()

    async def _runner() -> dict[str, Any]:
        started.set()
        if not release.wait(timeout=2):
            msg = "Test worker was not released."
            raise RuntimeError(msg)
        return {"status": "deployed", "executed_plan_sha256": "plan-1"}

    accepted = await manager.submit(
        operation="commit_and_deploy_group",
        server="prod",
        expected_plan_sha256="plan-1",
        runner=_runner,
    )

    assert accepted["status"] == "accepted"
    assert accepted["poll_with"] == "get_config_deployment_job"
    assert await asyncio.to_thread(started.wait, 1)
    running = await asyncio.wait_for(manager.get(job_id=str(accepted["job_id"])), timeout=0.1)
    recent = await manager.get()
    assert running["status"] == "running"
    assert "result" not in recent["jobs"][0]

    release.set()
    completed = await _wait_for_terminal(manager, str(accepted["job_id"]))

    assert completed["status"] == "completed"
    assert completed["result"] == {"status": "deployed", "executed_plan_sha256": "plan-1"}
    assert completed["started_at"] is not None
    assert completed["completed_at"] is not None


@pytest.mark.asyncio
async def test_jobs_serialize_per_server_and_report_worker_errors() -> None:
    """Mutations for one Leader should run in order while failures remain pollable."""
    manager = VersionControlJobManager()
    first_started = threading.Event()
    first_release = threading.Event()
    second_started = threading.Event()

    async def _first() -> dict[str, Any]:
        first_started.set()
        first_release.wait(timeout=2)
        return {"status": "completed"}

    async def _second() -> dict[str, Any]:
        second_started.set()
        return {"status": "completed"}

    first = await manager.submit(
        operation="first",
        server="prod",
        expected_plan_sha256="one",
        runner=_first,
    )
    second = await manager.submit(
        operation="second",
        server="prod",
        expected_plan_sha256="two",
        runner=_second,
    )
    assert await asyncio.to_thread(first_started.wait, 1)
    await asyncio.sleep(0.05)
    assert not second_started.is_set()

    first_release.set()
    assert (await _wait_for_terminal(manager, str(first["job_id"])))["status"] == "completed"
    assert (await _wait_for_terminal(manager, str(second["job_id"])))["status"] == "completed"
    assert second_started.is_set()

    class _StatusError(RuntimeError):
        status_code = 503

    async def _failure() -> dict[str, Any]:
        raise _StatusError("x" * 3000)

    failed = await manager.submit(
        operation="push_config_git",
        server="other",
        expected_plan_sha256="three",
        runner=_failure,
    )
    failure = await _wait_for_terminal(manager, str(failed["job_id"]))
    assert failure["status"] == "failed"
    assert failure["error"] == {
        "type": "_StatusError",
        "message": "x" * 2000,
        "message_truncated": True,
        "status_code": 503,
    }


@pytest.mark.asyncio
async def test_job_registry_validates_queries_and_prunes_completed_history() -> None:
    """The process-local registry should remain bounded and reject invalid lookups."""
    with pytest.raises(ValueError, match="at least 1"):
        VersionControlJobManager(max_retained_jobs=0)

    manager = VersionControlJobManager(max_retained_jobs=1)

    async def _runner() -> dict[str, Any]:
        return {"status": "completed"}

    first = await manager.submit(
        operation="first",
        server=None,
        expected_plan_sha256=None,
        runner=_runner,
    )
    await _wait_for_terminal(manager, str(first["job_id"]))
    second = await manager.submit(
        operation="second",
        server=None,
        expected_plan_sha256=None,
        runner=_runner,
    )
    await _wait_for_terminal(manager, str(second["job_id"]))

    with pytest.raises(ValueError, match="Unknown"):
        await manager.get(job_id=str(first["job_id"]))
    with pytest.raises(ValueError, match="between 1 and 100"):
        await manager.get(limit=0)
