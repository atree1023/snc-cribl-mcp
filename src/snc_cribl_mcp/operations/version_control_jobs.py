"""Non-blocking execution jobs for Cribl configuration mutations."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

type JobRunner = Callable[[], Awaitable[dict[str, Any]]]
type JobStatus = Literal["queued", "running", "completed", "failed"]

_DEFAULT_JOB_LIMIT = 20
_MAX_JOB_LIMIT = 100
_MAX_RETAINED_JOBS = 100
_MAX_ERROR_MESSAGE_CHARS = 2000


def _now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(UTC).isoformat()


def _job_error(exc: Exception) -> dict[str, Any]:
    """Return a bounded structured job error."""
    message = str(exc)
    error: dict[str, Any] = {
        "type": type(exc).__name__,
        "message": message[:_MAX_ERROR_MESSAGE_CHARS],
    }
    if len(message) > _MAX_ERROR_MESSAGE_CHARS:
        error["message_truncated"] = True
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int):
        error["status_code"] = status_code
    return error


def _run_in_worker_loop(runner: JobRunner) -> dict[str, Any]:
    """Run one async mutation in a dedicated worker-thread event loop."""
    return asyncio.run(runner())


@dataclass(slots=True)
class _JobRecord:
    """Mutable internal state for one submitted mutation."""

    job_id: str
    operation: str
    server: str
    expected_plan_sha256: str | None
    status: JobStatus
    submitted_at: str
    started_at: str | None = None
    completed_at: str | None = None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None

    def as_dict(self, *, include_result: bool) -> dict[str, Any]:
        """Return a stable public job snapshot."""
        snapshot: dict[str, Any] = {
            "job_id": self.job_id,
            "operation": self.operation,
            "server": self.server,
            "status": self.status,
            "expected_plan_sha256": self.expected_plan_sha256,
            "submitted_at": self.submitted_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }
        if self.error is not None:
            snapshot["error"] = self.error
        if include_result and self.result is not None:
            snapshot["result"] = self.result
        return snapshot


class VersionControlJobManager:
    """Run mutations off the MCP event loop and expose polling snapshots."""

    def __init__(self, *, max_retained_jobs: int = _MAX_RETAINED_JOBS) -> None:
        """Initialize an in-memory bounded job registry."""
        if max_retained_jobs < 1:
            msg = "max_retained_jobs must be at least 1."
            raise ValueError(msg)
        self._max_retained_jobs = max_retained_jobs
        self._jobs: dict[str, _JobRecord] = {}
        self._job_order: list[str] = []
        self._server_locks: dict[str, asyncio.Lock] = {}
        self._tasks: set[asyncio.Task[None]] = set()

    async def submit(
        self,
        *,
        operation: str,
        server: str | None,
        expected_plan_sha256: str | None,
        runner: JobRunner,
    ) -> dict[str, Any]:
        """Queue one mutation and return immediately with a polling handle."""
        self._prune_completed_jobs()
        job_id = str(uuid4())
        submitted_at = _now()
        server_name = server or "default"
        record = _JobRecord(
            job_id=job_id,
            operation=operation,
            server=server_name,
            expected_plan_sha256=expected_plan_sha256,
            status="queued",
            submitted_at=submitted_at,
        )
        self._jobs[job_id] = record
        self._job_order.append(job_id)
        task = asyncio.create_task(
            self._execute(record, server_key=server_name, runner=runner),
            name=f"cribl-config-{operation}-{job_id}",
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return {
            "status": "accepted",
            "job_id": job_id,
            "operation": operation,
            "server": server_name,
            "expected_plan_sha256": expected_plan_sha256,
            "submitted_at": submitted_at,
            "poll_with": "get_config_deployment_job",
        }

    async def get(self, *, job_id: str | None = None, limit: int = _DEFAULT_JOB_LIMIT) -> dict[str, Any]:
        """Return one detailed job or a compact list of recent jobs."""
        if limit < 1 or limit > _MAX_JOB_LIMIT:
            msg = f"limit must be between 1 and {_MAX_JOB_LIMIT}."
            raise ValueError(msg)
        if job_id is not None:
            normalized = job_id.strip()
            record = self._jobs.get(normalized)
            if record is None:
                msg = f"Unknown configuration deployment job '{job_id}'."
                raise ValueError(msg)
            return record.as_dict(include_result=True)

        records = [self._jobs[candidate] for candidate in reversed(self._job_order) if candidate in self._jobs][
            :_MAX_JOB_LIMIT
        ][:limit]
        return {
            "count": len(records),
            "jobs": [record.as_dict(include_result=False) for record in records],
        }

    async def _execute(self, record: _JobRecord, *, server_key: str, runner: JobRunner) -> None:
        """Serialize mutations per server and isolate blocking SDK calls."""
        lock = self._server_locks.setdefault(server_key, asyncio.Lock())
        async with lock:
            record.status = "running"
            record.started_at = _now()
            try:
                record.result = await asyncio.to_thread(_run_in_worker_loop, runner)
            except Exception as exc:  # noqa: BLE001 - jobs report bounded failures for polling
                record.status = "failed"
                record.error = _job_error(exc)
            else:
                record.status = "completed"
            finally:
                record.completed_at = _now()

    def _prune_completed_jobs(self) -> None:
        """Bound retained history without discarding active jobs."""
        removable = [job_id for job_id in self._job_order if self._jobs[job_id].status in {"completed", "failed"}]
        while len(self._jobs) >= self._max_retained_jobs and removable:
            job_id = removable.pop(0)
            self._jobs.pop(job_id, None)
            self._job_order.remove(job_id)


__all__ = ["JobRunner", "VersionControlJobManager"]
