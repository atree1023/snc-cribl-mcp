"""Durable, non-blocking execution jobs for Cribl configuration mutations."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import weakref
from collections.abc import Awaitable, Callable, Iterable
from contextlib import AsyncExitStack, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from uuid import uuid4

type JobRunner = Callable[[], Awaitable[dict[str, Any]]]
type ContextJobRunner = Callable[["JobContext"], Awaitable[dict[str, Any]]]
type JobStatus = Literal["queued", "running", "completed", "failed", "interrupted"]

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


def _empty_target_details() -> dict[str, dict[str, Any]]:
    """Return a typed empty per-target detail mapping."""
    return {}


@dataclass(slots=True)
class _JobRecord:
    """Mutable internal state for one submitted mutation."""

    job_id: str
    operation: str
    server: str
    servers: tuple[str, ...]
    expected_plan_sha256: str | None
    status: JobStatus
    submitted_at: str
    started_at: str | None = None
    completed_at: str | None = None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    progress: dict[str, Any] | None = None
    request: dict[str, Any] | None = None
    resume_of: str | None = None
    target_details: dict[str, dict[str, Any]] = field(default_factory=_empty_target_details)

    def as_dict(self, *, include_result: bool, target: str | None = None) -> dict[str, Any]:
        """Return a stable public job snapshot."""
        snapshot: dict[str, Any] = {
            "job_id": self.job_id,
            "operation": self.operation,
            "server": self.server,
            "servers": list(self.servers),
            "status": self.status,
            "expected_plan_sha256": self.expected_plan_sha256,
            "submitted_at": self.submitted_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }
        if self.resume_of is not None:
            snapshot["resume_of"] = self.resume_of
        if self.progress is not None:
            snapshot["progress"] = self.progress
        if self.error is not None:
            snapshot["error"] = self.error
        if target is not None:
            detail = self.target_details.get(target)
            if detail is None:
                if target not in self.servers:
                    msg = f"Job '{self.job_id}' does not include target '{target}'."
                    raise ValueError(msg)
                detail = {
                    "server": target,
                    "status": "pending" if self.status in {"queued", "running"} else "unavailable",
                    "message": (
                        "Target detail is not available yet."
                        if self.status in {"queued", "running"}
                        else "The job ended before target detail was recorded."
                    ),
                }
            snapshot["target"] = target
            snapshot["target_detail"] = detail
        elif include_result and self.result is not None:
            snapshot["result"] = self.result
        return snapshot


class JobContext:
    """Thread-safe progress and detail writer supplied to aggregate job runners."""

    def __init__(self, manager: VersionControlJobManager, job_id: str) -> None:
        """Bind progress updates to one durable job."""
        self.job_id = job_id
        self._manager = manager

    def update_progress(self, progress: dict[str, Any]) -> None:
        """Persist a bounded aggregate progress snapshot."""
        self._manager._update_progress(self.job_id, progress)  # pyright: ignore[reportPrivateUsage] # noqa: SLF001

    def set_target_detail(self, target: str, detail: dict[str, Any]) -> None:
        """Persist detail for one target without expanding the aggregate result."""
        self._manager._set_target_detail(  # pyright: ignore[reportPrivateUsage] # noqa: SLF001
            self.job_id,
            target,
            detail,
        )


class VersionControlJobManager:
    """Run mutations off the MCP event loop with optional durable SQLite state."""

    def __init__(self, *, max_retained_jobs: int = _MAX_RETAINED_JOBS, database_path: Path | None = None) -> None:
        """Initialize a bounded job registry and restore durable history when configured."""
        if max_retained_jobs < 1:
            msg = "max_retained_jobs must be at least 1."
            raise ValueError(msg)
        self._max_retained_jobs = max_retained_jobs
        self._jobs: dict[str, _JobRecord] = {}
        self._job_order: list[str] = []
        self._server_locks: dict[str, asyncio.Lock] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._state_lock = threading.RLock()
        self._database_path = database_path
        self._connection: sqlite3.Connection | None = None
        self._connection_finalizer: weakref.finalize[[], VersionControlJobManager] | None = None

    def _ensure_database(self) -> None:
        """Open durable state and restore job history on first use."""
        database_path = self._database_path
        if database_path is None or self._connection is not None:
            return
        with self._state_lock:
            if self._connection is not None:
                return
            database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(database_path, check_same_thread=False)
            connection.row_factory = sqlite3.Row
            self._connection = connection
            self._connection_finalizer = weakref.finalize(self, connection.close)
            self._initialize_database()
            self._restore_jobs()

    @staticmethod
    def _json(value: object) -> str | None:
        return None if value is None else json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _decoded(value: object) -> dict[str, Any] | None:
        if not isinstance(value, str):
            return None
        decoded = json.loads(value)
        return cast("dict[str, Any]", decoded) if isinstance(decoded, dict) else None

    def _initialize_database(self) -> None:
        """Create durable job tables when absent."""
        if self._connection is None:
            return
        with self._state_lock, self._connection:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS config_jobs (
                    job_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    server TEXT NOT NULL,
                    servers_json TEXT NOT NULL,
                    expected_plan_sha256 TEXT,
                    status TEXT NOT NULL,
                    submitted_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    result_json TEXT,
                    error_json TEXT,
                    progress_json TEXT,
                    request_json TEXT,
                    resume_of TEXT
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS config_job_target_details (
                    job_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    PRIMARY KEY (job_id, target)
                )
                """
            )

    def close(self) -> None:
        """Close the optional durable SQLite connection."""
        with self._state_lock:
            connection = self._connection
            if connection is None:
                return
            finalizer = self._connection_finalizer
            if finalizer is not None and finalizer.alive:
                finalizer()
            else:
                with suppress(sqlite3.ProgrammingError):
                    connection.close()
            self._connection = None
            self._connection_finalizer = None

    def __del__(self) -> None:
        """Best-effort cleanup for short-lived managers and test processes."""
        with suppress(Exception):
            self.close()

    def _restore_jobs(self) -> None:
        """Restore jobs and mark process-owned active work as safely interrupted."""
        if self._connection is None:
            return
        with self._state_lock, self._connection:
            rows = self._connection.execute("SELECT * FROM config_jobs ORDER BY submitted_at").fetchall()
            for row in rows:
                status = cast("JobStatus", row["status"])
                completed_at = cast("str | None", row["completed_at"])
                error = self._decoded(row["error_json"])
                original_status = status
                if status in {"queued", "running"}:
                    status = "interrupted"
                    completed_at = _now()
                    error = {
                        "type": "ProcessRestart",
                        "message": "The MCP process restarted before this job completed; resume the job to continue.",
                    }
                servers_value = cast("object", json.loads(cast("str", row["servers_json"])))
                servers = (
                    tuple(str(item) for item in cast("list[object]", servers_value))
                    if isinstance(servers_value, list)
                    else (str(row["server"]),)
                )
                record = _JobRecord(
                    job_id=str(row["job_id"]),
                    operation=str(row["operation"]),
                    server=str(row["server"]),
                    servers=servers,
                    expected_plan_sha256=cast("str | None", row["expected_plan_sha256"]),
                    status=status,
                    submitted_at=str(row["submitted_at"]),
                    started_at=cast("str | None", row["started_at"]),
                    completed_at=completed_at,
                    result=self._decoded(row["result_json"]),
                    error=error,
                    progress=self._decoded(row["progress_json"]),
                    request=self._decoded(row["request_json"]),
                    resume_of=cast("str | None", row["resume_of"]),
                )
                details = self._connection.execute(
                    "SELECT target, detail_json FROM config_job_target_details WHERE job_id = ?",
                    (record.job_id,),
                ).fetchall()
                record.target_details = {
                    str(detail["target"]): cast("dict[str, Any]", json.loads(str(detail["detail_json"]))) for detail in details
                }
                self._jobs[record.job_id] = record
                self._job_order.append(record.job_id)
                if original_status != status:
                    self._persist(record)

    def _persist(self, record: _JobRecord) -> None:
        """Persist one complete job snapshot."""
        if self._connection is None:
            return
        with self._state_lock, self._connection:
            self._connection.execute(
                """
                INSERT OR REPLACE INTO config_jobs (
                    job_id, operation, server, servers_json, expected_plan_sha256, status,
                    submitted_at, started_at, completed_at, result_json, error_json,
                    progress_json, request_json, resume_of
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.job_id,
                    record.operation,
                    record.server,
                    self._json(list(record.servers)),
                    record.expected_plan_sha256,
                    record.status,
                    record.submitted_at,
                    record.started_at,
                    record.completed_at,
                    self._json(record.result),
                    self._json(record.error),
                    self._json(record.progress),
                    self._json(record.request),
                    record.resume_of,
                ),
            )

    async def submit(
        self,
        *,
        operation: str,
        server: str | None,
        expected_plan_sha256: str | None,
        runner: JobRunner,
    ) -> dict[str, Any]:
        """Queue one legacy single-server mutation and return a polling handle."""

        async def _context_runner(_context: JobContext) -> dict[str, Any]:
            return await runner()

        return await self.submit_aggregate(
            operation=operation,
            servers=(server or "default",),
            expected_plan_sha256=expected_plan_sha256,
            runner=_context_runner,
        )

    async def submit_aggregate(
        self,
        *,
        operation: str,
        servers: Iterable[str],
        expected_plan_sha256: str | None,
        runner: ContextJobRunner,
        request: dict[str, Any] | None = None,
        resume_of: str | None = None,
        initial_progress: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Queue a durable aggregate mutation serialized across every target server."""
        self._ensure_database()
        self._prune_completed_jobs()
        normalized_servers = tuple(dict.fromkeys(server.strip() for server in servers if server.strip()))
        if not normalized_servers:
            msg = "Aggregate jobs require at least one server."
            raise ValueError(msg)
        if resume_of is not None:
            prior = self._require_record(resume_of)
            if prior.operation != operation:
                msg = f"Job '{resume_of}' belongs to operation '{prior.operation}', not '{operation}'."
                raise ValueError(msg)
            if prior.status not in {"failed", "interrupted", "completed"}:
                msg = f"Job '{resume_of}' is still {prior.status} and cannot be resumed."
                raise ValueError(msg)
        job_id = str(uuid4())
        submitted_at = _now()
        record = _JobRecord(
            job_id=job_id,
            operation=operation,
            server=normalized_servers[0] if len(normalized_servers) == 1 else "multiple",
            servers=normalized_servers,
            expected_plan_sha256=expected_plan_sha256,
            status="queued",
            submitted_at=submitted_at,
            request=request,
            resume_of=resume_of,
            progress=(
                dict(initial_progress)
                if initial_progress is not None
                else {
                    "unit": "targets",
                    "total": len(normalized_servers),
                    "completed": 0,
                    "failed": 0,
                    "running": 0,
                }
            ),
        )
        with self._state_lock:
            self._jobs[job_id] = record
            self._job_order.append(job_id)
            self._persist(record)
        task = asyncio.create_task(self._execute(record, runner=runner), name=f"cribl-config-{operation}-{job_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return {
            "status": "accepted",
            "job_id": job_id,
            "operation": operation,
            "server": record.server,
            "servers": list(normalized_servers),
            "expected_plan_sha256": expected_plan_sha256,
            "submitted_at": submitted_at,
            "resume_of": resume_of,
            "progress": dict(record.progress or {}),
            "poll_with": "get_config_deployment_job",
        }

    async def get(
        self,
        *,
        job_id: str | None = None,
        limit: int = _DEFAULT_JOB_LIMIT,
        target: str | None = None,
    ) -> dict[str, Any]:
        """Return one detailed job or a compact list of recent jobs."""
        self._ensure_database()
        if limit < 1 or limit > _MAX_JOB_LIMIT:
            msg = f"limit must be between 1 and {_MAX_JOB_LIMIT}."
            raise ValueError(msg)
        if target is not None and job_id is None:
            msg = "target requires job_id."
            raise ValueError(msg)
        if job_id is not None:
            record = self._require_record(job_id.strip())
            normalized_target = target.strip() if target is not None else None
            return record.as_dict(include_result=normalized_target is None, target=normalized_target)

        records = [self._jobs[candidate] for candidate in reversed(self._job_order) if candidate in self._jobs][
            :_MAX_JOB_LIMIT
        ][:limit]
        return {"count": len(records), "jobs": [record.as_dict(include_result=False) for record in records]}

    def resume_request(self, job_id: str, *, operation: str) -> dict[str, Any]:
        """Return the durable request payload for a compatible resumable job."""
        self._ensure_database()
        record = self._require_record(job_id)
        if record.operation != operation:
            msg = f"Job '{job_id}' belongs to operation '{record.operation}', not '{operation}'."
            raise ValueError(msg)
        if record.request is None:
            msg = f"Job '{job_id}' does not contain a resumable request."
            raise ValueError(msg)
        return dict(record.request)

    def target_details(self, job_id: str) -> dict[str, dict[str, Any]]:
        """Return durable per-target details for resumption logic."""
        self._ensure_database()
        return dict(self._require_record(job_id).target_details)

    async def _execute(self, record: _JobRecord, *, runner: ContextJobRunner) -> None:
        """Serialize mutations across all involved servers and isolate blocking SDK calls."""
        async with AsyncExitStack() as stack:
            for server_key in sorted(record.servers):
                lock = self._server_locks.setdefault(server_key, asyncio.Lock())
                await stack.enter_async_context(lock)
            with self._state_lock:
                record.status = "running"
                record.started_at = _now()
                self._persist(record)
            context = JobContext(self, record.job_id)

            async def _runner() -> dict[str, Any]:
                return await runner(context)

            try:
                result = await asyncio.to_thread(_run_in_worker_loop, _runner)
            except Exception as exc:  # noqa: BLE001 - jobs report bounded failures for polling
                with self._state_lock:
                    record.status = "failed"
                    record.error = _job_error(exc)
            else:
                with self._state_lock:
                    record.result = result
                    record.status = "completed"
            finally:
                with self._state_lock:
                    record.completed_at = _now()
                    if record.progress is not None:
                        record.progress = {**record.progress, "phase": record.status}
                        if "running" in record.progress:
                            record.progress["running"] = 0
                        if "source_running" in record.progress:
                            record.progress["source_running"] = 0
                    self._persist(record)

    def _require_record(self, job_id: str) -> _JobRecord:
        record = self._jobs.get(job_id)
        if record is None:
            msg = f"Unknown configuration deployment job '{job_id}'."
            raise ValueError(msg)
        return record

    def _update_progress(self, job_id: str, progress: dict[str, Any]) -> None:
        """Replace and persist one aggregate progress snapshot."""
        with self._state_lock:
            record = self._require_record(job_id)
            record.progress = dict(progress)
            self._persist(record)

    def _set_target_detail(self, job_id: str, target: str, detail: dict[str, Any]) -> None:
        """Replace and persist one target detail snapshot."""
        normalized = target.strip()
        if not normalized:
            msg = "Target detail key must not be blank."
            raise ValueError(msg)
        with self._state_lock:
            record = self._require_record(job_id)
            record.target_details[normalized] = dict(detail)
            if self._connection is not None:
                with self._connection:
                    self._connection.execute(
                        """
                        INSERT OR REPLACE INTO config_job_target_details (job_id, target, detail_json)
                        VALUES (?, ?, ?)
                        """,
                        (job_id, normalized, self._json(detail)),
                    )

    def _prune_completed_jobs(self) -> None:
        """Bound retained history without discarding active jobs."""
        terminal = {"completed", "failed", "interrupted"}
        removable = [job_id for job_id in self._job_order if self._jobs[job_id].status in terminal]
        while len(self._jobs) >= self._max_retained_jobs and removable:
            job_id = removable.pop(0)
            self._jobs.pop(job_id, None)
            self._job_order.remove(job_id)
            if self._connection is not None:
                with self._state_lock, self._connection:
                    self._connection.execute("DELETE FROM config_job_target_details WHERE job_id = ?", (job_id,))
                    self._connection.execute("DELETE FROM config_jobs WHERE job_id = ?", (job_id,))


__all__ = ["ContextJobRunner", "JobContext", "JobRunner", "VersionControlJobManager"]
