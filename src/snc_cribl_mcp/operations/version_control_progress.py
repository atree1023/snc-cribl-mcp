"""Durable fleet accounting for a single-Leader commit/deploy job."""

from __future__ import annotations

from typing import Any

from .version_control_jobs import JobContext


class FleetJobProgress:
    """Translate workflow events into bounded job and target snapshots."""

    def __init__(self, context: JobContext, server: str) -> None:
        """Start with an unknown fleet count until the execution plan is built."""
        self.context = context
        self.server = server
        self.progress: dict[str, Any] = {
            "unit": "fleets",
            "total": None,
            "completed": 0,
            "failed": 0,
            "skipped": 0,
            "noop": 0,
            "succeeded": 0,
            "running": 1,
            "leader_total": 1,
            "leaders_completed": 0,
            "leaders_failed": 0,
            "current_server": server,
            "phase": "planning",
        }
        self.targets: dict[str, dict[str, Any]] = {}
        self._persist()

    def _persist(self, *, status: str = "running", **detail: object) -> None:
        self.context.update_progress(dict(self.progress))
        self.context.set_target_detail(
            self.server, {"server": self.server, "status": status, "progress": dict(self.progress), **detail}
        )

    async def event(self, event: dict[str, Any]) -> None:
        """Persist plan, current operation, terminal fleet, or Leader result."""
        kind = event["event"]
        if kind == "planned":
            self.progress.update(total=len(event["targets"]), phase="executing")
            for target in event["targets"]:
                key = f"{target['product']}:{target['id']}"
                self.targets[key] = {"target": target, "status": "pending"}
                self.context.set_target_detail(key, self.targets[key])
        elif kind in {"running", "target_complete"}:
            key = f"{event['product']}:{event['group']}"
            self.progress.update(current_product=event["product"], current_group=event["group"], current_phase=event["phase"])
            detail = {**self.targets[key], "status": event["status"], "phase": event["phase"]}
            self.targets[key] = detail
            self.context.set_target_detail(key, detail)
            if kind == "target_complete":
                status = str(event["status"])
                self.progress["completed"] += 1
                if status == "failed":
                    self.progress["failed"] += 1
                elif status.startswith("skipped") or status == "not_started":
                    self.progress["skipped"] += 1
                elif status == "noop":
                    self.progress["noop"] += 1
                else:
                    self.progress["succeeded"] += 1
        elif kind == "phase":
            self.progress.update(current_phase=event["phase"], current_group=None, current_product=None)
        elif kind == "finished":
            self.progress.update(
                running=0, phase="completed", leaders_completed=1, leaders_failed=int(event["status"] != "completed")
            )
            self._persist(status=event["status"], summary=event["summary"], errors=event["errors"], push=event["push"])
            return
        self._persist()

    def fail(self, exc: Exception) -> None:
        """Record preflight or unexpected failures without claiming work succeeded."""
        for key, detail in self.targets.items():
            if detail["status"] in {"pending", "running", "awaiting_deploy"}:
                self.context.set_target_detail(key, {**detail, "status": "not_started"})
                self.progress["completed"] += 1
                self.progress["skipped"] += 1
        self.progress.update(running=0, phase="failed", leaders_completed=1, leaders_failed=1)
        self._persist(status="failed", error={"type": type(exc).__name__, "message": str(exc)[:2000]})
