"""Tests for aggregate configuration-manifest planning and execution."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

import snc_cribl_mcp.operations.config_manifest as operations
from snc_cribl_mcp.models.config_manifest import (
    ConfigManifest,
    LoadedConfigManifest,
    ManifestContent,
    ManifestOptions,
    ManifestSource,
)
from snc_cribl_mcp.operations.manifest_state import ManifestStateStore


class _JobContext:
    """Minimal progress sink used by operation tests."""

    def __init__(self, job_id: str = "job-1") -> None:
        self.job_id = job_id
        self.progress: list[dict[str, Any]] = []
        self.details: dict[str, dict[str, Any]] = {}

    def update_progress(self, progress: dict[str, Any]) -> None:
        self.progress.append(progress)

    def set_target_detail(self, target: str, detail: dict[str, Any]) -> None:
        self.details[target] = detail


def _loaded_manifest(*, targets: list[str] | None = None) -> LoadedConfigManifest:
    manifest = ConfigManifest.model_construct(
        schema_=1,
        wave="test",
        source=ManifestSource.model_construct(server="golden.oak", product="edge"),
        content=[ManifestContent.model_construct(group="fleet", kind="destinations", items=["out"])],
        targets=targets or ["leader-a", "leader-b"],
        options=ManifestOptions.model_construct(overwrite=True, append_routes=False, concurrency=2, on_drift="skip"),
    )
    return LoadedConfigManifest.model_construct(
        manifest=manifest,
        path=Path("/safe/wave.yaml"),
        relative_path="wave.yaml",
        file_sha256="file",
        manifest_sha256="manifest",
    )


def _snapshot() -> dict[str, Any]:
    return {
        "groups": {"fleet": "fleet"},
        "items": [
            {
                "group": "fleet",
                "group_id": "fleet",
                "kind": "destinations",
                "item_id": "out",
                "source_sha256": "source-item",
                "item": {"id": "out", "type": "devnull"},
            }
        ],
        "snapshot_sha256": "source-snapshot",
    }


def test_manifest_content_orders_edge_parents_and_resource_dependencies_first() -> None:
    """Selected parent content must precede child content while preserving kind dependencies."""
    loaded = _loaded_manifest()
    manifest = loaded.manifest.model_copy(
        update={
            "content": [
                *loaded.manifest.content,
                ManifestContent.model_construct(group="parent", kind="sources", items=["source"]),
                ManifestContent.model_construct(group="parent", kind="variables", items=["variable"]),
                ManifestContent.model_construct(group="child", kind="variables", items=["child-variable"]),
            ]
        }
    )
    ordered = operations._ordered_content(  # pyright: ignore[reportPrivateUsage]
        manifest,
        group_order={"parent": 0, "fleet": 1, "child": 2},
    )

    assert [(group, kind) for group, kind, _items in ordered] == [
        ("parent", "variables"),
        ("parent", "sources"),
        ("fleet", "destinations"),
        ("child", "variables"),
    ]


@pytest.mark.asyncio
async def test_replication_plan_and_execution_emit_durable_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    """A reviewed aggregate plan should execute once and save bounded target detail plus a receipt."""
    loaded = _loaded_manifest()
    snapshot = _snapshot()
    state = ManifestStateStore()

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(operations, "load_config_manifest", _load)
    monkeypatch.setattr(operations, "_source_snapshot", AsyncMock(return_value=snapshot))

    async def _target_plan(target: str, **_kwargs: object) -> dict[str, Any]:
        return {
            "server": target,
            "git": {},
            "items": [{"action": "update"}],
            "blocked_reasons": [],
            "target_plan_sha256": f"plan-{target}",
        }

    monkeypatch.setattr(operations, "_target_replication_plan", _target_plan)
    plan = await operations.plan_config_manifest_replication("wave.yaml", state_store=state)

    async def _write(target: str, **_kwargs: object) -> dict[str, Any]:
        return {
            "server": target,
            "status": "applied",
            "summary": {"updated": 1, "failed": 0},
            "items": [{"item_id": "out", "action": "updated"}],
            "receipt_groups": {"fleet": {"pending_diff_sha256": f"diff-{target}"}},
        }

    monkeypatch.setattr(operations, "_write_target", _write)
    context = _JobContext()
    result = await operations.execute_config_manifest_replication(
        "wave.yaml",
        expected_plan_sha256=str(plan["plan_sha256"]),
        state_store=state,
        job_context=context,  # type: ignore[arg-type]
    )

    assert result["status"] == "completed"
    assert result["summary"] == {"target_count": 2, "completed": 2, "failed_or_skipped": 0}
    assert set(context.details) == {"leader-a", "leader-b"}
    receipt = state.get_receipt(receipt_sha256=str(result["apply_receipt_sha256"]))
    assert receipt["job_id"] == "job-1"
    assert receipt["targets"]["leader-a"]["groups"]["fleet"]["pending_diff_sha256"] == "diff-leader-a"


@pytest.mark.asyncio
async def test_replication_drift_can_skip_or_abort(monkeypatch: pytest.MonkeyPatch) -> None:
    """Per-target drift should skip only that target unless the manifest requests global abort."""
    loaded = _loaded_manifest(targets=["leader-a"])
    state = ManifestStateStore()

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(operations, "load_config_manifest", _load)
    monkeypatch.setattr(operations, "_source_snapshot", AsyncMock(return_value=_snapshot()))
    calls = 0

    async def _target_plan(target: str, **_kwargs: object) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {
            "server": target,
            "git": {},
            "items": [],
            "blocked_reasons": [],
            "target_plan_sha256": "reviewed" if calls == 1 else "drifted",
        }

    monkeypatch.setattr(operations, "_target_replication_plan", _target_plan)
    plan = await operations.plan_config_manifest_replication("wave.yaml", state_store=state)
    context = _JobContext()
    skipped = await operations.execute_config_manifest_replication(
        "wave.yaml",
        expected_plan_sha256=str(plan["plan_sha256"]),
        state_store=state,
        job_context=context,  # type: ignore[arg-type]
        on_drift="skip",
    )
    assert skipped["status"] == "partial_failure"
    assert context.details["leader-a"]["status"] == "skipped_drift"

    with pytest.raises(ValueError, match="aborted"):
        await operations.execute_config_manifest_replication(
            "wave.yaml",
            expected_plan_sha256=str(plan["plan_sha256"]),
            state_store=state,
            job_context=_JobContext(),  # type: ignore[arg-type]
            on_drift="abort",
        )


@pytest.mark.asyncio
async def test_semantic_validation_tolerates_identity_differences(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment hostnames should be non-blocking while missing target objects remain blocking."""
    loaded = _loaded_manifest()
    source = _snapshot()
    source["items"][0]["item"] = {"id": "out", "type": "http", "host": "source.example"}

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(operations, "load_config_manifest", _load)
    monkeypatch.setattr(operations, "_source_snapshot", AsyncMock(return_value=source))

    @asynccontextmanager
    async def _connect(server: str) -> AsyncGenerator[SimpleNamespace]:
        yield SimpleNamespace(server_name=server)

    async def _target_item(target: SimpleNamespace, *_args: object, **_kwargs: object) -> dict[str, Any] | None:
        if target.server_name == "leader-b":
            return None
        return {"id": "out", "type": "http", "host": "target.example"}

    monkeypatch.setattr(operations, "connect_to_server", _connect)
    monkeypatch.setattr(operations, "_maybe_get_item", _target_item)
    result = await operations.validate_config_manifest("wave.yaml")

    assert result["status"] == "different"
    assert result["in_sync_count"] == 1
    first = next(target for target in result["targets"] if target["server"] == "leader-a")
    assert first["status"] == "in_sync"
    assert first["summary"]["identity_differences"] == 1


@pytest.mark.asyncio
async def test_commit_deploy_plan_and_execution_are_receipt_gated(monkeypatch: pytest.MonkeyPatch) -> None:
    """Commit/deploy should reuse only an exact apply receipt and reviewed inner plans."""
    loaded = _loaded_manifest()
    state = ManifestStateStore()
    receipt = {
        "receipt_sha256": "receipt",
        "job_id": "apply-job",
        "manifest_path": "wave.yaml",
        "manifest_sha256": "manifest",
        "intent_sha256": "intent",
        "targets": {
            "leader-a": {"status": "applied", "groups": {"fleet": {"pending_diff_sha256": "a"}}},
            "leader-b": {"status": "applied", "groups": {"fleet": {"pending_diff_sha256": "b"}}},
        },
    }
    state.save_receipt(
        receipt_sha256="receipt",
        job_id="apply-job",
        intent_sha256="intent",
        manifest_path="wave.yaml",
        created_at="now",
        payload=receipt,
    )

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(operations, "load_config_manifest", _load)
    monkeypatch.setattr(operations, "_receipt_drift", AsyncMock(return_value=[]))

    async def _commit(server: str, *, dry_run: bool, **_kwargs: object) -> dict[str, Any]:
        if dry_run:
            return {
                "status": "planned",
                "plan": {
                    "plan_sha256": f"inner-{server}",
                    "blocked_reasons": [],
                    "targets": [{"action": "commit_and_deploy"}],
                },
            }
        return {
            "status": "completed",
            "summary": {"target_count": 1},
            "push": {"status": "not_requested"},
            "errors": [],
        }

    monkeypatch.setattr(operations, "commit_and_deploy_all", _commit)
    plan = await operations.plan_manifest_commit_deploy(
        "wave.yaml",
        apply_job_id="apply-job",
        apply_receipt_sha256=None,
        message="wave test",
        push=False,
        state_store=state,
    )
    context = _JobContext(job_id="deploy-job")
    result = await operations.execute_manifest_commit_deploy(
        "wave.yaml",
        expected_plan_sha256=str(plan["plan_sha256"]),
        message="wave test",
        push=False,
        state_store=state,
        job_context=context,  # type: ignore[arg-type]
    )

    assert result["status"] == "completed"
    assert set(context.details) == {"leader-a", "leader-b"}
    assert all(detail["status"] == "completed" for detail in context.details.values())

    with pytest.raises(ValueError, match="message or push"):
        await operations.execute_manifest_commit_deploy(
            "wave.yaml",
            expected_plan_sha256=str(plan["plan_sha256"]),
            message="changed",
            push=False,
            state_store=state,
            job_context=_JobContext(),  # type: ignore[arg-type]
        )
