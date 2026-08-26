"""Tests for public configuration-manifest MCP tool wrappers."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp import Context

import snc_cribl_mcp.tools.config_manifest as tool_module
from snc_cribl_mcp.models.config_manifest import (
    ConfigManifest,
    LoadedConfigManifest,
    ManifestContent,
    ManifestOptions,
    ManifestSource,
)
from snc_cribl_mcp.operations.manifest_state import ManifestStateStore
from snc_cribl_mcp.operations.version_control_jobs import VersionControlJobManager


class _FakeApp:
    """Capture tool registrations without starting FastMCP."""

    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {}
        self.annotations: dict[str, dict[str, Any] | None] = {}

    def tool(
        self,
        *,
        name: str,
        description: str,
        annotations: dict[str, Any] | None = None,
    ) -> Callable[[Callable[..., Awaitable[dict[str, Any]]]], Callable[..., Awaitable[dict[str, Any]]]]:
        """Store one decorated tool function."""

        def _decorator(func: Callable[..., Awaitable[dict[str, Any]]]) -> Callable[..., Awaitable[dict[str, Any]]]:
            assert description
            self.tools[name] = func
            self.annotations[name] = annotations
            return func

        return _decorator


def _loaded() -> LoadedConfigManifest:
    manifest = ConfigManifest.model_construct(
        schema_=1,
        wave="test",
        source=ManifestSource.model_construct(server="source", product="edge"),
        content=[ManifestContent.model_construct(group="fleet", kind="sources", items=["in"])],
        targets=["target"],
        options=ManifestOptions.model_construct(overwrite=True, append_routes=False, concurrency=1, on_drift="skip"),
    )
    return LoadedConfigManifest.model_construct(
        manifest=manifest,
        path=Path("/safe/wave.yaml"),
        relative_path="wave.yaml",
        file_sha256="file",
        manifest_sha256="manifest",
    )


async def _wait(manager: VersionControlJobManager, job_id: str) -> dict[str, Any]:
    for _ in range(100):
        snapshot = await manager.get(job_id=job_id)
        if snapshot["status"] in {"completed", "failed"}:
            return snapshot
        await asyncio.sleep(0.01)
    msg = "Timed out waiting for manifest tool job."
    raise AssertionError(msg)


@pytest.mark.asyncio
async def test_manifest_tools_register_plan_validate_and_submit(monkeypatch: pytest.MonkeyPatch) -> None:
    """The three public tools should preserve the review contract and durable job path."""
    app = _FakeApp()
    jobs = VersionControlJobManager()
    state = ManifestStateStore()
    tool_module.register(app, job_manager=jobs, state_store=state)  # type: ignore[arg-type]
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()

    def _load_manifest(_path: str) -> LoadedConfigManifest:
        return _loaded()

    monkeypatch.setattr(tool_module, "load_config_manifest", _load_manifest)
    plan_impl = AsyncMock(return_value={"status": "planned", "plan_sha256": "plan"})
    validate_impl = AsyncMock(return_value={"status": "in_sync"})
    execute_impl = AsyncMock(return_value={"status": "completed"})
    commit_plan_impl = AsyncMock(return_value={"status": "planned", "plan_sha256": "deploy-plan"})
    monkeypatch.setattr(tool_module, "plan_config_manifest_replication", plan_impl)
    monkeypatch.setattr(tool_module, "validate_manifest_impl", validate_impl)
    monkeypatch.setattr(tool_module, "execute_config_manifest_replication", execute_impl)
    monkeypatch.setattr(tool_module, "plan_manifest_commit_deploy", commit_plan_impl)

    plan = await app.tools["replicate_config_manifest"](ctx, "wave.yaml")
    validation = await app.tools["validate_config_manifest"](ctx, "wave.yaml")
    deploy_plan = await app.tools["commit_and_deploy_manifest"](
        ctx,
        "wave.yaml",
        "test wave",
        apply_job_id="apply-job",
    )
    assert plan["plan_sha256"] == "plan"
    assert validation == {"status": "in_sync"}
    assert deploy_plan["plan_sha256"] == "deploy-plan"
    assert set(app.tools) == {
        "replicate_config_manifest",
        "validate_config_manifest",
        "commit_and_deploy_manifest",
    }
    assert app.annotations["validate_config_manifest"]["readOnlyHint"] is True  # type: ignore[index]

    with pytest.raises(ValueError, match="expected_plan_sha256"):
        await app.tools["replicate_config_manifest"](ctx, "wave.yaml", dry_run=False)

    accepted = await app.tools["replicate_config_manifest"](
        ctx,
        "wave.yaml",
        dry_run=False,
        expected_plan_sha256="plan",
    )
    completed = await _wait(jobs, str(accepted["job_id"]))
    assert completed["status"] == "completed"
    execute_impl.assert_awaited_once()
