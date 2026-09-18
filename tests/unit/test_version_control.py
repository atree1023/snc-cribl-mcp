"""Unit tests for Cribl version-control and deployment operations."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import unquote

import httpx
import pytest
from cribl_control_plane.errors import CriblControlPlaneError
from cribl_control_plane.models.countedgitdiffresult import CountedGitDiffResult
from cribl_control_plane.models.countedstring import CountedString
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from pytest_httpx import HTTPXMock

from snc_cribl_mcp.client.cribl_client import ResolvedControlPlane, create_control_plane
from snc_cribl_mcp.config import CriblConfig
from snc_cribl_mcp.models.config_manifest import ConfigManifest, LoadedConfigManifest, ManifestContent, ManifestSource
from snc_cribl_mcp.operations import config_manifest as manifest_ops
from snc_cribl_mcp.operations import version_control as vc
from snc_cribl_mcp.operations.git_diff import MAX_DIFF_BYTES
from snc_cribl_mcp.operations.manifest_state import ManifestStateStore


class _FakeModel:
    """Small generated-model stand-in for SDK response tests."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def model_dump(self, **_: object) -> dict[str, Any]:
        """Return the configured serialized payload."""
        return self.payload


class _Counted:
    """Small counted SDK response stand-in."""

    def __init__(self, *items: dict[str, Any], count: int | None = None) -> None:
        self.items = [_FakeModel(item) for item in items]
        self.count = len(items) if count is None else count


class _Page:
    """Small paginated SDK wrapper for group inventory tests."""

    def __init__(self, *items: dict[str, Any], next_page: object | None = None) -> None:
        self.result = _Counted(*items)
        self._next_page = next_page

    async def next(self) -> object | None:
        """Return the configured next page."""
        return self._next_page


def _group_payload(
    group_id: str,
    *,
    product: ProductsCore,
    committed: str = "commit-1",
    deployed: str = "commit-0",
    local_changes: int = 1,
    inherits: str | None = None,
) -> dict[str, Any]:
    """Build mutable group/fleet state for the fake SDK harness."""
    return {
        "id": group_id,
        "name": f"Name {group_id}",
        "description": f"Description {group_id}",
        "type": product.value,
        "inherits": inherits,
        "configVersion": deployed,
        "git": {"commit": committed, "localChanges": local_changes},
        "workerCount": 3,
        "deployingWorkerCount": 0,
        "incompatibleWorkerCount": 0,
    }


class _Harness:
    """Stateful fake Cribl SDK surface for end-to-end workflow tests."""

    def __init__(self, *groups: tuple[ProductsCore, dict[str, Any]]) -> None:
        self.states = {(product, str(payload["id"])): payload for product, payload in groups}
        self.client = MagicMock()
        self.global_dirty = False
        self.global_ahead = 0
        self.global_behind = 0
        self.global_conflicts: list[str] = []
        self.remote: str | bool = "https://user:secret@git.example.test/cribl/config.git"
        self.versioning = True
        self.commit_order: list[str] = []
        self.deploy_order: list[str] = []
        self.diff_calls: list[dict[str, Any]] = []
        self.push_count = 0
        self.push_error: Exception | None = None
        self.commit_error_for: str | None = None
        self.deploy_error_for: str | None = None
        self.dirty_leader_on_group_commit = False
        self.inherit_on_commit: dict[str, list[str]] = {}
        self.inherit_versions_on_commit: dict[str, list[str]] = {}
        self.commit_response_deletions: dict[str, int] = {}
        self.changed_paths_by_group: dict[str, list[str]] = {}
        self.diff_paths_by_group: dict[str, list[str]] = {}
        self._commit_sequence = 1

        self.client.groups.list_async = AsyncMock(side_effect=self._list_groups)
        self.client.groups.get_async = AsyncMock(side_effect=self._get_group)
        self.client.groups.deploy_async = AsyncMock(side_effect=self._deploy)
        self.client.versions.statuses.get_async = AsyncMock(side_effect=self._status)
        self.client.versions.commits.list_async = AsyncMock(side_effect=self._history)
        self.client.versions.commits.diff_async = AsyncMock(side_effect=self._diff)
        self.client.versions.commits.create_async = AsyncMock(side_effect=self._commit)
        self.client.versions.commits.push_async = AsyncMock(side_effect=self._push)
        self.client.versions.configs.get_async = AsyncMock(side_effect=self._git_info)

    @staticmethod
    def _scope_group(server_url: str | None) -> str | None:
        if server_url is None or "/m/" not in server_url:
            return None
        return unquote(server_url.rsplit("/", maxsplit=1)[-1])

    def _state_for_id(self, group_id: str) -> dict[str, Any]:
        matches = [payload for (_, candidate), payload in self.states.items() if candidate == group_id]
        if len(matches) != 1:
            msg = f"Expected one fake state for {group_id}."
            raise AssertionError(msg)
        return matches[0]

    async def _list_groups(self, *, product: ProductsCore, **_: object) -> _Counted:
        return _Counted(*(payload for (candidate, _), payload in self.states.items() if candidate == product))

    async def _get_group(self, *, product: ProductsCore, id: str, **_: object) -> _Counted:  # noqa: A002
        return _Counted(self.states[(product, id)])

    async def _status(self, *, server_url: str | None = None, **_: object) -> _Counted:
        group_id = self._scope_group(server_url)
        if group_id is None:
            changed = [vc._LEADER_METADATA_PATH] if self.global_dirty else []
            return _Counted(
                {
                    "ahead": self.global_ahead,
                    "behind": self.global_behind,
                    "conflicted": self.global_conflicts,
                    "created": [],
                    "current": "main",
                    "deleted": [],
                    "files": [{"path": path, "index": "M", "working_dir": "M"} for path in changed],
                    "modified": changed,
                    "not_added": [],
                    "renamed": [],
                    "staged": [],
                }
            )

        state = self._state_for_id(group_id)
        dirty = bool(cast("dict[str, Any]", state["git"])["localChanges"])
        changed = self.changed_paths_by_group.get(group_id, [f"local/cribl/{group_id}.yml"] if dirty else [])
        return _Counted(
            {
                "ahead": 0,
                "behind": 0,
                "conflicted": [],
                "created": [],
                "current": "main",
                "deleted": [],
                "files": [{"path": path, "index": "M", "working_dir": "M"} for path in changed],
                "modified": changed,
                "not_added": [],
                "renamed": [],
                "staged": [],
            }
        )

    async def _history(self, *, server_url: str | None = None, **_: object) -> _Counted:
        group_id = self._scope_group(server_url)
        if group_id is None:
            return _Counted()
        state = self._state_for_id(group_id)
        return _Counted({"hash": cast("dict[str, Any]", state["git"])["commit"]})

    @staticmethod
    def _diff_file(group_id: str) -> dict[str, Any]:
        return {
            "addedLines": 2,
            "blocks": [],
            "deletedLines": 1,
            "isBinary": False,
            "isCombined": False,
            "isGitDiff": True,
            "isTooBig": False,
            "language": "yaml",
            "newName": f"local/cribl/{group_id}.yml",
            "oldName": f"local/cribl/{group_id}.yml",
        }

    async def _diff(
        self,
        *,
        commit: str | None = None,
        filename: str | None = None,
        diff_line_limit: int | None = None,
        server_url: str | None = None,
        **_: object,
    ) -> _Counted:
        group_id = self._scope_group(server_url)
        if group_id is None:
            if filename != "local/cribl/groups.yml":
                msg = "Expected a group-scoped diff call or the guarded Leader metadata file."
                raise AssertionError(msg)
            files = []
            if self.global_dirty:
                files = [
                    {
                        **self._diff_file("groups"),
                        "newName": "local/cribl/groups.yml",
                        "oldName": "local/cribl/groups.yml",
                    }
                ]
            return _Counted({"diffJson": files})
        self.diff_calls.append(
            {
                "group": group_id,
                "commit": commit,
                "filename": filename,
                "diff_line_limit": diff_line_limit,
            }
        )
        state = self._state_for_id(group_id)
        git = cast("dict[str, Any]", state["git"])
        dirty = bool(git["localChanges"])
        differs_from_commit = commit is not None and commit != git["commit"]
        configured_paths = self.diff_paths_by_group.get(group_id)
        if configured_paths is not None:
            files = [
                {
                    **self._diff_file(group_id),
                    "newName": path,
                    "oldName": path,
                }
                for path in configured_paths
            ]
        else:
            files = [self._diff_file(group_id)] if dirty or differs_from_commit else []
        return _Counted({"diffJson": files})

    async def _commit(
        self,
        *,
        message: str,
        server_url: str | None = None,
        files: list[str] | None = None,
        **_: object,
    ) -> _Counted:
        group_id = self._scope_group(server_url)
        if group_id is None:
            self.global_dirty = False
            self.global_ahead += 1
            return _Counted(
                {
                    "branch": "main",
                    "commit": "leader-sync",
                    "summary": {"changes": 1, "insertions": 1, "deletions": 1},
                    "files": {"modified": files or []},
                }
            )
        if group_id == self.commit_error_for:
            msg = f"commit failed for {group_id}"
            raise RuntimeError(msg)
        self._commit_sequence += 1
        version = f"commit-{group_id}-{self._commit_sequence}"
        state = self._state_for_id(group_id)
        cast("dict[str, Any]", state["git"])["commit"] = version
        cast("dict[str, Any]", state["git"])["localChanges"] = 0
        self.commit_order.append(group_id)
        if self.dirty_leader_on_group_commit:
            self.global_dirty = True
        for descendant in self.inherit_on_commit.get(group_id, []):
            cast("dict[str, Any]", self._state_for_id(descendant)["git"])["localChanges"] = 1
        for descendant in self.inherit_versions_on_commit.get(group_id, []):
            descendant_git = cast("dict[str, Any]", self._state_for_id(descendant)["git"])
            descendant_git["commit"] = f"{version}-inherited-{descendant}"
            descendant_git["localChanges"] = 0
        return _Counted(
            {
                "branch": "main",
                "commit": version,
                "summary": {
                    "changes": 1,
                    "insertions": 2,
                    "deletions": self.commit_response_deletions.get(group_id, 1),
                },
                "files": {"modified": [f"local/cribl/{group_id}.yml"]},
                "message": message,
            }
        )

    async def _deploy(
        self,
        *,
        product: ProductsCore,
        id: str,  # noqa: A002
        version: str,
        **_: object,
    ) -> _Counted:
        if id == self.deploy_error_for:
            msg = f"deploy failed for {id}"
            raise RuntimeError(msg)
        state = self.states[(product, id)]
        state["configVersion"] = version
        self.deploy_order.append(id)
        self.global_dirty = True
        return _Counted(state)

    async def _git_info(self, **_: object) -> _Counted:
        return _Counted({"remote": self.remote, "versioning": self.versioning})

    async def _push(self, **_: object) -> CountedString:
        if self.push_error is not None:
            raise self.push_error
        self.push_count += 1
        self.global_ahead = 0
        return CountedString(count=1, items=["raw remote push output"])


def _install_harness(monkeypatch: pytest.MonkeyPatch, harness: _Harness) -> None:
    """Patch the operation module to use one stateful fake control plane."""

    @asynccontextmanager
    async def _connect(_server: str | None) -> AsyncGenerator[ResolvedControlPlane]:
        resolved = SimpleNamespace(
            server_name="test",
            config=SimpleNamespace(base_url_str="https://cribl.example.test/api/v1", timeout_ms=1000),
            client=harness.client,
        )
        yield cast("ResolvedControlPlane", resolved)

    monkeypatch.setattr(vc, "connect_to_server", _connect)


def test_group_target_helpers_and_serialization() -> None:
    """Target and SDK response helpers should normalize common shapes."""
    payload = _group_payload("edge child", product=ProductsCore.EDGE, inherits="parent")
    target = vc.GroupTarget.from_payload(ProductsCore.EDGE, payload)

    assert target.group_id == "edge child"
    assert target.inherits == "parent"
    assert target.local_changes == 1
    assert target.deploying_worker_count == 0
    assert target.incompatible_worker_count == 0
    assert target.as_dict()["deployed_version"] == "commit-0"
    zero_target = vc.GroupTarget.from_payload(
        ProductsCore.STREAM,
        _group_payload("zero", product=ProductsCore.STREAM, local_changes=0),
    )
    assert zero_target.local_changes == 0
    assert zero_target.worker_count == 3
    assert vc._group_server_url("https://example/api/v1/", "edge child") == "https://example/api/v1/m/edge%20child"
    assert vc._serialize_counted_response(_Counted({"id": "one"}, count=None))["count"] == 1
    assert vc._first_counted_item(_Counted()) is None
    assert vc._optional_int(True) is None  # noqa: FBT003
    assert vc._optional_int("12") == 12
    assert vc._optional_int(object()) is None
    with pytest.raises(TypeError, match="Expected an SDK model"):
        vc._serialize_model(object())
    with pytest.raises(ValueError, match="did not include an id"):
        vc.GroupTarget.from_payload(ProductsCore.STREAM, {})


def test_status_diff_and_remote_helpers_cover_response_shapes() -> None:
    """Status, diff, and remote helpers should retain safety-relevant metadata."""
    status = {
        "current": "main",
        "ahead": 2.0,
        "behind": 1,
        "conflicted": ["conflict.yml"],
        "created": ["created.yml"],
        "deleted": [],
        "modified": ["modified.yml"],
        "notAdded": ["new.yml"],
        "staged": [],
        "files": [{"path": "from-files.yml"}],
        "renamed": [{"from": "old.yml", "to": "new-name.yml"}],
    }
    summary = vc._status_summary(status)
    assert summary["ahead"] == 2
    assert summary["behind"] == 1
    assert summary["clean"] is False
    assert "new-name.yml" in summary["changed_paths"]

    diff_payload = {"items": [{"diffJson": [_Harness._diff_file("default")]}]}
    diff_summary = vc._diff_summary(diff_payload)
    assert diff_summary["file_count"] == 1
    assert diff_summary["added_lines"] == 2
    assert diff_summary["deleted_lines"] == 1
    assert vc._canonical_digest(vc._diff_files(diff_payload)) == vc._canonical_digest(vc._diff_files(diff_payload))
    assert vc._safe_remote("https://user:password@git.example.test/repo.git") == "https://git.example.test/repo.git"
    assert vc._safe_remote("git@example.test:repo.git") == "configured"
    bounded_error = vc._error_payload(RuntimeError("x" * 3000))
    assert len(bounded_error["message"]) == vc._MAX_ERROR_MESSAGE_CHARS
    assert bounded_error["message_truncated"] is True


@pytest.mark.asyncio
async def test_group_git_status_uses_one_coherent_local_change_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inventory metadata must not contradict the Git status in one response."""
    state = _group_payload("default", product=ProductsCore.STREAM, local_changes=1)
    harness = _Harness((ProductsCore.STREAM, state))
    harness.changed_paths_by_group["default"] = []
    _install_harness(monkeypatch, harness)

    result = await vc.collect_group_git_status("test", product="stream", group="default")

    target_result = result["targets"][0]
    assert target_result["target"]["local_changes"] == 0
    assert target_result["git"]["local_changes"] == 0
    assert target_result["git"]["changed_count"] == 0
    assert target_result["git"]["clean"] is True


@pytest.mark.asyncio
async def test_large_change_plan_and_execution_results_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Large replications should return one capped path preview and no raw mutation payloads."""
    state = _group_payload("default", product=ProductsCore.STREAM)
    harness = _Harness((ProductsCore.STREAM, state))
    paths = [f"local/cribl/config-{index:03}.yml" for index in range(107)]
    harness.changed_paths_by_group["default"] = paths
    harness.diff_paths_by_group["default"] = paths
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Replicate complete configuration",
    )
    plan = cast("dict[str, Any]", planned["plan"])
    changes = cast("dict[str, Any]", plan["changes"])

    assert changes["changed_count"] == 107
    assert len(changes["changed_paths"]) == vc._MAX_STATUS_PATHS
    assert changes["changed_paths_truncated"] is True
    assert len(changes["changed_paths_sha256"]) == 64
    assert "changed_paths" not in plan["git"]
    assert "pending_diff" not in plan
    assert json.dumps(planned).count(paths[0]) == 1
    assert len(json.dumps(planned)) < 12_000

    result = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Replicate complete configuration",
        dry_run=False,
        expected_plan_sha256=plan["plan_sha256"],
    )
    serialized_result = json.dumps(result)

    assert result["status"] == "deployed"
    assert result["executed_plan_sha256"] == plan["plan_sha256"]
    assert "plan" not in result
    assert "commit_response" not in result
    assert "deployment" not in result
    assert all(path not in serialized_result for path in paths)
    assert len(serialized_result) < 4_000


def test_deployment_order_is_parent_first_and_validates_hierarchy() -> None:
    """Edge Fleet topological ordering should handle levels, missing parents, and cycles."""
    stream = vc.GroupTarget(ProductsCore.STREAM, "stream-b")
    parent = vc.GroupTarget(ProductsCore.EDGE, "parent")
    child = vc.GroupTarget(ProductsCore.EDGE, "child", inherits="parent")
    grandchild = vc.GroupTarget(ProductsCore.EDGE, "grandchild", inherits="child")

    order = vc._deployment_order([grandchild, child, stream, parent])
    assert [target.group_id for target in order] == ["stream-b", "parent", "child", "grandchild"]
    with pytest.raises(ValueError, match="unknown fleet"):
        vc._deployment_order([child])
    with pytest.raises(ValueError, match="contains a cycle"):
        vc._deployment_order(
            [
                vc.GroupTarget(ProductsCore.EDGE, "one", inherits="two"),
                vc.GroupTarget(ProductsCore.EDGE, "two", inherits="one"),
            ]
        )


@pytest.mark.asyncio
async def test_collect_status_supports_one_subfleet_without_parent_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """A targeted read should not require the parent Fleet to be in the selected result."""
    child = _group_payload("child", product=ProductsCore.EDGE, local_changes=0, inherits="hidden-parent")
    harness = _Harness((ProductsCore.EDGE, child))
    _install_harness(monkeypatch, harness)

    result = await vc.collect_group_git_status("test", product="edge", group="Name child")

    assert result["count"] == 1
    assert result["targets"][0]["target"]["id"] == "child"
    assert result["targets"][0]["git"]["deployment_pending"] is True
    with pytest.raises(ValueError, match="product must be"):
        await vc.collect_group_git_status("test", product="all", group="child")


@pytest.mark.asyncio
async def test_collect_status_omits_internal_search_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stream status should cover worker groups without mutating internal Search groups."""
    workers = _group_payload("workers", product=ProductsCore.STREAM, local_changes=0)
    search = _group_payload("search", product=ProductsCore.STREAM, local_changes=0)
    search.update({"type": "search", "isSearch": True})
    harness = _Harness((ProductsCore.STREAM, search), (ProductsCore.STREAM, workers))
    _install_harness(monkeypatch, harness)

    result = await vc.collect_group_git_status("test", product="stream")

    assert result["count"] == 1
    assert result["targets"][0]["target"]["id"] == "workers"


@pytest.mark.asyncio
async def test_collect_status_reads_current_sdk_group_result_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    """Git status inventory should not turn SDK 0.11 group wrappers into zero targets."""
    workers = _group_payload("workers", product=ProductsCore.STREAM, local_changes=0)
    harness = _Harness((ProductsCore.STREAM, workers))

    async def _wrapped_groups(*, product: ProductsCore, **_: object) -> SimpleNamespace:
        payloads = [payload for (candidate, _), payload in harness.states.items() if candidate == product]
        return SimpleNamespace(result=_Counted(*payloads))

    harness.client.groups.list_async = AsyncMock(side_effect=_wrapped_groups)
    _install_harness(monkeypatch, harness)

    result = await vc.collect_group_git_status("test", product="stream")

    assert result["count"] == 1
    assert result["targets"][0]["target"]["id"] == "workers"


@pytest.mark.asyncio
async def test_collect_status_exhausts_sdk_group_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    """Version-control target discovery should include groups from every SDK page."""
    first = _group_payload("first", product=ProductsCore.STREAM, local_changes=0)
    second = _group_payload("second", product=ProductsCore.STREAM, local_changes=0)
    harness = _Harness((ProductsCore.STREAM, first), (ProductsCore.STREAM, second))
    harness.client.groups.list_async = AsyncMock(return_value=_Page(first, next_page=_Page(second)))
    _install_harness(monkeypatch, harness)

    result = await vc.collect_group_git_status("test", product="stream")

    assert result["count"] == 2
    assert [entry["target"]["id"] for entry in result["targets"]] == ["first", "second"]


@pytest.mark.asyncio
async def test_collect_diff_uses_deployed_baseline_and_full_pending_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Diff reads should compare with configVersion and hash the complete pending diff."""
    state = _group_payload("default", product=ProductsCore.STREAM)
    harness = _Harness((ProductsCore.STREAM, state))
    _install_harness(monkeypatch, harness)

    result = await vc.collect_group_git_diff(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        compare_to="deployed",
        filename="local/cribl/default.yml",
        diff_line_limit=10,
    )

    assert result["comparison_commit"] == "commit-0"
    assert result["summary"]["file_count"] == 1
    assert len(result["pending_diff_sha256"]) == 64
    assert harness.diff_calls[0]["commit"] == "commit-0"
    assert harness.diff_calls[1] == {
        "group": "default",
        "commit": None,
        "filename": None,
        "diff_line_limit": 0,
    }
    with pytest.raises(ValueError, match="zero or greater"):
        await vc.collect_group_git_diff(
            "test",
            product=ProductsCore.STREAM,
            group="default",
            diff_line_limit=-1,
        )


@pytest.mark.asyncio
async def test_commit_group_requires_reviewed_plan_and_reports_push_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Commit-only execution should enforce plan drift and preserve a successful commit on push failure."""
    state = _group_payload("default", product=ProductsCore.STREAM)
    harness = _Harness((ProductsCore.STREAM, state))
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Validated source update",
        push=True,
    )
    plan_hash = planned["plan"]["plan_sha256"]
    with pytest.raises(ValueError, match="stale"):
        await vc.commit_group_config(
            "test",
            product=ProductsCore.STREAM,
            group="default",
            message="Validated source update",
            push=True,
            dry_run=False,
            expected_plan_sha256="stale",
        )

    harness.push_error = RuntimeError("remote rejected")
    result = await vc.commit_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Validated source update",
        push=True,
        dry_run=False,
        expected_plan_sha256=plan_hash,
    )

    assert result["status"] == "partial_failure"
    assert result["completed_steps"] == ["group_commit"]
    assert result["commit"]["version"].startswith("commit-default-")
    assert result["push"]["status"] == "failed"
    assert "plan" not in result
    assert "commit_response" not in result


@pytest.mark.asyncio
async def test_commit_group_uses_selected_file_diff_for_line_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Selective commits should report only the reviewed files' pre-commit line counts."""
    state = _group_payload("default", product=ProductsCore.STREAM)
    harness = _Harness((ProductsCore.STREAM, state))
    selected_path = "local/cribl/selected.yml"
    harness.changed_paths_by_group["default"] = [selected_path, "local/cribl/other.yml"]
    harness.diff_paths_by_group["default"] = [selected_path, "local/cribl/other.yml"]
    harness.commit_response_deletions["default"] = 0
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Commit one reviewed file",
        files=[selected_path],
    )
    result = await vc.commit_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Commit one reviewed file",
        files=[selected_path],
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    assert planned["plan"]["changes"]["changed_paths"] == [selected_path]
    assert result["commit"]["line_changes"] == {"total": 3, "insertions": 2, "deletions": 1}


@pytest.mark.asyncio
async def test_deploy_explicit_version_commits_leader_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit deploy should use the requested hash and make a scoped Leader metadata commit."""
    state = _group_payload("default", product=ProductsCore.STREAM, local_changes=0)
    harness = _Harness((ProductsCore.STREAM, state))
    _install_harness(monkeypatch, harness)

    planned = await vc.deploy_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        version="rollback-123",
    )
    result = await vc.deploy_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        version="rollback-123",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    assert result["status"] == "deployed"
    assert result["version"] == "rollback-123"
    assert result["leader_commit"]["files"] == ["local/cribl/groups.yml"]
    assert result["control_plane_version_confirmed"] is True
    assert harness.deploy_order == ["default"]

    harness.global_conflicts = ["unrelated-conflict.yml"]
    blocked = await vc.deploy_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        version="next-version",
    )
    assert "Leader Git working tree contains conflicts" in blocked["plan"]["blocked_reasons"][0]
    with pytest.raises(ValueError, match="contains conflicts"):
        await vc.deploy_group_config(
            "test",
            product=ProductsCore.STREAM,
            group="default",
            version="next-version",
            dry_run=False,
            expected_plan_sha256=blocked["plan"]["plan_sha256"],
        )


@pytest.mark.asyncio
async def test_commit_and_deploy_group_runs_complete_workflow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Single-target workflow should commit, deploy, sync the Leader, and push in order."""
    state = _group_payload("fleet", product=ProductsCore.EDGE)
    harness = _Harness((ProductsCore.EDGE, state))
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.EDGE,
        group="fleet",
        message="Tune Edge source",
        push=True,
    )
    result = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.EDGE,
        group="fleet",
        message="Tune Edge source",
        push=True,
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    assert result["status"] == "deployed"
    assert result["completed_steps"] == ["group_commit", "deploy", "leader_commit", "push"]
    assert harness.commit_order == ["fleet"]
    assert harness.deploy_order == ["fleet"]
    assert harness.push_count == 1


@pytest.mark.asyncio
async def test_commit_and_deploy_group_rechecks_leader_before_deploy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Leader metadata drift after a group commit should stop before deployment."""
    state = _group_payload("default", product=ProductsCore.STREAM)
    harness = _Harness((ProductsCore.STREAM, state))
    harness.dirty_leader_on_group_commit = True
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Guard Leader state",
    )
    result = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Guard Leader state",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    assert result["status"] == "failed"
    assert result["completed_steps"] == ["group_commit"]
    assert "changed after planning" in result["error"]["message"]
    assert harness.deploy_order == []


@pytest.mark.asyncio
async def test_targeted_subfleet_blocks_until_parent_is_committed_and_deployed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A specific subfleet workflow should not leapfrog pending parent configuration."""
    parent = _group_payload("parent", product=ProductsCore.EDGE, local_changes=1)
    child = _group_payload("child", product=ProductsCore.EDGE, local_changes=1, inherits="parent")
    harness = _Harness((ProductsCore.EDGE, child), (ProductsCore.EDGE, parent))
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.EDGE,
        group="child",
        message="Update one subfleet",
    )

    assert planned["plan"]["edge_ancestors"][0]["target"]["id"] == "parent"
    assert "pending configuration" in planned["plan"]["blocked_reasons"][0]
    with pytest.raises(ValueError, match="parent chain first"):
        await vc.commit_and_deploy_group(
            "test",
            product=ProductsCore.EDGE,
            group="child",
            message="Update one subfleet",
            dry_run=False,
            expected_plan_sha256=planned["plan"]["plan_sha256"],
        )


@pytest.mark.asyncio
async def test_commit_and_deploy_all_rechecks_descendants_and_deploys_parent_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All-target workflow should capture inherited changes and preserve Edge hierarchy order."""
    parent = _group_payload("parent", product=ProductsCore.EDGE, local_changes=1)
    child = _group_payload(
        "child",
        product=ProductsCore.EDGE,
        local_changes=0,
        deployed="commit-1",
        inherits="parent",
    )
    grandchild = _group_payload(
        "grandchild",
        product=ProductsCore.EDGE,
        local_changes=0,
        deployed="commit-1",
        inherits="child",
    )
    harness = _Harness(
        (ProductsCore.EDGE, grandchild),
        (ProductsCore.EDGE, child),
        (ProductsCore.EDGE, parent),
    )
    harness.inherit_versions_on_commit = {"parent": ["child", "grandchild"]}
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_all("test", message="Roll out inherited Edge settings", product="edge")
    plan_by_id = {item["target"]["id"]: item for item in planned["plan"]["targets"]}
    assert plan_by_id["parent"]["action"] == "commit_and_deploy"
    assert plan_by_id["child"]["action"] == "deploy_inherited"
    assert plan_by_id["child"]["inherited_deploy_from"] == "parent"
    assert plan_by_id["grandchild"]["action"] == "deploy_inherited"
    assert plan_by_id["grandchild"]["inherited_deploy_from"] == "parent"
    progress: list[dict[str, Any]] = []

    async def _progress(item: dict[str, Any]) -> None:
        progress.append(item)

    result = await vc.commit_and_deploy_all(
        "test",
        message="Roll out inherited Edge settings",
        product="edge",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
        progress_callback=_progress,
    )

    assert result["status"] == "completed"
    assert harness.commit_order == ["parent"]
    assert harness.deploy_order == ["parent", "child", "grandchild"]
    commit_by_id = {item["target"]["id"]: item for item in result["commit_results"]}
    assert commit_by_id["child"]["status"] == "noop"
    assert commit_by_id["child"]["changes"]["changed_after_parent_commit"] is True
    assert commit_by_id["grandchild"]["status"] == "noop"
    assert commit_by_id["grandchild"]["changes"]["changed_after_parent_commit"] is True
    assert result["leader_commit"]["status"] == "committed"
    assert all(item["control_plane_version_confirmed"] for item in result["deploy_results"])
    assert [item["group"] for item in progress] == ["parent", "child", "grandchild"]
    assert harness.push_count == 0


@pytest.mark.asyncio
async def test_leader_git_diff_exposes_only_deployment_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    """The read-only Leader diff should close the groups.yml blocker inspection loop."""
    harness = _Harness()
    harness.global_dirty = True
    _install_harness(monkeypatch, harness)

    result = await vc.collect_leader_git_diff("test", diff_line_limit=0)

    assert result["scope"] == "leader"
    assert result["filename"] == "local/cribl/groups.yml"
    assert result["summary"]["paths"] == ["local/cribl/groups.yml"]


@pytest.mark.asyncio
async def test_commit_and_deploy_all_manifest_scope_includes_only_requested_edge_descendants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Manifest scope should include an affected subtree without committing unrelated fleets."""
    root = _group_payload("root", product=ProductsCore.EDGE, local_changes=0, deployed="commit-1")
    ancestor = _group_payload("linux", product=ProductsCore.EDGE, local_changes=0, deployed="commit-1", inherits="root")
    parent = _group_payload("parent", product=ProductsCore.EDGE, local_changes=1, inherits="linux")
    child = _group_payload("child", product=ProductsCore.EDGE, local_changes=0, inherits="parent")
    unrelated = _group_payload("unrelated", product=ProductsCore.EDGE, local_changes=1, inherits="linux")
    harness = _Harness(
        (ProductsCore.EDGE, unrelated),
        (ProductsCore.EDGE, child),
        (ProductsCore.EDGE, parent),
        (ProductsCore.EDGE, ancestor),
        (ProductsCore.EDGE, root),
    )
    harness.inherit_versions_on_commit = {"parent": ["child"]}
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_all(
        "test",
        message="Deploy one manifest subtree",
        product="edge",
        groups=["parent"],
    )
    assert [item["target"]["id"] for item in planned["plan"]["targets"]] == ["parent", "child"]
    assert planned["plan"]["requested_groups"] == ["parent"]

    result = await vc.commit_and_deploy_all(
        "test",
        message="Deploy one manifest subtree",
        product="edge",
        groups=["parent"],
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )
    assert result["status"] == "completed"
    assert harness.commit_order == ["parent"]
    assert harness.deploy_order == ["parent", "child"]
    assert "unrelated" not in harness.commit_order


@pytest.mark.asyncio
@pytest.mark.parametrize("ancestor_state", ["dirty", "undeployed", "unreadable"])
async def test_manifest_scope_blocks_unsettled_external_ancestors(monkeypatch: pytest.MonkeyPatch, ancestor_state: str) -> None:
    """Child-only scope must still require the entire external parent chain to be settled."""
    root = _group_payload(
        "root",
        product=ProductsCore.EDGE,
        local_changes=int(ancestor_state == "dirty"),
        deployed="commit-0" if ancestor_state == "undeployed" else "commit-1",
    )
    parent = _group_payload("linux", product=ProductsCore.EDGE, local_changes=0, deployed="commit-1", inherits="root")
    child = _group_payload("appnodes", product=ProductsCore.EDGE, inherits="linux")
    harness = _Harness(*((ProductsCore.EDGE, item) for item in (child, parent, root)))
    _install_harness(monkeypatch, harness)
    if ancestor_state == "unreadable":

        async def _status(*, server_url: str | None = None, **kwargs: object) -> _Counted:
            if harness._scope_group(server_url) == "root":
                msg = "Parent status unavailable"
                raise RuntimeError(msg)
            return await harness._status(server_url=server_url, **kwargs)

        harness.client.versions.statuses.get_async.side_effect = _status

    planned = await vc.commit_and_deploy_all("test", message="Child scope", product="edge", groups=["appnodes"])
    reason = "Cannot verify Edge ancestor 'root'" if ancestor_state == "unreadable" else "Edge ancestor 'root' has pending"
    assert any(reason in block for block in planned["plan"]["blocked_reasons"])
    with pytest.raises(ValueError, match=reason):
        await vc.commit_and_deploy_all(
            "test",
            message="Child scope",
            product="edge",
            groups=["appnodes"],
            dry_run=False,
            expected_plan_sha256=planned["plan"]["plan_sha256"],
        )
    assert harness.commit_order == harness.deploy_order == []
    assert harness.push_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_hierarchy", ["missing", "cycle"])
async def test_manifest_scope_rejects_invalid_full_hierarchy(monkeypatch: pytest.MonkeyPatch, invalid_hierarchy: str) -> None:
    """Filtering must not hide an actually missing parent or a cycle in its ancestor chain."""
    child = _group_payload("appnodes", product=ProductsCore.EDGE, inherits="linux")
    parent = _group_payload(
        "linux", product=ProductsCore.EDGE, inherits="absent" if invalid_hierarchy == "missing" else "appnodes"
    )
    harness = _Harness((ProductsCore.EDGE, child), (ProductsCore.EDGE, parent))
    _install_harness(monkeypatch, harness)
    reason = "unknown fleet 'absent'" if invalid_hierarchy == "missing" else "contains a cycle"
    with pytest.raises(ValueError, match=reason):
        await vc.commit_and_deploy_all("test", message="Invalid scope", product="edge", groups=["appnodes"])
    assert harness.commit_order == harness.deploy_order == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ancestor_drift", "push_outcome"),
    [
        ("none", "not_requested"),
        ("dirty", "not_requested"),
        ("redeployed", "not_requested"),
        ("none", "pushed"),
        ("none", "failed"),
    ],
)
async def test_manifest_child_only_receipt_uses_full_hierarchy(  # noqa: PLR0915 - end-to-end receipt, deploy, and push outcomes
    monkeypatch: pytest.MonkeyPatch, ancestor_drift: str, push_outcome: str
) -> None:
    """Child-only manifests must preserve hierarchy guards and report actual push outcomes (#25/#26)."""
    parent = _group_payload("linux", product=ProductsCore.EDGE, local_changes=0, deployed="commit-1")
    appnodes = _group_payload("appnodes", product=ProductsCore.EDGE, inherits="linux")
    dbnodes = _group_payload("dbnodes", product=ProductsCore.EDGE, inherits="linux")
    descendant = _group_payload(
        "appchild", product=ProductsCore.EDGE, local_changes=0, deployed="commit-1", inherits="appnodes"
    )
    unrelated = _group_payload("unrelated", product=ProductsCore.EDGE, inherits="linux")
    harness = _Harness(*((ProductsCore.EDGE, item) for item in (descendant, dbnodes, appnodes, unrelated, parent)))
    harness.inherit_versions_on_commit = {"appnodes": ["appchild"]}
    push_requested = push_outcome != "not_requested"
    if push_outcome == "failed":
        harness.push_error = RuntimeError("remote rejected")
    _install_harness(monkeypatch, harness)
    loaded = LoadedConfigManifest.model_construct(
        manifest=ConfigManifest.model_construct(
            schema_=1,
            wave="child-only",
            source=ManifestSource.model_construct(server="source", product="edge"),
            content=[
                ManifestContent.model_construct(group="dbnodes", kind="sources", items=["source-lastlogin"]),
                ManifestContent.model_construct(group="appnodes", kind="sources", items=["source-net", "source-xml"]),
            ],
            targets=["test"],
        ),
        path=Path("/safe/child-only.yaml"),
        relative_path="child-only.yaml",
        file_sha256="file",
        manifest_sha256="manifest",
    )

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(manifest_ops, "load_config_manifest", _load)
    receipt_groups: dict[str, Any] = {}
    for group_id in ("appnodes", "dbnodes"):
        diff = await vc.collect_group_git_diff("test", product=ProductsCore.EDGE, group=group_id, diff_line_limit=0)
        receipt_groups[group_id] = {"pending_diff_sha256": diff["pending_diff_sha256"]}
    state = ManifestStateStore()
    state.save_receipt(
        receipt_sha256="receipt",
        job_id="apply-job",
        intent_sha256="intent",
        manifest_path=loaded.relative_path,
        created_at="now",
        payload={
            "receipt_sha256": "receipt",
            "intent_sha256": "intent",
            "manifest_path": loaded.relative_path,
            "manifest_sha256": loaded.manifest_sha256,
            "targets": {"test": {"status": "applied", "groups": receipt_groups}},
        },
    )
    planned = await manifest_ops.plan_manifest_commit_deploy(
        loaded.relative_path,
        apply_job_id="apply-job",
        apply_receipt_sha256=None,
        message="Deploy child-only manifest",
        push=push_requested,
        state_store=state,
    )
    assert planned["blocked_target_count"] == 0
    target_plan = planned["targets"][0]
    assert [(item["group"], item["action"]) for item in target_plan["ordered_actions"]] == [
        ("appnodes", "commit_and_deploy"),
        ("appchild", "deploy_inherited"),
        ("dbnodes", "commit_and_deploy"),
    ]
    assert target_plan["summary"]["target_count"] == 3
    assert harness.commit_order == harness.deploy_order == []
    if ancestor_drift == "dirty":
        parent["git"]["localChanges"] = 1
    elif ancestor_drift == "redeployed":
        parent["git"]["commit"] = parent["configVersion"] = "commit-new"

    context = MagicMock(job_id="deploy-job")
    result = await manifest_ops.execute_manifest_commit_deploy(
        loaded.relative_path,
        expected_plan_sha256=planned["plan_sha256"],
        message="Deploy child-only manifest",
        push=push_requested,
        state_store=state,
        job_context=context,
        on_drift="skip",
    )
    assert "raw remote push output" not in json.dumps(result)
    if ancestor_drift == "none":
        assert result["status"] == ("partial_failure" if push_outcome == "failed" else "completed")
        assert result["failed_targets"] == (["test"] if push_outcome == "failed" else [])
        assert harness.commit_order == ["appnodes", "dbnodes"]
        assert harness.deploy_order == ["appnodes", "appchild", "dbnodes"]
        assert context.update_progress.call_args.args[0]["completed"] == 3
        detail = context.set_target_detail.call_args.args[1]
        assert detail["push"]["requested"] is push_requested
        assert detail["push"]["status"] == push_outcome
        if push_outcome == "pushed":
            assert detail["push"]["verification"] == "api_reports_synced"
            assert detail["push"]["remote_sync_verified"] is False
        assert "raw remote push output" not in json.dumps(detail)
        assert harness.client.versions.commits.push_async.await_count == int(push_requested)
        if push_outcome == "failed":
            assert detail["errors"] == [{"phase": "push", "error": {"type": "RuntimeError", "message": "remote rejected"}}]
            assert harness.global_ahead > 0
        else:
            assert detail["errors"] == []
        if push_outcome == "pushed":
            assert harness.global_ahead == 0
            followup = await vc.push_config_git("test")
            assert followup["plan"]["action"] == "noop"
    else:
        assert result["status"] == "partial_skip"
        assert result["skipped_targets"] == ["test"]
        assert result["failed_targets"] == []
        assert harness.commit_order == harness.deploy_order == []
        assert harness.push_count == 0


@pytest.mark.asyncio
async def test_commit_and_deploy_all_uses_precommit_diff_line_counts_across_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Alternating bad SDK deletion summaries must not corrupt commit audit results."""
    groups = [
        _group_payload(group_id, product=ProductsCore.STREAM, local_changes=1) for group_id in ("first", "second", "third")
    ]
    harness = _Harness(*((ProductsCore.STREAM, group) for group in groups))
    harness.commit_response_deletions = {"first": 0, "second": 1, "third": 0}
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_all("test", message="Audit all line counts", product="stream")
    result = await vc.commit_and_deploy_all(
        "test",
        message="Audit all line counts",
        product="stream",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    assert harness.commit_order == ["first", "second", "third"]
    for commit_result in result["commit_results"]:
        assert commit_result["commit"]["line_changes"] == {
            "total": 3,
            "insertions": 2,
            "deletions": 1,
        }
        assert commit_result["commit"]["line_changes"]["deletions"] == commit_result["changes"]["deleted_lines"]


@pytest.mark.asyncio
async def test_commit_and_deploy_all_stops_before_deploy_after_commit_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default all-target failure handling should avoid starting a partial deployment phase."""
    first = _group_payload("a", product=ProductsCore.STREAM)
    second = _group_payload("b", product=ProductsCore.STREAM)
    harness = _Harness((ProductsCore.STREAM, first), (ProductsCore.STREAM, second))
    harness.commit_error_for = "b"
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_all("test", message="Stream rollout", product="stream")
    result = await vc.commit_and_deploy_all(
        "test",
        message="Stream rollout",
        product="stream",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    assert result["status"] == "partial_failure"
    assert result["errors"][0]["phase"] == "commit"
    assert harness.commit_order == ["a"]
    assert harness.deploy_order == []


@pytest.mark.asyncio
async def test_commit_and_deploy_all_skips_descendants_after_parent_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Continue-on-error mode must keep failed Edge parents ahead of, and block, descendants."""
    parent = _group_payload("parent", product=ProductsCore.EDGE)
    child = _group_payload("child", product=ProductsCore.EDGE, inherits="parent")
    sibling = _group_payload("sibling", product=ProductsCore.EDGE)
    harness = _Harness(
        (ProductsCore.EDGE, child),
        (ProductsCore.EDGE, sibling),
        (ProductsCore.EDGE, parent),
    )
    harness.commit_error_for = "parent"
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_all(
        "test",
        message="Continue independent fleets",
        product="edge",
        stop_on_error=False,
    )
    result = await vc.commit_and_deploy_all(
        "test",
        message="Continue independent fleets",
        product="edge",
        stop_on_error=False,
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    child_result = next(item for item in result["commit_results"] if item["target"]["id"] == "child")
    assert child_result["status"] == "skipped_dependency"
    assert child_result["blocked_by"] == "parent"
    assert harness.commit_order == ["sibling"]
    assert harness.deploy_order == ["sibling"]
    assert result["deploy_results"][0]["control_plane_version_confirmed"] is True


@pytest.mark.asyncio
async def test_commit_and_deploy_all_skips_descendant_deploy_after_parent_deploy_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An Edge parent deployment failure must block descendant deployments in continue mode."""
    parent = _group_payload("parent", product=ProductsCore.EDGE)
    child = _group_payload("child", product=ProductsCore.EDGE, inherits="parent")
    sibling = _group_payload("sibling", product=ProductsCore.EDGE)
    harness = _Harness(
        (ProductsCore.EDGE, child),
        (ProductsCore.EDGE, sibling),
        (ProductsCore.EDGE, parent),
    )
    harness.deploy_error_for = "parent"
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_all(
        "test",
        message="Continue independent fleet deploys",
        product="edge",
        stop_on_error=False,
    )
    result = await vc.commit_and_deploy_all(
        "test",
        message="Continue independent fleet deploys",
        product="edge",
        stop_on_error=False,
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )

    child_result = next(item for item in result["deploy_results"] if item["target"]["id"] == "child")
    assert child_result["status"] == "skipped_dependency"
    assert child_result["blocked_by"] == "parent"
    assert harness.deploy_order == ["sibling"]


@pytest.mark.asyncio
@pytest.mark.parametrize("messages", [["raw remote push output"], []])
async def test_push_accepts_real_sdk_string_response(httpx_mock: HTTPXMock, messages: list[str]) -> None:
    """The installed SDK must parse successful HTTP push responses without model-item serialization."""
    config = CriblConfig(url="https://cribl.example.test/api/v1", username="user", password="pass", timeout_ms=1000)
    security = Security(bearer_auth="test-token")
    httpx_mock.add_response(
        method="POST",
        url="https://cribl.example.test/api/v1/version/push",
        json={"count": len(messages), "items": messages},
    )
    async with create_control_plane(config, security=security) as client:
        resolved = ResolvedControlPlane(server_name="test", config=config, client=client, security=security)
        await vc._push(resolved)
    assert len(httpx_mock.get_requests()) == 1


async def _sdk_workflow_response(  # noqa: C901 - model each HTTP route in the SDK contract test
    request: httpx.Request, *, harness: _Harness, mutations: list[tuple[str, str, dict[str, Any]]]
) -> httpx.Response:
    """Serve stateful Cribl responses while recording real SDK mutation requests."""
    path = request.url.path.removeprefix("/api/v1")
    scoped_url = None
    if path.startswith("/m/linux/"):
        scoped_url = "https://cribl.example.test/api/v1/m/linux"
        path = path.removeprefix("/m/linux")
    body: dict[str, Any] = json.loads(request.content) if request.content else {}
    if request.method != "GET":
        mutations.append((request.method, request.url.path, body))
    if path == "/products/edge/groups":
        result = _Counted() if request.url.params.get("offset") else await harness._list_groups(product=ProductsCore.EDGE)
    elif path == "/products/edge/groups/linux":
        result = await harness._get_group(product=ProductsCore.EDGE, id="linux")
    elif path == "/products/edge/groups/linux/deploy":
        result = await harness._deploy(product=ProductsCore.EDGE, id="linux", version=body["version"])
    elif path == "/version/status":
        result = await harness._status(server_url=scoped_url)
    elif path == "/version/info":
        result = await harness._git_info()
    elif path == "/version/diff":
        result = await harness._diff(
            server_url=scoped_url, filename=request.url.params.get("filename"), commit=request.url.params.get("commit")
        )
    elif path == "/version/commit":
        result = await harness._commit(server_url=scoped_url, **body)
    elif path == "/version/push":
        return httpx.Response(200, json=(await harness._push()).model_dump())
    else:
        pytest.fail(f"Unexpected Cribl request: {request.method} {path}")
    return httpx.Response(200, json={"count": result.count, "items": [item.payload for item in result.items]})


@pytest.mark.parametrize("push", [False, True])
@pytest.mark.parametrize("all_targets", [False, True])
async def test_sdk_commit_deploy_keeps_remote_push_separate(
    httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch, *, push: bool, all_targets: bool
) -> None:
    """Inspect actual SDK HTTP requests through the complete reviewed workflow."""
    harness = _Harness((ProductsCore.EDGE, _group_payload("linux", product=ProductsCore.EDGE)))
    config = CriblConfig(url="https://cribl.example.test/api/v1", username="user", password="pass", timeout_ms=1000)
    security = Security(bearer_auth="test-token")
    mutations: list[tuple[str, str, dict[str, Any]]] = []

    async def _respond(request: httpx.Request) -> httpx.Response:
        return await _sdk_workflow_response(request, harness=harness, mutations=mutations)

    httpx_mock.add_callback(_respond, is_reusable=True)
    async with create_control_plane(config, security=security) as client:

        @asynccontextmanager
        async def _connect(_server: str | None) -> AsyncGenerator[ResolvedControlPlane]:
            yield ResolvedControlPlane("test", config, client, security)

        monkeypatch.setattr(vc, "connect_to_server", _connect)
        operation = vc.commit_and_deploy_all if all_targets else vc.commit_and_deploy_group
        kwargs: dict[str, Any] = {"product": "edge", "message": "Reviewed rollout", "push": push}
        if not all_targets:
            kwargs.update(product=ProductsCore.EDGE, group="linux")
        plan = await operation("test", **kwargs)
        assert mutations == []
        result = await operation("test", **kwargs, dry_run=False, expected_plan_sha256=plan["plan"]["plan_sha256"])
        assert result["push"]["requested"] is push
        assert result["push"]["status"] == ("pushed" if push else "not_requested")
        if push and all_targets:
            assert result["push"]["verification"] == "api_reports_synced"
        assert harness.commit_order == ["linux"]
        assert harness.deploy_order == ["linux"]
        assert harness.push_count == int(push)
        assert [path for _, path, _ in mutations] == [
            "/api/v1/m/linux/version/commit",
            "/api/v1/products/edge/groups/linux/deploy",
            "/api/v1/version/commit",
            *(["/api/v1/version/push"] if push else []),
        ]
        assert mutations[0][2] == {
            "message": "Reviewed rollout [edge:linux]" if all_targets else "Reviewed rollout",
            "effective": True,
        }
        assert mutations[2][2]["files"] == ["local/cribl/groups.yml"]
        if not push:
            assert harness.global_ahead > 0
            followup = await vc.push_config_git("test")
            assert followup["plan"]["action"] == "push"
            await vc.push_config_git("test", dry_run=False, expected_plan_sha256=followup["plan"]["plan_sha256"])
            assert mutations[-1][1] == "/api/v1/version/push"
            assert harness.push_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [401, 500])
async def test_push_preserves_real_sdk_errors(httpx_mock: HTTPXMock, status_code: int) -> None:
    """Rejected and failed pushes must still propagate the SDK error instead of reporting success."""
    config = CriblConfig(url="https://cribl.example.test/api/v1", username="user", password="pass", timeout_ms=1000)
    security = Security(bearer_auth="test-token")
    httpx_mock.add_response(
        method="POST",
        url="https://cribl.example.test/api/v1/version/push",
        status_code=status_code,
        json={"message": "remote rejected"},
    )
    async with create_control_plane(config, security=security) as client:
        resolved = ResolvedControlPlane(server_name="test", config=config, client=client, security=security)
        with pytest.raises(CriblControlPlaneError, match="remote rejected"):
            await vc._push(resolved)
    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.asyncio
async def test_commit_group_reports_string_push_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """A commit-only workflow must mark a successful CountedString push as completed."""
    harness = _Harness((ProductsCore.STREAM, _group_payload("default", product=ProductsCore.STREAM)))
    _install_harness(monkeypatch, harness)
    planned = await vc.commit_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Commit and push",
        push=True,
    )
    result = await vc.commit_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Commit and push",
        push=True,
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )
    assert result["status"] == "committed"
    assert result["push"] == {"requested": True, "status": "pushed"}
    assert result["completed_steps"] == ["group_commit", "push"]
    assert "raw remote push output" not in json.dumps(result)
    assert harness.push_count == 1
    assert harness.global_ahead == 0


@pytest.mark.asyncio
async def test_push_config_git_preflight_and_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remote push should be review-gated and block unsafe remote states."""
    harness = _Harness()
    harness.global_ahead = 2
    _install_harness(monkeypatch, harness)

    planned = await vc.push_config_git("test")
    assert planned["plan"]["git_integration"]["remote"] == "https://git.example.test/cribl/config.git"
    result = await vc.push_config_git(
        "test",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )
    assert result["status"] == "pushed"

    harness.remote = False
    harness.global_ahead = 1
    blocked = await vc.push_config_git("test")
    with pytest.raises(ValueError, match="No remote Git repository"):
        await vc.push_config_git(
            "test",
            dry_run=False,
            expected_plan_sha256=blocked["plan"]["plan_sha256"],
        )

    harness.remote = "https://git.example.test/cribl/config.git"
    harness.versioning = False
    versioning_blocked = await vc.push_config_git("test")
    with pytest.raises(ValueError, match="versioning is disabled"):
        await vc.push_config_git(
            "test",
            dry_run=False,
            expected_plan_sha256=versioning_blocked["plan"]["plan_sha256"],
        )


@pytest.mark.asyncio
async def test_noop_paths_and_plan_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clean and already deployed targets should return no-op results without mutations."""
    state = _group_payload(
        "default",
        product=ProductsCore.STREAM,
        committed="same",
        deployed="same",
        local_changes=0,
    )
    harness = _Harness((ProductsCore.STREAM, state))
    _install_harness(monkeypatch, harness)

    planned = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="No changes",
    )
    with pytest.raises(ValueError, match="required"):
        await vc.commit_and_deploy_group(
            "test",
            product=ProductsCore.STREAM,
            group="default",
            message="No changes",
            dry_run=False,
        )
    result = await vc.commit_and_deploy_group(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="No changes",
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )
    assert result["status"] == "noop"
    assert harness.commit_order == []
    assert harness.deploy_order == []

    state["configVersion"] = "older"
    harness.remote = False
    commit_only_plan = await vc.commit_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Do not deploy",
        push=True,
    )
    assert commit_only_plan["plan"]["action"] == "noop"
    assert commit_only_plan["plan"]["blocked_reasons"] == []
    assert commit_only_plan["plan"]["git_integration"] is None
    commit_only_result = await vc.commit_group_config(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        message="Do not deploy",
        push=True,
        dry_run=False,
        expected_plan_sha256=commit_only_plan["plan"]["plan_sha256"],
    )
    assert commit_only_result["status"] == "noop"

    push_plan = await vc.push_config_git("test")
    push_result = await vc.push_config_git(
        "test",
        dry_run=False,
        expected_plan_sha256=push_plan["plan"]["plan_sha256"],
    )
    assert push_result["status"] == "noop"


def _large_diff_file(path: str, *, lines: int, content: str = "+ example") -> dict[str, Any]:
    """Build realistic SDK hunks whose total payload can exceed a client cap."""
    return {
        **_Harness._diff_file("fixture"),
        "newName": path,
        "oldName": path,
        "addedLines": lines,
        "deletedLines": 0,
        "blocks": [
            {
                "header": "@@ -0,0 +1 @@",
                "oldStartLine": 0,
                "newStartLine": 1,
                "lines": [{"type": "insert", "newNumber": i + 1, "content": f"{content} {i}"} for i in range(lines)],
            }
        ],
    }


@pytest.mark.parametrize("scope", ["group", "leader"])
@pytest.mark.parametrize("limit", [10, 120, 0])
async def test_diff_limits_bound_sdk_payload_and_preserve_full_hash(
    monkeypatch: pytest.MonkeyPatch, scope: str, limit: int
) -> None:
    """Both public diff tools cap oversized SDK results and can continue past the first page."""
    harness = _Harness((ProductsCore.STREAM, _group_payload("default", product=ProductsCore.STREAM)))
    _install_harness(monkeypatch, harness)
    path = "local/cribl/groups.yml" if scope == "leader" else "local/cribl/inputs.yml"
    files = [_large_diff_file(path, lines=2000, content="+" + "x" * 1024)]
    response = CountedGitDiffResult.model_validate({"count": 1, "items": [{"diffJson": files}]})
    harness.client.versions.commits.diff_async = AsyncMock(return_value=response)

    async def _read(offset: int = 0) -> dict[str, Any]:
        if scope == "leader":
            return await vc.collect_leader_git_diff("test", diff_line_limit=limit, line_offset=offset)
        return await vc.collect_group_git_diff(
            "test",
            product=ProductsCore.STREAM,
            group="default",
            compare_to="head",
            diff_line_limit=limit,
            line_offset=offset,
        )

    result = await _read()
    assert len(json.dumps(result["diff"]).encode()) <= MAX_DIFF_BYTES
    assert len(json.dumps(result).encode()) < 1_000_000
    page = result["diff_page"]
    assert page["total_lines"] == 2000
    assert page["returned_lines"] == limit if limit else page["returned_lines"] > 0
    assert page["truncated"] is True
    following = await _read(page["next_line_offset"])
    first_line = following["diff"]["items"][0]["diffJson"][0]["blocks"][0]["lines"][0]
    assert first_line["newNumber"] == page["returned_lines"] + 1
    assert result["diff_sha256"] == following["diff_sha256"]
    assert result["summary"]["added_lines"] == 2000
    if scope == "group":
        assert result["pending_diff_sha256"] == following["pending_diff_sha256"]
    files[0]["blocks"][0]["lines"][-1]["content"] = "+ changed beyond page"
    harness.client.versions.commits.diff_async.return_value = CountedGitDiffResult.model_validate(
        {"count": 1, "items": [{"diffJson": files}]}
    )
    assert (await _read())["diff_sha256"] != result["diff_sha256"]


async def test_diff_long_unicode_lines_and_many_files_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Line and file metadata cannot defeat the byte cap; upstream truncation remains visible."""
    harness = _Harness((ProductsCore.STREAM, _group_payload("default", product=ProductsCore.STREAM)))
    _install_harness(monkeypatch, harness)
    files = [_large_diff_file(f"local/cribl/file-{i}.yml", lines=1, content="🔥" * 100_000) for i in range(3)]
    harness.client.versions.commits.diff_async.return_value = _Counted({"diffJson": files})
    harness.client.versions.commits.diff_async.side_effect = None
    result = await vc.collect_group_git_diff("test", product=ProductsCore.STREAM, group="default", diff_line_limit=10)
    assert result["diff_page"]["content_truncated"] is True
    assert len(json.dumps(result["diff"]).encode()) <= MAX_DIFF_BYTES
    files = [{**_Harness._diff_file(str(i)), "isTooBig": i == 101} for i in range(200)]
    harness.client.versions.commits.diff_async.return_value = _Counted({"diffJson": files})
    result = await vc.collect_group_git_diff("test", product=ProductsCore.STREAM, group="default", diff_line_limit=0)
    assert result["summary"]["file_count"] == 200
    assert result["diff_page"]["returned_files"] == 100
    assert result["diff_page"]["truncated"] is True
    assert result["diff_page"]["upstream_truncated"] is True


async def test_diff_line_budget_spans_files_without_mutating_raw_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """The limit applies across files and pages preserve the original hunk line numbers."""
    harness = _Harness((ProductsCore.STREAM, _group_payload("default", product=ProductsCore.STREAM)))
    _install_harness(monkeypatch, harness)
    files = [_large_diff_file(f"local/cribl/{i}.yml", lines=7) for i in range(2)]
    harness.client.versions.commits.diff_async = AsyncMock(return_value=_Counted({"diffJson": files}))
    first = await vc.collect_group_git_diff("test", product=ProductsCore.STREAM, group="default", diff_line_limit=10)
    assert first["diff_page"]["returned_lines"] == 10
    second = await vc.collect_group_git_diff(
        "test",
        product=ProductsCore.STREAM,
        group="default",
        diff_line_limit=10,
        line_offset=10,
    )
    assert second["diff_page"]["returned_lines"] == 4
    assert second["diff_page"]["next_line_offset"] is None
    assert second["diff"]["items"][0]["diffJson"][0]["newName"] == "local/cribl/1.yml"
    assert len(files[0]["blocks"][0]["lines"]) == 7
    with pytest.raises(ValueError, match="zero or greater"):
        await vc.collect_leader_git_diff("test", line_offset=-1)


@pytest.mark.parametrize("push_error", [False, True])
async def test_commit_leader_requires_review_and_limits_sdk_commit_to_selected_files(
    monkeypatch: pytest.MonkeyPatch, *, push_error: bool
) -> None:
    """The Leader tool clears selected pending metadata without committing/deploying any group."""
    harness = _Harness((ProductsCore.STREAM, _group_payload("default", product=ProductsCore.STREAM)))
    harness.global_dirty = True
    _install_harness(monkeypatch, harness)
    files = ["local/cribl/groups.yml"]
    planned = await vc.commit_leader_config("test", message="Review metadata", files=files, push=push_error)
    assert planned["plan"]["pending_files"] == files
    harness.client.versions.commits.create_async.assert_not_awaited()
    with pytest.raises(ValueError, match="required"):
        await vc.commit_leader_config("test", message="Review metadata", files=files, dry_run=False)
    with pytest.raises(ValueError, match="stale"):
        await vc.commit_leader_config(
            "test", message="Different message", files=files, dry_run=False, expected_plan_sha256=planned["plan"]["plan_sha256"]
        )
    harness.push_error = RuntimeError("remote rejected") if push_error else None
    result = await vc.commit_leader_config(
        "test",
        message="Review metadata",
        files=files,
        push=push_error,
        dry_run=False,
        expected_plan_sha256=planned["plan"]["plan_sha256"],
    )
    assert result["status"] == ("partial_failure" if push_error else "committed")
    assert result["commit"]["version"] == "leader-sync"
    assert result["commit"]["line_changes"]["deletions"] == 1
    assert result["completed_steps"] == ["leader_commit"]
    harness.client.versions.commits.create_async.assert_awaited_once_with(
        message="Review metadata",
        files=files,
        timeout_ms=1000,
    )
    assert harness.commit_order == harness.deploy_order == []
    assert harness.global_dirty is False
    assert "plan" not in result
    assert "files" not in result


@pytest.mark.parametrize(
    "files",
    [
        [],
        ["groups/a/local/cribl/inputs.yml"],
        ["local"],
        ["../local/cribl/groups.yml"],
        ["/local/cribl/groups.yml"],
        ["local/*"],
        [":(top)**"],
        [".git/config"],
    ],
)
async def test_leader_commit_rejects_broad_or_nonleader_selection(monkeypatch: pytest.MonkeyPatch, files: list[str]) -> None:
    """Never turn an empty list, directory or pathspec into a global commit."""
    harness = _Harness()
    harness.global_dirty = True
    _install_harness(monkeypatch, harness)
    with pytest.raises(ValueError, match=r"Leader|directory"):  # noqa: PT012 - invalid syntax fails during planning
        planned = await vc.commit_leader_config("test", message="Review", files=files)
        await vc.commit_leader_config(
            "test", message="Review", files=files, dry_run=False, expected_plan_sha256=planned["plan"]["plan_sha256"]
        )
    harness.client.versions.commits.create_async.assert_not_awaited()


@pytest.mark.parametrize("failure", ["conflict", "remote", "behind", "versioning"])
async def test_leader_commit_blocks_unsafe_git_state(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    """Leader commits retain conflict and optional push preflight safeguards."""
    harness = _Harness()
    harness.global_dirty = True
    harness.global_conflicts = ["local/cribl/groups.yml"] if failure == "conflict" else []
    harness.remote = False if failure == "remote" else harness.remote
    harness.global_behind = int(failure == "behind")
    harness.versioning = failure != "versioning"
    _install_harness(monkeypatch, harness)
    files = ["local/cribl/groups.yml"]
    plan = (await vc.commit_leader_config("test", message="Review", files=files, push=True))["plan"]
    assert plan["blocked_reasons"]
    with pytest.raises(ValueError, match="blocked"):
        await vc.commit_leader_config(
            "test", message="Review", files=files, push=True, dry_run=False, expected_plan_sha256=plan["plan_sha256"]
        )
    harness.client.versions.commits.create_async.assert_not_awaited()


async def test_leader_commit_hash_covers_unshown_content_and_supports_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Changing content without changing file paths invalidates review; clean selections are no-ops."""
    harness = _Harness()
    harness.global_dirty = True
    _install_harness(monkeypatch, harness)
    files = ["local/cribl/groups.yml"]
    payload = [_large_diff_file(files[0], lines=300)]
    harness.client.versions.commits.diff_async = AsyncMock(return_value=_Counted({"diffJson": payload}))
    plan = (await vc.commit_leader_config("test", message="Review", files=files))["plan"]
    payload[0]["blocks"][0]["lines"][-1]["content"] = "+ later drift"
    with pytest.raises(ValueError, match="stale"):
        await vc.commit_leader_config(
            "test", message="Review", files=files, dry_run=False, expected_plan_sha256=plan["plan_sha256"]
        )
    harness.global_dirty = False
    plan = (await vc.commit_leader_config("test", message="Review", files=files))["plan"]
    result = await vc.commit_leader_config(
        "test", message="Review", files=files, dry_run=False, expected_plan_sha256=plan["plan_sha256"]
    )
    assert result["status"] == "noop"
    harness.client.versions.commits.create_async.assert_not_awaited()


@pytest.mark.parametrize("kind", ["missing", "truncated", "rename"])
async def test_leader_commit_blocks_incomplete_or_out_of_scope_diff(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    """A pending file cannot be committed without complete, in-scope review data."""
    harness = _Harness()
    harness.global_dirty = True
    _install_harness(monkeypatch, harness)
    file = _large_diff_file("local/cribl/groups.yml", lines=1)
    file["isTooBig"] = kind == "truncated"
    if kind == "rename":
        file["oldName"] = "groups/default/local/cribl/groups.yml"
    harness.client.versions.commits.diff_async = AsyncMock(
        return_value=_Counted({"diffJson": [] if kind == "missing" else [file]})
    )
    plan = (await vc.commit_leader_config("test", message="Review", files=["local/cribl/groups.yml"]))["plan"]
    assert plan["blocked_reasons"]
    with pytest.raises(ValueError, match="blocked"):
        await vc.commit_leader_config(
            "test", message="Review", files=["local/cribl/groups.yml"], dry_run=False, expected_plan_sha256=plan["plan_sha256"]
        )
    harness.client.versions.commits.create_async.assert_not_awaited()


async def test_explicit_leader_file_read_and_commit_preserve_unselected_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inspect and commit a non-metadata Leader file, even beyond the capped status preview."""
    harness = _Harness()
    _install_harness(monkeypatch, harness)
    path = "local/cribl/zz-settings.yml"
    paths = [f"local/cribl/other-{i}.yml" for i in range(30)] + [path]
    raw_status = {"current": "main", "ahead": 0, "behind": 0, "conflicted": [], "modified": paths}
    harness.client.versions.statuses.get_async = AsyncMock(return_value=_Counted(raw_status))
    harness.client.versions.commits.diff_async = AsyncMock(
        return_value=_Counted({"diffJson": [_large_diff_file(path, lines=12)]})
    )
    diff = await vc.collect_leader_git_diff("test", filename=path, diff_line_limit=10)
    assert diff["filename"] == path
    assert diff["diff_page"]["returned_lines"] == 10
    assert diff["diff_page"]["next_line_offset"] == 10
    plan = (await vc.commit_leader_config("test", message="Settings", files=[path], push=True))["plan"]
    assert plan["pending_files"] == [path]
    assert plan["changes"]["added_lines"] == 12
    result = await vc.commit_leader_config(
        "test", message="Settings", files=[path], push=True, dry_run=False, expected_plan_sha256=plan["plan_sha256"]
    )
    assert result["status"] == "committed"
    assert result["push"]["status"] == "pushed"
    harness.client.versions.commits.create_async.assert_awaited_once_with(message="Settings", files=[path], timeout_ms=1000)
    assert harness.deploy_order == []


@pytest.mark.parametrize("readback", ["ahead", "unavailable", "diverged"])
async def test_push_success_is_separate_from_cached_or_failed_readback(monkeypatch: pytest.MonkeyPatch, readback: str) -> None:
    """A push acknowledged by Cribl must not fail or retry because its status read is stale."""
    harness = _Harness()
    harness.global_ahead = 3
    _install_harness(monkeypatch, harness)
    plan = await vc.push_config_git("test")

    async def _push(**_: object) -> CountedString:
        harness.push_count += 1
        if readback == "unavailable":
            harness.client.versions.statuses.get_async.side_effect = RuntimeError("status unavailable")
        elif readback == "diverged":
            harness.global_behind = 1
        return CountedString(count=1, items=["private push output"])

    harness.client.versions.commits.push_async.side_effect = _push
    result = await vc.push_config_git("test", dry_run=False, expected_plan_sha256=plan["plan"]["plan_sha256"])
    assert result["status"] == result["push"]["status"] == "pushed"
    assert (
        result["push"]["verification"]
        == {"ahead": "api_reports_ahead", "unavailable": "unavailable", "diverged": "api_reports_divergence"}[readback]
    )
    assert result["push"]["remote_sync_verified"] is False
    assert harness.push_count == 1
    assert "private push output" not in json.dumps(result)
