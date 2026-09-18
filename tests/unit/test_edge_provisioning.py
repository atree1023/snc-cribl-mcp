"""Regression tests for reviewed fleet creation and mapping replication."""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from fastmcp import Client
from pydantic import ValidationError
from pytest_httpx import HTTPXMock

from snc_cribl_mcp.client.cribl_client import ResolvedControlPlane, create_control_plane
from snc_cribl_mcp.config import CriblConfig
from snc_cribl_mcp.models import config_manifest as models
from snc_cribl_mcp.models.config_manifest import ConfigManifest, LoadedConfigManifest, ManifestContent, ManifestSource
from snc_cribl_mcp.models.edge_fleet import EdgeFleet, ordered_fleets
from snc_cribl_mcp.operations import config_manifest as manifests
from snc_cribl_mcp.operations import edge_provisioning as edge
from snc_cribl_mcp.operations import version_control as vc
from snc_cribl_mcp.operations.manifest_state import ManifestStateStore
from snc_cribl_mcp.operations.version_control_jobs import JobContext
from snc_cribl_mcp.server import app

from .test_config_manifest_operations import _JobContext
from .test_version_control import _Counted, _group_payload, _Harness, _Page


def _mapping(*fleets: str, active: bool = True) -> dict[str, Any]:
    return {
        "id": "rollout",
        "active": active,
        "conf": {
            "functions": [
                {
                    "id": "eval",
                    "filter": f"host == '{fleet}'",
                    "final": True,
                    "conf": {"add": [{"name": "groupId", "value": f"'{fleet}'"}]},
                }
                for fleet in fleets
            ]
        },
    }


class _EdgeHarness(_Harness):
    """Fake both SDK fleets and HTTP mappings, including Leader Git changes."""

    def __init__(self, *fleet_ids: str) -> None:
        super().__init__(
            *(
                (
                    ProductsCore.EDGE,
                    _group_payload(fleet_id, product=ProductsCore.EDGE, committed="base", deployed="base", local_changes=0),
                )
                for fleet_id in fleet_ids
            )
        )
        self.mappings: dict[str, dict[str, Any]] = {}
        self.destinations: dict[str, dict[str, Any]] = {}
        self.mapping_dirty = False
        self.events: list[str] = []
        self.client.groups.create_async = AsyncMock(side_effect=self._create)
        self.client.destinations.get_async = AsyncMock(side_effect=self._get_destination)
        self.client.destinations.create_async = AsyncMock(side_effect=self._create_destination)
        self.client.sdk_configuration.server_url = "https://cribl.test/api/v1"
        self.http = httpx.AsyncClient(transport=httpx.MockTransport(self._http))
        self.client.sdk_configuration.async_client = self.http

    async def _list_groups(self, *, product: ProductsCore, **kwargs: object) -> _Counted:
        """Match Cribl's opt-in Git metadata instead of always returning it."""
        result = await super()._list_groups(product=product, **kwargs)
        if kwargs.get("fields") is None:
            return _Counted(*({key: value for key, value in item.payload.items() if key != "git"} for item in result.items))
        return result

    async def _create(self, *, id: str, **kwargs: Any) -> _Counted:  # noqa: A002, ANN401
        assert kwargs["product"] == ProductsCore.EDGE
        assert kwargs["type_"] == "edge"
        self.events.append(f"fleet:{id}")
        item = _group_payload(id, product=ProductsCore.EDGE, inherits=kwargs.get("inherits"))
        item.update({key: value for key, value in kwargs.items() if key in {"name", "description"}})
        for key, alias in (("is_search", "isSearch"), ("streamtags", "streamtags")):
            if key in kwargs:
                item[alias] = kwargs[key]
        self.states[ProductsCore.EDGE, id] = item
        self.global_dirty = True
        return _Counted(item)

    async def _get_destination(self, *, id: str, server_url: str, **_: object) -> _Counted:  # noqa: A002
        key = f"{self._scope_group(server_url)}/{id}"
        if key not in self.destinations:
            response = httpx.Response(404, request=httpx.Request("GET", server_url))
            response.raise_for_status()
        return _Counted(self.destinations[key])

    async def _create_destination(self, *, request: dict[str, Any], server_url: str, **_: object) -> _Counted:
        group = self._scope_group(server_url)
        self.events.append(f"destination:{group}/{request['id']}")
        self.destinations[f"{group}/{request['id']}"] = request
        return _Counted(request)

    def _http(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path.startswith("/api/v1/fleet-mappings")
        ruleset_id = request.url.path.rsplit("/", maxsplit=1)[-1]
        if request.method in {"POST", "PATCH"}:
            if request.method == "POST":
                assert request.url.path == "/api/v1/fleet-mappings"
                ruleset_id = json.loads(request.content)["id"]
            self.events.append(f"mapping:{ruleset_id}")
            self.mappings[ruleset_id] = json.loads(request.content)
            self.mapping_dirty = True
        if ruleset_id not in self.mappings:
            return httpx.Response(404, json={"message": "missing"})
        return httpx.Response(200, json={"count": 1, "items": [self.mappings[ruleset_id]]})

    async def _status(self, *, server_url: str | None = None, **kwargs: object) -> _Counted:
        result = await super()._status(server_url=server_url, **kwargs)
        if server_url is None and self.mapping_dirty:
            payload = result.items[0].payload
            payload["modified"].append(edge.MAPPING_FILE)
            payload["files"].append({"path": edge.MAPPING_FILE, "index": "M", "working_dir": "M"})
        return result

    async def _diff(self, *, filename: str | None = None, server_url: str | None = None, **kwargs: Any) -> _Counted:  # noqa: ANN401
        if server_url is None and filename == edge.FLEET_FILE:
            groups = {
                fleet_id: {key: value for key, value in state.items() if key not in {"git", "workerCount"}}
                for (_, fleet_id), state in self.states.items()
            }
            return _Counted(
                {
                    "diffJson": [
                        {
                            **self._diff_file("groups"),
                            "blocks": [{"lines": [{"type": "insert", "content": json.dumps(groups)}]}],
                        }
                    ]
                    if self.global_dirty
                    else []
                }
            )
        if server_url is None and filename == edge.MAPPING_FILE:
            files = (
                [
                    {
                        **self._diff_file("fleet-mappings"),
                        "blocks": [{"lines": [{"type": "insert", "content": json.dumps(self.mappings)}]}],
                    }
                ]
                if self.mapping_dirty
                else []
            )
            return _Counted({"diffJson": files})
        return await super()._diff(filename=filename, server_url=server_url, **kwargs)

    async def _commit(
        self, *, message: str, server_url: str | None = None, files: list[str] | None = None, **kwargs: object
    ) -> _Counted:
        dirty = self.global_dirty
        if server_url is None:
            assert files
            self.events.append("leader:" + ",".join(files))
            if edge.MAPPING_FILE in files:
                self.mapping_dirty = False
        result = await super()._commit(message=message, server_url=server_url, files=files, **kwargs)
        if server_url is None and edge.FLEET_FILE not in (files or []):
            self.global_dirty = dirty
        return result


@pytest.fixture
async def leaders(monkeypatch: pytest.MonkeyPatch) -> AsyncGenerator[dict[str, _EdgeHarness]]:
    """Install isolated source/target Leaders across all operation modules."""
    harnesses = {"source": _EdgeHarness("parent", "child"), "target": _EdgeHarness()}
    harnesses["source"].states[ProductsCore.EDGE, "child"]["inherits"] = "parent"
    harnesses["source"].mappings["rollout"] = _mapping("child")
    harnesses["source"].destinations["child/out"] = {"id": "out", "type": "devnull"}

    @asynccontextmanager
    async def _connect(server: str | None) -> AsyncGenerator[ResolvedControlPlane]:
        name = server or "target"
        yield ResolvedControlPlane(
            name,
            CriblConfig(url="https://cribl.test/api/v1", username="user", password="pass"),
            harnesses[name].client,
            Security(bearer_auth="test"),
        )

    for module in (vc, edge, manifests):
        monkeypatch.setattr(module, "connect_to_server", _connect)
    yield harnesses
    for harness in harnesses.values():
        await harness.http.aclose()


@pytest.mark.parametrize(("is_search", "tags"), [(True, ["prod", "linux"]), (False, [])])
async def test_sdk_fleet_creation_contract(httpx_mock: HTTPXMock, *, is_search: bool, tags: list[str]) -> None:
    """The real installed SDK sends the Edge product, parent, and writable fields."""
    httpx_mock.add_response(
        method="POST",
        url="https://cribl.test/api/v1/products/edge/groups",
        json={"count": 1, "items": [{"id": "child", "type": "edge", "inherits": "parent"}]},
    )
    async with create_control_plane(
        CriblConfig(url="https://cribl.test/api/v1", username="user", password="pass"), security=Security(bearer_auth="test")
    ) as client:
        await edge.create_resource(
            client,
            "groups",
            item=EdgeFleet(id="child", inherits="parent", isSearch=is_search, streamtags=tags).payload(),
            product=ProductsCore.EDGE,
            timeout_ms=1000,
        )
    request = httpx_mock.get_request()
    assert request is not None
    assert json.loads(request.content) == {
        "id": "child",
        "inherits": "parent",
        "type": "edge",
        "isSearch": is_search,
        "streamtags": tags,
    }


async def test_sdk_fleet_inventory_requests_git_metadata(httpx_mock: HTTPXMock) -> None:
    """Verify the actual SDK query and wrapped response used by the parent guard."""
    parent = _group_payload("linux", product=ProductsCore.EDGE, committed="2120a01", deployed="2120a01", local_changes=0)
    httpx_mock.add_response(
        method="GET",
        url="https://cribl.test/api/v1/products/edge/groups?fields=git.commit%2Cgit.localChanges",
        json={"count": 1, "items": [parent]},
    )
    httpx_mock.add_response(
        method="GET",
        url="https://cribl.test/api/v1/products/edge/groups?fields=git.commit%2Cgit.localChanges&offset=1",
        json={"count": 1, "items": []},
    )
    config = CriblConfig(url="https://cribl.test/api/v1", username="user", password="pass")
    security = Security(bearer_auth="test")
    async with create_control_plane(config, security=security) as client:
        inventory = await edge.fleet_inventory(ResolvedControlPlane("test", config, client, security))
    assert inventory[0]["git"]["commit"] == "2120a01"
    assert inventory[0]["configVersion"] == "2120a01"


async def test_fleet_inventory_exhausts_pages(leaders: dict[str, _EdgeHarness]) -> None:
    """Projected inventory still includes ancestors on later SDK pages."""
    target = leaders["target"]
    target.client.groups.list_async.return_value = _Page({"id": "first"}, next_page=_Page({"id": "last"}))
    target.client.groups.list_async.side_effect = None
    async with edge.connect_to_server("target") as resolved:
        inventory = await edge.fleet_inventory(resolved)
    assert [item["id"] for item in inventory] == ["first", "last"]


async def test_create_fleet_plan_drift_noop_and_parent_checks(leaders: dict[str, _EdgeHarness]) -> None:
    """Creation is review-gated, create-only, and checks exact parent readiness."""
    target = leaders["target"]
    fleet = EdgeFleet(id="parent")
    plan = await edge.create_edge_fleet("target", fleet=fleet)
    assert not target.events
    with pytest.raises(ValueError, match="expected_plan_sha256"):
        await edge.create_edge_fleet("target", fleet=fleet, dry_run=False)
    with pytest.raises(ValueError, match="stale"):
        await edge.create_edge_fleet(
            "target", fleet=EdgeFleet(id="different"), dry_run=False, expected_plan_sha256=plan["plan"]["plan_sha256"]
        )
    result = await edge.create_edge_fleet(
        "target", fleet=fleet, dry_run=False, expected_plan_sha256=plan["plan"]["plan_sha256"]
    )
    assert result["status"] == "created"
    assert (await edge.create_edge_fleet("target", fleet=fleet))["plan"]["action"] == "noop"
    conflict = await edge.create_edge_fleet("target", fleet=EdgeFleet(id="parent", name="new name"))
    assert conflict["plan"]["blocked_reasons"]
    child = await edge.create_edge_fleet("target", fleet=EdgeFleet(id="child", inherits="parent"))
    assert any("Parent fleet" in reason for reason in child["plan"]["blocked_reasons"])
    with pytest.raises(ValueError, match="unknown fleet"):
        await edge.create_edge_fleet("target", fleet=EdgeFleet(id="orphan", inherits="absent"))


@pytest.mark.parametrize("ahead", [0, 5])
async def test_parent_preflight_uses_projected_target_commit(leaders: dict[str, _EdgeHarness], ahead: int) -> None:
    """A full history hash must not make the same deployed short hash look pending."""
    target = leaders["target"]
    target.states[ProductsCore.EDGE, "linux"] = _group_payload(
        "linux", product=ProductsCore.EDGE, committed="2120a01", deployed="2120a01", local_changes=0
    )
    target.global_ahead = ahead
    target.client.versions.commits.list_async.return_value = _Counted({"hash": "2120a01" + "a" * 33})
    target.client.versions.commits.list_async.side_effect = None

    result = await edge.create_edge_fleet("target", fleet=EdgeFleet(id="child", inherits="linux"))

    assert result["plan"]["blocked_reasons"] == []
    target.client.versions.commits.list_async.assert_not_awaited()
    guard = result["plan"]["guard"]
    assert guard["existing_fleet_count"] == 1
    assert guard["planned_create_count"] == 1
    assert guard["fleet_count"] == 2
    assert guard["parents"][0]["committed_version"] == "2120a01"
    assert guard["parents"][0]["deployment_pending"] is False
    assert guard["leader_git"]["ahead"] == ahead
    assert not target.events


@pytest.mark.parametrize("signal", ["local_changes", "deployment_pending", "behind", "conflict_count"])
async def test_parent_block_names_signal_and_values(leaders: dict[str, _EdgeHarness], signal: str) -> None:
    """Dry-runs explain the exact target-local signal without follow-up reads."""
    target = leaders["target"]
    parent = _group_payload("linux", product=ProductsCore.EDGE, committed="2120a01", deployed="2120a01", local_changes=0)
    target.states[ProductsCore.EDGE, "linux"] = parent
    if signal == "local_changes":
        parent["git"]["localChanges"] = 1
    elif signal == "deployment_pending":
        parent["git"]["commit"] = "61f03ed"
    else:

        async def _status(**kwargs: Any) -> _Counted:  # noqa: ANN401
            result = await target._status(**kwargs)
            if kwargs.get("server_url"):
                result.items[0].payload.update({"behind": 2} if signal == "behind" else {"conflicted": ["conflict.yml"]})
            return result

        target.client.versions.statuses.get_async.side_effect = _status

    result = await edge.create_edge_fleet("target", fleet=EdgeFleet(id="child", inherits="linux"))
    reasons = " ".join(result["plan"]["blocked_reasons"])
    assert "Parent fleet 'linux'" in reasons
    assert signal in reasons
    guard = result["plan"]["guard"]
    assert guard["parents"][0][signal]
    if signal == "deployment_pending":
        assert "61f03ed" in reasons
        assert "2120a01" in reasons
    with pytest.raises(ValueError, match="blocked"):
        await edge.create_edge_fleet(
            "target",
            fleet=EdgeFleet(id="child", inherits="linux"),
            dry_run=False,
            expected_plan_sha256=result["plan"]["plan_sha256"],
        )
    assert not target.events


async def test_preflight_follows_new_parent_to_existing_ancestor(leaders: dict[str, _EdgeHarness]) -> None:
    """Declaring intermediate fleets must not hide a dirty existing ancestor."""
    target = leaders["target"]
    target.states[ProductsCore.EDGE, "linux"] = _group_payload("linux", product=ProductsCore.EDGE)
    async with edge.connect_to_server("target") as resolved:
        _, blocked, guard = await edge.provision_preflight(
            resolved,
            fleets=[EdgeFleet(id="child", inherits="new-parent"), EdgeFleet(id="new-parent", inherits="linux")],
            mappings=[],
        )
    assert any("linux" in reason and "local_changes" in reason for reason in blocked)
    assert guard["parent_count"] == 1


async def test_parent_without_git_projection_blocks_without_history_guess(leaders: dict[str, _EdgeHarness]) -> None:
    """Missing requested metadata is unknown readiness, not a clean parent."""
    target = leaders["target"]
    target.client.groups.list_async.return_value = _Counted({"id": "linux", "configVersion": "2120a01"})
    target.client.groups.list_async.side_effect = None
    result = await edge.create_edge_fleet("target", fleet=EdgeFleet(id="child", inherits="linux"))
    assert "committed_version unavailable" in result["plan"]["blocked_reasons"][0]
    assert result["plan"]["guard"]["parents"][0]["status"] == "unavailable"
    target.client.versions.commits.list_async.assert_not_awaited()


async def test_parent_guard_bounds_preview_but_hashes_all_parents(leaders: dict[str, _EdgeHarness]) -> None:
    """Parents outside the bounded preview must still invalidate reviewed plans."""
    target = leaders["target"]
    fleets: list[EdgeFleet] = []
    for index in range(30):
        parent_id = f"parent-{index:02d}"
        target.states[ProductsCore.EDGE, parent_id] = _group_payload(
            parent_id, product=ProductsCore.EDGE, committed="base", deployed="base", local_changes=0
        )
        fleets.append(EdgeFleet(id=f"child-{index:02d}", inherits=parent_id))
    async with edge.connect_to_server("target") as resolved:
        _, blocked, guard = await edge.provision_preflight(resolved, fleets=fleets, mappings=[])
        target.states[ProductsCore.EDGE, "parent-29"]["git"]["localChanges"] = 1
        _, changed_blocked, changed_guard = await edge.provision_preflight(resolved, fleets=fleets, mappings=[])
    assert blocked == []
    assert guard["parent_count"] == 30
    assert len(guard["parents"]) == 25
    assert guard["parents_truncated"] is True
    assert guard["parents"] == changed_guard["parents"]
    assert guard["parents_sha256"] != changed_guard["parents_sha256"]
    assert "parent-29" in changed_blocked[0]


async def test_mapping_replication_preserves_order_activation_and_guards(leaders: dict[str, _EdgeHarness]) -> None:
    """Both rule order and target destination changes are functional drift."""
    source, target = leaders["source"], leaders["target"]
    target.states = deepcopy(source.states)
    source.mappings["rollout"] = _mapping("parent", "child")
    plan = await edge.replicate_fleet_mapping_ruleset("target", source_server="source", ruleset_id="rollout")
    result = await edge.replicate_fleet_mapping_ruleset(
        "target", source_server="source", ruleset_id="rollout", dry_run=False, expected_plan_sha256=plan["plan"]["plan_sha256"]
    )
    assert result["status"] == "created"
    assert target.mappings["rollout"]["active"] is False
    assert target.mappings["rollout"]["conf"] == source.mappings["rollout"]["conf"]
    target.mappings["rollout"]["active"] = True
    target.mappings["rollout"]["conf"]["functions"].reverse()
    plan = await edge.replicate_fleet_mapping_ruleset("target", source_server="source", ruleset_id="rollout")
    assert plan["plan"]["action"] == "update"
    target.mappings["rollout"]["conf"]["functions"][0]["groupId"] = "parent"
    with pytest.raises(ValueError, match="stale"):
        await edge.replicate_fleet_mapping_ruleset(
            "target",
            source_server="source",
            ruleset_id="rollout",
            dry_run=False,
            expected_plan_sha256=plan["plan"]["plan_sha256"],
        )
    plan = await edge.replicate_fleet_mapping_ruleset("target", source_server="source", ruleset_id="rollout")
    await edge.replicate_fleet_mapping_ruleset(
        "target", source_server="source", ruleset_id="rollout", dry_run=False, expected_plan_sha256=plan["plan"]["plan_sha256"]
    )
    assert target.mappings["rollout"]["active"] is True
    source.mappings["rollout"] = _mapping("missing")
    plan = await edge.replicate_fleet_mapping_ruleset("target", source_server="source", ruleset_id="rollout")
    assert "missing fleets" in plan["plan"]["blocked_reasons"][0]
    with pytest.raises(ValueError, match="does not exist"):
        await edge.replicate_fleet_mapping_ruleset("target", source_server="source", ruleset_id="missing")


def _loaded(*, mappings_only: bool = False) -> LoadedConfigManifest:
    manifest = ConfigManifest.model_construct(
        schema_=1,
        wave="rollout",
        source=ManifestSource(server="source", product="edge"),
        targets=["target"],
        fleets=[] if mappings_only else [EdgeFleet(id="child", inherits="parent"), EdgeFleet(id="parent")],
        fleet_mappings=["rollout"],
        content=[] if mappings_only else [ManifestContent(group="child", kind="destinations", items=["out"])],
    )
    return LoadedConfigManifest.model_construct(
        manifest=manifest,
        path=Path("/safe/edge.yaml"),
        relative_path="edge.yaml",
        file_sha256="file",
        manifest_sha256=models._canonical_digest(manifest.canonical_payload()),
    )


@pytest.mark.parametrize("dirty", [False, True])
async def test_manifest_parent_guard_is_target_local_and_visible(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch, *, dirty: bool
) -> None:
    """Different source/target versions are normal; target blockers remain visible."""
    loaded = _loaded()
    target = leaders["target"]
    parent = _group_payload(
        "parent", product=ProductsCore.EDGE, committed="2120a01", deployed="2120a01", local_changes=int(dirty)
    )
    target.states[ProductsCore.EDGE, "parent"] = parent
    target.global_ahead = 5
    target.client.versions.commits.list_async.return_value = _Counted({"hash": "2120a01" + "a" * 33})
    target.client.versions.commits.list_async.side_effect = None

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(manifests, "load_config_manifest", _load)
    result = await manifests.plan_config_manifest_replication("edge.yaml", state_store=ManifestStateStore())
    assert result["blocked_target_count"] == int(dirty)
    plan = result["targets"][0]
    assert plan["provisioning_guard"]["parents"][0]["committed_version"] == "2120a01"
    assert plan["provisioning_guard"]["parents"][0]["deployment_pending"] is False
    assert plan["provisioning_guard"]["leader_git"]["ahead"] == 5
    if dirty:
        assert any("local_changes=1" in reason for reason in plan["blocked_reasons"])
    target.client.versions.commits.list_async.assert_not_awaited()
    assert not target.events


@pytest.mark.parametrize("mappings_only", [False, True])
async def test_manifest_provisions_then_commits_exact_leader_files(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch, *, mappings_only: bool
) -> None:
    """A reviewed manifest applies dependencies and carries Leader receipts through commit/deploy."""
    loaded = _loaded(mappings_only=mappings_only)
    if mappings_only:
        leaders["target"].states = deepcopy(leaders["source"].states)

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(manifests, "load_config_manifest", _load)
    state = ManifestStateStore()
    plan = await manifests.plan_config_manifest_replication("edge.yaml", state_store=state)
    assert plan["targets"][0]["blocked_reasons"] == []
    context = _JobContext()
    result = await manifests.execute_config_manifest_replication(
        "edge.yaml", expected_plan_sha256=plan["plan_sha256"], state_store=state, job_context=cast("JobContext", context)
    )
    assert result["status"] == "completed", context.details
    assert context.progress[-1]["completed"] == loaded.manifest.item_count
    target = leaders["target"]
    assert target.events == (
        ["mapping:rollout"] if mappings_only else ["fleet:parent", "fleet:child", "destination:child/out", "mapping:rollout"]
    )
    assert (await manifests.validate_config_manifest("edge.yaml"))["status"] == "in_sync"
    receipt = state.get_receipt(receipt_sha256=result["apply_receipt_sha256"])
    files = [edge.MAPPING_FILE] if mappings_only else [edge.FLEET_FILE, edge.MAPPING_FILE]
    assert set(receipt["targets"]["target"]["leader"]) == set(files)
    assert (
        await manifests.check_manifest_receipt_validity(
            "edge.yaml", apply_job_id=None, apply_receipt_sha256=result["apply_receipt_sha256"], state_store=state
        )
    )["status"] == "valid"
    deploy_plan = await manifests.plan_manifest_commit_deploy(
        "edge.yaml",
        apply_job_id=None,
        apply_receipt_sha256=result["apply_receipt_sha256"],
        message="rollout",
        push=False,
        state_store=state,
    )
    assert deploy_plan["targets"][0]["blocked_reasons"] == []
    deployed = await manifests.execute_manifest_commit_deploy(
        "edge.yaml",
        expected_plan_sha256=deploy_plan["plan_sha256"],
        message="rollout",
        push=False,
        state_store=state,
        job_context=cast("JobContext", context),
    )
    assert deployed["status"] == "completed", context.details
    assert target.events[loaded.manifest.item_count] == "leader:" + ",".join(sorted(files))
    assert target.deploy_order == ([] if mappings_only else ["parent", "child"])
    assert target.push_count == 0


async def test_manifest_blocks_unowned_and_changed_leader_files(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An apply receipt never authorizes unrelated or subsequently changed Leader files."""
    loaded = _loaded()

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(manifests, "load_config_manifest", _load)
    target = leaders["target"]
    target.mapping_dirty = True
    state = ManifestStateStore()
    blocked = await manifests.plan_config_manifest_replication("edge.yaml", state_store=state)
    assert any("already has pending" in reason for reason in blocked["targets"][0]["blocked_reasons"]), blocked
    target.mapping_dirty = False
    plan = await manifests.plan_config_manifest_replication("edge.yaml", state_store=state)
    result = await manifests.execute_config_manifest_replication(
        "edge.yaml", expected_plan_sha256=plan["plan_sha256"], state_store=state, job_context=cast("JobContext", _JobContext())
    )
    target.mappings["rollout"]["conf"]["functions"].reverse()
    target.mappings["rollout"]["conf"]["functions"][0]["filter"] = "false"
    validity = await manifests.check_manifest_receipt_validity(
        "edge.yaml", apply_job_id=None, apply_receipt_sha256=result["apply_receipt_sha256"], state_store=state
    )
    assert validity["status"] == "stale"


@pytest.mark.parametrize("payload", [{}, {"items": "wrong"}, {"items": ["wrong"]}, {"items": [{"id": "other"}]}])
async def test_mapping_rejects_unknown_responses(payload: dict[str, Any]) -> None:
    """Malformed responses must not be interpreted as missing and overwritten."""
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload))) as http:
        from cribl_control_plane import CriblControlPlane  # noqa: PLC0415

        client = CriblControlPlane(server_url="https://cribl.test/api/v1", async_client=http)
        resolved = ResolvedControlPlane(
            "target",
            CriblConfig(url="https://cribl.test/api/v1", username="user", password="pass"),
            client,
            Security(bearer_auth="test"),
        )
        with pytest.raises(ValueError, match="Mapping API"):
            await edge.read_mapping(resolved, "rollout")


def test_manifest_edge_schema_and_existing_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    """Edge extensions reject cycles/duplicates and leave legacy intent payloads unchanged."""
    monkeypatch.setattr(models, "configured_server_names", lambda: ["source", "target"])
    base: dict[str, Any] = {
        "schema": 1,
        "wave": "test",
        "source": {"server": "source", "product": "edge"},
        "targets": ["target"],
    }
    for additions in (
        {},
        {"fleets": [{"id": "x", "inherits": "x"}]},
        {"fleets": [{"id": "x"}, {"id": "x"}]},
        {"fleet_mappings": ["x", "x"]},
        {"fleets": [{"id": "x", "configVersion": "secret"}]},
        {"fleets": [{"id": "x", "lookupDeployments": [{"deployedVersion": "foreign"}]}]},
        {"fleets": [{"id": "x", "streamtags": "not-a-list"}]},
    ):
        with pytest.raises(ValidationError):
            ConfigManifest.model_validate({**base, **additions})
    with pytest.raises(ValidationError, match="product=edge"):
        ConfigManifest.model_validate({**base, "source": {"server": "source", "product": "stream"}, "fleet_mappings": ["x"]})
    manifest = ConfigManifest.model_validate({**base, "fleet_mappings": [" rollout "]})
    assert manifest.fleet_mappings == ["rollout"]
    fleet_manifest = ConfigManifest.model_validate({**base, "fleets": [{"id": "x", "isSearch": False, "streamtags": []}]})
    assert fleet_manifest.fleets[0].payload() == {"id": "x", "type": "edge", "isSearch": False, "streamtags": []}
    legacy = ConfigManifest.model_validate({**base, "content": [{"group": "x", "kind": "routes", "items": ["default"]}]})
    assert "fleets" not in legacy.canonical_payload()
    assert "fleet_mappings" not in legacy.canonical_payload()
    assert [fleet.id for fleet in ordered_fleets([EdgeFleet(id="child", inherits="parent"), EdgeFleet(id="parent")])] == [
        "parent",
        "child",
    ]


async def test_public_tools_registered_and_guarded() -> None:
    """FastMCP advertises actual creation arguments and mutation annotations."""
    async with Client(app) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    assert tools["create_edge_fleet"].input_schema["properties"]["dry_run"]["default"] is True
    assert tools["replicate_fleet_mapping_ruleset"].input_schema["properties"]["overwrite"]["default"] is True
    assert tools["create_edge_fleet"].annotations is not None
    assert tools["create_edge_fleet"].annotations.read_only_hint is False


@pytest.mark.parametrize("failure", ["parent_create", "mapping_write", "receipt_read"])
async def test_manifest_provisioning_failure_stops_dependencies(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """Failed dependencies stop later writes and never yield a usable deployment receipt."""
    loaded = _loaded()

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(manifests, "load_config_manifest", _load)
    state = ManifestStateStore()
    plan = await manifests.plan_config_manifest_replication("edge.yaml", state_store=state)
    target = leaders["target"]
    if failure == "parent_create":
        target.client.groups.create_async.side_effect = RuntimeError("create failed")
    elif failure == "mapping_write":
        original_write = edge.write_leader_item

        async def _write(resolved: ResolvedControlPlane, kind: str, item: dict[str, Any], *, overwrite: bool = True) -> str:
            if kind == "fleet_mappings":
                msg = "mapping failed"
                raise RuntimeError(msg)
            return await original_write(resolved, kind, item, overwrite=overwrite)

        monkeypatch.setattr(edge, "write_leader_item", _write)
    else:
        original_snapshot = edge.leader_file_snapshot

        async def _snapshot(server: str | None, files: list[str]) -> dict[str, Any]:
            if target.mapping_dirty:
                msg = "receipt unavailable"
                raise RuntimeError(msg)
            return await original_snapshot(server, files)

        monkeypatch.setattr(edge, "leader_file_snapshot", _snapshot)
    context = _JobContext()
    result = await manifests.execute_config_manifest_replication(
        "edge.yaml", expected_plan_sha256=plan["plan_sha256"], state_store=state, job_context=cast("JobContext", context)
    )
    assert result["status"] == "partial_failure"
    assert context.details["target"]["status"] == "partial_failure"
    if failure == "parent_create":
        assert target.events == []
        assert context.progress[-1]["skipped"] == 3
    assert not target.commit_order
    assert not target.deploy_order


async def test_mapping_noop_skip_and_source_drift(leaders: dict[str, _EdgeHarness]) -> None:
    """Noop/skipped writes are absent; source changes invalidate prior review."""
    source, target = leaders["source"], leaders["target"]
    target.states = deepcopy(source.states)
    target.mappings = deepcopy(source.mappings)
    plan = await edge.replicate_fleet_mapping_ruleset("target", source_server="source", ruleset_id="rollout")
    result = await edge.replicate_fleet_mapping_ruleset(
        "target", source_server="source", ruleset_id="rollout", dry_run=False, expected_plan_sha256=plan["plan"]["plan_sha256"]
    )
    assert result["status"] == "noop"
    source.mappings["rollout"]["conf"]["functions"][0]["filter"] = "true"
    with pytest.raises(ValueError, match="stale"):
        await edge.replicate_fleet_mapping_ruleset(
            "target",
            source_server="source",
            ruleset_id="rollout",
            dry_run=False,
            expected_plan_sha256=plan["plan"]["plan_sha256"],
        )
    plan = await edge.replicate_fleet_mapping_ruleset("target", source_server="source", ruleset_id="rollout", overwrite=False)
    result = await edge.replicate_fleet_mapping_ruleset(
        "target",
        source_server="source",
        ruleset_id="rollout",
        overwrite=False,
        dry_run=False,
        expected_plan_sha256=plan["plan"]["plan_sha256"],
    )
    assert result["status"] == "skipped_existing"
    assert target.events == []


@pytest.mark.parametrize("response_status", [200, 403, 500])
async def test_mapping_absence_and_http_errors(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch, response_status: int
) -> None:
    """Only an empty counted response or a 404 denotes absence; authorization failures propagate."""

    async def _request(*_args: Any, **_kwargs: Any) -> dict[str, Any]:  # noqa: ANN401
        response = httpx.Response(
            response_status, json={"count": 0, "items": []}, request=httpx.Request("GET", "https://cribl.test")
        )
        response.raise_for_status()
        return response.json()

    monkeypatch.setattr(edge, "_direct_request_json", _request)
    async with edge.connect_to_server("source") as resolved:
        if response_status == 200:
            assert await edge.read_mapping(resolved, "absent") is None
        else:
            with pytest.raises(httpx.HTTPStatusError):
                await edge.read_mapping(resolved, "rollout")


def test_mapping_literals_and_dynamic_expressions() -> None:
    """Dependency checks retain group IDs and report expressions without evaluating them."""
    mapping = _mapping("child")
    mapping["conf"]["functions"].extend(
        [
            {"disabled": True, "groupId": "disabled"},
            {"groupId": "parent", "conf": {"add": [{"name": "groupId", "value": "cribl.group"}]}},
            {"conf": {"add": [{"name": "unrelated", "value": "ignored"}]}},
        ]
    )
    assert edge.mapping_dependencies(mapping) == ({"child", "parent"}, 1)
    with pytest.raises(TypeError):
        edge.mapping_payload({"id": "rollout", "conf": {"functions": "bad"}})


async def test_leader_commit_failure_prevents_fleet_deployment(leaders: dict[str, _EdgeHarness]) -> None:
    """Receipt-selected Leader files must be committed before any group mutation begins."""
    target = leaders["target"]
    target.states = deepcopy(leaders["source"].states)
    target.global_dirty = True
    plan = await vc.commit_and_deploy_all(
        "target", message="rollout", product="edge", groups=["parent"], _leader_files=[edge.FLEET_FILE]
    )
    target.client.versions.commits.create_async.side_effect = RuntimeError("Leader commit failed")
    with pytest.raises(RuntimeError, match="Leader commit failed"):
        await vc.commit_and_deploy_all(
            "target",
            message="rollout",
            product="edge",
            groups=["parent"],
            _leader_files=[edge.FLEET_FILE],
            dry_run=False,
            expected_plan_sha256=plan["plan"]["plan_sha256"],
        )
    assert not target.commit_order
    assert not target.deploy_order
    with pytest.raises(ValueError, match=r"only groups\.yml"):
        await vc.commit_and_deploy_all("target", message="rollout", _leader_files=["local/cribl/unrelated.yml"])


@pytest.mark.parametrize("operation", ["create_edge_fleet", "replicate_fleet_mapping_ruleset"])
async def test_provisioning_tools_submit_reviewed_background_jobs(monkeypatch: pytest.MonkeyPatch, operation: str) -> None:
    """The exposed tools pass identical reviewed intent into the durable job runner."""
    from unittest.mock import MagicMock  # noqa: PLC0415

    from fastmcp import Context, FastMCP  # noqa: PLC0415

    from snc_cribl_mcp.operations.version_control_jobs import VersionControlJobManager  # noqa: PLC0415
    from snc_cribl_mcp.tools import edge_provisioning as tool_module  # noqa: PLC0415

    from .test_config_manifest_tools import _FakeApp  # noqa: PLC0415

    fake_app = _FakeApp()
    manager = MagicMock(spec=VersionControlJobManager)
    manager.submit = AsyncMock(return_value={"job_id": "queued"})
    implementation = AsyncMock(return_value={"status": "planned", "plan": {"plan_sha256": "reviewed"}})
    monkeypatch.setattr(tool_module, operation, implementation)
    tool_module.register(cast("FastMCP", fake_app), job_manager=manager)
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    kwargs: dict[str, Any] = (
        {"fleet": EdgeFleet(id="fleet")}
        if operation == "create_edge_fleet"
        else {"source_server": "source", "ruleset_id": "rollout", "overwrite": False}
    )
    await fake_app.tools[operation](ctx, server="target", **kwargs)
    manager.submit.assert_not_awaited()
    result = await fake_app.tools[operation](ctx, server="target", **kwargs, dry_run=False, expected_plan_sha256="reviewed")
    assert result == {"job_id": "queued"}
    assert manager.submit.await_args is not None
    call = manager.submit.await_args.kwargs
    assert call["operation"] == operation
    assert call["server"] == "target"
    assert call["expected_plan_sha256"] == "reviewed"
    implementation.reset_mock()
    await call["runner"]()
    implementation.assert_awaited_once_with("target", **kwargs, dry_run=False, expected_plan_sha256="reviewed")


async def test_fleet_review_ignores_runtime_node_counts(leaders: dict[str, _EdgeHarness]) -> None:
    """Ordinary node-count changes cannot invalidate a no-op fleet creation review."""
    target = leaders["target"]
    target.states = deepcopy(leaders["source"].states)
    fleet = EdgeFleet(id="child", inherits="parent")
    before = await edge.create_edge_fleet("target", fleet=fleet)
    target.states[ProductsCore.EDGE, "parent"]["workerCount"] = 100
    target.states[ProductsCore.EDGE, "child"]["workerCount"] = 100
    after = await edge.create_edge_fleet("target", fleet=fleet)
    assert before["plan"]["plan_sha256"] == after["plan"]["plan_sha256"]


async def test_fleet_only_manifest_does_not_require_source_fleets(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fleet declarations can provision an empty target independently of source config objects."""
    loaded = _loaded()
    loaded = loaded.model_copy(update={"manifest": loaded.manifest.model_copy(update={"content": [], "fleet_mappings": []})})

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(manifests, "load_config_manifest", _load)
    leaders["source"].client.groups.list_async.side_effect = AssertionError("source fleet inventory must not be read")
    state = ManifestStateStore()
    plan = await manifests.plan_config_manifest_replication("edge.yaml", state_store=state)
    result = await manifests.execute_config_manifest_replication(
        "edge.yaml", expected_plan_sha256=plan["plan_sha256"], state_store=state, job_context=cast("JobContext", _JobContext())
    )
    assert result["status"] == "completed"
    receipt = state.get_receipt(receipt_sha256=result["apply_receipt_sha256"])
    assert set(receipt["targets"]["target"]["leader"]) == {edge.FLEET_FILE}
    assert leaders["target"].events == ["fleet:parent", "fleet:child"]


async def _partial_manifest_apply(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch, state: ManifestStateStore
) -> tuple[LoadedConfigManifest, dict[str, Any], _JobContext]:
    """Create a parent then fail before its child on one of two Leaders."""
    loaded = _loaded()
    loaded.manifest.targets.append("peer")
    leaders["peer"] = _EdgeHarness()

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(manifests, "load_config_manifest", _load)
    plan = await manifests.plan_config_manifest_replication("edge.yaml", state_store=state)
    target = leaders["target"]

    async def _fail_child(*, id: str, **kwargs: Any) -> _Counted:  # noqa: A002, ANN401
        if id == "child":
            message = "temporary create failure"
            raise RuntimeError(message)
        return await target._create(id=id, **kwargs)

    target.client.groups.create_async.side_effect = _fail_child
    context = _JobContext("partial-apply")
    result = await manifests.execute_config_manifest_replication(
        "edge.yaml", expected_plan_sha256=plan["plan_sha256"], state_store=state, job_context=cast("JobContext", context)
    )
    assert result["status"] == "partial_failure", context.details
    assert context.details["target"]["receipt_groups"]["child"] == {"missing": True}
    assert context.details["target"]["created_fleets"] == ["parent"]
    assert context.details["peer"]["status"] == "applied"
    target.client.groups.create_async.side_effect = target._create
    return loaded, plan, context


@pytest.mark.parametrize("retry_mode", ["resume", "new_plan"])
async def test_manifest_partial_apply_retry_owns_only_recorded_changes(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch, tmp_path: Path, retry_mode: str
) -> None:
    """A restarted MCP can finish a partial apply without rejecting its own new parent."""
    database = tmp_path / "manifest.sqlite3"
    store = ManifestStateStore(database)
    _, plan, first = await _partial_manifest_apply(leaders, monkeypatch, store)
    store.close()
    store = ManifestStateStore(database)
    if retry_mode == "new_plan":
        plan = await manifests.plan_config_manifest_replication("edge.yaml", state_store=store)
        assert plan["blocked_target_count"] == 0, plan
        assert all(target["prior_apply_guard"]["matched"] for target in plan["targets"])
    context = _JobContext("retry-apply")
    result = await manifests.execute_config_manifest_replication(
        "edge.yaml",
        expected_plan_sha256=plan["plan_sha256"],
        state_store=store,
        job_context=cast("JobContext", context),
        resume_details=first.details if retry_mode == "resume" else None,
    )
    assert result["status"] == "completed", context.details
    for name in ("target", "peer"):
        assert leaders[name].events == ["fleet:parent", "fleet:child", "destination:child/out", "mapping:rollout"]
        assert context.details[name]["created_fleets"] == ["child", "parent"]
    if retry_mode == "resume":
        assert context.details["peer"]["status"] == "resumed_completed"
    validity = await manifests.check_manifest_receipt_validity(
        "edge.yaml", apply_job_id=context.job_id, apply_receipt_sha256=None, state_store=store
    )
    assert validity["status"] == "valid", validity
    deploy = await manifests.plan_manifest_commit_deploy(
        "edge.yaml", apply_job_id=context.job_id, apply_receipt_sha256=None, message="finish", push=False, state_store=store
    )
    assert deploy["blocked_target_count"] == 0, deploy
    # Replanning a completed apply before deployment must also preserve its ownership.
    repeat = await manifests.plan_config_manifest_replication("edge.yaml", state_store=store)
    assert repeat["blocked_target_count"] == 0, repeat
    assert all(target["summary"]["create"] == 0 for target in repeat["targets"])


@pytest.mark.parametrize("drift", ["leader_file", "group_diff", "commit", "deploy", "missing_created", "conflict", "behind"])
async def test_manifest_retry_still_rejects_foreign_changes(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    """Receipt ownership never excuses intervening writes, version drift, or unsafe Git state."""
    store = ManifestStateStore()
    _, plan, first = await _partial_manifest_apply(leaders, monkeypatch, store)
    target = leaders["target"]
    parent = target.states[ProductsCore.EDGE, "parent"]
    if drift == "leader_file":
        target.states[ProductsCore.EDGE, "unrelated"] = _group_payload("unrelated", product=ProductsCore.EDGE)
    elif drift == "group_diff":
        target.diff_paths_by_group["parent"] = ["local/cribl/foreign.yml"]
    elif drift == "commit":
        parent["git"]["commit"] = "foreign"
    elif drift == "deploy":
        parent["configVersion"] = "foreign"
    elif drift == "missing_created":
        target.states[ProductsCore.EDGE, "child"] = _group_payload("child", product=ProductsCore.EDGE, inherits="parent")
    elif drift == "conflict":
        target.global_conflicts = ["local/cribl/foreign.yml"]
    else:
        target.global_behind = 1
    events = target.events.copy()
    replanned = await manifests.plan_config_manifest_replication("edge.yaml", state_store=store)
    assert replanned["blocked_target_count"] == 1, replanned
    context = _JobContext("blocked-retry")
    result = await manifests.execute_config_manifest_replication(
        "edge.yaml",
        expected_plan_sha256=plan["plan_sha256"],
        state_store=store,
        job_context=cast("JobContext", context),
        resume_details=first.details,
    )
    assert result["status"] == "partial_skip", context.details
    assert context.details["target"]["blocked_reasons"]
    assert target.events == events


@pytest.mark.parametrize("push", [False, True])
async def test_cluster_manifest_fields_receipts_order_and_per_leader_push(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch, *, push: bool
) -> None:
    """One manifest handles 12 fleets on 22 Leaders without group copies or push sweeps."""
    loaded = _loaded()
    loaded.manifest.targets[:] = [f"leader-{index:02d}" for index in range(22)]
    loaded.manifest.fleets[:] = [
        EdgeFleet(
            id=f"fleet-{index:02d}",
            inherits=f"fleet-{index - 1:02d}" if index else None,
            isSearch=False,
            streamtags=["cluster", f"tag-{index}"],
        )
        for index in range(12)
    ]
    loaded.manifest.content.clear()
    loaded.manifest.fleet_mappings.clear()
    for name in loaded.manifest.targets:
        leaders[name] = _EdgeHarness()

        async def _cached_push(harness: _EdgeHarness = leaders[name], **kwargs: object) -> object:
            result = await harness._push(**kwargs)
            harness.global_ahead = 5  # Cribl 4.18.1 can retain cached ahead after successful push.
            return result

        leaders[name].client.versions.commits.push_async.side_effect = _cached_push

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(manifests, "load_config_manifest", _load)
    store = ManifestStateStore()
    plan = await manifests.plan_config_manifest_replication("edge.yaml", state_store=store)
    assert plan["blocked_target_count"] == 0
    context = _JobContext("cluster-apply")
    applied = await manifests.execute_config_manifest_replication(
        "edge.yaml", expected_plan_sha256=plan["plan_sha256"], state_store=store, job_context=cast("JobContext", context)
    )
    assert applied["status"] == "completed", context.details
    for name in loaded.manifest.targets:
        for fleet in loaded.manifest.fleets:
            actual = leaders[name].states[ProductsCore.EDGE, fleet.id]
            assert actual["isSearch"] is False
            assert actual["streamtags"] == fleet.streamtags
            assert actual["configVersion"] == "commit-0"
        leaders[name].client.groups.update_async.assert_not_called()
    deploy = await manifests.plan_manifest_commit_deploy(
        "edge.yaml",
        apply_job_id=context.job_id,
        apply_receipt_sha256=None,
        message="cluster rollout",
        push=push,
        state_store=store,
    )
    assert deploy["blocked_target_count"] == 0, deploy
    deployed = await manifests.execute_manifest_commit_deploy(
        "edge.yaml",
        expected_plan_sha256=deploy["plan_sha256"],
        message="cluster rollout",
        push=push,
        state_store=store,
        job_context=cast("JobContext", context),
    )
    assert deployed["status"] == "completed", context.details
    assert deployed["push_summary"]["pushed" if push else "not_requested"] == 22
    assert len(deployed["push_results"]) == 22
    for name in loaded.manifest.targets:
        harness = leaders[name]
        assert harness.deploy_order == [fleet.id for fleet in loaded.manifest.fleets]
        assert harness.events[12] == f"leader:{edge.FLEET_FILE}"
        assert harness.push_count == int(push)
        if push:
            assert context.details[name]["push"]["verification"] == "api_reports_ahead"
            assert context.details[name]["push"]["remote_sync_verified"] is False


async def test_manifest_pushes_only_successful_leaders_and_preserves_peer_failures(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deployment and push failures stay local to their Leader and need no separate push sweep."""
    loaded = _loaded()
    loaded.manifest.targets[:] = ["target", "deploy-fails", "push-fails"]
    leaders["deploy-fails"] = _EdgeHarness()
    leaders["push-fails"] = _EdgeHarness()

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(manifests, "load_config_manifest", _load)
    state = ManifestStateStore()
    plan = await manifests.plan_config_manifest_replication("edge.yaml", state_store=state)
    context = _JobContext()
    await manifests.execute_config_manifest_replication(
        "edge.yaml", expected_plan_sha256=plan["plan_sha256"], state_store=state, job_context=cast("JobContext", context)
    )
    deploy = await manifests.plan_manifest_commit_deploy(
        "edge.yaml", apply_job_id=context.job_id, apply_receipt_sha256=None, message="rollout", push=True, state_store=state
    )
    leaders["deploy-fails"].deploy_error_for = "parent"
    leaders["push-fails"].push_error = RuntimeError("remote rejected")
    result = await manifests.execute_manifest_commit_deploy(
        "edge.yaml",
        expected_plan_sha256=deploy["plan_sha256"],
        message="rollout",
        push=True,
        state_store=state,
        job_context=cast("JobContext", context),
    )
    assert result["status"] == "partial_failure", context.details
    assert result["push_summary"] == {"pushed": 1, "failed": 1, "not_attempted": 1, "not_requested": 0}
    assert leaders["target"].push_count == 1
    leaders["deploy-fails"].client.versions.commits.push_async.assert_not_awaited()
    leaders["push-fails"].client.versions.commits.push_async.assert_awaited_once()
    assert context.details["push-fails"]["errors"][0]["phase"] == "push"
    assert context.details["target"]["status"] == "completed"


@pytest.mark.parametrize("drift", ["commit", "dirty", "behind", "conflict"])
async def test_manifest_retry_does_not_own_external_parent(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    """Creating a child in a receipt never grants ownership of its existing ancestor."""
    loaded = _loaded()
    loaded.manifest.fleets[:] = [EdgeFleet(id="child", inherits="parent")]
    target = leaders["target"]
    target.states[ProductsCore.EDGE, "parent"] = deepcopy(leaders["source"].states[ProductsCore.EDGE, "parent"])

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(manifests, "load_config_manifest", _load)
    store = ManifestStateStore()
    plan = await manifests.plan_config_manifest_replication("edge.yaml", state_store=store)
    context = _JobContext()
    await manifests.execute_config_manifest_replication(
        "edge.yaml", expected_plan_sha256=plan["plan_sha256"], state_store=store, job_context=cast("JobContext", context)
    )
    if drift == "commit":
        target.states[ProductsCore.EDGE, "parent"]["git"]["commit"] = "undeployed"
    elif drift == "dirty":
        target.states[ProductsCore.EDGE, "parent"]["git"]["localChanges"] = 1
    else:

        async def _status(**kwargs: Any) -> _Counted:  # noqa: ANN401
            result = await target._status(**kwargs)
            if str(kwargs.get("server_url", "")).endswith("/parent"):
                result.items[0].payload.update({"behind": 1} if drift == "behind" else {"conflicted": ["conflict"]})
            return result

        target.client.versions.statuses.get_async.side_effect = _status
    repeated = await manifests.plan_config_manifest_replication("edge.yaml", state_store=store)
    assert repeated["blocked_target_count"] == 1, repeated
    assert any("Parent fleet 'parent'" in reason for reason in repeated["targets"][0]["blocked_reasons"])


async def test_skipped_retry_preserves_receipt_for_later_recovery(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A temporarily unsafe Git state must not erase ownership needed by a later retry."""
    store = ManifestStateStore()
    _, plan, first = await _partial_manifest_apply(leaders, monkeypatch, store)
    leaders["target"].global_behind = 1
    skipped = _JobContext("skipped")
    result = await manifests.execute_config_manifest_replication(
        "edge.yaml",
        expected_plan_sha256=plan["plan_sha256"],
        state_store=store,
        job_context=cast("JobContext", skipped),
        resume_details=first.details,
    )
    assert result["status"] == "partial_skip"
    assert skipped.details["target"]["receipt_groups"] == first.details["target"]["receipt_groups"]
    leaders["target"].global_behind = 0
    plan = await manifests.plan_config_manifest_replication("edge.yaml", state_store=store)
    assert plan["blocked_target_count"] == 0, plan
    recovered = _JobContext("recovered")
    result = await manifests.execute_config_manifest_replication(
        "edge.yaml", expected_plan_sha256=plan["plan_sha256"], state_store=store, job_context=cast("JobContext", recovered)
    )
    assert result["status"] == "completed", recovered.details
    assert leaders["target"].events.count("fleet:parent") == 1


async def test_receipt_owned_existing_parent_changes_are_retryable(
    leaders: dict[str, _EdgeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A receipt may own copied parent content without claiming the parent was newly created."""
    loaded = _loaded()
    loaded.manifest.content[:] = [ManifestContent(group="parent", kind="destinations", items=["out"])]
    source, target = leaders["source"], leaders["target"]
    source.destinations["parent/out"] = {"id": "out", "type": "devnull"}
    target.states = deepcopy(source.states)

    def _load(_path: str) -> LoadedConfigManifest:
        return loaded

    monkeypatch.setattr(manifests, "load_config_manifest", _load)

    async def _create_destination(**kwargs: Any) -> _Counted:  # noqa: ANN401
        result = await target._create_destination(**kwargs)
        target.states[ProductsCore.EDGE, "parent"]["git"]["localChanges"] = 1
        return result

    target.client.destinations.create_async.side_effect = _create_destination
    store = ManifestStateStore()
    plan = await manifests.plan_config_manifest_replication("edge.yaml", state_store=store)
    context = _JobContext()
    result = await manifests.execute_config_manifest_replication(
        "edge.yaml", expected_plan_sha256=plan["plan_sha256"], state_store=store, job_context=cast("JobContext", context)
    )
    assert result["status"] == "completed", context.details
    assert context.details["target"]["created_fleets"] == []
    repeated = await manifests.plan_config_manifest_replication("edge.yaml", state_store=store)
    assert repeated["blocked_target_count"] == 0, repeated
    # Committing it outside the receipt still invalidates the new plan.
    target.states[ProductsCore.EDGE, "parent"]["git"]["commit"] = "foreign"
    stale = await manifests.plan_config_manifest_replication("edge.yaml", state_store=store)
    assert stale["blocked_target_count"] == 1, stale
