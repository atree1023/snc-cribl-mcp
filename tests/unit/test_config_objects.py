"""Tests for consolidated config object response shaping."""

from typing import Any, cast

import pytest

from snc_cribl_mcp.operations.config_objects import extract_config_object_refs, shape_config_object_response


def test_shape_config_object_response_returns_compact_summaries_with_cursor() -> None:
    """Summary responses should be compact, sorted, and cursor bounded."""
    product_results = {
        "stream": {
            "status": "ok",
            "total_count": 3,
            "groups": [
                {
                    "group_id": "phx",
                    "items": [
                        {
                            "id": "pipe_a",
                            "conf": {"functions": [{"id": "eval", "filter": "true"}]},
                            "description": "First pipeline",
                        },
                        {
                            "id": "pipe_b",
                            "conf": {"functions": [{"id": "mask", "filter": "true"}]},
                        },
                    ],
                },
                {
                    "group_id": "aus",
                    "items": [
                        {
                            "id": "pipe_c",
                            "conf": {"functions": [{"id": "eval", "filter": "true"}]},
                        },
                    ],
                },
            ],
        }
    }

    response = shape_config_object_response(
        kind="pipelines",
        product_results=product_results,
        detail="summary",
        limit=2,
    )

    assert response["kind"] == "pipelines"
    assert response["total_count"] == 3
    assert response["returned_count"] == 2
    assert response["truncated"] is True
    assert response["next_cursor"] == "2"
    assert response["objects"] == [
        {
            "product": "stream",
            "group_id": "aus",
            "id": "pipe_c",
            "name": None,
            "type": None,
            "enabled": None,
            "description": None,
            "refs": {},
        },
        {
            "product": "stream",
            "group_id": "phx",
            "id": "pipe_a",
            "name": None,
            "type": None,
            "enabled": None,
            "description": "First pipeline",
            "refs": {},
        },
    ]


def test_shape_config_object_response_filters_selector_and_returns_full_payload() -> None:
    """Full detail should be available when the caller narrows by selector."""
    product_results = {
        "stream": {
            "status": "ok",
            "total_count": 1,
            "groups": [
                {
                    "group_id": "default",
                    "items": [
                        {
                            "id": "syslog:in_syslog",
                            "type": "syslog",
                            "pipeline": "preprocess_syslog",
                            "host": "cribl-ldr.phx.example.com",
                        }
                    ],
                }
            ],
        }
    }

    response = shape_config_object_response(
        kind="sources",
        product_results=product_results,
        detail="full",
        selector="syslog",
        include_dependencies=True,
    )

    assert response["returned_count"] == 1
    assert response["objects"][0]["id"] == "syslog:in_syslog"
    assert response["objects"][0]["refs"] == {"pipelines": ["preprocess_syslog"]}
    assert response["objects"][0]["payload"]["host"] == "cribl-ldr.phx.example.com"


def test_shape_config_object_response_treats_selector_wildcards_as_globs() -> None:
    """Wildcard selectors should match object fields instead of being treated literally."""
    product_results = {
        "edge": {
            "status": "ok",
            "groups": [
                {
                    "group_id": "linux",
                    "items": [
                        {"id": "source-sysinfo-one", "type": "system_metrics"},
                        {"id": "source-sysinfo-two", "type": "system_metrics"},
                        {"id": "source-journald-one", "type": "journald"},
                    ],
                }
            ],
        }
    }

    response = shape_config_object_response(
        kind="sources",
        product_results=product_results,
        selector="SOURCE-SYSINFO-*",
    )

    assert response["total_count"] == 2
    assert [item["id"] for item in response["objects"]] == [
        "source-sysinfo-one",
        "source-sysinfo-two",
    ]


def test_shape_config_object_response_extracts_route_dependencies() -> None:
    """Route references should expose dependent pipelines and destinations."""
    product_results = {
        "stream": {
            "status": "ok",
            "total_count": 1,
            "groups": [
                {
                    "group_id": "default",
                    "items": [
                        {
                            "id": "default",
                            "routes": [
                                {
                                    "id": "generated-a",
                                    "name": "firewall",
                                    "pipeline": "parse_firewall",
                                    "output": "splunk:firewall",
                                },
                                {
                                    "id": "generated-b",
                                    "name": "netflow",
                                    "pipeline": "parse_netflow",
                                    "output": "s3:archive",
                                },
                            ],
                        }
                    ],
                }
            ],
        }
    }

    response = shape_config_object_response(
        kind="routes",
        product_results=product_results,
        detail="refs",
        include_dependencies=True,
    )

    assert response["objects"][0]["refs"] == {
        "destinations": ["s3:archive", "splunk:firewall"],
        "pipelines": ["parse_firewall", "parse_netflow"],
    }


def test_shape_config_object_response_handles_bounds_product_items_and_status_errors() -> None:
    """Response shaping should coerce paging inputs and preserve product-level errors."""
    product_results = {
        "stream": {
            "status": "ok",
            "items": [
                {
                    "groupId": "fleet-a",
                    "name": 42,
                    "type": "",
                    "disabled": True,
                    "description": "Alpha fleet",
                },
                {
                    "id": "fleet-b",
                    "enabled": True,
                },
                "skip-me",
            ],
        },
        "edge": {"status": "error", "message": "edge unavailable"},
        "worker": {"status": "timeout"},
    }

    response = shape_config_object_response(
        kind="groups",
        product_results=product_results,
        cursor="not-an-int",
        limit=0,
    )

    assert response["total_count"] == 2
    assert response["returned_count"] == 2
    assert response["next_cursor"] is None
    assert response["objects"][0]["id"] == "fleet-a"
    assert response["objects"][0]["name"] == "42"
    assert response["objects"][0]["type"] is None
    assert response["objects"][0]["enabled"] is False
    assert response["objects"][1]["enabled"] is True
    assert response["errors"] == [
        {"product": "edge", "status": "error", "message": "edge unavailable"},
        {"product": "worker", "status": "timeout"},
    ]

    negative_cursor_response = shape_config_object_response(
        kind="groups",
        product_results={"stream": {"status": "ok", "items": "not-a-list"}},
        cursor="-10",
    )

    assert negative_cursor_response["total_count"] == 0
    assert negative_cursor_response["objects"] == []


def test_shape_config_object_response_product_filter_omits_other_product_errors() -> None:
    """Product-scoped responses should not report skipped product failures."""
    product_results = {
        "stream": {
            "status": "ok",
            "groups": [
                {
                    "group_id": "default",
                    "items": [{"id": "syslog:keep"}],
                }
            ],
        },
        "edge": {"status": "error", "message": "edge unavailable"},
    }

    response = shape_config_object_response(
        kind="sources",
        product_results=product_results,
        product="stream",
    )

    assert response["total_count"] == 1
    assert response["objects"][0]["product"] == "stream"
    assert response["errors"] == []


def test_shape_config_object_response_filters_product_group_and_selector() -> None:
    """Product, group, and selector filters should skip non-matching records."""
    product_results = {
        "stream": {
            "status": "ok",
            "groups": [
                {
                    "group_id": "default",
                    "items": [
                        {
                            "id": "syslog:keep",
                            "description": "Matching source",
                            "pipelineId": "pipe-a",
                            "preprocess_pipeline": "pipe-b",
                        },
                        {"id": "http:drop", "description": "Other source"},
                    ],
                },
                {"group_id": "other", "items": [{"id": "syslog:other"}]},
                "not-a-group",
                {"group_id": "bad-items", "items": "not-a-list"},
            ],
        },
        "edge": {
            "status": "ok",
            "groups": [{"group_id": "default", "items": [{"id": "edge:skip"}]}],
        },
    }

    response = shape_config_object_response(
        kind="sources",
        product_results=product_results,
        detail="refs",
        product="stream",
        group_id="DEFAULT",
        selector="matching",
    )

    assert response["total_count"] == 1
    assert response["objects"][0]["id"] == "syslog:keep"
    assert response["objects"][0]["refs"] == {"pipelines": ["pipe-a", "pipe-b"]}


def test_extract_config_object_refs_handles_malformed_routes_and_non_dependency_kinds() -> None:
    """Dependency extraction should ignore malformed route values and unrelated kinds."""
    assert extract_config_object_refs("routes", {"routes": "not-a-list"}) == {}
    assert extract_config_object_refs("destinations", {"id": "splunk:hec"}) == {}

    refs = extract_config_object_refs(
        "routes",
        {
            "routes": [
                "not-a-route",
                {"pipelineId": "pipe-a", "destination": "dest-a"},
                {"pipeline": "pipe-b", "destId": "dest-b"},
            ]
        },
    )

    assert refs == {
        "destinations": ["dest-a", "dest-b"],
        "pipelines": ["pipe-a", "pipe-b"],
    }


def test_extract_config_object_refs_handles_pipeline_function_shapes() -> None:
    """Pipeline dependency extraction should skip malformed function entries."""
    assert extract_config_object_refs("pipelines", {"conf": "not-a-dict"}) == {}
    assert extract_config_object_refs("pipelines", {"conf": {"functions": "not-a-list"}}) == {}

    refs = extract_config_object_refs(
        "pipelines",
        {
            "conf": {
                "functions": [
                    "not-a-function",
                    {"conf": "not-a-dict"},
                    {"conf": {"lookup": "lookup-a", "lookupName": "lookup-b", "file": "file-a"}},
                ]
            }
        },
    )

    assert refs == {"lookups": ["file-a", "lookup-a", "lookup-b"]}


def test_shape_config_object_response_rejects_unsupported_kind() -> None:
    """Unsupported object kinds should raise a clear ValueError."""
    with pytest.raises(ValueError, match="Unsupported config object kind"):
        shape_config_object_response(kind=cast("Any", "widgets"), product_results={})
