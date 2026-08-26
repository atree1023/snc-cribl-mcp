"""Strict models and safe loading for multi-leader configuration manifests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal, Self, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from yaml.events import AliasEvent, Event
from yaml.nodes import MappingNode, Node

from ..config import config_manifest_root, configured_server_names

type ManifestContentKind = Literal[
    "breakers",
    "destinations",
    "lookups",
    "pipelines",
    "routes",
    "sources",
    "variables",
]
type ManifestProduct = Literal["edge", "stream"]
type DriftPolicy = Literal["abort", "skip"]

_MAX_MANIFEST_BYTES = 1_048_576
_MAX_YAML_DEPTH = 20
_MAX_TARGETS = 100
_MAX_ITEMS = 10_000


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: MappingNode,
    deep: bool = False,  # noqa: FBT001, FBT002 - PyYAML callback signature
) -> dict[object, object]:
    """Construct a mapping while rejecting keys that would otherwise be overwritten."""
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    node_values = cast("list[tuple[Node, Node]]", node.value)
    for key_node, value_node in node_values:
        key = cast(
            "object",
            loader.construct_object(key_node, deep=deep),  # pyright: ignore[reportUnknownMemberType]
        )
        if key in result:
            msg = f"Duplicate YAML mapping key '{key}'."
            raise ValueError(msg)
        result[key] = cast(
            "object",
            loader.construct_object(value_node, deep=deep),  # pyright: ignore[reportUnknownMemberType]
        )
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _canonical_digest(value: object) -> str:
    """Return a deterministic SHA-256 digest for JSON-compatible data."""
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(payload).hexdigest()


def _yaml_depth(value: object, *, depth: int = 0) -> int:
    """Return the maximum container depth of a parsed YAML value."""
    if depth > _MAX_YAML_DEPTH:
        return depth
    if isinstance(value, dict):
        mapping = cast("dict[object, object]", value)
        return max((_yaml_depth(item, depth=depth + 1) for item in mapping.values()), default=depth)
    if isinstance(value, list):
        sequence = cast("list[object]", value)
        return max((_yaml_depth(item, depth=depth + 1) for item in sequence), default=depth)
    return depth


def _non_empty(value: str) -> str:
    """Normalize a required non-empty string."""
    normalized = value.strip()
    if not normalized:
        msg = "Value must not be blank."
        raise ValueError(msg)
    return normalized


def _unique_strings(values: list[str], *, field_name: str) -> list[str]:
    """Normalize and require unique non-empty strings."""
    normalized = [_non_empty(value) for value in values]
    duplicates = sorted({value for value in normalized if normalized.count(value) > 1})
    if duplicates:
        msg = f"{field_name} contains duplicate values: {', '.join(duplicates)}."
        raise ValueError(msg)
    return normalized


class ManifestSource(BaseModel):
    """Source leader and product for one manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server: str
    product: ManifestProduct

    @field_validator("server")
    @classmethod
    def _validate_server(cls, value: str) -> str:
        return _non_empty(value)


class ManifestContent(BaseModel):
    """Explicit resource items to replicate within one same-named group."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    group: str
    kind: ManifestContentKind
    items: list[str] = Field(min_length=1)

    @field_validator("group")
    @classmethod
    def _validate_group(cls, value: str) -> str:
        return _non_empty(value)

    @field_validator("items")
    @classmethod
    def _validate_items(cls, value: list[str]) -> list[str]:
        return _unique_strings(value, field_name="items")


class ManifestOptions(BaseModel):
    """Bounded execution options for a configuration manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    overwrite: bool = True
    append_routes: bool = False
    concurrency: int = Field(default=5, ge=1, le=10)
    on_drift: DriftPolicy = "skip"


class ConfigManifest(BaseModel):
    """Versioned manifest for replicating explicit items to configured leaders."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_: Literal[1] = Field(alias="schema")
    wave: str | int
    source: ManifestSource
    content: list[ManifestContent] = Field(min_length=1)
    targets: list[str] = Field(min_length=1, max_length=_MAX_TARGETS)
    options: ManifestOptions = Field(default_factory=ManifestOptions)

    @field_validator("wave")
    @classmethod
    def _validate_wave(cls, value: str | int) -> str | int:
        if isinstance(value, str):
            return _non_empty(value)
        return value

    @field_validator("targets")
    @classmethod
    def _validate_targets(cls, value: list[str]) -> list[str]:
        return _unique_strings(value, field_name="targets")

    @model_validator(mode="after")
    def _validate_manifest(self) -> Self:
        if self.source.server in self.targets:
            msg = "source.server must not also appear in targets."
            raise ValueError(msg)
        configured = set(configured_server_names())
        unknown = sorted(({self.source.server} | set(self.targets)) - configured)
        if unknown:
            msg = f"Manifest references unconfigured servers: {', '.join(unknown)}."
            raise ValueError(msg)
        content_keys = [(entry.group, entry.kind) for entry in self.content]
        duplicates = sorted({f"{group}/{kind}" for group, kind in content_keys if content_keys.count((group, kind)) > 1})
        if duplicates:
            msg = f"Manifest contains duplicate group/kind sections: {', '.join(duplicates)}."
            raise ValueError(msg)
        item_count = sum(len(entry.items) for entry in self.content)
        if item_count > _MAX_ITEMS:
            msg = f"Manifest contains {item_count} items; the maximum is {_MAX_ITEMS}."
            raise ValueError(msg)
        if self.options.append_routes and any(entry.kind != "routes" for entry in self.content):
            # The option still only affects route entries; this warning-worthy shape is legal.
            return self
        return self

    def canonical_payload(self) -> dict[str, Any]:
        """Return a stable manifest intent payload independent of YAML formatting."""
        payload = self.model_dump(by_alias=True, mode="json")
        payload["targets"] = sorted(self.targets)
        payload["content"] = sorted(
            (
                {
                    "group": entry.group,
                    "kind": entry.kind,
                    "items": sorted(entry.items),
                }
                for entry in self.content
            ),
            key=lambda item: (str(item["group"]), str(item["kind"])),
        )
        return payload


class LoadedConfigManifest(BaseModel):
    """Validated manifest plus stable file and intent metadata."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    manifest: ConfigManifest
    path: Path
    relative_path: str
    file_sha256: str
    manifest_sha256: str


def _resolve_manifest_path(manifest_path: str) -> tuple[Path, str]:
    """Resolve a manifest path beneath the configured root without following escapes."""
    requested = Path(_non_empty(manifest_path)).expanduser()
    root = config_manifest_root()
    candidate = (requested if requested.is_absolute() else root / requested).resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        msg = f"Manifest path must be within configured root '{root}'."
        raise ValueError(msg) from exc
    if candidate.suffix.casefold() not in {".yaml", ".yml"}:
        msg = "Manifest path must end in .yaml or .yml."
        raise ValueError(msg)
    if not candidate.is_file():
        msg = f"Manifest file '{relative}' does not exist."
        raise ValueError(msg)
    return candidate, relative.as_posix()


def _parse_manifest_bytes(raw: bytes) -> ConfigManifest:
    """Strictly parse and validate UTF-8 manifest bytes."""
    if len(raw) > _MAX_MANIFEST_BYTES:
        msg = f"Manifest exceeds the {_MAX_MANIFEST_BYTES}-byte limit."
        raise ValueError(msg)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        msg = "Manifest must be UTF-8 encoded."
        raise ValueError(msg) from exc
    try:
        events = cast(
            "Iterable[Event]",
            yaml.parse(text),  # pyright: ignore[reportUnknownMemberType]
        )
        if any(isinstance(event, AliasEvent) for event in events):
            msg = "YAML aliases are not allowed in configuration manifests."
            raise ValueError(msg)
        parsed = cast("object", yaml.load(text, Loader=_UniqueKeyLoader))  # noqa: S506 - custom SafeLoader subclass
    except yaml.YAMLError as exc:
        msg = f"Invalid YAML manifest: {exc}."
        raise ValueError(msg) from exc
    if not isinstance(parsed, dict):
        msg = "Manifest root must be a YAML mapping."
        raise TypeError(msg)
    parsed_mapping = cast("dict[object, object]", parsed)
    if _yaml_depth(parsed_mapping) > _MAX_YAML_DEPTH:
        msg = f"Manifest nesting exceeds the maximum depth of {_MAX_YAML_DEPTH}."
        raise ValueError(msg)
    return ConfigManifest.model_validate(parsed_mapping)


def _loaded_manifest(*, manifest: ConfigManifest, path: Path, relative_path: str, raw: bytes) -> LoadedConfigManifest:
    """Build stable file and intent metadata for a validated manifest."""
    return LoadedConfigManifest(
        manifest=manifest,
        path=path,
        relative_path=relative_path,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        manifest_sha256=_canonical_digest(manifest.canonical_payload()),
    )


def load_config_manifest(manifest_path: str) -> LoadedConfigManifest:
    """Safely load and strictly validate one configuration manifest."""
    path, relative_path = _resolve_manifest_path(manifest_path)
    raw = path.read_bytes()
    manifest = _parse_manifest_bytes(raw)
    return _loaded_manifest(manifest=manifest, path=path, relative_path=relative_path, raw=raw)


def write_config_manifest(name: str, content: str, *, overwrite: bool = False) -> tuple[LoadedConfigManifest, str]:
    """Validate and persist one manifest beneath the configured safe root.

    Identical existing content is idempotent. Replacing different content requires
    an explicit ``overwrite=true`` request.
    """
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        msg = "Manifest content must be UTF-8 encodable."
        raise ValueError(msg) from exc
    manifest = _parse_manifest_bytes(raw)

    requested = Path(_non_empty(name)).expanduser()
    if not requested.suffix:
        requested = requested.with_suffix(".yaml")
    root = config_manifest_root()
    candidate = (requested if requested.is_absolute() else root / requested).resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        msg = f"Manifest path must be within configured root '{root}'."
        raise ValueError(msg) from exc
    if candidate.suffix.casefold() not in {".yaml", ".yml"}:
        msg = "Manifest name must end in .yaml or .yml."
        raise ValueError(msg)
    if candidate.exists() and not candidate.is_file():
        msg = f"Manifest path '{relative}' is not a regular file."
        raise ValueError(msg)

    status = "created"
    if candidate.is_file():
        if candidate.read_bytes() == raw:
            status = "unchanged"
        elif not overwrite:
            msg = f"Manifest '{relative}' already exists with different content; pass overwrite=true to replace it."
            raise FileExistsError(msg)
        else:
            status = "updated"
    if status != "unchanged":
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_bytes(raw)
    loaded = _loaded_manifest(
        manifest=manifest,
        path=candidate,
        relative_path=relative.as_posix(),
        raw=raw,
    )
    return loaded, status


__all__ = [
    "ConfigManifest",
    "DriftPolicy",
    "LoadedConfigManifest",
    "ManifestContent",
    "ManifestContentKind",
    "ManifestOptions",
    "ManifestProduct",
    "ManifestSource",
    "load_config_manifest",
    "write_config_manifest",
]
