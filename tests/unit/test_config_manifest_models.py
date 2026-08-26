"""Tests for strict configuration-manifest parsing and path safety."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

import snc_cribl_mcp.models.config_manifest as manifest_module
from snc_cribl_mcp.models.config_manifest import delete_config_manifest, load_config_manifest, write_config_manifest


@pytest.fixture
def manifest_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Use an isolated safe root and configured-server catalog."""
    root = tmp_path / "manifests"
    root.mkdir()
    monkeypatch.setattr(manifest_module, "config_manifest_root", lambda: root)
    monkeypatch.setattr(manifest_module, "configured_server_names", lambda: ("golden.oak", "golden.oak.new"))
    return root


def _write_manifest(root: Path, content: str, *, name: str = "wave.yaml") -> Path:
    path = root / name
    path.write_text(content, encoding="utf-8")
    return path


def test_load_manifest_normalizes_and_hashes_stable_intent(manifest_root: Path) -> None:
    """Equivalent YAML formatting should produce one canonical manifest digest."""
    first = _write_manifest(
        manifest_root,
        """
schema: 1
wave: 6
source: {server: golden.oak, product: edge}
content:
  - group: default
    kind: sources
    items: [source-b, source-a]
targets: [golden.oak.new]
options: {overwrite: true, concurrency: 4}
""".strip(),
    )
    loaded = load_config_manifest(first.name)
    second = _write_manifest(
        manifest_root,
        """
targets:
  - golden.oak.new
content:
  - items: [source-a, source-b]
    kind: sources
    group: default
source:
  product: edge
  server: golden.oak
wave: 6
schema: 1
options:
  concurrency: 4
  overwrite: true
""".strip(),
        name="equivalent.yml",
    )
    equivalent = load_config_manifest(second.name)

    assert loaded.relative_path == "wave.yaml"
    assert loaded.manifest.options.concurrency == 4
    assert loaded.manifest_sha256 == equivalent.manifest_sha256
    assert loaded.file_sha256 != equivalent.file_sha256


@pytest.mark.parametrize(
    ("content", "match"),
    [
        (
            """
schema: 1
schema: 1
wave: test
source: {server: golden.oak, product: edge}
content: [{group: default, kind: sources, items: [one]}]
targets: [golden.oak.new]
""",
            "Duplicate YAML mapping key",
        ),
        (
            """
schema: 1
wave: test
source: &source {server: golden.oak, product: edge}
content: [{group: default, kind: sources, items: [one]}]
targets: [golden.oak.new]
copy: *source
""",
            "aliases are not allowed",
        ),
    ],
)
def test_loader_rejects_duplicate_keys_and_aliases(manifest_root: Path, content: str, match: str) -> None:
    """YAML features that can hide or overwrite intent must be rejected."""
    path = _write_manifest(manifest_root, content.strip())
    with pytest.raises(ValueError, match=match):
        load_config_manifest(path.name)


def test_loader_rejects_path_escape_unknown_fields_and_servers(manifest_root: Path, tmp_path: Path) -> None:
    """Only strict manifests under the configured root may be loaded."""
    outside = tmp_path / "outside.yaml"
    outside.write_text("schema: 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="within configured root"):
        load_config_manifest(str(outside))

    invalid = _write_manifest(
        manifest_root,
        """
schema: 1
wave: test
source: {server: golden.oak, product: stream}
content:
  - group: default
    kind: pipelines
    items: [main]
targets: [unknown, unknown]
inline_secret: forbidden
""".strip(),
    )
    with pytest.raises(ValidationError):
        load_config_manifest(invalid.name)


def test_manifest_rejects_source_target_overlap_and_duplicate_sections(manifest_root: Path) -> None:
    """Ambiguous server and content fan-out must fail before API calls."""
    path = _write_manifest(
        manifest_root,
        """
schema: 1
wave: test
source: {server: golden.oak, product: edge}
content:
  - {group: default, kind: sources, items: [one]}
  - {group: default, kind: sources, items: [two]}
targets: [golden.oak]
""".strip(),
    )
    with pytest.raises(ValidationError):
        load_config_manifest(path.name)


def test_write_manifest_validates_paths_and_requires_explicit_overwrite(manifest_root: Path) -> None:
    """Sandboxed authors should get schema validation before a safely rooted write."""
    content = """
schema: 1
wave: write-test
source: {server: golden.oak, product: edge}
content: [{group: default, kind: destinations, items: [out]}]
targets: [golden.oak.new]
options: {concurrency: 2}
""".strip()

    loaded, status = write_config_manifest("nested/wave", content)
    assert status == "created"
    assert loaded.relative_path == "nested/wave.yaml"
    assert loaded.path.read_text(encoding="utf-8") == content
    assert write_config_manifest("nested/wave.yaml", content)[1] == "unchanged"

    changed = content.replace("write-test", "changed")
    with pytest.raises(FileExistsError, match="overwrite=true"):
        write_config_manifest("nested/wave.yaml", changed)
    replaced, status = write_config_manifest("nested/wave.yaml", changed, overwrite=True)
    assert status == "updated"
    assert replaced.manifest.wave == "changed"

    with pytest.raises(ValueError, match="within configured root"):
        write_config_manifest("../escape.yaml", content)
    with pytest.raises(ValidationError):
        write_config_manifest("invalid.yaml", "schema: 1\n")
    assert not (manifest_root / "invalid.yaml").exists()


def test_delete_manifest_is_rooted_and_can_guard_the_file_digest(manifest_root: Path) -> None:
    """Cleanup should refuse stale or out-of-root targets before deleting a manifest."""
    content = """
schema: 1
wave: cleanup
source: {server: golden.oak, product: edge}
content: [{group: default, kind: destinations, items: [out]}]
targets: [golden.oak.new]
""".strip()
    loaded, _status = write_config_manifest("cleanup.yaml", content)

    with pytest.raises(ValueError, match="changed after inspection"):
        delete_config_manifest("cleanup.yaml", expected_file_sha256="stale")
    assert loaded.path.exists()

    deleted = delete_config_manifest("cleanup.yaml", expected_file_sha256=loaded.file_sha256)
    assert deleted.relative_path == "cleanup.yaml"
    assert not loaded.path.exists()
