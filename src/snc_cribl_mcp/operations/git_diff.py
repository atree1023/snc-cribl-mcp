"""Bound public Git diffs independently of upstream line-limit behavior."""

from __future__ import annotations

import json
from typing import Any

MAX_DIFF_BYTES = 256_000
_MAX_FILES = 100
_MAX_TEXT_CHARS = 8192


def _bounded_fields(value: dict[str, Any]) -> dict[str, Any]:
    """Copy scalar diff metadata, clipping unusually large strings."""
    result: dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, str):
            result[key] = item[:_MAX_TEXT_CHARS]
            if len(item) > _MAX_TEXT_CHARS:
                result["content_truncated"] = True
        elif item is None or isinstance(item, bool | int | float):
            result[key] = item
    return result


def _json_size(value: object) -> int:
    """Count conservatively, including JSON escaping and whitespace."""
    return len(json.dumps(value).encode())


def bounded_diff(  # noqa: C901, PLR0912, PLR0915 - one shared budget across nested files, hunks and lines
    files: list[dict[str, Any]], *, line_limit: int, line_offset: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a bounded diff page and explicit truncation/continuation metadata.

    Offsets count hunk lines across files. Hashes and summaries must be computed
    from the original files before calling this presentation-only helper.
    A zero line limit removes only the line cap, never the byte/file caps.
    """
    if line_limit < 0 or line_offset < 0:
        msg = "diff_line_limit and line_offset must be zero or greater."
        raise ValueError(msg)
    total_lines = sum(len(block.get("lines", [])) for file in files for block in file.get("blocks", []))
    output: list[dict[str, Any]] = []
    seen = returned = 0
    size = 100
    clipped = False
    stopped = False
    for file in files:
        blocks: list[dict[str, Any]] = []
        file_output = {**_bounded_fields(file), "blocks": blocks}
        file_size = _json_size(file_output)
        if len(output) >= _MAX_FILES or size + file_size > MAX_DIFF_BYTES:
            stopped = True
            break
        added_file = False
        for block in file.get("blocks", []):
            lines: list[dict[str, Any]] = []
            block_output = {**_bounded_fields(block), "lines": lines}
            block_size = _json_size(block_output)
            for line in block.get("lines", []):
                if seen < line_offset:
                    seen += 1
                    continue
                if line_limit and returned >= line_limit:
                    stopped = True
                    break
                line_output = _bounded_fields(line)
                line_size = _json_size(line_output) + 2
                overhead = (file_size if not added_file else 0) + (block_size if not lines else 0)
                if size + overhead + line_size > MAX_DIFF_BYTES:
                    stopped = True
                    break
                if not added_file:
                    output.append(file_output)
                    added_file = True
                    size += file_size
                if not lines:
                    blocks.append(block_output)
                    size += block_size
                lines.append(line_output)
                clipped |= bool(line_output.get("content_truncated"))
                size += line_size
                seen += 1
                returned += 1
            if stopped:
                break
        if not added_file and not file.get("blocks") and line_offset == 0:
            output.append(file_output)
            size += file_size
        clipped |= bool(file_output.get("content_truncated")) or any(b.get("content_truncated") for b in blocks)
        if stopped:
            break
    upstream_truncated = any(file.get("isTooBig") or file.get("is_too_big") for file in files)
    return {"count": 1, "items": [{"diffJson": output}]}, {
        "line_limit": line_limit,
        "line_offset": line_offset,
        "total_lines": total_lines,
        "returned_lines": returned,
        "returned_files": len(output),
        "truncated": stopped or clipped or upstream_truncated or line_offset > 0,
        "content_truncated": clipped,
        "upstream_truncated": upstream_truncated,
        "byte_limit": MAX_DIFF_BYTES,
        "next_line_offset": line_offset + returned if returned and line_offset + returned < total_lines else None,
    }
