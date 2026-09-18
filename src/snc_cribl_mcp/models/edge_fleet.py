"""Desired creation fields for Edge fleets and subfleets."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EdgeFleet(BaseModel):
    """Create-only fleet declaration; inherits names an exact parent fleet ID."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    id: str = Field(pattern=r"^[a-zA-Z0-9_-]+$", min_length=1, max_length=256)
    name: str | None = Field(default=None, min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=4096)
    inherits: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_-]+$")
    worker_remote_access: bool | None = Field(default=None, alias="workerRemoteAccess")
    is_search: bool | None = Field(default=None, alias="isSearch")
    streamtags: list[str] | None = None

    def payload(self) -> dict[str, Any]:
        """Return only writable SDK fields, with an explicit Edge type."""
        return {**self.model_dump(by_alias=True, exclude_none=True), "type": "edge"}


def ordered_fleets(fleets: list[EdgeFleet]) -> list[EdgeFleet]:
    """Validate declarations and sort parents before their descendants."""
    pending = {fleet.id: fleet for fleet in fleets}
    if len(pending) != len(fleets):
        msg = "fleets contains duplicate IDs."
        raise ValueError(msg)
    result: list[EdgeFleet] = []
    while pending:
        ready = sorted(key for key, fleet in pending.items() if fleet.inherits not in pending)
        if not ready:
            msg = "Fleet inheritance contains a cycle or self-reference."
            raise ValueError(msg)
        result.extend(pending.pop(key) for key in ready)
    return result
