# Config Object Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first production-ready foundation for consolidated Cribl config object retrieval, semantic equivalence, and dependency-aware replication planning.

**Architecture:** Add an SDK-first config object catalog that normalizes read access across supported Cribl object kinds, with direct API fallback metadata for endpoints the SDK does not cover. Layer semantic canonicalization over that catalog so validation can distinguish functional drift from environment identity and volatile fields. Keep mutation/deploy behavior behind explicit future planning hooks while making the read and compare substrate testable now.

**Tech Stack:** Python 3.14, FastMCP 3.2, cribl-control-plane SDK 0.7, Pydantic, pytest, pytest-httpx, pyright, ruff.

---

## Task list

### Task 1: Baseline And Safety

**Files:**

- Read: `CLAUDE.md`
- Read: `docs/CRIBL-CONTROL-PLANE-README.md`
- Read: installed SDK/FastMCP package metadata

- [ ] Run `uv run ruff check`
- [ ] Run `uv run pyright`
- [ ] Run `uv run pytest`
- [ ] Record any pre-existing failures before production edits.

### Task 2: Config Object Catalog

**Files:**

- Create: `src/snc_cribl_mcp/operations/config_objects.py`
- Test: `tests/unit/test_config_objects.py`

- [ ] Write tests for supported object kinds, object summaries, group-scoped SDK reads, product-scoped SDK reads, and result limiting.
- [ ] Implement `ConfigObjectKind`, `ConfigObjectQuery`, `ConfigObjectRecord`, and registry entries for `groups`, `sources`, `destinations`, `pipelines`, `routes`, `breakers`, and `lookups`.
- [ ] Reuse existing collectors where they already handle SDK validation errors and direct API fallbacks.
- [ ] Return compact summaries by default, with `detail="full"` gated by filters and limits.
- [ ] Include cursor/truncation metadata so large pipeline lists do not exceed client tool result limits.

### Task 3: Semantic Equivalence

**Files:**

- Create: `src/snc_cribl_mcp/operations/semantic_diff.py`
- Test: `tests/unit/test_semantic_diff.py`

- [ ] Write tests showing generated IDs, hostnames, URLs, destination server lists, timestamps, and revision metadata are non-blocking identity or volatile differences.
- [ ] Write tests showing route filters, pipeline function configuration, enabled state, and source/destination type are blocking functional differences.
- [ ] Implement path classification with explainable reasons.
- [ ] Implement canonicalization and bounded diff output with `functional_differences`, `identity_differences`, and `volatile_differences`.

### Task 4: Consolidated MCP Tools

**Files:**

- Create: `src/snc_cribl_mcp/tools/get_config_objects.py`
- Create: `src/snc_cribl_mcp/tools/validate_config_objects.py`
- Modify: `src/snc_cribl_mcp/server.py`
- Test: `tests/unit/test_get_config_objects_tool.py`
- Test: `tests/unit/test_validate_config_objects_tool.py`

- [ ] Register `get_config_objects` as the main consolidated read tool.
- [ ] Register `validate_config_objects` as the semantic validation entry point.
- [ ] Keep existing list tools for compatibility while the new tool matures.
- [ ] Add read-only annotations and concise descriptions that work well with FastMCP tool search.

### Task 5: Replication Planning Hook

**Files:**

- Create: `src/snc_cribl_mcp/operations/replication_plan.py`
- Create: `src/snc_cribl_mcp/tools/plan_config_replication.py`
- Modify: `src/snc_cribl_mcp/server.py`
- Test: `tests/unit/test_replication_plan.py`
- Test: `tests/unit/test_plan_config_replication_tool.py`

- [ ] Write tests for dependency closure from route to pipeline/destination and source to preprocessing pipeline.
- [ ] Implement a dry-run plan that lists create/update/skip actions and preserves target identity fields.
- [ ] Do not implement mutating apply behavior in this first slice unless the validation substrate is complete and verified.

### Task 6: Documentation And Validation Plan

**Files:**

- Modify: `README.md`
- Modify: `CLAUDE.md`
- Create: `docs/config-object-validation-plan.md`

- [ ] Document the new consolidated tools and semantic diff behavior.
- [ ] Document a mock-client test path using pytest fixtures.
- [ ] Document a dev-system smoke path using configured leaders without exposing credentials.
- [ ] Include expected checks: `get_config_objects` summaries, semantic validation between two leaders, dependency plan for one route/source, and FastMCP tool discovery.

### Task 7: Verification

**Files:**

- Verify all touched files.

- [ ] Run targeted tests for new modules.
- [ ] Run `uv run ruff format`.
- [ ] Run `uv run ruff check --fix`.
- [ ] Run `uv run pyright`.
- [ ] Run `uv run pytest`.
- [ ] If dev leaders are reachable, run an MCP/client smoke test against non-destructive read/plan tools only.
