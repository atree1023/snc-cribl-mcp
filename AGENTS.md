# SNC Cribl MCP

MCP server providing tools to query Cribl Stream and Edge deployments. Uses FastMCP 2 and the cribl-control-plane SDK.

> **For Claude Code users:** See `CLAUDE.md` for detailed guidance on architecture decisions, workflows, and patterns.

## Quick Start

```bash
uv sync                                    # install dependencies
uv run snc_cribl_mcp                       # run server
uv run pytest                              # run tests
```

## Dev Environment

- **Package manager:** uv
- **Virtual env:** `.venv/` (created by `uv sync`)
- **Entry point:** `src/snc_cribl_mcp/server.py`
- **Python version:** 3.13+

## Build & Test

```bash
# Tests
uv run pytest                             # all tests
uv run pytest --cov=src/snc_cribl_mcp     # with coverage
uv run pytest tests/unit/test_server.py   # specific file

# Quality checks (run all before committing)
uv run ruff format                         # format
uv run ruff check --fix                    # lint and auto-fix
uv run pyright                             # type check
```

## Code Style

- Python 3.13+ with complete type hints
- Ruff: line length 128 (see `pyproject.toml` for full config)
- Pyright: strict mode
- Docstrings: Google style
- Async/await for all I/O operations
- Pydantic for data models

## Documentation Resources

Before writing code:

1. **Cribl SDK:** Check `docs/examples/` for authentication and API patterns
2. **FastMCP:** Search web for latest docs from gofastmcp.com
3. **Pipeline functions:** `docs/pipeline_functions/<id>.json` for schemas
4. **Collectors:** `docs/collectors/<id>.json` for schemas
5. **Cribl API:** `docs/cribl-openapi-spec.yml` (prefer SDK over direct calls)

**Critical SDK notes:**

- "On-prem", "onprem", and "customer managed" are equivalent terms
- Use `docs/examples/example_onprem_auth.py` pattern for authentication
- Distributed environments require `/m/{group_id}/` URL scoping

## File Structure

```text
src/snc_cribl_mcp/
├── server.py              # FastMCP app, entry point
├── config.py              # Environment config loading
├── prompts.py             # MCP prompt definitions
├── resources.py           # MCP resource definitions
├── client/                # Token management, client factory
├── models/                # Pydantic models (collectors, pipeline functions)
├── operations/            # Business logic for Cribl API
└── tools/                 # MCP tool registrations

tests/unit/                # pytest tests
docs/                      # SDK docs, schemas, examples
```

## MCP Capabilities

**Tools:** list_groups, list_sources, list_destinations, list_pipelines, list_routes, list_breakers, list_lookups

**Resources:** cribl://groups, cribl://sources, cribl://destinations, cribl://pipelines, cribl://routes, cribl://breakers, cribl://lookups

**Prompts:** Summarize Cribl Configuration, Find Broken Sources, Analyze Pipeline, Troubleshoot Destination

## Common Workflows

### Add New Tool

1. Create `src/snc_cribl_mcp/operations/<resource>.py`
2. Create `src/snc_cribl_mcp/tools/list_<resource>.py` (follow `list_sources.py` pattern)
3. Register in `server.py` `_register_capabilities()`
4. Add `tests/unit/test_<resource>.py`
5. Run: `uv run ruff format && uv run ruff check --fix && uv run pyright && uv run pytest`

### Update Dependencies

```bash
uv add package-name           # runtime dependency
uv add --dev package-name     # dev dependency
uv sync                       # sync lockfile
```

## Definition of Done

- [ ] All tests pass (`uv run pytest`)
- [ ] Type check passes (`uv run pyright`)
- [ ] Lint passes (`uv run ruff check`)
- [ ] Test coverage ≥80%
- [ ] Docstrings reflect implementation
- [ ] README.md/CLAUDE.md/AGENTS.md updated if needed
