# Changelog

All notable changes to snc-cribl-mcp will be documented in this file.

## [0.1.1] - 2026-01-27

### Added

- **`pipeline_id` filter for `list_pipelines` tool** — Optional parameter to fetch a specific pipeline by ID instead of all pipelines. When provided, queries `/m/{group}/pipelines/{pipeline_id}` per group and gracefully handles 404s for groups that don't have that pipeline.

### Changed

- `HttpCollectionContext` now supports an optional `item_id` field for single-item fetches
- `generic_list_tool` accepts `collector_kwargs` for forwarding extra parameters to collectors
- Improved 404 error messages to distinguish between "endpoint not found" and "item not found"

## [0.1.0] - 2025-11-27

### Added

- Initial release
- **MCP Tools:**
  - `list_groups` — List all worker groups for Stream and Edge products
  - `list_pipelines` — List configured pipelines with full function configuration
  - `list_routes` — List routing rules across all groups
  - `list_sources` — List data sources including collectors
  - `list_destinations` — List output destinations
  - `list_breakers` — List event breaker rulesets
  - `list_lookups` — List lookup tables
- OAuth2 client credentials authentication with automatic token refresh
- Support for both Cribl Stream and Cribl Edge products
- HTTP-based collection for pipelines, breakers, and lookups to preserve full function config (SDK limitation workaround)
- Comprehensive error handling with graceful degradation for unavailable products
