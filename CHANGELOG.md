# Changelog

All notable changes to snc-cribl-mcp will be documented in this file.

## In Progress

### Added

- Added Git status and deployed/pending diff inspection for Stream worker groups and Edge fleets/subfleets.
- Added dry-run-protected group/fleet commit, explicit-version deploy, combined commit/deploy, parent-first deploy-all, and configured-remote push workflows.
- Added plan-digest drift checks, conflict/remote preflights, Leader deployment-metadata commits, partial-failure reporting, and rollout status reporting.
- Added `get_config_deployment_job` for polling non-blocking commit, deployment, and Git push executions.
- Added content-addressed dry-run plans and exact-plan confirmation to `copy_resource_config`; the exposed tool now defaults to `dry_run=true`.

### Fixed

- Bounded large-change review responses to one 25-path preview while retaining complete changed-path and pending-diff digests.
- Removed duplicate changed-path arrays, full reviewed plans, and raw SDK commit/deployment payloads from mutation results.
- Isolated mutation jobs from the MCP event loop and serialized them per configured server so long deployments do not block status and diff tools.
- Updated minimal group listing for the current SDK's counted response wrapper.
- Restored SDK 0.11 group, group-scoped object, Pack, leader-summary, and Git-status reads by normalizing `response.result` wrappers while rejecting unknown response shapes instead of returning silent empty results.
- Applied SDK 0.11 pagination to Pack inventories and version-control target discovery, and consolidated node pagination on the shared strict response normalizer.
- Documented the SDK 0.11 Pack `with_=collectors` expansion so callers can retrieve Pack collector counts without follow-up requests.
- Constrained the Preview `cribl-control-plane` dependency to the live-validated `>=0.11.0,<0.12` compatibility line.
- Preserved non-empty network error details and removed runtime-only status timestamps from config drift checks.

### Tests

- Added focused unit coverage for Git state serialization, deployed diffs, plan drift, targeted and all-target workflows, Edge inheritance ordering, partial failures, push preflights, and MCP wrappers.
- Added 107-file response-size regression coverage plus blocking-worker, polling, failure, and per-server job serialization tests.
- Added SDK 0.11 wrapper regressions, copy-plan drift-gate coverage, and live plan/execute/validate/cleanup testing against two local Cribl 4.19.2 leaders.
- Ran 58 safe MCP tool calls across both local leaders plus a temporary empty-Pack install/list/get/delete cleanup workflow.

## [0.3.0] - 2026-05-22

### Added

- Added cross-leader resource copy and validation tools for groups, sources, destinations, pipelines, routes, breakers, lookups, and variables.
- Added consolidated config-object tooling with bounded summaries, cursor-based follow-up reads, optional full payloads, dependency references, and semantic cross-leader validation.
- Added on-prem credential resolution through the local macOS user, macOS Keychain, and per-server environment-variable fallbacks, including configurable `keychain_name` support.
- Added Cribl Pack management tools for listing, inspecting, installing, uploading, updating, and deleting Packs, including distributed group/fleet scoping.
- Expanded `get_pack` into a bounded Pack inspection surface with drill-down support for sources, destinations, pipelines, routes, knowledge categories, and settings categories.
- Added variable discovery, local-user synchronization, full worker-group/fleet replication and validation, and global system-settings replication and validation tools.
- Added local Cribl SDK, API authentication, Cribl product, and FastMCP documentation references for future implementation work.

### Changed

- Refactored pipeline collection to use SDK methods and updated the related test surface.
- Updated the FastMCP integration for 3.x compatibility and constrained the dependency below FastMCP 4.
- Updated the Cribl Control Plane SDK dependency and improved collector/source handling, counted-list response handling, and product-error filtering.
- Improved cross-leader sync behavior for target group resolution, lookup content hydration, no-op update skipping, and environment-identity-aware semantic comparison.
- Reworked repository documentation and examples around local API specs, SDK usage, and agent development guidance.

### Security

- Hardened token caching with secure credential fingerprinting and clearer expired-cache-token failures.
- Improved validation-error redaction for sensitive field names and values.
- Documented the cleartext transport risk for local-user password sync against `http://` on-prem leaders.

### Tests

- Expanded unit coverage across config loading, token management, client security setup, variables, Packs, resource actions, semantic diffing, user sync, group sync, system settings, validation errors, and workflow tool wrappers.

## [0.2.0] - 2026-01-01

### Added

- Now supports both on-prem and cloud authentication using OAuth.
- Added support for multiple leaders. Configure the list of leaders in config.toml and specify the name in the prompt.

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
