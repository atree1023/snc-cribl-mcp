"""Tools package for MCP server.

Contains MCP tool registration modules:
- ``list_groups``: Enumerate worker groups and Edge fleets
- ``list_sources``: Enumerate configured sources per group
- ``list_destinations``: Enumerate configured destinations per group
- ``list_pipelines``: Enumerate configured pipelines per group
- ``list_routes``: Enumerate configured routes per group
- ``list_breakers``: Enumerate configured event breakers per group
- ``list_lookups``: Enumerate configured lookups per group
- ``list_variables``: Enumerate configured variables per group
- ``sync_user``: Create or replicate local users
- ``group_sync``: Replicate and validate whole groups/fleets
- ``system_settings``: Replicate and validate global system settings
- ``packs``: Manage installed Packs
- ``common``: Shared utilities for tool registration
"""
