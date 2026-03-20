"""Client package for Cribl MCP server.

Provides HTTP client setup and token management for the Cribl Control Plane API:
- ``cribl_client``: Async context manager factory for configured SDK clients and
  resolved single-/dual-server connection helpers
- ``token_manager``: Bearer token lifecycle management with automatic refresh
"""
