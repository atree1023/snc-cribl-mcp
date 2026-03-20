"""Shared helpers for sync and validation MCP tools."""

from __future__ import annotations

from typing import Literal

from cribl_control_plane.models.productscore import ProductsCore

type ProductName = Literal["edge", "stream"]


def parse_product(product: ProductName) -> ProductsCore:
    """Convert a tool-friendly product value into the SDK enum."""
    return ProductsCore.STREAM if product == "stream" else ProductsCore.EDGE


__all__ = [
    "ProductName",
    "parse_product",
]
