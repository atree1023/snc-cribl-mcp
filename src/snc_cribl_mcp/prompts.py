"""MCP prompts for Cribl operations.

Exposes common Cribl workflows as prompts.
"""

# pyright: reportUnusedFunction=false

from fastmcp import FastMCP
from fastmcp.prompts import Message


def register(app: FastMCP) -> None:
    """Register prompts on the provided app instance."""

    @app.prompt(
        name="Summarize Cribl Configuration",
        description="Create a prompt to summarize the current Cribl configuration.",
        tags={"summary", "config"},
    )
    def summarize_config() -> list[Message]:
        return [
            Message(
                "Please summarize the current Cribl configuration. "
                "List the worker groups, sources, destinations, and pipelines. "
                "Highlight any potential issues or misconfigurations."
            )
        ]

    @app.prompt(
        name="Find Broken Sources",
        description="Create a prompt to find broken sources.",
        tags={"troubleshooting", "sources"},
    )
    def find_broken_sources() -> list[Message]:
        return [
            Message(
                "Please find sources that are unhealthy, reporting errors, or have not received data recently. "
                "Judge this from each source's current runtime health, not only its configuration, "
                "and group the results by worker group or fleet."
            )
        ]

    @app.prompt(
        name="Analyze Pipeline",
        description="Analyze a specific pipeline for best practices and potential issues.",
        tags={"analysis", "pipelines"},
    )
    def analyze_pipeline(pipeline_id: str, group_id: str = "default") -> list[Message]:
        return [
            Message(
                f"Please analyze the pipeline '{pipeline_id}' in group '{group_id}'. "
                "Check for inefficient functions, potential data loss, and best practices."
            )
        ]

    @app.prompt(
        name="Troubleshoot Destination",
        description="Help troubleshoot issues with a specific destination.",
        tags={"troubleshooting", "destinations"},
    )
    def troubleshoot_destination(destination_id: str, error_message: str = "") -> list[Message]:
        prompt = f"I am experiencing issues with destination '{destination_id}'."
        if error_message:
            prompt += f" The error message is: '{error_message}'."
        prompt += (
            " Please help me troubleshoot this issue: check the destination's current runtime health "
            "and its configuration, then suggest potential fixes."
        )
        return [Message(prompt)]


__all__ = ["register"]
