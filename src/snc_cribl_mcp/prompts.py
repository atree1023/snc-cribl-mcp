"""MCP prompts for Cribl operations.

Exposes common Cribl workflows as prompts.
"""

# pyright: reportUnusedFunction=false

from fastmcp import FastMCP


def register(app: FastMCP) -> None:
    """Register prompts on the provided app instance."""

    @app.prompt(
        name="Summarize Cribl Configuration",
        description="Create a prompt to summarize the current Cribl configuration.",
        tags={"summary", "config"},
    )
    def summarize_config() -> str:
        return (
            "Please summarize the current Cribl configuration. "
            "List the worker groups, sources, destinations, and pipelines. "
            "Highlight any potential issues or misconfigurations."
        )

    @app.prompt(
        name="Find Broken Sources",
        description="Create a prompt to find broken sources.",
        tags={"troubleshooting", "sources"},
    )
    def find_broken_sources() -> str:
        return (
            "Please check all configured sources and identify any that are reporting errors "
            "or have not received data recently. Use the list_sources tool to get the data."
        )

    @app.prompt(
        name="Analyze Pipeline",
        description="Analyze a specific pipeline for best practices and potential issues.",
        tags={"analysis", "pipelines"},
    )
    def analyze_pipeline(pipeline_id: str, group_id: str = "default") -> str:
        return (
            f"Please analyze the pipeline '{pipeline_id}' in group '{group_id}'. "
            "Check for inefficient functions, potential data loss, and best practices. "
            "Use the list_pipelines tool to get the pipeline configuration."
        )

    @app.prompt(
        name="Troubleshoot Destination",
        description="Help troubleshoot issues with a specific destination.",
        tags={"troubleshooting", "destinations"},
    )
    def troubleshoot_destination(destination_id: str, error_message: str = "") -> str:
        prompt = f"I am experiencing issues with destination '{destination_id}'."
        if error_message:
            prompt += f" The error message is: '{error_message}'."
        prompt += (
            " Please help me troubleshoot this issue. "
            "Check the destination configuration using list_destinations and suggest potential fixes."
        )
        return prompt


__all__ = ["register"]
