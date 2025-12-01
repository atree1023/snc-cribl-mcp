"""Utilities for handling SDK validation errors gracefully.

The cribl-control-plane SDK uses Pydantic for response validation. When the
API returns data that doesn't match the SDK's expected schema (due to schema
drift or incomplete type definitions), a ResponseValidationError is raised.

This module provides utilities to extract meaningful error details from these
validation errors and present them to users in a clear, actionable format.
"""

import json
import logging
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

# Type alias for JSON-compatible values
type JsonValue = dict[str, Any] | list[Any] | str | int | float | bool | None

# Maximum length for JSON values in error messages
MAX_JSON_VALUE_LENGTH = 500

logger = logging.getLogger("snc_cribl_mcp.operations.validation_errors")


class SDKValidationError(Exception):
    """Exception raised when SDK response validation fails.

    This exception wraps the formatted error response that should be returned
    to the user instead of partial results.

    Attributes:
        error_response: The formatted error response dictionary.

    """

    def __init__(self, error_response: dict[str, Any]) -> None:
        """Initialize with the formatted error response.

        Args:
            error_response: The formatted error response dictionary to return to user.

        """
        self.error_response = error_response
        super().__init__(error_response.get("message", "SDK validation failed"))


@dataclass(frozen=True, slots=True)
class ParsedErrorLocation:
    """Parsed location information from a Pydantic validation error.

    Attributes:
        object_index: The index of the object in the items list (0-based).
        object_type_field: The type-specific field name (e.g., "tcpjson", "syslog").
        field_path: List of field names forming the path to the error.
        raw_location: The original location tuple from Pydantic.

    """

    object_index: int | None
    object_type_field: str | None
    field_path: list[str]
    raw_location: tuple[str | int, ...]


@dataclass(frozen=True, slots=True)
class ValidationErrorDetails:
    """Parsed details from a Pydantic validation error.

    Attributes:
        object_index: The index of the object in the items list that failed validation.
        object_type: The inferred type of the object (e.g., "tcpjson", "syslog").
        field_path: The path to the field that caused the error.
        error_type: The Pydantic error type (e.g., "missing", "string_type").
        error_message: The human-readable error message.
        input_value: The actual input value that caused the error.
        raw_location: The original location tuple from Pydantic.

    """

    object_index: int | None
    object_type: str | None
    field_path: str
    error_type: str
    error_message: str
    input_value: Any
    raw_location: tuple[str | int, ...]


def _parse_error_location(loc: tuple[str | int, ...]) -> ParsedErrorLocation:
    """Parse a Pydantic error location into structured components.

    The SDK generates locations like: ("body", "items", 6, "tcpjson", "connections", 0, "output")

    Args:
        loc: The location tuple from a Pydantic validation error.

    Returns:
        Parsed location with object index, type field, and remaining path.

    """
    loc_list = list(loc)
    object_index: int | None = None
    object_type_field: str | None = None
    field_path: list[str] = []

    i = 0
    # Skip "body" prefix if present
    if i < len(loc_list) and loc_list[i] == "body":
        i += 1

    # Look for "items" followed by an index
    if i < len(loc_list) and loc_list[i] == "items":
        i += 1
        if i < len(loc_list):
            next_val = loc_list[i]
            if isinstance(next_val, int):
                object_index = next_val
                i += 1

    # Next string is typically the type-specific field (e.g., "tcpjson")
    if i < len(loc_list) and isinstance(loc_list[i], str):
        object_type_field = str(loc_list[i])
        i += 1

    # Remaining parts form the field path
    while i < len(loc_list):
        field_path.append(str(loc_list[i]))
        i += 1

    return ParsedErrorLocation(
        object_index=object_index,
        object_type_field=object_type_field,
        field_path=field_path,
        raw_location=loc,
    )


def _extract_object_info(body: str | None, index: int) -> tuple[str | None, str | None]:
    """Extract object ID and type from the response body.

    Args:
        body: The raw JSON response body.
        index: The index of the object in the items array.

    Returns:
        Tuple of (object_id, object_type) or (None, None) if not found.

    """
    if not body:
        return None, None

    try:
        data = json.loads(body)
        items = data.get("items", [])
        if 0 <= index < len(items):
            item = items[index]
            obj_id = item.get("id") or item.get("name") or item.get("_id")
            obj_type = item.get("type")
            return str(obj_id) if obj_id else None, str(obj_type) if obj_type else None
    except (json.JSONDecodeError, KeyError, TypeError, IndexError):
        pass

    return None, None


def _extract_field_value(
    body: str | None,
    index: int,
    type_field: str | None,
    field_path: list[str],
) -> JsonValue:
    """Extract the actual field value from the response body.

    Args:
        body: The raw JSON response body.
        index: The index of the object in the items array.
        type_field: The type-specific field name (e.g., "tcpjson").
        field_path: The path to the field within the type-specific object.

    Returns:
        The field value or None if not found.

    """
    if not body:
        return None

    try:
        data = json.loads(body)
        items: list[dict[str, Any]] = data.get("items", [])
        if not (0 <= index < len(items)):
            return None

        item = items[index]

        # Navigate to type-specific field first
        current: JsonValue = item.get(type_field) if type_field and type_field in item else item

        # Navigate the field path, stopping one level before the error field
        path_to_navigate = field_path[:-1] if field_path else []
        for part in path_to_navigate:
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list):
                idx = int(part)  # May raise ValueError
                current = current[idx] if 0 <= idx < len(current) else None
            else:
                current = None
            if current is None:
                break
    except (json.JSONDecodeError, KeyError, TypeError, IndexError, ValueError):
        return None
    else:
        return current


def _format_json_value(value: JsonValue, max_length: int = MAX_JSON_VALUE_LENGTH) -> str:
    """Format a value as JSON with truncation for large values.

    Args:
        value: The value to format.
        max_length: Maximum length for the formatted string.

    Returns:
        JSON-formatted string, truncated if necessary.

    """
    try:
        formatted = json.dumps(value, indent=2)
    except (TypeError, ValueError):
        return str(value)[:max_length]
    else:
        if len(formatted) > max_length:
            return formatted[: max_length - 3] + "..."
        return formatted


@dataclass(frozen=True, slots=True)
class ErrorMessageContext:
    """Context for building a user-friendly error message.

    Attributes:
        resource_type: The type of resource (e.g., "sources").
        group_id: The group ID.
        object_id: The ID of the object with the error.
        object_type: The type of the object (e.g., "tcpjson").
        type_field: The type-specific field name from the error path.
        field_path: The remaining field path after the type field.
        error_msg: The Pydantic error message.
        error_type: The Pydantic error type.

    """

    resource_type: str
    group_id: str
    object_id: str | None
    object_type: str | None
    type_field: str | None
    field_path: list[str]
    error_msg: str
    error_type: str


def _build_user_friendly_message(ctx: ErrorMessageContext) -> str:
    """Build a user-friendly error message.

    Args:
        ctx: Context containing all parameters for building the message.

    Returns:
        A user-friendly error message string.

    """
    # Build object description
    singular_resource = ctx.resource_type.rstrip("s")
    obj_desc = f'"{ctx.object_id}"' if ctx.object_id else f"a {singular_resource}"
    if ctx.object_type:
        obj_desc = (
            f'{ctx.object_type} {singular_resource} "{ctx.object_id}"'
            if ctx.object_id
            else f"a {ctx.object_type} {singular_resource}"
        )

    # Build field description - focus on the parent containing the error
    if ctx.field_path:
        # The last element is the missing field, we want to describe the parent
        parent_path = ctx.field_path[:-1] if len(ctx.field_path) > 1 else ctx.field_path
        missing_field = ctx.field_path[-1] if ctx.field_path else "unknown"
        field_desc = ".".join(parent_path) if parent_path else ctx.type_field or "configuration"
    else:
        field_desc = ctx.type_field or "configuration"
        missing_field = "unknown"

    # Determine error description based on type
    if ctx.error_type == "missing":
        error_desc = f'the "{field_desc}" field is missing the required "{missing_field}" property'
    elif "type" in ctx.error_type:
        error_desc = f'the "{field_desc}" field has an invalid type'
    else:
        error_desc = f'the "{field_desc}" field is inconsistent with the SDK specification'

    return f'Validation error in {ctx.group_id} group {obj_desc}: {error_desc}. SDK error: "{ctx.error_msg}"'


def parse_validation_error(validation_error: ValidationError) -> list[ValidationErrorDetails]:
    """Parse a Pydantic ValidationError into structured details.

    Args:
        validation_error: The Pydantic ValidationError to parse.

    Returns:
        List of ValidationErrorDetails for each error in the validation failure.

    """
    details: list[ValidationErrorDetails] = []

    for error in validation_error.errors():
        loc = tuple(error.get("loc", ()))
        msg = error.get("msg", "Unknown error")
        error_type = error.get("type", "unknown")
        input_value = error.get("input", None)

        # Parse location to extract object index and type
        parsed = _parse_error_location(loc)

        # Build field path string including type field
        field_path_str = ".".join(parsed.field_path) if parsed.field_path else ""
        if parsed.object_type_field and field_path_str:
            field_path_str = f"{parsed.object_type_field}.{field_path_str}"
        elif parsed.object_type_field:
            field_path_str = parsed.object_type_field

        details.append(
            ValidationErrorDetails(
                object_index=parsed.object_index,
                object_type=parsed.object_type_field,
                field_path=field_path_str,
                error_type=error_type,
                error_message=msg,
                input_value=input_value,
                raw_location=loc,
            )
        )

    return details


def format_validation_error_response(
    *,
    resource_type: str,
    product: str,
    group_id: str,
    body: str | None,
    validation_errors: list[ValidationErrorDetails],
) -> dict[str, Any]:
    """Format validation errors into a user-friendly response.

    Args:
        resource_type: The type of resource being fetched (e.g., "sources").
        product: The product name (e.g., "stream", "edge").
        group_id: The group ID where the error occurred.
        body: The raw response body for extracting object details.
        validation_errors: List of parsed validation error details.

    Returns:
        A dictionary with the error response.

    """
    error_details: list[dict[str, Any]] = []
    primary_message: str | None = None

    for error in validation_errors:
        # Parse the error location
        loc = _parse_error_location(error.raw_location)

        # Extract object info from body
        object_id: str | None = None
        object_type: str | None = None
        if loc.object_index is not None:
            object_id, object_type = _extract_object_info(body, loc.object_index)

        # Extract the actual field value that caused the error
        field_value: JsonValue = None
        if loc.object_index is not None:
            field_value = _extract_field_value(body, loc.object_index, loc.object_type_field, loc.field_path)

        # Build user-friendly message
        msg_ctx = ErrorMessageContext(
            resource_type=resource_type,
            group_id=group_id,
            object_id=object_id,
            object_type=object_type,
            type_field=loc.object_type_field,
            field_path=loc.field_path,
            error_msg=error.error_message,
            error_type=error.error_type,
        )
        user_message = _build_user_friendly_message(msg_ctx)

        if primary_message is None:
            primary_message = user_message

        # Build detailed error entry
        error_entry: dict[str, Any] = {
            "message": user_message,
            "object_id": object_id,
            "object_type": object_type,
            "field": error.field_path,
        }

        if field_value is not None:
            error_entry["actual_value"] = _format_json_value(field_value)
            error_entry["help"] = (
                "The value shown above was returned by the Cribl API but does not match "
                "the SDK's expected schema. Check the Cribl UI to ensure this configuration "
                "is complete and valid."
            )

        error_details.append(error_entry)

    return {
        "status": "validation_error",
        "message": primary_message or (f"The Cribl API returned {resource_type} data that the SDK could not validate."),
        "product": product,
        "group_id": group_id,
        "resource_type": resource_type,
        "errors": error_details,
        "resolution": (
            "This error occurs when the Cribl API returns data that doesn't match the SDK's "
            "expected format. Common causes include: incomplete configuration (missing required "
            "fields), SDK version mismatch, or Cribl features not yet supported by the SDK. "
            "Review the affected object in the Cribl UI and ensure all required fields are populated."
        ),
    }


__all__ = [
    "SDKValidationError",
    "ValidationErrorDetails",
    "format_validation_error_response",
    "parse_validation_error",
]
