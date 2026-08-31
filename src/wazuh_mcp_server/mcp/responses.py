"""MCP response creation and protocol validation utilities."""

import logging
from typing import Any, Optional, Union

from fastapi import HTTPException

from wazuh_mcp_server.mcp.models import MCPError, MCPResponse

logger = logging.getLogger(__name__)

# MCP Protocol Version Support
MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]

# MCP Error Codes per specification
MCP_ERROR_CODES = {
    "PARSE_ERROR": -32700,
    "INVALID_REQUEST": -32600,
    "METHOD_NOT_FOUND": -32601,
    "INVALID_PARAMS": -32602,
    "INTERNAL_ERROR": -32603,
    "SERVER_ERROR_START": -32099,
    "SERVER_ERROR_END": -32000,
    "TOOL_USE_RESULT_UNKNOWN_TOOL": -32001,
    "TOOL_USE_RESULT_PROCESSING_ERROR": -32002,
    "RESOURCE_NOT_FOUND": -32003,
}


def create_error_response(
    request_id: Optional[Union[str, int]], code: int, message: str, data: Any = None
) -> MCPResponse:
    """Create MCP error response with correlation ID for tracing."""
    from wazuh_mcp_server.monitoring import get_correlation_id

    # Include correlation ID in error data for request tracing
    error_data = data if data else {}
    if isinstance(error_data, dict):
        error_data = {**error_data, "correlation_id": get_correlation_id()}
    elif data is None:
        error_data = {"correlation_id": get_correlation_id()}
    error = MCPError(code=code, message=message, data=error_data)
    return MCPResponse(id=request_id, error=error.dict())


def create_success_response(request_id: Optional[Union[str, int]], result: Any) -> MCPResponse:
    """Create MCP success response."""
    return MCPResponse(id=request_id, result=result)


def validate_protocol_version(version: Optional[str], strict: bool = False) -> str:
    """
    Validate and normalize MCP protocol version.

    Per MCP 2025-11-25 spec:
    - If no header provided, assume 2025-03-26 for backwards compatibility
    - If invalid/unsupported version, MUST return 400 Bad Request (when strict=True)

    Args:
        version: The protocol version from MCP-Protocol-Version header
        strict: If True, raise HTTPException for invalid versions (2025-11-25 behavior)

    Returns:
        The validated protocol version string
    """
    if not version:
        # Per spec: assume 2025-03-26 if no header provided (backwards compatibility)
        return "2025-03-26"

    if version in SUPPORTED_PROTOCOL_VERSIONS:
        return version

    # Per 2025-11-25 spec: "If the server receives a request with an invalid or
    # unsupported MCP-Protocol-Version, it MUST respond with 400 Bad Request"
    if strict:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported protocol version: {version}. Supported versions: {', '.join(SUPPORTED_PROTOCOL_VERSIONS)}",
        )

    # For backwards compatibility (non-strict mode), try to handle gracefully
    logger.warning(f"Unsupported protocol version {version}, falling back to 2025-03-26")
    return "2025-03-26"
