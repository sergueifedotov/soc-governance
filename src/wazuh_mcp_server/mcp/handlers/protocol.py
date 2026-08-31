"""MCP protocol handlers: lifecycle, health, and configuration."""

import logging
from collections import OrderedDict
from typing import Any, Dict

from wazuh_mcp_server import __version__
from wazuh_mcp_server.mcp.session import MCPSession
from wazuh_mcp_server.mcp.responses import MCP_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS

logger = logging.getLogger(__name__)

# Track initialized sessions (OrderedDict for O(1) eviction of oldest entries)
_initialized_sessions: OrderedDict[str, bool] = OrderedDict()

# Current log level for logging/setLevel
_current_log_level: str = "info"


async def handle_initialize(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle MCP initialize method per MCP specification."""
    client_protocol_version = params.get("protocolVersion", "2025-03-26")
    capabilities = params.get("capabilities", {})
    client_info = params.get("clientInfo", {})

    # Store client information
    session.capabilities = capabilities
    session.client_info = client_info

    # Protocol version negotiation per MCP spec
    # Server should respond with a version it supports
    if client_protocol_version in SUPPORTED_PROTOCOL_VERSIONS:
        negotiated_version = client_protocol_version
    else:
        # Default to latest supported version
        negotiated_version = MCP_PROTOCOL_VERSION

    # Server capabilities - only declare what we actually implement
    server_capabilities = {
        "logging": {},
        "prompts": {"listChanged": True},
        "resources": {"subscribe": False, "listChanged": True},  # Not fully implemented yet
        "tools": {"listChanged": True},
    }

    # Server information
    server_info = {
        "name": "Wazuh MCP Server",
        "version": __version__,
        "vendor": "GenSec AI",
        "description": "MCP-compliant remote server for Wazuh SIEM integration",
    }

    # Mark session as awaiting initialized notification (cap to prevent unbounded growth)
    if len(_initialized_sessions) > 10000:
        # Evict oldest entries in O(1) per removal
        for _ in range(len(_initialized_sessions) - 5000):
            _initialized_sessions.popitem(last=False)
    _initialized_sessions[session.session_id] = False

    return {
        "protocolVersion": negotiated_version,
        "capabilities": server_capabilities,
        "serverInfo": server_info,
        "instructions": "Connected to Wazuh MCP Server. Use available tools for security operations.",
    }


async def handle_initialized_notification(params: Dict[str, Any], session: MCPSession) -> None:
    """Handle notifications/initialized - marks session as fully initialized."""
    _initialized_sessions[session.session_id] = True
    logger.info(f"Session {session.session_id} fully initialized")


async def handle_ping(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle ping method - heartbeat/liveness check."""
    return {}


async def handle_logging_set_level(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle logging/setLevel method to adjust server log verbosity."""
    global _current_log_level

    level = params.get("level", "info").lower()
    valid_levels = ["debug", "info", "warning", "error", "critical"]

    if level not in valid_levels:
        raise ValueError(f"Invalid log level '{level}'. Valid levels: {', '.join(valid_levels)}")

    # Update all loggers
    _current_log_level = level
    numeric_level = getattr(logging, level.upper())
    logging.getLogger("wazuh_mcp_server").setLevel(numeric_level)
    logging.getLogger("wazuh_mcp_server.audit").setLevel(numeric_level)

    logger.info(f"Log level set to: {level}")
    return {}
