"""MCP request handlers package.

Modular organization of MCP protocol handlers:
- protocol.py: initialize, ping, logging, notifications
- prompts.py: prompt templates and retrieval
- resources.py: Wazuh resource listing and reading
- completion.py: argument completion suggestions
- tools.py: tool listing and execution dispatch
"""

from wazuh_mcp_server.mcp.handlers.completion import handle_completion_complete
from wazuh_mcp_server.mcp.handlers.prompts import handle_prompts_get, handle_prompts_list
from wazuh_mcp_server.mcp.handlers.protocol import (
    handle_initialized_notification,
    handle_initialize,
    handle_logging_set_level,
    handle_ping,
)
from wazuh_mcp_server.mcp.handlers.resources import (
    handle_resources_list,
    handle_resources_read,
    handle_resources_templates_list,
    set_wazuh_client as set_wazuh_client_resources,
)
from wazuh_mcp_server.mcp.handlers.tools import (
    handle_tools_call,
    handle_tools_list,
    set_wazuh_client as set_wazuh_client_tools,
)

__all__ = [
    # Protocol
    "handle_initialize",
    "handle_initialized_notification",
    "handle_ping",
    "handle_logging_set_level",
    # Prompts
    "handle_prompts_list",
    "handle_prompts_get",
    # Resources
    "handle_resources_list",
    "handle_resources_read",
    "handle_resources_templates_list",
    "set_wazuh_client_resources",
    # Completion
    "handle_completion_complete",
    # Tools
    "handle_tools_list",
    "handle_tools_call",
    "set_wazuh_client_tools",
]
