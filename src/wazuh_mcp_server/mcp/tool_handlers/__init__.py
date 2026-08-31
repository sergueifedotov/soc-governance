"""Tool handler modules used by MCP tool dispatch."""

from wazuh_mcp_server.mcp.tool_handlers.active_response import execute_active_response_tool
from wazuh_mcp_server.mcp.tool_handlers.agents import execute_agent_tool
from wazuh_mcp_server.mcp.tool_handlers.alerts import execute_alert_tool
from wazuh_mcp_server.mcp.tool_handlers.phase2 import execute_phase2_tool
from wazuh_mcp_server.mcp.tool_handlers.rollback import execute_rollback_tool
from wazuh_mcp_server.mcp.tool_handlers.security_analysis import execute_security_analysis_tool
from wazuh_mcp_server.mcp.tool_handlers.system import execute_system_tool
from wazuh_mcp_server.mcp.tool_handlers.verification import execute_verification_tool
from wazuh_mcp_server.mcp.tool_handlers.vulnerability import execute_vulnerability_tool

__all__ = [
    "execute_active_response_tool",
    "execute_agent_tool",
    "execute_alert_tool",
    "execute_phase2_tool",
    "execute_rollback_tool",
    "execute_security_analysis_tool",
    "execute_system_tool",
    "execute_verification_tool",
    "execute_vulnerability_tool",
]

