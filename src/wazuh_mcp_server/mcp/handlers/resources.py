"""MCP resources handlers: reading Wazuh data as resources."""

import json
import logging
from typing import Any, Dict

from wazuh_mcp_server.mcp.session import MCPSession

logger = logging.getLogger(__name__)

# wazuh_client will be injected at runtime from server.py
_wazuh_client = None


def set_wazuh_client(client):
    """Inject WazuhClient dependency."""
    global _wazuh_client
    _wazuh_client = client


async def handle_resources_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle resources/list method per MCP specification.
    Returns list of available resources with pagination support.
    """
    _cursor = params.get("cursor")  # Reserved for future pagination

    # Wazuh resources
    resources = [
        {
            "uri": "wazuh://manager/info",
            "name": "Wazuh Manager Information",
            "description": "Current Wazuh manager status and configuration",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://agents/summary",
            "name": "Agents Summary",
            "description": "Summary of all Wazuh agents and their status",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://alerts/recent",
            "name": "Recent Alerts",
            "description": "Most recent security alerts from Wazuh",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://cluster/status",
            "name": "Cluster Status",
            "description": "Wazuh cluster health and node information",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://rules/summary",
            "name": "Rules Summary",
            "description": "Summary of active Wazuh detection rules",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://vulnerabilities/critical",
            "name": "Critical Vulnerabilities",
            "description": "Critical vulnerabilities from Wazuh Indexer (requires 4.8.0+)",
            "mimeType": "application/json",
        },
    ]

    return {"resources": resources}


async def handle_resources_read(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle resources/read method per MCP specification.
    Returns resource content.
    """
    uri = params.get("uri")

    if not uri:
        raise ValueError("Resource URI is required")

    # Parse Wazuh resource URI
    if not uri.startswith("wazuh://"):
        raise ValueError(f"Invalid resource URI scheme: {uri}. Expected wazuh://")

    resource_path = uri[8:]  # Remove "wazuh://"

    if _wazuh_client is None:
        raise RuntimeError("Wazuh client not initialized")

    try:
        if resource_path == "manager/info":
            data = await _wazuh_client.get_manager_info()
        elif resource_path == "agents/summary":
            data = await _wazuh_client.get_running_agents()
        elif resource_path == "alerts/recent":
            data = await _wazuh_client.get_alerts(limit=50)
        elif resource_path == "cluster/status":
            data = await _wazuh_client.get_cluster_health()
        elif resource_path == "rules/summary":
            data = await _wazuh_client.get_rules_summary()
        elif resource_path == "vulnerabilities/critical":
            data = await _wazuh_client.get_critical_vulnerabilities(limit=50)
        else:
            raise ValueError(f"Resource not found: {uri}")

        return {"contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps(data, indent=2, default=str)}]}

    except Exception as e:
        logger.error(f"Error reading resource {uri}: {e}")
        raise ValueError(f"Failed to read resource: {str(e)}")


async def handle_resources_templates_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle resources/templates/list method per MCP specification.
    Returns list of resource URI templates.
    """
    templates = [
        {
            "uriTemplate": "wazuh://agents/{agent_id}/info",
            "name": "Agent Information",
            "description": "Detailed information for a specific agent",
            "mimeType": "application/json",
        },
        {
            "uriTemplate": "wazuh://agents/{agent_id}/alerts",
            "name": "Agent Alerts",
            "description": "Recent alerts for a specific agent",
            "mimeType": "application/json",
        },
        {
            "uriTemplate": "wazuh://agents/{agent_id}/vulnerabilities",
            "name": "Agent Vulnerabilities",
            "description": "Vulnerabilities for a specific agent",
            "mimeType": "application/json",
        },
    ]

    return {"resourceTemplates": templates}
