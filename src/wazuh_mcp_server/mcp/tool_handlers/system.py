"""System monitoring tool handlers."""

import json
from typing import Any, Dict, Optional

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.security import validate_limit, validate_query


async def execute_system_tool(tool_name: str, arguments: Dict[str, Any], wazuh_client: WazuhClient) -> Optional[str]:
    """Execute a system monitoring tool and return formatted output text when matched."""
    if tool_name == "get_wazuh_statistics":
        result = await wazuh_client.get_wazuh_statistics()
        return f"Wazuh Statistics:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "get_wazuh_weekly_stats":
        result = await wazuh_client.get_weekly_stats()
        return f"Weekly Statistics:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "get_wazuh_cluster_health":
        result = await wazuh_client.get_cluster_health()
        return f"Cluster Health:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "get_wazuh_cluster_nodes":
        result = await wazuh_client.get_cluster_nodes()
        return f"Cluster Nodes:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "get_wazuh_rules_summary":
        result = await wazuh_client.get_rules_summary()
        return f"Rules Summary:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "get_wazuh_remoted_stats":
        result = await wazuh_client.get_remoted_stats()
        return f"Remoted Statistics:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "get_wazuh_log_collector_stats":
        result = await wazuh_client.get_log_collector_stats()
        return f"Log Collector Statistics:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "search_wazuh_manager_logs":
        query = validate_query(arguments.get("query"), required=True)
        limit = validate_limit(arguments.get("limit"), max_val=1000)
        result = await wazuh_client.search_manager_logs(query, limit)
        return f"Manager Logs:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "get_wazuh_manager_error_logs":
        limit = validate_limit(arguments.get("limit"), max_val=1000)
        result = await wazuh_client.get_manager_error_logs(limit)
        return f"Manager Error Logs:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "validate_wazuh_connection":
        result = await wazuh_client.validate_connection()
        return f"Connection Validation:\n{json.dumps(result, indent=2, default=str)}"

    return None
