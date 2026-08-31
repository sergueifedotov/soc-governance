"""Agent management tool handlers."""

import json
from typing import Any, Dict, Optional

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.security import validate_agent_id, validate_agent_status, validate_limit


async def execute_agent_tool(tool_name: str, arguments: Dict[str, Any], wazuh_client: WazuhClient) -> Optional[str]:
    """Execute an agent-management tool and return formatted output text when matched."""
    if tool_name == "get_wazuh_agents":
        agent_id = validate_agent_id(arguments.get("agent_id"))
        status = validate_agent_status(arguments.get("status"))
        limit = validate_limit(arguments.get("limit"), max_val=1000)

        result = await wazuh_client.get_agents(agent_id=agent_id, status=status, limit=limit)
        return f"Wazuh Agents:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "get_wazuh_running_agents":
        result = await wazuh_client.get_running_agents()
        return f"Running Agents:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "check_agent_health":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        result = await wazuh_client.check_agent_health(agent_id)
        return f"Agent Health:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "get_agent_processes":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        limit = validate_limit(arguments.get("limit"), max_val=1000)
        result = await wazuh_client.get_agent_processes(agent_id, limit)
        return f"Agent Processes:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "get_agent_ports":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        limit = validate_limit(arguments.get("limit"), max_val=1000)
        result = await wazuh_client.get_agent_ports(agent_id, limit)
        return f"Agent Ports:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "get_agent_configuration":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        result = await wazuh_client.get_agent_configuration(agent_id)
        return f"Agent Configuration:\n{json.dumps(result, indent=2, default=str)}"

    return None
