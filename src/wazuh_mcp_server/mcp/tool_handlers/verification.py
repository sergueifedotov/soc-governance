"""Verification tool handlers."""

import json
from typing import Any, Dict, Optional

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.security import validate_agent_id, validate_file_path, validate_ip_address, validate_limit, validate_username


async def execute_verification_tool(tool_name: str, arguments: Dict[str, Any], wazuh_client: WazuhClient) -> Optional[str]:
    """Execute a verification tool and return formatted output text when matched."""
    if tool_name == "wazuh_check_blocked_ip":
        ip_address = validate_ip_address(arguments.get("ip_address"), required=True)
        agent_id = validate_agent_id(arguments.get("agent_id"))
        result = await wazuh_client.check_blocked_ip(ip_address, agent_id)
        return f"Blocked IP Check:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_check_agent_isolation":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        result = await wazuh_client.check_agent_isolation(agent_id)
        return f"Agent Isolation Check:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_check_process":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        process_id = arguments.get("process_id")
        if process_id is None:
            raise ValueError("Parameter 'process_id' is required")
        process_id = validate_limit(process_id, min_val=1, max_val=999999, param_name="process_id")
        result = await wazuh_client.check_process(agent_id, process_id)
        return f"Process Check:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_check_user_status":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        username = validate_username(arguments.get("username"), required=True)
        result = await wazuh_client.check_user_status(agent_id, username)
        return f"User Status Check:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_check_file_quarantine":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        file_path = validate_file_path(arguments.get("file_path"), required=True)
        result = await wazuh_client.check_file_quarantine(agent_id, file_path)
        return f"File Quarantine Check:\n{json.dumps(result, indent=2, default=str)}"

    return None
