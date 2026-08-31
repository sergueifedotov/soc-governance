"""Rollback tool handlers."""

import json
from typing import Any, Dict, Optional

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.security import validate_agent_id, validate_file_path, validate_ip_address, validate_username


async def execute_rollback_tool(tool_name: str, arguments: Dict[str, Any], wazuh_client: WazuhClient) -> Optional[str]:
    """Execute a rollback tool and return formatted output text when matched."""
    if tool_name == "wazuh_unisolate_host":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        result = await wazuh_client.unisolate_host(agent_id)
        return f"Unisolate Host Result:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_enable_user":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        username = validate_username(arguments.get("username"), required=True)
        assert username is not None
        result = await wazuh_client.enable_user(agent_id, username)
        return f"Enable User Result:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_restore_file":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        file_path = validate_file_path(arguments.get("file_path"), required=True)
        assert file_path is not None
        result = await wazuh_client.restore_file(agent_id, file_path)
        return f"Restore File Result:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_firewall_allow":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        src_ip = validate_ip_address(arguments.get("src_ip"), required=True, param_name="src_ip")
        assert src_ip is not None
        result = await wazuh_client.firewall_allow(agent_id, src_ip)
        return f"Firewall Allow Result:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_host_allow":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        src_ip = validate_ip_address(arguments.get("src_ip"), required=True, param_name="src_ip")
        assert src_ip is not None
        result = await wazuh_client.host_allow(agent_id, src_ip)
        return f"Host Allow Result:\n{json.dumps(result, indent=2, default=str)}"

    return None
