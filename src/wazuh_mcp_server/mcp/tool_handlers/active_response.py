"""Active response and action tool handlers."""

import json
from typing import Any, Dict, Optional

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.security import (
    validate_active_response_command,
    validate_agent_id,
    validate_file_path,
    validate_ip_address,
    validate_limit,
    validate_username,
)


async def execute_active_response_tool(
    tool_name: str, arguments: Dict[str, Any], wazuh_client: WazuhClient
) -> Optional[str]:
    """Execute an active-response/action tool and return formatted output text when matched."""
    if tool_name == "wazuh_block_ip":
        ip_address = validate_ip_address(arguments.get("ip_address"), required=True)
        assert ip_address is not None
        duration = (
            validate_limit(arguments.get("duration"), min_val=0, max_val=86400, param_name="duration")
            if arguments.get("duration") is not None
            else 0
        )
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        result = await wazuh_client.block_ip(ip_address, duration, agent_id)
        return f"Block IP Result:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_isolate_host":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        result = await wazuh_client.isolate_host(agent_id)
        return f"Isolate Host Result:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_kill_process":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        process_id = arguments.get("process_id")
        if process_id is None:
            raise ValueError("Parameter 'process_id' is required")
        process_id = validate_limit(process_id, min_val=1, max_val=999999, param_name="process_id")
        result = await wazuh_client.kill_process(agent_id, process_id)
        return f"Kill Process Result:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_disable_user":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        username = validate_username(arguments.get("username"), required=True)
        assert username is not None
        result = await wazuh_client.disable_user(agent_id, username)
        return f"Disable User Result:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_quarantine_file":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        file_path = validate_file_path(arguments.get("file_path"), required=True)
        assert file_path is not None
        result = await wazuh_client.quarantine_file(agent_id, file_path)
        return f"Quarantine File Result:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_active_response":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        command = validate_active_response_command(arguments.get("command"), required=True)
        assert command is not None
        raw_parameters = arguments.get("parameters")
        if raw_parameters is None:
            parameters: Dict[str, Any] = {}
        elif isinstance(raw_parameters, dict):
            parameters = raw_parameters
        else:
            raise ValueError("Parameter 'parameters' must be an object/dictionary when provided")
        result = await wazuh_client.run_active_response(agent_id, command, parameters)
        return f"Active Response Result:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_firewall_drop":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        src_ip = validate_ip_address(arguments.get("src_ip"), required=True, param_name="src_ip")
        assert src_ip is not None
        duration = (
            validate_limit(arguments.get("duration"), min_val=0, max_val=86400, param_name="duration")
            if arguments.get("duration") is not None
            else 0
        )
        result = await wazuh_client.firewall_drop(agent_id, src_ip, duration)
        return f"Firewall Drop Result:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_host_deny":
        agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
        assert agent_id is not None
        src_ip = validate_ip_address(arguments.get("src_ip"), required=True, param_name="src_ip")
        assert src_ip is not None
        result = await wazuh_client.host_deny(agent_id, src_ip)
        return f"Host Deny Result:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "wazuh_restart":
        target = arguments.get("target", "").strip()
        if not target:
            raise ValueError("Parameter 'target' is required. Use an agent ID or 'manager'.")
        if target != "manager":
            validate_agent_id(target, required=True, param_name="target")
        result = await wazuh_client.restart_service(target)
        return f"Restart Result:\n{json.dumps(result, indent=2, default=str)}"

    return None
