"""Alert management tool handlers."""

import json
import re
from typing import Any, Callable, Dict, Optional

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.security import (
    ToolValidationError,
    validate_agent_id,
    validate_boolean,
    validate_ip_address,
    validate_limit,
    validate_query,
    validate_rule_id,
    validate_time_range,
    validate_timestamp,
)


async def execute_alert_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    wazuh_client: WazuhClient,
    compact_alerts_result: Callable[[Dict[str, Any]], Dict[str, Any]],
    add_truncation_warning: Callable[[Dict[str, Any], int], Dict[str, Any]],
) -> Optional[str]:
    """Execute an alert-management tool and return formatted output text when matched."""
    if tool_name == "get_wazuh_alerts":
        limit = validate_limit(arguments.get("limit"), max_val=1000)
        rule_id = validate_rule_id(arguments.get("rule_id"))
        level = arguments.get("level")
        if level is not None:
            level = str(level).strip()
            if not re.match(r"^[0-9]{1,2}\+?$", level):
                raise ToolValidationError(
                    "level",
                    f"invalid format '{level}'",
                    "Use a number 0-15, optionally with '+' (e.g., '12', '10+')",
                )
        agent_id = validate_agent_id(arguments.get("agent_id"))
        timestamp_start = validate_timestamp(arguments.get("timestamp_start"), param_name="timestamp_start")
        timestamp_end = validate_timestamp(arguments.get("timestamp_end"), param_name="timestamp_end")
        compact = validate_boolean(arguments.get("compact"), default=True, param_name="compact")

        result = await wazuh_client.get_alerts(
            limit=limit,
            rule_id=rule_id,
            level=level,
            agent_id=agent_id,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
        )
        if compact:
            result = compact_alerts_result(result)
        result = add_truncation_warning(result, limit)
        return f"Wazuh Alerts:\n{json.dumps(result, indent=2 if not compact else None, default=str)}"

    if tool_name == "get_wazuh_alert_summary":
        time_range = validate_time_range(arguments.get("time_range"))
        group_by = arguments.get("group_by", "rule.level")
        valid_group_by = {"rule.level", "rule.id", "rule.groups", "agent.id", "agent.name"}
        if group_by not in valid_group_by:
            raise ToolValidationError(
                "group_by",
                f"invalid value '{group_by}'",
                f"Must be one of: {', '.join(sorted(valid_group_by))}",
            )
        result = await wazuh_client.get_alert_summary(time_range, group_by)
        return f"Alert Summary:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "analyze_alert_patterns":
        time_range = validate_time_range(arguments.get("time_range"))
        min_frequency = validate_limit(
            arguments.get("min_frequency"), min_val=1, max_val=1000, default=5, param_name="min_frequency"
        )
        result = await wazuh_client.analyze_alert_patterns(time_range, min_frequency)
        return f"Alert Patterns:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "search_security_events":
        query = validate_query(arguments.get("query"), required=True)
        time_range = validate_time_range(arguments.get("time_range"))
        limit = validate_limit(arguments.get("limit"), max_val=1000)
        compact = validate_boolean(arguments.get("compact"), default=True, param_name="compact")
        rule_id = validate_rule_id(arguments.get("rule_id"))
        agent_id = validate_agent_id(arguments.get("agent_id"))
        srcip = validate_ip_address(arguments.get("srcip"), param_name="srcip")
        dstip = validate_ip_address(arguments.get("dstip"), param_name="dstip")

        level_raw = arguments.get("level")
        level = None
        if level_raw is not None:
            level_str = str(level_raw).strip().rstrip("+")
            try:
                int(level_str)
                level = str(level_raw).strip()
            except (ValueError, TypeError):
                raise ToolValidationError(
                    "level", f"must be a numeric value, got '{level_raw}'", "Use a number like '10' or '12+'"
                )

        result = await wazuh_client.search_security_events(
            query,
            time_range,
            limit,
            rule_id=rule_id,
            agent_id=agent_id,
            level=level,
            srcip=srcip,
            dstip=dstip,
        )
        if compact:
            result = compact_alerts_result(result)
        result = add_truncation_warning(result, limit)
        return f"Security Events:\n{json.dumps(result, indent=2 if not compact else None, default=str)}"

    return None
