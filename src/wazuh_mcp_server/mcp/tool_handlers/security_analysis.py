"""Security analysis tool handlers."""

import json
from typing import Any, Dict, Optional

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.security import (
    validate_agent_id,
    validate_boolean,
    validate_compliance_framework,
    validate_indicator,
    validate_indicator_type,
    validate_limit,
    validate_report_type,
    validate_time_range,
)


async def execute_security_analysis_tool(
    tool_name: str, arguments: Dict[str, Any], wazuh_client: WazuhClient
) -> Optional[str]:
    """Execute a security-analysis tool and return formatted output text when matched."""
    if tool_name == "analyze_security_threat":
        indicator_type = validate_indicator_type(arguments.get("indicator_type"))
        indicator = validate_indicator(arguments.get("indicator"), indicator_type)

        result = await wazuh_client.analyze_security_threat(indicator, indicator_type)
        return f"Threat Analysis:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "check_ioc_reputation":
        indicator_type = validate_indicator_type(arguments.get("indicator_type"))
        indicator = validate_indicator(arguments.get("indicator"), indicator_type)

        result = await wazuh_client.check_ioc_reputation(indicator, indicator_type)
        return f"IoC Reputation:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "perform_risk_assessment":
        agent_id = validate_agent_id(arguments.get("agent_id"))
        result = await wazuh_client.perform_risk_assessment(agent_id)
        return f"Risk Assessment:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "get_top_security_threats":
        limit = validate_limit(arguments.get("limit"), min_val=1, max_val=50, default=10)
        time_range = validate_time_range(arguments.get("time_range"))

        result = await wazuh_client.get_top_security_threats(limit, time_range)
        return f"Top Security Threats:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "generate_security_report":
        report_type = validate_report_type(arguments.get("report_type"))
        include_recommendations = validate_boolean(
            arguments.get("include_recommendations"), default=True, param_name="include_recommendations"
        )

        result = await wazuh_client.generate_security_report(report_type, include_recommendations)
        return f"Security Report:\n{json.dumps(result, indent=2, default=str)}"

    if tool_name == "run_compliance_check":
        framework = validate_compliance_framework(arguments.get("framework"))
        agent_id = validate_agent_id(arguments.get("agent_id"))

        result = await wazuh_client.run_compliance_check(framework, agent_id)
        return f"Compliance Check:\n{json.dumps(result, indent=2, default=str)}"

    return None
