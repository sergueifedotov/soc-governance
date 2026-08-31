"""MCP prompts handlers: prompt templates for workflows."""

from typing import Any, Dict

from wazuh_mcp_server.mcp.session import MCPSession


async def handle_prompts_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle prompts/list method per MCP specification.
    Returns available prompt templates.
    """
    prompts = [
        {
            "name": "security_investigation",
            "description": "Security incident investigation workflow",
            "arguments": [
                {
                    "name": "incident_type",
                    "description": "Type of incident to investigate",
                    "required": False,
                },
                {
                    "name": "time_range",
                    "description": "Time range for investigation (e.g., 24h, 7d)",
                    "required": False,
                },
            ],
        },
        {
            "name": "threat_hunt",
            "description": "Proactive threat hunting workflow",
            "arguments": [
                {
                    "name": "hunt_hypothesis",
                    "description": "Hypothesis to test during hunting",
                    "required": False,
                },
                {
                    "name": "agent_scope",
                    "description": "Scope of agents to hunt (all, critical, specific)",
                    "required": False,
                },
            ],
        },
        {
            "name": "compliance_audit",
            "description": "Compliance audit workflow",
            "arguments": [
                {
                    "name": "framework",
                    "description": "Compliance framework (PCI-DSS, HIPAA, SOX, GDPR, NIST)",
                    "required": False,
                },
                {
                    "name": "include_remediation",
                    "description": "Include remediation steps in audit",
                    "required": False,
                },
            ],
        },
        {
            "name": "vulnerability_assessment",
            "description": "Vulnerability assessment workflow",
            "arguments": [
                {
                    "name": "severity_threshold",
                    "description": "Minimum severity level to include",
                    "required": False,
                },
                {
                    "name": "agent_id",
                    "description": "Specific agent to assess (or 'all')",
                    "required": False,
                },
            ],
        },
    ]

    return {"prompts": prompts}


async def handle_prompts_get(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle prompts/get method per MCP specification.
    Returns prompt content with substituted arguments.
    """
    name = params.get("name")
    arguments = params.get("arguments", {})

    if not name:
        raise ValueError("Prompt name is required")

    # Prompt templates
    prompt_templates = {
        "security_investigation": {
            "description": "Security incident investigation workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Investigate a {arguments.get('incident_type', 'security')} incident. "
                        f"Time range: {arguments.get('time_range', '24h')}. "
                        f"Steps:\n"
                        f"1. Use get_wazuh_alerts to retrieve relevant alerts\n"
                        f"2. Use analyze_alert_patterns to identify patterns\n"
                        f"3. Use search_security_events to find related events\n"
                        f"4. Use check_agent_health for affected agents\n"
                        f"5. Use perform_risk_assessment to evaluate impact",
                    },
                }
            ],
        },
        "threat_hunt": {
            "description": "Proactive threat hunting workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Hunt for threats based on hypothesis: {arguments.get('hunt_hypothesis', 'suspicious activity')}. "
                        f"Agent scope: {arguments.get('agent_scope', 'all')}. "
                        f"Workflow:\n"
                        f"1. Use get_wazuh_agents to identify target agents\n"
                        f"2. Use search_security_events with relevant patterns\n"
                        f"3. Use analyze_security_threat for any indicators found\n"
                        f"4. Use check_ioc_reputation for suspicious IPs/domains\n"
                        f"5. Use generate_security_report to document findings",
                    },
                }
            ],
        },
        "compliance_audit": {
            "description": "Compliance audit workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Perform {arguments.get('framework', 'PCI-DSS')} compliance audit. "
                        f"Include remediation: {arguments.get('include_remediation', 'true')}. "
                        f"Steps:\n"
                        f"1. Use run_compliance_check with the specified framework\n"
                        f"2. Use get_wazuh_agents to assess agent coverage\n"
                        f"3. Use get_wazuh_vulnerabilities to identify security gaps\n"
                        f"4. Use generate_security_report for compliance documentation",
                    },
                }
            ],
        },
        "vulnerability_assessment": {
            "description": "Vulnerability assessment workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Assess vulnerabilities with severity >= {arguments.get('severity_threshold', 'medium')}. "
                        f"Agent: {arguments.get('agent_id', 'all')}. "
                        f"Workflow:\n"
                        f"1. Use get_wazuh_vulnerabilities to retrieve vulnerability data\n"
                        f"2. Use get_wazuh_critical_vulnerabilities for highest priority items\n"
                        f"3. Use get_wazuh_vulnerability_summary for statistics\n"
                        f"4. Use perform_risk_assessment to evaluate overall risk",
                    },
                }
            ],
        },
    }

    if name not in prompt_templates:
        raise ValueError(f"Unknown prompt: {name}")

    return prompt_templates[name]
