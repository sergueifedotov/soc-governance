"""MCP completion handlers: argument completion and suggestions."""

from typing import Any, Dict

from wazuh_mcp_server.mcp.session import MCPSession


async def handle_completion_complete(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle completion/complete method per MCP specification.
    Returns argument completion suggestions.
    """
    ref = params.get("ref", {})
    argument = params.get("argument", {})

    ref_type = ref.get("type")
    ref_name = ref.get("name")
    arg_name = argument.get("name", "")
    arg_value = argument.get("value", "")

    completions = []

    # Provide completions based on context
    if ref_type == "ref/prompt":
        if arg_name == "incident_type":
            completions = ["malware", "intrusion", "data_breach", "ransomware", "phishing", "insider_threat"]
        elif arg_name == "time_range":
            completions = ["1h", "6h", "24h", "7d", "30d"]
        elif arg_name == "framework":
            completions = ["PCI-DSS", "HIPAA", "SOX", "GDPR", "NIST"]
        elif arg_name == "severity_threshold":
            completions = ["low", "medium", "high", "critical"]
        elif arg_name == "agent_scope":
            completions = ["all", "critical", "specific"]

    elif ref_type == "ref/resource":
        if "agent" in ref_name.lower():
            # Could fetch actual agent IDs here
            completions = ["001", "002", "003", "004", "005"]

    # Filter by current value
    if arg_value:
        completions = [c for c in completions if c.lower().startswith(arg_value.lower())]

    return {
        "completion": {
            "values": completions[:100],  # Max 100 per spec
            "total": len(completions),
            "hasMore": len(completions) > 100,
        }
    }
