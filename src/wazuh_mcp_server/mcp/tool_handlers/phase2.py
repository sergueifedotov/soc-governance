"""Phase 2 SOC orchestration tool handlers."""

import json
from typing import Any, Dict, List, Optional

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.phase2 import (
    build_phase2_alert_triage,
    build_phase2_context_enrichment,
    build_phase2_ioc_pivot,
    build_phase2_mitre_attack_mapping,
    build_phase2_proxy_adaptive_masking_recommendations,
    build_phase2_proxy_policy_recommendations,
    build_phase2_soc_report,
)
from wazuh_mcp_server.security import (
    ToolValidationError,
    validate_agent_id,
    validate_boolean,
    validate_ip_address,
    validate_limit,
    validate_query,
    validate_rule_id,
    validate_time_range,
)


def _render_analyst_handoff_markdown(result: Dict[str, Any]) -> str:
    """Render a concise analyst handoff section for Phase 2 tool output."""
    data = result.get("data", {}) if isinstance(result, dict) else {}
    workflow = str(data.get("workflow", "unknown"))
    analysis = str(data.get("analysis", "")).strip()

    next_steps = data.get("recommended_next_steps")
    if not isinstance(next_steps, list):
        next_steps = data.get("recommendations") if isinstance(data.get("recommendations"), list) else []

    escalation = data.get("escalation_draft", {}) if isinstance(data.get("escalation_draft"), dict) else {}
    incident_handoff = str(escalation.get("incident_handoff", "")).strip()
    soc_note = str(escalation.get("soc_note", "")).strip()

    lines = [
        "## Analyst Handoff",
        f"- Workflow: {workflow}",
    ]
    if analysis:
        lines.append("- Summary: " + analysis)
    if incident_handoff:
        lines.append("- Incident Handoff: " + incident_handoff)
    if soc_note:
        lines.append("- SOC Note: " + soc_note)

    if next_steps:
        lines.append("- Recommended Next Steps:")
        for step in next_steps[:5]:
            lines.append(f"  - {step}")

    return "\n".join(lines)


async def execute_phase2_tool(tool_name: str, arguments: Dict[str, Any], wazuh_client: WazuhClient) -> Optional[str]:
    """Execute a Phase 2 tool and return formatted output text when matched."""
    if tool_name == "triage_wazuh_alerts":
        time_range = validate_time_range(arguments.get("time_range"))
        min_level = validate_limit(arguments.get("min_level"), min_val=1, max_val=15, default=10, param_name="min_level")
        limit = validate_limit(arguments.get("limit"), min_val=1, max_val=200, default=50, param_name="limit")
        include_agent_health = validate_boolean(
            arguments.get("include_agent_health"), default=True, param_name="include_agent_health"
        )

        result = await build_phase2_alert_triage(
            wazuh_client,
            time_range=time_range,
            min_level=min_level,
            limit=limit,
            include_agent_health=include_agent_health,
        )
        return (
            "Phase 2 Alert Triage:\n"
            f"{_render_analyst_handoff_markdown(result)}\n\n"
            "### Raw JSON\n"
            f"{json.dumps(result, indent=2, default=str)}"
        )

    if tool_name == "enrich_wazuh_context":
        time_range = validate_time_range(arguments.get("time_range"))
        limit = validate_limit(arguments.get("limit"), min_val=1, max_val=100, default=20, param_name="limit")
        query = arguments.get("query")
        if query is not None:
            query = validate_query(query, required=False)
        rule_id = validate_rule_id(arguments.get("rule_id"))
        agent_id = validate_agent_id(arguments.get("agent_id"))
        srcip = validate_ip_address(arguments.get("srcip"), param_name="srcip")

        result = await build_phase2_context_enrichment(
            wazuh_client,
            time_range=time_range,
            limit=limit,
            query=query,
            rule_id=rule_id,
            agent_id=agent_id,
            srcip=srcip,
        )
        return (
            "Phase 2 Context Enrichment:\n"
            f"{_render_analyst_handoff_markdown(result)}\n\n"
            "### Raw JSON\n"
            f"{json.dumps(result, indent=2, default=str)}"
        )

    if tool_name == "generate_soc_handoff_report":
        report_type = arguments.get("report_type", "shift")
        valid_report_types = {"shift", "daily", "incident"}
        if report_type not in valid_report_types:
            raise ToolValidationError(
                "report_type",
                f"invalid value '{report_type}'",
                f"Must be one of: {', '.join(sorted(valid_report_types))}",
            )
        time_range = validate_time_range(arguments.get("time_range"))
        include_recommendations = validate_boolean(
            arguments.get("include_recommendations"), default=True, param_name="include_recommendations"
        )

        result = await build_phase2_soc_report(
            wazuh_client,
            report_type=report_type,
            time_range=time_range,
            include_recommendations=include_recommendations,
        )
        return (
            "SOC Handoff Report:\n"
            f"{_render_analyst_handoff_markdown(result)}\n\n"
            "### Raw JSON\n"
            f"{json.dumps(result, indent=2, default=str)}"
        )

    if tool_name == "generate_proxy_policy_recommendations":
        time_range = validate_time_range(arguments.get("time_range"))
        limit = validate_limit(arguments.get("limit"), min_val=10, max_val=500, default=100, param_name="limit")
        run_llm = validate_boolean(arguments.get("run_llm"), default=True, param_name="run_llm")

        focus = str(arguments.get("focus") or "all").strip().lower() or "all"
        if focus not in {"all", "overblocking", "underblocking"}:
            raise ToolValidationError(
                "focus",
                f"invalid value '{focus}'",
                "Must be one of: all, overblocking, underblocking",
            )

        recommendation_types = arguments.get("recommendation_types")
        if not isinstance(recommendation_types, list):
            recommendation_types = ["masking", "discovery"]
        recommendation_types = [str(item).strip().lower() for item in recommendation_types if isinstance(item, str)]
        if not recommendation_types:
            recommendation_types = ["masking", "discovery"]
        recommendation_types = [item for item in recommendation_types if item in {"masking", "discovery"}]
        if not recommendation_types:
            raise ToolValidationError(
                "recommendation_types",
                "must include at least one valid recommendation type",
                "Use one or both of: masking, discovery",
            )

        proxy_summary = arguments.get("proxy_summary") if isinstance(arguments.get("proxy_summary"), dict) else {}
        proxy_root_cause = arguments.get("proxy_root_cause") if isinstance(arguments.get("proxy_root_cause"), dict) else {}
        proxy_denied_events = (
            arguments.get("proxy_denied_events") if isinstance(arguments.get("proxy_denied_events"), list) else []
        )

        result = await build_phase2_proxy_policy_recommendations(
            wazuh_client,
            time_range=time_range,
            focus=focus,
            recommendation_types=recommendation_types,
            limit=limit,
            run_llm=run_llm,
            proxy_summary=proxy_summary,
            proxy_root_cause=proxy_root_cause,
            proxy_denied_events=proxy_denied_events,
        )
        return (
            "Proxy Policy Recommendations:\n"
            f"{_render_analyst_handoff_markdown(result)}\n\n"
            "### Raw JSON\n"
            f"{json.dumps(result, indent=2, default=str)}"
        )

    if tool_name == "generate_proxy_adaptive_masking_recommendations":
        time_range = validate_time_range(arguments.get("time_range"))
        limit = validate_limit(arguments.get("limit"), min_val=1, max_val=500, default=100, param_name="limit")
        run_llm = validate_boolean(arguments.get("run_llm"), default=True, param_name="run_llm")

        mode = str(arguments.get("mode") or "monitor").strip().lower() or "monitor"
        if mode not in {"monitor", "review"}:
            raise ToolValidationError(
                "mode",
                f"invalid value '{mode}'",
                "Must be one of: monitor, review",
            )

        raw_tool_filter = arguments.get("tool_filter")
        tool_filter: List[str] = []
        if isinstance(raw_tool_filter, list):
            tool_filter = [str(item).strip() for item in raw_tool_filter if isinstance(item, str) and str(item).strip()]
        elif isinstance(raw_tool_filter, str) and raw_tool_filter.strip():
            tool_filter = [raw_tool_filter.strip()]

        proxy_summary = arguments.get("proxy_summary") if isinstance(arguments.get("proxy_summary"), dict) else {}
        proxy_root_cause = arguments.get("proxy_root_cause") if isinstance(arguments.get("proxy_root_cause"), dict) else {}
        proxy_denied_events = (
            arguments.get("proxy_denied_events") if isinstance(arguments.get("proxy_denied_events"), list) else []
        )

        result = await build_phase2_proxy_adaptive_masking_recommendations(
            wazuh_client,
            time_range=time_range,
            mode=mode,
            limit=limit,
            run_llm=run_llm,
            tool_filter=tool_filter,
            proxy_summary=proxy_summary,
            proxy_root_cause=proxy_root_cause,
            proxy_denied_events=proxy_denied_events,
        )
        return (
            "Proxy Adaptive Masking Recommendations:\n"
            f"{_render_analyst_handoff_markdown(result)}\n\n"
            "### Raw JSON\n"
            f"{json.dumps(result, indent=2, default=str)}"
        )

    if tool_name == "map_alerts_to_mitre_attack":
        time_range = validate_time_range(arguments.get("time_range"))
        min_level = validate_limit(arguments.get("min_level"), min_val=1, max_val=15, default=7, param_name="min_level")
        limit = validate_limit(arguments.get("limit"), min_val=1, max_val=100, default=20, param_name="limit")

        query = arguments.get("query")
        if query is not None:
            query = validate_query(query, required=False)
        rule_id = validate_rule_id(arguments.get("rule_id"))
        agent_id = validate_agent_id(arguments.get("agent_id"))
        srcip = validate_ip_address(arguments.get("srcip"), param_name="srcip")
        include_llm = validate_boolean(arguments.get("include_llm"), default=True, param_name="include_llm")

        result = await build_phase2_mitre_attack_mapping(
            wazuh_client,
            time_range=time_range,
            min_level=min_level,
            limit=limit,
            query=query,
            rule_id=rule_id,
            agent_id=agent_id,
            srcip=srcip,
            include_llm=include_llm,
        )
        return (
            "MITRE ATT&CK Mapping:\n"
            f"{_render_analyst_handoff_markdown(result)}\n\n"
            "### Raw JSON\n"
            f"{json.dumps(result, indent=2, default=str)}"
        )

    if tool_name == "ioc_pivot":
        ioc_value = arguments.get("ioc_value")
        if not isinstance(ioc_value, str) or not ioc_value.strip():
            raise ToolValidationError(
                "ioc_value",
                "missing or empty value",
                "Provide a non-empty IOC value (IP, domain, hash, or username).",
            )
        ioc_value = ioc_value.strip()
        ioc_type = arguments.get("ioc_type") or "auto"
        if ioc_type not in {"auto", "ip", "domain", "hash", "user"}:
            raise ToolValidationError(
                "ioc_type",
                f"invalid value '{ioc_type}'",
                "Must be one of: auto, ip, domain, hash, user.",
            )
        time_range = validate_time_range(arguments.get("time_range"))
        min_level = validate_limit(arguments.get("min_level"), min_val=1, max_val=15, default=5, param_name="min_level")
        limit = validate_limit(arguments.get("limit"), min_val=1, max_val=100, default=30, param_name="limit")
        max_hops = validate_limit(arguments.get("max_hops"), min_val=1, max_val=6, default=5, param_name="max_hops")
        include_opencti = validate_boolean(arguments.get("include_opencti"), default=True, param_name="include_opencti")
        include_neo4j = validate_boolean(arguments.get("include_neo4j"), default=True, param_name="include_neo4j")
        include_llm = validate_boolean(arguments.get("include_llm"), default=True, param_name="include_llm")

        result = await build_phase2_ioc_pivot(
            wazuh_client,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            time_range=time_range,
            min_level=min_level,
            limit=limit,
            max_hops=max_hops,
            include_opencti=include_opencti,
            include_neo4j=include_neo4j,
            include_llm=include_llm,
        )
        return (
            "IOC Pivot:\n"
            f"{_render_analyst_handoff_markdown(result)}\n\n"
            "### Raw JSON\n"
            f"{json.dumps(result, indent=2, default=str)}"
        )

    return None
