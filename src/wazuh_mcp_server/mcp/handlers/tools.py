"""MCP tools handlers: tool listing and execution dispatch."""

import json
import logging
import time
from typing import Any, Dict

from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError
from wazuh_mcp_server.mcp.formatting import add_truncation_warning, compact_alerts_result, compact_vulns_result
from wazuh_mcp_server.mcp.session import MCPSession
from wazuh_mcp_server.mcp.tool_handlers import (
    execute_active_response_tool,
    execute_agent_tool,
    execute_alert_tool,
    execute_phase2_tool,
    execute_rollback_tool,
    execute_security_analysis_tool,
    execute_system_tool,
    execute_verification_tool,
    execute_vulnerability_tool,
)
from wazuh_mcp_server.monitoring import record_tool_execution
from wazuh_mcp_server.security import ToolValidationError, validate_input

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("wazuh_mcp_server.audit")

# Tool scope mapping: tools requiring write access (active response, rollback, restart)
# All other tools only require wazuh:read
WRITE_SCOPE_TOOLS = frozenset({
    "wazuh_block_ip",
    "wazuh_isolate_host",
    "wazuh_kill_process",
    "wazuh_disable_user",
    "wazuh_quarantine_file",
    "wazuh_active_response",
    "wazuh_firewall_drop",
    "wazuh_host_deny",
    "wazuh_restart",
    "wazuh_unisolate_host",
    "wazuh_enable_user",
    "wazuh_restore_file",
    "wazuh_firewall_allow",
    "wazuh_host_allow",
})

# WazuhClient will be injected at runtime from server.py
_wazuh_client = None


def set_wazuh_client(client):
    """Inject WazuhClient dependency."""
    global _wazuh_client
    _wazuh_client = client


def _get_tool_scope(tool_name: str) -> str:
    """Get the required scope for a tool."""
    return "wazuh:write" if tool_name in WRITE_SCOPE_TOOLS else "wazuh:read"


async def handle_tools_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle tools/list method - All Wazuh Security Tools with pagination.
    Filters tools based on session token scopes."""
    _cursor = params.get("cursor")  # Reserved for future pagination
    tools = [
        # Alert Management Tools (4 tools)
        {
            "name": "get_wazuh_alerts",
            "description": "Retrieve Wazuh security alerts with optional filtering",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                    "rule_id": {"type": "string", "description": "Filter by specific rule ID"},
                    "level": {"type": "string", "description": "Filter by alert level (e.g., '12', '10+')"},
                    "agent_id": {"type": "string", "description": "Filter by agent ID"},
                    "timestamp_start": {"type": "string", "description": "Start timestamp (ISO format)"},
                    "timestamp_end": {"type": "string", "description": "End timestamp (ISO format)"},
                    "compact": {
                        "type": "boolean",
                        "default": True,
                        "description": "Return compact alerts with essential fields only (recommended to avoid token limits)",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "get_wazuh_alert_summary",
            "description": "Get a summary of Wazuh alerts grouped by specified field",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {"type": "string", "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"], "default": "24h"},
                    "group_by": {"type": "string", "default": "rule.level"},
                },
                "required": [],
            },
        },
        {
            "name": "analyze_alert_patterns",
            "description": "Analyze alert patterns to identify trends and anomalies",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {"type": "string", "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"], "default": "24h"},
                    "min_frequency": {"type": "integer", "minimum": 1, "default": 5},
                },
                "required": [],
            },
        },
        {
            "name": "search_security_events",
            "description": "Search for specific security events across all Wazuh data. Supports free-text search (Lucene syntax: AND, OR, NOT, field:value, wildcards, quoted phrases) and structured field filters. All filters are combined with AND logic.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Free-text search query (Lucene syntax: AND, OR, NOT, field:value, wildcards, quoted phrases). Searched across all alert fields via Elasticsearch query_string."},
                    "time_range": {"type": "string", "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"], "default": "24h"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                    "rule_id": {"type": "string", "description": "Filter by Wazuh rule ID (e.g., '5710', '100002')"},
                    "agent_id": {"type": "string", "description": "Filter by Wazuh agent ID (e.g., '001', '1234')"},
                    "level": {"type": "string", "description": "Minimum rule severity level (e.g., '10' for level >= 10, '12+' for level >= 12)"},
                    "srcip": {"type": "string", "description": "Filter by source IP address (data.srcip)"},
                    "dstip": {"type": "string", "description": "Filter by destination IP address (data.dstip)"},
                    "compact": {
                        "type": "boolean",
                        "default": True,
                        "description": "Return compact events with essential fields only (recommended to avoid token limits)",
                    },
                },
                "required": ["query"],
            },
        },
        # Agent Management Tools (6 tools)
        {
            "name": "get_wazuh_agents",
            "description": "Retrieve information about Wazuh agents",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Specific agent ID to query"},
                    "status": {
                        "type": "string",
                        "enum": ["active", "disconnected", "never_connected", "pending"],
                        "description": "Filter by agent status",
                    },
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                },
                "required": [],
            },
        },
        {
            "name": "get_wazuh_running_agents",
            "description": "Get list of currently running/active Wazuh agents",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "check_agent_health",
            "description": "Check the health status of a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID of the agent to check"}},
                "required": ["agent_id"],
            },
        },
        {
            "name": "get_agent_processes",
            "description": "Get running processes from a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                },
                "required": ["agent_id"],
            },
        },
        {
            "name": "get_agent_ports",
            "description": "Get open ports from a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                },
                "required": ["agent_id"],
            },
        },
        {
            "name": "get_agent_configuration",
            "description": "Get configuration details for a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID of the agent"}},
                "required": ["agent_id"],
            },
        },
        # Vulnerability Management Tools (3 tools) - Requires Wazuh Indexer (4.8.0+)
        {
            "name": "get_wazuh_vulnerabilities",
            "description": "Retrieve vulnerability information from Wazuh Indexer (requires WAZUH_INDEXER_HOST configuration)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Filter by specific agent ID"},
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Filter by severity level",
                    },
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
                    "compact": {
                        "type": "boolean",
                        "default": True,
                        "description": "Return compact vulnerabilities with essential fields only (recommended to avoid token limits)",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "get_wazuh_critical_vulnerabilities",
            "description": "Get critical vulnerabilities from Wazuh Indexer (requires WAZUH_INDEXER_HOST configuration)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                    "compact": {
                        "type": "boolean",
                        "default": True,
                        "description": "Return compact vulnerabilities with essential fields only (recommended to avoid token limits)",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "get_wazuh_vulnerability_summary",
            "description": "Get vulnerability summary statistics from Wazuh Indexer (requires WAZUH_INDEXER_HOST configuration)",
            "inputSchema": {
                "type": "object",
                "properties": {"time_range": {"type": "string", "enum": ["1d", "7d", "30d"], "default": "7d"}},
                "required": [],
            },
        },
        # Security Analysis Tools (6 tools)
        {
            "name": "analyze_security_threat",
            "description": "Analyze a security threat indicator using AI-powered analysis",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "indicator": {
                        "type": "string",
                        "description": "The threat indicator to analyze (IP, hash, domain)",
                    },
                    "indicator_type": {"type": "string", "enum": ["ip", "hash", "domain", "url"], "default": "ip"},
                },
                "required": ["indicator"],
            },
        },
        {
            "name": "check_ioc_reputation",
            "description": "Check reputation of an Indicator of Compromise (IoC)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "indicator": {"type": "string", "description": "The IoC to check (IP, domain, hash, etc.)"},
                    "indicator_type": {"type": "string", "enum": ["ip", "domain", "hash", "url"], "default": "ip"},
                },
                "required": ["indicator"],
            },
        },
        {
            "name": "perform_risk_assessment",
            "description": "Perform comprehensive risk assessment for agents or the entire environment",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Specific agent ID to assess (if None, assess entire environment)",
                    }
                },
                "required": [],
            },
        },
        {
            "name": "get_top_security_threats",
            "description": "Get top security threats based on alert frequency and severity",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
                    "time_range": {"type": "string", "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"], "default": "24h"},
                },
                "required": [],
            },
        },
        {
            "name": "generate_security_report",
            "description": "Generate comprehensive security report",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "report_type": {
                        "type": "string",
                        "enum": ["daily", "weekly", "monthly", "incident"],
                        "default": "daily",
                    },
                    "include_recommendations": {"type": "boolean", "default": True},
                },
                "required": [],
            },
        },
        {
            "name": "run_compliance_check",
            "description": "Run compliance check against security frameworks",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "enum": ["PCI-DSS", "HIPAA", "SOX", "GDPR", "NIST"],
                        "default": "PCI-DSS",
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Specific agent ID to check (if None, check entire environment)",
                    },
                },
                "required": [],
            },
        },
        # System Monitoring Tools (10 tools)
        {
            "name": "get_wazuh_statistics",
            "description": "Get comprehensive Wazuh statistics and metrics",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_weekly_stats",
            "description": "Get weekly statistics from Wazuh including alerts, agents, and trends",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_cluster_health",
            "description": "Get Wazuh cluster health information",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_cluster_nodes",
            "description": "Get information about Wazuh cluster nodes",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_rules_summary",
            "description": "Get summary of Wazuh rules and their effectiveness",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_remoted_stats",
            "description": "Get Wazuh remoted (agent communication) statistics",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_log_collector_stats",
            "description": "Get Wazuh log collector statistics",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "search_wazuh_manager_logs",
            "description": "Search Wazuh manager logs for specific patterns",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query/pattern"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                },
                "required": ["query"],
            },
        },
        {
            "name": "get_wazuh_manager_error_logs",
            "description": "Get recent error logs from Wazuh manager",
            "inputSchema": {
                "type": "object",
                "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}},
                "required": [],
            },
        },
        {
            "name": "validate_wazuh_connection",
            "description": "Validate connection to Wazuh server and return status",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        # Phase 2 SOC Orchestration Tools (6 tools)
        {
            "name": "triage_wazuh_alerts",
            "description": "Phase 2 read-only workflow that triages recent alerts into analyst-ready priorities, top rules, top agents, and notable source IPs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {"type": "string", "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"], "default": "24h"},
                    "min_level": {"type": "integer", "minimum": 1, "maximum": 15, "default": 10},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
                    "include_agent_health": {"type": "boolean", "default": True},
                },
                "required": [],
            },
        },
        {
            "name": "enrich_wazuh_context",
            "description": "Phase 2 read-only workflow that enriches an investigation with matching alerts, patterns, agent health, vulnerabilities, and indicator context.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {"type": "string", "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"], "default": "24h"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
                    "query": {"type": "string", "description": "Free-text security event query for enrichment"},
                    "rule_id": {"type": "string", "description": "Wazuh rule ID to pivot on"},
                    "agent_id": {"type": "string", "description": "Agent ID to enrich"},
                    "srcip": {"type": "string", "description": "Source IP address to investigate"},
                },
                "required": [],
            },
        },
        {
            "name": "generate_soc_handoff_report",
            "description": "Phase 2 read-only workflow that assembles a shift or daily SOC handoff report from connection status, health, threats, and vulnerabilities.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "report_type": {"type": "string", "enum": ["shift", "daily", "incident"], "default": "shift"},
                    "time_range": {"type": "string", "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"], "default": "12h"},
                    "include_recommendations": {"type": "boolean", "default": True},
                },
                "required": [],
            },
        },
        {
            "name": "map_alerts_to_mitre_attack",
            "description": "Phase 2 read-only workflow that maps alert context to MITRE ATT&CK techniques with confidence and rationale. Uses deterministic mapping and optional LangChain refinement.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {"type": "string", "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"], "default": "24h"},
                    "min_level": {"type": "integer", "minimum": 1, "maximum": 15, "default": 7},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
                    "query": {"type": "string", "description": "Optional Lucene query to select alerts for ATT&CK mapping"},
                    "rule_id": {"type": "string", "description": "Optional Wazuh rule ID filter"},
                    "agent_id": {"type": "string", "description": "Optional agent ID filter"},
                    "srcip": {"type": "string", "description": "Optional source IP filter"},
                    "include_llm": {"type": "boolean", "default": True, "description": "Enable LangChain structured refinement when PHASE2_LLM_* is configured"},
                },
                "required": [],
            },
        },
        {
            "name": "generate_proxy_policy_recommendations",
            "description": "Phase 2 read-only workflow that generates structured policy-tuning recommendations from proxy denied-call telemetry for masking and discovery rule tuning.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {"type": "string", "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"], "default": "24h"},
                    "limit": {"type": "integer", "minimum": 10, "maximum": 500, "default": 100},
                    "focus": {"type": "string", "enum": ["all", "overblocking", "underblocking"], "default": "all"},
                    "run_llm": {"type": "boolean", "default": True, "description": "Compatibility flag for callers; current engine is deterministic and proxy-specific."},
                    "recommendation_types": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["masking", "discovery"]},
                        "default": ["masking", "discovery"],
                    },
                    "proxy_summary": {"type": "object", "description": "Proxy summary object with deny counts and top denied tools."},
                    "proxy_root_cause": {"type": "object", "description": "Derived root-cause hints from denied calls."},
                    "proxy_denied_events": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Optional sampled denied events for context enrichment.",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "generate_proxy_adaptive_masking_recommendations",
            "description": "Phase 2 read-only workflow that generates adaptive masking recommendations (redact/hash/tokenize) from proxy denied-call telemetry.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {"type": "string", "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"], "default": "24h"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
                    "mode": {"type": "string", "enum": ["monitor", "review"], "default": "monitor"},
                    "run_llm": {"type": "boolean", "default": True, "description": "Compatibility flag for callers; current engine is deterministic and proxy-specific."},
                    "tool_filter": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of tool names to scope recommendations.",
                    },
                    "proxy_summary": {"type": "object", "description": "Proxy summary object with deny counts and top denied tools."},
                    "proxy_root_cause": {"type": "object", "description": "Derived root-cause hints from denied calls."},
                    "proxy_denied_events": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Optional sampled denied events for context enrichment.",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "ioc_pivot",
            "description": "Phase 2 read-only IOC pivot engine. Pulls evidence for an IOC (IP, domain, hash, or user) from Wazuh, OpenCTI, and Neo4j, then optionally synthesizes a verdict and recommended actions via LangChain. Falls back deterministically when the LLM is unavailable.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ioc_value": {"type": "string", "description": "IOC value to pivot on (IP, domain, hash, or username)"},
                    "ioc_type": {"type": "string", "enum": ["auto", "ip", "domain", "hash", "user"], "default": "auto"},
                    "time_range": {"type": "string", "enum": ["1h", "6h", "12h", "1d", "24h", "7d", "30d"], "default": "24h"},
                    "min_level": {"type": "integer", "minimum": 1, "maximum": 15, "default": 5},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 30},
                    "max_hops": {"type": "integer", "minimum": 1, "maximum": 6, "default": 5},
                    "include_opencti": {"type": "boolean", "default": True, "description": "Query OpenCTI for matching observables/indicators"},
                    "include_neo4j": {"type": "boolean", "default": True, "description": "Query Neo4j for graph context (attack chain, IP context, etc.)"},
                    "include_llm": {"type": "boolean", "default": True, "description": "Enable LangChain synthesis when PHASE2_LLM_* is configured"},
                },
                "required": ["ioc_value"],
            },
        },
        # Active Response / Action Tools (9 tools)
        {
            "name": "wazuh_block_ip",
            "description": "[ACTION] Block an IP address via Wazuh active response firewall-drop. Risk: LOW, Reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "IP address to block"},
                    "duration": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Block duration in seconds (0 = permanent)",
                    },
                    "agent_id": {"type": "string", "description": "Target agent ID (empty = all agents)"},
                },
                "required": ["ip_address"],
            },
        },
        {
            "name": "wazuh_isolate_host",
            "description": "[ACTION] Isolate a host from the network via active response. Risk: MEDIUM, Reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID of the agent to isolate"}},
                "required": ["agent_id"],
            },
        },
        {
            "name": "wazuh_kill_process",
            "description": "[ACTION] Terminate a process on an agent via active response. Risk: MEDIUM, Not reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "process_id": {"type": "integer", "description": "PID of the process to kill"},
                },
                "required": ["agent_id", "process_id"],
            },
        },
        {
            "name": "wazuh_disable_user",
            "description": "[ACTION] Disable a user account on an agent via active response. Risk: HIGH, Reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "username": {"type": "string", "description": "Username to disable"},
                },
                "required": ["agent_id", "username"],
            },
        },
        {
            "name": "wazuh_quarantine_file",
            "description": "[ACTION] Quarantine a file on an agent via active response. Risk: LOW, Reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "file_path": {"type": "string", "description": "Path of the file to quarantine"},
                },
                "required": ["agent_id", "file_path"],
            },
        },
        {
            "name": "wazuh_active_response",
            "description": "[ACTION] Execute a generic Wazuh active response command. Risk: HIGH, Not reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "command": {"type": "string", "description": "Active response command name"},
                    "parameters": {"type": "object", "description": "Optional command parameters"},
                },
                "required": ["agent_id", "command"],
            },
        },
        {
            "name": "wazuh_firewall_drop",
            "description": "[ACTION] Add a firewall drop rule on an agent via active response. Risk: MEDIUM, Reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "src_ip": {"type": "string", "description": "Source IP address to drop"},
                    "duration": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Duration in seconds (0 = permanent)",
                    },
                },
                "required": ["agent_id", "src_ip"],
            },
        },
        {
            "name": "wazuh_host_deny",
            "description": "[ACTION] Add an entry to hosts.deny on an agent via active response. Risk: MEDIUM, Reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "src_ip": {"type": "string", "description": "Source IP address to deny"},
                },
                "required": ["agent_id", "src_ip"],
            },
        },
        {
            "name": "wazuh_restart",
            "description": "[ACTION] Restart Wazuh agent or manager service. Risk: CRITICAL, Not reversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Agent ID or 'manager' to restart",
                    }
                },
                "required": ["target"],
            },
        },
        # Verification Tools (5 tools)
        {
            "name": "wazuh_check_blocked_ip",
            "description": "Check if an IP was blocked by searching active response alert history (not live firewall state)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "IP address to check"},
                    "agent_id": {"type": "string", "description": "Filter by agent ID (optional)"},
                },
                "required": ["ip_address"],
            },
        },
        {
            "name": "wazuh_check_agent_isolation",
            "description": "Check agent isolation status via connectivity and active response alert history (not live network state)",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID of the agent to check"}},
                "required": ["agent_id"],
            },
        },
        {
            "name": "wazuh_check_process",
            "description": "Check if a specific process is running on an agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "process_id": {"type": "integer", "description": "PID to check"},
                },
                "required": ["agent_id", "process_id"],
            },
        },
        {
            "name": "wazuh_check_user_status",
            "description": "Check if a user account was disabled by searching active response alert history (not live OS state)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "username": {"type": "string", "description": "Username to check"},
                },
                "required": ["agent_id", "username"],
            },
        },
        {
            "name": "wazuh_check_file_quarantine",
            "description": "Check if a file has been quarantined on an agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "file_path": {"type": "string", "description": "Path of the file to check"},
                },
                "required": ["agent_id", "file_path"],
            },
        },
        # Rollback Tools (5 tools)
        {
            "name": "wazuh_unisolate_host",
            "description": "[ACTION] Remove host network isolation. Risk: MEDIUM, Reversal of isolate_host.",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID of the agent to unisolate"}},
                "required": ["agent_id"],
            },
        },
        {
            "name": "wazuh_enable_user",
            "description": "[ACTION] Re-enable a disabled user account. Risk: HIGH, Reversal of disable_user.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "username": {"type": "string", "description": "Username to re-enable"},
                },
                "required": ["agent_id", "username"],
            },
        },
        {
            "name": "wazuh_restore_file",
            "description": "[ACTION] Restore a quarantined file. Risk: LOW, Reversal of quarantine_file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "file_path": {"type": "string", "description": "Path of the file to restore"},
                },
                "required": ["agent_id", "file_path"],
            },
        },
        {
            "name": "wazuh_firewall_allow",
            "description": "[ACTION] Remove a firewall drop rule. Risk: MEDIUM, Reversal of firewall_drop.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "src_ip": {"type": "string", "description": "Source IP to unblock"},
                },
                "required": ["agent_id", "src_ip"],
            },
        },
        {
            "name": "wazuh_host_allow",
            "description": "[ACTION] Remove a hosts.deny entry. Risk: MEDIUM, Reversal of host_deny.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "src_ip": {"type": "string", "description": "Source IP to allow"},
                },
                "required": ["agent_id", "src_ip"],
            },
        },
        # OpenCTI Integration Tools (6 tools: 2 write + 4 read)
        {
            "name": "opencti_sync_alerts",
            "description": (
                "Bulk sync recent Wazuh alerts to OpenCTI as STIX 2.1 bundles and "
                "write them into the Neo4j forensic graph. "
                "Requires OPENCTI_URL, OPENCTI_API_TOKEN, and WAZUH_INDEXER_HOST env vars."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hours":      {"type": "integer", "minimum": 1, "maximum": 720,  "default": 24,  "description": "Hours back to look for alerts"},
                    "min_level": {"type": "integer", "minimum": 1, "maximum": 15,   "default": 5,   "description": "Minimum Wazuh rule level to include"},
                    "batch_size":{"type": "integer", "minimum": 1, "maximum": 1000, "default": 200, "description": "Maximum number of alerts to sync per call"},
                },
                "required": [],
            },
        },
        {
            "name": "opencti_check_status",
            "description": "Check whether OpenCTI is reachable with the configured OPENCTI_URL and OPENCTI_API_TOKEN.",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        # OpenCTI read tools (4 tools)
        {
            "name": "opencti_query_indicators",
            "description": (
                "Search OpenCTI for STIX cyber-observables (IPs, domains, file hashes, etc.) "
                "by value. Returns matching observables with confidence scores, TLP markings, "
                "labels, and linked indicators. Useful for threat-intel lookups."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": "IP address, domain name, file hash, or other observable value to search for",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 20,
                        "description": "Maximum number of observables to return",
                    },
                },
                "required": ["value"],
            },
        },
        {
            "name": "opencti_get_incident",
            "description": (
                "Fetch a full CaseIncident from OpenCTI by its STIX ID. Returns the case "
                "with all linked observables, analyst notes, assignees, TLP markings, and status."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "stix_id": {
                        "type": "string",
                        "description": "STIX ID of the incident/case (e.g. 'case-incident--xxxxxxxx-…')",
                    },
                },
                "required": ["stix_id"],
            },
        },
        {
            "name": "opencti_list_cases",
            "description": (
                "List recent CaseIncident objects from OpenCTI ordered by creation date. "
                "Optionally filter by time window and minimum confidence."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 8760,
                        "default": 24,
                        "description": "Return cases created within the last N hours",
                    },
                    "min_confidence": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 100,
                        "default": 0,
                        "description": "Minimum confidence score (0–100)",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 20,
                        "description": "Maximum number of cases to return",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "opencti_get_observable",
            "description": (
                "Get full detail for a single STIX observable identified by its value. "
                "Returns the observable with TLP markings, MITRE kill-chain phases, "
                "linked indicators, and related reports."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": "Exact or partial observable value (IP, domain, hash, …)",
                    },
                },
                "required": ["value"],
            },
        },
        # Neo4j read tools (4 tools)
        {
            "name": "neo4j_attack_chain",
            "description": (
                "Trace a multi-hop attack chain in the Neo4j forensic graph starting from "
                "an IP address or alert ID. Returns the full path of nodes and relationships "
                "up to max_hops hops deep."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Source IP address to trace from (provide either ip or alert_id)",
                    },
                    "alert_id": {
                        "type": "string",
                        "description": "Alert ID to trace from (provide either ip or alert_id)",
                    },
                    "max_hops": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 6,
                        "default": 5,
                        "description": "Maximum relationship hops to traverse",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "neo4j_lateral_movement",
            "description": (
                "Detect lateral movement in the Neo4j forensic graph by finding users "
                "that logged into multiple workstations. Useful for identifying compromised "
                "accounts spreading across the environment."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 720,
                        "default": 24,
                        "description": "Time window in hours to look back",
                    },
                    "min_machines": {
                        "type": "integer",
                        "minimum": 2,
                        "maximum": 100,
                        "default": 2,
                        "description": "Minimum number of distinct workstations a user must appear on",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "neo4j_ip_context",
            "description": (
                "Return all forensic context for a given IP address from Neo4j: "
                "all related alerts, linked users, domains, processes, and workstations."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address to look up",
                    },
                },
                "required": ["ip"],
            },
        },
        {
            "name": "neo4j_query",
            "description": (
                "Execute a read-only Cypher query against the Neo4j forensic graph. "
                "Queries containing write operations (CREATE, MERGE, SET, DELETE, REMOVE, "
                "DROP, DETACH) are rejected. A LIMIT clause is automatically added when "
                "none is present."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cypher": {
                        "type": "string",
                        "description": "Read-only Cypher MATCH query to execute",
                    },
                    "params": {
                        "type": "object",
                        "description": "Optional named parameters referenced in the query via $name syntax",
                        "additionalProperties": True,
                    },
                },
                "required": ["cypher"],
            },
        },
    ]

    # Filter tools by session scopes: hide write tools from read-only or unknown tokens
    auth_token = getattr(session, "_auth_token", None)
    if not auth_token or not auth_token.has_scope("wazuh:write"):
        tools = [t for t in tools if t["name"] not in WRITE_SCOPE_TOOLS]

    # Pagination support per MCP spec
    return {"tools": tools}  # No more tools


async def handle_tools_call(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle tools/call method - all Wazuh Security Tools with comprehensive validation."""
    if _wazuh_client is None:
        raise RuntimeError("Wazuh client not initialized")

    tool_name = params.get("name")
    arguments = params.get("arguments", {})

    if not tool_name:
        raise ValueError("Tool name is required")

    # Validate tool name
    validate_input(tool_name, max_length=100)

    # Scope enforcement: check if the token has the required scope for this tool.
    # If auth_token is missing (should not happen in normal flow), deny write tools by default.
    auth_token = getattr(session, "_auth_token", None)
    required_scope = _get_tool_scope(tool_name)
    if required_scope == "wazuh:write" and not auth_token:
        raise ValueError(
            f"Insufficient permissions: tool '{tool_name}' requires '{required_scope}' scope. "
            f"Authentication token not found on session."
        )
    if auth_token and not auth_token.has_scope(required_scope):
        raise ValueError(
            f"Insufficient permissions: tool '{tool_name}' requires '{required_scope}' scope. "
            f"Your token has scopes: {auth_token.scopes}. "
            f"Request a token with '{required_scope}' scope to use this tool."
        )

    # Audit logging for destructive operations
    if tool_name in WRITE_SCOPE_TOOLS:
        client_id = auth_token.api_key_id if auth_token else "unknown"
        audit_logger.warning(
            f"AUDIT: tool={tool_name} client={client_id} session={session.session_id} "
            f"args={json.dumps({k: v for k, v in arguments.items() if k != 'parameters'}, default=str)}"
        )

    # Track tool execution for metrics
    def _tool_result(text: str) -> dict:
        """Return MCP-compliant tool success response with isError field."""
        return {"content": [{"type": "text", "text": text}], "isError": False}

    def _tool_error(text: str) -> dict:
        """Return MCP-compliant tool error response with isError field."""
        return {"content": [{"type": "text", "text": text}], "isError": True}

    _start_time = time.time()
    _success = False

    try:
        alert_response = await execute_alert_tool(
            tool_name,
            arguments,
            _wazuh_client,
            compact_alerts_result=compact_alerts_result,
            add_truncation_warning=add_truncation_warning,
        )
        if alert_response is not None:
            _success = True
            return _tool_result(alert_response)

        agent_response = await execute_agent_tool(tool_name, arguments, _wazuh_client)
        if agent_response is not None:
            _success = True
            return _tool_result(agent_response)

        vulnerability_response = await execute_vulnerability_tool(
            tool_name,
            arguments,
            _wazuh_client,
            compact_vulns_result=compact_vulns_result,
            add_truncation_warning=add_truncation_warning,
        )
        if vulnerability_response is not None:
            _success = True
            return _tool_result(vulnerability_response)

        security_response = await execute_security_analysis_tool(tool_name, arguments, _wazuh_client)
        if security_response is not None:
            _success = True
            return _tool_result(security_response)

        system_response = await execute_system_tool(tool_name, arguments, _wazuh_client)
        if system_response is not None:
            _success = True
            return _tool_result(system_response)

        # Phase 2 SOC Orchestration Tools
        phase2_response = await execute_phase2_tool(tool_name, arguments, _wazuh_client)
        if phase2_response is not None:
            _success = True
            return _tool_result(phase2_response)

        active_response = await execute_active_response_tool(tool_name, arguments, _wazuh_client)
        if active_response is not None:
            _success = True
            return _tool_result(active_response)

        verification_response = await execute_verification_tool(tool_name, arguments, _wazuh_client)
        if verification_response is not None:
            _success = True
            return _tool_result(verification_response)

        rollback_response = await execute_rollback_tool(tool_name, arguments, _wazuh_client)
        if rollback_response is not None:
            _success = True
            return _tool_result(rollback_response)

        # OpenCTI Integration Tools
        if tool_name == "opencti_sync_alerts":
            try:
                from wazuh_mcp_server.phase4.forensics.opencti_sync import sync_alerts
            except ImportError:
                return _tool_error("opencti_sync module not available (phase4 package not installed)")
            hours      = int(arguments.get("hours",      24))
            min_level  = int(arguments.get("min_level",  5))
            batch_size = int(arguments.get("batch_size", 200))
            result = await sync_alerts(hours=hours, min_level=min_level, batch_size=batch_size)
            _success = True
            return _tool_result(json.dumps(result, indent=2, default=str))

        if tool_name == "opencti_check_status":
            try:
                import os
                from wazuh_mcp_server.phase4.forensics.opencti_client import OpenCTIClient
                opencti_url   = os.getenv("OPENCTI_URL",       "").strip()
                opencti_token = os.getenv("OPENCTI_API_TOKEN", "").strip()
                if not opencti_url:
                    result = {"configured": False, "reachable": False}
                else:
                    client    = OpenCTIClient(opencti_url, opencti_token)
                    reachable = client.ping()
                    result    = {"configured": True, "reachable": reachable, "url": opencti_url}
            except ImportError:
                result = {"configured": False, "reachable": False, "error": "phase4 not installed"}
            except Exception as exc:
                result = {"configured": True, "reachable": False, "error": str(exc)}
            _success = True
            return _tool_result(json.dumps(result, indent=2, default=str))

        # OpenCTI read tools
        if tool_name == "opencti_query_indicators":
            try:
                import os
                from wazuh_mcp_server.phase4.forensics.opencti_client import OpenCTIClient
            except ImportError:
                return _tool_error("opencti_client module not available (phase4 package not installed)")
            opencti_url   = os.getenv("OPENCTI_URL",       "").strip()
            opencti_token = os.getenv("OPENCTI_API_TOKEN", "").strip()
            if not opencti_url:
                return _tool_error("OPENCTI_URL is not configured")
            value = str(arguments.get("value", "")).strip()
            if not value:
                return _tool_error("'value' parameter is required")
            limit = int(arguments.get("limit", 20))
            client = OpenCTIClient(opencti_url, opencti_token)
            result = client.search_observables(value=value, limit=limit)
            _success = True
            return _tool_result(json.dumps(result, indent=2, default=str))

        if tool_name == "opencti_get_incident":
            try:
                import os
                from wazuh_mcp_server.phase4.forensics.opencti_client import OpenCTIClient
            except ImportError:
                return _tool_error("opencti_client module not available (phase4 package not installed)")
            opencti_url   = os.getenv("OPENCTI_URL",       "").strip()
            opencti_token = os.getenv("OPENCTI_API_TOKEN", "").strip()
            if not opencti_url:
                return _tool_error("OPENCTI_URL is not configured")
            stix_id = str(arguments.get("stix_id", "")).strip()
            if not stix_id:
                return _tool_error("'stix_id' parameter is required")
            client = OpenCTIClient(opencti_url, opencti_token)
            result = client.get_incident(stix_id=stix_id)
            _success = True
            return _tool_result(json.dumps(result, indent=2, default=str))

        if tool_name == "opencti_list_cases":
            try:
                import os
                from wazuh_mcp_server.phase4.forensics.opencti_client import OpenCTIClient
            except ImportError:
                return _tool_error("opencti_client module not available (phase4 package not installed)")
            opencti_url   = os.getenv("OPENCTI_URL",       "").strip()
            opencti_token = os.getenv("OPENCTI_API_TOKEN", "").strip()
            if not opencti_url:
                return _tool_error("OPENCTI_URL is not configured")
            hours          = int(arguments.get("hours",          24))
            min_confidence = int(arguments.get("min_confidence",  0))
            limit          = int(arguments.get("limit",          20))
            client = OpenCTIClient(opencti_url, opencti_token)
            result = client.list_cases(hours=hours, min_confidence=min_confidence, limit=limit)
            _success = True
            return _tool_result(json.dumps(result, indent=2, default=str))

        if tool_name == "opencti_get_observable":
            try:
                import os
                from wazuh_mcp_server.phase4.forensics.opencti_client import OpenCTIClient
            except ImportError:
                return _tool_error("opencti_client module not available (phase4 package not installed)")
            opencti_url   = os.getenv("OPENCTI_URL",       "").strip()
            opencti_token = os.getenv("OPENCTI_API_TOKEN", "").strip()
            if not opencti_url:
                return _tool_error("OPENCTI_URL is not configured")
            value = str(arguments.get("value", "")).strip()
            if not value:
                return _tool_error("'value' parameter is required")
            client = OpenCTIClient(opencti_url, opencti_token)
            result = client.get_observable(value=value)
            _success = True
            return _tool_result(json.dumps(result, indent=2, default=str))

        # Neo4j read tools
        if tool_name == "neo4j_attack_chain":
            try:
                import os
                from wazuh_mcp_server.phase4.forensics.neo4j_read import Neo4jReadClient
            except ImportError:
                return _tool_error("neo4j_read module not available (phase4 package not installed)")
            http_url = os.getenv("NEO4J_HTTP_URL", "http://phase4-neo4j:7474")
            user     = os.getenv("NEO4J_USER",     "neo4j")
            password = os.getenv("NEO4J_PASSWORD", "phase4_admin")
            ip       = str(arguments.get("ip",       "")).strip()
            alert_id = str(arguments.get("alert_id", "")).strip()
            max_hops = int(arguments.get("max_hops", 5))
            if not ip and not alert_id:
                return _tool_error("Either 'ip' or 'alert_id' must be provided")
            client = Neo4jReadClient(http_url, user, password)
            result = client.attack_chain(ip=ip, alert_id=alert_id, max_hops=max_hops)
            _success = True
            return _tool_result(json.dumps(result, indent=2, default=str))

        if tool_name == "neo4j_lateral_movement":
            try:
                import os
                from wazuh_mcp_server.phase4.forensics.neo4j_read import Neo4jReadClient
            except ImportError:
                return _tool_error("neo4j_read module not available (phase4 package not installed)")
            http_url     = os.getenv("NEO4J_HTTP_URL", "http://phase4-neo4j:7474")
            user         = os.getenv("NEO4J_USER",     "neo4j")
            password     = os.getenv("NEO4J_PASSWORD", "phase4_admin")
            hours        = int(arguments.get("hours",        24))
            min_machines = int(arguments.get("min_machines",  2))
            client = Neo4jReadClient(http_url, user, password)
            result = client.lateral_movement(hours=hours, min_machines=min_machines)
            _success = True
            return _tool_result(json.dumps(result, indent=2, default=str))

        if tool_name == "neo4j_ip_context":
            try:
                import os
                from wazuh_mcp_server.phase4.forensics.neo4j_read import Neo4jReadClient
            except ImportError:
                return _tool_error("neo4j_read module not available (phase4 package not installed)")
            http_url = os.getenv("NEO4J_HTTP_URL", "http://phase4-neo4j:7474")
            user     = os.getenv("NEO4J_USER",     "neo4j")
            password = os.getenv("NEO4J_PASSWORD", "phase4_admin")
            ip = str(arguments.get("ip", "")).strip()
            if not ip:
                return _tool_error("'ip' parameter is required")
            client = Neo4jReadClient(http_url, user, password)
            result = client.ip_context(ip=ip)
            _success = True
            return _tool_result(json.dumps(result, indent=2, default=str))

        if tool_name == "neo4j_query":
            try:
                import os
                from wazuh_mcp_server.phase4.forensics.neo4j_read import Neo4jReadClient
            except ImportError:
                return _tool_error("neo4j_read module not available (phase4 package not installed)")
            http_url = os.getenv("NEO4J_HTTP_URL", "http://phase4-neo4j:7474")
            user     = os.getenv("NEO4J_USER",     "neo4j")
            password = os.getenv("NEO4J_PASSWORD", "phase4_admin")
            cypher = str(arguments.get("cypher", "")).strip()
            if not cypher:
                return _tool_error("'cypher' parameter is required")
            params = arguments.get("params") or {}
            if not isinstance(params, dict):
                return _tool_error("'params' must be a JSON object")
            client = Neo4jReadClient(http_url, user, password)
            result = client.run_read_query(cypher=cypher, params=params)
            _success = True
            return _tool_result(json.dumps(result, indent=2, default=str))

        raise ValueError(f"Unknown tool: {tool_name}. Use 'tools/list' to see available tools.")

    except ToolValidationError as e:
        # Parameter validation errors - return tool-level error with actionable guidance
        logger.warning(f"Tool validation error in {tool_name}: {e}")
        return _tool_error(str(e))

    except IndexerNotConfiguredError as e:
        # Provide helpful error for vulnerability tools when indexer is not configured
        logger.warning(f"Indexer not configured for tool {tool_name}: {e}")
        return _tool_error(str(e))

    except ConnectionError as e:
        # Network/connection errors - provide retry guidance
        logger.error(f"Connection error in tool {tool_name}: {e}")
        return _tool_error(f"Connection failed: {str(e)}. Check Wazuh server connectivity and try again.")

    except Exception as e:
        logger.error(f"Tool execution error in {tool_name}: {e}", exc_info=True)
        return _tool_error(f"Tool execution failed: {str(e)}")

    finally:
        # Record tool execution metrics
        _duration = time.time() - _start_time
        record_tool_execution(tool_name, _duration, _success)
