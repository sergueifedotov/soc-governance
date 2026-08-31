"""LangChain-backed read-only Phase 2 SOC orchestration helpers."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, TypedDict, cast

from pydantic import SecretStr

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.config import get_config

try:
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_openai import ChatOpenAI
except ImportError:  # pragma: no cover
    StrOutputParser = None
    ChatPromptTemplate = None
    ChatOpenAI = None


_TIME_RANGE_HOURS = {
    "1h": 1,
    "6h": 6,
    "12h": 12,
    "1d": 24,
    "24h": 24,
    "7d": 24 * 7,
    "30d": 24 * 30,
}

_LLM_CONTRACT_VERSION = "1.0"
_LLM_PAYLOAD_MAX_BYTES = 12_000
_REDACT_KEYS = {"full_log", "password", "token", "api_key", "secret", "authorization"}
_MITRE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

_MITRE_HEURISTICS: List[Dict[str, Any]] = [
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "patterns": [r"brute\s*force", r"failed\s+password", r"authentication\s+failed", r"multiple\s+login\s+fail"],
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "patterns": [r"valid\s+account", r"successful\s+login", r"privileged\s+account", r"account\s+enabled"],
    },
    {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "patterns": [r"powershell", r"-enc\b", r"invoke-expression", r"iex\s*\("],
    },
    {
        "technique_id": "T1059.003",
        "technique_name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "patterns": [r"cmd\.exe", r"/c\s", r"whoami", r"net\s+user"],
    },
    {
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "patterns": [r"ssh", r"sshd", r"port\s*22", r"remote\s+login"],
    },
    {
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "patterns": [r"rdp", r"remote\s+desktop", r"3389", r"terminal\s+services"],
    },
    {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion",
        "patterns": [r"process\s+injection", r"inject(ed|ion)", r"remote\s+thread", r"hollowing"],
    },
    {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "patterns": [r"http", r"https", r"beacon", r"c2"],
    },
    {
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "patterns": [r"dns", r"domain\s+generation", r"tunneling", r"txt\s+record"],
    },
    {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "patterns": [r"exfil", r"data\s+transfer", r"outbound\s+traffic", r"upload\s+sensitive"],
    },
]


class LLMTimeWindow(TypedDict):
    start_utc: str
    end_utc: str
    range_label: str


class LLMContractPayload(TypedDict, total=False):
    contract_version: str
    workflow: str
    time_window: LLMTimeWindow
    filters: Dict[str, Any]
    totals: Dict[str, Any]
    top_rules: List[Dict[str, Any]]
    top_agents: List[Dict[str, Any]]
    top_source_ips: List[Dict[str, Any]]
    sample_alerts: List[Dict[str, Any]]
    enrichment_summary: Dict[str, Any]
    analyst_objective: str
    required_output_shape: List[str]
    budget_trimmed: bool


def _time_range_to_start(time_range: str) -> str:
    hours = _TIME_RANGE_HOURS.get(time_range, 24)
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def _affected_items(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    return result.get("data", {}).get("affected_items", [])


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _severity_bucket(level: Any) -> str:
    severity = _safe_int(level)
    if severity >= 12:
        return "critical"
    if severity >= 10:
        return "high"
    if severity >= 7:
        return "medium"
    return "low"


def _compact_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    compact: Dict[str, Any] = {
        "timestamp": alert.get("timestamp"),
        "agent": {
            "id": alert.get("agent", {}).get("id", ""),
            "name": alert.get("agent", {}).get("name", ""),
        },
        "rule": {
            "id": alert.get("rule", {}).get("id", ""),
            "level": alert.get("rule", {}).get("level", 0),
            "description": alert.get("rule", {}).get("description", ""),
            "groups": alert.get("rule", {}).get("groups", []),
        },
    }
    data = alert.get("data", {})
    if data.get("srcip"):
        compact["srcip"] = data["srcip"]
    if data.get("dstip"):
        compact["dstip"] = data["dstip"]
    return compact


def _sort_counts(counts: Dict[str, Dict[str, Any]], sort_key: str = "count", limit: int = 5) -> List[Dict[str, Any]]:
    values = list(counts.values())
    values.sort(key=lambda item: item.get(sort_key, 0), reverse=True)
    return values[:limit]


def _parse_alert_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _severity_breakdown_from_alerts(alerts: List[Dict[str, Any]]) -> Dict[str, int]:
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for alert in alerts:
        bucket = _severity_bucket(alert.get("rule", {}).get("level"))
        breakdown[bucket] += 1
    return breakdown


def _window_change_summary(current: List[Dict[str, Any]], previous: List[Dict[str, Any]]) -> Dict[str, Any]:
    current_severity = _severity_breakdown_from_alerts(current)
    previous_severity = _severity_breakdown_from_alerts(previous)

    current_total = len(current)
    previous_total = len(previous)
    delta = current_total - previous_total
    pct_change = 100.0 if previous_total == 0 and current_total > 0 else 0.0
    if previous_total > 0:
        pct_change = round((delta / previous_total) * 100.0, 2)

    severity_delta = {
        key: current_severity.get(key, 0) - previous_severity.get(key, 0)
        for key in ("critical", "high", "medium", "low")
    }
    spike_levels = [
        key
        for key in ("critical", "high", "medium")
        if current_severity.get(key, 0) >= max(previous_severity.get(key, 0) + 3, previous_severity.get(key, 0) * 2)
    ]

    return {
        "current_window": {
            "total": current_total,
            "severity": current_severity,
        },
        "previous_window": {
            "total": previous_total,
            "severity": previous_severity,
        },
        "delta_total": delta,
        "percent_change_total": pct_change,
        "severity_delta": severity_delta,
        "spike_levels": spike_levels,
    }


def _pattern_summarization(
    alerts: List[Dict[str, Any]],
    top_rules: List[Dict[str, Any]],
    top_agents: List[Dict[str, Any]],
    top_source_ips: List[Dict[str, Any]],
) -> Dict[str, Any]:
    clusters: Dict[str, Dict[str, Any]] = {}
    for alert in alerts:
        srcip = alert.get("data", {}).get("srcip")
        if not srcip:
            continue

        cluster = clusters.setdefault(
            srcip,
            {
                "srcip": srcip,
                "count": 0,
                "agents": set(),
                "rules": set(),
                "max_level": 0,
            },
        )
        cluster["count"] += 1
        agent_id = str(alert.get("agent", {}).get("id", "unknown"))
        rule_id = str(alert.get("rule", {}).get("id", "unknown"))
        cluster["agents"].add(agent_id)
        cluster["rules"].add(rule_id)
        cluster["max_level"] = max(cluster["max_level"], _safe_int(alert.get("rule", {}).get("level")))

    suspicious_clusters: List[Dict[str, Any]] = []
    for value in clusters.values():
        if value["count"] >= 3 and (len(value["agents"]) >= 2 or len(value["rules"]) >= 2):
            suspicious_clusters.append(
                {
                    "srcip": value["srcip"],
                    "count": value["count"],
                    "distinct_agents": len(value["agents"]),
                    "distinct_rules": len(value["rules"]),
                    "max_level": value["max_level"],
                }
            )

    suspicious_clusters.sort(key=lambda item: (item["count"], item["max_level"]), reverse=True)
    return {
        "repeated_source_ips": [item for item in top_source_ips if item.get("count", 0) >= 2][:5],
        "repeated_rule_ids": [item for item in top_rules if item.get("count", 0) >= 2][:5],
        "repeated_agent_impact": [item for item in top_agents if item.get("count", 0) >= 2][:5],
        "suspicious_clusters": suspicious_clusters[:5],
    }


def _build_most_important(
    alerts: List[Dict[str, Any]],
    top_rules: List[Dict[str, Any]],
    top_agents: List[Dict[str, Any]],
    top_source_ips: List[Dict[str, Any]],
) -> Dict[str, Any]:
    ranked = sorted(alerts, key=lambda item: _safe_int(item.get("rule", {}).get("level")), reverse=True)
    return {
        "highest_priority_alerts": [_compact_alert(alert) for alert in ranked[:3]],
        "top_rule": top_rules[0] if top_rules else {},
        "top_agent": top_agents[0] if top_agents else {},
        "top_source_ip": top_source_ips[0] if top_source_ips else {},
    }


def _build_escalation_draft(
    time_range: str,
    severity_breakdown: Dict[str, int],
    pattern_summary: Dict[str, Any],
    top_rules: List[Dict[str, Any]],
    top_agents: List[Dict[str, Any]],
    sample_alerts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    top_rule = top_rules[0] if top_rules else {}
    top_agent = top_agents[0] if top_agents else {}
    suspicious = pattern_summary.get("suspicious_clusters", [])
    escalation_recommended = severity_breakdown.get("critical", 0) > 0 or len(suspicious) > 0

    handoff = (
        f"In the last {time_range}, Wazuh recorded {sum(severity_breakdown.values())} alerts "
        f"(critical={severity_breakdown.get('critical', 0)}, high={severity_breakdown.get('high', 0)}). "
        f"Top recurring rule is {top_rule.get('rule_id', 'n/a')} and most impacted agent is "
        f"{top_agent.get('agent_name', top_agent.get('agent_id', 'n/a'))}."
    )
    if suspicious:
        lead = suspicious[0]
        handoff += (
            f" Notable cluster: srcip {lead.get('srcip')} across {lead.get('distinct_agents')} agents "
            f"and {lead.get('distinct_rules')} rules."
        )

    soc_note = [
        "Escalation recommendation:" if escalation_recommended else "Escalation optional:",
        handoff,
        "Curated alerts attached for analyst review.",
    ]

    return {
        "escalation_recommended": escalation_recommended,
        "incident_handoff": handoff,
        "soc_note": " ".join(soc_note),
        "curated_alert_subset": sample_alerts[:5],
    }


def _extract_ip_from_text(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value):
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return None


async def _fetch_external_readonly_context(candidate_ip: Optional[str], time_range: str) -> Dict[str, Any]:
    sections: Dict[str, Any] = {}
    hours = _TIME_RANGE_HOURS.get(time_range, 24)

    try:
        import os
        from forensics.opencti_client import OpenCTIClient

        opencti_url = os.getenv("OPENCTI_URL", "").strip()
        opencti_token = os.getenv("OPENCTI_API_TOKEN", "").strip()
        if opencti_url:
            opencti = OpenCTIClient(opencti_url, opencti_token)
            if candidate_ip:
                sections["opencti_observable"] = opencti.get_observable(candidate_ip)
                sections["opencti_indicator_search"] = opencti.search_observables(candidate_ip, limit=5)
            sections["opencti_recent_cases"] = opencti.list_cases(hours=hours, min_confidence=0, limit=5)
        else:
            sections["opencti"] = {"error": "OPENCTI_URL is not configured"}
    except Exception as exc:
        sections["opencti"] = {"error": str(exc)}

    try:
        from forensics.neo4j_read import _default_client

        neo4j = _default_client()
        if candidate_ip:
            sections["neo4j_ip_context"] = neo4j.ip_context(candidate_ip)
            sections["neo4j_attack_chain"] = neo4j.attack_chain(ip=candidate_ip, max_hops=3)
        sections["neo4j_lateral_movement"] = neo4j.lateral_movement(hours=min(hours, 168), min_machines=2)
    except Exception as exc:
        sections["neo4j"] = {"error": str(exc)}

    return sections


def _sanitize_for_llm(value: Any) -> Any:
    """Recursively redact risky keys and trim long strings before prompt assembly."""
    if isinstance(value, dict):
        sanitized: Dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in _REDACT_KEYS:
                sanitized[key] = "[REDACTED]"
                continue
            sanitized[key] = _sanitize_for_llm(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_for_llm(item) for item in value]
    if isinstance(value, str):
        text = value
        if len(text) > 240:
            text = text[:240] + "... [truncated]"
        # Extra guard for bearer tokens that may appear in arbitrary strings.
        return re.sub(r"(bearer\s+)[a-zA-Z0-9._-]+", r"\1[REDACTED]", text, flags=re.IGNORECASE)
    return value


def _llm_payload_size(payload: Dict[str, Any]) -> int:
    return len(json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8"))


def _contract_window(time_range: str) -> LLMTimeWindow:
    return {
        "start_utc": _time_range_to_start(time_range),
        "end_utc": datetime.now(timezone.utc).isoformat(),
        "range_label": time_range,
    }


def _validate_contract_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    required_keys = {"contract_version", "workflow", "analyst_objective", "required_output_shape"}
    missing = [key for key in sorted(required_keys) if key not in payload]
    if missing:
        raise ValueError(f"Missing LLM contract keys: {', '.join(missing)}")

    if payload.get("contract_version") != _LLM_CONTRACT_VERSION:
        raise ValueError("Invalid LLM contract version")

    output_shape = payload.get("required_output_shape")
    if not isinstance(output_shape, list) or not all(isinstance(item, str) for item in output_shape):
        raise ValueError("required_output_shape must be a list[str]")

    return payload


def _apply_budget_trimming(payload: Dict[str, Any], max_bytes: int = _LLM_PAYLOAD_MAX_BYTES) -> Dict[str, Any]:
    """Trim low-priority sections until payload fits the configured byte budget."""
    if _llm_payload_size(payload) <= max_bytes:
        return payload

    trimmed = dict(payload)
    trimmed["budget_trimmed"] = True

    if isinstance(trimmed.get("sample_alerts"), list):
        trimmed["sample_alerts"] = trimmed["sample_alerts"][:3]
    if _llm_payload_size(trimmed) <= max_bytes:
        return trimmed

    if isinstance(trimmed.get("enrichment_summary"), dict):
        enrich = dict(trimmed["enrichment_summary"])
        enrich.pop("details", None)
        trimmed["enrichment_summary"] = enrich
    if _llm_payload_size(trimmed) <= max_bytes:
        return trimmed

    compacted = _compact_for_llm(trimmed, list_limit=2, dict_key_limit=15, text_limit=120)
    if isinstance(compacted, dict):
        compacted["budget_trimmed"] = True
        return compacted
    return trimmed


def _build_llm_contract_payload(workflow: str, objective: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    required_output_shape = [
        "short_analyst_summary",
        "important_findings",
        "recommended_read_only_next_steps",
    ]

    if workflow == "phase2_alert_triage":
        time_range = str(payload.get("time_range", "24h"))
        severity = payload.get("severity_breakdown", {})
        contract: LLMContractPayload = {
            "contract_version": _LLM_CONTRACT_VERSION,
            "workflow": workflow,
            "time_window": _contract_window(time_range),
            "filters": {
                "min_level": payload.get("minimum_level"),
            },
            "totals": {
                "total_alerts": payload.get("total_alerts", 0),
                "critical": severity.get("critical", 0),
                "high": severity.get("high", 0),
                "medium": severity.get("medium", 0),
                "low": severity.get("low", 0),
            },
            "top_rules": list(payload.get("top_rules", []))[:10],
            "top_agents": list(payload.get("top_agents", []))[:10],
            "top_source_ips": list(payload.get("top_source_ips", []))[:10],
            "sample_alerts": list(payload.get("sample_alerts", []))[:8],
            "enrichment_summary": {
                "changes_over_window": payload.get("changes_over_window", {}),
                "pattern_summary": payload.get("pattern_summary", {}),
                "most_important": payload.get("most_important", {}),
                "escalation_draft": payload.get("escalation_draft", {}),
            },
            "analyst_objective": objective,
            "required_output_shape": required_output_shape,
        }
        return _apply_budget_trimming(_validate_contract_payload(_sanitize_for_llm(contract)))

    contract_generic: LLMContractPayload = {
        "contract_version": _LLM_CONTRACT_VERSION,
        "workflow": workflow,
        "analyst_objective": objective,
        "required_output_shape": required_output_shape,
        "enrichment_summary": _compact_for_llm(payload, list_limit=5, dict_key_limit=25, text_limit=180),
    }
    return _apply_budget_trimming(_validate_contract_payload(_sanitize_for_llm(contract_generic)))


def _recommend_triage_actions(severity_breakdown: Dict[str, int], agent_health: List[Dict[str, Any]]) -> List[str]:
    recommendations: List[str] = []
    if severity_breakdown.get("critical", 0) > 0:
        recommendations.append("Review critical alerts immediately and confirm whether containment is required.")
    if severity_breakdown.get("high", 0) > 0:
        recommendations.append("Pivot on the highest-volume high-severity rules to identify repeated attack patterns.")
    unhealthy_agents = [item for item in agent_health if item.get("health") != "healthy"]
    if unhealthy_agents:
        recommendations.append("Investigate unhealthy or disconnected agents before relying on their telemetry.")
    if not recommendations:
        recommendations.append("No urgent escalation indicators were found in the sampled alerts.")
    return recommendations


def _deterministic_triage_summary(payload: Dict[str, Any]) -> str:
    severity = payload.get("severity_breakdown", {})
    top_rules = payload.get("top_rules") or [{}]
    top_agents = payload.get("top_agents") or [{}]
    top_rule = top_rules[0]
    top_agent = top_agents[0]
    return (
        f"Analyzed {payload.get('total_alerts', 0)} alerts over {payload.get('time_range', '24h')}. "
        f"Critical: {severity.get('critical', 0)}, high: {severity.get('high', 0)}, medium: {severity.get('medium', 0)}, low: {severity.get('low', 0)}. "
        f"Top rule: {top_rule.get('rule_id', 'n/a')} ({top_rule.get('description', 'n/a')}). "
        f"Most affected agent: {top_agent.get('agent_name', top_agent.get('agent_id', 'n/a'))}."
    )


def _deterministic_enrichment_summary(payload: Dict[str, Any]) -> str:
    filters = payload.get("filters", {})
    return (
        f"Enriched {payload.get('match_count', 0)} matching alerts for filters {filters}. "
        f"Supporting context sections: {', '.join(sorted(payload.get('supporting_context', {}).keys())) or 'none'}."
    )


def _deterministic_report_summary(payload: Dict[str, Any]) -> str:
    sections = payload.get("sections", {})
    return (
        f"Generated a {payload.get('report_type', 'shift')} report for {payload.get('time_range', '12h')} with sections: "
        f"{', '.join(sorted(sections.keys()))}. Executive summary contains {len(payload.get('executive_summary', []))} key statements."
    )


def _normalize_mitre_id(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    candidate = value.strip().upper()
    return candidate if _MITRE_ID_RE.match(candidate) else None


def _to_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _extract_rule_mitre_candidates(alert: Dict[str, Any], alert_index: int) -> List[Dict[str, Any]]:
    rule = alert.get("rule", {})
    mitre = rule.get("mitre")
    if not isinstance(mitre, dict):
        return []

    ids_raw = (
        mitre.get("id")
        or mitre.get("ids")
        or mitre.get("technique_id")
        or mitre.get("technique_ids")
    )
    names_raw = mitre.get("technique") or mitre.get("techniques")
    tactics_raw = mitre.get("tactic") or mitre.get("tactics") or mitre.get("phase")

    ids = [_normalize_mitre_id(item) for item in _to_list(ids_raw)]
    ids = [item for item in ids if item]
    if not ids:
        return []

    names = [str(item).strip() for item in _to_list(names_raw) if str(item).strip()]
    tactics = [str(item).strip() for item in _to_list(tactics_raw) if str(item).strip()]
    level = _safe_int(rule.get("level"), 0)

    candidates: List[Dict[str, Any]] = []
    for idx, technique_id in enumerate(ids):
        candidates.append(
            {
                "technique_id": technique_id,
                "technique_name": names[idx] if idx < len(names) else "",
                "tactic": tactics[idx] if idx < len(tactics) else (tactics[0] if tactics else ""),
                "confidence": round(min(0.99, 0.88 + min(level, 15) / 150.0), 2),
                "rationale": "Mapped from Wazuh rule MITRE metadata.",
                "evidence_alert_indexes": [alert_index],
                "source": "rule_metadata",
            }
        )
    return candidates


def _alert_feature_text(alert: Dict[str, Any]) -> str:
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    parts: List[str] = [
        str(rule.get("description", "")),
        " ".join(str(item) for item in rule.get("groups", []) if item),
        str(alert.get("full_log", "")),
        str(data.get("srcip", "")),
        str(data.get("dstip", "")),
        str(data.get("command", "")),
        str(data.get("process", "")),
        str(data.get("win", {})),
    ]
    return " ".join(part for part in parts if part).lower()


def _extract_heuristic_mitre_candidates(alert: Dict[str, Any], alert_index: int) -> List[Dict[str, Any]]:
    text = _alert_feature_text(alert)
    if not text:
        return []

    level = _safe_int(alert.get("rule", {}).get("level"), 0)
    candidates: List[Dict[str, Any]] = []
    for entry in _MITRE_HEURISTICS:
        matched_terms: List[str] = []
        for pattern in entry["patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                matched_terms.append(pattern)
        if not matched_terms:
            continue

        confidence = 0.45 + min(level, 15) / 40.0 + min(len(matched_terms), 3) * 0.05
        confidence = round(min(0.93, confidence), 2)
        candidates.append(
            {
                "technique_id": entry["technique_id"],
                "technique_name": entry["technique_name"],
                "tactic": entry["tactic"],
                "confidence": confidence,
                "rationale": (
                    "Matched alert context patterns: "
                    + ", ".join(matched_terms[:3])
                    + "."
                ),
                "evidence_alert_indexes": [alert_index],
                "source": "heuristic",
            }
        )
    return candidates


def _aggregate_mitre_candidates(candidates: List[Dict[str, Any]], total_alerts: int) -> List[Dict[str, Any]]:
    if not candidates:
        return []

    grouped: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "technique_id": "",
        "technique_name": "",
        "tactic": "",
        "max_confidence": 0.0,
        "sources": set(),
        "rationales": [],
        "evidence_alert_indexes": set(),
        "supporting_alert_count": 0,
    })

    for item in candidates:
        technique_id = item.get("technique_id")
        if not isinstance(technique_id, str) or not technique_id:
            continue
        bucket = grouped[technique_id]
        bucket["technique_id"] = technique_id
        if not bucket["technique_name"] and item.get("technique_name"):
            bucket["technique_name"] = item.get("technique_name")
        if not bucket["tactic"] and item.get("tactic"):
            bucket["tactic"] = item.get("tactic")
        bucket["max_confidence"] = max(float(bucket["max_confidence"]), float(item.get("confidence", 0.0)))
        bucket["sources"].add(str(item.get("source", "heuristic")))
        rationale = str(item.get("rationale", "")).strip()
        if rationale:
            bucket["rationales"].append(rationale)
        for idx in item.get("evidence_alert_indexes", []):
            if isinstance(idx, int):
                bucket["evidence_alert_indexes"].add(idx)
        bucket["supporting_alert_count"] = len(bucket["evidence_alert_indexes"])

    mappings: List[Dict[str, Any]] = []
    for technique_id, bucket in grouped.items():
        support_ratio = 0.0 if total_alerts <= 0 else bucket["supporting_alert_count"] / float(total_alerts)
        source_bonus = 0.1 if "rule_metadata" in bucket["sources"] else 0.0
        confidence = min(0.99, float(bucket["max_confidence"]) + min(0.2, support_ratio * 0.25) + source_bonus)

        mapping = {
            "technique_id": technique_id,
            "technique_name": bucket["technique_name"],
            "tactic": bucket["tactic"],
            "confidence": round(confidence, 2),
            "rationale": " ".join(bucket["rationales"][:2]).strip() or "Derived from alert context.",
            "evidence_alert_indexes": sorted(bucket["evidence_alert_indexes"])[:8],
            "supporting_alert_count": bucket["supporting_alert_count"],
            "source": "+".join(sorted(bucket["sources"])),
        }
        mappings.append(mapping)

    mappings.sort(key=lambda item: (item.get("confidence", 0.0), item.get("supporting_alert_count", 0)), reverse=True)
    return mappings


def _strip_markdown_json_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return stripped


def _extract_json_object(text: str) -> Dict[str, Any]:
    cleaned = _strip_markdown_json_fence(text)
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start >= 0 and end > start:
        parsed = json.loads(cleaned[start : end + 1])
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("LLM output did not contain a valid JSON object")


def _sanitize_llm_mitre_techniques(items: Any, total_alerts: int) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []

    mappings: List[Dict[str, Any]] = []
    for raw in items[:20]:
        if not isinstance(raw, dict):
            continue
        technique_id = _normalize_mitre_id(raw.get("technique_id"))
        if not technique_id:
            continue
        evidence_raw = raw.get("evidence_alert_indexes")
        evidence = []
        if isinstance(evidence_raw, list):
            for idx in evidence_raw:
                if isinstance(idx, int) and idx >= 0:
                    evidence.append(idx)

        confidence = raw.get("confidence", 0.0)
        try:
            confidence_val = float(confidence)
        except (TypeError, ValueError):
            confidence_val = 0.0
        confidence_val = round(min(0.99, max(0.0, confidence_val)), 2)

        mappings.append(
            {
                "technique_id": technique_id,
                "technique_name": str(raw.get("technique_name", "")).strip(),
                "tactic": str(raw.get("tactic", "")).strip(),
                "confidence": confidence_val,
                "rationale": str(raw.get("rationale", "")).strip()[:600],
                "evidence_alert_indexes": sorted(set(evidence))[:8],
                "supporting_alert_count": len(set(evidence)),
                "source": "langchain",
            }
        )

    if not mappings:
        return []

    # Guarantee deterministic ordering for downstream consumers.
    mappings.sort(key=lambda item: (item.get("confidence", 0.0), item.get("supporting_alert_count", 0)), reverse=True)

    # Keep counts coherent when the model omitted evidence indexes.
    for item in mappings:
        if item["supporting_alert_count"] == 0 and total_alerts > 0:
            item["supporting_alert_count"] = 1

    return mappings


async def _classify_mitre_with_langchain(
    alerts: List[Dict[str, Any]],
    deterministic_mappings: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    synthesizer = Phase2LangChainSynthesizer()
    status = synthesizer._status()
    if not status.get("enabled"):
        return deterministic_mappings, {
            "engine": "deterministic",
            "status": status.get("reason", "LangChain disabled"),
        }

    if ChatPromptTemplate is None or StrOutputParser is None:
        return deterministic_mappings, {
            "engine": "deterministic",
            "status": "LangChain prompt/parser dependencies unavailable",
        }

    try:
        prompt_factory = cast(Any, ChatPromptTemplate)
        parser_cls = cast(Any, StrOutputParser)
        prompt = prompt_factory.from_messages(
            [
                (
                    "system",
                    "You are a SOC analyst assistant specialized in MITRE ATT&CK mapping. "
                    "Classify only from provided evidence. Return strict JSON only.",
                ),
                (
                    "human",
                    "Map the provided Wazuh alert context to MITRE ATT&CK techniques. "
                    "Return this JSON object shape exactly: "
                    "{{\"techniques\":[{{\"technique_id\":\"T1110\",\"technique_name\":\"Brute Force\",\"tactic\":\"Credential Access\",\"confidence\":0.0,\"rationale\":\"...\",\"evidence_alert_indexes\":[0]}}],\"overall_rationale\":\"...\"}}.\n"
                    "Rules:\n"
                    "- technique_id must match ATT&CK format T#### or T####.###\n"
                    "- confidence must be between 0.0 and 0.99\n"
                    "- include at most 8 techniques\n"
                    "- reference evidence by alert index\n\n"
                    "Deterministic hints:\n{hints}\n\n"
                    "Alert context:\n{alerts}",
                ),
            ]
        )
        chain = prompt | synthesizer._create_model() | parser_cls()
        hints_payload = _compact_for_llm(deterministic_mappings[:5], list_limit=5, dict_key_limit=6, text_limit=120)
        alerts_payload = _compact_for_llm([_compact_alert(alert) for alert in alerts[:6]], list_limit=6, dict_key_limit=8, text_limit=120)
        output = await chain.ainvoke(
            {
                "hints": json.dumps(hints_payload, indent=2, default=str),
                "alerts": json.dumps(alerts_payload, indent=2, default=str),
            }
        )
        payload = _extract_json_object(output)
        techniques = _sanitize_llm_mitre_techniques(payload.get("techniques"), total_alerts=len(alerts))
        if not techniques:
            raise ValueError("LLM output did not include valid MITRE techniques")
        return techniques, {
            "engine": "langchain",
            "status": "LangChain ATT&CK mapping enabled",
            "model": synthesizer._config.PHASE2_LLM_MODEL,
            "base_url": synthesizer._config.PHASE2_LLM_BASE_URL,
            "overall_rationale": str(payload.get("overall_rationale", "")).strip()[:800],
        }
    except Exception as exc:  # pragma: no cover
        return deterministic_mappings, {
            "engine": "deterministic",
            "status": f"LangChain ATT&CK mapping fallback: {exc}",
        }


def _compact_for_llm(value: Any, list_limit: int = 5, dict_key_limit: int = 30, text_limit: int = 400) -> Any:
    """Reduce payload size before prompting an LLM with limited context window."""
    if isinstance(value, dict):
        compacted: Dict[str, Any] = {}
        for idx, (k, v) in enumerate(value.items()):
            if idx >= dict_key_limit:
                compacted["_truncated_keys"] = len(value) - dict_key_limit
                break
            compacted[k] = _compact_for_llm(v, list_limit=list_limit, dict_key_limit=dict_key_limit, text_limit=text_limit)
        return compacted
    if isinstance(value, list):
        trimmed = value[:list_limit]
        compacted_list = [_compact_for_llm(item, list_limit=list_limit, dict_key_limit=dict_key_limit, text_limit=text_limit) for item in trimmed]
        if len(value) > list_limit:
            compacted_list.append({"_truncated_items": len(value) - list_limit})
        return compacted_list
    if isinstance(value, str) and len(value) > text_limit:
        return value[:text_limit] + "... [truncated]"
    return value


class Phase2LangChainSynthesizer:
    """Analyst-facing synthesis layer for read-only Phase 2 workflows."""

    def __init__(self) -> None:
        self._config = get_config()

    def _status(self) -> Dict[str, Any]:
        if not self._config.PHASE2_LLM_ENABLED:
            return {"enabled": False, "reason": "PHASE2_LLM_ENABLED is false"}
        if ChatOpenAI is None or ChatPromptTemplate is None or StrOutputParser is None:
            return {"enabled": False, "reason": "LangChain dependencies are unavailable"}
        if not self._config.PHASE2_LLM_MODEL:
            return {"enabled": False, "reason": "PHASE2_LLM_MODEL is not configured"}
        if not self._config.PHASE2_LLM_BASE_URL:
            return {"enabled": False, "reason": "PHASE2_LLM_BASE_URL is not configured"}
        return {"enabled": True, "reason": "LangChain synthesis enabled"}

    def _create_model(self) -> Any:
        if ChatOpenAI is None:
            raise RuntimeError("LangChain OpenAI integration is unavailable")
        return ChatOpenAI(
            model=self._config.PHASE2_LLM_MODEL,
            base_url=self._config.PHASE2_LLM_BASE_URL,
            api_key=SecretStr(self._config.PHASE2_LLM_API_KEY or "local-phase2-key"),
            temperature=0,
            timeout=self._config.PHASE2_LLM_TIMEOUT_SECONDS,
            max_retries=0,
        )

    async def summarize(
        self,
        workflow: str,
        objective: str,
        payload: Dict[str, Any],
        fallback_summary: str,
    ) -> Dict[str, Any]:
        status = self._status()
        if not status["enabled"]:
            return {"engine": "deterministic", "summary": fallback_summary, "status": status["reason"]}

        prompt_factory = cast(Any, ChatPromptTemplate)
        parser_cls = cast(Any, StrOutputParser)
        prompt = prompt_factory.from_messages(
            [
                (
                    "system",
                    "You are a SOC analyst assistant. Summarize only the provided Wazuh facts. Do not invent additional events, hosts, or indicators. Keep the answer concise and operationally useful.",
                ),
                (
                    "human",
                    "Workflow: {workflow}\nObjective: {objective}\n"
                    "Provide: 1. A short analyst summary. 2. The most important findings. 3. Recommended read-only next steps only.\n\nFacts:\n{payload}",
                ),
            ]
        )
        chain = prompt | self._create_model() | parser_cls()

        async def _invoke_with_payload(payload_obj: Dict[str, Any]) -> str:
            return await chain.ainvoke(
                {
                    "workflow": workflow,
                    "objective": objective,
                    "payload": json.dumps(payload_obj, indent=2, default=str),
                }
            )

        try:
            summary = await _invoke_with_payload(payload)
            return {
                "engine": "langchain",
                "summary": summary.strip(),
                "status": status["reason"],
                "model": self._config.PHASE2_LLM_MODEL,
                "base_url": self._config.PHASE2_LLM_BASE_URL,
            }
        except Exception as exc:  # pragma: no cover
            message = str(exc).lower()
            if "context" in message and ("exceed" in message or "too long" in message or "n_ctx" in message):
                try:
                    compact_payload = _compact_for_llm(payload, list_limit=3, dict_key_limit=20, text_limit=240)
                    summary = await _invoke_with_payload(compact_payload)
                    return {
                        "engine": "langchain",
                        "summary": summary.strip(),
                        "status": f"{status['reason']} (compact payload retry)",
                        "model": self._config.PHASE2_LLM_MODEL,
                        "base_url": self._config.PHASE2_LLM_BASE_URL,
                    }
                except Exception:
                    try:
                        ultra_compact_payload = _compact_for_llm(payload, list_limit=1, dict_key_limit=10, text_limit=120)
                        summary = await _invoke_with_payload(ultra_compact_payload)
                        return {
                            "engine": "langchain",
                            "summary": summary.strip(),
                            "status": f"{status['reason']} (ultra-compact payload retry)",
                            "model": self._config.PHASE2_LLM_MODEL,
                            "base_url": self._config.PHASE2_LLM_BASE_URL,
                        }
                    except Exception:
                        pass
            return {"engine": "deterministic", "summary": fallback_summary, "status": f"LangChain synthesis failed: {exc}"}


async def _attach_summary(workflow: str, objective: str, payload: Dict[str, Any], fallback_summary: str) -> Dict[str, Any]:
    synthesizer = Phase2LangChainSynthesizer()
    llm_payload = _build_llm_contract_payload(workflow, objective, payload)
    orchestration = await synthesizer.summarize(workflow, objective, llm_payload, fallback_summary)
    payload["analysis"] = orchestration["summary"]
    payload["orchestration"] = orchestration
    return payload


async def build_phase2_alert_triage(
    client: WazuhClient,
    time_range: str,
    min_level: int,
    limit: int,
    include_agent_health: bool,
) -> Dict[str, Any]:
    alerts_result = await client.get_alerts(limit=limit, level=f"{min_level}+", timestamp_start=_time_range_to_start(time_range))
    alerts = _affected_items(alerts_result)

    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    rules: Dict[str, Dict[str, Any]] = {}
    agents: Dict[str, Dict[str, Any]] = {}
    source_ips: Dict[str, Dict[str, Any]] = {}

    for alert in alerts:
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        srcip = alert.get("data", {}).get("srcip")
        severity = _severity_bucket(rule.get("level"))
        severity_breakdown[severity] += 1

        rule_id = str(rule.get("id", "unknown"))
        if rule_id not in rules:
            rules[rule_id] = {"rule_id": rule_id, "description": rule.get("description", ""), "level": _safe_int(rule.get("level")), "count": 0}
        rules[rule_id]["count"] += 1

        agent_id = str(agent.get("id", "unknown"))
        if agent_id not in agents:
            agents[agent_id] = {"agent_id": agent_id, "agent_name": agent.get("name", ""), "count": 0}
        agents[agent_id]["count"] += 1

        if srcip:
            if srcip not in source_ips:
                source_ips[srcip] = {"srcip": srcip, "count": 0}
            source_ips[srcip]["count"] += 1

    top_agents = _sort_counts(agents)
    top_rules = _sort_counts(rules)
    top_source_ips = _sort_counts(source_ips)

    hours = _TIME_RANGE_HOURS.get(time_range, 24)
    now = datetime.now(timezone.utc)
    current_start = now - timedelta(hours=hours)
    previous_start = current_start - timedelta(hours=hours)
    previous_window_alerts: List[Dict[str, Any]] = []
    current_window_alerts: List[Dict[str, Any]] = alerts
    compare_error: Optional[str] = None

    try:
        compare_limit = min(max(limit * 4, 100), 1000)
        compare_result = await client.get_alerts(
            limit=compare_limit,
            level=f"{min_level}+",
            timestamp_start=previous_start.isoformat(),
        )
        compare_alerts = _affected_items(compare_result)
        partitioned_current: List[Dict[str, Any]] = []
        partitioned_previous: List[Dict[str, Any]] = []
        for alert in compare_alerts:
            ts = _parse_alert_timestamp(alert.get("timestamp"))
            if not ts:
                continue
            if ts >= current_start:
                partitioned_current.append(alert)
            elif ts >= previous_start:
                partitioned_previous.append(alert)
        if partitioned_current:
            current_window_alerts = partitioned_current
        previous_window_alerts = partitioned_previous
    except Exception as exc:
        compare_error = str(exc)

    changes_over_window = _window_change_summary(current_window_alerts, previous_window_alerts)
    if compare_error:
        changes_over_window["baseline_error"] = compare_error

    severity_breakdown = _severity_breakdown_from_alerts(current_window_alerts)

    pattern_summary = _pattern_summarization(current_window_alerts, top_rules, top_agents, top_source_ips)
    most_important = _build_most_important(current_window_alerts, top_rules, top_agents, top_source_ips)

    agent_health: List[Dict[str, Any]] = []
    if include_agent_health:
        health_targets = [agent for agent in top_agents if agent["agent_id"] != "unknown"]
        health_tasks = [client.check_agent_health(agent["agent_id"]) for agent in health_targets]
        health_results = await asyncio.gather(*health_tasks, return_exceptions=True)
        for agent, result in zip(health_targets, health_results):
            if isinstance(result, Exception):
                agent_health.append({"agent_id": agent["agent_id"], "agent_name": agent["agent_name"], "health": "unknown", "error": str(result)})
            else:
                health_result = cast(Dict[str, Any], result)
                data = health_result.get("data", {})
                agent_health.append({
                    "agent_id": data.get("agent_id", agent["agent_id"]),
                    "agent_name": data.get("name", agent["agent_name"]),
                    "status": data.get("status"),
                    "health": data.get("health", "unknown"),
                    "last_keep_alive": data.get("last_keep_alive"),
                })

    sample_alerts = [_compact_alert(alert) for alert in alerts[:10]]
    escalation_draft = _build_escalation_draft(
        time_range=time_range,
        severity_breakdown=severity_breakdown,
        pattern_summary=pattern_summary,
        top_rules=top_rules,
        top_agents=top_agents,
        sample_alerts=sample_alerts,
    )

    payload = {
        "workflow": "phase2_alert_triage",
        "time_range": time_range,
        "minimum_level": min_level,
        "total_alerts": len(current_window_alerts),
        "severity_breakdown": severity_breakdown,
        "top_rules": top_rules,
        "top_agents": top_agents,
        "top_source_ips": top_source_ips,
        "changes_over_window": changes_over_window,
        "pattern_summary": pattern_summary,
        "most_important": most_important,
        "escalation_draft": escalation_draft,
        "agent_health": agent_health,
        "sample_alerts": sample_alerts,
        "recommended_next_steps": _recommend_triage_actions(severity_breakdown, agent_health),
    }
    payload = await _attach_summary(
        workflow="phase2_alert_triage",
        objective="Prioritize recent Wazuh alerts for analyst review.",
        payload=payload,
        fallback_summary=_deterministic_triage_summary(payload),
    )
    return {"data": payload}


async def build_phase2_context_enrichment(
    client: WazuhClient,
    time_range: str,
    limit: int,
    query: Optional[str] = None,
    rule_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    srcip: Optional[str] = None,
) -> Dict[str, Any]:
    if not any([query, rule_id, agent_id, srcip]):
        raise ValueError("At least one of query, rule_id, agent_id, or srcip is required.")

    recent_matches: List[Dict[str, Any]] = []
    indicator_context: Optional[Dict[str, Any]] = None

    if query:
        matches_result = await client.search_security_events(query=query, time_range=time_range, limit=limit, rule_id=rule_id, agent_id=agent_id, srcip=srcip)
        recent_matches = _affected_items(matches_result)
    elif srcip:
        indicator_context = await client.check_ioc_reputation(srcip, "ip")
        threat_context = await client.analyze_security_threat(srcip, "ip")
        recent_matches = threat_context.get("data", {}).get("alerts", [])
        if rule_id:
            recent_matches = [alert for alert in recent_matches if str(alert.get("rule", {}).get("id")) == str(rule_id)]
        if agent_id:
            recent_matches = [alert for alert in recent_matches if str(alert.get("agent", {}).get("id")) == str(agent_id)]
        recent_matches = recent_matches[:limit]
    else:
        matches_result = await client.get_alerts(limit=limit, rule_id=rule_id, agent_id=agent_id, timestamp_start=_time_range_to_start(time_range))
        recent_matches = _affected_items(matches_result)

    tasks = [client.analyze_alert_patterns(time_range, 2), client.get_top_security_threats(limit=5, time_range=time_range)]
    task_names = ["patterns", "top_threats"]
    if agent_id:
        tasks.extend([client.check_agent_health(agent_id), client.get_vulnerabilities(agent_id=agent_id, limit=10)])
        task_names.extend(["agent_health", "agent_vulnerabilities"])

    results = await asyncio.gather(*tasks, return_exceptions=True)
    sections: Dict[str, Any] = {}
    for name, result in zip(task_names, results):
        if isinstance(result, Exception):
            sections[name] = {"error": str(result)}
        else:
            section_result = cast(Dict[str, Any], result)
            sections[name] = section_result.get("data", section_result)

    candidate_ip = srcip or _extract_ip_from_text(query)
    if not candidate_ip and recent_matches:
        for alert in recent_matches:
            maybe = alert.get("data", {}).get("srcip") or alert.get("data", {}).get("dstip")
            if isinstance(maybe, str) and maybe:
                candidate_ip = maybe
                break

    external_context = await _fetch_external_readonly_context(candidate_ip, time_range)

    recommendations: List[str] = []
    if recent_matches:
        recommendations.append("Review the sample matches and pivot on the dominant rule IDs or source IPs.")
    if agent_id and "agent_vulnerabilities" in sections and not sections["agent_vulnerabilities"].get("error"):
        vuln_count = len(sections["agent_vulnerabilities"].get("affected_items", []))
        if vuln_count:
            recommendations.append("Use vulnerability context to separate exposure issues from active exploitation.")
    if srcip:
        recommendations.append("Check whether the source IP appears across multiple agents or rule groups before escalation.")
    if candidate_ip and "neo4j_attack_chain" in external_context:
        recommendations.append("Use the Neo4j attack-chain output to prioritize the first lateral movement hop for analyst validation.")
    if "opencti_recent_cases" in external_context:
        recommendations.append("Compare matched alerts to recent OpenCTI cases to decide whether to attach to an existing case or open a new incident.")
    if not recommendations:
        recommendations.append("No direct enrichment findings were returned; broaden the time range or add another filter.")

    payload = {
        "workflow": "phase2_context_enrichment",
        "filters": {"time_range": time_range, "query": query, "rule_id": rule_id, "agent_id": agent_id, "srcip": srcip},
        "matching_alerts": [_compact_alert(alert) for alert in recent_matches[:10]],
        "match_count": len(recent_matches),
        "pivot_ip": candidate_ip,
        "indicator_context": indicator_context.get("data") if indicator_context else None,
        "supporting_context": sections,
        "external_read_only_context": external_context,
        "recommended_next_steps": recommendations,
    }
    payload = await _attach_summary(
        workflow="phase2_context_enrichment",
        objective="Combine recent Wazuh alerts with read-only OpenCTI and Neo4j context, then provide an analyst investigation plan.",
        payload=payload,
        fallback_summary=_deterministic_enrichment_summary(payload),
    )
    return {"data": payload}


async def build_phase2_soc_report(
    client: WazuhClient,
    report_type: str,
    time_range: str,
    include_recommendations: bool,
) -> Dict[str, Any]:
    tasks = [
        client.validate_connection(),
        client.get_cluster_health(),
        client.get_running_agents(),
        client.get_alert_summary(time_range, "rule.level"),
        client.get_top_security_threats(limit=5, time_range=time_range),
        client.get_manager_error_logs(limit=20),
        client.get_critical_vulnerabilities(limit=10),
    ]
    task_names = ["connection", "cluster_health", "running_agents", "alert_summary", "top_threats", "manager_errors", "critical_vulnerabilities"]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    sections: Dict[str, Any] = {}
    for name, result in zip(task_names, results):
        sections[name] = {"error": str(result)} if isinstance(result, Exception) else result

    active_agents = len(_affected_items(sections.get("running_agents", {}))) if not sections.get("running_agents", {}).get("error") else 0
    critical_vulns = len(_affected_items(sections.get("critical_vulnerabilities", {}))) if not sections.get("critical_vulnerabilities", {}).get("error") else 0
    top_threats = sections.get("top_threats", {}).get("data", {}).get("threats", []) if not sections.get("top_threats", {}).get("error") else []
    executive_summary = [
        f"Validated Wazuh connectivity for a {report_type} report covering {time_range}.",
        f"Observed {active_agents} active agents in the current environment.",
        f"Identified {len(top_threats)} top threat patterns and {critical_vulns} critical vulnerabilities in the sampled data.",
    ]

    recommendations: List[str] = []
    if include_recommendations:
        if sections.get("connection", {}).get("status") != "connected":
            recommendations.append("Restore stable Wazuh connectivity before trusting the rest of the report.")
        if critical_vulns > 0:
            recommendations.append("Prioritize remediation planning for critical vulnerabilities on exposed agents.")
        if top_threats:
            recommendations.append("Review the top threat rules and hand off the highest scoring items to an analyst queue.")
        if not recommendations:
            recommendations.append("No immediate escalations were derived from the sampled report sections.")

    payload = {
        "workflow": "phase2_soc_report",
        "report_type": report_type,
        "time_range": time_range,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": executive_summary,
        "recommendations": recommendations,
        "escalation_draft": {
            "incident_handoff": " ".join(executive_summary),
            "soc_note": " ".join(recommendations) if recommendations else "No immediate escalation recommendations.",
            "priority": "high" if critical_vulns > 0 else "normal",
        },
        "sections": sections,
    }
    payload = await _attach_summary(
        workflow="phase2_soc_report",
        objective="Generate a read-only SOC handoff report from Wazuh health, threat, and vulnerability signals.",
        payload=payload,
        fallback_summary=_deterministic_report_summary(payload),
    )
    return {"data": payload}


async def build_phase2_proxy_policy_recommendations(
    client: WazuhClient,
    time_range: str,
    focus: str,
    recommendation_types: List[str],
    limit: int,
    run_llm: bool,
    proxy_summary: Optional[Dict[str, Any]] = None,
    proxy_root_cause: Optional[Dict[str, Any]] = None,
    proxy_denied_events: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build policy-tuning recommendations scoped to proxy deny telemetry.

    This tool is intentionally deterministic and proxy-specific. It avoids generic
    SOC handoff recommendations so the policy-tuning UI receives actionable
    masking/discovery guidance tied to denied call patterns.
    """

    # Keep the signature aligned with other Phase 2 builders; client is reserved
    # for future data fetches and environment-specific enrichments.
    _ = client
    summary = proxy_summary if isinstance(proxy_summary, dict) else {}
    root_cause = proxy_root_cause if isinstance(proxy_root_cause, dict) else {}
    denied_events = proxy_denied_events if isinstance(proxy_denied_events, list) else []

    total_denied = int(summary.get("total_denied") or len(denied_events) or 0)
    top_denied_tools = summary.get("top_denied_tools") if isinstance(summary.get("top_denied_tools"), dict) else {}
    deny_reasons = summary.get("deny_reasons") if isinstance(summary.get("deny_reasons"), dict) else {}
    top_client = str(summary.get("top_offending_client") or "").strip() or "unknown"
    attack_pattern = str(root_cause.get("attack_pattern") or "").strip() or "unknown"

    recommendations: List[Dict[str, Any]] = []

    if "masking" in recommendation_types:
        if top_client not in {"unknown", ""} and focus != "underblocking":
            recommendations.append(
                {
                    "title": "Reduce noisy identity leakage in deny telemetry",
                    "type": "masking",
                    "target": "client_ip",
                    "action": "redact",
                    "rationale": (
                        f"Client {top_client} is overrepresented in denied activity ({total_denied} denied calls in scope). "
                        "Redacting client_ip in shared audit views reduces analyst bias while keeping raw values in restricted traces."
                    ),
                    "confidence": 0.72 if total_denied >= 10 else 0.64,
                    "impact": "low",
                    "tool_scope": list(top_denied_tools.keys())[:3],
                    "source": "proxy_policy_tool",
                }
            )

        for tool, count in list(top_denied_tools.items())[:2]:
            if int(count) < 2:
                continue
            recommendations.append(
                {
                    "title": f"Mask sensitive arguments for {tool}",
                    "type": "masking",
                    "target": f"tool_arguments[{tool}]",
                    "action": "hash",
                    "rationale": (
                        f"Tool {tool} produced {count} denied calls in the selected window. "
                        "Hashing argument payloads preserves cross-event correlation without exposing raw values."
                    ),
                    "confidence": min(0.86, 0.55 + (int(count) * 0.04)),
                    "impact": "low",
                    "tool_scope": [tool],
                    "source": "proxy_policy_tool",
                }
            )

        if "argument_validation" in deny_reasons:
            recommendations.append(
                {
                    "title": "Tokenize repeatedly invalid argument fields",
                    "type": "masking",
                    "target": "tool_arguments[*]",
                    "action": "tokenize",
                    "rationale": (
                        "Argument validation denials are recurrent. Tokenizing high-cardinality argument keys helps detect "
                        "probing patterns while avoiding repeated cleartext exposure in policy logs."
                    ),
                    "confidence": 0.61,
                    "impact": "medium",
                    "tool_scope": list(top_denied_tools.keys())[:3],
                    "source": "proxy_policy_tool",
                }
            )

    if "discovery" in recommendation_types:
        if top_denied_tools:
            dominant_tool = next(iter(top_denied_tools.keys()))
            burst_threshold = max(3, min(12, int(total_denied / 4) if total_denied else 5))
            recommendations.append(
                {
                    "title": "Flag repeated deny bursts on dominant tool",
                    "type": "discovery",
                    "target": "discovery_rules.proxy_denials",
                    "signal": "repeated_tool_denials",
                    "action": "monitor" if focus == "overblocking" else "challenge",
                    "rationale": (
                        f"Denied activity is concentrated on {dominant_tool}. Add a burst detector to identify policy probing "
                        "or broken client retry loops earlier in the workflow."
                    ),
                    "confidence": 0.69 if total_denied >= 8 else 0.58,
                    "threshold": f"{burst_threshold} denials in 5 minutes",
                    "action_on_trigger": "notify_and_attach_context",
                    "impact": "medium",
                    "tool_scope": [dominant_tool],
                    "source": "proxy_policy_tool",
                }
            )

        if int(deny_reasons.get("rate_limit", 0)) > 0:
            recommendations.append(
                {
                    "title": "Detect rate-limit evasion attempts",
                    "type": "discovery",
                    "target": "discovery_rules.rate_limit_evasion",
                    "signal": "rate_limit_churn",
                    "action": "monitor",
                    "rationale": (
                        "Rate-limit denials are present in this window. A dedicated discovery rule can separate noisy automation "
                        "from intentional bypass attempts and improve policy tuning precision."
                    ),
                    "confidence": 0.63,
                    "threshold": "3 rate-limit denials from same actor in 10 minutes",
                    "action_on_trigger": "monitor",
                    "impact": "low",
                    "tool_scope": list(top_denied_tools.keys())[:3],
                    "source": "proxy_policy_tool",
                }
            )

        if attack_pattern not in {"", "unknown"}:
            recommendations.append(
                {
                    "title": f"Track denies tied to {attack_pattern}",
                    "type": "discovery",
                    "target": "discovery_rules.attack_pattern_mapping",
                    "signal": "attack_pattern_denials",
                    "action": "challenge" if focus == "underblocking" else "monitor",
                    "rationale": (
                        f"Root-cause analysis labeled the deny trend as {attack_pattern}. "
                        "Mapping this pattern into discovery rules improves explainability and triage handoff quality."
                    ),
                    "confidence": 0.66,
                    "threshold": "5 matching denies in 15 minutes",
                    "action_on_trigger": "challenge",
                    "impact": "medium",
                    "tool_scope": list(top_denied_tools.keys())[:3],
                    "source": "proxy_policy_tool",
                }
            )

    if not recommendations:
        recommendations.append(
            {
                "title": "Collect additional proxy deny samples",
                "type": "discovery",
                "target": "discovery_rules.proxy_baseline",
                "signal": "insufficient_proxy_signal",
                "action": "monitor",
                "rationale": (
                    "Current proxy deny volume is too low for high-confidence policy changes. Expand the time window "
                    "or include more denied events before modifying masking/discovery rules."
                ),
                "confidence": 0.51,
                "threshold": "N/A",
                "action_on_trigger": "monitor",
                "impact": "low",
                "tool_scope": list(top_denied_tools.keys())[:3],
                "source": "proxy_policy_tool",
            }
        )

    payload: Dict[str, Any] = {
        "workflow": "phase2_proxy_policy_recommendations",
        "time_range": time_range,
        "focus": focus,
        "limit": limit,
        "run_llm_requested": run_llm,
        "summary": {
            "total_denied": total_denied,
            "top_denied_tools": top_denied_tools,
            "deny_reasons": deny_reasons,
            "top_offending_client": top_client,
            "attack_pattern": attack_pattern,
        },
        "analysis": (
            f"Generated {len(recommendations)} proxy policy recommendations from denied-call telemetry. "
            f"Focus={focus}, total_denied={total_denied}, dominant_tools={', '.join(list(top_denied_tools.keys())[:3]) or 'none'}."
        ),
        "orchestration": {
            "engine": "policy-deterministic",
            "status": "completed",
            "llm_invoked": False,
        },
        "recommendations": recommendations,
        "recommended_next_steps": [
            "Review rationale and confidence for each recommendation",
            "Validate against known legitimate proxy workflows",
            "Pilot selected changes in staging before production rollout",
        ],
    }
    return {"data": payload}


async def build_phase2_proxy_adaptive_masking_recommendations(
    client: WazuhClient,
    time_range: str,
    mode: str,
    limit: int,
    run_llm: bool,
    tool_filter: Optional[List[str]] = None,
    proxy_summary: Optional[Dict[str, Any]] = None,
    proxy_root_cause: Optional[Dict[str, Any]] = None,
    proxy_denied_events: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build adaptive masking recommendations scoped to proxy deny telemetry.

    The current implementation is deterministic and proxy-specific by design so the
    output remains predictable and auditable for operator review workflows.
    """

    _ = client
    summary = proxy_summary if isinstance(proxy_summary, dict) else {}
    root_cause = proxy_root_cause if isinstance(proxy_root_cause, dict) else {}
    denied_events = proxy_denied_events if isinstance(proxy_denied_events, list) else []

    total_denied = int(summary.get("total_denied") or len(denied_events) or 0)
    top_denied_tools = summary.get("top_denied_tools") if isinstance(summary.get("top_denied_tools"), dict) else {}
    deny_reasons = summary.get("deny_reasons") if isinstance(summary.get("deny_reasons"), dict) else {}
    top_client = str(summary.get("top_offending_client") or "").strip() or "unknown"
    attack_pattern = str(root_cause.get("attack_pattern") or "").strip() or "unknown"

    allowed_tools = {
        str(name).strip().lower()
        for name in (tool_filter or [])
        if isinstance(name, str) and str(name).strip()
    }
    sorted_tools = sorted(
        (
            (str(tool), int(count))
            for tool, count in top_denied_tools.items()
            if (not allowed_tools) or str(tool).strip().lower() in allowed_tools
        ),
        key=lambda item: item[1],
        reverse=True,
    )

    def _sample_argument_keys_for_tool(tool_name: str, max_keys: int = 3) -> List[str]:
        keys: List[str] = []
        seen: set[str] = set()
        for event in denied_events:
            if not isinstance(event, dict):
                continue
            tool = str(event.get("tool") or event.get("tool_name") or "").strip()
            if tool != tool_name:
                continue
            args_obj = event.get("arguments")
            if not isinstance(args_obj, dict):
                params = event.get("params")
                if isinstance(params, dict):
                    args_obj = params.get("arguments")
            if not isinstance(args_obj, dict):
                continue
            for key in args_obj.keys():
                normalized = str(key).strip()
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                keys.append(f"arguments.{normalized}")
                if len(keys) >= max_keys:
                    return keys
        return keys

    recommendations: List[Dict[str, Any]] = []

    if top_client not in {"", "unknown"} and mode == "monitor":
        recommendations.append(
            {
                "tool": "*",
                "argument_path": "client_ip",
                "recommended_mode": "redact",
                "confidence": 0.66 if total_denied >= 10 else 0.58,
                "rationale": (
                    f"Client {top_client} is overrepresented in denied proxy calls ({total_denied} events). "
                    "Redacting client_ip in shared views reduces sensitive exposure without affecting policy enforcement."
                ),
                "examples": ["client_ip"],
                "expected_impact": "low",
                "source": "adaptive_masking_deterministic",
            }
        )

    argument_validation_denies = int(deny_reasons.get("argument_validation", 0) or 0)
    for idx, (tool_name, count) in enumerate(sorted_tools[:5]):
        preferred_mode = "hash"
        if argument_validation_denies > 0 and idx == 0:
            preferred_mode = "tokenize"
        elif count <= 2:
            preferred_mode = "redact"

        sample_keys = _sample_argument_keys_for_tool(tool_name)
        path = sample_keys[0] if sample_keys else "arguments[*]"
        recommendations.append(
            {
                "tool": tool_name,
                "argument_path": path,
                "recommended_mode": preferred_mode,
                "confidence": min(0.89, 0.52 + (count * 0.05)),
                "rationale": (
                    f"Tool {tool_name} generated {count} denied calls in the selected window. "
                    f"Using {preferred_mode} on sensitive argument paths limits data exposure while preserving "
                    "operational triage value."
                ),
                "examples": sample_keys or ["arguments[*]"],
                "expected_impact": "low" if preferred_mode in {"redact", "hash"} else "medium",
                "source": "adaptive_masking_deterministic",
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "tool": "*",
                "argument_path": "arguments[*]",
                "recommended_mode": "redact",
                "confidence": 0.5,
                "rationale": (
                    "Insufficient denied proxy telemetry for targeted adaptive masking suggestions. "
                    "Collect a larger window before applying masking changes."
                ),
                "examples": ["arguments[*]"],
                "expected_impact": "low",
                "source": "adaptive_masking_deterministic",
            }
        )

    payload: Dict[str, Any] = {
        "workflow": "phase2_proxy_adaptive_masking_recommendations",
        "time_range": time_range,
        "mode": mode,
        "limit": limit,
        "run_llm_requested": run_llm,
        "summary": {
            "total_denied": total_denied,
            "top_denied_tools": top_denied_tools,
            "deny_reasons": deny_reasons,
            "top_offending_client": top_client,
            "attack_pattern": attack_pattern,
        },
        "analysis": (
            f"Generated {len(recommendations)} adaptive masking recommendations from proxy deny telemetry. "
            f"Mode={mode}, total_denied={total_denied}, tools_considered={len(sorted_tools)}."
        ),
        "orchestration": {
            "engine": "adaptive-masking-deterministic",
            "status": "completed",
            "llm_invoked": False,
        },
        "recommendations": recommendations,
        "recommended_next_steps": [
            "Review suggested argument paths and masking mode per tool",
            "Validate masking behavior in staging with trace monitoring",
            "Apply changes only after SOC reviewer approval",
        ],
    }
    return {"data": payload}


async def build_phase2_mitre_attack_mapping(
    client: WazuhClient,
    time_range: str,
    min_level: int,
    limit: int,
    query: Optional[str] = None,
    rule_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    srcip: Optional[str] = None,
    include_llm: bool = True,
) -> Dict[str, Any]:
    if query:
        matches_result = await client.search_security_events(
            query=query,
            time_range=time_range,
            limit=limit,
            rule_id=rule_id,
            agent_id=agent_id,
            srcip=srcip,
            level=f"{min_level}+",
        )
        alerts = _affected_items(matches_result)
    else:
        alerts_result = await client.get_alerts(
            limit=limit,
            rule_id=rule_id,
            agent_id=agent_id,
            level=f"{min_level}+",
            timestamp_start=_time_range_to_start(time_range),
        )
        alerts = _affected_items(alerts_result)
        if srcip:
            alerts = [alert for alert in alerts if str(alert.get("data", {}).get("srcip", "")).strip() == srcip]

    candidate_mappings: List[Dict[str, Any]] = []
    for idx, alert in enumerate(alerts):
        candidate_mappings.extend(_extract_rule_mitre_candidates(alert, idx))
        candidate_mappings.extend(_extract_heuristic_mitre_candidates(alert, idx))

    deterministic_mappings = _aggregate_mitre_candidates(candidate_mappings, total_alerts=len(alerts))

    mapping_meta: Dict[str, Any] = {
        "engine": "deterministic",
        "status": "Mapped from rule metadata and deterministic heuristics.",
    }
    final_mappings = deterministic_mappings
    if include_llm and alerts:
        final_mappings, mapping_meta = await _classify_mitre_with_langchain(alerts, deterministic_mappings)

    top_confidence = final_mappings[0]["confidence"] if final_mappings else 0.0
    recommendations: List[str] = []
    if final_mappings:
        recommendations.append("Prioritize validation of top-ranked ATT&CK techniques against endpoint telemetry.")
        recommendations.append("Use mapped techniques to choose the closest matching incident-response playbook.")
        if any(item.get("confidence", 0.0) >= 0.8 for item in final_mappings):
            recommendations.append("Escalate high-confidence technique mappings into analyst handoff notes.")
    else:
        recommendations.append("No MITRE techniques were confidently mapped; broaden filters or include a richer query.")

    payload = {
        "workflow": "phase2_mitre_attack_mapping",
        "filters": {
            "time_range": time_range,
            "min_level": min_level,
            "query": query,
            "rule_id": rule_id,
            "agent_id": agent_id,
            "srcip": srcip,
        },
        "total_alerts_analyzed": len(alerts),
        "mapping_method": mapping_meta,
        "technique_count": len(final_mappings),
        "top_confidence": top_confidence,
        "technique_mappings": final_mappings,
        "sample_alerts": [_compact_alert(alert) for alert in alerts[:10]],
        "recommended_next_steps": recommendations,
    }
    payload = await _attach_summary(
        workflow="phase2_mitre_attack_mapping",
        objective="Produce MITRE ATT&CK technique mapping with confidence scores and rationale from alert context.",
        payload=payload,
        fallback_summary=(
            f"Mapped {payload['total_alerts_analyzed']} alerts to {payload['technique_count']} ATT&CK techniques "
            f"with top confidence {payload['top_confidence']}."
        ),
    )
    return {"data": payload}


# ============================================================================
# Phase 2 — IOC Pivot Engine across Wazuh, OpenCTI, and Neo4j
# ============================================================================

_IOC_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_IOC_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")
_IOC_VALID_TYPES = {"auto", "ip", "domain", "hash", "user"}


def _detect_ioc_type(value: str, hint: str = "auto") -> str:
    """Return the canonical IOC type for ``value`` (ip|domain|hash|user)."""
    if hint and hint != "auto":
        return hint if hint in _IOC_VALID_TYPES else "user"
    raw = (value or "").strip()
    if not raw:
        return "user"
    try:
        ipaddress.ip_address(raw)
        return "ip"
    except ValueError:
        pass
    if _IOC_HASH_RE.match(raw):
        return "hash"
    if _IOC_DOMAIN_RE.match(raw):
        return "domain"
    return "user"


def _ioc_search_query(value: str, ioc_type: str, extra: Optional[str] = None) -> str:
    """Build a Lucene search string that finds ``value`` across common Wazuh fields."""
    safe = (value or "").replace('"', '\\"').strip()
    if not safe:
        return extra or ""
    if ioc_type == "ip":
        clauses = [
            f'data.srcip:"{safe}"',
            f'data.dstip:"{safe}"',
            f'data.src_ip:"{safe}"',
            f'data.dest_ip:"{safe}"',
            f'agent.ip:"{safe}"',
            f'"{safe}"',
        ]
    elif ioc_type == "domain":
        clauses = [
            f'data.url:"{safe}"',
            f'data.hostname:"{safe}"',
            f'data.dns.question.name:"{safe}"',
            f'"{safe}"',
        ]
    elif ioc_type == "hash":
        clauses = [
            f'data.virustotal.malicious:"{safe}"',
            f'data.osquery.columns.sha256:"{safe}"',
            f'data.audit.file.sha256:"{safe}"',
            f'data.win.eventdata.hashes:"{safe}"',
            f'"{safe}"',
        ]
    elif ioc_type == "user":
        clauses = [
            f'data.srcuser:"{safe}"',
            f'data.dstuser:"{safe}"',
            f'data.user:"{safe}"',
            f'data.win.eventdata.targetUserName:"{safe}"',
            f'"{safe}"',
        ]
    else:
        clauses = [f'"{safe}"']
    base = "(" + " OR ".join(clauses) + ")"
    if extra:
        return f"{base} AND ({extra})"
    return base


def _summarize_wazuh_alerts_for_ioc(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute light aggregates for the Wazuh source block of an IOC pivot."""
    rule_ids: Dict[str, int] = defaultdict(int)
    rule_descs: Dict[str, int] = defaultdict(int)
    agents: Dict[str, int] = defaultdict(int)
    levels: Dict[str, int] = defaultdict(int)
    src_ips: Dict[str, int] = defaultdict(int)
    earliest: Optional[str] = None
    latest: Optional[str] = None
    for alert in alerts:
        rule = alert.get("rule") or {}
        agent = alert.get("agent") or {}
        data = alert.get("data") or {}
        rid = str(rule.get("id") or "").strip()
        if rid:
            rule_ids[rid] += 1
        rdesc = str(rule.get("description") or "").strip()
        if rdesc:
            rule_descs[rdesc[:120]] += 1
        aid = str(agent.get("id") or "").strip()
        if aid:
            agents[aid] += 1
        levels[_severity_bucket(rule.get("level"))] += 1
        sip = str(data.get("srcip") or data.get("src_ip") or "").strip()
        if sip:
            src_ips[sip] += 1
        ts = str(alert.get("timestamp") or "").strip()
        if ts:
            if earliest is None or ts < earliest:
                earliest = ts
            if latest is None or ts > latest:
                latest = ts

    def _top(counts: Dict[str, int], n: int = 5) -> List[Dict[str, Any]]:
        return [
            {"value": k, "count": v}
            for k, v in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:n]
        ]

    return {
        "alerts_count": len(alerts),
        "earliest": earliest,
        "latest": latest,
        "severity_breakdown": dict(levels),
        "top_rule_ids": _top(rule_ids),
        "top_rule_descriptions": _top(rule_descs, 3),
        "top_agents": _top(agents),
        "top_source_ips": _top(src_ips, 3),
    }


def _collect_opencti_for_ioc(value: str) -> Dict[str, Any]:
    """Best-effort OpenCTI lookup. Always returns a dict with ``available`` flag."""
    import os

    block: Dict[str, Any] = {"available": False, "queried_value": value}
    opencti_url = (os.getenv("OPENCTI_URL") or "").strip()
    opencti_token = (os.getenv("OPENCTI_API_TOKEN") or "").strip()
    if not opencti_url:
        block["error"] = "OPENCTI_URL is not configured"
        return block
    try:
        from wazuh_mcp_server.phase4.forensics.opencti_client import OpenCTIClient
    except Exception as exc:  # pragma: no cover
        block["error"] = f"opencti_client unavailable: {exc}"
        return block
    try:
        client = OpenCTIClient(opencti_url, opencti_token)
        observables = client.search_observables(value=value, limit=10) or {}
        observable = client.get_observable(value=value) or {}
    except Exception as exc:
        block["error"] = f"OpenCTI query failed: {exc}"
        return block

    obs_list = []
    raw_obs = observables.get("observables") if isinstance(observables, dict) else None
    if isinstance(raw_obs, list):
        obs_list = raw_obs
    elif isinstance(observables, list):
        obs_list = observables

    labels: Dict[str, int] = defaultdict(int)
    tlp: Dict[str, int] = defaultdict(int)
    confidences: List[int] = []
    for item in obs_list[:10]:
        if not isinstance(item, dict):
            continue
        for lab in item.get("labels", []) or []:
            if isinstance(lab, dict) and lab.get("value"):
                labels[str(lab["value"])] += 1
            elif isinstance(lab, str):
                labels[lab] += 1
        for mark in item.get("markings", []) or item.get("objectMarking", []) or []:
            if isinstance(mark, dict):
                tlp[str(mark.get("definition") or "")] += 1
        cval = item.get("confidence")
        if isinstance(cval, (int, float)):
            confidences.append(int(cval))

    block.update(
        {
            "available": True,
            "indicators_count": len(obs_list),
            "top_labels": [{"value": k, "count": v} for k, v in sorted(labels.items(), key=lambda kv: kv[1], reverse=True)[:5]],
            "top_tlp": [{"value": k, "count": v} for k, v in sorted(tlp.items(), key=lambda kv: kv[1], reverse=True)[:3]],
            "max_confidence": max(confidences) if confidences else None,
            "observable_summary": {
                "id": str(observable.get("id") or "") if isinstance(observable, dict) else "",
                "entity_type": str(observable.get("entity_type") or "") if isinstance(observable, dict) else "",
                "value": str(observable.get("observable_value") or value) if isinstance(observable, dict) else value,
            },
            "sample_observables": obs_list[:3],
        }
    )
    return block


def _collect_neo4j_for_ioc(value: str, ioc_type: str, max_hops: int = 5) -> Dict[str, Any]:
    """Best-effort Neo4j lookup. Always returns a dict with ``available`` flag."""
    import os

    block: Dict[str, Any] = {"available": False, "queried_value": value, "ioc_type": ioc_type}
    try:
        from wazuh_mcp_server.phase4.forensics.neo4j_read import Neo4jReadClient
    except Exception as exc:  # pragma: no cover
        block["error"] = f"neo4j_read unavailable: {exc}"
        return block
    http_url = os.getenv("NEO4J_HTTP_URL", "http://phase4-neo4j:7474")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "phase4_admin")
    try:
        nclient = Neo4jReadClient(http_url, user, password)
    except Exception as exc:
        block["error"] = f"Neo4j client init failed: {exc}"
        return block

    try:
        if ioc_type == "ip":
            block["ip_context"] = nclient.ip_context(ip=value)
            block["attack_chain"] = nclient.attack_chain(ip=value, alert_id="", max_hops=max(1, min(6, int(max_hops))))
        elif ioc_type == "user":
            cypher = (
                "MATCH (u:USER {name: $value})-[r]-(n) "
                "RETURN labels(n) AS node_labels, n AS node, type(r) AS rel "
                "LIMIT 50"
            )
            block["user_context"] = nclient.run_read_query(cypher=cypher, params={"value": value})
        elif ioc_type == "hash":
            cypher = (
                "MATCH (f:FILE) "
                "WHERE f.sha256 = $value OR f.md5 = $value OR f.sha1 = $value "
                "OPTIONAL MATCH (f)-[r]-(n) "
                "RETURN f AS file, collect({rel: type(r), node_labels: labels(n), node: n})[0..25] AS related "
                "LIMIT 10"
            )
            block["file_context"] = nclient.run_read_query(cypher=cypher, params={"value": value})
        elif ioc_type == "domain":
            cypher = (
                "MATCH (d:DOMAIN {name: $value})-[r]-(n) "
                "RETURN labels(n) AS node_labels, n AS node, type(r) AS rel "
                "LIMIT 50"
            )
            block["domain_context"] = nclient.run_read_query(cypher=cypher, params={"value": value})
        else:
            cypher = (
                "MATCH (n) WHERE any(prop IN keys(n) WHERE toString(n[prop]) = $value) "
                "RETURN labels(n) AS node_labels, n AS node "
                "LIMIT 25"
            )
            block["generic_context"] = nclient.run_read_query(cypher=cypher, params={"value": value})
        block["available"] = True
    except Exception as exc:
        block["error"] = f"Neo4j query failed: {exc}"
    return block


def _deterministic_ioc_verdict(
    wazuh_summary: Dict[str, Any],
    opencti_block: Dict[str, Any],
    neo4j_block: Dict[str, Any],
) -> Dict[str, Any]:
    """Produce a verdict/severity from deterministic signals only."""
    alerts_count = int(wazuh_summary.get("alerts_count") or 0)
    severity_bucket = wazuh_summary.get("severity_breakdown") or {}
    high_or_crit = int(severity_bucket.get("high") or 0) + int(severity_bucket.get("critical") or 0)
    cti_indicators = int(opencti_block.get("indicators_count") or 0) if opencti_block.get("available") else 0
    cti_max_conf = int(opencti_block.get("max_confidence") or 0) if opencti_block.get("available") else 0
    has_graph = bool(neo4j_block.get("available")) and any(
        neo4j_block.get(k) for k in ("ip_context", "attack_chain", "user_context", "file_context", "domain_context", "generic_context")
    )

    score = 0.0
    rationale_parts: List[str] = []
    if alerts_count > 0:
        score += min(0.4, 0.05 * alerts_count)
        rationale_parts.append(f"{alerts_count} Wazuh alert(s) reference the IOC")
    if high_or_crit > 0:
        score += 0.2
        rationale_parts.append(f"{high_or_crit} alert(s) at high/critical severity")
    if cti_indicators > 0:
        score += 0.2 + min(0.2, cti_max_conf / 100.0)
        rationale_parts.append(f"OpenCTI returned {cti_indicators} matching indicator(s) (max confidence {cti_max_conf})")
    if has_graph:
        score += 0.1
        rationale_parts.append("Neo4j has graph context for the IOC")

    score = min(0.95, max(0.0, score))
    if score >= 0.7:
        verdict, severity = "malicious", "high"
    elif score >= 0.4:
        verdict, severity = "suspicious", "medium"
    elif score > 0.0:
        verdict, severity = "benign", "low"
    else:
        verdict, severity = "unknown", "low"
    return {
        "verdict": verdict,
        "confidence": round(score, 2),
        "severity": severity,
        "rationale": "; ".join(rationale_parts) or "No signals collected for this IOC.",
    }


async def _synthesize_ioc_pivot_with_langchain(
    ioc: Dict[str, Any],
    wazuh_summary: Dict[str, Any],
    sample_alerts: List[Dict[str, Any]],
    opencti_block: Dict[str, Any],
    neo4j_block: Dict[str, Any],
    deterministic: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """LangChain synthesis layer for the IOC pivot. Falls back deterministically."""
    synthesizer = Phase2LangChainSynthesizer()
    status = synthesizer._status()
    if not status.get("enabled"):
        return deterministic, {
            "engine": "deterministic",
            "status": status.get("reason", "LangChain disabled"),
        }
    if ChatPromptTemplate is None or StrOutputParser is None:
        return deterministic, {
            "engine": "deterministic",
            "status": "LangChain prompt/parser dependencies unavailable",
        }
    try:
        prompt_factory = cast(Any, ChatPromptTemplate)
        parser_cls = cast(Any, StrOutputParser)
        prompt = prompt_factory.from_messages(
            [
                (
                    "system",
                    "You are a SOC analyst assistant. Synthesize an IOC pivot across Wazuh, "
                    "OpenCTI, and Neo4j sources. Use only the provided evidence. Return strict "
                    "JSON only.",
                ),
                (
                    "human",
                    "Classify the IOC and produce an analyst-ready summary. "
                    "Return this JSON shape exactly: "
                    "{{\"verdict\":\"malicious|suspicious|benign|unknown\",\"confidence\":0.0,\"severity\":\"low|medium|high|critical\",\"rationale\":\"...\",\"recommended_actions\":[\"...\"]}}.\n"
                    "Rules:\n"
                    "- confidence between 0.0 and 0.99\n"
                    "- recommended_actions: at most 5 short imperative items\n"
                    "- prefer 'unknown' when evidence is empty\n\n"
                    "IOC:\n{ioc}\n\n"
                    "Wazuh summary:\n{wazuh}\n\n"
                    "Sample alerts:\n{alerts}\n\n"
                    "OpenCTI:\n{opencti}\n\n"
                    "Neo4j:\n{neo4j}\n\n"
                    "Deterministic baseline:\n{baseline}",
                ),
            ]
        )
        chain = prompt | synthesizer._create_model() | parser_cls()
        wazuh_payload = _compact_for_llm(wazuh_summary, list_limit=3, dict_key_limit=6, text_limit=100)
        alerts_payload = _compact_for_llm(sample_alerts[:2], list_limit=2, dict_key_limit=6, text_limit=100)
        opencti_payload = _compact_for_llm(opencti_block, list_limit=2, dict_key_limit=6, text_limit=100)
        neo4j_payload = _compact_for_llm(neo4j_block, list_limit=2, dict_key_limit=6, text_limit=100)
        baseline_payload = {
            "verdict": deterministic.get("verdict"),
            "confidence": deterministic.get("confidence"),
            "severity": deterministic.get("severity"),
            "rationale": str(deterministic.get("rationale", ""))[:200],
            "recommended_actions": (deterministic.get("recommended_actions") or [])[:2],
        }
        output = await chain.ainvoke(
            {
                "ioc": json.dumps(ioc, default=str),
                "wazuh": json.dumps(wazuh_payload, default=str),
                "alerts": json.dumps(alerts_payload, default=str),
                "opencti": json.dumps(opencti_payload, default=str),
                "neo4j": json.dumps(neo4j_payload, default=str),
                "baseline": json.dumps(baseline_payload, default=str),
            }
        )
        payload = _extract_json_object(output)

        verdict = str(payload.get("verdict", "unknown")).strip().lower()
        if verdict not in {"malicious", "suspicious", "benign", "unknown"}:
            verdict = "unknown"
        try:
            confidence = float(payload.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(0.99, confidence))
        severity = str(payload.get("severity", "low")).strip().lower()
        if severity not in {"low", "medium", "high", "critical"}:
            severity = "low"
        rationale = str(payload.get("rationale", "")).strip()[:1200]
        actions_raw = payload.get("recommended_actions") or []
        actions = [str(a).strip()[:200] for a in actions_raw if isinstance(a, (str, int, float))][:5]
        if not rationale and not actions:
            raise ValueError("LLM output missing rationale and recommended_actions")

        return (
            {
                "verdict": verdict,
                "confidence": round(confidence, 2),
                "severity": severity,
                "rationale": rationale or deterministic.get("rationale", ""),
                "recommended_actions": actions,
            },
            {
                "engine": "langchain",
                "status": "LangChain IOC pivot synthesis enabled",
                "model": synthesizer._config.PHASE2_LLM_MODEL,
                "base_url": synthesizer._config.PHASE2_LLM_BASE_URL,
            },
        )
    except Exception as exc:  # pragma: no cover
        return deterministic, {
            "engine": "deterministic",
            "status": f"LangChain IOC pivot fallback: {exc}",
        }


async def build_phase2_ioc_pivot(
    client: WazuhClient,
    ioc_value: str,
    ioc_type: str = "auto",
    time_range: str = "24h",
    min_level: int = 5,
    limit: int = 30,
    max_hops: int = 5,
    include_opencti: bool = True,
    include_neo4j: bool = True,
    include_llm: bool = True,
) -> Dict[str, Any]:
    """Phase 2 IOC pivot engine across Wazuh, OpenCTI, and Neo4j.

    Implements the LangChain ``retrieval + synthesis`` pattern: pull evidence
    from each source, then optionally let an LLM produce a verdict + recommended
    actions while keeping a deterministic fallback verdict on errors.
    """
    raw_value = (ioc_value or "").strip()
    detected_type = _detect_ioc_type(raw_value, ioc_type)

    # --- Wazuh retrieval -----------------------------------------------------
    alerts: List[Dict[str, Any]] = []
    if raw_value:
        try:
            search_result = await client.search_security_events(
                query=_ioc_search_query(raw_value, detected_type),
                time_range=time_range,
                limit=max(1, min(100, int(limit))),
                level=f"{min_level}+" if min_level else None,
                srcip=raw_value if detected_type == "ip" else None,
            )
            alerts = _affected_items(search_result)
        except Exception:
            alerts = []
    wazuh_summary = _summarize_wazuh_alerts_for_ioc(alerts)
    wazuh_summary["queried_value"] = raw_value
    wazuh_summary["queried_type"] = detected_type

    # --- OpenCTI retrieval (best-effort, sync — wrapped) --------------------
    if include_opencti and raw_value:
        opencti_block = await asyncio.to_thread(_collect_opencti_for_ioc, raw_value)
    else:
        opencti_block = {"available": False, "skipped": True, "queried_value": raw_value}

    # --- Neo4j retrieval (best-effort, sync — wrapped) ----------------------
    if include_neo4j and raw_value:
        neo4j_block = await asyncio.to_thread(
            _collect_neo4j_for_ioc, raw_value, detected_type, int(max_hops)
        )
    else:
        neo4j_block = {"available": False, "skipped": True, "queried_value": raw_value}

    # --- Synthesis -----------------------------------------------------------
    deterministic = _deterministic_ioc_verdict(wazuh_summary, opencti_block, neo4j_block)
    synthesis_method: Dict[str, Any] = {
        "engine": "deterministic",
        "status": "Deterministic verdict from Wazuh + OpenCTI + Neo4j signals.",
    }
    final_synthesis = dict(deterministic)
    final_synthesis.setdefault("recommended_actions", [])
    if include_llm:
        llm_synthesis, synthesis_method = await _synthesize_ioc_pivot_with_langchain(
            ioc={"value": raw_value, "type": detected_type, "type_hint": ioc_type},
            wazuh_summary=wazuh_summary,
            sample_alerts=[_compact_alert(a) for a in alerts[:6]],
            opencti_block=opencti_block,
            neo4j_block=neo4j_block,
            deterministic=deterministic,
        )
        # Merge: LLM provides verdict/confidence/severity/rationale/recommended_actions;
        # always keep deterministic baseline as a sibling field for auditability.
        if "recommended_actions" not in llm_synthesis:
            llm_synthesis["recommended_actions"] = []
        final_synthesis = llm_synthesis

    next_steps: List[str] = []
    if final_synthesis.get("verdict") in {"malicious", "suspicious"}:
        next_steps.append("Pivot to Phase 3 escalation if scope justifies analyst handoff.")
    if opencti_block.get("available") and (opencti_block.get("indicators_count") or 0) > 0:
        next_steps.append("Open OpenCTI to review analyst notes, TLP, and related campaigns.")
    if neo4j_block.get("available"):
        next_steps.append("Inspect the Neo4j graph for additional pivots (peer IPs, processes, files).")
    if not alerts:
        next_steps.append("Broaden the time window or lower min_level if expecting recent activity.")
    if not next_steps:
        next_steps.append("Re-run with include_llm=true for a richer narrative once a model is reachable.")

    payload: Dict[str, Any] = {
        "workflow": "phase2_ioc_pivot",
        "ioc": {"value": raw_value, "type": detected_type, "type_hint": ioc_type},
        "filters": {
            "time_range": time_range,
            "min_level": min_level,
            "limit": limit,
            "max_hops": max_hops,
            "include_opencti": include_opencti,
            "include_neo4j": include_neo4j,
        },
        "sources": {
            "wazuh": wazuh_summary,
            "opencti": opencti_block,
            "neo4j": neo4j_block,
        },
        "sample_alerts": [_compact_alert(alert) for alert in alerts[:8]],
        "synthesis_method": synthesis_method,
        "verdict": final_synthesis.get("verdict", "unknown"),
        "confidence": final_synthesis.get("confidence", 0.0),
        "severity": final_synthesis.get("severity", "low"),
        "rationale": final_synthesis.get("rationale", ""),
        "recommended_actions": final_synthesis.get("recommended_actions", []),
        "deterministic_baseline": deterministic,
        "recommended_next_steps": next_steps,
    }
    payload = await _attach_summary(
        workflow="phase2_ioc_pivot",
        objective="Pivot an IOC across Wazuh, OpenCTI, and Neo4j and synthesize an analyst-ready verdict.",
        payload=payload,
        fallback_summary=(
            f"IOC {raw_value or '(empty)'} ({detected_type}): verdict={payload['verdict']} "
            f"confidence={payload['confidence']} alerts={wazuh_summary.get('alerts_count', 0)}."
        ),
    )
    return {"data": payload}
