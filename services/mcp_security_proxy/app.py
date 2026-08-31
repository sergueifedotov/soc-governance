#!/usr/bin/env python3
"""Standalone MCP security proxy with dedicated metrics.

This service sits in front of the upstream MCP endpoint and enforces a
policy before forwarding the request. Metrics are intentionally separate from
Wazuh MCP server metrics.
"""

from __future__ import annotations

from collections import deque
import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import Body, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

try:
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_openai import ChatOpenAI
except Exception:  # pragma: no cover - optional dependency path
    ChatOpenAI = None
    HumanMessage = None
    SystemMessage = None

logger = logging.getLogger("mcp_security_proxy")
logging.basicConfig(
    level=os.getenv("MCP_PROXY_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


MCP_PROXY_CALLS_TOTAL = Counter(
    "mcp_security_proxy_calls_total",
    "Total MCP calls observed by the standalone MCP security proxy.",
    ["method", "tool", "decision"],
)

MCP_PROXY_DENIED_TOTAL = Counter(
    "mcp_security_proxy_denied_total",
    "Total denied MCP calls by reason.",
    ["method", "tool", "reason"],
)

MCP_PROXY_UPSTREAM_ERRORS_TOTAL = Counter(
    "mcp_security_proxy_upstream_errors_total",
    "Total upstream forwarding errors by category.",
    ["category"],
)

MCP_PROXY_CALL_DURATION_SECONDS = Histogram(
    "mcp_security_proxy_call_duration_seconds",
    "MCP proxy end-to-end request duration in seconds.",
    ["method", "tool", "decision"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

MCP_PROXY_LLM_RISK_CALLS_TOTAL = Counter(
    "mcp_security_proxy_llm_risk_calls_total",
    "Total pre-call LLM risk scoring evaluations by hint and outcome.",
    ["decision_hint", "outcome"],
)

MCP_PROXY_LLM_RISK_LATENCY_SECONDS = Histogram(
    "mcp_security_proxy_llm_risk_latency_seconds",
    "Latency of pre-call LLM risk scoring.",
    ["decision_hint", "outcome"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

MCP_PROXY_LLM_RISK_SCORE = Histogram(
    "mcp_security_proxy_llm_risk_score",
    "Distribution of pre-call LLM risk scores (0..1).",
    ["decision_hint", "outcome"],
    buckets=(0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0),
)

MCP_PROXY_LLM_RISK_VALUE = Histogram(
    "mcp_security_proxy_llm_risk_value",
    "Distribution of pre-call LLM risk values (0..1); fallback metric for dashboards.",
    ["decision_hint", "outcome"],
    buckets=(0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0),
)

MCP_PROXY_TOOL_INTENT_CALLS_TOTAL = Counter(
    "mcp_security_proxy_tool_intent_calls_total",
    "Total tool-intent verification evaluations by hint and outcome.",
    ["decision_hint", "outcome"],
)

MCP_PROXY_TOOL_INTENT_LATENCY_SECONDS = Histogram(
    "mcp_security_proxy_tool_intent_latency_seconds",
    "Latency of tool-intent verification.",
    ["decision_hint", "outcome"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

MCP_PROXY_TOOL_INTENT_SCORE = Histogram(
    "mcp_security_proxy_tool_intent_score",
    "Distribution of tool-intent mismatch scores (0..1).",
    ["decision_hint", "outcome"],
    buckets=(0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0),
)

MCP_PROXY_DISCOVERY_TRIGGERS_TOTAL = Counter(
    "mcp_security_proxy_discovery_triggers_total",
    "Total discovery rule triggers emitted by signal/action/tool.",
    ["signal", "action", "tool"],
)


class ProxyPolicy:
    def __init__(self, config: Dict[str, Any]):
        self.allowed_methods = set(config.get("allowed_methods", []))
        self.denied_tools = set(config.get("denied_tools", []))
        self.blocked_argument_patterns = [
            re.compile(pattern) for pattern in config.get("blocked_argument_patterns", [])
        ]
        action = str(config.get("blocked_pattern_action", "deny")).strip().lower()
        self.blocked_pattern_action = action if action in {"deny", "challenge"} else "deny"
        self.max_body_bytes = int(config.get("max_body_bytes", 262144))
        self.tool_name_regex = re.compile(config.get("tool_name_regex", r"^[a-zA-Z0-9_:-]{1,120}$"))
        self.llm_risk = config.get("llm_risk") or {}
        self.tool_intent = config.get("tool_intent") or {}
        discovery_rules_raw = config.get("discovery_rules") if isinstance(config.get("discovery_rules"), list) else []
        self.discovery_rules = [rule for rule in discovery_rules_raw if isinstance(rule, dict)]


def _policy_file_path() -> Path:
    return Path(
        os.getenv(
            "MCP_PROXY_POLICY_FILE",
            "/app/config/mcp_proxy/policy.json",
        )
    )


def _load_policy() -> ProxyPolicy:
    file_path = _policy_file_path()
    if not file_path.exists():
        raise RuntimeError(f"MCP proxy policy file not found: {file_path}")
    with file_path.open("r", encoding="utf-8") as f:
        config = json.load(f)
    return ProxyPolicy(config)


def _read_policy_config() -> Dict[str, Any]:
    file_path = _policy_file_path()
    with file_path.open("r", encoding="utf-8") as f:
        loaded = json.load(f)
    if not isinstance(loaded, dict):
        raise RuntimeError("MCP proxy policy file must contain a JSON object")
    return loaded


def _policy_config_summary(config: Dict[str, Any]) -> Dict[str, int]:
    allowed_methods = _normalize_string_list(config.get("allowed_methods"))
    denied_tools = _normalize_string_list(config.get("denied_tools"))
    blocked_patterns = _normalize_string_list(config.get("blocked_argument_patterns"))
    masking_rules_raw = config.get("masking_rules") if isinstance(config.get("masking_rules"), list) else []
    discovery_rules_raw = config.get("discovery_rules") if isinstance(config.get("discovery_rules"), list) else []
    masking_rules = [rule for rule in masking_rules_raw if isinstance(rule, dict)]
    discovery_rules = [rule for rule in discovery_rules_raw if isinstance(rule, dict)]
    return {
        "allowed_methods_count": len(allowed_methods),
        "denied_tool_count": len(denied_tools),
        "blocked_pattern_count": len(blocked_patterns),
        "masking_rule_count": len(masking_rules),
        "discovery_rule_count": len(discovery_rules),
    }


def _write_policy_config(config: Dict[str, Any]) -> None:
    file_path = _policy_file_path()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = file_path.with_suffix(file_path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=True)
        f.write("\n")
    tmp_path.replace(file_path)


def _backup_policy_file() -> Path:
    file_path = _policy_file_path()
    configured_backup_dir = os.getenv("MCP_PROXY_POLICY_BACKUP_DIR", "").strip()
    backup_dir = Path(configured_backup_dir) if configured_backup_dir else file_path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    base_name = f"{file_path.stem}.{stamp}.bak{file_path.suffix}"
    backup_path = backup_dir / base_name
    suffix = 1
    while backup_path.exists():
        backup_path = backup_dir / f"{file_path.stem}.{stamp}.{suffix}.bak{file_path.suffix}"
        suffix += 1

    backup_path.write_bytes(file_path.read_bytes())
    return backup_path


def _normalize_string_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    out: List[str] = []
    seen = set()
    for item in value:
        if not isinstance(item, str):
            continue
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        out.append(normalized)
        seen.add(normalized)
    return out


def _append_unique_dict(items: List[Dict[str, Any]], item: Dict[str, Any]) -> bool:
    for existing in items:
        if existing == item:
            return False
    items.append(item)
    return True


def _policy_bundle_updates(bundle: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    preview = bundle.get("policy_patch_preview") if isinstance(bundle.get("policy_patch_preview"), dict) else {}
    masking_updates = preview.get("masking_updates") if isinstance(preview.get("masking_updates"), list) else []
    discovery_updates = preview.get("discovery_updates") if isinstance(preview.get("discovery_updates"), list) else []

    if masking_updates or discovery_updates:
        return (
            [entry for entry in masking_updates if isinstance(entry, dict)],
            [entry for entry in discovery_updates if isinstance(entry, dict)],
        )

    accepted = bundle.get("accepted_recommendations") if isinstance(bundle.get("accepted_recommendations"), list) else []
    derived_masking: List[Dict[str, Any]] = []
    derived_discovery: List[Dict[str, Any]] = []

    for entry in accepted:
        if not isinstance(entry, dict):
            continue
        rec = entry.get("recommendation") if isinstance(entry.get("recommendation"), dict) else {}
        rec_idx = int(entry.get("recommendation_index", -1)) if str(entry.get("recommendation_index", "")).isdigit() else -1
        rec_type = str(rec.get("type", "")).strip().lower()
        if rec_type == "masking":
            derived_masking.append(
                {
                    "recommendation_index": rec_idx,
                    "target": rec.get("target") or rec.get("field"),
                    "mode": rec.get("mode") or rec.get("action"),
                    "tool_scope": rec.get("tool_scope") if isinstance(rec.get("tool_scope"), list) else [],
                    "confidence": rec.get("confidence"),
                    "rationale": rec.get("rationale") or rec.get("reason"),
                }
            )
        elif rec_type == "discovery":
            derived_discovery.append(
                {
                    "recommendation_index": rec_idx,
                    "signal": rec.get("signal") or rec.get("target"),
                    "threshold": rec.get("threshold"),
                    "action_on_trigger": rec.get("action_on_trigger") or rec.get("action"),
                    "tool_scope": rec.get("tool_scope") if isinstance(rec.get("tool_scope"), list) else [],
                    "confidence": rec.get("confidence"),
                    "rationale": rec.get("rationale") or rec.get("reason"),
                }
            )

    return (derived_masking, derived_discovery)


def _apply_policy_bundle_to_config(config: Dict[str, Any], bundle: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    updated = dict(config)
    masking_rules = [entry for entry in (updated.get("masking_rules") or []) if isinstance(entry, dict)]
    discovery_rules = [entry for entry in (updated.get("discovery_rules") or []) if isinstance(entry, dict)]
    denied_tools = _normalize_string_list(updated.get("denied_tools") or [])

    masking_updates, discovery_updates = _policy_bundle_updates(bundle)

    added_masking = 0
    added_discovery = 0
    added_denied_tools = 0

    for row in masking_updates:
        target = str(row.get("target") or "").strip()
        mode = str(row.get("mode") or row.get("action") or "").strip().lower()
        if not target or not mode:
            continue

        rule = {
            "target": target,
            "mode": mode,
            "tool_scope": _normalize_string_list(row.get("tool_scope") if isinstance(row.get("tool_scope"), list) else []),
            "confidence": row.get("confidence"),
            "rationale": row.get("rationale") or None,
            "source": "policy_tuning_change_bundle",
        }
        if _append_unique_dict(masking_rules, rule):
            added_masking += 1

    for row in discovery_updates:
        signal = str(row.get("signal") or row.get("target") or "").strip()
        action_on_trigger = str(row.get("action_on_trigger") or row.get("action") or "monitor").strip().lower()
        if not signal:
            continue

        tool_scope = _normalize_string_list(row.get("tool_scope") if isinstance(row.get("tool_scope"), list) else [])
        rule = {
            "signal": signal,
            "threshold": row.get("threshold") or None,
            "action_on_trigger": action_on_trigger,
            "tool_scope": tool_scope,
            "confidence": row.get("confidence"),
            "rationale": row.get("rationale") or None,
            "source": "policy_tuning_change_bundle",
        }
        if _append_unique_dict(discovery_rules, rule):
            added_discovery += 1

        if action_on_trigger in {"deny", "quarantine", "challenge"}:
            for tool_name in tool_scope:
                if tool_name not in denied_tools:
                    denied_tools.append(tool_name)
                    added_denied_tools += 1

    updated["masking_rules"] = masking_rules
    updated["discovery_rules"] = discovery_rules
    updated["denied_tools"] = denied_tools

    summary = {
        "added_masking_rules": added_masking,
        "added_discovery_rules": added_discovery,
        "added_denied_tools": added_denied_tools,
        "masking_rule_count": len(masking_rules),
        "discovery_rule_count": len(discovery_rules),
        "denied_tool_count": len(denied_tools),
    }
    return updated, summary


def _reload_policy() -> ProxyPolicy:
    global policy
    global _llm_client
    global _tool_intent_client
    policy = _load_policy()
    with _llm_client_lock:
        _llm_client = None
    with _tool_intent_client_lock:
        _tool_intent_client = None
    return policy


app = FastAPI(title="MCP Security Proxy", version="1.0.0")
policy = _load_policy()

_UPSTREAM_URL = os.getenv("MCP_PROXY_UPSTREAM_URL", "http://wazuh-mcp-server:3000/mcp").strip()
_UPSTREAM_API_KEY = os.getenv("MCP_PROXY_UPSTREAM_API_KEY", "").strip()
_PROXY_API_KEY = os.getenv("MCP_PROXY_API_KEY", "").strip()
_FORWARD_TIMEOUT_SECONDS = float(os.getenv("MCP_PROXY_FORWARD_TIMEOUT_SECONDS", "30"))
_RECENT_DENIED_LIMIT = int(os.getenv("MCP_PROXY_RECENT_DENIED_LIMIT", "200"))
_recent_denied_events: deque = deque(maxlen=_RECENT_DENIED_LIMIT)
_recent_denied_lock = threading.Lock()
_RECENT_DISCOVERY_ALERTS_LIMIT = int(os.getenv("MCP_PROXY_RECENT_DISCOVERY_ALERTS_LIMIT", "200"))
_recent_discovery_alerts: deque = deque(maxlen=_RECENT_DISCOVERY_ALERTS_LIMIT)
_recent_discovery_lock = threading.Lock()
_discovery_last_trigger_ts: Dict[str, float] = {}
_llm_client = None
_llm_client_lock = threading.Lock()
_tool_intent_client = None
_tool_intent_client_lock = threading.Lock()


def _jsonrpc_error(
    request_id: Any,
    code: int,
    message: str,
    http_status: int,
    data: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    body: Dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }
    if data:
        body["error"]["data"] = data
    return JSONResponse(status_code=http_status, content=body)


def _extract_method_and_tool(payload: Dict[str, Any]) -> Tuple[str, str]:
    method = str(payload.get("method", "unknown"))
    params = payload.get("params") or {}
    if not isinstance(params, dict):
        return method, "none"

    tool = "none"
    if method == "tools/call":
        tool = str(params.get("name", "none"))
    return method, tool


def _summarize_arguments(arguments: Any) -> str:
    try:
        rendered = json.dumps(arguments, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return "<unserializable>"
    return rendered[:240] + ("..." if len(rendered) > 240 else "")


def _record_denied_event(
    request_id: Any,
    method: str,
    tool: str,
    reason: str,
    arguments: Any,
    client_ip: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "request_id": "" if request_id is None else str(request_id),
        "method": method,
        "tool": tool,
        "reason": reason,
        "client_ip": client_ip,
        "arguments_summary": _summarize_arguments(arguments),
    }
    if metadata and isinstance(metadata, dict):
        event["metadata"] = metadata
    with _recent_denied_lock:
        _recent_denied_events.appendleft(event)
    return event


def _parse_discovery_threshold(value: Any) -> Tuple[Optional[int], Optional[int], str]:
    text = str(value).strip().lower() if value is not None else ""
    if not text:
        return None, None, ""

    match = re.search(r"(\d+)\s+\w+\s+in\s+(\d+)\s+(second|seconds|minute|minutes|hour|hours)", text)
    if not match:
        return None, None, text

    min_count = int(match.group(1))
    window_value = int(match.group(2))
    unit = match.group(3)
    multiplier = 1
    if unit.startswith("minute"):
        multiplier = 60
    elif unit.startswith("hour"):
        multiplier = 3600
    return min_count, window_value * multiplier, text


def _event_ts_to_epoch(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return time.time()
    try:
        if text.endswith("Z"):
            parsed = time.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
            return float(calendar_timegm(parsed))
    except Exception:
        pass
    return time.time()


def _is_sensitive_write_tool(tool_name: str) -> bool:
    tool = str(tool_name or "").strip().lower()
    if not tool:
        return False
    sensitive_tokens = (
        "write",
        "block",
        "isolate",
        "kill",
        "disable",
        "quarantine",
        "firewall",
        "deny",
        "active_response",
        "restart",
        "delete",
        "remove",
    )
    return any(token in tool for token in sensitive_tokens)


def _signal_event_matches(signal: str, event: Dict[str, Any]) -> bool:
    reason = str(event.get("reason") or "").strip().lower()
    tool = str(event.get("tool") or "").strip().lower()
    if signal == "repeated_tool_denials":
        return bool(reason)
    if signal == "write_tool_abuse":
        if not reason:
            return False
        if reason in {"tool_denied", "method_not_allowed", "llm_risk_deny", "llm_risk_challenge"}:
            return _is_sensitive_write_tool(tool)
        if reason.startswith("blocked_pattern"):
            return _is_sensitive_write_tool(tool)
        return False
    if signal == "attack_pattern_denials":
        if reason.startswith("blocked_pattern"):
            return True
        if reason in {
            "llm_risk_deny",
            "llm_risk_challenge",
            "llm_intent_deny",
            "llm_intent_challenge",
            "tool_denied",
            "method_not_allowed",
        }:
            return True
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        labels = metadata.get("labels") if isinstance(metadata.get("labels"), list) else []
        lowered = {str(item).strip().lower() for item in labels if str(item).strip()}
        return bool(lowered & {"malware", "attack", "probing", "exfiltration", "injection"})
    return False


def _emit_discovery_alert(alert: Dict[str, Any]) -> None:
    with _recent_discovery_lock:
        _recent_discovery_alerts.appendleft(alert)
    MCP_PROXY_DISCOVERY_TRIGGERS_TOTAL.labels(
        signal=str(alert.get("signal") or "unknown"),
        action=str(alert.get("action_on_trigger") or "monitor"),
        tool=str(alert.get("tool") or "*"),
    ).inc()
    logger.warning("mcp_proxy discovery trigger emitted: %s", alert)


def _evaluate_discovery_rules(new_event: Dict[str, Any]) -> None:
    rules = policy.discovery_rules if isinstance(policy.discovery_rules, list) else []
    if not rules:
        return

    now = time.time()
    with _recent_denied_lock:
        snapshot = list(_recent_denied_events)

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        signal = str(rule.get("signal") or "").strip().lower()
        if not signal:
            continue

        min_count, window_seconds, threshold_text = _parse_discovery_threshold(rule.get("threshold"))
        if not min_count or not window_seconds:
            continue

        tool_scope = _normalize_string_list(rule.get("tool_scope") if isinstance(rule.get("tool_scope"), list) else [])
        event_tool = str(new_event.get("tool") or "").strip()
        if tool_scope and event_tool not in tool_scope:
            continue

        window_start = now - float(window_seconds)
        matching = []
        for event in snapshot:
            if not isinstance(event, dict):
                continue
            if _event_ts_to_epoch(event.get("timestamp")) < window_start:
                continue
            tool_name = str(event.get("tool") or "").strip()
            if tool_scope and tool_name not in tool_scope:
                continue
            if not _signal_event_matches(signal, event):
                continue
            matching.append(event)

        observed = len(matching)
        if observed < min_count:
            continue

        action_on_trigger = str(rule.get("action_on_trigger") or rule.get("action") or "monitor").strip().lower()
        dedupe_key = f"{idx}:{signal}:{action_on_trigger}:{','.join(tool_scope) if tool_scope else '*'}"
        last_fired = _discovery_last_trigger_ts.get(dedupe_key, 0.0)
        if (now - last_fired) < float(window_seconds):
            continue
        _discovery_last_trigger_ts[dedupe_key] = now

        top_tool = event_tool or (str(matching[0].get("tool") or "*") if matching else "*")
        reason_counts: Dict[str, int] = {}
        for event in matching:
            reason = str(event.get("reason") or "unknown")
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

        alert = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "signal": signal,
            "threshold": threshold_text,
            "window_seconds": window_seconds,
            "required_count": min_count,
            "observed_count": observed,
            "action_on_trigger": action_on_trigger,
            "tool_scope": tool_scope,
            "tool": top_tool or "*",
            "reason_counts": reason_counts,
            "source": "discovery_rules_runtime",
            "rationale": str(rule.get("rationale") or "").strip(),
            "trigger_event": {
                "request_id": str(new_event.get("request_id") or ""),
                "tool": str(new_event.get("tool") or "*"),
                "reason": str(new_event.get("reason") or "unknown"),
            },
        }
        _emit_discovery_alert(alert)


def _llm_risk_config() -> Dict[str, Any]:
    cfg = policy.llm_risk if isinstance(policy.llm_risk, dict) else {}
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "provider": str(cfg.get("provider", "langchain")).strip().lower() or "langchain",
        "model": str(cfg.get("model", "ai/gemma3-qat:latest")).strip() or "ai/gemma3-qat:latest",
        "base_url": str(cfg.get("base_url", "http://model-runner.docker.internal/engines/v1")).strip(),
        "api_key": str(cfg.get("api_key", os.getenv("MCP_PROXY_LLM_API_KEY", "local-demo"))).strip() or "local-demo",
        "timeout_seconds": float(cfg.get("timeout_seconds", 5)),
        "min_monitor_score": float(cfg.get("min_monitor_score", 0.55)),
        "min_challenge_score": float(cfg.get("min_challenge_score", 0.65)),
        "min_deny_score": float(cfg.get("min_deny_score", 0.69)),
        "enforce": bool(cfg.get("enforce", False)),
        "max_argument_chars": int(cfg.get("max_argument_chars", 2000)),
        "system_prompt": str(
            cfg.get(
                "system_prompt",
                "You are an MCP security risk classifier. Return only compact JSON with keys: "
                "decision_hint, risk_score, labels, rationale. decision_hint must be one of "
                "allow, monitor, challenge, deny. risk_score must be 0..1.",
            )
        ),
    }


def _tool_intent_config() -> Dict[str, Any]:
    cfg = policy.tool_intent if isinstance(policy.tool_intent, dict) else {}
    metadata_keys = cfg.get("metadata_intent_keys") if isinstance(cfg.get("metadata_intent_keys"), list) else ["intent", "declared_intent", "task_intent"]
    normalized_keys = []
    for item in metadata_keys:
        key = str(item).strip()
        if key and key not in normalized_keys:
            normalized_keys.append(key)

    return {
        "enabled": bool(cfg.get("enabled", False)),
        "provider": str(cfg.get("provider", "langchain")).strip().lower() or "langchain",
        "model": str(cfg.get("model", "ai/gemma3-qat:latest")).strip() or "ai/gemma3-qat:latest",
        "base_url": str(cfg.get("base_url", "http://model-runner.docker.internal/engines/v1")).strip(),
        "api_key": str(cfg.get("api_key", os.getenv("MCP_PROXY_LLM_API_KEY", "local-demo"))).strip() or "local-demo",
        "timeout_seconds": float(cfg.get("timeout_seconds", 5)),
        "min_monitor_score": float(cfg.get("min_monitor_score", 0.45)),
        "min_challenge_score": float(cfg.get("min_challenge_score", 0.65)),
        "min_deny_score": float(cfg.get("min_deny_score", 0.82)),
        "enforce": bool(cfg.get("enforce", False)),
        "max_argument_chars": int(cfg.get("max_argument_chars", 2000)),
        "require_intent_metadata": bool(cfg.get("require_intent_metadata", False)),
        "metadata_intent_keys": normalized_keys,
        "system_prompt": str(
            cfg.get(
                "system_prompt",
                "You are an MCP tool-intent verifier. Compare declared intent against selected method/tool/arguments. "
                "Return only compact JSON with keys: decision_hint, intent_score, labels, rationale. "
                "decision_hint must be one of allow, monitor, challenge, deny. "
                "intent_score must be 0..1 where higher means stronger intent mismatch risk.",
            )
        ),
    }


def _build_langchain_client(cfg: Dict[str, Any]) -> Optional[Any]:
    if ChatOpenAI is None:
        return None
    return ChatOpenAI(
        model=cfg["model"],
        base_url=cfg["base_url"],
        api_key=cfg["api_key"],
        timeout=cfg["timeout_seconds"],
        temperature=0,
    )


def _get_llm_client(cfg: Dict[str, Any]) -> Optional[Any]:
    global _llm_client
    if _llm_client is not None:
        return _llm_client
    with _llm_client_lock:
        if _llm_client is None:
            _llm_client = _build_langchain_client(cfg)
    return _llm_client


def _get_tool_intent_client(cfg: Dict[str, Any]) -> Optional[Any]:
    global _tool_intent_client
    if _tool_intent_client is not None:
        return _tool_intent_client
    with _tool_intent_client_lock:
        if _tool_intent_client is None:
            _tool_intent_client = _build_langchain_client(cfg)
    return _tool_intent_client


def _llm_risk_hint_from_score(score: float, cfg: Dict[str, Any]) -> str:
    if score >= cfg["min_deny_score"]:
        return "deny"
    if score >= cfg["min_challenge_score"]:
        return "challenge"
    if score >= cfg["min_monitor_score"]:
        return "monitor"
    return "allow"


def _tool_intent_hint_from_score(score: float, cfg: Dict[str, Any]) -> str:
    if score >= cfg["min_deny_score"]:
        return "deny"
    if score >= cfg["min_challenge_score"]:
        return "challenge"
    if score >= cfg["min_monitor_score"]:
        return "monitor"
    return "allow"


def _extract_declared_intent(method: str, tool: str, params: Dict[str, Any], cfg: Dict[str, Any]) -> str:
    metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}
    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}

    for key in cfg["metadata_intent_keys"]:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    for key in cfg["metadata_intent_keys"]:
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    fallback = metadata.get("justification")
    if isinstance(fallback, str) and fallback.strip():
        return fallback.strip()

    return f"method={method}, tool={tool}"


def _coerce_llm_content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks: List[str] = []
        for item in content:
            if isinstance(item, str):
                chunks.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    chunks.append(text)
        return "\n".join(chunks)
    return str(content)


def _strip_code_fences(text: str) -> str:
    cleaned = text.strip()
    if not cleaned.startswith("```"):
        return cleaned
    lines = cleaned.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _parse_llm_json_object(raw_text: str) -> Dict[str, Any]:
    candidate = _strip_code_fences(raw_text)

    # First attempt: parse the whole payload as-is.
    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    except ValueError:
        pass

    # Second attempt: parse the first JSON object embedded in surrounding text.
    decoder = json.JSONDecoder()
    for idx, ch in enumerate(candidate):
        if ch != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(candidate[idx:])
        except ValueError:
            continue
        if isinstance(obj, dict):
            return obj

    raise ValueError("LLM response does not contain a JSON object")


async def _llm_risk_score(
    method: str,
    tool: str,
    arguments: Any,
    client_ip: str,
) -> Optional[Dict[str, Any]]:
    cfg = _llm_risk_config()
    if not cfg["enabled"]:
        return None

    start = time.time()
    serialized_args = _summarize_arguments(arguments)[: cfg["max_argument_chars"]]
    outcome = "ok"
    decision_hint = "allow"
    risk_score = 0.0

    fallback = {
        "decision_hint": "allow",
        "risk_score": 0.0,
        "labels": [],
        "rationale": "llm_risk_unavailable",
        "engine": "none",
    }

    try:
        if cfg["provider"] != "langchain":
            outcome = "unsupported_provider"
            return fallback
        client = _get_llm_client(cfg)
        if client is None or HumanMessage is None or SystemMessage is None:
            outcome = "langchain_unavailable"
            return fallback

        prompt_payload = {
            "method": method,
            "tool": tool,
            "client_ip": client_ip,
            "arguments": serialized_args,
        }
        msg = [
            SystemMessage(content=cfg["system_prompt"]),
            HumanMessage(content=json.dumps(prompt_payload, ensure_ascii=True)),
        ]
        response = await client.ainvoke(msg)
        raw_text = _coerce_llm_content_to_text(getattr(response, "content", "")).strip()
        if not raw_text:
            raise ValueError("LLM response is empty")
        parsed = _parse_llm_json_object(raw_text)

        score = float(parsed.get("risk_score", 0.0))
        if score < 0:
            score = 0.0
        if score > 1:
            score = 1.0
        risk_score = score
        decision_hint = str(parsed.get("decision_hint", "")).strip().lower()
        if decision_hint not in {"allow", "monitor", "challenge", "deny"}:
            decision_hint = _llm_risk_hint_from_score(score, cfg)

        labels = parsed.get("labels") if isinstance(parsed.get("labels"), list) else []
        rationale = str(parsed.get("rationale", "")).strip()[:500]

        return {
            "decision_hint": decision_hint,
            "risk_score": score,
            "labels": labels,
            "rationale": rationale,
            "engine": "langchain",
        }
    except Exception as exc:
        outcome = "error"
        logger.warning(
            "mcp_proxy llm_risk failure method=%s tool=%s err=%s",
            method,
            tool,
            exc,
        )
        return fallback
    finally:
        elapsed = time.time() - start
        MCP_PROXY_LLM_RISK_CALLS_TOTAL.labels(decision_hint=decision_hint, outcome=outcome).inc()
        MCP_PROXY_LLM_RISK_LATENCY_SECONDS.labels(decision_hint=decision_hint, outcome=outcome).observe(elapsed)
        MCP_PROXY_LLM_RISK_SCORE.labels(decision_hint=decision_hint, outcome=outcome).observe(risk_score)
        MCP_PROXY_LLM_RISK_VALUE.labels(decision_hint=decision_hint, outcome=outcome).observe(risk_score)


async def _tool_intent_score(
    method: str,
    tool: str,
    params: Dict[str, Any],
    client_ip: str,
) -> Optional[Dict[str, Any]]:
    cfg = _tool_intent_config()
    if not cfg["enabled"]:
        return None

    start = time.time()
    outcome = "ok"
    decision_hint = "allow"
    intent_score = 0.0

    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    declared_intent = _extract_declared_intent(method, tool, params, cfg)
    serialized_args = _summarize_arguments(arguments)[: cfg["max_argument_chars"]]

    fallback = {
        "decision_hint": "allow",
        "intent_score": 0.0,
        "labels": [],
        "rationale": "tool_intent_unavailable",
        "engine": "none",
        "declared_intent": declared_intent,
    }

    if cfg["require_intent_metadata"]:
        intent_found = False
        metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}
        for key in cfg["metadata_intent_keys"]:
            if isinstance(metadata.get(key), str) and metadata.get(key).strip():
                intent_found = True
                break
        if not intent_found:
            return {
                "decision_hint": "challenge",
                "intent_score": 1.0,
                "labels": ["missing_intent_metadata"],
                "rationale": "intent metadata required but missing",
                "engine": "deterministic",
                "declared_intent": declared_intent,
            }

    try:
        if cfg["provider"] != "langchain":
            outcome = "unsupported_provider"
            return fallback
        client = _get_tool_intent_client(cfg)
        if client is None or HumanMessage is None or SystemMessage is None:
            outcome = "langchain_unavailable"
            return fallback

        prompt_payload = {
            "method": method,
            "tool": tool,
            "client_ip": client_ip,
            "declared_intent": declared_intent,
            "arguments": serialized_args,
        }
        msg = [
            SystemMessage(content=cfg["system_prompt"]),
            HumanMessage(content=json.dumps(prompt_payload, ensure_ascii=True)),
        ]
        response = await client.ainvoke(msg)
        raw_text = _coerce_llm_content_to_text(getattr(response, "content", "")).strip()
        if not raw_text:
            raise ValueError("LLM response is empty")
        parsed = _parse_llm_json_object(raw_text)

        score = float(parsed.get("intent_score", 0.0))
        if score < 0:
            score = 0.0
        if score > 1:
            score = 1.0
        intent_score = score

        decision_hint = str(parsed.get("decision_hint", "")).strip().lower()
        if decision_hint not in {"allow", "monitor", "challenge", "deny"}:
            decision_hint = _tool_intent_hint_from_score(score, cfg)

        labels = parsed.get("labels") if isinstance(parsed.get("labels"), list) else []
        rationale = str(parsed.get("rationale", "")).strip()[:500]

        return {
            "decision_hint": decision_hint,
            "intent_score": score,
            "labels": labels,
            "rationale": rationale,
            "engine": "langchain",
            "declared_intent": declared_intent,
        }
    except Exception as exc:
        outcome = "error"
        logger.warning(
            "mcp_proxy tool_intent failure method=%s tool=%s err=%s",
            method,
            tool,
            exc,
        )
        return fallback
    finally:
        elapsed = time.time() - start
        MCP_PROXY_TOOL_INTENT_CALLS_TOTAL.labels(decision_hint=decision_hint, outcome=outcome).inc()
        MCP_PROXY_TOOL_INTENT_LATENCY_SECONDS.labels(decision_hint=decision_hint, outcome=outcome).observe(elapsed)
        MCP_PROXY_TOOL_INTENT_SCORE.labels(decision_hint=decision_hint, outcome=outcome).observe(intent_score)


def _validate_or_raise_proxy_auth(authorization: Optional[str]) -> None:
    if not _validate_proxy_auth(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")


def _validate_proxy_auth(authorization: Optional[str]) -> bool:
    if not _PROXY_API_KEY:
        return True
    if not authorization or not authorization.startswith("Bearer "):
        return False
    token = authorization[len("Bearer ") :].strip()
    return token == _PROXY_API_KEY


def _contains_blocked_pattern(arguments: Any) -> Optional[str]:
    try:
        serialized = json.dumps(arguments, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return "arguments_not_serializable"

    for pattern in policy.blocked_argument_patterns:
        if pattern.search(serialized):
            return f"blocked_pattern:{pattern.pattern}"
    return None


def _policy_decision(payload: Dict[str, Any]) -> Tuple[bool, str]:
    method, tool = _extract_method_and_tool(payload)

    if policy.allowed_methods and method not in policy.allowed_methods:
        return False, "method_not_allowed"

    if method == "tools/call":
        params = payload.get("params") or {}
        if not isinstance(params, dict):
            return False, "invalid_params"

        if not policy.tool_name_regex.match(tool):
            return False, "invalid_tool_name"

        if tool in policy.denied_tools:
            return False, "tool_denied"

        blocked_reason = _contains_blocked_pattern(params.get("arguments", {}))
        if blocked_reason:
            if policy.blocked_pattern_action == "challenge":
                return False, blocked_reason.replace("blocked_pattern:", "blocked_pattern_challenge:", 1)
            return False, blocked_reason

    return True, "allow"


def _public_llm_risk_config() -> Dict[str, Any]:
    cfg = _llm_risk_config()
    return {
        "enabled": cfg["enabled"],
        "provider": cfg["provider"],
        "model": cfg["model"],
        "base_url": cfg["base_url"],
        "timeout_seconds": cfg["timeout_seconds"],
        "min_monitor_score": cfg["min_monitor_score"],
        "min_challenge_score": cfg["min_challenge_score"],
        "min_deny_score": cfg["min_deny_score"],
        "enforce": cfg["enforce"],
        "max_argument_chars": cfg["max_argument_chars"],
        "system_prompt": cfg["system_prompt"],
    }


def _public_tool_intent_config() -> Dict[str, Any]:
    cfg = _tool_intent_config()
    return {
        "enabled": cfg["enabled"],
        "provider": cfg["provider"],
        "model": cfg["model"],
        "base_url": cfg["base_url"],
        "timeout_seconds": cfg["timeout_seconds"],
        "min_monitor_score": cfg["min_monitor_score"],
        "min_challenge_score": cfg["min_challenge_score"],
        "min_deny_score": cfg["min_deny_score"],
        "enforce": cfg["enforce"],
        "max_argument_chars": cfg["max_argument_chars"],
        "require_intent_metadata": cfg["require_intent_metadata"],
        "metadata_intent_keys": cfg["metadata_intent_keys"],
        "system_prompt": cfg["system_prompt"],
    }


def _apply_llm_risk_patch(base_cfg: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base_cfg)

    bool_keys = {"enabled", "enforce"}
    str_keys = {"provider", "model", "base_url", "api_key", "system_prompt"}
    float_keys = {
        "timeout_seconds",
        "min_monitor_score",
        "min_challenge_score",
        "min_deny_score",
    }
    int_keys = {"max_argument_chars"}

    for key, value in patch.items():
        if key in bool_keys:
            merged[key] = bool(value)
        elif key in str_keys:
            merged[key] = str(value).strip()
        elif key in float_keys:
            merged[key] = float(value)
        elif key in int_keys:
            merged[key] = int(value)

    for score_key in ("min_monitor_score", "min_challenge_score", "min_deny_score"):
        if score_key in merged:
            score = float(merged[score_key])
            if score < 0:
                score = 0.0
            if score > 1:
                score = 1.0
            merged[score_key] = score

    return merged


def _apply_tool_intent_patch(base_cfg: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base_cfg)

    bool_keys = {"enabled", "enforce", "require_intent_metadata"}
    str_keys = {"provider", "model", "base_url", "api_key", "system_prompt"}
    float_keys = {
        "timeout_seconds",
        "min_monitor_score",
        "min_challenge_score",
        "min_deny_score",
    }
    int_keys = {"max_argument_chars"}

    for key, value in patch.items():
        if key in bool_keys:
            merged[key] = bool(value)
        elif key in str_keys:
            merged[key] = str(value).strip()
        elif key in float_keys:
            merged[key] = float(value)
        elif key in int_keys:
            merged[key] = int(value)
        elif key == "metadata_intent_keys" and isinstance(value, list):
            keys = []
            for item in value:
                item_key = str(item).strip()
                if item_key and item_key not in keys:
                    keys.append(item_key)
            merged[key] = keys

    for score_key in ("min_monitor_score", "min_challenge_score", "min_deny_score"):
        if score_key in merged:
            score = float(merged[score_key])
            if score < 0:
                score = 0.0
            if score > 1:
                score = 1.0
            merged[score_key] = score

    return merged


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "service": "mcp-security-proxy",
        "upstream": _UPSTREAM_URL,
    }


@app.get("/metrics")
async def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/recent-denied")
async def recent_denied_calls(
    limit: int = Query(default=200, ge=1, le=1000),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    with _recent_denied_lock:
        events = list(_recent_denied_events)[:limit]
    return {"count": len(events), "events": events}


@app.get("/recent-discovery-alerts")
async def recent_discovery_alerts(
    limit: int = Query(default=200, ge=1, le=1000),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    with _recent_discovery_lock:
        alerts = list(_recent_discovery_alerts)[:limit]
    return {"count": len(alerts), "alerts": alerts}


@app.post("/admin/clear-discovery-alerts")
async def clear_discovery_alerts(
    payload: dict = Body(default_factory=dict),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    reset_cooldown = bool(payload.get("reset_cooldown", True))
    with _recent_discovery_lock:
        cleared_count = len(_recent_discovery_alerts)
        _recent_discovery_alerts.clear()
        cooldown_entries_cleared = 0
        if reset_cooldown:
            cooldown_entries_cleared = len(_discovery_last_trigger_ts)
            _discovery_last_trigger_ts.clear()

    logger.info(
        "mcp_proxy discovery alerts cleared: alerts=%d reset_cooldown=%s cooldown_entries=%d",
        cleared_count,
        reset_cooldown,
        cooldown_entries_cleared,
    )
    return {
        "status": "ok",
        "cleared_count": cleared_count,
        "reset_cooldown": reset_cooldown,
        "cooldown_entries_cleared": cooldown_entries_cleared,
    }


@app.get("/admin/llm-risk-config")
async def get_llm_risk_config(
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    return {"status": "ok", "llm_risk": _public_llm_risk_config()}


@app.get("/admin/tool-intent-config")
async def get_tool_intent_config(
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    return {"status": "ok", "tool_intent": _public_tool_intent_config()}


@app.get("/admin/policy-config")
async def get_policy_config(
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)

    current = _read_policy_config()
    summary = _policy_config_summary(current)
    masking_rules_raw = current.get("masking_rules") if isinstance(current.get("masking_rules"), list) else []
    discovery_rules_raw = current.get("discovery_rules") if isinstance(current.get("discovery_rules"), list) else []
    masking_rules = [rule for rule in masking_rules_raw if isinstance(rule, dict)]
    discovery_rules = [rule for rule in discovery_rules_raw if isinstance(rule, dict)]
    llm_risk = current.get("llm_risk") if isinstance(current.get("llm_risk"), dict) else {}
    tool_intent = current.get("tool_intent") if isinstance(current.get("tool_intent"), dict) else {}

    return {
        "status": "ok",
        "policy_file": str(_policy_file_path()),
        "raw_policy": current,
        "policy": {
            "allowed_methods": _normalize_string_list(current.get("allowed_methods")),
            "denied_tools": _normalize_string_list(current.get("denied_tools")),
            "blocked_argument_patterns": _normalize_string_list(current.get("blocked_argument_patterns")),
            "data_masking_rules": masking_rules,
            "discovery_rules": discovery_rules,
            "llm_risk": llm_risk,
            "tool_intent": tool_intent,
        },
        "summary": summary,
    }


@app.post("/admin/policy-config")
async def update_policy_config(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)

    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    raw_policy = payload.get("raw_policy")
    if raw_policy is None:
        raw_policy = payload.get("policy")
    if not isinstance(raw_policy, dict):
        raise HTTPException(status_code=400, detail="'raw_policy' must be a JSON object")

    current = _read_policy_config()
    updated = dict(raw_policy)

    if "masking_rules" not in updated and isinstance(updated.get("data_masking_rules"), list):
        updated["masking_rules"] = updated.get("data_masking_rules")

    if "data_masking_rules" in updated and "masking_rules" not in updated:
        updated["masking_rules"] = updated.pop("data_masking_rules")

    backup_path = _backup_policy_file()
    _write_policy_config(updated)
    _reload_policy()

    summary = _policy_config_summary(updated)
    return {
        "status": "ok",
        "message": "policy updated",
        "backup_file": str(backup_path),
        "policy_file": str(_policy_file_path()),
        "raw_policy": updated,
        "summary": summary,
    }


@app.post("/admin/llm-risk-config")
async def update_llm_risk_config(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)

    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    patch = payload.get("llm_risk")
    if not isinstance(patch, dict):
        raise HTTPException(status_code=400, detail="'llm_risk' must be a JSON object")

    current = _read_policy_config()
    current_llm_risk = current.get("llm_risk") if isinstance(current.get("llm_risk"), dict) else {}
    merged_llm_risk = _apply_llm_risk_patch(current_llm_risk, patch)
    current["llm_risk"] = merged_llm_risk

    _write_policy_config(current)
    _reload_policy()

    return {
        "status": "ok",
        "message": "llm_risk policy updated",
        "llm_risk": _public_llm_risk_config(),
    }


@app.post("/admin/tool-intent-config")
async def update_tool_intent_config(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)

    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    patch = payload.get("tool_intent")
    if not isinstance(patch, dict):
        raise HTTPException(status_code=400, detail="'tool_intent' must be a JSON object")

    current = _read_policy_config()
    current_tool_intent = current.get("tool_intent") if isinstance(current.get("tool_intent"), dict) else {}
    merged_tool_intent = _apply_tool_intent_patch(current_tool_intent, patch)
    current["tool_intent"] = merged_tool_intent

    _write_policy_config(current)
    _reload_policy()

    return {
        "status": "ok",
        "message": "tool_intent policy updated",
        "tool_intent": _public_tool_intent_config(),
    }


@app.post("/admin/reload-policy")
async def reload_policy(
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    updated = _reload_policy()
    cfg = updated.llm_risk if isinstance(updated.llm_risk, dict) else {}
    return {
        "status": "ok",
        "message": "policy reloaded",
        "llm_risk": {
            "enabled": bool(cfg.get("enabled", False)),
            "enforce": bool(cfg.get("enforce", False)),
            "min_monitor_score": float(cfg.get("min_monitor_score", 0.55)),
            "min_challenge_score": float(cfg.get("min_challenge_score", 0.65)),
            "min_deny_score": float(cfg.get("min_deny_score", 0.69)),
        },
        "tool_intent": {
            "enabled": bool((updated.tool_intent or {}).get("enabled", False)) if isinstance(updated.tool_intent, dict) else False,
            "enforce": bool((updated.tool_intent or {}).get("enforce", False)) if isinstance(updated.tool_intent, dict) else False,
            "min_monitor_score": float((updated.tool_intent or {}).get("min_monitor_score", 0.45)) if isinstance(updated.tool_intent, dict) else 0.45,
            "min_challenge_score": float((updated.tool_intent or {}).get("min_challenge_score", 0.65)) if isinstance(updated.tool_intent, dict) else 0.65,
            "min_deny_score": float((updated.tool_intent or {}).get("min_deny_score", 0.82)) if isinstance(updated.tool_intent, dict) else 0.82,
        },
    }


@app.post("/admin/apply-policy-bundle")
async def apply_policy_bundle(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)

    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    bundle = payload.get("policy_bundle")
    if not isinstance(bundle, dict):
        raise HTTPException(status_code=400, detail="'policy_bundle' must be a JSON object")

    dry_run = bool(payload.get("dry_run", False))

    current = _read_policy_config()
    updated, summary = _apply_policy_bundle_to_config(current, bundle)

    backup_path = None
    if not dry_run:
        backup_path = _backup_policy_file()
        _write_policy_config(updated)
        _reload_policy()

    return {
        "status": "ok",
        "message": "dry-run apply completed" if dry_run else "policy bundle applied",
        "dry_run": dry_run,
        "backup_file": str(backup_path) if backup_path is not None else None,
        "policy_file": str(_policy_file_path()),
        "summary": summary,
        "applied": not dry_run,
    }


@app.post("/mcp")
async def mcp_proxy(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> JSONResponse:
    request_id: Any = None
    start = time.time()

    body_bytes = await request.body()
    client_ip = request.client.host if request.client and request.client.host else "unknown"

    if len(body_bytes) > policy.max_body_bytes:
        MCP_PROXY_CALLS_TOTAL.labels(method="unknown", tool="none", decision="deny").inc()
        MCP_PROXY_DENIED_TOTAL.labels(method="unknown", tool="none", reason="body_too_large").inc()
        denied_event = _record_denied_event(None, "unknown", "none", "body_too_large", {}, client_ip)
        _evaluate_discovery_rules(denied_event)
        return _jsonrpc_error(None, -32003, "Request denied by MCP proxy policy", 413, {"reason": "body_too_large"})

    if not _validate_proxy_auth(authorization):
        MCP_PROXY_CALLS_TOTAL.labels(method="unknown", tool="none", decision="deny").inc()
        MCP_PROXY_DENIED_TOTAL.labels(method="unknown", tool="none", reason="proxy_auth_failed").inc()
        denied_event = _record_denied_event(None, "unknown", "none", "proxy_auth_failed", {}, client_ip)
        _evaluate_discovery_rules(denied_event)
        return _jsonrpc_error(None, -32001, "Unauthorized", 401, {"reason": "proxy_auth_failed"})

    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        MCP_PROXY_CALLS_TOTAL.labels(method="unknown", tool="none", decision="deny").inc()
        MCP_PROXY_DENIED_TOTAL.labels(method="unknown", tool="none", reason="invalid_json").inc()
        denied_event = _record_denied_event(None, "unknown", "none", "invalid_json", {}, client_ip)
        _evaluate_discovery_rules(denied_event)
        return _jsonrpc_error(None, -32700, "Parse error", 400)

    request_id = payload.get("id")
    method, tool = _extract_method_and_tool(payload)

    allowed, reason = _policy_decision(payload)
    if not allowed:
        elapsed = time.time() - start
        MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
        MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=reason).inc()
        MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
        _denied_params = payload.get("params") or {}
        _denied_req_meta = _denied_params.get("metadata") if isinstance(_denied_params.get("metadata"), dict) else {}
        _denied_pv = _denied_req_meta.get("payload_variant")
        denied_event = _record_denied_event(
            request_id, method, tool, reason,
            _denied_params.get("arguments", {}),
            client_ip,
            metadata={"payload_variant": _denied_pv} if _denied_pv else None,
        )
        _evaluate_discovery_rules(denied_event)
        logger.warning("mcp_proxy deny method=%s tool=%s reason=%s", method, tool, reason)
        if reason.startswith("blocked_pattern_challenge:"):
            return _jsonrpc_error(
                request_id,
                -32003,
                "Request challenged by MCP proxy policy",
                403,
                {"reason": reason, "decision_hint": "challenge"},
            )
        return _jsonrpc_error(
            request_id,
            -32003,
            "Request denied by MCP proxy policy",
            403,
            {"reason": reason},
        )

    params = payload.get("params") or {}
    arguments = params.get("arguments", {}) if isinstance(params, dict) else {}
    _req_metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}
    _payload_variant = _req_metadata.get("payload_variant") or ""
    llm_risk = await _llm_risk_score(method, tool, arguments, client_ip)
    if llm_risk is not None:
        cfg = _llm_risk_config()
        hint = str(llm_risk.get("decision_hint", "allow"))
        score = float(llm_risk.get("risk_score", 0.0))
        labels = llm_risk.get("labels") if isinstance(llm_risk.get("labels"), list) else []
        rationale = str(llm_risk.get("rationale", "")).strip()
        logger.info(
            "mcp_proxy llm_risk method=%s tool=%s hint=%s score=%.3f labels=%s",
            method,
            tool,
            hint,
            score,
            labels,
        )
        if cfg["enforce"] and hint in {"deny", "challenge"}:
            elapsed = time.time() - start
            deny_reason = "llm_risk_deny" if hint == "deny" else "llm_risk_challenge"
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(
                request_id,
                method,
                tool,
                deny_reason,
                arguments,
                client_ip,
                metadata={
                    "risk_score": score,
                    "decision_hint": hint,
                    "labels": labels,
                    "rationale": rationale,
                    "engine": llm_risk.get("engine", "unknown"),
                    **({"payload_variant": _payload_variant} if _payload_variant else {}),
                },
            )

    tool_intent = await _tool_intent_score(method, tool, params if isinstance(params, dict) else {}, client_ip)
    if tool_intent is not None:
        cfg = _tool_intent_config()
        hint = str(tool_intent.get("decision_hint", "allow"))
        score = float(tool_intent.get("intent_score", 0.0))
        labels = tool_intent.get("labels") if isinstance(tool_intent.get("labels"), list) else []
        rationale = str(tool_intent.get("rationale", "")).strip()
        logger.info(
            "mcp_proxy tool_intent method=%s tool=%s hint=%s score=%.3f labels=%s",
            method,
            tool,
            hint,
            score,
            labels,
        )
        if cfg["enforce"] and hint in {"deny", "challenge"}:
            elapsed = time.time() - start
            deny_reason = "llm_intent_deny" if hint == "deny" else "llm_intent_challenge"
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(
                request_id,
                method,
                tool,
                deny_reason,
                arguments,
                client_ip,
                metadata={
                    "intent_score": score,
                    "decision_hint": hint,
                    "labels": labels,
                    "rationale": rationale,
                    "declared_intent": tool_intent.get("declared_intent", ""),
                    "engine": tool_intent.get("engine", "unknown"),
                    **({"payload_variant": _payload_variant} if _payload_variant else {}),
                },
            )
            _evaluate_discovery_rules(denied_event)
            return _jsonrpc_error(
                request_id,
                -32003,
                "Request denied by MCP proxy tool intent policy",
                403,
                {
                    "reason": deny_reason,
                    "intent_score": score,
                    "decision_hint": hint,
                    "labels": labels,
                    "rationale": rationale,
                },
            )
            _evaluate_discovery_rules(denied_event)
            return _jsonrpc_error(
                request_id,
                -32003,
                "Request denied by MCP proxy LLM risk policy",
                403,
                {
                    "reason": deny_reason,
                    "risk_score": score,
                    "decision_hint": hint,
                    "labels": labels,
                    "rationale": rationale,
                },
            )

    headers = {"Content-Type": "application/json"}
    if _UPSTREAM_API_KEY:
        headers["Authorization"] = f"Bearer {_UPSTREAM_API_KEY}"

    try:
        async with httpx.AsyncClient(timeout=_FORWARD_TIMEOUT_SECONDS) as client:
            upstream_response = await client.post(_UPSTREAM_URL, content=body_bytes, headers=headers)
        elapsed = time.time() - start
        decision = "allow"
        if upstream_response.status_code >= 500:
            MCP_PROXY_UPSTREAM_ERRORS_TOTAL.labels(category="upstream_5xx").inc()
            decision = "upstream_error"
        elif upstream_response.status_code >= 400:
            MCP_PROXY_UPSTREAM_ERRORS_TOTAL.labels(category="upstream_4xx").inc()
            decision = "upstream_error"

        MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision=decision).inc()
        MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision=decision).observe(elapsed)

        return JSONResponse(status_code=upstream_response.status_code, content=upstream_response.json())
    except httpx.TimeoutException:
        elapsed = time.time() - start
        MCP_PROXY_UPSTREAM_ERRORS_TOTAL.labels(category="timeout").inc()
        MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="error").inc()
        MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="error").observe(elapsed)
        return _jsonrpc_error(request_id, -32004, "Upstream timeout", 504)
    except Exception as exc:
        elapsed = time.time() - start
        MCP_PROXY_UPSTREAM_ERRORS_TOTAL.labels(category="transport").inc()
        MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="error").inc()
        MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="error").observe(elapsed)
        logger.exception("mcp_proxy forwarding error: %s", exc)
        return _jsonrpc_error(request_id, -32004, "Upstream transport error", 502)
