#!/usr/bin/env python3
"""Standalone MCP security proxy with metrics and lightweight admin UI."""

from __future__ import annotations

import asyncio
from calendar import timegm as calendar_timegm
from collections import deque
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import Body, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

try:
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_openai import ChatOpenAI
except Exception:  # pragma: no cover - optional dependency path
    ChatOpenAI = None
    HumanMessage = None
    SystemMessage = None

from . import __version__
from . import governance as gov

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

MCP_PROXY_USAGE_TOTAL = Counter(
    "mcp_security_proxy_usage_total",
    "Commercial usage counters by tier and kind.",
    ["tier", "kind"],
)

MCP_PROXY_TIER_LIMIT_TOTAL = Counter(
    "mcp_security_proxy_tier_limit_total",
    "Tier limit evaluations by tier, kind, and enforcement.",
    ["tier", "kind", "enforcement"],
)


_EXECUTION_TOOL_DEFAULT_PATTERNS = (
    "exec", "shell", "run_command", "run_script", "command", "cmd",
    "eval", "subprocess", "system", "powershell", "bash", "ssh",
    "python_repl", "interpreter", "sandbox_run",
)

_SANDBOX_ATTESTATION_DEFAULT_MODES = (
    "isolated", "sandboxed", "gvisor", "firecracker", "kata", "wasm",
)

_TRUST_ACTION_CHOICES = {"monitor", "challenge", "deny"}


def _normalize_trust_action(value: Any, default: str) -> str:
    text = str(value or "").strip().lower()
    return text if text in _TRUST_ACTION_CHOICES else default


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

        trusted_servers_raw = config.get("trusted_servers")
        if isinstance(trusted_servers_raw, list):
            self.trusted_servers = {str(item).strip().lower() for item in trusted_servers_raw if str(item).strip()}
        else:
            self.trusted_servers = set()
        self.untrusted_server_action = _normalize_trust_action(config.get("untrusted_server_action"), "deny")

        hashes_raw = config.get("tool_descriptor_hashes") if isinstance(config.get("tool_descriptor_hashes"), dict) else {}
        self.tool_descriptor_hashes = {
            str(name).strip(): str(digest).strip().lower()
            for name, digest in hashes_raw.items()
            if str(name).strip() and str(digest).strip()
        }
        self.descriptor_drift_action = _normalize_trust_action(config.get("descriptor_drift_action"), "deny")

        exec_raw = config.get("execution_tool_profile") if isinstance(config.get("execution_tool_profile"), dict) else {}
        exec_enabled = bool(exec_raw.get("enabled", False))
        exec_patterns_raw = exec_raw.get("patterns")
        if isinstance(exec_patterns_raw, list) and exec_patterns_raw:
            patterns = tuple(str(p).strip().lower() for p in exec_patterns_raw if str(p).strip())
        else:
            patterns = _EXECUTION_TOOL_DEFAULT_PATTERNS
        self.execution_tool_profile = {
            "enabled": exec_enabled,
            "action": _normalize_trust_action(exec_raw.get("action"), "deny"),
            "patterns": patterns,
        }

        attestation_raw = config.get("sandbox_attestation_profile") if isinstance(config.get("sandbox_attestation_profile"), dict) else {}
        attestation_tools_raw = attestation_raw.get("require_for_tools")
        if isinstance(attestation_tools_raw, list) and attestation_tools_raw:
            attestation_patterns = tuple(str(p).strip().lower() for p in attestation_tools_raw if str(p).strip())
        else:
            attestation_patterns = _EXECUTION_TOOL_DEFAULT_PATTERNS
        trusted_issuers_raw = attestation_raw.get("trusted_issuers")
        trusted_issuers = {
            str(v).strip().lower() for v in (trusted_issuers_raw or []) if str(v).strip()
        } if isinstance(trusted_issuers_raw, list) else set()
        allowed_modes_raw = attestation_raw.get("allowed_modes")
        allowed_modes = {
            str(v).strip().lower() for v in (allowed_modes_raw or []) if str(v).strip()
        } if isinstance(allowed_modes_raw, list) and allowed_modes_raw else set(_SANDBOX_ATTESTATION_DEFAULT_MODES)
        self.sandbox_attestation_profile = {
            "enabled": bool(attestation_raw.get("enabled", False)),
            "action": _normalize_trust_action(attestation_raw.get("action"), "deny"),
            "require_for_tools": attestation_patterns,
            "trusted_issuers": trusted_issuers,
            "allowed_modes": allowed_modes,
            "max_age_seconds": int(attestation_raw.get("max_age_seconds", 900)),
            "allow_missing_expiry": bool(attestation_raw.get("allow_missing_expiry", False)),
            "require_pass": bool(attestation_raw.get("require_pass", True)),
        }

        fail_safe_raw = config.get("dependency_fail_safe_profile") if isinstance(config.get("dependency_fail_safe_profile"), dict) else {}
        required_controls_raw = fail_safe_raw.get("required_controls")
        if isinstance(required_controls_raw, list) and required_controls_raw:
            required_controls = [str(v).strip().lower() for v in required_controls_raw if str(v).strip()]
        else:
            required_controls = ["llm_risk", "tool_intent"]
        self.dependency_fail_safe_profile = {
            "enabled": bool(fail_safe_raw.get("enabled", True)),
            "action": _normalize_trust_action(fail_safe_raw.get("action"), "deny"),
            "required_controls": required_controls,
            "require_network_reachability": bool(fail_safe_raw.get("require_network_reachability", True)),
            "health_cache_ttl_seconds": max(1, int(fail_safe_raw.get("health_cache_ttl_seconds", 15))),
            "prevent_silent_bypass": bool(fail_safe_raw.get("prevent_silent_bypass", True)),
        }

        # Sprint 3: Isolated executor profile
        executor_raw = config.get("isolated_executor_profile") if isinstance(config.get("isolated_executor_profile"), dict) else {}
        executor_tools_raw = executor_raw.get("require_for_tools")
        if isinstance(executor_tools_raw, list) and executor_tools_raw:
            executor_patterns = tuple(str(p).strip().lower() for p in executor_tools_raw if str(p).strip())
        else:
            executor_patterns = _EXECUTION_TOOL_DEFAULT_PATTERNS
        self.isolated_executor_profile = {
            "enabled": bool(executor_raw.get("enabled", False)),
            "action": _normalize_trust_action(executor_raw.get("action"), "deny"),
            "executor_url": str(executor_raw.get("executor_url") or "").strip(),
            "fallback_to_upstream": bool(executor_raw.get("fallback_to_upstream", False)),
            "require_for_tools": executor_patterns,
            "forward_on_success": bool(executor_raw.get("forward_on_success", True)),
            "max_retries": max(0, int(executor_raw.get("max_retries", 2))),
            "timeout_seconds": max(1, int(executor_raw.get("timeout_seconds", 60))),
            "runtime_limits": self._parse_runtime_limits(executor_raw.get("runtime_limits")),
            "require_rootless": bool(executor_raw.get("require_rootless", False)),
            "rootless_verification": self._parse_rootless_verification(executor_raw.get("rootless_verification")),
            "filesystem_restrictions": self._parse_filesystem_restrictions(executor_raw.get("filesystem_restrictions")),
        }

        # Sprint 3: Upstream provenance profile
        provenance_raw = config.get("upstream_provenance_profile") if isinstance(config.get("upstream_provenance_profile"), dict) else {}
        allowed_dest_raw = provenance_raw.get("allowed_destinations")
        if isinstance(allowed_dest_raw, list) and allowed_dest_raw:
            allowed_destinations = [str(v).strip().lower() for v in allowed_dest_raw if str(v).strip()]
        else:
            allowed_destinations = []
        blocked_dest_raw = provenance_raw.get("blocked_destinations")
        if isinstance(blocked_dest_raw, list) and blocked_dest_raw:
            blocked_destinations = [str(v).strip().lower() for v in blocked_dest_raw if str(v).strip()]
        else:
            blocked_destinations = []
        egress_patterns_raw = provenance_raw.get("egress_filter_patterns")
        if isinstance(egress_patterns_raw, list) and egress_patterns_raw:
            egress_patterns = [re.compile(p) for p in egress_patterns_raw if isinstance(p, str) and p]
        else:
            egress_patterns = []
        self.upstream_provenance_profile = {
            "enabled": bool(provenance_raw.get("enabled", False)),
            "action": _normalize_trust_action(provenance_raw.get("action"), "deny"),
            "allowed_destinations": allowed_destinations,
            "blocked_destinations": blocked_destinations,
            "require_destination_attestation": bool(provenance_raw.get("require_destination_attestation", True)),
            "max_egress_bytes": max(0, int(provenance_raw.get("max_egress_bytes", 1048576))),
            "log_all_egress": bool(provenance_raw.get("log_all_egress", False)),
            "egress_filter_patterns": egress_patterns,
        }

        commercial_raw = config.get("commercial") if isinstance(config.get("commercial"), dict) else {}
        tier_env = os.getenv("MCP_PROXY_TIER", "").strip().lower()
        license_env = os.getenv("MCP_PROXY_LICENSE_KEY", "").strip()
        tier = tier_env or str(commercial_raw.get("tier", "core")).strip().lower()
        if tier not in {"trial", "core", "enterprise"}:
            tier = "core"
        limits_raw = commercial_raw.get("limits") if isinstance(commercial_raw.get("limits"), dict) else {}
        features_raw = commercial_raw.get("features") if isinstance(commercial_raw.get("features"), dict) else {}
        webhook_raw = commercial_raw.get("webhook") if isinstance(commercial_raw.get("webhook"), dict) else {}
        default_policy_bundles = tier == "enterprise"
        self.commercial = {
            "tier": tier,
            "license_key": license_env or str(commercial_raw.get("license_key", "")).strip(),
            "limits": {
                "max_mcp_calls_per_day": max(0, int(limits_raw.get("max_mcp_calls_per_day", 100000))),
                "max_llm_risk_calls_per_day": max(0, int(limits_raw.get("max_llm_risk_calls_per_day", 50000))),
                "max_tool_intent_calls_per_day": max(0, int(limits_raw.get("max_tool_intent_calls_per_day", 50000))),
                "max_denied_events_retained": max(0, int(limits_raw.get("max_denied_events_retained", 5000))),
            },
            "features": {
                "llm_risk": bool(features_raw.get("llm_risk", True)),
                "tool_intent": bool(features_raw.get("tool_intent", True)),
                "discovery_advanced": bool(features_raw.get("discovery_advanced", tier != "trial")),
                "policy_bundles": bool(features_raw.get("policy_bundles", default_policy_bundles)),
                "webhook_export": bool(features_raw.get("webhook_export", tier != "trial")),
            },
            "webhook": {
                "enabled": bool(webhook_raw.get("enabled", False)),
                "url": str(webhook_raw.get("url", "")).strip(),
                "on_deny": bool(webhook_raw.get("on_deny", True)),
                "timeout_seconds": max(1, int(webhook_raw.get("timeout_seconds", 5))),
            },
        }

        governance_raw = config.get("governance") if isinstance(config.get("governance"), dict) else {}
        self.governance = gov.parse_governance_profile(governance_raw)
        if tier == "enterprise" and not self.governance.get("enabled"):
            self.governance = gov.parse_governance_profile(
                {
                    **governance_raw,
                    "enabled": True,
                    "signing": {
                        **(governance_raw.get("signing") if isinstance(governance_raw.get("signing"), dict) else {}),
                        "enabled": True,
                    },
                    "audit_chain": {
                        **(governance_raw.get("audit_chain") if isinstance(governance_raw.get("audit_chain"), dict) else {}),
                        "enabled": True,
                    },
                }
            )

    @staticmethod
    def _parse_runtime_limits(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {}
        return {
            "max_cpu_seconds": max(0, int(raw.get("max_cpu_seconds", 0))) if raw.get("max_cpu_seconds") else None,
            "max_memory_mb": max(0, int(raw.get("max_memory_mb", 0))) if raw.get("max_memory_mb") else None,
            "max_wall_time_seconds": max(0, int(raw.get("max_wall_time_seconds", 0))) if raw.get("max_wall_time_seconds") else None,
            "max_processes": max(0, int(raw.get("max_processes", 0))) if raw.get("max_processes") else None,
            "max_file_descriptors": max(0, int(raw.get("max_file_descriptors", 0))) if raw.get("max_file_descriptors") else None,
            "max_network_connections": max(-1, int(raw.get("max_network_connections", -1))) if raw.get("max_network_connections") is not None else None,
        }

    @staticmethod
    def _parse_rootless_verification(raw: Any) -> Dict[str, bool]:
        if not isinstance(raw, dict):
            return {"verify_uid": True, "verify_gid": True, "verify_no_new_privs": True, "verify_seccomp": True}
        return {
            "verify_uid": bool(raw.get("verify_uid", True)),
            "verify_gid": bool(raw.get("verify_gid", True)),
            "verify_no_new_privs": bool(raw.get("verify_no_new_privs", True)),
            "verify_seccomp": bool(raw.get("verify_seccomp", True)),
            "verify_apparmor": bool(raw.get("verify_apparmor", False)),
            "verify_selinux": bool(raw.get("verify_selinux", False)),
        }

    @staticmethod
    def _parse_filesystem_restrictions(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {"read_only_root": False, "allow_write_paths": [], "deny_read_paths": [], "deny_write_paths": []}
        allow_write = raw.get("allow_write_paths")
        deny_read = raw.get("deny_read_paths")
        deny_write = raw.get("deny_write_paths")
        required_mounts = raw.get("required_mounts")
        return {
            "read_only_root": bool(raw.get("read_only_root", False)),
            "allow_write_paths": [str(p) for p in allow_write if isinstance(p, (str,)) and p] if isinstance(allow_write, list) else [],
            "deny_read_paths": [str(p) for p in deny_read if isinstance(p, (str,)) and p] if isinstance(deny_read, list) else [],
            "deny_write_paths": [str(p) for p in deny_write if isinstance(p, (str,)) and p] if isinstance(deny_write, list) else [],
            "max_file_size_mb": max(0, int(raw.get("max_file_size_mb", 0))) if raw.get("max_file_size_mb") else None,
            "max_total_size_mb": max(0, int(raw.get("max_total_size_mb", 0))) if raw.get("max_total_size_mb") else None,
            "required_mounts": [str(p) for p in required_mounts if isinstance(p, (str,)) and p] if isinstance(required_mounts, list) else [],
        }


def _policy_file_path() -> Path:
    default_path = Path(__file__).resolve().parent.parent / "config" / "policy.json"
    return Path(os.getenv("MCP_PROXY_POLICY_FILE", str(default_path)))


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


def _write_policy_config(config: Dict[str, Any]) -> None:
    file_path = _policy_file_path()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = file_path.with_suffix(file_path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=True)
        f.write("\n")
    try:
        tmp_path.replace(file_path)
    except OSError:
        with file_path.open("w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=True)
            f.write("\n")
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def _backup_policy_file() -> Path:
    file_path = _policy_file_path()
    backup_dir = file_path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup_path = backup_dir / f"{file_path.stem}.{stamp}.bak{file_path.suffix}"
    suffix = 1
    while backup_path.exists():
        backup_path = backup_dir / f"{file_path.stem}.{stamp}.{suffix}.bak{file_path.suffix}"
        suffix += 1
    backup_path.write_bytes(file_path.read_bytes())
    return backup_path


def _history_file_path() -> Path:
    default_path = Path(__file__).resolve().parent.parent / "data" / "runtime_history.json"
    return Path(os.getenv("MCP_PROXY_HISTORY_FILE", str(default_path)))


def _governance_profile() -> Dict[str, Any]:
    return gov.governance_profile_from_policy(policy)


def _audit_chain_enabled() -> bool:
    audit = _governance_profile().get("audit_chain")
    return bool(_governance_profile().get("enabled")) and bool(
        isinstance(audit, dict) and audit.get("enabled", False)
    )


def _append_audit_chain_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    global _audit_chain_head, _audit_chain_seq
    if not _audit_chain_enabled():
        return event
    with _audit_chain_lock:
        prev = _audit_chain_head
        chain_hash = gov.compute_audit_chain_hash(prev, event)
        _audit_chain_seq += 1
        event = dict(event)
        event["chain_seq"] = _audit_chain_seq
        event["chain_prev"] = prev
        event["chain_hash"] = chain_hash
        _audit_chain_head = chain_hash
    return event


def _persist_runtime_history() -> None:
    with _recent_denied_lock:
        denied_events = list(_recent_denied_events)
    with _recent_decision_lock:
        decision_events = list(_recent_decision_events)
    with _recent_discovery_lock:
        discovery_alerts = list(_recent_discovery_alerts)
    with _audit_chain_lock:
        chain_head = _audit_chain_head

    payload = {
        "recent_denied_events": denied_events,
        "recent_decision_events": decision_events,
        "recent_discovery_alerts": discovery_alerts,
        "discovery_last_trigger_ts": {str(k): float(v) for k, v in _discovery_last_trigger_ts.items()},
        "audit_chain_head": chain_head,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    file_path = _history_file_path()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = file_path.with_suffix(file_path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=True)
        f.write("\n")
    tmp_path.replace(file_path)


def _load_runtime_history() -> None:
    global _audit_chain_head
    file_path = _history_file_path()
    if not file_path.exists():
        return
    try:
        with file_path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as exc:
        logger.warning("mcp_proxy history load failed path=%s err=%s", file_path, exc)
        return

    if isinstance(payload, dict):
        with _audit_chain_lock:
            if payload.get("audit_chain_head"):
                _audit_chain_head = str(payload.get("audit_chain_head"))
            try:
                global _audit_chain_seq
                _audit_chain_seq = max(
                    _audit_chain_seq,
                    max(
                        (int(e.get("chain_seq", 0)) for e in (payload.get("recent_denied_events") or []) if isinstance(e, dict)),
                        default=0,
                    ),
                    max(
                        (int(e.get("chain_seq", 0)) for e in (payload.get("recent_decision_events") or []) if isinstance(e, dict)),
                        default=0,
                    ),
                )
            except (TypeError, ValueError):
                pass

    denied = payload.get("recent_denied_events") if isinstance(payload, dict) else []
    decisions = payload.get("recent_decision_events") if isinstance(payload, dict) else []
    discovery = payload.get("recent_discovery_alerts") if isinstance(payload, dict) else []
    cooldowns = payload.get("discovery_last_trigger_ts") if isinstance(payload, dict) else {}

    with _recent_denied_lock:
        _recent_denied_events.clear()
        for event in denied if isinstance(denied, list) else []:
            if isinstance(event, dict):
                _recent_denied_events.append(event)

    with _recent_decision_lock:
        _recent_decision_events.clear()
        for event in decisions if isinstance(decisions, list) else []:
            if isinstance(event, dict):
                _recent_decision_events.append(event)

    with _recent_discovery_lock:
        _recent_discovery_alerts.clear()
        for alert in discovery if isinstance(discovery, list) else []:
            if isinstance(alert, dict):
                _recent_discovery_alerts.append(alert)

    _discovery_last_trigger_ts.clear()
    if isinstance(cooldowns, dict):
        for key, value in cooldowns.items():
            try:
                _discovery_last_trigger_ts[str(key)] = float(value)
            except (TypeError, ValueError):
                continue

    logger.info(
        "mcp_proxy history restored denied=%d decisions=%d discovery=%d cooldowns=%d",
        len(_recent_denied_events),
        len(_recent_decision_events),
        len(_recent_discovery_alerts),
        len(_discovery_last_trigger_ts),
    )


def _usage_counters_file_path() -> Path:
    default_path = Path(__file__).resolve().parent.parent / "data" / "usage_counters.json"
    return Path(os.getenv("MCP_PROXY_USAGE_COUNTERS_FILE", str(default_path)))


_usage_counters_lock = threading.Lock()
_usage_counters_state: Dict[str, Any] = {"day": "", "counters": {"mcp_calls": 0, "llm_risk_calls": 0, "tool_intent_calls": 0}}


def _today_utc() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def _load_usage_counters() -> Dict[str, Any]:
    global _usage_counters_state
    file_path = _usage_counters_file_path()
    today = _today_utc()
    if file_path.exists():
        try:
            with file_path.open("r", encoding="utf-8") as f:
                payload = json.load(f)
            if isinstance(payload, dict) and payload.get("day") == today:
                counters = payload.get("counters") if isinstance(payload.get("counters"), dict) else {}
                _usage_counters_state = {
                    "day": today,
                    "counters": {
                        "mcp_calls": int(counters.get("mcp_calls", 0)),
                        "llm_risk_calls": int(counters.get("llm_risk_calls", 0)),
                        "tool_intent_calls": int(counters.get("tool_intent_calls", 0)),
                    },
                }
                return dict(_usage_counters_state)
        except Exception as exc:
            logger.warning("mcp_proxy usage counters load failed path=%s err=%s", file_path, exc)
    _usage_counters_state = {"day": today, "counters": {"mcp_calls": 0, "llm_risk_calls": 0, "tool_intent_calls": 0}}
    return dict(_usage_counters_state)


def _persist_usage_counters() -> None:
    file_path = _usage_counters_file_path()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = file_path.with_suffix(file_path.suffix + ".tmp")
    with _usage_counters_lock:
        payload = {
            "day": _usage_counters_state.get("day", _today_utc()),
            "counters": dict(_usage_counters_state.get("counters", {})),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=True)
        f.write("\n")
    tmp_path.replace(file_path)


def _commercial_profile() -> Dict[str, Any]:
    commercial = getattr(policy, "commercial", None)
    return commercial if isinstance(commercial, dict) else {}


def _commercial_tier() -> str:
    return str(_commercial_profile().get("tier", "core")).strip().lower() or "core"


def _commercial_limits() -> Dict[str, int]:
    limits = _commercial_profile().get("limits")
    if not isinstance(limits, dict):
        return {}
    return {str(k): max(0, int(v)) for k, v in limits.items() if str(k).strip()}


def _commercial_features() -> Dict[str, bool]:
    features = _commercial_profile().get("features")
    if not isinstance(features, dict):
        return {}
    return {str(k): bool(v) for k, v in features.items()}


def _feature_enabled(feature_name: str, default: bool = True) -> bool:
    features = _commercial_features()
    if feature_name in features:
        return bool(features[feature_name])
    return default


def _limit_exceeded_enforcement() -> str:
    tier = _commercial_tier()
    if tier == "trial":
        return "monitor"
    return "deny"


def _usage_limit_kind_map() -> Dict[str, str]:
    return {
        "mcp_calls": "max_mcp_calls_per_day",
        "llm_risk_calls": "max_llm_risk_calls_per_day",
        "tool_intent_calls": "max_tool_intent_calls_per_day",
    }


def _check_usage_limit(kind: str) -> Tuple[bool, str, str]:
    """Return (allowed, reason, enforcement) where enforcement is allow|monitor|deny."""
    limits = _commercial_limits()
    limit_key = _usage_limit_kind_map().get(kind)
    if not limit_key:
        return True, "allow", "allow"
    max_value = limits.get(limit_key, 0)
    if max_value <= 0:
        return True, "allow", "allow"
    with _usage_counters_lock:
        if _usage_counters_state.get("day") != _today_utc():
            _usage_counters_state["day"] = _today_utc()
            _usage_counters_state["counters"] = {"mcp_calls": 0, "llm_risk_calls": 0, "tool_intent_calls": 0}
        current = int(_usage_counters_state.get("counters", {}).get(kind, 0))
    if current < max_value:
        return True, "allow", "allow"
    tier = _commercial_tier()
    enforcement = _limit_exceeded_enforcement()
    MCP_PROXY_TIER_LIMIT_TOTAL.labels(tier=tier, kind=kind, enforcement=enforcement).inc()
    return False, "tier_limit_exceeded", enforcement


def _increment_usage_counter(kind: str) -> int:
    tier = _commercial_tier()
    MCP_PROXY_USAGE_TOTAL.labels(tier=tier, kind=kind).inc()
    with _usage_counters_lock:
        if _usage_counters_state.get("day") != _today_utc():
            _usage_counters_state["day"] = _today_utc()
            _usage_counters_state["counters"] = {"mcp_calls": 0, "llm_risk_calls": 0, "tool_intent_calls": 0}
        counters = _usage_counters_state.setdefault("counters", {})
        counters[kind] = int(counters.get(kind, 0)) + 1
        value = int(counters[kind])
    _persist_usage_counters()
    return value


def _public_usage_snapshot() -> Dict[str, Any]:
    state = _load_usage_counters()
    limits = _commercial_limits()
    tier = _commercial_tier()
    counters = state.get("counters") if isinstance(state.get("counters"), dict) else {}
    return {
        "tier": tier,
        "day": state.get("day", _today_utc()),
        "counters": counters,
        "limits": limits,
        "limit_exceeded_enforcement": _limit_exceeded_enforcement(),
    }


def _public_entitlements() -> Dict[str, Any]:
    commercial = _commercial_profile()
    return {
        "tier": _commercial_tier(),
        "license_key_configured": bool(str(commercial.get("license_key", "")).strip()),
        "features": _commercial_features(),
        "limits": _commercial_limits(),
        "webhook": {
            "enabled": bool((commercial.get("webhook") or {}).get("enabled", False)),
            "url_configured": bool(str((commercial.get("webhook") or {}).get("url", "")).strip()),
            "on_deny": bool((commercial.get("webhook") or {}).get("on_deny", True)),
        },
    }


async def _fire_deny_webhook(event: Dict[str, Any]) -> None:
    commercial = _commercial_profile()
    webhook = commercial.get("webhook") if isinstance(commercial.get("webhook"), dict) else {}
    if not _feature_enabled("webhook_export", default=True):
        return
    if not bool(webhook.get("enabled", False)):
        return
    if not bool(webhook.get("on_deny", True)):
        return
    url = str(webhook.get("url", "")).strip()
    if not url:
        return
    timeout = max(1.0, float(webhook.get("timeout_seconds", 5)))
    body = {"event_type": "deny", "event": event, "tier": _commercial_tier(), "service": "mcp-security-proxy"}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            await client.post(url, json=body)
    except Exception as exc:
        logger.warning("mcp_proxy deny webhook failed url=%s err=%s", url, exc)


def _schedule_deny_webhook(event: Dict[str, Any]) -> None:
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_fire_deny_webhook(event))
    except RuntimeError:
        pass


def _audit_integrity_snapshot(
    denied_events: Optional[List[Dict[str, Any]]] = None,
    decision_events: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    if denied_events is None:
        with _recent_denied_lock:
            denied_events = list(_recent_denied_events)
    if decision_events is None:
        with _recent_decision_lock:
            decision_events = list(_recent_decision_events)
    chained = [e for e in (denied_events + decision_events) if isinstance(e, dict) and e.get("chain_hash")]
    with _audit_chain_lock:
        chain_head = _audit_chain_head
    verification = (
        gov.verify_audit_chain(chained, chain_head=chain_head)
        if chained
        else {"valid": True, "verified_events": 0}
    )
    return {
        "audit_chain_enabled": _audit_chain_enabled(),
        "chain_head": chain_head,
        "chained_event_count": len(chained),
        "verification": verification,
    }


def _build_audit_export_payload() -> Dict[str, Any]:
    with _recent_denied_lock:
        denied_events = list(_recent_denied_events)
    with _recent_decision_lock:
        decision_events = list(_recent_decision_events)
    with _recent_discovery_lock:
        discovery_alerts = list(_recent_discovery_alerts)
    file_path = _history_file_path()
    return {
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "service": "mcp-security-proxy",
        "version": __version__,
        "tier": _commercial_tier(),
        "history_file": str(file_path),
        "history_file_exists": file_path.exists(),
        "counts": {
            "denied_events": len(denied_events),
            "decision_events": len(decision_events),
            "discovery_alerts": len(discovery_alerts),
        },
        "recent_denied_events": denied_events,
        "recent_decision_events": decision_events,
        "recent_discovery_alerts": discovery_alerts,
        "usage": _public_usage_snapshot(),
        "governance": gov.public_governance_status(_governance_profile()),
        "integrity": _audit_integrity_snapshot(denied_events, decision_events),
    }


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


def _policy_config_summary(config: Dict[str, Any]) -> Dict[str, int]:
    return {
        "allowed_methods_count": len(_normalize_string_list(config.get("allowed_methods"))),
        "denied_tool_count": len(_normalize_string_list(config.get("denied_tools"))),
        "blocked_pattern_count": len(_normalize_string_list(config.get("blocked_argument_patterns"))),
        "masking_rule_count": len([r for r in config.get("masking_rules", []) if isinstance(r, dict)]),
        "discovery_rule_count": len([r for r in config.get("discovery_rules", []) if isinstance(r, dict)]),
    }


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


def _reload_policy() -> ProxyPolicy:
    global policy
    global _llm_client
    global _tool_intent_client
    global _dependency_health_cache
    policy = _load_policy()
    with _llm_client_lock:
        _llm_client = None
    with _tool_intent_client_lock:
        _tool_intent_client = None
    with _dependency_health_cache_lock:
        _dependency_health_cache = {}
    return policy


app = FastAPI(title="MCP Security Proxy", version=__version__)
policy = _load_policy()

_cors_origins_raw = os.getenv(
    "MCP_PROXY_CORS_ALLOW_ORIGINS",
    "http://localhost:8082,http://127.0.0.1:8082,http://localhost:8090,http://127.0.0.1:8090",
)
_cors_allow_origins = [origin.strip() for origin in _cors_origins_raw.split(",") if origin.strip()]
if _cors_allow_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_allow_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

_UPSTREAM_URL = os.getenv("MCP_PROXY_UPSTREAM_URL", "http://host.docker.internal:3000/mcp").strip()
_UPSTREAM_API_KEY = os.getenv("MCP_PROXY_UPSTREAM_API_KEY", "").strip()
_PROXY_API_KEY = os.getenv("MCP_PROXY_API_KEY", "").strip()
_FORWARD_TIMEOUT_SECONDS = float(os.getenv("MCP_PROXY_FORWARD_TIMEOUT_SECONDS", "30"))
_RECENT_DENIED_LIMIT = int(os.getenv("MCP_PROXY_RECENT_DENIED_LIMIT", "200"))
_recent_denied_events: deque = deque(maxlen=_RECENT_DENIED_LIMIT)
_recent_denied_lock = threading.Lock()
_RECENT_DECISION_LIMIT = int(os.getenv("MCP_PROXY_RECENT_DECISION_LIMIT", "5000"))
_DECISION_EVENT_RATIONALE_MAX = int(os.getenv("MCP_PROXY_DECISION_RATIONALE_MAX", "2000"))
_recent_decision_events: deque = deque(maxlen=_RECENT_DECISION_LIMIT)
_recent_decision_lock = threading.Lock()
_RECENT_DISCOVERY_ALERTS_LIMIT = int(os.getenv("MCP_PROXY_RECENT_DISCOVERY_ALERTS_LIMIT", "200"))
_recent_discovery_alerts: deque = deque(maxlen=_RECENT_DISCOVERY_ALERTS_LIMIT)
_recent_discovery_lock = threading.Lock()
_discovery_last_trigger_ts: Dict[str, float] = {}
_DISCOVERY_ALERT_COOLDOWN_SECONDS = float(os.getenv("MCP_PROXY_DISCOVERY_ALERT_COOLDOWN_SECONDS", "120"))
_llm_client = None
_llm_client_lock = threading.Lock()
_tool_intent_client = None
_tool_intent_client_lock = threading.Lock()
_dependency_health_cache: Dict[str, Dict[str, Any]] = {}
_dependency_health_cache_lock = threading.Lock()
_audit_chain_head = "genesis"
_audit_chain_seq = 0
_audit_chain_lock = threading.Lock()

_load_runtime_history()
_load_usage_counters()

static_dir = Path(__file__).resolve().parent / "ui" / "static"
if static_dir.exists():
    app.mount("/ui/static", StaticFiles(directory=str(static_dir)), name="ui-static")


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
    tool = str(params.get("name", "none")) if method == "tools/call" else "none"
    return method, tool


def _summarize_arguments(arguments: Any) -> str:
    try:
        rendered = json.dumps(arguments, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return "<unserializable>"
    return rendered[:240] + ("..." if len(rendered) > 240 else "")


def _argument_keys(arguments: Any) -> List[str]:
    if isinstance(arguments, dict):
        return [str(k) for k in arguments.keys()]
    if isinstance(arguments, list):
        return [str(i) for i in range(len(arguments))]
    return []


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
    event = _append_audit_chain_fields(event)
    with _recent_denied_lock:
        _recent_denied_events.appendleft(event)
    _persist_runtime_history()
    _schedule_deny_webhook(event)
    return event


def _record_decision_event(
    *,
    stage: str,
    decision: str,
    method: str,
    tool: str,
    reason: str,
    client_ip: str,
    request_id: Any = None,
    score: Optional[float] = None,
    labels: Optional[List[str]] = None,
    rationale: Optional[str] = None,
    enforce: Optional[bool] = None,
    status_code: Optional[int] = None,
    elapsed_ms: Optional[int] = None,
    args_keys: Optional[List[str]] = None,
    auth_subject: Optional[str] = None,
    executor_evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    event: Dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "request_id": "" if request_id is None else str(request_id),
        "stage": stage,
        "decision": decision,
        "method": method,
        "tool": tool,
        "reason": reason,
        "client_ip": client_ip,
    }
    if score is not None:
        event["score"] = round(float(score), 3)
    if labels:
        event["labels"] = [str(v) for v in labels if str(v).strip()]
    if rationale:
        event["rationale"] = str(rationale)[:_DECISION_EVENT_RATIONALE_MAX]
    if enforce is not None:
        event["enforce"] = bool(enforce)
    if status_code is not None:
        event["status_code"] = int(status_code)
    if elapsed_ms is not None:
        event["elapsed_ms"] = int(elapsed_ms)
    if args_keys:
        event["args_keys"] = [str(v) for v in args_keys if str(v).strip()]
    if auth_subject:
        event["auth_subject"] = str(auth_subject)
    if isinstance(executor_evidence, dict) and executor_evidence:
        event["executor_evidence"] = executor_evidence
    event = _append_audit_chain_fields(event)
    with _recent_decision_lock:
        _recent_decision_events.appendleft(event)
    _persist_runtime_history()
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


def _default_discovery_threshold(signal: str) -> Tuple[int, int, str]:
        normalized = str(signal or "").strip().lower()
        if normalized == "repeated_tool_denials":
            return 2, 3600, "2 events in 1 hour (default)"
        if normalized == "write_tool_abuse":
            return 1, 3600, "1 event in 1 hour (default)"
        if normalized == "attack_pattern_denials":
            return 1, 3600, "1 event in 1 hour (default)"
        if normalized == "untrusted_server_calls":
            return 1, 3600, "1 event in 1 hour (default)"
        if normalized == "descriptor_drift_events":
            return 1, 3600, "1 event in 1 hour (default)"
        if normalized == "execution_tool_attempts":
            return 1, 3600, "1 event in 1 hour (default)"
        if normalized == "sandbox_attestation_failures":
            return 1, 3600, "1 event in 1 hour (default)"
        if normalized == "dependency_health_failures":
            return 1, 3600, "1 event in 1 hour (default)"
        if normalized == "security_layer_bypass_attempts":
            return 1, 3600, "1 event in 1 hour (default)"
        return 1, 3600, "1 event in 1 hour (default)"


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


def _parse_iso_or_epoch(value: Any) -> Optional[float]:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return float(text)
    except (TypeError, ValueError):
        pass
    try:
        if text.endswith("Z"):
            parsed = time.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
            return float(calendar_timegm(parsed))
    except Exception:
        return None
    return None


def _time_range_to_seconds(value: Any, default_seconds: int = 86400) -> int:
    text = str(value or "").strip().lower()
    if not text:
        return int(default_seconds)
    match = re.match(r"^(\d+)\s*([smhd]?)$", text)
    if not match:
        return int(default_seconds)
    amount = int(match.group(1))
    unit = match.group(2) or "h"
    multiplier = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
    }.get(unit, 3600)
    return max(1, amount * multiplier)


def _is_sensitive_write_tool(tool_name: str) -> bool:
    tool = str(tool_name or "").strip().lower()
    sensitive_tokens = (
        "write", "block", "isolate", "kill", "disable", "quarantine", "firewall", "deny",
        "active_response", "restart", "delete", "remove",
    )
    return bool(tool) and any(token in tool for token in sensitive_tokens)


def _is_execution_like_tool(tool_name: str) -> bool:
    profile = policy.execution_tool_profile if isinstance(policy.execution_tool_profile, dict) else {}
    if not profile.get("enabled"):
        return False
    tool = str(tool_name or "").strip().lower()
    if not tool:
        return False
    patterns = profile.get("patterns") or _EXECUTION_TOOL_DEFAULT_PATTERNS
    return any(p and p in tool for p in patterns)


def _tool_matches_any_pattern(tool_name: str, patterns: Any) -> bool:
    tool = str(tool_name or "").strip().lower()
    if not tool:
        return False
    if not isinstance(patterns, (list, tuple, set)):
        return False
    return any(str(p).strip().lower() in tool for p in patterns if str(p).strip())


def _extract_sandbox_attestation(params: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(params, dict):
        return None
    metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}
    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    for container in (metadata, arguments):
        value = container.get("sandbox_attestation")
        if isinstance(value, dict):
            return value
    return None


def _sandbox_attestation_check(method: str, tool: str, params: Any) -> Tuple[bool, str, Dict[str, Any]]:
    profile = policy.sandbox_attestation_profile if isinstance(policy.sandbox_attestation_profile, dict) else {}
    if method != "tools/call" or not profile.get("enabled"):
        return True, "allow", {}
    if not _tool_matches_any_pattern(tool, profile.get("require_for_tools")):
        return True, "allow", {}

    att = _extract_sandbox_attestation(params)
    if not isinstance(att, dict):
        return False, "sandbox_attestation_missing", {"error": "missing_attestation"}

    now = time.time()
    issuer = str(att.get("issuer") or "").strip().lower()
    mode = str(att.get("mode") or att.get("sandbox_mode") or "").strip().lower()
    status_raw = str(att.get("status") or att.get("result") or "").strip().lower()
    verified = att.get("verified")
    expires_ts = _parse_iso_or_epoch(att.get("expires_at") or att.get("exp"))
    issued_ts = _parse_iso_or_epoch(att.get("issued_at") or att.get("iat"))

    trusted_issuers = profile.get("trusted_issuers") if isinstance(profile.get("trusted_issuers"), set) else set()
    allowed_modes = profile.get("allowed_modes") if isinstance(profile.get("allowed_modes"), set) else set()
    require_pass = bool(profile.get("require_pass", True))
    allow_missing_expiry = bool(profile.get("allow_missing_expiry", False))
    max_age_seconds = max(1, int(profile.get("max_age_seconds", 900)))

    if trusted_issuers and issuer not in trusted_issuers:
        return False, "sandbox_attestation_invalid", {"error": "issuer_not_trusted", "issuer": issuer}
    if allowed_modes and mode not in allowed_modes:
        return False, "sandbox_attestation_invalid", {"error": "sandbox_mode_not_allowed", "mode": mode}
    if require_pass:
        status_ok = status_raw in {"ok", "pass", "passed", "verified", "valid", "success"}
        verified_ok = isinstance(verified, bool) and verified
        if not (status_ok or verified_ok):
            return False, "sandbox_attestation_invalid", {"error": "attestation_not_verified", "status": status_raw}
    if expires_ts is None and not allow_missing_expiry:
        return False, "sandbox_attestation_invalid", {"error": "missing_expiry"}
    if expires_ts is not None and expires_ts <= now:
        return False, "sandbox_attestation_invalid", {"error": "attestation_expired"}
    if issued_ts is not None and (now - issued_ts) > max_age_seconds:
        return False, "sandbox_attestation_invalid", {"error": "attestation_too_old", "max_age_seconds": max_age_seconds}

    return True, "allow", {
        "issuer": issuer,
        "mode": mode,
        "expires_at": att.get("expires_at") or att.get("exp"),
    }


async def _probe_dependency_reachability(url: str, timeout_seconds: float, ttl_seconds: int) -> Tuple[bool, str]:
    candidate = str(url or "").strip().rstrip("/")
    if not candidate:
        return False, "missing_base_url"
    now = time.time()
    with _dependency_health_cache_lock:
        cached = _dependency_health_cache.get(candidate)
        if cached and (now - float(cached.get("ts", 0.0))) <= ttl_seconds:
            return bool(cached.get("ok", False)), str(cached.get("detail", "cache"))
    try:
        async with httpx.AsyncClient(timeout=max(0.5, float(timeout_seconds))) as client:
            response = await client.get(candidate)
        ok = True
        detail = f"reachable_http_{response.status_code}"
    except Exception as exc:
        ok = False
        detail = f"unreachable:{type(exc).__name__}"
    with _dependency_health_cache_lock:
        _dependency_health_cache[candidate] = {"ts": now, "ok": ok, "detail": detail}
    return ok, detail


async def _dependency_fail_safe_check(method: str) -> Tuple[bool, str, Dict[str, Any]]:
    profile = policy.dependency_fail_safe_profile if isinstance(policy.dependency_fail_safe_profile, dict) else {}
    if method != "tools/call" or not profile.get("enabled"):
        return True, "allow", {}

    required_controls = profile.get("required_controls") if isinstance(profile.get("required_controls"), list) else []
    require_reachability = bool(profile.get("require_network_reachability", True))
    ttl = max(1, int(profile.get("health_cache_ttl_seconds", 15)))
    failures: List[Dict[str, Any]] = []

    if "llm_risk" in required_controls:
        cfg = _llm_risk_config()
        if cfg["enabled"] and cfg["enforce"]:
            if cfg["provider"] != "langchain" or ChatOpenAI is None or HumanMessage is None or SystemMessage is None:
                failures.append({"control": "llm_risk", "reason": "provider_unavailable"})
            elif _get_llm_client(cfg) is None:
                failures.append({"control": "llm_risk", "reason": "client_unavailable"})
            elif require_reachability:
                ok, detail = await _probe_dependency_reachability(cfg.get("base_url", ""), cfg.get("timeout_seconds", 5), ttl)
                if not ok:
                    failures.append({"control": "llm_risk", "reason": detail})

    if "tool_intent" in required_controls:
        cfg = _tool_intent_config()
        if cfg["enabled"] and cfg["enforce"]:
            if cfg["provider"] != "langchain" or ChatOpenAI is None or HumanMessage is None or SystemMessage is None:
                failures.append({"control": "tool_intent", "reason": "provider_unavailable"})
            elif _get_tool_intent_client(cfg) is None:
                failures.append({"control": "tool_intent", "reason": "client_unavailable"})
            elif require_reachability:
                ok, detail = await _probe_dependency_reachability(cfg.get("base_url", ""), cfg.get("timeout_seconds", 5), ttl)
                if not ok:
                    failures.append({"control": "tool_intent", "reason": detail})

    if failures:
        return False, "dependency_health_failed", {"failures": failures}
    return True, "allow", {}


def _security_layer_unavailable(result: Optional[Dict[str, Any]], unavailable_rationale: str) -> bool:
    if not isinstance(result, dict):
        return True
    if str(result.get("rationale") or "") == unavailable_rationale:
        return True
    if str(result.get("engine") or "").strip().lower() in {"", "none"}:
        return True
    return False


def _canonical_descriptor(descriptor: Any) -> str:
    if not isinstance(descriptor, dict):
        return json.dumps(descriptor, sort_keys=True, separators=(",", ":"))
    keep_keys = ("name", "description", "inputSchema", "outputSchema", "annotations")
    canonical = {k: descriptor[k] for k in keep_keys if k in descriptor}
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _compute_tool_descriptor_hash(descriptor: Any) -> str:
    payload = _canonical_descriptor(descriptor).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _check_descriptor_drift(tool_name: str, descriptor: Any) -> Optional[str]:
    expected = policy.tool_descriptor_hashes.get(str(tool_name or "").strip())
    if not expected:
        return None
    actual = _compute_tool_descriptor_hash(descriptor)
    if actual.lower() != expected.lower():
        return actual
    return None


def _is_trusted_upstream(url: str) -> bool:
    trusted = policy.trusted_servers if isinstance(policy.trusted_servers, set) else set()
    if not trusted:
        return True
    candidate = str(url or "").strip().lower()
    if candidate in trusted:
        return True
    try:
        parsed = urlparse(candidate)
    except Exception:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host in trusted:
        return True
    netloc = (parsed.netloc or "").lower()
    if netloc and netloc in trusted:
        return True
    origin = f"{parsed.scheme}://{parsed.netloc}".lower() if parsed.scheme and parsed.netloc else ""
    if origin and origin in trusted:
        return True
    return False


def _isolated_executor_check(method: str, tool: str, params: Any) -> Tuple[bool, str, Dict[str, Any]]:
    """Check if request should be routed to isolated executor (Sprint 3)."""
    profile = policy.isolated_executor_profile if isinstance(policy.isolated_executor_profile, dict) else {}
    if method != "tools/call" or not profile.get("enabled"):
        return True, "allow", {}
    if not _tool_matches_any_pattern(tool, profile.get("require_for_tools")):
        return True, "allow", {}

    executor_url = str(profile.get("executor_url") or "").strip()
    fallback = bool(profile.get("fallback_to_upstream", False))

    # If no executor URL configured and no fallback, deny
    if not executor_url and not fallback:
        return False, "isolated_executor_unavailable", {"executor_url": None, "fallback_enabled": False}

    # Check runtime limits
    runtime_limits = profile.get("runtime_limits") or {}
    limit_check, limit_reason, limit_meta = _check_runtime_limits(params, runtime_limits)
    if not limit_check:
        return False, limit_reason, limit_meta

    # Check filesystem restrictions
    fs_restrictions = profile.get("filesystem_restrictions") or {}
    fs_check, fs_reason, fs_meta = _check_filesystem_restrictions(params, fs_restrictions)
    if not fs_check:
        return False, fs_reason, fs_meta

    # If executor URL is configured, mark for routing (actual routing happens in mcp_proxy)
    if executor_url:
        return True, "route_to_executor", {
            "executor_url": executor_url,
            "runtime_limits": runtime_limits,
            "filesystem_restrictions": fs_restrictions,
            "require_rootless": bool(profile.get("require_rootless", False)),
        }

    # No executor but fallback allowed
    return True, "fallback_to_upstream", {"executor_url": None, "fallback_enabled": True}


def _check_runtime_limits(params: Any, limits: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Check if request parameters would exceed runtime limits."""
    if not isinstance(limits, dict) or not limits:
        return True, "allow", {}

    arguments = (params.get("arguments") if isinstance(params, dict) else {}) or {}

    # Check CPU limit
    max_cpu = limits.get("max_cpu_seconds")
    if max_cpu:
        requested_cpu = float(arguments.get("timeout_seconds") or arguments.get("cpu_seconds") or 0)
        if requested_cpu > max_cpu:
            return False, "runtime_limits_exceeded", {
                "limit_type": "max_cpu_seconds",
                "limit": max_cpu,
                "requested": requested_cpu,
            }

    # Check memory limit
    max_mem = limits.get("max_memory_mb")
    if max_mem:
        requested_mem = float(arguments.get("memory_mb") or arguments.get("memory_limit_mb") or 0)
        if requested_mem > max_mem:
            return False, "runtime_limits_exceeded", {
                "limit_type": "max_memory_mb",
                "limit": max_mem,
                "requested": requested_mem,
            }

    # Check wall time limit
    max_time = limits.get("max_wall_time_seconds")
    if max_time:
        requested_time = float(arguments.get("wall_time_seconds") or arguments.get("duration_seconds") or 0)
        if requested_time > max_time:
            return False, "runtime_limits_exceeded", {
                "limit_type": "max_wall_time_seconds",
                "limit": max_time,
                "requested": requested_time,
            }

    return True, "allow", {"limits_checked": list(limits.keys())}


def _check_filesystem_restrictions(params: Any, restrictions: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Check if request violates filesystem restrictions."""
    if not isinstance(restrictions, dict) or not restrictions:
        return True, "allow", {}

    arguments = (params.get("arguments") if isinstance(params, dict) else {}) or {}

    # Check for denied read paths in arguments
    deny_read_paths = restrictions.get("deny_read_paths") or []
    for path in deny_read_paths:
        # Check in various argument fields that might contain paths
        for arg_key in ["path", "file", "filepath", "source", "input", "read_path"]:
            arg_val = str(arguments.get(arg_key) or "")
            if arg_val and (arg_val.startswith(path) or path in arg_val):
                return False, "filesystem_restriction_violation", {
                    "violation_type": "deny_read_path",
                    "denied_path": path,
                    "argument": arg_key,
                    "value": arg_val,
                }

    # Check for denied write paths in arguments
    deny_write_paths = restrictions.get("deny_write_paths") or []
    for path in deny_write_paths:
        for arg_key in ["output", "destination", "write_path", "save_path", "target"]:
            arg_val = str(arguments.get(arg_key) or "")
            if arg_val and (arg_val.startswith(path) or path in arg_val):
                return False, "filesystem_restriction_violation", {
                    "violation_type": "deny_write_path",
                    "denied_path": path,
                    "argument": arg_key,
                    "value": arg_val,
                }

    return True, "allow", {"restrictions_checked": list(restrictions.keys())}


def _verify_rootless_execution(executor_response: Any) -> Tuple[bool, str, Dict[str, Any]]:
    """Verify that executor is running in rootless mode (Sprint 3)."""
    if not isinstance(executor_response, dict):
        return False, "rootless_verification_failed", {"error": "invalid_executor_response"}

    runtime_info = executor_response.get("runtime_info") or {}
    if not isinstance(runtime_info, dict):
        return False, "rootless_verification_failed", {"error": "missing_runtime_info"}

    verification = {
        "uid": runtime_info.get("uid"),
        "gid": runtime_info.get("gid"),
        "no_new_privs": runtime_info.get("no_new_privs"),
        "seccomp_enabled": runtime_info.get("seccomp_enabled"),
    }

    # Check for root UID
    if verification["uid"] == 0:
        return False, "rootless_execution_required", {
            "violation": "running_as_root",
            "uid": verification["uid"],
        }

    # Check for no_new_privs (should be True for proper isolation)
    if verification["no_new_privs"] is False:
        return False, "rootless_verification_failed", {
            "violation": "no_new_privs_not_set",
        }

    return True, "rootless_verified", verification


def _check_upstream_provenance(destination_url: str) -> Tuple[bool, str, Dict[str, Any]]:
    """Check if upstream destination is allowed by provenance policy (Sprint 3)."""
    profile = policy.upstream_provenance_profile if isinstance(policy.upstream_provenance_profile, dict) else {}
    if not profile.get("enabled"):
        return True, "allow", {}

    allowed = profile.get("allowed_destinations") or []
    blocked = profile.get("blocked_destinations") or []

    dest_lower = str(destination_url or "").strip().lower()

    # Check blocked destinations first (patterns supported)
    for pattern in blocked:
        if _match_url_pattern(dest_lower, pattern):
            return False, "upstream_dest_blocked", {
                "destination": destination_url,
                "matched_pattern": pattern,
            }

    # Check allowed destinations (exact match or pattern)
    if allowed:
        matched = False
        for pattern in allowed:
            if _match_url_pattern(dest_lower, pattern):
                matched = True
                break
        if not matched:
            return False, "upstream_provenance_denied", {
                "destination": destination_url,
                "allowed_patterns": allowed,
            }

    return True, "upstream_allowed", {"destination": destination_url}


def _match_url_pattern(url: str, pattern: str) -> bool:
    """Match URL against a pattern (supports wildcards)."""
    pattern = str(pattern or "").strip().lower()
    if not pattern:
        return False

    # Exact match
    if url == pattern:
        return True

    # Wildcard prefix match (e.g., *.example.com)
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .example.com
        if url.endswith(suffix):
            return True
        # Also match if URL contains the pattern (e.g., sub.example.com matches *.example.com)
        if suffix in url and "." in url.split(suffix)[0]:
            return True

    # Wildcard anywhere (e.g., *webhook*)
    if pattern.startswith("*") and pattern.endswith("*"):
        middle = pattern[1:-1]
        if middle in url:
            return True

    # Wildcard suffix match
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        if url.startswith(prefix):
            return True

    # Wildcard prefix match
    if pattern.startswith("*"):
        suffix = pattern[1:]
        if url.endswith(suffix):
            return True

    return False


def _check_egress_content(content: Any, patterns: List[Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Check if egress content contains sensitive patterns (Sprint 3)."""
    if not patterns:
        return True, "allow", {}

    content_str = json.dumps(content) if not isinstance(content, str) else content

    for pattern in patterns:
        if isinstance(pattern, type(re.compile(""))):  # compiled regex
            if pattern.search(content_str):
                return False, "egress_sensitive_content_detected", {
                    "matched_pattern": pattern.pattern,
                }
        elif isinstance(pattern, str) and pattern:
            if re.search(pattern, content_str, re.IGNORECASE):
                return False, "egress_sensitive_content_detected", {
                    "matched_pattern": pattern,
                }

    return True, "allow", {}


async def _forward_to_isolated_executor(
    executor_url: str,
    body_bytes: bytes,
    headers: Dict[str, str],
    method: str,
    tool: str,
    params: Any,
    start: float,
    client_ip: str,
    request_id: Any,
    args_keys: List[str],
    auth_subject: str,
) -> JSONResponse:
    """Forward request to isolated executor service (Sprint 3)."""
    profile = policy.isolated_executor_profile if isinstance(policy.isolated_executor_profile, dict) else {}
    timeout = max(1, int(profile.get("timeout_seconds", 60)))
    max_retries = max(0, int(profile.get("max_retries", 2)))
    require_rootless = bool(profile.get("require_rootless", False))
    forward_on_success = bool(profile.get("forward_on_success", True))

    executor_headers = {"Content-Type": "application/json"}
    if _UPSTREAM_API_KEY:
        executor_headers["Authorization"] = f"Bearer {_UPSTREAM_API_KEY}"

    # Prepare executor request with security context
    try:
        original_payload = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        original_payload = {}

    executor_payload = {
        "original_request": original_payload,
        "security_context": {
            "client_ip": client_ip,
            "request_id": str(request_id) if request_id else None,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "runtime_limits": profile.get("runtime_limits") or {},
            "filesystem_restrictions": profile.get("filesystem_restrictions") or {},
            "require_rootless": require_rootless,
        },
    }

    # Check upstream provenance before forwarding
    provenance_profile = policy.upstream_provenance_profile if isinstance(policy.upstream_provenance_profile, dict) else {}
    if provenance_profile.get("enabled") and executor_url:
        prov_ok, prov_reason, prov_meta = _check_upstream_provenance(executor_url)
        if not prov_ok:
            prov_action = str(provenance_profile.get("action", "deny")).strip().lower()
            if prov_action in {"deny", "challenge"}:
                elapsed = time.time() - start
                deny_reason = prov_reason if prov_action == "deny" else "upstream_provenance_challenge"
                MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
                MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
                MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
                denied_event = _record_denied_event(
                    request_id, method, tool, deny_reason, {}, client_ip,
                    metadata={
                        "action": prov_action,
                        **(prov_meta if isinstance(prov_meta, dict) else {}),
                    },
                )
                _evaluate_discovery_rules(denied_event)
                _record_decision_event(
                    stage="upstream_provenance",
                    decision="challenge" if prov_action == "challenge" else "deny",
                    method=method,
                    tool=tool,
                    reason=deny_reason,
                    client_ip=client_ip,
                    request_id=request_id,
                    elapsed_ms=int(elapsed * 1000),
                    args_keys=args_keys,
                    auth_subject=auth_subject,
                )
                return _jsonrpc_error(
                    request_id, -32003, "Upstream provenance check failed", 403,
                    {"reason": deny_reason, **(prov_meta if isinstance(prov_meta, dict) else {})},
                )
            _record_decision_event(
                stage="upstream_provenance",
                decision="monitor",
                method=method,
                tool=tool,
                reason="upstream_provenance_monitor",
                client_ip=client_ip,
                request_id=request_id,
                args_keys=args_keys,
                auth_subject=auth_subject,
            )

    last_error = None
    for attempt in range(max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                executor_response = await client.post(executor_url, headers=executor_headers, json=executor_payload)
            break
        except Exception as exc:
            last_error = str(exc)
            if attempt < max_retries:
                await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff
                continue
            # All retries exhausted
            elapsed = time.time() - start
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="error").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason="isolated_executor_error").inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="error").observe(elapsed)
            denied_event = _record_denied_event(
                request_id, method, tool, "isolated_executor_error", {}, client_ip,
                metadata={"executor_url": executor_url, "error": last_error, "retries": max_retries},
            )
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="isolated_executor",
                decision="error",
                method=method,
                tool=tool,
                reason="isolated_executor_error",
                client_ip=client_ip,
                request_id=request_id,
                elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            return _jsonrpc_error(
                request_id, -32004, "Isolated executor unavailable after retries", 504,
                {"reason": "isolated_executor_error", "executor_url": executor_url, "error": last_error},
            )
    else:
        # No successful response after all retries
        elapsed = time.time() - start
        MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="error").inc()
        return _jsonrpc_error(
            request_id, -32004, "Isolated executor communication failed", 504,
            {"reason": "isolated_executor_error", "executor_url": executor_url},
        )

    elapsed = time.time() - start

    # Check executor response status
    if executor_response.status_code >= 400:
        MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="error").inc()
        MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason="isolated_executor_error").inc()
        denied_event = _record_denied_event(
            request_id, method, tool, "isolated_executor_error", {}, client_ip,
            metadata={"executor_url": executor_url, "status_code": executor_response.status_code},
        )
        _evaluate_discovery_rules(denied_event)
        _record_decision_event(
            stage="isolated_executor",
            decision="error",
            method=method,
            tool=tool,
            reason="isolated_executor_error",
            client_ip=client_ip,
            request_id=request_id,
            elapsed_ms=int(elapsed * 1000),
            args_keys=args_keys,
            auth_subject=auth_subject,
        )
        return _jsonrpc_error(
            request_id, -32003, "Isolated executor returned error", executor_response.status_code,
            {"reason": "isolated_executor_error", "executor_url": executor_url, "status_code": executor_response.status_code},
        )

    # Parse executor response
    try:
        executor_content = executor_response.json()
    except ValueError:
        executor_content = {"raw": executor_response.text}

    # Verify rootless execution if required
    if require_rootless:
        rootless_ok, rootless_reason, rootless_meta = _verify_rootless_execution(executor_content)
        if not rootless_ok:
            elapsed = time.time() - start
            deny_reason = rootless_reason
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(
                request_id, method, tool, deny_reason, {}, client_ip,
                metadata={"executor_url": executor_url, **(rootless_meta if isinstance(rootless_meta, dict) else {})},
            )
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="rootless_verification",
                decision="deny",
                method=method,
                tool=tool,
                reason=deny_reason,
                client_ip=client_ip,
                request_id=request_id,
                elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            return _jsonrpc_error(
                request_id, -32003, "Rootless execution verification failed", 403,
                {"reason": deny_reason, **(rootless_meta if isinstance(rootless_meta, dict) else {})},
            )

    # Check egress content for sensitive patterns
    if provenance_profile.get("enabled") and provenance_profile.get("egress_filter_patterns"):
        patterns = provenance_profile.get("egress_filter_patterns") or []
        egress_ok, egress_reason, egress_meta = _check_egress_content(executor_content, patterns)
        if not egress_ok:
            elapsed = time.time() - start
            deny_reason = egress_reason
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(
                request_id, method, tool, deny_reason, {}, client_ip,
                metadata={"executor_url": executor_url, **(egress_meta if isinstance(egress_meta, dict) else {})},
            )
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="egress_filter",
                decision="deny",
                method=method,
                tool=tool,
                reason=deny_reason,
                client_ip=client_ip,
                request_id=request_id,
                elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            return _jsonrpc_error(
                request_id, -32003, "Egress content check failed", 403,
                {"reason": deny_reason, **(egress_meta if isinstance(egress_meta, dict) else {})},
            )

    # Record executor evidence for audit telemetry
    executor_evidence = {
        "executor_url": executor_url,
        "execution_id": executor_content.get("execution_id") if isinstance(executor_content, dict) else None,
        "runtime_limits_applied": profile.get("runtime_limits") or {},
        "rootless_verified": require_rootless,
        "filesystem_restrictions_applied": list((profile.get("filesystem_restrictions") or {}).keys()),
        "start_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start)),
        "end_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_ms": int(elapsed * 1000),
        "status_code": executor_response.status_code,
    }

    # If forward_on_success, forward to standard upstream
    if forward_on_success:
        try:
            async with httpx.AsyncClient(timeout=_FORWARD_TIMEOUT_SECONDS) as client:
                upstream_response = await client.post(_UPSTREAM_URL, content=body_bytes, headers=headers)
            upstream_elapsed = time.time() - start
            decision = "allow"
            if upstream_response.status_code >= 500:
                MCP_PROXY_UPSTREAM_ERRORS_TOTAL.labels(category="upstream_5xx").inc()
                decision = "upstream_error"
            elif upstream_response.status_code >= 400:
                MCP_PROXY_UPSTREAM_ERRORS_TOTAL.labels(category="upstream_4xx").inc()
                decision = "upstream_error"
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision=decision).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision=decision).observe(upstream_elapsed)
            _record_decision_event(
                stage="proxy_forward",
                decision=decision,
                method=method,
                tool=tool,
                reason=f"upstream_status_{upstream_response.status_code}",
                client_ip=client_ip,
                request_id=request_id,
                status_code=upstream_response.status_code,
                elapsed_ms=int(upstream_elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
                executor_evidence=executor_evidence,
            )
            logger.info(
                "[Executor]  %-9s  tool=%-28s  executor_status=%d  upstream_status=%d  elapsed=%.3fs  client=%s",
                "allow".upper(), tool or method, executor_response.status_code, upstream_response.status_code, upstream_elapsed, client_ip,
            )
            try:
                upstream_content = upstream_response.json()
            except ValueError:
                upstream_content = {"raw": upstream_response.text}
            return JSONResponse(status_code=upstream_response.status_code, content=upstream_content)
        except Exception as exc:
            # Upstream forward failed, but executor succeeded - log and return executor response
            logger.warning("[Executor] Upstream forward failed after executor success: %s", exc)

    # Return executor response directly
    MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="allow").inc()
    MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="allow").observe(elapsed)
    _record_decision_event(
        stage="isolated_executor",
        decision="allow",
        method=method,
        tool=tool,
        reason="executor_success",
        client_ip=client_ip,
        request_id=request_id,
        elapsed_ms=int(elapsed * 1000),
        args_keys=args_keys,
        auth_subject=auth_subject,
        executor_evidence=executor_evidence,
    )
    logger.info(
        "[Executor]  %-9s  tool=%-28s  status=%d  elapsed=%.3fs  client=%s",
        "allow".upper(), tool or method, executor_response.status_code, elapsed, client_ip,
    )
    return JSONResponse(status_code=200, content=executor_content)


def _signal_event_matches(signal: str, event: Dict[str, Any]) -> bool:
    reason = str(event.get("reason") or "").strip().lower()
    tool = str(event.get("tool") or "").strip().lower()
    if signal == "repeated_tool_denials":
        return bool(reason)
    if signal == "write_tool_abuse":
        if reason in {"tool_denied", "method_not_allowed", "llm_risk_deny", "llm_risk_challenge"}:
            return _is_sensitive_write_tool(tool)
        return reason.startswith("blocked_pattern") and _is_sensitive_write_tool(tool)
    if signal == "attack_pattern_denials":
        if reason.startswith("blocked_pattern"):
            return True
        if reason in {
            "llm_intent_deny",
            "llm_intent_challenge",
            "llm_risk_deny",
            "llm_risk_challenge",
            "tool_denied",
            "method_not_allowed",
        }:
            return True
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        labels = metadata.get("labels") if isinstance(metadata.get("labels"), list) else []
        lowered = {str(item).strip().lower() for item in labels if str(item).strip()}
        return bool(lowered & {"malware", "attack", "probing", "exfiltration", "injection"})
    if signal == "untrusted_server_calls":
        return reason.startswith("untrusted_server")
    if signal == "descriptor_drift_events":
        return reason.startswith("descriptor_drift") or reason.startswith("descriptor_")
    if signal == "execution_tool_attempts":
        return reason.startswith("execution_tool_")
    if signal == "sandbox_attestation_failures":
        return reason.startswith("sandbox_attestation")
    if signal == "dependency_health_failures":
        return reason.startswith("dependency_health")
    if signal == "security_layer_bypass_attempts":
        return reason.startswith("security_layer_")
    # Sprint 3 discovery signals
    if signal == "isolated_executor_failures":
        return reason.startswith("isolated_executor_")
    if signal == "runtime_limits_violations":
        return reason in {"runtime_limits_exceeded", "runtime_limits_violation"}
    if signal == "rootless_verification_failures":
        return reason.startswith("rootless_")
    if signal == "filesystem_violations":
        return reason.startswith("filesystem_")
    if signal == "upstream_provenance_violations":
        return reason.startswith("upstream_") or reason.startswith("egress_")
    if signal == "sensitive_egress_detected":
        return reason == "egress_sensitive_content_detected"
    return False


def _emit_discovery_alert(alert: Dict[str, Any]) -> None:
    with _recent_discovery_lock:
        _recent_discovery_alerts.appendleft(alert)
    _persist_runtime_history()
    MCP_PROXY_DISCOVERY_TRIGGERS_TOTAL.labels(
        signal=str(alert.get("signal") or "unknown"),
        action=str(alert.get("action_on_trigger") or "monitor"),
        tool=str(alert.get("tool") or "*"),
    ).inc()
    logger.warning("mcp_proxy discovery trigger emitted: %s", alert)


def _build_discovery_alerts_from_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rules = policy.discovery_rules if isinstance(policy.discovery_rules, list) else []
    if not rules:
        return []
    now = time.time()
    alerts: List[Dict[str, Any]] = []
    seen_keys = set()
    for idx, rule in enumerate(rules):
        signal = str(rule.get("signal") or "").strip().lower()
        if not signal:
            continue
        min_count, window_seconds, threshold_text = _parse_discovery_threshold(rule.get("threshold"))
        if not min_count or not window_seconds:
            min_count, window_seconds, threshold_text = _default_discovery_threshold(signal)
        tool_scope = _normalize_string_list(rule.get("tool_scope") if isinstance(rule.get("tool_scope"), list) else [])
        window_start = now - float(window_seconds)
        matching: List[Dict[str, Any]] = []
        for event in events:
            if _event_ts_to_epoch(event.get("timestamp")) < window_start:
                continue
            tool_name = str(event.get("tool") or "").strip()
            if tool_scope and tool_name not in tool_scope:
                continue
            if _signal_event_matches(signal, event):
                matching.append(event)
        if len(matching) < min_count:
            continue
        action_on_trigger = str(rule.get("action_on_trigger") or rule.get("action") or "monitor").strip().lower()
        dedupe_key = f"{idx}:{signal}:{action_on_trigger}:{','.join(tool_scope) if tool_scope else '*'}"
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        reason_counts: Dict[str, int] = {}
        for event in matching:
            reason = str(event.get("reason") or "unknown")
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        event_tool = str(matching[-1].get("tool") or "*").strip() or "*"
        alerts.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "signal": signal,
            "threshold": threshold_text,
            "window_seconds": window_seconds,
            "required_count": min_count,
            "observed_count": len(matching),
            "action_on_trigger": action_on_trigger,
            "tool_scope": tool_scope,
            "tool": event_tool,
            "reason_counts": reason_counts,
            "source": "discovery_rules_runtime",
            "rationale": str(rule.get("rationale") or "").strip(),
        })
    return alerts


def _evaluate_discovery_rules(new_event: Dict[str, Any]) -> None:
    with _recent_denied_lock:
        snapshot = list(_recent_denied_events)
    for alert in _build_discovery_alerts_from_events(snapshot):
        signal = str(alert.get("signal") or "").strip().lower()
        action_on_trigger = str(alert.get("action_on_trigger") or "monitor").strip().lower()
        tool_scope = alert.get("tool_scope") if isinstance(alert.get("tool_scope"), list) else []
        dedupe_key = f"{signal}:{action_on_trigger}:{','.join(tool_scope) if tool_scope else '*'}"
        last_fired = _discovery_last_trigger_ts.get(dedupe_key, 0.0)
        now = time.time()
        cooldown_seconds = min(float(alert.get("window_seconds") or 0), _DISCOVERY_ALERT_COOLDOWN_SECONDS)
        if cooldown_seconds <= 0:
            continue
        if (now - last_fired) < cooldown_seconds:
            continue
        _discovery_last_trigger_ts[dedupe_key] = now
        _emit_discovery_alert(alert)


def _llm_risk_config() -> Dict[str, Any]:
    cfg = policy.llm_risk if isinstance(policy.llm_risk, dict) else {}
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "provider": str(cfg.get("provider", "langchain")).strip().lower() or "langchain",
        "model": str(cfg.get("model", "ai/gemma3-qat:latest")).strip() or "ai/gemma3-qat:latest",
        "base_url": str(cfg.get("base_url", "http://host.docker.internal/engines/v1")).strip(),
        "api_key": str(cfg.get("api_key", os.getenv("MCP_PROXY_LLM_API_KEY", "local-demo"))).strip() or "local-demo",
        "timeout_seconds": float(cfg.get("timeout_seconds", 5)),
        "min_monitor_score": float(cfg.get("min_monitor_score", 0.55)),
        "min_challenge_score": float(cfg.get("min_challenge_score", 0.65)),
        "min_deny_score": float(cfg.get("min_deny_score", 0.69)),
        "enforce": bool(cfg.get("enforce", False)),
        "max_argument_chars": int(cfg.get("max_argument_chars", 2000)),
        "system_prompt": str(cfg.get("system_prompt", "You are an MCP security risk classifier. Return only compact JSON with keys: decision_hint, risk_score, labels, rationale. decision_hint must be one of allow, monitor, challenge, deny. risk_score must be 0..1.")),
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
        "base_url": str(cfg.get("base_url", "http://host.docker.internal/engines/v1")).strip(),
        "api_key": str(cfg.get("api_key", os.getenv("MCP_PROXY_LLM_API_KEY", "local-demo"))).strip() or "local-demo",
        "timeout_seconds": float(cfg.get("timeout_seconds", 5)),
        "min_monitor_score": float(cfg.get("min_monitor_score", 0.45)),
        "min_challenge_score": float(cfg.get("min_challenge_score", 0.65)),
        "min_deny_score": float(cfg.get("min_deny_score", 0.82)),
        "enforce": bool(cfg.get("enforce", False)),
        "max_argument_chars": int(cfg.get("max_argument_chars", 2000)),
        "require_intent_metadata": bool(cfg.get("require_intent_metadata", False)),
        "metadata_intent_keys": normalized_keys,
        "system_prompt": str(cfg.get("system_prompt", "You are an MCP tool-intent verifier. Compare declared intent against selected method/tool/arguments. Return only compact JSON with keys: decision_hint, intent_score, labels, rationale. decision_hint must be one of allow, monitor, challenge, deny. intent_score must be 0..1 where higher means stronger intent mismatch risk.")),
    }


def _build_langchain_client(cfg: Dict[str, Any]) -> Optional[Any]:
    if ChatOpenAI is None:
        return None
    return ChatOpenAI(model=cfg["model"], base_url=cfg["base_url"], api_key=cfg["api_key"], timeout=cfg["timeout_seconds"], temperature=0)


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
        for source in (metadata, arguments):
            value = source.get(key)
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
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                chunks.append(item["text"])
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
    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    except ValueError:
        pass
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


async def _openai_compatible_chat_json(cfg: Dict[str, Any], system_prompt: str, user_payload: Dict[str, Any]) -> Optional[Any]:
    base_url = str(cfg.get("base_url", "")).rstrip("/")
    if not base_url:
        return None
    url = f"{base_url}/chat/completions"
    headers = {"Content-Type": "application/json"}
    api_key = str(cfg.get("api_key", "")).strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    body = {
        "model": cfg.get("model", "ai/gemma3-qat:latest"),
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=True)},
        ],
    }
    timeout = float(cfg.get("timeout_seconds", 8))
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, headers=headers, json=body)
        if resp.status_code >= 400:
            return None
        data = resp.json()
        choices = data.get("choices") if isinstance(data, dict) else None
        if not isinstance(choices, list) or not choices:
            return None
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        text = _coerce_llm_content_to_text(content).strip()
        if not text:
            return None
        candidate = _strip_code_fences(text)
        try:
            parsed_any = json.loads(candidate)
            if isinstance(parsed_any, (dict, list)):
                return parsed_any
        except Exception:
            pass
        return _parse_llm_json_object(text)
    except Exception:
        return None


async def _llm_risk_score(method: str, tool: str, arguments: Any, client_ip: str) -> Optional[Dict[str, Any]]:
    cfg = _llm_risk_config()
    if not cfg["enabled"]:
        return None
    start = time.time()
    serialized_args = _summarize_arguments(arguments)[: cfg["max_argument_chars"]]
    outcome = "ok"
    decision_hint = "allow"
    risk_score = 0.0
    fallback = {"decision_hint": "allow", "risk_score": 0.0, "labels": [], "rationale": "llm_risk_unavailable", "engine": "none"}
    try:
        if cfg["provider"] != "langchain":
            outcome = "unsupported_provider"
            return fallback
        client = _get_llm_client(cfg)
        if client is None or HumanMessage is None or SystemMessage is None:
            outcome = "langchain_unavailable"
            return fallback
        prompt_payload = {"method": method, "tool": tool, "client_ip": client_ip, "arguments": serialized_args}
        response = await client.ainvoke([
            SystemMessage(content=cfg["system_prompt"]),
            HumanMessage(content=json.dumps(prompt_payload, ensure_ascii=True)),
        ])
        raw_text = _coerce_llm_content_to_text(getattr(response, "content", "")).strip()
        if not raw_text:
            raise ValueError("LLM response is empty")
        parsed = _parse_llm_json_object(raw_text)
        score = max(0.0, min(1.0, float(parsed.get("risk_score", 0.0))))
        risk_score = score
        decision_hint = str(parsed.get("decision_hint", "")).strip().lower()
        if decision_hint not in {"allow", "monitor", "challenge", "deny"}:
            decision_hint = _llm_risk_hint_from_score(score, cfg)
        return {
            "decision_hint": decision_hint,
            "risk_score": score,
            "labels": parsed.get("labels") if isinstance(parsed.get("labels"), list) else [],
            "rationale": str(parsed.get("rationale", "")).strip()[:500],
            "engine": "langchain",
        }
    except Exception as exc:
        outcome = "error"
        logger.warning("mcp_proxy llm_risk failure method=%s tool=%s err=%s", method, tool, exc)
        return fallback
    finally:
        elapsed = time.time() - start
        MCP_PROXY_LLM_RISK_CALLS_TOTAL.labels(decision_hint=decision_hint, outcome=outcome).inc()
        MCP_PROXY_LLM_RISK_LATENCY_SECONDS.labels(decision_hint=decision_hint, outcome=outcome).observe(elapsed)
        MCP_PROXY_LLM_RISK_SCORE.labels(decision_hint=decision_hint, outcome=outcome).observe(risk_score)
        MCP_PROXY_LLM_RISK_VALUE.labels(decision_hint=decision_hint, outcome=outcome).observe(risk_score)


async def _tool_intent_score(method: str, tool: str, params: Dict[str, Any], client_ip: str) -> Optional[Dict[str, Any]]:
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
        metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}
        if not any(isinstance(metadata.get(key), str) and metadata.get(key).strip() for key in cfg["metadata_intent_keys"]):
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
        response = await client.ainvoke([
            SystemMessage(content=cfg["system_prompt"]),
            HumanMessage(content=json.dumps(prompt_payload, ensure_ascii=True)),
        ])
        raw_text = _coerce_llm_content_to_text(getattr(response, "content", "")).strip()
        if not raw_text:
            raise ValueError("LLM response is empty")
        parsed = _parse_llm_json_object(raw_text)
        score = max(0.0, min(1.0, float(parsed.get("intent_score", 0.0))))
        intent_score = score
        decision_hint = str(parsed.get("decision_hint", "")).strip().lower()
        if decision_hint not in {"allow", "monitor", "challenge", "deny"}:
            decision_hint = _tool_intent_hint_from_score(score, cfg)
        return {
            "decision_hint": decision_hint,
            "intent_score": score,
            "labels": parsed.get("labels") if isinstance(parsed.get("labels"), list) else [],
            "rationale": str(parsed.get("rationale", "")).strip()[:500],
            "engine": "langchain",
            "declared_intent": declared_intent,
        }
    except Exception as exc:
        outcome = "error"
        logger.warning("mcp_proxy tool_intent failure method=%s tool=%s err=%s", method, tool, exc)
        return fallback
    finally:
        elapsed = time.time() - start
        MCP_PROXY_TOOL_INTENT_CALLS_TOTAL.labels(decision_hint=decision_hint, outcome=outcome).inc()
        MCP_PROXY_TOOL_INTENT_LATENCY_SECONDS.labels(decision_hint=decision_hint, outcome=outcome).observe(elapsed)
        MCP_PROXY_TOOL_INTENT_SCORE.labels(decision_hint=decision_hint, outcome=outcome).observe(intent_score)


def _validate_proxy_auth(authorization: Optional[str]) -> bool:
    return gov.resolve_auth(
        authorization,
        proxy_api_key=_PROXY_API_KEY,
        governance=_governance_profile(),
    ) is not None


def _resolve_auth_context(authorization: Optional[str]) -> gov.AuthContext:
    ctx = gov.resolve_auth(
        authorization,
        proxy_api_key=_PROXY_API_KEY,
        governance=_governance_profile(),
    )
    if ctx is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return ctx


def _validate_or_raise_proxy_auth(authorization: Optional[str]) -> None:
    _resolve_auth_context(authorization)


def _require_admin_permission(authorization: Optional[str], permission: str) -> gov.AuthContext:
    ctx = _resolve_auth_context(authorization)
    if not gov.has_permission(ctx.role, permission):
        raise HTTPException(
            status_code=403,
            detail={"reason": "forbidden", "permission": permission, "role": ctx.role},
        )
    return ctx


def _policy_lifecycle_settings() -> Dict[str, Any]:
    lifecycle = _governance_profile().get("policy_lifecycle")
    return lifecycle if isinstance(lifecycle, dict) else {}


def _maybe_version_policy(policy_config: Dict[str, Any], *, created_by: str, reason: str) -> Optional[Dict[str, Any]]:
    if not _governance_profile().get("enabled"):
        return None
    lifecycle = _policy_lifecycle_settings()
    if not lifecycle.get("enabled", True) or not lifecycle.get("auto_version_on_write", True):
        return None
    return gov.save_policy_version(
        policy_config,
        created_by=created_by,
        reason=reason,
        max_versions=max(1, int(lifecycle.get("max_versions", 50))),
    )


def _apply_policy_update(
    raw_policy: Dict[str, Any],
    *,
    ctx: gov.AuthContext,
    reason: str = "policy update",
    force: bool = False,
) -> Dict[str, Any]:
    lifecycle = _policy_lifecycle_settings()
    if (
        _governance_profile().get("enabled")
        and lifecycle.get("enabled", True)
        and lifecycle.get("require_approval_for_writes", False)
        and not force
        and not gov.has_permission(ctx.role, "policy:approve")
    ):
        proposal = gov.create_policy_proposal(
            raw_policy,
            proposed_by=ctx.subject,
            note=reason,
        )
        return {
            "status": "pending_approval",
            "message": "policy change queued for approval",
            "proposal": {
                "proposal_id": proposal["proposal_id"],
                "status": proposal["status"],
                "content_hash": proposal["content_hash"],
            },
        }

    current = _read_policy_config()
    _maybe_version_policy(current, created_by=ctx.subject, reason=f"pre-write snapshot: {reason}")
    backup_path = _backup_policy_file()
    _write_policy_config(dict(raw_policy))
    _reload_policy()
    version = _maybe_version_policy(dict(raw_policy), created_by=ctx.subject, reason=reason)
    return {
        "status": "ok",
        "message": "policy updated",
        "backup_file": str(backup_path),
        "policy_file": str(_policy_file_path()),
        "raw_policy": raw_policy,
        "summary": _policy_config_summary(raw_policy),
        "version": (
            {
                "version_id": version.get("version_id"),
                "content_hash": version.get("content_hash"),
            }
            if isinstance(version, dict)
            else None
        ),
        "applied_by": ctx.subject,
        "applied_role": ctx.role,
    }


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
        if _is_execution_like_tool(tool):
            exec_action = str(policy.execution_tool_profile.get("action", "deny")).lower()
            if exec_action == "deny":
                return False, "execution_tool_blocked"
            if exec_action == "challenge":
                return False, "execution_tool_challenge"
            # monitor: allow through early policy gate; decision events recorded later
        blocked_reason = _contains_blocked_pattern(params.get("arguments", {}))
        if blocked_reason:
            if policy.blocked_pattern_action == "challenge":
                return False, blocked_reason.replace("blocked_pattern:", "blocked_pattern_challenge:", 1)
            return False, blocked_reason
    return True, "allow"


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _metrics_lines_for_prefixes(prefixes: List[str], limit: int = 40) -> List[str]:
    metrics_text = generate_latest().decode("utf-8", errors="replace")
    lines: List[str] = []
    for line in metrics_text.splitlines():
        if any(line.startswith(prefix) for prefix in prefixes):
            lines.append(line)
            if len(lines) >= limit:
                break
    return lines


def _summarize_proxy_denied(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    reason_counts: Dict[str, int] = {}
    tool_counts: Dict[str, int] = {}
    client_counts: Dict[str, int] = {}

    for event in events:
        reason = _coerce_str(event.get("reason"), "unknown")
        tool = _coerce_str(event.get("tool"), "none")
        client_ip = _coerce_str(event.get("client_ip"), "unknown")
        reason_counts[reason] = reason_counts.get(reason, 0) + 1
        tool_counts[tool] = tool_counts.get(tool, 0) + 1
        client_counts[client_ip] = client_counts.get(client_ip, 0) + 1

    top_reason = max(reason_counts.items(), key=lambda x: x[1])[0] if reason_counts else "none"
    top_tool = max(tool_counts.items(), key=lambda x: x[1])[0] if tool_counts else "none"
    top_client_ip = max(client_counts.items(), key=lambda x: x[1])[0] if client_counts else "unknown"

    return {
        "total": len(events),
        "reason_counts": reason_counts,
        "tool_counts": tool_counts,
        "client_ip_counts": client_counts,
        "top_reason": top_reason,
        "top_tool": top_tool,
        "top_client_ip": top_client_ip,
    }


def _proxy_denied_root_cause(summary: Dict[str, Any]) -> str:
    top_reason = _coerce_str(summary.get("top_reason"), "none")
    total = _coerce_int(summary.get("total"), 0)
    if total <= 0:
        return "No denied calls available."
    if top_reason.startswith("blocked_pattern"):
        return "Most denied calls are argument pattern matches; review blocked regex strictness and challenge/deny action."
    if top_reason.startswith("llm_risk_"):
        return "LLM risk gate is dominant; tune llm_risk thresholds if false positives are observed."
    if top_reason.startswith("llm_intent_"):
        return "Tool-intent verification is dominant; tune intent thresholds or metadata requirements."
    if top_reason == "tool_denied":
        return "Static deny-list rules are dominant; validate denied_tools policy for operational necessity."
    if top_reason == "method_not_allowed":
        return "Method allow-list is dominant; verify allowed_methods in policy."
    return f"Primary denied reason is '{top_reason}'."


def _proxy_tuning_recommendations(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    reason_counts = summary.get("reason_counts") if isinstance(summary.get("reason_counts"), dict) else {}
    total = _coerce_int(summary.get("total"), 0)
    llm_risk_denies = _coerce_int(reason_counts.get("llm_risk_deny"), 0) + _coerce_int(reason_counts.get("llm_risk_challenge"), 0)
    llm_intent_denies = _coerce_int(reason_counts.get("llm_intent_deny"), 0) + _coerce_int(reason_counts.get("llm_intent_challenge"), 0)
    blocked_pattern = sum(count for reason, count in reason_counts.items() if str(reason).startswith("blocked_pattern"))

    if total == 0:
        recs.append({
            "id": "collect-traffic",
            "category": "data",
            "priority": "low",
            "title": "Generate baseline denied traffic",
            "rationale": "No denied events are available for tuning. Run smoke scripts and refresh analysis.",
            "suggested_patch": {},
        })
        return recs

    if llm_risk_denies > 0:
        recs.append({
            "id": "llm-risk-review",
            "category": "llm_risk",
            "priority": "medium",
            "title": "Review LLM risk thresholds",
            "rationale": f"Observed {llm_risk_denies} llm_risk challenge/deny events.",
            "suggested_patch": {"llm_risk": {"min_challenge_score": 0.70, "min_deny_score": 0.80}},
        })

    if llm_intent_denies > 0:
        recs.append({
            "id": "tool-intent-review",
            "category": "tool_intent",
            "priority": "medium",
            "title": "Review tool-intent thresholds",
            "rationale": f"Observed {llm_intent_denies} llm_intent challenge/deny events.",
            "suggested_patch": {"tool_intent": {"min_challenge_score": 0.55, "min_deny_score": 0.70}},
        })

    if blocked_pattern > 0:
        recs.append({
            "id": "pattern-action-review",
            "category": "policy",
            "priority": "medium",
            "title": "Review blocked pattern action",
            "rationale": f"Observed {blocked_pattern} blocked_pattern denials/challenges.",
            "suggested_patch": {"blocked_pattern_action": "challenge"},
        })

    if not recs:
        recs.append({
            "id": "stable-policy",
            "category": "policy",
            "priority": "low",
            "title": "Policy appears stable",
            "rationale": "No dominant deny class detected; keep current rollout and continue monitoring.",
            "suggested_patch": {},
        })
    return recs


def _policy_tuning_recommendations_fallback(summary: Dict[str, Any], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    reason_counts = summary.get("reason_counts") if isinstance(summary.get("reason_counts"), dict) else {}
    client_counts = summary.get("client_ip_counts") if isinstance(summary.get("client_ip_counts"), dict) else {}
    tool_counts = summary.get("tool_counts") if isinstance(summary.get("tool_counts"), dict) else {}

    top_client = max(client_counts.items(), key=lambda x: x[1])[0] if client_counts else "192.168.65.1"
    top_client_count = _coerce_int(client_counts.get(top_client), 12)
    top_tool = max(tool_counts.items(), key=lambda x: x[1])[0] if tool_counts else "search_security_events"
    top_tool_count = _coerce_int(tool_counts.get(top_tool), 12)
    top_reason = max(reason_counts.items(), key=lambda x: x[1])[0] if reason_counts else "repeated_tool_denials"

    return [
        {
            "id": "mask-client-ip",
            "kind": "MASKING",
            "key": "client_ip",
            "score": 70,
            "confidence": "Low",
            "rationale": f"Top offending client {top_client} appears in {top_client_count} denied calls; recommend masking client_ip in audit logs",
            "action": "redact",
            "scope": top_tool,
            "change": {"masking_rules": [{"field": "client_ip", "action": "redact", "scope": top_tool}]},
        },
        {
            "id": "mask-tool-arguments",
            "kind": "MASKING",
            "key": f"tool_arguments[{top_tool}]",
            "score": 60,
            "confidence": "Low",
            "rationale": f"Tool '{top_tool}' has {top_tool_count} denials; recommend hashing sensitive arguments for forensic correlation",
            "action": "hash",
            "scope": top_tool,
            "change": {"masking_rules": [{"field": f"tool_arguments.{top_tool}", "action": "hash", "scope": top_tool}]},
        },
        {
            "id": "disc-repeated-denials",
            "kind": "DISCOVERY",
            "key": "repeated_tool_denials",
            "score": 65,
            "confidence": "Medium",
            "rationale": f"Detected repeated denials from policy '{top_reason}'; recommend discovery rule to flag probing campaigns",
            "action": "monitor",
            "scope": "—",
            "change": {"discovery_rules": [{"signal": "repeated_tool_denials", "action_on_trigger": "monitor"}]},
        },
        {
            "id": "disc-write-tool-abuse",
            "kind": "DISCOVERY",
            "key": "write_tool_abuse",
            "score": 70,
            "confidence": "Medium",
            "rationale": f"Tool '{top_tool}' has highest deny rate; recommend challenge rule for repeated attempts",
            "action": "challenge",
            "scope": top_tool,
            "change": {"discovery_rules": [{"signal": "write_tool_abuse", "action_on_trigger": "challenge", "scope": top_tool}]},
        },
    ]


def _normalize_policy_tuning_recommendations(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    normalized: List[Dict[str, Any]] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        kind_in = _coerce_str(item.get("kind"), "")
        if not kind_in:
            type_in = _coerce_str(item.get("type"), "masking").lower()
            kind_in = "DISCOVERY" if type_in == "discovery" else "MASKING"
        kind = kind_in.upper()
        if kind not in {"MASKING", "DISCOVERY"}:
            kind = "MASKING"
        raw_score = item.get("score")
        if isinstance(raw_score, (int, float)):
            score = max(0, min(100, int(round(float(raw_score)))))
        else:
            conf_val = item.get("confidence")
            if isinstance(conf_val, (int, float)):
                score = max(0, min(100, int(round(float(conf_val) * 100.0))))
            else:
                score = 60

        confidence_raw = item.get("confidence")
        if isinstance(confidence_raw, str):
            confidence = confidence_raw.capitalize() if confidence_raw.lower() in {"low", "medium", "high"} else ("High" if score >= 80 else "Medium" if score >= 65 else "Low")
        else:
            confidence = "High" if score >= 80 else "Medium" if score >= 65 else "Low"

        action = _coerce_str(item.get("action") or item.get("action_on_trigger"), "monitor").lower()
        if action not in {"redact", "hash", "tokenize", "monitor", "challenge", "deny"}:
            action = "monitor"
        key = _coerce_str(item.get("key") or item.get("target") or item.get("signal"), f"recommendation_{idx + 1}")
        rec_id = _coerce_str(item.get("id"), f"llm-rec-{idx + 1}")
        rationale = _coerce_str(item.get("rationale"), "No rationale provided.")[:600]
        scope = _coerce_str(item.get("scope"), "")
        if not scope:
            tool_scope = item.get("tool_scope")
            if isinstance(tool_scope, list) and tool_scope:
                scope = ", ".join([_coerce_str(x, "") for x in tool_scope if _coerce_str(x, "")])
        if not scope:
            scope = "—"

        change = item.get("change") if isinstance(item.get("change"), dict) else {}
        if not change:
            if kind == "MASKING":
                change = {
                    "masking_rules": [
                        {
                            "field": key,
                            "action": action,
                            "scope": scope if scope != "—" else "*",
                        }
                    ]
                }
            else:
                change = {
                    "discovery_rules": [
                        {
                            "signal": key,
                            "action_on_trigger": action,
                            **({"scope": scope} if scope != "—" else {}),
                        }
                    ]
                }
        normalized.append(
            {
                "id": rec_id,
                "kind": kind,
                "key": key,
                "score": score,
                "confidence": confidence,
                "rationale": rationale,
                "action": action,
                "scope": scope,
                "change": change,
            }
        )
    return normalized


def _extract_recommendation_list_from_llm_payload(payload: Any) -> Optional[List[Any]]:
    if isinstance(payload, list):
        if payload and all(isinstance(item, dict) for item in payload):
            return payload
        return None
    if not isinstance(payload, dict):
        return None

    preferred_keys = [
        "recommendations",
        "policy_tuning_recommendations",
        "policyRecommendations",
        "items",
    ]
    for key in preferred_keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value

    for nested_key in ["data", "result", "output", "response"]:
        nested = payload.get(nested_key)
        extracted = _extract_recommendation_list_from_llm_payload(nested)
        if isinstance(extracted, list):
            return extracted

    for value in payload.values():
        if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
            first = value[0]
            if any(k in first for k in ["type", "kind", "action", "rationale", "target", "signal"]):
                return value
        if isinstance(value, dict):
            extracted = _extract_recommendation_list_from_llm_payload(value)
            if isinstance(extracted, list):
                return extracted
    return None


async def _llm_policy_tuning_recommendations(events: List[Dict[str, Any]], summary: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _llm_risk_config()
    policy_tuning_timeout = float(os.getenv("MCP_PROXY_POLICY_TUNING_LLM_TIMEOUT_SECONDS", "20"))
    tuned_cfg = dict(cfg)
    tuned_cfg["timeout_seconds"] = max(float(cfg.get("timeout_seconds", 5.0)), policy_tuning_timeout)
    fallback_recs = _policy_tuning_recommendations_fallback(summary, events)
    out: Dict[str, Any] = {
        "invoked": False,
        "engine": "none",
        "fallback_used": True,
        "detail": "LLM recommendation synthesis not attempted.",
        "recommendations": fallback_recs,
    }
    client = _build_langchain_client(tuned_cfg) if tuned_cfg.get("provider") == "langchain" else None

    compact_events = [
        {
            "timestamp": _coerce_str(ev.get("timestamp"), ""),
            "tool": _coerce_str(ev.get("tool"), "none"),
            "reason": _coerce_str(ev.get("reason"), "unknown"),
            "client_ip": _coerce_str(ev.get("client_ip"), "unknown"),
            "arguments_summary": _coerce_str(ev.get("arguments_summary"), "")[:220],
        }
        for ev in events[:60]
    ]

    prompt = {
        "task": "Generate policy tuning recommendations for MCP proxy denied-call telemetry.",
        "rules": {
            "return_only_json": True,
            "max_recommendations": 4,
            "required_kinds": ["MASKING", "DISCOVERY"],
            "allowed_actions": ["redact", "hash", "tokenize", "monitor", "challenge", "deny"],
            "schema": {
                "recommendations": [
                    {
                        "id": "string",
                        "kind": "MASKING|DISCOVERY",
                        "key": "string",
                        "score": "0..100",
                        "confidence": "Low|Medium|High",
                        "rationale": "string",
                        "action": "redact|hash|tokenize|monitor|challenge|deny",
                        "scope": "string",
                        "change": "object",
                    }
                ]
            },
        },
        "summary": summary,
        "events": compact_events,
    }

    llm_system_prompt = "You generate SOC policy tuning recommendations. Output JSON only."

    try:
        parsed: Optional[Any] = None
        llm_call_completed = False
        if client is not None and HumanMessage is not None and SystemMessage is not None:
            response = await client.ainvoke([
                SystemMessage(content=llm_system_prompt),
                HumanMessage(content=json.dumps(prompt, ensure_ascii=True)),
            ])
            llm_call_completed = True
            raw_text = _coerce_llm_content_to_text(getattr(response, "content", "")).strip()
            if raw_text:
                candidate = _strip_code_fences(raw_text)
                try:
                    parsed_any = json.loads(candidate)
                    if isinstance(parsed_any, (dict, list)):
                        parsed = parsed_any
                except Exception:
                    parsed = _parse_llm_json_object(raw_text)
        if parsed is None:
            parsed = await _openai_compatible_chat_json(tuned_cfg, llm_system_prompt, prompt)
            if parsed is not None:
                llm_call_completed = True
        if parsed is None:
            out["detail"] = "LLM recommendation synthesis returned empty or invalid output."
            return out
        raw_recs: Any = _extract_recommendation_list_from_llm_payload(parsed)
        llm_recs = _normalize_policy_tuning_recommendations(raw_recs)
        if not llm_recs:
            if llm_call_completed:
                out["invoked"] = True
                out["engine"] = "langchain"
                out["fallback_used"] = True
                out["detail"] = "LLM was invoked, but returned unsupported schema; deterministic fallback supplemented."
            else:
                out["detail"] = "LLM recommendation synthesis returned invalid recommendation schema."
            return out
        return {
            "invoked": True,
            "engine": "langchain",
            "fallback_used": False,
            "detail": "LLM recommendation synthesis successful.",
            "recommendations": llm_recs,
        }
    except Exception as exc:
        logger.warning("mcp_proxy policy_tuning llm failure err=%s", exc)
        out["detail"] = "LLM recommendation synthesis failed; deterministic fallback used."
        return out


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "healthy", "service": "mcp-security-proxy", "version": __version__, "upstream": _UPSTREAM_URL}


@app.get("/metrics")
async def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/recent-denied")
async def recent_denied_calls(limit: int = Query(default=200, ge=1, le=1000), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    with _recent_denied_lock:
        events = list(_recent_denied_events)[:limit]
    return {"count": len(events), "events": events}


@app.get("/recent-decisions")
async def recent_decision_calls(limit: int = Query(default=1000, ge=1, le=10000), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    with _recent_decision_lock:
        events = list(_recent_decision_events)[:limit]
    return {"count": len(events), "events": events}


@app.get("/recent-discovery-alerts")
async def recent_discovery_alerts(limit: int = Query(default=200, ge=1, le=1000), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    with _recent_discovery_lock:
        alerts = list(_recent_discovery_alerts)
    if not alerts:
        with _recent_denied_lock:
            events = list(_recent_denied_events)
        alerts = _build_discovery_alerts_from_events(events)
    alerts = alerts[:limit]
    return {"count": len(alerts), "alerts": alerts}


def _purge_runtime_history_store(clear_runtime_buffers: bool = True) -> Dict[str, Any]:
    global _audit_chain_head, _audit_chain_seq
    cleared = {
        "denied_events": 0,
        "decision_events": 0,
        "discovery_alerts": 0,
        "discovery_cooldowns": 0,
    }
    if clear_runtime_buffers:
        with _recent_denied_lock:
            cleared["denied_events"] = len(_recent_denied_events)
            _recent_denied_events.clear()
        with _recent_decision_lock:
            cleared["decision_events"] = len(_recent_decision_events)
            _recent_decision_events.clear()
        with _recent_discovery_lock:
            cleared["discovery_alerts"] = len(_recent_discovery_alerts)
            _recent_discovery_alerts.clear()
        cleared["discovery_cooldowns"] = len(_discovery_last_trigger_ts)
        _discovery_last_trigger_ts.clear()
        with _audit_chain_lock:
            _audit_chain_head = "genesis"
            _audit_chain_seq = 0

    file_path = _history_file_path()
    file_deleted = False
    if file_path.exists():
        try:
            file_path.unlink()
            file_deleted = True
        except OSError as exc:
            raise RuntimeError(f"failed to delete history file {file_path}: {exc}") from exc

    return {
        "status": "ok",
        "history_file": str(file_path),
        "history_file_deleted": file_deleted,
        "cleared": cleared,
    }


@app.get("/admin/usage")
async def admin_usage(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_permission(authorization, "usage:read")
    return {"status": "ok", "usage": _public_usage_snapshot()}


@app.get("/admin/entitlements")
async def admin_entitlements(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_permission(authorization, "usage:read")
    entitlements = _public_entitlements()
    entitlements["governance"] = gov.public_governance_status(_governance_profile())
    return {"status": "ok", "entitlements": entitlements}


@app.get("/admin/audit-export")
async def admin_audit_export(
    format: str = Query(default="json"),
    authorization: Optional[str] = Header(default=None),
) -> Response:
    _require_admin_permission(authorization, "audit:read")
    export_format = str(format or "json").strip().lower()
    if export_format not in {"json", "ndjson"}:
        raise HTTPException(status_code=400, detail="format must be json or ndjson")
    payload = _build_audit_export_payload()
    if export_format == "ndjson":
        lines = []
        for key in ("recent_denied_events", "recent_decision_events", "recent_discovery_alerts"):
            for item in payload.get(key, []):
                if isinstance(item, dict):
                    lines.append(json.dumps({"record_type": key, **item}, ensure_ascii=True))
        body = "\n".join(lines)
        if body:
            body += "\n"
        return Response(content=body, media_type="application/x-ndjson")
    return JSONResponse(content={"status": "ok", "audit": payload})


@app.get("/admin/audit-integrity")
async def admin_audit_integrity(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_permission(authorization, "audit:read")
    return {"status": "ok", "integrity": _audit_integrity_snapshot()}


@app.get("/admin/runtime-history")
async def admin_runtime_history(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_permission(authorization, "audit:read")
    file_path = _history_file_path()
    return {
        "status": "ok",
        "history_file": str(file_path),
        "history_file_exists": file_path.exists(),
        "in_memory": {
            "denied_events": len(_recent_denied_events),
            "decision_events": len(_recent_decision_events),
            "discovery_alerts": len(_recent_discovery_alerts),
            "discovery_cooldowns": len(_discovery_last_trigger_ts),
        },
    }


@app.post("/admin/purge-runtime-history")
async def admin_purge_runtime_history(payload: Dict[str, Any] = Body(default_factory=dict), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_permission(authorization, "audit:purge")
    clear_runtime_buffers = bool(payload.get("clear_runtime_buffers", True)) if isinstance(payload, dict) else True
    try:
        return _purge_runtime_history_store(clear_runtime_buffers=clear_runtime_buffers)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/soc/proxy-runtime-history-purge")
async def soc_proxy_runtime_history_purge(payload: Dict[str, Any] = Body(default_factory=dict), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    clear_runtime_buffers = bool(payload.get("clear_runtime_buffers", True)) if isinstance(payload, dict) else True
    try:
        result = _purge_runtime_history_store(clear_runtime_buffers=clear_runtime_buffers)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {"status": "ok", "result": result}


@app.get("/admin/policy-config")
async def get_policy_config(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_permission(authorization, "policy:read")
    current = _read_policy_config()
    return {
        "status": "ok",
        "policy_file": str(_policy_file_path()),
        "raw_policy": current,
        "summary": _policy_config_summary(current),
    }


@app.get("/admin/auth/me")
async def admin_auth_me(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    ctx = _resolve_auth_context(authorization)
    return {
        "status": "ok",
        "principal": {
            "subject": ctx.subject,
            "role": ctx.role,
            "auth_method": ctx.auth_method,
            "permissions": sorted(gov.ROLE_PERMISSIONS.get(ctx.role, frozenset())),
        },
    }


@app.get("/admin/governance/status")
async def admin_governance_status(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_permission(authorization, "governance:read")
    return {"status": "ok", "governance": gov.public_governance_status(_governance_profile())}


@app.get("/admin/auth/oidc/config")
async def admin_oidc_config(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_permission(authorization, "governance:read")
    return {"status": "ok", "oidc": gov.public_oidc_config(_governance_profile())}


@app.get("/admin/policy-versions")
async def admin_policy_versions(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_permission(authorization, "policy:read")
    return {"status": "ok", "versions": gov.list_policy_versions()}


@app.get("/admin/policy-versions/{version_id}")
async def admin_policy_version_detail(version_id: str, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_permission(authorization, "policy:read")
    record = gov.get_policy_version(version_id)
    if record is None:
        raise HTTPException(status_code=404, detail="policy version not found")
    return {"status": "ok", "version": record}


@app.post("/admin/policy-versions")
async def admin_policy_version_snapshot(
    payload: Dict[str, Any] = Body(default_factory=dict),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    ctx = _require_admin_permission(authorization, "policy:write")
    lifecycle = _policy_lifecycle_settings()
    if _governance_profile().get("enabled") and not lifecycle.get("enabled", True):
        raise HTTPException(status_code=403, detail={"reason": "policy_lifecycle_disabled"})
    current = _read_policy_config()
    reason = str(payload.get("reason", "manual snapshot") if isinstance(payload, dict) else "manual snapshot")
    record = gov.save_policy_version(
        current,
        created_by=ctx.subject,
        reason=reason,
        max_versions=max(1, int(lifecycle.get("max_versions", 50))),
    )
    return {"status": "ok", "version": record}


@app.post("/admin/policy-rollback")
async def admin_policy_rollback(
    payload: Dict[str, Any] = Body(default_factory=dict),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    ctx = _require_admin_permission(authorization, "policy:rollback")
    version_id = str(payload.get("version_id", "")).strip() if isinstance(payload, dict) else ""
    if not version_id:
        raise HTTPException(status_code=400, detail="'version_id' is required")
    record = gov.get_policy_version(version_id)
    if record is None:
        raise HTTPException(status_code=404, detail="policy version not found")
    policy_body = record.get("policy")
    if not isinstance(policy_body, dict):
        raise HTTPException(status_code=500, detail="stored policy version is invalid")
    return _apply_policy_update(
        policy_body,
        ctx=ctx,
        reason=f"rollback to {version_id}",
        force=True,
    )


@app.get("/admin/policy-proposals")
async def admin_policy_proposals(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_permission(authorization, "policy:read")
    return {"status": "ok", "proposals": gov.list_policy_proposals()}


@app.post("/admin/policy-proposals")
async def admin_policy_proposal_create(
    payload: Dict[str, Any] = Body(default_factory=dict),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    ctx = _require_admin_permission(authorization, "policy:write")
    raw_policy = payload.get("raw_policy") if isinstance(payload, dict) else None
    if not isinstance(raw_policy, dict):
        raise HTTPException(status_code=400, detail="'raw_policy' must be a JSON object")
    note = str(payload.get("note", "policy proposal") if isinstance(payload, dict) else "policy proposal")
    proposal = gov.create_policy_proposal(raw_policy, proposed_by=ctx.subject, note=note)
    return {"status": "ok", "proposal": proposal}


@app.post("/admin/policy-proposals/{proposal_id}/approve")
async def admin_policy_proposal_approve(
    proposal_id: str,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    ctx = _require_admin_permission(authorization, "policy:approve")
    proposals = gov.list_policy_proposals()
    match = next((p for p in proposals if p.get("proposal_id") == proposal_id), None)
    if match is None:
        raise HTTPException(status_code=404, detail="proposal not found")
    if match.get("status") != "pending":
        raise HTTPException(status_code=409, detail=f"proposal status is {match.get('status')}")
    raw_policy = match.get("raw_policy")
    if not isinstance(raw_policy, dict):
        raise HTTPException(status_code=500, detail="proposal policy payload invalid")
    result = _apply_policy_update(raw_policy, ctx=ctx, reason=f"approved proposal {proposal_id}", force=True)
    gov.update_proposal_status(proposal_id, new_status="approved", actor=ctx.subject)
    result["proposal_id"] = proposal_id
    result["proposal_status"] = "approved"
    return result


@app.post("/admin/policy-proposals/{proposal_id}/reject")
async def admin_policy_proposal_reject(
    proposal_id: str,
    payload: Dict[str, Any] = Body(default_factory=dict),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    ctx = _require_admin_permission(authorization, "policy:approve")
    reason = str(payload.get("reason", "rejected") if isinstance(payload, dict) else "rejected")
    updated = gov.update_proposal_status(
        proposal_id,
        new_status="rejected",
        actor=ctx.subject,
        rejection_reason=reason,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="proposal not found")
    return {"status": "ok", "proposal": updated}


@app.post("/admin/sign-policy-bundle")
async def admin_sign_policy_bundle(
    payload: Dict[str, Any] = Body(default_factory=dict),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _require_admin_permission(authorization, "bundle:sign")
    signing = _governance_profile().get("signing")
    signing = signing if isinstance(signing, dict) else {}
    if not signing.get("enabled"):
        raise HTTPException(status_code=403, detail={"reason": "signing_disabled"})
    bundle = payload.get("policy_bundle") if isinstance(payload, dict) else None
    if not isinstance(bundle, dict):
        raise HTTPException(status_code=400, detail="'policy_bundle' must be a JSON object")
    signing_key = str(signing.get("signing_key", "")).strip()
    if not signing_key:
        raise HTTPException(status_code=400, detail={"reason": "signing_key_not_configured"})
    try:
        signed = gov.sign_policy_bundle(bundle, signing_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "signed_bundle": signed}


@app.get("/soc/proxy-policy-config")
async def soc_proxy_policy_config_get(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    current = _read_policy_config()
    return {
        "status": "ok",
        "policy_file": str(_policy_file_path()),
        "raw_policy": current,
        "summary": _policy_config_summary(current),
    }


@app.get("/admin/llm-risk-config")
async def get_llm_risk_config(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    return {
        "status": "ok",
        "llm_risk": _public_llm_risk_config(),
    }


@app.get("/admin/tool-intent-config")
async def get_tool_intent_config(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    return {
        "status": "ok",
        "tool_intent": _public_tool_intent_config(),
    }


@app.post("/admin/policy-config")
async def update_policy_config(request: Request, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    ctx = _require_admin_permission(authorization, "policy:write")
    payload = await request.json()
    raw_policy = payload.get("raw_policy") if isinstance(payload, dict) else None
    if raw_policy is None and isinstance(payload, dict):
        raw_policy = payload.get("policy")
    if not isinstance(raw_policy, dict):
        raise HTTPException(status_code=400, detail="'raw_policy' must be a JSON object")
    force = bool(payload.get("force", False)) if isinstance(payload, dict) else False
    reason = str(payload.get("reason", "admin policy update") if isinstance(payload, dict) else "admin policy update")
    return _apply_policy_update(dict(raw_policy), ctx=ctx, reason=reason, force=force)


@app.post("/soc/proxy-policy-config")
async def soc_proxy_policy_config_update(payload: Dict[str, Any] = Body(default_factory=dict), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    raw_policy = payload.get("raw_policy") if isinstance(payload, dict) else None
    if raw_policy is None and isinstance(payload, dict):
        raw_policy = payload.get("policy")
    if not isinstance(raw_policy, dict):
        raise HTTPException(status_code=400, detail="'raw_policy' must be a JSON object")

    backup_path = _backup_policy_file()
    _write_policy_config(dict(raw_policy))
    _reload_policy()
    return {
        "status": "ok",
        "message": "policy updated",
        "backup_file": str(backup_path),
        "policy_file": str(_policy_file_path()),
        "raw_policy": raw_policy,
        "summary": _policy_config_summary(raw_policy),
    }


def _extract_verified_policy_bundle(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    signing = _governance_profile().get("signing")
    signing = signing if isinstance(signing, dict) else {}
    signed_envelope = payload.get("signed_bundle")
    bundle = payload.get("policy_bundle")
    signature_meta: Optional[Dict[str, Any]] = None

    if isinstance(signed_envelope, dict):
        signing_key = str(signing.get("signing_key", "")).strip()
        ok, reason = gov.verify_signed_bundle_envelope(signed_envelope, signing_key)
        if not ok:
            raise HTTPException(status_code=400, detail={"reason": reason, "field": "signed_bundle"})
        bundle = signed_envelope.get("policy_bundle")
        signature_meta = {
            "verified": True,
            "algorithm": signed_envelope.get("algorithm"),
            "signed_at": signed_envelope.get("signed_at"),
        }
    elif signing.get("enabled") and signing.get("require_signature_on_apply"):
        raise HTTPException(status_code=400, detail={"reason": "signed_bundle_required", "field": "signed_bundle"})

    if not isinstance(bundle, dict):
        raise HTTPException(status_code=400, detail="'policy_bundle' must be a JSON object")
    return bundle, signature_meta


@app.post("/admin/apply-policy-bundle")
async def apply_policy_bundle(request: Request, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    ctx = _require_admin_permission(authorization, "bundle:apply")
    if not _feature_enabled("policy_bundles", default=False):
        raise HTTPException(
            status_code=403,
            detail={"reason": "feature_not_entitled", "feature": "policy_bundles", "tier": _commercial_tier()},
        )

    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    bundle, signature_meta = _extract_verified_policy_bundle(payload)
    dry_run = bool(payload.get("dry_run", False))

    current = _read_policy_config()
    updated, summary = _apply_policy_bundle_to_config(current, bundle)

    backup_path = None
    version = None
    if not dry_run:
        _maybe_version_policy(current, created_by=ctx.subject, reason="pre-bundle snapshot")
        backup_path = _backup_policy_file()
        _write_policy_config(updated)
        _reload_policy()
        version = _maybe_version_policy(updated, created_by=ctx.subject, reason="policy bundle apply")

    return {
        "status": "ok",
        "message": "dry-run apply completed" if dry_run else "policy bundle applied",
        "dry_run": dry_run,
        "backup_file": str(backup_path) if backup_path is not None else None,
        "policy_file": str(_policy_file_path()),
        "summary": summary,
        "applied": not dry_run,
        "signature": signature_meta,
        "version": (
            {"version_id": version.get("version_id"), "content_hash": version.get("content_hash")}
            if isinstance(version, dict)
            else None
        ),
        "applied_by": ctx.subject,
    }


@app.post("/soc/proxy-policy-bundle-apply")
async def soc_proxy_policy_bundle_apply(payload: Dict[str, Any] = Body(default_factory=dict), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    if not _feature_enabled("policy_bundles", default=False):
        raise HTTPException(
            status_code=403,
            detail={"reason": "feature_not_entitled", "feature": "policy_bundles", "tier": _commercial_tier()},
        )
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
        "result": {
            "status": "ok",
            "message": "dry-run apply completed" if dry_run else "policy bundle applied",
            "dry_run": dry_run,
            "backup_file": str(backup_path) if backup_path is not None else None,
            "policy_file": str(_policy_file_path()),
            "summary": summary,
            "applied": not dry_run,
        },
    }


@app.post("/admin/llm-risk-config")
async def update_llm_risk_config(request: Request, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    patch = payload.get("llm_risk")
    if not isinstance(patch, dict):
        raise HTTPException(status_code=400, detail="'llm_risk' must be a JSON object")

    current = _read_policy_config()
    current_llm_risk = current.get("llm_risk") if isinstance(current.get("llm_risk"), dict) else {}
    current["llm_risk"] = _apply_llm_risk_patch(current_llm_risk, patch)
    _write_policy_config(current)
    _reload_policy()

    return {
        "status": "ok",
        "message": "llm_risk policy updated",
        "llm_risk": _public_llm_risk_config(),
    }


@app.post("/admin/tool-intent-config")
async def update_tool_intent_config(request: Request, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    patch = payload.get("tool_intent")
    if not isinstance(patch, dict):
        raise HTTPException(status_code=400, detail="'tool_intent' must be a JSON object")

    current = _read_policy_config()
    current_tool_intent = current.get("tool_intent") if isinstance(current.get("tool_intent"), dict) else {}
    current["tool_intent"] = _apply_tool_intent_patch(current_tool_intent, patch)
    _write_policy_config(current)
    _reload_policy()

    return {
        "status": "ok",
        "message": "tool_intent policy updated",
        "tool_intent": _public_tool_intent_config(),
    }


@app.post("/admin/reload-policy")
async def reload_policy(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    updated = _reload_policy()
    return {
        "status": "ok",
        "message": "policy reloaded",
        "policy_file": str(_policy_file_path()),
        "llm_risk_enabled": bool((updated.llm_risk or {}).get("enabled", False)) if isinstance(updated.llm_risk, dict) else False,
        "tool_intent_enabled": bool((updated.tool_intent or {}).get("enabled", False)) if isinstance(updated.tool_intent, dict) else False,
    }


@app.get("/soc/proxy-llm-risk-config")
async def soc_proxy_llm_risk_config_get(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    return {
        "status": "ok",
        "llm_risk": _public_llm_risk_config(),
        "steps": {
            "step1_enabled_score_only": True,
            "step2_observe": True,
            "step3_tune_thresholds": True,
            "step4_enable_enforcement": True,
        },
    }


@app.post("/soc/proxy-llm-risk-config")
async def soc_proxy_llm_risk_config_update(payload: Dict[str, Any] = Body(default_factory=dict), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    llm_risk = payload.get("llm_risk") if isinstance(payload, dict) else None
    if not isinstance(llm_risk, dict):
        raise HTTPException(status_code=400, detail="'llm_risk' must be a JSON object")
    current = _read_policy_config()
    current_llm_risk = current.get("llm_risk") if isinstance(current.get("llm_risk"), dict) else {}
    current["llm_risk"] = _apply_llm_risk_patch(current_llm_risk, llm_risk)
    _write_policy_config(current)
    _reload_policy()
    return {
        "status": "ok",
        "message": "llm_risk config updated",
        "llm_risk": _public_llm_risk_config(),
    }


@app.get("/soc/proxy-tool-intent-config")
async def soc_proxy_tool_intent_config_get(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    return {
        "status": "ok",
        "tool_intent": _public_tool_intent_config(),
        "steps": {
            "step1_enabled_score_only": True,
            "step2_observe": True,
            "step3_tune_thresholds": True,
            "step4_enable_enforcement": True,
        },
    }


@app.post("/soc/proxy-tool-intent-config")
async def soc_proxy_tool_intent_config_update(payload: Dict[str, Any] = Body(default_factory=dict), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    tool_intent = payload.get("tool_intent") if isinstance(payload, dict) else None
    if not isinstance(tool_intent, dict):
        raise HTTPException(status_code=400, detail="'tool_intent' must be a JSON object")
    current = _read_policy_config()
    current_tool_intent = current.get("tool_intent") if isinstance(current.get("tool_intent"), dict) else {}
    current["tool_intent"] = _apply_tool_intent_patch(current_tool_intent, tool_intent)
    _write_policy_config(current)
    _reload_policy()
    return {
        "status": "ok",
        "message": "tool_intent config updated",
        "tool_intent": _public_tool_intent_config(),
    }


@app.get("/soc/proxy-llm-risk-observability")
async def soc_proxy_llm_risk_observability(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    lines = _metrics_lines_for_prefixes(
        [
            "mcp_security_proxy_llm_risk_calls_total",
            "mcp_security_proxy_llm_risk_latency_seconds",
            "mcp_security_proxy_llm_risk_score",
            "mcp_security_proxy_llm_risk_value",
        ],
        limit=40,
    )
    return {
        "status": "ok",
        "metrics_found": bool(lines),
        "sample_lines": lines,
        "log_hint": "Check mcp-security-proxy logs for llm_risk decisions.",
    }


@app.get("/soc/proxy-tool-intent-observability")
async def soc_proxy_tool_intent_observability(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    lines = _metrics_lines_for_prefixes(
        [
            "mcp_security_proxy_tool_intent_calls_total",
            "mcp_security_proxy_tool_intent_latency_seconds",
            "mcp_security_proxy_tool_intent_score",
        ],
        limit=40,
    )
    return {
        "status": "ok",
        "metrics_found": bool(lines),
        "sample_lines": lines,
        "log_hint": "Check mcp-security-proxy logs for tool_intent decisions.",
    }


@app.post("/soc/proxy-denied-llm-analysis")
async def soc_proxy_denied_llm_analysis(payload: Dict[str, Any] = Body(default_factory=dict), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    time_range = _coerce_str(payload.get("time_range"), "24h") or "24h"
    limit = max(1, min(200, _coerce_int(payload.get("limit"), 50)))
    include_events = bool(payload.get("include_events", True))
    llm_risk_only = bool(payload.get("llm_risk_only", False))
    run_llm = bool(payload.get("run_llm", False))

    now = time.time()
    range_start = now - float(_time_range_to_seconds(time_range, default_seconds=86400))

    with _recent_denied_lock:
        recent_events = list(_recent_denied_events)

    ranged_events = [
        ev for ev in recent_events
        if _event_ts_to_epoch(ev.get("timestamp")) >= range_start
    ]
    all_events = ranged_events[:limit]

    if llm_risk_only:
        filtered_events = [
            ev for ev in all_events
            if _coerce_str(ev.get("reason")).startswith("llm_risk_")
        ]
    else:
        filtered_events = all_events

    summary = _summarize_proxy_denied(filtered_events)
    llm_meta: Dict[str, Any] = {
        "invoked": False,
        "engine": "none",
        "fallback_used": True,
        "detail": "LLM synthesis is not required; standalone heuristic analysis is returned by the proxy component.",
        "requested": run_llm,
    }
    tuning_recs = _policy_tuning_recommendations_fallback(summary, filtered_events)
    if run_llm:
        llm_out = await _llm_policy_tuning_recommendations(filtered_events, summary)
        llm_meta = {
            **llm_meta,
            "invoked": bool(llm_out.get("invoked")),
            "engine": _coerce_str(llm_out.get("engine"), "none"),
            "fallback_used": bool(llm_out.get("fallback_used", True)),
            "detail": _coerce_str(llm_out.get("detail"), llm_meta["detail"]),
        }
        recs = llm_out.get("recommendations")
        if isinstance(recs, list) and recs:
            tuning_recs = recs

    response: Dict[str, Any] = {
        "status": "ok",
        "source": "mcp_proxy_recent_denied_local",
        "time_range": time_range,
        "events_count": len(filtered_events),
        "events_total": len(filtered_events),
        "events_total_in_range": len(ranged_events),
        "llm_risk_only": llm_risk_only,
        "summary": summary,
        "root_cause": _proxy_denied_root_cause(summary),
        "recommendations": _proxy_tuning_recommendations(summary),
        "policy_tuning_recommendations": tuning_recs,
        "llm": llm_meta,
    }

    if include_events:
        response["events"] = filtered_events
    return response


@app.post("/soc/proxy-policy-recommendations")
async def soc_proxy_policy_recommendations(payload: Dict[str, Any] = Body(default_factory=dict), authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _validate_or_raise_proxy_auth(authorization)
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    time_range = _coerce_str(payload.get("time_range"), "24h") or "24h"
    limit = max(10, min(500, _coerce_int(payload.get("limit"), 100)))
    focus = _coerce_str(payload.get("focus"), "all").lower() or "all"
    if focus not in {"all", "overblocking", "underblocking"}:
        focus = "all"
    recommendation_types = payload.get("recommendation_types", ["masking", "discovery"])
    if not isinstance(recommendation_types, list):
        recommendation_types = ["masking", "discovery"]
    recommendation_types = [str(item).strip().lower() for item in recommendation_types if str(item).strip()]
    if not recommendation_types:
        recommendation_types = ["masking", "discovery"]
    run_llm = bool(payload.get("run_llm", True))

    now = time.time()
    range_start = now - float(_time_range_to_seconds(time_range, default_seconds=86400))

    with _recent_denied_lock:
        denied_events = [
            ev for ev in list(_recent_denied_events)
            if _event_ts_to_epoch(ev.get("timestamp")) >= range_start
        ][:limit]
    denied_summary = _summarize_proxy_denied(denied_events)

    analysis_summary = {
        "time_range": time_range,
        "focus": focus,
        "total_denied": denied_summary.get("total", 0),
        "deny_reasons": dict(sorted((denied_summary.get("reason_counts", {}) or {}).items(), key=lambda x: x[1], reverse=True)[:10]),
        "top_denied_tools": dict(sorted((denied_summary.get("tool_counts", {}) or {}).items(), key=lambda x: x[1], reverse=True)[:5]),
        "top_offending_client": denied_summary.get("top_client_ip", "unknown"),
    }

    llm_meta: Dict[str, Any] = {
        "invoked": False,
        "engine": "deterministic",
        "fallback_used": False,
        "detail": "Deterministic recommendation generation used.",
        "requested": run_llm,
    }

    normalized_recs = _policy_tuning_recommendations_fallback(denied_summary, denied_events)
    if run_llm:
        llm_out = await _llm_policy_tuning_recommendations(denied_events, denied_summary)
        llm_meta = {
            **llm_meta,
            "invoked": bool(llm_out.get("invoked")),
            "engine": _coerce_str(llm_out.get("engine"), "deterministic") or "deterministic",
            "fallback_used": bool(llm_out.get("fallback_used", False)),
            "detail": _coerce_str(llm_out.get("detail"), llm_meta["detail"]),
        }
        llm_recs = llm_out.get("recommendations")
        if isinstance(llm_recs, list) and llm_recs:
            normalized_recs = llm_recs

    def _to_api_rec(item: Dict[str, Any]) -> Dict[str, Any]:
        kind = _coerce_str(item.get("kind"), "MASKING").lower()
        rec_type = "discovery" if kind == "discovery" else "masking"
        confidence = max(0.0, min(1.0, float(_coerce_int(item.get("score"), 60) / 100.0)))
        scope = _coerce_str(item.get("scope"), "")
        tool_scope = [] if scope in {"", "—", "none"} else [scope]
        rec: Dict[str, Any] = {
            "id": _coerce_str(item.get("id"), "rec"),
            "type": rec_type,
            "target": _coerce_str(item.get("key"), "target"),
            "action": _coerce_str(item.get("action"), "monitor"),
            "rationale": _coerce_str(item.get("rationale"), "No rationale provided."),
            "confidence": confidence,
            "tool_scope": tool_scope,
            "impact": "low" if confidence < 0.65 else "medium",
            "change": item.get("change") if isinstance(item.get("change"), dict) else {},
        }
        if rec_type == "discovery":
            rec["signal"] = _coerce_str(item.get("key"), "repeated_tool_denials")
            rec["threshold"] = "5 denials in 5 minutes"
            rec["action_on_trigger"] = _coerce_str(item.get("action"), "monitor")
        else:
            rec["mode"] = _coerce_str(item.get("action"), "redact")
        return rec

    api_recommendations = [_to_api_rec(item) for item in normalized_recs]
    if "masking" not in recommendation_types:
        api_recommendations = [rec for rec in api_recommendations if rec.get("type") != "masking"]
    if "discovery" not in recommendation_types:
        api_recommendations = [rec for rec in api_recommendations if rec.get("type") != "discovery"]

    return {
        "status": "ok",
        "summary": analysis_summary,
        "llm": llm_meta,
        "recommendations": api_recommendations,
        "human_review_required": True,
        "safety_model": "recommendations_only_no_auto_apply",
        "next_steps": [
            "Review each recommendation rationale and confidence score",
            "Validate recommendation against known SOC use cases",
            "Test recommendation in staging/lab with trace monitoring",
            "Apply only after team consensus and change control approval",
        ],
    }


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    # Browsers request /favicon.ico automatically; avoid noisy 404s in the console.
    return Response(status_code=204)


@app.get("/ui", response_class=HTMLResponse)
async def ui() -> HTMLResponse:
    html_path = static_dir / "index.html"
    if html_path.exists():
        return HTMLResponse(
            html_path.read_text(encoding="utf-8"),
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "Pragma": "no-cache",
                "X-MCP-Proxy-UI-Build": "resize-v6-dividers",
            },
        )
    return HTMLResponse("<h1>MCP Security Proxy</h1><p>UI not bundled.</p>")


@app.get("/", response_class=HTMLResponse)
async def root() -> HTMLResponse:
    return HTMLResponse(f"<h1>MCP Security Proxy {__version__}</h1><p>See <a href='/ui'>/ui</a>, <a href='/metrics'>/metrics</a>, <a href='/docs'>/docs</a>.</p>")


@app.post("/mcp")
async def mcp_proxy(request: Request, authorization: Optional[str] = Header(default=None)) -> JSONResponse:
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
    params = payload.get("params") or {}
    arguments = params.get("arguments", {}) if isinstance(params, dict) else {}
    args_keys = _argument_keys(arguments)
    auth_subject = "proxy_api_key"
    usage_ok, usage_reason, usage_enforcement = _check_usage_limit("mcp_calls")
    if not usage_ok and usage_enforcement == "deny":
        elapsed = time.time() - start
        MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
        MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=usage_reason).inc()
        MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
        denied_event = _record_denied_event(
            request_id, method, tool, usage_reason, arguments, client_ip,
            metadata={"tier": _commercial_tier(), "kind": "mcp_calls"},
        )
        _evaluate_discovery_rules(denied_event)
        _record_decision_event(
            stage="commercial",
            decision="deny",
            method=method,
            tool=tool,
            reason=usage_reason,
            client_ip=client_ip,
            request_id=request_id,
            elapsed_ms=int(elapsed * 1000),
            args_keys=args_keys,
            auth_subject=auth_subject,
        )
        return _jsonrpc_error(
            request_id, -32003, "Request denied by MCP proxy tier limit", 403,
            {"reason": usage_reason, "tier": _commercial_tier()},
        )
    if not usage_ok and usage_enforcement == "monitor":
        _record_decision_event(
            stage="commercial",
            decision="monitor",
            method=method,
            tool=tool,
            reason=usage_reason,
            client_ip=client_ip,
            request_id=request_id,
            args_keys=args_keys,
            auth_subject=auth_subject,
        )
    _increment_usage_counter("mcp_calls")
    allowed, reason = _policy_decision(payload)
    if not allowed:
        elapsed = time.time() - start
        MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
        MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=reason).inc()
        MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
        denied_event = _record_denied_event(request_id, method, tool, reason, arguments, client_ip)
        _evaluate_discovery_rules(denied_event)
        decision_word = "challenge" if reason.startswith("blocked_pattern_challenge:") else "deny"
        _record_decision_event(
            stage="policy",
            decision=decision_word,
            method=method,
            tool=tool,
            reason=reason,
            client_ip=client_ip,
            request_id=request_id,
            elapsed_ms=int(elapsed * 1000),
            args_keys=args_keys,
            auth_subject=auth_subject,
        )
        message = "Request challenged by MCP proxy policy" if reason.startswith("blocked_pattern_challenge:") else "Request denied by MCP proxy policy"
        data = {"reason": reason, **({"decision_hint": "challenge"} if reason.startswith("blocked_pattern_challenge:") else {})}
        return _jsonrpc_error(request_id, -32003, message, 403, data)

    if not _is_trusted_upstream(_UPSTREAM_URL):
        action = policy.untrusted_server_action
        if action in {"deny", "challenge"}:
            elapsed = time.time() - start
            deny_reason = "untrusted_server" if action == "deny" else "untrusted_server_challenge"
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(
                request_id, method, tool, deny_reason, arguments, client_ip,
                metadata={"upstream_url": _UPSTREAM_URL},
            )
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="trust", decision="challenge" if action == "challenge" else "deny",
                method=method, tool=tool, reason=deny_reason, client_ip=client_ip,
                request_id=request_id, elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys, auth_subject=auth_subject,
            )
            return _jsonrpc_error(
                request_id, -32003, "Upstream server not in trusted_servers policy", 403,
                {"reason": deny_reason, "upstream_url": _UPSTREAM_URL},
            )
        else:
            _record_decision_event(
                stage="trust", decision="monitor",
                method=method, tool=tool, reason="untrusted_server_monitor",
                client_ip=client_ip, request_id=request_id,
                args_keys=args_keys, auth_subject=auth_subject,
            )

    sandbox_ok, sandbox_reason, sandbox_meta = _sandbox_attestation_check(method, tool, params)
    if not sandbox_ok:
        action = str((policy.sandbox_attestation_profile or {}).get("action", "deny")).strip().lower()
        if action in {"deny", "challenge"}:
            elapsed = time.time() - start
            deny_reason = sandbox_reason if action == "deny" else "sandbox_attestation_challenge"
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(
                request_id, method, tool, deny_reason, arguments, client_ip,
                metadata={"action": action, **(sandbox_meta if isinstance(sandbox_meta, dict) else {})},
            )
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="sandbox_attestation",
                decision="challenge" if action == "challenge" else "deny",
                method=method,
                tool=tool,
                reason=deny_reason,
                client_ip=client_ip,
                request_id=request_id,
                elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            return _jsonrpc_error(
                request_id, -32003, "Sandbox attestation check failed", 403,
                {"reason": deny_reason, **(sandbox_meta if isinstance(sandbox_meta, dict) else {})},
            )
        _record_decision_event(
            stage="sandbox_attestation",
            decision="monitor",
            method=method,
            tool=tool,
            reason="sandbox_attestation_monitor",
            client_ip=client_ip,
            request_id=request_id,
            args_keys=args_keys,
            auth_subject=auth_subject,
        )

    dep_ok, dep_reason, dep_meta = await _dependency_fail_safe_check(method)
    if not dep_ok:
        action = str((policy.dependency_fail_safe_profile or {}).get("action", "deny")).strip().lower()
        if action in {"deny", "challenge"}:
            elapsed = time.time() - start
            deny_reason = dep_reason if action == "deny" else "dependency_health_challenge"
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(
                request_id, method, tool, deny_reason, arguments, client_ip,
                metadata=dep_meta if isinstance(dep_meta, dict) else {},
            )
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="dependency_health",
                decision="challenge" if action == "challenge" else "deny",
                method=method,
                tool=tool,
                reason=deny_reason,
                client_ip=client_ip,
                request_id=request_id,
                elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            return _jsonrpc_error(
                request_id, -32003, "Required dependency health checks failed", 403,
                {"reason": deny_reason, **(dep_meta if isinstance(dep_meta, dict) else {})},
            )
        _record_decision_event(
            stage="dependency_health",
            decision="monitor",
            method=method,
            tool=tool,
            reason="dependency_health_monitor",
            client_ip=client_ip,
            request_id=request_id,
            args_keys=args_keys,
            auth_subject=auth_subject,
        )

    # Sprint 3: Isolated executor routing check
    exec_ok, exec_reason, exec_meta = _isolated_executor_check(method, tool, params)
    route_to_executor = False
    executor_url = None
    if not exec_ok:
        action = str((policy.isolated_executor_profile or {}).get("action", "deny")).strip().lower()
        if action in {"deny", "challenge"}:
            elapsed = time.time() - start
            deny_reason = exec_reason if action == "deny" else "isolated_executor_challenge"
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(
                request_id, method, tool, deny_reason, arguments, client_ip,
                metadata=exec_meta if isinstance(exec_meta, dict) else {},
            )
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="isolated_executor",
                decision="challenge" if action == "challenge" else "deny",
                method=method,
                tool=tool,
                reason=deny_reason,
                client_ip=client_ip,
                request_id=request_id,
                elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            return _jsonrpc_error(
                request_id, -32003, "Isolated executor check failed", 403,
                {"reason": deny_reason, **(exec_meta if isinstance(exec_meta, dict) else {})},
            )
        _record_decision_event(
            stage="isolated_executor",
            decision="monitor",
            method=method,
            tool=tool,
            reason="isolated_executor_monitor",
            client_ip=client_ip,
            request_id=request_id,
            args_keys=args_keys,
            auth_subject=auth_subject,
        )
    elif exec_reason == "route_to_executor":
        route_to_executor = True
        executor_url = exec_meta.get("executor_url") if isinstance(exec_meta, dict) else None

    llm_risk = None
    if method == "tools/call" and _feature_enabled("llm_risk", True):
        llm_usage_ok, llm_usage_reason, llm_usage_enforcement = _check_usage_limit("llm_risk_calls")
        if not llm_usage_ok and llm_usage_enforcement == "deny":
            elapsed = time.time() - start
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=llm_usage_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(
                request_id, method, tool, llm_usage_reason, arguments, client_ip,
                metadata={"tier": _commercial_tier(), "kind": "llm_risk_calls"},
            )
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="commercial",
                decision="deny",
                method=method,
                tool=tool,
                reason=llm_usage_reason,
                client_ip=client_ip,
                request_id=request_id,
                elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            return _jsonrpc_error(
                request_id, -32003, "Request denied by MCP proxy tier limit", 403,
                {"reason": llm_usage_reason, "tier": _commercial_tier()},
            )
        if not llm_usage_ok and llm_usage_enforcement == "monitor":
            _record_decision_event(
                stage="commercial",
                decision="monitor",
                method=method,
                tool=tool,
                reason=llm_usage_reason,
                client_ip=client_ip,
                request_id=request_id,
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
        llm_risk = await _llm_risk_score(method, tool, arguments, client_ip)
        if llm_risk is not None:
            _increment_usage_counter("llm_risk_calls")
    if llm_risk is not None:
        cfg = _llm_risk_config()
        hint = str(llm_risk.get("decision_hint", "allow"))
        score = float(llm_risk.get("risk_score", 0.0))
        fail_safe_cfg = policy.dependency_fail_safe_profile if isinstance(policy.dependency_fail_safe_profile, dict) else {}
        if cfg["enforce"] and fail_safe_cfg.get("prevent_silent_bypass", True) and _security_layer_unavailable(llm_risk, "llm_risk_unavailable"):
            elapsed = time.time() - start
            deny_reason = "security_layer_bypass_prevented"
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(
                request_id, method, tool, deny_reason, arguments, client_ip,
                metadata={"required_layer": "llm_risk", "result": llm_risk},
            )
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="llm_risk",
                decision="deny",
                method=method,
                tool=tool,
                reason=deny_reason,
                client_ip=client_ip,
                request_id=request_id,
                score=score,
                labels=llm_risk.get("labels") or [],
                rationale="required llm_risk layer unavailable in enforce mode",
                enforce=cfg["enforce"],
                elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            return _jsonrpc_error(
                request_id, -32003, "Required security layer unavailable", 403,
                {"reason": deny_reason, "required_layer": "llm_risk"},
            )
        if cfg["enforce"] and hint in {"deny", "challenge"}:
            elapsed = time.time() - start
            deny_reason = "llm_risk_deny" if hint == "deny" else "llm_risk_challenge"
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(request_id, method, tool, deny_reason, arguments, client_ip, metadata=llm_risk)
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="llm_risk",
                decision=hint,
                method=method,
                tool=tool,
                reason=deny_reason,
                client_ip=client_ip,
                request_id=request_id,
                score=score,
                labels=llm_risk.get("labels") or [],
                rationale=llm_risk.get("rationale") or "",
                enforce=cfg["enforce"],
                elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            logger.info(
                "[LLM Risk]  %-9s  tool=%-28s  score=%.3f  labels=%-20s  rationale=%s  client=%s",
                hint.upper(), tool or method, score,
                ",".join(llm_risk.get("labels") or []) or "none",
                (llm_risk.get("rationale") or "")[:120], client_ip,
            )
            return _jsonrpc_error(request_id, -32003, "Request denied by MCP proxy LLM risk policy", 403, {"reason": deny_reason, "risk_score": score, "decision_hint": hint, "labels": llm_risk.get("labels", []), "rationale": llm_risk.get("rationale", "")})
        else:
            _record_decision_event(
                stage="llm_risk",
                decision=hint,
                method=method,
                tool=tool,
                reason="llm_risk_score_only",
                client_ip=client_ip,
                request_id=request_id,
                score=score,
                labels=llm_risk.get("labels") or [],
                rationale=llm_risk.get("rationale") or "",
                enforce=cfg["enforce"],
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            logger.info(
                "[LLM Risk]  %-9s  tool=%-28s  score=%.3f  labels=%-20s  enforce=%s  client=%s",
                hint.upper(), tool or method, score,
                ",".join(llm_risk.get("labels") or []) or "none",
                cfg["enforce"], client_ip,
            )

    tool_intent = None
    if method == "tools/call" and _feature_enabled("tool_intent", True):
        intent_usage_ok, intent_usage_reason, intent_usage_enforcement = _check_usage_limit("tool_intent_calls")
        if not intent_usage_ok and intent_usage_enforcement == "deny":
            elapsed = time.time() - start
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=intent_usage_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(
                request_id, method, tool, intent_usage_reason, arguments, client_ip,
                metadata={"tier": _commercial_tier(), "kind": "tool_intent_calls"},
            )
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="commercial",
                decision="deny",
                method=method,
                tool=tool,
                reason=intent_usage_reason,
                client_ip=client_ip,
                request_id=request_id,
                elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            return _jsonrpc_error(
                request_id, -32003, "Request denied by MCP proxy tier limit", 403,
                {"reason": intent_usage_reason, "tier": _commercial_tier()},
            )
        if not intent_usage_ok and intent_usage_enforcement == "monitor":
            _record_decision_event(
                stage="commercial",
                decision="monitor",
                method=method,
                tool=tool,
                reason=intent_usage_reason,
                client_ip=client_ip,
                request_id=request_id,
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
        tool_intent = await _tool_intent_score(method, tool, params if isinstance(params, dict) else {}, client_ip)
        if tool_intent is not None:
            _increment_usage_counter("tool_intent_calls")
    if tool_intent is not None:
        cfg = _tool_intent_config()
        hint = str(tool_intent.get("decision_hint", "allow"))
        score = float(tool_intent.get("intent_score", 0.0))
        fail_safe_cfg = policy.dependency_fail_safe_profile if isinstance(policy.dependency_fail_safe_profile, dict) else {}
        if cfg["enforce"] and fail_safe_cfg.get("prevent_silent_bypass", True) and _security_layer_unavailable(tool_intent, "tool_intent_unavailable"):
            elapsed = time.time() - start
            deny_reason = "security_layer_bypass_prevented"
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(
                request_id, method, tool, deny_reason, arguments, client_ip,
                metadata={"required_layer": "tool_intent", "result": tool_intent},
            )
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="tool_intent",
                decision="deny",
                method=method,
                tool=tool,
                reason=deny_reason,
                client_ip=client_ip,
                request_id=request_id,
                score=score,
                labels=tool_intent.get("labels") or [],
                rationale="required tool_intent layer unavailable in enforce mode",
                enforce=cfg["enforce"],
                elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            return _jsonrpc_error(
                request_id, -32003, "Required security layer unavailable", 403,
                {"reason": deny_reason, "required_layer": "tool_intent"},
            )
        if cfg["enforce"] and hint in {"deny", "challenge"}:
            elapsed = time.time() - start
            deny_reason = "llm_intent_deny" if hint == "deny" else "llm_intent_challenge"
            MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="deny").inc()
            MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool, reason=deny_reason).inc()
            MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="deny").observe(elapsed)
            denied_event = _record_denied_event(request_id, method, tool, deny_reason, arguments, client_ip, metadata=tool_intent)
            _evaluate_discovery_rules(denied_event)
            _record_decision_event(
                stage="tool_intent",
                decision=hint,
                method=method,
                tool=tool,
                reason=deny_reason,
                client_ip=client_ip,
                request_id=request_id,
                score=score,
                labels=tool_intent.get("labels") or [],
                rationale=tool_intent.get("rationale") or "",
                enforce=cfg["enforce"],
                elapsed_ms=int(elapsed * 1000),
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            logger.info(
                "[Intent]    %-9s  tool=%-28s  score=%.3f  labels=%-20s  rationale=%s  client=%s",
                hint.upper(), tool or method, score,
                ",".join(tool_intent.get("labels") or []) or "none",
                (tool_intent.get("rationale") or "")[:120], client_ip,
            )
            return _jsonrpc_error(request_id, -32003, "Request denied by MCP proxy tool intent policy", 403, {"reason": deny_reason, "intent_score": score, "decision_hint": hint, "labels": tool_intent.get("labels", []), "rationale": tool_intent.get("rationale", "")})
        else:
            _record_decision_event(
                stage="tool_intent",
                decision=hint,
                method=method,
                tool=tool,
                reason="tool_intent_score_only",
                client_ip=client_ip,
                request_id=request_id,
                score=score,
                labels=tool_intent.get("labels") or [],
                rationale=tool_intent.get("rationale") or "",
                enforce=cfg["enforce"],
                args_keys=args_keys,
                auth_subject=auth_subject,
            )
            logger.info(
                "[Intent]    %-9s  tool=%-28s  score=%.3f  labels=%-20s  enforce=%s  client=%s",
                hint.upper(), tool or method, score,
                ",".join(tool_intent.get("labels") or []) or "none",
                cfg["enforce"], client_ip,
            )

    headers = {"Content-Type": "application/json"}
    if _UPSTREAM_API_KEY:
        headers["Authorization"] = f"Bearer {_UPSTREAM_API_KEY}"

    # Sprint 3: Route to isolated executor if configured
    if route_to_executor and executor_url:
        return await _forward_to_isolated_executor(
            executor_url=executor_url,
            body_bytes=body_bytes,
            headers=headers,
            method=method,
            tool=tool,
            params=params,
            start=start,
            client_ip=client_ip,
            request_id=request_id,
            args_keys=args_keys,
            auth_subject=auth_subject,
        )

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
        _record_decision_event(
            stage="proxy_forward",
            decision=decision,
            method=method,
            tool=tool,
            reason=f"upstream_status_{upstream_response.status_code}",
            client_ip=client_ip,
            request_id=request_id,
            status_code=upstream_response.status_code,
            elapsed_ms=int(elapsed * 1000),
            args_keys=args_keys,
            auth_subject=auth_subject,
        )
        logger.info(
            "[Proxy]     %-9s  tool=%-28s  status=%d  elapsed=%.3fs  client=%s",
            decision.upper(), tool or method, upstream_response.status_code, elapsed, client_ip,
        )
        try:
            content = upstream_response.json()
        except ValueError:
            content = {"raw": upstream_response.text}

        if (
            method == "tools/list"
            and isinstance(content, dict)
            and policy.tool_descriptor_hashes
        ):
            result = content.get("result") if isinstance(content.get("result"), dict) else None
            tools_list = result.get("tools") if result and isinstance(result.get("tools"), list) else None
            if tools_list is not None:
                drift_action = policy.descriptor_drift_action
                kept: List[Any] = []
                drift_findings: List[Dict[str, Any]] = []
                for descriptor in tools_list:
                    if not isinstance(descriptor, dict):
                        kept.append(descriptor)
                        continue
                    tool_name = str(descriptor.get("name") or "").strip()
                    actual_hash = _check_descriptor_drift(tool_name, descriptor)
                    if actual_hash is None:
                        kept.append(descriptor)
                        continue
                    drift_findings.append({
                        "tool": tool_name,
                        "expected": policy.tool_descriptor_hashes.get(tool_name),
                        "actual": actual_hash,
                    })
                    drift_reason = "descriptor_drift" if drift_action == "deny" else (
                        "descriptor_drift_challenge" if drift_action == "challenge" else "descriptor_drift_monitor"
                    )
                    drift_event = _record_denied_event(
                        request_id, method, tool_name, drift_reason, {}, client_ip,
                        metadata={"expected": policy.tool_descriptor_hashes.get(tool_name), "actual": actual_hash},
                    )
                    _evaluate_discovery_rules(drift_event)
                    MCP_PROXY_DENIED_TOTAL.labels(method=method, tool=tool_name, reason=drift_reason).inc()
                    if drift_action == "monitor":
                        descriptor["_descriptor_drift"] = {"expected": policy.tool_descriptor_hashes.get(tool_name), "actual": actual_hash}
                        kept.append(descriptor)
                if drift_findings and drift_action == "deny":
                    result["tools"] = kept
                    result["_descriptor_drift"] = drift_findings
                elif drift_findings and drift_action == "challenge":
                    result["tools"] = kept
                    result["_descriptor_drift_challenge"] = drift_findings
                elif drift_findings:
                    result["tools"] = kept

        return JSONResponse(status_code=upstream_response.status_code, content=content)
    except httpx.TimeoutException:
        elapsed = time.time() - start
        MCP_PROXY_UPSTREAM_ERRORS_TOTAL.labels(category="timeout").inc()
        MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="error").inc()
        MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="error").observe(elapsed)
        _record_decision_event(
            stage="proxy_forward",
            decision="error",
            method=method,
            tool=tool,
            reason="upstream_timeout",
            client_ip=client_ip,
            request_id=request_id,
            elapsed_ms=int(elapsed * 1000),
            args_keys=args_keys,
            auth_subject=auth_subject,
        )
        return _jsonrpc_error(request_id, -32004, "Upstream timeout", 504)
    except Exception as exc:
        elapsed = time.time() - start
        MCP_PROXY_UPSTREAM_ERRORS_TOTAL.labels(category="transport").inc()
        MCP_PROXY_CALLS_TOTAL.labels(method=method, tool=tool, decision="error").inc()
        MCP_PROXY_CALL_DURATION_SECONDS.labels(method=method, tool=tool, decision="error").observe(elapsed)
        _record_decision_event(
            stage="proxy_forward",
            decision="error",
            method=method,
            tool=tool,
            reason="upstream_transport",
            client_ip=client_ip,
            request_id=request_id,
            elapsed_ms=int(elapsed * 1000),
            args_keys=args_keys,
            auth_subject=auth_subject,
        )
        logger.exception("mcp_proxy forwarding error: %s", exc)
        return _jsonrpc_error(request_id, -32004, "Upstream transport error", 502)